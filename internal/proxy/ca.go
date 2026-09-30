package proxy

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	caCertificateFilename = "ca.pem"
	caPrivateKeyFilename  = "ca-key.pem"
	caMaxPEMSize          = 64 << 10
	caLeafCacheLimit      = 256
	caClockSkew           = 5 * time.Minute
	caLeafLifetime        = 24 * time.Hour
)

// CA owns one installation's inspection root and an in-memory leaf certificate
// cache. Its private key is never exposed by the public API. Returned TLS
// certificates are immutable and may safely be shared between TLS connections.
type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPEM  []byte
	certPath string
	mu       sync.Mutex
	cache    map[string]*list.Element
	lru      *list.List
}

type caLeafEntry struct {
	host string
	cert *tls.Certificate
}

// Serializes installation creation inside this process. O_EXCL also prevents
// different processes from overwriting each other's root material.
var caInitMu sync.Mutex

// LoadOrCreateCA loads an existing inspection CA, or creates one only if both
// files are absent. An incomplete, invalid, mismatched, or expired installation
// is an error: replacing a trusted root requires an explicit operator decision.
// On Unix, the directory must be private (0700), and the private key must be
// 0600. Newly created directories and keys receive these permissions.
func LoadOrCreateCA(dir string) (*CA, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("CA directory is empty")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve CA directory: %w", err)
	}
	caInitMu.Lock()
	defer caInitMu.Unlock()
	if err := os.MkdirAll(absDir, 0700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	dirInfo, err := os.Lstat(absDir)
	if err != nil {
		return nil, fmt.Errorf("inspect CA directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("CA directory must be a real directory, not a symbolic link")
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("CA directory %q must have permissions 0700", absDir)
	}
	certPath := filepath.Join(absDir, caCertificateFilename)
	keyPath := filepath.Join(absDir, caPrivateKeyFilename)
	certExists, err := caFileExists(certPath)
	if err != nil {
		return nil, err
	}
	keyExists, err := caFileExists(keyPath)
	if err != nil {
		return nil, err
	}
	if certExists != keyExists {
		return nil, fmt.Errorf("incomplete CA installation in %q: both ca.pem and ca-key.pem are required; restore the matching pair", absDir)
	}
	if !certExists {
		certPEM, keyPEM, err := generateCARoot()
		if err != nil {
			return nil, fmt.Errorf("generate CA: %w", err)
		}
		if err := writeNewCAFile(keyPath, keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("save CA private key: %w", err)
		}
		if err := writeNewCAFile(certPath, certPEM, 0644); err != nil {
			// Only remove the newly created key belonging to this attempt.
			return nil, fmt.Errorf("save CA certificate: %w", errors.Join(err, os.Remove(keyPath)))
		}
	}
	certPEM, err := readCAFile(certPath, false)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := readCAFile(keyPath, true)
	if err != nil {
		return nil, fmt.Errorf("read CA private key: %w", err)
	}
	cert, key, err := parseCARoot(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CA installation in %q: %w", absDir, err)
	}
	return &CA{
		cert: cert, key: key, certPEM: certPEM, certPath: certPath,
		cache: make(map[string]*list.Element), lru: list.New(),
	}, nil
}

// CertPath returns the absolute path of the public root certificate.
func (c *CA) CertPath() string { return c.certPath }

// CertificatePEM returns a copy of the public root certificate for trust-store
// installation. It never includes the private key.
func (c *CA) CertificatePEM() []byte { return bytes.Clone(c.certPEM) }

func caFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect CA file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("CA file %q must be a regular file, not a symbolic link", path)
	}
	return true, nil
}

func readCAFile(path string, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("CA material must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("CA file changed while opening it")
	}
	if private && runtime.GOOS != "windows" && after.Mode().Perm() != 0600 {
		return nil, errors.New("CA private key must have permissions 0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, caMaxPEMSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > caMaxPEMSize {
		return nil, errors.New("CA PEM file exceeds the size limit")
	}
	return data, nil
}

func writeNewCAFile(path string, data []byte, mode os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func generateCARoot() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := caRandomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "NetLens Local Inspection CA", Organization: []string{"NetLens"},
		},
		NotBefore: now.Add(-caClockSkew), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:           x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func parseCARoot(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	trimmedCert := bytes.TrimSpace(certPEM)
	certBlock, rest := pem.Decode(trimmedCert)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(certBlock.Headers) != 0 ||
		!bytes.HasPrefix(trimmedCert, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(trimmedCert, []byte("-----BEGIN ")) != 1 {
		return nil, nil, errors.New("ca.pem must contain exactly one certificate PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	trimmedKey := bytes.TrimSpace(keyPEM)
	keyBlock, rest := pem.Decode(trimmedKey)
	if keyBlock == nil || len(bytes.TrimSpace(rest)) != 0 || len(keyBlock.Headers) != 0 ||
		!bytes.HasPrefix(trimmedKey, []byte("-----BEGIN ")) || bytes.Count(trimmedKey, []byte("-----BEGIN ")) != 1 {
		return nil, nil, errors.New("ca-key.pem must contain exactly one unencrypted private key PEM block")
	}
	var parsedKey any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		parsedKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, errors.New("unsupported CA private key PEM type")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("CA private key must be ECDSA P-256")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("CA certificate and private key do not match")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("certificate is not a valid certificate-signing CA")
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, nil, errors.New("inspection CA must be a self-signed root")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, nil, fmt.Errorf("verify CA self-signature: %w", err)
	}
	if err := caCheckValidity(cert, time.Now()); err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, nil, fmt.Errorf("verify CA certificate: %w", err)
	}
	return cert, key, nil
}

func caCheckValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return errors.New("CA certificate is not valid yet; check the system clock")
	}
	if !now.Before(cert.NotAfter) {
		return errors.New("CA certificate has expired; explicitly replace it and update client trust stores")
	}
	return nil
}

func caRandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil || serial.Sign() > 0 {
			return serial, err
		}
	}
}

func (c *CA) certificateFor(host string) (*tls.Certificate, error) {
	name, ip, err := caCertificateHost(host)
	if err != nil {
		return nil, err
	}
	if c == nil || c.cert == nil || c.key == nil {
		return nil, errors.New("inspection CA is not initialized")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if err := caCheckValidity(c.cert, now); err != nil {
		return nil, err
	}
	if element, ok := c.cache[name]; ok {
		entry := element.Value.(caLeafEntry)
		if now.Before(entry.cert.Leaf.NotAfter.Add(-caClockSkew)) {
			c.lru.MoveToFront(element)
			return entry.cert, nil
		}
		delete(c.cache, name)
		c.lru.Remove(element)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := caRandomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	notBefore, notAfter := now.Add(-caClockSkew), now.Add(caLeafLifetime)
	if notBefore.Before(c.cert.NotBefore) {
		notBefore = c.cert.NotBefore
	}
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signed leaf certificate: %w", err)
	}
	result := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	c.cache[name] = c.lru.PushFront(caLeafEntry{host: name, cert: result})
	if c.lru.Len() > caLeafCacheLimit {
		oldest := c.lru.Back()
		delete(c.cache, oldest.Value.(caLeafEntry).host)
		c.lru.Remove(oldest)
	}
	return result, nil
}

func caCertificateHost(host string) (string, net.IP, error) {
	if host == "" || strings.TrimSpace(host) != host {
		return "", nil, errors.New("certificate host is empty or contains surrounding whitespace")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if ip := net.ParseIP(host[1 : len(host)-1]); ip != nil {
			return ip.String(), ip, nil
		}
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", nil, errors.New("certificate host contains an invalid port")
		}
		host = h
		if ip := net.ParseIP(host); ip != nil {
			return ip.String(), ip, nil
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip, nil
	}
	if host == "" || len(host) > 253 {
		return "", nil, errors.New("certificate host must be a DNS name or IP address")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", nil, errors.New("certificate host has an invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", nil, errors.New("certificate host must be an ASCII DNS name (use punycode) or IP address")
			}
		}
	}
	return host, nil, nil
}
