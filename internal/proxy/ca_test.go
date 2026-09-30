package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreateCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCAPersistsAndIsUniquePerInstallation(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	reloaded, err := LoadOrCreateCA(filepath.Dir(c.CertPath()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.CertificatePEM(), reloaded.CertificatePEM()) || !c.key.Equal(reloaded.key) {
		t.Fatal("reloading changed the inspection root")
	}
	other := testCA(t)
	if bytes.Equal(c.CertificatePEM(), other.CertificatePEM()) || c.key.Equal(other.key) {
		t.Fatal("independent installations share CA material")
	}
	if !filepath.IsAbs(c.CertPath()) {
		t.Fatal("certificate path is not absolute")
	}
	if !c.cert.IsCA || !c.cert.BasicConstraintsValid || !c.cert.MaxPathLenZero || c.cert.MaxPathLen != 0 {
		t.Fatal("root CA constraints permit subordinate CAs")
	}
	copyPEM := c.CertificatePEM()
	copyPEM[0] = '!'
	if bytes.Equal(copyPEM, c.CertificatePEM()) {
		t.Fatal("public certificate accessor exposes mutable internal storage")
	}
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{
			filepath.Dir(c.CertPath()):                                      0700,
			filepath.Join(filepath.Dir(c.CertPath()), caPrivateKeyFilename): 0600,
		} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("incorrect permissions for %s: info=%v err=%v", path, info, err)
			}
		}
	}
}

func TestCALeafTrustAndSANs(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CertificatePEM()) {
		t.Fatal("root cannot be imported into a trust store")
	}
	serials := map[string]bool{}
	for _, host := range []string{"example.com", "localhost", "127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			cert, err := c.certificateFor(host)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Fatalf("leaf is not trusted for %s: %v", host, err)
			}
			if err := cert.Leaf.VerifyHostname("unrelated.example"); err == nil {
				t.Fatal("certificate authenticates an unrelated hostname")
			}
			if cert.Leaf.IsCA || cert.Leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
				t.Fatal("leaf can sign certificates")
			}
			if len(cert.Leaf.ExtKeyUsage) != 1 || cert.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatal("leaf has unexpected extended key usages")
			}
			if cert.Leaf.NotAfter.After(c.cert.NotAfter) || cert.Leaf.NotBefore.Before(c.cert.NotBefore) {
				t.Fatal("leaf validity exceeds root validity")
			}
			serial := cert.Leaf.SerialNumber.String()
			if cert.Leaf.SerialNumber.Sign() <= 0 || serials[serial] {
				t.Fatal("leaf serials are not positive and distinct")
			}
			serials[serial] = true
			if len(cert.Leaf.DNSNames)+len(cert.Leaf.IPAddresses) != 1 {
				t.Fatal("leaf must contain exactly one DNS or IP SAN")
			}
		})
	}
}

func TestCAWorksWithTLSClient(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	leaf, err := c.certificateFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "trusted")
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*leaf}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(c.CertificatePEM())
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "trusted" {
		t.Fatalf("TLS response: %q, %v", body, err)
	}
}

func TestCARejectsIncompleteInstallation(t *testing.T) {
	t.Parallel()
	for _, filename := range []string{caCertificateFilename, caPrivateKeyFilename} {
		t.Run(filename, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ca")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, filename)
			original := []byte("existing material must survive")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Fatalf("expected incomplete-installation error, got %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, original) {
				t.Fatal("incomplete installation was overwritten")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("load unexpectedly created missing CA material")
			}
		})
	}
}

func TestCARejectsInvalidInstallationWithoutReplacingIt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		want   string
		modify func(*testing.T, *CA)
	}{
		{"bad_certificate", "certificate", func(t *testing.T, c *CA) {
			if err := os.WriteFile(c.CertPath(), []byte("invalid certificate"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"bad_key", "private key", func(t *testing.T, c *CA) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(c.CertPath()), caPrivateKeyFilename), []byte("invalid key"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"mismatched_key", "do not match", func(t *testing.T, c *CA) {
			other := testCA(t)
			key, err := os.ReadFile(filepath.Join(filepath.Dir(other.CertPath()), caPrivateKeyFilename))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(filepath.Dir(c.CertPath()), caPrivateKeyFilename), key, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"expired", "expired", func(t *testing.T, c *CA) {
			template := *c.cert
			template.NotBefore = time.Now().Add(-48 * time.Hour)
			template.NotAfter = time.Now().Add(-24 * time.Hour)
			rewriteTestCARoot(t, c, &template)
		}},
		{"future", "not valid yet", func(t *testing.T, c *CA) {
			template := *c.cert
			template.NotBefore = time.Now().Add(time.Hour)
			rewriteTestCARoot(t, c, &template)
		}},
		{"not_ca", "certificate-signing CA", func(t *testing.T, c *CA) {
			template := *c.cert
			template.IsCA = false
			template.MaxPathLenZero = false
			template.MaxPathLen = -1
			template.KeyUsage = x509.KeyUsageDigitalSignature
			rewriteTestCARoot(t, c, &template)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testCA(t)
			tc.modify(t, c)
			dir := filepath.Dir(c.CertPath())
			before := make(map[string][]byte)
			for _, filename := range []string{caCertificateFilename, caPrivateKeyFilename} {
				data, err := os.ReadFile(filepath.Join(dir, filename))
				if err != nil {
					t.Fatal(err)
				}
				before[filename] = data
			}
			if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
			for filename, data := range before {
				after, err := os.ReadFile(filepath.Join(dir, filename))
				if err != nil || !bytes.Equal(after, data) {
					t.Fatalf("invalid installation file %s was replaced", filename)
				}
			}
		})
	}
}

func rewriteTestCARoot(t *testing.T, c *CA, template *x509.Certificate) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, template, &c.key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCARejectsUnsafePermissionsAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions and unprivileged symbolic links are platform-specific")
	}
	t.Parallel()
	t.Run("directory_permissions", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "0700") {
			t.Fatalf("expected private-directory error, got %v", err)
		}
	})
	t.Run("key_permissions", func(t *testing.T) {
		c := testCA(t)
		dir := filepath.Dir(c.CertPath())
		if err := os.Chmod(filepath.Join(dir, caPrivateKeyFilename), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("expected private-key permissions error, got %v", err)
		}
	})
	t.Run("certificate_symlink", func(t *testing.T) {
		c := testCA(t)
		dir := filepath.Join(t.TempDir(), "ca")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(c.CertPath(), filepath.Join(dir, caCertificateFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("expected symbolic-link error, got %v", err)
		}
	})
}

func TestCACacheIsBoundedAndConcurrent(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	var wg sync.WaitGroup
	errors := make(chan error, 32)
	for worker := 0; worker < 32; worker++ {
		wg.Go(func() {
			for i := 0; i < 16; i++ {
				if _, err := c.certificateFor(fmt.Sprintf("concurrent-%d.example", i%8)); err != nil {
					errors <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	first, err := c.certificateFor("oldest.example")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < caLeafCacheLimit; i++ {
		if _, err := c.certificateFor(fmt.Sprintf("bounded-%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.cache) != caLeafCacheLimit || c.lru.Len() != caLeafCacheLimit {
		t.Fatalf("cache is not bounded: map=%d list=%d", len(c.cache), c.lru.Len())
	}
	if _, ok := c.cache["oldest.example"]; ok {
		t.Fatal("least recently used certificate was not evicted")
	}
	again, err := c.certificateFor("oldest.example")
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Cmp(again.Leaf.SerialNumber) == 0 {
		t.Fatal("evicted leaf was reused")
	}
}

func TestCAConcurrentInstallationLoad(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "ca")
	var wg sync.WaitGroup
	results := make(chan *CA, 8)
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			c, err := LoadOrCreateCA(dir)
			if err != nil {
				errors <- err
				return
			}
			results <- c
		})
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	var first []byte
	for c := range results {
		if first == nil {
			first = c.CertificatePEM()
		} else if !bytes.Equal(first, c.CertificatePEM()) {
			t.Fatal("concurrent initializers created different roots")
		}
	}
}

func TestCAHostNormalizationAndValidation(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	a, err := c.certificateFor("EXAMPLE.COM.:443")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.certificateFor("example.com")
	if err != nil || a != b {
		t.Fatalf("normalized hostname did not reuse its certificate: %v", err)
	}
	for input, want := range map[string]string{
		"[::1]:443": "::1", "[::1]": "::1", "127.0.0.1:8443": "127.0.0.1",
	} {
		cert, err := c.certificateFor(input)
		if err != nil || cert.Leaf.VerifyHostname(want) != nil {
			t.Fatalf("IP address %q did not receive the correct SAN: %v", input, err)
		}
	}
	for _, host := range []string{"", " example.com", "https://example.com", "*.example.com", "bad..name", "host:0", "host:65536", "host:abc", "-bad.example", "bad-.example", "你好.example", "user@example.com"} {
		if _, err := c.certificateFor(host); err == nil {
			t.Errorf("invalid hostname %q accepted", host)
		}
	}
}

func TestCALeafCannotOutliveRootAndExpiredRootStopsSigning(t *testing.T) {
	t.Parallel()
	c := testCA(t)
	template := *c.cert
	template.NotAfter = time.Now().Add(time.Hour).Truncate(time.Second)
	rewriteTestCARoot(t, c, &template)
	c, err := LoadOrCreateCA(filepath.Dir(c.CertPath()))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := c.certificateFor("example.com")
	if err != nil || !leaf.Leaf.NotAfter.Equal(c.cert.NotAfter) {
		t.Fatalf("leaf was not limited by CA expiry: %v", err)
	}
	c.cert.NotAfter = time.Now().Add(-time.Second)
	if _, err := c.certificateFor("example.com"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired CA returned a cached leaf: %v", err)
	}
}
