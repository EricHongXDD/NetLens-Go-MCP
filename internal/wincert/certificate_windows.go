//go:build windows

// Package wincert 仅管理当前 NetLens CA 的用户级 Windows 根证书信任。
package wincert

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Certificate struct{ Cert *x509.Certificate }
type Status struct{ User, Machine bool }

func Load(path string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Certificate, error) {
	block, tail := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(tail)) != 0 {
		return nil, errors.New("CA 文件必须只包含一张公开证书")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("本实例证书不是有效的自签名根 CA")
	}
	return &Certificate{Cert: cert}, nil
}

func (c *Certificate) Fingerprint() string {
	sum := sha256.Sum256(c.Cert.Raw)
	return hex.EncodeToString(sum[:])
}

func openRoot(location uint32, readonly bool) (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString("ROOT")
	flags := location
	if readonly {
		flags |= windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG
	}
	// 访问物理注册表存储，移除时不会触及继承的机器级根证书。
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0, flags, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	return h, err
}

func (c *Certificate) find(store windows.Handle) (*windows.CertContext, error) {
	var prev *windows.CertContext
	for {
		cert, err := windows.CertEnumCertificatesInStore(store, prev)
		if cert == nil {
			if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil, nil
			}
			return nil, err
		}
		prev = cert
		der := unsafe.Slice(cert.EncodedCert, int(cert.Length))
		if bytes.Equal(der, c.Cert.Raw) {
			return cert, nil
		}
	}
}

func (c *Certificate) Check() (Status, error) {
	var status Status
	for i, location := range []uint32{windows.CERT_SYSTEM_STORE_CURRENT_USER, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE} {
		h, err := openRoot(location, true)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			return status, err
		}
		ctx, err := c.find(h)
		if ctx != nil {
			windows.CertFreeCertificateContext(ctx)
			if i == 0 {
				status.User = true
			} else {
				status.Machine = true
			}
		}
		windows.CertCloseStore(h, 0)
		if err != nil {
			return status, err
		}
	}
	return status, nil
}

func (c *Certificate) Install() error {
	if time.Now().Before(c.Cert.NotBefore) || time.Now().After(c.Cert.NotAfter) {
		return errors.New("CA 尚未生效或已到期，不能安装")
	}
	h, err := openRoot(windows.CERT_SYSTEM_STORE_CURRENT_USER, false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(h, 0)
	return c.installTo(h)
}

func (c *Certificate) installTo(h windows.Handle) error {
	existing, err := c.find(h)
	if err != nil {
		return err
	}
	if existing != nil {
		windows.CertFreeCertificateContext(existing)
		return nil
	}
	ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &c.Cert.Raw[0], uint32(len(c.Cert.Raw)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(ctx)
	// 仅导入公开 DER；不导入或复制本地 CA 私钥。
	if err := windows.CertAddCertificateContextToStore(h, ctx, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		return fmt.Errorf("安装用户根证书：%w", err)
	}
	return nil
}

func (c *Certificate) Remove() error {
	h, err := openRoot(windows.CERT_SYSTEM_STORE_CURRENT_USER, false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(h, 0)
	return c.removeFrom(h)
}

func (c *Certificate) removeFrom(h windows.Handle) error {
	for {
		ctx, err := c.find(h)
		if err != nil || ctx == nil {
			return err
		}
		// 删除精确 DER 匹配的用户证书；Windows 删除 API 同时释放 context。
		if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
			return err
		}
	}
}
