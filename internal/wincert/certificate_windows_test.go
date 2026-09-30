//go:build windows

package wincert

import (
	"golang.org/x/sys/windows"
	"netlens/internal/proxy"
	"testing"
)

func TestExactCertificateRemovalKeepsUnrelatedRoot(t *testing.T) {
	// 使用内存证书存储验证真实 CryptoAPI；不修改开发者或 runner 的信任根。
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(store, 0)
	first, err := proxy.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxy.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(first.CertificatePEM())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(second.CertificatePEM())
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*Certificate{a, a, b} {
		if err := cert.installTo(store); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.removeFrom(store); err != nil {
		t.Fatal(err)
	}
	if ctx, err := a.find(store); err != nil || ctx != nil {
		t.Fatal("移除后仍有本实例证书", err)
	}
	ctx, err := b.find(store)
	if err != nil || ctx == nil {
		t.Fatal("其他证书被误删", err)
	}
	windows.CertFreeCertificateContext(ctx)
	if err := a.removeFrom(store); err != nil {
		t.Fatal("重复移除应成功", err)
	}
}

func TestRejectPrivateKeyAndInvalidCertificate(t *testing.T) {
	for _, data := range []string{"", "bad", "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----"} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatal("无效证书被接受")
		}
	}
}
