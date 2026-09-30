//go:build windows

package systemproxy

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestNativeProxyStructLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 && (unsafe.Sizeof(internetOption{}) != 16 || unsafe.Sizeof(optionList{}) != 32) {
		t.Fatal("WinINet 结构体布局与 Windows x64 ABI 不符")
	}
}

func TestWindowsProxyRoundTripInIsolatedRunner(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("NETLENS_SYSTEM_TEST") != "1" {
		t.Skip("真实系统代理写入仅在显式开启的隔离 CI runner 中执行")
	}
	backend := WindowsBackend{}
	unlock, err := backend.Lock()
	if err != nil {
		t.Fatal(err)
	}
	original, err := backend.Read()
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	m := New(filepath.Join(t.TempDir(), "backup.json"), backend)
	t.Cleanup(func() {
		if err := m.Restore(true); err != nil {
			t.Error(err)
		}
		actual, err := backend.Read()
		if err != nil || actual != original {
			t.Errorf("代理配置未完整恢复：%+v，%v", actual, err)
		}
	})
	if err := m.Enable(listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	state, err := m.Status()
	if err != nil || !state.Owned {
		t.Fatal("未开启 NetLens 系统代理", err)
	}
	if err := m.Restore(false); err != nil {
		t.Fatal(err)
	}
}
