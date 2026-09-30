package systemproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeBackend struct {
	settings   Settings
	failWrites int
}

func (b *fakeBackend) Read() (Settings, error) { return b.settings, nil }
func (b *fakeBackend) Write(s Settings) error {
	b.settings = s
	if b.failWrites > 0 {
		b.failWrites--
		return errors.New("通知失败")
	}
	return nil
}
func (*fakeBackend) Lock() (func(), error) { return func() {}, nil }

func TestRestorePreservesPACAndDetectAfterRestart(t *testing.T) {
	original := Settings{Flags: 15, Server: "http=corp:3128;https=corp:443", Bypass: "*.internal;<local>", PAC: "https://corp/proxy.pac"}
	backend := &fakeBackend{settings: original}
	path := filepath.Join(t.TempDir(), "proxy.json")
	m := New(path, backend)
	if err := m.Enable("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if backend.settings.Flags != 3 || backend.settings.PAC != "" {
		t.Fatal("PAC 未关闭，流量仍可能绕过本地代理")
	}
	if err := m.Enable("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable("127.0.0.1:9091"); err == nil {
		t.Fatal("第二个实例覆盖了原始备份")
	}
	// 新进程从磁盘恢复，不能依赖旧窗口中的内存。
	if err := New(path, backend).Restore(false); err != nil {
		t.Fatal(err)
	}
	if backend.settings != original {
		t.Fatalf("恢复丢失原始配置：%+v", backend.settings)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("恢复后备份未清理")
	}
}

func TestExternalChangesAreNotOverwrittenAutomatically(t *testing.T) {
	original := Settings{Flags: 9, Bypass: "old", PAC: "https://old/pac"}
	backend := &fakeBackend{settings: original}
	m := New(filepath.Join(t.TempDir(), "proxy.json"), backend)
	if err := m.Enable("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	external := Settings{Flags: 3, Server: "127.0.0.1:7890"}
	backend.settings = external
	if err := m.Restore(false); !errors.Is(err, ErrChanged) {
		t.Fatal(err)
	}
	if backend.settings != external {
		t.Fatal("其他程序的设置被自动覆盖")
	}
	if err := m.Restore(true); err != nil {
		t.Fatal(err)
	}
	if backend.settings != original {
		t.Fatal("显式恢复没有恢复原配置")
	}
}

func TestFailureRollsBackAndRetainsRecoveryWhenRollbackFails(t *testing.T) {
	for _, failures := range []int{1, 2} {
		t.Run(string(rune('0'+failures)), func(t *testing.T) {
			original := Settings{Flags: 9, PAC: "https://corp/pac"}
			backend := &fakeBackend{settings: original, failWrites: failures}
			path := filepath.Join(t.TempDir(), "proxy.json")
			m := New(path, backend)
			if err := m.Enable("127.0.0.1:8080"); err == nil {
				t.Fatal("写入失败却报告成功")
			}
			if backend.settings != original {
				t.Fatal("部分写入未回滚")
			}
			_, err := os.Stat(path)
			if failures == 1 && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("成功回滚后备份未清理")
			}
			if failures == 2 && err != nil {
				t.Fatal("回滚失败丢失恢复备份")
			}
			if err := m.Restore(false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBadBackupAndNonLoopbackDoNotChangeSystem(t *testing.T) {
	backend := &fakeBackend{settings: Settings{Flags: 1}}
	path := filepath.Join(t.TempDir(), "proxy.json")
	m := New(path, backend)
	for _, address := range []string{"0.0.0.0:8080", "example.com:8080", "127.0.0.1:0"} {
		if m.Enable(address) == nil {
			t.Fatal("接受了无效或非本地代理")
		}
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if m.Enable("127.0.0.1:8080") == nil || m.Restore(true) == nil {
		t.Fatal("损坏备份未阻止写入")
	}
	if backend.settings.Flags != 1 {
		t.Fatal("无效操作改变了代理")
	}
}
