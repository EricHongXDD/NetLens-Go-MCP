// Package systemproxy 管理系统代理的可恢复切换，平台操作通过 Backend 隔离。
package systemproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

var ErrChanged = errors.New("系统代理已被其他程序修改，未覆盖当前设置")

type Settings struct {
	Flags  uint32 `json:"flags"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
	PAC    string `json:"pac"`
}

type Backend interface {
	Read() (Settings, error)
	Write(Settings) error
	Lock() (func(), error)
}

type backup struct {
	Version  int      `json:"version"`
	Original Settings `json:"original"`
	Applied  Settings `json:"applied"`
}

type Status struct {
	Current   Settings
	HasBackup bool
	Owned     bool
	Original  Settings
}

type Manager struct {
	path    string
	backend Backend
}

func New(path string, backend Backend) *Manager { return &Manager{path: path, backend: backend} }

func (m *Manager) load() (*backup, error) {
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b backup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("读取系统代理备份：%w", err)
	}
	if b.Version != 1 || b.Applied.Flags != 3 || b.Applied.Server == "" {
		return nil, errors.New("系统代理备份无效，请保留文件以便人工恢复")
	}
	return &b, nil
}

func (m *Manager) Status() (Status, error) {
	unlock, err := m.backend.Lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	current, err := m.backend.Read()
	if err != nil {
		return Status{}, err
	}
	b, err := m.load()
	if err != nil {
		return Status{}, err
	}
	state := Status{Current: current, HasBackup: b != nil}
	if b != nil {
		state.Owned, state.Original = current == b.Applied, b.Original
	}
	return state, nil
}

func (m *Manager) Enable(address string) error {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("系统代理必须指向已启动的本机回环地址和有效端口")
	}
	unlock, err := m.backend.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	current, err := m.backend.Read()
	if err != nil {
		return err
	}
	b, err := m.load()
	if err != nil {
		return err
	}
	applied := Settings{Flags: 3, Server: "http=" + address + ";https=" + address, Bypass: "localhost;127.*;[::1];<local>"}
	if b != nil {
		if current == b.Applied && b.Applied == applied {
			return nil
		}
		return errors.New("存在尚未恢复的代理备份，请先点击“恢复原代理”")
	}
	b = &backup{Version: 1, Original: current, Applied: applied}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	// 备份必须先成功落盘；独占创建避免覆盖旧的恢复凭据。
	file, err := os.OpenFile(m.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(data, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(m.path)
		return errors.Join(writeErr, closeErr)
	}
	if err := m.apply(applied); err != nil {
		// Windows 通知失败时设置可能已生效，因此失败也要回滚并检查。
		if rollbackErr := m.apply(current); rollbackErr != nil {
			return fmt.Errorf("开启代理失败：%v；恢复失败：%w；备份已保留", err, rollbackErr)
		}
		_ = os.Remove(m.path)
		return err
	}
	return nil
}

func (m *Manager) apply(value Settings) error {
	if err := m.backend.Write(value); err != nil {
		return err
	}
	actual, err := m.backend.Read()
	if err != nil {
		return err
	}
	if actual != value {
		return errors.New("Windows 返回的代理配置与写入配置不一致")
	}
	return nil
}

func (m *Manager) Restore(force bool) error {
	unlock, err := m.backend.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	b, err := m.load()
	if err != nil || b == nil {
		return err
	}
	current, err := m.backend.Read()
	if err != nil {
		return err
	}
	// 手工更改后不自动覆盖；已恢复但删除备份失败时可安全重试。
	if current != b.Applied && current != b.Original && !force {
		return ErrChanged
	}
	// 即使注册表值已恢复也重新通知，确保上次广播失败后的重试有效。
	if err := m.apply(b.Original); err != nil {
		return fmt.Errorf("恢复代理失败，备份已保留：%w", err)
	}
	return os.Remove(m.path)
}
