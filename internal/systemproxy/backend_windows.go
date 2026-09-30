//go:build windows

package systemproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wininet     = windows.NewLazySystemDLL("wininet.dll")
	queryOption = wininet.NewProc("InternetQueryOptionW")
	setOption   = wininet.NewProc("InternetSetOptionW")
	globalFree  = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

// Windows 联合体同时容纳指针和 FILETIME；32 位下补足八字节。
type internetOption struct {
	Option uint32
	Value  uint64
}

type optionList struct {
	Size        uint32
	Connection  *uint16
	Count       uint32
	OptionError uint32
	Options     *internetOption
}

type WindowsBackend struct{}

func NewWindows() (*Manager, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	// 所有实例共享一份用户级备份，避免不同数据目录相互覆盖原配置。
	return New(filepath.Join(dir, "NetLens", "system-proxy-backup.json"), WindowsBackend{}), nil
}

func (WindowsBackend) Lock() (func(), error) {
	runtime.LockOSThread()
	locked := false
	defer func() {
		if !locked {
			runtime.UnlockOSThread()
		}
	}()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString("Local\\NetLens.SystemProxy." + user.User.Sid.String())
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return nil, err
	}
	state, err := windows.WaitForSingleObject(handle, 3000)
	if err != nil || (state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED) {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("另一个 NetLens 实例正在修改代理：%v", err)
	}
	locked = true
	return func() { _ = windows.ReleaseMutex(handle); _ = windows.CloseHandle(handle); runtime.UnlockOSThread() }, nil
}

func optionCall(proc *windows.LazyProc, options []internetOption) error {
	list := optionList{Count: uint32(len(options)), Options: &options[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	var ok uintptr
	var err error
	if proc == queryOption {
		ok, _, err = proc.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	} else {
		ok, _, err = proc.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(size))
	}
	runtime.KeepAlive(options)
	if ok == 0 {
		return fmt.Errorf("Windows 代理选项 %d：%w", list.OptionError, err)
	}
	return nil
}

func (WindowsBackend) Read() (Settings, error) {
	options := []internetOption{{Option: 10}, {Option: 2}, {Option: 3}, {Option: 4}}
	defer func() {
		// WinINet 分配查询字符串，按文档使用 GlobalFree 释放。
		for i := 1; i < len(options); i++ {
			ptr := *(**uint16)(unsafe.Pointer(&options[i].Value))
			if ptr != nil {
				globalFree.Call(uintptr(unsafe.Pointer(ptr)))
			}
		}
	}()
	if err := optionCall(queryOption, options); err != nil {
		return Settings{}, err
	}
	text := func(i int) string { return windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&options[i].Value))) }
	return Settings{Flags: uint32(options[0].Value), Server: text(1), Bypass: text(2), PAC: text(3)}, nil
}

func (WindowsBackend) Write(value Settings) error {
	server, err := syscall.UTF16PtrFromString(value.Server)
	if err != nil {
		return err
	}
	bypass, err := syscall.UTF16PtrFromString(value.Bypass)
	if err != nil {
		return err
	}
	pac, err := syscall.UTF16PtrFromString(value.PAC)
	if err != nil {
		return err
	}
	options := []internetOption{{Option: 1, Value: uint64(value.Flags)}, {Option: 2}, {Option: 3}, {Option: 4}}
	for i, pointer := range []*uint16{server, bypass, pac} {
		*(**uint16)(unsafe.Pointer(&options[i+1].Value)) = pointer
	}
	err = optionCall(setOption, options)
	runtime.KeepAlive(server)
	runtime.KeepAlive(bypass)
	runtime.KeepAlive(pac)
	if err != nil {
		return err
	}
	// 广播代理变化并刷新 WinINet；不修改 WinHTTP 或 VPN 连接配置。
	for _, option := range []uintptr{95, 37} {
		ok, _, err := setOption.Call(0, option, 0, 0)
		if ok == 0 {
			return fmt.Errorf("通知代理变更：%w", err)
		}
	}
	return nil
}
