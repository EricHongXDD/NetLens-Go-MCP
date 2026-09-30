//go:build windows

package desktop

import (
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

var themedButtons = map[win.HWND]*walk.PushButton{}
var themedChecks = map[win.HWND]bool{}
var themeParents = map[win.HWND]uintptr{}
var themeProc = syscall.NewCallback(themeWndProc)

// 原生按钮采用公共控件自绘通知，保留键盘、焦点与可访问性行为。
func applyTheme(root walk.Container) error {
	surface, err := walk.NewSolidColorBrush(panelRaised)
	if err != nil {
		return err
	}
	root.AsWindowBase().Disposing().Attach(func() { surface.Dispose() })
	var visit func(walk.Window)
	visit = func(window walk.Window) {
		setupModernControl(window)
		switch widget := window.(type) {
		case *walk.PushButton:
			themedButtons[widget.Handle()] = widget
		case *walk.CheckBox:
			themedChecks[widget.Handle()] = true
			empty, _ := syscall.UTF16PtrFromString("")
			win.SetWindowTheme(widget.Handle(), empty, empty)
		case *walk.LineEdit:
			widget.SetTextColor(ink)
			widget.SetBackground(surface)
		case *walk.TextEdit:
			widget.SetTextColor(ink)
			textSurface, e := walk.NewSolidColorBrush(panel)
			if e == nil {
				widget.SetBackground(textSurface)
				widget.Disposing().Attach(textSurface.Dispose)
			}
		case *walk.Label:
			if widget.TextColor() == 0 {
				widget.SetTextColor(ink)
			}
		}
		if container, ok := window.(walk.Container); ok {
			children := container.Children()
			for i := 0; i < children.Len(); i++ {
				visit(children.At(i))
			}
		}
		if tabs, ok := window.(*walk.TabWidget); ok {
			for i := 0; i < tabs.Pages().Len(); i++ {
				visit(tabs.Pages().At(i))
			}
		}
	}
	visit(root)
	for handle := range themedButtons {
		installParentTheme(win.GetParent(handle))
	}
	for handle := range themedChecks {
		installParentTheme(win.GetParent(handle))
	}
	// Windows 10/11 标题栏请求深色背景；旧版本不支持时保留系统标题栏。
	dwm := syscall.NewLazyDLL("dwmapi.dll").NewProc("DwmSetWindowAttribute")
	if dwm.Find() == nil {
		value := int32(1)
		dwm.Call(uintptr(root.Handle()), 20, uintptr(unsafe.Pointer(&value)), 4)
	}
	root.AsWindowBase().Disposing().Attach(func() {
		for handle, button := range themedButtons {
			if button.IsDisposed() {
				delete(themedButtons, handle)
			}
		}
	})
	return nil
}

func installParentTheme(parent win.HWND) {
	if _, ok := themeParents[parent]; !ok {
		themeParents[parent] = win.SetWindowLongPtr(parent, win.GWLP_WNDPROC, themeProc)
	}
}

func themeWndProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	original := themeParents[hwnd]
	if msg == win.WM_NOTIFY && lp != 0 {
		// WM_NOTIFY 的 lParam 是原生结构指针，按消息联合体读取，不做地址运算。
		n := (*win.NMCUSTOMDRAW)(*(*unsafe.Pointer)(unsafe.Pointer(&lp)))
		if n.Hdr.Code == win.NM_CUSTOMDRAW && n.DwDrawStage == win.CDDS_PREPAINT {
			if button := themedButtons[n.Hdr.HwndFrom]; button != nil {
				drawButton(button, n)
				return win.CDRF_SKIPDEFAULT
			}
		}
	}
	result := win.CallWindowProc(original, hwnd, msg, wp, lp)
	if (msg == win.WM_CTLCOLORBTN || msg == win.WM_CTLCOLORSTATIC) && themedChecks[win.HWND(lp)] {
		win.SetTextColor(win.HDC(wp), win.COLORREF(ink))
		win.SetBkMode(win.HDC(wp), win.TRANSPARENT)
	}
	if msg == win.WM_NCDESTROY {
		delete(themeParents, hwnd)
		for handle := range themedButtons {
			if win.GetParent(handle) == hwnd || win.GetParent(handle) == 0 {
				delete(themedButtons, handle)
			}
		}
		for handle := range themedChecks {
			if win.GetParent(handle) == hwnd || win.GetParent(handle) == 0 {
				delete(themedChecks, handle)
			}
		}
	}
	return result
}

func drawButton(button *walk.PushButton, n *win.NMCUSTOMDRAW) {
	fill, border, text := panelRaised, line, ink
	switch button.Name() {
	case "primary":
		fill, border, text = green, green, bg
	case "secondary":
		fill, border, text = walk.RGB(16, 44, 57), walk.RGB(43, 97, 117), cyan
	case "danger":
		text = danger
	}
	if n.UItemState&win.CDIS_HOT != 0 {
		border = cyan
		fill = walk.RGB(24, 43, 64)
		if button.Name() == "primary" {
			fill, border = walk.RGB(115, 237, 182), walk.RGB(115, 237, 182)
		}
	}
	if n.UItemState&win.CDIS_SELECTED != 0 {
		fill = bg
	}
	if !button.Enabled() {
		text = muted
		border = line
		fill = panel
	}
	brush := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(fill)})
	pen := win.ExtCreatePen(win.PS_GEOMETRIC|win.PS_SOLID, 1, &win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(border)}, 0, nil)
	defer win.DeleteObject(win.HGDIOBJ(brush))
	defer win.DeleteObject(win.HGDIOBJ(pen))
	saved := win.SaveDC(n.Hdc)
	defer win.RestoreDC(n.Hdc, saved)
	// 清除整个按钮区域，使圆角外侧与父面板衔接。
	fillRect(n.Hdc, n.Rc, panel)
	win.SelectObject(n.Hdc, win.HGDIOBJ(brush))
	win.SelectObject(n.Hdc, win.HGDIOBJ(pen))
	diameter := int32(20 * button.DPI() / 96)
	win.RoundRect(n.Hdc, n.Rc.Left+1, n.Rc.Top+1, n.Rc.Right-1, n.Rc.Bottom-1, diameter, diameter)
	win.SetBkMode(n.Hdc, win.TRANSPARENT)
	win.SetTextColor(n.Hdc, win.COLORREF(text))
	font := win.SendMessage(button.Handle(), win.WM_GETFONT, 0, 0)
	if font != 0 {
		win.SelectObject(n.Hdc, win.HGDIOBJ(font))
	}
	content, _ := syscall.UTF16FromString(button.Text())
	r := n.Rc
	win.DrawTextEx(n.Hdc, &content[0], -1, &r, win.DT_CENTER|win.DT_VCENTER|win.DT_SINGLELINE|win.DT_NOPREFIX, nil)
	if n.UItemState&win.CDIS_FOCUS != 0 {
		r.Left += 4
		r.Top += 4
		r.Right -= 4
		r.Bottom -= 4
		win.DrawFocusRect(n.Hdc, &r)
	}
}
