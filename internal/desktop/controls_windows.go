//go:build windows

package desktop

import (
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// 只接管绘制，选择、键盘导航、屏幕阅读器和消息循环仍由原生控件负责。
type paintedControl struct {
	original uintptr
	widget   walk.Window
	kind     string
	combo    *walk.ComboBox
	tabs     *walk.TabWidget
	table    *walk.TableView
}

var paintedControls = map[win.HWND]*paintedControl{}
var roundedSizes = map[win.HWND]walk.Size{}
var paintedProc = syscall.NewCallback(paintedWndProc)
var createRoundRegion = syscall.NewLazyDLL("gdi32.dll").NewProc("CreateRoundRectRgn")
var setWindowRegion = syscall.NewLazyDLL("user32.dll").NewProc("SetWindowRgn")

func installPaint(hwnd win.HWND, c *paintedControl) {
	if _, exists := paintedControls[hwnd]; exists || hwnd == 0 {
		return
	}
	c.original = win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, paintedProc)
	paintedControls[hwnd] = c
}

func setupModernControl(widget walk.Window) {
	hwnd := widget.Handle()
	switch c := widget.(type) {
	case *walk.Composite:
		if c.Name() == "card" || c.Name() == "input-shell" {
			installPaint(hwnd, &paintedControl{widget: c, kind: c.Name()})
			roundControl(hwnd, c, 12)
		}
	case *walk.Label:
		if c.Name() == "brand" {
			installPaint(hwnd, &paintedControl{widget: c, kind: "brand"})
			roundControl(hwnd, c, 12)
		}
	case *walk.LineEdit:
		if c.Parent().Name() == "input-shell" {
			removeEditBorder(c)
			installPaint(hwnd, &paintedControl{widget: c, kind: "edit"})
		}
	case *walk.TextEdit:
		removeEditBorder(c)
	case *walk.CheckBox:
		c.SetMinMaxSize(walk.Size{Width: 118, Height: 22}, walk.Size{})
		installPaint(hwnd, &paintedControl{widget: c, kind: "switch"})
		c.CheckedChanged().Attach(func() { c.Invalidate() })
	case *walk.ComboBox:
		empty, _ := syscall.UTF16PtrFromString("")
		win.SetWindowTheme(hwnd, empty, empty)
		installPaint(hwnd, &paintedControl{widget: c, kind: "combo", combo: c})
		setupComboMetrics(c)
		c.CurrentIndexChanged().Attach(func() { c.Invalidate() })
		// 下拉列表保留系统的弹出、滚动和选择语义，统一绘制选中行。
		var info struct {
			Size              uint32
			Item, Button      win.RECT
			State             uint32
			Combo, Edit, List win.HWND
		}
		info.Size = uint32(unsafe.Sizeof(info))
		win.SendMessage(hwnd, win.CB_GETCOMBOBOXINFO, 0, uintptr(unsafe.Pointer(&info)))
		if info.List != 0 {
			win.SetWindowTheme(info.List, empty, empty)
			style := win.GetWindowLongPtr(info.List, win.GWL_STYLE)
			ex := win.GetWindowLongPtr(info.List, win.GWL_EXSTYLE)
			win.SetWindowLongPtr(info.List, win.GWL_STYLE, style&^win.WS_BORDER)
			win.SetWindowLongPtr(info.List, win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
			installPaint(info.List, &paintedControl{widget: c, kind: "combo-list", combo: c})
		}
	case *walk.TabWidget:
		child := childByClass(hwnd, "SysTabControl32")
		if child != 0 {
			installPaint(child, &paintedControl{widget: c, kind: "tabs", tabs: c})
			// 增加标签页点击区域，原生布局按此高度重新计算内容区。
			win.SendMessage(child, win.TCM_SETPADDING, 0, uintptr(14*c.DPI()/96)|uintptr(9*c.DPI()/96)<<16)
			c.SetBoundsPixels(c.BoundsPixels())
		}
	case *walk.TableView:
		removeEditBorder(c)
		for child := win.GetWindow(hwnd, win.GW_CHILD); child != 0; child = win.GetWindow(child, win.GW_HWNDNEXT) {
			if windowClass(child) == "SysListView32" {
				installPaint(child, &paintedControl{widget: c, kind: "table-list"})
				setListColors(child)
				style := win.GetWindowLongPtr(child, win.GWL_STYLE)
				win.SetWindowLongPtr(child, win.GWL_STYLE, style|win.LVS_NOSORTHEADER)
				header := win.HWND(win.SendMessage(child, win.LVM_GETHEADER, 0, 0))
				installPaint(header, &paintedControl{widget: c, kind: "table-header", table: c})
			}
		}
	}
}

func windowClass(hwnd win.HWND) string {
	var name [256]uint16
	win.GetClassName(hwnd, &name[0], len(name))
	return syscall.UTF16ToString(name[:])
}

func childByClass(parent win.HWND, class string) win.HWND {
	for child := win.GetWindow(parent, win.GW_CHILD); child != 0; child = win.GetWindow(child, win.GW_HWNDNEXT) {
		if windowClass(child) == class {
			return child
		}
	}
	return 0
}

func setListColors(hwnd win.HWND) {
	win.SendMessage(hwnd, win.LVM_SETBKCOLOR, 0, uintptr(panel))
	win.SendMessage(hwnd, win.LVM_SETTEXTBKCOLOR, 0, uintptr(panel))
	win.SendMessage(hwnd, win.LVM_SETTEXTCOLOR, 0, uintptr(ink))
	style := win.SendMessage(hwnd, win.LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0)
	win.SendMessage(hwnd, win.LVM_SETEXTENDEDLISTVIEWSTYLE, 0, style&^win.LVS_EX_GRIDLINES)
}

func removeEditBorder(c walk.Window) {
	hwnd := c.Handle()
	style := win.GetWindowLongPtr(hwnd, win.GWL_STYLE)
	ex := win.GetWindowLongPtr(hwnd, win.GWL_EXSTYLE)
	win.SetWindowLongPtr(hwnd, win.GWL_STYLE, style&^win.WS_BORDER)
	win.SetWindowLongPtr(hwnd, win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
	win.SetWindowPos(hwnd, 0, 0, 0, 0, 0, win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_FRAMECHANGED)
}

func setupComboMetrics(c *walk.ComboBox) {
	height := uintptr(34 * c.DPI() / 96)
	win.SendMessage(c.Handle(), win.CB_SETITEMHEIGHT, ^uintptr(0), height)
	win.SendMessage(c.Handle(), win.CB_SETITEMHEIGHT, 0, height)
}

func roundControl(hwnd win.HWND, widget walk.Window, radius int) {
	var r win.RECT
	win.GetClientRect(hwnd, &r)
	if r.Right <= 0 || r.Bottom <= 0 {
		return
	}
	size := walk.Size{Width: int(r.Right), Height: int(r.Bottom)}
	if roundedSizes[hwnd] == size {
		return
	}
	roundedSizes[hwnd] = size
	diameter := uintptr(radius * 2 * widget.DPI() / 96)
	region, _, _ := createRoundRegion.Call(0, 0, uintptr(r.Right+1), uintptr(r.Bottom+1), diameter, diameter)
	if region != 0 {
		result, _, _ := setWindowRegion.Call(uintptr(hwnd), region, 1)
		// 成功时区域归系统所有，失败时由调用方释放。
		if result == 0 {
			win.DeleteObject(win.HGDIOBJ(region))
		}
	}
}

func paintedWndProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	c := paintedControls[hwnd]
	if c == nil {
		return win.DefWindowProc(hwnd, msg, wp, lp)
	}
	ownPaint := c.kind == "combo" || c.kind == "combo-list" || c.kind == "switch" || c.kind == "tabs" || c.kind == "table-header"
	if ownPaint && (msg == win.WM_PAINT || msg == win.WM_PRINTCLIENT) {
		var ps win.PAINTSTRUCT
		dc := win.HDC(wp)
		if msg == win.WM_PAINT {
			dc = win.BeginPaint(hwnd, &ps)
			defer win.EndPaint(hwnd, &ps)
		}
		if dc != 0 {
			paintNativeControl(hwnd, dc, c)
		}
		return 0
	}
	if ownPaint && msg == win.WM_ERASEBKGND {
		return 1
	}
	result := win.CallWindowProc(c.original, hwnd, msg, wp, lp)
	switch msg {
	case win.WM_SETFONT:
		if c.kind == "combo" {
			setupComboMetrics(c.combo)
		}
	case win.WM_THEMECHANGED:
		if c.kind == "table-list" {
			setListColors(hwnd)
		}
	case win.WM_PAINT:
		if c.kind == "card" || c.kind == "input-shell" {
			dc := win.GetDC(hwnd)
			if dc != 0 {
				drawShell(hwnd, dc, c)
				win.ReleaseDC(hwnd, dc)
			}
		}
		const lvmGetItemCount = 0x1004
		if c.kind == "table-list" && win.SendMessage(hwnd, lvmGetItemCount, 0, 0) == 0 {
			dc := win.GetDC(hwnd)
			if dc != 0 {
				saved := win.SaveDC(dc)
				var r win.RECT
				win.GetClientRect(hwnd, &r)
				selectControlFont(dc, c.widget.Handle())
				r.Top += int32(36 * c.widget.DPI() / 96)
				drawNativeText(dc, "等待流量 · 开启系统代理或配置应用代理后开始采集", r, muted, win.DT_CENTER)
				win.RestoreDC(dc, saved)
				win.ReleaseDC(hwnd, dc)
			}
		}
	case win.WM_SIZE, win.WM_WINDOWPOSCHANGED:
		if c.kind == "card" || c.kind == "input-shell" || c.kind == "brand" {
			roundControl(hwnd, c.widget, 12)
		}
		if c.kind == "combo-list" {
			roundControl(hwnd, c.widget, 10)
		}
	case win.WM_SETFOCUS, win.WM_KILLFOCUS, win.WM_ENABLE, win.WM_LBUTTONDOWN, win.WM_LBUTTONUP, win.WM_MOUSEMOVE, win.WM_KEYDOWN, win.WM_KEYUP, win.WM_MOUSEWHEEL, win.WM_VSCROLL:
		if ownPaint {
			win.InvalidateRect(hwnd, nil, false)
		}
		if c.kind == "edit" {
			win.InvalidateRect(win.GetParent(hwnd), nil, false)
		}
	case 0x02e3: // WM_DPICHANGED_AFTERPARENT
		delete(roundedSizes, hwnd)
		if c.kind == "combo" {
			setupComboMetrics(c.combo)
		}
		if c.kind == "card" || c.kind == "input-shell" {
			roundControl(hwnd, c.widget, 12)
		}
	case win.WM_NCDESTROY:
		delete(paintedControls, hwnd)
		delete(roundedSizes, hwnd)
	}
	return result
}

func paintNativeControl(hwnd win.HWND, dc win.HDC, c *paintedControl) {
	saved := win.SaveDC(dc)
	defer win.RestoreDC(dc, saved)
	var r win.RECT
	win.GetClientRect(hwnd, &r)
	selectControlFont(dc, c.widget.Handle())
	dpi := c.widget.DPI()
	px := func(n int) int32 { return int32(n * dpi / 96) }
	switch c.kind {
	case "combo":
		fillRect(dc, r, panel)
		color := line
		if win.GetFocus() == hwnd || win.SendMessage(hwnd, win.CB_GETDROPPEDSTATE, 0, 0) != 0 {
			color = green
		}
		r.Left++
		r.Top++
		r.Right--
		r.Bottom--
		drawRound(dc, r, panelRaised, color, px(20))
		textBounds := r
		textBounds.Left += px(12)
		textBounds.Right -= px(30)
		drawNativeText(dc, c.combo.Text(), textBounds, ink, win.DT_LEFT)
		x, y := r.Right-px(17), (r.Top+r.Bottom)/2
		pen := win.ExtCreatePen(win.PS_GEOMETRIC|win.PS_SOLID, 2, &win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(muted)}, 0, nil)
		old := win.SelectObject(dc, win.HGDIOBJ(pen))
		points := []win.POINT{{X: x - px(4), Y: y - px(2)}, {X: x, Y: y + px(2)}, {X: x + px(4), Y: y - px(2)}}
		win.Polyline(dc, unsafe.Pointer(&points[0]), int32(len(points)))
		win.SelectObject(dc, old)
		win.DeleteObject(win.HGDIOBJ(pen))
	case "combo-list":
		fillRect(dc, r, panelRaised)
		count := int(win.SendMessage(hwnd, win.LB_GETCOUNT, 0, 0))
		selected := int(win.SendMessage(hwnd, win.LB_GETCURSEL, 0, 0))
		top := int(win.SendMessage(hwnd, win.LB_GETTOPINDEX, 0, 0))
		items, _ := c.combo.Model().([]string)
		for i := max(0, top); i < count; i++ {
			var item win.RECT
			if int32(win.SendMessage(hwnd, win.LB_GETITEMRECT, uintptr(i), uintptr(unsafe.Pointer(&item)))) == -1 || item.Top >= r.Bottom {
				break
			}
			item.Left += px(4)
			item.Right -= px(4)
			item.Top += px(2)
			item.Bottom -= px(2)
			color := ink
			if i == selected {
				drawRound(dc, item, walk.RGB(25, 60, 49), walk.RGB(25, 60, 49), px(12))
				color = green
			}
			item.Left += px(10)
			if i < len(items) {
				drawNativeText(dc, items[i], item, color, win.DT_LEFT)
			}
		}
	case "switch":
		fillRect(dc, r, panel)
		check := c.widget.(*walk.CheckBox)
		track := win.RECT{Left: px(1), Top: (r.Bottom - px(18)) / 2, Right: px(33), Bottom: (r.Bottom + px(18)) / 2}
		fill, border, thumb := panelRaised, line, muted
		if check.Checked() {
			fill, border, thumb = walk.RGB(23, 65, 49), walk.RGB(43, 100, 73), green
		}
		text := ink
		if !check.Enabled() {
			fill, border, thumb = panelRaised, line, muted
			text = muted
		}
		if win.GetFocus() == hwnd {
			border = green
		}
		drawRound(dc, track, fill, border, px(18))
		knob := track
		knob.Left += px(3)
		knob.Right = knob.Left + px(12)
		knob.Top += px(3)
		knob.Bottom -= px(3)
		if check.Checked() {
			knob.Left += px(14)
			knob.Right += px(14)
		}
		drawRound(dc, knob, thumb, thumb, px(12))
		textRect := r
		textRect.Left = px(42)
		drawNativeText(dc, check.Text(), textRect, text, win.DT_LEFT)
	case "tabs":
		fillRect(dc, r, panel)
		for i := 0; i < c.tabs.Pages().Len(); i++ {
			var item win.RECT
			win.SendMessage(hwnd, win.TCM_GETITEMRECT, uintptr(i), uintptr(unsafe.Pointer(&item)))
			item.Left += px(2)
			item.Right -= px(2)
			item.Top += px(3)
			item.Bottom -= px(3)
			text := muted
			if i == c.tabs.CurrentIndex() {
				drawRound(dc, item, panelRaised, line, px(16))
				text = green
			}
			drawNativeText(dc, c.tabs.Pages().At(i).Title(), item, text, win.DT_CENTER)
		}
	case "table-header":
		fillRect(dc, r, panelRaised)
		for i := 0; i < c.table.Columns().Len(); i++ {
			var item win.RECT
			if win.SendMessage(hwnd, win.HDM_GETITEMRECT, uintptr(i), uintptr(unsafe.Pointer(&item))) != 0 {
				item.Left += px(10)
				drawNativeText(dc, c.table.Columns().At(i).Title(), item, muted, win.DT_LEFT)
			}
		}
	}
}

func drawShell(hwnd win.HWND, dc win.HDC, c *paintedControl) {
	saved := win.SaveDC(dc)
	var r win.RECT
	win.GetClientRect(hwnd, &r)
	r.Right--
	r.Bottom--
	border := line
	if c.kind == "input-shell" && win.GetParent(win.GetFocus()) == hwnd {
		border = green
	}
	pen := win.ExtCreatePen(win.PS_GEOMETRIC|win.PS_SOLID, 1, &win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(border)}, 0, nil)
	win.SelectObject(dc, win.HGDIOBJ(pen))
	win.SelectObject(dc, win.GetStockObject(win.NULL_BRUSH))
	diameter := int32(24 * c.widget.DPI() / 96)
	win.RoundRect(dc, r.Left, r.Top, r.Right, r.Bottom, diameter, diameter)
	win.RestoreDC(dc, saved)
	win.DeleteObject(win.HGDIOBJ(pen))
}

func fillRect(dc win.HDC, r win.RECT, color walk.Color) {
	b := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(color)})
	oldB := win.SelectObject(dc, win.HGDIOBJ(b))
	oldP := win.SelectObject(dc, win.GetStockObject(win.NULL_PEN))
	win.RoundRect(dc, r.Left, r.Top, r.Right+1, r.Bottom+1, 0, 0)
	win.SelectObject(dc, oldB)
	win.SelectObject(dc, oldP)
	win.DeleteObject(win.HGDIOBJ(b))
}

func drawRound(dc win.HDC, r win.RECT, fill, border walk.Color, diameter int32) {
	b := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(fill)})
	p := win.ExtCreatePen(win.PS_GEOMETRIC|win.PS_SOLID, 1, &win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(border)}, 0, nil)
	oldB := win.SelectObject(dc, win.HGDIOBJ(b))
	oldP := win.SelectObject(dc, win.HGDIOBJ(p))
	win.RoundRect(dc, r.Left, r.Top, r.Right, r.Bottom, diameter, diameter)
	win.SelectObject(dc, oldB)
	win.SelectObject(dc, oldP)
	win.DeleteObject(win.HGDIOBJ(b))
	win.DeleteObject(win.HGDIOBJ(p))
}

func selectControlFont(dc win.HDC, hwnd win.HWND) {
	font := win.SendMessage(hwnd, win.WM_GETFONT, 0, 0)
	if font != 0 {
		win.SelectObject(dc, win.HGDIOBJ(font))
	}
}

func drawNativeText(dc win.HDC, text string, r win.RECT, color walk.Color, alignment uint32) {
	win.SetBkMode(dc, win.TRANSPARENT)
	win.SetTextColor(dc, win.COLORREF(color))
	content, _ := syscall.UTF16FromString(text)
	win.DrawTextEx(dc, &content[0], -1, &r, alignment|win.DT_VCENTER|win.DT_SINGLELINE|win.DT_NOPREFIX|win.DT_END_ELLIPSIS, nil)
}

func (w *window) styleFlowCell(style *walk.CellStyle) {
	style.TextColor = ink
	if style.Row() < 0 {
		if canvas := style.Canvas(); canvas != nil {
			r := style.BoundsPixels()
			dc := canvas.HDC()
			rect := win.RECT{Left: int32(r.X), Top: int32(r.Y), Right: int32(r.X + r.Width), Bottom: int32(r.Y + r.Height)}
			fillRect(dc, rect, panelRaised)
			rect.Left += int32(10 * w.mw.DPI() / 96)
			drawNativeText(dc, w.table.Columns().At(style.Col()).Title(), rect, muted, win.DT_LEFT)
		}
		return
	}
	style.BackgroundColor = panel
	if style.Row()%2 == 1 {
		style.BackgroundColor = walk.RGB(14, 26, 42)
	}
	if style.Row() == w.table.CurrentIndex() {
		style.BackgroundColor = walk.RGB(25, 53, 58)
	}
	if style.Row() < len(w.model.items) {
		if style.Col() == 1 {
			style.TextColor = cyan
		}
		if style.Col() == 2 {
			style.TextColor = green
			if w.model.items[style.Row()].StatusCode >= 400 {
				style.TextColor = danger
			}
		}
	}
}
