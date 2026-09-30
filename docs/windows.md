# Windows 安装与发布

## 安装

从 GitHub 的 Releases 页面下载 `NetLens-版本-windows-amd64-setup.exe` 并运行。安装面向 Windows 10/11 x64（ARM64 可通过系统 x64 仿真运行），使用当前用户权限，默认目录为 `%LOCALAPPDATA%\Programs\NetLens`。

安装后开始菜单的 **NetLens** 文件夹包含启动入口、用户数据目录、使用指南和卸载入口。安装向导还提供可选桌面快捷方式。程序使用英文安装向导，Web 界面为中文。

点击 **NetLens** 会启动本地代理并打开默认浏览器，自动连接控制服务。令牌仅保存在页面内存中；地址中的 fragment 读取后立即移除，刷新页面后需要重新输入令牌。代理地址为 `127.0.0.1:8080`，Web UI 为 `http://127.0.0.1:9090/`。

程序运行期间保留控制台窗口，使用 `Ctrl+C` 正常退出。再次启动前先结束原实例。程序默认不修改系统代理、不自动信任 CA，也不开启 HTTPS 解密、规则或重放。

用户数据默认位于 `%APPDATA%\NetLens`，包括 `control.token`、CA 和可选脱敏日志。升级和卸载保留这些数据；重新安装会复用令牌与 CA。安装目录和用户数据目录相互独立。

## PowerShell 启动

```powershell
$netlens = Join-Path $env:LOCALAPPDATA 'Programs\NetLens\netlens.exe'
& $netlens version
& $netlens serve --open
```

需要自定义启动权限时，先结束原实例，再使用：

```powershell
& $netlens serve --open --mitm --allow-rules --allow-replay
```

只添加你需要的选项。HTTPS 测试客户端需要明确信任 `%APPDATA%\NetLens\ca\ca.pem`。浏览器刷新后可从开始菜单的用户数据目录打开 `control.token`，复制到页面令牌框。

## MCP

`examples/mcp-windows.json` 是 Windows stdio 模板。将 `YOUR_USER` 和安装目录替换成实际绝对路径，JSON 中反斜杠需要写成 `\\`。客户端启动 stdio 子进程前结束开始菜单启动的实例，因为同一端口只允许一个进程监听。

希望继续使用开始菜单启动的实例时，使用 `examples/mcp-http.json`，将令牌替换为用户数据目录中 `control.token` 的内容。

## 自动构建

`.github/workflows/build.yml` 在以下情况下运行：

- 推送分支：Linux/Windows 测试、Linux race 检测、真实二进制冒烟，然后生成 Windows 安装包。
- Pull request：相同测试和安装包验证，供合并前检查。
- Actions 页手动运行：使用源码的默认版本构建安装包。
- 推送 `vMAJOR.MINOR.PATCH` 标签：将标签版本注入程序，验证安装后将安装包、便携 ZIP 和 SHA256 校验文件发布到 Releases。

普通推送的安装包位于对应 Actions 运行的 **Artifacts → NetLens-windows-amd64**，保留 30 天。标签发布的文件位于 Releases，适合直接分发。

构建使用固定 SHA 的 GitHub Actions，以及固定版本并校验 SHA256 的 Inno Setup 编译器。Windows runner 会实际安装、检查开始菜单快捷方式和版本、运行已安装程序的 MCP/代理冒烟测试，再卸载并检查清理结果。

发布示例：

```powershell
git tag v0.1.1
git push origin v0.1.1
```

## 本地打包

先安装 Go 1.26+ 和 [Inno Setup](https://jrsoftware.org/isdl.php)，在项目根目录运行：

```powershell
./scripts/package-windows.ps1 -Version 0.1.1
```

如果编译器不在默认位置，用 `-ISCC 'C:\实际路径\ISCC.exe'` 指定。结果位于 `dist`，包括安装包、便携 ZIP 和 `SHA256SUMS.txt`。本地打包不安装 NetLens；安装验收脚本只允许在隔离的 GitHub Actions runner 中运行。
