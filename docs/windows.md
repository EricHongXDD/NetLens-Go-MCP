# Windows 原生桌面软件

## 安装与使用

运行 `NetLens-版本-windows-amd64-setup.exe`，默认以当前用户权限安装到 `%LOCALAPPDATA%\Programs\NetLens`。支持 Windows 10/11 x64，ARM64 可使用系统 x64 仿真。

开始菜单的 **NetLens** 打开中文原生窗口；安装向导提供可选桌面快捷方式，并添加用户数据目录、指南及卸载入口。程序直接使用 Windows 控件，不使用浏览器或 WebView，也不显示控制台。

窗口自动启动代理 `127.0.0.1:8080` 和 API/MCP 服务 `127.0.0.1:9090`。测试应用需要配置代理，流量表会自动刷新。选中请求可查看脱敏概览、请求、响应和 JSON；可以筛选、分页、暂停记录、导出 HAR、设置比较基准、比较请求。规则和重放需要先停止服务，在窗口勾选对应权限后重新启动。

HTTPS 解密需要在窗口勾选并重启服务，且测试客户端明确信任 `%APPDATA%\NetLens\ca\ca.pem`。软件不会自动修改系统代理或系统证书信任。关闭窗口会停止服务；同一端口只能运行一个实例。

用户数据默认位于 `%APPDATA%\NetLens`，包括令牌、CA 和可选脱敏日志。升级、卸载保留用户数据；重新安装复用令牌与 CA。

## MCP 与命令行

连接当前桌面实例时，点击 **MCP 连接** 获取 Streamable HTTP 配置和令牌。API/MCP 共用窗口中的记录，控制端口不提供网页。

stdio 使用独立的 `netlens-cli.exe`，参考安装目录的 `examples/mcp-windows.json`。替换模板中的用户和安装目录为实际绝对路径。stdio 客户端启动子进程前结束占用同一端口的桌面实例；客户端断开后子进程退出。

```powershell
$cli = Join-Path $env:LOCALAPPDATA 'Programs\NetLens\netlens-cli.exe'
& $cli version
& $cli serve --mitm --allow-rules --allow-replay
```

桌面程序可从命令行指定启动参数：

```powershell
$desktop = Join-Path $env:LOCALAPPDATA 'Programs\NetLens\NetLens.exe'
& $desktop --proxy 127.0.0.1:8080 --control 127.0.0.1:9090
```

## 自动构建与发布

`.github/workflows/build.yml` 在分支推送、PR 和手动运行时执行 Linux/Windows 测试、Linux race、CLI 冒烟，然后构建并验证 Windows 原生安装包。Windows runner 实际安装，验证 GUI 子系统、开始菜单快捷方式、原生窗口功能、MCP 和代理，再卸载检查清理。

普通构建从 Actions 运行的 **Artifacts → NetLens-windows-amd64** 下载，保留 30 天。推送 `vMAJOR.MINOR.PATCH` 标签后，工作流将标签版本注入程序，并把安装包、便携 ZIP 和 SHA256 校验文件发布到 Releases。

```powershell
git tag v0.2.0
git push origin v0.2.0
```

## 源码构建与打包

安装 Go 1.26+，在项目根目录运行：

```powershell
./scripts/build-desktop.ps1
./bin/NetLens.exe
```

打包还需要 [Inno Setup](https://jrsoftware.org/isdl.php)：

```powershell
./scripts/package-windows.ps1 -Version 0.2.0 -ISCC 'C:\实际路径\ISCC.exe'
```

构建脚本生成公共控件及 DPI manifest 资源并编译 GUI 程序。打包结果位于 `dist`，包含安装包、便携 ZIP 和 `SHA256SUMS.txt`。本地打包不安装软件；安装验收只在隔离 CI runner 中执行。
