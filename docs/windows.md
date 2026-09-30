# Windows 原生桌面软件

## 安装与使用

运行 `NetLens-版本-windows-amd64-setup.exe`，默认以当前用户权限安装到 `%LOCALAPPDATA%\Programs\NetLens`。支持 Windows 10/11 x64，ARM64 可使用系统 x64 仿真。

开始菜单的 **NetLens** 打开中文原生窗口；安装向导提供可选桌面快捷方式，并添加用户数据目录、指南及卸载入口。程序直接使用 Windows 控件，不使用浏览器或 WebView，也不显示控制台。

窗口自动启动代理 `127.0.0.1:8080` 和 API/MCP 服务 `127.0.0.1:9090`。桌面上游默认 `127.0.0.1:7890`；没有 Clash 或其他上游时清空“上游”后点击开启系统代理，或停止并重新启动服务应用直连设置。测试应用需要配置代理，流量表会自动刷新。选中请求可查看脱敏概览、请求、响应和 JSON；可以筛选、分页、暂停记录、导出 HAR、设置比较基准、比较请求。规则和重放需要先停止服务，在窗口勾选对应权限后重新启动。

目标 HTTPS 解密需要在窗口勾选并重启服务，再填写主机并点击“同时应用为采集条件”（或由 MCP 设置 filter.hosts）；未设置目标时 HTTPS 默认透传，非目标站点也不会被解密。测试客户端需明确信任 `%APPDATA%\NetLens\ca\ca.pem`。左侧“安装／检查／移除”按钮管理本实例 CA 的用户级信任；“开启系统代理”切换当前用户的 HTTP/HTTPS 代理，“恢复原代理”恢复开启前的手动代理、PAC、绕过列表和自动检测设置。关闭窗口或停止服务时自动恢复本窗口开启的代理；同一端口只能运行一个实例。

用户数据默认位于 `%APPDATA%\NetLens`，包括令牌、CA 和可选脱敏日志。升级、卸载保留用户数据；重新安装复用令牌与 CA。

## 证书与系统代理

- **安装证书**：确认后仅将本实例公开 CA 导入当前用户根证书存储，不导入私钥，不修改机器级信任。Windows 可能要求额外的系统确认，取消时软件会报告失败。
- **检查证书**：显示 SHA-256 指纹、有效期、用户／机器信任状态及证书路径。
- **移除证书**：只删除完整证书精确匹配的用户级信任；本地 CA 文件和其他根证书保留。机器级信任需管理员自行处理。
- **开启系统代理**：必须先启动服务。暂时关闭 PAC 和自动检测，使用实际监听地址设置 HTTP/HTTPS 代理；本机地址默认绕过。只影响遵循 Windows Internet 设置的应用，不修改 WinHTTP、VPN 或环境变量。
- **恢复原代理**：原配置先写入 `%APPDATA%\NetLens\system-proxy-backup.json` 后才切换。正常退出自动恢复；异常退出后重新打开软件，可手动恢复。恢复失败会保留备份。如果其他程序改变代理，自动恢复不会覆盖，手动恢复会要求确认。

## 与 Clash / VPN 一起抓取

“上游”默认 `127.0.0.1:7890`，支持 HTTP 代理地址及 Clash 的混合端口。网络路径为：

```text
应用 → NetLens 127.0.0.1:8080 → Clash 127.0.0.1:7890 → 网络
```

先运行 Clash 并保持节点／规则配置，再点击 NetLens 的 **开启系统代理**。NetLens 先检查上游端口可达，再切换 Windows 代理；失败时不切换系统代理，并恢复之前的上游路由。Clash 的进程、配置、节点、规则、7890 端口和 TUN 设置保持原状。HTTP、HTTPS 解密、CONNECT 隧道及请求重放均经过上游。

开启期间 Windows 系统代理地址显示为 NetLens 的 8080，Clash 的 7890 继续作为上游。恢复或正常退出后还原开启前的 Windows 代理、PAC、自动检测和绕过设置。不要在抓取期间重新打开 Clash 的“系统代理”开关，否则 Clash 可能把 Windows 代理写回 7890，让应用直接绕过 NetLens。

上游不可用时返回代理连接错误，不会自动绕过 VPN 直连。如果需要明确使用直连，将上游留空后重新开启。只配置了 7890 的独立应用需要改为 8080 才能被 NetLens 抓取；TUN、独立代理和非 HTTP(S) 流量不一定经过 Windows 系统代理。非目标 HTTPS 站点保留原始 TLS 证书、浏览器握手、HTTP/2 和 WebSocket，通过 7890 联网；只记录符合采集条件的 CONNECT 概要，正文仍保持加密。已建立隧道不会在 60 秒 HTTP 请求超时后被切断。缩小解密主机范围时，旧解密连接先完成当前响应，再关闭连接，让后续请求重新以原始 TLS 连接。全站 HTTPS 解密需要显式 --mitm --mitm-all，或 capture.hosts:["*"]。

圆角侧栏完整显示主要操作，流量表和详情上下排列。窗口最小为 `1100×740`，会按可用工作区调整初始大小；滚动限定在流量和长文本详情中。

## MCP 与命令行

请求／响应页默认开启 **完整正文**，直接显示全部保留的 HTML、文本或 JSON（未脱敏）。关闭开关返回脱敏预览；JSON 页始终脱敏。**复制**复制当前请求／响应页；**导出正文**保存当前页的原始采集字节，其他页默认导出响应。默认采集上限 1 MiB，已截断内容会显示提示；超过上限的原文无法事后恢复。MCP 通过 `flows_body` 分页读取，参数 `id`、`side:response`、`offset:0`、`limit:16384`，按 `next_offset` 继续直到 `has_more:false`。

连接当前桌面实例时，点击 **复制 MCP 配置** 一键复制完整 JSON；也可查看 **连接与证书详情**。点击 **导出 AI 操作手册** 保存 UTF-8 Markdown，包含实际地址、令牌、当前权限、12 个工具和排查步骤。手册等同于访问凭据，默认文件名为 `NetLens-AI-Guide.private.md`，请只提供给授权本机客户端。API/MCP 共用窗口中的记录，控制端口不提供网页。

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

`.github/workflows/build.yml` 在分支推送、PR 和手动运行时执行 Linux/Windows 测试、Linux race、CLI 冒烟，然后构建并验证 Windows 原生安装包。Windows runner 实际安装，验证 GUI 子系统、开始菜单快捷方式、原生窗口功能、最小窗口控件裁切、下拉框键盘选择、MCP 和代理，再卸载检查清理。

普通构建从 Actions 运行的 **Artifacts → NetLens-windows-amd64** 下载，保留 30 天。推送 `vMAJOR.MINOR.PATCH` 标签后，工作流将标签版本注入程序，并把安装包、便携 ZIP 和 SHA256 校验文件发布到 Releases。

```powershell
git tag v0.4.2
git push origin v0.4.2
```

## 源码构建与打包

安装 Go 1.26+，在项目根目录运行：

```powershell
./scripts/build-desktop.ps1
./bin/NetLens.exe
```

打包还需要 [Inno Setup](https://jrsoftware.org/isdl.php)：

```powershell
./scripts/package-windows.ps1 -Version 0.4.2 -ISCC 'C:\实际路径\ISCC.exe'
```

构建脚本生成公共控件及 DPI manifest 资源并编译 GUI 程序。打包结果位于 `dist`，包含安装包、便携 ZIP 和 `SHA256SUMS.txt`。本地打包不安装软件；安装验收只在隔离 CI runner 中执行。
