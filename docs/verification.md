# 验证记录

## v0.4.3 真实值输出

- UI、API、MCP、HAR、规则和可选 JSONL 统一返回真实值，Authorization、Cookie、URL 参数、JSON／表单、HTML、纯文本与错误均不脱敏。
- MCP 回归验证两个不同 Authorization 原值均可读取、比较；正文在 8192 字节预览之外变化也能被检出。截断、未完成及加密 CONNECT 内容不会标记为完整比较。
- 二进制输出以 Base64 无损表示，UTF-8 预览边界不拆分字符；正文保留采集、解码和展示截断标记。
- 本地 go test、go vet、actionlint 通过。0.4.3 安装包构建成功，1100×740 原生桌面 15 项自检和实际 CLI stdio／代理冒烟通过。
- 旧版本验证记录保留如下；旧版脱敏描述不适用于 0.4.3。

## v0.4.2 登录与 HTTPS 兼容性

- 应用默认仅解密 capture.hosts；未设置主机或不匹配目标时保持原始 TLS，通过相同上游联网。exclude_hosts 优先，方法／路径筛选不阻断 CONNECT。
- 本地 TLS 登录测试覆盖 NetLens→上游→网站：原始服务器证书、HTTP/2、登录 Cookie 持续有效及 PNG 二维码完整返回。
- 目标 HTTPS 转发测试验证 Host 的默认 443 端口省略形式、Cookie／Origin／Referer、多个 Set-Cookie 和响应字节保持一致。
- 缩小解密范围不会截断正在传输的响应；旧解密连接结束后，新连接恢复原始 TLS。
- 透明隧道在单个 HTTP 请求超时之后仍能双向传输；服务退出仍会关闭连接。禁用的已开启开关仍保留绿色状态指示。

## v0.4.1 完整正文与 v0.4.0 原生界面／Clash 上游

- 原生控件圆角、下拉列表、开关、深色表格与分区布局；1100×740 最小窗口通过控件边界自检。
- 代理支持 HTTP 上游链路、HTTPS CONNECT／MITM、半关闭、拒绝自环与不可用上游；开启系统代理前检查上游端口，失败不更改原设置。
- 错标 text/html／text/plain 的完整 JSON（含 UTF-8 BOM）仍经严格解析和脱敏；实际 HTML、文本及二进制由独立完整正文入口读取。
- 真实代理 → MCP 测试覆盖大于 64 KiB 的 HTML 错误页无损分页、请求正文原样读取、UTF-8 边界、非法游标、缺失记录及完整正文 API 的令牌认证。
- gzip／zlib deflate／raw deflate 解码、8 MiB 解压预算、不完整采集提示及不可解码的原始字节保留。
- 本地 Go 测试、go vet、actionlint、原生桌面 15 项自检、CLI stdio 冒烟及安装包构建通过。桌面自检验证完整正文中的尾部与未脱敏字段，再切回脱敏模式确认凭据隐藏。

## v0.3.0 系统集成与桌面优化

- 深蓝工作区和左侧功能栏参考 LabRemote，继续使用原生 Windows 控件。
- 代理测试覆盖 PAC／自动检测恢复、进程重启、跨实例备份保护、外部配置冲突、部分写入回滚及失败后保留恢复文件。
- 证书测试使用真实 CryptoAPI 内存存储，验证精确删除、重复操作及无关证书保留，不修改开发者的根证书信任。
- 桌面自检验证隔离代理恢复、MCP 配置及 AI Markdown 导出。
- 显式启用的隔离 Windows CI runner 验证真实 WinINet 代理切换与恢复。

## v0.2.0 原生桌面软件

- Windows 原生 Win32 控件，桌面二进制使用 Windows GUI 子系统并嵌入 DPI／公共控件 manifest。
- 本地 `go test ./...`、`go vet ./...` 通过。
- 原生消息循环自检覆盖窗口创建、真实代理抓包、详情脱敏、窗口筛选、暂停／恢复、HAR 导出、控制端口无网页、服务退出释放监听地址。
- 安装包同时包含 `NetLens.exe` 与 `netlens-cli.exe`；开始菜单和桌面快捷方式打开原生窗口。
- CI 在隔离 Windows runner 中安装、检查 GUI 子系统和快捷方式、运行已安装桌面自检及 CLI MCP／代理冒烟，再卸载并检查清理。Linux CI 运行 race 检测。

## 历史版本记录

以下内容描述原始版本的验证情况；v0.2.0 已删除 Web UI。

# NetLens 验证记录

## v0.1.1 Windows 安装包

2026-09-30 在 Windows amd64、Go 1.27.0、Inno Setup 6.7.3 验证：

- `go test ./...` 和 `go vet ./...` 通过。
- 编译后的 `netlens.exe version` 输出 `NetLens 0.1.1`。
- 真实 Windows 二进制通过 stdio MCP、11 个工具、代理采集、脱敏、重放、共享控制状态、认证、HAR 和 EOF 退出冒烟测试。
- 安装包和便携 ZIP 成功生成，产物附有 SHA256 校验文件。
- PowerShell 打包与安装验收脚本通过语法检查。
- GitHub Actions 工作流通过 `actionlint v1.7.12` 检查，Web UI 通过 Node.js 语法检查。
- 新增启动 URL 测试验证 IPv4/IPv6 地址和特殊字符令牌，确保令牌只放在 URL fragment。

实际安装、开始菜单快捷方式、卸载清理，以及更新版本的 Linux race 检测由 GitHub Actions 验证；本地未执行 NetLens 安装或真实浏览器交互验收。

## v0.1.0 原始验证记录

验证日期：2026-09-30。环境：Linux amd64、Go 1.26.8，MCP Go SDK v1.8.0。所有自动化网络测试均使用本地测试服务器，不依赖公网业务接口。

## 已执行并通过

```bash
go vet ./...
go test -race ./... -count=1
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ./bin/netlens-linux-amd64 ./cmd/netlens
python3 scripts/smoke.py ./bin/netlens-linux-amd64
```

最终包内 Linux 可执行文件经过真实子进程验证，stdio 冒烟测试输出：

```text
PASS: real stdio MCP handshake, 11 tools, proxy capture, redaction, replay, shared control state, auth, HAR and graceful EOF shutdown
```

## 自动化验证覆盖

| 范围 | 已验证的行为 |
|---|---|
| HTTP 代理 | 请求与响应完整转发、正文大小统计、采集前缀与截断标识、连接头处理、有限响应头、代理自环拒绝 |
| 流式行为 | SSE 首事件及时到达、响应中断时中止下游连接、提前响应与 Expect: 100-continue 的收尾行为 |
| HTTPS | 真实 CA 信任链与 MITM 握手、上游证书不受信任时拒绝、连接复用、CONNECT 透传与预读字节保留 |
| 证书 | 独立根 CA、DNS/IP SAN、密钥权限、无效或不完整证书材料拒绝、并发证书缓存 |
| MCP | 官方 SDK 客户端的旧版 initialize 与新版 discovery、11 个工具、参数 schema、结构化结果、工具错误与 annotations |
| 控制面 | Bearer token、Host、Origin、默认 HTTP 80 端口的省略／显式形式、UI/API/MCP 共享状态 |
| 抓包配置 | 动态 host/method/URL 过滤、暂停仍转发、清除过滤、只有完成后才能判断的条件 |
| 主动调试 | 默认规则／重放关闭、每次重放确认、跨源拒绝、成功重放恰好增加一次请求、父请求关联、Mock 不触达上游、移除规则恢复转发 |
| 异常调试 | 不完整请求体拒绝直接重放、新正文移除旧编码／摘要头、非法控制字符规则原子拒绝、失败重放回执包含请求 ID 和是否保留 |
| 存储 | 深拷贝、更新、稳定游标、条数和字节预算淘汰、轮转 JSONL、不从日志恢复、清空内存与关闭并发 |
| 对外数据 | 请求／响应 JSON、Header、Cookie、URL 参数脱敏；未支持正文隐藏；HAR、统计和可见字段对比 |
| 并发 | 包含 96 个并发代理请求的回归；全部 Go 包通过 race 检测 |

## 验证边界

Web UI 已通过 JavaScript 语法与 HTML/DOM 静态检查，UI 所使用的 REST 路径由集成测试覆盖。本环境缺少 Chromium/Chrome/Firefox 可执行文件，因此没有完成真实图形浏览器的交互和截图验收。

初版没有做大规模持续负载基准、生产网络认证兼容矩阵、Windows/macOS 运行测试或完整第三方 MCP 客户端兼容认证。Windows 本次增量验证见本文件开头。

本版仅实现 README 列出的应用层代理能力。测试通过不表示支持 PCAP、HTTP/3、WebSocket 帧、HTTP trailers、gRPC 完整解码、客户端 mTLS 或证书锁定应用。
