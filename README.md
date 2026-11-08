# Xdecrypt Rust 1.1.0

Windows x64 图形界面会话密码恢复工具，针对用户本人或获授权管理的 Xshell / Xftp 会话。纯 Rust 应用，无需 Python、.NET 或 WebView2。运行时无需联网。

## 使用

1. 运行安装包，或解压 portable.zip 后启动 `xdecrypt-rust.exe`。
2. 启动时自动搜索当前用户 Documents 中 `NetSarang Computer\6`、`7`、`8` 下的会话，包含子目录。点击“自动搜索”可刷新；自定义位置使用“搜索目录…”。也可用“选择文件 / XTS…”直接选择 `.xsh`、`.xfp` 或 `.xts`。一次最多处理 1000 个会话。
3. 启动时会填入当前 **Windows 用户名和 SID**。请确认它们是保存会话时的账户信息。这里不是服务器登录账号；迁移的文件需要改为原账户信息。
4. 选择“自动识别”或具体版本，点击“开始恢复”。
5. 校验通过后勾选“显示密码”。窗口失去焦点时自动隐藏；点击“清空”释放当前结果。

自动发现只枚举默认目录中的文件名；点击“开始恢复”后才读取会话内容并解密。搜索范围限于当前用户默认目录或手动指定的目录，不搜索其他用户，不跟随符号链接/目录联接。使用 Windows 已知文件夹 API 识别重定向的 Documents；权限不足或达到搜索上限时显示提示。

XTS 按 ZIP 导出包读取其中的 `.xsh/.xfp`，支持 Stored / Deflate 压缩、子目录和 UTF-16 会话，不落盘解压。限制为 100 MiB 压缩包、单会话 2 MiB、会话解压合计 32 MiB；损坏包、不安全路径、加密 ZIP 条目会明确报错。XTS 是容器支持，密码解密仍受下表兼容范围限制。导出时若勾选“清除密码”，无法恢复不存在的密码。

应用不修改会话，不写出恢复密码、不记录密码日志，不向网络发送数据。显示后的文字仍可能存在于操作系统/图形缓存中，不能据此保证内存取证安全。

## 兼容范围与证据

| 范围 | 当前状态 |
| --- | --- |
| Xshell / Xftp 6 的用户名 + SID 规则 | 已实现，独立 Python 测试向量通过 |
| Xshell 7 / 8 的反转 SID + 用户名规则 | 已实现，独立 Python 测试向量通过 |
| Xshell 8 会话解析 | 合成 `.xsh` 文件端到端测试通过；尚无真实 Xshell 8 导出样本验收 |
| UTF-8 / 带 BOM 的 UTF-16 LE/BE / GBK | 已实现 |
| XTS 导出包 | 已实现标准 ZIP 中的会话导入，合成 Stored/Deflate 包测试；真实导出包待验收 |
| 主密码保护、认证配置文件、其他新版格式 | 暂不支持，校验失败或没有保存密码时明确提示 |
| 非 ASCII Windows 用户名 | 当前不支持，明确提示；恢复的密码支持 UTF-8 |

自动识别只尝试两种已知的账户密钥规则；每次必须通过文件中的 SHA-256 完整性校验才显示密码，不猜测密码。Xshell 8 可能使用此前迁移的旧格式，遇到失败可用“自动识别”。不能将算法测试等同于所有 Xshell 8 构建版本的兼容验收。

参考资料：

- 用户指定项目：[dzxs/Xdecrypt](https://github.com/dzxs/Xdecrypt)，算法参考文件 `Xdecrypt.py`，Git blob `2a6795ef0b809c76fdabc4e87c528dd8bbbc90d7`。
- 7/8 兼容规则交叉核对：[ssmmtt/Xpass](https://github.com/ssmmtt/Xpass)，`Xclass.cs`，Git blob `f618a79de776c61c041d27a12cab2453baea7114`。
- [NetSarang Xshell 8 官方手册](https://www.netsarang.com/docs/Xshell8_manual.pdf)说明主密码会参与会话加密。
- [NetSarang 官方 XTS 格式说明](https://netsarang.atlassian.net/wiki/spaces/ENSUP/pages/1504740120/How+can+I+use+my+Version+6+sessions+in+Version+5+File+Encoding+Conversions+Batch+Conversions)：XTS 是 ZIP 格式，Xshell 6 起使用 UTF-16 会话。

本项目独立编写 Rust 实现、界面与安装脚本，未捆绑上游 Python/C# 源文件。上游参考项目的授权不由本仓库授予。构建产物附带 Rust 依赖的第三方声明。

## 构建与验证

需要 Rust 1.95+、Windows MSVC 构建环境和 NSIS 3：

```powershell
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
./packaging/build.ps1 -MakensisPath 'C:\path\to\NSIS\makensis.exe'
```

脚本生成 release 可执行文件、安装程序、免安装 ZIP、源码 ZIP 和 SHA-256 清单。依赖固定在 Cargo.lock。首次构建需要下载依赖；运行应用无需联网。

脚本默认允许下载构建依赖；已有缓存时可加 `-Offline`。安装包版本从 `Cargo.toml` 自动读取，无需修改 NSIS 脚本。

## GitHub Actions

[查看自动构建](https://github.com/gooddayday009/xshell-decrypt/actions/workflows/windows.yml)

- 推送 `main`、向 `main` 提交 PR 或在 Actions 页面手动运行：执行格式检查、测试、Clippy，并构建 Windows x64 安装包、免安装 ZIP、源码 ZIP 和校验清单。成功后在该次运行的 Artifacts 中下载，保留 30 天。
- 推送与 `Cargo.toml` 版本一致的标签（例如 `v1.1.0`）：通过上述检查后自动创建 GitHub Release 并上传产物。普通分支构建不发布 Release。
- 工作流使用 GitHub 自带的 `GITHUB_TOKEN`，不需要配置个人令牌。仅 Release 作业获得仓库写权限。

发布新版本时先修改 `Cargo.toml` 版本并更新 `Cargo.lock`，提交到 `main` 后再推送对应的 `v版本号` 标签。安装包未签名；Actions 成功不代表真实会话和安装卸载流程已人工验收。

`tests/fixtures/xshell8-synthetic.xsh` 仅为合成测试文件：Windows 用户名 `testuser`，SID `S-1-5-21-111-222-333-1001`，测试密码 `Test-only_密码!`。它不是从实际 Xshell 8 导出的兼容性证据。

安装仅面向当前 Windows 用户，在开始菜单创建快捷方式，可从系统应用列表卸载。安装包未做代码签名。
