# 首次电脑离线签名：只交回公开文件

请在电脑的本地目录解压本包，先断网也能完成签名；需要 Python 3.8+ 和 OpenSSL（可使用 Git for Windows 附带版本）。测试已在 Linux/OpenSSL3.5.9 和真实 Java 验签实现上通过，Windows/macOS 尚待本机核验。工具不发网络请求、不安装依赖。

## 一条命令

Windows 双击 `tools/first-sign.cmd`；macOS/Linux 在包根目录运行 `sh tools/first-sign.sh`。脚本使用仓库根目录固定路径和已确认的发布地址：`https://xunianooo.github.io/allin-rules/current.bin`。

脚本让你交互设置私钥口令（输入不显示），生成加密 RSA3072 私钥到用户主目录 `.allin-rules/private.pem`，公钥到 `out/public`，再输入一次私钥口令完成 `out/first-sign`。已有密钥和公钥完整时不会重建；只完成一部分时停止让你核查，绝不静默轮换。若已有 `out/first-sign`，请先检查已有产物，不重复覆盖。

如不使用脚本，也可在包根目录手动执行：

```text
python tools/rules_tool.py init-key --out out/public
python tools/rules_tool.py prepare rules/source.json --public out/public/public.pem
python tools/rules_tool.py finish rules/source.json --private <用户主目录>/.allin-rules/private.pem --public out/public/public.pem --url https://xunianooo.github.io/allin-rules/current.bin --out-dir out/first-sign
python tools/rules_tool.py verify out/first-sign/current.bin --public out/first-sign/public.pem
```

先创建 `out` 目录。将 `<用户主目录>` 换为电脑实际路径，Windows 路径可用双引号包裹。首次 `init-key` 会提示口令两次，`finish` 再输入一次。`prepare` 展示公钥 SHA256 指纹，可在手机端接入时独立核对。

## 交回什么

仅将 `out/first-sign` 中三个文件发回手机：`current.bin`、`public.pem`、`trust.json`；同时告诉 Eta 终端显示的公钥 SHA256 指纹。它们都是公开文件。公钥和 trust.json 可公开，只有管理员确认后APK才固定对应信任。

**不要交回私钥文件，也不要在聊天中发送私钥口令。** 私钥保存在电脑用户目录之外于本包；请自行离线备份密文私钥和口令，遗失会影响以后发布，APK密钥轮换需再次发版。

收到公开文件后，手机端将重新独立验签/核对指纹，把签名包发布至公开站点 `current.bin` 并验证下载，把公钥和固定 URL 嵌进 APK，再完成一键检查/更新/重启缓存回读。当前线上只有 endpoint-probe.bin 传输探针，没有生产签名 current.bin；不得把探针当规则。

## 后续更新

在电脑修改 `rules/source.json`、增加三段数字 `ruleVersion`，先核变化。保留已发布的签名包和公钥，使用 `sign` 在该已存在的签名输出路径签署可验证的新版本；工具拒绝降版和同版本不同内容。不要删除历史包后声称工具能获知服务器历史。每次只发布签名信封和对应公开规则，私钥一直留在电脑。
