# All In 签名兼容规则

公开规则仓库与电脑离线签名工具。All In 主项目保持私有；本仓库不包含应用源码、用户账号、GitHub凭据或生产私钥。

## 当前状态

- GitHub Pages 已启用，发布 `main` 分支的 `docs` 目录。
- 匿名下载探针 `https://xunianooo.github.io/allin-rules/endpoint-probe.bin` 已实测直接200、Content-Type application/octet-stream、无重定向、正文匹配。它不是规则签名包，应用会拒绝它。
- 约定生产地址 `https://xunianooo.github.io/allin-rules/current.bin`；当前该文件不存在，等待维护者在电脑完成首签。
- 生产公钥尚未确定，应用更新源保持 disabled，不打包测试密钥。
- `rules/source.json` 的1.0.1仅把既有内置1.0.0规则复制为分发引导版，三条规则内容相同，不声称新增厂商兼容。

## 首次接入

按 [FIRST-SIGN.md](FIRST-SIGN.md) 在电脑运行首签脚本。需要 Python3.8+、OpenSSL1.1.1/3 CLI（Windows Git附带OpenSSL路径会自动尝试），无pip、无网络请求。Windows/macOS尚未实机验证；Linux/OpenSSL3.5.9的11项单测和应用真实Java SignedQuirksStore互操作已通过。

- Windows：双击 `tools/first-sign.cmd`。
- macOS/Linux：在本目录运行 `sh tools/first-sign.sh`。

脚本在电脑用户主目录`.allin-rules/private.pem`生成口令加密RSA3072私钥，公钥/首次签名包仅输出到本仓库忽略的`out/`。已有目标不会静默重建。把`out/first-sign`中的current.bin、public.pem、trust.json和显示的公钥指纹交回手机，私钥和口令始终留在电脑。

接入后，用户在治理页主动点击检查更新；APK内置公钥验签，严格校验版本/schema/目的地/头操作，失败保留上一版。规则更新不能添加任意脚本、认证头或新目的地，也不能自动更新APK。

## 更新发布

先增加source的数字三段版本并核对变化，用可信上一版签名文件和固定公钥签署，再把已验签的信封放到`docs/current.bin`。仅发布公开规则与签名数据。`sign`在输出路径有旧包时拒绝降版、同版异内容；`finish`要求全新输出目录，不能代替服务器历史版本比对。

完整签名格式：QRK1 magic＋大端u32原文长度＋严格UTF8规则原文＋大端u16签名长度＋RSA PKCS1v1.5 SHA256签名。签名内容为ASCII AllIn-Q2＋0x00＋0x01＋原文。来源描述符只含schemaVersion/url/rsaPublicKeySpkiBase64（X.509 SPKI DER Base64）。生产密钥轮换需APK更换固定信任。

## 检查

```text
python tools/rules_tool.py validate rules/source.json
python -m unittest discover -s tests -v
```

测试仅使用系统临时目录中的加密测试密钥并清理。输出采用排他文件创建和同目录暂存，finish使用平台原子不覆盖目录重命名；不支持时安全报错。不要把生产私钥、口令、账号数据或私库内容放进公开仓库。
