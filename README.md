# All In 离线规则工具

本目录只包含公开规则和离线工具。`rules/source.json` 的 1.0.1 与 APK 内置 1.0.0 的规则内容相同，仅用于分发引导，不改变行为。仓库不包含生产私钥、生产信任配置或签名包。

需要 Python 3.8+ 和 OpenSSL 1.1.1 或 3，可在 Windows、macOS、Linux 离线运行，无需 pip。将 `openssl` 加入 PATH；Windows Git for Windows 可使用 `C:\Program Files\Git\usr\bin\openssl.exe` 或 `C:\Program Files\Git\mingw64\bin\openssl.exe`，工具会尝试自动发现。

在安全的电脑上执行（将输出路径换成实际位置）：

```text
python tools/rules_tool.py init-key --out public
python tools/rules_tool.py validate rules/source.json
python tools/rules_tool.py prepare rules/source.json --public public/public.pem
python tools/rules_tool.py sign rules/source.json --private <私钥绝对路径> --public public/public.pem --out public/current.bin
python tools/rules_tool.py verify public/current.bin --public public/public.pem
python tools/rules_tool.py export-trust --public public/public.pem --url https://example.org/rules/current.bin --out public/trust.json
```

`init-key` 默认把加密私钥存到用户主目录的 `.allin-rules/private.pem`，交互输入并确认非空口令；请安全备份私钥和口令。公开目录只有公钥、SPKI DER 的 base64 和 SHA-256 指纹。签名前应通过独立可信渠道核对 `prepare` 输出的指纹；`--public` 是签名密钥的核对基准。URL 示例必须换成确定的正式 HTTPS 地址，不应作为生产配置直接使用。

`finish` 是组合命令：`python tools/rules_tool.py finish rules/source.json --private <私钥路径> --public public/public.pem --url <正式HTTPS地址> --out-dir <输出目录>`，会生成 `current.bin`、`public.pem`、`trust.json`。完成后需通过 `verify` 验证并核对指纹，交给手机端集成；这些文件只含公开数据。对已有同路径签名包，工具拒绝版本倒退以及相同版本不同内容；请保留并使用可信的上一版文件，否则工具无法知道历史版本。

测试只在系统 `/tmp` 创建临时加密测试密钥并清理：`python -m unittest discover -s tests -v`。不要将生产密钥放到仓库或输出目录，不要将私钥上传。此工具不进行网络请求。
