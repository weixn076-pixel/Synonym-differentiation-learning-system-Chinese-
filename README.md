# 近义词辨析学习系统

面向现代汉语近义词学习的网页应用，包含 720 组词库、词义对照、搭配、练习、学习进度同步、智能辨析和管理员邀请码管理。

## 本地运行

需要 Python 3.9 或更高版本：

```bash
python3 synonym_server.py
```

按隐藏提示输入 ECNU API 密钥，然后访问：

```text
http://127.0.0.1:8765/synonym_app_v2.html
```

首次创建管理员账号：

```bash
python3 synonym_server.py --create-admin admin
```

管理员登录网页后可以批量生成固定格式的一次性邀请码。邀请码默认自生成之日起 60 天有效，注册成功后立即核销。

## 生产部署

生产域名为 [chennxn.xyz](https://chennxn.xyz)。完整的 HTTPS、systemd、Caddy、数据目录和密钥配置见 [DEPLOYMENT.md](DEPLOYMENT.md)。

不要将 API 密钥、SQLite 用户数据库或备份文件提交到版本控制。
