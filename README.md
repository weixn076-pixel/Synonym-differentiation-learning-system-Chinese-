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

当前仓库同时包含适用于 Vercel 的 Serverless API。线上账号、管理员邀请码和学习记录需要连接持久 PostgreSQL，并配置以下服务端环境变量：

- `DATABASE_URL`：托管 PostgreSQL 连接地址
- `APP_ORIGIN=https://chennxn.xyz`
- `ADMIN_USERNAME`、`ADMIN_PASSWORD`：首次请求时安全创建管理员账号
- `ECNU_API_KEY`：智能辨析服务密钥

这些变量只能配置在部署平台中，不能写入仓库。管理员账号创建完成后，可从 Vercel 删除 `ADMIN_PASSWORD`，已有密码摘要仍保存在数据库中。

不要将 API 密钥、SQLite 用户数据库或备份文件提交到版本控制。
