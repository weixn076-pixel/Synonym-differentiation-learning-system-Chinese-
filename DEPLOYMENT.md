# 公网部署说明

本项目包含账号、答题记录和付费/受限 API 密钥，不应作为纯静态网页上传。推荐在一台 Linux 云服务器上单实例运行 `synonym_server.py`，由 Caddy 对外提供 HTTPS。

## Vercel 部署

仓库中的 `api/index.js`、`vercel.json` 和 `package.json` 提供 Vercel Serverless API。Vercel 的临时文件系统不能持久保存 SQLite，因此必须先为项目连接 PostgreSQL，再配置：

```text
DATABASE_URL=托管 PostgreSQL 连接地址
APP_ORIGIN=https://chennxn.xyz
ADMIN_USERNAME=管理员用户名
ADMIN_PASSWORD=不少于 12 位的管理员密码
ECNU_API_KEY=智能辨析服务密钥
```

所有变量必须只在 Vercel 项目设置中保存，并应用于 Production。首次访问 API 时服务会自动建表；当数据库中还没有管理员时，会使用 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 创建一个。管理员成功登录后可删除 Vercel 中的 `ADMIN_PASSWORD`，不要把它留在仓库或构建日志中。

部署完成后检查 `https://chennxn.xyz/api/auth/me` 应返回 JSON，而不是 Vercel 404。然后用管理员账号登录网页，确认“邀请码管理”入口可生成、刷新和撤销邀请码。

下述章节是自建 Linux 云服务器方案。

## 1. 准备域名和服务器

- 准备一个带公网 IPv4 的 Linux 云服务器。
- 将域名 `chennxn.xyz` 的 A 记录指向服务器公网 IP。
- 防火墙只开放 SSH、HTTP 80 和 HTTPS 443；不要开放应用端口 8765。
- 将 `synonym_app_v2.html`、`dictionary.json` 和 `synonym_server.py` 放到 `/opt/synonym-app`。

## 2. 创建专用用户和数据目录

以具有管理员权限的账号执行：

```bash
sudo useradd --system --home /var/lib/synonym-app --shell /usr/sbin/nologin synonym-app
sudo install -d -o synonym-app -g synonym-app -m 700 /var/lib/synonym-app
sudo install -d -o root -g synonym-app -m 750 /etc/synonym-app
```

如需迁移已有用户数据，停止本地服务后，将 `synonym_users.sqlite3` 以及存在的 `-wal`、`-shm` 文件一起复制到 `/var/lib/synonym-app`，再把所有者设为 `synonym-app`。不要在数据库仍有写入时只复制主文件。

## 3. 安全配置密钥

在服务器创建 `/etc/synonym-app/app.env`，只写一行 `ECNU_API_KEY=` 加实际密钥。不要把该文件放进项目目录或版本控制。随后执行：

```bash
sudo chown root:synonym-app /etc/synonym-app/app.env
sudo chmod 640 /etc/synonym-app/app.env
```

密钥曾在聊天中直接发送过，正式上线前应在 API 管理端撤销旧密钥并生成新密钥。

## 4. 创建管理员账号

管理员账号只能在服务器命令行创建，不能通过网页注册成为管理员。首次部署时执行：

```bash
sudo -u synonym-app env APP_DATA_DIR=/var/lib/synonym-app python3 /opt/synonym-app/synonym_server.py --create-admin "admin"
```

按隐藏提示设置不少于 12 位的管理员密码。管理员登录网页后会看到“邀请码管理”，可以调用受保护的站内 API 批量生成、查看和撤销邀请码。普通账号即使直接请求该 API 也会返回 403。

如果需要将已有普通账号提升为管理员，可在服务器命令行执行：

```bash
sudo -u synonym-app env APP_DATA_DIR=/var/lib/synonym-app python3 /opt/synonym-app/synonym_server.py --promote-admin "已有用户名"
```

## 5. 创建注册邀请码

注册必须使用服务端生成的一次性邀请码。每个邀请码只能成功注册一个账号，数据库只保存邀请码摘要，原始邀请码仅在生成时显示一次。

管理员网页默认生成 60 天有效的邀请码，格式固定为五组四位大写字母或数字，例如 `ABCD-EFGH-JKLM-NPQR-STUV`。每个邀请码注册成功后立即核销，不能再次使用。

也可以在服务器命令行批量生成。例如生成 10 个、60 天有效并注明批次：

```bash
sudo -u synonym-app env APP_DATA_DIR=/var/lib/synonym-app python3 /opt/synonym-app/synonym_server.py --create-invites 10 --invite-valid-days 60 --invite-label "第一批用户"
```

妥善记录命令输出并分别发送给用户。邀请码不区分大小写，输入时可保留或省略连字符。查看邀请码状态：

```bash
sudo -u synonym-app env APP_DATA_DIR=/var/lib/synonym-app python3 /opt/synonym-app/synonym_server.py --list-invites
```

撤销尚未使用的邀请码：

```bash
sudo -u synonym-app env APP_DATA_DIR=/var/lib/synonym-app python3 /opt/synonym-app/synonym_server.py --revoke-invite "填写完整邀请码"
```

## 6. 安装系统服务

复制 `synonym.service.example` 到 `/etc/systemd/system/synonym.service`。示例文件已经将 `APP_ORIGIN` 配置为 `https://chennxn.xyz`，然后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now synonym.service
sudo systemctl status synonym.service
```

应用保持监听 `127.0.0.1:8765`。生产环境的 `APP_ORIGIN` 必须是完整 HTTPS 源，不能带路径。`APP_TRUST_PROXY=1` 仅应在应用端口不对公网开放、且前置代理可信时启用。

## 7. 配置 HTTPS

安装 Caddy，将 `Caddyfile.example` 复制为 `/etc/caddy/Caddyfile`。示例文件已经配置域名 `chennxn.xyz`，然后重新加载：

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy 会自动申请和续期 TLS 证书。浏览器会收到 `Secure`、`HttpOnly`、`SameSite=Strict` 会话 Cookie，应用也会发送 HSTS 和严格同源响应头。

## 8. 上线验收和备份

上线后分别用桌面浏览器和手机访问 HTTPS 域名，检查注册、登录、答题同步、退出及智能辨析。未登录直接请求 `/api/synonym-analysis` 应返回 401。

用户数据存储在 `/var/lib/synonym-app/synonym_users.sqlite3`。该版本适合单服务器、小规模使用，不能让多个应用实例同时共享这份 SQLite 数据库。建议每天使用 SQLite 在线备份命令生成一致性备份，并把备份同步到另一台机器或对象存储：

```bash
sudo -u synonym-app sqlite3 /var/lib/synonym-app/synonym_users.sqlite3 ".backup '/var/lib/synonym-app/synonym_users.sqlite3.backup'"
```

备份文件同样包含账号和学习记录，应加密保存并限制读取权限。更新程序前先备份数据库，再替换代码并重启 `synonym.service`。

## 本地开发

本地开发无需设置生产域名，直接运行 `python3 synonym_server.py`，按隐藏提示输入 API 密钥，访问 `http://127.0.0.1:8765/synonym_app_v2.html`。本地 HTTP 模式不会设置 `Secure` Cookie，也不会发送 HSTS。

本地首次创建管理员账号：

```bash
python3 synonym_server.py --create-admin "admin"
```

本地生成一个 60 天有效的邀请码：

```bash
python3 synonym_server.py --create-invites 1 --invite-valid-days 60 --invite-label "本地测试"
```
