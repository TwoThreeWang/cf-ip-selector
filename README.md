# CF IP Selector

一个用于从给定来源域名解析 IP、并发测速选出低延迟 IP、然后批量更新到 Cloudflare DNS 的小工具。支持“先加后删”的安全策略，避免因新增失败而导致记录被清空。

## 特性
- 从 `SOURCE_DOMAINS` 中解析并去重获取 IPv4 地址
- 并发 TCP 443 延迟测试，限制并发，控制超时
- 选取 Top N（默认 10）低延迟 IP
- 更新 Cloudflare DNS：仅新增缺失记录，随后删除非目标集合的旧记录
- Bark 推送结果通知（可选），自动进行 URL 编码

## 运行环境
- Go >= 1.25
- Cloudflare 认证方式（任选其一）：
  - API Token（推荐）：需要权限 Zone.Zone Read、Zone.DNS Edit，并作用于目标 Zone
  - Global API Key + Email（备用）：`CF_API_KEY` 与 `CF_API_EMAIL`

## 快速开始
1. 复制示例配置
   ```bash
   cp .env.example .env
   ```
2. 编辑 `.env`，填写你的 Cloudflare 与任务配置
3. 构建与运行
   ```bash
   go build
   ./cf-ip-selector
   ```

## Docker 运行
- 依赖：已安装 Docker 与 Docker Compose
- 准备环境变量：复制并编辑 `.env`
  ```bash
  cp .env.example .env
  # 按需修改 .env
  ```
- 一键启动
  ```bash
  docker compose up -d
  ```
- 查看日志
  ```bash
  docker compose logs -f
  ```
- 更新配置后重启
  ```bash
  docker compose restart
  ```
- 说明
  - Compose 会通过 `env_file: .env` 注入环境变量
  - 同时将 `.env` 挂载为只读到容器 `/app/.env`，程序也可从文件加载

## 配置项说明（.env）
- `CF_API_TOKEN`：Cloudflare API Token（推荐方式）
- `CF_API_KEY` / `CF_API_EMAIL`：Cloudflare Global API Key 与邮箱（备用）
- `CF_ZONE_ID`：目标 Zone 的 ID（必填）
- `CF_TARGET_DOMAIN`：要被批量管理的 A 记录的域名（例如：`cf.example.com`）
- `SOURCE_DOMAINS`：用于解析 IP 的来源域名列表，逗号分隔（例如：`a.example.com,b.example.com`）
- `INTERVAL_SECONDS`：循环执行的时间间隔，默认 3600 秒
- `BARK_URL`：Bark 推送的基础 URL（例如：`https://api.day.app/你的Key`），可选

## 设计要点
- 域名解析使用 `context.WithTimeout` 控制每个域名 3 秒超时，避免阻塞
- TCP 延迟测试：
  - 端口 `443`
  - 并发信号量上限 50
  - 单次连接超时 2 秒
- Cloudflare 更新：
  - 先新增缺失 IP 记录，若全部新增失败则不删除旧记录（安全保护）
  - 仅删除不在目标集合中的旧记录（差集删除）
  - A 记录 TTL 固定为 60，`Proxied=false`（关闭小云朵）
- Bark 推送：对标题与正文进行 URL Path 编码，避免中文与换行导致的非法字符

## 常见问题
- 10000/10001 认证错误：
  - 使用 API Token 时，请确保权限包含 Zone.Zone Read 与 Zone.DNS Edit，并且作用范围包含你的 `CF_ZONE_ID` 对应的 Zone
  - 若仍失败，可改用 Global API Key + Email（设置 `CF_API_KEY` 和 `CF_API_EMAIL`）
- Bark 推送 URL 解析失败：
  - 已在代码中进行编码处理，若仍失败，请检查 `BARK_URL` 是否正确，以及标题/正文是否包含非法字符

## 安全提示
- 请勿将真实密钥与令牌提交到仓库
- `.env` 仅用于本地开发，部署时请使用安全的环境变量管理方式
