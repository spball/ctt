# CFTeleTrans (CTT)

基于 Cloudflare Workers、D1 和 Telegram Bot API 的私聊消息转发机器人。外部用户通过 Bot 发消息，管理员在自己与 Bot 的私聊窗口中使用独立 Threads 处理每个用户的会话。

## 功能

- Cloudflare Turnstile + Telegram Mini App 验证，不再使用算术验证码。
- 每个通过验证的用户在管理员私聊中对应一个独立 Thread。
- Thread 首条置顶消息同时展示用户资料和可操作的管理员面板。
- 支持文本、图片、文件等 Telegram 可复制消息的双向转发。
- 支持拉黑、解除拉黑、验证开关、黑名单查询、欢迎内容开关和删除用户。
- D1 持久化验证状态、频率限制及用户与 Thread 的映射。

## 工作流程

1. 用户向 Bot 发送 `/start` 或任意消息。
2. Bot 发送“开始验证”按钮，在 Telegram Mini App 中打开当前 Worker 的 `/verify` 页面。
3. 用户完成 Turnstile；Worker 同时校验 Turnstile Siteverify、Telegram `initData` 和一次性挑战令牌。
4. 验证成功后，Bot 在管理员私聊中创建用户专属 Thread，并置顶管理员面板。
5. 用户消息进入该 Thread；管理员在 Thread 中回复即可转发给用户。

验证挑战 5 分钟内有效且只能使用一次。验证通过状态默认保持 24 小时；用户触发消息频率限制后需要重新验证。验证期间发送的消息不会排队或补发。

## 部署准备

### 1. 创建 Telegram Bot

1. 使用 [@BotFather](https://t.me/BotFather) 创建 Bot 并保存 Token。
2. 在 Bot 设置中启用私聊 Topics 模式。部署后可通过 `getMe` 返回的 `has_topics_enabled` 确认。
3. 将 Worker 的 HTTPS 域名配置为 Bot 的 Mini App/Web App 域名。
4. 管理员必须先主动打开 Bot 并发送一次 `/start`，否则 Bot 无法访问管理员私聊。
5. 获取管理员本人的 Telegram User ID，作为 `ADMIN_CHAT_ID_ENV`。这里不能填写群组 ID。

本版本不再需要后台群组，也不再使用 `GROUP_ID_ENV`。

### 2. 创建 Turnstile Widget

1. 在 Cloudflare 控制台创建 Turnstile Widget。
2. 将 Worker 的 `workers.dev` 域名或自定义域名加入允许的 Hostname。
3. 保存 Site Key 和 Secret Key。

Turnstile 客户端成功并不代表验证完成；Worker 会强制调用 Siteverify 进行服务端校验。

### 3. 创建并绑定 D1

创建 D1 数据库并以变量名 `D1` 绑定到 Worker。数据库表和新增字段会在 Worker 初始化时自动创建或补齐。

### 4. 配置环境变量

| 变量 | 必需 | 说明 | 示例 |
| --- | --- | --- | --- |
| `BOT_TOKEN_ENV` | 是 | Telegram Bot Token | `123456:ABC...` |
| `ADMIN_CHAT_ID_ENV` | 是 | 单一管理员的 Telegram User ID | `123456789` |
| `TURNSTILE_SITE_KEY_ENV` | 是 | Turnstile Site Key | `0x4AAAA...` |
| `TURNSTILE_SECRET_KEY_ENV` | 是 | Turnstile Secret Key，建议配置为 Secret | `0x4AAAA...` |
| `MAX_MESSAGES_PER_MINUTE_ENV` | 否 | 单用户每分钟消息上限 | `40` |
| `D1` | 是 | Cloudflare D1 绑定 | `cfteletrans-db` |

### 5. 部署与注册 Webhook

将 `_worker.js` 部署为 Cloudflare Worker 或 Pages Advanced Mode Worker。首次请求会自动检查数据库、验证 Bot 配置并将 Webhook 注册到：

```text
https://<你的域名>/webhook
```

也可以手动访问以下维护端点：

- `GET /registerWebhook`：重新注册 Webhook。
- `GET /unRegisterWebhook`：移除 Webhook。
- `GET /checkTables`：检查并补齐 D1 表结构。

Mini App 使用以下公开接口：

- `GET /verify?challenge=...`：显示 Turnstile 页面。
- `POST /api/verify`：完成 Telegram 身份和 Turnstile 服务端校验。

## 管理员使用

- 用户验证成功后，管理员私聊中会自动出现以用户昵称命名的 Thread。
- 置顶面板包含用户昵称、用户名、User ID、接入时间和管理按钮。
- 在 Thread 中发送普通消息或媒体即可回复该用户。
- 发送 `/admin` 可重新显示或刷新置顶面板。
- `删除用户` 会删除用户状态、验证挑战、映射和对应 Thread；用户下次发起会话时会重新验证。

## 从群组 Threads 版本升级

- 新增 `ADMIN_CHAT_ID_ENV` 以及两个 Turnstile Key，删除 `GROUP_ID_ENV` 配置。
- 在 BotFather 中启用私聊 Topics，并确保管理员已与 Bot 发起私聊。
- 旧 `chat_topic_mappings` 数据会保留，但因为没有管理员私聊范围标记而自动失效。
- 用户下一次验证或发消息时会在管理员私聊中惰性创建新 Thread，不会批量迁移旧群组消息。

## 本地检查

```bash
npm test
node --check _worker.js
```

测试覆盖 Telegram Mini App 签名和时效校验、跨用户拒绝、挑战令牌哈希、Turnstile 页面内容及安全响应头。

## 安全说明

- 不要将 Bot Token 或 Turnstile Secret 提交到仓库。
- Mini App 的 `initDataUnsafe` 不可信；本项目只在后端验证原始 `initData` 后使用用户身份。
- Turnstile Token 由 Cloudflare Siteverify 校验，且挑战令牌在 D1 中一次性消费。
- 管理员按钮同时校验发送者 ID、管理员私聊 ID、Thread 与用户映射。

## 致谢与许可

灵感来源于 Telegram-interactive-bot，并感谢原项目贡献者和社区测试者。项目许可证见 [LICENSE](LICENSE)。
