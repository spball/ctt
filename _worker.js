let BOT_TOKEN;
let ADMIN_CHAT_ID;
let MAX_MESSAGES_PER_MINUTE;
let TURNSTILE_SITE_KEY;
let TURNSTILE_SECRET_KEY;

const VERIFICATION_TTL_SECONDS = 5 * 60;
const VERIFIED_SESSION_SECONDS = 24 * 60 * 60;
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS = 5 * 60;
const TURNSTILE_ACTION = 'telegram_verify';

let lastCleanupTime = 0;
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 小时
let isInitialized = false;
const processedMessages = new Set();
const processedCallbacks = new Set();

const topicCreationLocks = new Map();

const settingsCache = new Map([
  ['verification_enabled', null],
  ['user_raw_enabled', null]
]);

class LRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }
  get(key) {
    const value = this.cache.get(key);
    if (value !== undefined) {
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }
  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }
  clear() {
    this.cache.clear();
  }
}

const userInfoCache = new LRUCache(1000);
const topicIdCache = new LRUCache(1000);
const userStateCache = new LRUCache(1000);
const messageRateCache = new LRUCache(1000);

const encoder = new TextEncoder();

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

async function hmacSha256(key, value) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    typeof key === 'string' ? encoder.encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(value));
}

export async function sha256Hex(value) {
  return bytesToHex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

export async function validateTelegramInitData(
  initData,
  botToken,
  expectedUserId,
  maxAgeSeconds = TELEGRAM_INIT_DATA_MAX_AGE_SECONDS,
  nowSeconds = Math.floor(Date.now() / 1000)
) {
  if (!initData || !botToken) return { valid: false, error: 'missing-init-data' };

  const params = new URLSearchParams(initData);
  const receivedHash = params.get('hash');
  if (!receivedHash) return { valid: false, error: 'missing-hash' };

  params.delete('hash');
  const dataCheckString = Array.from(params.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const secretKey = await hmacSha256('WebAppData', botToken);
  const calculatedHash = bytesToHex(await hmacSha256(secretKey, dataCheckString));
  if (!timingSafeEqual(calculatedHash, receivedHash.toLowerCase())) {
    return { valid: false, error: 'invalid-signature' };
  }

  const authDate = Number(params.get('auth_date'));
  if (!Number.isInteger(authDate) || authDate > nowSeconds + 30 || nowSeconds - authDate > maxAgeSeconds) {
    return { valid: false, error: 'expired-init-data' };
  }

  let user;
  try {
    user = JSON.parse(params.get('user') || 'null');
  } catch {
    return { valid: false, error: 'invalid-user' };
  }

  if (!user?.id || String(user.id) !== String(expectedUserId)) {
    return { valid: false, error: 'user-mismatch' };
  }

  return { valid: true, user };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function renderVerificationPage(siteKey, challengeToken) {
  const serializedSiteKey = JSON.stringify(String(siteKey)).replaceAll('<', '\\u003c');
  const serializedChallenge = JSON.stringify(String(challengeToken)).replaceAll('<', '\\u003c');
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <title>安全验证</title>
  <link rel="preconnect" href="https://challenges.cloudflare.com">
  <script src="https://telegram.org/js/telegram-web-app.js?63"></script>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--tg-theme-bg-color, #fff); color: var(--tg-theme-text-color, #111); }
    main { width: min(92vw, 420px); box-sizing: border-box; padding: 28px 20px; text-align: center; }
    h1 { margin: 0 0 10px; font-size: 24px; }
    p { margin: 0 0 22px; color: var(--tg-theme-hint-color, #667085); line-height: 1.5; }
    #turnstile { min-height: 65px; }
    #status { min-height: 24px; margin-top: 18px; font-weight: 600; overflow-wrap: anywhere; }
    #retry { margin-top: 14px; padding: 10px 18px; font: inherit; font-weight: 600; color: var(--tg-theme-button-text-color, #fff); background: var(--tg-theme-button-color, #2481cc); border: 0; border-radius: 8px; cursor: pointer; }
    .error { color: #d92d20; }
    .success { color: #079455; }
  </style>
</head>
<body>
  <main>
    <h1>完成安全验证</h1>
    <p>验证成功后即可继续与 Bot 对话。</p>
    <div id="turnstile"></div>
    <div id="status" role="status" aria-live="polite"></div>
    <button id="retry" type="button" hidden>重新加载验证组件</button>
  </main>
  <script>
    const challenge = ${serializedChallenge};
    const webApp = window.Telegram && window.Telegram.WebApp;
    const statusElement = document.getElementById('status');
    const retryButton = document.getElementById('retry');
    if (webApp) { webApp.ready(); webApp.expand(); }

    function setStatus(message, type = '') {
      statusElement.textContent = message;
      statusElement.className = type;
    }

    async function completeVerification(turnstileToken) {
      setStatus('正在确认验证…');
      try {
        const response = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            challenge,
            turnstileToken,
            initData: webApp ? webApp.initData : ''
          })
        });
        const result = await response.json();
        if (!response.ok || !result.ok) throw new Error(result.error || '验证失败');
        setStatus('验证成功，可以返回聊天。', 'success');
        if (webApp) setTimeout(() => webApp.close(), 900);
      } catch (error) {
        setStatus(error.message || '验证失败，请重试。', 'error');
        if (window.turnstile) window.turnstile.reset();
      }
    }

    function renderWidget() {
      try {
        window.turnstile.render('#turnstile', {
          sitekey: ${serializedSiteKey},
          action: '${TURNSTILE_ACTION}',
          theme: 'auto',
          size: 'flexible',
          callback: completeVerification,
          'error-callback': (code) => setStatus('验证组件加载失败（错误码 ' + code + '），请稍后重试。', 'error'),
          'expired-callback': () => setStatus('验证已过期，请重新完成验证。', 'error')
        });
      } catch (error) {
        setStatus('验证组件初始化失败：' + ((error && error.message) || '未知错误'), 'error');
      }
    }

    let waitedMs = 0;
    const POLL_INTERVAL_MS = 200;
    const INIT_DATA_GRACE_MS = 3000;
    const LOAD_TIMEOUT_MS = 15000;

    function waitForTurnstile() {
      const hasInitData = Boolean(webApp && webApp.initData);
      const hasTurnstile = Boolean(window.turnstile && typeof window.turnstile.render === 'function');
      if (hasInitData && hasTurnstile) {
        renderWidget();
        return;
      }
      waitedMs += POLL_INTERVAL_MS;
      if (!hasInitData && waitedMs >= INIT_DATA_GRACE_MS) {
        setStatus('请从 Telegram Bot 中打开此页面。', 'error');
        return;
      }
      if (waitedMs >= LOAD_TIMEOUT_MS) {
        setStatus('验证组件加载超时：当前网络无法访问 challenges.cloudflare.com。请检查代理、VPN、防火墙或广告拦截设置后重试。', 'error');
        retryButton.hidden = false;
        return;
      }
      setTimeout(waitForTurnstile, POLL_INTERVAL_MS);
    }

    function reloadTurnstileScript() {
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&t=' + Date.now();
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }

    retryButton.addEventListener('click', () => {
      retryButton.hidden = true;
      setStatus('正在重新加载验证组件…');
      waitedMs = 0;
      reloadTurnstileScript();
      waitForTurnstile();
    });

    waitForTurnstile();
  </script>
</body>
</html>`;
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

export function verificationPageResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline' https://telegram.org https://challenges.cloudflare.com; style-src 'unsafe-inline'; connect-src 'self' https://challenges.cloudflare.com; frame-src 'self' https://challenges.cloudflare.com; img-src data: https:; base-uri 'none'; form-action 'self'",
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}

export default {
  async fetch(request, env) {
    BOT_TOKEN = env.BOT_TOKEN_ENV || null;
    ADMIN_CHAT_ID = env.ADMIN_CHAT_ID_ENV ? String(env.ADMIN_CHAT_ID_ENV) : null;
    TURNSTILE_SITE_KEY = env.TURNSTILE_SITE_KEY_ENV || null;
    TURNSTILE_SECRET_KEY = env.TURNSTILE_SECRET_KEY_ENV || null;
    const configuredRateLimit = env.MAX_MESSAGES_PER_MINUTE_ENV ? parseInt(env.MAX_MESSAGES_PER_MINUTE_ENV, 10) : 40;
    MAX_MESSAGES_PER_MINUTE = Number.isFinite(configuredRateLimit) && configuredRateLimit > 0 ? configuredRateLimit : 40;

    if (!env.D1) {
      return new Response('Server configuration error: D1 database is not bound', { status: 500 });
    }

    if (!BOT_TOKEN || !ADMIN_CHAT_ID || !TURNSTILE_SITE_KEY || !TURNSTILE_SECRET_KEY) {
      return new Response(
        'Server configuration error: BOT_TOKEN_ENV, ADMIN_CHAT_ID_ENV, TURNSTILE_SITE_KEY_ENV and TURNSTILE_SECRET_KEY_ENV are required',
        { status: 500 }
      );
    }

    async function handleRequest(request) {
      const url = new URL(request.url);
      if (url.pathname === '/verify' && request.method === 'GET') {
        const challenge = url.searchParams.get('challenge');
        if (!challenge) return renderVerificationErrorPage('验证链接无效。', 400);

        const tokenHash = await sha256Hex(challenge);
        const record = await env.D1.prepare(
          'SELECT expires_at, used_at FROM verification_challenges WHERE token_hash = ?'
        ).bind(tokenHash).first();
        const nowSeconds = Math.floor(Date.now() / 1000);
        if (!record || record.used_at || record.expires_at < nowSeconds) {
          return renderVerificationErrorPage('验证链接已失效，请返回 Bot 获取新链接。', 410);
        }
        return verificationPageResponse(renderVerificationPage(TURNSTILE_SITE_KEY, challenge));
      } else if (url.pathname === '/api/verify' && request.method === 'POST') {
        return completeMiniAppVerification(request);
      } else if (url.pathname === '/webhook' && request.method === 'POST') {
        try {
          const update = await request.json();
          await handleUpdate(update);
          return new Response('OK');
        } catch (error) {
          console.error(`Webhook processing failed: ${error.message}`);
          return new Response('Bad Request', { status: 400 });
        }
      } else if (url.pathname === '/registerWebhook') {
        return await registerWebhook(request);
      } else if (url.pathname === '/unRegisterWebhook') {
        return await unRegisterWebhook();
      } else if (url.pathname === '/checkTables') {
        await checkAndRepairTables(env.D1);
        return new Response('Database tables checked and repaired', { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    }

    async function initialize(d1, request) {
      await checkAndRepairTables(d1);
      await Promise.all([
        autoRegisterWebhook(request),
        checkBotConfiguration(),
        cleanExpiredVerificationCodes(d1)
      ]);
    }

    function renderVerificationErrorPage(message, status) {
      const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全验证</title></head><body><main><h1>无法验证</h1><p>${escapeHtml(message)}</p></main></body></html>`;
      return verificationPageResponse(html, status);
    }

    async function autoRegisterWebhook(request) {
      const webhookUrl = `${new URL(request.url).origin}/webhook`;
      await fetchWithRetry(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl }),
      });
    }

    async function checkBotConfiguration() {
      const botResponse = await fetchWithRetry(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const botData = await botResponse.json();
      if (!botData.ok || !botData.result.has_topics_enabled) {
        throw new Error('Bot private chat Topics mode is not enabled in BotFather');
      }

      const response = await fetchWithRetry(`https://api.telegram.org/bot${BOT_TOKEN}/getChat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: ADMIN_CHAT_ID })
      });
      const data = await response.json();
      if (!data.ok || data.result.type !== 'private') {
        throw new Error(`ADMIN_CHAT_ID_ENV must identify a private chat that has started the bot: ${data.description || 'not a private chat'}`);
      }
    }

    async function checkAndRepairTables(d1) {
      const expectedTables = {
        user_states: {
          columns: {
            chat_id: 'TEXT PRIMARY KEY',
            is_blocked: 'BOOLEAN DEFAULT FALSE',
            is_verified: 'BOOLEAN DEFAULT FALSE',
            verified_expiry: 'INTEGER',
            verification_code: 'TEXT',
            code_expiry: 'INTEGER',
            last_verification_message_id: 'TEXT',
            is_first_verification: 'BOOLEAN DEFAULT TRUE',
            is_rate_limited: 'BOOLEAN DEFAULT FALSE',
            is_verifying: 'BOOLEAN DEFAULT FALSE'
          }
        },
        message_rates: {
          columns: {
            chat_id: 'TEXT PRIMARY KEY',
            message_count: 'INTEGER DEFAULT 0',
            window_start: 'INTEGER',
            start_count: 'INTEGER DEFAULT 0',
            start_window_start: 'INTEGER'
          }
        },
        chat_topic_mappings: {
          columns: {
            chat_id: 'TEXT PRIMARY KEY',
            topic_id: 'TEXT NOT NULL',
            topic_chat_id: 'TEXT DEFAULT NULL',
            panel_message_id: 'TEXT DEFAULT NULL',
            created_at: 'INTEGER DEFAULT NULL'
          }
        },
        verification_challenges: {
          columns: {
            token_hash: 'TEXT PRIMARY KEY',
            chat_id: 'TEXT NOT NULL',
            expires_at: 'INTEGER NOT NULL',
            used_at: 'INTEGER DEFAULT NULL',
            created_at: 'INTEGER NOT NULL'
          }
        },
        settings: {
          columns: {
            key: 'TEXT PRIMARY KEY',
            value: 'TEXT'
          }
        }
      };

      for (const [tableName, structure] of Object.entries(expectedTables)) {
        const tableInfo = await d1.prepare(
          `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`
        ).bind(tableName).first();

        if (!tableInfo) {
          await createTable(d1, tableName, structure);
        } else {
          const columnsResult = await d1.prepare(
            `PRAGMA table_info(${tableName})`
          ).all();

          const currentColumns = new Map(
            columnsResult.results.map(col => [col.name, {
              type: col.type,
              notnull: col.notnull,
              dflt_value: col.dflt_value
            }])
          );

          for (const [colName, colDef] of Object.entries(structure.columns)) {
            if (!currentColumns.has(colName)) {
              const addColumnSQL = `ALTER TABLE ${tableName} ADD COLUMN ${colName} ${colDef}`;
              await d1.exec(addColumnSQL);
            }
          }
        }

        if (tableName === 'settings') {
          await d1.exec('CREATE INDEX IF NOT EXISTS idx_settings_key ON settings (key)');
        } else if (tableName === 'verification_challenges') {
          await d1.exec('CREATE INDEX IF NOT EXISTS idx_verification_challenges_chat_id ON verification_challenges (chat_id)');
          await d1.exec('CREATE INDEX IF NOT EXISTS idx_verification_challenges_expires_at ON verification_challenges (expires_at)');
        } else if (tableName === 'chat_topic_mappings') {
          await d1.exec('CREATE INDEX IF NOT EXISTS idx_chat_topic_scope ON chat_topic_mappings (topic_chat_id, topic_id)');
        }
      }

      await Promise.all([
        d1.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)')
          .bind('verification_enabled', 'true').run(),
        d1.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)')
          .bind('user_raw_enabled', 'true').run()
      ]);

      settingsCache.set('verification_enabled', (await getSetting('verification_enabled', d1)) === 'true');
      settingsCache.set('user_raw_enabled', (await getSetting('user_raw_enabled', d1)) === 'true');
    }

    async function createTable(d1, tableName, structure) {
      const columnsDef = Object.entries(structure.columns)
        .map(([name, def]) => `${name} ${def}`)
        .join(', ');
      const createSQL = `CREATE TABLE ${tableName} (${columnsDef})`;
      await d1.exec(createSQL);
    }

    async function cleanExpiredVerificationCodes(d1) {
      const now = Date.now();
      if (now - lastCleanupTime < CLEANUP_INTERVAL) {
        return;
      }

      const nowSeconds = Math.floor(now / 1000);
      await d1.prepare(
        'DELETE FROM verification_challenges WHERE expires_at < ? OR used_at IS NOT NULL'
      ).bind(nowSeconds).run();

      const expiredCodes = await d1.prepare(
        'SELECT chat_id FROM user_states WHERE code_expiry IS NOT NULL AND code_expiry < ?'
      ).bind(nowSeconds).all();

      if (expiredCodes.results.length > 0) {
        await d1.batch(
          expiredCodes.results.map(({ chat_id }) =>
            d1.prepare(
              'UPDATE user_states SET verification_code = NULL, code_expiry = NULL, is_verifying = FALSE WHERE chat_id = ?'
            ).bind(chat_id)
          )
        );
      }
      lastCleanupTime = now;
    }

    async function completeMiniAppVerification(verificationRequest) {
      let payload;
      try {
        payload = await verificationRequest.json();
      } catch {
        return jsonResponse({ ok: false, error: '请求格式无效。' }, 400);
      }

      const challenge = typeof payload.challenge === 'string' ? payload.challenge : '';
      const turnstileToken = typeof payload.turnstileToken === 'string' ? payload.turnstileToken : '';
      const initData = typeof payload.initData === 'string' ? payload.initData : '';
      if (!challenge || !turnstileToken || !initData) {
        return jsonResponse({ ok: false, error: '缺少验证数据。' }, 400);
      }

      const tokenHash = await sha256Hex(challenge);
      const nowSeconds = Math.floor(Date.now() / 1000);
      const challengeRecord = await env.D1.prepare(
        `SELECT vc.chat_id, vc.expires_at, vc.used_at, us.is_blocked, us.last_verification_message_id
         FROM verification_challenges vc
         LEFT JOIN user_states us ON us.chat_id = vc.chat_id
         WHERE vc.token_hash = ?`
      ).bind(tokenHash).first();

      if (!challengeRecord || challengeRecord.used_at || challengeRecord.expires_at < nowSeconds) {
        return jsonResponse({ ok: false, error: '验证链接已失效，请返回 Bot 获取新链接。' }, 410);
      }
      if (challengeRecord.is_blocked) {
        return jsonResponse({ ok: false, error: '此账户无法继续发送消息。' }, 403);
      }

      const telegramValidation = await validateTelegramInitData(
        initData,
        BOT_TOKEN,
        challengeRecord.chat_id
      );
      if (!telegramValidation.valid) {
        return jsonResponse({ ok: false, error: 'Telegram 身份验证失败，请从 Bot 重新打开。' }, 401);
      }

      const siteverifyResponse = await fetchWithRetry(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            secret: TURNSTILE_SECRET_KEY,
            response: turnstileToken,
            remoteip: verificationRequest.headers.get('CF-Connecting-IP') || undefined,
            idempotency_key: crypto.randomUUID()
          })
        }
      );
      const siteverifyResult = await siteverifyResponse.json();
      if (!siteverifyResult.success || siteverifyResult.action !== TURNSTILE_ACTION) {
        return jsonResponse({ ok: false, error: 'Turnstile 验证失败，请重试。' }, 400);
      }

      const claimResult = await env.D1.prepare(
        'UPDATE verification_challenges SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?'
      ).bind(nowSeconds, tokenHash, nowSeconds).run();
      if (!claimResult.meta?.changes) {
        return jsonResponse({ ok: false, error: '该验证已被使用，请返回 Bot 获取新链接。' }, 409);
      }

      const verifiedExpiry = nowSeconds + VERIFIED_SESSION_SECONDS;
      await env.D1.batch([
        env.D1.prepare(
          `INSERT INTO user_states (chat_id, is_verified, verified_expiry, is_first_verification, is_verifying, verification_code, code_expiry, last_verification_message_id)
           VALUES (?, TRUE, ?, FALSE, FALSE, NULL, NULL, NULL)
           ON CONFLICT(chat_id) DO UPDATE SET
             is_verified = TRUE,
             verified_expiry = excluded.verified_expiry,
             is_first_verification = FALSE,
             is_verifying = FALSE,
             verification_code = NULL,
             code_expiry = NULL,
             last_verification_message_id = NULL`
        ).bind(challengeRecord.chat_id, verifiedExpiry),
        env.D1.prepare(
          `INSERT INTO message_rates (chat_id, message_count, window_start)
           VALUES (?, 0, ?)
           ON CONFLICT(chat_id) DO UPDATE SET message_count = 0, window_start = excluded.window_start`
        ).bind(challengeRecord.chat_id, nowSeconds * 1000)
      ]);

      const refreshedState = await env.D1.prepare(
        'SELECT is_blocked, is_first_verification, is_verified, verified_expiry, is_verifying FROM user_states WHERE chat_id = ?'
      ).bind(challengeRecord.chat_id).first();
      userStateCache.set(challengeRecord.chat_id, refreshedState);
      messageRateCache.set(challengeRecord.chat_id, { message_count: 0, window_start: nowSeconds * 1000 });

      if (challengeRecord.last_verification_message_id) {
        try {
          await telegramApi('deleteMessage', {
            chat_id: challengeRecord.chat_id,
            message_id: challengeRecord.last_verification_message_id
          });
        } catch (error) {
          console.log(`Unable to delete completed verification message: ${error.message}`);
        }
      }

      try {
        const successMessage = await getVerificationSuccessMessage();
        if (successMessage) await sendMessageToUser(challengeRecord.chat_id, successMessage);
        const userInfo = await getUserInfo(challengeRecord.chat_id);
        await ensureUserTopic(challengeRecord.chat_id, userInfo);
      } catch (error) {
        console.error(`Post-verification Telegram setup failed: ${error.message}`);
      }

      return jsonResponse({ ok: true });
    }

    async function handleUpdate(update) {
      if (update.message) {
        const messageId = update.message.message_id.toString();
        const chatId = update.message.chat.id.toString();
        const messageKey = `${chatId}:${messageId}`;
        
        if (processedMessages.has(messageKey)) {
          return;
        }
        processedMessages.add(messageKey);
        
        if (processedMessages.size > 10000) {
          processedMessages.clear();
        }

        await onMessage(update.message);
      } else if (update.callback_query) {
        await onCallbackQuery(update.callback_query);
      }
    }

    async function onMessage(message) {
      const chatId = message.chat.id.toString();
      const text = message.text || '';
      const messageId = message.message_id;

      if (chatId === ADMIN_CHAT_ID) {
        const topicId = message.message_thread_id;
        if (!topicId) {
          if (text === '/start') {
            await sendMessageToUser(ADMIN_CHAT_ID, '管理员工作区已就绪。用户通过验证后会在此创建独立 Thread。');
          }
          return;
        }

        const privateChatId = await getPrivateChatId(topicId);
        if (!privateChatId) {
          if (text === '/start') {
            await sendMessageToTopic(topicId, '管理员工作区已就绪。用户通过验证后会在此创建独立 Thread。');
            return;
          }
          await sendMessageToTopic(topicId, '未找到此 Thread 对应的用户。');
          return;
        }
        if (
          message.forum_topic_created || message.forum_topic_closed ||
          message.forum_topic_reopened || message.forum_topic_edited ||
          message.pinned_message
        ) {
          return;
        }
        if (text === '/admin') {
          await sendAdminPanel(topicId, privateChatId, messageId, true);
          return;
        }
        if (text.startsWith('/reset_user')) {
          await handleResetUser(chatId, topicId, text);
          return;
        }
        await forwardMessageToPrivateChat(privateChatId, message);
        return;
      }

      let userState = userStateCache.get(chatId);
      if (userState === undefined) {
        userState = await env.D1.prepare('SELECT is_blocked, is_first_verification, is_verified, verified_expiry, is_verifying FROM user_states WHERE chat_id = ?')
          .bind(chatId)
          .first();
        if (!userState) {
          userState = { is_blocked: false, is_first_verification: true, is_verified: false, verified_expiry: null, is_verifying: false };
          await env.D1.prepare('INSERT INTO user_states (chat_id, is_blocked, is_first_verification, is_verified, is_verifying) VALUES (?, ?, ?, ?, ?)')
            .bind(chatId, false, true, false, false)
            .run();
        }
        userStateCache.set(chatId, userState);
      }

      if (userState.is_blocked) {
        await sendMessageToUser(chatId, "You have been blocked and cannot send messages.");
        return;
      }

      const verificationEnabled = (await getSetting('verification_enabled', env.D1)) === 'true';
      if (verificationEnabled) {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const isVerified = userState.is_verified && userState.verified_expiry && nowSeconds < userState.verified_expiry;
        const isFirstVerification = userState.is_first_verification;
        const isRateLimited = await checkMessageRate(chatId);

        if (!isVerified || (isRateLimited && !isFirstVerification)) {
          const activeChallenge = await env.D1.prepare(
            'SELECT token_hash FROM verification_challenges WHERE chat_id = ? AND used_at IS NULL AND expires_at >= ? LIMIT 1'
          ).bind(chatId, nowSeconds).first();
          if (activeChallenge && userState.is_verifying) {
            await sendMessageToUser(chatId, '请点击上方“开始验证”按钮完成安全验证。');
            return;
          }
          await issueVerificationChallenge(chatId);
          return;
        }
      }

      if (text === '/start') {
        if (await checkStartCommandRate(chatId)) {
          await sendMessageToUser(chatId, "Too many attempts, please try again later.");
          return;
        }

        const successMessage = await getVerificationSuccessMessage();
        if (successMessage) await sendMessageToUser(chatId, successMessage);
        const userInfo = await getUserInfo(chatId);
        await ensureUserTopic(chatId, userInfo);
        return;
      }

      const userInfo = await getUserInfo(chatId);
      if (!userInfo) {
        await sendMessageToUser(chatId, "Unable to retrieve user information. Please try again later.");
        return;
      }

      let topicId = await ensureUserTopic(chatId, userInfo);
      if (!topicId) {
        await sendMessageToUser(chatId, "Unable to create a topic. Please try again later.");
        return;
      }

      const isTopicValid = await validateTopic(topicId);
      if (!isTopicValid) {
        await env.D1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(chatId).run();
        topicIdCache.set(topicCacheKey(chatId), undefined);
        topicId = await ensureUserTopic(chatId, userInfo);
        if (!topicId) {
          await sendMessageToUser(chatId, "Unable to recreate the topic. Please try again later.");
          return;
        }
      }

      const userName = userInfo.username || `User_${chatId}`;
      const nickname = userInfo.nickname || userName;

      if (text) {
        const formattedMessage = `${nickname}:\n${text}`;
        await sendMessageToTopic(topicId, formattedMessage);
      } else {
        await copyMessageToTopic(topicId, message);
      }
    }

    async function validateTopic(topicId) {
      try {
        const result = await telegramApi('sendMessage', {
          chat_id: ADMIN_CHAT_ID,
          message_thread_id: topicId,
          text: '正在检查会话…',
          disable_notification: true
        });
        await telegramApi('deleteMessage', {
          chat_id: ADMIN_CHAT_ID,
          message_id: result.message_id
        });
        return true;
      } catch (error) {
        return false;
      }
    }

    async function ensureUserTopic(chatId, userInfo) {
      const existingLock = topicCreationLocks.get(chatId);
      if (existingLock) return existingLock;

      const creation = (async () => {
        let topicId = await getExistingTopicId(chatId);
        if (topicId) {
          const mapping = await getTopicMapping(chatId);
          if (!mapping?.panel_message_id) await sendAdminPanel(topicId, chatId);
          return topicId;
        }

        const userName = userInfo.username || `User_${chatId}`;
        const nickname = userInfo.nickname || userName;
        topicId = await createForumTopic(nickname);
        await saveTopicId(chatId, topicId);
        await sendAdminPanel(topicId, chatId);
        return topicId;
      })();

      topicCreationLocks.set(chatId, creation);
      try {
        return await creation;
      } finally {
        if (topicCreationLocks.get(chatId) === creation) topicCreationLocks.delete(chatId);
      }
    }

    async function handleResetUser(chatId, topicId, text) {
      const senderId = chatId;
      const isAdmin = await checkIfAdmin(senderId);
      if (!isAdmin) {
        await sendMessageToTopic(topicId, '只有管理员可以使用此功能。');
        return;
      }

      const parts = text.split(' ');
      if (parts.length !== 2) {
        await sendMessageToTopic(topicId, '用法：/reset_user <chat_id>');
        return;
      }

      const targetChatId = parts[1];
      await env.D1.batch([
        env.D1.prepare('DELETE FROM verification_challenges WHERE chat_id = ?').bind(targetChatId),
        env.D1.prepare('DELETE FROM user_states WHERE chat_id = ?').bind(targetChatId),
        env.D1.prepare('DELETE FROM message_rates WHERE chat_id = ?').bind(targetChatId),
        env.D1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(targetChatId)
      ]);
      userStateCache.set(targetChatId, undefined);
      messageRateCache.set(targetChatId, undefined);
      topicIdCache.set(topicCacheKey(targetChatId), undefined);
      await sendMessageToTopic(topicId, `用户 ${targetChatId} 的状态已重置。`);
    }

    async function sendAdminPanel(topicId, privateChatId, messageId = null, deleteTrigger = false) {
      const verificationEnabled = (await getSetting('verification_enabled', env.D1)) === 'true';
      const userRawEnabled = (await getSetting('user_raw_enabled', env.D1)) === 'true';
      const userInfo = await getUserInfo(privateChatId);
      const mapping = await getTopicMapping(privateChatId);
      const createdAt = mapping?.created_at ? new Date(mapping.created_at * 1000) : new Date();
      const formattedTime = createdAt.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

      const buttons = [
        [
          { text: '拉黑用户', callback_data: `block_${privateChatId}` },
          { text: '解除拉黑', callback_data: `unblock_${privateChatId}` }
        ],
        [
          { text: verificationEnabled ? '关闭验证' : '开启验证', callback_data: `toggle_verification_${privateChatId}` },
          { text: '查询黑名单', callback_data: `check_blocklist_${privateChatId}` }
        ],
        [
          { text: userRawEnabled ? '关闭用户Raw' : '开启用户Raw', callback_data: `toggle_user_raw_${privateChatId}` },
          { text: 'GitHub项目', url: 'https://github.com/iawooo/ctt' }
        ],
        [
          { text: '删除用户', callback_data: `delete_user_${privateChatId}` }
        ]
      ];

      const adminMessage = [
        '🛡️ 管理员面板',
        '',
        `昵称: ${userInfo?.nickname || `User_${privateChatId}`}`,
        `用户名: @${userInfo?.username || `User_${privateChatId}`}`,
        `UserID: ${privateChatId}`,
        `接入时间: ${formattedTime}`
      ].join('\n');

      if (deleteTrigger && messageId) {
        try {
          await telegramApi('deleteMessage', { chat_id: ADMIN_CHAT_ID, message_id: messageId });
        } catch (error) {
          console.log(`Unable to delete /admin command: ${error.message}`);
        }
      }

      const panelMessageId = deleteTrigger ? mapping?.panel_message_id : (messageId || mapping?.panel_message_id);
      if (panelMessageId) {
        try {
          await telegramApi('editMessageText', {
            chat_id: ADMIN_CHAT_ID,
            message_id: panelMessageId,
            text: adminMessage,
            reply_markup: { inline_keyboard: buttons }
          });
          return panelMessageId;
        } catch (error) {
          if (!String(error.message).includes('message is not modified')) {
            console.log(`Unable to edit admin panel, creating a new one: ${error.message}`);
          } else {
            return panelMessageId;
          }
        }
      }

      const sentMessage = await telegramApi('sendMessage', {
        chat_id: ADMIN_CHAT_ID,
        message_thread_id: topicId,
        text: adminMessage,
        reply_markup: { inline_keyboard: buttons }
      });
      await env.D1.prepare(
        'UPDATE chat_topic_mappings SET panel_message_id = ? WHERE chat_id = ? AND topic_chat_id = ?'
      ).bind(String(sentMessage.message_id), privateChatId, ADMIN_CHAT_ID).run();
      await pinMessage(sentMessage.message_id);
      return String(sentMessage.message_id);
    }

    async function getVerificationSuccessMessage() {
      const userRawEnabled = (await getSetting('user_raw_enabled', env.D1)) === 'true';
      if (!userRawEnabled) return '';

      const response = await fetch('https://raw.githubusercontent.com/spball/ctt/refs/heads/main/CFTeleTrans/start.md');
      if (!response.ok) return '';
      const message = await response.text();
      return message.trim() || '';
    }

    async function checkStartCommandRate(chatId) {
      const now = Date.now();
      const window = 5 * 60 * 1000;
      const maxStartsPerWindow = 1;

      let data = messageRateCache.get(chatId) || {};
      if (!Number.isFinite(data.start_count) || !Number.isFinite(data.start_window_start)) {
        const storedData = await env.D1.prepare('SELECT start_count, start_window_start FROM message_rates WHERE chat_id = ?')
          .bind(chatId)
          .first();
        data = {
          ...data,
          start_count: Number.isFinite(storedData?.start_count) ? storedData.start_count : 0,
          start_window_start: Number.isFinite(storedData?.start_window_start) ? storedData.start_window_start : now
        };
        await env.D1.prepare(
          `INSERT INTO message_rates (chat_id, start_count, start_window_start) VALUES (?, ?, ?)
           ON CONFLICT(chat_id) DO UPDATE SET start_count = excluded.start_count, start_window_start = excluded.start_window_start`
        ).bind(chatId, data.start_count, data.start_window_start).run();
      }

      if (now - data.start_window_start > window) {
        data.start_count = 1;
        data.start_window_start = now;
        await env.D1.prepare('UPDATE message_rates SET start_count = ?, start_window_start = ? WHERE chat_id = ?')
          .bind(data.start_count, data.start_window_start, chatId)
          .run();
      } else {
        data.start_count += 1;
        await env.D1.prepare('UPDATE message_rates SET start_count = ? WHERE chat_id = ?')
          .bind(data.start_count, chatId)
          .run();
      }

      messageRateCache.set(chatId, data);
      return data.start_count > maxStartsPerWindow;
    }

    async function checkMessageRate(chatId) {
      const now = Date.now();
      const window = 60 * 1000;

      let data = messageRateCache.get(chatId) || {};
      if (!Number.isFinite(data.message_count) || !Number.isFinite(data.window_start)) {
        const storedData = await env.D1.prepare('SELECT message_count, window_start FROM message_rates WHERE chat_id = ?')
          .bind(chatId)
          .first();
        data = {
          ...data,
          message_count: Number.isFinite(storedData?.message_count) ? storedData.message_count : 0,
          window_start: Number.isFinite(storedData?.window_start) ? storedData.window_start : now
        };
        await env.D1.prepare(
          `INSERT INTO message_rates (chat_id, message_count, window_start) VALUES (?, ?, ?)
           ON CONFLICT(chat_id) DO UPDATE SET message_count = excluded.message_count, window_start = excluded.window_start`
        ).bind(chatId, data.message_count, data.window_start).run();
      }

      if (now - data.window_start > window) {
        data.message_count = 1;
        data.window_start = now;
      } else {
        data.message_count += 1;
      }

      messageRateCache.set(chatId, data);
      await env.D1.prepare('UPDATE message_rates SET message_count = ?, window_start = ? WHERE chat_id = ?')
        .bind(data.message_count, data.window_start, chatId)
        .run();
      return data.message_count > MAX_MESSAGES_PER_MINUTE;
    }

    async function getSetting(key, d1) {
      const result = await d1.prepare('SELECT value FROM settings WHERE key = ?')
        .bind(key)
        .first();
      return result?.value || null;
    }

    async function setSetting(key, value) {
      await env.D1.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
        .bind(key, value)
        .run();
      if (key === 'verification_enabled') {
        settingsCache.set('verification_enabled', value === 'true');
        if (value === 'false') {
          const nowSeconds = Math.floor(Date.now() / 1000);
          const verifiedExpiry = nowSeconds + 3600 * 24;
          await env.D1.prepare('UPDATE user_states SET is_verified = ?, verified_expiry = ?, is_verifying = ?, verification_code = NULL, code_expiry = NULL, is_first_verification = ? WHERE chat_id NOT IN (SELECT chat_id FROM user_states WHERE is_blocked = TRUE)')
            .bind(true, verifiedExpiry, false, false)
            .run();
          await env.D1.prepare('DELETE FROM verification_challenges').run();
          userStateCache.clear();
        }
      } else if (key === 'user_raw_enabled') {
        settingsCache.set('user_raw_enabled', value === 'true');
      }
    }

    async function onCallbackQuery(callbackQuery) {
      const chatId = callbackQuery.message.chat.id.toString();
      const topicId = callbackQuery.message.message_thread_id;
      const data = callbackQuery.data || '';
      const messageId = callbackQuery.message.message_id;
      const callbackKey = `${chatId}:${callbackQuery.id}`;

      if (processedCallbacks.has(callbackKey)) return;
      processedCallbacks.add(callbackKey);
      if (processedCallbacks.size > 10000) processedCallbacks.clear();

      let action;
      let privateChatId;
      if (data.startsWith('toggle_verification_')) {
        action = 'toggle_verification';
        privateChatId = data.slice('toggle_verification_'.length);
      } else if (data.startsWith('toggle_user_raw_')) {
        action = 'toggle_user_raw';
        privateChatId = data.slice('toggle_user_raw_'.length);
      } else if (data.startsWith('check_blocklist_')) {
        action = 'check_blocklist';
        privateChatId = data.slice('check_blocklist_'.length);
      } else if (data.startsWith('block_')) {
        action = 'block';
        privateChatId = data.slice('block_'.length);
      } else if (data.startsWith('unblock_')) {
        action = 'unblock';
        privateChatId = data.slice('unblock_'.length);
      } else if (data.startsWith('delete_user_')) {
        action = 'delete_user';
        privateChatId = data.slice('delete_user_'.length);
      } else {
        await telegramApi('answerCallbackQuery', {
          callback_query_id: callbackQuery.id,
          text: '未知操作'
        });
        return;
      }

      const senderId = callbackQuery.from.id.toString();
      const mappedChatId = topicId ? await getPrivateChatId(topicId) : null;
      if (chatId !== ADMIN_CHAT_ID || !(await checkIfAdmin(senderId)) || mappedChatId !== privateChatId) {
        await telegramApi('answerCallbackQuery', {
          callback_query_id: callbackQuery.id,
          text: '无权执行此操作',
          show_alert: true
        });
        return;
      }

      let refreshPanel = true;
      if (action === 'block') {
        await env.D1.prepare(
          `INSERT INTO user_states (chat_id, is_blocked) VALUES (?, TRUE)
           ON CONFLICT(chat_id) DO UPDATE SET is_blocked = TRUE`
        ).bind(privateChatId).run();
        const state = userStateCache.get(privateChatId);
        if (state) userStateCache.set(privateChatId, { ...state, is_blocked: true });
        await sendMessageToTopic(topicId, `用户 ${privateChatId} 已被拉黑，消息将不再转发。`);
      } else if (action === 'unblock') {
        await env.D1.prepare(
          `INSERT INTO user_states (chat_id, is_blocked, is_first_verification) VALUES (?, FALSE, TRUE)
           ON CONFLICT(chat_id) DO UPDATE SET is_blocked = FALSE, is_first_verification = TRUE`
        ).bind(privateChatId).run();
        const state = userStateCache.get(privateChatId);
        if (state) userStateCache.set(privateChatId, { ...state, is_blocked: false, is_first_verification: true });
        await sendMessageToTopic(topicId, `用户 ${privateChatId} 已解除拉黑，消息将继续转发。`);
      } else if (action === 'toggle_verification') {
        const currentState = (await getSetting('verification_enabled', env.D1)) === 'true';
        const newState = !currentState;
        await setSetting('verification_enabled', newState.toString());
        await sendMessageToTopic(topicId, `Turnstile 验证已${newState ? '开启' : '关闭'}。`);
      } else if (action === 'check_blocklist') {
        const blockedUsers = await env.D1.prepare('SELECT chat_id FROM user_states WHERE is_blocked = TRUE').all();
        const blockList = blockedUsers.results.length
          ? blockedUsers.results.map(row => row.chat_id).join('\n')
          : '当前没有被拉黑的用户。';
        await sendMessageToTopic(topicId, `黑名单列表：\n${blockList}`);
      } else if (action === 'toggle_user_raw') {
        const currentState = (await getSetting('user_raw_enabled', env.D1)) === 'true';
        const newState = !currentState;
        await setSetting('user_raw_enabled', newState.toString());
        await sendMessageToTopic(topicId, `用户端 Raw 链接已${newState ? '开启' : '关闭'}。`);
      } else if (action === 'delete_user') {
        userStateCache.set(privateChatId, undefined);
        messageRateCache.set(privateChatId, undefined);
        topicIdCache.set(topicCacheKey(privateChatId), undefined);
        await env.D1.batch([
          env.D1.prepare('DELETE FROM verification_challenges WHERE chat_id = ?').bind(privateChatId),
          env.D1.prepare('DELETE FROM user_states WHERE chat_id = ?').bind(privateChatId),
          env.D1.prepare('DELETE FROM message_rates WHERE chat_id = ?').bind(privateChatId),
          env.D1.prepare('DELETE FROM chat_topic_mappings WHERE chat_id = ?').bind(privateChatId)
        ]);
        refreshPanel = false;
      }

      await telegramApi('answerCallbackQuery', { callback_query_id: callbackQuery.id });
      if (action === 'delete_user') {
        await telegramApi('deleteForumTopic', {
          chat_id: ADMIN_CHAT_ID,
          message_thread_id: topicId
        });
      } else if (refreshPanel) {
        await sendAdminPanel(topicId, privateChatId, messageId);
      }
    }

    async function issueVerificationChallenge(chatId) {
      const nowSeconds = Math.floor(Date.now() / 1000);
      const expiresAt = nowSeconds + VERIFICATION_TTL_SECONDS;
      const challenge = crypto.randomUUID();
      const tokenHash = await sha256Hex(challenge);
      const previousState = await env.D1.prepare(
        'SELECT last_verification_message_id FROM user_states WHERE chat_id = ?'
      ).bind(chatId).first();

      if (previousState?.last_verification_message_id) {
        try {
          await telegramApi('deleteMessage', {
            chat_id: chatId,
            message_id: previousState.last_verification_message_id
          });
        } catch (error) {
          console.log(`Unable to delete previous verification message: ${error.message}`);
        }
      }

      await env.D1.batch([
        env.D1.prepare('DELETE FROM verification_challenges WHERE chat_id = ?').bind(chatId),
        env.D1.prepare(
          'INSERT INTO verification_challenges (token_hash, chat_id, expires_at, used_at, created_at) VALUES (?, ?, ?, NULL, ?)'
        ).bind(tokenHash, chatId, expiresAt, nowSeconds),
        env.D1.prepare(
          'UPDATE user_states SET is_verifying = TRUE, verification_code = NULL, code_expiry = NULL, last_verification_message_id = NULL WHERE chat_id = ?'
        ).bind(chatId)
      ]);

      try {
        const verificationUrl = `${new URL(request.url).origin}/verify?challenge=${encodeURIComponent(challenge)}`;
        const sentMessage = await telegramApi('sendMessage', {
          chat_id: chatId,
          text: '发送消息前，请先完成 Cloudflare Turnstile 安全验证。验证链接 5 分钟内有效。',
          reply_markup: {
            inline_keyboard: [[
              { text: '开始验证', web_app: { url: verificationUrl } }
            ]]
          }
        });

        await env.D1.prepare(
          'UPDATE user_states SET last_verification_message_id = ? WHERE chat_id = ?'
        ).bind(String(sentMessage.message_id), chatId).run();
        const currentState = userStateCache.get(chatId) || {};
        userStateCache.set(chatId, {
          ...currentState,
          is_verifying: true,
          last_verification_message_id: String(sentMessage.message_id)
        });
      } catch (error) {
        await env.D1.batch([
          env.D1.prepare('DELETE FROM verification_challenges WHERE token_hash = ?').bind(tokenHash),
          env.D1.prepare('UPDATE user_states SET is_verifying = FALSE WHERE chat_id = ?').bind(chatId)
        ]);
        const currentState = userStateCache.get(chatId);
        if (currentState) userStateCache.set(chatId, { ...currentState, is_verifying: false });
        throw error;
      }
    }

    async function checkIfAdmin(userId) {
      return String(userId) === ADMIN_CHAT_ID;
    }

    async function getUserInfo(chatId) {
      let userInfo = userInfoCache.get(chatId);
      if (userInfo !== undefined) {
        return userInfo;
      }

      const response = await fetchWithRetry(`https://api.telegram.org/bot${BOT_TOKEN}/getChat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId })
      });
      const data = await response.json();
      if (!data.ok) {
        userInfo = {
          id: chatId,
          username: `User_${chatId}`,
          nickname: `User_${chatId}`
        };
      } else {
        const result = data.result;
        const nickname = result.first_name
          ? `${result.first_name}${result.last_name ? ` ${result.last_name}` : ''}`.trim()
          : result.username || `User_${chatId}`;
        userInfo = {
          id: result.id || chatId,
          username: result.username || `User_${chatId}`,
          nickname: nickname
        };
      }

      userInfoCache.set(chatId, userInfo);
      return userInfo;
    }

    function topicCacheKey(chatId) {
      return `${ADMIN_CHAT_ID}:${chatId}`;
    }

    async function getTopicMapping(chatId) {
      return env.D1.prepare(
        'SELECT topic_id, topic_chat_id, panel_message_id, created_at FROM chat_topic_mappings WHERE chat_id = ? AND topic_chat_id = ?'
      ).bind(chatId, ADMIN_CHAT_ID).first();
    }

    async function getExistingTopicId(chatId) {
      const cacheKey = topicCacheKey(chatId);
      let topicId = topicIdCache.get(cacheKey);
      if (topicId !== undefined) {
        return topicId;
      }

      const result = await getTopicMapping(chatId);
      topicId = result?.topic_id || null;
      if (topicId) {
        topicIdCache.set(cacheKey, topicId);
      }
      return topicId;
    }

    async function createForumTopic(topicName) {
      const normalizedName = String(topicName || '新用户').trim().slice(0, 128) || '新用户';
      const result = await telegramApi('createForumTopic', {
        chat_id: ADMIN_CHAT_ID,
        name: normalizedName
      });
      return result.message_thread_id;
    }

    async function saveTopicId(chatId, topicId) {
      const nowSeconds = Math.floor(Date.now() / 1000);
      await env.D1.prepare(
        `INSERT INTO chat_topic_mappings (chat_id, topic_id, topic_chat_id, panel_message_id, created_at)
         VALUES (?, ?, ?, NULL, ?)
         ON CONFLICT(chat_id) DO UPDATE SET
           topic_id = excluded.topic_id,
           topic_chat_id = excluded.topic_chat_id,
           panel_message_id = NULL,
           created_at = excluded.created_at`
      )
        .bind(chatId, String(topicId), ADMIN_CHAT_ID, nowSeconds)
        .run();
      topicIdCache.set(topicCacheKey(chatId), String(topicId));
    }

    async function getPrivateChatId(topicId) {
      const mapping = await env.D1.prepare(
        'SELECT chat_id FROM chat_topic_mappings WHERE topic_id = ? AND topic_chat_id = ?'
      )
        .bind(String(topicId), ADMIN_CHAT_ID)
        .first();
      return mapping?.chat_id || null;
    }

    async function sendMessageToTopic(topicId, text) {
      if (!text.trim()) {
        throw new Error('Message text is empty');
      }

      const result = await telegramApi('sendMessage', {
        chat_id: ADMIN_CHAT_ID,
        text: text,
        message_thread_id: topicId
      });
      return { ok: true, result };
    }

    async function copyMessageToTopic(topicId, message) {
      await telegramApi('copyMessage', {
        chat_id: ADMIN_CHAT_ID,
        from_chat_id: message.chat.id,
        message_id: message.message_id,
        message_thread_id: topicId,
        disable_notification: true
      });
    }

    async function pinMessage(messageId) {
      await telegramApi('pinChatMessage', {
        chat_id: ADMIN_CHAT_ID,
        message_id: messageId,
        disable_notification: true
      });
    }

    async function forwardMessageToPrivateChat(privateChatId, message) {
      await telegramApi('copyMessage', {
        chat_id: privateChatId,
        from_chat_id: message.chat.id,
        message_id: message.message_id,
        disable_notification: true
      });
    }

    async function sendMessageToUser(chatId, text) {
      if (!String(text).trim()) return null;
      return telegramApi('sendMessage', { chat_id: chatId, text: text });
    }

    async function telegramApi(method, payload) {
      const response = await fetchWithRetry(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!data.ok) {
        throw new Error(`Telegram ${method} failed: ${data.description || 'unknown error'}`);
      }
      return data.result;
    }

    async function fetchWithRetry(url, options, retries = 3, backoff = 1000) {
      for (let i = 0; i < retries; i++) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          const response = await fetch(url, { ...options, signal: controller.signal });
          clearTimeout(timeoutId);

          if (response.ok) {
            return response;
          }
          if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After') || 5;
            const delay = parseInt(retryAfter) * 1000;
            await new Promise(resolve => setTimeout(resolve, delay));
            continue;
          }
          throw new Error(`Request failed with status ${response.status}: ${await response.text()}`);
        } catch (error) {
          if (i === retries - 1) throw error;
          await new Promise(resolve => setTimeout(resolve, backoff * Math.pow(2, i)));
        }
      }
      throw new Error(`Failed to fetch ${url} after ${retries} retries`);
    }

    async function registerWebhook(request) {
      const webhookUrl = `${new URL(request.url).origin}/webhook`;
      const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl })
      }).then(r => r.json());
      return new Response(response.ok ? 'Webhook set successfully' : JSON.stringify(response, null, 2));
    }

    async function unRegisterWebhook() {
      const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/setWebhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: '' })
      }).then(r => r.json());
      return new Response(response.ok ? 'Webhook removed' : JSON.stringify(response, null, 2));
    }

    try {
      if (!isInitialized) {
        await initialize(env.D1, request);
        isInitialized = true;
      }
      return await handleRequest(request);
    } catch (error) {
      console.error(`Request failed: ${error.message}`);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
