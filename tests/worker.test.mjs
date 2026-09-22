import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workerSource = await readFile(new URL('../_worker.js', import.meta.url), 'utf8');
const workerModule = await import(`data:text/javascript;base64,${Buffer.from(workerSource).toString('base64')}`);

const {
  normalizePublicBaseUrl,
  renderVerificationPage,
  sha256Hex,
  validateTelegramInitData,
  verificationPageResponse
} = workerModule;

const botToken = '123456:TEST_TOKEN';
const nowSeconds = 1_800_000_000;

function createInitData({ userId = 42, authDate = nowSeconds, mutateHash = false } = {}) {
  const params = new URLSearchParams({
    auth_date: String(authDate),
    query_id: 'AAEAAAE',
    user: JSON.stringify({ id: userId, first_name: 'Test', username: 'tester' })
  });
  const dataCheckString = Array.from(params.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  const secretKey = createHmac('sha256', 'WebAppData').update(botToken).digest();
  const hash = createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  params.set('hash', mutateHash ? `${hash.slice(0, -1)}0` : hash);
  return params.toString();
}

test('validates authentic Telegram Mini App initData for the expected user', async () => {
  const result = await validateTelegramInitData(
    createInitData(),
    botToken,
    '42',
    300,
    nowSeconds
  );
  assert.equal(result.valid, true);
  assert.equal(result.user.id, 42);
});

test('rejects tampered, stale, and cross-user Telegram initData', async () => {
  const tampered = await validateTelegramInitData(
    createInitData({ mutateHash: true }), botToken, '42', 300, nowSeconds
  );
  assert.equal(tampered.valid, false);
  assert.equal(tampered.error, 'invalid-signature');

  const stale = await validateTelegramInitData(
    createInitData({ authDate: nowSeconds - 301 }), botToken, '42', 300, nowSeconds
  );
  assert.equal(stale.valid, false);
  assert.equal(stale.error, 'expired-init-data');

  const wrongUser = await validateTelegramInitData(
    createInitData({ userId: 99 }), botToken, '42', 300, nowSeconds
  );
  assert.equal(wrongUser.valid, false);
  assert.equal(wrongUser.error, 'user-mismatch');
});

test('hashes challenge tokens deterministically without exposing the token', async () => {
  assert.equal(
    await sha256Hex('challenge-token'),
    '6fce58c8aacc3bc1b62271a5bf7353c137ddc166f55212a44128fb9caebc7575'
  );
});

test('renders a Telegram Mini App with Turnstile and no secret key', () => {
  const html = renderVerificationPage('site-key-123', 'challenge-456');
  assert.match(html, /telegram-web-app\.js/);
  assert.match(html, /challenges\.cloudflare\.com\/turnstile/);
  assert.match(html, /site-key-123/);
  assert.match(html, /challenge-456/);
  assert.match(html, /\/api\/verify/);
  assert.doesNotMatch(html, /turnstile-secret/);
});

test('does not shadow the window.turnstile global with the widget container id', () => {
  const html = renderVerificationPage('site-key-123', 'challenge-456');
  assert.match(html, /id="turnstile-widget"/);
  assert.doesNotMatch(html, /id="turnstile"/);
});

test('verification pages are non-cacheable and constrained by CSP', () => {
  const response = verificationPageResponse('<p>ok</p>');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.match(response.headers.get('Content-Security-Policy'), /challenges\.cloudflare\.com/);
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
});

class FakeD1Statement {
  constructor(database, sql) {
    this.database = database;
    this.sql = sql.replace(/\s+/g, ' ').trim();
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async first() {
    const { sql, values, database } = this;
    if (sql.startsWith('SELECT sql FROM sqlite_master')) {
      return database.tables.has(values[0]) ? { sql: 'CREATE TABLE' } : null;
    }
    if (sql.startsWith('SELECT value FROM settings')) {
      const value = database.settings.get(values[0]);
      return value === undefined ? null : { value };
    }
    if (sql.includes('FROM verification_challenges vc')) {
      const challenge = database.challenges.get(values[0]);
      if (!challenge) return null;
      const user = database.users.get(challenge.chat_id) || {};
      return { ...challenge, is_blocked: user.is_blocked || false, last_verification_message_id: user.last_verification_message_id || null };
    }
    if (sql.startsWith('SELECT expires_at, used_at FROM verification_challenges')) {
      return database.challenges.get(values[0]) || null;
    }
    if (sql.startsWith('SELECT token_hash FROM verification_challenges')) {
      return Array.from(database.challenges.values()).find(record => (
        record.chat_id === String(values[0]) && !record.used_at && record.expires_at >= values[1]
      )) || null;
    }
    if (sql.startsWith('SELECT last_verification_message_id FROM user_states')) {
      return database.users.get(String(values[0])) || null;
    }
    if (sql.includes('FROM user_states WHERE chat_id = ?')) {
      return database.users.get(String(values[0])) || null;
    }
    if (sql.includes('FROM message_rates WHERE chat_id = ?')) {
      return database.rates.get(String(values[0])) || null;
    }
    if (sql.startsWith('SELECT topic_id, topic_chat_id')) {
      const mapping = database.mappings.get(String(values[0]));
      return mapping?.topic_chat_id === String(values[1]) ? mapping : null;
    }
    if (sql.startsWith('SELECT chat_id FROM chat_topic_mappings')) {
      return Array.from(database.mappings.entries())
        .map(([chat_id, mapping]) => ({ chat_id, ...mapping }))
        .find(mapping => mapping.topic_id === String(values[0]) && mapping.topic_chat_id === String(values[1])) || null;
    }
    return null;
  }

  async all() {
    const { sql, database } = this;
    if (sql.startsWith('PRAGMA table_info')) return { results: [] };
    if (sql.startsWith('SELECT chat_id FROM user_states WHERE code_expiry')) return { results: [] };
    if (sql.startsWith('SELECT chat_id FROM user_states WHERE is_blocked')) {
      return {
        results: Array.from(database.users.entries())
          .filter(([, user]) => user.is_blocked)
          .map(([chat_id]) => ({ chat_id }))
      };
    }
    return { results: [] };
  }

  async run() {
    const { sql, values, database } = this;
    if (sql.startsWith('INSERT OR IGNORE INTO settings')) {
      if (!database.settings.has(values[0])) database.settings.set(values[0], values[1]);
    } else if (sql.startsWith('DELETE FROM verification_challenges WHERE expires_at')) {
      for (const [key, record] of database.challenges) {
        if (record.expires_at < values[0] || record.used_at) database.challenges.delete(key);
      }
    } else if (sql.startsWith('DELETE FROM verification_challenges WHERE chat_id')) {
      for (const [key, record] of database.challenges) {
        if (record.chat_id === String(values[0])) database.challenges.delete(key);
      }
    } else if (sql.startsWith('DELETE FROM verification_challenges WHERE token_hash')) {
      database.challenges.delete(values[0]);
    } else if (sql.startsWith('INSERT INTO verification_challenges')) {
      database.challenges.set(values[0], {
        token_hash: values[0], chat_id: String(values[1]), expires_at: values[2], used_at: null, created_at: values[3]
      });
    } else if (sql.startsWith('UPDATE verification_challenges SET used_at')) {
      const record = database.challenges.get(values[1]);
      if (record && !record.used_at && record.expires_at >= values[2]) {
        record.used_at = values[0];
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    } else if (sql.startsWith('INSERT INTO user_states (chat_id, is_blocked, is_first_verification, is_verified')) {
      database.users.set(String(values[0]), {
        is_blocked: Boolean(values[1]), is_first_verification: Boolean(values[2]),
        is_verified: Boolean(values[3]), is_verifying: Boolean(values[4]), verified_expiry: null
      });
    } else if (sql.startsWith('UPDATE user_states SET is_verifying = TRUE')) {
      const user = database.user(values[0]);
      Object.assign(user, { is_verifying: true, last_verification_message_id: null });
    } else if (sql.startsWith('UPDATE user_states SET last_verification_message_id')) {
      database.user(values[1]).last_verification_message_id = String(values[0]);
    } else if (sql.startsWith('UPDATE user_states SET is_verifying = FALSE')) {
      database.user(values[0]).is_verifying = false;
    } else if (sql.startsWith('INSERT INTO user_states (chat_id, is_verified')) {
      const user = database.user(values[0]);
      Object.assign(user, {
        is_verified: true, verified_expiry: values[1], is_first_verification: false,
        is_verifying: false, last_verification_message_id: null
      });
    } else if (sql.startsWith('INSERT INTO message_rates (chat_id, message_count, window_start)')) {
      database.rates.set(String(values[0]), { message_count: Number(values[1]), window_start: values[2] });
    } else if (sql.startsWith('INSERT INTO message_rates (chat_id, start_count')) {
      database.rates.set(String(values[0]), { start_count: values[1], start_window_start: values[2], message_count: 0, window_start: values[2] });
    } else if (sql.startsWith('UPDATE message_rates SET message_count')) {
      Object.assign(database.rate(values[2]), { message_count: values[0], window_start: values[1] });
    } else if (sql.startsWith('INSERT INTO chat_topic_mappings')) {
      database.mappings.set(String(values[0]), {
        topic_id: String(values[1]), topic_chat_id: String(values[2]), panel_message_id: null, created_at: values[3]
      });
    } else if (sql.startsWith('UPDATE chat_topic_mappings SET panel_message_id')) {
      database.mappings.get(String(values[1])).panel_message_id = String(values[0]);
    }
    return { meta: { changes: 1 } };
  }
}

class FakeD1 {
  constructor() {
    this.tables = new Set();
    this.settings = new Map();
    this.users = new Map();
    this.rates = new Map();
    this.challenges = new Map();
    this.mappings = new Map();
  }

  prepare(sql) { return new FakeD1Statement(this, sql); }
  user(chatId) {
    const key = String(chatId);
    if (!this.users.has(key)) this.users.set(key, {});
    return this.users.get(key);
  }
  rate(chatId) {
    const key = String(chatId);
    if (!this.rates.has(key)) this.rates.set(key, {});
    return this.rates.get(key);
  }
  async exec(sql) {
    const match = sql.match(/^CREATE TABLE ([a-z_]+)/i);
    if (match) this.tables.add(match[1]);
    return { success: true };
  }
  async batch(statements) { return Promise.all(statements.map(statement => statement.run())); }
}

test('runs first verification, creates one private admin Thread, and rejects replay', async () => {
  const database = new FakeD1();
  const calls = [];
  let messageId = 100;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const href = String(url);
    const body = options.body ? JSON.parse(options.body) : {};
    calls.push({ href, body });
    if (href.includes('challenges.cloudflare.com/turnstile')) {
      return Response.json(body.response === 'bad-token'
        ? { success: false, 'error-codes': ['invalid-input-response'] }
        : { success: true, action: 'telegram_verify' });
    }
    if (href.includes('raw.githubusercontent.com')) return new Response('Ready');
    const method = href.split('/').at(-1);
    if (method === 'getMe') return Response.json({ ok: true, result: { id: 7, has_topics_enabled: true } });
    if (method === 'getWebhookInfo') return Response.json({ ok: true, result: { url: '' } });
    if (method === 'getChat') {
      const id = String(body.chat_id);
      return Response.json({ ok: true, result: id === '9001'
        ? { id: 9001, type: 'private', first_name: 'Admin' }
        : { id: 42, type: 'private', first_name: 'Test', username: 'tester' } });
    }
    if (method === 'createForumTopic') return Response.json({ ok: true, result: { message_thread_id: 77 } });
    if (method === 'sendMessage') return Response.json({ ok: true, result: { message_id: ++messageId } });
    if (['setWebhook', 'deleteMessage', 'pinChatMessage', 'copyMessage', 'answerCallbackQuery'].includes(method)) {
      return Response.json({ ok: true, result: true });
    }
    throw new Error(`Unexpected fetch: ${href}`);
  };

  try {
    const env = {
      BOT_TOKEN_ENV: botToken,
      ADMIN_CHAT_ID_ENV: '9001',
      TURNSTILE_SITE_KEY_ENV: 'site-key',
      TURNSTILE_SECRET_KEY_ENV: 'secret-key',
      D1: database
    };
    const webhookResponse = await workerModule.default.fetch(new Request('https://bot.example/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: { message_id: 1, chat: { id: 42 }, text: '/start' } })
    }), env);
    assert.equal(webhookResponse.status, 200);

    const launchCall = calls.find(call => call.href.endsWith('/sendMessage') && call.body.chat_id === '42');
    const launchUrl = launchCall.body.reply_markup.inline_keyboard[0][0].web_app.url;
    const challenge = new URL(launchUrl).searchParams.get('challenge');
    assert.ok(challenge);
    assert.equal(database.challenges.size, 1);
    assert.equal(calls.some(call => call.href.endsWith('/createForumTopic')), false);

    const verificationPage = await workerModule.default.fetch(
      new Request(`https://bot.example/verify?challenge=${encodeURIComponent(challenge)}`), env
    );
    assert.equal(verificationPage.status, 200);
    assert.match(await verificationPage.text(), /challenges\.cloudflare\.com\/turnstile/);

    const failedTurnstileResponse = await workerModule.default.fetch(new Request('https://bot.example/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge,
        turnstileToken: 'bad-token',
        initData: createInitData({ authDate: Math.floor(Date.now() / 1000) })
      })
    }), env);
    assert.equal(failedTurnstileResponse.status, 400);
    assert.equal(calls.some(call => call.href.endsWith('/createForumTopic')), false);

    const verificationResponse = await workerModule.default.fetch(new Request('https://bot.example/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.2' },
      body: JSON.stringify({
        challenge,
        turnstileToken: 'turnstile-token',
        initData: createInitData({ authDate: Math.floor(Date.now() / 1000) })
      })
    }), env);
    assert.equal(verificationResponse.status, 200);
    assert.deepEqual(await verificationResponse.json(), { ok: true });

    const topicCalls = calls.filter(call => call.href.endsWith('/createForumTopic'));
    assert.equal(topicCalls.length, 1);
    assert.equal(String(topicCalls[0].body.chat_id), '9001');
    assert.equal(database.mappings.get('42').topic_chat_id, '9001');
    assert.ok(database.mappings.get('42').panel_message_id);
    assert.ok(calls.some(call => call.href.endsWith('/pinChatMessage') && String(call.body.chat_id) === '9001'));

    const replayResponse = await workerModule.default.fetch(new Request('https://bot.example/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge,
        turnstileToken: 'second-token',
        initData: createInitData({ authDate: Math.floor(Date.now() / 1000) })
      })
    }), env);
    assert.equal(replayResponse.status, 410);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fails closed when required Worker bindings are missing', async () => {
  const response = await workerModule.default.fetch(
    new Request('https://bot.example/webhook', { method: 'POST', body: '{}' }),
    { D1: new FakeD1() }
  );
  assert.equal(response.status, 500);
  assert.match(await response.text(), /ADMIN_CHAT_ID_ENV/);
});

test('does not re-challenge a user whose verification state was written by another request', async () => {
  const database = new FakeD1();
  database.settings.set('verification_enabled', 'true');
  const calls = [];
  let messageId = 500;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const href = String(url);
    const body = options.body ? JSON.parse(options.body) : {};
    calls.push({ href, body });
    if (href.includes('raw.githubusercontent.com')) return new Response('Ready');
    const method = href.split('/').at(-1);
    if (method === 'getMe') return Response.json({ ok: true, result: { id: 7, has_topics_enabled: true } });
    if (method === 'getWebhookInfo') return Response.json({ ok: true, result: { url: '' } });
    if (method === 'getChat') {
      const id = String(body.chat_id);
      return Response.json({ ok: true, result: id === '9001'
        ? { id: 9001, type: 'private', first_name: 'Admin' }
        : { id: 4242, type: 'private', first_name: 'Test', username: 'tester' } });
    }
    if (method === 'createForumTopic') return Response.json({ ok: true, result: { message_thread_id: 77 } });
    if (method === 'sendMessage') return Response.json({ ok: true, result: { message_id: ++messageId } });
    if (['setWebhook', 'deleteMessage', 'pinChatMessage', 'copyMessage', 'answerCallbackQuery'].includes(method)) {
      return Response.json({ ok: true, result: true });
    }
    throw new Error(`Unexpected fetch: ${href}`);
  };

  const env = {
    BOT_TOKEN_ENV: botToken,
    ADMIN_CHAT_ID_ENV: '9001',
    TURNSTILE_SITE_KEY_ENV: 'site-key',
    TURNSTILE_SECRET_KEY_ENV: 'secret-key',
    D1: database
  };

  const sendUserMessage = (messageId, text) => workerModule.default.fetch(new Request('https://bot.example/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: { message_id: messageId, chat: { id: 4242 }, text } })
  }), env);
  const challengesToUser = () => calls.filter(call => (
    call.href.endsWith('/sendMessage') && String(call.body.chat_id) === '4242' && call.body.reply_markup
  ));

  try {
    await sendUserMessage(7101, 'hello');
    assert.equal(challengesToUser().length, 1, 'an unverified user must be sent a verification challenge');

    database.users.set('4242', {
      is_blocked: false, is_first_verification: false, is_verified: true,
      verified_expiry: Math.floor(Date.now() / 1000) + 3600, is_verifying: false,
      last_verification_message_id: null
    });
    calls.length = 0;

    await sendUserMessage(7102, 'hello again');

    assert.equal(challengesToUser().length, 0, 'a verified user must not be challenged again');
    assert.ok(
      calls.some(call => call.href.endsWith('/sendMessage')
        && String(call.body.chat_id) === '9001'
        && String(call.body.text).includes('hello again')),
      'the message must be forwarded to the admin topic'
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('normalizes the configured public base URL and rejects non-https values', () => {
  assert.equal(normalizePublicBaseUrl('https://ctt.example/verify?x=1'), 'https://ctt.example');
  assert.equal(normalizePublicBaseUrl('http://ctt.example'), null);
  assert.equal(normalizePublicBaseUrl('not a url'), null);
  assert.equal(normalizePublicBaseUrl(''), null);
  assert.equal(normalizePublicBaseUrl(undefined), null);
});

test('maintenance endpoints require a token and honor the configured public base URL', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    const href = String(url);
    const body = options.body ? JSON.parse(options.body) : {};
    calls.push({ href, body });
    if (href.includes('raw.githubusercontent.com')) return new Response('Ready');
    const method = href.split('/').at(-1);
    if (method === 'getMe') return Response.json({ ok: true, result: { id: 7, has_topics_enabled: true } });
    if (method === 'getWebhookInfo') return Response.json({ ok: true, result: { url: '' } });
    if (method === 'setWebhook') return Response.json({ ok: true, result: true });
    throw new Error(`Unexpected fetch: ${href}`);
  };

  const env = {
    BOT_TOKEN_ENV: botToken,
    ADMIN_CHAT_ID_ENV: '9001',
    TURNSTILE_SITE_KEY_ENV: 'site-key',
    TURNSTILE_SECRET_KEY_ENV: 'secret-key',
    PUBLIC_BASE_URL_ENV: 'https://ctt.example',
    D1: new FakeD1()
  };
  const withToken = { ...env, MAINTENANCE_TOKEN_ENV: 's3cret' };
  const lastSetWebhook = () => calls.filter(call => call.href.endsWith('/setWebhook')).at(-1);

  try {
    const disabled = await workerModule.default.fetch(new Request('https://bot.example/registerWebhook'), env);
    assert.equal(disabled.status, 503);

    const missingToken = await workerModule.default.fetch(new Request('https://bot.example/registerWebhook'), withToken);
    assert.equal(missingToken.status, 401);

    const wrongToken = await workerModule.default.fetch(new Request('https://bot.example/checkTables?token=nope'), withToken);
    assert.equal(wrongToken.status, 401);

    const authorized = await workerModule.default.fetch(
      new Request('https://bot.example/registerWebhook', { headers: { Authorization: 'Bearer s3cret' } }),
      withToken
    );
    assert.equal(authorized.status, 200);
    assert.equal(lastSetWebhook().body.url, 'https://ctt.example/webhook');

    const viaQuery = await workerModule.default.fetch(
      new Request('https://bot.example/registerWebhook?token=s3cret'),
      { ...withToken, PUBLIC_BASE_URL_ENV: undefined }
    );
    assert.equal(viaQuery.status, 200);
    assert.equal(lastSetWebhook().body.url, 'https://bot.example/webhook');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
