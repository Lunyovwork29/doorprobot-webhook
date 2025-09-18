// api/amo-dp-webhook.js
// Vercel (Node runtime) — amoCRM Digital Pipeline webhook → Telegram
// Универсальная работа с заголовками/телом (Node/Edge safe) + автообновление токена + HMAC-подпись

// ===== ENV =====
const {
  // amoCRM auth/config
  AMO_CLIENT_ID,
  AMO_CLIENT_SECRET,
  AMO_REDIRECT_URI,

  AMO_REFRESH_TOKEN: ENV_REFRESH,
  AMO_ACCESS_TOKEN: ENV_ACCESS, // опционально (ускоряет холодный старт)

  // домены
  AMO_SUBDOMAIN,                // напр.: "new1754065789" (короткое имя без .amocrm.ru)
  AMO_API_DOMAIN,               // напр.: "new1754065789.amocrm.ru" (если не задан — соберём из SUBDOMAIN)

  // подпись вебхуков
  SECRET_TOKEN,                 // лучше использовать тот же secret из интеграции (client_secret)

  // Telegram
  TELEGRAM_BOT_TOKEN,
  TELEGRAM_CHAT_ID,
  TG_BOT_TOKEN,                 // запасные имена
  TG_CHAT_ID,

  // кастомные поля сделки (можно переопределить через ENV)
  FIELD_DOOR_TYPE_ID = '2094731',
  FIELD_CITY_ID      = '2094733',
} = process.env;

// ===== RUNTIME STATE (в памяти инстанса) =====
let cachedAccessToken  = ENV_ACCESS  || '';
let cachedRefreshToken = ENV_REFRESH || '';

const BOT_TOKEN = TELEGRAM_BOT_TOKEN || TG_BOT_TOKEN;
const CHAT_ID   = TELEGRAM_CHAT_ID   || TG_CHAT_ID;

const VERSION = 'amo-dp-webhook v1.1.0 (node-edge safe + HMAC)';

function log(level, ...args) {
  // level: 'info' | 'warn' | 'error'
  console[level]('[amo-dp]', ...args);
}

// ===== Utilities: headers/raw body (Node/Edge-safe) =====
function getHeader(req, name) {
  const n = String(name).toLowerCase();
  // Edge Request: Headers-like (get)
  if (req?.headers && typeof req.headers.get === 'function') {
    return req.headers.get(n) || '';
  }
  // Node: plain object
  if (req?.headers && typeof req.headers === 'object') {
    return req.headers[n] || '';
  }
  return '';
}

async function readRawBody(req) {
  // Edge: есть req.text()
  if (typeof req?.text === 'function') {
    return await req.text();
  }
  // Node: IncomingMessage — собираем чанки
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function parseBody(req) {
  const ctype = getHeader(req, 'content-type') || '';
  const raw = await readRawBody(req);

  if (ctype.includes('application/json')) {
    try { return JSON.parse(raw || '{}'); } catch { return {}; }
  }

  // amo часто шлёт form-urlencoded
  const params = new URLSearchParams(raw || '');
  const obj = Object.create(null);
  for (const [k, v] of params.entries()) obj[k] = v;
  return obj;
}

// ===== HMAC (amo → X-Signature) =====
function verifyAmoSignature(rawBody, headerSignature) {
  if (!SECRET_TOKEN) return true; // подпись не включена — пропускаем
  try {
    const crypto = require('crypto');
    const digest = crypto.createHmac('sha1', SECRET_TOKEN)
      .update(Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), 'utf8'))
      .digest('hex');
    return (headerSignature || '').toLowerCase() === digest.toLowerCase();
  } catch (e) {
    log('warn', 'Cannot verify HMAC (crypto error):', e?.message || e);
    return false;
  }
}

// ===== Telegram =====
async function sendTelegram(text) {
  if (!BOT_TOKEN || !CHAT_ID) {
    log('error', 'TG env missing; BOT_TOKEN/CHAT_ID');
    return { ok: false, note: 'tg env missing' };
  }
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: /^\-?\d+$/.test(String(CHAT_ID)) ? Number(CHAT_ID) : CHAT_ID,
      text,
      disable_web_page_preview: true,
    }),
  });
  let data = null;
  try { data = await resp.json(); } catch {}
  log('info', 'TG RESP:', resp.status, data?.ok === false ? data : 'ok');
  return data || { ok: false };
}

// ===== amo helpers =====
function uiSubdomain() {
  // если дали уже с доменом — аккуратно уберём .amocrm.ru, чтобы не задвоить
  const s = (AMO_SUBDOMAIN || '').replace(/\.amocrm\.ru$/i, '');
  return s || (AMO_API_DOMAIN || '').replace(/\.amocrm\.ru$/i, '');
}
function leadUrl(leadId) {
  return `https://${uiSubdomain()}.amocrm.ru/leads/detail/${leadId}`;
}

async function refreshAccessToken() {
  if (!cachedRefreshToken) throw new Error('No refresh token in env');
  const domain = AMO_API_DOMAIN || `${uiSubdomain()}.amocrm.ru`;
  const url = `https://${domain}/oauth2/access_token`;
  const body = {
    client_id:     AMO_CLIENT_ID,
    client_secret: AMO_CLIENT_SECRET,
    grant_type:    'refresh_token',
    refresh_token: cachedRefreshToken,
    redirect_uri:  AMO_REDIRECT_URI,
  };
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    log('error', 'REFRESH FAIL', resp.status, json);
    throw new Error('refresh_failed');
  }
  const newAccess  = json.access_token;
  const newRefresh = json.refresh_token;
  if (!newAccess) throw new Error('refresh_missing_access');

  cachedAccessToken = newAccess;
  if (newRefresh && newRefresh !== cachedRefreshToken) {
    const mask = (s) => s ? `${s.slice(0, 6)}…${s.slice(-6)}` : '';
    log('info', `REFRESH ROTATED → update AMO_REFRESH_TOKEN in Vercel: ${mask(newRefresh)}`);
    cachedRefreshToken = newRefresh;
  }
  log('info', 'TOKEN REFRESHED');
  return cachedAccessToken;
}

async function amoFetch(path, init = {}, allowRefresh = true) {
  const domain = AMO_API_DOMAIN || `${uiSubdomain()}.amocrm.ru`;
  const url = `https://${domain}${path}`;

  const doFetch = async (token) => fetch(url, {
    ...init,
    headers: {
      ...(init.headers || {}),
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  let token = cachedAccessToken;
  if (!token && cachedRefreshToken) {
    try { token = await refreshAccessToken(); } catch (e) { /* fallthrough */ }
  }
  let resp = await doFetch(token || '');
  if (resp.status === 401 && allowRefresh && cachedRefreshToken) {
    await refreshAccessToken();
    resp = await doFetch(cachedAccessToken);
  }
  return resp;
}

function pickCfValue(custom_fields_values = [], cfIdStr) {
  const cfId = Number(cfIdStr);
  const field = custom_fields_values.find((f) => Number(f.field_id) === cfId);
  if (!field || !Array.isArray(field.values) || !field.values.length) return '—';
  const v = field.values[0];
  return v.value ?? v.enum ?? '—';
}

function extractLeadEvent(raw) {
  // JSON формат: { leads: { status: [ {...} ] } }
  if (raw?.leads?.status) {
    const s = raw.leads.status[0];
    return {
      id: String(s?.id || ''),
      pipeline_id: String(s?.pipeline_id || ''),
      status_id: String(s?.status_id || ''),
      old_status_id: String(s?.old_status_id || ''),
    };
  }
  // form-urlencoded
  const id           = raw['leads[status][0][id]'];
  const pipeline_id  = raw['leads[status][0][pipeline_id]'];
  const status_id    = raw['leads[status][0][status_id]'];
  const old_status_id= raw['leads[status][0][old_status_id]'];
  return { id, pipeline_id, status_id, old_status_id };
}

async function buildPrettyMessage(leadId) {
  // 1) сделка
  const leadResp = await amoFetch(`/api/v4/leads/${leadId}?with=contacts`);
  const leadJson = await leadResp.json().catch(() => ({}));
  log('info', 'LEAD RESP STATUS:', leadResp.status);
  if (!leadResp.ok) {
    log('error', 'LEAD RESP BODY:', leadJson);
    throw new Error('lead_fetch_failed');
  }

  const name       = leadJson.name || `Сделка #${leadId}`;
  const respUserId = leadJson.responsible_user_id;
  const doorType   = pickCfValue(leadJson.custom_fields_values, FIELD_DOOR_TYPE_ID);
  const city       = pickCfValue(leadJson.custom_fields_values, FIELD_CITY_ID);

  // 2) ответственный
  let manager = '—';
  if (respUserId) {
    const userResp = await amoFetch(`/api/v4/users/${respUserId}`);
    const userJson = await userResp.json().catch(() => ({}));
    log('info', 'USER RESP STATUS:', userResp.status);
    if (userResp.ok) {
      manager = userJson.name || userJson.email || String(respUserId);
    } else {
      log('error', 'USER RESP BODY:', userJson);
    }
  }

  const url = leadUrl(leadId);
  return [
    '🚨 Упала новая заявка на производство',
    'Просьба срочно принять в работу.',
    '',
    `Сделка: ${name}`,
    `Ссылка: ${url}`,
    `Менеджер: ${manager}`,
    `Тип двери: ${doorType}`,
    `Город доставки: ${city}`,
  ].join('\n');
}

// ===== Handler =====
export default async function handler(req, res) {
  try {
    // health / версия для быстрого контроля деплоя
    if (req.method === 'GET') {
      return res.status(200).json({
        ok: true,
        version: VERSION,
        domain: AMO_API_DOMAIN || `${uiSubdomain()}.amocrm.ru`,
      });
    }

    if (req.method !== 'POST') return res.status(405).end();

    // читаем raw тело для HMAC
    const ctype = getHeader(req, 'content-type') || '';
    const rawBody = await readRawBody(req);

    // подпись (если SECRET_TOKEN задан)
    const xSig = getHeader(req, 'x-signature');
    if (SECRET_TOKEN) {
      const ok = verifyAmoSignature(rawBody, xSig);
      if (!ok) {
        log('error', 'Invalid HMAC signature');
        // 200, чтобы amo не потерял событие, но пометим ошибку
        return res.status(200).json({ ok: false, error: 'invalid_signature' });
      }
    } else {
      log('warn', 'SECRET_TOKEN is not set → skipping HMAC verification.');
    }

    // парсим в объект
    let rawParsed;
    try {
      if (ctype.includes('application/json')) {
        rawParsed = JSON.parse(rawBody || '{}');
      } else {
        const params = new URLSearchParams(rawBody || '');
        const o = Object.create(null);
        for (const [k, v] of params.entries()) o[k] = v;
        rawParsed = o;
      }
    } catch {
      rawParsed = {};
    }

    log('info', 'AMO RAW:', rawParsed);

    const ev = extractLeadEvent(rawParsed);
    const leadId = ev.id;
    if (!leadId) {
      // ничего критичного — зафиксируем и завершим
      return res.status(200).json({ ok: true, note: 'no lead id' });
    }

    // 1) минималка — чтобы событие не потерять даже если API ляжет
    const minimal = [
      '✅ Изменение сделки',
      `Deal #${leadId}`,
      `Pipeline: ${ev.pipeline_id}`,
      `Status: ${ev.old_status_id} → ${ev.status_id}`,
      leadUrl(leadId),
    ].join('\n');
    await sendTelegram(minimal);

    // 2) «красивое» подробное сообщение
    try {
      const text = await buildPrettyMessage(leadId);
      await sendTelegram(text);
      return res.status(200).json({ ok: true });
    } catch (e) {
      log('error', 'pretty build failed:', e?.message || e);
      return res.status(200).json({ ok: false, error: 'exception_after_minimal' });
    }
  } catch (e) {
    log('error', 'hook error', e);
    // Возвращаем 200, чтобы amo не «терял» событие
    return res.status(200).json({ ok: false });
  }
}
