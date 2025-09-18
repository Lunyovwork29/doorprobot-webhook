// api/amo-dp-webhook.js
// amoCRM → Webhook → Vercel (Node runtime). Без require, с raw-body, HMAC (hex|base64), авто-рефреш токена.

const {
  // amoCRM OAuth
  AMO_CLIENT_ID,
  AMO_CLIENT_SECRET,
  AMO_REDIRECT_URI,

  // домены
  AMO_SUBDOMAIN,                 // напр.: "new1754065789" (без .amocrm.ru)
  AMO_API_DOMAIN,                // напр.: "new1754065789.amocrm.ru" (если не задан — соберём из SUBDOMAIN)

  // стартовые токены
  AMO_ACCESS_TOKEN: ENV_ACCESS,
  AMO_REFRESH_TOKEN: ENV_REFRESH,

  // вебхук-подпись (секрет интеграции)
  SECRET_TOKEN,                  // = секретный ключ интеграции (можно равен client_secret)

  // Telegram
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
  TG_BOT_TOKEN, TG_CHAT_ID,

  // Кастомные поля сделки (ID можно переопределить через ENV)
  FIELD_DOOR_TYPE_ID = '2094731',
  FIELD_CITY_ID      = '2094733',
} = process.env;

// ——— state (в памяти функции)
let cachedAccessToken  = ENV_ACCESS  || '';
let cachedRefreshToken = ENV_REFRESH || '';

const BOT_TOKEN = TELEGRAM_BOT_TOKEN || TG_BOT_TOKEN;
const CHAT_ID   = TELEGRAM_CHAT_ID   || TG_CHAT_ID;

const VERSION = 'amo-dp-webhook v1.2.0';

// ---------- helpers: лог, сабдомен/домен ----------
function log(level, ...args) {
  console[level]('[amo-dp]', ...args);
}
function uiSubdomain() {
  // нормализуем короткое имя
  const s = (AMO_SUBDOMAIN || '').replace(/\.amocrm\.ru$/i, '');
  if (s) return s;
  const fromApi = (AMO_API_DOMAIN || '').replace(/\.amocrm\.ru$/i, '');
  return fromApi || 'api-b'; // fallback (лучше явно задать AMO_API_DOMAIN)
}
function domainHost() {
  return (AMO_API_DOMAIN && AMO_API_DOMAIN.trim())
    ? AMO_API_DOMAIN.trim()
    : `${uiSubdomain()}.amocrm.ru`;
}
function leadUrl(leadId) {
  return `https://${uiSubdomain()}.amocrm.ru/leads/detail/${leadId}`;
}

// ---------- headers & raw body (Node/Edge-safe) ----------
function getHeader(req, name) {
  const n = String(name).toLowerCase();
  if (req?.headers && typeof req.headers.get === 'function') return req.headers.get(n) || '';
  if (req?.headers && typeof req.headers === 'object') return req.headers[n] || '';
  return '';
}
async function readRawBody(req) {
  if (typeof req?.text === 'function') return await req.text(); // Edge
  // Node IncomingMessage stream:
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
function parseUrlEncoded(str) {
  const params = new URLSearchParams(str || '');
  const o = Object.create(null);
  for (const [k, v] of params.entries()) o[k] = v;
  return o;
}

// ---------- HMAC подпись (hex|base64), без require ----------
async function verifyAmoSignature(rawBody, headerSignature) {
  if (!SECRET_TOKEN) return { ok: true, mode: 'no_secret' };
  const sig = (headerSignature || '').trim();
  try {
    const { createHmac } = await import('node:crypto');
    const rawStr = typeof rawBody === 'string' ? rawBody : String(rawBody ?? '');
    const data = typeof Buffer !== 'undefined'
      ? Buffer.from(rawStr, 'utf8')
      : new TextEncoder().encode(rawStr);

    const h1 = createHmac('sha1', SECRET_TOKEN).update(data).digest('hex');
    const h2 = createHmac('sha1', SECRET_TOKEN).update(data).digest('base64');

    const ok = sig.toLowerCase() === h1.toLowerCase() || sig === h2;
    if (!ok) {
      const short = (s) => (s ? `${s.slice(0, 16)}…${s.slice(-8)}` : '');
      log('error', 'Invalid HMAC signature', { got: short(sig), want_hex: short(h1), want_b64: short(h2) });
    }
    return { ok, hex: h1, b64: h2 };
  } catch (e) {
    log('warn', 'HMAC crypto error:', e?.message || e);
    return { ok: false, mode: 'crypto_error' };
  }
}

// ---------- Telegram ----------
async function sendTelegram(text) {
  if (!BOT_TOKEN || !CHAT_ID) {
    log('error', 'TG env missing (BOT_TOKEN/CHAT_ID)');
    return { ok: false };
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
  let data = null; try { data = await resp.json(); } catch {}
  log('info', 'TG', resp.status, data?.ok === false ? data : 'ok');
  return data || { ok: false };
}

// ---------- OAuth refresh & amoFetch ----------
async function refreshAccessToken() {
  if (!cachedRefreshToken) throw new Error('No refresh token');
  const url = `https://${domainHost()}/oauth2/access_token`;
  const body = {
    client_id:     AMO_CLIENT_ID,
    client_secret: AMO_CLIENT_SECRET,
    grant_type:    'refresh_token',
    refresh_token: cachedRefreshToken,
    redirect_uri:  AMO_REDIRECT_URI,
  };
  const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) { log('error', 'REFRESH FAIL', resp.status, json); throw new Error('refresh_failed'); }
  cachedAccessToken  = json.access_token || '';
  const newRefresh   = json.refresh_token;
  if (newRefresh && newRefresh !== cachedRefreshToken) {
    const mask = (s) => s ? `${s.slice(0,6)}…${s.slice(-6)}` : '';
    log('info', `REFRESH ROTATED → update AMO_REFRESH_TOKEN in Vercel: ${mask(newRefresh)}`);
    cachedRefreshToken = newRefresh;
  }
  log('info', 'TOKEN REFRESHED');
  return cachedAccessToken;
}
async function amoFetch(path, init = {}, allowRefresh = true) {
  const url = `https://${domainHost()}${path}`;
  const doFetch = async (token) => fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}), Authorization: `Bearer ${token}` },
  });

  let token = cachedAccessToken;
  if (!token && cachedRefreshToken) { try { token = await refreshAccessToken(); } catch {} }
  let resp = await doFetch(token || '');
  if (resp.status === 401 && allowRefresh && cachedRefreshToken) {
    await refreshAccessToken();
    resp = await doFetch(cachedAccessToken);
  }
  return resp;
}

// ---------- lead utils ----------
function pickCfValue(custom_fields_values = [], fieldIdStr) {
  const fid = Number(fieldIdStr);
  const f = custom_fields_values.find((x) => Number(x.field_id) === fid);
  if (!f || !Array.isArray(f.values) || !f.values.length) return '—';
  const v = f.values[0];
  return v.value ?? v.enum ?? '—';
}
function extractLeadEvent(raw) {
  if (raw?.leads?.status) {
    const s = raw.leads.status[0];
    return {
      id: String(s?.id || ''),
      pipeline_id: String(s?.pipeline_id || ''),
      status_id: String(s?.status_id || ''),
      old_status_id: String(s?.old_status_id || ''),
    };
  }
  return {
    id:            raw['leads[status][0][id]'],
    pipeline_id:   raw['leads[status][0][pipeline_id]'],
    status_id:     raw['leads[status][0][status_id]'],
    old_status_id: raw['leads[status][0][old_status_id]'],
  };
}
async function buildPrettyMessage(leadId) {
  const leadResp = await amoFetch(`/api/v4/leads/${leadId}?with=contacts`);
  const leadJson = await leadResp.json().catch(() => ({}));
  if (!leadResp.ok) { log('error', 'LEAD FAIL', leadResp.status, leadJson); throw new Error('lead_fetch_failed'); }

  const name       = leadJson.name || `Сделка #${leadId}`;
  const respUserId = leadJson.responsible_user_id;
  const doorType   = pickCfValue(leadJson.custom_fields_values, FIELD_DOOR_TYPE_ID);
  const city       = pickCfValue(leadJson.custom_fields_values, FIELD_CITY_ID);

  let manager = '—';
  if (respUserId) {
    const u = await amoFetch(`/api/v4/users/${respUserId}`);
    const uj = await u.json().catch(() => ({}));
    if (u.ok) manager = uj.name || uj.email || String(respUserId);
  }

  return [
    '🚨 Упала новая заявка на производство',
    'Просьба срочно принять в работу.',
    '',
    `Сделка: ${name}`,
    `Ссылка: ${leadUrl(leadId)}`,
    `Менеджер: ${manager}`,
    `Тип двери: ${doorType}`,
    `Город доставки: ${city}`,
  ].join('\n');
}

// ---------- handler ----------
export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      return res.status(200).json({ ok: true, version: VERSION, domain: domainHost() });
    }
    if (req.method !== 'POST') return res.status(405).end();

    // 1) читаем сырое тело до любого парсинга
    const contentType = getHeader(req, 'content-type') || '';
    const rawBody = await readRawBody(req);

    // 2) HMAC-подпись (hex|base64). Заголовок может быть любым регистром.
    const headerSig = getHeader(req, 'x-signature') || getHeader(req, 'X-Signature') || '';
    const sigCheck  = await verifyAmoSignature(rawBody, headerSig);

    log('info', 'SIG-CONTEXT', {
      ctype: contentType,
      len: rawBody?.length || 0,
      headSig: headerSig ? (headerSig.slice(0,16) + '…') : null,
      sample: (rawBody || '').slice(0, 200),
    });

    if (!sigCheck.ok) {
      // возвращаем 200, чтобы amo не ретраил, но фиксируем проблему
      return res.status(200).json({ ok: false, error: 'invalid_signature' });
    }

    // 3) парсим тело
    let data;
    if (contentType.includes('application/json')) {
      try { data = JSON.parse(rawBody || '{}'); } catch { data = {}; }
    } else {
      data = parseUrlEncoded(rawBody);
    }
    log('info', 'AMO RAW:', { keys: Object.keys(data).slice(0, 12) });

    // 4) вынимаем событие
    const ev = extractLeadEvent(data);
    const leadId = ev.id;
    if (!leadId) return res.status(200).json({ ok: true, note: 'no_lead_id' });

    // 5) «минималка» — всегда отправляем сразу
    const minimal = [
      '✅ Изменение сделки',
      `Deal #${leadId}`,
      `Pipeline: ${ev.pipeline_id}`,
      `Status: ${ev.old_status_id} → ${ev.status_id}`,
      leadUrl(leadId),
    ].join('\n');
    await sendTelegram(minimal);

    // 6) расшифровка и «красивое» сообщение
    try {
      const pretty = await buildPrettyMessage(leadId);
      await sendTelegram(pretty);
      return res.status(200).json({ ok: true });
    } catch (e) {
      log('error', 'pretty fail:', e?.message || e);
      return res.status(200).json({ ok: false, error: 'pretty_exception' });
    }
  } catch (e) {
    log('error', 'hook error', e?.stack || e);
    // Возвращаем 200, чтобы amo не терял событие
    return res.status(200).json({ ok: false });
  }
}
