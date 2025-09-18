// api/amo-dp-webhook.js
// Vercel Edge/Node function: авто-обновляет access_token, тянет данные сделки и шлёт красиво в Telegram

const {
  AMO_CLIENT_ID,
  AMO_CLIENT_SECRET,
  AMO_REDIRECT_URI,
  AMO_REFRESH_TOKEN: ENV_REFRESH,
  AMO_ACCESS_TOKEN: ENV_ACCESS, // опционально
  AMO_SUBDOMAIN,
  AMO_API_DOMAIN,
  SECRET_TOKEN,

  TELEGRAM_BOT_TOKEN,
  TELEGRAM_CHAT_ID,

  // запасные имена, если захочешь оставить TG_*
  TG_BOT_TOKEN,
  TG_CHAT_ID,

  FIELD_DOOR_TYPE_ID = '2094731',
  FIELD_CITY_ID = '2094733',
} = process.env;

// кеш в памяти для «тёплой» функции (Vercel сохраняет в рамках инстанса)
let cachedAccessToken = ENV_ACCESS || '';
let cachedRefreshToken = ENV_REFRESH || '';

const BOT_TOKEN = TELEGRAM_BOT_TOKEN || TG_BOT_TOKEN;
const CHAT_ID = TELEGRAM_CHAT_ID || TG_CHAT_ID;

function log(level, ...args) {
  console[level](`[amo-dp]`, ...args);
}

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
  log('info', 'TG RESP:', resp.status, data);
  return data || { ok: false };
}

async function parseBody(req) {
  const ctype = req.headers.get('content-type') || '';
  if (ctype.includes('application/json')) {
    return await req.json(); // digital pipeline может так прислать
  }
  // amo чаще шлёт form-urlencoded
  const text = await req.text();
  const params = new URLSearchParams(text);
  const obj = Object.create(null);
  for (const [k, v] of params.entries()) obj[k] = v;
  return obj;
}

function extractLeadEvent(raw) {
  // поддержка обоих форматов: form и json
  if (raw?.leads?.status) {
    // JSON вида { leads: { status: [ {...} ] } }
    const s = raw.leads.status[0];
    return {
      id: String(s?.id || ''),
      pipeline_id: String(s?.pipeline_id || ''),
      status_id: String(s?.status_id || ''),
      old_status_id: String(s?.old_status_id || ''),
    };
  }
  // form-urlencoded
  const id = raw['leads[status][0][id]'];
  const pipeline_id = raw['leads[status][0][pipeline_id]'];
  const status_id = raw['leads[status][0][status_id]'];
  const old_status_id = raw['leads[status][0][old_status_id]'];
  return { id, pipeline_id, status_id, old_status_id };
}

function leadUrl(leadId) {
  // UI-ссылка всегда на субдомен
  return `https://${AMO_SUBDOMAIN}.amocrm.ru/leads/detail/${leadId}`;
}

async function refreshAccessToken() {
  if (!cachedRefreshToken) throw new Error('No refresh token in env');
  const url = `https://${AMO_SUBDOMAIN}.amocrm.ru/oauth2/access_token`;
  const body = {
    client_id: AMO_CLIENT_ID,
    client_secret: AMO_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: cachedRefreshToken,
    redirect_uri: AMO_REDIRECT_URI,
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

  const newAccess = json.access_token;
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
  if (!AMO_API_DOMAIN) throw new Error('AMO_API_DOMAIN required');
  const url = `https://${AMO_API_DOMAIN}${path}`;

  // всегда пробуем с текущим access; если 401 — рефрешимся и повторяем
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
  // поддержим простой текст и «элементы списков»
  return v.value ?? v.enum ?? '—';
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

  const name = leadJson.name || `Сделка #${leadId}`;
  const respUserId = leadJson.responsible_user_id;
  const doorType = pickCfValue(leadJson.custom_fields_values, FIELD_DOOR_TYPE_ID);
  const city     = pickCfValue(leadJson.custom_fields_values, FIELD_CITY_ID);

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

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') return res.status(405).end();

    // защита по секрету (query ?token=…)
    const okSecret = !SECRET_TOKEN || (req.query?.token === SECRET_TOKEN);
    if (!okSecret) return res.status(401).json({ ok: false, error: 'bad token' });

    const raw = await parseBody(req);
    log('info', 'AMO RAW:', raw);

    const ev = extractLeadEvent(raw);
    const leadId = ev.id;
    if (!leadId) return res.status(200).json({ ok: true, note: 'no lead id' });

    // 1) минималка — чтобы событие не потерять даже если API ляжет
    const minimal = [
      '✅ Изменение сделки',
      `Deal #${leadId}`,
      `Pipeline: ${ev.pipeline_id}`,
      `Status: ${ev.old_status_id} → ${ev.status_id}`,
      leadUrl(leadId),
    ].join('\n');
    await sendTelegram(minimal);

    // 2) полноценное сообщение
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
