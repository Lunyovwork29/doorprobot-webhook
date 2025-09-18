// api/amo-dp-webhook.js
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // 1) Проверка секрета в URL (?token=...)
  const ok = !process.env.SECRET_TOKEN || req.query.token === process.env.SECRET_TOKEN;
  if (!ok) return res.status(401).json({ ok: false, error: 'bad token' });

  // 2) Достаём тело запроса: amo может слать JSON ИЛИ form-data (x-www-form-urlencoded)
  let raw = req.body || {};
  if (typeof raw === 'string') {
    try { raw = JSON.parse(raw); } catch { raw = {}; }
  }

  // Лог для диагностики
  console.log('AMO RAW:', JSON.stringify(raw, null, 2));

  // --- Нормализуем в массив событий {id, pipeline_id, status_id, old_status_id} ---
  const events = [];

  // 2a) JSON-формат: { leads: { status: [ {...} ], add: [..], update:[..] } }
  if (raw?.leads) {
    for (const key of ['status', 'add', 'update']) {
      const arr = raw.leads[key];
      if (Array.isArray(arr)) {
        for (const e of arr) {
          events.push({
            id: e.id || e.lead_id || e.entity_id,
            pipeline_id: e.pipeline_id,
            status_id: e.status_id,
            old_status_id: e.old_status_id
          });
        }
      }
    }
  }

  // 2b) FORM-формат: ключи вида "leads[status][0][id]"
  // Берём только нулевой элемент, amo обычно шлёт по одному событию.
  const f = (k) => raw[`leads[status][0][${k}]`];
  if (!events.length && (f('id') || f('status_id'))) {
    events.push({
      id: numOrStr(f('id')),
      pipeline_id: numOrStr(f('pipeline_id')),
      status_id: numOrStr(f('status_id')),
      old_status_id: numOrStr(f('old_status_id'))
    });
  }

  // Если всё ещё пусто — выходим
  if (!events.length) {
    console.log('AMO HOOK: no events');
    return res.status(200).json({ ok: true, note: 'no events' });
  }

  try {
    // Опциональный фильтр по конкретному статусу/воронке (задать в ENV, если нужно)
    const FILTER_STATUS_ID = envNum('FILTER_STATUS_ID');      // напр. id «СЧЁТ ОПЛАЧЕН»
    const FILTER_PIPELINE_ID = envNum('FILTER_PIPELINE_ID');  // id воронки (если хочешь)

    const amoSub = process.env.AMO_SUBDOMAIN; // например: new1754065789
    const leadUrl = (id) => `https://${amoSub}.amocrm.ru/leads/detail/${id}`;

    // 3) Отправляем каждое событие в Telegram
    for (const e of events) {
      if (FILTER_STATUS_ID && +e.status_id !== FILTER_STATUS_ID) continue;
      if (FILTER_PIPELINE_ID && +e.pipeline_id !== FILTER_PIPELINE_ID) continue;

      const text = [
        '✅ Событие amoCRM',
        e.id && `Deal #${e.id}`,
        e.pipeline_id && `Pipeline: ${e.pipeline_id}`,
        (e.old_status_id || e.status_id) && `Status: ${e.old_status_id ?? '—'} → ${e.status_id ?? '—'}`,
        e.id && leadUrl(e.id)
      ].filter(Boolean).join('\n');

      const tgUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
      const resp = await fetch(tgUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: process.env.TELEGRAM_CHAT_ID,
          text,
          disable_web_page_preview: true
        })
      });
      const j = await resp.json();
      console.log('TG RESP:', j);
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('hook error', err);
    return res.status(200).json({ ok: false });
  }
}

// ——— helpers ———
function envNum(name) {
  const v = process.env[name];
  if (v === undefined || v === null || v === '') return 0;
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}
function numOrStr(v) {
  if (v === undefined || v === null) return v;
  const n = Number(v);
  return Number.isFinite(n) ? n : v;
}
