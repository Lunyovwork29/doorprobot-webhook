export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const ok = !process.env.SECRET_TOKEN || req.query.token === process.env.SECRET_TOKEN;
  if (!ok) return res.status(401).json({ ok: false, error: 'bad token' });

  let body = req.body || {};
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  // Логируем всё, что прилетает
  console.log("AMO RAW:", JSON.stringify(body, null, 2));

  try {
    // amo может прислать разные типы событий
    const events = [
      ...(body?.leads?.add || []),
      ...(body?.leads?.update || []),
      ...(body?.leads?.status || [])
    ];

    if (!Array.isArray(events) || events.length === 0) {
      console.log("AMO HOOK: no events");
      return res.status(200).json({ ok: true, note: 'no events' });
    }

    const amoSub = process.env.AMO_SUBDOMAIN;
    const leadUrl = (id) => `https://${amoSub}.amocrm.ru/leads/detail/${id}`;

    for (const e of events) {
      const text = [
        '🔔 Новое событие из amoCRM',
        `Deal #${e.id}`,
        e.pipeline_id ? `Pipeline: ${e.pipeline_id}` : null,
        e.old_status_id && e.status_id ? `Status: ${e.old_status_id} → ${e.status_id}` : null,
        leadUrl(e.id)
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
      console.log("TG RESP:", j);
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("hook error", err);
    return res.status(200).json({ ok: false });
  }
}
