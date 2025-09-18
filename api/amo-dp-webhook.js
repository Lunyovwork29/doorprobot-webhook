// api/amo-dp-webhook.js
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const ok = !process.env.SECRET_TOKEN || req.query.token === process.env.SECRET_TOKEN;
  if (!ok) return res.status(401).json({ ok: false, error: 'bad token' });

  let body = req.body || {};
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }

  try {
    const statuses = body?.leads?.status || [];
    if (!Array.isArray(statuses) || statuses.length === 0) {
      return res.status(200).json({ ok: true, note: 'no statuses' });
    }

    const amoSub = process.env.AMO_SUBDOMAIN; // напр. new1754065789
    const leadUrl = (id) => `https://${amoSub}.amocrm.ru/leads/detail/${id}`;

    const texts = statuses.map((s) => {
      const leadId = s.id, pipelineId = s.pipeline_id, statusId = s.status_id, oldStatusId = s.old_status_id;
      return ['✅ Оплачен заказ', `Deal #${leadId}`, `Pipeline: ${pipelineId}`, `Status: ${oldStatusId} → ${statusId}`, leadUrl(leadId)].join('\n');
    });

    const tgUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    for (const text of texts) {
      await fetch(tgUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: process.env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true }) });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('hook error', err);
    return res.status(200).json({ ok: false });
  }
}
