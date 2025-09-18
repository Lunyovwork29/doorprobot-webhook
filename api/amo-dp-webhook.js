async function getAccessToken() {
  const resp = await fetch(`https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/oauth2/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.AMO_CLIENT_ID,
      client_secret: process.env.AMO_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: process.env.AMO_REFRESH_TOKEN,
      redirect_uri: process.env.AMO_REDIRECT_URI
    })
  });
  const data = await resp.json();
  if (!data.access_token) throw new Error("Не удалось обновить токен");
  return data.access_token;
}

async function fetchLead(leadId, token) {
  const resp = await fetch(
    `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/api/v4/leads/${leadId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return resp.json();
}

async function fetchUser(userId, token) {
  const resp = await fetch(
    `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/api/v4/users/${userId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return resp.json();
}

function extractFormData(raw) {
  const get = (k) => raw[`leads[status][0][${k}]`];
  if (!get("id")) return null;
  return {
    id: get("id"),
    pipeline_id: get("pipeline_id"),
    status_id: get("status_id"),
    old_status_id: get("old_status_id")
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  if (process.env.SECRET_TOKEN && req.query.token !== process.env.SECRET_TOKEN) {
    return res.status(401).json({ ok: false, error: "bad token" });
  }

  try {
    const body = req.body || {};
    console.log("AMO RAW:", body);

    const event = extractFormData(body);
    if (!event) return res.status(200).json({ ok: true, note: "no event" });

    const token = await getAccessToken();
    const lead = await fetchLead(event.id, token);

    // ответственный
    let manager = "—";
    if (lead.responsible_user_id) {
      const user = await fetchUser(lead.responsible_user_id, token);
      manager = user?.name || `ID ${lead.responsible_user_id}`;
    }

    // кастомные поля
    const fields = lead.custom_fields_values || [];
    const doorType = fields.find(f => f.field_id == 2094731)?.values?.[0]?.value || "—";
    const city = fields.find(f => f.field_id == 2094733)?.values?.[0]?.value || "—";

    // ссылка на сделку
    const link = `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/leads/detail/${event.id}`;
    const leadName = lead.name || `Сделка #${event.id}`;

    const text =
`🚨 Упала новая заявка на производство
Просьба срочно принять в работу.

<b>Сделка:</b> <a href="${link}">${leadName}</a>
<b>Менеджер:</b> ${manager}
<b>Тип двери:</b> ${doorType}
<b>Город доставки:</b> ${city}`;

    // шлём в TG
    const tgUrl = `https://api.telegram.org/bot${process.env.TG_BOT_TOKEN}/sendMessage`;
    await fetch(tgUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: process.env.TG_CHAT_ID,
        text,
        parse_mode: "HTML",
        disable_web_page_preview: true
      })
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("hook error", err);
    return res.status(200).json({ ok: false, error: err.message });
  }
}
