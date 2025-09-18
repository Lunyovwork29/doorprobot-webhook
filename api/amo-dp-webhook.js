export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  // Проверка токена
  const secretOk =
    !process.env.SECRET_TOKEN ||
    req.query.token === process.env.SECRET_TOKEN;
  if (!secretOk)
    return res.status(401).json({ ok: false, error: "bad token" });

  try {
    const body = req.body || {};
    console.log("AMO RAW:", body);

    const statuses = body["leads[status]"];
    if (!statuses || !statuses.length) {
      return res.status(200).json({ ok: true, note: "no statuses" });
    }

    for (const s of statuses) {
      const leadId = s.id;
      const pipelineId = s.pipeline_id;
      const statusId = s.status_id;

      // Делаем запрос к API amoCRM для получения полной информации о сделке
      const amoRes = await fetch(
        `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/api/v4/leads/${leadId}?with=contacts`,
        {
          headers: {
            Authorization: `Bearer ${process.env.AMO_REFRESH_TOKEN}`,
          },
        }
      );
      const lead = await amoRes.json();

      // Вытаскиваем данные
      const leadName = lead.name || "Без названия";
      const link = `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru/leads/detail/${leadId}`;

      // Ответственный менеджер
      const manager =
        lead._embedded?.responsible_user?.name ||
        lead.responsible_user_id ||
        "Не указан";

      // Кастомные поля
      const fields = lead.custom_fields_values || [];
      const typeDoor =
        fields.find((f) => f.field_id == 2094731)?.values?.[0]?.value ||
        "—";
      const city =
        fields.find((f) => f.field_id == 2094733)?.values?.[0]?.value ||
        "—";

      // Формируем сообщение
      const text = `🚨 *Упала новая заявка на производство*  
Просьба срочно принять в работу.  

*Сделка:* [${leadName}](${link})  
*Менеджер:* ${manager}  
*Тип двери:* ${typeDoor}  
*Город доставки:* ${city}`;

      // Отправка в Telegram
      const tgUrl = `https://api.telegram.org/bot${process.env.TG_BOT_TOKEN}/sendMessage`;
      await fetch(tgUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: process.env.TG_CHAT_ID,
          text,
          parse_mode: "Markdown",
          disable_web_page_preview: true,
        }),
      });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("hook error", e);
    return res.status(200).json({ ok: false, error: e.message });
  }
}
