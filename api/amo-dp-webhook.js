// api/amo-dp-webhook.js
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // 0) Секрет
  const okSecret = !process.env.SECRET_TOKEN || req.query.token === process.env.SECRET_TOKEN;
  if (!okSecret) {
    console.warn('BAD SECRET');
    return res.status(401).json({ ok: false, error: 'bad token' });
  }

  try {
    // 1) RAW (amo шлёт form-urlencoded)
    const raw = req.body || {};
    console.log('AMO RAW:', raw);

    // 2) Собираем событие из ключей вида leads[status][0][...]
    const statuses = [];
    for (const k of Object.keys(raw)) {
      const m = k.match(/^leads\[status]\[(\d+)]\[(id|pipeline_id|status_id|old_status_id|old_pipeline_id)]$/);
      if (m) {
        const idx = Number(m[1]);
        const field = m[2];
        statuses[idx] ??= {};
        statuses[idx][field] = raw[k];
      }
    }
    if (!statuses.length || !statuses[0]?.id) {
      console.log('AMO HOOK: no events');
      return res.status(200).json({ ok: true, note: 'no events' });
    }

    const ev = statuses[0];
    const leadId = String(ev.id);
    const amoBase = `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru`;
    const leadUrl = `${amoBase}/leads/detail/${leadId}`;

    // 3) Сначала отправим МИНИМАЛЬНОЕ уведомление (чтобы ничего не потерять)
    const minimalText =
      `✅ Оплачен/изменён заказ\n` +
      `Deal #${leadId}\n` +
      `Pipeline: ${ev.pipeline_id}\n` +
      `Status: ${ev.old_status_id} → ${ev.status_id}\n` +
      `${leadUrl}`;
    await sendToTelegram(minimalText);

    // 4) Пытаемся обогатить данными из amo (не критично, если что-то пойдёт не так)
    const accessToken = await getAccessToken();
    if (!accessToken) {
      console.error('TOKEN: no access_token — пропускаем обогащение');
      return res.status(200).json({ ok: true, note: 'sent minimal, no token' });
    }
    console.log('TOKEN OK');

    // 5) Читаем сделку
    const leadResp = await fetch(`${amoBase}/api/v4/leads/${leadId}?with=contacts`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const leadJson = await leadResp.json();
    console.log('LEAD RESP STATUS:', leadResp.status);
    if (!leadResp.ok) {
      console.error('LEAD RESP BODY:', leadJson);
      return res.status(200).json({ ok: true, note: 'sent minimal, lead fetch failed' });
    }

    // 6) Ответственный
    let manager = '—';
    if (leadJson.responsible_user_id) {
      const userResp = await fetch(`${amoBase}/api/v4/users/${leadJson.responsible_user_id}`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const userJson = await userResp.json();
      console.log('USER RESP STATUS:', userResp.status);
      if (userResp.ok) manager = userJson?.name || `ID ${leadJson.responsible_user_id}`;
      else console.warn('USER RESP BODY:', userJson);
    }

    // 7) Кастомные поля
    const getCf = (id) => {
      const arr = leadJson.custom_fields_values || [];
      const f = arr.find((x) => String(x.field_id) === String(id));
      if (!f?.values?.length) return '';
      return f.values[0].value ?? f.values[0].enum_id ?? '';
    };
    const doorType = getCf(process.env.FIELD_DOOR_TYPE_ID || 2094731);
    const city     = getCf(process.env.FIELD_CITY_ID || 2094733);
    const leadName = leadJson.name || `Сделка #${leadId}`;

    // 8) Красивое сообщение
    const pretty =
      `🚨 Упала новая заявка на производство\n` +
      `Просьба срочно принять в работу.\n\n` +
      `Сделка: ${leadName}\n` +
      `Ссылка: ${leadUrl}\n` +
      `Менеджер: ${manager}\n` +
      `Тип двери: ${doorType || '—'}\n` +
      `Город доставки: ${city || '—'}`;

    await sendToTelegram(pretty);
    return res.status(200).json({ ok: true, note: 'sent minimal+pretty' });

  } catch (e) {
    console.error('hook error', e);
    // даже если всё упало — уже отправили минималку выше
    return res.status(200).json({ ok: false, error: 'exception_after_minimal' });
  }
}

// ===== helpers =====
async function getAccessToken() {
  // 1) Если положен вручную — используем
  if (process.env.AMO_ACCESS_TOKEN) return process.env.AMO_ACCESS_TOKEN;

  // 2) Иначе получаем по refresh
  try {
    const amoBase = `https://${process.env.AMO_SUBDOMAIN}.amocrm.ru`;
    const body = {
      client_id: process.env.AMO_CLIENT_ID,
      client_secret: process.env.AMO_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: process.env.AMO_REFRESH_TOKEN,
      redirect_uri: process.env.AMO_REDIRECT_URI
    };
    const resp = await fetch(`${amoBase}/oauth2/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const json = await resp.json();
    if (!resp.ok || !json.access_token) {
      console.error('TOKEN RESP', resp.status, json);
      return null;
    }
    console.log('TOKEN REFRESHED');
    return json.access_token;
  } catch (e) {
    console.error('TOKEN ERROR', e);
    return null;
  }
}

async function sendToTelegram(text) {
  try {
    const tgUrl = `https://api.telegram.org/bot${process.env.TG_BOT_TOKEN}/sendMessage`;
    const resp = await fetch(tgUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: process.env.TG_CHAT_ID,
        text,
        disable_web_page_preview: true
      })
    });
    const json = await resp.json();
    console.log('TG RESP:', resp.status, json);
  } catch (e) {
    console.error('TG ERROR', e);
  }
}
