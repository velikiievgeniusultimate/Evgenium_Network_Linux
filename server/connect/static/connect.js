'use strict';
(function () {
  const form = document.getElementById('enroll-form');
  const token = document.getElementById('token');
  const name = document.getElementById('device-name');
  const status = document.getElementById('status');
  const create = document.getElementById('create-profile');
  const toggle = document.getElementById('token-toggle');
  const result = document.getElementById('result');
  const download = document.getElementById('download-profile');
  const next = document.getElementById('download-next');
  let keys = null, device = null, profile = null, activeToken = null;

  function tell(message, error) {
    status.textContent = message;
    status.classList.toggle('error', Boolean(error));
  }
  function identifier() {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
  }
  function discard() {
    keys = null; device = null; profile = null; activeToken = null;
    result.hidden = true;
    next.hidden = true;
    download.textContent = 'Скачать файл для WireGuard';
    document.getElementById('profile-filename').textContent = '';
    document.getElementById('import-filename').textContent = 'EVG-….conf';
  }
  function filename() { return 'EVG-' + profile.device.slice(0, 8) + '.conf'; }
  function configuration(p, secret) {
    return '[Interface]\nPrivateKey = ' + secret + '\nAddress = ' + p.addresses.join(', ') +
      '\nDNS = ' + p.dns.join(', ') + '\nMTU = ' + p.mtu +
      '\n\n[Peer]\nPublicKey = ' + p.public_key + '\nAllowedIPs = ' + p.allowed_ips.join(', ') +
      '\nEndpoint = ' + p.endpoint + '\nPersistentKeepalive = 25\n';
  }
  const messages = {
    token_invalid: 'Токен не принят. Вставьте его целиком, начиная с EVN1-. Если ошибка остаётся, попросите владельца сети проверить ваш доступ.',
    device_conflict: 'Такое устройство уже зарегистрировано с другим ключом. Перезагрузите страницу и создайте новый профиль.',
    invalid_request: 'Проверьте токен и имя устройства. Вставьте токен целиком, начиная с EVN1-.',
    too_many_attempts: 'Слишком много попыток. Повторите через 15 минут.',
    request_rejected: 'Сеанс страницы истёк. Нажмите «Получить файл» ещё раз. Если ошибка остаётся, откройте страницу в Safari.',
    enrollment_unavailable: 'Сервер временно не может выдать профиль. Повторите через минуту.',
  };
  toggle.addEventListener('click', function () {
    const visible = token.type === 'password';
    token.type = visible ? 'text' : 'password';
    toggle.textContent = visible ? 'Скрыть' : 'Показать';
    toggle.setAttribute('aria-label', visible ? 'Скрыть токен' : 'Показать токен');
    toggle.setAttribute('aria-pressed', String(visible));
  });
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (create.disabled || form.hidden) return;
    const value = token.value.trim();
    if (!/^EVN1-[A-Za-z0-9_-]{43}$/.test(value)) {
      tell(messages.invalid_request, true); token.focus(); return;
    }
    if (!window.isSecureContext || !window.crypto || !window.crypto.getRandomValues || !window.wireguard) {
      tell('Для безопасной генерации ключа откройте страницу по HTTPS в актуальном Safari, Chrome или Firefox.', true); return;
    }
    create.disabled = true; token.readOnly = true; name.readOnly = true;
    create.textContent = 'Готовим файл…';
    tell('Подключаем устройство. Подождите…');
    try {
      if (!keys || activeToken !== value) {
        discard(); keys = window.wireguard.generateKeypair(); device = identifier(); activeToken = value;
      }
      const session = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' });
      if (!session.ok) throw { code: session.status === 429 ? 'too_many_attempts' : 'enrollment_unavailable' };
      const csrf = (await session.json()).csrf;
      const response = await fetch('/api/enroll', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ token: value, device: device, name: name.value.trim(), public_key: keys.publicKey }),
      });
      const reply = await response.json();
      if (!response.ok || !reply.ok) throw { code: reply.error || 'enrollment_unavailable' };
      profile = reply.profile;
      document.getElementById('profile-name').textContent = profile.device_name;
      document.getElementById('profile-filename').textContent = filename();
      document.getElementById('import-filename').textContent = filename();
      result.hidden = false;
      form.hidden = true;
      token.type = 'password';
      token.value = '';
      activeToken = null;
      tell('');
      document.getElementById('result-title').focus();
    } catch (error) {
      // A revoked device identifier is deliberately never reusable. Keep a key
      // only for transport failures; an authorization/conflict rejection must
      // allow the next attempt to create a genuinely new device.
      if (error.code === 'token_invalid' || error.code === 'device_conflict') discard();
      tell(messages[error.code] || 'Не удалось связаться с сервером. Проверьте интернет и повторите. Ключ сохранён только в памяти этой страницы.', true);
      token.readOnly = false; name.readOnly = false;
    } finally {
      create.disabled = false;
      create.textContent = 'Получить файл';
    }
  });
  download.addEventListener('click', function () {
    if (!profile || !keys) return;
    const blob = new Blob([configuration(profile, keys.privateKey)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    // Short ASCII tunnel name is accepted by WireGuard on every supported OS.
    link.download = filename();
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
    // A download click does not prove Safari saved the file or enabled VPN.
    next.hidden = false;
    download.textContent = 'Скачать этот файл ещё раз';
    tell('Сохраните файл, затем переходите к шагу 3.');
  });
  document.getElementById('change-token').addEventListener('click', function () {
    discard(); form.hidden = false; token.readOnly = false; name.readOnly = false;
    token.value = ''; token.type = 'password'; toggle.textContent = 'Показать';
    toggle.setAttribute('aria-label', 'Показать токен'); toggle.setAttribute('aria-pressed', 'false');
    tell('Введите другой токен. Ранее созданное подключение продолжит работать.');
    token.focus();
  });
})();
