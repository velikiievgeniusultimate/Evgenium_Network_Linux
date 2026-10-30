'use strict';
(function () {
  const form = document.getElementById('enroll-form');
  const token = document.getElementById('token');
  const name = document.getElementById('device-name');
  const status = document.getElementById('status');
  const create = document.getElementById('create-profile');
  const toggle = document.getElementById('token-toggle');
  const result = document.getElementById('result');
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
  }
  function configuration(p, secret) {
    return '[Interface]\nPrivateKey = ' + secret + '\nAddress = ' + p.address +
      '\nDNS = ' + p.dns.join(', ') + '\nMTU = ' + p.mtu +
      '\n\n[Peer]\nPublicKey = ' + p.public_key + '\nAllowedIPs = ' + p.allowed_ips.join(', ') +
      '\nEndpoint = ' + p.endpoint + '\nPersistentKeepalive = 25\n';
  }
  const messages = {
    token_invalid: 'Проверьте токен. Для другого устройства создайте новый профиль. Если доступ отозван, обратитесь к владельцу сети.',
    device_conflict: 'Такое устройство уже зарегистрировано с другим ключом. Перезагрузите страницу и создайте новый профиль.',
    invalid_request: 'Проверьте токен и имя устройства. Вставьте токен целиком, начиная с EVN1-.',
    too_many_attempts: 'Слишком много попыток. Повторите через 15 минут.',
    request_rejected: 'Сеанс страницы истёк. Повторите создание профиля.',
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
    const value = token.value.trim();
    if (!/^EVN1-[A-Za-z0-9_-]{43}$/.test(value)) {
      tell(messages.invalid_request, true); token.focus(); return;
    }
    if (!window.isSecureContext || !window.crypto || !window.crypto.getRandomValues || !window.wireguard) {
      tell('Для безопасной генерации ключа откройте страницу по HTTPS в актуальном Safari, Chrome или Firefox.', true); return;
    }
    create.disabled = true; token.readOnly = true; name.readOnly = true;
    tell('Создаём защищённый профиль…');
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
      result.hidden = false;
      form.hidden = true;
      token.type = 'password';
      token.value = '';
      activeToken = null;
      tell('Устройство добавлено. Скачайте профиль и импортируйте его в WireGuard.');
    } catch (error) {
      // A revoked device identifier is deliberately never reusable. Keep a key
      // only for transport failures; an authorization/conflict rejection must
      // allow the next attempt to create a genuinely new device.
      if (error.code === 'token_invalid' || error.code === 'device_conflict') discard();
      tell(messages[error.code] || 'Не удалось связаться с сервером. Проверьте интернет и повторите. Ключ сохранён только в памяти этой страницы.', true);
      token.readOnly = false; name.readOnly = false;
    } finally {
      create.disabled = false;
    }
  });
  document.getElementById('download-profile').addEventListener('click', function () {
    if (!profile || !keys) return;
    const blob = new Blob([configuration(profile, keys.privateKey)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    // Short ASCII tunnel name is accepted by WireGuard on every supported OS.
    link.download = 'EVG-' + profile.device.slice(0, 8) + '.conf';
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
  });
  document.getElementById('change-token').addEventListener('click', function () {
    discard(); form.hidden = false; token.readOnly = false; name.readOnly = false;
    token.value = ''; token.type = 'password'; toggle.textContent = 'Показать';
    toggle.setAttribute('aria-label', 'Показать токен'); toggle.setAttribute('aria-pressed', 'false');
    tell('Введите токен для нового профиля. Ранее выданное устройство останется в панели владельца.');
    token.focus();
  });
})();
