# Выдача WireGuard по существующему токену

Один EVN1 принадлежит человеку. У каждого устройства отдельные WireGuard public key,
адрес и запись в существующем `accounts.json`. Private key создаёт клиент; issuer
не принимает его даже как дополнительное поле и никогда не возвращает его.
Серверный private key управляется службой ingress и не нужен процессу выдачи.

Установите `token_issuer.py` как `/usr/local/sbin/evgenium-token-issuer`, а
`wireguard_backend.py` рядом, как `/usr/local/sbin/wireguard_backend.py`.
Файл `/etc/evgenium-wireguard/config.json` принадлежит root, режим 0600:

```json
{
  "interface": "evg-clients",
  "subnet": "10.78.0.0/24",
  "public_key": "SERVER_WIREGUARD_PUBLIC_KEY",
  "endpoint": "195.209.211.163:51820"
}
```

Здесь только публичный серверный ключ. Интерфейс `evg-clients` принадлежит этому
backend целиком. Создание интерфейса, серверный private key, правила маршрутизации
только в `evg-link` и fail closed firewall устанавливаются отдельно. Backend не
меняет default route, DNS хоста, интерфейсы других VPN или межсерверный канал.
Диапазон клиентов — `10.78.0.2`—`10.78.0.254`. Старые адреса сохраняются в
истории и не передаются новым устройствам. При исчерпании пула выдача прекращается.

Публичный процесс обращается **только** к отдельному Unix socket:

```text
/usr/bin/python3 /usr/local/sbin/evgenium-token-issuer serve-wireguard --group evg-portal
/run/evgenium-wireguard/enroll.sock
```

Каталог socket root:evg-portal 0750, сам socket 0660. Этот обработчик допускает
только `operation=wireguard-enroll`, включая запросы от UID 0. Основной issuer
socket `/run/evgenium-enrollment/issuer.sock` остаётся root-only 0600; не выдавайте
его публичной службе. Обе службы используют один accounts lock.

Формат запроса: `operation`, `token`, `device` (32 строчные hex-цифры),
`public_key` (канонический base64 32 байт), необязательное `name` (1–64 символа).
Повтор device + key идемпотентен. Изменение ключа, повторное использование ключа
другим устройством, отключённое устройство и чужой токен отклоняются.
Ответ `ok/profile` содержит только серверный public key, endpoint, адрес,
DNS, MTU, маршруты и имя устройства. Токены не помещаются в URL или логи.

Службам, выполняющим `wg`, необходимы `CAP_NET_ADMIN` и
`RestrictAddressFamilies=AF_UNIX AF_NETLINK`. У публичной web-службы этих прав нет.
Owner broker использует лишь `wg show ... latest-handshakes` и `transfer`;
команда `wg show ... dump`, раскрывающая private key интерфейса, не используется.

После создания ingress и на каждом его перезапуске выполните:

```text
/usr/bin/python3 /usr/local/sbin/evgenium-token-issuer sync-wireguard
```

Эту же команду следует запускать ограниченным systemd timer, чтобы повторить
удаление peer после временного отказа `wg`. Она берёт accounts lock, восстанавливает
разрешённые peer и удаляет неизвестные/отозванные **только с evg-clients**.
Сбой команды не скрывается и не снимает отключение в базе.

Owner panel поддерживает переименование и индивидуальный отзыв IKEv2 и WireGuard.
Сначала отзыв сохраняется в базе с `disabled/revoke_pending`; затем удаляется peer
либо отзываются все поколения сертификата и завершаются только соответствующие
IKE SA. При ошибке карточка остаётся видна с возможностью повторить отзыв. Удаление
человека отключает токен до сетевых операций, обрабатывает оба типа устройств,
сохраняет tombstone и допускает безопасный повтор.

Профили захватывают также `::/0` для предотвращения обхода через IPv6. Наличие этого
маршрута не означает предоставление IPv6: текущий ingress обслуживает IPv4, и его
firewall должен запрещать IPv6 forwarding. Реальный iPhone необходим для окончательной
проверки поведения WireGuard/iOS и мобильного оператора.
