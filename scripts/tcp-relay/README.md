# Evgenium TCP relay

Фиксированный вход `195.209.211.163:24579` пересылает байты на
`38.180.164.67:24578`. TLS 1.3, проверка сертификатов устройств и отзыв остаются
на эстонском EvgeniumTunnel. Ключи на ретранслятор не копируются. Это не HTTP/SOCKS
прокси: клиент не выбирает адрес назначения.

Сборка Linux: из `transport/evgenium-tunnel` выполнить
`CGO_ENABLED=0 go build -trimpath -buildvcs=false -o evgenium-tcp-relay ./cmd/relay`.
Нужен Go 1.24+. Копировать бинарник в `/usr/local/libexec/evgenium-tcp-relay`,
`firewall.py` в `/usr/local/libexec/evgenium-relay-firewall` (оба 0755), unit в
`/etc/systemd/system/evgenium-tcp-relay.service`.

Данный unit рассчитан на существующую RU-цепочку `inet firewall input`,
в которой уже разрешён established/related. Скрипт меняет только правило со
своим комментарием. Не заменять им firewall целиком. `modprobe tcp_bbr` и файл
`/etc/modules-load.d/evgenium-relay.conf` с `tcp_bbr` обеспечивают наличие алгоритма;
системный алгоритм TCP не меняется. BBR включается только для backend-сокетов.
Если BBR недоступен, используется системный алгоритм с записью в журнал.
Затем `systemctl daemon-reload` и `systemctl enable --now evgenium-tcp-relay`.

Лимиты по умолчанию: 128 соединений, 32 на публичный IP (важно для CGNAT),
384 MiB памяти, 60 секунд без данных в обе стороны. Heartbeat сохраняет
здоровое соединение без ограничения общей длительности. Новый TCP вход ограничен
60 соединениями/с в firewall. TLS-аутентификацией и защитой от злоупотреблений
дополнительно занимается конечный сервер; публичный relay всё равно потребляет
ресурсы при неавторизованных попытках, поэтому мониторинг лимитов необходим.

Откат: `systemctl disable --now evgenium-tcp-relay` удаляет только своё правило.
Старые маршруты продолжают работать. Для исключения нового маршрута из будущих
рейтингов убрать `ee-evgt-ru` в клиенте и пересобрать выпуск.
