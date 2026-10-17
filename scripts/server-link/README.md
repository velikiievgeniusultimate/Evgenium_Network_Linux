# Межсерверный канал

Исходники служб и ограниченных диагностических проб, использованных 17 октября 2026. Это операционные шаблоны, не установщик клиента. Порядок работы и ограничения: ../../docs/INTERSERVER_LINK_OPERATIONS.md.

`link-est.sh` и `link-star.sh` разворачиваются как `/opt/evgenium-link/link.sh` на соответствующем узле с правами root:root 0700 (ExecStart вызывает shell-скрипт напрямую). Python-файлы вызываются через `/usr/bin/python3`. `firewall-est.nft` — постоянный `/etc/evgenium-link/firewall.nft` на VPS. В units с NODE заменить NODE на est или star. Примеры JSON требуют новых собственных UUID/паролей и ключей; все значения REPLACE и нулевой UUID — заглушки. Приватные ключи генерируются на серверах, не помещаются в репозиторий. Сертификат TLS и публичная доверенная копия создаются отдельно; проверка TLS не отключается.

`evgenium-link-hy-server.service` и `evgenium-link-hy-client.service` устанавливаются под одинаковым именем `evgenium-link-hy.service` на соответствующем узле. TCP-unit одинаков на обоих. `evgenium-link-services.*` используются только на StarFive.

Для TLS-транспортов применены самостоятельные units с MemoryMax=192M, TasksMax=48, Restart=on-failure и RestartSec=15. Базовая CPUQuota=25% сохранена на Эстонии и у резервного Hysteria. Для TCP-транспорта StarFive используется `starfive-tcp.service.d/30-cpu-budget.conf`: CPUQuota=75% одного ядра, CPUQuotaPeriodSec=20ms. Этот override нельзя переносить на общий Xray панели.

18 октября ограничение 25% было измеренным узким местом: 7,57 Мбит/с скачивания и 80 ограниченных CPU-интервалов из 81. Квота 75% и период 20ms дали 24,66 Мбит/с в аналогичной короткой пробе с потолком 50 Мбит/с. Это не доказательство максимальной или гарантированной скорости. Защита по общей загрузке и памяти остаётся включённой.

Применение только на StarFive (не перезапускает транспорт):

```bash
install -Dm0644 starfive-tcp.service.d/30-cpu-budget.conf /etc/systemd/system/evgenium-link-tcp.service.d/30-cpu-budget.conf
systemctl daemon-reload
systemctl set-property --runtime evgenium-link-tcp.service CPUQuota=75% CPUQuotaPeriodSec=20ms
systemctl show evgenium-link-tcp -p MainPID -p CPUQuotaPerSecUSec -p CPUQuotaPeriodUSec
```

Постоянный drop-in сохраняет настройки после перезагрузки; runtime-применение меняет текущий cgroup без остановки процесса. Для отката удалить только этот drop-in, выполнить daemon-reload и вернуть CPUQuota=25%, CPUQuotaPeriodSec=100ms через `set-property --runtime`.

Диагностические серверы запускаются только на время испытаний. Их порты и разрешения отсутствуют в постоянных примерах транспортов. Не запускать нагрузочные пробы без ресурсного наблюдения.

`transport.py` устанавливается на StarFive в `/opt/evgenium-link/transport.py`. Он необходим для link-star.sh и health.py: фиксация источника UDP24444 предотвращает смену endpoint запоздавшими пакетами неактивного relay. Ручной выбор транспорта выполняется этим же скриптом.

## IKEv2 client relay

After the link is installed on StarFive, `install-relay-star.sh` adds the authenticated client-pool policy route, fail-closed forwarding and a boot-time guard include. It does not modify strongSwan or the Estonia panel. Stop `evgenium-relay` to block client egress; stopping is deliberately not an uninstall. See `docs/STARFIVE-ESTONIA.md` for lifecycle and client behavior.
