# Компоненты Android alpha

Это модифицированный клиент strongSwan, не официальный продукт strongSwan.
Собственный Java overlay и изменения интеграции распространяются под GPL-2.0-or-later.
Оригинальные copyright notices сохраняются в исходниках upstream.

- strongSwan Android 2.6.2 / IKE core 6.0.3, GPL-2.0-or-later.
  Commit: 5e410617d4c9d06cff5b860a26f51ee91aa73228.
  https://github.com/strongswan/strongswan
  Текст GPL: licenses/GPL-2.0.txt. Скрипт сборки и overlay содержат изменения.
- OpenSSL 3.5.9, Apache-2.0.
  Commit: 45e844fa2a14ec92d146bd8f5778ac130b6625fb.
  https://github.com/openssl/openssl
  Текст: licenses/OpenSSL-Apache-2.0.txt.
- Conscrypt Android 2.7.0, Apache-2.0; включает BoringSSL с собственными notices.
  https://github.com/google/conscrypt
  Артефакт: org.conscrypt:conscrypt-android:2.7.0.
- AndroidX/Material и Gradle-зависимости перечислены в закреплённом
  src/frontends/android/app/build.gradle upstream и изменениях prepare.py.

APK пока предназначен для локального тестирования. Перед публичным бинарным
релизом собрать notices всех транзитивных компонентов и соответствующие исходники;
этот перечень не заменяет полную комплектацию исходниками и лицензиями.

Для HTTPS-проверки выхода на Android 8–9 дополнено системное хранилище доверия:
SSL.com Root Certification Authority ECC, публичный корневой сертификат из
локального системного CA bundle. Используется только ExitProbe к 1.1.1.1,
не меняет доверие Android или проверку сертификатов VPN. SHA-256 fingerprint:
3417BB06CC6007DA1B961C920B8AB4CE3FAD820E4AA30B9ACBC4A74EBDCEBC65.
Срок действия: 2016-02-12 — 2041-02-12.
