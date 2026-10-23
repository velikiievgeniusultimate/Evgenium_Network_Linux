/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.Locale;
final class UserMessages {
  static String connection(String error) {
    String e = error == null ? "" : error.toLowerCase(Locale.ROOT);
    if (e.contains("auth") || e.contains("http_403"))
      return "Сервер не подтвердил доступ. Проверьте токен или обратитесь к владельцу VPN.";
    if (e.contains("certificate") || e.contains("certpath"))
      return "Не удалось проверить сертификат. Проверьте дату и время телефона; при повторе подтвердите токен заново.";
    if (e.contains("unknownhost") || e.contains("dns"))
      return "Не удалось найти сервер по имени. Проверьте соединение и повторите подключение.";
    if (e.contains("timeout") || e.contains("timed out"))
      return "Сервер не ответил вовремя. Попробуйте другой маршрут или восстановление в настройках.";
    if (e.contains("unexpected_exit"))
      return "Маршрут не подтвердил выход через Эстонию и не прошёл проверку.";
    return "Не удалось подключиться. Проверьте интернет и запустите восстановление в настройках.";
  }
}
