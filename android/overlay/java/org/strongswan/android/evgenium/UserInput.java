/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
final class UserInput {
  static String token(String value) {
    String t = value == null ? "" : value.trim();
    if (t.isEmpty()) throw new IllegalArgumentException("Вставьте токен клиента");
    if (!t.matches("EVN1-[A-Za-z0-9_-]{43}"))
      throw new IllegalArgumentException("Нужен полный токен EVN1-… без пробелов внутри");
    return t;
  }
  static String name(String value) {
    String n = value == null ? "" : value.trim();
    if (n.isEmpty() || n.codePointCount(0, n.length()) > 64 || n.chars().anyMatch(Character::isISOControl))
      throw new IllegalArgumentException("Введите имя от 1 до 64 символов без переносов строк");
    return n;
  }
}
