/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
final class RenewalPolicy {
  static boolean due(long now, long expires, long lastAttempt) {
    return expires <= now
        || (expires - now <= 7L * 86400000
            && (lastAttempt == 0 || lastAttempt > now || now - lastAttempt >= 3600000));
  }
}
