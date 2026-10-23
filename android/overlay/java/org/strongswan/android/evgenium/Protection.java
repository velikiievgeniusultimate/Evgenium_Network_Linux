/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;
final class Protection {
  static boolean alwaysOn(Context c) {
    try {
      org.strongswan.android.logic.CharonVpnService v =
          org.strongswan.android.logic.CharonVpnService.evgeniumInstance;
      if (Build.VERSION.SDK_INT >= 29 && v != null)
        return v.isAlwaysOn();
      return c.getPackageName().equals(
          Settings.Secure.getString(c.getContentResolver(), "always_on_vpn_app"));
    } catch (Exception e) {
      return false;
    }
  }
  static boolean lockdown(Context c) {
    try {
      org.strongswan.android.logic.CharonVpnService v =
          org.strongswan.android.logic.CharonVpnService.evgeniumInstance;
      if (Build.VERSION.SDK_INT >= 29 && v != null)
        return v.isLockdownEnabled();
      return alwaysOn(c)
          && Settings.Secure.getInt(c.getContentResolver(), "always_on_vpn_lockdown", 0) == 1;
    } catch (Exception e) {
      return false;
    }
  }
  static String summary(Context c) {
    return lockdown(c) ? "Системная блокировка трафика без VPN включена"
                       : "Защита при остановке приложения не включена · настройте постоянный VPN и "
                         + "блокировку соединений";
  }
}
