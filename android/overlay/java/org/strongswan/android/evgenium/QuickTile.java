/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.*;
import android.service.quicksettings.*;
/** The tile opens the same controls and permission flow as the launcher. */
public class QuickTile extends TileService {
  private final Handler handler = new Handler(Looper.getMainLooper());
  private final Runnable refresh = new Runnable() {
    public void run() {
      Tile t = getQsTile();
      if (t != null) {
        t.setLabel("Evgenium VPN");
        t.setState(Engine.verified ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        if (Build.VERSION.SDK_INT >= 29)
          t.setSubtitle(Engine.verified ? "Подключено" : Engine.running ? "Подключение…" : "Открыть управление");
        t.updateTile();
      }
      handler.postDelayed(this, 1000);
    }
  };
  public void onStartListening() { super.onStartListening();handler.removeCallbacks(refresh);handler.post(refresh); }
  public void onStopListening() { handler.removeCallbacks(refresh);super.onStopListening(); }
  public void onDestroy() { handler.removeCallbacksAndMessages(null);super.onDestroy(); }
  @SuppressWarnings("deprecation")
  public void onClick() {
    super.onClick();
    Intent i = new Intent(this, HomeActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    if (Build.VERSION.SDK_INT >= 34)
      startActivityAndCollapse(PendingIntent.getActivity(this, 23, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
    else startActivityAndCollapse(i);
  }
}
