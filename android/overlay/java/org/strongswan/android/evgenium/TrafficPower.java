/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.os.PowerManager;

/** Keep the packet pump runnable during bulk transfers, never hold an idle VPN awake. */
final class TrafficPower implements AutoCloseable {
  private final PowerManager.WakeLock lock;
  private long previous;
  private boolean closed;
  TrafficPower(Context context, boolean enabled) {
    lock = enabled ? context.getSystemService(PowerManager.class).newWakeLock(
        PowerManager.PARTIAL_WAKE_LOCK, "Evgenium:packet-transfer") : null;
    if (lock != null) lock.setReferenceCounted(false);
  }
  synchronized void connecting() {
    if (!closed && lock != null) lock.acquire(8000);
  }
  synchronized void sample(long bytes) {
    if (closed) return;
    long delta = bytes - previous;
    previous = bytes;
    if (lock != null && delta >= 65536) lock.acquire(3000);
  }
  synchronized boolean held() { return lock != null && lock.isHeld(); }
  @Override public synchronized void close() {
    closed = true;
    if (lock != null && lock.isHeld()) lock.release();
  }
}
