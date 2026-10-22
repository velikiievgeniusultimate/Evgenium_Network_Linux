/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
/** Monotonic round-trip watchdog. Unrelated received traffic does not acknowledge a probe. */
final class Heartbeat {
  private final long interval, timeout;
  private long next, sent = -1, nonce;
  Heartbeat(long interval, long timeout) {
    if (interval <= 0 || timeout <= interval) throw new IllegalArgumentException();
    this.interval = interval; this.timeout = timeout;
  }
  synchronized byte[] probe(long now) {
    if (sent >= 0 || now < next) return null;
    sent = now; next = now + interval; nonce++;
    byte[] b = new byte[8]; long n = nonce;
    for (int i=7;i>=0;i--) { b[i]=(byte)n; n >>>= 8; }
    return b;
  }
  synchronized long ack(byte[] b, long now) {
    if (b.length != 8 || sent < 0) return -1;
    long n=0; for (byte v:b) n=(n<<8)|(v&255L);
    if (n != nonce) return -1;
    long rtt=Math.max(0,now-sent); sent=-1; next=now+interval; return rtt;
  }
  synchronized boolean expired(long now) { return sent >= 0 && now - sent >= timeout; }
}
