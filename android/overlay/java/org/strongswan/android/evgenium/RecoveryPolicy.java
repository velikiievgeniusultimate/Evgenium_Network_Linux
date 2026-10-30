/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
/** Monotonic, bounded retry timing. Stop revokes pending automatic retries. */
final class RecoveryPolicy {
  private boolean active, pending;
  private int rounds;
  private long at;
  synchronized void start() { active = true; pending = false; rounds = 0; at = 0; }
  synchronized void stop() { active = false; pending = false; }
  synchronized void connected() { pending = false; rounds = 0; at = 0; }
  synchronized long failed(long now) {
    if (!active) return -1;
    long delay = Math.min(60000L, 5000L << Math.min(rounds, 4));
    rounds = Math.min(rounds + 1, 5);
    pending = true; at = now + delay;
    return delay;
  }
  synchronized void networkChanged(long now) { if (active && pending) at = now; }
  synchronized boolean pending() { return active && pending; }
  synchronized boolean ready(long now) { return active && pending && now >= at; }
  synchronized long remaining(long now) { return pending() ? Math.max(0, at - now) : 0; }
}
