/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
/** Serializes connection side effects with Stop, including delayed worker results. */
final class ConnectionGuard {
  private long generation;
  private boolean active;
  synchronized void activate(long owner) { generation = owner; active = true; }
  synchronized void cancel() { active = false; }
  synchronized boolean run(long owner, Runnable action) {
    if (!active || owner != generation) return false;
    action.run();
    return true;
  }
}
