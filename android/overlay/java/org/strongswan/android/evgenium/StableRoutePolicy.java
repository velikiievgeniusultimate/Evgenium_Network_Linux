/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.Objects;
/** A preference requires continuous service, not one successful exit probe. */
final class StableRoutePolicy {
  static final long MIN_STABLE_MS = 60000;
  static final class Session {
    final long generation, connection;
    final int route;
    final String profile, carrier;
    final Object network;
    Session(long generation, long connection, int route, String profile, Object network, String carrier) {
      this.generation=generation; this.connection=connection; this.route=route;
      this.profile=profile; this.network=network; this.carrier=carrier;
    }
    @Override public boolean equals(Object other) {
      if (!(other instanceof Session)) return false;
      Session s=(Session)other;
      return generation==s.generation && connection==s.connection && route==s.route
          && Objects.equals(profile,s.profile) && Objects.equals(network,s.network)
          && Objects.equals(carrier,s.carrier);
    }
    @Override public int hashCode() { return Objects.hash(generation,connection,route,profile,network,carrier); }
  }
  private Session session;
  private long since, lastHealth;
  private int healthCount;
  private boolean promoted;
  synchronized void reset() { session=null; healthCount=0; promoted=false; }
  synchronized void observe(Session current,long now) {
    if (current==null) { reset(); return; }
    if (!current.equals(session) || now<since) {
      session=current; since=now; lastHealth=now; healthCount=0; promoted=false;
    }
  }
  /** Before/after snapshots must match: a probe crossing a reconnect proves nothing. */
  synchronized boolean healthy(Session before,Session after,long now) {
    if (before==null || !before.equals(after) || !before.equals(session)) {
      reset(); observe(after,now); return false;
    }
    if (now<=lastHealth) return false;
    lastHealth=now; healthCount++;
    if (!promoted && healthCount>=2 && now-since>=MIN_STABLE_MS) {
      promoted=true; return true;
    }
    return false;
  }
}
