/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.*;
/** Connection checks stop at the first verified route; speed tests are explicit. */
final class ConnectionCandidates {
  static final long QUARANTINE_MS = 120000;
  private static final int[] DEFAULT_ORDER = {0, 4, 3, 1, 2};
  static int effectiveLosses(int losses, long quarantineAt, long now) {
    if (losses < 3) return Math.max(0, losses);
    // Old files without a quarantine clock, clock rollback and expired bans must
    // never require the user to rebuild a ranking by hand.
    return quarantineAt <= 0 || now < quarantineAt || now - quarantineAt >= QUARANTINE_MS ? 0 : 3;
  }
  static int after(int[] order, int current) {
    for (int i = 0; i + 1 < order.length; i++) if (order[i] == current) return order[i + 1];
    return -1;
  }
  /** Without confirmed stability, an old speed score must not delay the safe bootstrap. */
  static int initial(int[] order, int lastStable) {
    for (int route : order) if (route == lastStable) return route;
    for (int route : order) if (route == 0) return route;
    return order.length == 0 ? -1 : order[0];
  }
  static int[] attemptOrder(int[] order, int first, int exclude) {
    List<Integer> result = new ArrayList<>();
    for (int route : order) if (route == first && route != exclude) result.add(route);
    for (int route : order) if (route != exclude && !result.contains(route)) result.add(route);
    return result.stream().mapToInt(Integer::intValue).toArray();
  }
  static int[] order(double[] scores, int[] losses, int lastStable) {
    if (scores.length != 5 || losses.length != 5) throw new IllegalArgumentException("routes");
    List<Integer> measured = new ArrayList<>(), fallback = new ArrayList<>();
    for (int route : DEFAULT_ORDER) if (losses[route] < 3) {
      if (Double.isFinite(scores[route]) && scores[route] > 0) measured.add(route);
      else fallback.add(route);
    }
    measured.sort((a, b) -> Double.compare(scores[b], scores[a]));
    measured.addAll(fallback);
    // A confirmed stable connection is more useful at startup than an old speed
    // result. Explicit remeasurement drops this hint before picking its winner.
    if (measured.remove(Integer.valueOf(lastStable))) measured.add(0, lastStable);
    return measured.stream().mapToInt(Integer::intValue).toArray();
  }
}
