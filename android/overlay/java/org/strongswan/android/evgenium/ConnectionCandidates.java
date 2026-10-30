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
  static int[] order(double[] scores, int[] losses, int lastWorking) {
    if (scores.length != 5 || losses.length != 5) throw new IllegalArgumentException("routes");
    List<Integer> measured = new ArrayList<>(), fallback = new ArrayList<>();
    for (int route : DEFAULT_ORDER) if (losses[route] < 3) {
      if (Double.isFinite(scores[route]) && scores[route] > 0) measured.add(route);
      else fallback.add(route);
    }
    measured.sort((a, b) -> Double.compare(scores[b], scores[a]));
    measured.addAll(fallback);
    // A recent actual connection is more useful at startup than an old speed
    // result. Explicit remeasurement drops this hint before picking its winner.
    if (measured.remove(Integer.valueOf(lastWorking))) measured.add(0, lastWorking);
    return measured.stream().mapToInt(Integer::intValue).toArray();
  }
}
