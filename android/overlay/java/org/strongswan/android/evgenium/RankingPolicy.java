/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.*;
/** A stable order is preserved until an explicit new measurement. */
public final class RankingPolicy {
  private final List<Integer> order = new ArrayList<>();
  private final double[] scores;
  private final int[] losses;
  public RankingPolicy(double[] score, int[] loss) {
    if (score.length != loss.length)
      throw new IllegalArgumentException("ranking_size");
    scores = score.clone();
    losses = loss.clone();
    for (int i = 0; i < scores.length; i++) {
      if (!Double.isFinite(scores[i]) || scores[i] < 0)
        scores[i] = 0;
      order.add(i);
    }
    order.sort((a, b) -> Double.compare(scores[b], scores[a]));
  }
  public int first() {
    for (int i : order)
      if (losses[i] < 3 && scores[i] > 0)
        return i;
    return -1;
  }
  public int after(int route) {
    boolean passed = false;
    for (int i : order) {
      if (i == route) {
        passed = true;
        continue;
      }
      if (passed && losses[i] < 3)
        return i;
    }
    return -1;
  }
}
