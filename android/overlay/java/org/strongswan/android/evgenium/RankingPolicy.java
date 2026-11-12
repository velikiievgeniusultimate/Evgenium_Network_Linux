/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
/** Compatibility facade for quality scoring; historical losses have no effect. */
public final class RankingPolicy {
  private final int[] order;
  public RankingPolicy(double[] scores,int[] ignoredLosses) {
    if(scores.length!=ignoredLosses.length) throw new IllegalArgumentException("ranking_size");
    order=ConnectionCandidates.order(scores);
  }
  public int first() { return ConnectionCandidates.initial(order,-1); }
  public int after(int route) { return ConnectionCandidates.after(order,route); }
}
