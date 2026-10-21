/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
public class RankingPolicyTest {
  @Test
  public void restartReturnsToLeaderUntilThreeLosses() {
    double[] s = {10, 0, 15, 25};
    assertEquals(3, new RankingPolicy(s, new int[] {0, 1, 0, 2}).first());
    assertEquals(2, new RankingPolicy(s, new int[] {0, 1, 0, 3}).first());
    assertEquals(3, new RankingPolicy(s, new int[4]).first());
  }
  @Test
  public void failoverMovesOnlyDownAndSkipsExcluded() {
    RankingPolicy p = new RankingPolicy(new double[] {10, 0, 15, 25}, new int[] {0, 1, 3, 1});
    assertEquals(0, p.after(3));
    assertEquals(1, p.after(0));
    assertEquals(-1, p.after(1));
  }
  @Test
  public void invalidOrFailedScoresCannotWin() {
    assertEquals(-1,
        new RankingPolicy(new double[] {0, Double.NaN, Double.POSITIVE_INFINITY, -1}, new int[4])
            .first());
  }
  @Test
  public void tiesAreStable() {
    RankingPolicy p = new RankingPolicy(new double[] {2, 2, 1}, new int[3]);
    assertEquals(0, p.first());
    assertEquals(1, p.after(0));
  }
}
