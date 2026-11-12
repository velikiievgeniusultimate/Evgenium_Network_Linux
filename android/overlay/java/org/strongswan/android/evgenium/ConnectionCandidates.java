/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.*;
/** One measured order; reconnects never promote, ban or remove a route. */
final class ConnectionCandidates {
  static int migrateLegacyIndex(int old) { return old==1 ? -1 : old>1 ? old-1 : old; }
  static int after(int[] order, int current) {
    for (int i=0; i<order.length; i++) if (order[i]==current) return order[(i+1)%order.length];
    return order.length==0 ? -1 : order[0];
  }
  static int initial(int[] order, int ignoredStable) { return order.length==0 ? -1 : order[0]; }
  static int[] attemptOrder(int[] order, int first, int exclude) {
    List<Integer> result=new ArrayList<>();
    int start=0;
    for(int i=0;i<order.length;i++) if(order[i]==first) start=i;
    for(int i=0;i<order.length;i++) {
      int route=order[(start+i)%order.length];
      if(route!=exclude) result.add(route);
    }
    return result.stream().mapToInt(Integer::intValue).toArray();
  }
  static int[] order(double[] scores) {
    List<Integer> order=new ArrayList<>();
    for(int i=0;i<scores.length;i++) order.add(i);
    order.sort((a,b)->Double.compare(safe(scores[b]),safe(scores[a])));
    return order.stream().mapToInt(Integer::intValue).toArray();
  }
  private static double safe(double n) { return Double.isFinite(n)&&n>0 ? n : 0; }
}
