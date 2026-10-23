/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
/** Keep degraded but reachable paths as last-resort candidates, with one loss. */
final class RouteQuality {
  static boolean degraded(boolean transferFailed,int attempts,int failures) {
    return transferFailed || (failures>=2 && attempts>0 && failures*4L>=attempts);
  }
  static double score(double down,double up,double latency,boolean degraded) {
    if(degraded)return 0.001;
    if(!Double.isFinite(down)||!Double.isFinite(up)||!Double.isFinite(latency)||down<=0||up<=0||latency<0)return 0;
    return Math.max(0.002,2*down*up/(down+up)/(1+latency/200));
  }
}
