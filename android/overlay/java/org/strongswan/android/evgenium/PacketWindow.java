/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.Arrays;
/** Counts unique replies; loss is round-trip absence, never attributed to an ISP. */
final class PacketWindow {
  final boolean[] seen;
  final double[] rtts;
  int received, duplicates, reordered, invalid, highest = -1;
  double jitterSum, previous;
  PacketWindow(int count) {
    seen = new boolean[count];
    rtts = new double[count];
  }
  void reply(int seq, double rtt) {
    if (seq < 0 || seq >= seen.length || !Double.isFinite(rtt) || rtt < 0) {
      invalid++;
      return;
    }
    if (seen[seq]) {
      duplicates++;
      return;
    }
    if (seq < highest)
      reordered++;
    highest = Math.max(highest, seq);
    seen[seq] = true;
    if (received > 0)
      jitterSum += Math.abs(rtt - previous);
    previous = rtt;
    rtts[received++] = rtt;
  }
  double percentile(double q) {
    if (received == 0)
      return 0;
    double[] sorted = Arrays.copyOf(rtts, received);
    Arrays.sort(sorted);
    return sorted[Math.max(0, Math.min(received - 1, (int) Math.ceil(q * received) - 1))];
  }
  double jitter() {
    return received < 2 ? 0 : jitterSum / (received - 1);
  }
}
