/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
public class ConnectionRecoveryTest {
  @Test public void firstInstallCanTryRoutesWithoutAnySpeedScores() {
    assertArrayEquals(new int[]{0,4,3,1,2}, ConnectionCandidates.order(new double[5], new int[5], -1));
  }
  @Test public void lastWorkingPrecedesStaleSpeedScores() {
    assertEquals(1, ConnectionCandidates.order(new double[5], new int[5], 1)[0]);
    assertEquals(1, ConnectionCandidates.order(new double[]{0,0,0,20,5}, new int[5], 1)[0]);
    assertEquals(3, ConnectionCandidates.order(new double[]{0,0,0,20,5}, new int[5], -1)[0]);
  }
  @Test public void failedOrInvalidMeasurementsStillHaveConnectionFallbacks() {
    assertArrayEquals(new int[]{3,0,4,1,2}, ConnectionCandidates.order(
        new double[]{Double.NaN, Double.POSITIVE_INFINITY, -2, 10, 0}, new int[5], -1));
  }
  @Test public void quarantinedLeaderDoesNotHideTheRest() {
    assertArrayEquals(new int[]{0,1,2}, ConnectionCandidates.order(
        new double[]{10,5,1,20,30}, new int[]{0,0,0,3,3}, 4));
    // Include current only when finding its successor after recording a loss.
    assertEquals(0, ConnectionCandidates.after(ConnectionCandidates.order(
        new double[]{10,5,1,20,30}, new int[]{0,0,0,0,3}, 4), 3));
  }
  @Test public void activeQuarantineIsBoundedAndLegacyBanIsNotPermanent() {
    assertEquals(3, ConnectionCandidates.effectiveLosses(3, 1000, 120999));
    assertEquals(0, ConnectionCandidates.effectiveLosses(3, 1000, 121000));
    assertEquals(0, ConnectionCandidates.effectiveLosses(3, 0, 100));
    assertEquals(0, ConnectionCandidates.effectiveLosses(3, 1000, 900));
    assertEquals(2, ConnectionCandidates.effectiveLosses(2, 0, 100));
  }
  @Test public void allRoutesCanBeTemporarilyQuarantinedWithoutInventingSuccess() {
    assertEquals(0, ConnectionCandidates.order(new double[]{1,2,3,4,5}, new int[]{3,3,3,3,3}, 4).length);
    assertEquals(-1, ConnectionCandidates.after(new int[]{4,3}, 3));
  }
  @Test public void outageRetriesHaveABoundedBackoff() {
    RecoveryPolicy p = new RecoveryPolicy(); p.start();
    long now=1000;
    for(long delay : new long[]{5000,10000,20000,40000,60000,60000}) {
      assertEquals(delay, p.failed(now));
      assertFalse(p.ready(now + delay - 1));
      assertTrue(p.ready(now + delay));
      now += delay;
    }
  }
  @Test public void newNetworkWakesPendingRetryWithoutCreatingOneWhileConnected() {
    RecoveryPolicy p = new RecoveryPolicy(); p.start(); p.failed(1000);
    p.networkChanged(2000); assertTrue(p.ready(2000));
    p.connected(); p.networkChanged(3000); assertFalse(p.pending());
  }
  @Test public void stopRevokesRetryEvenIfLateFailureOrNetworkCallbackArrives() {
    RecoveryPolicy p = new RecoveryPolicy(); p.start(); p.failed(1000); p.stop();
    p.networkChanged(10000);
    assertEquals(-1, p.failed(10000));
    assertFalse(p.ready(Long.MAX_VALUE)); assertFalse(p.pending());
    p.start(); assertEquals(5000, p.failed(10001));
  }
  @Test public void successResetsTheOutageBackoff() {
    RecoveryPolicy p = new RecoveryPolicy(); p.start(); p.failed(0); p.failed(5000);
    p.connected(); assertFalse(p.pending()); assertEquals(5000, p.failed(20000));
  }
}
