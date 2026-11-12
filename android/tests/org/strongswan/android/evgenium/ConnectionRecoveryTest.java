/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
public class ConnectionRecoveryTest {
  @Test public void legacyManualSelectionKeepsItsTunnelIdentity() {
    assertEquals(-1,ConnectionCandidates.migrateLegacyIndex(1));
    assertEquals(1,ConnectionCandidates.migrateLegacyIndex(2));
    assertEquals(2,ConnectionCandidates.migrateLegacyIndex(3));
    assertEquals(3,ConnectionCandidates.migrateLegacyIndex(4));
    assertEquals(0,ConnectionCandidates.migrateLegacyIndex(0));
    assertEquals(-1,ConnectionCandidates.migrateLegacyIndex(-1));
  }
  @Test public void measuredLeaderAlwaysStartsEachNewConnection() {
    int[] order=ConnectionCandidates.order(new double[]{1,100,90,80});
    assertEquals(1,ConnectionCandidates.initial(order,3));
    assertEquals(1,ConnectionCandidates.initial(order,0));
  }
  @Test public void zeroAndInvalidMeasurementsRemainRetryableFallbacks() {
    assertArrayEquals(new int[]{2,0,1,3},ConnectionCandidates.order(new double[]{Double.NaN,0,10,-1}));
  }
  @Test public void failoverWalksSavedOrderAndWrapsWithoutPenalties() {
    int[] order=ConnectionCandidates.order(new double[]{10,20,30,40});
    int route=3;
    for(int cycle=0;cycle<10;cycle++) {
      assertEquals(2,route=ConnectionCandidates.after(order,route));
      assertEquals(1,route=ConnectionCandidates.after(order,route));
      assertEquals(0,route=ConnectionCandidates.after(order,route));
      assertEquals(3,route=ConnectionCandidates.after(order,route));
    }
    assertArrayEquals(new int[]{2,1,0,3},ConnectionCandidates.attemptOrder(order,2,-1));
    assertArrayEquals(new int[]{2,1,0},ConnectionCandidates.attemptOrder(order,2,3));
    assertEquals(-1,ConnectionCandidates.initial(new int[0],-1));
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
