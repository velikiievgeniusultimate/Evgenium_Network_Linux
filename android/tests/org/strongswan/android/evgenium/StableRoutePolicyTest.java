/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
public class StableRoutePolicyTest {
  private StableRoutePolicy.Session session(long generation,long connection,int route,String profile,String network,String carrier) {
    return new StableRoutePolicy.Session(generation,connection,route,profile,network,carrier);
  }
  private StableRoutePolicy.Session base() { return session(1,1,0,"ru","wifi1",""); }
  @Test public void initialExitAndOneHealthCannotPromoteEvenAfterAMinute() {
    StableRoutePolicy p=new StableRoutePolicy(); StableRoutePolicy.Session s=base();
    p.observe(s,1000);
    assertFalse(p.healthy(s,s,61000));
    assertTrue(p.healthy(s,s,76000));
    assertFalse(p.healthy(s,s,91000));
  }
  @Test public void TwoEarlyHealthChecksStillNeedSixtySeconds() {
    StableRoutePolicy p=new StableRoutePolicy(); StableRoutePolicy.Session s=base();p.observe(s,0);
    assertFalse(p.healthy(s,s,15000)); assertFalse(p.healthy(s,s,30000));
    assertFalse(p.healthy(s,s,59999)); assertTrue(p.healthy(s,s,60000));
  }
  @Test public void DuplicateCompletionDoesNotCountAsTwoFreshChecks() {
    StableRoutePolicy p=new StableRoutePolicy(); StableRoutePolicy.Session s=base();p.observe(s,0);
    assertFalse(p.healthy(s,s,60000));assertFalse(p.healthy(s,s,60000));
    assertTrue(p.healthy(s,s,75000));
  }
  @Test public void EverySessionIdentityChangeRestartsTheWindow() {
    StableRoutePolicy.Session original=base();
    for (StableRoutePolicy.Session changed : new StableRoutePolicy.Session[]{
        session(2,1,0,"ru","wifi1",""),session(1,2,0,"ru","wifi1",""),
        session(1,1,4,"evgt","wifi1","1:0"),session(1,1,0,"other","wifi1",""),
        session(1,1,0,"ru","cellular2",""),session(1,1,0,"ru","wifi1","2:1")}) {
      StableRoutePolicy p=new StableRoutePolicy();p.observe(original,0);
      assertFalse(p.healthy(original,original,15000));
      p.observe(changed,59000);
      assertFalse(p.healthy(original,changed,60000));
      assertFalse(p.healthy(changed,changed,75000));
      assertFalse(p.healthy(changed,changed,119999));
      assertTrue(p.healthy(changed,changed,120000));
    }
  }
  @Test public void BriefCarrierReconnectDuringProbeDoesNotPromote() {
    StableRoutePolicy p=new StableRoutePolicy();
    StableRoutePolicy.Session a=session(1,1,4,"evgt","wifi","8:0");
    StableRoutePolicy.Session b=session(1,1,4,"evgt","wifi","8:1");
    p.observe(a,0);assertFalse(p.healthy(a,a,15000));
    assertFalse(p.healthy(a,b,61000));
    assertFalse(p.healthy(b,b,76000)); assertTrue(p.healthy(b,b,121000));
  }
  @Test public void RepeatedFailuresNeverAccumulateStableTime() {
    StableRoutePolicy p=new StableRoutePolicy(); StableRoutePolicy.Session s=base();
    for (int i=0;i<6;i++) {
      long now=i*45000L;p.observe(s,now);
      assertFalse(p.healthy(s,s,now+15000));assertFalse(p.healthy(s,s,now+30000));
      p.reset();
    }
    p.observe(s,300000);assertFalse(p.healthy(s,s,315000));assertTrue(p.healthy(s,s,360000));
  }
  @Test public void NativeDisconnectEvenWithoutChangedConnectionIdRestartsTheWindow() {
    StableRoutePolicy p=new StableRoutePolicy();StableRoutePolicy.Session s=base();p.observe(s,0);
    assertFalse(p.healthy(s,s,15000));p.observe(null,59000);p.observe(s,60000);
    assertFalse(p.healthy(s,s,61000));assertFalse(p.healthy(s,s,119999));assertTrue(p.healthy(s,s,120000));
  }
  @Test public void StopBlocksLatePromotionAndNewGenerationCannotReuseHealth() {
    StableRoutePolicy p=new StableRoutePolicy();StableRoutePolicy.Session s=base();
    ConnectionGuard g=new ConnectionGuard();g.activate(1);p.observe(s,0);p.healthy(s,s,15000);
    g.cancel();p.reset();boolean[] written={false};
    assertFalse(g.run(1,()->written[0]=p.healthy(s,s,60000)));assertFalse(written[0]);
    g.activate(2);StableRoutePolicy.Session n=session(2,2,0,"ru","wifi1","");p.observe(n,61000);
    assertFalse(g.run(1,()->written[0]=true));assertFalse(p.healthy(n,n,76000));
    assertTrue(p.healthy(n,n,121000));
  }
}
