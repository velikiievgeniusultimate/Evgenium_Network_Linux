package org.strongswan.android.evgenium;
import static org.junit.Assert.*;
import org.junit.Test;
import java.io.*;
import java.util.*;
public class TransferHealthTest {
 @Test public void fallbackPreventsSingleServiceOutageFailover() throws Exception {
  List<Integer> visited=new ArrayList<>();
  String r=new TransferHealth().check(i->{visited.add(i);if(i==0)throw new IOException("timeout");return "receipt";});
  assertEquals("receipt",r);assertEquals(Arrays.asList(0,1),visited);
 }
 @Test public void twoFailedTransfersCannotBeHiddenBySuccessfulIpProbe() throws Exception {
  try {new TransferHealth().check(i->{throw new java.net.SocketTimeoutException();});fail();}
  catch(IOException e){assertEquals("partial_transfer_timeout",e.getMessage());}
 }
 @Test public void disabledOrOldCollectorIsNotEvidenceOfBrokenVpn() throws Exception {
  assertNull(new TransferHealth().check(i->{if(i==0)throw new TransferHealth.ServiceUnavailable();throw new IOException("timeout");}));
 }
 @Test public void cancellationNeverTriesAnotherEndpoint() throws Exception {
  List<Integer> called=new ArrayList<>();
  try {new TransferHealth().check(i->{called.add(i);throw new InterruptedException();});fail();}
  catch(InterruptedException expected){assertEquals(Collections.singletonList(0),called);assertTrue(Thread.interrupted());}
 }
 @Test public void degradedRouteIsLastResortAndAccumulatesLosses() {
  assertTrue(RouteQuality.degraded(true,0,0));assertTrue(RouteQuality.degraded(false,18,9));
  assertFalse(RouteQuality.degraded(false,9,1));assertFalse(RouteQuality.degraded(false,0,0));
  double poor=RouteQuality.score(200,200,10,true),slow=RouteQuality.score(.001,.001,500,false);
  assertTrue(slow>poor);assertEquals(1,new RankingPolicy(new double[]{poor,slow},new int[]{1,0}).first());
  assertEquals(-1,new RankingPolicy(new double[]{poor},new int[]{3}).first());
 }
}
