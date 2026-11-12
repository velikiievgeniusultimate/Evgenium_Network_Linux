package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
public class RankingPolicyTest {
 @Test public void historicalLossesNeverRemoveTheLeader() {
  assertEquals(3,new RankingPolicy(new double[]{10,0,15,25},new int[]{3,3,3,3}).first());
 }
 @Test public void failoverIncludesFailedMeasurementsAndWraps() {
  RankingPolicy p=new RankingPolicy(new double[]{10,0,15,25},new int[]{3,3,3,3});
  assertEquals(2,p.after(3));assertEquals(0,p.after(2));assertEquals(1,p.after(0));assertEquals(3,p.after(1));
 }
 @Test public void invalidScoresHaveDeterministicRetryOrder() {
  assertEquals(0,new RankingPolicy(new double[]{0,Double.NaN,Double.POSITIVE_INFINITY,-1},new int[4]).first());
 }
 @Test public void tiesPreserveOrder() {
  RankingPolicy p=new RankingPolicy(new double[]{2,2,1},new int[3]);assertEquals(0,p.first());assertEquals(1,p.after(0));
 }
}
