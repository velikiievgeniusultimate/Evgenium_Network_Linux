package org.strongswan.android.evgenium;
import org.junit.Test;import static org.junit.Assert.*;
public class HeartbeatTest {
 @Test public void wrongOrOldPongsCannotHideFailure(){Heartbeat h=new Heartbeat(3000,12000);byte[] old=h.probe(0);assertEquals(-1,h.ack(new byte[8],1));assertTrue(h.expired(12000));assertEquals(100,h.ack(old,100));byte[] current=h.probe(3100);assertNotNull(current);assertEquals(-1,h.ack(old,3200));assertTrue(h.expired(15100));assertEquals(12001,h.ack(current,15101));assertFalse(h.expired(99999));}
 @Test public void busySenderCannotMoveDeadline(){Heartbeat h=new Heartbeat(3000,12000);assertNotNull(h.probe(100));for(int i=101;i<15000;i++)assertNull(h.probe(i));assertTrue(h.expired(12100));}
 @Test public void successfulRoundtripSchedulesNextProbe(){Heartbeat h=new Heartbeat(3000,12000);byte[] p=h.probe(20);assertEquals(40,h.ack(p,60));assertNull(h.probe(3059));assertNotNull(h.probe(3060));assertFalse(h.expired(15059));assertTrue(h.expired(15060));}
}
