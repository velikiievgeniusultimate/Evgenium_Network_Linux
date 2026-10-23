package org.strongswan.android.evgenium;
import static org.junit.Assert.*;
import java.io.*;
import java.util.concurrent.*;
import org.junit.Test;
public class CarrierQueueTest {
  @Test(timeout=5000) public void delayedEncryptedBurstSurvivesAndDecodesInOrder() throws Exception {
    CarrierQueue q = new CarrierQueue(1024);
    for (int i=0;i<600;i++) assertTrue(q.offer(new byte[]{(byte)(i>>8),(byte)i}, 0));
    // Reproduce the 638-ms stall observed on TECNO. No fresh enqueue is needed
    // to revive the queue; every opaque packet must reach the wire unchanged.
    Thread.sleep(700);
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(bytes);
    CarrierQueue.Packet p; long seq=0;
    while ((p=q.poll())!=null) FrameCodec.write(out,1,++seq,p.bytes);
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));
    for (int i=0;i<600;i++) {
      FrameCodec.Frame f=FrameCodec.read(in,true,i);
      assertEquals(i+1,f.sequence);
      assertArrayEquals(new byte[]{(byte)(i>>8),(byte)i},f.data);
    }
    assertEquals(0,in.available()); assertEquals(600,seq);
  }
  @Test public void overloadRemainsBoundedWithoutEvictingEarlierPackets() {
    CarrierQueue q=new CarrierQueue(2);
    assertTrue(q.offer(new byte[]{1},0)); assertTrue(q.offer(new byte[]{2},0));
    assertFalse(q.offer(new byte[]{3},0)); assertEquals(2,q.size());
    assertEquals(1,q.poll().bytes[0]); assertEquals(2,q.poll().bytes[0]);
  }
  @Test public void reconnectDiscardsOldSessionBeforeAcceptingNewData() throws Exception {
    CarrierQueue q=new CarrierQueue(2);q.offer(new byte[]{1},0);q.clear();
    assertNull(q.poll(1,TimeUnit.MILLISECONDS));q.offer(new byte[]{2},1000);
    assertEquals(2,q.poll().bytes[0]);assertEquals(0,q.size());
  }
}
