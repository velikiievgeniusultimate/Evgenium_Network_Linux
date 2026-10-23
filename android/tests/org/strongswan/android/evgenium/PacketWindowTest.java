package org.strongswan.android.evgenium;
import static org.junit.Assert.*;

import org.junit.Test;
public class PacketWindowTest {
  @Test
  public void duplicateAndReorderDoNotHideLoss() {
    PacketWindow w = new PacketWindow(4);
    w.reply(2, 30);
    w.reply(0, 10);
    w.reply(2, 40);
    assertEquals(2, w.received);
    assertEquals(1, w.duplicates);
    assertEquals(1, w.reordered);
    assertEquals(10, w.percentile(.5), 0);
    assertEquals(30, w.percentile(.95), 0);
    assertEquals(20, w.jitter(), 0);
  }
  @Test
  public void invalidRepliesAndNoRepliesAreNotSuccess() {
    PacketWindow w = new PacketWindow(3);
    w.reply(-1, 5);
    w.reply(3, 5);
    w.reply(0, Double.NaN);
    w.reply(0, -1);
    assertEquals(0, w.received);
    assertEquals(4, w.invalid);
    assertEquals(0, w.percentile(.95), 0);
  }
}
