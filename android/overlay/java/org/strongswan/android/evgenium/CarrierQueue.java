/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
/** Bounded FIFO for one transport session; no time-based packet destruction. */
final class CarrierQueue {
  static final class Packet {
    final byte[] bytes;
    final long at;
    Packet(byte[] bytes, long at) { this.bytes = bytes; this.at = at; }
  }
  private final ArrayBlockingQueue<Packet> packets;
  CarrierQueue(int capacity) { packets = new ArrayBlockingQueue<>(capacity); }
  boolean offer(byte[] bytes, long now) { return packets.offer(new Packet(bytes, now)); }
  Packet poll(long wait, TimeUnit unit) throws InterruptedException { return packets.poll(wait, unit); }
  Packet poll() { return packets.poll(); }
  int size() { return packets.size(); }
  void clear() { packets.clear(); }
}
