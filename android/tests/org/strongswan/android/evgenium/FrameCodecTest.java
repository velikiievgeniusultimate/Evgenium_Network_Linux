/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.util.Random;
public class FrameCodecTest {
  private byte[] frame(int type, int len, long seq, byte[] data) throws Exception {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(b);
    out.writeByte(type);
    out.writeShort(len);
    out.writeLong(seq);
    out.write(data);
    return b.toByteArray();
  }
  private FrameCodec.Frame read(byte[] b, long prev) throws Exception {
    return FrameCodec.read(new DataInputStream(new ByteArrayInputStream(b)), true, prev);
  }
  @Test
  public void binaryCompatible() throws Exception {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    FrameCodec.write(new DataOutputStream(b), 1, 7, new byte[] {1, 2, 3});
    assertArrayEquals(frame(1, 3, 7, new byte[] {1, 2, 3}), b.toByteArray());
    assertEquals(7, read(b.toByteArray(), 6).sequence);
  }
  @Test
  public void rejectsBadHeaders() throws Exception {
    for (byte[] b : new byte[][] {frame(0, 1, 1, new byte[] {0}), frame(1, 4097, 1, new byte[0]),
             frame(1, 0, 1, new byte[0]), frame(2, 7, 0, new byte[7]),
             frame(1, 1, 0, new byte[] {0}), frame(1, 1, 5, new byte[] {0}),
             frame(1, 5, 6, new byte[] {0})}) {
      try {
        read(b, 5);
        fail("accepted malformed frame");
      } catch (IOException expected) {
      }
    }
  }
  @Test
  public void heartbeatDoesNotUseDataSequence() throws Exception {
    assertEquals(2, read(frame(2, 8, 0, new byte[8]), 99).type);
  }
  @Test
  public void fragmentedInput() throws Exception {
    byte[] b = frame(1, 4096, 1, new byte[4096]);
    InputStream partial = new FilterInputStream(new ByteArrayInputStream(b)) {
      public int read(byte[] dst, int off, int n) throws IOException {
        return super.read(dst, off, Math.min(n, 3));
      }
    };
    assertEquals(4096, FrameCodec.read(new DataInputStream(partial), true, 0).data.length);
  }
  @Test
  public void coalescedFramesPreserveDatagramsAndSequences() throws Exception {
    ByteArrayOutputStream wire = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(new BufferedOutputStream(wire, 16384));
    for (int i = 1; i <= 16; i++) {
      byte[] packet = new byte[1280];
      new Random(i).nextBytes(packet);
      FrameCodec.write(out, 1, i, packet);
    }
    out.flush();
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(wire.toByteArray()));
    for (int i = 1; i <= 16; i++) {
      FrameCodec.Frame frame = FrameCodec.read(in, true, i - 1);
      byte[] expected = new byte[1280];
      new Random(i).nextBytes(expected);
      assertEquals(i, frame.sequence);
      assertArrayEquals(expected, frame.data);
    }
    assertEquals(-1, in.read());
  }
  @Test
  public void boundedRandomInputs() throws Exception {
    Random random = new Random(17);
    for (int n = 0; n < 20000; n++) {
      byte[] bytes = new byte[random.nextInt(80)];
      random.nextBytes(bytes);
      try {
        FrameCodec.Frame f = read(bytes, 0);
        assertTrue(f.data.length <= 4096);
      } catch (IOException expected) {
      }
    }
  }
}
