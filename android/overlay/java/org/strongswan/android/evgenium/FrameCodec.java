/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.io.*;
/** Strict EvgeniumTunnel v1 framing, shared by the transport and parser tests. */
public final class FrameCodec {
  public static final class Frame {
    public final int type;
    public final long sequence;
    public final byte[] data;
    Frame(int t, long s, byte[] d) {
      type = t;
      sequence = s;
      data = d;
    }
  }
  public static Frame read(DataInputStream in, boolean evgt, long previous) throws IOException {
    int type = evgt ? in.readUnsignedByte() : 1;
    int length = in.readUnsignedShort();
    long seq = evgt ? in.readLong() : 0;
    if (evgt
        && (type < 1 || type > 3 || length > (type == 1 ? 4096 : 8) || (type != 1 && length != 8)
            || (type == 1 && (length < 1 || seq <= previous))))
      throw new IOException("invalid_frame");
    if (!evgt && length > 65507)
      throw new IOException("oversized_datagram");
    byte[] data = new byte[length];
    in.readFully(data);
    return new Frame(type, seq, data);
  }
  public static void write(DataOutputStream out, int type, long sequence, byte[] data)
      throws IOException {
    if (type < 1 || type > 3 || data.length > (type == 1 ? 4096 : 8)
        || (type != 1 && data.length != 8) || (type == 1 && (data.length < 1 || sequence <= 0)))
      throw new IOException("invalid_frame");
    out.writeByte(type);
    out.writeShort(data.length);
    out.writeLong(sequence);
    out.write(data);
  }
}
