/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.net.VpnService;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.concurrent.*;
import javax.net.ssl.*;

/** Bounded loopback UDP carrier. Only the authenticated Estonia server is reachable. */
public final class TunnelCarrier implements AutoCloseable {
  private static volatile TunnelCarrier active;
  private static volatile long faultUntil;
  public static void debugFault(android.content.Context c) {
    if ((c.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
      return;
    faultUntil = SystemClock.elapsedRealtime() + 90000;
    TunnelCarrier a = active;
    if (a != null && a.evgt)
      new Thread(() -> a.abortTransport(), "evgenium-fault").start();
  }
  private void abortTransport() {
    try {
      Socket socket = raw;
      if (socket != null)
        socket.close();
    } catch (IOException ignored) {
    }
    try {
      SSLSocket socket = tls;
      if (socket != null)
        socket.close();
    } catch (IOException ignored) {
    }
  }

  private final VpnService service;
  private final boolean evgt;
  private final DatagramSocket udp;
  private volatile SSLSocket tls;
  private volatile Socket raw;
  private volatile boolean closed;
  private volatile SocketAddress peer;
  private volatile long lastRx;
  private final ArrayBlockingQueue<Packet> queue = new ArrayBlockingQueue<>(1024);
  private final ExecutorService threads = Executors.newFixedThreadPool(4);
  private long seq;
  public volatile long sent, received, dropped, reconnects;
  private static final byte[] MAGIC = {69, 86, 71, 84, 0, 1, 0, 0};
  private static class Packet {
    final byte[] bytes;
    final long at = SystemClock.elapsedRealtime();
    Packet(byte[] b) {
      bytes = b;
    }
  }
  public TunnelCarrier(VpnService s, boolean e) throws Exception {
    service = s;
    active = this;
    evgt = e;
    udp = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 24573));
    udp.setReceiveBufferSize(4 * 1024 * 1024);
    threads.execute(this::receiveUdp);
    threads.execute(this::connectLoop);
    threads.execute(() -> {
      while (!closed) {
        try {
          Thread.sleep(1000);
          SSLSocket sck = tls;
          if (sck != null && lastRx > 0 && SystemClock.elapsedRealtime() - lastRx > 25000)
            abortTransport();
        } catch (Exception ignored) {
        }
      }
    });
  }
  private void receiveUdp() {
    byte[] buf = new byte[65535];
    while (!closed) {
      try {
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        udp.receive(p);
        if (peer == null) {
          peer = p.getSocketAddress();
          Log.i("Evgenium", "carrier_udp_peer_ready");
        }
        if (!peer.equals(p.getSocketAddress()))
          continue;
        if ((evgt && p.getLength() > 4096)
            || !queue.offer(new Packet(Arrays.copyOf(buf, p.getLength()))))
          dropped++;
      } catch (IOException e) {
        if (!closed)
          Log.w("Evgenium", "carrier_udp_" + e.getClass().getSimpleName());
      }
    }
  }
  private void connectLoop() {
    while (!closed) {
      try {
        if (evgt && SystemClock.elapsedRealtime() < faultUntil) {
          Thread.sleep(500);
          continue;
        }
        raw = new Socket();
        raw.bind(new InetSocketAddress(0));
        if (!service.protect(raw))
          throw new IOException("protect_failed");
        boolean labForward = (service.getApplicationInfo().flags
                                 & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE)
                != 0
            && service.getSharedPreferences("evgenium", 0).getBoolean("lab-forward", false);
        raw.connect(new InetSocketAddress(labForward ? "127.0.0.1" : Credentials.EE,
                        labForward ? (evgt ? 34578 : 34571) : (evgt ? 24578 : 24571)),
            7000);
        raw.setTcpNoDelay(true);
        tls = (SSLSocket) Credentials.tls(service, true)
                  .getSocketFactory()
                  .createSocket(raw, Credentials.EE, evgt ? 24578 : 24571, true);
        tls.setEnabledProtocols(new String[] {"TLSv1.3"});
        SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        if (evgt && Build.VERSION.SDK_INT >= 29)
          params.setApplicationProtocols(new String[] {"evgenium/1"});
        tls.setSSLParameters(params);
        if (evgt && Build.VERSION.SDK_INT < 29)
          org.conscrypt.Conscrypt.setApplicationProtocols(tls, new String[] {"evgenium/1"});
        tls.setSoTimeout(20000);
        tls.startHandshake();
        Log.i("Evgenium", "carrier_tls_authenticated");
        if (evgt
            && !"evgenium/1".equals(Build.VERSION.SDK_INT >= 29
                    ? tls.getApplicationProtocol()
                    : org.conscrypt.Conscrypt.getApplicationProtocol(tls)))
          throw new IOException("alpn_mismatch");
        DataInputStream in = new DataInputStream(tls.getInputStream());
        DataOutputStream out =
            new DataOutputStream(new BufferedOutputStream(tls.getOutputStream()));
        if (evgt) {
          out.write(MAGIC);
          out.flush();
          byte[] m = new byte[8];
          in.readFully(m);
          if (!Arrays.equals(m, MAGIC))
            throw new IOException("protocol_magic");
        }
        seq = 0;
        lastRx = SystemClock.elapsedRealtime();
        SSLSocket session = tls;
        Future<?> writer = threads.submit(() -> writeLoop(out, session));
        long lastSeq = 0;
        try {
          while (!closed) {
            FrameCodec.Frame packet = FrameCodec.read(in, evgt, lastSeq);
            int type = packet.type;
            int len = packet.data.length;
            long number = packet.sequence;
            byte[] data = packet.data;
            lastRx = SystemClock.elapsedRealtime();
            if (type == 2) {
              synchronized (out) {
                frame(out, 3, number, data);
                out.flush();
              }
              continue;
            }
            if (type == 3 || len == 0)
              continue;
            if (evgt)
              lastSeq = number;
            SocketAddress dest = peer;
            if (dest != null) {
              udp.send(new DatagramPacket(data, len, dest));
              received += len;
            }
          }
        } finally {
          abortTransport();
          writer.cancel(true);
        }
      } catch (Exception e) {
        if (!closed)
          Log.w("Evgenium",
              "carrier_" + (evgt ? "evgt" : "tls") + "_" + e.getClass().getSimpleName() + ":"
                  + e.getMessage());
      } finally {
        abortTransport();
        queue.clear();
      }
      if (!closed) {
        reconnects++;
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          return;
        }
      }
    }
  }
  private void writeLoop(DataOutputStream out, SSLSocket session) {
    try {
      while (!closed && !session.isClosed()) {
        Packet p = queue.poll(5, TimeUnit.SECONDS);
        synchronized (out) {
          if (p == null) {
            if (evgt) {
              byte[] stamp = new byte[8];
              long t = SystemClock.elapsedRealtime();
              for (int i = 7; i >= 0; i--) {
                stamp[i] = (byte) t;
                t >>>= 8;
              }
              frame(out, 2, 0, stamp);
            } else
              out.writeShort(0);
          } else if (SystemClock.elapsedRealtime() - p.at > 500) {
            dropped++;
            continue;
          } else {
            if (evgt)
              frame(out, 1, ++seq, p.bytes);
            else {
              out.writeShort(p.bytes.length);
              out.write(p.bytes);
            }
            sent += p.bytes.length;
          }
          out.flush();
        }
      }
    } catch (Exception e) {
      try {
        session.close();
      } catch (IOException ignored) {
      }
    }
  }
  private void frame(DataOutputStream out, int type, long number, byte[] data) throws IOException {
    FrameCodec.write(out, type, number, data);
  }
  public static void stopCurrent() {
    TunnelCarrier a = active;
    if (a != null)
      a.close();
  }
  public void close() {
    if (active == this)
      active = null;
    closed = true;
    udp.close();
    abortTransport();
    threads.shutdownNow();
  }
}
