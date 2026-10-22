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
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;
import javax.net.ssl.*;

/**
 * Bounded loopback UDP carrier. Only the authenticated Estonia server is
 * reachable.
 */
public final class TunnelCarrier implements AutoCloseable {
  private static volatile TunnelCarrier active;
  private static volatile long faultUntil;
  public static void debugFault(android.content.Context c) {
    if ((c.getApplicationInfo().flags &
         android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
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
  private final int endpointPort, batchPackets, udpBuffer;
  final int localPort;
  private final long startedAt = System.currentTimeMillis();
  private final boolean laboratory;
  private final AtomicLong queued = new AtomicLong(),
                           fullDrops = new AtomicLong(),
                           staleDrops = new AtomicLong();
  private final AtomicLong sentPackets = new AtomicLong(),
                           receivedPackets = new AtomicLong(),
                           sequenceGaps = new AtomicLong();
  private final AtomicLong writeTimeouts = new AtomicLong();
  private volatile long maxQueueMs, maxWriteMs, writeMs, flushes;
  public JSONObject metrics() throws Exception {
    return new JSONObject()
        .put("sent_bytes", sent)
        .put("received_bytes", received)
        .put("enqueued", queued.get())
        .put("sent_packets", sentPackets.get())
        .put("received_packets", receivedPackets.get())
        .put("queue_drops", fullDrops.get())
        .put("stale_drops", staleDrops.get())
        .put("sequence_gaps", sequenceGaps.get())
        .put("queue_depth", queue.size())
        .put("max_queue_ms", maxQueueMs)
        .put("max_write_ms", maxWriteMs)
        .put("write_timeouts", writeTimeouts.get())
        .put("write_ms", writeMs)
        .put("flushes", flushes)
        .put("reconnects", reconnects)
        .put("udp_receive_buffer", udpBuffer)
        .put("batch_packets", batchPackets)
        .put("started_at", startedAt);
  }
  public static JSONObject activeMetrics() {
    TunnelCarrier a = active;
    try {
      return a == null ? new JSONObject() : a.metrics();
    } catch (Exception ignored) {
      return new JSONObject();
    }
  }
  static VpnService labService(android.content.Context context)
      throws IOException {
    if ((context.getApplicationInfo().flags &
         android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
      throw new IOException("lab_disabled");
    TunnelCarrier a = active;
    if (a == null || a.closed)
      throw new IOException("connect_tls_route_first");
    return a.service;
  }
  static TunnelCarrier laboratory(android.content.Context context, int batch)
      throws Exception {
    if (batch != 1 && batch != 10 && batch != 32)
      throw new IOException("invalid_batch");
    return new TunnelCarrier(labService(context), true, 0, 24580, batch, true);
  }
  void awaitReady() throws Exception {
    long end = SystemClock.elapsedRealtime() + 8000;
    while (lastRx == 0 && !closed && SystemClock.elapsedRealtime() < end)
      Thread.sleep(20);
    if (lastRx == 0 || closed)
      throw new SocketTimeoutException("carrier_handshake");
  }
  private final DatagramSocket udp;
  private volatile SSLSocket tls;
  private volatile Socket raw;
  private volatile boolean closed;
  private volatile SocketAddress peer;
  private volatile long lastRx;
  private final ArrayBlockingQueue<Packet> queue =
      new ArrayBlockingQueue<>(1024);
  private final ExecutorService threads = Executors.newFixedThreadPool(4);
  private long seq;
  public volatile long sent, received, dropped, reconnects;
  private static final byte[] MAGIC = {69, 86, 71, 84, 0, 1, 0, 0};
  private static class Packet {
    final byte[] bytes;
    final long at = SystemClock.elapsedRealtime();
    Packet(byte[] b) { bytes = b; }
  }
  public TunnelCarrier(VpnService s, boolean e) throws Exception {
    this(s, e, 24573, e ? 24578 : 24571, 1, false);
  }
  private TunnelCarrier(VpnService s, boolean e, int localPort, int remotePort,
                        int batch, boolean lab) throws Exception {
    service = s;
    evgt = e;
    endpointPort = remotePort;
    batchPackets = batch;
    laboratory = lab;
    udp = new DatagramSocket(
        new InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort));
    udp.setReceiveBufferSize(4 * 1024 * 1024);
    udpBuffer = udp.getReceiveBufferSize();
    this.localPort = udp.getLocalPort();
    if (!lab)
      active = this;
    threads.execute(this::receiveUdp);
    threads.execute(this::connectLoop);
    threads.execute(() -> {
      while (!closed) {
        try {
          Thread.sleep(1000);
          SSLSocket sck = tls;
          if (sck != null && lastRx > 0 &&
              SystemClock.elapsedRealtime() - lastRx > 25000)
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
        if ((evgt && p.getLength() > 4096) ||
            !queue.offer(new Packet(Arrays.copyOf(buf, p.getLength())))) {
          dropped++;
          fullDrops.incrementAndGet();
        } else
          queued.incrementAndGet();
      } catch (IOException e) {
        if (!closed)
          Log.w("Evgenium", "carrier_udp_" + e.getClass().getSimpleName());
      }
    }
  }
  private void connectLoop() {
    while (!closed) {
      try {
        if (!laboratory && evgt && SystemClock.elapsedRealtime() < faultUntil) {
          Thread.sleep(500);
          continue;
        }
        raw = new Socket();
        raw.bind(new InetSocketAddress(0));
        if (!service.protect(raw))
          throw new IOException("protect_failed");
        boolean labForward =
            !laboratory &&
            (service.getApplicationInfo().flags &
             android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0 &&
            service.getSharedPreferences("evgenium", 0)
                .getBoolean("lab-forward", false);
        raw.connect(new InetSocketAddress(
                        labForward ? "127.0.0.1" : Credentials.EE,
                        labForward ? (evgt ? 34578 : 34571) : endpointPort),
                    7000);
        raw.setTcpNoDelay(true);
        tls = (SSLSocket)Credentials.tls(service, true)
                  .getSocketFactory()
                  .createSocket(raw, Credentials.EE, endpointPort, true);
        tls.setEnabledProtocols(new String[] {"TLSv1.3"});
        SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        if (evgt && Build.VERSION.SDK_INT >= 29)
          params.setApplicationProtocols(new String[] {"evgenium/1"});
        tls.setSSLParameters(params);
        if (evgt && Build.VERSION.SDK_INT < 29)
          org.conscrypt.Conscrypt.setApplicationProtocols(
              tls, new String[] {"evgenium/1"});
        tls.setSoTimeout(20000);
        tls.startHandshake();
        Log.i("Evgenium", "carrier_tls_authenticated");
        if (evgt &&
            !"evgenium/1".equals(
                Build.VERSION.SDK_INT >= 29
                    ? tls.getApplicationProtocol()
                    : org.conscrypt.Conscrypt.getApplicationProtocol(tls)))
          throw new IOException("alpn_mismatch");
        DataInputStream in = new DataInputStream(tls.getInputStream());
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(
            tls.getOutputStream(), laboratory ? 65536 : 8192));
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
        Socket transport = raw;
        Future<?> writer =
            threads.submit(() -> writeLoop(out, session, transport));
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
            if (evgt) {
              sequenceGaps.addAndGet(number - lastSeq - 1);
              lastSeq = number;
            }
            SocketAddress dest = peer;
            if (dest != null) {
              udp.send(new DatagramPacket(data, len, dest));
              received += len;
              receivedPackets.incrementAndGet();
            }
          }
        } finally {
          abortTransport();
          writer.cancel(true);
        }
      } catch (Exception e) {
        if (!closed)
          Log.w("Evgenium", "carrier_" + (evgt ? "evgt" : "tls") + "_" +
                                e.getClass().getSimpleName() + ":" +
                                e.getMessage());
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
  private void writeLoop(DataOutputStream out, SSLSocket session,
                         Socket transport) {
    try (SocketDeadline.Writes deadline = new SocketDeadline.Writes(
             transport, 10000, () -> writeTimeouts.incrementAndGet())) {
      while (!closed && !session.isClosed()) {
        Packet p = queue.poll(5, TimeUnit.SECONDS);
        synchronized (out) {
          deadline.begin();
          try {
            long started = SystemClock.elapsedRealtime();
            if (p == null) {
              if (evgt) {
                byte[] stamp = new byte[8];
                long t = SystemClock.elapsedRealtime();
                for (int i = 7; i >= 0; i--) {
                  stamp[i] = (byte)t;
                  t >>>= 8;
                }
                frame(out, 2, 0, stamp);
              } else
                out.writeShort(0);
            } else {
              int count = 0;
              do {
                long age = SystemClock.elapsedRealtime() - p.at;
                maxQueueMs = Math.max(maxQueueMs, age);
                if (age > 500) {
                  dropped++;
                  staleDrops.incrementAndGet();
                } else {
                  if (evgt)
                    frame(out, 1, ++seq, p.bytes);
                  else {
                    out.writeShort(p.bytes.length);
                    out.write(p.bytes);
                  }
                  sent += p.bytes.length;
                  sentPackets.incrementAndGet();
                }
                count++;
              } while (count < batchPackets && (p = queue.poll()) != null);
            }
            out.flush();
            long elapsed = SystemClock.elapsedRealtime() - started;
            flushes++;
            writeMs += elapsed;
            maxWriteMs = Math.max(maxWriteMs, elapsed);
          } finally {
            deadline.end();
          }
        }
      }
    } catch (Exception e) {
      try {
        session.close();
      } catch (IOException ignored) {
      }
    }
  }
  private void frame(DataOutputStream out, int type, long number, byte[] data)
      throws IOException {
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
