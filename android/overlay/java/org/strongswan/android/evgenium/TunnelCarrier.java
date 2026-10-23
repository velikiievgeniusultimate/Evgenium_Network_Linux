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
  private static volatile long heartbeatFaultUntil;
  public static void debugHeartbeatFault(android.content.Context c) {
    if ((c.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
      heartbeatFaultUntil = SystemClock.uptimeMillis() + 90000;
  }
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

  private final TrafficPower power;
  private final VpnService service;
  private final boolean evgt;
  private final int endpointPort, batchPackets, udpBuffer;
  private final int requestedSendBuffer;
  private volatile int tcpSendBuffer, tcpReceiveBuffer, dialAttempts;
  private volatile long connectMs;
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
  private volatile long maxQueueMs, maxWriteMs, writeMs, flushes, heartbeatRttMs;
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
        .put("heartbeat_rtt_ms", heartbeatRttMs)
        .put("heartbeat_timeouts", heartbeatTimeouts.get())
        .put("max_queue_ms", maxQueueMs)
        .put("max_write_ms", maxWriteMs)
        .put("write_timeouts", writeTimeouts.get())
        .put("write_ms", writeMs)
        .put("flushes", flushes)
        .put("reconnects", reconnects)
        .put("udp_receive_buffer", udpBuffer)
        .put("batch_packets", batchPackets)
        .put("max_age_ms", 0) // live sessions do not expire opaque IPsec packets
        .put("transfer_cpu_lock", power.held())
        .put("dial_attempts", dialAttempts)
        .put("connect_ms", connectMs)
        .put("tcp_send_buffer", tcpSendBuffer)
        .put("tcp_receive_buffer", tcpReceiveBuffer)
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
  private volatile Heartbeat heartbeat;
  private final AtomicLong heartbeatTimeouts = new AtomicLong();
  private volatile long offlineSince = SystemClock.elapsedRealtime();
  public static long offlineMillis() {
    TunnelCarrier a = active;
    return a == null || a.closed || a.offlineSince == 0 ? 0 : Math.max(0, SystemClock.elapsedRealtime() - a.offlineSince);
  }
  private final CarrierQueue queue = new CarrierQueue(1024);
  private final ExecutorService threads = Executors.newFixedThreadPool(4);
  private long seq;
  public volatile long sent, received, dropped, reconnects;
  private static final byte[] MAGIC = {69, 86, 71, 84, 0, 1, 0, 0};
  private static int debugBatch(VpnService s,boolean evgt) {
    if(!evgt || (s.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE)==0)return 1;
    int n=s.getSharedPreferences("evgenium",0).getInt("lab-batch",1);
    return n==10||n==32?n:1;
  }
  public TunnelCarrier(VpnService s, boolean e) throws Exception {
    this(s, e, 24573, e ? 24578 : 24571, debugBatch(s,e), false);
  }
  private TunnelCarrier(VpnService s, boolean e, int localPort, int remotePort,
                        int batch, boolean lab) throws Exception {
    service = s;
    evgt = e;
    endpointPort = remotePort;
    batchPackets = batch;
    laboratory = lab;
    boolean debug = (s.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    int buffer = debug ? s.getSharedPreferences("evgenium", 0).getInt("lab-send-buffer", 0) : 0;
    requestedSendBuffer = buffer == 1048576 || buffer == 4194304 ? buffer : 0;
    power = new TrafficPower(s, debug && s.getSharedPreferences("evgenium", 0).getBoolean("lab-traffic-power", false));
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
          power.sample(sent + received);
          Heartbeat h = heartbeat;
          if (h != null && h.expired(SystemClock.uptimeMillis())) {
            heartbeat = null; heartbeatTimeouts.incrementAndGet(); abortTransport();
          }
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
            !queue.offer(Arrays.copyOf(buf, p.getLength()), SystemClock.elapsedRealtime())) {
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
        lastRx = 0;
        power.connecting();
        boolean labForward =
            !laboratory &&
            (service.getApplicationInfo().flags &
             android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0 &&
            service.getSharedPreferences("evgenium", 0)
                .getBoolean("lab-forward", false);
        boolean relay = evgt && !laboratory && "ee-evgt-ru".equals(service.getSharedPreferences("evgenium", 0).getString("route", ""));
        dialAttempts = (service.getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0 && service.getSharedPreferences("evgenium", 0).getInt("lab-dials", 1) == 3 ? 3 : 1;
        long dialStart = SystemClock.elapsedRealtime();
        raw = SocketRace.connect(new InetSocketAddress(
                        labForward ? "127.0.0.1" : relay ? Credentials.RU : Credentials.EE,
                        labForward ? (evgt ? 34578 : 34571) : relay ? 24579 : endpointPort),
                    dialAttempts, 7000, socket -> {
                      if (requestedSendBuffer > 0) socket.setSendBufferSize(requestedSendBuffer);
                      socket.bind(new InetSocketAddress(0));
                      if (!service.protect(socket)) throw new IOException("protect_failed");
                    });
        if (closed) { raw.close(); return; }
        connectMs = SystemClock.elapsedRealtime() - dialStart;
        raw.setTcpNoDelay(true);
        tcpSendBuffer = raw.getSendBufferSize();
        tcpReceiveBuffer = raw.getReceiveBufferSize();
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
        DataInputStream in;
        DataOutputStream out;
        try (SocketDeadline handshake = new SocketDeadline(raw, 6000)) {
        tls.startHandshake();
        Log.i("Evgenium", "carrier_tls_authenticated");
        if (evgt &&
            !"evgenium/1".equals(
                Build.VERSION.SDK_INT >= 29
                    ? tls.getApplicationProtocol()
                    : org.conscrypt.Conscrypt.getApplicationProtocol(tls)))
          throw new IOException("alpn_mismatch");
        in = new DataInputStream(tls.getInputStream());
        out = new DataOutputStream(new BufferedOutputStream(
            tls.getOutputStream(), laboratory ? 65536 : 8192));
        if (evgt) {
          out.write(MAGIC);
          out.flush();
          byte[] m = new byte[8];
          in.readFully(m);
          if (!Arrays.equals(m, MAGIC))
            throw new IOException("protocol_magic");
        }
        }
        heartbeat = evgt ? new Heartbeat(3000, 12000) : null;
        offlineSince = 0;
        seq = 0;
        lastRx = SystemClock.elapsedRealtime();
        SSLSocket session = tls;
        Socket transport = raw;
        SocketDeadline.Writes deadline = new SocketDeadline.Writes(transport, 10000, () -> writeTimeouts.incrementAndGet());
        Future<?> writer = threads.submit(() -> writeLoop(out, session, deadline));
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
                deadline.begin();
                try { frame(out, 3, number, data); out.flush(); }
                finally { deadline.end(); }
              }
              continue;
            }
            if (type == 3) {
              Heartbeat h = heartbeat;
              long rtt = h == null || SystemClock.uptimeMillis() < heartbeatFaultUntil ? -1 : h.ack(data, SystemClock.uptimeMillis());
              if (rtt >= 0) heartbeatRttMs = rtt;
              continue;
            }
            if (len == 0) continue;
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
          deadline.close();
        }
      } catch (Exception e) {
        if (!closed)
          Log.w("Evgenium", "carrier_" + (evgt ? "evgt" : "tls") + "_" +
                                e.getClass().getSimpleName() + ":" +
                                e.getMessage());
      } finally {
        heartbeat = null;
        if (!closed && offlineSince == 0) offlineSince = SystemClock.elapsedRealtime();
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
                         SocketDeadline.Writes deadline) {
    try {
      while (!closed && !session.isClosed()) {
        CarrierQueue.Packet p = queue.poll(evgt ? 1 : 5, TimeUnit.SECONDS);
        Heartbeat h = heartbeat;
        byte[] probe = h == null ? null : h.probe(SystemClock.uptimeMillis());
        if (p == null && evgt && probe == null) continue;
        synchronized (out) {
          deadline.begin();
          try {
            long started = SystemClock.elapsedRealtime();
            if (probe != null) frame(out, 2, 0, probe);
            if (p == null) {
              if (!evgt) out.writeShort(0);
            } else {
              int count = 0;
              do {
                long age = SystemClock.elapsedRealtime() - p.at;
                maxQueueMs = Math.max(maxQueueMs, age);
                // Opaque IPsec can contain TCP ACKs or IKE. Dropping a whole
                // delayed burst amplifies congestion; keep FIFO until session reset.
                if (evgt)
                  frame(out, 1, ++seq, p.bytes);
                else {
                  out.writeShort(p.bytes.length);
                  out.write(p.bytes);
                }
                sent += p.bytes.length;
                sentPackets.incrementAndGet();
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
    power.close();
    udp.close();
    abortTransport();
    threads.shutdownNow();
  }
}
