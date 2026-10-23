/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.net.*;
import android.os.SystemClock;
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import org.json.*;
/** Synthetic datagrams traverse the active VPN; no protect(), raw capture or user payload. */
final class PacketDiagnostics {
  interface Guard {
    void check() throws Exception;
  }
  interface Record {
    void add(String phase, JSONObject values, String error);
  }
  static byte[] hex(String text, int size) throws IOException {
    if (text.length() != size * 2 || !text.matches("[a-f0-9]+"))
      throw new IOException("packet_ticket");
    byte[] out = new byte[size];
    for (int i = 0; i < size; i++)
      out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
    return out;
  }
  static JSONObject control(Context c, String path, JSONObject body) throws Exception {
    try (Socket raw = new Socket(); SocketDeadline deadline = new SocketDeadline(raw, 12000)) {
      raw.connect(new InetSocketAddress("10.77.0.1", 8443), 4000);
      raw.setSoTimeout(4000);
      try (SSLSocket tls = (SSLSocket) Credentials.tls(c, true).getSocketFactory().createSocket(
               raw, "10.77.0.1", 8443, true)) {
        SSLParameters p = tls.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(p);
        tls.startHandshake();
        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        OutputStream out = tls.getOutputStream();
        out.write(("POST " + path
            + " HTTP/1.0\r\nHost: 10.77.0.1\r\nContent-Type: application/json\r\nContent-Length: "
            + bytes.length + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.write(bytes);
        out.flush();
        String response =
            new String(Credentials.read(tls.getInputStream(), 8192), StandardCharsets.UTF_8);
        int split = response.indexOf("\r\n\r\n");
        if (!response.startsWith("HTTP/1.0 200 ") || split < 0)
          throw new IOException("packet_control_http");
        return new JSONObject(response.substring(split + 4));
      }
    }
  }
  static void run(Context c, Guard guard, Record record) throws Exception {
    guard.check();
    dns(c, guard, record);
    try (LoadProbe baseline = new LoadProbe(6)) {
      baseline.await();
      guard.check();
      record.add("baseline", baseline.metrics(), "")
      ;
    }
    JSONObject ticket;
    long start = SystemClock.elapsedRealtime();
    try {
      ticket = control(c, "/packet-session", new JSONObject());
    } catch (Exception e) {
      guard.check();
      record.add("packet",
          new JSONObject().put("control_ms", SystemClock.elapsedRealtime() - start),
          DiagnosticReports.error(e.toString()))
      ;
      return;
    }
    long controlMs = SystemClock.elapsedRealtime() - start;
    byte[] sid = hex(ticket.getString("session"), 16), key = hex(ticket.getString("key"), 32);
    if (ticket.getInt("port") != 24584)
      throw new IOException("packet_port");
    JSONObject[] rows = new JSONObject[6];
    for (int cse = 0; cse < 6; cse++) {
      guard.check();
      int size = new int[] {128, 512, 1200}[cse / 2], burst = cse % 2 == 0 ? 1 : 10;
      rows[cse] = exchange(sid, key, cse, size, burst, guard).put("control_ms", controlMs);
      // Persist immediately: cancellation or a broken control channel cannot erase observations.
      record.add("packet", rows[cse], "")
      ;
    }
    guard.check();
    try {
      JSONArray counts =
          control(c, "/packet-result", new JSONObject().put("session", ticket.getString("session")))
              .getJSONArray("cases");
      // A separate compact sample carries server observations; never infer missing directional
      // counts.
      for (int i = 0; i < 6; i++) {
        JSONObject n = counts.getJSONObject(i);
        record.add("packet_server",
            new JSONObject()
                .put("size", new int[] {128, 512, 1200}[i / 2])
                .put("burst", i % 2 == 0 ? 1 : 10)
                .put("server_received", n.getInt("received"))
                .put("server_replies", n.getInt("replies"))
                .put("server_duplicates", n.getInt("duplicates")),
            "")
        ;
      }
    } catch (Exception e) {
      guard.check();
      record.add("packet_server", new JSONObject(), DiagnosticReports.error(e.toString()))
      ;
    }
    java.util.Arrays.fill(key, (byte) 0);
  }
  static JSONObject exchange(byte[] sid, byte[] key, int cse, int size, int burst, Guard guard)
      throws Exception {
    PacketWindow stats = new PacketWindow(20);
    long[] sentAt = new long[20];
    int sent = 0;
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    byte[][] expected = new byte[20][];
    try (DatagramSocket sock = new DatagramSocket()) {
      sock.connect(InetAddress.getByName("10.77.0.1"), 24584);
      sock.setSoTimeout(50);
      long began = System.nanoTime(), next = began, finished = 0;
      while (System.nanoTime() - began < 5_000_000_000L) {
        guard.check();
        long now = System.nanoTime();
        if (sent < 20 && now >= next) {
          for (int n = 0; n < burst && sent < 20; n++, sent++) {
            byte[] bytes = new byte[size];
            new SecureRandom().nextBytes(bytes);
            ByteBuffer.wrap(bytes).putInt(0x45565031).put(sid).putInt(cse * 20 + sent);
            mac.update(bytes, 0, size - 32);
            System.arraycopy(mac.doFinal(), 0, bytes, size - 32, 32);
            sentAt[sent] = System.nanoTime();
            sock.send(new DatagramPacket(bytes, bytes.length));
            bytes[3] = 50;
            mac.update(bytes, 0, size - 32);
            System.arraycopy(mac.doFinal(), 0, bytes, size - 32, 32);
            expected[sent] = bytes;
          }
          next = now + 100_000_000L;
          if (sent == 20)
            finished = System.nanoTime();
        }
        if (finished > 0 && System.nanoTime() - finished > 1_500_000_000L)
          break;
        byte[] data = new byte[1401];
        DatagramPacket packet = new DatagramPacket(data, data.length);
        try {
          sock.receive(packet);
        } catch (SocketTimeoutException e) {
          continue;
        }
        if (packet.getLength() != size) {
          stats.invalid++;
          continue;
        }
        int seq = ByteBuffer.wrap(data).getInt(20) - cse * 20;
        if (seq < 0 || seq >= sent
            || !MessageDigest.isEqual(expected[seq], java.util.Arrays.copyOf(data, size))) {
          stats.invalid++;
          continue;
        }
        stats.reply(seq, (System.nanoTime() - sentAt[seq]) / 1e6);
        if (stats.received == 20)
          break;
      }
    }
    return new JSONObject()
        .put("size", size)
        .put("burst", burst)
        .put("sent", sent)
        .put("received", stats.received)
        .put("duplicates", stats.duplicates)
        .put("reordered", stats.reordered)
        .put("invalid", stats.invalid)
        .put("loss_percent", sent == 0 ? 0 : 100.0 * (sent - stats.received) / sent)
        .put("rtt_p50_ms", stats.percentile(.5))
        .put("rtt_p95_ms", stats.percentile(.95))
        .put("rtt_max_ms", stats.percentile(1))
        .put("jitter_ms", stats.jitter());
  }
  static void dns(Context context, Guard guard, Record record) throws Exception {
    JSONObject result = new JSONObject();
    ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
    LinkProperties props = cm.getLinkProperties(cm.getActiveNetwork());
    InetAddress server = null;
    if (props != null)
      for (InetAddress a : props.getDnsServers())
        if (a instanceof Inet4Address) {
          server = a;
          break;
        }
    if (server == null) {
      record.add("dns", result, "dns")
      ;
      return;
    }
    int success = 0, timeouts = 0;
    long elapsed = 0;
    for (String host : new String[] {"example.com", "discord.com", "vk.com"}) {
      guard.check();
      long began = SystemClock.elapsedRealtime();
      try (DatagramSocket sock = new DatagramSocket()) {
        sock.connect(server, 53);
        sock.setSoTimeout(1200);
        int id = new SecureRandom().nextInt(65536);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeShort(id);
        out.writeShort(0x100);
        out.writeShort(1);
        out.write(new byte[6]);
        for (String part : host.split("\\.")) {
          out.writeByte(part.length());
          out.writeBytes(part);
        }
        out.writeByte(0);
        out.writeShort(1);
        out.writeShort(1);
        byte[] q = bytes.toByteArray();
        sock.send(new DatagramPacket(q, q.length));
        DatagramPacket reply = new DatagramPacket(new byte[4096], 4096);
        sock.receive(reply);
        byte[] b = reply.getData();
        if (reply.getLength() >= 12 && ((b[0] & 255) * 256 + (b[1] & 255)) == id
            && (b[2] & 0x80) != 0 && (b[3] & 15) == 0 && ((b[6] & 255) * 256 + (b[7] & 255)) > 0)
          success++;
      } catch (SocketTimeoutException e) {
        timeouts++;
      } catch (IOException ignored) {
      }
      elapsed += SystemClock.elapsedRealtime() - began;
    }
    guard.check();
    record.add("dns",
        result.put("dns_queries", 3)
            .put("dns_success", success)
            .put("dns_timeouts", timeouts)
            .put("dns_total_ms", elapsed),
        success == 3 ? "" : "dns")
    ;
  }
}
