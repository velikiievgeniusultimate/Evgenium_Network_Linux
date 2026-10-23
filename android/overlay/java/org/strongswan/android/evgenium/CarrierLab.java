/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.os.SystemClock;
import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;
import org.json.*;
/**
 * Debug-only synthetic traffic; no user payload and no change to the active
 * VPN.
 */
public final class CarrierLab {
  private static final AtomicBoolean running = new AtomicBoolean();
  public static void mobileCheck(Context c) {
    if ((c.getApplicationInfo().flags &
         android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
      return;
    new Thread(() -> {
      JSONArray rows = new JSONArray();
      try {
        android.net.ConnectivityManager cm =
            c.getSystemService(android.net.ConnectivityManager.class);
        android.net.Network mobile = null;
        for (android.net.Network n : cm.getAllNetworks()) {
          android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
          if (caps != null &&
              caps.hasTransport(
                  android.net.NetworkCapabilities.TRANSPORT_CELLULAR) &&
              caps.hasCapability(
                  android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
              caps.hasCapability(android.net.NetworkCapabilities
                                     .NET_CAPABILITY_NOT_RESTRICTED)) {
            mobile = n;
            break;
          }
        }
        if (mobile == null)
          throw new IOException("no_mobile_internet_network");
        android.net.Network selectedMobile = mobile;
        android.net.VpnService protection = null;
        for (android.net.Network n : cm.getAllNetworks()) {
          android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
          if (caps != null &&
              caps.hasTransport(
                  android.net.NetworkCapabilities.TRANSPORT_VPN)) {
            protection = TunnelCarrier.labService(c);
            break;
          }
        }
        String[] hosts = {"vk.com", "www.wikipedia.org", "www.google.com",
                          "yandex.ru"};
        String[] fallback = {"87.240.132.72", "185.15.59.224",
                             "142.251.151.119", "5.255.255.77"};
        for (int index = 0; index < hosts.length; index++) {
          String host = hosts[index];
          JSONObject r = new JSONObject()
                             .put("host", host)
                             .put("time", System.currentTimeMillis());
          long start = SystemClock.elapsedRealtime();
          try (Socket raw = new Socket();
               SocketDeadline deadline = new SocketDeadline(raw, 12000)) {
            raw.bind(new InetSocketAddress(0));
            if (protection != null && !protection.protect(raw))
              throw new IOException("protect");
            mobile.bindSocket(raw);
            ExecutorService resolver = Executors.newSingleThreadExecutor();
            Future<InetAddress[]> query =
                resolver.submit(() -> selectedMobile.getAllByName(host));
            InetAddress[] addresses;
            try {
              addresses = query.get(3, TimeUnit.SECONDS);
              r.put("dns", "mobile");
            } catch (Exception e) {
              addresses =
                  new InetAddress[] {InetAddress.getByName(fallback[index])};
              r.put("dns", "lab_fixed_ip_fallback");
            } finally {
              query.cancel(true);
              resolver.shutdownNow();
            }
            InetAddress selected = addresses[0];
            for (InetAddress address : addresses)
              if (address instanceof Inet4Address) {
                selected = address;
                break;
              }
            raw.connect(new InetSocketAddress(selected, 443), 5000);
            try (
                SSLSocket tls =
                    (SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault())
                        .createSocket(raw, host, 443, true)) {
              tls.setSoTimeout(5000);
              SSLParameters params = tls.getSSLParameters();
              params.setEndpointIdentificationAlgorithm("HTTPS");
              tls.setSSLParameters(params);
              tls.startHandshake();
              tls.getOutputStream().write(
                  ("GET / HTTP/1.1\r\nHost: " + host +
                   "\r\nConnection: close\r\n\r\n")
                      .getBytes(StandardCharsets.US_ASCII));
              ByteArrayOutputStream line = new ByteArrayOutputStream();
              for (int i = 0; i < 512; i++) {
                int b = tls.getInputStream().read();
                if (b < 0 || b == 10)
                  break;
                line.write(b);
              }
              String status = line.toString("US-ASCII").trim();
              if (!status.startsWith("HTTP/"))
                throw new IOException("no_http_response");
              r.put("status", status).put("tls_verified", true);
            }
          } catch (Exception e) {
            r.put("error", e.getClass().getSimpleName());
          }
          r.put("ms", SystemClock.elapsedRealtime() - start);
          rows.put(r);
          try (FileOutputStream f = c.openFileOutput("mobile-check.json",
                                                     Context.MODE_PRIVATE)) {
            f.write(rows.toString(2).getBytes(StandardCharsets.UTF_8));
          }
        }
        try (FileOutputStream f =
                 c.openFileOutput("mobile-check.json", Context.MODE_PRIVATE)) {
          f.write(rows.toString(2).getBytes(StandardCharsets.UTF_8));
        }
      } catch (Exception e) {
        try (FileOutputStream f=c.openFileOutput("mobile-check.json",Context.MODE_PRIVATE)) {
          JSONObject failure=new JSONObject().put("time",System.currentTimeMillis()).put("error",e.getClass().getSimpleName()).put("fresh_site_results",false);
          f.write(new JSONArray().put(failure).toString().getBytes(StandardCharsets.UTF_8));
        } catch(Exception ignored) {}
        android.util.Log.w("Evgenium",
                           "mobile_check_" + e.getClass().getSimpleName());
      }
      android.util.Log.i("Evgenium", "mobile_check_finished");
    }, "evgenium-mobile-check").start();
  }
  public static void start(Context c) {
    if ((c.getApplicationInfo().flags &
         android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0 ||
        !running.compareAndSet(false, true))
      return;
    new Thread(() -> {
      JSONArray rows = new JSONArray();
      try {
        try {
          rows.put(baseline(c));
        } catch (Exception e) {
          rows.put(new JSONObject()
                       .put("time", System.currentTimeMillis())
                       .put("case", "ordinary_tls_echo")
                       .put("error", e.getClass().getSimpleName() + ":" +
                                         e.getMessage()));
        }
        save(c, rows);
        for (int rate : new int[] {5, 20, 50})
          for (int batch : new int[] {1, 10, 32}) {
            try {
              rows.put(datagrams(c, batch, rate));
            } catch (Exception e) {
              rows.put(new JSONObject()
                           .put("batch", batch)
                           .put("rate", rate)
                           .put("error", e.getClass().getSimpleName() + ":" +
                                             e.getMessage()));
            }
            save(c, rows);
          }
      } catch (Exception e) {
        android.util.Log.e("Evgenium",
                           "packet_lab_failed_" + e.getClass().getSimpleName());
      } finally {
        running.set(false);
        android.util.Log.i("Evgenium", "packet_lab_finished");
      }
    }, "evgenium-packet-lab").start();
  }
  private static void save(Context c, JSONArray rows) throws Exception {
    try (FileOutputStream f =
             c.openFileOutput("packet-lab.json", Context.MODE_PRIVATE)) {
      f.write(rows.toString(2).getBytes(StandardCharsets.UTF_8));
    }
  }
  private static JSONObject baseline(Context c) throws Exception {
    final int size = 4 * 1024 * 1024;
    try (Socket raw = new Socket();
         SocketDeadline limit = new SocketDeadline(raw, 30000)) {
      raw.bind(new InetSocketAddress(0));
      if (!TunnelCarrier.labService(c).protect(raw))
        throw new IOException("protect");
      raw.connect(new InetSocketAddress(Credentials.EE, 24582), 5000);
      raw.setTcpNoDelay(true);
      try (SSLSocket tls =
               (SSLSocket)Credentials.tls(c, true)
                   .getSocketFactory()
                   .createSocket(raw, Credentials.EE, 24582, true)) {
        tls.setSoTimeout(10000);
        tls.setEnabledProtocols(new String[] {"TLSv1.3"});
        SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(params);
        tls.startHandshake();
        DataOutputStream out = new DataOutputStream(tls.getOutputStream());
        InputStream in = tls.getInputStream();
        out.writeBytes("EVB1");
        out.writeInt(size);
        out.flush();
        if (in.read() != 75)
          throw new IOException("header");
        AtomicReference<Exception> failure = new AtomicReference<>();
        byte[] data = new byte[32768];
        for (int j = 0; j < data.length; j++)
          data[j] = (byte)j;
        long started = SystemClock.elapsedRealtime();
        Thread sender = new Thread(() -> {
          try {
            for (int n = 0; n < size; n += data.length)
              out.write(data);
            out.flush();
          } catch (Exception e) {
            failure.set(e);
          }
        });
        sender.start();
        int count = 0, n;
        byte[] buf = new byte[32768];
        while (count < size &&
               (n = in.read(buf, 0, Math.min(buf.length, size - count))) > 0) {
          for (int j = 0; j < n; j++)
            if (buf[j] != (byte)(count + j))
              throw new IOException("integrity");
          count += n;
        }
        sender.join(2000);
        if (count != size || failure.get() != null || sender.isAlive())
          throw new IOException("stream_incomplete");
        return new JSONObject()
            .put("time", System.currentTimeMillis())
            .put("case", "ordinary_tls_echo")
            .put("bytes", count)
            .put("integrity", true)
            .put("mbps",
                 size * 8.0 /
                     Math.max(1, SystemClock.elapsedRealtime() - started) /
                     1000);
      }
    }
  }
  private static JSONObject datagrams(Context c, int batch, int rate)
      throws Exception {
    final int total = rate >= 50 ? 8192 : 2048, size = 1200, burst = 10;
    try (TunnelCarrier carrier = TunnelCarrier.laboratory(c, batch);
         DatagramSocket socket =
             new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
      socket.setReceiveBufferSize(4194304);
      socket.connect(InetAddress.getByName("127.0.0.1"), carrier.localPort);
      carrier.awaitReady();
      socket.setSoTimeout(8000);
      byte[] warm = new byte[] {69, 86, 71};
      socket.send(new DatagramPacket(warm, warm.length));
      DatagramPacket reply = new DatagramPacket(new byte[4096], 4096);
      socket.receive(reply);
      JSONObject before = carrier.metrics();
      socket.setSoTimeout(150);
      boolean[] seen = new boolean[total];
      AtomicInteger sent = new AtomicInteger();
      AtomicReference<Exception> failure = new AtomicReference<>();
      long start = System.nanoTime();
      AtomicLong sendFinished = new AtomicLong();
      Thread sender = new Thread(() -> {
        try {
          for (int seq = 0; seq < total; seq++) {
            if (seq % burst == 0) {
              long target = start + (long)(seq * size * 8000.0 / rate);
              long wait = target - System.nanoTime();
              if (wait > 0)
                java.util.concurrent.locks.LockSupport.parkNanos(wait);
            }
            byte[] bytes = new byte[size];
            for (int j = 8; j < size; j++)
              bytes[j] = (byte)(seq + j);
            ByteBuffer.wrap(bytes).putLong(seq);
            socket.send(new DatagramPacket(bytes, bytes.length));
            sent.incrementAndGet();
          }
        } catch (Exception e) {
          failure.set(e);
        } finally {
          sendFinished.set(System.nanoTime());
        }
      }, "lab-datagrams");
      sender.start();
      int received = 0, duplicates = 0, invalid = 0;
      long end = SystemClock.elapsedRealtime() + 15000, finished = 0, last = 0;
      while (SystemClock.elapsedRealtime() < end) {
        if (!sender.isAlive() && finished == 0)
          finished = SystemClock.elapsedRealtime();
        if (finished > 0 && SystemClock.elapsedRealtime() - finished > 3000)
          break;
        try {
          reply.setLength(4096);
          socket.receive(reply);
        } catch (SocketTimeoutException e) {
          continue;
        }
        if (reply.getLength() != size) {
          invalid++;
          continue;
        }
        int seq = (int)ByteBuffer.wrap(reply.getData()).getLong();
        if (seq < 0 || seq >= total) {
          invalid++;
          continue;
        }
        boolean ok = true;
        for (int j = 8; j < size; j++)
          if (reply.getData()[j] != (byte)(seq + j)) {
            ok = false;
            break;
          }
        if (!ok) {
          invalid++;
          continue;
        }
        if (seen[seq])
          duplicates++;
        else {
          seen[seq] = true;
          received++;
          last = System.nanoTime();
        }
        if (received == total)
          break;
      }
      socket.close();
      sender.join(1000);
      return new JSONObject()
          .put("time", System.currentTimeMillis())
          .put("case", "udp_carrier_echo")
          .put("batch", batch)
          .put("offered_mbps", rate)
          .put("burst", burst)
          .put("sent", sent.get())
          .put("send_seconds", (sendFinished.get() - start) / 1e9)
          .put("received", received)
          .put("duplicates", duplicates)
          .put("invalid", invalid)
          .put("sender_error", failure.get() == null
                                   ? ""
                                   : failure.get().getClass().getSimpleName())
          .put("delivery_mbps",
               last > start ? received * size * 8.0 / (last - start) * 1000 : 0)
          .put("before", before)
          .put("after", carrier.metrics());
    }
  }
}
