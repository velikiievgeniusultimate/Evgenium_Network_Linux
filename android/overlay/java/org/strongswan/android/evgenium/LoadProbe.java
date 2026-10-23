/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.net.*;
import org.json.JSONObject;
/** Small TCP-connect samples through the VPN, including while speed traffic runs. */
final class LoadProbe implements AutoCloseable {
  private volatile boolean closed;
  private volatile Socket active;
  private final Thread thread;
  private final PacketWindow samples = new PacketWindow(32);
  private int attempts, failures;
  LoadProbe(int limit) {
    thread = new Thread(() -> {
      for (int i = 0; i < limit && !closed; i++) {
        try (Socket socket = new Socket()) {
          active = socket;
          if (closed)
            break;
          synchronized (this) {
            attempts++;
          }
          long start = System.nanoTime();
          try {
            socket.connect(new InetSocketAddress("1.1.1.1", 443), 1000);
            synchronized (this) {
              samples.reply(i, (System.nanoTime() - start) / 1e6);
            }
          } catch (Exception e) {
            if (!closed)
              synchronized (this) {
                failures++;
              }
          }
        } catch (Exception ignored) {
        } finally {
          active = null;
        }
        try {
          Thread.sleep(250);
        } catch (InterruptedException e) {
          break;
        }
      }
    }, "evgenium-load-latency");
    thread.start();
  }
  synchronized JSONObject metrics() throws Exception {
    return new JSONObject()
        .put("tcp_attempts", attempts)
        .put("tcp_success", samples.received)
        .put("tcp_failed", failures)
        .put("tcp_pending", closed ? 0 : Math.max(0, attempts - samples.received - failures))
        .put("tcp_cancelled", closed ? Math.max(0, attempts - samples.received - failures) : 0)
        .put("tcp_p50_ms", samples.percentile(.5))
        .put("tcp_p95_ms", samples.percentile(.95))
        .put("tcp_max_ms", samples.percentile(1));
  }
  void await() throws InterruptedException {
    thread.join(8000);
  }
  public void close() {
    closed = true;
    Socket s = active;
    if (s != null)
      try {
        s.close();
      } catch (Exception ignored) {
      }
    thread.interrupt();
    try {
      thread.join(1200);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
