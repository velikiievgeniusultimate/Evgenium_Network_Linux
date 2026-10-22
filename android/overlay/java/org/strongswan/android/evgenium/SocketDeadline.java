/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.net.Socket;
import java.io.IOException;
import java.util.concurrent.*;
public final class SocketDeadline implements AutoCloseable {
  private static final ScheduledExecutorService timers =
      Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "evgenium-socket-deadline");
        t.setDaemon(true);
        return t;
      });
  /**
   * One timer per connection; beginning a write allocates no per-packet timer.
   */
  public static final class Writes implements AutoCloseable {
    private final java.util.concurrent.atomic.AtomicLong started =
        new java.util.concurrent.atomic.AtomicLong();
    private final ScheduledFuture<?> timer;
    public Writes(Socket socket, long millis, Runnable onTimeout) {
      if (millis <= 0)
        throw new IllegalArgumentException("write deadline");
      long budget = TimeUnit.MILLISECONDS.toNanos(millis);
      timer = timers.scheduleWithFixedDelay(
          ()
              -> {
            long at = started.get();
            if (at != 0 && System.nanoTime() - at >= budget &&
                started.compareAndSet(at, 0)) {
              try {
                socket.close();
              } catch (IOException ignored) {
              }
              onTimeout.run();
            }
          },
          Math.min(1000, Math.max(1, millis / 4)),
          Math.min(1000, Math.max(1, millis / 4)), TimeUnit.MILLISECONDS);
    }
    public void begin() { started.set(System.nanoTime()); }
    public void end() { started.set(0); }
    public void close() {
      end();
      timer.cancel(false);
    }
  }
  private final ScheduledFuture<?> task;
  public SocketDeadline(Socket socket, long millis) {
    task = timers.schedule(() -> {
      try {
        socket.close();
      } catch (IOException ignored) {
      }
    }, millis, TimeUnit.MILLISECONDS);
  }
  public void close() { task.cancel(false); }
}
