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
  private final ScheduledFuture<?> task;
  public SocketDeadline(Socket socket, long millis) {
    task = timers.schedule(() -> {
      try {
        socket.close();
      } catch (IOException ignored) {
      }
    }, millis, TimeUnit.MILLISECONDS);
  }
  public void close() {
    task.cancel(false);
  }
}
