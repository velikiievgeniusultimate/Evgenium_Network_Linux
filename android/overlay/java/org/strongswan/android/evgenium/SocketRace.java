/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/** Bounded TCP-only race. TLS authenticates exactly one winner afterwards. */
public final class SocketRace {
  interface Prepare { void apply(Socket socket) throws IOException; }
  public static Socket connect(InetSocketAddress address, int attempts, int timeout, Prepare prepare)
      throws IOException, InterruptedException {
    if (attempts < 1 || attempts > 3 || timeout < 1) throw new IllegalArgumentException();
    Socket[] sockets = new Socket[attempts];
    ExecutorService pool = Executors.newFixedThreadPool(attempts);
    CompletionService<Socket> completed = new ExecutorCompletionService<>(pool);
    Socket winner = null;
    try {
      // Register every socket before submitting work so cancellation can close all losers.
      for (int i = 0; i < attempts; i++) sockets[i] = new Socket();
      for (Socket socket : sockets) completed.submit(() -> {
        prepare.apply(socket);
        socket.connect(address, timeout);
        return socket;
      });
      long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout);
      IOException failure = new SocketTimeoutException("connect_deadline");
      for (int i = 0; i < attempts; i++) {
        long left = end - System.nanoTime();
        if (left <= 0) break;
        Future<Socket> next = completed.poll(left, TimeUnit.NANOSECONDS);
        if (next == null) break;
        try { winner = next.get(); return winner; }
        catch (ExecutionException e) { failure = new IOException("connect_failed", e.getCause()); }
      }
      throw failure;
    } finally {
      for (Socket socket : sockets) if (socket != null && socket != winner) {
        try { socket.close(); } catch (IOException ignored) {}
      }
      pool.shutdownNow();
    }
  }
}
