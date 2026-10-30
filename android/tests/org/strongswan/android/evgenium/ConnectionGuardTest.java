/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;
public class ConnectionGuardTest {
  @Test public void cancelledSlowWorkCannotStartAVpnOrPublishConnected() {
    ConnectionGuard guard = new ConnectionGuard();
    AtomicInteger effects = new AtomicInteger();
    guard.activate(1);
    guard.cancel(); // Stop while the worker was waiting on credentials or exit verification.
    assertFalse(guard.run(1, effects::incrementAndGet));
    assertEquals(0, effects.get());
  }
  @Test public void supersededWorkerCannotPublishIntoANewConnection() {
    ConnectionGuard guard = new ConnectionGuard(); AtomicInteger effects = new AtomicInteger();
    guard.activate(1); guard.cancel(); guard.activate(3);
    assertFalse(guard.run(1, effects::incrementAndGet));
    assertTrue(guard.run(3, effects::incrementAndGet));
    assertEquals(1, effects.get());
  }
  @Test public void stopOrdersDisconnectAfterAnAlreadyDispatchedStart() throws Exception {
    ConnectionGuard guard = new ConnectionGuard(); guard.activate(1);
    CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1), stopping = new CountDownLatch(1);
    java.util.List<String> actions = new java.util.concurrent.CopyOnWriteArrayList<>();
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<?> start = pool.submit(() -> guard.run(1, () -> {
        entered.countDown();
        try { if (!release.await(2, TimeUnit.SECONDS)) throw new AssertionError("release"); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
        actions.add("start");
      }));
      assertTrue(entered.await(2, TimeUnit.SECONDS));
      Future<?> stop = pool.submit(() -> { stopping.countDown(); guard.cancel(); actions.add("disconnect"); });
      assertTrue(stopping.await(2, TimeUnit.SECONDS));
      release.countDown(); start.get(2, TimeUnit.SECONDS); stop.get(2, TimeUnit.SECONDS);
      assertEquals(java.util.Arrays.asList("start", "disconnect"), actions);
      assertFalse(guard.run(1, () -> actions.add("late-start")));
    } finally { release.countDown(); pool.shutdownNow(); }
  }
}
