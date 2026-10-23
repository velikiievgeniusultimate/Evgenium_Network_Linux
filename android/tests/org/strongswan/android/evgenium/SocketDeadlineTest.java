/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.net.*;
public class SocketDeadlineTest {
  @Test(timeout = 3000)
  public void closesAStalledRead() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline deadline = new SocketDeadline(client, 100)) {
      try {
        client.getInputStream().read();
        fail("read remained open");
      } catch (IOException expected) {
        assertTrue(client.isClosed());
      }
    }
  }
  @Test(timeout = 3000)
  public void finishingProbeCancelsDeadline() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept()) {
      new SocketDeadline(client, 100).close();
      Thread.sleep(200);
      peer.getOutputStream().write(42);
      client.setSoTimeout(500);
      assertEquals(42, client.getInputStream().read());
    }
  }
  @Test(timeout = 3000)
  public void trickleDoesNotExtendTotalDeadline() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline deadline = new SocketDeadline(client, 200)) {
      client.setSoTimeout(500);
      try {
        for (int i = 0; i < 100; i++) {
          peer.getOutputStream().write(1);
          client.getInputStream().read();
          Thread.sleep(25);
        }
        fail("trickle defeated deadline");
      } catch (IOException expected) {
        assertTrue(client.isClosed());
      }
    }
  }
  @Test(timeout = 5000)
  public void writeGuardInterruptsNonReadingPeer() throws Exception {
    try (ServerSocket server = new ServerSocket()) {
      server.setReceiveBufferSize(1024);
      server.bind(new InetSocketAddress("127.0.0.1", 0));
      try (Socket client = new Socket("127.0.0.1", server.getLocalPort());
           Socket peer = server.accept()) {
        client.setSendBufferSize(1024);
        java.util.concurrent.atomic.AtomicInteger timeouts =
            new java.util.concurrent.atomic.AtomicInteger();
        try (SocketDeadline.Writes guard = new SocketDeadline.Writes(
                 client, 150, timeouts::incrementAndGet)) {
          guard.begin();
          try {
            while (true)
              client.getOutputStream().write(new byte[65536]);
          } catch (IOException expected) {
            assertTrue(client.isClosed());
          } finally {
            guard.end();
          }
          for (int i = 0; i < 20 && timeouts.get() == 0; i++)
            Thread.sleep(10);
          assertEquals(1, timeouts.get());
        }
      }
    }
  }
  @Test(timeout = 3000)
  public void completedWritesDoNotCloseIdleConnection() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline.Writes guard = new SocketDeadline.Writes(
             client, 80, () -> fail("unexpected deadline"))) {
      for (int i = 0; i < 3; i++) {
        guard.begin();
        client.getOutputStream().write(i);
        guard.end();
        assertEquals(i, peer.getInputStream().read());
        Thread.sleep(120);
      }
      assertFalse(client.isClosed());
    }
  }
  @Test(timeout = 3000)
  public void bufferedUploadMayReceiveAckAfterShortReadTimeout() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline deadline = new SocketDeadline(client, 1500)) {
      client.setSoTimeout(50);
      client.getOutputStream().write(42);
      assertEquals(42, peer.getInputStream().read());
      Thread response = new Thread(() -> {
        try { Thread.sleep(250); peer.getOutputStream().write(7); }
        catch (Exception e) { throw new AssertionError(e); }
      });
      response.start();
      deadline.awaitResponse(client);
      assertEquals(7, client.getInputStream().read());
      response.join();
    }
  }
  @Test(timeout = 3000)
  public void waitingForAckDoesNotRestartWholeBudget() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline deadline = new SocketDeadline(client, 400)) {
      Thread.sleep(250); // part of the budget already spent uploading
      deadline.awaitResponse(client);
      assertTrue(client.getSoTimeout() <= 200);
      long began = System.nanoTime();
      try { client.getInputStream().read(); fail("stalled ACK accepted"); }
      catch (IOException expected) {
        assertTrue(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began) < 350);
      }
    }
  }
  @Test(timeout = 3000)
  public void expiredBudgetCannotBecomeInfiniteSocketRead() throws Exception {
    try (Socket socket = new Socket(); SocketDeadline deadline = new SocketDeadline(socket, 20)) {
      Thread.sleep(80);
      try { deadline.awaitResponse(socket); fail("expired budget reused"); }
      catch (java.net.SocketTimeoutException expected) {}
    }
  }
}
