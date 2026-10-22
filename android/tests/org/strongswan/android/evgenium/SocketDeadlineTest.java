/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.net.*;
public class SocketDeadlineTest {
  @Test(timeout = 3000) public void closesAStalledRead() throws Exception {
    try (ServerSocket server = new ServerSocket(0);
         Socket client = new Socket("127.0.0.1", server.getLocalPort());
         Socket peer = server.accept();
         SocketDeadline deadline = new SocketDeadline(client, 100)) {
      try { client.getInputStream().read(); fail("read remained open"); }
      catch (IOException expected) { assertTrue(client.isClosed()); }
    }
  }
  @Test(timeout = 3000) public void finishingProbeCancelsDeadline() throws Exception {
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
  @Test(timeout = 3000) public void trickleDoesNotExtendTotalDeadline() throws Exception {
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
      } catch (IOException expected) { assertTrue(client.isClosed()); }
    }
  }
}
