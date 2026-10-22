package org.strongswan.android.evgenium;
import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
public class ReleaseSafetyTest {
  @Test
  public void rejectsUntrustedOrigins() {
    for (String u : new String[] {"http://github.com/a", "https://github.com.evil/a",
             "https://user@github.com/a", "https://github.com:444/a", "file:///tmp/a"})
      assertFalse(u, UpdatePolicy.allowed(u));
    assertTrue(UpdatePolicy.allowed("https://release-assets.githubusercontent.com/a"));
  }
  @Test
  public void rejectsWrongPackageKeyAndDowngrade() {
    for (String[] row : new String[][] {{"other", UpdatePolicy.SIGNER, "11", "11"},
             {UpdatePolicy.PACKAGE, "bad", "11", "11"},
             {UpdatePolicy.PACKAGE, UpdatePolicy.SIGNER, "10", "10"},
             {UpdatePolicy.PACKAGE, UpdatePolicy.SIGNER, "11", "12"}}) {
      try {
        UpdatePolicy.validate(row[0], row[1], 10, Long.parseLong(row[2]), Long.parseLong(row[3]));
        fail();
      } catch (SecurityException expected) {
      }
    }
    UpdatePolicy.validate(UpdatePolicy.PACKAGE, UpdatePolicy.SIGNER, 10, 11, 11);
  }
  @Test
  public void renewalWindowAndExpiredRetry() {
    long now = 10000000000L;
    assertFalse(RenewalPolicy.due(now, now + 8L * 86400000, 0));
    assertTrue(RenewalPolicy.due(now, now + 6L * 86400000, 0));
    assertFalse(RenewalPolicy.due(now, now + 86400000, now - 1000));
    assertTrue(RenewalPolicy.due(now, now - 1, now - 1000));
    assertTrue(RenewalPolicy.due(now, now + 86400000, now + 1000));
  }
  private String read(String s) throws IOException {
    return BootstrapResponse.read(new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8)));
  }
  @Test
  public void boundedBootstrapReply() throws Exception {
    assertEquals("{}", read("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}"));
    for (String s : new String[] {"HTTP/1.0 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}",
             "HTTP/1.0 200 OK\r\nContent-Length: 70000\r\n\r\n",
             "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
             "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{",
             "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"}) {
      try {
        read(s);
        fail();
      } catch (IOException expected) {
      }
    }
  }
}
