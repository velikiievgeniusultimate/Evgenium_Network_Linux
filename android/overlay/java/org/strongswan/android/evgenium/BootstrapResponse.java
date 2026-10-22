/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.io.*;
import java.nio.charset.StandardCharsets;
final class BootstrapResponse {
  static String read(InputStream in) throws IOException {
    ByteArrayOutputStream header = new ByteArrayOutputStream();
    int match = 0;
    byte[] end = {13, 10, 13, 10};
    while (match < 4) {
      int b = in.read();
      if (b < 0 || header.size() >= 8192)
        throw new IOException("bootstrap_header");
      header.write(b);
      match = b == end[match] ? match + 1 : (b == 13 ? 1 : 0);
    }
    String[] lines = new String(header.toByteArray(), StandardCharsets.US_ASCII).split("\r\n");
    if (!lines[0].matches("HTTP/1\\.[01] 200(?: .*)?"))
      throw new IOException("bootstrap_rejected");
    int length = -1;
    for (String line : lines) {
      String lower = line.toLowerCase(java.util.Locale.ROOT);
      if (lower.startsWith("transfer-encoding:"))
        throw new IOException("bootstrap_encoding");
      if (lower.startsWith("content-length:")) {
        if (length != -1)
          throw new IOException("bootstrap_duplicate_length");
        try {
          length = Integer.parseInt(line.substring(15).trim());
        } catch (NumberFormatException e) {
          throw new IOException("bootstrap_length");
        }
      }
    }
    if (length < 0 || length > 65536)
      throw new IOException("bootstrap_length");
    byte[] data = new byte[length];
    int read = 0;
    while (read < length) {
      int n = in.read(data, read, length - read);
      if (n < 0)
        throw new EOFException();
      read += n;
    }
    return new String(data, StandardCharsets.UTF_8);
  }
}
