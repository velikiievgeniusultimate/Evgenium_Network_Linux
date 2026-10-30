/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Bounded HTTP/1 response framing; a complete response does not require socket EOF. */
final class HttpResponseReader {
  private final InputStream in;
  private final int limit;
  private final ByteArrayOutputStream wire = new ByteArrayOutputStream();

  private HttpResponseReader(InputStream in, int limit) {
    if (limit <= 0) throw new IllegalArgumentException("response limit");
    this.in = in;
    this.limit = limit;
  }

  static byte[] read(InputStream in, int limit) throws IOException {
    return new HttpResponseReader(in, limit).read();
  }

  private int one() throws IOException {
    int b = in.read();
    if (b == -1) throw new IOException("exit_probe_truncated");
    if (wire.size() == limit) throw new IOException("response_too_large");
    wire.write(b);
    return b;
  }

  private String line() throws IOException {
    ByteArrayOutputStream text = new ByteArrayOutputStream();
    while (true) {
      int b = one();
      if (b == '\r') {
        if (one() != '\n') throw new IOException("exit_probe_http_framing");
        return new String(text.toByteArray(), StandardCharsets.US_ASCII);
      }
      if (b == '\n' || b == 0 || b == 127 || (b < 32 && b != '\t') || b > 126)
        throw new IOException("exit_probe_http_framing");
      text.write(b);
    }
  }

  private static String name(String line) throws IOException {
    int at = line.indexOf(':');
    if (at <= 0 || !line.substring(0, at).matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
      throw new IOException("exit_probe_http_header");
    return line.substring(0, at).toLowerCase(Locale.ROOT);
  }

  private void exact(int count) throws IOException {
    if (count < 0 || count > limit - wire.size()) throw new IOException("response_too_large");
    byte[] buffer = new byte[Math.min(4096, Math.max(1, count))];
    while (count > 0) {
      int n = in.read(buffer, 0, Math.min(buffer.length, count));
      if (n == -1) throw new IOException("exit_probe_truncated");
      if (n == 0) { one(); count--; }
      else { wire.write(buffer, 0, n); count -= n; }
    }
  }

  private byte[] read() throws IOException {
    String status = line();
    // These probes require 200; reject errors/interim/upgrade responses immediately.
    if (!(status.startsWith("HTTP/1.1 200 ") || status.startsWith("HTTP/1.0 200 ")))
      throw new IOException("exit_probe_http");
    Integer length = null;
    boolean chunked = false;
    String header;
    while (!(header = line()).isEmpty()) {
      String key = name(header);
      String value = header.substring(header.indexOf(':') + 1).trim();
      if (key.equals("content-length")) {
        if (length != null || !value.matches("[0-9]+"))
          throw new IOException("exit_probe_http_length");
        try { length = Integer.valueOf(value); }
        catch (NumberFormatException e) { throw new IOException("exit_probe_http_length"); }
      } else if (key.equals("transfer-encoding")) {
        if (chunked || !value.equalsIgnoreCase("chunked"))
          throw new IOException("exit_probe_http_encoding");
        chunked = true;
      }
    }
    if (chunked && length != null) throw new IOException("exit_probe_http_ambiguous_length");
    if (chunked) {
      while (true) {
        String chunk = line();
        String size = chunk.split(";", 2)[0];
        if (!size.matches("[0-9a-fA-F]+")) throw new IOException("exit_probe_chunk");
        int count;
        try { count = Integer.parseInt(size, 16); }
        catch (NumberFormatException e) { throw new IOException("exit_probe_chunk"); }
        if (count == 0) {
          String trailer;
          while (!(trailer = line()).isEmpty()) {
            String key = name(trailer);
            if (key.equals("content-length") || key.equals("transfer-encoding"))
              throw new IOException("exit_probe_http_trailer");
          }
          break;
        }
        exact(count);
        if (one() != '\r' || one() != '\n') throw new IOException("exit_probe_chunk");
      }
    } else if (length != null) {
      exact(length);
    } else {
      // HTTP/1.0 and responses explicitly delimited by closing the connection.
      byte[] buffer = new byte[4096];
      int n;
      while ((n = in.read(buffer)) != -1) {
        if (n == 0) continue;
        if (n > limit - wire.size()) throw new IOException("response_too_large");
        wire.write(buffer, 0, n);
      }
    }
    return wire.toByteArray();
  }
}
