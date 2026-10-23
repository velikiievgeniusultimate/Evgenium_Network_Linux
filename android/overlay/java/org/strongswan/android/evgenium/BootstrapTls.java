/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.net.Network;
import java.net.*;
import java.io.*;
import javax.net.ssl.*;
/** Only connects to the fixed pinned-CA enrollment endpoint. No generic bypass. */
final class BootstrapTls {
  private final Context context;
  private final SSLSocketFactory delegate;
  BootstrapTls(Context c, SSLSocketFactory d) {
    context = c;
    delegate = d;
  }
  private Socket connect(String host, int port) throws IOException {
    if (!Credentials.RU.equals(host) || port != 8443)
      throw new IOException("bootstrap_endpoint");
    Socket s = new Socket();
    try {
      org.strongswan.android.logic.CharonVpnService vpn =
          org.strongswan.android.logic.CharonVpnService.evgeniumInstance;
      if (vpn != null) {
        if (!vpn.protect(s))
          throw new IOException("bootstrap_protect");
        Network n = NetworkAccess.select(context);
        if (n == null)
          throw new IOException("bootstrap_offline");
        n.bindSocket(s);
      }
      s.connect(new InetSocketAddress(host, port), 8000);
      s.setSoTimeout(10000);
      return delegate.createSocket(s, host, port, true);
    } catch (IOException e) {
      s.close();
      throw e;
    }
  }
  org.json.JSONObject post(String path, org.json.JSONObject body) throws Exception {
    if (!"/enroll".equals(path) && !"/device".equals(path))
      throw new IOException("bootstrap_path");
    byte[] payload = body.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    try (SSLSocket socket = (SSLSocket) connect(Credentials.RU, 8443)) {
      SSLParameters params = socket.getSSLParameters();
      params.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(params);
      socket.startHandshake();
      byte[] header = ("POST " + path + " HTTP/1.0\r\nHost: " + Credentials.RU
          + ":8443\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
          + payload.length + "\r\n\r\n")
                          .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      OutputStream out = socket.getOutputStream();
      out.write(header);
      out.write(payload);
      out.flush();
      return new org.json.JSONObject(BootstrapResponse.read(socket.getInputStream()));
    }
  }
}
