/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.*;
/** No DNS dependency: ordinary unprotected socket, inside the VPN, authenticated HTTPS. */
public final class ExitProbe {
  private static volatile SSLSocketFactory factory;
  private static synchronized SSLSocketFactory factory(android.content.Context context)
      throws Exception {
    if (factory != null)
      return factory;
    if (android.os.Build.VERSION.SDK_INT >= 29)
      return factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    java.security.KeyStore system = java.security.KeyStore.getInstance("AndroidCAStore");
    system.load(null);
    java.security.KeyStore trust =
        java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
    trust.load(null);
    java.util.Enumeration<String> aliases = system.aliases();
    while (aliases.hasMoreElements()) {
      String a = aliases.nextElement();
      trust.setCertificateEntry(a, system.getCertificate(a));
    }
    try (InputStream in = context.getAssets().open("sslcom-root-ecc.pem")) {
      trust.setCertificateEntry("evgenium-sslcom-root-ecc",
          java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in));
    }
    TrustManagerFactory managers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    managers.init(trust);
    SSLContext tls = SSLContext.getInstance("TLS");
    tls.init(null, managers.getTrustManagers(), null);
    return factory = tls.getSocketFactory();
  }
  public static String get(android.content.Context context) throws Exception {
    try (Socket raw = new Socket()) {
      raw.connect(new InetSocketAddress("1.1.1.1", 443), 3000);
      raw.setSoTimeout(3000);
      try (SSLSocket tls = (SSLSocket) factory(context).createSocket(raw, "1.1.1.1", 443, true)) {
        tls.setSoTimeout(3000);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        tls.getOutputStream().write(
            "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".getBytes(
                StandardCharsets.US_ASCII));
        String reply =
            new String(Credentials.read(tls.getInputStream(), 32768), StandardCharsets.US_ASCII);
        if (!reply.startsWith("HTTP/1.1 200 "))
          throw new IOException("exit_probe_http");
        for (String line : reply.split("\\r?\\n"))
          if (line.matches("ip=[0-9.]{7,15}"))
            return line.substring(3);
        throw new IOException("exit_probe_format");
      }
    }
  }
}
