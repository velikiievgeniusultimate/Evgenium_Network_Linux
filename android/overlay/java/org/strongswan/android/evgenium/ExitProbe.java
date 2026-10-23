/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.*;
/**
 * Authenticated HTTPS inside the VPN. Numeric primary/final probes avoid DNS;
 * an independent provider uses a bounded resolver as fallback.
 */
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
  private static final ExitChecks checks = new ExitChecks();
  private static final java.util.concurrent.ExecutorService resolver = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
    Thread t=new Thread(r,"evgenium-exit-dns");t.setDaemon(true);return t;
  });
  private static java.util.concurrent.Future<InetAddress[]> query;
  private static InetAddress[] cached;
  private static long cachedAt;
  private static synchronized InetAddress resolveIndependent() throws Exception {
    long now=android.os.SystemClock.elapsedRealtime();
    if(cached!=null && now-cachedAt<600000)return cached[0];
    // At most one DNS task: a resolver stall cannot accumulate threads or work.
    if(query==null)query=resolver.submit(()->InetAddress.getAllByName("api.ipify.org"));
    try {
      InetAddress[] result=query.get(2,java.util.concurrent.TimeUnit.SECONDS);
      query=null;
      for(InetAddress address:result)if(address instanceof Inet4Address){cached=new InetAddress[]{address};cachedAt=now;return address;}
      throw new IOException("exit_probe_no_ipv4");
    } catch(java.util.concurrent.TimeoutException e) {
      if(cached!=null)return cached[0];throw new IOException("exit_probe_dns_timeout");
    } catch(java.util.concurrent.ExecutionException e){query=null;if(cached!=null)return cached[0];throw new IOException("exit_probe_dns_failed");}
  }
  public static String get(android.content.Context context) throws Exception {
    return checks.get(index -> get(context,index));
  }
  private static String get(android.content.Context context, int index) throws Exception {
    String host=index==0?"1.1.1.1":index==1?"api.ipify.org":"1.0.0.1";
    InetAddress address=index==1?resolveIndependent():InetAddress.getByName(host);
    try (Socket raw = new Socket(); SocketDeadline deadline = new SocketDeadline(raw, 4500)) {
      raw.connect(new InetSocketAddress(address, 443), 3000);
      raw.setSoTimeout(3000);
      try (SSLSocket tls = (SSLSocket) factory(context).createSocket(raw, host, 443, true)) {
        tls.setSoTimeout(3000);
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        tls.getOutputStream().write(
            ("GET "+(index==1?"/":"/cdn-cgi/trace")+" HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        String reply = new String(Credentials.read(tls.getInputStream(), 32768), StandardCharsets.US_ASCII);
        return ExitChecks.parse(reply,index!=1);
      }
    }
  }
}
