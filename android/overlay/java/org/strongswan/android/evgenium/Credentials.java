/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

/** Device keys never leave AndroidKeyStore. Enrollment uses the pinned project CA. */
public final class Credentials {
  public static final String ALIAS = "evgenium-device-v2";
  public static final String RU = "195.209.211.163", EE = "38.180.164.67";
  public static KeyStore store() throws Exception {
    KeyStore s = KeyStore.getInstance("AndroidKeyStore");
    s.load(null);
    return s;
  }
  public static PrivateKey key() throws Exception {
    return (PrivateKey) store().getKey(ALIAS, null);
  }
  public static X509Certificate ca(Context c) throws Exception {
    try (InputStream in = c.getAssets().open("evgenium-ca.pem")) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
  }
  public static JSONObject profile(Context c) throws Exception {
    try (InputStream in = c.openFileInput("device.json")) {
      return new JSONObject(new String(read(in, 32768), StandardCharsets.UTF_8));
    }
  }
  public static X509Certificate certificate(Context c) throws Exception {
    return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
        new ByteArrayInputStream(
            profile(c).getString("certificate").getBytes(StandardCharsets.US_ASCII)));
  }
  public static SSLContext tls(Context c, boolean client) throws Exception {
    KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
    trust.load(null);
    trust.setCertificateEntry("ca", ca(c));
    TrustManagerFactory tm =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tm.init(trust);
    KeyManager[] km = null;
    if (client) {
      final PrivateKey k = key();
      final X509Certificate[] chain = {certificate(c), ca(c)};
      km = new KeyManager[] {new X509ExtendedKeyManager(){public String[] getClientAliases(
          String type, Principal[] p){return "RSA".equals(type) ? new String[] {ALIAS} : null;
    }
    public String chooseClientAlias(String[] types, Principal[] p, Socket s) {
      for (String t : types)
        if ("RSA".equals(t))
          return ALIAS;
      return null;
    }
    public String chooseEngineClientAlias(String[] types, Principal[] p, SSLEngine e) {
      return chooseClientAlias(types, p, null);
    }
    public String[] getServerAliases(String t, Principal[] p) {
      return null;
    }
    public String chooseServerAlias(String t, Principal[] p, Socket s) {
      return null;
    }
    public X509Certificate[] getCertificateChain(String a) {
      return ALIAS.equals(a) ? chain : null;
    }
    public PrivateKey getPrivateKey(String a) {
      return ALIAS.equals(a) ? k : null;
    }
  }
};
}
SSLContext ctx = android.os.Build.VERSION.SDK_INT < 29
    ? SSLContext.getInstance("TLS", org.conscrypt.Conscrypt.newProvider())
    : SSLContext.getInstance("TLS");
ctx.init(km, tm.getTrustManagers(), new SecureRandom());
return ctx;
}
public static JSONObject request(
    Context c, String host, String path, JSONObject body, boolean client) throws Exception {
  if (!client && RU.equals(host) && ("/enroll".equals(path) || "/device".equals(path)))
    return new BootstrapTls(c, tls(c, false).getSocketFactory()).post(path, body);
  HttpsURLConnection conn =
      (HttpsURLConnection) new URL("https://" + host + ":8443" + path).openConnection();
  conn.setSSLSocketFactory(tls(c, client).getSocketFactory());
  conn.setConnectTimeout(8000);
  conn.setReadTimeout(10000);
  conn.setInstanceFollowRedirects(false);
  conn.setRequestMethod("POST");
  conn.setDoOutput(true);
  conn.setRequestProperty("Content-Type", "application/json");
  byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
  conn.setFixedLengthStreamingMode(payload.length);
  try {
    try (OutputStream out = conn.getOutputStream()) {
      out.write(payload);
    }
    if (conn.getResponseCode() != 200)
      throw new IOException("HTTP_" + conn.getResponseCode());
    try (InputStream in = conn.getInputStream()) {
      return new JSONObject(new String(read(in, 65536), StandardCharsets.UTF_8));
    }
  } finally {
    conn.disconnect();
  }
}
public static synchronized void ensureFresh(Context c) throws Exception {
  X509Certificate previous = certificate(c);
  long now = System.currentTimeMillis();
  android.content.SharedPreferences prefs = c.getSharedPreferences("evgenium", 0);
  if (!RenewalPolicy.due(now, previous.getNotAfter().getTime(), prefs.getLong("renewal-attempt", 0))) {
    previous.checkValidity(); return;
  }
  prefs.edit().putLong("renewal-attempt", now).commit();
  try {
    enroll(c, token(c));
    android.util.Log.i("Evgenium", "certificate_renewed");
  } catch (Exception failure) {
    previous.checkValidity(); // fail closed if no valid certificate remains
    android.util.Log.w("Evgenium", "certificate_renewal_deferred_"+failure.getClass().getSimpleName());
  }
}
public static synchronized void enroll(Context c, String token) throws Exception {
  if (!token.matches("EVN1-[A-Za-z0-9_-]{43}"))
    throw new IllegalArgumentException("Неверный формат токена");
  KeyStore ks = store();
  if (!ks.containsAlias(ALIAS)) {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    gen.initialize(new KeyGenParameterSpec
            .Builder(ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setKeySize(3072)
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(
                KeyProperties.ENCRYPTION_PADDING_NONE, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setSignaturePaddings(
                KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
            .build());
    gen.generateKeyPair();
  }
  String device = c.getSharedPreferences("evgenium", 0).getString("device-v2", null);
  if (device == null) {
    device = UUID.randomUUID().toString().replace("-", "");
    c.getSharedPreferences("evgenium", 0).edit().putString("device-v2", device).commit();
  }
  byte[] pub = store().getCertificate(ALIAS).getPublicKey().getEncoded();
  byte[] subject = der(0x30,
      der(0x31,
          der(0x30,
              concat(new byte[] {6, 3, 0x55, 4, 3},
                  der(12, "evgenium-device".getBytes(StandardCharsets.UTF_8))))));
  byte[] info = der(0x30, concat(new byte[] {2, 1, 0}, subject, pub, new byte[] {(byte) 0xa0, 0}));
  Signature sig = Signature.getInstance("SHA256withRSA");
  sig.initSign(key());
  sig.update(info);
  byte[] alg = {
      0x30, 0x0d, 6, 9, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 1, 1, 0x0b, 5, 0};
  byte[] csr = der(0x30, concat(info, alg, der(3, concat(new byte[] {0}, sig.sign()))));
  String pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + Base64.encodeToString(csr, Base64.NO_WRAP)
      + "\n-----END CERTIFICATE REQUEST-----\n";
  JSONObject response = request(c, RU, "/enroll",
      new JSONObject().put("token", token).put("device", device).put("csr", pem), false);
  if (!response.optBoolean("ok"))
    throw new IOException("enrollment_rejected");
  JSONObject p = response.getJSONObject("profile");
  if (!p.getString("identity").matches("device-[a-f0-9]{24}") || !RU.equals(p.getString("server")))
    throw new IOException("invalid_profile");
  X509Certificate cert =
      (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
          new ByteArrayInputStream(p.getString("certificate").getBytes(StandardCharsets.US_ASCII)));
  try {
    cert.checkValidity();
  } catch (CertificateNotYetValidException e) {
    long wait = cert.getNotBefore().getTime() - System.currentTimeMillis();
    if (wait < 0 || wait > 5000)
      throw e;
    Thread.sleep(wait + 100);
    cert.checkValidity();
  }
  cert.verify(ca(c).getPublicKey());
  if (!Arrays.equals(cert.getPublicKey().getEncoded(), pub))
    throw new IOException("certificate_key_mismatch");
  File tmp = new File(c.getFilesDir(), "device.json.tmp");
  try (FileOutputStream out = new FileOutputStream(tmp)) {
    out.write(p.toString().getBytes(StandardCharsets.UTF_8));
    out.getFD().sync();
  }
  if (!tmp.renameTo(new File(c.getFilesDir(), "device.json")))
    throw new IOException("profile_save_failed");
  saveToken(c, token);
}
public static void saveToken(Context c, String token) throws Exception {
  final String alias = "evgenium-token-storage";
  KeyStore ks = store();
  if (!ks.containsAlias(alias)) {
    javax.crypto.KeyGenerator gen = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore");
    gen.init(new KeyGenParameterSpec
            .Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build());
    gen.generateKey();
  }
  javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, store().getKey(alias, null));
  byte[] sealed = concat(cipher.getIV(), cipher.doFinal(token.getBytes(StandardCharsets.UTF_8)));
  try (FileOutputStream out = c.openFileOutput("token.sealed", Context.MODE_PRIVATE)) {
    out.write(sealed);
    out.getFD().sync();
  }
}
public static String token(Context c) throws Exception {
  byte[] sealed;
  try (InputStream in = c.openFileInput("token.sealed")) {
    sealed = read(in, 512);
  }
  if (sealed.length < 28)
    throw new IOException("token_storage_invalid");
  javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(javax.crypto.Cipher.DECRYPT_MODE, store().getKey("evgenium-token-storage", null),
      new javax.crypto.spec.GCMParameterSpec(128, Arrays.copyOf(sealed, 12)));
  return new String(
      cipher.doFinal(Arrays.copyOfRange(sealed, 12, sealed.length)), StandardCharsets.UTF_8);
}
public static synchronized String rename(Context c, String name) throws Exception {
  name = name.trim();
  if (name.isEmpty() || name.length() > 64 || name.chars().anyMatch(Character::isISOControl))
    throw new IllegalArgumentException("Имя: от 1 до 64 символов без управляющих знаков");
  String device = c.getSharedPreferences("evgenium", 0).getString("device-v2", null);
  JSONObject response = request(c, RU, "/device",
      new JSONObject().put("token", token(c)).put("device", device).put("name", name), false);
  if (!response.optBoolean("ok"))
    throw new IOException("rename_rejected");
  String actual = response.getJSONObject("device").getString("name");
  JSONObject p = profile(c);
  p.put("device_name", actual);
  File temp = new File(c.getFilesDir(), "device.json.tmp");
  try (FileOutputStream out = new FileOutputStream(temp)) {
    out.write(p.toString().getBytes(StandardCharsets.UTF_8));
    out.getFD().sync();
  }
  if (!temp.renameTo(new File(c.getFilesDir(), "device.json")))
    throw new IOException("profile_save_failed");
  return actual;
}
public static byte[] read(InputStream in, int limit) throws IOException {
  ByteArrayOutputStream out = new ByteArrayOutputStream();
  byte[] b = new byte[4096];
  int n;
  while ((n = in.read(b)) != -1) {
    if (out.size() + n > limit)
      throw new IOException("response_too_large");
    out.write(b, 0, n);
  }
  return out.toByteArray();
}
static byte[] concat(byte[]... parts) {
  ByteArrayOutputStream b = new ByteArrayOutputStream();
  for (byte[] p : parts) b.write(p, 0, p.length);
  return b.toByteArray();
}
static byte[] der(int tag, byte[] data) {
  byte[] size = data.length < 128 ? new byte[] {(byte) data.length}
      : data.length < 256 ? new byte[] {(byte) 0x81, (byte) data.length}
                          : new byte[] {(byte) 0x82, (byte) (data.length >> 8), (byte) data.length};
  return concat(new byte[] {(byte) tag}, size, data);
}
}
