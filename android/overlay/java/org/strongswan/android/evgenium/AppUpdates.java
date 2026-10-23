/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.app.Activity;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.Build;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;
final class AppUpdates {
  static final String MANIFEST = "https://raw.githubusercontent.com/velikiievgeniusultimate/"
                                 + "Evgenium_Network_Linux/main/releases/android/beta.json";
  static final AtomicBoolean busy = new AtomicBoolean();
  static volatile String status = "Проверить обновления";
  static HttpURLConnection open(String url) throws Exception {
    for (int i = 0; i < 5; i++) {
      if (!UpdatePolicy.allowed(url))
        throw new IOException("update_origin");
      HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
      c.setConnectTimeout(8000);
      c.setReadTimeout(12000);
      c.setInstanceFollowRedirects(false);
      int code;
      try {
        code = c.getResponseCode();
      } catch (Exception e) {
        c.disconnect();
        throw e;
      }
      if (code == 200)
        return c;
      String next = c.getHeaderField("Location");
      c.disconnect();
      if (code < 300 || code >= 400 || next == null)
        throw new IOException("update_http_" + code);
      url = new URL(new URL(url), next).toString();
    }
    throw new IOException("update_redirects");
  }
  static String signer(PackageInfo info) throws Exception {
    android.content.pm.Signature[] signs =
        Build.VERSION.SDK_INT >= 28 ? info.signingInfo.getApkContentsSigners() : info.signatures;
    if (signs == null || signs.length != 1)
      throw new SecurityException("update_signers");
    return UpdatePolicy.hex(MessageDigest.getInstance("SHA-256").digest(signs[0].toByteArray()));
  }
  static int flags() {
    return Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES
                                       : PackageManager.GET_SIGNATURES;
  }
  static void check(Activity a) {
    if (!busy.compareAndSet(false, true))
      return;
    new Thread(() -> {
      File temporary = null;
      try {
        if (!UpdatePolicy.PACKAGE.equals(a.getPackageName()))
          throw new IOException("Сначала установите релизную версию");
        status = "Проверяю обновления…";
        HttpURLConnection c = open(MANIFEST);
        JSONObject manifest;
        try (InputStream in = c.getInputStream()) {
          manifest =
              new JSONObject(new String(Credentials.read(in, 16384), StandardCharsets.UTF_8));
        } finally {
          c.disconnect();
        }
        PackageInfo installed = a.getPackageManager().getPackageInfo(a.getPackageName(), flags());
        long offered = manifest.getLong("version_code");
        if (offered <= installed.versionCode) {
          status = "Установлена актуальная версия";
          return;
        }
        if (!UpdatePolicy.SIGNER.equals(signer(installed)))
          throw new SecurityException("installed_signer");
        long size = manifest.getLong("size");
        String digest = manifest.getString("sha256");
        if (size < 1000 || size > 120 * 1024 * 1024 || !digest.matches("[a-f0-9]{64}"))
          throw new IOException("update_manifest");
        File folder = new File(a.getCacheDir(), "updates");
        folder.mkdirs();
        File apk = new File(folder, "update.apk"), tmp = new File(folder, "update.tmp");
        temporary = tmp;
        if (apk.isFile() && apk.length() == size) {
          MessageDigest cached = MessageDigest.getInstance("SHA-256");
          try (InputStream in = new FileInputStream(apk)) {
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) != -1) cached.update(b, 0, n);
          }
          if (digest.equals(UpdatePolicy.hex(cached.digest()))) {
            PackageInfo archive =
                a.getPackageManager().getPackageArchiveInfo(apk.toString(), flags());
            if (archive == null)
              throw new SecurityException("update_apk");
            UpdatePolicy.validate(archive.packageName, signer(archive), installed.versionCode,
                offered, archive.versionCode);
            a.runOnUiThread(() -> install(a, apk));
            return;
          }
        }
        status = "Скачиваю обновление…";
        c = open(manifest.getString("url"));
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        long count = 0, deadline = android.os.SystemClock.elapsedRealtime() + 180000;
        try (InputStream in = c.getInputStream();
            FileOutputStream out = new FileOutputStream(tmp)) {
          byte[] b = new byte[65536];
          int n;
          while ((n = in.read(b)) != -1) {
            count += n;
            if (count > size || android.os.SystemClock.elapsedRealtime() > deadline)
              throw new IOException("update_size_or_deadline");
            hash.update(b, 0, n);
            out.write(b, 0, n);
          }
          out.getFD().sync();
        } finally {
          c.disconnect();
        }
        if (count != size || !digest.equals(UpdatePolicy.hex(hash.digest())))
          throw new SecurityException("update_integrity");
        PackageInfo archive = a.getPackageManager().getPackageArchiveInfo(tmp.toString(), flags());
        if (archive == null)
          throw new SecurityException("update_apk");
        UpdatePolicy.validate(archive.packageName, signer(archive), installed.versionCode, offered,
            archive.versionCode);
        if (!tmp.renameTo(apk))
          throw new IOException("update_save");
        status = "Обновление проверено — установить";
        a.runOnUiThread(() -> install(a, apk));
      } catch (Exception e) {
        status = "Не удалось обновить. Повторите позже.";
      } finally {
        if (temporary != null)
          temporary.delete();
        busy.set(false);
      }
    }, "evgenium-update").start();
  }
  static void install(Activity a, File apk) {
    try {
      if (!a.getPackageManager().canRequestPackageInstalls()) {
        status = "Разрешите установку и нажмите обновление ещё раз";
        a.startActivity(new Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
            Uri.parse("package:" + a.getPackageName())));
        return;
      }
      Uri uri =
          androidx.core.content.FileProvider.getUriForFile(a, a.getPackageName() + ".updates", apk);
      a.startActivity(new Intent(Intent.ACTION_VIEW)
              .setDataAndType(uri, "application/vnd.android.package-archive")
              .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));
    } catch (Exception e) {
      status = "Не удалось открыть установщик Android";
    }
  }
}
