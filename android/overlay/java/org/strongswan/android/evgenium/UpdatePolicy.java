/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.net.URI;
import java.util.Arrays;
final class UpdatePolicy {
  static final String PACKAGE = "com.evgenium.network";
  static final String SIGNER = "2cc051f3ec0950ac29a3e86772449e9d8492fed078e323768d25facb397f9aee";
  static boolean allowed(String url) {
    try {
      URI u = new URI(url);
      return "https".equals(u.getScheme()) && u.getUserInfo() == null
          && (u.getPort() == -1 || u.getPort() == 443)
          && Arrays
                 .asList("raw.githubusercontent.com", "github.com", "objects.githubusercontent.com",
                     "release-assets.githubusercontent.com")
                 .contains(u.getHost());
    } catch (Exception e) {
      return false;
    }
  }
  static void validate(String pkg, String signer, long installed, long offered, long archive) {
    if (!PACKAGE.equals(pkg) || !SIGNER.equals(signer) || offered <= installed
        || archive != offered)
      throw new SecurityException("update_identity_or_version");
  }
  static String hex(byte[] data) {
    StringBuilder s = new StringBuilder();
    for (byte b : data) s.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
    return s.toString();
  }
}
