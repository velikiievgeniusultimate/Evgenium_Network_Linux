/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.Locale;
final class DiagnosticErrors {
  static String classify(String text) {
    String e = text.toLowerCase(Locale.ROOT);
    if (e.isEmpty()) return "none";
    for (String state : new String[] {"auth_failed", "peer_auth_failed", "lookup_failed",
        "unreachable", "generic_error", "password_missing", "certificate_unavailable", "timeout"})
      if (e.contains("ike_" + state)) return "ike_" + state;
    if (e.contains("measurement_deadline") || e.contains("probe_deadline")) return "timeout";
    for (String kind : new String[] {"timeout", "dns", "certificate", "authentication", "network",
        "cancel", "unexpected_exit", "carrier", "http"})
      if (e.contains(kind)) return kind;
    return "other";
  }
}
