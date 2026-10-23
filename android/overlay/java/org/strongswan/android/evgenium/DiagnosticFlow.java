/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.util.function.BooleanSupplier;
/** Consent belongs to one explicit diagnose-send command, never ordinary ranking. */
final class DiagnosticFlow {
  static boolean sameOwner(String current, String saved) {
    return current != null && current.matches("device-[a-f0-9]{24}") && current.equals(saved);
  }
  interface Save {
    void run() throws Exception;
  }
  static boolean isDiagnostic(String command) {
    return "diagnose".equals(command) || "diagnose-send".equals(command);
  }
  static void finish(String command, Save save, BooleanSupplier current, Runnable send)
      throws Exception {
    if (!isDiagnostic(command))
      return;
    save.run();
    // Recheck after saving: cancellation or a superseding operation revokes this upload.
    if ("diagnose-send".equals(command) && current.getAsBoolean())
      send.run();
  }
}
