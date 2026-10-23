package org.strongswan.android.evgenium;
import static org.junit.Assert.*;
import org.junit.Test;
public class DiagnosticErrorsTest {
  @Test public void ikeFailuresRetainSpecificReasonWithoutRawText() {
    for(String state:new String[]{"AUTH_FAILED","PEER_AUTH_FAILED","LOOKUP_FAILED","UNREACHABLE","GENERIC_ERROR","PASSWORD_MISSING","CERTIFICATE_UNAVAILABLE","TIMEOUT"})
      assertEquals("ike_"+state.toLowerCase(java.util.Locale.ROOT),DiagnosticErrors.classify("IOException:ike_"+state));
  }
  @Test public void unknownTextNeverLeaksAndDeadlinesAreTimeouts() {
    assertEquals("other",DiagnosticErrors.classify("EVN1-secret 192.0.2.1"));
    assertEquals("timeout",DiagnosticErrors.classify("IOException:measurement_deadline"));
    assertEquals("timeout",DiagnosticErrors.classify("SocketTimeoutException: Read timed out"));
    assertEquals("none",DiagnosticErrors.classify(""));
  }
}
