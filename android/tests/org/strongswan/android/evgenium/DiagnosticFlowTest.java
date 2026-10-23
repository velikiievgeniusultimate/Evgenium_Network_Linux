package org.strongswan.android.evgenium;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Test;
public class DiagnosticFlowTest {
  @Test
  public void explicitWorkflowSavesBeforeSending() throws Exception {
    List<String> events = new ArrayList<>();
    DiagnosticFlow.finish(
        "diagnose-send", () -> events.add("save"), () -> true, () -> events.add("send"));
    assertEquals(Arrays.asList("save", "send"), events);
  }
  @Test
  public void saveFailureNeverUploadsAnOlderReport() {
    try {
      DiagnosticFlow.finish("diagnose-send",
          () -> { throw new IOException(); }, () -> true, () -> fail("stale upload"));
      fail("save must fail");
    } catch (IOException expected) {
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }
  @Test
  public void cancellationWhileSavingPreventsUpload() throws Exception {
    AtomicBoolean current = new AtomicBoolean(true);
    DiagnosticFlow.finish(
        "diagnose-send", () -> current.set(false), current::get, () -> fail("cancelled upload"));
  }
  @Test
  public void OrdinaryRankingNeverSavesOrUploads() throws Exception {
    for (String command : Arrays.asList("rank", "connect", "measure", null))
      DiagnosticFlow.finish(
          command, () -> fail("unexpected save"), () -> true, () -> fail("unconsented upload"));
  }
  @Test
  public void localDiagnosisDoesNotBecomeImplicitConsent() throws Exception {
    List<String> events = new ArrayList<>();
    DiagnosticFlow.finish(
        "diagnose", () -> events.add("save"), () -> true, () -> fail("unconsented upload"));
    assertEquals(Collections.singletonList("save"), events);
  }
}
