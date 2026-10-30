package org.strongswan.android.evgenium;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import static org.junit.Assert.*;

public class HttpResponseReaderTest {
  private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
  /** Models a keep-alive socket: reading beyond the complete response would block. */
  private static InputStream open(String s) {
    return new ByteArrayInputStream(bytes(s)) {
      @Override public synchronized int read() {
        if (available()==0) throw new AssertionError("waited for EOF after complete response");
        return super.read();
      }
      @Override public synchronized int read(byte[] b,int off,int len) {
        if (available()==0) throw new AssertionError("waited for EOF after complete response");
        return super.read(b,off,len);
      }
    };
  }
  private static void bad(String s,int limit) throws Exception {
    try { HttpResponseReader.read(new ByteArrayInputStream(bytes(s)),limit); fail("accepted malformed response"); }
    catch(IOException expected) {}
  }
  @Test public void contentLengthCompletesWithoutEof() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\n38.180.164.67";
    assertEquals("38.180.164.67",ExitChecks.parse(new String(HttpResponseReader.read(open(s),32768),StandardCharsets.US_ASCII),false));
  }
  @Test public void chunkedTrailersCompleteWithoutEof() throws Exception {
    String s="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\n38.18\r\n8\r\n0.164.67\r\n0\r\nX-Trace: done\r\n\r\n";
    assertEquals("38.180.164.67",ExitChecks.parse(new String(HttpResponseReader.read(open(s),32768),StandardCharsets.US_ASCII),false));
  }
  @Test public void zeroBodyCompletesWithoutEof() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assertArrayEquals(bytes(s),HttpResponseReader.read(open(s),s.length()));
  }
  @Test public void closeDelimitedFallbackStillWorks() throws Exception {
    String s="HTTP/1.0 200 OK\r\n\r\nip=38.180.164.67\n";
    assertArrayEquals(bytes(s),HttpResponseReader.read(new ByteArrayInputStream(bytes(s)),32768));
  }
  @Test public void doesNotConsumeNextResponse() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
    ByteArrayInputStream in=new ByteArrayInputStream(bytes(s+"NEXT"));
    assertArrayEquals(bytes(s),HttpResponseReader.read(in,32768));assertEquals('N',in.read());
  }
  @Test public void shortReadsWork() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n38.180.164.67";
    InputStream in=new ByteArrayInputStream(bytes(s)) {
      public synchronized int read(byte[] b,int off,int len) { return super.read(b,off,Math.min(len,1)); }
    };
    assertArrayEquals(bytes(s),HttpResponseReader.read(in,32768));
  }
  @Test public void truncationRejected() throws Exception {
    for(String s:new String[]{"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n38.18",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: a\r\n"}) bad(s,32768);
  }
  @Test public void conflictingOrInvalidLengthsRejected() throws Exception {
    for(String headers:new String[]{"Content-Length: 1\r\nContent-Length: 1","Content-Length: 1, 1",
      "Content-Length: -1","Content-Length: 99999999999999999","Content-Length: 1\r\nTransfer-Encoding: chunked",
      "Transfer-Encoding: gzip, chunked","Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"})
      bad("HTTP/1.1 200 OK\r\n"+headers+"\r\n\r\nx",32768);
  }
  @Test public void malformedChunkAndTrailersRejected() throws Exception {
    for(String body:new String[]{"-1\r\nx\r\n0\r\n\r\n","FFFFFFFFFFFFFFFF\r\n","1\r\nxXX0\r\n\r\n",
      "0\r\nContent-Length: 1\r\n\r\n","0\r\n bad: trailer\r\n\r\n"})
      bad("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"+body,32768);
  }
  @Test public void totalWireBoundIncludesHeadersAndChunkOverhead() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
    assertArrayEquals(bytes(s),HttpResponseReader.read(open(s),s.length()));bad(s,s.length()-1);
    bad("HTTP/1.1 200 OK\r\nContent-Length: 32768\r\n\r\n",32768);
    bad("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8000\r\n",32768);
    bad("HTTP/1.0 200 OK\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",30);
  }
  @Test public void invalidStatusAndHeadersRejectedWithoutWaitingForBody() throws Exception {
    for(String s:new String[]{"HTTP/1.1 503 Unavailable\r\n","HTTP/1.1 200 OK\n\n","HTTP/1.1 200 OK\r\n Folded: a\r\n\r\n"}) bad(s,32768);
  }
  @Test public void unexpectedExitIsNotChangedByFraming() throws Exception {
    String s="HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n192.0.2.1";
    assertEquals("192.0.2.1",ExitChecks.parse(new String(HttpResponseReader.read(open(s),32768),StandardCharsets.US_ASCII),false));
  }
}
