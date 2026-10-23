package org.strongswan.android.evgenium;
import org.junit.Test;import static org.junit.Assert.*;import java.io.*;import java.util.*;
public class ExitChecksTest {
 @Test public void outageUsesIndependentProviderAndRemembersIt()throws Exception{ExitChecks p=new ExitChecks();List<Integer> seen=new ArrayList<>();ExitChecks.Probe f=i->{seen.add(i);if(i==0)throw new IOException();return "38.180.164.67";};assertEquals("38.180.164.67",p.get(f));assertEquals("38.180.164.67",p.get(f));assertEquals(Arrays.asList(0,1,1),seen);}
 @Test public void unexpectedExitIsNeverMasked()throws Exception{ExitChecks p=new ExitChecks();List<Integer> seen=new ArrayList<>();assertEquals("192.0.2.1",p.get(i->{seen.add(i);return "192.0.2.1";}));assertEquals(1,seen.size());}
 @Test public void parsesCloseAndChunkedResponses()throws Exception{assertEquals("38.180.164.67",ExitChecks.parse("HTTP/1.0 200 OK\r\n\r\n38.180.164.67\n",false));assertEquals("38.180.164.67",ExitChecks.parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nd\r\n38.180.164.67\r\n0\r\n\r\n",false));assertEquals("38.180.164.67",ExitChecks.parse("HTTP/1.1 200 OK\r\n\r\nfoo=1\nip=38.180.164.67\n",true));}
 @Test public void malformedOrAmbiguousRepliesAreRejected(){for(String body:new String[]{"ip=999.0.0.1","ip=38.180.164.67\nip=192.0.2.1","ip=038.180.164.67","prefix ip=38.180.164.67"}){try{ExitChecks.parse("HTTP/1.1 200 OK\r\n\r\n"+body,true);fail();}catch(IOException expected){}}}
}
