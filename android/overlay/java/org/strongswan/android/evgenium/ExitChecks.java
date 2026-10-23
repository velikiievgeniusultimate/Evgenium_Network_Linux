/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.io.IOException;
import java.util.Locale;
final class ExitChecks {
  interface Probe { String get(int provider) throws Exception; }
  private volatile int preferred;
  String get(Probe probe) throws Exception {
    Exception last=null; int first=preferred;
    for(int n=0;n<3;n++) {
      int i=(first+n)%3;
      try {
        String ip=probe.get(i);
        if(!ipv4(ip))throw new IOException("exit_probe_format");
        preferred=i;return ip; // Never hide an observed unexpected exit with another provider.
      } catch(InterruptedException e){Thread.currentThread().interrupt();throw e;}
      catch(Exception e){last=e;}
    }
    throw last;
  }
  static boolean ipv4(String value) {
    if(value==null||!value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))return false;
    for(String v:value.split("\\."))if(Integer.parseInt(v)>255 || (v.length()>1&&v.startsWith("0")))return false;
    return true;
  }
  static String parse(String reply, boolean trace) throws IOException {
    int split=reply.indexOf("\r\n\r\n");
    if(split<0 || !(reply.startsWith("HTTP/1.1 200 ")||reply.startsWith("HTTP/1.0 200 ")))throw new IOException("exit_probe_http");
    String headers=reply.substring(0,split).toLowerCase(Locale.ROOT),body=reply.substring(split+4);
    if(headers.matches("(?s).*\\r\\ntransfer-encoding: *chunked\\r?($|\\n.*)")) {
      StringBuilder decoded=new StringBuilder();int at=0;
      while(true) {
        int end=body.indexOf("\r\n",at);if(end<0)throw new IOException("exit_probe_chunk");
        int size;try{size=Integer.parseInt(body.substring(at,end).split(";",2)[0].trim(),16);}catch(RuntimeException e){throw new IOException("exit_probe_chunk");}
        if(size==0)break;
        at=end+2;if(size<0 || size>32768 || at+size+2>body.length() || !body.substring(at+size,at+size+2).equals("\r\n"))throw new IOException("exit_probe_chunk");
        decoded.append(body,at,at+size);at+=size+2;
      }
      body=decoded.toString();
    }
    String value=null;
    if(trace){for(String line:body.split("\\r?\\n"))if(line.startsWith("ip=")){if(value!=null)throw new IOException("exit_probe_ambiguous");value=line.substring(3);}}
    else value=body.trim();
    if(!ipv4(value))throw new IOException("exit_probe_format");return value;
  }
}
