/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.net.ssl.*;
import org.json.*;
/** Synthetic mTLS transfer through the VPN. Never protects or binds a bypass socket. */
final class TransferProbe {
  private static final String PRIVATE = "10.77.0.1";
  private static byte[] bytes(JSONObject body) { return body.toString().getBytes(StandardCharsets.UTF_8); }
  private static String hash(byte[] b) throws Exception {
    StringBuilder s=new StringBuilder();for(byte x:MessageDigest.getInstance("SHA-256").digest(b))s.append(String.format(java.util.Locale.ROOT,"%02x",x&255));return s.toString();
  }
  private static JSONObject post(Context c,String host,String path,byte[] payload,String session,int deadlineMs,JSONObject metrics) throws Exception {
    if(Thread.currentThread().isInterrupted())throw new InterruptedException();
    try(Socket raw=new Socket();SocketDeadline deadline=new SocketDeadline(raw,deadlineMs)) {
      raw.connect(new InetSocketAddress(host,8443),Math.min(3000,deadlineMs));raw.setSoTimeout(Math.min(8000,deadlineMs));
      try(SSLSocket tls=(SSLSocket)Credentials.tls(c,true).getSocketFactory().createSocket(raw,host,8443,true)) {
        SSLParameters p=tls.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");tls.setSSLParameters(p);tls.startHandshake();
        OutputStream out=tls.getOutputStream();
        out.write(("POST "+path+" HTTP/1.0\r\nHost: "+host+"\r\nContent-Type: application/octet-stream\r\nContent-Length: "+payload.length+"\r\nConnection: close\r\n"+(session.isEmpty()?"":"X-Evgenium-Session: "+session+"\r\n")+"\r\n").getBytes(StandardCharsets.US_ASCII));
        long began=SystemClock.elapsedRealtime();int written=0;
        for(int offset=0;offset<payload.length;offset+=16384) {
          if(Thread.currentThread().isInterrupted())throw new InterruptedException();
          int n=Math.min(16384,payload.length-offset);out.write(payload,offset,n);written+=n;
          if(metrics!=null)metrics.put("flow_client_written",written);
        }
        out.flush();if(metrics!=null)metrics.put("flow_write_ms",SystemClock.elapsedRealtime()-began);
        JSONObject result;
        try {result=new JSONObject(BootstrapResponse.read(tls.getInputStream()));}
        catch(IOException e) {
          if ("bootstrap_rejected".equals(e.getMessage())) throw new TransferHealth.ServiceUnavailable();
          throw e;
        }
        if(metrics!=null)metrics.put("flow_ack_ms",SystemClock.elapsedRealtime()-began);
        return result;
      }
    }
  }
  private static JSONObject begin(Context c,String host,int size) throws Exception {
    return post(c,host,"/transfer-start",bytes(new JSONObject().put("size",size)),"",6000,null);
  }
  private static String session(JSONObject r) throws Exception {
    String s=r.getString("session");if(!s.matches("[a-f0-9]{32}"))throw new IOException("transfer_session");return s;
  }
  private static void receipt(JSONObject r,byte[] payload) throws Exception {
    if(!r.optBoolean("complete")||r.optInt("received",-1)!=payload.length||!hash(payload).equals(r.optString("sha256"))||!r.optString("padding").equals(new String(new char[16384]).replace('\0','x')))throw new IOException("transfer_integrity");
  }
  private static void counters(JSONObject into,JSONObject r) throws Exception {
    into.put("flow_server_received",r.getLong("received")).put("flow_server_complete",r.getBoolean("complete")?1:0)
        .put("flow_server_ms",r.getLong("elapsed_ms")).put("flow_server_max_read_ms",r.getLong("max_read_ms")).put("flow_result_available",1);
  }
  static JSONObject health(Context c) throws Exception {
    return new TransferHealth().check(endpoint -> {
      String host=endpoint==0?PRIVATE:Credentials.RU;
      byte[] payload=new byte[32768];new SecureRandom().nextBytes(payload);
      String sid=session(begin(c,host,payload.length));
      JSONObject metrics=new JSONObject().put("flow_endpoint",endpoint).put("flow_size",payload.length);
      JSONObject reply=post(c,host,"/transfer-upload",payload,sid,8000,metrics);receipt(reply,payload);counters(metrics,reply);
      return metrics;
    });
  }
  static void diagnose(Context c,PacketDiagnostics.Guard guard,PacketDiagnostics.Record record) throws Exception {
    JSONObject metrics=new JSONObject().put("flow_size",4194304);String sid="",error="";
    guard.check();
    try {
      sid=session(begin(c,PRIVATE,4194304));
      metrics.put("flow_id",sid);
      byte[] payload=new byte[4194304];new SecureRandom().nextBytes(payload);
      JSONObject reply=post(c,PRIVATE,"/transfer-upload",payload,sid,30000,metrics);receipt(reply,payload);counters(metrics,reply);
    } catch(InterruptedException e) {throw e;}
    catch(Exception e) {
      guard.check();error=DiagnosticErrors.classify(e.toString());
      if(!sid.isEmpty())try {
        JSONObject result=post(c,PRIVATE,"/transfer-result",bytes(new JSONObject().put("session",sid)),"",6000,null);counters(metrics,result);
      } catch(Exception unavailable) {metrics.put("flow_result_available",0);}
    }
    guard.check();record.add("flow",metrics,error);
  }
}
