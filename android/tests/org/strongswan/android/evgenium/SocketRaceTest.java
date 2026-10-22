/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
public class SocketRaceTest {
 @Test(timeout=3000) public void winnerRemainsUsableAndLosersClose() throws Exception {
  List<Socket> seen=Collections.synchronizedList(new ArrayList<>());
  CountDownLatch ready=new CountDownLatch(3);
  try(ServerSocket server=new ServerSocket(0)) {
   try(Socket winner=SocketRace.connect(new InetSocketAddress("127.0.0.1",server.getLocalPort()),3,1000,s->{
    seen.add(s);ready.countDown();
    try { if(!ready.await(500,TimeUnit.MILLISECONDS))throw new IOException("barrier"); }
    catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}
   })) {
    assertTrue(winner.isConnected());assertFalse(winner.isClosed());assertEquals(3,seen.size());
    for(Socket s:seen)if(s!=winner)assertTrue(s.isClosed());
   }
  }
 }
 @Test(timeout=3000) public void protectFailureClosesEverySocket() throws Exception {
  List<Socket> seen=Collections.synchronizedList(new ArrayList<>());
  try { SocketRace.connect(new InetSocketAddress("127.0.0.1",1),3,500,s->{seen.add(s);throw new IOException("protect_failed");});fail(); }
  catch(IOException expected){}
  assertEquals(3,seen.size());for(Socket s:seen){assertTrue(s.isClosed());assertFalse(s.isConnected());}
 }
 @Test(timeout=3000) public void timeoutClosesPendingSockets() throws Exception {
  AtomicReference<Socket> seen=new AtomicReference<>();
  try { SocketRace.connect(new InetSocketAddress("127.0.0.1",1),1,100,s->{seen.set(s);try{Thread.sleep(1000);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IOException(e);}});fail(); }
  catch(SocketTimeoutException expected){}
  assertNotNull(seen.get());assertTrue(seen.get().isClosed());
 }
}
