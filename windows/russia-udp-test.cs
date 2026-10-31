// CI-only UDP/STUN fixture. Not included in the application package.
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

public static class RussiaUdpTest {
 public static int Main(string[] args) {
  try {
   using(var udp=new UdpClient(AddressFamily.InterNetwork)) {
    udp.Client.ReceiveTimeout=7000;
    if(args.Length==1)udp.Client.Bind(new IPEndPoint(IPAddress.Parse(args[0]),0));
    IPAddress target=null;foreach(var ip in Dns.GetHostAddresses("stun.cloudflare.com"))if(ip.AddressFamily==AddressFamily.InterNetwork){target=ip;break;}
    if(target==null)throw new Exception("STUN IPv4 unavailable");
    udp.Connect(target,3478);
    var packet=new byte[20];packet[1]=1;packet[4]=0x21;packet[5]=0x12;packet[6]=0xa4;packet[7]=0x42;
    var transaction=new byte[12];using(var random=RandomNumberGenerator.Create())random.GetBytes(transaction);Array.Copy(transaction,0,packet,8,12);
    udp.Send(packet,packet.Length);
    IPEndPoint peer=null;var reply=udp.Receive(ref peer);
    if(reply.Length<20||reply[0]!=1||reply[1]!=1)throw new Exception("Invalid STUN reply");
    for(int i=8;i<20;i++)if(reply[i]!=packet[i])throw new Exception("Wrong STUN transaction");
    for(int at=20;at+4<=reply.Length;){
     int type=(reply[at]<<8)|reply[at+1],length=(reply[at+2]<<8)|reply[at+3];
     if(at+4+length>reply.Length)throw new Exception("Truncated STUN reply");
     if(type==0x20&&length>=8&&reply[at+5]==1){
      var address=new byte[4];for(int i=0;i<4;i++)address[i]=(byte)(reply[at+8+i]^packet[4+i]);
      Console.Write(new IPAddress(address));return 0;
     }
     at+=4+((length+3)/4)*4;
    }
    throw new Exception("Missing UDP mapping");
   }
  }catch(Exception e){Console.Error.Write(e.GetType().Name);return 1;}
 }
}
