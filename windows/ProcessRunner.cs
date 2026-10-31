using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
public static class EvgeniumProcess {
 public sealed class Result { public int ExitCode; public string Output; public string Error; }
 public static Result Run(string executable,string arguments,string input,int timeout) {
  var info=new ProcessStartInfo(executable,arguments) { UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8 };
  using(var p=new Process { StartInfo=info }) {
   if(!p.Start()) throw new InvalidOperationException("Не удалось запустить сетевое ядро.");
   var output=p.StandardOutput.ReadToEndAsync(); var error=p.StandardError.ReadToEndAsync();
   var bytes=new UTF8Encoding(false).GetBytes(input);
   p.StandardInput.BaseStream.Write(bytes,0,bytes.Length);p.StandardInput.BaseStream.Flush();p.StandardInput.Close();Array.Clear(bytes,0,bytes.Length);
   var started=DateTime.UtcNow;
   while(!p.WaitForExit(100)) {
    if(System.Windows.Forms.Application.MessageLoop)System.Windows.Forms.Application.DoEvents();
    if((DateTime.UtcNow-started).TotalMilliseconds>timeout){p.Kill();p.WaitForExit();throw new TimeoutException("Операция сетевого ядра превысила время ожидания.");}
   }
   if(!Task.WaitAll(new Task[]{output,error},2000))throw new TimeoutException("Не получен ответ сетевого ядра.");
   return new Result { ExitCode=p.ExitCode,Output=output.Result.Trim(),Error=error.Result.Trim() };
  }
 }
}
