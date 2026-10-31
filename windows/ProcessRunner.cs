using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

// No shell, no console encoding and no key on the command line.
// .NET Framework Process creates a BOM-writing stdin StreamWriter on UTF-8 consoles.
public static class EvgeniumProcess {
    public sealed class Result { public int ExitCode; public string Output; public string Error; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct StartupInfo {
        public int cb; public string reserved; public string desktop; public string title;
        public int x,y,xSize,ySize,xChars,yChars,fillAttribute,flags;
        public short showWindow,reserved2Length; public IntPtr reserved2,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo { public IntPtr process, thread; public int processId, threadId; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CreateProcess(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] private static extern bool GetExitCodeProcess(IntPtr process,out uint exitCode);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(IntPtr process,uint exitCode);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    public static Result Run(string executable,string arguments,string input,int timeout) {
        if (!Regex.IsMatch(arguments,@"\A(selftest|keygen|pubkey|render|validate|validate-exception|routes|reload|remove|uninstall-all|upgrade-stop|upgrade-start|install S-1-5-21-[0-9-]+|diagnose S-1-5-21-[0-9-]+)\z")) throw new ArgumentException("Unsupported engine operation");
        if(executable.IndexOf('"')>=0||input.Length>131072)throw new ArgumentException("Invalid engine input");
        using (var stdin=new AnonymousPipeServerStream(PipeDirection.Out,HandleInheritability.Inheritable))
        using (var stdout=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable))
        using (var stderr=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable)) {
            var startup=new StartupInfo(); startup.cb=Marshal.SizeOf(typeof(StartupInfo)); startup.flags=0x100;
            startup.input=stdin.ClientSafePipeHandle.DangerousGetHandle(); startup.output=stdout.ClientSafePipeHandle.DangerousGetHandle(); startup.error=stderr.ClientSafePipeHandle.DangerousGetHandle();
            ProcessInfo process;
            if (!CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,true,0x08000000,IntPtr.Zero,null,ref startup,out process)) throw new InvalidOperationException("Could not start bundled engine");
            try {
                stdin.DisposeLocalCopyOfClientHandle(); stdout.DisposeLocalCopyOfClientHandle(); stderr.DisposeLocalCopyOfClientHandle();
                using (var outputReader=new StreamReader(stdout,Encoding.UTF8))
                using (var errorReader=new StreamReader(stderr,Encoding.UTF8)) {
                    Task<string> output=outputReader.ReadToEndAsync(), error=errorReader.ReadToEndAsync();
                    byte[] bytes=new UTF8Encoding(false).GetBytes(input);
                    if(bytes.Length>0) stdin.Write(bytes,0,bytes.Length);
                    stdin.Flush(); stdin.Dispose(); Array.Clear(bytes,0,bytes.Length);
                    var started=DateTime.UtcNow;
                    while(WaitForSingleObject(process.process,100)!=0) {
                        if(System.Windows.Forms.Application.MessageLoop)System.Windows.Forms.Application.DoEvents();
                        if((DateTime.UtcNow-started).TotalMilliseconds>timeout){TerminateProcess(process.process,1);WaitForSingleObject(process.process,2000);throw new TimeoutException("Операция сетевого ядра превысила время ожидания.");}
                    }
                    uint exitCode; if(!GetExitCodeProcess(process.process,out exitCode)) throw new InvalidOperationException("Could not query engine exit code");
                    if(!Task.WaitAll(new Task[]{output,error},2000)) throw new TimeoutException("Engine output timed out");
                    return new Result { ExitCode=(int)exitCode, Output=output.Result.Trim(), Error=error.Result };
                }
            } finally { CloseHandle(process.thread); CloseHandle(process.process); }
        }
    }
}
