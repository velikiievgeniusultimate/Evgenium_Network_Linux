using System;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Windows.Forms;
internal static class Host {
    [STAThread] static int Main(string[] args) {
        string command =
#if CONSOLE
            "status";
#else
            "gui";
#endif
        string expectedSid = "";
        for (int i = 0; i < args.Length; i++) {
            if (args[i] == "--command" && i + 1 < args.Length) command = args[++i];
            else if (args[i] == "--expected-sid" && i + 1 < args.Length) expectedSid = args[++i];
            else if (i == 0 && !args[i].StartsWith("-")) command = args[i];
            else { Console.Error.WriteLine("Unknown argument"); return 2; }
        }
        try {
            using (var reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("Evgenium.ps1")))
            using (var ps = PowerShell.Create()) {
                ps.AddScript(reader.ReadToEnd()).AddParameter("Command", command).AddParameter("ExpectedSid", expectedSid).AddParameter("ExecutableDirectory", AppDomain.CurrentDomain.BaseDirectory);
                foreach (var item in ps.Invoke()) if (item != null) Console.WriteLine(item.ToString());
                if (ps.InvocationStateInfo.State == PSInvocationState.Failed) throw new Exception("Evgenium could not complete the operation.");
                var result = ps.Runspace.SessionStateProxy.GetVariable("EvgeniumExitCode");
                return result == null ? 0 : Convert.ToInt32(result);
            }
        } catch (Exception) {
#if CONSOLE
            Console.Error.WriteLine("Evgenium: operation failed. Start Evgenium.exe for details.");
#else
            MessageBox.Show("Не удалось запустить Evgenium. Нужны Windows 10/11 x64 и Windows PowerShell 5.1.", "Evgenium", MessageBoxButtons.OK, MessageBoxIcon.Error);
#endif
            return 1;
        }
    }
}
