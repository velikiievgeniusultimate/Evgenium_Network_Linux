using System;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Threading;
using System.Management.Automation.Runspaces;
using System.Windows.Forms;
internal static class Host {
    [STAThread] static int Main(string[] args) {
        string command = "gui";
        string expectedSid = "";
        string resultId = "";
        for (int i = 0; i < args.Length; i++) {
            if (args[i] == "--command" && i + 1 < args.Length) command = args[++i];
            else if (args[i] == "--expected-sid" && i + 1 < args.Length) expectedSid = args[++i];
            else if (args[i] == "--result-id" && i + 1 < args.Length) resultId = args[++i];
            else if (i == 0 && !args[i].StartsWith("-")) command = args[i];
            else { Console.Error.WriteLine("Unknown argument"); return 2; }
        }
        Mutex singleInstance = null;
        try {
            // The same windowed executable hosts privileged operations internally.
            // No console process or separately exposed CLI is required.
            if (command == "gui" || command == "widget") {
                bool created;
                singleInstance = new Mutex(true, "Local\\EvgeniumNetwork.Desktop", out created);
                if (!created) { MessageBox.Show("Evgenium уже открыт. Найдите его окно на панели задач.", "Evgenium"); return 0; }
            }
            using (var reader = new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("Evgenium.ps1")))
            using (var runspace = RunspaceFactory.CreateRunspace())
            using (var ps = PowerShell.Create()) {
                runspace.ApartmentState=ApartmentState.STA;
                runspace.ThreadOptions=PSThreadOptions.UseCurrentThread;
                runspace.Open();ps.Runspace=runspace;
                ps.AddScript(reader.ReadToEnd()).AddParameter("Command", command).AddParameter("ExpectedSid", expectedSid).AddParameter("ResultId", resultId).AddParameter("ExecutableDirectory", AppDomain.CurrentDomain.BaseDirectory);
                foreach (var item in ps.Invoke()) if (item != null) Console.WriteLine(item.ToString());
                if (ps.InvocationStateInfo.State == PSInvocationState.Failed) throw new Exception("Evgenium could not complete the operation.");
                var result = ps.Runspace.SessionStateProxy.GetVariable("EvgeniumExitCode");
                return result == null ? 0 : Convert.ToInt32(result);
            }
        } catch (Exception) {
            if (command == "gui" || command == "widget" || command == "uninstall") MessageBox.Show("Не удалось запустить Evgenium. Нужны Windows 10/11 x64 и Windows PowerShell 5.1.", "Evgenium", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        } finally { if (singleInstance != null) singleInstance.Dispose(); }
    }
}
