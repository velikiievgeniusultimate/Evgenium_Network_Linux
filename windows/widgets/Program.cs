using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Windows.Widgets.Providers;
using WinRT;

namespace Evgenium.NativeWidget;

internal static class Program {
 internal const string ClassId="E7214EB8-485E-4C4E-AB89-1527E3EAE7C9";
 [DllImport("ole32.dll")]private static extern int CoRegisterClassObject([MarshalAs(UnmanagedType.LPStruct)] Guid clsid,[MarshalAs(UnmanagedType.IUnknown)] object factory,uint context,uint flags,out uint cookie);
 [DllImport("ole32.dll")]private static extern int CoRevokeClassObject(uint cookie);
 [MTAThread]private static void Main(string[] args){
  if(args.Contains("--selftest")){Card.SelfTest();return;}
  ComWrappersSupport.InitializeComWrappers();
  var factory=new ProviderFactory();Marshal.ThrowExceptionForHR(CoRegisterClassObject(new Guid(ClassId),factory,4,1,out uint cookie));
  try {Provider.Shutdown.Wait();}finally {CoRevokeClassObject(cookie);GC.KeepAlive(factory);}
 }
}

[ComImport,InterfaceType(ComInterfaceType.InterfaceIsIUnknown),Guid("00000001-0000-0000-C000-000000000046")]
internal interface IClassFactory {
 [PreserveSig]int CreateInstance(IntPtr outer,ref Guid iid,out IntPtr instance);
 [PreserveSig]int LockServer([MarshalAs(UnmanagedType.Bool)]bool value);
}
[ComVisible(true)]internal sealed class ProviderFactory:IClassFactory {
 public int CreateInstance(IntPtr outer,ref Guid iid,out IntPtr instance){instance=IntPtr.Zero;if(outer!=IntPtr.Zero)return unchecked((int)0x80040110);IntPtr provider=IntPtr.Zero;try{provider=MarshalInspectable<IWidgetProvider>.FromManaged(Provider.Instance);return Marshal.QueryInterface(provider,in iid,out instance);}catch(Exception e){return Marshal.GetHRForException(e);}finally{if(provider!=IntPtr.Zero)Marshal.Release(provider);}}
 public int LockServer(bool value){return 0;}
}

internal sealed class Provider:IWidgetProvider {
 internal static readonly ManualResetEventSlim Shutdown=new(false);
 internal static readonly Provider Instance=new();
 private readonly ConcurrentDictionary<string,bool> widgets=new();
 private readonly SemaphoreSlim operation=new(1,1);
 private readonly System.Threading.Timer refresh;
 private readonly System.Threading.Timer idle;
 private int polling;
 private bool busy;
 private string error="";
 public Provider(){
  foreach(var item in WidgetManager.GetDefault().GetWidgetInfos())widgets[item.WidgetContext.Id]=false;
  refresh=new System.Threading.Timer(_=>Refresh(),null,TimeSpan.FromSeconds(2),TimeSpan.FromSeconds(2));
  // Windows restarts the COM provider when required. Do not remain resident
  // indefinitely when the board is closed; pinned widgets survive process exit.
  idle=new System.Threading.Timer(_=>{if(!busy&&!widgets.Values.Any(v=>v))Shutdown.Set();},null,TimeSpan.FromMinutes(3),TimeSpan.FromMinutes(1));
 }
 public void CreateWidget(WidgetContext context){string id=context.Id;widgets[id]=true;Update(id);}
 public void DeleteWidget(string id,string state){widgets.TryRemove(id,out _);}
 public void Activate(WidgetContext context){string id=context.Id;widgets[id]=true;Update(id);}
 public void Deactivate(string id){widgets[id]=false;}
 public void OnWidgetContextChanged(WidgetContextChangedArgs args){string id=args.WidgetContext.Id;Update(id);}
 public void OnActionInvoked(WidgetActionInvokedArgs args){
  // Callback arguments have no lifetime beyond this method. Copy only the verb.
  string verb=args.Verb;if(verb!="toggle"&&verb!="settings")return;
  _=Task.Run(()=>Act(verb));
 }
 private async Task Act(string verb){
  if(!await operation.WaitAsync(0))return;
  try{
   if(verb=="settings"){OpenGui();return;}
   busy=true;error="";Refresh();
   string exe=MainExecutable();
   using var process=Process.Start(new ProcessStartInfo(exe,"--command "+(Card.ReadState().Protected?"off":"on")){UseShellExecute=false,CreateNoWindow=true});
   if(process==null)throw new IOException("Не удалось запустить приложение.");
   using var limit=new CancellationTokenSource(TimeSpan.FromMinutes(3));await process.WaitForExitAsync(limit.Token);
   if(process.ExitCode!=0){error="Действие не выполнено. Откройте приложение и проверьте токен или запрос Windows.";OpenGui();}
  }catch(Exception){error="Не удалось выполнить действие. Откройте Evgenium.";}
  finally{busy=false;operation.Release();Refresh();}
 }
 private static string MainExecutable(){string path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"EvgeniumNetwork","Evgenium.exe");if(!File.Exists(path))throw new FileNotFoundException("Установите основное приложение Evgenium.");return path;}
 private static void OpenGui(){Process.Start(new ProcessStartInfo(MainExecutable()){UseShellExecute=true});}
 private void Refresh(){if(Interlocked.Exchange(ref polling,1)!=0)return;try{foreach(var item in widgets)if(item.Value)Update(item.Key);}finally{Volatile.Write(ref polling,0);}}
 private void Update(string id){try{WidgetManager.GetDefault().UpdateWidget(new WidgetUpdateRequestOptions(id){Template=Card.Template,Data=Card.Data(Card.ReadState(),busy,error),CustomState="",IsPlaceholderContent=false});}catch(COMException){}catch(IOException){} }
}

internal readonly record struct State(bool Protected,bool Connected,bool Stale);
internal static class Card {
 // Adaptive Cards are rendered by the Windows host, not a floating app window.
 // Keep credentials, device names, endpoint addresses and logs out of the card.
 internal const string Template="""
 {"type":"AdaptiveCard","version":"1.5","$schema":"http://adaptivecards.io/schemas/adaptive-card.json","body":[
 {"type":"TextBlock","text":"E-VPN","weight":"Bolder","size":"Large","wrap":true},
 {"type":"TextBlock","text":"${status}","wrap":true,"isSubtle":true,"spacing":"Small"},
 {"type":"ActionSet","actions":[{"type":"Action.Execute","title":"${button}","verb":"toggle","isEnabled":"${enabled}"},{"type":"Action.Execute","title":"⚙","verb":"settings"}],"$when":"${$host.isUserContextAuthenticated}"},
 {"type":"TextBlock","text":"Управление VPN доступно после входа в Windows.","wrap":true,"$when":"${!$host.isUserContextAuthenticated}"}
 ]}
 """;
 internal static State ReadState(){
  string sid=WindowsIdentity.GetCurrent().User!.Value;
  string file=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"EvgeniumNetwork",sid,"status.json");
  try{if(!File.Exists(file)||new FileInfo(file).Length>1024*1024)return new(false,false,false);using var json=JsonDocument.Parse(File.ReadAllText(file));var r=json.RootElement;bool guard=r.TryGetProperty("protected",out var p)&&p.GetBoolean();bool stale=!r.TryGetProperty("updated",out var t)||t.GetInt64()<DateTimeOffset.UtcNow.ToUnixTimeSeconds()-30;return new(guard,!stale&&r.TryGetProperty("state",out var s)&&s.GetString()=="connected",stale&&guard);}catch(IOException){return new(false,false,true);}catch(UnauthorizedAccessException){return new(false,false,true);}catch(JsonException){return new(false,false,true);}
 }
 internal static string Data(State state,bool busy,string error){return JsonSerializer.Serialize(new{status=error!=""?error:busy?"Выполняется…":state.Connected?"● Подключено":state.Protected||state.Stale?"Восстановление связи…":"Отключено",button=state.Protected?"Отключить":"Подключить",enabled=!busy});}
 internal static void SelfTest(){
  using var template=JsonDocument.Parse(Template);
  foreach(var state in new[]{new State(false,false,false),new State(true,true,false),new State(true,false,true)}){using var data=JsonDocument.Parse(Data(state,false,""));if(data.RootElement.GetProperty("button").GetString()!=(state.Protected?"Отключить":"Подключить"))throw new Exception("Wrong widget action");}
  using var busy=JsonDocument.Parse(Data(new(true,true,false),true,""));if(busy.RootElement.GetProperty("enabled").GetBoolean())throw new Exception("Duplicate widget actions enabled");
 }
}
