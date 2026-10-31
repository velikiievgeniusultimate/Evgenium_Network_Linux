using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shell;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

// The engine and PowerShell operation contract are unchanged. All application
// visuals now live in a retained WPF tree: no GDI child windows, pixel anchors,
// native combo boxes or WinForms scrollbars participate in page layout.
public sealed class EvgeniumDesktop : Window, IDisposable {
 public event Action<string,string> Operation;
 public bool Busy, TokenEditing, Refreshing, AllowExit;
 public bool IsDisposed {get;private set;}
 public bool Visible {get{return IsVisible;}}
 public string LastReport="";
 private string lastError="",category="";
 private readonly JavaScriptSerializer json=new JavaScriptSerializer();
 private readonly Border visual;
 private readonly StackPanel cards,navigation;
 private readonly TextBlock pageTitle,breadcrumb,sideStatus;
 private readonly CheckBox startup;
 private readonly Forms.NotifyIcon tray=new Forms.NotifyIcon();
 private readonly List<Button> navButtons=new List<Button>();
 private Dictionary<string,object> snapshot=new Dictionary<string,object>(),policy=new Dictionary<string,object>();
 private object[] apps=new object[0];
 private int page;
 private bool editingName,showBaseValue;
 private TextBox tokenInput,nameInput,exceptionInput;
 private TextBlock statusText,deviceName,tokenHint,connectionTitle,resultText;
 private Button tokenSave,deviceSave,toggle;
 private ComboBox route,running,protocol,direction;
 private StackPanel deviceCard,exceptions,baseRules;
 private CheckBox showBase;
 private static readonly Brush Bg=BrushOf("#141217"),Surface=BrushOf("#211c24"),Accent=BrushOf("#ff586d"),Muted=BrushOf("#baa8af"),Main=BrushOf("#fff1e9"),BorderBrushColor=BrushOf("#48303c");
 public EvgeniumDesktop(){
  Title="Evgenium Network";Width=1040;Height=740;MinWidth=860;MinHeight=580;Background=Bg;Foreground=Main;FontFamily=new FontFamily("Segoe UI");FontSize=13;WindowStartupLocation=WindowStartupLocation.CenterScreen;
  WindowStyle=WindowStyle.None;ResizeMode=ResizeMode.CanResize;UseLayoutRounding=true;SnapsToDevicePixels=true;
  WindowChrome.SetWindowChrome(this,new WindowChrome{CaptionHeight=38,ResizeBorderThickness=new Thickness(6),GlassFrameThickness=new Thickness(0),CornerRadius=new CornerRadius(8),UseAeroCaptionButtons=false});
  using(var stream=Resource("Desktop.xaml"))visual=(Border)XamlReader.Load(stream);Content=visual;
  cards=Find<StackPanel>("cards");navigation=Find<StackPanel>("navigation");pageTitle=Find<TextBlock>("pageTitle");breadcrumb=Find<TextBlock>("breadcrumb");sideStatus=Find<TextBlock>("sideStatus");startup=Find<CheckBox>("startupOption");
  using(var stream=Resource("app-256.png")){var image=new BitmapImage();image.BeginInit();image.CacheOption=BitmapCacheOption.OnLoad;image.StreamSource=stream;image.EndInit();image.Freeze();Icon=image;Find<Image>("brandMark").Source=image;}
  Find<TextBlock>("versionLabel").Text="Windows "+Assembly.GetExecutingAssembly().GetName().Version.ToString(3);
  Find<Button>("closeWindow").Click+=(s,e)=>Close();Find<Button>("minimizeWindow").Click+=(s,e)=>WindowState=WindowState.Minimized;
  startup.Checked+=(s,e)=>OptionChanged();startup.Unchecked+=(s,e)=>OptionChanged();
  string[] labels={"VPN","Приложения","Сайты и IP","Порты","DNS"},badges={"VPN","APP","NET","PRT","DNS"};
  for(int i=0;i<labels.Length;i++){
   int index=i;var row=new Grid();row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(28)});row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});
   var badge=new Border{Background=BrushOf("#302330"),CornerRadius=new CornerRadius(3),Height=28,Child=new TextBlock{Text=badges[i],FontSize=10,FontWeight=FontWeights.Bold,HorizontalAlignment=HorizontalAlignment.Center}};row.Children.Add(badge);
   var label=Text(labels[i],14);label.Margin=new Thickness(11,0,0,0);Grid.SetColumn(label,1);row.Children.Add(label);
   var button=new Button{Content=row,Height=48,Margin=new Thickness(0,0,0,4),Padding=new Thickness(12,0,12,0),BorderThickness=new Thickness(0),HorizontalContentAlignment=HorizontalAlignment.Stretch,Tag=badge};button.Click+=(s,e)=>Navigate(index);System.Windows.Automation.AutomationProperties.SetName(button,labels[i]);navigation.Children.Add(button);navButtons.Add(button);
  }
  var menu=new Forms.ContextMenuStrip();menu.Items.Add("Открыть Evgenium",null,(s,e)=>OpenMain());menu.Items.Add("Подключить / отключить",null,(s,e)=>Send("toggle",null));menu.Items.Add(new Forms.ToolStripSeparator());menu.Items.Add("Закрыть приложение",null,(s,e)=>ExitApplication());
  using(var stream=Resource("Evgenium.ico"))tray.Icon=new System.Drawing.Icon(stream);tray.Text="Evgenium Network";tray.ContextMenuStrip=menu;tray.Visible=true;tray.DoubleClick+=(s,e)=>OpenMain();
  Closing+=(s,e)=>{if(!AllowExit){e.Cancel=true;Hide();}};Closed+=(s,e)=>{IsDisposed=true;tray.Dispose();};
  SourceInitialized+=(s,e)=>InitializeChrome();Navigate(0);
 }
 private static Stream Resource(string name){return Assembly.GetExecutingAssembly().GetManifestResourceStream("Evgenium."+name);}
 private T Find<T>(string name) where T:FrameworkElement{return (T)visual.FindName(name);}
 public FrameworkElement FindVisual(string name){return (FrameworkElement)visual.FindName(name);}
 private static Brush BrushOf(string value){var b=(SolidColorBrush)new BrushConverter().ConvertFromString(value);b.Freeze();return b;}
 private static TextBlock Text(string text,double size){return new TextBlock{Text=text,FontSize=size,TextWrapping=TextWrapping.Wrap,Foreground=Main,VerticalAlignment=VerticalAlignment.Center};}
 private static void Accessible(DependencyObject c,string name){System.Windows.Automation.AutomationProperties.SetName(c,name);}
 private Button Button(string label,Action action,bool primary){var b=new Button{Content=label,Margin=new Thickness(0,0,12,0)};if(primary){b.Background=Accent;b.Foreground=BrushOf("#180d13");b.BorderThickness=new Thickness(0);b.FontWeight=FontWeights.SemiBold;}b.Click+=(s,e)=>action();Accessible(b,label);return b;}
 private StackPanel Card(string title){var content=new StackPanel();if(title!="")content.Children.Add(new TextBlock{Text=title,FontSize=15,FontWeight=FontWeights.SemiBold,Foreground=Main,Margin=new Thickness(0,0,0,14),TextWrapping=TextWrapping.Wrap});cards.Children.Add(new Border{Background=Surface,BorderBrush=BorderBrushColor,BorderThickness=new Thickness(1),CornerRadius=new CornerRadius(7),Padding=new Thickness(18),Margin=new Thickness(0,0,0,16),Child=content});return content;}
 private static Grid Pair(FrameworkElement field,FrameworkElement action){var row=new Grid();row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});row.ColumnDefinitions.Add(new ColumnDefinition{Width=GridLength.Auto});field.Margin=new Thickness(0,0,12,0);action.Margin=new Thickness(0);row.Children.Add(field);row.Children.Add(action);Grid.SetColumn(action,1);return row;}
 private static TextBox Input(string label){var t=new TextBox{MinWidth=0,Tag=label=="Токен клиента"?"Введите токен":label};Accessible(t,label);return t;}
 private WrapPanel Actions(params Button[] buttons){var row=new WrapPanel();foreach(var b in buttons){b.Margin=new Thickness(0,0,12,8);row.Children.Add(b);}return row;}
 private void OptionChanged(){if(!Refreshing)Send("option",new{name="startup",value=startup.IsChecked==true});}
 private void Send(string action,object payload){if(Busy&&action!="option")return;var handler=Operation;if(handler!=null)handler(action,payload==null?"{}":json.Serialize(payload));}
 public void Navigate(int index){
  page=index;bool previous=Refreshing;Refreshing=true;
  try{
   cards.Children.Clear();deviceCard=null;statusText=null;connectionTitle=null;tokenInput=null;nameInput=null;tokenHint=null;tokenSave=null;deviceSave=null;route=null;toggle=null;resultText=null;exceptions=null;baseRules=null;
   for(int i=0;i<navButtons.Count;i++){bool selected=i==page;navButtons[i].Background=selected?BrushOf("#3a202d"):Brushes.Transparent;((Border)navButtons[i].Tag).Background=selected?Accent:BrushOf("#302330");}
   pageTitle.Text=new[]{"Ваш VPN","Исключения приложений","Сайты и IP","Исключения портов","DNS"}[page];breadcrumb.Text="EVGENIUM  /  "+new[]{"ПОДКЛЮЧЕНИЕ","ПРИЛОЖЕНИЯ","САЙТЫ И IP","ПОРТЫ","DNS"}[page];
   statusText=Text("",13);statusText.Foreground=Muted;Card("").Children.Add(statusText);
   if(page==0)BuildVpn();else BuildExceptions();ApplySnapshot();Find<ScrollViewer>("pageScroll").ScrollToTop();
  }finally{Refreshing=previous;}
  if(Operation!=null)Send("refresh",null);
 }
 private void BuildVpn(){
  deviceCard=Card("Ваше устройство");deviceName=Text("",16);deviceName.FontWeight=FontWeights.SemiBold;nameInput=Input("Имя устройства");nameInput.Text=TextOf(snapshot,"device_name");nameInput.MaxLength=64;
  var nameField=new Grid();nameField.Children.Add(deviceName);nameField.Children.Add(nameInput);deviceSave=Button(editingName?"Сохранить":"Изменить имя",()=>{if(editingName)Send("rename",new{name=nameInput.Text});else{editingName=true;nameInput.Text=deviceName.Text;ApplySnapshot();nameInput.Focus();}},false);deviceCard.Children.Add(Pair(nameField,deviceSave));
  var connect=Card("");connectionTitle=Text("VPN отключён",22);connectionTitle.FontWeight=FontWeights.SemiBold;connect.Children.Add(connectionTitle);var path=Text("Компьютер → HSVDS → Эстония",13);path.Foreground=Muted;path.Margin=new Thickness(0,10,0,20);connect.Children.Add(path);
  toggle=Button("Подключить",()=>Send("toggle",null),true);toggle.MinWidth=160;connect.Children.Add(Actions(toggle,Button("Восстановить",()=>Send("repair",null),false)));
  var help=Text("Весь трафик идёт через VPN, кроме включённых исключений. При обрыве защищённые подключения блокируются.",13);help.Foreground=Muted;help.Margin=new Thickness(0,10,0,0);connect.Children.Add(help);
  var token=Card("Токен клиента");tokenInput=Input("Токен клиента");tokenInput.MaxLength=48;tokenHint=Text("Токен сохранён на этом устройстве",13);tokenHint.Foreground=Muted;
  var tokenField=new Grid();tokenField.Children.Add(tokenInput);tokenField.Children.Add(tokenHint);tokenSave=Button("Подтвердить",()=>{if(!TokenEditing&&BoolOf(snapshot,"has_token"))Send("token-edit",null);else Send("token-save",new{token=tokenInput.Text});},false);token.Children.Add(Pair(tokenField,tokenSave));
  var routes=Card("Маршрут");route=new ComboBox();Accessible(route,"Маршрут VPN");route.SelectionChanged+=(s,e)=>{if(!Refreshing&&route.SelectedItem is RouteItem)Send("route",new{value=((RouteItem)route.SelectedItem).ID});};routes.Children.Add(route);
  Card("").Children.Add(Actions(Button("Полная диагностика",()=>Send("diagnostic",null),false),Button("Проверить обновления",()=>Send("update",null),false)));
  resultText=Text("",13);resultText.Foreground=Muted;Card("Результат").Children.Add(resultText);
 }
 private void BuildExceptions(){
  category=new[]{"","applications","networks","ports","dns"}[page];
  string[] descriptions={"","Выбранные приложения подключаются напрямую. Остальные используют VPN.","Добавьте домен, адрес или подсеть. Домены включают поддомены; знак = задаёт точное совпадение.","Исходящие — подключения к порту. Входящие — прямые ответы вашего сервера. Оба — оба направления.","Обычный DNS остаётся в VPN. Добавленные DNS-серверы получают запросы напрямую и могут видеть запрашиваемые имена."};
  var entry=Card("Новое исключение");var help=Text(descriptions[page],13);help.Foreground=Muted;help.Margin=new Thickness(0,0,0,16);entry.Children.Add(help);exceptionInput=Input("Новое исключение");
  entry.Children.Add(Pair(exceptionInput,Button("Добавить",()=>{string value=exceptionInput.Text.Trim();if(page==3)value=protocol.SelectedItem.ToString().ToLower()+":"+value+":"+new[]{"out","in","both"}[Math.Max(0,direction.SelectedIndex)];Send("add",new{category=category,value=value});},true)));
  if(page==3){var row=new Grid{Margin=new Thickness(0,12,0,0)};row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});row.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(2,GridUnitType.Star)});protocol=new ComboBox{Margin=new Thickness(0,0,12,0)};foreach(string p in new[]{"TCP","UDP","BOTH"})protocol.Items.Add(p);protocol.SelectedIndex=0;Accessible(protocol,"Протокол");direction=new ComboBox();foreach(string d in new[]{"Исходящие","Входящие","Оба"})direction.Items.Add(d);direction.SelectedIndex=0;Accessible(direction,"Направление");row.Children.Add(protocol);row.Children.Add(direction);Grid.SetColumn(direction,1);entry.Children.Add(row);}
  exceptions=Card("Ваши исключения");
  var bases=Card("");showBase=new CheckBox{Content="Отобразить базовые исключения",IsChecked=showBaseValue};bases.Children.Add(showBase);baseRules=new StackPanel{Margin=new Thickness(0,10,0,0),Visibility=showBaseValue?Visibility.Visible:Visibility.Collapsed};bases.Children.Add(baseRules);showBase.Checked+=(s,e)=>{showBaseValue=true;baseRules.Visibility=Visibility.Visible;};showBase.Unchecked+=(s,e)=>{showBaseValue=false;baseRules.Visibility=Visibility.Collapsed;};
  if(page==1){var processes=Card("Запущены сейчас");running=new ComboBox();Accessible(running,"Запущенные приложения");FillApps();processes.Children.Add(Pair(running,Button("В обход",()=>{var item=running.SelectedItem as AppItem;if(item!=null)Send("add",new{category="applications",value=item.Path});},false)));var actions=Actions(Button("Выбрать .exe…",()=>{using(var dialog=new Forms.OpenFileDialog{Filter="Приложения (*.exe)|*.exe",CheckFileExists=true})if(dialog.ShowDialog()==Forms.DialogResult.OK)Send("add",new{category="applications",value=dialog.FileName});},false),Button("Обновить список",()=>Send("running",null),false));actions.Margin=new Thickness(0,12,0,0);processes.Children.Add(actions);}
  FillPolicyList();
 }
 private void FillPolicyList(){
  if(exceptions==null)return;exceptions.Children.Clear(); // Preserve the card heading when rebuilding.
  var heading=Text("Ваши исключения",15);heading.FontWeight=FontWeights.SemiBold;heading.Margin=new Thickness(0,0,0,14);exceptions.Children.Add(heading);
  object value;object[] list=policy.TryGetValue(category,out value)?AsArray(value):new object[0];
  foreach(var item in list){string text=Convert.ToString(item);var label=Text(text,13);label.ToolTip=text;var row=Pair(label,Button("Удалить",()=>Send("remove",new{category=category,value=text}),false));row.Margin=new Thickness(0,0,0,10);exceptions.Children.Add(row);}
  if(list.Length==0){var empty=Text("Ваших исключений пока нет",13);empty.Foreground=Muted;exceptions.Children.Add(empty);}
  baseRules.Children.Clear();string[,] bases=category=="networks"?new string[,]{{"networks:lan","Устройства текущей локальной сети"},{"networks:linklocal","Устройства с локальным автоматическим адресом"}}:category=="ports"?new string[,]{{"ports:discovery","Обнаружение устройств: mDNS, SSDP, LLMNR"}}:category=="dns"?new string[,]{{"dns:stub","Локальные DNS-приложения (127.0.0.0/8)"}}:new string[0,2];
  var disabled=new HashSet<string>();if(policy.TryGetValue("disabled_base",out value))foreach(var x in AsArray(value))disabled.Add(Convert.ToString(x));
  for(int i=0;i<bases.GetLength(0);i++){string id=bases[i,0];var check=new CheckBox{Content=Text(bases[i,1],13),IsChecked=!disabled.Contains(id),Margin=new Thickness(0,4,0,4)};check.Checked+=(s,e)=>{if(!Refreshing)Send("base",new{value=id,enabled=true});};check.Unchecked+=(s,e)=>{if(!Refreshing)Send("base",new{value=id,enabled=false});};baseRules.Children.Add(check);}
  if(bases.GetLength(0)==0){var empty=Text("Базовых исключений приложений нет",13);empty.Foreground=Muted;baseRules.Children.Add(empty);}
 }
 private static object[] AsArray(object v){return v as object[]??new object[0];}
 private static Dictionary<string,object> Map(object v){return v as Dictionary<string,object>??new Dictionary<string,object>();}
 private static string TextOf(Dictionary<string,object> v,string k,string fallback=""){object x;return v.TryGetValue(k,out x)&&x!=null?Convert.ToString(x):fallback;}
 private static bool BoolOf(Dictionary<string,object> v,string k){object x;return v.TryGetValue(k,out x)&&x is bool&&(bool)x;}
 private static void ShowElement(UIElement element,bool visible){if(element!=null)element.Visibility=visible?Visibility.Visible:Visibility.Collapsed;}
 public void SetSnapshot(string text){snapshot=Map(json.DeserializeObject(text));policy=Map(snapshot.ContainsKey("policy")?snapshot["policy"]:null);bool previous=Refreshing;Refreshing=true;try{ApplySnapshot();}finally{Refreshing=previous;}}
 private void ApplySnapshot(){
  var engine=Map(snapshot.ContainsKey("engine")?snapshot["engine"]:null);var options=Map(snapshot.ContainsKey("options")?snapshot["options"]:null);bool active=BoolOf(snapshot,"running"),connected=active&&TextOf(engine,"state")=="connected";
  startup.IsChecked=BoolOf(options,"startup");sideStatus.Text=connected?"● Подключено":active?"◌ Подключение":"○ Отключено";sideStatus.Foreground=connected?BrushOf("#a6d8c2"):Muted;
  if(statusText!=null&&!Busy){statusText.Text=lastError!=""?lastError:TextOf(engine,"message","VPN отключён.");statusText.Foreground=lastError!=""?BrushOf("#ffad9e"):Muted;}
  if(page!=0||connectionTitle==null)return;
  connectionTitle.Text=connected?"Подключено через Эстонию":active?"Подключение и восстановление…":"VPN отключён";connectionTitle.Foreground=connected?BrushOf("#a6d8c2"):Main;toggle.Content=active||BoolOf(engine,"protected")?"Отключить":"Подключить";
  bool saved=BoolOf(snapshot,"has_token");ShowElement((UIElement)VisualTreeHelper.GetParent(deviceCard),saved);deviceName.Text=TextOf(snapshot,"device_name","Имя появится после ввода токена");ShowElement(deviceName,!editingName);ShowElement(nameInput,editingName);deviceSave.Content=editingName?"Сохранить":"Изменить имя";
  if(!saved)TokenEditing=true;ShowElement(tokenInput,TokenEditing||!saved);ShowElement(tokenHint,saved&&!TokenEditing);tokenSave.Content=saved&&!TokenEditing?"Изменить":"Подтвердить";
  if(snapshot.ContainsKey("routes")){
   string selected=TextOf(policy,"route","auto");string key=selected+json.Serialize(snapshot["routes"]);
   if((string)route.Tag!=key){route.Items.Clear();route.Items.Add(new RouteItem{ID="auto",Label="Автоматически · рейтинг и восстановление"});foreach(var v in AsArray(snapshot["routes"])){var r=Map(v);route.Items.Add(new RouteItem{ID=TextOf(r,"id"),Label=TextOf(r,"label")});}for(int i=0;i<route.Items.Count;i++)if(((RouteItem)route.Items[i]).ID==selected)route.SelectedIndex=i;route.Tag=key;}
  }
  var lines=new List<string>();object ranking;if(engine.TryGetValue("ranking",out ranking))foreach(var v in AsArray(ranking)){var r=Map(v);lines.Add(TextOf(r,"label")+" · "+TextOf(r,"download_mbps","0")+" Мбит/с · сбоев "+TextOf(r,"losses","0")+"/3");}if(LastReport!="")lines.Add(LastReport);resultText.Text=lines.Count>0?String.Join("\n",lines.ToArray()):"После подключения здесь появятся результаты выбора маршрута.";
 }
 public void SetTokenEditing(string token){TokenEditing=true;if(page!=0)Navigate(0);tokenInput.Text=token;ShowElement(tokenInput,true);ShowElement(tokenHint,false);tokenSave.Content="Подтвердить";tokenInput.Focus();}
 public void SavedToken(){TokenEditing=false;if(tokenInput!=null)tokenInput.Clear();}
 public void SavedName(){editingName=false;ApplySnapshot();}
 public void RefreshPolicy(){bool previous=Refreshing;Refreshing=true;try{if(page>0)FillPolicyList();if(exceptionInput!=null)exceptionInput.Clear();}finally{Refreshing=previous;}}
 public void SetApps(string text){apps=AsArray(json.DeserializeObject(text));FillApps();}
 private void FillApps(){if(running==null)return;running.Items.Clear();foreach(var v in apps){var a=Map(v);running.Items.Add(new AppItem{Name=TextOf(a,"name"),Path=TextOf(a,"exe")});}if(running.Items.Count>0)running.SelectedIndex=0;}
 public void SetError(string message){lastError=message;if(statusText!=null){statusText.Text=message;statusText.Foreground=BrushOf("#ffad9e");}if(!IsVisible)tray.ShowBalloonTip(5000,"Evgenium",message,Forms.ToolTipIcon.Warning);}
 public void SetBusy(bool value){Busy=value;cards.IsEnabled=!value;navigation.IsEnabled=!value;startup.IsEnabled=!value;if(value){lastError="";if(statusText!=null)statusText.Text="Выполняется… Подтвердите запрос Windows, если он появится.";}else ApplySnapshot();}
 public void OpenMain(){Show();WindowState=WindowState.Normal;Activate();}
 public void ExitApplication(){AllowExit=true;Close();}
 public void Dispose(){if(!IsDisposed){AllowExit=true;Close();}tray.Dispose();}
 public static void PumpEvents(){var frame=new DispatcherFrame();Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background,new Action(()=>frame.Continue=false));Dispatcher.PushFrame(frame);}
 public void SavePreview(string path){SavePreviewAtDpi(path,96);}
 public void SavePreviewAtDpi(string path,double dpi){UpdateLayout();PumpEvents();var bitmap=new RenderTargetBitmap((int)Math.Ceiling(ActualWidth*dpi/96),(int)Math.Ceiling(ActualHeight*dpi/96),dpi,dpi,PixelFormats.Pbgra32);bitmap.Render(visual);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using(var file=File.Create(path))encoder.Save(file);}
 // Layout regression checks cover content measurement, not only window bounds.
 // WPF uses DIPs; separate 96/120/144/192-DPI renders check rasterization.
 // Actual monitor transitions still require a physical multi-monitor test.
 public void ValidateLayout(double scale){
  UpdateLayout();PumpEvents();
  var scroll=Find<ScrollViewer>("pageScroll");if(scroll.ScrollableWidth>1)throw new Exception("Horizontal overflow on page "+page);
  foreach(var child in cards.Children){var card=(FrameworkElement)child;if(card.ActualWidth>cards.ActualWidth+1)throw new Exception("Card exceeds viewport");}
  ValidateChildren(visual);var close=Find<Button>("closeWindow");var min=Find<Button>("minimizeWindow");var a=min.TransformToAncestor(visual).Transform(new Point(min.ActualWidth,0));var b=close.TransformToAncestor(visual).Transform(new Point(0,0));if(a.X>b.X+1)throw new Exception("Caption buttons overlap");
 }
 private static void ValidateChildren(DependencyObject node){for(int i=0;i<VisualTreeHelper.GetChildrenCount(node);i++){var c=VisualTreeHelper.GetChild(node,i);var f=c as FrameworkElement;var parent=node as FrameworkElement;if(f!=null&&parent!=null&&f.Visibility==Visibility.Visible&&f is Button&&parent is Grid&&f.ActualWidth>parent.ActualWidth+1)throw new Exception("Button exceeds its row");ValidateChildren(c);}}
 [DllImport("user32.dll")]private static extern IntPtr SendMessage(IntPtr h,int msg,IntPtr w,IntPtr l);
 public void ValidateChrome(){var h=new WindowInteropHelper(this).Handle;if((GetWindowLong(h,-16)&0x10000)!=0)throw new Exception("Native maximize is enabled");foreach(var point in new[]{new Point(1,1),new Point(ActualWidth-2,1),new Point(1,ActualHeight-2),new Point(ActualWidth-2,ActualHeight-2)}){var p=PointToScreen(point);int expected=point.Y<3?(point.X<3?13:14):(point.X<3?16:17);long xy=((long)(ushort)(int)p.Y<<16)|(ushort)(int)p.X;if(SendMessage(h,0x84,IntPtr.Zero,(IntPtr)xy).ToInt32()!=expected)throw new Exception("Native corner sizing failed");}}
 [DllImport("user32.dll")]private static extern int GetWindowLong(IntPtr h,int index);
 [DllImport("user32.dll")]private static extern int SetWindowLong(IntPtr h,int index,int value);
 [DllImport("dwmapi.dll")]private static extern int DwmSetWindowAttribute(IntPtr h,int attribute,ref int value,int size);
 private void InitializeChrome(){var h=new WindowInteropHelper(this).Handle;SetWindowLong(h,-16,GetWindowLong(h,-16)&~0x00010000);HwndSource.FromHwnd(h).AddHook(WindowHook);try{int dark=1,round=2,none=unchecked((int)0xfffffffe);DwmSetWindowAttribute(h,20,ref dark,4);DwmSetWindowAttribute(h,33,ref round,4);DwmSetWindowAttribute(h,34,ref none,4);}catch(DllNotFoundException){}catch(EntryPointNotFoundException){} }
 private IntPtr WindowHook(IntPtr h,int msg,IntPtr w,IntPtr l,ref bool handled){if(msg==0xA3||(msg==0x112&&(w.ToInt64()&0xfff0)==0xf030)){handled=true;return IntPtr.Zero;}return IntPtr.Zero;}
 private sealed class RouteItem{public string ID,Label;public override string ToString(){return Label;}}
 private sealed class AppItem{public string Name,Path;public override string ToString(){return Name+" — "+Path;}}
}
