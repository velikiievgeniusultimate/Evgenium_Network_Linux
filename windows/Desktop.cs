using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Windows.Forms;

public sealed class EvgeniumDesktop : Form {
 public event Action<string,string> Operation;
 public readonly TextBox TokenInput=new TextBox(), NameInput=new TextBox();
 public readonly Label StatusText=new Label();
 public bool Busy, TokenEditing, Refreshing, AllowExit;
 public string LastReport=""; private string LastError="";
 private readonly JavaScriptSerializer json=new JavaScriptSerializer();
 private readonly Color Bg=Color.FromArgb(20,18,23),Surface=Color.FromArgb(33,28,36),Side=Color.FromArgb(25,21,28),Accent=Color.FromArgb(255,88,109),TextMain=Color.FromArgb(255,241,233),Muted=Color.FromArgb(186,168,175),Border=Color.FromArgb(72,48,60);
 private readonly Panel body=new Panel(),sidebar=new Panel(); private Panel deviceCard;
 private readonly FlowLayoutPanel cards=new FlowLayoutPanel();
 private readonly Label pageTitle=new Label(),deviceName=new Label(),connectionTitle=new Label(),tokenHint=new Label(),sideStatus=new Label();
 private readonly Button toggle=new Button(),tokenSave=new Button(),deviceSave=new Button();
 private readonly ComboBox route=new ComboBox();
 private readonly CheckBox widgetOption=new CheckBox(),startupOption=new CheckBox(),showBase=new CheckBox();
 private readonly TextBox exceptionInput=new TextBox();
 private readonly ComboBox protocol=new ComboBox(),direction=new ComboBox(),running=new ComboBox();
 private readonly FlowLayoutPanel exceptions=new FlowLayoutPanel(),baseRules=new FlowLayoutPanel();
 private readonly Label resultText=new Label();
 private readonly Form widget=new Form(); private readonly Button widgetToggle=new Button();private readonly Label widgetStatus=new Label();
 private readonly NotifyIcon tray=new NotifyIcon();
 private int page;private bool active,editingName;private string category="";private Dictionary<string,object> policy=new Dictionary<string,object>();private object[] apps=new object[0];
 [DllImport("user32.dll")] private static extern bool ReleaseCapture();
 [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr h,int msg,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr h);
 public EvgeniumDesktop() {
  Application.EnableVisualStyles(); Text="Evgenium Network";ClientSize=new Size(1040,700);MinimumSize=new Size(900,620);StartPosition=FormStartPosition.CenterScreen;BackColor=Bg;ForeColor=TextMain;Font=new Font("Segoe UI",10);AutoScaleMode=AutoScaleMode.Dpi;
  sidebar.Dock=DockStyle.Left;sidebar.Width=222;sidebar.BackColor=Side;Controls.Add(sidebar);
  var mark=new DrillMark {Location=new Point(18,18),Size=new Size(52,57)};sidebar.Controls.Add(mark);
  sidebar.Controls.Add(LabelAt("EVGENIUM",18,84,190,30,20,true,TextMain));sidebar.Controls.Add(LabelAt("N E T W O R K",18,116,190,20,9,false,Muted));
  string[] labels={"VPN","Приложения","Сайты и IP","Порты","DNS"},badges={"VPN","APP","NET","PRT","DNS"};
  for(int i=0;i<labels.Length;i++){int index=i;var b=ButtonAt(badges[i]+"    "+labels[i],16,166+i*51,190,44,false);b.TextAlign=ContentAlignment.MiddleLeft;b.Click+=(s,e)=>{page=index;ShowPage();};sidebar.Controls.Add(b);}
  widgetOption.Text="Виджет";widgetOption.SetBounds(18,500,190,28);widgetOption.ForeColor=Muted;widgetOption.Anchor=AnchorStyles.Bottom|AnchorStyles.Left;widgetOption.Top=ClientSize.Height-156;sidebar.Controls.Add(widgetOption);widgetOption.CheckedChanged+=(s,e)=>{if(!Refreshing)Send("option",new {name="widget",value=widgetOption.Checked});ShowWidget(widgetOption.Checked);};
  startupOption.Text="Запускать с Windows";startupOption.SetBounds(18,532,190,28);startupOption.ForeColor=Muted;startupOption.Anchor=AnchorStyles.Bottom|AnchorStyles.Left;startupOption.Top=ClientSize.Height-124;sidebar.Controls.Add(startupOption);startupOption.CheckedChanged+=(s,e)=>{if(!Refreshing)Send("option",new{name="startup",value=startupOption.Checked});};
  sideStatus.SetBounds(18,ClientSize.Height-73,190,26);sideStatus.Anchor=AnchorStyles.Bottom|AnchorStyles.Left;sideStatus.ForeColor=Muted;sidebar.Controls.Add(sideStatus);
  sidebar.Controls.Add(LabelAt("Windows 0.2.0",18,ClientSize.Height-42,190,24,9,false,Muted,AnchorStyles.Bottom|AnchorStyles.Left));
  body.Dock=DockStyle.Fill;body.Padding=new Padding(28);Controls.Add(body);body.BringToFront();
  var top=new Panel {Dock=DockStyle.Top,Height=76};top.Controls.Add(LabelAt("EVGENIUM  /  ПОДКЛЮЧЕНИЕ",0,0,600,18,8,false,Accent));pageTitle.SetBounds(0,26,680,45);pageTitle.Font=new Font(Font.FontFamily,24,FontStyle.Bold);pageTitle.ForeColor=TextMain;top.Controls.Add(pageTitle);body.Controls.Add(top);
  cards.Dock=DockStyle.Fill;cards.FlowDirection=FlowDirection.TopDown;cards.WrapContents=false;cards.AutoScroll=true;cards.Padding=new Padding(0,4,8,12);body.Controls.Add(cards);cards.BringToFront();cards.Resize+=(s,e)=>ResizeCards();
  StatusText.SetBounds(0,0,700,36);StatusText.ForeColor=Color.FromArgb(255,173,158);StatusText.AutoSize=false;StatusText.Text="";
  var menu=new ContextMenuStrip();menu.Items.Add("Открыть Evgenium",null,(s,e)=>OpenMain());menu.Items.Add("Подключить / отключить",null,(s,e)=>Send("toggle",null));menu.Items.Add("Виджет",null,(s,e)=>{widgetOption.Checked=!widgetOption.Checked;});menu.Items.Add(new ToolStripSeparator());menu.Items.Add("Закрыть приложение",null,(s,e)=>{AllowExit=true;Close();});
  using(var bmp=new Bitmap(32,32)){using(var g=Graphics.FromImage(bmp)){g.Clear(Side);DrillMark.PaintDrills(g,new Rectangle(1,1,30,30));}var handle=bmp.GetHicon();Icon=(Icon)System.Drawing.Icon.FromHandle(handle).Clone();DestroyIcon(handle);}
  tray.Icon=Icon;tray.Text="Evgenium Network";tray.ContextMenuStrip=menu;tray.Visible=true;tray.DoubleClick+=(s,e)=>OpenMain();
  widget.Text="Evgenium";widget.FormBorderStyle=FormBorderStyle.None;widget.ClientSize=new Size(286,80);widget.ShowInTaskbar=false;widget.TopMost=true;widget.BackColor=Surface;widget.StartPosition=FormStartPosition.Manual;widget.Location=new Point(Screen.PrimaryScreen.WorkingArea.Right-306,Screen.PrimaryScreen.WorkingArea.Bottom-100);widget.ForeColor=TextMain;widget.Font=Font;
  var wm=new DrillMark {Location=new Point(8,10),Size=new Size(36,50)};widget.Controls.Add(wm);var wh=LabelAt("EVGENIUM",52,9,122,23,10,true,TextMain);widget.Controls.Add(wh);widgetStatus.SetBounds(52,35,140,30);widgetStatus.ForeColor=Muted;widget.Controls.Add(widgetStatus);
  StyleButton(widgetToggle,true);widgetToggle.SetBounds(201,13,49,52);widgetToggle.Click+=(s,e)=>Send("toggle",null);widget.Controls.Add(widgetToggle);var gear=ButtonAt("⚙",251,15,30,48,false);gear.Click+=(s,e)=>OpenMain();widget.Controls.Add(gear);
  MouseEventHandler drag=(s,e)=>{if(e.Button==MouseButtons.Left){ReleaseCapture();SendMessage(widget.Handle,0xA1,(IntPtr)2,IntPtr.Zero);}};widget.MouseDown+=drag;wh.MouseDown+=drag;widgetStatus.MouseDown+=drag;
  widget.FormClosing+=(s,e)=>{if(!AllowExit){e.Cancel=true;widgetOption.Checked=false;widget.Hide();}};
  FormClosing+=(s,e)=>{if(!AllowExit&&e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}else{AllowExit=true;tray.Visible=false;widget.Close();}};
  ShowPage();
 }
 private Label LabelAt(string text,int x,int y,int w,int h,float size,bool bold,Color color,AnchorStyles anchor=AnchorStyles.Top|AnchorStyles.Left){return new Label{Text=text,Bounds=new Rectangle(x,y,w,h),Font=new Font(Font.FontFamily,size,bold?FontStyle.Bold:FontStyle.Regular),ForeColor=color,Anchor=anchor};}
 private void StyleButton(Button b,bool primary){b.FlatStyle=FlatStyle.Flat;b.FlatAppearance.BorderColor=Border;b.BackColor=primary?Accent:Color.FromArgb(41,32,43);b.ForeColor=primary?Color.FromArgb(24,13,19):TextMain;b.Cursor=Cursors.Hand;b.Font=new Font(Font.FontFamily,10,primary?FontStyle.Bold:FontStyle.Regular);}
 private Button ButtonAt(string text,int x,int y,int w,int h,bool primary){var b=new Button{Text=text,Bounds=new Rectangle(x,y,w,h)};StyleButton(b,primary);return b;}
 private Panel Card(int height){var p=new Panel{Size=new Size(700,height),BackColor=Surface,Margin=new Padding(0,0,0,16)};p.Paint+=(s,e)=>{using(var pen=new Pen(Border)){e.Graphics.DrawRectangle(pen,0,0,p.Width-1,p.Height-1);}};cards.Controls.Add(p);return p;}
 private void Send(string action,object payload){if(Busy&&action!="option")return;var handler=Operation;if(handler!=null)handler(action,payload==null?"{}":json.Serialize(payload));}
 private void Field(TextBox t,int x,int y,int w){t.SetBounds(x,y,w,30);t.BackColor=Color.FromArgb(24,19,27);t.ForeColor=TextMain;t.BorderStyle=BorderStyle.FixedSingle;}
 private void ResizeCards(){foreach(Control c in cards.Controls)c.Width=Math.Max(600,cards.ClientSize.Width-26);}
 private void FillPolicyList(){
  exceptions.Controls.Clear();baseRules.Controls.Clear();
  object value;object[] list=policy.TryGetValue(category,out value)?AsArray(value):new object[0];
  foreach(var item in list){string text=Convert.ToString(item);var row=new Panel{Width=650,Height=42};row.Controls.Add(LabelAt(text,0,10,520,28,10,false,TextMain));var del=ButtonAt("Удалить",540,0,95,34,false);del.Click+=(s,e)=>Send("remove",new{category=category,value=text});row.Controls.Add(del);exceptions.Controls.Add(row);}
  if(list.Length==0)exceptions.Controls.Add(LabelAt("Ваших исключений пока нет",0,0,600,30,10,false,Muted));
  string[,] bases=category=="networks"?new string[,]{{"networks:lan","Устройства текущей локальной сети"},{"networks:linklocal","Устройства с локальным автоматическим адресом"}}:category=="ports"?new string[,]{{"ports:discovery","Обнаружение устройств: mDNS, SSDP, LLMNR"}}:category=="dns"?new string[,]{{"dns:stub","Локальные DNS-приложения (127.0.0.0/8)"}}:new string[0,2];
  object disabled;var disabledList=new HashSet<string>();if(policy.TryGetValue("disabled_base",out disabled))foreach(var x in AsArray(disabled))disabledList.Add(Convert.ToString(x));
  for(int i=0;i<bases.GetLength(0);i++){string id=bases[i,0];var b=new CheckBox{Text=bases[i,1],Width=650,Height=35,ForeColor=TextMain,Checked=!disabledList.Contains(id)};b.CheckedChanged+=(s,e)=>{if(!Refreshing)Send("base",new{value=id,enabled=b.Checked});};baseRules.Controls.Add(b);}
  if(bases.GetLength(0)==0)baseRules.Controls.Add(LabelAt("Базовых исключений приложений нет",0,0,600,30,10,false,Muted));
 }
 private void ShowPage(){
  Refreshing=true;try{
   // Reused input controls must survive disposing their previous containers.
   foreach(Control reusable in new Control[]{StatusText,NameInput,deviceName,deviceSave,connectionTitle,toggle,route,TokenInput,tokenHint,tokenSave,exceptionInput,protocol,direction,running,exceptions,showBase,baseRules,resultText})if(reusable.Parent!=null)reusable.Parent.Controls.Remove(reusable);
   while(cards.Controls.Count>0)cards.Controls[0].Dispose();pageTitle.Text=new[]{"Ваш VPN","Исключения приложений","Сайты и IP","Исключения портов","DNS"}[page];
   var status=Card(44);StatusText.Dock=DockStyle.Fill;StatusText.Padding=new Padding(10,4,10,0);status.Controls.Add(StatusText);
   if(page==0){
    var device=Card(76);deviceCard=device;deviceName.SetBounds(18,18,480,38);deviceName.Font=new Font(Font.FontFamily,15,FontStyle.Bold);deviceName.ForeColor=TextMain;device.Controls.Add(deviceName);Field(NameInput,18,22,470);NameInput.Visible=editingName;device.Controls.Add(NameInput);deviceSave.Text=editingName?"Сохранить":"Изменить имя";StyleButton(deviceSave,false);deviceSave.SetBounds(510,18,150,38);deviceSave.Click-=NameClick;deviceSave.Click+=NameClick;device.Controls.Add(deviceSave);
    var connect=Card(226);connectionTitle.SetBounds(18,16,640,38);connectionTitle.Font=new Font(Font.FontFamily,18,FontStyle.Bold);connectionTitle.ForeColor=TextMain;connect.Controls.Add(connectionTitle);connect.Controls.Add(LabelAt("Компьютер → HSVDS → Эстония",18,58,640,24,10,false,Muted));
    StyleButton(toggle,true);toggle.SetBounds(18,94,176,43);toggle.Click-=ToggleClick;toggle.Click+=ToggleClick;connect.Controls.Add(toggle);var repair=ButtonAt("Восстановить",205,94,164,43,false);repair.Click+=(s,e)=>Send("repair",null);connect.Controls.Add(repair);
    connect.Controls.Add(LabelAt("Весь трафик идёт через VPN, кроме включённых исключений.\nПри обрыве защищённые подключения блокируются.",18,154,650,56,10,false,Muted));
    var token=Card(112);token.Controls.Add(LabelAt("Токен клиента",18,12,640,24,12,true,TextMain));Field(TokenInput,18,48,478);token.Controls.Add(TokenInput);tokenHint.SetBounds(18,51,470,30);tokenHint.ForeColor=Muted;token.Controls.Add(tokenHint);StyleButton(tokenSave,false);tokenSave.SetBounds(510,44,150,39);tokenSave.Click-=TokenClick;tokenSave.Click+=TokenClick;token.Controls.Add(tokenSave);
    var routes=Card(110);routes.Controls.Add(LabelAt("Маршрут",18,12,630,24,12,true,TextMain));route.DropDownStyle=ComboBoxStyle.DropDownList;route.SetBounds(18,49,642,34);route.SelectedIndexChanged-=RouteChanged;route.SelectedIndexChanged+=RouteChanged;routes.Controls.Add(route);
    var actions=Card(76);var diagnostic=ButtonAt("Полная диагностика",18,18,242,40,false);diagnostic.Click+=(s,e)=>Send("diagnostic",null);actions.Controls.Add(diagnostic);var update=ButtonAt("Проверить обновления",276,18,280,40,false);update.Click+=(s,e)=>Send("update",null);actions.Controls.Add(update);
    var result=Card(150);result.Controls.Add(LabelAt("Результат",18,12,600,24,12,true,TextMain));resultText.SetBounds(18,44,640,94);resultText.ForeColor=Muted;result.Controls.Add(resultText);
   }else{
    category=new[]{"","applications","networks","ports","dns"}[page];
    var descriptions=new[]{"","Выбранные приложения подключаются напрямую. Остальные используют VPN.","Добавьте домен, адрес или подсеть. Домены включают поддомены; знак = задаёт точное совпадение.","Исходящие — подключения к порту. Входящие — прямые ответы вашего сервера. Оба — оба направления.","Обычный DNS остаётся в VPN. Добавленные DNS-серверы получают запросы напрямую и могут видеть запрашиваемые имена."};
    var entry=Card(page==3?162:124);entry.Controls.Add(LabelAt(descriptions[page],18,14,640,54,10,false,Muted));Field(exceptionInput,18,77,page==3?260:478);entry.Controls.Add(exceptionInput);var add=ButtonAt("Добавить",510,72,150,38,true);add.Click+=(s,e)=>{string text=exceptionInput.Text.Trim();if(page==3)text=protocol.Text.ToLower()+":"+text+":"+new[]{"out","in","both"}[Math.Max(0,direction.SelectedIndex)];Send("add",new{category=category,value=text});};entry.Controls.Add(add);
    if(page==3){protocol.Items.Clear();protocol.Items.AddRange(new object[]{"TCP","UDP","BOTH"});protocol.SelectedIndex=0;protocol.DropDownStyle=ComboBoxStyle.DropDownList;protocol.SetBounds(18,119,100,30);entry.Controls.Add(protocol);direction.Items.Clear();direction.Items.AddRange(new object[]{"Исходящие","Входящие","Оба"});direction.SelectedIndex=0;direction.DropDownStyle=ComboBoxStyle.DropDownList;direction.SetBounds(132,119,210,30);entry.Controls.Add(direction);}
    exceptions.FlowDirection=FlowDirection.TopDown;exceptions.WrapContents=false;exceptions.AutoSize=true;exceptions.Padding=new Padding(18);var list=Card(160);exceptions.Dock=DockStyle.Fill;exceptions.AutoScroll=true;list.Controls.Add(exceptions);
    showBase.Text="Отобразить базовые исключения";showBase.SetBounds(0,0,650,38);showBase.ForeColor=Muted;showBase.CheckedChanged-=ShowBaseChanged;showBase.CheckedChanged+=ShowBaseChanged;var baseCard=Card(180);showBase.SetBounds(18,12,640,30);baseCard.Controls.Add(showBase);baseRules.SetBounds(18,48,640,120);baseRules.FlowDirection=FlowDirection.TopDown;baseRules.WrapContents=false;baseRules.Visible=showBase.Checked;baseCard.Controls.Add(baseRules);
    if(page==1){var processes=Card(120);processes.Controls.Add(LabelAt("Запущены сейчас",18,12,640,25,12,true,TextMain));running.SetBounds(18,48,478,30);running.DropDownStyle=ComboBoxStyle.DropDown;running.AutoCompleteMode=AutoCompleteMode.SuggestAppend;running.AutoCompleteSource=AutoCompleteSource.ListItems;processes.Controls.Add(running);var pick=ButtonAt("В обход",510,44,150,38,false);pick.Click+=(s,e)=>{var item=running.SelectedItem as AppItem;if(item!=null)Send("add",new{category="applications",value=item.Path});};processes.Controls.Add(pick);var browse=ButtonAt("Выбрать .exe…",18,82,180,30,false);browse.Click+=(s,e)=>{using(var dialog=new OpenFileDialog{Filter="Приложения (*.exe)|*.exe",CheckFileExists=true})if(dialog.ShowDialog(this)==DialogResult.OK)Send("add",new{category="applications",value=dialog.FileName});};processes.Controls.Add(browse);var refresh=ButtonAt("Обновить список",220,82,200,30,false);refresh.Click+=(s,e)=>Send("running",null);processes.Controls.Add(refresh);FillApps();}
    FillPolicyList();
   }
   ResizeCards();
  }finally{Refreshing=false;}
  if(Operation!=null)Send("refresh",null);
 }
 private void ToggleClick(object s,EventArgs e){Send("toggle",null);}
 private void TokenClick(object s,EventArgs e){if(!TokenEditing)Send("token-edit",null);else Send("token-save",new{token=TokenInput.Text});}
 private void NameClick(object s,EventArgs e){if(!editingName){editingName=true;NameInput.Text=deviceName.Text;ShowPage();}else Send("rename",new{name=NameInput.Text});}
 private void RouteChanged(object s,EventArgs e){if(!Refreshing&&route.SelectedItem is RouteItem)Send("route",new{value=((RouteItem)route.SelectedItem).ID});}
 private void ShowBaseChanged(object s,EventArgs e){baseRules.Visible=showBase.Checked;}
 private static object[] AsArray(object v){return v as object[]??new object[0];}
 private static Dictionary<string,object> Map(object v){return v as Dictionary<string,object>??new Dictionary<string,object>();}
 private static string TextOf(Dictionary<string,object> v,string k,string fallback=""){object x;return v.TryGetValue(k,out x)&&x!=null?Convert.ToString(x):fallback;}
 private static bool BoolOf(Dictionary<string,object> v,string k){object x;return v.TryGetValue(k,out x)&&x is bool&&(bool)x;}
 public void SetSnapshot(string text){
  var state=Map(json.DeserializeObject(text));var engine=Map(state.ContainsKey("engine")?state["engine"]:null);var options=Map(state.ContainsKey("options")?state["options"]:null);policy=Map(state.ContainsKey("policy")?state["policy"]:null);active=BoolOf(state,"running");
  Refreshing=true;try{
   widgetOption.Checked=BoolOf(options,"widget");startupOption.Checked=BoolOf(options,"startup");
   string label=TextOf(engine,"message","VPN отключён.");string engineState=TextOf(engine,"state");bool connected=active&&engineState=="connected";
   connectionTitle.Text=connected?"Подключено через Эстонию":active?"Подключение и восстановление…":"VPN отключён";connectionTitle.ForeColor=connected?Color.FromArgb(166,216,194):TextMain;
   toggle.Text=active||BoolOf(engine,"protected")?"Отключить":"Подключить";widgetToggle.Text=active||BoolOf(engine,"protected")?"ВЫКЛ":"ВКЛ";widgetStatus.Text=connected?"● Подключено":active?"◌ Подключение":"○ Отключено";sideStatus.Text=widgetStatus.Text;
   if(!Busy)StatusText.Text=LastError!=""?LastError:label;
   deviceName.Text=TextOf(state,"device_name","Имя появится после ввода токена");deviceName.Visible=!editingName;
   bool saved=BoolOf(state,"has_token");if(deviceCard!=null)deviceCard.Visible=saved;TokenInput.Visible=TokenEditing||!saved;TokenInput.UseSystemPasswordChar=!TokenEditing;tokenHint.Visible=saved&&!TokenEditing;tokenHint.Text="Токен сохранён на этом устройстве";tokenSave.Text=saved&&!TokenEditing?"Изменить":"Подтвердить";
   if(!saved)TokenEditing=true;
   if(page==0&&state.ContainsKey("routes")){string selected=TextOf(policy,"route","auto");route.Items.Clear();route.Items.Add(new RouteItem{ID="auto",Label="Автоматически · рейтинг и восстановление"});foreach(var v in AsArray(state["routes"])){var r=Map(v);route.Items.Add(new RouteItem{ID=TextOf(r,"id"),Label=TextOf(r,"label")});}for(int i=0;i<route.Items.Count;i++)if(((RouteItem)route.Items[i]).ID==selected)route.SelectedIndex=i;}
   var lines=new List<string>();object ranking;if(engine.TryGetValue("ranking",out ranking)){foreach(var v in AsArray(ranking)){var r=Map(v);lines.Add(TextOf(r,"label")+" · "+TextOf(r,"download_mbps","0")+" Мбит/с · сбоев "+TextOf(r,"losses","0")+"/3");}}
   if(LastReport!="")lines.Add(LastReport);resultText.Text=String.Join("\n",lines.ToArray());
   ShowWidget(widgetOption.Checked);
  }finally{Refreshing=false;}
 }
 public void SetTokenEditing(string token){TokenEditing=true;TokenInput.Text=token;TokenInput.Visible=true;tokenHint.Visible=false;tokenSave.Text="Подтвердить";TokenInput.UseSystemPasswordChar=false;TokenInput.Focus();}
 public void SavedToken(){TokenEditing=false;TokenInput.Clear();}
 public void SavedName(){editingName=false;NameInput.Visible=false;deviceName.Visible=true;deviceSave.Text="Изменить имя";}
 public void RefreshPolicy(){Refreshing=true;try{if(page>0)FillPolicyList();exceptionInput.Clear();}finally{Refreshing=false;}}
 public void SetApps(string text){apps=AsArray(json.DeserializeObject(text));FillApps();}
 private void FillApps(){running.Items.Clear();foreach(var v in apps){var a=Map(v);running.Items.Add(new AppItem{Name=TextOf(a,"name"),Path=TextOf(a,"exe")});}if(running.Items.Count>0)running.SelectedIndex=0;}
 public void SetError(string message){LastError=message;StatusText.Text=message;if(!Visible)tray.ShowBalloonTip(5000,"Evgenium",message,ToolTipIcon.Warning);}
 public void SetBusy(bool value){Busy=value;if(value)LastError="";UseWaitCursor=value;SetControlsEnabled(cards,!value);widgetToggle.Enabled=!value;if(value)StatusText.Text="Выполняется… Подтвердите запрос Windows, если он появится.";}
 private void SetControlsEnabled(Control parent,bool enabled){foreach(Control c in parent.Controls){if(c is Button||c is ComboBox||c is TextBox||c is CheckBox)c.Enabled=enabled;SetControlsEnabled(c,enabled);}}
 public void ShowWidget(bool enabled){if(enabled&&!widget.Visible&&!IsDisposed)widget.Show();else if(!enabled&&widget.Visible)widget.Hide();}
 public void OpenMain(){Show();WindowState=FormWindowState.Normal;BringToFront();Activate();}
 public void ExitApplication(){AllowExit=true;Close();}
 protected override void Dispose(bool disposing){if(disposing){tray.Dispose();widget.Dispose();}base.Dispose(disposing);}
 private sealed class RouteItem{public string ID,Label;public override string ToString(){return Label;}}
 private sealed class AppItem{public string Name,Path;public override string ToString(){return Name+" — "+Path;}}
 public sealed class DrillMark:Control {
  public DrillMark(){SetStyle(ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.UserPaint,true);}
  protected override void OnPaint(PaintEventArgs e){PaintDrills(e.Graphics,ClientRectangle);}
  public static void PaintDrills(Graphics g,Rectangle r){g.SmoothingMode=SmoothingMode.AntiAlias;var old=g.Transform;g.TranslateTransform(r.X,r.Y);g.ScaleTransform(r.Width/100f,r.Height/100f);for(int side=0;side<2;side++){var state=g.Save();if(side==1){g.TranslateTransform(100,0);g.ScaleTransform(-1,1);}using(var p=new GraphicsPath()){p.AddBezier(39,8,8,-1,2,14,8,25);p.AddBezier(8,25,14,34,31,34,34,40);p.AddBezier(34,40,10,37,3,46,12,57);p.AddBezier(12,57,18,65,31,65,34,70);p.AddBezier(34,70,17,66,13,76,22,84);p.AddBezier(22,84,28,90,35,92,39,96);p.AddBezier(39,96,37,83,47,75,42,65);p.AddBezier(42,65,48,52,39,47,42,36);p.AddBezier(42,36,49,23,43,13,39,8);p.CloseFigure();using(var brush=new SolidBrush(Color.FromArgb(255,88,109)))g.FillPath(brush,p);}using(var pen=new Pen(Color.FromArgb(255,172,184),2)){g.DrawBezier(pen,38,10,15,2,5,15,10,21);g.DrawBezier(pen,8,36,7,46,25,49,34,52);g.DrawBezier(pen,17,62,17,69,29,72,34,74);}g.Restore(state);}g.Transform=old;old.Dispose();}
 }
}
