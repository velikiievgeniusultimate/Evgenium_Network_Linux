"""Run the real Plasma executable data engine against a disposable fake VPN."""
import importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('widget_manager',ROOT/'src/vpnctl.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
@unittest.skipUnless(shutil.which('plasmawindowed'),'Plasma runtime not installed')
class WidgetTests(unittest.TestCase):
 def test_switch_twice_and_settings_launcher(self):
  with tempfile.TemporaryDirectory(prefix='evg-widget-') as td:
   d=Path(td);ui=d/'contents/ui';ui.mkdir(parents=True)
   metadata=json.loads(m.PLASMOID_METADATA);metadata['KPlugin']['Id']='com.evgenium.widgettest';(d/'metadata.json').write_text(json.dumps(metadata))
   helper=d/'fake.py';state=d/'state.json';state.write_text(json.dumps({'active':False,'toggles':0,'settings':0}))
   helper.write_text("import json,sys,time\nfrom pathlib import Path\np=Path(__file__).with_name('state.json');s=json.loads(p.read_text())\nif sys.argv[1]=='toggle':\n time.sleep(.2);s['active']=not s['active'];s['toggles']+=1;p.write_text(json.dumps(s))\nelif sys.argv[1]=='settings':\n s['settings']+=1;p.write_text(json.dumps(s))\nprint(json.dumps(s))\n")
   qml=m.PLASMOID_MAIN_QML.replace('/usr/local/bin/vpn',f'/usr/bin/python3 {helper}').replace('/usr/local/bin/evgenium-network --detach',f'/usr/bin/python3 {helper} settings')
   pos=qml.rfind('}')
   qml=qml[:pos]+'''
    property int testStep: 0
    Timer { interval: 100; running: true; repeat: true; onTriggered: {
        if (root.errorText || root.statusErrorText) { console.error("WIDGET ERROR",root.errorText,root.statusErrorText); Qt.exit(1); return }
        if (root.statusPending || root.busy || root.settingsBusy) return
        if (root.testStep === 0) { root.testStep=1; root.toggleVpn() }
        else if (root.testStep === 1 && root.vpnActive) { root.testStep=2; root.toggleVpn() }
        else if (root.testStep === 2 && !root.vpnActive) { root.testStep=3; root.openSettings() }
        else if (root.testStep === 3) { console.info("WIDGET PASSED"); Qt.quit() }
    }}
    Timer { interval: 10000; running: true; onTriggered: { console.error("WIDGET TIMEOUT"); Qt.exit(2) } }
'''+qml[pos:]
   (ui/'main.qml').write_text(qml)
   import time
   proc=subprocess.Popen(['plasmawindowed',str(d)],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**os.environ,'QT_QPA_PLATFORM':'offscreen','QT_QUICK_BACKEND':'software','QML_DISABLE_DISK_CACHE':'1'})
   try:
    until=time.monotonic()+10
    while time.monotonic()<until:
     try:value=json.loads(state.read_text())
     except ValueError:time.sleep(.1);continue
     if value=={'active':False,'toggles':2,'settings':1}:break
     if proc.poll() is not None:break
     time.sleep(.1)
   finally:
    proc.terminate();proc.communicate(timeout=3)
   self.assertEqual(json.loads(state.read_text()),{'active':False,'toggles':2,'settings':1})
