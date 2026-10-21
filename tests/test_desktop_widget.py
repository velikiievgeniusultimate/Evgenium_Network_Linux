"""Exercise the shipped desktop QML against an authenticated disposable API."""
import base64
import contextlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
QML = shutil.which('qml6') or shutil.which('qml-qt6') or shutil.which('qml')
spec = importlib.util.spec_from_file_location('desktop_manager', ROOT/'src/vpnctl.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class WidgetInstallTests(unittest.TestCase):
    def test_release_installs_and_refreshes_widget_without_changing_payload_format(self):
        with tempfile.TemporaryDirectory() as td, patch.object(m.shutil, 'which', return_value=None):
            settings = {'owner_user': pwd.getpwuid(os.getuid()).pw_name, 'owner_home': td}
            m.cmd_desktop_install(settings)
            package = m._gui_package_dir(settings)
            self.assertEqual((package/'evgenium_widget.qml').read_bytes(), (ROOT/'src/evgenium_widget.qml').read_bytes())
            self.assertEqual(base64.b64decode(m.DESKTOP_WIDGET_QML_B64), (ROOT/'src/evgenium_widget.qml').read_bytes())
            self.assertIn('--widget --detach', m._desktop_autostart_path(settings).read_text())
            (package/'evgenium_widget.qml').write_text('old version')
            m.cmd_gui_install(settings)  # This runs unconditionally from vpn update.
            self.assertEqual((package/'evgenium_widget.qml').read_bytes(), (ROOT/'src/evgenium_widget.qml').read_bytes())
            m.cmd_desktop_remove(settings)
            self.assertFalse(m._desktop_autostart_path(settings).exists())
            self.assertTrue((package/'evgenium_gui.qml').exists())

@unittest.skipUnless(QML, 'Qt QML runtime not installed')
class WidgetQmlTests(unittest.TestCase):
    def exercise(self, checks, fail_poll=False, fail_action=False):
        class Handler(http.server.BaseHTTPRequestHandler):
            posts = []
            active = False
            def log_message(self, *args): pass
            def reply(self, data, code=200):
                blob=json.dumps(data).encode()
                self.send_response(code); self.send_header('Content-Length',str(len(blob))); self.end_headers(); self.wfile.write(blob)
            def do_GET(self):
                if self.headers.get('X-Evgenium-Token') != 'test-token': return self.reply({'ok':False},403)
                if fail_poll and type(self).posts: return self.reply({'ok':False,'error':'poll failed'},500)
                self.reply({'ok':True,'state':{'active':self.active,'guard':self.active,'tunnel':{'running':self.active,'has_token':True,'device_name':'Тестовый компьютер'},'manager_version':'test'}})
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                type(self).posts.append(data.get('action',self.path))
                if fail_action:
                    import time; time.sleep(.5)
                    return self.reply({'ok':False,'error':'operation failed'},500)
                type(self).active = data.get('action') == 'connect'
                self.reply({'ok':True})
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                qml=Path(td)/'widget.qml'
                text=(ROOT/'src/evgenium_widget.qml').read_text()
                i=text.rfind('}');text=text[:i]+checks+'\nTimer { interval: 4500; running: true; onTriggered: { console.error("test timeout"); Qt.exit(3) } }\n'+text[i:]
                qml.write_text(text)
                # Test UI actions only against this fake HTTP server.
                result=subprocess.run([QML,'--apptype','widget',str(qml),'--','--preview',str(Path(td)/'widget.ini'),str(server.server_port),'test-token'],env={**os.environ,'QT_QPA_PLATFORM':'offscreen','QT_QUICK_BACKEND':'software','QML_DISABLE_DISK_CACHE':'1','QT_FORCE_STDERR_LOGGING':'1'},capture_output=True,text=True,timeout=7)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('WIDGET PASSED',result.stdout+result.stderr)
                self.assertNotIn('TypeError',result.stderr)
                self.assertNotIn('ReferenceError',result.stderr)
                return Handler.posts
        finally:server.shutdown();server.server_close();worker.join(timeout=1)

    def test_connect_disconnect_and_open_settings(self):
        posts=self.exercise('''
property int step: 0
Timer { interval: 50; running: true; repeat: true; onTriggered: {
    if (!root.visible || root.width!==164 || root.height!==48) { console.error("desktop widget disappeared or changed size"); Qt.exit(1); return }
    if (!root.ready || root.busy || root.statePending) return
    if (root.step===0) { root.step=1; root.action("connect") }
    else if (root.step===1 && root.connected) { root.step=2; root.action("disconnect") }
    else if (root.step===2 && !root.connected) { root.step=3; root.openSettings() }
    else if (root.step===3) { console.info("WIDGET PASSED"); Qt.exit(0) }
}}
''')
        self.assertEqual(posts,['connect','disconnect','/api/settings'])

    def test_poll_failure_does_not_unlock_or_erase_operation_error(self):
        posts=self.exercise('''
property bool started: false
Timer { interval: 50; running: true; repeat: true; onTriggered: {
    if (root.ready && !root.started) { root.started=true; root.action("connect"); root.refreshState() }
}}
Timer { interval: 300; running: true; onTriggered: {
    if (!root.busy) { console.error("poll unlocked operation"); Qt.exit(1) }
    root.action("connect")
}}
Timer { interval: 900; running: true; onTriggered: { root.refreshState() } }
Timer { interval: 1200; running: true; onTriggered: {
    if (root.busy || root.errorText!=="operation failed" || root.connected || !root.pollErrorText) { console.error("unsafe error state",root.errorText,root.pollErrorText); Qt.exit(1); return }
    console.info("WIDGET PASSED"); Qt.exit(0)
}}
''',fail_poll=True,fail_action=True)
        self.assertEqual(posts,['connect'])


class WidgetLifecycleTests(unittest.TestCase):
    def test_single_instance_and_asset_update_relaunch(self):
        # Fake QML executable only. Never calls the installed VPN or its API.
        import signal
        import sys
        import time
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td); launches=folder/'launches'
            runner=folder/'fake-qml'
            runner.write_text('#!'+sys.executable+'\nimport time\nfrom pathlib import Path\np=Path('+repr(str(launches))+')\nwith p.open("a") as f:f.write("launch\\n")\ntime.sleep(30)\n')
            runner.chmod(0o755)
            source=(ROOT/'src/evgenium_gui.py').read_text().replace('qml = find_qml_runtime()', 'qml = '+repr(str(runner)))
            script=folder/'evgenium_gui.py';script.write_text(source)
            asset=folder/'evgenium_widget.qml';asset.write_text('old asset')
            env={**os.environ,'XDG_STATE_HOME':str(folder/'state'),'QT_QPA_PLATFORM':'offscreen'}
            proc=subprocess.Popen([sys.executable,str(script),'--widget'],env=env,start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            def count():return len(launches.read_text().splitlines()) if launches.exists() else 0
            def await_count(n):
                until=time.monotonic()+7
                while time.monotonic()<until:
                    if count()>=n:return
                    if proc.poll() is not None:break
                    time.sleep(.05)
                self.fail('Widget did not start/reload: '+str(proc.poll()))
            try:
                await_count(1)
                second=subprocess.run([sys.executable,str(script),'--widget'],env=env,capture_output=True,timeout=3)
                self.assertEqual(second.returncode,0,second.stderr)
                self.assertEqual(count(),1,'second launch created a duplicate widget')
                asset.write_text('updated asset from vpn update')
                await_count(2)
                self.assertEqual(count(),2)
            finally:
                os.killpg(proc.pid,signal.SIGTERM)
                proc.communicate(timeout=3)

if __name__ == '__main__': unittest.main()
