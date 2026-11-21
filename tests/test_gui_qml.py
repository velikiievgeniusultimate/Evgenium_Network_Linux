import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).parents[1]
QML=shutil.which('qml6') or shutil.which('qml-qt6') or ('/usr/lib/qt6/bin/qml' if Path('/usr/lib/qt6/bin/qml').is_file() else None)

@unittest.skipUnless(QML, 'Qt QML runtime not installed')
class QmlStateTests(unittest.TestCase):
    def exercise(self, checks, shorten_watchdog=False, start_action=True):
        class Handler(http.server.BaseHTTPRequestHandler):
            posts=0
            def log_message(self,*args):pass
            def reply(self,payload):
                body=json.dumps(payload).encode()
                try:
                    self.send_response(500);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):self.reply({'ok':False,'error':'poll failed'})
            def do_POST(self):
                type(self).posts+=1
                self.rfile.read(int(self.headers.get('Content-Length',0)))
                time.sleep(1)
                self.reply({'ok':False,'error':'expected action failure'})
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        text=(ROOT/'src/evgenium_gui.qml').read_text()
        if start_action:
            text=text.replace('    Component.onCompleted: {\n        refreshState()', '    Component.onCompleted: {\n        action({action:"test"})\n        refreshState()')
        if shorten_watchdog:text=text.replace('operation ? 780000 : 12000','operation ? 300 : 12000')
        i=text.rfind('}');text=text[:i]+checks+'\n'+text[i:]
        try:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/'test.qml';p.write_text(text)
                env={**os.environ,'QT_QPA_PLATFORM':'offscreen','QT_QUICK_BACKEND':'software','QML_DISABLE_DISK_CACHE':'1','QT_FORCE_STDERR_LOGGING':'1'}
                result=subprocess.run([QML,str(p),'--',str(server.server_port),'test-token'],env=env,capture_output=True,text=True,timeout=6)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertNotIn('Unable to assign [undefined] to bool', result.stderr)
                self.assertEqual(Handler.posts, int(start_action))
        finally:server.shutdown();server.server_close();thread.join(timeout=1)

    def test_connection_button_follows_available_state(self):
        self.exercise('''
    Timer { interval: 100; running: true; onTriggered: {
        function check(expected, label) {
            if (connectionButton.enabledButton !== expected || connectionButton.label !== label)
                throw new Error("Unexpected connection button: " + JSON.stringify(root.state))
        }
        try {
            check(false, "Подключить")
            root.state = {tunnel: {has_token: true}}
            check(true, "Подключить")
            root.state = {guard: true}
            check(true, "Отключить")
            root.state = {tunnel: {running: true}}
            check(true, "Отключить")
            root.busy = true
            check(false, "Отключить")
            Qt.exit(0)
        } catch (error) {
            console.error(error.message)
            Qt.exit(1)
        }
    }}
''', start_action=False)

    def test_failed_polls_do_not_unlock_action_or_erase_action_error(self):
        self.exercise('''
    Timer { interval: 200; running: true; onTriggered: {
        if (!root.busy) { console.error("poll unlocked action"); Qt.exit(1); return }
        root.action({action:"duplicate"})
    }}
    Timer { interval: 1400; running: true; onTriggered: {
        if (root.busy || root.errorText !== "expected action failure") { console.error("missing action failure", root.errorText); Qt.exit(1); return }
        root.refreshState()
    }}
    Timer { interval: 1800; running: true; onTriggered: {
        if (root.errorText !== "expected action failure") { console.error("poll erased action failure"); Qt.exit(1); return }
        Qt.exit(0)
    }}
''')

    def test_missing_action_reply_has_a_ui_deadline(self):
        self.exercise('''
    Timer { interval: 600; running: true; onTriggered: {
        if (root.busy || root.errorText.indexOf("Ответ операции не получен") < 0) { console.error("watchdog failed",root.busy,root.errorText); Qt.exit(1); return }
        Qt.exit(0)
    }}
''',shorten_watchdog=True)

    def test_caption_actions_and_resize_zones(self):
        self.exercise('''
    property bool closeRequested: false
    onClosing: function(event) { root.closeRequested = true; event.accepted = false }
    Timer { interval: 1200; running: true; onTriggered: {
        if (!(root.flags & Qt.FramelessWindowHint) || (root.flags & Qt.WindowMaximizeButtonHint)) {
            console.error("Unexpected native caption flags"); Qt.exit(1); return
        }
        if (minimizeWindow.x + minimizeWindow.width > closeWindow.x || closeWindow.width < 40) {
            console.error("Caption buttons overlap"); Qt.exit(1); return
        }
        root.width = 1200; root.height = 800
        minimizeWindow.clicked()
        if (root.visibility !== Window.Minimized) { console.error("Minimize failed"); Qt.exit(1); return }
        root.showNormal()
        closeWindow.clicked()
        if (!root.closeRequested) { console.error("Close not requested"); Qt.exit(1); return }
        Qt.exit(0)
    }}
''')
