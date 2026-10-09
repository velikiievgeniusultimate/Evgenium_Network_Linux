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
QML=shutil.which('qml6') or shutil.which('qml-qt6')

@unittest.skipUnless(QML, 'Qt QML runtime not installed')
class QmlStateTests(unittest.TestCase):
    def exercise(self, checks, shorten_watchdog=False):
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
        text=text.replace('    Component.onCompleted: {\n        refreshState()', '    Component.onCompleted: {\n        action({action:"test"})\n        refreshState()')
        if shorten_watchdog:text=text.replace('operation ? 780000 : 12000','operation ? 300 : 12000')
        i=text.rfind('}');text=text[:i]+checks+'\n'+text[i:]
        try:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/'test.qml';p.write_text(text)
                env={**os.environ,'QT_QPA_PLATFORM':'offscreen','QT_QUICK_BACKEND':'software','QML_DISABLE_DISK_CACHE':'1'}
                result=subprocess.run([QML,str(p),'--',str(server.server_port),'test-token'],env=env,capture_output=True,text=True,timeout=6)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(Handler.posts,1,'Polls must not unlock a second toggle/action')
        finally:server.shutdown();server.server_close();thread.join(timeout=1)

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
