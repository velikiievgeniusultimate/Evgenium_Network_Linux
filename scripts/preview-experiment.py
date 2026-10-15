from pathlib import Path
import importlib.util,secrets,threading,subprocess,os,tempfile
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gui',root/'src/evgenium_gui.py');gui=importlib.util.module_from_spec(spec);spec.loader.exec_module(gui)
token=secrets.token_urlsafe(32);server=gui.ApiServer(('127.0.0.1',0),gui.Handler,token)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
text=(root/'src/evgenium_gui.qml').read_text().replace('property int pageIndex: 0','property int pageIndex: 6')

try:
 with tempfile.TemporaryDirectory()as td:
  qml=Path(td)/'preview.qml';qml.write_text(text)
  env={**os.environ,**__import__('json').loads((Path.home()/'.cache/evgenium-starfive-access/preview-environment.json').read_text()),'QT_QPA_PLATFORM':'wayland','QT_QUICK_BACKEND':'software'}
  process=subprocess.Popen([gui.find_qml_runtime(),str(qml),'--',str(server.server_port),token],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   __import__('time').sleep(3)
   result=subprocess.run(['spectacle','-b','-n','-f','-o','/tmp/evgenium-experimental-preview.png'],env=env,capture_output=True,text=True,timeout=8)
   print('Preview capture exit:',result.returncode)
   if result.returncode:print(result.stderr[-1000:])
  finally:process.terminate();process.wait(timeout=3)

finally:server.shutdown();server.server_close()
