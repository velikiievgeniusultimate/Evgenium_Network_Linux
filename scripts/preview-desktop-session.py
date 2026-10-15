import json,os,signal,time
from pathlib import Path
p=Path.home()/'.cache/evgenium-starfive-access/preview-environment.json'
p.write_text(json.dumps({k:os.environ[k]for k in ('DISPLAY','XAUTHORITY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS')if k in os.environ}));p.chmod(0o600)
while True:time.sleep(10)
