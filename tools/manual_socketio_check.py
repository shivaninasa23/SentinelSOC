"""End-to-end WebSocket smoke check; run from project root with test dependencies installed."""
import http.cookiejar
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import socketio as socketio_client
from sentinelsoc import create_app
from sentinelsoc.extensions import db
from sentinelsoc.models import User

password=secrets.token_urlsafe(24)
secret=secrets.token_hex(32)
username="ws-smoke-"+secrets.token_hex(4)
with tempfile.TemporaryDirectory(prefix="ws-smoke-",dir=ROOT/"instance") as temp:
    database=Path(temp,"socket-smoke.db")
    env=os.environ.copy();env.update({"SECRET_KEY":secret,"DATABASE_URL":"sqlite:///"+database.as_posix(),"COOKIE_SECURE":"false","PORT":"0"})
    # Choose a currently free port for a separate compatible Socket.IO server process.
    listener=socket.socket();listener.bind(("127.0.0.1",0));port=listener.getsockname()[1];listener.close();env["PORT"]=str(port)
    app=create_app({"SECRET_KEY":secret,"SQLALCHEMY_DATABASE_URI":"sqlite:///"+database.as_posix(),"TESTING":True})
    with app.app_context():
        db.create_all();user=User(username=username,role="analyst");user.set_password(password);db.session.add(user);db.session.commit()
        db.session.remove();db.engine.dispose()
    log_path=Path(temp,"server.log")
    with log_path.open("w",encoding="utf-8") as log:
        process=subprocess.Popen([sys.executable,"devserver.py"],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            base=f"http://127.0.0.1:{port}";cookies=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
            for _ in range(80):
                try:opener.open(base+"/api/health",timeout=1).read();break
                except Exception:time.sleep(.2)
            else:raise RuntimeError("Socket.IO development server did not start: "+log_path.read_text(encoding="utf-8")[-2000:])
            login_html=opener.open(base+"/login").read().decode("utf-8")
            csrf=re.search(r'name="csrf_token" value="([^"]+)',login_html).group(1)
            form=urllib.parse.urlencode({"username":username,"password":password,"csrf_token":csrf}).encode()
            opener.open(urllib.request.Request(base+"/login",data=form,method="POST",headers={"Content-Type":"application/x-www-form-urlencoded"})).read()
            dashboard=opener.open(base+"/").read().decode("utf-8")
            csrf=re.search(r'name="csrf-token" content="([^"]+)',dashboard).group(1)
            cookie="; ".join(f"{c.name}={c.value}" for c in cookies)
            rejected=socketio_client.Client(reconnection=False)
            try:
                rejected.connect(base,namespaces=["/live"],transports=["websocket"],wait_timeout=3)
                raise AssertionError("Unauthenticated WebSocket was accepted")
            except socketio_client.exceptions.ConnectionError:
                pass
            client=socketio_client.Client(reconnection=False);received=[]
            client.on("event",lambda payload:received.append(payload),namespace="/live")
            client.connect(base,headers={"Cookie":cookie},namespaces=["/live"],transports=["websocket"],wait_timeout=5)
            if client.eio.transport()!="websocket":raise AssertionError(f"Expected WebSocket transport, got {client.eio.transport()}")
            payload={"event_id":str(uuid.uuid4()),"event_type":"system","source_system":"websocket-smoke","description":"live event delivered"}
            req=urllib.request.Request(base+"/api/events",data=json.dumps(payload).encode(),method="POST",headers={"Content-Type":"application/json","X-CSRFToken":csrf,"Cookie":cookie})
            response=json.loads(opener.open(req).read())
            deadline=time.monotonic()+3
            while time.monotonic()<deadline and not received:time.sleep(.05)
            if response.get("created") is not True or not any(e.get("event_id")==payload["event_id"] for e in received):raise AssertionError("Committed event was not delivered to WebSocket client")
            print("WebSocket authentication, websocket transport, and event delivery passed.")
            client.disconnect()
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
