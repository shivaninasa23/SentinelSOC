"""Local development entry point with Flask-SocketIO's WebSocket-capable runner."""
import os
from sentinelsoc import create_app

app=create_app()

if __name__=="__main__":
    app.extensions["socketio"].run(app,host=os.getenv("SENTINEL_HOST","127.0.0.1"),port=int(os.getenv("PORT","5000")),
        debug=False,use_reloader=False,allow_unsafe_werkzeug=True)
