from socketio import WSGIApp
from sentinelsoc import create_app

app = create_app()
# Waitress supports the polling transport. For websocket upgrade support use a
# Socket.IO-capable deployment server rather than plain Waitress.
app.wsgi_app = WSGIApp(app.extensions["socketio"].server, app.wsgi_app)
