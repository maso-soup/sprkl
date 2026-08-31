"""Request instrumentation.

Sink events stream to the scorer over a one-way socket as they happen. Nothing
in this process interprets them; nothing in this process can read them back.

INVARIANTS — anything added here must hold all three, or the answer key leaks
back into the app image:

  1. Emit RAW MATERIAL, never a verdict. `tmpl.render` carries the template
     source; it does not carry "this looked like SSTI". No looks_xss(), no
     thresholds, no regexes that encode what "exploited" means.
  2. Emit for ALL traffic. Every SQL statement goes through sql.exec, the
     parameterised ones included. A tap that only fires on attacks is a label.
  3. No finding ids, no vulnerability names, no severity, no categories.

The response side is not instrumented here at all: the ingress proxy sees it.
"""
import json, os, queue, socket, threading
from flask import g, has_request_context, request
from shared import records as R

SOCKET = os.environ.get("SPRKL_TAP_SOCKET", "/run/sprkl/tap.sock")
MAX_FIELD = 8192
_Q = queue.Queue(maxsize=8192)
_started = False


def _writer():
    sock = None
    while True:
        rec = _Q.get()
        try:
            line = R.dumps(rec).encode() + b"\n"
        except Exception:
            continue
        for _ in range(2):
            try:
                if sock is None:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect(SOCKET)
                sock.sendall(line)
                break
            except OSError:
                if sock is not None:
                    try: sock.close()
                    except Exception: pass
                sock = None
        # A dropped event is a lost solve. It is never a failed request: the
        # collector being down must be invisible to the tester, including in
        # response timing, or sqli-time-based becomes unscorable.


def _start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_writer, daemon=True).start()


def _cap(v):
    if isinstance(v, bytes):
        return v[:MAX_FIELD].decode("utf-8", "replace")
    if isinstance(v, str):
        return v[:MAX_FIELD]
    return v


def emit(_kind, /, **d):
    """Record one sink event against the current request.

    The event name is positional-only so a payload field may itself be called
    `kind` (coupon.redeem, token.issue) without colliding.
    """
    if not has_request_context():
        return
    rid = getattr(g, "_rid", None)
    if rid is None:
        return
    g._seq = getattr(g, "_seq", 0) + 1
    try:
        _Q.put_nowait(R.tap(rid, g._seq, _kind, **{k: _cap(v) for k, v in d.items()}))
    except queue.Full:
        pass


def install(app):
    _start()

    @app.before_request
    def _bind_rid():
        # Injected by the ingress proxy, which strips any client-supplied value.
        g._rid = request.headers.get(R.REQUEST_ID_HEADER)
        g._seq = 0
