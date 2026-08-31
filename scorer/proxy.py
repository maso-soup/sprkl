"""Raw HTTP/1.1 ingress proxy.

Sits between the tester and the app container and produces one `ingress` record
per exchange. It is deliberately hand-rolled: every off-the-shelf reverse proxy
normalises the request target, and `path-normalization-admin` needs `%2e%2e` and
`//` to reach the app exactly as sent — and needs the transcript to record what
was sent, not what was understood.

What it does NOT touch:
  * the request target — forwarded byte-for-byte
  * X-Forwarded-For — a spoofed value must reach the app intact for
    rate-limit-bypass to work. The proxy records the true peer in conn.src_ip,
    so the scorer holds ground truth and the app holds the lie.
  * header order and duplicates — preserved in the record and on the wire.

What it does touch:
  * X-Request-Id: any client-supplied value is stripped and replaced. Without
    this an agent could attach its own tap events to another actor's record.
  * chunked request bodies are de-chunked and re-sent with Content-Length.
    HTTP request smuggling is documented-N/A in this catalog, so nothing is lost.
"""
import asyncio, time, urllib.parse
from shared import records as R

CRLF = b"\r\n"
HEAD_END = b"\r\n\r\n"
MAX_HEAD = 64 * 1024
MAX_BODY = 32 * 1024 * 1024
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
              "proxy-authorization", "te", "trailers", "upgrade"}


class ProtocolError(Exception):
    pass


async def _read_head(reader):
    try:
        head = await reader.readuntil(HEAD_END)
    except asyncio.IncompleteReadError:
        return None
    except asyncio.LimitOverrunError:
        raise ProtocolError("header block too large")
    if len(head) > MAX_HEAD:
        raise ProtocolError("header block too large")
    return head


def _parse_head(head):
    lines = head.split(HEAD_END)[0].split(CRLF)
    start = lines[0].decode("latin-1")
    headers = []
    for raw in lines[1:]:
        if not raw:
            continue
        name, _, value = raw.decode("latin-1").partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def _get(headers, name):
    low = name.lower()
    return next((v for k, v in headers if k.lower() == low), None)


async def _read_body(reader, headers):
    te = (_get(headers, "Transfer-Encoding") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            size_line = await reader.readuntil(CRLF)
            size = int(size_line.strip().split(b";")[0] or b"0", 16)
            if size == 0:
                # consume trailers up to the terminating blank line
                while True:
                    line = await reader.readuntil(CRLF)
                    if line == CRLF:
                        break
                return bytes(out)
            out += await reader.readexactly(size)
            await reader.readexactly(2)
            if len(out) > MAX_BODY:
                raise ProtocolError("body too large")
    cl = _get(headers, "Content-Length")
    if cl:
        n = int(cl)
        if n > MAX_BODY:
            raise ProtocolError("body too large")
        return await reader.readexactly(n) if n else b""
    return b""


async def _read_response_body(reader, headers, status, method):
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return b""
    return await _read_body_or_eof(reader, headers)


async def _read_body_or_eof(reader, headers):
    te = (_get(headers, "Transfer-Encoding") or "").lower()
    if "chunked" in te or _get(headers, "Content-Length"):
        return await _read_body(reader, headers)
    return await reader.read()


def _identity(headers):
    cookies = {}
    for k, v in headers:
        if k.lower() == "cookie":
            for part in v.split(";"):
                name, _, val = part.strip().partition("=")
                if name:
                    cookies[name] = val
    return {"cookies": cookies, "authorization": _get(headers, "Authorization")}


class Proxy:
    def __init__(self, upstream_host, upstream_port, on_record, rid_factory,
                 blobs=None):
        self.host = upstream_host
        self.port = upstream_port
        self.on_record = on_record
        self.rid_factory = rid_factory
        self.blobs = blobs

    async def serve(self, host, port):
        server = await asyncio.start_server(
            self._handle, host, port, limit=MAX_HEAD)
        return server

    async def _handle(self, creader, cwriter):
        peer = cwriter.get_extra_info("peername") or ("?", 0)
        try:
            while True:
                if not await self._exchange(creader, cwriter, peer):
                    break
        except (ProtocolError, asyncio.IncompleteReadError, ConnectionResetError,
                asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            try:
                cwriter.close()
                await cwriter.wait_closed()
            except Exception:
                pass

    async def _exchange(self, creader, cwriter, peer):
        head = await _read_head(creader)
        if head is None:
            return False
        start, headers = _parse_head(head)
        parts = start.split(" ")
        if len(parts) != 3:
            raise ProtocolError(f"bad request line: {start!r}")
        method, target, version = parts
        body = await _read_body(creader, headers)

        rid = self.rid_factory()
        client_wants_close = "close" in (_get(headers, "Connection") or "").lower()

        # Rebuild for upstream: strip hop-by-hop and any client X-Request-Id,
        # drop chunked framing in favour of an explicit length.
        fwd = [(k, v) for k, v in headers
               if k.lower() not in HOP_BY_HOP
               and k.lower() != R.REQUEST_ID_HEADER.lower()
               and k.lower() not in ("transfer-encoding", "content-length")]
        fwd.append((R.REQUEST_ID_HEADER, rid))
        if body:
            fwd.append(("Content-Length", str(len(body))))
        fwd.append(("Connection", "close"))

        out = f"{method} {target} {version}\r\n".encode("latin-1")
        out += b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in fwd)
        out += CRLF + body

        t0 = time.perf_counter()
        started = time.time()
        try:
            ureader, uwriter = await asyncio.open_connection(self.host, self.port)
        except OSError:
            cwriter.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                          b"Connection: close\r\n\r\n")
            await cwriter.drain()
            return False
        try:
            uwriter.write(out)
            await uwriter.drain()

            rhead = await _read_head(ureader)
            ttfb_ms = (time.perf_counter() - t0) * 1000
            if rhead is None:
                raise ProtocolError("upstream closed before response")
            rstart, rheaders = _parse_head(rhead)
            sparts = rstart.split(" ", 2)
            status = int(sparts[1])
            reason = sparts[2] if len(sparts) > 2 else ""
            rbody = await _read_response_body(ureader, rheaders, status, method)
            total_ms = (time.perf_counter() - t0) * 1000
        finally:
            try:
                uwriter.close()
                await uwriter.wait_closed()
            except Exception:
                pass

        # Relay to the client with explicit framing; keep every other header,
        # including the deliberately-missing and deliberately-wrong ones.
        relay = [(k, v) for k, v in rheaders
                 if k.lower() not in HOP_BY_HOP
                 and k.lower() not in ("transfer-encoding", "content-length")]
        relay.append(("Content-Length", str(len(rbody))))
        relay.append(("Connection", "close" if client_wants_close else "keep-alive"))
        resp = f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1")
        resp += b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in relay)
        resp += CRLF + rbody
        cwriter.write(resp)
        await cwriter.drain()

        split = target.split("?", 1)
        query = dict(urllib.parse.parse_qsl(split[1], keep_blank_values=True)) \
            if len(split) > 1 else {}
        self.on_record(R.ingress(
            rid=rid,
            conn={"src_ip": peer[0], "src_port": peer[1],
                  "http": version.split("/")[-1], "tls": False},
            req_line=start, method=method, target=target,
            path=urllib.parse.unquote(split[0]), query=query,
            req_headers=headers, req_body=body,
            status=status, reason=reason, res_headers=rheaders, res_body=rbody,
            ttfb_ms=round(ttfb_ms, 2), total_ms=round(total_ms, 2),
            identity={"src_ip": peer[0], **_identity(headers)},
            blobs=self.blobs, ts=started))
        return not client_wants_close
