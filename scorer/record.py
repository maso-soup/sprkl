"""The view a rule matches against: one sealed bundle, fully described.

Accessors record which record types they touched (`touched`), so a finding's
evidence class is derived from its own rule rather than hand-maintained.
"""
import base64, ipaddress, urllib.parse


class Event:
    """Attribute access over a tap payload; missing keys are None, not KeyError.

    Deliberately NOT a dict subclass: a payload field may be named `keys`,
    `values`, `items` or `get`, which would otherwise resolve to the dict method
    and silently break the rule.
    """
    __slots__ = ("_d",)

    def __init__(self, d):
        object.__setattr__(self, "_d", d)

    def __getattr__(self, k):
        return self._d.get(k)


class Record:
    def __init__(self, bundle, manifest, store, state):
        self._b = bundle
        self._ing = bundle["ingress"]
        self._events = bundle["events"]
        self.m = manifest
        self.store = store
        self.state = state
        self.touched = set()

        self.rid = bundle["rid"]
        self.ts = self._ing["ts"]

    # -- proxy-observed -----------------------------------------------------
    def _i(self):
        self.touched.add("ingress")
        return self._ing

    @property
    def method(self):  return self._i()["req"]["method"]
    @property
    def path(self):    return self._i()["req"]["path"]
    @property
    def target(self):  return self._i()["req"]["target"]
    @property
    def line(self):    return self._i()["req"]["line"]
    @property
    def args(self):    return self._i()["req"]["query"]
    @property
    def status(self):  return self._i()["res"]["status"]
    @property
    def ms(self):      return self._i()["timing"]["total_ms"]
    @property
    def src_ip(self):  return self._i()["conn"]["src_ip"]

    @property
    def headers(self):
        return {k.lower(): v for k, v in self._i()["req"]["headers"]}

    def header_all(self, name):
        low = name.lower()
        return [v for k, v in self._i()["req"]["headers"] if k.lower() == low]

    @property
    def res_headers(self):
        return {k.lower(): v for k, v in self._i()["res"]["headers"]}

    def res_header_all(self, name):
        low = name.lower()
        return [v for k, v in self._i()["res"]["headers"] if k.lower() == low]

    @property
    def body(self):
        b = self._i()["res"]["body_b64"]
        return base64.b64decode(b).decode("utf-8", "replace") if b else ""

    @property
    def req_body(self):
        b = self._i()["req"]["body_b64"]
        return base64.b64decode(b).decode("utf-8", "replace") if b else ""

    @property
    def form(self):
        ct = (self.headers.get("content-type") or "")
        if "form-urlencoded" not in ct:
            return {}
        return dict(urllib.parse.parse_qsl(self.req_body, keep_blank_values=True))

    def inputs(self):
        """Every attacker-controlled string in the request."""
        yield from self.args.values()
        yield from self.form.values()
        for k, v in self._i()["req"]["headers"]:
            if k.lower() not in ("host", "connection", "content-length"):
                yield v

    def stored_hits(self, pred):
        """Server-persisted attacker payloads (reviews, messages) that are present
        in THIS response and satisfy pred. Chrome never matches: it was never
        submitted, so it is not in the stored set."""
        body = self.body
        if not body:
            return []
        return [p for p in self.store.stored_payloads("html")
                if p in body and pred(p)]

    def reflected(self, pred=None):
        body = self.body
        return [v for v in self.inputs()
                if v and len(v) > 3 and v in body and (pred is None or pred(v))]

    # -- app-reported -------------------------------------------------------
    def ev(self, kind):
        self.touched.add("tap")
        return [Event(e["d"]) for e in self._events
                if e["t"] == "tap" and e["k"] == kind]

    def any(self, kind, pred):
        return any(pred(e) for e in self.ev(kind))

    # -- egress -------------------------------------------------------------
    def egress(self, obs=None):
        self.touched.add(f"egress:{obs}" if obs else "egress:any")
        return [e for e in self._events
                if e["t"] == "egress" and (obs is None or e.get("obs") == obs)]

    # -- scorer-observed ----------------------------------------------------
    def oast_hits(self):
        self.touched.add("oast")
        return self.store.oast_for_actor(self.actor, since=self.ts - 60)

    # -- identity -----------------------------------------------------------
    @property
    def actor(self):
        """Stable CLIENT identity, never the claimed one.

        Deliberately opaque: a forged JWT or a spoofed session must not make the
        actor *become* the victim, or leaked() would decide they owned the
        secret they just stole.
        """
        ident = self._i()["identity"]
        sess = (ident.get("cookies") or {}).get("session")
        if sess:
            return "sess:" + sess[-24:]
        auth = ident.get("authorization")
        if auth:
            return "bearer:" + auth[-24:]
        return "ip:" + (ident.get("src_ip") or "?")

    @property
    def principals(self):
        """Identities this actor legitimately authenticated as (password verified)."""
        return self.store.principals_for(self.actor)

    # -- canaries -----------------------------------------------------------
    def _res_text(self):
        ing = self._i()
        parts = ["{}: {}".format(k, v) for k, v in ing["res"]["headers"]]
        if ing["res"]["body_b64"]:
            parts.append(base64.b64decode(ing["res"]["body_b64"])
                         .decode("utf-8", "replace"))
        return "\n".join(parts)

    def _req_text(self):
        ing = self._i()
        parts = [ing["req"]["target"]]
        parts += ["{}: {}".format(k, v) for k, v in ing["req"]["headers"]]
        if ing["req"]["body_b64"]:
            parts.append(base64.b64decode(ing["req"]["body_b64"])
                         .decode("utf-8", "replace"))
        return "\n".join(parts)

    def submitted(self, kind=None):
        """Canaries the tester sent BACK to the app — proof they already hold a
        secret they were never given (a key lifted from JS, a token from a dump)."""
        text = self._req_text()
        return [(t, m) for t, m in self.m["tokens"].items()
                if t in text and (kind is None or m["kind"] == kind)]

    def leaked(self, kind=None):
        """Canaries in the response this actor has not earned the right to see.

        Scans response headers as well as the body: known-cve-dependency plants
        its marker in X-Powered-By.
        """
        text = self._res_text()
        if not text:
            return []
        earned = self.principals
        out = []
        for tok, meta in self.m["tokens"].items():
            if tok not in text:
                continue
            if meta["owner"] in earned:
                continue
            if kind and meta["kind"] != kind:
                continue
            out.append((tok, meta))
        return out

    # -- manifest helpers ---------------------------------------------------
    def is_internal(self, ip):
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(c) for c in self.m["internal_cidrs"])

    def _internal_target(self, e):
        """SSRF reached internal space: by resolved IP, or by an internal-only
        hostname the fetcher never resolved (….internal, the app origin)."""
        if self.is_internal(e.resolved_ip):
            return True
        host = (e.host or "")
        return host.endswith(".internal") or host in ("app", "scorer", "0.0.0.0")

    def escaped_root(self, e):
        """True if a resolved path left the root the app intended. Containment is
        a judgement, so the tap reports resolved+root and the scorer decides."""
        resolved, root = e.resolved, e.root
        return bool(resolved and root) and not resolved.startswith(root)
