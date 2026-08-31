"""Captured outbox. send() takes attacker-influenced headers verbatim so newline
injection adds Bcc/extra headers, and stored bodies are a blind-XSS landing spot."""
outbox = []


def send(to, subject, body, extra_headers=""):
    headers = {"To": to, "Subject": subject}
    raw = f"To: {to}\r\nSubject: {subject}\r\n{extra_headers}"
    for line in raw.split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    msg = {"headers": headers, "body": body}
    outbox.append(msg)
    return msg
