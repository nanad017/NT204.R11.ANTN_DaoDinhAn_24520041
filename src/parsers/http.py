from src.schema import HTTPHeader, HTTPInfo


def parse_http(payload, event):
    text = payload.decode("utf-8", errors="replace")
    header_text, body = _split_message(text)
    lines = header_text.splitlines()
    if not lines:
        event.parser.warnings.append("Empty HTTP payload")
        return

    start_line = lines[0].strip()
    headers = _parse_headers(lines[1:], event)
    header_map = {header.name.lower(): header.value for header in headers}
    info = HTTPInfo(
        hostname=header_map.get("host"),
        http_port=_http_port(event),
        http_user_agent=header_map.get("user-agent"),
        http_content_type=header_map.get("content-type"),
        cookie=header_map.get("cookie"),
        http_refer=header_map.get("referer"),
        length=_content_length(header_map, len(body.encode("utf-8"))),
        body=body or None,
    )

    if start_line.upper().startswith("HTTP/"):
        _parse_response_start_line(start_line, info, event)
        info.response_headers = headers
    else:
        _parse_request_start_line(start_line, info, event)
        info.request_headers = headers

    event.http = info


def _split_message(text):
    if "\r\n\r\n" in text:
        return tuple(text.split("\r\n\r\n", 1))
    if "\n\n" in text:
        return tuple(text.split("\n\n", 1))
    return text, ""


def _parse_headers(lines, event):
    headers = []
    for line in lines:
        if not line:
            continue
        if ":" not in line:
            event.parser.warnings.append(f"Malformed HTTP header: {line[:80]}")
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if not name:
            event.parser.warnings.append("HTTP header with empty name")
            continue
        headers.append(HTTPHeader(name=name, value=value.strip()))
    return headers


def _parse_request_start_line(
    start_line,
    info,
    event,
):
    parts = start_line.split()
    if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
        event.parser.warnings.append(f"Malformed HTTP request line: {start_line[:80]}")
        return
    info.http_method = parts[0].upper()
    info.url = parts[1]
    info.protocol = parts[2].upper()


def _parse_response_start_line(
    start_line,
    info,
    event,
):
    parts = start_line.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        event.parser.warnings.append(f"Malformed HTTP status line: {start_line[:80]}")
        return
    info.protocol = parts[0].upper()
    try:
        info.status = int(parts[1])
    except ValueError:
        event.parser.warnings.append(f"Invalid HTTP status code: {parts[1]}")


def _content_length(headers, fallback):
    value = headers.get("content-length")
    if value is None:
        return fallback if fallback else None
    try:
        return int(value)
    except ValueError:
        return fallback if fallback else None


def _http_port(event):
    return event.dest_port or event.src_port
