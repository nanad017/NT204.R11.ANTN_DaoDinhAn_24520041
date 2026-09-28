from src.parsers.http import parse_http
from src.schema import PacketEvent


def test_parse_http_request_and_response():
    request_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00", dest_port=80)
    parse_http(
        b"POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Length: 2\r\n\r\nok",
        request_event,
    )

    assert request_event.http is not None
    assert request_event.http.http_method == "POST"
    assert request_event.http.url == "/login"
    assert request_event.http.hostname == "example.test"
    assert request_event.http.body == "ok"

    response_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00", src_port=80)
    parse_http(b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\n", response_event)

    assert response_event.http is not None
    assert response_event.http.status == 201
    assert response_event.http.http_content_type == "text/plain"
