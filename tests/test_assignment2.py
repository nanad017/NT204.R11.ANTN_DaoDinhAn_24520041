from datetime import datetime, timezone

from src.config import ProcessingConfig
from src.decoder import Decoder
from src.flow_tracker import FlowTracker, TCPState
from src.preprocessor import Preprocessor
from src.pipeline import build_pipeline_handler
from src.schema import HTTPHeader, HTTPInfo, PacketEvent, SMTPInfo, TCPInfo, UDPInfo


def event(**kwargs):
    defaults = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.1",
        "src_port": 50000,
        "dest_port": 80,
        "proto": "TCP",
        "packet_length": 60,
    }
    defaults.update(kwargs)
    return PacketEvent(**defaults)


def tcp_event(flags, *, timestamp="2026-01-01T00:00:00+00:00", **kwargs):
    return event(
        timestamp=timestamp,
        tcp=TCPInfo(flags=list(flags), payload_length=0),
        **kwargs,
    )


def test_t01_http_url_decoding_preserves_raw_uri():
    packet_event = event(http=HTTPInfo(url="/search?q=%27%20OR%201%3D1+literal"))
    Decoder().decode_event(packet_event)

    assert packet_event.http.raw_url == "/search?q=%27%20OR%201%3D1+literal"
    assert packet_event.http.decoded_url == "/search?q=' OR 1=1+literal"
    assert packet_event.http.decoded_query == "q=' OR 1=1+literal"


def test_t02_html_entity_decoding_is_separate_from_raw_body():
    packet_event = event(http=HTTPInfo(body="&lt;script&gt;alert(1)&lt;/script&gt;", http_content_type="text/html"))
    Decoder().decode_event(packet_event)

    assert packet_event.http.raw_body == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert packet_event.http.html_decoded_body == "<script>alert(1)</script>"


def test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it():
    base64_event = event(smtp=SMTPInfo(), proto="TCP", dest_port=25)
    Decoder().decode_event(
        base64_event,
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQh",
    )
    qp_event = event(smtp=SMTPInfo(), proto="TCP", dest_port=25)
    Decoder().decode_event(
        qp_event,
        b"Content-Type: text/plain\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\nHello=20world!",
    )

    assert base64_event.email.decoded_body == "Hello World!"
    assert base64_event.email.decode_status == "success"
    assert qp_event.email.decoded_body == "Hello world!"
    assert qp_event.email.decode_status == "success"


def test_t04_invalid_utf8_is_partial_and_does_not_raise():
    packet_event = event(smtp=SMTPInfo(), proto="TCP", dest_port=25)
    Decoder().decode_event(
        packet_event,
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n//4=",
    )

    assert packet_event.decoder.status == "partial"
    assert packet_event.email.decode_status == "partial"


def test_t05_normalization_is_consistent_and_does_not_lower_uri():
    packet_event = event(
        proto="tcp",
        app_proto="HTTP",
        timestamp="2026-01-01T00:00:00Z",
        http=HTTPInfo(
            hostname="Example.TEST.",
            url="/CaseSensitive/Path",
            request_headers=[HTTPHeader("Host", "Example.TEST.")],
        ),
    )
    Preprocessor().process(packet_event)

    assert packet_event.proto == "TCP"
    assert packet_event.app_proto == "http"
    assert packet_event.http.hostname == "example.test"
    assert packet_event.http.request_headers[0].name == "host"
    assert packet_event.http.request_headers[0].original_name == "Host"
    assert packet_event.http.url == "/CaseSensitive/Path"
    assert packet_event.http.normalized_url == "/CaseSensitive/Path"


def test_t06_missing_fields_have_invalid_status_without_exception():
    packet_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    Preprocessor().process(packet_event)

    assert packet_event.preprocess.status == "invalid"
    assert packet_event.preprocess.processing_action == "retain"
    assert "src_ip is required" in packet_event.preprocess.reason


def test_t07_tcp_handshake_reaches_established_in_one_flow():
    tracker = FlowTracker()
    syn = tcp_event(["SYN"], timestamp="2026-01-01T00:00:00+00:00")
    synack = tcp_event(
        ["SYN", "ACK"],
        timestamp="2026-01-01T00:00:01+00:00",
        src_ip="198.51.100.1", dest_ip="192.0.2.1", src_port=80, dest_port=50000,
    )
    ack = tcp_event(["ACK"], timestamp="2026-01-01T00:00:02+00:00")

    tracker.process(syn)
    tracker.process(synack)
    summary = tracker.process(ack)

    assert summary.state == TCPState.ESTABLISHED
    assert len(tracker.active) == 1
    assert syn.flow_id == synack.flow_id == ack.flow_id


def test_t08_bidirectional_packets_share_id_and_direction_is_stable():
    tracker = FlowTracker()
    forward = tracker.process(event())
    reverse_event = event(src_ip="198.51.100.1", dest_ip="192.0.2.1", src_port=80, dest_port=50000)
    backward = tracker.process(reverse_event)

    assert forward.flow_id == backward.flow_id
    assert reverse_event.flow_direction == "backward"


def test_t09_fin_close_and_rst_are_terminal_states():
    tracker = FlowTracker()
    tracker.process(tcp_event(["SYN"]))
    tracker.process(tcp_event(["SYN", "ACK"], src_ip="198.51.100.1", dest_ip="192.0.2.1", src_port=80, dest_port=50000))
    tracker.process(tcp_event(["ACK"]))
    tracker.process(tcp_event(["FIN"], timestamp="2026-01-01T00:00:03+00:00"))
    closed = tracker.process(tcp_event(["FIN", "ACK"], timestamp="2026-01-01T00:00:04+00:00", src_ip="198.51.100.1", dest_ip="192.0.2.1", src_port=80, dest_port=50000))
    assert closed.state == TCPState.CLOSED
    assert not tracker.active

    reset = tracker.process(tcp_event(["RST"], timestamp="2026-01-01T00:00:05+00:00"))
    assert reset.state == TCPState.RESET
    assert not tracker.active


def test_t10_udp_query_response_is_one_bidirectional_flow():
    tracker = FlowTracker()
    query = event(proto="UDP", src_port=53000, dest_port=53, udp=UDPInfo(length=40, payload_length=32), packet_length=60)
    response = event(proto="UDP", src_ip="198.51.100.1", dest_ip="192.0.2.1", src_port=53, dest_port=53000, udp=UDPInfo(length=80, payload_length=72), packet_length=100)
    tracker.process(query)
    summary = tracker.process(response)

    assert summary.packet_count == 2
    assert summary.byte_count == 160
    assert summary.forward_packet_count == 1
    assert summary.backward_packet_count == 1


def test_t11_concurrent_five_tuples_remain_separate():
    tracker = FlowTracker()
    first = tracker.process(event(dest_port=80))
    second = tracker.process(event(dest_port=443))

    assert first.flow_id != second.flow_id
    assert len(tracker.active) == 2


def test_t12_idle_timeout_removes_flow_and_keeps_final_summary():
    tracker = FlowTracker(ProcessingConfig(tcp_idle_timeout=5, udp_idle_timeout=5))
    tracker.process(event(proto="UDP", timestamp="2026-01-01T00:00:00+00:00"))
    expired = tracker.expire(now=datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc))

    assert len(expired) == 1
    assert not tracker.active
    assert tracker.completed[0].packet_count == 1


def test_t13_statistics_count_full_packet_bytes_and_duration():
    tracker = FlowTracker()
    tracker.process(event(proto="UDP", packet_length=70, timestamp="2026-01-01T00:00:00+00:00"))
    summary = tracker.process(event(proto="UDP", packet_length=90, timestamp="2026-01-01T00:00:05+00:00"))

    assert summary.packet_count == 2
    assert summary.byte_count == 160
    assert summary.forward_byte_count == 160
    assert summary.duration == 5.0


def test_t14_malformed_event_is_safe_and_meaningful():
    packet_event = PacketEvent(
        timestamp="not-a-timestamp",
        src_ip="not-an-ip",
        dest_ip="198.51.100.1",
        src_port=70000,
        dest_port=80,
        proto="TCP",
    )
    Preprocessor(ProcessingConfig(invalid_event_policy="retain")).process(packet_event)

    assert packet_event.preprocess.status == "invalid"
    assert packet_event.preprocess.reason
    assert FlowTracker().process(packet_event) is None


def test_pipeline_runs_decoder_preprocessor_and_flow_tracker_in_order():
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    emitted = []
    handler = build_pipeline_handler("pcap", emitted.append)
    packet_event = handler(
        IP(src="192.0.2.1", dst="198.51.100.1")
        / TCP(sport=50000, dport=8080, flags="PA")
        / Raw(b"GET /q/%27 HTTP/1.1\r\nHost: Example.TEST\r\n\r\n")
    )

    assert packet_event.http.decoded_url == "/q/'"
    assert packet_event.http.hostname == "example.test"
    assert packet_event.decoder.status == "success"
    assert packet_event.preprocess.status in {"valid", "partial"}
    assert packet_event.flow_id == 1
    assert packet_event.flow_direction == "forward"
    assert emitted == [packet_event]


def test_end_of_capture_flushes_active_flows_to_flow_handler():
    from scapy.layers.inet import IP, UDP

    finalized = []
    handler = build_pipeline_handler("pcap", flow_handler=finalized.append)
    handler(IP(src="192.0.2.1", dst="198.51.100.1") / UDP(sport=53000, dport=53))

    summaries = handler.flush()

    assert len(summaries) == 1
    assert finalized[0].flow_id == summaries[0].flow_id
    assert not handler.flow_tracker.active


def test_five_tuple_reuse_after_reset_creates_a_new_flow_instance():
    tracker = FlowTracker()
    first = tracker.process(tcp_event(["RST"]))
    second = tracker.process(tcp_event(["SYN"], timestamp="2026-01-01T00:00:01+00:00"))

    assert first.flow_id != second.flow_id
    assert second.state == TCPState.HANDSHAKE


def test_out_of_order_timestamps_are_monotonic_for_duration():
    tracker = FlowTracker()
    tracker.process(event(proto="UDP", timestamp="2026-01-01T00:00:10+00:00"))
    summary = tracker.process(event(proto="UDP", timestamp="2026-01-01T00:00:05+00:00"))

    assert summary.start_time.endswith("00:00:05+00:00")
    assert summary.last_seen.endswith("00:00:10+00:00")
    assert summary.duration == 5.0


def test_partial_tcp_capture_does_not_fabricate_established_state():
    tracker = FlowTracker()
    summary = tracker.process(tcp_event(["ACK"]))

    assert summary.state == TCPState.NEW


def test_invalid_ports_and_unsupported_mime_encoding_are_reported():
    invalid = event(src_port=65536)
    Preprocessor().process(invalid)
    assert invalid.preprocess.status == "invalid"

    mime = event(smtp=SMTPInfo(), dest_port=25)
    Decoder().decode_event(mime, b"Content-Transfer-Encoding: x-custom\r\n\r\nvalue")
    assert mime.decoder.status == "partial"
    assert mime.decoder.errors


def test_decoder_size_limit_is_partial_not_fatal():
    packet_event = event(http=HTTPInfo(body="0123456789", http_content_type="text/plain"))
    Decoder(ProcessingConfig(max_decoded_content_size=4)).decode_event(packet_event)

    assert packet_event.http.decoded_body == "0123"
    assert packet_event.decoder.status == "partial"
