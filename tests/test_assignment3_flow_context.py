from src.flow_tracker import FlowTracker, TCPState
from src.schema import PacketEvent, TCPInfo, UDPInfo


def _tcp_event(
    flags,
    *,
    reverse=False,
    timestamp="2026-01-01T00:00:00+00:00",
):
    endpoints = (
        {
            "src_ip": "198.51.100.1",
            "src_port": 80,
            "dest_ip": "192.0.2.1",
            "dest_port": 50000,
        }
        if reverse
        else {
            "src_ip": "192.0.2.1",
            "src_port": 50000,
            "dest_ip": "198.51.100.1",
            "dest_port": 80,
        }
    )
    return PacketEvent(
        timestamp=timestamp,
        proto="TCP",
        packet_length=60,
        tcp=TCPInfo(flags=list(flags)),
        **endpoints,
    )


def test_tcp_flow_context_exposes_client_server_role_and_established_state():
    tracker = FlowTracker()
    syn = _tcp_event(["SYN"])
    syn_ack = _tcp_event(
        ["SYN", "ACK"],
        reverse=True,
        timestamp="2026-01-01T00:00:01+00:00",
    )
    ack = _tcp_event(["ACK"], timestamp="2026-01-01T00:00:02+00:00")

    tracker.process(syn)
    tracker.process(syn_ack)
    summary = tracker.process(ack)

    assert syn.flow_role == "to_server"
    assert syn_ack.flow_role == "to_client"
    assert ack.flow_role == "to_server"
    assert summary.state == TCPState.ESTABLISHED
    assert summary.established is True
    assert summary.initiator_direction == "forward"
    assert summary.client_endpoint.ip == "192.0.2.1"
    assert summary.client_endpoint.port == 50000
    assert summary.server_endpoint.ip == "198.51.100.1"
    assert summary.server_endpoint.port == 80


def test_udp_flow_uses_stable_first_seen_client_server_fallback():
    tracker = FlowTracker()
    query = PacketEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        proto="UDP",
        src_ip="192.0.2.1",
        src_port=53000,
        dest_ip="198.51.100.1",
        dest_port=53,
        packet_length=60,
        udp=UDPInfo(length=40, payload_length=32),
    )
    response = PacketEvent(
        timestamp="2026-01-01T00:00:01+00:00",
        proto="UDP",
        src_ip="198.51.100.1",
        src_port=53,
        dest_ip="192.0.2.1",
        dest_port=53000,
        packet_length=100,
        udp=UDPInfo(length=80, payload_length=72),
    )

    tracker.process(query)
    summary = tracker.process(response)

    assert query.flow_role == "to_server"
    assert response.flow_role == "to_client"
    assert summary.established is False
    assert summary.client_endpoint.ip == "192.0.2.1"
    assert summary.server_endpoint.ip == "198.51.100.1"


def test_syn_ack_first_infers_roles_without_fabricating_established_state():
    tracker = FlowTracker()
    syn_ack = _tcp_event(["SYN", "ACK"], reverse=True)

    summary = tracker.process(syn_ack)

    assert syn_ack.flow_direction == "forward"
    assert syn_ack.flow_role == "to_client"
    assert summary.client_endpoint.ip == "192.0.2.1"
    assert summary.server_endpoint.ip == "198.51.100.1"
    assert summary.initiator_direction is None
    assert summary.established is False


def test_established_context_persists_while_tcp_flow_is_closing():
    tracker = FlowTracker()
    tracker.process(_tcp_event(["SYN"]))
    tracker.process(
        _tcp_event(
            ["SYN", "ACK"],
            reverse=True,
            timestamp="2026-01-01T00:00:01+00:00",
        )
    )
    tracker.process(_tcp_event(["ACK"], timestamp="2026-01-01T00:00:02+00:00"))

    closing = tracker.process(
        _tcp_event(["FIN", "ACK"], timestamp="2026-01-01T00:00:03+00:00")
    )

    assert closing.state == TCPState.CLOSING
    assert closing.established is True
