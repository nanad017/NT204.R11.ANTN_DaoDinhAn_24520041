from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.config import ProcessingConfig
from src.schema import EndpointInfo, FlowInfo, PacketEvent


class TCPState:
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    RESET = "RESET"


Endpoint = tuple[str, int | None]
FlowKey = tuple[str, Endpoint, Endpoint]


@dataclass
class Flow:
    flow_id: int
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: datetime
    last_seen: datetime
    application_protocol: str | None = None
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_packet_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str = TCPState.NEW
    initiator_direction: str | None = None
    syn_directions: set[str] = field(default_factory=set)
    syn_ack_directions: set[str] = field(default_factory=set)
    fin_directions: set[str] = field(default_factory=set)

    def snapshot(self) -> FlowInfo:
        duration = max(0.0, (self.last_seen - self.start_time).total_seconds())
        return FlowInfo(
            flow_id=self.flow_id,
            protocol=self.protocol,
            application_protocol=self.application_protocol,
            endpoint_a=EndpointInfo(*self.endpoint_a),
            endpoint_b=EndpointInfo(*self.endpoint_b),
            start_time=self.start_time.isoformat(),
            last_seen=self.last_seen.isoformat(),
            duration=duration,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            forward_packet_count=self.forward_packet_count,
            forward_byte_count=self.forward_byte_count,
            backward_packet_count=self.backward_packet_count,
            backward_byte_count=self.backward_byte_count,
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            fin_count=self.fin_count,
            rst_count=self.rst_count,
            state=self.state,
        )


class FlowTracker:
    def __init__(
        self,
        config: ProcessingConfig | None = None,
        *,
        clock=None,
    ):
        self.config = config or ProcessingConfig()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.active: dict[FlowKey, Flow] = {}
        self.completed: list[FlowInfo] = []
        self._next_flow_id = 1

    @property
    def active_flows(self) -> dict[FlowKey, Flow]:
        return self.active

    @property
    def flows(self) -> dict[FlowKey, Flow]:
        return self.active

    def process(self, event: PacketEvent) -> FlowInfo | None:
        protocol = str(event.proto).upper() if event.proto is not None else None
        if protocol not in {"TCP", "UDP"}:
            return None
        event.proto = protocol
        if not self._valid_endpoint(event):
            return None

        seen = _event_time(event, self.clock)
        self.expire(now=seen)
        source = (str(event.src_ip), event.src_port)
        destination = (str(event.dest_ip), event.dest_port)
        key = _flow_key(event.proto, source, destination)
        flow = self.active.get(key)
        if flow is None:
            self._enforce_capacity(seen)
            flow = Flow(
                flow_id=self._next_flow_id,
                protocol=event.proto,
                endpoint_a=source,
                endpoint_b=destination,
                start_time=seen,
                last_seen=seen,
            )
            self._next_flow_id += 1
            self.active[key] = flow

        direction = "forward" if source == flow.endpoint_a else "backward"
        event.flow_id = flow.flow_id
        event.flow_direction = direction
        self._update(flow, event, direction, seen)
        snapshot = flow.snapshot()
        event.flow = snapshot

        if flow.state in {TCPState.CLOSED, TCPState.RESET}:
            self._finalize_key(key, flow)
        return snapshot

    track = process
    update = process

    def expire(self, now: datetime | None = None) -> list[FlowInfo]:
        reference = now or self.clock()
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        expired: list[FlowInfo] = []
        for key, flow in list(self.active.items()):
            timeout = (
                self.config.tcp_idle_timeout
                if flow.protocol == "TCP"
                else self.config.udp_idle_timeout
            )
            if reference >= flow.last_seen and (reference - flow.last_seen).total_seconds() >= timeout:
                expired.append(self._finalize_key(key, flow))
        return expired

    def flush(self) -> list[FlowInfo]:
        result = [self._finalize_key(key, flow) for key, flow in list(self.active.items())]
        return result

    def drain_completed(self) -> list[FlowInfo]:
        result = list(self.completed)
        self.completed.clear()
        return result

    def _update(self, flow: Flow, event: PacketEvent, direction: str, seen: datetime) -> None:
        flow.start_time = min(flow.start_time, seen)
        flow.last_seen = max(flow.last_seen, seen)
        flow.packet_count += 1
        byte_count = _packet_bytes(event)
        flow.byte_count += byte_count
        if direction == "forward":
            flow.forward_packet_count += 1
            flow.forward_byte_count += byte_count
        else:
            flow.backward_packet_count += 1
            flow.backward_byte_count += byte_count
        if event.app_proto and event.app_proto != "unknown":
            flow.application_protocol = event.app_proto

        if flow.protocol != "TCP" or event.tcp is None:
            return
        flags = _flag_set(event.tcp.flags)
        if "SYN" in flags:
            flow.syn_count += 1
            if "ACK" in flags:
                flow.syn_ack_directions.add(direction)
            else:
                flow.syn_directions.add(direction)
                if flow.initiator_direction is None:
                    flow.initiator_direction = direction
        if "ACK" in flags:
            flow.ack_count += 1
        if "FIN" in flags:
            flow.fin_count += 1
            flow.fin_directions.add(direction)
        if "RST" in flags:
            flow.rst_count += 1
            flow.state = TCPState.RESET
            return

        if "FIN" in flags:
            flow.state = TCPState.CLOSED if len(flow.fin_directions) == 2 else TCPState.CLOSING
            return

        if flow.state == TCPState.NEW and "SYN" in flags:
            flow.state = TCPState.HANDSHAKE
        if flow.state == TCPState.HANDSHAKE:
            handshake_complete = (
                flow.initiator_direction is not None
                and flow.syn_directions
                and flow.syn_ack_directions
                and "ACK" in flags
                and direction == flow.initiator_direction
            )
            if handshake_complete:
                flow.state = TCPState.ESTABLISHED

    def _enforce_capacity(self, now: datetime) -> None:
        self.expire(now=now)
        if len(self.active) < self.config.max_active_flows:
            return
        oldest_key, oldest = min(self.active.items(), key=lambda item: item[1].last_seen)
        self._finalize_key(oldest_key, oldest)

    def _finalize_key(self, key: FlowKey, flow: Flow) -> FlowInfo:
        snapshot = flow.snapshot()
        self.active.pop(key, None)
        self.completed.append(snapshot)
        return snapshot

    @staticmethod
    def _valid_endpoint(event: PacketEvent) -> bool:
        return (
            isinstance(event.src_ip, str)
            and isinstance(event.dest_ip, str)
            and isinstance(event.src_port, int)
            and isinstance(event.dest_port, int)
            and 0 <= event.src_port <= 65535
            and 0 <= event.dest_port <= 65535
        )


FlowTable = FlowTracker


def _flow_key(protocol: str, source: Endpoint, destination: Endpoint) -> FlowKey:
    return (protocol, min(source, destination), max(source, destination))


def _event_time(event: PacketEvent, clock) -> datetime:
    try:
        result = datetime.fromisoformat(str(event.timestamp).replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return clock()


def _packet_bytes(event: PacketEvent) -> int:
    if isinstance(event.packet_length, int) and event.packet_length >= 0:
        return event.packet_length
    if event.ip is not None and isinstance(event.ip.total_length, int) and event.ip.total_length >= 0:
        return event.ip.total_length
    ip_header = event.ip.header_length if event.ip and event.ip.header_length else 20
    if event.tcp is not None:
        return ip_header + (event.tcp.header_length or 20) + event.tcp.payload_length
    if event.udp is not None:
        return ip_header + (event.udp.length or (8 + event.udp.payload_length))
    return 0


def _flag_set(flags) -> set[str]:
    if isinstance(flags, str):
        aliases = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST"}
        if flags in aliases:
            return {aliases[flags]}
        return {aliases[flag] for flag in flags if flag in aliases}
    return set(flags or [])
