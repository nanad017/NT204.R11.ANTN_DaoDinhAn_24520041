from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessingConfig:
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0
    max_active_flows: int = 100_000
    max_decoded_content_size: int = 1_048_576
    invalid_event_policy: str = "retain"
    unsupported_data_policy: str = "retain"

    def __post_init__(self):
        if self.tcp_idle_timeout < 0 or self.udp_idle_timeout < 0:
            raise ValueError("flow idle timeouts must be non-negative")
        if self.max_active_flows <= 0:
            raise ValueError("max_active_flows must be positive")
        if self.max_decoded_content_size <= 0:
            raise ValueError("max_decoded_content_size must be positive")
        if self.invalid_event_policy not in {"retain", "skip"}:
            raise ValueError("invalid_event_policy must be retain or skip")
        if self.unsupported_data_policy not in {"retain", "skip"}:
            raise ValueError("unsupported_data_policy must be retain or skip")
