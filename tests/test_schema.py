import json

from src.schema import PacketEvent, TCPInfo


def test_schema_to_dict_removes_empty_values_and_keeps_falsey_data():
    event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00", pcap_cnt=0)
    event.tcp = TCPInfo(seq=0, ack=0, payload_length=0)

    data = event.to_dict()

    assert data["pcap_cnt"] == 0
    assert data["tcp"]["seq"] == 0
    assert data["tcp"]["payload_length"] == 0
    assert "ether" not in data
    assert json.loads(json.dumps(data)) == data
