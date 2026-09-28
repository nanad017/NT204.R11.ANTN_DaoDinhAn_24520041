from src.parsers.smtp import parse_smtp
from src.schema import PacketEvent


def test_parse_smtp_command_response_and_email_metadata():
    command_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    parse_smtp(b"MAIL FROM: <alice@example.test>\r\n", command_event)

    assert command_event.smtp is not None
    assert command_event.smtp.command == "MAIL FROM"
    assert command_event.smtp.mail_from == "<alice@example.test>"

    response_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    parse_smtp(b"250-mail.example\r\n250 OK\r\n", response_event)

    assert response_event.smtp is not None
    assert response_event.smtp.status_code == 250
    assert response_event.smtp.response is not None

    email_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    parse_smtp(b"From: alice@example.test\r\nTo: bob@example.test\r\nSubject: Hi\r\n\r\nBody", email_event)

    assert email_event.email is not None
    assert email_event.email.from_address == "alice@example.test"
    assert email_event.email.to == ["bob@example.test"]
    assert email_event.email.body_md5 is not None
