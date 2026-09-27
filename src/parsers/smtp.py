import hashlib
import re

from src.schema import EmailInfo, SMTPInfo

_RESPONSE = re.compile(r"^(\d{3})(?:[ -])(.*)$")
_COMMAND = re.compile(
    r"^(EHLO|HELO|MAIL\s+FROM:|RCPT\s+TO:|DATA|QUIT|RSET|NOOP)(?:\s+(.*))?$",
    re.IGNORECASE,
)
_ATTACHMENT = re.compile(r'filename="?([^";\r\n]+)', re.IGNORECASE)


def parse_smtp(payload, event):
    text = payload.decode("utf-8", errors="replace")
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line]
    if not lines:
        event.parser.warnings.append("Empty SMTP payload")
        return

    first_line = lines[0]
    info = SMTPInfo()
    response = _RESPONSE.match(first_line)
    command = _COMMAND.match(first_line)
    if response:
        info.status_code = int(response.group(1))
        info.response = "\n".join(lines)
    elif command:
        _set_command_fields(info, command.group(1), command.group(2) or "")
    else:
        event.parser.warnings.append(f"Unrecognized SMTP line: {first_line[:80]}")

    event.smtp = info
    email = _parse_email_metadata(text, payload)
    if email is not None:
        event.email = email


def _set_command_fields(info, command, argument):
    normalized = " ".join(command.upper().replace(":", "").split())
    info.command = normalized
    info.argument = argument or None
    if normalized in {"HELO", "EHLO"}:
        info.helo = argument or None
    elif normalized == "MAIL FROM":
        info.mail_from = argument or None
    elif normalized == "RCPT TO" and argument:
        info.rcpt_to.append(argument)


def _parse_email_metadata(text, payload):
    if "\r\n\r\n" in text:
        header_text, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        header_text, body = text.split("\n\n", 1)
    else:
        return None

    headers = {}
    for line in header_text.replace("\r\n", "\n").split("\n"):
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    if not headers:
        return None

    recipients = [value.strip() for value in headers.get("to", "").split(",") if value.strip()]
    attachments = _ATTACHMENT.findall(header_text)
    body_bytes = body.encode("utf-8", errors="replace")
    return EmailInfo(
        from_address=headers.get("from"),
        to=recipients,
        subject=headers.get("subject"),
        date=headers.get("date"),
        message_id=headers.get("message-id"),
        x_mailer=headers.get("x-mailer"),
        attachment=attachments,
        body_md5=hashlib.md5(body_bytes).hexdigest() if body else None,
    )
