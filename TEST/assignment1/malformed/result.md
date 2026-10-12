# Result: Malformed Packet

Source: intentionally invalid capture file.

Expected: invalid input does not crash the program.

Actual: the program reports `Not a supported capture file` in `run.log` and
exits with code 1 without an unhandled traceback.

Result: PASS
