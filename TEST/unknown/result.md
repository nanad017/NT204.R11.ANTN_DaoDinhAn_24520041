# Result: Unknown Protocol

Source: synthetic IPv4 packet using unsupported transport protocol 99.

Expected: unsupported protocol traffic does not crash the program.

Actual: the program exits with code 0 and emits one event containing the
warning `Unsupported IPv4 transport protocol`.

Result: PASS
