"""Read one bounded, newline-delimited request under a total deadline.

This is protocol framing, not an authentication or authorization decision.

Three deadlines govern one call, and they nest. ``FRAME_TIMEOUT`` bounds how
long a *listener* waits for a caller to finish sending its frame: a caller is
local and has nothing to wait for. ``BROKER_REPLY_DEADLINE`` bounds how long
anything that forwards a frame *to* the broker waits for its answer, and
``RELAYED_REPLY_DEADLINE`` bounds how long a client of such a forwarder waits
for that forwarder's answer. Each covers the one it contains and every leg
between them, so of the hops that wait, the one nearest the broker gives up
first and is the one that says why. These are shared protocol constants, not
knowledge of any service.

The broker itself never gives up. Once it has read a frame it runs it, even
after its forwarder has stopped waiting, and ``BROKER_REPLY_DEADLINE`` covers
one request's own work, not time spent queued: the broker runs requests one at
a time, and an OAuth vault lock may be held by another session. So a request
answered ``outcome_unknown`` may still be carried out *after* that answer, and
a check made straight away that finds nothing applied does not prove it never
will be.
"""
from __future__ import annotations
import socket
import time
from ..errors import SecretsError
from ..primitives import codec

FRAME_TIMEOUT = 5.0
# How long a forwarder may take to *reach* the broker before anything is
# sent. A failure here is definite: no frame left this process.
CONNECT_TIMEOUT = 5.0
# The broker answers only after its own egress: a preflight and a final call,
# each bounded by ``host/egress.TOTAL_DEADLINE`` (45 s), plus credential and
# audit work. 120 s is that worst case for one request with margin; it does
# not include waiting behind other requests (see above). Waiting less is not
# merely impatient: the broker keeps going after the forwarder gives up, so a
# write the caller was told had failed could still be applied.
BROKER_REPLY_DEADLINE = 120.0
# Once a client of the identity bridge has sent its frame, the bridge may
# still be reading it (FRAME_TIMEOUT), then connects to the broker and sends
# it on (CONNECT_TIMEOUT each), waits for the broker, and sends the answer
# back (FRAME_TIMEOUT).
RELAYED_REPLY_DEADLINE = (BROKER_REPLY_DEADLINE + 2 * CONNECT_TIMEOUT
                          + 2 * FRAME_TIMEOUT)


def read_frame(
    sock: socket.socket,
    *,
    limit: int = codec.MAX_FRAME,
    timeout: float = FRAME_TIMEOUT,
) -> bytes:
    """Read exactly one newline-terminated frame under an absolute deadline.

    The deadline is for the whole frame, not renewed per byte, and anything
    after the newline -- a pipelined second request -- is a protocol error.

    Every failure is ``invalid_request``, which is right for a *listener*
    reading a request: nothing has been done yet. A forwarder reading the
    broker's *reply* has already dispatched a request and must not pass this
    code on; see ``identity/service.py``.
    """
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretsError('invalid_request')
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(16384, limit + 1 - len(data)))
        except (OSError, TimeoutError):
            raise SecretsError('invalid_request') from None
        if not chunk:
            raise SecretsError('invalid_request')
        data.extend(chunk)
        if len(data) > limit:
            raise SecretsError('invalid_request')
        if b'\n' in data:
            line, trailing = bytes(data).split(b'\n', 1)
            if trailing:
                raise SecretsError('invalid_request')
            return line
