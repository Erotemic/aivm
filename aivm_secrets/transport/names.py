"""Fixed names of broker's Unix sockets.

The identity bridge may connect ONLY to the guest request socket.
"""
GUEST_SOCKET = 'broker.sock'
CONTROL_SOCKET = 'control.sock'
