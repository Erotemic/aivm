"""Independent secret-use broker: a guest uses a credential it never holds.

``aivm_secrets.kernel`` is the pure authorization state machine;
``aivm_secrets.host`` is the trusted shell that performs I/O for it;
``aivm_secrets.guest`` is the untrusted client; ``aivm_secrets.cli`` is the
operator's ``aivm-secrets`` command. The package never imports AIVM.

Importing it initializes nothing: no cryptography, network or service.
The implementation is tested Python, not formally verified code.
"""

__version__ = '0.2.0'
