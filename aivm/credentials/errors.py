"""Provider-neutral outcomes of a deploy-key request.

These live apart from any one forge backend because the lifecycle layer
dispatches across providers: it has to distinguish "the forge decided and
changed nothing" from "the forge would not tell us" without knowing which
backend produced the failure. Defining them per-backend produced two distinct
classes with the same name, so ``except ProviderRejectedError`` meant different
things depending on the import.
"""

from __future__ import annotations

from ..errors import AIVMError


class ProviderRejectedError(AIVMError):
    """Raised when a forge validated a request and refused it outright.

    A 4xx response means the provider reached a decision and changed nothing:
    the deploy key was not created. That is materially different from a
    timeout or a 5xx, where the provider may have acted and AIVM must keep
    local state so the key can still be found and revoked. Only this error
    lets a caller discard state recorded in anticipation of the call.
    """


class ProviderPermissionError(AIVMError):
    """Raised when the authenticated identity may not administer deploy keys.

    Deliberately *not* a subclass of :class:`ProviderRejectedError`. Nothing
    was created either way, but this one is fixable out of band: deploy-key
    endpoints need admin permission on the repository, which write access does
    not confer, so an admin can add the public key AIVM already generated. The
    pending credential and its keypair must therefore survive, and a sibling
    type means a caller that only handles rejection cannot discard them by
    accident.
    """
