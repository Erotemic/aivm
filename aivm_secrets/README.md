# aivm-secrets (experimental)

An experimental Python broker for using host-held service credentials through
explicitly authorized operations. **Unaudited: not approved for production
credentials or unattended privileged use.** It is not a TPM or hardware identity
service and it is not a formally verified implementation.

This source currently lives alongside AIVM, but builds an **independent** Python
wheel. The ordinary AIVM wheel does not contain this package or its executable.
An independent repository is planned; see the source checkout's
`docs/planning/aivm-secrets-repository-boundary.md` for the transition rules.

For development from a trusted host checkout (not a guest-writable directory):

```bash
python -m pip install ./aivm_secrets
python -m aivm_secrets --help
```

The broker uses a separate process and a restricted, versioned operation
interface. Review the operation policy and test with synthetic credentials
before using it with a real service.
