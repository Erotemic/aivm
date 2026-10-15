# Garrett identity: vTPM key policy

**Status (2026-10-13): design only. No VM has a TPM, and no claim in this
document may be made until it is implemented and validated on real libvirt
with swtpm.** AIVM creates every VM with `virt-install --tpm none`
(`aivm/vm/create.py`, asserted by `tests/test_vm_create.py`). The guest
identity key is a software P-256 key that `aivm-guestctl` generates with
`/usr/bin/openssl req -newkey ec` as the guest user, in
`~/.config/aivm/identity/client.key` (`aivm/rc/guest/guestctl.py`). The
open obligation is VTPM-01 in [the assumption ledger](aivm-secrets-assumptions.json).
Statements about libvirt, QEMU and swtpm behavior below are from their
documentation and are **unverified** here: no libvirt, KVM or TPM was
available.

## What a vTPM would change, and what it would not

It would change one thing. The private key would exist only as a blob
wrapped by the VM's virtual TPM, which only that TPM can load. Reading the
guest user's files, or the guest disk, would no longer yield a usable key.

It would not change these:

- **Use is not export.** Any guest process that can reach the TPM and holds
  the key's authorization value can sign with the key. That is everything a
  compromised guest needs to answer mTLS handshakes, including handshakes
  it relays for someone elsewhere. Today the same holds for any process that
  can read `client.key`.
- **The vTPM is a host file.** swtpm is software on the host, and its state
  is a file there. Host administrators, and anything else that can read
  libvirt's swtpm state, can copy the whole TPM, key included, to another
  domain. "Non-exportable" means non-exportable *from the guest*, and nothing
  more.
- **It is not a hardware root of trust.** No physical TPM is involved, and
  nothing here attests the host.

## swtpm state: owner, location, lifecycle

- **Owner.** For the system connection, libvirt starts one swtpm process per
  domain under the user configured as `swtpm_user` in `qemu.conf`. The state
  is machine state, like the domain's disk: no access principal reads or
  copies it, and AIVM never backs it up or copies it.
- **Location.** libvirt keeps per-domain state keyed by domain UUID, by
  default under `/var/lib/libvirt/swtpm/<domain UUID>/` for `qemu:///system`.
  A domain defined with a new UUID gets fresh state unless someone copies the
  directory.
- **Creation is opt-in per VM** and changes the VM's shape (for example
  `virt-install --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb`).
  Existing VMs are not changed. Adding a TPM to an existing VM is a
  redefinition that needs the user's consent, like any other domain change.
- **Manufacture and EK.** At creation, the EK certificate must be issued by
  the host's swtpm local CA (`swtpm_setup --create-ek-cert`). Its public key
  goes into the decided principal-private enrollment record in the VM
  profile's state directory. This lets the host recognize "the TPM AIVM
  created for this VM" later. It cannot recognize a byte copy of that TPM,
  which has the same EK.
- **Deletion.** The state is destroyed with the domain. libvirt's default
  for keeping TPM state at undefine differs between versions and depends on
  the `persistent_state` attribute. AIVM's delete must therefore remove the
  state explicitly and check that it is gone.

## Snapshots and revert

QEMU treats the emulated TPM's state as device state, so a memory-inclusive
snapshot can carry it. Whether a disk-only or external snapshot carries it
depends on the libvirt version. The policy does not depend on either answer:

- AIVM assumes a revert may restore an older TPM state together with the disk
  (an older key, older NV values). It also assumes a revert may restore an
  older disk while keeping the current TPM state, in which case the wrapped
  key blob on disk can still load under the unchanged parent.
- In both cases the [rollback and clone policy](aivm-secrets-garrett-rollback-clone-policy.md)
  applies unchanged. The host registry stays authoritative, and a revert ends
  in re-enrollment when the reverted key is not the enrolled one.
- **A vTPM NV counter is not an anchor for anything,** because a revert can
  roll it back together with the guest. Host rollback detection uses the host
  TPM or a remote witness, never the guest's vTPM.

## Clones

- A clone gets **reset TPM state and a new subject.** AIVM never copies swtpm
  state, whether for a clone, a backup or a migration.
- A clone that carries copied state (made outside AIVM) holds a duplicate of
  the key. Neither the vTPM, EK pinning nor TPM2_Certify can tell the copies
  apart. The decided host key custody rule, defined in the rollback and
  clone policy, refuses the second enrollment while the first is active: no
  key is certified under two active subjects at once. Once the original is
  revoked, that rule no longer refuses the copied key, and no evidence tells
  the copy apart, so only AIVM's own clone path (reset state and a new
  subject) gives a clone a key of its own. Nothing stops the copy from
  *using* the key, if it can reach a bridge that admits it.

## Key template

- **Parent:** the owner-hierarchy storage primary key: ECC P-256 with the
  standard TCG storage-key template, created (and optionally persisted) by
  guestctl.
- **Identity key:** ECC NIST P-256, ECDSA with SHA-256.
  - Attributes: exactly `fixedTPM | fixedParent | sensitiveDataOrigin |
    userWithAuth | sign`.
  - Not `decrypt`. Not `restricted`, because a restricted key refuses to
    sign the external digests a TLS 1.3 `CertificateVerify` needs.
  - `fixedParent` already rules out duplication, so no duplication policy is
    set.
- **Authorization value:** random, stored mode 0600 in the guest user's
  identity directory. Access to the TPM device alone (for example via the
  `tss` group) then does not confer use of the key. Root in the guest can
  still use it.
- **Optional PCR policy:** an `authPolicy` of `PolicyPCR` over a chosen PCR
  selection. Off by default, and opt-in per VM with its consequence
  documented. AIVM VMs boot UEFI with Secure Boot off and take kernel and
  firmware updates, so a PCR-sealed key stops working after an update. Unless
  the PCR values are checked against a reference, a PCR policy is not a claim
  of code integrity either.

## CSR creation inside guestctl

- A new closed forced operation (proposed: `identity-tpm-csr`) in
  `aivm-guestctl`. Like `identity-csr` today, it runs fixed absolute programs
  under `runuser` as the guest user, with the same minimal environment. That
  environment deliberately inherits no OpenSSL settings from its caller, so
  the provider is selected on the command line:
  `/usr/bin/openssl genpkey -provider tpm2 -provider default -algorithm EC
  -pkeyopt group:P-256 ...`, then `/usr/bin/openssl req -provider tpm2
  -provider default -new -key <TSS2 key> -subj /CN=aivm-guest ...`.
- **Guest prerequisites:** the `tpm2-openssl` and `tpm2-tools` packages, and
  TPM device access for the guest user. These are guest system changes. They
  happen through an explicit, consented guest maintenance action, never as a
  side effect of a secrets operation.
- guestctl reads the created key's public area and refuses unless its
  attributes equal the template exactly. The host does not rely on that check,
  because guest root can lie. The host's only TPM evidence is TPM2_Certify,
  below.
- The host keeps today's CSR rules unchanged: proof of possession, no
  extensions, a confirmed fingerprint, a subject derived from host facts. A
  CSR signature shows that the requester can sign with the key. It shows
  nothing about where the key lives.
- **Unvalidated prerequisite: the TLS client.** The guest bound client is a
  single standard-library Python file. It loads the key with
  `ssl.SSLContext.load_cert_chain` (`aivm_secrets/guest.py`). Using a
  TPM-resident key requires the `tpm2` provider in that process's OpenSSL
  library context, for example through a fixed configuration file passed by
  absolute path, or a different signer. Proving that this works on the guest
  OS's OpenSSL is a precondition of the design, not a detail.

## Optional TPM2_Certify evidence

The flow:

1. At creation, the host records the vTPM's EK public key, from an EK
   certificate that chains to the host's swtpm local CA.
2. The guest creates an attestation key (AK), a restricted signing key. The
   host binds the AK to the recorded EK by credential activation:
   `TPM2_MakeCredential` on the host, `TPM2_ActivateCredential` in the guest.
3. The guest runs `TPM2_Certify` on the identity key with that AK, using a
   fresh host nonce as qualifying data.
4. In an isolated `aivm_secrets` child, like every other certificate parse,
   the host verifies:
   - that the AK's own `TPMT_PUBLIC`, as the guest supplied it, has exactly
     the attributes `fixedTPM | fixedParent | sensitiveDataOrigin |
     userWithAuth | restricted | sign`, and not `decrypt`;
   - that the AK's name, which the host computes from that checked public
     area, is the name it used in `TPM2_MakeCredential`, and that the guest
     returned the activated credential;
   - the signature over `TPMS_ATTEST`, under that checked AK public key, and
     the structure's magic, type and nonce;
   - that the attested name is the name of the supplied identity-key
     `TPMT_PUBLIC`;
   - that the identity key's attributes equal the template, and that its
     `authPolicy` is empty or is the PCR policy digest this VM opted into;
   - that the identity key's public point equals the CSR's public key.

   The AK checks are what make the evidence resist guest root. Credential
   activation succeeds for any object loaded in the EK's TPM, and only a
   restricted signing key refuses to sign data that begins with
   `TPM_GENERATED_VALUE` unless the TPM itself produced it. Without them, a
   guest could present an unrestricted key as its AK and sign a forged
   `TPMS_ATTEST`.
5. AIVM only carries bytes, over the forced bootstrap channel.

The evidence proves this: at certification time, the CSR's key was a
non-duplicable signing key resident in the vTPM whose EK the host recorded
when it created that vTPM.

It does **not** prove:

- **Code integrity.** It quotes no PCRs against a reference, and a quote
  would show only what was measured.
- **Which guest process uses the key, or that the guest is uncompromised.**
- **Absence of relay.** A compromised guest can keep using the key to answer
  handshakes on someone else's behalf. Relay is bounded only by the bridge
  socket existing inside the live SSH session.
- **That the vTPM was not copied.** A copy produces identical evidence.
- **Anything about the host.** The host runs swtpm and owns the local CA, so
  host root can fabricate the EK and the AK at will.

## What AIVM may claim

| When | AIVM may say | AIVM must not say |
| --- | --- | --- |
| Today | "The identity key is a software key in the guest user's account. Anyone who can read that account's files or the VM's disk can copy it, including host administrators. Enrollment binds a certificate to that key. It does not show which VM or process holds it." | anything containing "TPM", "hardware" or "non-exportable" |
| vTPM key, no Certify evidence | "AIVM asked the VM's virtual TPM to generate a key that the TPM will not export. The host has not verified that it did." | "the host verified", "non-exportable" without "from the guest" |
| vTPM key with verified Certify evidence | "At enrollment, the host verified TPM2_Certify evidence that the enrolled key is a non-exportable signing key in the virtual TPM AIVM created for this VM. That virtual TPM is software on this host: host administrators can copy it, and any process in the VM that can use the TPM as the guest user can use the key." | -- |
| Never | -- | "hardware-backed", "hardware-bound", "attested VM", "remote attestation", "tamper-proof", "cannot be cloned", "proves the agent or VM is uncompromised" |

## Prerequisites before any of this is scheduled

1. A per-VM opt-in TPM device at creation, with explicit TPM-state removal
   on delete, tested on real libvirt.
2. A demonstrated TLS 1.3 handshake from the guest client with a
   provider-backed key on the guest OS's OpenSSL.
3. Observed snapshot, revert and `virt-clone` behavior of swtpm state on the
   supported libvirt versions, recorded in the validation record.
4. The decided host key custody rule (rollback and clone policy), which
   refuses to certify a key that another active subject already holds,
   whatever the TPM says.
