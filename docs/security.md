# Security boundaries

Version 0.3 adds an explicitly chosen [password-backed Microsoft-account route](password-backed-unlock.md). Its DPAPI-encrypted password is bound to the enrolled SID and released only to OS-authenticated LogonUI after a one-use face approval in the same locked console session. Ordinary diagnostics cannot retrieve it. The provider targets built-in Negotiate; Windows protection is unchanged. Administrator/service compromise can recover this reversibly encrypted password. Native Windows authentication rejects stale or restricted account credentials, and rejection removes the saved password to prevent repeated replay. The no-stored-password statements below apply only to the legacy custom LSA route and transient enrollment verification.

The experimental backend trusts the protected service/private worker for RGB recognition and Windows for session/account/token identity. Administrator, kernel or service compromise is outside these ACL boundaries. Ordinary same-user processes can change their own settings or invoke diagnostics, but diagnostic jobs never receive unlock authorization.

Implemented: local-only first-instance pipe; bounded I/O; SCM PID verification; OS caller tokens and SYSTEM executable-role checks; SID isolation; nonce/expiry; fresh interactive-token enrollment; DPAPI encryption/integrity; protected ACLs; reparse-point rejection; bounded reads and atomic encrypted writes. Password/PIN replay is absent. Transient verification buffers are wiped.

Unlock additionally requires an observed native sign-in and locked console session, random short-lived tickets with monotonic expiry, atomic LSASS consumption and revocation on job/policy/session changes. Convenience, Balanced and Strict profiles require Strict liveness/threshold >=0.55 for unlock. The explicit Instant profile skips all liveness, duration and multi-frame checks, accepting the first quality 2D match at the saved threshold (0.363..0.85). A photo or replayed video can therefore unlock; Instant provides no presentation-attack resistance. Changing preferences cancels an active scan to prevent an earlier profile from authorizing later. The package refuses boot/remote/non-local accounts and copies an existing native token. Supervised capture terminates blocked workers. Images/previews remain in memory.

Remaining risks:

- RGB challenges can be defeated by sophisticated replay/generated video. No evaluated PAD, accuracy campaign or independent audit exists.
- The package has not been loaded into LSASS or tested through Winlogon. Profile/token behavior, account restrictions, native fallback and recovery require VM testing.
- Production/Microsoft LSA signing is outstanding. Protected LSASS refuses unsigned plug-ins; the script does not disable protection.
- Fresh native sign-in proves authentication freshness, not operation-specific trusted consent under same-user compromise. A dedicated trusted Hello enrollment broker is not implemented.
- One profile per SID; MSA/AD/Entra, boot sign-in, RDP and enterprise provisioning are outside this first backend.
- Explicit buffers are wiped; exhaustive wiping of OpenCV/exception-path copies is not guaranteed. UI layout is fixed Win32 rather than responsive WinUI.

Retain native Windows providers and use the custom package only for disposable-VM development until validated/audited.
