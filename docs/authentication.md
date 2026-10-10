# Custom passwordless authentication

For the new Microsoft-account route, see [password-backed unlock](password-backed-unlock.md). It stores an encrypted password and uses a Credential Provider with built-in Negotiate, preserving LSA protection. The remainder of this document describes only the optional legacy no-stored-password authentication package.

FacePassAuth.dll implements an LSA authentication package. The provider serializes an UnlockLogon buffer carrying service authorization, never a password or PIN. LSA remains the Windows authentication authority. [Microsoft authentication packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-packages), [LsaApLogonUserEx2](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user_ex2).

Only a trusted OS LogonUI job in the enrolled user's locked console session can receive authorization. The service must have observed native session logon/unlock since startup. Unlock forces Strict randomized liveness and cosine threshold >=0.55 for Convenience, Balanced and Strict profiles. The explicitly selected Instant profile instead accepts the first quality 2D match at the saved threshold without liveness or a minimum wait; photos or replayed video can unlock. Ordinary settings/CLI diagnostic scans cannot obtain tickets.

Tickets bind a random 256-bit nonce to SID/session and a ten-second expiry; service memory additionally enforces a monotonic deadline. New scans, configuration changes, cancellation, deletion, unlock, disconnect, logoff and restart revoke grants. Only the OS-authenticated SYSTEM lsass.exe client can consume them, atomically and once. Clients verify the SCM service PID. This live verified service channel replaces a persisted ticket-signing secret.

The package checks the locked console session, obtains its native WTS token, checks SID equality and a current enabled/non-locked/non-expired local SAM account, and copies token identity, groups, privileges, owner, primary group and default DACL into one LSA-owned V2 allocation. It excludes the prior logon SID. After consuming authorization it rechecks lock state, creates an authentication LUID and returns an interactive profile. Failures return no token. Both Interactive and Unlock logon types require an existing locked session; boot sign-in is refused.

No account password, PIN or hash is requested by this backend. Enrollment accepts a recent native interactive token without collecting a password, or separate transient password verification that is erased immediately.

## Validation limits

Local console unlock is implemented but **not validated in Windows**. Boot logon and MSA/AD/Entra/RDP are unsupported. Mock tests do not establish Winlogon acceptance of the profile/token, account-policy correctness, PPL loading, Session 0 capture or secure-desktop stability. These remain required VM tests. RGB software liveness has no measured presentation-attack assurance and must not be advertised as Windows Hello or production authentication.
