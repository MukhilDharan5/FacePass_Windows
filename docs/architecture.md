# Architecture

The installed service uses LocalService, a service SID and protected Program Files/ProgramData ACLs. The per-user demo uses a separate pipe/store and never grants unlock authorization. Protocol v3 authenticates caller tokens and executable roles, verifies the running SCM service PID and bounds message sizes/nonces/I/O deadlines. The optional Microsoft-account password record is DPAPI-encrypted and SID-bound; its owned copies erase their secret on destruction.

Enrollment requires fresh interactive OS authentication. Capture/inference runs in FacePassCapture with explicitly inherited unnamed mapping, mutex and event handles. Its job object terminates it on parent exit. The supervisor cancels or kills blocked capture at a hard deadline. No public capture-helper success message can authorize a match.

Worker output carries bounded results/progress and optional 320x240 JPEG preview. Images are never persisted. Only ordinary own-account clients receive previews; provider/authority clients receive none. The parent serializes enrollment commit with Off/cancellation to prevent late saves.

Eligible LogonUI jobs use Strict liveness unless the user has explicitly saved the Instant profile. Instant accepts the first quality 2D face match at the configured threshold, with no liveness, minimum duration or multi-frame gate. Both paths can produce ten-second one-use service authorization. In password-backed mode only LogonUI in the matching locked console session can consume the grant to obtain the saved credential. The provider protects and packs it in its own logon session and targets built-in Negotiate. Windows authenticates the password; no FacePass LSA package is used. In the optional legacy mode the provider serializes a ticket to FacePassUnlock, whose package validates the existing locked local console session and returns copied native token information. Configuration changes cancel an active scan and revoke existing grants.

Off revokes/cancels. Manual requires selection or explicit diagnostics. Automatic authentication begins when LogonUI advises the provider and cannot force tile selection. Diagnostic-only automatic mode also listens for lock events. Session changes revoke grants; startup/logoff/suspend require native session authentication before passwordless authorization.

Tests do not load a package into LSASS. LogonUI behavior, package/token/profile semantics and Session 0 camera availability remain VM validation requirements.
