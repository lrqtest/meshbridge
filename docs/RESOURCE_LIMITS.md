# Server resource and traffic bounds

The control API accepts at most 64 sockets and runs at most 64 request handlers.
The separate gateway accepts at most 128 sockets and runs at most 128 handlers.
Socket slots remain occupied after hijack until the underlying connection closes.
Tunnel proxy requests additionally share a process-wide limit of 128, with 16
live requests per tunnel. Large uploads and response streams remain incremental;
there is no server-wide response write deadline.

Agent handshakes and live sessions share 32 slots. Replacing a still-live session
also needs a slot, so reconnects can temporarily receive a busy response. Gateway
yamux streams share limits of 32 per session and 128 globally, including pending
opens and streams waiting for the peer to acknowledge FIN. Stream close timeout
is 30 seconds. A peer that ignores FIN can temporarily saturate these limits;
retries cannot create another unbounded set. Agents may accept controller streams
but may not create inbound streams on the controller.

Password authentication consumes an entire JSON document of at most 16 KiB
before any password hash work. Existing login passwords that fit inside that
document remain accepted. The existing creation/reset password policy remains
in place. Hash work also retains its process-wide admission gate.
The shared kit password engine keeps Mesh's 64 MiB/t=1/p=4 generation parameters
and one admitted calculation per process. Stored Argon2id records must be v19
and request at most 64 MiB; malformed or larger records fail before admission.
Mesh account IDs, bearer-token storage and permission queries remain local.

Traffic accounting counts ordinary HTTP request/response bodies, SSE response
bytes, and both directions after HTTP upgrade. The HTTP upgrade response headers
are included in upgraded outbound bytes. A buffered upgraded request prefix is
counted exactly once. The shared monthly balance reserves up to 16 KiB before
each I/O operation, then settles only the actual bytes read or written. Temporary
reservation saturation returns busy; it does not persist a quota stop. Monthly
keys are UTC. A persisted `quota_exceeded` status requires an explicit owner/admin
action to re-enable it; the calendar does not automatically reset that status.

Dirty traffic is flushed across all tunnels at 256 KiB, every second, and after
the final close. Active and dirty entries remain in memory; clean idle entries
and unused old months are removed. Under a healthy SQLite database, an abrupt
process crash can lose less than 272 KiB of settled but uncommitted deltas plus
at most 4 MiB from 128 live requests with one 16 KiB I/O reservation in each
direction. This assumes one server gateway process and the standard ReverseProxy
copy path, with at most one I/O operation per request in each direction. It bounds
accounting bytes rather than resident memory and does not cover several processes
sharing the same database. The one-second timer bounds ordinary low-volume delay,
while a SQLite operation may take up to five seconds. This is a process-crash
accounting bound, not a promise against operating-system or storage power failure.

A meter database error closes live proxy jobs and agent sessions, denies further
metered I/O, and makes readiness return HTTP 503 with `meter_degraded: true`.
Unapplied deltas remain available for a final retry; successful retry does not
clear the degraded latch. Restart after correcting the database error is required.
No database rows are deleted to recover meter failures. Owner-requested tunnel
deletion drains its live jobs and final meter writes before the existing cascading
delete, preventing a late accounting write from violating its foreign key.

SIGTERM and SIGINT stop listeners and request admission, cancel server-owned
probes/jobs, close gateway sessions, drain handlers (including upgrade handlers),
and finally stop/flush the meter before SQLite closes. The complete drain has a
ten-second deadline. If an owner fails to drain by that deadline, the process exits
with failure rather than closing SQLite beneath a still-running handler. Normal
HTTP server closure is not a fatal serve error.

The kit HTTP primitives own request/socket admission, strict JSON document
limits, trusted local-proxy address resolution, and loopback listener validation.
Mesh selects blocking socket admission and separate 64/128 budgets; account apps
can select the shared shedding listener. The kit lifecycle owner and HTTP drain
primitive are also used by Mesh, with the tunnel-session and meter ordering kept
in its shutdown callback. These shared packages do not own Mesh's SQLite handle.
