# Generated Go SDK conformance driver

This independent module connects JSON Lines commands to generated Go SDK methods.
The runtime module gains no dependencies. The shared coordinator owns fixture
generation, compiler arguments, toolchain/environment selection, SDK bindings,
artifact identity and conformance verdicts.

## Build and start

The repository-root `driver.json` supplies a typed build declaration: `tool: go`,
relative entry `conformance/driver/cmd/driver`, and empty `features`. The coordinator
copies the repository, connects `chickinfry-client-plain` and
`chickinfry-client-auth` through local module replacements, and executes its fixed
offline `go build -mod=readonly -buildvcs=false -tags=chik_conformance` template.
There is no custom builder, shell command, driver-selected output directory, or
committed generated SDK. The declaration pins the implementation commit; its
publication commit changes only declaration metadata.

Every client creation request requires `fixture: "plain"` or `fixture: "auth"`.
The driver selects the corresponding fixed generated SDK alias, and copies retain
that selection. Missing, empty, null, non-string and unknown values are
`invalid_args`. Fixture identity is never inferred from operation names, case IDs,
files, or credential presence. Suite/execution/result schema version 3 is owned by
the coordinator; the driver process protocol remains version 1.

The executable reads initial credentials from inherited anonymous pipe descriptor
3, with exactly `ref` and `value` string keys. A complete line including LF is at
most 64 KiB and the whole bootstrap is at most 1 MiB. Duplicate references, even
with identical values, unknown/case-variant fields, duplicate keys, invalid UTF-8,
oversized input and truncated lines are rejected. EOF is consumed before handshake.
There is no credential environment, argv, file or reverse delivery fallback.
Coordinator-supplied SDK path arguments do not select the fixture or load code;
the generated packages are already linked into the executable.

## Protocol and observations

Protocol version 1 and driver version `1` advertise `client.create`, `client.copy`,
`client.call`, and (in tagged builds) `barrier`, `session.store`, and `session.trace`.
A handshake may include an exact Go SDK/native
target. Each call runs independently, while stdout writes are serialized by line.
The driver adds no SDK refresh flight, request retry, refresh lock or credential
comparison. Session commands use the runtime's `MemoryStore` directly, including
the same pointer for clients sharing a store. Protected full session records are
validated against their token references and origin before `MemoryStore.Set`.
Store bindings reject a different client origin.

The store's wire `revision` comes from the tagged runtime observation and counts
every successful Set, stored refresh result, and Clear that deletes credentials.
Credentials are read first and the revision separately afterward; they are
separate observations, not an atomic snapshot. The driver adds no comparison,
retry, or lock to merge them. The coordinator's barriers establish ordering when
it checks a concurrent login.

The tagged barrier capability forwards actual sdk-entered and
both-originals-rejected and refresh-joined hooks. Each arriving execution waits for its matching
coordinator response while other commands continue; cancellation stops the wait.
refresh-started remains peer-owned. The runtime supplies the shared opaque refresh
reference at its real participation point. Expected-credential clear attempts and
their atomic removal result come from its Clear hook. No wrapper changes the
runtime store type or implements clearing. Store reads with `includeTrace: true`
return these actual attempts, including an observed empty list when no clear ran;
unmeasurable clear observations return `unimplemented`. Session capabilities are
advertised together only in builds with both runtime observations.

`client.transport` is not advertised. `client.observe` validates the revision-3
`callId` and nonnegative integer `afterSequence` arguments, then returns
`unimplemented`; it emits no fabricated snapshot. The runtime's existing hooks
measure loopback HTTP only: HTTPS has no connection/body-buffer measurements,
and the constructor and user-visible errors do not expose
`constructorNetworkRequests` or `rawTransportDetails`. Consequently the driver
cannot provide all required fields, including a complete eight-field transport
snapshot, from actual observations. These missing observations also prevent
C-02 and SDK-error-dependent cases from establishing conformance. No partial
transport capability or hard-coded zero/false counters are published.

Generated input models serialize valid declared fields, and the input adapter
preserves absent/null fields which Go string structs cannot represent. Generated
output decoders validate complete responses. Time strings stay strings. SDK error
codes/statuses are taken from structured `OperationError` values; other metadata
remains unavailable, with no string parsing or invented status/code. SDK
`outcomeUnknown` is null because the public runtime does not expose that
observation; HTTP status does not resolve refresh-token consumption. Command
deadline errors also leave `outcomeUnknown` null because the runtime does not
expose the outcome at the deadline.

Initial credentials and generated output references feed the redaction table.
No driver-owned store rotates credentials.
Secret fields/values are removed from output and a final serialization check
rejects literal, base64 (standard/URL, padded/unpadded), and hexadecimal
(lower/upper case) credential echoes in keys, nested values, and error paths.

Control lines, including LF, are limited to 16 MiB. Every final stdout line,
including fallback errors, follows the same limit. Oversized results get a bounded
error with the same ID. IDs and references must match
`[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}`. Malformed envelope IDs produce no stdout response. IDs are never shortened or
replaced. Invalid UTF-8, truncation, duplicate keys, unknown/case-variant fields, repeated IDs and
unsolicited response IDs are rejected.

Command deadline/cancellation gets one `driver/deadline_exceeded` response. SDK
work preserves context values without caller cancellation, so the public return
joins internal refresh work under the SDK's finite request timeout. Closing stdin
waits for all call work, with no late response for a finished
ID. The coordinator owns case-level process termination and reaping. Diagnostics
are fixed messages without exceptions, request IDs, bodies or stack traces.

## Checks

The core module tests protocol framing, bootstrap limits, credential protection,
fixture selection, real copy behavior and shutdown sequencing. The D12 test uses
explicit deadline/entry/release channels instead of wall-clock ordering. Tests
under `chik_conformance` also exercise the generated bridges, input presence and
descriptor validation against the coordinator-prepared alias modules. Run them
from a prepared module with the coordinator-owned local replacements.

These tests and a successful coordinator build establish driver behavior and
linkage only. Missing hooks and shared conformance observations remain
`unimplemented`; they do not establish full SDK or customer-path support.
