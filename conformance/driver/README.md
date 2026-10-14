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
`client.call`, and (in tagged builds) `barrier`, `session.store`, and `session.trace` and `client.transport`.
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

Tagged builds advertise `client.transport` and implement `client.observe`.
Snapshots return exactly `callId`, `throughSequence`, `complete` and `events`;
each event projects the runtime's eight protocol fields, with no driver byte
accounting, outcome comparison, retry or refresh merging. Observations remain
available while the call is pending and after its SDK result. Unknown call IDs
and future watermarks are rejected; empty complete watermark intervals are valid.
The conformance peer uses loopback HTTP. Unsupported wire shapes or HTTPS buffer
measurements remain unavailable and cannot establish conformance.

The tagged constructor wraps the cloned SDK transport's real RoundTrip,
DialContext, optional DialTLSContext and DNS entry callbacks. Its counter delta
from constructor entry to return supplies `constructorNetworkRequests`, including
constructor rejections. The same counter records later actual call entries.
The SDK's single client.Do path uses this transport; there is no separate default
client, socket or resolver path. A regression check guards those bypasses.
User-visible raw-error exposure and resolvable outcome/status observations come
from the runtime result hook; unavailable metadata remains null. No raw exception
text, body or header is emitted.

The HTTP/1.1 response path fixes the sole payload I/O buffer at 4096 bytes and
disables compression and HTTP/2. The fixed buffer is excluded as transient
(F=4096, below 64 KiB). Source pins: Go 1.26.9 `net/http/transport.go:322-326,1991`
and Go 1.27.2 `net/http/transport.go:329-333,2120` select and construct the
bufio reader; both versions' `bufio/bufio.go:50-59` allocate exactly
max(ReadBufferSize,16). `net/http/internal/chunked.go:27-35` reuses that reader,
so content-length and chunked responses do not gain another payload buffer.
The runtime reports the valid cumulative body bytes (Q) separately from the
library's active, undelivered payload bytes (L). Its wire parser holds
HTTP/chunk framing, not a body copy. The retained buffer inventory is:

| Storage | Active body bytes and lifetime |
| --- | --- |
| SDK `data` | One zero-initialized 1 MiB array; Q counts populated bytes, not reserved capacity. The final slice aliases the same array. Redirect rejection precedes allocation, so Q is zero. |
| HTTP/1 `persistConn.br.buf` | One 4096-byte array; L counts body bytes in `buf[r:w]`, excluding consumed bytes, unused capacity and chunk framing. Content-length and chunked readers share it. |
| Overflow check | A separate one-byte handoff counted in reads, excluded from Q/peak and the diagnostic total. |

`RetainedBytes` and `RuntimeRetainedBytes` report Q; `PeakRetainedBytes` is the
call-wide maximum Q. `LibraryRetainedBytes` reports L even though the fixed
I/O buffer is excluded from retained/peak. `TotalHeldBytes` is the internal
diagnostic Q+L, not process heap usage. Body wrappers reference these stores
without another payload copy; chunk CRLF storage is framing. Request, peer and
OS buffers are outside SDK-owned response body storage.
These bounds cover the fixed loopback peer; HTTPS/TLS buffers remain unmeasured.
The complete capability covers C-04/C-05's oversized 3xx variants, which stop
before JSON decoding (guarded by a decoder sentinel test). Other calls that
enter JSON decoding cannot establish a complete retained-byte peak:
`encoding/json/stream.go:284-288` copies RawMessage bytes with append and the
fixed generated SDK's `client.go:28-45` creates a map of RawMessage fields in
UnmarshalJSON. Decoder temporary copies are not observable from this runtime.
After decoder entry, snapshots preserve `complete:false` and null retained/peak
fields, including subsequent exchanges in the same call. No guessed byte count
or driver reserialization fills this gap. Generator instrumentation is separate
work; ordinary decoded calls therefore remain incomplete.

Generated input models serialize valid declared fields, and the input adapter
preserves absent/null fields which Go string structs cannot represent. Generated
output decoders validate complete responses. Time strings stay strings. SDK error
codes/statuses are taken from structured `OperationError` values; other metadata
remains unavailable, with no string parsing or invented status/code. Tagged runtime observations report `outcomeUnknown` only where the runtime can
resolve it; HTTP status alone does not resolve refresh-token consumption. Command
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

The root tagged `TestConformanceRetainedBytesOracle` independently checks the
inventory above through the real `NewHTTP`/`net/http.Transport` path over
`net.Pipe`. A private synchronous probe receives only the actual response and
SDK array view before headers/read observations. It stores numbers, never
body views. The oracle counts fixed `Z` bytes in the entire actual `data` array
and, using read-only reflection, in the actual bufio active window. It follows
the optional `cancelTimerBody.rc`, then `bodyEOFSignal.body`, `body.src`, and
`LimitedReader.R` or `chunkedReader.r` wrappers. Unexpected types, fields or
buffer bounds fail the test; no unsafe access, fallback or skipped measurement
is used. Go source pins are 1.26.9
(`2ae494ef9fb90e0da0073c31800ba38870249994`) and 1.27.2
(`022c8636110ebac86a9b88724cda168ed713c21f`).

Redirect/overflow and content-length/chunked subtests force positive library
checkpoints and, for overflow, a full SDK array. Only independently measured
Q releases the peer gate. Expected Q, L, Q+L and maximum Q never use accounting
counters or events. All comparisons have zero-byte tolerance; terminal events
preserve the independently measured peak without re-reading closed buffers.
The fixed inventory must be updated if another cumulative payload copy is
introduced. Decoder copies remain outside this oracle's scope.

Run from the root with each pinned toolchain:

```sh
go test -race -count=1 -tags=chik_conformance -run '^TestConformanceRetainedBytesOracle$' .
```

Honest proportional retention is checked by the real driver and shared C-04
aggregation. Missing SDK/library bytes are checked by this independent oracle:
one-byte omissions must fail the overflow/redirect subtests respectively.
Shared CLI CI expectations are unchanged regression checks. The root CI runs
untagged tests and does not yet run this tagged oracle automatically.

These tests and a successful coordinator build establish driver behavior and
linkage only. Missing hooks and shared conformance observations remain
`unimplemented`; they do not establish full SDK or customer-path support.
