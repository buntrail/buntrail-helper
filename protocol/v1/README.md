# Remote protocol 1.0

The Rust protocol crate owns framing and typed wire metadata; the helper and
client share these definitions. This is a process/network boundary, separate from
the buntrail-ffi native ABI. Native edits and terminal I/O never serialize through it.

An eight-byte prefix contains big-endian u32 header and payload lengths, followed
by a UTF-8 JSON header and raw bytes. Header length is 1..65,536; payload is at
most 1,048,576 bytes. File chunks and terminal chunks are at most 65,536 bytes.
The incremental decoder accepts partial prefixes/headers/payloads, checks lengths
before buffering the header, and deserializes/validates the complete typed header
before allocating any payload bytes. One input window is bounded to one maximum
frame size. An invalid frame poisons its decoder; EOF with a partial frame fails.

`schema.json` describes closed JSON header shapes. Serde's closed structs/tagged
enum enforce the same shapes at runtime, with additional semantic validation:
absolute NUL-free base64 POSIX paths, UUIDs, operation/stream requirements, payload
rules and exact authenticated-context matching. JSON Schema alone cannot verify
authenticated context or decode a path. Nullable header fields must be explicitly
present. No wire DTO is a cast or direct serialization of a core runtime object.

A connection owner supplies the expected workspace/client/verified-target/runtime
context. Scoped messages must match it exactly; display names are never trusted
as identity. Hello is unscoped and carries limits/capabilities. Reject unknown
major before work; negotiate minor/capabilities/limits before sending work.
Unknown kinds/metadata fields fail closed. An incompatible live supervisor is
left running. The Rust helper now implements the local Unix transport and
supervisor below. SSH authentication and environment provisioning remain client
transport responsibilities; a claimed header context never authenticates itself.

The currently declared wire methods cover negotiation, listing, segmented read/
upload/save-commit, operation inspection, terminal output, cancellation and typed
errors. Service-specific transport methods are added when their capabilities are
implemented; unsupported kinds are rejected rather than accepted as JSON blobs.

Read/upload begin identifies the transfer, file, total length and operation when
mutating. Chunks have ordered byte offsets. `TransferVerifier` rejects gaps,
overlaps, mismatched IDs, excess length and chunks larger than 64 KiB. End requires
exact length and SHA-256. It retains only hash state, not whole-file bytes. The file
service must stage uploads privately, revalidate expected version at durable
commit, leave project files unchanged on incomplete/cancelled uploads, and remove
unaccepted staging after 600 seconds idle. Accepted operations retain their staging.
Expired transfers restart explicitly; resumability is not claimed. Lost commit
acknowledgements require inspection of the same operation ID, never replay.

`golden/manifest.json` distinguishes valid/invalid binary frames. Tests split valid
control and raw-payload frames at every byte and reject unknown major, oversized
lengths, malformed JSON, unknown fields, partial EOF and mismatched context. The
schema is checked alongside golden decoding. Retention is 1,800 seconds under the
separate owner-lease policy; framing does not implement session supervision.


## Helper supervisor and bridge (T13)

The binary identity is `buntrail-helper`. `probe` prints one JSON identity/version
object; `serve --socket /absolute/private/state/socket` owns the environment;
`bridge --socket /absolute/private/state/socket` attaches or starts that owner and
relays framed bytes through stdio. The connection owner selects one stable state
directory per effective-user/environment. Its parent must already exist. The
helper requires a mode-0700, current-user-owned directory, rejects symlinks and
unsafe lock files, protects the socket with mode 0600 and checks peer UID on both
ends (`getpeereid` on macOS, `SO_PEERCRED` on Linux). Client/workspace UUIDs are
registrations within that authenticated user boundary, not isolation from other
processes running as the same OS user.

A startup file lock serializes bridge launch; a separate lifetime owner lock
prevents concurrent supervisors. An unlocked stale socket is removed only after
connection refusal. An existing live/incompatible owner is never terminated or
replaced. The detached child starts a new session, uses null stdio and marks
inherited nonstdio descriptors close-on-exec. Bridge stdout is bounded binary
transport with explicit flushes; diagnostics are bounded stderr text. EOF/failure
marks bridge leases disconnected. No terminal input or mutation is replayed.

Send `hello`, wait for `welcome`, then send `lease.register` and wait for `ack`
before scoped work. The welcome returns minor 0, the capability intersection,
negotiated limits, 524,288 initial credit bytes, a server-derived target binding
and fresh runtime UUID. This implementation needs at least a 1,024-byte header
and 65,536-byte payload negotiation limit. Registration echoes the target/runtime
and supplies stable client/workspace/lease UUIDs; the server checks its own binding
and runtime and then installs the expected context. Multiple workspaces from one
client share a bridge; releasing one lease leaves the others usable. View
detachment, resolved workspace closure and unexpected bridge loss are distinct.
Only explicit owner resume cancels that lease's 1,800-second disconnected deadline.
T15 owns retained remote PTYs; terminal capability is not advertised here.

Implemented capabilities are `leases`, `operations`, `file.read`, `file.save`.
They cover the explicit typed methods in `schema.json`; Git/search/watch/terminal
service parity is T14/T15 work. Read starts with `file.read`, then produces
`file.read.begin/chunk/end`. Version strings in read-begin and save-commit encode
the explicit `WireVersion` object (opaque token and file identity as base64,
SHA-256 as hexadecimal). The verified target is supplied by the installed service,
not deserialized from a client runtime object.

Each outbound stream starts with 512 KiB credit; a chunk consumes its byte count.
`stream.credit` restores consumed credit, never beyond that window. No snapshot
bytes are read or new data frames produced while credit is zero; a single queued
data frame is bounded to 64 KiB. Control frames precede further data production.
At most four data workers/read streams and four separately reserved inspection
workers exist per supervisor, with eight pending jobs per connection, 32 clients,
256 leases and four upload transfers per connection. Saturated service admission
returns a bounded refusal before acceptance: mutations receive the existing
`operation.receipt` with `failed`/`proven_no_effect` and the typed `Busy` code;
read-only requests and uncommitted upload admission retain typed `error` replies.
Maintenance refusal uses the same distinction with `Unavailable`. These admission
receipts do not create ledger records. Generic worker/transport errors after
submission are not proof of no effects. Protocol/queue violations close
the connection. Completed worker results use bounded channels. Snapshot reads use
the existing immutable file-service memory/spool policy (64 MiB file bound).

Uploads stage in private files, with ordered chunks and SHA-256 verified at end.
Upload credit is restored only after its grant has actually left the transport.
Commit rechecks staging length/digest, converts the bounded source into immutable
memory (at most 32 MiB + 4 bytes), and calls the existing file service, which owns
target/version revalidation, request digest, durable acceptance and replacement.
The worker/source outlives bridge loss; disconnect cannot delete its accepted
source. Uncommitted uploads are dropped on disconnect/cancel and expire after
600 seconds idle. Crash-orphan staging is swept after 600 seconds (maintenance
scan granularity: 60 seconds); an active staging file lock prevents removal.

`cancel.result` reports `confirmed_cancel` for stopped read/upload delivery and
`unknown` when a submitted mutation may still run. It never claims no-effect
cancellation for an accepted mutation. Explicit operation inspection uses the
same `LocalFileService::inspect_sync` reconciliation as the client: raw interrupted
ledger state is unknown, while stronger verified current-file evidence may
subsequently confirm the requested contents. Wire receipts preserve failure
code/effect, file/version/digest evidence and the verified context. Missing receipts
remain unknown and do not authorize replay.

Client route ownership lasts through consumer finish or drop, including a terminal
frame held unread in the mailbox. Finishing flushes consumed-byte credit before
retiring the bounded route; dropping sends cancellation. Completed mutation result
streams retain their mutating request identity until delivery/credit retirement,
so cancellation of their delivery remains `unknown`, never `confirmed_cancel`.

The shared ledger persists through atomic fsynced records. Its actual API maps
acceptance to `Ledger::accept`, finalization to existing typed service writes via
`Ledger::write`, and raw inspection to `Ledger::inspect`; dispatcher code does not
invent a parallel mutation state machine. `write` bounds/serializes/persists; it
does not centrally validate every transition. Startup, under exclusive ownership,
turns interrupted accepted/running records into durable unknown receipts. Periodic
compaction leaves live accepted/running records unchanged and expires completed
payloads after 24 hours while preserving the original envelope and terminal
session anti-reuse identity.

**Interim quota:** existing ID tombstones remain at the 10,000-record lifetime cap;
new admission is refused rather than forgetting an ID and allowing replay. This
is not a permanent daily-use retention solution. T19/final must resolve that
policy and consolidate the established core/service partial-effect transition
semantics. No running operation is evicted. With no clients or owned work (and no
remote sessions in this T13 capability slice), the supervisor removes its own
socket and exits after 30 seconds idle.

## T14 services extension

Clients negotiate the additive `services` capability before `service.call`. A call's
`method` selects the explicit DTO in `services.schema.json`; unknown nested fields
and omitted nullable fields are rejected. Target authority is the registered
header context, never a path display string or a target supplied in a call.
Paths are absolute NUL-free POSIX bytes encoded as base64. Worktree discovery and
`contains` run on the target. No call contains a coordinator-approved flag or an
alternate execution expectation. The engine must apply its document gate before
composing remote checkout/FF-pull into T16 routes.

`service.event` carries typed Reply JSON in raw payload segments of at most 64 KiB,
not in the 64 KiB header. Metadata contains ordered offset, total event length,
SHA-256 and terminal status; the header stream ID remains fixed for the request,
and sequence advances once per complete event. Reassembly is bounded to 32 MiB
per service outcome. An oversized serialized outcome returns a typed unavailable
error; this bound is separate from file/editor limits. Initial credit remains
512 KiB. Consumers replenish every consumed segment, including the final segment;
the helper retains stream ownership until all outstanding credit returns or the
owner cancels/disconnects. Only one data frame is queued on the helper connection.
Client credit is coalesced per owner rather than queuing a frame for each small
search event. Search producers retain their shared two-job/32-event bounds.
Watch events preserve `rescan_required`; cancellation closes the owned producer.

Files still use the raw `file.read.*` / `file.upload.*` segmented transfer protocol.
`file.create.commit` accepts a completed owned upload through shared create policy;
`file.save.commit` preserves version, submitted revision and original operation.
Incomplete upload cancellation/disconnect has no project-file effect. Once
submitted, a mutation retains its input independently of bridge lifetime.
Operation inspection returns full saved/file/Git/network evidence via
`service.call {method: inspect}`; old save receipts remain compatible. No proxy
replays an operation or input on loss, timeout, cancellation, or inspection.

`file_mutate.delete` requires both `confirmed_target` (the current verified binding)
and `confirmed_path` (the exact selected base64 path). The frontend must display
that actual target/path and obtain explicit permanent-delete confirmation before
calling FileService::mutate(Delete); it must not imply local Trash semantics.
Remote Trash is unavailable. This service contract is not a UI confirmation flow.

`connection.authentication` replaces the connection's current optional target-side
SSH_AUTH_SOCK for future app-run Git commands. Each admitted command captures that
context. An explicit null clears an obsolete forwarded socket. It never modifies
the supervisor process environment or inherited environments of existing terminals;
an expired socket is not restored. The authenticated route owner supplies this
context when composing T16 routes.

Inspection has four reserved helper control workers. File reads retain four slots;
finite service jobs have eight slots, watches four, and searches two. Every pending
request/stream participates in lease, request-ID, maintenance-admission and idle
ownership. The 1,800-second disconnected-owner grace is unchanged. Service streams
have a bounded 512 KiB credit window; client mailboxes cap raw payload at 1 MiB and
10,000 frames per request, with at most 32 live routes and bounded 32-command queues.
The helper's existing 32 MiB + 4-byte completed-upload and 64 MiB read-spool limits
remain in force; an immutable accepted source is not a queued chunk stream.

The parent Buntrail application’s `Scripts/build-helper.sh` (not included here) builds the pinned target ripgrep (15.1.0, existing vendored
lockfile and source manifest, no default features, offline) and places `rg` beside
the helper. Explicit SEARCH_TARGET artifacts have separate build-cache outputs;
Linux cross-builds do not overwrite the native developer search executable. No
system package installation or privilege elevation is part of provisioning.

## T15 retained terminals

The negotiated `terminal` capability enables `terminal_open`, `terminal_attach`,
`terminal_input`, `terminal_resize` and `terminal_end` through the existing typed
service dispatcher. Each call names a registered lease and session; authenticated
Context binds client, workspace, verified target and supervisor runtime. Open
also requires its durable operation ID, lossless directory/shell paths and
positive rows/columns. Inspection recovers the original receipt/session; it never
restarts a shell. Authentication is a launch-time command environment snapshot,
outside the durable request digest.

`terminal_input` carries its bytes in the **raw frame payload**, at most 64 KiB.
It is never resent or split automatically. Other terminal calls have no payload.
Output/events reuse bounded `service.event` streams; raw PTY bytes are losslessly
base64 encoded inside each typed output event payload. Credit counts encoded wire
bytes. Arrival of a final frame does not release client consumer ownership.
Dropping/cancelling an attachment stops delivery, not the PTY. Input, resize and
end share the existing four reserved control positions with inspection; no queue
or slot limit is expanded. Input/resize/end remain available during a durable
mutation admission pause after owner validation.

Per-session replay remains at most 8 MiB, 10,000 newlines and 4,096 chunks; eight
live/retired stores enforce the existing 64 MiB supervisor ceiling. Eviction
produces an explicit sequence gap. A gap means a partial transcript, not a
restored complete screen. Natural process exit, backend-confirmed intentional
end, expiry and runtime loss are distinct. Reattachment replaces the previous
renderer, and only that owner's resumed lease cancels its 1,800-second monotonic
expiry. New supervisor boots cannot attach old sessions.

### Target folder resolution and shared client views

`file.resolve` negotiates the read-only `service.call/file_resolve` method.
`purpose=root` chooses an existing directory and returns its canonical target path
and observed node identity. `open_child` validates the resolved parent beneath
that root, then follows the existing leaf as FileService reads already do.
`mutation_node` validates the resolved parent plus leaf without following the
leaf; an absent leaf is permitted. The requested path remains in `file`, while
`resolved_path` records the observed destination/node path. `node_kind` describes
the leaf (including a symlink). A version is supplied only for a strongly read
regular file; directory, symlink-node and missing-node results have null versions.
These are observations, never later mutation authorization. Project paths are
lossless base64 data and are resolved only on the target.

One client installation can register separate workspace lease views on one
physical bridge. Release revokes that view's new requests; other views and already
owned response/credit/cancel obligations remain independent. The client admits at
most 256 live or retiring view scopes and retains their actual owners through
queued frames and pending routes. Freed scopes can be reused; no lifetime context
tombstones or extra expiry timer are needed. Known replies must match their exact
request context and operation. Structurally valid replies for retired request IDs
are discarded without events or authority; malformed frames and peer commands
still fail closed. The helper's request decoder is unchanged.

### Final lease retirement capability

`leases.retirement` strengthens `ResolvedWorkspaceClosure`: its ACK is withheld until
all PTY startup/process workers belonging to the exact released lease have retired,
including sessions unknown to the requesting client and sessions removed from the
active session map. The bridge continues serving sibling owners and owned controls
while waiting. `ViewDetachment` retains the existing disconnect/grace semantics.
Clients requiring final-close certainty must negotiate this capability; generic
`leases` from a compatible older supervisor does not prove retirement. Do not
replace or kill that live supervisor to manufacture this capability.

Helper request decoding admits late Credit/Cancel only under the fixed client,
target binding and runtime pinned by the bridge's first successful registration.
A control still needs its exact outstanding request/stream owner and credit budget
to change state; retired unknown controls are discarded. This grants no new-work
or registration authority, retains no retired-context tombstones, and does not
change the general decoder's registered-context checks. The client pin survives
release of the final registered workspace on a bridge.

`terminal.ordered_controls` guarantees that helper input, resize and attachment replacement are admitted in wire order before independent response workers run.
These operations only update the existing bounded in-memory session state. Clients
requiring this guarantee refuse input/resize/attach before admission when it was not
negotiated; generic `terminal` from an older compatible supervisor is insufficient.
Engine orders each session's attachment admission before dispatching its next
replacement; cancellation retires the earlier admission signal without replay.

### Read-only owner observations

Container routes negotiate `container.binding.v1`. Their `welcome` metadata
optionally carries `container_start_base64` (1–256 decoded bytes), published by
the actual supervisor. The client verifies it against current engine discovery;
the supervisor boot UUID alone never substitutes for the complete runtime.
`LeaseOwner` carries the same optional field, so observations compare both boot
and container start. Ordinary SSH omits it and retains its previous frame shape.
The helper's target-scoped cache/operation directory remains stable across a
container restart; changed runtime never creates permission to replay a missing
or old operation. An incompatible live supervisor remains running.

`leases.observe` attests `service.call/lease_observe`. Its explicit `LeaseOwner`
binds client, workspace, lease, target binding and original runtime. The caller
uses a currently registered sibling or temporary observer on the same verified
target/client. The helper refuses mismatched current or retained owner identity.
The observation does not register, resume, renew retention, revoke or start work.
It uses only current bounded lease and retained worker state, with no tombstones.

`lease_observed` echoes the exact owner and includes the actual current runtime,
`active`, `detached` (remaining monotonic grace in milliseconds), `absent`, or
`runtime_lost`, plus independent `workers_retired`. A missing lease alone does
not prove terminal retirement. On original-runtime mismatch the reply is
`runtime_lost` with `workers_retired=false`; it never claims an original process
is alive or recreates it. Matching-runtime inactive/absent plus retired workers
can resolve retirement uncertainty, but is not an acknowledgement of the original
release request. New full SSH readiness requires `leases.observe`,
`leases.retirement` and `terminal.ordered_controls`; an incompatible running
supervisor is preserved.

## T16 original Git request lookup

`git.existing` attests the active helper's read-only `service.call/git_existing`.
The call carries the original `worktree`, `expected`, and `command`, with the
original operation ID in the header. The helper reconstructs the original request
using the authenticated target and validates its full request digest against the
existing ledger before reading the filesystem or current Git state. A changed
payload cannot inherit another request's receipt. No operation is accepted and
no ledger entry is created or overwritten by this lookup.

The `git_existing` reply requires a nullable `receipt`: null means no record was
found; an existing expired/interrupted record remains Unknown and is never
executed again. Null is not evidence that a previously submitted operation had
no effect or permission to replay it. Only ordinary first-submission policy can
admit a new mutation, with its original expected state and digest unchanged.
Explicit operation inspection remains available independently.

Lookup shares the existing reserved inspection/control admission on client and
helper. Engine ordinary Git mutation workers perform it before workspace-root
revalidation. Full environment readiness now requires `git.existing`; missing
support preserves the active supervisor and reports Unavailable. Remote checkout
and pull remain unavailable until the target save-proof and document gate are
composed. This capability grants no alternate execution expectation.
