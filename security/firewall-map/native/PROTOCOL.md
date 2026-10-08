# Firewall Map native helper protocol

`firewallmap-native` is a persistent child of the Python collector. It reads
requests on stdin and writes framed binary responses on stdout. Diagnostics go
to stderr (syslog under `daemon -S`). Every response is complete or the helper
exits: Python never resynchronizes a stream; it closes the helper instead.

All integers are big-endian. `addr` is 17 bytes: family (4 or 6), then 16
address bytes (IPv4 in the first 4, the rest zero). `f64` is an IEEE-754
double sent as its 64-bit pattern. A *frame* is `u32 length` followed by
`length` payload bytes (1..4096). The first payload byte is the record kind.
Checksums are CRC-32 (zlib polynomial) over every frame (length and payload)
before the footer, in order.

## Vocabulary

| Term | Meaning |
| --- | --- |
| wire key / stack key | PF's two state keys: addresses on the wire, and as the host stack sees them. |
| pf_direction | PF state direction (`in`/`out`) of the interface that created the state. |
| initiator / responder | The endpoints of the packet that created the state. |
| untranslated | The endpoint PF rewrote, before translation (inside source of SNAT, public destination of rdr). |
| local / remote | The logical flow pair: our-side anchor address and the external peer. |
| inside | The site-internal host endpoint, when known. |
| outside_view | Our side of the connection as the remote sees it. |
| remote_initiated | Exact: the remote is PF's initiator. Orients all counters. |
| apparent_remote_initiated | Presentation heuristic (low source port to high port counts as remote initiated). Never orients counters. |
| bytes_from_remote / bytes_to_remote | Oriented traffic; likewise packets and rates. |
| pf_bytes_forward / pf_bytes_reverse | Raw PF counters: initiator to responder, and replies. |

External JSON keeps older names for compatibility: `rate_in`/`bytes_in` mean
*from remote*, `rate_out`/`bytes_out` mean *to remote*.

## Banner

On start the helper writes one line:

    FMNATIVE5 pf_state_version=<n> freebsd_version=<n>\n

`pf_state_version` is the `PF_STATE_VERSION` the helper was compiled against
(every decoded state must carry exactly that version). `freebsd_version` is
the build host's `__FreeBSD_version`. Both are 0 on non-FreeBSD test builds.

## Sample request (FMCONF2)

Text lines, ending with `RUN`:

    FMCONF2
    THREATS                         include the threat summary
    SNAPSHOT                        stay in a snapshot session after the response
    BUDGET <memory_bytes> <candidates_per_kind> <threat_remotes>
    CORRELATION <0|1>               0: no IDS consumer; skip correlation work
    EVIDENCE <address>              remotes the threat summary must keep (≤ threat_remotes)
    Q <id> <proto> <public> <public_port> <remote> <remote_port>
    R <low> <high> <flags>          classification range (flags: 1 public, 2 private)
    L <address>                     firewall-local address
    N <address> <prefix> <device>   interface network, most specific first
    A <address> <device>            address assigned to an interface
    W <device>                      primary WAN device
    S <proto> <port> <group>        service grouping
    RUN

Each keyword row may appear at most once. `Q` ids are consecutive from 0.
Python does not send elapsed time: the helper anchors each sample at the
monotonic time it sent its PF dump request.

Context maxima (`L` 4096, `N` 8192, `A` 1024, `R` 1024, `S` 1024, `EVIDENCE`
= threat_remotes, `Q` 2500) are enforced on both sides. Exceeding an operator
context maximum (L, N, A) refuses the sample (outcome 2); any other malformed
or excessive row is a request failure.

## Sample response (FMAGG4)

    "FMAGG4\0\0", frames..., footer frame

| Kind | Record | Payload after the kind byte |
| --- | --- | --- |
| 0 | header | u32 version (4), u32 flags (1 threat summary) |
| 1 | flow | u32 rank, addr local, addr remote, u64 states, u64 bytes_from_remote, u64 bytes_to_remote, u32 oldest_age, u32 youngest_age, u64 remote_initiated_weight, u64 local_initiated_weight, u64 first_seen_seq, u64 delta_bytes_from_remote, u64 delta_bytes_to_remote, u64 delta_packets, f64 rate_from_remote, f64 rate_to_remote, f64 packet_rate, f64 activity, f64 score |
| 2 | candidate | u32 rank, u8 kind, u64 seq, u64 weight, u64 association, u16 length, value |
| 3 | threat remote | u32 index, addr, u64 remote_initiated_states, u64 local_initiated_states, u64 bytes, u32 youngest_age |
| 4 | threat candidate | u32 remote index, u8 kind, u64 seq, u64 association, u16 length, value |
| 5 | event match | u16 query, u8 match kind, u8 proto, addr public, u16 port, addr remote, u16 port, u8 has_inside, addr inside, u16 port, u64 state id, u32 creator, u8 ambiguous, u32 age, u64 bytes_from_remote, u64 bytes_to_remote, u64 packets_from_remote, u64 packets_to_remote, u8 remote_initiated, u8 apparent_remote_initiated, char[16] interface, char[64] rule label |
| 6 | telemetry | see below; exactly once, before the footer |
| 255 | footer | u32 outcome, u32 refused context kind (ASCII row letter or 0), u64 refused actual, u64 refused limit, u64 states seen, u64 retained, u64 mapped, u64 flows total, u64 flows sent, u64 candidates sent, u64 matches sent, u64 threat remotes sent, u64 threat candidates sent, u32 checksum |

Candidate kinds: 1 protocol, 2 inside host, 3 egress interface, 4 service,
5 remote target, 6 rule label. Event match kinds: 1 current state, 2 recently
seen state. Records of kinds 1 to 5 appear in nondecreasing kind order; ranks
and indexes are dense from 0.

Outcomes: 0 sample, 1 refused (too many PF states), 2 refused (context
maximum exceeded), 3 refused (helper memory budget). A refusal carries no
flow, candidate, threat or match records, and resets the rate baseline: the
next accepted sample is a baseline.

Telemetry record (kind 6):

    u32 helper pid, u64 sample sequence, f64 interval seconds (-1 baseline),
    f64 dump seconds, f64 processing seconds, f64 helper user CPU seconds,
    f64 helper system CPU seconds, u64 max RSS bytes, u64 heap bytes,
    u64 heap peak bytes (this sample), u64 heap blocks, u64 heap budget bytes,
    u64 preflight state count (0 when unavailable),
    u64 skipped states (unsupported address-family translation),
    u64 candidates omitted, u64 threat remotes omitted,
    u64 threat candidates omitted, u64 event history evictions

## Failure response (FMFAIL1)

When a request cannot be answered and nothing of a response was written yet,
the helper writes

    "FMFAIL1\0", one frame: u8 254, u32 class, i32 errno, message bytes

and exits. Classes: 1 structural (malformed or truncated PF/netlink data),
2 internal invariant, 3 incompatible PF ABI, 4 resources, 5 malformed request.

## Snapshot session

After a sample requested with `SNAPSHOT`, the helper waits for commands:

    FMSNAP1 PAGE <offset>                         -> FMPAGE1
    FMSNAP1 SELECT <generation> <count>, F rows, RUN -> FMAGG4 (selected flows)
    FMSNAP1 DETAIL <generation> <bytes> <states> <count>, F rows, RUN -> FMSTATE2, session ends
    FMSNAP1 CANCEL                                -> no response, session ends

`F <local> <remote> <required>` rows identify flows. A session never changes
the rate baseline.

FMSTATE2 (`"FMSTATE2"`, frames, footer):

| Kind | Record | Payload |
| --- | --- | --- |
| 0 | header | u32 version (2), u64 generation |
| 1 | state | u32 flow index, JSON object |
| 2 | flow totals | u32 flow index, u64 matching states, u64 captured states, u64 bytes_from_remote, u64 bytes_to_remote, u64 packets_from_remote, u64 packets_to_remote, u8 omission reasons (1 byte budget, 2 state budget, 4 per-flow quota) |
| 255 | footer | u64 traversed, u64 matching, u64 captured, u64 encoded bytes, u32 omission reasons, u32 selection policy, u64 skipped states, u32 checksum, f64 sample time, f64 detail start, f64 detail end |

Every selected flow has exactly one totals record. Totals are exact over all
matching states, independent of how many exemplars were captured.
