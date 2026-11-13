# The flow record

A flow record is one observed conversation: who talked to whom, when, how much,
and whether the far end answered. Three producers write it and several commands
read it, so it is a contract rather than a convenience:

| producer | source | reads |
|---|---|---|
| `zeek-to-flows` | `zeek` | zeek `conn` logs or parquet |
| `loot-flows` | `arkime` | the Arkime sessions API |
| `loot-conntrack` | `conntrack` | `conntrack -L` and `-E` on a host |

`tighten`, `firru diff --flows` and `flow-verdict` read them back.
`docs/flow-record.schema.json`
carries the types and the required list, and nothing else: the meaning is here,
in one place, so the two cannot drift into disagreeing about it.

One `flows.jsonl` may hold records from several producers, so every record names
its own `source`.

A producer may add fields of its own beyond the ones below, and a consumer has
to tolerate them. Where a fact is one several producers can supply, it is named
once here instead -- see "Conditional fields".

## Normalize the decision, not the label

Each source describes a connection's state in its own vocabulary. Zeek's
`conn_state` summarizes a finished connection (`SF`, `REJ`, `OTH`); conntrack's
state is where the TCP machine stands right now (`ESTABLISHED`, `SYN_SENT`);
IPFIX, if it is ever added, would offer `flowEndReason` and `tcpControlBits`.
These do not map onto one another, and a merged vocabulary would invent
equivalences that are not true.

So the raw labels stay raw, each under its own name — `conn_state` for the
zeek-shaped sources, `ct_state` for conntrack — and never share a field. What is
normalized is the *decision* a consumer needs:

- **`direction_known`** — is `originator` really the end that opened the flow?
  Zeek answers from `conn_state`, Arkime from the handshake, conntrack
  because the kernel followed the flow from its first packet.
- **`responded`** — did the far end answer? The admitted/blocked axis.

A consumer asks those two questions and never learns any producer's vocabulary.
This was not always so: a consumer once read `conn_state` directly,
so a conntrack record — which has no `conn_state` at all — read as midstream
capture and had its direction second-guessed by a port heuristic, turning an
NFS mount from a reserved client port into a listener on that port.

Adding a source means answering the two questions, not extending an enum.

## Addresses are canonical text

`src_ip`, `dst_ip` and `originator` are in canonical text form: dotted quad
for IPv4, RFC 5952 for IPv6 (compressed, lowercase), which is what Python's
`ipaddress` and Zeek both write. Consumers compare them as strings, against
addresses taken from the definitions in the same form, so a producer whose
source spells them differently converts them. One that did not (LSPR24 writes
IPv6 fully expanded) had every IPv6 flow silently match no host.

## Absent is not zero, and not-yet is not no

`orig_pkts` and `resp_pkts` are null when the source does not count packets,
which is a different statement from a flow that carried none. conntrack counts
only when `net.netfilter.nf_conntrack_acct=1`, and only for flows created after
it was switched on.

`responded` is null on a conntrack `NEW` event. A flow created a moment ago has
not been answered *yet*; reporting that as `false` would turn every connection
attempt into evidence of a block.

`timestamp` is null where the source has no clock for the flow. conntrack gives
one under `-o ktimestamp` with `net.netfilter.nf_conntrack_timestamp=1`, or
under `-o timestamp` for events, which is conntrack's own wall clock.

## What direction_known does not promise

For conntrack it is `true` on the assumption that the kernel saw the flow open.
`net.netfilter.nf_conntrack_tcp_loose` is 1 by default, so the kernel also
adopts TCP flows it never saw a SYN for, and the text output does not mark them.
On a host watching its own sockets that is rare. On a gateway, or anywhere
forwarding traffic it did not originate, conntrack has the same midstream
problem as a capture source and this field is optimistic.

## Conditional fields

Not every fact about a flow is an observation of it. Some come from a list
someone maintained -- a red-team address list, a zone map, a name -- and exist
only for the runs where that list was on hand. These are not optional in the
sense of being decorative: a consumer that needs one has to check whether it is
there.

The rule is that each such fact has exactly one spelling, whichever step
supplies it.

| field | means | written by |
|---|---|---|
| `fqdn` | the name the destination was reached by | a naming layer, where one is installed (none ships with this release: `zeek-to-flows` writes it null in a parquet store, so the store's schema does not vary) |
| `rt_src`, `rt_dst` | the endpoint is red team | `flow-verdict --rt-ips` |
| `src_zone`, `dst_zone`, `intra_zone` | the endpoint's zone | `flow-verdict --defs`, from `{ZONE}_HOSTS` membership |
| `src_token`, `dst_token`, `src_groups`, `dst_groups` | the aerleon definition the endpoint resolves to | `annotate-flows --defs` |

### How red team gets known

`rt_src` says whether an endpoint is red team, not how that was decided. There
are three ways it is decided, and they are not the same claim:

**Live.** There is no list. The exercise is running, and who the red team is is
the thing under investigation. `rt_src` is absent, and most of the analysis does
not need it -- a policy is scored against what it allowed, not against who was
on the other end.

**Post-hoc, with the released list.** The exercise publishes red-team addresses
afterwards and `flow-verdict --rt-ips` annotates the flows against them. The
file shape is whatever that exercise happened to publish; `firru.iptrees` takes
a bare list, a mapping, or one CIDR per line, so a new exercise should mean a
new shape there and not a new tool. The list is a snapshot: a flow annotated
against one revision and re-annotated against a later one can change its answer,
and the later one is not retroactively what was known at the time.

**A dataset that came with labels.** Some public datasets carry their own
label column. That is red-team *identity*, ground truth about who the peer was
rather than anything a detector observed, so scoring detection with it is
circular. The source data cannot be corrected either: someone else collected
it, parts of it may be missing, and the work is to normalize what is there and
name what is not. The record's `source` says which dataset it came from.

### false is a finding; absent is not

The null rule above has a sharp edge here. The flag is written for both
endpoints whenever a list was consulted, `false` included; it is absent only
where nothing was evaluated, which is the live case. Omitting the `false` looks
harmless and is not, because the clean arm of the 2x2 is `NOT rt_src`: a missing
field is null, `NOT` null is null, and the row falls out of both arms instead of
into the clean one. What goes quietly wrong is a denominator.

The same asymmetry applies one layer up, to the list itself. A list that fails
to load is not an empty list: it would mark every flow as *not* red team, which
is a claim about the traffic rather than about the file. `firru.iptrees` raises
rather than returning nothing.

## Annotated flows

`flow-verdict` is both a consumer and a producer: it reads a flow record,
resolves the destination against a policy tree, and writes the same record back
with `direction`, `host`, `policy_verdict`, `matched_term`, `practice`,
`src_zone`, `dst_zone`, `intra_zone`, and one `verdict_<name>` per
counterfactual variant. Nothing is removed, so an annotated flow is still a flow
record and still validates.

It reads `responded` through the null rule above: null is `practice: unknown`,
not `blocked`, and it does not fall through to `incomplete`, which is true on a
just-created flow for the same reason. This is where the rule earns its keep --
the 2x2 in the paper counts those columns.

## Parquet stores

The same record is written as a partitioned parquet store by
`zeek-to-flows --parquet`. duckdb reads a glob of parquet files only when they agree on
their columns, so a store written before `source` and `direction_known` existed
cannot take a new partition: the append would make the *whole* store unreadable,
not just the new part. `firru.flows.check_appendable` compares the store's
columns against what the run is about to write and refuses, the same way it
already refuses a fractional timestamp into a whole-second store. Rebuild such a
store, or write to a new directory.

`firru.flows.ZEEK_FLOW_COLUMNS` is read off the SQL projection itself, so the
JSONL route and the parquet route cannot drift apart unnoticed;
`tests/test_zeek_to_flows_parquet.py` compares them row by row.
