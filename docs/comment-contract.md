# The comment contract

How firru tools may and may not touch a human-edited policy or service file.

## The problem

A `policies/pol/<host>.yml` (and `def/services.yml`) is edited by tools *and*
by hand. Its comment block ends up holding three unrelated kinds of record in
one untyped channel:

- **derived view** — observed IPs, processes, flow counts, `[NEW]`, `via:`,
  aliases. Regenerable from loot/flows. *Wants* to go stale and be refreshed.
- **human intent** — "DO NOT BLOCK, partner integration", "keep ANY until Q3,
  vendor still migrating". Authored, not regenerable, must survive untouched.
- **audit / history** — "was: ANY", "changed by reloot". The previous value of
  something now overwritten.

Because they are indistinguishable text, "regenerate the comments" is unsafe:
it cannot refresh the stale derived view without also destroying hand-written
intent. The file has become a database with one untyped column.

## The rule

**Every comment line is typed by the source that regenerates it.** The type is
a leading tag; an untagged line is owned by nobody and is inviolable.

```yaml
- name: allow-tcp-POSTGRES
  # [auto] IPv4 10.0.0.5 (postgres) | 1234 flows: NET_APP (h1, h2)
  # [score] DO NOT BLOCK — partner integration
  # keep ANY until Q3, vendor still migrating          <- untagged: human, never touched
  protocol: tcp
  destination-port: POSTGRES
  action: accept
```

| tag        | regenerated from        | who writes it            |
|------------|-------------------------|--------------------------|
| `[auto]`   | loot / flow store       | any generator            |
| `[score]`  | `scoring.yml`           | the scoring pass         |
| *(none)*   | nobody — authored       | a human, in `$EDITOR`    |

History is **not** a tag. "was: ANY" is the pre-change value, which is exactly
what `git diff <file>` and `git blame` already hold, losslessly and dated. Do
not write a `[hist]` line; lean on the repo.

## The contract every tool obeys

> A tool may rewrite only the lines carrying its own tag. `[auto]` lines are
> fair game for any generator; every other line — `[score]`, untagged — is
> inviolable. Data fields (`source-address`, `destination-port`, `action`,
> the term list) are changed only by an explicit, named operation.

This is **not** a feature of one tool. It binds every tool that round-trips a
human file: `firru synth`, `firru tighten`, and the edit commands (`firru
set-source`, `firru apply`, `firru rm`) alike. A
generator that rewrites a term's whole comment block — as `tighten` once did,
with an unconditional `yaml_set_start_comment` — violates it and silently eats
intent. The `firru.comments` helper is the shared implementation: it recovers
each term's non-`[auto]` lines before a rebuild and re-attaches them, hiding
ruyaml's quirk of storing a term's leading comment on the previous sibling.

Once every generator honors it, both adoption flows below are safe *for the
same reason*.

### Which YAML library

The contract dictates the library, not taste:

> **ruyaml** for any tool that emits or round-trips a human-facing firru YAML
> (pol, staged, def stubs) — only round-trip loading preserves the comments the
> tags live in. **PyYAML** (`import yaml`) is fine for reading YAML as data and
> for writing non-firru compile targets (nftables, VyOS, Calico, nmap), where
> formatting is discarded anyway.

Doing everything with ruyaml would not be *wrong*, just unnecessary — PyYAML is
the lighter choice where comments are irrelevant. The one hard invariant:
**never read a firru file with PyYAML and write the same file back.**
`safe_load` silently drops every comment and tag, so a read-modify-write through
it is a contract violation even though nothing looks amiss. `merge_zones` reads
pol with PyYAML but is on the right side of this line: it does not write pol, it
emits a fresh, wholesale-regenerated `zones/` view and keeps its machine notes
in aerleon's `comment:` *data* field, not `#` comments.

## Term identity

Terms are matched across files by their **resolved `(direction, proto, port)`
surface**, never by token name or term name. Expanding `destination-port`
through the aerleon defs is what makes the following all classify correctly:

- a service renamed `TCP_5432` → `POSTGRES` — same surface, cosmetic
- a service folded into a group token on one side — same surface, unchanged
- postgres moved to a docker port — surface changed, a real add/remove
- a policy carrying both directions — ingress and egress at tcp/443 are two
  rows, compared against their own side's peer field (`source-address`
  inbound, `destination-address` outbound)

A diff over two generated policies classifies each port as:

| class                 | example                          | default action                    |
|-----------------------|----------------------------------|-----------------------------------|
| added (known svc)     | new listener on a defined port   | apply — copy the term verbatim    |
| added (unknown port)  | rogue / undefined port           | **alert**, never auto-allow       |
| removed               | postgres → loopback-only         | annotate; `--prune` opt-in; **scoring vetoes** |
| modified, enforcement | source ANY → DOCKER_INTERNAL     | advisory — preview old vs new     |
| modified, cosmetic    | token renamed, process changed   | auto — refresh the `[auto]` line  |
| unchanged             | —                                | nothing                           |

Diff the generated `policies/staged/` snapshots, not raw loot: the generator
already drops loopback-only binds and runs source heuristics, so
"postgres → loopback" shows up as a missing term and "bind moved" as a changed
source-address, with cosmetic bind noise producing no diff at all. The
generated policy is the right comparison surface.

## The two adoption flows

**Wholesale** — *baseline → tighten → copy over, go through everything.*
Regenerate `staged/`, run `tighten`, then adopt the result and read it top to
bottom. Adoption is a copy (`cp`, or copy in `$EDITOR`); it is safe only
because the generator left untagged intent lines alone. Bulk edits during the
read-through are trivial precisely because token names are **not** load-bearing
— a mass rename `HTTP` → `HXXP` is a find-replace (or a regen), never a
per-term judgment, because identity is the port surface and the token is just a
label.

**Surgical** — `firru diff policies/pol/<host>.yml tightened/<host>.yml
--defs def -o sh` writes each change as one runnable `firru` command (a
narrowed source is a `firru set-source` line); keep the lines you trust
(`grep HTTP`) and run them. That copies just the term's `source-address`
(data) and refreshes its `[auto]` evidence, touching nothing else. This is the flow for "I trust only the HTTP
tightening", where a wholesale copy would drag in the egress rebuild and every
other change.

Both are legitimate. The wholesale copy is the baseline and needs no tool —
`$EDITOR` already does copies and renames. The edit commands earn their
existence **only** for the surgical case.

## The edit commands' boundary

The edit commands automate edits that are **deterministic and regenerable** —
regenerate the `[auto]` block, copy a verbatim addition term, pull one named
tightened field. The moment an edit needs a *choice* (keep ANY? is
DOCKER_INTERNAL right? allow this rogue port?) there is no flag for it: the
tool tells you where to open `$EDITOR`, not a switch that decides for you.
Looking and writing are separate: `firru diff` only reports (or prints the
commands), `firru apply --dry-run` previews a merge, every write is a command
that names what it changes, and destructive actions take their own flag
(`firru apply --prune`, `firru rm --force` for a term with a scoring note).

If a proposed flag seems to want an argument that encodes a judgment, that is
the signal to stop and let the editor win.

## Services are the same model, already split

`def/services.yml` has the identical structure, but cleaner: the human
decision is the **token name and its port grouping** — structural data in the
key, not a comment — so the comment column is *entirely* `[auto]`.
`audit-services` is the read side: `--report`/`--all` emit the observed service
surface (100% regenerable, arguably never persisted — a report you pipe), while
`def/services.yml` holds the naming decisions. The old hand-maintained
`funny.yml` conflated view and decisions in one file; splitting them is this
contract applied once already. Policies are catching up.

## Summary

Generators emit **views** (all `[auto]`, regenerable). Humans own **decisions**
(token names, sources, intent notes — untagged or structural). Git owns
**history**. The edit commands only automate the mechanical reconciliation between
view and decision; everything else is `$EDITOR`.
