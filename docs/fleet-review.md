# Reviewing a fleet against baselines

The order is: what the hosts run beyond stock, then names for that, then the
policy. A baseline (a stock install of the OS or role, from
firru-os-baselines) explains most of what a host listens on. What it doesn't
explain is short, and that short list is what a person has to look at.

## Steps

1. **Collect.** `scripts/loot-host.sh` / `loot-host.ps1` on every host, into
   `loot/`. The loot records each host's ephemeral (dynamic) port range, so a
   host whose range was moved (Exchange Setup starts TCP's at 6005) is
   compared by its own range.

2. **Diff the fleet against its baselines**, one baseline per role:

   ```
   firru diff --baseline baselines/ loot/ -o sh \
       --assign 'dc*=win2022-dc' --assign 'mail*=win2022-exchange' \
       --assign 'ws*=win11' --assign '*=win2022' > review.sh
   ```

   `review.sh` lists the fleet's delta once, not per host:

   ```
   # ! RemoteTool_Service holds 10 dynamic udp port(s) on 5 host(s): a process the baseline does not have
   # firru edit-services add def/funny.yml TCP_8091 8091/tcp  # unnamed: pythonx10; 10 host(s)
   # + RDP 3389/tcp,3389/udp  (svchost; 28 host(s)) beyond the baseline
   # + SSH 22/tcp  (sshd; 28 host(s)) beyond the baseline
   firru synth --input loot/ --output policies/staged --defs def --overwrite
   firru diff policies/pol/ws01.yml policies/staged/ws01.yml --defs def
   ...
   ```

   - `# !` is a process the baseline doesn't have, holding dynamic ports. Its
     port numbers change at every restart, so the finding is the process.
   - `# firru edit-services add ...` is a port that no service token names.
   - `# +` is a named service beyond stock: a feature someone switched on, or
     software someone installed.

3. **Name.** One decision per distinct port, not per host. Edit and run the
   `edit-services` lines (they are comments because naming is a judgment):
   change the token name, and point each line at the file it belongs in (see
   below). Accept or question each `# !` and `# +`.

4. **Synthesize once**, for the whole fleet (the `firru synth` line).

5. **Review per host** with the `firru diff` lines, in this order:
   - hosts with `# !` or unnamed additions: that's where the findings are
   - hosts whose delta is only named services; hosts with the same delta (most
     workstations) can be reviewed as one, by checking the rest match it
   - hosts equal to their baseline, last

## Where definitions go

| File | Who edits it | What's in it |
|---|---|---|
| firru's `def/` | nobody (ships with firru) | well-known and Windows services; used when there is no `./def` |
| `<segment>.yml`, `<host>.yml` | the operator | the site's own software, by name |
| `site.yml` | the operator, via `edit-services` | stock software on a number the site chose: a moved port, a narrowed RPC range (`WINDOWS-RPC-DYNAMIC-<lo>-<hi>`) |
| `funny.yml` | the operator | unnamed ports (`TCP_<port>`) and nothing else |

An unnamed port is funny until someone says what it is; then it moves, under a
real name, to a segment or host file (the site's own software) or to
`site.yml` (stock software on a moved port). `TCP_` and `UDP_` tokens anywhere
but `funny.yml` mean that step was skipped, and `funny.yml` should shrink to
empty: what stays in it is a finding of its own.

## Relation to the paper's pipeline

The paper synthesizes the policy from what the hosts listen on and then
narrows each rule's sources from observed traffic. That is steps 4 and 5
here. The baseline diff before it changes what the reviewer reads: not every
listener, but only what the fleet runs beyond stock, with names decided once
for the fleet before any policy is written.
