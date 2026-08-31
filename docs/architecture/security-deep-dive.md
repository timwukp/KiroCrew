# Security Deep Dive

The security **architecture**: what Kiro Crew defends against, where its trust
boundaries sit, and how the layers compose. Mechanism detail (exact rule tables,
regex shapes, per-function algorithms) lives in the module specs and is linked
from here rather than restated:

- [`../system-specs/modules/security.md`](../system-specs/modules/security.md)
  is the mechanism spec for every control below.
- [`../system-specs/modules/governance.md`](../system-specs/modules/governance.md)
  is the two-level Policy ∩ Profile model.
- [`../system-specs/modules/platform-context.md`](../system-specs/modules/platform-context.md)
  is the edition seam that lets a companion ADD (never remove) deny rules.
- [`resource-protection.md`](resource-protection.md) covers the DoS/resource
  ceilings (cgroup scope, RLIMIT, file descriptors).

Counts are deliberately absent from this document. Every posture count is
derived at runtime by `security_posture.py` and rendered in Settings → Security
from `GET /api/security/posture`; a number written into prose goes stale silently
while the code it describes keeps changing.

## Threat model

Kiro Crew runs an LLM agent with filesystem and shell access on the operator's own
machine. The dominant threat is **prompt injection from content the agent reads**
(web pages, repository files, Slack thread history, imported documents): text
that is data as far as the operator is concerned, but that the model may follow as
instructions. The two payloads that matter are credential exfiltration and
destructive local action.

Three properties shape every control:

1. **The model is untrusted input, not a trusted caller.** Anything the model
   chooses (a tool title, a file path, a command string) is attacker-controllable
   in the injection case. Controls therefore key on ground truth (the real
   `tool_input` command, the resolved filesystem path) and never on model-authored
   display text alone.
2. **The operator is trusted, the agent is not.** The operator may widen their
   own posture; the agent must not be able to widen it for them. That asymmetry is
   what the keystone (below) enforces.
3. **No single layer is assumed to hold.** A credential read has to defeat the OS
   sandbox, the path gate, the command gate, and output redaction; they fail in
   different ways and are not correlated.

The per-threat mitigation table (XPIA credential theft, WebSocket hijack, CSRF,
DNS rebinding, unauthenticated remote access, and the rest) is in
[`security.md` § Threat Model](../system-specs/modules/security.md).

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforced by |
|---|---|---|---|
| Gateway process ↔ agent subprocess | Kiro Crew gateway | `kiro-cli` + every tool/MCP descendant | OS sandbox (`sandbox.py`), env scrub, cgroup scope |
| Agent tool request ↔ execution | the PreToolUse gate's decision | the tool call as the model phrased it | `hooks.py:HookManager.on_tool_call` |
| Operator ceiling ↔ agent | keystone files under the data home | every agent read/write path | `security.is_sensitive_path` / `is_sensitive_write_path` |
| Agent output ↔ any human or external service | nothing | all agent-derived text | `redact_credentials` / `redact_exfiltration_urls` / `StreamRedactor` |
| Browser ↔ dashboard | authenticated session | any other origin or host | token auth, CSRF Origin check, Host allowlist |
| Slack workspace ↔ gateway | owner + allowlisted users | every other Slack sender | owner lock, `is_allowed_user`, Enterprise Grid check |

The single most important structural property: **the PreToolUse gate is
Kiro Crew's own gate, not the agent's.** Denied commands and the governance
ceiling are evaluated in `hooks.py` and are never written into a `kiro-cli` agent
JSON, so an agent config that omits or edits its own deny list cannot weaken the
ceiling.

## How the layers compose

```
Layer 5  Audit ........ SEL event log (HMAC-chained, verifiable)
Layer 4  Output ....... credential redaction + URL exfil scan + streaming redactor
Layer 3  Validation ... typed MCP tool schemas, unicode normalization, length caps
Layer 2  Command ...... denied-command rules + sensitive-bash + exfil shapes
Layer 1  Filesystem ... resolved-path gate (read block + wider write block)
Layer 0  OS sandbox ... namespace (Linux) / Seatbelt (macOS), opt-in

Across all layers: request auth (dashboard tokens, CSRF, Host allowlist),
                   Slack owner lock + workspace origin check,
                   governance ceiling (Policy ∩ Profile), SEL audit
```

Layers 1 through 4 are always on and are the reason Layer 0 can be optional.
Layers 1, 2 and the governance ceiling all evaluate at the same chokepoint
(`on_tool_call`), in a fixed order that matters: sensitive-path and deny checks
run **before** any auto-approve or trust fast-path, so a user trust decision or an
active YOLO grant can never route around a hard deny.

## Layer 0: OS-level sandbox (`sandbox.py`)

Confines the `kiro-cli` subprocess tree with platform-native isolation, hiding
credential directories by bind-mount (Linux user + mount namespaces) or file-read
denial (macOS Seatbelt), and scrubbing credential-bearing environment variables
on the way in. Windows has no Kiro Crew OS wrapper, so positively identified
official Kiro CLI spawns delegate to the CLI's built-in sandbox; their environment
is scrubbed by the parent before spawn. The parent gateway process is unaffected.

**`agent.sandbox` defaults to `"auto"`, engaging OS-level isolation
(namespace on Linux, sandbox-exec on macOS).** The only alternative value is
`"off"` (`config/loader.py`, `AgentConfig.sandbox`, `enum=["auto", "off"]`;
the same two-value enum gates the dashboard config editor in
`dashboard/handlers/core.py`). `"off"` skips Kiro Crew's own sandbox but still
delegates to `kiro-cli`'s internal agent sandbox on macOS when it is enabled,
which cannot nest inside Kiro Crew's
Seatbelt wrap (the macOS kernel returns EPERM even under an allow-all outer
profile), so exactly one layer can own isolation per spawn. Setting `"auto"`
re-enables Kiro Crew's own sandbox.

`wrap_argv`'s internal tier vocabulary is wider than the config enum: `standard`
(what `auto` resolves to), `cc`, `strict` and `off`. Those extra tiers are reached
by internal callers and by the governance `sandbox.min_level` ordinal floor
(`_ORDINAL_SCALES["sandbox"] = ("off", "standard", "cc", "strict")`), which clamps
a requested mode **up** before resolution, so an enterprise floor confines even a
`mode="off"` call. They are not values an operator writes into `agent.sandbox`.
Per-tier hidden paths, the empirical backend probes, the nested-passthrough rule
and the fail-closed/fail-open flags are specified in
[`security.md` § OS-Level Sandbox](../system-specs/modules/security.md).

Two properties are load-bearing at the architecture level:

- **Failure is refusal, not degradation.** With no sandbox backend available and
  a mode other than `off`, `wrap_argv` raises rather than spawning unconfined.
  Running unconfined is an explicit opt-in (`agent.sandbox_allow_unsandboxed_exec`);
  a separate flag (`agent.sandbox_allow_no_isolation`) only demotes the warning's
  log level and does not permit execution. The opt-in's default is
  **platform-independent** — a platform-derived default would grant unconfined
  execution on every backend-less host with no operator having declared it — so
  the discoverable path is instead a consent step in `kirocrew setup`, which
  prompts (default no) when `detect_backend()` reports `"none"` and writes the
  key only on an explicit yes.
- **Windows Kiro delegation is not a global fail-open.** `is_kiro_cli=True` from a
  reviewed official-Kiro spawn site delegates directly to Kiro's built-in sandbox
  before backend probing. A Kiro-looking filename is insufficient on Windows.
  Third-party ACP backends, scripts, hooks and other subprocesses still take the
  normal no-backend refusal and require the explicit opt-in above.
- **Delegation is audited, never silent.** When `kiro-cli`'s internal sandbox owns
  isolation for a spawn, the decision is config-driven (never a reaction to a wrap
  failure), logged once per process, and SEL-audited on an audit-or-deny basis: if
  the audit cannot be written, the delegation is refused. Kiro Crew's own Seatbelt
  takes the spawn on macOS; Windows returns to its no-backend fail-closed policy.

**Launcher shims are deliberately not bypassed on the delegated path.** On that
path the shim is part of `kiro-cli`'s own sandbox mechanism, so resolving past it
would defeat the delegated layer. Where an edition needs a managed launcher
replaced with the executable it ultimately invokes, that goes through the
`PlatformContext.agent_executable` resolver, whose result is always placed
*inside* the same namespace/Seatbelt wrapper. The capability probe never runs an
edition-resolved or user-writable target; it runs a fixed trusted system binary.

### Why the default is defensible

The sandbox is the only optional layer, so the credential-read threat has to be
covered without it. It is, three times over, at different altitudes:

- A tool read of `~/.aws` or `~/.ssh` is refused by the resolved-path gate
  (Layer 1), which follows symlinks before deciding.
- A shell read of the same paths is refused by `is_sensitive_bash_command`
  (Layer 2), which tokenizes and normalizes the command rather than pattern-
  matching raw text, so quoting and expansion tricks do not evade it.
- Anything that still reaches tool output is caught by redaction (Layer 4) before
  it reaches a human or an external service.

`SSH_AUTH_SOCK` is scrubbed whenever a Kiro Crew sandbox tier is active, so
ssh-agent forwarding is unavailable inside a confined spawn. Operators who depend
on passphrase-protected keys or hardware tokens use key files directly or leave
`agent.sandbox` at `off`.

## Layer 1: Filesystem gate (`security.py` + `hooks.py`)

`is_sensitive_path()` is the shared read+write block, and
`is_sensitive_write_path()` is its strict superset: it adds paths that stay
readable but must not be modified by an agent tool (the data home's `config.json`
/ `config.local.json`, which carry resource ceilings, and the data-home migration
marker, whose mere presence is a trust signal). Path matching checks the fully
symlink-resolved target as well as the lexically normalized and raw forms, so a
workspace symlink into a blocked directory is refused through the link.

`hooks.safe_read_file()` is the guarded read used by Kiro Crew's own non-tool file
access: it re-checks the resolved target and then opens the canonical path with
`O_NOFOLLOW`, which closes the TOCTOU window where the final component is swapped
for a symlink after the check.

### The keystone: the agent cannot read or rewrite its own ceiling

The governance trust root (`security_policy.json`, `profiles/`,
`admission_policy.json`), the denied-command opt-out state
(`denied_commands.json`), the SEL HMAC key and event log, the dashboard token
signing key, and the channel credential `.env` all sit on the read+write block.
This is a single mechanism with an outsized consequence: it is what makes the
enterprise ceiling **un-disableable from inside the agent**. An agent that could
read these could forge tokens or impersonate internal callers; one that could
write them could set `disable_all: true` and neuter the deny gate after a
restart. Every legitimate reader and writer opens these paths directly rather
than through the shared gate, so real functionality is unaffected.

Each leaf is registered under every known data-home prefix, so a not-yet-migrated
legacy home is fenced identically to the current `~/.kiro/crew`.

#### The container the leaves sit in

Every leaf above is identified by its **path**, which silently assumes the directory
holding it stays where it is. It did not. `rm -rf ~/.kiro/crew` was already refused,
but relocation was not, so

```
mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew
```

left every fence naming a file that is no longer there, and the next write to
`security_policy.json`, `profiles/`, `admission_policy.json` or `computer_use.json`
followed the link. A bypass of the ceiling itself, not of one feature.

`is_unreplaceable_container` closes it. Two properties are load-bearing:

- **Exact, not prefix.** The leaf matcher is prefix-based, so adding the data home to
  `_SENSITIVE_HOME_DIRS` would fence `sessions/`, `memory/`, `skills/` and `logs/`
  and cut the agent off from its own working data. Only the container itself is
  refused; everything under it stays as reachable as it is today.
- **Verb-independent, with no exemptions at all** — an enumerated write-verb
  allowlist is bypassable (`mv`, `ln`, `cp`, `rsync`, a novel verb, a Python
  `os.rename`), so the refusal is on *naming* the container.

  There was briefly a `cd`/`pushd` carve-out, on the reasoning that entering a
  directory cannot relocate it. It is gone. Identifying the operand meant inspecting
  the preceding token, so `mv cd ~/.kiro/crew` claimed the exemption by containing the
  word `cd`; and `cd` is a builtin that a function or alias can shadow, so even a
  correct parse would not have been evidence. Deciding what a token *means* in a shell
  needs a shell. The cost of removing it is bounded by the match being exact — only
  `~/.kiro/crew` itself, never anything beneath it.

**Shell expansion is normalized before either gate matches.** Bash expands an operand
before the command runs and the matcher did not, so `~/.kiro/cr{e..e}w` arrived as a
literal matching no protected path and reached bash as `~/.kiro/crew`. This was never
specific to the container gate — the **leaf** gate had the identical hole, so
`cat ~/.kiro/cr{e..e}w/security_policy.json` read the trust root. Brace expansion
therefore lands in the shared candidate generator, where both gates inherit it, and a
glob carrying `*`/`?`/`[…]` is refused when it *could* name a protected path, since a
gate cannot resolve one without the filesystem.

The expander models bash, and four divergences from it were each a bypass: a
**descending** range (`{w..e}`) produced an empty span where bash produces `crew`; an
**oversized** brace was truncated, dropping the tail so a 65-item list with `crew` last
expanded to `crew` in bash and to everything-but-`crew` here (it now fails closed); a
**shadowed** `cd` (`cd(){ mv "$1" /tmp; }`) inherited the navigation carve-out, so
defining or aliasing one of those verbs now withdraws it; and a **custom
`KIROCREW_HOME`** was invisible to the raw scan, which is the only layer that sees an
interpreter payload — the configured root is now its own branch, and the compiled
pattern is cached per value rather than pinned at first call.

None of that makes the matcher a shell parser, and it is not meant to: the floor under
it is the sandbox hide list above, which a shadowed builtin or a runtime-assembled
payload cannot reach past.

Brace ranges take bash's optional step (`{a..z..2}`); without it the whole range
matched nothing and the token read as clean. And `*` does not match a leading dot
**unless the command enables it** (`shopt -s dotglob`, `setopt globdots`), under which
`~/*` names `~/.kiro` — detected in the command text, which is the scope a per-command
matcher has. An option set in a startup file is outside it, which is one more reason
the hide list above is the floor and this is not.

Glob matching is **component-wise**, not `fnmatch` over the whole path: `fnmatch`'s `*`
crosses `/`, which denied a bare `ls *`, and it ignores the dotfile rule, which matched
`~/*` against `~/.kiro`. Bash's rules are what keep an ordinary home listing out of the
gate while `ls ~/.kiro/*`, which names the container, stays refused. Expansion is
bounded — past the cap the token is left unexpanded and the metacharacter arm still
refuses it.

It runs in all three passes — raw regex, normalizer, and the `cd`-resolved segment
walk — because the gate beside it does. Wired into only one, it missed the
`cd`-relative, variable, and interpreter-payload forms the leaf gate had caught for
a long time; `TestItIsNoWeakerThanTheLeafGateBesideIt` asserts that parity
form-by-form so the two cannot drift apart again.

#### A subprocess is not constrained by a command gate

The command gate reads command **text**. `./script.sh`, `make install` and `npm run
build` are each one opaque token to it, and whatever they write internally is never
inspected — so the path fence refuses
`echo x > ~/.kiro/crew/security_policy.json` and says nothing about a script
containing that exact line. The fence was never the layer that stopped a subprocess.

The sandbox's hide lists are, on **every** mode:

| what | where | which modes |
|---|---|---|
| `variables/`, `profiles/` | `_STRICT_DIRS`, `_STANDARD_DIRS`, `_CC_DIRS` | **every** mode |
| `security_policy.json`, `admission_policy.json`, `computer_use.json`, `crons.json`, `autonudge.json` | `_KEYSTONE_FILES` | **every** mode |
| `.npmrc`, `.netrc`, `.git-credentials`, `.env` | `_CC_FILES` | `cc` and `strict` only |

The keystone files live in a list of their own precisely so that last row cannot pull
them along. An earlier revision put them in `_CC_FILES`, and this document argued the
result was an acceptable incomplete floor on the grounds that `standard` "has no
file-level hiding mechanism at all". **That was wrong.** The mechanism is there — the
launcher hides whatever `files` contains on any tier — and the only thing excluding the
default tier was the selection expression choosing an empty list for it
(`files = _CC_FILES if sandbox_level in ("cc", "strict") else []`). Since
`_SANDBOX_MODE_ALIASES` maps the default `auto` onto `standard`, the effect was that
the governance ceiling was readable to an agent subprocess in the shipped
configuration, while this document described that as a considered trade.

It is worth naming the failure mode, because it is the one this whole section warns
about: the gap was **documented**, and a test pinned the documented behaviour, so both
halves of the usual safety net agreed with each other and neither noticed the floor had
a hole in it. Writing a limitation down is not the same as deciding it.

The credential files keep the `cc`/`strict` split, which is the posture this repo
already chose for them; widening that is a separate decision with its own reasoning.

Hiding rather than merely denying is safe because nothing in the subprocess needs to
read any of the keystone files: variable expansion happens in the gateway before the
prompt is built, and the ceiling is deliberately not the agent's to read.

The two platforms enforce this through different mechanisms and had to be fixed in
different places — Linux bind-mounts an empty file over each path, macOS emits Seatbelt
rules — so coverage on one says nothing about the other. On macOS the keystone files are
denied `file-read*`, `file-link` **and `file-write*`**: hiding the ceiling from a
subprocess is worth little if the same subprocess can overwrite it, and forging
`computer_use.json` is how an agent would grant itself the operator's own opt-in. The
credential files keep read-only denial, because npm and git write to `.npmrc` and
`.git-credentials` legitimately.

**One gap remains, and it is a property of the file-hiding mechanism rather than of
this list.** Linux bind-mounts over a path only `if os.path.isfile(target)`, so a
keystone file that does not exist yet is not covered and an approved opaque script can
CREATE it. This applies to every file entry, not only these — `.npmrc` and `.env` have
always behaved this way. The obvious fix, creating a placeholder so the mount has
somewhere to land, is not obviously safe: it leaves an empty file in the operator's data
home, and while an empty `computer_use.json` reads as disabled
(`enable_state.py` treats a failed load as off — the safe direction), an empty
`security_policy.json` would need the same check made for each loader before anyone
could rely on it. Doing that per loader, or inverting the data home to a read-only mount
with the writable subtrees bound back in, is the real fix and belongs in its own change.

This is recorded as an open gap, not as a decision — the distinction the previous
paragraph exists to make.

### The container entry, not just its contents

Every list above hides CONTENTS. None of them stops the container being **moved**, and
content-hiding cannot: after `mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil
~/.kiro/crew`, each leaf rule names a path the attacker has already emptied, and the
next gateway write follows the link. `security.is_unreplaceable_container` refuses that
as a *command*, but a subprocess is one opaque token to the command gate — `./script.sh`
containing those two lines is never inspected — which is the same reason the hide lists
exist at all.

So the sandbox protects the directory ENTRY, by a different mechanism on each platform:

| platform | mechanism | why it works |
|---|---|---|
| Linux | bind the container onto itself | a bind over itself is transparent, but the directory becomes a mount point, and the kernel refuses to rename one (`EBUSY`) |
| macOS | `(deny file-write* (literal …))` | Seatbelt's `file-write*` covers the unlink/create a rename needs |

`literal`, never `subpath`, and a self-bind rather than an empty-dir bind: the agent's
own `sessions/`, `memory/` and `logs/` live inside this directory and must stay readable
and writable. Fencing the subtree would cut the agent off from its own working data —
the same false positive the container gate is exact-match to avoid.

The two halves live in different modules with no shared symbol — `security.py` names
the fenced leaves, `sandbox.py` names what is hidden — so a leaf added to one and not
the other is protected only against the spelling nobody uses.
`TestTheFencedPathsAreHiddenFromSubprocesses` asserts the coupling rather than either
list.

**Do not weaken this when editing the path or bash matchers.** Write and extract
verbs must stay covered: a bash command that merely *names* a write-protected
leaf is refused, verb-independently, because an enumerated write-verb allowlist is
inherently bypassable (quoted redirects, `cp`, a Python `open(..., 'w')`, or any
novel verb).

### Ancestors, and what a self-bind cannot protect

The container's ANCESTORS are protected the same way, not just the container itself:
`mv ~/.kiro /tmp/stash && ln -s /tmp/evil ~/.kiro` carries `~/.kiro/crew` away without
ever naming it. For a nested custom `KIROCREW_HOME` this walks every ancestor, not a
fixed depth — a fixed depth only moves the goalpost, since renaming ANY ancestor and
replacing it with a symlink completes the same relocation attack regardless of nesting
depth. The walk stops at whichever comes first: the filesystem root (protects nothing
in particular) or `Path.home()` (excluded on its own account, matching
`_SENSITIVE_LEAF_PARENT_DIRS`'s existing rule that a single-segment entry whose parent
is home is excluded so as not to taint `cd ~`). This is safe to be broad about because
the mechanism denies RENAMING the literal directory entry only — every file inside
every ancestor, at every level, stays fully readable and writable, and only the
sandboxed agent subprocess is bound by it.

The command gate (`security.py`) carries its own copy of this walk, independent of the
sandbox's. It matters when the sandbox is disabled, or on a platform it does not cover:
the text gate is then the *only* defense, and a fixed-depth version of it would leave
the same class of gap the sandbox side closed.

**Ancestors must be self-bound SHALLOWEST first, not in whatever order the walk
produces them.** `MS_BIND` without `MS_REC` copies only the mount at that point, not
the submounts beneath it — the same reasoning behind self-bind-before-masking earlier
in this section. Binding a deep directory and then binding one of ITS ancestors a
moment later produces a fresh view of the ancestor that does not carry the deeper bind
forward, silently undoing it. The ancestor walk collects entries deepest-first (it
starts at the immediate parent and moves outward) and reverses them before returning,
so the self-bind loop — which consumes this list in order — always establishes an
ancestor's mount before any descendant's.

**A symlinked container defeats the Linux self-bind, and there is no bind-based fix.**
`os.path.isdir()` follows a symlink, so the self-bind loop would happily bind through
one. `mount(2)` resolves the symlink target the same way `open()` does, landing the
bind on the directory the link points to — not on the link's own directory-entry slot,
which stays exactly as replaceable as before: `rm ~/.kiro/crew && ln -s /evil
~/.kiro/crew` swaps the link out from under a mount still faithfully protecting the OLD
target. Protecting the link's own slot would mean write-denying the *parent's*
contents, which is the subtree-fencing this whole mechanism deliberately does not do.
So the Linux launcher detects a symlinked container with `os.path.islink()` *before*
the bind and refuses the spawn, matching every other control in this file: a control
that cannot be established blocks rather than degrades open.

macOS does not share this gap. Verified empirically against real `sandbox-exec`: a
literal `(deny file-write* (literal …))` rule on a symlink's own path blocks `rm` /
`ln -s` replacing it, because Seatbelt's literal-path match denies operations *at that
pathname* rather than following the link the way a bind-mount target does. No fix is
needed there, and none should be added — the two platforms differ here for a real
reason, not an oversight.

**A symlinked custom home is a second, distinct case of the same gap.** `config_dir()`
resolves any symlink in `KIROCREW_HOME` before returning, so the self-bind protection
above landed on the RESOLVED target. But `config_dir()` is consulted once per process,
not once per read of the env var — a restart re-reads the raw `KIROCREW_HOME` and
re-resolves it fresh, so if the *configured* path is itself a symlink, protecting only
the old resolved target never covers a replacement made in the meantime:
`rm <symlinked KIROCREW_HOME> && ln -s /evil <same path>` swaps what the *next*
resolution follows, and nothing named the symlink's own path to protect it. The
unresolved, expanded (but not `.resolve()`-d) override is now added to the same
protected list in its own right — appended *after* the resolved leaf and its
ancestors, matching the shallowest-first ordering invariant, since in the common
non-symlink case this entry equals the resolved leaf exactly and dedup collapses it.
If it turns out to be a symlink, the same `os.path.islink()` check above catches it
and refuses the spawn.

**The ancestor walk also stops at the system temp root, and getting that stop
condition wrong is its own regression class.** This project's own test suite pins
`KIROCREW_HOME` under the system temp directory for isolation (see
[testing-conventions](../system-specs/common/testing-conventions.md)), so an
ancestor walk with no temp exclusion reaches the bare temp root itself and starts
treating it as a protected container — refusing every ordinary command that merely
*names* it, `cd /tmp && cat notes.txt` included. This was invisible in a bare local
run (nothing sets `KIROCREW_HOME` there) and visible only in CI, where the pinned
home is nested under `/tmp`.

The fix is not "stop at the first ancestor that happens to be *under* the temp
root" — that overshoots. `_is_system_tmp_root()` (`config/paths.py`) has to answer
true only exactly *at* the boundary — under-or-equal a temp root (`tempfile.
gettempdir()` or, on POSIX, literal `/tmp`, both resolved) while its *parent* is
not — because an intermediate ancestor between the leaf and the temp root is a
uniquely-identifying directory the walk must still protect, not shared territory
like the root itself. Stopping at the first under-match instead un-protects every
intermediate ancestor, silently reopening the exact gap this walk exists to close.

`tempfile.gettempdir()` itself can raise (`OSError`, when it exhausts its candidate
list without finding a writable directory) — rare, but `_under_system_tmp` is now
reached from the per-command ancestor walk, not only its original gateway-start
callers, so an uncaught raise there would crash whatever is deciding whether to
allow a command rather than return a decision. The call is wrapped and falls back
to skipping that root (still trying the POSIX `/tmp` literal, or an empty root list
on Windows) — discovery failure fails toward "not a recognized temp root", the same
direction `_under_system_tmp`'s existing per-candidate `.resolve()` failures already
fail.

**The stop is asymmetric between the two copies of the walk, on review feedback.**
`security.py`'s text gate is verb-independent matching, so reaching the temp root
there refuses every command merely *naming* it — it has to stop early, as above.
`sandbox.py`'s `_unrenamable_containers` self-bind costs nothing comparable: it
denies *renaming* one literal directory entry, nothing else, so there is no
usability reason to give a user- or environment-selected `$TMPDIR` a pass there.
Leaving it out was an unforced gap — a `KIROCREW_HOME` nested under a writable
custom temp root had that boundary's own directory entry left unprotected, the same
exposure as any other unwalked ancestor — so only `security.py` calls
`_is_system_tmp_root`; the sandbox walk stops at `Path.home()` and the filesystem
root only, same as before the temp-root case existed.

**The raw regex was not the only matcher checking against a custom home's
ancestors, and the other two were never told about them.** `security.py` carries
three independent operand checks beyond the raw regex — a substitution scanner
(`_substitution_could_name_container`, for `~/.k$(printf i)ro/crew`-shaped
obfuscation), a glob scanner (`_raw_glob_could_name_container`, for
`~/@(.kiro)/crew`), and the cd-relative segment walk's exact-match check
(`is_unreplaceable_container`) — and each built its own target set from
`_UNREPLACEABLE_CONTAINER_DIRS` alone. The ancestor walk was added only to the raw
regex's own branches, so `mv ~/comp$(echo any)/dept /tmp/x` and, with extglob
enabled, `mv ~/comp@(any)/dept /tmp/x` both named a real ancestor exactly as their
literal form does, yet reached none of the other three checks — a real, reproduced
bypass. `_container_targets()` now builds the shared target set once (the anchored
`_UNREPLACEABLE_CONTAINER_DIRS` entries plus every ancestor from
`_custom_home_ancestors()`, the same walk `_build_container_regex` itself now
calls) and all four consumers read from it, so an ancestor added to the walk cannot
silently go missing from three of its four checkers again.

Closing the glob-scanner gap surfaced an adjacent, narrower bug in extglob
widening. `_glob_could_name` widens an extglob group (`@(.kiro)`, `!(x)`) to `.*`
so the result can still name a dotfile target — deliberate, since bash's
`*`-without-`dotglob` rule would otherwise make the widened form miss the very
`.kiro`-shaped targets an extglob group is most useful for hiding. But `.*` is a
GLOB pattern, where `.` is a literal character, not "any character" — so it widens
correctly only when the group sits at the very start of a component
(`@(.kiro)` → `.kiro`-shaped, a literal dot the dotfile-prefixed target also has).
Embedded mid-component (`comp@(any)` → `comp.*`), the literal dot has to appear
literally in the target too, and an ordinary, non-dot-prefixed ancestor name like
`company` has none — so the widened pattern never matched it, even though the
extglob group is meant to name "anything here". `_UNREPLACEABLE_CONTAINER_DIRS`
entries are all dot-prefixed (`.kiro`, `.kiro/crew`, `.kirocrew`), so this never
surfaced before a custom home's plain-named ancestors joined the target set.
Fixed by building a second, plainly-widened reading (`*` in place of the group)
alongside the dot-preserving one and checking both — the two overlap on plenty of
tokens, which only widens the match, never narrows either reading.

### The raw scan approximates a shell grammar, and keeps needing to approximate more of it

The container-naming raw scan (`_names_unreplaceable_container_raw`) compares command
TEXT, because it is the only pass that sees inside an un-tokenizable interpreter
payload (`python3 -c "..."`). Text comparison means it inherits every way a shell can
make two spellings equivalent without looking equivalent as strings, and each one
found so far has been closed as its own narrow, justified addition rather than
declared out of scope by default — separator runs the filesystem collapses to one
(`~//.kiro/crew` and `~/.kiro//crew` are the same path everywhere the pattern needs to
recognize a container, not only after the home prefix), quoting forms that vanish at
resolution time (`$'…'`, `$"…"`, ANSI-C escapes), expansions that produce nothing
(unset variables, empty command substitution, positional and special parameters like
`$1`/`$*`), and glob or extglob syntax that resolves to the container without ever
spelling it (`dotglob`, `globstar`, `GLOBIGNORE`, a *nested* `@(...)` group, which one
substitution pass cannot fully resolve and now runs to a fixed point), and a
*deeply nested* command or variable substitution (`$(echo $(echo $(printf i)))`),
which the masking pattern's one extra level of balanced parens — the most a
fixed-width regex can express for nesting at all — cannot fully consume in a single
pass either, and which now runs to the same kind of fixed point for the same reason.

**Detecting a glob mode is not the same as USING it.** `_glob_modes` reads `dotglob` /
`globstar` / `extglob` from the raw command text, but the operand check that applies
those modes runs on the normalizer pass's candidates — and a quoted `-c '...'` payload
is one opaque token to that pass, same as any other embedded interpreter script. A
mode detected with perfect accuracy still protected nothing if the glob-shaped operand
it applies to was never extracted. The raw scan carries its own glob-word check for
exactly this reason: no masking is needed first (an extglob or bracket pattern
contains no whitespace of its own, so it isolates as its own word on a plain split),
but the modes have to be read from THIS SAME raw text — a mode detected from the outer
command and not threaded through would silently narrow the check back to unmodified
glob semantics. Mode detection itself is quote-normalized first, for the same reason
the container match is: `ext""glob` is `extglob` once bash tokenizes it, and a regex
comparing the raw text alone read the option as absent.

One class is handled differently on principle: a substitution embedded between two
adjacent quoted string literals joined by `+` — a common concatenation idiom shared by
several interpreters Kiro Crew spawns payloads through — is reconstructed explicitly,
because the alternative is genuinely unbounded (parsing an arbitrary interpreter's full
expression grammar has no natural stopping point). This is the deliberate line: a
finite, well-known idiom gets a targeted fix; an interpreter's general grammar does
not, and the gap is why the sandbox mount protection above is the floor rather than
this scan.

### Audited internal carve-out

`safe_read_file_internal(read_id)` permits a small hardcoded allowlist of
system-internal reads of otherwise-sensitive paths. It re-verifies
`is_sensitive_path()` (a path that has stopped being sensitive means the
configuration drifted, so it refuses rather than silently widening), opens with
`O_NOFOLLOW` on a single descriptor, SEL-audits every outcome, and fails closed:
a `success` whose audit cannot be persisted returns `None`, because a log warning
is not an audit event and the carve-out's validity depends on every successful
read producing one. `read_id` is never constructed from untrusted input.

## Layer 2: Command gate (`security.py` + `hooks.py`)

Three independent checks run on every shell-bearing tool call, each against the
model's title **and** the raw command:

- **Denied-command rules** (`BUILTIN_DENIED_RULES`): first-class
  `DeniedCommandRule` records (stable `id`, regex `pattern`, `category`,
  human `description`) covering credential exfiltration, destructive
  infrastructure and data operations, publishing to a protected branch, and
  self-protection (the agent disabling Kiro Crew or minting its own dashboard
  token). Default-ON, user-configurable from Settings → Security; the governance
  `commands` scope is the enterprise force-pin that cannot be opted out of
  (tightest-wins).
- **Sensitive-bash detection** (`is_sensitive_bash_command`): refuses commands
  that read credential paths, reach the cloud metadata endpoint under any IP
  encoding, or dump credential environment variables. Regex fast-path first, then
  a tokenizing pass that resolves quoting, empty-string concatenation, `$HOME`
  and tilde before routing path-like tokens through `is_sensitive_path()`.
- **Exfiltration shapes** (`audit_bash_exfiltration`): data-egress and
  reverse-shell forms, narrowly scoped so it can be a hard deny at the gate
  without blocking benign local commands.

`SUSPICIOUS_BASH_PATTERNS` / `audit_bash_command()` are a **separate, advisory**
surface: they back the `kirocrew security audit` history scan and the posture
count, and are not enforced at the gate. The gate enforces the narrower checks
above. Conflating the two is the historical error here, so keep the distinction
explicit.

Rule-table contents, the two-pass whole-string/per-segment evaluation, the
verb-anchored git-publish detector, the protected-branch and force-push
semantics, the argv-structural self-protection floor, and the linear-time
ReDoS-safe matcher are all specified in
[`security.md` § Denied Commands](../system-specs/modules/security.md).

Every denial emits a `deny_event` SEL record; an exception grant emits
`deny_exception` fail-closed (if the audit cannot be written, the exception is not
granted).

## Layer 3: Input validation (`validation.py`)

Every MCP tool call is checked against a declarative `FieldSpec` + `ToolSchema`
before the handler sees it: NFC unicode normalization with hidden-character
stripping (control, format, private-use and surrogate code points, preserving
`\n`/`\r`/`\t`), enum allow-lists, regex patterns for identifiers, range checks,
unknown-field rejection, tiered length caps (`MAX_TOOL_NAME_LEN` 256,
`MAX_SHORT_STRING` 500, `MAX_MEDIUM_STRING` 5 000, `MAX_LONG_STRING` 50 000, and
the field-specific `MAX_CRON_MESSAGE` 50 000 for the cron `message` — a task
prompt, enforced on the MCP schemas, both REST cron endpoints, and the
`CronService` persistence chokepoint), and
response truncation at `MAX_RESPONSE_LEN` (100 000 chars) so unbounded tool output
cannot be a DoS vector.

The schema count is a runtime-derived posture value (`tool_schemas` in
`security_posture.py`), surfaced in Settings; it is not stated here.

## Layer 4: Output redaction

Redaction runs at **every** boundary where agent-derived output reaches a human or
an external service. The authoritative list is the `redaction_paths` control in
`security_posture.py`, whose registry is kept honest by an omission-detecting
test: every redactor call site in the package must be either a registered sink or
on an explicit non-egress allowlist, so a new egress path cannot be added without
someone deciding which bucket it belongs in.

- `redact_credentials()` recognizes credential families in plaintext and
  base64-encoded form (it decodes base64-looking chunks and re-checks the decoded
  bytes), including cloud access keys and secrets, private-key headers, chat and
  forge tokens, package-registry tokens, and database connection URIs carrying
  embedded credentials. Key-value matching is JSON-aware and value classes are
  bounded at JSON structural delimiters, so a match in compact JSON cannot
  over-capture and mask the next credential.
- `redact_exfiltration_urls()` / `scan_exfiltration_urls()` are
  **domain-agnostic**: they flag the payload, not the destination. A credential in
  a URL is an unconditional floor; long query strings, base64 blobs and heavy
  URL-encoding are heuristics. A flagged URL is replaced with a redaction marker.
- `redact()` composes both in order for a single call site.
- `StreamRedactor` handles the case per-chunk redaction structurally cannot: a
  credential split across a streaming boundary, where neither fragment matches on
  its own. It withholds the trailing run of credential-class characters until a
  non-credential terminator arrives or the stream ends, emitting only the
  confirmed-safe prefix, with a bounded hold-back so latency and memory stay
  bounded on a pathologically long unbroken run.

Two ordering rules generalize beyond this layer and are worth stating once:
**screen after decode, not before** (screening an encoded form and then writing
the decoded value makes every escape a bypass), and **redact before truncate**
(truncating first can slice a credential so neither fragment matches).

## Layer 5: Audit (SEL)

The Security Event Log is append-only and HMAC-chained, so tampering is
detectable rather than merely discouraged; `GET /api/sel/verify` reports the
chain's integrity and `GET /api/sel/events` returns recent records. Every event
carries a `source` inferred from the session key (`sel._infer_source`, published
via `sel.audit_sources()`), and a call site may stamp a more specific source, so
the inferred set is a floor rather than a total.

The audit log is itself a user-facing, *durable* surface: string fields are
redacted before they are written or forwarded. A leak into the SEL persists in a
way a response body does not. See
[`../system-specs/modules/sel.md`](../system-specs/modules/sel.md).

Several security decisions are audit-or-deny rather than best-effort: a sandbox
delegation, a deny exception, and an internal sensitive read all refuse to
proceed when their audit cannot be written. The one documented exception is the
nested-sandbox passthrough, which has no safe alternative (the kernel denies a
re-wrap by design) and would otherwise couple every in-sandbox spawn to SEL
health; it logs loudly and proceeds, still confined by the outer boundary.

## Governance: the enterprise ceiling

Governance is a second, orthogonal axis to the layers above:
`effective = POLICY ∩ PROFILE`, tightest-wins. Level 1 POLICY is loaded at boot
from the trust-root path and is never merged from `config.json`; Level 2 PROFILE
is a per-surface, narrow-only ceiling. Both are enforced at Kiro Crew's own
PreToolUse gate, which is what lets a policy deny a tool or MCP call **even when
the `kiro-cli` agent config granted it**.

Architecturally the important properties are that the evaluator is
scope-name-agnostic (adding a scope is a `SCOPE_CATALOG` data change, never an
evaluator edit), that governance runs before the auto-approve path so it cannot be
bypassed by a trust decision, and that its trust-root files are on the keystone
floor so the agent cannot read or rewrite its own ceiling. Archetypes,
composition algebra, scope boundaries and the signed-policy authenticity model
are in [`../system-specs/modules/governance.md`](../system-specs/modules/governance.md).

**Computer use is deliberately not governed.** It is one operator opt-in on a
keystone file, with refusals enforced in band on the tool dispatch path rather
than at the fail-open PreToolUse gate. See
[`../system-specs/modules/computer-use.md`](../system-specs/modules/computer-use.md).

## Authentication and authorization

### Dashboard requests

HMAC-signed tokens with dual expiry: a short link-click window
(`LINK_WINDOW_SECS`, 5 minutes) and a longer cookie session TTL capped at
`MAX_SESSION_TTL_SECS` (20 hours), IP-pinned on first use. Every request requires
a valid token, with a small set of deliberate, secret-free exceptions: static
assets and same-origin vendored JS (the SPA and sandboxed-iframe bootstrap), the
local-bootstrap endpoints that authenticate with a loopback peer plus a
filesystem secret, the three liveness probes, and self-authenticating external
webhooks that validate their own signatures.

Supporting controls: per-session logout via a cookie nonce recorded in a revoked
set (so one session is revoked without affecting others); app tokens confined to
their manifest-declared API allowlist, deny-by-default even on internal paths; a
path-restricted refresh cookie so the app self-recovers after access-cookie
expiry; and the `Secure` cookie attribute when the gateway is behind TLS.

### CSRF and DNS rebinding are two different barriers

Origin/Referer validation covers state-changing methods. The `Host`-header
allowlist runs on **every** method, because GET-based exfiltration is the
DNS-rebinding payload, and it deliberately does **not** trust a loopback
`request.remote`: a rebound request *is* loopback at the socket while its `Host`
carries the attacker's domain. Both derive their allowlists from one source
(`check_origin` / `check_host` over `allowed_origins`, plus a canonical-loopback
floor from `build_allowed_hosts`) so the two layers cannot drift. Host validation
is deny-by-default (an empty `allowed_origins` denies, never fails open) and
rejects with 403 plus a SEL event. The sole exemption is the three liveness
probes, whose handlers compensate by stripping build-identity fields unless the
caller is direct-local, so a rebound request learns only the liveness bit.

### Slack

Deny-by-default owner lock: socket mode refuses to connect without an owner id,
and event handling rejects messages when it is missing. Trust and YOLO buttons
are DM-gated and suppressed in group channels, with a non-owner receiving an
ephemeral rejection.

Slack messages are processed **inline** and reach the agent directly, gated by
`is_allowed_user` and the workspace origin check. There is no challenge-and-
redirect interception; `send_channel_challenge()` does not exist and must not be
reintroduced on an upstream sync. The generic signed-token helpers remain and
back the explicit `/kirocrew dashboard` link command.

Enterprise Grid validation is a two-layer, **default-open** control: with no
`slack.allowed_enterprise_ids` configured, every reachable workspace is allowed.
`auth.test` caches the workspace `team_id` (plus the org-level enterprise id on
Grid) at startup, and each inbound event's `team` is compared against the cached
allowlist. A governance `channels.posture` policy is the agent-unweakenable
ceiling on top of the operator-editable config allowlist. A corrupt `config.json`
does not reopen the control: because `KiroCrewConfig.load()` degrades a torn
config to defaults rather than raising, the module positively detects that case (a
config file that exists but does not parse) and fails CLOSED, keeping the allowlist
enforced and admitting NO origin -- not even the just-validated workspace,
since which authenticated workspace is allowed is exactly what the unreadable
allowlist would have decided -- rather than reverting to default-open.

### Interactive trust escalation

Dashboard tool approvals offer four decisions, in widening scope: `trust_command`
(this exact command, session-scoped), `trust_base` (the base command glob, e.g.
`ls *`, plus the bare binary, session-scoped), `trust_reads` (read-only bash for
the slot), and `trust` (all tools for the slot). `yolo` is the global escalation.

The security-relevant property is what the pattern is derived from: the **actual
command in `tool_input`**, not the model-authored display title. Trust patterns
are per-slot fnmatch globs; a multi-command title yields one pattern per binary.
Trust never outranks a deny: the gate's deny and governance checks run before the
trust and auto-approve paths.

### Auto-approve (YOLO) has one duration

Auto-approve is time-bounded by a **single** duration shared by every ad-hoc
surface (`agent.yolo_duration`, default `6h`, hard ceiling 24 h, or
`until_shutdown` for an in-memory grant with no timed expiry that a restart
clears). There are deliberately no per-surface TTLs: giving the same grant a
different lifetime depending on which surface enabled it is unpredictable for the
operator without buying any security.

The duration is resolved from live config at activation time, so a value saved in
Settings applies to the next activation without a restart. A 5-minute grace
window after expiry allows renewal instead of a fresh activation.

The one non-expiring grant is `agent.dangerously_skip_permissions` in
operator-owned config: a standing instruction, deliberately config-file-only with
no dashboard toggle, re-established and re-audited on every startup. An
enterprise policy can deny it via the `yolo_duration` scope's `permanent` member,
which downgrades it to the ordinary ad-hoc duration.

Every lifecycle transition (`activate`, `renew`, `expired`, `deactivate`) is
SEL-audited. The transitions that create or extend auto-approval authority
(`activate`, `activate_scoped`, `renew`) audit **fail-closed**: the SEL event is
written before the grant is committed, and if the write fails the grant (or the
extension) is refused — auto-approval authority never exists without an audit
record. Fleet-visibility endpoints expose the live state
(`/api/status` reports `yolo_active` / `yolo_expires_at`;
`/api/admin/compliance/yolo-status` carries the full override status).

## Context isolation

Observe-mode channel history is gated on sender authorization: only owner or
allowlisted messages are recorded, so a non-owner cannot influence LLM context by
posting into shared channel traffic. Slack thread-root content, which any thread
participant can author, is injection-screened and dropped on match, and surviving
text is framed as explicitly untrusted data with a SEL event on every drop.

## Frontend

| Control | Implementation |
|---|---|
| XSS prevention | DOMPurify on all rendered HTML content |
| Safe DOM APIs | `createElement` + `textContent` for error fallbacks |
| Mermaid | `securityLevel: 'strict'` (iframe sandbox), so an injected diagram cannot execute JS |
| No `innerHTML` | React text children rather than HTML string construction |
| No regex linkification | React elements via `.split()` |

## Credential file handling

`load_credentials()` tightens `~/.kiro/crew/.env` to owner-only mode at load time
and warns if it cannot (for example when the file is owned by another user). The
file is also on the keystone read+write block, so the agent cannot reach it
through any tool or shell form regardless of its filesystem mode: owner-only
permissions do not isolate another process running as the same uid, which is
exactly the agent's situation.

---

## Known gaps

Each gap below is a real residual, stated with why the obvious fix is not already
in place.

**No network egress control by default.** The sandbox hides credential files but
does not restrict outbound network access, so a compromised agent can post
non-credential data to an arbitrary host. Redaction blunts the credential case
and the `network.egress` governance scope can bound hosts where a policy is
configured, but there is no default-on egress boundary. A network namespace
(Linux) or host firewall rules with a trusted-destination allowlist would close
it.

**Regex and tokenizer command matching is not a shell parser.** The command gate
normalizes aggressively (quoting, empty-string concatenation, `$HOME`/tilde,
mid-word empty substitutions, local assignment inlining, literal interpreter
payloads) and adds argv-structural floors for the self-protection rules, which
closes the well-known evasion families. It is still not a bash AST: a payload
assembled at runtime (string concatenation, a base64 blob, an indirect `eval
"$CMD"`) contains nothing for a pattern to find. The un-disableable guarantee for
the signing credential is the keystone path floor, which these rules do not
replace.

**No audit dashboard.** SEL events are queryable over the API
(`/api/sel/events`, `/api/sel/verify`) but there is no UI to browse, filter or
alert on them, so tamper detection and anomaly spotting are manual.

**No in-agent sandbox-escape detection.** The gateway decides fail-closed whether
a backend exists before spawning, but nothing verifies from *inside* the agent
process that confinement actually took effect (for example by attempting to read
a canary that should be hidden). A confinement that loads but does not enforce
would not be noticed.

**Base64 credential detection has a floor.** Only base64 chunks at or above the
minimum length are decoded and re-checked, so a shorter encoded fragment, or one
split across messages, can pass. Cross-message correlation and entropy-based
detection would extend it.

**Write protection covers Kiro Crew's own trust root, not the user's shell
startup files.** Credential directories and the keystone are read+write blocked,
and `config.json` plus the migration marker are write-blocked, but ordinary
persistence targets such as `~/.bashrc` or `~/.zshrc` are not: they are not
credential stores, and blocking the whole home directory would make the agent
useless for its normal work. An agent write there is therefore a real persistence
vector, mitigated only by the approval gate and the destructive-command rules.

**Resource ceilings depend on the platform.** The cgroup v2 scope that bounds
fork bombs and memory balloons requires Linux with cgroup delegation; where it is
unavailable (macOS, older Linux, no user session) it is a no-op with a loud
warning and only the file-descriptor limit applies. See
[`resource-protection.md`](resource-protection.md).
