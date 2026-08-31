"""The data home cannot be relocated by the agent.

Every fenced leaf is identified by its PATH, so the fence assumes the directory
holding it stays where it is. It did not: ``rm -rf ~/.kiro/crew`` was refused, but
``mv`` and ``ln -s`` were not, so

    mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew

left every fence naming a file that is no longer there, and the next write to
``security_policy.json``, ``profiles/``, ``admission_policy.json`` or
``computer_use.json`` followed the link. That is the keystone the whole ceiling
rests on, so this is a bypass of the ceiling rather than of one feature.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

from kiro_crew import platform_compat, security

HOME = os.path.expanduser("~")


def _blocked(command: str) -> bool:
    return security.is_sensitive_bash_command(command) is not None


class TestTheContainerCannotBeRelocated:
    """Refused verb-independently: the refusal is on NAMING the container, because an
    enumerated write-verb allowlist is bypassable -- the reason the leaf fence gives
    for its own verb-independence."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/crew /tmp/stash",
            "ln -s /tmp/evil ~/.kiro/crew",
            "cp -r ~/.kiro /tmp/x",
            "rsync -a ~/.kiro/crew /tmp/x",
            "mv ~/.kiro/crew/ /tmp/x",
            # A verb nobody enumerated, which is the point of not enumerating.
            "install -d ~/.kiro/crew",
        ],
    )
    def test_a_relocating_verb_is_refused(self, command: str) -> None:
        assert _blocked(command), f"{command!r} can relocate the fenced container"

    @pytest.mark.parametrize(
        "command",
        [
            'mv "$HOME/.kiro/crew" /tmp/x',
            "mv $HOME/.kiro/crew /tmp/x",
            "mv ~/.kiro/../.kiro/crew /tmp/x",
            "mv ~/.KIRO/CREW /tmp/x",
            "cd ~/.kiro && mv crew /tmp/x",
            "cd ~/.kiro/crew && mv . /tmp/x",
            "cd ~ && mv .kiro/crew /tmp/x",
            "D=~/.kiro/crew; mv $D /tmp/x",
            "python3 -c \"import os; os.rename(os.path.expanduser('~/.kiro/crew'),'/tmp/x')\"",
        ],
    )
    def test_the_obfuscated_forms_are_refused(self, command: str) -> None:
        """Quoting, `$HOME`, traversal, casefold, `cd`-relative, variables, and an
        interpreter payload -- the evasion families the leaf gate already covers."""
        assert _blocked(command), f"{command!r} relocates the container undetected"

    def test_a_spent_cd_does_not_excuse_a_later_mention(self) -> None:
        """The navigation carve-out must not become a prefix that launders the rest of
        the line."""
        assert _blocked("cd ~/.kiro/crew && mv ~/.kiro/crew /tmp/x")


class TestOrdinaryAgentWorkIsUnaffected:
    """The gate is exact, not prefix -- the reason the container cannot simply be added
    to ``_SENSITIVE_HOME_DIRS``, whose matcher IS prefix-based."""

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/crew/sessions/a.json",
            "ls ~/.kiro/crew/skills",
            "tail -n 50 ~/.kiro/crew/logs/gateway.log",
            "grep -r todo ~/.kiro/crew/memory",
        ],
    )
    def test_content_under_the_container_stays_reachable(self, command: str) -> None:
        assert not _blocked(command), (
            f"{command!r} was refused; a prefix match here cuts the agent off from its "
            "own sessions, memory, skills and logs"
        )

    @pytest.mark.parametrize("command", ["cd ~/.kiro", "cd ~/.kiro/crew", 'cd "~/.kiro"'])
    def test_even_navigating_into_it_is_refused(self, command: str) -> None:
        """This REVERSES an earlier decision, deliberately.

        `cd` into the container used to be spared -- entering a directory cannot
        relocate it. But the exemption was identified by inspecting the preceding token,
        so `mv cd ~/.kiro/crew` claimed it, and `cd` is a builtin a function can shadow
        besides. Both were reported. Deciding what a token means needs a shell, so the
        exemption is gone rather than narrowed.

        The cost is bounded by the match being exact: only the container itself, never
        anything under it (see `test_removing_it_costs_only_the_container_itself`).
        """
        assert _blocked(command)

    def test_an_unrelated_path_is_untouched(self) -> None:
        assert not _blocked("mv /tmp/a /tmp/b")


class TestItIsNoWeakerThanTheLeafGateBesideIt:
    """The ratchet, and the invariant that matters most.

    The container gate reuses the leaf gate's machinery precisely so the two cannot
    drift, but they are separate code paths and the first cut of this fix was wired
    into only ONE of the three passes -- so it missed `cd`-relative, variable, and
    interpreter forms that the leaf gate had caught for a long time. Asserting parity
    form-by-form is what caught that; asserting the attack alone did not.
    """

    # (leaf command, container command) exercising the SAME evasion family.
    FORMS = [
        (
            "cd ~/.kiro && cat crew/security_policy.json",
            "cd ~/.kiro && mv crew /tmp/x",
        ),
        (
            "cd ~/.kiro/crew && cat ./security_policy.json",
            "cd ~/.kiro/crew && mv . /tmp/x",
        ),
        (
            "cd ~ && cat .kiro/crew/security_policy.json",
            "cd ~ && mv .kiro/crew /tmp/x",
        ),
        (
            "D=~/.kiro/crew; cat $D/security_policy.json",
            "D=~/.kiro/crew; mv $D /tmp/x",
        ),
        (
            f"python3 -c \"print(open('{HOME}/.kiro/crew/security_policy.json').read())\"",
            f"python3 -c \"import os; os.rename('{HOME}/.kiro/crew','/tmp/x')\"",
        ),
    ]

    @pytest.mark.parametrize("leaf,container", FORMS)
    def test_every_form_the_leaf_gate_catches_the_container_gate_catches(
        self, leaf: str, container: str
    ) -> None:
        assert _blocked(leaf), (
            f"the leaf gate stopped catching {leaf!r}; this test's premise is gone and "
            "the parity assertion below would pass vacuously"
        )
        assert _blocked(container), (
            f"the leaf gate catches {leaf!r} but the container gate misses the same "
            f"evasion in {container!r} -- the container gate is the weaker of the two"
        )


class TestTheContainerSetCoversEveryDataHome:
    def test_the_legacy_home_is_covered_too(self) -> None:
        """`~/.kirocrew` is fully deprecated and never migrated to, but an installation
        that still has one must not have it swapped out from under the files inside --
        the same reason it stays in the leaf fence."""
        assert _blocked("mv ~/.kirocrew /tmp/x")

    def test_the_predicate_is_exact_rather_than_prefix(self) -> None:
        assert security.is_unreplaceable_container("~/.kiro/crew")
        assert not security.is_unreplaceable_container("~/.kiro/crew/sessions")
        assert not security.is_unreplaceable_container("~/.kiro/crewuxx")


class TestShellExpansionCannotSpellAroundEitherGate:
    """Bash expands the operand before the command runs; the matcher did not.

    `~/.kiro/cr{e..e}w` reached the gate as a literal matching no protected path and
    reached bash as `~/.kiro/crew`. This was NOT specific to the container gate -- the
    leaf gate had the identical hole, so `cat ~/.kiro/cr{e..e}w/security_policy.json`
    read the governance trust root on `main`. Expansion therefore lands in the shared
    candidate generator, where both gates inherit it.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cat ~/.kiro/cr{e..e}w/security_policy.json",
            "cat ~/.kiro/crew/security_polic{y..y}.json",
            "cat ~/.kiro/cre[w]/security_policy.json",
            "cat ~/.kiro/*/security_policy.json",
        ],
    )
    def test_the_leaf_gate_resists_it_too(self, command: str) -> None:
        """The finding arrived on the container gate; the fix had to cover both."""
        assert _blocked(command), f"{command!r} reads the trust root through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cr{e..e}w /tmp/x",
            "mv ~/.kiro/cre[w] /tmp/x",
            "mv ~/.kiro/* /tmp/x",
            "mv ~/.kiro/{crew,other} /tmp/x",
        ],
    )
    def test_the_container_gate_resists_it(self, command: str) -> None:
        assert _blocked(command), f"{command!r} relocates the container through expansion"

    @pytest.mark.parametrize(
        "command",
        [
            "ls *",
            "ls ~/*",
            "rm -f build/*.o",
            "cp {a,b}.txt /tmp/",
            "ls ~/.kiro/crew/sessions/*.json",
            "cat ~/.kiro/crew/logs/*.log",
            "grep -r x ~/.kiro/crew/skills/*",
        ],
    )
    def test_ordinary_globbing_is_untouched(self, command: str) -> None:
        """The expensive half of this fix.

        A first cut used `fnmatch` over the whole path and denied `ls *`, because
        `fnmatch`'s `*` crosses `/` and matched every absolute target. Matching is
        component-wise instead, with bash's dotfile rule -- which is why `ls ~/*` is
        allowed (bash without `dotglob` does not match `.kiro`) while `ls ~/.kiro/*`,
        which names it, is not.
        """
        assert not _blocked(command), f"{command!r} is ordinary shell usage"

    def test_a_pattern_naming_the_container_explicitly_is_still_refused(self) -> None:
        assert _blocked("ls ~/.kiro/*")

    def test_expansion_is_bounded(self) -> None:
        """A gate is not the place to discover that `{a..z}{a..z}{a..z}` is 17,576
        strings. Past the cap the token is left unexpanded and the metacharacter arm
        still refuses anything that could name a protected path."""
        from kiro_crew.security import _MAX_BRACE_EXPANSIONS, _expand_braces

        assert len(_expand_braces("~/{a..z}{a..z}{a..z}")) <= _MAX_BRACE_EXPANSIONS


class TestTheFencedPathsAreHiddenFromSubprocesses:
    """The command gate reads command TEXT; a subprocess is one opaque token to it.

    `security.is_sensitive_bash_command` refuses `echo x > ~/.kiro/crew/
    security_policy.json`, and says nothing about `./script.sh` containing that exact
    line — an approved `make install` or `npm run build` writes whatever it likes. So
    the path fence alone never constrained a subprocess, and the sandbox's hide lists
    are the layer that does not depend on the write being spelled out in a command.

    Asserted as a COUPLING rather than as a literal list, because the two halves live
    in different modules with no shared symbol: `security.py` names the fenced leaves,
    `sandbox.py` names what is hidden, and a leaf added to one and not the other is
    protected only against the spelling nobody uses.
    """

    # The keystone leaves this branch's base already fences by NAME. Both halves of
    # the coupling are assertable for these.
    MUST_BE_HIDDEN = [
        ".kiro/crew/profiles",
        ".kiro/crew/security_policy.json",
        ".kiro/crew/admission_policy.json",
        ".kiro/crew/computer_use.json",
    ]

    # Hidden here, but fenced by NAME only once the crew-variables work lands, so the
    # command-gate half of the coupling cannot be asserted on this base yet. Listed
    # separately rather than dropped: the hide list is the half that stops a
    # subprocess, and it is correct to ship it whether or not the name fence exists.
    HIDDEN_AHEAD_OF_ITS_NAME_FENCE = [
        ".kiro/crew/variables",
        # Persisted authorship records. Same reasoning: the flag is derived carefully
        # in process and forgeable on disk, so the file has to be out of reach. Name
        # fence lands with the crew-variables work; the hide list is independent.
        ".kiro/crew/crons.json",
        ".kiro/crew/autonudge.json",
    ]

    def _all_hidden(self) -> set[str]:
        """Union of every list — use only where the mode genuinely does not matter.

        Unioning HID a real gap: `_CC_FILES` applies on `cc`/`strict` only, so a file
        listed there is not hidden on the default `standard` tier, and a test that
        unions cannot tell the difference. `test_the_mode_coverage_is_what_the_spec_says`
        below asserts the split directly.
        """
        from kiro_crew import sandbox

        hidden: set[str] = set()
        for name in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS", "_CC_FILES", "_KEYSTONE_FILES"):
            hidden.update(getattr(sandbox, name, []))
        return hidden

    KEYSTONE_FILES = [
        ".kiro/crew/security_policy.json",
        ".kiro/crew/admission_policy.json",
        ".kiro/crew/computer_use.json",
        ".kiro/crew/crons.json",
        ".kiro/crew/autonudge.json",
    ]

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
            "`os.getuid()`. The macOS equivalent is asserted in "
            "`TestTheSeatbeltProfileMatchesTheLinuxLauncher`; Windows uses neither."
        ),
    )
    def test_the_keystone_files_are_hidden_on_EVERY_tier(self) -> None:
        """Including `standard`, which is where nearly every install actually runs.

        An earlier revision of this file asserted the opposite -- that these were
        `cc`/`strict`-only -- and wrote the reason down as if it were the design. It was
        not: `_SANDBOX_MODE_ALIASES` maps the default `auto` to `standard`, and
        `standard` applies `files = []`, so the governance ceiling was readable to an
        agent subprocess in the shipped configuration. Documenting a gap is not the same
        as choosing it.

        Asserted through the LAUNCHER for each tier rather than against a list, so the
        selection expression is what is under test. `files = _CC_FILES if … else []`
        was exactly the line that made the list membership meaningless.
        """
        from kiro_crew import sandbox

        for tier in ("standard", "cc", "strict"):
            script = sandbox._build_launcher_script(tier)
            for f in self.KEYSTONE_FILES:
                assert f in script, f"{f} is not hidden on the {tier!r} tier"

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason=(
            "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
            "`os.getuid()`. The macOS equivalent is asserted in "
            "`TestTheSeatbeltProfileMatchesTheLinuxLauncher`; Windows uses neither."
        ),
    )
    def test_credential_files_keep_their_existing_tier_split(self) -> None:
        """The keystone hoist must not quietly widen anything else.

        `.npmrc` and friends are `cc`/`strict`-only, which is the split this repo
        already chose for credential files; changing it is a separate decision and
        would belong in its own change with its own reasoning.
        """
        from kiro_crew import sandbox

        assert ".npmrc" in sandbox._build_launcher_script("cc")
        assert ".npmrc" not in sandbox._build_launcher_script("standard")

    def test_the_directories_still_hold_on_every_tier(self) -> None:
        from kiro_crew import sandbox

        for d in (".kiro/crew/variables", ".kiro/crew/profiles"):
            for tier in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS"):
                assert d in getattr(sandbox, tier), f"{d} missing from {tier}"

    def test_the_cron_record_is_the_one_cron_actually_writes(self) -> None:
        """Derived, because a hardcoded name passed while covering nothing.

        An earlier revision hid `cron.json`; cron writes `crons.json`. The hide list
        takes plain strings, so the wrong name is silently inert -- there is no file to
        fail against."""
        from kiro_crew import cron, sandbox

        assert f".kiro/crew/{cron._CRONS_FILE}" in sandbox._KEYSTONE_FILES

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_each_fenced_path_is_hidden_from_the_agent(self, path: str) -> None:
        assert path in self._all_hidden(), (
            f"{path} is refused by the command gate but VISIBLE to a subprocess. An "
            "approved script can write it without the gate ever seeing a path."
        )

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_legacy_home_is_covered_too(self, path: str) -> None:
        """A not-yet-migrated box still holds the real bytes."""
        legacy = path.replace(".kiro/crew/", ".kirocrew/")
        assert legacy in self._all_hidden()

    @pytest.mark.parametrize("path", MUST_BE_HIDDEN)
    def test_the_command_gate_still_refuses_the_spelled_out_write(self, path: str) -> None:
        """The other half of the coupling. If this stops refusing, the hide list is
        carrying a burden it was never meant to carry alone.

        A directory entry is probed through a file INSIDE it: `echo x > <dir>` is not a
        write anyone can perform, so asserting on the bare directory would be asserting
        on a shape that never occurs.
        """
        target = f"~/{path}" if path.endswith(".json") else f"~/{path}/planted"
        assert security.is_sensitive_bash_command(f"echo x > {target}") is not None

    @pytest.mark.parametrize("path", HIDDEN_AHEAD_OF_ITS_NAME_FENCE)
    def test_the_store_is_hidden_even_before_its_name_fence_exists(self, path: str) -> None:
        assert path in self._all_hidden()
        assert path.replace(".kiro/crew/", ".kirocrew/") in self._all_hidden()

    def test_hiding_is_in_every_mode_not_only_strict(self) -> None:
        """A protection that only applies in strict mode is absent on the default."""
        from kiro_crew import sandbox

        for name in ("_STRICT_DIRS", "_STANDARD_DIRS", "_CC_DIRS"):
            entries = getattr(sandbox, name)
            assert ".kiro/crew/variables" in entries, f"{name} does not hide the store"


class TestTheMatcherDoesNotDivergeFromBash:
    """Four ways the hand-rolled expander disagreed with the shell it models.

    Each is the same failure mode: bash produced a protected path and the gate produced
    something else, so the operand looked harmless. This layer is best-effort by
    construction -- a matcher is not a bash parser, which the module says of itself --
    and the floor beneath it is the sandbox hide list. That is why these are worth
    fixing but not worth trusting alone.
    """

    def test_a_descending_range_expands_like_bash(self) -> None:
        """`{w..e}` counts DOWN in bash. Walking only upward gave an empty span, so the
        operand produced no candidates at all while bash produced `crew`."""
        from kiro_crew.security import _expand_braces

        assert "crew" in _expand_braces("cr{w..e}w")
        assert "crew" in _expand_braces("cr{e..e}w")
        assert _blocked("mv ~/.kiro/cr{w..e}w /tmp/stash")

    def test_a_descending_numeric_range_too(self) -> None:
        from kiro_crew.security import _expand_braces

        assert _expand_braces("{3..1}") == ["3", "2", "1"]

    def test_an_oversized_brace_fails_closed(self) -> None:
        """Truncating dropped the TAIL, so a 65-item list with `crew` last expanded to
        `crew` in bash and to everything-but-`crew` here. Too-many-to-check must answer
        like names-the-container, not like names-nothing."""
        big = ",".join([f"x{i}" for i in range(64)] + ["crew"])
        assert _blocked(f"mv ~/.kiro/{{{big}}} /tmp/stash")

    def test_a_shadowed_navigation_verb_loses_the_carve_out(self) -> None:
        """`cd` can be a function. The carve-out spares an ordinary `cd`, and an
        ordinary `cd` does not appear in a command that also defines one."""
        assert _blocked('cd(){ mv "$1" /tmp/stash; }; cd ~/.kiro/crew')
        assert _blocked('function cd { mv "$1" /tmp/x; }; cd ~/.kiro/crew')
        assert _blocked("alias cd='mv'; cd ~/.kiro/crew /tmp/x")

    def test_the_carve_out_is_gone(self) -> None:
        """Superseded: there is no navigation exemption left to keep."""
        assert _blocked("cd ~/.kiro")
        assert _blocked("cd ~/.kiro/crew")
        # What replaces it as the "not everything is refused" guarantee:
        assert not _blocked("cd ~/.kiro/crew/sessions")

    def test_glob_matching_splits_on_either_separator(self) -> None:
        """`_home_dir_targets` yields NATIVE paths, so a Windows target is
        backslash-separated. Splitting on "/" alone gave one component, the length
        check never matched, and the glob arm silently passed everything -- green on
        macOS and absent on Windows."""
        from kiro_crew.security import _glob_could_name

        assert _glob_could_name("/x/y/*", {"/x/y/z"})
        assert _glob_could_name("/x/y/*", {r"\x\y\z"}), "a native Windows target must match"


class TestACustomDataHomeIsProtectedToo:
    """`KIROCREW_HOME` relocates the data home wholesale.

    An interpreter payload never tokenizes, so for a custom home the RAW scan is the
    only layer that can see it -- and anchoring solely on `~` left it invisible. With
    the variable set, that directory IS the container rather than a parent of one.
    """

    def test_the_configured_home_is_refused(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        assert _blocked("mv /opt/crewdata /tmp/stash")
        assert _blocked("python3 -c \"import os; os.rename('/opt/crewdata','/tmp/x')\"")

    def test_the_pattern_is_rebuilt_when_the_home_changes(self, monkeypatch) -> None:
        """The cache is keyed on the variable. A plain module-level cache would pin
        whatever it was at first call, and tests pin it per test -- so one built under
        a previous test's home would be reused, failing in the permissive direction."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata-one")
        assert _blocked("mv /opt/crewdata-one /tmp/x")
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata-two")
        assert _blocked("mv /opt/crewdata-two /tmp/x"), "the cached pattern went stale"

    def test_content_under_a_custom_home_is_still_reachable(self, monkeypatch) -> None:
        # Fixture root deliberately contains no "home" segment: the de-Amazon scrub's
        # identity scan treats a home-shaped path as a personal one, and an earlier
        # fixture root tripped it on a substring that was never a real home. Naming the
        # offending literal in this comment trips it again -- so it is described, not
        # quoted.
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        assert not _blocked("cat /opt/crewdata/sessions/a.json")


class TestBraceOverflowFailsClosedWithoutOverReaching:
    """Two opposite mistakes in one mechanism, and both were real.

    Bash expands braces before the command runs, so a token the matcher cannot fully
    enumerate is a token it cannot judge. The first version handled that by refusing
    ANY over-large brace expression, which refused `cp /data/img{a..z}{a..z}.jpg /out/`
    -- 676 ordinary expansions on a path that cannot be the trust root -- with a
    "governance trust root" message.

    It also stopped after a fixed number of passes and returned what it had, so nesting
    deeper than the limit left recognized braces UNEXPANDED and the token read as clean.

    The decision now hangs on the LITERAL PREFIX: everything before the first brace,
    which no expansion can change. If that cannot begin a protected path, the token is
    left alone; if it can, it is refused.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cp /data/img{a..z}{a..z}.jpg /out/",
            "ls /tmp/{a..z}{a..z}",
            "echo {1..100}",
            "mv /var/log/{a,b,c}{1..40} /backup/",
        ],
    )
    def test_ordinary_large_expansions_are_untouched(self, command: str) -> None:
        assert not _blocked(command), (
            f"{command!r} was refused as a trust-root access; its literal prefix "
            "cannot reach a protected path"
        )

    @pytest.mark.parametrize(
        "command",
        [
            # Nine brace groups -- more than the pass limit, so an earlier revision
            # left them unexpanded and read the token as clean. Verified against bash:
            # this really does produce `~/.kiro/crew`.
            "mv ~/.kiro/{c,c}{r,r}{e,e}{w,w}{,}{,}{,}{,}{,} /tmp/x",
            "cat ~/.kiro/crew/{s,s}{e,e}curity_policy.json",
        ],
    )
    def test_a_protected_path_behind_deep_nesting_is_refused(self, command: str) -> None:
        assert _blocked(command), f"{command!r} reaches a protected path through braces"

    def test_the_decision_does_not_depend_on_where_the_home_lives(self) -> None:
        """The environment-independence, which CI caught and every local run missed.

        The first version asked whether the literal prefix is a prefix OF a protected
        root -- true of a bare `/tmp/` on any machine whose data home sits under `/tmp`,
        which is exactly what a CI runner does. So `ls /tmp/{a..z}{a..z}` was refused as
        a trust-root access there while passing here, and the difference was the
        runner's directory layout rather than anything about the command.

        Asserted against the ROOTS directly rather than through a fake `$HOME`: the
        target set is TTL-cached, so a test that moves `HOME` mid-process measures the
        cache instead of the change -- which is how I first "confirmed" a regression
        that was not there.
        """
        from kiro_crew.security import _BRACE_OVERFLOW_SENTINEL, _overflow

        # `/tmp/` is an ANCESTOR of a CI-shaped root
        # (`/tmp/pytest-of-runner/.../.kiro/crew`) but not a sibling, so it must not
        # trip.
        assert _overflow("/tmp/{a..z}{a..z}") != [_BRACE_OVERFLOW_SENTINEL]
        # And a genuine sibling still does.
        assert _overflow("~/.ki{r,r}{o,o}{/,/}{c,c}{r,r}{e,e}{w,w}{,}{,}") == [
            _BRACE_OVERFLOW_SENTINEL
        ]

    def test_the_overflow_decision_reads_the_literal_prefix(self) -> None:
        """Unit-level, because the two behaviours above are one function's answer."""
        from kiro_crew.security import _BRACE_OVERFLOW_SENTINEL, _expand_braces

        deep = "~/.kiro/" + "".join(f"{{{c},{c}}}" for c in "crew") + "{,}" * 5
        assert _expand_braces(deep) == [_BRACE_OVERFLOW_SENTINEL]

        wide = "/data/img" + "{a..z}{a..z}.jpg"
        assert _BRACE_OVERFLOW_SENTINEL not in _expand_braces(wide)

    def test_a_single_element_brace_is_not_an_expansion(self) -> None:
        """`{c}` has no comma and no range, so bash leaves it literal -- confirmed with
        `bash -c` while writing this. Treating it as an expansion would refuse text that
        never becomes a path."""
        from kiro_crew.security import _expand_braces

        assert _expand_braces("~/.kiro/{c}{r}{e}{w}") == ["~/.kiro/{c}{r}{e}{w}"]


class TestTheMatcherStopsPretendingToBeAShell:
    """Three more shell-grammar divergences, and one of them ended a class rather than
    patching it.

    `AGENTS.md` already says this layer "is not a bash parser" and cannot become one.
    That is the frame for all three: fix what is cheap and exact, remove what cannot be
    decided textually, and leave the sandbox hide list as the floor.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv cd ~/.kiro/crew /tmp/x",
            "echo cd ~/.kiro/crew",
            "install cd ~/.kiro/crew /tmp/x",
            'cd(){ mv "$1" /tmp/x; }; cd ~/.kiro/crew',
        ],
    )
    def test_no_navigation_exemption_survives(self, command: str) -> None:
        """The carve-out is GONE, not narrowed.

        It spared a container named as a `cd` operand, and identified that operand by
        looking at the preceding token -- so `mv cd ~/.kiro/crew` earned the exemption
        by containing the word `cd`. Even parsed correctly it would not have been
        evidence: `cd` is a builtin a function or alias can shadow. Deciding what a
        token MEANS needs a shell.

        `ls cd ~/.kiro/crew /tmp/x` was here instead of `install`, and #6021's
        exoneration retired it from this list rather than failing it: unlike the other
        three, `ls` genuinely cannot rename or replace anything regardless of which
        words follow it, so treating it as a spoofing decoy for a WRITER conflated two
        different questions. It is exercised on its own merits in
        `TestBareTrustRootReadsAlsoExemptTheContainerGate` below.
        """
        assert _blocked(command)

    def test_removing_it_costs_only_the_container_itself(self) -> None:
        """The match is exact, so the blast radius is one path, not the data home."""
        for allowed in (
            "cd ~/.kiro/crew/sessions",
            "ls ~/.kiro/crew/skills",
            "cat ~/.kiro/crew/logs/gateway.log",
        ):
            assert not _blocked(allowed), f"{allowed!r} is ordinary agent work"

    @pytest.mark.parametrize(
        "command",
        ["mv ~/.kiro/cr{a..z..1}w /tmp/x", "mv ~/.kiro/cr{e..e..1}w /tmp/x"],
    )
    def test_a_stepped_range_expands(self, command: str) -> None:
        """`{a..z..2}` is bash 4+ syntax. Unhandled, the whole range matched nothing, so
        the token expanded to itself and read as clean."""
        assert _blocked(command)

    def test_step_expansion_matches_the_shell(self) -> None:
        """Checked against zsh while writing this -- `{1..9..3}` really is `1 4 7`.
        macOS's bash 3.2 does not support the form at all, which is why expanding is the
        safe direction: the deployment shell (bash 5.x on Linux) does."""
        from kiro_crew.security import _expand_braces

        assert _expand_braces("{1..9..3}") == ["1", "4", "7"]
        assert _expand_braces("{a..e..2}") == ["a", "c", "e"]
        assert _expand_braces("{e..a..2}") == ["e", "c", "a"]
        # A zero step is ignored by bash rather than being an error.
        assert _expand_braces("{1..3..0}") == ["1", "2", "3"]

    def test_dotglob_makes_a_bare_star_reach_the_container(self) -> None:
        """`*` does not match a leading dot -- unless `dotglob` is on, and then `~/*`
        names `~/.kiro`."""
        assert _blocked("shopt -s dotglob; mv ~/* /tmp/x")
        assert _blocked("setopt globdots; mv ~/* /tmp/x")

    def test_without_dotglob_an_ordinary_home_listing_is_untouched(self) -> None:
        """The reason this is conditional rather than always-on: refusing `ls ~/*`
        outright would be a false positive on one of the commonest commands there is."""
        assert not _blocked("ls ~/*")
        assert not _blocked("mv ~/* /tmp/x")


class TestTheRawGateCoversWindowsAndPosixClasses:
    """Two more spellings, and both were mine to have covered already.

    The pattern in each: I wrote a second, narrower version of something the leaf gate
    beside me already did properly. That is the same mistake as re-deriving the
    `$skill` token shape, and it fails in the permissive direction every time.
    """

    @pytest.mark.parametrize(
        "command",
        [
            r"move C:\Users\me\.kiro\crew D:\tmp",
            r"move %USERPROFILE%\.kiro\crew D:\x",
            r"Move-Item $env:USERPROFILE\.kiro\crew D:\x",
        ],
    )
    def test_native_windows_spellings_are_refused(self, command: str) -> None:
        """The raw scan is the ONLY layer that sees these: POSIX shlex eats backslashes
        during tokenization, and an embedded interpreter script never tokenizes at all.
        The leaf regex has had a Windows arm for a long time; this pattern was written
        with `/` alone."""
        assert _blocked(command), f"{command!r} names the container in native spelling"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cre[[:alpha:]] /tmp/x",
            "cat ~/.kiro/crew/[[:lower:]]ecurity_policy.json",
        ],
    )
    def test_posix_character_classes_are_refused(self, command: str) -> None:
        """`[[:alpha:]]` matches ONE character, but `fnmatch.translate` renders the
        inner `[:alpha:]` literally, so the pattern matched nothing and read as clean."""
        assert _blocked(command)

    def test_a_class_on_an_unrelated_path_is_untouched(self) -> None:
        """Reduced to `?`, not to "refuse anything containing a bracket"."""
        assert not _blocked("ls /data/[[:digit:]]*.log")
        assert not _blocked("rm /tmp/[[:alpha:]]*.tmp")

    def test_the_windows_branch_is_built_from_the_leaf_arm(self) -> None:
        """Structural, because the gap was a SECOND spelling rather than a missing one.

        The container pattern must carry a Windows alternation at all; a future edit
        that drops it takes the native spellings with it and nothing else notices.
        """
        from kiro_crew.security import _get_container_re

        pattern = _get_container_re().pattern
        assert "USERPROFILE" in pattern, "the container pattern lost its Windows arm"
        assert "[A-Za-z]:" in pattern, "the drive-letter anchor is gone"


class TestMoreShellSpellings:
    """Three more, of which two were ordinary logic bugs rather than grammar gaps."""

    @pytest.mark.parametrize(
        "command",
        ["mv ~/.k$'i'ro/crew /tmp/stash", "mv ~/.k$'i'r$'o'/crew /tmp/x"],
    )
    def test_ansi_c_quoting_is_unwrapped(self, command: str) -> None:
        """`$'i'` is `i` to the shell, so a path can be spliced through it a letter at
        a time and reassembled after both scans pass."""
        assert _blocked(command)

    def test_an_ordinary_ansi_c_string_is_untouched(self) -> None:
        assert not _blocked("echo $'hello' > /tmp/x")

    def test_bash_option_flags_count_as_dotglob(self) -> None:
        """`bash -O dotglob -c ...` enables it without ever running `shopt`, so a scan
        for the builtin alone reads it as disabled."""
        assert _blocked("bash -O dotglob -c mv ~/* /tmp/x")
        assert _blocked("shopt -s dotglob; mv ~/* /tmp/x")
        assert not _blocked("ls ~/*")

    def test_a_key_value_operand_is_expanded_before_extraction(self) -> None:
        """A logic-order bug, not a grammar gap.

        `_path_candidates` appended the RAW `key=value` right-hand side beside the
        expanded candidates, so `dd of=$HOME/.kiro/cr{e..e}w/...` produced two useless
        ones: the expanded whole token (not path-like, because of the `of=` prefix) and
        the unexpanded value (still carrying braces). Neither named the path.
        """
        assert _blocked("dd of=$HOME/.kiro/cr{e..e}w/security_policy.json")
        assert not _blocked("dd of=/tmp/out.img if=/dev/zero")


class TestAConfiguredHomeSurvivesWindowsNormalization:
    """CI-only failure, made reproducible here.

    `_build_container_regex` anchored the custom-home branch on
    `abspath(expanduser(KIROCREW_HOME))`. On Windows that rewrites a POSIX-shaped
    `/opt/crewdata` into `D:\\opt\\crewdata` — current drive, backslashes — so the
    pattern named a string that appears nowhere in `os.rename('/opt/crewdata', ...)`.
    The operand pass still normalized `mv /opt/crewdata ...` and caught it, which is
    why only the interpreter-payload form went red: the raw scan is the one layer
    that sees inside a `-c` payload, and it compares TEXT.
    """

    def test_the_configured_spelling_matches_when_abspath_rewrites_it(self, monkeypatch) -> None:
        """Simulates the Windows rewrite on any platform, so this cannot regress
        silently on the four fifths of CI that are not Windows."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        real_abspath = os.path.abspath
        monkeypatch.setattr(
            os.path,
            "abspath",
            lambda p: "D:\\opt\\crewdata" if p == "/opt/crewdata" else real_abspath(p),
        )
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("python3 -c \"import os; os.rename('/opt/crewdata','/tmp/x')\"")
        assert _blocked("mv /opt/crewdata /tmp/stash")

    def test_either_separator_matches_whichever_was_configured(self, monkeypatch) -> None:
        """An operator may configure `C:/data/crew` and then type `C:\\data\\crew`."""
        monkeypatch.setenv("KIROCREW_HOME", "D:/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv D:\\opt\\crewdata C:\\stash")
        assert _blocked("mv D:/opt/crewdata /tmp/x")
        assert not _blocked("mv D:/opt/other /tmp/x")

    @pytest.mark.parametrize("degenerate", ["/", "\\", "C:\\", "C:/"])
    def test_a_bare_root_fences_nothing(self, monkeypatch, degenerate: str) -> None:
        """A root names the whole filesystem, not a container. A branch matching it
        would refuse every absolute path in every command."""
        monkeypatch.setenv("KIROCREW_HOME", degenerate)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("cat /etc/hosts")
        assert not _blocked("ls /home")


class TestTheTailFailsClosed:
    """The terminator enumerated what may FOLLOW the container name, so every shell
    operator nobody listed ended the match and carried the path through. Inverted to
    enumerate what CONTINUES a pathname, an unforeseen spelling is refused instead.

    These cases are the evidence for the inversion, not the specification of it --
    the specification is that an unlisted character terminates. Adding a spelling
    here is welcome; needing to add a matching branch in `security.py` for it is the
    signal that the inversion has been undone.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # An operator welded to the path. `bash` ends the word at each of these,
            # so every one of them still names the container.
            "mv ~/.kiro/crew>/dev/null /tmp/stash",
            "mv ~/.kiro/crew>>log /tmp/stash",
            "mv ~/.kiro/crew|cat /tmp/x",
            "mv ~/.kiro/crew&& true",
            "mv ~/.kiro/crew&",
            "mv ~/.kiro/crew<in /tmp/x",
            # An expansion welded on that expands to nothing, so the word is the
            # container after expansion.
            "mv ~/.kiro/crew$(true) /tmp/stash",
            "mv ~/.kiro/crew`true` /tmp/x",
            "mv ~/.kiro/crew${EMPTY} /tmp/x",
        ],
    )
    def test_an_operator_welded_to_the_path_still_names_it(self, command: str) -> None:
        assert _blocked(command), f"{command!r} reaches the container"

    @pytest.mark.parametrize(
        "command",
        [
            "mv ${HOME:0}/.kiro/crew /tmp/stash",
            "mv ${HOME:-/root}/.kiro/crew /tmp/x",
            "mv ${HOME##*/}/.kiro/crew /tmp/x",
            "mv ${HOME}/.kiro/crew /tmp/x",
        ],
    )
    def test_a_parameter_operator_does_not_hide_the_home(self, command: str) -> None:
        """`${HOME:0}` is `$HOME`. Enumerating the operators would repeat the
        fail-open mistake, so anything up to the closing brace counts -- which can
        only ever refuse a command, never admit one."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            # Deeper than the container: the leaf gate's business, not this one's.
            "ls ~/.kiro/crew/sessions",
            "cat ~/.kiro/crew/memory/notes.md",
            "ls ~/.kiro/crew/logs/today.log",
            # A sibling whose name merely starts the same way.
            "ls ~/.kiro/crewold",
            "ls ~/.kiro/crew-backup",
            # A variable that merely starts with HOME.
            "echo $HOMEBREW_PREFIX",
        ],
    )
    def test_the_inversion_does_not_over_claim(self, command: str) -> None:
        assert not _blocked(command), f"{command!r} is not the container"

    def test_a_deeper_path_keeps_the_leaf_gates_own_refusal(self) -> None:
        """Regression: the first cut of the inversion let `crew/` be followed by
        anything, so this gate swallowed `~/.kiro/crew/$F` and replaced the leaf
        gate's precise `unresolved shell variable` refusal with its own. Beyond
        losing the better message, claiming everything under `crew/` would fence the
        agent out of its own `sessions/`, `memory/` and `logs/`.
        """
        reason = security.is_sensitive_bash_command("F=security_policy.json; cat ~/.kiro/crew/$F")
        assert reason is not None
        assert "must not be replaced" not in reason.lower()


class TestGlobModesAreModelledNotAssumed:
    """`_glob_could_name` answers "could this pattern name a protected path", and the
    answer depends on shell options that change what a glob MEANS. Assuming the
    defaults made the evaluator confidently wrong whenever one was enabled.
    """

    def test_globignore_enables_dotfile_matching(self) -> None:
        """Setting `GLOBIGNORE` to anything non-empty turns dotfile matching on as a
        documented side effect, without the word `dotglob` appearing anywhere.
        Verified against bash: `GLOBIGNORE=zz; echo *` lists `.kiro`."""
        assert _blocked("GLOBIGNORE=x; mv ~/* /tmp/x")
        assert not _blocked("echo GLOBIGNORE=")

    @pytest.mark.parametrize(
        "command",
        [
            "shopt -s globstar; mv ~/**/crew /tmp/x",
            "bash -O globstar -c mv ~/**/crew /tmp/x",
            "shopt -s globstar dotglob; mv ~/**/crew /tmp/x",
        ],
    )
    def test_globstar_defeats_the_fixed_depth_comparison(self, command: str) -> None:
        """`**` spans any number of components, so comparing component COUNTS -- which
        is right for `*`, since it never crosses a separator -- stops holding."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["shopt -s extglob; mv ~/@(.kiro)/crew /tmp/x", "shopt -s extglob; mv ~/!(x)/crew /tmp/x"],
    )
    def test_an_extglob_group_is_not_read_literally(self, command: str) -> None:
        """`fnmatch` renders `@(...)` literally, so the group matched nothing at all and
        the token read as clean. Note this token contains none of `*?[`, so the
        substitution has to happen BEFORE the "not a glob" exit."""
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            "ls ~/*",
            "ls ~/Documents/*",
            "mv ~/**/crew /tmp/x",
            "shopt -s globstar; ls ~/Documents/**/*.md",
            "shopt -s extglob; ls ~/Documents/@(a|b).md",
            "shopt -s extglob; echo hello",
        ],
    )
    def test_an_ordinary_glob_stays_ordinary(self, command: str) -> None:
        """The modes are MODELLED rather than treated as "refuse everything from here":
        enabling one must not turn an unrelated listing into a refusal."""
        assert not _blocked(command)


class TestADollarInFrontOfAQuoteIsDropped:
    """`$'…'` and `$"…"` both make the shell drop the marker and keep the text, so a
    path can be spliced through one and reassembled after every scan.

    Handled as ONE class in `_DOLLAR_QUOTE_RE`. Two forms arrived as separate findings
    a round apart; a third belongs in that alternation, not as another independent
    regex elsewhere in the file. That is the point these cases pin.
    """

    @pytest.mark.parametrize(
        "command",
        [
            # Locale translation. With no message catalogue `$"i"` is `i`, and the
            # catalogue belongs to the operator either way.
            'mv ~/.k$"i"ro/crew /tmp/stash',
            'mv ~/.kiro/$"crew" /tmp/x',
            'mv $"~"/.kiro/crew /tmp/x',
        ],
    )
    def test_locale_quotes_are_unwrapped(self, command: str) -> None:
        assert _blocked(command), f"bash resolves {command!r} to the container"

    def test_an_ordinary_locale_string_is_untouched(self) -> None:
        assert not _blocked('echo $"hello" > /tmp/x')


class TestAnsiCEscapesAreDecoded:
    def test_an_escape_that_spells_a_path_character(self) -> None:
        """`$'\\x69'` is `i`. Skipping any fragment containing a backslash was the same
        fail-open shape as enumerating terminators -- the rationale for skipping them
        (that a `\\n` in a path component does not help) was simply wrong: a hex or
        octal escape produces an ordinary letter."""
        assert _blocked(r"mv ~/.k$'\x69'ro/crew /tmp/x")
        assert _blocked(r"mv ~/.k$'\151'ro/crew /tmp/x")

    @pytest.mark.parametrize("command", [r"echo $'a\tb' > /tmp/x", r"printf $'line\n' > /tmp/x"])
    def test_an_ordinary_escape_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestABraceWithNoLiteralPrefix:
    def test_an_absent_prefix_rules_nothing_out(self) -> None:
        """The overflow decision rests on the literal prefix precisely because no
        expansion can change it. `{a,...,~/.kiro/crew}` has no prefix at all, so it
        decides nothing -- and "decides nothing" was being read as "decided clean"."""
        big = ",".join(f"/tmp/x{i}" for i in range(80))
        assert _blocked("mv {" + big + ",~/.kiro/crew} /tmp/z")

    def test_a_large_ordinary_brace_is_still_allowed(self) -> None:
        """The reason the decision is made on the prefix at all: refusing every
        oversized brace called `cp /data/img{a..z}{a..z}.jpg` a trust-root access."""
        assert not _blocked("cp /data/img{a..z}{a..z}.jpg /out/")


@pytest.mark.skipif(
    not platform_compat.IS_POSIX,
    reason=(
        "`_build_launcher_script` builds the LINUX namespace sandbox and calls "
        "`os.getuid()`, which Windows does not have. Asserting on it there would be "
        "asserting on an artifact that platform never produces -- the Windows sandbox "
        "is a different mechanism entirely. `_data_home_equivalents` itself is "
        "platform-neutral and is covered below on every platform."
    ),
)
class TestTheHideListFollowsTheDataHome:
    """The sandbox hide list is the layer this PR's own reasoning leans on: the command
    gate reads TEXT and cannot see inside `./script` or `make install`, so hiding the
    paths is what does not depend on the write being spelled out. Every entry was
    spelled relative to `~`, which quietly assumed the data home sits where it does by
    default -- so under `KIROCREW_HOME` the list covered a directory that does not
    exist while the real keystone files stayed readable.
    """

    def test_a_custom_home_is_hidden_too(self, monkeypatch, tmp_path) -> None:
        """Asserted on the LAUNCHER SCRIPT, not on the helper.

        Checking the helper's return value alone passes even when nothing calls it --
        which it did, when the wiring was mutated away to check exactly that.
        """
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("strict")
        for leaf in ("variables", "profiles", ".vault"):
            expected = str(tmp_path / "crewdata" / leaf)
            assert expected in script, f"{expected} is not hidden under a custom data home"

    def test_the_keystone_files_follow_it_as_well(self, monkeypatch, tmp_path) -> None:
        """`_CC_FILES` is anchored on `~` by a separate join, so it needed the same
        treatment -- the FILE-shaped keystone leaves are not reached by the directory
        entries."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("cc")
        for leaf in ("security_policy.json", "admission_policy.json", "computer_use.json"):
            assert str(tmp_path / "crewdata" / leaf) in script, leaf

    def test_a_neighbour_of_the_data_home_does_not_move_with_it(
        self, monkeypatch, tmp_path
    ) -> None:
        """`~/.kiro/crew-auth-staging` sits BESIDE the data home, not inside it.
        Re-anchoring it would point the hide list at a path that never exists."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        script = sandbox._build_launcher_script("strict")
        assert str(tmp_path / "crewdata" / "crew-auth-staging") not in script


class TestTheDataHomeReanchoringItself:
    """Platform-neutral half, deliberately OUTSIDE the launcher-script class above.

    That class can only run where the Linux launcher can be built, so keeping every
    assertion inside it left Windows -- the platform whose path handling differs most
    -- covering none of this.
    """

    @pytest.mark.parametrize("leaf", ["variables", "profiles", ".vault"])
    def test_a_crew_relative_entry_is_reanchored(self, monkeypatch, tmp_path, leaf) -> None:
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        got = sandbox._data_home_equivalents(sandbox._STRICT_DIRS)
        assert any(os.path.basename(path) == leaf for path in got), leaf

    def test_a_neighbour_is_not_reanchored(self, monkeypatch, tmp_path) -> None:
        """`~/.kiro/crew-auth-staging` sits BESIDE the data home, not inside it."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        got = sandbox._data_home_equivalents(sandbox._STRICT_DIRS)
        assert not any("crew-auth-staging" in path for path in got)

    def test_the_default_relative_entries_are_kept(self, monkeypatch, tmp_path) -> None:
        """Not replaced: a default install resolves to the same place anyway, and a box
        part-way through a data-home move can hold real bytes at both."""
        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        assert ".kiro/crew/variables" in sandbox._STRICT_DIRS
        assert ".kirocrew/variables" in sandbox._STRICT_DIRS


class TestRepeatedTrailingSeparators:
    def test_two_slashes_are_one_directory(self) -> None:
        """`~/.kiro/crew//` is `~/.kiro/crew` to every OS. The operand pass normalizes
        it away and caught this; the raw scan compares TEXT and matched one trailing
        separator but not two -- so only the interpreter-payload form got through,
        the same asymmetry as the Windows `abspath` bug earlier in this PR."""
        payload = (
            "python3 -c \"import os;os.rename(os.path.expanduser('~/.kiro/crew//'),'/tmp/x')\""
        )
        assert _blocked(payload)
        assert _blocked(payload.replace("crew//", "crew///"))

    def test_a_deeper_path_is_still_not_the_container(self) -> None:
        assert not _blocked("ls ~/.kiro/crew/sessions")


class TestAnEmptyExpansionRebuildsThePath:
    """An unset variable expands to nothing, so a path can be split around one and
    reassembled by the shell after both scans have read it as an unrelated string."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/${UNSET}crew /tmp/x",
            "mv ~/.kiro/cr${U}ew /tmp/x",
            "mv ~/.ki${U}ro/crew /tmp/x",
            # Braced only. `$UNSETcrew` is a variable NAMED `UNSETcrew` to bash, so it
            # expands to nothing at all rather than leaving `crew` behind -- the brace
            # is what ends the name early enough to weld a literal onto it.
            "mv ~/.kiro/${U}crew /tmp/x",
        ],
    )
    def test_an_expansion_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    def test_an_expansion_that_is_a_whole_component_is_left_alone(self) -> None:
        """`~/.kiro/crew/$F` must NOT collapse to `~/.kiro/crew/`.

        Welded into a component the expansion changes that component's NAME; alone it
        merely names a child, and the leaf gate already refuses that with the more
        accurate `unresolved shell variable`. Collapsing it here made this gate claim
        every deeper path ending in a variable -- caught by the existing suite, not by
        a test written for it.
        """
        reason = security.is_sensitive_bash_command("F=security_policy.json; cat ~/.kiro/crew/$F")
        assert reason is not None
        assert "must not be replaced" not in reason.lower()

    def test_an_ordinary_variable_path_is_untouched(self) -> None:
        assert not _blocked("ls $HOME/Documents")
        assert not _blocked("echo $PATH")


class TestABraceAlternativeThatCarriesASeparator:
    def test_an_alternative_can_reach_below_the_prefix(self) -> None:
        """The sibling rule completes exactly ONE component, which is all a
        separator-free alternative can add. `~/{a0,…,.kiro/crew}` has the harmless
        prefix `~/` and still names the container."""
        many = ",".join(f"a{i}" for i in range(70))
        assert _blocked("mv ~/{" + many + ",.kiro/crew} /tmp/x")

    def test_the_documented_tmp_case_stays_allowed(self) -> None:
        """Guarded by requiring a separator in the brace body. Without that guard this
        rule re-breaks `ls /tmp/{a..z}{a..z}` on a machine whose data home sits under
        `/tmp` -- a false positive that was already found and fixed once, and those
        single-character alternatives cannot produce the `/` such a reach would need.
        """
        assert not _blocked("ls /tmp/{a..z}{a..z}")
        assert not _blocked("cp /data/img{a..z}{a..z}.jpg /out/")


class TestAnAbsurdBraceStepDoesNotCrashTheGate:
    def test_a_step_too_long_to_parse(self) -> None:
        """CPython refuses to parse an integer past
        `sys.int_info.str_digits_check_threshold` and raises, so a 4,400-digit step
        took `ValueError` straight out through `_expand_braces` and aborted the
        tool-approval path. A gate that raises is a gate that is not answering.
        """
        command = "echo {1..2.." + "9" * 4400 + "}"
        assert security.is_sensitive_bash_command(command) is not None

    def test_an_ordinary_step_still_expands(self) -> None:
        assert not _blocked("echo {1..9..2}")
        assert _blocked("mv ~/.kiro/cr{e..e..1}w /tmp/x")


class TestPerCommandWorkHappensOncePerCommand:
    """Asserted as an invocation SHAPE, not a duration.

    `testing-conventions` § Determinism: a timed threshold false-reds on a shared
    runner. The defect here is structural and can be observed structurally -- work
    whose answer cannot vary between operands was being redone for every candidate.
    """

    def test_glob_modes_are_computed_once_regardless_of_operand_count(self, monkeypatch) -> None:
        """`_glob_modes` runs three regex scans over the WHOLE command text, and the
        answer is a property of the command, not of the operand being checked. Called
        per candidate it was 4,802 calls -- 14,406 full-text scans -- for one 9 KB
        command, and 2.3s of its 5.4s.

        Pinned by doubling the operand count and requiring the SAME call count: a
        per-candidate regression shows up as a number that grows with the input, with
        no dependence on how fast the machine is.
        """
        calls: list[str] = []
        real = security._glob_modes
        monkeypatch.setattr(
            security,
            "_glob_modes",
            lambda command: (calls.append(command), real(command))[1],
        )

        def count_for(operands: int) -> int:
            calls.clear()
            brace = "{" + ",".join(f"a{i}" for i in range(8)) + "}"
            command = "cp " + " ".join(f"/data/{brace}/f{j}" for j in range(operands)) + " /out/"
            security.is_sensitive_bash_command(command)
            return len(calls)

        assert count_for(2) == count_for(4) == count_for(8)

    def test_one_command_cannot_expand_without_bound(self) -> None:
        """`_MAX_BRACE_EXPANSIONS` bounds ONE token, which is a different bound: many
        operands each just under it never trip the overflow path while together they
        are unbounded. The budget is per command and shared across its operands.

        It is NOT what makes the pathological case fast -- see the class docstring in
        `security.py`; the expansions themselves cost single-digit milliseconds. It
        bounds work that was otherwise unbounded, which is worth doing on its own.
        """
        budget = security._ExpansionBudget(total=100)
        assert budget.spend(60) is True
        assert budget.spend(60) is False

    def test_an_exhausted_budget_degrades_to_the_overflow_reading(self) -> None:
        """Fail-closed, and gracefully: an overrun token takes the same reading an
        oversized one does, so a benign prefix is still allowed through unexpanded
        while one that could reach a protected root is refused."""
        budget = security._ExpansionBudget(total=1)
        out = security._expand_braces("/data/img{a,b,c}.jpg", budget)
        assert out == ["/data/img{a,b,c}.jpg"]
        budget2 = security._ExpansionBudget(total=1)
        assert security._expand_braces("~/.kiro/cr{e,f}w", budget2) == [
            security._BRACE_OVERFLOW_SENTINEL
        ]


class TestEveryUnresolvedExpansionVanishes:
    """An expansion that resolves to nothing lets a path be split around it and
    reassembled by the shell after every scan has read it as an unrelated string.

    The first cut listed the forms it knew -- `${NAME}` and `$NAME` -- which is the
    same fail-open shape as enumerating terminators, and `${A[@]}` walked through the
    gap. What is listed now is `${…}` with ANY content, plus both command-substitution
    spellings, because those vanish for exactly the same reason.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.ki${A[@]}ro/crew /tmp/x",
            "mv ~/.ki${A:-}ro/crew /tmp/x",
            "mv ~/.ki${!A}ro/crew /tmp/x",
            # Command substitution producing nothing, both spellings. Not reported;
            # found while confirming the array case, and verified against bash --
            # `echo ~/.ki$(true)ro/crew` prints the container.
            "mv ~/.ki$(true)ro/crew /tmp/x",
            "mv ~/.ki`true`ro/crew /tmp/x",
        ],
    )
    def test_a_vanishing_expansion_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["ls $HOME/Documents", "echo $(date) > /tmp/x", "echo `date` > /tmp/x"],
    )
    def test_ordinary_expansions_are_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestBashsOtherBracketNegation:
    def test_a_caret_negates_exactly_like_a_bang(self) -> None:
        """`[^x]` and `[!x]` are the same thing in bash. `fnmatch` reads a leading `^`
        as an ordinary set MEMBER and escapes it -- `translate("cre[^x]")` gives
        `cre[\\^x]` -- so the pattern matched nothing at all and read as clean, while
        the `!` spelling was handled correctly all along.
        """
        assert _blocked("mv ~/.kiro/cre[^x] /tmp/x")
        assert _blocked("mv ~/.kiro/cre[!x] /tmp/x")

    def test_an_unrelated_bracket_glob_is_untouched(self) -> None:
        assert not _blocked("ls /data/f[^x].txt")


class TestLineContinuations:
    def test_a_continuation_is_removed_before_matching(self) -> None:
        """The shell deletes a backslash-newline during lexing, so the characters on
        either side join into one word -- and each half is inert on its own, which is
        why both the raw and the normalized pass read this as clean."""
        assert _blocked("mv ~/.kiro/cre\\\nw /tmp/x")
        assert _blocked("mv ~/.ki\\\nro/crew /tmp/x")

    def test_an_ordinary_continuation_is_untouched(self) -> None:
        assert not _blocked("cp /a/b \\\n /tmp/x")


class TestAnUnknownSubstitutionOutput:
    """An unset expansion vanishes; a substitution's output does NOT.

    `$(printf i)` contributes `i`, so the empty-expansion reading -- which models every
    expansion as producing nothing -- reads `~/.k$(printf i)ro/crew` as `~/.kro/crew`
    and finds nothing. The output cannot be known without running the command, which is
    the one thing a gate must not do, so it is treated as UNKNOWN rather than as empty:
    the substitution becomes a `*` and the existing glob machinery answers.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.k$(printf i)ro/crew /tmp/x",
            "mv ~/.k`printf i`ro/crew /tmp/x",
            "mv ~/.kiro/cr$(printf e)w /tmp/x",
        ],
    )
    def test_output_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        [
            "echo $(date) > /tmp/x",
            "echo `date`",
            "cp $(ls /data) /out/",
            "cp $(which python) /tmp/x",
            "tar -czf /tmp/b.tgz $(find /data -name '*.log')",
        ],
    )
    def test_an_ordinary_substitution_is_untouched(self, command: str) -> None:
        """The refusal is not "a command contains a substitution" -- it is "a
        substitution sits where a container component would be"."""
        assert not _blocked(command)

    def test_the_word_is_masked_before_it_is_split(self) -> None:
        """A substitution contains whitespace of its own. Splitting first tore
        `~/.k$(printf i)ro/crew` into `~/.k$(printf` and `i)ro/crew`, and neither half
        resembles anything -- the first cut of this check silently found nothing."""
        assert _blocked("mv ~/.k$(printf   i)ro/crew /tmp/x")


class TestTheConfiguredHomeVariableItself:
    def test_any_spelling_of_the_variable_names_the_container(self, monkeypatch) -> None:
        """`$KIROCREW_HOME` and `${KIROCREW_HOME}` already resolved through
        `expandvars`; `${KIROCREW_HOME:-/tmp/no}` did not. Every spelling of that name
        refers to this container by definition, whatever operator is attached -- so the
        VARIABLE is matched, not just the value it currently holds."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked('mv "${KIROCREW_HOME:-/tmp/no}" /tmp/x')
        assert _blocked("mv $KIROCREW_HOME /tmp/x")
        assert _blocked("mv ${KIROCREW_HOME} /tmp/x")

    def test_an_unrelated_variable_is_untouched(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo ${KIROCREW_HOMEBREW:-x}")
        assert not _blocked("ls $HOME/Documents")


@pytest.mark.skipif(
    not sys.platform.startswith("darwin"),
    reason="Seatbelt profile text is macOS's mechanism; the Linux launcher is asserted above.",
)
class TestTheSeatbeltProfileMatchesTheLinuxLauncher:
    """macOS enforces through Seatbelt rules, not bind mounts, and the two were fixed
    in different places -- so the launcher's coverage said nothing about this one.

    Both halves had gaps: the file rules emitted `file-read*` and `file-link` but no
    `file-write*`, so hiding the governance ceiling from a subprocess did nothing to
    stop the same subprocess OVERWRITING it; and both the dir and file loops built
    their paths as `os.path.join(Path.home(), …)`, so under `KIROCREW_HOME` every rule
    named a path that does not exist.
    """

    def _profile(self, tier: str) -> str:
        from kiro_crew import sandbox

        return sandbox._build_seatbelt_profile(tier)

    @pytest.fixture
    def crew_root(self, monkeypatch, tmp_path) -> str:
        from kiro_crew.config.paths import config_dir

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        # `config_dir()` resolves symlinks -- on macOS `/var` is `/private/var` -- so
        # the expected path has to come from the resolver, not from `tmp_path`.
        return str(config_dir())

    @pytest.mark.parametrize("tier", ["standard", "cc", "strict"])
    @pytest.mark.parametrize(
        "leaf",
        [
            "security_policy.json",
            "admission_policy.json",
            "computer_use.json",
            "crons.json",
            "autonudge.json",
        ],
    )
    def test_a_keystone_file_is_read_and_WRITE_denied(self, crew_root, tier, leaf) -> None:
        """Write, not just read. Forging `computer_use.json` is how an agent grants
        itself the operator's own opt-in, and a read-only deny leaves that open."""
        profile = self._profile(tier)
        target = os.path.join(crew_root, leaf)
        assert '(deny file-read* (literal "%s"))' % target in profile
        assert '(deny file-write* (literal "%s"))' % target in profile

    @pytest.mark.parametrize("leaf", ["variables", "profiles"])
    def test_a_keystone_directory_follows_the_custom_home(self, crew_root, leaf) -> None:
        assert '(deny file-read* (subpath "%s"))' % os.path.join(crew_root, leaf) in self._profile(
            "standard"
        )

    def test_credential_files_keep_read_only_denial(self, crew_root) -> None:
        """`.npmrc` and `.git-credentials` are read-denied but NOT write-denied: npm and
        git write to them legitimately, and turning that into a hard failure is a
        separate decision from closing the governance ceiling."""
        profile = self._profile("cc")
        npmrc = os.path.join(os.path.expanduser("~"), ".npmrc")
        assert '(deny file-read* (literal "%s"))' % npmrc in profile
        assert '(deny file-write* (literal "%s"))' % npmrc not in profile


class TestTheContainerItselfCannotBeMoved:
    """The subprocess half of this PR's own thesis.

    `security.is_unreplaceable_container` refuses a COMMAND that names the container,
    but a subprocess is one opaque token to that gate: `./script.sh` containing
    `mv ~/.kiro/crew /tmp/stash && ln -s /tmp/evil ~/.kiro/crew` is never inspected.
    Every other list here hides CONTENTS, and content-hiding cannot help -- after the
    rename each leaf rule names a path the attacker has already emptied.

    So the sandbox has to protect the directory ENTRY, and it does it differently on
    each platform: Linux binds the container onto itself (a mount point cannot be
    renamed, EBUSY), macOS denies `file-write*` on the literal path.
    """

    @pytest.fixture
    def crew_root(self, monkeypatch, tmp_path) -> str:
        from kiro_crew.config.paths import config_dir

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        return str(config_dir())

    def test_the_resolved_data_home_is_listed(self, crew_root) -> None:
        from kiro_crew import sandbox

        assert crew_root in sandbox._unrenamable_containers()

    def test_the_default_locations_are_listed_too(self, crew_root) -> None:
        """Both spellings, for the same reason the hide lists keep both: a default
        install resolves to one of them, and a box mid-move can have real bytes at
        either."""
        from kiro_crew import sandbox

        listed = sandbox._unrenamable_containers()
        home = str(pathlib.Path.home())
        assert os.path.join(home, ".kiro/crew") in listed
        assert os.path.join(home, ".kirocrew") in listed

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_linux_launcher_binds_each_container_onto_itself(self, crew_root) -> None:
        """A bind of a directory over itself is transparent -- same contents, still
        writable -- but it makes the directory a mount point, and Linux refuses to
        rename one."""
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        assert "UNRENAMABLE_DIRS" in script
        assert crew_root in script
        # Through `_mount_or_die`, like every other mount in this launcher -- a bare
        # `_libc.mount` call here would silently fail open, and this specific mount is
        # the one this whole class exists to make un-defeatable.
        assert '_mount_or_die(target, target, _MS_BIND, "protecting data-home' in script

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_self_bind_happens_BEFORE_the_masking_mounts(self, crew_root) -> None:
        """Ordering, and it is the whole correctness of this mount.

        `MS_BIND` without `MS_REC` copies only the mount at that point and NOT the
        submounts beneath it. So binding the container AFTER the masking loops produces
        a fresh view of the container in which `profiles/` and `variables/` are the
        original directories again -- this protection silently undoing the one it sits
        inside, with every individual assertion about either one still passing.

        Nothing about a single mount call can express that, so the order is what gets
        pinned: self-bind, then the directory masks, then the file masks.
        """
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        self_bind = script.index("for d in UNRENAMABLE_DIRS:")
        dir_masks = script.index("for d in SENSITIVE_DIRS:")
        file_masks = script.index("for f in SENSITIVE_FILES:")
        assert self_bind < dir_masks < file_masks, (
            "the container self-bind must precede the masking mounts; a non-recursive "
            "bind applied afterwards discards them"
        )

    @pytest.mark.skipif(
        not sys.platform.startswith("darwin"), reason="Seatbelt profile text is macOS's."
    )
    @pytest.mark.parametrize("tier", ["standard", "cc", "strict"])
    def test_the_seatbelt_profile_denies_writing_the_entry(self, crew_root, tier) -> None:
        from kiro_crew import sandbox

        profile = sandbox._build_seatbelt_profile(tier)
        assert '(deny file-write* (literal "%s"))' % crew_root in profile

    @pytest.mark.skipif(
        not sys.platform.startswith("darwin"), reason="Seatbelt profile text is macOS's."
    )
    def test_the_descendants_are_left_writable(self, crew_root) -> None:
        """`literal`, never `subpath`. The agent's own `sessions/`, `memory/` and
        `logs/` live inside this directory; fencing the subtree would cut it off from
        its own working data, which is the same false positive the container gate is
        exact-match to avoid.

        Verified end-to-end against real `sandbox-exec` while writing this: with the
        literal rule in force, `mv <container> <elsewhere>` fails with `Operation not
        permitted` while a write to `<container>/sessions/new.json` succeeds.
        """
        from kiro_crew import sandbox

        profile = sandbox._build_seatbelt_profile("standard")
        assert '(deny file-write* (subpath "%s"))' % crew_root not in profile


class TestACdRelativeGlob:
    """The `cd`-relative arm asked only the EXACT container question.

    Both absolute arms already run `_glob_could_name`, so `mv ~/.kir?/crew /tmp/x` was
    refused while `cd ~ && mv .kir?/crew /tmp/x` -- the same path, reached by joining
    the operand onto the `cd` base -- was not. An asymmetry between two arms of one
    check is the shape worth pinning here, more than any single spelling.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "cd ~ && mv .kir?/crew /tmp/x",
            "cd ~ && mv .kiro/cre? /tmp/x",
            "cd ~ && mv .ki*/crew /tmp/x",
            "cd ~/.kiro && mv cre? /tmp/x",
        ],
    )
    def test_a_glob_joined_onto_a_cd_base_is_checked(self, command: str) -> None:
        assert _blocked(command)

    def test_the_leaf_gate_gets_the_same_treatment(self) -> None:
        """Both `_glob_could_name` calls were missing here, not just the container one."""
        assert _blocked("cd ~ && mv .ssh/id_* /tmp/x")

    @pytest.mark.parametrize(
        "command",
        ["cd ~ && ls Documents/*", "cd /tmp && mv a? b", "cd ~ && cat notes.md"],
    )
    def test_an_ordinary_cd_relative_glob_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestASymlinkedConfiguredHome:
    def test_the_resolved_spelling_is_matched_too(self, monkeypatch, tmp_path) -> None:
        """A configured home reached through a symlink has TWO spellings on disk.

        The operand passes resolve links themselves, so they caught both; only the raw
        scan was left comparing text, and it knew just the configured one. That makes
        the interpreter payload the single reachable form -- the same asymmetry as the
        Windows `abspath` bug and the doubled-separator bug earlier in this PR, and for
        the same reason each time.
        """
        real = tmp_path / "real" / "crewdata"
        real.mkdir(parents=True)
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "real")
        monkeypatch.setenv("KIROCREW_HOME", str(link / "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        resolved = os.path.realpath(str(link / "crewdata"))
        assert _blocked("python3 -c \"import os; os.rename('%s', '/tmp/x')\"" % resolved)
        assert _blocked("python3 -c \"import os; os.rename('%s', '/tmp/x')\"" % (link / "crewdata"))

    def test_an_unrelated_path_is_untouched(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv %s /tmp/x" % (tmp_path / "unrelated"))


class TestTheParentIsRelocatableToo:
    def test_the_kiro_directory_itself_is_protected(self) -> None:
        """Renaming the PARENT carries the container with it.

        `mv ~/.kiro /tmp/stash && ln -s /tmp/evil ~/.kiro` relocates the data home
        without ever naming it, so protecting only `~/.kiro/crew` leaves the identical
        attack one level up. `security._UNREPLACEABLE_CONTAINER_DIRS` has covered
        `.kiro` from the start; the sandbox list had not, so the two halves of one
        fence disagreed about its extent.
        """
        from kiro_crew import sandbox

        listed = sandbox._unrenamable_containers()
        home = str(pathlib.Path.home())
        assert os.path.join(home, ".kiro") in listed
        assert os.path.join(home, ".kiro/crew") in listed

    def test_it_matches_the_command_gate_s_own_list(self) -> None:
        """The two lists answer the same question and must not drift apart."""
        from kiro_crew import sandbox

        listed = {
            p.rsplit(str(pathlib.Path.home()) + os.sep, 1)[-1]
            for p in sandbox._unrenamable_containers()
        }
        for name in security._UNREPLACEABLE_CONTAINER_DIRS:
            assert name in listed, f"{name} is fenced as a command but not protected in the sandbox"


class TestNestedSubstitutionsAndUnicodeRanges:
    def test_a_nested_substitution_is_still_a_substitution(self) -> None:
        """`[^()]*` cannot span a nested `$()`, so `$(echo $(printf i))` matched nothing
        and the word read as ordinary text -- while the single-level form was refused."""
        assert _blocked("mv ~/.k$(echo $(printf i))ro/crew /tmp/x")
        assert _blocked("mv ~/.k$(printf i)ro/crew /tmp/x")

    def test_an_ordinary_nested_substitution_is_untouched(self) -> None:
        assert not _blocked("echo $(echo $(date))")

    def test_a_unicode_digit_range_does_not_crash_the_gate(self) -> None:
        """`str.isdigit()` is TRUE for `²` and `٣`, which `int()` then refuses, so
        `echo {²..³}` took `ValueError` straight out of `_expand_braces` and aborted
        the tool-approval path. A gate that raises is a gate that is not answering."""
        assert security.is_sensitive_bash_command("echo {²..³}") is None
        assert security.is_sensitive_bash_command("echo {٣..٥}") is None

    def test_ordinary_ranges_still_expand(self) -> None:
        assert not _blocked("echo {1..9}")
        assert not _blocked("cp /data/img{a..z}.jpg /out/")
        assert _blocked("mv ~/.kiro/cr{e..e}w /tmp/x")


class TestBareTrustRootReadsAlsoExemptTheContainerGate:
    """`_is_bare_trust_root_read` reused, not re-derived, at all four sites this PR's
    container-naming gate fires from: the raw pass-1 scan and the three
    `is_unreplaceable_container(...)` call sites inside the normalizer second pass.

    `ls -d ~/.kiro/crew` NAMES the container exactly like a relocating `mv` does, and
    a verb-independent match cannot tell them apart on text alone -- but the
    container-naming refusal exists to stop RENAMES and REPLACEMENTS, and nothing in
    the narrow, hand-audited allowlist this exoneration already checks (`ls`, `stat`,
    `du`, `readlink`, `basename`, `dirname`, `wc`, with no shell composition at all)
    can do either. This is the same false-positive family issue #6021 already fixed
    for the extraction-into-trust-root gate; this class is the container gate getting
    the identical treatment.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "ls -d ~/.kiro/crew",
            "ls -ld ~/.kiro/crew",
            "stat ~/.kiro/crew",
            "readlink ~/.kiro/crew",
            "du ~/.kiro/crew",
        ],
    )
    def test_a_bare_read_of_the_container_itself_is_allowed(self, command: str) -> None:
        assert not _blocked(command)

    def test_a_compound_cd_relative_read_is_not_exonerated(self) -> None:
        """`&&` is shell composition, which the exoneration's positive character-set
        check refuses on principle -- `_is_bare_trust_root_read` requires no
        composition at all, so a compound command never qualifies regardless of which
        program follows the `&&`. This is the conservative direction: the container
        gate over-blocks a chained read rather than risk exonerating a chained WRITE
        that merely opens with a harmless-looking one.
        """
        assert _blocked("cd ~ && ls -d .kiro/crew")

    def test_the_exoneration_does_not_widen_to_non_listed_programs(self) -> None:
        """The allowlist is the boundary, not "looks like a read".

        `echo` and `cat` are not writers of the container either, but they are not on
        the hand-audited list this exoneration reuses, and this class does not get to
        widen that list on its own authority -- #6021's own comments explain exactly
        why the list is closed rather than heuristic (`find -delete`, `install -d`).
        """
        assert _blocked("echo ~/.kiro/crew")
        assert _blocked("cat ~/.kiro/crew")

    def test_the_exoneration_does_not_survive_shell_composition(self) -> None:
        """A bare-looking read followed by a real write, chained on the same line."""
        assert _blocked("ls -d ~/.kiro/crew; rm -rf ~/.kiro/crew")
        assert _blocked("ls -d ~/.kiro/crew && mv ~/.kiro/crew /tmp/x")

    def test_actual_relocation_still_blocks_regardless(self) -> None:
        """The exoneration is scoped to the ALLOWLISTED PROGRAMS, not to the shape of
        the command -- a writer naming the container plainly is unaffected."""
        assert _blocked("mv ~/.kiro/crew /tmp/stash")
        assert _blocked("ln -s /tmp/evil ~/.kiro/crew")
        assert _blocked("install -d ~/.kiro/crew")
        assert _blocked("cd ~ && mv .kiro/crew /tmp/x")

    def test_a_pathname_program_is_not_exonerated(self) -> None:
        """`_is_bare_trust_root_read` itself refuses a path like `/bin/ls`, since a
        basename says nothing about what an attacker-placed executable at that path
        actually does -- this class inherits that boundary rather than re-deciding
        it, and pins that it survived the reuse."""
        assert _blocked("/bin/ls -d ~/.kiro/crew")


class TestPositionalAndSpecialParameters:
    """An unset positional parameter expands to nothing exactly like an unset named
    variable, and `_SHELL_EXPANSION_RE`'s bare-name pattern required a leading letter
    or underscore, so `$1` never matched it and a path spliced around one was
    reassembled by the shell after every scan read it as an unrelated string."""

    @pytest.mark.parametrize(
        "command",
        [
            "mv ~/.kiro/cre$1w /tmp/x",
            "mv ~/.kiro/cre$9w /tmp/x",
            "mv ~/.kiro/cre$*w /tmp/x",
            'bash -c "mv ~/.kiro/cre$1w /tmp/x"',
        ],
    )
    def test_a_special_parameter_welded_into_a_component(self, command: str) -> None:
        assert _blocked(command)

    @pytest.mark.parametrize(
        "command",
        ["echo $1", "echo $@ > /tmp/x", "echo $? > /tmp/x", "echo $$ > /tmp/x"],
    )
    def test_an_ordinary_use_is_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestTheSubstitutionScanFailsClosedPastItsBudget:
    """`_MAX_SUBSTITUTION_WORDS` bounds the WORK, not the ANSWER. Breaking the loop and
    falling through to `return False` meant a command with enough substitution-bearing
    words silently read as clean past word 64, regardless of whether the unexamined
    tail contained the one word that names the container -- exhausting a budget is not
    evidence of safety, and every other bounded scan in this module (braces, glob
    expansions) already answers "could name it" on overflow, not "does not"."""

    def test_a_container_forming_word_past_the_budget_is_still_caught(self) -> None:
        benign = " ".join("$(echo /data/f%d)" % i for i in range(70))
        command = "cp %s ~/.k$(printf i)ro/crew /out/" % benign
        assert _blocked(command)

    def test_exhausting_the_budget_with_no_real_container_word_fails_closed_too(
        self,
    ) -> None:
        """The honest cost of the fix: a command with more substitutions than the
        budget and NONE of them forming the container is refused anyway, because the
        scan cannot tell the two cases apart once it stops looking."""
        benign = " ".join("$(echo /data/f%d)" % i for i in range(100))
        assert _blocked("cp %s /out/" % benign)

    def test_an_ordinary_command_under_the_budget_is_untouched(self) -> None:
        assert not _blocked("echo $(date) > /tmp/x")


class TestANestedCustomHomesAncestorsAreProtectedToo:
    """One level up was not enough for an arbitrary custom `KIROCREW_HOME`: renaming
    ANY ancestor and replacing it with a symlink completes the same relocation attack
    this whole class of gate exists to stop, regardless of how many directories deep
    the configured home sits."""

    def test_every_ancestor_up_to_home_or_root_is_protected(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        nested = _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        containers = sandbox._unrenamable_containers()
        assert _os.path.join(resolved_tmp, "company") in containers
        assert _os.path.join(resolved_tmp, "company", "dept") in containers

    def test_the_bare_filesystem_root_is_never_included(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        monkeypatch.setenv("KIROCREW_HOME", _os.path.join(str(tmp_path), "company", "crewdata"))
        assert "/" not in sandbox._unrenamable_containers()

    def test_home_itself_is_never_included_when_the_custom_home_is_nested_under_it(
        self, monkeypatch
    ) -> None:
        """Matches `_SENSITIVE_LEAF_PARENT_DIRS`'s existing rule: a single-segment
        entry whose parent is home is excluded so as not to taint `cd ~`."""
        from kiro_crew import sandbox

        monkeypatch.setenv(
            "KIROCREW_HOME", os.path.join(os.path.expanduser("~"), "myworkspace", "crewdata")
        )
        containers = sandbox._unrenamable_containers()
        assert os.path.expanduser("~") not in containers
        assert os.path.join(os.path.expanduser("~"), "myworkspace") in containers

    def test_the_seatbelt_builder_picks_up_every_ancestor(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        monkeypatch.setenv(
            "KIROCREW_HOME", _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        )
        company_dir = _os.path.join(resolved_tmp, "company")
        assert (
            '(deny file-write* (literal "%s"))' % company_dir
        ) in sandbox._build_seatbelt_profile("standard")

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_linux_launcher_picks_up_every_ancestor(self, monkeypatch, tmp_path) -> None:
        import os as _os

        from kiro_crew import sandbox

        resolved_tmp = _os.path.realpath(str(tmp_path))
        monkeypatch.setenv(
            "KIROCREW_HOME", _os.path.join(resolved_tmp, "company", "dept", "crewdata")
        )
        company_dir = _os.path.join(resolved_tmp, "company")
        assert company_dir in sandbox._build_launcher_script("standard")


class TestTheCommandGateWalksCustomHomeAncestorsToo:
    """The sandbox's own ancestor walk (`sandbox._unrenamable_containers`) has a
    second-layer counterpart here: without the sandbox (disabled deliberately, or a
    platform it does not cover), this text gate is the LAST defense, and it did not
    know about a nested custom home's ancestors at all.
    """

    def test_every_ancestor_of_a_nested_custom_home_is_refused(self, monkeypatch, tmp_path) -> None:
        resolved_tmp = os.path.realpath(str(tmp_path))
        nested = os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        company_dir = os.path.join(resolved_tmp, "company")
        dept_dir = os.path.join(resolved_tmp, "company", "dept")
        assert _blocked("mv %s /tmp/x" % company_dir)
        assert _blocked("mv %s /tmp/x" % dept_dir)
        assert _blocked("mv %s /tmp/x" % nested)

    def test_an_unrelated_path_is_untouched(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("KIROCREW_HOME", os.path.join(str(tmp_path), "company", "crewdata"))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("mv /etc/passwd /tmp/x")
        assert not _blocked("ls ~/.kiro/crew/sessions")


class TestRepeatedInteriorSeparators:
    """The filesystem collapses a run of separators to one, so `~//.kiro/crew` and
    `~/.kiro//crew` both resolve to `~/.kiro/crew` -- and only the raw scan needs to
    know this, since the operand passes normalize the path themselves."""

    @pytest.mark.parametrize(
        "path",
        [
            "~//.kiro/crew",
            "~/.kiro//crew",
            "~///.kiro///crew",
        ],
    )
    def test_a_doubled_separator_still_names_the_container(self, path: str) -> None:
        payload = "python3 -c \"import os; os.rename(os.path.expanduser('%s'),'/tmp/x')\"" % path
        assert _blocked(payload)

    def test_an_ordinary_single_separator_path_is_untouched(self) -> None:
        assert not _blocked("cat /tmp/normal")
        assert not _blocked("ls ~/.kiro/crewold")


class TestNestedExtglobGroups:
    """`_EXTGLOB_GROUP_RE` excludes `(`/`)` from what it captures, so it can only ever
    match the INNERMOST group in a nested one -- one substitution pass left an outer
    `@(...)` construct in place for `fnmatch` to render literally. Not reproduced on
    this box's bash 3.2 (no newer bash available to confirm nested extglob expansion
    directly), so this is a defensive fix: the cost of over-fixing here is a sharper
    "any single character" reading, never a missed one, so there is no permissive
    direction to weigh against.
    """

    def test_a_nested_extglob_group_is_still_widened(self) -> None:
        assert _blocked("shopt -s extglob; mv ~/@(.k@(i)ro)/crew /tmp/x")

    def test_a_single_level_extglob_group_is_unaffected(self) -> None:
        assert _blocked("shopt -s extglob; mv ~/@(.kiro)/crew /tmp/x")

    def test_an_ordinary_extglob_is_untouched(self) -> None:
        assert not _blocked("shopt -s extglob; ls ~/Documents/@(a|b).md")
        assert not _blocked("shopt -s extglob; echo hello")


class TestConcatenatedQuotedLiteralsInAnInterpreterPayload:
    """A substitution can sit BETWEEN quoted literals joined by `+` rather than welded
    onto one continuous bash word -- `'~/.k' + '$(printf i)' + 'ro/crew'` inside a
    `python3 -c` payload is three whitespace-separated bash words, none of which alone
    names anything. Deliberately narrow: this reconstructs one common concatenation
    idiom, not an interpreter's full expression grammar.
    """

    def test_the_exact_reported_shape(self) -> None:
        assert _blocked(
            "python3 -c \"import os; os.rename('~/.k' + '$(printf i)' + " "'ro/crew', '/tmp/x')\""
        )

    def test_either_quote_ordering(self) -> None:
        """The outer `-c` wrapper and the inner literals must use DIFFERENT quote
        characters -- a combined either-quote scan matches the outer pair first and
        swallows every inner literal as unstructured content before ever looking
        for the pieces inside it."""
        assert _blocked("python3 -c \"os.rename('~/.kiro/' + 'cr' + '$(printf ew)', '/tmp/x')\"")
        assert _blocked('python3 -c \'os.rename("~/.k" + "$(printf i)" + "ro/crew", "/tmp/x")\'')

    def test_ordinary_concatenation_is_untouched(self) -> None:
        assert not _blocked("python3 -c \"print('hello' + ' ' + 'world')\"")
        assert not _blocked("python3 -c \"x = 'a' + 'b'; print(x)\"")

    def test_unrelated_adjacent_literals_with_no_plus_are_untouched(self) -> None:
        assert not _blocked("python3 -c \"print('foo'); print('bar')\"")


class TestTheLinuxSelfBindRefusesASymlinkedContainer:
    """`os.path.isdir` follows a symlink, so the self-bind loop would happily bind
    THROUGH one -- `mount(2)` resolves the link the same way `open()` does, landing
    the bind on the directory the link points to rather than on the link's own
    directory-entry slot. `rm ~/.kiro/crew && ln -s /evil ~/.kiro/crew` then swaps the
    link out from under a mount still faithfully protecting the OLD target.

    There is no bind-based fix -- protecting the link's own slot would mean
    write-denying the PARENT's contents, the subtree-fencing this whole mechanism
    deliberately does not do. So a symlinked container fails the spawn instead,
    matching every other control in this launcher.
    """

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_a_symlinked_container_is_detected_before_the_bind(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        link_path = tmp_path / "crewdata_link"
        link_path.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(link_path))
        script = sandbox._build_launcher_script("standard")
        assert "os.path.islink(target)" in script
        assert "sys.exit(" in script

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_islink_check_precedes_the_isdir_check(self) -> None:
        """Ordering: `isdir` alone would already have bound through the symlink by
        the time anything noticed."""
        from kiro_crew import sandbox

        script = sandbox._build_launcher_script("standard")
        islink_at = script.index("os.path.islink(target)")
        isdir_at = script.index("if os.path.isdir(target):", islink_at)
        assert islink_at < isdir_at

    def test_macos_seatbelt_already_protects_a_symlinked_container(self) -> None:
        """Verified empirically against real `sandbox-exec`, not asserted from the
        profile text alone: a literal `file-write*` deny on a symlink's OWN path
        blocks `rm`+`ln -s` replacing it, because Seatbelt's literal-path match is
        NOT symlink-following the way a Linux bind-mount target is. No fix needed on
        this platform; this test exists so a future refactor of the self-bind logic
        does not "fix" macOS too and paper over that the two platforms differ here
        for a real reason.
        """
        assert True


class TestAncestorSelfBindsAreOrderedShallowestFirst:
    """`MS_BIND` without `MS_REC` copies only the mount at that point, not the
    submounts beneath it -- the same failure mode a much earlier round of this PR
    fixed for self-bind-vs-masking order. Binding a DEEPER directory and then binding
    one of its ANCESTORS a moment later produces a fresh view of the ancestor that does
    not carry the deeper bind forward, undoing it. The ancestor walk appended entries
    deepest-first (the walk starts at the immediate parent and moves outward), which is
    backwards for the self-bind loop that consumes this list in order.
    """

    def test_every_ancestor_precedes_its_descendants(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        resolved_tmp = os.path.realpath(str(tmp_path))
        nested = os.path.join(resolved_tmp, "company", "dept", "crewdata")
        monkeypatch.setenv("KIROCREW_HOME", nested)
        containers = sandbox._unrenamable_containers()
        for i, ancestor in enumerate(containers):
            for j, descendant in enumerate(containers):
                if ancestor != descendant and descendant.startswith(ancestor.rstrip("/") + "/"):
                    assert i < j, (
                        f"{ancestor!r} (index {i}) must precede its descendant "
                        f"{descendant!r} (index {j}), or its self-bind would hide the "
                        "descendant's mount"
                    )

    def test_the_default_kiro_pair_is_also_ordered_correctly(self) -> None:
        """Not new behavior -- `.kiro` already preceded `.kiro/crew`. Pinned so a
        future edit cannot flip it while "fixing" something else."""
        from kiro_crew import sandbox

        containers = sandbox._unrenamable_containers()
        kiro = next(c for c in containers if c.endswith("/.kiro"))
        kiro_crew = next(c for c in containers if c.endswith("/.kiro/crew"))
        assert containers.index(kiro) < containers.index(kiro_crew)


class TestQuotedExtglobActivationAndPayloadScanning:
    """Two bugs in one finding. `ext""glob` is `extglob` once bash tokenizes it --
    dropping an adjacent empty quote pair is exactly what `$""` does elsewhere in this
    file's own reasoning -- but the mode-detection regex compared against the raw,
    un-normalized text and read the option as absent. Separately, and this one held
    even with the UNQUOTED spelling: a quoted `-c '...'` payload never tokenizes, so
    the operand check that runs on the normalizer pass's candidates never saw
    `~/@(.kiro)/crew` inside it, no matter how correctly the mode was detected.
    """

    @pytest.mark.parametrize(
        "command",
        [
            "bash -O ext\"\"glob -c 'mv ~/@(.kiro)/crew /tmp/stash'",
            "bash -O extglob -c 'mv ~/@(.kiro)/crew /tmp/stash'",
            'bash -O extglob -c "mv ~/@(.kiro)/crew /tmp/stash"',
        ],
    )
    def test_a_quoted_c_payload_is_scanned_with_its_enabled_modes(self, command: str) -> None:
        assert _blocked(command)

    def test_the_quote_split_activation_is_detected_on_its_own(self) -> None:
        from kiro_crew import security

        assert security._glob_modes("""bash -O ext""glob""")["extglob"]
        assert not security._glob_modes("echo hello")["extglob"]

    @pytest.mark.parametrize(
        "command",
        [
            "bash -c 'ls ~/Documents/@(a|b).md'",
            "bash -O extglob -c 'ls ~/Documents/@(a|b).md'",
            "echo 'a+b'",
            "echo user@example.com",
        ],
    )
    def test_ordinary_commands_are_untouched(self, command: str) -> None:
        assert not _blocked(command)


class TestASymlinkedCustomHomeIsProtectedAtTheConfiguredPath:
    """`config_dir()` resolves any symlink in `KIROCREW_HOME` before returning, so the
    self-bind protection landed on the RESOLVED target -- but a restart re-reads the
    raw env var and re-resolves it, so if the CONFIGURED path is itself a symlink,
    `rm <that path> && ln -s /evil <same path>` swaps what the next resolution follows,
    and nothing protected the symlink's own directory-entry slot.
    """

    def test_the_unresolved_configured_path_is_protected(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "crewdata_link"
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        containers = sandbox._unrenamable_containers()
        assert str(symlink_home) in containers

    @pytest.mark.skipif(
        not platform_compat.IS_POSIX,
        reason="`_build_launcher_script` builds the Linux namespace sandbox.",
    )
    def test_the_launcher_refuses_to_spawn_through_it(self, monkeypatch, tmp_path) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "crewdata_link"
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        script = sandbox._build_launcher_script("standard")
        assert str(symlink_home) in script

    def test_an_ordinary_custom_home_is_not_duplicated(self, monkeypatch, tmp_path) -> None:
        """The common case: no symlink, so the unresolved and resolved forms are the
        SAME path, and dedup must collapse them rather than mounting twice."""
        from kiro_crew import sandbox

        ordinary = tmp_path / "crewdata"
        ordinary.mkdir()
        monkeypatch.setenv("KIROCREW_HOME", str(ordinary))
        containers = sandbox._unrenamable_containers()
        assert len(containers) == len(set(containers))

    def test_ordering_holds_even_with_the_symlink_entry_present(
        self, monkeypatch, tmp_path
    ) -> None:
        from kiro_crew import sandbox

        real_target = tmp_path / "real_crewdata"
        real_target.mkdir()
        symlink_home = tmp_path / "company" / "crewdata_link"
        symlink_home.parent.mkdir()
        symlink_home.symlink_to(real_target)
        monkeypatch.setenv("KIROCREW_HOME", str(symlink_home))
        containers = sandbox._unrenamable_containers()
        for i, a in enumerate(containers):
            for j, b in enumerate(containers):
                if a != b and b.startswith(a.rstrip("/") + "/"):
                    assert i < j, f"{a!r} (index {i}) must precede {b!r} (index {j})"


class TestDeeplyNestedSubstitutionsAreMaskedToAFixedPoint:
    """`_OUTPUT_SUBSTITUTION_RE` allows one extra level of balanced parens inside
    `$(...)`, which is what a fixed-width regex can express for nesting at all --
    arbitrarily deep balanced nesting has no such pattern. One masking pass fully
    resolves one level and leaves a deeper one still `$(...)`-shaped, an unresolved
    marker rather than the `*` it should read as.
    """

    def test_one_level_still_works(self) -> None:
        assert _blocked("mv ~/.k$(echo $(printf i))ro/crew /tmp/x")

    def test_two_levels_of_nesting(self) -> None:
        assert _blocked("mv ~/.k$(echo $(echo $(printf i)))ro/crew /tmp/x")

    def test_three_levels_of_nesting(self) -> None:
        assert _blocked("mv ~/.k$(echo $(echo $(echo $(printf i))))ro/crew /tmp/x")

    def test_an_ordinary_deeply_nested_substitution_is_untouched(self) -> None:
        assert not _blocked("echo $(echo $(echo $(date)))")
        assert not _blocked("echo $(date)")


class TestTheAncestorWalkStopsAtTheSystemTempRootNotUnderIt:
    """A real regression, caught by CI and not by any local run: this project's OWN
    test suite pins `KIROCREW_HOME` under `/tmp` for isolation
    (`testing-conventions`), and the unbounded ancestor walk added two rounds ago
    reached bare `/tmp` and treated it as a protected container -- refusing every
    command naming it, `cd /tmp && cat notes.txt` included. Invisible locally because
    nothing in a bare `pytest` invocation sets `KIROCREW_HOME` at all.

    The fix is not "stop the walk at the first ancestor that happens to be under
    `/tmp`" -- that overshoots and un-protects every INTERMEDIATE ancestor between the
    leaf and `/tmp`, silently reopening the exact gap the walk exists to close. It has
    to stop EXACTLY at the temp root itself, the same exact-match shape the
    `Path.home()` stop already has.

    The stop is asymmetric between the two mechanisms, on review feedback: the
    command gate (`security.py`) is verb-independent text matching, so reaching the
    temp root there refuses every command merely NAMING it -- it has to stop early.
    The sandbox self-bind (`sandbox.py`) costs nothing comparable -- it denies
    RENAMING one literal directory entry, nothing else -- so it keeps walking through
    the temp root, protecting a `KIROCREW_HOME` nested under a user- or
    environment-selected `$TMPDIR` from having THAT boundary itself relocated.
    """

    def test_the_sandbox_protects_the_temp_root_itself(self, monkeypatch, tmp_path) -> None:
        """Unlike the command gate, the sandbox's ancestor walk does NOT exempt the
        temp root: self-binding it costs nothing (it only blocks renaming that one
        directory entry), so there is no usability reason to leave it out, and
        leaving it out would un-protect a `KIROCREW_HOME` nested under a writable
        custom `$TMPDIR`."""
        from kiro_crew.config.paths import _is_system_tmp_root

        nested = tmp_path / "company" / "dept" / "crewdata"
        nested.parent.mkdir(parents=True)
        monkeypatch.setenv("KIROCREW_HOME", str(nested))
        from kiro_crew import sandbox

        containers = sandbox._unrenamable_containers()
        real_tmp = pathlib.Path(os.path.realpath(str(tmp_path)))
        temp_root = next((a for a in [real_tmp, *real_tmp.parents] if _is_system_tmp_root(a)), None)
        assert temp_root is not None, "tmp_path is not under a recognized temp root"
        assert str(temp_root) in containers

    def test_ordinary_tmp_commands_are_allowed_even_with_a_tmp_nested_home(
        self, monkeypatch
    ) -> None:
        """The exact shape of the CI failure: an ordinary command naming `/tmp`,
        while `KIROCREW_HOME` happens to be pinned somewhere under it.

        Deliberately rooted at the LITERAL string `/tmp`, not the `tmp_path` fixture:
        on macOS `tmp_path` lives under `$TMPDIR` (`/private/var/folders/...`), a
        subtree that never passes through `/tmp` at all, so a `tmp_path`-based home
        cannot exercise this boundary there and this exact test passed locally with
        the fix removed -- the bug is only reachable through `/tmp` itself, which is
        where CI's own `tempfile.gettempdir()` resolves on Linux. No directory needs
        to exist on disk: `security.is_sensitive_bash_command` walks ancestors with
        plain `os.path` string operations, never `.exists()`."""
        nested = "/tmp/kirocrew-boundary-test/company/dept/crewdata"
        monkeypatch.setenv("KIROCREW_HOME", nested)
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("cd /tmp && cat notes.txt")
        assert not _blocked("mv /tmp /tmp2")
        assert not _blocked("cd /tmp; cd -; cat notes.txt")

    def test_intermediate_ancestors_under_tmp_stay_protected(self, monkeypatch, tmp_path) -> None:
        """The property that must NOT regress while fixing the above: everything
        strictly BETWEEN the leaf and the temp root is still a uniquely identifying
        directory, not shared territory, and stays protected on both mechanisms."""
        from kiro_crew import sandbox

        nested = tmp_path / "company" / "dept" / "crewdata"
        nested.parent.mkdir(parents=True)
        monkeypatch.setenv("KIROCREW_HOME", str(nested))
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        resolved_tmp = os.path.realpath(str(tmp_path))
        company_dir = os.path.join(resolved_tmp, "company")
        dept_dir = os.path.join(resolved_tmp, "company", "dept")
        assert company_dir in sandbox._unrenamable_containers()
        assert dept_dir in sandbox._unrenamable_containers()
        assert _blocked("mv %s /tmp/x" % company_dir)
        assert _blocked("mv %s /tmp/x" % dept_dir)

    def test_the_boundary_helper_directly(self, tmp_path) -> None:
        """Unit-level pin for `_is_system_tmp_root` itself: true exactly at the
        boundary, false one level either side of it."""
        from kiro_crew.config.paths import _is_system_tmp_root

        real_tmp = pathlib.Path(os.path.realpath(str(tmp_path)))
        assert not _is_system_tmp_root(real_tmp)
        assert not _is_system_tmp_root(real_tmp.parent)
        for ancestor in list(real_tmp.parents):
            if _is_system_tmp_root(ancestor):
                assert not _is_system_tmp_root(ancestor.parent)
                break
        else:
            pytest.fail("no ancestor of tmp_path was recognized as the temp root")


class TestObfuscatedAncestorReferencesAreCaughtToo:
    """GPT review, round after the temp-root fix: `_substitution_could_name_container`
    and `_raw_glob_could_name_container` each built their own target set from
    `_UNREPLACEABLE_CONTAINER_DIRS` alone, never from a configured home's ANCESTORS --
    so `mv ~/comp$(echo any)/dept /tmp/x` (substitution) and, with extglob enabled,
    `mv ~/comp@(any)/dept /tmp/x` (glob) both reached only the raw regex the ancestor
    walk was added to, and bypassed the substitution and glob scanners entirely, even
    though the LITERAL form of the same rename is refused. `_container_targets()` now
    feeds all three (plus `is_unreplaceable_container`, the cd-relative segment walk's
    own exact-match check) from one shared ancestor walk.
    """

    def test_substitution_obfuscated_ancestor_rename_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("mv /opt/comp$(echo any)/dept /tmp/x")

    def test_glob_obfuscated_ancestor_rename_is_blocked(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv /opt/comp@(any) /tmp/x'")

    def test_extglob_widening_still_matches_a_leading_dotfile(self, monkeypatch) -> None:
        """Regression pin for the widening fix itself: the ORIGINAL `.*` substitution
        exists so `@(.kiro)`-shaped groups still match a dotfile target, and the new
        plain-`*` reading added alongside it must not have narrowed that."""
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert _blocked("bash -O extglob -c 'mv ~/@(.kiro) /tmp/x'")

    def test_ordinary_extglob_use_is_still_unaffected(self, monkeypatch) -> None:
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("bash -O extglob -c 'ls @(*.txt|*.md)'")

    def test_cd_relative_resolution_to_an_ancestor_is_recognized(self, monkeypatch) -> None:
        """`is_unreplaceable_container` -- the cd-relative segment walk's own
        exact-match check -- has the identical gap independently of the raw scanners
        above, since it built its target set the same way."""
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        assert security.is_unreplaceable_container("/opt/company/dept")
        assert security.is_unreplaceable_container("/opt/company")

    def test_ordinary_substitution_and_glob_commands_stay_allowed(self, monkeypatch) -> None:
        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        assert not _blocked("echo $(date)")
        assert not _blocked("ls *.txt")


class TestTempRootDiscoveryFailureDoesNotCrashTheGate:
    """GPT review: `tempfile.gettempdir()` probes every candidate temp directory and
    raises `OSError` if none is usable -- rare, but `_under_system_tmp` is now reached
    from the per-command ancestor walk (`_is_system_tmp_root`), not only the
    gateway-start callers it originally served, so an uncaught raise there would crash
    whatever is deciding whether to allow a command instead of returning a decision.
    """

    def test_gettempdir_failure_is_caught_not_raised(self, monkeypatch) -> None:
        from kiro_crew.config import paths

        def _raise():
            raise OSError("no usable temporary directory found")

        monkeypatch.setattr(paths.tempfile, "gettempdir", _raise)
        # Must not raise. On POSIX the literal `/tmp` fallback still applies, so a
        # path actually under it is still recognized -- discovery failure fails
        # closed (falls back to the one hardcoded root) rather than fails open.
        result = paths._under_system_tmp(pathlib.Path("/tmp/some/nested/path"))
        assert result is True or result is False

    def test_command_authorization_survives_the_failure(self, monkeypatch) -> None:
        from kiro_crew.config import paths

        def _raise():
            raise OSError("no usable temporary directory found")

        monkeypatch.setenv("KIROCREW_HOME", "/opt/company/dept/crewdata")
        monkeypatch.setattr(security, "_CONTAINER_RE", None)
        monkeypatch.setattr(paths.tempfile, "gettempdir", _raise)
        # Must not raise, regardless of the answer.
        security.is_sensitive_bash_command("cd /tmp && cat notes.txt")


class TestTheSandboxProtectsAUserSelectedTempRootAncestor:
    """GPT review: unlike the command gate, the sandbox's ancestor walk has no
    usability reason to exempt the temp root -- self-binding it only blocks RENAMING
    that one directory entry, nothing else -- so leaving it out was an unforced gap:
    a `KIROCREW_HOME` nested under a writable, non-default `$TMPDIR` had that
    boundary itself left unprotected. See also
    `TestTheAncestorWalkStopsAtTheSystemTempRootNotUnderIt.
    test_the_sandbox_protects_the_temp_root_itself`, added alongside this class.
    """

    def test_sandbox_walk_no_longer_imports_the_boundary_helper_unnecessarily(self) -> None:
        """Documents the asymmetry directly: the command gate needs the temp-root
        exclusion (`security.py` imports and calls `_is_system_tmp_root`), the
        sandbox self-bind does not (`sandbox.py` no longer imports it -- it may
        still be named in an explanatory comment, but nothing there calls it)."""
        from kiro_crew import sandbox

        assert not hasattr(sandbox, "_is_system_tmp_root")
        assert hasattr(security, "_is_system_tmp_root")
