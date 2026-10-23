#!/usr/bin/env python3
"""Parser contract aligned to libseccomp/runc operand order.

SCMP_CMP_MASKED_EQ datum_a is the mask and datum_b is the compared value.
runc passes OCI value as datum_a and valueTwo as datum_b.
(flags & NAMESPACE_MASK) == 0 is therefore value=NAMESPACE_MASK, valueTwo=0.
value=0, valueTwo=NAMESPACE_MASK is the encoding libseccomp 2.6 compiles to
an unconditional allow. value=NAMESPACE_MASK, valueTwo=NAMESPACE_MASK is the
comparison against the mask.
"""

from __future__ import annotations

import json
import sys
from collections import Counter

NAMESPACE_MASK = (
    0x80 | 0x20000 | 0x2000000 | 0x4000000 | 0x8000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x200000000
)
DENY = {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP"}
EXECUTABLE = {"SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_NOTIFY"}
FORBIDDEN = {
    "clone3",
    "socketcall",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "io_setup",
    "io_submit",
    "io_cancel",
    "io_destroy",
    "io_getevents",
    "io_pgetevents",
}


class Reject(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def correct_clone_arg() -> dict:
    return {
        "index": 0,
        "op": "SCMP_CMP_MASKED_EQ",
        "value": NAMESPACE_MASK,
        "valueTwo": 0,
    }


def base(archs: list[str]) -> dict:
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": list(archs),
        "syscalls": [
            {"names": ["read"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["clone"], "action": "SCMP_ACT_ALLOW", "args": [correct_clone_arg()]},
        ],
    }


def check(profile: dict, archs: list[str]) -> None:
    if profile.get("defaultAction") not in DENY:
        raise Reject(f"defaultAction {profile.get('defaultAction')!r} is not a deny action")
    if sorted(profile.get("architectures") or []) != sorted(archs):
        raise Reject(f"architecture set {profile.get('architectures')!r} != {archs!r}")
    if "SCMP_ARCH_X86_64" not in archs:
        raise Reject("SCMP_ARCH_X86_64 is required in the frozen architecture set")
    rules = profile.get("syscalls") or []
    bag: Counter = Counter()
    for rule in rules:
        act = rule.get("action")
        names = rule.get("names") or []
        if act in EXECUTABLE:
            raise Reject(f"extra non-allow executable action {act} names={names}")
        if act != "SCMP_ACT_ALLOW":
            raise Reject(f"extra non-allow rule action {act}")
        for name in names:
            if name in FORBIDDEN:
                raise Reject(f"{name} appears in a rule")
            args = rule.get("args") or []
            if name == "clone":
                if len(args) != 1:
                    raise Reject("clone rule does not have the single frozen filter")
                arg = args[0]
                op = arg.get("op")
                value = int(arg.get("value", -1))
                compared = int(arg.get("valueTwo", -1))
                index = int(arg.get("index", -1))
                if value == NAMESPACE_MASK and compared == NAMESPACE_MASK:
                    raise Reject("clone filter compares against NAMESPACE_MASK")
                if value == 0 and compared == NAMESPACE_MASK:
                    raise Reject("clone filter uses the operand order libseccomp compiles to unconditional allow")
                if not (
                    op == "SCMP_CMP_MASKED_EQ"
                    and index == 0
                    and value == NAMESPACE_MASK
                    and compared == 0
                ):
                    raise Reject(
                        f"clone filter is not (flags & NAMESPACE_MASK) == 0 "
                        f"in runc operand order (value={value} valueTwo={compared})"
                    )
            bag[(name, act, tuple(sorted(archs)))] += 1
    frozen: Counter = Counter()
    for _arch in archs:
        frozen[("read", "SCMP_ACT_ALLOW", tuple(sorted(archs)))] += 0
    # One read rule and one clone rule, independent of arch repetition inside the rule.
    names = [name for rule in rules for name in rule.get("names") or []]
    if names.count("read") != 1 or names.count("clone") != 1 or len(names) != 2:
        raise Reject(f"frozen allow names {names} != ['read', 'clone']")


def expect(name: str, profile: dict, archs: list[str], ok: bool) -> bool:
    try:
        check(profile, archs)
        got = "ACCEPT"
    except Reject as exc:
        got = f"REJECT {exc.reason}"
    good = (got == "ACCEPT") == ok
    print(f"PARSER {name} expect_accept={ok} result={got} ok={good}")
    return good


def main() -> int:
    archs = sys.argv[1:] or ["SCMP_ARCH_X86_64"]
    print(f"PARSER_ARCHS {archs}")
    print(f"PARSER_NAMESPACE_MASK 0x{NAMESPACE_MASK:x}")
    print(f"PARSER_CORRECT_CLONE {json.dumps(correct_clone_arg())}")
    fail = 0
    good = base(archs)
    if not expect("correct_masked_eq_zero", good, archs, True):
        fail += 1
    wrong = json.loads(json.dumps(good))
    wrong["syscalls"][1]["args"][0]["valueTwo"] = NAMESPACE_MASK
    if not expect("compare_against_mask", wrong, archs, False):
        fail += 1
    swapped = json.loads(json.dumps(good))
    swapped["syscalls"][1]["args"][0]["value"] = 0
    swapped["syscalls"][1]["args"][0]["valueTwo"] = NAMESPACE_MASK
    if not expect("swapped_operands_unconditional_allow", swapped, archs, False):
        fail += 1
    for act in ("SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_NOTIFY"):
        profile = json.loads(json.dumps(good))
        profile["syscalls"].append({"names": ["mkdirat"], "action": act})
        if not expect(f"extra_{act}", profile, archs, False):
            fail += 1
    for name in (
        "clone3",
        "io_setup",
        "io_submit",
        "io_uring_setup",
        "io_uring_enter",
        "socketcall",
    ):
        profile = json.loads(json.dumps(good))
        profile["syscalls"].append({"names": [name], "action": "SCMP_ACT_ALLOW"})
        if not expect(f"allow_{name}", profile, archs, False):
            fail += 1
    missing = json.loads(json.dumps(good))
    missing["architectures"] = [a for a in archs if a != "SCMP_ARCH_X86_64"] or ["SCMP_ARCH_X86"]
    if not expect("missing_x86_64_arch", missing, archs, False):
        fail += 1
    print(f"PARSER_FAILURES {fail}")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
