"""Run leakcheck from Bazel.

    load("//bazel:leakcheck.bzl", "leakcheck_report")

    leakcheck_report(
        name = "leakcheck",
        tool = "@leakcheck//:leakcheck",
        srcs = glob(["src/**/*.c", "src/**/*.h"]),
        args = ["--baseline", "compare", "ci/leakcheck-baseline.txt"],
    )

`bazel build //:leakcheck` fails when leakcheck exits 2 or 3, and leaves
`leakcheck.sarif` in bazel-bin for a code-scanning upload. The sources are
analysed as one directory, because the cross-file checks (a lock order split
over two files, text that reaches a dangerous call in another file) need the
whole tree, not one translation unit at a time.

The tool comes from an external repository or a file in the workspace:

    leakcheck_report(
        name = "leakcheck",
        tool = "@leakcheck//:leakcheck",
        ...
    )
"""

def _leakcheck_report_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".sarif")
    if not ctx.files.srcs:
        fail("leakcheck_report %s: srcs is empty" % ctx.label.name)
    target = ctx.attr.target or ctx.files.srcs[0].dirname

    args = ctx.actions.args()
    args.add("static")
    args.add("-f", "sarif")
    args.add("-o", out.path)
    args.add_all(ctx.attr.args)
    args.add(target)

    ctx.actions.run(
        executable = ctx.executable.tool,
        arguments = [args],
        inputs = ctx.files.srcs,
        outputs = [out],
        mnemonic = "Leakcheck",
        progress_message = "leakcheck %s" % target,
    )
    return [DefaultInfo(files = depset([out]))]

leakcheck_report = rule(
    implementation = _leakcheck_report_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True, mandatory = True),
        "args": attr.string_list(
            doc = "Further flags, e.g. --baseline, --min-severity, --exclude.",
        ),
        "target": attr.string(
            doc = "Path to analyse; default: the directory of the first source.",
        ),
        "tool": attr.label(
            executable = True,
            cfg = "exec",
            mandatory = True,
            doc = "The leakcheck binary, e.g. @leakcheck//:leakcheck.",
        ),
    },
    doc = "Run leakcheck over a source tree and write SARIF; fails the build on findings.",
)
