#!/usr/bin/env python3
# The `/cmd` bot's command runner.
#
# Ported from virto-network/frame-contrib (.github/scripts/cmd/cmd.py), itself ported from
# polkadot-fellows/runtimes (.github/scripts/cmd/cmd.py), Apache-2.0, and adapted to the Pass
# authenticators: benchmarks run on the benchmark runtime (`pass-authenticators-bench-runtime`,
# at `bench-runtime/`), and write each authenticator's default weights to
# `authenticators/<authenticator>/src/weights.rs`.
#
# It runs from the root of the checked-out repository (the pull request's head), so it works for
# every maintained line that has a benchmark runtime. The benchmarks to run are discovered from the
# built runtime rather than hardcoded, since each line benchmarks a different set of
# authenticators.

import argparse
import os
import re
import subprocess
import sys

import _help

_HelpAction = _help._HelpAction

RUNTIME_PACKAGE = "pass-authenticators-bench-runtime"
PROFILE = "release"
TARGET_DIR = os.environ.get("CARGO_TARGET_DIR", "target")
WASM = f"{TARGET_DIR}/{PROFILE}/wbuild/{RUNTIME_PACKAGE}/{RUNTIME_PACKAGE.replace('-', '_')}.compact.compressed.wasm"
TEMPLATE = ".maintain/frame-weight-template.hbs"
# Optional: the template renders `{{header}}` empty without it.
HEADER = ".maintain/file_header.txt"
BENCHMARK_PREFIX = "pass_"
AUTHENTICATORS_DIR = "authenticators"
# The only files a benchmark may write (and the bot may commit).
WEIGHTS_PATH = re.compile(r"^authenticators/[^/]+/src/weights\.rs$")

common_args = {
    '--continue-on-fail': {"action": "store_true", "help": "Won't exit(1) on a failed command and continues with the "
                                                           "next steps. Helpful to push at least the successful "
                                                           "benchmarks, and then run the failed ones separately"},
    '--quiet': {"action": "store_true", "help": "Won't print start/end/failed messages in the pull request"},
    '--clean': {"action": "store_true", "help": "Cleans up the previous bot's and author's comments in the pull "
                                                "request which triggered /cmd"},
}

parser = argparse.ArgumentParser(prog="/cmd ", description='A command runner for the Pass authenticators repo',
                                 add_help=False)
parser.add_argument('--help', action=_HelpAction, help='help for help if you need some help')  # help for help

subparsers = parser.add_subparsers(help='a command to run', dest='command')

"""
BENCH
"""

bench_example = '''**Examples**:

 > runs every benchmark in the benchmark runtime, and updates each authenticator's default weights

 %(prog)s

 > runs the benchmarks of pass_webauthn and pass_substrate_keys
 > --quiet makes it output nothing to the pull request but reactions

 %(prog)s --pallet pass_webauthn pass_substrate_keys --quiet

 > runs every benchmark, and continues even if some fail

 %(prog)s --continue-on-fail

 > does not output anything and cleans up the previous bot's and author's command triggering comments

 %(prog)s --pallet pass_webauthn --quiet --clean

 '''

parser_bench = subparsers.add_parser('bench', help="Runs benchmarks on the benchmark runtime, and updates the "
                                                   "authenticators' default weights",
                                     epilog=bench_example, formatter_class=argparse.RawDescriptionHelpFormatter)

for arg, config in common_args.items():
    parser_bench.add_argument(arg, **config)

parser_bench.add_argument('--pallet', help='Benchmark(s) space separated (e.g. pass_webauthn); all by default',
                          nargs='*', default=[])
# Used by the bot, which builds the runtime and runs the benchmarks on different machines.
parser_bench.add_argument('--runtime', help=argparse.SUPPRESS, default=None)

"""
FMT
"""
parser_fmt = subparsers.add_parser('fmt', help='Formats code (cargo fmt, as CI checks it)')
for arg, config in common_args.items():
    parser_fmt.add_argument(arg, **config)


def authenticator_dir(benchmark):
    """Maps a benchmark name (e.g. `pass_substrate_keys`) to its authenticator's directory
    (e.g. `authenticators/substrate-keys`)."""
    if not benchmark.startswith(BENCHMARK_PREFIX):
        return None
    path = os.path.join(AUTHENTICATORS_DIR, benchmark[len(BENCHMARK_PREFIX):].replace('_', '-'))
    return path if os.path.isdir(path) else None


def weights_file(benchmark):
    return f"{authenticator_dir(benchmark)}/src/weights.rs"


def list_benchmarks(wasm):
    result = subprocess.run(
        ["frame-omni-bencher", "v1", "benchmark", "pallet", "--no-csv-header", "--all", "--list",
         f"--runtime={wasm}"],
        capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to list the benchmarks of the benchmark runtime: {result.stderr}")
        sys.exit(1)
    return sorted({line.split(',')[0].strip() for line in result.stdout.splitlines() if line.strip()})


def bench(args):
    wasm = args.runtime
    if wasm is None:
        print(f'-- compiling {RUNTIME_PACKAGE} with runtime-benchmarks')
        result = subprocess.run(
            ["cargo", "build", "--locked", "-p", RUNTIME_PACKAGE, "--profile", PROFILE, "-q", "--features",
             "runtime-benchmarks"],
            env={"WASM_BUILD_RUSTFLAGS": "-C link-arg=--allow-undefined", **os.environ})
        if result.returncode != 0:
            print(f"Failed to build {RUNTIME_PACKAGE}")
            sys.exit(1)
        wasm = WASM
    print(f'-- using the runtime at {wasm}')

    available = list_benchmarks(wasm)
    print(f'-- benchmarks in the runtime: {available}')

    benchmarks = args.pallet or available
    unknown = [b for b in benchmarks if b not in available]
    if unknown:
        print(f'❌ No benchmarks for {unknown} in the benchmark runtime. Available: {available}')
        sys.exit(1)

    unmapped = [b for b in benchmarks if authenticator_dir(b) is None]
    if unmapped:
        print(f'❌ Cannot find the directory of {unmapped} '
              f'(expected `{AUTHENTICATORS_DIR}/<name>` for `{BENCHMARK_PREFIX}<name>`, with `_` as `-`)')
        sys.exit(1)

    unsafe = [b for b in benchmarks if not WEIGHTS_PATH.match(weights_file(b))]
    if unsafe:
        print(f'❌ The weights of {unsafe} would be written outside `{WEIGHTS_PATH.pattern}`')
        sys.exit(1)

    template = os.path.abspath(TEMPLATE)
    header = os.path.abspath(HEADER) if os.path.isfile(HEADER) else None
    failed, successful = [], []

    for benchmark in benchmarks:
        output = weights_file(benchmark)
        print(f'-- benchmarking {benchmark} into {output}')

        status = subprocess.run(
            ["frame-omni-bencher", "v1", "benchmark", "pallet",
             f"--runtime={wasm}",
             f"--pallet={benchmark}",
             "--extrinsic=*",
             "--steps=50",
             "--repeat=20",
             "--wasm-execution=compiled",
             "--heap-pages=4096",
             f"--template={template}",
             *([f"--header={header}"] if header else []),
             f"--output={output}",
             "--quiet"],
            env={**os.environ, "RUNTIME_LOG": "off"}).returncode

        if status != 0:
            failed.append(benchmark)
            if not args.continue_on_fail:
                print(f'Failed to benchmark {benchmark}')
                sys.exit(1)
        else:
            successful.append(benchmark)

    if failed:
        print(f'❌ Failed benchmarks: {failed}')
    if successful:
        print(f'✅ Successful benchmarks: {successful}')
    # With `--continue-on-fail`, the successful benchmarks are still worth committing.
    if failed and not (args.continue_on_fail and successful):
        sys.exit(1)


def fmt(args):
    # Same check as CI (`cargo fmt --all -- --check`), with the stable toolchain.
    command = "cargo fmt --all"
    print(f'Formatting with `{command}`')
    if os.system(command) != 0:
        print('❌ Failed to format code')
        if not args.continue_on_fail:
            sys.exit(1)


if __name__ == '__main__':
    args, unknown = parser.parse_known_args()
    print(f'args: {args}')

    if args.command == 'bench':
        bench(args)
    elif args.command == 'fmt':
        fmt(args)
    else:
        parser.print_help()
        sys.exit(1)
