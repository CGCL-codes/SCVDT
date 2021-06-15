#!/usr/bin/env python3
"""
Construct CG and calculate distances, similarly to genDistance.sh.
The distance is parallelized and uses the compiled distance calculation
version by default.
"""
import argparse
import multiprocessing as mp
import sys
import subprocess
from argparse import ArgumentTypeError as ArgTypeErr
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


STEP = 0
STATE_FN = "state-fast"
DOT_DIR_NAME = "dot-files"
CALLGRAPH_NAME = "callgraph.dot"
PROJ_ROOT = Path(__file__).resolve().parent.parent
DIST_BIN = PROJ_ROOT / "distance_calculator/distance_calculator"
DIST_PY = PROJ_ROOT / "scripts/distance.py"


def next_step(args):
    global STEP
    STEP += 1
    fn = args.temporary_directory / STATE_FN
    with fn.open("w") as f:
        print(STEP, file=f)


def get_resume(args):
    fn = args.temporary_directory / STATE_FN
    r = 0
    try:
        with fn.open("r") as f:
            r = int(f.read())
    except FileNotFoundError:
        pass
    return r


def abort(args):
    print(f"Failed in step {STEP}", file=sys.stderr)
    log_p = args.temporary_directory / f"step{STEP}.log"
    print(f"Check {log_p} for more information", file=sys.stderr)
    sys.exit(1)


def remove_repeated_lines(in_path, out_path):
    lines_seen = set()
    with out_path.open("w") as out, in_path.open("r") as in_f:
        for line in in_f.readlines():
            if line not in lines_seen:
                out.write(line)
                lines_seen.add(line)


def merge_callgraphs(dots, outfilepath):
    import networkx as nx
    print(f"({STEP}) Integrating several call-graphs into one.")
    G = nx.DiGraph()
    for dot in dots:
        G.update(nx.DiGraph(nx.drawing.nx_pydot.read_dot(dot)))
    with outfilepath.open('w') as f:
        nx.drawing.nx_pydot.write_dot(G, f)


def opt_callgraph(args, binary):
    print(f"({STEP}) Constructing CG for {binary}..")
    dot_files = args.temporary_directory / DOT_DIR_NAME
    prefix = dot_files / f"{binary.name}"
    cmd = ["opt", "-dot-callgraph", f"{binary}",
           "-callgraph-dot-filename-prefix", prefix,
           "-o", "/dev/null"]
    log_p = args.temporary_directory / f"step{STEP}.log"
    with log_p.open("w") as f:
        try:
            subprocess.run(cmd, stderr=f, check=True, cwd=dot_files)
        except subprocess.CalledProcessError:
            abort(args)


def construct_callgraph(args, binaries):
    fuzzer = args.fuzzer_name
    dot_files = args.temporary_directory / DOT_DIR_NAME
    callgraph_out = dot_files / CALLGRAPH_NAME

    if fuzzer:
        tmp = next(args.binaries_directory.glob(f"{fuzzer.name}.0.0.*.bc"))
        binaries = [tmp]

    for binary in binaries:
        opt_callgraph(args, binary)
        temp = dot_files / f"{binary.name}.callgraph.temp.dot"
        callgraph = dot_files / f"{binary.name}.callgraph.dot"
        callgraph.replace(temp)     # return only works with py >= 3.8 :(
        remove_repeated_lines(temp, callgraph)
        temp.unlink()

    # The goal is to have one file called "callgraph.dot"
    if fuzzer:
        cg = dot_files / f"{binary.name}.callgraph.dot"
        cg.replace(callgraph_out)
    else:
        callgraphs = dot_files.glob("*.callgraph.dot")
        merge_callgraphs(callgraphs, callgraph_out)
    next_step(args)


def exec_distance_prog(dot, targets, out, names, cg_distance=None,
                       cg_callsites=None, py_version=False):
    """
    Args:
        dot: Path to dot-file representing the graph.
        targets: Path to file specifying Target nodes.
        out: Path to output file containing distance for each node.
        names: Path to file containing name for each node.
        cg_distance: Path to file containing call-graph distance.
        cg_callsites: Path to file containing mapping between basic blocks and
            called functions.
        py_version: If true, the python version is used.
    """
    prog = DIST_BIN if not py_version else DIST_PY
    cmd = [prog,
           "-d", dot,
           "-t", targets,
           "-o", out,
           "-n", names]
    if cg_distance is not None and cg_callsites is not None:
        cmd.extend(["-c", cg_distance,
                    "-s", cg_callsites])
    pipe = subprocess.PIPE
    r = subprocess.run(cmd, stdout=pipe, stderr=pipe, check=True)
    return r


def dd_cleanup(cfg):
    cmd = fr"""
    awk '!a[$0]++' {cfg} > {cfg}.smaller.dot;
    mv {cfg}.smaller.dot {cfg};
    sed -i s/\\\\\"//g {cfg};
    sed -i 's/\[.\"]//g' {cfg};
    sed -i 's/\(^\s*[0-9a-zA-Z_]*\):[a-zA-Z0-9]*\( -> \)/\1\2/g' {cfg}
    """
    subprocess.run(cmd, shell=True)


def merge_distance_files(cfg_cg_path, output):
    with output.open('w') as f:
        for dist in cfg_cg_path.glob("*.distances.txt"):
            with dist.open("r") as df:
                f.write(df.read())


def calculating_distances(args):
    dot_files = args.temporary_directory / DOT_DIR_NAME
    bbcalls = args.temporary_directory / "BBcalls.txt"
    bbnames = args.temporary_directory / "BBnames.txt"
    fnames = args.temporary_directory / "Fnames.txt"
    bbtargets = args.temporary_directory / "BBtargets.txt"
    ftargets = args.temporary_directory / "Ftargets.txt"
    callgraph = dot_files / CALLGRAPH_NAME
    callgraph_distance = args.temporary_directory / "callgraph.distance.txt"

    if STEP == 1:
        print(f"({STEP}) Computing distance for callgraph")
        log_p = args.temporary_directory / f"step{STEP}.log"
        try:
            r = exec_distance_prog(
                    callgraph,
                    ftargets,
                    callgraph_distance,
                    fnames,
                    py_version=args.python_only)
        except subprocess.CalledProcessError as err:
            with log_p.open("w") as f:
                f.write(err.stderr.decode())
            abort(args)
        if not callgraph_distance.exists():
            with log_p.open("w") as f:
                f.write(r.stdout.decode())
                f.write(r.stderr.decode())
            abort(args)
        next_step(args)

    with callgraph.open("r") as f:
        callgraph_dot = f.read()

    # Helper
    def calculate_cfg_distance_from_file(cfg: Path):
        if cfg.stat().st_size == 0: return
        dd_cleanup(cfg)     # for python version
        name = cfg.name.split('.')[-2]
        if name not in callgraph_dot: return
        outname = name + ".distances.txt"
        outpath = cfg.parent / outname
        exec_distance_prog(
                cfg,
                bbtargets,
                outpath,
                bbnames,
                callgraph_distance,
                bbcalls,
                py_version=args.python_only)
    print(f"({STEP}) Computing distance for control-flow graphs (this might "
          "take a while)")
    with ThreadPoolExecutor(max_workers=mp.cpu_count()) as executor:
        results = executor.map(calculate_cfg_distance_from_file,
                               dot_files.glob("cfg.*.dot"))

    try:
        for r in results: pass  # forward Exceptions
    except subprocess.CalledProcessError as err:
        log_p = args.temporary_directory / f"step{STEP}.log"
        with log_p.open("w") as f:
            f.write(err.stderr.decode())
        abort(args)

    print(f"({STEP}) Done computing distance for CFG")
    merge_distance_files(
            dot_files,
            args.temporary_directory / "distance.cfg.txt")
    next_step(args)


def done(args):
    fn = args.temporary_directory / STATE_FN
    fn.unlink()
    print(f"""
----------[DONE]----------

Now, you may wish to compile your sources with
CC=\"{PROJ_ROOT}/afl-clang-fast\"
CXX=\"{PROJ_ROOT}/afl-clang-fast++\"
CFLAGS=\"$CFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\"
CXXFLAGS=\"$CXXFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\"

--------------------------
""")


# -- Argparse --
def is_path_to_dir(path):
    """Returns Path object when path is an existing directory"""
    p = Path(path)
    if not p.exists():
        raise ArgTypeErr("path doesn't exist")
    if not p.is_dir():
        raise ArgTypeErr("not a directory")
    return p
# ----


def main():
    global STEP
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries_directory", metavar="binaries-directory",
                        type=is_path_to_dir,
                        help="Directory where binaries of 'subject' are "
                             "located")
    parser.add_argument("temporary_directory", metavar="temporary-directory",
                        type=is_path_to_dir,
                        help="Directory where dot files and target files are "
                             "located")
    parser.add_argument("fuzzer_name", metavar="fuzzer-name",
                        nargs='?',
                        help="Name of fuzzer binary")
    parser.add_argument("-p" ,"--python-only",
                        action="store_true",
                        default=False,
                        help="Use the python version for distance calculation")
    args = parser.parse_args()

    # Additional sanity checks
    binaries = list(args.binaries_directory.glob("*.0.0.*.bc"))
    if len(binaries) == 0:
        parser.error("Couldn't find any binaries in folder "
                     f"{args.binaries_directory}.")
    if args.fuzzer_name:
        tmp = args.binaries_directory.glob(f"{args.fuzzer_name}.0.0.*.bc")
        args.fuzzer_name = args.binaries_directory / args.fuzzer_name
        if not args.fuzzer_name.exists() or args.fuzzer_name.is_dir():
            parser.error(f"Couldn't find {args.fuzzer}.")
        if len(list(tmp)) == 0:
            parser.error(f"Couldn't find bytecode for fuzzer {args.fuzzer} "
                         f"in folder {args.binaries_directory}.")

    STEP = get_resume(args)
    if not STEP:
        construct_callgraph(args, binaries),
    calculating_distances(args),
    done(args)


if __name__ == '__main__':
    main()
