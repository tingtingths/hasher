#!/usr/bin/env python3
import argparse
import errno
import glob
import hashlib
import os
import re
import typing as typ
from concurrent import futures

__version__ = '0.0.5'

from rich.progress import *


@dataclass
class Hashed:
    input_name: str = None
    algo: str = None
    hex: str = None
    mode: str = None
    err: str = None


def _hash_stream(algo: str, reader: typ.Callable):
    _hash = hashlib.new(algo)
    for buf in iter(reader, b''):
        _hash.update(buf)
    return _hash


def _print_hashed(hashed_lst: typ.List[Hashed]):
    for hashed in hashed_lst:
        if hashed.err is not None:
            print(f'{hashed.input_name}: {hashed.err}', file=sys.stderr)
        else:
            # only binary mode supported
            print(f'{hashed.hex} *{hashed.input_name}')


def parse_checksum_file(file: str, encoding=None) -> typ.Iterator[re.Match]:
    if not os.path.exists(file):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file)

    with open(file, 'r', encoding=encoding) as f:
        s = f.read()
        # ^(?P<hash>.+)\s(?P<mode>\s|[*])(?P<file>.+)$
        pattern = re.compile(r"^(?P<hex>.+?)\s(?P<mode>\s|[*])(?P<input_name>.+)$", flags=re.MULTILINE)
        matches = pattern.finditer(s)
        return matches


def _hash_paths(paths, hashed_lst, prog_args, task_id=None, progress=None):
    def _done(_future: futures.Future):
        result = _future.result()
        if task_id is not None and progress is not None:
            if result is None:
                progress.update(task_id, advance=1)
            else:
                name = result.input_name
                if len(result.input_name) > 40:
                    name = f'{name[:18]}...{name[len(name) - 19:]}'
                if len(result.input_name) < 40:
                    name = f'{name}{" " * (40 - len(result.input_name))}'
                progress.update(task_id, advance=1, description=name)

        if result is not None:
            hashed_lst.append(result)

    future_tasks = []
    with futures.ProcessPoolExecutor(max_workers=1 if prog_args.parallel < 1 else prog_args.parallel) as executor:
        for path in paths:
            future = executor.submit(_process, path, prog_args.algo, prog_args.buffer_size)
            future.add_done_callback(lambda f: _done(f))
            future_tasks.append(future)

        # wait all tasks
        [f.result() for f in future_tasks]


def _process(path, algo, buf_size):
    ret = None
    if not os.path.exists(path):
        ret = Hashed(input_name=path, err='Not exists')
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            _hash = hashlib.new(algo)
            _hashed = _hash_stream(algo, lambda: f.read(buf_size))
            ret = Hashed(input_name=path, algo=_hashed.name, hex=_hashed.hexdigest(), mode='b')
    return ret


def main():
    parser = argparse.ArgumentParser(prog='hasher', description='hash files.')
    parser.add_argument('algo', type=str, choices=hashlib.algorithms_available, help='one of these hash algorithms')
    parser.add_argument('input', type=str, help='file path, omit if reading from stdin', nargs='*')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-b', '--buffer-size', default=65536, type=int, nargs='?', help='buffer size. default 65536')
    parser.add_argument('-c', '--checksum_file', type=str, nargs='?', help='checksum file to check against')
    parser.add_argument('--encoding', default='utf8', type=str, nargs='?',
                        help='checksum file encoding. refer to Python Standard Encodings.')
    parser.add_argument('-p', '--parallel', default=1, type=int, nargs='?', help='parallel count')
    parser.add_argument('--progress', action='store_true', help='print progress bar to stderr')
    # define how to get input files
    traversal_type_group = parser.add_mutually_exclusive_group()
    traversal_type_group.add_argument('-g', '--glob', action='store_true', help='treat input as glob pattern')
    traversal_type_group.add_argument('-r', '--recursive', action='store_true',
                                      help='traversal the directory recursively')
    # read arguments
    args = parser.parse_args()

    checksum_file = args.checksum_file
    if checksum_file and not os.path.exists(checksum_file):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), checksum_file)

    # If not connected to a tty device, i.e. terminal, ignore input argument and read from stdin.
    hashed_lst = []
    if not sys.stdin.isatty() and "PYCHARM_HOSTED" not in os.environ:
        # read from stdin
        hashed = _hash_stream(args.algo, lambda: sys.stdin.buffer.read(args.buffer_size))
        hashed_lst.append(Hashed(input_name='-', algo=hashed.name, hex=hashed.hexdigest(), mode='b'))
        _print_hashed(hashed_lst)  # print result
    else:
        # read from files
        paths = []
        expected_hashes: typ.Dict[str, Hashed] = None
        # if checksum file provided, hash file in it. Otherwise use input.
        if checksum_file:
            matches = [m for m in parse_checksum_file(checksum_file, encoding=args.encoding)]
            paths = [m.groupdict()['input_name'] for m in matches]
            # construct dict from parsed values
            # input_name -> Hashed(input_name, hex, mode)
            expected_hashes = {
                d['input_name']: Hashed(input_name=d['input_name'], hex=d['hex'], mode='b' if d['mode'] == '*' else 't')
                for d in [m.groupdict() for m in matches]
            }
        else:
            if args.glob:
                [paths.extend(glob.glob(path, recursive=True)) for path in args.input]
            elif args.recursive:
                # old fashioned traversal
                for path in args.input:
                    if os.path.isfile(path):
                        paths.append(path)
                        continue
                    if os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            if len(files) > 0:
                                paths.extend([os.path.join(root, f) for f in files])
            else:
                paths = args.input

        rich_print = False
        if args.progress:
            try:
                import rich.console
                import rich.progress
                rich_print = True
            except ImportError as e:
                print(f'Warning: Failed to import \'rich\'. {e}', file=sys.stderr)

        if rich_print:
            _console = rich.console.Console(stderr=True)
            with rich.progress.Progress(
                    # ---------- columns
                    "({task.completed}/{task.total})",
                    "[progress.description]{task.description}",
                    BarColumn(),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeRemainingColumn(),
                    # -------------------
                    console=_console,
                    transient=True
            ) as _progress:
                task_id = _progress.add_task(total=len(paths), description='Hashing...')
                _hash_paths(paths, hashed_lst, args, task_id, _progress)
        else:
            _hash_paths(paths, hashed_lst, args)

        if expected_hashes is not None:
            """Match hex from file to actual file from filesystem.
            Result could be one of [match, mismatch, file not found]"""
            mismatch = []
            error = []
            ok = []

            actual_hashes: typ.Dict[str, Hashed] = {h.input_name: h for h in hashed_lst}
            for filename, expected in expected_hashes.items():
                if filename not in actual_hashes:
                    # should not happens
                    error.append(f'{filename}: No candidate?')
                actual = actual_hashes[filename]
                if actual.err is not None and len(actual.err) > 0:
                    error.append(f'{filename}: {actual.err}')
                else:
                    if expected.hex == actual.hex:
                        ok.append(filename)
                    else:
                        mismatch.append(filename)

            [print(f'{f}: OK') for f in ok]
            if len(error) > 0:
                [print(f'{s}') for s in error]
            if len(mismatch) > 0:
                [print(f'{f}: Mismatch') for f in mismatch]

            print(f'Total {len(expected_hashes.keys())} files', file=sys.stderr)
            print(f'{len(ok)} file{"s" if len(ok) > 1 else ""} OK', file=sys.stderr)
            print(f'{len(error)} file{"s" if len(error) > 1 else ""} failed to process', file=sys.stderr)
            print(f'{len(mismatch)} file{"s" if len(mismatch) > 1 else ""} checksum mismatch', file=sys.stderr)
        else:
            _print_hashed(hashed_lst)


if __name__ == "__main__":
    main()
