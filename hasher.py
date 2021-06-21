#!/usr/bin/env python3
import argparse
import errno
import glob
import hashlib
import os
import re
import sys
import typing as typ
from concurrent import futures
from dataclasses import dataclass

__version__ = '0.0.4'


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


def parse_checksum_file(file: str) -> typ.Iterator[re.Match]:
    if not os.path.exists(file):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file)

    with open(file, 'r') as f:
        s = f.read()
        # ^(?P<hash>.+)\s(?P<mode>\s|[*])(?P<file>.+)$
        pattern = re.compile(r"^(?P<hex>.+)\s(?P<mode>\s|[*])(?P<input_name>.+)$", flags=re.MULTILINE)
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
    parser.add_argument('-g', '--glob', action='store_true', help='treat input as glob pattern')
    parser.add_argument('-p', '--parallel', default=1, type=int, nargs='?', help='parallel count')
    parser.add_argument('--progress', action='store_true', help='print progress bar to stderr')
    args = parser.parse_args()

    checksum_file = args.checksum_file
    if checksum_file and not os.path.exists(checksum_file):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), checksum_file)

    # If not connected to a tty device, i.e. terminal, ignore input argument and read from stdin.
    hashed_lst = []
    if not sys.stdin.isatty():
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
            matches = [m for m in parse_checksum_file(checksum_file)]
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
            console = rich.console.Console(stderr=True)
            with rich.progress.Progress(console=console, transient=True) as progress:
                task_id = progress.add_task(total=len(paths), description='Hashing...')
                _hash_paths(paths, hashed_lst, args, task_id, progress)
        else:
            _hash_paths(paths, hashed_lst, args)

        if expected_hashes is not None:
            """Match hex from file to actual file from filesystem.
            Result could be one of [match, mismatch, file not found]"""
            mismatch = 0
            not_found = 0
            ok = 0

            actual_hashes: typ.Dict[str, Hashed] = {h.input_name: h for h in hashed_lst}
            for filename, expected in expected_hashes.items():
                if filename not in actual_hashes:
                    # should not happens
                    print(f'{filename}: No candidate?', file=sys.stderr)
                    not_found += 1
                actual = actual_hashes[filename]
                if actual.err is not None and len(actual.err) > 0:
                    print(f'{filename}: {actual.err}', file=sys.stderr)
                    not_found += 1
                else:
                    if expected.hex == actual.hex:
                        print(f'{filename}: OK')
                        ok += 1
                    else:
                        print(f'{filename}: Mismatch')
                        mismatch += 1

            print(f'Total {len(expected_hashes.keys())} files', file=sys.stderr)
            print(f'{ok} file{"s" if ok > 1 else ""} OK', file=sys.stderr)
            if not_found > 0:
                print(f'{not_found} file{"s" if not_found > 1 else ""} cannot be found', file=sys.stderr)
            if mismatch > 0:
                print(f'{mismatch} file{"s" if mismatch > 1 else ""} checksum mismatch', file=sys.stderr)
        else:
            _print_hashed(hashed_lst)


if __name__ == "__main__":
    main()
