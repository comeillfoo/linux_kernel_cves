#!/usr/bin/env python3
import sys
import argparse
import json
import pathlib


from cve_org import CVEorg
from linux_cve_announce import LinuxCveAnnounce


def argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()

    # Options:
    for source in [ 'cvelistV5', 'vulns' ]:
        def_path = './' + source
        short_opt = '-' + source[0].upper().strip()
        p.add_argument(short_opt, '--' + source, type=pathlib.Path,
                   default=pathlib.Path(def_path), metavar='PATH',
                   help=f'path to {source} repository folder, default {def_path}')

    # Arguments:
    p.add_argument('output', help='Print results to stdout (-) or file')
    return p


def dump_item(depth: int, key: str, value) -> str:
    result = ''
    for _ in range(depth):
        result += '    '
    result += json.dumps(key) + ': '
    if isinstance(value, dict):
        result += dump_dict(depth, value)
    else:
        result += json.dumps(value)
    return result


def dump_dict(depth: int, data: dict) -> str:
    result = '{\n'
    is_first_dumped = False
    for k, v in data.items():
        if is_first_dumped:
            result += ',\n'
        result += dump_item(depth + 1, k, v)
        is_first_dumped = True
    result += '\n'
    for _ in range(depth):
        result += '    '
    return result + '}'


def main() -> int:
    args = argparser().parse_args()

    cve_org = CVEorg.from_bare_path(args.cvelistV5)
    # lx_cve_announce = LinuxCveAnnounce.from_bare_path(args.vulns)
    fp = sys.stdout if args.output == '-' else open(args.output)

    is_first_printed = False
    print('{', file=fp)
    for kernel_cve in cve_org.to_kernel_cves():
        if is_first_printed:
            print(',', file=fp)

        print(f'    "{kernel_cve.id}": {dump_dict(1, kernel_cve.to_dict())}',
              end='', file=fp)
        is_first_printed = True
    print('}', file=fp)

    fp.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('Terminated')
        sys.exit(1)
