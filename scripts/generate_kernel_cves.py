#!/usr/bin/env python3
import sys
import argparse
import json
import pathlib

from typing import Tuple
from cve_org import vulnerabilities


def argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()

    def_path = './cvelistV5'
    p.add_argument('-d', '--data', type=pathlib.Path, default=pathlib.Path(def_path),
                   help=f'path to cvelistV5 repository folder, default {def_path}')
    p.add_argument('output', help='Print results to stdout (-) or file')
    return p


ref_urls_templates = {
    'Debian': 'https://security-tracker.debian.org/tracker/CVE-%s',
    'ExploitDB': 'https://www.exploit-db.com/search?cve=%s',
    'NVD': 'https://nvd.nist.gov/vuln/detail/CVE-%s',
    'Red Hat': 'https://access.redhat.com/security/cve/CVE-%s',
    'SUSE': 'https://www.suse.com/security/cve/CVE-%s',
    'Ubuntu': 'https://ubuntu.com/security/CVE-%s',
    'CVE.org': 'https://www.cve.org/CVERecord?id=CVE-%s',
    'Red Hat\'s Bugzilla': 'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-%s',
    'SUSE\'s Bugzilla': 'https://bugzilla.suse.com/show_bug.cgi?id=CVE-%s',
    'Gentoo\'s Bugzilla': 'https://bugs.gentoo.org/show_bug.cgi?id=CVE-%s',
}


def cveId(data: dict) -> str:
    return data['cveMetadata']['cveId']


def affected_versions(data: dict) -> str:
    return 'unk to unk'

def backport(data: dict) -> bool:
    return False


def breaks(data: dict) -> str:
    return ''


def cvss2(data: dict) -> dict:
    raise NotImplementedError


def _parse_vector_string(vector_string: str) -> list[Tuple[str, str]]:
    result = []
    common_values = { 'H': 'High', 'L': 'Low', 'N': 'None' }
    table = {
        'AV': (
            'Attack Vector',
            { 'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical' }
        ),
        'AC': ( 'Attack Complexity', { 'H': 'High', 'L': 'Low' } ),
        'PR': ( 'Privileges Required', common_values ),
        'UI': ( 'User Interaction', { 'R': 'Required', 'N': 'None' } ),
        'S': ( 'Scope', { 'C': 'Changed', 'U': 'Unchanged' } ),
        'C': ( 'Confidentiality', common_values ),
        'I': ( 'Integrity', common_values ),
        'A': ( 'Availability', common_values ),
    }
    for part in vector_string.split('/')[1:]: # skip CVSS and version
        key, value = part.split(':')
        name, values = table[key]
        result.append((name, values[value]))
    return result


def _cvss3(cvss3: dict) -> dict:
    items = [('score', cvss3['baseScore'])]
    items.extend(_parse_vector_string(cvss3['vectorString']))
    return dict(items)


def cvss3(data: dict) -> dict:
    metrics = data['containers']['cna']['metrics']
    cvssV3_1, cvssV3_0 = None, None

    for metric in metrics:
        if 'cvssV3_1' in metric:
            cvssV3_1 = metric['cvssV3_1']
        elif 'cvssV3_0' in metric:
            cvssV3_0 = metric['cvssV3_0']

    if cvssV3_1 is not None:
        return _cvss3(cvssV3_1)
    if cvssV3_0 is not None:
        return _cvss3(cvssV3_0)

    raise FileNotFoundError


def cwe(data: dict) -> str:
    for problem_type in data['containers']['cna']['problemTypes']:
        for desc in problem_type['descriptions']:
            if desc['type'] == 'CWE' and desc['lang'] == 'en':
                return desc['cweId']
    return 'Other'


def fixes(data: dict) -> str:
    return ''


def nvd_text(data: dict) -> str:
    for desc in data['containers']['cna']['descriptions']:
        if desc['lang'] == 'en':
            return desc['value']
    return ''


def ref_urls(data: dict) -> dict[str, str]:
    id = cveId(data).lstrip('CVE-')
    return { src: tmplt % id for src, tmplt in ref_urls_templates.items() }


def make_item_cb(constructor):
    def make_item(d: dict) -> Tuple:
        try:
            return (constructor.__name__, constructor(d))
        except Exception:
            return ()
    return make_item


def cveorg2kernelcve(data: dict) -> Tuple[str, dict]:
    fields = [
        affected_versions, backport, breaks, cvss2, cvss3, cwe, fixes, nvd_text,
        ref_urls
    ]
    return cveId(data), dict(filter(lambda item: len(item) == 2,
                                    map(lambda apply: apply(data),
                                        map(make_item_cb, fields))))


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

    fp = sys.stdout if args.output == '-' else open(args.output)

    is_first_printed = False
    print('{', file=fp)
    for vuln in vulnerabilities(args.data):
        if is_first_printed:
            print(',', file=fp)
        id, data = cveorg2kernelcve(vuln)
        print(f'    "{id}": {dump_dict(1, data)}', end='', file=fp)
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
