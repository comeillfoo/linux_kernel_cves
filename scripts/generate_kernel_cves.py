#!/usr/bin/env python3
import sys
import argparse
import json
import pathlib

from typing import Tuple, Union, Callable
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


def _metric_values(values: list[str]) -> dict[str, str]:
    return { value[0]: value for value in values }

CVSS2_COMMON = _metric_values([ 'None', 'Partial', 'Complete' ])
CVSS2_VECTOR_TABLE = {
    'AV': ( 'Access Vector', _metric_values([ 'Network', 'Adjacent', 'Local' ]) ),
    'AC': ( 'Access Complexity', _metric_values([ 'High', 'Medium', 'Low' ]) ),
    'Au': ( 'Authentication', _metric_values([ 'Multiple', 'Single', 'None' ]) ),
    'C': ( 'Confidentiality', CVSS2_COMMON ),
    'I': ( 'Integrity', CVSS2_COMMON ),
    'A': ( 'Availability', CVSS2_COMMON )
}

def _cvss2_parse_vector_string(vector_string: str) -> list[Tuple[str, str]]:
    result = []
    for part in vector_string.split('/'):
        key, value = part.split(':')
        name, values = CVSS2_VECTOR_TABLE[key]
        result.append((name, values[value]))
    return result


CVSS3_COMMON = { 'H': 'High', 'L': 'Low', 'N': 'None' }
CVSS3_VECTOR_TABLE = {
    'AV': ( 'Attack Vector',
           _metric_values([ 'Network', 'Adjacent', 'Local', 'Physical' ]) ),
    'AC': ( 'Attack Complexity', _metric_values([ 'High', 'Low' ]) ),
    'PR': ( 'Privileges Required', CVSS3_COMMON ),
    'UI': ( 'User Interaction', _metric_values([ 'Required', 'None' ]) ),
    'S': ( 'Scope', _metric_values([ 'Changed', 'Unchanged' ]) ),
    'C': ( 'Confidentiality', CVSS3_COMMON ),
    'I': ( 'Integrity', CVSS3_COMMON ),
    'A': ( 'Availability', CVSS3_COMMON ),
}

def _cvss3_parse_vector_string(vector_string: str) -> list[Tuple[str, str]]:
    result = []
    for part in vector_string.split('/')[1:]: # skip CVSS and version
        key, value = part.split(':')
        name, values = CVSS3_VECTOR_TABLE[key]
        result.append((name, values[value]))
    return result

VectorStringParser = Callable[[str], list[Tuple[str, str]]]

def _cvss(cvss: dict,
          vector_string_parser: VectorStringParser) -> dict[str, Union[str, int]]:
    items = [('score', cvss['baseScore'])]
    items.extend(vector_string_parser(cvss['vectorString']))
    return dict(items)


def cvss2(data: dict) -> dict[str, Union[str, int]]:
    metrics = data['containers']['cna']['metrics']
    for metric in metrics:
        if 'cvssV2_0' in metric:
            return _cvss(metric, _cvss2_parse_vector_string)
    raise FileNotFoundError


def cvss3(data: dict) -> dict[str, Union[str, int]]:
    metrics = data['containers']['cna']['metrics']
    cvssV3_1, cvssV3_0 = None, None

    for metric in metrics:
        if 'cvssV3_1' in metric:
            cvssV3_1 = metric['cvssV3_1']
        elif 'cvssV3_0' in metric:
            cvssV3_0 = metric['cvssV3_0']

    if cvssV3_1 is not None:
        return _cvss(cvssV3_1, _cvss3_parse_vector_string)
    if cvssV3_0 is not None:
        return _cvss(cvssV3_0, _cvss3_parse_vector_string)

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
