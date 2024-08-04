#!/usr/bin/env python3
import sys
import json
import argparse
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


def cvss3(data: dict) -> dict:
    raise NotImplementedError


def cwe(data: dict) -> str:
    for problem_type in data['containers']['cna']['problemTypes']:
        for desc in problem_type['descriptions']:
            if desc['type'] == 'CWE' and desc['lang'] == 'en':
                return desc['cweId']
    return 'Other'


def fixes(data: dict) -> str:
    return ''


def nvd_text(data: dict) -> str:
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


def main() -> int:
    args = argparser().parse_args()

    fp = sys.stdout if args.output == '-' else open(args.output)

    is_first_printed = False
    print('{', file=fp)
    for vuln in vulnerabilities(args.data):
        if is_first_printed:
            print(',', file=fp)
        id, data = cveorg2kernelcve(vuln)
        print(f'\t"{id}": {json.dumps(data)}', end='', file=fp)
        is_first_printed = True
    print('}', file=fp)

    fp.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
