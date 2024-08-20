#!/usr/bin/env python3
from typing import Optional, Union, TypeVar
from dataclasses import dataclass

from cvss import CVSSType, _cvss, _cvss3_parse_vector_string, _cvss2_parse_vector_string


_REF_URLS_TEMPLATES = {
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


T = TypeVar('T')
TypeOrString = Union[T, str]
MultipleOrSingleStr = TypeOrString[list[str]]


@dataclass
class KernelCve:
    id: str
    affected_versions: MultipleOrSingleStr = 'unk to unk'
    backport: Optional[bool] = None
    breaks: MultipleOrSingleStr = ''
    cmt_msg: Optional[str] = None
    cvss2: Optional[CVSSType] = None
    cvss3: Optional[CVSSType] = None
    cwe: Optional[str] = None
    fixes: MultipleOrSingleStr = ''
    last_affected_version: Optional[str] = None
    last_modified: Optional[str] = None
    nvd_text: Optional[str] = None
    published: Optional[str] = None
    vendor_specific: Optional[bool] = None
    rejected: Optional[bool] = None

    @property
    def ref_urls(self) -> dict[str, str]:
        '''Reference URLs property'''
        return { src: tmplt % self.id for src, tmplt in _REF_URLS_TEMPLATES.items() }


    def to_dict(self) -> dict[str, dict]:
        fields = [
            'affected_versions', 'backport', 'breaks', 'cmt_msg', 'cvss2', 'cvss3',
            'cwe', 'fixes', 'last_affected_version', 'last_modified', 'nvd_text',
            'published', 'ref_urls', 'vendor_specific', 'rejected'
        ]
        result = {
            self.id: { },
        }
        for _field in fields:
            value = getattr(self, _field, None)
            if value is not None:
                result[self.id][_field] = value
        return result


    @classmethod
    def from_dict(cls, vuln: dict):
        return KernelCve(cveId(vuln),
                         affected_versions(vuln),
                         backport(vuln),
                         breaks(vuln),
                         cmt_msg(vuln),
                         cvss2(vuln),
                         cvss3(vuln),
                         cwe(vuln),
                         fixes(vuln),
                         last_affected_version(vuln),
                         last_modified(vuln),
                         nvd_text(vuln),
                         published(vuln),
                         vendor_specific(vuln),
                         rejected(vuln))


def cveId(vuln: dict) -> str:
    assert 'cveMetadata' in vuln
    assert 'cveId' in vuln['cveMetadata']
    return vuln['cveMetadata']['cveId']


def affected_versions(vuln: dict) -> MultipleOrSingleStr:
    return 'unk to unk'


def backport(vuln: dict) -> Optional[bool]:
    r = vuln.get('containers', None)
    if r is None: return r
    r = r.get('cna', None)
    if r is None: return r
    for reference in r.get('references', []):
        url = reference.get('url', '')
        if 'stable' in url: return True
    return None


def breaks(vuln: str) -> MultipleOrSingleStr:
    return ''


def cmt_msg(vuln: dict) -> Optional[str]:
    r = vuln.get('containers', None)
    if r is None: return r
    r = r.get('cna', None)
    if r is None: return r
    return r.get('title', None)


def cvss2(vuln: dict) -> Optional[CVSSType]:
    for metric in vuln['containers']['cna'].get('metrics', []):
        if 'cvssV2_0' in metric:
            return _cvss(metric['cvssV2_0'], _cvss2_parse_vector_string)
    return None


def cvss3(vuln: dict) -> Optional[CVSSType]:
    cvssV3_1, cvssV3_0 = None, None
    for metric in vuln['containers']['cna'].get('metrics', []):
        if 'cvssV3_1' in metric:
            cvssV3_1 = metric['cvssV3_1']
        elif 'cvssV3_0' in metric:
            cvssV3_0 = metric['cvssV3_0']

    if cvssV3_1 is not None:
        return _cvss(cvssV3_1, _cvss3_parse_vector_string)
    if cvssV3_0 is not None:
        return _cvss(cvssV3_0, _cvss3_parse_vector_string)

    return None


def cwe(vuln: dict) -> Optional[str]:
    try:
        for problem_type in vuln['containers']['cna']['problemTypes']:
            for desc in problem_type.get('descriptions', []):
                if desc.get('type', '') == 'CWE' \
                    and desc.get('lang', '') == 'en':
                    return desc.get('cweId', 'Other')
        return 'Other'
    except KeyError:
        pass
    return None


def fixes(vuln: dict) -> MultipleOrSingleStr:
    return ''


def last_affected_version(vuln: dict) -> Optional[str]:
    return None


def last_modified(vuln: dict) -> Optional[str]:
    return vuln \
        .get('cveMetadata', { 'dateUpdated': None }) \
        .get('dateUpdated', None)


def nvd_text(vuln: dict) -> Optional[str]:
    r = vuln.get('containers', None)
    if r is None: return r
    r = r.get('cna', None)
    if r is None: return r
    for description in r.get('descriptions', []):
        if description.get('lang', '') == 'en':
            return description.get('value', None)
    return None


def published(vuln: dict) -> Optional[str]:
    return vuln \
        .get('cveMetadata', { 'datePublished': None }) \
        .get('datePublished', None)


def vendor_specific(vuln: dict) -> Optional[bool]:
    return None


def rejected(vuln: dict) -> Optional[bool]:
    return None
