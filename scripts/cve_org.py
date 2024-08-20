#!/usr/bin/env python3
import os
from typing import Generator
import json
import re
import logging

from git import Repo

from common import GitVulnerabilitiesSource, is_json, listdir_against
from model import KernelCve


def list_jsons(storage: str) -> Generator[str, None, None]:
    cves = os.path.join(storage, 'cves')
    for year in filter(os.path.isdir, listdir_against(cves)):
        for cve_id_prefix in filter(os.path.isdir, listdir_against(year)):
            for cve_json in filter(is_json, listdir_against(cve_id_prefix)):
                yield cve_json


LX_KERNEL_REGEX = re.compile(r'.*linux kernel.*', re.IGNORECASE)


def is_cve_affect_linux(vuln: dict) -> bool:
    vuln = vuln.get('containers', None)
    if vuln is None: return False
    vuln = vuln.get('cna', None)
    if vuln is None: return False
    affected = vuln.get('affected', None)
    if affected is None: return False
    for affect in affected:
        vendor = affect.get('vendor', None)
        if vendor is not None and 'Linux' in vendor:
            return True
        product = affect.get('product', '').lower()
        if product == 'kernel' or LX_KERNEL_REGEX.match(product) is not None:
            return True

    # analyzing descriptions because of https://www.cve.org/CVERecord?id=CVE-2022-25265
    for description in vuln.get('descriptions', []):
        if description.get('lang', '') == 'en':
            return LX_KERNEL_REGEX.match(description.get('value', '')) is not None
    return False


def read_json(json_path: str) -> dict:
    try:
        with open(json_path, encoding='utf-8') as fp:
            return json.load(fp)
    except Exception as e:
        logging.fatal('failed to parse flaw at %s', json_path,
                      exc_info=e)
    return {}


class CVEorg(GitVulnerabilitiesSource):
    def __init__(self, repository: Repo):
        super().__init__(repository)
        self.cves_index = {}

    @classmethod
    def repo_source(cls) -> str:
        return 'https://github.com/CVEProject/cvelistV5.git'


    def index(self) -> dict[str, str]:
        '''Indexes kernel related vulnerabilities
        '''
        if self.cves_index:
            return self.cves_index

        total = 0
        logging.debug('Indexing vulnerabilities...')
        for json_path in list_jsons(self.repo_workdir):
            cveid = os.path.basename(json_path).strip('.json').strip()
            self.cves_index[cveid] = json_path
            total += 1
        logging.debug('Indexed %d vulnerabilities', total)
        return self.cves_index


    @classmethod
    def to_kernel_cve(cls, vuln: dict) -> KernelCve:
        return KernelCve.from_dict(vuln)


    def to_kernel_cves(self) -> Generator[KernelCve, None, None]:
        total = 0
        for json_path in self.index().values():
            try:
                raw_vuln = read_json(json_path)
                if is_cve_affect_linux(raw_vuln):
                    total += 1
                    yield self.to_kernel_cve(raw_vuln)
            except Exception as e:
                logging.error('failed to parse/convert vulnerability at %s',
                              json_path, exc_info=e)
        logging.info('successfully converted %d vulnerabilities', total)
