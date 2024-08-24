#!/usr/bin/env python3
import os
from typing import Generator, Tuple
import logging
import json
import gzip
from git import Repo
import requests


from common import GitBasedVulnerabilitiesSource, is_json, listdir_against
from model import KernelCve


def download_mbox(cve_id: str) -> str:
    url = f'https://lore.kernel.org/linux-cve-announce/?q={cve_id}&x=m'
    response = requests.post(url, data=[('z', 'results only')])
    try:
        response.raise_for_status()
        return gzip.decompress(response.content).decode()
    except requests.HTTPError as e:
        print('failed to retrieve mbox for', cve_id)
        return ''


def list_jsons(storage: str) -> Generator[Tuple[str, str], None, None]:
    for category in ['published', 'rejected']:
        category_root = os.path.join(storage, 'cve', category)
        for year in filter(os.path.isdir, listdir_against(category_root)):
            for vuln in filter(is_json, listdir_against(year)):
                yield category, vuln


class LinuxCveAnnounce(GitBasedVulnerabilitiesSource):
    def __init__(self, repository: Repo):
        super().__init__(repository)
        self.cves_index = {}


    @classmethod
    def repo_source(cls) -> str:
        return 'https://git.kernel.org/pub/scm/linux/security/vulns.git'


    def index(self) -> dict[str, Tuple[str, str]]:
        '''Indexes all available vulnerabilities
        '''
        if self.cves_index:
            return self.cves_index

        total = 0
        logging.debug('Indexing CVEs...')
        for category, json_path in list_jsons(self.repo_workdir):
            cveid = os.path.basename(json_path).strip('.json').strip()
            self.cves_index[cveid] = (category, json_path)
            total += 1
        logging.debug('Indexed %d CVEs', total)
        return self.cves_index


    def identifiers(self) -> set[str]:
        return set(self.index().keys())


    @classmethod
    def to_kernel_cve(cls, category: str, vuln: dict) -> KernelCve:
        kernel_cve: KernelCve = KernelCve.from_dict(vuln)
        kernel_cve.rejected = True if category == 'rejected' else None
        return kernel_cve


    def to_kernel_cves(self) -> Generator[KernelCve, None, None]:
        for category, json_path in self.index().values():
            raw_vuln = None
            try:
                with open(json_path, encoding='utf-8') as fp:
                    raw_vuln = json.load(fp)
                yield self.to_kernel_cve(category, raw_vuln)
            except Exception as e:
                logging.error('failed to parse vulnerability at %s', json_path,
                              exc_info=e)
