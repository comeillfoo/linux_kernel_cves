#!/usr/bin/env python3
import os
from typing import Generator, Tuple, Optional
import logging
import json
import gzip
import requests
from git import Repo


from model.KernelCve import KernelCve, MultipleOrSingleStr


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
        for year in os.listdir(category_root):
            year_root = os.path.join(category_root, year)
            for vuln in os.listdir(year_root):
                if vuln.endswith('.json'):
                    yield category, os.path.join(year_root, vuln)


class LinuxCveAnnounce:
    _repo_source = 'https://git.kernel.org/pub/scm/linux/security/vulns.git'

    def __init__(self, repository: Repo):
        self.cves_index = {}
        self.repo = repository
        self.repo_workdir = self.repo.working_tree_dir
        logging.info('pulling updates...')
        self.repo.remote().pull()
        logging.info('successfully pulled')


    @classmethod
    def from_bare_path(cls, repository_path: str):
        return cls(Repo(repository_path))


    @classmethod
    def clone_to(cls, storage: str):
        logging.info('cloning to %s...', storage)
        repo = Repo.clone_from(cls._repo_source)
        logging.info('successfully cloned to %s', repo.working_tree_dir)
        return cls(repo)


    def index(self) -> int:
        '''Indexes all available vulnerabilities
        '''
        total = 0
        logging.debug('Indexing CVEs...')
        for category, json_path in list_jsons(self.repo_workdir):
            cveid = os.path.basename(json_path).strip('.json').strip()
            self.cves_index[cveid] = (category, json_path)
            total += 1
        logging.debug('Indexed %d CVEs', total)
        return total


    def _to_kernel_cve(self, category: str, vuln: dict) -> KernelCve:
        def _cmt_msg(vuln: dict) -> Optional[str]:
            r = vuln.get('containers', None)
            if r is None: return r
            r = r.get('cna', None)
            if r is None: return r
            return r.get('title', None)

        def _backport(vuln: dict) -> Optional[bool]:
            r = vuln.get('containers', None)
            if r is None: return r
            r = r.get('cna', None)
            if r is None: return r
            for reference in r.get('references', []):
                url = reference.get('url', '')
                if 'stable' in url: return True
            return None

        def _affected_versions(vuln: dict) -> MultipleOrSingleStr:
            return 'unk to unk'

        def _description(vuln: dict) -> Optional[str]:
            r = vuln.get('containers', None)
            if r is None: return r
            r = r.get('cna', None)
            if r is None: return r
            for description in r.get('descriptions', []):
                if description.get('lang', '') == 'en':
                    return description.get('value', None)
            return None
        return KernelCve(vuln['cveMetadata']['cveID'],
                         _affected_versions(vuln),
                         _backport(vuln),
                         cmt_msg=_cmt_msg(vuln),
                         nvd_text=_description(vuln),
                         rejected=True if category == 'rejected' else None)


    def to_kernel_cves(self) -> Generator[KernelCve, None, None]:
        for category, json_path in self.cves_index.values():
            raw_vuln = None
            try:
                with open(json_path) as fp:
                    raw_vuln = json.load(fp)
            except Exception as e:
                logging.error('failed to parse vulnerability at %s', json_path,
                            exc_info=e)
                continue
            yield self._to_kernel_cve(category, raw_vuln)
