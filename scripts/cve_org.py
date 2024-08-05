#!/usr/bin/env python3
import os
import tempfile
import json
import re

from typing import Generator
from git import Repo


def _deserialize(data_dir: str) -> Generator[dict, None, None]:
    for cve_year in os.listdir(data_dir):
        cve_year = os.path.join(data_dir, cve_year)
        if not os.path.isdir(cve_year): continue
        for cve_id_prefix in os.listdir(cve_year):
            cve_id_prefix = os.path.join(cve_year, cve_id_prefix)
            if not os.path.isdir(cve_id_prefix): continue
            for single_cve_json in os.listdir(cve_id_prefix):
                single_cve_json = os.path.join(cve_id_prefix, single_cve_json)
                if not single_cve_json.endswith('.json'): continue
                with open(single_cve_json) as fp:
                    yield json.load(fp)


def _is_cve_affect_linux(data: dict) -> bool:
    data = data.get('containers', None)
    if data is None: return False
    data = data.get('cna', None)
    if data is None: return False
    data = data.get('affected', None)
    if data is None: return False
    for affect in data:
        vendor = affect.get('vendor', None)
        if vendor is not None and 'Linux' in vendor:
            return True
        product = affect.get('product', None)
        if product is not None and ('Linux kernel' in product or product == 'kernel'):
            return True
    return False


def _get_linux_kernel_cves(data_dir: str) -> Generator[dict, None, None]:
    for data in _deserialize(data_dir):
        if _is_cve_affect_linux(data):
            yield data


def vulnerabilities(storage: str) -> Generator[dict, None, None]:
    cves = os.path.join(storage, 'cves')
    return _get_linux_kernel_cves(cves)

