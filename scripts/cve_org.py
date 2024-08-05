#!/usr/bin/env python3
import os
import json
import re

from typing import Generator


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


LX_KERNEL_REGEX = re.compile(r'.*linux kernel.*', re.IGNORECASE)

def _is_cve_affect_linux(data: dict) -> bool:
    data = data.get('containers', None)
    if data is None: return False
    data = data.get('cna', None)
    if data is None: return False
    affected = data.get('affected', None)
    if affected is None: return False
    for affect in affected:
        vendor = affect.get('vendor', None)
        if vendor is not None and 'Linux' in vendor:
            return True
        product = affect.get('product', '').lower()
        if product == 'kernel' or LX_KERNEL_REGEX.match(product) is not None:
            return True

    # analyzing descriptions because of https://www.cve.org/CVERecord?id=CVE-2022-25265
    descriptions = data.get('descriptions', [])
    for description in descriptions:
        if description['lang'] == 'en':
            return LX_KERNEL_REGEX.match(description['value']) is not None
    return False


def _get_linux_kernel_cves(data_dir: str) -> Generator[dict, None, None]:
    for data in _deserialize(data_dir):
        if _is_cve_affect_linux(data):
            yield data


def vulnerabilities(storage: str) -> Generator[dict, None, None]:
    cves = os.path.join(storage, 'cves')
    return _get_linux_kernel_cves(cves)

