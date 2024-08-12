#!/usr/bin/env python3
import io
import gzip
import requests


def download_mbox(cve_id: str) -> str:
    url = f'https://lore.kernel.org/linux-cve-announce/?q={cve_id}&x=m'
    response = requests.post(url, data=[('z', 'results only')])
    try:
        response.raise_for_status()
        return gzip.decompress(response.content).decode()
    except requests.HTTPError as e:
        print('failed to retrieve mbox for', cve_id)
        return ''


def vulnerability(cve_id: str) -> dict:
    # TODO: consider using GET-requests to
    # https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2024/CVE-2024-42258.json,
    # instead of bombarding with the POSTs
    mbox = download_mbox(cve_id)
    # TODO: parse mail
    return dict()
