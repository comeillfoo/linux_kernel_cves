#!/usr/bin/env python3

ref_urls_templates = {
    'Debian': 'https://security-tracker.debian.org/tracker/CVE-%s',
    'ExploitDB': 'https://www.exploit-db.com/search?cve=%s',
    'NVD': 'https://nvd.nist.gov/vuln/detail/CVE-%s',
    'Red Hat': 'https://access.redhat.com/security/cve/CVE-%s',
    'SUSE': 'https://www.suse.com/security/cve/CVE-%s',
    'Ubuntu': 'https://ubuntu.com/security/CVE-%s',
    'CVE.org': 'https://www.cve.org/CVERecord?id=CVE-%s',
    'SUSE\'s Bugzilla': 'https://bugzilla.suse.com/show_bug.cgi?id=CVE-%s',
    'Gentoo\'s Bugzilla': 'https://bugs.gentoo.org/show_bug.cgi?id=CVE-%s',
}

def ref_urls(cve_id: str) -> dict[str, str]:
    id = cve_id.lstrip('CVE-')
    return { src: tmplt % id for src, tmplt in ref_urls_templates.items() }
