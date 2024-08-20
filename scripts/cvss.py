#!/usr/bin/env python3
from typing import Tuple, Callable, Union


CVSSType = Union[str, dict[str, Union[str, float]]]
VectorStringParser = Callable[[str], list[Tuple[str, str]]]


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


def _cvss(cvss: dict,
          vector_string_parser: VectorStringParser) -> CVSSType:
    items = [('score', float(cvss['baseScore']))]
    items.extend(vector_string_parser(cvss['vectorString']))
    return dict(items)
