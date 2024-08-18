#!/usr/bin/env python3
from typing import Optional, Union, TypeVar
from dataclasses import dataclass, field


T = TypeVar('T')
TypeOrString = Union[T, str]
MultipleOrSingleStr = TypeOrString[list[str]]
ObjectOrString = TypeOrString[dict[str, str]]


@dataclass
class KernelCve:
    id: str
    affected_versions: MultipleOrSingleStr = 'unk to unk'
    backport: Optional[bool] = None
    breaks: MultipleOrSingleStr = ''
    cmt_msg: Optional[str] = None
    cvss2: Optional[ObjectOrString] = None
    cvss3: Optional[ObjectOrString] = None
    cwe: Optional[str] = None
    fixes: MultipleOrSingleStr = ''
    last_affected_version: Optional[str] = None
    last_modified: Optional[str] = None
    nvd_text: Optional[str] = None
    ref_urls: dict[str, str] = field(default_factory=dict)
    vendor_specific: Optional[bool] = None
    rejected: Optional[bool] = None


def convert_to_primitive(self: KernelCve) -> dict[str, dict]:
    fields = [
        'affected_versions', 'backport', 'breaks', 'cmt_msg', 'cvss2', 'cvss3',
        'cwe', 'fixes', 'last_affected_version', 'last_modified', 'nvd_text',
        'ref_urls', 'vendor_specific', 'rejected'
    ]
    result = {
        self.id: { },
    }
    for _field in fields:
        value = getattr(self, _field, None)
        if value is not None:
            result[self.id][_field] = value
    return result
