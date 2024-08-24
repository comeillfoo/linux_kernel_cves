#!/usr/bin/env python3
from functools import reduce
from typing import Generator, Tuple
import logging

from common import SomeVulnerabilitiesSource
from model import KernelCve, mix_kernel_cves


def set_bit(bitarray: int, bit: int) -> int:
    return bitarray | (1 << bit)

def clear_bit(bitarray: int, bit: int) -> int:
    return bitarray & ~(1 << bit)


def mix_identifiers(dest: dict[str, int],
                      isource: Tuple[int, set[str]]) -> dict[str, int]:
    i, idents = isource
    for ident in idents:
        dest[ident] = dest.get(ident, 0) | (1 << i)
    return dest


def _identifiers(self: SomeVulnerabilitiesSource) -> set[str]:
    self.identifiers()


def is_same_bitmask(current: int, example: int, mask: int) -> bool:
    return (current & mask) == (example & mask)


class MixedSource(SomeVulnerabilitiesSource):
    def __init__(self, sources: list[SomeVulnerabilitiesSource] = []):
        self.sources = sources
        self.masks_index: dict[str, int] = {}
        self.sources_mask = (1 << len(self.sources)) - 1


    def identifiers(self) -> set[str]:
        if self.masks_index:
            return self.masks_index
        self.masks_index = reduce(mix_identifiers,
                                  enumerate(map(_identifiers, self.sources)),
                                  {})
        return self.masks_index


    def to_kernel_cves(self) -> Generator[KernelCve, None, None]:
        curr_masks = {}
        buffer_dict = {}
        generators = [ source.to_kernel_cves() for source in self.sources ]
        is_empty = self.sources_mask
        while bool(is_empty & self.sources_mask):
            for i in range(len(generators)):
                kernel_cve = next(generators[i], None)
                if kernel_cve is None:
                    is_empty = clear_bit(is_empty, i)
                    logging.debug('source[%d] is exhausted', i)
                    continue
                _id = kernel_cve.id
                buffer_dict[_id] = mix_kernel_cves(kernel_cve,
                                                buffer_dict.get(_id, None))
                curr_masks[_id] = set_bit(curr_masks.get(_id, 0), i)
                logging.debug('%s: got from source[%d]', _id, i)
                if is_same_bitmask(curr_masks[_id],
                                self.masks_index.get(_id, curr_masks[_id]),
                                self.sources_mask):
                    logging.debug('%s: no more data is expected from sources - '
                                  'yield', _id)
                    temp = buffer_dict[_id]
                    del buffer_dict[_id]
                    del curr_masks[_id]
                    yield temp
