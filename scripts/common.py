#!/usr/bin/env python3
from typing import Generator
from abc import ABC, abstractmethod
import os
import logging

from git import Repo
from model import KernelCve


def is_json(path: str) -> bool:
    return path.endswith('.json')


def listdir_against(folder: str) -> list[str]:
    return [ os.path.join(folder, file) for file in os.listdir(folder) ]


class SomeVulnerabilitiesSource(ABC):
    @abstractmethod
    def to_kernel_cves(self) -> Generator[KernelCve, None, None]:
        raise NotImplementedError


    @abstractmethod
    def identifiers(self) -> set[str]:
        raise NotImplementedError


class GitBasedVulnerabilitiesSource(SomeVulnerabilitiesSource):
    def __init__(self, repository: Repo):
        self.repo = repository
        self.repo_workdir = self.repo.working_tree_dir
        origin = self.repo.remote()
        logging.info('pulling updates from %s...', origin.url)
        origin.pull()
        logging.info('successfully pulled')


    @classmethod
    @abstractmethod
    def repo_source(cls) -> str:
        raise NotImplementedError


    @classmethod
    def from_bare_path(cls, repository_path: str):
        return cls(Repo(repository_path))


    @classmethod
    def clone_to(cls, storage: str):
        logging.info('cloning to %s...', storage)
        repo = Repo.clone_from(cls.repo_source())
        logging.info('successfully cloned to %s', repo.working_tree_dir)
        return cls(repo)
