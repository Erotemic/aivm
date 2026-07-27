"""Credential-domain models that are not part of the config-store schema."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GitRepository:
    """Normalized repository identity for a supported Git forge."""

    host: str
    owner: str
    name: str
    source_url: str = field(default='', compare=False, repr=False)

    @property
    def canonical(self) -> str:
        return f'{self.host.lower()}/{self.owner.lower()}/{self.name.lower()}'

    @property
    def display(self) -> str:
        return f'{self.host}/{self.owner}/{self.name}'

    @property
    def path(self) -> str:
        return f'{self.owner}/{self.name}'

    @property
    def gh_repo_arg(self) -> str:
        if self.host.lower() == 'github.com':
            return f'{self.owner}/{self.name}'
        return self.display

    @property
    def ssh_url(self) -> str:
        return f'git@{self.host}:{self.owner}/{self.name}.git'

    @property
    def https_url(self) -> str:
        return f'https://{self.host}/{self.owner}/{self.name}.git'

    @property
    def verification_url(self) -> str:
        return self.source_url or self.https_url


@dataclass(frozen=True)
class ProviderDeployKey:
    """Deploy-key metadata returned by a forge backend."""

    key_id: str
    key: str
    title: str
    read_only: bool
