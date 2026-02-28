"""Abstract base class for agent plugins."""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import Any, Dict

if sys.version_info >= (3, 11):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


class InstallConfig(TypedDict, total=False):
    org_id: str
    agent_id: str
    private_key: str
    kid: str
    token: str
    base_url: str
    guard_script_path: str


class PluginStatus(TypedDict):
    installed: bool
    agent: str
    details: str


class AgentPlugin(ABC):
    """Base class for all agent plugins."""

    @abstractmethod
    def install(self, config: InstallConfig) -> None:
        """Install the Elydora hook for this agent."""

    @abstractmethod
    def uninstall(self) -> None:
        """Remove the Elydora hook for this agent."""

    @abstractmethod
    def status(self) -> PluginStatus:
        """Check whether the Elydora hook is installed for this agent."""
