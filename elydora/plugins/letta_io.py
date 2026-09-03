"""Strict Letta Code managed runtime inspection."""

from __future__ import annotations

from typing import List, Tuple

from ._runtime import expected_runtime_scripts, runtime_contract_exists
from ._strict_json import JsonObject
from .letta_contract import AGENT_KEY, LettaRuntimeContract


def _expected_scripts(agent_id: str, config: JsonObject) -> Tuple[str, str]:
    return expected_runtime_scripts(AGENT_KEY, agent_id, config, fail_closed=True)


def letta_runtime_files_exist(contracts: List[LettaRuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(contract, AGENT_KEY, "Letta Code", _expected_scripts)
        for contract in contracts
    )
