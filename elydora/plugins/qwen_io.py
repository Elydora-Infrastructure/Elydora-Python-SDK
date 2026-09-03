"""Strict Qwen Code managed runtime inspection."""

from __future__ import annotations

from typing import List, Tuple

from ._runtime import expected_runtime_scripts, runtime_contract_exists
from ._strict_json import JsonObject
from .qwen_contract import AGENT_KEY, QwenRuntimeContract


def _expected_scripts(agent_id: str, config: JsonObject) -> Tuple[str, str]:
    return expected_runtime_scripts(AGENT_KEY, agent_id, config)


def qwen_runtime_files_exist(contracts: List[QwenRuntimeContract]) -> bool:
    return any(
        runtime_contract_exists(contract, AGENT_KEY, "Qwen Code", _expected_scripts)
        for contract in contracts
    )
