"""Data contracts for fail-fast transactional file changes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from ._managed_files import DirectorySnapshot, FileSnapshot, MAX_SOURCE_BYTES
from ._pinned_directory import PinnedDirectory


@dataclass(frozen=True)
class FileChange:
    file_path: str
    label: str
    original: Optional[str]
    next_source: Optional[str]
    mode: int
    original_mode: Optional[int]
    original_device: Optional[int]
    original_inode: Optional[int]
    maximum_bytes: int


@dataclass(frozen=True)
class FilePrecondition:
    file_path: str
    label: str
    original: Optional[FileSnapshot]
    maximum_bytes: int = MAX_SOURCE_BYTES


@dataclass(frozen=True)
class DirectoryPrecondition:
    directory_path: str
    label: str
    original: Optional[DirectorySnapshot]
    created: bool = False


TransactionPreconditions = Tuple[
    Sequence[FilePrecondition], Sequence[DirectoryPrecondition], str
]
DirectoryMap = Dict[str, PinnedDirectory]


@dataclass
class StagedChange:
    change: FileChange
    directory: PinnedDirectory
    temporary_path: Optional[str]
    temporary_snapshot: Optional[FileSnapshot]
    temporary_reservation: Optional[FileSnapshot]
    rollback_path: Optional[str]
    rollback_snapshot: Optional[FileSnapshot]
    rollback_reservation: Optional[FileSnapshot]
    preconditions: TransactionPreconditions
    directories: DirectoryMap
    committed_snapshot: Optional[FileSnapshot] = None
    committed: bool = False
