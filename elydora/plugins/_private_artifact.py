"""Identity-bound private artifacts for transactional file boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
from typing import Optional
from uuid import uuid4

from ._managed_files import DirectorySnapshot, FileSnapshot
from ._pinned_directory import PinnedDirectory


def _remove_posix_private_directory(parent_descriptor: int, name: str) -> None:
    """Remove one empty child through the platform's native *at semantics."""
    if os.rmdir not in os.supports_dir_fd:
        raise OSError("Host does not support identity-bound directory removal")
    os.rmdir(name, dir_fd=parent_descriptor)


def reserve_private_path(
    directory: PinnedDirectory,
    file_path: str,
    label: str,
) -> FileSnapshot:
    """Reserve one unpredictable name with exclusive physical-file creation."""
    name = directory.name_for(file_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = directory.open_file(name, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"{label} reservation is not a physical file: {file_path}")
        directory.chmod_descriptor(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    directory.sync()
    snapshot = directory.read_file(name, f"{label} reservation", 0)
    if snapshot is None or snapshot.contents:
        raise OSError(f"{label} reservation changed after creation: {file_path}")
    return snapshot


def _open_container(
    parent: PinnedDirectory,
    name: str,
    path: str,
    label: str,
    expected: DirectorySnapshot,
) -> PinnedDirectory:
    if os.name == "nt":
        return PinnedDirectory.open(path, label, expected)
    if parent.descriptor is None:
        raise OSError(f"Pinned {parent.label} is closed")
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        metadata = os.fstat(descriptor)
        after = parent.stat_file(name)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or DirectorySnapshot(metadata.st_dev, metadata.st_ino) != expected
            or (after.st_dev, after.st_ino) != (expected.device, expected.inode)
        ):
            raise OSError(f"Private {label} changed while pinning: {path}")
        pinned = PinnedDirectory(path, label, expected, descriptor, False)
        descriptor = -1
        return pinned
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reported_entry_path(container: PinnedDirectory) -> str:
    if os.name == "nt" or container.path_bound or container.descriptor is None:
        return container.path_for("entry")
    for descriptor_path in (
        f"/proc/self/fd/{container.descriptor}",
        f"/dev/fd/{container.descriptor}",
    ):
        resolved = os.path.realpath(descriptor_path)
        if os.path.isabs(resolved) and resolved != descriptor_path:
            return os.path.join(resolved, "entry")
    return container.path_for("entry")


def _create_container(
    parent: PinnedDirectory,
    basename: str,
    label: str,
) -> tuple[str, PinnedDirectory]:
    name = f".{basename}.{uuid4().hex}.elydora-quarantine"
    path = parent.path_for(name)
    try:
        if os.name == "nt":
            os.mkdir(path, 0o700)
        else:
            if parent.descriptor is None:
                raise OSError(f"Pinned {parent.label} is closed")
            os.mkdir(name, 0o700, dir_fd=parent.descriptor)
    except OSError as error:
        raise OSError(f"Create private {label} at {path}: {error}") from error
    metadata = parent.stat_file(name)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise OSError(f"Private {label} is not a physical directory: {path}")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise OSError(f"Private {label} has an unexpected mode: {path}")
    snapshot = DirectorySnapshot(metadata.st_dev, metadata.st_ino)
    return path, _open_container(parent, name, path, label, snapshot)


def _move_into_container(
    parent: PinnedDirectory,
    source_name: str,
    container: PinnedDirectory,
) -> None:
    if os.name == "nt":
        os.rename(parent.path_for(source_name), container.path_for("entry"))
        return
    if parent.descriptor is None or container.descriptor is None:
        raise OSError("Pinned private artifact directory is closed")
    os.rename(
        source_name,
        "entry",
        src_dir_fd=parent.descriptor,
        dst_dir_fd=container.descriptor,
    )


def _link_from_container(
    container: PinnedDirectory,
    parent: PinnedDirectory,
    destination_name: str,
) -> None:
    if os.name == "nt":
        os.link(container.path_for("entry"), parent.path_for(destination_name))
        return
    if container.descriptor is None or parent.descriptor is None:
        raise OSError("Pinned private artifact directory is closed")
    os.link(
        "entry",
        destination_name,
        src_dir_fd=container.descriptor,
        dst_dir_fd=parent.descriptor,
        follow_symlinks=False,
    )


@dataclass
class QuarantinedFile:
    parent: PinnedDirectory
    original_path: str
    label: str
    container_path: str
    container: PinnedDirectory
    active: bool = True

    @classmethod
    def capture(
        cls,
        parent: PinnedDirectory,
        file_path: str,
        label: str,
        *,
        require_parent_path: bool = True,
    ) -> "QuarantinedFile":
        if require_parent_path:
            parent.assert_path_stable("transaction")
        name = parent.name_for(file_path)
        container_path, container = _create_container(parent, name, label)
        try:
            _move_into_container(parent, name, container)
        except Exception:
            container.close()
            try:
                if os.name == "nt":
                    os.rmdir(container_path)
                else:
                    assert parent.descriptor is not None
                    _remove_posix_private_directory(
                        parent.descriptor,
                        parent.name_for(container_path),
                    )
            except OSError:
                pass
            raise
        captured = cls(parent, file_path, label, container_path, container)
        if require_parent_path:
            try:
                parent.assert_path_stable("transaction")
            except Exception as boundary_error:
                try:
                    captured.restore()
                except Exception as restore_error:
                    preserved = (
                        captured.preserve()
                        if captured.active
                        else file_path
                    )
                    raise OSError(
                        f"{boundary_error}; {label} preserved at {preserved}; "
                        f"restoration failed: {restore_error}"
                    ) from boundary_error
                raise
        return captured

    @property
    def entry_path(self) -> str:
        return _reported_entry_path(self.container)

    def text_snapshot(self, maximum_bytes: int) -> Optional[FileSnapshot]:
        return self.container.read_file("entry", self.label, maximum_bytes)

    def link(self, destination_path: Optional[str] = None) -> None:
        """Install a no-clobber link while retaining the private identity."""
        if not self.active:
            raise OSError(f"Private {self.label} capture is closed")
        target = self.original_path if destination_path is None else destination_path
        destination_name = self.parent.name_for(target)
        _link_from_container(self.container, self.parent, destination_name)
        linked = self.parent.stat_file(destination_name)
        captured = self.container.stat_file("entry")
        if (linked.st_dev, linked.st_ino) != (captured.st_dev, captured.st_ino):
            raise OSError(f"{self.label} changed while restoring: {target}")

    def restore(self, destination_path: Optional[str] = None) -> None:
        self.link(destination_path)
        self.discard()

    def discard(self) -> None:
        if not self.active:
            return
        self.container.remove_file("entry")
        self.active = False
        self._close_empty_container()

    def preserve(self) -> str:
        entry_path = self.entry_path
        if self.container.descriptor is not None:
            self.container.close()
        self.active = False
        return entry_path

    def _close_empty_container(self) -> None:
        if self.container.list_names():
            raise OSError(
                f"Private {self.label} is not empty: {self.container_path}"
            )
        snapshot = self.container.snapshot
        self.container.close()
        name = self.parent.name_for(self.container_path)
        current = self.parent.stat_file(name)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (snapshot.device, snapshot.inode)
        ):
            raise OSError(
                f"Private {self.label} changed before cleanup: "
                f"{self.container_path}"
            )
        if os.name == "nt":
            os.rmdir(self.container_path)
        else:
            if self.parent.descriptor is None:
                raise OSError(f"Pinned {self.parent.label} is closed")
            _remove_posix_private_directory(self.parent.descriptor, name)


__all__ = ["QuarantinedFile", "reserve_private_path"]
