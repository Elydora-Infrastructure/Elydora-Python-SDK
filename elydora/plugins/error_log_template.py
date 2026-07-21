"""Bounded error-log primitives embedded in generated audit hooks."""

ERROR_LOG_RUNTIME = r"""
MAX_ERROR_ENTRY_BYTES = 64 * 1024
ERROR_LOG_LOCK_ATTEMPTS = 50
ERROR_LOG_LOCK_DELAY_SECONDS = 0.01


def validate_error_log_metadata(metadata, file_path, label):
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(label + " path is not a physical file: " + file_path)
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(label + " permissions are too broad: " + file_path)


def open_error_log(file_path, label):
    for _attempt in range(3):
        try:
            before = os.lstat(file_path)
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(file_path, flags, 0o600)
            except FileExistsError:
                continue
            try:
                validate_error_log_metadata(os.fstat(descriptor), file_path, label)
                return descriptor
            except Exception:
                os.close(descriptor)
                raise

        if stat.S_ISLNK(before.st_mode):
            raise ValueError(label + " path is not a physical file: " + file_path)
        validate_error_log_metadata(before, file_path, label)
        flags = os.O_RDWR | os.O_APPEND
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(file_path, flags)
        try:
            after = os.fstat(descriptor)
            validate_error_log_metadata(after, file_path, label)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise OSError(label + " changed while opening: " + file_path)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise
    raise OSError(label + " changed repeatedly while opening: " + file_path)


def lock_error_log(descriptor, file_path, label):
    import errno

    if os.name == "nt":
        import msvcrt

        lock_kind = "windows"
        lock = lambda: msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        retry_errors = {
            errno.EACCES,
            errno.EAGAIN,
            getattr(errno, "EDEADLK", -1),
        }
    else:
        import fcntl

        lock_kind = "posix"
        lock = lambda: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        retry_errors = {errno.EACCES, errno.EAGAIN}
    for attempt in range(ERROR_LOG_LOCK_ATTEMPTS):
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            lock()
            return lock_kind
        except OSError as error:
            if error.errno not in retry_errors:
                raise
            if attempt + 1 == ERROR_LOG_LOCK_ATTEMPTS:
                raise TimeoutError(
                    label + " remained locked: " + file_path
                ) from error
            time.sleep(ERROR_LOG_LOCK_DELAY_SECONDS)
    raise AssertionError("unreachable")


def unlock_error_log(descriptor, lock_kind):
    if lock_kind == "windows":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


def write_all(descriptor, value, label, file_path):
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise OSError(label + " write made no progress: " + file_path)
        offset += written


def bounded_error_message(error):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prefix = (timestamp + " [elydora-hook] ").encode("ascii")
    detail = repr(error).encode("utf-8", errors="backslashreplace")
    suffix = b"\n"
    if len(prefix) + len(detail) + len(suffix) <= MAX_ERROR_ENTRY_BYTES:
        return prefix + detail + suffix
    marker = b"... [error entry truncated]\n"
    available = MAX_ERROR_ENTRY_BYTES - len(prefix) - len(marker)
    detail = detail[:available].decode("utf-8", errors="ignore").encode("utf-8")
    return prefix + detail + marker


def error_log_rollover_notice(max_bytes):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return (
        "[elydora-hook] Error log truncated at the "
        + str(max_bytes)
        + "-byte limit at "
        + timestamp
        + "\n"
    ).encode("ascii")


def append_bounded_error_log(file_path, label, encoded, max_bytes):
    if len(encoded) > max_bytes:
        raise ValueError(label + " entry exceeds the size limit: " + file_path)
    descriptor = open_error_log(file_path, label)
    lock_kind = None
    try:
        lock_kind = lock_error_log(descriptor, file_path, label)
        metadata = os.fstat(descriptor)
        validate_error_log_metadata(metadata, file_path, label)
        if metadata.st_size + len(encoded) > max_bytes:
            value = error_log_rollover_notice(max_bytes) + encoded
            if len(value) > max_bytes:
                raise ValueError(label + " entry exceeds the size limit: " + file_path)
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
        else:
            value = encoded
            os.lseek(descriptor, 0, os.SEEK_END)
        write_all(descriptor, value, label, file_path)
        os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
    finally:
        try:
            if lock_kind is not None:
                unlock_error_log(descriptor, lock_kind)
        finally:
            os.close(descriptor)
"""

__all__ = ["ERROR_LOG_RUNTIME"]
