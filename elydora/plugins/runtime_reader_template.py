"""Protected runtime-file primitives embedded in generated hook scripts."""

PROTECTED_RUNTIME_READER = r"""
MAX_PROTECTED_SECRET_BYTES = 64 * 1024
MAX_PROTECTED_CONFIG_BYTES = 512 * 1024
MAX_PROTECTED_LOG_BYTES = 2 * 1024 * 1024


def validate_protected_metadata(metadata, file_path, label, max_bytes):
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(label + " path is not a physical file: " + file_path)
    if metadata.st_size > max_bytes:
        raise ValueError(label + " exceeds the size limit: " + file_path)
    if os.name != "nt" and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(label + " permissions are too broad: " + file_path)


def inspect_protected_file(file_path, label, max_bytes):
    metadata = os.lstat(file_path)
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(label + " path is not a physical file: " + file_path)
    validate_protected_metadata(metadata, file_path, label, max_bytes)
    return metadata


def read_protected_file(
    file_path,
    label,
    max_bytes=MAX_PROTECTED_SECRET_BYTES,
):
    before = inspect_protected_file(file_path, label, max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(file_path, flags)
    try:
        after = os.fstat(descriptor)
        validate_protected_metadata(after, file_path, label, max_bytes)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise OSError(label + " changed while opening: " + file_path)
        with os.fdopen(descriptor, "rb") as file:
            descriptor = -1
            value = file.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > max_bytes:
        raise ValueError(label + " exceeds the size limit: " + file_path)
    return value


def open_protected_append(file_path, label, max_bytes):
    for _attempt in range(3):
        try:
            before = inspect_protected_file(file_path, label, max_bytes)
        except FileNotFoundError:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(file_path, flags, 0o600)
            except FileExistsError:
                continue
            try:
                validate_protected_metadata(
                    os.fstat(descriptor),
                    file_path,
                    label,
                    max_bytes,
                )
                return descriptor
            except Exception:
                os.close(descriptor)
                raise

        flags = os.O_WRONLY | os.O_APPEND
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(file_path, flags)
        try:
            after = os.fstat(descriptor)
            validate_protected_metadata(after, file_path, label, max_bytes)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise OSError(label + " changed while opening: " + file_path)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise
    raise OSError(label + " changed repeatedly while opening: " + file_path)


def append_protected_text(
    file_path,
    label,
    text,
    max_bytes=MAX_PROTECTED_LOG_BYTES,
):
    encoded = text.encode("utf-8")
    descriptor = open_protected_append(file_path, label, max_bytes)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size + len(encoded) > max_bytes:
            raise ValueError(label + " exceeds the size limit: " + file_path)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError(label + " write made no progress: " + file_path)
            offset += written
        os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def write_protected_json(file_path, label, value):
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PROTECTED_CONFIG_BYTES:
        raise ValueError(label + " exceeds the size limit: " + file_path)
    temporary_path = (
        file_path
        + "."
        + str(os.getpid())
        + "."
        + os.urandom(8).hex()
        + ".tmp"
    )
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            descriptor = -1
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        try:
            inspect_protected_file(
                file_path,
                label,
                MAX_PROTECTED_CONFIG_BYTES,
            )
        except FileNotFoundError:
            pass
        os.replace(temporary_path, file_path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.remove(temporary_path)
        except FileNotFoundError:
            pass
"""
