"""Protected runtime-file reader embedded in generated hook scripts."""

PROTECTED_RUNTIME_READER = r'''
MAX_PROTECTED_SECRET_BYTES = 64 * 1024
MAX_PROTECTED_CONFIG_BYTES = 512 * 1024


def read_protected_file(
    file_path,
    label,
    max_bytes=MAX_PROTECTED_SECRET_BYTES,
    require_private_permissions=True,
):
    before = os.lstat(file_path)
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ValueError(label + " path is not a physical file: " + file_path)
    if before.st_size > max_bytes:
        raise ValueError(label + " exceeds the size limit: " + file_path)
    if require_private_permissions and os.name != "nt" and before.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(label + " permissions are too broad: " + file_path)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(file_path, flags)
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise ValueError(label + " path is not a physical file: " + file_path)
        if after.st_size > max_bytes:
            raise ValueError(label + " exceeds the size limit: " + file_path)
        if require_private_permissions and os.name != "nt" and after.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(label + " permissions are too broad: " + file_path)
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
'''
