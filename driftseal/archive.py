import io
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .safety import MAX_DOWNLOAD, MAX_EXTRACTED, MAX_FILE, MAX_FILES, Rejected

TEXT_EXTENSIONS = {
    ".json",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".py",
    ".md",
    ".txt",
    ".toml",
    ".cfg",
    ".ini",
    ".sh",
    ".lock",
    ".yaml",
    ".yml",
}
SECRET_NAMES = {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json", ".npmrc", ".pypirc"}


def safe_name(name):
    p = PurePosixPath(name)
    if (
        not name
        or len(name) > 300
        or "\\" in name
        or ":" in name
        or any(ord(c) < 32 for c in name)
        or p.is_absolute()
        or ".." in p.parts
    ):
        raise Rejected("Unsafe archive path")
    return p


def relevant(name):
    p = PurePosixPath(name)
    return (
        p.name not in SECRET_NAMES
        and not p.name.startswith(".env")
        and p.suffix.lower() not in {".pem", ".key", ".p12"}
        and (p.suffix.lower() in TEXT_EXTENSIONS or p.name in {"SKILL.md", "Dockerfile", "PKG-INFO", "METADATA"})
    )


def unpack(data):
    """Validate every entry; materialize only bounded text in an isolated directory, then destroy it."""
    if len(data) > MAX_DOWNLOAD:
        raise Rejected("Artifact exceeds limit")
    files, seen, total, count = {}, set(), 0, 0
    with tempfile.TemporaryDirectory(prefix="driftseal-") as tmp:
        root = Path(tmp)

        def consume(name, size, stream, directory=False):
            nonlocal total, count
            path = safe_name(name)
            count += 1
            total += size
            if count > MAX_FILES or total > MAX_EXTRACTED:
                raise Rejected("Archive file count or decompression limit exceeded")
            normalized = str(path)
            if normalized in seen:
                raise Rejected("Duplicate archive member")
            seen.add(normalized)
            if directory:
                return
            if size > MAX_FILE:
                raise Rejected("Archive member exceeds 1 MiB")
            content = stream.read(MAX_FILE + 1)
            if len(content) != size:
                raise Rejected("Archive size mismatch")
            if relevant(normalized):
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as out:
                    out.write(content)
                if b"\x00" not in content:
                    files[normalized] = content.decode("utf-8", errors="replace")

        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for member in archive.infolist():
                        mode = member.external_attr >> 16
                        if (
                            stat.S_ISLNK(mode)
                            or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                            or member.flag_bits & 1
                        ):
                            raise Rejected("Archive links, special files and encryption are forbidden")
                        if member.file_size > max(1024 * 1024, member.compress_size * 150):
                            raise Rejected("Compression ratio limit exceeded")
                        with archive.open(member) as stream:
                            consume(member.filename, member.file_size, stream, member.is_dir())
            else:
                # Streaming prevents unbounded member-list allocation.
                with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as archive:
                    for member in archive:
                        if not (member.isfile() or member.isdir()) or member.sparse:
                            raise Rejected("Archive links, sparse files and special files are forbidden")
                        stream = archive.extractfile(member) if member.isfile() else io.BytesIO()
                        with stream:
                            consume(member.name, member.size, stream, member.isdir())
            if total > max(1024 * 1024, len(data) * 150):
                raise Rejected("Compression ratio limit exceeded")
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, RuntimeError) as exc:
            raise Rejected("Invalid or unsafe archive") from exc
    return files, {
        "downloaded_bytes": len(data),
        "extracted_bytes": total,
        "file_count": count,
        "analysed_files": len(files),
    }
