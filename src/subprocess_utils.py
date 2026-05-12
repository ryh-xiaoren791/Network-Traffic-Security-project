import locale
import subprocess
from collections.abc import Sequence


def decode_process_output(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if not data:
        return ""
    tried: set[str] = set()
    preferred = locale.getpreferredencoding(False) or "utf-8"
    for encoding in ("utf-8", preferred, "gbk", "cp936", "utf-16-le"):
        normalized = str(encoding or "").strip().lower()
        if not normalized or normalized in tried:
            continue
        tried.add(normalized)
        try:
            return data.decode(encoding)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def run_command_capture(command: Sequence[str], **kwargs) -> tuple[subprocess.CompletedProcess[bytes], str, str]:
    result = subprocess.run(command, capture_output=True, text=False, check=False, **kwargs)
    stdout_text = decode_process_output(result.stdout)
    stderr_text = decode_process_output(result.stderr)
    return result, stdout_text, stderr_text
