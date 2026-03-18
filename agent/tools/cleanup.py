import glob
import shutil
import os
import tempfile


def run() -> str:
    deleted = []
    errors = []

    # Fixed path
    logs_temp = os.path.join("logs", "temp")
    if os.path.exists(logs_temp):
        try:
            shutil.rmtree(logs_temp)
            deleted.append(logs_temp)
        except Exception as e:
            errors.append(f"{logs_temp}: {e}")

    # Glob-expanded paths — cross-platform temp directory
    tmp_dir = tempfile.gettempdir()
    for path in glob.glob(os.path.join(tmp_dir, "phantom_*")):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            deleted.append(path)
        except Exception as e:
            errors.append(f"{path}: {e}")

    if errors:
        return f"⚠️ Cleanup partial — deleted: {deleted}, errors: {errors}"
    if deleted:
        return f"✅ Temporary files deleted: {deleted}"
    return "✅ Nothing to clean"


TOOL_SPEC = {
    "name": "cleanup_temp",
    "description": "Secure cleanup of the temp files (ghost mode)",
    "input_schema": {"type": "object", "properties": {}},
}
