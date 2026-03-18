import os
import platform
import subprocess


def _default_wordlist() -> str:
    """Return a sensible default wordlist path depending on the OS."""
    if platform.system() == "Windows":
        # Common location when SecLists is cloned alongside the project
        return os.path.join("wordlists", "directory-list-2.3-medium.txt")
    return "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"


def run(url: str, wordlist: str = "") -> str:
    if not wordlist:
        wordlist = _default_wordlist()

    output_path = os.path.join("logs", "ffuf.json")
    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-mc", "200,204,301,302,307,403",
        "-o", output_path, "-of", "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return f"⚠️ ffuf exited with code {result.returncode}\n{result.stderr[-300:]}"
        return f"✅ ffuf terminé – résultats dans {output_path}"
    except Exception as e:
        return f"❌ Erreur ffuf : {str(e)}"


TOOL_SPEC = {
    "name": "run_ffuf",
    "description": "Fuzzing directories/files ultra-rapide",
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "wordlist": {"type": "string"},
        },
        "required": ["url"],
    },
}
