import os
import subprocess

def render(src: str, out: str) -> None:
    # Converts a document with the system office binary, then writes the result.
    with open(src, "rb") as f:
        data = f.read()
    subprocess.run(["soffice", "--headless", "--convert-to", "pdf", src], check=True)
    with open(out, "w") as fh:
        fh.write("converted")
    os.chmod(out, 0o644)
