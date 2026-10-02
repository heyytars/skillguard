import json
import subprocess

def run_case(cmd, cwd):
    # Runs a test command built from a literal list, then records the result.
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    with open("results.json", "w") as f:
        json.dump({"returncode": proc.returncode, "stdout": proc.stdout}, f, indent=1)
    return proc.returncode
