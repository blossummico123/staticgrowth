import os
import subprocess

# 1. HARDCODED SECRETS
OPENAI_API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# 2. COMMAND INJECTION
def ping_user_machine(ip_address):
    # Vulnerable to: 8.8.8.8; rm -rf /
    os.system(f"ping -c 4 {ip_address}")

# 3. PATH TRAVERSAL
def read_user_profile(username):
    # Vulnerable to: ../../../etc/passwd
    with open("/app/profiles/" + username, "r") as f:
        return f.read()

# 4. INSECURE DESERIALIZATION
def load_config(yaml_string):
    import yaml
    # Should be yaml.safe_load()
    return yaml.load(yaml_string)
