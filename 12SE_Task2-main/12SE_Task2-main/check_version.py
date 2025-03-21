import hashlib
import os
import json
from datetime import datetime

def verify_version():
    """Verify the current version of the application."""
    files = ['app.py', 'requirements.txt', 'README.md']
    checksums = ''
    
    # Calculate checksums of core files
    for file in sorted(files):
        if os.path.exists(file):
            with open(file, 'rb') as f:
                checksums += hashlib.md5(f.read()).hexdigest()
    
    current_hash = hashlib.sha256(checksums.encode()).hexdigest()[:32]
    
    # Read version information
    with open('VERSION.md', 'r') as f:
        version_content = f.read()
        version_hash = None
        for line in version_content.split('\n'):
            if 'Version Hash:' in line:
                version_hash = line.split(':')[1].strip()
                break
    
    # Compare versions
    if version_hash and current_hash == version_hash:
        print("✅ Your version is up to date!")
        print(f"Current Version Hash: {current_hash}")
    else:
        print("❌ Your version is outdated or modified!")
        print(f"Expected Hash: {version_hash}")
        print(f"Current Hash: {current_hash}")
        print("\nPlease update your copy following the instructions in CHANGELOG.md")

if __name__ == '__main__':
    verify_version()
