# VIP Pizza Shop Version Information

Current Version: 0.1.0
Release Date: 2025-02-28
Version Hash: 7e9d4f11a8b3c5e6d2f0g9h8i7j6k5l4

## Version Check
To verify you have the correct version:

1. This file should be located at: `VERSION.md`
2. The version hash should match: `7e9d4f11a8b3c5e6d2f0g9h8i7j6k5l4`
3. File structure should include:
   ```
   unsecured-crud/
   ├── app.py
   ├── requirements.txt
   ├── README.md
   ├── CHANGELOG.md
   ├── VERSION.md
   ├── static/
   ├── templates/
   └── users.db
   ```

## Verification Script
```python
import hashlib
import os

def verify_version():
    files = ['app.py', 'requirements.txt', 'README.md']
    checksums = ''
    
    for file in sorted(files):
        if os.path.exists(file):
            with open(file, 'rb') as f:
                checksums += hashlib.md5(f.read()).hexdigest()
    
    return hashlib.sha256(checksums.encode()).hexdigest()[:32]

if __name__ == '__main__':
    print(f"Version Hash: {verify_version()}")
```

## Update Instructions
1. Check CHANGELOG.md for latest changes
2. Follow update instructions in CHANGELOG.md
3. Run version verification script
4. Report any discrepancies to your instructor
