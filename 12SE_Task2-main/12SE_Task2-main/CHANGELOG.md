# Changelog

All notable changes to the VIP Pizza Shop will be documented in this file.

## [0.1.0] - 2025-02-28

### Added
- Initial release
- Basic user authentication system
- Pizza ordering functionality
- Admin interface
- User registration
- Basic cart functionality
- README.md with student instructions
- Requirements.txt with dependencies
- Security report template

### Known Issues
- Some features may be intentionally vulnerable for educational purposes
- Database may need to be recreated if schema changes

## [0.2.0] - 2025-02-28

### Added
- Added price formatting in templates to show consistent decimal places
- Added proper error handling for file uploads
- Added backup system for pizza data
- Added proper validation for pizza prices
- Added PDF documentation in uploads folder

### Changed
- Improved admin interface with better form validation
- Enhanced pizza deletion functionality to handle edge cases
- Simplified pizza data management system
- Improved error handling in admin routes
- Fixed issue with deleting the last pizza in admin panel
- Streamlined pizza data backup system

### Fixed
- Fixed price display formatting in templates
- Fixed file upload validation and error handling
- Fixed pizza deletion issues in admin panel
- Fixed data persistence issues with pizza.json

### Known Issues
- Some features may be intentionally vulnerable for educational purposes
- Database may need to be recreated if schema changes

## [0.3.0] - 2025-02-28 19:18


### Security Analysis
- Completed thorough security audit of all application components
- Identified critical authentication vulnerabilities


### Known Issues
- All previously identified security vulnerabilities remain present
- Some features remain intentionally vulnerable for educational purposes
- Database schema unchanged

## How to Update

1. Check your current version:
```bash
python check_version.py
```

2. Update your local copy:
```bash
git pull origin main
```

3. Install any new dependencies:
```bash
pip install -r requirements.txt
```

## Version Verification
Each release includes a VERSION.md file with a unique hash. You can verify you have the correct version by comparing the hash in your VERSION.md with the official hash.
