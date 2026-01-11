#!/usr/bin/env python3
"""Production Readiness Check for Admin Dashboard"""

import os
import sys
import re

def check_production_readiness():
    issues = []
    warnings = []
    
    # Check admin_dashboard.py
    try:
        with open('admin_dashboard.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Check for hardcoded secrets
            if re.search(r'secret_key\s*=\s*["\'].{10,}["\']', content, re.IGNORECASE):
                if 'os.environ' not in content or 'SECRET_KEY' not in content:
                    warnings.append('⚠️  Potential hardcoded secret key')
            
            # Check for debug=True
            if 'debug=True' in content:
                issues.append('❌ Debug mode enabled in code')
            
            # Check for Flask dev server
            if 'app.run(' in content and 'if __name__' in content:
                warnings.append('⚠️  Flask dev server in main (OK if WSGI factory exists)')
            
            # Check for WSGI factory
            if 'def create_wsgi_app(' in content:
                print('✅ WSGI factory function exists')
            else:
                issues.append('❌ No create_wsgi_app() function found')
            
            # Check for CSRF protection
            if 'csrf' not in content.lower() and '@app.route' in content:
                warnings.append('⚠️  No CSRF protection detected')
            
            # Check for TLS support
            if 'ssl_context' in content or 'tls' in content:
                print('✅ TLS support present')
            else:
                warnings.append('⚠️  No TLS configuration found')
            
            # Check for password hashing
            if 'check_password_hash' in content or 'generate_password_hash' in content:
                print('✅ Password hashing implemented')
            else:
                issues.append('❌ No password hashing found')
            
            # Check for login protection
            if '@login_required' in content:
                print('✅ Login protection decorator used')
            else:
                issues.append('❌ No @login_required decorator')
    
    except FileNotFoundError:
        issues.append('❌ admin_dashboard.py not found')
    
    # Check for required files
    required_files = [
        'admin_dashboard.py',
        'policy_engine.py',
        'templates/base.html',
        'templates/login.html',
        'templates/dashboard.html',
        'templates/paths.html',
        'templates/drivers.html',
    ]
    
    missing_files = []
    for f in required_files:
        if not os.path.exists(f):
            missing_files.append(f)
    
    if missing_files:
        issues.append(f'❌ Missing files: {", ".join(missing_files)}')
    else:
        print('✅ All required template files exist')
    
    # Check environment variables
    env_vars = ['ADMIN_USERNAME', 'ADMIN_PASSWORD', 'ADMIN_SECRET_KEY']
    missing_env = [v for v in env_vars if not os.environ.get(v)]
    
    if missing_env:
        warnings.append(f'⚠️  Missing env vars (runtime check): {", ".join(missing_env)}')
    else:
        print('✅ All required environment variables set')
    
    # Check for waitress/gunicorn
    try:
        import waitress
        print('✅ Waitress installed (production WSGI server)')
    except ImportError:
        warnings.append('⚠️  Waitress not installed (install with: pip install waitress)')
    
    # Summary
    print('\n' + '='*60)
    print('PRODUCTION READINESS SUMMARY')
    print('='*60)
    
    if issues:
        print('\n🚨 CRITICAL ISSUES:')
        for issue in issues:
            print(f'  {issue}')
    
    if warnings:
        print('\n⚠️  WARNINGS:')
        for warning in warnings:
            print(f'  {warning}')
    
    if not issues and not warnings:
        print('\n✅ ALL CHECKS PASSED - PRODUCTION READY')
        return 0
    elif not issues:
        print('\n✅ No critical issues, but review warnings')
        return 0
    else:
        print('\n❌ CRITICAL ISSUES FOUND - NOT PRODUCTION READY')
        return 1

if __name__ == '__main__':
    sys.exit(check_production_readiness())
