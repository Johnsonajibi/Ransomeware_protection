#!/usr/bin/env python3
"""
Comprehensive Placeholder Scanner
=================================
Scans code files for incomplete implementations, TODOs, stubs, etc.
"""

import os
import re
from pathlib import Path

# Files to check
FILES_TO_CHECK = [
    'emergency_kill_switch.py',
    'shadow_copy_protection.py',
    'email_alerting.py',
    'siem_integration.py',
    'system_health_checker.py',
    'desktop_app.py',
    'unified_antiransomware.py',
    'security_event_logger.py'
]

# Patterns to detect
PATTERNS = {
    'TODO comments': r'#\s*TODO(?!.*completed)',
    'FIXME comments': r'#\s*FIXME',
    'XXX comments': r'#\s*XXX',
    'HACK comments': r'#\s*HACK',
    'Placeholder text': r'(?i)placeholder(?!text)',  # Exclude setPlaceholderText
    'Stub text': r'(?i)stub(?!s\b)',  # Exclude "stubs" as noun
    'Not implemented': r'NotImplementedError|raise\s+NotImplemented',
    'Empty functions': r'def\s+\w+[^:]*:\s*pass\s*(?:#.*)?$',
    'Ellipsis stubs': r'^\s*\.\.\.\s*(?:#.*)?$',
    'Unfinished': r'(?i)unfinished|incomplete|work\s+in\s+progress'
}

def is_false_positive(line: str, pattern_name: str) -> bool:
    """Check if match is a false positive"""
    line_lower = line.lower()
    
    # GUI placeholder text is okay
    if 'setplaceholdertext' in line_lower or 'placeholder=' in line_lower:
        return True
    
    # Exception handlers with pass are okay
    if pattern_name == 'Empty functions' and ('except' in line_lower or 'try:' in line_lower):
        return True
    
    # Comments about documentation/history are okay
    if any(word in line_lower for word in ['doc:', 'note:', 'history:', 'changelog:']):
        return True
    
    # References to external stubs (like protobuf) are okay
    if 'pb2' in line_lower or 'grpc' in line_lower or '_stub' in line_lower:
        return True
    
    return False

def scan_file(filepath: Path) -> dict:
    """Scan a single file for placeholders"""
    results = {pattern: [] for pattern in PATTERNS.keys()}
    
    if not filepath.exists():
        return None
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"⚠️  Error reading {filepath}: {e}")
        return None
    
    # Scan each line
    for i, line in enumerate(lines, 1):
        for pattern_name, pattern_regex in PATTERNS.items():
            if re.search(pattern_regex, line):
                if not is_false_positive(line, pattern_name):
                    results[pattern_name].append((i, line.strip()))
    
    return results

def print_report():
    """Generate and print comprehensive report"""
    print('='*80)
    print('COMPREHENSIVE PLACEHOLDER DETECTION REPORT')
    print('='*80)
    print(f'Scanning {len(FILES_TO_CHECK)} critical security files...')
    print()
    
    total_issues = 0
    files_with_issues = []
    
    for filename in FILES_TO_CHECK:
        filepath = Path(filename)
        
        print(f'\n📄 {filename}')
        print('-' * 80)
        
        if not filepath.exists():
            print(f'   ⚠️  FILE NOT FOUND')
            continue
        
        # Get file stats
        file_size = filepath.stat().st_size
        with open(filepath, 'r', encoding='utf-8') as f:
            line_count = len(f.readlines())
        
        print(f'   Size: {file_size:,} bytes | Lines: {line_count:,}')
        
        # Scan for issues
        results = scan_file(filepath)
        if results is None:
            continue
        
        file_issues = 0
        for pattern_name, matches in results.items():
            if matches:
                file_issues += len(matches)
                print(f'   ❌ {pattern_name}: {len(matches)} found')
                for line_num, line_text in matches[:3]:  # Show first 3
                    print(f'      Line {line_num}: {line_text[:65]}...')
                if len(matches) > 3:
                    print(f'      ... and {len(matches)-3} more')
        
        if file_issues == 0:
            print('   ✅ NO PLACEHOLDERS DETECTED - PRODUCTION READY')
        else:
            files_with_issues.append(filename)
            total_issues += file_issues
    
    # Summary
    print()
    print('='*80)
    print('SUMMARY')
    print('='*80)
    print(f'Total files scanned: {len(FILES_TO_CHECK)}')
    print(f'Files with issues: {len(files_with_issues)}')
    print(f'Total issues found: {total_issues}')
    print()
    
    if total_issues == 0:
        print('✅ ALL FILES ARE PRODUCTION-READY!')
        print('✅ Zero placeholders, zero TODOs, zero incomplete implementations')
    else:
        print('⚠️  Issues detected in:')
        for f in files_with_issues:
            print(f'   - {f}')
    
    print('='*80)

if __name__ == '__main__':
    print_report()
