"""One-shot rebranding script: EnterpriseSecurityIQ -> PostureIQ (display text only).

SKIPS all functional identifiers:
- ENTERPRISESECURITYIQ_NS (UUID namespace)
- ENTERPRISESECURITYIQ_* env vars
- enterprisesecurityiq logger name
- enterprisesecurityiq-theme localStorage key
- enterprisesecurityiq-diag diagnostic settings name
- SIEM source/sourcetype strings
- SARIF tool name + URL
- Jira labels, ADO tags
- agent name in api.py (name="EnterpriseSecurityIQ")
- agent name check in api.py (a.name == "EnterpriseSecurityIQ")
- test env var references
"""

import os
import re

ROOT = os.path.dirname(os.path.abspath(__file__))

# ══════════════════════════════════════════════════════════════
# DO-NOT-TOUCH patterns — lines containing ANY of these are SKIPPED
# ══════════════════════════════════════════════════════════════
SKIP_PATTERNS = [
    "ENTERPRISESECURITYIQ_NS",
    "ENTERPRISESECURITYIQ_APP_CLIENT",
    "ENTERPRISESECURITYIQ_AUTH_MODE",
    "ENTERPRISESECURITYIQ_CONFIG",
    "ENTERPRISESECURITYIQ_FRAMEWORKS",
    "ENTERPRISESECURITYIQ_LOG_FORMAT",
    "ENTERPRISESECURITYIQ_LOG_LEVEL",
    "enterprisesecurityiq-theme",
    "enterprisesecurityiq-diag",
    'enterprisesecurityiq")',          # logger name
    '"enterprisesecurityiq"',          # logger name in quotes
    "enterprisesecurityiq:finding",    # Splunk sourcetype
    'source": "enterprisesecurityiq"', # Splunk source fn default
    'source": "EnterpriseSecurityIQ"', # QRadar source
    '"name": "EnterpriseSecurityIQ"',  # SARIF tool name
    "enterprisesecurityiq",            # Jira label in list (lowercase exact)
    'name="EnterpriseSecurityIQ"',     # agent instance name
    'a.name == "EnterpriseSecurityIQ"',# agent name check
    "informationUri",                  # SARIF URL
    "OSCAL",                           # OSCAL identifiers — skip oscal lines
    "EnterpriseSecurityIQ;Security",   # ADO tags
    "from app.models import",          # import of ENTERPRISESECURITYIQ_NS
    "ENTERPRISESECURITYIQ_NS",         # any reference to NS constant
]

# Files to completely skip (functional, test fixtures, or already done)
SKIP_FILES = {
    "shared_theme.py",     # localStorage key
    "siem_integration.py", # SIEM sources
    "sarif_export.py",     # SARIF tool metadata
    "oscal_export.py",     # OSCAL identifiers (under postureiq_reports/ and reports/)
    "test_enhancements.py",# test env vars
}

# ══════════════════════════════════════════════════════════════
# TARGETED REPLACEMENTS
# ══════════════════════════════════════════════════════════════

changes = 0
files_changed = set()

def process_file(filepath):
    global changes, files_changed
    
    basename = os.path.basename(filepath)
    if basename in SKIP_FILES:
        return
    
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    new_lines = []
    file_changed = False
    
    for i, line in enumerate(lines):
        # Check if this line contains any skip pattern
        skip = False
        for pat in SKIP_PATTERNS:
            if pat in line:
                skip = True
                break
        
        if skip:
            new_lines.append(line)
            continue
        
        # Only replace display-text occurrences
        if "EnterpriseSecurityIQ" in line:
            new_line = line.replace("EnterpriseSecurityIQ", "PostureIQ")
            if new_line != line:
                changes += 1
                file_changed = True
                new_lines.append(new_line)
                continue
        
        new_lines.append(line)
    
    if file_changed:
        files_changed.add(filepath)
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


# Walk AIAgent/ tree
for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "AIAgent")):
    # Skip test fixtures and __pycache__
    dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "test_data", "fixtures")]
    for fn in filenames:
        if fn.endswith(".py"):
            process_file(os.path.join(dirpath, fn))

# Also process the i18n locale file
locale_path = os.path.join(ROOT, "AIAgent", "app", "locales", "en.json")
if os.path.exists(locale_path):
    with open(locale_path, "r", encoding="utf-8") as f:
        content = f.read()
    new_content = content.replace("EnterpriseSecurityIQ Compliance Report", "PostureIQ Compliance Report")
    if new_content != content:
        with open(locale_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        changes += 1
        files_changed.add(locale_path)

print(f"\n{'='*60}")
print(f"Rebranding complete: {changes} replacements in {len(files_changed)} files")
print(f"{'='*60}")
for fp in sorted(files_changed):
    rel = fp.replace(ROOT + os.sep, "")
    print(f"  ✓ {rel}")
print()
