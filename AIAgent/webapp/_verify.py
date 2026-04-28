import pathlib, re

WEBAPP = pathlib.Path(".")

# Verify assessment pages
for p in ['RiskAnalysis','CopilotReadiness','AIAgentSecurity','RBACReport']:
    h = (WEBAPP / f'{p}.html').read_text('utf-8')
    perm_html_divs = h.count('<div class="perm-panel-group">')
    checks = {
        'body.page': f'body.page = "{p}";' in h,
        'assess-panel': 'id="assessPanel"' in h,
        'perm-panel': 'id="permPanel"' in h,
        'ce-panel': 'id="cePanel"' in h,
        'qs-cards': 'qs-card' in h,
        'fwModalOverlay': 'fwModalOverlay' in h,
        'sessionSnapshots': 'sessionSnapshots' in h,
        'FOLLOWUP_MAP': 'FOLLOWUP_MAP' in h,
        'only 1 perm group': perm_html_divs == 1,
        'no DataSecurity': 'body.page = "DataSecurity"' not in h,
    }
    fails = [k for k,v in checks.items() if not v]
    print(f'{p}: {"PASS" if not fails else "FAIL: "+str(fails)} (perm HTML groups: {perm_html_divs})')

# Verify CloudExplorer
h = (WEBAPP / 'CloudExplorer.html').read_text('utf-8')
ce_perm_html_divs = h.count('<div class="perm-panel-group">')
# 4 qs-card = 2 HTML + 2 in resetChat JS
qs_count = h.count('class="qs-card"')
ce_checks = {
    'body.page': 'body.page = "CloudExplorer";' in h,
    'NO assess-panel': 'id="assessPanel"' not in h,
    'NO navAssessment': 'id="navAssessment"' not in h,
    'NO fwModalOverlay HTML': 'id="fwModalOverlay"' not in h,
    'perm-panel': 'id="permPanel"' in h,
    'ce-panel': 'id="cePanel"' in h,
    'only 1 perm group': ce_perm_html_divs == 1,
    'qs-cards': 'qs-card' in h,
    'Cloud Explorer title': '<h1>Cloud Explorer</h1>' in h,
    'sessionSnapshots': 'sessionSnapshots' in h,
    '4 qs-card refs (2 HTML + 2 JS)': qs_count == 4,
    'navPermissions': 'id="navPermissions"' in h,
    'navExplorer': 'id="navExplorer"' in h,
}
fails = [k for k,v in ce_checks.items() if not v]
print(f'CloudExplorer: {"PASS" if not fails else "FAIL: "+str(fails)} (QS: {qs_count}, perm HTML: {ce_perm_html_divs})')

# Verify protected pages unchanged
for prot in ['SecurityComplianceAssessment.html', 'DataSecurity.html']:
    sz = len((WEBAPP / prot).read_text('utf-8'))
    print(f'{prot}: {sz:,} chars (unchanged)')
