"""
Apply Check Permissions + Cloud Explorer enhancements to
AIAgentSecurity.html, CopilotReadiness.html, RBACReport.html.

Changes:
1. Replace sidebar Check Permissions onclick to call startCheckPermissions()
2. Add startCheckPermissions() function with page-specific prompts in chat
3. Replace startCloudExplorer() with page-specific priority ordering
4. Update resetChat() welcome text to be page-specific
"""
import re

# ── Page definitions ──
pages = {
    'AIAgentSecurity.html': {
        'title': 'AI Agent Security',
        'icon': '🤝',
        'assessment_prompt': 'Evaluate AI agent security across Copilot Studio and Foundry',
        'welcome_icon': '🛡️',
        'footer': 'AI Agent Security uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.',
        'perm_prompts': [
            {'group': '🛡 Assessment Readiness', 'items': [
                ('Check all permissions I need to run a full AI Agent Security assessment covering Copilot Studio, Azure AI Foundry, and custom agents', 'all permissions for AI Agent Security?'),
                ('What permissions am I missing to audit AI agents? Check Azure RBAC, Microsoft Graph, and Entra ID roles', 'what permissions am I missing?'),
                ('Verify my readiness to audit Copilot Studio bots, Foundry deployments, and agent security configurations', 'verify readiness for agent audit'),
            ]},
            {'group': '🔷 Azure RBAC', 'items': [
                ('Do I have Reader role on subscriptions containing Azure AI services, Copilot Studio, and Bot Service resources?', 'Reader for AI resources?'),
                ('Can I access Azure AI Foundry projects and model deployments for security review?', 'Foundry project access?'),
                ('Do I have Cognitive Services Reader or Contributor for reviewing AI service configurations?', 'Cognitive Services Reader?'),
                ('Can I query Azure Resource Graph for Bot Service, OpenAI, and AI Search resources?', 'Resource Graph for AI resources?'),
            ]},
            {'group': '🟣 Entra ID & Graph', 'items': [
                ('Do I have Application.Read.All to review app registrations used by AI agents?', 'Application.Read.All?'),
                ('Check if I have ServicePrincipal.Read.All to audit agent service identities', 'ServicePrincipal.Read.All?'),
                ('Can I read bot channel registrations and Copilot Studio environment configurations?', 'bot channel & Copilot Studio access?'),
                ('Do I have Policy.Read.All and ConditionalAccess.Read.All for governance checks?', 'governance policy read access?'),
            ]},
            {'group': '🛡️ Security Roles', 'items': [
                ('Am I a Security Reader or Security Admin for Defender AI threat detection?', 'Security Reader / Admin?'),
                ('Do I have access to review Responsible AI settings and content safety filters?', 'Responsible AI access?'),
                ('Can I view audit logs for AI agent interactions and data access events?', 'audit log access for agents?'),
            ]},
        ],
        'ce_welcome': {
            'categories': [
                ('AI Agents &amp; Bots', 'Copilot Studio bots, Bot Service channels, Foundry agents, agent action configurations'),
                ('Azure AI Services', 'Azure OpenAI, AI Search, Cognitive Services, ML workspaces, AI Foundry projects'),
                ('Security &amp; Compliance', 'Defender plans, secure score, security recommendations, policy compliance, resource locks'),
                ('Identities &amp; Access', 'users, groups, apps, service principals, directory roles, conditional access policies, risky users'),
                ('Cloud Resources', 'VMs, storage accounts, databases, Key Vaults, web apps, container apps'),
                ('Networking', 'VNets, subnets, private endpoints, public IPs, NSG rules, firewalls'),
                ('Infrastructure', 'subscriptions, resource groups, management groups, tags, locations'),
            ],
            'placeholder': 'Explore your cloud — e.g., "list Copilot Studio bots", "show AI Foundry projects", "Azure OpenAI resources"...',
            'examples': '"list Copilot Studio bots" or "show Azure OpenAI resources"',
        },
        'reset_welcome_h3': 'AI Agent Security',
        'reset_welcome_p': 'Audit AI agent security across Copilot Studio, Foundry, and custom agents. Select a tool from the sidebar to begin.',
    },
    'CopilotReadiness.html': {
        'title': 'Copilot Readiness',
        'icon': '🤖',
        'assessment_prompt': 'Assess M365 Copilot readiness for my tenant',
        'welcome_icon': '🛡️',
        'footer': 'Copilot Readiness uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.',
        'perm_prompts': [
            {'group': '🛡 Assessment Readiness', 'items': [
                ('Check all permissions I need to run a full Copilot Readiness assessment covering oversharing, DLP, sensitivity labels, and access governance', 'all permissions for Copilot Readiness?'),
                ('What permissions am I missing to assess M365 Copilot readiness? Check Graph API, Purview, and Entra roles', 'what permissions am I missing?'),
                ('Verify my readiness to audit SharePoint oversharing, DLP policies, and sensitivity label coverage', 'verify readiness for all checks'),
            ]},
            {'group': '🔷 Azure & M365 Access', 'items': [
                ('Do I have SharePoint Administrator or Sites.Read.All to detect oversharing in SharePoint and OneDrive?', 'SharePoint oversharing access?'),
                ('Can I read DLP policies and alerts via Security & Compliance Center or Graph API?', 'DLP policy read access?'),
                ('Do I have InformationProtection.Read.All to audit sensitivity label deployment?', 'sensitivity label read access?'),
                ('Can I read Microsoft 365 usage reports to assess Copilot adoption readiness?', 'M365 usage reports access?'),
            ]},
            {'group': '🟣 Microsoft Graph', 'items': [
                ('Do I have Sites.Read.All and Files.Read.All to scan SharePoint sites for oversharing?', 'Sites.Read.All & Files.Read.All?'),
                ('Check if I have Policy.Read.All for DLP and retention policy assessment', 'Policy.Read.All for DLP?'),
                ('Do I have SecurityAlert.Read.All and SecurityIncident.Read.All for threat detection?', 'security alert read access?'),
                ('Can I read conditional access policies affecting Copilot access?', 'conditional access for Copilot?'),
            ]},
            {'group': '🛡️ Compliance Roles', 'items': [
                ('Am I a Compliance Administrator or Information Protection Administrator?', 'Compliance / InfoProtection Admin?'),
                ('Do I have Global Reader or Security Reader for tenant-wide Copilot readiness checks?', 'Global Reader / Security Reader?'),
                ('Can I access Purview Information Protection and eDiscovery for data governance audit?', 'Purview access for governance?'),
            ]},
        ],
        'ce_welcome': {
            'categories': [
                ('Data Governance &amp; Labels', 'sensitivity labels, label policies, retention labels, information barriers, DLP policies'),
                ('SharePoint &amp; OneDrive', 'site collections, sharing settings, anonymous links, external sharing, oversharing detection'),
                ('Identities &amp; Access', 'users, groups, apps, service principals, conditional access, PIM, risky users'),
                ('Security &amp; Compliance', 'Defender plans, secure score, security alerts, DLP alerts, compliance policies'),
                ('Cloud Resources', 'VMs, storage accounts, databases, Key Vaults, web apps, AKS clusters'),
                ('Networking', 'VNets, subnets, private endpoints, public IPs, NSG rules, firewalls'),
                ('Infrastructure', 'subscriptions, resource groups, management groups, tags, locations'),
            ],
            'placeholder': 'Explore your cloud — e.g., "show sensitivity labels", "list SharePoint sites", "DLP policy status"...',
            'examples': '"show sensitivity labels" or "list SharePoint external sharing sites"',
        },
        'reset_welcome_h3': 'Copilot Readiness',
        'reset_welcome_p': 'Evaluate your organization\'s readiness for M365 Copilot. Select a tool from the sidebar to begin.',
    },
    'RBACReport.html': {
        'title': 'RBAC Report',
        'icon': '🌳',
        'assessment_prompt': 'Generate an RBAC tree report for all subscriptions',
        'welcome_icon': '🛡️',
        'footer': 'RBAC Report uses your signed-in credentials to query Microsoft cloud services. Results reflect your permission level.',
        'perm_prompts': [
            {'group': '🛡 Assessment Readiness', 'items': [
                ('Check all permissions I need to generate a full RBAC tree report covering subscriptions, role assignments, PIM, and risk flags', 'all permissions for RBAC Report?'),
                ('What permissions am I missing to generate an RBAC hierarchy report? Check Azure RBAC, Graph API, and Entra roles', 'what permissions am I missing?'),
                ('Verify my readiness to audit role assignments, PIM eligibility, and custom role definitions', 'verify readiness for RBAC audit'),
            ]},
            {'group': '🔷 Azure RBAC', 'items': [
                ('Do I have Reader role on all subscriptions to enumerate role assignments across the hierarchy?', 'Reader on all subscriptions?'),
                ('Can I read management group role assignments for cross-subscription RBAC analysis?', 'management group RBAC access?'),
                ('Do I have Authorization/roleAssignments/read and roleDefinitions/read permissions?', 'role assignment read access?'),
                ('Can I query Azure Resource Graph for role assignments and custom role definitions?', 'Resource Graph for RBAC?'),
            ]},
            {'group': '🟣 Entra ID & Graph', 'items': [
                ('Do I have RoleManagement.Read.All to enumerate Entra ID directory role assignments?', 'RoleManagement.Read.All?'),
                ('Check if I have PrivilegedAccess.Read.AzureResources for PIM eligible role enumeration', 'PIM read access?'),
                ('Do I have User.Read.All and Group.Read.All to resolve role assignment principals?', 'User.Read.All & Group.Read.All?'),
                ('Can I read app registrations and service principals that have role assignments?', 'app & SP role assignments?'),
            ]},
            {'group': '🛡️ Governance Roles', 'items': [
                ('Am I a Global Reader or Security Reader to see all Entra directory role assignments?', 'Global Reader / Security Reader?'),
                ('Do I have Privileged Role Administrator to audit PIM settings and eligible assignments?', 'Privileged Role Administrator?'),
                ('Can I view audit logs for role assignment changes and PIM activation history?', 'audit logs for RBAC changes?'),
            ]},
        ],
        'ce_welcome': {
            'categories': [
                ('Role Assignments &amp; RBAC', 'role assignments, custom roles, deny assignments, PIM eligible roles, management group RBAC'),
                ('Identities &amp; Access', 'admin users, service principals, app registrations, directory roles, group memberships, risky users'),
                ('Security &amp; Compliance', 'Defender plans, secure score, security recommendations, policy compliance, resource locks'),
                ('Cloud Resources', 'VMs, storage accounts, databases, Key Vaults, web apps, AKS clusters'),
                ('Networking', 'VNets, subnets, private endpoints, public IPs, NSG rules, firewalls'),
                ('Governance', 'policy assignments, compliance violations, blueprints, initiatives, deny assignments'),
                ('Infrastructure', 'subscriptions, resource groups, management groups, tags, locations'),
            ],
            'placeholder': 'Explore your cloud — e.g., "list role assignments", "show PIM eligible roles", "custom RBAC role definitions"...',
            'examples': '"list all role assignments" or "show PIM eligible roles"',
        },
        'reset_welcome_h3': 'RBAC Report',
        'reset_welcome_p': 'Generate RBAC tree reports with role hierarchy, PIM, and risk flags. Select a tool from the sidebar to begin.',
    },
}

def build_perm_function(page_cfg):
    """Build the startCheckPermissions() function JS code."""
    js = "function startCheckPermissions() {\n"
    js += "  startSession('Check Permissions', '🔑', '');\n"
    js += "  var html = '<div class=\"msg assistant\"><div class=\"msg-content\">';\n"
    js += "  html += '<h3>🔑 Check Permissions</h3>';\n"
    js += "  html += '<p>Verify your Azure RBAC roles, Entra directory roles, and security permissions for <strong>" + page_cfg['title'] + "</strong>.<br>Click any prompt below or type your own query.</p>';\n"
    js += "  html += '<div style=\"margin-top:.8rem\">';\n"

    for group in page_cfg['perm_prompts']:
        group_name = group['group']
        js += f"  html += '<div style=\"font-size:.8rem;font-weight:700;margin-top:.7rem;margin-bottom:.3rem;color:var(--tx2)\">{group_name}</div>';\n"
        for prompt_text, label in group['items']:
            escaped_prompt = prompt_text.replace("'", "\\'")
            js += f"  html += '<button style=\"display:block;width:100%;text-align:left;padding:.4rem .6rem;margin:.15rem 0;border:1px solid var(--bd);border-radius:8px;background:var(--bg2);color:var(--tx);cursor:pointer;font-size:.78rem;font-family:inherit;transition:background .15s\" onmouseover=\"this.style.background=\\'var(--bg4)\\'\" onmouseout=\"this.style.background=\\'var(--bg2)\\'\" onclick=\"document.getElementById(\\'chatInput\\').value=\\'{escaped_prompt}\\';sendChat()\">\u203a {label}</button>';\n"

    js += "  html += '</div>';\n"
    js += "  html += '</div></div>';\n"
    js += "  document.getElementById('chatScroll').innerHTML = html;\n"
    js += "  document.getElementById('chatInput').placeholder = 'Ask about your permissions — e.g., \"what roles do I have\", \"can I run an assessment\"...';\n"
    js += "  document.getElementById('chatInput').focus();\n"
    js += "}\n"
    return js


def build_ce_function(page_cfg):
    """Build the updated startCloudExplorer() function."""
    ce = page_cfg['ce_welcome']
    js = "function startCloudExplorer() {\n"
    js += "  startSession('Cloud Explorer', '☁️', '');\n"
    js += "  // Show a welcome message instead of auto-sending\n"
    js += "  var html = '<div class=\"msg assistant\">';\n"
    js += "  html += '<div class=\"msg-content\">';\n"
    js += "  html += '<h3>☁️ Cloud Explorer</h3>';\n"
    js += "  html += '<p>I can explore your Microsoft cloud environment in real time. Ask me anything about:</p>';\n"
    js += "  html += '<ul>';\n"

    for cat_name, cat_desc in ce['categories']:
        js += f"  html += '<li><strong>{cat_name}</strong> — {cat_desc}</li>';\n"

    js += "  html += '</ul>';\n"
    js += f"  html += '<p><em>Just type your question below — for example: {ce['examples']}</em></p>';\n"
    js += "  html += '</div></div>';\n"
    js += "  document.getElementById('chatScroll').innerHTML = html;\n"
    js += f"  document.getElementById('chatInput').placeholder = '{ce['placeholder']}';\n"
    js += "  document.getElementById('chatInput').focus();\n"
    js += "}\n"
    return js


def build_reset_function(page_cfg):
    """Build updated resetChat() with page-specific welcome."""
    h3 = page_cfg['reset_welcome_h3']
    p = page_cfg['reset_welcome_p'].replace("'", "\\'")
    js = '''function resetChat() {
  // Reset server-side session state
  if (conversationId) {
    fetch(AGENT_URL + "/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ conversation_id: conversationId })
    }).catch(function() {});
  }
  conversationId = null;

  chatHistory = [];
  document.getElementById("chatScroll").innerHTML = "";
  document.getElementById("chatInput").value = "";
  document.getElementById("chatSessionTitle").textContent = "Select a tool to begin";
  document.getElementById("newChatBtn").style.display = "none";
  setActiveSidebar(null);

  // Re-show welcome
  var scroll = document.getElementById("chatScroll");
  scroll.innerHTML = '<div class="chat-welcome" id="chatWelcome"><div class="chat-welcome-icon">''' + page_cfg['welcome_icon'] + '''</div><h3>''' + h3 + '''</h3><p>''' + p + '''</p></div>';
  document.getElementById("chatInput").focus();
}
'''
    return js


for fname, cfg in pages.items():
    filepath = rf'c:\Users\mchillakuru\#GitHubMyrepos\EnterpriseSecurityIQ\webapp\{fname}'
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    print(f"\n=== {fname} ===")

    # 1. Replace sidebar Check Permissions onclick
    old_perm_onclick = "startSession('Check Permissions','🔑','Check my permissions before running an assessment')"
    new_perm_onclick = "startCheckPermissions()"
    if old_perm_onclick in content:
        content = content.replace(old_perm_onclick, new_perm_onclick)
        print("  Sidebar perm onclick: updated")
    else:
        print("  WARNING: Sidebar perm onclick not found!")

    # 2. Find the startCloudExplorer function and replace it
    # Pattern: from "function startCloudExplorer()" to the closing "}\n" before "function resetChat()"
    ce_match = re.search(r'function startCloudExplorer\(\) \{.*?\n\}\n', content, re.DOTALL)
    if ce_match:
        old_ce = ce_match.group(0)
        new_ce = build_ce_function(cfg)
        content = content.replace(old_ce, new_ce)
        print(f"  startCloudExplorer: replaced ({len(old_ce.split(chr(10)))} -> {len(new_ce.split(chr(10)))} lines)")
    else:
        print("  WARNING: startCloudExplorer not found!")

    # 3. Find resetChat and replace it
    reset_match = re.search(r'function resetChat\(\) \{.*?\n\}\n', content, re.DOTALL)
    if reset_match:
        old_reset = reset_match.group(0)
        new_reset = build_reset_function(cfg)
        content = content.replace(old_reset, new_reset)
        print(f"  resetChat: replaced ({len(old_reset.split(chr(10)))} -> {len(new_reset.split(chr(10)))} lines)")
    else:
        print("  WARNING: resetChat not found!")

    # 4. Insert startCheckPermissions() function right before startCloudExplorer
    perm_func = build_perm_function(cfg)
    insert_marker = "function startCloudExplorer()"
    if insert_marker in content:
        content = content.replace(insert_marker, perm_func + "\n" + insert_marker)
        print(f"  startCheckPermissions: inserted ({len(perm_func.split(chr(10)))} lines)")
    else:
        print("  WARNING: insertion point for startCheckPermissions not found!")

    # Write result
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    # Verify balance
    opens = len(re.findall(r'<div[\s>]', content))
    closes = len(re.findall(r'</div>', content))
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
    brace_ok = True
    for idx, s in enumerate(scripts):
        bd = s.count('{') - s.count('}')
        if bd != 0:
            print(f"  Script#{idx}: BRACE IMBALANCE diff={bd}")
            brace_ok = False

    print(f"  Result: {len(content)} chars, divs {opens}/{closes} diff={opens-closes}")
    if opens == closes and brace_ok:
        print("  OK: All balanced")
    else:
        print("  WARNING: SOMETHING IS IMBALANCED!")
