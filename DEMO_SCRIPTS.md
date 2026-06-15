# ═══════════════════════════════════════════════════════════════
# DEMO SCRIPT 1: AWS Governance Copilot (5 minutes)
# Target audience: Wiz, Datadog, CrowdStrike, AWS SA hiring managers
# ═══════════════════════════════════════════════════════════════

## OPENING (30 seconds)
"This is an AI-powered security and cost governance assistant running over 
real AWS data — not a dashboard, not a static report. You type a question 
in plain English and get answers grounded in actual findings from the account."

## MINUTE 1 — Show the findings summary
# Click "Run collectors" in sidebar (or if using demo data, skip)
# Ask: "Give me an overview of our current security posture"
# Shows: critical/high counts, services affected

## MINUTE 2 — IAM dormant admin
# Ask: "Which IAM users haven't logged in for 90 days but still have active access keys?"
# Expected: svc-legacy-backup (187 days), dev-contractor-04 (134 days)
# Say: "This is the question that takes a security team 30 minutes to answer manually.
#       It took 3 seconds. And notice it gives us the exact AWS CLI command to fix it."

## MINUTE 3 — Cost spike
# Ask: "Why did our AWS bill spike last week?"
# Expected: NAT Gateway cross-region + rogue EC2 instances
# Say: "The NAT Gateway finding correlates with a CloudTrail event — 
#       a deployment bot changed the replication config. That root cause 
#       took me 30 seconds to surface. Previously it was a support ticket."

## MINUTE 4 — Blast radius analysis
# Ask: "What is the blast radius if svc-analytics credentials were compromised?"
# Expected: GuardDuty finding + Tor IP + 23 API calls + remediation steps
# Say: "This is the question a CISO asks after an incident. We're answering it
#       before the incident happens, from the GuardDuty finding we saw 14 minutes ago."

## MINUTE 5 — Prioritised remediation
# Ask: "Give me a prioritised remediation plan for our top 5 findings"
# Shows: ordered by severity + effort, with specific steps
# Close: "Real AWS data. No dashboards to configure. No SIEM rules to write.
#         You ask the question your CISO would ask, you get the answer."


# ═══════════════════════════════════════════════════════════════
# DEMO SCRIPT 2: Security Discovery Copilot (5 minutes)
# Target audience: Okta, Cloudflare, Wiz, SailPoint, CyberArk hiring managers
# ═══════════════════════════════════════════════════════════════

## SETUP: Select "FinTech Zero Trust" scenario from sidebar
## This loads: 2000-employee FinTech, hybrid AD+Azure AD, VPN-dependent, new CISO

## OPENING (30 seconds)
"I'm going to show you a system that does what you do in your first three 
customer meetings — discovery, gap analysis, architecture recommendations, 
and an executive summary. Watch how it adapts to the customer's answers."

## MINUTE 1 — Discovery conversation
# Click "Begin Discovery" — SE opens with a contextual question
# Answer as the customer:
#   "We're a 2000-person FinTech. We have Active Directory on-prem, 
#    Azure AD in the cloud, and we just hired a new CISO who wants Zero Trust."
# Watch: copilot follows up on AD/Azure AD hybrid — asks about SCIM, federation %
# Answer: "Manual provisioning. About 40% of apps are federated."
# Watch: copilot surfaces the SCIM gap without being told explicitly

## MINUTE 2 — Gap analysis
# Click "Run Analysis"
# Shows: deterministic scoring against CIS Controls, SOC2, NIST
# Point out: "This isn't AI guessing. These are real compliance framework mappings.
#             The severity scores are deterministic — they don't change between runs."

## MINUTE 3 — Recommendations
# Click "Generate Recommendations"  
# Shows: Okta (SCIM), Cloudflare Access (VPN replacement), CyberArk (PAM)
# Point out the "Why it may NOT fit" column
# Say: "Every SE hiring manager has seen demos where the tool just recommends
#       everything. This one tells you when NOT to use a vendor. 
#       That's the trusted advisor position."

## MINUTE 4 — Architecture options
# Click "Architecture Options"
# Shows 4 paths: Best Security / Best Cost / Fastest TTV / Lowest OpEx
# Point to the decision matrix
# Say: "Enterprise customers never accept one recommendation. 
#       A senior SE always presents options with honest tradeoffs."

## MINUTE 5 — Executive summary
# Click "Executive Summary"
# Shows: CISO-level 1-pager, 3-phase roadmap, business impact in dollars
# Print to PDF
# Say: "This is the document that goes to the CISO after the discovery call.
#       We just generated it from a 4-minute conversation."


# ═══════════════════════════════════════════════════════════════
# DEMO SCRIPT 3: ZTNA Simulator (5 minutes)
# Target audience: Cloudflare, Okta, Palo Alto, Zscaler hiring managers
# ═══════════════════════════════════════════════════════════════

## SETUP: Okta connected, signed in as your admin user

## MINUTE 1 — Show live identity
# Point to identity badge: "This is my real Okta identity. 
#  My actual groups, my actual MFA method — pulled from the IdP token.
#  Not a mock user. Not a simulated login."

## MINUTE 2 — Legitimate access (load "Trusted employee" scenario)
# Select resource: Internal App
# Click Evaluate → ALLOW
# Say: "Identity verified via Okta SSO, hardware MFA, managed device, 
#       corporate network. Every check passes. Access granted."

## MINUTE 3 — Attack scenario (load "Stolen credentials" scenario)
# Okta identity stays, but device and network flip to: unknown device, Tor IP
# Click Evaluate → DENY
# Point to: MITRE ATT&CK tags (T1110.004 Credential Stuffing)
# Point to: Post-deny remediation — P1: rotate credentials, revoke sessions
# Say: "Same user identity — but the Tor exit node and unknown device 
#       trigger a deny. This is exactly the decision Cloudflare Access makes
#       in production. The policy trace shows every check."

## MINUTE 4 — Policy Impact tab
# Switch to Policy Impact tab
# Select "Require MDM for critical resources"
# Show: which users would be blocked before rollout
# Say: "Every customer asks 'what breaks if I turn this on?' 
#       This answers that question before you flip the switch."

## MINUTE 5 — Compliance tab
# Switch to Compliance tab  
# Toggle off "Require MFA" policy
# Watch SOC2 CC6.1 flip from MAPPED to GAP in real time
# Say: "The compliance team needs to know which controls are satisfied.
#       Toggle a policy off — the gap appears immediately. 
#       This is the conversation that happens in every SOC2 audit."
