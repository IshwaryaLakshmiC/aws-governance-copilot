#!/usr/bin/env python3
"""
Demo data seeder for AWS Governance Copilot.
Generates realistic security findings without needing real AWS resources.
Run: python seed_demo_data.py
"""
import psycopg2
import json
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.getenv("DB_NAME", "cloud_security_platform"),
    user=os.getenv("DB_USER", "platform_admin"),
    password=os.getenv("DB_PASSWORD", "localdev123"),
)
cur = conn.cursor()

now = datetime.now(timezone.utc)

# ── IAM FINDINGS ──────────────────────────────────────────────
iam_findings = [
    {
        "finding_id": "iam-001",
        "service": "iam",
        "severity": "critical",
        "title": "Root account has no MFA enrolled",
        "description": "The AWS root account is not protected by multi-factor authentication. Any credential compromise would grant unrestricted access to all AWS resources and billing.",
        "resource_id": "root",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"user": "root", "mfa_active": False, "has_access_keys": True}
    },
    {
        "finding_id": "iam-002",
        "service": "iam",
        "severity": "critical",
        "title": "svc-legacy-backup has AdministratorAccess and hasn't logged in for 187 days",
        "description": "Service account svc-legacy-backup holds AdministratorAccess policy and has been inactive for 187 days. Active credentials on a dormant account with admin rights is your highest blast-radius risk.",
        "resource_id": "svc-legacy-backup",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"user": "svc-legacy-backup", "days_inactive": 187, "policy": "AdministratorAccess", "access_keys": 2, "mfa_active": False}
    },
    {
        "finding_id": "iam-003",
        "service": "iam",
        "severity": "high",
        "title": "dev-contractor-04 has no MFA and access key not rotated in 134 days",
        "description": "Contractor account with S3FullAccess and EC2FullAccess policies. No MFA enrolled. Access key issued 134 days ago without rotation. Contractor accounts are high-risk as offboarding is often delayed.",
        "resource_id": "dev-contractor-04",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"user": "dev-contractor-04", "days_inactive": 134, "key_age_days": 134, "mfa_active": False, "policies": ["S3FullAccess", "EC2FullAccess"]}
    },
    {
        "finding_id": "iam-004",
        "service": "iam",
        "severity": "high",
        "title": "6 IAM access keys not rotated in over 90 days",
        "description": "Six access keys across five users have not been rotated in 90+ days. Oldest key: 287 days (svc-legacy-backup). CIS AWS Foundations Benchmark 1.14 requires rotation within 90 days.",
        "resource_id": "multiple",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"affected_users": ["svc-legacy-backup", "dev-contractor-04", "svc-monitoring-ro", "ops-deploy", "ci-runner"], "oldest_key_days": 287}
    },
    {
        "finding_id": "iam-005",
        "service": "iam",
        "severity": "medium",
        "title": "4 of 12 console users have no MFA enrolled",
        "description": "Users dev-contractor-04, svc-analytics, admin-temp, and ci-runner have console access enabled without MFA. This violates CIS 6.3 and SOC2 CC6.1.",
        "resource_id": "multiple",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"no_mfa_users": ["dev-contractor-04", "svc-analytics", "admin-temp", "ci-runner"], "total_console_users": 12}
    },
    {
        "finding_id": "iam-006",
        "service": "iam",
        "severity": "high",
        "title": "admin-temp account active for 97 days — was supposed to be temporary",
        "description": "admin-temp was created as a temporary account 97 days ago. It holds PowerUserAccess and has active console login. Temporary accounts that persist become permanent orphaned credentials.",
        "resource_id": "admin-temp",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"user": "admin-temp", "created_days_ago": 97, "policy": "PowerUserAccess", "last_login_days": 3}
    },
]

# ── S3 FINDINGS ───────────────────────────────────────────────
s3_findings = [
    {
        "finding_id": "s3-001",
        "service": "s3",
        "severity": "critical",
        "title": "acme-prod-customer-data: public access block DISABLED",
        "description": "Production bucket containing customer PII has public access block fully disabled. No bucket policy restricts access. This is a data breach waiting to happen. SOC2 CC6.1 failure.",
        "resource_id": "acme-prod-customer-data",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"bucket": "acme-prod-customer-data", "public_access_block": False, "has_bucket_policy": False, "contains_pii": True}
    },
    {
        "finding_id": "s3-002",
        "service": "s3",
        "severity": "high",
        "title": "8 S3 buckets missing default encryption",
        "description": "Eight buckets lack server-side encryption (SSE-S3 or SSE-KMS). Any data written to these buckets is stored unencrypted at rest. Includes dev-data-exports and staging-ml-datasets.",
        "resource_id": "multiple",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"buckets": ["dev-data-exports", "staging-ml-datasets", "temp-uploads-2024", "legacy-archive", "etl-staging", "test-fixtures", "build-artifacts", "old-backups"]}
    },
    {
        "finding_id": "s3-003",
        "service": "s3",
        "severity": "medium",
        "title": "acme-prod-static-assets: public read ACL with unencrypted uploads",
        "description": "Static asset CDN bucket with intentional public read — but SSE-S3 encryption is not enforced on uploads. New objects may be stored unencrypted.",
        "resource_id": "acme-prod-static-assets",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"bucket": "acme-prod-static-assets", "public_read_intentional": True, "encryption_enforced": False}
    },
]

# ── EC2 FINDINGS ──────────────────────────────────────────────
ec2_findings = [
    {
        "finding_id": "ec2-001",
        "service": "ec2",
        "severity": "critical",
        "title": "Security group sg-prod-db allows port 5432 from 0.0.0.0/0",
        "description": "Production database security group allows PostgreSQL (port 5432) from any IP address. Database should never be directly reachable from the internet. Immediate remediation required.",
        "resource_id": "sg-0abc123def456",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"sg_id": "sg-0abc123def456", "sg_name": "sg-prod-db", "port": 5432, "cidr": "0.0.0.0/0"}
    },
    {
        "finding_id": "ec2-002",
        "service": "ec2",
        "severity": "high",
        "title": "3 EC2 instances allow IMDSv1 (SSRF attack vector)",
        "description": "Three running instances allow IMDSv1, which is vulnerable to SSRF attacks that can steal IAM credentials from the instance metadata endpoint. IMDSv2 should be required on all instances.",
        "resource_id": "multiple",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"instances": ["i-0abc123", "i-0def456", "i-0ghi789"], "vulnerability": "SSRF via IMDSv1"}
    },
    {
        "finding_id": "ec2-003",
        "service": "ec2",
        "severity": "medium",
        "title": "Security group sg-bastion allows SSH from 0.0.0.0/0",
        "description": "Bastion host security group allows SSH from any IP. Should be restricted to corporate IP ranges or VPN egress. Exposes SSH to internet-wide brute force attempts.",
        "resource_id": "sg-0bastion789",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"sg_name": "sg-bastion", "port": 22, "cidr": "0.0.0.0/0"}
    },
]

# ── GUARDDUTY FINDINGS ────────────────────────────────────────
guardduty_findings = [
    {
        "finding_id": "gd-001",
        "service": "guardduty",
        "severity": "critical",
        "title": "UnauthorizedAccess:IAMUser/TorIPCaller — svc-analytics",
        "description": "IAM user svc-analytics made 23 API calls from a Tor exit node at 14:32 UTC. High-confidence indicator of credential compromise. Tor usage by a corporate service account is never legitimate.",
        "resource_id": "svc-analytics",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"finding_type": "UnauthorizedAccess:IAMUser/TorIPCaller", "user": "svc-analytics", "api_calls": 23, "time": "14:32 UTC", "severity_score": 8.9}
    },
    {
        "finding_id": "gd-002",
        "service": "guardduty",
        "severity": "high",
        "title": "Recon:IAMUser/UserPermissions — ci-runner enumerated 23 IAM policies",
        "description": "CI runner account made 23 ListPolicies and GetPolicy calls in 4 minutes. Unusual for a CI account. May indicate credential theft and attacker performing privilege escalation reconnaissance.",
        "resource_id": "ci-runner",
        "region": "us-east-1",
        "account_id": "123456789012",
        "raw_data": {"finding_type": "Recon:IAMUser/UserPermissions", "user": "ci-runner", "api_calls": 23, "duration_minutes": 4, "severity_score": 6.1}
    },
]

# ── COST ANOMALIES ────────────────────────────────────────────
cost_anomalies = [
    {
        "anomaly_id": "cost-001",
        "service": "AWS Data Transfer",
        "region": "us-east-1",
        "amount_usd": 218.40,
        "expected_usd": 12.00,
        "anomaly_date": (now - timedelta(days=3)).date().isoformat(),
        "description": "NAT Gateway cross-region data transfer spike: eu-west-1 → us-east-1, 2.1TB transferred. Correlates with ModifyReplicationGroup API call by svc-deployment-bot at 09:11 UTC."
    },
    {
        "anomaly_id": "cost-002",
        "service": "Amazon EC2",
        "region": "us-east-1",
        "amount_usd": 89.20,
        "expected_usd": 8.00,
        "anomaly_date": (now - timedelta(days=3)).date().isoformat(),
        "description": "3x r5.2xlarge instances launched on-demand at 09:22 UTC and left running. No termination scheduled. Likely forgot to terminate after testing."
    },
    {
        "anomaly_id": "cost-003",
        "service": "Amazon S3",
        "region": "ap-southeast-1",
        "amount_usd": 180.00,
        "expected_usd": 12.00,
        "anomaly_date": (now - timedelta(days=7)).date().isoformat(),
        "description": "S3 traffic routed through NAT Gateway in ap-southeast-1 instead of VPC endpoint. Creating an S3 VPC endpoint would eliminate this cost entirely."
    },
]

# ── INSERT ALL FINDINGS ───────────────────────────────────────
print("Inserting IAM findings...")
for f in iam_findings:
    cur.execute("""
        INSERT INTO findings (finding_id, service, severity, title, description, resource_id, region, account_id, raw_data, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (finding_id) DO UPDATE SET severity=EXCLUDED.severity, title=EXCLUDED.title, collected_at=NOW()
    """, (f["finding_id"], f["service"], f["severity"], f["title"], f["description"],
          f["resource_id"], f["region"], f["account_id"], json.dumps(f["raw_data"])))

print("Inserting S3 findings...")
for f in s3_findings:
    cur.execute("""
        INSERT INTO findings (finding_id, service, severity, title, description, resource_id, region, account_id, raw_data, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (finding_id) DO UPDATE SET severity=EXCLUDED.severity, title=EXCLUDED.title, collected_at=NOW()
    """, (f["finding_id"], f["service"], f["severity"], f["title"], f["description"],
          f["resource_id"], f["region"], f["account_id"], json.dumps(f["raw_data"])))

print("Inserting EC2 findings...")
for f in ec2_findings:
    cur.execute("""
        INSERT INTO findings (finding_id, service, severity, title, description, resource_id, region, account_id, raw_data, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (finding_id) DO UPDATE SET severity=EXCLUDED.severity, title=EXCLUDED.title, collected_at=NOW()
    """, (f["finding_id"], f["service"], f["severity"], f["title"], f["description"],
          f["resource_id"], f["region"], f["account_id"], json.dumps(f["raw_data"])))

print("Inserting GuardDuty findings...")
for f in guardduty_findings:
    cur.execute("""
        INSERT INTO findings (finding_id, service, severity, title, description, resource_id, region, account_id, raw_data, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (finding_id) DO UPDATE SET severity=EXCLUDED.severity, title=EXCLUDED.title, collected_at=NOW()
    """, (f["finding_id"], f["service"], f["severity"], f["title"], f["description"],
          f["resource_id"], f["region"], f["account_id"], json.dumps(f["raw_data"])))

print("Inserting cost anomalies...")
for c in cost_anomalies:
    cur.execute("""
        INSERT INTO cost_anomalies (anomaly_id, service, region, amount_usd, expected_usd, anomaly_date, description, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (anomaly_id) DO UPDATE SET amount_usd=EXCLUDED.amount_usd, collected_at=NOW()
    """, (c["anomaly_id"], c["service"], c["region"], c["amount_usd"],
          c.get("expected_usd"), c["anomaly_date"], c["description"]))

conn.commit()
cur.close()
conn.close()

print("\n✓ Demo data loaded successfully")
print(f"  {len(iam_findings)} IAM findings")
print(f"  {len(s3_findings)} S3 findings")
print(f"  {len(ec2_findings)} EC2 findings")
print(f"  {len(guardduty_findings)} GuardDuty findings")
print(f"  {len(cost_anomalies)} cost anomalies")
print("\nTry these queries in the Governance Copilot:")
print("  → 'Which IAM users are dormant with active access keys?'")
print("  → 'Show me all critical findings'")
print("  → 'Why did our AWS bill spike this week?'")
print("  → 'What is the blast radius of the svc-analytics compromise?'")
