"""
AWS Collectors — polls real AWS APIs and stores findings in PostgreSQL.
Each collector is independent and can be run on a schedule.
EC2 IAM role provides read-only access — no credentials needed in code.
"""

import boto3
import json
import hashlib
from datetime import datetime, timezone
from app.core.database import execute, executemany
from app.core.config import get_settings

settings = get_settings()


def _finding_id(service: str, resource_id: str, title: str) -> str:
    """Stable finding ID — same finding doesn't create duplicates on re-run"""
    raw = f"{service}:{resource_id}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _upsert_finding(finding_id, service, severity, title, description, resource_id, region, account_id, raw_data):
    execute("""
        INSERT INTO findings (finding_id, service, severity, title, description,
                              resource_id, region, account_id, raw_data, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (finding_id) DO UPDATE SET
            severity    = EXCLUDED.severity,
            description = EXCLUDED.description,
            raw_data    = EXCLUDED.raw_data,
            collected_at = NOW()
    """, (finding_id, service, severity, title, description,
          resource_id, region, account_id, json.dumps(raw_data)))


# ── IAM Collector ─────────────────────────────────────────────

def collect_iam():
    iam = boto3.client("iam", region_name=settings.aws_region)
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]
    findings = []

    # Credential report — inactive users, no MFA, old access keys
    try:
        iam.generate_credential_report()
        import time; time.sleep(2)
        report = iam.get_credential_report()
        import csv, io
        reader = csv.DictReader(io.StringIO(report["Content"].decode("utf-8")))
        for row in reader:
            user = row.get("user", "")
            if user == "<root_account>":
                if row.get("mfa_active") == "false":
                    _upsert_finding(
                        _finding_id("iam", "root", "root_no_mfa"),
                        "iam", "critical",
                        "Root account has no MFA enrolled",
                        "The root account is not protected by MFA. This is the highest-severity IAM finding.",
                        "root", settings.aws_region, account_id,
                        {"user": user, "mfa_active": False}
                    )
                continue

            # Check last activity
            last_used = row.get("password_last_used", "N/A")
            access_key_1_active = row.get("access_key_1_active") == "true"
            access_key_2_active = row.get("access_key_2_active") == "true"
            mfa_active = row.get("mfa_active") == "true"

            if not mfa_active and row.get("password_enabled") == "true":
                _upsert_finding(
                    _finding_id("iam", user, "no_mfa"),
                    "iam", "high",
                    f"IAM user {user} has no MFA enrolled",
                    f"Console user {user} can sign in without MFA. Account compromise via phishing is significantly more likely.",
                    user, settings.aws_region, account_id,
                    {"user": user, "password_enabled": True, "mfa_active": False}
                )

            # Check access key age
            for key_num in ["1", "2"]:
                last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                if row.get(f"access_key_{key_num}_active") == "true" and last_rotated not in ["N/A", "no_information"]:
                    try:
                        rotated = datetime.fromisoformat(last_rotated.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - rotated).days
                        if age_days > 90:
                            _upsert_finding(
                                _finding_id("iam", user, f"old_key_{key_num}"),
                                "iam", "medium",
                                f"IAM user {user} access key {key_num} not rotated in {age_days} days",
                                f"Access key has not been rotated in {age_days} days (threshold: 90). Long-lived credentials increase exposure window.",
                                user, settings.aws_region, account_id,
                                {"user": user, "key_num": key_num, "age_days": age_days}
                            )
                    except Exception:
                        pass

    except Exception as e:
        print(f"IAM collector error: {e}")

    print(f"IAM collector complete")


# ── S3 Collector ──────────────────────────────────────────────

def collect_s3():
    s3 = boto3.client("s3", region_name=settings.aws_region)
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                # Public access block
                try:
                    pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    if not all([pab.get("BlockPublicAcls"), pab.get("BlockPublicPolicy"),
                                pab.get("IgnorePublicAcls"), pab.get("RestrictPublicBuckets")]):
                        _upsert_finding(
                            _finding_id("s3", name, "public_access"),
                            "s3", "critical",
                            f"S3 bucket {name} has public access enabled",
                            "Public access block is not fully enabled. This bucket may be accessible to the internet.",
                            name, settings.aws_region, account_id,
                            {"bucket": name, "public_access_block": pab}
                        )
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    _upsert_finding(
                        _finding_id("s3", name, "no_pab"),
                        "s3", "high",
                        f"S3 bucket {name} has no public access block configured",
                        "No public access block configuration. Default settings may allow public access.",
                        name, settings.aws_region, account_id,
                        {"bucket": name}
                    )

                # Encryption
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    _upsert_finding(
                        _finding_id("s3", name, "no_encryption"),
                        "s3", "medium",
                        f"S3 bucket {name} has no default encryption",
                        "Default server-side encryption is not configured. New objects may be stored unencrypted.",
                        name, settings.aws_region, account_id,
                        {"bucket": name}
                    )

                # Versioning
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get("Status") != "Enabled":
                    _upsert_finding(
                        _finding_id("s3", name, "no_versioning"),
                        "s3", "low",
                        f"S3 bucket {name} versioning not enabled",
                        "Versioning is disabled. Accidental deletion or overwrite cannot be recovered.",
                        name, settings.aws_region, account_id,
                        {"bucket": name, "versioning": versioning.get("Status", "Disabled")}
                    )

            except Exception as e:
                print(f"S3 bucket {name} error: {e}")

    except Exception as e:
        print(f"S3 collector error: {e}")

    print("S3 collector complete")


# ── EC2 / VPC Collector ───────────────────────────────────────

def collect_ec2():
    ec2 = boto3.client("ec2", region_name=settings.aws_region)
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]

    try:
        # Security groups with open ports
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)
                        proto = rule.get("IpProtocol", "-1")
                        severity = "critical" if from_port in [22, 3389, 3306, 5432] else "medium"
                        _upsert_finding(
                            _finding_id("ec2", sg["GroupId"], f"open_{from_port}_{proto}"),
                            "ec2", severity,
                            f"Security group {sg['GroupName']} allows {proto} port {from_port}-{to_port} from 0.0.0.0/0",
                            f"Inbound rule allows unrestricted access on port {from_port}. Review and restrict to specific IP ranges.",
                            sg["GroupId"], settings.aws_region, account_id,
                            {"sg_id": sg["GroupId"], "sg_name": sg["GroupName"],
                             "from_port": from_port, "to_port": to_port}
                        )

        # IMDSv1 instances (should require IMDSv2)
        reservations = ec2.describe_instances()["Reservations"]
        for res in reservations:
            for inst in res["Instances"]:
                if inst["State"]["Name"] == "running":
                    metadata = inst.get("MetadataOptions", {})
                    if metadata.get("HttpTokens") != "required":
                        _upsert_finding(
                            _finding_id("ec2", inst["InstanceId"], "imdsv1"),
                            "ec2", "medium",
                            f"EC2 instance {inst['InstanceId']} allows IMDSv1",
                            "Instance metadata service v1 is allowed. IMDSv2 should be required to prevent SSRF attacks.",
                            inst["InstanceId"], settings.aws_region, account_id,
                            {"instance_id": inst["InstanceId"], "http_tokens": metadata.get("HttpTokens")}
                        )

    except Exception as e:
        print(f"EC2 collector error: {e}")

    print("EC2 collector complete")


# ── GuardDuty Collector ───────────────────────────────────────

def collect_guardduty():
    gd = boto3.client("guardduty", region_name=settings.aws_region)
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]

    try:
        detectors = gd.list_detectors()["DetectorIds"]
        if not detectors:
            print("GuardDuty not enabled — skipping")
            return

        detector_id = detectors[0]
        paginator = gd.get_paginator("list_findings")
        pages = paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"severity": {"Gte": 4}}}  # medium+
        )

        finding_ids = []
        for page in pages:
            finding_ids.extend(page["FindingIds"])

        if finding_ids:
            findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50])["Findings"]
            for f in findings:
                sev_score = f.get("Severity", 0)
                severity = "critical" if sev_score >= 8 else "high" if sev_score >= 6 else "medium"
                _upsert_finding(
                    _finding_id("guardduty", f["Id"], f["Type"]),
                    "guardduty", severity,
                    f["Title"],
                    f.get("Description", ""),
                    f.get("Resource", {}).get("InstanceDetails", {}).get("InstanceId", f["Id"]),
                    f.get("Region", settings.aws_region),
                    account_id,
                    {"type": f["Type"], "severity": sev_score, "service": f.get("Service", {})}
                )

    except Exception as e:
        print(f"GuardDuty collector error: {e}")

    print("GuardDuty collector complete")


# ── CloudTrail Collector ──────────────────────────────────────

def collect_cloudtrail():
    ct = boto3.client("cloudtrail", region_name=settings.aws_region)
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]

    # Look for suspicious API calls in the last 24 hours
    SUSPICIOUS_EVENTS = [
        "DeleteTrail", "StopLogging", "DeleteFlowLogs",
        "AuthorizeSecurityGroupIngress", "CreateKeyPair",
        "GetSecretValue", "DeleteSecret", "PutBucketPolicy",
        "ConsoleLogin", "AssumeRoleWithSAML"
    ]

    try:
        from datetime import timedelta
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)

        for event_name in SUSPICIOUS_EVENTS:
            try:
                resp = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=start,
                    EndTime=end,
                    MaxResults=10
                )
                for event in resp.get("Events", []):
                    user = event.get("Username", "unknown")
                    _upsert_finding(
                        _finding_id("cloudtrail", event["EventId"], event_name),
                        "cloudtrail", "medium",
                        f"CloudTrail: {event_name} called by {user}",
                        f"Potentially sensitive API call {event_name} was made by {user} in the last 24 hours.",
                        event.get("Resources", [{}])[0].get("ResourceName", event["EventId"]),
                        settings.aws_region, account_id,
                        {"event_name": event_name, "user": user,
                         "event_time": event["EventTime"].isoformat()}
                    )
            except Exception:
                pass

    except Exception as e:
        print(f"CloudTrail collector error: {e}")

    print("CloudTrail collector complete")


# ── Cost Collector ────────────────────────────────────────────

def collect_cost_anomalies():
    ce = boto3.client("ce", region_name="us-east-1")  # Cost Explorer is us-east-1 only
    sts = boto3.client("sts", region_name=settings.aws_region)
    account_id = sts.get_caller_identity()["Account"]

    try:
        from datetime import timedelta
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(days=30)

        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": str(start), "End": str(end)},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
        )

        # Find services with cost > $10/day
        for result in resp.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                service = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if amount > 10:
                    from app.core.database import execute
                    execute("""
                        INSERT INTO cost_anomalies (anomaly_id, service, region, amount_usd, anomaly_date, description, collected_at)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (anomaly_id) DO UPDATE SET amount_usd = EXCLUDED.amount_usd, collected_at = NOW()
                    """, (
                        _finding_id("cost", service, result["TimePeriod"]["Start"]),
                        service, settings.aws_region, amount,
                        result["TimePeriod"]["Start"],
                        f"{service} cost ${amount:.2f} on {result['TimePeriod']['Start']}"
                    ))

    except Exception as e:
        print(f"Cost collector error: {e}")

    print("Cost collector complete")


def run_all_collectors():
    """Run all collectors — called on startup and on schedule"""
    print(f"Starting collection run at {datetime.now(timezone.utc).isoformat()}")
    for collector_fn in [collect_iam, collect_s3, collect_ec2, collect_guardduty, collect_cloudtrail, collect_cost_anomalies]:
        try:
            collector_fn()
        except Exception as e:
            print(f"Collector {collector_fn.__name__} failed: {e}")
    print("Collection run complete")
