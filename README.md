# AWS Security & Cost Governance Copilot

> **Natural language interface over real AWS infrastructure.** Ask "which IAM users haven't logged in for 90 days?" or "why did our bill spike?" and get answers grounded in live AWS data.

Live demo: **[ishwaryaaunfiltered.live/copilot](https://ishwaryaaunfiltered.live/copilot)**  
Built by [Ishwarya Chengalvarayan](https://github.com/IshwaryaLakshmiC)

---

## What it does

Collectors poll 6 AWS services every 15 minutes and store findings in PostgreSQL + pgvector. The chat interface runs semantic search over findings and uses Claude via AWS Bedrock to generate answers with source citations.

| Service | What it collects |
|---------|-----------------|
| IAM | Inactive users, no MFA, old access keys, root account issues |
| S3 | Public buckets, missing encryption, no versioning |
| EC2 | Open security group ports, IMDSv1 instances |
| GuardDuty | Active threat findings (medium+) |
| CloudTrail | Suspicious API calls in last 24 hours |
| Cost Explorer | Daily spend by service, anomalies |

---

## Infrastructure

Deployed on AWS via [cloud-security-platform-infra](https://github.com/IshwaryaLakshmiC/cloud-security-platform-infra):
- EC2 t2.micro (free tier) — app server
- RDS PostgreSQL 15 + pgvector — findings store
- AWS Bedrock — Claude Sonnet + Titan Embeddings
- EC2 IAM role — read-only access to all collected services

---

## Deployment

```bash
# On EC2 after terraform apply
git clone https://github.com/IshwaryaLakshmiC/aws-governance-copilot /opt/governance-copilot
cd /opt/governance-copilot
pip3.11 install -r requirements.txt
sudo systemctl enable --now governance-copilot

# Access at
curl http://YOUR_EC2_IP/governance/health
```

---

**Ishwarya Chengalvarayan** · [ishwaryaaunfiltered.live](https://ishwaryaaunfiltered.live)
