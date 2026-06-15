# Local Demo Execution Checklist
# All three projects running on localhost

# ═══════════════════════════════════════════════════════════════
# STEP 0 — PREREQUISITES (one-time)
# ═══════════════════════════════════════════════════════════════

# Required installed on your Mac:
# - Python 3.11+  (python3 --version)
# - AWS CLI       (aws --version)
# - Docker        (docker --version) — for local PostgreSQL
# - psql client   (brew install libpq && brew link --force libpq)
# - Node.js 18+   (node --version) — for ZTNA server.js

# AWS credentials — must have Bedrock access
aws sts get-caller-identity        # Verify credentials work
aws bedrock list-foundation-models \
  --region us-east-1 \
  --query 'modelSummaries[?modelId==`anthropic.claude-3-sonnet-20240229-v1:0`]' \
  # Should return the model — if empty, request Bedrock model access first


# ═══════════════════════════════════════════════════════════════
# STEP 1 — LOCAL DATABASE (PostgreSQL + pgvector)
# ═══════════════════════════════════════════════════════════════
# OPTION A — Use Docker (fastest, recommended for local dev)

docker run -d \
  --name csp-postgres \
  -e POSTGRES_DB=cloud_security_platform \
  -e POSTGRES_USER=platform_admin \
  -e POSTGRES_PASSWORD=localdev123 \
  -p 5432:5432 \
  pgvector/pgvector:pg15

# Verify it's running
docker ps | grep csp-postgres
psql "host=localhost port=5432 dbname=cloud_security_platform user=platform_admin password=localdev123" -c "SELECT version();"

# OPTION B — SSH tunnel to your RDS (if you want real AWS data)
# Get RDS endpoint first:
# cd cloud-security-platform-infra/environments/dev && terraform output rds_host
# Then:
ssh -i ~/.ssh/cloud-security-platform \
  -L 5432:YOUR_RDS_ENDPOINT:5432 \
  ec2-user@YOUR_EC2_IP \
  -N &
# Now localhost:5432 → RDS


# ═══════════════════════════════════════════════════════════════
# STEP 2 — DATABASE INITIALISATION
# ═══════════════════════════════════════════════════════════════

psql "host=localhost port=5432 dbname=cloud_security_platform user=platform_admin password=localdev123" << 'SQL'

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Governance Copilot tables
CREATE TABLE IF NOT EXISTS findings (
    id           SERIAL PRIMARY KEY,
    finding_id   TEXT UNIQUE NOT NULL,
    service      TEXT NOT NULL,
    severity     TEXT,
    title        TEXT NOT NULL,
    description  TEXT,
    resource_id  TEXT,
    region       TEXT,
    account_id   TEXT,
    raw_data     JSONB,
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    embedding    vector(1536)
);
CREATE INDEX IF NOT EXISTS findings_embedding_idx ON findings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS findings_service_idx ON findings (service);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);

CREATE TABLE IF NOT EXISTS cost_anomalies (
    id           SERIAL PRIMARY KEY,
    anomaly_id   TEXT UNIQUE,
    service      TEXT,
    region       TEXT,
    amount_usd   NUMERIC(10,2),
    expected_usd NUMERIC(10,2),
    anomaly_date DATE,
    description  TEXT,
    collected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS governance_chat_history (
    id         SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Discovery Copilot tables
CREATE TABLE IF NOT EXISTS discovery_sessions (
    id           TEXT PRIMARY KEY,
    company_name TEXT NOT NULL DEFAULT 'Prospect',
    industry     TEXT,
    company_size TEXT,
    scenario_id  TEXT,
    status       TEXT DEFAULT 'discovery',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS discovery_messages (
    id         SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS gap_analysis_results (
    id                 SERIAL PRIMARY KEY,
    session_id         TEXT NOT NULL,
    gaps               JSONB NOT NULL DEFAULT '[]',
    maturity_scores    JSONB NOT NULL DEFAULT '{}',
    overall_risk_level TEXT,
    compliance_status  JSONB NOT NULL DEFAULT '{}',
    generated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recommendation_results (
    id              SERIAL PRIMARY KEY,
    session_id      TEXT NOT NULL,
    recommendations JSONB NOT NULL DEFAULT '[]',
    generated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vendor_capabilities (
    id                        SERIAL PRIMARY KEY,
    vendor                    TEXT NOT NULL,
    domain                    TEXT NOT NULL,
    capability                TEXT NOT NULL,
    description               TEXT,
    fits_when                 TEXT,
    not_fits_when             TEXT,
    cost_tier                 TEXT,
    implementation_complexity TEXT,
    embedding                 vector(1536)
);

CREATE TABLE IF NOT EXISTS advanced_analysis (
    id            SERIAL PRIMARY KEY,
    session_id    TEXT NOT NULL,
    analysis_type TEXT NOT NULL,
    result        JSONB NOT NULL,
    generated_at  TIMESTAMPTZ DEFAULT NOW()
);

SELECT 'Database ready' AS status;
SQL


# ═══════════════════════════════════════════════════════════════
# STEP 3 — ENVIRONMENT FILES
# ═══════════════════════════════════════════════════════════════

# Governance Copilot .env
cat > ~/repos/aws-governance-copilot/.env << 'ENV'
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cloud_security_platform
DB_USER=platform_admin
DB_PASSWORD=localdev123
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0
OPENROUTER_API_KEY=sk-or-v1-YOUR_KEY_HERE
S3_CACHE_BUCKET=
ENV

# Discovery Copilot .env
cat > ~/repos/security-discovery-copilot/backend/.env << 'ENV'
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cloud_security_platform
DB_USER=platform_admin
DB_PASSWORD=localdev123
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0
OPENROUTER_API_KEY=sk-or-v1-YOUR_KEY_HERE
FRONTEND_URL=http://localhost:3000
ENV


# ═══════════════════════════════════════════════════════════════
# STEP 4 — INSTALL DEPENDENCIES
# ═══════════════════════════════════════════════════════════════

# Governance Copilot
cd ~/repos/aws-governance-copilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
deactivate

# Discovery Copilot
cd ~/repos/security-discovery-copilot/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
deactivate


# ═══════════════════════════════════════════════════════════════
# STEP 5 — LOAD DEMO DATA (Governance Copilot)
# ═══════════════════════════════════════════════════════════════
# Run the Python demo data seeder (created separately — see seed_demo_data.py)

cd ~/repos/aws-governance-copilot
source .venv/bin/activate
python seed_demo_data.py
deactivate


# ═══════════════════════════════════════════════════════════════
# STEP 6 — START ALL THREE PROJECTS
# ═══════════════════════════════════════════════════════════════
# Open 3 terminal tabs

# TAB 1 — Governance Copilot backend
cd ~/repos/aws-governance-copilot
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# → http://localhost:8000/api/docs

# TAB 2 — Discovery Copilot backend
cd ~/repos/security-discovery-copilot/backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
# → http://localhost:8001/api/docs

# TAB 3 — ZTNA Simulator
cd ~/repos/ztna-simulator
python3 serve.py
# → http://localhost:8080/

# Frontends:
# Governance:  open frontend/index.html in browser, set API to http://localhost:8000
# Discovery:   open frontend/index.html in browser, set API to http://localhost:8001
# ZTNA:        http://localhost:8080/ (already the full app)


# ═══════════════════════════════════════════════════════════════
# VERIFY ALL RUNNING
# ═══════════════════════════════════════════════════════════════

curl http://localhost:8000/health   # → {"status":"healthy","service":"governance-copilot"}
curl http://localhost:8001/health   # → {"status":"healthy","service":"security-discovery-copilot"}
curl http://localhost:8080/         # → 200 HTML
