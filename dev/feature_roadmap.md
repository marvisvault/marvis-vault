# Marvis Vault OSS - Feature Development Roadmap

## Current State vs Future Vision

### OSS Features (Implemented)
- Policy engine (mask, simulate)
- Full CLI + Python SDK
- Audit logging system
- Policy templates (GDPR, PII, healthcare, finance)
- Condition evaluation engine
- JSON/text redaction
- Role-based access control

### Vault Plus Features (Commercial - To Build)
- Hosted API (FastAPI)
- Secure role-based unmasking
- Interactive TUI playground
- Telemetry + usage analytics
- Policy Marketplace

## Development Priorities

### Phase 1: Core Vault Plus Foundation (MVP)

#### 1.1 FastAPI Server (`vault-server/`)
**Priority**: HIGH
**Effort**: 2-3 weeks

```
vault-server/
├── app/
│   ├── main.py              # FastAPI app
│   ├── routers/
│   │   ├── redact.py        # POST /redact
│   │   ├── simulate.py      # POST /simulate  
│   │   ├── policies.py      # CRUD /policies
│   │   └── audit.py         # GET /audit
│   ├── models/
│   │   ├── requests.py      # Pydantic request models
│   │   └── responses.py     # Pydantic response models
│   └── security/
│       ├── auth.py          # API key auth
│       └── rate_limit.py    # Rate limiting
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── requirements.txt
```

**Key Endpoints**:
```python
POST /api/v1/redact
POST /api/v1/simulate
GET  /api/v1/policies
POST /api/v1/policies
GET  /api/v1/audit
POST /api/v1/unmask  # Premium feature
```

#### 1.2 Enhanced Unmasking System
**Priority**: HIGH
**Effort**: 1-2 weeks

Current OSS unmask is basic - enhance with:
- **Secure key management**: Encrypted original value storage
- **Time-limited access**: Temporary unmasking tokens
- **Audit integration**: Detailed unmask logging
- **Role hierarchies**: Granular permission levels

```python
# vault/sdk/unmask_plus.py
class SecureUnmaskService:
    def generate_unmask_token(self, user_id: str, fields: List[str], ttl: int) -> str
    def unmask_with_token(self, token: str, redacted_data: str) -> str
    def revoke_token(self, token: str) -> bool
```

#### 1.3 Usage Analytics & Telemetry
**Priority**: MEDIUM
**Effort**: 1-2 weeks

```
vault/analytics/
├── collector.py             # Event collection
├── metrics.py              # Usage metrics
├── dashboard.py            # Analytics dashboard
└── exporters/
    ├── prometheus.py       # Prometheus metrics
    └── datadog.py         # DataDog integration
```

**Metrics to Track**:
- Policy evaluation frequency
- Field access patterns
- Role usage statistics
- Performance metrics
- Error rates

### Phase 2: Interactive Features

#### 2.1 TUI Playground (`vault-tui/`)
**Priority**: MEDIUM
**Effort**: 2-3 weeks

Interactive terminal UI using Rich/Textual:
```python
# vault-tui/app.py
class VaultTUI(App):
    def compose(self) -> ComposeResult:
        yield PolicyEditor()
        yield DataPreview()
        yield SimulationResults()
        yield AuditViewer()
```

**Features**:
- Live policy editing with syntax highlighting
- Real-time simulation preview
- Interactive audit log browser
- Policy template gallery

#### 2.2 Policy Marketplace
**Priority**: LOW
**Effort**: 3-4 weeks

Community policy sharing platform:
```
marketplace/
├── backend/
│   ├── fastapi_app/         # API for marketplace
│   ├── database/           # Policy storage
│   └── search/             # Policy search/discovery
├── frontend/
│   ├── react_app/          # Web interface
│   └── cli_integration/    # CLI marketplace commands
└── policies/
    ├── community/          # User-contributed
    ├── verified/           # Marvis-verified
    └── premium/            # Commercial policies
```

### Phase 3: Enterprise Features

#### 3.1 Multi-Tenant Support
**Priority**: MEDIUM
**Effort**: 2-3 weeks

- Tenant isolation for SaaS deployment
- Per-tenant policy management
- Usage quotas and billing
- Tenant-specific audit logs

#### 3.2 Advanced Integrations
**Priority**: LOW
**Effort**: 1-2 weeks each

```python
# vault/integrations/
├── langchain.py            # LangChain integration
├── openai.py              # OpenAI API wrapper
├── anthropic.py           # Claude integration
├── huggingface.py         # HF Transformers
└── frameworks/
    ├── llamaindex.py      # LlamaIndex
    ├── haystack.py        # Haystack
    └── crewai.py          # CrewAI
```

## Detailed Implementation Plans

### FastAPI Server Implementation

#### Directory Structure
```
vault-server/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── dependencies.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── redact.py
│   │   ├── simulate.py
│   │   ├── policies.py
│   │   ├── audit.py
│   │   └── health.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── requests.py
│   │   ├── responses.py
│   │   └── schemas.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── redaction.py
│   │   ├── policy.py
│   │   └── audit.py
│   └── security/
│       ├── __init__.py
│       ├── auth.py
│       └── rate_limit.py
├── tests/
│   ├── test_routers/
│   ├── test_services/
│   └── test_security/
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.prod.yml
├── scripts/
│   ├── start.sh
│   └── deploy.sh
├── requirements.txt
└── README.md
```

#### Key Files Content

**app/main.py**:
```python
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from .routers import redact, simulate, policies, audit, health
from .security.auth import get_api_key

app = FastAPI(
    title="Marvis Vault Plus API",
    description="Programmable compliance infrastructure for AI",
    version="1.0.0"
)

app.add_middleware(CORSMiddleware, allow_origins=["*"])

app.include_router(health.router, prefix="/health")
app.include_router(redact.router, prefix="/api/v1", dependencies=[Depends(get_api_key)])
app.include_router(simulate.router, prefix="/api/v1", dependencies=[Depends(get_api_key)])
app.include_router(policies.router, prefix="/api/v1", dependencies=[Depends(get_api_key)])
app.include_router(audit.router, prefix="/api/v1", dependencies=[Depends(get_api_key)])
```

**app/routers/redact.py**:
```python
from fastapi import APIRouter, HTTPException
from ..models.requests import RedactRequest
from ..models.responses import RedactResponse
from ..services.redaction import RedactionService

router = APIRouter()

@router.post("/redact", response_model=RedactResponse)
async def redact_data(request: RedactRequest):
    try:
        service = RedactionService()
        result = service.redact(request.content, request.policy)
        return RedactResponse(
            content=result.content,
            redacted_fields=result.redacted_fields,
            audit_log=result.audit_log
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

### TUI Implementation Plan

#### Core Components
```python
# vault-tui/components/
├── policy_editor.py        # Rich text editor for policies
├── data_preview.py         # JSON/text data viewer
├── simulation_panel.py     # Live simulation results
├── audit_browser.py        # Audit log viewer
└── template_gallery.py    # Policy template browser
```

**Key Features**:
- **Syntax Highlighting**: JSON/YAML policy editing
- **Live Preview**: Real-time simulation as you type
- **File Browser**: Navigate and load policies/data
- **Export Options**: Save policies, export results

#### Sample TUI Layout
```
┌─ Marvis Vault TUI ──────────────────────────────────────────────────────────┐
│ [File] [Edit] [View] [Tools] [Help]                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ ┌─ Policy Editor ──────────────┐ ┌─ Data Preview ─────────────────────────┐ │
│ │ {                            │ │ {                                      │ │
│ │   "mask": ["ssn", "cc"],     │ │   "name": "John Doe",                  │ │
│ │   "unmask_roles": ["admin"], │ │   "ssn": "[REDACTED]",                 │ │
│ │   "conditions": [            │ │   "cc": "[REDACTED]"                   │ │
│ │     "role == 'admin'"        │ │ }                                      │ │
│ │   ]                          │ │                                        │ │
│ │ }                            │ │                                        │ │
│ └──────────────────────────────┘ └────────────────────────────────────────┘ │
│ ┌─ Simulation Results ─────────┐ ┌─ Audit Log ──────────────────────────┐ │
│ │ Policy Valid              │ │ 2024-01-15 10:30:21 - MASK - ssn     │ │
│ │ Fields Masked: ssn, cc    │ │ 2024-01-15 10:30:21 - MASK - cc      │ │
│ │ Role: admin (allowed)     │ │ 2024-01-15 10:30:22 - UNMASK - ssn   │ │
│ │ Conditions: 1/1 passed    │ │                                      │ │
│ └──────────────────────────────┘ └────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│ Ready | Ctrl+O: Open | Ctrl+S: Save | Ctrl+T: Test | F1: Help              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Wins & Low-Hanging Fruit

### 1. Enhanced CLI Commands (1-2 days each)
```bash
vault diff policy1.json policy2.json           # Policy comparison
vault validate --input data.json --policy p.json  # Data validation
vault export --format csv --output report.csv     # Export audit data
vault templates list                            # List available templates
vault templates install gdpr-full              # Install from marketplace
```

### 2. Docker Support (1-2 days)
```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY vault/ vault/
COPY setup.py .
RUN pip install -e .

EXPOSE 8000
CMD ["uvicorn", "vault-server.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 3. GitHub Actions CI/CD (1 day)
```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -v
      - run: black --check vault/
      - run: mypy vault/
```

### 4. More Policy Templates (1-2 days)
```json
# vault/templates/hipaa-full.json
# vault/templates/gdpr-full.json  
# vault/templates/ccpa-basic.json
# vault/templates/sox-compliance.json
# vault/templates/custom-finance.json
```

## Resource Requirements

### Development Team Sizing
- **Phase 1 (MVP)**: 2-3 developers, 6-8 weeks
- **Phase 2 (Interactive)**: 2-3 developers, 8-10 weeks  
- **Phase 3 (Enterprise)**: 3-4 developers, 10-12 weeks

### Technical Skills Needed
- **Backend**: Python, FastAPI, async programming
- **Frontend**: React/Vue (for marketplace), Rich/Textual (for TUI)
- **DevOps**: Docker, CI/CD, monitoring
- **Security**: Authentication, encryption, secure storage

### Infrastructure Requirements
- **Development**: Local development environments
- **Staging**: Docker-based staging environment
- **Production**: Cloud deployment (AWS/GCP/Azure)
- **Monitoring**: Logging, metrics, alerting

## Success Metrics

### Technical Metrics
- **API Performance**: <100ms p95 response time
- **Uptime**: 99.9% availability
- **Test Coverage**: >90% code coverage
- **Security**: Zero known vulnerabilities

### Business Metrics
- **User Adoption**: Active users/month
- **API Usage**: Requests per day
- **Policy Creation**: New policies/week
- **Community Growth**: Marketplace contributions

## Risk Mitigation

### Technical Risks
- **Performance**: Load testing with large policies/data
- **Security**: Regular security audits and penetration testing
- **Compatibility**: Ensure backward compatibility with OSS

### Business Risks
- **Market Fit**: Validate enterprise features with beta customers
- **Competition**: Monitor competitive landscape
- **Open Source**: Maintain clear OSS vs Plus boundaries

This roadmap provides a clear path from the current working OSS implementation to a comprehensive commercial platform while maintaining the open-source foundation.