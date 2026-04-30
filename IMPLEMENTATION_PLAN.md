# IACyber — Implementation Plan Completo

> AI-powered Cybersecurity & Threat Detection Platform
> Versione 2.0 — Aprile 2026
> Stack: Java 21 + Spring Boot 3 · Angular 17 · Kafka · OpenSearch

---

## Visione del Prodotto

**IACyber** è una piattaforma SaaS multi-tenant di AI-powered Cybersecurity e Threat Detection con capacità predittiva sulle vulnerabilità, scansione statica del codice sorgente e integrazione Git nativa per remediation automatica. Vendibile a MSSP, enterprise e PMI.

**Differenziatori chiave vs concorrenza:**
- Predice vulnerabilità *prima* che vengano pubblicate (ML su pattern CVE)
- Scansiona il codice dei clienti (SAST) e apre PR con il fix direttamente su GitHub/GitLab
- AI analyst spiega ogni alert in linguaggio naturale con remediation step-by-step

---

## 1. Architettura C4 — Contesto Sistema

```mermaid
graph TD
    subgraph Clienti["Clienti / Tenant"]
        SOC["SOC Analyst"]
        CISO["CISO / Manager"]
        DEV["Developer\n(riceve PR con fix)"]
        API_CLIENT["Sistemi via API REST"]
    end

    subgraph IACyber["Piattaforma IACyber — Spring Cloud Microservices"]
        GW["API Gateway\nSpring Cloud Gateway"]
        AUTH["Auth Service\nSpring Security + Keycloak"]
        INGEST["Ingestion Engine\nSpring Kafka Streams"]
        ML["AI/ML Engine\nSpring AI + Python sidecar"]
        SIEM["SIEM Core\nOpenSearch + Spring Data"]
        RESP["Response Orchestrator\nSpring Batch + State Machine"]
        DASH["Dashboard SOC\nAngular 17"]
        REPORT["Compliance Reporter\nSpring Boot + JasperReports"]
        VULN["Vulnerability Scanner\nSpring Boot + Nuclei/OpenVAS"]
        INTEL["Threat Intelligence\nMISP + Spring Integration"]
        CODESCAN["Code Scanner SAST\nSpring Boot + Semgrep/CodeQL"]
        PREDICT["Predictive Engine\nSpring AI + ML models"]
        GITINT["Git Integration Service\nSpring Boot + JGit"]
    end

    subgraph External["Sistemi Esterni"]
        MITRE["MITRE ATT&CK"]
        NVD["NVD / CVE DB"]
        FEEDS["TI Feeds AlienVault/Shodan"]
        GITHUB["GitHub / GitLab / Bitbucket"]
        JIRA["Jira / ServiceNow"]
        SLACK["Slack / Teams"]
        CLOUD["AWS/Azure/GCP logs"]
        SONAR["SonarQube (opzionale)"]
    end

    SOC --> DASH
    CISO --> DASH
    DEV --> GITHUB
    API_CLIENT --> GW
    GW --> AUTH
    GW --> INGEST
    GW --> CODESCAN
    GW --> PREDICT
    INGEST --> SIEM
    INGEST --> ML
    ML --> RESP
    SIEM --> ML
    INTEL --> ML
    ML --> DASH
    PREDICT --> DASH
    CODESCAN --> GITINT
    GITINT --> GITHUB
    RESP --> JIRA
    RESP --> SLACK
    REPORT --> DASH
    VULN --> NVD
    INTEL --> MITRE
    INTEL --> FEEDS
    CLOUD --> INGEST
    CODESCAN --> SONAR
```

---

## 2. Flusso Dati — Threat Detection End-to-End

```mermaid
sequenceDiagram
    participant SRC as Source (Agent/Cloud/API)
    participant KAFKA as Apache Kafka
    participant NORM as Normalizer (Spring Kafka)
    participant ES as OpenSearch
    participant ML as ML Engine (Spring AI)
    participant INTEL as Threat Intelligence
    participant CORR as Correlation Engine
    participant RESP as Response Orchestrator
    participant SOC as Angular Dashboard
    participant TICK as Jira / ServiceNow

    SRC->>KAFKA: Raw events (CEF/JSON/Syslog)
    KAFKA->>NORM: @KafkaListener consume
    NORM->>NORM: Parse + normalize → ECS schema
    NORM->>ES: Index via Spring Data OpenSearch
    NORM->>ML: Forward scored event

    ML->>INTEL: Enrich IoC/TTP lookup (REST)
    INTEL-->>ML: MITRE mapping + IoC match
    ML->>ML: Anomaly score + classification
    ML->>CORR: Send scored event

    CORR->>CORR: Sigma rules + ML correlation
    CORR->>ES: Save Alert/Incident
    CORR->>SOC: Push via WebSocket (Spring WebFlux)
    CORR->>RESP: Trigger Spring State Machine playbook

    RESP->>TICK: Create ticket via REST
    RESP->>SOC: Update incident timeline
    RESP-->>SRC: Block IP / Isolate (opzionale)

    SOC->>ES: Forensic query
    SOC->>RESP: Analyst approve/escalate
```

---

## 3. Flusso — Predictive Vulnerability Engine

```mermaid
sequenceDiagram
    participant ASSET as Asset Inventory
    participant NVD as NVD / CVE DB
    participant GITHUB_ADV as GitHub Advisory DB
    participant PRED as Predictive Engine (Spring AI)
    participant ML as ML Models (Python sidecar)
    participant SOC as Angular Dashboard
    participant GITINT as Git Integration Service
    participant REPO as Cliente GitHub/GitLab

    ASSET->>PRED: Lista software/librerie in uso (SBOM)
    NVD->>PRED: CVE storici + trend (scheduled pull)
    GITHUB_ADV->>PRED: Advisory + patch info

    PRED->>ML: Analisi pattern: vendor, versione, categoria, storico CVE
    ML->>ML: Time-series forecasting vulnerabilità
    ML->>ML: Similarity scoring vs CVE storici
    ML-->>PRED: Risk score predittivo per ogni componente

    PRED->>SOC: "Alta probabilità CVE su Log4j-core 2.x entro 30gg"
    PRED->>GITINT: Richiedi analisi codice impattato

    GITINT->>REPO: Scan dipendenze (pom.xml, package.json)
    GITINT->>GITINT: Identifica file/classi che usano il componente
    GITINT->>REPO: Apre PR automatica con fix (upgrade versione + test)
    REPO-->>SOC: Link PR creata per review developer
```

---

## 4. Flusso — Code Scanner SAST + Git Fix

```mermaid
sequenceDiagram
    participant DEV as Developer / CI Pipeline
    participant GITINT as Git Integration (Spring Boot + JGit)
    participant REPO as GitHub / GitLab
    participant SCAN as SAST Engine (Semgrep + CodeQL)
    participant AI as AI Analyst (Spring AI + LLM)
    participant SOC as Angular Dashboard
    participant JIRA as Jira

    DEV->>GITINT: Webhook push / PR opened
    GITINT->>REPO: Clone / diff fetch (JGit)
    GITINT->>SCAN: Submit code per analisi SAST

    SCAN->>SCAN: Analisi pattern: SQLi, XSS, IDOR,\nHardcoded secrets, RCE, SSRF...
    SCAN->>SCAN: Dependency check (OWASP DC)
    SCAN-->>GITINT: Finding list con file:line + CWE + CVSS

    GITINT->>AI: "Spiega vulnerability + genera fix"
    AI-->>GITINT: Explanation + codice corretto + test suggerito
    GITINT->>REPO: Commit fix su branch + apri PR\ncon link a CWE, OWASP, CVE reference
    GITINT->>JIRA: Crea ticket con severity + link PR

    GITINT->>SOC: Alert SAST con dettaglio
    SOC->>SOC: Analyst review finding + approva PR
```

---

## 5. Modello Dati Core

```mermaid
erDiagram
    TENANT {
        uuid id PK
        string name
        string tier
        string region
        jsonb config
        timestamp created_at
    }
    USER {
        uuid id PK
        uuid tenant_id FK
        string email
        string role
        string[] permissions
        timestamp last_login
    }
    EVENT {
        uuid id PK
        uuid tenant_id FK
        string source_type
        string raw_log
        jsonb normalized
        float severity_score
        string[] mitre_tactics
        timestamp ingested_at
    }
    ALERT {
        uuid id PK
        uuid tenant_id FK
        string type
        string status
        float confidence
        string[] event_ids
        jsonb context
        timestamp triggered_at
    }
    INCIDENT {
        uuid id PK
        uuid tenant_id FK
        uuid alert_id FK
        string severity
        string status
        string assignee_id
        jsonb timeline
        timestamp created_at
        timestamp resolved_at
    }
    ASSET {
        uuid id PK
        uuid tenant_id FK
        string hostname
        string ip
        string os
        jsonb sbom
        float risk_score
        float predicted_risk_score
        timestamp last_scanned
    }
    CODE_FINDING {
        uuid id PK
        uuid tenant_id FK
        string repo_url
        string file_path
        int line_number
        string cwe_id
        string cve_ref
        float cvss_score
        string severity
        text description
        text ai_fix
        string git_pr_url
        string status
        timestamp detected_at
    }
    PREDICTED_VULN {
        uuid id PK
        uuid tenant_id FK
        uuid asset_id FK
        string component
        string version
        float probability_score
        string prediction_basis
        string[] affected_repos
        timestamp predicted_at
        timestamp expires_at
    }
    PLAYBOOK {
        uuid id PK
        uuid tenant_id FK
        string name
        jsonb trigger_conditions
        jsonb actions
        bool active
    }
    IOC {
        uuid id PK
        string type
        string value
        string source
        float confidence
        timestamp expires_at
    }
    GIT_INTEGRATION {
        uuid id PK
        uuid tenant_id FK
        string provider
        string repo_url
        string token_ref
        bool auto_pr_enabled
        timestamp last_scan
    }
    COMPLIANCE_REPORT {
        uuid id PK
        uuid tenant_id FK
        string framework
        jsonb findings
        float score
        timestamp generated_at
    }

    TENANT ||--o{ USER : "has"
    TENANT ||--o{ EVENT : "generates"
    TENANT ||--o{ ALERT : "receives"
    TENANT ||--o{ ASSET : "owns"
    TENANT ||--o{ PLAYBOOK : "configures"
    TENANT ||--o{ GIT_INTEGRATION : "connects"
    TENANT ||--o{ CODE_FINDING : "has"
    ALERT ||--o{ INCIDENT : "escalates to"
    ALERT }o--o{ EVENT : "correlates"
    INCIDENT ||--o{ PLAYBOOK : "triggers"
    ASSET ||--o{ PREDICTED_VULN : "has predictions"
    GIT_INTEGRATION ||--o{ CODE_FINDING : "produces"
    CODE_FINDING }o--o{ PREDICTED_VULN : "confirmed by"
```

---

## 6. Stack Tecnologico

### Separazione responsabilità

```
┌─────────────────────────────────────────────────────────────┐
│  JAVA 21 + SPRING BOOT 3                                     │
│  → API REST, business logic, orchestrazione, auth,          │
│    Kafka consumers, gateway, compliance, Git integration,    │
│    scheduling, WebSocket, tutto ciò che è "piattaforma"     │
├─────────────────────────────────────────────────────────────┤
│  PYTHON 3.12 (FastAPI — microservizi AI autonomi)           │
│  → Modelli ML, anomaly detection, predizione CVE,           │
│    SAST AI analysis, LLM orchestration, NLP, embeddings     │
│    Esposti come REST API interne, chiamati da Spring        │
└─────────────────────────────────────────────────────────────┘
```

Spring non tocca mai il codice ML — chiama Python via REST/gRPC.
Python non espone nulla all'esterno — solo endpoint interni protetti.

### Tabella Stack

| Layer | Tecnologia | Chi la gestisce |
|---|---|---|
| **API Gateway** | Spring Cloud Gateway | Java/Spring |
| **Auth & RBAC** | Spring Security + Keycloak 24 | Java/Spring |
| **Business Logic** | Spring Boot 3.3 + Spring Cloud | Java/Spring |
| **Stream Processing** | Spring Kafka (@KafkaListener) | Java/Spring |
| **SIEM Indexing** | Spring Data OpenSearch | Java/Spring |
| **Correlation Engine** | Spring Boot + Sigma rules | Java/Spring |
| **Response Orchestrator** | Spring State Machine + Spring Batch | Java/Spring |
| **Git Integration** | Spring Boot + JGit + GitHub API | Java/Spring |
| **Compliance Reporter** | Spring Boot + JasperReports | Java/Spring |
| **Notification Service** | Spring Boot + Spring Mail/Slack SDK | Java/Spring |
| **Vulnerability Scanner** | Spring Boot (orchestratore Nuclei/OpenVAS) | Java/Spring |
| **--- AI/ML boundary ---** | **tutto sotto è Python** | |
| **Anomaly Detection API** | Python FastAPI + Isolation Forest/Autoencoder | Python |
| **Threat Classifier API** | Python FastAPI + XGBoost (MITRE ATT&CK) | Python |
| **Predictive CVE API** | Python FastAPI + LSTM + time-series | Python |
| **SAST AI Analyzer API** | Python FastAPI + CodeBERT + LLM | Python |
| **NLP Analyst API** | Python FastAPI + LangChain + Claude/GPT-4 | Python |
| **Embedding Service** | Python FastAPI + sentence-transformers | Python |
| **--- Storage & Infra ---** | | |
| **SIEM Storage** | OpenSearch | Infra |
| **Database** | PostgreSQL 16 + TimescaleDB | Infra |
| **Cache** | Redis | Infra |
| **Message Broker** | Apache Kafka 3.7 | Infra |
| **Frontend** | Angular 17 (Standalone Components) | Frontend |
| **UI Components** | Angular Material + ECharts | Frontend |
| **Real-time UI** | Angular STOMP over WebSocket | Frontend |
| **Orchestration** | Kubernetes + Helm | DevOps |
| **IaC** | Terraform | DevOps |
| **CI/CD** | GitHub Actions + ArgoCD | DevOps |
| **Build Java** | Maven 3.9 multi-module | DevOps |
| **Build Python** | Poetry + Docker | DevOps |
| **Monitoring** | Micrometer (Java) + Prometheus + Grafana | DevOps |
| **Secret Mgmt** | HashiCorp Vault | DevOps |
| **Service Mesh** | Istio (mTLS) | DevOps |

---

## 7. Struttura Monorepo

```
IACyber/
│
│  ══════════════════════════════════════
│  JAVA — Spring Boot (API & Platform)
│  ══════════════════════════════════════
├── pom.xml                              # Parent POM — BOM Spring Boot 3.3
├── spring-services/
│   ├── gateway-service/                 # Spring Cloud Gateway — routing, JWT, rate limit
│   ├── auth-service/                    # Spring Security + Keycloak adapter
│   ├── ingestion-service/               # @KafkaListener, ECS normalizer, log parsing
│   ├── siem-service/                    # OpenSearch indexing + Sigma rule execution
│   ├── correlation-service/             # Alert correlation (Spring State Machine)
│   ├── ai-orchestrator-service/         # Chiama Python AI APIs — NON contiene ML
│   │   └── client/
│   │       ├── AnomalyDetectionClient   # Feign → Python anomaly-api
│   │       ├── ThreatClassifierClient   # Feign → Python classifier-api
│   │       ├── PredictiveCveClient      # Feign → Python predictive-api
│   │       └── NlpAnalystClient         # Feign → Python nlp-api
│   ├── threat-intel-service/            # MISP client + feed aggregator + IoC lookup
│   ├── vuln-scanner-service/            # Orchestratore Nuclei/OpenVAS (CLI wrapper)
│   ├── code-scanner-service/            # Orchestratore Semgrep/CodeQL — chiama Python per AI fix
│   ├── git-integration-service/         # JGit + GitHub/GitLab API + PR automation
│   ├── response-orchestrator/           # Playbook engine + Spring Batch
│   ├── compliance-service/              # NIS2/ISO27001/GDPR — JasperReports PDF
│   └── notification-service/           # Slack, Teams, Email, PagerDuty
│
│  ══════════════════════════════════════
│  PYTHON — AI/ML Services (FastAPI)
│  ══════════════════════════════════════
├── python-ai/
│   ├── anomaly-detection-api/           # FastAPI — Isolation Forest + Autoencoder (UEBA)
│   │   ├── main.py
│   │   ├── models/isolation_forest.py
│   │   ├── models/autoencoder.py
│   │   └── pyproject.toml              # Poetry
│   ├── threat-classifier-api/           # FastAPI — XGBoost MITRE ATT&CK classifier
│   │   ├── main.py
│   │   ├── models/xgboost_classifier.py
│   │   └── training/train.py
│   ├── predictive-cve-api/              # FastAPI — LSTM CVE forecasting + risk scoring
│   │   ├── main.py
│   │   ├── models/lstm_forecaster.py
│   │   ├── models/codebert_similarity.py
│   │   └── data/nvd_fetcher.py
│   ├── sast-ai-api/                     # FastAPI — AI code analysis + fix generation
│   │   ├── main.py
│   │   ├── analyzer/cwe_detector.py
│   │   ├── fixer/patch_generator.py    # LangChain + LLM
│   │   └── embeddings/code_embedder.py
│   └── nlp-analyst-api/                 # FastAPI — Alert summarization + remediation (LLM)
│       ├── main.py
│       ├── chains/alert_chain.py       # LangChain RAG su knowledge base MITRE
│       └── chains/remediation_chain.py
│
│  ══════════════════════════════════════
│  FRONTEND — Angular 17
│  ══════════════════════════════════════
├── frontend/
│   └── soc-dashboard/
│       ├── src/app/
│       │   ├── core/                   # Auth, guards, HTTP interceptors, WebSocket
│       │   ├── features/
│       │   │   ├── dashboard/          # SOC overview + KPI widgets
│       │   │   ├── alerts/             # Alert list realtime + MITRE detail
│       │   │   ├── incidents/          # Case management + forensic timeline
│       │   │   ├── assets/             # Inventory + SBOM + risk score
│       │   │   ├── code-scan/          # SAST findings + diff viewer + PR link
│       │   │   ├── predictions/        # Predicted CVE + probability ECharts
│       │   │   ├── threat-intel/       # IoC explorer + TTP heatmap
│       │   │   ├── compliance/         # NIS2 / ISO27001 / GDPR reports
│       │   │   └── playbooks/          # Visual playbook builder
│       │   └── shared/                 # Components, pipes, models TypeScript
│       └── package.json
│
│  ══════════════════════════════════════
│  INFRA & DevOps
│  ══════════════════════════════════════
├── infra/
│   ├── terraform/                       # VPC, EKS, RDS, MSK, ElastiCache, Vault
│   ├── helm/                            # Chart separato per ogni servizio
│   └── kubernetes/                      # Namespace, RBAC, NetworkPolicy, Istio
├── docs/
│   ├── api/                             # OpenAPI 3.1 (generati da Spring + FastAPI)
│   ├── architecture/                    # ADR — Architecture Decision Records
│   └── compliance/                      # Framework mappings NIS2/ISO/GDPR
└── .github/
    └── workflows/
        ├── ci-java.yml                  # Maven build + JUnit + SpotBugs + Trivy
        ├── ci-python.yml                # Poetry + pytest + Bandit + Safety
        ├── ci-angular.yml               # npm + Karma + ESLint + Playwright
        └── deploy.yml                   # ArgoCD sync trigger
```

---

## 8. Predictive Vulnerability Engine — Dettaglio

Questo è il modulo più innovativo della piattaforma. Predice vulnerabilità **prima** che vengano pubblicate o sfruttate.

```mermaid
graph TD
    subgraph INPUT["Fonti Dati"]
        NVD["NVD CVE storico\n(15 anni di dati)"]
        GH_ADV["GitHub Advisory DB"]
        EXPLOIT_DB["Exploit-DB / PoC-in-GitHub"]
        SBOM["SBOM Asset\n(librerie in uso)"]
        CODE_HIST["Git commit history\n(pattern di fix)"]
        DARK["Dark Web feeds\n(exploit menzionati)"]
    end

    subgraph FEATURE["Feature Engineering"]
        F1["Vendor track record\n(CVE frequency per vendor)"]
        F2["Component age +\nultimo aggiornamento"]
        F3["Categoria CWE prevalente\nper libreria"]
        F4["Dipendenze transitive\na rischio"]
        F5["Exploit availability\ntemporale"]
        F6["Similarità codice vs\npattern vulnerabili noti"]
    end

    subgraph MODELS["Modelli Predittivi"]
        LSTM["LSTM Time-series\n(quando uscirà CVE?)"]
        XGB["XGBoost Classifier\n(che tipo di vuln?)"]
        EMBED["Code Embedding\n(CodeBERT similarity)"]
        ENSEMBLE["Ensemble Score\n(probabilità + severità attesa)"]
    end

    subgraph OUTPUT["Output Actionable"]
        ALERT_PRED["Alert predittivo\n30/60/90 giorni"]
        PR_AUTO["PR automatica:\nUpgrade dipendenza"]
        PATCH_GUIDE["Guida patch\nstep-by-step (LLM)"]
        RISK_SCORE["Risk score\nper asset aggiornato"]
    end

    NVD --> F1
    GH_ADV --> F3
    EXPLOIT_DB --> F5
    SBOM --> F4
    CODE_HIST --> F6
    DARK --> F5

    F1 --> LSTM
    F2 --> LSTM
    F3 --> XGB
    F4 --> XGB
    F5 --> ENSEMBLE
    F6 --> EMBED
    EMBED --> ENSEMBLE
    LSTM --> ENSEMBLE
    XGB --> ENSEMBLE

    ENSEMBLE --> ALERT_PRED
    ENSEMBLE --> PR_AUTO
    ENSEMBLE --> PATCH_GUIDE
    ENSEMBLE --> RISK_SCORE
```

**Accuracy target:** > 70% delle vulnerabilità HIGH/CRITICAL predette correttamente entro 90 giorni dalla pubblicazione CVE reale (validato su dataset storico NVD 2015-2024).

---

## 9. Code Scanner SAST — Regole e Copertura

| Categoria | Tool | Linguaggi | CWE coperte |
|---|---|---|---|
| **Injection** | Semgrep | Java, JS, Python, Go, PHP | CWE-89, 78, 917 |
| **XSS** | Semgrep + CodeQL | Java, JS, TS | CWE-79, 80 |
| **Broken Auth** | Semgrep custom rules | Java Spring, Node | CWE-287, 384 |
| **Hardcoded Secrets** | Semgrep + Trufflehog | All | CWE-798 |
| **SSRF** | CodeQL | Java, Python | CWE-918 |
| **Insecure Deser.** | CodeQL | Java | CWE-502 |
| **Path Traversal** | Semgrep | Java, Python | CWE-22 |
| **Dep. Vulnerabilities** | OWASP DC + Trivy | Maven, npm, pip | NVD CVE |
| **Crypto weak** | Semgrep | Java, Python | CWE-326, 327 |
| **Race Conditions** | CodeQL | Java | CWE-362 |

### Git Fix Automation — Come funziona

1. **Finding trovato** → AI genera spiegazione + fix code patch
2. **JGit crea branch** `iacyber/fix/CWE-89-UserRepo-L42`
3. **Commit patch** con messaggio strutturato: `fix(security): CWE-89 SQL injection in UserRepository:42`
4. **PR aperta** con:
   - Descrizione vulnerabilità + impatto
   - Diff codice originale vs corretto
   - Link a CWE, OWASP Top 10, CVE reference
   - Test unitario suggerito dall'AI
   - Severity + CVSS score
5. **Notifica** al developer via Slack/email + ticket Jira
6. **Dashboard SOC** mostra stato PR (open/merged/rejected)

---

## 10. Architettura DevOps / CI-CD

```mermaid
graph LR
    subgraph DEV["Developer"]
        CODE["Git Push\nfeature branch"]
    end

    subgraph CI["GitHub Actions CI"]
        LINT["Checkstyle + SpotBugs\nESLint Angular"]
        TEST["JUnit 5 + Mockito\nJasmine + Karma"]
        BUILD["mvn package\n-DskipTests=false"]
        SAST_SELF["SAST su se stessa\nSemgrep + CodeQL"]
        DOCKER["Docker multi-stage\nJava 21 slim image"]
        SCAN_IMG["Trivy container scan\nCVSS >= 7 = fail"]
        PUSH["Push ECR/GHCR"]
    end

    subgraph GITOPS["ArgoCD GitOps"]
        STAGING["Deploy Staging\nauto on main merge"]
        SMOKE["k6 load test\n+ Playwright E2E"]
        GATE["Manual approval\n(CISO / Tech Lead)"]
        PROD["Deploy Production\nrolling update"]
    end

    subgraph K8S["Kubernetes EKS — Namespace isolation"]
        SHARED["shared-services\nKafka · OpenSearch · MISP · Redis"]
        MGMT["management\nKeycloak · Gateway · Monitoring"]
        T_A["tenant-acme\nDedicato + NetworkPolicy"]
        T_B["tenant-globex\nDedicato + NetworkPolicy"]
    end

    CODE --> LINT --> TEST --> BUILD --> SAST_SELF --> DOCKER --> SCAN_IMG --> PUSH
    PUSH --> STAGING --> SMOKE --> GATE --> PROD
    PROD --> SHARED
    PROD --> MGMT
    PROD --> T_A
    PROD --> T_B
```

---

## 11. Pattern Architetturali

### Spring Boot — Struttura standard ogni microservizio

```
spring-services/[service-name]/
├── src/main/java/com/iacyber/[service]/
│   ├── config/
│   │   ├── SecurityConfig.java          # Spring Security + JWT resource server
│   │   ├── KafkaConfig.java             # Producer/Consumer beans
│   │   └── TenantConfig.java            # Multi-tenant filter
│   ├── domain/                          # Entità JPA + value objects
│   ├── repository/                      # Spring Data JPA / OpenSearch repos
│   ├── service/                         # Business logic pura
│   ├── kafka/
│   │   ├── consumer/                    # @KafkaListener
│   │   └── producer/                    # KafkaTemplate wrappers
│   ├── api/
│   │   ├── rest/                        # @RestController — esposto all'esterno
│   │   └── websocket/                   # @MessageMapping STOMP
│   ├── client/                          # Feign clients
│   │   ├── [OtherSpringService]Client   # verso altri Spring services
│   │   └── [PythonAiService]Client      # verso Python AI APIs (stessa struttura)
│   └── dto/                             # Request/Response records Java
├── src/test/java/
│   ├── unit/                            # JUnit 5 + Mockito
│   ├── integration/                     # @SpringBootTest + Testcontainers
│   └── arch/                            # ArchUnit: layer rules enforced
└── pom.xml                              # Eredita parent POM
```

**Pattern Java/Spring:**
- **Multi-tenancy:** `TenantContext` ThreadLocal + `@TenantFilter` su ogni JPA query
- **Event-driven:** Outbox pattern — ogni cambio stato pubblica evento Kafka
- **Circuit breaker:** Resilience4j su tutte le chiamate inter-service (incluse Python APIs)
- **Tracing:** OpenTelemetry → Jaeger, propagato anche nelle chiamate verso Python

### Python FastAPI — Struttura standard ogni AI service

```
python-ai/[service-name]-api/
├── main.py                              # FastAPI app + router mount
├── routers/
│   └── predict.py                       # Endpoint REST (chiamati da Spring via Feign)
├── models/
│   └── [model_name].py                  # Classe modello ML (train + predict)
├── training/
│   ├── train.py                         # Script training offline
│   └── datasets/                        # Dataset preprocessati
├── schemas/
│   └── request_response.py              # Pydantic models (validazione I/O)
├── core/
│   ├── config.py                        # Settings (pydantic-settings)
│   └── security.py                      # Verifica token interno (shared secret)
├── tests/
│   └── test_predict.py                  # pytest
├── Dockerfile
└── pyproject.toml                       # Poetry dependencies
```

**Pattern Python AI:**
- Ogni servizio è **stateless** — modelli caricati in memoria all'avvio
- **Autenticazione interna:** shared secret header `X-Internal-Token` (non esposto fuori dal cluster)
- **Versioning modelli:** MLflow per tracking esperimenti e model registry
- **Retraining:** scheduled job Python separato, ricarica modello senza restart

---

## 12. Angular Dashboard — Struttura Feature Modules

```mermaid
graph TD
    APP["AppComponent\n(Shell + Router)"]
    APP --> AUTH_M["AuthModule\nLogin · MFA · SSO"]
    APP --> DASH_M["DashboardModule\nSOC Overview · KPI widgets"]
    APP --> ALERT_M["AlertsModule\nReal-time list · Detail · MITRE view"]
    APP --> INC_M["IncidentsModule\nTimeline · Case management"]
    APP --> ASSET_M["AssetsModule\nInventory · Risk score · SBOM"]
    APP --> CODE_M["CodeScanModule\nSAST findings · PR link · Fix preview"]
    APP --> PRED_M["PredictionsModule\nPredicted CVE · Probability chart"]
    APP --> INTEL_M["ThreatIntelModule\nIoC explorer · TTP heatmap"]
    APP --> PLAY_M["PlaybookModule\nVisual builder · Execution log"]
    APP --> COMP_M["ComplianceModule\nNIS2 · ISO27001 · GDPR report"]
    APP --> ADMIN_M["AdminModule\nTenant config · Users · Git integrations"]

    ALERT_M --> WS["WebSocket Service\nSTOMP real-time push"]
    PRED_M --> CHART["ECharts\nTime-series probability"]
    CODE_M --> GIT_LINK["Link diretto\nGitHub PR / GitLab MR"]
```

---

## 13. Roadmap 18 Mesi

### FASE 1 — Foundation Spring (Mesi 1-3)
**Goal: Core microservizi funzionanti, primo tenant**

| Task | Dettaglio |
|---|---|
| Monorepo Maven setup | Parent POM, Spring Cloud Config Server, Eureka |
| API Gateway | Spring Cloud Gateway + JWT validation + multi-tenant routing |
| Auth Service | Keycloak 24 + Spring Security OAuth2 Resource Server |
| Ingestion Service | @KafkaListener + ECS normalizer (Syslog, CEF, JSON, WinEvents) |
| SIEM Service | OpenSearch indexing + Sigma rule execution |
| Angular shell | App skeleton + auth (Keycloak Angular adapter) + routing |
| Dashboard MVP | Alert list real-time via WebSocket STOMP |

**Milestone M1:** Log ingestiti → alert su dashboard Angular in < 2 secondi

---

### FASE 2 — AI & Prediction (Mesi 4-6)
**Goal: ML in produzione, predizioni CVE attive**

| Task | Dettaglio |
|---|---|
| ML Bridge Service | Spring AI + Python sidecar (FastAPI) per modelli ML |
| Anomaly Detection | Isolation Forest per network + UEBA |
| Threat Classifier | XGBoost → classificazione MITRE ATT&CK |
| Predictive Engine MVP | LSTM su dataset NVD 2015-2024, predizioni 30/60/90gg |
| SBOM Ingestion | Parser Maven/npm/pip per asset inventory |
| Threat Intel | MISP integration + IoC lookup cache Redis |
| Angular Predictions | Panel predizioni con ECharts time-series |

**Milestone M2:** Predizione corretta su 65%+ CVE HIGH/CRITICAL (back-test 2023-2024)

---

### FASE 3 — Code Scanner & Git (Mesi 7-9)
**Goal: SAST operativo, PR automatiche funzionanti**

| Task | Dettaglio |
|---|---|
| Code Scanner Service | Semgrep + CodeQL runner orchestrato da Spring Boot |
| Git Integration Service | JGit + GitHub/GitLab API (webhook + clone + PR) |
| AI Fix Generator | Spring AI → LLM genera patch code + test suggerito |
| Auto PR creation | Branch naming, commit strutturato, PR con full context |
| OWASP Dep Check | Integrazione in pipeline SAST |
| Angular CodeScan | Finding list + diff viewer + link PR + status tracking |
| Vuln Scanner | Nuclei + OpenVAS per network/machine scanning |

**Milestone M3:** Finding SAST → PR con fix in < 5 minuti, copertura 10 CWE critiche

---

### FASE 4 — Response & Compliance (Mesi 10-12)
**Goal: SOAR completo, compliance reporting, enterprise-ready**

| Task | Dettaglio |
|---|---|
| Playbook Engine | Spring State Machine + visual builder Angular |
| Response Actions | Block IP, isolate host, disable AD account via API |
| Jira/ServiceNow | Integrazione bidirezionale ticket ↔ incident |
| NIS2 Reporter | Mapping eventi → articoli NIS2, JasperReports PDF |
| ISO 27001 | Audit trail + control scoring automatico |
| GDPR Module | Breach detection + 72h notification workflow |
| SSO Enterprise | SAML 2.0 per grandi clienti |
| SOC 2 prep | Audit log immutabile + evidenze automatiche |

**Milestone M4:** Primo cliente enterprise live, compliance report NIS2 approvato da auditor

---

### FASE 5 — Scale & Market (Mesi 13-18)
**Goal: Crescita clienti, marketplace, MSSP channel**

| Task | Dettaglio |
|---|---|
| Marketplace | 50+ connettori (Splunk, CrowdStrike, Defender, Wiz) |
| White-label | Ribranding Angular + Keycloak per MSSP partner |
| Self-service | Trial automatico + billing Stripe integrato |
| Advanced UEBA | Behavioral baseline per utente/asset |
| Threat Hunting | Query DSL custom + pre-built hunt playbooks |
| Predictive V2 | CodeBERT per similarity su codice sorgente |
| Mobile | Angular PWA + notifiche push per alert critici |
| Partner Portal | Gestione sub-tenant + revenue dashboard MSSP |

**Milestone M5:** 10+ clienti paganti, MRR > €50k, 3 MSSP partner attivi

---

## 14. Modello di Business

### Piani SaaS

| Piano | Target | Prezzo | Incluso |
|---|---|---|---|
| **Starter** | PMI < 200 dip. | €2.500/mese | 5 utenti · 10GB logs/day · Alert base · 1 repo Git |
| **Professional** | Mid-market | €8.000/mese | 25 utenti · 100GB/day · ML + SAST + Predictive · 10 repo |
| **Enterprise** | Large / MSSP | €20.000+/mese | Unlimited · White-label · SLA 99.9% · Repo illimitati |
| **MSSP Partner** | Rivenditori | Revenue share 30% | Multi-tenant · Partner portal · Co-marketing |

### Revenue Aggiuntivi
- **Professional Services:** Setup, tuning ML, custom Sigma rules (€150-250/ora)
- **IR Retainer:** Incident Response on-demand mensile
- **TI Premium:** Feed dark web + settore specifico
- **Training:** Certificazione SOC analyst sulla piattaforma

---

## 15. Sicurezza della Piattaforma

| Area | Implementazione |
|---|---|
| **Multi-tenancy** | Schema-per-tenant PostgreSQL + K8s namespace isolation |
| **JWT Security** | Spring Security RS256, short-lived tokens (15min) + refresh |
| **Secrets** | HashiCorp Vault + Spring Cloud Vault (zero secret in config) |
| **Encryption rest** | AES-256, chiavi per-tenant in AWS KMS |
| **Encryption transit** | TLS 1.3 + Istio mTLS inter-service |
| **SAST su se stessa** | La piattaforma scansiona il proprio codice in CI |
| **Dep. scanning** | OWASP DC + Trivy su ogni build |
| **Zero trust** | Istio service mesh + identity-based auth |
| **Audit log** | Immutable append-only su S3 Object Lock |
| **Pentest** | Quarterly external + continuous con Nuclei su staging |

---

## 16. Prossimi Passi Immediati

```
Settimana 1-2:
  [ ] Creare repo GitHub monorepo IACyber
  [ ] Parent POM Maven con BOM Spring Boot 3.3
  [ ] Docker Compose locale: Kafka + OpenSearch + PostgreSQL + Keycloak
  [ ] Scaffold gateway-service (Spring Cloud Gateway)
  [ ] Scaffold auth-service (Keycloak adapter)

Settimana 3-4:
  [ ] ingestion-service: primo @KafkaListener + ECS normalizer Syslog
  [ ] siem-service: indexing OpenSearch + prima query REST
  [ ] Angular app: ng new soc-dashboard --standalone
  [ ] Keycloak Angular adapter + route guards

Mese 2:
  [ ] WebSocket STOMP: alert push real-time su Angular
  [ ] Dashboard widget: alert list live
  [ ] GitHub Actions CI: build + test + Trivy
  [ ] ArgoCD: deploy su staging K8s
```
