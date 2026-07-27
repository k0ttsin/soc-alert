#SOC Alert
AI assistant for SOC Alerts to enrich them with useful context

<details>
<summary><b>📁 Project Structure</b></summary>
soc-ai-assistant/
├── config.yaml (API Keys, Model Settings)
├── pyproject.toml (Dependencies)
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── models/
│   │   ├── __init__.py
│   │   └── alert.py
│   ├── enrichment/
│   │   ├── __init__.py
│   │   ├── pipeline.py
│   │   ├── abuseipdb.py
│   │   ├── otx.py
│   │   ├── virustotal.py
│   │   └── cache.py
│   ├── mapping/
│   │   ├── __init__.py
│   │   ├── mitre_mapper.py
│   │   └── navigator.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── llm_analyzer.py
│   │   └── prompts.py
│   ├── output/
│   │   ├── __init__.py
│   │   └── formatter.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   └── webhooks.py
│   └── cli.py
├── tests/
│   ├── test_enrichment.py
│   ├── test_mapping.py
│   └── fixtures/
│       ├── sample_wazuh_alert.json
│       └── sample_elastic_alert.json
└── docs/
    ├── architecture.md
    ├── api_reference.md
    └── deployment.md
</details>

## Key Dependencies (pyproject.toml)
The project requires **Python 3.11+**.

<details>
<summary><b>View pyproject.toml dependencies</b></summary>

```toml
[project]
name = "soc-ai-assistant"
version = "0.1.0"
requires-python = ">=3.11"

dependencies = [
    # Core
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "pyyaml>=6.0",

    # Async & HTTP
    "httpx>=0.27",
    "tenacity>=8.3",

    # MITRE ATT&CK
    "attackcti>=3.0",
    "mitreattack-python>=1.4",
    "pyattck>=2.0",

    # Threat Intel APIs
    "abuseipdb-wrapper>=0.2",
    "OTXv2>=1.2",
    "vt-py>=0.11",

    # LLM
    "openai>=1.30",
    "anthropic>=0.25",
    "instructor>=1.4", # Structured output validation

    # Web Framework
    "fastapi>=0.110",
    "uvicorn[standard]>=0.29",

    # Caching
    "redis>=5.0",
    "diskcache>=5.6",

    # Utils
    "python-dateutil>=2.9",
    "ipaddress>=1.0",
    "rich>=13.7", # Pretty CLI output
]

[project.optional-dependencies]

dev = [
    "pytest>=8.2",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
    "ruff>=0.5",
    "mypy>=1.10",
]

local-llm = [
    "ollama>=0.3"
]
```

</details>