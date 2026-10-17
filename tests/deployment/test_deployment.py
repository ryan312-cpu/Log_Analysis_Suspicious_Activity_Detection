import subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_dockerfile_backend_exists():
    backend_dockerfile = ROOT / "docker" / "backend.Dockerfile"
    assert backend_dockerfile.exists()
    content = backend_dockerfile.read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in content
    assert "uvicorn" in content
    assert "EXPOSE 8000" in content


def test_dockerfile_frontend_exists():
    frontend_dockerfile = ROOT / "docker" / "frontend.Dockerfile"
    assert frontend_dockerfile.exists()
    content = frontend_dockerfile.read_text(encoding="utf-8")
    assert "FROM node:20-alpine AS build" in content
    assert "FROM nginx:alpine" in content
    assert "EXPOSE 80" in content


def test_nginx_conf_exists_and_configured():
    nginx_conf = ROOT / "docker" / "nginx.conf"
    assert nginx_conf.exists()
    content = nginx_conf.read_text(encoding="utf-8")
    assert "location /api/" in content
    assert "proxy_pass http://backend:8000" in content
    assert "location /health" in content
    assert "try_files $uri $uri/ /index.html;" in content
    assert "X-Frame-Options" in content


def test_docker_compose_exists_and_valid():
    compose_file = ROOT / "docker-compose.yml"
    assert compose_file.exists()
    parsed = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    assert "services" in parsed
    services = parsed["services"]
    assert "backend" in services
    assert "frontend" in services

    # Verify backend config
    backend = services["backend"]
    assert "build" in backend
    assert "healthcheck" in backend
    assert any("8000:8000" in str(p) for p in backend.get("ports", []))

    # Verify frontend config
    frontend = services["frontend"]
    assert "build" in frontend
    assert "depends_on" in frontend
    assert any("80:80" in str(p) for p in frontend.get("ports", []))


def test_docker_compose_persistence_volumes():
    compose_file = ROOT / "docker-compose.yml"
    parsed = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    backend = parsed["services"]["backend"]
    volumes = backend.get("volumes", [])
    assert any("./data:/app/data" in v for v in volumes)
    assert any("./logs:/app/logs" in v for v in volumes)


def test_ci_pipeline_exists_and_valid():
    ci_file = ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_file.exists()
    parsed = yaml.safe_load(ci_file.read_text(encoding="utf-8"))
    assert "jobs" in parsed
    jobs = parsed["jobs"]
    assert "test" in jobs
    assert "security-check" in jobs


def test_deployment_docs_exist():
    docs_file = ROOT / "docs" / "deployment.md"
    assert docs_file.exists()
    content = docs_file.read_text(encoding="utf-8")
    assert "Architecture Overview" in content
    assert "Quick Start" in content
    assert "docker compose up" in content


def test_env_not_tracked_in_git():
    if not (ROOT / ".git").exists():
        return
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    tracked = result.stdout.splitlines()
    assert ".env" not in tracked
    assert ".env.example" in tracked
