from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_env_is_gitignored():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore
    assert ".env.example" not in gitignore.splitlines()


def test_env_example_exists_without_real_secrets():
    example = ROOT / ".env.example"
    assert example.exists()
    text = example.read_text(encoding="utf-8")
    assert "API_KEY=" in text
    assert "ADMIN_API_KEY=" in text
    assert "change-this" in text.lower() or "your-" in text.lower()


def test_tracked_files_do_not_include_dotenv(tmp_path=None):
    git_dir = ROOT / ".git"
    if not git_dir.exists():
        return

    import subprocess

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    tracked = result.stdout.splitlines()
    env_files = [path for path in tracked if path == ".env" or path.endswith("/.env")]
    assert env_files == []
    assert ".env.example" in tracked
