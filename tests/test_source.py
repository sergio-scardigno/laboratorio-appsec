import base64

import pytest

from lab import source


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "git@github.com:a/b.git", "file:///etc/passwd", "ssh://x/y",
    "https://", "ext::sh -c id", "--upload-pack=touch", "https://user:pw@github.com/a/b",
])
def test_rejects_unsafe_repo_urls(url):
    with pytest.raises(source.SourceError):
        source.validate_repo_url(url)


def test_accepts_https_repo():
    source.validate_repo_url("https://github.com/juice-shop/juice-shop.git")


def test_sanitize_removes_control_files_at_any_depth(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git/config").write_text("x")
    (tmp_path / ".semgrepignore").write_text("*")
    (tmp_path / "sonar-project.properties").write_text("sonar.exclusions=**")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub/.semgrepignore").write_text("*")
    (tmp_path / "keep.ts").write_text("x")
    removed = source.sanitize(tmp_path)
    assert sorted(removed) == [".semgrepignore", "sonar-project.properties", "sub/.semgrepignore"]
    assert not (tmp_path / ".git").exists()
    assert (tmp_path / "keep.ts").exists()


def test_github_token_only_for_github():
    assert source.github_auth_env("https://gitlab.com/a/b", "tok") == {}
    assert source.github_auth_env("https://github.com.evil.example/a/b", "tok") == {}
    assert source.github_auth_env("https://github.com/a/b", "") == {}


def test_github_token_goes_in_env_scoped_to_github():
    env = source.github_auth_env("https://github.com/org/private", "tok")
    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    header = env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: Basic ")
    assert base64.b64decode(header).decode() == "x-access-token:tok"


class FakeGit:
    """Simula git: falla con credencial rechazada mientras reciba el token."""

    def __init__(self, public: bool):
        self.public, self.calls = public, []

    def __call__(self, argv, env=None, **kwargs):
        import subprocess

        with_token = "GIT_CONFIG_KEY_0" in env
        self.calls.append(with_token)
        ok = self.public and not with_token
        stderr = "" if ok else "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
        return subprocess.CompletedProcess(argv, 0 if ok else 128, "", stderr)


def test_rejected_token_retries_without_it_for_public_repos(tmp_path, monkeypatch):
    git = FakeGit(public=True)
    monkeypatch.setattr(source.subprocess, "run", git)
    warning = source.clone("https://github.com/a/b", tmp_path / "x", github_token="muerto")
    assert git.calls == [True, False]
    assert "rechazó LAB_GITHUB_TOKEN" in warning
    assert "muerto" not in warning


def test_rejected_token_on_a_private_repo_gives_a_clear_error(tmp_path, monkeypatch):
    git = FakeGit(public=False)
    monkeypatch.setattr(source.subprocess, "run", git)
    with pytest.raises(source.SourceError, match="LAB_GITHUB_TOKEN") as exc:
        source.clone("https://github.com/a/b", tmp_path / "x", github_token="muerto")
    assert git.calls == [True, False]
    assert "muerto" not in str(exc.value)


def test_no_token_means_no_retry(tmp_path, monkeypatch):
    git = FakeGit(public=False)
    monkeypatch.setattr(source.subprocess, "run", git)
    with pytest.raises(source.SourceError, match="token de solo lectura"):
        source.clone("https://github.com/a/b", tmp_path / "x")
    assert git.calls == [False]


def test_trivy_control_files_are_removed(tmp_path):
    for name in (".trivyignore", ".trivyignore.yaml", "trivy.yaml", "trivy-secret.yaml"):
        (tmp_path / name).write_text("x")
    assert len(source.sanitize(tmp_path)) == 4
