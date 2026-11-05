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
