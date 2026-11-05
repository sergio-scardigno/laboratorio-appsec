import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def semgrep_raw():
    return json.loads((FIXTURES / "semgrep.json").read_text())


@pytest.fixture
def sonar_raw():
    return json.loads((FIXTURES / "sonar.json").read_text())


@pytest.fixture
def zap_raw():
    return json.loads((FIXTURES / "zap.json").read_text())
