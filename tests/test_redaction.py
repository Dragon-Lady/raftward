import pytest

from raftward.safety import Redactor, secret_name


@pytest.mark.parametrize("name", ["PATH", "NODE_PATH", "PYTHONPATH", "PYTHON_PATHS", "DATA_PATHS", "projectPath", "KEYBOARD"])
def test_path_and_keyboard_are_not_credential_names(name):
    assert not secret_name(name)
    redactor = Redactor(b"k" * 32)
    redactor.discover({name: "/fixture/tools"})
    assert redactor.clean("/fixture/tools") == "/fixture/tools"


@pytest.mark.parametrize("name", ["PAT", "GH_PAT", "GITHUB_PAT", "API_KEY", "apiKey", "APIKEY", "clientSecret", "ACCESS_TOKEN"])
def test_credential_names_still_detected(name):
    assert secret_name(name)
    redactor = Redactor(b"k" * 32)
    redactor.discover({name: "canary-sensitive-value"})
    assert redactor.clean("canary-sensitive-value").startswith("fp:")
