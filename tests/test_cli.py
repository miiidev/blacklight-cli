from typer.testing import CliRunner

from blacklight.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "blacklight-cli 0.1.0" in result.output
