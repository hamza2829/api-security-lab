"""Keep the teaching examples honest: every intended attack must work."""

from pathlib import Path

from exploits import exposed_secret, forge_jwt, idor, sql_injection


def test_vulnerable_app_is_still_exploitable(vulnerable_api):
    assert idor.exploit(vulnerable_api)
    assert sql_injection.exploit(vulnerable_api)
    assert forge_jwt.exploit(vulnerable_api)
    assert exposed_secret.exploit(Path(__file__).resolve().parents[1] / "app_vulnerable")
