"""The proof scripts must refuse remote origins and redirects."""

import pytest

from exploits.common import LocalAPI


@pytest.mark.parametrize("url", [
    "https://example.com", "http://192.0.2.1:8000",
    "http://127.0.0.1@example.com", "http://127.0.0.1:8000/remote",
])
def test_exploits_reject_nonlocal_origins(url):
    with pytest.raises(ValueError, match="loopback"):
        LocalAPI(url)
