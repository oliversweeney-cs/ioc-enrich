import pytest
from ioc_enrich.models import IoCType, detect_ioc_type


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1.2.3.4", IoCType.IP),
        ("255.255.255.255", IoCType.IP),
        ("example.com", IoCType.DOMAIN),
        ("sub.example.co.uk", IoCType.DOMAIN),
        ("http://example.com/path", IoCType.URL),
        ("https://evil.com/malware", IoCType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IoCType.HASH),  # MD5
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IoCType.HASH),  # SHA1
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IoCType.HASH),  # SHA256
        ("not_an_ioc!!", IoCType.UNKNOWN),
    ],
)
def test_detect_ioc_type(value: str, expected: IoCType) -> None:
    assert detect_ioc_type(value) == expected
