import pytest

from app.validator import InvalidDomain, validate_domain


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("example.com.", "example.com"),
    ("  sub.example.org ", "sub.example.org"),
    ("bücher.de", "xn--bcher-kva.de"),
])
def test_valid(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "https://example.com", "example.com/path", "8.8.8.8", "::1",
                                 "localhost", "-bad.com", "bad-.com", "a..com", "user@example.com",
                                 "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com", "exa mple.com"])
def test_invalid(raw):
    with pytest.raises(InvalidDomain):
        validate_domain(raw)
