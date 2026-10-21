from app.normalizer import is_internal, normalise, prefix_of
from app.resolver_service import RawResponse, RRset


def test_cname_chain_and_max_ttl():
    raw = RawResponse("Google Public DNS", "8.8.8.8", "A", "ok", "NOERROR", answer=[
        RRset("www.example.com", "CNAME", 300, ["edge.cdn.example.net."]),
        RRset("edge.cdn.example.net", "A", 42, ["198.51.100.21", "198.51.100.20"]),
    ])
    a = normalise(raw)
    assert a.values == ["198.51.100.20", "198.51.100.21"]
    assert a.cname_chain == ["edge.cdn.example.net"]
    assert a.max_ttl == 42
    assert a.prefixes == ["198.51.100.0/24"]


def test_failed_response_has_no_values():
    a = normalise(RawResponse("Quad9", "9.9.9.9", "A", "timeout"))
    assert not a.answered and a.values == []


def test_prefix_and_internal():
    assert prefix_of("2001:db8:10::20") == "2001:db8:10::/48"
    assert is_internal("10.0.0.5") and is_internal("127.0.0.1") and is_internal("fe80::1")
    assert not is_internal("198.51.100.20") and not is_internal("8.8.8.8")
