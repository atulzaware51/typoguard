import pytest

from app.services.url_parser import (
    parse_url,
    normalize_domain,
)


def test_parse_standard_url():
    result = parse_url(
        "https://www.google.com/search"
    )

    assert result["scheme"] == "https"
    assert result["hostname"] == "www.google.com"
    assert result["path"] == "/search"


def test_parse_url_without_scheme():
    result = parse_url("google.com")

    assert result["scheme"] == "https"
    assert result["hostname"] == "google.com"


def test_preserve_original_url_and_parse_components():
    url = "  HTTP://www.google.com.:8080/search?q=login#top  "
    result = parse_url(url)
    assert result["original_url"] == url
    assert result["hostname"] == "www.google.com"
    assert result["port"] == 8080
    assert result["path"] == "/search"
    assert result["query"] == "q=login"
    assert result["fragment"] == "top"


@pytest.mark.parametrize("url", ["", "   ", "https://", "https:///path", "https://bad_host.com", "https://-bad.com", "https://bad..com", "https://example.com..", "https://example.com:", "https://example.com:99999", "https://example.com:notaport", "ftp://example.com", "https://exa mple.com"])
def test_reject_invalid_urls(url):
    with pytest.raises(ValueError):
        parse_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.com/",
        "https://user@example.com/",
        "https://@example.com/",
    ],
)
def test_reject_credential_urls(url):
    with pytest.raises(ValueError, match="URL credentials are not permitted"):
        parse_url(url)


def test_valid_ports_and_idn_are_normalized_to_punycode():
    assert parse_url("https://example.com:443")['port'] == 443
    assert parse_url("https://bücher.de")["hostname"] == "xn--bcher-kva.de"
    assert parse_url("https://xn--bcher-kva.de")["hostname"] == "xn--bcher-kva.de"


def test_valid_ipv6_host_is_supported():
    assert parse_url("https://[2001:db8::1]:8443/path")["port"] == 8443


def test_normalize_www():
    result = normalize_domain("www.google.com")

    assert result == "google.com"


def test_normalize_uppercase():
    result = normalize_domain("GOOGLE.COM")

    assert result == "google.com"


def test_normalize_trailing_dot():
    result = normalize_domain("google.com.")

    assert result == "google.com"


def test_normalize_www_and_trailing_dot_together():
    assert normalize_domain("WWW.Google.COM.") == "google.com"
