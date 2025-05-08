import pytest
import struct
from unittest.mock import patch, MagicMock
from sDNSradar import (
    process_endpoints,
    create_dns_query,
    is_dns_answer,
    send_doh_request,
    send_dot_request,
)


# ---- process_endpoints ----
def test_process_endpoints_valid():
    input_data = ["1.1.1.1:443", "dns.google:853"]
    expected = [["1.1.1.1", "443"], ["dns.google", "853"]]
    assert process_endpoints(input_data) == expected


def test_process_endpoints_invalid():
    with pytest.raises(ValueError):
        process_endpoints(["badformat", "127.0.0.1:-1", "127.0.0.1::00", "127.0.0.1:12345678"])


# ---- create_dns_query ----
def test_create_dns_query_basic():
    domain = "example.com"
    query = create_dns_query(domain)

    assert isinstance(query, bytes)
    assert b"example" in query
    assert b"com" in query
    assert len(query) > 12


# ---- is_dns_answer ----
def test_is_dns_answer_valid():
    # Create a simple valid DNS response with header and one answer
    header = struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b'\x07example\x03com\x00\x00\x01\x00\x01'
    answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22'
    data = header + question + answer
    assert is_dns_answer(data)


def test_is_dns_answer_invalid_short():
    assert not is_dns_answer(b'\x00')


def test_is_dns_answer_rcode_error():
    # Header with non-zero rcode
    header = struct.pack("!6H", 0x1234, 0x8183, 1, 0, 0, 0)
    data = header + b'\x07example\x03com\x00\x00\x01\x00\x01'
    assert not is_dns_answer(data)


# ---- send_doh_request ----
@patch("sDNSradar.requests.post")
def test_send_doh_request_success(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200

    # DNS Header: ID=0x1234, Flags=0x8180 (standard response, no error)
    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0)

    # Question section: example.com, type A, class IN
    question = b'\x07example\x03com\x00\x00\x01\x00\x01'

    # Answer section:
    # Name = pointer to offset 12 (0xc00c), Type=A, Class=IN, TTL=60, RDLENGTH=4, RDATA=93.184.216.34
    answer = b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + b'\x5d\xb8\xd8\x22'

    mock_response.content = header + question + answer
    mock_post.return_value = mock_response

    result = send_doh_request("doh.example.com", "example.com", 443)
    assert result is True


@patch("sDNSradar.requests.post")
def test_send_doh_request_fail(mock_post):
    mock_post.side_effect = Exception("Failed")
    with pytest.raises(Exception):
        send_doh_request("fail.example.com", "example.com", 443)


# ---- send_dot_request ----
@patch("sDNSradar.socket.create_connection")
@patch("sDNSradar.ssl.create_default_context")
def test_send_dot_request_success(mock_ssl_context, mock_socket):
    mock_sock = MagicMock()
    mock_ssl_sock = MagicMock()

    # Same valid response as above
    header = struct.pack("!6H", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b'\x07example\x03com\x00\x00\x01\x00\x01'
    answer = b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + b'\x5d\xb8\xd8\x22'
    response = header + question + answer

    mock_ssl_sock.recv.side_effect = [struct.pack(">H", len(response)), response]
    mock_ssl_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
    mock_socket.return_value.__enter__.return_value = mock_sock

    result = send_dot_request("dot.example.com", "example.com", 853)
    assert result is True


# ---- Integration check (optional) ----
@patch("sDNSradar.send_doh_request", return_value=True)
@patch("sDNSradar.send_dot_request", return_value=False)
def test_service_detection_logic(mock_doh, mock_dot):
    from sDNSradar import check_doh_multiple_ips, check_dot_multiple_endpoints

    endpoints = [["1.1.1.1", "443"]]
    results = {"doh": [], "dot": [], "unsupported": [], "error": []}

    check_doh_multiple_ips(endpoints, "example.com", results)
    check_dot_multiple_endpoints(endpoints, "example.com", results)

    assert "1.1.1.1:443" in results["doh"]
    assert "1.1.1.1:443 (DoT)" in results["unsupported"]
