from backend.security.totp import build_qr_code_data_uri


def test_totp_qr_code_is_local_data_uri():
    uri = "otpauth://totp/SentinelDNS:test?secret=JBSWY3DPEHPK3PXP&issuer=SentinelDNS"
    data_uri = build_qr_code_data_uri(uri)

    assert data_uri.startswith("data:image/svg+xml;base64,")
    assert len(data_uri) > 200
