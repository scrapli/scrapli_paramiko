from scrapli_paramiko.transport import Transport


def test_creation():
    conn = Transport("localhost")
    assert conn.host == "localhost"
    assert conn.port == 22
