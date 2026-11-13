import textwrap

from firru.scoring import load_scoring, DEFAULT_NOTE


def _write(tmp_path, body):
    p = tmp_path / "scoring.yml"
    p.write_text(textwrap.dedent(body))
    return str(p)


class TestLoadScoring:
    def test_indexes_by_host_and_portproto(self, tmp_path):
        path = _write(tmp_path, """
            WEB_FRONTEND:
              - {proto: tcp, port: 443, note: "public endpoint"}
              - {proto: tcp, port: 80}
            DB_HOST:
              - {proto: tcp, port: 5432, note: "app backend"}
        """)
        idx = load_scoring(path)
        assert idx["WEB_FRONTEND"][("tcp", 443)] == "public endpoint"
        assert idx["DB_HOST"][("tcp", 5432)] == "app backend"

    def test_port_coerced_to_int(self, tmp_path):
        path = _write(tmp_path, """
            H:
              - {proto: udp, port: "53"}
        """)
        idx = load_scoring(path)
        assert ("udp", 53) in idx["H"]

    def test_missing_note_uses_default(self, tmp_path):
        path = _write(tmp_path, """
            H:
              - {proto: tcp, port: 22}
        """)
        assert load_scoring(path)["H"][("tcp", 22)] == DEFAULT_NOTE

    def test_malformed_entry_skipped(self, tmp_path):
        path = _write(tmp_path, """
            H:
              - {proto: tcp}
              - {proto: tcp, port: 443}
        """)
        idx = load_scoring(path)
        assert list(idx["H"]) == [("tcp", 443)]

    def test_empty_path_returns_empty(self):
        assert load_scoring(None) == {}
        assert load_scoring("") == {}

    def test_missing_file_returns_empty(self, tmp_path):
        assert load_scoring(str(tmp_path / "nope.yml")) == {}
