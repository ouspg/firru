import io
import textwrap

from ruyaml import YAML
from ruyaml.comments import CommentedMap, CommentedSeq

from firru.comments import (
    TAG_AUTO,
    TAG_SCORE,
    line_tag,
    tagged,
    partition_comment,
    preceding_raw_comment,
    kept_comments_by_term,
    compose_start_comment,
    set_term_comment,
)


def _yaml():
    y = YAML()
    y.indent(mapping=2, sequence=4, offset=2)
    return y


# ruyaml stores a comment block preceding item N with '#', indentation, and
# newlines, exactly like this.
RAW_BLOCK = "\n      # [auto] IPv4 10.0.0.5 (postgres)\n      # [score] DO NOT BLOCK\n      # keep ANY until Q3\n"


class TestLineHelpers:
    def test_line_tag(self):
        assert line_tag("[auto] 3 flows") == "auto"
        assert line_tag("[score] must stay open") == "score"
        assert line_tag("keep ANY until Q3") is None
        assert line_tag("") is None

    def test_tagged(self):
        assert tagged(TAG_AUTO, "3 flows") == "[auto] 3 flows"


class TestPartition:
    def test_splits_owned_from_kept(self):
        owned, kept = partition_comment(RAW_BLOCK, owned=TAG_AUTO)
        assert owned == ["[auto] IPv4 10.0.0.5 (postgres)"]
        assert kept == ["[score] DO NOT BLOCK", "keep ANY until Q3"]

    def test_kept_preserves_order_and_tags(self):
        raw = "# keep first\n# [score] then score\n# [auto] drop me\n# keep last"
        owned, kept = partition_comment(raw)
        assert owned == ["[auto] drop me"]
        assert kept == ["keep first", "[score] then score", "keep last"]

    def test_owned_selects_tag(self):
        owned, kept = partition_comment(RAW_BLOCK, owned=TAG_SCORE)
        assert owned == ["[score] DO NOT BLOCK"]
        assert "[auto] IPv4 10.0.0.5 (postgres)" in kept

    def test_empty(self):
        assert partition_comment(None) == ([], [])
        assert partition_comment("") == ([], [])


DOC = textwrap.dedent("""\
    metadata:
      host: H1
    filters:
      - header:
          targets:
            nftables: mixed input DROP
        terms:
          # [auto] leading note on first term
          # keep me first
          - name: allow-loopback
            source-address: LOOPBACK
            action: accept
          # [auto] IPv4 10.0.0.5 (postgres)
          # [score] DO NOT BLOCK - partner
          # keep ANY until Q3
          - name: allow-tcp-POSTGRES
            protocol: tcp
            destination-port: POSTGRES
            action: accept
          - name: allow-tcp-SSH
            protocol: tcp
            destination-port: SSH
            action: accept
""")


class TestPrecedingComment:
    def setup_method(self):
        self.terms = _yaml().load(DOC)["filters"][0]["terms"]

    def test_first_item(self):
        _, kept = partition_comment(preceding_raw_comment(self.terms, 0))
        assert kept == ["keep me first"]

    def test_quirk_attached_item(self):
        raw = preceding_raw_comment(self.terms, 1)
        owned, kept = partition_comment(raw)
        assert owned == ["[auto] IPv4 10.0.0.5 (postgres)"]
        assert kept == ["[score] DO NOT BLOCK - partner", "keep ANY until Q3"]

    def test_no_comment(self):
        assert preceding_raw_comment(self.terms, 2) is None

    def test_kept_by_term(self):
        m = kept_comments_by_term(self.terms)
        assert m["allow-loopback"] == ["keep me first"]
        assert m["allow-tcp-POSTGRES"] == ["[score] DO NOT BLOCK - partner", "keep ANY until Q3"]
        assert "allow-tcp-SSH" not in m  # no carried lines


class TestRoundTrip:
    """The contract in action: rebuild the term list, refresh [auto], keep the rest."""

    def test_regenerate_preserves_human_and_score(self):
        y = _yaml()
        src = y.load(DOC)
        old_terms = src["filters"][0]["terms"]
        kept_map = kept_comments_by_term(old_terms)

        # Simulate a generator rebuilding terms from scratch with fresh [auto].
        new_terms = CommentedSeq()
        for term in old_terms:
            nt = CommentedMap()
            for k, v in term.items():
                nt[k] = v
            fresh_auto = [tagged(TAG_AUTO, f"regenerated for {nt['name']}")]
            set_term_comment(nt, fresh_auto, kept_map.get(nt["name"], []))
            new_terms.append(nt)
        src["filters"][0]["terms"] = new_terms

        buf = io.StringIO()
        y.dump(src, buf)
        out = buf.getvalue()

        # Human line survived
        assert "keep ANY until Q3" in out
        assert "keep me first" in out
        # [score] line survived
        assert "[score] DO NOT BLOCK - partner" in out
        # Old [auto] gone, new [auto] present
        assert "IPv4 10.0.0.5 (postgres)" not in out
        assert "[auto] regenerated for allow-tcp-POSTGRES" in out
        # Data intact
        reloaded = y.load(out)
        names = [t["name"] for t in reloaded["filters"][0]["terms"]]
        assert names == ["allow-loopback", "allow-tcp-POSTGRES", "allow-tcp-SSH"]

    def test_clear_when_nothing_to_write(self):
        assert compose_start_comment([], []) is None
