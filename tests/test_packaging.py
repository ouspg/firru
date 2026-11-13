"""The wheel carries def/ and baseline/ (pyproject package-dir), and defs_dir
finds them installed (inside the package) as well as in a checkout (beside it)."""
import tomllib
from pathlib import Path

from firru import defs_dir

ROOT = Path(__file__).resolve().parent.parent


def test_every_mapped_data_package_exists_and_has_its_files():
    st = tomllib.loads((ROOT / 'pyproject.toml').read_text())['tool']['setuptools']
    for pkg, src in st['package-dir'].items():
        assert pkg in st['packages'], pkg
        globs = st['package-data'][pkg]
        assert any(next((ROOT / src).glob(g), None) for g in globs), (pkg, src, globs)


def test_installed_location_wins_over_the_checkout(tmp_path, monkeypatch):
    pkg = tmp_path / 'site' / 'firru'
    (pkg / '_stock_def').mkdir(parents=True)
    (tmp_path / 'site' / 'def').mkdir()
    monkeypatch.setattr(defs_dir, '_HERE', pkg)
    assert defs_dir._stock('_stock_def', 'def') == pkg / '_stock_def'
    monkeypatch.setattr(defs_dir, '_HERE', tmp_path / 'checkout' / 'firru')
    assert defs_dir._stock('_stock_def', 'def') == tmp_path / 'checkout' / 'def'


def test_the_checkout_resolves_to_the_repo_root():
    assert defs_dir.STOCK == ROOT / 'def' and defs_dir.STOCK_BASELINE == ROOT / 'baseline'


class TestNear:
    """Without --defs, the def/ nearest the policy wins over ./def and the stock
    definitions: a project keeps policies/ and def/ side by side."""

    def _project(self, root):
        (root / 'proj' / 'def').mkdir(parents=True)
        (root / 'proj' / 'policies' / 'pol').mkdir(parents=True)
        pol = root / 'proj' / 'policies' / 'pol' / 'h1.yml'
        pol.write_text('{}\n')
        return pol

    def test_the_def_beside_the_policies_wins_over_cwd(self, tmp_path, monkeypatch):
        pol = self._project(tmp_path)
        (tmp_path / 'cwd' / 'def').mkdir(parents=True)
        monkeypatch.chdir(tmp_path / 'cwd')
        assert defs_dir.near([pol]) == str(tmp_path / 'proj' / 'def')

    def test_an_explicit_defs_wins(self, tmp_path, monkeypatch):
        pol = self._project(tmp_path)
        (tmp_path / 'mine').mkdir()
        assert defs_dir.near([pol], str(tmp_path / 'mine')) == str(tmp_path / 'mine')

    def test_with_none_near_it_falls_back_to_stock(self, tmp_path, monkeypatch, capsys):
        pol = tmp_path / 'h1.yml'
        pol.write_text('{}\n')
        monkeypatch.chdir(tmp_path)
        assert defs_dir.near([pol]) == str(defs_dir.STOCK)
        assert 'stock definitions' in capsys.readouterr().err
