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
