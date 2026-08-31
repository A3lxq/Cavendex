"""Test isolation: point every persistence layer at a throwaway temp
directory before any test module imports graph.py / memory / obsidian, so
running the test suite never touches the real data/, .chroma/, or
obsidian_vault/ the app uses in normal operation.
"""

import os
import tempfile

_TEST_DIR = tempfile.mkdtemp(prefix="cavendex_test_")
os.environ["CAVENDEX_DATA_DIR"] = os.path.join(_TEST_DIR, "data")
os.environ["CHROMA_PERSIST_DIR"] = os.path.join(_TEST_DIR, "chroma")
os.environ["OBSIDIAN_VAULT_PATH"] = os.path.join(_TEST_DIR, "vault")
