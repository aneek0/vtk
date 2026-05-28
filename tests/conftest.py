"""Pytest configuration — add project root to path."""
import sys
from pathlib import Path

# Add project root to sys.path so `import core` works
sys.path.insert(0, str(Path(__file__).parent.parent))
