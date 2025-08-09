"""Pytest helpers and utilities for PQC Migration Audit tests."""

import tempfile
import shutil
from pathlib import Path
from contextlib import contextmanager
from typing import Dict, Any, Union
import pytest


class PytestHelpers:
    """Helper class for pytest utilities."""
    
    @staticmethod
    @contextmanager
    def temp_python_file(content: Union[str, bytes], suffix: str = '.py'):
        """Create a temporary Python file with given content."""
        if isinstance(content, bytes):
            mode = 'wb'
        else:
            mode = 'w'
            
        with tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, delete=False, encoding='utf-8' if mode == 'w' else None) as f:
            f.write(content)
            temp_path = Path(f.name)
        
        try:
            yield temp_path
        finally:
            if temp_path.exists():
                temp_path.unlink()
    
    @staticmethod
    @contextmanager
    def temp_directory():
        """Create a temporary directory."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            yield temp_dir
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# Make helpers available as pytest.helpers
pytest.helpers = PytestHelpers()