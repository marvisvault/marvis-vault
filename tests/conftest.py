"""
Pytest configuration to ensure test isolation and proper output directories.
"""
import os
import pytest
import tempfile
from pathlib import Path
import shutil

# Store original working directory
_original_cwd = os.getcwd()

@pytest.fixture(autouse=True)
def isolated_test_environment(tmp_path, monkeypatch):
    """
    Ensure each test runs in isolation with its own temporary directory.
    This prevents tests from creating files in the project root.
    """
    # Create a test-specific temporary directory
    test_dir = tmp_path / "test_workspace"
    test_dir.mkdir()
    
    # Change to the test directory for the duration of the test
    monkeypatch.chdir(test_dir)
    
    # Ensure any imports still work by adding project root to path
    import sys
    project_root = Path(_original_cwd)
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    yield test_dir
    
    # Cleanup is automatic with tmp_path

@pytest.fixture
def test_output_dir(tmp_path):
    """
    Provide a dedicated output directory for test artifacts.
    """
    output_dir = tmp_path / "test_outputs"
    output_dir.mkdir()
    return output_dir

@pytest.fixture
def project_root():
    """
    Return the actual project root directory.
    """
    return Path(_original_cwd)

@pytest.fixture(autouse=True)
def verify_no_root_pollution():
    """
    Verify tests don't create files in the project root.
    """
    # Get files in root before test
    root_files_before = set(os.listdir(_original_cwd))
    
    yield
    
    # Check files in root after test
    root_files_after = set(os.listdir(_original_cwd))
    new_files = root_files_after - root_files_before
    
    # Filter out acceptable files
    new_files = {f for f in new_files if not any([
        f.startswith('.pytest'),
        f.startswith('.coverage'),
        f.endswith('.pyc'),
        f == '__pycache__',
        f.startswith('.'),  # Hidden files
    ])}
    
    assert len(new_files) == 0, (
        f"Test created files in project root: {new_files}. "
        f"Tests should use tmp_path or test_output_dir fixtures."
    )

@pytest.fixture
def safe_cli_runner():
    """
    Provide a CLI runner that ensures output goes to temp directory.
    """
    from typer.testing import CliRunner
    
    class SafeCliRunner(CliRunner):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.isolated = True
            
        def invoke(self, *args, **kwargs):
            # Ensure we're in a safe directory
            if os.getcwd() == _original_cwd:
                with tempfile.TemporaryDirectory() as tmpdir:
                    original_dir = os.getcwd()
                    try:
                        os.chdir(tmpdir)
                        return super().invoke(*args, **kwargs)
                    finally:
                        os.chdir(original_dir)
            else:
                return super().invoke(*args, **kwargs)
    
    return SafeCliRunner()

# Configure pytest to use temporary directories for cache
def pytest_configure(config):
    """Configure pytest to use temp directories."""
    # Use a temporary directory for pytest cache if not specified
    if not config.option.cacheclear and not config.option.cacheshow:
        cache_dir = tempfile.mkdtemp(prefix="pytest_cache_")
        config.option.cachedir = cache_dir

# Ensure matplotlib doesn't try to create files in home directory
os.environ['MPLCONFIGDIR'] = tempfile.mkdtemp()

# Set temporary directory for any other tools that might write files
os.environ['TMPDIR'] = tempfile.mkdtemp()
os.environ['TEMP'] = os.environ['TMPDIR']
os.environ['TMP'] = os.environ['TMPDIR']