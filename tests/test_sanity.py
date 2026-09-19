"""
NetSentinel Phase 0 - Environment & Test Runner Sanity Check
"""
import sys


def test_python_version():
    """Verify we are running on Python 3.9+."""
    assert sys.version_info.major == 3
    assert sys.version_info.minor == 9


def test_core_dependencies_available():
    """Verify foundational scientific, API, and persistence libraries import cleanly."""
    import fastapi
    import numpy
    import pandas
    import pydantic
    import sklearn
    import sqlalchemy
    import streamlit

    assert numpy.__version__ == "1.26.4"
    assert pandas.__version__ == "2.2.3"
    assert sklearn.__version__ == "1.5.2"
    assert fastapi.__version__ == "0.115.6"
    assert pydantic.__version__.startswith("2.")
    assert sqlalchemy.__version__.startswith("2.")
    assert streamlit.__version__.startswith("1.")
