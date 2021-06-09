from flask_pyjwt import __version__


def test_version():
    """Assert that the version of flask_pyjwt matches the expected version."""
    assert __version__ == "0.1.6"
