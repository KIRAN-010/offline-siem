from app.main import APP_VERSION, app


def test_app_is_created():
    assert app is not None
    assert APP_VERSION == "0.1.0"
