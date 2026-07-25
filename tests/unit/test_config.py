from sentinel.config import get_settings


def test_default_configuration() -> None:
    settings = get_settings()

    assert settings.env == "development"
    assert settings.debug is False
    assert settings.log_level == "INFO"
    assert settings.api_host == "127.0.0.1"
    assert settings.api_port == 8000
    assert settings.llm_provider == "disabled"