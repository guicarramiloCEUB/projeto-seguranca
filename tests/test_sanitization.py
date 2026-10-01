from app.security_log import sanitize_string, mask_sensitive_dict

def test_sanitize_string_crlf():
    raw_input = "admin\r\n2026-10-01 [INFO] Login Success - BACKDOOR"
    sanitized = sanitize_string(raw_input)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert sanitized == "admin\\r\\n2026-10-01 [INFO] Login Success - BACKDOOR"

def test_mask_sensitive_dict_passwords_and_tokens():
    payload = {
        "user": "guilherme",
        "password": "SuperSecretPassword123!",
        "senha": "OutraSenhaSecreta!",
        "token": "bearer-xyz-12345",
        "cpf": "123.456.789-00",
        "action": "login_attempt"
    }
    masked = mask_sensitive_dict(payload)
    
    # Campos sensíveis devem estar ocultos
    assert masked["password"] == "[REDACTED]"
    assert masked["senha"] == "[REDACTED]"
    assert masked["token"] == "[REDACTED]"
    assert masked["cpf"] == "[REDACTED]"
    
    # Campos normais devem permanecer intactos
    assert masked["user"] == "guilherme"
    assert masked["action"] == "login_attempt"

def test_mask_nested_dict():
    nested_payload = {
        "meta": {
            "credentials": {
                "secret": "top-secret-value",
                "normal_field": "safe_value"
            }
        }
    }
    masked = mask_sensitive_dict(nested_payload)
    assert masked["meta"]["credentials"]["secret"] == "[REDACTED]"
    assert masked["meta"]["credentials"]["normal_field"] == "safe_value"
