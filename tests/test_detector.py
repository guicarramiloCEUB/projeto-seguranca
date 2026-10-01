import time
import app.detector as detector
from app.config import BRUTE_FORCE_THRESHOLD

def test_detector_triggers_alert_at_threshold():
    detector.reset_detector()
    ip = "192.168.10.50"
    user = "vitima"

    # Tentativas antes do limiar não devem disparar alerta
    for i in range(1, BRUTE_FORCE_THRESHOLD):
        result = detector.record_failed_login(ip, user)
        assert result is None, f"Alerta não deveria disparar na tentativa {i}"

    # Tentativa no limiar (5ª tentativa) DEVE disparar alerta
    alert_result = detector.record_failed_login(ip, user)
    assert alert_result is not None
    assert alert_result["alert"] is True
    assert alert_result["ip"] == ip
    assert alert_result["attempt_count"] == BRUTE_FORCE_THRESHOLD

    detector.reset_detector()

def test_detector_reset():
    detector.reset_detector()
    ip = "10.0.0.99"
    detector.record_failed_login(ip, "admin")
    detector.record_failed_login(ip, "admin")
    detector.reset_detector()
    
    # Após reset, precisa de threshold completo de tentativas novamente
    alert = detector.record_failed_login(ip, "admin")
    assert alert is None
    detector.reset_detector()
