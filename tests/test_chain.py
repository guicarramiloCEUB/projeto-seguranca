import json
from pathlib import Path
import app.security_log as slog
from app.verify_chain import verify_log_chain

def test_hash_chain_integrity_and_tamper_detection(tmp_path: Path):
    test_log = tmp_path / "test_chain.jsonl"
    prev_hash = slog.GENESIS_HASH

    # 1. Cria 4 registros válidos encadeados
    for i in range(1, 5):
        payload = {
            "timestamp": f"2026-10-01T12:00:0{i}Z",
            "event_type": "AUTH_LOGIN",
            "ip": "127.0.0.1",
            "username": f"user{i}",
            "status": "SUCCESS" if i % 2 == 0 else "FAILED",
            "details": {"attempt": i}
        }
        current_hash = slog.calculate_entry_hash(prev_hash, payload)
        record = {**payload, "prev_hash": prev_hash, "current_hash": current_hash}
        with open(test_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        prev_hash = current_hash

    # Verifica integridade inicial
    is_valid, msg, err_line = verify_log_chain(test_log)
    assert is_valid is True
    assert err_line == 0

    # 2. Simula adulteração na Linha 2 (alterando o status)
    lines = test_log.read_text().splitlines()
    entry_2 = json.loads(lines[1])
    entry_2["status"] = "FORGED_STATUS"
    lines[1] = json.dumps(entry_2)
    test_log.write_text("\n".join(lines) + "\n")

    # Verifica se a adulteração é detectada na linha 2
    is_valid_tampered, msg_tampered, err_line_tampered = verify_log_chain(test_log)
    assert is_valid_tampered is False
    assert err_line_tampered == 2
    assert "Linha 2" in msg_tampered
