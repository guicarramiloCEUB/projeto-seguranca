import os
import json
import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from app.config import (
    LOG_FILE_VULNERABLE,
    LOG_FILE_PROTECTED,
    is_protected,
    is_vulnerable
)

_log_lock = threading.Lock()
GENESIS_HASH = "0" * 64

SENSITIVE_KEYS = {
    "password", "senha", "pass", "secret", "token", 
    "authorization", "auth", "cpf", "credit_card", "card"
}

def sanitize_string(value: str) -> str:
    """Neutraliza caracteres de quebra de linha e controle (CWE-117)."""
    if not isinstance(value, str):
        return str(value)
    # Neutraliza CRLF para impedir forja de linha (log forging)
    return value.replace("\r", "\\r").replace("\n", "\\n")

def mask_sensitive_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Mascara campos sensíveis como senhas e tokens (CWE-532)."""
    masked = {}
    for k, v in data.items():
        if str(k).strip().lower() in SENSITIVE_KEYS:
            masked[k] = "[REDACTED]"
        elif isinstance(v, dict):
            masked[k] = mask_sensitive_dict(v)
        elif isinstance(v, str):
            masked[k] = sanitize_string(v)
        else:
            masked[k] = v
    return masked

def get_last_hash(log_path: Path) -> str:
    """Obtém o hash do último registro gravado no arquivo de log JSONL."""
    if not log_path.exists() or log_path.stat().st_size == 0:
        return GENESIS_HASH

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            if not lines:
                return GENESIS_HASH
            last_entry = json.loads(lines[-1])
            return last_entry.get("current_hash", GENESIS_HASH)
    except Exception:
        return GENESIS_HASH

def calculate_entry_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    """Calcula o hash SHA-256 de forma canônica e determinística."""
    # Garante ordenação de chaves para cálculo consistente
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    raw_content = f"{prev_hash}|{canonical_payload}"
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()

def log_event(
    event_type: str,
    ip: str,
    username: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    raw_password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Grava o evento no modo configurado (vulnerable vs protected).
    Retorna o payload registrado.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    details = details or {}

    with _log_lock:
        if is_vulnerable():
            # ==========================================
            # MODO VULNERÁVEL:
            # - Sem sanitização de CRLF (vulnerável a CWE-117)
            # - Grava senha em texto claro no log (CWE-532)
            # - Sem integridade / sem cadeia de hashes
            # ==========================================
            pwd_info = f", password={raw_password}" if raw_password else ""
            log_line = (
                f"{timestamp} [{event_type.upper()}] status={status}, "
                f"ip={ip}, user={username}{pwd_info}, details={details}\n"
            )
            with open(LOG_FILE_VULNERABLE, "a", encoding="utf-8") as f:
                f.write(log_line)
            
            return {
                "mode": "vulnerable",
                "raw_line": log_line
            }

        else:
            # ==========================================
            # MODO PROTEGIDO:
            # - Sanitização contra injeção CRLF (CWE-117)
            # - Mascaramento de senhas e dados sensíveis (CWE-532)
            # - JSON estruturado padronizado
            # - Cadeia de hashes SHA-256 (Integridade)
            # ==========================================
            sanitized_user = sanitize_string(username)
            sanitized_details = mask_sensitive_dict(details)
            
            prev_hash = get_last_hash(LOG_FILE_PROTECTED)

            # Conteúdo a ser assinado pelo hash
            entry_content = {
                "timestamp": timestamp,
                "event_type": event_type,
                "ip": ip,
                "username": sanitized_user,
                "status": status,
                "details": sanitized_details
            }

            current_hash = calculate_entry_hash(prev_hash, entry_content)

            full_record = {
                **entry_content,
                "prev_hash": prev_hash,
                "current_hash": current_hash
            }

            with open(LOG_FILE_PROTECTED, "a", encoding="utf-8") as f:
                f.write(json.dumps(full_record, ensure_ascii=False) + "\n")

            return full_record
