from fastapi import FastAPI, Request, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict, Any
from pathlib import Path
import json

from app.config import (
    SECURITY_MODE,
    is_protected,
    is_vulnerable,
    LOG_FILE_VULNERABLE,
    LOG_FILE_PROTECTED,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    MOCK_USERS
)
import app.security_log as security_log
import app.detector as detector

app = FastAPI(
    title=f"OWASP A09 Defense Demo ({SECURITY_MODE.upper()})",
    description="Demonstração prática de defesas contra Falhas de Registro, Monitoramento e Alerta.",
    version="1.0.0"
)

class LoginRequest(BaseModel):
    username: str
    password: str

def get_client_ip(request: Request) -> str:
    """Extrai o IP do cliente considerando proxies se existirem."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@app.get("/")
def read_root():
    return {
        "projeto": "Defesa contra OWASP A09 (Security Logging and Alerting Failures)",
        "modo_atual": SECURITY_MODE,
        "docs": "/docs",
        "endpoints": {
            "login": "POST /login",
            "profile": "GET /profile?user=admin",
            "status": "GET /status",
            "logs": "GET /logs"
        }
    }

@app.get("/status")
def get_status():
    """Retorna o estado operacional e os parâmetros de segurança."""
    active_log = str(LOG_FILE_PROTECTED if is_protected() else LOG_FILE_VULNERABLE)
    return {
        "security_mode": SECURITY_MODE,
        "is_protected": is_protected(),
        "active_log_file": active_log,
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "brute_force_window_seconds": BRUTE_FORCE_WINDOW_SECONDS
    }

@app.post("/login")
def login(creds: LoginRequest, request: Request):
    """
    Endpoint de autenticação.
    Registra eventos com contexto suficiente e aciona monitoramento.
    """
    client_ip = get_client_ip(request)
    username = creds.username
    password = creds.password

    # Valida credenciais na base simulada
    stored_password = MOCK_USERS.get(username)
    is_authenticated = (stored_password is not None and stored_password == password)

    if is_authenticated:
        # Sucesso de autenticação
        if is_vulnerable():
            security_log.log_event(
                event_type="AUTH_LOGIN",
                ip=client_ip,
                username=username,
                status="SUCCESS",
                raw_password=password
            )
        else:
            security_log.log_event(
                event_type="AUTH_LOGIN",
                ip=client_ip,
                username=username,
                status="SUCCESS",
                details={"action": "user_login", "auth_method": "password"}
            )

        return {
            "status": "success",
            "message": f"Autenticado com sucesso como '{username}'.",
            "user": username
        }

    # Falha de autenticação
    if is_vulnerable():
        # Modo vulnerável:
        # 1. Sem sanitização (CWE-117)
        # 2. Senha em texto claro (CWE-532)
        # 3. Detector inativo (CWE-778)
        security_log.log_event(
            event_type="AUTH_LOGIN",
            ip=client_ip,
            username=username,
            status="FAILED",
            raw_password=password
        )
        detector.record_failed_login(client_ip, username)
    else:
        # Modo protegido:
        # 1. Sanitização e mascaramento
        # 2. Cadeia de hashes
        # 3. Detector ativo com disparo de alerta
        security_log.log_event(
            event_type="AUTH_LOGIN",
            ip=client_ip,
            username=username,
            status="FAILED",
            details={
                "action": "user_login",
                "reason": "invalid_credentials",
                "password_attempt": password # Será mascarado para [REDACTED]
            }
        )

        alert_info = detector.record_failed_login(client_ip, username)
        if alert_info:
            # Registra o evento de alerta também na trilha de auditoria
            security_log.log_event(
                event_type="SECURITY_ALERT",
                ip=client_ip,
                username=username,
                status="TRIGGERED",
                details=alert_info
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas."
    )

@app.get("/profile")
def get_profile(user: str = "convidado"):
    return {
        "user": user,
        "message": f"Perfil do usuário {user}.",
        "access": "granted"
    }

@app.get("/logs")
def view_logs(limit: int = 50):
    """Permite inspecionar os últimos registros de log gerados no modo atual."""
    target_file = LOG_FILE_PROTECTED if is_protected() else LOG_FILE_VULNERABLE
    if not target_file.exists():
        return {"mode": SECURITY_MODE, "entries": []}

    with open(target_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if is_protected():
        parsed = []
        for line in lines[-limit:]:
            try:
                parsed.append(json.loads(line))
            except Exception:
                parsed.append({"raw": line})
        return {"mode": SECURITY_MODE, "total_lines": len(lines), "entries": parsed}
    else:
        return {"mode": SECURITY_MODE, "total_lines": len(lines), "entries": lines[-limit:]}

@app.delete("/logs")
def clear_logs():
    """Limpa os arquivos de log (útil para reiniciar a demonstração)."""
    detector.reset_detector()
    if LOG_FILE_VULNERABLE.exists():
        LOG_FILE_VULNERABLE.unlink()
    if LOG_FILE_PROTECTED.exists():
        LOG_FILE_PROTECTED.unlink()
    return {"message": "Logs limpos e detector reiniciado com sucesso."}
