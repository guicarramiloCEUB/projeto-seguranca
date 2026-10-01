import time
import threading
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, Dict, Any, List

import httpx

from app.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DISCORD_WEBHOOK_URL,
    is_protected,
    is_vulnerable
)

_detector_lock = threading.Lock()
# Estrutura em memória: ip -> lista de timestamps das tentativas falhas
_failed_attempts: Dict[str, List[float]] = defaultdict(list)
# Controle para evitar disparos repetidos a cada milissegundo (cooldown de alerta por IP)
_last_alert_time: Dict[str, float] = {}

def send_terminal_alert(alert_title: str, ip: str, username: str, count: int) -> None:
    """Exibe um banner visual de alta prioridade no console."""
    border = "=" * 70
    alert_box = (
        f"\n\033[91m{border}\n"
        f"🚨 [ALERTA DE SEGURANÇA - OWASP A09] {alert_title.upper()}\n"
        f"{border}\033[0m\n"
        f"  ⏰ Horário     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"  🌐 IP Atacante : \033[93m{ip}\033[0m\n"
        f"  👤 Alvo        : \033[96m{username}\033[0m\n"
        f"  ⚠️  Tentativas  : \033[91m{count} falhas na janela de {BRUTE_FORCE_WINDOW_SECONDS}s\033[0m (Limite: {BRUTE_FORCE_THRESHOLD})\n"
        f"  🛡️ Ação tomada : Notificação aos administradores e registro em trilha de auditoria.\n"
        f"\033[91m{border}\033[0m\n"
    )
    print(alert_box, flush=True)

def send_discord_webhook(alert_title: str, ip: str, username: str, count: int) -> None:
    """Envia notificação via Webhook Discord se a URL estiver configurada."""
    if not DISCORD_WEBHOOK_URL:
        return

    payload = {
        "content": "🚨 **[ALERTA DE SEGURANÇA OWASP A09]** Possível ataque detectado!",
        "embeds": [
            {
                "title": alert_title,
                "color": 15158332, # Vermelho
                "fields": [
                    {"name": "IP Atacante", "value": ip, "inline": True},
                    {"name": "Usuário Alvo", "value": username or "N/A", "inline": True},
                    {"name": "Tentativas Falhas", "value": f"{count} em {BRUTE_FORCE_WINDOW_SECONDS}s", "inline": False},
                    {"name": "Timestamp", "value": datetime.now(timezone.utc).isoformat(), "inline": False}
                ],
                "footer": {"text": "Projeto Segurança OWASP A09 - Defesa Ativa"}
            }
        ]
    }
    try:
        httpx.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3.0)
    except Exception as e:
        print(f"[!] Falha ao enviar alerta para Discord: {e}", flush=True)

def record_failed_login(ip: str, username: str) -> Optional[Dict[str, Any]]:
    """
    Registra uma tentativa falha de login.
    No modo vulnerável: não faz monitoramento nem emite alertas (cegueira de monitoramento).
    No modo protegido: avalia a janela deslizante e aciona alertas ao ultrapassar o limiar.
    """
    if is_vulnerable():
        # Modo vulnerável simula a ausência de monitoramento/alertas
        return None

    now = time.time()
    with _detector_lock:
        timestamps = _failed_attempts[ip]
        # Remove registros fora da janela móvel
        _failed_attempts[ip] = [t for t in timestamps if now - t <= BRUTE_FORCE_WINDOW_SECONDS]
        _failed_attempts[ip].append(now)

        current_count = len(_failed_attempts[ip])
        last_alert = _last_alert_time.get(ip, 0)

        # Se atingir ou ultrapassar o threshold e já passou o cooldown (10 segundos)
        if current_count >= BRUTE_FORCE_THRESHOLD and (now - last_alert > 10):
            _last_alert_time[ip] = now
            
            # 1. Alerta no terminal
            send_terminal_alert("Possível Ataque de Força Bruta Detectado", ip, username, current_count)

            # 2. Alerta no Discord (se configurado)
            send_discord_webhook("Detecção de Força Bruta", ip, username, current_count)

            return {
                "alert": True,
                "type": "BRUTE_FORCE_ATTACK",
                "ip": ip,
                "target_user": username,
                "attempt_count": current_count
            }

    return None

def reset_detector() -> None:
    """Limpa contadores (útil para testes unitários)."""
    with _detector_lock:
        _failed_attempts.clear()
        _last_alert_time.clear()
