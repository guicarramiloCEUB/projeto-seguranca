import os
from pathlib import Path

# Diretórios base
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Modo de Operação: 'vulnerable' ou 'protected' (padrão: protected)
SECURITY_MODE = os.getenv("SECURITY_MODE", "protected").strip().lower()

def is_protected() -> bool:
    return SECURITY_MODE == "protected"

def is_vulnerable() -> bool:
    return SECURITY_MODE == "vulnerable"

# Arquivos de log para cada modo
LOG_FILE_VULNERABLE = LOG_DIR / "app_vulnerable.log"
LOG_FILE_PROTECTED = LOG_DIR / "app_protected.jsonl"

# Parâmetros de detecção de força bruta (Ideia 1 - CWE-778)
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "60"))

# Configuração de Alertas (Notificações)
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()

# Base de usuários em memória para simulação da aplicação
MOCK_USERS = {
    "admin": "SuperAdminPass2026!",
    "guilherme": "SenhaForte#2026",
    "analista": "Analista123!"
}
