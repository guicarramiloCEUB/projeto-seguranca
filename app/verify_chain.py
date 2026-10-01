import sys
import json
import argparse
from pathlib import Path
from typing import Tuple, List, Dict, Any

# Suporte para execução direta 'python app/verify_chain.py'
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import LOG_FILE_PROTECTED
from app.security_log import GENESIS_HASH, calculate_entry_hash

def verify_log_chain(log_path: Path) -> Tuple[bool, str, int]:
    """
    Verifica a integridade criptográfica da cadeia de logs SHA-256.
    Retorna: (is_valid, message, error_line_number)
    """
    if not log_path.exists() or log_path.stat().st_size == 0:
        return True, "Arquivo de log não existe ou está vazio. Nenhuma inconsistência encontrada.", 0

    expected_prev_hash = GENESIS_HASH
    total_entries = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line_str = raw_line.strip()
            if not line_str:
                continue

            total_entries += 1

            # 1. Validação de formato JSON
            try:
                entry: Dict[str, Any] = json.loads(line_str)
            except json.JSONDecodeError as e:
                return False, f"Linha {line_num} contém JSON corrompido: {e}", line_num

            prev_hash = entry.get("prev_hash")
            stored_current_hash = entry.get("current_hash")

            # 2. Validação da continuidade do encadeamento (prev_hash)
            if prev_hash != expected_prev_hash:
                return (
                    False,
                    f"Rompimento da cadeia na Linha {line_num}!\n"
                    f"  - 'prev_hash' esperado : {expected_prev_hash}\n"
                    f"  - 'prev_hash' gravado  : {prev_hash}",
                    line_num
                )

            # 3. Recálculo do Hash do conteúdo (Assinatura do registro)
            entry_content = {
                "timestamp": entry.get("timestamp"),
                "event_type": entry.get("event_type"),
                "ip": entry.get("ip"),
                "username": entry.get("username"),
                "status": entry.get("status"),
                "details": entry.get("details")
            }

            calculated_hash = calculate_entry_hash(prev_hash, entry_content)

            if calculated_hash != stored_current_hash:
                return (
                    False,
                    f"Adulteração de conteúdo detectada na Linha {line_num}!\n"
                    f"  - Hash calculado a partir do conteúdo : {calculated_hash}\n"
                    f"  - Hash gravado originalmente         : {stored_current_hash}\n"
                    f"  - Dados da linha: {json.dumps(entry_content, ensure_ascii=False)}",
                    line_num
                )

            # Avança o elo esperado para a próxima iteração
            expected_prev_hash = stored_current_hash

    return True, f"Cadeia íntegra. Total de {total_entries} registros verificados com sucesso.", 0

def main():
    parser = argparse.ArgumentParser(description="Verificador de Integridade de Logs (Cadeia SHA-256) - OWASP A09")
    parser.add_argument("--file", type=str, default=str(LOG_FILE_PROTECTED), help="Caminho do arquivo de log JSONL")
    args = parser.parse_args()

    log_path = Path(args.file)
    print("\n🔍 Iniciando verificação de integridade da trilha de auditoria...")
    print(f"📄 Arquivo analisado: {log_path.resolve()}\n")

    is_valid, msg, error_line = verify_log_chain(log_path)

    border = "=" * 70
    if is_valid:
        print(f"\033[92m{border}")
        print("✅ [INTEGRIDADE CONFIRMADA] A CADEIA DE LOGS ESTÁ 100% ÍNTEGRA!")
        print(f"{border}\033[0m")
        print(f"  ℹ️  {msg}")
        print("\033[92m" + border + "\033[0m\n")
        sys.exit(0)
    else:
        print(f"\033[91m{border}")
        print("❌ [FALHA DE INTEGRIDADE] DETECTADA ADULTERAÇÃO NO ARQUIVO DE LOG!")
        print(f"{border}\033[0m")
        print(f"  🚨 Linha afetada : \033[93m{error_line}\033[0m")
        print(f"  ⚠️  Detalhes     :\n{msg}")
        print(f"\033[91m{border}\033[0m\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
