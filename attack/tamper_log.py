import sys
import json
import argparse
from pathlib import Path

# Garante que o diretório raiz do projeto esteja no sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.config import LOG_FILE_PROTECTED

def tamper_log(line_number: int, target_file: Path):
    if not target_file.exists():
        print(f"❌ Erro: O arquivo {target_file} não existe. Execute algumas requisições no modo protegido primeiro.")
        sys.exit(1)

    with open(target_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        print("❌ Erro: O arquivo de log está vazio.")
        sys.exit(1)

    if line_number < 1 or line_number > len(lines):
        print(f"❌ Linha inválida: O arquivo possui {len(lines)} registros (escolha entre 1 e {len(lines)}).")
        sys.exit(1)

    idx = line_number - 1
    original_line = lines[idx]
    
    try:
        entry = json.loads(original_line)
    except Exception as e:
        print(f"❌ Erro ao decodificar JSON na linha {line_number}: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(f"🎭 [SIMULAÇÃO DE ADULTERAÇÃO DE AUDITORIA] Modificando Linha {line_number}")
    print("=" * 70)
    print(f"📜 Conteúdo Original:\n  {json.dumps(entry, ensure_ascii=False)}")

    # Simula um invasor tentando encobrir uma falha ou fraudar o status
    original_status = entry.get("status")
    new_status = "SUCCESS" if original_status != "SUCCESS" else "FAILED_TAMPERED"
    entry["status"] = new_status
    
    # Se houver usuário, adiciona marcador de adulteração
    if "details" in entry and isinstance(entry["details"], dict):
        entry["details"]["tampered_by_attacker"] = True

    tampered_line = json.dumps(entry, ensure_ascii=False)
    lines[idx] = tampered_line

    with open(target_file, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"\n✏️ Conteúdo Adulterado (Status alterado para '{new_status}'):\n  {tampered_line}")
    print("=" * 70)
    print("🚨 Adulteração aplicada no arquivo de log com sucesso!")
    print("👉 Agora execute a verificação para ver o detector em ação:")
    print("   .venv/bin/python -m app.verify_chain\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulador de Adulteração de Log de Auditoria")
    parser.add_argument("--line", type=int, default=1, help="Número da linha a ser adulterada (1-indexed)")
    parser.add_argument("--file", type=str, default=str(LOG_FILE_PROTECTED), help="Caminho do arquivo de log")
    args = parser.parse_args()

    tamper_log(args.line, Path(args.file))
