import sys
import argparse
import httpx

def run_log_injection(base_url: str):
    login_url = f"{base_url.rstrip('/')}/login"

    # Payload malicioso: quebra de linha com falso evento de sucesso de autenticação
    forged_event = "2026-10-01T12:00:00 [AUTH_LOGIN] status=SUCCESS, ip=10.0.0.99, user=admin - BACKDOOR_AUTHENTICATED"
    malicious_username = f"admin\n{forged_event}"
    sensitive_password = "MinhaSenhaSuperSecreta123!"

    payload = {
        "username": malicious_username,
        "password": sensitive_password
    }

    print("\n" + "=" * 70)
    print("💉 [SIMULAÇÃO DE ATAQUE] Teste de Log Injection (CWE-117) e Vazamento (CWE-532)")
    print(f"🎯 Destino: {login_url}")
    print("=" * 70)
    print("📦 Payload enviado:")
    print(f"   👤 username : {repr(malicious_username)}")
    print(f"   🔑 password : {sensitive_password}")
    print("=" * 70 + "\n")

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(login_url, json=payload)
            print(f"📡 Resposta do Servidor: HTTP {resp.status_code}")
            print(f"📄 Corpo: {resp.text}\n")
    except httpx.ConnectError:
        print(f"❌ Erro: Não foi possível conectar ao servidor em {base_url}.")
        print("Certifique-se de que a aplicação FastAPI está rodando.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro na requisição: {e}")
        sys.exit(1)

    print("=" * 70)
    print("🔍 COMO AVALIAR O RESULTADO:")
    print("1. No MODO VULNERÁVEL:")
    print("   Abra 'logs/app_vulnerable.log'.")
    print("   -> Você verá que a quebra de linha criou uma linha falsa (CWE-117).")
    print("   -> Você verá a senha 'MinhaSenhaSuperSecreta123!' em texto claro (CWE-532).")
    print("\n2. No MODO PROTEGIDO:")
    print("   Abra 'logs/app_protected.jsonl'.")
    print("   -> O registro permanece estritamente em uma única linha JSON (CWE-117 neutralizado).")
    print("   -> A senha foi substituída por '[REDACTED]' (CWE-532 protegido).")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulador de Log Injection (CWE-117) e Vazamento de Senhas (CWE-532)")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="URL base da API FastAPI")
    args = parser.parse_args()

    run_log_injection(args.url)
