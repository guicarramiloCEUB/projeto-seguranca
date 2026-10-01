import sys
import time
import argparse
import httpx

def run_brute_force(base_url: str, username: str, attempts: int, delay: float):
    login_url = f"{base_url.rstrip('/')}/login"
    print("\n" + "=" * 65)
    print(f"💥 [SIMULAÇÃO DE ATAQUE] Iniciando Força Bruta contra {login_url}")
    print(f"🎯 Alvo: Usuário '{username}' | Total de tentativas: {attempts}")
    print("=" * 65 + "\n")

    success_count = 0
    fail_count = 0

    with httpx.Client(timeout=5.0) as client:
        for i in range(1, attempts + 1):
            payload = {
                "username": username,
                "password": f"TentativaSenhaErrada#{i}"
            }
            try:
                start_time = time.time()
                resp = client.post(login_url, json=payload)
                elapsed = (time.time() - start_time) * 1000

                if resp.status_code == 200:
                    status_icon = "🟢"
                    success_count += 1
                elif resp.status_code == 401:
                    status_icon = "🔴"
                    fail_count += 1
                else:
                    status_icon = "⚠️"

                print(f"[{i:02d}/{attempts:02d}] {status_icon} Tentativa com senha '{payload['password']}' -> HTTP {resp.status_code} ({elapsed:.1f}ms)")

            except httpx.ConnectError:
                print(f"\n❌ Erro: Não foi possível conectar ao servidor em {base_url}.")
                print("Certifique-se de que a aplicação FastAPI está rodando (ex.: uvicorn app.main:app).")
                sys.exit(1)
            except Exception as e:
                print(f"[{i:02d}/{attempts:02d}] ❌ Exceção: {e}")

            time.sleep(delay)

    print("\n" + "=" * 65)
    print("🏁 [FIM DO TESTE]")
    print(f"   Falhas registradas : {fail_count}")
    print(f"   Sucessos           : {success_count}")
    print("=" * 65)
    print("👉 Verifique o terminal do servidor FastAPI para conferir se houve disparo de alerta!\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulador de Ataque de Força Bruta - OWASP A09")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="URL base da API FastAPI")
    parser.add_argument("--user", type=str, default="admin", help="Nome do usuário alvo")
    parser.add_argument("--attempts", type=int, default=15, help="Quantidade de requisições de teste")
    parser.add_argument("--delay", type=float, default=0.1, help="Intervalo em segundos entre as tentativas")
    args = parser.parse_args()

    run_brute_force(args.url, args.user, args.attempts, args.delay)
