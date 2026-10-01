# 📋 Guia de Comandos para a Apresentação (Passo a Passo)

Este guia contém o roteiro prático e a sequência exata de comandos para a apresentação ao vivo do projeto de defesa contra **OWASP A09 (Security Logging and Alerting Failures)**.

---

## 🖥️ Preparação dos Terminais (Antes de Iniciar)

Abra **dois terminais lado a lado**:
- **Terminal 1 (Esquerda)**: Será o servidor da aplicação FastAPI.
- **Terminal 2 (Direita)**: Será o cliente (atacante / auditor).

Em **ambos os terminais**, navegue até o diretório do projeto e ative o ambiente virtual:
```bash
cd /home/guicarramilo/git/projeto-seguranca
source .venv/bin/activate
```

---

## 🎬 PARTE 1: O "Antes" (Modo Vulnerável)
> **Objetivo:** Mostrar que sem registros úteis, monitoramento e alerta, ataques passam despercebidos e dados confidenciais vazam.

### 1. Iniciar o servidor em Modo Vulnerável
No **Terminal 1**:
```bash
SECURITY_MODE=vulnerable uvicorn app.main:app --port 8000
```

### 2. Disparar o Ataque de Força Bruta
No **Terminal 2**:
```bash
python attack/brute_force.py --attempts 15
```
* **O que falar:**  
  *"O atacante disparou 15 tentativas consecutivas de senha. Observem o Terminal 1: a aplicação respondeu com erro 401, mas nenhum alerta foi gerado e nenhum log de segurança relevante foi gravado (**CWE-778 - Insufficient Logging**). O ataque passou em silêncio total."*

### 3. Disparar Injeção em Logs e Vazamento de Senha
No **Terminal 2**:
```bash
python attack/log_injection.py
```

### 4. Mostrar o Arquivo de Log Corrompido
No **Terminal 2**:
```bash
cat logs/app_vulnerable.log
```
* **O que mostrar na tela:**
  1. A quebra de linha `\n` injetou uma **segunda linha falsa** de login com status `SUCCESS` (**CWE-117 - Log Injection**);
  2. A senha `MinhaSenhaSuperSecreta123!` foi gravada em texto claro (**CWE-532 - Vazamento de Dados**), violando o princípio da necessidade da LGPD.

---

## 🔁 Transição Rápida (10 segundos)

1. No **Terminal 1**, pressione `Ctrl + C` para encerrar o servidor vulnerável.
2. No **Terminal 2**, limpe os logs anteriores para iniciar a demonstração protegida:
```bash
rm -f logs/*
```

---

## 🛡️ PARTE 2: O "Depois" (Modo Protegido)
> **Objetivo:** Mostrar a defesa ativa, o alerta em tempo real, a neutralização da injeção e o mascaramento.

### 1. Iniciar o servidor em Modo Protegido
No **Terminal 1**:
```bash
SECURITY_MODE=protected uvicorn app.main:app --port 8000
```
*(Opcional: Se quiser notificações reais no Discord, execute `export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."` no Terminal 1 antes do uvicorn).*

### 2. Repetir o Ataque de Força Bruta
No **Terminal 2**:
```bash
python attack/brute_force.py --attempts 15
```
* **O que observar:**  
  Olhe para o **Terminal 1**. Exatamente na **5ª falha**, um banner vermelho `🚨 [ALERTA DE SEGURANÇA - OWASP A09]` aparece na tela informando o IP atacante e as 5 falhas no intervalo de 60 segundos.
* **O que falar:**  
  *"Conforme a edição 2025 da OWASP (Security Logging and Alerting Failures), o foco é a capacidade de agir. Atingido o limiar da janela deslizante, a aplicação detectou o padrão anômalo e disparou o alerta imediatamente."*

### 3. Repetir o Ataque de Injeção em Log
No **Terminal 2**:
```bash
python attack/log_injection.py
```

### 4. Inspecionar o Log Estruturado
No **Terminal 2**:
```bash
cat logs/app_protected.jsonl
```
* **O que falar:**  
  *"Notem a diferença: agora os logs são JSON estruturado. A injeção de quebra de linha foi neutralizada (`\n` virou string literal) mantendo o registro em linha única, e a senha foi mascarada para `[REDACTED]`."*

---

## 🔗 PARTE 3: Auditoria e Integridade Criptográfica (SHA-256)
> **Objetivo:** Demonstrar que o log possui integridade garantida e detecta se alguém tentar adulterar o histórico.

### 1. Verificar a Integridade da Cadeia de Logs
No **Terminal 2**:
```bash
python -m app.verify_chain
```
* **Resultado esperado:**  
  Caixa verde: `✅ [INTEGRIDADE CONFIRMADA] A CADEIA DE LOGS ESTÁ 100% ÍNTEGRA!`.

### 2. Simular uma Adulteração Maliciosa
No **Terminal 2**, execute o script que altera o status de uma linha do log (ex: forjando um login para SUCCESS):
```bash
python attack/tamper_log.py --line 3
```

### 3. Rodar a Verificação Novamente
No **Terminal 2**:
```bash
python -m app.verify_chain
```
* **Resultado esperado:**  
  Caixa vermelha: `❌ [FALHA DE INTEGRIDADE] DETECTADA ADULTERAÇÃO NO ARQUIVO DE LOG!` apontando com precisão a **Linha 3**.
* **O que falar:**  
  *"Cada linha armazena o hash da anterior e o seu próprio hash criptográfico. Se um invasor ou administrador mal-intencionado alterar o status de um registro, a quebra da cadeia é imediatamente identificada."*

---

## 🧪 PARTE 4: Conclusão com Testes Automatizados (Opcional - 30s)
No **Terminal 2**:
```bash
pytest -v
```
* **O que falar:**  
  *"Para assegurar a confiabilidade, construímos uma suíte com 10 testes unitários automatizados validando sanitização, mascaramento, detecção por limiar, integridade e rotas da API."*
