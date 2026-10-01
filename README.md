# Projeto de Segurança: Mecanismo de Defesa para OWASP A09
> **OWASP Top 10 - A09: Security Logging and Alerting Failures**  
> Implementação prática dos fundamentos teóricos do artigo acadêmico (*Guilherme de Castro Carramilo e Luiz Alberto Lisot*).

---

## 🎯 Visão Geral do Projeto

Este projeto implementa um mecanismo de defesa ativo e demonstrável contra falhas de registro, monitoramento e alerta, estruturado em uma aplicação web moderna com **FastAPI (Python)**.

A aplicação conta com um seletor de ambiente (`SECURITY_MODE`) que permite demonstrar o contraste direto **"Antes vs. Depois"**:
1. **Modo Vulnerável (`SECURITY_MODE=vulnerable`)**: simula uma aplicação legada sem monitoramento ativo, exposta a injeção em logs, vazamento de credenciais e silenciosa diante de ataques.
2. **Modo Protegido (`SECURITY_MODE=protected`)**: aplica os 5 eixos de mitigação do artigo, integrando logs estruturados, sanitização estrita, cadeia de custódia criptográfica e alertas em tempo real.

---

## 🛡️ As 3 Defesas Implementadas

| # | Defesa | O que foi implementado | Fraquezas Cobertas |
|---|---|---|---|
| **1** | **Detector de Força Bruta com Alerta em Tempo Real** | Algoritmo de janela deslizante em memória que monitora falhas de autenticação. Ao atingir o limiar (5 falhas em 60s), emite alerta crítico no terminal e notificação via Webhook Discord. | **CWE-778** (*Insufficient Logging*) |
| **2** | **Proteção contra Log Injection e Vazamento de Dados** | Filtro que neutraliza quebras de linha (`\r`, `\n`) em dados do usuário e aplica mascaramento automático (`[REDACTED]`) em senhas, tokens e credenciais. | **CWE-117** (*Improper Output Neutralization*) e **CWE-532** (*Insertion of Sensitive Information*) |
| **3** | **Integridade de Auditoria (Cadeia de Hashes SHA-256)** | Cada registro armazena `prev_hash` e calcula `hash = SHA256(prev_hash + payload)`. O utilitário `verify_chain.py` detecta qualquer modificação manual e aponta a linha exata adulterada. | **Integridade de Logs / Trilha de Auditoria** |

---

## 📂 Estrutura de Arquivos

```
projeto-seguranca/
├── app/
│   ├── config.py           # Configurações gerais, limiares de alerta e alternância de modos
│   ├── security_log.py     # Motor de logging vulnerável vs. estruturado + sanitização + SHA-256
│   ├── detector.py         # Janela deslizante de força bruta e emissão de alertas (Terminal/Discord)
│   ├── verify_chain.py     # Verificador CLI de integridade criptográfica da cadeia
│   └── main.py             # Aplicação FastAPI com rotas /login, /status, /logs e Swagger UI
├── attack/
│   ├── brute_force.py      # Script de simulação de rajada de tentativas inválidas de login
│   ├── log_injection.py    # Script que envia payload malicioso CRLF e credencial real
│   └── tamper_log.py       # Utilitário para forjar uma linha do log durante a demonstração
├── tests/
│   ├── test_api.py          # Testes funcionais das rotas da API
│   ├── test_detector.py     # Testes da contagem de falhas e limiar do detector
│   ├── test_sanitization.py # Testes de neutralização CRLF (CWE-117) e mascaramento (CWE-532)
│   └── test_chain.py        # Testes de integridade da cadeia e detecção de adulteração
├── requirements.txt        # Dependências do projeto (FastAPI, Uvicorn, HTTPX, Pytest)
└── README.md               # Documentação e roteiro de apresentação
```

---

## 🚀 Instalação e Preparação

### 1. Criar e Ativar o Ambiente Virtual

```bash
# Criar o ambiente virtual
python3 -m venv .venv

# Ativar no Linux / macOS
source .venv/bin/activate
```

### 2. Instalar as Dependências

```bash
pip install -r requirements.txt
```

---

## 🎬 Roteiro de Demonstração ao Vivo (5 a 8 minutos)

O roteiro abaixo foi desenhado para ser apresentado com **dois terminais abertos lado a lado**:
- **Terminal 1**: Executando o servidor FastAPI.
- **Terminal 2**: Executando os scripts de ataque e verificação.

---

### **PARTE 1: O "Antes" (Modo Vulnerável)**

#### 1. Iniciar a API em Modo Vulnerável
No **Terminal 1**:
```bash
SECURITY_MODE=vulnerable uvicorn app.main:app --port 8000
```

#### 2. Executar o Ataque de Força Bruta
No **Terminal 2**:
```bash
python attack/brute_force.py --attempts 15
```
> **O que falar:**  
> *"O invasor realizou 15 tentativas consecutivas de invasão. Como demonstrado na teoria da CWE-778, a aplicação vulnerável não monitora nem alerta. O ataque passou em total silêncio operacional."*

#### 3. Executar o Ataque de Log Injection e Vazamento
No **Terminal 2**:
```bash
python attack/log_injection.py
```
Em seguida, inspecione o arquivo de log gerado:
```bash
cat logs/app_vulnerable.log
```
> **O que falar:**  
> *"Vejam que o atacante injetou uma quebra de linha com um falso status 'SUCCESS', forjando o histórico de auditoria (CWE-117). Além disso, a senha foi gravada em texto claro no arquivo (CWE-532), violando o princípio da necessidade da LGPD."*

---

### **PARTE 2: O "Depois" (Modo Protegido)**

Encerre o servidor no **Terminal 1** (`Ctrl+C`) e limpe os logs anteriores:
```bash
rm -f logs/*
```

#### 1. Iniciar a API em Modo Protegido
No **Terminal 1**:
```bash
SECURITY_MODE=protected uvicorn app.main:app --port 8000
```
*(Opcional: Se quiser notificações reais no Discord, defina `export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."` antes).*

#### 2. Repetir o Ataque de Força Bruta
No **Terminal 2**:
```bash
python attack/brute_force.py --attempts 15
```
> **O que observar:**  
> No **Terminal 1**, exatamente na **5ª falha**, um banner vermelho `🚨 [ALERTA DE SEGURANÇA - OWASP A09]` é emitido imediatamente na tela informando o IP atacante e o alvo.

#### 3. Repetir o Ataque de Log Injection
No **Terminal 2**:
```bash
python attack/log_injection.py
```
Inspecione o log protegido:
```bash
cat logs/app_protected.jsonl
```
> **O que falar:**  
> *"Agora o log é JSON estruturado. A injeção de quebra de linha foi neutralizada (`\n` virou string literal sem quebrar o registro), e a senha foi automaticamente mascarada com `[REDACTED]`."*

---

### **PARTE 3: Auditoria e Integridade Criptográfica (SHA-256)**

#### 1. Conferir a Integridade da Cadeia
No **Terminal 2**:
```bash
python -m app.verify_chain
```
> **Resultado:**  
> `✅ [INTEGRIDADE CONFIRMADA] A CADEIA DE LOGS ESTÁ 100% ÍNTEGRA!`

#### 2. Simular uma Adulteração Maliciosa
No **Terminal 2**, execute o script que altera o status de uma linha do log (ex: forjando um login para SUCCESS):
```bash
python attack/tamper_log.py --line 3
```

#### 3. Reexecutar a Verificação
No **Terminal 2**:
```bash
python -m app.verify_chain
```
> **Resultado:**  
> `❌ [FALHA DE INTEGRIDADE] DETECTADA ADULTERAÇÃO NO ARQUIVO DE LOG!`  
> O script aponta com precisão: `🚨 Linha afetada : 3` e mostra a divergência criptográfica entre o hash armazenado e o conteúdo recalculado.

---

## 🧪 Testes Automatizados

Para executar toda a suíte de testes unitários:

```bash
pytest -v
```

Os 10 testes validam:
- Sanitização contra CRLF injection (`CWE-117`);
- Mascaramento de dados e senhas em dicionários aninhados (`CWE-532`);
- Comportamento de janela temporal e gatilho de alerta (`CWE-778`);
- Encadeamento contínuo de hashes e detecção determinística de fraude;
- Endpoints REST da API FastAPI.
