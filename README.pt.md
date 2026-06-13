# 🔭 MailScope

> Um diagnóstico completo da segurança de e-mail do seu domínio.

Script em Python que analisa a segurança de e-mail de qualquer domínio, verificando **SPF**, **DKIM**, **DMARC**, **MTA-STS**, **registros MX** e **DNSSEC**.

Todas as verificações usam **consultas DNS públicas** (e HTTPS apenas para MTA-STS) — **nenhuma API externa** é necessária.

[🇺🇸 English (main)](README.md)

---

## 🚀 Como executar

### 1. Pré-requisitos

- Python 3.8 ou superior
- Instalar as dependências:

```bash
pip install -r requirements.txt
```

(ou manualmente: `pip install dnspython requests`)

### 2. Executar

**Modo interativo** (o script pergunta o domínio):

```bash
python mailscope.py
```

**Modo direto** (domínio como argumento):

```bash
python mailscope.py exemplo.com.br
```

**Informando o seletor DKIM** (segundo argumento, opcional):

```bash
python mailscope.py exemplo.com.br google
```

> 💡 Digite apenas o domínio, sem `https://` ou `www` — o script limpa isso automaticamente.

---

## 🔍 O que cada verificação faz

### 1. SPF (Sender Policy Framework)

**O que é:** registro TXT no DNS que lista quais servidores estão autorizados a enviar e-mail em nome do domínio. Sem ele, qualquer pessoa pode enviar e-mails "fingindo" ser o seu domínio.

**Como o script verifica:** busca registros TXT no domínio raiz que comecem com `v=spf1`.

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` com `-all` | Hard fail — servidores não autorizados são rejeitados. **Configuração ideal.** |
| `[WARNING]` com `~all` | Soft fail — e-mails suspeitos são marcados, mas não rejeitados. Aceitável. |
| `[WARNING]` com `?all` | Neutro — praticamente não protege nada. |
| `[FAIL]` com `+all` | **Crítico** — autoriza qualquer servidor do mundo a enviar pelo seu domínio. |
| `[FAIL]` sem registro | Não existe SPF. Crie um registro TXT no DNS. |
| `[FAIL]` registros duplicados | Mais de um SPF causa erro de validação (`permerror`). |

O script também conta os **lookups DNS** (`include:`, `mx`, `a`, etc.). A RFC 7208 limita a 10 — acima disso, o SPF quebra.

**Riscos mitigados quando OK (`-all`):** spoofing de remetente; envio não autorizado; spam/phishing usando sua marca.

---

### 2. DKIM (DomainKeys Identified Mail)

**O que é:** assinatura criptográfica adicionada aos e-mails enviados. O servidor de destino valida a assinatura usando a chave pública publicada no DNS, garantindo que a mensagem não foi alterada e veio mesmo do domínio.

**Como o script verifica:** o DKIM fica em `<seletor>._domainkey.<dominio>`. Como o seletor varia por provedor, o script testa automaticamente os mais comuns do mercado:

- `google` (Google Workspace)
- `selector1`, `selector2` (Microsoft 365)
- `k1`, `k2` (Mailchimp)
- `s1`, `s2` (SendGrid)
- `amazonses` (Amazon SES)
- entre outros

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` seletor encontrado | DKIM publicado. O script ainda avalia o tamanho da chave. |
| `[INFO]` chave ~2048 bits | Tamanho recomendado atualmente. |
| `[WARNING]` chave ~1024 bits | Funciona, mas é considerada fraca. Migre para 2048. |
| `[FAIL]` chave vazia (`p=`) | O seletor existe mas a chave foi revogada. |
| `[NOT FOUND]` | Nenhum seletor comum respondeu. **Não significa que o DKIM não existe** — informe o seletor do seu provedor manualmente. |

**Riscos mitigados quando OK:** alteração de mensagens em trânsito; repúdio de e-mails legítimos; falha de autenticação no alinhamento DMARC.

---

### 3. DMARC

**O que é:** política que diz aos servidores de destino **o que fazer** quando um e-mail falha no SPF ou DKIM (entregar, colocar em quarentena ou rejeitar). Também habilita relatórios sobre quem está enviando e-mails pelo seu domínio.

**Como o script verifica:** busca o registro TXT em `_dmarc.<dominio>` começando com `v=DMARC1`.

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` `p=reject` | E-mails fraudulentos são rejeitados. **Proteção máxima.** |
| `[WARNING]` `p=quarantine` | E-mails suspeitos vão para spam. Bom estágio intermediário. |
| `[WARNING]` `p=none` | Apenas monitora — **não bloqueia spoofing**. Use só na fase inicial. |
| `[FAIL]` sem registro | Sem DMARC, o SPF e o DKIM perdem boa parte da eficácia. |
| `[WARNING]` sem `rua=` | Você não recebe relatórios agregados. Recomenda-se configurar. |
| `[WARNING]` `pct=` < 100 | A política só se aplica a parte dos e-mails. |

**Riscos mitigados quando OK (`p=reject`):** entrega de e-mails fraudulentos; spoofing não bloqueado; falta de visibilidade sobre uso indevido do domínio.

---

### 4. MTA-STS

**O que é:** mecanismo que força os servidores de e-mail a usarem **TLS (criptografia)** ao entregar mensagens ao seu domínio, prevenindo ataques de interceptação (downgrade/man-in-the-middle).

**Como o script verifica** (duas etapas):

1. **DNS:** registro TXT em `_mta-sts.<dominio>` com `v=STSv1; id=...`
2. **HTTPS:** arquivo de política em `https://mta-sts.<dominio>/.well-known/mta-sts.txt`

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` `mode: enforce` | TLS obrigatório na entrega. **Configuração ideal.** |
| `[WARNING]` `mode: testing` | Apenas monitora, não bloqueia conexões inseguras. |
| `[WARNING]` `mode: none` | Política existe mas está desativada. |
| `[FAIL]` sem registro DNS | MTA-STS não configurado (é o caso da maioria dos domínios). |
| `[FAIL]` HTTP ≠ 200 ou erro SSL | O registro DNS existe, mas o arquivo de política está inacessível ou o certificado é inválido. |

**Riscos mitigados quando OK (`mode: enforce`):** interceptação de e-mails em trânsito (man-in-the-middle), downgrade de TLS para conexão sem criptografia e leitura do conteúdo das mensagens na rede.

---

### 5. MX (Mail Exchange)

**O que é:** registros DNS que indicam **quais servidores recebem e-mail** para o domínio, com prioridade numérica (menor = preferido).

**Como o script verifica:** consulta registros MX no domínio via DNS (sem API). Lista prioridade e hostname, verifica se cada host resolve para A/AAAA e alerta sobre falta de redundância.

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` MX encontrados e resolvendo | Servidores de entrada configurados e alcançáveis. |
| `[WARNING]` apenas 1 MX | Sem redundância — queda do servidor interrompe recebimento. |
| `[FAIL]` sem MX | Domínio não recebe e-mail (ou registro ausente). |
| `[FAIL]` host MX não resolve | Entrega de e-mail provavelmente falhará. |

**Riscos mitigados quando OK:** indisponibilidade silenciosa de e-mail por MX ausente ou mal configurado; falhas de entrega por hostname inválido; diagnóstico claro da infraestrutura de entrada.

---

### 6. DNSSEC (DNS Security Extensions)

**O que é:** extensão do DNS que **assina criptograficamente** os registros, permitindo detectar respostas falsificadas ou alteradas.

**Como o script verifica:** consulta registros DNSKEY no domínio e, em resolvers validadores (Google 8.8.8.8, Cloudflare 1.1.1.1), verifica o flag AD (Authenticated Data) na cadeia de confiança. **Apenas DNS — sem API.**

**Resultados possíveis:**

| Resultado | Significado |
|---|---|
| `[OK]` DNSKEY + AD confirmado | DNSSEC ativo e cadeia de confiança validada. |
| `[WARNING]` DNSKEY sem AD | Chaves publicadas, mas cadeia incompleta (verificar DS no registrador). |
| `[FAIL]` sem DNSKEY | DNSSEC não habilitado — registros DNS podem ser spoofados. |

**Riscos mitigados quando OK:** cache poisoning, spoofing de registros SPF/DKIM/DMARC via DNS falsificado, redirecionamento de MX para servidores maliciosos e envenenamento de respostas DNS.

---

## 🛡️ Riscos mitigados por categoria (quando tudo OK)

Quando cada verificação retorna **OK** na configuração ideal, estes são os principais riscos que ficam mitigados:

| Categoria | Status ideal | Riscos mitigados |
|-----------|--------------|------------------|
| **SPF** | `-all` (hard fail) | Spoofing de remetente; envio não autorizado em nome do domínio; spam/phishing usando sua marca |
| **DKIM** | Seletor ativo, chave 2048 bits | Alteração de conteúdo em trânsito; repúdio de mensagens legítimas; falha de alinhamento DMARC |
| **DMARC** | `p=reject` + `rua=` | Entrega de e-mails fraudulentos; spoofing não detectado; ausência de visibilidade sobre abusos do domínio |
| **MTA-STS** | `mode: enforce` | Interceptação MITM; downgrade TLS; leitura de e-mails em trânsito |
| **MX** | Múltiplos MX resolvendo | Perda total de e-mail por MX ausente; falha silenciosa por hostname inválido; ponto único de falha (com redundância) |
| **DNSSEC** | DNSKEY + cadeia validada | Envenenamento DNS; falsificação de SPF/DKIM/DMARC; hijack de MX para servidor atacante |

> **Nota:** OK em SPF/DKIM/DMARC não substitui MTA-STS (camada de transporte) nem DNSSEC (integridade do DNS). A proteção completa exige todas as camadas relevantes ao seu cenário.

### Mapeamento de pontuação (0–10)

| Check | 10/10 | 8–9 | 6–7 | 3–5 | 0–2 |
|-------|-------|-----|-----|-----|-----|
| **SPF** | `-all` | `~all` | — | `?all`, incompleto | ausente, `+all`, duplicado |
| **DKIM** | chave 2048+ bits | chave 1024 bits | — | não encontrado | chave revogada |
| **DMARC** | `p=reject` + `rua=` | `p=reject` sem `rua`, ou `quarantine` | — | `p=none` | ausente / malformado |
| **MTA-STS** | `mode: enforce` | — | `mode: testing` | — | ausente / inválido |
| **MX** | múltiplos MX | load balance | 1 MX funcional | — | ausente / host inválido |
| **DNSSEC** | DNSKEY + AD validado | DNSKEY parcial | — | — | desabilitado |

---

## 📊 Resumo e scorecard

Ao terminar, o script exibe um painel consolidado com notas **0–10** e um **SCORECARD** com barras visuais por verificação e por camada (Autenticação, Transporte, Infraestrutura, Integridade DNS):

```
============================================================
  SUMMARY — exemplo.com.br
============================================================
  SPF        OK                 10/10
  DKIM       OK                  8/10
  DMARC      OK                  9/10
  MTA-STS    FAIL                0/10
  MX         OK (can improve)     7/10
  DNSSEC     FAIL                0/10

============================================================
  SCORECARD
============================================================
  Authentication (SPF·DKIM·DMARC)  █████████░   9/10
  Transport (MTA-STS)              ░░░░░░░░░░   0/10
  Infrastructure (MX)              ███████░░░   7/10
  DNS Integrity (DNSSEC)           ░░░░░░░░░░   0/10

  Overall                          ██████░░░░   6/10
```

- 🟢 **Verde (OK):** configurado corretamente
- 🟡 **Amarelo (WEAK / can improve):** existe, mas a configuração pode ser endurecida
- 🔴 **Vermelho (FAIL / CRITICAL):** ausente ou perigosamente mal configurado

---

## ⚠️ Observações

- O script faz apenas **consultas públicas** (DNS e HTTPS para MTA-STS) — **não usa APIs de terceiros** e não envia e-mails.
- MX e DNSSEC são verificados exclusivamente via protocolo DNS (`dnspython`).
- Para o DKIM, se o seu provedor usa um seletor incomum, descubra-o no cabeçalho de um e-mail enviado pelo domínio (campo `DKIM-Signature`, tag `s=`) e informe ao script.
- Ferramentas online como MXToolbox podem ser usadas para comparar os resultados.

---

## 📁 Documentação adicional

| Arquivo | Descrição |
|---------|-----------|
| [docs/GITHUB.md](docs/GITHUB.md) | Guia para criar e publicar o repositório no GitHub |
| [docs/REPOSITORY.md](docs/REPOSITORY.md) | Descrição do repositório no GitHub (inglês) e topics |
