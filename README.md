# jev-sanitizer

Cliente **não oficial** do [Jev](https://docs.typesafe.ai) (TypeSafe AI) que **sanitiza por padrão**
tudo o que envia: PII e segredos são mascarados antes da requisição, e o envio é **bloqueado** se
sobrar algo arriscado. Uma biblioteca, três portas: **CLI**, **servidor MCP** e **import Python**.
Zero dependências.

> Sem afiliação com a TypeSafe AI. "Jev" é marca da TypeSafe.

## Instalação

```bash
pip install git+https://github.com/uilhamello/jev-sanitizer.git
```

Requer Python 3.11+.

## Configuração básica

1. Crie a chave no [console da TypeSafe](https://console.typesafe.ai) → **API Keys**.
2. Salve fora do repositório, com permissão 600 (o comando pede a chave sem exibi-la):

   ```bash
   read -rs "?Chave: " K; printf 'export TYPESAFE_API_KEY=%s\n' "$K" > ~/.jev_env; chmod 600 ~/.jev_env; unset K
   ```

   (No bash, use `read -rsp "Chave: " K`.)
3. Copie `jev-sanitizer.example.toml` para `~/.config/jev-sanitizer/config.toml`.
   Ou apenas exporte `TYPESAFE_API_KEY`.

| Chave | Padrão | Env |
|---|---|---|
| `provider` | `typesafe` (ou `vercel`, via AI Gateway) | `JEV_SANITIZER_PROVIDER` |
| `model` | `jev-latest` | `JEV_SANITIZER_MODEL` |
| `key_file` | — | `JEV_SANITIZER_KEY_FILE` |
| `sanitize` | **`true`** | `JEV_SANITIZER_SANITIZE` |
| `timeout` | `15` | `JEV_SANITIZER_TIMEOUT` |
| `log_path` | `~/.local/state/jev-sanitizer/requests.jsonl` (`off` desliga) | `JEV_SANITIZER_LOG` |
| `extra_masks` / `extra_blocks` | — | — |

## Uso

**CLI**

```bash
jev-sanitizer dry-run < examples/request.json   # mostra o que seria enviado; nada sai
jev-sanitizer ask < examples/request.json
jev-sanitizer models
echo "fulano@example.com 10.0.0.7" | jev-sanitizer sanitize   # offline
```

Código de saída: `0` ok · `1` pedido inválido · `2` bloqueado · `3` indisponível.

**MCP** (Claude Code ou qualquer cliente MCP)

```bash
claude mcp add --scope user jev -- jev-sanitizer-mcp
```

Ferramentas: `jev_ask`, `jev_dry_run`, `jev_models`.

**Python**

```python
from jev_sanitizer import JevClient

r = JevClient().ask(
    state="Boleto não chegou e vence hoje",
    questions={"urgent": {"type": "noul", "instructions": "É urgente?",
                          "criteria": {"true": "Sensível a prazo", "false": "Sem urgência"}}},
    origin="meu-script",
)
if r["status"] == "ok":
    print(r["answers"]["urgent"]["noul"])
```

Tipos de pergunta: `noul` (sim/não com probabilidade), `choice` (uma opção entre 2–20) e
`score` (nível ordenado, de 2 a 10).

## O que a sanitização faz

| Ação | Alvo |
|---|---|
| **Mascara** | e-mail, CPF, CNPJ, telefone BR, placa BR, IPv4/IPv6, UUID, JWT, `Bearer`, `senha=`/`token=`/`api_key=`…, query string de URL, hex longo, número de 6+ dígitos, `*_id=` |
| **Bloqueia** (nada é enviado) | chave AWS, chave de service account GCP, PEM/certificado, connection string (`mysql://`, `redis://`…), string de alta entropia, `@` residual, texto acima de `max_chars` |

Cobre o `state` **e** as instruções e critérios das perguntas.

**Limites conhecidos:**
- Não detecta **nomes de pessoas** nem endereços.
- Número de 6+ dígitos sem separador vira `<N>`: escreva métricas como `51.000.000` ou `51M`.
- Regex não substitui a sua política de dados. Mande só o necessário, já resumido.

`sanitize = false` desliga a máscara, com aviso no stderr. Use só com dado sintético.

## Resultado e falhas

| `status` | Significado |
|---|---|
| `ok` | `answers` com as respostas tipadas |
| `blocked` | o sanitizador achou algo que não pode mascarar; **nada foi enviado** |
| `unavailable` | rede, chave ou API falhou; **não é uma resposta** e não deve contar como concordância |

O log local guarda só origem, hash, tamanho, máscaras e resultado, **nunca o conteúdo**. O
arquivo é criado com permissão 600.

## Segurança

- Hosts fixos por provider: não há URL configurável, então dados e chave não vão para um host desconhecido.
- A chave vem de variável de ambiente ou de arquivo com permissão 600; nunca é logada nem devolvida.
- Retenção de dados: veja a [Privacy Policy](https://typesafe.ai/legal/privacy-policy) e o
  [DPA](https://typesafe.ai/legal/data-processing) da TypeSafe. Sem contrato de retenção zero
  (ZDR), trate tudo o que for enviado como armazenado.

## Desenvolvimento

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Licença MIT.
