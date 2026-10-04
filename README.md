# jev-sanitizer

[![test](https://github.com/uilhamello/jev-sanitizer/actions/workflows/test.yml/badge.svg)](https://github.com/uilhamello/jev-sanitizer/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Dependências](https://img.shields.io/badge/depend%C3%AAncias-0-brightgreen)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-green)](LICENSE)

**Cliente do [Jev](https://docs.typesafe.ai) que sanitiza tudo antes de enviar.** PII e segredos
são mascarados em cada requisição, e o envio é **bloqueado** quando sobra algo que não dá para
mascarar com segurança. Uma biblioteca, três formas de uso: **CLI**, **servidor MCP** e
**import Python**. Sem dependências além da biblioteca padrão.

A sanitização vive em pacotes próprios, que servem sem o Jev para mascarar qualquer texto:
[**text-sanitizer-core**](https://github.com/uilhamello/text-sanitizer-core) (motor e regras
universais) e as regiões, como o [**text-sanitizer-br**](https://github.com/uilhamello/text-sanitizer-br)
(padrão). Para outra região, instale o pacote dela e acrescente o nome em `sanitizers`.

> Projeto independente, sem afiliação com a TypeSafe AI. "Jev" é marca da TypeSafe.

- [Por que usar](#por-que-usar)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Agentes de IA e clientes MCP](#agentes-de-ia-e-clientes-mcp)
- [Sanitização](#sanitização)
- [Segurança](#segurança)
- [Desenvolvimento](#desenvolvimento)

## Por que usar

O Jev devolve decisões tipadas (sim/não, uma opção, um nível) com probabilidade, rápido e
barato: serve para triagem, roteamento e classificação. O texto que você manda para ele,
porém, costuma vir de log, chamado ou banco, e carrega e-mail, CPF, IP, token. O jev-sanitizer
fica entre o seu código e a API:

| Sem o jev-sanitizer | Com o jev-sanitizer |
|---|---|
| o texto vai como está | máscara aplicada em `state`, instruções e critérios |
| segredo que escapou vai junto | envio **bloqueado**, nada sai |
| falha de rede vira exceção no seu fluxo | `status: unavailable`, explícito |
| sem rastro do que foi enviado | log local com hash, tamanho e máscaras, **sem conteúdo** |

## Instalação

Requer Python 3.11 ou superior.

**Com [pipx](https://pipx.pypa.io) (recomendado).** Já deixa `jev-sanitizer` e
`jev-sanitizer-mcp` no PATH:

```bash
pipx install git+https://github.com/uilhamello/jev-sanitizer.git
```

**Sem pipx.** Use um venv próprio e ligue os comandos em `~/.local/bin`. O `pip install` direto no
Python do sistema costuma ser bloqueado (PEP 668, padrão no Ubuntu 24.04+ e no Debian 12+):

```bash
python3 -m venv ~/.local/share/jev-sanitizer/venv && ~/.local/share/jev-sanitizer/venv/bin/pip install git+https://github.com/uilhamello/jev-sanitizer.git && mkdir -p ~/.local/bin && ln -sf ~/.local/share/jev-sanitizer/venv/bin/jev-sanitizer ~/.local/share/jev-sanitizer/venv/bin/jev-sanitizer-mcp ~/.local/bin/
```

Confira com `jev-sanitizer --version`. Se aparecer "command not found", `~/.local/bin` não está
no seu PATH.

### Instalação por um agente de IA

Cole o texto abaixo no seu agente de código. Funciona em qualquer agente que rode comandos de
terminal (Claude Code, opencode, Gemini CLI, Codex, Cursor e outros):

```text
Instale e configure o jev-sanitizer (https://github.com/uilhamello/jev-sanitizer) para mim:

1. Clone com `git clone --depth 1 https://github.com/uilhamello/jev-sanitizer.git
   ~/tools/jev-sanitizer` (ou atualize com git pull, se já existir) e leia o README inteiro
   antes de rodar qualquer coisa.
2. Confira que há Python 3.11+. Instale seguindo a seção "Instalação" do README (pipx ou,
   sem pipx, o venv com os links em ~/.local/bin). No fim, `jev-sanitizer --version` precisa
   funcionar.
3. Rode os testes num venv: cd ~/tools/jev-sanitizer && pip install -e . && python3 -m unittest discover -s tests
4. Chave da API: NUNCA me peça a chave no chat, nunca a leia e nunca a exiba. Se ~/.jev_env não
   existir, me passe o comando da seção "Configuração" para eu rodar no MEU terminal (ou abra um
   terminal interativo, se você puder) e espere eu avisar. Depois confira só a permissão (600).
5. Crie ~/.config/jev-sanitizer/config.toml a partir de jev-sanitizer.example.toml, com
   key_file = "~/.jev_env" e sanitize = true.
6. Registre o servidor MCP no cliente que você é, seguindo a tabela "Agentes de IA e clientes
   MCP" do README. Se o seu cliente não estiver na tabela, use a configuração genérica.
   Não altere outros servidores MCP já configurados.
7. Valide sem gastar: jev-sanitizer dry-run < ~/tools/jev-sanitizer/examples/request.json
   (o e-mail tem de aparecer como <EMAIL>). Depois, uma chamada real: jev-sanitizer models.
8. Me mostre um resumo: versão, testes, onde o MCP foi registrado e o resultado das validações.
   Diga se preciso reiniciar o cliente para as ferramentas aparecerem.
```

## Configuração

1. Crie a chave no [console da TypeSafe](https://console.typesafe.ai), em **API Keys**.
2. Salve a chave fora de qualquer repositório, com permissão 600. O comando pede a chave sem
   exibi-la e não a grava no histórico do shell:

   ```bash
   read -rs "?Chave: " K; printf 'export TYPESAFE_API_KEY=%s\n' "$K" > ~/.jev_env; chmod 600 ~/.jev_env; unset K
   ```

   Esse é o formato do zsh. No bash, troque o começo por `read -rsp "Chave: " K`.
3. Copie [`jev-sanitizer.example.toml`](jev-sanitizer.example.toml) para
   `~/.config/jev-sanitizer/config.toml`. Se preferir, apenas exporte `TYPESAFE_API_KEY`.

A configuração vem, nesta ordem de prioridade: argumentos do código, variáveis de ambiente,
arquivo de configuração e padrões.

| Chave | Padrão | Variável de ambiente |
|---|---|---|
| `provider` | `typesafe` (ou `vercel`, via AI Gateway) | `JEV_SANITIZER_PROVIDER` |
| `model` | `jev-latest` | `JEV_SANITIZER_MODEL` |
| `key_file` | nenhum | `JEV_SANITIZER_KEY_FILE` |
| `sanitize` | **`true`** | `JEV_SANITIZER_SANITIZE` |
| `sanitizers` | `["br"]`. Regiões aplicadas pelo [core](https://github.com/uilhamello/text-sanitizer-core), numa passada; região não instalada **bloqueia tudo** | `JEV_SANITIZER_SANITIZERS` (`br,eu`) |
| `ner` | `false`. `true` mascara nomes de pessoas; exige o extra `[ner]` e **bloqueia tudo** se o modelo faltar | `JEV_SANITIZER_NER` |
| `timeout` | `15` segundos | `JEV_SANITIZER_TIMEOUT` |
| `max_chars` | `20000` | não há |
| `log_path` | `~/.local/state/jev-sanitizer/requests.jsonl` (`off` desliga) | `JEV_SANITIZER_LOG` |
| `extra_masks` e `extra_blocks` | nenhum | não há |

O arquivo é lido de `$JEV_SANITIZER_CONFIG` ou de `~/.config/jev-sanitizer/config.toml`.
**Nunca do diretório atual**, para que um repositório clonado não consiga desligar a sanitização.

## Uso

Todo pedido tem um `state` (o texto a julgar, já resumido) e de 1 a 20 perguntas:

| Tipo | Responde | `criteria` |
|---|---|---|
| `noul` | sim/não, com probabilidade | `{"true": "...", "false": "..."}` |
| `choice` | uma opção entre 2 e 20 | `{"opcao_snake_case": "descrição", ...}` |
| `score` | um nível ordenado, de 2 a 10 | `["baixo", "médio", "alto"]` |

Veja um pedido completo em [`examples/request.json`](examples/request.json).

### CLI

```bash
jev-sanitizer dry-run < examples/request.json   # mostra o que seria enviado; nada sai
jev-sanitizer ask < examples/request.json       # envia
jev-sanitizer models                            # modelos disponíveis na conta
echo "fulano@example.com 10.0.0.7" | jev-sanitizer sanitize   # só sanitiza, offline
```

| Código de saída | Significado |
|---|---|
| `0` | ok |
| `1` | pedido ou configuração inválidos |
| `2` | bloqueado pelo sanitizador |
| `3` | indisponível (rede, chave ou API) |

### Python

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

### Resultado

| `status` | Significado |
|---|---|
| `ok` | `answers` traz as respostas tipadas; `usage` traz os tokens |
| `blocked` | o sanitizador encontrou algo que não pode mascarar; **nada foi enviado** |
| `unavailable` | rede, chave ou API falhou; **não é uma resposta** e não deve contar como concordância |

## Agentes de IA e clientes MCP

O servidor `jev-sanitizer-mcp` segue o protocolo MCP por stdio e expõe três ferramentas:
`jev_ask`, `jev_dry_run` e `jev_models`. Com ele, qualquer agente pode consultar o Jev pedindo em
linguagem natural, por exemplo: *"use o jev para classificar a urgência deste chamado"*.

| Cliente | Como registrar | Verificado |
|---|---|---|
| Claude Code | `claude mcp add --scope user jev -- jev-sanitizer-mcp` | ✅ chamada real |
| opencode | em `opencode.json`: `{"mcp": {"jev": {"type": "local", "command": ["jev-sanitizer-mcp"]}}}` | ✅ chamada real e prompt de instalação ponta a ponta, com modelo GPT |
| Gemini CLI | em `~/.gemini/settings.json`: `{"mcpServers": {"jev": {"command": "jev-sanitizer-mcp"}}}` | ⚪ não testado |
| Codex CLI | em `~/.codex/config.toml`: `[mcp_servers.jev]` e `command = "jev-sanitizer-mcp"` | ⚪ não testado |
| Claude Desktop, Cursor e outros | configuração genérica: `{"mcpServers": {"jev": {"command": "jev-sanitizer-mcp"}}}` | ⚪ não testado |

Aplicativos gráficos nem sempre herdam o PATH do terminal. Se o servidor não subir, use o
caminho absoluto, que é a saída de `command -v jev-sanitizer-mcp`.

A chave nunca passa pelo agente: o servidor a lê do ambiente ou do `key_file`, e ela não aparece
nas respostas das ferramentas.

## Sanitização

Vale para o `state`, para as instruções e para os critérios das perguntas. As regras são as do
[text-sanitizer-br](https://github.com/uilhamello/text-sanitizer-br).

| Ação | Alvo |
|---|---|
| **Mascara** | nome de pessoa (só com `ner = true`), endereço (logradouro + número), e-mail, CPF, RG, CNPJ, CEP, cartão de pagamento (13 a 19 dígitos, com espaço ou hífen, validado por Luhn), token com prefixo conhecido (Slack, GitHub, Anthropic/OpenAI, Stripe, Google API), telefone BR, placa BR, IPv4/IPv6, UUID, JWT, `Bearer`, credencial em URL (`user:senha@host`), `senha=`/`token=`/`api_key=` (também em JSON e em texto corrido), query string de URL, hex longo, número de 6+ dígitos, `*_id=` |
| **Bloqueia** (nada é enviado) | chave AWS, chave de service account GCP, PEM ou certificado, connection string (`mysql://`, `redis://`...), string de alta entropia, `@` residual, texto acima de `max_chars` (checado antes das regex), PII em identificadores (modelo, nome de pergunta, chave de opção) |

Dá para acrescentar regras próprias com `extra_masks` e `extra_blocks`. As regras padrão não podem
ser removidas.

**Limites conhecidos:**
- Sem `ner = true`, **não detecta nomes de pessoas**. Com ele, nome em minúsculas ou fora de frase
  pode escapar: o modelo depende de contexto.
- Endereço só é mascarado com logradouro **e** número ("Rua X, 150"). Cidade e bairro soltos passam.
- Número de 6+ dígitos sem separador vira `<N>`. Escreva métricas como `51.000.000` ou `51M`.
- Regex não substitui uma política de dados. Mande só o necessário, já resumido.

`sanitize = false` desliga a máscara e emite um aviso no stderr. Use só com dados sintéticos.

## Segurança

- **Hosts fixos por provider.** Não existe URL configurável, então dados e chave não vão para um
  host desconhecido. Redirecionamento HTTP não é seguido: um `3xx` vira `unavailable`, e a chave
  nunca é reenviada para outro destino.
- **A chave** vem do ambiente ou de um arquivo com permissão 600, que é recusado se estiver mais
  aberto. Ela nunca é logada nem devolvida.
- **O log local** guarda origem, hash, tamanho, máscaras e resultado, nunca o conteúdo. O arquivo é
  criado com permissão 600, e uma falha de escrita não derruba a requisição.
- **Retenção de dados:** leia a [Privacy Policy](https://typesafe.ai/legal/privacy-policy) e o
  [DPA](https://typesafe.ai/legal/data-processing) da TypeSafe. Sem contrato de retenção zero
  (ZDR), trate tudo o que for enviado como armazenado.

Encontrou uma forma de vazar dados pelo sanitizador? Abra uma
[issue](https://github.com/uilhamello/jev-sanitizer/issues) sem incluir dados reais.

## Desenvolvimento

```bash
git clone https://github.com/uilhamello/jev-sanitizer.git && cd jev-sanitizer
pip install -e . && python3 -m unittest discover -s tests -v
```

O `pip install -e .` traz o [text-sanitizer-br](https://github.com/uilhamello/text-sanitizer-br) da tag
fixada. Os testes das máscaras vivem lá.

O CI roda os testes em Python 3.11, 3.12 e 3.13 a cada push. A prova ponta a ponta, com chamada
real e canários capturados no fio, está em [examples/prova](examples/prova/README.md).

## Licença

[MIT](LICENSE).
