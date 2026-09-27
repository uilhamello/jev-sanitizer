# Prova ponta a ponta

Comprova, com uma chamada real, três coisas:

| O que | Como |
|---|---|
| **Conecta ao Jev** | chamada real; lista os hosts contatados (deve ser só `api.typesafe.ai`) |
| **Sai sanitizado** | captura os bytes em `http.client`, **abaixo** do pacote, e envia 5 canários únicos por execução (e-mail, CPF, IP, senha, id); nenhum pode aparecer no fio |
| **É genérico** | roda num container limpo, sem config nem arquivo de chave, instalando do GitHub, a partir de um diretório qualquer |

## Rodar

A partir da raiz do repositório, com a chave no ambiente (uma chamada, ~330 tokens):

```bash
docker run --rm -e TYPESAFE_API_KEY -e JEV_SANITIZER_LOG=off \
  -v "$PWD/examples/prova:/prova:ro" python:3.12-slim sh /prova/no_container.sh
```

Para testar o seu checkout local em vez do GitHub, monte o repositório e aponte `JEV_SANITIZER_SRC`:

```bash
docker run --rm -e TYPESAFE_API_KEY -e JEV_SANITIZER_LOG=off -e JEV_SANITIZER_SRC=/repo \
  -v "$PWD:/repo:ro" -v "$PWD/examples/prova:/prova:ro" python:3.12-slim sh /prova/no_container.sh
```

Sem Docker: `pip install .` e `python examples/prova/prova_fio.py`.

## Resultado esperado

- `1_conexao.status = ok` e `hosts_contatados = ["api.typesafe.ai"]`
- `2_sanitizacao.canarios_que_vazaram = "nenhum"`
- `sha256_fio == sha256_log = true` (o log do pacote descreve exatamente o que saiu)
- `chave_so_no_cabecalho = true`
- saída com código 0; qualquer vazamento ou host inesperado sai com código 1

Prova externa: a chamada aparece em **Usage** no [console da TypeSafe](https://console.typesafe.ai).

Limite: a captura é dentro do processo, antes do TLS. Para uma prova fora do processo, use um
proxy como o mitmproxy. Nomes de pessoas não são mascarados, por isso não há canário de nome.
