#!/bin/sh
# Roda dentro de um python:3.11+ limpo. Só entram este diretório (somente leitura) e a chave em env.
# Instala o pacote de JEV_SANITIZER_SRC (padrão: o zip de main no GitHub).
set -e
REPO=https://github.com/uilhamello/jev-sanitizer
SRC=${JEV_SANITIZER_SRC:-$REPO/archive/refs/heads/main.zip}
echo "== ambiente: $(python --version), HOME=$HOME, config: $(ls ~/.config/jev-sanitizer 2>/dev/null || echo nenhuma), ~/.jev_env: $(test -e ~/.jev_env && echo existe || echo ausente)"
echo "== instalar de $SRC"
# Diretório montado como somente leitura: copia, porque o build do pip grava na árvore.
if [ -d "$SRC" ]; then cp -r "$SRC" /tmp/jev-src && SRC=/tmp/jev-src; fi
pip install -q --root-user-action=ignore --disable-pip-version-check "$SRC"
mkdir -p /projeto-qualquer && cd /projeto-qualquer
echo "== CLI em diretório alheio ($(pwd))"
jev-sanitizer --version
jev-sanitizer models | tr -d '\n '; echo
echo "== sanitize offline"
echo "fulano@example.com 10.0.0.7 senha=abc" | jev-sanitizer sanitize 2>/dev/null; echo
echo "== bloqueio (exit esperado 2)"
printf '%s' '{"state":"dsn redis://h","questions":{"x":{"type":"noul","instructions":"y","criteria":{"true":"a","false":"b"}}}}' | jev-sanitizer ask >/dev/null || echo "exit=$?"
echo "== MCP"
printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jev-sanitizer-mcp | python -c "import sys,json; [print(json.loads(l)['result'].get('serverInfo') or [t['name'] for t in json.loads(l)['result']['tools']]) for l in sys.stdin]"
echo "== prova no fio (canários)"
python /prova/prova_fio.py
