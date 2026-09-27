"""Prova de sanitização no fio: captura os bytes que o http.client entrega ao TLS.

A captura fica ABAIXO do jev-sanitizer (patch em http.client), então não depende do
dry_run nem do log do próprio pacote. Os canários são únicos por execução.
"""
import hashlib
import http.client
import json
import secrets
import sys

capturado = []
_orig_send = http.client.HTTPConnection.send


def espiao(self, data):
    capturado.append((self.host, bytes(data) if not isinstance(data, str) else data.encode()))
    return _orig_send(self, data)


http.client.HTTPConnection.send = espiao  # HTTPSConnection herda de HTTPConnection

from jev_sanitizer import JevClient  # noqa: E402  (importa depois do patch)

tag = secrets.token_hex(4)
CANARIOS = {
    "email": f"canario.{tag}@example.com",
    "cpf": "123.456.789-09",
    "ip": "10.99.88.77",
    "senha": f"senha=Canario{tag}",
    "id": f"id_cliente={int(tag, 16) % 10**7 + 10**6}",
}
state = ("Cliente " + CANARIOS["email"] + ", CPF " + CANARIOS["cpf"] + ", acessou de " + CANARIOS["ip"]
         + " com " + CANARIOS["senha"] + " e " + CANARIOS["id"] + ". Reclama que o boleto vence hoje e não chegou.")
questions = {"urgente": {"type": "noul", "instructions": "O chamado é urgente?",
                         "criteria": {"true": "Sensível a prazo", "false": "Sem urgência"}}}

r = JevClient().ask(state, questions, origin="prova:fio")
corpo = b"".join(d for h, d in capturado if d.startswith(b"{"))
cabecalho = b"".join(d for h, d in capturado if not d.startswith(b"{"))
hosts = sorted({h for h, _ in capturado})

vazou = {k: v for k, v in CANARIOS.items() if v.encode() in corpo}
chave_no_corpo = b"Bearer" in corpo
print(json.dumps({
    "1_conexao": {"status": r["status"], "modelo": r.get("model"), "uso": r.get("usage"), "hosts_contatados": hosts},
    "2_sanitizacao": {
        "bytes_no_fio": len(corpo),
        "canarios_enviados": len(CANARIOS),
        "canarios_que_vazaram": vazou or "nenhum",
        "mascaras_no_fio": sorted(set(p.decode() for p in __import__("re").findall(rb"<[A-Z_]+>", corpo))),
        "sha256_fio == sha256_log": hashlib.sha256(corpo).hexdigest()[:16] == r.get("sha256"),
        "chave_so_no_cabecalho": (not chave_no_corpo) and b"Authorization: Bearer" in cabecalho,
        "trecho_do_state_no_fio": json.loads(corpo)["state"][:160],
    },
}, ensure_ascii=False, indent=1))
sys.exit(0 if r["status"] == "ok" and not vazou and hosts == ["api.typesafe.ai"] else 1)
