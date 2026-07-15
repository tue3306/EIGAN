"""Runner do dns-enum: agrega várias consultas dig (registros + AXFR).

O ``dig`` faz uma consulta por invocação; enumerar vários tipos + tentar AXFR em
cada nameserver exige múltiplas chamadas. ``scan`` roda cada uma pelo executor
seguro (lista de args, nunca ``shell=True``, timeout obrigatório) e junta a saída
com marcadores de seção para o parser. Flags verificadas no ``dig`` real (§2):
``+noall +answer`` (só a seção de resposta), ``axfr @<ns> <domínio>``.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding
from eigan.perspective import extract_host

from .parser import nameservers_from_dig, parse

_SECTION = ";; EIGAN-SECTION "
_RECORD_TYPES = ("SOA", "NS", "MX", "TXT", "SRV")
_MAX_NS = 8  # teto: não tentar AXFR contra dezenas de NS (anti-abuso/tempo)


class DnsEnumRunner(BaseToolPlugin):
    binary = "dig"
    name = "dns-enum"
    default_timeout = 20  # por consulta; +time=5/+tries=1 limitam ainda mais

    def build_args(
        self,
        target: str,
        *,
        rtype: str = "NS",
        nameserver: str = "",
        axfr: bool = False,
        **_: object,
    ) -> list[str]:
        host = extract_host(target) or target
        common = ["+noall", "+answer", "+time=5", "+tries=1"]
        if axfr:
            return [*common, "axfr", f"@{nameserver}", host]
        return [*common, host, rtype]

    def scan(self, target: str, *, timeout: int | None = None, **options: object) -> list[Finding]:
        host = extract_host(target) or target
        sections: list[tuple[str, str]] = []
        nameservers: list[str] = []
        for rtype in _RECORD_TYPES:
            res = self._run(self.build_args(host, rtype=rtype), timeout=timeout)
            sections.append((f"RECORD:{rtype}", res.stdout))
            if rtype == "NS":
                nameservers = nameservers_from_dig(res.stdout)
        for ns in nameservers[:_MAX_NS]:
            res = self._run(self.build_args(host, nameserver=ns, axfr=True), timeout=timeout)
            sections.append((f"AXFR:{ns}", res.stdout))
        combined = "\n".join(f"{_SECTION}{label}\n{out}" for label, out in sections)
        return self.parse(ToolResult(0, combined, ""), host)

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
