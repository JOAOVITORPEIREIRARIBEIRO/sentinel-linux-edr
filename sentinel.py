import json
import os
import re
import shutil
from datetime import datetime
from fim_monitor import mapear_arquivos, ARQUIVO_BASELINE, PASTA_COFRE

LOG_REDE = "auth_servidor.log"
FIREWALL_RULES = "firewall_bloqueados.rules"
RELATORIO_FORENSE = "relatorio_incidente.json"
LIMITE_TENTATIVAS = 3


def analisar_logs_e_bloquear():
    tentativas_por_ip = {}
    ips_bloqueados = []

    with open(LOG_REDE, "r") as f:
        for linha in f:
            if "Failed password" in linha:
                busca_ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", linha)
                if busca_ip:
                    ip = busca_ip.group(1)
                    tentativas_por_ip[ip] = tentativas_por_ip.get(ip, 0) + 1

    with open(FIREWALL_RULES, "w") as fw:
        fw.write("# Regras ativas geradas automaticamente pelo Sentinel EDR\n")
        for ip, total in tentativas_por_ip.items():
            if total >= LIMITE_TENTATIVAS:
                regra = f"iptables -A INPUT -s {ip} -j DROP"
                fw.write(regra + "\n")
                ips_bloqueados.append({"ip": ip, "tentativas": total, "acao": "BLOQUEADO_NO_FIREWALL"})
                print(f"[BLOQUEIO ATIVO] IP {ip} bloqueado ({total} tentativas de invasao).")

    return ips_bloqueados


def auditar_arquivos():
    with open(ARQUIVO_BASELINE, "r") as f:
        baseline = json.load(f)

    atual = mapear_arquivos()
    violacoes = []

    for caminho, hash_orig in baseline.items():
        nome_arquivo = os.path.basename(caminho)
        backup_cofre = os.path.join(PASTA_COFRE, nome_arquivo)

        if caminho not in atual:
            shutil.copy2(backup_cofre, caminho)
            print(f"[AUTO-CURA] Arquivo DELETADO restaurado do cofre: {caminho}")
            violacoes.append({"arquivo": caminho, "status": "DELETADO_E_RESTAURADO"})
        elif atual[caminho] != hash_orig:
            shutil.copy2(backup_cofre, caminho)
            print(f"[AUTO-CURA] Arquivo ADULTERADO revertido ao original: {caminho}")
            violacoes.append({"arquivo": caminho, "status": "ADULTERADO_E_RESTAURADO"})

    for caminho in atual:
        if caminho not in baseline:
            violacoes.append({"arquivo": caminho, "status": "ARQUIVO_NAO_AUTORIZADO"})

    return violacoes


def executar_sentinel():
    print("=== INICIANDO VARREDURA SENTINEL EDR ===")
    bloqueios = analisar_logs_e_bloquear()
    violacoes_fim = auditar_arquivos()

    relatorio = {
        "timestamp": datetime.now().isoformat(),
        "status_geral": "CRITICO" if (bloqueios or violacoes_fim) else "SEGURO",
        "ips_bloqueados": bloqueios,
        "violacoes_integridade": violacoes_fim
    }

    with open(RELATORIO_FORENSE, "w") as f:
        json.dump(relatorio, f, indent=4)

    print(f"[FORENSE] Relatorio salvo em '{RELATORIO_FORENSE}'.")
    print(f"[RESUMO] {len(bloqueios)} IP(s) bloqueado(s) | {len(violacoes_fim)} violacao(oes) de arquivo.")


if __name__ == "__main__":
    executar_sentinel()