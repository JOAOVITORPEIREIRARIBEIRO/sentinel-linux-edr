import hashlib
import json
import os
import shutil
import sys

DIRETORIO_ALVO = "arquivos_criticos"
ARQUIVO_BASELINE = "baseline.json"
PASTA_COFRE = ".cofre_seguro"

def calcular_sha256(caminho_arquivo):
    sha256 = hashlib.sha256()
    with open(caminho_arquivo, "rb") as f:
        for bloco in iter(lambda: f.read(4096), b""):
            sha256.update(bloco)
        return sha256.hexdigest()

def mapear_arquivos():
        estado_atual = {}
        for nome_arquivo in sorted(os.listdir(DIRETORIO_ALVO)):
            caminho = os.path.join(DIRETORIO_ALVO, nome_arquivo)
            if os.path.isfile(caminho):
                estado_atual[caminho] = calcular_sha256(caminho)
        return estado_atual;   

def criar_baseline():
    os.makedirs(PASTA_COFRE, exist_ok=True)
    hashes = mapear_arquivos()

    for caminho in hashes:
        nome_arquivo = os.path.basename(caminho)
        shutil.copy2(caminho, os.path.join(PASTA_COFRE, nome_arquivo))

    with open(ARQUIVO_BASELINE, "w") as f:
        json.dump(hashes, f, indent=4)
    print(f"[OK] Baseline e cofre seguro criados! {len(hashes)} arquivos protegidos.")

def verificar_integridade():
    if not os.path.exists(ARQUIVO_BASELINE):
        print("[ERRO] Baseline nao encontrada. Rode primeiro: python3 fim_monitor.py baseline")
        return

    with open(ARQUIVO_BASELINE, "r") as f:
        baseline = json.load(f)

    atual = mapear_arquivos()
    alertas = 0

    for caminho, hash_original in baseline.items():
        if caminho not in atual:
            print(f"[ALERTA CRITICO] Arquivo DELETADO: {caminho}")
            alertas += 1
        elif atual[caminho] != hash_original:
            print(f"[ALERTA CRITICO] Arquivo ADULTERADO: {caminho}")
            print(f"   -> Hash original: {hash_original}")
            print(f"   -> Hash atual:    {atual[caminho]}")
            alertas += 1

    for caminho in atual:
        if caminho not in baseline:
            print(f"[ALERTA] Novo arquivo nao autorizado detectado: {caminho}")
            alertas += 1

    if alertas == 0:
        print("[SEGURO] Integridade 100% verificada. Nenhuma alteracao detectada.")
    else:
        print(f"\n[RESUMO] {alertas} violacao(oes) de integridade detectada(s)!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 fim_monitor.py [baseline | verificar]")
    elif sys.argv[1] == "baseline":
        criar_baseline()
    elif sys.argv[1] == "verificar":
        verificar_integridade()
    else:
        print("Comando invalido. Use 'baseline' ou 'verificar'.")    


