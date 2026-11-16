# Sentinel Linux EDR

Um sistema de **Detecção e Resposta de Endpoint (EDR)** e **Automação de Resposta a Incidentes (Mini-SOAR)** desenvolvido em Python puro para ambientes Linux.

Este projeto nasceu com o objetivo de colocar em prática, sem depender de ferramentas prontas de mercado, como funcionam os bastidores da defesa cibernética: monitoramento de integridade via criptografia, análise comportamental de logs de rede, bloqueio ativo em firewall e recuperação automática de arquivos críticos (*Self-Healing*).

---

## O que o sistema faz na prática

O **Sentinel EDR** atua em quatro frentes integradas:

1. **Monitoramento de Integridade de Arquivos (FIM — `fim_monitor.py`)**
   * Calcula o hash criptográfico **SHA-256** de todos os arquivos dentro do diretório monitorado (`arquivos_criticos/`).
   * Gera uma linha de base confiável (`baseline.json`) e armazena uma cópia íntegra dos arquivos originais em um cofre isolado (`.cofre_seguro/`).
   * Identifica instantaneamente qualquer adulteração de conteúdo, exclusão indevida ou criação de scripts não autorizados.

2. **Detecção de Força Bruta e Bloqueio Ativo (`sentinel.py`)**
   * Analisa os logs de autenticação SSH (`auth_servidor.log`) utilizando expressões regulares para rastrear falhas de login por endereço IP.
   * Quando um IP ultrapassa o limite configurado de 3 tentativas falhas, o sistema gera automaticamente regras de descarte de pacotes para o firewall Linux (`iptables -A INPUT -s <IP> -j DROP`) em `firewall_bloqueados.rules`.

3. **Auto-Cura (*Self-Healing* / Auto-Remediation)**
   * Ao detectar que um arquivo crítico foi adulterado ou deletado durante um ataque, o motor não apenas emite o alerta: ele restaura automaticamente a versão original a partir do `.cofre_seguro/`, neutralizando a sabotagem sem intervenção manual.

4. **Relatório Forense Automatizado**
   * Ao final de cada varredura, consolida data/hora, severidade do incidente, IPs bloqueados e arquivos restaurados em um dossiê estruturado (`relatorio_incidente.json`) pronto para auditoria ou integração com ferramentas de SIEM.

---

## Estrutura do Projeto

```text
sentinel-linux-edr/
├── arquivos_criticos/         # Diretório de configurações sensíveis monitoradas
│   ├── servidor_web.conf
│   ├── ssh_config.conf
│   └── usuarios_sistema.conf
├── .cofre_seguro/             # Cópia de backup íntegra usada na auto-cura
├── fim_monitor.py             # Módulo de cálculo SHA-256, baseline e auditoria
├── sentinel.py                # Motor SOAR: logs, firewall, auto-cura e forense
├── baseline.json              # Assinaturas SHA-256 originais dos arquivos
├── auth_servidor.log          # Log simulado de tentativas de acesso SSH
├── firewall_bloqueados.rules  # Regras iptables geradas automaticamente
└── relatorio_incidente.json   # Saída forense consolidada da última varredura

### Último passo: Salvar e enviar tudo para o seu GitHub

Depois de colar o texto no `README.md` e apertar **`Ctrl + S`**, rode estes 3 comandos no terminal para publicar o projeto completo no seu repositório:

```bash
git add .
git commit -m "feat: implementa Sentinel EDR com FIM SHA-256, bloqueio de rede e auto-cura"
git push