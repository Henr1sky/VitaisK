# Integração de telemetria

O VitaisK usa os coletores locais quando consegue observar o sinal diretamente. Para DNS, HTTP, autenticação de outros serviços, fluxos, saúde de aplicações e métricas externas, uma integração pode gravar observações em um arquivo JSONL local.

```bash
# Acompanha novas linhas sem precisar reiniciar o monitor.
vitaisk watch --signal-file /caminho/telemetria.jsonl --view anomalies

# Reprocessa um arquivo existente para validar as detecções e correlações.
vitaisk rules test - < telemetria.jsonl

# Lista de onde vem cada detecção.
vitaisk rules coverage

# Lista quais sinais e formas de coleta cada correlação exige.
vitaisk rules correlations

# Lista as políticas de priorização dos alertas.
vitaisk rules priorities
```

A opção `--signal-file` pode ser repetida. Para persistir os caminhos, defina `signal_files` no YAML de configuração. O monitor segue o fim do arquivo no primeiro acesso. Depois de uma rotação, lê o arquivo novo do início. Linhas inválidas ou maiores que 64 KiB são rejeitadas. A tela de coletores indica o total de rejeições.

Use arquivos regulares em diretórios com permissões controladas. Somente produtores que você confia devem ter acesso de escrita. A interface recebe metadados e rótulos que o produtor fornece. Ela não verifica se o produtor classificou corretamente um alerta.

## Formato

Cada linha é um objeto JSON UTF-8. Os dois tipos aceitam os seguintes metadados:

| Campo | Conteúdo |
| --- | --- |
| `record_type` | `event` para uma observação bruta estruturada ou `signal` para uma detecção que já foi classificada. |
| `ts` | Timestamp Unix em segundos, com fração opcional. |
| `host` | Identificador do host observado. Use o mesmo nome em fontes que devem se cruzar. |
| `scope` | Identificador compartilhado da entidade ou do incidente, como serviço, fluxo ou sessão. Diferentes escopos ficam separados. |
| `producer` e `observation_id` | Identificação do produtor e da observação. Reutilize o ID ao retransmitir o mesmo registro. Sinais derivados de uma única observação devem usar o mesmo ID. |
| `message` | Resumo legível, com até 2.000 caracteres. |
| `src_ip`, `dst_ip`, `dst_port`, `protocol`, `user`, `pid`, `unit`, `device` | Campos opcionais usados nos filtros e nas correlações que exigem uma identidade específica. |
| `severity` | Opcional. Nível original do evento ou nível informado pelo produtor para um sinal classificado. |

Mantenha IDs consistentes durante a janela de correlação. Um `scope` também separa casos no mesmo host. Para regras nativas com identidade específica, consulte os campos em `vitaisk rules show ID`.

### Observação estruturada

Defina `kind` e um objeto `facts`. A origem é deduzida do tipo. Os fatos ausentes permanecem desconhecidos, inclusive valores booleanos.

```json
{"record_type":"event","kind":"service","ts":1760000000,"host":"server-1","scope":"checkout.service","producer":"probe-local","observation_id":"check-1","unit":"checkout.service","message":"Endpoint indisponível","facts":{"state":"active","health_reachable":false}}
{"record_type":"event","kind":"service","ts":1760000020,"host":"server-1","scope":"checkout.service","producer":"probe-local","observation_id":"check-2","unit":"checkout.service","message":"Sonda funcional falhou","facts":{"functional_probe_ok":false}}
```

| `kind` | Exemplos de fatos |
| --- | --- |
| `dns` | `operation` (`query` ou `response`), `qtype`, `rcode`, `query_length`, `payload_bytes`, `authorized`. |
| `http` | `method`, `status`, `body_bytes`, `uri_length`, `login_endpoint`, `host_header_present`. |
| `authentication` | `result` (`success` ou `failure`) e `anonymous`. Informe também `protocol` no registro, como `ftp`, `rdp` ou `openvpn`. |
| `flow` | `direction`, `duration_seconds`, `outbound_bytes`, `external_destination`, `new_destination`. |
| `service` | `state`, `health_reachable`, `functional_probe_ok`, `fd_usage_percent`, `tasks_usage_percent`, `needs_reload`. |
| `monitoring` | `exporter_reachable`, `systemd_metric_present`, `scrape_duration_ms`, `failed_units`, `alert_open`, `open_seconds`. |

Os nomes exatos usados em cada regra ficam em [regras estruturadas](../vitaisk/rules/structured.yaml). O VitaisK avalia os valores recebidos e aplica os limiares, as contagens e as janelas definidos ali.

### Sinal já classificado

Defina `rule_id` com um ID do catálogo e `source` com uma origem conhecida. A confiança opcional vai de 0 a 1. O padrão é 0,90. Sinais em janelas de manutenção também podem informar `valid_until` como timestamp Unix até 24 horas depois de `ts`.

```json
{"record_type":"signal","rule_id":"dependency-root-failed","source":"system","ts":1760000000,"host":"server-1","scope":"incident-31","producer":"dependency-monitor","observation_id":"check-31","message":"A unidade raiz falhou","confidence":0.95}
```

Esse formato permite que sensores de firewall, ferramentas de monitoramento ou outras integrações tragam evidências que o VitaisK não consegue medir sozinho. Ações propostas no catálogo aparecem como sugestões. As sessões e exportações guardam a origem e as evidências com o alerta.
