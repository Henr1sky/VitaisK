# Regras de detecção

Consulte o catálogo com `vitaisk rules list` e uma definição com `vitaisk rules show ssh-fail-then-success`. Adicione arquivos `.yaml` ou `.yml` em `rules.d/` dentro do diretório de configuração. Cada arquivo contém uma lista. Um ID já existente substitui a regra anterior com o mesmo ID.

## Campos

| Campo | Comportamento |
| --- | --- |
| `id` | Identificador da regra. |
| `source`, `category` | Origem e categoria normalizadas. `category` aceita uma categoria ou uma lista. |
| `contains`, `regex` | Correspondência na mensagem sem distinção de maiúsculas. Em `contains`, basta um dos termos. |
| `equals`, `one_of` | Comparam os valores de campos, inclusive metadados `extra.campo`. |
| `number` | Aplica limites numéricos `gt`, `gte`, `lt` e `lte`. |
| `severity` | `DEBUG`, `INFO`, `WARN`, `ERROR` ou `CRITICAL`. O padrão é `WARN`. |
| `group_by` | Campos que separam os grupos usados para contagem ou correlação. |
| `threshold`, `window` | Quantidade mínima de ocorrências e janela em segundos. O padrão de quantidade é 1. |
| `distinct` | Campo de que se contam valores distintos. |
| `followed_by` | Condição para o evento posterior. Aceita os mesmos campos de correspondência. |
| `match_window` | Intervalo máximo entre as ocorrências do primeiro estágio, em segundos. |
| `suggested_actions` | Lista de ações sugeridas exibida no alerta. |

Uma regra precisa de ao menos um campo de correspondência. Quando vários são definidos, todos precisam corresponder. Regras com contagens superiores a 1 ou com `followed_by` exigem uma janela positiva.

## Exemplo

```yaml
- id: service-restart-example
  source: system
  contains: ["scheduled restart job"]
  group_by: [host]
  threshold: 3
  window: 60
  severity: WARN
```

Para testar uma regra temporal, envie uma sequência de eventos normalizados, um objeto JSON por linha, com horários e campos de agrupamento representativos:

```bash
vitaisk rules test - < eventos-sinteticos.jsonl
```

Para inspecionar uma correspondência pontual:

```bash
vitaisk rules test --source kernel 'EXT4-fs error on sda'
```

## Correlações entre detecções

Use `vitaisk rules correlations` para ver o estado de cada entrada e `vitaisk rules show ssh-success-after-brute-force` para inspecionar uma correlação.

O catálogo combina duas ou mais detecções dentro de uma janela. Chaves como host, IP, usuário ou unit identificam quais eventos podem ser combinados. As correlações nativas declaram os campos e a janela. Para as combinações que precisam de sensores adicionais, o motor junta as observações pelo mesmo host e escopo, com janela padrão de cinco minutos. Veja como fornecer esses registros na [integração de telemetria](telemetry.md). Eventos sem um campo de identidade exigido ficam fora daquela correlação.

No `watch`, o evento que completa a combinação recebe um alerta com o ID da correlação e os IDs dos sinais. As sessões JSONL e as exportações JSON/CSV preservam os dados em `anomalies`, incluindo `evidence` com detalhes de cada sinal. As regras podem reaproveitar um único evento explicitamente, como um panic que também indica OOM. Janelas e agrupamentos indicam associação observada.

O alerta composto de SSH identifica as detecções que ele substitui para triagem em `supersedes`. O painel prioriza o alerta composto e oculta sinais redundantes na mesma linha. A sessão preserva as detecções originais. As políticas podem suprimir redundâncias nas visualizações de alertas, ajustar a gravidade de apresentação, agrupar incidentes ou pedir revisão humana. Recomendações, sinais e decisões de triagem ficam na gravação. O VitaisK não executa remediação.


### Amostragem de rede e cores

As regras SYN contam somente os registros recebidos do coletor de pacotes. A amostragem é opcional e pode perder parte do tráfego. Os limites se referem ao volume observado. As regras distinguem níveis `WARN` e `CRITICAL` conforme os sinais e as janelas da regra.

No monitor, o nível mais alto entre o evento e seus alertas determina a cor do evento, do contador e da amostra do pulso daquele segundo. `DEBUG/INFO` usam verde, `WARN` usa amarelo e `ERROR/CRITICAL` usam vermelho. A visualização pode ocultar o evento por filtro. A gravação mantém os alertas processados independentemente da visualização.


Os detectores de alterações em sudoers, PAM, configuração SSH, chaves autorizadas e shadow exigem registros de syscall com sucesso e uma chave de auditoria explicitamente configurada pelo operador. As chaves esperadas são `vitaisk_sudoers_write`, `vitaisk_pam_write`, `vitaisk_sshd_write`, `vitaisk_authorized_keys_write` e `vitaisk_shadow_write`. Uma chave precisa corresponder à mudança que ela descreve. A presença de um caminho no log, sozinha, não comprova uma gravação.
