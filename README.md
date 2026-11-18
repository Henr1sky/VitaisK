# VitaisK

Monitor local de sinais vitais do Linux. O painel acompanha o pulso dos eventos em tempo real, mostra CPU, RAM e disco e destaca alertas por gravidade.

**Status:** alfa. A cobertura varia com as fontes disponíveis no host. O catálogo está em expansão.

## Instalação

Em uma distribuição Linux com Python 3.10 ou superior, clone o repositório e entre na pasta do projeto:

```bash
git clone https://github.com/Henr1sky/VitaisK.git
cd VitaisK
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install .
.venv/bin/vitaisk doctor
.venv/bin/vitaisk --lang pt watch
```

O monitor roda com as permissões do usuário atual. As fontes disponíveis variam com a distribuição e o acesso a journald, syslog, auditoria e conexões. O painel mostra quais coletores estão ativos. A opção global `--lang` aceita `pt`, `en` e `auto`.

## Monitoramento

- **Importantes** é a visualização inicial. Mostra eventos de nível `WARN` ou superior e alertas.
- **Tudo** mostra todos os eventos emitidos pelos coletores ativos.
- **Anomalias** mostra apenas eventos associados a uma regra ou ao desvio estatístico.
- O pulso mostra o volume de eventos por segundo. Verde indica `DEBUG/INFO`, amarelo indica `WARN` e vermelho indica `ERROR/CRITICAL`. As caixas coloridas abaixo do traçado mostram os totais da sessão por nível. Cada evento conta uma vez na sua maior gravidade, considerando os alertas associados. O pulso e os totais incluem eventos ocultados pelos filtros.
- Use **←/→** ou **1/2/3** para trocar de visão, **↑/↓** ou **Page Up/Page Down** para navegar no histórico e **Enter** para abrir detalhes. Use **Espaço** para alternar entre o histórico e o painel ao vivo. A coleta continua em ambas as visualizações.
- **F** abre os filtros do painel. Na tela de filtros, use **↑/↓** para escolher um campo e siga as teclas indicadas no rodapé. **/** abre a busca por expressão regular. **C** mostra o estado dos coletores, **?** exibe ajuda e **Q** encerra o monitor.
- **I** alterna entre português e inglês durante o monitoramento. Para definir o idioma das próximas sessões, use `vitaisk config set lang pt` ou `vitaisk config set lang en`.
- Em um pipe ou com `--mode stream`, o VitaisK imprime os eventos em linhas.
- A CLI aceita `--level`, `--source`, `--grep`, `--ip` e `--ignore`. O nível considera a maior gravidade entre o evento e seus alertas. A fonte aceita a origem do evento ou uma origem participante da correlação. Texto e exclusões usam expressões regulares sobre a mensagem. O IP corresponde à origem ou ao destino registrados.

```bash
vitaisk watch --mode stream --view all --source auth
vitaisk watch --view anomalies --no-save
vitaisk config path
```

Adicione perfis ao arquivo de configuração e selecione um com `vitaisk watch --profile ssh`:

```yaml
profiles:
  ssh:
    view: all
    sources: [auth]
    grep: ssh
```

## Sessões e exportação

As sessões gravam os eventos antes dos filtros de visualização, com a linha original e os alertas associados. O histórico fica no diretório de dados do usuário, em JSONL compactado por padrão. Por padrão, a retenção é de até 20 arquivos finalizados e 500 MiB para o histórico. A configuração nova usa 50 MiB como alvo de rotação por arquivo. A retenção remove as sessões finalizadas mais antigas. O tamanho de uma rotação pode ultrapassar o limite pelo volume recebido entre gravações. Use `--no-save` para desativar a gravação de sessões.

```bash
vitaisk sessions list
vitaisk summary --session latest
vitaisk export --session latest --format json
vitaisk export --session latest --format csv --output sessao.csv
```

## Detecção e captura

```bash
vitaisk rules list
vitaisk rules show ssh-fail-then-success
vitaisk rules test --source kernel 'EXT4-fs error on sda'
vitaisk rules test - < eventos.jsonl
```

O catálogo inicial cobre detecções de serviço, kernel, autenticação e firewall. As regras podem correlacionar sequências por campos compartilhados e indicar ações sugeridas. A gravação de pacotes é separada e depende de `tcpdump` e acesso à interface escolhida.

```bash
vitaisk capture --interface lo --duration 10s --max-size 20M
```

As personalizações de regras ficam em `rules.d/` no diretório de configuração. Um arquivo YAML contém uma lista de regras. Um ID já existente substitui a regra com o mesmo ID. Eventos de erro também alimentam uma referência estatística local por host e origem. Configure `baseline_enabled: false` para desativá-la.


## Documentação

- [Arquitetura e fontes de dados](docs/architecture.md)
- [Referência de regras e correlações](docs/rules.md)
- [Como contribuir](CONTRIBUTING.md)
- [Licença MIT](LICENSE)
