"""Portuguese help for the Click interface."""
from copy import copy

import click

from .i18n import current_lang


_PT = {
    "VitaisK — multi-parameter vital signs monitor for Linux.": "VitaisK — monitor de sinais vitais do Linux.",
    "Live monitoring. Press Ctrl+C to stop.": "Monitore ao vivo. Pressione Ctrl+C para sair.",
    "Summarize a saved session.": "Resuma uma sessão gravada.",
    "Capture packets to a .pcap file (on demand).": "Capture pacotes em um arquivo .pcap sob demanda.",
    "Export a session to JSON or CSV.": "Exporte uma sessão em JSON ou CSV.",
    "Manage saved sessions.": "Gerencie as sessões gravadas.",
    "List saved sessions.": "Liste as sessões gravadas.",
    "Show session metadata.": "Exiba os dados da sessão.",
    "Delete old sessions.": "Remova sessões antigas.",
    "Delete a session.": "Remova uma sessão.",
    "Inspect detection rules.": "Consulte as regras de detecção.",
    "List available detection rules.": "Liste as regras de detecção disponíveis.",
    "Show a rule's definition.": "Exiba a definição de uma regra.",
    "Test a rule against a sample line.": "Teste a detecção com uma linha ou uma sequência pela entrada padrão.",
    "Check dependencies, privileges, and paths.": "Verifique dependências, permissões e caminhos.",
    "Print VitaisK version and environment.": "Exiba a versão e o ambiente do VitaisK.",
    "Source for an unstructured sample.": "Indique a fonte de uma amostra de texto simples.",
    "Print config and data directory paths.": "Exiba os caminhos da configuração e dos dados.",
    "Print effective configuration.": "Exiba a configuração em uso.",
    "Set a dotted config key, e.g. `vitaisk config set sensitivity high`.": "Altere uma opção da configuração com `vitaisk config set`.",
    "Restore configuration to defaults.": "Restaure a configuração padrão.",
    "BPF filter, e.g. 'host 1.2.3.4'.": "Use um filtro BPF como 'host 1.2.3.4'.",
    "e.g. 60, 30s, 2m.": "Informe a duração, como 60, 30s ou 2m.",
    "e.g. 100M.": "Informe o tamanho máximo, como 100M.",
    "Inspect and modify configuration.": "Consulte e altere a configuração.",
    "Manage configuration.": "Gerencie a configuração.",
    "UI mode (overrides config).": "Escolha o modo de visualização.",
    "Use a named filter profile from config.": "Use um perfil de filtros definido na configuração.",
    "Select which events to display.": "Escolha quais eventos exibir.",
    "Show only alerts flagged as anomalies.": "Exiba somente as anomalias.",
    "Minimum severity to display.": "Defina o nível mínimo exibido.",
    "Limit to these sources (repeatable).": "Limite a estas fontes. Pode ser repetida.",
    "Only show events matching this regex.": "Exiba eventos que correspondam à expressão regular.",
    "Only show events involving this IP.": "Exiba eventos que envolvam este IP.",
    "Regex of lines to ignore (repeatable).": "Ignore linhas que correspondam à expressão regular. Pode ser repetida.",
    "Write the session during monitoring (default from config).": "Grave a sessão durante o monitoramento.",
    "Session ID or 'latest'.": "ID da sessão ou 'latest' para a mais recente.",
    "Specify a configuration file.": "Indique um arquivo de configuração.",
    "Keep only N most recent.": "Mantenha somente as N sessões mais recentes.",
    "Prune until total size <= X.": "Remova sessões até atingir o limite de tamanho.",
    "Show this message and exit.": "Exiba esta ajuda e saia.",
    "Show the version and exit.": "Exiba a versão e saia.",
}


def _localized(value):
    return _PT.get(value, value) if current_lang() == "pt" else value


class LocalizedOption(click.Option):
    def get_help_record(self, ctx):
        option = copy(self)
        option.help = _localized(self.help)
        return click.Option.get_help_record(option, ctx)


class _LocalizedHelp:
    def format_help_text(self, ctx, formatter):
        command = copy(self)
        command.help = _localized(self.help)
        click.Command.format_help_text(command, ctx, formatter)

    def get_short_help_str(self, limit=45):
        command = copy(self)
        command.short_help = _localized(self.short_help)
        command.help = _localized(self.help)
        return click.Command.get_short_help_str(command, limit)

    def get_help_option(self, ctx):
        option = super().get_help_option(ctx)
        if option is not None:
            option = copy(option)
            option.help = _localized(option.help)
        return option


class LocalizedCommand(_LocalizedHelp, click.Command):
    pass


class LocalizedGroup(_LocalizedHelp, click.Group):
    command_class = LocalizedCommand
    group_class = type
