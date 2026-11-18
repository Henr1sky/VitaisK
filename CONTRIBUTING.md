# Como contribuir

Use Linux com Python 3.10 ou superior. Depois de clonar o repositório, configure o ambiente e execute os testes:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

Para mudanças em coletores ou detecção, inclua uma amostra sintética que reproduza o caso e registre quais distribuições, versões de Python e fontes foram verificadas. Use exemplos anonimizados em issues e pull requests. Os testes em `tests/` rodam sem `sudo`. Os scripts de diagnóstico na raiz dependem do ambiente local e, em alguns modos, de permissões de captura.

Ao abrir um pull request, descreva o comportamento alterado, como foi verificado e qualquer alteração de compatibilidade ou configuração. Consulte a [arquitetura](docs/architecture.md) e a [referência de regras](docs/rules.md).
