# Organização Sequencial-Indexada - Algoritmos e Estruturas de Dados II

Trabalho prático desenvolvido para a disciplina de Algoritmos e Estruturas de Dados II. O objetivo é gerir e consultar ficheiros binários de registos de tamanho fixo em disco através de uma estrutura **sequencial-indexada**, utilizando o dataset de comportamento em *e-commerce*.

Todas as operações de consulta, inserção e remoção são feitas diretamente em memória secundária através de navegação por *offset* (`fseek`), sem carregar a totalidade dos dados para a memória RAM.

---

## Funcionalidades

* **Carga inicial:** Leitura dos ficheiros CSV (`2019-Oct.csv` e `2019-Nov.csv`), geração dos ficheiros binários (`produtos.dat` e `acessos.dat`) e construção dos respetivos índices parciais (`.idx`).
* **Exibição de dados:** Leitura e navegação parcial ou total dos registos em disco.
* **Pesquisa binária direta:** Busca binária executada diretamente sobre o ficheiro `.dat`.
* **Consulta por índice parcial:** Localização do bloco no ficheiro `.idx` via pesquisa binária, seguida de leitura sequencial restrita no ficheiro `.dat`.
* **Inserção de registos:** Adição de dados mantendo a ordenação por chave e atualização do índice parcial.
* **Remoção lógica:** Marcação de eliminação no registo do ficheiro de dados e reconstrução do índice.

---

## Estrutura do Projeto

* `consulta.py`: Script principal com o menu interativo e a lógica de manipulação de ficheiros em disco.
* `produtos.dat` / `acessos.dat`: Ficheiros binários de dados com registos de tamanho fixo (71 e 43 bytes).
* `produtos.idx` / `acessos.idx`: Ficheiros de índice parcial guardando pares de chave e *offset*.

---

## Como Executar

1. Colocar os ficheiros CSV originais na mesma pasta do projeto.
2. Executar o programa:

```bash
py consulta.py
