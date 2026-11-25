# Organização Sequencial-Indexada - Algoritmos e Estruturas de Dados II

Trabalho prático desenvolvido para a disciplina de Algoritmos e Estruturas de Dados II. O objetivo é gerir e consultar ficheiros binários de registos de tamanho fixo em disco através de uma estrutura sequencial-indexada, utilizando o dataset de comportamento em e-commerce.

Todas as operações de consulta, inserção e remoção são feitas diretamente em memória secundária através de navegação por offset (`fseek`), sem carregar a totalidade dos dados para a memória RAM.

Para teste, o conjunto de dados é reduzido, para até 100.000 linhas. Conjunto de acessos chega a quase 200.000 pois são dois arquivos. Já o de produtos chega a menos de 40.000, pois há muitos Id repetidos.

## Funcionalidades (Trabalho I)
- **Carga inicial:** Leitura dos ficheiros CSV (`2019-Oct.csv` e `2019-Nov.csv`), geração dos ficheiros binários (`produtos.dat` e `acessos.dat`) e construção dos respetivos índices parciais (`.idx`).
- **Exibição de dados:** Leitura e navegação parcial ou total dos registos em disco.
- **Pesquisa binária direta:** Busca binária executada diretamente sobre o ficheiro `.dat`.
- **Consulta por índice parcial:** Localização do bloco no ficheiro `.idx` via pesquisa binária, seguida de leitura sequencial restrita no ficheiro `.dat`.
- **Inserção de registos:** Adição de dados mantendo a ordenação por chave e atualização do índice parcial.
- **Remoção lógica:** Marcação de eliminação no registo do ficheiro de dados e reconstrução do índice.

---

## Novidades do Trabalho II — Índices em Memória (Árvore B+ e Tabela Hash) e Criptografia

Na segunda etapa do projeto, o sistema foi estendido para suportar **criptografia de tamanho fixo** sobre cópias dos ficheiros de dados e **indexação em memória RAM** para acelerar as consultas, mantendo os ficheiros originais do Trabalho I intactos.

### O que mudou:
- **Preservação dos Originais e Cópias Criptografadas:** Os ficheiros `produtos.dat` e `acessos.dat` são abertos apenas em modo de leitura na carga inicial (Opção 1), permanecendo 100% intactos. Todas as operações passam a ocorrer sobre `produtos_criptografado.dat` (71 bytes) e `acessos_criptografado.dat` (43 bytes), cifrados com uma cifra simétrica de tamanho fixo que preserva os delimitadores `\n` e `*` para manter a navegação direta via `fseek()`.
- **Árvore B+ em Memória (Produtos):** Índice primário em RAM sobre `product_id`, dimensionado com **ordem 128** (bloco/página de 4.096 bytes dividido por 32 bytes por entrada, comportando até 127 chaves por nodo) e folhas encadeadas sequencialmente que apontam para os *offsets* físicos em `produtos_criptografado.dat`.
- **Tabela Hash em Memória (Acessos):** Índice secundário em RAM sobre a coluna não-chave `product_id` (relacionamento 1:N), com capacidade prima de **50.021 buckets**, função de dispersão *djb2* e resolução de colisões por **Encadeamento Separado (*Separate Chaining*)**.
- **Índice Secundário Exaustivo em Disco:** Geração do ficheiro `acessos_criptografado_prod.idx` ordenado por `product_id` para permitir consultas em disco por produto e comparação direta com a Tabela Hash em memória.
- **Manutenção Sincronizada (Disco + RAM):**
  - Na **inserção**, o ficheiro criptografado e os índices `.idx` são reconstruídos e as estruturas em RAM são recriadas.
  - Na **remoção lógica**, além da marcação `*` no `.dat` e atualização dos `.idx`, a chave ou *offset* é removido pontualmente da Árvore B+ ou da Tabela Hash sem necessidade de reler todo o ficheiro.

---

## Estrutura do Projeto
- `consulta.py`: Script principal com o menu interativo, criptografia, manipulação dos ficheiros em disco e estruturas de índice em memória (Árvore B+ e Tabela Hash).
- `produtos.dat` / `acessos.dat`: Ficheiros binários originais do Trabalho I (mantidos intactos).
- `produtos_criptografado.dat` / `acessos_criptografado.dat`: Cópias criptografadas de tamanho fixo (71 e 43 bytes) onde todas as operações são realizadas.
- `produtos_criptografado.idx` / `acessos_criptografado.idx`: Ficheiros de índice parcial em disco (pares `chave:offset`).
- `acessos_criptografado_prod.idx`: Índice secundário exaustivo em disco ordenado por `product_id`.

## Como Executar
1. Colocar os ficheiros binários originais (`produtos.dat` e `acessos.dat`) na mesma pasta do projeto.
2. Executar o programa:
```bash
py consulta.py
