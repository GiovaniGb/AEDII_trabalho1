import os

TAMANHO_REGISTRO_PRODUTO = 71  # 10 + 20 + 10 + 30 + 1 (\n)
TAMANHO_REGISTRO_ACESSO = 43   # 10 + 12 + 10 + 10 + 1 (\n)
TAMANHO_CHAVE = 10
INTERVALO_BLOCO = 20


def desformatar_produto(registro_bytes: bytes) -> dict:
    """Converte os 71 bytes de um registro do produto em um dicionário legível."""
    texto = registro_bytes.decode('utf-8')
    return {
        "product_id": texto[0:10].strip(),
        "brand": texto[10:30].strip(),
        "price": float(texto[30:40].strip()),
        "category_code": texto[40:70].strip()
    }


def desformatar_acesso(registro_bytes: bytes) -> dict:
    """Converte os 43 bytes de um registro de acesso em um dicionário legível."""
    texto = registro_bytes.decode('utf-8')
    return {
        "event_id": texto[0:10].strip(),
        "event_type": texto[10:22].strip(),
        "product_id": texto[22:32].strip(),
        "user_id": texto[32:42].strip()
    }


def carregar_indice_parcial(arq_indice: str) -> list:
    """
    Carrega o arquivo .idx para a memória RAM.
    Retorna uma lista de tuplas: [(chave_str, byte_offset), ...]
    """
    indice = []
    if not os.path.exists(arq_indice):
        print(f"[!] Arquivo de índice '{arq_indice}' não existe.")
        return indice

    with open(arq_indice, "r", encoding="utf-8") as f:
        for linha in f:
            partes = linha.strip().split(":")
            if len(partes) == 2:
                chave, offset = partes[0], int(partes[1])
                indice.append((chave, offset))
    return indice


def mostrar_dados(arq_dados: str, tamanho_registro: int, parser_fn, inicio: int = 0, quantidade: int = 10):
    """
    Lê e exibe uma quantidade específica de registros do arquivo binário.
    """
    if not os.path.exists(arq_dados):
        print(f"[!] Arquivo '{arq_dados}' não encontrado.")
        return

    print(f"\n--- Exibindo registros de '{arq_dados}' (Início: {inicio}, Quantidade: {quantidade}) ---")
    
    with open(arq_dados, "rb") as f:
        # Posiciona o ponteiro do arquivo no registro inicial desejado
        f.seek(inicio * tamanho_registro)
        lidos = 0
        
        while lidos < quantidade:
            registro_bytes = f.read(tamanho_registro)
            if not registro_bytes or len(registro_bytes) < tamanho_registro:
                break  # Fim do arquivo
            
            chave = registro_bytes[:TAMANHO_CHAVE].decode('utf-8')
            if not chave.startswith('*'):  # Ignora registros marcados como removidos
                dados = parser_fn(registro_bytes)
                print(f"[{inicio + lidos:05d}] {dados}")
            lidos += 1


def pesquisa_binaria_direta(arq_dados: str, target_id: int, tamanho_registro: int, parser_fn) -> dict:
    """
    Realiza a pesquisa binária diretamente no arquivo de dados em memória secundária,
    calculando a posição dos registros e navegando com fseek().
    """
    if not os.path.exists(arq_dados):
        return None

    target_str = f"{int(target_id):010d}"
    tamanho_arquivo = os.path.getsize(arq_dados)
    total_registros = tamanho_arquivo // tamanho_registro

    low = 0
    high = total_registros - 1
    comparacoes = 0

    with open(arq_dados, "rb") as f:
        while low <= high:
            comparacoes += 1
            mid = (low + high) // 2
            
            # Posiciona diretamente no registro do meio
            f.seek(mid * tamanho_registro)
            registro_bytes = f.read(tamanho_registro)
            
            chave_mid = registro_bytes[:TAMANHO_CHAVE].decode('utf-8')

            if chave_mid == target_str:
                print(f"    [Busca Direta] Registro encontrado em {comparacoes} comparações (posição {mid}).")
                return parser_fn(registro_bytes)
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    print(f"    [Busca Direta] Registro {target_str} não encontrado após {comparacoes} comparações.")
    return None

def consultar_por_indice_parcial(arq_dados: str, arq_indice: str, target_id: int, 
                                tamanho_registro: int, parser_fn, intervalo_bloco: int) -> dict:
    """
    1. Carrega o índice parcial leve.
    2. Realiza pesquisa binária no índice para encontrar o byte offset do bloco.
    3. Posiciona com fseek() no arquivo de dados e pesquisa apenas no pequeno bloco.
    """
    indice = carregar_indice_parcial(arq_indice)
    if not indice:
        return None

    target_str = f"{int(target_id):010d}"
    
    # Pesquisa binária no índice parcial
    low = 0
    high = len(indice) - 1
    offset_bloco = 0
    comparacoes_idx = 0

    while low <= high:
        comparacoes_idx += 1
        mid = (low + high) // 2
        chave_mid = indice[mid][0]

        if chave_mid <= target_str:
            offset_bloco = indice[mid][1]
            low = mid + 1
        else:
            high = mid - 1

    # Leitura pontual do bloco no arquivo de dados via fseek()
    comparacoes_dat = 0
    with open(arq_dados, "rb") as f:
        f.seek(offset_bloco)
        
        # Lê sequencialmente apenas o bloco de registros (ex: até 20 registros)
        for _ in range(intervalo_bloco):
            registro_bytes = f.read(tamanho_registro)
            if not registro_bytes or len(registro_bytes) < tamanho_registro:
                break

            comparacoes_dat += 1
            chave_atual = registro_bytes[:TAMANHO_CHAVE].decode('utf-8')

            if chave_atual == target_str:
                print(f"    [Busca c/ Índice] Encontrado! Comparações no índice: {comparacoes_idx}, Comparações no .dat: {comparacoes_dat}")
                return parser_fn(registro_bytes)
            elif chave_atual > target_str:
                break  # Como o arquivo está ordenado, pode interromper se passar da chave

    print(f"    [Busca c/ Índice] Registro {target_str} não encontrado.")
    return None



if __name__ == "__main__":
    print("==================================================================")
    print("        MÓDULO DE CONSULTAS E EXIBIÇÃO DE DADOS")
    print("==================================================================")

    # 1. Exibir amostra dos dados gravados
    mostrar_dados("produtos.dat", TAMANHO_REGISTRO_PRODUTO, desformatar_produto, inicio=0, quantidade=5)
    mostrar_dados("acessos.dat", TAMANHO_REGISTRO_ACESSO, desformatar_acesso, inicio=0, quantidade=5)

    # Definir um ID de produto de teste (substitua por um ID válido gerado no seu .dat)
    id_produto_teste = 1001500

    print("\n------------------------------------------------------------------")
    print(f"TESTE DE CONSULTA 1: Produto ID = {id_produto_teste}")
    print("------------------------------------------------------------------")
    
    print("\n-> Executando Pesquisa Binária Direta no .DAT:")
    prod_direto = pesquisa_binaria_direta("produtos.dat", id_produto_teste, TAMANHO_REGISTRO_PRODUTO, desformatar_produto)
    print("   Resultado:", prod_direto)

    print("\n-> Executando Consulta via Índice Parcial + fseek():")
    prod_idx = consultar_por_indice_parcial(
        "produtos.dat", "produtos.idx", id_produto_teste, 
        TAMANHO_REGISTRO_PRODUTO, desformatar_produto, INTERVALO_BLOCO
    )
    print("   Resultado:", prod_idx)

    # Definir um ID de evento de acesso de teste
    id_acesso_teste = 50

    print("\n------------------------------------------------------------------")
    print(f"TESTE DE CONSULTA 2: Acesso ID = {id_acesso_teste}")
    print("------------------------------------------------------------------")
    
    print("\n-> Executando Consulta via Índice Parcial + fseek():")
    acesso_idx = consultar_por_indice_parcial(
        "acessos.dat", "acessos.idx", id_acesso_teste, 
        TAMANHO_REGISTRO_ACESSO, desformatar_acesso, INTERVALO_BLOCO
    )
    print("   Resultado:", acesso_idx)