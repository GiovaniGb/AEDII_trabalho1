import csv
import os
import shutil

# ==============================================================================
# CONFIGURAÇÕES E TAMANHOS DE REGISTROS (TAMANHO FIXO COM '\n')
# ==============================================================================
# Registros de Produtos: 10 (id) + 20 (brand) + 10 (price) + 30 (cat) + 1 (\n) = 71 bytes
TAMANHO_REGISTRO_PRODUTO = 71
# Registros de Acessos: 10 (id) + 12 (type) + 10 (prod_id) + 10 (user_id) + 1 (\n) = 43 bytes
TAMANHO_REGISTRO_ACESSO = 43

TAMANHO_CHAVE = 10
INTERVALO_BLOCO_INDICE = 20  # Grava 1 chave no índice parcial a cada 20 registros

ARQ_PROD_DAT = "produtos.dat"
ARQ_PROD_IDX = "produtos.idx"
ARQ_ACES_DAT = "acessos.dat"
ARQ_ACES_IDX = "acessos.idx"

# Estruturas em memória RAM para os índices parciais: list de tuplas (chave_str, offset_byte)
indice_produtos = []
indice_acessos = []


# ==============================================================================
# FORMATADORES E PARSERS DE REGISTROS
# ==============================================================================
def formatar_produto(p_id: int, brand: str, price: float, category: str) -> bytes:
    p_id_str = f"{int(p_id):010d}"
    brand_str = f"{brand[:20]:<20}"
    price_str = f"{float(price):010.2f}"
    cat_str = f"{category[:30]:<30}"
    return f"{p_id_str}{brand_str}{price_str}{cat_str}\n".encode('utf-8')


def desformatar_produto(registro_bytes: bytes) -> dict:
    texto = registro_bytes.decode('utf-8')
    return {
        "product_id": texto[0:10].strip(),
        "brand": texto[10:30].strip(),
        "price": float(texto[30:40].strip()),
        "category_code": texto[40:70].strip()
    }


def formatar_acesso(e_id: int, e_type: str, p_id: int, u_id: int) -> bytes:
    e_id_str = f"{int(e_id):010d}"
    e_type_str = f"{e_type[:12]:<12}"
    p_id_str = f"{int(p_id):010d}"
    u_id_str = f"{int(u_id):010d}"
    return f"{e_id_str}{e_type_str}{p_id_str}{u_id_str}\n".encode('utf-8')


def desformatar_acesso(registro_bytes: bytes) -> dict:
    texto = registro_bytes.decode('utf-8')
    return {
        "event_id": texto[0:10].strip(),
        "event_type": texto[10:22].strip(),
        "product_id": texto[22:32].strip(),
        "user_id": texto[32:42].strip()
    }


# ==============================================================================
# PERSISTÊNCIA E MANIPULAÇÃO DE ÍNDICES PARCIAIS
# ==============================================================================
def carregar_indice_parcial(arq_indice: str) -> list:
    """Carrega o arquivo de índice parcial .idx para a memória RAM se ele existir."""
    indice = []
    if os.path.exists(arq_indice):
        with open(arq_indice, "r", encoding="utf-8") as f:
            for linha in f:
                partes = linha.strip().split(":")
                if len(partes) == 2:
                    indice.append((partes[0], int(partes[1])))
    return indice


def salvar_indice_parcial(arq_indice: str, indice: list):
    """Salva a estrutura do índice parcial da RAM no arquivo .idx no disco."""
    with open(arq_indice, "w", encoding="utf-8") as f:
        for chave, offset in indice:
            f.write(f"{chave}:{offset}\n")


def reconstruir_indice_parcial(arq_dados: str, arq_indice: str, tamanho_registro: int) -> list:
    """Reconstrói o índice parcial varrendo o arquivo .dat sequencialmente."""
    novo_indice = []
    if not os.path.exists(arq_dados):
        salvar_indice_parcial(arq_indice, novo_indice)
        return novo_indice

    registros_validos = 0
    with open(arq_dados, "rb") as f_dados:
        while True:
            offset_atual = f_dados.tell()
            reg_bytes = f_dados.read(tamanho_registro)
            if not reg_bytes or len(reg_bytes) < tamanho_registro:
                break

            chave = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')
            # Ignora registros marcados como deletados logicamente ('*')
            if not chave.startswith('*'):
                if registros_validos % INTERVALO_BLOCO_INDICE == 0:
                    novo_indice.append((chave, offset_atual))
                registros_validos += 1

    salvar_indice_parcial(arq_indice, novo_indice)
    return novo_indice


# ==============================================================================
# OPERAÇÕES PRINCIPAIS DO SISTEMA
# ==============================================================================
def inserir_dados_iniciais(arquivos_csv: list = None, max_linhas_por_arquivo: int = 100000):
    """
    1) INSERIR DADOS INICIAIS:
    Lê os arquivos CSV originais, gera os arquivos binários ('produtos.dat' e 'acessos.dat') 
    e constrói os arquivos de índice parcial ('.idx').
    """
    global indice_produtos, indice_acessos

    if arquivos_csv is None:
        arquivos_csv = ["2019-Oct.csv", "2019-Nov.csv"]

    csvs_encontrados = [f for f in arquivos_csv if os.path.exists(f)]
    if not csvs_encontrados:
        print("\n[!] Erro: Nenhum arquivo CSV original (2019-Oct.csv / 2019-Nov.csv) foi localizado.")
        return False

    print("\n==================================================================")
    print("      INICIANDO CARGA INICIAL DE DADOS E GERAÇÃO DE ÍNDICES       ")
    print("==================================================================")

    produtos_dict = {}  # Mantém unicidade dos produtos
    event_id_counter = 1

    # 1. Leitura dos CSVs e escrita streaming do arquivo acessos.dat
    with open(ARQ_ACES_DAT, "wb") as f_acessos:
        for csv_file in csvs_encontrados:
            print(f"[->] Processando '{csv_file}'...")
            with open(csv_file, mode='r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)  # Pula o cabeçalho do CSV
                
                count = 0
                for row in reader:
                    if not row or len(row) < 8:
                        continue

                    try:
                        event_type = row[1].strip()
                        product_id = int(row[2].strip())
                        category_code = row[4].strip() if row[4].strip() else "sem_categoria"
                        brand = row[5].strip() if row[5].strip() else "sem_marca"
                        price = float(row[6].strip()) if row[6].strip() else 0.0
                        user_id = int(row[7].strip())
                    except (ValueError, IndexError):
                        continue

                    # Salva produto no dicionário
                    if product_id not in produtos_dict:
                        produtos_dict[product_id] = (brand, price, category_code)

                    # Grava o registro de acesso formatado no .dat
                    rec_acesso = formatar_acesso(event_id_counter, event_type, product_id, user_id)
                    f_acessos.write(rec_acesso)
                    event_id_counter += 1

                    count += 1
                    if max_linhas_por_arquivo and count >= max_linhas_por_arquivo:
                        print(f"    Limite de {max_linhas_por_arquivo:,} linhas atingido para '{csv_file}'.")
                        break

    # 2. Gravação ordenada do arquivo produtos.dat
    print(f"\n[->] Ordenando e gravando {len(produtos_dict):,} produtos em '{ARQ_PROD_DAT}'...")
    produtos_ordenados = sorted(produtos_dict.items(), key=lambda x: x[0])

    with open(ARQ_PROD_DAT, "wb") as f_produtos:
        for p_id, (brand, price, category_code) in produtos_ordenados:
            rec_produto = formatar_produto(p_id, brand, price, category_code)
            f_produtos.write(rec_produto)

    print(f"[+] '{ARQ_PROD_DAT}' gerado com sucesso!")
    print(f"[+] '{ARQ_ACES_DAT}' gerado com sucesso!")

    # 3. Construção dos arquivos de índice parcial .idx
    print("\n[->] Gerando arquivos de índices parciais (.idx)...")
    indice_produtos = reconstruir_indice_parcial(ARQ_PROD_DAT, ARQ_PROD_IDX, TAMANHO_REGISTRO_PRODUTO)
    indice_acessos = reconstruir_indice_parcial(ARQ_ACES_DAT, ARQ_ACES_IDX, TAMANHO_REGISTRO_ACESSO)

    print(f"[+] '{ARQ_PROD_IDX}' gerado com {len(indice_produtos):,} entradas.")
    print(f"[+] '{ARQ_ACES_IDX}' gerado com {len(indice_acessos):,} entradas.")
    print("\n[+] Carga inicial concluída com sucesso!")
    return True


def mostrar_dados(arq_dados: str, tamanho_registro: int, parser_fn, inicio: int, qtd: int):
    """Exibe registros do arquivo .dat sem carregar tudo na RAM (navega com seek)."""
    if not os.path.exists(arq_dados):
        print(f"\n[!] Erro: Arquivo '{arq_dados}' não existe no diretório.")
        return

    print(f"\n--- EXIBINDO REGISTROS DE '{arq_dados}' (Início: {inicio}, Qtd: {qtd}) ---")
    with open(arq_dados, "rb") as f:
        f.seek(inicio * tamanho_registro)
        lidos = 0
        while lidos < qtd:
            reg_bytes = f.read(tamanho_registro)
            if not reg_bytes or len(reg_bytes) < tamanho_registro:
                break
            
            chave = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')
            if not chave.startswith('*'):  # Oculta deletados logicamente
                dados = parser_fn(reg_bytes)
                print(f"[{inicio + lidos:06d}] {dados}")
            else:
                print(f"[{inicio + lidos:06d}] [REGISTRO REMOVIDO LOGICAMENTE]")
            lidos += 1


def pesquisa_binaria_direta(arq_dados: str, target_id: int, tamanho_registro: int, parser_fn):
    """Realiza pesquisa binária diretamente no arquivo físico usando fseek()."""
    if not os.path.exists(arq_dados):
        print(f"\n[!] Arquivo '{arq_dados}' não encontrado.")
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
            f.seek(mid * tamanho_registro)
            reg_bytes = f.read(tamanho_registro)
            
            chave_mid = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')

            if chave_mid == target_str:
                print(f"\n[+] Registro encontrado em {comparacoes} comparações (Posição {mid})!")
                return parser_fn(reg_bytes)
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    print(f"\n[-] Registro ID {target_str} não foi encontrado após {comparacoes} comparações.")
    return None


def consultar_por_indice(arq_dados: str, indice_ram: list, target_id: int, tamanho_registro: int, parser_fn):
    """Busca binária no índice em RAM -> Pega offset -> seek() no bloco do arquivo de dados."""
    if not indice_ram:
        print("\n[!] Erro: O índice parcial está vazio ou não foi carregado.")
        return None

    target_str = f"{int(target_id):010d}"
    
    # 1. Pesquisa Binária na tabela de Índice Parcial
    low = 0
    high = len(indice_ram) - 1
    offset_bloco = 0
    comp_idx = 0

    while low <= high:
        comp_idx += 1
        mid = (low + high) // 2
        chave_mid = indice_ram[mid][0]

        if chave_mid <= target_str:
            offset_bloco = indice_ram[mid][1]
            low = mid + 1
        else:
            high = mid - 1

    # 2. Pesquisa sequencial restrita apenas ao bloco no arquivo .dat
    comp_dat = 0
    with open(arq_dados, "rb") as f:
        f.seek(offset_bloco)
        for _ in range(INTERVALO_BLOCO_INDICE):
            reg_bytes = f.read(tamanho_registro)
            if not reg_bytes or len(reg_bytes) < tamanho_registro:
                break

            comp_dat += 1
            chave_atual = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')

            if chave_atual == target_str:
                print(f"\n[+] Encontrado! Comparações no índice: {comp_idx} | Comparações no .dat: {comp_dat}")
                return parser_fn(reg_bytes)
            elif chave_atual > target_str:
                break

    print(f"\n[-] Registro ID {target_str} não encontrado.")
    return None


def inserir_registro(tipo_base: str, novo_bytes: bytes, target_id: int):
    """Insere registro mantendo a ordenação por streaming e reconstrói o índice parcial."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == 'produto' else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == 'produto' else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == 'produto' else TAMANHO_REGISTRO_ACESSO

    target_str = f"{int(target_id):010d}"
    arq_temp = arq_dados + ".tmp"
    inserido = False

    if not os.path.exists(arq_dados):
        with open(arq_dados, "wb") as f:
            f.write(novo_bytes)
    else:
        with open(arq_dados, "rb") as f_in, open(arq_temp, "wb") as f_out:
            while True:
                reg_bytes = f_in.read(tamanho_registro)
                if not reg_bytes or len(reg_bytes) < tamanho_registro:
                    break

                chave_atual = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')
                if chave_atual == target_str:
                    print(f"\n[!] Erro: Registro com ID {target_str} já existe.")
                    f_out.close()
                    os.remove(arq_temp)
                    return False

                if not inserido and chave_atual > target_str:
                    f_out.write(novo_bytes)
                    inserido = True

                f_out.write(reg_bytes)

            if not inserido:
                f_out.write(novo_bytes)

        shutil.move(arq_temp, arq_dados)

    print(f"\n[+] Registro ID {target_str} inserido com sucesso!")

    # Reconstrução e atualização dinâmica do índice parcial
    if tipo_base == 'produto':
        indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
    else:
        indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
    
    print("    [->] Índice parcial reconstruído e atualizado no disco com sucesso.")
    return True


def remover_registro_logico(tipo_base: str, target_id: int):
    """Marca o registro com '*' via fseek e reconstrói o índice parcial."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == 'produto' else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == 'produto' else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == 'produto' else TAMANHO_REGISTRO_ACESSO

    if not os.path.exists(arq_dados):
        print(f"\n[!] Arquivo '{arq_dados}' não existe.")
        return False

    target_str = f"{int(target_id):010d}"
    tamanho_arquivo = os.path.getsize(arq_dados)
    total_registros = tamanho_arquivo // tamanho_registro

    low = 0
    high = total_registros - 1
    removido = False

    # 1. Localiza e marca o registro no arquivo .dat
    with open(arq_dados, "r+b") as f:
        while low <= high:
            mid = (low + high) // 2
            offset = mid * tamanho_registro
            f.seek(offset)
            reg_bytes = f.read(tamanho_registro)
            chave_mid = reg_bytes[:TAMANHO_CHAVE].decode('utf-8')

            if chave_mid == target_str:
                f.seek(offset)
                f.write(b'*')
                f.flush()
                removido = True
                print(f"\n[-] Registro ID {target_str} removido logicamente.")
                break
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    # 2. Reconstrói o índice APÓS a remoção
    if removido:
        if tipo_base == 'produto':
            indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
        else:
            indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
        
        print("    [->] Índice parcial reconstruído sem o registro excluído.")
        return True

    print(f"\n[-] Erro: Registro ID {target_str} não encontrado.")
    return False


# ==============================================================================
# MENU INTERATIVO NO TERMINAL
# ==============================================================================
def menu_principal():
    global indice_produtos, indice_acessos

    # Inicialização: carrega índices existentes no disco ao abrir o programa
    indice_produtos = carregar_indice_parcial(ARQ_PROD_IDX)
    indice_acessos = carregar_indice_parcial(ARQ_ACES_IDX)

    while True:
        print("\n==================================================================")
        print("     SISTEMA DE ORGANIZAÇÃO SEQUENCIAL-INDEXADO DE ARQUIVOS")
        print("==================================================================")
        print("1. Inserir dados iniciais (Gerar .dat e .idx dos CSVs)")
        print("2. Mostrar dados (Parcial ou Total)")
        print("3. Pesquisa Binária DIRETA no arquivo de dados (.dat)")
        print("4. Consulta por ÍNDICE PARCIAL (.idx + fseek)")
        print("5. Inserir novo registro (com reconstrução do índice)")
        print("6. Remover registro (com reconstrução do índice)")
        print("0. Sair do programa")
        print("------------------------------------------------------------------")
        
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "0":
            print("\n[+] Salvando índices e encerrando o programa... Até logo!")
            salvar_indice_parcial(ARQ_PROD_IDX, indice_produtos)
            salvar_indice_parcial(ARQ_ACES_IDX, indice_acessos)
            break

        elif opcao == "1":
            qtd_max = input("Informe o limite de linhas por CSV a carregar (Enter para 100.000): ").strip()
            limite = int(qtd_max) if qtd_max.isdigit() else 100000
            inserir_dados_iniciais(max_linhas_por_arquivo=limite)

        elif opcao in ["2", "3", "4", "5", "6"]:
            print("\nSelecione qual arquivo deseja manipular:")
            print("  1. Produtos (produtos.dat)")
            print("  2. Acessos  (acessos.dat)")
            sel_base = input("Escolha (1 ou 2): ").strip()
            
            tipo_base = 'produto' if sel_base == '1' else 'acesso' if sel_base == '2' else None
            if not tipo_base:
                print("[!] Opção de base inválida!")
                continue

            arq_dat = ARQ_PROD_DAT if tipo_base == 'produto' else ARQ_ACES_DAT
            arq_idx = ARQ_PROD_IDX if tipo_base == 'produto' else ARQ_ACES_IDX
            tam_rec = TAMANHO_REGISTRO_PRODUTO if tipo_base == 'produto' else TAMANHO_REGISTRO_ACESSO
            parser = desformatar_produto if tipo_base == 'produto' else desformatar_acesso
            ind_ram = indice_produtos if tipo_base == 'produto' else indice_acessos

            if opcao == "2":
                inicio = int(input("Informe o índice inicial (padrão 0): ") or "0")
                qtd = int(input("Informe a quantidade de registros a exibir (padrão 10): ") or "10")
                mostrar_dados(arq_dat, tam_rec, parser, inicio, qtd)

            elif opcao == "3":
                target = int(input(f"Digite o ID do {tipo_base} para pesquisa binária direta: "))
                res = pesquisa_binaria_direta(arq_dat, target, tam_rec, parser)
                if res:
                    print("    Dados:", res)

            elif opcao == "4":
                target = int(input(f"Digite o ID do {tipo_base} para consultar via Índice Parcial: "))
                res = consultar_por_indice(arq_dat, ind_ram, target, tam_rec, parser)
                if res:
                    print("    Dados:", res)

            elif opcao == "5":
                print(f"\n--- Inserindo novo registro em {arq_dat} ---")
                target_id = int(input(f"ID do {tipo_base}: "))
                if tipo_base == 'produto':
                    brand = input("Marca (brand): ")
                    price = float(input("Preço (price): "))
                    cat = input("Categoria: ")
                    novo_bytes = formatar_produto(target_id, brand, price, cat)
                else:
                    e_type = input("Tipo de evento (view, cart, purchase): ")
                    p_id = int(input("ID do produto relacionado: "))
                    u_id = int(input("ID do usuário: "))
                    novo_bytes = formatar_acesso(target_id, e_type, p_id, u_id)
                
                inserir_registro(tipo_base, novo_bytes, target_id)

            elif opcao == "6":
                target_id = int(input(f"Digite o ID do {tipo_base} a ser REMOVIDO: "))
                remover_registro_logico(tipo_base, target_id)

        else:
            print("\n[!] Opção inválida. Tente novamente.")


if __name__ == "__main__":
    menu_principal()