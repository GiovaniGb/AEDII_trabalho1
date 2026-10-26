import csv
import os

# Estrutura do Arquivo de Produtos (Total: 71 bytes por registro)
# - product_id:    10 bytes (Chave primária única)
# - brand:         20 bytes (Texto preenchido com espaços à direita)
# - price:         10 bytes (Float formatado com zeros: 0000129.99)
# - category_code: 30 bytes (Texto preenchido com espaços à direita)
# - quebra_linha:   1 byte  ('\n')

# Estrutura do Arquivo de Acessos (Total: 43 bytes por registro)
# - event_id:      10 bytes (Chave primária única, gerada sequencialmente)
# - event_type:    12 bytes (view, cart, purchase, etc.)
# - product_id:    10 bytes (Chave estrangeira)
# - user_id:       10 bytes (ID do usuário)
# - quebra_linha:   1 byte  ('\n')


def formatar_produto(product_id: int, brand: str, price: float, category_code: str) -> bytes:
    """Formata um registro de produto para tamanho fixo de 71 bytes."""
    p_id_str = f"{int(product_id):010d}"
    brand_str = f"{brand[:20]:<20}"
    price_str = f"{float(price):010.2f}"
    cat_str = f"{category_code[:30]:<30}"
    
    registro_str = f"{p_id_str}{brand_str}{price_str}{cat_str}\n"
    return registro_str.encode('utf-8')


def formatar_acesso(event_id: int, event_type: str, product_id: int, user_id: int) -> bytes:
    """Formata um registro de acesso/evento para tamanho fixo de 43 bytes."""
    e_id_str = f"{int(event_id):010d}"
    e_type_str = f"{event_type[:12]:<12}"
    p_id_str = f"{int(product_id):010d}"
    u_id_str = f"{int(user_id):010d}"
    
    registro_str = f"{e_id_str}{e_type_str}{p_id_str}{u_id_str}\n"
    return registro_str.encode('utf-8')


def processar_csvs_e_gerar_binarios(arquivos_csv: list, max_linhas_por_arquivo: int = 100000):
    """
    Lê os arquivos CSV informados e gera os arquivos binários 'produtos.dat' e 'acessos.dat'.
    """
    produtos_dict = {}  # Mapeia {product_id: (brand, price, category_code)} para evitar duplicatas
    event_id_counter = 1

    print("--- INICIANDO PROCESSAMENTO DOS ARQUIVOS CSV ---")

    # Abrir arquivo de acessos para escrita contínua (streaming)
    with open("acessos.dat", "wb") as f_acessos:
        for csv_file in arquivos_csv:
            if not os.path.exists(csv_file):
                print(f"[!] Arquivo '{csv_file}' não encontrado na pasta atual. Pulando...")
                continue

            print(f"[->] Lendo '{csv_file}'...")
            
            with open(csv_file, mode='r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)  # Pula a linha do cabeçalho
                
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
                        # Pula linhas com formatação corrompida ou incompleta
                        continue

                    # 1. Armazena/atualiza o produto no dicionário (unicidade de produto)
                    if product_id not in produtos_dict:
                        produtos_dict[product_id] = (brand, price, category_code)

                    # 2. Grava o acesso diretamente no arquivo binário em disco
                    rec_acesso = formatar_acesso(event_id_counter, event_type, product_id, user_id)
                    f_acessos.write(rec_acesso)
                    event_id_counter += 1

                    count += 1
                    if max_linhas_por_arquivo and count >= max_linhas_por_arquivo:
                        print(f"    Limite de {max_linhas_por_arquivo:,} linhas atingido para '{csv_file}'.")
                        break

    # Gravação do arquivo de produtos ordenado por product_id
    print(f"\n[->] Ordenando e gravando {len(produtos_dict):,} produtos únicos em 'produtos.dat'...")
    produtos_ordenados = sorted(produtos_dict.items(), key=lambda x: x[0])

    with open("produtos.dat", "wb") as f_produtos:
        for p_id, (brand, price, category_code) in produtos_ordenados:
            rec_produto = formatar_produto(p_id, brand, price, category_code)
            f_produtos.write(rec_produto)

    print("\n--- PROCESSAMENTO CONCLUÍDO ---")
    print(f"[+] 'produtos.dat' gerado com {len(produtos_ordenados):,} registros.")
    print(f"[+] 'acessos.dat' gerado com {event_id_counter - 1:,} registros.")

if __name__ == "__main__":
    arquivos = ["2019-Oct.csv", "2019-Nov.csv"]
    processar_csvs_e_gerar_binarios(arquivos, max_linhas_por_arquivo=100000)