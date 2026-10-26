import os

TAMANHO_REGISTRO_PRODUTO = 71  # 10 + 20 + 10 + 30 + 1 (\n)
TAMANHO_REGISTRO_ACESSO = 43   # 10 + 12 + 10 + 10 + 1 (\n)

TAMANHO_CHAVE_PRIMARIA = 10 

INTERVALO_BLOCO = 20

def gerar_indice_parcial(arq_dados: str, arq_indice: str, tamanho_registro: int, intervalo: int):
    if not os.path.exists(arq_dados):
        print(f"[!] Erro: Arquivo de dados '{arq_dados}' não foi encontrado.")
        return

    registros_processados = 0
    entradas_indice = 0

    print(f"[->] Gerando índice parcial para '{arq_dados}' (Intervalo = {intervalo} registros)...")

    with open(arq_dados, "rb") as f_dados, open(arq_indice, "w", encoding="utf-8") as f_idx:
        while True:
            # Pega o deslocamento atual em bytes antes da leitura
            offset_atual = f_dados.tell()
            
            # Lê exatamente o tamanho de um registro
            registro_bytes = f_dados.read(tamanho_registro)
            if not registro_bytes or len(registro_bytes) < tamanho_registro:
                break  # Fim do arquivo

            # A cada 'intervalo' registros, extraímos a chave primária e salvamos no índice
            if registros_processados % intervalo == 0:
                # A chave primária está nos primeiros 10 bytes
                chave_primaria = registro_bytes[:TAMANHO_CHAVE_PRIMARIA].decode('utf-8')
                
                # Desconsidera registros marcados logicamente como deletados (que começam com '*')
                if not chave_primaria.startswith('*'):
                    f_idx.write(f"{chave_primaria}:{offset_atual}\n")
                    entradas_indice += 1

            registros_processados += 1

    print(f"[+] Índice parcial '{arq_indice}' gerado com sucesso!")
    print(f"    - Registros no arquivo .dat: {registros_processados:,}")
    print(f"    - Entradas salvas no .idx:   {entradas_indice:,}")
    
    tam_dat = os.path.getsize(arq_dados)
    tam_idx = os.path.getsize(arq_indice)
    print(f"    - Tamanho .dat: {tam_dat / 1024:.2f} KB | Tamanho .idx: {tam_idx / 1024:.2f} KB\n")


if __name__ == "__main__":
    print("--- CONSTRUÇÃO DOS ARQUIVOS DE ÍNDICE PARCIAL (.IDX) ---\n")

    gerar_indice_parcial(
        arq_dados="produtos.dat",
        arq_indice="produtos.idx",
        tamanho_registro=TAMANHO_REGISTRO_PRODUTO,
        intervalo=INTERVALO_BLOCO
    )

    gerar_indice_parcial(
        arq_dados="acessos.dat",
        arq_indice="acessos.idx",
        tamanho_registro=TAMANHO_REGISTRO_ACESSO,
        intervalo=INTERVALO_BLOCO
    )