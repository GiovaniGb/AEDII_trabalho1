import bisect
import os
import shutil
import time
import zlib

# ==============================================================================
# CONFIGURAÇÕES GERAIS E TAMANHOS DE REGISTROS (TAMANHO FIXO COM '\n')
# ==============================================================================
# Registros de Produtos: 10 (id) + 20 (brand) + 10 (price) + 30 (cat) + 1 (\n) = 71 bytes
TAMANHO_REGISTRO_PRODUTO = 71
# Registros de Acessos: 10 (id) + 12 (type) + 10 (prod_id) + 10 (user_id) + 1 (\n) = 43 bytes
TAMANHO_REGISTRO_ACESSO = 43

TAMANHO_CHAVE = 10
INTERVALO_BLOCO_INDICE = 20

# Definição da Ordem da Árvore B+ baseada no tamanho de página/bloco de disco
TAMANHO_PAGINA_BYTES = 4096      # Bloco/página padrão de 4 KB
TAMANHO_ENTRADA_BMAIS = 32       # Chave (10B) + Offset (8B) + Ponteiro/Overhead (14B)
ORDEM_ARVORE_BMAIS = TAMANHO_PAGINA_BYTES // TAMANHO_ENTRADA_BMAIS  # Ordem = 128

# Capacidade prima da Tabela Hash (Encadeamento Separado)
CAPACIDADE_TABELA_HASH = 50021

# Chave simétrica para criptografia dos arquivos .dat
CHAVE_CRIPTO = b"AED2_TRABALHO2_2026"

# Nomes dos arquivos
ARQ_PROD_DAT = "produtos.dat"
ARQ_PROD_IDX = "produtos.idx"           # Índice parcial em arquivo (chave: product_id)
ARQ_ACES_DAT = "acessos.dat"
ARQ_ACES_IDX = "acessos.idx"            # Índice parcial em arquivo (chave: event_id)
ARQ_ACES_PROD_IDX = "acessos_prod.idx"  # Índice exaustivo em arquivo (coluna não-chave: product_id)

# Estruturas em memória RAM e estado de criptografia por arquivo
indice_produtos = []
indice_acessos = []
arvore_b_mais_produtos = None
tabela_hash_acessos = None
arquivo_criptografado = {"produto": False, "acesso": False}


# ==============================================================================
# CRIPTOGRAFIA SIMÉTRICA DE TAMANHO FIXO E COMPRESSÃO (ZLIB)
# ==============================================================================
def criptografar_payload(dados: bytes) -> bytes:
    """
    Criptografa os bytes do registro mantendo rigorosamente o mesmo tamanho em bytes
    e evitando gerar 0x0A ('\n') ou 0x2A ('*'), preservando a navegação por fseek().
    """
    resultado = bytearray(len(dados))
    k_len = len(CHAVE_CRIPTO)
    for i, b in enumerate(dados):
        if b == 10 or b == 42:
            resultado[i] = b
        else:
            idx = b - (1 if b > 10 else 0) - (1 if b > 42 else 0)
            k = (CHAVE_CRIPTO[i % k_len] + (i * 17)) % 253 + 1
            enc = (idx + k) % 254
            out = enc + (1 if enc >= 10 else 0)
            if out >= 42:
                out += 1
            resultado[i] = out
    return bytes(resultado)


def descriptografar_payload(dados_cifrados: bytes) -> bytes:
    """Reverte a criptografia de um bloco de registro lido do disco."""
    resultado = bytearray(len(dados_cifrados))
    k_len = len(CHAVE_CRIPTO)
    for i, b in enumerate(dados_cifrados):
        if b == 10 or b == 42:
            resultado[i] = b
        else:
            enc = b - (1 if b > 10 else 0) - (1 if b > 42 else 0)
            k = (CHAVE_CRIPTO[i % k_len] + (i * 17)) % 253 + 1
            idx = (enc - k) % 254
            out = idx + (1 if idx >= 10 else 0)
            if out >= 42:
                out += 1
            resultado[i] = out
    return bytes(resultado)


def criptografar_registro(registro_plano: bytes) -> bytes:
    """Criptografa o conteúdo mantendo o '\n' final intacto."""
    return criptografar_payload(registro_plano[:-1]) + b"\n"


def descriptografar_registro(registro_cifrado: bytes) -> bytes:
    """Descriptografa o conteúdo mantendo o '\n' final."""
    return descriptografar_payload(registro_cifrado[:-1]) + b"\n"


def arquivo_tem_deslocamento_crlf(arq_dados: str, tamanho_registro: int) -> bool:
    """Detecta se um arquivo cifrado sofreu deslocamento de 1 byte por quebra de linha Windows (\\r\\n)."""
    if not os.path.exists(arq_dados) or os.path.getsize(arq_dados) < tamanho_registro * 2:
        return False
    with open(arq_dados, "rb") as f:
        for _ in range(10):
            reg = f.read(tamanho_registro)
            if not reg or len(reg) < tamanho_registro:
                break
            if 10 in reg[:-1]:
                return True
    return False


def arquivo_esta_criptografado(arq_dados: str) -> bool:
    """
    Inspeciona as primeiras linhas do arquivo .dat para detectar se está em texto plano
    (Trabalho I, incluindo arquivos Windows com \\r\\n) ou criptografado (Trabalho II).
    """
    if not os.path.exists(arq_dados) or os.path.getsize(arq_dados) == 0:
        return False
    with open(arq_dados, "rb") as f:
        for _ in range(20):
            linha = f.readline()
            if not linha:
                break
            payload = linha.rstrip(b"\r\n")
            if not payload or payload.startswith(b"*"):
                continue
            nao_ascii = sum(1 for b in payload if b < 32 or b > 126)
            if nao_ascii > 0:
                return True
            return not payload[:TAMANHO_CHAVE].strip().isdigit()
    return False


def atualizar_estados_criptografia():
    """Sincroniza o estado de criptografia de cada arquivo .dat."""
    arquivo_criptografado["produto"] = arquivo_esta_criptografado(ARQ_PROD_DAT)
    arquivo_criptografado["acesso"] = arquivo_esta_criptografado(ARQ_ACES_DAT)


def extrair_chave_registro(reg_bytes: bytes, criptografado: bool) -> str:
    """Extrai a chave primária (10 bytes) conforme o estado do arquivo e retorna '*' se removido."""
    if reg_bytes.startswith(b"*"):
        return "*"
    raw_chave = descriptografar_payload(reg_bytes[:TAMANHO_CHAVE]) if criptografado else reg_bytes[:TAMANHO_CHAVE]
    chave = raw_chave.decode("utf-8", errors="replace")
    if chave.startswith("*"):
        return "*"
    return chave


def _reparar_id_com_espaco(id_str: str, prev_id, next_id) -> str:
    """Reconstrói um ID de 10 dígitos que teve 1 byte substituído por espaço usando vizinhos ordenados."""
    if id_str.isdigit() and len(id_str) == 10:
        return id_str
    pos_espaco = id_str.find(" ")
    if pos_espaco == -1:
        return id_str
    candidatos = []
    for d in "0123456789":
        cand = id_str[:pos_espaco] + d + id_str[pos_espaco + 1:]
        if cand.isdigit():
            val = int(cand)
            if (prev_id is None or val > prev_id) and (next_id is None or val < next_id):
                candidatos.append(cand)
    if len(candidatos) == 1:
        return candidatos[0]
    elif len(candidatos) > 1 and prev_id is not None:
        return min(candidatos, key=lambda c: abs(int(c) - (prev_id + 1)))
    return id_str


def sanitizar_e_ordenar_dat(arq_dat: str, tam_reg: int, criptografado: bool) -> bool:
    """
    Verifica se existem chaves com espaços residuais (causados pelo deslocamento \\r\\n)
    ou registros fora de ordem crescente no .dat, corrige e garante ordenação estrita.
    """
    if not os.path.exists(arq_dat) or os.path.getsize(arq_dat) == 0:
        return False

    precisa_reparo = False
    registros_planos = []
    prev_chave = ""

    with open(arq_dat, "rb") as f:
        while True:
            reg = f.read(tam_reg)
            if not reg or len(reg) < tam_reg:
                break
            if reg.startswith(b"*"):
                registros_planos.append((True, reg[:-1]))
                continue
            plano = descriptografar_payload(reg[:-1]) if criptografado else reg[:-1]
            chave = plano[:TAMANHO_CHAVE].decode("utf-8", errors="replace")
            if not chave.isdigit() or (prev_chave and chave < prev_chave):
                precisa_reparo = True
            prev_chave = chave
            registros_planos.append((False, plano))

    if not precisa_reparo:
        return False

    for i, (removido, plano) in enumerate(registros_planos):
        if removido:
            continue
        id_str = plano[:TAMANHO_CHAVE].decode("utf-8", errors="replace")
        if not id_str.isdigit():
            prev_id = None
            for j in range(i - 1, -1, -1):
                if not registros_planos[j][0]:
                    c_prev = registros_planos[j][1][:TAMANHO_CHAVE].decode("utf-8", errors="replace")
                    if c_prev.isdigit():
                        prev_id = int(c_prev)
                        break
            next_id = None
            for j in range(i + 1, len(registros_planos)):
                if not registros_planos[j][0]:
                    c_next = registros_planos[j][1][:TAMANHO_CHAVE].decode("utf-8", errors="replace")
                    if c_next.isdigit():
                        next_id = int(c_next)
                        break
            id_corrigido = _reparar_id_com_espaco(id_str, prev_id, next_id)
            if id_corrigido.isdigit():
                registros_planos[i] = (False, id_corrigido.encode("utf-8") + plano[TAMANHO_CHAVE:])

    validos = []
    removidos = []
    for removido, plano in registros_planos:
        if removido:
            removidos.append(plano)
        else:
            chave = plano[:TAMANHO_CHAVE].decode("utf-8", errors="replace")
            if chave.isdigit():
                validos.append((chave, plano))

    validos.sort(key=lambda x: x[0])

    arq_temp = arq_dat + ".tmp"
    with open(arq_temp, "wb") as f_out:
        for _, plano in validos:
            out = criptografar_payload(plano) + b"\n" if criptografado else plano + b"\n"
            f_out.write(out)
        for plano_rem in removidos:
            f_out.write(plano_rem + b"\n")

    shutil.move(arq_temp, arq_dat)
    return True


def _reparar_e_criptografar_deslocado(arq_dat: str, tam_reg: int) -> int:
    """Realinha um arquivo .dat deslocado por \\r\\n e grava os registros criptografados no tamanho fixo exato."""
    tam_payload = tam_reg - 1
    arq_temp = arq_dat + ".tmp"
    stream_recuperado = bytearray()

    with open(arq_dat, "rb") as f_in:
        while True:
            chunk = f_in.read(tam_reg)
            if not chunk or len(chunk) < tam_reg:
                break
            if chunk.startswith(b"*"):
                stream_recuperado.extend(chunk)
            else:
                dec = descriptografar_payload(chunk[:-1])
                stream_recuperado.extend(dec + b" ")

    total_regs = 0
    with open(arq_temp, "wb") as f_out:
        for parte in bytes(stream_recuperado).split(b"\n"):
            limpo = parte.rstrip(b"\r")
            if len(limpo) < tam_payload - 5:
                continue
            payload = limpo[:tam_payload].ljust(tam_payload, b" ")
            if payload.startswith(b"*"):
                f_out.write(payload + b"\n")
            else:
                f_out.write(criptografar_payload(payload) + b"\n")
            total_regs += 1

    shutil.move(arq_temp, arq_dat)
    sanitizar_e_ordenar_dat(arq_dat, tam_reg, True)
    return os.path.getsize(arq_dat) // tam_reg


def criptografar_arquivos_dat_existentes():
    """
    Lê os arquivos produtos.dat e acessos.dat gerados no Trabalho I linha a linha (tratando \\r\\n),
    criptografa cada registro cravando exatamente 71 e 43 bytes e gera todos os índices do Trabalho II.
    """
    global indice_produtos, indice_acessos

    arquivos_config = [
        ("produto", ARQ_PROD_DAT, TAMANHO_REGISTRO_PRODUTO),
        ("acesso", ARQ_ACES_DAT, TAMANHO_REGISTRO_ACESSO),
    ]

    encontrados = [arq for _, arq, _ in arquivos_config if os.path.exists(arq)]
    if not encontrados:
        print("\n[!] Erro: Arquivos 'produtos.dat' e 'acessos.dat' (do Trabalho I) não encontrados na pasta.")
        return False

    print("\n==================================================================")
    print("   CRIPTOGRAFANDO ARQUIVOS .DAT DO TRABALHO I E GERANDO ÍNDICES   ")
    print("==================================================================")

    for tipo_base, arq_dat, tam_reg in arquivos_config:
        if not os.path.exists(arq_dat):
            print(f"[!] Aviso: '{arq_dat}' não encontrado, pulando...")
            continue

        t0 = time.perf_counter()
        tam_payload = tam_reg - 1

        if arquivo_tem_deslocamento_crlf(arq_dat, tam_reg):
            total_regs = _reparar_e_criptografar_deslocado(arq_dat, tam_reg)
            arquivo_criptografado[tipo_base] = True
            dt_ms = (time.perf_counter() - t0) * 1000
            print(f"[+] '{arq_dat}' realinhado e criptografado ({total_regs:,} registros | {os.path.getsize(arq_dat):,} bytes) em {dt_ms:.2f} ms.".replace(",", "."))
            continue

        if arquivo_esta_criptografado(arq_dat):
            arquivo_criptografado[tipo_base] = True
            sanitizar_e_ordenar_dat(arq_dat, tam_reg, True)
            print(f"[i] '{arq_dat}' já está criptografado, alinhado e ordenado ({os.path.getsize(arq_dat):,} bytes).".replace(",", "."))
            continue

        arq_temp = arq_dat + ".tmp"
        total_regs = 0

        with open(arq_dat, "rb") as f_in, open(arq_temp, "wb") as f_out:
            for linha in f_in:
                payload = linha.rstrip(b"\r\n")
                if not payload:
                    continue
                payload = payload[:tam_payload].ljust(tam_payload, b" ")
                if payload.startswith(b"*"):
                    f_out.write(payload + b"\n")
                else:
                    f_out.write(criptografar_payload(payload) + b"\n")
                total_regs += 1

        shutil.move(arq_temp, arq_dat)
        sanitizar_e_ordenar_dat(arq_dat, tam_reg, True)
        arquivo_criptografado[tipo_base] = True
        dt_ms = (time.perf_counter() - t0) * 1000
        print(f"[+] '{arq_dat}' criptografado com sucesso ({total_regs:,} registros | {os.path.getsize(arq_dat):,} bytes) em {dt_ms:.2f} ms.".replace(",", "."))

    # Reconstrói os índices em disco (.idx)
    print("\n[->] Atualizando arquivos de índices em disco (.idx)...")
    if os.path.exists(ARQ_PROD_DAT):
        indice_produtos = reconstruir_indice_parcial(ARQ_PROD_DAT, ARQ_PROD_IDX, TAMANHO_REGISTRO_PRODUTO, arquivo_criptografado["produto"])
        print(f"[+] '{ARQ_PROD_IDX}' atualizado ({len(indice_produtos):,} blocos).".replace(",", "."))

    if os.path.exists(ARQ_ACES_DAT):
        indice_acessos = reconstruir_indice_parcial(ARQ_ACES_DAT, ARQ_ACES_IDX, TAMANHO_REGISTRO_ACESSO, arquivo_criptografado["acesso"])
        reconstruir_indice_exaustivo_acessos_prod()
        print(f"[+] '{ARQ_ACES_IDX}' ({len(indice_acessos):,} blocos) e '{ARQ_ACES_PROD_IDX}' (índice exaustivo) atualizados.".replace(",", "."))

    # Constrói os índices em memória (Árvore B+ e Tabela Hash) medindo os tempos
    if os.path.exists(ARQ_PROD_DAT):
        construir_arvore_b_mais_produtos()
    if os.path.exists(ARQ_ACES_DAT):
        construir_tabela_hash_acessos()

    return True


def comprimir_arquivos_dados():
    """Comprime os arquivos .dat usando zlib e exibe as taxas de compressão."""
    print("\n--- COMPRESSÃO DE ARQUIVOS DE DADOS (ZLIB) ---")
    for arq in [ARQ_PROD_DAT, ARQ_ACES_DAT]:
        if not os.path.exists(arq):
            print(f"[!] '{arq}' não encontrado.")
            continue
        arq_comp = arq + ".zlib"
        t0 = time.perf_counter()
        with open(arq, "rb") as f_in:
            dados_originais = f_in.read()
        dados_comprimidos = zlib.compress(dados_originais, level=6)
        with open(arq_comp, "wb") as f_out:
            f_out.write(dados_comprimidos)
        dt = (time.perf_counter() - t0) * 1000

        tam_orig = len(dados_originais)
        tam_comp = len(dados_comprimidos)
        reducao = (1 - (tam_comp / tam_orig)) * 100 if tam_orig > 0 else 0
        print(f"[+] {arq} -> {arq_comp}")
        print(f"    Original: {tam_orig:,} bytes | Comprimido: {tam_comp:,} bytes | Redução: {reducao:.2f}% ({dt:.2f} ms)".replace(",", "."))


def descomprimir_arquivos_dados():
    """Descomprime arquivos .dat.zlib restaurando os arquivos .dat."""
    print("\n--- DESCOMPRESSÃO DE ARQUIVOS DE DADOS (ZLIB) ---")
    for arq in [ARQ_PROD_DAT, ARQ_ACES_DAT]:
        arq_comp = arq + ".zlib"
        if not os.path.exists(arq_comp):
            print(f"[!] Arquivo compactado '{arq_comp}' não encontrado.")
            continue
        t0 = time.perf_counter()
        with open(arq_comp, "rb") as f_in:
            dados_comprimidos = f_in.read()
        dados_originais = zlib.decompress(dados_comprimidos)
        with open(arq, "wb") as f_out:
            f_out.write(dados_originais)
        dt = (time.perf_counter() - t0) * 1000
        print(f"[+] '{arq_comp}' descomprimido para '{arq}' ({len(dados_originais):,} bytes) em {dt:.2f} ms".replace(",", "."))
    atualizar_estados_criptografia()


# ==============================================================================
# FORMATADORES E PARSERS DE REGISTROS
# ==============================================================================
def formatar_produto(p_id: int, brand: str, price: float, category: str, criptografar: bool = None) -> bytes:
    if criptografar is None:
        criptografar = arquivo_criptografado["produto"]
    p_id_str = f"{int(p_id):010d}"
    brand_str = f"{brand[:20]:<20}"
    price_str = f"{float(price):010.2f}"
    cat_str = f"{category[:30]:<30}"
    plano = f"{p_id_str}{brand_str}{price_str}{cat_str}\n".encode("utf-8")
    return criptografar_registro(plano) if criptografar else plano


def desformatar_produto(registro_bytes: bytes, criptografado: bool = None) -> dict:
    if criptografado is None:
        criptografado = arquivo_criptografado["produto"]
    plano = descriptografar_registro(registro_bytes) if criptografado else registro_bytes
    texto = plano.decode("utf-8", errors="replace")
    price_str = texto[30:40].strip()
    try:
        preco = float(price_str)
    except ValueError:
        preco = 0.0
    return {
        "product_id": texto[0:10].strip(),
        "brand": texto[10:30].strip(),
        "price": preco,
        "category_code": texto[40:70].strip()
    }


def formatar_acesso(e_id: int, e_type: str, p_id: int, u_id: int, criptografar: bool = None) -> bytes:
    if criptografar is None:
        criptografar = arquivo_criptografado["acesso"]
    e_id_str = f"{int(e_id):010d}"
    e_type_str = f"{e_type[:12]:<12}"
    p_id_str = f"{int(p_id):010d}"
    u_id_str = f"{int(u_id):010d}"
    plano = f"{e_id_str}{e_type_str}{p_id_str}{u_id_str}\n".encode("utf-8")
    return criptografar_registro(plano) if criptografar else plano


def desformatar_acesso(registro_bytes: bytes, criptografado: bool = None) -> dict:
    if criptografado is None:
        criptografado = arquivo_criptografado["acesso"]
    plano = descriptografar_registro(registro_bytes) if criptografado else registro_bytes
    texto = plano.decode("utf-8", errors="replace")
    return {
        "event_id": texto[0:10].strip(),
        "event_type": texto[10:22].strip(),
        "product_id": texto[22:32].strip(),
        "user_id": texto[32:42].strip()
    }


# ==============================================================================
# ESTRUTURAS DE ÍNDICE EM MEMÓRIA (TRABALHO II): ÁRVORE B+ E TABELA HASH
# ==============================================================================
class NoBMais:
    def __init__(self, folha: bool = False):
        self.folha = folha
        self.chaves = []
        self.valores = []    # Folhas: offsets no .dat | Internos: nós filhos
        self.proximo = None  # Encadeamento sequencial entre folhas


class ArvoreBMais:
    """
    Índice em memória via Árvore B+ para produtos.dat (chave: product_id).
    Ordem definida pelo tamanho de bloco/página (4096B / 32B = 128).
    Os endereços (offsets) dos registros residem exclusivamente nos nós folhas.
    """
    def __init__(self, ordem: int = ORDEM_ARVORE_BMAIS):
        self.ordem = ordem
        self.raiz = NoBMais(folha=True)
        self.total_elementos = 0

    def buscar(self, chave: str):
        no = self.raiz
        while not no.folha:
            idx = bisect.bisect_right(no.chaves, chave)
            no = no.valores[idx]
        idx = bisect.bisect_left(no.chaves, chave)
        if idx < len(no.chaves) and no.chaves[idx] == chave:
            return no.valores[idx]
        return None

    def inserir(self, chave: str, offset: int):
        raiz = self.raiz
        if len(raiz.chaves) == self.ordem - 1:
            nova_raiz = NoBMais(folha=False)
            nova_raiz.valores.append(self.raiz)
            self._dividir_filho(nova_raiz, 0)
            self.raiz = nova_raiz
        self._inserir_nao_cheio(self.raiz, chave, offset)

    def _dividir_filho(self, pai: NoBMais, idx: int):
        ordem = self.ordem
        filho = pai.valores[idx]
        novo_no = NoBMais(folha=filho.folha)
        meio = ordem // 2

        if filho.folha:
            novo_no.chaves = filho.chaves[meio:]
            novo_no.valores = filho.valores[meio:]
            filho.chaves = filho.chaves[:meio]
            filho.valores = filho.valores[:meio]

            novo_no.proximo = filho.proximo
            filho.proximo = novo_no

            pai.chaves.insert(idx, novo_no.chaves[0])
            pai.valores.insert(idx + 1, novo_no)
        else:
            chave_promovida = filho.chaves[meio]
            novo_no.chaves = filho.chaves[meio + 1:]
            novo_no.valores = filho.valores[meio + 1:]
            filho.chaves = filho.chaves[:meio]
            filho.valores = filho.valores[:meio + 1]

            pai.chaves.insert(idx, chave_promovida)
            pai.valores.insert(idx + 1, novo_no)

    def _inserir_nao_cheio(self, no: NoBMais, chave: str, offset: int):
        if no.folha:
            idx = bisect.bisect_left(no.chaves, chave)
            if idx < len(no.chaves) and no.chaves[idx] == chave:
                no.valores[idx] = offset
            else:
                no.chaves.insert(idx, chave)
                no.valores.insert(idx, offset)
                self.total_elementos += 1
        else:
            idx = bisect.bisect_right(no.chaves, chave)
            filho = no.valores[idx]
            if len(filho.chaves) == self.ordem - 1:
                self._dividir_filho(no, idx)
                if chave >= no.chaves[idx]:
                    idx += 1
            self._inserir_nao_cheio(no.valores[idx], chave, offset)

    def remover(self, chave: str) -> bool:
        no = self.raiz
        while not no.folha:
            idx = bisect.bisect_right(no.chaves, chave)
            no = no.valores[idx]
        idx = bisect.bisect_left(no.chaves, chave)
        if idx < len(no.chaves) and no.chaves[idx] == chave:
            no.chaves.pop(idx)
            no.valores.pop(idx)
            self.total_elementos -= 1
            return True
        return False

    def altura(self) -> int:
        h = 1
        no = self.raiz
        while not no.folha:
            h += 1
            no = no.valores[0]
        return h


class NoHash:
    def __init__(self, chave: str, offset: int):
        self.chave = chave
        self.offsets = [offset]
        self.proximo = None


class TabelaHash:
    """
    Índice em memória via Tabela Hash para acessos.dat (coluna não-chave: product_id).
    Resolução de colisões por Encadeamento Separado (Separate Chaining).
    """
    def __init__(self, capacidade: int = CAPACIDADE_TABELA_HASH):
        self.capacidade = capacidade
        self.buckets = [None] * capacidade
        self.total_chaves_unicas = 0
        self.total_registros_indexados = 0
        self.total_colisoes = 0

    def _funcao_hash(self, chave: str) -> int:
        h = 5381
        for c in chave:
            h = ((h << 5) + h) + ord(c)
        return h % self.capacidade

    def inserir(self, chave: str, offset: int):
        idx = self._funcao_hash(chave)
        atual = self.buckets[idx]

        if atual is None:
            self.buckets[idx] = NoHash(chave, offset)
            self.total_chaves_unicas += 1
            self.total_registros_indexados += 1
            return

        anterior = None
        while atual is not None:
            if atual.chave == chave:
                atual.offsets.append(offset)
                self.total_registros_indexados += 1
                return
            anterior = atual
            atual = atual.proximo

        anterior.proximo = NoHash(chave, offset)
        self.total_chaves_unicas += 1
        self.total_registros_indexados += 1
        self.total_colisoes += 1

    def buscar(self, chave: str) -> list:
        idx = self._funcao_hash(chave)
        atual = self.buckets[idx]
        while atual is not None:
            if atual.chave == chave:
                return atual.offsets
            atual = atual.proximo
        return []

    def remover_offset(self, chave: str, offset: int) -> bool:
        idx = self._funcao_hash(chave)
        atual = self.buckets[idx]
        anterior = None
        while atual is not None:
            if atual.chave == chave:
                if offset in atual.offsets:
                    atual.offsets.remove(offset)
                    self.total_registros_indexados -= 1
                    if not atual.offsets:
                        if anterior is None:
                            self.buckets[idx] = atual.proximo
                        else:
                            anterior.proximo = atual.proximo
                        self.total_chaves_unicas -= 1
                    return True
                return False
            anterior = atual
            atual = atual.proximo
        return False


# ==============================================================================
# CONSTRUÇÃO DOS ÍNDICES EM MEMÓRIA A PARTIR DOS ARQUIVOS EM DISCO
# ==============================================================================
def construir_arvore_b_mais_produtos():
    """Lê produtos.dat em fluxo e constrói a Árvore B+ na memória RAM medindo o tempo."""
    global arvore_b_mais_produtos
    if not os.path.exists(ARQ_PROD_DAT):
        print(f"\n[!] Arquivo '{ARQ_PROD_DAT}' não encontrado.")
        return 0.0

    t0 = time.perf_counter()
    arvore = ArvoreBMais(ordem=ORDEM_ARVORE_BMAIS)
    cript = arquivo_criptografado["produto"]

    with open(ARQ_PROD_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_PRODUTO:
                break
            chave = extrair_chave_registro(reg_bytes, cript)
            if not chave.startswith("*"):
                arvore.inserir(chave, offset_atual)

    arvore_b_mais_produtos = arvore
    tempo_ms = (time.perf_counter() - t0) * 1000
    print(f"\n[+] Árvore B+ (Produtos) construída em {tempo_ms:.3f} ms!")
    print(f"    Ordem da Árvore: {arvore.ordem} (Bloco: {TAMANHO_PAGINA_BYTES}B) | Elementos: {arvore.total_elementos:,} | Altura: {arvore.altura()}".replace(",", "."))
    return tempo_ms


def construir_tabela_hash_acessos():
    """Lê acessos.dat em fluxo e constrói a Tabela Hash sobre product_id medindo o tempo."""
    global tabela_hash_acessos
    if not os.path.exists(ARQ_ACES_DAT):
        print(f"\n[!] Arquivo '{ARQ_ACES_DAT}' não encontrado.")
        return 0.0

    t0 = time.perf_counter()
    th = TabelaHash(capacidade=CAPACIDADE_TABELA_HASH)
    cript = arquivo_criptografado["acesso"]

    with open(ARQ_ACES_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_ACESSO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_ACESSO:
                break
            chave_primaria = extrair_chave_registro(reg_bytes, cript)
            if not chave_primaria.startswith("*"):
                dados = desformatar_acesso(reg_bytes, cript)
                th.inserir(dados["product_id"], offset_atual)

    tabela_hash_acessos = th
    tempo_ms = (time.perf_counter() - t0) * 1000
    fator_carga = th.total_chaves_unicas / th.capacidade
    print(f"\n[+] Tabela Hash (Acessos -> product_id) construída em {tempo_ms:.3f} ms!")
    print(f"    Buckets: {th.capacidade:,} | Chaves únicas: {th.total_chaves_unicas:,} | Acessos indexados: {th.total_registros_indexados:,}".replace(",", "."))
    print(f"    Colisões resolvidas (Encadeamento Separado): {th.total_colisoes:,} | Fator de carga: {fator_carga:.2f}".replace(",", "."))
    return tempo_ms


# ==============================================================================
# PERSISTÊNCIA E MANIPULAÇÃO DE ÍNDICES EM ARQUIVO (.IDX)
# ==============================================================================
def carregar_indice_parcial(arq_indice: str) -> list:
    indice = []
    if os.path.exists(arq_indice):
        with open(arq_indice, "r", encoding="utf-8") as f:
            for linha in f:
                partes = linha.strip().split(":")
                if len(partes) == 2:
                    indice.append((partes[0], int(partes[1])))
    return indice


def salvar_indice_parcial(arq_indice: str, indice: list):
    with open(arq_indice, "w", encoding="utf-8") as f:
        for chave, offset in indice:
            f.write(f"{chave}:{offset}\n")


def reconstruir_indice_parcial(arq_dados: str, arq_indice: str, tamanho_registro: int, criptografado: bool) -> list:
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

            chave = extrair_chave_registro(reg_bytes, criptografado)
            if not chave.startswith("*"):
                if registros_validos % INTERVALO_BLOCO_INDICE == 0:
                    novo_indice.append((chave, offset_atual))
                registros_validos += 1

    salvar_indice_parcial(arq_indice, novo_indice)
    return novo_indice


def reconstruir_indice_exaustivo_acessos_prod():
    """
    Gera/atualiza o arquivo de índice exaustivo secundário (acessos_prod.idx)
    ordenado por product_id para comparação com a Tabela Hash em memória.
    """
    if not os.path.exists(ARQ_ACES_DAT):
        return 0.0

    t0 = time.perf_counter()
    entradas = []
    cript = arquivo_criptografado["acesso"]

    with open(ARQ_ACES_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_ACESSO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_ACESSO:
                break
            chave = extrair_chave_registro(reg_bytes, cript)
            if not chave.startswith("*"):
                dados = desformatar_acesso(reg_bytes, cript)
                entradas.append((dados["product_id"], offset_atual))

    entradas.sort(key=lambda x: x[0])
    with open(ARQ_ACES_PROD_IDX, "w", encoding="utf-8") as f_out:
        for prod_id, offset in entradas:
            f_out.write(f"{prod_id}:{offset}\n")

    return (time.perf_counter() - t0) * 1000


# ==============================================================================
# OPERAÇÕES DE EXIBIÇÃO, BUSCA E ATUALIZAÇÃO
# ==============================================================================
def mostrar_dados(arq_dados: str, tamanho_registro: int, parser_fn, criptografado: bool, inicio: int, qtd: int):
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

            chave = extrair_chave_registro(reg_bytes, criptografado)
            if not chave.startswith("*"):
                dados = parser_fn(reg_bytes, criptografado)
                print(f"[{inicio + lidos:06d}] {dados}")
            else:
                print(f"[{inicio + lidos:06d}] [REGISTRO REMOVIDO LOGICAMENTE]")
            lidos += 1


def _ler_registro_ativo_proximo(f, mid: int, low: int, high: int, tamanho_registro: int, criptografado: bool):
    """
    Quando o meio da busca binária cai em um registro logicamente removido ('*'),
    localiza o registro ativo mais próximo dentro de [low, high].
    """
    esq, dir_ = mid - 1, mid + 1
    while esq >= low or dir_ <= high:
        if esq >= low:
            f.seek(esq * tamanho_registro)
            r_esq = f.read(tamanho_registro)
            c_esq = extrair_chave_registro(r_esq, criptografado)
            if c_esq != "*":
                return esq, c_esq, r_esq
            esq -= 1
        if dir_ <= high:
            f.seek(dir_ * tamanho_registro)
            r_dir = f.read(tamanho_registro)
            c_dir = extrair_chave_registro(r_dir, criptografado)
            if c_dir != "*":
                return dir_, c_dir, r_dir
            dir_ += 1
    return -1, "*", b""


def pesquisa_binaria_direta(arq_dados: str, target_id: int, tamanho_registro: int, parser_fn, criptografado: bool):
    if not os.path.exists(arq_dados):
        print(f"\n[!] Arquivo '{arq_dados}' não encontrado.")
        return None

    t0 = time.perf_counter()
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
            chave_mid = extrair_chave_registro(reg_bytes, criptografado)

            if chave_mid == "*":
                mid, chave_mid, reg_bytes = _ler_registro_ativo_proximo(
                    f, mid, low, high, tamanho_registro, criptografado
                )
                if mid == -1:
                    break

            if chave_mid == target_str:
                dt_us = (time.perf_counter() - t0) * 1_000_000
                print(f"\n[+] Registro encontrado em {comparacoes} comparações ({dt_us:.2f} µs)!")
                return parser_fn(reg_bytes, criptografado)
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[-] Registro ID {target_str} não encontrado após {comparacoes} comparações ({dt_us:.2f} µs).")
    return None


def consultar_por_indice_arquivo(arq_dados: str, indice_ram: list, target_id: int, tamanho_registro: int, parser_fn, criptografado: bool, silencioso: bool = False):
    """Consulta usando o índice parcial em arquivo (.idx) + seek() no .dat."""
    if not indice_ram:
        if not silencioso:
            print("\n[!] Erro: O índice parcial está vazio ou não foi carregado.")
        return None, 0.0

    t0 = time.perf_counter()
    target_str = f"{int(target_id):010d}"

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

    comp_dat = 0
    with open(arq_dados, "rb") as f:
        f.seek(offset_bloco)
        for _ in range(INTERVALO_BLOCO_INDICE):
            reg_bytes = f.read(tamanho_registro)
            if not reg_bytes or len(reg_bytes) < tamanho_registro:
                break

            comp_dat += 1
            chave_atual = extrair_chave_registro(reg_bytes, criptografado)

            if chave_atual == target_str:
                dt_us = (time.perf_counter() - t0) * 1_000_000
                if not silencioso:
                    print(f"\n[+] Índice Arquivo: Encontrado em {dt_us:.2f} µs (Comp. idx: {comp_idx} | Comp. dat: {comp_dat})")
                return parser_fn(reg_bytes, criptografado), dt_us
            elif chave_atual > target_str and not chave_atual.startswith("*"):
                break

    dt_us = (time.perf_counter() - t0) * 1_000_000
    if not silencioso:
        print(f"\n[-] Registro ID {target_str} não encontrado ({dt_us:.2f} µs).")
    return None, dt_us


def consultar_produto_arvore_b_mais(target_id: int, silencioso: bool = False):
    """Consulta produto usando a Árvore B+ em memória + seek() único no produtos.dat."""
    if arvore_b_mais_produtos is None:
        if not silencioso:
            print("\n[!] Árvore B+ ainda não foi construída.")
        return None, 0.0

    t0 = time.perf_counter()
    target_str = f"{int(target_id):010d}"
    offset = arvore_b_mais_produtos.buscar(target_str)
    cript = arquivo_criptografado["produto"]

    if offset is not None:
        with open(ARQ_PROD_DAT, "rb") as f:
            f.seek(offset)
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            dados = desformatar_produto(reg_bytes, cript)
        dt_us = (time.perf_counter() - t0) * 1_000_000
        if not silencioso:
            print(f"\n[+] Árvore B+ (Memória): Encontrado no offset {offset} em {dt_us:.2f} µs!")
        return dados, dt_us

    dt_us = (time.perf_counter() - t0) * 1_000_000
    if not silencioso:
        print(f"\n[-] Árvore B+ (Memória): ID {target_str} não encontrado ({dt_us:.2f} µs).")
    return None, dt_us


def consultar_acessos_por_produto_arquivo(target_prod_id: int, silencioso: bool = False):
    """Consulta acessos de um product_id via índice exaustivo em arquivo (acessos_prod.idx)."""
    if not os.path.exists(ARQ_ACES_PROD_IDX) or not os.path.exists(ARQ_ACES_DAT):
        if not silencioso:
            print("\n[!] Arquivo de índice exaustivo 'acessos_prod.idx' não encontrado. Execute a Opção 1.")
        return [], 0.0

    t0 = time.perf_counter()
    target_str = f"{int(target_prod_id):010d}"
    offsets = []
    cript = arquivo_criptografado["acesso"]

    tam_arq = os.path.getsize(ARQ_ACES_PROD_IDX)
    with open(ARQ_ACES_PROD_IDX, "r", encoding="utf-8") as f_idx:
        low = 0
        high = tam_arq
        pos_encontrada = -1

        while low <= high:
            mid = (low + high) // 2
            f_idx.seek(mid)
            if mid > 0:
                f_idx.readline()
            pos_linha = f_idx.tell()
            linha = f_idx.readline()
            if not linha:
                high = mid - 1
                continue

            chave_lida, _ = linha.strip().split(":")
            if chave_lida == target_str:
                pos_encontrada = pos_linha
                high = mid - 1
            elif chave_lida < target_str:
                low = f_idx.tell()
            else:
                high = mid - 1

        if pos_encontrada != -1:
            f_idx.seek(pos_encontrada)
            while True:
                linha = f_idx.readline()
                if not linha:
                    break
                chave_lida, off_str = linha.strip().split(":")
                if chave_lida == target_str:
                    offsets.append(int(off_str))
                elif chave_lida > target_str:
                    break

    resultados = []
    with open(ARQ_ACES_DAT, "rb") as f_dat:
        for off in offsets:
            f_dat.seek(off)
            reg_bytes = f_dat.read(TAMANHO_REGISTRO_ACESSO)
            if reg_bytes and not extrair_chave_registro(reg_bytes, cript).startswith("*"):
                resultados.append(desformatar_acesso(reg_bytes, cript))

    dt_us = (time.perf_counter() - t0) * 1_000_000
    if not silencioso:
        print(f"\n[+] Índice Arquivo (acessos_prod.idx): {len(resultados)} acesso(s) encontrado(s) em {dt_us:.2f} µs!")
    return resultados, dt_us


def consultar_acessos_por_produto_hash(target_prod_id: int, silencioso: bool = False):
    """Consulta acessos de um product_id via Tabela Hash em memória + seek() no acessos.dat."""
    if tabela_hash_acessos is None:
        if not silencioso:
            print("\n[!] Tabela Hash ainda não foi construída.")
        return [], 0.0

    t0 = time.perf_counter()
    target_str = f"{int(target_prod_id):010d}"
    offsets = tabela_hash_acessos.buscar(target_str)
    cript = arquivo_criptografado["acesso"]

    resultados = []
    if offsets and os.path.exists(ARQ_ACES_DAT):
        with open(ARQ_ACES_DAT, "rb") as f_dat:
            for off in offsets:
                f_dat.seek(off)
                reg_bytes = f_dat.read(TAMANHO_REGISTRO_ACESSO)
                if reg_bytes and not extrair_chave_registro(reg_bytes, cript).startswith("*"):
                    resultados.append(desformatar_acesso(reg_bytes, cript))

    dt_us = (time.perf_counter() - t0) * 1_000_000
    if not silencioso:
        print(f"\n[+] Tabela Hash (Memória): {len(resultados)} acesso(s) encontrado(s) em {dt_us:.2f} µs!")
    return resultados, dt_us


def inserir_registro(tipo_base: str, novo_bytes: bytes, target_id: int):
    """Insere registro mantendo ordenação e atualiza índices em disco e memória."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == "produto" else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO
    cript = arquivo_criptografado[tipo_base]

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

                chave_atual = extrair_chave_registro(reg_bytes, cript)
                if chave_atual == target_str:
                    print(f"\n[!] Erro: Registro com ID {target_str} já existe.")
                    f_out.close()
                    os.remove(arq_temp)
                    return False

                if not inserido and not chave_atual.startswith("*") and chave_atual > target_str:
                    f_out.write(novo_bytes)
                    inserido = True

                f_out.write(reg_bytes)

            if not inserido:
                f_out.write(novo_bytes)

        shutil.move(arq_temp, arq_dados)

    print(f"\n[+] Registro ID {target_str} inserido em '{arq_dados}'!")

    t0_idx = time.perf_counter()
    if tipo_base == "produto":
        indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro, cript)
    else:
        indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro, cript)
        reconstruir_indice_exaustivo_acessos_prod()
    dt_idx_ms = (time.perf_counter() - t0_idx) * 1000
    print(f"    [->] Índice em arquivo reconstruído em {dt_idx_ms:.3f} ms.")

    if tipo_base == "produto":
        construir_arvore_b_mais_produtos()
    else:
        construir_tabela_hash_acessos()
    return True


def remover_registro_logico(tipo_base: str, target_id: int):
    """Remove logicamente ('*') e atualiza índices em arquivo e em memória medindo tempos."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == "produto" else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO
    cript = arquivo_criptografado[tipo_base]

    if not os.path.exists(arq_dados):
        print(f"\n[!] Arquivo '{arq_dados}' não existe.")
        return False

    target_str = f"{int(target_id):010d}"
    tamanho_arquivo = os.path.getsize(arq_dados)
    total_registros = tamanho_arquivo // tamanho_registro

    low = 0
    high = total_registros - 1
    removido = False
    offset_removido = -1
    dados_acesso_removido = None

    with open(arq_dados, "r+b") as f:
        while low <= high:
            mid = (low + high) // 2
            offset = mid * tamanho_registro
            f.seek(offset)
            reg_bytes = f.read(tamanho_registro)
            chave_mid = extrair_chave_registro(reg_bytes, cript)

            if chave_mid == "*":
                mid, chave_mid, reg_bytes = _ler_registro_ativo_proximo(
                    f, mid, low, high, tamanho_registro, cript
                )
                if mid == -1:
                    break
                offset = mid * tamanho_registro

            if chave_mid == target_str:
                if tipo_base == "acesso":
                    dados_acesso_removido = desformatar_acesso(reg_bytes, cript)
                f.seek(offset)
                f.write(b"*")
                f.flush()
                removido = True
                offset_removido = offset
                print(f"\n[-] Registro ID {target_str} removido logicamente.")
                break
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    if removido:
        t0_idx = time.perf_counter()
        if tipo_base == "produto":
            indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro, cript)
        else:
            indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro, cript)
            reconstruir_indice_exaustivo_acessos_prod()
        dt_idx_ms = (time.perf_counter() - t0_idx) * 1000
        print(f"    [->] Índice em arquivo atualizado em {dt_idx_ms:.3f} ms.")

        t0_mem = time.perf_counter()
        if tipo_base == "produto" and arvore_b_mais_produtos is not None:
            arvore_b_mais_produtos.remover(target_str)
            dt_mem_us = (time.perf_counter() - t0_mem) * 1_000_000
            print(f"    [->] Chave removida da Árvore B+ (Memória) em {dt_mem_us:.2f} µs.")
        elif tipo_base == "acesso" and tabela_hash_acessos is not None and dados_acesso_removido:
            tabela_hash_acessos.remover_offset(dados_acesso_removido["product_id"], offset_removido)
            dt_mem_us = (time.perf_counter() - t0_mem) * 1_000_000
            print(f"    [->] Offset removido da Tabela Hash (Memória) em {dt_mem_us:.2f} µs.")
        return True

    print(f"\n[-] Erro: Registro ID {target_str} não encontrado.")
    return False


# ==============================================================================
# BENCHMARK COMPARATIVO (ITEM 3.2 DO TRABALHO II)
# ==============================================================================
def executar_benchmark_comparativo():
    """Executa 5 consultas reais comparando Índices de Arquivo vs Índices em Memória."""
    if not os.path.exists(ARQ_PROD_DAT) or not os.path.exists(ARQ_ACES_DAT):
        print("\n[!] Arquivos 'produtos.dat' e 'acessos.dat' não encontrados.")
        return

    if not os.path.exists(ARQ_ACES_PROD_IDX):
        reconstruir_indice_exaustivo_acessos_prod()
    if arvore_b_mais_produtos is None:
        construir_arvore_b_mais_produtos()
    if tabela_hash_acessos is None:
        construir_tabela_hash_acessos()

    cript_prod = arquivo_criptografado["produto"]
    tam_prod = os.path.getsize(ARQ_PROD_DAT)
    total_prod = tam_prod // TAMANHO_REGISTRO_PRODUTO
    indices_amostra = [0, total_prod // 4, total_prod // 2, (3 * total_prod) // 4, max(0, total_prod - 2)]
    chaves_teste = []

    with open(ARQ_PROD_DAT, "rb") as f:
        for idx in indices_amostra:
            f.seek(idx * TAMANHO_REGISTRO_PRODUTO)
            reg = f.read(TAMANHO_REGISTRO_PRODUTO)
            if reg:
                ch = extrair_chave_registro(reg, cript_prod)
                if not ch.startswith("*"):
                    chaves_teste.append(int(ch))

    print("\n==================================================================================")
    print("       TABELA COMPARATIVA 1: PRODUTOS (ÍNDICE PARCIAL .IDX vs ÁRVORE B+)          ")
    print("==================================================================================")
    print(f"{'Consulta':<10} | {'Product ID':<12} | {'Índice Arquivo (µs)':<20} | {'Árvore B+ RAM (µs)':<20}")
    print("-" * 82)
    for i, pid in enumerate(chaves_teste, 1):
        _, t_arq = consultar_por_indice_arquivo(ARQ_PROD_DAT, indice_produtos, pid, TAMANHO_REGISTRO_PRODUTO, desformatar_produto, cript_prod, silencioso=True)
        _, t_mem = consultar_produto_arvore_b_mais(pid, silencioso=True)
        print(f"#{i:<9} | {pid:<12} | {t_arq:<20.2f} | {t_mem:<20.2f}")

    print("\n==================================================================================")
    print("     TABELA COMPARATIVA 2: ACESSOS POR PRODUTO (ÍNDICE .IDX vs TABELA HASH)       ")
    print("==================================================================================")
    print(f"{'Consulta':<10} | {'Product ID':<12} | {'Qtd Acessos':<12} | {'Índice Arquivo (µs)':<20} | {'Tabela Hash (µs)':<18}")
    print("-" * 82)
    for i, pid in enumerate(chaves_teste, 1):
        _, t_arq = consultar_acessos_por_produto_arquivo(pid, silencioso=True)
        res_mem, t_mem = consultar_acessos_por_produto_hash(pid, silencioso=True)
        print(f"#{i:<9} | {pid:<12} | {len(res_mem):<12} | {t_arq:<20.2f} | {t_mem:<18.2f}")
    print("==================================================================================")


# ==============================================================================
# CONSULTAS ANALÍTICAS DO TRABALHO I (STREAMING DIRETO DO DISCO)
# ==============================================================================
def pergunta_marca_mais_produtos():
    if not os.path.exists(ARQ_PROD_DAT):
        print(f"\n[!] Arquivo '{ARQ_PROD_DAT}' não encontrado.")
        return

    contagem_marcas = {}
    valores_invalidos = {"sem_marca", "sem marca", "semmarca", "null", "none", "n/a", "undefined", "unknown", ""}
    cript = arquivo_criptografado["produto"]

    with open(ARQ_PROD_DAT, "rb") as f:
        while True:
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_PRODUTO:
                break
            chave = extrair_chave_registro(reg_bytes, cript)
            if not chave.startswith("*"):
                dados = desformatar_produto(reg_bytes, cript)
                marca = dados["brand"].strip()
                m_lower = marca.lower()
                if m_lower not in valores_invalidos and not m_lower.startswith("sem_") and not m_lower.startswith("sem "):
                    contagem_marcas[marca] = contagem_marcas.get(marca, 0) + 1

    if not contagem_marcas:
        print("[-] Nenhum registro com marca válida encontrado.")
        return

    marca_lider = max(contagem_marcas, key=contagem_marcas.get)
    qtd = contagem_marcas[marca_lider]
    print("\n--- RESPOSTA DA PERGUNTA 1 ---")
    print(f"Marca com maior número de produtos: '{marca_lider}'")
    print(f"Total de produtos cadastrados: {qtd:,}".replace(",", "."))


def pergunta_evento_mais_frequente():
    if not os.path.exists(ARQ_ACES_DAT):
        print(f"\n[!] Arquivo '{ARQ_ACES_DAT}' não encontrado.")
        return

    contagem_eventos = {}
    cript = arquivo_criptografado["acesso"]

    with open(ARQ_ACES_DAT, "rb") as f:
        while True:
            reg_bytes = f.read(TAMANHO_REGISTRO_ACESSO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_ACESSO:
                break
            chave = extrair_chave_registro(reg_bytes, cript)
            if not chave.startswith("*"):
                dados = desformatar_acesso(reg_bytes, cript)
                tipo_evento = dados["event_type"]
                contagem_eventos[tipo_evento] = contagem_eventos.get(tipo_evento, 0) + 1

    if not contagem_eventos:
        print("[-] Nenhum registro válido encontrado.")
        return

    evento_lider = max(contagem_eventos, key=contagem_eventos.get)
    print("\n--- RESPOSTA DA PERGUNTA 2 ---")
    print(f"Tipo de evento mais frequente: '{evento_lider}' ({contagem_eventos[evento_lider]:,} ocorrências)".replace(",", "."))
    for evt, total in contagem_eventos.items():
        print(f"  - {evt}: {total:,}".replace(",", "."))


def pergunta_produto_maior_preco():
    if not os.path.exists(ARQ_PROD_DAT):
        print(f"\n[!] Arquivo '{ARQ_PROD_DAT}' não encontrado.")
        return

    maior_preco = -1.0
    produto_mais_caro = None
    cript = arquivo_criptografado["produto"]

    with open(ARQ_PROD_DAT, "rb") as f:
        while True:
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_PRODUTO:
                break
            chave = extrair_chave_registro(reg_bytes, cript)
            if not chave.startswith("*"):
                dados = desformatar_produto(reg_bytes, cript)
                if dados["price"] > maior_preco:
                    maior_preco = dados["price"]
                    produto_mais_caro = dados

    if not produto_mais_caro:
        print("[-] Nenhum registro válido encontrado.")
        return

    print("\n--- RESPOSTA DA PERGUNTA 3 ---")
    print(f"  - ID do Produto: {produto_mais_caro['product_id']}")
    print(f"  - Marca:         {produto_mais_caro['brand']}")
    print(f"  - Categoria:     {produto_mais_caro['category_code']}")
    print(f"  - Preço:         $ {produto_mais_caro['price']:.2f}")


# ==============================================================================
# MENU INTERATIVO
# ==============================================================================
def menu_principal():
    global indice_produtos, indice_acessos

    atualizar_estados_criptografia()
    indice_produtos = carregar_indice_parcial(ARQ_PROD_IDX)
    indice_acessos = carregar_indice_parcial(ARQ_ACES_IDX)

    if os.path.exists(ARQ_PROD_DAT):
        if arquivo_tem_deslocamento_crlf(ARQ_PROD_DAT, TAMANHO_REGISTRO_PRODUTO):
            print("\n[!] Aviso: 'produtos.dat' está com deslocamento de quebra de linha. Use a Opção 1 para realinhar e criptografar.")
        elif not arquivo_criptografado["produto"]:
            print("\n[!] Aviso: 'produtos.dat' está em formato plano (Trabalho I). Use a Opção 1 para criptografar.")
        else:
            if sanitizar_e_ordenar_dat(ARQ_PROD_DAT, TAMANHO_REGISTRO_PRODUTO, True):
                print("\n[+] Ordenação e integridade das chaves de 'produtos.dat' reparadas automaticamente.")
                indice_produtos = reconstruir_indice_parcial(ARQ_PROD_DAT, ARQ_PROD_IDX, TAMANHO_REGISTRO_PRODUTO, True)
            construir_arvore_b_mais_produtos()

    if os.path.exists(ARQ_ACES_DAT):
        if arquivo_tem_deslocamento_crlf(ARQ_ACES_DAT, TAMANHO_REGISTRO_ACESSO):
            print("[!] Aviso: 'acessos.dat' está com deslocamento de quebra de linha. Use a Opção 1 para realinhar e criptografar.")
        elif not arquivo_criptografado["acesso"]:
            print("[!] Aviso: 'acessos.dat' está em formato plano (Trabalho I). Use a Opção 1 para criptografar.")
        else:
            if sanitizar_e_ordenar_dat(ARQ_ACES_DAT, TAMANHO_REGISTRO_ACESSO, True):
                print("[+] Ordenação e integridade das chaves de 'acessos.dat' reparadas automaticamente.")
                indice_acessos = reconstruir_indice_parcial(ARQ_ACES_DAT, ARQ_ACES_IDX, TAMANHO_REGISTRO_ACESSO, True)
                reconstruir_indice_exaustivo_acessos_prod()
            construir_tabela_hash_acessos()

    while True:
        print("\n==================================================================")
        print("   ORGANIZAÇÃO SEQUENCIAL-INDEXADA + ÁRVORE B+ E TABELA HASH      ")
        print("==================================================================")
        print("1. Criptografar arquivos .dat (do Trabalho I) e gerar índices")
        print("2. Mostrar dados (Parcial ou Total)")
        print("3. Pesquisa Binária DIRETA no arquivo de dados (.dat)")
        print("4. Consulta por ÍNDICE EM ARQUIVO (.idx)")
        print("5. Consulta por ÍNDICE EM MEMÓRIA (Árvore B+ / Tabela Hash)")
        print("6. Inserir novo registro (atualiza índices em disco e RAM)")
        print("7. Remover registro (atualiza índices em disco e RAM)")
        print("8. Perguntas Analíticas (Trabalho I)")
        print("9. Executar Benchmark Comparativo (Arquivo vs Memória)")
        print("10. Comprimir / Descomprimir arquivos de dados (.zlib)")
        print("0. Sair do programa")
        print("------------------------------------------------------------------")

        opcao = input("Escolha uma opção: ").strip()

        if opcao == "0":
            print("\n[+] Salvando índices em arquivo e encerrando...")
            salvar_indice_parcial(ARQ_PROD_IDX, indice_produtos)
            salvar_indice_parcial(ARQ_ACES_IDX, indice_acessos)
            break

        elif opcao == "1":
            criptografar_arquivos_dat_existentes()

        elif opcao in ["2", "3", "4", "6", "7"]:
            print("\nSelecione a base:")
            print("  1. Produtos (produtos.dat)")
            print("  2. Acessos  (acessos.dat)")
            sel_base = input("Escolha (1 ou 2): ").strip()

            tipo_base = "produto" if sel_base == "1" else "acesso" if sel_base == "2" else None
            if not tipo_base:
                print("[!] Opção inválida!")
                continue

            arq_dat = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
            tam_rec = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO
            parser = desformatar_produto if tipo_base == "produto" else desformatar_acesso
            ind_ram = indice_produtos if tipo_base == "produto" else indice_acessos
            cript = arquivo_criptografado[tipo_base]

            if opcao == "2":
                inicio = int(input("Índice inicial (padrão 0): ") or "0")
                qtd = int(input("Quantidade a exibir (padrão 10): ") or "10")
                mostrar_dados(arq_dat, tam_rec, parser, cript, inicio, qtd)

            elif opcao == "3":
                target = int(input(f"ID do {tipo_base}: "))
                res = pesquisa_binaria_direta(arq_dat, target, tam_rec, parser, cript)
                if res:
                    print("    Dados:", res)

            elif opcao == "4":
                if tipo_base == "produto":
                    target = int(input("ID do produto (chave): "))
                    res, _ = consultar_por_indice_arquivo(arq_dat, ind_ram, target, tam_rec, parser, cript)
                    if res:
                        print("    Dados:", res)
                else:
                    print("  1. Buscar acesso por event_id (índice parcial acessos.idx)")
                    print("  2. Buscar acessos por product_id (índice exaustivo acessos_prod.idx)")
                    sub = input("Escolha (1 ou 2): ").strip()
                    if sub == "1":
                        target = int(input("event_id: "))
                        res, _ = consultar_por_indice_arquivo(arq_dat, ind_ram, target, tam_rec, parser, cript)
                        if res:
                            print("    Dados:", res)
                    elif sub == "2":
                        target_prod = int(input("product_id: "))
                        res_lista, _ = consultar_acessos_por_produto_arquivo(target_prod)
                        for item in res_lista[:10]:
                            print("   ", item)

            elif opcao == "6":
                target_id = int(input(f"Novo ID do {tipo_base}: "))
                if tipo_base == "produto":
                    brand = input("Marca (brand): ")
                    price = float(input("Preço (price): "))
                    cat = input("Categoria: ")
                    novo_bytes = formatar_produto(target_id, brand, price, cat, cript)
                else:
                    e_type = input("Tipo de evento (view, cart, purchase): ")
                    p_id = int(input("ID do produto relacionado: "))
                    u_id = int(input("ID do usuário: "))
                    novo_bytes = formatar_acesso(target_id, e_type, p_id, u_id, cript)
                inserir_registro(tipo_base, novo_bytes, target_id)

            elif opcao == "7":
                target_id = int(input(f"ID do {tipo_base} a REMOVER: "))
                remover_registro_logico(tipo_base, target_id)

        elif opcao == "5":
            print("\n--- CONSULTA POR ÍNDICE EM MEMÓRIA ---")
            print("  1. Buscar Produto por product_id (Árvore B+)")
            print("  2. Buscar Acessos por product_id (Tabela Hash)")
            sub_mem = input("Escolha (1 ou 2): ").strip()
            if sub_mem == "1":
                pid = int(input("Digite o product_id: "))
                res, _ = consultar_produto_arvore_b_mais(pid)
                if res:
                    print("    Dados:", res)
            elif sub_mem == "2":
                pid = int(input("Digite o product_id: "))
                res_lista, _ = consultar_acessos_por_produto_hash(pid)
                for item in res_lista[:10]:
                    print("   ", item)
                if len(res_lista) > 10:
                    print(f"    ... e mais {len(res_lista) - 10} registros.")

        elif opcao == "8":
            print("\n--- PERGUNTAS ANALÍTICAS ---")
            print("1. Marca com maior número de produtos cadastrados")
            print("2. Tipo de evento mais frequente")
            print("3. Produto de maior valor (preço mais alto)")
            sub_op = input("Escolha (1, 2 ou 3): ").strip()
            if sub_op == "1":
                pergunta_marca_mais_produtos()
            elif sub_op == "2":
                pergunta_evento_mais_frequente()
            elif sub_op == "3":
                pergunta_produto_maior_preco()

        elif opcao == "9":
            executar_benchmark_comparativo()

        elif opcao == "10":
            print("\n  1. Comprimir arquivos .dat (.zlib)")
            print("  2. Descomprimir arquivos .dat.zlib")
            sub_c = input("Escolha (1 ou 2): ").strip()
            if sub_c == "1":
                comprimir_arquivos_dados()
            elif sub_c == "2":
                descomprimir_arquivos_dados()

        else:
            print("\n[!] Opção inválida.")


if __name__ == "__main__":
    menu_principal()