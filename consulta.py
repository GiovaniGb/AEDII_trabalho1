import bisect
import os
import shutil
import time

# ==============================================================================
# CONFIGURAÇÕES GERAIS E CONSTANTES
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

# Arquivos originais (somente leitura na Opção 1)
ARQ_PROD_ORIG = "produtos.dat"
ARQ_ACES_ORIG = "acessos.dat"

# Cópias criptografadas e seus respectivos índices em disco
ARQ_PROD_DAT = "produtos_criptografado.dat"
ARQ_PROD_IDX = "produtos_criptografado.idx"
ARQ_ACES_DAT = "acessos_criptografado.dat"
ARQ_ACES_IDX = "acessos_criptografado.idx"
ARQ_ACES_PROD_IDX = "acessos_criptografado_prod.idx"

# Estruturas em memória RAM
indice_produtos = []
indice_acessos = []
arvore_b_mais_produtos = None
tabela_hash_acessos = None


# ==============================================================================
# CRIPTOGRAFIA SIMÉTRICA DE TAMANHO FIXO
# ==============================================================================
def criptografar_payload(dados: bytes) -> bytes:
    """Criptografa bytes preservando o tamanho fixo e evitando '\\n' (10) e '*' (42)."""
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
    return criptografar_payload(registro_plano[:-1]) + b"\n"


def descriptografar_registro(registro_cifrado: bytes) -> bytes:
    return descriptografar_payload(registro_cifrado[:-1]) + b"\n"


def extrair_chave_registro(reg_bytes: bytes) -> str:
    """Descriptografa e retorna a chave primária (10 bytes), ou '*' se removido."""
    if reg_bytes.startswith(b"*"):
        return "*"
    raw_chave = descriptografar_payload(reg_bytes[:TAMANHO_CHAVE])
    chave = raw_chave.decode("utf-8", errors="replace")
    if chave.startswith("*"):
        return "*"
    return chave


def criar_copias_criptografadas():
    """Gera cópias criptografadas dos arquivos originais e reconstrói todos os índices."""
    global indice_produtos, indice_acessos

    bases = [
        ("Produtos", ARQ_PROD_ORIG, ARQ_PROD_DAT, TAMANHO_REGISTRO_PRODUTO),
        ("Acessos", ARQ_ACES_ORIG, ARQ_ACES_DAT, TAMANHO_REGISTRO_ACESSO),
    ]

    encontrados = [orig for _, orig, _, _ in bases if os.path.exists(orig)]
    if not encontrados:
        print(f"\n[!] Erro: Arquivos originais '{ARQ_PROD_ORIG}' e '{ARQ_ACES_ORIG}' não encontrados.")
        return False

    print("\n==================================================================")
    print("  GERANDO CÓPIAS CRIPTOGRAFADAS                                   ")
    print("==================================================================")

    for nome, arq_orig, arq_dest, tam_reg in bases:
        if not os.path.exists(arq_orig):
            print(f"[!] Aviso: Original '{arq_orig}' não encontrado, pulando...")
            continue

        t0 = time.perf_counter()
        tam_payload = tam_reg - 1
        total_regs = 0

        with open(arq_orig, "rb") as f_in, open(arq_dest, "wb") as f_out:
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

        dt_ms = (time.perf_counter() - t0) * 1000
        print(f"[+] {nome}: '{arq_orig}' (intacto) -> '{arq_dest}'")
        print(f"    Registros: {total_regs:,} | Tamanho: {os.path.getsize(arq_dest):,} bytes | Tempo: {dt_ms:.2f} ms".replace(",", "."))

    print("\n[->] Gerando arquivos de índices em disco (.idx) para as cópias criptografadas...")
    if os.path.exists(ARQ_PROD_DAT):
        indice_produtos = reconstruir_indice_parcial(ARQ_PROD_DAT, ARQ_PROD_IDX, TAMANHO_REGISTRO_PRODUTO)
        print(f"[+] '{ARQ_PROD_IDX}' gerado ({len(indice_produtos):,} blocos).".replace(",", "."))

    if os.path.exists(ARQ_ACES_DAT):
        indice_acessos = reconstruir_indice_parcial(ARQ_ACES_DAT, ARQ_ACES_IDX, TAMANHO_REGISTRO_ACESSO)
        reconstruir_indice_exaustivo_acessos_prod()
        print(f"[+] '{ARQ_ACES_IDX}' ({len(indice_acessos):,} blocos) e '{ARQ_ACES_PROD_IDX}' (exaustivo) gerados.".replace(",", "."))

    if os.path.exists(ARQ_PROD_DAT):
        construir_arvore_b_mais_produtos()
    if os.path.exists(ARQ_ACES_DAT):
        construir_tabela_hash_acessos()

    return True


# ==============================================================================
# FORMATADORES E PARSERS DE REGISTROS
# ==============================================================================
def formatar_produto(p_id: int, brand: str, price: float, category: str) -> bytes:
    p_id_str = f"{int(p_id):010d}"
    brand_str = f"{brand[:20]:<20}"
    price_str = f"{float(price):010.2f}"
    cat_str = f"{category[:30]:<30}"
    plano = f"{p_id_str}{brand_str}{price_str}{cat_str}\n".encode("utf-8")
    return criptografar_registro(plano)


def desformatar_produto(registro_bytes: bytes) -> dict:
    plano = descriptografar_registro(registro_bytes)
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
        "category_code": texto[40:70].strip(),
    }


def formatar_acesso(e_id: int, e_type: str, p_id: int, u_id: int) -> bytes:
    e_id_str = f"{int(e_id):010d}"
    e_type_str = f"{e_type[:12]:<12}"
    p_id_str = f"{int(p_id):010d}"
    u_id_str = f"{int(u_id):010d}"
    plano = f"{e_id_str}{e_type_str}{p_id_str}{u_id_str}\n".encode("utf-8")
    return criptografar_registro(plano)


def desformatar_acesso(registro_bytes: bytes) -> dict:
    plano = descriptografar_registro(registro_bytes)
    texto = plano.decode("utf-8", errors="replace")
    return {
        "event_id": texto[0:10].strip(),
        "event_type": texto[10:22].strip(),
        "product_id": texto[22:32].strip(),
        "user_id": texto[32:42].strip(),
    }


# ==============================================================================
# ÍNDICES EM MEMÓRIA RAM: ÁRVORE B+ E TABELA HASH
# ==============================================================================
class NoBMais:
    def __init__(self, folha: bool = False):
        self.folha = folha
        self.chaves = []
        self.valores = []    # Folhas: offsets no .dat | Internos: nós filhos
        self.proximo = None  # Encadeamento sequencial entre folhas


class ArvoreBMais:
    """
    Índice em memória via Árvore B+ para produtos_criptografado.dat (chave: product_id).
    Ordem definida pelo tamanho de bloco/página (4096B / 32B = 128).
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
    Índice em memória via Tabela Hash para acessos_criptografado.dat (coluna não-chave: product_id).
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


def construir_arvore_b_mais_produtos() -> float:
    """Lê produtos_criptografado.dat em fluxo e constrói a Árvore B+ na RAM."""
    global arvore_b_mais_produtos
    if not os.path.exists(ARQ_PROD_DAT):
        print(f"\n[!] '{ARQ_PROD_DAT}' não encontrado. Execute a Opção 1 primeiro.")
        return 0.0

    t0 = time.perf_counter()
    arvore = ArvoreBMais(ordem=ORDEM_ARVORE_BMAIS)

    with open(ARQ_PROD_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_PRODUTO:
                break
            chave = extrair_chave_registro(reg_bytes)
            if not chave.startswith("*"):
                arvore.inserir(chave, offset_atual)

    arvore_b_mais_produtos = arvore
    tempo_ms = (time.perf_counter() - t0) * 1000
    print(f"\n[+] Árvore B+ ({ARQ_PROD_DAT}) construída em {tempo_ms:.3f} ms!")
    print(f"    Ordem: {arvore.ordem} (Bloco: {TAMANHO_PAGINA_BYTES}B) | Elementos: {arvore.total_elementos:,} | Altura: {arvore.altura()}".replace(",", "."))
    return tempo_ms


def construir_tabela_hash_acessos() -> float:
    """Lê acessos_criptografado.dat em fluxo e constrói a Tabela Hash sobre product_id."""
    global tabela_hash_acessos
    if not os.path.exists(ARQ_ACES_DAT):
        print(f"\n[!] '{ARQ_ACES_DAT}' não encontrado. Execute a Opção 1 primeiro.")
        return 0.0

    t0 = time.perf_counter()
    th = TabelaHash(capacidade=CAPACIDADE_TABELA_HASH)

    with open(ARQ_ACES_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_ACESSO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_ACESSO:
                break
            chave_primaria = extrair_chave_registro(reg_bytes)
            if not chave_primaria.startswith("*"):
                dados = desformatar_acesso(reg_bytes)
                th.inserir(dados["product_id"], offset_atual)

    tabela_hash_acessos = th
    tempo_ms = (time.perf_counter() - t0) * 1000
    fator_carga = th.total_chaves_unicas / th.capacidade
    print(f"\n[+] Tabela Hash ({ARQ_ACES_DAT} -> product_id) construída em {tempo_ms:.3f} ms!")
    print(f"    Buckets: {th.capacidade:,} | Chaves únicas: {th.total_chaves_unicas:,} | Acessos indexados: {th.total_registros_indexados:,}".replace(",", "."))
    print(f"    Colisões (Encadeamento Separado): {th.total_colisoes:,} | Fator de carga: {fator_carga:.2f}".replace(",", "."))
    return tempo_ms


# ==============================================================================
# MANIPULAÇÃO DE ÍNDICES EM DISCO (.IDX)
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


def reconstruir_indice_parcial(arq_dados: str, arq_indice: str, tamanho_registro: int) -> list:
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

            chave = extrair_chave_registro(reg_bytes)
            if not chave.startswith("*"):
                if registros_validos % INTERVALO_BLOCO_INDICE == 0:
                    novo_indice.append((chave, offset_atual))
                registros_validos += 1

    salvar_indice_parcial(arq_indice, novo_indice)
    return novo_indice


def reconstruir_indice_exaustivo_acessos_prod() -> float:
    """Atualiza o índice exaustivo secundário ordenado por product_id."""
    if not os.path.exists(ARQ_ACES_DAT):
        return 0.0

    t0 = time.perf_counter()
    entradas = []

    with open(ARQ_ACES_DAT, "rb") as f:
        while True:
            offset_atual = f.tell()
            reg_bytes = f.read(TAMANHO_REGISTRO_ACESSO)
            if not reg_bytes or len(reg_bytes) < TAMANHO_REGISTRO_ACESSO:
                break
            chave = extrair_chave_registro(reg_bytes)
            if not chave.startswith("*"):
                dados = desformatar_acesso(reg_bytes)
                entradas.append((dados["product_id"], offset_atual))

    entradas.sort(key=lambda x: x[0])
    with open(ARQ_ACES_PROD_IDX, "w", encoding="utf-8") as f_out:
        for prod_id, offset in entradas:
            f_out.write(f"{prod_id}:{offset}\n")

    return (time.perf_counter() - t0) * 1000


# ==============================================================================
# OPERAÇÕES DE LEITURA, CONSULTA, INSERÇÃO E REMOÇÃO
# ==============================================================================
def mostrar_dados(arq_dados: str, tamanho_registro: int, parser_fn, inicio: int, qtd: int):
    if not os.path.exists(arq_dados):
        print(f"\n[!] Erro: '{arq_dados}' não existe. Execute a Opção 1 para gerar a cópia criptografada.")
        return

    print(f"\n--- EXIBINDO REGISTROS DE '{arq_dados}' (Início: {inicio}, Qtd: {qtd}) ---")
    with open(arq_dados, "rb") as f:
        f.seek(inicio * tamanho_registro)
        lidos = 0
        while lidos < qtd:
            reg_bytes = f.read(tamanho_registro)
            if not reg_bytes or len(reg_bytes) < tamanho_registro:
                break

            chave = extrair_chave_registro(reg_bytes)
            if not chave.startswith("*"):
                dados = parser_fn(reg_bytes)
                print(f"[{inicio + lidos:06d}] {dados}")
            else:
                print(f"[{inicio + lidos:06d}] [REGISTRO REMOVIDO LOGICAMENTE]")
            lidos += 1


def _ler_registro_ativo_proximo(f, mid: int, low: int, high: int, tamanho_registro: int):
    """Localiza o registro ativo mais próximo quando o pivô da busca binária foi removido."""
    esq, dir_ = mid - 1, mid + 1
    while esq >= low or dir_ <= high:
        if esq >= low:
            f.seek(esq * tamanho_registro)
            r_esq = f.read(tamanho_registro)
            c_esq = extrair_chave_registro(r_esq)
            if c_esq != "*":
                return esq, c_esq, r_esq
            esq -= 1
        if dir_ <= high:
            f.seek(dir_ * tamanho_registro)
            r_dir = f.read(tamanho_registro)
            c_dir = extrair_chave_registro(r_dir)
            if c_dir != "*":
                return dir_, c_dir, r_dir
            dir_ += 1
    return -1, "*", b""


def pesquisa_binaria_direta(arq_dados: str, target_id: int, tamanho_registro: int, parser_fn):
    if not os.path.exists(arq_dados):
        print(f"\n[!] '{arq_dados}' não encontrado. Execute a Opção 1 primeiro.")
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
            chave_mid = extrair_chave_registro(reg_bytes)

            if chave_mid == "*":
                mid, chave_mid, reg_bytes = _ler_registro_ativo_proximo(
                    f, mid, low, high, tamanho_registro
                )
                if mid == -1:
                    break

            if chave_mid == target_str:
                dt_us = (time.perf_counter() - t0) * 1_000_000
                print(f"\n[+] Registro encontrado em '{arq_dados}' após {comparacoes} comparações ({dt_us:.2f} µs)!")
                return parser_fn(reg_bytes)
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[-] Registro ID {target_str} não encontrado em '{arq_dados}' após {comparacoes} comparações ({dt_us:.2f} µs).")
    return None


def consultar_por_indice_arquivo(arq_dados: str, indice_ram: list, target_id: int, tamanho_registro: int, parser_fn):
    """Consulta usando o índice parcial em arquivo (.idx) + seek() na cópia criptografada."""
    if not os.path.exists(arq_dados) or not indice_ram:
        print("\n[!] Erro: Cópia criptografada ou índice parcial não disponível. Execute a Opção 1.")
        return None

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
            chave_atual = extrair_chave_registro(reg_bytes)

            if chave_atual == target_str:
                dt_us = (time.perf_counter() - t0) * 1_000_000
                print(f"\n[+] Índice Arquivo: Encontrado em {dt_us:.2f} µs (Comp. idx: {comp_idx} | Comp. dat: {comp_dat})")
                return parser_fn(reg_bytes)
            elif chave_atual > target_str and not chave_atual.startswith("*"):
                break

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[-] Registro ID {target_str} não encontrado ({dt_us:.2f} µs).")
    return None


def consultar_produto_arvore_b_mais(target_id: int):
    """Consulta produto usando a Árvore B+ em memória + seek() em produtos_criptografado.dat."""
    if arvore_b_mais_produtos is None or not os.path.exists(ARQ_PROD_DAT):
        print("\n[!] Árvore B+ ou cópia criptografada não disponível. Execute a Opção 1.")
        return None

    t0 = time.perf_counter()
    target_str = f"{int(target_id):010d}"
    offset = arvore_b_mais_produtos.buscar(target_str)

    if offset is not None:
        with open(ARQ_PROD_DAT, "rb") as f:
            f.seek(offset)
            reg_bytes = f.read(TAMANHO_REGISTRO_PRODUTO)
            dados = desformatar_produto(reg_bytes)
        dt_us = (time.perf_counter() - t0) * 1_000_000
        print(f"\n[+] Árvore B+ (Memória): Encontrado no offset {offset} em {dt_us:.2f} µs!")
        return dados

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[-] Árvore B+ (Memória): ID {target_str} não encontrado ({dt_us:.2f} µs).")
    return None


def consultar_acessos_por_produto_arquivo(target_prod_id: int) -> list:
    """Consulta acessos de um product_id via índice exaustivo em arquivo."""
    if not os.path.exists(ARQ_ACES_PROD_IDX) or not os.path.exists(ARQ_ACES_DAT):
        print("\n[!] Índice exaustivo ou cópia criptografada não encontrado. Execute a Opção 1.")
        return []

    t0 = time.perf_counter()
    target_str = f"{int(target_prod_id):010d}"
    offsets = []

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
            if reg_bytes and not extrair_chave_registro(reg_bytes).startswith("*"):
                resultados.append(desformatar_acesso(reg_bytes))

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[+] Índice Arquivo ({ARQ_ACES_PROD_IDX}): {len(resultados)} acesso(s) encontrado(s) em {dt_us:.2f} µs!")
    return resultados


def consultar_acessos_por_produto_hash(target_prod_id: int) -> list:
    """Consulta acessos de um product_id via Tabela Hash em memória."""
    if tabela_hash_acessos is None or not os.path.exists(ARQ_ACES_DAT):
        print("\n[!] Tabela Hash ou cópia criptografada não disponível. Execute a Opção 1.")
        return []

    t0 = time.perf_counter()
    target_str = f"{int(target_prod_id):010d}"
    offsets = tabela_hash_acessos.buscar(target_str)

    resultados = []
    if offsets:
        with open(ARQ_ACES_DAT, "rb") as f_dat:
            for off in offsets:
                f_dat.seek(off)
                reg_bytes = f_dat.read(TAMANHO_REGISTRO_ACESSO)
                if reg_bytes and not extrair_chave_registro(reg_bytes).startswith("*"):
                    resultados.append(desformatar_acesso(reg_bytes))

    dt_us = (time.perf_counter() - t0) * 1_000_000
    print(f"\n[+] Tabela Hash (Memória): {len(resultados)} acesso(s) encontrado(s) em {dt_us:.2f} µs!")
    return resultados


def inserir_registro(tipo_base: str, novo_bytes: bytes, target_id: int) -> bool:
    """Insere registro ordenadamente na cópia criptografada e atualiza os índices."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == "produto" else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO

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

                chave_atual = extrair_chave_registro(reg_bytes)
                if chave_atual == target_str:
                    print(f"\n[!] Erro: Registro com ID {target_str} já existe em '{arq_dados}'.")
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
        indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
    else:
        indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
        reconstruir_indice_exaustivo_acessos_prod()
    dt_idx_ms = (time.perf_counter() - t0_idx) * 1000
    print(f"    [->] Índice em arquivo reconstruído em {dt_idx_ms:.3f} ms.")

    if tipo_base == "produto":
        construir_arvore_b_mais_produtos()
    else:
        construir_tabela_hash_acessos()
    return True


def remover_registro_logico(tipo_base: str, target_id: int) -> bool:
    """Marca o registro como removido ('*') na cópia criptografada e atualiza os índices."""
    global indice_produtos, indice_acessos

    arq_dados = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
    arq_indice = ARQ_PROD_IDX if tipo_base == "produto" else ARQ_ACES_IDX
    tamanho_registro = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO

    if not os.path.exists(arq_dados):
        print(f"\n[!] '{arq_dados}' não existe. Execute a Opção 1 primeiro.")
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
            chave_mid = extrair_chave_registro(reg_bytes)

            if chave_mid == "*":
                mid, chave_mid, reg_bytes = _ler_registro_ativo_proximo(
                    f, mid, low, high, tamanho_registro
                )
                if mid == -1:
                    break
                offset = mid * tamanho_registro

            if chave_mid == target_str:
                if tipo_base == "acesso":
                    dados_acesso_removido = desformatar_acesso(reg_bytes)
                f.seek(offset)
                f.write(b"*")
                f.flush()
                removido = True
                offset_removido = offset
                print(f"\n[-] Registro ID {target_str} removido logicamente em '{arq_dados}'.")
                break
            elif chave_mid < target_str:
                low = mid + 1
            else:
                high = mid - 1

    if removido:
        t0_idx = time.perf_counter()
        if tipo_base == "produto":
            indice_produtos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
        else:
            indice_acessos = reconstruir_indice_parcial(arq_dados, arq_indice, tamanho_registro)
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

    print(f"\n[-] Erro: Registro ID {target_str} não encontrado em '{arq_dados}'.")
    return False


# ==============================================================================
# MENU INTERATIVO
# ==============================================================================
def menu_principal():
    global indice_produtos, indice_acessos

    indice_produtos = carregar_indice_parcial(ARQ_PROD_IDX)
    indice_acessos = carregar_indice_parcial(ARQ_ACES_IDX)

    if os.path.exists(ARQ_PROD_DAT):
        if not indice_produtos:
            indice_produtos = reconstruir_indice_parcial(ARQ_PROD_DAT, ARQ_PROD_IDX, TAMANHO_REGISTRO_PRODUTO)
        construir_arvore_b_mais_produtos()
    else:
        print(f"\n[!] Cópia '{ARQ_PROD_DAT}' ainda não existe. Use a Opção 1 para criá-la a partir de '{ARQ_PROD_ORIG}'.")

    if os.path.exists(ARQ_ACES_DAT):
        if not indice_acessos:
            indice_acessos = reconstruir_indice_parcial(ARQ_ACES_DAT, ARQ_ACES_IDX, TAMANHO_REGISTRO_ACESSO)
        construir_tabela_hash_acessos()
    else:
        print(f"[!] Cópia '{ARQ_ACES_DAT}' ainda não existe. Use a Opção 1 para criá-la a partir de '{ARQ_ACES_ORIG}'.")

    while True:
        print("\n==================================================================")
        print("   ORGANIZAÇÃO SEQUENCIAL-INDEXADA + ÁRVORE B+ E TABELA HASH      ")
        print("==================================================================")
        print("1. Criar cópias criptografadas (*_criptografado.dat) e gerar índices")
        print("2. Mostrar dados")
        print("3. Pesquisa Binária DIRETA (.dat)")
        print("4. Consulta por ÍNDICE EM ARQUIVO (.idx)")
        print("5. Consulta por ÍNDICE EM MEMÓRIA (Árvore B+ / Tabela Hash)")
        print("6. Inserir novo registro")
        print("7. Remover registro")
        print("0. Sair do programa")
        print("------------------------------------------------------------------")

        opcao = input("Escolha uma opção: ").strip()

        try:
            if opcao == "0":
                print("\n[+] Salvando índices em arquivo e encerrando...")
                salvar_indice_parcial(ARQ_PROD_IDX, indice_produtos)
                salvar_indice_parcial(ARQ_ACES_IDX, indice_acessos)
                break

            elif opcao == "1":
                criar_copias_criptografadas()

            elif opcao in ["2", "3", "4", "6", "7"]:
                print("\nSelecione a base:")
                print(f"  1. Produtos ({ARQ_PROD_DAT})")
                print(f"  2. Acessos  ({ARQ_ACES_DAT})")
                sel_base = input("Escolha (1 ou 2): ").strip()

                tipo_base = "produto" if sel_base == "1" else "acesso" if sel_base == "2" else None
                if not tipo_base:
                    print("[!] Opção inválida!")
                    continue

                arq_dat = ARQ_PROD_DAT if tipo_base == "produto" else ARQ_ACES_DAT
                tam_rec = TAMANHO_REGISTRO_PRODUTO if tipo_base == "produto" else TAMANHO_REGISTRO_ACESSO
                parser = desformatar_produto if tipo_base == "produto" else desformatar_acesso
                ind_ram = indice_produtos if tipo_base == "produto" else indice_acessos

                if opcao == "2":
                    inicio = int(input("Índice inicial (padrão 0): ") or "0")
                    qtd = int(input("Quantidade a exibir (padrão 10): ") or "10")
                    mostrar_dados(arq_dat, tam_rec, parser, inicio, qtd)

                elif opcao == "3":
                    target = int(input(f"ID do {tipo_base}: "))
                    res = pesquisa_binaria_direta(arq_dat, target, tam_rec, parser)
                    if res:
                        print("    Dados:", res)

                elif opcao == "4":
                    if tipo_base == "produto":
                        target = int(input("ID do produto (chave): "))
                        res = consultar_por_indice_arquivo(arq_dat, ind_ram, target, tam_rec, parser)
                        if res:
                            print("    Dados:", res)
                    else:
                        print(f"  1. Buscar acesso por event_id (índice parcial {ARQ_ACES_IDX})")
                        print(f"  2. Buscar acessos por product_id (índice exaustivo {ARQ_ACES_PROD_IDX})")
                        sub = input("Escolha (1 ou 2): ").strip()
                        if sub == "1":
                            target = int(input("event_id: "))
                            res = consultar_por_indice_arquivo(arq_dat, ind_ram, target, tam_rec, parser)
                            if res:
                                print("    Dados:", res)
                        elif sub == "2":
                            target_prod = int(input("product_id: "))
                            res_lista = consultar_acessos_por_produto_arquivo(target_prod)
                            for item in res_lista[:10]:
                                print("   ", item)
                            if len(res_lista) > 10:
                                print(f"    ... e mais {len(res_lista) - 10} registros.")
                        else:
                            print("[!] Opção inválida!")

                elif opcao == "6":
                    target_id = int(input(f"Novo ID do {tipo_base}: "))
                    if tipo_base == "produto":
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
                    res = consultar_produto_arvore_b_mais(pid)
                    if res:
                        print("    Dados:", res)
                elif sub_mem == "2":
                    pid = int(input("Digite o product_id: "))
                    res_lista = consultar_acessos_por_produto_hash(pid)
                    for item in res_lista[:10]:
                        print("   ", item)
                    if len(res_lista) > 10:
                        print(f"    ... e mais {len(res_lista) - 10} registros.")
                else:
                    print("[!] Opção inválida!")

            else:
                print("\n[!] Opção inválida.")

        except ValueError:
            print("\n[!] Entrada inválida: informe um valor numérico válido.")


if __name__ == "__main__":
    menu_principal()