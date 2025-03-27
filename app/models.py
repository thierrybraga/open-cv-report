import sqlite3
import os
import logging
from functools import lru_cache
from logging.handlers import RotatingFileHandler

# Configuração básica do logger com rotação de arquivos
log_handler = RotatingFileHandler('vulnerabilities.log', maxBytes=10*1024*1024, backupCount=3)
log_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_handler.setFormatter(formatter)
logging.getLogger().addHandler(log_handler)

DATABASE_FILE = os.path.join(os.path.dirname(__file__), "vulnerabilities.db")

def get_connection():
    """Retorna uma conexão com o banco de dados SQLite."""
    return sqlite3.connect(DATABASE_FILE)

def create_table():
    """Cria a tabela 'vulnerabilities' no banco de dados, se não existir."""
    with get_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                baseSeverity TEXT,
                cvssScore REAL,
                reference_links TEXT,
                vendor TEXT,
                risks TEXT
            )
        ''')

def validate_vulnerability(vuln):
    """Valida e normaliza os dados da vulnerabilidade."""
    required_keys = ['cve_id', 'description', 'published_date', 'baseSeverity', 'cvssScore', 'references', 'vendor']
    missing_keys = [key for key in required_keys if key not in vuln]
    if missing_keys:
        logging.error(f"Chaves faltando na vulnerabilidade: {', '.join(missing_keys)}")
        return None

    try:
        vuln['cvssScore'] = float(vuln['cvssScore'])
    except (ValueError, TypeError):
        logging.error(f"Valor inválido para cvssScore em vulnerabilidade: {vuln}")
        return None

    # Verifique o formato de data, caso necessário
    try:
        from datetime import datetime
        datetime.strptime(vuln['published_date'], "%Y-%m-%d")  # Validação de formato de data
    except ValueError:
        logging.error(f"Formato de data inválido: {vuln['published_date']}")
        return None

    return vuln

def check_cve_exists(conn, cve_id):
    """Verifica se um CVE já existe no banco de dados."""
    cursor = conn.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    return cursor.fetchone() is not None

def get_cve(conn, cve_id):
    """Obtém uma vulnerabilidade (CVE) do banco de dados."""
    cursor = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    if row:
        return {
            "cve_id": row[0],
            "description": row[1],
            "published_date": row[2],
            "baseSeverity": row[3],
            "cvssScore": row[4],
            "reference_links": row[5],
            "vendor": row[6],
            "risks": row[7]
        }
    return None

def update_cve(conn, cve):
    """Atualiza uma vulnerabilidade existente no banco de dados."""
    conn.execute('''
        UPDATE vulnerabilities
        SET description = ?, published_date = ?, baseSeverity = ?, cvssScore = ?, 
            reference_links = ?, vendor = ?, risks = ?
        WHERE cve_id = ?
    ''', (
        cve['description'],
        cve['published_date'],
        cve['baseSeverity'],
        cve['cvssScore'],
        ', '.join(cve['references']),
        cve['vendor'],
        cve.get('risks', None),
        cve['cve_id']
    ))

@lru_cache(maxsize=128)
def get_cve_cached(conn, cve_id):
    """Obtém uma vulnerabilidade (CVE) com cache."""
    return get_cve(conn, cve_id)

def populate_database(data):
    """Popula o banco de dados com dados de vulnerabilidades."""
    try:
        with get_connection() as conn:
            conn.execute("BEGIN TRANSACTION;")
            for vuln in data.get('vulnerabilities', []):
                vuln = validate_vulnerability(vuln)
                if vuln is None:
                    continue  # Pula vulnerabilidades com dados inválidos

                cve_id = vuln['cve_id']
                if not check_cve_exists(conn, cve_id):
                    conn.execute('''
                        INSERT INTO vulnerabilities (
                            cve_id, description, published_date, baseSeverity, cvssScore, 
                            reference_links, vendor, risks
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        vuln['description'],
                        vuln['published_date'],
                        vuln['baseSeverity'],
                        vuln['cvssScore'],
                        ', '.join(vuln['references']),
                        vuln['vendor'],
                        vuln.get('risks', None)
                    ))
                    logging.info(f"CVE {cve_id} inserido no banco.")
                else:
                    existing = get_cve_cached(conn, cve_id)
                    if existing and (existing["baseSeverity"] != vuln['baseSeverity'] or existing["cvssScore"] != vuln['cvssScore']):
                        update_cve(conn, vuln)
                        logging.info(f"CVE {cve_id} atualizado no banco.")
            conn.execute("COMMIT;")
    except sqlite3.Error as e:
        logging.error(f"Erro ao popular banco de dados: {e}")

def get_latest_cve_date(vendor):
    """Obtém a última data de CVE para um fornecedor específico."""
    try:
        with get_connection() as conn:
            cursor = conn.execute('''
                SELECT MAX(published_date) FROM vulnerabilities
                WHERE vendor = ? AND published_date >= '2024-01-01'
            ''', (vendor,))
            result = cursor.fetchone()[0]
            return result
    except sqlite3.Error as e:
        logging.error(f"Erro ao obter última data de CVE para fornecedor ({vendor}): {e}")
        return None

# Exemplo de uso:
if __name__ == "__main__":
    create_table()
    # Suponha que 'data' seja um dicionário contendo a lista de vulnerabilidades
    # data = {"vulnerabilities": [...]}
    # populate_database(data)
