import logging
import asyncio
import aiohttp
import os
import sqlite3
import json


TARGET_PRODUCTS = [
    "Palo Alto Networks", "Fortinet", "Check Point Software Technologies",
    "Meraki", "Sophos"
]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Caminho para o banco de dados
DB_PATH = "vulnerabilities.db"

def initialize_database():
    """
    Verifica se o banco de dados existe.
    Caso não exista, cria o arquivo e a tabela 'vulnerabilities' com as colunas necessárias.
    """
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE vulnerabilities (
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
        conn.commit()
        conn.close()
        logging.info("Banco de dados criado com a tabela 'vulnerabilities'.")
    else:
        logging.info("Banco de dados já existe.")

def populate_database(data):
    """
    Insere os registros de vulnerabilidades no banco de dados.
    Espera um dicionário no formato: {"vulnerabilities": [lista de dicionários]}.
    Converte a lista de links de referência em string JSON para armazená-los.
    """
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        logging.info("Nenhum dado para inserir no banco de dados.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for vuln in vulnerabilities:
        # Converte a lista de reference_links em uma string JSON
        ref_links = json.dumps(vuln.get("reference_links", []))
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, description, published_date, baseSeverity, cvssScore, reference_links, vendor, risks
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.get("cve_id"),
                vuln.get("description"),
                vuln.get("published_date"),
                vuln.get("baseSeverity"),
                vuln.get("cvssScore"),
                ref_links,
                vuln.get("vendor"),
                vuln.get("risks")
            ))
        except Exception as e:
            logging.error(f"Erro ao inserir CVE {vuln.get('cve_id')}: {e}")

    conn.commit()
    conn.close()
    logging.info("Dados inseridos no banco de dados com sucesso.")

def verify_population():
    """
    Verifica quantos registros foram inseridos na tabela 'vulnerabilities'.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    count = cursor.fetchone()[0]
    conn.close()
    logging.info(f"O banco de dados contém {count} registros.")

# --- Cliente HTTP Assíncrono com Lógica de Re-tentativa ---
async def fetch_with_retry(session, url, headers, max_retries=3):
    retry_delays = [2 ** i for i in range(max_retries)]
    for attempt, delay in enumerate(retry_delays, 1):
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                response.raise_for_status()
                return await response.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.warning(f"Tentativa {attempt} falhou para a URL {url}: {e}")
            if attempt < max_retries:
                await asyncio.sleep(delay)
    raise Exception(f"Falha após {max_retries} tentativas para a URL: {url}")

# --- Função para buscar os CVEs via API NVD ---
async def fetch_nvd_cves(vendor, last_updated):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_with_retry(session, url, headers)
            cves = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                description = next(
                    (desc["value"] for desc in cve_data.get("descriptions", []) if desc.get("lang") == "en"),
                    "N/A"
                )
                published_date = cve_data.get("published", "N/A")
                
                # Filtra CVEs anteriores a 2024
                if int(published_date[:4]) < 2024:
                    continue

                reference_links = [ref["url"] for ref in cve_data.get("references", [])]
                cvss_metrics = cve_data.get("metrics", {})
                base_severity = "N/A"
                cvss_score = "N/A"

                for metric in ["cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"]:
                    if metric in cvss_metrics:
                        base_severity = cvss_metrics[metric][0]["cvssData"]["baseSeverity"]
                        cvss_score = cvss_metrics[metric][0]["cvssData"]["baseScore"]
                        break

                cves.append({
                    "cve_id": cve_id,
                    "description": description,
                    "published_date": published_date,
                    "baseSeverity": base_severity,
                    "cvssScore": cvss_score,
                    "reference_links": reference_links,
                    "vendor": vendor,
                    "risks": "N/A"  # Valor padrão para risks; ajuste conforme necessário
                })
            return cves
    except Exception as err:
        logging.error(f"Erro ao buscar CVEs para {vendor}: {err}")
        return []

# --- Função principal para coletar e inserir os dados ---
async def main():
    all_vulnerabilities = []
    default_last_updated = "2024-01-01T00:00:00"
    
    for vendor in TARGET_PRODUCTS:
        logging.info(f"Buscando CVEs para o vendor: {vendor}")
        vendor_cves = await fetch_nvd_cves(vendor, default_last_updated)
        if vendor_cves:
            all_vulnerabilities.extend(vendor_cves)
        else:
            logging.info(f"Nenhum CVE encontrado para {vendor}")
        await asyncio.sleep(1)  # Pausa para evitar sobrecarga na API

    if all_vulnerabilities:
        # Insere os dados no banco de dados
        populate_database({"vulnerabilities": all_vulnerabilities})
        logging.info(f"Inseridos {len(all_vulnerabilities)} CVEs no banco de dados.")
    else:
        logging.info("Nenhum CVE foi coletado para inserção.")
    
    # Verifica se o banco de dados foi populado corretamente
    verify_population()

if __name__ == "__main__":
    # Inicializa o banco de dados (caso não exista)
    initialize_database()
    # Executa a coleta e inserção dos dados
    asyncio.run(main())
