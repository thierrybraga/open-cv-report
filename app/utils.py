import logging
import requests
import json
import time
from .models import populate_database, check_cve_exists, get_latest_cve_date, get_cve, update_cve
from apscheduler.schedulers.background import BackgroundScheduler
from .TARGET_PRODUCTS import TARGET_PRODUCTS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')


def fetch_nvd_cves(vendor, last_updated):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")
            description = next(
                (desc["value"] for desc in cve_data.get("descriptions", []) if desc["lang"] == "en"),
                "N/A"
            )
            published_date = cve_data.get("published", "N/A")
            references = [ref["url"] for ref in cve_data.get("references", [])]
            cvss_metrics = cve_data.get("metrics", {})

            base_severity = "N/A"
            cvss_score = "N/A"

            if "cvssMetricV2" in cvss_metrics:
                base_severity = cvss_metrics["cvssMetricV2"][0]["baseSeverity"]
                cvss_score = cvss_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in cvss_metrics:
                base_severity = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                cvss_score = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV31" in cvss_metrics:
                base_severity = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                cvss_score = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV40" in cvss_metrics:
                base_severity = cvss_metrics["cvssMetricV40"][0]["cvssData"]["baseSeverity"]
                cvss_score = cvss_metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]

            # Validação de data publicada após a última atualização
            if published_date and (published_date <= last_updated or int(published_date[:4]) < 2024):
                continue

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "published_date": published_date,
                "baseSeverity": base_severity,
                "cvssScore": cvss_score,
                "references": references,
                "vendor": vendor
            })

        return cves

    except requests.exceptions.RequestException as err:
        logging.error(f"Erro ao acessar NVD para {vendor}: {err}")
        return []
    except json.decoder.JSONDecodeError:
        logging.error(f"Erro ao decodificar JSON da resposta da NVD para {vendor}.")
        return []


def update_vulnerabilities():
    for vendor in TARGET_PRODUCTS:
        logging.info(f"Iniciando busca de CVEs para o vendor: {vendor}")

        last_updated = get_latest_cve_date(vendor)
        if not last_updated:
            last_updated = "2024-01-01T00:00:00"

        vendor_cves = fetch_nvd_cves(vendor, last_updated)

        new_cves = []
        for cve in vendor_cves:
            exists = check_cve_exists(cve["cve_id"])
            if not exists:
                new_cves.append(cve)
            else:
                existing = get_cve(cve["cve_id"])
                if existing and (
                        existing["baseSeverity"] != cve["baseSeverity"] or existing["cvssScore"] != cve["cvssScore"]):
                    update_cve(cve)
                    logging.info(f"CVE atualizado: {cve['cve_id']}")

        if new_cves:
            populate_database({"vulnerabilities": new_cves})
            logging.info(f"Novas CVEs inseridas para o vendor {vendor}: {len(new_cves)}")

        logging.info(f"Aguardando 15 segundos para evitar limite de rate da API do NVD...")
        time.sleep(15)

    logging.info("Banco de dados atualizado com sucesso!")


def schedule_update():
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_vulnerabilities, 'interval', hours=24)
    scheduler.start()
    logging.info("Agendamento diário configurado com sucesso.")
