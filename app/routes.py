import io
import sqlite3
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from flask import Blueprint, render_template, request, send_file, jsonify, redirect
from .LLMReport import create_pdf_in_memory

TARGET_PRODUCTS = [
    "Palo Alto Networks", "Fortinet", "Check Point Software Technologies",
    "Meraki", "Sophos", "Juniper Networks", "Barracuda Networks",
    "Forcepoint", "Huawei", "SonicWall", "WatchGuard",
    "Versa Networks", "Cato Networks", "Trend Micro", "Hillstone Networks"
]

# Configure logging for debugging purposes
logging.basicConfig(level=logging.DEBUG)

main_blueprint = Blueprint('main', __name__)
db_path = os.path.join(os.path.dirname(__file__), "vulnerabilities.db")


def safe_float(value: Any) -> float:
    """Safely converts a value to float; returns 0.0 on failure."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


class Database:
    """SQLite database abstraction for vulnerability operations."""
    def __init__(self, db_name: str) -> None:
        self.db_name = db_name

    def get_connection(self) -> sqlite3.Connection:
        """Returns a database connection with rows accessible by column name."""
        try:
            conn = sqlite3.connect(self.db_name)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logging.exception("Error connecting to database: %s", e)
            raise

    def _execute_query(self, query: str, params: List[Any]) -> List[sqlite3.Row]:
        """Executes a SQL query with parameters and returns the results."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, tuple(params))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.exception("Error executing query: %s", e)
            return []

    def fetch_vulnerabilities(
        self,
        year: Optional[str] = None,
        vendor: Optional[str] = None,
        severity: Optional[str] = None,
        page: Optional[int] = None,
        items_per_page: Optional[int] = None,
    ) -> List[sqlite3.Row]:
        """
        Fetches vulnerabilities from the database based on provided filters.
        Applies pagination if no specific filter is provided.
        """
        query = """
            SELECT cve_id, description, published_date, baseSeverity, cvssScore, reference_links, vendor
            FROM vulnerabilities WHERE 1=1
        """
        params: List[Any] = []

        if year:
            query += " AND published_date LIKE ?"
            params.append(f"{year}%")
        if vendor:
            query += " AND vendor = ?"
            params.append(vendor)
        if severity:
            query += " AND lower(baseSeverity) = ?"
            params.append(severity.lower())

        # Apply pagination when no filter is provided
        if not (year or vendor or severity) and page is not None and items_per_page is not None:
            query += " LIMIT ? OFFSET ?"
            offset = (page - 1) * items_per_page
            params.extend([items_per_page, offset])

        return self._execute_query(query, params)

    def _fetch_distinct(self, cursor: sqlite3.Cursor, column: str) -> List[str]:
        """Returns distinct values for a specific column."""
        cursor.execute(f"SELECT DISTINCT {column} FROM vulnerabilities")
        return [row[0] for row in cursor.fetchall()]

    def fetch_filters(self) -> Tuple[List[str], List[str]]:
        """
        Retrieves available filters: vendors and severities.
        The vendors list is overridden by the TARGET_PRODUCTS constant.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                severities = self._fetch_distinct(cursor, "baseSeverity")
            return TARGET_PRODUCTS, severities
        except Exception as e:
            logging.exception("Error fetching filters: %s", e)
            return TARGET_PRODUCTS, []

    def fetch_vulnerability_by_id(self, cve_id: str) -> Optional[sqlite3.Row]:
        """Fetches a specific vulnerability by its CVE ID."""
        query = """
            SELECT cve_id, description, risks, vendor, reference_links, baseSeverity, published_date
            FROM vulnerabilities WHERE cve_id = ?
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (cve_id,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            logging.exception("Error fetching vulnerability %s: %s", cve_id, e)
            return None


def serialize_vulnerability(vuln: sqlite3.Row) -> Dict[str, Any]:
    return {
        "CVE ID": vuln["cve_id"],
        "Description": vuln["description"],
        "Published Date": vuln["published_date"],
        "Severity": vuln["baseSeverity"],
        "CVSS Score": vuln["cvssScore"],
        "reference_links": vuln["reference_links"],  # Alterado para "reference_links"
        "Vendor": vuln["vendor"],
    }



@main_blueprint.route('/api/vulnerabilities', methods=['GET'])
def api_vulnerabilities() -> Any:
    """
    Returns vulnerabilities as JSON with applied filters.
    Supports pagination if no specific filter is provided.
    """
    year = request.args.get('year')
    vendor_filter = request.args.get('vendor')
    severity = request.args.get('severity')
    page = request.args.get('page', type=int)
    items_per_page = request.args.get('items_per_page', type=int)

    try:
        db = Database(db_path)
        vulnerabilities = db.fetch_vulnerabilities(year, vendor_filter, severity, page, items_per_page)
        processed_vulns = [serialize_vulnerability(v) for v in vulnerabilities]
        _, severities = db.fetch_filters()

        return jsonify({
            "vulnerabilities": processed_vulns,
            "totalVulnerabilities": len(processed_vulns),
            "vendors": TARGET_PRODUCTS,
            "severities": severities,
        })
    except Exception as e:
        logging.exception("Error fetching vulnerabilities: %s", e)
        return jsonify({"error": "Error accessing vulnerabilities"}), 500


@main_blueprint.route('/generate_report', methods=['GET'])
def generate_report() -> Any:
    """Generates and returns a PDF report for a specific vulnerability."""
    cve_id = request.args.get('cve_id')
    if not cve_id:
        return "CVE ID not provided.", 400

    try:
        db = Database(db_path)
        data = db.fetch_vulnerability_by_id(cve_id)
        if data:
            pdf_data = create_pdf_in_memory(data)
            return send_file(
                io.BytesIO(pdf_data),
                as_attachment=True,
                download_name=f"relatorio_vulnerabilidade_{cve_id}.pdf",
                mimetype="application/pdf"
            )
        else:
            return "CVE ID not found.", 404
    except Exception as e:
        logging.exception("Error generating report for %s: %s", cve_id, e)
        return "Error generating report.", 500


@main_blueprint.route('/analytics', methods=['GET'])
def analytics() -> Any:
    """Renders the Analytics page."""
    return render_template('analytics.html')

@main_blueprint.route('/contact', methods=['GET'])
def contact() -> Any:
    """Renders the contact page."""
    return render_template('contact.html')


@main_blueprint.route('/api/cves', methods=['GET'])
def api_get_cves() -> Any:
    """
    Returns processed vulnerability data for the dashboard in JSON format.
    The vendors list is replaced with TARGET_PRODUCTS.
    """
    vendor_filter = request.args.get('vendor', '')
    db = Database(db_path)

    try:
        vulnerabilities = db.fetch_vulnerabilities(vendor=vendor_filter)
        data = process_vulnerability_data(vulnerabilities)
        data["vendors"] = TARGET_PRODUCTS
        return jsonify(data)
    except Exception as e:
        logging.exception("Error fetching dashboard data: %s", e)
        return jsonify({"error": "Error accessing dashboard data"}), 500


def process_vulnerability_data(vulnerabilities: List[sqlite3.Row]) -> Dict[str, Any]:
    """
    Processes vulnerability data into the format expected by the dashboard.
    Computes statistics such as average CVSS score, severity distribution,
    histogram bins for CVSS scores, and daily CVE history.
    """
    total_vulnerabilities = len(vulnerabilities)
    avg_cvss_score = (
        sum(safe_float(vuln["cvssScore"]) for vuln in vulnerabilities) / total_vulnerabilities
        if total_vulnerabilities else 0
    )
    severity_distribution = count_severity(vulnerabilities)
    top_vendors = count_top_vendors(vulnerabilities)
    cvss_bins = [0, 0, 0, 0, 0]

    for vuln in vulnerabilities:
        score = safe_float(vuln["cvssScore"])
        if score <= 2:
            cvss_bins[0] += 1
        elif score <= 4:
            cvss_bins[1] += 1
        elif score <= 6:
            cvss_bins[2] += 1
        elif score <= 8:
            cvss_bins[3] += 1
        else:
            cvss_bins[4] += 1

    # Build CVE history per day (formatted as YYYY-MM-DD)
    history: Dict[str, int] = {}
    for vuln in vulnerabilities:
        date_str = vuln["published_date"][:10]
        history[date_str] = history.get(date_str, 0) + 1
    sorted_dates = sorted(history.keys())
    history_labels = sorted_dates
    history_data = [history[date] for date in sorted_dates]

    return {
        "totalVulnerabilities": total_vulnerabilities,
        "avgCvssScore": avg_cvss_score,
        "severity": severity_distribution,
        "topVendors": top_vendors,
        "vendors": TARGET_PRODUCTS,
        "cvssScoreDistribution": cvss_bins,
        "cveHistoryLabels": history_labels,
        "cveHistoryData": history_data
    }


def count_severity(vulnerabilities: List[sqlite3.Row]) -> Dict[str, int]:
    """Counts the distribution of vulnerability severities."""
    return {
        "low": sum(1 for vuln in vulnerabilities if vuln["baseSeverity"].lower() == "low"),
        "medium": sum(1 for vuln in vulnerabilities if vuln["baseSeverity"].lower() == "medium"),
        "high": sum(1 for vuln in vulnerabilities if vuln["baseSeverity"].lower() == "high"),
        "critical": sum(1 for vuln in vulnerabilities if vuln["baseSeverity"].lower() == "critical"),
    }


def count_top_vendors(vulnerabilities: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    """Counts the number of vulnerabilities per vendor."""
    vendor_set = {vuln["vendor"] for vuln in vulnerabilities}
    return [
        {"name": vendor, "quantity": sum(1 for vuln in vulnerabilities if vuln["vendor"] == vendor)}
        for vendor in vendor_set
    ]


@main_blueprint.route('/', methods=['GET'])
def index() -> Any:
    """
    Renders the main page with filters and a list of vulnerabilities.
    Data is processed and passed to the 'index.html' template.
    """
    year = request.args.get('year')
    vendor_filter = request.args.get('vendor')
    severity = request.args.get('severity')

    try:
        db = Database(db_path)
        vulnerabilities = db.fetch_vulnerabilities(year, vendor_filter, severity)
        processed_vulns = format_vulnerabilities(vulnerabilities)
        _, severities = db.fetch_filters()
        return render_template('index.html', vulnerabilities=processed_vulns, vendors=TARGET_PRODUCTS, severities=severities)
    except Exception as e:
        logging.exception("Error fetching vulnerabilities for the homepage: %s", e)
        return "Error loading the homepage.", 500


def format_vulnerabilities(vulnerabilities: List[sqlite3.Row]) -> List[Dict[str, Any]]:
    """Formats vulnerability rows for display on the main page."""
    return [serialize_vulnerability(v) for v in vulnerabilities]


@main_blueprint.route('/redirect_reference', methods=['GET'])
def redirect_reference() -> Any:
    """
    Redirects to a reference URL provided via the 'link' parameter.
    Prepends 'http://' if the link does not start with it.
    """
    link = request.args.get('link', '')
    if link and not link.startswith('http'):
        link = 'http://' + link
    if link:
        return redirect(link)
    return "Invalid link", 400
