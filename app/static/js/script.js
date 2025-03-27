document.addEventListener("DOMContentLoaded", () => {
  // Função para formatar a data para DD/MM/AA
  const formatDate = (dateString) => {
    const dateObj = new Date(dateString);
    if (isNaN(dateObj)) return dateString; // Se a data não for válida, retorna a string original
    const day = ("0" + dateObj.getDate()).slice(-2); // Garante que o dia tenha dois dígitos
    const month = ("0" + (dateObj.getMonth() + 1)).slice(-2); // Garante que o mês tenha dois dígitos
    const year = dateObj.getFullYear().toString().slice(-2); // Retorna os dois últimos dígitos do ano
    return `${day}/${month}/${year}`;
  };

  // Função para gerar CSV a partir dos dados das vulnerabilidades
  const generateCSV = () => {
    const headers = ["CVE ID", "Descrição", "Data de Publicação", "Severidade", "Fornecedor", "CVSS Score"];
    const rows = filteredVulnerabilities.map(vuln => [
      vuln["CVE ID"],
      vuln["Description"],
      formatDate(vuln["Published Date"]),
      vuln["Severity"],
      vuln["Vendor"],
      vuln["CVSS Score"]
    ]);

    let csvContent = "data:text/csv;charset=utf-8," + headers.join(",") + "\n";
    rows.forEach(row => {
      csvContent += row.join(",") + "\n";
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "vulnerabilities_report.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Função para buscar os dados das vulnerabilidades da API
  const fetchCveData = async (vendor = '') => {
    try {
      const response = await fetch(`/api/vulnerabilities?vendor=${vendor}`);
      if (!response.ok) {
        throw new Error(`Erro na requisição: ${response.statusText}`);
      }
      const data = await response.json();
      updateDashboard(data);
    } catch (error) {
      console.error('Erro ao carregar dados da API:', error);
      alert("Erro ao carregar dados. Tente novamente mais tarde.");
    }
  };

  // Função para definir a cor da fonte conforme a severidade
  const getSeverityColor = (severity) => {
    if (!severity) return "";
    switch(severity.toLowerCase()){
      case "critical":
        return "text-danger";  // Vermelho
      case "high":
        return "text-danger";  // Vermelho (alta)
      case "medium":
        return "text-warning"; // Amarelo
      case "low":
        return "text-success"; // Verde
      default:
        return "";
    }
  };

  // Elementos DOM
  const vulnerabilityDataEl = document.getElementById("vulnData");
  const vulnerabilities = JSON.parse(vulnerabilityDataEl.textContent); // Dados das vulnerabilidades no formato JSON
  const itemsPerPage = 10;
  let currentPage = 1;
  let filteredVulnerabilities = [...vulnerabilities];

  const tableBody = document.getElementById("vulnTableBody");
  const paginationEl = document.getElementById("pagination");
  const generateReportBtn = document.getElementById("generateReportBtn");
  const yearFilterEl = document.getElementById("year");
  const vendorFilterEl = document.getElementById("vendor");
  const severityFilterEl = document.getElementById("severity");
  const clearFiltersBtn = document.getElementById("clearFiltersBtn");
  const loadingEl = document.getElementById("loading");

  // Função para ordenar as vulnerabilidades por data
  const sortByDate = (data) => {
    return data.sort((a, b) => {
      const dateA = new Date(a["Published Date"]);
      const dateB = new Date(b["Published Date"]);
      return dateB - dateA; // Ordena do mais recente para o mais antigo
    });
  };

  // Função para exibir a tabela de vulnerabilidades
  const displayTable = () => {
    tableBody.innerHTML = "";
    const startIdx = (currentPage - 1) * itemsPerPage;
    const pageData = filteredVulnerabilities.slice(startIdx, startIdx + itemsPerPage);

    if (pageData.length === 0) {
      const row = document.createElement("tr");
      row.innerHTML = `<td colspan="7" class="text-center">Nenhuma vulnerabilidade encontrada.</td>`;
      tableBody.appendChild(row);
    } else {
      pageData.forEach(vuln => {
        // const refLink = vuln["References"] ? vuln["References"].split(',')[0] : "#";
        const formattedDate = formatDate(vuln["Published Date"]);
        const severityColorClass = getSeverityColor(vuln["Severity"]);
        const refLinkRaw = vuln["References"]; // Pegamos o campo como está
        let refLink = "#"; // Valor padrão caso não tenha referência
        
        if (refLinkRaw) {
          try {
            const parsedLinks = JSON.parse(refLinkRaw.replace(/'/g, '"')); // Corrige aspas simples e converte para array
            refLink = parsedLinks.length > 0 ? parsedLinks[0] : "#"; // Pega o primeiro link
          } catch (error) {
            console.error("Erro ao processar link de referência:", error);
          }
        }        

        const row = document.createElement("tr");
        row.innerHTML = `
          <td><a href="${refLink}" target="_blank">${vuln["CVE ID"]}</a></td>
          <td>${vuln["Description"]}</td>
          <td>${formattedDate}</td>
          <td class="${severityColorClass}">${vuln["Severity"]}</td>
          <td>${vuln["Vendor"]}</td>
          <td>${vuln["CVSS Score"]}</td>
          <td>
            <button class="btn btn-success btn-sm" onclick="downloadReport('${vuln["CVE ID"]}')">
              <i class="fas fa-file-alt"></i> Gerar Relatório
            </button>
          </td>
        `;
        tableBody.appendChild(row);
      });
    }
    updatePagination();
  };

  // Função para atualizar a paginação
  const updatePagination = () => {
    paginationEl.innerHTML = "";
    const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage);

    if (totalPages <= 1) return;

    createPaginationButton("Primeira", 1, totalPages, "angle-double-left");
    createPaginationButton("Anterior", currentPage - 1, totalPages, "chevron-left");

    const maxPageButtons = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxPageButtons / 2));
    let endPage = startPage + maxPageButtons - 1;
    if (endPage > totalPages) {
      endPage = totalPages;
      startPage = Math.max(1, endPage - maxPageButtons + 1);
    }

    if (startPage > 1) {
      const ellipsisLi = document.createElement("li");
      ellipsisLi.className = "page-item disabled";
      ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
      paginationEl.appendChild(ellipsisLi);
    }

    for (let i = startPage; i <= endPage; i++) {
      createPaginationButton(i, i, totalPages);
    }

    if (endPage < totalPages) {
      const ellipsisLi = document.createElement("li");
      ellipsisLi.className = "page-item disabled";
      ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
      paginationEl.appendChild(ellipsisLi);
    }

    createPaginationButton("Próxima", currentPage + 1, totalPages, "chevron-right");
    createPaginationButton("Última", totalPages, totalPages, "angle-double-right");
  };

  const createPaginationButton = (label, pageNum, totalPages, icon) => {
    const li = document.createElement("li");
    li.className = "page-item" + (pageNum === currentPage || pageNum < 1 || pageNum > totalPages ? " disabled" : "");
    li.innerHTML = icon ? `<a class="page-link" href="#" aria-label="${label}"><i class="fas fa-${icon}"></i></a>` :
      `<a class="page-link" href="#" aria-label="Página ${label}">${label}</a>`;

    li.addEventListener("click", (e) => {
      e.preventDefault();
      if (pageNum !== currentPage && pageNum >= 1 && pageNum <= totalPages) {
        currentPage = pageNum;
        displayTable();
      }
    });
    paginationEl.appendChild(li);
  };

  // Função para aplicar os filtros
  const applyFilters = () => {
    const year = yearFilterEl.value;
    const vendor = vendorFilterEl.value;
    const severity = severityFilterEl.value;

    filteredVulnerabilities = vulnerabilities.filter(vuln => {
      return (!year || vuln["Published Date"].includes(year)) &&
             (!vendor || vuln["Vendor"] === vendor) &&
             (!severity || vuln["Severity"].toLowerCase() === severity.toLowerCase());
    });

    filteredVulnerabilities = sortByDate(filteredVulnerabilities);

    generateReportBtn.disabled = !(year && vendor && severity);

    currentPage = 1;

    displayTable();
  };

  // Função para limpar os filtros
  const clearFilters = () => {
    yearFilterEl.value = "";
    vendorFilterEl.value = "";
    severityFilterEl.value = "";

    filteredVulnerabilities = [...vulnerabilities];

    generateReportBtn.disabled = true;

    currentPage = 1;

    filteredVulnerabilities = sortByDate(filteredVulnerabilities);

    displayTable();
  };

  window.downloadReport = (cve_id) => {
    showLoading();
    fetch(`/generate_report?cve_id=${cve_id}`)
      .then(response => {
        if (response.ok) {
          return response.blob();
        } else {
          alert("Erro ao gerar o relatório.");
          throw new Error("Erro na requisição");
        }
      })
      .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `relatorio_vulnerabilidade_${cve_id}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      })
      .catch(error => console.error("Download report error:", error))
      .finally(hideLoading);
  };

  const showLoading = () => {
    loadingEl.style.display = "block";
  };

  const hideLoading = () => {
    loadingEl.style.display = "none";
  };


  yearFilterEl.addEventListener("change", applyFilters);
  vendorFilterEl.addEventListener("change", applyFilters);
  severityFilterEl.addEventListener("change", applyFilters);
  clearFiltersBtn.addEventListener("click", clearFilters);

  generateReportBtn.addEventListener("click", generateCSV);

  filteredVulnerabilities = sortByDate(filteredVulnerabilities);

  displayTable();
});










