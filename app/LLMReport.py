import io
import markdown
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from datetime import datetime


# Estilos definidos globalmente para otimização de desempenho
STYLES = None


def create_pdf_in_memory(data):
    """
    Gera o relatório PDF em memória para ser enviado diretamente ao cliente sem salvar no disco.
    """
    global STYLES
    if not STYLES:
        STYLES = define_styles()

    # Verifica a quantidade de dados recebidos
    if len(data) < 7:
        raise ValueError("Dados insuficientes para gerar o relatório. A entrada deve conter pelo menos 7 valores.")

    # Atribui os valores dos dados, com tratamento de exceções caso algum dado esteja ausente
    cve_id, description, risks, vendor, reference_links, base_severity, published_date = data[:7]
    generated_on = datetime.now().strftime("%d/%m/%Y %H:%M")

    # Formatar a data de publicação para o formato DD/MM/AA
    formatted_date = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f").strftime("%d/%m/%y")

    # Usamos um buffer em memória para o PDF
    buffer = io.BytesIO()

    # Gerar o documento PDF
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=20, leftMargin=30, topMargin=30, bottomMargin=20)

    # Criar conteúdo para o relatório
    content = create_content(cve_id, description, risks, vendor, reference_links, base_severity, formatted_date, generated_on)

    # Criar o documento e adicionar o conteúdo, com numeração de página
    doc.build(content, onFirstPage=add_page_number, onLaterPages=add_page_number)

    # Retorna o PDF em formato binário (bytes) para ser enviado diretamente ao cliente
    return buffer.getvalue()


def define_styles():
    """Define os estilos para o PDF"""
    return {
        "normal": ParagraphStyle("Normal", fontSize=10, leading=14, fontName="Helvetica", textColor=colors.black),
        "title": ParagraphStyle("Title", fontSize=14, alignment=1, spaceAfter=12, fontName="Helvetica-Bold", leading=16,
                                textColor=colors.black),
        "section_title": ParagraphStyle("SectionTitle", fontSize=12, spaceAfter=8, fontName="Helvetica-Bold",
                                        textColor=colors.darkblue),
        "severity": ParagraphStyle("Severity", fontSize=10, fontName="Helvetica-Bold", alignment=1, textColor=colors.black),
        "text": ParagraphStyle("Text", fontSize=10, fontName="Helvetica", textColor=colors.black)
    }


def markdown_to_paragraph(text, styles):
    """
    Converte o texto Markdown para HTML e em seguida para um parágrafo de PDF.
    """
    # Substituir as listas não ordenadas e ordenadas para garantir que sejam formatadas corretamente
    html = markdown.markdown(text)

    # Ajustar o estilo para bullet points e listas
    html = html.replace('<ul>', '<ul style="list-style-type: disc; margin-left: 20px;">')
    html = html.replace('<ol>', '<ol style="list-style-type: decimal; margin-left: 20px;">')

    return Paragraph(html, styles["text"])


def classify_severity(severity):
    """
    Classifica a severidade e retorna a cor correspondente.
    """
    severity_colors = {
        "Critical": colors.red,
        "High": colors.orange,
        "Medium": colors.yellow,
        "Low": colors.green,
        "N/A": colors.black,
    }
    return severity_colors.get(severity, colors.black)  # Default para preto se não encontrado


def create_content(cve_id, description, risks, vendor, reference_links, base_severity, published_date, generated_on):
    """
    Cria o conteúdo do relatório técnico em PDF.
    """
    content = []

    # Título do Relatório
    content.append(Spacer(1, 20))
    content.append(Paragraph(f"RELATÓRIO TÉCNICO {cve_id}", STYLES["title"]))
    content.append(Spacer(1, 20))

    # Tabela de Informações Básicas
    content.append(create_basic_info_table(cve_id, vendor, published_date, base_severity, generated_on))

    content.append(Spacer(1, 20))

    # Descrição
    content.append(Spacer(1, 12))
    content.append(Paragraph("Descrição", STYLES["section_title"]))
    content.append(markdown_to_paragraph(description, STYLES))
    content.append(Spacer(1, 10))

    # Riscos
    content.append(Spacer(1, 12))
    content.append(Paragraph("Riscos", STYLES["section_title"]))
    content.append(markdown_to_paragraph(risks, STYLES))
    content.append(Spacer(1, 10))

    # Referências
    content.append(Spacer(1, 12))
    content.append(Paragraph("Referências", STYLES["section_title"]))
    content.extend(process_references(reference_links))

    # Adiciona uma quebra de página após o conteúdo se necessário
    content.append(PageBreak())

    return content


def create_basic_info_table(cve_id, vendor, published_date, base_severity, generated_on):
    """Cria a tabela de informações básicas, incluindo severidade com cores"""
    color = classify_severity(base_severity)

    # Definir as células da tabela com cabeçalho
    table_data = [
        ["CVE ID", cve_id],
        ["Fornecedor", vendor or "Desconhecido"],
        ["Data de Publicação", published_date],
        ["Severidade", Paragraph(f"<font color='{color}'>{base_severity}</font>", STYLES["severity"])],
        ["Gerado em", generated_on]
    ]

    # Definir o estilo da tabela
    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("LINEBEFORE", (0, 0), (0, -1), 1, colors.black),
        ("LINEAFTER", (1, 0), (1, -1), 1, colors.black),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),  # Alinha as colunas ao centro
        ("ALIGN", (1, 0), (-1, -1), "CENTER"), # Alinha os dados ao centro
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),  # Colocando cor no cabeçalho
        ("BOX", (0, 0), (-1, -1), 1, colors.black)  # Adiciona borda ao redor da tabela
    ])

    # Retorna a tabela com os dados e estilo
    return Table(table_data, colWidths=[150, 200, 100, 100], style=table_style)


def process_references(reference_links):
    """
    Processa as referências, criando links clicáveis.
    """
    content = []
    if reference_links:
        for ref in reference_links.split(", "):
            content.append(Paragraph(f'<a href="{ref}">{ref}</a>', STYLES["normal"]))
    else:
        content.append(Paragraph("Nenhuma referência disponível.", STYLES["normal"]))

    return content


def add_page_number(canvas, doc):
    """Adiciona o número da página no rodapé"""
    page_num = canvas.getPageNumber()
    text = f"Página {page_num}"
    canvas.setFont("Helvetica", 8)
    canvas.drawString(500, 15, text)
