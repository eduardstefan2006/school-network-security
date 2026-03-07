"""
Generator de rapoarte PDF pentru SchoolSec.
Folosește ReportLab pentru PDF și matplotlib pentru grafice.
"""
import io
import os
import tempfile
from datetime import datetime, timezone, timedelta

import matplotlib
matplotlib.use('Agg')  # Backend non-interactiv, sigur pe server
import matplotlib.pyplot as plt

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable

# ---------------------------------------------------------------------------
# Schemă de culori (matching app-ul)
# ---------------------------------------------------------------------------
COLOR_BG = colors.HexColor('#0d1117')
COLOR_HEADER_BG = colors.HexColor('#161b22')
COLOR_GREEN = colors.HexColor('#3fb950')
COLOR_BLUE = colors.HexColor('#58a6ff')
COLOR_RED = colors.HexColor('#f78166')
COLOR_YELLOW = colors.HexColor('#d29922')
COLOR_DARK_RED = colors.HexColor('#da3633')
COLOR_TEXT = colors.HexColor('#e6edf3')
COLOR_MUTED = colors.HexColor('#8b949e')
COLOR_BORDER = colors.HexColor('#30363d')
COLOR_ROW_ALT = colors.HexColor('#1c2128')

# Culori severitate
SEV_COLORS = {
    'critical': COLOR_DARK_RED,
    'high': COLOR_RED,
    'medium': COLOR_YELLOW,
    'low': COLOR_BLUE,
}

# Culori tip alertă (pentru grafice matplotlib)
TYPE_COLORS_MPL = ['#3fb950', '#58a6ff', '#f78166', '#d29922', '#da3633', '#a371f7']
SEV_COLORS_MPL = ['#da3633', '#f78166', '#d29922', '#58a6ff']


# ---------------------------------------------------------------------------
# Stiluri ReportLab
# ---------------------------------------------------------------------------
def _build_styles():
    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'SchoolSecTitle',
        parent=base['Title'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=COLOR_GREEN,
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        'SchoolSecSubtitle',
        parent=base['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=COLOR_MUTED,
        spaceAfter=2,
        alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        'SchoolSecSection',
        parent=base['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=COLOR_BLUE,
        spaceBefore=14,
        spaceAfter=6,
        borderPad=0,
    )
    body_style = ParagraphStyle(
        'SchoolSecBody',
        parent=base['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=COLOR_TEXT,
        spaceAfter=4,
    )
    small_style = ParagraphStyle(
        'SchoolSecSmall',
        parent=base['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=COLOR_MUTED,
        alignment=TA_CENTER,
    )
    table_header_style = ParagraphStyle(
        'SchoolSecTableHeader',
        parent=base['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=COLOR_TEXT,
    )
    table_cell_style = ParagraphStyle(
        'SchoolSecTableCell',
        parent=base['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=COLOR_TEXT,
    )

    return {
        'title': title_style,
        'subtitle': subtitle_style,
        'section': section_style,
        'body': body_style,
        'small': small_style,
        'table_header': table_header_style,
        'table_cell': table_cell_style,
    }


# ---------------------------------------------------------------------------
# Funcții ajutătoare pentru grafice matplotlib
# ---------------------------------------------------------------------------
def _fig_to_tempfile(fig):
    """Salvează figura matplotlib într-un fișier temporar PNG și returnează calea."""
    tmp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    fig.savefig(tmp.name, format='png', dpi=120, bbox_inches='tight',
                facecolor='#161b22', edgecolor='none')
    plt.close(fig)
    tmp.close()
    return tmp.name


def _build_timeline_chart(timeline_data):
    """Generează graficul de tendință alerte (line chart)."""
    labels = timeline_data.get('labels', [])
    if not labels:
        return None

    fig, ax = plt.subplots(figsize=(10, 3.5))
    fig.patch.set_facecolor('#161b22')
    ax.set_facecolor('#0d1117')

    x = range(len(labels))
    for sev, color in [('critical', '#da3633'), ('high', '#f78166'),
                       ('medium', '#d29922'), ('low', '#58a6ff')]:
        values = timeline_data.get(sev, [0] * len(labels))
        ax.plot(list(x), values, marker='o', markersize=3, linewidth=1.5,
                color=color, label=sev.capitalize())

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=7, color='#8b949e')
    ax.tick_params(axis='y', colors='#8b949e', labelsize=7)
    ax.spines[:].set_color('#30363d')
    ax.grid(True, color='#30363d', linewidth=0.5, alpha=0.7)
    ax.legend(fontsize=8, facecolor='#161b22', edgecolor='#30363d',
              labelcolor='#e6edf3', loc='upper right')
    ax.set_title('Tendință Alerte', color='#e6edf3', fontsize=10, pad=8)

    plt.tight_layout()
    return _fig_to_tempfile(fig)


def _build_pie_chart(data_dict, title, colors_list):
    """Generează un grafic tip pie chart."""
    filtered = {k: v for k, v in data_dict.items() if v > 0}
    if not filtered:
        return None

    labels = list(filtered.keys())
    values = list(filtered.values())
    chart_colors = colors_list[:len(labels)]

    fig, ax = plt.subplots(figsize=(5, 3.5))
    fig.patch.set_facecolor('#161b22')
    ax.set_facecolor('#161b22')

    wedges, texts, autotexts = ax.pie(
        values,
        labels=None,
        colors=chart_colors,
        autopct='%1.1f%%',
        startangle=140,
        pctdistance=0.75,
        wedgeprops={'linewidth': 1, 'edgecolor': '#30363d'},
    )
    for at in autotexts:
        at.set_color('#e6edf3')
        at.set_fontsize(7)

    ax.legend(
        wedges,
        [f'{l} ({v})' for l, v in zip(labels, values)],
        fontsize=7,
        facecolor='#161b22',
        edgecolor='#30363d',
        labelcolor='#e6edf3',
        loc='lower center',
        bbox_to_anchor=(0.5, -0.3),
        ncol=2,
    )
    ax.set_title(title, color='#e6edf3', fontsize=10, pad=8)

    plt.tight_layout()
    return _fig_to_tempfile(fig)


# ---------------------------------------------------------------------------
# Page template cu header/footer
# ---------------------------------------------------------------------------
def _make_page_template(doc, period_label, gen_time):
    """Construiește template-ul de pagină cu footer."""
    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        doc.width, doc.height,
        id='main',
    )

    def _draw_page(canvas, doc):
        canvas.saveState()
        page_width, page_height = A4

        # Header bar
        canvas.setFillColor(COLOR_HEADER_BG)
        canvas.rect(0, page_height - 1.5 * cm, page_width, 1.5 * cm, fill=1, stroke=0)
        canvas.setFillColor(COLOR_GREEN)
        canvas.setFont('Helvetica-Bold', 14)
        canvas.drawString(1.5 * cm, page_height - 1.05 * cm, 'SchoolSec')
        canvas.setFillColor(COLOR_MUTED)
        canvas.setFont('Helvetica', 8)
        canvas.drawString(4.5 * cm, page_height - 1.05 * cm,
                          f'Raport de Securitate · {period_label}')
        canvas.setFillColor(COLOR_MUTED)
        canvas.drawRightString(
            page_width - 1.5 * cm, page_height - 1.05 * cm,
            f'Generat: {gen_time}',
        )

        # Footer
        canvas.setFillColor(COLOR_HEADER_BG)
        canvas.rect(0, 0, page_width, 1.2 * cm, fill=1, stroke=0)
        canvas.setFillColor(COLOR_MUTED)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(
            1.5 * cm, 0.45 * cm,
            'Generat automat de SchoolSec - Școala 2 Liești',
        )
        canvas.drawRightString(
            page_width - 1.5 * cm, 0.45 * cm,
            f'Pagina {doc.page}',
        )
        canvas.restoreState()

    return PageTemplate(id='main', frames=[frame], onPage=_draw_page)


# ---------------------------------------------------------------------------
# Construire date timeline (fără import din routes)
# ---------------------------------------------------------------------------
def _build_timeline_data(alerts, period):
    """Construiește datele pentru graficul de tip linie (timeline)."""
    now = datetime.now(timezone.utc)
    severities = ['critical', 'high', 'medium', 'low']

    if period == '24h':
        labels = []
        buckets = {}
        for i in range(23, -1, -1):
            dt = now - timedelta(hours=i)
            label = dt.strftime('%H:00')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}
        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%H:00')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    elif period in ('7d', '30d'):
        days = 7 if period == '7d' else 30
        labels = []
        buckets = {}
        for i in range(days - 1, -1, -1):
            dt = now - timedelta(days=i)
            label = dt.strftime('%d.%m')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}
        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%d.%m')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    else:
        if not alerts:
            return {'labels': [], 'critical': [], 'high': [], 'medium': [], 'low': []}
        timestamps = [
            a.timestamp if a.timestamp.tzinfo else a.timestamp.replace(tzinfo=timezone.utc)
            for a in alerts
        ]
        min_dt = min(timestamps)
        max_dt = max(timestamps)
        delta = (max_dt - min_dt).days + 1
        labels = []
        buckets = {}
        for i in range(delta):
            dt = min_dt + timedelta(days=i)
            label = dt.strftime('%d.%m')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}
        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%d.%m')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    return {
        'labels': labels,
        'critical': [buckets[l]['critical'] for l in labels],
        'high': [buckets[l]['high'] for l in labels],
        'medium': [buckets[l]['medium'] for l in labels],
        'low': [buckets[l]['low'] for l in labels],
    }


# ---------------------------------------------------------------------------
# Funcție principală
# ---------------------------------------------------------------------------
def generate_report(alerts, period_label, output_path=None):
    """
    Generează un raport PDF de securitate.

    Args:
        alerts: Lista de obiecte Alert din baza de date.
        period_label: Etichetă text pentru perioada raportului (ex. "Ultimele 7 zile").
        output_path: Cale opțională pentru salvarea PDF-ului. Dacă None, returnează bytes.

    Returns:
        bytes dacă output_path este None, altfel scrie fișierul și returnează None.
    """
    styles = _build_styles()
    gen_time = datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')
    temp_files = []

    # ------------------------------------------------------------------
    # Calculăm statistici
    # ------------------------------------------------------------------
    total = len(alerts)
    critical_count = sum(1 for a in alerts if a.severity == 'critical')
    high_count = sum(1 for a in alerts if a.severity == 'high')
    medium_count = sum(1 for a in alerts if a.severity == 'medium')
    low_count = sum(1 for a in alerts if a.severity == 'low')
    resolved = sum(1 for a in alerts if a.status == 'resolved')
    resolved_pct = round(resolved / total * 100, 1) if total > 0 else 0.0
    unique_ips = len({a.source_ip for a in alerts})

    # Top 10 IP-uri
    ip_counts = {}
    ip_last_seen = {}
    ip_types = {}
    for a in alerts:
        ip_counts[a.source_ip] = ip_counts.get(a.source_ip, 0) + 1
        ts = a.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if a.source_ip not in ip_last_seen or ts > ip_last_seen[a.source_ip]:
            ip_last_seen[a.source_ip] = ts
        types = ip_types.setdefault(a.source_ip, set())
        types.add(a.alert_type)

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # By type / severity
    by_type = {}
    for a in alerts:
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1

    by_severity = {
        'critical': critical_count,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
    }

    # Timeline — detectăm perioada din eticheta de text
    period_key = 'all'
    if '24' in period_label:
        period_key = '24h'
    elif '7' in period_label:
        period_key = '7d'
    elif '30' in period_label:
        period_key = '30d'
    timeline_data = _build_timeline_data(alerts, period_key)

    # Ultimele 20 alerte critice/high
    critical_alerts = sorted(
        [a for a in alerts if a.severity in ('critical', 'high')],
        key=lambda a: a.timestamp,
        reverse=True,
    )[:20]

    # ------------------------------------------------------------------
    # Buffer PDF
    # ------------------------------------------------------------------
    buffer = io.BytesIO()
    target = output_path if output_path else buffer

    doc = BaseDocTemplate(
        target,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
        title='Raport de Securitate SchoolSec',
        author='SchoolSec',
    )

    page_tmpl = _make_page_template(doc, period_label, gen_time)
    doc.addPageTemplates([page_tmpl])

    story = []

    # ------------------------------------------------------------------
    # 1. Header / Titlu
    # ------------------------------------------------------------------
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph('Raport de Securitate', styles['title']))
    story.append(Paragraph(
        f'Perioada: <b>{period_label}</b> &nbsp;|&nbsp; Generat: {gen_time}',
        styles['subtitle'],
    ))
    story.append(HRFlowable(width='100%', thickness=1, color=COLOR_BORDER,
                            spaceAfter=10))

    # ------------------------------------------------------------------
    # 2. Rezumat Executiv
    # ------------------------------------------------------------------
    story.append(Paragraph('Rezumat Executiv', styles['section']))

    if total == 0:
        story.append(Paragraph('Nu sunt date disponibile pentru perioada selectată.',
                               styles['body']))
    else:
        summary_data = [
            [Paragraph('Indicator', styles['table_header']),
             Paragraph('Valoare', styles['table_header'])],
            [Paragraph('Total alerte', styles['table_cell']),
             Paragraph(str(total), styles['table_cell'])],
            [Paragraph('Alerte critice', styles['table_cell']),
             Paragraph(str(critical_count), styles['table_cell'])],
            [Paragraph('Alerte high', styles['table_cell']),
             Paragraph(str(high_count), styles['table_cell'])],
            [Paragraph('Alerte medium', styles['table_cell']),
             Paragraph(str(medium_count), styles['table_cell'])],
            [Paragraph('Alerte low', styles['table_cell']),
             Paragraph(str(low_count), styles['table_cell'])],
            [Paragraph('IP-uri suspecte unice', styles['table_cell']),
             Paragraph(str(unique_ips), styles['table_cell'])],
            [Paragraph('Alerte rezolvate', styles['table_cell']),
             Paragraph(f'{resolved} ({resolved_pct}%)', styles['table_cell'])],
        ]
        summary_table = Table(summary_data, colWidths=[8 * cm, 8 * cm])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_TEXT),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_BG, COLOR_ROW_ALT]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)

    # ------------------------------------------------------------------
    # 3. Grafic Tendință Alerte
    # ------------------------------------------------------------------
    story.append(Paragraph('Grafic Tendință Alerte', styles['section']))

    if timeline_data.get('labels'):
        chart_path = _build_timeline_chart(timeline_data)
        if chart_path:
            temp_files.append(chart_path)
            story.append(Image(chart_path, width=16 * cm, height=5.5 * cm))
    else:
        story.append(Paragraph('Nu sunt date disponibile pentru grafic.',
                               styles['body']))

    # ------------------------------------------------------------------
    # 4. Top 10 IP-uri Suspecte
    # ------------------------------------------------------------------
    story.append(Paragraph('Top 10 IP-uri Suspecte', styles['section']))

    if top_ips:
        ip_table_data = [
            [
                Paragraph('IP', styles['table_header']),
                Paragraph('Alerte', styles['table_header']),
                Paragraph('Ultima activitate', styles['table_header']),
                Paragraph('Tipuri alerte', styles['table_header']),
            ]
        ]
        for ip, count in top_ips:
            last_ts = ip_last_seen.get(ip)
            last_str = last_ts.strftime('%d.%m.%Y %H:%M') if last_ts else '-'
            types_str = ', '.join(sorted(ip_types.get(ip, set())))
            ip_table_data.append([
                Paragraph(ip, styles['table_cell']),
                Paragraph(str(count), styles['table_cell']),
                Paragraph(last_str, styles['table_cell']),
                Paragraph(types_str, styles['table_cell']),
            ])

        ip_table = Table(ip_table_data,
                         colWidths=[3.5 * cm, 2 * cm, 4 * cm, 6.5 * cm])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER_BG),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_BG, COLOR_ROW_ALT]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ip_table)
    else:
        story.append(Paragraph('Nu sunt IP-uri suspecte în perioada selectată.',
                               styles['body']))

    # ------------------------------------------------------------------
    # 5 & 6. Pie charts: by type + by severity (side by side)
    # ------------------------------------------------------------------
    story.append(Paragraph('Distribuție Alerte', styles['section']))

    pie_type_path = _build_pie_chart(by_type, 'Distribuție pe Tip', TYPE_COLORS_MPL)
    pie_sev_path = _build_pie_chart(by_severity, 'Distribuție pe Severitate',
                                    SEV_COLORS_MPL)

    if pie_type_path or pie_sev_path:
        chart_cells = []
        if pie_type_path:
            temp_files.append(pie_type_path)
            chart_cells.append(Image(pie_type_path, width=7.5 * cm, height=5.5 * cm))
        else:
            chart_cells.append(Paragraph('Nu sunt date.', styles['body']))

        if pie_sev_path:
            temp_files.append(pie_sev_path)
            chart_cells.append(Image(pie_sev_path, width=7.5 * cm, height=5.5 * cm))
        else:
            chart_cells.append(Paragraph('Nu sunt date.', styles['body']))

        pie_table = Table([chart_cells], colWidths=[8 * cm, 8 * cm])
        pie_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_HEADER_BG),
        ]))
        story.append(pie_table)
    else:
        story.append(Paragraph('Nu sunt date disponibile pentru grafice.',
                               styles['body']))

    # ------------------------------------------------------------------
    # 7. Ultimele Alerte Critice/High
    # ------------------------------------------------------------------
    story.append(Paragraph('Ultimele Alerte Critice și High', styles['section']))

    if critical_alerts:
        crit_data = [
            [
                Paragraph('ID', styles['table_header']),
                Paragraph('Tip', styles['table_header']),
                Paragraph('IP Sursă', styles['table_header']),
                Paragraph('Severitate', styles['table_header']),
                Paragraph('Status', styles['table_header']),
                Paragraph('Data', styles['table_header']),
            ]
        ]
        for a in critical_alerts:
            sev_color = SEV_COLORS.get(a.severity, COLOR_TEXT)
            crit_data.append([
                Paragraph(str(a.id), styles['table_cell']),
                Paragraph(a.alert_type, styles['table_cell']),
                Paragraph(a.source_ip, styles['table_cell']),
                Paragraph(a.severity.upper(), ParagraphStyle(
                    'sev', parent=styles['table_cell'],
                    textColor=sev_color, fontName='Helvetica-Bold',
                )),
                Paragraph(a.status, styles['table_cell']),
                Paragraph(a.timestamp.strftime('%d.%m.%Y %H:%M'),
                          styles['table_cell']),
            ])

        crit_table = Table(
            crit_data,
            colWidths=[1.2 * cm, 3.2 * cm, 3.2 * cm, 2.2 * cm, 2.2 * cm, 4 * cm],
        )
        crit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_HEADER_BG),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_BG, COLOR_ROW_ALT]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(crit_table)
    else:
        story.append(Paragraph('Nu există alerte critice sau high în perioada selectată.',
                               styles['body']))

    # ------------------------------------------------------------------
    # Build PDF
    # ------------------------------------------------------------------
    try:
        doc.build(story)
    finally:
        # Curățăm fișierele temporare
        for path in temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass

    if output_path:
        return None

    buffer.seek(0)
    return buffer.read()
