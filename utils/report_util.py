from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
from io import BytesIO
from utils.osv_util import query_vulnerability_info_from_osv_by_ids
import asyncio

TABLE_COLUMN_COUNT = 8

CRITICAL_STRING = "Critical"
HIGH_STRING = "High"
MEDIUM_STRING = "Medium"
LOW_STRING = "Low"

severity_rank = {
	"Critical": 3,
	"High": 2,
	"Medium": 1,
	"Low": 0
}

styles = getSampleStyleSheet()

header2_style = ParagraphStyle(
    'CustomHeader2',
    parent=styles['Heading2'],
    fontSize=18,
    spaceAfter=12,
    spaceBefore=20
)

header3_style = ParagraphStyle(
    'CustomHeader3',
    parent=styles['Heading3'],
    fontSize=14,
    spaceAfter=12,
    spaceBefore=20,
    textColor=colors.darkgreen
)

header4_style_link = ParagraphStyle(
    'CustomBody',
    parent=styles['Normal'],
	fontName='Helvetica',
    fontSize=14,
    spaceAfter=12,
    spaceBefore=20,
	textColor=colors.blue,
    underlineLinks=True,
)

header4_style = ParagraphStyle(
    'CustomBody',
    parent=styles['Normal'],
	fontName='Helvetica-Bold',
    fontSize=14,
    spaceAfter=12,
    spaceBefore=20,
    textColor=colors.black
)

body_style = ParagraphStyle(
    'CustomBody',
    parent=styles['Normal'],
    fontSize=10,
    spaceAfter=6,
    alignment=TA_LEFT
)

styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    'CustomTitle',
    parent=styles['Heading1'],
    fontSize=24,
    spaceAfter=30,
    alignment=TA_CENTER,
    textColor=colors.darkblue
)

def create_vulenrability_severity_pie_chart(table_data):
	critical_count = 0
	high_count = 0
	medium_count = 0
	low_count = 0

	for row in table_data:
		match row[5]:
			case "Critical":
				critical_count += 1
			case "High":
				high_count += 1
			case "Medium":
				medium_count += 1
			case "Low":
				low_count += 1

	labels = [CRITICAL_STRING, HIGH_STRING, MEDIUM_STRING, LOW_STRING]
	sizes = [critical_count, high_count, medium_count, low_count]
	colors = ['red', 'orange', 'yellow', 'yellowgreen']
	explode = (0.1, 0.05, 0.01, 0.0)

	final_labels = []
	final_sizes = []
	final_colors = []
	final_explode = []
	
	for lbl, sz, clr, exp in zip(labels, sizes, colors, explode):
		if sz > 0:
			final_labels.append(lbl)
			final_sizes.append(sz)
			final_colors.append(clr)
			final_explode.append(exp)
	
	def autopct_format(pct, all_vals):
		absolute = int(round(pct/100.*sum(all_vals)))
		return f"{absolute} ({pct:.1f}%)"
	
	fig, ax = plt.subplots(figsize=(4, 4))
	wedges, texts, autotexts = ax.pie(
        final_sizes,
        explode=final_explode,
        labels=final_labels,
        colors=final_colors,
        autopct=lambda pct: autopct_format(pct, sizes),
        shadow=True,
        startangle=140,
        textprops={'fontsize': 10}
    )
	
	ax.axis('equal')
	
	buffer = BytesIO()
	plt.savefig(buffer, format='png', bbox_inches='tight')
	plt.close(fig)
	buffer.seek(0)
	
	return buffer


def get_pie_chart_legend():
	legend = Drawing(0, 0)

	items = [
        (colors.red, CRITICAL_STRING),
        (colors.orange, HIGH_STRING),
        (colors.yellow, MEDIUM_STRING),
        (colors.green, LOW_STRING),
    ]
	
	box_size = 12
	spacing = 5
	y_start = 80

	for i, (color, label) in enumerate(items):
		y = y_start - i * (box_size + spacing)
		legend.add(Rect(10, y, box_size, box_size, fillColor=color, strokeColor=colors.black))
		legend.add(String(30, y + 2, label, fontSize=12, fillColor=colors.black))

	return legend

def get_severity_level_counts_pie_chart(table_data):
	critical_count = 0
	high_count = 0
	medium_count = 0
	low_count = 0

	for row in table_data:
		match row[5]:
			case "Critical":
				critical_count += 1
			case "High":
				high_count += 1
			case "Medium":
				medium_count += 1
			case "Low":
				low_count += 1

	graphic = Drawing(0, 0)

	pie = Pie()

	pie.x = 50
	pie.y = 15

	pie.labels = [CRITICAL_STRING, HIGH_STRING, MEDIUM_STRING, LOW_STRING]
	pie.data = [critical_count, high_count, medium_count, low_count]
	
	pie.slices[0].fillColor = colors.red
	pie.slices[1].fillColor = colors.orange
	pie.slices[2].fillColor = colors.yellow
	pie.slices[3].fillColor = colors.green

	graphic.add(pie)

	return graphic

def get_pie_chart_combined_drawing(table_data):
	pie = get_severity_level_counts_pie_chart(table_data)
	legend = get_pie_chart_legend()

	combined_drawing = Drawing(400, 150)

	for item in pie.contents:
		combined_drawing.add(item)
	for item in legend.contents:
		item_copy = item.copy()
		item_copy.translate(250, 0)
		combined_drawing.add(item_copy)

	return combined_drawing

def generate_table(vulnerabilities_table_string):
	table_data = []
	ids = []

	lines = vulnerabilities_table_string.strip().split("\n")

	header = lines[0].split()

	table_data.append(header)
	
	for line in lines[1:]:
		columns = line.split(None, len(header) - 1)

		# Add empty column if FIXED-IN is empty
		if (len(columns) < TABLE_COLUMN_COUNT):
			columns.insert(2, "")
		ids.append(columns[4])
		table_data.append(columns)

	header = table_data[0]
	rows = table_data[1:]

	rows_sorted = sorted(rows, key=lambda r: severity_rank.get(r[5], -1), reverse=True)

	sorted_table = [header] + rows_sorted

	table = Table(sorted_table)

	style = TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('BACKGROUND', (0, 1), (-1, -1), colors.beige)])

	table.setStyle(style)

	return table, sorted_table, ids

def create_vulnerablity_info_tables(report, vulnerabilities_info):
	for info in vulnerabilities_info:
		id = info.get('id') or "No Id info"
		details = info.get('details') or "No details available"
		published = info.get('published') or "No publish date"
		cwe_ids = ", ".join(info.get("database_specific", {}).get("cwe_ids", [])) or ""
	
		report.append(Paragraph(f'<link href="https://osv.dev/vulnerability/{id}">{id}</link>' if id != 'No Id info' else 'No Id info', header4_style_link))

		report.append(Spacer(1, 12))

		normal_style = styles["Normal"]

		data = [
			["Id", id],
			["Details", Paragraph(details, normal_style)],
			["CWEs", cwe_ids],
			["Published", published],
		]

		table = Table(data, colWidths=[80, 400])
		table.setStyle(TableStyle([
			("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
			("BOX", (0, 0), (-1, -1), 0.25, colors.grey),
			("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
			("VALIGN", (0, 0), (-1, -1), "TOP"),
			("LEFTPADDING", (0, 0), (-1, -1), 6),
			("RIGHTPADDING", (0, 0), (-1, -1), 6),
			("BOTTOMPADDING", (0, 0), (-1, -1), 4),
		]))

		report.append(table)

		report.append(Spacer(1, 12))

def create_patch_dictionary(table_data):
	name_to_fix_dictionary = {}
	vulnerabilities_without_fixes_dictionary = {}

	for line in table_data[1:]:

		name = line[0]
		severity = line[5]
		fixed_in = line[2].strip()


		if name not in name_to_fix_dictionary:
			if fixed_in == '':
				if name not in vulnerabilities_without_fixes_dictionary or severity_rank[severity] > severity_rank[vulnerabilities_without_fixes_dictionary[name]]:
					vulnerabilities_without_fixes_dictionary[name] = severity
			else:
				name_to_fix_dictionary[name] = {'fixed_in': fixed_in, 'severity': severity }
		else:
			if name_to_fix_dictionary[name]['fixed_in'] != '':
				current_fixed_in_int_dict_value = int(name_to_fix_dictionary[name]['fixed_in'].replace(".", ""))

			if (fixed_in == ""):
				if name not in vulnerabilities_without_fixes_dictionary or severity_rank[severity] > severity_rank[vulnerabilities_without_fixes_dictionary[name]]:
					vulnerabilities_without_fixes_dictionary[name] = severity
				continue

			fixed_in_int = int(fixed_in.replace(".", ""))

			if (fixed_in_int > current_fixed_in_int_dict_value):
				name_to_fix_dictionary[name]['fixed_in'] = fixed_in
			
			if (severity_rank[severity] > severity_rank[name_to_fix_dictionary[name]['severity']]):
				name_to_fix_dictionary[name]['severity'] = severity
	
	return name_to_fix_dictionary, vulnerabilities_without_fixes_dictionary

def create_patch_paragraph(report, table_data):
	patch_dictionary, patch_dictionary_without_fixes = create_patch_dictionary(table_data)

	critical_patches = [{'name': name, 'fixed_in': data['fixed_in'], 'severity': data['severity']}
    for name, data in patch_dictionary.items()
    if data['severity'] == CRITICAL_STRING]

	high_patches = [{'name': name, 'fixed_in': data['fixed_in'], 'severity': data['severity']}
    for name, data in patch_dictionary.items()
    if data['severity'] == HIGH_STRING]

	medium_patches = [{'name': name, 'fixed_in': data['fixed_in'], 'severity': data['severity']}
    for name, data in patch_dictionary.items()
    if data['severity'] == MEDIUM_STRING]

	low_patches = [{'name': name, 'fixed_in': data['fixed_in'], 'severity': data['severity']}
    for name, data in patch_dictionary.items()
    if data['severity'] == LOW_STRING]

	if patch_dictionary_without_fixes:
		no_patches_paragraph = "<br/>".join([
    	f"Consider removing or replacing <b>{name}</b> (severity: <b>{severity}</b>) as no patched version is currently available."
    	for name, severity in patch_dictionary_without_fixes.items()])

		report.append(Paragraph(f"Vulnerabilities without available patches:", header4_style))
		report.append(Paragraph(no_patches_paragraph, body_style))
		report.append(Spacer(1, 1))

	if critical_patches:
		critical_patches_paragraph = "<br/>".join([f"Update <b>{item['name']}</b> to version <b>{item['fixed_in']}</b> or later." for item in critical_patches])

		report.append(Paragraph(f"Critical patch recommendations:", header4_style))
		report.append(Paragraph(critical_patches_paragraph, body_style))
		report.append(Spacer(1, 1))

	if high_patches:
		high_patches_paragraph = "<br/>".join([f"Update <b>{item['name']}</b> to version <b>{item['fixed_in']}</b> or later." for item in high_patches])

		report.append(Paragraph(f"High patch recommendations:", header4_style))
		report.append(Paragraph(high_patches_paragraph, body_style))
		report.append(Spacer(1, 1))

	if medium_patches:
		medium_patches_paragraph = "<br/>".join([f"Update <b>{item['name']}</b> to version <b>{item['fixed_in']}</b> or later." for item in medium_patches])

		report.append(Paragraph(f"Medium patch recommendations:", header4_style))
		report.append(Paragraph(medium_patches_paragraph, body_style))
		report.append(Spacer(1, 1))
	
	if low_patches:
		low_patches_paragraph = "<br/>".join([f"Update <b>{item['name']}</b> to version <b>{item['fixed_in']}</b> or later." for item in low_patches])

		report.append(Paragraph(f"Low patch recommendations:", header4_style))
		report.append(Paragraph(low_patches_paragraph, body_style))
		report.append(Spacer(1, 1))


def create_security_report_pdf(vulnerabilities_table_string, repository_name, output_filename="report.pdf"):
	doc = SimpleDocTemplate(
        output_filename,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=18
    )

	report = []

	report.append(Paragraph(f"{repository_name}: Vulnerabilities Scan Report", title_style))
	report.append(Spacer(1, 12))

	# In case no vulnerabilities found
	if (vulnerabilities_table_string == "No vulnerabilities found\n"):
		report.append(Paragraph("No Vulnerabilities Found", header4_style))
		doc.build(report)
		return

	table, table_data, ids = generate_table(vulnerabilities_table_string)

	# Create pie chart for vulnerablity counts
	pie_chart_image_buffer = create_vulenrability_severity_pie_chart(table_data)

	report.append(Paragraph("Vulnerability severity counts:", header3_style))
	report.append(Spacer(1, 12))
	
	img = Image(pie_chart_image_buffer, width=5*inch, height=3.5*inch)
	
	report.append(img)

	report.append(Paragraph("Package vulnerability information:", header3_style))
	report.append(Spacer(1, 12))

	report.append(table)

	report.append(Spacer(1, 12))

	report.append(Paragraph("Vulnerability patch recommendations:", header3_style))

	create_patch_paragraph(report, table_data)

	report.append(Spacer(1, 12))

	report.append(Paragraph("Detailed vulnerability information:", header3_style))

	vulnerability_info = asyncio.run(query_vulnerability_info_from_osv_by_ids(ids))
	create_vulnerablity_info_tables(report, vulnerability_info)
	
	doc.build(report)

