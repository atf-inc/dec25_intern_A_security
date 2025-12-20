"""
PDF Report Generator
Creates professional PDF reports with charts and statistics
"""
import io
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.units import inch
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
from core.database import db

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
    async def generate_weekly_report(self) -> bytes:
        """Generate weekly threat report PDF"""
        
        try:
            # Create PDF in memory
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30
            )
            story.append(Paragraph("QuantumShield Honeypot", title_style))
            story.append(Paragraph("Weekly Threat Intelligence Report", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            # Date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=7)
            date_text = f"Report Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
            story.append(Paragraph(date_text, self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Fetch data
            logs_collection = db.get_collection("logs")
            sessions_collection = db.get_collection("sessions")
            
            total_attacks = await logs_collection.count_documents({
                "timestamp": {"$gte": start_date}
            })
            
            total_sessions = await sessions_collection.count_documents({
                "start_time": {"$gte": start_date}
            })
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['Heading2']))
            summary_data = [
                ["Metric", "Value"],
                ["Total Attack Attempts", str(total_attacks)],
                ["Unique Attacker Sessions", str(total_sessions)],
                ["Average Attacks per Session", f"{total_attacks/max(total_sessions, 1):.1f}"],
                ["Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))
            
            if total_attacks == 0:
                # No attacks detected
                story.append(Paragraph("No attack activity detected during this period.", self.styles['Normal']))
            else:
                # Attack Types Distribution
                pipeline = [
                    {"$match": {"timestamp": {"$gte": start_date}}},
                    {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}
                ]
                attack_types = await logs_collection.aggregate(pipeline).to_list(length=None)
                
                if attack_types:
                    story.append(Paragraph("Attack Types Distribution", self.styles['Heading2']))
                    
                    # Create chart
                    labels = [at["_id"] if at["_id"] else "Unknown" for at in attack_types]
                    sizes = [at["count"] for at in attack_types]
                    
                    fig, ax = plt.subplots(figsize=(6, 4))
                    ax.bar(labels, sizes, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8'])
                    ax.set_ylabel('Number of Attacks')
                    ax.set_title('Attack Types Distribution')
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    
                    # Save chart to buffer
                    chart_buffer = io.BytesIO()
                    plt.savefig(chart_buffer, format='png', dpi=150, bbox_inches='tight')
                    chart_buffer.seek(0)
                    plt.close()
                    
                    # Add chart to PDF
                    img = Image(chart_buffer, width=5*inch, height=3.3*inch)
                    story.append(img)
                    story.append(Spacer(1, 0.3*inch))
                
                # Top Attacker IPs
                ip_pipeline = [
                    {"$match": {"timestamp": {"$gte": start_date}}},
                    {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                    {"$limit": 10}
                ]
                top_ips = await logs_collection.aggregate(ip_pipeline).to_list(length=10)
                
                if top_ips:
                    story.append(PageBreak())
                    story.append(Paragraph("Top 10 Attacker IPs", self.styles['Heading2']))
                    
                    ip_data = [["Rank", "IP Address", "Attack Count"]]
                    for i, ip_info in enumerate(top_ips, 1):
                        ip_data.append([str(i), ip_info["_id"] if ip_info["_id"] else "Unknown", str(ip_info["count"])])
                    
                    ip_table = Table(ip_data, colWidths=[0.7*inch, 2.5*inch, 1.5*inch])
                    ip_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 11),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    story.append(ip_table)
            
            # Build PDF
            doc.build(story)
            
            # Get PDF bytes
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            return pdf_bytes
            
        except Exception as e:
            # If report generation fails, create a simple error report
            print(f"[REPORT] Error generating report: {str(e)}")
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = [
                Paragraph("QuantumShield Honeypot", self.styles['Heading1']),
                Paragraph("Weekly Threat Intelligence Report", self.styles['Heading2']),
                Spacer(1, 0.3*inch),
                Paragraph(f"Error generating report: {str(e)}", self.styles['Normal']),
                Spacer(1, 0.2*inch),
                Paragraph("Please check the backend logs for more details.", self.styles['Normal'])
            ]
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes

# Singleton instance
report_generator = ReportGenerator()
