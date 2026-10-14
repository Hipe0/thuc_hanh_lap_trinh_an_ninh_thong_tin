"""
Chuong trinh chinh (CLI) cua Web Vulnerability Scanner.

Khoi tao cac bo quet, chay lan luot tren mot URL/HTML mau, roi in bao cao
tong hop ra man hinh.
"""

from scanners.xss_scanner import XSSScanner
from scanners.sql_injection_tester import SQLInjectionTester
from scanners.csrf_detector import CSRFDetector
from scanners.ssrf_tester import SSRFTester
from report.report_generator import ReportGenerator


def main():
    # Du lieu dau vao mau (chua nhieu dau hieu lo hong khac nhau).
    url = '''http://example.com/page?
            input=<script>alert(1)</script>&id='
            OR '1'='1&url=http://127.0.0.1/admin'''
    html = '''<form><input type="hidden"
            name="csrf_token" value="abc123"/></form>'''

    # Khoi tao cac bo quet va bo tao bao cao.
    xss = XSSScanner()
    sql = SQLInjectionTester()
    csrf = CSRFDetector()
    ssrf = SSRFTester()
    report_gen = ReportGenerator()

    # Thu thap ket qua tu tung bo quet.
    findings = []
    findings.append(xss.scan(url))
    findings.append(sql.scan(url))
    findings.append(csrf.scan(html))
    findings.append(ssrf.scan(url))

    # Tong hop va in bao cao.
    report = report_gen.generate(findings)

    print("=== Vulnerability Report ===")
    for vuln in report['vulnerabilities']:
        print(f'''Param: {vuln.get('param', 'N/A')}, Desc: {vuln.get('desc')},
            Risk: {vuln.get('risk')}''')


if __name__ == '__main__':
    main()
