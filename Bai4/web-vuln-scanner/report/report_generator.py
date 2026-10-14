"""
Module ReportGenerator.

Tong hop ket qua tu cac bo quet (moi phan tu co the la list hoac dict)
thanh mot bao cao lo hong thong nhat duoi dang {'vulnerabilities': [...]}.
"""


class ReportGenerator:
    """Bo tao bao cao lo hong tu danh sach ket qua quet."""

    def generate(self, findings_list):
        report = {'vulnerabilities': []}

        for findings in findings_list:

            # Ket qua dang list -> noi vao danh sach lo hong.
            if isinstance(findings, list):
                report['vulnerabilities'].extend(findings)

            # Ket qua dang dict -> them truc tiep mot muc.
            elif isinstance(findings, dict):
                report['vulnerabilities'].append(findings)

        return report
