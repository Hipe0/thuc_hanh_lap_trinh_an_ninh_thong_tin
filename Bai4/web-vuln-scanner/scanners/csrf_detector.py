"""
Module CSRFDetector.

Phan tich noi dung HTML de xac dinh ung dung co su dung CSRF token hay khong.
Neu khong tim thay token nao -> canh bao kha nang bi tan cong CSRF.
"""

import re


class CSRFDetector:
    """Bo phat hien kha nang bao ve CSRF cua mot trang HTML."""

    # Cac mau ten truong an thuong duoc dung cho CSRF token.
    csrf_token_patterns = [
        re.compile(r'name=["\']csrf_token["\']', re.I),
        re.compile(r'name=["\']_csrf["\']', re.I),
        re.compile(r'name=["\']csrfmiddlewaretoken["\']', re.I),
    ]

    def scan(self, html_content):
        # Chi can khop mot mau la coi nhu da co bao ve CSRF.
        for pattern in self.csrf_token_patterns:
            if pattern.search(html_content):
                return {'csrf_protected': True}

        return {
            'csrf_protected': False,
            'desc': 'No CSRF token found, vulnerable to CSRF',
            'risk': 'Medium',
        }
