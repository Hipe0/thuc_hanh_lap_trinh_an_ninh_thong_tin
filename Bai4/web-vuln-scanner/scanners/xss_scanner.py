"""
Module XSSScanner.

Phat hien lo hong XSS (Cross-Site Scripting) bang cach chen cac payload
da chuan hoa vao tham so query cua URL, sau do kiem tra xem payload co bi
phan hoi nguyen van trong noi dung tra ve hay khong.
"""

import requests


class XSSScanner:
    """Bo quet XSS dua tren danh sach payload co san."""

    def __init__(self):
        # Danh sach payload dung de thu nghiem phan hoi tu may chu.
        self.payloads = [
            "<script>alert(1)</script>",
            "'><svg/onload=alert(1)>",
        ]

    def scan(self, url):
        results = []

        for payload in self.payloads:
            test_url = f"{url}?q={payload}"

            try:
                resp = requests.get(test_url, timeout=5)

                # Neu payload xuat hien nguyen van trong phan hoi -> dinh XSS.
                if payload in resp.text:
                    results.append({
                        "type":    "XSS",
                        "payload": payload,
                        "url":     test_url,
                        "risk":    "HIGH",
                    })

            except Exception:
                # Bo qua loi mang (timeout, khong ket noi duoc, ...).
                pass

        return results
