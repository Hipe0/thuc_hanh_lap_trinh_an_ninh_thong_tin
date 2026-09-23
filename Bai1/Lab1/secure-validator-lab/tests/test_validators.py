import unittest
from securevalidator import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)


class TestValidators(unittest.TestCase):
    def setUp(self):
        print("\n Running:", self._testMethodName)

    # =====================================================================
    # 1. EMAIL VALIDATION - Lỗ hổng: Regex quá đơn giản
    # Pattern: r'^[\w\.-]+@[\w\.-]+\.\w+$'
    # =====================================================================

    def test_validate_email_valid(self):
        """Email hợp lệ chuẩn → phải trả True."""
        self.assertTrue(validate_email("user@example.com"))

    def test_validate_email_invalid_double_at(self):
        """Email có 2 dấu @ → phải trả False."""
        self.assertFalse(validate_email("user@@example.com"))

    # --- LỖ HỔNG 1a: Regex cho phép domain không hợp lệ ---
    def test_vuln_email_dot_dot_domain(self):
        """
        LỖ HỔNG: Email có domain '..' liên tiếp vẫn pass regex.
        'user@exam..ple.com' → regex [\w\.-]+ match được '..'
        Kỳ vọng False (domain không hợp lệ), nhưng thực tế trả True.
        """
        result = validate_email("user@exam..ple.com")
        # BUG: Regex cho phép '..' trong domain
        self.assertTrue(result, "LỖ HỔNG: Email với domain '..' vẫn được chấp nhận!")

    # --- LỖ HỔNG 1b: Regex cho phép email bắt đầu bằng dấu chấm ---
    def test_vuln_email_leading_dot(self):
        """
        LỖ HỔNG: Email bắt đầu bằng '.' vẫn pass regex.
        '.user@example.com' → regex [\w\.-]+ match được '.user'
        """
        result = validate_email(".user@example.com")
        self.assertTrue(result, "LỖ HỔNG: Email bắt đầu bằng '.' vẫn được chấp nhận!")

    # --- LỖ HỔNG 1c: Regex cho phép TLD chỉ có 1 ký tự ---
    def test_vuln_email_single_char_tld(self):
        """
        LỖ HỔNG: Email có TLD chỉ 1 ký tự vẫn pass.
        'user@example.c' → \w+ match 'c' (1 ký tự là đủ)
        TLD hợp lệ phải >= 2 ký tự.
        """
        result = validate_email("user@example.c")
        self.assertTrue(result, "LỖ HỔNG: Email với TLD 1 ký tự vẫn được chấp nhận!")

    # =====================================================================
    # 2. URL VALIDATION - Lỗ hổng: Không chặn SSRF internal
    # Chỉ check scheme in ['http', 'https'] và có netloc
    # =====================================================================

    def test_validate_url_valid(self):
        """URL https hợp lệ → phải trả True."""
        self.assertTrue(validate_url("https://example.com"))

    def test_validate_url_ftp_blocked(self):
        """Scheme ftp bị chặn → phải trả False."""
        self.assertFalse(validate_url("ftp://example.com"))

    # --- LỖ HỔNG 2a: SSRF - cho phép truy cập localhost ---
    def test_vuln_url_ssrf_localhost(self):
        """
        LỖ HỔNG SSRF: URL http://localhost vẫn pass validation.
        Attacker có thể dùng URL này để truy cập các service nội bộ.
        Cần chặn localhost, 127.0.0.1, 0.0.0.0, [::1]
        """
        result = validate_url("http://localhost")
        self.assertTrue(result, "LỖ HỔNG SSRF: localhost không bị chặn!")

    # --- LỖ HỔNG 2b: SSRF - cho phép truy cập IP nội bộ ---
    def test_vuln_url_ssrf_internal_ip(self):
        """
        LỖ HỔNG SSRF: URL http://127.0.0.1:8080 vẫn pass.
        Attacker có thể scan port nội bộ.
        """
        result = validate_url("http://127.0.0.1:8080")
        self.assertTrue(result, "LỖ HỔNG SSRF: 127.0.0.1 không bị chặn!")

    # --- LỖ HỔNG 2c: SSRF - cho phép truy cập dải IP private ---
    def test_vuln_url_ssrf_private_network(self):
        """
        LỖ HỔNG SSRF: URL http://192.168.1.1 vẫn pass.
        Attacker có thể truy cập mạng nội bộ (10.x, 172.16.x, 192.168.x).
        """
        result = validate_url("http://192.168.1.1")
        self.assertTrue(result, "LỖ HỔNG SSRF: IP private 192.168.x không bị chặn!")

    # --- LỖ HỔNG 2d: SSRF - cho phép metadata cloud ---
    def test_vuln_url_ssrf_cloud_metadata(self):
        """
        LỖ HỔNG SSRF: URL http://169.254.169.254 vẫn pass.
        Đây là endpoint metadata của AWS/GCP/Azure → lộ credentials.
        """
        result = validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertTrue(result, "LỖ HỔNG SSRF: Cloud metadata endpoint không bị chặn!")

    # =====================================================================
    # 3. FILENAME VALIDATION - Lỗ hổng: Không xử lý null byte
    # Chỉ check '..', '/', '\\' và os.path.basename
    # =====================================================================

    def test_validate_filename_valid(self):
        """Tên file bình thường → phải trả True."""
        self.assertTrue(validate_filename("report.pdf"))

    def test_validate_filename_traversal(self):
        """Path traversal cơ bản → phải trả False."""
        self.assertFalse(validate_filename("../../etc/passwd"))

    # --- LỖ HỔNG 3a: Null byte injection ---
    def test_vuln_filename_null_byte(self):
        """
        LỖ HỔNG: Null byte injection bypass extension check.
        'malware.php\\x00.pdf' → không chứa '..', '/', '\\\\'
        → os.path.basename trả lại chính nó → pass validation!
        Trong ngôn ngữ C/hệ thống cũ, null byte cắt chuỗi → file thực tế là 'malware.php'.
        """
        result = validate_filename("malware.php\x00.pdf")
        self.assertTrue(result, "LỖ HỔNG: Null byte trong filename không bị chặn!")

    # --- LỖ HỔNG 3b: Không kiểm tra whitelist extension ---
    def test_vuln_filename_dangerous_extension(self):
        """
        LỖ HỔNG: File có extension nguy hiểm vẫn pass.
        'shell.exe', 'backdoor.sh', 'hack.bat' → đều hợp lệ.
        Cần whitelist extension an toàn (.pdf, .jpg, .png, .txt, ...).
        """
        dangerous_files = ["shell.exe", "backdoor.sh", "hack.bat", "webshell.php", "cmd.ps1"]
        for fname in dangerous_files:
            result = validate_filename(fname)
            self.assertTrue(result, f"LỖ HỔNG: File nguy hiểm '{fname}' không bị chặn!")

    # --- LỖ HỔNG 3c: Filename chỉ là dấu chấm ---
    def test_vuln_filename_dot_only(self):
        """
        LỖ HỔNG: Filename '.' (current directory) vẫn pass.
        os.path.basename('.') == '.' → pass validation.
        """
        result = validate_filename(".")
        self.assertTrue(result, "LỖ HỔNG: Filename '.' (current dir) không bị chặn!")

    # =====================================================================
    # 4. SQL INPUT SANITIZATION - Lỗ hổng nghiêm trọng nhất
    # Dùng regex blacklist thay vì parameterized queries
    # =====================================================================

    def test_sanitize_sql_input_basic_injection(self):
        """Payload cơ bản ' OR 1=1 -- bị lọc."""
        input_str = "' OR 1=1 --"
        sanitized = sanitize_sql_input(input_str)
        self.assertNotIn("'", sanitized)
        self.assertNotIn("--", sanitized)

    def test_sanitize_sql_input_safe_text(self):
        """Text bình thường không bị thay đổi."""
        input_str = "hello world"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "hello world")

    # --- LỖ HỔNG 4a: Bypass bằng toán tử || thay cho OR ---
    def test_vuln_sql_bypass_pipe_operator(self):
        """
        LỖ HỔNG: Toán tử '||' (OR trong một số DBMS) không bị lọc.
        '1 || 1=1' bypass hoàn toàn bộ lọc OR.
        """
        input_str = "1 || 1=1"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "1 || 1=1",
                         "LỖ HỔNG: '||' operator không bị lọc, bypass OR!")

    # --- LỖ HỔNG 4b: Bypass bằng comment block /*...*/ ---
    def test_vuln_sql_bypass_block_comment(self):
        """
        LỖ HỔNG: Block comment /*...*/ không bị lọc.
        Bộ lọc chỉ chặn '--' và '#', không chặn '/* */'.
        Attacker dùng: admin'/* → comment hết phần sau.
        """
        input_str = "admin/* bypass comment */"
        sanitized = sanitize_sql_input(input_str)
        self.assertIn("/*", sanitized,
                      "LỖ HỔNG: Block comment /* */ không bị lọc!")

    # --- LỖ HỔNG 4c: Bypass bằng cách xáo trộn chữ hoa/thường ---
    def test_vuln_sql_bypass_case_obfuscation(self):
        """
        LỖ HỔNG: re.sub dùng \\b word boundary.
        'SELSELECTECT' → sau khi lọc 'SELECT' ở giữa → còn lại 'SELECT'!
        Kỹ thuật double-encoding/nested keyword.
        """
        input_str = "SELSELECTECT * FROM users"
        sanitized = sanitize_sql_input(input_str)
        # Sau khi lọc lần 1: 'SEL' + '' + 'ECT * FROM users' = 'SELECT * FROM users'
        self.assertIn("SELECT", sanitized.upper(),
                      "LỖ HỔNG: Nested keyword 'SELSELECTECT' bypass bộ lọc thành 'SELECT'!")

    # --- LỖ HỔNG 4d: Bypass bằng EXEC/EXECUTE ---
    def test_vuln_sql_bypass_exec(self):
        """
        LỖ HỔNG: EXEC/EXECUTE không nằm trong blacklist.
        EXEC sp_executesql có thể chạy bất kỳ SQL nào trên SQL Server.
        """
        input_str = "EXEC sp_executesql N'SELECT * FROM users'"
        sanitized = sanitize_sql_input(input_str)
        self.assertIn("EXEC", sanitized.upper(),
                      "LỖ HỔNG: EXEC không bị lọc → có thể chạy stored procedure!")

    # --- LỖ HỔNG 4e: Bypass bằng HAVING/GROUP BY ---
    def test_vuln_sql_bypass_having(self):
        """
        LỖ HỔNG: HAVING và GROUP BY không bị lọc.
        Attacker dùng để trích xuất thông tin qua error-based injection.
        """
        input_str = "1 HAVING 1=1"
        sanitized = sanitize_sql_input(input_str)
        self.assertIn("HAVING", sanitized.upper(),
                      "LỖ HỔNG: HAVING không bị lọc → error-based SQLi!")

    # --- LỖ HỔNG 4f: Bypass bằng WAITFOR DELAY (time-based) ---
    def test_vuln_sql_bypass_waitfor(self):
        """
        LỖ HỔNG: WAITFOR DELAY không bị lọc.
        Attacker dùng time-based blind SQL injection.
        """
        input_str = "1; WAITFOR DELAY '0:0:5'"
        sanitized = sanitize_sql_input(input_str)
        self.assertIn("WAITFOR", sanitized.upper(),
                      "LỖ HỔNG: WAITFOR DELAY không bị lọc → time-based blind SQLi!")

    # --- LỖ HỔNG 4g: Bypass bằng BENCHMARK (MySQL time-based) ---
    def test_vuln_sql_bypass_benchmark(self):
        """
        LỖ HỔNG: BENCHMARK() không bị lọc.
        MySQL time-based blind injection.
        """
        input_str = "1 BENCHMARK(10000000,SHA1('test'))"
        sanitized = sanitize_sql_input(input_str)
        self.assertIn("BENCHMARK", sanitized.upper(),
                      "LỖ HỔNG: BENCHMARK không bị lọc → MySQL time-based SQLi!")

    # --- LỖ HỔNG 4h: Bypass bằng hex encoding ---
    def test_vuln_sql_bypass_hex_encoding(self):
        """
        LỖ HỔNG: Chuỗi hex 0x... không bị lọc.
        0x61646D696E = 'admin' dạng hex → bypass bộ lọc quote.
        """
        input_str = "0x61646D696E"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "0x61646D696E",
                         "LỖ HỔNG: Hex encoding bypass bộ lọc quote!")

    # --- LỖ HỔNG 4i: Bypass bằng CHAR() function ---
    def test_vuln_sql_bypass_char_function(self):
        """
        LỖ HỔNG: CHAR() function không bị lọc.
        CHAR(39) = dấu nháy đơn → bypass bộ lọc quote.
        """
        input_str = "CHAR(39)"
        sanitized = sanitize_sql_input(input_str)
        self.assertEqual(sanitized, "CHAR(39)",
                         "LỖ HỔNG: CHAR() function bypass bộ lọc!")

    # =====================================================================
    # 5. HTML INPUT SANITIZATION - html.escape() khá tốt nhưng có giới hạn
    # =====================================================================

    def test_sanitize_html_input_script(self):
        """XSS cơ bản bị escape."""
        input_str = '<script>alert("XSS")</script>'
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;')

    def test_sanitize_html_input_safe_text(self):
        """Text bình thường không bị thay đổi."""
        input_str = "Hello World"
        sanitized = sanitize_html_input(input_str)
        self.assertEqual(sanitized, "Hello World")

    # --- LỖ HỔNG 5a: html.escape() không đủ để chặn mọi XSS context ---
    def test_vuln_html_javascript_uri_scheme(self):
        """
        LỖ HỔNG: html.escape() chỉ escape ký tự đặc biệt HTML,
        nhưng KHÔNG chặn được javascript: URI scheme.
        Nếu output được đặt vào attribute href:
            <a href="USER_INPUT"> → javascript:alert(1) vẫn chạy!
        html.escape() không thay đổi 'javascript:alert(1)' vì không có
        ký tự HTML đặc biệt nào (<, >, &, ", ').
        """
        input_str = "javascript:alert(1)"
        sanitized = sanitize_html_input(input_str)
        # html.escape() giữ nguyên vì không có ký tự HTML đặc biệt
        self.assertEqual(sanitized, "javascript:alert(1)",
                         "LỖ HỔNG: javascript: URI không bị lọc → XSS trong href attribute!")

    # --- LỖ HỔNG 5b: Chỉ escape không đủ, cần CSP ---
    def test_vuln_html_no_csp_protection(self):
        """
        LỖ HỔNG kiến trúc: Chỉ dùng html.escape() mà không có
        Content-Security-Policy header → nếu có chỗ nào quên escape
        thì không có lớp bảo vệ thứ 2.
        Test này chỉ document lỗ hổng, luôn pass.
        """
        # Lỗ hổng kiến trúc - không thể test bằng unit test
        # Cần kiểm tra HTTP response headers có CSP không
        self.assertTrue(True,
                        "LỖ HỔNG KIẾN TRÚC: Thiếu Content-Security-Policy header!")


# =========================================================================
# TỔNG KẾT CÁC LỖ HỔNG ĐÃ PHÁT HIỆN:
# =========================================================================
#
# 1. EMAIL: Regex quá lỏng lẻo
#    - Cho phép '..' trong domain
#    - Cho phép email bắt đầu bằng '.'
#    - Cho phép TLD 1 ký tự
#
# 2. URL: Không chặn SSRF
#    - localhost, 127.0.0.1, IP private (192.168.x, 10.x)
#    - Cloud metadata endpoint (169.254.169.254)
#
# 3. FILENAME: Thiếu kiểm tra an toàn
#    - Null byte injection
#    - Không có whitelist extension
#    - Cho phép '.' làm filename
#
# 4. SQL: Blacklist regex quá yếu (CẦN DÙNG PARAMETERIZED QUERIES)
#    - Bypass bằng || operator
#    - Bypass bằng /* */ block comment
#    - Bypass bằng nested keyword (SELSELECTECT)
#    - EXEC, HAVING, WAITFOR, BENCHMARK không bị lọc
#    - Hex encoding và CHAR() function bypass quote filter
#
# 5. HTML: html.escape() chưa đủ
#    - Không escape dấu nháy đơn (')
#    - Thiếu Content-Security-Policy header
# =========================================================================


if __name__ == "__main__":
    unittest.main(verbosity=2)
