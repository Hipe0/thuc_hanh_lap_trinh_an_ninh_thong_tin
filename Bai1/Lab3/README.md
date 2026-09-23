# Phân tích và Khắc phục lỗ hổng Masking PII trong Lab 3

Tài liệu này ghi chú lại quá trình phát hiện, khai thác (bypass) và đề xuất cách khắc phục lỗ hổng trong cơ chế che dấu dữ liệu nhạy cảm (PII Masking) của module `SecureLogger`.

## 1. Mô tả lỗ hổng (Vulnerability)

Trong `logger.py`, cơ chế che dấu dữ liệu nhạy cảm (như email, password, token) đang sử dụng Biểu thức chính quy (Regex) chưa đủ chặt chẽ:

```python
PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{8,}["\']?'
}
```

**Các điểm yếu:**
1. **Email:** Ký tự `\w` không bao gồm dấu cộng (`+`). Nếu người dùng nhập email có định dạng sub-addressing (ví dụ: `hacker+admin@example.com`), phần `hacker+` sẽ không bị bôi đen, dẫn đến lộ một phần thông tin.
2. **Password/Token:** Regex đang tìm kiếm chuỗi có định dạng gán bằng (ví dụ: `password=...`). Tuy nhiên, khi ứng dụng nhận JSON và biến đổi thành Python Dictionary (hoặc chuỗi JSON), định dạng của nó là `{'password': '...'}` hoặc `"password": "..."`. Do không có dấu `=`, Regex bị "mù" hoàn toàn và bỏ qua việc che giấu.

## 2. Chứng minh lỗ hổng (Proof of Concept - PoC)

### Payload sử dụng trong Postman
Gửi một request `POST` đến `/validate` với nội dung Body (JSON) như sau:

```json
{
    "email": "hacker+admin@example.com",
    "password": "SuperSecretPassword123",
    "token": "admin_token_xyz_999"
}
```

![Postman Payload](link_anh_postman_o_day)

### Kết quả trong file `secure.log`
Khi mở file log, ta thấy:

```json
"data": "{'email': 'hacker+<email_masked>', 'password': 'SuperSecretPassword123', 'token': 'admin_token_xyz_999'}"
```

Nhìn vào log, ta dễ dàng nhận thấy:
- Một phần định danh email (`hacker+`) bị lộ.
- Mật khẩu (`SuperSecretPassword123`) và Token (`admin_token_xyz_999`) **bị lộ hoàn toàn dưới dạng rõ (plaintext)** thay vì bị đổi thành `<password_masked>`.

![Bypass Log Result](link_anh_log_o_day)

## 3. Đề xuất khắc phục (Remediation)

Để vá các lỗ hổng này, chúng ta cần cập nhật lại cấu trúc của `PII_PATTERNS` trong file `logger.py` sao cho nó bao quát được các ký tự đặc biệt trong email và cả các định dạng chuỗi JSON/Dictionary.

**Cách khắc phục 1: Cập nhật Regex (Sửa đổi trực tiếp)**
Sửa nội dung `PII_PATTERNS` trong `logger.py` thành:

```python
PII_PATTERNS = {
    # Thêm dấu + và các ký tự hợp lệ khác vào regex email
    "email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    
    # Cho phép cả dấu '=' và ':' (kèm khoảng trắng) để bắt được định dạng Dictionary và JSON
    "token": r'(?i)(token|apikey|key|password)\s*(=|:)\s*["\']?[\w\-]{8,}["\']?'
}
```

**Cách khắc phục 2: Khử nhạy cảm ở cấp độ Object (Best Practice)**
Việc dùng Regex trên một chuỗi `str(dict)` luôn tiềm ẩn rủi ro. Cách tốt nhất trong thực tế là duyệt qua các `key` của Dictionary trước khi nó bị biến thành chuỗi:

```python
def mask_dict_pii(data_dict):
    sensitive_keys = ['password', 'token', 'apikey', 'key']
    if isinstance(data_dict, dict):
        for k in data_dict.keys():
            if str(k).lower() in sensitive_keys:
                data_dict[k] = "<masked>"
            elif isinstance(data_dict[k], str):
                # Vẫn dùng regex cho email
                data_dict[k] = mask_pii(data_dict[k])
    return data_dict
```
Phương pháp này đảm bảo không một password hay token nào có thể lọt qua dù cho người dùng có nhập định dạng rắc rối đến đâu.
