import pyotp
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
import urllib.parse as urlparse
import base64
import hmac
import hashlib
import time
import struct

# Tạo mã bí mật ngẫu nhiên
def create_secret():
    return pyotp.random_base32()

# Tạo mã QR từ mã bí mật và thông tin người dùng
def generate_qr_code(secret, user_email, issuer_name):
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(user_email, issuer_name=issuer_name)
    qr = qrcode.make(otp_uri)
    qr.save("otp_qr_1.png")
    return otp_uri

# Giải mã mã QR để lấy URI OTPAuth
def decode_qr_code(file_path):
    qr_image = Image.open(file_path)
    decoded_objects = decode(qr_image)
    for obj in decoded_objects:
        otp_uri = obj.data.decode('utf-8')
        return otp_uri
    return None

# Phân tích URI OTPAuth để lấy thông tin
def parse_otp_uri(otp_uri):
    parsed_url = urlparse.urlparse(otp_uri)
    params = urlparse.parse_qs(parsed_url.query)
    
    # Trích xuất các thông tin cần thiết và giải mã URL
    secret = params.get('secret', [None])[0]
    account_name = urlparse.unquote(parsed_url.path.split(':')[-1])
    issuer = params.get('issuer', [None])[0]

    return {
        'secret': secret,
        'account_name': account_name,
        'issuer': issuer
    }

# Tạo mã OTP
def get_totp_token(secret, intervals_no=None):
    if intervals_no is None:
        intervals_no = int(time.time()) // 30

    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", intervals_no)
    hmac_sha1 = hmac.new(key, msg, hashlib.sha1).digest()
    o_offset = hmac_sha1[-1] & 0x0F
    binary = struct.unpack(">I", hmac_sha1[o_offset:o_offset + 4])[0] & 0x7FFFFFFF
    otp = binary % 1000000

    return str(otp).zfill(6)

# Xác thực mã OTP
def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

# Chạy ứng dụng
if __name__ == "__main__":
    # user_email = "sangnd@example.com"
    # issuer_name = "SecondService"
    # secret = create_secret()
    # print("Mã bí mật của bạn là:", secret)

    # # Tạo mã QR
    # otp_uri = generate_qr_code(secret, user_email, issuer_name)
    # print("URI OTPAuth là:", otp_uri)

    # Giải mã mã QR
    decoded_otp_uri = decode_qr_code("otp_qr_1.png")
    print("URI OTPAuth giải mã là:", decoded_otp_uri)

    # Phân tích URI OTPAuth
    otp_info = parse_otp_uri(decoded_otp_uri)
    secret = otp_info['secret']
    print("Thông tin phân tích từ URI OTPAuth:")
    print(f"Mã bí mật: {otp_info['secret']}")
    print(f"Tên tài khoản: {otp_info['account_name']}")
    print(f"Tên dịch vụ: {otp_info['issuer']}")

    # Tạo mã OTP
    # otp = get_totp_token(secret)
    # print(f"Mã OTP là: {otp}")

    # Xác thực mã OTP
    user_otp = input("Nhập mã OTP: ")
    if verify_otp(secret, user_otp):
        print("Xác thực thành công!")
    else:
        print("Mã OTP không hợp lệ.")
