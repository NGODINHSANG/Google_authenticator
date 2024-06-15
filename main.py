import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.image import Image
from kivy.uix.button import Button
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics.texture import Texture
import cv2
import pyotp
from pyzbar.pyzbar import decode
import base64
import hmac
import hashlib
import time
import struct
import urllib.parse as urlparse
import json
import os

Window.size = (360, 640)

class AddAccountPopup(Popup):
    def __init__(self, main_app, **kwargs):
        super(AddAccountPopup, self).__init__(**kwargs)
        self.main_app = main_app

    def add_account(self):
        email = self.ids.email_input.text
        service = self.ids.service_input.text
        secret = pyotp.random_base32()
        self.main_app.add_account(email, service, secret)
        self.dismiss()

class ScanQrPopup(Popup):
    def __init__(self, main_app, **kwargs):
        super(ScanQrPopup, self).__init__(**kwargs)
        self.main_app = main_app
        self.capture = cv2.VideoCapture(0)
        Clock.schedule_interval(self.update, 1.0 / 30.0)

    def update(self, dt):
        ret, frame = self.capture.read()
        if ret:
            buffer = cv2.flip(frame, 0).tostring()
            texture = Texture.create(size=(frame.shape[1], frame.shape[0]), colorfmt='bgr')
            texture.blit_buffer(buffer, colorfmt='bgr', bufferfmt='ubyte')
            self.ids.qr_image.texture = texture

            # Quét và giải mã QR code
            decoded_objects = decode(frame)
            for obj in decoded_objects:
                otp_uri = obj.data.decode('utf-8')
                account_info = parse_otp_uri(otp_uri)
                self.main_app.add_account(account_info['account_name'], account_info['issuer'], account_info['secret'])
                self.capture.release()
                self.dismiss()
                return

    def on_dismiss(self):
        self.capture.release()

class MyAuthenticatorApp(App):
    def build(self):
        self.authenticator = MyAuthenticator()
        self.authenticator.load_accounts()
        Clock.schedule_interval(self.authenticator.update_otps, 30)
        return self.authenticator

class MyAuthenticator(BoxLayout):
    def __init__(self, **kwargs):
        super(MyAuthenticator, self).__init__(**kwargs)
        self.accounts = []

    def add_account(self, email, service, secret):
        account = {
            'email': email,
            'service': service,
            'secret': secret
        }
        self.accounts.append(account)
        self.ids.accounts_list.add_widget(AccountItem(account))
        self.save_accounts()

    def show_add_account_popup(self):
        popup = AddAccountPopup(self)
        popup.open()

    def show_scan_qr_popup(self):
        popup = ScanQrPopup(self)
        popup.open()

    def update_otps(self, *args):
        for account_item in self.ids.accounts_list.children:
            account_item.update_otp()

    def save_accounts(self):
        with open("accounts.json", "w") as f:
            json.dump(self.accounts, f)

    def load_accounts(self):
        if os.path.exists("accounts.json"):
            with open("accounts.json", "r") as f:
                self.accounts = json.load(f)
            for account in self.accounts:
                self.ids.accounts_list.add_widget(AccountItem(account))

class AccountItem(BoxLayout):
    def __init__(self, account, **kwargs):
        super(AccountItem, self).__init__(**kwargs)
        self.account = account
        self.ids.email_label.text = account['email']
        self.ids.service_label.text = account['service']
        self.update_otp()

    def update_otp(self):
        otp = self.get_totp_token(self.account['secret'])
        self.ids.otp_label.text = otp

    def get_totp_token(self, secret, intervals_no=None):
        if intervals_no is None:
            intervals_no = int(time.time()) // 30

        key = base64.b32decode(secret.upper())
        msg = struct.pack(">Q", intervals_no)
        hmac_sha1 = hmac.new(key, msg, hashlib.sha1).digest()
        o_offset = hmac_sha1[-1] & 0x0F
        binary = struct.unpack(">I", hmac_sha1[o_offset:o_offset + 4])[0] & 0x7FFFFFFF
        otp = binary % 1000000
        return str(otp).zfill(6)

def parse_otp_uri(otp_uri):
    parsed_url = urlparse.urlparse(otp_uri)
    params = urlparse.parse_qs(parsed_url.query)
    secret = params.get('secret', [None])[0]
    account_name = urlparse.unquote(parsed_url.path.split(':')[-1])
    issuer = params.get('issuer', [None])[0]
    return {
        'secret': secret,
        'account_name': account_name,
        'issuer': issuer
    }

if __name__ == '__main__':
    MyAuthenticatorApp().run()
