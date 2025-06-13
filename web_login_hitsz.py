import requests
import urllib3
import time
import random
import json
import base64
import pickle
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from point_picker import pick_points
from getpass import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ATRUST_HOST = "vpn.zju.edu.cn"
ATRUST_HOST = "trust.hitsz.edu.cn"

HITIDS_HOST = "https://ids-hit-edu-cn-s.hitsz.edu.cn"

ATRUST_API_HEADERS = {
    # "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US",
    "Connection": "keep-alive",
    # "Content-Type": "application/json;charset=utf-8",
    # 不要设 Host 和 Content-Type，request 会自动设置；设置了还会影响联合登录
    # "Host": ATRUST_HOST,
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType",
}


class ATrustSession:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(ATRUST_API_HEADERS)

    def login(self, username, password, deviceId, useCasLogin=None, interactive=True):
        """
        1. authConfig | checkMITMAttack | getEnv
        2. psw
        3. checkCode (first time)
        4. authConfig | checkMITMAttack | getEnv
        5. psw/checkCode
        ?  reportEnv ? reportEnvBeforeLogin
        6. authCheck
        7. sms/sendSms | phoneNumber | sms/checkcode
        8. onlineInfo
        9. clientResource
            start | status | init
        """

        self.username = username
        self.password = password
        self.deviceId = deviceId

        self.response = {}
        self.csrfToken = ""

        self.rid = base64.b64encode(ATRUST_HOST.encode())
        self.env = base64.b64encode(
            f'{{"deviceId":"{self.deviceId}"}}'.encode()
        ).decode()

        # start

        self.authConfig()

        if self.response["authConfig"]["data"]["isLogin"] == 1:
            print("already logged in")
            return

        if useCasLogin:
            self.useCasLogin = useCasLogin
            self.casLogin(interactive=interactive)
            self.authConfig(need_ticket=False, mod=True)
        else:
            self.psw()
            print("next", self.response["psw"]["data"]["nextService"])

            # while True:
            if self.response["psw"]["data"]["nextService"] == "auth/psw":
                self.checkCode()
                self.authConfig()
                self.psw(self.graphCheckCode)
                print(self.response["psw"]["data"]["nextService"])

        # self.reportEnvBeforeLogin()
        self.reportEnv()

        self.authCheck()
        print("next", self.response["authCheck"]["data"]["nextService"])

        if self.response["authCheck"]["data"]["nextService"] == "auth/sms":
            self.sendSms()
            self.phoneNumber()
            self.smsCheckCode()

        self.onlineInfo()

        self.clientResource()

    def authConfig(self, need_ticket=True, mod=False):
        print("authConfig")

        params = (
            {
                "clientType": "SDPClient",
                "platform": "Linux",
                "lang": "en-US",
            }
            | ({"needTicket": "1"} if need_ticket else {})
            | ({"mod": "1"} if mod else {})
        )

        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-rid": self.rid,
            "x-sdp-traceid": self.randSdpId(),
        }
        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/public/authConfig",
            params=params,
            headers=headers,
        )
        print(response.status_code)

        self.response["authConfig"] = response.json()
        self.csrfToken = self.response["authConfig"]["data"]["security"]["csrfToken"]

        with open("logs/authConfig.json", "w") as f:
            f.write(response.text)

    def psw(self, other_params={}):
        print("psw")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-env": self.env,
            "x-sdp-traceid": self.randSdpId(),
        }

        N = int(self.response["authConfig"]["data"]["pubKey"], 16)
        E = int(self.response["authConfig"]["data"]["pubKeyExp"], 10)
        antiReplayRand = self.response["authConfig"]["data"]["antiReplayRand"]
        message = (self.password + "_" + antiReplayRand).encode("utf-8")

        public_numbers = rsa.RSAPublicNumbers(E, N)
        public_key = public_numbers.public_key()
        ciphertext = public_key.encrypt(message, padding.PKCS1v15())
        encrypted_password = ciphertext.hex()

        json_data = {
            "username": self.username + "@Radius",
            "password": encrypted_password,
            "rememberPwd": "0",
            **other_params,
        }

        response = self.session.post(
            f"https://{ATRUST_HOST}/passport/v1/auth/psw",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)

        self.response["psw"] = response.json()
        with open("logs/psw.json", "w") as f:
            f.write(response.text)

    def casLogin(self, interactive=False):
        print("=== 正在为你登录*本部*统一身份认证平台 ===")
        if self.password and self.username:
            self.casLogin_pwd()
            return

        if not interactive:
            raise Exception("[!] 未提供用户名或密码，且处于非交互会话中，无法继续。")
        choice = input("未提供用户名或密码，要使用二维码登录吗？[Y/n] ")
        if choice.lower().startswith("n"):
            if not self.username:
                self.username = input("用户名（学号）：").strip()
            else:
                print(f"用户名（学号）：{self.username}")

            from idshit.pwd_login import check_need_captcha

            try:
                need_captcha = check_need_captcha(
                    self.session, self.username, ids_host=HITIDS_HOST
                )
            except:
                print("[!] 无法获取 need capcha 信息！请检查网络。")
                raise

            if need_captcha:
                msg = "[!] 你的统一身份认证账号当前需要安全验证，atrust-experiment-proto 无法为你完成密码登录。请你用浏览器自行完成一次登录后再尝试使用此工具，或改用扫码登录方式。"
                print(msg)
                raise NotImplementedError(msg)

            if not self.password:
                self.password = getpass("密码：")
            self.casLogin_pwd()
        else:
            self.casLogin_qr()

    def casLogin_pwd(self):
        res = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/public/casLogin",
            params={"sfDomain": self.useCasLogin},
            allow_redirects=False,
        )

        if HITIDS_HOST not in res.headers["Location"]:
            raise Exception(
                f"未能进入统一身份认证。跳转网址断言异常！#{res.headers['Location']}#"
            )

        from idshit.pwd_login import auth_login

        err, res = auth_login(
            self.session,
            self.username.strip(),
            self.password,
            # 也可从 res.headers["Location"] 中获得
            service=f"https://{ATRUST_HOST}:443/passport/v1/auth/cas?sfDomain={self.useCasLogin}",
            ids_host=HITIDS_HOST,
        )
        if not res.ok:
            print(f"[!] 统一身份认证登录请求失败！（{res.status_code}）")
        if err:
            raise Exception(f"统一身份认证登录失败：{err}")

        if ATRUST_HOST not in res.url:
            raise Exception(f"统一身份认证登录失败。跳转网址断言异常！#{res.url}#")

        self.response["casLogin"] = res.content
        print("=== 统一身份认证登录成功 ===")

    def casLogin_qr(self):
        res = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/public/casLogin",
            params={"sfDomain": self.useCasLogin},
            allow_redirects=False,
        )

        if HITIDS_HOST not in res.headers["Location"]:
            raise Exception(
                f"未能进入统一身份认证。跳转网址断言异常！#{res.headers['Location']}#"
            )

        from idshit.qr_login import get_qr_token, get_qr_image, get_status, login

        qr_token = get_qr_token(self.session, ids_host=HITIDS_HOST)
        print("[i] 请用哈工大 APP 扫描以下二维码：")
        print(HITIDS_HOST + "/authserver/qrCode/getCode?uuid=" + qr_token)

        qr_img = get_qr_image(self.session, qr_token, ids_host=HITIDS_HOST)

        try:
            from PIL import Image
            import io

            qr_img = Image.open(io.BytesIO(qr_img))
            from textual_image.renderable import Image
            import rich

            rich.print(Image(qr_img))
        except:
            print(
                "[!] 无法在你的终端中显示二维码。请在浏览器中打开以上网址来查看二维码图像。"
            )

        login_status = "0"
        while login_status != "1":
            input("当你在移动设备上确认登录后，按下回车：")
            login_status = get_status(self.session, qr_token, ids_host=HITIDS_HOST)
            if login_status == "0":
                print("[i] 尚未扫码！")
            elif login_status == "2":
                print("[i] 请在移动设备上确认登录。")
            elif login_status != "1":
                print("[!] 二维码已失效，请重试。")
                if login_status != "3":
                    print(
                        f'[!] 未知的 login_status "{login_status}"，请向开发者报告此情况。'
                    )
                raise Exception("统一身份认证二维码已失效")

        err, res = login(
            self.session,
            qr_token,
            service=f"https://{ATRUST_HOST}:443/passport/v1/auth/cas?sfDomain=hitcas",
            ids_host=HITIDS_HOST,
        )
        if not res.ok:
            print(f"[!] 统一身份认证登录请求失败！（{res.status_code}）")
        if err:
            raise Exception(f"统一身份认证登录失败：{err}")

        if ATRUST_HOST not in res.url:
            raise Exception(f"统一身份认证登录失败。跳转网址断言异常！#{res.url}#")

        self.response["casLogin"] = res.content
        print("=== 统一身份认证登录成功 ===")

    def checkCode(self):
        print("checkCode")

        headers = {
            "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
        }

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
            "rnd": str(int(time.time() * 1000)),
        }

        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/public/checkCode",
            params=params,
            headers=headers,
        )
        print(response.status_code)

        with open("logs/checkCode.jpg", "wb") as f:
            f.write(response.content)

        self.graphCheckCode = {
            "graphCheckCode": json.dumps(pick_points(response.content)),
        }

        print("checkCode: ", self.graphCheckCode)

    def reportEnvBeforeLogin(self):
        print("reportEnvBeforeLogin")

        guid = self.response["authConfig"]["data"]["guid"]
        ticket = self.response["psw"]["data"]["ticket"]
        antiMITMAttackData = self.response["authConfig"]["data"]["antiMITMAttackData"]
        json_data = {
            "addr": f"https://{ATRUST_HOST}",
            "type": "web",
            "guid": guid,
            "lang": "en-US",
            "sdpTraceId": self.randSdpId(),
            "token": "",
            "data": {
                "ticket": ticket,
                "timing": "pre-login",
                "antiMITMAttackData": antiMITMAttackData,
            },
        }

        response = self.session.post(
            f"https://{ATRUST_HOST}/v1/service/reportEnvBeforeLogin",
            json=json_data,
        )

        print(response.status_code)

        self.response["reportEnvBeforeLogin"] = response.json()
        with open("logs/reportEnvBeforeLogin.json", "w") as f:
            f.write(response.text)

    def reportEnv(self):
        print("reportEnv")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        if self.useCasLogin:
            ticket = self.response["authConfig"]["data"]["antiMITMAttackData"]["ticket"]
            print("using ticket", ticket)
        else:
            ticket = self.response["psw"]["data"]["ticket"]

        json_data = {
            "ticket": ticket,
            "deviceId": self.deviceId,
            "env": {
                "endpoint": {
                    "device_id": self.deviceId,
                    "device": {
                        "type": "browser",
                    },
                },
            },
        }

        response = self.session.post(
            f"https://{ATRUST_HOST}/controller/v1/public/reportEnv",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)
        print("message:", response.json()["message"])

        with open("logs/reportEnv.json", "w") as f:
            f.write(response.text)

    def authCheck(self):
        print("authCheck")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/auth/authCheck",
            params=params,
            headers=headers,
        )
        print(response.status_code)
        sid = self.session.cookies.get("sid")
        print("sid:", sid)

        print("message:", response.json()["message"])

        self.response["authCheck"] = response.json()
        with open("logs/authCheck.json", "w") as f:
            f.write(response.text)

    def sendSms(self):
        print("sendSms")

        authId = self.response["authCheck"]["data"]["nextServiceList"][0]["authId"]
        params = {
            "action": "sendsms",
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
            "isPrevEffect": "0",
            "taskId": "",
            "authId": authId,
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/auth/sms",
            params=params,
            headers=headers,
        )
        print(response.status_code)
        print("message:", response.json()["message"])

        with open("logs/sendSms.json", "w") as f:
            f.write(response.text)

    def phoneNumber(self):
        print("phoneNumber")
        pass

    def smsCheckCode(self):
        print("smsCheckCode")

        params = {
            "action": "checkcode",
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        # input sms checkCode
        checkCode = input("input sms checkCode: ")

        authId = self.response["authCheck"]["data"]["nextServiceList"][0]["authId"]
        json_data = {
            "isPrevEffect": False,
            "code": checkCode,
            "skipSecondaryAuth": "0",
            "taskId": "",
            "authId": authId,
        }

        response = self.session.post(
            f"https://{ATRUST_HOST}/passport/v1/auth/sms",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)
        print("message:", response.json()["message"])

        with open("logs/smsCheckCode.json", "w") as f:
            f.write(response.text)

    def onlineInfo(self):
        print("onlineInfo")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/user/onlineInfo",
            params=params,
            headers=headers,
        )
        print(response.status_code)
        print("message:", response.json()["message"])


        with open("logs/onlineInfo.json", "w") as f:
            f.write(response.text)

    def clientResource(self):
        print("clientResource")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        json_data = {
            "resourceType": {
                "sdpPolicy": {},
                "appList": {},
                "favoriteAppList": {},
                "featureCenter": {},
                "uemSpace": {
                    "params": {
                        "action": "login",
                    },
                },
            },
        }

        response = self.session.post(
            f"https://{ATRUST_HOST}/controller/v1/user/clientResource",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)
        print("message:", response.json()["message"])

        with open("logs/clientResource.json", "w") as f:
            f.write(response.text)

    def queryDevice(self):
        print("queryDevice")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
            "status": "untrust",
        }
        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-traceid": self.randSdpId(),
        }

        response = self.session.get(
            f"https://{ATRUST_HOST}/passport/v1/security/queryDevice",
            params=params,
            headers=headers,
        )
        print(response.status_code)

        with open("logs/queryDevice.json", "w") as f:
            f.write(response.text)

    def randSdpId(self, length=8):
        return "".join(hex(random.randint(0, 15))[2:] for _ in range(length))

    def load(self, filename="session.pickle"):
        with open(filename, "rb") as f:
            self.session = pickle.load(f)

    def save(self, filename="session.pickle"):
        with open(filename, "wb") as f:
            pickle.dump(self.session, f)


if __name__ == "__main__":
    session = ATrustSession()
    os.makedirs("logs", exist_ok=True)
    try:
        session.load("logs/session.pickle")
    except FileNotFoundError:
        pass

    username = ""
    password = ""
    # username = "2024311000"
    # password = "xxxxxxxxxx"

    deviceId = "".join(hex(random.randint(0, 15))[2:] for _ in range(32)).upper()
    # deviceId = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("deviceId: ", deviceId)

    session.login(username, password, deviceId, useCasLogin="hitcas")
    print("sid: ", session.session.cookies.get("sid"))

    session.queryDevice()
    session.save("logs/session.pickle")
