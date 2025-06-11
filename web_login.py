import requests
import urllib3
import time
import random
import json
import base64
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from point_picker import pick_points

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ATrustSession:
    def __init__(self):
        self.session = requests.Session()
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US",
            "Connection": "keep-alive",
            "Content-Type": "application/json;charset=utf-8",
            "Host": "vpn.zju.edu.cn",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType",
        }
        self.session.headers.update(headers)

    def login(self, username, password, deviceId):
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

        self.rid = base64.b64encode("vpn.zju.edu.cn".encode())
        self.env = base64.b64encode(
            f'{{"deviceId":"{self.deviceId}"}}'.encode()
        ).decode()

        # start

        self.authConfig()

        if self.response["authConfig"]["data"]["isLogin"] == 1:
            print("already logged in")
            return

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

    def authConfig(self):
        print("authConfig")

        params = {
            "clientType": "SDPClient",
            "platform": "Linux",
            "lang": "en-US",
            "needTicket": "1",
        }

        headers = {
            "x-csrf-token": self.csrfToken,
            "x-sdp-rid": self.rid,
            "x-sdp-traceid": self.randSdpId(),
        }
        response = self.session.get(
            "https://vpn.zju.edu.cn/passport/v1/public/authConfig",
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
            "https://vpn.zju.edu.cn/passport/v1/auth/psw",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)

        self.response["psw"] = response.json()
        with open("logs/psw.json", "w") as f:
            f.write(response.text)

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
            "https://vpn.zju.edu.cn/passport/v1/public/checkCode",
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
            "addr": "https://vpn.zju.edu.cn",
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
            "https://vpn.zju.edu.cn/v1/service/reportEnvBeforeLogin",
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
            "https://vpn.zju.edu.cn/controller/v1/public/reportEnv",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)

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
            "https://vpn.zju.edu.cn/passport/v1/auth/authCheck",
            params=params,
            headers=headers,
        )
        print(response.status_code)
        sid = response.cookies.get("sid")
        print("sid:", sid)

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
            "https://vpn.zju.edu.cn/passport/v1/auth/sms",
            params=params,
            headers=headers,
        )
        print(response.status_code)

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
            "https://vpn.zju.edu.cn/passport/v1/auth/sms",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)

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
            "https://vpn.zju.edu.cn/passport/v1/user/onlineInfo",
            params=params,
            headers=headers,
        )
        print(response.status_code)

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
            "https://vpn.zju.edu.cn/controller/v1/user/clientResource",
            params=params,
            json=json_data,
            headers=headers,
        )
        print(response.status_code)

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
            "https://vpn.zju.edu.cn/passport/v1/security/queryDevice",
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
    try:
        # mkdir logs
        session.load("logs/session.pickle")
    except FileNotFoundError:
        pass

    username = "22222222"
    password = "xxxxxxxx"

    deviceId = "".join(hex(random.randint(0, 15))[2:] for _ in range(32)).upper()
    # deviceId = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("deviceId:", deviceId)

    session.login(username, password, deviceId)
    print("sid:", session.session.cookies.get("sid"))

    session.queryDevice()
    session.save("logs/session.pickle")
