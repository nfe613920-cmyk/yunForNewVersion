import sys
sys.path.append("..")
from main import encrypt_sm4, decrypt_sm4, b64decode
import requests
import json
import time
import hashlib
import configparser


config = configparser.ConfigParser()
config.read('config.ini', encoding='utf-8')
default_key =  config.get("Yun", "cipherkey")
CipherKeyEncrypted = config.get("Yun", "cipherkeyencrypted")


def md5_encryption(data):
    md5 = hashlib.md5()  # 创建一个md5对象
    md5.update(data.encode('utf-8'))  # 使用utf-8编码数据
    return md5.hexdigest()  # 返回加密后的十六进制字符串

def getschool_Url_Id(schoolName): 
    utc = str(int(time.time()))
    uuid = "2211725972932675"
    sign_data = f'platform=android&utc={utc}&uuid={uuid}&appsecret=pie0hDSfMRINRXc7s1UIXfkE'
    sign = md5_encryption(sign_data)
    url = "http://sports.aiyyd.com:9001/api/app/schoolList"
    headers = {
        "isApp": "app",
        "deviceId": uuid,
        "deviceName": "Xiaomi",
        "version": "3.4.7",
        "platform": "android",
        "uuid": uuid,
        "utc": utc,
        "sign": sign,
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": "217",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.12.0"
    }
    data_json = {
        "cipherKey": CipherKeyEncrypted,
        "content": encrypt_sm4("", b64decode(default_key),isBytes=False)
    }
    req = requests.post(url=url, data=json.dumps(data_json), headers=headers)
    infojson = json.loads(decrypt_sm4(req.text, b64decode(default_key)).decode())
    if infojson.get('code') != 200:
        print("请求失败，请检查输入或网络。")
        return None, None
    if infojson.get('code') == 200:
        for school in infojson.get('data', []):
            if school.get('schoolName') == schoolName:
                schoolUrl = school.get('schoolUrl').rstrip('/')
                schoolId = school.get('schoolId')
                return schoolUrl, schoolId
        else:
            print("未找到匹配的学校名称")
            return None, None

def writeUrlToConfig(schoolUrl, schoolId):
    current_school_host = config.get("Yun", "school_host")
    current_school_id = config.get("Yun", "school_id")
    if schoolUrl != current_school_host or str(schoolId) != current_school_id:
        print("schoolUrl:",schoolUrl)
        print("schoolId:",schoolId)
        config.set("Yun", "school_host", schoolUrl)
        config.set("Yun", "school_id", str(schoolId))
        with open('config.ini', 'w', encoding='utf-8') as configfile:
            config.write(configfile)
    else:
        print("当前学校URL和ID与配置文件中的一致，无需更新。")

if __name__ == '__main__':
    schoolName = input("请输入学校名称：")
    url, schoolId = getschool_Url_Id(schoolName)
    writeUrlToConfig(url, schoolId)