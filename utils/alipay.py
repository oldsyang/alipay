# -*- coding: utf-8 -*-
# @Author  : oldsyang
import json
from base64 import b64encode, b64decode
from datetime import datetime
from urllib import quote_plus

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class AliPay(object):
    """
    支付宝支付接口
    """

    def __init__(self, appid, app_notify_url, app_private_key_path, return_url, debug=True):
        '''

        :param appid: 帐号id
        :param app_notify_url: 
        :param app_private_key_path: 在我们本地存放的私钥路径
        :param return_url: 支付成功后跳转的路径
        :param debug: 调式模式（也就是我们的沙箱中）
        '''
        self.appid = appid
        self.app_notify_url = app_notify_url
        self.app_private_key_path = app_private_key_path
        self.app_private_key = None
        self.return_url = return_url
        with open(self.app_private_key_path) as fp:
            self.app_private_key = RSA.importKey(fp.read())

        if debug is True:
            self.__gateway = "https://openapi.alipaydev.com/gateway.do"
        else:
            self.__gateway = "https://openapi.alipay.com/gateway.do"

    def direct_pay(self, subject, out_trade_no, total_amount, return_url=None, **kwargs):
        '''

        :param subject: 
        :param out_trade_no: 
        :param total_amount: 
        :param return_url: 
        :param kwargs: 
        :return: 
        '''

        # https://doc.open.alipay.com/doc2/detail.htm?treeId=270&articleId=105901&docType=1
        # biz_content参数
        biz_content = {
            "subject": subject,
            "out_trade_no": out_trade_no,
            "total_amount": total_amount,
            "product_code": "FAST_INSTANT_TRADE_PAY",
            # "qr_pay_mode":4
        }

        biz_content.update(kwargs)
        data = self.build_body("alipay.trade.page.pay", biz_content, self.return_url)
        return self.sign_data(data)

    def build_body(self, method, biz_content, return_url=None):
        '''
        公共请求参数
        :param method: 
        :param biz_content: 
        :param return_url: 
        :return: 
        '''
        data = {
            "app_id": self.appid,
            "method": method,
            "charset": "utf-8",
            "sign_type": "RSA2",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
            "biz_content": biz_content
        }

        if return_url is not None:
            data["notify_url"] = self.app_notify_url
            data["return_url"] = self.return_url

        return data

    def sign_data(self, data):
        '''
        签名入口
        :param data: 
        :return: 
        '''
        data.pop("sign", None)
        # 排序后的字符串
        unsigned_items = self.ordered_data(data)
        unsigned_string = "&".join("{0}={1}".format(k, v) for k, v in unsigned_items)
        sign = self.sign(self.app_private_key, unsigned_string.encode("utf-8"))
        ordered_items = self.ordered_data(data)
        quoted_string = "&".join("{0}={1}".format(k, quote_plus(v)) for k, v in ordered_items)

        # 获得最终的订单信息字符串
        signed_string = quoted_string + "&sign=" + quote_plus(sign)
        return signed_string

    @staticmethod
    def ordered_data(data):
        complex_keys = []
        for key, value in data.items():
            if isinstance(value, dict):
                complex_keys.append(key)

        # 将字典类型的数据dump出来
        for key in complex_keys:
            data[key] = json.dumps(data[key], separators=(',', ':'))

        return sorted([(k, v) for k, v in data.items()])

    @staticmethod
    def sign(key, unsigned_string):
        # 开始计算签名
        key = key
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string))
        # base64 编码，转换为unicode表示并移除回车
        sign = b64encode(signature).decode("utf8").replace("\n", "")
        return sign

    @classmethod
    def _verify(cls, raw_content, signature, alipay_public_key):
        '''
        使用公钥加密和签名的字符串比较是否一致
        :param raw_content:
        :param signature:
        :return:
        '''
        key = alipay_public_key
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new()
        digest.update(raw_content.encode("utf8"))
        if signer.verify(digest, b64decode(signature.encode("utf8"))):
            return True
        return False

    @classmethod
    def verify(cls, data, signature, alipay_public_key):
        if "sign_type" in data:
            sign_type = data.pop("sign_type")
        # 排序后的字符串
        print("data:", data)
        unsigned_items = cls.ordered_data(data)
        message = "&".join("{}={}".format(k, v) for k, v in unsigned_items)
        return cls._verify(message, signature, alipay_public_key)
