# -*- coding: utf-8 -*-
import uuid

import os
from Crypto.PublicKey import RSA
from django.conf import settings
from django.shortcuts import render, HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from utils.alipay import AliPay

path = os.path.dirname(os.path.abspath(__file__))

csrf_exempt_m = method_decorator(csrf_exempt)


def index(request):
    alipay = AliPay(
        appid=settings.PAY_APP_ID,
        app_notify_url=settings.PAY_CALLBACK_NOTIFY_URL,
        app_private_key_path=os.path.join(path, 'key/private_2048.txt'),
        return_url=settings.PAY_CALLBACK_URL
    )
    url = alipay.direct_pay(
        subject="测试订单",
        out_trade_no=uuid.uuid4().int,
        total_amount=0.01
    )
    pc_url = "https://openapi.alipaydev.com/gateway.do?{data}".format(data=url)
    return render(request, 'index.html', {'pc_url': pc_url})


class AlipayValidateAPI(View):

    def get(self, request):
        return render(request, 'payover.html')

    @method_decorator(csrf_exempt)
    def post(self, request):
        """在支付完成之后会给return_url发请求，必须验证这个返回是否是支付宝返回的"""

        # 支付宝的公钥，验证支付宝回传消息使用，不是你自己的公钥,
        with open(os.path.join(path, 'key/alipay_key_2048.txt')) as fp:
            alipay_public_key = RSA.import_key(fp.read())

        processed_dict = {}
        for key, value in request.POST.iteritems():
            processed_dict[key] = value

        sign = processed_dict.pop("sign", None)
        verify_re = AliPay.verify(processed_dict, sign, alipay_public_key)

        if verify_re:
            return HttpResponse('success')
