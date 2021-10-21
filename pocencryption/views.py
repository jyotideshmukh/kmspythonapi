import base64

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from rest_framework.parsers import JSONParser

from .encryptdecrypt import retrieve_cmk, data_encrypt, data_decrypt, createKeyFirstTime
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.core import serializers
from django.conf import settings
import json
import requests





# Create your views here.
from .models import Datakeys


def encrypt(request):
    cmk = retrieve_cmk('Jyoti POC python key')
    encrypted_data, data_key_encrypted = data_encrypt('Hello Santosh',cmk[0])
    decrypted_content = data_decrypt(encrypted_data, data_key_encrypted)


    # responseData = {
    #     'cmk':cmk,
    #     'cmkkey':cmk[0],
    #     'datakeys':datakey
    # }

    return HttpResponse(decrypted_content)

def decrypt(request):
    data = {'name':'jyoti','email':'jyotipawar2003@gmail.com'}
    responseData = {
        'data':data
    }

    return JsonResponse(responseData)



def savekey(request):
    cmk = retrieve_cmk('Jyoti POC python key')
    createKeyFirstTime(cmk[0])
    return HttpResponse("Saved key successfully")

@api_view(["POST"])
def encryptapi(request):
    try:
        #print(request.data)
        data = request.data
        cmk = retrieve_cmk('Jyoti POC python key')
        responseData = {}
        for i in data:
            encrypted_data, data_key_encrypted = data_encrypt(data[i],cmk[0])
            encoded = base64.b64encode(encrypted_data)
            responseData[i] = encoded.decode('ascii')

        responseData = json.dumps(responseData)
        return JsonResponse(responseData,safe=False)
    except ValueError as e:
        return Response(e.args[0],status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def decryptapi(request):
    try:
        data = request.data
        #print(data)
        #data = json.loads(data)
        #print(data)
        cmk = retrieve_cmk('Jyoti POC python key')
        data_key_encrypted = Datakeys.objects.all()[0].data_key
        responseData = {}
        for i in data:
            #print(data[i])
            encrypted_data = base64.b64decode(data[i])
            decrypted_content = data_decrypt(encrypted_data,data_key_encrypted)
            #print(decrypted_content)
            responseData[i] = decrypted_content.decode('ascii')

        responseData = json.dumps(responseData)
        #print("*****************")
        #print(responseData)
        return JsonResponse(responseData,safe=False)
    except ValueError as e:
        return Response(e.args[0],status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def getdata(request):
    try:
        #print(request.body)
        #data = json.loads(request.body)
        #print("Data{}",format(data))
        #cmk = retrieve_cmk('Jyoti POC python key')
        #print("CMK={}",format(cmk))
        # encrypted_data, data_key_encrypted = data_encrypt(data,cmk[0])
        # return JsonResponse(encrypted_data)
        responseData = {
            'name':'jyoti',
            'email':'jyotipawar2003@gmail.com'
        }
        return JsonResponse(responseData,safe=False)
    except ValueError as e:
        return Response(e.args[0],status.HTTP_400_BAD_REQUEST)



