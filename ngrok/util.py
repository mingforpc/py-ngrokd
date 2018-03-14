import struct
import hashlib
import json
import random
from ngrok.config import VERSION, MM_VERSION


def tolen(data):
    if len(data) == 8:
        return struct.unpack('<II', data)[0]
    return 0


def len_to_byte(length):
    return struct.pack('<LL', length, 0)


def conform_resp(resp):
    byte_resp = bytearray()
    byte_resp.extend(len_to_byte(len(resp)))
    byte_resp.extend(resp.encode('utf-8'))
    return byte_resp


def generate_auth_resp(client_id='', version=VERSION, mm_version=MM_VERSION, error=''):
    payload = dict()
    payload['ClientId'] = client_id
    payload['Version'] = version
    payload['MmVersion'] = mm_version
    payload['Error'] = error
    body = dict()
    body['Type'] = 'AuthResp'
    body['Payload'] = payload
    buffer = json.dumps(body)
    return conform_resp(buffer)


def generate_new_tunnel(req_id='', url='', protocol='', error=''):
    payload = dict()
    payload['ReqId'] = req_id
    payload['Url'] = url
    payload['Protocol'] = protocol
    payload['Error'] = error
    body = dict()
    body['Type'] = 'NewTunnel'
    body['Payload'] = payload
    buffer = json.dumps(body)
    return conform_resp(buffer)


def generate_pong():
    payload = dict()
    body = dict()
    body['Type'] = 'Pong'
    body['Payload'] = payload
    buffer = json.dumps(body)
    return conform_resp(buffer)


def generate_req_proxy():
    payload = dict()
    body = dict()
    body['Type'] = 'ReqProxy'
    body['Payload'] = payload
    buffer = json.dumps(body)
    return conform_resp(buffer)


def generate_start_proxy(url, client_addr):
    payload = dict()
    payload['Url'] = url
    payload['ClientAddr'] = client_addr
    body = dict()
    body['Type'] = 'StartProxy'
    body['Payload'] = payload
    buffer = json.dumps(body)
    return conform_resp(buffer)


def md5(content):
    return hashlib.md5(content.encode('utf-8')).hexdigest().lower()


def get_rand_char(length):
    _chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    return ''.join(random.sample(_chars, length))


def get_http_headers(request):
    header, data = request.split('\r\n\r\n', 1)
    headers = dict()
    for line in header.split('\r\n')[1:]:
        key, val = line.split(': ', 1)
        headers[key.upper()] = val

    return headers
