#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re
import csv
import json
import base64
import copy
import logging as log
import os
import socket
import time
import multiprocessing
import hashlib

from logging import getLogger, Formatter, StreamHandler

logger = getLogger(__name__)

url            =     os.getenv("HTTP_END_POINT", "http://127.0.0.1:5000/" )
listen_ip      =     os.getenv("LISTEN_IP"     , "0.0.0.0" )
listen_port    = int(os.getenv("LISTEN_PORT"   , 5060        ))
udp_buffer_size= int(os.getenv("UDP_BUFFER_SIE", 16*1024*1024))#16M

loglevel       = int(os.getenv("LOGLEVEL"      , log.DEBUG))

calls={}

def sipParser(raw_data):
    data_str = raw_data.decode('utf-8').lstrip()
    headers, body = data_str.split('\r\n\r\n',1)

    request={}
    response={}
    header={}
    output={}

    last_header=None
    splited_list=headers.split('\r\n')

    first_line=splited_list.pop(0)

    ''' first line parser '''
    el1, el2, el3 = first_line.split(' ',2)
    if el1[:3] == 'SIP':
        response['status-code'  ]=el2
        response['status-phrase']=el3
        output['response']=response
    else :
        request['method'       ]=el1
        request['request-uri'  ]=el2
        output['request' ]=request

    output['original_cases']={}

    ''' header parser '''
    for header_line in splited_list:
        if header_line[0] == ' ' or header_line[0] == '\t':
            key=last_header

            if key == None or not key in header:
                continue

            header[key][-1]=header[key][-1]+header_line.strip()
        else:
            key, val = header_line.split(':',1)
            key=key.strip()
            output['original_cases'][key.lower()]=key
            key=key.lower()
            val=val.strip()
            if not key in header:
                header[key]=[]
            header[key].append(val)
            last_header=key

    for key,vals in header.items():
        header[key] = sum(list(csv.reader(vals)),[])

    output['header']=header
    output['body'  ]=base64.b64encode(body.encode('utf-8')).decode('utf-8')

    # logger.debug('{}'.format(json.dumps(output, ensure_ascii=False, indent=2,
    #                 sort_keys=True, separators=(',', ': '))))

    return output

def sendSIPmessageTo(sock, ret, frm):

    message=''
    if 'request' in ret:
        message+='{} {} SIP/2.0\r\n'.format(ret['request']['method'],
                ret['request']['request-uri'])
    else:
        message+='SIP/2.0 {} {}\r\n'.format(ret['response']['status-code'],
                ret['response']['status-phrase'])

    for key, vals in ret['header'].items():
        for val in vals:
            message+='{}: {}\r\n'.format(key, val)

    message+='\r\n'
    if 'body' in ret:
        message+=base64.decode(ret['body'])

    logger.debug('<<<< send to {}'.format(frm))
    logger.debug('\n{}'.format(message))
    sock.sendto(message.encode('utf-8'),frm)

def scenario(sock, frm, output):
    if 'request' in output :
        if output['request']['method'] == 'INVITE':
            if not ';tag=' in output['header']['to'][-1]: # initial-INVITE
                ret = {}
                ret['response']={}
                ret['response']['status-code']='100'
                ret['response']['status-phrase']='Trying'

                ret['header']={}
                ret['header']['from']=output['header']['from']
                ret['header']['to']=output['header']['to']
                ret['header']['call-id']=output['header']['call-id']
                ret['header']['cseq']=output['header']['cseq']
                ret['header']['via']=output['header']['via']

                ret['header']['contact']=['sip:{}:{}'.format(
                                                listen_ip,listen_port)]

                sendSIPmessageTo(sock,ret,frm)

                ret['response']={}
                ret['response']['status-code']='180'
                ret['response']['status-phrase']='Ringing'
                ret['header']['To']=[ ret['header']['to'][-1]
                                      + ';tag=123123123' ]

                sendSIPmessageTo(sock,ret,frm)

                time.sleep(3)

                ret['response']={}
                ret['response']['status-code']='200'
                ret['response']['status-phrase']='OK'

                sendSIPmessageTo(sock,ret,frm)
            else:
                ret = {}
                ret['response']={}
                ret['response']['status-code']='200'
                ret['response']['status-phrase']='OK'

                ret['header']={}
                ret['header']['from']=output['header']['from']
                ret['header']['to']=output['header']['to']
                ret['header']['call-id']=output['header']['call-id']
                ret['header']['cseq']=output['header']['cseq']
                ret['header']['via']=output['header']['via']

                ret['header']['contact']=['sip:{}:{}'.format(
                                                listen_ip,listen_port)]

                sendSIPmessageTo(sock,ret,frm)

        elif output['request']['method'] == 'ACK':
            pass

        elif output['request']['method'] == 'BYE'       \
             or output['request']['method'] == 'CANCEL' \
             or output['request']['method'] == 'PRACK'  \
             or output['request']['method'] == 'OPTIONS':
            ret = {}
            ret['response']={}
            ret['response']['status-code']='200'
            ret['response']['status-phrase']='OK'

            ret['header']={}
            ret['header']['from']=output['header']['from']
            ret['header']['to']=output['header']['to']
            ret['header']['call-id']=output['header']['call-id']
            ret['header']['cseq']=output['header']['cseq']
            ret['header']['via']=output['header']['via']

            ret['header']['contact']=['sip:{}:{}'.format(
                                            listen_ip,listen_port)]

            sendSIPmessageTo(sock,ret,frm)

def calcHash(data,from_tag='',to_tag='',call_id=''):
    hashable=from_tag+to_tag+call_id
    logger.debug('{} + {} + {} = {}'.format(from_tag,to_tag,call_id,hashable))
    return hashlib.sha1(hashable.encode('utf-8')).hexdigest()

jobs = []

def listningLoop(sock, bufsize):
    reg_tag_str=r'tag=([^\s^;]+)'
    reg_tag=re.compile(reg_tag_str)
    while True:
        data, frm=sock.recvfrom(bufsize)
        #recvfrom_into(bufsize)
        logger.debug('>>>> recieve from {}'.format(frm))
        logger.debug('\n{}'.format(data.decode('utf-8')))
        output=sipParser(data)
        from_tag=''
        to_tag=''

        m=reg_tag.search(output['header']['from'][-1])
        print(output['header']['from'][-1])
        if m:
            from_tag=m.group(1)
        m=reg_tag.search(output['header']['to'][-1])
        if m:
            to_tag=m.group(1)
        call_id=output['header']['call-id'][-1]
        hashed=calcHash(output,from_tag=from_tag,to_tag=to_tag,call_id=call_id)
        logger.debug(' hash : {}'.format(hashed))


        job=multiprocessing.Process(target=scenario, args=(sock, frm, output,))
        jobs.append(job)
        job.start()

def main():
    logger.setLevel(loglevel)
    sh = StreamHandler()
    logger.addHandler(sh)
    formatter = Formatter('%(asctime)s:%(lineno)d:%(levelname)s:%(message)s')
    sh.setFormatter(formatter)

    logger.info('server started...')

    job=[]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((listen_ip, listen_port))
        logger.info('listening on ({}:{})'.format(listen_ip, listen_port))
        try:
            listningLoop(sock, udp_buffer_size)
        except KeyboardInterrupt:
            pass

    [job.join() for job in jobs]
    logger.info('server terminating...')

if __name__ == '__main__':
    main()
