#-*- coding: utf-8 -*-
import sys
if sys.version[0] == '2':
   print('[X] Not Supported For python 2.x please use python 3')
   exit()

try:
    import click
    import tldextract
    import requests
    import colorlog
except Exception:
    print('\n!pip install -r requirements.txt\n')
    
import click,sys,urllib3,os
from datetime import datetime as date
from http.cookies import SimpleCookie
from src.fingerprint import (
    waf,
    respon_hider,
    location_info,
    reverse_DNS,
    port_scan
)
from src.disclosure import disc
from src.crawl import extractor
from src.enumeration import subdomain_enumeration
from src.utils.request_handler import request_handler
from src.utils.ngelog import (
    logger,
    skema,
    no_skema,
    merah,
    kuning,
    hijau,
    ban
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logger(__name__)

def set_cookie(x):
    try:
       if x != None:
          cc = SimpleCookie()
          kue = cc.load()
          coki_coki = {a:b.value for a,b in kue.items()}
          return coki_coki
       else:
          return None
    except Exception:
       return None

def set_proxy(x):
    try:
        if x != None:
           return {'http':x,'https':x},'http://{}'.format(x)
        else:
           return None,None
    except Exception:
        return None,None

@click.command()
@click.argument('target')
@click.option('--timeout',help='Seconds to wait before timeout connections ',default=None,show_default=True,type=int)
@click.option('--proxy',default=None,help='if Use a proxy ex: 0.0.0.0:8888' 
                             'if with auth 0.0.0.0:8888@user:password')
@click.option('--cookies',default=None,help='if use cookie comma separated cookies to add the request'
                               'ex: PHPSESS:123,kontol=True')
       

def main(target,timeout,proxy,cookies):
    try:
        print(ban)
        log.log(50,'Starting At {}'.format(hijau(str(date.now()))))
        batas = '-'*50
        kue = set_cookie(cookies)
        proxies = set_proxy(proxy)
        res = request_handler(
            proxy=proxies[0],
            cookie=kue,
            timeout=timeout
        ).send(
            mtd='GET',
            url=skema(target),
            allow_redirects=True,
            verify=False
        )
        log.log(50,'Collecting Information On: {}'.format(merah(target)))
        log.log(10,'Status: \033[1;30m{}\033[0m'.format(res.status_code))
        print(batas)
        hider = respon_hider(res)
        hider.detect()
        for a,b in res.headers.items():
            print('- {}: {}'.format(a,b))
        print(batas)
        location_info(target).location()
        print(batas)
        wff = waf(res)
        wff.start_()
        if wff.bNer == False:
           log.log(40,"Didn't Detect WAF Presence on: {}".format(hijau(res.url)))
        print(batas)
        reverse_DNS(target).rDNS()
        print(batas)
        port_scan(target).nmap()
        print(batas)
        log.log(50,'Collecting Information Disclosure!')
        dd = disc(target,cookie=kue,proxy=proxies[0],timeout=timeout)
        dd.mail()
        dd.phone()
        dd.cc()
        dd.ssn()
        dd.sitemap()
        dd.robot()
        print(batas)
        log.log(50,'Crawling Url Parameter On: {}'.format(merah(res.url)))
        ext = extractor(target,res)
        print(batas)
        ext.form()
        print(batas)
        ext.dom()
        print(batas)
        ext.in_dynamic()
        print(batas)
        ext.ex_dynamic()
        print(batas)
        ext.in_link()
        print(batas)
        ext.ex_link()
        print(batas)
        log.log(10,'Mapping Subdomain..')
        sub = subdomain_enumeration(target)
        sub.request()
        if len(sub.raw_result) == 0:
           log.log(30,'No Any Subdomain Found')
        log.log(20,'Found {} Subdomain'.format(hijau(len(sub.raw_result))))
        for i in sub.raw_result:
            print('- {}'.format(hijau(i)))
        print(batas)
        log.log(20,'Done At {}'.format(hijau(date.now())))
    except Exception as e:
        print(merah(e))
        log.log(20,'Done At {}'.format(hijau(date.now())))           
if __name__ == '__main__':
   main()        
        
        
        
        













        
        
        