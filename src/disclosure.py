#-*- coding: utf-8 -*-
from .utils.information_handler import parser
from .utils.request_handler import request_handler as request
from .utils.ngelog import merah,kuning,hijau,biru,logger

log = logger(__name__)
class disc(object):

      def __init__(self,target,cookie=None,proxy=None,timeout=7):
          self.target = target
          self.cookie = cookie
          self.proxy = proxy
          self.timeout = timeout
          self.r = request(proxy=self.proxy,cookie=self.cookie,timeout=self.timeout)
          self.res = self.respon()
          
      def make_request(self):
          r = self.r.send(
            mtd='GET',
            url=self.target,
            verify=False
          )
          return r
          
      def respon(self):
          rr = self.make_request()
          return parser.information_disclosure(rr)
          
      def cc(self):
          cc = self.res['cc']
          if cc != []:
             log.log(20,f'Found {hijau(len(cc))} Credit Card Number')
             for i in cc:
                 log.log(50,f'{i}')
                 
      def mail(self): 
          mail = self.res['email']
          if mail != []:
             log.log(20,f'Found {hijau(len(mail))} Email')
             for i in mail:
                 log.log(50,f'{i}')
                 
      def phone(self):  
          phone = self.res['phone']
          if phone != []:
             log.log(20,f'Found {hijau(len(phone))} Phone Number')
             for i in phone:
                 log.log(50,f'{i}')
                 
      def ssn(self):
          ssn = self.res['ssn']
          if ssn != []:
             log.log(20,f'Found {hijau(len(ssn))} Social Security Number')
             for i in ssn:
                 log.log(50,f'{i}')
                 
      def sitemap(self):
          log.log(10,'Detecting sitemap.xml file')
          r = self.r.send(
            mtd='GET',
            url=f'{self.target}/sitemap.xml',
            verify=False
          )
          if r.status_code != 404 and '<!DOCTYPE html>' not in r.text:
             log.log(20,f'{hijau("sitemap.xml")} File Found: {r.url}')
          else:
             log.log(30,'sitemap.xml file not Found!?')
             
      def robot(self):
          log.log(10,'Detecting robots.txt file')
          r = self.r.send(
            mtd='GET',
            url=f'{self.target}/robots.txt',
            verify=False
          )
          if r.status_code != 404 and '<!DOCTYPE html>' not in r.text:
             log.log(20,f'{hijau("robots.txt")} File Found: {r.url}')
          else:
             log.log(30,'robots.txt file not Found!?')








      
