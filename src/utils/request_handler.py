#-*- coding: utf-8 -*-
from requests import request,Session,utils
from .user_agent import useragent as uag

class request_handler(object):

      def __init__(self,proxy=None,cookie=None,timeout=7):
         self.is_proxy = proxy
         self.cookie = cookie
         self.timeout = timeout

      def send(self,mtd='GET',*args,**kwargs):
          return request(
            mtd,
            headers={'User-Agent': uag(), 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'},
            cookies=self.cookie,
            timeout=self.timeout,
            proxies=self.is_proxy,
            *args,
            **kwargs                        
          )
          
      def sessi(self):
          ses = Session()
          ses.headers = {'User-Agent': uag(), 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
          ses.proxies = self.is_proxy
          return ses

          
          
                 
             
            

