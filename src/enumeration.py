#-*- coding: utf-8 -*-
from .utils.request_handler import request_handler as request
from .utils.ngelog import logger,skema,no_skema
import re

class subdomain_enumeration(object):

      def __init__(self,domain):
          self.domain = domain
          self.__result = []
          self.req = request().sessi()
          self.url = 'https://dnsdumpster.com'

      @property
      def raw_result(self):
          return self.__result

      def request(self):
          get_token = self.req.get(self.url)
          better_cookie = get_token.cookies.get_dict()
          r = self.req.post(
            self.url,
            cookies=better_cookie,
            headers={'Referer':self.url},
            data={
                'csrfmiddlewaretoken':better_cookie['csrftoken'],
                'targetip':no_skema(self.domain)
            }
          )
          rgx = re.findall(r'http://(.*?)"',r.text)
          for dmn in rgx:
              self.__result.append(dmn)


           

