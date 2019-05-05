#-*- coding: utf-8 -*-
from .utils.information_handler import crawl,parser
from .utils.request_handler import request_handler as request
from .utils.ngelog import logger,merah,kuning,hijau,biru,no_skema
from bs4 import BeautifulSoup 

log = logger(__name__)

class extractor(object):

      def __init__(self,target,respon):
          self.target = target
          self.respon = respon
          self.p = crawl
          self.links = self.link()
          
      def form(self):
          bs = BeautifulSoup(self.respon.text,'lxml')
          log.log(10,'Searching Html Form !')
          html_form = self.p.html_form(bs)
          if any(html_form.values()) == True:
             log.log(50,'Html Form Discovered')
             for a,b in html_form.items():
                 log.log(10,f'{a}: {hijau(b)}')
          else:
             log.log(30,'No Html Form Found!?')   
             
      def link(self):
          all_link = self.p.extract_link(self.respon)
          insert_link = []
          if all_link != []:
             for i in all_link:
                 if not i.startswith("http"):
                    insert_link.append(f'{self.target}/{i}')
                 else:
                    insert_link.append(i)
             return insert_link 
          else:
             return []
             
      def dom(self):
          dom = self.p.dom(self.links)
          if dom != []:
             log.log(20,f'Found {hijau(len(dom))} dom parameter')
             for i in dom:
                 log.log(10,f'{i}')
          else:
             log.log(30,f'No DOM Paramter Found!?') 
             
      def in_dynamic(self): 
          in_dynamic = self.p.internal_dynamic(self.links,no_skema(self.target))
          if in_dynamic != []:
             log.log(20,f'{hijau(len(in_dynamic))} Internal Dynamic Parameter Discovered')
             for i in in_dynamic:
                 log.log(50,f'{i}')
          else:
             log.log(30,f'No internal Dynamic Parameter Found!?')
             
      def ex_dynamic(self):
          ex_dynamic = self.p.external_dynamic(self.links,no_skema(self.target))
          if ex_dynamic != []:
             log.log(20,f'{hijau(len(ex_dynamic))} External Dynamic Parameter Discovered')
             for i in ex_dynamic:
                 log.log(10,f'{i}')
          else:
             log.log(30,f'No external Dynamic Paramter Found!?')
             
      def in_link(self):
          in_link = self.p.internal_link(self.links,no_skema(self.target))
          if in_link != []:
             log.log(20,f'{hijau(len(in_link))} Internal links Discovered')
             for i in in_link:
                 log.log(50,f'{i}')
          else:
             log.log(30,f'No Internal Link Found!?')
             
      def ex_link(self):
          ex_link = self.p.external_link(self.links,no_skema(self.target))
          if ex_link != []:
             log.log(20,f'{hijau(len(ex_link))} External links Discovered')
             for i in ex_link:
                 log.log(10,f'{i}')
          else:
             log.log(30,f'No External Link Found!?')      
