#-*- coding: utf-8 -*-
import re

class waf_detect(object):

      @classmethod
      def cloudfront(cls,r):
          serv = 'CloudFront'
          if any(p in r.headers.keys() for p in ('Via','X-cache')) and any(serv.lower() in isi for isi in r.headers.values()):
             return True
          if r.headers.get('Server') == serv:
             return True
          return

      @classmethod
      def incapsula(cls,r):
          if 'X-Iinfo' in r.headers.keys() or r.headers.get('X-CDN') == 'Incapsula':
              return True
          return

      @classmethod
      def distil(cls,r):
          if r.headers.get('x-distil-cs'):
             return True
          return

      @classmethod
      def cloudflare(cls,r):
          if 'CF-RAY' in r.headers.keys() or r.headers.get('Server') == 'cloudflare' or r.headers.get('server') == 'cloudflare-nginx':
              return True
          return

      @classmethod
      def edgecast(cls,r):
          if 'Server' in r.headers.keys() and 'ECD' in r.headers['Server']:
             return True

      @classmethod
      def maxcdn(cls,r):
          if 'Server' in r.headers.keys() and 'NetDNA-cache' in r.headers['Server']:
              return True
          return

      @classmethod
      def sucuri(cls,r):
          if any((r.headers.get('Server') == 'Sucuri/Cloudproxy','X-Sucuri-ID' in r.headers.keys(),'X-Sucuri-Cache' in r.headers.keys(),'Access Denied - Sucuri Website Firewall' in r.text)):
             return True
          return

      @classmethod
      def reblaze(cls,r):
          if r.headers.get('Server') == 'Reblaze Secure Web Gateway' or r.cookies.get('rbzid'):
             return True
          return

      @classmethod
      def bigip(cls,r):
          if 'x-cnection' in r.headers.keys() or 'x-wa-info' in r.headers.keys():
             return True
          return
          
      @classmethod
      def anquanbao(cls,r):
          if 'x-powered-by-anquanbao' in r.headers.values():
             return True
          return
          
      @classmethod
      def baidu(cls,r):
          if 'yunjiasu-nginx' in r.headers.values() or 'fh1' in r.headers.values():
             return True
          return
          
      @classmethod
      def aescure(cls,r):
          if r.headers.get('aeSecure-code') is not None or 'aesecure_denied.png' in r.text:
             return True
          return
          
      @classmethod
      def dynamic(cls,r):
          if r.headers.get('X-403-Status-By') in ['dw-inj-check','dw_inj_check']:
             return True
          return
          
      @classmethod
      def binarysec(cls,r):
          if r.headers.get('server') == 'BinarySec' or r.headers.get('x-binarysec-via') is not None or r.headers.get('x-binarysec-nochace') is not None:
             return True
          return 
          
      @classmethod
      def block_dos(cls,r):
          if r.headers.get('server') == 'BlockDos.net':
             return True
          return
          
      @classmethod
      def cachewall(cls,r):
          if r.headers.get('Server') == 'Varnish' or r.headers.get('X-Varnish') is not None or r.headers.get('X-Chacewall-Action') is not None or r.headers.get('X-Chacewall-Reason') is not None:
             return True
          return
          
      @classmethod
      def china_cache(cls,r):
          if r.headers.get('Powered-By-ChinaCache') is not None:
             return True
          return
          
      @classmethod
      def ace_xml(cls,r):
          if r.headers.get('server') == 'ACE XML Gateway':
             return True
          return

      @classmethod
      def cloudbrick(cls,r):
          if r.headers.get('Server') == 'Approach Web Application Firewall':
             return True
          return

      @classmethod
      def defender(cls,r):
          if r.headers.get('X-dotDefender-denied') != None:
             return True
          return
          
      @classmethod
      def greywizard(cls,r):
          if r.headers.get('Server') == 'greywizard':
             return True
          return
          
      @classmethod    
      def datapower(cls,r):
          if r.headers.get('X-Backside-Transport') in ['OK','FAIL']:
             return True
          return

      @classmethod
      def jiasule(cls,r):
          if r.headers.get('Server') == 'Jiasule-WAF':
             return True
          return

      @classmethod
      def Akamai(cls,r):
          if r.headers.get('Server') == 'AkamaiGhost':
             return True
          return

      @classmethod
      def mission_control(cls,r):
          if r.headers.get('server') == 'Mission Control Application Shield':
             return True
          return

      @classmethod
      def mod_security(cls,r):
          if r.headers.get('Server') in ['mod_security','Mod_Security','NOYB']:
             return True
          return

      @classmethod
      def newdefend(cls,r):
          if r.headers.get('Server') == 'Newdefend':
             return True
          return

      @classmethod
      def nsfocus(cls,r):
          if r.headers.get('server') == 'NSFocus':
             return True
          return

      @classmethod
      def oneMessage(cls,r):
          if r.headers.get('X-Engine') == 'onMessage Shield':
             return True
          return
          
      @classmethod
      def profense(cls,r):
          if r.headers.get('Server') == 'profense':
             return True
          return

      @classmethod
      def radware(cls,r):
          if r.headers.get('X-SL-CompState') is not None:
             return True
             
      @classmethod
      def Asp(cls,r):
          if r.headers.get('X-ASPNET-Version') is not None:
             return True
          return
          
      @classmethod
      def safe3(cls,r):
          if r.headers.get('Server') == 'Safe3 Web Firewall':
             return True
          return
          
      @classmethod
      def safedog(cls,r):
          if r.headers.get('server') == 'Safedog':
             return True
          return

      @classmethod
      def secureentry(cls,r):
          if r.headers.get('Server') == 'Secure Entry Server':
             return True
          return

      @classmethod
      def sonicwall(cls,r):
          if r.headers.get('Server') == 'SonicWALL':
             return True
          return
          
      @classmethod
      def transIp(cls,r):
          if r.headers.get('X-TransIP-Backend') is not None:
             return True
          return

      @classmethod
      def urlmaster(cls,r):
          if r.headers.get('X-UrlMaster-Ex') is not None or r.headers.get('X-UrlMaster-Debug') is not None:
             return True
          return

      @classmethod
      def wallarm(cls,r):
          if r.headers.get('Server') == 'nginx-wallarm':
             return True
          return
          
      @classmethod
      def watchguard(cls,r):
          if r.headers.get('Server') == 'WatchGuard':
             return True
          return
          
      @classmethod
      def webseal(cls,r):
          if r.headers.get('Server') == 'WebSEAL':
             return True
          return

      @classmethod
      def wangzanbao(cls,r):
          if r.headers.get('X-Powered-By-360WZB') is not None:
             return True
          return

      @classmethod
      def xlabs(cls,r):
          if r.headers.get('X-cdn') == 'XLabs Security':
             return True
          return
          
      @classmethod
      def yundun(cls,r):
          if r.headers.get('Server') == 'YUNDUN' or r.headers.get('X-Chace') == 'YUNDUN':
             return True
          return
          
      @classmethod
      def zenedge(cls,r):
          if r.headers.get('Server') == 'ZENEDGE':
             return True
          return
          
      @classmethod
      def zscaler(cls,r):
          if r.headers.get('Server') == 'ZScaler':
             return True
          return
          
class headers(object):

      @classmethod
      def server(cls,r):
          return r.headers.get('server')
          
      @classmethod
      def x_powered(cls,r):
          return r.headers.get('X-Powered-By')
          
      @classmethod
      def click_jacking(cls,r):
          if r.headers.get('X-Frame-Options') == None:
             return True
          else:
             return None
             
      @classmethod
      def xss_protect(cls,r):
          if r.headers.get('X-XSS-PROTECTION') and '1' in r.headers.get('X-XSS-PROTECTION'):
             return True
          else:
             return None
             
      @classmethod
      def cors_wildcard(cls,r):
          if r.headers.get('Access-Control-Allow-Origin') == '*':
             return True
          else:
             return None


class crawl(object):

      @classmethod
      def html_form(cls,sop):
          form = {}
          for x in sop.select('form'):
              if x.get('action') == '#':
                 continue
              form['action'] = x.get('action')
              form['class'] = x.get('class')
              form['id'] = x.get('id')
              form['method'] = x.get('method')
          return form    
          
      @classmethod
      def extract_link(cls,r):
          link = []
          ex = re.findall(r'href="(.+?)"',r.text)
          for i in ex:
              link.append(i)
          return link
           
      @classmethod
      def dom(cls,list_link):
          dom = []
          for i in list_link:
              if '#' in i:
               dom.append(i)
          return dom
           
      @classmethod
      def internal_dynamic(cls,list_link,domain):
          internal_dynamic = []
          for i in list_link:
              if '?' in i and domain in i:
                 internal_dynamic.append(i)
          return internal_dynamic
          
      @classmethod
      def external_dynamic(cls,list_link,domain):
          ex_any_dynamic = []
          for i in list_link:
              if '?' in i and domain not in i:
                 ex_any_dynamic.append(i)
          return ex_any_dynamic
          
      @classmethod
      def internal_link(cls,list_link,domain):
          link = []
          for i in list_link:
              if domain in i and '?' not in i and '#' not in i:
                 link.append(i)
          return link      
          
      @classmethod
      def external_link(cls,list_link,domain):
          link = []
          for i in list_link:
              if i.startswith('http') and domain not in i and '?' not in i:
                 link.append(i)   
          return link                    


class parser(object):

      @classmethod
      def port(cls,result):
          port = []
          for x in result.split('\n'):
              if 'open' in x:
                 p = x.split()
                 isi = '{}%s{}  %s' % (p[0],' '.join(p[1:]))
                 port.append(isi)
          return port
          
      @classmethod
      def information_disclosure(cls,r):
          isi = {}
          isi['email'] = re.findall(r'[\\w\\-][\\w\\-\\.]+@[\\w\\-][\\w\\-\\.]+[a-zA-Z]{1,4}',r.text)
          isi['phone'] = re.findall(r'\+\d{2}\s?0?\d{10}',r.text)
          isi['cc'] = re.findall(r'((^|\s)\d{4}[- ]?(\d{4}[- ]?\d{4}|\d{6})[- ]?(\d{5}|\d{4})($|\s))',r.text)
          isi['ssn'] = re.findall(r'(((?!000)(?!666)(?:[0-6]\d{2}|7[0-2][0-9]|73[0-3]|7[5-6][0-9]|77[0-2]))-((?!00)\d{2})-((?!0000)\d{4}))',r.text)
          return isi                    
          

