#-*- coding: utf-8 -*-
from .utils.information_handler import waf_detect,headers,parser
from .utils.request_handler import request_handler as request
from .utils.ngelog import merah,kuning,hijau,biru,skema,no_skema,logger
from subprocess import Popen,PIPE
log = logger(__name__)


class waf(object):

      def __init__(self,respon):
          self.func = waf_detect
          self.bNer = False
          self.respon = respon

      def kasih_tahu(self,name):
          log.log(50,f'Detected WAF Presence in web application: {kuning(name)}')
          self.bNer = True

      def start_(self):
          for var,val in self._name().items():
              mtd = val(self.respon)
              if mtd:
                 self.bNer += 'ada'
                 self.kasih_tahu(var)

      def _name(self):
          nama = {
            'Cloudfront (Amazon)': self.func.cloudfront,
            'Incapsula (Imperva Inc.)':self.func.incapsula,
            'Distil (Distil Networks)':self.func.distil,
            'Cloudflare (Cloudflare Inc.)':self.func.cloudflare,
            'Edgecast (Verizon Digital Media)':self.func.edgecast,
            'MaxCDN (MaxCDN)':self.func.maxcdn,
            'Sucuri (Sucuri Inc.)':self.func.sucuri,
            'Reblaze (Reblaze)':self.func.reblaze,
            'BigIP (BigIP)':self.func.bigip,
            'Anquanbao (Anquanbao)':self.func.anquanbao,
            'Yunjiasu (Baidu Cloud Computing)':self.func.baidu,
            'aeSecure (aeSecure)':self.func.aescure,
            'DynamicWeb Injection Check (DynamicWeb)':self.func.dynamic,
            'BinarySec (BinarySec)':self.func.binarysec,
            'BlockDoS (BlockDoS)':self.func.block_dos,
            'CacheWall (Varnish)':self.func.cachewall,
            'ACE XML Gateway':self.func.ace_xml,
            'Cloudbric (Zendesk)':self.func.cloudbrick,
            'DotDefender (Applicure Technologies)':self.func.defender,
            'Greywizard (Grey Wizard)':self.func.greywizard,
            'Data Power (IBM)':self.func.datapower,
            'Jiasule (Jiasule)':self.func.jiasule,
            'Akamai (Akamai)':self.func.Akamai,
            'Mission Control Application Shield (Mission Control)':self.func.mission_control,
            'ModSecurity (SpiderLabs)':self.func.mod_security,
            'Newdefend (NewDefend)':self.func.newdefend,
            'NSFocus (NSFocus Global Inc.)':self.func.nsfocus,
            'OnMessage Shield (BlackBaud)':self.func.oneMessage,
            'Profense (ArmorLogic)':self.func.profense,
            'AppWall (Radware)':self.func.radware,
            'ASP.NET Generic Web Application Protection':self.func.Asp,
            'Safe3 Web Firewall (Safe3)':self.func.safe3,
            'Safedog (SafeDog)':self.func.safedog,
            'Secure Entry (United Security Providers)':self.func.secureentry,
            'SonicWall (Dell)':self.func.sonicwall,
            'TransIP Web Firewall (TransIP)':self.func.transIp,
            'URLMaster SecurityCheck (iFinity/DotNetNuke)':self.func.urlmaster,
            'Wallarm (Wallarm Inc.)':self.func.wallarm,
            'WatchGuard (WatchGuard Technologies)':self.func.watchguard,
            'WebSEAL (IBM)':self.func.webseal,
            '360WangZhanBao (360 Technologies)':self.func.wangzanbao,
            'XLabs Security WAF (XLabs)':self.func.xlabs,
            'Yundun (Yundun)':self.func.yundun,
            'Zenedge (Zenedge)':self.func.zenedge,
            'ZScaler (Accenture)':self.func.zscaler,
          }
          return nama

class respon_hider(object):

      def __init__(self,respon):
          self.respon = respon
          self.hider = headers
          
      def detect(self):
          server = self.hider.server(self.respon)
          xpowered = self.hider.x_powered(self.respon)
          click_jacking = self.hider.click_jacking(self.respon)
          xss_protect = self.hider.xss_protect(self.respon)
          cors_wildcard = self.hider.cors_wildcard(self.respon)
          if server != None:
             log.log(10,f'Web Server Detected: {hijau(server)}')
          if xpowered != None:
             log.log(10,f'X-Powered-By: {hijau(xpowered)}')
          if click_jacking == True:
             log.log(20,f'X-Frame-Options Headers not detect! target might be vulnerable {merah("Click Jacking")}')
          if xss_protect == True:
             log.log(50,f'Xss Protection Detected !')
          if cors_wildcard == True:
             log.log(50,f'CORS Wildcard Detected !')

class location_info(object):

      def __init__(self,target):
          self.target = no_skema(target)
          self.r = request().sessi()
          
      def location(self):
          log.log(10,'Finding Location..!')
          r = self.r.get(f'http://ip-api.com/json/{self.target}')
          for x,y in r.json().items():
              log.log(10,f'{x}: {hijau(y)}')
          r.close()

class reverse_DNS(object):

      def __init__(self,target):
          self.target = no_skema(target)
          self.r = request().sessi()
          
      def rDNS(self):
          log.log(10,'Starting Reverse DNS')
          r = self.r.post(
            'https://domains.yougetsignal.com/domains.php',
            data = {
                'remoteAddress':self.target,
                'key':''
            }
          )
          if r.json()['status'] == 'Success':
             log.log(20,f'Found {hijau(len(r.json()["domainArray"]))} any Domain')
             for isi,_ in r.json()['domainArray']:
                 print(f'- {hijau(isi)}')
          else:
             log.log(30,f'Failed ! {merah(r.json()["status"])}')

class port_scan(object):

      def __init__(self,target):
          self.target = no_skema(target)
          self.pars = parser           
          
      def nmap(self):
          log.log(20,'Scanning Open Port')
          ss = Popen([
            'nmap',
            '--open',
            self.target
          ],stdout=PIPE,stderr=PIPE)
          res,err = ss.communicate()
          res,err = res.decode().strip(),err.decode().strip()
          result = self.pars.port(res)
          for i in result:
              xxx = i.format('\033[92m','\033[0m')
              log.log(10,f'{xxx}')


          
          
          














