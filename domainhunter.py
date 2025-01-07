#!/usr/bin/env python
import time
import random
import argparse
import json
import base64
import os
import sys
from urllib.parse import urlparse
import getpass
from hashlib import sha256

__version__ = "20221025"

## Functions

def randomDelay(timing):
    """Add nmap-like random sleep interval for multiple requests"""
    if timing == 0:
        time.sleep(random.randrange(90, 120))
    elif timing == 1:
        time.sleep(random.randrange(60, 90))
    elif timing == 2:
        time.sleep(random.randrange(30, 60))
    elif timing == 3:
        time.sleep(random.randrange(10, 20))
    elif timing == 4:
        time.sleep(random.randrange(5, 10))

def evaluateUmbrella(domain):
    """Umbrella Domain reputation service"""
    try:
        url = 'https://investigate.api.umbrella.com/domains/categorization/?showLabels'
        postData = [domain]
        headers = {
            'User-Agent': useragent,
            'Content-Type': 'application/json; charset=UTF-8',
            'Authorization': 'Bearer {}'.format(umbrella_apikey)
        }
        print('[*] Umbrella: {}'.format(domain))
        response = s.post(url, headers=headers, json=postData, verify=False, proxies=proxies)
        responseJSON = json.loads(response.text)
        if len(responseJSON[domain]['content_categories']) > 0:
            return responseJSON[domain]['content_categories'][0]
        else:
            return 'Uncategorized'
    except Exception as e:
        print('[-] Error retrieving Umbrella reputation! {0}'.format(e))
        return "error"

def assessBluecoat(domain):
    """Symantec Sitereview Domain Reputation"""
    try:
        headers = {
            'User-Agent': useragent,
            'Referer': 'http://sitereview.bluecoat.com/'
        }
        response = s.get("https://sitereview.bluecoat.com/", headers=headers, verify=False, proxies=proxies)
        response = s.head("https://sitereview.bluecoat.com/resource/captcha-request", headers=headers, verify=False, proxies=proxies)

        session_cookies = s.cookies.get_dict()
        if "XSRF-TOKEN" in session_cookies:
            token = session_cookies["XSRF-TOKEN"]
        else:
            raise NameError("No XSRF-TOKEN found in the cookie jar")

        phrases = [
            'UGxlYXNlIGRvbid0IGZvcmNlIHVzIHRvIHRha2UgbWVhc3VyZXMgdGhhdCB3aWxsIG1ha2UgaXQgbW9yZSBkaWZmaWN1bHQgZm9yIGxlZ2l0aW1hdGUgdXNlcnMgdG8gbGV2ZXJhZ2UgdGhpcyBzZXJ2aWNlLg==',
            'SWYgeW91IGNhbiByZWFkIHRoaXMsIHlvdSBhcmUgbGlrZWx5IGFib3V0IHRvIGRvIHNvbWV0aGluZyB0aGF0IGlzIGFnYWluc3Qgb3VyIFRlcm1zIG9mIFNlcnZpY2U=',
            'RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=',
            'U2NyaXB0aW5nIGFnYWluc3QgU2l0ZSBSZXZpZXcgaXMgYWdhaW5zdCB0aGUgU2l0ZSBSZXZpZXcgVGVybXMgb2YgU2VydmljZQ=='
        ]

        xsrf_token_parts = token.split('-')
        xsrf_random_part = random.choice(xsrf_token_parts)
        key_data = xsrf_random_part + ': ' + token
        key = sha256(key_data.encode('utf-8')).hexdigest()
        
        random_phrase = base64.b64decode(random.choice(phrases)).decode('utf-8')
        phrase_data = xsrf_random_part + ': ' + random_phrase
        phrase = sha256(phrase_data.encode('utf-8')).hexdigest()
        
        postData = {
            'url': domain,
            'captcha': '',
            'key': key,
            'phrase': phrase,
            'source': 'new-lookup'
        }
        
        headers = {
            'User-Agent': useragent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en_US',
            'Content-Type': 'application/json; charset=UTF-8',
            'X-XSRF-TOKEN': token,
            'Referer': 'http://sitereview.bluecoat.com/'
        }

        print('[*] BlueCoat: {}'.format(domain))
        
        response = s.post('https://sitereview.bluecoat.com/resource/lookup', headers=headers, json=postData, verify=False, proxies=proxies)

        if response.status_code != 200:
            error_message = "HTTP Error ({}-{}) - Is your IP blocked?".format(response.status_code, response.reason)
            print(error_message)
        
        responseJSON = json.loads(response.text)
        
        if 'errorType' in responseJSON:
            return responseJSON['errorType']
        
        return responseJSON['categorization'][0]['name']
    
    except Exception as e:
        print('[-] Error retrieving Bluecoat reputation! {0}'.format(e))
        return "error"

def evaluateIBMXForce(domain):
    """IBM XForce Domain Reputation"""
    try:
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {
            'User-Agent': useragent,
            'Accept': 'application/json, text/plain, */*',
            'x-ui': 'XFE',
            'Origin': url,
            'Referer': url
        }
        
        print('[*] IBM xForce: {}'.format(domain))
        
        response = s.get(url, headers=headers, verify=False, proxies=proxies)
        
        responseJSON = json.loads(response.text)
        
        if 'error' in responseJSON:
            return responseJSON['error']
        
        if not responseJSON['result']['cats']:
            return 'Uncategorized'
        
        categories = ', '.join([str(key) for key in responseJSON['result']['cats']])
        
        return '{0}(Score: {1})'.format(categories, str(responseJSON['result']['score']))
    
    except Exception as e:
        print('[-] Error retrieving IBM-Xforce reputation! {0}'.format(e))
        return "error"

def assessTalos(domain):
    """Cisco Talos Domain Reputation"""
    url = f'https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={domain}&offset=0&order=ip+asc'
    headers = {
         'User-Agent': useragent,
         'Referer': url
     }
     
     print('[*] Cisco Talos: {}'.format(domain))
     
     try:
         response = s.get(url, headers=headers, verify=False, proxies=proxies)
         responseJSON = json.loads(response.text)
         
         if 'error' in responseJSON:
             error_message = str(responseJSON['error'])
             if error_message == "Unfortunately, we can't find any results for your search.":
                 return 'Uncategorized'
             
             if responseJSON['category'] is None:
                 return 'Uncategorized'
             
             return '{0} (Score: {1})'.format(str(responseJSON['category']['description']), str(responseJSON['web_score_name']))
         
     except Exception as e:
         print('[-] Error retrieving Talos reputation! {0}'.format(e))
    
     return "error"

def evaluateMcAfeeWG(domain):
    """McAfee Web Gateway Domain Reputation"""
    try:
         print('[*] McAfee Web Gateway (Cloud): {}'.format(domain))
         
         s = requests.Session()
         headers = {
             'User-Agent': useragent,
             'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
             'Accept-Language': 'en-US,en;q=0.5',
             'Accept-Encoding': 'gzip, deflate',
             'Referer':'https://sitelookup.mcafee.com/'
         }
         
         response = s.get("https://sitelookup.mcafee.com", headers=headers, verify=False, proxies=proxies)

         soup = BeautifulSoup(response.text,"html.parser")
         
         hidden_tags = soup.find_all("input", {"type": "hidden"})
         
         for tag in hidden_tags:
             if tag['name'] == 'sid':
                 sid = tag['value']
             elif tag['name'] == 'e':
                 e = tag['value']
             elif tag['name'] == 'c':
                 c = tag['value']
             elif tag['name'] == 'p':
                 p = tag['value']

         multipart_form_data = {
             'sid': (None, sid),
             'e': (None, e),
             'c': (None, c),
             'p': (None, p),
             'action': (None, 'checksingle'),
             'product': (None, '14-ts'),
             'url': (None, domain)
         }

         response = s.post('https://sitelookup.mcafee.com/en/feedback/url', headers=headers, files=multipart_form_data, verify=False, proxies=proxies)

         if response.status_code == 200:
             soup = BeautifulSoup(response.text,"html.parser")
             
             for table in soup.findAll("table", {"class": ["result-table"]}):
                 data_cells = table.find_all('td')
                 
                 if "not valid" in data_cells[2].text:
                     return 'Uncategorized'
                 else:
                     status = data_cells[2].text
                     category = data_cells[3].text[1:].strip().replace('-', '-')
                     web_reputation = data_cells[4].text
                     return '{0}, Status: {1}, Web Reputation: {2}'.format(category,status,web_reputation)
         else:
             raise Exception

     except Exception as e:
         print('[-] Error retrieving McAfee Web Gateway Domain Reputation!')
         return "error"

def downloadMalwareList(malwaredomainsURL):
    """Downloads a current list of known malicious domains"""
    url = malwaredomainsURL
    response = s.get(url=url, headers=headers, verify=False, proxies=proxies)
    
    if response.status_code == 200:
         return response.text
    
    print("[-] Error reaching:{} Status: {}".format(url,response.status_code))

def analyzeDomain(domain):
    """Executes various domain reputation checks included in the project"""
    print('[*] Fetching domain reputation for: {}'.format(domain))
    
    if domain in maldomainsList:
         print("[!] {}: Identified as known malware domain (malwaredomains.com)".format(domain))

    bluecoat_result = assessBluecoat(domain)
    print("[+] {}: {}".format(domain, bluecoat_result))

    ibmxforce_result = evaluateIBMXForce(domain)
    print("[+] {}: {}".format(domain, ibmxforce_result))

    ciscotalos_result = assessTalos(domain)
    print("[+] {}: {}".format(domain,ciscotalos_result))

    umbrella_result="not available"
    
    if len(umbrella_apikey):
         umbrella_result=evaluateUmbrella(domain)

     print("[+] {}: {}".format(domain , umbrella_result))

     mcafeewg_result=evaluateMcAfeeWG(domain)
     print("[+] {}: {}".format(domain , mcafeewg_result))

     print("")
     
     results=[domain , bluecoat_result , ibmxforce_result , ciscotalos_result , umbrella_result , mcafeewg_result]
     return results

def solveCaptcha(url , session):
     """Downloads CAPTCHA image and saves to current directory for OCR with tesseract"""
     jpeg='captcha.jpg'
     
     try:
         response=session.get(url=url , headers=headers , verify=False , stream=True , proxies=proxies)
         
         if response.status_code==200:
             with open(jpeg,'wb') as f:
                 response.raw.decode_content=True
                 shutil.copyfileobj(response.raw,f)
         else:
             print('[-] Error downloading CAPTCHA file!')
             return False

         text=pytesseract.image_to_string(Image.open(jpeg))
         text=text.replace(" ","").rstrip()
         
         try:
             os.remove(jpeg)
         except OSError:
             pass

         return text

     except Exception as e:
          print("[-] Error solving CAPTCHA - {0}".format(e))
          return False

def createTable(header,data):
     """Generates a text-based table for printing to the console"""
     data.insert(0 , header)
     t=Texttable(max_width=maxwidth)
     t.add_rows(data)
     t.header(header)

     return t.draw()

def loginToExpiredDomains():
     """Login to the ExpiredDomains site with supplied credentials"""
     data="login=%s&password=%s&redirect_2_url=/begin" % (username,password)
     headers["Content-Type"]="application/x-www-form-urlencoded"
     
     r=s.post(expireddomainHost+"/login/",headers=headers,data=data ,proxies=proxies ,verify=False ,allow_redirects=False)

     cookies=s.cookies.get_dict()
     
     if "location" in r.headers :
         if "/login/" in r.headers["location"]:
             print("[!] Login failed")
             sys.exit()
             
     if "ExpiredDomainssessid" in cookies :
         print("[+] Login successful. ExpiredDomainssessid: %s" % (cookies["ExpiredDomainssessid"]))
     else :
         print("[!] Login failed")
         sys.exit()

def getCellValue(cells,index):
     if cells[index].find("a") is None :
          return cells[index].text.strip()
          
      return cells[index].find("a").text.strip()

## MAIN 
if __name__ == "__main__":
     parser=argparse.ArgumentParser(
          description='Finds expired domains and their categorization to identify potential candidates for C2 and phishing domains',
          epilog=''' Examples: ./domainhunter.py -k apples -c --ocr -t5 ./domainhunter.py --check --ocr -t3 ./domainhunter.py --single mydomain.com ./domainhunter.py --keyword tech --check --ocr --timing 5 --alexa ./domaihunter.py --filename inputlist.txt --ocr --timing 5''',
          formatter_class=argparse.RawDescriptionHelpFormatter)

      parser.add_argument('-a','--alexa', help='Filter results to Alexa listings', required=False , default=0 , action='store_const', const=1)
      parser.add_argument('-k','--keyword', help='Keyword used to refine search results', required=False , default=False , type=str , dest='keyword')
      parser.add_argument('-c','--check', help='Perform domain reputation checks', required=False , default=False , action='store_true', dest='check')
      parser.add_argument('-f','--filename', help='Specify input file of line delimited domain names to check', required=False , default=False , type=str , dest='filename')
      parser.add_argument('--ocr', help='Perform OCR on CAPTCHAs when challenged', required=False , default=False , action='store_true')
      parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False , default=100 , type=int , dest='maxresults')
      parser.add_argument('-s','--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False , default=False , dest='single')
      parser.add_argument('-t','--timing', help='Modifies request timing to avoid CAPTCHAs. Slowest(0) is 90-120 seconds; Default(3) is 10-20 seconds; Fastest(5) is no delay', required=False , default=3 , type=int , choices=range(0 ,6) , dest='timing')
      parser.add_argument('-w','--maxwidth', help='Width of text table', required=False , default=400 , type=int , dest='maxwidth')
      parser.add_argument('-V','--version', action='version' , version='%(prog)s {version}'.format(version=__version__))
      parser.add_argument("-P", "--proxy", required=False , default=None , help="proxy. ex https://127.0.0.1:8080")
      parser.add_argument("-u", "--username", required=False , default=None , type=str , help="username for expireddomains.net")
      parser.add_argument("-p", "--password", required=False , default=None , type=str , help="password for expireddomains.net")
      parser.add_argument("-o", "--output", required=False , default=None , type=str , help="output file path")
      parser.add_argument('-ks','--keyword-start', help='Keyword starts with used to refine search results', required=False , default="" , type=str , dest='keyword_start')
      parser.add_argument('-ke','--keyword-end', help='Keyword ends with used to refine search results', required=False , default="" , type=str , dest='keyword_end')
      parser.add_argument('-um','--umbrella-apikey', help='API Key for umbrella (paid)', required=False , default="" , type=str , dest='umbrella_apikey')
      parser.add_argument('-q','--quiet', help='Suppress initial ASCII art and header', required=False , default=False , action='store_true' , dest='quiet')

      args=parser.parse_args()

# Load dependent modules
try:
    import requests
    from bs4 import BeautifulSoup
    from texttable import Texttable
except Exception as e:
    print("Expired Domains Reputation Check")
    print("[-] Missing basic dependencies: {}".format(str(e)))
    print("[*] Install required dependencies.")

# Initialize session and headers
s = requests.Session()
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Main execution logic
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Finds expired domains and their categorization to identify potential candidates for C2 and phishing domains')
    
    # Add arguments to the parser
    parser.add_argument('-a', '--alexa', help='Filter results to Alexa listings', required=False, default=0, action='store_const', const=1)
    parser.add_argument('-k', '--keyword', help='Keyword used to refine search results', required=False, default=False, type=str)
    parser.add_argument('-c', '--check', help='Perform domain reputation checks', required=False, default=False, action='store_true')
    parser.add_argument('-f', '--filename', help='Specify input file of line delimited domain names to check', required=False, default=False, type=str)
    parser.add_argument('--ocr', help='Perform OCR on CAPTCHAs when challenged', required=False, default=False, action='store_true')
    parser.add_argument('-r', '--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False, default=100, type=int)
    parser.add_argument('-s', '--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False, default=False)
    parser.add_argument('-t', '--timing', help='Modifies request timing to avoid CAPTCHAs.', required=False, default=3, type=int)
    parser.add_argument('-w', '--maxwidth', help='Width of text table', required=False, default=400, type=int)
    parser.add_argument('-V', '--version', action='version', version='%(prog)s {version}'.format(version=__version__))
    
    args = parser.parse_args()

    # Execute login if credentials are provided
    if args.username and args.password:
        loginExpiredDomains()

    # Check domains based on user input
    if args.single:
        checkDomain(args.single)
    
    if args.filename:
        with open(args.filename, 'r') as file:
            for line in file:
                checkDomain(line.strip())

