import requests
import base64

def chkifobfs(net,type,obfs):
    if(type == "none" and  net != "ws"):
        return ""
    else:
        return obfs

def chkobfs(net):
    if(net == "ws"):
        return "ws"
    else:
        return "http"

def chkobfspath(path):
    if(path != ""):
        return path
    else:
        return "/"

def chkobfshost(add,host):
    if(host == ""):
        return add
    else:
        return host

def chktls(tls):
    if(tls == "tls"):
        return "true"
    else:
        return "false"
def converter(url):
    ua="Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16A5366a"
    group="V2speed"
    method="chacha20-ietf-poly1305"
    strInput=str(requests.get(url).text)+"=="
    strInput=base64.b64decode(strInput)
    strInput=strInput.decode()
    vmess_list=strInput.split("\n")
    vmess_list.pop()
    strResult=""
    for vmess in vmess_list:
        vmess=vmess.replace("vmess://","")
        vmess.strip()
        strTemp=base64.b64decode(vmess).decode()
        dict_vmess=eval(strTemp)
        ps=dict_vmess['ps']
        add=dict_vmess["add"]
        port=dict_vmess["port"]
        path=dict_vmess["path"].replace("\\","")
        type1=dict_vmess["type"]
        id1=dict_vmess["id"]
        net=dict_vmess["net"]
        host=dict_vmess["host"]
        tls=dict_vmess["tls"]
        obfs=",obfs="+chkobfs(net)+",obfs-path=\""+chkobfspath(path)+"\",obfs-header=\"Host: "+chkobfshost(add,host)+"[Rr][Nn]User-Agent: "+ua+"\""
        quanVmess=ps+" = vmess,"+add+","+port+","+method+",\""+id1+"\",group="+group+",over-tls="+chktls(tls)+",certificate=1"+chkifobfs(net,type1,obfs)
        strResult+="vmess://"+base64.b64encode(quanVmess.encode()).decode()+'\r'
    return base64.b64encode(strResult.encode()).decode()