#!/usr/bin/python
# coding=utf-8
import socket as sk
from optparse import OptionParser
import sys
import time
import re

TIMEOUT=5
TLD_DATA='TLD_DATA'
TODAY = time.strftime('%Y-%m-%d',time.localtime(time.time()))
sleep_time=1

def logo():
    logo = """
 _____ _____ _     _   _ ___________   
/  ___|_   _| |   | | | |  ___| ___ \  
\ `--.  | | | |   | | | | |__ | |_/ /  
 `--. \ | | | |   | | | |  __||    /   
/\__/ /_| |_| |___\ \_/ / |___| |\ \   
\____/ \___/\_____/\___/\____/\_| \_|  
                                       
                                       
 _   _  _____ ___________ _      _____ 
| \ | ||  ___|  ___|  _  \ |    |  ___|
|  \| || |__ | |__ | | | | |    | |__  
| . ` ||  __||  __|| | | | |    |  __| 
| |\  || |___| |___| |/ /| |____| |___ 
\_| \_/\____/\____/|___/ \_____/\____/ 
                                       
                                       

"""
    return logo

def whois_query(server,query):
    sd=sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    sd.settimeout(TIMEOUT)
    address=""
    try:
        address=sk.gethostbyname(server)
    except Exception as e:
        print(e,(server+"|FAILED TO RESOLVE HOSTNAME!"))
        sys.exit(0)
    try:
        sd.connect((address,43))
    except Exception as e:
        print(e,server+"|FAILED TO REACH WHOIS SERVER!")
        sys.exit(0)
    message=query+"\r\n"
    try:
        if(sys.version_info[0]==2):
            sd.sendall(message)
        else:
            sd.sendall(str.encode(message))
    except Exception as e:
        print(e,server+" FAILED TO SEND QUERY!")
        sys.exit(0)
    try:
        result = sd.recv(2048)
    except Exception as e:
        print(e,server+" FAILED TO RECEIVE MSG")
    return result

def find_server(tld,TLD_DATA):
    #open tls_data file
    try:
        with open(TLD_DATA) as f:
            tld_ini = f.readlines()
    except Exception as e:
        print('ERROR: TLD_DATA file not found')
    for line in tld_ini:
        tld_line = line.strip('\n')
        if(tld_line[0]!='/' and tld_line[0]!='='):
            arr=tld_line.split("=")
            whois_tld=arr[0]
            whois_server=arr[1]
            whois_resp=arr[2]
            if (whois_tld==tld):
                return (whois_server,whois_resp)

def writelog(file, data):
    try:
        with open(file, "a+") as ban:
            ban.write(data)
    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    usage="usage: domain.py -t tld -d dict"
    parser = OptionParser(usage=usage)
    parser.add_option("-t", "--tld", dest="TLD",help="domain TLD")
    parser.add_option("-d", "--dict", dest="DICT",help="domain dict")
    (options, args) = parser.parse_args()

    if options.TLD ==None or options.DICT==None:
        print(logo())
        print(usage)
        print('ERROR: You should specify TLD and DICT file\n')
        sys.exit(0)
    if options.TLD !=None and options.DICT!=None:
        TLD=options.TLD
        DICT=options.DICT
        out_file= TODAY + '_' + TLD + ".txt"
    #open tls_data file
    try:
        with open('TLD_DATA') as f:
            tld_ini = f.readlines()
    except Exception as e:
        print('ERROR: TLD_DATA file not found\n')

    #open DICT
    try:
        with open(DICT) as f:
            dict_ini = f.readlines()
    except Exception as e:
        print('ERROR: DICT file not found\n')
        sys.exit(0)
    print('Scanning domains with '+TLD+' domains...with '+DICT+'\n')

    (server,resp)=find_server(TLD,TLD_DATA)
    if(server==None):
        print("ERROR:WHOIS SERVER NOT FOUND")

    i=0
    for line in dict_ini:
        dict_line = line.strip('\n')
        domain=dict_line+"."+TLD
        result=whois_query(server,domain)
        if re.search(resp, str(result), re.I):
            message=(domain+" AVAILABLE FOR REGISTRATION!\n")
            print(message)
            writelog(out_file,domain+"\n")
        else:
            print(domain+" NOT AVAILABLE\n")
        i+=1
        if(i%5==0):
            time.sleep(sleep_time)
