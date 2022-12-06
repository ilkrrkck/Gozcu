#!/usr/bin/python3

import socket
import urllib.request
from os import path, remove
from platform import system
from subprocess import check_output, run
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup
from scapy.all import *
import scapy.layers.dns

TAB_1 = '\t'
TAB_2 = '\t\t'

# Çalışan OS
runningOS = system()

HOST = '192.168.1.13'  # Server IP.
PORT = 1597  # Server dinlenen port.

restrictedSitesList = []


def main():
    global clientSocket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('Server a bağlanılmaya çalışılıyor...')
    try:
        clientSocket.connect((HOST, PORT))  
        print(f'[INFO] Bağlantı Sağlandı: {HOST} portu: {PORT}.')
        welcomeMessage = clientSocket.recv(1024) 
        print(welcomeMessage.decode())
    except socket.error as error:
        exit(
            f'[ERROR] Server Bağlantısı Başarısız:\n\033[31m{error}\033[0m')


def MITM():
    while True:
        macList = []
        macDict = {}
        if runningOS == "Windows":
            ARPmacs = check_output("arp -a", shell=True).decode()

            for line in ARPmacs.splitlines():
                if "dynamic" in line:
                    macList.append(line[24:41])

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1

            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(
                        f'[WARNING]MAC address duplication bulundu. Man in the Middle Attack İhtimali Var!\nBu MAC i kontrol et: {MAC}\n\n'.encode())

        elif runningOS == "Linux":
            ARPmacs = check_output(
                "arp | awk '{print $3}' | grep -v HW | grep -v eth0", shell=True).decode()
            for line in ARPmacs.splitlines():
                macList.append(line)

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1
            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(
                        f'[WARNING]MAC address duplication bulundu. Man in the Middle Attack İhtimali Var!\nBu MAC i kontrol et: {MAC}\n\n'.encode())
        sleep(15)


def restricted_Sites_List_Maker():
    while True:
        # Restricted Websites webpage:
        restrictedWebsites = f"http://{HOST}/restricted_sites.html"

        HTMLrestrictedWebsites = urllib.request.urlopen(
            restrictedWebsites).read()
        soup = BeautifulSoup(HTMLrestrictedWebsites, features="lxml")

        textRestictedWebsites = soup.body.get_text() 

        lines = (line.strip() for line in textRestictedWebsites.splitlines())

        chunks = (phrase.strip()
                  for line in lines for phrase in line.split("  "))

        textRestictedWebsites = '\n'.join(chunk for chunk in chunks if chunk)

        if runningOS == "Windows":
            if path.exists("Restricted_Sites.txt"):
                remove("Restricted_Sites.txt")

            with open("Restricted_Sites.txt", "w") as restrictedSitesFile:
                restrictedSitesFile.write(textRestictedWebsites)
                run("attrib +h Restricted_Sites.txt", shell=True)

            with open("Restricted_Sites.txt", "r") as f:
                for siteLine in f.readlines():
                    restrictedSitesList.append(siteLine.strip())

        elif runningOS == "Linux":
            with open(".Restricted_Sites.txt", "w") as restrictedSitesFile:
                restrictedSitesFile.write(textRestictedWebsites)

            with open(".Restricted_Sites.txt", "r") as f:
                for siteLine in f.readlines():
                    restrictedSitesList.append(siteLine.strip())
        sleep(60)


def findDNS(pkt):
    if pkt.haslayer(DNS):
        ozet = pkt.summary()
        print("özet : ", ozet)
        if "Qry" in ozet:  
            url = pkt.summary().split('\"')[-2].replace("", "")[2:-2]
            print(url)
            for site in restrictedSitesList:
                if site in url:
                    clientSocket.send(
                        f'[ALERT] Bir Yasaklı Website ye Giriş Yapıldı:\n{site}\n\n'.encode())


if __name__ == '__main__':
    main()
    Thread(target=restricted_Sites_List_Maker).start()
    Thread(target=MITM).start()
    Thread(target=sniff(prn=findDNS)).start()

