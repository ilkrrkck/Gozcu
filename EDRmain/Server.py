

from importlib.resources import path
import sys

from re import sub
import socket
from timeit import repeat
from turtle import Turtle
import urllib.request
from pathlib import Path
from subprocess import check_output, run
from threading import Thread, ThreadError
from time import sleep, time
import os
import platform
import subprocess
from datetime import datetime



#region Variables
TAB_1 = '\t'
TAB_2 = '\t\t'

PROJECTPATH = Path(__file__).resolve().parent
HOST = '192.168.1.13'  # win makine ip
PORT = 1597

line_break = '-' * 80

global taskCount

runcount = 0
# Socket object.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connectionsCount = 0  
activeAddressesList = []  
openClientSocketsList = []  

#endregion


def apache2Start():
    print("[INFO] Sistem Windows")
    # Apache çalıştırıldı.
    if subprocess.call(r'C:\Windows\Apache24\bin\httpd.exe', shell=True, start_new_session=True):
        print('[INFO] Apache2 Server Başlatıldı (http://localhost:80)')
    else:
        print('[ERROR] Apache Başlatılamadı')

    # sleep(5)
    try:
        response = urllib.request.urlopen(
            'http://127.0.0.1/restricted_sites.html')
    except:
        print("[ERROR] Yasaklı Sitelere Ulaşılamadı")
    sleep(5)


def connections():
    print(line_break,"\n")
    try:
        serverSocket.bind((HOST, PORT))  # Bind the socket.
        print(f'[INFO]Server Erişime Açıldı ({HOST})')
    except socket.error as error:
        exit(
            f'[ERROR] Server Kurulumda Hata:\n\033[31m{error}\033[0m')
    print(
        f'[INFO] Dinlenen Port {PORT}... (Bağlantı Bekleniyor)')
    serverSocket.listen(50)
    for clientSocket in openClientSocketsList:
        # Önceki tüm bağlantılar kapatılır:
        clientSocket.close()
        # Tüm önceki client'lar kapatılır ve aktif bağlantılar listeden silinir. 
        del openClientSocketsList[:], activeAddressesList[:]

    while True:
        try:
            # Bağlantı Kabul:
            conn, (address, port) = serverSocket.accept()
            openClientSocketsList.append(conn)
            connName = '{}:{}'.format(address, port)
            print(f'[INFO] {connName} Bağlandı!')
            welcomeMessage = f'Başarıyla EDR Server''a bağlandı {HOST}:{PORT}'
            conn.send(welcomeMessage.encode())
            global connectionsCount
            connectionsCount += 1  
            activeAddressesList.append(connName)
            print(
                f'[INFO] Aktif Bağlantı Sayısı : {connectionsCount}')
            Thread(target=handleClient, args=(conn, connName)).start()
            Thread(target=checkConnections).start()
        except socket.error as acceptError:
            print(
                f'[ERROR] Bağlantı Kabulünde Hata: {conn.getpeername()}:\n\033[31m{acceptError}\033[0m')
            continue


def handleClient(conn, connName):
    while True:
        data = conn.recv(4096).decode()
        if "MAC" in data:
            print(
                '[WARNING] Man in the Middle ihtimali. MitM Logger.log u kontrol edin')
            
            timestamp = now.strftime(f"%d/%m/%Y %H:%M:%S")
                   
            with open(f"{PROJECTPATH}/MitM Logger.log", "a+") as MitMLog:
                MitMLog.write(
                    f"[{timestamp}]{TAB_1}[{connName}]:\n{data}")  

        if "restricted" in data:

            print(
                f'[ALERT] Yasaklı sitelere girildi.Restricted Sites Logger.log u kontrol edin.')
            now = datetime.now()
            timestamp = now.strftime(f"%d/%m/%Y %H:%M:%S")
            

            
            print("Timestamp label : ",timestamp,"\n")
            with open(f'{PROJECTPATH}/Restricted Sites Logger.log', 'a+') as restrictedLog:
                restrictedLog.write(
                    f"[{timestamp}]{TAB_1}[{connName}]:\n{data}")  


# Her client'a bir boş metin göndererek canlılıklarınıı kontrol eder.
# Hata meydana gelirse Client'lar koptu demektir.
# Ölü client'ları listeden siler ve connection count bir azaltılır
# Her 10 saniyede bir bu kontrol yapılır
def checkConnections():
    while True:
        global connectionsCount
        if len(openClientSocketsList) != 0:
            for x, currentSocket in enumerate(openClientSocketsList):
                try:
                    # Send a whitespace to every socket in the list:
                    pingToClientMessage = ' '
                    currentSocket.send(pingToClientMessage.encode())
                except:
                    print(f'[INFO] Client {x} Disconnected!')
                    # Deletes the client socket and address from the lists:
                    del openClientSocketsList[x], activeAddressesList[x]
                    connectionsCount -= 1
                    if connectionsCount == 0:  # If no connections left:
                        print(f'[INFO] No active connections left.')
                    else:  # If there are still connections left:
                        print(
                            f'[INFO] Number of Active Connections: {connectionsCount}')
                        print('[INFO] Active addresses connected:')
                        # Prints a list of the current open connections:
                        for index, value in enumerate(activeAddressesList):
                            print(f'{TAB_1}{index}.{TAB_1}{value}')
                    continue
        sleep(10)


#endregion



#region LOG MANAGEMENT
def startLogSystem():


    server = None  # None = local machine
    logTypes = ["System", "Application", "Security"]
    
    pylog.getCriticalEvents()
    while True:
        print(os.getcwd()+f"\Logs"  )
        pylog.getAllEvents(server, logTypes, os.getcwd()+f"\Logs") # DİRECTORY DE SORUN OLABİLİR DİKKAT ET
        print("[INFO] Log Yönetim Sistemi Bekleme Süresinde .. 10dk")
        sleep(600) # 10 dakikada bir event kontrolü
        

def startRegisteryCheckSystem():
    print(line_break,"\n[INFO] Registery Kontrolü Başladı..")
    
    while True:     
        regcheck.get_regs()
        regcheck.runCount = regcheck.runCount+1
        sleep(30)
        
#endregion

# Start of the Script:
if __name__ == '__main__':
    
    pylogDIR = os.path.dirname(os.path.abspath(path="C:\\Users\\ilker\\Desktop\\EDR\\EventLogCollect\\pyLog.py"))
    regCheckDIR = os.path.dirname(os.path.abspath(path="C:\\Users\\ilker\\Desktop\\EDR\\RegCheck\\check.py"))

    sys.path.append(os.path.dirname(pylogDIR))
    sys.path.append(os.path.dirname(regCheckDIR))
    
    import EventLogCollect.pyLog as pylog
    import RegCheck.check as regcheck

    apache2Start() # Web Server başlatılır
    
    # Diğer Sistemler Eş Zamanlı Başlatılır # 
    try:     
        Thread(target=connections).start()
        Thread(target=startLogSystem).start()
        Thread(target=startRegisteryCheckSystem).start()
        Thread(target= os.system(f"start /wait cmd /c python {PROJECTPATH.parent}\\ProcessMon\\process_monitor.py")).start()
    except ThreadError:
        pass
        
   