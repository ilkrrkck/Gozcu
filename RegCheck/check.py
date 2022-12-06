from asyncio.windows_events import NULL
from datetime import date, datetime
import os
from pathlib import Path
from queue import Empty
from time import sleep
from winreg import *

PROJECTPATH = Path(__file__).parent.resolve()


"""
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKLM\SYSTEM\MountedDevices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Services
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Services
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServicesOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServicesOnce
HKLM\SOFTWARE\Microsoft\Command Processor
HKCU\Software\Microsoft\Command Processor
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SYSTEM\CurrentControlSet\Services
HKCR\exe\fileshell\opencommand
HKEY_CLASSES_ROOT\batfile\shell\open\command
HKEY_CLASSES_ROOT\comfile\shell\open\command
"""

regName = []

regData = []

runCount =0

line_break = '-' * 80

regs_HKLM = [
    'SYSTEM\MountedDevices',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon']

regs_HKCU = [
    'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'Software\Microsoft\Command Processor']

regs_HKCR = [
    'exe\fileshell\opencommand',
    'batfile\shell\open\command',
    'comfile\shell\open\command']


def get_regs():
    HLMReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    
    for reg in regs_HKLM:
        rreg = r"{}".format(reg)   
        HLMKey = OpenKey(HLMReg, rreg) 
        print(rreg,"\t","Okunuyor..","\n\n")  
        for taskCount in range(1024):
            try:             
                name, data, index = EnumValue(HLMKey, taskCount)
                if(rreg =="SYSTEM\MountedDevices"): # mountedın verisi çok fazla ve anlamsız. O yüzden sakladım.
                    print("name : ",name,)
                    continue
                               
                print("name : ",name,"\ndata : ",data)
                
                if runCount == 0:
                    regName.append(name)
                    regData.append(data)
                elif regData[regName.index(name)]!= data and runCount !=0:
                    changeTime = datetime.now()
                    alarm(name,regData[regName.index(name)],data,changeTime)
                    data = regData[regName.index(name)]
                else:
                    regName,regData
                
            except EnvironmentError:
                print("\n",taskCount," kayıt bulundu.")
                break
            
            print("\n")
        print("*","-"*40,"*","\n\n")
        CloseKey(HLMKey)
      
            


def alarm(name,data,newData,changeTime):
    """
    
    print(r"*** Writing to SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run ***")
    aKey = OpenKey(aReg, r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\Run", 0, KEY_WRITE)
    try:   
    SetValueEx(aKey,"MyNewKey",0, REG_SZ, r"c:\\winnt\\explorer.exe") 
    except EnvironmentError:                                          
        print("Encountered problems writing into the Registry...")
    CloseKey(aKey)
    """
    logdate = datetime.now().strftime(f"%d-%m-%Y")
    logFile = open(f"{PROJECTPATH.parent}\Logs\Alerts\RegistryChange_{logdate}.log",
                    encoding='utf-8', mode='a')

    logFile.write("Change Time: %s\n" % changeTime)
    logFile.write("Registry  %s" % name)
    logFile.write("\n")
    logFile.write("Old Value: %s  / "% data)
    logFile.write("New Value %s" % newData)
    logFile.write("\n")
    logFile.write(line_break)
    logFile.write("\n")
    
    regData[regName.index(name)] =  newData
    
    print("*** {} İSİMLİ KAYIT DEĞİŞTİRİLDİ *** \n ESKİ DEĞER : {} / YENİ DEĞER : {} \nLOG : {} ".format(name, data,newData,logFile.name))
    

