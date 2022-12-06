from cmath import e
import codecs
from datetime import date, datetime
from fileinput import close
from math import radians
import os
import sys
import time
import traceback
from tracemalloc import start
import win32con
import win32evtlog
import win32evtlogutil
import winerror
import sys
import win32comext.shell.shell as shell
from pathlib import Path

"""
Critical Security Events
Event ID    What it means
4624    Successful account log on
4625	Failed account log on
4634	An account logged off
4648	A logon attempt was made with explicit credentials
4719	System audit policy was changed.
4964	A special group has been assigned to a new log on
1102	Audit log was cleared. This can relate to a potential attack
4720	A user account was created
4722	A user account was enabled
4723	An attempt was made to change the password of an account
4725	A user account was disabled
4728	A user was added to a privileged global group
4732	A user was added to a privileged local group
4756	A user was added to a privileged universal group
4738	A user account was changed
4740	A user account was locked out
4767	A user account was unlocked
4735	A privileged local group was modified
4737	A privileged global group was modified
4755	A privileged universal group was modified
4772	A Kerberos authentication ticket request failed
4777	The domain controller failed to validate the credentials of an account.
4782	Password hash an account was accessed
4616	System time was changed
4657	A registry value was changed
4697	An attempt was made to install a service
4698, 4699, 4700, 4701, 4702    Events related to Windows scheduled tasks being created, modified, deleted, enabled or disabled
4946	A rule was added to the Windows Firewall exception list
4947	A rule was modified in the Windows Firewall exception list
4950	A setting was changed in Windows Firewall
4954	Group Policy settings for Windows Firewall has changed
5025	The Windows Firewall service has been stopped
5031	Windows Firewall blocked an application from accepting incoming traffic
5152, 5153  A network packet was blocked by Windows Filtering Platform
5155	Windows Filtering Platform blocked an application or service from listening on a port
5157	Windows Filtering Platform blocked a connection
5447	A Windows Filtering Platform filter was changed

"""

PROJECTPATH = Path(__file__).parent.resolve()

eventID = []

eventDes = []

alertedEvents = []

writeLogPath = ""

line_break = '-' * 80

start_time = ""

ASADMIN = 'asadmin'




def getCriticalEvents():  # SORUNSUZ

    num = set('0123456789')
    f = open(f"{PROJECTPATH}\events.txt", "r")
    for x in f:
        for a in x.split('\t'):
            if any((s in num) for s in a):
                eventID.append(a)
            else:
                eventDes.append(a)
    close()


# ----------------------------------------------------------------------
def getAllEvents(server, logtypes, basePath):   # SORUNSUZ


    if not server:
        serverName = "localhost"
    else:
        serverName = server
    for logtype in logtypes:
        path = os.path.join(basePath, "%s_%s_log.log" % (serverName, logtype))


        getEventLogs(server, logtype, path)

# ----------------------------------------------------------------------


def getEventLogs(server, logtype, logPath):


    print("Logging %s events" % logtype)
    log = codecs.open(logPath, encoding='utf-8', mode='w')

    log.write("\n%s Log of %s Events\n" % (server, logtype))
    log.write("Created: %s\n\n" % time.ctime())
    log.write("\n" + line_break + "\n")
    hand = win32evtlog.OpenEventLog(server, logtype)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    print("Total events in %s = %s" % (logtype, total))
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    evt_dict = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
                win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
                win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
                win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
                win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}

    try:
        events = 1
        while events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            for ev_obj in events:
                # the_time = ev_obj.TimeGenerated.Format()  # '12/23/99 15:54:09'
                the_time = ev_obj.TimeGenerated.strftime(f'%d-%m-%Y %H:%M:%S')
                evt_id = str(winerror.HRESULT_CODE(ev_obj.EventID))
                computer = str(ev_obj.ComputerName)
                cat = ev_obj.EventCategory
        # seconds=date2sec(the_time)
                record = ev_obj.RecordNumber
                msg = win32evtlogutil.SafeFormatMessage(ev_obj, logtype)
                source = str(ev_obj.SourceName)
                if not ev_obj.EventType in evt_dict.keys():
                    evt_type = "unknown"
                else:
                    evt_type = str(evt_dict[ev_obj.EventType])
                log.write("Event Date/Time: %s\n" % the_time)
                log.write("Event ID / Type: %s / %s\n" % (evt_id, evt_type))
                log.write("Record #%s\n" % record)
                log.write("Source: %s\n\n" % source)
                log.write(msg)
                log.write("\n\n")
                log.write(line_break)
                log.write("\n\n")

                if logtype == "Security" and evt_id in eventID:
                    # ALARM ÜRETİMİ İÇİN EVENT ID LER BİR YANDAN GÖNDERİLİYOR.
                    criticalLogAlert(evt_id, evt_type,
                                     ev_obj.TimeGenerated, msg)
                else:
                    continue
    except Exception as e:
        # print(traceback.print_exc(sys.exc_info()))
        print("%s" % e)
    print("Log creation finished. Location of log is %s" % logPath)


def criticalLogAlert(evt_id, evt_type, evnt_generated, msg):

    logDate = evnt_generated.strftime(f'%d-%m-%Y')

    today = datetime.now().strftime(f'%d-%m-%Y')

    # print("\n",
    #      "Event Date/Time: %s\n" % evnt_generated,
    #      "Event ID / Type: %s / %s\n\n" % (evt_id, evt_type),)

    #print("*** {} NOLU EVENT TETİKLENDİ. {}'u İNCELEMEK İSTEYEBİLİRSİNİZ. ***".format(evt_id,alertlog.name))

   #print(evnt_generated," type ",type(evnt_generated))
   #print(start_time," type : ",type(start_time))
   
   #if logDate == today:
    if start_time <= evnt_generated:

        alertlog = open(f"{PROJECTPATH.parent}\Logs\Alerts\EventAlert_{logDate}.log",
                    encoding='utf-8', mode='a')
        
        alertlog.write("\n")
        alertlog.write("Event Date/Time: %s\n" % evnt_generated)
        alertlog.write("Event ID / Type: %s / %s\n\n" % (evt_id, evt_type))
        alertlog.write("%s\n\n" % msg)
        alertlog.write("%s\n\n" % line_break)
        
        if evt_id not in alertedEvents:  # alertlenen eventler . HENÜZ BASTIRMA MEKANİZMASI HAZIR DEĞİL
            alertedEvents.append(evt_id)
            print("*** {} NOLU EVENT TETİKLENDİ. KAYIT YERİ : {}  ***".format(evt_id, alertlog.name))
        else:
            alertedEvents


#if __name__ == "__main__":
#
#    start_time = datetime.now() # program başladıktan sonra gelen uyarılar dikkate alınsın diye
#    
#    # C:\Users\ilker\Desktop\EDR
#    #home_path = Path(__file__).parent.parent.resolve()
#
#    #cwd = os.getcwd()  # C:\Users\ilker\Desktop\EDR
#
#    server = None  # None = local machine
#    logTypes = ["System", "Application", "Security"]
#
#    getCriticalEvents()
#
#    # C:\Users\ilker\Desktop\EDR\Logs
#    getAllEvents(server, logTypes, os.getcwd()+f"\Logs")
