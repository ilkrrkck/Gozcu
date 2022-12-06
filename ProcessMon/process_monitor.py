import psutil
from datetime import datetime
import pandas as pd
import time
import os

# CMD LİNE ÜZERİNDEN ÇALIŞIYOR VE ARGÜMAN GEREKİYOR


def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024


def get_processes_info():
    # tüm process dizinlerini ekler
    processes = []
    for process in psutil.process_iter():
        # tüm process infolarını al
        with process.oneshot():
            # Process ID 
            pid = process.pid
            if pid == 0:
                # System Idle Process, Windows NT için. Görmek işe yaramaz.
                continue
            # Çalıştırılan exe'nin adı
            name = process.name()
            # process oluşma zamanı
            try:
                create_time = datetime.fromtimestamp(process.create_time())
            except OSError:
                # boot time processleri
                create_time = datetime.fromtimestamp(psutil.boot_time())
            try:
                # programı execute edebilen çekirdek sayısı
                cores = len(process.cpu_affinity())
            except psutil.AccessDenied:
                cores = 0
            # CPU kullanımı yüzde
            cpu_usage = process.cpu_percent()
            # process statüleri (running, idle, ...)
            status = process.status()
            try:
                # process önceliği (düşük değer daha öncelikli)
                nice = int(process.nice())
            except psutil.AccessDenied:
                nice = 0
            try:
                # memory kullanımı byte bazında
                memory_usage = process.memory_full_info().uss
            except psutil.AccessDenied:
                memory_usage = 0
            # okunan ve yazılan toplam byte
            io_counters = process.io_counters()
            read_bytes = io_counters.read_bytes
            write_bytes = io_counters.write_bytes
            # processin oluşturduğu toplam threadler
            n_threads = process.num_threads()
            # processi oluşturan kullanıcı
            try:
                username = process.username()
            except psutil.AccessDenied:
                username = "N/A"
            
        processes.append({
            'pid': pid, 'name': name, 'create_time': create_time,
            'cores': cores, 'cpu_usage': cpu_usage, 'status': status, 'nice': nice,
            'memory_usage': memory_usage, 'read_bytes': read_bytes, 'write_bytes': write_bytes,
            'n_threads': n_threads, 'username': username,
        })

    return processes


def construct_dataframe(processes):
    # pandas dataframe
    df = pd.DataFrame(processes)
    df.set_index('pid', inplace=True)
    df.sort_values(sort_by, inplace=True, ascending=not descending)
    
    df['memory_usage'] = df['memory_usage'].apply(get_size)
    df['write_bytes'] = df['write_bytes'].apply(get_size)
    df['read_bytes'] = df['read_bytes'].apply(get_size)
    df['create_time'] = df['create_time'].apply(datetime.strftime, args=(f"%Y-%m-%d %H:%M:%S",)) #buraya dikkat
    
    df = df[columns.split(",")]
    return df

if __name__ == "__main__":

    columns = "name,cpu_usage,memory_usage,read_bytes,write_bytes,status,create_time,nice,n_threads,cores"
    sort_by = "memory_usage"
    descending = "store_false"
    n = 25
    live_update = "store_true"
    # processleri ilk kez bastır
    processes = get_processes_info()
    df = construct_dataframe(processes)
    if n == 0:
        print(df.to_string())
    elif n > 0:
        print(df.head(n).to_string())
    # bastırmaya devam et
    while live_update:
        # tüm process infolarını al
        processes = get_processes_info()
        df = construct_dataframe(processes)
        # ekranı temizle
        os.system("cls") if "nt" in os.name else os.system("clear")
        if n == 0:
            print(df.to_string())
        elif n > 0:
            print(df.head(n).to_string())
        time.sleep(0.7)