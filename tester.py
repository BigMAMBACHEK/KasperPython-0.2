import os
import subprocess
import sys
import psutil
import socket



processes=[]

commands={
    "help_command":"Показывает список доступных команд",
    "scanning_pc":"Сканирование компьютера на вирусы",
    "pc_info":"Показывает характеристики компьютера",
    "check_disk":"Проверяет битось дисков", 
    "snanning_host":"Проверяет открыт ли порт или нет",
    "suspicious_process":"Проверяет на наличие старнных процессов",
}

def show_info():
    print("Доступные команды:")
    for cmd, desc in commands.items():
        print(f"  {cmd}: {desc}")

known_miners_and_viruses=["xmrig","minered","ccmier","trojan"]

def scanning_pc():
    suspicious_processes = []
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() in known_miners_and_viruses:
            suspicious_processes.append((process.info['name'], process.info['pid']))
    if suspicious_processes:
        message = "Suspicious processes detected:\n"
        for name, pid in suspicious_processes:
            message += f"{name} (PID: {pid})\n"
        print(message)
    else:
        print("Подозрительных процессов не обнаружено. Ваша система чиста!")

def pc_info():
    # Информация о процессоре
    cpu_count = psutil.cpu_count(logical=True)  # Количество логических ядер
    cpu_freq = psutil.cpu_freq()  # Частота процессора
    print(f"Процессор: {cpu_count} логических ядер")
    print(f"Частота процессора: {cpu_freq.current:.2f} МГц")

    # Информация о памяти
    virtual_mem = psutil.virtual_memory()
    print(f"Оперативная память: {virtual_mem.total / (1024 ** 3):.2f} ГБ")
    print(f"Свободная память: {virtual_mem.available / (1024 ** 3):.2f} ГБ")

    # Информация о дисках
    print("\nДиски:")
    for partition in psutil.disk_partitions():
        print(f"Диск: {partition.device}")
        usage = psutil.disk_usage(partition.mountpoint)
        print(f"  Всего: {usage.total / (1024 ** 3):.2f} ГБ")
        print(f"  Использовано: {usage.used / (1024 ** 3):.2f} ГБ")
        print(f"  Свободно: {usage.free / (1024 ** 3):.2f} ГБ")

    # Информация об аккумуляторе (если есть)
    if psutil.sensors_battery():
        battery = psutil.sensors_battery()
        print("\nБатарея:")
        print(f"  Уровень заряда: {battery.percent}%")
        print(f"  Время работы от батареи: {battery.secsleft // 60} минут")
    else:
        print("\nБатарея не обнаружена")


def list_drives():
    partitions = psutil.disk_partitions()
    drives = [partition.device for partition in partitions]
    return drives

def check_disk_for_errors():
    try:
        drives = list_drives()
        if not drives:
            print("Диски не найдены.")
            return

        print("Доступные диски:")
        for i, drive in enumerate(drives):
            print(f"{i + 1}: {drive}")

        choice = int(input("Выберите номер диска для проверки: "))
        if choice < 1 or choice > len(drives):
            print("Неверный выбор.")
            return

        drive = drives[choice - 1]
        command = f'chkdsk {drive}'
        result = os.system(command)

        if result == 0:
            print(f"Диск {drive} проверен, ошибок не найдено.")
        else:
            print(f"На диске {drive} обнаружена ошибка.")
    except Exception as e:
        print(f"Произошла ошибка при проверке диска: {e}")

known_suspicious_processes = [
    "xmrig", "minered", "ccminer", "trojan", "keylogger", "malware-inject"
]

def check_pc_on_process():
    suspicious_processes = []

    # Проверяем запущенные процессы
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_name = process.info['name'].lower()
            if process_name in known_suspicious_processes:
                suspicious_processes.append((process.info['name'], process.info['pid']))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Игнорируем ошибки доступа к процессу или если процесс завершился
            continue

    # Вывод результата
    if suspicious_processes:
        print("Найдены подозрительные процессы:")
        for name, pid in suspicious_processes:
            print(f"  {name} (PID: {pid})")

        # Возможность завершить процессы
        choice = input("Вы хотите завершить эти процессы? (Y/n): ").strip().lower()
        if choice == "Y":
            for name, pid in suspicious_processes:
                try:
                    process = psutil.Process(pid)
                    process.terminate()  # Завершение процесса
                    print(f"Процесс {name} (PID: {pid}) завершен.")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Не удалось завершить {name} (PID: {pid}): {e}")
        else:
            print("Завершение процессов отменено.")
    else:
        print("Подозрительных процессов не обнаружено.")


def checking_pc_on_hosting(host="127.0.0.1", ports=range(1, 1025)):
    open_ports = []
    print(f"Сканирование открытых портов на {host}...")

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Установить тайм-аут в 1 секунду
            result = sock.connect_ex((host, port))  # Проверка подключения
            if result == 0:  # Если результат 0, порт открыт
                open_ports.append(port)

    if open_ports:
        print("Открытые порты:")
        for port in open_ports:
            print(f"  Порт {port} открыт")
    else:
        print("Открытых портов не обнаружено.")
    
    return open_ports



def main():
    print(""" 
 __        ___   _ ___ _____ _____    _   _ _____ ____   ____ _____ ____ 
 \ \      / / | | |_ _|_   _| ____|  | | | | ____|  _ \ / ___| ____/ ___|
  \ \ /\ / /| |_| || |  | | |  _|    | |_| |  _| | |_) | |   |  _|| |  _ 
   \ V  V / |  _  || |  | | | |___   |  _  | |___|  _ <| |___| |__| |_| |
    \_/\_/  |_| |_|___| |_| |_____|  |_| |_|_____|_| \_\\____|_____\____|
    """)
    show_info()

    while True:
        user_input = input("\n> ").strip().split()
        if not user_input:
            continue

        command = user_input[0]
        args = user_input[1:]

        if command=="help_command":
            show_info()
        elif command=="scanning_pc":
            scanning_pc()
        elif command=="pc_info":
            pc_info()
        elif command=="check_disk":
            check_disk_for_errors()
        elif command=="snanning_host":
            checking_pc_on_hosting()
            host_to_scan = input("Введите IP-адрес для сканирования (по умолчанию 127.0.0.1): ") or " "
            checking_pc_on_hosting(host_to_scan)
        elif command=="suspicious_process":
            check_pc_on_process()
        else:
            print("Неизвестная команда. Введите команду help_command")



if __name__ == "__main__":
    main()
