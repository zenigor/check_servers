import requests
import yaml
import subprocess
import json
import time
import os
import shutil

# --- КОНФИГУРАЦИЯ ---
SERVERS_YAML_URL = "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml"
TARGET_URL_TO_CHECK = "https://aistudio.google.com"
# УКАЖИТЕ ПУТЬ К ВАШЕМУ ИСПОЛНЯЕМОМУ ФАЙЛУ XRAY ИЛИ V2RAY
CORE_EXECUTABLE_PATH = "core/xray.exe" # Пример для Xray
# CORE_EXECUTABLE_PATH = r"C:\путь\к\v2rayN-Core\v2ray-core\v2ray.exe" # Пример для V2Ray

LOCAL_SOCKS_PORT = 10808
TEMP_CONFIG_FILENAME = "temp_checker_config.json"
GOOD_SERVERS_FILENAME = "good_servers.yml"
REQUEST_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Ограничение количества проверяемых серверов. Установите 0 или None для проверки всех.
MAX_SERVERS_TO_TEST = 200
# --- КОНЕЦ КОНФИГУРАЦИИ ---

def check_core_executable():
    if not os.path.exists(CORE_EXECUTABLE_PATH):
        print(f"Ошибка: Исполняемый файл ядра '{CORE_EXECUTABLE_PATH}' не найден.")
        print("Пожалуйста, проверьте и исправьте путь в переменной CORE_EXECUTABLE_PATH.")
        return False
    # shutil.which() проверяет, есть ли исполняемый файл в PATH или по прямому пути (для Windows)
    if not shutil.which(CORE_EXECUTABLE_PATH):
         print(f"Предупреждение: Файл ядра '{CORE_EXECUTABLE_PATH}' найден, но shutil.which() не может его верифицировать как исполняемый. Убедитесь, что путь полный и корректный.")
    return True

def fetch_server_configs(url):
    print(f"Скачивание списка серверов с {url}...")
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        # Замена одинарных кавычек на двойные для некоторых нестрогих YAML
        yaml_content = response.text.replace("'", '"') 
        # Замена некоторых булевых значений, которые PyYAML может не понять без кавычек
        yaml_content = yaml_content.replace('tls: "true"', 'tls: true').replace('tls: "false"', 'tls: false')
        yaml_content = yaml_content.replace('udp: "true"', 'udp: true').replace('udp: "false"', 'udp: false')
        yaml_content = yaml_content.replace('skip-cert-verify: "true"', 'skip-cert-verify: true')
        yaml_content = yaml_content.replace('skip-cert-verify: "false"', 'skip-cert-verify: false')
        return yaml.safe_load(yaml_content)
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при скачивании списка серверов: {e}")
        return None
    except yaml.YAMLError as e:
        print(f"Ошибка при парсинге YAML: {e}")
        print("Попробуйте проверить YAML на валидность. Возможно, проблема в одинарных/двойных кавычках или неэкранированных спецсимволах.")
        return None

def create_v2ray_config(server_details):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": LOCAL_SOCKS_PORT, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}
        }],
        "outbounds": []
    }

    outbound_config = {
        "protocol": server_details.get("type", "").lower(),
        "settings": {},
        "streamSettings": { # Инициализация streamSettings
            "network": server_details.get("network", "tcp"), # tcp, ws, grpc etc.
            "security": "", # tls, xtls, reality
        }
    }
    
    # Нормализация некоторых полей из Clash YAML
    if server_details.get("tls") == True: # Clash "tls: true"
        server_details["tls"] = "tls"
    
    server_name_for_log = server_details.get('name', 'N/A')

    # Протокол-специфичные настройки
    protocol = outbound_config["protocol"]
    if protocol == "vmess":
        outbound_config["settings"]["vnext"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "users": [{
                "id": server_details.get("uuid"),
                "alterId": int(server_details.get("alterId", server_details.get("alterid", 0))), # common typo
                "security": server_details.get("cipher", "auto"),
                "level": 0
            }]
        }]
    elif protocol == "vless":
        outbound_config["settings"]["vnext"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "users": [{
                "id": server_details.get("uuid"),
                "encryption": server_details.get("cipher", "none"), # "none" for VLESS typically
                "flow": server_details.get("flow", ""),
                "level": 0
            }]
        }]
        # Проверка на REALITY (часто встречается в VLESS)
        reality_opts_yaml = server_details.get("reality-opts", {})
        if server_details.get("reality") == "true" or server_details.get("reality") == True or reality_opts_yaml:
            outbound_config["streamSettings"]["security"] = "reality"
            outbound_config["streamSettings"]["realitySettings"] = {
                "serverName": server_details.get("servername", server_details.get("sni", "")),
                "fingerprint": server_details.get("fingerprint", reality_opts_yaml.get("fingerprint", "chrome")),
                "publicKey": reality_opts_yaml.get("public-key", server_details.get("public-key", "")),
                "shortId": reality_opts_yaml.get("short-id", server_details.get("short-id", "")),
                "spiderX": reality_opts_yaml.get("spider-x", server_details.get("spiderX", "")),
            }
            # Для REALITY TLS из YAML не используется, т.к. REALITY сам управляет "защищенным" соединением
            server_details["tls"] = None # Предотвращаем применение обычного TLS, если есть REALITY
            print(f"  Конфигурируется REALITY для {server_name_for_log}")


    elif protocol == "trojan":
         outbound_config["settings"]["servers"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "password": server_details.get("password"),
            "level": 0
        }]
    elif protocol == "ss" or protocol == "shadowsocks":
        outbound_config["protocol"] = "shadowsocks" # Нормализация
        ss_settings = {
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "method": server_details.get("cipher"), # В Clash YAML 'cipher' это метод
            "password": server_details.get("password"),
        }
        # Поддержка плагинов для SS (базовая)
        plugin = server_details.get("plugin")
        plugin_opts = server_details.get("plugin-opts", {})
        if plugin == "obfs":
            ss_settings["obfs"] = plugin_opts.get("mode")
            ss_settings["obfsparam"] = plugin_opts.get("host")
        elif plugin == "v2ray-plugin" and plugin_opts.get("mode") == "websocket":
            outbound_config["streamSettings"]["network"] = "ws" # Принудительно ставим сеть ws
            outbound_config["streamSettings"]["wsSettings"] = {
                "path": plugin_opts.get("path", "/"),
                "headers": {"Host": plugin_opts.get("host", server_details.get("server"))}
            }
            if plugin_opts.get("tls") == True: # Если плагин требует TLS
                 server_details["tls"] = "tls" # Устанавливаем tls для дальнейшей обработки
                 # SNI для v2ray-plugin TLS будет взят из plugin_opts.host или server_details.servername
                 if "servername" not in server_details and plugin_opts.get("host"):
                     server_details["servername"] = plugin_opts.get("host")


        outbound_config["settings"]["servers"] = [ss_settings]
    else:
        print(f"  Предупреждение: Протокол '{protocol}' для сервера '{server_name_for_log}' не полностью поддерживается этим скриптом. Попытка базовой конфигурации.")
        # Можно добавить другие протоколы или общую логику здесь
        return None


    # Общие настройки StreamSettings (сеть, ws, grpc, tls/xtls)
    # Сеть (ws, grpc)
    network_type = outbound_config["streamSettings"]["network"]
    if network_type == "ws" and not outbound_config["streamSettings"].get("wsSettings"): # Если wsSettings еще не заданы плагином
        ws_opts = server_details.get("ws-opts", {})
        path = ws_opts.get("path", server_details.get("ws-path", "/")) # ws-path из Clash
        headers = ws_opts.get("headers", {})
        if not headers.get("Host") and server_details.get("ws-host"): # ws-host из Clash
            headers["Host"] = server_details.get("ws-host")
        if not headers.get("Host") and server_details.get("host"): # общий 'host' как fallback для WS Host
            headers["Host"] = server_details.get("host")
        
        outbound_config["streamSettings"]["wsSettings"] = {"path": path}
        if headers: # Добавляем заголовки только если они есть
            outbound_config["streamSettings"]["wsSettings"]["headers"] = headers

    elif network_type == "grpc" and not outbound_config["streamSettings"].get("grpcSettings"):
        grpc_opts = server_details.get("grpc-opts", {})
        service_name = grpc_opts.get("grpc-service-name", server_details.get("serviceName", "")) # serviceName из Clash
        if service_name:
            outbound_config["streamSettings"]["grpcSettings"] = {"serviceName": service_name}

    # TLS / XTLS (если не REALITY)
    yaml_tls_type = server_details.get("tls") # Уже нормализовано к "tls" если было true
    if outbound_config["streamSettings"]["security"] != "reality" and yaml_tls_type in ["tls", "xtls"]:
        outbound_config["streamSettings"]["security"] = yaml_tls_type
        
        sni_val = server_details.get("servername", server_details.get("sni"))
        # Если SNI не указан явно, пытаемся взять из Host заголовка ws или host из plugin-opts (для ss+v2ray-plugin)
        if not sni_val:
            if network_type == "ws":
                ws_host_header = outbound_config["streamSettings"].get("wsSettings", {}).get("headers", {}).get("Host")
                if ws_host_header:
                    sni_val = ws_host_header
        if not sni_val: # крайний случай - сам сервер
            sni_val = server_details.get("server")

        common_tls_xtls_settings = {
            "serverName": sni_val,
            "allowInsecure": server_details.get("skip-cert-verify", False) or server_details.get("allowInsecure", False),
        }
        if "fingerprint" in server_details and server_details["fingerprint"]:
            common_tls_xtls_settings["fingerprint"] = server_details["fingerprint"]
        
        if yaml_tls_type == "tls":
            outbound_config["streamSettings"]["tlsSettings"] = common_tls_xtls_settings
        elif yaml_tls_type == "xtls":
            outbound_config["streamSettings"]["xtlsSettings"] = common_tls_xtls_settings
            # 'flow' для VLESS XTLS уже должен быть в users settings

    config["outbounds"].append(outbound_config)
    config["outbounds"].append({"protocol": "freedom", "tag": "direct", "settings": {}}) # Для DNS и др.

    try:
        with open(TEMP_CONFIG_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return TEMP_CONFIG_FILENAME
    except Exception as e:
        print(f"  Ошибка записи временного файла конфигурации {TEMP_CONFIG_FILENAME}: {e}")
        return None

def test_server_connection(server_name):
    proxies = {
        "http": f"socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}",
        "https": f"socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}",
    }
    headers = {"User-Agent": USER_AGENT}
    print(f"  Проверка {server_name} -> {TARGET_URL_TO_CHECK} через SOCKS5://127.0.0.1:{LOCAL_SOCKS_PORT}")
    try:
        # Отключаем проверку SSL сертификата самого проксируемого запроса, 
        # т.к. мы тестируем доступность, а не валидность SSL сайта через прокси.
        # Иначе могут быть ошибки SSL из-за MITM-подобного поведения прокси.
        response = requests.get(TARGET_URL_TO_CHECK, proxies=proxies, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        
        print(f"  Сервер '{server_name}': Статус {response.status_code}, URL: {response.url}")
        if response.status_code == 200:
            # Проверка, что это действительно страница AI Studio, а не капча или страница логина Google
            if "aistudio.google.com" in response.url.lower() or \
               ("google ai studio" in response.text.lower() or "gemini" in response.text.lower()): # более общие маркеры
                 print(f"  УСПЕХ: Сервер '{server_name}' работает и вернул страницу Google AI Studio.")
                 return True
            else:
                 print(f"  ПРЕДУПРЕЖДЕНИЕ: Сервер '{server_name}' вернул 200, но контент не похож на AI Studio. Возможно, редирект или капча.")
                 # Для отладки можно сохранить контент:
                 # with open(f"debug_{server_name.replace('/', '_')}.html", "w", encoding="utf-8") as df:
                 #    df.write(response.text)
                 return False # Считаем это неудачей, если не уверены
        elif response.status_code == 403:
            print(f"  ОШИБКА (403): Сервер '{server_name}' заблокирован для {TARGET_URL_TO_CHECK}.")
            return False
        else:
            print(f"  ОШИБКА (код {response.status_code}): Сервер '{server_name}' вернул неожиданный статус.")
            return False
    except requests.exceptions.Timeout:
        print(f"  ОШИБКА (Таймаут): Сервер '{server_name}' не ответил за {REQUEST_TIMEOUT} сек.")
        return False
    except requests.exceptions.ProxyError as e:
        print(f"  ОШИБКА (Прокси): Сервер '{server_name}': Не удалось подключиться через прокси. {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  ОШИБКА (Соединение): Сервер '{server_name}': {e}")
        return False

def main():
    if not check_core_executable():
        return

    all_servers_data = fetch_server_configs(SERVERS_YAML_URL)
    if not all_servers_data:
        print("Не удалось получить или распарсить список серверов.")
        return

    all_proxies_original = all_servers_data.get("proxies", [])
    if not all_proxies_original:
        print("Ключ 'proxies' не найден в YAML файле или список серверов пуст.")
        return
    
    proxies_to_process = []
    if MAX_SERVERS_TO_TEST and MAX_SERVERS_TO_TEST > 0:
        proxies_to_process = all_proxies_original[:MAX_SERVERS_TO_TEST]
        print(f"Найдено {len(all_proxies_original)} серверов. Будет протестировано первых {len(proxies_to_process)} (согласно MAX_SERVERS_TO_TEST={MAX_SERVERS_TO_TEST}).")
    else:
        proxies_to_process = all_proxies_original
        print(f"Найдено {len(proxies_to_process)} серверов. MAX_SERVERS_TO_TEST={MAX_SERVERS_TO_TEST} (проверка всех). Начинаю проверку...")

    good_proxies = []
    total_servers_being_tested = len(proxies_to_process)

    for i, server_details in enumerate(proxies_to_process):
        # Проверка на None, если YAML парсер вернул такой элемент
        if server_details is None:
            print(f"\n[{i+1}/{total_servers_being_tested}] Пропуск элемента: некорректные данные (None) в списке серверов.")
            continue

        server_name = server_details.get("name", f"Сервер_{i+1}")
        print(f"\n[{i+1}/{total_servers_being_tested}] Тестирую сервер: {server_name}")

        required_fields = ["server", "port", "type"]
        if not all(k in server_details for k in required_fields):
            print(f"  Пропуск сервера '{server_name}': отсутствуют обязательные поля ({', '.join(required_fields)}).")
            continue
        
        proto_type = server_details["type"].lower()
        if proto_type in ["vmess", "vless"] and "uuid" not in server_details:
             print(f"  Пропуск '{server_name}' ({proto_type}): отсутствует 'uuid'.")
             continue
        if proto_type == "trojan" and "password" not in server_details:
             print(f"  Пропуск '{server_name}' (trojan): отсутствует 'password'.")
             continue
        if proto_type in ["ss", "shadowsocks"] and not ("password" in server_details and "cipher" in server_details):
             print(f"  Пропуск '{server_name}' ({proto_type}): отсутствует 'password' или 'cipher'.")
             continue


        config_file = create_v2ray_config(server_details)
        if not config_file:
            print(f"  Не удалось создать конфигурацию для '{server_name}'. Пропускаю.")
            continue

        process = None
        try:
            startupinfo = None
            if os.name == 'nt': # Скрытие окна консоли на Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # Команда для Xray: xray run -c config.json. Для старого V2Ray: v2ray -config config.json
            core_command = [CORE_EXECUTABLE_PATH, "run", "-c", config_file]
            # Если используете старый V2Ray, раскомментируйте следующую строку и закомментируйте предыдущую
            # core_command = [CORE_EXECUTABLE_PATH, "-config", config_file]


            process = subprocess.Popen(core_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
            print(f"  Ядро запущено для '{server_name}' (PID: {process.pid}). Ожидание 3 сек...")
            time.sleep(3)

            if process.poll() is not None:
                stdout, stderr = process.communicate()
                print(f"  Ошибка запуска ядра для '{server_name}'.")
                print(f"  Stdout: {stdout.decode(errors='ignore').strip()}")
                print(f"  Stderr: {stderr.decode(errors='ignore').strip()}")
                continue

            if test_server_connection(server_name):
                good_proxies.append(server_details)

        except Exception as e:
            print(f"  Критическая ошибка при тестировании сервера '{server_name}': {e}")
        finally:
            if process and process.poll() is None: # Если процесс еще жив
                print(f"  Остановка ядра для '{server_name}' (PID: {process.pid})...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"  Ядро для '{server_name}' не остановилось, принудительное завершение.")
                    process.kill()
                    process.wait()
            if os.path.exists(TEMP_CONFIG_FILENAME):
                try:
                    os.remove(TEMP_CONFIG_FILENAME)
                except OSError as e:
                    print(f"  Не удалось удалить временный файл {TEMP_CONFIG_FILENAME}: {e}")


    print(f"\nПроверка завершена. Найдено {len(good_proxies)} работающих серверов из {total_servers_being_tested} протестированных.")

    if good_proxies:
        output_data = {"proxies": good_proxies} # Сохраняем в том же формате, что и исходный файл
        try:
            with open(GOOD_SERVERS_FILENAME, 'w', encoding='utf-8') as f:
                yaml.dump(output_data, f, allow_unicode=True, sort_keys=False, indent=2, default_flow_style=False)
            print(f"Список работающих серверов сохранен в файл: {GOOD_SERVERS_FILENAME}")
        except Exception as e:
            print(f"Ошибка при сохранении файла {GOOD_SERVERS_FILENAME}: {e}")
            print("Список работающих серверов (сырой вывод YAML):")
            print(yaml.dump(output_data, allow_unicode=True, sort_keys=False, indent=2))
    else:
        print("К сожалению, работающих серверов, не возвращающих 403 для Google AI Studio, не найдено среди протестированных.")

if __name__ == "__main__":
    # Добавляем предупреждение о requests.get(..., verify=False)
    import warnings
    from urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter('ignore', InsecureRequestWarning) # Подавляем предупреждения об отключении SSL-проверки

    main()