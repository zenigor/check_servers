import requests
import yaml
import subprocess
import json
import time
import os
import shutil
import base64
import re
from urllib.parse import urlparse, parse_qs, urlencode
import urllib3 # Добавлено для отключения предупреждений
import datetime # Для измерения времени скачивания

# Отключаем InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- КОНФИГУРАЦИЯ ---
# SERVERS_YAML_URL = "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml" # Заменено на чтение из файла
SUBSCRIPTIONS_FILENAME = "subscriptions.txt"
PRE_CHECK_URL = "https://www.gstatic.com/generate_204" # URL для предварительной проверки
TARGET_URL_TO_CHECK = "https://aistudio.google.com"
DOWNLOAD_TEST_URL = "https://cachefly.cachefly.net/50mb.test" # URL для теста скорости
DOWNLOAD_TEST_FILE_SIZE_MB = 50 # Размер файла для теста скорости в МБ
CORE_EXECUTABLE_PATH = "core/xray.exe"

LOCAL_SOCKS_PORT = 10808
TEMP_CONFIG_FILENAME = "temp_checker_config.json"
# GOOD_SERVERS_FILENAME = "good_servers.yml" # Будет генерироваться динамически
PRE_CHECK_TIMEOUT = 7 # Таймаут для предварительной проверки (в секундах)
REQUEST_TIMEOUT = 15    # Таймаут для основной проверки
DOWNLOAD_TIMEOUT = 60 # Таймаут для теста скорости загрузки (в секундах)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
MAX_SERVERS_TO_TEST = 0
DEBUG_SAVE_CONFIG = True # Флаг для сохранения конфигов, вызвавших ошибку 23
# --- КОНЕЦ КОНФИГУРАЦИИ ---

def check_core_executable():
    if not os.path.exists(CORE_EXECUTABLE_PATH):
        print(f"Ошибка: Исполняемый файл ядра '{CORE_EXECUTABLE_PATH}' не найден.")
        print("Пожалуйста, проверьте и исправьте путь в переменной CORE_EXECUTABLE_PATH.")
        return False
    if not shutil.which(CORE_EXECUTABLE_PATH):
         print(f"Предупреждение: Файл ядра \'{CORE_EXECUTABLE_PATH}\' найден, но shutil.which() не может его верифицировать как исполняемый. Убедитесь, что путь полный и корректный.")
    return True

def parse_trojan_link(link):
    # trojan://password@server:port#name
    try:
        parsed_url = urlparse(link)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = parsed_url.fragment if parsed_url.fragment else f"trojan_{server}:{port}"
        return {
            "type": "trojan",
            "name": name,
            "server": server,
            "port": port,
            "password": password,
            # Стандартные значения, которые могут быть переопределены, если есть в query params
            "udp": True,
            "skip-cert-verify": False,
        }
    except Exception as e:
        print(f"  Ошибка парсинга Trojan ссылки {link}: {e}")
        return None

def parse_ss_link(link):
    # ss://method:password@server:port#name (base64 encoded part before #)
    # ss://base64_encoded_part#name
    # base64_encoded_part = method:password@server:port
    try:
        if "#" in link:
            encoded_part, name = link.split("#", 1)
            name = requests.utils.unquote(name)
        else:
            encoded_part = link
            name = None

        if encoded_part.startswith("ss://"):
            encoded_part = encoded_part[5:]

        # Некоторые ссылки могут быть дважды URL-кодированы перед base64
        try:
            decoded_bytes = base64.urlsafe_b64decode(encoded_part + '=' * (-len(encoded_part) % 4))
            decoded_str = decoded_bytes.decode('utf-8').strip()
        except Exception:
            # Если первая попытка не удалась, пробуем URL-декодировать и затем base64
            try:
                temp_decoded_url = requests.utils.unquote(encoded_part)
                decoded_bytes = base64.urlsafe_b64decode(temp_decoded_url + '=' * (-len(temp_decoded_url) % 4))
                decoded_str = decoded_bytes.decode('utf-8')
            except Exception as e_inner:
                 print(f"  Ошибка декодирования base64 для SS: {encoded_part}, {e_inner}")
                 return None


        # decoded_str = method:password@server:port
        parts = decoded_str.split('@')
        method_password = parts[0].split(':', 1)
        server_port = parts[1].split(':', 1)

        config = {
            "type": "ss",
            "name": name if name else f"ss_{server_port[0]}:{server_port[1]}",
            "server": server_port[0],
            "port": int(server_port[1]),
            "cipher": method_password[0],
            "password": method_password[1],
            "udp": True
        }
        # Обработка плагинов, если они есть в имени (старый формат) или в параметрах
        # Это очень упрощенная обработка, полная поддержка сложнее
        if "obfs" in name.lower() if name else False:
            # Пример: name=shadowsocks_obfs_http_example.com
            # Это очень грубое предположение
            config["plugin"] = "obfs"
            config["plugin-opts"] = {"mode": "http"} # или "tls"
            if "tls" in name.lower() if name else False:
                 config["plugin-opts"]["mode"] = "tls"


        return config
    except Exception as e:
        print(f"  Ошибка парсинга SS ссылки {link}: {e}")
        return None


def parse_vmess_vless_link(link, link_type="vmess"):
    # vmess://<base64_encoded_json>
    # vless://<uuid>@<server>:<port>?<params>#<name>
    try:
        if link_type == "vmess":
            if not link.startswith("vmess://"):
                return None
            base64_data = link[8:]
            try:
                decoded_data = base64.urlsafe_b64decode(base64_data + '=' * (-len(base64_data) % 4)).decode('utf-8')
                config = json.loads(decoded_data)
            except Exception as e_dec:
                print(f"  Ошибка декодирования vmess JSON: {e_dec}, data: {base64_data}")
                return None

            # Преобразование ключей из формата vmess (Clash?) в формат, ожидаемый скриптом
            # Это может потребовать доработки в зависимости от источника ссылок vmess
            # ps (name), add (server), port, id (uuid), aid (alterId), net (network), type (headerType for http), host, path, tls, sni
            server_config = {
                "type": "vmess", # или vless, но тут мы парсим vmess
                "name": config.get("ps", f"vmess_{config.get('add')}:{config.get('port')}"),
                "server": config.get("add"),
                "port": int(config.get("port")),
                "uuid": config.get("id"),
                "alterId": int(config.get("aid", 0)),
                "cipher": config.get("scy", "auto"), # scy/security -> cipher
                "network": config.get("net", "tcp"),
                "headerType": config.get("type", "none"), # for http
                "host": config.get("host", ""),
                "path": config.get("path", "/"),
                "tls": config.get("tls", ""), # "tls" or ""
                "sni": config.get("sni", config.get("host", "")), # sni or host
                "skip-cert-verify": config.get("skip-cert-verify", False), # не стандартный, но полезный
                "udp": True # По умолчанию для vmess
            }
            if server_config["tls"] == "tls":
                server_config["streamSettings"] = {"security": "tls"} # Для create_v2ray_config
                if "tlsSettings" not in server_config["streamSettings"]:
                    server_config["streamSettings"]["tlsSettings"] = {}
                server_config["streamSettings"]["tlsSettings"]["serverName"] = server_config["sni"] if server_config["sni"] else server_config["server"]

            if server_config["network"] == "ws":
                server_config["ws-opts"] = {
                    "path": server_config["path"],
                    "headers": {"Host": server_config["host"]} if server_config["host"] else {}
                }
            return server_config

        elif link_type == "vless":
            parsed_url = urlparse(link)
            if not parsed_url.scheme == "vless" or not parsed_url.username or not parsed_url.hostname or not parsed_url.port:
                 print(f"  Некорректная VLESS ссылка (основные части): {link}")
                 return None

            params = parse_qs(parsed_url.query)

            server_config = {
                "type": "vless",
                "name": requests.utils.unquote(parsed_url.fragment) if parsed_url.fragment else f"vless_{parsed_url.hostname}:{parsed_url.port}",
                "server": parsed_url.hostname,
                "port": int(parsed_url.port),
                "uuid": parsed_url.username,
                "cipher": params.get("encryption", ["none"])[0], # VLESS обычно "none"
                "flow": params.get("flow", [""])[0],
                "network": params.get("type", ["tcp"])[0], # ws, grpc, tcp
                "security": params.get("security", ["none"])[0], # tls, reality, none
                "sni": params.get("sni", [parsed_url.hostname])[0],
                "fingerprint": params.get("fp", [""])[0],
                "publicKey": params.get("pbk", [""])[0],
                "shortId": params.get("sid", [""])[0],
                "spiderX": params.get("spx", [""])[0],
                "skip-cert-verify": params.get("allowInsecure", ["0"])[0] == "1",
                "udp": True # По умолчанию для vless
            }

            if server_config["security"] == "tls":
                server_config["tls"] = "tls" # для create_v2ray_config
                server_config["servername"] = server_config["sni"]
            elif server_config["security"] == "reality":
                server_config["reality"] = "true" # для create_v2ray_config
                server_config["servername"] = server_config["sni"]
                # reality-opts будут собраны в create_v2ray_config из fingerprint, publicKey и т.д.

            if server_config["network"] == "ws":
                server_config["ws-opts"] = {
                    "path": params.get("path", ["/"])[0],
                    "headers": {"Host": params.get("host", [server_config["sni"]])[0]}
                }
            elif server_config["network"] == "grpc":
                server_config["grpc-opts"] = {
                    "grpc-service-name": params.get("serviceName", [""])[0]
                }
            return server_config

    except Exception as e:
        print(f"  Ошибка парсинга {link_type} ссылки {link}: {e}")
        return None

def format_trojan_link(details):
    password = details.get("password", "")
    server = details.get("server", "")
    port = details.get("port", "")
    name = details.get("name", "")
    # trojan://password@server:port#name
    link = f"trojan://{password}@{server}:{port}"
    if name:
        link += f"#{requests.utils.quote(name)}"
    return link

def format_ss_link(details):
    cipher = details.get("cipher", "")
    password = details.get("password", "")
    server = details.get("server", "")
    port = details.get("port", "")
    name = details.get("name", "")
    # ss://base64_encode(cipher:password@server:port)#name
    auth_part = f"{cipher}:{password}@{server}:{port}"
    encoded_auth_part = base64.urlsafe_b64encode(auth_part.encode('utf-8')).decode('utf-8').rstrip("=")
    
    link = f"ss://{encoded_auth_part}"
    if name:
        link += f"#{requests.utils.quote(name)}"
    return link

def format_vmess_link(details):
    # Vmess link is vmess://<base64_encoded_json>
    # JSON structure based on what parse_vmess_vless_link extracts and common fields:
    vmess_obj = {
        "ps": details.get("name"),
        "add": details.get("server"),
        "port": str(details.get("port")), # Port should be string in JSON
        "id": details.get("uuid"),
        "aid": str(details.get("alterId", "0")), # AlterId should be string
        "scy": details.get("cipher", "auto"), # 'cipher' from details maps to 'scy'
        "net": details.get("network", "tcp"),
        "type": details.get("headerType", "none"), # 'headerType' from details maps to 'type' in JSON
        "host": details.get("host", ""),
        "path": details.get("path", ""),
        "tls": details.get("tls", ""), # "tls" or ""
        "sni": details.get("sni", ""),
        "v": "2" # Protocol version
    }

    # Clean up optional fields if they are empty or default to make links cleaner
    keys_to_remove_if_empty_or_default = {
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
        "type": "none" # if 'type' (headerType) is 'none', it can often be omitted
    }

    final_vmess_obj = {}
    for key, value in vmess_obj.items():
        if key in keys_to_remove_if_empty_or_default and value == keys_to_remove_if_empty_or_default[key]:
            continue
        if value is not None and value != "": # Keep field if it has a non-empty value
            final_vmess_obj[key] = value
        elif key not in keys_to_remove_if_empty_or_default : # Keep essential fields even if empty (though parser should provide them)
             final_vmess_obj[key] = value


    # If tls is not present or empty, sni should also be removed
    if not final_vmess_obj.get("tls"):
        final_vmess_obj.pop("sni", None)
    
    # Ensure 'v' is always present
    final_vmess_obj["v"] = "2"


    json_string = json.dumps(final_vmess_obj, separators=(',', ':'), sort_keys=True)
    base64_encoded_json = base64.urlsafe_b64encode(json_string.encode('utf-8')).decode('utf-8').rstrip('=')
    return f"vmess://{base64_encoded_json}"

def format_vless_link(details):
    uuid = details.get("uuid")
    server = details.get("server")
    port = details.get("port")
    name = details.get("name", "")

    params = {}
    # Mapping details from server_details to VLESS query parameters
    if details.get("cipher"): # VLESS uses "encryption"
        params["encryption"] = details["cipher"]
    if details.get("flow"):
        params["flow"] = details["flow"]
    if details.get("network"): # VLESS uses "type" for network
        params["type"] = details["network"]
    if details.get("security"): # 'tls', 'reality', 'none'
        params["security"] = details["security"]
    if details.get("sni"):
        params["sni"] = details["sni"]
    if details.get("fingerprint"): # For reality or tls with custom fingerprint
        params["fp"] = details["fingerprint"]
    
    # Reality-specific parameters
    if details.get("security") == "reality":
        if details.get("publicKey"):
            params["pbk"] = details["publicKey"]
        if details.get("shortId"):
            params["sid"] = details["shortId"]
        if details.get("spiderX"): # Parsed as "spiderX"
            params["spx"] = details["spiderX"]

    if details.get("skip-cert-verify") is True:
        params["allowInsecure"] = "1"
    
    # Network-specific parameters (ws, grpc)
    network_type = details.get("network")
    if network_type == "ws":
        ws_opts = details.get("ws-opts", {})
        if "path" in ws_opts and ws_opts["path"]:
            params["path"] = ws_opts["path"]
        # VLESS uses 'host' query param for Host header in ws
        if "headers" in ws_opts and "Host" in ws_opts["headers"] and ws_opts["headers"]["Host"]:
            params["host"] = ws_opts["headers"]["Host"]
    elif network_type == "grpc":
        grpc_opts = details.get("grpc-opts", {})
        if "grpc-service-name" in grpc_opts and grpc_opts["grpc-service-name"]:
            params["serviceName"] = grpc_opts["grpc-service-name"]

    query_string = urlencode(params)
    encoded_name = requests.utils.quote(name) if name else ""

    link = f"vless://{uuid}@{server}:{port}"
    if query_string:
        link += f"?{query_string}"
    if encoded_name: # Only add '#' if there's a name
        link += f"#{encoded_name}"
    return link

def fetch_server_configs(url, custom_regex_pattern=None):
    print(f"Скачивание и обработка подписки: {url}...")
    original_filename = os.path.basename(urlparse(url).path)
    if not original_filename: # Если URL заканчивается на / или не содержит пути
        original_filename = "unknown_subscription"


    output_filename_base = original_filename
    # Убираем расширения, если они есть, чтобы добавить свое чисто
    if '.' in output_filename_base:
        output_filename_base = output_filename_base.rsplit('.', 1)[0]

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        file_extension = os.path.splitext(urlparse(url).path)[1].lower()

        all_servers = []

        if file_extension == ".yml" or file_extension == ".yaml" or "yaml" in content_type:
            print(f"  Тип подписки: YAML ({url})")
            yaml_content = response.text
            # Существующая логика обработки YAML
            yaml_content = yaml_content.replace("TLS", "tls") # Пример дополнительной нормализации
            yaml_content = yaml_content.replace("\\'", """\\"_""") # Одинарные в двойные (осторожно, может ломать строки) - лучше не использовать или использовать regex
            yaml_content = yaml_content.replace('tls: "true"', 'tls: true').replace('tls: "false"', 'tls: false')
            yaml_content = yaml_content.replace('udp: "true"', 'udp: true').replace('udp: "false"', 'udp: false')
            yaml_content = yaml_content.replace('skip-cert-verify: "true"', 'skip-cert-verify: true')
            yaml_content = yaml_content.replace('skip-cert-verify: "false"', 'skip-cert-verify: false')
            # Добавим еще несколько замен для общих случаев
            # yaml_content = yaml_content.replace("'true'", "true").replace("'false'", "false") # Строковые булевы в настоящие булевы (если возможно)

            try:
                data = yaml.safe_load(yaml_content)
                if data and "proxies" in data:
                    all_servers = data["proxies"]
                elif isinstance(data, list): # Иногда YAML это просто список серверов
                    all_servers = data
                else:
                    print(f"  YAML не содержит ожидаемой структуры ('proxies' или список): {url}")
                    return None, output_filename_base
            except yaml.YAMLError as e:
                print(f"  Ошибка парсинга YAML из {url}: {e}")
                print(f"  Содержимое YAML (начало):\\n{yaml_content[:500]}")
                return None, output_filename_base

        elif file_extension == ".txt" or "text/plain" in content_type or "application/octet-stream" in content_type:
            print(f"  Тип подписки: TXT ({url})")
            lines_from_file_content = response.text.splitlines()
            parsed_servers = [] # Используем parsed_servers, как в вашей текущей версии
            
            for line_from_file in lines_from_file_content:
                line_from_file = line_from_file.strip()
                if not line_from_file or line_from_file.startswith("#"): # Пропускаем пустые строки и комментарии
                    continue

                strings_to_attempt_parsing = []
                decoded_content_block_for_log_check = "" # Для проверки в логгировании неизвестных строк

                try:
                    # Попытка декодировать всю строку из файла как base64
                    padding = '=' * (-len(line_from_file) % 4)
                    decoded_bytes = base64.urlsafe_b64decode(line_from_file + padding)
                    decoded_content_block = decoded_bytes.decode('utf-8').strip()
                    decoded_content_block_for_log_check = decoded_content_block # Сохраняем для проверки ниже
                    
                    # Проверяем, начинается ли декодированный блок с известного протокола
                    if decoded_content_block.startswith(("vless://", "vmess://", "ss://", "trojan://")):
                        print(f"  Обнаружена и декодирована строка Base64. Содержимое будет разделено по строкам для парсинга: {line_from_file[:30]}...")
                        for single_link_in_decoded_block in decoded_content_block.splitlines():
                            single_link_in_decoded_block = single_link_in_decoded_block.strip()
                            if single_link_in_decoded_block:
                                strings_to_attempt_parsing.append(single_link_in_decoded_block)
                    else:
                        # Декодировано, но не похоже на конфигурацию. Обрабатываем исходную строку как литерал.
                        print(f"  Строка была декодирована из Base64, но не начинается с известного протокола. Обработка как обычной строки: {line_from_file[:50]}...")
                        strings_to_attempt_parsing.append(line_from_file)
                
                except Exception:
                    # Ошибка декодирования Base64, обрабатываем исходную строку как литерал.
                    strings_to_attempt_parsing.append(line_from_file)

                for current_line_to_parse in strings_to_attempt_parsing:
                    server_config = None
                    if current_line_to_parse.startswith("ss://"):
                        server_config = parse_ss_link(current_line_to_parse)
                    elif current_line_to_parse.startswith("trojan://"):
                        server_config = parse_trojan_link(current_line_to_parse)
                    elif current_line_to_parse.startswith("vless://"):
                        server_config = parse_vmess_vless_link(current_line_to_parse, link_type="vless")
                    elif current_line_to_parse.startswith("vmess://"):
                        server_config = parse_vmess_vless_link(current_line_to_parse, link_type="vmess")
                    elif current_line_to_parse.startswith("http://") or current_line_to_parse.startswith("https://"):
                        # Эта проверка должна быть здесь, если current_line_to_parse не является результатом Base64
                        # или если сама ссылка на подписку была внутри Base64.
                        # Убедимся, что это не результат Base64-декодирования, который случайно выглядит как HTTP URL.
                        # Обычно, если это была Base64 и она декодировалась, она не должна снова попасть сюда как http,
                        # а должна была быть обработана выше.
                        if line_from_file == current_line_to_parse: # Только если это оригинальная строка
                             print(f"  Найден вложенный URL в TXT: {current_line_to_parse}. Рекурсивная обработка пока не реализована, URL пропущен.")
                        # Рекурсивная обработка закомментирована, как в вашем коде
                        # sub_servers, _ = fetch_server_configs(current_line_to_parse)
                        # if sub_servers:
                        #     parsed_servers.extend(sub_servers)
                    else:
                        # Логгируем только если это была оригинальная строка из файла, которая не была Base64
                        # ИЛИ если это была часть Base64, но все равно не распозналась.
                        # Условие `not decoded_content_block_for_log_check.startswith(...)` проверяет, был ли успешный decode, но не тот протокол
                        is_original_unparsed_line = (line_from_file == current_line_to_parse)
                        is_decoded_but_unknown_sub_line = (decoded_content_block_for_log_check and line_from_file != current_line_to_parse and not current_line_to_parse.startswith(("vless://", "vmess://", "ss://", "trojan://")))
                        
                        if is_original_unparsed_line or is_decoded_but_unknown_sub_line:
                             print(f"  Неизвестный формат строки в TXT: {current_line_to_parse[:50]}...")


                    if server_config:
                        parsed_servers.append(server_config)
            
            # Фильтрация серверов по регулярному выражению для TXT подписок - ЭТОТ БЛОК БУДЕТ УДАЛЕН
            # if parsed_servers: # Только если есть что фильтровать
            #     print(f"  Начинаю фильтрацию {len(parsed_servers)} серверов по регулярному выражению...")
            #     regex_pattern = r"^(?!.*(?:NA-|RU-)).*(?:\b(?:TCP-RLT|GRPC-RLT)\b).*" 
            #     filtered_servers_by_name = []
            #     for server in parsed_servers:
            #         server_name = server.get("name", "")
            #         if re.search(regex_pattern, server_name):
            #             filtered_servers_by_name.append(server)
            #         # else: # Убираем вывод отфильтрованных серверов
            #         #     print(f"  Сервер '{server_name}' не соответствует регулярному выражению, отфильтрован.")
                
            #     if not filtered_servers_by_name:
            #         print(f"  Внимание: После фильтрации по имени не осталось серверов из {url}.")
            #     else:
            #         print(f"  После фильтрации по имени осталось {len(filtered_servers_by_name)} серверов.")
            #     parsed_servers = filtered_servers_by_name # Заменяем список отфильтрованным

            all_servers = parsed_servers # Присваиваем результат в all_servers
        else:
            print(f"  Неподдерживаемый тип контента или расширение файла для {url}: ext='{file_extension}', content-type='{content_type}'. Попытка обработать как YAML.")
            # По умолчанию пытаемся как YAML, так как это был исходный формат
            try:
                yaml_content = response.text
                yaml_content = yaml_content.replace("TLS", "tls")
                # yaml_content = yaml_content.replace("\\'", """\\"_""") # Осторожно с этой заменой
                yaml_content = yaml_content.replace('tls: "true"', 'tls: true').replace('tls: "false"', 'tls: false')
                yaml_content = yaml_content.replace('udp: "true"', 'udp: true').replace('udp: "false"', 'udp: false')
                yaml_content = yaml_content.replace('skip-cert-verify: "true"', 'skip-cert-verify: true')
                yaml_content = yaml_content.replace('skip-cert-verify: "false"', 'skip-cert-verify: false')
                data = yaml.safe_load(yaml_content)
                if data and "proxies" in data:
                    all_servers = data["proxies"]
                elif isinstance(data, list):
                    all_servers = data
                else:
                    print(f"  YAML (по умолчанию) не содержит ожидаемой структуры: {url}")
                    return None, output_filename_base
            except yaml.YAMLError as e:
                print(f"  Ошибка парсинга (по умолчанию как YAML) из {url}: {e}")
                return None, output_filename_base
            except Exception as e_fallback:
                 print(f"  Общая ошибка при попытке обработать {url} как YAML (fallback): {e_fallback}")
                 return None, output_filename_base


        if not all_servers:
            print(f"  Не найдено серверов в подписке: {url}")
            return None, output_filename_base

        # Нормализация имен серверов, чтобы они были уникальны и допустимы для имен файлов (хотя мы имя файла не из имени сервера берем)
        for i, server in enumerate(all_servers):
            if not server.get("name"):
                server["name"] = f"{server.get('type', 'server')}_{i+1}"
            # Дополнительная обработка/валидация полей может быть здесь

        # Новый блок универсальной фильтрации
        if custom_regex_pattern and all_servers:
            print(f"  Применение пользовательского регулярного выражения к {len(all_servers)} серверам: {custom_regex_pattern}")
            original_server_count_for_filter = len(all_servers) # Сохраняем для лога
            temp_filtered_servers = []
            regex_is_valid = True
            try:
                # Проверяем валидность регулярного выражения один раз перед циклом
                re.compile(custom_regex_pattern)
            except re.error as e:
                print(f"  Ошибка в синтаксисе регулярного выражения '{custom_regex_pattern}': {e}. Фильтрация по этому РВ для подписки {url} будет пропущена.")
                regex_is_valid = False

            if regex_is_valid:
                for server in all_servers:
                    server_name = server.get("name", "")
                    if re.search(custom_regex_pattern, server_name):
                        temp_filtered_servers.append(server)
                    # else: # Для отладки можно раскомментировать
                    #     print(f"  Сервер '{server_name}' (из {url}) не соответствует РВ '{custom_regex_pattern}', отфильтрован.")
                
                all_servers = temp_filtered_servers # Обновляем all_servers результатом фильтрации

                if not all_servers: # Если после фильтрации ничего не осталось
                    print(f"  Внимание: После фильтрации по РВ '{custom_regex_pattern}' не осталось серверов из {original_server_count_for_filter} (URL: {url}).")
                elif len(all_servers) < original_server_count_for_filter : # Если что-то было отфильтровано
                    print(f"  После фильтрации по РВ '{custom_regex_pattern}' осталось {len(all_servers)} из {original_server_count_for_filter} серверов (URL: {url}).")
                # Если количество не изменилось, значит все серверы совпали с РВ (или РВ было таким, что ничего не отфильтровало) - не логируем отдельно.

        return all_servers, output_filename_base

    except requests.exceptions.RequestException as e:
        print(f"Ошибка при скачивании {url}: {e}")
        return None, output_filename_base
    except Exception as e_global:
        print(f"Непредвиденная ошибка при обработке {url}: {e_global}")
        return None, output_filename_base

def create_v2ray_config(server_details):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": LOCAL_SOCKS_PORT, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"auth": "noauth", "udp": server_details.get("udp", True), "ip": "127.0.0.1"}
        }],
        "outbounds": []
    }
    outbound_config = {
        "protocol": server_details.get("type", "").lower(),
        "settings": {},
        "streamSettings": {
            "network": server_details.get("network", "tcp"),
            "security": "",
        }
    }
    # Небольшая нормализация для поля tls из YAML, если оно булево
    if server_details.get("tls") == True:
        server_details["tls"] = "tls"
    # elif server_details.get("tls") == False: # Если есть tls: false, убираем его
    #     server_details.pop("tls", None)


    server_name_for_log = server_details.get('name', 'N/A') # Для логов
    protocol = outbound_config["protocol"]

    if protocol == "vmess":
        outbound_config["settings"]["vnext"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "users": [{
                "id": server_details.get("uuid"), 
                "alterId": int(server_details.get("alterId", server_details.get("alterid", 0))), # alterid из clash yaml
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
                "encryption": server_details.get("cipher", "none"), # vless использует 'encryption'
                "flow": server_details.get("flow", ""), 
                "level": 0 
            }]
        }]
        # Обработка REALITY (важно: reality и tls взаимоисключающие в streamSettings)
        # reality: true из YAML или reality-opts из YAML
        reality_opts_yaml = server_details.get("reality-opts", {})
        if server_details.get("reality") == "true" or server_details.get("reality") == True or reality_opts_yaml: # reality: true/True или есть reality-opts
            outbound_config["streamSettings"]["security"] = "reality"
            outbound_config["streamSettings"]["realitySettings"] = {
                "serverName": server_details.get("servername", server_details.get("sni", "")), # servername из clash, sni из vless link
                "fingerprint": server_details.get("fingerprint", reality_opts_yaml.get("fingerprint", "chrome")), # fingerprint из clash или vless link, default chrome
                "publicKey": reality_opts_yaml.get("public-key", server_details.get("publicKey", "")), # public-key из clash, publicKey из vless link
                "shortId": reality_opts_yaml.get("short-id", server_details.get("shortId", "")), # short-id из clash, shortId из vless link
                "spiderX": reality_opts_yaml.get("spider-x", server_details.get("spiderX", "")) # spider-x из clash, spiderX из vless link
            }
            server_details["tls"] = None # Убеждаемся, что tls не будет настроен параллельно
            print(f"  Конфигурируется REALITY для {server_name_for_log}")

    elif protocol == "trojan":
         outbound_config["settings"]["servers"] = [{
            "address": server_details.get("server"), "port": int(server_details.get("port")),
            "password": server_details.get("password"), "level": 0
        }]
    elif protocol == "ss" or protocol == "shadowsocks":
        outbound_config["protocol"] = "shadowsocks" # Xray ожидает "shadowsocks"
        ss_settings = {
            "address": server_details.get("server"), "port": int(server_details.get("port")),
            "method": server_details.get("cipher"), "password": server_details.get("password"),
        }
        # Обработка плагинов для Shadowsocks (например, obfs или v2ray-plugin)
        plugin = server_details.get("plugin")
        plugin_opts = server_details.get("plugin-opts", {})

        if plugin == "obfs": # Старый obfs-local
            # Xray напрямую не поддерживает "obfs" как plugin, это было для ss-libev.
            # Для Xray это обычно реализуется через streamSettings + ws/http (если obfs=http/tls)
            # Это очень упрощенная попытка, может не работать для всех obfs типов
            if plugin_opts.get("mode") == "http" or plugin_opts.get("mode") == "tls":
                outbound_config["streamSettings"]["network"] = "tcp" # obfs обычно TCP, но оборачивается
                # Xray не имеет прямого `obfs` и `obfsparam` в shadowsocks settings.
                # Вместо этого, если obfs это http/tls, то это часть streamSettings. 
                # Этот блок может потребовать пересмотра для корректной работы с Xray и obfs.
                # print(f"  Предупреждение: Прямая конфигурация obfs для Shadowsocks в Xray ограничена. Попытка настроить для {server_name_for_log}")
                # Если obfs-mode=tls, то нужно streamSettings.security=tls и tlsSettings
                if plugin_opts.get("mode") == "tls":
                    server_details["tls"] = "tls" # Устанавливаем для общей обработки TLS ниже
                    if "host" in plugin_opts:
                        server_details["servername"] = plugin_opts["host"] # Используем host из obfs-opts как SNI
            # ss_settings["plugin"] = "obfs" # Xray не поймет это поле тут
            # ss_settings["plugin_opts"] = f"obfs={plugin_opts.get('mode')};obfs-host={plugin_opts.get('host','')}" 

        elif plugin == "v2ray-plugin" and plugin_opts.get("mode") == "websocket":
            # Это более современный способ для SS over WS
            outbound_config["streamSettings"]["network"] = "ws"
            outbound_config["streamSettings"]["wsSettings"] = {
                "path": plugin_opts.get("path", "/"),
                "headers": {"Host": plugin_opts.get("host", server_details.get("server"))}
            }
            if plugin_opts.get("tls") == True: # Если v2ray-plugin использует TLS
                 server_details["tls"] = "tls" # Устанавливаем для общей обработки TLS ниже
                 if "servername" not in server_details and plugin_opts.get("host"):
                     server_details["servername"] = plugin_opts["host"] # SNI из host v2ray-plugin
        outbound_config["settings"]["servers"] = [ss_settings]
    else:
        print(f"  Предупреждение: Протокол '{protocol}' для сервера '{server_name_for_log}' не полностью поддерживается этим скриптом. Попытка базовой конфигурации.")
        # Если протокол неизвестен, возвращаем None, чтобы пропустить сервер
        return None 

    # Общая настройка streamSettings (network, security: tls/xtls, etc.)
    # network уже установлен (tcp по умолчанию, или ws/grpc из деталей сервера, или из ss plugin)
    network_type = outbound_config["streamSettings"]["network"]

    # WS settings (если network="ws", но wsSettings еще не созданы плагином SS)
    if network_type == "ws" and not outbound_config["streamSettings"].get("wsSettings"):
        ws_opts = server_details.get("ws-opts", {})
        path = ws_opts.get("path", server_details.get("path", "/")) # path из vmess/vless, или ws-path из YAML
        headers = ws_opts.get("headers", {})
        if not headers.get("Host") and server_details.get("host"): # host из vmess/vless
            headers["Host"] = server_details.get("host")
        # if not headers.get("Host") and server_details.get("ws-host"): # ws-host из YAML (уже не нужен, если есть host)
        #     headers["Host"] = server_details.get("ws-host")
        outbound_config["streamSettings"]["wsSettings"] = {"path": path}
        if headers: # Только если есть какие-то заголовки
            outbound_config["streamSettings"]["wsSettings"]["headers"] = headers
    elif network_type == "grpc" and not outbound_config["streamSettings"].get("grpcSettings"):
        grpc_opts = server_details.get("grpc-opts", {})
        service_name = grpc_opts.get("serviceName", server_details.get("serviceName", "")) # serviceName из vless, grpc-service-name из YAML
        if service_name: # grpcSettings нужны только если есть serviceName
            outbound_config["streamSettings"]["grpcSettings"] = {"serviceName": service_name}

    # TLS/XTLS settings (если security не 'reality')
    # server_details["tls"] может быть "tls", "xtls" или None/отсутствовать
    yaml_tls_type = server_details.get("tls") # Может быть уже установлено выше (e.g. ss+obfs/v2ray-plugin)

    if outbound_config["streamSettings"]["security"] != "reality" and yaml_tls_type in ["tls", "xtls"]:
        outbound_config["streamSettings"]["security"] = yaml_tls_type
        
        # Определение SNI (servername)
        # Приоритет: servername (из YAML/Clash), sni (из VLESS link), host (из VMess/ws-opts), server (адрес сервера)
        sni_val = server_details.get("servername", server_details.get("sni"))
        if not sni_val:
            # Если WS, и есть Host заголовок, используем его для SNI
            if network_type == "ws":
                ws_host_header = outbound_config["streamSettings"].get("wsSettings", {}).get("headers", {}).get("Host")
                if ws_host_header: sni_val = ws_host_header
            # Если VMess и есть 'host', используем его
            elif protocol == "vmess" and server_details.get("host"):
                sni_val = server_details.get("host")
        # Фоллбэк на адрес сервера, если SNI так и не определен
        if not sni_val: sni_val = server_details.get("server")

        common_tls_xtls_settings = {
            "serverName": sni_val,
            "allowInsecure": server_details.get("skip-cert-verify", False) or server_details.get("allowInsecure", False),
        }
        # Добавляем fingerprint, если он есть (для TLS/XTLS)
        if "fingerprint" in server_details and server_details["fingerprint"]:
            common_tls_xtls_settings["fingerprint"] = server_details["fingerprint"]

        if yaml_tls_type == "tls":
            outbound_config["streamSettings"]["tlsSettings"] = common_tls_xtls_settings
        elif yaml_tls_type == "xtls": # Для XTLS flow также нужен
            outbound_config["streamSettings"]["xtlsSettings"] = common_tls_xtls_settings
            # XTLS обычно используется с VLESS, flow для VLESS настраивается в vnext users.

    # Если security не установлено (не tls, не xtls, не reality), то оно остается "" (none)
    # Если network tcp и security "", то streamSettings можно было бы и убрать, но xray их примет.
    # Однако, если network не tcp (ws, grpc), то streamSettings нужны даже без security.
    if not outbound_config["streamSettings"]["security"] and network_type == "tcp":
        # Можно очистить streamSettings, если это просто TCP без TLS/REALITY
        # outbound_config.pop("streamSettings", None) - Но это не обязательно
        pass 

    config["outbounds"].append(outbound_config)
    # Добавляем прямой выход для предотвращения ошибок, если прокси не работает
    config["outbounds"].append({"protocol": "freedom", "tag": "direct", "settings": {}})

    try:
        with open(TEMP_CONFIG_FILENAME, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return TEMP_CONFIG_FILENAME
    except Exception as e:
        print(f"  Ошибка записи временного файла конфигурации {TEMP_CONFIG_FILENAME}: {e}")
        return None

def test_download_speed(server_name, proxy_address, proxy_port, download_url, file_size_mb, timeout):
    """Тестирует скорость загрузки через указанный прокси."""
    print(f"  Тестирование скорости загрузки для {server_name}...")
    start_time = time.time()
    process = None
    try:
        output_to = "NUL" if os.name == 'nt' else "/dev/null"
        cmd = [
            "curl",
            "-x", f"socks5h://{proxy_address}:{proxy_port}",
            "-o", output_to,
            "-s", # Тихий режим
            "-L", # Следовать редиректам
            "--connect-timeout", str(PRE_CHECK_TIMEOUT), # Таймаут на соединение
            "--max-time", str(timeout), # Общий таймаут на операцию
            "--fail", # Завершиться с ошибкой при HTTP ошибках
            download_url
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=timeout + 5) 

        if process.returncode == 0:
            end_time = time.time()
            duration = end_time - start_time
            if duration > 0.1: # Избегаем деления на ноль или слишком малое время
                speed_MBps = (file_size_mb / duration)
                print(f"  Скорость загрузки для {server_name}: {speed_MBps:.2f} MB/s (файл {file_size_mb}MB за {duration:.2f} сек)")
                return speed_MBps
            else:
                print(f"  Тест скорости для {server_name} завершился слишком быстро ({duration:.3f} сек), невозможно точно рассчитать скорость.")
                return 0.0 # Считаем неудачей, если слишком быстро
        else:
            if "Could not resolve host" in stderr.decode(errors='ignore'):
                print(f"  Ошибка теста скорости для {server_name}: Не удалось разрешить хост через прокси (DNS).")
            else:
                print(f"  Ошибка теста скорости для {server_name} (код: {process.returncode}). stderr: {stderr.decode(errors='ignore')[:200]}...")
            return 0.0

    except subprocess.TimeoutExpired:
        print(f"  Тест скорости для {server_name} превысил таймаут ({timeout} сек).")
        if process:
            try:
                process.kill()
                process.wait()
            except Exception as e_kill:
                print(f"  Ошибка при попытке убить процесс curl для {server_name}: {e_kill}")
        return 0.0
    except FileNotFoundError:
        print(f"  Команда 'curl' не найдена. Пожалуйста, установите curl и убедитесь, что он в PATH.")
        global curl_not_found_reported
        if not curl_not_found_reported:
            curl_not_found_reported = True
            print("  Тесты скорости будут пропущены из-за отсутствия curl.")
        return -1 # Специальное значение, чтобы обозначить проблему с curl (сервер будет отброшен)
    except Exception as e:
        print(f"  Неожиданная ошибка во время теста скорости для {server_name}: {e}")
        return 0.0

# Глобальный флаг, чтобы сообщить об отсутствии curl только один раз
curl_not_found_reported = False

def test_server_connection(server_name):
    """Тестирует соединение с сервером через Xray. Возвращает (latency_ms, download_speed_mbps) или (None, 0.0)."""
    global curl_not_found_reported
    config_filename = TEMP_CONFIG_FILENAME # Используем глобальное имя файла конфига
    process = None
    try:
        # CORE_EXECUTABLE_PATH должен указывать на xray.exe или аналогичный
        # Команда для Xray: xray -c config.json (или xray run -c config.json)
        # Используем просто `xray -c config.json` как более общий вариант для Xray.
        cmd = [CORE_EXECUTABLE_PATH, "-c", config_filename]
        
        # Подавляем консольное окно для xray.exe на Windows
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        time.sleep(2) # Даем время ядру Xray запуститься и стабилизироваться

        proxies = {
            "http": f"socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}",
            "https": f"socks5h://127.0.0.1:{LOCAL_SOCKS_PORT}"
        }
        headers = {"User-Agent": USER_AGENT}

        # 1. Предварительная проверка (generate_204)
        try:
            response_pre = requests.get(PRE_CHECK_URL, proxies=proxies, timeout=PRE_CHECK_TIMEOUT, headers=headers, verify=False)
            if response_pre.status_code == 204:
                pass # Успех, продолжаем
            else:
                print(f"  Предварительная проверка для {server_name} не удалась (status {response_pre.status_code}). Пропуск.")
                return None, 0.0
        except requests.exceptions.RequestException as e_pre:
            print(f"  Ошибка предв. проверки для {server_name} ({type(e_pre).__name__}). Пропуск.")
            return None, 0.0

        # 2. Основная проверка (TARGET_URL_TO_CHECK)
        test_url = TARGET_URL_TO_CHECK
        start_time = time.time()
        response = requests.get(test_url, proxies=proxies, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        end_time = time.time()
        latency = round((end_time - start_time) * 1000)

        if response.status_code == 200:
            print(f"  Сервер {server_name} РАБОТАЕТ (основная проверка). Задержка: {latency}ms.")
            
            # 3. Проверка скорости загрузки
            download_speed_mbps = 0.0
            if curl_not_found_reported and not os.path.exists("curl.exe"): # Если curl глобально не найден и нет локального
                print(f"  Пропуск теста скорости для {server_name} (curl не найден). Сервер будет считаться нерабочим.")
                # download_speed_mbps остается 0.0, что приведет к отбраковке ниже
            else:
                download_speed_mbps = test_download_speed(
                    server_name,
                    "127.0.0.1", LOCAL_SOCKS_PORT,
                    DOWNLOAD_TEST_URL,
                    DOWNLOAD_TEST_FILE_SIZE_MB,
                    DOWNLOAD_TIMEOUT
                )
                if download_speed_mbps == -1: # curl не найден во время вызова test_download_speed
                    curl_not_found_reported = True # Устанавливаем глобальный флаг
                    print(f"  Тест скорости для {server_name} не выполнен (curl не найден). Сервер будет считаться нерабочим.")
                    download_speed_mbps = 0.0 # Устанавливаем в 0 для отбраковки

            # Если скорость 0.0 (неудача теста или curl не найден), сервер считается нерабочим
            if download_speed_mbps > 0:
                print(f"  Сервер {server_name} успешно прошел все проверки. Скорость: {download_speed_mbps:.2f} MB/s.")
                return latency, download_speed_mbps
            else:
                print(f"  Сервер {server_name} не прошел тест скорости (скорость {download_speed_mbps:.2f} MB/s). Считается нерабочим.")
                return None, 0.0
        else:
            print(f"  Сервер {server_name} НЕ РАБОТАЕТ (основная проверка). Статус: {response.status_code}. Задержка: {latency}ms.")
            return None, 0.0
    
    except Exception as e:
        print(f"  Критическая ошибка во время тестирования {server_name}: {e}")
        # В случае любой другой ошибки во время теста соединения, считаем сервер нерабочим
        return None, 0.0
    finally:
        if process:
            try:
                process.terminate() # Сначала пытаемся мягко завершить
                process.wait(timeout=5) # Даем время на завершение
                # print(f"  Процесс Xray для {server_name} остановлен (terminate, код: {process.returncode}).")
            except subprocess.TimeoutExpired:
                print(f"  Процесс Xray для {server_name} не завершился (terminate), принудительная остановка (kill)...")
                process.kill()
                try:
                    process.wait(timeout=5)
                    # print(f"  Процесс Xray для {server_name} остановлен (kill, код: {process.returncode}).")
                except Exception as e_kill_wait:
                    print(f"  Ошибка при ожидании завершения процесса Xray (kill) для {server_name}: {e_kill_wait}")
            except Exception as e_term_wait: # Если ошибка при wait после terminate
                print(f"  Ошибка при ожидании завершения процесса Xray (terminate) для {server_name}: {e_term_wait}")
            # Удаление временного файла конфигурации теперь происходит в main цикле

def main():
    """Основная функция скрипта."""
    start_total_time = time.time()
    print(f"Запуск скрипта проверки серверов в {time.strftime('%Y-%m-%d %H:%M:%S')}")

    if not check_core_executable():
        return

    # Загрузка списка подписок
    if not os.path.exists(SUBSCRIPTIONS_FILENAME):
        print(f"Файл подписок '{SUBSCRIPTIONS_FILENAME}' не найден.")
        all_servers_from_all_subs = [] # Инициализируем пустым списком, если файла нет
    else:
        with open(SUBSCRIPTIONS_FILENAME, 'r', encoding='utf-8') as f:
            subscription_lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        all_servers_from_all_subs = []
        for idx, sub_line in enumerate(subscription_lines):
            parts = sub_line.split('|', 1)
            sub_url_or_path = parts[0].strip()
            custom_regex_for_sub = parts[1].strip() if len(parts) > 1 else None
            
            print(f"\nЗагрузка и парсинг источника {idx+1}/{len(subscription_lines)}: {sub_url_or_path}")
            if custom_regex_for_sub:
                print(f"  Применяется РВ для фильтрации имен: {custom_regex_for_sub}")

            # Определение имени файла для сохранения оригинальной подписки и для хороших серверов
            safe_filename_base = "unknown_source"
            if os.path.exists(sub_url_or_path): # Это локальный файл
                print(f"  Обработка локального файла: {sub_url_or_path}")
                safe_filename_base = os.path.splitext(os.path.basename(sub_url_or_path))[0]
                # Чтение содержимого локального файла
                try:
                    with open(sub_url_or_path, 'r', encoding='utf-8') as local_f:
                        content = local_f.read()
                    # Попытка декодировать из Base64, если это одна строка без переносов
                    if not any(c in content for c in '\n\r') and len(content) > 50:
                        try:
                            padding = '=' * (-len(content) % 4)
                            decoded_b64_content = base64.b64decode(content + padding).decode('utf-8')
                            if any(proto_sig in decoded_b64_content for proto_sig in ['vmess://', 'vless://', 'ss://', 'trojan://']):
                                print(f"  Локальный файл {sub_url_or_path} распознан как Base64-кодированный список.")
                                content = decoded_b64_content
                        except Exception:
                            pass # Не Base64 или ошибка декодирования, используем как есть
                    servers_from_sub = parse_subscription_content(content, sub_url_or_path, f"{safe_filename_base}_original_servers.txt", custom_regex_for_sub)
                except IOError as e_io:
                    print(f"  Ошибка чтения локального файла {sub_url_or_path}: {e_io}")
                    servers_from_sub = []
            else: # Это URL
                parsed_sub_url = urlparse(sub_url_or_path)
                url_path_parts = parsed_sub_url.path.split('/')
                raw_filename_part = "url_subscription"
                if url_path_parts:
                    potential_name = url_path_parts[-1]
                    if potential_name: raw_filename_part = os.path.splitext(potential_name)[0]
                    elif len(url_path_parts) > 1 and url_path_parts[-2]: raw_filename_part = os.path.splitext(url_path_parts[-2])[0]
                safe_filename_base = re.sub(r'[^a-zA-Z0-9_\-]', '_', raw_filename_part)[:50]
                servers_from_sub, _ = fetch_server_configs(sub_url_or_path, custom_regex_pattern=custom_regex_for_sub) # fetch_server_configs теперь возвращает servers, base_name
                # fetch_server_configs должна также сохранять _original_servers.txt, если необходимо

            if servers_from_sub:
                # Добавляем информацию об источнике (filename_base) к каждому серверу
                for server in servers_from_sub:
                    server['source_info'] = {'filename_base': safe_filename_base, 'original_url': sub_url_or_path}
                all_servers_from_all_subs.extend(servers_from_sub)
                print(f"  Добавлено {len(servers_from_sub)} серверов из {sub_url_or_path}.")
            else:
                print(f"  Не найдено или не удалось обработать серверы в {sub_url_or_path}.")
    
    # Удаление дубликатов серверов
    print(f"\nВсего загружено {len(all_servers_from_all_subs)} серверов (с возможными дубликатами). Уникализация...")
    unique_servers_map = {}
    for server in all_servers_from_all_subs:
        key_parts = [server['type'], server['server'], str(server['port'])]
        if server['type'] == 'trojan': key_parts.append(server.get('password',''))
        elif server['type'] == 'ss': key_parts.extend([server.get('password',''), server.get('cipher','')])
        elif server['type'] in ['vmess', 'vless']: key_parts.append(server.get('uuid',''))
        if server.get('network') == 'ws':
            key_parts.append(server.get('ws-opts',{}).get('path','/') or server.get('path','/'))
            key_parts.append(server.get('ws-opts',{}).get('headers',{}).get('Host','') or server.get('host',''))
        if server.get('tls') == 'tls' or server.get('security') in ['tls', 'reality']:
            key_parts.append(server.get('sni', server.get('servername', server.get('host',''))))
        unique_key = tuple(key_parts)
        if unique_key not in unique_servers_map:
            unique_servers_map[unique_key] = server
    
    unique_servers_to_test = list(unique_servers_map.values())
    print(f"Уникальных серверов для тестирования: {len(unique_servers_to_test)}")

    if MAX_SERVERS_TO_TEST > 0 and len(unique_servers_to_test) > MAX_SERVERS_TO_TEST:
        print(f"\nОграничение MAX_SERVERS_TO_TEST: {MAX_SERVERS_TO_TEST}. Случайным образом выбираем серверы...")
        selected_servers = random.sample(unique_servers_to_test, MAX_SERVERS_TO_TEST) # Нужен import random
        print(f"Выбрано {len(selected_servers)} серверов для тестирования.")
    else:
        selected_servers = unique_servers_to_test
    
    good_servers_by_source_identifier = {} 

    print(f"\nНачинается тестирование {len(selected_servers)} серверов... ({PRE_CHECK_TIMEOUT}s предпроверка, {REQUEST_TIMEOUT}s основная, {DOWNLOAD_TIMEOUT}s тест скорости)")
    tested_server_count = 0
    for server_details in selected_servers:
        tested_server_count += 1
        server_name_original = server_details.get('name', 'N/A')
        print(f"\n({tested_server_count}/{len(selected_servers)}) Тестирование: {server_name_original}")
        
        config_temp_file = create_v2ray_config(server_details)
        if not config_temp_file:
            print(f"  Не удалось создать конфиг для {server_name_original}. Пропуск.")
            continue
        
        latency_ms, download_mbps = test_server_connection(server_name_original)
        
        # Удаляем временный конфиг после теста одного сервера
        if os.path.exists(TEMP_CONFIG_FILENAME):
            try: os.remove(TEMP_CONFIG_FILENAME)
            except OSError as e_rem_temp: print(f"  Предупреждение: Не удалось удалить {TEMP_CONFIG_FILENAME}: {e_rem_temp}")

        if latency_ms is not None and download_mbps > 0: # Сервер рабочий И тест скорости успешен (больше 0)
            new_name = f"{download_mbps:.2f}MB/s | {server_name_original}"
            
            server_details_copy = server_details.copy()
            server_details_copy['name'] = new_name
            server_details_copy['latency_ms'] = latency_ms 
            server_details_copy['download_mbps'] = download_mbps

            source_id = server_details.get('source_info', {}).get('filename_base', 'unknown_source')
            if source_id not in good_servers_by_source_identifier:
                good_servers_by_source_identifier[source_id] = []
            good_servers_by_source_identifier[source_id].append(server_details_copy)
        # else: сервер не прошел проверку (сообщение об этом выводится в test_server_connection)
    
    # Сохранение хороших серверов
    print("\n--- Итоги тестирования ---")
    total_good_servers_saved = 0
    if not good_servers_by_source_identifier:
        print("Не найдено рабочих серверов, прошедших все проверки.")
    else:
        active_good_files_generated_this_run = set()
        for source_id, servers_list in good_servers_by_source_identifier.items():
            if not servers_list: continue # Пропускаем, если для источника нет хороших серверов

            servers_list.sort(key=lambda s: (-s.get('download_mbps', 0), s.get('latency_ms', float('inf'))))
            
            # Определяем, в каком формате сохранять (по типу исходного файла или по умолчанию txt)
            # Это потребует информации о типе исходного файла, которую нужно пробросить
            # Пока что по умолчанию будем сохранять в .txt (список ссылок)
            output_filename = f"{source_id}_good_servers.txt"
            active_good_files_generated_this_run.add(output_filename)

            formatted_links = []
            for server in servers_list:
                link = "" # Важно инициализировать
                server_type = server.get("type", "").lower()
                if server_type == 'trojan': link = format_trojan_link(server)
                elif server_type == 'ss' or server_type == 'shadowsocks': link = format_ss_link(server)
                elif server_type == 'vmess': link = format_vmess_link(server)
                elif server_type == 'vless': link = format_vless_link(server)
                if link:
                    formatted_links.append(link)
                else:
                    print(f"  Предупреждение: Не удалось отформатировать ссылку для сохранения сервера {server.get('name', 'N/A')} типа {server_type}")
            
            if formatted_links:
                total_good_servers_saved += len(formatted_links)
                print(f"Найдено {len(formatted_links)} рабочих серверов для источника '{source_id}'. Сохранение в {output_filename}")
                try:
                    # Если файл .txt, то сохраняем список ссылок, каждая на новой строке
                    # Если файл .yml, то нужно сохранять как YAML {'proxies': servers_list}
                    # TODO: Определить формат сохранения на основе исходного типа файла или по флагу
                    with open(output_filename, 'w', encoding='utf-8') as f:
                        f.write("\n".join(formatted_links))
                    
                    # Пример сохранения в base64 (если нужно для v2rayN)
                    # base64_content = base64.b64encode("\n".join(formatted_links).encode('utf-8')).decode('utf-8')
                    # with open(f"{source_id}_good_servers_b64.txt", 'w', encoding='utf-8') as f_b64:
                    #     f_b64.write(base64_content)
                    # print(f"  Также сохранено в Base64: {source_id}_good_servers_b64.txt")
                    # active_good_files_generated_this_run.add(f"{source_id}_good_servers_b64.txt")

                except IOError as e_io_save:
                    print(f"Ошибка записи в файл {output_filename}: {e_io_save}")
            else:
                print(f"Нет рабочих серверов для источника '{source_id}' для сохранения.")

        # Удаление старых файлов _good_servers.txt/_good_servers.yml, которые не были обновлены
        # (т.е. для которых в этом запуске не было найдено хороших серверов)
        all_potentially_good_files_in_dir = [f for f in os.listdir('.') if re.match(r'.+_good_servers\.(txt|yml|yaml)$', f)]
        # Добавить сюда и _b64.txt, если они генерируются
        # all_potentially_good_files_in_dir.extend([f for f in os.listdir('.') if re.match(r'.+_good_servers_b64\.txt$', f)])

        for old_file in all_potentially_good_files_in_dir:
            if old_file not in active_good_files_generated_this_run:
                try:
                    os.remove(old_file)
                    print(f"Удален старый/неактуальный файл хороших серверов: {old_file}")
                except OSError as e_rem_old:
                    print(f"Ошибка при удалении старого файла {old_file}: {e_rem_old}")


    print(f"\nВсего найдено и сохранено рабочих серверов (прошедших все проверки): {total_good_servers_saved}")
    end_total_time = time.time()
    # Используем timedelta для красивого вывода времени
    print(f"Скрипт завершил работу за {datetime.timedelta(seconds=end_total_time - start_total_time)}")


if __name__ == '__main__':
    start_time = time.time()
    main()
    end_time = time.time()
    # print(f"Скрипт завершил работу за {end_time - start_time:.2f} секунд.") # Заменено на timedelta в main
