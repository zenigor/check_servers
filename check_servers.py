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

# Отключаем InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- КОНФИГУРАЦИЯ ---
# SERVERS_YAML_URL = "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml" # Заменено на чтение из файла
SUBSCRIPTIONS_FILENAME = "subscriptions.txt"
PRE_CHECK_URL = "https://www.gstatic.com/generate_204" # URL для предварительной проверки
TARGET_URL_TO_CHECK = "https://aistudio.google.com"
CORE_EXECUTABLE_PATH = "core/xray.exe"

LOCAL_SOCKS_PORT = 10808
TEMP_CONFIG_FILENAME = "temp_checker_config.json"
# GOOD_SERVERS_FILENAME = "good_servers.yml" # Будет генерироваться динамически
PRE_CHECK_TIMEOUT = 7 # Таймаут для предварительной проверки (в секундах)
REQUEST_TIMEOUT = 15    # Таймаут для основной проверки
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
MAX_SERVERS_TO_TEST = 0
DEBUG_SAVE_CONFIG = True # Флаг для сохранения конфигов, вызвавших ошибку 23

# --- Настройки для проксирования через sing-box ---
# Установите USE_SING_BOX_PROXY_IF_CONFIGURED = True, чтобы включить эту функцию.
# Убедитесь, что sing-box настроен на предоставление SOCKS5 прокси на SING_BOX_LOCAL_SOCKS_PORT.
USE_SING_BOX_PROXY_IF_CONFIGURED = True # По умолчанию выключено
SING_BOX_EXECUTABLE_PATH = "core/sing-box/sing-box.exe" # Пример: "core/sing-box.exe" или "/usr/local/bin/sing-box"
SING_BOX_RUSSIAN_VPN_CONFIG_PATH = "core/sing-box-russian-config.json" # Пример: "core/config_ru_vpn.json"
SING_BOX_LOCAL_SOCKS_PORT = 10809 # Порт, на котором sing-box будет предоставлять SOCKS5 прокси
# --- Конец настроек для sing-box ---
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
            decoded_str = decoded_bytes.decode('utf-8')
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

def create_v2ray_config(server_details, use_sing_box_proxy=False):
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
        "streamSettings": {
            "network": server_details.get("network", "tcp"),
            "security": "",
        }
    }
    if server_details.get("tls") == True:
        server_details["tls"] = "tls"
    server_name_for_log = server_details.get('name', 'N/A')
    protocol = outbound_config["protocol"]

    if protocol == "vmess":
        outbound_config["settings"]["vnext"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "users": [{"id": server_details.get("uuid"), "alterId": int(server_details.get("alterId", server_details.get("alterid", 0))), "security": server_details.get("cipher", "auto"), "level": 0}]
        }]
    elif protocol == "vless":
        outbound_config["settings"]["vnext"] = [{
            "address": server_details.get("server"),
            "port": int(server_details.get("port")),
            "users": [{"id": server_details.get("uuid"), "encryption": server_details.get("cipher", "none"), "flow": server_details.get("flow", ""), "level": 0}]
        }]
        reality_opts_yaml = server_details.get("reality-opts", {})
        if server_details.get("reality") == "true" or server_details.get("reality") == True or reality_opts_yaml:
            outbound_config["streamSettings"]["security"] = "reality"
            outbound_config["streamSettings"]["realitySettings"] = {
                "serverName": server_details.get("servername", server_details.get("sni", "")),
                "fingerprint": server_details.get("fingerprint", reality_opts_yaml.get("fingerprint", "chrome")),
                "publicKey": reality_opts_yaml.get("public-key", server_details.get("publicKey", "")),
                "shortId": reality_opts_yaml.get("short-id", server_details.get("shortId", "")),
                "spiderX": reality_opts_yaml.get("spider-x", server_details.get("spiderX", "")),
            }
            server_details["tls"] = None
            print(f"  Конфигурируется REALITY для {server_name_for_log}")
    elif protocol == "trojan":
         outbound_config["settings"]["servers"] = [{
            "address": server_details.get("server"), "port": int(server_details.get("port")),
            "password": server_details.get("password"), "level": 0
        }]
    elif protocol == "ss" or protocol == "shadowsocks":
        outbound_config["protocol"] = "shadowsocks"
        ss_settings = {
            "address": server_details.get("server"), "port": int(server_details.get("port")),
            "method": server_details.get("cipher"), "password": server_details.get("password"),
        }
        plugin = server_details.get("plugin")
        plugin_opts = server_details.get("plugin-opts", {})
        if plugin == "obfs":
            ss_settings["obfs"] = plugin_opts.get("mode")
            ss_settings["obfsparam"] = plugin_opts.get("host")
        elif plugin == "v2ray-plugin" and plugin_opts.get("mode") == "websocket":
            outbound_config["streamSettings"]["network"] = "ws"
            outbound_config["streamSettings"]["wsSettings"] = {
                "path": plugin_opts.get("path", "/"),
                "headers": {"Host": plugin_opts.get("host", server_details.get("server"))}
            }
            if plugin_opts.get("tls") == True:
                 server_details["tls"] = "tls"
                 if "servername" not in server_details and plugin_opts.get("host"):
                     server_details["servername"] = plugin_opts.get("host")
        outbound_config["settings"]["servers"] = [ss_settings]
    else:
        print(f"  Предупреждение: Протокол '{protocol}' для сервера '{server_name_for_log}' не полностью поддерживается этим скриптом. Попытка базовой конфигурации.")
        return None

    network_type = outbound_config["streamSettings"]["network"]
    if network_type == "ws" and not outbound_config["streamSettings"].get("wsSettings"):
        ws_opts = server_details.get("ws-opts", {})
        path = ws_opts.get("path", server_details.get("ws-path", "/"))
        headers = ws_opts.get("headers", {})
        if not headers.get("Host") and server_details.get("ws-host"):
            headers["Host"] = server_details.get("ws-host")
        if not headers.get("Host") and server_details.get("host"):
            headers["Host"] = server_details.get("host")
        outbound_config["streamSettings"]["wsSettings"] = {"path": path}
        if headers:
            outbound_config["streamSettings"]["wsSettings"]["headers"] = headers
    elif network_type == "grpc" and not outbound_config["streamSettings"].get("grpcSettings"):
        grpc_opts = server_details.get("grpc-opts", {})
        service_name = grpc_opts.get("grpc-service-name", server_details.get("serviceName", ""))
        if service_name:
            outbound_config["streamSettings"]["grpcSettings"] = {"serviceName": service_name}

    yaml_tls_type = server_details.get("tls")
    if outbound_config["streamSettings"]["security"] != "reality" and yaml_tls_type in ["tls", "xtls"]:
        outbound_config["streamSettings"]["security"] = yaml_tls_type
        sni_val = server_details.get("servername", server_details.get("sni"))
        if not sni_val:
            if network_type == "ws":
                ws_host_header = outbound_config["streamSettings"].get("wsSettings", {}).get("headers", {}).get("Host")
                if ws_host_header: sni_val = ws_host_header
        if not sni_val: sni_val = server_details.get("server")
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

    config["outbounds"].append(outbound_config)
    
    # Добавление sing-box как прокси, если включено
    if use_sing_box_proxy:
        if not any(out.get("tag") == "russian_proxy_via_singbox" for out in config["outbounds"]):
            print(f"  Добавление исходящего SOCKS5 прокси через sing-box (127.0.0.1:{SING_BOX_LOCAL_SOCKS_PORT}) для сервера {server_details.get('name', 'N/A')}.")
            config["outbounds"].insert(0, { # Вставляем в начало, чтобы теги были доступны
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": SING_BOX_LOCAL_SOCKS_PORT
                    }]
                },
                "tag": "russian_proxy_via_singbox"
            })
        
        # Назначаем sing-box прокси основному исходящему соединению
        # Основной outbound должен быть первым в списке после добавления sing-box прокси (если он есть)
        # или если sing-box не используется, он и так будет первым подходящим (не 'direct')
        main_outbound_index = -1
        for i, out_cfg in enumerate(config["outbounds"]):
            if out_cfg.get("protocol") not in ["freedom", "socks", "blackhole"] and out_cfg.get("tag") != "russian_proxy_via_singbox":
                main_outbound_index = i
                break
        
        if main_outbound_index != -1:
            if "proxySettings" not in config["outbounds"][main_outbound_index] or \
               config["outbounds"][main_outbound_index].get("proxySettings", {}).get("tag") != "russian_proxy_via_singbox":
                config["outbounds"][main_outbound_index]["proxySettings"] = {"tag": "russian_proxy_via_singbox"}
                print(f"  Основной исходящий узел ({config['outbounds'][main_outbound_index].get('protocol')}) для {server_details.get('name', 'N/A')} будет использовать прокси 'russian_proxy_via_singbox'.")
        else:
            print(f"  Предупреждение: Не удалось найти основной исходящий узел для назначения прокси sing-box для сервера {server_details.get('name', 'N/A')}.")

    config["outbounds"].append({"protocol": "freedom", "tag": "direct", "settings": {}})
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

    # --- Начало: Предварительная проверка ---
    # print(f"  Предварительная проверка: {server_name} -> {PRE_CHECK_URL}")
    try:
        # Используем stream=True, чтобы не загружать тело ответа, если оно вдруг будет
        # Для generate_204 тело не ожидается, но это хорошая практика
        response_pre = requests.get(PRE_CHECK_URL, proxies=proxies, timeout=PRE_CHECK_TIMEOUT, headers=headers, verify=False, stream=True)
        
        if response_pre.status_code == 204:
            print(f"  Предварительная проверка УСПЕХ: Сервер '{server_name}' достиг {PRE_CHECK_URL}.")
        else:
            # print(f"  Предварительная проверка ОШИБКА: Сервер '{server_name}' к {PRE_CHECK_URL} вернул статус {response_pre.status_code} (ожидался 204).")
            return False # Если предварительная проверка не прошла, дальше не идем
        # Закрываем соединение, так как использовали stream=True
        response_pre.close()

    except requests.exceptions.Timeout:
        # print(f"  Предварительная проверка ОШИБКА (Таймаут): Сервер '{server_name}' не ответил на {PRE_CHECK_URL} за {PRE_CHECK_TIMEOUT} сек.")
        return False
    except requests.exceptions.ProxyError as e:
        # print(f"  Предварительная проверка ОШИБКА (Прокси): Сервер '{server_name}' к {PRE_CHECK_URL}. {e}")
        return False
    except requests.exceptions.RequestException as e:
        # print(f"  Предварительная проверка ОШИБКА (Соединение): Сервер '{server_name}' к {PRE_CHECK_URL}. {e}")
        return False
    # --- Конец: Предварительная проверка ---

    # --- Начало: Основная проверка (если предварительная пройдена) ---
    print(f"  Основная проверка: {server_name} -> {TARGET_URL_TO_CHECK} через SOCKS5://127.0.0.1:{LOCAL_SOCKS_PORT}")
    try:
        response = requests.get(TARGET_URL_TO_CHECK, proxies=proxies, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        
        print(f"  Основная проверка: Сервер '{server_name}': Статус {response.status_code}, URL: {response.url}")
        if response.status_code == 200:
            if "aistudio.google.com" in response.url.lower() or \
               ("google ai studio" in response.text.lower() or "gemini" in response.text.lower()):
                 print(f"  Основная проверка УСПЕХ: Сервер '{server_name}' работает и вернул страницу Google AI Studio.")
                 return True
            else:
                 print(f"  Основная проверка ПРЕДУПРЕЖДЕНИЕ: Сервер '{server_name}' вернул 200, но контент не похож на AI Studio. Возможно, редирект или капча.")
                 return False
        elif response.status_code == 403:
            print(f"  Основная проверка ОШИБКА (403): Сервер '{server_name}' заблокирован для {TARGET_URL_TO_CHECK}.")
            return False
        else:
            print(f"  Основная проверка ОШИБКА (код {response.status_code}): Сервер '{server_name}' вернул неожиданный статус.")
            return False
    except requests.exceptions.Timeout:
        print(f"  Основная проверка ОШИБКА (Таймаут): Сервер '{server_name}' не ответил за {REQUEST_TIMEOUT} сек.")
        return False
    except requests.exceptions.ProxyError as e:
        print(f"  Основная проверка ОШИБКА (Прокси): Сервер '{server_name}': Не удалось подключиться через прокси. {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  Основная проверка ОШИБКА (Соединение): Сервер '{server_name}': {e}")
        return False
    # --- Конец: Основная проверка ---

def main():
    if not check_core_executable():
        return

    sing_box_process = None # Для хранения процесса sing-box

    if USE_SING_BOX_PROXY_IF_CONFIGURED:
        print("--- Попытка запуска sing-box для проксирования трафика ---")
        if not SING_BOX_EXECUTABLE_PATH or not os.path.exists(SING_BOX_EXECUTABLE_PATH):
            print(f"  Ошибка: Исполняемый файл sing-box '{SING_BOX_EXECUTABLE_PATH}' не найден или путь не указан.")
            print("  Проксирование через sing-box будет отключено.")
            use_sing_box = False
        elif not SING_BOX_RUSSIAN_VPN_CONFIG_PATH or not os.path.exists(SING_BOX_RUSSIAN_VPN_CONFIG_PATH):
            print(f"  Ошибка: Файл конфигурации sing-box '{SING_BOX_RUSSIAN_VPN_CONFIG_PATH}' не найден или путь не указан.")
            print("  Проксирование через sing-box будет отключено.")
            use_sing_box = False
        else:
            try:
                print(f"  Запуск sing-box с конфигурацией: {SING_BOX_RUSSIAN_VPN_CONFIG_PATH}")
                # Запускаем sing-box в фоновом режиме. Убедитесь, что sing-box настроен правильно
                # и не выводит слишком много в stdout/stderr, чтобы не мешать основному логу.
                # Возможно, потребуется настроить логирование sing-box в файл в его конфигурации.
                sing_box_command = [SING_BOX_EXECUTABLE_PATH, "run", "-c", SING_BOX_RUSSIAN_VPN_CONFIG_PATH]
                sing_box_process = subprocess.Popen(sing_box_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
                print(f"  sing-box запущен (PID: {sing_box_process.pid}). Ожидание ~2 секунд для стабилизации...")
                time.sleep(2) # Даем время sing-box-у запуститься и подключиться
                if sing_box_process.poll() is not None:
                    print(f"  КРИТИЧЕСКАЯ ОШИБКА: sing-box завершился сразу после запуска с кодом {sing_box_process.returncode}.")
                    stdout_sb, stderr_sb = sing_box_process.communicate()
                    if stdout_sb and stdout_sb.strip(): print(f"  SING-BOX STDOUT:\\n{stdout_sb.strip()}")
                    if stderr_sb and stderr_sb.strip(): print(f"  SING-BOX STDERR:\\n{stderr_sb.strip()}")
                    sing_box_process = None # Сбрасываем, так как он не работает
                    use_sing_box = False
                    print("  Проксирование через sing-box будет отключено.")
                else:
                    print(f"  sing-box работает. Тесты будут проводиться через прокси 127.0.0.1:{SING_BOX_LOCAL_SOCKS_PORT}")
                    use_sing_box = True
            except Exception as e_sb_start:
                print(f"  Ошибка при запуске sing-box: {e_sb_start}")
                sing_box_process = None # Убедимся, что он None если была ошибка
                use_sing_box = False
                print("  Проксирование через sing-box будет отключено.")
    else:
        use_sing_box = False
        print("--- Проксирование через sing-box отключено в конфигурации (USE_SING_BOX_PROXY_IF_CONFIGURED = False) ---")


    if not os.path.exists(SUBSCRIPTIONS_FILENAME):
        print(f"Файл с подписками '{SUBSCRIPTIONS_FILENAME}' не найден. Пожалуйста, создайте его и добавьте URL-адреса подписок.")
        # Создадим пустой файл для примера
        with open(SUBSCRIPTIONS_FILENAME, 'w') as f:
            f.write("# Пример:\\n")
            f.write("# https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml\\n")
            f.write("# https://example.com/another_subscription.txt | ВашеРегулярноеВыражениеДляИменСерверов\\n") # Обновлен пример
        print(f"Создан пустой файл '{SUBSCRIPTIONS_FILENAME}'. Заполните его и перезапустите скрипт.")
        return

    subscriptions_data = []  # Новый код
    with open(SUBSCRIPTIONS_FILENAME, 'r', encoding='utf-8') as f: # Новый код, добавлен encoding
        for line in f: # Новый код
            line = line.strip() # Новый код
            if not line or line.startswith("#"): # Новый код
                continue # Новый код
            parts = line.split('|', 1) # Новый код
            url = parts[0].strip() # Новый код
            regex_pattern_str = parts[1].strip() if len(parts) > 1 else None # Новый код
            subscriptions_data.append({"url": url, "regex": regex_pattern_str}) # Новый код


    if not subscriptions_data: # Новый код
        print(f"Файл с подписками '{SUBSCRIPTIONS_FILENAME}' пуст или содержит только комментарии.")
        return

    all_good_servers_overall_count = 0

    for sub_data in subscriptions_data: # Новый код
        sub_url = sub_data["url"] # Новый код
        custom_regex = sub_data["regex"] # Новый код

        print(f"\n--- Обработка подписки: {sub_url} ---")
        if custom_regex: # Новый код
            print(f"  Будет применено регулярное выражение для фильтрации имен: {custom_regex}") # Новый код
        
        server_configs, output_filename_base = fetch_server_configs(sub_url, custom_regex) # Новый код

        if not server_configs:
            print(f"Не удалось получить или обработать конфигурации серверов для {sub_url}. Пропуск.")
            continue

        good_servers_for_this_subscription = []
        
        servers_to_test_list = server_configs
        if MAX_SERVERS_TO_TEST > 0 and len(server_configs) > MAX_SERVERS_TO_TEST:
            print(f"  Ограничение на {MAX_SERVERS_TO_TEST} серверов из {len(server_configs)}.")
            servers_to_test_list = server_configs[:MAX_SERVERS_TO_TEST]

        for i, server_details in enumerate(servers_to_test_list):
            server_name = server_details.get('name', f'Server_{i+1}')
            print(f"\nТестирование сервера {i+1}/{len(servers_to_test_list)}: {server_name} (из {sub_url})")

            protocol = server_details.get("type", "").lower()
            required_fields = []
            if protocol == "vmess" or protocol == "vless":
                required_fields = ["server", "port", "uuid"]
            elif protocol == "trojan":
                required_fields = ["server", "port", "password"]
            elif protocol == "ss" or protocol == "shadowsocks":
                required_fields = ["server", "port", "cipher", "password"]

            missing_fields = [field for field in required_fields if not server_details.get(field)]
            if missing_fields:
                print(f"  Пропуск сервера {server_name}: отсутствуют обязательные поля: {', '.join(missing_fields)}")
                continue
            
            port = server_details.get("port")
            if port:
                try:
                    int(port)
                except ValueError:
                    print(f"  Пропуск сервера {server_name}: некорректный порт '{port}'.")
                    continue
            else:
                 print(f"  Пропуск сервера {server_name}: порт не указан.")
                 continue

            config_file_path = None # Для finally
            process = None      # Для finally

            try:
                config_file_path = create_v2ray_config(server_details, use_sing_box_proxy=use_sing_box)
                if not config_file_path:
                    print(f"  Не удалось создать конфигурационный файл для {server_name}. Пропуск.")
                    continue

                command = [CORE_EXECUTABLE_PATH, "run", "-c", config_file_path]
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
                
                print(f"  Ядро Xray/V2Ray запущено для {server_name} (PID: {process.pid}). Ожидание ~0.5 сек для проверки стабильности...")
                time.sleep(0.5)

                stdout_data_early = None
                stderr_data_early = None

                if process.poll() is not None: # Процесс завершился сразу
                    # Собираем вывод один раз
                    stdout_data_early, stderr_data_early = process.communicate()
                    print(f"  КРИТИЧЕСКАЯ ОШИБКА: Ядро Xray/V2Ray для {server_name} завершилось сразу после запуска с кодом {process.returncode}.")
                    if stdout_data_early and stdout_data_early.strip():
                        print(f"  XRAY STDOUT ({server_name}):\\n{stdout_data_early.strip()}")
                    if stderr_data_early and stderr_data_early.strip():
                        print(f"  XRAY STDERR ({server_name}):\\n{stderr_data_early.strip()}")
                    
                    if process.returncode == 23 and DEBUG_SAVE_CONFIG:
                        saved_config_filename = f"debug_config_{server_name.replace(' ', '_').replace(':', '_')}.json"
                        if os.path.exists(config_file_path): # Используем config_file_path
                            try:
                                shutil.copyfile(config_file_path, saved_config_filename)
                                print(f"  КОНФИГ С ОШИБКОЙ 23 сохранен как: {saved_config_filename}")
                                print(f"  Детали сервера, вызвавшего ошибку: {json.dumps(server_details, indent=2, ensure_ascii=False)}")
                            except Exception as e_copy:
                                print(f"  Не удалось скопировать ошибочный конфиг {config_file_path} в {saved_config_filename}: {e_copy}")
                        else:
                            print(f"  Файл конфига {config_file_path} не найден для копирования при ошибке 23.")
                    # Дальнейшие действия не нужны, finally всё почистит.
                
                else: # Процесс не упал сразу, продолжаем тестирование
                    print(f"  Ядро Xray/V2Ray для {server_name} работает. Ожидание ~1.5 сек для стабилизации...")
                    time.sleep(1.5) # Оставшееся время для стабилизации

                    if test_server_connection(server_name):
                        print(f"УСПЕХ: Сервер '{server_name}' ({server_details.get('server')}:{server_details.get('port')}) работает.")
                        good_servers_for_this_subscription.append(server_details)
                    else:
                        print(f"НЕУДАЧА: Сервер '{server_name}' ({server_details.get('server')}:{server_details.get('port')}) не прошел проверку.")

            except Exception as e:
                print(f"  Ошибка при запуске или тестировании Xray/V2Ray для {server_name}: {e}")

            finally:
                if process:
                    pid_for_log = process.pid if process.pid else 'N/A'
                    print(f"  Остановка процесса для {server_name} (PID: {pid_for_log})...")
                    
                    # Если процесс еще работает и вывод не был собран (т.е. не было мгновенного падения)
                    if process.poll() is None and stdout_data_early is None and stderr_data_early is None:
                        try:
                            stdout_data_late, stderr_data_late = process.communicate(timeout=0.5)
                            if stdout_data_late and stdout_data_late.strip():
                                print(f"  XRAY STDOUT (при остановке {server_name}):\\\\n{stdout_data_late.strip()}")
                            if stderr_data_late and stderr_data_late.strip():
                                print(f"  XRAY STDERR (при остановке {server_name}):\\\\n{stderr_data_late.strip()}")
                        except subprocess.TimeoutExpired:
                            print(f"  Не удалось получить stdout/stderr от {server_name} перед terminate (timeout).")
                        except Exception as e_comm:
                            print(f"  Ошибка при чтении stdout/stderr от {server_name} перед terminate: {e_comm}")

                    # Убеждаемся, что процесс действительно остановлен
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                            print(f"  Процесс для {server_name} остановлен (terminate). Код: {process.returncode}")
                        except subprocess.TimeoutExpired:
                            print(f"  Процесс для {server_name} не завершился вовремя (terminate), принудительная остановка (kill)...")
                            process.kill()
                            try:
                                process.wait(timeout=5)
                                print(f"  Процесс для {server_name} остановлен (kill). Код: {process.returncode}")
                            except subprocess.TimeoutExpired:
                                print(f"  ПРЕДУПРЕЖДЕНИЕ: Процесс для {server_name} (PID: {pid_for_log}) не завершился даже после kill.")
                            except Exception as e_wait_kill:
                                print(f"  Ошибка при ожидании завершения процесса {server_name} после kill: {e_wait_kill}")
                        except Exception as e_wait_term:
                            print(f"  Ошибка при ожидании завершения процесса {server_name} после terminate: {e_wait_term}")
                    else:
                        # Если poll() не None, значит, он уже завершился.
                        # Вывод либо был собран через stdout_data_early/stderr_data_early, либо не был (если упал без вывода)
                        print(f"  Процесс для {server_name} уже был остановлен до основной логики остановки (код: {process.returncode}).")
                
                if config_file_path and os.path.exists(config_file_path):
                    try:
                        os.remove(config_file_path)
                        # print(f"  Временный файл конфигурации {config_file_path} удален.")
                    except Exception as e_rem:
                        print(f"  Предупреждение: Не удалось удалить временный файл конфигурации {config_file_path}: {e_rem}")
        
        if good_servers_for_this_subscription:
            all_good_servers_overall_count += len(good_servers_for_this_subscription)
            # Определяем имя файла для сохранения на основе имени исходного файла/URL
            original_input_extension = os.path.splitext(urlparse(sub_url).path)[1].lower()
            output_filename_suffix = "_good_servers"
            
            # Проверяем, является ли sub_url локальным путем к файлу
            is_local_file = os.path.exists(sub_url)
            
            if is_local_file:
                # Если это локальный файл, берем его расширение
                _, original_input_extension = os.path.splitext(sub_url)
                original_input_extension = original_input_extension.lower()
                # Используем имя файла без расширения как output_filename_base
                output_filename_base = os.path.splitext(os.path.basename(sub_url))[0]
            else:
                # Для URL используем существующую логику извлечения output_filename_base
                # и original_input_extension уже определен выше из urlparse
                pass # output_filename_base уже получен из fetch_server_configs
            
            # Формируем имя выходного файла
            if original_input_extension == ".txt":
                output_filename = f"{output_filename_base}{output_filename_suffix}.txt"
                print(f"\nСохранение {len(good_servers_for_this_subscription)} хороших серверов в TXT (Base64) файл: {output_filename}")
                
                links_to_encode = []
                for server in good_servers_for_this_subscription:
                    link = None
                    server_type = server.get("type", "").lower()
                    
                    if server_type == "trojan":
                        link = format_trojan_link(server)
                    elif server_type == "ss" or server_type == "shadowsocks":
                        link = format_ss_link(server)
                    elif server_type == "vmess":
                        link = format_vmess_link(server)
                    elif server_type == "vless":
                        link = format_vless_link(server)
                    
                    if link:
                        links_to_encode.append(link)
                    else:
                        print(f"  Предупреждение: Не удалось отформатировать ссылку для сервера: {server.get('name', 'N/A')}")
                        # Fallback to name or some identifier if formatting fails
                        links_to_encode.append(server.get("name", f"Unnamed_{server.get('type')}_{server.get('server')}"))

                if links_to_encode:
                    full_subscription_content = "\n".join(links_to_encode)
                    # Use urlsafe_b64encode for broader compatibility, though standard base64 often works.
                    # V2RayN typically expects standard base64, not necessarily URL-safe for the whole blob.
                    # Let's stick to standard base64 for the final output as per common subscription formats.
                    base64_encoded_subscription = base64.b64encode(full_subscription_content.encode('utf-8')).decode('utf-8')
                    
                    with open(output_filename, 'w', encoding='utf-8') as f:
                        f.write(base64_encoded_subscription)
                    print(f"Сохранено в {output_filename}")
                else:
                    print(f"Нет ссылок для кодирования и сохранения в {output_filename}")
            
            else: # По умолчанию или если расширение было .yml/.yaml
                final_extension = original_input_extension if original_input_extension in [".yml", ".yaml"] else ".yml"
                output_filename = f"{output_filename_base}{output_filename_suffix}{final_extension}"
                print(f"\nСохранение {len(good_servers_for_this_subscription)} хороших серверов в YAML файл: {output_filename}")
                proxies_output = {'proxies': good_servers_for_this_subscription}
                try:
                    with open(output_filename, 'w', encoding='utf-8') as f:
                        yaml.dump(proxies_output, f, allow_unicode=True, sort_keys=False, indent=2)
                    print(f"Сохранено в {output_filename}")
                except Exception as e:
                    print(f"Ошибка при сохранении YAML файла {output_filename}: {e}")
        else:
            print(f"Для подписки {sub_url} не найдено работающих серверов.")

    print(f"\n\n--- Итог ---")
    print(f"Всего протестировано подписок: {len(subscriptions_data)}")
    print(f"Общее количество найденных и сохраненных хороших серверов: {all_good_servers_overall_count}")
    if os.path.exists(TEMP_CONFIG_FILENAME):
        try:
            os.remove(TEMP_CONFIG_FILENAME)
            print(f"Финальное удаление временного файла конфигурации {TEMP_CONFIG_FILENAME} успешно.")
        except Exception as e_remove_final:
            print(f"Предупреждение: Не удалось удалить временный файл конфигурации {TEMP_CONFIG_FILENAME} в конце: {e_remove_final}")

    if sing_box_process:
        print(f"--- Остановка sing-box (PID: {sing_box_process.pid}) ---")
        sing_box_process.terminate()
        try:
            stdout_sb_end, stderr_sb_end = sing_box_process.communicate(timeout=5) # Даем время на сбор вывода
            print(f"  sing-box остановлен (terminate). Код возврата: {sing_box_process.returncode}")
            if stdout_sb_end and stdout_sb_end.strip():
                print(f"  SING-BOX STDOUT (при остановке):\\n{stdout_sb_end.strip()}")
            if stderr_sb_end and stderr_sb_end.strip():
                print(f"  SING-BOX STDERR (при остановке):\\n{stderr_sb_end.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  sing-box не ответил на terminate в течение 5 секунд. Принудительная остановка (kill)...")
            sing_box_process.kill()
            try:
                sing_box_process.wait(timeout=5)
                print(f"  sing-box остановлен (kill). Код возврата: {sing_box_process.returncode}")
            except subprocess.TimeoutExpired:
                print(f"  ПРЕДУПРЕЖДЕНИЕ: sing-box (PID: {sing_box_process.pid}) не завершился даже после kill.")
            except Exception as e_sb_wait_kill:
                print(f"  Ошибка при ожидании завершения sing-box после kill: {e_sb_wait_kill}")
        except Exception as e_sb_comm:
            print(f"  Ошибка при получении вывода от sing-box во время остановки: {e_sb_comm}")


if __name__ == '__main__':
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"Скрипт завершил работу за {end_time - start_time:.2f} секунд.")