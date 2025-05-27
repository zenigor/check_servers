import requests
import yaml
import subprocess
import json
import time
import os
import shutil
import base64
import re
from urllib.parse import urlparse, parse_qs

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

def fetch_server_configs(url):
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
            
            # Фильтрация серверов по регулярному выражению для TXT подписок
            if parsed_servers: # Только если есть что фильтровать
                print(f"  Начинаю фильтрацию {len(parsed_servers)} серверов по регулярному выражению...")
                regex_pattern = r"^(?!.*(?:NA-|RU-)).*(?:\b(?:TCP-RLT|GRPC-RLT)\b).*"
                filtered_servers_by_name = []
                for server in parsed_servers:
                    server_name = server.get("name", "")
                    if re.search(regex_pattern, server_name):
                        filtered_servers_by_name.append(server)
                    else:
                        print(f"  Сервер '{server_name}' не соответствует регулярному выражению, отфильтрован.")
                
                if not filtered_servers_by_name:
                    print(f"  Внимание: После фильтрации по имени не осталось серверов из {url}.")
                else:
                    print(f"  После фильтрации по имени осталось {len(filtered_servers_by_name)} серверов.")
                parsed_servers = filtered_servers_by_name # Заменяем список отфильтрованным

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
                "publicKey": reality_opts_yaml.get("public-key", server_details.get("public-key", "")),
                "shortId": reality_opts_yaml.get("short-id", server_details.get("short-id", "")),
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
    print(f"  Предварительная проверка: {server_name} -> {PRE_CHECK_URL}")
    try:
        # Используем stream=True, чтобы не загружать тело ответа, если оно вдруг будет
        # Для generate_204 тело не ожидается, но это хорошая практика
        response_pre = requests.get(PRE_CHECK_URL, proxies=proxies, timeout=PRE_CHECK_TIMEOUT, headers=headers, verify=False, stream=True)
        
        if response_pre.status_code == 204:
            print(f"  Предварительная проверка УСПЕХ: Сервер '{server_name}' достиг {PRE_CHECK_URL}.")
        else:
            print(f"  Предварительная проверка ОШИБКА: Сервер '{server_name}' к {PRE_CHECK_URL} вернул статус {response_pre.status_code} (ожидался 204).")
            return False # Если предварительная проверка не прошла, дальше не идем
        # Закрываем соединение, так как использовали stream=True
        response_pre.close()

    except requests.exceptions.Timeout:
        print(f"  Предварительная проверка ОШИБКА (Таймаут): Сервер '{server_name}' не ответил на {PRE_CHECK_URL} за {PRE_CHECK_TIMEOUT} сек.")
        return False
    except requests.exceptions.ProxyError as e:
        print(f"  Предварительная проверка ОШИБКА (Прокси): Сервер '{server_name}' к {PRE_CHECK_URL}. {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  Предварительная проверка ОШИБКА (Соединение): Сервер '{server_name}' к {PRE_CHECK_URL}. {e}")
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

    if not os.path.exists(SUBSCRIPTIONS_FILENAME):
        print(f"Файл с подписками '{SUBSCRIPTIONS_FILENAME}' не найден. Пожалуйста, создайте его и добавьте URL-адреса подписок.")
        # Создадим пустой файл для примера
        with open(SUBSCRIPTIONS_FILENAME, 'w') as f:
            f.write("# Пример:\n")
            f.write("# https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml\n")
            f.write("# https://example.com/another_subscription.txt\n")
        print(f"Создан пустой файл '{SUBSCRIPTIONS_FILENAME}'. Заполните его и перезапустите скрипт.")
        return

    with open(SUBSCRIPTIONS_FILENAME, 'r') as f:
        subscription_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not subscription_urls:
        print(f"Файл с подписками '{SUBSCRIPTIONS_FILENAME}' пуст или содержит только комментарии.")
        return

    all_good_servers_overall_count = 0

    for sub_url in subscription_urls:
        print(f"\n--- Обработка подписки: {sub_url} ---")
        server_configs, output_filename_base = fetch_server_configs(sub_url)

        if not server_configs:
            print(f"Не удалось получить или обработать конфигурации серверов для {sub_url}. Пропуск.")
            continue

        good_servers_for_this_subscription = []
        active_processes = []

        # Ограничение на количество тестируемых серверов, если MAX_SERVERS_TO_TEST > 0
        servers_to_test_list = server_configs
        if MAX_SERVERS_TO_TEST > 0 and len(server_configs) > MAX_SERVERS_TO_TEST:
            print(f"  Ограничение на {MAX_SERVERS_TO_TEST} серверов из {len(server_configs)}.")
            # Можно добавить случайный выбор, если нужно: random.shuffle(servers_to_test_list)
            servers_to_test_list = server_configs[:MAX_SERVERS_TO_TEST]


        for i, server_details in enumerate(servers_to_test_list):
            server_name = server_details.get('name', f'Server_{i+1}') # Используем имя из конфига или генерируем
            print(f"\nТестирование сервера {i+1}/{len(servers_to_test_list)}: {server_name} (из {sub_url})")

            # Проверка наличия необходимых полей
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
            
            # Проверка типа порта
            port = server_details.get("port")
            if port:
                try:
                    int(port)
                except ValueError:
                    print(f"  Пропуск сервера {server_name}: некорректный порт '{port}'.")
                    continue
            else: # Если port отсутствует (хотя он должен быть в required_fields)
                 print(f"  Пропуск сервера {server_name}: порт не указан.")
                 continue


            config_file = create_v2ray_config(server_details)
            if not config_file:
                print(f"  Не удалось создать конфигурационный файл для {server_name}. Пропуск.")
                continue

            # Запуск xray/v2ray ядра в фоновом режиме
            command = [CORE_EXECUTABLE_PATH, "run", "-c", config_file]
            try:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                active_processes.append({"process": process, "config_file": config_file, "server_name": server_name})
                print(f"  Ядро Xray/V2Ray запущено для {server_name} (PID: {process.pid}). Ожидание для стабилизации...")
                time.sleep(2) # Даем время ядру запуститься

                if test_server_connection(server_name):
                    print(f"УСПЕХ: Сервер \'{server_name}\' ({server_details.get('server')}:{server_details.get('port')}) работает.")
                    good_servers_for_this_subscription.append(server_details)
                else:
                    print(f"НЕУДАЧА: Сервер \'{server_name}\' ({server_details.get('server')}:{server_details.get('port')}) не прошел проверку.")

            except Exception as e:
                print(f"  Ошибка при запуске или тестировании Xray/V2Ray для {server_name}: {e}")
            finally:
                # Останавливаем процесс и удаляем временный конфиг
                # Эта логика будет перенесена ниже, чтобы остановить все процессы после цикла
                pass # processos.terminate() и os.remove() будут ниже

        # Остановка всех активных процессов и удаление временных файлов после проверки всех серверов из текущей подписки
        for proc_info in active_processes:
            try:
                print(f"  Остановка процесса для {proc_info['server_name']} (PID: {proc_info['process'].pid})...")
                proc_info["process"].terminate() # Сначала пытаемся мягко завершить
                try:
                    proc_info["process"].wait(timeout=5) # Ждем завершения
                except subprocess.TimeoutExpired:
                    print(f"  Процесс для {proc_info['server_name']} не завершился вовремя, принудительная остановка (kill)...")
                    proc_info["process"].kill() # Если не помогло, "убиваем"
                    proc_info["process"].wait() # Дожидаемся после kill
                print(f"  Процесс для {proc_info['server_name']} остановлен.")
            except Exception as e:
                print(f"  Ошибка при остановке процесса для {proc_info['server_name']}: {e}")
            finally:
                if os.path.exists(proc_info["config_file"]):
                    try:
                        os.remove(proc_info["config_file"])
                        # print(f"  Временный файл конфигурации {proc_info['config_file']} удален.")
                    except Exception as e_rem:
                        print(f"  Не удалось удалить временный файл {proc_info['config_file']}: {e_rem}")


        if good_servers_for_this_subscription:
            # Формируем имя выходного файла
            output_filename = f"{output_filename_base}_good_servers.yml"
            try:
                with open(output_filename, 'w', encoding='utf-8') as f:
                    #yaml.dump({"proxies": good_servers_for_this_subscription}, f, allow_unicode=True, sort_keys=False)
                    # В V2RayN используется немного другой формат yaml, без "proxies:", а просто список
                    # И также часто поля пишутся с одинарными кавычками, но это не стандарт YAML для строк
                    # Будем писать стандартный YAML, который должен быть совместим
                    
                    # V2RayN-совместимый вывод (максимально близко)
                    f.write("proxies:\\n")
                    for server in good_servers_for_this_subscription:
                        f.write("- ")
                        # Преобразуем некоторые поля обратно или обеспечиваем нужный формат
                        server_copy = server.copy() # Работаем с копией
                        
                        # Boolean значения как true/false без кавычек
                        for key in ['udp', 'tls', 'skip-cert-verify', 'uot', 'ติ๊กถูกแล้วจะทำให้การเชื่อมต่ออินเทอร์เน็ตของคุณถูกส่งผ่านเซิร์ฟเวอร์นี้']: # последняя строка - пример странного ключа
                            if key in server_copy and isinstance(server_copy[key], bool):
                                server_copy[key] = str(server_copy[key]).lower()
                            elif key in server_copy and server_copy[key] is None: # Удаляем ключи с None значением
                                del server_copy[key]


                        # Строки в двойных кавычках, если содержат спецсимволы или начинаются с цифр/булевых и т.д.
                        # pyyaml по умолчанию хорошо с этим справляется, если не указывать default_flow_style=None/False
                        
                        # Для v2rayN важно, чтобы name, server, uuid и т.д. были на месте
                        # Имена полей как есть
                        
                        # dump одного сервера за раз, чтобы контролировать отступы и формат списка
                        yaml_lines = yaml.dump(server_copy, allow_unicode=True, sort_keys=False, width=float("inf")).splitlines()
                        first_line = True
                        for line_idx, dump_line in enumerate(yaml_lines):
                            if first_line:
                                f.write(dump_line + "\n")
                                first_line = False
                            else:
                                # Добавляем 2 пробела для отступа под "- "
                                f.write("  " + dump_line + "\n")
                    
                print(f"Сохранено {len(good_servers_for_this_subscription)} хороших серверов в файл \'{output_filename}\'")
                all_good_servers_overall_count += len(good_servers_for_this_subscription)
            except Exception as e:
                print(f"Ошибка при сохранении хороших серверов в файл {output_filename}: {e}")
        else:
            print(f"Хороших серверов для подписки {sub_url} не найдено.")

    print(f"\n--- Завершено ---")
    print(f"Всего найдено и сохранено хороших серверов: {all_good_servers_overall_count}")
    # Удаление временного файла конфигурации, если он остался после аварийного завершения
    # (хотя теперь он удаляется для каждого сервера индивидуально)
    if os.path.exists(TEMP_CONFIG_FILENAME):
        try:
            os.remove(TEMP_CONFIG_FILENAME)
        except Exception:
            pass # Игнорируем, если не удалось удалить

if __name__ == "__main__":
    main()