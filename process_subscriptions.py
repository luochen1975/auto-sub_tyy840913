import requests
import base64
import re
import json
import os
import yaml # 导入 PyYAML 库
from urllib.parse import urlparse, parse_qs, unquote, quote

# --- 配置部分 ---
# 订阅链接输入/输出文件路径
SUBSCRIPTION_FILE = "sub.txt"
# 代理节点输出文件路径
OUTPUT_CONFIG_FILE = "config.txt"

# --- 辅助函数：将Clash YAML字典转换为标准URI ---
def _parse_clash_proxy_entry(proxy_entry: dict) -> tuple[str, str] | None:
    """
    尝试将一个Clash YAML代理字典转换为标准代理URI和去重ID。
    如果无法转换，返回None。
    返回 (dedup_id, node_uri)
    """
    node_uri = None
    dedup_id = None
    
    p_type = proxy_entry.get('type')
    server = proxy_entry.get('server')
    port = proxy_entry.get('port')
    name = proxy_entry.get('name', '').strip() # 节点名称，用于URI的tag

    if not server or not port:
        # print(f"⚠️ Clash YAML节点缺少服务器或端口: {proxy_entry.get('name', '未知节点')}")
        return None

    if p_type == 'ss':
        cipher = proxy_entry.get('cipher')
        password = proxy_entry.get('password')
        if cipher and password:
            try:
                auth_part = base64.urlsafe_b64encode(f"{cipher}:{password}".encode('utf-8')).decode().rstrip('=')
                node_uri = f"ss://{auth_part}@{server}:{port}"
                if name: node_uri += f"#{quote(name)}"
                dedup_id = f"ss://{server}:{port}"
            except Exception as e:
                print(f"⚠️ SS YAML节点重构失败: {e} - {name}")
        
    elif p_type == 'vmess':
        # VMess 节点需要构建一个 JSON 字符串
        vmess_config = {
            "v": "2", # 默认为V2
            "ps": name,
            "add": server,
            "port": port,
            "id": proxy_entry.get('uuid', ''),
            "aid": proxy_entry.get('alterId', 0),
            "scy": proxy_entry.get('cipher', 'auto'),
            "net": proxy_entry.get('network', 'tcp'),
            "type": proxy_entry.get('type', 'none'), # http, ws, quic, grpc
            "host": proxy_entry.get('ws-opts', {}).get('headers', {}).get('Host', ''),
            "path": proxy_entry.get('ws-opts', {}).get('path', ''),
            "tls": "tls" if proxy_entry.get('tls') else "",
            "sni": proxy_entry.get('sni', ''),
            "skip-cert-verify": proxy_entry.get('skip-cert-verify', False)
        }
        # 移除空值或默认值，使JSON更简洁
        vmess_config = {k: v for k, v in vmess_config.items() if v not in ["", 0, False, "none", "tcp"]}
        
        try:
            vmess_json = json.dumps(vmess_config, ensure_ascii=False) # 允许非ASCII字符
            node_uri = "vmess://" + base64.b64encode(vmess_json.encode('utf-8')).decode().rstrip('=')
            dedup_id = f"vmess://{vmess_config['id']}@{server}:{port}"
        except Exception as e:
            print(f"⚠️ VMess YAML节点重构失败: {e} - {name}")

    elif p_type == 'trojan':
        password = proxy_entry.get('password')
        if password:
            node_uri = f"trojan://{password}@{server}:{port}"
            if proxy_entry.get('tls'): node_uri += "?tls=true"
            if proxy_entry.get('skip-cert-verify'): node_uri += "&skip-cert-verify=true"
            if proxy_entry.get('sni'): node_uri += f"&sni={proxy_entry['sni']}"
            if name: node_uri += f"#{quote(name)}"
            dedup_id = f"trojan://{server}:{port}"

    elif p_type == 'vless':
        uuid = proxy_entry.get('uuid')
        if uuid:
            params = []
            if proxy_entry.get('tls'): params.append("tls=true")
            if proxy_entry.get('skip-cert-verify'): params.append("skip-cert-verify=true")
            if proxy_entry.get('network'): params.append(f"type={proxy_entry['network']}")
            if proxy_entry.get('ws-opts') and proxy_entry['ws-opts'].get('path'): params.append(f"path={proxy_entry['ws-opts']['path']}")
            if proxy_entry.get('ws-opts') and proxy_entry['ws-opts'].get('headers') and 'Host' in proxy_entry['ws-opts']['headers']: 
                params.append(f"host={proxy_entry['ws-opts']['headers']['Host']}")
            # 添加其他VLESS参数，如flow, security, fingerprint等
            
            query_string = "?" + "&".join(params) if params else ""
            node_uri = f"vless://{uuid}@{server}:{port}{query_string}"
            if name: node_uri += f"#{quote(name)}"
            dedup_id = f"vless://{uuid}@{server}:{port}"

    elif p_type == 'hysteria':
        password = proxy_entry.get('password')
        if password:
            params = []
            if proxy_entry.get('auth'): params.append(f"auth={proxy_entry['auth']}") # Hysteria的认证字段
            if proxy_entry.get('alpn'): params.append(f"alpn={','.join(proxy_entry['alpn'])}")
            if proxy_entry.get('fast-open'): params.append("fastopen=true")
            if proxy_entry.get('mptcp'): params.append("mptcp=true")
            if proxy_entry.get('obfs'): params.append(f"obfs={proxy_entry['obfs']}")
            if proxy_entry.get('obfs-password'): params.append(f"obfs-password={proxy_entry['obfs-password']}")
            if proxy_entry.get('up'): params.append(f"upmbps={proxy_entry['up']}")
            if proxy_entry.get('down'): params.append(f"downmbps={proxy_entry['down']}")
            if proxy_entry.get('tls'): params.append("tls=true")
            if proxy_entry.get('skip-cert-verify'): params.append("insecure=1") # Hysteria insecure参数
            if proxy_entry.get('sni'): params.append(f"sni={proxy_entry['sni']}")
            
            query_string = "?" + "&".join(params) if params else ""
            node_uri = f"hysteria://{server}:{port}{query_string}"
            if name: node_uri += f"#{quote(name)}"
            dedup_id = f"hysteria://{server}:{port}"
            if proxy_entry.get('auth'): dedup_id += f"?auth={proxy_entry['auth']}" # auth也是去重关键

    elif p_type == 'hysteria2':
        password = proxy_entry.get('password')
        if password:
            params = []
            if proxy_entry.get('tls'): params.append("tls=true")
            if proxy_entry.get('skip-cert-verify'): params.append("insecure=1")
            if proxy_entry.get('sni'): params.append(f"sni={proxy_entry['sni']}")
            
            query_string = "?" + "&".join(params) if params else ""
            node_uri = f"hysteria2://{quote(password)}@{server}:{port}{query_string}"
            if name: node_uri += f"#{quote(name)}"
            dedup_id = f"hysteria2://{password}@{server}:{port}"

    elif p_type == 'tuic':
        uuid = proxy_entry.get('uuid')
        password = proxy_entry.get('password')
        if uuid and password:
            params = []
            if proxy_entry.get('version'): params.append(f"version={proxy_entry['version']}")
            if proxy_entry.get('congestion-controller'): params.append(f"congestion_controller={proxy_entry['congestion-controller']}")
            if proxy_entry.get('udp-relay-mode'): params.append(f"udp_relay_mode={proxy_entry['udp-relay-mode']}")
            if proxy_entry.get('tls'): params.append("tls=true")
            if proxy_entry.get('skip-cert-verify'): params.append("insecure=1")
            if proxy_entry.get('sni'): params.append(f"sni={proxy_entry['sni']}")
            if proxy_entry.get('alpn'): params.append(f"alpn={','.join(proxy_entry['alpn'])}")

            query_string = "?" + "&".join(params) if params else ""
            node_uri = f"tuic://{uuid}:{password}@{server}:{port}{query_string}"
            if name: node_uri += f"#{quote(name)}"
            dedup_id = f"tuic://{uuid}:{password}@{server}:{port}"

    # 对于其他未明确处理的类型，如果能识别到协议头，则尝试作为原始URI
    if node_uri:
        return (dedup_id, node_uri)
    else:
        # 如果无法重构为标准URI，将整个字典转换为字符串作为去重ID和原始URI
        # 这确保了节点不会丢失，但可能不是可用的URI
        dedup_id = f"clash_unknown_{json.dumps(proxy_entry, sort_keys=True, ensure_ascii=False)[:100]}"
        return (dedup_id, str(proxy_entry)) # 将字典转换为字符串形式存储

# --- 辅助函数：解析原始URI字符串 ---
def _parse_raw_uri_line(line: str) -> tuple[str, str] | None:
    """
    解析单个原始代理URI字符串，尝试识别协议并生成去重ID。
    返回 (dedup_id, node_uri) 或 None。
    """
    if not line:
        return None

    # 过滤掉明显的规则行、注释行或非代理URI的行
    # 增加对 `name:` 的过滤，因为在某些非标准订阅中，节点名称可能以 `- name:` 开头
    if line.startswith(('- DOMAIN-SUFFIX', '- DOMAIN-KEYWORD', '- IP-CIDR', '- GEOIP', '- PROCESS-NAME', '- RULE-SET', '- MATCH', '#')) or \
       '→ tg@' in line or 'name:' in line.lower() or not re.match(r'^[a-zA-Z]+://', line): # 确保以协议头开头
        # print(f"ℹ️ 跳过非代理协议行: {line[:50]}...") # 避免过多输出
        return None

    # 常用协议前缀列表
    protocol_prefixes = (
        "ss://", "vmess://", "trojan://", "vless://", "snell://", 
        "hysteria://", "hysteria2://", "tuic://", "ssr://", 
        "http://", "https://", "socks5://"
    )

    for prefix in protocol_prefixes:
        if line.startswith(prefix):
            node_uri = line.strip() # 原始完整链接
            dedup_id_base = f"{prefix}{node_uri[:100]}" # 默认去重ID

            # 特殊处理 Base64 编码的协议部分
            if prefix in ("ss://", "vmess://", "vless://"):
                # 提取协议头后的部分
                encoded_part = node_uri[len(prefix):]
                try:
                    # 尝试将这部分编码为 ASCII 字节，如果包含非 ASCII 字符，会抛出 UnicodeEncodeError
                    # 这是为了避免 base64.b64decode 内部的 'ascii' codec 错误
                    encoded_bytes_for_b64 = encoded_part.encode('ascii') + b'=='
                    decoded_bytes = base64.b64decode(encoded_bytes_for_b64)
                    
                    # 尝试多种编码解码 Base64 内容
                    try:
                        decoded_content = decoded_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        decoded_content = decoded_bytes.decode('latin-1') # Fallback

                    # 尝试作为 JSON 解析
                    try:
                        node_info = json.loads(decoded_content)
                        server = node_info.get('add') or node_info.get('server')
                        port = node_info.get('port')
                        
                        if prefix == "vmess://":
                            uuid = node_info.get('id', '')
                            if server and port and uuid:
                                dedup_id = f"vmess://{uuid}@{server}:{port}"
                                return (dedup_id, node_uri)
                        elif prefix == "vless://":
                            uuid = node_info.get('id', '') # 有些VLESS JSON里用id
                            if not uuid: # 有些VLESS JSON里用uuid
                                uuid = node_info.get('uuid', '')
                            if server and port and uuid:
                                dedup_id = f"vless://{uuid}@{server}:{port}"
                                return (dedup_id, node_uri)
                        elif prefix == "ss://":
                            if server and port:
                                dedup_id = f"ss://{server}:{port}"
                                return (dedup_id, node_uri)
                    except json.JSONDecodeError:
                        # 如果不是 JSON，尝试作为简单的 method:password@server:port 或 UUID@server:port 字符串解析
                        if prefix == "ss://":
                            match = re.search(r'([\w\d\.-]+):(\d+)', decoded_content)
                            if match:
                                server = match.group(1)
                                port = match.group(2)
                                dedup_id = f"ss://{server}:{port}"
                                return (dedup_id, node_uri)
                        elif prefix == "vless://":
                            match = re.search(r'([\w\d-]+)@([\w\d\.-]+):(\d+)', decoded_content)
                            if match:
                                uuid = match.group(1)
                                server = match.group(2)
                                port = match.group(3)
                                dedup_id = f"vless://{uuid}@{server}:{port}"
                                return (dedup_id, node_uri)
                        # 其他 Base64 编码但非 JSON 的情况，回退到通用处理
                        print(f"⚠️ {prefix} Base64解码内容既非JSON也非标准URI格式: {decoded_content[:50]}...")

                except (UnicodeEncodeError, base64.binascii.Error, ValueError) as e:
                    # Base64 解码失败或包含非 ASCII 字符，回退到非 Base64 格式的解析
                    # print(f"ℹ️ {prefix} Base64解码失败，尝试作为普通URI解析: {e}")
                    pass # 继续尝试下面的传统URI解析

            # 传统 URI 格式解析 (如果上面 Base64 尝试失败或不适用)
            if prefix == "ss://":
                parts = node_uri[5:].split('@', 1)
                server_part_with_tag = parts[1] if len(parts) == 2 else node_uri[5:]
                server_port_match = re.search(r'([\w\d\.-]+):(\d+)', server_part_with_tag)
                if server_port_match:
                    server = server_port_match.group(1)
                    port = server_port_match.group(2)
                    dedup_id = f"ss://{server}:{port}"
                    return (dedup_id, node_uri)
            elif prefix == "vmess://": # VMess 几乎总是 Base64 JSON，这里作为回退
                # 如果到这里还没返回，说明Base64解码失败，这个VMess链接可能无效
                print(f"⚠️ VMess 链接无法解析 (非Base64 JSON): {node_uri[:50]}...")
                return None
            elif prefix == "trojan://":
                match = re.match(r"trojan://[^@]+@([\w\d\.-]+):(\d+)", node_uri)
                if match:
                    server = match.group(1)
                    port = match.group(2)
                    dedup_id = f"trojan://{server}:{port}"
                    return (dedup_id, node_uri)
            elif prefix == "vless://":
                parsed_url = urlparse(node_uri)
                uuid = parsed_url.username or ""
                server = parsed_url.hostname
                port = parsed_url.port
                if uuid and server and port:
                    dedup_id = f"vless://{uuid}@{server}:{port}"
                    return (dedup_id, node_uri)
            elif prefix == "http://" or prefix == "https://":
                parsed_url = urlparse(node_uri)
                if parsed_url.hostname and parsed_url.port:
                    dedup_id = f"{parsed_url.scheme}://{parsed_url.hostname}:{parsed_url.port}"
                    return (dedup_id, node_uri)
            elif prefix == "socks5://":
                parsed_url = urlparse(node_uri)
                if parsed_url.hostname and parsed_url.port:
                    dedup_id = f"socks5://{parsed_url.hostname}:{parsed_url.port}"
                    return (dedup_id, node_uri)
            elif prefix == "snell://":
                parsed_url = urlparse(node_uri)
                server = parsed_url.hostname
                port = parsed_url.port
                query_params = parse_qs(parsed_url.query)
                psk = query_params.get('psk', [''])[0]
                if server and port and psk:
                    dedup_id = f"snell://{server}:{port}?psk={psk}"
                    return (dedup_id, node_uri)
            elif prefix == "hysteria://":
                parsed_url = urlparse(node_uri)
                server = parsed_url.hostname
                port = parsed_url.port
                query_params = parse_qs(parsed_url.query)
                auth = query_params.get('auth', [''])[0]
                if server and port and auth:
                    dedup_id = f"hysteria://{server}:{port}?auth={auth}"
                    return (dedup_id, node_uri)
            elif prefix == "hysteria2://":
                parsed_url = urlparse(node_uri)
                server = parsed_url.hostname
                port = parsed_url.port
                password = unquote(parsed_url.username or "")
                if server and port and password:
                    dedup_id = f"hysteria2://{password}@{server}:{port}"
                    return (dedup_id, node_uri)
            elif prefix == "tuic://":
                match = re.match(r"tuic://([^:]+):([^@]+)@([\w\d\.-]+):(\d+)", node_uri)
                if match:
                    uuid = match.group(1)
                    password = match.group(2)
                    server = match.group(3)
                    port = match.group(4)
                    dedup_id = f"tuic://{uuid}:{password}@{server}:{port}"
                    return (dedup_id, node_uri)
            elif prefix == "ssr://":
                try:
                    ssr_config_b64 = node_uri[6:]
                    decoded_ssr_url = base64.b64decode(ssr_config_b64 + '==').decode('utf-8')
                    parts = decoded_ssr_url.split(':')
                    if len(parts) >= 5:
                        server = parts[0]
                        port = parts[1]
                        dedup_id = f"ssr://{server}:{port}"
                        return (dedup_id, node_uri)
                except Exception as e:
                    print(f"⚠️ SSR 链接解析失败: {e} - {node_uri[:50]}...")
            
            # 如果以上所有解析都失败，但确实是协议头开头的行，则作为通用节点处理
            # 使用协议头 + 链接前N个字符作为去重ID
            print(f"❓ 无法完全解析已知协议，但识别到协议头: {node_uri[:100]}...")
            return (dedup_id_base, node_uri) # 返回原始链接和通用去重ID

    # 如果一行不是任何已知协议开头，则跳过
    # print(f"❓ 未识别的行 (非协议或规则): {line[:100]}...")
    return None

def parse_nodes(content: str) -> list[tuple[str, str]]:
    """
    解析解码后的订阅内容，从 Clash YAML 或纯节点列表中识别并获取代理节点。
    返回一个列表，每个元素是一个元组 (去重标识, 原始节点URI)。
    """
    nodes_info = []
    
    # 尝试作为 YAML 文件解析
    try:
        if content.strip().startswith(('proxies:', 'proxy-providers:', 'rules:', 'port:', 'mixed-port:', 'allow-lan:')):
            print("ℹ️ 内容被识别为 YAML 格式。尝试 PyYAML 解析。")
            yaml_data = yaml.safe_load(content)

            # 提取 proxies 部分的节点
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                print("ℹ️ 找到 YAML 中的 'proxies' 部分。")
                for proxy_entry in yaml_data['proxies']:
                    if isinstance(proxy_entry, dict):
                        parsed_node = _parse_clash_proxy_entry(proxy_entry)
                        if parsed_node:
                            nodes_info.append(parsed_node)
                        else:
                            print(f"⚠️ 无法从Clash YAML字典解析节点: {str(proxy_entry)[:100]}...")
                    elif isinstance(proxy_entry, str): # 有些YAML直接嵌入URI字符串
                        parsed_node = _parse_raw_uri_line(proxy_entry)
                        if parsed_node:
                            nodes_info.append(parsed_node)
                        else:
                            print(f"⚠️ 无法从Clash YAML字符串解析节点: {proxy_entry[:100]}...")

            # 提取 proxy-providers 部分的节点 (通常是外部订阅，这里只作为识别，不深入获取)
            if isinstance(yaml_data, dict) and 'proxy-providers' in yaml_data and isinstance(yaml_data['proxy-providers'], dict):
                print("ℹ️ 找到 YAML 中的 'proxy-providers' 部分，不深入获取其内容。")
                for provider_name, provider_config in yaml_data['proxy-providers'].items():
                    if isinstance(provider_config, dict) and 'url' in provider_config:
                        # print(f"   识别到代理提供者 URL: {provider_config['url']}")
                        pass # 暂时不将 provider 添加到主节点列表

            return nodes_info # 如果成功解析了 YAML，就返回，不再尝试其他解析方式

    except yaml.YAMLError as e:
        print(f"❌ 解析 YAML 内容失败 (PyYAML 错误): {e}")
    except Exception as e:
        print(f"❌ 解析 YAML 内容时发生未知错误: {e}")
    
    # 如果不是 YAML 或 YAML 解析失败，尝试按行解析 (用于 Base64 解码后的纯节点列表)
    print("ℹ️ 内容不是 YAML 或 YAML 解析失败，尝试按行解析。")
    for line in content.splitlines():
        parsed_node = _parse_raw_uri_line(line.strip())
        if parsed_node:
            nodes_info.append(parsed_node)
            
    return nodes_info

def deduplicate_nodes(node_info_list: list[tuple[str, str]]) -> list[str]:
    """
    对代理节点列表进行去重。
    使用元组中的第一个元素（去重标识）进行去重，保留第二个元素（原始节点URI）。
    """
    unique_nodes_map = {} # {dedup_id: original_node_uri}
    for dedup_id, original_uri in node_info_list:
        if dedup_id not in unique_nodes_map:
            unique_nodes_map[dedup_id] = original_uri
    return list(unique_nodes_map.values())

# --- 主逻辑 ---

def main():
    if not os.path.exists(SUBSCRIPTION_FILE):
        print(f"错误：文件 {SUBSCRIPTION_FILE} 不存在。请确保它在脚本的同级目录中。")
        return

    subscription_urls = []
    try:
        with open(SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(("http://", "https://")):
                    subscription_urls.append(url)
        print(f"从 {SUBSCRIPTION_FILE} 读取到 {len(subscription_urls)} 个订阅链接。")
    except IOError as e:
        print(f"❌ 读取订阅文件 {SUBSCRIPTION_FILE} 失败: {e}")
        return

    all_fetched_nodes_info = []
    valid_subscriptions = []
    failed_subscriptions_count = 0

    print("\n--- 开始获取和识别订阅内容中的节点 ---")
    for url in subscription_urls:
        print(f"处理订阅: {url}")
        nodes_from_this_url = [] # 用于统计当前订阅获取的节点数量
        raw_content = fetch_subscription_content(url)

        if raw_content:
            processed_content = None
            
            # 优先尝试 Base64 解码，因为很多订阅是 Base64 编码的 YAML 或纯节点列表
            try:
                # 尝试 URL-safe Base64 解码，并处理填充
                # 关键：先将字符串编码为 ASCII 字节，如果包含非 ASCII 字符，会在此处抛出 UnicodeEncodeError
                decoded_bytes = base64.urlsafe_b64decode(raw_content.strip().encode('ascii') + b'==')
                # 尝试多种编码来解码 Base64 内容到字符串
                try:
                    processed_content = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    processed_content = decoded_bytes.decode('latin-1') # Fallback
                print(f"   内容被 Base64 解码。")
            except (UnicodeEncodeError, base64.binascii.Error, ValueError): # 捕获 Base64 格式错误或非ASCII字符导致的ValueError
                processed_content = raw_content
                print(f"   内容未被 Base64 解码 (可能是原始文本或解码失败)。")

            if processed_content:
                nodes_from_this_url = parse_nodes(processed_content)
                if nodes_from_this_url:
                    all_fetched_nodes_info.extend(nodes_from_this_url)
                    valid_subscriptions.append(url)
                else:
                    print(f"⚠️ 订阅 {url} 成功获取但未识别到任何有效节点，标记为无效。")
                    failed_subscriptions_count += 1
            else:
                print(f"❌ 处理订阅 {url} 失败 (无法处理内容)。")
                failed_subscriptions_count += 1
        else:
            failed_subscriptions_count += 1
        
        print(f"   从当前订阅识别到 {len(nodes_from_this_url)} 个节点。") # 统计每个订阅
        print("-" * 30)

    print("\n--- 进行节点去重 ---")
    unique_nodes = deduplicate_nodes(all_fetched_nodes_info)
    
    print("\n--- 保存结果 ---")
    try:
        with open(SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
            for url in valid_subscriptions:
                f.write(url + "\n")
        print(f"✅ 已将 {len(valid_subscriptions)} 个正常订阅链接写回 {SUBSCRIPTION_FILE}")
    except IOError as e:
        print(f"❌ 将正常订阅链接写回 {SUBSCRIPTION_FILE} 失败: {e}")

    try:
        with open(OUTPUT_CONFIG_FILE, "w", encoding="utf-8") as f:
            for node in unique_nodes:
                f.write(node + "\n")
        print(f"✅ 已将去重后的节点保存到: {OUTPUT_CONFIG_FILE}")
    except IOError as e:
        print(f"❌ 保存代理节点到 {OUTPUT_CONFIG_FILE} 失败: {e}")

    print("\n--- 脚本执行完毕 ---")
    print("\n--- 统计信息 ---")
    print(f"总共处理了 {len(subscription_urls)} 个订阅链接。")
    print(f"其中：")
    print(f"  - **有效订阅链接数量**: {len(valid_subscriptions)}")
    print(f"  - **失效订阅链接数量**: {failed_subscriptions_count}")
    print(f"总共识别到 {len(all_fetched_nodes_info)} 个节点 (含重复)。")
    print(f"**去重后得到 {len(unique_nodes)} 个唯一节点**。")


if __name__ == "__main__":
    main()
