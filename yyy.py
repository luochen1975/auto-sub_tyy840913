import requests
import base64
import re
import json
import os
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置部分 ---
# 订阅链接输入/输出文件路径
SUBSCRIPTION_FILE = "sub.txt"
# 代理节点输出文件路径
OUTPUT_CONFIG_FILE = "config.txt"

# --- 函数定义 ---

def fetch_and_decode_subscription(url: str) -> str | None:
    """
    从给定的URL获取订阅内容并进行Base64解码。
    如果获取或解码失败，则返回None。
    """
    try:
        # 设置超时，避免长时间等待
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 如果状态码不是200，抛出HTTPError

        # 尝试Base64解码
        # 移除可能的空白符，确保解码正确
        decoded_content = base64.b64decode(response.text.strip()).decode('utf-8')
        print(f"✅ 成功获取并解码: {url}")
        return decoded_content
    except requests.exceptions.RequestException as e:
        print(f"❌ 获取订阅失败 ({url}): {e}")
        return None
    except base64.binascii.Error as e:
        print(f"❌ Base64解码失败 ({url}): {e}")
        return None
    except Exception as e:
        print(f"❌ 发生未知错误 ({url}): {e}")
        return None

def parse_nodes(content: str) -> list[tuple[str, str]]:
    """
    解析解码后的订阅内容，提取代理节点。
    返回一个列表，每个元素是一个元组 (去重标识, 原始节点URI)。
    去重标识通常是 "协议://服务器:端口"，或包含其他关键唯一参数。
    """
    nodes_info = []
    for line in content.splitlines():
        line = line.strip()
        if not line: # 排除空行
            continue

        # Shadowsocks (SS) 协议解析: ss://[base64(method:password)]@server:port[#tag]
        if line.startswith("ss://"):
            try:
                # 提取 ss:// 后面的部分
                encoded_part = line[5:]
                # 尝试解码 method:password 部分，如果存在
                if '@' in encoded_part:
                    # 考虑到 auth_part 可能是 base64 编码，也可能不是
                    parts = encoded_part.split('@', 1)
                    if len(parts) == 2:
                        auth_part, server_part_with_tag = parts
                    else: # 没有认证部分，直接是 server:port#tag
                        auth_part = ''
                        server_part_with_tag = encoded_part
                else:
                    auth_part = ''
                    server_part_with_tag = encoded_part

                # 提取服务器和端口
                # 服务器部分可能包含tag，需要处理
                server_port_match = re.search(r'([\w\d\.-]+):(\d+)', server_part_with_tag)
                if server_port_match:
                    server = server_port_match.group(1)
                    port = server_port_match.group(2)
                    dedup_id = f"ss://{server}:{port}"
                    # TODO: 对于SS，如果需要考虑加密方法或密码去重，需要进一步解析auth_part
                    # 例如，可以解析 auth_part 来获取 method 和 password
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 SS 链接解析服务器/端口: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 SS 节点失败: {e} - {line[:50]}...")

        # VMess 协议解析: vmess://[base64(json)]
        elif line.startswith("vmess://"):
            try:
                vmess_json_b64 = line[8:]
                vmess_json_decoded = base64.b64decode(vmess_json_b64 + '==').decode('utf-8')
                node_info = json.loads(vmess_json_decoded)

                server = node_info.get('add')
                port = node_info.get('port')
                # VMess 通常需要 UUID 作为唯一标识的一部分
                uuid = node_info.get('id', '')
                if server and port:
                    # 去重ID包含UUID，确保不同UUID但同IP端口的节点区分开
                    dedup_id = f"vmess://{uuid}@{server}:{port}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 VMess JSON 解析服务器/端口: {line[:50]}...")
            except (base64.binascii.Error, json.JSONDecodeError, KeyError) as e:
                print(f"⚠️ 解析 VMess 节点 JSON 失败: {e} - {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 VMess 节点失败: {e} - {line[:50]}...")

        # Trojan 协议解析: trojan://password@server:port[?params][#tag]
        elif line.startswith("trojan://"):
            try:
                match = re.match(r"trojan://[^@]+@([\w\d\.-]+):(\d+)", line)
                if match:
                    server = match.group(1)
                    port = match.group(2)
                    dedup_id = f"trojan://{server}:{port}"
                    # TODO: 对于Trojan，如果password或SNI是去重关键，需要进一步解析
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 Trojan 链接解析服务器/端口: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 Trojan 节点失败: {e} - {line[:50]}...")

        # VLESS 协议解析: vless://UUID@server:port?params#tag
        elif line.startswith("vless://"):
            try:
                parsed_url = urlparse(line)
                uuid = parsed_url.username or "" # VLESS UUID 在username部分
                server = parsed_url.hostname
                port = parsed_url.port

                if uuid and server and port:
                    # 去重ID包含UUID和主要传输参数
                    query_params = parse_qs(parsed_url.query)
                    security = query_params.get('security', [''])[0] # tls, xtls
                    node_type = query_params.get('type', [''])[0] # ws, grpc
                    dedup_id = f"vless://{uuid}@{server}:{port}?security={security}&type={node_type}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 VLESS 链接解析核心信息: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 VLESS 节点失败: {e} - {line[:50]}...")

        # NaïveProxy (Naive) 协议: https://user:pass@server:port (与标准HTTPS区分需看上下文)
        # 这里仅按通用HTTPS代理处理，具体识别NaïveProxy可能需要特定端口或额外的识别方法
        elif line.startswith(("http://", "https://")):
            try:
                parsed_url = urlparse(line)
                if parsed_url.hostname and parsed_url.port:
                    # 区分HTTP/HTTPS代理和Naive Proxy可能需要额外的逻辑，比如通过端口
                    # 这里先按通用HTTP/HTTPS代理处理
                    dedup_id = f"{parsed_url.scheme}://{parsed_url.hostname}:{parsed_url.port}"
                    # 如果有用户名和密码，也加入去重ID
                    if parsed_url.username and parsed_url.password:
                         dedup_id += f"@{parsed_url.username}:{parsed_url.password}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 HTTP/HTTPS 链接解析服务器/端口: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 HTTP/HTTPS 节点失败: {e} - {line[:50]}...")

        # SOCKS5 代理: socks5://[user:pass@]server:port
        elif line.startswith("socks5://"):
            try:
                parsed_url = urlparse(line)
                if parsed_url.hostname and parsed_url.port:
                    dedup_id = f"socks5://{parsed_url.hostname}:{parsed_url.port}"
                    # 如果有用户名和密码，也加入去重ID
                    if parsed_url.username and parsed_url.password:
                        dedup_id += f"@{parsed_url.username}:{parsed_url.password}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 SOCKS5 链接解析服务器/端口: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 SOCKS5 节点失败: {e} - {line[:50]}...")

        # Snell 协议: snell://server:port?psk=your_psk&obfs=...#tag
        elif line.startswith("snell://"):
            try:
                parsed_url = urlparse(line)
                server = parsed_url.hostname
                port = parsed_url.port
                query_params = parse_qs(parsed_url.query)
                psk = query_params.get('psk', [''])[0] # Pre-Shared Key 是关键去重参数

                if server and port and psk:
                    dedup_id = f"snell://{server}:{port}?psk={psk}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 Snell 链接解析核心信息: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 Snell 节点失败: {e} - {line[:50]}...")

        # Hysteria 协议: hysteria://server:port?protocol=udp&auth=password&upmbps=...#tag
        elif line.startswith("hysteria://"):
            try:
                parsed_url = urlparse(line)
                server = parsed_url.hostname
                port = parsed_url.port
                query_params = parse_qs(parsed_url.query)
                auth = query_params.get('auth', [''])[0] # 认证信息是关键

                if server and port and auth:
                    dedup_id = f"hysteria://{server}:{port}?auth={auth}"
                    # 可以考虑包含协议类型和SNI等更多参数
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 Hysteria 链接解析核心信息: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 Hysteria 节点失败: {e} - {line[:50]}...")
        
        # TUIC 协议: tuic://UUID:password@server:port/?version=...&congestion_controller=...#tag
        elif line.startswith("tuic://"):
            try:
                # TUIC 链接结构复杂，这里简化解析UUID、密码、服务器和端口
                # tuic://UUID:password@server:port/?params...
                match = re.match(r"tuic://([^:]+):([^@]+)@([\w\d\.-]+):(\d+)", line)
                if match:
                    uuid = match.group(1)
                    password = match.group(2)
                    server = match.group(3)
                    port = match.group(4)
                    
                    # TUIC 去重标识应包含 UUID 和密码，因为它们定义了唯一连接
                    dedup_id = f"tuic://{uuid}:{password}@{server}:{port}"
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 TUIC 链接解析核心信息: {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 TUIC 节点失败: {e} - {line[:50]}...")

        # ShadowsocksR (SSR) 协议: ssr://base64_encoded_config
        # SSR 链接的 Base64 解码后的格式复杂，这里提供一个基础解析框架
        elif line.startswith("ssr://"):
            try:
                ssr_config_b64 = line[6:]
                # 补齐Base64填充，然后URL解码，再Base64解码
                # 注意：SSR的Base64编码可能不标准，这里需要额外处理
                decoded_ssr_url = base64.b64decode(ssr_config_b64 + '==').decode('utf-8')
                # SSR 链接格式通常是 server:port:protocol:method:obfs:password_base64/?params_base64
                parts = decoded_ssr_url.split(':')
                if len(parts) >= 5:
                    server = parts[0]
                    port = parts[1]
                    # protocol = parts[2]
                    # method = parts[3]
                    # obfs = parts[4]
                    # password = base64.b64decode(parts[5].split('/')[0] + '==').decode('utf-8') # 密码部分需要再次Base64解码

                    dedup_id = f"ssr://{server}:{port}"
                    # TODO: SSR的去重可能需要考虑协议、混淆和密码，这里只用服务器和端口
                    nodes_info.append((dedup_id, line))
                else:
                    print(f"⚠️ 无法从 SSR 链接解析核心信息 (格式不符): {line[:50]}...")
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                print(f"⚠️ SSR Base64解码或URL解码失败: {e} - {line[:50]}...")
            except Exception as e:
                print(f"⚠️ 解析 SSR 节点失败: {e} - {line[:50]}...")
            
        # 其他未知协议或无法解析的行，直接作为原始节点添加
        else:
            print(f"❓ 发现未知或无法解析的协议行: {line[:50]}...")
            # 使用原始行作为去重ID，意味着只有完全相同的字符串才会被去重
            nodes_info.append((line, line))

    return nodes_info

def deduplicate_nodes(node_info_list: list[tuple[str, str]]) -> list[str]:
    """
    对代理节点列表进行去重。
    使用元组中的第一个元素（去重标识）进行去重，保留第二个元素（原始节点URI）。
    """
    unique_nodes_map = {} # {dedup_id: original_node_uri}
    for dedup_id, original_uri in node_info_list:
        # 如果去重ID已经存在，我们保留第一次出现的节点（或者你可以选择覆盖，取决于你的需求）
        if dedup_id not in unique_nodes_map:
            unique_nodes_map[dedup_id] = original_uri
    return list(unique_nodes_map.values())

# --- 主逻辑 ---

def main():
    # 确保 sub.txt 文件存在
    if not os.path.exists(SUBSCRIPTION_FILE):
        print(f"错误：文件 {SUBSCRIPTION_FILE} 不存在。请确保它在脚本的同级目录中。")
        return

    # 读取订阅链接
    subscription_urls = []
    try:
        with open(SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(("http://", "https://")): # 简单验证URL格式
                    subscription_urls.append(url)
        print(f"从 {SUBSCRIPTION_FILE} 读取到 {len(subscription_urls)} 个订阅链接。")
    except IOError as e:
        print(f"❌ 读取订阅文件 {SUBSCRIPTION_FILE} 失败: {e}")
        return

    all_fetched_nodes_info = [] # 存储 (去重标识, 原始节点URI)
    valid_subscriptions = [] # 存储检查后仍然有效的订阅链接

    print("\n--- 开始获取和解析订阅 ---")
    for url in subscription_urls:
        print(f"处理订阅: {url}")
        content = fetch_and_decode_subscription(url)
        if content:
            nodes_from_url = parse_nodes(content)
            if nodes_from_url: # 只有成功获取到至少一个可解析的节点才算有效订阅
                all_fetched_nodes_info.extend(nodes_from_url)
                valid_subscriptions.append(url) # 添加到有效列表
            else:
                print(f"⚠️ 订阅 {url} 成功获取但未解析到任何已知协议的有效节点，标记为无效。")
        else:
            # fetch_and_decode_subscription 失败时已打印错误信息，无需再次打印
            pass # 不添加到有效列表，因此自然被排除

        print("-" * 30)

    print("\n--- 进行节点去重 ---")
    unique_nodes = deduplicate_nodes(all_fetched_nodes_info)
    print(f"总共获取到 {len(all_fetched_nodes_info)} 个节点 (含重复)。")
    print(f"去重后得到 {len(unique_nodes)} 个唯一节点。")

    print("\n--- 保存结果 ---")
    # 将正常的订阅链接写回 sub.txt
    try:
        with open(SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
            for url in valid_subscriptions:
                f.write(url + "\n")
        print(f"✅ 已将 {len(valid_subscriptions)} 个正常订阅链接写回 {SUBSCRIPTION_FILE}")
    except IOError as e:
        print(f"❌ 将正常订阅链接写回 {SUBSCRIPTION_FILE} 失败: {e}")

    # 将去重后的代理节点输出到 config.txt
    try:
        with open(OUTPUT_CONFIG_FILE, "w", encoding="utf-8") as f:
            for node in unique_nodes:
                f.write(node + "\n")
        print(f"✅ 已将去重后的节点保存到: {OUTPUT_CONFIG_FILE}")
    except IOError as e:
        print(f"❌ 保存代理节点到 {OUTPUT_CONFIG_FILE} 失败: {e}")

    print("\n--- 脚本执行完毕 ---")

if __name__ == "__main__":
    main()
