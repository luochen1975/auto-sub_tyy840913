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

def fetch_subscription_content(url: str) -> str | None:
    """
    从给定的URL获取订阅内容。
    如果获取失败，则返回None。
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 如果状态码不是200，抛出HTTPError
        
        # 尝试以 UTF-8 解码，如果失败则尝试其他常见编码
        try:
            content = response.content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = response.content.decode('gbk') # 尝试GBK，中文环境可能遇到
            except UnicodeDecodeError:
                content = response.content.decode('latin-1') # Fallback to latin-1
        
        print(f"✅ 成功获取内容: {url}")
        return content
    except requests.exceptions.RequestException as e:
        print(f"❌ 获取订阅失败 ({url}): {e}")
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
    # 如果内容是 YAML 格式，尝试解析其代理部分
    if content.strip().startswith('proxies:') or content.strip().startswith('proxy-providers:'):
        try:
            # 简化处理：从 YAML 中提取以 '  - ' 开头的行，这些通常是代理节点定义
            for line in content.splitlines():
                if line.strip().startswith('- '):
                    # 尝试用正则匹配URI部分
                    match = re.search(r'(ss|vmess|trojan|vless|snell|hysteria|hysteria2|tuic|ssr|http|https|socks5)://.*', line)
                    if match:
                        node_uri = match.group(0).strip()
                        # 然后将提取到的 URI 传递给现有的解析逻辑
                        temp_nodes_info = parse_single_node_uri(node_uri)
                        nodes_info.extend(temp_nodes_info)
            if not nodes_info: # 如果 YAML 解析器未能识别任何节点，尝试作为普通文本列表解析
                 print(f"⚠️ YAML 内容未识别出已知代理节点，尝试按行解析。")
                 # 回退到按行解析
                 for line in content.splitlines():
                     temp_nodes_info = parse_single_node_uri(line.strip())
                     nodes_info.extend(temp_nodes_info)
        except Exception as e:
            print(f"❌ 解析 YAML 格式内容失败: {e}")
            # 如果 YAML 解析失败，回退到按行解析
            for line in content.splitlines():
                temp_nodes_info = parse_single_node_uri(line.strip())
                nodes_info.extend(temp_nodes_info)
    else: # 不是 YAML 格式，按行解析
        for line in content.splitlines():
            temp_nodes_info = parse_single_node_uri(line.strip())
            nodes_info.extend(temp_nodes_info)

    return nodes_info

def parse_single_node_uri(line: str) -> list[tuple[str, str]]:
    """
    解析单个代理节点 URI。
    这是一个辅助函数，用于将 parse_nodes 拆分为更小的单元。
    """
    nodes_info_local = []
    if not line:
        return nodes_info_local

    # Shadowsocks (SS) 协议解析
    if line.startswith("ss://"):
        try:
            # 尝试 Base64 解码，处理 Base64 编码的 SS 配置 (JSON 或其他)
            encoded_part = line[5:]
            try:
                # 尝试 Base64 解码
                decoded_bytes = base64.b64decode(encoded_part + '==')
                decoded_content = decoded_bytes.decode('utf-8')
                
                # 尝试作为 JSON 解析 (常见于某些 SS 链接)
                node_info = json.loads(decoded_content)
                server = node_info.get('add') or node_info.get('server')
                port = node_info.get('port')
                if server and port:
                    dedup_id = f"ss://{server}:{port}"
                    nodes_info_local.append((dedup_id, line))
                    return nodes_info_local # 成功解析并返回
            except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                # 如果 Base64 解码失败或不是 JSON，则继续按传统 SS URI 格式解析
                pass
            
            # 传统 SS URI 格式解析: ss://[base64(method:password)]@server:port[#tag]
            parts = encoded_part.split('@', 1)
            server_part_with_tag = parts[1] if len(parts) == 2 else encoded_part

            server_port_match = re.search(r'([\w\d\.-]+):(\d+)', server_part_with_tag)
            if server_port_match:
                server = server_port_match.group(1)
                port = server_port_match.group(2)
                dedup_id = f"ss://{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 SS 链接解析服务器/端口 (非Base64或传统格式): {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 SS 节点失败: {e} - {line[:50]}...")

    # VMess 协议解析: vmess://[base64(json)]
    elif line.startswith("vmess://"):
        try:
            vmess_json_b64 = line[8:]
            decoded_bytes = base64.b64decode(vmess_json_b64 + '==')
            # 尝试多种编码来解码 Base64 内容
            try:
                vmess_json_decoded = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    vmess_json_decoded = decoded_bytes.decode('gbk')
                except UnicodeDecodeError:
                    vmess_json_decoded = decoded_bytes.decode('latin-1') # Fallback
            
            node_info = json.loads(vmess_json_decoded)

            server = node_info.get('add')
            port = node_info.get('port')
            uuid = node_info.get('id', '')
            if server and port:
                dedup_id = f"vmess://{uuid}@{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 VMess JSON 解析服务器/端口: {line[:50]}...")
        except (base64.binascii.Error, json.JSONDecodeError, KeyError, UnicodeDecodeError) as e:
            print(f"⚠️ 解析 VMess 节点失败: {e} - {line[:50]}...") # 统一错误信息
        except Exception as e:
            print(f"⚠️ 解析 VMess 节点失败: {e} - {line[:50]}...")

    # Trojan 协议解析
    elif line.startswith("trojan://"):
        try:
            match = re.match(r"trojan://[^@]+@([\w\d\.-]+):(\d+)", line)
            if match:
                server = match.group(1)
                port = match.group(2)
                dedup_id = f"trojan://{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 Trojan 链接解析服务器/端口: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 Trojan 节点失败: {e} - {line[:50]}...")

    # VLESS 协议解析
    elif line.startswith("vless://"):
        try:
            # 尝试 Base64 解码，处理 Base64 编码的 VLESS 配置 (JSON 或其他)
            encoded_part = line[8:]
            try:
                decoded_bytes = base64.b64decode(encoded_part + '==')
                decoded_content = decoded_bytes.decode('utf-8')
                
                node_info = json.loads(decoded_content) # 尝试作为 JSON 解析
                server = node_info.get('add') or node_info.get('server')
                port = node_info.get('port')
                uuid = node_info.get('id', '')
                
                if uuid and server and port:
                    # 尝试从原始 Base64 URI 中重构 VLESS 链接，这可能有点复杂
                    # 简单起见，如果解析出关键信息，就用这些信息做去重ID
                    dedup_id = f"vless://{uuid}@{server}:{port}"
                    nodes_info_local.append((dedup_id, line))
                    return nodes_info_local # 成功解析并返回
            except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
                # 如果 Base64 解码失败或不是 JSON，则继续按传统 VLESS URI 格式解析
                pass

            # 传统 VLESS URI 格式解析: vless://UUID@server:port?params#tag
            parsed_url = urlparse(line)
            uuid = parsed_url.username or ""
            server = parsed_url.hostname
            port = parsed_url.port

            if uuid and server and port:
                query_params = parse_qs(parsed_url.query)
                security = query_params.get('security', [''])[0]
                node_type = query_params.get('type', [''])[0]
                dedup_id = f"vless://{uuid}@{server}:{port}?security={security}&type={node_type}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 VLESS 链接解析核心信息 (非Base64或传统格式): {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 VLESS 节点失败: {e} - {line[:50]}...")

    # HTTP/HTTPS 代理
    elif line.startswith(("http://", "https://")):
        try:
            parsed_url = urlparse(line)
            if parsed_url.hostname and parsed_url.port:
                dedup_id = f"{parsed_url.scheme}://{parsed_url.hostname}:{parsed_url.port}"
                if parsed_url.username and parsed_url.password:
                     dedup_id += f"@{parsed_url.username}:{parsed_url.password}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 HTTP/HTTPS 链接解析服务器/端口: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 HTTP/HTTPS 节点失败: {e} - {line[:50]}...")

    # SOCKS5 代理
    elif line.startswith("socks5://"):
        try:
            parsed_url = urlparse(line)
            if parsed_url.hostname and parsed_url.port:
                dedup_id = f"socks5://{parsed_url.hostname}:{parsed_url.port}"
                if parsed_url.username and parsed_url.password:
                    dedup_id += f"@{parsed_url.username}:{parsed_url.password}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 SOCKS5 链接解析服务器/端口: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 SOCKS5 节点失败: {e} - {line[:50]}...")

    # Snell 协议
    elif line.startswith("snell://"):
        try:
            parsed_url = urlparse(line)
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)
            psk = query_params.get('psk', [''])[0]

            if server and port and psk:
                dedup_id = f"snell://{server}:{port}?psk={psk}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 Snell 链接解析核心信息: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 Snell 节点失败: {e} - {line[:50]}...")

    # Hysteria 协议
    elif line.startswith("hysteria://"):
        try:
            parsed_url = urlparse(line)
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)
            auth = query_params.get('auth', [''])[0]

            if server and port and auth:
                dedup_id = f"hysteria://{server}:{port}?auth={auth}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 Hysteria 链接解析核心信息: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 Hysteria 节点失败: {e} - {line[:50]}...")
        
    # Hysteria2 协议
    elif line.startswith("hysteria2://"):
        try:
            parsed_url = urlparse(line)
            server = parsed_url.hostname
            port = parsed_url.port
            password = unquote(parsed_url.username or "") # 密码在username部分，可能URL编码

            if server and port and password:
                dedup_id = f"hysteria2://{password}@{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 Hysteria2 链接解析核心信息: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 Hysteria2 节点失败: {e} - {line[:50]}...")

    # TUIC 协议
    elif line.startswith("tuic://"):
        try:
            match = re.match(r"tuic://([^:]+):([^@]+)@([\w\d\.-]+):(\d+)", line)
            if match:
                uuid = match.group(1)
                password = match.group(2)
                server = match.group(3)
                port = match.group(4)
                
                dedup_id = f"tuic://{uuid}:{password}@{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 TUIC 链接解析核心信息: {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 TUIC 节点失败: {e} - {line[:50]}...")

    # ShadowsocksR (SSR) 协议
    elif line.startswith("ssr://"):
        try:
            ssr_config_b64 = line[6:]
            decoded_ssr_url = base64.b64decode(ssr_config_b64 + '==').decode('utf-8')
            parts = decoded_ssr_url.split(':')
            if len(parts) >= 5:
                server = parts[0]
                port = parts[1]
                dedup_id = f"ssr://{server}:{port}"
                nodes_info_local.append((dedup_id, line))
            else:
                print(f"⚠️ 无法从 SSR 链接解析核心信息 (格式不符): {line[:50]}...")
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"⚠️ SSR Base64解码或URL解码失败: {e} - {line[:50]}...")
        except Exception as e:
            print(f"⚠️ 解析 SSR 节点失败: {e} - {line[:50]}...")
            
    # 其他未知协议或无法解析的行
    else:
        print(f"❓ 发现未知或无法解析的协议行: {line[:50]}...") 
        # 作为原始行添加，去重效果可能不佳，但至少不丢弃
        nodes_info_local.append((line, line)) 

    return nodes_info_local

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

    print("\n--- 开始获取和解析订阅 ---")
    for url in subscription_urls:
        print(f"处理订阅: {url}")
        raw_content = fetch_subscription_content(url)

        if raw_content:
            processed_content = None
            parsed_url_obj = urlparse(url) 
            
            # 如果是 .yaml 或 .yml 结尾的链接，直接作为原始文本处理
            if parsed_url_obj.path.lower().endswith(('.yaml', '.yml')):
                processed_content = raw_content
                print(f"   订阅链接以 .yaml 或 .yml 结尾，作为原始文本处理。")
            else:
                # 否则，尝试 Base64 解码。如果失败，则认为内容是原始文本
                try:
                    # 尝试 URL-safe Base64 解码，并处理填充
                    decoded_bytes = base64.urlsafe_b64decode(raw_content.strip() + '==')
                    # 尝试多种编码来解码 Base64 内容到字符串
                    try:
                        processed_content = decoded_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            processed_content = decoded_bytes.decode('gbk')
                        except UnicodeDecodeError:
                            processed_content = decoded_bytes.decode('latin-1')
                    print(f"   内容被 Base64 解码。")
                except (base64.binascii.Error, ValueError): # 捕获 Base64 格式错误或非ASCII字符导致的ValueError
                    processed_content = raw_content
                    print(f"   内容未被 Base64 解码 (可能是原始文本或解码失败)。")

            if processed_content:
                nodes_from_url = parse_nodes(processed_content)
                if nodes_from_url:
                    all_fetched_nodes_info.extend(nodes_from_url)
                    valid_subscriptions.append(url)
                else:
                    print(f"⚠️ 订阅 {url} 成功获取但未解析到任何已知协议的有效节点，标记为无效。")
                    failed_subscriptions_count += 1
            else:
                print(f"❌ 处理订阅 {url} 失败 (无法处理内容)。")
                failed_subscriptions_count += 1
        else:
            failed_subscriptions_count += 1
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
    print(f"总共获取到 {len(all_fetched_nodes_info)} 个节点 (含重复)。")
    print(f"**去重后得到 {len(unique_nodes)} 个唯一节点**。")


if __name__ == "__main__":
    main()
