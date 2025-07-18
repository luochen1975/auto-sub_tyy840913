import requests
import base64
import re
import json
import os
import yaml # 导入 PyYAML 库
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
    解析解码后的订阅内容，从 Clash YAML 或纯节点列表中识别并获取代理节点。
    返回一个列表，每个元素是一个元组 (去重标识, 原始节点URI)。
    去重标识使用原始链接的前缀或部分，确保尽量保留所有独特的链接。
    """
    nodes_info = []
    
    # 常用协议前缀列表，用于快速识别
    protocol_prefixes = (
        "ss://", "vmess://", "trojan://", "vless://", "snell://", 
        "hysteria://", "hysteria2://", "tuic://", "ssr://", 
        "http://", "https://", "socks5://"
    )

    # 尝试作为 YAML 文件解析
    try:
        # 如果内容看起来是 YAML 的开头，尝试用 PyYAML 解析
        if content.strip().startswith(('proxies:', 'proxy-providers:', 'rules:', 'port:', 'mixed-port:', 'allow-lan:')):
            # print("ℹ️ 尝试将内容解析为 YAML。")
            yaml_data = yaml.safe_load(content)

            # 提取 proxies 部分的节点
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                # print("ℹ️ 找到 YAML 中的 'proxies' 部分。")
                for proxy_entry in yaml_data['proxies']:
                    if isinstance(proxy_entry, dict) and 'type' in proxy_entry:
                        # 尝试根据类型重构 URI 或直接使用某种标准格式
                        # 这是一个简化的示例，Clash YAML 结构复杂，需要根据实际情况细化
                        # 最简单的方式是尝试从字典中直接提取 URI 模式的字段
                        
                        # 对于 Clash YAML，通常节点是字典形式，需要根据类型构建URI
                        # 这里我们只尝试将常见的几种直接提取为URI
                        node_uri = None
                        if proxy_entry['type'] == 'ss':
                            server = proxy_entry.get('server')
                            port = proxy_entry.get('port')
                            cipher = proxy_entry.get('cipher')
                            password = proxy_entry.get('password')
                            if server and port and cipher and password:
                                # ss://base64(method:password)@server:port
                                # 简化为只提取关键信息做去重，保留完整的原始字典，方便后续处理
                                # 或者尝试拼接为最简单的ss://...
                                try:
                                    auth_part = base64.urlsafe_b64encode(f"{cipher}:{password}".encode()).decode().rstrip('=')
                                    node_uri = f"ss://{auth_part}@{server}:{port}"
                                except Exception:
                                    node_uri = None # 拼接失败
                        elif proxy_entry['type'] == 'vmess':
                            # vmess://base64(json)
                            # 从yaml字典直接构建json
                            try:
                                vmess_json = json.dumps(proxy_entry, ensure_ascii=False) # 允许非ASCII字符
                                node_uri = "vmess://" + base64.b64encode(vmess_json.encode('utf-8')).decode().rstrip('=')
                            except Exception:
                                node_uri = None
                        elif proxy_entry['type'] == 'trojan':
                             server = proxy_entry.get('server')
                             port = proxy_entry.get('port')
                             password = proxy_entry.get('password')
                             if server and port and password:
                                 # trojan://password@server:port
                                 node_uri = f"trojan://{password}@{server}:{port}"
                        elif proxy_entry['type'] == 'vless':
                            server = proxy_entry.get('server')
                            port = proxy_entry.get('port')
                            uuid = proxy_entry.get('uuid')
                            if server and port and uuid:
                                params = []
                                if proxy_entry.get('udp'): params.append("udp=true")
                                if proxy_entry.get('tls'): params.append("tls=true")
                                if proxy_entry.get('skip-cert-verify'): params.append("skip-cert-verify=true")
                                if proxy_entry.get('network'): params.append(f"type={proxy_entry['network']}")
                                if proxy_entry.get('ws-path'): params.append(f"path={proxy_entry['ws-path']}")
                                if proxy_entry.get('ws-headers') and 'Host' in proxy_entry['ws-headers']: params.append(f"host={proxy_entry['ws-headers']['Host']}")
                                
                                query_string = "?" + "&".join(params) if params else ""
                                node_uri = f"vless://{uuid}@{server}:{port}{query_string}"
                        # 可以在这里添加更多协议类型的处理 (hysteria, hysteria2, tuic, etc.)
                        # 对于不直接是URI的字典形式节点，我们将其转换为字符串并作为去重ID
                        if node_uri:
                            dedup_id = f"{node_uri[:100]}"
                            nodes_info.append((dedup_id, node_uri))
                        else:
                            # 如果无法重构为标准URI，将整个字典作为去重ID，保留其完整性
                            dedup_id = f"clash_node_{json.dumps(proxy_entry, sort_keys=True, ensure_ascii=False)[:100]}"
                            nodes_info.append((dedup_id, str(proxy_entry))) # 将字典转换为字符串形式存储
                            # print(f"⚠️ 无法将Clash YAML节点重构为标准URI，存储为原始字典字符串: {str(proxy_entry)[:100]}...")


            # 提取 proxy-providers 部分的节点 (通常是外部订阅，这里只作为识别，不深入获取)
            if isinstance(yaml_data, dict) and 'proxy-providers' in yaml_data and isinstance(yaml_data['proxy-providers'], dict):
                # print("ℹ️ 找到 YAML 中的 'proxy-providers' 部分。")
                for provider_name, provider_config in yaml_data['proxy-providers'].items():
                    if isinstance(provider_config, dict) and 'url' in provider_config:
                        provider_url = provider_config['url']
                        # 可以将 provider_url 作为一种特殊的“节点”进行记录或去重
                        # 但通常我们不直接解析 provider_url 中的节点，因为它们是另一个订阅
                        # 这里我们只简单识别并打印，不添加到主节点列表
                        # print(f"   识别到代理提供者 URL: {provider_url}")
                        pass # 暂时不将 provider 添加到主节点列表，以免重复获取或混淆

            return nodes_info # 如果成功解析了 YAML，就返回，不再尝试其他解析方式

    except yaml.YAMLError as e:
        print(f"❌ 解析 YAML 内容失败 (PyYAML 错误): {e}")
    except Exception as e:
        print(f"❌ 解析 YAML 内容时发生未知错误: {e}")
    
    # 如果不是 YAML 或 YAML 解析失败，尝试按行解析 (用于 Base64 解码后的纯节点列表)
    # print("ℹ️ 内容不是 YAML 或 YAML 解析失败，尝试按行解析。")
    for line in content.splitlines():
        stripped_line = line.strip()

        # 过滤掉明显的规则行、注释行或非代理URI的行
        if stripped_line.startswith(('- DOMAIN-SUFFIX', '- DOMAIN-KEYWORD', '- IP-CIDR', '- GEOIP', '- PROCESS-NAME', '- RULE-SET', '- MATCH', '#')) or \
           '→ tg@' in stripped_line or not stripped_line:
            continue # 跳过规则行、注释行、杂项行和空行

        for prefix in protocol_prefixes:
            if stripped_line.startswith(prefix):
                # 直接将原始行作为节点URI
                node_uri = stripped_line
                # 使用协议头 + 链接前N个字符作为去重ID
                dedup_id = f"{prefix}{node_uri[:100]}"
                nodes_info.append((dedup_id, node_uri))
                break # 找到一个协议就处理并跳出内层循环
    
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
            parsed_url_obj = urlparse(url) 
            
            # 判断内容是否是 Base64 编码的纯文本或 YAML
            # 优先尝试 Base64 解码，因为很多订阅是 Base64 编码的 YAML
            try:
                # 尝试 URL-safe Base64 解码，并处理填充
                decoded_bytes = base64.urlsafe_b64decode(raw_content.strip() + '==')
                # 尝试多种编码来解码 Base64 内容到字符串
                try:
                    processed_content = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    processed_content = decoded_bytes.decode('latin-1') # Fallback
                print(f"   内容被 Base64 解码。")
            except (base64.binascii.Error, ValueError): # 捕获 Base64 格式错误或非ASCII字符导致的ValueError
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
