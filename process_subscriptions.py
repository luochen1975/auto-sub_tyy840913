import requests
import base64
import re
import json
import os
import yaml # 导入 PyYAML 库
from urllib.parse import urlparse, quote

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

# --- 辅助函数：只识别Clash YAML字典中的节点类型和名称 ---
def _identify_clash_proxy_entry(proxy_entry: dict) -> tuple[str, str] | None:
    """
    尝试从一个Clash YAML代理字典中识别节点，不进行深度解析。
    返回 (去重标识, 原始节点字符串形式)。
    """
    p_type = proxy_entry.get('type')
    name = proxy_entry.get('name', '').strip()
    server = proxy_entry.get('server', '').strip() # 即使不解析，也尝试获取server做为去重辅助

    if p_type:
        # 使用 type + name + server 前缀作为去重标识，并保留原始字典字符串
        dedup_id = f"CLASH_TYPE_{p_type}_NAME_{name[:50]}_SERVER_{server[:50]}"
        return (dedup_id, str(proxy_entry))
    
    return None

# --- 辅助函数：只识别原始URI字符串的协议头 ---
def _identify_raw_uri_line(line: str) -> tuple[str, str] | None:
    """
    只识别单个原始URI字符串的协议头，不进行深度解析。
    返回 (去重标识, 原始URI)。
    """
    stripped_line = line.strip()
    if not stripped_line:
        return None

    # 过滤掉明显的规则行、注释行、或非代理URI的行
    # 这里匹配规则行、注释行、空行或不以字母+://开头的行
    if stripped_line.startswith(('- DOMAIN-SUFFIX', '- DOMAIN-KEYWORD', '- IP-CIDR', '- GEOIP', '- PROCESS-NAME', '- RULE-SET', '- MATCH', '#')) or \
       '→ tg@' in stripped_line or 'name:' in stripped_line.lower() or not re.match(r'^[a-zA-Z]+://', stripped_line):
        return None

    # 常用协议前缀列表，用于快速识别
    protocol_prefixes = (
        "ss://", "vmess://", "trojan://", "vless://", "snell://", 
        "hysteria://", "hysteria2://", "tuic://", "ssr://", 
        "http://", "https://", "socks5://"
    )

    for prefix in protocol_prefixes:
        if stripped_line.startswith(prefix):
            # 直接将原始行作为节点URI
            node_uri = stripped_line
            # 使用协议头 + 链接前100个字符作为去重ID，因为它不再进行任何解析
            dedup_id = f"{prefix}{node_uri[:100]}"
            return (dedup_id, node_uri)

    # 如果一行不是任何已知协议开头，则跳过
    return None

def parse_nodes(content: str) -> list[tuple[str, str]]:
    """
    解析解码后的订阅内容，从Clash YAML或纯节点列表中**只识别**代理节点。
    返回一个列表，每个元素是一个元组 (去重标识, 原始节点字符串)。
    """
    nodes_info = []
    
    # 尝试作为 YAML 文件解析
    try:
        # 如果内容看起来是 YAML 的开头，尝试用 PyYAML 解析
        if content.strip().startswith(('proxies:', 'proxy-providers:', 'rules:', 'port:', 'mixed-port:', 'allow-lan:')):
            print("ℹ️ 内容被识别为 YAML 格式。尝试 PyYAML 解析。")
            yaml_data = yaml.safe_load(content)

            # 提取 proxies 部分的节点
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                print("ℹ️ 找到 YAML 中的 'proxies' 部分。")
                for proxy_entry in yaml_data['proxies']:
                    if isinstance(proxy_entry, dict):
                        identified_node = _identify_clash_proxy_entry(proxy_entry)
                        if identified_node:
                            nodes_info.append(identified_node)
                        else:
                            print(f"⚠️ 无法从Clash YAML字典识别节点: {str(proxy_entry)[:100]}...")
                    elif isinstance(proxy_entry, str): # 有些YAML直接嵌入URI字符串
                        identified_node = _identify_raw_uri_line(proxy_entry)
                        if identified_node:
                            nodes_info.append(identified_node)
                        else:
                            print(f"⚠️ 无法从Clash YAML字符串识别节点: {proxy_entry[:100]}...")

            # 提取 proxy-providers 部分 (只做识别，不深入获取内容)
            if isinstance(yaml_data, dict) and 'proxy-providers' in yaml_data and isinstance(yaml_data['proxy-providers'], dict):
                print("ℹ️ 找到 YAML 中的 'proxy-providers' 部分，不深入获取其内容。")
                for provider_name, provider_config in yaml_data['proxy-providers'].items():
                    if isinstance(provider_config, dict) and 'url' in provider_config:
                        # 仅识别其 URL，不作为代理节点加入
                        # print(f"   识别到代理提供者 URL: {provider_config['url']}")
                        pass 

            return nodes_info # 如果成功解析了 YAML，就返回，不再尝试其他解析方式

    except yaml.YAMLError as e:
        print(f"❌ 解析 YAML 内容失败 (PyYAML 错误): {e}")
    except Exception as e:
        print(f"❌ 解析 YAML 内容时发生未知错误: {e}")
    
    # 如果不是 YAML 或 YAML 解析失败，尝试按行解析 (用于 Base64 解码后的纯节点列表)
    print("ℹ️ 内容不是 YAML 或 YAML 解析失败，尝试按行识别。")
    for line in content.splitlines():
        identified_node = _identify_raw_uri_line(line.strip())
        if identified_node:
            nodes_info.append(identified_node)
            
    return nodes_info

def deduplicate_nodes(node_info_list: list[tuple[str, str]]) -> list[str]:
    """
    对代理节点列表进行去重。
    使用元组中的第一个元素（去重标识）进行去重，保留第二个元素（原始节点字符串）。
    """
    unique_nodes_map = {} # {dedup_id: original_node_string}
    for dedup_id, original_string in node_info_list:
        if dedup_id not in unique_nodes_map:
            unique_nodes_map[dedup_id] = original_string
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
