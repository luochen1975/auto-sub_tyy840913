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
    解析解码后的订阅内容，**只识别出代理节点，不进行深度解析**。
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

    # 如果内容是 YAML 格式，尝试逐行处理
    if content.strip().startswith('proxies:') or content.strip().startswith('proxy-providers:') or content.strip().startswith('rules:'):
        # print("ℹ️ 内容被识别为 YAML 格式。")
        for line in content.splitlines():
            stripped_line = line.strip()

            # 过滤掉明显的规则行、注释行或非代理URI的行
            if stripped_line.startswith(('- DOMAIN-SUFFIX', '- DOMAIN-KEYWORD', '- IP-CIDR', '- GEOIP', '- PROCESS-NAME', '- RULE-SET', '- MATCH', '#')) or \
               '→ tg@' in stripped_line or 'name:' in stripped_line.lower() or not stripped_line:
                continue # 跳过规则行、注释行、杂项行和空行

            # 尝试从 YAML 格式中提取完整的代理 URI
            # 这里我们放宽匹配，只要行包含协议前缀就尝试处理
            for prefix in protocol_prefixes:
                if prefix in stripped_line:
                    # 找到协议开头的实际URI部分
                    match = re.search(r'(' + re.escape(prefix) + r'.*)', stripped_line)
                    if match:
                        node_uri = match.group(0).strip()
                        # 对于 Base64 编码的整个订阅内容，如果它也是 Base64 字符串，
                        # 则先尝试解码。这一步发生在 main 函数的 processed_content 阶段。
                        # 这里我们只确保行本身符合URI格式。
                        
                        # 使用协议头 + 链接前N个字符作为去重ID，因为我们不做深度解析
                        dedup_id = f"{prefix}{node_uri[:100]}" 
                        nodes_info.append((dedup_id, node_uri))
                        break # 找到一个协议就处理并跳出内层循环
            # else: # 如果循环结束没有找到协议前缀
                # print(f"❓ YAML 行未识别为已知代理协议: {stripped_line[:100]}...")
        if not nodes_info and len(content) > 500: # 如果YAML解析器未能识别任何节点，且内容较长，可能是无效YAML
             print(f"⚠️ YAML 内容未能解析出任何已知代理节点，可能是无效或非标准YAML。")
    else: # 不是 YAML 格式，按行解析 (通常是Base64解码后的纯代理链接列表)
        # print("ℹ️ 内容被识别为非 YAML 格式。")
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
            # else: # 如果循环结束没有找到协议前缀
                # print(f"❓ 未识别的协议行: {stripped_line[:100]}...") # 避免过多输出
                
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
            
            # 如果是 .yaml 或 .yml 结尾的链接，或内容看起来是 YAML，直接作为原始文本处理
            # 否则，尝试 Base64 解码。
            if parsed_url_obj.path.lower().endswith(('.yaml', '.yml')) or \
               raw_content.strip().startswith(('proxies:', 'proxy-providers:', 'rules:')):
                processed_content = raw_content
                print(f"   订阅链接或内容识别为 YAML 格式，作为原始文本处理。")
            else:
                # 尝试 Base64 解码。如果失败，则认为内容是原始文本
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
