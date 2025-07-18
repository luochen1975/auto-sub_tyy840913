import requests
import base64
import yaml
import re
from urllib.parse import urlparse
import time
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import argparse

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('script.log'),  # 输出日志到文件，便于GitHub Actions调试
        logging.StreamHandler()
    ]
)

# 支持的代理协议（至少10种）
SUPPORTED_PROTOCOLS = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 
    'http', 'https', 'socks4', 'socks5', 'hysteria', 
    'hysteria2', 'tuic', 'wireguard'
]

def read_subscription_file(file_path):
    """读取订阅链接文件并返回去重后的链接列表"""
    try:
        if not os.path.exists(file_path):
            logging.error(f"订阅文件 {file_path} 不存在")
            return []
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        # 去重订阅链接
        unique_lines = list(dict.fromkeys(lines))
        logging.info(f"读取到 {len(lines)} 条订阅链接，去重后 {len(unique_lines)} 条")
        return unique_lines
    except Exception as e:
        logging.error(f"读取订阅文件失败: {e}")
        return []

def write_subscription_file(links, file_path):
    """将有效的订阅链接写回文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)  # 确保目录存在
        with open(file_path, 'w', encoding='utf-8') as f:
            for link in links:
                f.write(link + '\n')
        logging.info(f"已将 {len(links)} 条有效订阅链接写回 {file_path}")
    except Exception as e:
        logging.error(f"写回订阅文件失败: {e}")

def fetch_subscription_content(url, timeout=10):
    """获取订阅链接的内容"""
    try:
        headers = {'User-Agent': 'Clash/2.0'}
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        content = response.text
        # 尝试解码Base64
        try:
            if not content.startswith(('vmess://', 'ss://', 'trojan://', 'vless://')):
                content = base64.b64decode(content).decode('utf-8')
        except:
            pass
        return content
    except Exception as e:
        logging.warning(f"无法获取订阅内容 {url}: {e}")
        return None

def parse_proxy_node(line):
    """解析单条代理节点"""
    try:
        for protocol in SUPPORTED_PROTOCOLS:
            if line.startswith(f"{protocol}://"):
                return {'protocol': protocol, 'config': line}
        return None
    except Exception as e:
        logging.warning(f"解析代理节点失败: {line}, 错误: {e}")
        return None

def fetch_proxies_from_subscription(url):
    """从订阅链接获取代理节点"""
    content = fetch_subscription_content(url)
    if not content:
        return []
    
    proxies = []
    lines = content.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        node = parse_proxy_node(line)
        if node:
            proxies.append(node)
    
    return proxies

def validate_subscriptions(subscription_urls):
    """验证订阅链接有效性并获取代理节点"""
    valid_urls = []
    all_proxies = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_proxies_from_subscription, url): url for url in subscription_urls}
        for future in future_to_url:
            url = future_to_url[future]
            try:
                proxies = future.result()
                if proxies:
                    valid_urls.append(url)
                    all_proxies.extend(proxies)
                    logging.info(f"订阅 {url} 有效，获取到 {len(proxies)} 个代理节点")
                else:
                    logging.warning(f"订阅 {url} 无效，无代理节点")
            except Exception as e:
                logging.error(f"处理订阅 {url} 时出错: {e}")
    
    return valid_urls, all_proxies

def deduplicate_proxies(proxies):
    """代理节点去重"""
    seen = set()
    unique_proxies = []
    for proxy in proxies:
        config = proxy['config']
        if config not in seen:
            seen.add(config)
            unique_proxies.append(proxy)
    logging.info(f"去重后剩余 {len(unique_proxies)} 个代理节点")
    return unique_proxies

def generate_clash_config(proxies, output_file):
    """生成Clash配置文件"""
    clash_config = {
        'proxies': []
    }
    
    for proxy in proxies:
        try:
            config = proxy['config']
            parsed = parse_proxy_for_clash(config)
            if parsed:
                clash_config['proxies'].append(parsed)
        except Exception as e:
            logging.warning(f"处理代理节点 {config} 失败: {e}")
    
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)  # 确保目录存在
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logging.info(f"已生成Clash配置文件 {output_file}，包含 {len(clash_config['proxies'])} 个代理节点")
    except Exception as e:
        logging.error(f"写入Clash配置文件失败: {e}")

def parse_proxy_for_clash(config):
    """将代理节点转换为Clash格式（简化的解析逻辑）"""
    try:
        protocol = None
        for proto in SUPPORTED_PROTOCOLS:
            if config.startswith(f"{proto}://"):
                protocol = proto
                break
        
        if not protocol:
            return None
            
        parsed = {
            'name': f"{protocol}-{hash(config) % 10000}",
            'type': protocol,
            'server': 'example.com',  # 需从config解析
            'port': 443,              # 需从config解析
        }
        
        if protocol in ['vmess', 'vless', 'trojan']:
            parsed.update({
                'uuid': 'example-uuid',  # 需从config解析
                'tls': True
            })
        elif protocol in ['ss', 'ssr']:
            parsed.update({
                'password': 'example-pass',  # 需从config解析
                'cipher': 'aes-256-gcm'     # 需从config解析
            })
        elif protocol in ['http', 'https', 'socks4', 'socks5']:
            parsed.update({
                'username': 'user',  # 可选，需从config解析
                'password': 'pass'   # 可选，需从config解析
            })
        
        return parsed
    except Exception as e:
        logging.warning(f"解析Clash代理配置失败 {config}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Process subscription links and generate Clash config")
    parser.add_argument('--sub-file', default='sub.txt', help='Path to subscription file')
    parser.add_argument('--config-file', default='config.txt', help='Path to output Clash config file')
    args = parser.parse_args()

    # 读取订阅链接
    subscription_urls = read_subscription_file(args.sub_file)
    if not subscription_urls:
        logging.error("没有读取到任何订阅链接，程序退出")
        return
    
    # 验证订阅链接并获取代理节点
    valid_urls, proxies = validate_subscriptions(subscription_urls)
    
    # 写回有效订阅链接
    if valid_urls:
        write_subscription_file(valid_urls, args.sub_file)
    else:
        logging.warning("没有有效的订阅链接")
    
    # 去重代理节点
    unique_proxies = deduplicate_proxies(proxies)
    
    # 生成Clash配置文件
    if unique_proxies:
        generate_clash_config(unique_proxies, args.config_file)
    else:
        logging.warning("没有有效的代理节点，无法生成配置文件")

if __name__ == "__main__":
    main()
