#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
1. 读取 sub.txt 全部订阅（不去除失效）
2. 自动识别 Base64 URI 或 Clash YAML
3. 拉取节点、去重、写入 config.txt
4. 把全部订阅（含失效）去重后写回 sub.txt
"""
import base64
import os
import re
import sys
import time
import urllib.parse
from typing import List

import requests
import yaml

# ---------- 配置 ----------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SUB_FILE = os.path.join(REPO_ROOT, 'sub.txt')
OUT_FILE = os.path.join(REPO_ROOT, 'config.txt')

PROTOCOL_PATTERNS = {
    'ss': r'^ss://', 'ssr': r'^ssr://', 'vmess': r'^vmess://',
    'vless': r'^vless://', 'trojan': r'^trojan://',
    'hysteria': r'^hysteria://', 'hysteria2': r'^hysteria2://',
    'tuic': r'^tuic://', 'naive+https': r'^naive\+https://',
    'wireguard': r'^wireguard://'
}

TIMEOUT = 10
MAX_RETRIES = 3


# ---------- 工具 ----------
def 下载(url: str) -> bytes:
    headers = {'User-Agent': 'Mozilla/5.0'}
    for i in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            print(f'[警告] 下载失败：{url} 原因：{e}，重试 {i+1}/{MAX_RETRIES}')
            time.sleep(2)
    return b''


def 解码base64(data: str) -> str:
    missing = len(data) % 4
    if missing:
        data += '=' * (4 - missing)
    try:
        return base64.urlsafe_b64decode(data.encode()).decode('utf-8')
    except Exception:
        return ''


def 订阅是否有效(url: str) -> bool:
    raw = 下载(url)
    if not raw:
        return False
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')
    # 简单判断：有节点即可
    return bool(解码base64(text).strip()) or bool(
        re.search(r'^proxies\s*:', text, re.MULTILINE)
    )


def 读取订阅() -> List[str]:
    if not os.path.exists(SUB_FILE):
        return []
    with open(SUB_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def 写回全部订阅(links: List[str]):
    seen = set()
    dedup = [l for l in links if not (l in seen or seen.add(l))]
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(dedup) + '\n')


def 保存节点(nodes: List[str]):
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(nodes))) + '\n')


# ---------- Clash YAML 转 URI ----------
def _clash_proxy_to_uri(proxy: dict) -> str:
    ptype = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', ''))

    # SS
    if ptype == 'ss':
        cipher = proxy['cipher']
        password = proxy['password']
        server = proxy['server']
        port = proxy['port']
        auth = base64.urlsafe_b64encode(f'{cipher}:{password}'.encode()).decode()
        return f'ss://{auth}@{server}:{port}#{name}'

    # VMess
    if ptype == 'vmess':
        vmess_json = {
            "v": "2",
            "ps": name,
            "add": proxy['server'],
            "port": str(proxy['port']),
            "id": proxy['uuid'],
            "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'),
            "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', ''),
            "path": proxy.get('ws-path', ''),
            "tls": 'tls' if proxy.get('tls', False) else ''
        }
        b64 = base64.urlsafe_b64encode(str(vmess_json).encode()).decode()
        return f'vmess://{b64}'

    # Trojan
    if ptype == 'trojan':
        server = proxy['server']
        port = proxy['port']
        password = proxy['password']
        sni = proxy.get('sni', '')
        return f'trojan://{password}@{server}:{port}?sni={sni}#{name}'

    # 其余协议暂未实现
    return ''


# ---------- 主逻辑 ----------
def 从订阅获取节点(url: str) -> List[str]:
    raw = 下载(url)
    if not raw:
        return []

    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')

    # 1. 判断是否为 Clash YAML
    if re.search(r'^proxies\s*:', text, re.MULTILINE):
        try:
            data = yaml.safe_load(text)
            proxies = data.get('proxies', [])
            nodes = [_clash_proxy_to_uri(p) for p in proxies]
            return [n for n in nodes if n]
        except Exception as e:
            print(f'[警告] 解析 Clash YAML 失败：{e}')
            return []

    # 2. Base64 URI 列表
    decoded = 解码base64(text)
    if not decoded:
        return []
    lines = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    return [ln for ln in lines if any(re.match(p, ln) for p in PROTOCOL_PATTERNS.values())]


def 主函数():
    print('[信息] 开始更新订阅...')
    subs = 读取订阅()
    if not subs:
        print('[错误] sub.txt 为空或不存在')
        sys.exit(1)

    # 检测有效性（仅用于统计，不删除）
    valid_subs, invalid_subs = [], []
    for s in subs:
        (valid_subs if 订阅是否有效(s) else invalid_subs).append(s)

    print(f'[信息] 有效订阅 {len(valid_subs)} 个，失效订阅 {len(invalid_subs)} 个')

    # 拉取节点（仅有效订阅）
    all_nodes: List[str] = []
    for sub in valid_subs:
        nodes = 从订阅获取节点(sub)
        all_nodes.extend(nodes)
        print(f'[信息] {sub} -> {len(nodes)} 个节点')

    # 去重
    all_nodes = list(dict.fromkeys(all_nodes))
    print(f'[信息] 合并去重后共 {len(all_nodes)} 个节点')
    保存节点(all_nodes)

    # 全部订阅写回（含失效）
    写回全部订阅(subs)
    print('[信息] 全部订阅已写回 sub.txt（未删除失效链接）')


if __name__ == '__main__':
    主函数()
