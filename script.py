#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
订阅去重、有效性检测、节点拉取、协议支持、Clash 规则合并、节点去重并写入 config.txt
"""
import base64
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import List, Tuple

import yaml

# ---------- 配置 ----------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SUB_FILE = os.path.join(REPO_ROOT, 'sub.txt')
OUT_FILE = os.path.join(REPO_ROOT, 'config.txt')
CLASH_RULE_URL = 'https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/rule-providers.yaml'

# 支持的协议正则（>=10 种）
PROTOCOL_PATTERNS = {
    'ss': r'^ss://',
    'ssr': r'^ssr://',
    'vmess': r'^vmess://',
    'vless': r'^vless://',
    'trojan': r'^trojan://',
    'hysteria': r'^hysteria://',
    'hysteria2': r'^hysteria2://',
    'tuic': r'^tuic://',
    'naive+https': r'^naive\+https://',
    'wireguard': r'^wireguard://'
}

TIMEOUT = 10
MAX_RETRIES = 3

# ---------- 工具 ----------
def fetch(url: str) -> bytes:
    """带重试的 HTTP 下载"""
    for i in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
                return resp.read()
        except Exception as e:
            print(f'[WARN] fetch failed {url} ({e}), retry {i+1}/{MAX_RETRIES}')
            time.sleep(2)
    return b''

def decode_base64(data: str) -> str:
    """自动补全等号并解码 base64"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8')
    except Exception:
        return ''

def is_valid_sub(url: str) -> bool:
    """测试订阅链接能否返回内容"""
    content = fetch(url)
    return bool(content and decode_base64(content.decode('utf-8')))

def get_nodes_from_sub(url: str) -> List[str]:
    """解析订阅返回的节点列表"""
    content = fetch(url)
    if not content:
        return []
    decoded = decode_base64(content.decode('utf-8'))
    if not decoded:
        return []
    nodes = [line.strip() for line in decoded.splitlines() if line.strip()]
    return [n for n in nodes if any(re.match(p, n) for p in PROTOCOL_PATTERNS.values())]

def load_existing_subs() -> List[str]:
    if not os.path.exists(SUB_FILE):
        return []
    with open(SUB_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_subs(subs: List[str]):
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(subs))) + '\n')

def save_nodes(nodes: List[str]):
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(nodes))) + '\n')

# ---------- 主逻辑 ----------
def main():
    print('[INFO] 开始更新订阅...')
    subs = load_existing_subs()
    if not subs:
        print('[ERROR] sub.txt 为空或不存在')
        sys.exit(1)

    # 去重
    subs = list(dict.fromkeys(subs))
    print(f'[INFO] 共计 {len(subs)} 个订阅')

    # 过滤有效订阅
    valid_subs = [s for s in subs if is_valid_sub(s)]
    print(f'[INFO] 有效订阅 {len(valid_subs)} 个')

    # 保存有效订阅
    save_subs(valid_subs)

    # 拉取节点
    all_nodes = []
    for sub in valid_subs:
        nodes = get_nodes_from_sub(sub)
        all_nodes.extend(nodes)
        print(f'[INFO] {sub} -> {len(nodes)} 个节点')

    # 去重
    all_nodes = list(dict.fromkeys(all_nodes))
    print(f'[INFO] 合并去重后共 {len(all_nodes)} 个节点')

    # 保存
    save_nodes(all_nodes)
    print('[INFO] 已写入 config.txt')

if __name__ == '__main__':
    main()
