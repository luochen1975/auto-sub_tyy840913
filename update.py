#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
1. 读取 sub.txt 全部订阅（不去除失效）
2. 检测每条订阅是否有效
3. 控制台分别输出有效/无效数量
4. 仍去重、拉取节点、写入 config.txt
5. 最后把**全部**订阅（含失效）原样写回 sub.txt
"""
import base64
import os
import re
import sys
import time
from typing import List, Tuple

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
    return bool(解码base64(text).strip())


def 读取订阅() -> List[str]:
    if not os.path.exists(SUB_FILE):
        return []
    with open(SUB_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def 写回全部订阅(links: List[str]):
    """把全部链接（含失效）去重后写回，保持原顺序"""
    seen = set()
    dedup = [l for l in links if not (l in seen or seen.add(l))]
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(dedup) + '\n')


def 保存节点(nodes: List[str]):
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(nodes))) + '\n')


# ---------- 主逻辑 ----------
def 主函数():
    print('[信息] 开始更新订阅...')
    subs = 读取订阅()
    if not subs:
        print('[错误] sub.txt 为空或不存在')
        sys.exit(1)

    # 检测有效性
    valid_subs, invalid_subs = [], []
    for s in subs:
        (valid_subs if 订阅是否有效(s) else invalid_subs).append(s)

    print(f'[信息] 有效订阅 {len(valid_subs)} 个，失效订阅 {len(invalid_subs)} 个')

    # 1. 从有效订阅拉节点
    all_nodes: List[str] = []
    for sub in valid_subs:
        raw = 下载(sub)
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = raw.decode('latin-1')

        decoded = 解码base64(text)
        nodes = [ln.strip() for ln in decoded.splitlines() if ln.strip()]
        nodes = [n for n in nodes if any(re.match(p, n) for p in PROTOCOL_PATTERNS.values())]
        all_nodes.extend(nodes)
        print(f'[信息] {sub} -> {len(nodes)} 个节点')

    # 2. 节点去重
    all_nodes = list(dict.fromkeys(all_nodes))
    print(f'[信息] 合并去重后共 {len(all_nodes)} 个节点')
    保存节点(all_nodes)

    # 3. 把全部订阅（含失效）写回
    写回全部订阅(subs)
    print('[信息] 全部订阅已写回 sub.txt（未删除失效链接）')


if __name__ == '__main__':
    主函数()
