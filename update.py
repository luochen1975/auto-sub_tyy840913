#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
- 自动识别 Base64、Clash YAML、纯文本 URI
- 不再按协议过滤，全部保留
- 不删除失效订阅
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

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SUB_FILE = os.path.join(REPO_ROOT, 'sub.txt')
OUT_FILE = os.path.join(REPO_ROOT, 'config.txt')

TIMEOUT = 10
MAX_RETRIES = 3


# ---------- 下载 ----------
def 下载(url: str) -> bytes:
    headers = {'User-Agent': 'Mozilla/5.0'}
    for i in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            print(f'[警告] 下载失败：{url}  {e}')
            time.sleep(2)
    return b''


# ---------- 节点提取 ----------
def 提取节点(raw: bytes) -> List[str]:
    if not raw:
        return []

    # 1. 解码
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')

    # 2. 先按 Clash YAML 解析
    if re.search(r'^proxies\s*:', text, re.MULTILINE):
        try:
            data = yaml.safe_load(text)
            proxies = data.get('proxies', [])
            nodes = [_clash_to_uri(p) for p in proxies]
            return [n for n in nodes if n]
        except Exception as e:
            print('[警告] YAML 解析失败', e)

    # 3. 再按 Base64 解析
    decoded = _try_base64(text)
    if decoded:
        return [ln for ln in decoded.splitlines() if ln.strip()]

    # 4. 直接按纯文本行处理（兜底）
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


# ---------- 工具 ----------
def _try_base64(data: str) -> str:
    """尝试 Base64 解码"""
    try:
        # 补 =
        missing = len(data) % 4
        if missing:
            data += '=' * (4 - missing)
        decoded = base64.urlsafe_b64decode(data.encode()).decode('utf-8')
        return decoded
    except Exception:
        return ''


def _clash_to_uri(proxy: dict) -> str:
    """Clash 节点 → URI"""
    t = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', ''))

    # SS
    if t == 'ss':
        cipher, pwd, server, port = proxy['cipher'], proxy['password'], proxy['server'], proxy['port']
        auth = base64.urlsafe_b64encode(f'{cipher}:{pwd}'.encode()).decode()
        return f'ss://{auth}@{server}:{port}#{name}'

    # VMess
    if t == 'vmess':
        vm = {
            "v": "2", "ps": name, "add": proxy['server'], "port": str(proxy['port']),
            "id": proxy['uuid'], "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'), "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', ''),
            "path": proxy.get('ws-path', ''),
            "tls": 'tls' if proxy.get('tls', False) else ''
        }
        return f"vmess://{base64.urlsafe_b64encode(str(vm).encode()).decode()}"

    # Trojan
    if t == 'trojan':
        return f"trojan://{proxy['password']}@{proxy['server']}:{proxy['port']}?sni={proxy.get('sni', '')}#{name}"

    # 其余协议可自行扩展
    return ''


# ---------- 文件读写 ----------
def 读取链接() -> List[str]:
    if not os.path.exists(SUB_FILE):
        return []
    with open(SUB_FILE, encoding='utf-8') as f:
        return [ln.strip() for ln in f if ln.strip()]


def 写回全部(links: List[str]):
    seen = {}
    dedup = [seen.setdefault(x, x) for x in links if x not in seen]
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(dedup) + '\n')


def 保存节点(nodes: List[str]):
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(nodes) + '\n')


# ---------- 主 ----------
def main():
    links = 读取链接()
    if not links:
        print('[错误] sub.txt 为空')
        sys.exit(1)

    nodes: List[str] = []
    for url in links:
        raw = 下载(url)
        tmp = 提取节点(raw)
        nodes.extend(tmp)
        print(f'[信息] {url} -> {len(tmp)} 个节点')

    # 去重并保持顺序
    seen = {}
    nodes = [seen.setdefault(x, x) for x in nodes if x not in seen]

    保存节点(nodes)
    写回全部(links)
    print(f'[完成] 共 {len(nodes)} 个节点 已写入 config.txt')


if __name__ == '__main__':
    main()
