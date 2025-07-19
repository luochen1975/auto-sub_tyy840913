#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
- 自动识别 Base64 / Clash YAML / 纯文本 URI
- 新增：订阅链接分组（有效/失效）
- 节点去重后写入 config.txt
- 所有文件自动创建
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

# ---------- 路径常量 ----------
REPO_ROOT    = os.path.dirname(os.path.abspath(__file__))
SUB_FILE     = os.path.join(REPO_ROOT, 'sub.txt')
VALID_FILE   = os.path.join(REPO_ROOT, 'sub_valid.txt')
INVALID_FILE = os.path.join(REPO_ROOT, 'sub_invalid.txt')
OUT_FILE     = os.path.join(REPO_ROOT, 'config.txt')

TIMEOUT = 10
MAX_RETRIES = 3

# ---------- 自动创建空文件 ----------
def _确保文件(*paths):
    for p in paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if not os.path.exists(p):
            open(p, 'a', encoding='utf-8').close()

_确保_file(SUB_FILE, VALID_FILE, INVALID_FILE, OUT_FILE)

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

# ---------- 提取节点 ----------
def 提取节点(raw: bytes) -> List[str]:
    if not raw:
        return []
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')

    # 1. Clash YAML
    for key in ('proxies', 'Proxy', 'proxy-providers'):
        if re.search(rf'^{key}\s*:', text, flags=re.MULTILINE | re.IGNORECASE):
            try:
                data = yaml.safe_load(text)
                proxies = data.get(key, []) if key != 'proxy-providers' else \
                          [p for v in data.get(key, {}).values() for p in v.get('proxies', [])]
                return [_clash_to_uri(p) for p in proxies if _clash_to_uri(p)]
            except Exception as e:
                print(f'[警告] YAML 解析失败：{e}')
                return []

    # 2. Base64
    decoded = _try_base64(text)
    if decoded:
        return [ln.strip() for ln in decoded.splitlines() if ln.strip()]

    # 3. 纯文本行
    return [ln.strip() for ln in text.splitlines() if ln.strip()]

# ---------- Clash → URI ----------
def _clash_to_uri(proxy: dict) -> str:
    t = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', ''))
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    if not server or not port:
        return ''

    if t == 'ss':
        cipher = proxy.get('cipher', '')
        password = proxy.get('password', '')
        if not cipher or not password:
            return ''
        auth = base64.urlsafe_b64encode(f'{cipher}:{password}'.encode()).decode()
        return f'ss://{auth}@{server}:{port}#{name}'

    if t == 'vmess':
        vmess = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": proxy.get('uuid', ''), "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'), "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('ws-opts', {}).get('headers', {}).get('Host', ''),
            "path": proxy.get('ws-path', '') or proxy.get('ws-opts', {}).get('path', ''),
            "tls": 'tls' if proxy.get('tls', False) else ''
        }
        if not vmess['id']:
            return ''
        b64 = base64.urlsafe_b64encode(str(vmess).encode()).decode()
        return f'vmess://{b64}'

    if t == 'trojan':
        password = proxy.get('password', '')
        if not password:
            return ''
        sni = proxy.get('sni', '')
        return f'trojan://{password}@{server}:{port}?sni={sni}#{name}'

    if t == 'vless':
        uuid = proxy.get('uuid', '')
        if not uuid:
            return ''
        net = proxy.get('network', 'tcp')
        tls = 'tls' if proxy.get('tls', False) else ''
        host = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
        path = proxy.get('ws-opts', {}).get('path', '')
        return f'vless://{uuid}@{server}:{port}?type={net}&security={tls}&host={host}&path={path}#{name}'

    if t in ('hysteria', 'hysteria2'):
        auth = proxy.get('auth', proxy.get('password', ''))
        if not auth:
            return ''
        alpn = ','.join(proxy.get('alpn', []))
        return f'{t}://{auth}@{server}:{port}?alpn={alpn}#{name}'

    if t == 'tuic':
        uuid = proxy.get('uuid', '')
        password = proxy.get('password', '')
        if not uuid or not password:
            return ''
        return f'tuic://{uuid}:{password}@{server}:{port}#{name}'

    return ''


def _try_base64(data: str) -> str:
    try:
        data += '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data.encode()).decode('utf-8')
    except Exception:
        return ''


def 读取链接() -> List[str]:
    with open(SUB_FILE, encoding='utf-8') as f:
        return [ln.strip() for ln in f if ln.strip()]


def 写回全部(links: List[str]):
    seen = {}
    dedup = [seen.setdefault(x, x) for x in links if x not in seen]
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(dedup) + '\n')


def 保存节点(nodes: List[str]):
    # 写入前确保目录存在
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(nodes) + '\n')


# ---------- 主 ----------
def main():
    links = 读取链接()
    if not links:
        print('[提示] sub.txt 为空，请添加订阅链接后重试')
        sys.exit(0)

    # 1. 检测有效 / 失效
    valid, invalid = [], []
    for url in links:
        (valid if len(提取节点(下载(url))) > 0 else invalid).append(url)

    # 2. 写分组文件
    with open(VALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 有效订阅（共 {len(valid)} 条）\n')
        f.write('\n'.join(valid) + '\n')

    with open(INVALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 失效订阅（共 {len(invalid)} 条）\n')
        f.write('\n'.join(invalid) + '\n')

    print(f'[信息] 有效 {len(valid)} 条 → {VALID_FILE}')
    print(f'[信息] 失效 {len(invalid)} 条 → {INVALID_FILE}')

    # 3. 拉取节点（仅有效订阅）
    nodes: List[str] = []
    for url in valid:
        raw = 下载(url)
        tmp = 提取节点(raw)
        nodes.extend(tmp)
        print(f'[信息] {url} → {len(tmp)} 个节点')

    # 4. 去重并写文件
    nodes = list(dict.fromkeys(nodes))
    保存节点(nodes)
    print(f'[完成] 共 {len(nodes)} 个节点 已写入 {OUT_FILE}')


if __name__ == '__main__':
    main()
