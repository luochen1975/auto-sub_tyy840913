#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
订阅去重、有效性检测、节点拉取、协议支持、节点去重并写入 config.txt
所有提示信息及注释均为中文
"""
import base64
import os
import re
import sys
import time
from typing import List

import requests
import yaml

# ---------- 配置 ----------
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SUB_FILE = os.path.join(REPO_ROOT, 'sub.txt')
OUT_FILE = os.path.join(REPO_ROOT, 'config.txt')

# 支持的协议（≥10 种）
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
def 下载(url: str) -> bytes:
    """带重试并自动处理 gzip / deflate 的下载"""
    headers = {'User-Agent': 'Mozilla/5.0'}
    for i in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            print(f'[警告] 下载失败：{url}，原因：{e}，重试 {i+1}/{MAX_RETRIES}')
            time.sleep(2)
    return b''


def 解码base64(data: str) -> str:
    """自动补全等号并解码 base64，失败返回空字符串"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(data.encode()).decode('utf-8')
    except Exception:
        return ''


def 订阅是否有效(url: str) -> bool:
    """判断订阅链接能否返回节点文本"""
    raw = 下载(url)
    if not raw:
        return False
    # 先尝试 UTF-8，失败则用 latin-1 兜底
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')
    return bool(解码base64(text).strip())


def 从订阅获取节点(url: str) -> List[str]:
    """解析订阅返回的节点列表"""
    raw = 下载(url)
    if not raw:
        return []
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = raw.decode('latin-1')

    decoded = 解码base64(text)
    if not decoded:
        return []

    nodes = [line.strip() for line in decoded.splitlines() if line.strip()]
    # 过滤支持的协议
    return [n for n in nodes if any(re.match(p, n) for p in PROTOCOL_PATTERNS.values())]


def 读取现有订阅() -> List[str]:
    """读取 sub.txt 中的订阅链接"""
    if not os.path.exists(SUB_FILE):
        return []
    with open(SUB_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def 保存订阅链接(links: List[str]):
    """将有效订阅写回 sub.txt"""
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(links))) + '\n')


def 保存节点(nodes: List[str]):
    """将节点写入 config.txt"""
    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(nodes))) + '\n')


# ---------- 主逻辑 ----------
def 主函数():
    print('[信息] 开始更新订阅...')
    subs = 读取现有订阅()
    if not subs:
        print('[错误] sub.txt 为空或不存在')
        sys.exit(1)

    # 去重并保持顺序
    subs = list(dict.fromkeys(subs))
    print(f'[信息] 总计 {len(subs)} 个订阅')

    # 过滤有效订阅
    valid_subs = [s for s in subs if 订阅是否有效(s)]
    print(f'[信息] 有效订阅 {len(valid_subs)} 个')

    # 保存有效订阅
    保存订阅链接(valid_subs)

    # 拉取节点
    all_nodes = []
    for sub in valid_subs:
        nodes = 从订阅获取节点(sub)
        all_nodes.extend(nodes)
        print(f'[信息] {sub} -> {len(nodes)} 个节点')

    # 去重
    all_nodes = list(dict.fromkeys(all_nodes))
    print(f'[信息] 合并去重后共 {len(all_nodes)} 个节点')

    # 保存
    保存节点(all_nodes)
    print('[信息] 已写入 config.txt')


if __name__ == '__main__':
    主函数()
