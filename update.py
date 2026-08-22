#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update.py
- 自动识别 Base64 / Clash YAML / 纯文本 URI
- 新增：订阅分组（有效/失效）
- 节点去重后写入 config.txt
- 新增：输出 Mihomo 兼容的 proxies.yaml，并过滤不支持的格式
- 所有文件自动创建并写入
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse
from typing import List, Optional, Dict

import requests
import yaml

# ---------- 路径 ----------
REPO_ROOT    = os.path.dirname(os.path.abspath(__file__))
SUB_FILE     = os.path.join(REPO_ROOT, 'sub.txt')
VALID_FILE   = os.path.join(REPO_ROOT, 'sub_valid.txt')
INVALID_FILE = os.path.join(REPO_ROOT, 'sub_invalid.txt')
OUT_FILE     = os.path.join(REPO_ROOT, 'config.txt')
YAML_FILE    = os.path.join(REPO_ROOT, 'proxies.yaml')   # 新增

PROTO_FILES = {                 # 协议 → 文件名
    'ss': 'ss.txt',
    'ssr': 'ssr.txt',
    'vmess': 'vmess.txt',
    'vless': 'vless.txt',
    'trojan': 'trojan.txt',
    'hysteria': 'hysteria.txt',
    'hysteria2': 'hysteria2.txt',
    'tuic': 'tuic.txt',
    'naive+https': 'naive_https.txt',
    'wireguard': 'wireguard.txt',
    'clash': 'clash.yaml'       # 完整 Clash YAML 单独保存
}
ALL_FILE = 'all.txt'           # 总节点文件

TIMEOUT = 10
MAX_RETRIES = 3
MIN_NODES_PER_SUB = 20   # 每条订阅最少节点数，低于此数视为低质量

# ---------- Mihomo 兼容性配置 ----------
# Mihomo 支持的 SS cipher（参考官方文档）
MIHOMO_SS_CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'rc4-md5', 'chacha20-ietf', 'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'none',
}

# 常见错误映射：自动修正为 Mihomo 支持的名称
CIPHER_FIX_MAP = {
    'chacha20-poly1305': 'chacha20-ietf-poly1305',
}

# ---------- 工具 ----------
def _ensure_files(*paths):
    for p in paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)

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

def _try_base64(data: str) -> str:
    data += '=' * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data.encode()).decode('utf-8')
    except Exception:
        return ''

def _clash_to_uri(proxy: dict) -> str:
    t = proxy.get('type', '').lower()
    name = urllib.parse.quote(proxy.get('name', ''))
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    if not server or not port:
        return ''
    if t == 'ss':
        cipher, pwd = proxy.get('cipher', ''), proxy.get('password', '')
        if not cipher or not pwd:
            return ''
        auth = base64.urlsafe_b64encode(f'{cipher}:{pwd}'.encode()).decode()
        return f'ss://{auth}@{server}:{port}#{name}'
    if t == 'vmess':
        vm = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": proxy.get('uuid', ''), "aid": str(proxy.get('alterId', 0)),
            "net": proxy.get('network', 'tcp'), "type": proxy.get('type', 'none'),
            "host": proxy.get('ws-headers', {}).get('Host', '') or proxy.get('ws-opts', {}).get('headers', {}).get('Host', ''),
            "path": proxy.get('ws-path', '') or proxy.get('ws-opts', {}).get('path', ''),
            "tls": 'tls' if proxy.get('tls', False) else ''
        }
        if not vm['id']:
            return ''
        b64 = base64.urlsafe_b64encode(str(vm).encode()).decode()
        return f'vmess://{b64}'
    if t == 'trojan':
        pwd = proxy.get('password', '')
        if not pwd:
            return ''
        sni = proxy.get('sni', '')
        return f'trojan://{pwd}@{server}:{port}?sni={sni}#{name}'
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
        pwd = proxy.get('password', '')
        if not uuid or not pwd:
            return ''
        return f'tuic://{uuid}:{pwd}@{server}:{port}#{name}'
    return ''

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
            except Exception:
                return []

    # 2. Base64
    decoded = _try_base64(text)
    if decoded:
        return [ln.strip() for ln in decoded.splitlines() if ln.strip()]

    # 3. 纯文本行
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


# ========== 新增：URI → Mihomo Proxy Dict ==========

def _parse_ss(uri: str) -> Optional[Dict]:
    """解析 ss URI 为 Mihomo proxy dict，过滤/修正不支持的 cipher"""
    # 手动解析，避免 urlparse 对不规范 IPv6 / 特殊字符的严格检查
    if not uri.startswith('ss://'):
        return None

    body = uri[5:]
    if body.startswith('//'):
        body = body[2:]

    # 分离 name (fragment)
    if '#' in body:
        body, name_raw = body.split('#', 1)
        name = urllib.parse.unquote(name_raw)
    else:
        name = ''

    # 去掉可能的尾部斜杠
    body = body.split('/')[0]

    if '@' not in body:
        return None

    userinfo, server_part = body.rsplit('@', 1)

    # 解析 server:port（支持 IPv6）
    if server_part.startswith('['):
        # IPv6: [::1]:8080
        if ']:' in server_part:
            server, port_str = server_part.rsplit(':', 1)
            server = server[1:-1]  # 去掉 []
        else:
            # 没有端口，如 [::1]
            server = server_part[1:-1]
            port_str = '8388'  # 默认端口
    elif ':' in server_part:
        # IPv4 或域名
        server, port_str = server_part.rsplit(':', 1)
    else:
        return None

    try:
        port = int(port_str)
    except ValueError:
        return None

    # 解析 userinfo：先尝试 Base64(method:password)，失败则尝试明文
    userinfo = urllib.parse.unquote(userinfo)
    cipher, pwd = None, None

    # 尝试 Base64
    try:
        decoded = base64.urlsafe_b64decode(userinfo + '=' * (-len(userinfo) % 4)).decode('utf-8')
        if ':' in decoded:
            cipher, pwd = decoded.split(':', 1)
    except Exception:
        pass

    # 回退到明文 method:password
    if cipher is None and ':' in userinfo:
        cipher, pwd = userinfo.split(':', 1)

    if not cipher or not pwd:
        return None

    # 自动修正常见错误 cipher
    cipher = CIPHER_FIX_MAP.get(cipher, cipher)

    # 检查 Mihomo 是否支持
    if cipher not in MIHOMO_SS_CIPHERS:
        print(f'[过滤] 不支持的 SS cipher: {cipher} | {uri[:60]}...')
        return None

    return {
        'name': name or f'ss-{server}',
        'type': 'ss',
        'server': server,
        'port': port,
        'cipher': cipher,
        'password': pwd,
    }


def _parse_ssr(uri: str) -> Optional[Dict]:
    body = uri[6:]
    if not body:
        return None
    try:
        decoded = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
    except Exception:
        return None

    if '/?' in decoded:
        main_part, params_str = decoded.split('/?', 1)
    else:
        main_part, params_str = decoded, ''

    parts = main_part.split(':')
    if len(parts) != 6:
        return None

    server, port_str, proto, method, obfs, pwd_b64 = parts
    try:
        port = int(port_str)
    except ValueError:
        return None

    try:
        password = base64.urlsafe_b64decode(pwd_b64 + '=' * (-len(pwd_b64) % 4)).decode('utf-8')
    except Exception:
        password = pwd_b64

    params = urllib.parse.parse_qs(params_str)
    remarks = ''
    if 'remarks' in params:
        try:
            remarks = base64.urlsafe_b64decode(params['remarks'][0] + '=' * (-len(params['remarks'][0]) % 4)).decode('utf-8')
        except Exception:
            remarks = params['remarks'][0]

    obfs_param = params.get('obfsparam', [''])[0]
    proto_param = params.get('protoparam', [''])[0]

    method = CIPHER_FIX_MAP.get(method, method)
    if method not in MIHOMO_SS_CIPHERS:
        print(f'[过滤] 不支持的 SSR method: {method} | {uri[:60]}...')
        return None

    node = {
        'name': remarks or f'ssr-{server}',
        'type': 'ssr',
        'server': server,
        'port': port,
        'cipher': method,
        'password': password,
        'protocol': proto,
        'protocol-param': proto_param,
        'obfs': obfs,
        'obfs-param': obfs_param,
    }
    return {k: v for k, v in node.items() if v}


def _parse_vmess(uri: str) -> Optional[Dict]:
    body = uri[8:]
    if not body:
        return None
    try:
        decoded = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
        data = json.loads(decoded)
    except Exception:
        return None

    name = data.get('ps', '') or data.get('remark', '') or f"vmess-{data.get('add', '')}"

    node = {
        'name': name,
        'type': 'vmess',
        'server': data.get('add', ''),
        'port': int(data.get('port', 0)),
        'uuid': data.get('id', ''),
        'alterId': int(data.get('aid', 0)),
        'cipher': 'auto',
    }

    if not node['server'] or not node['port'] or not node['uuid']:
        return None

    if data.get('tls') in ('tls', True, 1):
        node['tls'] = True
        node['servername'] = data.get('sni', '') or data.get('host', '')

    net = data.get('net', 'tcp')
    if net == 'ws':
        node['network'] = 'ws'
        node['ws-opts'] = {}
        if data.get('host'):
            node['ws-opts']['headers'] = {'Host': data.get('host')}
        if data.get('path'):
            node['ws-opts']['path'] = data.get('path')
    elif net == 'h2':
        node['network'] = 'h2'
    elif net == 'grpc':
        node['network'] = 'grpc'
        node['grpc-opts'] = {'grpc-service-name': data.get('path', '')}
    elif net in ('kcp', 'mkcp'):
        print(f'[过滤] Mihomo 不支持 vmess+mkcp: {name}')
        return None

    return node


def _parse_vless(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    uuid = parsed.username

    if not server or not port or not uuid:
        return None

    qs = urllib.parse.parse_qs(parsed.query)

    node = {
        'name': name or f'vless-{server}',
        'type': 'vless',
        'server': server,
        'port': port,
        'uuid': uuid,
    }

    sec = qs.get('security', [''])[0]
    if sec in ('tls', 'xtls', 'reality'):
        node['tls'] = True
        if qs.get('sni'):
            node['servername'] = qs['sni'][0]
        if sec == 'reality':
            node['client-fingerprint'] = qs.get('fp', ['chrome'])[0]

    if qs.get('flow', [''])[0]:
        node['flow'] = qs.get('flow')[0]

    net = qs.get('type', ['tcp'])[0]
    if net == 'ws':
        node['network'] = 'ws'
        node['ws-opts'] = {}
        if qs.get('host'):
            node['ws-opts']['headers'] = {'Host': qs['host'][0]}
        if qs.get('path'):
            node['ws-opts']['path'] = qs['path'][0]
    elif net == 'grpc':
        node['network'] = 'grpc'
        node['grpc-opts'] = {'grpc-service-name': qs.get('serviceName', [''])[0]}
    elif net == 'h2':
        node['network'] = 'h2'

    return node


def _parse_trojan(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    pwd = urllib.parse.unquote(parsed.username) if parsed.username else ''

    if not server or not port or not pwd:
        return None

    qs = urllib.parse.parse_qs(parsed.query)

    node = {
        'name': name or f'trojan-{server}',
        'type': 'trojan',
        'server': server,
        'port': port,
        'password': pwd,
    }

    if qs.get('sni'):
        node['sni'] = qs['sni'][0]
    if qs.get('allowInsecure', [''])[0] == '1':
        node['skip-cert-verify'] = True

    return node


def _parse_hysteria(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    auth = urllib.parse.unquote(parsed.username) if parsed.username else ''

    if not server or not port or not auth:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    node = {
        'name': name or f'hysteria-{server}',
        'type': 'hysteria',
        'server': server,
        'port': port,
        'auth_str': auth,
    }
    if qs.get('peer'):
        node['sni'] = qs['peer'][0]
    if qs.get('alpn'):
        node['alpn'] = qs['alpn'][0].split(',')
    return node


def _parse_hysteria2(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    auth = urllib.parse.unquote(parsed.username) if parsed.username else ''

    if not server or not port:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    node = {
        'name': name or f'hysteria2-{server}',
        'type': 'hysteria2',
        'server': server,
        'port': port,
    }
    if auth:
        node['password'] = auth
    if qs.get('sni'):
        node['sni'] = qs['sni'][0]
    return node


def _parse_tuic(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    uuid = parsed.username
    pwd = parsed.password

    if not server or not port or not uuid or not pwd:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    node = {
        'name': name or f'tuic-{server}',
        'type': 'tuic',
        'server': server,
        'port': port,
        'uuid': uuid,
        'password': urllib.parse.unquote(pwd),
    }
    if qs.get('sni'):
        node['sni'] = qs['sni'][0]
    return node


def _parse_wireguard(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(uri)
    except ValueError:
        return None
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
    server = parsed.hostname
    port = parsed.port
    private_key = parsed.username

    if not server or not port or not private_key:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    node = {
        'name': name or f'wg-{server}',
        'type': 'wireguard',
        'server': server,
        'port': port,
        'private-key': private_key,
    }
    if qs.get('publickey'):
        node['public-key'] = qs['publickey'][0]
    if qs.get('address'):
        node['ip'] = qs['address'][0]
    return node


def uri_to_mihomo(uri: str) -> Optional[Dict]:
    """把 URI 转成 Mihomo 兼容的 proxy dict，不支持的返回 None"""
    if not uri:
        return None

    # 修复：urlparse 遇到不规范 IPv6 会抛异常，需要捕获
    try:
        parsed = urllib.parse.urlparse(uri)
        scheme = parsed.scheme.lower()
    except ValueError as e:
        print(f'[过滤] URL 解析失败: {e} | {uri[:80]}...')
        return None

    handlers = {
        'ss': _parse_ss,
        'ssr': _parse_ssr,
        'vmess': _parse_vmess,
        'vless': _parse_vless,
        'trojan': _parse_trojan,
        'hysteria': _parse_hysteria,
        'hysteria2': _parse_hysteria2,
        'tuic': _parse_tuic,
        'wireguard': _parse_wireguard,
    }

    handler = handlers.get(scheme)
    if not handler:
        return None

    try:
        return handler(uri)
    except Exception as e:
        print(f'[解析错误] {scheme}: {e} | {uri[:60]}...')
        return None


# ========== 主程序 ==========

def main():
    # 确保目录存在
    for p in (SUB_FILE, VALID_FILE, INVALID_FILE, OUT_FILE, YAML_FILE, *PROTO_FILES.values()):
        os.makedirs(os.path.dirname(os.path.join(REPO_ROOT, p)), exist_ok=True)

    # 读取订阅
    try:
        links = [ln.strip() for ln in open(SUB_FILE, encoding='utf-8') if ln.strip()]
    except FileNotFoundError:
        links = []

    if not links:
        print('[提示] sub.txt 为空，请添加订阅后重试')
        sys.exit(0)

    # 检测有效性
    valid, invalid = [], []
    for url in links:
        (valid if len(提取节点(下载(url))) > 0 else invalid).append(url)

    # 写分组文件
    with open(VALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 有效订阅（共 {len(valid)} 条）\n' + '\n'.join(valid) + '\n')
    with open(INVALID_FILE, 'w', encoding='utf-8') as f:
        f.write(f'# 失效订阅（共 {len(invalid)} 条）\n' + '\n'.join(invalid) + '\n')

    print(f'[分组] 有效 {len(valid)} 条')
    print(f'[分组] 失效 {len(invalid)} 条')

    # 协议桶
    protocol_nodes = {proto: [] for proto in PROTO_FILES}
    all_nodes = []

    # 拉取并分类
    for url in valid:
        raw = 下载(url)
        tmp_nodes = 提取节点(raw)
        all_nodes.extend(tmp_nodes)

        for node in tmp_nodes:
            if node.startswith('ss://'):
                protocol_nodes['ss'].append(node)
            elif node.startswith('ssr://'):
                protocol_nodes['ssr'].append(node)
            elif node.startswith('vmess://'):
                protocol_nodes['vmess'].append(node)
            elif node.startswith('vless://'):
                protocol_nodes['vless'].append(node)
            elif node.startswith('trojan://'):
                protocol_nodes['trojan'].append(node)
            elif node.startswith('hysteria://'):
                protocol_nodes['hysteria'].append(node)
            elif node.startswith('hysteria2://'):
                protocol_nodes['hysteria2'].append(node)
            elif node.startswith('tuic://'):
                protocol_nodes['tuic'].append(node)
            elif node.startswith('naive+https://'):
                protocol_nodes['naive+https'].append(node)
            elif node.startswith('wireguard://'):
                protocol_nodes['wireguard'].append(node)

    # 去重（保序）
    for proto in protocol_nodes:
        protocol_nodes[proto] = list(dict.fromkeys(protocol_nodes[proto]))

    all_nodes = list(dict.fromkeys(all_nodes))

    # 写入各协议文件
    for proto, filename in PROTO_FILES.items():
        with open(os.path.join(REPO_ROOT, filename), 'w', encoding='utf-8') as f:
            f.write('\n'.join(protocol_nodes[proto]) + '\n')
        print(f'[写入] {filename} : {len(protocol_nodes[proto])} 条')

    # 总节点
    with open(os.path.join(REPO_ROOT, ALL_FILE), 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_nodes) + '\n')
    print(f'[完成] {ALL_FILE} : {len(all_nodes)} 条')

    # ========== 新增：生成 Mihomo 兼容的 proxies.yaml ==========
    print('\n[YAML] 开始转换并过滤 Mihomo 不兼容节点...')
    mihomo_proxies = []
    filtered_count = 0

    for node in all_nodes:
        proxy = uri_to_mihomo(node)
        if proxy:
            mihomo_proxies.append(proxy)
        else:
            filtered_count += 1

    # 按 name+server+port+type 去重
    seen = set()
    unique_proxies = []
    for p in mihomo_proxies:
        key = (p.get('name', ''), p.get('server', ''), p.get('port', 0), p.get('type', ''))
        if key not in seen:
            seen.add(key)
            unique_proxies.append(p)

    # 写入 YAML
    yaml_content = yaml.safe_dump(
        {'proxies': unique_proxies},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False
    )
    with open(YAML_FILE, 'w', encoding='utf-8') as f:
        f.write(yaml_content)

    print(f'[YAML] 原始节点: {len(all_nodes)}')
    print(f'[YAML] 过滤掉: {filtered_count} 条')
    print(f'[YAML] 有效写入: {len(unique_proxies)} 条 → {YAML_FILE}')

    # ========== 新增：节点分组（每300个一组）==========
    print('[分组] 开始按 300 节点/组拆分...')
    GROUP_SIZE = 300
    group_count = (len(unique_proxies) + GROUP_SIZE - 1) // GROUP_SIZE

    for i in range(group_count):
        start = i * GROUP_SIZE
        end = start + GROUP_SIZE
        group_proxies = unique_proxies[start:end]
        group_file = os.path.join(REPO_ROOT, f'proxies_{i+1}.yaml')
        group_yaml = yaml.safe_dump(
            {'proxies': group_proxies},
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False
        )
        with open(group_file, 'w', encoding='utf-8') as f:
            f.write(group_yaml)
        print(f'[分组] proxies_{i+1}.yaml : {len(group_proxies)} 条')

    print(f'[分组] 共 {group_count} 组，保留完整版: {YAML_FILE}')


if __name__ == '__main__':
    main()
