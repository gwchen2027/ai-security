#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI漏洞防护与扫毒应用
功能：AI安全扫描 + 文件病毒扫描 + Web界面
"""

import os
import re
import json
import hashlib
import logging
import mimetypes
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, flash, redirect, url_for
from flask_cors import CORS
import watchdog.events
import watchdog.observers

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)
app.secret_key = 'ai-security-scanner-2026'

# ===================== 配置 =====================
BASE_DIR = Path(__file__).parent
SCAN_DIR = BASE_DIR / 'scanned_files'
QUARANTINE_DIR = BASE_DIR / 'quarantine'
LOG_FILE = BASE_DIR / 'security_log.json'

# 创建必要目录
SCAN_DIR.mkdir(exist_ok=True)
QUARANTINE_DIR.mkdir(exist_ok=True)

# ===================== AI漏洞检测规则 =====================
AI_VULN_RULES = {
    'prompt_injection': {
        'name': 'Prompt注入攻击',
        'patterns': [
            r'ignore\s+(all\s+)?previous\s+instructions',
            r'forget\s+(all\s+)?(previous|above|prior)',
            r'act\s+as\s+(if\s+)?(you\s+are\s+)?(a[n]?\s+)?(?!assistant)',
            r'you\s+are\s+(now\s+)?(a[n]?\s+)?(?!assistant)(developer|hacker|admin|root)',
            r'jailbreak',
            r'DAN\s+mode',
            r'system\s*:\s*you\s+are',
            r'###\s*instruction',
            r'role\s*:\s*system',
        ],
        'severity': 'HIGH',
        'description': '检测到可能的Prompt注入攻击，试图绕过AI安全限制'
    },
    'data_leakage': {
        'name': '数据泄露风险',
        'patterns': [
            r'(api[_-]?key|apikey)\s*[:=]\s*[\w\-]+',
            r'(secret|token|password|pwd)\s*[:=]\s*[\w\-]+',
            r'sk-[a-zA-Z0-9]{32,}',  # OpenAI API key pattern
            r'(AWS|aws|AKIA)[0-9A-Z]{16}',
            r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}',
            r'\b[\w\.\-]+@[\w\.\-]+\.\w{2,}\b.*(password|pass|pwd)',
        ],
        'severity': 'CRITICAL',
        'description': '检测到可能的敏感信息泄露（API密钥、密码、Token等）'
    },
    'model_extraction': {
        'name': '模型提取攻击',
        'patterns': [
            r'(repeat|output)\s+(the\s+)?(above|previous)\s+(text|content|response)',
            r'show\s+me\s+(your\s+)?(system\s+)?(prompt|instruction)',
            r'what\s+(were\s+)?(your\s+)?(initial\s+)?(prompt|instruction)',
            r'(dump|extract|print)\s+(all\s+)?(training|data|weights)',
        ],
        'severity': 'HIGH',
        'description': '检测到可能的模型提取攻击，试图获取模型内部信息'
    },
    'malicious_code': {
        'name': '恶意代码注入',
        'patterns': [
            r'exec\s*\(',
            r'eval\s*\(',
            r'os\.system\(',
            r'subprocess\.',
            r'__import__\s*\(',
            r'compile\s*\(',
            r'base64\.b64decode\(',
            r'curl\s+-[oO]|wget\s+http',
        ],
        'severity': 'CRITICAL',
        'description': '检测到可能的恶意代码注入，试图执行系统命令'
    },
    'suspicious_urls': {
        'name': '可疑URL/链接',
        'patterns': [
            r'https?://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s]*)?',
        ],
        'severity': 'MEDIUM',
        'description': '检测到URL链接，请确认来源可信'
    }
}

# ===================== 病毒特征库（简化版） =====================
VIRUS_SIGNATURES = {
    # 常见恶意文件特征（Magic Bytes + 特征串）
    'trojan_js': {
        'name': 'Trojan.JS.Generic',
        'patterns': [b'<script', b'eval(', b'fromCharCode', b'document.write'],
        'extensions': ['.js', '.html', '.htm'],
        'severity': 'HIGH'
    },
    'virus_vbs': {
        'name': 'Virus.VBS.Generic',
        'patterns': [b'CreateObject', b'WScript.Shell', b'Execute', b'ReDim'],
        'extensions': ['.vbs', '.vbe'],
        'severity': 'HIGH'
    },
    'worm_script': {
        'name': 'Worm.Script.Generic',
        'patterns': [b'FileSystemObject', b'GetSpecialFolder', b'CopyFile', b'CreateFolder'],
        'extensions': ['.vbs', '.js', '.bat', '.cmd'],
        'severity': 'MEDIUM'
    },
    'ransomware_marker': {
        'name': 'Ransomware.Generic',
        'patterns': [b'.encrypted', b'.locked', b'README_DECRYPT', b'PAY_BITCOIN'],
        'extensions': ['.txt', '.html', '.lnk'],
        'severity': 'CRITICAL'
    },
    'phishing_html': {
        'name': 'Phishing.HTML',
        'patterns': [b'password', b'login', b'<form', b'action=', b'<input type="password"'],
        'extensions': ['.html', '.htm', '.php'],
        'severity': 'HIGH'
    }
}

# ===================== 工具函数 =====================
def calculate_hash(data):
    """计算文件哈希"""
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    return hashlib.sha256(str(data).encode()).hexdigest()

def scan_ai_vulnerabilities(text, filename=''):
    """扫描AI漏洞"""
    results = []
    if not text:
        return results
    
    # 检测文本类型
    text_lower = text.lower()
    
    for rule_id, rule in AI_VULN_RULES.items():
        for pattern in rule['patterns']:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                results.append({
                    'type': 'ai_vulnerability',
                    'rule_id': rule_id,
                    'name': rule['name'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'match': match.group()[:200],
                    'position': match.start(),
                    'filename': filename
                })
    
    return results

def scan_file_virus(file_path):
    """扫描文件病毒"""
    results = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # 计算文件哈希
        file_hash = calculate_hash(content)
        ext = Path(file_path).suffix.lower()
        
        # 检查文件大小（过大文件跳过二进制扫描）
        file_size = len(content)
        if file_size > 50 * 1024 * 1024:  # 50MB
            results.append({
                'type': 'file_info',
                'name': '文件过大',
                'severity': 'INFO',
                'description': f'文件大小 {file_size // (1024*1024)}MB，跳过完整二进制扫描',
                'hash': file_hash,
                'size': file_size
            })
            return results
        
        # 检查病毒特征
        for sig_id, sig in VIRUS_SIGNATURES.items():
            # 检查扩展名
            if ext in sig['extensions'] or True:  # 对所有文件检查
                for pattern in sig['patterns']:
                    if pattern in content:
                        results.append({
                            'type': 'virus',
                            'sig_id': sig_id,
                            'name': sig['name'],
                            'severity': sig['severity'],
                            'description': f'检测到疑似{sig["name"]}特征',
                            'hash': file_hash,
                            'size': file_size
                        })
                        break
        
        # 如果没有检测到病毒
        if not any(r['type'] == 'virus' for r in results):
            results.append({
                'type': 'clean',
                'name': '未检测到威胁',
                'severity': 'INFO',
                'description': '文件扫描完成，未发现已知威胁',
                'hash': file_hash,
                'size': file_size
            })
        
    except Exception as e:
        logger.error(f"扫描文件 {file_path} 出错: {e}")
        results.append({
            'type': 'error',
            'name': '扫描错误',
            'severity': 'ERROR',
            'description': str(e)
        })
    
    return results

def save_security_log(records):
    """保存安全日志"""
    try:
        logs = []
        if LOG_FILE.exists():
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        
        for record in records:
            record['timestamp'] = datetime.now().isoformat()
            logs.append(record)
        
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs[-1000:], f, ensure_ascii=False, indent=2)  # 保留最近1000条
    except Exception as e:
        logger.error(f"保存日志失败: {e}")

# ===================== 路由 =====================
@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/api/scan/text', methods=['POST'])
def scan_text():
    """扫描文本内容"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        filename = data.get('filename', 'untitled')
        
        if not text:
            return jsonify({'error': '请输入要扫描的文本'}), 400
        
        # AI漏洞扫描
        ai_results = scan_ai_vulnerabilities(text, filename)
        
        # 统计结果
        summary = {
            'total': len(ai_results),
            'critical': len([r for r in ai_results if r['severity'] == 'CRITICAL']),
            'high': len([r for r in ai_results if r['severity'] == 'HIGH']),
            'medium': len([r for r in ai_results if r['severity'] == 'MEDIUM']),
            'low': len([r for r in ai_results if r['severity'] == 'LOW']),
        }
        
        # 保存日志
        log_records = ai_results.copy()
        for r in log_records:
            r['source'] = 'text_scan'
        save_security_log(log_records)
        
        return jsonify({
            'success': True,
            'results': ai_results,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"文本扫描出错: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """扫描上传的文件"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': '请选择要扫描的文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '文件名为空'}), 400
        
        # 保存文件
        filename = Path(file.filename).name  # 防止路径遍历
        file_path = SCAN_DIR / filename
        file.save(file_path)
        
        # 获取文件信息
        file_size = file_path.stat().st_size
        mime_type, _ = mimetypes.guess_type(filename)
        
        results = []
        
        # 根据文件类型扫描
        text_exts = {'.txt', '.md', '.py', '.js', '.html', '.htm', '.json', '.xml', '.csv', '.log', '.yaml', '.yml', '.docx', '.doc'}
        if Path(filename).suffix.lower() in text_exts:
            try:
                # 尝试读取文本内容
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            text_content = f.read()
                        results.extend(scan_ai_vulnerabilities(text_content, filename))
                        break
                    except UnicodeDecodeError:
                        continue
            except Exception as e:
                logger.warning(f"读取文件文本失败 {filename}: {e}")
        
        # 病毒扫描
        virus_results = scan_file_virus(file_path)
        results.extend(virus_results)
        
        # 统计结果
        summary = {
            'total': len([r for r in results if r['type'] in ('ai_vulnerability', 'virus')]),
            'critical': len([r for r in results if r.get('severity') == 'CRITICAL']),
            'high': len([r for r in results if r.get('severity') == 'HIGH']),
            'medium': len([r for r in results if r.get('severity') == 'MEDIUM']),
            'low': len([r for r in results if r.get('severity') == 'LOW']),
            'clean': len([r for r in results if r.get('type') == 'clean']),
        }
        
        # 保存日志
        log_records = results.copy()
        for r in log_records:
            r['source'] = 'file_scan'
            r['filename'] = filename
            r['file_size'] = file_size
            r['mime_type'] = mime_type
        save_security_log(log_records)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_size': file_size,
            'mime_type': mime_type,
            'results': results,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"文件扫描出错: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/batch', methods=['POST'])
def scan_batch():
    """批量扫描"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': '请选择要扫描的文件'}), 400
        
        files = request.files.getlist('files')
        all_results = []
        
        for file in files:
            if file.filename == '':
                continue
            
            filename = Path(file.filename).name
            file_path = SCAN_DIR / filename
            file.save(file_path)
            
            results = []
            # AI漏洞扫描（文本文件）
            text_exts = {'.txt', '.md', '.py', '.js', '.html', '.json', '.xml', '.csv', '.log', '.yaml', '.yml'}
            if Path(filename).suffix.lower() in text_exts:
                try:
                    for encoding in ['utf-8', 'gbk', 'latin-1']:
                        try:
                            with open(file_path, 'r', encoding=encoding) as f:
                                text_content = f.read()
                            results.extend(scan_ai_vulnerabilities(text_content, filename))
                            break
                        except UnicodeDecodeError:
                            continue
                except:
                    pass
            
            # 病毒扫描
            results.extend(scan_file_virus(file_path))
            all_results.append({
                'filename': filename,
                'results': results,
                'summary': {
                    'total': len([r for r in results if r['type'] in ('ai_vulnerability', 'virus')]),
                    'critical': len([r for r in results if r.get('severity') == 'CRITICAL']),
                    'high': len([r for r in results if r.get('severity') == 'HIGH']),
                    'medium': len([r for r in results if r.get('severity') == 'MEDIUM']),
                }
            })
        
        return jsonify({
            'success': True,
            'files_scanned': len(all_results),
            'results': all_results
        })
    except Exception as e:
        logger.error(f"批量扫描出错: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """获取安全日志"""
    try:
        if not LOG_FILE.exists():
            return jsonify({'logs': [], 'total': 0})
        
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        # 支持过滤
        severity_filter = request.args.get('severity')
        type_filter = request.args.get('type')
        
        if severity_filter:
            logs = [l for l in logs if l.get('severity') == severity_filter.upper()]
        if type_filter:
            logs = [l for l in logs if l.get('type') == type_filter]
        
        return jsonify({
            'logs': logs[-100:],  # 最近100条
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules')
def get_rules():
    """获取检测规则"""
    return jsonify({
        'ai_vuln_rules': {k: {'name': v['name'], 'severity': v['severity'], 'description': v['description']} 
                           for k, v in AI_VULN_RULES.items()},
        'virus_signatures': {k: {'name': v['name'], 'severity': v['severity'], 'extensions': v['extensions']} 
                             for k, v in VIRUS_SIGNATURES.items()}
    })

@app.route('/api/quarantine', methods=['POST'])
def quarantine_file():
    """隔离文件"""
    try:
        data = request.get_json()
        filename = Path(data.get('filename', '')).name
        if not filename:
            return jsonify({'error': '文件名不能为空'}), 400
        
        src = SCAN_DIR / filename
        if not src.exists():
            return jsonify({'error': '文件不存在'}), 404
        
        dst = QUARANTINE_DIR / filename
        import shutil
        shutil.move(str(src), str(dst))
        
        return jsonify({'success': True, 'message': f'文件 {filename} 已隔离'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """健康检查"""
    return jsonify({
        'status': 'ok',
        'version': '1.0.0',
        'ai_vuln_rules': len(AI_VULN_RULES),
        'virus_signatures': len(VIRUS_SIGNATURES)
    })

# ===================== 文件监控 =====================
class FileScanHandler(watchdog.events.FileSystemEventHandler):
    """文件监控处理器"""
    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"检测到新文件: {event.src_path}")
            # 可以在这里自动扫描新文件

def start_file_monitor(path):
    """启动文件监控"""
    event_handler = FileScanHandler()
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    logger.info(f"已启动文件监控: {path}")
    return observer

if __name__ == '__main__':
    logger.info("="*50)
    logger.info("AI漏洞防护与扫毒应用 启动中...")
    logger.info(f"AI漏洞检测规则: {len(AI_VULN_RULES)} 条")
    logger.info(f"病毒特征库: {len(VIRUS_SIGNATURES)} 个")
    logger.info(f"扫描目录: {SCAN_DIR}")
    logger.info(f"隔离目录: {QUARANTINE_DIR}")
    logger.info("="*50)
    
    # 启动文件监控（可选）
    # monitor = start_file_monitor(str(SCAN_DIR))
    
    app.run(host='0.0.0.0', port=5000, debug=False)
