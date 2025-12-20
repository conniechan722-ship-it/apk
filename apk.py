#!/usr/bin/env python3
"""
APK多维度分析系统 - 基于多智能体协作的深度APK分析框架
使用Ollama模型进行全方位APK安全与结构分析
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from pathlib import Path
import shutil
import re
import subprocess
import zipfile
import tempfile
import random
import traceback
import sqlite3
from tqdm import tqdm
import aiohttp
import requests


# 常量定义
DECOMPILE_TIMEOUT = 300  # 反编译超时时间（秒）
PACKER_CONFIDENCE_MULTIPLIER = 30  # 加壳检测置信度乘数
MAX_SCAN_FILES = 50  # 代码扫描最大文件数


def find_ollama_path() -> str:
    """查找 Ollama 可执行文件路径"""
    ollama_path = shutil.which('ollama')
    if ollama_path:
        print(f"✓ 找到 Ollama: {ollama_path}")
        return ollama_path
   
    if sys.platform == 'win32':
        username = os.getenv('USERNAME', 'User')
        possible_paths = [
            r'd:\Ollama\ollama.exe',
            r'e:\Ollama\ollama.exe',
            r'f:\Ollama\ollama.exe',
            rf'C:\Users\{username}\AppData\Local\Programs\Ollama\ollama.exe',
            rf'D:\Users\{username}\AppData\Local\Programs\Ollama\ollama.exe',
            rf'C:\Users\{username}\AppData\Local\Ollama\ollama.exe',
            r'C:\Program Files\Ollama\ollama.exe',
            r'D:\Program Files\Ollama\ollama.exe',
            r'C:\Program Files (x86)\Ollama\ollama.exe',
            r'C:\ProgramData\Ollama\ollama.exe',
            r'C:\Ollama\ollama.exe',
        ]
       
        for path in possible_paths:
            if os.path.exists(path):
                print(f"✓ 找到 Ollama: {path}")
                return path
   
    print("⚠️  未找到 Ollama，请确保已安装: https://ollama.ai")
    return 'ollama'


OLLAMA_PATH = find_ollama_path()
DEFAULT_MODEL = 'qwen2.5:32b'


def find_decompiler_tools() -> Dict[str, str]:
    """查找反编译工具"""
    tools = {}
    # 查找 jadx
    jadx_path = shutil.which('jadx')
    if jadx_path:
        tools['jadx'] = jadx_path
        print(f"✓ 找到 jadx: {jadx_path}")
    # 查找 apktool
    apktool_path = shutil.which('apktool')
    if apktool_path:
        tools['apktool'] = apktool_path
        print(f"✓ 找到 apktool: {apktool_path}")
    
    if not tools:
        print("⚠️  未找到反编译工具 (jadx/apktool)")
    
    return tools


def get_ollama_models(base_url: str = "http://127.0.0.1:11434") -> List[str]:
    """从Ollama API获取已安装的模型列表"""
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            data = response.json()
            models = [model["name"] for model in data.get("models", [])]
            return models
        else:
            print(f"⚠️ 获取模型列表失败: HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"⚠️ 无法连接到Ollama服务 ({base_url})")
        print(f"    请确保Ollama正在运行: ollama serve")
    except Exception as e:
        print(f"⚠️ 获取模型列表失败: {e}")
    return []


class APKExtractor:
    """APK信息提取器"""
   
    def __init__(self, apk_path: str, enable_decompile: bool = False, output_dir: str = None, analyze_db: bool = False):
        self.apk_path = apk_path
        self.temp_dir = tempfile.mkdtemp()
        self.extracted_info = {}
        self.enable_decompile = enable_decompile
        self.output_dir = output_dir or tempfile.mkdtemp()
        self.decompile_dir = None
        self.decompiler_tools = find_decompiler_tools() if enable_decompile else {}
        self.analyze_db = analyze_db
       
    def extract_basic_structure(self) -> Dict[str, Any]:
        """提取APK基本结构"""
        print("\n📦 正在提取APK基本结构...")
       
        structure = {
            "file_list": [],
            "file_sizes": {},
            "total_size": 0,
            "dex_files": [],
            "so_files": [],
            "resource_files": [],
            "manifest_found": False,
            "certificate_found": False
        }
       
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                structure["file_list"] = zip_ref.namelist()
                structure["total_size"] = os.path.getsize(self.apk_path)
               
                for file_info in zip_ref.infolist():
                    structure["file_sizes"][file_info.filename] = file_info.file_size
                   
                    # 分类文件
                    if file_info.filename.endswith('.dex'):
                        structure["dex_files"].append(file_info.filename)
                    elif file_info.filename.endswith('.so'):
                        structure["so_files"].append(file_info.filename)
                    elif file_info.filename.startswith('res/'):
                        structure["resource_files"].append(file_info.filename)
                    elif file_info.filename == 'AndroidManifest.xml':
                        structure["manifest_found"] = True
                    elif 'META-INF' in file_info.filename and '.RSA' in file_info.filename:
                        structure["certificate_found"] = True
               
                # 提取关键文件
                zip_ref.extractall(self.temp_dir)
               
            print(f"  ✓ 提取了 {len(structure['file_list'])} 个文件")
            print(f"  ✓ 找到 {len(structure['dex_files'])} 个DEX文件")
            print(f"  ✓ 找到 {len(structure['so_files'])} 个SO库")
           
        except Exception as e:
            print(f"  ✗ 提取失败: {e}")
           
        return structure
   
    def analyze_manifest(self) -> Dict[str, Any]:
        """分析AndroidManifest.xml（需要apktool或aapt）"""
        print("\n📄 正在分析AndroidManifest.xml...")
       
        manifest_info = {
            "raw_available": False,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "package_name": "",
            "version_code": "",
            "version_name": "",
            "min_sdk": "",
            "target_sdk": ""
        }
       
        try:
            # 尝试使用aapt读取
            aapt_path = shutil.which('aapt')
            if aapt_path:
                result = subprocess.run(
                    [aapt_path, 'dump', 'badging', self.apk_path],
                    capture_output=True,
                    text=True
                )
               
                if result.returncode == 0:
                    output = result.stdout
                   
                    # 提取包名
                    package_match = re.search(r"package: name='([^']+)'", output)
                    if package_match:
                        manifest_info["package_name"] = package_match.group(1)
                   
                    # 提取版本信息
                    version_match = re.search(r"versionCode='([^']+)'.*versionName='([^']+)'", output)
                    if version_match:
                        manifest_info["version_code"] = version_match.group(1)
                        manifest_info["version_name"] = version_match.group(2)
                   
                    # 提取SDK版本
                    sdk_match = re.search(r"sdkVersion:'(\d+)'", output)
                    if sdk_match:
                        manifest_info["min_sdk"] = sdk_match.group(1)
                   
                    target_sdk_match = re.search(r"targetSdkVersion:'(\d+)'", output)
                    if target_sdk_match:
                        manifest_info["target_sdk"] = target_sdk_match.group(1)
                   
                    # 提取权限
                    permissions = re.findall(r"uses-permission: name='([^']+)'", output)
                    manifest_info["permissions"] = permissions
                   
                    manifest_info["raw_available"] = True
                    print(f"  ✓ 包名: {manifest_info['package_name']}")
                    print(f"  ✓ 版本: {manifest_info['version_name']} ({manifest_info['version_code']})")
                    print(f"  ✓ 找到 {len(permissions)} 个权限")
            else:
                print("  ⚠️  未找到aapt工具，使用基础分析")
               
        except Exception as e:
            print(f"  ✗ 分析失败: {e}")
           
        return manifest_info
   
    def analyze_dex_files(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """分析DEX文件信息"""
        print("\n🔍 正在分析DEX文件...")
       
        dex_info = {
            "count": len(structure["dex_files"]),
            "files": [],
            "total_size": 0,
            "estimated_methods": 0
        }
       
        for dex_file in structure["dex_files"]:
            file_path = os.path.join(self.temp_dir, dex_file)
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                dex_info["total_size"] += size
                dex_info["files"].append({
                    "name": dex_file,
                    "size": size,
                    "size_mb": round(size / 1024 / 1024, 2)
                })
       
        # 粗略估计方法数（每个方法大约100-200字节）
        dex_info["estimated_methods"] = int(dex_info["total_size"] / 150)
       
        print(f"  ✓ DEX文件数: {dex_info['count']}")
        print(f"  ✓ DEX总大小: {round(dex_info['total_size'] / 1024 / 1024, 2)} MB")
        print(f"  ✓ 估计方法数: {dex_info['estimated_methods']}")
       
        return dex_info
   
    def analyze_native_libs(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """分析Native库"""
        print("\n🔧 正在分析Native库...")
       
        native_info = {
            "architectures": {},
            "libraries": [],
            "total_size": 0
        }
       
        for so_file in structure["so_files"]:
            # 提取架构信息
            parts = so_file.split('/')
            if len(parts) >= 2 and parts[0] == 'lib':
                arch = parts[1]
                lib_name = parts[-1]
               
                if arch not in native_info["architectures"]:
                    native_info["architectures"][arch] = []
               
                file_path = os.path.join(self.temp_dir, so_file)
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    native_info["total_size"] += size
                    native_info["architectures"][arch].append({
                        "name": lib_name,
                        "size": size
                    })
                   
                    if lib_name not in [lib["name"] for lib in native_info["libraries"]]:
                        native_info["libraries"].append({
                            "name": lib_name,
                            "architectures": [arch]
                        })
       
        print(f"  ✓ 支持的架构: {', '.join(native_info['architectures'].keys())}")
        print(f"  ✓ 库文件数: {len(native_info['libraries'])}")
        print(f"  ✓ Native代码总大小: {round(native_info['total_size'] / 1024 / 1024, 2)} MB")
       
        return native_info
   
    def extract_resources_info(self) -> Dict[str, Any]:
        """提取资源信息"""
        print("\n🎨 正在分析资源文件...")
       
        resources_info = {
            "has_resources_arsc": False,
            "layout_count": 0,
            "drawable_count": 0,
            "xml_count": 0,
            "asset_files": []
        }
       
        resources_arsc = os.path.join(self.temp_dir, "resources.arsc")
        if os.path.exists(resources_arsc):
            resources_info["has_resources_arsc"] = True
            resources_info["arsc_size"] = os.path.getsize(resources_arsc)
       
        # 统计资源文件
        res_dir = os.path.join(self.temp_dir, "res")
        if os.path.exists(res_dir):
            for root, dirs, files in os.walk(res_dir):
                for file in files:
                    if 'layout' in root:
                        resources_info["layout_count"] += 1
                    elif 'drawable' in root or 'mipmap' in root:
                        resources_info["drawable_count"] += 1
                    elif file.endswith('.xml'):
                        resources_info["xml_count"] += 1
       
        # 统计assets
        assets_dir = os.path.join(self.temp_dir, "assets")
        if os.path.exists(assets_dir):
            for root, dirs, files in os.walk(assets_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), assets_dir)
                    resources_info["asset_files"].append(rel_path)
       
        print(f"  ✓ 布局文件: {resources_info['layout_count']}")
        print(f"  ✓ 图像资源: {resources_info['drawable_count']}")
        print(f"  ✓ Assets文件: {len(resources_info['asset_files'])}")
       
        return resources_info
   
    def analyze_signature(self) -> Dict[str, Any]:
        """分析签名信息"""
        print("\n🔐 正在分析签名信息...")
       
        signature_info = {
            "signed": False,
            "certificates": [],
            "signature_versions": []
        }
       
        try:
            # 检查META-INF目录
            meta_inf_dir = os.path.join(self.temp_dir, "META-INF")
            if os.path.exists(meta_inf_dir):
                cert_files = [f for f in os.listdir(meta_inf_dir) if f.endswith(('.RSA', '.DSA', '.EC'))]
                signature_info["signed"] = len(cert_files) > 0
                signature_info["certificates"] = cert_files
               
                # 检查签名版本
                if os.path.exists(os.path.join(meta_inf_dir, "MANIFEST.MF")):
                    signature_info["signature_versions"].append("v1 (JAR)")
               
            print(f"  ✓ 已签名: {signature_info['signed']}")
            print(f"  ✓ 证书文件: {len(signature_info['certificates'])}")
           
        except Exception as e:
            print(f"  ✗ 分析失败: {e}")
           
        return signature_info
   
    def detect_packer(self) -> Dict[str, Any]:
        """检测加壳"""
        print("\n🛡️  正在检测加壳...")
       
        packer_info = {
            "is_packed": False,
            "packer_name": None,
            "confidence": 0,
            "indicators": [],
            "entry_class": None,
            "difficulty": "未知"
        }
       
        # 加壳特征库
        packer_signatures = {
            "360加固": {
                "signatures": ["com.stub.StubApp", "com.qihoo.util", "com.qihoo360", "libjiagu"],
                "difficulty": "中"
            },
            "腾讯乐固": {
                "signatures": ["com.tencent.StubShell", "com.tencent.bugly", "libtup", "libshell"],
                "difficulty": "高"
            },
            "梆梆加固": {
                "signatures": ["com.secneo.apkwrapper", "com.bangcle", "libsecexe", "libDexHelper"],
                "difficulty": "高"
            },
            "爱加密": {
                "signatures": ["com.ijiami", "s.h.e.l.l", "libijiami", "libexec"],
                "difficulty": "中高"
            },
            "娜迦加固": {
                "signatures": ["com.nagain", "com.naga", "libnaga", "libddog"],
                "difficulty": "中"
            },
            "阿里聚安全": {
                "signatures": ["com.alibaba.wireless.security", "libsgmain", "libmobisec"],
                "difficulty": "高"
            },
            "百度加固": {
                "signatures": ["com.baidu.protect", "libbaiduprotect"],
                "difficulty": "中"
            },
            "网易易盾": {
                "signatures": ["com.netease.nis", "libnesec"],
                "difficulty": "中高"
            },
            "顶象加固": {
                "signatures": ["com.dingxiang.mobile", "libdxshield"],
                "difficulty": "高"
            },
        }
       
        try:
            # 简单的特征检测：检查文件列表中的关键字
            all_files = self.extracted_info.get('structure', {}).get('file_list', [])
            so_files = self.extracted_info.get('structure', {}).get('so_files', [])
           
            matched_packers = []
            for packer_name, packer_data in packer_signatures.items():
                signatures = packer_data['signatures']
                matches = []
               
                # 检查文件路径中的特征
                for signature in signatures:
                    for file_path in all_files + so_files:
                        if signature.lower() in file_path.lower():
                            matches.append(f"文件路径包含: {signature}")
                            break
               
                if matches:
                    matched_packers.append({
                        "name": packer_name,
                        "matches": matches,
                        "confidence": min(len(matches) * PACKER_CONFIDENCE_MULTIPLIER, 90),  # 限制最大90%
                        "difficulty": packer_data['difficulty']
                    })
           
            # 选择置信度最高的加壳方案
            if matched_packers:
                matched_packers.sort(key=lambda x: x['confidence'], reverse=True)
                best_match = matched_packers[0]
               
                packer_info["is_packed"] = True
                packer_info["packer_name"] = best_match['name']
                packer_info["confidence"] = min(best_match['confidence'], 90)
                packer_info["indicators"] = best_match['matches']
                packer_info["difficulty"] = best_match['difficulty']
               
                print(f"  ⚠️  检测到加壳: {best_match['name']}")
                print(f"  ⚠️  置信度: {packer_info['confidence']}%")
                print(f"  ⚠️  脱壳难度: {best_match['difficulty']}")
            else:
                print(f"  ✓ 未检测到常见加壳")
               
        except Exception as e:
            print(f"  ✗ 加壳检测失败: {e}")
           
        return packer_info
   
    def detect_obfuscation(self) -> Dict[str, Any]:
        """检测混淆"""
        print("\n🔀 正在检测混淆...")
       
        obfuscation_info = {
            "is_obfuscated": False,
            "obfuscation_level": 0,  # 1-10
            "identifier_obfuscation": False,
            "string_encryption": False,
            "control_flow_obfuscation": False,
            "details": {
                "short_names_ratio": 0,
                "single_char_names": 0,
                "obfuscated_packages": []
            }
        }
       
        try:
            # 分析包名和类名特征
            package_name = self.extracted_info.get('manifest', {}).get('package_name', '')
           
            # 检测包名混淆
            if package_name:
                # 检查是否有短类名或单字符包名
                package_parts = package_name.split('.')
                short_parts = [p for p in package_parts if len(p) <= 2]
               
                if short_parts:
                    obfuscation_info["identifier_obfuscation"] = True
                    obfuscation_info["details"]["obfuscated_packages"].append(package_name)
           
            # 分析DEX文件数量和大小
            dex_count = self.extracted_info.get('dex', {}).get('count', 0)
            if dex_count > 1:
                # 多DEX可能暗示使用了混淆
                obfuscation_info["obfuscation_level"] += 2
           
            # 检查是否有ProGuard/R8的映射文件
            all_files = self.extracted_info.get('structure', {}).get('file_list', [])
            has_mapping = any('mapping' in f.lower() or 'proguard' in f.lower() for f in all_files)
           
            # 分析Native库（混淆通常会有native代码）
            native_count = len(self.extracted_info.get('native', {}).get('libraries', []))
            if native_count > 3:
                obfuscation_info["obfuscation_level"] += 1
           
            # 估算混淆等级
            if obfuscation_info["identifier_obfuscation"]:
                obfuscation_info["obfuscation_level"] += 3
                obfuscation_info["is_obfuscated"] = True
           
            if has_mapping:
                obfuscation_info["obfuscation_level"] += 2
                obfuscation_info["is_obfuscated"] = True
           
            # 检测可能的字符串加密（通过检测加密相关的库）
            crypto_libs = [lib['name'] for lib in self.extracted_info.get('native', {}).get('libraries', [])
                          if any(keyword in lib['name'].lower() for keyword in ['crypto', 'cipher', 'encrypt'])]
            if crypto_libs:
                obfuscation_info["string_encryption"] = True
                obfuscation_info["obfuscation_level"] += 2
           
            # 限制在1-10范围内
            obfuscation_info["obfuscation_level"] = min(obfuscation_info["obfuscation_level"], 10)
           
            if obfuscation_info["is_obfuscated"]:
                print(f"  ⚠️  检测到代码混淆")
                print(f"  ⚠️  混淆等级: {obfuscation_info['obfuscation_level']}/10")
            else:
                print(f"  ✓ 未检测到明显混淆")
               
        except Exception as e:
            print(f"  ✗ 混淆检测失败: {e}")
           
        return obfuscation_info
   
    def decompile_apk(self) -> Dict[str, Any]:
        """反编译APK"""
        print("\n🔓 正在反编译APK...")
       
        decompile_info = {
            "success": False,
            "method": None,
            "output_dir": None,
            "java_sources": [],
            "smali_sources": [],
            "error": None
        }
       
        if not self.enable_decompile:
            print("  ⚠️  反编译功能未启用")
            return decompile_info
       
        if not self.decompiler_tools:
            print("  ⚠️  未找到反编译工具")
            decompile_info["error"] = "未找到反编译工具"
            return decompile_info
       
        try:
            # 尝试使用jadx反编译
            if 'jadx' in self.decompiler_tools:
                print("  → 使用jadx进行反编译...")
                jadx_output = os.path.join(self.output_dir, 'jadx_output')
                os.makedirs(jadx_output, exist_ok=True)
               
                result = subprocess.run(
                    [self.decompiler_tools['jadx'], '-d', jadx_output, self.apk_path, '--show-bad-code'],
                    capture_output=True,
                    text=True,
                    timeout=DECOMPILE_TIMEOUT  # 反编译超时
                )
               
                if result.returncode == 0 or os.path.exists(os.path.join(jadx_output, 'sources')):
                    decompile_info["success"] = True
                    decompile_info["method"] = "jadx"
                    decompile_info["output_dir"] = jadx_output
                    self.decompile_dir = jadx_output
                   
                    # 统计反编译的Java文件
                    sources_dir = os.path.join(jadx_output, 'sources')
                    if os.path.exists(sources_dir):
                        for root, dirs, files in os.walk(sources_dir):
                            for file in files:
                                if file.endswith('.java'):
                                    rel_path = os.path.relpath(os.path.join(root, file), sources_dir)
                                    decompile_info["java_sources"].append(rel_path)
                   
                    print(f"  ✓ jadx反编译成功")
                    print(f"  ✓ 输出目录: {jadx_output}")
                    print(f"  ✓ Java源文件数: {len(decompile_info['java_sources'])}")
                else:
                    print(f"  ✗ jadx反编译失败: {result.stderr}")
           
            # 尝试使用apktool反编译
            if 'apktool' in self.decompiler_tools and not decompile_info["success"]:
                print("  → 使用apktool进行反编译...")
                apktool_output = os.path.join(self.output_dir, 'apktool_output')
                os.makedirs(apktool_output, exist_ok=True)
               
                result = subprocess.run(
                    [self.decompiler_tools['apktool'], 'd', self.apk_path, '-o', apktool_output, '-f'],
                    capture_output=True,
                    text=True,
                    timeout=DECOMPILE_TIMEOUT
                )
               
                if result.returncode == 0 and os.path.exists(apktool_output):
                    decompile_info["success"] = True
                    decompile_info["method"] = "apktool"
                    decompile_info["output_dir"] = apktool_output
                    self.decompile_dir = apktool_output
                   
                    # 统计反编译的Smali文件
                    smali_dir = os.path.join(apktool_output, 'smali')
                    if os.path.exists(smali_dir):
                        for root, dirs, files in os.walk(smali_dir):
                            for file in files:
                                if file.endswith('.smali'):
                                    rel_path = os.path.relpath(os.path.join(root, file), smali_dir)
                                    decompile_info["smali_sources"].append(rel_path)
                   
                    print(f"  ✓ apktool反编译成功")
                    print(f"  ✓ 输出目录: {apktool_output}")
                    print(f"  ✓ Smali源文件数: {len(decompile_info['smali_sources'])}")
                else:
                    print(f"  ✗ apktool反编译失败: {result.stderr}")
                    decompile_info["error"] = result.stderr
           
        except subprocess.TimeoutExpired:
            print(f"  ✗ 反编译超时")
            decompile_info["error"] = "反编译超时"
        except Exception as e:
            print(f"  ✗ 反编译失败: {e}")
            decompile_info["error"] = str(e)
           
        return decompile_info
   
    def analyze_code_logic(self, decompile_info: Dict[str, Any]) -> Dict[str, Any]:
        """分析代码逻辑"""
        print("\n🧠 正在分析代码逻辑...")
       
        logic_info = {
            "entry_points": [],      # 入口点
            "key_classes": [],       # 关键类
            "sensitive_methods": [], # 敏感方法
            "modifiable_points": [], # 可修改点
            "hook_suggestions": []   # Hook 建议
        }
       
        if not decompile_info.get("success"):
            print("  ⚠️  反编译未成功，跳过代码逻辑分析")
            return logic_info
       
        try:
            decompile_dir = decompile_info.get("output_dir")
            if not decompile_dir or not os.path.exists(decompile_dir):
                print("  ⚠️  反编译目录不存在")
                return logic_info
           
            # 分析AndroidManifest.xml（从apktool输出）
            manifest_path = os.path.join(decompile_dir, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    manifest_content = f.read()
                   
                # 提取Activity
                activities = re.findall(r'<activity[^>]*android:name="([^"]+)"', manifest_content)
                for activity in activities[:10]:  # 限制数量
                    logic_info["entry_points"].append({
                        "type": "Activity",
                        "name": activity,
                        "description": "应用界面入口"
                    })
                    logic_info["key_classes"].append(activity)
               
                # 提取Service
                services = re.findall(r'<service[^>]*android:name="([^"]+)"', manifest_content)
                for service in services[:10]:
                    logic_info["entry_points"].append({
                        "type": "Service",
                        "name": service,
                        "description": "后台服务"
                    })
                    logic_info["key_classes"].append(service)
               
                # 提取BroadcastReceiver
                receivers = re.findall(r'<receiver[^>]*android:name="([^"]+)"', manifest_content)
                for receiver in receivers[:10]:
                    logic_info["entry_points"].append({
                        "type": "BroadcastReceiver",
                        "name": receiver,
                        "description": "广播接收器"
                    })
                    logic_info["key_classes"].append(receiver)
           
            # 分析Java/Smali源代码，查找敏感方法
            sources_dir = os.path.join(decompile_dir, 'sources')
            smali_dir = os.path.join(decompile_dir, 'smali')
           
            # 敏感关键词
            sensitive_keywords = {
                "网络请求": ["HttpURLConnection", "OkHttp", "Retrofit", "URLConnection", "HttpClient"],
                "文件操作": ["FileOutputStream", "FileInputStream", "File.write", "File.read"],
                "加密解密": ["Cipher", "MessageDigest", "SecretKey", "encrypt", "decrypt", "AES", "DES", "RSA"],
                "签名验证": ["Signature", "PackageManager.GET_SIGNATURES", "checkSignature", "verifySignature"],
                "动态加载": ["DexClassLoader", "PathClassLoader", "loadClass", "loadDex"],
                "反射调用": ["Class.forName", "Method.invoke", "getDeclaredMethod"],
                "Native调用": ["System.loadLibrary", "JNI", "native "],
                "数据库操作": ["SQLiteDatabase", "ContentProvider", "query", "insert", "update"],
                "SharedPreferences": ["SharedPreferences", "getSharedPreferences", "edit().put"],
                "Root检测": ["su", "Superuser", "isRooted", "checkRoot"]
            }
           
            # 扫描Java源文件
            if os.path.exists(sources_dir):
                java_files = decompile_info.get("java_sources", [])[:MAX_SCAN_FILES]  # 限制扫描文件数
                for java_file in java_files:
                    file_path = os.path.join(sources_dir, java_file)
                    if os.path.exists(file_path):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                               
                            for category, keywords in sensitive_keywords.items():
                                for keyword in keywords:
                                    if keyword in content:
                                        logic_info["sensitive_methods"].append({
                                            "category": category,
                                            "keyword": keyword,
                                            "file": java_file,
                                            "description": f"在{java_file}中发现{category}操作"
                                        })
                                        break
                        except Exception:
                            continue
           
            # 生成可修改点建议
            if logic_info["sensitive_methods"]:
                # 签名验证相关
                signature_related = [m for m in logic_info["sensitive_methods"] if m["category"] == "签名验证"]
                if signature_related:
                    logic_info["modifiable_points"].append({
                        "point": "签名验证绕过",
                        "description": "检测到签名验证代码，可以通过修改验证逻辑绕过签名检查",
                        "files": [m["file"] for m in signature_related],
                        "difficulty": "中"
                    })
               
                # 网络请求相关
                network_related = [m for m in logic_info["sensitive_methods"] if m["category"] == "网络请求"]
                if network_related:
                    logic_info["modifiable_points"].append({
                        "point": "API地址修改",
                        "description": "检测到网络请求代码，可以修改API服务器地址",
                        "files": list(set([m["file"] for m in network_related])),
                        "difficulty": "低"
                    })
               
                # Root检测相关
                root_related = [m for m in logic_info["sensitive_methods"] if m["category"] == "Root检测"]
                if root_related:
                    logic_info["modifiable_points"].append({
                        "point": "Root检测绕过",
                        "description": "检测到Root检测代码，可以修改检测逻辑",
                        "files": [m["file"] for m in root_related],
                        "difficulty": "低"
                    })
           
            # 生成Hook建议
            if logic_info["key_classes"]:
                logic_info["hook_suggestions"].append({
                    "target": "Application入口",
                    "classes": [c for c in logic_info["key_classes"] if "Application" in c],
                    "method": "onCreate",
                    "reason": "Hook应用启动流程，可以在应用启动时执行自定义代码"
                })
           
            if any(m["category"] == "加密解密" for m in logic_info["sensitive_methods"]):
                logic_info["hook_suggestions"].append({
                    "target": "加密解密方法",
                    "classes": ["javax.crypto.Cipher"],
                    "method": "doFinal",
                    "reason": "Hook加密解密方法，可以获取明文数据"
                })
           
            if any(m["category"] == "网络请求" for m in logic_info["sensitive_methods"]):
                logic_info["hook_suggestions"].append({
                    "target": "网络请求",
                    "classes": ["okhttp3.OkHttpClient", "java.net.HttpURLConnection"],
                    "method": "execute / connect",
                    "reason": "Hook网络请求，可以查看或修改请求内容"
                })
           
            print(f"  ✓ 发现 {len(logic_info['entry_points'])} 个入口点")
            print(f"  ✓ 发现 {len(logic_info['sensitive_methods'])} 个敏感方法")
            print(f"  ✓ 识别 {len(logic_info['modifiable_points'])} 个可修改点")
            print(f"  ✓ 生成 {len(logic_info['hook_suggestions'])} 个Hook建议")
           
        except Exception as e:
            print(f"  ✗ 代码逻辑分析失败: {e}")
           
        return logic_info
   
    def find_database_files(self, structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        """查找APK中的所有数据库文件"""
        db_files = []
        # 搜索 assets 目录和其他位置的 .db 文件
        for file_path in structure.get('file_list', []):
            if file_path.endswith('.db') or file_path.endswith('.sqlite') or file_path.endswith('.sqlite3'):
                full_path = os.path.join(self.temp_dir, file_path)
                db_files.append({
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'size': os.path.getsize(full_path) if os.path.exists(full_path) else 0
                })
        return db_files
   
    def analyze_database(self, db_path: str) -> Dict[str, Any]:
        """分析单个数据库文件"""
        result = {
            'path': db_path,
            'tables': [],
            'total_records': 0,
            'sensitive_data': [],
            'error': None
        }
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # 获取所有表名
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                for table in tables:
                    table_name = table[0]
                    # 验证表名以防止SQL注入（虽然来自sqlite_master，但为了安全起见）
                    # SQLite表名只能包含字母、数字、下划线
                    if not all(c.isalnum() or c == '_' for c in table_name):
                        continue
                    
                    table_info = {
                        'name': table_name,
                        'columns': [],
                        'row_count': 0,
                        'sample_data': []
                    }
                    
                    # 获取表结构 - PRAGMA命令是安全的，不需要参数化
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = cursor.fetchall()
                    table_info['columns'] = [{'name': col[1], 'type': col[2]} for col in columns]
                    
                    # 获取行数 - 使用参数化查询
                    # Note: SQLite doesn't support parameter substitution for table names in standard queries
                    # But we've validated the table name above
                    cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
                    table_info['row_count'] = cursor.fetchone()[0]
                    result['total_records'] += table_info['row_count']
                    
                    # 获取样本数据（前10行）
                    cursor.execute(f'SELECT * FROM "{table_name}" LIMIT 10')
                    table_info['sample_data'] = cursor.fetchall()
                    
                    # 检测敏感数据
                    sensitive_keywords = ['password', 'token', 'secret', 'key', 'auth', 'session', 
                                          'user', 'email', 'phone', 'credential', 'cookie']
                    for col in table_info['columns']:
                        col_name_lower = col['name'].lower()
                        for keyword in sensitive_keywords:
                            if keyword in col_name_lower:
                                result['sensitive_data'].append({
                                    'table': table_name,
                                    'column': col['name'],
                                    'keyword': keyword
                                })
                    
                    result['tables'].append(table_info)
        except Exception as e:
            result['error'] = str(e)
        
        return result
   
    def analyze_all_databases(self) -> Dict[str, Any]:
        """分析APK中所有的数据库文件"""
        print("\n🗄️  正在分析数据库文件...")
        
        structure = self.extracted_info.get('structure', {})
        db_files = self.find_database_files(structure)
        
        results = {
            'total_databases': len(db_files),
            'databases': []
        }
        
        print(f"  ✓ 找到 {len(db_files)} 个数据库文件")
        
        for db_file in db_files:
            full_path = os.path.join(self.temp_dir, db_file['path'])
            if os.path.exists(full_path):
                print(f"  → 分析数据库: {db_file['name']}")
                db_analysis = self.analyze_database(full_path)
                # Add size information from db_file
                db_analysis['size'] = db_file.get('size', 0)
                results['databases'].append(db_analysis)
                
                if db_analysis.get('error'):
                    print(f"    ✗ 分析失败: {db_analysis['error']}")
                else:
                    print(f"    ✓ 找到 {len(db_analysis.get('tables', []))} 个表，共 {db_analysis.get('total_records', 0)} 条记录")
                    if db_analysis.get('sensitive_data'):
                        print(f"    ⚠️  发现 {len(db_analysis['sensitive_data'])} 个敏感字段")
        
        return results
   
    def extract_all(self) -> Dict[str, Any]:
        """提取所有APK信息"""
        print("\n" + "="*80)
        print("开始提取APK信息")
        print("="*80)
       
        all_info = {
            "apk_path": self.apk_path,
            "timestamp": datetime.now().isoformat()
        }
       
        all_info["structure"] = self.extract_basic_structure()
        all_info["manifest"] = self.analyze_manifest()
        all_info["dex"] = self.analyze_dex_files(all_info["structure"])
        all_info["native"] = self.analyze_native_libs(all_info["structure"])
        all_info["resources"] = self.extract_resources_info()
        all_info["signature"] = self.analyze_signature()
       
        # Store for later use by other methods
        self.extracted_info = all_info
        
        # 添加数据库分析
        if self.analyze_db:
            all_info['database_analysis'] = self.analyze_all_databases()
       
        return all_info
   
    def cleanup(self):
        """清理临时文件"""
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass


class OllamaClient:
    """Ollama客户端封装 - 使用HTTP API"""
    
    def __init__(self, model_name: str, base_url: str = "http://127.0.0.1:11434"):
        self.model_name = model_name
        self.base_url = base_url
        
    async def generate(self, prompt: str, context: str = "") -> str:
        """调用Ollama API生成回复"""
        full_prompt = f"{context}\n\n{prompt}" if context else prompt
        
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": full_prompt,
            "stream": False
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("response", "").strip()
                    else:
                        error = await response.text()
                        print(f"❌ Ollama API错误: {error}")
                        return ""
        except aiohttp.ClientConnectorError:
            print(f"❌ 无法连接到Ollama服务 ({self.base_url})")
            print("   请确保Ollama正在运行: ollama serve")
            return ""
        except Exception as e:
            print(f"❌ 调用Ollama失败: {e}")
            return ""


class AIAgent:
    """AI智能体"""
   
    def __init__(self, agent_id: int, model_name: str, role: str, base_url: str = "http://127.0.0.1:11434"):
        self.agent_id = agent_id
        self.model_name = model_name
        self.role = role
        self.base_url = base_url
        self.client = OllamaClient(model_name, base_url)
       
    async def think(self, prompt: str, context: str = "") -> str:
        """思考并生成回复"""
        role_prompt = f"你是安全分析团队成员#{self.agent_id}，专长领域是【{self.role}】。\n\n"
        full_prompt = role_prompt + prompt
        return await self.client.generate(full_prompt, context)
   
    async def vote(self, candidates: List[Dict[str, Any]], task: str) -> int:
        """投票选择最佳观点"""
        vote_prompt = f"""
分析任务: {task}

以下是团队其他成员的分析结果（编号从1开始）:

"""
        for i, candidate in enumerate(candidates, 1):
            if candidate['agent_id'] != self.agent_id:
                vote_prompt += f"\n分析 {i} (来自专家 #{candidate['agent_id']}):\n{candidate['response'][:500]}...\n"
       
        vote_prompt += f"""

你是专家 #{self.agent_id}，请投票选择你认为最专业、最全面的分析。
注意：不能投给自己（分析 {self.agent_id}）。

请只输出一个数字（1-6），表示你选择的分析编号。
你的投票:"""
       
        vote_response = await self.client.generate(vote_prompt, "")
       
        # 解析投票结果
        try:
            numbers = re.findall(r'\d+', vote_response)
            if numbers:
                vote = int(numbers[0])
                if 1 <= vote <= 6 and vote != self.agent_id:
                    return vote
                else:
                    valid_votes = [i for i in range(1, 7) if i != self.agent_id]
                    return random.choice(valid_votes)
            else:
                valid_votes = [i for i in range(1, 7) if i != self.agent_id]
                return random.choice(valid_votes)
        except:
            valid_votes = [i for i in range(1, 7) if i != self.agent_id]
            return random.choice(valid_votes)


class AITeam:
    """AI分析团队 - 6个专家组成"""
   
    def __init__(self, team_id: int, role: str, models: List[str], base_url: str = "http://127.0.0.1:11434"):
        self.team_id = team_id
        self.role = role
        self.base_url = base_url
        self.agents = [
            AIAgent(i + 1, models[i % len(models)], role, base_url)
            for i in range(6)
        ]
       
    async def collaborate(self, task: str, context: str = "") -> Dict[str, Any]:
        """团队协作分析"""
        print(f"\n{'='*80}")
        print(f"团队 #{self.team_id} - 专长: {self.role}")
        print(f"{'='*80}")
       
        # 所有AI并行分析
        tasks = [agent.think(task, context) for agent in self.agents]
        responses = await asyncio.gather(*tasks)
       
        # 显示各AI的分析
        print(f"\n【初步分析结果】")
        for i, response in enumerate(responses):
            print(f"\n专家 #{i+1} 的分析:")
            print(f"{response[:300]}..." if len(response) > 300 else response)
       
        # 投票共识
        consensus = await self._voting_consensus(responses, task, context)
       
        return {
            "team_id": self.team_id,
            "role": self.role,
            "individual_responses": responses,
            "consensus": consensus,
            "timestamp": datetime.now().isoformat()
        }
   
    async def _voting_consensus(self, responses: List[str], task: str, context: str) -> str:
        """投票共识算法"""
        print(f"\n{'='*80}")
        print(f"开始投票共识过程")
        print(f"{'='*80}")
       
        candidates = [
            {"agent_id": i + 1, "response": resp, "votes": 0}
            for i, resp in enumerate(responses)
        ]
       
        round_num = 1
       
        while len(candidates) > 1:
            print(f"\n【第 {round_num} 轮投票】")
            print(f"当前剩余分析: {len(candidates)}")
           
            for candidate in candidates:
                candidate['votes'] = 0
           
            vote_tasks = []
            for agent in self.agents:
                vote_tasks.append(agent.vote(candidates, task))
           
            votes = await asyncio.gather(*vote_tasks)
           
            print(f"\n投票结果:")
            for i, vote in enumerate(votes, 1):
                print(f"  专家 #{i} 投给了分析 {vote}")
                for candidate in candidates:
                    if candidate['agent_id'] == vote:
                        candidate['votes'] += 1
                        break
           
            print(f"\n得票统计:")
            for candidate in sorted(candidates, key=lambda x: x['votes'], reverse=True):
                print(f"  分析 {candidate['agent_id']}: {candidate['votes']} 票")
           
            min_votes = min(c['votes'] for c in candidates)
            eliminated = [c for c in candidates if c['votes'] == min_votes]
           
            if len(eliminated) == len(candidates):
                eliminated = [random.choice(candidates)]
           
            if len(eliminated) > 1:
                eliminated = [random.choice(eliminated)]
           
            print(f"\n❌ 淘汰分析 {eliminated[0]['agent_id']} (得票 {eliminated[0]['votes']})")
           
            candidates = [c for c in candidates if c['agent_id'] != eliminated[0]['agent_id']]
           
            round_num += 1
       
        winner = candidates[0]
        print(f"\n{'='*80}")
        print(f"✓ 投票结束！最佳分析: 专家 #{winner['agent_id']}")
        print(f"{'='*80}")
        print(f"\n最终共识:")
        print(winner['response'])
       
        return winner['response']


class APKAnalysisOrchestrator:
    """APK分析编排器"""
   
    def __init__(self, models: List[str], apk_path: str, requirements: str = "", 
                 enable_decompile: bool = False, output_dir: str = None, base_url: str = "http://127.0.0.1:11434", 
                 analyze_db: bool = False):
        self.models = models
        self.apk_path = apk_path
        self.requirements = requirements
        self.enable_decompile = enable_decompile
        self.output_dir = output_dir
        self.base_url = base_url
        self.analyze_db = analyze_db
        self.extractor = APKExtractor(apk_path, enable_decompile, output_dir, analyze_db)
        self.apk_info = {}
        self.analysis_results = []
        self.packer_info = {}
        self.obfuscation_info = {}
        self.decompile_info = {}
        self.code_logic_info = {}
       
    async def analyze_packer_and_obfuscation(self) -> Dict[str, Any]:
        """分析0: 加壳与混淆检测"""
        print("\n" + "="*80)
        print("阶段 0: 加壳与混淆检测")
        print("="*80)
       
        # 执行检测
        self.packer_info = self.extractor.detect_packer()
        self.obfuscation_info = self.extractor.detect_obfuscation()
       
        # 如果启用了反编译，执行反编译
        if self.enable_decompile:
            self.decompile_info = self.extractor.decompile_apk()
       
        team = AITeam(0, "加壳与混淆分析专家", self.models, self.base_url)
       
        task = f"""
请分析以下APK的加壳与混淆情况:

【加壳检测结果】
- 是否加壳: {self.packer_info.get('is_packed', False)}
- 加壳方案: {self.packer_info.get('packer_name', '无')}
- 置信度: {self.packer_info.get('confidence', 0)}%
- 脱壳难度: {self.packer_info.get('difficulty', '未知')}
- 检测指标: {', '.join(self.packer_info.get('indicators', []))}

【混淆检测结果】
- 是否混淆: {self.obfuscation_info.get('is_obfuscated', False)}
- 混淆等级: {self.obfuscation_info.get('obfuscation_level', 0)}/10
- 标识符混淆: {self.obfuscation_info.get('identifier_obfuscation', False)}
- 字符串加密: {self.obfuscation_info.get('string_encryption', False)}
- 控制流混淆: {self.obfuscation_info.get('control_flow_obfuscation', False)}

【反编译情况】
- 反编译启用: {self.enable_decompile}
- 反编译成功: {self.decompile_info.get('success', False)}
- 反编译方法: {self.decompile_info.get('method', '未执行')}
- Java源文件数: {len(self.decompile_info.get('java_sources', []))}
- Smali源文件数: {len(self.decompile_info.get('smali_sources', []))}

请从以下角度进行分析:

1. **加壳技术评估**:
   - 加壳方案的特点和强度
   - 脱壳的难度和方法建议
   - 加壳对逆向分析的影响

2. **混淆技术评估**:
   - 混淆方案的类型（ProGuard/R8/DexGuard等）
   - 混淆强度和覆盖范围
   - 反混淆的难度和策略

3. **综合保护评估**:
   - 加壳+混淆的组合效果
   - 整体保护强度评分
   - 逆向工程的切入点

4. **分析建议**:
   - 推荐的分析工具和方法
   - 绕过保护的策略
   - 需要注意的难点
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供专业的加壳与混淆分析报告。\n"
       
        result = await team.collaborate(task, json.dumps({
            "packer": self.packer_info,
            "obfuscation": self.obfuscation_info,
            "decompile": self.decompile_info
        }, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_structure_and_metadata(self) -> Dict[str, Any]:
        """分析1: APK构成与元数据"""
        print("\n" + "="*80)
        print("阶段 1: APK构成与元数据分析")
        print("="*80)
       
        team = AITeam(1, "APK结构与元数据分析专家", self.models, self.base_url)
       
        task = f"""
请深入分析以下APK的构成与元数据:

【基本信息】
- APK路径: {self.apk_info['apk_path']}
- 包名: {self.apk_info['manifest'].get('package_name', '未知')}
- 版本: {self.apk_info['manifest'].get('version_name', '未知')} ({self.apk_info['manifest'].get('version_code', '未知')})
- 最小SDK: {self.apk_info['manifest'].get('min_sdk', '未知')}
- 目标SDK: {self.apk_info['manifest'].get('target_sdk', '未知')}

【文件结构】
- 总文件数: {len(self.apk_info['structure']['file_list'])}
- DEX文件数: {len(self.apk_info['structure']['dex_files'])}
- Native库数: {len(self.apk_info['structure']['so_files'])}
- 总大小: {round(self.apk_info['structure']['total_size'] / 1024 / 1024, 2)} MB

【权限列表】
{chr(10).join('- ' + p for p in self.apk_info['manifest'].get('permissions', [])[:20])}
{'...(还有更多)' if len(self.apk_info['manifest'].get('permissions', [])) > 20 else ''}

【签名信息】
- 已签名: {self.apk_info['signature']['signed']}
- 证书文件: {', '.join(self.apk_info['signature']['certificates'])}

【资源信息】
- 布局文件: {self.apk_info['resources']['layout_count']}
- 图像资源: {self.apk_info['resources']['drawable_count']}
- Assets文件: {len(self.apk_info['resources']['asset_files'])}

请从以下角度进行深入分析:
1. **AndroidManifest.xml分析**: 组件声明的合理性、权限使用的必要性、intent-filter的安全性
2. **resources.arsc**: 资源组织结构、本地化支持、资源保护措施
3. **DEX文件**: 多DEX策略、方法数评估、MultiDex使用
4. **Native库**: 架构支持、库的用途推测、潜在的安全考虑
5. **签名与证书**: 签名版本、证书链完整性、防篡改机制
6. **Assets**: 特殊资源、配置文件、潜在的动态内容
7. **整体评估**: 应用规模、复杂度、可能的技术栈
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供专业、详细的分析报告。\n"
       
        result = await team.collaborate(task, "")
        self.analysis_results.append(result)
        return result
   
    async def analyze_static_code_structure(self) -> Dict[str, Any]:
        """分析2: 静态代码结构与语义"""
        print("\n" + "="*80)
        print("阶段 2: 静态代码结构与语义分析")
        print("="*80)
       
        team = AITeam(2, "静态代码分析专家", self.models, self.base_url)
       
        task = f"""
基于APK的代码结构信息，请进行静态代码分析:

【DEX信息】
- DEX文件数: {self.apk_info['dex']['count']}
- DEX总大小: {round(self.apk_info['dex']['total_size'] / 1024 / 1024, 2)} MB
- 估计方法数: {self.apk_info['dex']['estimated_methods']}
- DEX文件列表: {', '.join([d['name'] for d in self.apk_info['dex']['files']])}

【Native代码】
- 支持架构: {', '.join(self.apk_info['native']['architectures'].keys())}
- 库文件数: {len(self.apk_info['native']['libraries'])}
- Native代码总大小: {round(self.apk_info['native']['total_size'] / 1024 / 1024, 2)} MB

请从以下维度进行深入分析:

1. **DEX结构分析**:
   - 单DEX vs 多DEX策略
   - 方法数是否接近64K限制
   - DEX分包策略评估
   - 可能的代码组织方式

2. **代码语义推断**:
   - 从权限推断主要功能模块
   - 可能的第三方SDK（广告、统计、支付等）
   - 数据流向（敏感源→汇聚点）
   - API使用模式

3. **调用关系推测**:
   - 可能的控制流结构
   - 模块间调用关系
   - 潜在的热点代码

4. **库识别**:
   - 从文件名推测使用的第三方库
   - 常见框架识别（如Retrofit、OkHttp、Gson等）
   - Native库的可能用途

5. **复杂度评估**:
   - 代码规模评估
   - 维护复杂度
   - 潜在的代码质量问题
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供详细的静态分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_obfuscation_hardening(self) -> Dict[str, Any]:
        """分析3: 混淆与加固"""
        print("\n" + "="*80)
        print("阶段 3: 混淆与加固分析")
        print("="*80)
       
        team = AITeam(3, "代码混淆与加固分析专家", self.models, self.base_url)
       
        task = f"""
请分析APK可能采用的混淆与加固技术:

【基础信息】
- 包名: {self.apk_info['manifest'].get('package_name', '未知')}
- DEX文件数: {self.apk_info['dex']['count']}
- Native库: {len(self.apk_info['native']['libraries'])} 个
- 签名方案: {', '.join(self.apk_info['signature']['signature_versions'])}

【文件结构特征】
- 多DEX: {'是' if self.apk_info['dex']['count'] > 1 else '否'}
- Native代码占比: {round(self.apk_info['native']['total_size'] / self.apk_info['structure']['total_size'] * 100, 2)}%

请从以下角度分析可能的混淆与加固技术:

1. **代码混淆指标**:
   - ProGuard/R8混淆可能性
   - 标识符重命名程度推测
   - 字符串加密可能性
   - 控制流混淆迹象

2. **加固技术推测**:
   - DEX加壳可能性
   - 动态加载特征
   - Native层保护
   - 类加载器定制

3. **反调试机制**:
   - 可能的反调试检测
   - 完整性校验
   - 时间检测
   - 环境检测

4. **代码保护程度**:
   - 整体保护强度评估
   - 关键代码保护策略
   - 可能的加固方案（360、腾讯等）

5. **分析难度评估**:
   - 静态分析难度
   - 动态分析难度
   - 逆向工程复杂度
   - 建议的分析策略
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供专业的混淆与加固分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_dynamic_behavior(self) -> Dict[str, Any]:
        """分析4: 动态行为与运行时特征"""
        print("\n" + "="*80)
        print("阶段 4: 动态行为与运行时特征分析")
        print("="*80)
       
        team = AITeam(4, "动态行为分析专家", self.models, self.base_url)
       
        task = f"""
请分析APK可能的动态行为和运行时特征:

【权限分析】
{chr(10).join('- ' + p for p in self.apk_info['manifest'].get('permissions', []))}

【Native库信息】
支持架构: {', '.join(self.apk_info['native']['architectures'].keys())}
库列表: {', '.join([lib['name'] for lib in self.apk_info['native']['libraries']])}

【Assets文件】
{chr(10).join('- ' + f for f in self.apk_info['resources']['asset_files'][:20])}

请从以下维度进行分析:

1. **运行时API调用预测**:
   - 基于权限推测的API调用
   - 敏感API使用（位置、相机、存储等）
   - 系统服务访问
   - 反射使用可能性

2. **动态代码加载**:
   - DexClassLoader使用可能
   - 插件化框架迹象
   - 热修复机制
   - 远程代码执行风险

3. **JNI边界分析**:
   - Java-Native交互模式
   - 关键逻辑在Native层的可能性
   - JNI函数调用模式
   - 跨语言数据传递

4. **进程与线程行为**:
   - 多进程架构可能性
   - 后台服务运行
   - 异步任务处理
   - 并发访问模式

5. **文件与数据库访问**:
   - SharedPreferences使用
   - SQLite数据库
   - 外部存储访问
   - 内部存储策略

6. **IPC机制**:
   - Broadcast使用
   - ContentProvider
   - BoundService
   - 跨应用通信

7. **动态分析建议**:
   - Hook点推荐
   - 监控重点
   - Frida脚本思路
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供详细的动态行为分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_native_code(self) -> Dict[str, Any]:
        """分析5: Native库与本地代码"""
        print("\n" + "="*80)
        print("阶段 5: Native库与本地代码分析")
        print("="*80)
       
        team = AITeam(5, "Native代码分析专家", self.models, self.base_url)
       
        task = f"""
请深入分析APK的Native库与本地代码:

【Native库详情】
支持的架构: {', '.join(self.apk_info['native']['architectures'].keys())}
总库数: {len(self.apk_info['native']['libraries'])}
Native代码总大小: {round(self.apk_info['native']['total_size'] / 1024 / 1024, 2)} MB
Native代码占比: {round(self.apk_info['native']['total_size'] / self.apk_info['structure']['total_size'] * 100, 2)}%

【各架构库列表】
{chr(10).join(f"{arch}: {', '.join([lib['name'] for lib in libs])}" for arch, libs in self.apk_info['native']['architectures'].items())}

请从以下角度进行分析:

1. **库功能推测**:
   - 从库名推测功能（加密、网络、音视频等）
   - 第三方Native SDK识别
   - 核心业务逻辑在Native层的可能性
   - 游戏引擎识别（Unity、Cocos2d-x、Unreal等）

2. **架构支持分析**:
   - 支持的CPU架构及其意义
   - 32位vs64位支持
   - ABI兼容性
   - 架构选择策略

3. **安全机制推测**:
   - 关键算法Native化
   - 加密/签名验证
   - 反调试技术
   - 代码保护措施

4. **二进制分析策略**:
   - IDA Pro分析建议
   - 符号恢复难度
   - 关键函数定位
   - 交叉引用分析

5. **JNI交互分析**:
   - JNI_OnLoad分析重点
   - 注册的Native方法推测
   - Java-Native数据交换
   - 回调机制

6. **性能与优化**:
   - Native代码使用的合理性
   - 性能关键路径
   - 内存管理策略
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供专业的Native代码分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_network_protocol(self) -> Dict[str, Any]:
        """分析6: 网络与协议语义"""
        print("\n" + "="*80)
        print("阶段 6: 网络与协议语义分析")
        print("="*80)
       
        team = AITeam(6, "网络协议分析专家", self.models, self.base_url)
       
        task = f"""
请分析APK的网络通信与协议特征:

【网络权限】
{chr(10).join('- ' + p for p in self.apk_info['manifest'].get('permissions', []) if 'INTERNET' in p or 'NETWORK' in p)}

【相关库推测】
Native库: {', '.join([lib['name'] for lib in self.apk_info['native']['libraries'] if any(keyword in lib['name'].lower() for keyword in ['ssl', 'crypto', 'curl', 'http', 'net'])])}

【Assets中的配置】
{chr(10).join('- ' + f for f in self.apk_info['resources']['asset_files'] if any(ext in f.lower() for ext in ['.json', '.xml', '.conf', '.pem', '.crt']))}

请从以下角度进行分析:

1. **网络通信模式**:
   - HTTP/HTTPS使用预测
   - WebSocket可能性
   - 自定义协议迹象
   - 长连接vs短连接

2. **加密与安全**:
   - SSL/TLS使用
   - 证书固定（Certificate Pinning）
   - 双向认证可能性
   - 加密算法推测

3. **API通信模式**:
   - RESTful API
   - GraphQL
   - Protocol Buffers
   - 自定义序列化

4. **数据传输分析**:
   - 明文传输风险
   - 敏感数据加密
   - 数据压缩策略
   - 传输优化

5. **后端架构推测**:
   - API设计模式
   - 认证机制（Token、OAuth等）
   - 会话管理
   - CDN使用

6. **隐私与合规**:
   - 数据上传范围
   - 用户追踪
   - 第三方数据共享
   - GDPR/隐私合规

7. **抓包分析建议**:
   - 抓包工具选择
   - 证书绕过策略
   - 关键接口识别
   - 流量重放测试
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供详细的网络协议分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_signature_integrity(self) -> Dict[str, Any]:
        """分析7: 签名、完整性与更新机制"""
        print("\n" + "="*80)
        print("阶段 7: 签名、完整性与更新机制分析")
        print("="*80)
       
        team = AITeam(7, "应用安全与完整性专家", self.models, self.base_url)
       
        task = f"""
请分析APK的签名、完整性保护与更新机制:

【签名信息】
已签名: {self.apk_info['signature']['signed']}
证书文件: {', '.join(self.apk_info['signature']['certificates'])}
签名版本: {', '.join(self.apk_info['signature']['signature_versions'])}

【应用信息】
包名: {self.apk_info['manifest'].get('package_name', '未知')}
版本号: {self.apk_info['manifest'].get('version_code', '未知')}
版本名: {self.apk_info['manifest'].get('version_name', '未知')}

请从以下角度进行分析:

1. **签名策略分析**:
   - 签名方案版本（v1/v2/v3/v4）
   - 签名强度评估
   - 证书链分析
   - 签名者身份推测

2. **完整性保护**:
   - APK篡改检测机制
   - 自校验实现可能性
   - 代码完整性验证
   - 资源完整性保护

3. **重打包风险**:
   - 重签名难度
   - 签名校验绕过可能性
   - 重打包检测机制
   - 防二次打包措施

4. **更新机制**:
   - 应用内更新
   - 增量更新可能性
   - 更新安全性
   - 降级攻击防护

5. **中间人攻击防护**:
   - 更新通道安全性
   - 更新包验证
   - 回滚保护
   - 强制更新机制

6. **证书管理**:
   - 证书有效期
   - 密钥管理策略
   - 证书吊销机制
   - 应用迁移考虑

7. **安全建议**:
   - 签名加固建议
   - 完整性保护增强
   - 更新机制改进
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供专业的签名与完整性分析报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_anti_analysis(self) -> Dict[str, Any]:
        """分析8: 反调试与反分析机制"""
        print("\n" + "="*80)
        print("阶段 8: 反调试与反分析机制分析")
        print("="*80)
       
        team = AITeam(8, "反调试与对抗技术专家", self.models, self.base_url)
       
        task = f"""
请分析APK可能采用的反调试与反分析技术:

【基础信息】
Native库数: {len(self.apk_info['native']['libraries'])}
DEX文件数: {self.apk_info['dex']['count']}
加固迹象: {'多DEX+Native代码' if self.apk_info['dex']['count'] > 1 and len(self.apk_info['native']['libraries']) > 3 else '较少'}

【权限分析】
系统级权限: {chr(10).join('- ' + p for p in self.apk_info['manifest'].get('permissions', []) if any(keyword in p for keyword in ['SYSTEM', 'DEBUG', 'INSTALL']))}

请从以下角度进行深入分析:

1. **反调试技术**:
   - ptrace检测
   - TracerPid检测
   - 调试端口检测
   - 时间检测（TOCTOU）
   - 断点检测

2. **反模拟器/沙箱**:
   - 模拟器特征检测
   - 硬件特征验证
   - 传感器检测
   - Build.FINGERPRINT检测
   - 环境指纹识别

3. **反Hook/注入**:
   - Frida检测
   - Xposed检测
   - 系统API Hook检测
   - 内存完整性检查
   - PLT/GOT保护

4. **反静态分析**:
   - 代码混淆深度
   - 字符串加密
   - 反编译对抗
   - JDWP保护
   - 调试信息清理

5. **完整性检查**:
   - 签名校验
   - CRC/Hash校验
   - DEX完整性
   - SO文件校验
   - 资源文件校验

6. **环境检测**:
   - Root检测
   - 越狱检测
   - 危险应用检测
   - VPN/代理检测
   - 网络环境验证

7. **对抗强度评估**:
   - 整体对抗等级
   - 绕过难度评分
   - 薄弱环节识别
   - 绕过策略建议

8. **分析工具建议**:
   - 推荐的分析工具
   - 绕过技术路线
   - 自动化分析可行性
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供详细的反调试与反分析评估报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_code_logic_and_modifiable_points(self) -> Dict[str, Any]:
        """分析9: 代码逻辑分析与可修改点识别"""
        print("\n" + "="*80)
        print("阶段 9: 代码逻辑分析与可修改点识别")
        print("="*80)
       
        # 执行代码逻辑分析
        self.code_logic_info = self.extractor.analyze_code_logic(self.decompile_info)
       
        team = AITeam(9, "代码逻辑分析与修改建议专家", self.models, self.base_url)
       
        task = f"""
请基于反编译结果分析APK的代码逻辑和可修改点:

【入口点分析】
发现 {len(self.code_logic_info.get('entry_points', []))} 个入口点:
{chr(10).join(f"- {ep.get('type')}: {ep.get('name')}" for ep in self.code_logic_info.get('entry_points', [])[:20])}

【关键类】
{chr(10).join(f"- {cls}" for cls in self.code_logic_info.get('key_classes', [])[:20])}

【敏感方法】
发现 {len(self.code_logic_info.get('sensitive_methods', []))} 个敏感方法:
{chr(10).join(f"- {sm.get('category')}: {sm.get('keyword')} ({sm.get('file')})" for sm in self.code_logic_info.get('sensitive_methods', [])[:20])}

【可修改点】
{chr(10).join(f"- {mp.get('point')}: {mp.get('description')}" for mp in self.code_logic_info.get('modifiable_points', []))}

【Hook建议】
{chr(10).join(f"- {hs.get('target')}: {hs.get('reason')}" for hs in self.code_logic_info.get('hook_suggestions', []))}

请从以下角度进行深入分析:

1. **代码架构分析**:
   - 应用的整体架构模式
   - 模块划分和职责
   - 关键业务流程

2. **敏感操作识别**:
   - 网络通信实现细节
   - 数据加密和存储方式
   - 权限使用和敏感API调用
   - 安全检测机制

3. **可修改点详细分析**:
   - 每个修改点的具体位置
   - 修改的技术方案
   - 修改的风险和难度
   - 修改后的影响范围

4. **Hook方案设计**:
   - Frida Hook脚本建议
   - Hook时机和顺序
   - 需要Hook的具体方法
   - Hook可能遇到的问题

5. **逆向工程路线**:
   - 分析的切入点
   - 关键代码定位方法
   - 动静态结合分析策略
   - 调试和测试方法

6. **修改实施建议**:
   - 重打包流程
   - 签名处理
   - 防检测措施
   - 测试验证方法
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请提供详细的代码逻辑分析和修改建议报告。\n"
       
        result = await team.collaborate(task, json.dumps(self.code_logic_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def generate_comprehensive_report(self) -> Dict[str, Any]:
        """生成综合分析报告"""
        print("\n" + "="*80)
        print("阶段 10: 综合分析报告生成")
        print("="*80)
       
        team = AITeam(10, "安全分析总结专家", self.models, self.base_url)
       
        # 汇总所有分析结果
        all_analyses = "\n\n".join([
            f"## {result['role']}\n{result['consensus']}"
            for result in self.analysis_results
        ])
       
        task = f"""
基于以下多个维度的深入分析结果，请生成一份综合性的APK安全分析报告:

{all_analyses}

请在综合报告中包含:

1. **执行摘要**:
   - 应用基本信息概述
   - 关键发现总结
   - 风险等级评估
   - 核心建议

2. **技术架构总览**:
   - 整体架构评估
   - 技术栈识别
   - 开发质量评价

3. **安全态势分析**:
   - 安全机制总结
   - 主要安全风险
   - 隐私保护评估
   - 合规性分析

4. **代码保护评估**:
   - 加壳检测结果: {self.packer_info.get('packer_name', '无')}
   - 混淆等级: {self.obfuscation_info.get('obfuscation_level', 0)}/10
   - 反调试能力
   - 逆向工程难度

5. **动态行为综述**:
   - 运行时行为总结
   - 敏感操作汇总
   - 潜在风险点

6. **代码逻辑与可修改点**:
   - 入口点数量: {len(self.code_logic_info.get('entry_points', []))}
   - 敏感方法数量: {len(self.code_logic_info.get('sensitive_methods', []))}
   - 可修改点列表: {', '.join([mp.get('point', '') for mp in self.code_logic_info.get('modifiable_points', [])])}
   - Hook建议数量: {len(self.code_logic_info.get('hook_suggestions', []))}

7. **建议与改进**:
   - 安全加固建议
   - 隐私保护改进
   - 合规性建议
   - 最佳实践推荐

8. **渗透测试路线**:
   - 分析切入点
   - 测试方法建议
   - 工具选择推荐
   - 预期挑战

9. **脱壳/去混淆建议**:
   - 脱壳方法和工具
   - 去混淆策略
   - 预期难度和时间

10. **评分矩阵**:
   - 安全性评分 (1-10)
   - 隐私保护评分 (1-10)
   - 代码质量评分 (1-10)
   - 逆向难度评分 (1-10)
   - 整体评级
"""
       
        if self.requirements:
            task += f"\n\n【分析需求方向】\n{self.requirements}\n"
       
        task += "\n请生成一份专业、全面、有深度的综合分析报告。\n"
       
        result = await team.collaborate(task, all_analyses)
        self.analysis_results.append(result)
        return result
   
    async def orchestrate(self):
        """编排整个分析流程"""
        print("\n" + "🔍" * 40)
        print("APK多维度安全分析系统启动")
        print("🔍" * 40)
       
        # 步骤1: 提取APK信息
        self.apk_info = self.extractor.extract_all()
       
        # 步骤2: 执行阶段0 - 加壳与混淆检测（必须在extract_all之后）
        # 这个阶段需要先执行，因为它会进行反编译，我们需要知道反编译是否成功
        print("\n执行阶段 0: 加壳与混淆检测...")
        try:
            await self.analyze_packer_and_obfuscation()
        except Exception as e:
            print(f"\n❌ 错误: 加壳与混淆检测失败: {e}")
            traceback.print_exc()
       
        # 步骤3: 定义后续分析阶段
        stages = [
            ("APK构成与元数据", self.analyze_structure_and_metadata),
            ("静态代码结构", self.analyze_static_code_structure),
            ("混淆与加固", self.analyze_obfuscation_hardening),
            ("动态行为", self.analyze_dynamic_behavior),
            ("Native代码", self.analyze_native_code),
            ("网络协议", self.analyze_network_protocol),
            ("签名完整性", self.analyze_signature_integrity),
            ("反调试机制", self.analyze_anti_analysis),
        ]
       
        # 如果启用了反编译且成功，添加代码逻辑分析阶段
        if self.enable_decompile and self.decompile_info.get('success'):
            stages.append(("代码逻辑与可修改点", self.analyze_code_logic_and_modifiable_points))
       
        # 添加综合报告生成阶段
        stages.append(("综合报告生成", self.generate_comprehensive_report))
       
        # 步骤4: 使用进度条执行后续分析
        total_stages = 1 + len(stages)  # 1 for stage 0 already executed
        with tqdm(total=total_stages, desc="APK分析进度", unit="阶段", initial=1) as pbar:
            for stage_name, stage_func in stages:
                try:
                    pbar.set_description(f"正在分析: {stage_name}")
                    await stage_func()
                    pbar.update(1)
                except Exception as e:
                    print(f"\n❌ 错误: {stage_name} 分析失败: {e}")
                    traceback.print_exc()
                    # 继续执行下一个阶段
                    pbar.update(1)
       
        # 步骤5: 保存结果
        self.save_results()
       
        # 清理临时文件
        self.extractor.cleanup()
       
        print("\n" + "✅" * 40)
        print("APK分析完成！")
        print("✅" * 40)
   
    def save_results(self):
        """保存分析结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        apk_name = Path(self.apk_path).stem
       
        # 确定输出目录
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            output_file = os.path.join(self.output_dir, f"apk_analysis_{apk_name}_{timestamp}.json")
            markdown_file = os.path.join(self.output_dir, f"apk_analysis_{apk_name}_{timestamp}.md")
        else:
            output_file = f"apk_analysis_{apk_name}_{timestamp}.json"
            markdown_file = f"apk_analysis_{apk_name}_{timestamp}.md"
       
        output_data = {
            "apk_info": self.apk_info,
            "packer_info": self.packer_info,
            "obfuscation_info": self.obfuscation_info,
            "decompile_info": self.decompile_info,
            "code_logic_info": self.code_logic_info,
            "analysis_results": self.analysis_results,
            "timestamp": datetime.now().isoformat(),
            "models_used": self.models
        }
       
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            print(f"\n✓ JSON报告已保存到: {output_file}")
        except Exception as e:
            print(f"\n✗ 保存JSON失败: {e}")
       
        # 保存Markdown格式
        try:
            with open(markdown_file, 'w', encoding='utf-8') as f:
                f.write(f"# APK深度安全分析报告\n\n")
                f.write(f"**APK文件:** {self.apk_path}\n")
                f.write(f"**分析时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**使用模型:** {', '.join(self.models)}\n\n")
               
                f.write(f"---\n\n")
                f.write(f"## 应用基本信息\n\n")
                f.write(f"- **包名:** {self.apk_info['manifest'].get('package_name', '未知')}\n")
                f.write(f"- **版本:** {self.apk_info['manifest'].get('version_name', '未知')} ({self.apk_info['manifest'].get('version_code', '未知')})\n")
                f.write(f"- **最小SDK:** {self.apk_info['manifest'].get('min_sdk', '未知')}\n")
                f.write(f"- **目标SDK:** {self.apk_info['manifest'].get('target_sdk', '未知')}\n")
                f.write(f"- **APK大小:** {round(self.apk_info['structure']['total_size'] / 1024 / 1024, 2)} MB\n\n")
               
                # 加壳检测结果
                f.write(f"## 加壳检测\n\n")
                f.write(f"- **是否加壳:** {self.packer_info.get('is_packed', False)}\n")
                if self.packer_info.get('is_packed'):
                    f.write(f"- **加壳方案:** {self.packer_info.get('packer_name', '未知')}\n")
                    f.write(f"- **置信度:** {self.packer_info.get('confidence', 0)}%\n")
                    f.write(f"- **脱壳难度:** {self.packer_info.get('difficulty', '未知')}\n")
                f.write(f"\n")
               
                # 混淆检测结果
                f.write(f"## 混淆检测\n\n")
                f.write(f"- **是否混淆:** {self.obfuscation_info.get('is_obfuscated', False)}\n")
                f.write(f"- **混淆等级:** {self.obfuscation_info.get('obfuscation_level', 0)}/10\n")
                f.write(f"- **标识符混淆:** {self.obfuscation_info.get('identifier_obfuscation', False)}\n")
                f.write(f"- **字符串加密:** {self.obfuscation_info.get('string_encryption', False)}\n\n")
               
                # 代码逻辑分析结果
                if self.code_logic_info:
                    f.write(f"## 代码逻辑分析\n\n")
                    f.write(f"- **入口点数量:** {len(self.code_logic_info.get('entry_points', []))}\n")
                    f.write(f"- **关键类数量:** {len(self.code_logic_info.get('key_classes', []))}\n")
                    f.write(f"- **敏感方法数量:** {len(self.code_logic_info.get('sensitive_methods', []))}\n")
                    f.write(f"- **可修改点数量:** {len(self.code_logic_info.get('modifiable_points', []))}\n")
                    f.write(f"- **Hook建议数量:** {len(self.code_logic_info.get('hook_suggestions', []))}\n\n")
                   
                    if self.code_logic_info.get('modifiable_points'):
                        f.write(f"### 可修改点列表\n\n")
                        for mp in self.code_logic_info.get('modifiable_points', []):
                            f.write(f"- **{mp.get('point')}**: {mp.get('description')} (难度: {mp.get('difficulty')})\n")
                        f.write(f"\n")
                   
                    if self.code_logic_info.get('hook_suggestions'):
                        f.write(f"### Hook建议\n\n")
                        for hs in self.code_logic_info.get('hook_suggestions', []):
                            f.write(f"- **{hs.get('target')}**: {hs.get('reason')}\n")
                        f.write(f"\n")
                
                # 数据库分析结果
                if self.analyze_db and 'database_analysis' in self.apk_info:
                    db_analysis = self.apk_info['database_analysis']
                    f.write(f"## 数据库分析\n\n")
                    f.write(f"- **数据库文件数量:** {db_analysis.get('total_databases', 0)}\n\n")
                    
                    if db_analysis.get('total_databases', 0) > 0:
                        f.write(f"### 找到的数据库文件\n\n")
                        f.write(f"| 文件名 | 路径 | 大小 | 表数量 | 记录数 |\n")
                        f.write(f"|--------|------|------|--------|--------|\n")
                        
                        for db in db_analysis.get('databases', []):
                            db_name = os.path.basename(db.get('path', ''))
                            db_path = db.get('path', '')
                            # Format size
                            size_bytes = db.get('size', 0)
                            if size_bytes >= 1024 * 1024:
                                db_size = f"{size_bytes / (1024 * 1024):.2f} MB"
                            elif size_bytes >= 1024:
                                db_size = f"{size_bytes / 1024:.2f} KB"
                            else:
                                db_size = f"{size_bytes} bytes"
                            table_count = len(db.get('tables', []))
                            total_records = db.get('total_records', 0)
                            f.write(f"| {db_name} | {db_path} | {db_size} | {table_count} | {total_records} |\n")
                        
                        f.write(f"\n")
                        
                        # 详细分析每个数据库
                        for db in db_analysis.get('databases', []):
                            db_name = os.path.basename(db.get('path', ''))
                            f.write(f"### {db_name} 详细分析\n\n")
                            
                            if db.get('error'):
                                f.write(f"**错误:** {db.get('error')}\n\n")
                                continue
                            
                            for table in db.get('tables', []):
                                table_name = table.get('name', '')
                                f.write(f"#### 表: {table_name}\n")
                                f.write(f"- 列数: {len(table.get('columns', []))}\n")
                                f.write(f"- 记录数: {table.get('row_count', 0)}\n\n")
                                
                                # 表结构
                                if table.get('columns'):
                                    # 检查是否有敏感列
                                    sensitive_cols = [s['column'] for s in db.get('sensitive_data', []) if s['table'] == table_name]
                                    
                                    f.write(f"| 列名 | 类型 | 敏感 |\n")
                                    f.write(f"|------|------|------|\n")
                                    for col in table.get('columns', []):
                                        is_sensitive = "⚠️" if col['name'] in sensitive_cols else "❌"
                                        f.write(f"| {col['name']} | {col['type']} | {is_sensitive} |\n")
                                    f.write(f"\n")
                                
                                # 样本数据（脱敏处理）
                                if table.get('sample_data') and len(table.get('sample_data', [])) > 0:
                                    f.write(f"##### 样本数据（前5行，已脱敏）\n\n")
                                    
                                    columns = table.get('columns', [])
                                    sample_data = table.get('sample_data', [])[:5]
                                    
                                    # 表头
                                    f.write(f"| {' | '.join([col['name'] for col in columns])} |\n")
                                    f.write(f"|{'|'.join(['---' for _ in columns])}|\n")
                                    
                                    # 数据行（脱敏处理）
                                    for row in sample_data:
                                        masked_row = []
                                        for i, col in enumerate(columns):
                                            value = row[i] if i < len(row) else ''
                                            # 对敏感列进行脱敏
                                            if col['name'] in sensitive_cols:
                                                masked_row.append('[REDACTED]')
                                            elif value is None:
                                                masked_row.append('NULL')
                                            elif isinstance(value, str) and len(value) > 20:
                                                masked_row.append(value[:10] + '...')
                                            else:
                                                masked_row.append(str(value))
                                        f.write(f"| {' | '.join(masked_row)} |\n")
                                    f.write(f"\n")
                            
                            # 敏感数据汇总
                            if db.get('sensitive_data'):
                                f.write(f"#### 敏感数据检测\n\n")
                                f.write(f"发现 {len(db.get('sensitive_data', []))} 个敏感字段:\n\n")
                                for sensitive in db.get('sensitive_data', []):
                                    f.write(f"- **{sensitive.get('table')}.{sensitive.get('column')}** (关键词: {sensitive.get('keyword')})\n")
                                f.write(f"\n")
                
                f.write(f"---\n\n")
               
                for result in self.analysis_results:
                    f.write(f"## {result['role']}\n\n")
                    f.write(f"{result['consensus']}\n\n")
                    f.write(f"---\n\n")
           
            print(f"✓ Markdown报告已保存到: {markdown_file}")
        except Exception as e:
            print(f"✗ 保存Markdown失败: {e}")


async def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='APK多维度安全分析系统 - 基于多智能体AI协作',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 基本分析（交互选择模型）
  python apk.py --apk app.apk

  # 指定模型
  python apk.py --apk app.apk --model qwen2.5-coder:7b

  # 启用反编译分析
  python apk.py --apk app.apk --model qwen2.5-coder:7b --decompile

  # 导入需求文件
  python apk.py --apk app.apk --model qwen2.5-coder:7b --txt requirements.txt

  # 完整分析
  python apk.py --apk app.apk --model qwen2.5-coder:7b --decompile --txt requirements.txt --output-dir ./output

  # 启用数据库分析
  python apk.py --apk app.apk --model qwen2.5-coder:7b --analyze-db

注意: 需要安装以下工具以获得更完整的分析结果:
  - aapt (Android Asset Packaging Tool)
  - jadx (APK反编译为Java代码，使用 --decompile 时需要)
  - apktool (APK反编译为Smali代码，使用 --decompile 时需要)
        """
    )
   
    parser.add_argument('--apk', required=True, help='APK文件路径')
    parser.add_argument('--model', help='指定要使用的Ollama模型（可选）')
    parser.add_argument('--txt', help='需求方向文件路径（可选）')
    parser.add_argument('--decompile', action='store_true', help='启用反编译分析')
    parser.add_argument('--analyze-db', action='store_true', help='启用数据库深度分析')
    parser.add_argument('--output-dir', help='输出目录（可选）')
    parser.add_argument('--ollama-url', default='http://127.0.0.1:11434', help='Ollama API地址（默认: http://127.0.0.1:11434）')
   
    args = parser.parse_args()
   
    # 检查APK文件
    if not os.path.exists(args.apk):
        print(f"❌ 错误: APK文件不存在: {args.apk}")
        sys.exit(1)
   
    # 读取需求文件
    requirements = ""
    if args.txt:
        if not os.path.exists(args.txt):
            print(f"❌ 错误: 需求文件不存在: {args.txt}")
            sys.exit(1)
        try:
            with open(args.txt, 'r', encoding='utf-8') as f:
                requirements = f.read()
            print(f"✓ 已加载需求文件: {args.txt}")
        except Exception as e:
            print(f"❌ 错误: 无法读取需求文件: {e}")
            sys.exit(1)
   
    # 处理模型选择
    model = None
    if args.model:
        # 用户指定了模型，验证模型是否存在
        available_models = get_ollama_models(args.ollama_url)
        if not available_models:
            print("⚠️  警告: 无法获取模型列表，将尝试使用指定的模型")
            model = args.model
        elif args.model in available_models:
            model = args.model
            print(f"✓ 使用指定模型: {model}")
        else:
            print(f"❌ 错误: 模型 '{args.model}' 不存在")
            print(f"可用的模型列表:")
            for i, m in enumerate(available_models, 1):
                print(f"  {i}. {m}")
            sys.exit(1)
    else:
        # 用户未指定模型，显示列表让用户选择
        available_models = get_ollama_models(args.ollama_url)
        if not available_models:
            print("⚠️  警告: 无法获取模型列表，使用默认模型")
            model = DEFAULT_MODEL
        else:
            print("\n可用的Ollama模型列表:")
            for i, m in enumerate(available_models, 1):
                print(f"  {i}. {m}")
            
            max_attempts = 5
            attempts = 0
            while attempts < max_attempts:
                try:
                    choice = input(f"\n请选择模型 (1-{len(available_models)}): ").strip()
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(available_models):
                        model = available_models[choice_idx]
                        print(f"✓ 已选择模型: {model}")
                        break
                    else:
                        print(f"❌ 请输入 1 到 {len(available_models)} 之间的数字")
                        attempts += 1
                except ValueError:
                    print("❌ 请输入有效的数字")
                    attempts += 1
                except (KeyboardInterrupt, EOFError):
                    print("\n\n用户取消操作")
                    sys.exit(0)
            
            if attempts >= max_attempts:
                print(f"\n❌ 错误: 超过最大尝试次数，使用默认模型")
                model = available_models[0] if available_models else DEFAULT_MODEL
                print(f"✓ 使用模型: {model}")
   
    # 创建分析编排器
    orchestrator = APKAnalysisOrchestrator(
        models=[model],
        apk_path=args.apk,
        requirements=requirements,
        enable_decompile=args.decompile,
        output_dir=args.output_dir,
        base_url=args.ollama_url,
        analyze_db=args.analyze_db
    )
   
    # 开始分析
    await orchestrator.orchestrate()


if __name__ == '__main__':
    asyncio.run(main())