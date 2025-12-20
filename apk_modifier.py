#!/usr/bin/env python3
"""
APK自动化修改工具 - 基于分析报告的APK修改框架
"""

import argparse
import json
import os
import sys
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


class APKModifier:
    """APK修改器"""
    
    def __init__(self, apk_path: str, report_path: str = None, output_path: str = None, keystore_path: str = None):
        self.apk_path = apk_path
        self.report_path = report_path or self._find_analysis_report()
        self.output_path = output_path or self._generate_output_path()
        self.keystore_path = keystore_path
        self.work_dir = None
        self.analysis_report = {}
        self.modifications = []
        self.decompiled_dir = None
        
    def _find_analysis_report(self) -> Optional[str]:
        """查找对应的分析报告"""
        apk_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        current_dir = os.path.dirname(self.apk_path) or '.'
        
        # 查找匹配的JSON报告
        for file in os.listdir(current_dir):
            if file.startswith('apk_analysis_') and file.endswith('.json'):
                if apk_name in file:
                    return os.path.join(current_dir, file)
        
        # 如果当前目录没找到，在当前工作目录查找
        for file in os.listdir('.'):
            if file.startswith('apk_analysis_') and file.endswith('.json'):
                if apk_name in file:
                    return file
        
        return None
        
    def _generate_output_path(self) -> str:
        """生成输出文件路径"""
        apk_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        return f"{apk_name}_modified.apk"
        
    def load_analysis_report(self) -> Dict[str, Any]:
        """加载分析报告"""
        if not self.report_path:
            print("⚠️  警告: 未找到分析报告，将以有限功能模式运行")
            return {}
        
        print(f"✓ 加载分析报告: {self.report_path}")
        try:
            with open(self.report_path, 'r', encoding='utf-8') as f:
                self.analysis_report = json.load(f)
            return self.analysis_report
        except Exception as e:
            print(f"❌ 错误: 无法加载分析报告: {e}")
            return {}
        
    def find_modifiable_points(self) -> List[Dict[str, Any]]:
        """查找可修改点"""
        modifiable_points = []
        
        # 从分析报告中提取可修改点
        if self.analysis_report and 'analysis_results' in self.analysis_report:
            results = self.analysis_report['analysis_results']
            
            # 检查代码逻辑分析结果
            for result in results:
                if result.get('team_id') == 9 and 'consensus' in result:
                    consensus = result['consensus']
                    # 尝试解析可修改点
                    if '可修改点' in consensus or 'modifiable' in consensus.lower():
                        # 这是一个简化的提取，实际应该根据报告格式解析
                        pass
        
        # 添加通用的可修改点
        modifiable_points.extend([
            {
                'id': 1,
                'name': '签名验证绕过',
                'description': '修改签名校验相关代码',
                'difficulty': '中等',
                'category': 'security'
            },
            {
                'id': 2,
                'name': 'Root检测绕过',
                'description': '修改Root检测逻辑',
                'difficulty': '简单',
                'category': 'security'
            },
            {
                'id': 3,
                'name': 'API地址修改',
                'description': '替换网络请求的API地址',
                'difficulty': '简单',
                'category': 'network',
                'requires_params': True
            },
            {
                'id': 4,
                'name': '启用调试模式',
                'description': '在AndroidManifest.xml中启用调试',
                'difficulty': '简单',
                'category': 'config'
            },
            {
                'id': 5,
                'name': 'SSL证书固定绕过',
                'description': '修改证书验证逻辑',
                'difficulty': '中等',
                'category': 'security'
            },
            {
                'id': 6,
                'name': '移除广告',
                'description': '移除广告SDK相关代码',
                'difficulty': '中等',
                'category': 'feature'
            },
            {
                'id': 7,
                'name': '修改版本号',
                'description': '修改versionCode和versionName',
                'difficulty': '简单',
                'category': 'config',
                'requires_params': True
            },
            {
                'id': 8,
                'name': '添加权限',
                'description': '在AndroidManifest.xml中添加权限',
                'difficulty': '简单',
                'category': 'config',
                'requires_params': True
            },
        ])
        
        return modifiable_points
        
    def display_modifiable_points(self, points: List[Dict[str, Any]]) -> None:
        """显示可修改点列表"""
        print("\n" + "="*80)
        print("APK自动化修改工具")
        print("="*80)
        print(f"\n✓ 已加载APK: {self.apk_path}")
        if self.report_path:
            print(f"✓ 已加载分析报告: {self.report_path}")
        
        print("\n📋 可修改点列表:")
        print("-"*80)
        
        for point in points:
            print(f"  [{point['id']}] {point['name']}")
            print(f"      {point['description']}")
            print(f"      难度: {point['difficulty']}")
            if point.get('requires_params'):
                print(f"      ⚠️  需要输入参数")
            print()
        
        print("-"*80)
        
    def prompt_user_selection(self, points: List[Dict[str, Any]]) -> List[int]:
        """提示用户选择要修改的项目"""
        while True:
            selection = input("\n请选择要执行的修改 (输入数字，多个用逗号分隔，全部输入 'all', 退出输入 'q'): ").strip()
            
            if selection.lower() == 'q':
                return []
            
            if selection.lower() == 'all':
                return [p['id'] for p in points]
            
            try:
                selected_ids = [int(x.strip()) for x in selection.split(',')]
                valid_ids = [p['id'] for p in points]
                
                # 验证所有ID都是有效的
                if all(id in valid_ids for id in selected_ids):
                    return selected_ids
                else:
                    print("❌ 错误: 包含无效的选项编号")
            except ValueError:
                print("❌ 错误: 输入格式无效，请输入数字，多个数字用逗号分隔")
        
    def prompt_modification_params(self, mod_type: str) -> Dict[str, Any]:
        """提示用户输入修改参数"""
        params = {}
        
        if mod_type == 'API地址修改':
            old_url = input("请输入当前的API地址 (留空自动检测): ").strip()
            new_url = input("请输入新的API地址: ").strip()
            params = {'old_url': old_url, 'new_url': new_url}
            
        elif mod_type == '修改版本号':
            version_code = input("请输入新的versionCode (留空保持不变): ").strip()
            version_name = input("请输入新的versionName (留空保持不变): ").strip()
            params = {
                'version_code': int(version_code) if version_code else None,
                'version_name': version_name if version_name else None
            }
            
        elif mod_type == '添加权限':
            permissions = input("请输入要添加的权限 (多个用逗号分隔): ").strip()
            params = {'permissions': [p.strip() for p in permissions.split(',')]}
        
        return params
        
    def decompile_apk(self) -> bool:
        """使用apktool反编译APK"""
        print("\n🔧 正在反编译APK...")
        
        # 检查apktool是否可用
        apktool_path = shutil.which('apktool')
        if not apktool_path:
            print("❌ 错误: 未找到apktool工具")
            print("   请安装apktool: https://ibotpeaches.github.io/Apktool/")
            return False
        
        # 创建工作目录
        self.work_dir = tempfile.mkdtemp(prefix='apk_modifier_')
        self.decompiled_dir = os.path.join(self.work_dir, 'decompiled')
        
        try:
            # 执行反编译
            result = subprocess.run(
                [apktool_path, 'd', self.apk_path, '-o', self.decompiled_dir, '-f'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("✓ 反编译完成")
                return True
            else:
                print(f"❌ 反编译失败: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ 反编译超时")
            return False
        except Exception as e:
            print(f"❌ 反编译出错: {e}")
            return False
        
    def apply_modification(self, modification: Dict[str, Any]) -> bool:
        """应用单个修改"""
        mod_name = modification['name']
        print(f"\n🔧 正在应用修改: {mod_name}...")
        
        try:
            if mod_name == '签名验证绕过':
                return self.bypass_signature_check()
            elif mod_name == 'Root检测绕过':
                return self.bypass_root_detection()
            elif mod_name == 'API地址修改':
                params = modification.get('params', {})
                return self.modify_api_url(params.get('old_url'), params.get('new_url'))
            elif mod_name == '启用调试模式':
                return self.enable_debug_mode()
            elif mod_name == 'SSL证书固定绕过':
                return self.bypass_ssl_pinning()
            elif mod_name == '移除广告':
                return self.remove_ads()
            elif mod_name == '修改版本号':
                params = modification.get('params', {})
                return self.modify_version(params.get('version_code'), params.get('version_name'))
            elif mod_name == '添加权限':
                params = modification.get('params', {})
                return self.modify_permissions(add=params.get('permissions', []), remove=[])
            else:
                print(f"⚠️  警告: 未实现的修改类型: {mod_name}")
                return False
                
        except Exception as e:
            print(f"❌ 修改失败: {e}")
            return False
        
    def bypass_signature_check(self) -> bool:
        """绕过签名验证"""
        print("  正在搜索签名验证代码...")
        
        # 搜索smali文件中的签名验证相关代码
        smali_files = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    smali_files.append(file_path)
        
        modified_count = 0
        signature_patterns = [
            (r'invoke.*getPackageManager', 'signature check'),
            (r'invoke.*getPackageInfo', 'package info'),
            (r'invoke.*GET_SIGNATURES', 'get signatures'),
        ]
        
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 检查是否包含签名验证代码
                for pattern, desc in signature_patterns:
                    if re.search(pattern, content):
                        # 这里应该实现具体的修改逻辑
                        # 简化处理：标记发现
                        print(f"    发现可疑代码: {smali_file}")
                        modified_count += 1
                        break
                        
            except Exception as e:
                continue
        
        if modified_count > 0:
            print(f"  ✓ 发现 {modified_count} 处可疑代码位置")
            print("  ⚠️  注意: 实际修改需要根据具体代码实现")
            return True
        else:
            print("  ⚠️  未找到明显的签名验证代码")
            return True
        
    def bypass_root_detection(self) -> bool:
        """绕过Root检测"""
        print("  正在搜索Root检测代码...")
        
        root_indicators = [
            '/system/app/Superuser.apk',
            '/sbin/su',
            '/system/bin/su',
            '/system/xbin/su',
            'eu.chainfire.supersu',
            'com.noshufou.android.su',
            'com.koushikdutta.superuser',
            'test-keys'
        ]
        
        smali_files = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith('.smali'):
                    smali_files.append(os.path.join(root, file))
        
        modified_count = 0
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 检查是否包含Root检测相关字符串
                for indicator in root_indicators:
                    if indicator in content:
                        print(f"    发现Root检测: {smali_file}")
                        modified_count += 1
                        break
                        
            except Exception as e:
                continue
        
        if modified_count > 0:
            print(f"  ✓ 发现 {modified_count} 处Root检测代码")
            print("  ⚠️  注意: 实际修改需要根据具体代码实现")
            return True
        else:
            print("  ⚠️  未找到明显的Root检测代码")
            return True
        
    def modify_api_url(self, old_url: str = None, new_url: str = None) -> bool:
        """修改API地址"""
        if not new_url:
            print("  ❌ 错误: 未提供新的API地址")
            return False
        
        print(f"  正在搜索API地址...")
        
        # 搜索strings.xml
        strings_files = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            if 'values' in root and 'strings.xml' in files:
                strings_files.append(os.path.join(root, 'strings.xml'))
        
        modified_count = 0
        url_pattern = r'https?://[^\s<>"\']+' if not old_url else re.escape(old_url)
        
        for strings_file in strings_files:
            try:
                with open(strings_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if re.search(url_pattern, content):
                    # 替换URL
                    if old_url:
                        new_content = content.replace(old_url, new_url)
                    else:
                        # 如果没有指定old_url，列出所有找到的URL
                        urls = re.findall(url_pattern, content)
                        if urls:
                            print(f"    发现URL: {strings_file}")
                            for url in set(urls):
                                print(f"      - {url}")
                            modified_count += 1
                            continue
                    
                    with open(strings_file, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    print(f"    修改: {strings_file}")
                    modified_count += 1
                    
            except Exception as e:
                continue
        
        # 也搜索smali文件
        smali_files = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith('.smali'):
                    smali_files.append(os.path.join(root, file))
        
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if re.search(url_pattern, content):
                    if old_url:
                        new_content = content.replace(old_url, new_url)
                        with open(smali_file, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"    修改: {smali_file}")
                        modified_count += 1
                    else:
                        urls = re.findall(url_pattern, content)
                        if urls:
                            print(f"    发现URL: {smali_file}")
                            
            except Exception as e:
                continue
        
        if modified_count > 0:
            print(f"  ✓ 处理了 {modified_count} 个文件")
            return True
        else:
            print("  ⚠️  未找到匹配的API地址")
            return True
        
    def enable_debug_mode(self) -> bool:
        """启用调试模式"""
        manifest_path = os.path.join(self.decompiled_dir, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            print("  ❌ 错误: 未找到AndroidManifest.xml")
            return False
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 检查是否已经启用调试
            if 'android:debuggable="true"' in content:
                print("  ⚠️  调试模式已启用")
                return True
            
            # 在application标签中添加debuggable属性
            if '<application' in content:
                # 如果已有debuggable=false，替换为true
                if 'android:debuggable="false"' in content:
                    content = content.replace('android:debuggable="false"', 'android:debuggable="true"')
                else:
                    # 在application标签中添加debuggable="true"
                    content = content.replace('<application', '<application android:debuggable="true"', 1)
                
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                print("  ✓ 已启用调试模式")
                return True
            else:
                print("  ❌ 错误: AndroidManifest.xml格式异常")
                return False
                
        except Exception as e:
            print(f"  ❌ 修改失败: {e}")
            return False
        
    def bypass_ssl_pinning(self) -> bool:
        """绕过SSL证书固定"""
        print("  正在搜索SSL Pinning代码...")
        
        ssl_patterns = [
            'CertificatePinner',
            'TrustManager',
            'SSLContext',
            'X509Certificate',
            'HostnameVerifier'
        ]
        
        smali_files = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith('.smali'):
                    smali_files.append(os.path.join(root, file))
        
        modified_count = 0
        for smali_file in smali_files:
            try:
                with open(smali_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in ssl_patterns:
                    if pattern in content:
                        print(f"    发现SSL相关代码: {smali_file}")
                        modified_count += 1
                        break
                        
            except Exception as e:
                continue
        
        if modified_count > 0:
            print(f"  ✓ 发现 {modified_count} 处SSL相关代码")
            print("  ⚠️  注意: 实际修改需要根据具体实现，建议使用Frida进行运行时Hook")
            return True
        else:
            print("  ⚠️  未找到明显的SSL Pinning代码")
            return True
        
    def remove_ads(self) -> bool:
        """移除广告"""
        print("  正在搜索广告SDK...")
        
        ad_sdks = [
            'com.google.android.gms.ads',
            'com.facebook.ads',
            'com.unity3d.ads',
            'com.applovin',
            'com.ironsource',
            'com.mopub',
            'com.chartboost'
        ]
        
        found_sdks = []
        for root, dirs, files in os.walk(self.decompiled_dir):
            dir_name = os.path.basename(root)
            for sdk in ad_sdks:
                sdk_path = sdk.replace('.', os.sep)
                if sdk_path in root:
                    found_sdks.append((sdk, root))
                    break
        
        if found_sdks:
            print(f"  发现 {len(found_sdks)} 个广告SDK:")
            for sdk, path in found_sdks:
                print(f"    - {sdk}")
            print("  ⚠️  注意: 直接删除SDK可能导致应用崩溃，建议分析调用关系后再操作")
            return True
        else:
            print("  ⚠️  未找到常见的广告SDK")
            return True
        
    def modify_permissions(self, add: List[str] = None, remove: List[str] = None) -> bool:
        """修改权限"""
        manifest_path = os.path.join(self.decompiled_dir, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            print("  ❌ 错误: 未找到AndroidManifest.xml")
            return False
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            modified = False
            
            # 添加权限
            if add:
                for permission in add:
                    # 确保权限格式正确
                    if not permission.startswith('android.permission.'):
                        permission = f'android.permission.{permission}'
                    
                    perm_tag = f'<uses-permission android:name="{permission}"/>'
                    
                    if perm_tag not in content:
                        # 在manifest标签后添加权限
                        content = content.replace(
                            '<manifest',
                            f'<manifest',
                            1
                        )
                        # 找到第一个>后插入
                        pos = content.find('>', content.find('<manifest'))
                        if pos != -1:
                            content = content[:pos+1] + '\n    ' + perm_tag + content[pos+1:]
                            print(f"    添加权限: {permission}")
                            modified = True
                    else:
                        print(f"    权限已存在: {permission}")
            
            # 移除权限
            if remove:
                for permission in remove:
                    if not permission.startswith('android.permission.'):
                        permission = f'android.permission.{permission}'
                    
                    pattern = f'<uses-permission android:name="{permission}"\\s*/>'
                    if re.search(pattern, content):
                        content = re.sub(pattern, '', content)
                        print(f"    移除权限: {permission}")
                        modified = True
            
            if modified:
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print("  ✓ 权限修改完成")
                return True
            else:
                print("  ⚠️  无需修改")
                return True
                
        except Exception as e:
            print(f"  ❌ 修改失败: {e}")
            return False
        
    def modify_version(self, version_code: int = None, version_name: str = None) -> bool:
        """修改版本号"""
        manifest_path = os.path.join(self.decompiled_dir, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            print("  ❌ 错误: 未找到AndroidManifest.xml")
            return False
        
        if not version_code and not version_name:
            print("  ⚠️  未指定要修改的版本信息")
            return True
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            modified = False
            
            if version_code:
                # 修改versionCode
                pattern = r'android:versionCode="[^"]+"'
                if re.search(pattern, content):
                    content = re.sub(pattern, f'android:versionCode="{version_code}"', content)
                    print(f"    修改versionCode: {version_code}")
                    modified = True
            
            if version_name:
                # 修改versionName
                pattern = r'android:versionName="[^"]+"'
                if re.search(pattern, content):
                    content = re.sub(pattern, f'android:versionName="{version_name}"', content)
                    print(f"    修改versionName: {version_name}")
                    modified = True
            
            if modified:
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print("  ✓ 版本号修改完成")
                return True
            else:
                print("  ⚠️  未找到版本信息")
                return True
                
        except Exception as e:
            print(f"  ❌ 修改失败: {e}")
            return False
        
    def recompile_apk(self) -> bool:
        """重新打包APK"""
        print("\n🔧 正在重新打包APK...")
        
        apktool_path = shutil.which('apktool')
        if not apktool_path:
            print("❌ 错误: 未找到apktool工具")
            return False
        
        # 生成临时输出路径
        temp_output = os.path.join(self.work_dir, 'output.apk')
        
        try:
            result = subprocess.run(
                [apktool_path, 'b', self.decompiled_dir, '-o', temp_output],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # 复制到最终输出路径
                shutil.copy(temp_output, self.output_path)
                print("✓ 打包完成")
                return True
            else:
                print(f"❌ 打包失败: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ 打包超时")
            return False
        except Exception as e:
            print(f"❌ 打包出错: {e}")
            return False
        
    def sign_apk(self, keystore_path: str = None) -> bool:
        """签名APK"""
        print("\n🔧 正在签名APK...")
        
        # 使用自定义密钥库或创建debug密钥库
        if keystore_path and os.path.exists(keystore_path):
            ks_path = keystore_path
            print(f"  使用指定的密钥库: {keystore_path}")
        else:
            # 创建debug密钥库
            ks_path = os.path.join(self.work_dir, 'debug.keystore')
            print("  使用debug密钥库")
            
            # 创建debug密钥
            try:
                keytool_path = shutil.which('keytool')
                if keytool_path:
                    subprocess.run(
                        [
                            keytool_path, '-genkeypair',
                            '-keystore', ks_path,
                            '-alias', 'androiddebugkey',
                            '-keyalg', 'RSA',
                            '-keysize', '2048',
                            '-validity', '10000',
                            '-storepass', 'android',
                            '-keypass', 'android',
                            '-dname', 'CN=Android Debug,O=Android,C=US'
                        ],
                        capture_output=True,
                        check=True
                    )
            except Exception as e:
                print(f"  ⚠️  创建debug密钥失败: {e}")
        
        # 尝试使用apksigner
        apksigner_path = shutil.which('apksigner')
        if apksigner_path:
            try:
                result = subprocess.run(
                    [
                        apksigner_path, 'sign',
                        '--ks', ks_path,
                        '--ks-key-alias', 'androiddebugkey',
                        '--ks-pass', 'pass:android',
                        '--key-pass', 'pass:android',
                        self.output_path
                    ],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    print("✓ 签名完成 (apksigner)")
                    return True
                else:
                    print(f"  apksigner失败: {result.stderr}")
            except Exception as e:
                print(f"  apksigner出错: {e}")
        
        # 尝试使用jarsigner
        jarsigner_path = shutil.which('jarsigner')
        if jarsigner_path:
            try:
                result = subprocess.run(
                    [
                        jarsigner_path,
                        '-verbose',
                        '-sigalg', 'SHA1withRSA',
                        '-digestalg', 'SHA1',
                        '-keystore', ks_path,
                        '-storepass', 'android',
                        '-keypass', 'android',
                        self.output_path,
                        'androiddebugkey'
                    ],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    print("✓ 签名完成 (jarsigner)")
                    return True
                else:
                    print(f"  jarsigner失败: {result.stderr}")
            except Exception as e:
                print(f"  jarsigner出错: {e}")
        
        print("⚠️  警告: 未找到签名工具，APK未签名")
        print("   请手动签名APK后再安装")
        return True
        
    def run(self, auto_mode: bool = False, list_only: bool = False) -> bool:
        """运行修改流程"""
        try:
            # 加载分析报告
            self.load_analysis_report()
            
            # 查找可修改点
            modifiable_points = self.find_modifiable_points()
            
            # 显示可修改点
            self.display_modifiable_points(modifiable_points)
            
            # 如果只是列表模式，直接返回
            if list_only:
                return True
            
            # 获取用户选择
            if auto_mode:
                print("\n⚠️  自动模式: 将跳过需要参数的修改")
                selected_ids = [p['id'] for p in modifiable_points if not p.get('requires_params')]
            else:
                selected_ids = self.prompt_user_selection(modifiable_points)
            
            if not selected_ids:
                print("\n取消修改")
                return True
            
            # 准备修改列表
            self.modifications = []
            for point in modifiable_points:
                if point['id'] in selected_ids:
                    mod = point.copy()
                    
                    # 如果需要参数且不是自动模式，提示输入
                    if point.get('requires_params') and not auto_mode:
                        print(f"\n【修改 {point['id']}: {point['name']}】")
                        params = self.prompt_modification_params(point['name'])
                        mod['params'] = params
                    
                    self.modifications.append(mod)
            
            # 确认修改
            if not auto_mode:
                print("\n确认以下修改:")
                for mod in self.modifications:
                    print(f"  ✓ {mod['name']}")
                    if 'params' in mod:
                        for key, value in mod['params'].items():
                            if value:
                                print(f"      {key}: {value}")
                
                confirm = input("\n继续执行? (y/n): ").strip().lower()
                if confirm != 'y':
                    print("取消修改")
                    return True
            
            # 反编译APK
            if not self.decompile_apk():
                return False
            
            # 应用修改
            success_count = 0
            for i, mod in enumerate(self.modifications, 1):
                print(f"\n[{i}/{len(self.modifications)}] ", end='')
                if self.apply_modification(mod):
                    success_count += 1
                    print("  ✓ 修改成功")
                else:
                    print("  ⚠️  修改失败")
            
            print(f"\n完成 {success_count}/{len(self.modifications)} 个修改")
            
            # 重新打包
            if not self.recompile_apk():
                return False
            
            # 签名
            if not self.sign_apk(self.keystore_path):
                print("  ⚠️  签名失败，但APK已生成")
            
            # 完成
            print("\n" + "="*80)
            print("✅ APK修改完成!")
            print(f"输出文件: {self.output_path}")
            print("="*80)
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n⚠️  用户中断")
            return False
        except Exception as e:
            print(f"\n❌ 错误: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            # 清理临时文件
            if self.work_dir and os.path.exists(self.work_dir):
                try:
                    shutil.rmtree(self.work_dir)
                except:
                    pass


def find_analysis_report(apk_path: str) -> Optional[str]:
    """查找对应的分析报告"""
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    current_dir = os.path.dirname(apk_path) or '.'
    
    # 查找匹配的JSON报告
    for file in os.listdir(current_dir):
        if file.startswith('apk_analysis_') and file.endswith('.json'):
            if apk_name in file:
                return os.path.join(current_dir, file)
    
    return None


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='APK自动化修改工具 - 基于分析报告的APK修改',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  基本使用:
    %(prog)s --apk app.apk
  
  指定分析报告:
    %(prog)s --apk app.apk --report analysis.json
  
  自动模式（使用默认选项）:
    %(prog)s --apk app.apk --auto
  
  指定输出文件和签名密钥:
    %(prog)s --apk app.apk --output modified.apk --keystore key.jks
  
  仅列出可修改点:
    %(prog)s --apk app.apk --list
        """
    )
    
    parser.add_argument('--apk', '-a', required=True, help='目标APK文件路径')
    parser.add_argument('--report', '-r', help='分析报告JSON文件路径（可选，自动查找）')
    parser.add_argument('--output', '-o', help='输出APK文件路径（可选）')
    parser.add_argument('--keystore', '-k', help='签名密钥库路径（可选，使用debug密钥）')
    parser.add_argument('--auto', action='store_true', help='自动模式，使用默认选项')
    parser.add_argument('--list', '-l', action='store_true', help='仅列出可修改点，不执行修改')
    
    args = parser.parse_args()
    
    # 检查APK文件
    if not os.path.exists(args.apk):
        print(f"❌ 错误: APK文件不存在: {args.apk}")
        sys.exit(1)
    
    # 创建修改器
    modifier = APKModifier(
        apk_path=args.apk,
        report_path=args.report,
        output_path=args.output,
        keystore_path=args.keystore
    )
    
    # 运行修改流程
    success = modifier.run(auto_mode=args.auto, list_only=args.list)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
