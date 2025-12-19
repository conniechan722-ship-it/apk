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


class APKExtractor:
    """APK信息提取器"""
   
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.temp_dir = tempfile.mkdtemp()
        self.extracted_info = {}
       
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
       
        return all_info
   
    def cleanup(self):
        """清理临时文件"""
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass


class OllamaClient:
    """Ollama客户端封装"""
   
    def __init__(self, model_name: str):
        self.model_name = model_name
       
    async def generate(self, prompt: str, context: str = "") -> str:
        """调用Ollama生成回复"""
        full_prompt = f"{context}\n\n{prompt}" if context else prompt
       
        try:
            process = await asyncio.create_subprocess_exec(
                OLLAMA_PATH, 'run', self.model_name, full_prompt,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
           
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                raise Exception(f"Ollama错误: {error_msg}")
           
            return stdout.decode('utf-8', errors='ignore').strip()
        except FileNotFoundError:
            error_msg = f"无法找到 Ollama。请确保已安装: https://ollama.ai"
            print(f"❌ {error_msg}")
            return ""
        except Exception as e:
            print(f"调用Ollama失败: {e}")
            return ""


class AIAgent:
    """AI智能体"""
   
    def __init__(self, agent_id: int, model_name: str, role: str):
        self.agent_id = agent_id
        self.model_name = model_name
        self.role = role
        self.client = OllamaClient(model_name)
       
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
                    import random
                    return random.choice(valid_votes)
            else:
                valid_votes = [i for i in range(1, 7) if i != self.agent_id]
                import random
                return random.choice(valid_votes)
        except:
            valid_votes = [i for i in range(1, 7) if i != self.agent_id]
            import random
            return random.choice(valid_votes)


class AITeam:
    """AI分析团队 - 6个专家组成"""
   
    def __init__(self, team_id: int, role: str, models: List[str]):
        self.team_id = team_id
        self.role = role
        self.agents = [
            AIAgent(i + 1, models[i % len(models)], role)
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
                import random
                eliminated = [random.choice(candidates)]
           
            if len(eliminated) > 1:
                import random
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
   
    def __init__(self, models: List[str], apk_path: str):
        self.models = models
        self.apk_path = apk_path
        self.extractor = APKExtractor(apk_path)
        self.apk_info = {}
        self.analysis_results = []
       
    async def analyze_structure_and_metadata(self) -> Dict[str, Any]:
        """分析1: APK构成与元数据"""
        print("\n" + "="*80)
        print("阶段 1: APK构成与元数据分析")
        print("="*80)
       
        team = AITeam(1, "APK结构与元数据分析专家", self.models)
       
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

请提供专业、详细的分析报告。
"""
       
        result = await team.collaborate(task, "")
        self.analysis_results.append(result)
        return result
   
    async def analyze_static_code_structure(self) -> Dict[str, Any]:
        """分析2: 静态代码结构与语义"""
        print("\n" + "="*80)
        print("阶段 2: 静态代码结构与语义分析")
        print("="*80)
       
        team = AITeam(2, "静态代码分析专家", self.models)
       
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

请提供详细的静态分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_obfuscation_hardening(self) -> Dict[str, Any]:
        """分析3: 混淆与加固"""
        print("\n" + "="*80)
        print("阶段 3: 混淆与加固分析")
        print("="*80)
       
        team = AITeam(3, "代码混淆与加固分析专家", self.models)
       
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

请提供专业的混淆与加固分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_dynamic_behavior(self) -> Dict[str, Any]:
        """分析4: 动态行为与运行时特征"""
        print("\n" + "="*80)
        print("阶段 4: 动态行为与运行时特征分析")
        print("="*80)
       
        team = AITeam(4, "动态行为分析专家", self.models)
       
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

请提供详细的动态行为分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_native_code(self) -> Dict[str, Any]:
        """分析5: Native库与本地代码"""
        print("\n" + "="*80)
        print("阶段 5: Native库与本地代码分析")
        print("="*80)
       
        team = AITeam(5, "Native代码分析专家", self.models)
       
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

请提供专业的Native代码分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_network_protocol(self) -> Dict[str, Any]:
        """分析6: 网络与协议语义"""
        print("\n" + "="*80)
        print("阶段 6: 网络与协议语义分析")
        print("="*80)
       
        team = AITeam(6, "网络协议分析专家", self.models)
       
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

请提供详细的网络协议分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_signature_integrity(self) -> Dict[str, Any]:
        """分析7: 签名、完整性与更新机制"""
        print("\n" + "="*80)
        print("阶段 7: 签名、完整性与更新机制分析")
        print("="*80)
       
        team = AITeam(7, "应用安全与完整性专家", self.models)
       
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

请提供专业的签名与完整性分析报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def analyze_anti_analysis(self) -> Dict[str, Any]:
        """分析8: 反调试与反分析机制"""
        print("\n" + "="*80)
        print("阶段 8: 反调试与反分析机制分析")
        print("="*80)
       
        team = AITeam(8, "反调试与对抗技术专家", self.models)
       
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

请提供详细的反调试与反分析评估报告。
"""
       
        result = await team.collaborate(task, json.dumps(self.apk_info, ensure_ascii=False, indent=2))
        self.analysis_results.append(result)
        return result
   
    async def generate_comprehensive_report(self) -> Dict[str, Any]:
        """生成综合分析报告"""
        print("\n" + "="*80)
        print("阶段 9: 综合分析报告生成")
        print("="*80)
       
        team = AITeam(9, "安全分析总结专家", self.models)
       
        # 汇总所有分析结果
        all_analyses = "\n\n".join([
            f"## {result['role']}\n{result['consensus']}"
            for result in self.analysis_results
        ])
       
        task = f"""
基于以下8个维度的深入分析结果，请生成一份综合性的APK安全分析报告:

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
   - 混淆加固总结
   - 反调试能力
   - 逆向工程难度

5. **动态行为综述**:
   - 运行时行为总结
   - 敏感操作汇总
   - 潜在风险点

6. **建议与改进**:
   - 安全加固建议
   - 隐私保护改进
   - 合规性建议
   - 最佳实践推荐

7. **渗透测试路线**:
   - 分析切入点
   - 测试方法建议
   - 工具选择推荐
   - 预期挑战

8. **评分矩阵**:
   - 安全性评分 (1-10)
   - 隐私保护评分 (1-10)
   - 代码质量评分 (1-10)
   - 逆向难度评分 (1-10)
   - 整体评级

请生成一份专业、全面、有深度的综合分析报告。
"""
       
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
       
        # 步骤2: 8个维度深入分析
        await self.analyze_structure_and_metadata()      # 1. APK构成与元数据
        await self.analyze_static_code_structure()       # 2. 静态代码结构
        await self.analyze_obfuscation_hardening()       # 3. 混淆与加固
        await self.analyze_dynamic_behavior()            # 4. 动态行为
        await self.analyze_native_code()                 # 5. Native代码
        await self.analyze_network_protocol()            # 6. 网络协议
        await self.analyze_signature_integrity()         # 7. 签名完整性
        await self.analyze_anti_analysis()               # 8. 反调试机制
       
        # 步骤3: 生成综合报告
        await self.generate_comprehensive_report()
       
        # 步骤4: 保存结果
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
       
        # 保存JSON格式
        output_file = f"apk_analysis_{apk_name}_{timestamp}.json"
       
        output_data = {
            "apk_info": self.apk_info,
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
        markdown_file = f"apk_analysis_{apk_name}_{timestamp}.md"
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
  python apk_analyzer.py --apk app.apk
  python apk_analyzer.py --apk app.apk --models qwen2.5:32b llama3:8b
  python apk_analyzer.py --apk app.apk --models deepseek-r1:32b

注意: 需要安装以下工具以获得更完整的分析结果:
  - aapt (Android Asset Packaging Tool)
  - apktool (APK反编译工具)
        """
    )
   
    parser.add_argument('--apk', required=True, help='APK文件路径')
    parser.add_argument('--models', nargs='+', help='指定要使用的Ollama模型（可选）')
   
    args = parser.parse_args()
   
    # 检查APK文件
    if not os.path.exists(args.apk):
        print(f"❌ 错误: APK文件不存在: {args.apk}")
        sys.exit(1)
   
    # 使用用户指定的模型，或使用默认模型
    if args.models:
        models = args.models
        print(f"✓ 使用指定模型: {', '.join(models)}")
    else:
        models = ['qwen2.5:32b']
        print(f"✓ 使用默认模型: {', '.join(models)}")
   
    # 创建分析编排器
    orchestrator = APKAnalysisOrchestrator(
        models=models,
        apk_path=args.apk
    )
   
    # 开始分析
    await orchestrator.orchestrate()


if __name__ == '__main__':
    asyncio.run(main())