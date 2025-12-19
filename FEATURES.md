# APK分析系统 - 新功能说明

## 概述

本次更新为APK分析系统添加了多项重要功能，包括反编译、加壳检测、混淆检测和代码逻辑分析。

## 新增功能

### 1. 反编译功能

集成了 `jadx` 和 `apktool` 工具进行APK反编译：

- **jadx**: 反编译为Java源代码
- **apktool**: 反编译为Smali代码

**使用方法**:
```bash
python apk.py --apk app.apk --decompile
```

**要求**:
- 系统中需要安装 `jadx` 或 `apktool` 工具
- 工具需要在PATH环境变量中，或使用标准安装路径

### 2. 加壳检测

自动检测常见的Android加壳方案：

- 360加固
- 腾讯乐固
- 梆梆加固
- 爱加密
- 娜迦加固
- 阿里聚安全
- 百度加固
- 网易易盾
- 顶象加固

**检测结果包括**:
- 是否加壳
- 加壳方案名称
- 检测置信度
- 脱壳难度评估

### 3. 混淆检测

分析代码混淆程度：

- ProGuard/R8混淆检测
- 标识符混淆分析
- 字符串加密检测
- 混淆等级评分（1-10分）

**检测指标**:
- 是否混淆
- 混淆等级
- 标识符混淆
- 字符串加密
- 控制流混淆

### 4. 代码逻辑自动识别

分析反编译后的代码，识别：

- **入口点**: Activity、Service、BroadcastReceiver等
- **关键类**: 应用核心类识别
- **敏感方法**: 网络请求、文件操作、加密解密等
- **可修改点**: 签名验证、API地址、Root检测等
- **Hook建议**: Frida Hook方案推荐

### 5. 新增分析阶段

#### 阶段0: 加壳与混淆检测
在所有分析之前执行，评估APK的保护强度。

#### 阶段9: 代码逻辑分析与可修改点识别
在综合报告之前执行，提供具体的修改建议和Hook方案。

### 6. 新增命令行参数

```bash
--decompile         启用反编译分析
--output-dir DIR    指定输出目录
```

### 7. 增强的输出报告

最终报告中新增：

- **加壳检测结果**: 加壳方案、置信度、脱壳难度
- **混淆程度评估**: 混淆等级、混淆类型
- **可修改代码点列表**: 具体的修改建议和难度评估
- **Hook建议**: Frida Hook方案和目标方法
- **脱壳/去混淆建议**: 具体的技术路线

## 使用示例

### 基本分析
```bash
python apk.py --apk app.apk
```

### 指定模型
```bash
python apk.py --apk app.apk --model qwen2.5-coder:7b
```

### 启用反编译分析
```bash
python apk.py --apk app.apk --model qwen2.5-coder:7b --decompile
```

### 导入需求文件
```bash
python apk.py --apk app.apk --model qwen2.5-coder:7b --txt requirements.txt
```

### 完整分析（所有功能）
```bash
python apk.py --apk app.apk --model qwen2.5-coder:7b --decompile --txt requirements.txt --output-dir ./output
```

## 技术要求

### 必需工具
- Python 3.7+
- Ollama (AI模型运行时)

### 可选工具（用于增强分析）
- **aapt**: Android Asset Packaging Tool（基本分析）
- **jadx**: APK反编译为Java代码（--decompile功能）
- **apktool**: APK反编译为Smali代码（--decompile功能）

### 安装工具

#### Linux/macOS:
```bash
# aapt
sudo apt-get install aapt  # Ubuntu/Debian
brew install aapt          # macOS

# jadx
brew install jadx          # macOS
# 或从 https://github.com/skylot/jadx/releases 下载

# apktool
brew install apktool       # macOS
# 或从 https://ibotpeaches.github.io/Apktool/ 下载
```

#### Windows:
从以下网址下载并添加到PATH:
- jadx: https://github.com/skylot/jadx/releases
- apktool: https://ibotpeaches.github.io/Apktool/
- aapt: Android SDK Tools

## 输出文件

分析完成后会生成两个文件：

1. **JSON报告**: `apk_analysis_<apk名>_<时间戳>.json`
   - 包含所有结构化数据
   - 适合程序解析

2. **Markdown报告**: `apk_analysis_<apk名>_<时间戳>.md`
   - 人类可读的报告
   - 包含分析摘要和详细结果
   - 新增加壳、混淆、代码逻辑分析部分

## 分析流程

1. **阶段0**: 加壳与混淆检测
2. **阶段1**: APK构成与元数据分析
3. **阶段2**: 静态代码结构与语义
4. **阶段3**: 混淆与加固
5. **阶段4**: 动态行为与运行时特征
6. **阶段5**: Native库与本地代码
7. **阶段6**: 网络与协议语义
8. **阶段7**: 签名、完整性与更新机制
9. **阶段8**: 反调试与反分析机制
10. **阶段9**: 代码逻辑分析与可修改点识别（需要--decompile）
11. **阶段10**: 综合分析报告生成

## 注意事项

1. **反编译耗时**: 大型APK的反编译可能需要几分钟
2. **内存占用**: 反编译会占用较多内存
3. **工具依赖**: 未安装反编译工具时会跳过相关分析
4. **超时设置**: 反编译超时设置为5分钟
5. **输出目录**: 使用--output-dir可以指定输出位置，避免污染工作目录

## 故障排除

### 反编译失败
- 确认jadx/apktool已正确安装
- 检查APK文件是否损坏
- 确保有足够的磁盘空间
- 查看错误消息获取更多信息

### 加壳检测误报
- 加壳检测基于特征匹配，可能存在误报
- 检测置信度低于70%时需要人工确认

### 混淆检测不准确
- 混淆检测基于启发式规则
- 建议结合反编译结果人工确认

## 未来改进

- [ ] 支持更多加壳方案识别
- [ ] 改进混淆检测算法
- [ ] 增加自动脱壳功能
- [ ] 支持更多反编译工具
- [ ] 优化代码逻辑分析性能
- [ ] 增加更多Hook建议模板

## 许可证

与主项目保持一致
