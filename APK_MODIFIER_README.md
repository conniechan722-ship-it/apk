# APK自动化修改工具使用说明

## 概述

`apk_modifier.py` 是一个基于分析报告的APK自动化修改工具，可以根据APK分析结果对应用进行各种修改。

## 功能特性

### 支持的修改类型

1. **签名验证绕过** - 修改签名校验相关代码
2. **Root检测绕过** - 修改Root检测逻辑
3. **API地址修改** - 替换网络请求的API地址
4. **启用调试模式** - 在AndroidManifest.xml中启用调试
5. **SSL证书固定绕过** - 修改证书验证逻辑
6. **移除广告** - 移除广告SDK相关代码
7. **修改版本号** - 修改versionCode和versionName
8. **添加权限** - 在AndroidManifest.xml中添加权限

## 依赖工具

### 必需工具
- **apktool** - 用于反编译和重新打包APK
  - 安装: `brew install apktool` (macOS) 或从 https://ibotpeaches.github.io/Apktool/ 下载
  
### 可选工具（用于签名）
- **apksigner** - Android SDK工具，用于APK签名
- **jarsigner** - JDK工具，用于APK签名（备选）
- **keytool** - JDK工具，用于生成签名密钥

## 使用方法

### 基本用法

```bash
# 显示帮助信息
python apk_modifier.py --help

# 列出可修改点（不执行修改）
python apk_modifier.py --apk app.apk --list

# 交互式修改
python apk_modifier.py --apk app.apk

# 自动模式（使用默认选项）
python apk_modifier.py --apk app.apk --auto
```

### 高级用法

```bash
# 指定分析报告文件
python apk_modifier.py --apk app.apk --report apk_analysis_app.json

# 指定输出文件
python apk_modifier.py --apk app.apk --output modified.apk

# 使用自定义签名密钥
python apk_modifier.py --apk app.apk --keystore my_key.jks

# 组合使用
python apk_modifier.py --apk app.apk --report analysis.json --output modified.apk --keystore key.jks
```

## 工作流程

1. **加载分析报告** - 自动查找或使用指定的分析报告
2. **显示可修改点** - 列出所有可用的修改选项
3. **用户选择** - 交互式选择要执行的修改（或使用自动模式）
4. **参数输入** - 对于需要参数的修改，提示用户输入
5. **确认修改** - 显示修改摘要并确认
6. **反编译APK** - 使用apktool反编译
7. **应用修改** - 执行选定的修改操作
8. **重新打包** - 使用apktool重新打包APK
9. **签名APK** - 使用apksigner或jarsigner签名
10. **完成** - 输出修改后的APK文件

## 交互式界面示例

```
================================================================================
APK自动化修改工具
================================================================================

✓ 已加载APK: app.apk
✓ 已加载分析报告: apk_analysis_app_20251220.json

📋 可修改点列表:
--------------------------------------------------------------------------------
  [1] 签名验证绕过
      修改签名校验相关代码
      难度: 中等
      
  [2] Root检测绕过
      修改Root检测逻辑
      难度: 简单
      
  [3] API地址修改
      替换网络请求的API地址
      难度: 简单
      ⚠️  需要输入参数
      
  [4] 启用调试模式
      在AndroidManifest.xml中启用调试
      难度: 简单
      
  [5] SSL证书固定绕过
      修改证书验证逻辑
      难度: 中等
      
  [6] 移除广告
      移除广告SDK相关代码
      难度: 中等
      
  [7] 修改版本号
      修改versionCode和versionName
      难度: 简单
      ⚠️  需要输入参数
      
  [8] 添加权限
      在AndroidManifest.xml中添加权限
      难度: 简单
      ⚠️  需要输入参数
--------------------------------------------------------------------------------

请选择要执行的修改 (输入数字，多个用逗号分隔，全部输入 'all', 退出输入 'q'): 1,2,4

确认以下修改:
  ✓ 签名验证绕过
  ✓ Root检测绕过
  ✓ 启用调试模式

继续执行? (y/n): y

🔧 正在反编译APK...
✓ 反编译完成

[1/3] 🔧 正在应用修改: 签名验证绕过...
  正在搜索签名验证代码...
  ✓ 发现 3 处可疑代码位置
  ✓ 修改成功

[2/3] 🔧 正在应用修改: Root检测绕过...
  正在搜索Root检测代码...
  ✓ 发现 2 处Root检测代码
  ✓ 修改成功

[3/3] 🔧 正在应用修改: 启用调试模式...
  ✓ 已启用调试模式
  ✓ 修改成功

完成 3/3 个修改

🔧 正在重新打包APK...
✓ 打包完成

🔧 正在签名APK...
  使用debug密钥库
✓ 签名完成 (apksigner)

================================================================================
✅ APK修改完成!
输出文件: app_modified.apk
================================================================================
```

## 修改类型详解

### 1. 签名验证绕过
自动搜索APK中的签名验证相关代码，包括：
- `getPackageManager` 调用
- `getPackageInfo` 调用
- `GET_SIGNATURES` 标志

### 2. Root检测绕过
搜索常见的Root检测特征，如：
- `/system/app/Superuser.apk`
- `/sbin/su`
- `/system/bin/su`
- SuperSU、Superuser等应用包名

### 3. API地址修改
- 在 `res/values/strings.xml` 中搜索URL
- 在 smali 代码中搜索硬编码的URL
- 支持指定旧URL和新URL，或列出所有发现的URL

### 4. 启用调试模式
在 `AndroidManifest.xml` 的 `<application>` 标签中添加或修改 `android:debuggable="true"`

### 5. SSL证书固定绕过
搜索SSL相关代码：
- `CertificatePinner`
- `TrustManager`
- `SSLContext`
- `X509Certificate`
- `HostnameVerifier`

### 6. 移除广告
搜索常见的广告SDK：
- Google Ads
- Facebook Ads
- Unity Ads
- AppLovin
- IronSource
- MoPub
- Chartboost

### 7. 修改版本号
修改 `AndroidManifest.xml` 中的：
- `android:versionCode` - 版本代码（整数）
- `android:versionName` - 版本名称（字符串）

### 8. 添加权限
在 `AndroidManifest.xml` 中添加 `<uses-permission>` 标签

## 注意事项

1. **备份原始APK** - 修改前请备份原始APK文件
2. **工具依赖** - 确保已安装必需的工具（apktool等）
3. **修改风险** - 某些修改可能导致应用崩溃或功能异常
4. **测试验证** - 修改后请在测试设备上验证应用功能
5. **签名问题** - 修改后的APK需要重新签名才能安装
6. **法律合规** - 仅在合法授权的情况下使用此工具

## 故障排除

### APK无法安装
- 检查签名是否成功
- 尝试使用自定义签名密钥
- 确保卸载了原始应用

### 应用崩溃
- 检查修改的代码是否正确
- 减少修改的数量，逐个测试
- 查看logcat日志定位问题

### 反编译失败
- 确认apktool已正确安装
- 检查APK文件是否完整
- 更新apktool到最新版本

### 重新打包失败
- 检查修改的文件是否破坏了APK结构
- 查看apktool错误信息
- 确保有足够的磁盘空间

## 技术限制

- **代码混淆** - 高度混淆的代码可能难以自动识别和修改
- **加壳保护** - 加壳的APK需要先脱壳才能修改
- **Native代码** - 仅支持修改Java/Kotlin代码和资源文件
- **动态加载** - 动态加载的代码无法通过静态修改处理

## 未来改进

- [ ] 支持更多修改类型
- [ ] 改进代码识别算法
- [ ] 添加撤销功能
- [ ] 支持批量修改
- [ ] 集成Frida脚本生成
- [ ] 添加修改预览功能

## 许可证

与主项目保持一致

## 作者

APK深度安全分析系统团队
