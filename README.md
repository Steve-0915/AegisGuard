# 神盾卫士 AegisGuard

一款完全本地运行的 Android 恶意软件检测与 CVE 漏洞扫描工具。

AegisGuard 是纯 Kotlin 实现、基于 Material Design 3 的 Android 应用，内置离线签名库与 CVE 版本区间匹配引擎，在**不联网**的情况下即可对已安装应用进行风险检测，识别已知恶意签名与受影响组件版本。

> ⚠️ **重要免责声明**：本项目仅用于安全研究与学习用途。检测结果仅供参考，不构成任何形式的权威安全判断。

## ✨ 功能特性

- **全盘扫描**：枚举设备上已安装的第三方应用，基于内置离线签名库进行匹配。
- **威胁判定**：对命中应用标记风险等级（critical / high / medium / low），并支持一键卸载。
- **CVE 漏洞检测**：内置 CVE 版本区间匹配引擎，可识别应用内嵌的受影响组件版本。
- **实时防护**：可选开启，监控应用安装/卸载事件并推送通知提醒。
- **离线优先**：所有扫描逻辑在本机完成，不依赖云端，保护隐私。

## 🏗️ 技术架构

```
AegisGuard
├── data/model      # 数据模型（AppInfo / Cve / Signature / Threat）
├── data/repo       # ThreatRepository 数据仓库
├── engine          # 核心引擎（签名匹配 / 风险评分 / 规则加载）
├── cve             # CVE 版本区间匹配器（自研 VersionComparator）
├── scan            # 扫描器（完整性探测）
├── service         # 前台服务 / 开机广播 / 包变更监听
└── ui              # MD3 界面（首页 / CVE / 设置 / 关于 / 扫描 / 详情）
```

**核心引擎**：
- `SignatureEngine`：加载 `assets/rules/signatures.json`（32 条签名规则 + 20 条启发式规则）做哈希/特征匹配。
- `CveMatcher` + `VersionComparator`：加载 `assets/rules/cve.json`（26 条 CVE），正确比较版本号（如 `1.10 > 1.9`），输出命中组件。
- `Scanner.integrityChecks()`：只读用户态探测，**不提权**。

**技术栈**：Kotlin 1.9.24 · AGP 8.5.2 · Compose/MD3（Material 1.12.0）· Coroutines · Gson · minSdk 24 / targetSdk 35

## 📦 构建

> 需要 JDK 17 与 Android SDK（compileSdk 35）。Gradle Wrapper 已包含，可直接使用 `./gradlew`。

```bash
# 1. 克隆仓库
git clone https://github.com/Steve-0915/AegisGuard.git
cd AegisGuard

# 2. 构建 Debug APK
./gradlew assembleDebug

# 3. 产物位置
# app/build/outputs/apk/debug/app-debug.apk
```

首次构建请在本机 `local.properties` 中配置 `sdk.dir`（或设置 `ANDROID_HOME` 环境变量）。

> **说明**：本仓库的 `gradle.properties` 中有一段被注释掉的 `android.aapt2FromMavenOverride`，那是特定沙箱环境专用的，普通机器请保持注释状态（默认即可正常构建）。

## 🔍 CVE 能力边界

本应用的 CVE 检测存在明确边界，请知悉：

1. **仅能识别「应用内嵌受影响版本组件」**：通过比对已安装应用的静态信息与内置 CVE 版本区间，判断某应用是否捆绑了受影响的库/组件版本。
2. **无法验证系统内核 / 固件补丁状态**：本项目无法检测 Android 系统层面的安全补丁级别或内核漏洞是否已修复。
3. **版本区间是基于公开 CVE 情报的近似匹配**：实际的漏洞可利用性还取决于厂商是否已打回补丁等，检测结果仅供辅助参考。

## 🔒 隐私说明

- 所有扫描与匹配逻辑**完全在本机完成**，不上传任何应用列表或扫描结果。
- 可选「云端情报查询」开关：仅在用户手动开启后，才会上传**应用包名/版本哈希**用于查询，且不包含个人数据。

## 📄 许可证

本项目采用 [Apache License 2.0](LICENSE)。

## 👤 作者

Steve-0915
DeepSeek
