# 发布签名（Release Signing）说明

本项目在 `app/build.gradle` 中内置了从 `local.properties` 读取签名配置的逻辑，**签名凭据不会进入 Git 历史**。

## 为什么需要签名

Android 应用（APK）必须经过签名才能安装。正式发布到应用商店、或供用户长期升级的应用，必须使用**固定的 release 密钥**（如果更换密钥，用户将无法覆盖安装新版本）。

## 配置步骤

### 1. 生成自己的 release keystore

```bash
keytool -genkeypair -v \
  -keystore ~/.android/release.jks \
  -alias mykey \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Your Name, OU=YourOrg, O=YourOrg, L=City, ST=State, C=CN"
```

> 请务必妥善保管生成的 `.jks` 文件与密码，丢失后将无法为同名应用发布更新。

### 2. 在 `local.properties` 中配置签名凭据

`local.properties` 已被 `.gitignore` 忽略，**不会提交到仓库**，可安全写入密码。

```properties
sdk.dir=/path/to/android-sdk
signing.storeFile=/path/to/your/release.jks
signing.storePassword=你的store密码
signing.keyAlias=你的别名
signing.keyPassword=你的key密码
```

### 3. 构建签名 release APK

```bash
./gradlew assembleRelease
```

产物位于：`app/build/outputs/apk/release/app-release.apk`

## 无签名配置时的行为

若 `local.properties` 中未配置签名（例如第三方 fork 后直接构建），`./gradlew assembleRelease` 仍可成功，但产出的 `app-release.apk` 为**未签名**包，无法直接安装。

## 安全提示

- **绝不**将 `.jks` 文件、`local.properties` 中的密码提交到 Git 仓库。
- `.gitignore` 已排除 `*.jks`、`*.keystore` 与 `local.properties`。
- 建议使用秘密管理工具（如 GitHub Secrets、本地加密备份）保存签名凭据。
