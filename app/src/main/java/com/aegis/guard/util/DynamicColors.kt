package com.aegis.guard.util

import android.app.Activity
import android.app.Application
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.color.DynamicColors
import com.google.android.material.color.DynamicColorsOptions

/**
 * Material You 动态取色工具。
 *
 * 系统层面的动态取色从 Android 12（API 31）开始提供。
 * 在更低版本上，Material3 的默认调色板（我们已在 colors.xml 里定义了一整套）
 * 会作为回退，因此视觉上是"降级但不破相"。
 *
 * 用法：在每个 Activity 的 `onCreate` 里、`setContentView` 之前调用
 * [setupMaterialYou]。这样 Material3 组件会先拿到动态色，再渲染布局。
 *
 * 注意：本对象刻意使用 `AegisDynamicColors` 名字，避免与 Material 的
 * `com.google.android.material.color.DynamicColors` 重名产生解析歧义。
 */
object AegisDynamicColors {

    /** 当前系统是否支持动态取色 */
    val isSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    /**
     * 按用户开关应用动态取色。
     *
     * @param enabled 用户在设置里的选择
     * @return 是否真的应用了动态色（供 UI 判断是否需要提示"本机不支持"）
     */
    fun applyIfEnabled(activity: Activity, enabled: Boolean): Boolean {
        if (!enabled || !isSupported) return false
        return try {
            DynamicColors.applyToActivityIfAvailable(
                activity,
                DynamicColorsOptions.Builder()
                    .setPrecondition { _, _ -> true }
                    .build()
            )
            true
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * 应用到整个进程内的所有 Activity。
     * 由于我们是在每个 Activity 自行调用，这里仅作为后备入口保留。
     */
    fun applyToApplication(application: Application, enabled: Boolean) {
        if (!enabled || !isSupported) return
        runCatching { DynamicColors.applyToActivitiesIfAvailable(application) }
    }
}

/**
 * 在 Activity 上一次性配置动态取色。
 * 必须在 `setContentView` 之前调用。
 */
fun AppCompatActivity.setupMaterialYou(dynamicColorEnabled: Boolean) {
    AegisDynamicColors.applyIfEnabled(this, dynamicColorEnabled)
}
