package com.aegis.guard.engine

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 文件与 APK 的静态分析工具集。
 *
 * 全部为纯本地解析，不依赖任何外部服务；所有读取都带上限保护，
 * 避免被构造出来的畸形文件拖垮。
 */
object FileAnalyzer {

    /** 单次读入内存的上限，超过则只做流式哈希 + 头部分析 */
    const val MAX_INMEMORY_BYTES = 6L * 1024 * 1024

    /** APK 中提取 DEX 字符串池的上限 */
    private const val MAX_DEX_STRINGS_CHARS = 2_000_000

    /**
     * 流式计算 SHA-256。使用 64KB 缓冲，内存占用恒定。
     */
    fun sha256(file: File): String? = try {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    } catch (_: Throwable) {
        null
    }

    /**
     * 读取文件的可分析文本内容。
     *
     * 策略：
     * - 小文件直接读取全部字节，再按可打印比例判断是否为文本；
     * - 二进制文件只抽取"可打印字符串序列"（类似 `strings`），
     *   这对识别脚本嵌入、URL、C2 域名等非常有效；
     * - 大文件只读头部窗口，避免 OOM。
     */
    fun extractText(file: File, maxBytes: Long = MAX_INMEMORY_BYTES): String? = run {
        try {
        val size = file.length()
        if (size <= 0) return@run null
        if (size <= maxBytes) {
            val bytes = file.readBytes()
            if (isProbablyText(bytes)) String(bytes, Charsets.UTF_8)
            else extractStrings(bytes, limit = 400_000)
        } else {
            val head = ByteArray(minOf(maxBytes, size).toInt())
            file.inputStream().use { it.read(head) }
            val text = if (isProbablyText(head)) String(head, Charsets.UTF_8)
            else extractStrings(head, limit = 400_000)
            text
        }
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * 判断是否更像文本。用可打印字符占比做快速启发式判断。
     */
    fun isProbablyText(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        var printable = 0
        val sample = minOf(bytes.size, 4096)
        for (i in 0 until sample) {
            val b = bytes[i].toInt() and 0xFF
            if (b == 0x09 || b == 0x0A || b == 0x0D || b in 0x20..0x7E) printable++
            // 允许 UTF-8 多字节序列
            else if (b >= 0xC0) printable++
        }
        return printable.toDouble() / sample > 0.85
    }

    /**
     * 抽取二进制中的可打印 ASCII 串。等价于 `strings -n 4` 的简化实现。
     */
    fun extractStrings(bytes: ByteArray, minLen: Int = 4, limit: Int = 512 * 1024): String {
        val sb = StringBuilder(minOf(bytes.size, limit))
        val current = StringBuilder(32)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 0x20..0x7E) {
                current.append(c.toChar())
                if (sb.length + current.length > limit) break
            } else {
                if (current.length >= minLen) {
                    sb.append(current).append('\n')
                }
                current.setLength(0)
                if (sb.length > limit) break
            }
        }
        if (current.length >= minLen) sb.append(current)
        return sb.toString()
    }

    /**
     * 从 APK/ZIP 中抽取可读字符串，用于规则匹配。
     *
     * - `AndroidManifest.xml` 是二进制 AXML，这里做轻量文本抽取
     *   （取出其中的字符串池与资源引用名，足以支撑规则匹配）；
     * - `classes*.dex` 抽取字符串常量池；
     * - 其他小文本条目（`*.json`、`assets/` 下脚本等）直接读取。
     */
    fun extractApkText(apk: File, includeDex: Boolean = true): String? {
        val sb = StringBuilder(256 * 1024)
        try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().toList()

                // 1. 清单
                entries.firstOrNull { it.name == "AndroidManifest.xml" }?.let { e ->
                    if (e.size < 2 * 1024 * 1024) {
                        readEntry(zip, e)?.let { bytes ->
                            sb.append("[manifest]\n")
                            sb.append(extractManifestStrings(bytes)).append('\n')
                        }
                    }
                }

                // 2. DEX 字符串池
                if (includeDex) {
                    var dexChars = 0
                    for (e in entries) {
                        if (!e.name.startsWith("classes") || !e.name.endsWith(".dex")) continue
                        if (e.size > 24L * 1024 * 1024) continue   // 单 dex 上限
                        if (dexChars > MAX_DEX_STRINGS_CHARS) break
                        val bytes = readEntry(zip, e) ?: continue
                        val strings = extractStrings(bytes, minLen = 5, limit = 600_000)
                        sb.append("[dex:${e.name}]\n").append(strings).append('\n')
                        dexChars += strings.length
                    }
                }

                // 3. 其他可疑/可读条目
                for (e in entries) {
                    if (e.isDirectory) continue
                    val n = e.name.lowercase()
                    val interesting = n.endsWith(".json") || n.endsWith(".js") ||
                        n.endsWith(".html") || n.endsWith(".sh") || n.endsWith(".so") ||
                        n.endsWith(".xml") || n.endsWith(".txt") || n.endsWith(".properties") ||
                        n.endsWith(".kt") || n.endsWith(".java")
                    if (!interesting) continue
                    if (e.size > 512 * 1024) continue
                    val bytes = readEntry(zip, e) ?: continue
                    sb.append("[file:").append(e.name).append("]\n")
                    sb.append(
                        if (isProbablyText(bytes)) String(bytes, Charsets.UTF_8)
                        else extractStrings(bytes, minLen = 4, limit = 40_000)
                    ).append('\n')
                    if (sb.length > 1_500_000) break
                }
            }
        } catch (_: Throwable) {
            // 损坏的 ZIP/APK，退化成原始字符串抽取
            return runCatching { extractText(apk) }.getOrNull()
        }
        return sb.takeIf { it.isNotEmpty() }?.toString()
    }

    private fun readEntry(zip: ZipFile, entry: ZipEntry): ByteArray? = try {
        zip.getInputStream(entry).use { it.readBytesBounded(entry.size.coerceAtLeast(0)) }
    } catch (_: Throwable) {
        null
    }

    private fun InputStream.readBytesBounded(declaredSize: Long): ByteArray {
        val cap = if (declaredSize in 1..(32L * 1024 * 1024)) declaredSize.toInt() else 1 shl 20
        val out = java.io.ByteArrayOutputStream(minOf(cap, 8 shl 20))
        val buf = ByteArray(32 * 1024)
        var total = 0
        while (true) {
            val n = read(buf)
            if (n <= 0) break
            total += n
            if (total > (32 shl 20)) break   // 硬上限 32MB
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    /**
     * 从二进制 AXML 中抽取字符串池。
     *
     * 完整解析 AXML 需要实现 ResChunk 结构；但字符串池（chunk type 0x0001）
     * 位于文件开头的固定位置附近，且其内部就是 UTF-16/UTF-8 长度前缀字符串。
     * 为了不引入体积庞大的解析器，这里用字符串池的启发式抽取：
     * 找出连续的可打印 UTF-16LE 序列，已足以支撑权限/组件名匹配。
     */
    fun extractManifestStrings(axml: ByteArray): String {
        val sb = StringBuilder(8192)
        // UTF-16LE 扫描
        var i = 0
        val n = axml.size
        val cur = StringBuilder(32)
        while (i + 1 < n) {
            val lo = axml[i].toInt() and 0xFF
            val hi = axml[i + 1].toInt() and 0xFF
            val code = lo or (hi shl 8)
            val ok = code in 0x20..0x7E || code == 0x0A || code == 0x2F || code == 0x2E
            if (ok) {
                cur.append(code.toChar())
            } else {
                if (cur.length >= 4) {
                    sb.append(cur).append('\n')
                    // 权重保护：清单字符串池通常很小
                    if (sb.length > 300_000) return sb.toString()
                }
                cur.setLength(0)
            }
            i += 2
        }
        if (cur.length >= 4) sb.append(cur)
        // 同时补充 UTF-8 文本，覆盖部分使用 UTF-8 池的构建工具
        sb.append('\n').append(extractStrings(axml, minLen = 5, limit = 120_000))
        return sb.toString()
    }

    /**
     * 判断文件是否为 ZIP 容器（APK/JAR/DOCX 等），用于决定要不要深入扫描。
     */
    fun isZip(file: File): Boolean = try {
        val magic = ByteArray(4)
        file.inputStream().use { if (it.read(magic) < 4) return false }
        magic[0] == 0x50.toByte() && magic[1] == 0x4B.toByte() &&
            (magic[2] == 0x03.toByte() || magic[2] == 0x05.toByte() || magic[2] == 0x07.toByte())
    } catch (_: Throwable) {
        false
    }

    /** 是否为可执行/脚本类扩展名 */
    private val EXECUTABLE_EXT = setOf(
        "apk", "dex", "jar", "elf", "so", "bin", "sh", "bat", "cmd", "ps1",
        "vbs", "js", "py", "pl", "php", "exe", "dll", "scr", "msi", "hta", "wsf"
    )

    private val ARCHIVE_EXT = setOf("zip", "apk", "jar", "aar", "xapk", "apks", "docx", "xlsx", "pptx", "epub")

    fun extensionOf(file: File): String = file.name.substringAfterLast('.', "").lowercase()

    fun isExecutableLike(file: File): Boolean = extensionOf(file) in EXECUTABLE_EXT

    fun isArchive(file: File): Boolean = extensionOf(file) in ARCHIVE_EXT

    /**
     * 需要主动扫描的扩展名集合。空集合表示"全部文件"。
     */
    fun isHighValueTarget(file: File): Boolean {
        val ext = extensionOf(file)
        return ext in EXECUTABLE_EXT || ext in ARCHIVE_EXT || ext.isEmpty()
    }
}