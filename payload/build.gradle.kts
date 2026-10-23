import java.security.SecureRandom

plugins {
    id("java-library")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// Generate a per-build random port (32000..58000) and 256-bit secret into a disguised resource
// so neither is hardcoded in git and no Binder/PackageManager call is needed inside WeChat.
val generatedChannelDir = layout.buildDirectory.dir("generated/channelResources")

val generateChannelSecret = tasks.register("generateChannelSecret") {
    outputs.dir(generatedChannelDir)
    doLast {
        val rng = SecureRandom()
        val port = 32000 + rng.nextInt(26000)
        val tokenBytes = ByteArray(32)
        rng.nextBytes(tokenBytes)
        val tokenHex = tokenBytes.joinToString("") { "%02x".format(it) }
        val outFile = generatedChannelDir.get().file("META-INF/services/jdk.internal.pref").asFile
        outFile.parentFile.mkdirs()
        outFile.writeText("$port:$tokenHex\n", Charsets.UTF_8)
    }
}

sourceSets.named("main") {
    resources.srcDir(generatedChannelDir)
}

tasks.named("processResources") {
    dependsOn(generateChannelSecret)
}

dependencies {
    compileOnly(libs.json)
    testImplementation(libs.junit)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    archiveFileName.set("payload.jar")
    manifest {
        attributes(
            "Implementation-Title" to "compat-runtime",
            "Implementation-Version" to "1.0",
        )
    }
}
