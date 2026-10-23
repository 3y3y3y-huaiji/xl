plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.ryf5584.wxdbdump.xposed"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = false
    }

    packaging {
        resources.excludes.add("META-INF/*.kotlin_module")
        resources.excludes.add("kotlin/**")
        resources.excludes.add("**/*.kotlin_builtins")
        resources.excludes.add("DebugProbesKt.bin")
    }
}

dependencies {
    compileOnly(libs.xposed.api)
    compileOnly("androidx.annotation:annotation:1.8.1")
    implementation(project(":payload"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.1.10")
}
