plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android { namespace = "com.xemquery.app"; compileSdk = 35
    defaultConfig { applicationId = "com.xemquery.app"; minSdk = 24; targetSdk = 35; versionCode = 1; versionName = "1.0.0"
        buildConfigField("String", "TAVDB_URL", "\"https://YOUR-DOMAIN.example/dashboard/\"") }
    buildFeatures { buildConfig = true }
}
