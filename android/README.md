# XEM_QUERY Android app

This is a native Android WebView shell for the XEM_QUERY website. It keeps the website as the single API client and does not expose database nodes.

## Build an APK

1. Install Android Studio.
2. Open this `android/` folder.
3. In `app/build.gradle.kts`, replace `https://YOUR-DOMAIN.example/dashboard/` with your HTTPS-deployed TAVDB dashboard URL.
4. Choose **Build → Build APK(s)**.
5. Android Studio writes the debug APK under `app/build/outputs/apk/debug/`.

For local emulator testing only, use `http://10.0.2.2:8004/dashboard/` and permit cleartext traffic. A real phone must use a reachable LAN/HTTPS server URL, never `127.0.0.1`.
