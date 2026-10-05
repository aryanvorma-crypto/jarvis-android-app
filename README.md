# Jarvis Android App

A private AI assistant for Android with encryption, biometric security, and Gemini API integration.

## Quick Start

1. Clone this repo
2. Open in Android Studio (Bumblebee or newer)
3. Connect your Android device (API 30+) or use an emulator
4. Click "Run" or use `./gradlew installDebug`
5. In the app, add your Gemini API key (get free key at aistudio.google.com)
6. Set a 6+ character code word
7. Enable Accessibility in device Settings > Apps > Jarvis

## Build APK

### Debug APK (fast, for testing):
```bash
./gradlew assembleDebug
```
APK location: `app/build/outputs/apk/debug/app-debug.apk`

### Release APK (signed, for distribution):
```bash
./gradlew assembleRelease
```
APK location: `app/build/outputs/apk/release/app-release.apk`

## Install on Phone

```bash
# Transfer APK to phone and tap to install, OR
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Features

- 🔐 Encrypted on-device memory (AES-256-GCM)
- 🔑 Biometric + code word unlock
- 🤖 Gemini API integration (free tier)
- 📱 Accessibility Service for app automation
- 🎙️ Push-to-talk voice input (Android speech recognizer)
- 💾 Action log & memory search
- ⚠️ Protected app blocklist

## Permissions

- `INTERNET` — to call Gemini API
- `POST_NOTIFICATIONS` — for approval prompts
- `SET_ALARM` — to create alarms/timers
- Accessibility Service — to read screens and interact with other apps

## Honest Limits (v1)

- No always-on voice listening (push-to-talk only)
- No self-modifying code
- Memory search is keyword-based, not semantic
- Tasks interrupted are not auto-resumed
- Free-tier API rate limits apply

## Settings

- **API Key**: Paste your free Gemini key here
- **Model**: Default `gemini-2.5-flash` (edit if API rejects it)
- **Protected Apps**: Comma-separated prefixes (e.g., `com.google.android.apps.walletnfcrel,com.android.settings`)
- **Code Word**: 6+ characters; required for click/type actions

## License

MIT
