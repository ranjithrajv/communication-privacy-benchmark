# Appium Runner Lock

Appium 3 and its drivers are external Apache-2.0 tools, not first-party code. The
future lock here must pin exact server, UiAutomator2, and XCUITest driver versions and
Node.js 24 LTS.

Appium must bind only to loopback or a protected lab network. Device preflight records
the complete automation stack and runs `appium driver doctor`.
