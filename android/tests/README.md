# Android tests

`android/build.sh` runs the JVM tests for transport framing, deadlines, ranking,
consent/cancellation, renewal/update validation, input validation and report ownership.

Release UI/device checklist: `android/QA.md`. The manual/device suite is run on
isolated Android emulators and an explicitly authorised phone, never by changing
the development computer's VPN. Real AndroidKeyStore recovery is tested with a
separately signed, temporary instrumentation APK on an emulator. That APK and its
key-deletion entrypoint must not be bundled with the release application.
