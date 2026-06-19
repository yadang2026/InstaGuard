#!/bin/bash
# InstaGuard Build Script
set -e

echo "=== Fixing apt dependencies ==="
sudo apt-get update -qq || true
sudo apt-get install -y libncurses-dev libtinfo-dev 2>/dev/null || true

echo "=== Installing Python dependencies ==="
pip install --upgrade pip setuptools wheel
pip install buildozer cython virtualenv

echo "=== Fixing buildozer.spec ==="
sed -i 's/requirements = python3,kivy.*/requirements = python3,kivy==2.3.0,https:\/\/github.com\/kivymd\/KivyMD\/archive\/refs\/heads\/master.zip,requests,httpx,lxml/' buildozer.spec 2>/dev/null || true
sed -i 's/# android.accept_sdk_license/android.accept_sdk_license/' buildozer.spec 2>/dev/null || true
sed -i 's/android.api = 34/android.api = 33/' buildozer.spec 2>/dev/null || true

echo "=== Building APK ==="
buildozer android debug

echo "=== Done ==="
ls -lh bin/*.apk 2>/dev/null || echo "APK not found in bin/"
