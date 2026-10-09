#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import base64
import concurrent.futures
import contextlib
import hashlib
import ipaddress
import json
import os
import pwd
import pathlib
import random
import signal
import struct
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import NoReturn

MANAGER_VERSION = "0.2.27"

# Не "latest". Это намеренно совместимый pin.
# Его меняет следующая проверенная версия VPN Manager.
SAFE_XRAY_VERSION = "26.7.28"

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")
STATE = pathlib.Path("/var/lib/vpn-manager/state.json")
RUNTIME_DIR = pathlib.Path("/run/vpn-manager")
RUNTIME_CONFIG = RUNTIME_DIR / "config.json"
DIAGNOSTIC_LOG = pathlib.Path("/var/lib/vpn-manager/diagnostic.jsonl")
DIAGNOSTIC_INTERVAL = 5.0
DIAGNOSTIC_LOG_SEGMENT_BYTES = 50 * 1024 * 1024 * 1024

XRAY = pathlib.Path("/opt/vpn-manager/bin/xray")
XRAY_PREVIOUS = pathlib.Path("/opt/vpn-manager/bin/xray.previous")
SERVICE = "vpn-xray.service"
DIAGNOSTIC_SERVICE = "vpn-diagnostic.service"
TUN_NAME = "xraytun"
NFT_TABLE = "vpn_guard"
DIRECT_SOCKS_HOST = "127.0.0.1"
DIRECT_SOCKS_PORT = 18443
DNS_PROXY_PORT = 18553
# dns.cert.ee: CERT-EE public recursive resolver, reached only through VLESS.
ESTONIA_DNS_IP = "46.226.143.83"
ESTONIA_DNS_SERVERS = ("46.226.143.83", "195.80.119.101", "46.226.143.86", "195.80.119.99")

PLASMOID_ID = "com.evgenium.network"
APP_ICON_NAME = "evgenium-network"
APP_ICON_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1325"/>
      <stop offset="1" stop-color="#162238"/>
    </linearGradient>
    <linearGradient id="edge" x1="0" y1="1" x2="1" y2="0">
      <stop offset="0" stop-color="#35b8ff"/>
      <stop offset="0.52" stop-color="#ff4d78"/>
      <stop offset="1" stop-color="#ff9bb5"/>
    </linearGradient>
    <linearGradient id="hair" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff315f"/>
      <stop offset="1" stop-color="#ff7e9b"/>
    </linearGradient>
  </defs>

  <rect x="8" y="8" width="496" height="496" rx="112" fill="url(#bg)"/>

  <path d="M256 58 403 118v120c0 103-61 174-147 215-86-41-147-112-147-215V118Z"
        fill="none" stroke="url(#edge)" stroke-width="18" stroke-linejoin="round"/>

  <!-- Anime-inspired silhouette with drill pigtails -->
  <path d="M256 132c-44 0-76 27-82 71-4 28 7 54 26 72-13 17-19 37-20 61h152c-1-24-7-44-20-61 19-18 30-44 26-72-6-44-38-71-82-71Z"
        fill="#070b14"/>
  <path d="M193 186c-15-32-48-47-75-34 24 8 35 23 26 43-6 14-23 21-35 30 28 1 50-8 63-27-6 24-23 41-51 49 35 7 68-7 82-35Z"
        fill="url(#hair)"/>
  <path d="M319 186c15-32 48-47 75-34-24 8-35 23-26 43 6 14 23 21 35 30-28 1-50-8-63-27 6 24 23 41 51 49-35 7-68-7-82-35Z"
        fill="url(#hair)"/>
  <path d="M221 142c-17 7-29 22-34 42 18-9 34-9 48-3 7-16 19-28 35-35-14-8-32-9-49-4Zm70 0c17 7 29 22 34 42-18-9-34-9-48-3-7-16-19-28-35-35 14-8 32-9 49-4Z"
        fill="url(#hair)"/>
  <path d="M237 115c10-17 28-28 51-27-12 6-18 15-17 27 1 9 7 16 15 23-22 0-38-7-49-23Z" fill="#ff88a6"/>

  <path d="M213 258c13 14 27 21 43 21s30-7 43-21c-6 30-21 46-43 46s-37-16-43-46Z" fill="#111827"/>
  <path d="M209 307c15 10 31 15 47 15s32-5 47-15c12 13 21 29 25 49H184c4-20 13-36 25-49Z" fill="#0b1220"/>

  <rect x="112" y="385" width="288" height="74" rx="28" fill="#0c1528" stroke="#26364f" stroke-width="3"/>
  <text x="256" y="434" text-anchor="middle" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="52" font-weight="800" fill="#f8fafc">E-VPN</text>
</svg>
'''

PLASMOID_METADATA = r'''{
  "KPlugin": {
    "Authors": [
      {
        "Name": "Evgenium"
      }
    ],
    "Category": "System Information",
    "Description": "Quick VPN switch for Evgenium Network Linux",
    "Icon": "evgenium-network",
    "Id": "com.evgenium.network",
    "Name": "Evgenium Network",
    "Version": "1.6"
  },
  "X-Plasma-API-Minimum-Version": "6.0",
  "KPackageStructure": "Plasma/Applet"
}
'''
PLASMOID_MAIN_QML = r'''import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.plasmoid
import org.kde.plasma.plasma5support as Plasma5Support

PlasmoidItem {
    id: root

    property bool vpnActive: false
    property bool busy: false
    property bool settingsBusy: false
    property bool statusPending: false
    property bool operationBusy: false
    property string lastProfile: ""
    property string errorText: ""
    property string statusErrorText: ""

    readonly property string statusCommand: "/usr/local/bin/vpn status --json"
    readonly property string toggleCommand: "/usr/local/bin/vpn toggle"
    readonly property string settingsCommand: "/usr/local/bin/evgenium-network --detach"

    Plasmoid.icon: "evgenium-network"
    toolTipMainText: "E-VPN"
    toolTipSubText: errorText.length > 0
        ? errorText
        : statusErrorText.length > 0 ? statusErrorText
        : ((busy || operationBusy) ? "Выполняется операция VPN…" : ((vpnActive ? "VPN включён" : "VPN выключен") + (lastProfile.length ? " · " + lastProfile : "")))
    preferredRepresentation: fullRepresentation

    width: Kirigami.Units.gridUnit * 9
    height: Kirigami.Units.gridUnit * 2.7

    function requestStatus() {
        if (statusPending)
            return
        statusPending = true
        statusSource.connectSource(statusCommand)
    }

    function toggleVpn() {
        if (busy || operationBusy)
            return
        busy = true
        errorText = ""
        actionWatchdog.restart()
        actionSource.connectSource(toggleCommand)
    }

    function openSettings() {
        if (settingsBusy)
            return
        settingsBusy = true
        errorText = ""
        settingsSource.connectSource(settingsCommand)
    }

    Component.onCompleted: requestStatus()

    Timer {
        interval: 1500
        repeat: true
        running: true
        onTriggered: root.requestStatus()
    }

    Timer {
        id: actionWatchdog
        interval: 780000
        onTriggered: {
            root.busy = false
            root.errorText = "Операция не завершилась за ожидаемое время. Проверь vpn status; повторное переключение не запущено."
            actionSource.disconnectSource(root.toggleCommand)
            root.requestStatus()
        }
    }

    Plasma5Support.DataSource {
        id: statusSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== root.statusCommand)
                return
            const output = String(data["stdout"] || "").trim()
            if (Number(data["exit code"] || 0) !== 0)
                root.statusErrorText = String(data["stderr"] || output || "Не удалось получить состояние VPN")
            if (output.length > 0) {
                try {
                    const state = JSON.parse(output)
                    root.vpnActive = Boolean(state.active)
                    root.operationBusy = Boolean(state.connecting)
                    root.lastProfile = String(state.last_profile || "")
                    root.statusErrorText = ""
                } catch (error) {
                    root.statusErrorText = "Не удалось прочитать состояние VPN"
                }
            }
            root.statusPending = false
            statusSource.disconnectSource(sourceName)
        }
    }

    Plasma5Support.DataSource {
        id: actionSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            const stderrText = String(data["stderr"] || "").trim()
            const stdoutText = String(data["stdout"] || "").trim()
            if (exitCode !== 0)
                root.errorText = stderrText.length > 0 ? stderrText : stdoutText
            actionWatchdog.stop()
            root.busy = false
            actionSource.disconnectSource(sourceName)
            root.requestStatus()
        }
    }

    Plasma5Support.DataSource {
        id: settingsSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== root.settingsCommand)
                return
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            const stderrText = String(data["stderr"] || "").trim()
            const stdoutText = String(data["stdout"] || "").trim()
            if (exitCode !== 0)
                root.errorText = stderrText.length > 0 ? stderrText : (stdoutText.length > 0 ? stdoutText : "Не удалось открыть Evgenium Network")
            root.settingsBusy = false
            settingsSource.disconnectSource(sourceName)
        }
    }

    fullRepresentation: Item {
        Layout.minimumWidth: Kirigami.Units.gridUnit * 8
        Layout.preferredWidth: Kirigami.Units.gridUnit * 9
        Layout.minimumHeight: Kirigami.Units.gridUnit * 2.4
        Layout.preferredHeight: Kirigami.Units.gridUnit * 2.7

        RowLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.smallSpacing * 2
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Label {
                text: "E-VPN"
                font.bold: true
                Layout.fillWidth: true
            }

            Item {
                id: switchControl
                Layout.preferredWidth: 44
                Layout.preferredHeight: 24
                opacity: root.busy ? 0.55 : 1.0

                Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: root.vpnActive
                        ? Kirigami.Theme.highlightColor
                        : Kirigami.Theme.disabledTextColor
                    opacity: root.vpnActive ? 0.95 : 0.45
                }

                Rectangle {
                    width: 18
                    height: 18
                    radius: 9
                    y: 3
                    x: root.vpnActive ? switchControl.width - width - 3 : 3
                    color: Kirigami.Theme.backgroundColor

                    Behavior on x {
                        NumberAnimation { duration: 120 }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled: !root.busy && !root.operationBusy
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.toggleVpn()
                }
            }

            PlasmaComponents3.ToolButton {
                Layout.preferredWidth: 30
                Layout.preferredHeight: 30
                icon.name: "configure"
                text: ""
                enabled: !root.settingsBusy
                onClicked: root.openSettings()
            }
        }
    }
}
'''
GUI_DESKTOP_ENTRY = r'''[Desktop Entry]
Type=Application
Name=Evgenium Network
Comment=Evgenium VPN control and exclusions
Exec=/usr/local/bin/evgenium-network
Icon=evgenium-network
Terminal=false
Categories=Network;Settings;
StartupNotify=true
'''
STANDALONE_GUI_PY_B64 = (
    'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zCgppbXBvcnQgYmFzZTY0'
    'CmltcG9ydCBodHRwLnNlcnZlcgppbXBvcnQganNvbgppbXBvcnQgb3MKaW1wb3J0IHBhdGhsaWIKaW1wb3J0IHNlY3JldHMK'
    'aW1wb3J0IHNodXRpbAppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgc3lzCmltcG9ydCB0aHJlYWRpbmcKaW1wb3J0IHVybGxp'
    'Yi5wYXJzZQoKQVBQX05BTUUgPSAiRXZnZW5pdW0gTmV0d29yayIKVlBOID0gIi91c3IvbG9jYWwvYmluL3ZwbiIKSEVSRSA9'
    'IHBhdGhsaWIuUGF0aChfX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudApRTUxfRklMRSA9IEhFUkUgLyAiZXZnZW5pdW1fZ3Vp'
    'LnFtbCIKTUFYX0JPRFkgPSA2NCAqIDEwMjQKCgpkZWYgZmluZF9xbWxfcnVudGltZSgpIC0+IHN0ciB8IE5vbmU6CiAgICBm'
    'b3IgY2FuZGlkYXRlIGluICgKICAgICAgICAiL3Vzci9iaW4vcW1sNiIsCiAgICAgICAgIi91c3IvYmluL3FtbC1xdDYiLAog'
    'ICAgICAgICIvdXNyL2xpYi9xdDYvYmluL3FtbCIsCiAgICAgICAgIi91c3IvbGliNjQvcXQ2L2Jpbi9xbWwiLAogICAgICAg'
    'ICIvdXNyL2Jpbi9xbWwiLAogICAgKToKICAgICAgICBpZiBwYXRobGliLlBhdGgoY2FuZGlkYXRlKS5pc19maWxlKCkgYW5k'
    'IG9zLmFjY2VzcyhjYW5kaWRhdGUsIG9zLlhfT0spOgogICAgICAgICAgICByZXR1cm4gY2FuZGlkYXRlCiAgICByZXR1cm4g'
    'c2h1dGlsLndoaWNoKCJxbWw2Iikgb3Igc2h1dGlsLndoaWNoKCJxbWwtcXQ2Iikgb3Igc2h1dGlsLndoaWNoKCJxbWwiKQoK'
    'CmRlZiBydW5fdnBuKGFyZ3M6IGxpc3Rbc3RyXSwgdGltZW91dDogaW50ID0gNzUwKSAtPiBzdHI6CiAgICBjcCA9IHN1YnBy'
    'b2Nlc3MucnVuKAogICAgICAgIFtWUE4sICphcmdzXSwKICAgICAgICB0ZXh0PVRydWUsCiAgICAgICAgc3Rkb3V0PXN1YnBy'
    'b2Nlc3MuUElQRSwKICAgICAgICBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgIHRpbWVvdXQ9dGltZW91dCwKICAg'
    'ICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgY2hlY2s9RmFsc2UsCiAgICApCiAgICBpZiBjcC5yZXR1'
    'cm5jb2RlICE9IDA6CiAgICAgICAgZGV0YWlsID0gKGNwLnN0ZGVyciBvciBjcC5zdGRvdXQgb3IgZiJleGl0IHtjcC5yZXR1'
    'cm5jb2RlfSIpLnN0cmlwKCkKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoZGV0YWlsKQogICAgcmV0dXJuIChjcC5zdGRv'
    'dXQgb3IgIiIpLnN0cmlwKCkKCgpkZWYgcnVuX3Zwbl9qc29uKGFyZ3M6IGxpc3Rbc3RyXSkgLT4gZGljdDoKICAgIHJhdyA9'
    'IHJ1bl92cG4oYXJncywgdGltZW91dD0xMCkKICAgIHRyeToKICAgICAgICBkYXRhID0ganNvbi5sb2FkcyhyYXcpCiAgICBl'
    'eGNlcHQganNvbi5KU09ORGVjb2RlRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihmIlZQTiBNYW5h'
    'Z2VyINCy0LXRgNC90YPQuyDQvdC10LrQvtGA0YDQtdC60YLQvdGL0LkgSlNPTjoge2V4Y30iKSBmcm9tIGV4YwogICAgaWYg'
    'bm90IGlzaW5zdGFuY2UoZGF0YSwgZGljdCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCJWUE4gTWFuYWdlciDQstC1'
    '0YDQvdGD0Lsg0L3QtdC+0LbQuNC00LDQvdC90YvQuSDQvtGC0LLQtdGCLiIpCiAgICByZXR1cm4gZGF0YQoKCmRlZiBlbmNv'
    'ZGVfdWlfcGF5bG9hZChwYXlsb2FkOiBkaWN0KSAtPiBzdHI6CiAgICByYXcgPSBqc29uLmR1bXBzKHBheWxvYWQsIGVuc3Vy'
    'ZV9hc2NpaT1GYWxzZSwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKQogICAgcXVvdGVkID0gdXJsbGliLnBhcnNlLnF1b3RlKHJh'
    'dywgc2FmZT0iIikKICAgIHJldHVybiBiYXNlNjQuYjY0ZW5jb2RlKHF1b3RlZC5lbmNvZGUoImFzY2lpIikpLmRlY29kZSgi'
    'YXNjaWkiKQoKCmNsYXNzIEFwaVNlcnZlcihodHRwLnNlcnZlci5UaHJlYWRpbmdIVFRQU2VydmVyKToKICAgIGRhZW1vbl90'
    'aHJlYWRzID0gVHJ1ZQogICAgYWxsb3dfcmV1c2VfYWRkcmVzcyA9IEZhbHNlCgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGFk'
    'ZHJlc3MsIGhhbmRsZXIsIHRva2VuOiBzdHIpOgogICAgICAgIHN1cGVyKCkuX19pbml0X18oYWRkcmVzcywgaGFuZGxlcikK'
    'ICAgICAgICBzZWxmLnRva2VuID0gdG9rZW4KCgpjbGFzcyBIYW5kbGVyKGh0dHAuc2VydmVyLkJhc2VIVFRQUmVxdWVzdEhh'
    'bmRsZXIpOgogICAgc2VydmVyOiBBcGlTZXJ2ZXIKCiAgICBkZWYgbG9nX21lc3NhZ2Uoc2VsZiwgX2Zvcm1hdDogc3RyLCAq'
    'X2FyZ3MpIC0+IE5vbmU6CiAgICAgICAgcmV0dXJuCgogICAgZGVmIF9oZWFkZXJzKHNlbGYsIHN0YXR1czogaW50ID0gMjAw'
    'LCBjb250ZW50X3R5cGU6IHN0ciA9ICJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PXV0Zi04IikgLT4gTm9uZToKICAgICAg'
    'ICBzZWxmLnNlbmRfcmVzcG9uc2Uoc3RhdHVzKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtVHlwZSIsIGNv'
    'bnRlbnRfdHlwZSkKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDYWNoZS1Db250cm9sIiwgIm5vLXN0b3JlIikKICAgICAg'
    'ICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iLCAiKiIpCiAgICAgICAgc2VsZi5zZW5k'
    'X2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyIsICJDb250ZW50LVR5cGUsIFgtRXZnZW5pdW0tVG9rZW4i'
    'KQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMiLCAiR0VULCBQT1NULCBP'
    'UFRJT05TIikKICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKCiAgICBkZWYgX2pzb24oc2VsZiwgcGF5bG9hZDogZGljdCwg'
    'c3RhdHVzOiBpbnQgPSAyMDApIC0+IE5vbmU6CiAgICAgICAgZGF0YSA9IGpzb24uZHVtcHMocGF5bG9hZCwgZW5zdXJlX2Fz'
    'Y2lpPUZhbHNlLCBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29kZSgidXRmLTgiKQogICAgICAgIHNlbGYuc2VuZF9yZXNw'
    'b25zZShzdGF0dXMpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC1UeXBlIiwgImFwcGxpY2F0aW9uL2pzb247'
    'IGNoYXJzZXQ9dXRmLTgiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtTGVuZ3RoIiwgc3RyKGxlbihkYXRh'
    'KSkpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ2FjaGUtQ29udHJvbCIsICJuby1zdG9yZSIpCiAgICAgICAgc2VsZi5z'
    'ZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luIiwgIioiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIo'
    'IkFjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMiLCAiQ29udGVudC1UeXBlLCBYLUV2Z2VuaXVtLVRva2VuIikKICAgICAg'
    'ICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzIiwgIkdFVCwgUE9TVCwgT1BUSU9OUyIp'
    'CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICAgICAgc2VsZi53ZmlsZS53cml0'
    'ZShkYXRhKQogICAgICAgIGV4Y2VwdCAoQnJva2VuUGlwZUVycm9yLCBDb25uZWN0aW9uUmVzZXRFcnJvcik6CiAgICAgICAg'
    'ICAgICMgVGhlIFVJIG1heSBoYXZlIGNsb3NlZCBvciBjYW5jZWxlZCBhIHBvbGwuIERvIG5vdCBlbWl0IGEgc2Vjb25kIHJl'
    'c3BvbnNlLgogICAgICAgICAgICByZXR1cm4KCiAgICBkZWYgX2F1dGhvcml6ZWQoc2VsZikgLT4gYm9vbDoKICAgICAgICBy'
    'ZXR1cm4gc2VjcmV0cy5jb21wYXJlX2RpZ2VzdCgKICAgICAgICAgICAgc2VsZi5oZWFkZXJzLmdldCgiWC1Fdmdlbml1bS1U'
    'b2tlbiIsICIiKSwKICAgICAgICAgICAgc2VsZi5zZXJ2ZXIudG9rZW4sCiAgICAgICAgKQoKICAgIGRlZiBfcmVxdWlyZV9h'
    'dXRoKHNlbGYpIC0+IGJvb2w6CiAgICAgICAgaWYgc2VsZi5fYXV0aG9yaXplZCgpOgogICAgICAgICAgICByZXR1cm4gVHJ1'
    'ZQogICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAiZXJyb3IiOiAidW5hdXRob3JpemVkIn0sIDQwMykKICAgICAg'
    'ICByZXR1cm4gRmFsc2UKCiAgICBkZWYgX3JlYWRfanNvbihzZWxmKSAtPiBkaWN0OgogICAgICAgIHRyeToKICAgICAgICAg'
    'ICAgbGVuZ3RoID0gaW50KHNlbGYuaGVhZGVycy5nZXQoIkNvbnRlbnQtTGVuZ3RoIiwgIjAiKSkKICAgICAgICBleGNlcHQg'
    'VmFsdWVFcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3R'
    'i9C5IENvbnRlbnQtTGVuZ3RoLiIpIGZyb20gZXhjCiAgICAgICAgaWYgbGVuZ3RoIDwgMCBvciBsZW5ndGggPiBNQVhfQk9E'
    'WToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC70LjRiNC60L7QvCDQsdC+0LvRjNGI0L7QuSDQt9Cw0L/R'
    'gNC+0YEuIikKICAgICAgICByYXcgPSBzZWxmLnJmaWxlLnJlYWQobGVuZ3RoKQogICAgICAgIHRyeToKICAgICAgICAgICAg'
    'cGF5bG9hZCA9IGpzb24ubG9hZHMocmF3LmRlY29kZSgidXRmLTgiKSBpZiByYXcgZWxzZSAie30iKQogICAgICAgIGV4Y2Vw'
    'dCAoVW5pY29kZURlY29kZUVycm9yLCBqc29uLkpTT05EZWNvZGVFcnJvcikgYXMgZXhjOgogICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoZiLQndC10LrQvtGA0YDQtdC60YLQvdGL0LkgSlNPTjoge2V4Y30iKSBmcm9tIGV4YwogICAgICAgIGlm'
    'IG5vdCBpc2luc3RhbmNlKHBheWxvYWQsIGRpY3QpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCe0LbQuNC0'
    '0LDQu9GB0Y8gSlNPTiBvYmplY3QuIikKICAgICAgICByZXR1cm4gcGF5bG9hZAoKICAgIGRlZiBkb19PUFRJT05TKHNlbGYp'
    'IC0+IE5vbmU6CiAgICAgICAgc2VsZi5faGVhZGVycygyMDQpCgogICAgZGVmIGRvX0dFVChzZWxmKSAtPiBOb25lOgogICAg'
    'ICAgIGlmIG5vdCBzZWxmLl9yZXF1aXJlX2F1dGgoKToKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgdHJ5OgogICAgICAg'
    'ICAgICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvc3RhdGUiOgogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1'
    'ZSwgInN0YXRlIjogcnVuX3Zwbl9qc29uKFsidWkiLCAic3RhdGUiXSl9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAg'
    'ICAgICAgIGlmIHNlbGYucGF0aCA9PSAiL2FwaS9ydW5uaW5nIjoKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6'
    'IFRydWUsICJydW5uaW5nIjogcnVuX3Zwbl9qc29uKFsidWkiLCAicnVubmluZyJdKX0pCiAgICAgICAgICAgICAgICByZXR1'
    'cm4KICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL2hlYWx0aCI6CiAgICAgICAgICAgICAgICBzZWxmLl9qc29u'
    'KHsib2siOiBUcnVlLCAiYXBwIjogQVBQX05BTUV9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIHNlbGYu'
    'X2pzb24oeyJvayI6IEZhbHNlLCAiZXJyb3IiOiAibm90IGZvdW5kIn0sIDQwNCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9u'
    'IGFzIGV4YzoKICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6IHN0cihleGMpfSwgNTAwKQoK'
    'ICAgIGRlZiBkb19QT1NUKHNlbGYpIC0+IE5vbmU6CiAgICAgICAgaWYgbm90IHNlbGYuX3JlcXVpcmVfYXV0aCgpOgogICAg'
    'ICAgICAgICByZXR1cm4KICAgICAgICB0cnk6CiAgICAgICAgICAgIHBheWxvYWQgPSBzZWxmLl9yZWFkX2pzb24oKQogICAg'
    'ICAgICAgICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvYWN0aW9uIjoKICAgICAgICAgICAgICAgIHRva2VuID0gZW5jb2RlX3Vp'
    'X3BheWxvYWQocGF5bG9hZCkKICAgICAgICAgICAgICAgIG91dHB1dCA9IHJ1bl92cG4oWyJ1aSIsICJhY3Rpb24iLCB0b2tl'
    'bl0pCiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAib3V0cHV0Ijogb3V0cHV0fSkKICAgICAgICAg'
    'ICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvdG9nZ2xlIjoKICAgICAgICAgICAgICAg'
    'IG91dHB1dCA9IHJ1bl92cG4oWyJ0b2dnbGUiXSkKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IFRydWUsICJv'
    'dXRwdXQiOiBvdXRwdXQsICJzdGF0ZSI6IHJ1bl92cG5fanNvbihbInVpIiwgInN0YXRlIl0pfSkKICAgICAgICAgICAgICAg'
    'IHJldHVybgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogIm5vdCBmb3VuZCJ9LCA0MDQp'
    'CiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAi'
    'ZXJyb3IiOiBzdHIoZXhjKX0sIDUwMCkKCgpkZWYgc3RhdGVfbG9nX3BhdGgoKSAtPiBwYXRobGliLlBhdGg6CiAgICByb290'
    'ID0gcGF0aGxpYi5QYXRoKG9zLmVudmlyb24uZ2V0KCJYREdfU1RBVEVfSE9NRSIsIHBhdGhsaWIuUGF0aC5ob21lKCkgLyAi'
    'LmxvY2FsIiAvICJzdGF0ZSIpKQogICAgcGF0aCA9IHJvb3QgLyAiZXZnZW5pdW0tbmV0d29yayIgLyAiZ3VpLmxvZyIKICAg'
    'IHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHJldHVybiBwYXRoCgoKZGVmIGxh'
    'dW5jaF9kZXRhY2hlZCgpIC0+IGludDoKICAgIGlmIG5vdCBRTUxfRklMRS5pc19maWxlKCk6CiAgICAgICAgcHJpbnQoZiLQ'
    'ndC1INC90LDQudC00LXQvSDQuNC90YLQtdGA0YTQtdC50YE6IHtRTUxfRklMRX0iLCBmaWxlPXN5cy5zdGRlcnIpCiAgICAg'
    'ICAgcmV0dXJuIDEKICAgIGlmIG5vdCBmaW5kX3FtbF9ydW50aW1lKCk6CiAgICAgICAgcHJpbnQoItCd0LUg0L3QsNC50LTQ'
    'tdC9IFF0IDYgUU1MIHJ1bnRpbWUgKEFyY2g6IHF0Ni1kZWNsYXJhdGl2ZTsgRmVkb3JhOiBxdDYtcXRkZWNsYXJhdGl2ZS1k'
    'ZXZlbCkuIiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBsb2dfcGF0aCA9IHN0YXRlX2xvZ19wYXRo'
    'KCkKICAgIHdpdGggbG9nX3BhdGgub3BlbigiYWIiLCBidWZmZXJpbmc9MCkgYXMgbG9nOgogICAgICAgIHN1YnByb2Nlc3Mu'
    'UG9wZW4oCiAgICAgICAgICAgIFtzeXMuZXhlY3V0YWJsZSwgc3RyKHBhdGhsaWIuUGF0aChfX2ZpbGVfXykucmVzb2x2ZSgp'
    'KV0sCiAgICAgICAgICAgIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwKICAgICAgICAgICAgc3Rkb3V0PWxvZywKICAgICAg'
    'ICAgICAgc3RkZXJyPWxvZywKICAgICAgICAgICAgc3RhcnRfbmV3X3Nlc3Npb249VHJ1ZSwKICAgICAgICAgICAgY2xvc2Vf'
    'ZmRzPVRydWUsCiAgICAgICAgKQogICAgcmV0dXJuIDAKCgpkZWYgcnVuX2d1aSgpIC0+IGludDoKICAgIHFtbCA9IGZpbmRf'
    'cW1sX3J1bnRpbWUoKQogICAgaWYgbm90IHFtbDoKICAgICAgICBwcmludCgi0J3QtSDQvdCw0LnQtNC10L0gUXQgNiBRTUwg'
    'cnVudGltZSAoQXJjaDogcXQ2LWRlY2xhcmF0aXZlOyBGZWRvcmE6IHF0Ni1xdGRlY2xhcmF0aXZlLWRldmVsKS4iLCBmaWxl'
    'PXN5cy5zdGRlcnIpCiAgICAgICAgcmV0dXJuIDEKICAgIGlmIG5vdCBRTUxfRklMRS5pc19maWxlKCk6CiAgICAgICAgcHJp'
    'bnQoZiLQndC1INC90LDQudC00LXQvSDQuNC90YLQtdGA0YTQtdC50YE6IHtRTUxfRklMRX0iLCBmaWxlPXN5cy5zdGRlcnIp'
    'CiAgICAgICAgcmV0dXJuIDEKCiAgICB0b2tlbiA9IHNlY3JldHMudG9rZW5fdXJsc2FmZSgzMikKICAgIHNlcnZlciA9IEFw'
    'aVNlcnZlcigoIjEyNy4wLjAuMSIsIDApLCBIYW5kbGVyLCB0b2tlbikKICAgIHBvcnQgPSBpbnQoc2VydmVyLnNlcnZlcl9h'
    'ZGRyZXNzWzFdKQogICAgdGhyZWFkID0gdGhyZWFkaW5nLlRocmVhZCh0YXJnZXQ9c2VydmVyLnNlcnZlX2ZvcmV2ZXIsIG5h'
    'bWU9ImV2Z2VuaXVtLWd1aS1hcGkiLCBkYWVtb249VHJ1ZSkKICAgIHRocmVhZC5zdGFydCgpCgogICAgZW52ID0gb3MuZW52'
    'aXJvbi5jb3B5KCkKICAgIGVudi5zZXRkZWZhdWx0KCJRVF9RVUlDS19DT05UUk9MU19TVFlMRSIsICJCYXNpYyIpCiAgICBl'
    'bnYuc2V0ZGVmYXVsdCgiUU1MX0RJU0FCTEVfRElTS19DQUNIRSIsICIwIikKCiAgICB0cnk6CiAgICAgICAgY3AgPSBzdWJw'
    'cm9jZXNzLnJ1bigKICAgICAgICAgICAgW3FtbCwgc3RyKFFNTF9GSUxFKSwgIi0tIiwgc3RyKHBvcnQpLCB0b2tlbl0sCiAg'
    'ICAgICAgICAgIGVudj1lbnYsCiAgICAgICAgICAgIGNoZWNrPUZhbHNlLAogICAgICAgICkKICAgICAgICByZXR1cm4gaW50'
    'KGNwLnJldHVybmNvZGUpCiAgICBmaW5hbGx5OgogICAgICAgIHNlcnZlci5zaHV0ZG93bigpCiAgICAgICAgc2VydmVyLnNl'
    'cnZlcl9jbG9zZSgpCiAgICAgICAgdGhyZWFkLmpvaW4odGltZW91dD0yKQoKCmRlZiBzZWxmX3Rlc3QoKSAtPiBpbnQ6CiAg'
    'ICBzYW1wbGUgPSB7ImFjdGlvbiI6ICJhcHBfYWRkIiwgInRhcmdldCI6ICIvb3B0L2V4YW1wbGUvYmluL2FwcCJ9CiAgICB0'
    'b2tlbiA9IGVuY29kZV91aV9wYXlsb2FkKHNhbXBsZSkKICAgIGRlY29kZWQgPSB1cmxsaWIucGFyc2UudW5xdW90ZShiYXNl'
    'NjQuYjY0ZGVjb2RlKHRva2VuKS5kZWNvZGUoImFzY2lpIikpCiAgICBhc3NlcnQganNvbi5sb2FkcyhkZWNvZGVkKSA9PSBz'
    'YW1wbGUKICAgIGFzc2VydCBNQVhfQk9EWSA8PSAxMDI0ICogMTAyNAogICAgcW1sID0gSEVSRSAvICJldmdlbml1bV9ndWku'
    'cW1sIgogICAgaWYgcW1sLmV4aXN0cygpOgogICAgICAgIHRleHQgPSBxbWwucmVhZF90ZXh0KGVuY29kaW5nPSJ1dGYtOCIp'
    'CiAgICAgICAgYXNzZXJ0ICJFdmdlbml1bSBOZXR3b3JrIiBpbiB0ZXh0CiAgICAgICAgYXNzZXJ0ICIvYXBpL3J1bm5pbmci'
    'IGluIHRleHQKICAgICAgICBhc3NlcnQgIi9hcGkvYWN0aW9uIiBpbiB0ZXh0CiAgICBwcmludCgiZXZnZW5pdW0tZ3VpIHNl'
    'bGYtdGVzdCBPSyIpCiAgICByZXR1cm4gMAoKCmRlZiBtYWluKCkgLT4gaW50OgogICAgaWYgIi0tc2VsZi10ZXN0IiBpbiBz'
    'eXMuYXJndjoKICAgICAgICByZXR1cm4gc2VsZl90ZXN0KCkKICAgIGlmICItLWRldGFjaCIgaW4gc3lzLmFyZ3Y6CiAgICAg'
    'ICAgcmV0dXJuIGxhdW5jaF9kZXRhY2hlZCgpCiAgICByZXR1cm4gcnVuX2d1aSgpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFp'
    'bl9fIjoKICAgIHJhaXNlIFN5c3RlbUV4aXQobWFpbigpKQo='
)
STANDALONE_GUI_QML_B64 = (
    'aW1wb3J0IFF0UXVpY2sKaW1wb3J0IFF0UW1sCmltcG9ydCBRdFF1aWNrLkNvbnRyb2xzIGFzIEMKaW1wb3J0IFF0UXVpY2su'
    'TGF5b3V0cwoKQy5BcHBsaWNhdGlvbldpbmRvdyB7CiAgICBpZDogcm9vdAogICAgd2lkdGg6IDEwNDAKICAgIGhlaWdodDog'
    'NzAwCiAgICBtaW5pbXVtV2lkdGg6IDg2MAogICAgbWluaW11bUhlaWdodDogNTgwCiAgICB2aXNpYmxlOiB0cnVlCiAgICB0'
    'aXRsZTogIkV2Z2VuaXVtIE5ldHdvcmsiCiAgICBjb2xvcjogIiNmNGY2ZmEiCgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29s'
    'b3IgYmc6ICIjZjRmNmZhIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3Igc3VyZmFjZTogIiNmZmZmZmYiCiAgICByZWFk'
    'b25seSBwcm9wZXJ0eSBjb2xvciBzaWRlYmFyOiAiIzExMTgyNyIKICAgIHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIHNpZGVi'
    'YXJIb3ZlcjogIiMxZjI5MzciCiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciBhY2NlbnQ6ICIjMzlhZWYwIgogICAgcmVh'
    'ZG9ubHkgcHJvcGVydHkgY29sb3IgYWNjZW50U29mdDogIiNlOGY2ZmUiCiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciB0'
    'ZXh0TWFpbjogIiMxMTE4MjciCiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciB0ZXh0TXV0ZWQ6ICIjNmI3MjgwIgogICAg'
    'cmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYm9yZGVyOiAiI2U1ZTdlYiIKICAgIHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIGdv'
    'b2Q6ICIjMTZhMzRhIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYmFkOiAiI2RjMjYyNiIKCiAgICBwcm9wZXJ0eSBp'
    'bnQgcGFnZUluZGV4OiAwCiAgICBwcm9wZXJ0eSBib29sIGJ1c3k6IGZhbHNlCiAgICBwcm9wZXJ0eSBzdHJpbmcgZXJyb3JU'
    'ZXh0OiAiIgogICAgcHJvcGVydHkgc3RyaW5nIHBvbGxFcnJvclRleHQ6ICIiCiAgICBwcm9wZXJ0eSB2YXIgc3RhdGU6ICh7'
    'fSkKICAgIHByb3BlcnR5IHZhciBydW5uaW5nQXBwczogW10KICAgIHJlYWRvbmx5IHByb3BlcnR5IHZhciBleHBlcmltZW50'
    'OiByb290LnN0YXRlLmV4cGVyaW1lbnRhbCB8fCAoe30pCgogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIGFyZ3M6IFF0LmFw'
    'cGxpY2F0aW9uLmFyZ3VtZW50cwogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVRva2VuOiBhcmdzLmxlbmd0aCA+'
    'PSAyID8gU3RyaW5nKGFyZ3NbYXJncy5sZW5ndGggLSAxXSkgOiAiIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFw'
    'aVBvcnQ6IGFyZ3MubGVuZ3RoID49IDMgPyBTdHJpbmcoYXJnc1thcmdzLmxlbmd0aCAtIDJdKSA6ICIwIgogICAgcmVhZG9u'
    'bHkgcHJvcGVydHkgc3RyaW5nIGFwaUJhc2U6ICJodHRwOi8vMTI3LjAuMC4xOiIgKyBhcGlQb3J0CgogICAgcHJvcGVydHkg'
    'Ym9vbCBzdGF0ZVBlbmRpbmc6IGZhbHNlCiAgICBwcm9wZXJ0eSBib29sIHJ1bm5pbmdQZW5kaW5nOiBmYWxzZQoKICAgIGZ1'
    'bmN0aW9uIGFwaShtZXRob2QsIHBhdGgsIGJvZHksIGNhbGxiYWNrLCBvcGVyYXRpb24pIHsKICAgICAgICBjb25zdCB4aHIg'
    'PSBuZXcgWE1MSHR0cFJlcXVlc3QoKQogICAgICAgIGxldCBmaW5pc2hlZCA9IGZhbHNlCiAgICAgICAgY29uc3QgdGltZXIg'
    'PSByZXF1ZXN0VGltZXIuY3JlYXRlT2JqZWN0KHJvb3QpCiAgICAgICAgZnVuY3Rpb24gZmluaXNoKGVycm9yLCBwYXlsb2Fk'
    'KSB7CiAgICAgICAgICAgIGlmIChmaW5pc2hlZCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBmaW5pc2hl'
    'ZCA9IHRydWUKICAgICAgICAgICAgdGltZXIuc3RvcCgpCiAgICAgICAgICAgIHRpbWVyLmRlc3Ryb3koKQogICAgICAgICAg'
    'ICBpZiAocGF0aCA9PT0gIi9hcGkvc3RhdGUiKSByb290LnN0YXRlUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChw'
    'YXRoID09PSAiL2FwaS9ydW5uaW5nIikgcm9vdC5ydW5uaW5nUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChvcGVy'
    'YXRpb24pIHsKICAgICAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAgICAgICByb290LmVycm9yVGV4'
    'dCA9IGVycm9yIHx8ICIiCiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICByb290LnBvbGxFcnJvclRleHQg'
    'PSBlcnJvciB8fCAiIgogICAgICAgICAgICB9CiAgICAgICAgICAgIGlmICghZXJyb3IgJiYgY2FsbGJhY2spIGNhbGxiYWNr'
    'KHBheWxvYWQpCiAgICAgICAgfQogICAgICAgIHRpbWVyLmludGVydmFsID0gb3BlcmF0aW9uID8gNzgwMDAwIDogMTIwMDAK'
    'ICAgICAgICB0aW1lci50cmlnZ2VyZWQuY29ubmVjdChmdW5jdGlvbigpIHsKICAgICAgICAgICAgZmluaXNoKG9wZXJhdGlv'
    'biA/ICLQntGC0LLQtdGCINC+0L/QtdGA0LDRhtC40Lgg0L3QtSDQv9C+0LvRg9GH0LXQvS4g0J/RgNC+0LLQtdGA0YwgdnBu'
    'IHN0YXR1cyDQv9C10YDQtdC0INC/0L7QstGC0L7RgNC90YvQvCDQv9C10YDQtdC60LvRjtGH0LXQvdC40LXQvC4iIDogItCe'
    '0L/RgNC+0YEg0YHQvtGB0YLQvtGP0L3QuNGPINC90LUg0LfQsNCy0LXRgNGI0LjQu9GB0Y8iLCBudWxsKQogICAgICAgICAg'
    'ICB4aHIuYWJvcnQoKQogICAgICAgIH0pCiAgICAgICAgeGhyLm9wZW4obWV0aG9kLCBhcGlCYXNlICsgcGF0aCwgdHJ1ZSkK'
    'ICAgICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcigiWC1Fdmdlbml1bS1Ub2tlbiIsIGFwaVRva2VuKQogICAgICAgIGlmIChi'
    'b2R5ICE9PSBudWxsKQogICAgICAgICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcigiQ29udGVudC1UeXBlIiwgImFwcGxpY2F0'
    'aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgiKQogICAgICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHsK'
    'ICAgICAgICAgICAgaWYgKHhoci5yZWFkeVN0YXRlICE9PSBYTUxIdHRwUmVxdWVzdC5ET05FIHx8IGZpbmlzaGVkKQogICAg'
    'ICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGxldCBwYXlsb2FkID0gbnVsbAogICAgICAgICAgICB0cnkgeyBwYXls'
    'b2FkID0gSlNPTi5wYXJzZShTdHJpbmcoeGhyLnJlc3BvbnNlVGV4dCB8fCAie30iKSkgfQogICAgICAgICAgICBjYXRjaCAo'
    'ZSkgeyBmaW5pc2goItCd0LUg0YPQtNCw0LvQvtGB0Ywg0YDQsNC30L7QsdGA0LDRgtGMINC+0YLQstC10YIg0LvQvtC60LDQ'
    'u9GM0L3QvtCz0L4gQVBJIiwgbnVsbCk7IHJldHVybiB9CiAgICAgICAgICAgIGlmICh4aHIuc3RhdHVzIDwgMjAwIHx8IHho'
    'ci5zdGF0dXMgPj0gMzAwIHx8ICFwYXlsb2FkLm9rKSB7CiAgICAgICAgICAgICAgICBmaW5pc2goU3RyaW5nKHBheWxvYWQu'
    'ZXJyb3IgfHwgKCJIVFRQICIgKyB4aHIuc3RhdHVzKSksIG51bGwpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICBmaW5pc2gobnVsbCwgcGF5bG9hZCkKICAgICAgICB9CiAgICAgICAgdGltZXIuc3RhcnQoKQog'
    'ICAgICAgIHhoci5zZW5kKGJvZHkgPT09IG51bGwgPyBudWxsIDogSlNPTi5zdHJpbmdpZnkoYm9keSkpCiAgICB9CgogICAg'
    'Q29tcG9uZW50IHsKICAgICAgICBpZDogcmVxdWVzdFRpbWVyCiAgICAgICAgVGltZXIgeyByZXBlYXQ6IGZhbHNlIH0KICAg'
    'IH0KCiAgICBmdW5jdGlvbiByZWZyZXNoU3RhdGUoKSB7CiAgICAgICAgaWYgKHN0YXRlUGVuZGluZykgcmV0dXJuCiAgICAg'
    'ICAgc3RhdGVQZW5kaW5nID0gdHJ1ZQogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvc3RhdGUiLCBudWxsLCBmdW5jdGlvbihw'
    'YXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9KQogICAg'
    'fQoKICAgIGZ1bmN0aW9uIHJlZnJlc2hSdW5uaW5nKCkgewogICAgICAgIGlmIChydW5uaW5nUGVuZGluZykgcmV0dXJuCiAg'
    'ICAgICAgcnVubmluZ1BlbmRpbmcgPSB0cnVlCiAgICAgICAgYXBpKCJHRVQiLCAiL2FwaS9ydW5uaW5nIiwgbnVsbCwgZnVu'
    'Y3Rpb24ocGF5bG9hZCkgewogICAgICAgICAgICByb290LnJ1bm5pbmdBcHBzID0gKHBheWxvYWQucnVubmluZyAmJiBwYXls'
    'b2FkLnJ1bm5pbmcuYXBwbGljYXRpb25zKSB8fCBbXQogICAgICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gYWN0aW9uKHBh'
    'eWxvYWQpIHsKICAgICAgICBpZiAoYnVzeSB8fCBCb29sZWFuKHN0YXRlLmNvbm5lY3RpbmcpKQogICAgICAgICAgICByZXR1'
    'cm4KICAgICAgICBidXN5ID0gdHJ1ZQogICAgICAgIGFwaSgiUE9TVCIsICIvYXBpL2FjdGlvbiIsIHBheWxvYWQsIGZ1bmN0'
    'aW9uKF9yZXBseSkgewogICAgICAgICAgICByb290LmJ1c3kgPSBmYWxzZQogICAgICAgICAgICByb290LnJlZnJlc2hTdGF0'
    'ZSgpCiAgICAgICAgICAgIHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgIH0sIHRydWUpCiAgICB9CgogICAgZnVuY3Rp'
    'b24gdG9nZ2xlVnBuKCkgewogICAgICAgIGlmIChidXN5IHx8IEJvb2xlYW4oc3RhdGUuY29ubmVjdGluZykpCiAgICAgICAg'
    'ICAgIHJldHVybgogICAgICAgIGJ1c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkvdG9nZ2xlIiwge30sIGZ1'
    'bmN0aW9uKHBheWxvYWQpIHsKICAgICAgICAgICAgcm9vdC5idXN5ID0gZmFsc2UKICAgICAgICAgICAgcm9vdC5zdGF0ZSA9'
    'IHBheWxvYWQuc3RhdGUgfHwgKHt9KQogICAgICAgIH0sIHRydWUpCiAgICB9CgogICAgZnVuY3Rpb24gZmlsdGVyZWRSdW5u'
    'aW5nKCkgewogICAgICAgIGNvbnN0IG5lZWRsZSA9IGFwcFNlYXJjaC50ZXh0LnRyaW0oKS50b0xvd2VyQ2FzZSgpCiAgICAg'
    'ICAgaWYgKCFuZWVkbGUubGVuZ3RoKQogICAgICAgICAgICByZXR1cm4gcnVubmluZ0FwcHMKICAgICAgICByZXR1cm4gcnVu'
    'bmluZ0FwcHMuZmlsdGVyKGZ1bmN0aW9uKGFwcCkgewogICAgICAgICAgICByZXR1cm4gU3RyaW5nKGFwcC5uYW1lIHx8ICIi'
    'KS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICAgICAgICAgIHx8IFN0cmluZyhhcHAuZXhlIHx8ICIi'
    'KS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICB9KQogICAgfQoKICAgIENvbXBvbmVudC5vbkNvbXBs'
    'ZXRlZDogewogICAgICAgIHJlZnJlc2hTdGF0ZSgpCiAgICAgICAgcmVmcmVzaFJ1bm5pbmcoKQogICAgfQoKICAgIFRpbWVy'
    'IHsKICAgICAgICBpbnRlcnZhbDogMjUwMAogICAgICAgIHJlcGVhdDogdHJ1ZQogICAgICAgIHJ1bm5pbmc6IHRydWUKICAg'
    'ICAgICBvblRyaWdnZXJlZDogcm9vdC5yZWZyZXNoU3RhdGUoKQogICAgfQoKICAgIGNvbXBvbmVudCBGbGF0QnV0dG9uOiBS'
    'ZWN0YW5nbGUgewogICAgICAgIGlkOiBmbGF0QnV0dG9uCiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgc3RyaW5nIGxhYmVs'
    'CiAgICAgICAgcHJvcGVydHkgYm9vbCBwcmltYXJ5OiBmYWxzZQogICAgICAgIHByb3BlcnR5IGJvb2wgZGFuZ2VyOiBmYWxz'
    'ZQogICAgICAgIHByb3BlcnR5IGJvb2wgZW5hYmxlZEJ1dHRvbjogdHJ1ZQogICAgICAgIHNpZ25hbCBjbGlja2VkKCkKICAg'
    'ICAgICBpbXBsaWNpdEhlaWdodDogMzgKICAgICAgICBpbXBsaWNpdFdpZHRoOiBNYXRoLm1heCg5MiwgYnV0dG9uVGV4dC5p'
    'bXBsaWNpdFdpZHRoICsgMjgpCiAgICAgICAgcmFkaXVzOiAxMAogICAgICAgIGNvbG9yOiAhZW5hYmxlZEJ1dHRvbiA/ICIj'
    'ZWVmMGYzIgogICAgICAgICAgICAgIDogZGFuZ2VyID8gKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiI2ZlZTJlMiIg'
    'OiAiI2ZlZjJmMiIpCiAgICAgICAgICAgICAgOiBwcmltYXJ5ID8gKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiIzIw'
    'OTlkYyIgOiByb290LmFjY2VudCkKICAgICAgICAgICAgICA6IChidXR0b25Nb3VzZS5jb250YWluc01vdXNlID8gIiNlZWYy'
    'ZjciIDogIiNmN2Y5ZmMiKQogICAgICAgIGJvcmRlci53aWR0aDogcHJpbWFyeSA/IDAgOiAxCiAgICAgICAgYm9yZGVyLmNv'
    'bG9yOiBkYW5nZXIgPyAiI2ZlY2FjYSIgOiByb290LmJvcmRlcgogICAgICAgIG9wYWNpdHk6IGVuYWJsZWRCdXR0b24gPyAx'
    'IDogMC42CgogICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICBpZDogYnV0dG9uVGV4dAogICAgICAgICAgICBhbmNob3Jz'
    'LmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgdGV4dDogZmxhdEJ1dHRvbi5sYWJlbAogICAgICAgICAgICBjb2xvcjog'
    'ZmxhdEJ1dHRvbi5wcmltYXJ5ID8gIndoaXRlIiA6IChmbGF0QnV0dG9uLmRhbmdlciA/IHJvb3QuYmFkIDogcm9vdC50ZXh0'
    'TWFpbikKICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEzCiAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlC'
    'b2xkCiAgICAgICAgfQogICAgICAgIE1vdXNlQXJlYSB7CiAgICAgICAgICAgIGlkOiBidXR0b25Nb3VzZQogICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBlbmFibGVkOiBmbGF0QnV0dG9uLmVuYWJsZWRCdXR0b24KICAg'
    'ICAgICAgICAgaG92ZXJFbmFibGVkOiB0cnVlCiAgICAgICAgICAgIGN1cnNvclNoYXBlOiBlbmFibGVkID8gUXQuUG9pbnRp'
    'bmdIYW5kQ3Vyc29yIDogUXQuQXJyb3dDdXJzb3IKICAgICAgICAgICAgb25DbGlja2VkOiBmbGF0QnV0dG9uLmNsaWNrZWQo'
    'KQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgTmF2QnV0dG9uOiBSZWN0YW5nbGUgewogICAgICAgIGlkOiBuYXYK'
    'ICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbGFiZWwKICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBpbnQgaW5k'
    'ZXgKICAgICAgICBwcm9wZXJ0eSBzdHJpbmcgc2hvcnRMYWJlbDogIiIKICAgICAgICBzaWduYWwgY2xpY2tlZCgpCiAgICAg'
    'ICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgIGltcGxpY2l0V2lkdGg6IDE4NgogICAgICAgIGhlaWdodDogNDgK'
    'ICAgICAgICByYWRpdXM6IDExCiAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBpbmRleCA/ICIjMjUzMjQ2IiA6'
    'IChuYXZNb3VzZS5jb250YWluc01vdXNlID8gcm9vdC5zaWRlYmFySG92ZXIgOiAidHJhbnNwYXJlbnQiKQoKICAgICAgICBS'
    'b3dMYXlvdXQgewogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBhbmNob3JzLmxlZnRNYXJn'
    'aW46IDEyCiAgICAgICAgICAgIGFuY2hvcnMucmlnaHRNYXJnaW46IDEyCiAgICAgICAgICAgIHNwYWNpbmc6IDExCiAgICAg'
    'ICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICB3aWR0aDogMjgKICAgICAgICAgICAgICAgIGhlaWdodDogMjgK'
    'ICAgICAgICAgICAgICAgIHJhZGl1czogOAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYu'
    'aW5kZXggPyByb290LmFjY2VudCA6ICIjMjczNDQ5IgogICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgdGV4dDogbmF2LnNob3J0TGFiZWwK'
    'ICAgICAgICAgICAgICAgICAgICBjb2xvcjogIndoaXRlIgogICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAx'
    'MAogICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgIHRleHQ6IG5hdi5sYWJlbAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYu'
    'aW5kZXggPyAid2hpdGUiIDogIiNjYmQ1ZTEiCiAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAg'
    'ICAgICAgIGZvbnQud2VpZ2h0OiByb290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gRm9udC5EZW1pQm9sZCA6IEZvbnQu'
    'Tm9ybWFsCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IG5hdk1v'
    'dXNlCiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAg'
    'ICAgICAgICBjdXJzb3JTaGFwZTogUXQuUG9pbnRpbmdIYW5kQ3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAg'
    'ICAgICAgICAgICAgcm9vdC5wYWdlSW5kZXggPSBuYXYuaW5kZXgKICAgICAgICAgICAgICAgIG5hdi5jbGlja2VkKCkKICAg'
    'ICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgQ2FyZDogUmVjdGFuZ2xlIHsKICAgICAgICByYWRp'
    'dXM6IDE2CiAgICAgICAgY29sb3I6IHJvb3Quc3VyZmFjZQogICAgICAgIGJvcmRlci53aWR0aDogMQogICAgICAgIGJvcmRl'
    'ci5jb2xvcjogcm9vdC5ib3JkZXIKICAgIH0KCiAgICBSb3dMYXlvdXQgewogICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'CiAgICAgICAgc3BhY2luZzogMAoKICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICBMYXlvdXQucHJlZmVycmVkV2lk'
    'dGg6IDIyMgogICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICBjb2xvcjogcm9vdC5zaWRl'
    'YmFyCgogICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAg'
    'ICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTgKICAgICAgICAgICAgICAgIHNwYWNpbmc6IDcKCiAgICAgICAgICAg'
    'ICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAg'
    'ICAgICAgICBMYXlvdXQuYm90dG9tTWFyZ2luOiAyNAogICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDExCiAgICAgICAg'
    'ICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDQwCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGhlaWdodDogNDAKICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAgICAgICAg'
    'ICAgICAgICBjb2xvcjogcm9vdC5hY2NlbnQKICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRl'
    'eHQ6ICJFIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGZvbnQucGl4ZWxTaXplOiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQu'
    'QmxhY2sKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAwCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIkV2Z2VuaXVtIgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXpl'
    'OiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'dGV4dDogIk5ldHdvcmsiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiM5NGEzYjgiCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogIlZQTiI7'
    'IHNob3J0TGFiZWw6ICJWUE4iOyBpbmRleDogMCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCf0YDQ'
    'vtGE0LjQu9C4IFZQTiI7IHNob3J0TGFiZWw6ICJQUkYiOyBpbmRleDogMSB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24g'
    'ewogICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J/RgNC40LvQvtC20LXQvdC40Y8iOyBzaG9ydExhYmVsOiAiQVBQIjsg'
    'aW5kZXg6IDIKICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6ICLQodCw0LnRgtGLINC4IElQIjsgc2hvcnRMYWJl'
    'bDogIk5FVCI7IGluZGV4OiAzIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0J/QvtGA0YLRiyI7IHNo'
    'b3J0TGFiZWw6ICJQUlQiOyBpbmRleDogNCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCU0LjQsNCz'
    '0L3QvtGB0YLQuNC60LAiOyBzaG9ydExhYmVsOiAiU1lTIjsgaW5kZXg6IDUgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9u'
    'IHsgbGFiZWw6ICLQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1Ijsgc2hvcnRMYWJlbDogIkVYUCI7IGluZGV4'
    'OiA2IH0KCiAgICAgICAgICAgICAgICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUgfQoKICAgICAgICAgICAgICAg'
    'IFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgIGhlaWdodDogNjQKICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEyCiAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'ICIjMTcyMDMzIgogICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiA1CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyByb290Lmdvb2QgOiAi'
    'IzY0NzQ4YiIKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgc3BhY2luZzogMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgdGV4dDogcm9vdC5zdGF0ZS5jb25uZWN0aW5nID8gItCS0YvQv9C+0LvQvdGP0LXRgtGB0Y8g'
    '0L7Qv9C10YDQsNGG0LjRjyBWUE7igKYiIDogKEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gIlZQTiDQstC60LvRjtGH'
    '0ZHQvSIgOiAiVlBOINCy0YvQutC70Y7Rh9C10L0iKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAi'
    'd2hpdGUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcocm9v'
    'dC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3RhdGUubGFzdF9wcm9maWxlIHx8ICLQndC10YIg0L/RgNC+0YTQuNC70Y8iKQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiIzk0YTNiOCIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBmb250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4dC5F'
    'bGlkZVJpZ2h0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CgogICAgICAgIEl0ZW0g'
    'ewogICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVl'
    'CgogICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMjgKICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE4CgogICAgICAgICAgICAg'
    'ICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdGV4dDogWyJWUE4iLCAi0J/RgNC+0YTQuNC70LggVlBOIiwgItCf0YDQuNC70L7QttC10L3QuNGP'
    'INCx0LXQtyBWUE4iLCAi0KHQsNC50YLRiyDQuCBJUCDQsdC10LcgVlBOIiwgItCS0YXQvtC00Y/RidC40LUg0L/QvtGA0YLR'
    'iyIsICLQlNC40LDQs9C90L7RgdGC0LjQutCwIiwgItCt0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdC+0LUiXVtyb290'
    'LnBhZ2VJbmRleF0KICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZm9udC5waXhlbFNpemU6IDI1CiAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJv'
    'bGQKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQy5CdXN5SW5kaWNhdG9yIHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgcnVubmluZzogcm9vdC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJ1bm5p'
    'bmcKICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRXaWR0aDogMjgKICAgICAgICAgICAgICAgICAgICAgICAgaW1w'
    'bGljaXRIZWlnaHQ6IDI4CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewog'
    'ICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCe0LHQvdC+0LLQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAg'
    'IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKQogICAgICAgICAg'
    'ICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QucmVmcmVzaFN0YXRl'
    'KCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyb290LnBhZ2VJbmRleCA9PT0gMikKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICByb290LnJlZnJlc2hSdW5uaW5nKCkKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAg'
    'ICAgICAgICAgIHZpc2libGU6IHJvb3QuZXJyb3JUZXh0Lmxlbmd0aCA+IDAgfHwgcm9vdC5wb2xsRXJyb3JUZXh0Lmxlbmd0'
    'aCA+IDAKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgaW1w'
    'bGljaXRIZWlnaHQ6IGVycm9yTGFiZWwuaW1wbGljaXRIZWlnaHQgKyAyMgogICAgICAgICAgICAgICAgICAgIHJhZGl1czog'
    'MTAKICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmZmYxZjIiCiAgICAgICAgICAgICAgICAgICAgYm9yZGVyLndpZHRo'
    'OiAxCiAgICAgICAgICAgICAgICAgICAgYm9yZGVyLmNvbG9yOiAiI2ZlY2RkMyIKICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGVycm9yTGFiZWwKICAgICAgICAgICAgICAgICAgICAgICAgYW5j'
    'aG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxMQogICAgICAgICAg'
    'ICAgICAgICAgICAgICB0ZXh0OiByb290LmVycm9yVGV4dCB8fCByb290LnBvbGxFcnJvclRleHQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgY29sb3I6IHJvb3QuYmFkCiAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0LldvcmRXcmFw'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBTdGFja0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgY3VycmVudEluZGV4OiByb290LnBhZ2VJbmRleAoKICAgICAgICAgICAgICAgICAgICAvLyBWUE4KICAgICAgICAg'
    'ICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMjgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAy'
    'MAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNw'
    'YWNpbmc6IDE4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogNzIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGhlaWdodDogNzIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMjIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/IHJv'
    'b3QuYWNjZW50U29mdCA6ICIjZWVmMmY3IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJl'
    'bCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmFj'
    'dGl2ZSkgPyAiT04iIDogIk9GRiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjog'
    'Qm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyByb290LmFjY2VudCA6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE4CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA1'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/ICLQl9Cw0YnQuNGJ0ZHQ'
    'vdC90L7QtSDRgdC+0LXQtNC40L3QtdC90LjQtSDQsNC60YLQuNCy0L3QviIgOiAiVlBOINGB0LXQudGH0LDRgSDQstGL0LrQ'
    'u9GO0YfQtdC9IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRN'
    'YWluCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDIwCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0'
    'ZS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgID8gKHJvb3Quc3RhdGUu'
    'YmFja2VuZCA9PT0gImlrZXYyIiA/ICLQktC10YHRjCBJUHY0LdGC0YDQsNGE0LjQuiDQuNC00ZHRgiDRh9C10YDQtdC3IFN0'
    'YXJGaXZlINCyINCg0L7RgdGB0LjQuC4gSVB2NiDQuCBESVJFQ1Qt0LjRgdC60LvRjtGH0LXQvdC40Y8g0L7RgtC60LvRjtGH'
    '0LXQvdGLLiIgOiAi0JLQtdGB0Ywg0L7QsdGL0YfQvdGL0Lkg0YLRgNCw0YTQuNC6INC40LTRkdGCINGH0LXRgNC10LcgVlBO'
    'LCDQutGA0L7QvNC1INC90LDRgdGC0YDQvtC10L3QvdGL0YUg0LjRgdC60LvRjtGH0LXQvdC40LkuIikKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiAi0JLQutC70Y7Rh9C4IFZQTiDQvtC00L3QuNC8INC90LDQ'
    'ttCw0YLQuNC10LwuINCR0YPQtNC10YIg0LjRgdC/0L7Qu9GM0LfQvtCy0LDQvSDQv9C+0YHQu9C10LTQvdC40Lkg0LLRi9Cx'
    '0YDQsNC90L3Ri9C5INC/0YDQvtGE0LjQu9GMLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFw'
    'TW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4'
    'ZWxTaXplOiAxMwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8g'
    'ItCS0YvQutC70Y7Rh9C40YLRjCBWUE4iIDogItCS0LrQu9GO0YfQuNGC0YwgVlBOIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcHJpbWFyeTogIUJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBkYW5nZXI6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3Rh'
    'dGUuY29ubmVjdGluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC50'
    'b2dnbGVWcG4oKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgeyBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAxOyBjb2xvcjogcm9vdC5ib3JkZXIgfQoKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBHcmlkTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zOiAyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtblNwYWNpbmc6IDI0CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHJvd1NwYWNpbmc6IDE0CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsg'
    'dGV4dDogItCf0YDQvtGE0LjQu9GMIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJp'
    'bmcocm9vdC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3RhdGUubGFzdF9wcm9maWxlIHx8ICLigJQiKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJJUHY2IjsgY29s'
    'b3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5pcHY2X21vZGUgfHwg'
    'InVua25vd24iKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IHRleHQ6ICJLaWxsIHN3aXRjaCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDog'
    'Qm9vbGVhbihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/ICLQkNC60YLQuNCy0LXQvSIgOiAi0JLRi9C60LvRjtGH0LXQvSIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUua2lsbF9z'
    'd2l0Y2gpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQktC10YDRgdC40Y8gbWFuYWdlciI7'
    'IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUubWFuYWdlciB8'
    'fCAi4oCUIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0SGVp'
    'Z2h0OiA5MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDE0CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Ym9yZGVyLndpZHRoOiAxCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci5jb2xvcjogcm9vdC5i'
    'b3JkZXIKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMTQKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA0NgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICByYWRpdXM6IDEzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4o'
    'cm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKSA/IHJvb3QuYWNjZW50U29mdCA6ICIjZWVmMmY3IgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIldEIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpID8gcm9vdC5hY2Nl'
    'bnQgOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250'
    'LnBpeGVsU2l6ZTogMTMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWln'
    'aHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'b2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJWUE4g0LTQu9GPIFdheWRyb2lkIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIUJvb2xlYW4ocm9vdC5zdGF0'
    'ZS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/ICLQntCx0YnQ'
    'uNC5IFZQTiDQstGL0LrQu9GO0YfQtdC9IOKAlCBXYXlkcm9pZCDRgtC+0LbQtSDRgNCw0LHQvtGC0LDQtdGCINCx0LXQtyBW'
    'UE4uIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiAoQm9vbGVhbihyb290'
    'LnN0YXRlLndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgPyAi0KLRgNCw0YTQuNC6IFdheWRyb2lkINC40LTRkdGCINGH0LXRgNC10LcgRS1WUE4uIgogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogIldheWRyb2lkINC40YHQv9C+'
    '0LvRjNC30YPQtdGCINC/0YDRj9C80L7QuSDQuNC90YLQtdGA0L3QtdGCINCyINC+0LHRhdC+0LQgRS1WUE4uIikKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBpZDogd2F5ZHJvaWRTd2l0Y2gKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBMYXlvdXQucHJlZmVycmVkV2lkdGg6IDQ4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZEhlaWdodDogMjYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBvcGFjaXR5OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSAmJiAhcm9vdC5idXN5ID8gMS4wIDogMC40'
    'NQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IGhlaWdodCAvIDIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0'
    'aXZlKSA/IHJvb3QuYWNjZW50IDogIiNjYmQ1ZTEiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAyMAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDIwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeTog'
    'MwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB4OiBCb29sZWFuKHJvb3Quc3RhdGUu'
    'd2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyB3YXlkcm9pZFN3aXRjaC53aWR0aCAtIHdpZHRoIC0gMyA6IDMKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQmVoYXZpb3Igb24geCB7IE51bWJlckFuaW1hdGlvbiB7IGR1cmF0aW9u'
    'OiAxMjAgfSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIE1vdXNlQXJlYSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGVuYWJsZWQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpICYmICFyb290LmJ1c3kKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY3Vyc29yU2hhcGU6IGVuYWJsZWQgPyBRdC5Qb2ludGlu'
    'Z0hhbmRDdXJzb3IgOiBRdC5BcnJvd0N1cnNvcgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFjdGlvbjogIndheWRyb2lkX3Zwbl9zZXQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgdGFyZ2V0OiBCb29sZWFuKHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyAi'
    'b2ZmIiA6ICJvbiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSkKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICB9CgoKICAgICAgICAgICAgICAgICAgICAvLyBWUE4gcHJvZmlsZXMKICAgICAgICAgICAgICAgICAgICBJdGVtIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNAoKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDc4CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJl'
    'bnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBS'
    'ZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDQyCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICByYWRpdXM6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5h'
    'Y2NlbnRTb2Z0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAiUFJGIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGNvbG9yOiByb290LmFjY2VudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQucGl4ZWxTaXplOiAxMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQu'
    'd2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlv'
    'dXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4'
    'dDogIlZQTi3Qv9GA0L7RhNC40LvQuCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xv'
    'cjogcm9vdC50ZXh0TWFpbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxT'
    'aXplOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJv'
    'bGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJp'
    'bmcocm9vdC5zdGF0ZS5jb25maWdfZGlyIHx8ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZv'
    'bnQucGl4ZWxTaXplOiAxMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWRlOiBUZXh0'
    'LkVsaWRlTWlkZGxlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcoKHJvb3Quc3RhdGUucHJvZmlsZXMgfHwg'
    'W10pLmxlbmd0aCkgKyAiINGI0YIuIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJv'
    'b3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0Vmll'
    'dyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA3CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LnN0YXRlLnByb2ZpbGVzIHx8IFtdCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgaWQ6IHByb2ZpbGVSb3cKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWln'
    'aHQ6IDY2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEyCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpID8g'
    'cm9vdC5hY2NlbnRTb2Z0IDogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3Jk'
    'ZXIud2lkdGg6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/IDEgOiAwCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIuY29sb3I6IHJvb3QuYWNjZW50CgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMubGVmdE1hcmdpbjogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLnJp'
    'Z2h0TWFyZ2luOiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEyCgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHJhZGl1czogNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9v'
    'bGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICA/IHJvb3QuZ29vZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgOiAoQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5sYXN0KSA/IHJvb3QuYWNjZW50IDogIiNjYmQ1ZTEiKQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBzcGFjaW5nOiAyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5n'
    'KHByb2ZpbGVSb3cubW9kZWxEYXRhLnN0ZW0gfHwgcHJvZmlsZVJvdy5tb2RlbERhdGEubmFtZSB8fCAiIikKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4dC5FbGlkZVJpZ2h0'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/ICLQkNC60YLQuNCy0L3Ri9C5INC/0YDQ'
    'vtGE0LjQu9GMIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogKEJv'
    'b2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEubGFzdCkgPyAi0J/QvtGB0LvQtdC00L3QuNC5INC40YHQv9C+0LvRjNC30L7Q'
    'stCw0L3QvdGL0LkiIDogU3RyaW5nKHByb2ZpbGVSb3cubW9kZWxEYXRhLm5hbWUgfHwgIiIpKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEu'
    'YWN0aXZlKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpID8g'
    'ItCQ0LrRgtC40LLQtdC9IiA6ICLQn9C+0LTQutC70Y7Rh9C40YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcHJpbWFyeTogIUJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFC'
    'b29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZykgJiYgIUJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGlvbjogInByb2ZpbGVfYWN0'
    'aXZhdGUiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFyZ2V0OiBTdHJp'
    'bmcocHJvZmlsZVJvdy5tb2RlbERhdGEubmFtZSB8fCAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB2aXNpYmxlOiAocm9vdC5zdGF0ZS5wcm9maWxlcyB8fCBbXSkubGVuZ3RoID09PSAwCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0JIg0L/QsNC/0LrQtSBWUE4gY29uZmlncyDQv9C+0LrQsCDQvdC10YIg'
    '0L/RgNC+0YTQuNC70LXQuSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRl'
    'eHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAvLyBBcHBsaWNhdGlvbnMKICAgICAgICAgICAgICAgICAgICBJ'
    'dGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNAoKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDgyCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxs'
    'OiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBDLlRleHRGaWVsZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogbWFudWFsQXBw'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6ICLQmNC80Y8g0L/RgNC+0YbQtdGB0YHQ'
    'sCwgL9C/0L7Qu9C90YvQuS/Qv9GD0YLRjCDQuNC70LggL9C/0LDQv9C60LAvIgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYmFja2dyb3VuZDogUmVjdGFuZ2xlIHsgcmFkaXVzOiAxMDsgY29sb3I6ICIjZjhmYWZjIjsgYm9yZGVyLmNvbG9yOiBy'
    'b290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjY2VwdGVkOiBpZiAodGV4'
    'dC50cmltKCkubGVuZ3RoKSByb290LmFjdGlvbih7YWN0aW9uOiAiYXBwX2FkZCIsIHRhcmdldDogdGV4dC50cmltKCl9KQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQlNC+0LHQsNCy'
    '0LjRgtGMINCy0YDRg9GH0L3Rg9GOIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbWFyeTog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAm'
    'JiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpICYmIG1hbnVhbEFwcC50ZXh0LnRyaW0oKS5sZW5ndGggPiAwCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICByb290LmFjdGlvbih7YWN0aW9uOiAiYXBwX2FkZCIsIHRhcmdldDogbWFudWFsQXBw'
    'LnRleHQudHJpbSgpfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYW51YWxBcHAuY2xl'
    'YXIoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0'
    'ZXh0OiAi0KPQttC1INC40YHQutC70Y7Rh9C10L3RiyI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTog'
    'MTU7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQ7IExheW91dC5maWxsV2lkdGg6IHRydWUgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmcoKHJvb3Quc3RhdGUuYXBwbGljYXRpb25zIHx8IFtdKS5sZW5n'
    'dGgpOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAxNDUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2lu'
    'czogOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHNwYWNpbmc6IDUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IHJv'
    'b3Quc3RhdGUuYXBwbGljYXRpb25zIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRl'
    'OiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkg'
    'dmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IExpc3RWaWV3LnZp'
    'ZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogOQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgY29sb3I6ICIjZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubGVmdE1hcmdpbjogMTIKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiA4CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0'
    'cmluZyhtb2RlbERhdGEpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGUgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCj0LTQsNC70LjRgtGMIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBkYW5nZXI6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3Rp'
    'bmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rp'
    'b24oe2FjdGlvbjogImFwcF9yZW1vdmUiLCB0YXJnZXQ6IFN0cmluZyhtb2RlbERhdGEpfSkKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFy'
    'ZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiAocm9vdC5zdGF0ZS5hcHBsaWNh'
    'dGlvbnMgfHwgW10pLmxlbmd0aCA9PT0gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDog'
    'ItCf0L7QutCwINC90LXRgiDQv9GA0LjQu9C+0LbQtdC90LjQuS3QuNGB0LrQu9GO0YfQtdC90LjQuSIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiAi0JfQsNC/0YPRidC10L3RiyDRgdC10LnRh9Cw0YEiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhl'
    'bFNpemU6IDE1OyBmb250LndlaWdodDogRm9udC5Cb2xkOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntCx0L3QvtCy0LjRgtGMINGB0L/QuNGB0L7QuiI7'
    'IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKTsgb25DbGlja2Vk'
    'OiByb290LnJlZnJlc2hSdW5uaW5nKCkgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogYXBwU2VhcmNo'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyVGV4dDogItCd0LDQudGC0Lgg0LfQsNC/0YPRidC10L3QvdC+0LUg0L/RgNC4'
    '0LvQvtC20LXQvdC40LUg0L/QviDQuNC80LXQvdC4INC40LvQuCDQv9GD0YLQuOKApiIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBzZWxlY3RCeU1vdXNlOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3Vu'
    'ZDogUmVjdGFuZ2xlIHsgcmFkaXVzOiAxMDsgY29sb3I6IHJvb3Quc3VyZmFjZTsgYm9yZGVyLmNvbG9yOiByb290LmJvcmRl'
    'ciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlz'
    'dFZpZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDgKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA2CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LmZpbHRlcmVkUnVubmluZygpCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgd2lkdGg6IExpc3RWaWV3LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGhlaWdodDogNjQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czog'
    'MTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBhbmNob3JzLm1hcmdpbnM6IDkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFj'
    'aW5nOiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA0MDsgaGVpZ2h0OiA0MDsgcmFkaXVzOiAx'
    'MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihtb2RlbERh'
    'dGEuZXhjbHVkZWQpID8gIiNkY2ZjZTciIDogcm9vdC5hY2NlbnRTb2Z0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLm5hbWUgfHwgIj8iKS5zbGljZSgwLCAxKS50b1VwcGVyQ2Fz'
    'ZSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbiht'
    'b2RlbERhdGEuZXhjbHVkZWQpID8gcm9vdC5nb29kIDogcm9vdC5hY2NlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5nKG1vZGVs'
    'RGF0YS5uYW1lIHx8ICIiKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkOyBlbGlk'
    'ZTogVGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2RlbERhdGEuZXhlIHx8ICIiKTsgY29sb3I6'
    'IHJvb3QudGV4dE11dGVkOyBmb250LnBpeGVsU2l6ZTogMTE7IGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpc2li'
    'bGU6IE51bWJlcihtb2RlbERhdGEuY291bnQgfHwgMSkgPiAxCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHRleHQ6ICLDlyIgKyBTdHJpbmcobW9kZWxEYXRhLmNvdW50KQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1'
    'dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiBCb29sZWFuKG1v'
    'ZGVsRGF0YS5leGNsdWRlZCkgPyAi0KPQttC1INC40YHQutC70Y7Rh9C10L3QviIgOiAi0JjRgdC60LvRjtGH0LjRgtGMIgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiAhQm9vbGVhbihtb2RlbERh'
    'dGEuZXhjbHVkZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0'
    'b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKSAmJiAhQm9vbGVhbihtb2RlbERhdGEu'
    'ZXhjbHVkZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9v'
    'dC5hY3Rpb24oe2FjdGlvbjogImFwcF9hZGQiLCB0YXJnZXQ6IFN0cmluZyhtb2RlbERhdGEuZXhlIHx8IG1vZGVsRGF0YS5u'
    'YW1lIHx8ICIiKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gU2l0ZXMvSVAKICAg'
    'ICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFj'
    'aW5nOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogODIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1h'
    'cmdpbnM6IDE2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEwCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGlkOiBkaXJlY3RUYXJnZXQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxs'
    'V2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyVGV4dDogImV4'
    'YW1wbGUuY29tLCAyMDMuMC4xMTMuMTAg0LjQu9C4IDIwMy4wLjExMy4wLzI0IgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYmFja2dyb3VuZDogUmVjdGFuZ2xlIHsgcmFkaXVzOiAxMDsgY29sb3I6ICIjZjhmYWZjIjsgYm9yZGVyLmNvbG9yOiBy'
    'b290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjY2VwdGVkOiBpZiAodGV4'
    'dC50cmltKCkubGVuZ3RoKSByb290LmFjdGlvbih7YWN0aW9uOiAiZGlyZWN0X2FkZCIsIHRhcmdldDogdGV4dC50cmltKCl9'
    'KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQlNC+0LHQ'
    'sNCy0LjRgtGMINC40YHQutC70Y7Rh9C10L3QuNC1IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'cHJpbWFyeTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJv'
    'b3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpICYmIGRpcmVjdFRhcmdldC50ZXh0LnRyaW0oKS5s'
    'ZW5ndGggPiAwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmFjdGlvbih7YWN0aW9uOiAiZGlyZWN0X2FkZCIsIHRh'
    'cmdldDogZGlyZWN0VGFyZ2V0LnRleHQudHJpbSgpfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBkaXJlY3RUYXJnZXQuY2xlYXIoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHNwYWNpbmc6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Q29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFy'
    'ZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCU0L7QvNC10L3RiyI7IGNvbG9yOiBy'
    'b290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5Cb2xkOyBmb250LnBpeGVsU2l6ZTogMTUgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlzdFZpZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA1CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IHJvb3Quc3RhdGUuZG9tYWlucyB8fCBbXQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRh'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3Lndp'
    'ZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiA5CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50OyBhbmNob3JzLmxlZnRNYXJnaW46IDEwOyBhbmNob3JzLnJpZ2h0TWFy'
    'Z2luOiA3CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5nKG1vZGVsRGF0YSk7IGNvbG9yOiByb290LnRleHRNYWluOyBlbGlk'
    'ZTogVGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEZsYXRCdXR0b24geyBsYWJlbDogItCj0LTQsNC70LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9v'
    'dC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZyk7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlv'
    'bjogImRpcmVjdF9yZW1vdmUiLCB0YXJnZXQ6IFN0cmluZyhtb2RlbERhdGEpfSkgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNj'
    'cm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5tYXJnaW5zOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'IHRleHQ6ICJJUCDQuCDRgdC10YLQuCI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5Cb2xkOyBm'
    'b250LnBpeGVsU2l6ZTogMTUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlzdFZpZXcgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBzcGFjaW5nOiA1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'bW9kZWw6IHJvb3Quc3RhdGUubmV0d29ya3MgfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgcmVxdWlyZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHJhZGl1czogOQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZh'
    'ZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudDsgYW5jaG9y'
    'cy5sZWZ0TWFyZ2luOiAxMDsgYW5jaG9ycy5yaWdodE1hcmdpbjogNwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2Rl'
    'bERhdGEpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGUgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0KPQtNCw0LvQuNGC0Ywi'
    'OyBkYW5nZXI6IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0'
    'aW5nKTsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAiZGlyZWN0X3JlbW92ZSIsIHRhcmdldDogU3RyaW5nKG1v'
    'ZGVsRGF0YSl9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIFBvcnRzCiAgICAgICAgICAgICAgICAgICAg'
    'SXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwNQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMu'
    'ZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogOAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQlNC70Y8g0LvQvtC60LDQ'
    'u9GM0L3Ri9GFINGB0LXRgNCy0LXRgNC+0LI6INC+0YLQstC10YLRiyDQvdCwINCy0YXQvtC00Y/RidC40LUg0L/QvtC00LrQ'
    'u9GO0YfQtdC90LjRjyDQuiDRjdGC0LjQvCDQv9C+0YDRgtCw0Lwg0LjQtNGD0YIg0L3QsNC/0YDRj9C80YPRjiDRh9C10YDQ'
    'tdC3INGE0LjQt9C40YfQtdGB0LrRg9GOINGB0LXRgtGMLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1v'
    'ZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXpl'
    'OiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHBvcnRGaWVsZAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6ICIyNTU2NSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBpbnB1dE1ldGhvZEhpbnRzOiBRdC5JbWhEaWdpdHNPbmx5CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZDogUmVjdGFuZ2xlIHsgcmFkaXVzOiAxMDsgY29sb3I6ICIjZjhmYWZj'
    'IjsgYm9yZGVyLmNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJvQm94IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogcHJvdG9Cb3gKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBtb2RlbDogWyJUQ1AiLCAiVURQIiwgIkJPVEgiXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDExMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQlNC+0LHQsNCy0LjRgtGMIgogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZykg'
    'JiYgcG9ydEZpZWxkLnRleHQubGVuZ3RoID4gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCBwID0g'
    'TnVtYmVyKHBvcnRGaWVsZC50ZXh0KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBp'
    'ZiAocCA+PSAxICYmIHAgPD0gNjU1MzUgJiYgcCA9PT0gTWF0aC5mbG9vcihwKSkgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogInBvcnRfYWRkIiwgcG9ydDogcCwg'
    'cHJvdG86IHByb3RvQm94LmN1cnJlbnRUZXh0LnRvTG93ZXJDYXNlKCl9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgcG9ydEZpZWxkLmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxs'
    'V2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJn'
    'aW5zOiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDcKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6'
    'IHJvb3Quc3RhdGUuc2VydmVyX3BvcnRzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVn'
    'YXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVy'
    'dHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IExpc3RWaWV3'
    'LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNTQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xh'
    'eW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQ7'
    'IGFuY2hvcnMubGVmdE1hcmdpbjogMTI7IGFuY2hvcnMucmlnaHRNYXJnaW46IDgKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB3aWR0aDogNTQ7IGhlaWdodDogMzA7IHJhZGl1czogODsgY29sb3I6IHJvb3QuYWNjZW50U29mdAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgYW5jaG9ycy5jZW50ZXJJbjogcGFy'
    'ZW50OyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLnByb3RvIHx8ICIiKS50b1VwcGVyQ2FzZSgpOyBjb2xvcjogcm9vdC5hY2Nl'
    'bnQ7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQ7IGZvbnQucGl4ZWxTaXplOiAxMSB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLnBvcnQgfHwgIiIpOyBjb2xvcjog'
    'cm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6IDE2OyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0KPQtNCw0LvQuNGC0YwiOyBkYW5nZXI6IHRydWU7IGVuYWJsZWRC'
    'dXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJwb3J0X3JlbW92'
    'ZSIsIHBvcnQ6IE51bWJlcihtb2RlbERhdGEucG9ydCksIHByb3RvOiBTdHJpbmcobW9kZWxEYXRhLnByb3RvKX0pCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50OyB2aXNpYmxlOiAocm9vdC5zdGF0ZS5z'
    'ZXJ2ZXJfcG9ydHMgfHwgW10pLmxlbmd0aCA9PT0gMDsgdGV4dDogItCd0LXRgiDRgdC10YDQstC10YDQvdGL0YUg0L/QvtGA'
    '0YLQvtCyIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9'
    'CgogICAgICAgICAgICAgICAgICAgIC8vIERpYWdub3N0aWNzCiAgICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6'
    'IDI0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCi0LXQutGD0YnQtdC1INGB0L7RgdGC0L7Rj9C90LjQtSI7IGNvbG9yOiByb290'
    'LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTogMTg7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEdyaWRMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnM6IDIKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1uU3BhY2luZzogMjgKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgcm93U3BhY2luZzogMTMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRl'
    'eHQ6ICJWUE4iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LkxhYmVsIHsgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyAi0JLQutC70Y7Rh9GR0L0iIDogItCS0YvQutC7'
    '0Y7Rh9C10L0iOyBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyByb290Lmdvb2QgOiByb290LnRleHRNdXRl'
    'ZDsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsgdGV4dDogItCf0YDQvtGE0LjQu9GMIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLnByb2ZpbGUgfHwgcm9vdC5zdGF0'
    'ZS5sYXN0X3Byb2ZpbGUgfHwgIuKAlCIpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJv'
    'bGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIlRVTiI7IGNvbG9yOiBy'
    'b290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBCb29s'
    'ZWFuKHJvb3Quc3RhdGUudHVuKSA/ICJ4cmF5dHVuINC/0L7QtNC90Y/RgiIgOiAi0J3QtdGCIjsgY29sb3I6IHJvb3QudGV4'
    'dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5MYWJlbCB7IHRleHQ6ICJLaWxsIHN3aXRjaCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBCb29sZWFuKHJvb3Quc3RhdGUua2lsbF9zd2l0Y2gpID8gItCQ'
    '0LrRgtC40LLQtdC9IiA6ICLQktGL0LrQu9GO0YfQtdC9IjsgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5raWxsX3N3aXRj'
    'aCkgPyByb290Lmdvb2QgOiByb290LnRleHRNdXRlZDsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIklQdjYiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUu'
    'aXB2Nl9tb2RlIHx8ICJ1bmtub3duIik7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9s'
    'ZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRElSRUNUINC/0YDQuNC7'
    '0L7QttC10L3QuNGPIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLmRpcmVjdF9hcHBsaWNhdGlvbnMgfHwgMCk7IGNvbG9yOiBy'
    'b290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRElSRUNUINC00L7QvNC10L3RiyI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5kaXJl'
    'Y3RfZG9tYWlucyB8fCAwKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJESVJFQ1QgSVAv0YHQtdGC0LgiOyBj'
    'b2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4'
    'dDogU3RyaW5nKHJvb3Quc3RhdGUuZGlyZWN0X25ldHdvcmtzIHx8IDApOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53'
    'ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4'
    'dDogIk1hbmFnZXIiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUubWFuYWdlciB8fCAi4oCUIik7IGNvbG9yOiByb290LnRleHRN'
    'YWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogItCe0LrQvdC+INC9'
    '0LDRgdGC0YDQvtC10Log0YDQsNCx0L7RgtCw0LXRgiDQvtGC0LTQtdC70YzQvdC+INC+0YIgUGxhc21hLiBLREUg0LjRgdC/'
    '0L7Qu9GM0LfRg9C10YLRgdGPINGC0L7Qu9GM0LrQviDQtNC70Y8g0LzQsNC70LXQvdGM0LrQvtCz0L4g0LLQuNC00LbQtdGC'
    '0LAg0L3QsCDRgNCw0LHQvtGH0LXQvCDRgdGC0L7Qu9C1LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Y29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0'
    'LldvcmRXcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gRXhwZXJpbWVudGFsIElL'
    'RXYyIGlzIGRlbGliZXJhdGVseSBvcHQtaW47IG5vIGF1dG9tYXRpYyBhY3RpdmF0aW9uLgogICAgICAgICAgICAgICAgICAg'
    'IEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbFZpZXcgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGlkOiBzdGFyZml2ZVNjcm9sbAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFu'
    'Y2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyNAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRlbnRXaWR0aDogYXZhaWxhYmxlV2lkdGgKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3'
    'aWR0aDogc3RhcmZpdmVTY3JvbGwuYXZhaWxhYmxlV2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMTgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJTdGFyRml2'
    'ZSDCtyBJS0V2Mi9JUHNlYyI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTogMjA7IGZvbnQud2VpZ2h0'
    'OiBGb250LkJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQotC10YHRgtC+0LLRi9C5INCy0YvRhdC+0LQg0LIg0LjQvdGC0LXRgNC90LXR'
    'giDRh9C10YDQtdC3INC00L7QvNCw0YjQvdC40LkgU3RhckZpdmUg0LIg0KDQvtGB0YHQuNC4LiDQrdGB0YLQvtC90YHQutC4'
    '0Lkg0LLRi9GF0L7QtCDQv9C+0LrQsCDQvdC1INC/0L7QtNC60LvRjtGH0ZHQvS4iCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5'
    'b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0J/QvtC00LrQu9GO0YfQtdC90LjQtSDQuiBTdGFyRml2ZSI7'
    'IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgdGV4dDogcm9vdC5leHBlcmltZW50LmFjdGl2ZSA/ICLQn9C+0LTQutC70Y7Rh9C10L3QviDCtyDQstGL0YXQ'
    'vtC0INCg0L7RgdGB0LjRjyIgOiAocm9vdC5leHBlcmltZW50Lmd1YXJkID8gItCh0L7QtdC00LjQvdC10L3QuNC1INC/0L7R'
    'gtC10YDRj9C90L4gwrcg0LjQvdGC0LXRgNC90LXRgiDQt9Cw0LHQu9C+0LrQuNGA0L7QstCw0L0iIDogItCS0YvQutC70Y7R'
    'h9C10L3QviIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LmV4'
    'cGVyaW1lbnQuYWN0aXZlID8gcm9vdC5nb29kIDogKHJvb3QuZXhwZXJpbWVudC5ndWFyZCA/IHJvb3QuYmFkIDogcm9vdC50'
    'ZXh0TXV0ZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0'
    'LldvcmRXcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Td2l0'
    'Y2ggewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoZWNrZWQ6IEJvb2xlYW4ocm9vdC5l'
    'eHBlcmltZW50Lmd1YXJkKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWQ6ICFy'
    'b290LmJ1c3kgJiYgKEJvb2xlYW4ocm9vdC5leHBlcmltZW50Lmd1YXJkKSB8fCAoQm9vbGVhbihyb290LmV4cGVyaW1lbnQu'
    'Y29uZmlndXJlZCkgJiYgQm9vbGVhbihyb290LmV4cGVyaW1lbnQuYXZhaWxhYmxlKSAmJiAhQm9vbGVhbihyb290LnN0YXRl'
    'LmFjdGl2ZSkpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5h'
    'Y3Rpb24oe2FjdGlvbjogY2hlY2tlZCA/ICJleHBlcmltZW50YWxfb24iIDogImV4cGVyaW1lbnRhbF9vZmYifSkKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHRleHQ6ICLQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDQvtCx0YvRh9C90YvQuSBWUE4uINCSINGN0YLQ'
    'vtC8INGA0LXQttC40LzQtSBJUHY2LCBESVJFQ1Qt0LjRgdC60LvRjtGH0LXQvdC40Y8g0Lgg0LTQvtGB0YLRg9C/INC6INC7'
    '0L7QutCw0LvRjNC90L7QuSDRgdC10YLQuCDQsdC70L7QutC40YDRg9GO0YLRgdGPLiDQn9GA0Lgg0L7QsdGA0YvQstC1INC4'
    '0L3RgtC10YDQvdC10YIg0L7RgdGC0LDRkdGC0YHRjyDQt9Cw0LrRgNGL0YLRi9C8LCDQv9C+0LrQsCDRgtGLINC90LUg0LLR'
    'i9C60LvRjtGH0LjRiNGMINGA0LXQttC40LwuIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29s'
    'b3I6IHJvb3QudGV4dE11dGVkOyB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcDsgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFu'
    'Z2xlIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgTGF5b3V0LnByZWZlcnJlZEhlaWdodDogMTsgY29sb3I6IHJvb3QuYm9y'
    'ZGVyIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiAi0KHQvtCy0LzQtdGB0YLQuNC8'
    '0L7RgdGC0YwgU3RlYW1PUzogSVBzZWMg0YfQtdGA0LXQtyBUVU4iOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgd3JhcE1vZGU6'
    'IFRleHQuV29yZFdyYXAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Td2l0Y2ggewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNoZWNrZWQ6IFN0cmluZyhyb290LmV4cGVyaW1lbnQu'
    'aXBzZWNfYmFja2VuZCB8fCAia2VybmVsIikgPT09ICJ1c2Vyc3BhY2UiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgZW5hYmxlZDogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LmV4cGVyaW1lbnQuZ3VhcmQpICYm'
    'ICFCb29sZWFuKHJvb3QuZXhwZXJpbWVudC5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiBjaGVja2VkID8gImV4cGVyaW1lbnRhbF9iYWNrZW5kLXVz'
    'ZXJzcGFjZSIgOiAiZXhwZXJpbWVudGFsX2JhY2tlbmQta2VybmVsIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0J3QsCBTdGVh'
    'bU9TINCy0YvQsdC40YDQsNC10YLRgdGPINCw0LLRgtC+0LzQsNGC0LjRh9C10YHQutC4LiDQntGC0LTQtdC70YzQvdGL0Lkg'
    '0LTQstC40LbQvtC6INC+0LHRgNCw0LHQsNGC0YvQstCw0LXRgiBJUHNlYyDRh9C10YDQtdC3IFRVTiwg0YHQvtGF0YDQsNC9'
    '0Y/RjyDRgdC40YHRgtC10LzQvdGL0Lkg0LfQsNC/0YDQtdGCIGVzcDQuINCf0LXRgNC10LQg0L/QtdGA0LLRi9C8INC/0L7Q'
    'tNC60LvRjtGH0LXQvdC40LXQvCDQvdCw0LbQvNC4IMKr0J/QvtC00LPQvtGC0L7QstC40YLRjCBJS0V2MsK7LiDQodC40YHR'
    'gtC10LzQvdGL0LUg0LHQuNCx0LvQuNC+0YLQtdC60Lgg0L3QtSDQt9Cw0LzQtdC90Y/RjtGC0YHRjy4g0KDQtdC20LjQvCDQ'
    'vNC+0LbQtdGCINGA0LDQsdC+0YLQsNGC0Ywg0LzQtdC00LvQtdC90L3QtdC1INGA0LXQsNC70LjQt9Cw0YbQuNC4INCyINGP'
    '0LTRgNC1LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsg'
    'd3JhcE1vZGU6IFRleHQuV29yZFdyYXA7IGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IHJvb3QuZXhwZXJpbWVudC5hdmFpbGFibGUgPyAiSUtFdjIg0LPQ'
    'vtGC0L7QsiIgOiAi0J/QvtC00LPQvtGC0L7QstC40YLRjCBJS0V2MiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKSAm'
    'JiAhQm9vbGVhbihyb290LmV4cGVyaW1lbnQuYXZhaWxhYmxlKSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4'
    'cGVyaW1lbnRhbF9wcmVwYXJlIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IHJvb3QuZXhw'
    'ZXJpbWVudC5jb25maWd1cmVkID8gItCf0LXRgNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvRjCDRg9GB0YLQsNC9'
    '0L7QstC70LXQvSIgOiAi0J3Rg9C20LXQvSDQv9C10YDRgdC+0L3QsNC70YzQvdGL0Lkg0L/RgNC+0YTQuNC70Ywg0YPRgdGC'
    '0YDQvtC50YHRgtCy0LAiOyBjb2xvcjogcm9vdC5leHBlcmltZW50LmNvbmZpZ3VyZWQgPyByb290Lmdvb2QgOiByb290LnRl'
    'eHRNdXRlZDsgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBS'
    'b3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1'
    'ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgeyBpZDogc3RhcmZpdmVQcm9m'
    'aWxlOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6ICJ+L1Zwbi9TdGFyRml2ZS9wcm9maWxlLmpz'
    'b24iOyBzZWxlY3RCeU1vdXNlOiB0cnVlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRC'
    'dXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0JjQvNC/0L7RgNGC'
    '0LjRgNC+0LLQsNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRv'
    'bjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpICYmICFCb29sZWFuKHJvb3QuZXhwZXJp'
    'bWVudC5ndWFyZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3Qu'
    'YWN0aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfaW1wb3J0IiwgdGFyZ2V0OiBzdGFyZml2ZVByb2ZpbGUudGV4dC50cmlt'
    'KCkgfHwgIn4vVnBuL1N0YXJGaXZlL3Byb2ZpbGUuanNvbiJ9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJlY3RhbmdsZSB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDE7'
    'IGNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogItCS'
    '0YDQtdC80LXQvdC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCwIjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2Vp'
    'Z2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU3dpdGNoIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjaGVja2VkOiBCb29sZWFuKHJvb3QuZXhwZXJp'
    'bWVudC50ZWxlbWV0cnkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZDogIXJv'
    'b3QuYnVzeSAmJiBCb29sZWFuKHJvb3QuZXhwZXJpbWVudC5jb25maWd1cmVkKQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogY2hlY2tlZCA/ICJleHBlcmltZW50'
    'YWxfdGVsZW1ldHJ5LW9uIiA6ICJleHBlcmltZW50YWxfdGVsZW1ldHJ5LW9mZiJ9KQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogItCa'
    '0LDQttC00YPRjiDQvNC40L3Rg9GC0YMg0L/RgNC+0LLQtdGA0Y/RjtGC0YHRjyDQr9C90LTQtdC60YEsIE1haWwg0Lgg0KDQ'
    'vtGB0YLQtdC70LXQutC+0LwuINCe0YjQuNCx0LrQuCDQv9C+0LTQutC70Y7Rh9C10L3QuNGPINC4INGA0LXQt9GD0LvRjNGC'
    '0LDRgtGLINGC0LXRgdGC0LAg0L7RgtC/0YDQsNCy0LvRj9GO0YLRgdGPINC90LDQv9GA0Y/QvNGD0Y4g0L3QsCBTdGFyRml2'
    'ZSDQv9C+IEhUVFBTINGBINC/0LXRgNGB0L7QvdCw0LvRjNC90YvQvCDRgdC10YDRgtC40YTQuNC60LDRgtC+0LwsINC00LDQ'
    'ttC1INC/0YDQuCDQvdC10YDQsNCx0L7RgtCw0Y7RidC10LwgVlBOLiDQotC+0LvRjNC60L4g0YHQu9GD0LbQtdCx0L3Ri9C5'
    'INC60LDQvdCw0Lsg0L7QsdGF0L7QtNC40YIg0LHQu9C+0LrQuNGA0L7QstC60YMg0LjQvdGC0LXRgNC90LXRgtCwLiDQndC1'
    '0L7RgtC/0YDQsNCy0LvQtdC90L3Ri9C1INC+0YLRh9GR0YLRiyDRgdC+0YXRgNCw0L3Rj9GO0YLRgdGPINC90LAg0YPRgdGC'
    '0YDQvtC50YHRgtCy0LU7INC/0L7Qv9GL0YLQutC4INC/0L7QstGC0L7RgNGP0Y7RgtGB0Y8g0YEg0L/QsNGD0LfQsNC80Lgu'
    'INCf0LDRgNC+0LvQuCwg0LrQu9GO0YfQuCDQuCDRgdC+0LTQtdGA0LbQuNC80L7QtSDRgtGA0LDRhNC40LrQsCDQvdC1INC+'
    '0YLQv9GA0LDQstC70Y/RjtGC0YHRjy4g0KXRgNCw0L3QtdC90LjQtSDQvdCwINGB0LXRgNCy0LXRgNC1OiA3INC00L3QtdC5'
    'LiDQodC10YDQstC10YAg0LLQuNC00LjRgiBJUCDRgdC+0LXQtNC40L3QtdC90LjRjzsg0Y3RgtC+INC/0YHQtdCy0LTQvtC9'
    '0LjQvNC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCwLCDQsCDQvdC1INC/0L7Qu9C90LDRjyDQsNC90L7QvdC40LzQvdC+'
    '0YHRgtGMLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsg'
    'd3JhcE1vZGU6IFRleHQuV29yZFdyYXA7IGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQntGC0L/RgNCw0LLQuNGC0Ywg0LTQuNCw0LPQvdC+0YHRgtC4'
    '0LrRgyDQvdCw0L/RgNGP0LzRg9GOIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1'
    'dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpICYmIEJvb2xlYW4ocm9vdC5leHBl'
    'cmltZW50LmNvbmZpZ3VyZWQpICYmIEJvb2xlYW4ocm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4cGVyaW1lbnRhbF9z'
    'ZW5kLWRpYWdub3N0aWNzIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0JTQ'
    'vtGB0YLQsNCy0LrQsCDQvtGC0YfRkdGC0L7QsjogIiArICh7aWRsZToi0LXRidGRINC90LUg0LfQsNC/0YPRgdC60LDQu9Cw'
    '0YHRjCIscXVldWVkOiLQvtGC0YfRkdGCINCyINC+0YfQtdGA0LXQtNC4IixzZW5kaW5nOiLQvtGC0L/RgNCw0LLQu9GP0LXR'
    'gtGB0Y8iLHNlbnQ6ItC00L7RgdGC0LDQstC70LXQvSDQvdCwIFN0YXJGaXZlIixyZXRyeToi0L3QtSDQtNC+0YHRgtCw0LLQ'
    'u9C10L07INC/0L7QstGC0L7RgNGP0LXQvCDRgSDQv9Cw0YPQt9Cw0LzQuCJ9W1N0cmluZygocm9vdC5leHBlcmltZW50LmRl'
    'bGl2ZXJ5IHx8IHt9KS5zdGF0dXMgfHwgImlkbGUiKV0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgKyAiLiDQkiDQvtGH0LXRgNC10LTQuDogIiArIE51bWJlcigocm9vdC5leHBlcmltZW50LmRlbGl2ZXJ5IHx8IHt9'
    'KS5wZW5kaW5nIHx8IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAocm9vdC5leHBl'
    'cmltZW50LnRlbGVtZXRyeSA/ICIiIDogIi4g0J7RgtC/0YDQsNCy0LrQsCDQstGL0LrQu9GO0YfQtdC90LAiKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsgKChyb290LmV4cGVyaW1lbnQuZGVsaXZlcnkgfHwge30p'
    'LmVycm9yID8gIi4g0J/RgNC40YfQuNC90LA6ICIgKyBTdHJpbmcocm9vdC5leHBlcmltZW50LmRlbGl2ZXJ5LmVycm9yKSA6'
    'ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkOyB3cmFw'
    'TW9kZTogVGV4dC5Xb3JkV3JhcDsgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IHN0YXJmaXZlRG9tYWluOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBw'
    'bGFjZWhvbGRlclRleHQ6ICLQlNC+0LzQtdC9INC90LXRgNCw0LHQvtGC0LDRjtGJ0LXQs9C+INGB0LDQudGC0LAsINC90LDQ'
    'v9GA0LjQvNC10YAgeWFuZGV4LnJ1Ijsgc2VsZWN0QnlNb3VzZTogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBs'
    'YWJlbDogItCf0YDQvtCy0LXRgNC40YLRjCDQuCDQvtGC0L/RgNCw0LLQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNv'
    'bm5lY3RpbmcpICYmIEJvb2xlYW4ocm9vdC5leHBlcmltZW50LmFjdGl2ZSkgJiYgQm9vbGVhbihyb290LmV4cGVyaW1lbnQu'
    'dGVsZW1ldHJ5KSAmJiBzdGFyZml2ZURvbWFpbi50ZXh0LnRyaW0oKS5sZW5ndGggPiAwCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAiZXhwZXJpbWVudGFsX3Jl'
    'cG9ydCIsIHRhcmdldDogc3RhcmZpdmVEb21haW4udGV4dC50cmltKCl9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IExheW91dC5wcmVmZXJyZWRIZWln'
    'aHQ6IDE7IGNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiAi0KHRgtCw0LHQuNC70YzQvdC+0YHRgtGMINGA0L7RgdGB0LjQudGB0LrQvtCz0L4g0LzQvtGB0YLQsCI7IGNv'
    'bG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogItCT0LvQvtCx0LDQ'
    'u9GM0L3Ri9C5INGC0LXRgdGCINC30LDQudC80ZHRgiDQv9GA0LjQvNC10YDQvdC+IDTigJM4INC80LjQvdGD0YIg0Lgg0LTQ'
    'viAyMDAg0JzQuNCRINGC0YDQsNGE0LjQutCwLiDQmNC90YLQtdGA0L3QtdGCINC90LXRgdC60L7Qu9GM0LrQviDRgNCw0Lcg'
    '0L/RgNC10YDQstGR0YLRgdGPOiDQv9GA0L7QstC10YDRj9GO0YLRgdGPINC/0LXRgNC10L/QvtC00LrQu9GO0YfQtdC90LjR'
    'jywg0YTQsNC50LvRiyDQuCDQtNC+0LrQsNGH0LrQsCwg0L/QvtGC0LXRgNC4LCDQv9GA0L7RgdGC0L7QuSDQuCDQv9Cw0YDQ'
    'sNC70LvQtdC70YzQvdCw0Y8g0L3QsNCz0YDRg9C30LrQsC4gS2lsbCBzd2l0Y2gg0L7RgdGC0LDRkdGC0YHRjyDQstC60LvR'
    'jtGH0ZHQvdC90YvQvC4g0J/RgNC+0LLQtdGA0LrQuDogU3RhckZpdmUsINCv0L3QtNC10LrRgSwgTWFpbCwg0KDQvtGB0YLQ'
    'tdC70LXQutC+0LwuINCY0YLQvtCzINC+0YLQv9GA0LDQstC40YLRgdGPINC90LDQv9GA0Y/QvNGD0Y4g0L/QviBIVFRQUzsg'
    '0LXRgdC70Lgg0YHQtdGA0LLQtdGAINC90LXQtNC+0YHRgtGD0L/QtdC9LCDQvtGC0YfRkdGCINC+0YHRgtCw0L3QtdGC0YHR'
    'jyDQsiDQvtGH0LXRgNC10LTQuC4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9v'
    'dC50ZXh0TXV0ZWQ7IHdyYXBNb2RlOiBUZXh0LldvcmRXcmFwOyBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQk9C70L7QsdCw0LvRjNC90YvQuSDRgtC10YHRgiIKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFu'
    'KHJvb3Quc3RhdGUuY29ubmVjdGluZykgJiYgQm9vbGVhbihyb290LmV4cGVyaW1lbnQuYWN0aXZlKSAmJiBCb29sZWFuKHJv'
    'b3QuZXhwZXJpbWVudC50ZWxlbWV0cnkpICYmIFN0cmluZygocm9vdC5leHBlcmltZW50LnRlc3QgfHwge30pLnBoYXNlKSAh'
    'PT0gInJ1bm5pbmciCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290'
    'LmFjdGlvbih7YWN0aW9uOiAiZXhwZXJpbWVudGFsX2dsb2JhbC10ZXN0In0pCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCe0YHRgtCw0L3QvtCy0LjRgtGMINGC'
    '0LXRgdGCIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290'
    'LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKSAmJiBTdHJpbmcoKHJvb3QuZXhwZXJpbWVudC50ZXN0'
    'IHx8IHt9KS5waGFzZSkgPT09ICJydW5uaW5nIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4cGVyaW1lbnRhbF9jYW5jZWwtdGVzdCJ9KQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuUHJvZ3Jlc3NCYXIgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZnJvbTogMDsgdG86IDEwMDsgdmFsdWU6IE51bWJlcigocm9vdC5leHBlcmltZW50LnRlc3QgfHwge30pLnBy'
    'b2dyZXNzIHx8IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBTdHJpbmcoKHJv'
    'b3QuZXhwZXJpbWVudC50ZXN0IHx8IHt9KS5waGFzZSkgPT09ICJydW5uaW5nIgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKChyb290LmV4cGVyaW1lbnQudGVzdCB8fCB7fSkubWVzc2FnZSB8fCAi'
    '0KLQtdGB0YIg0LXRidGRINC90LUg0LfQsNC/0YPRgdC60LDQu9GB0Y8iKQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICsgKChyb290LmV4cGVyaW1lbnQudGVzdCB8fCB7fSkucGFzc2VkICE9PSB1bmRlZmluZWQgPyAi'
    'INCf0YDQvtCy0LXRgNC+0Log0YPRgdC/0LXRiNC90L46ICIgKyAocm9vdC5leHBlcmltZW50LnRlc3QgfHwge30pLnBhc3Nl'
    'ZCArICI7INGB0L4g0YHQsdC+0Y/QvNC4OiAiICsgKHJvb3QuZXhwZXJpbWVudC50ZXN0IHx8IHt9KS5mYWlsZWQgKyAiLiIg'
    'OiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsgd3Jh'
    'cE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogItCf0L7RgdC7'
    '0LXQtNC90LjQuSDQvtGC0YfRkdGCOiAiICsgU3RyaW5nKHJvb3QuZXhwZXJpbWVudC5sYXN0X3JlcG9ydCB8fCAi0LXRidGR'
    'INC90LUg0L7RgtC/0YDQsNCy0LvQtdC9Iik7IGNvbG9yOiByb290LnRleHRNdXRlZDsgd3JhcE1vZGU6IFRleHQuV29yZFdy'
    'YXA7IGZvbnQucGl4ZWxTaXplOiAxMiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcocm9vdC5leHBlcmltZW50Lmxhc3RfZXJyb3IgfHwgIiIpOyBj'
    'b2xvcjogcm9vdC5iYWQ7IHdyYXBNb2RlOiBUZXh0LldvcmRXcmFwIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0K'
)
RELEASES = pathlib.Path("/opt/vpn-manager/releases")
CURRENT = pathlib.Path("/opt/vpn-manager/current")
PREVIOUS = pathlib.Path("/opt/vpn-manager/previous")

MAX_PROFILE_BYTES = 5 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024

DNS_DISCOVERY_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DNS_SNAPSHOT_BEGIN = "# EVGENIUM-DNS-BEGIN "
DNS_SNAPSHOT_END = "# EVGENIUM-DNS-END "
SERVER_BYPASS_MARK = 0x45564E01
SERVER_BYPASS_RULE_PREF = 50
SERVER_BYPASS_TABLE = 51820
WAYDROID_IFACE = "waydroid0"
WAYDROID_BYPASS_MARK = 0x45564E02
WAYDROID_BYPASS_RULE_PREF = 51
WAYDROID_BYPASS_TABLE = 51821

XRAY_RELEASE_API = (
    "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v"
    + SAFE_XRAY_VERSION
)

SERVICE_TEXT = r"""[Unit]
Description=Evgenius VPN Manager - Xray core
Wants=network-online.target
After=network-online.target
ConditionPathExists=/run/vpn-manager/config.json

[Service]
Type=simple
User=vpn-xray
Group=vpn-xray
ExecStart=/opt/vpn-manager/bin/xray run -config /run/vpn-manager/config.json
Restart=on-failure
RestartSec=2

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/vpn-manager /run/vpn-manager
DeviceAllow=/dev/net/tun rw
UMask=0077

[Install]
WantedBy=multi-user.target
"""

DIAGNOSTIC_SERVICE_TEXT = r"""[Unit]
Description=Evgenium VPN non-invasive diagnostic monitor
After=vpn-xray.service
ConditionPathExists=/run/vpn-manager/config.json

[Service]
Type=simple
ExecStart=/usr/local/sbin/vpnctl internal-diagnostic-monitor
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/vpn-manager /run/vpn-manager
UMask=0077
"""

WRAPPER_TEXT = r"""#!/usr/bin/env bash
set -e
exec /usr/bin/sudo -n /usr/local/sbin/vpnctl "$@"
"""

GUI_WRAPPER_TEXT = r'''#!/usr/bin/env bash
set -e
GUI="$HOME/.local/share/evgenium-network/evgenium_gui.py"
if [[ ! -f "$GUI" ]]; then
  echo "Evgenium Network GUI is not installed. Run: vpn gui install" >&2
  exit 1
fi
exec /usr/bin/python3 "$GUI" "$@"
'''

class VPNError(RuntimeError):
    pass

def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def info(msg: str) -> None:
    print(color("==>", "1;36"), msg)

def ok(msg: str) -> None:
    print(color("✓", "1;32"), msg)

def warn(msg: str) -> None:
    print(color("!", "1;33"), msg, file=sys.stderr)

def fail(msg: str) -> NoReturn:
    raise VPNError(msg)

def run(args, *, check=True, capture=False, input_text=None, timeout=None, user=None):
    cmd = [str(x) for x in args]
    if user:
        cmd = ["/usr/bin/runuser", "-u", user, "--"] + cmd
    default_timeout = timeout is None
    if default_timeout:
        timeout = 60
    try:
        return subprocess.run(
            cmd, check=check, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            input=input_text, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        if not default_timeout:
            raise
        fail(f"Команда {pathlib.Path(str(args[0])).name} не завершилась за {timeout} с. "
             "Операция прервана; повтори команду или проверь vpn status.")

def ensure_root() -> None:
    if os.geteuid() != 0:
        fail("vpnctl должен запускаться через команду vpn.")

def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS.read_text())
    except Exception as exc:
        fail(f"Не могу прочитать {SETTINGS}: {exc}")
    # 0.2.5 adds an application-level DIRECT list. Migrate existing 0.2.x
    # installations before validating the expanded settings schema: the
    # transactional updater execs this new vpnctl against the old settings.
    if "direct_apps" not in data and data.get("owner_home"):
        data["direct_apps"] = str(
            pathlib.Path(str(data["owner_home"])) / "Vpn" / "DIRECT apps.txt"
        )
        save_settings(data)

    # 0.2.13 adds a persistent Waydroid VPN preference.  True preserves
    # the historical behavior: Waydroid follows the main VPN while it is active.
    if "waydroid_vpn_enabled" not in data:
        data["waydroid_vpn_enabled"] = True
        save_settings(data)

    required = (
        "owner_user", "owner_home", "config_dir", "direct_sites",
        "direct_networks", "direct_apps", "xray_uid", "xray_gid",
        "waydroid_vpn_enabled",
    )
    for key in required:
        if key not in data:
            fail(f"settings.json не содержит {key}")
    return data

def save_settings(data: dict) -> None:
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SETTINGS)

def load_state() -> dict:
    if not STATE.exists():
        return {"active": None}
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"active": None}

def save_state(data: dict) -> None:
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)

def ensure_runtime(settings: dict) -> None:
    RUNTIME_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(RUNTIME_DIR, 0, int(settings["xray_gid"]))
    os.chmod(RUNTIME_DIR, 0o750)

def http_get(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        fail("Разрешены только HTTPS URL.")

    ctx = ssl.create_default_context()
    retryable_http = {408, 425, 429, 500, 502, 503, 504}
    attempts = 4
    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"EvgeniusVPNManager/{MANAGER_VERSION}",
                "Accept": "application/vnd.github+json, application/json, text/plain, */*",
            },
        )
        retryable = False
        try:
            with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
                out = bytearray()
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    out += chunk
                    if len(out) > max_bytes:
                        fail(f"Загрузка превысила лимит {max_bytes} bytes.")
                return bytes(out)
        except urllib.error.HTTPError as exc:
            last_error = exc
            retryable = int(exc.code) in retryable_http
        except urllib.error.URLError as exc:
            # Certificate verification failures are not transient and must never
            # be worked around by retries or weaker TLS settings.
            if isinstance(getattr(exc, "reason", None), ssl.SSLCertVerificationError):
                fail(f"HTTPS certificate verification failed: {exc}")
            last_error = exc
            retryable = True
        except (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError) as exc:
            last_error = exc
            retryable = True
        except ssl.SSLCertVerificationError as exc:
            fail(f"HTTPS certificate verification failed: {exc}")
        except Exception as exc:
            fail(f"HTTPS download failed: {exc}")

        if not retryable or attempt >= attempts:
            fail(f"HTTPS download failed after {attempt} attempt(s): {last_error}")

        delay = min(8, 2 ** (attempt - 1))
        warn(
            f"Временная ошибка HTTPS ({last_error}); "
            f"повтор {attempt + 1}/{attempts} через {delay} с."
        )
        time.sleep(delay)

    fail(f"HTTPS download failed: {last_error}")


def list_config_paths(settings: dict) -> list[pathlib.Path]:
    d = pathlib.Path(settings["config_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return sorted(
        [
            p for p in d.iterdir()
            if p.is_file() and not p.is_symlink() and not p.name.startswith(".")
        ],
        key=lambda p: p.name.lower(),
    )

def choose_config(settings: dict, requested: str | None) -> pathlib.Path:
    paths = list_config_paths(settings)
    if not paths:
        fail(f"В {settings['config_dir']} нет конфигов.")

    if requested:
        for p in paths:
            if p.name == requested or p.stem == requested:
                return p
        fail(f"Конфиг '{requested}' не найден. Используй: vpn list")

    if not sys.stdin.isatty():
        fail("Не указан конфиг: vpn on <имя>")

    print("Доступные VPN-конфиги:")
    for i, p in enumerate(paths, 1):
        print(f"  {i}) {p.name}")
    while True:
        raw = input("> ").strip()
        try:
            n = int(raw)
            if 1 <= n <= len(paths):
                return paths[n - 1]
        except ValueError:
            pass
        print("Введи номер из списка.")

def q1(q: dict[str, list[str]], *names: str, default=""):
    for name in names:
        vals = q.get(name)
        if vals:
            return vals[0]
    return default

def truthy(v: str) -> bool:
    return str(v).lower() in {"1", "true", "yes", "on"}

def resolve_server(host: str) -> str:
    # Резолвим ДО поднятия TUN, чтобы адрес VPN-сервера не зависел
    # от DNS уже внутри VPN.
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        fail(f"Не могу разрешить адрес VPN-сервера {host}: {exc}")
    v4, v6 = [], []
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET:
            v4.append(sa[0])
        elif fam == socket.AF_INET6:
            v6.append(sa[0])
    if v4:
        return v4[0]
    if v6:
        return v6[0]
    fail(f"DNS не вернул IP для {host}")

def parse_xhttp_extra(raw: str):
    if not raw:
        return None
    try:
        obj = json.loads(urllib.parse.unquote(raw))
    except Exception as exc:
        fail(f"Некорректный XHTTP extra JSON: {exc}")
    if not isinstance(obj, dict):
        fail("XHTTP extra должен быть JSON-объектом.")
    return obj

def parse_vless_url(url: str, fallback_name: str) -> dict:
    try:
        u = urllib.parse.urlsplit(url.strip())
    except Exception as exc:
        fail(f"Некорректный VLESS URL: {exc}")
    if u.scheme.lower() != "vless":
        fail("Ожидался vless:// URL.")
    if not u.username or not u.hostname or u.port is None:
        fail("В VLESS URL отсутствует UUID/server/port.")

    q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    security = q1(q, "security", default="").lower()
    transport = q1(q, "type", "network", default="tcp").lower()
    if transport == "tcp":
        transport = "raw"

    server_host = u.hostname
    server_ip = resolve_server(server_host)

    settings = {
        "address": server_ip,
        "port": int(u.port),
        "id": urllib.parse.unquote(u.username),
        "encryption": q1(q, "encryption", default="none") or "none",
    }
    flow = q1(q, "flow")
    if flow:
        settings["flow"] = flow

    stream: dict = {
        "network": transport,
        "security": security if security in {"reality", "tls"} else "none",
    }

    sni = q1(q, "sni", "servername")
    fp = q1(q, "fp", "fingerprint", default="chrome") or "chrome"
    alpn = q1(q, "alpn")

    if security == "reality":
        pbk = q1(q, "pbk", "publicKey", "password")
        sid = q1(q, "sid", "shortId")
        spx = urllib.parse.unquote(q1(q, "spx", "spiderX", default=""))
        if not pbk:
            fail("REALITY link не содержит pbk/publicKey.")
        reality = {
            "serverName": sni,
            "fingerprint": fp,
            # Xray accepts publicKey here; newer builds also expose password as an alias.
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx,
        }
        pqv = q1(q, "pqv", "mldsa65Verify")
        if pqv:
            reality["mldsa65Verify"] = pqv
        stream["realitySettings"] = reality
    elif security == "tls":
        tls = {
            "serverName": sni or server_host,
            "fingerprint": fp,
            "allowInsecure": truthy(q1(q, "allowInsecure", default="false")),
        }
        if alpn:
            tls["alpn"] = [x for x in re.split(r"[,|]", alpn) if x]
        stream["tlsSettings"] = tls

    path = urllib.parse.unquote(q1(q, "path", default=""))
    host = q1(q, "host", default="")
    mode = q1(q, "mode", default="")
    extra_raw = q1(q, "extra", default="")

    if transport == "xhttp":
        xh = {}
        if path:
            xh["path"] = path
        if host:
            xh["host"] = host
        if mode:
            xh["mode"] = mode
        extra = parse_xhttp_extra(extra_raw)
        if extra is not None:
            xh["extra"] = extra
        stream["xhttpSettings"] = xh

    elif transport == "grpc":
        grpc = {}
        service = urllib.parse.unquote(q1(q, "serviceName", "service-name", default=""))
        authority = q1(q, "authority", default="")
        if service:
            grpc["serviceName"] = service
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc

    elif transport == "websocket" or transport == "ws":
        stream["network"] = "websocket"
        ws = {}
        if path:
            ws["path"] = path
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws

    elif transport == "httpupgrade":
        hu = {}
        if path:
            hu["path"] = path
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu

    elif transport == "raw":
        # Не добавляем лишних rawSettings: defaults надёжнее.
        pass
    else:
        fail(f"Этот manager пока не поддерживает VLESS transport '{transport}'.")

    return {
        "name": urllib.parse.unquote(u.fragment) if u.fragment else fallback_name,
        "server_host": server_host,
        "server_ip": server_ip,
        "outbound": {
            "tag": "proxy",
            "protocol": "vless",
            "settings": settings,
            "streamSettings": stream,
        },
    }

def maybe_decode_subscription(text: str) -> str:
    compact = "".join(text.split())
    if not compact:
        return text
    if compact.startswith("vless://") or compact.startswith("https://"):
        return text
    # Многие subscription endpoints возвращают base64 без заголовка.
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        pad = "=" * (-len(compact) % 4)
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                raw = decoder((compact + pad).encode())
                decoded = raw.decode("utf-8-sig")
                if "vless://" in decoded:
                    return decoded
            except Exception:
                pass
    return text

def parse_profile_bytes(raw: bytes, fallback_name: str) -> list[dict]:
    if len(raw) > MAX_PROFILE_BYTES:
        fail("Конфиг слишком большой.")
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        fail("Конфиг должен быть текстовым UTF-8.")
    if not text:
        fail("Пустой конфиг.")

    text = maybe_decode_subscription(text)
    lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    if len(lines) == 1 and lines[0].lower().startswith("https://"):
        info("Загружаю HTTPS subscription до поднятия TUN...")
        remote = http_get(lines[0], MAX_PROFILE_BYTES)
        return parse_profile_bytes(remote, fallback_name)

    vless = [line for line in lines if line.lower().startswith("vless://")]
    if not vless:
        fail(
            "В конфиге не найден vless:// link. "
            "В 0.2.0 поддерживаются VLESS share links и HTTPS subscriptions."
        )
    return [
        parse_vless_url(link, f"{fallback_name}-{i}")
        for i, link in enumerate(vless, 1)
    ]

def load_profile(path: pathlib.Path) -> list[dict]:
    if path.stat().st_size > MAX_PROFILE_BYTES:
        fail("Конфиг слишком большой.")
    return parse_profile_bytes(path.read_bytes(), path.stem)

def read_direct_sites(settings: dict) -> list[tuple[str, str]]:
    p = pathlib.Path(settings["direct_sites"])
    if not p.exists():
        return []
    out = []
    for raw in p.read_text(errors="strict").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        exact = s.startswith("=")
        if exact:
            s = s[1:].strip()
        if s.startswith("*."):
            s = s[2:]
        s = s.strip(".").lower()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", s) or ".." in s:
            fail(f"Некорректный DIRECT domain: {raw!r}")
        out.append(("full" if exact else "domain", s))
    return out

def read_direct_networks(settings: dict) -> list[ipaddress._BaseNetwork]:
    p = pathlib.Path(settings["direct_networks"])
    if not p.exists():
        return []
    out = []
    for raw in p.read_text().splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            out.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            fail(f"Некорректная DIRECT network: {raw!r}")
    return out


def _normalize_direct_app_target(target: str) -> str:
    value = target.strip()
    if not value or value.startswith("#"):
        fail("Пустое имя процесса.")
    if len(value) > 4096 or any(ord(ch) < 32 for ch in value):
        fail("Некорректное имя/путь процесса.")

    if "/" not in value:
        if value in {".", ".."}:
            fail("Некорректное имя процесса.")
        return value

    if not value.startswith("/"):
        fail("Путь процесса должен быть абсолютным.")
    is_directory = value.endswith("/")
    path = pathlib.PurePosixPath(value)
    if value == "/" or ".." in path.parts:
        fail("Слишком широкий или небезопасный путь процесса.")
    normalized = str(path)
    return normalized + "/" if is_directory else normalized


def read_direct_apps(settings: dict) -> list[str]:
    raw_path = settings.get("direct_apps")
    if not raw_path:
        return []
    p = pathlib.Path(str(raw_path))
    if not p.exists():
        return []
    out: list[str] = []
    for raw in p.read_text(errors="strict").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        normalized = _normalize_direct_app_target(value)
        if normalized not in out:
            out.append(normalized)
    return out


def _owner_ids(settings: dict) -> tuple[int, int]:
    try:
        pw = pwd.getpwnam(str(settings["owner_user"]))
    except KeyError:
        fail(f"Не найден пользователь {settings['owner_user']!r}.")
    return pw.pw_uid, pw.pw_gid


def _safe_direct_path(settings: dict, key: str) -> pathlib.Path:
    p = pathlib.Path(settings[key])
    if p.is_symlink():
        fail(f"Отказываюсь изменять symlink: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_direct_file(settings: dict, key: str, text: str) -> None:
    p = _safe_direct_path(settings, key)
    uid, gid = _owner_ids(settings)
    mode = 0o600
    if p.exists():
        st = p.stat()
        uid, gid = st.st_uid, st.st_gid
        mode = st.st_mode & 0o777 or 0o600
    fd, tmpname = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, mode)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, p)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def ensure_direct_apps_file(settings: dict) -> None:
    p = _safe_direct_path(settings, "direct_apps")
    if p.exists():
        return
    _write_direct_file(
        settings,
        "direct_apps",
        "# Xray process matches are case-sensitive. One process name, absolute path,\n"
        "# or directory path ending in / per line. Managed with: vpn app ...\n"
        "evgenium-waydroid-mapper\n",
    )


def _append_unique_app(settings: dict, target: str) -> bool:
    value = _normalize_direct_app_target(target)
    if value in read_direct_apps(settings):
        return False
    p = _safe_direct_path(settings, "direct_apps")
    old = p.read_text() if p.exists() else ""
    if old and not old.endswith("\n"):
        old += "\n"
    _write_direct_file(settings, "direct_apps", old + value + "\n")
    return True


def _remove_app_entry(settings: dict, target: str) -> bool:
    value = _normalize_direct_app_target(target)
    p = _safe_direct_path(settings, "direct_apps")
    if not p.exists():
        return False
    changed = False
    kept: list[str] = []
    for raw in p.read_text().splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            with contextlib.suppress(VPNError):
                if _normalize_direct_app_target(stripped) == value:
                    changed = True
                    continue
        kept.append(raw)
    if changed:
        _write_direct_file(settings, "direct_apps", "\n".join(kept) + ("\n" if kept else ""))
    return changed


def _normalize_domain_target(target: str) -> tuple[str, bool]:
    raw = target.strip()
    exact = raw.startswith("=")
    if exact:
        raw = raw[1:].strip()
    if not raw:
        fail("Пустой domain.")

    if "://" in raw:
        host = urllib.parse.urlsplit(raw).hostname
    else:
        # Разрешаем вставить example.com/path без схемы.
        host = urllib.parse.urlsplit("//" + raw).hostname
    if not host:
        fail(f"Не могу извлечь domain из {target!r}.")
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        fail(f"Некорректный domain {target!r}: {exc}")
    if len(host) > 253 or ".." in host:
        fail(f"Некорректный domain: {host!r}")
    labels = host.split(".")
    if len(labels) < 2:
        fail("Нужен обычный DNS-domain вроде example.com.")
    for label in labels:
        if not label or len(label) > 63 or not re.fullmatch(r"[A-Za-z0-9-]+", label):
            fail(f"Некорректный DNS label: {label!r}")
        if label.startswith("-") or label.endswith("-"):
            fail(f"Некорректный DNS label: {label!r}")
    return host, exact


def _classify_direct_target(target: str):
    raw = target.strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return "network", net.compressed
    except ValueError:
        pass
    domain, exact = _normalize_domain_target(raw)
    return "domain", ("full" if exact else "domain"), domain


def _clean_lines(text: str) -> list[str]:
    return text.splitlines()


def _append_unique_domain(settings: dict, domain: str, exact: bool = False) -> bool:
    p = _safe_direct_path(settings, "direct_sites")
    old = p.read_text() if p.exists() else ""
    existing = {(kind, d) for kind, d in read_direct_sites(settings)}
    kind = "full" if exact else "domain"
    if (kind, domain) in existing:
        return False
    line = ("=" if exact else "") + domain
    new = old
    if new and not new.endswith("\n"):
        new += "\n"
    new += line + "\n"
    _write_direct_file(settings, "direct_sites", new)
    return True


def _remove_domain_entry(settings: dict, domain: str) -> bool:
    p = _safe_direct_path(settings, "direct_sites")
    if not p.exists():
        return False
    old_lines = p.read_text().splitlines()
    new_lines = []
    changed = False
    for raw in old_lines:
        s = raw.strip()
        probe = s[1:].strip() if s.startswith("=") else s
        if probe.startswith("*."):
            probe = probe[2:]
        probe = probe.strip(".").lower()
        if probe == domain:
            changed = True
            continue
        new_lines.append(raw)
    if changed:
        _write_direct_file(settings, "direct_sites", "\n".join(new_lines) + ("\n" if new_lines else ""))
    return changed


def _append_unique_network(settings: dict, network: str) -> bool:
    canonical = ipaddress.ip_network(network, strict=False).compressed
    if any(n.compressed == canonical for n in read_direct_networks(settings)):
        return False
    p = _safe_direct_path(settings, "direct_networks")
    old = p.read_text() if p.exists() else ""
    new = old
    if new and not new.endswith("\n"):
        new += "\n"
    new += canonical + "\n"
    _write_direct_file(settings, "direct_networks", new)
    return True


def _parse_dns_blocks(text: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        if raw.startswith(DNS_SNAPSHOT_BEGIN):
            current = raw[len(DNS_SNAPSHOT_BEGIN):].strip().lower()
            blocks[current] = []
            continue
        if raw.startswith(DNS_SNAPSHOT_END):
            current = None
            continue
        if current is not None:
            s = raw.strip()
            if s and not s.startswith("#"):
                blocks[current].append(s)
    return blocks


def _replace_dns_block_text(text: str, domain: str, networks: list[str] | None) -> str:
    begin = re.escape(DNS_SNAPSHOT_BEGIN + domain)
    end = re.escape(DNS_SNAPSHOT_END + domain)
    pattern = re.compile(rf"(?ms)^{begin}\n.*?^{end}\n?")
    text = pattern.sub("", text)
    text = text.rstrip("\n")
    if networks is None:
        return text + ("\n" if text else "")
    block = [
        DNS_SNAPSHOT_BEGIN + domain,
        "# DNS snapshot: these IPs may change; use `vpn direct refresh`.",
        *networks,
        DNS_SNAPSHOT_END + domain,
    ]
    if text:
        text += "\n\n"
    return text + "\n".join(block) + "\n"


def _set_dns_snapshot(settings: dict, domain: str, networks: list[str] | None) -> bool:
    p = _safe_direct_path(settings, "direct_networks")
    old = p.read_text() if p.exists() else ""
    new = _replace_dns_block_text(old, domain, networks)
    if new == old:
        return False
    _write_direct_file(settings, "direct_networks", new)
    return True


def _remove_network_entry(settings: dict, network: str) -> bool:
    canonical = ipaddress.ip_network(network, strict=False).compressed
    p = _safe_direct_path(settings, "direct_networks")
    if not p.exists():
        return False
    old_lines = p.read_text().splitlines()
    new_lines = []
    changed = False
    for raw in old_lines:
        s = raw.strip()
        if s and not s.startswith("#"):
            try:
                if ipaddress.ip_network(s, strict=False).compressed == canonical:
                    changed = True
                    continue
            except ValueError:
                pass
        new_lines.append(raw)
    if changed:
        _write_direct_file(settings, "direct_networks", "\n".join(new_lines) + ("\n" if new_lines else ""))
    return changed


def _dns_encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        if not 1 <= len(b) <= 63:
            raise ValueError("bad DNS label")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _dns_decode_name(packet: bytes, offset: int, seen=None) -> tuple[str, int]:
    if seen is None:
        seen = set()
    labels = []
    original_next = None
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name outside packet")
        length = packet[offset]
        if length == 0:
            offset += 1
            if original_next is None:
                original_next = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if ptr in seen:
                raise ValueError("DNS compression loop")
            seen.add(ptr)
            if original_next is None:
                original_next = offset + 2
            offset = ptr
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label type")
        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels).lower(), int(original_next)


def _parse_dns_answer(packet: bytes, tid: int) -> tuple[set[str], set[str], bool]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if rid != tid:
        raise ValueError("DNS transaction mismatch")
    if flags & 0x000F:
        return set(), set(), bool(flags & 0x0200)
    off = 12
    for _ in range(qd):
        _name, off = _dns_decode_name(packet, off)
        off += 4
        if off > len(packet):
            raise ValueError("truncated DNS question")
    ips: set[str] = set()
    cnames: set[str] = set()
    for _ in range(an):
        _name, off = _dns_decode_name(packet, off)
        if off + 10 > len(packet):
            raise ValueError("truncated DNS RR")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[off:off + 10])
        off += 10
        rdata_off = off
        if off + rdlen > len(packet):
            raise ValueError("truncated DNS rdata")
        if rclass == 1 and rtype == 1 and rdlen == 4:
            ips.add(str(ipaddress.IPv4Address(packet[off:off + 4])))
        elif rclass == 1 and rtype == 28 and rdlen == 16:
            ips.add(str(ipaddress.IPv6Address(packet[off:off + 16])))
        elif rclass == 1 and rtype == 5:
            cname, _ = _dns_decode_name(packet, rdata_off)
            cnames.add(cname)
        off += rdlen
    return ips, cnames, bool(flags & 0x0200)


def _dns_query_tcp(resolver: str, name: str, qtype: int, tid: int, query: bytes, timeout: float) -> tuple[set[str], set[str]]:
    s = socket.create_connection((resolver, 53), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(struct.pack("!H", len(query)) + query)
        hdr = b""
        while len(hdr) < 2:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                raise OSError("DNS TCP closed")
            hdr += chunk
        length = struct.unpack("!H", hdr)[0]
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                raise OSError("DNS TCP closed")
            data += chunk
        ips, cnames, _ = _parse_dns_answer(data, tid)
        return ips, cnames
    finally:
        s.close()


def _dns_query(resolver: str, name: str, qtype: int, timeout: float = 1.5) -> tuple[set[str], set[str]]:
    tid = random.randrange(65536)
    query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _dns_encode_name(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (resolver, 53))
        data, _ = s.recvfrom(65535)
    finally:
        s.close()
    ips, cnames, truncated = _parse_dns_answer(data, tid)
    if truncated:
        return _dns_query_tcp(resolver, name, qtype, tid, query, timeout)
    return ips, cnames


def discover_dns_ips(domain: str, rounds: int = 2) -> list[str]:
    rounds = max(1, min(int(rounds), 5))
    ips: set[str] = set()
    names = {domain}

    # Системный resolver — полезен для локального/ISP/VPN-вида DNS.
    with contextlib.suppress(OSError):
        for fam, _sock, _proto, _canon, sa in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
            if fam in {socket.AF_INET, socket.AF_INET6}:
                ips.add(sa[0])

    # Несколько публичных resolver'ов + несколько раундов ловят часть rotating/CDN RRsets.
    # Это всё равно snapshot, а не математически полный список всех IP сайта.
    for _round in range(rounds):
        queue = list(names)
        queried = set()
        while queue and len(queried) < 12:
            name = queue.pop(0)
            if name in queried:
                continue
            queried.add(name)
            for resolver in DNS_DISCOVERY_RESOLVERS:
                for qtype in (1, 28):
                    try:
                        found, cnames = _dns_query(resolver, name, qtype)
                    except (OSError, ValueError):
                        continue
                    ips.update(found)
                    for cname in cnames:
                        if cname not in names and len(names) < 12:
                            names.add(cname)
                            queue.append(cname)

    if not ips:
        fail(f"DNS discovery не нашёл ни одного A/AAAA для {domain}.")
    return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version, int(ipaddress.ip_address(s))))


def _host_network(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return ipaddress.ip_network(f"{addr}/{32 if addr.version == 4 else 128}", strict=False).compressed


def _reload_direct_if_active(settings: dict) -> None:
    st = load_state()
    if st.get("active") and service_active():
        info("Применяю DIRECT-правила к активному VPN...")
        activate(settings, choose_config(settings, st["active"]))
    else:
        ok("Правило сохранено; применится при следующем vpn on.")


def cmd_direct_list(settings: dict) -> None:
    print("DIRECT domains:")
    sites = read_direct_sites(settings)
    if not sites:
        print("  (нет)")
    else:
        for kind, domain in sites:
            print(f"  {'=' if kind == 'full' else ''}{domain}")

    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    block_ips = {ip for values in blocks.values() for ip in values}
    manual = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s in block_ips:
            continue
        with contextlib.suppress(ValueError):
            manual.append(ipaddress.ip_network(s, strict=False).compressed)

    print("DIRECT networks:")
    if not manual:
        print("  (нет)")
    else:
        for n in sorted(set(manual)):
            print(f"  {n}")

    print("DNS snapshots:")
    if not blocks:
        print("  (нет)")
    else:
        for domain in sorted(blocks):
            print(f"  {domain}: {len(blocks[domain])} IP")
            for n in blocks[domain]:
                print(f"    {n}")


def cmd_direct_add(settings: dict, target: str) -> None:
    kind, *rest = _classify_direct_target(target)
    if kind == "network":
        changed = _append_unique_network(settings, rest[0])
        if changed:
            ok(f"Добавлено DIRECT network: {rest[0]}")
        else:
            ok(f"DIRECT network уже есть: {rest[0]}")
    else:
        match_kind, domain = rest
        changed = _append_unique_domain(settings, domain, exact=(match_kind == "full"))
        if changed:
            ok(f"Добавлен DIRECT domain: {'=' if match_kind == 'full' else ''}{domain}")
        else:
            ok(f"DIRECT domain уже есть: {'=' if match_kind == 'full' else ''}{domain}")
    if changed:
        _reload_direct_if_active(settings)


def cmd_direct_remove(settings: dict, target: str) -> None:
    kind, *rest = _classify_direct_target(target)
    changed = False
    if kind == "network":
        changed = _remove_network_entry(settings, rest[0])
        label = rest[0]
    else:
        _match_kind, domain = rest
        changed = _remove_domain_entry(settings, domain)
        changed = _set_dns_snapshot(settings, domain, None) or changed
        label = domain
    if changed:
        ok(f"Удалено из DIRECT: {label}")
        _reload_direct_if_active(settings)
    else:
        ok(f"В DIRECT ничего не найдено: {label}")


def _confirm_shared_ip_risk(domain: str, yes: bool) -> None:
    warn(
        "DNS-IP исключения являются snapshot. CDN может менять адреса, а один IP "
        "может обслуживать несколько сайтов — тогда DIRECT затронет весь трафик к этому IP."
    )
    if yes:
        return
    if not sys.stdin.isatty():
        fail("Для неинтерактивного запуска добавь --yes.")
    ans = input(f"Добавить найденные IP для {domain} в DIRECT? [y/N] ").strip().lower()
    if ans not in {"y", "yes", "д", "да"}:
        fail("Отменено пользователем.")


def cmd_direct_discover(settings: dict, target: str, rounds: int, yes: bool) -> None:
    domain, _exact = _normalize_domain_target(target)
    info(f"Ищу A/AAAA для {domain}: system DNS + {len(DNS_DISCOVERY_RESOLVERS)} public resolvers...")
    ips = discover_dns_ips(domain, rounds)
    networks = [_host_network(ip) for ip in ips]
    print("Найдено:")
    for n in networks:
        print(f"  {n}")
    _confirm_shared_ip_risk(domain, yes)

    changed = _append_unique_domain(settings, domain, exact=False)
    changed = _set_dns_snapshot(settings, domain, networks) or changed
    ok(f"DNS snapshot сохранён: {domain} -> {len(networks)} IP")
    if changed:
        _reload_direct_if_active(settings)


def cmd_direct_refresh(settings: dict, target: str | None, rounds: int) -> None:
    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    if target:
        domain, _exact = _normalize_domain_target(target)
        domains = [domain]
    else:
        domains = sorted(blocks)
    if not domains:
        fail("Нет DNS snapshots. Сначала: vpn direct discover example.com")

    changed = False
    for domain in domains:
        info(f"Обновляю DNS snapshot: {domain}")
        ips = discover_dns_ips(domain, rounds)
        networks = [_host_network(ip) for ip in ips]
        changed = _append_unique_domain(settings, domain, exact=False) or changed
        changed = _set_dns_snapshot(settings, domain, networks) or changed
        ok(f"{domain}: {len(networks)} IP")
    if changed:
        _reload_direct_if_active(settings)
    else:
        ok("DNS snapshots не изменились.")


def cmd_app_list(settings: dict) -> None:
    print("DIRECT applications (case-sensitive Xray process rules):")
    apps = read_direct_apps(settings)
    if not apps:
        print("  (нет)")
        return
    for value in apps:
        print(f"  {value}")


def cmd_app_add(settings: dict, target: str) -> None:
    value = _normalize_direct_app_target(target)
    if _append_unique_app(settings, value):
        ok(f"Добавлено DIRECT-приложение: {value}")
        _reload_direct_if_active(settings)
    else:
        ok(f"DIRECT-приложение уже есть: {value}")


def cmd_app_remove(settings: dict, target: str) -> None:
    value = _normalize_direct_app_target(target)
    if _remove_app_entry(settings, value):
        ok(f"Удалено DIRECT-приложение: {value}")
        _reload_direct_if_active(settings)
    else:
        ok(f"DIRECT-приложение не найдено: {value}")



def cmd_waydroid_vpn_set(settings: dict, enabled: bool) -> None:
    old_enabled = bool(settings.get("waydroid_vpn_enabled", True))
    enabled = bool(enabled)
    if old_enabled == enabled:
        return

    settings["waydroid_vpn_enabled"] = enabled
    save_settings(settings)
    if not service_active():
        return

    try:
        install_guard(settings)
    except Exception:
        settings["waydroid_vpn_enabled"] = old_enabled
        save_settings(settings)
        with contextlib.suppress(Exception):
            install_guard(settings)
        raise


def _server_ports_path(settings: dict) -> pathlib.Path:
    p = pathlib.Path(settings["owner_home"]) / "Vpn" / "SERVER ports.txt"
    if p.is_symlink():
        fail(f"Отказываюсь изменять symlink: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _parse_server_port_entry(raw: str) -> tuple[str, int] | None:
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) != 2:
        fail(f"Некорректная SERVER port запись: {raw!r}; ожидается `tcp 25565`.")
    proto = parts[0].lower()
    if proto not in {"tcp", "udp"}:
        fail(f"Некорректный протокол SERVER port: {proto!r}.")
    try:
        port = int(parts[1])
    except ValueError:
        fail(f"Некорректный SERVER port: {parts[1]!r}.")
    if not 1 <= port <= 65535:
        fail(f"SERVER port вне диапазона 1..65535: {port}.")
    return proto, port


def read_server_ports(settings: dict) -> set[tuple[str, int]]:
    p = _server_ports_path(settings)
    if not p.exists():
        return set()
    entries: set[tuple[str, int]] = set()
    for raw in p.read_text(errors="strict").splitlines():
        parsed = _parse_server_port_entry(raw)
        if parsed is not None:
            entries.add(parsed)
    return entries


def _write_server_ports(settings: dict, entries: set[tuple[str, int]]) -> None:
    p = _server_ports_path(settings)
    uid, gid = _owner_ids(settings)
    text = "".join(
        f"{proto} {port}\n"
        for proto, port in sorted(entries, key=lambda x: (x[0], x[1]))
    )
    fd, tmpname = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, 0o600)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, p)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def _server_port_sets(settings: dict) -> tuple[set[int], set[int]]:
    entries = read_server_ports(settings)
    tcp = {port for proto, port in entries if proto == "tcp"}
    udp = {port for proto, port in entries if proto == "udp"}
    return tcp, udp


def _normalize_server_proto(proto: str) -> tuple[str, ...]:
    p = proto.lower()
    if p == "both":
        return ("tcp", "udp")
    if p in {"tcp", "udp"}:
        return (p,)
    fail(f"Некорректный протокол {proto!r}; используй tcp, udp или both.")


def _validate_server_port(port: int) -> int:
    if not 1 <= int(port) <= 65535:
        fail(f"Порт вне диапазона 1..65535: {port}.")
    return int(port)


def _apply_server_ports_if_active(settings: dict) -> None:
    if service_active() and nft_exists():
        info("Применяю SERVER-port bypass без выключения VPN...")
        install_guard(settings)
        ok("SERVER-port bypass применён.")
    else:
        ok("Правило сохранено; применится при следующем vpn on.")


def cmd_port_list(settings: dict) -> None:
    entries = sorted(read_server_ports(settings), key=lambda x: (x[0], x[1]))
    if not entries:
        print("(SERVER ports нет)")
        return
    print("SERVER ports (ответы на входящие соединения идут DIRECT):")
    for proto, port in entries:
        print(f"  {proto.upper():3} {port}")


def cmd_port_add(settings: dict, port: int, proto: str) -> None:
    port = _validate_server_port(port)
    entries = read_server_ports(settings)
    old = set(entries)
    for p in _normalize_server_proto(proto):
        entries.add((p, port))
    if entries == old:
        ok(f"SERVER port уже есть: {proto} {port}")
        return
    _write_server_ports(settings, entries)
    try:
        _apply_server_ports_if_active(settings)
    except Exception:
        _write_server_ports(settings, old)
        if service_active() and nft_exists():
            with contextlib.suppress(Exception):
                install_guard(settings)
        raise
    ok(f"Добавлен SERVER port: {proto} {port}")


def cmd_port_remove(settings: dict, port: int, proto: str) -> None:
    port = _validate_server_port(port)
    entries = read_server_ports(settings)
    old = set(entries)
    for p in _normalize_server_proto(proto):
        entries.discard((p, port))
    if entries == old:
        ok(f"SERVER port не найден: {proto} {port}")
        return
    _write_server_ports(settings, entries)
    try:
        _apply_server_ports_if_active(settings)
    except Exception:
        _write_server_ports(settings, old)
        if service_active() and nft_exists():
            with contextlib.suppress(Exception):
                install_guard(settings)
        raise
    ok(f"Удалён SERVER port: {proto} {port}")


def _nft_port_set(ports: set[int]) -> str:
    return "{ " + ", ".join(str(p) for p in sorted(ports)) + " }"


def render_guard_rules(uid: int, tcp_ports: set[int], udp_ports: set[int],
                       waydroid_direct: bool = False,
                       waydroid_iface: str = WAYDROID_IFACE,
                       dns_redirect: bool = False) -> str:
    server_mark = f"0x{SERVER_BYPASS_MARK:08x}"
    waydroid_mark = f"0x{WAYDROID_BYPASS_MARK:08x}"
    mark_lines = []
    allow_lines = []

    if tcp_ports:
        ports = _nft_port_set(tcp_ports)
        mark_lines.append(
            f"    ct state established tcp sport {ports} meta mark set {server_mark}"
        )
        allow_lines.append(
            f"    meta mark {server_mark} ct state established tcp sport {ports} accept"
        )
    if udp_ports:
        ports = _nft_port_set(udp_ports)
        mark_lines.append(
            f"    ct state established udp sport {ports} meta mark set {server_mark}"
        )
        allow_lines.append(
            f"    meta mark {server_mark} ct state established udp sport {ports} accept"
        )

    lines = [
        "",
        f"table inet {NFT_TABLE} {{",
    ]
    if dns_redirect:
        # Intercept even loopback stubs and link-local IPv6 router DNS. This
        # precedes LAN / DIRECT exceptions and does not modify resolv.conf.
        lines.extend([
            "  chain dns_output {",
            "    type nat hook output priority dstnat; policy accept;",
            f"    meta skuid != {uid} meta l4proto {{ tcp, udp }} th dport 53 redirect to :{DNS_PROXY_PORT}",
            "  }",
        ])
    if mark_lines:
        lines.extend([
            "",
            "  chain server_port_mark {",
            "    type route hook output priority mangle; policy accept;",
            *mark_lines,
            "  }",
        ])
    if waydroid_direct:
        lines.extend([
            "",
            "  chain waydroid_mark {",
            "    type filter hook prerouting priority mangle; policy accept;",
            f'    meta nfproto ipv4 iifname "{waydroid_iface}" meta mark set {waydroid_mark}',
            "  }",
        ])

    lines.extend([
        "",
        "  chain output {",
        "    type filter hook output priority filter; policy accept;",
        "",
        '    oifname "lo" accept',
        f"    meta skuid {uid} accept",
    ])
    if dns_redirect:
        lines.append(
            f'    oifname != "{TUN_NAME}" meta l4proto {{ tcp, udp }} th dport 53 reject with icmpx type admin-prohibited'
        )
    if allow_lines:
        lines.extend(["", *allow_lines])
    lines.extend([
        "",
        "    ip daddr 127.0.0.0/8 accept",
        "    ip daddr 10.0.0.0/8 accept",
        "    ip daddr 172.16.0.0/12 accept",
        "    ip daddr 192.168.0.0/16 accept",
        "    ip daddr 169.254.0.0/16 accept",
        "    ip daddr 224.0.0.0/4 accept",
        "    ip daddr 255.255.255.255/32 accept",
        "",
        "    ip6 daddr ::1/128 accept",
        "    ip6 daddr fc00::/7 accept",
        "    ip6 daddr fe80::/10 accept",
        "    ip6 daddr ff00::/8 accept",
        "",
        "    udp sport 68 udp dport 67 accept",
        "    udp sport 67 udp dport 68 accept",
        "",
        f'    oifname "{TUN_NAME}" accept',
        "",
        "    reject with icmpx type admin-prohibited",
        "  }",
        "",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        "",
        f'    iifname "{waydroid_iface}" ip daddr 10.0.0.0/8 accept',
        f'    iifname "{waydroid_iface}" ip daddr 172.16.0.0/12 accept',
        f'    iifname "{waydroid_iface}" ip daddr 192.168.0.0/16 accept',
        f'    iifname "{waydroid_iface}" ip daddr 169.254.0.0/16 accept',
    ])
    if waydroid_direct:
        lines.append(
            f'    iifname "{waydroid_iface}" meta mark {waydroid_mark} accept'
        )
    lines.extend([
        f'    iifname "{waydroid_iface}" oifname "{TUN_NAME}" accept',
        f'    iifname "{waydroid_iface}" reject with icmpx type admin-prohibited',
        "  }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _delete_server_bypass_policy_rules() -> None:
    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"
    # Remove both the broken 0.2.3 rule -> main and the fixed rule -> dedicated table.
    for famflag in ("-4", "-6"):
        for table in ("main", str(SERVER_BYPASS_TABLE)):
            for _ in range(8):
                cp = run(
                    [
                        "/usr/bin/ip", famflag, "rule", "del",
                        "pref", str(SERVER_BYPASS_RULE_PREF),
                        "fwmark", mark,
                        "lookup", table,
                    ],
                    check=False, capture=True
                )
                if cp.returncode != 0:
                    break
        run(
            [
                "/usr/bin/ip", famflag, "route", "flush",
                "table", str(SERVER_BYPASS_TABLE),
            ],
            check=False, capture=True
        )


def _physical_routes_from_main(family: int) -> tuple[str | None, list[dict]]:
    famflag = "-4" if family == 4 else "-6"
    cp = run(
        ["/usr/bin/ip", "-j", famflag, "route", "show", "table", "main"],
        check=False, capture=True
    )
    if cp.returncode != 0:
        return None, []
    try:
        routes = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return None, []
    if not isinstance(routes, list):
        return None, []

    defaults = [
        r for r in routes
        if isinstance(r, dict)
        and r.get("dst", "default") == "default"
        and r.get("dev")
        and r.get("dev") != TUN_NAME
        and r.get("type", "unicast") == "unicast"
    ]
    if not defaults:
        return None, []

    def metric(route: dict) -> int:
        try:
            return int(route.get("metric", 0))
        except (TypeError, ValueError):
            return 0

    chosen = min(defaults, key=metric)
    iface = str(chosen["dev"])
    selected = [
        r for r in routes
        if isinstance(r, dict)
        and r.get("dev") == iface
        and r.get("type", "unicast") == "unicast"
    ]
    # Install connected/link routes before the default route so its gateway is reachable.
    selected.sort(key=lambda r: (r.get("dst", "default") == "default", metric(r)))
    return iface, selected


def _populate_server_bypass_table(family: int) -> str | None:
    famflag = "-4" if family == 4 else "-6"
    iface, routes = _physical_routes_from_main(family)
    run(
        [
            "/usr/bin/ip", famflag, "route", "flush",
            "table", str(SERVER_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if not iface:
        return None

    for route in routes:
        dst = str(route.get("dst", "default"))
        cmd = [
            "/usr/bin/ip", famflag, "route", "replace",
            "table", str(SERVER_BYPASS_TABLE), dst,
        ]
        gateway = route.get("gateway")
        if gateway:
            cmd += ["via", str(gateway)]
        cmd += ["dev", iface]
        prefsrc = route.get("prefsrc")
        if prefsrc:
            cmd += ["src", str(prefsrc)]
        metric = route.get("metric")
        if metric is not None:
            cmd += ["metric", str(metric)]
        cp = run(cmd, check=False, capture=True)
        if cp.returncode != 0:
            fail(
                f"Не удалось скопировать физический маршрут в table {SERVER_BYPASS_TABLE}: "
                + (cp.stderr or "").strip()
            )
    return iface


def _verify_server_bypass_route(family: int, iface: str) -> None:
    famflag = "-4" if family == 4 else "-6"
    target = "1.1.1.1" if family == 4 else "2606:4700:4700::1111"
    cp = run(
        [
            "/usr/bin/ip", famflag, "route", "get", target,
            "mark", f"0x{SERVER_BYPASS_MARK:08x}",
        ],
        check=False, capture=True
    )
    out = (cp.stdout or "").strip()
    if cp.returncode != 0 or TUN_NAME in out or f"dev {iface}" not in out:
        fail(
            "SERVER-port policy route не обходит TUN. "
            f"Ожидался dev {iface}, получено: {out or (cp.stderr or '').strip()}"
        )


def _install_server_bypass_policy_rules(enabled: bool) -> None:
    _delete_server_bypass_policy_rules()
    if not enabled:
        return

    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"

    iface4 = _populate_server_bypass_table(4)
    if not iface4:
        fail("Не найден физический IPv4 default route для SERVER-port bypass.")
    v4 = run(
        [
            "/usr/bin/ip", "-4", "rule", "add",
            "pref", str(SERVER_BYPASS_RULE_PREF),
            "fwmark", mark,
            "lookup", str(SERVER_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if v4.returncode != 0:
        fail("Не удалось поставить IPv4 policy rule для SERVER ports:\n" + (v4.stderr or ""))
    _verify_server_bypass_route(4, iface4)

    # IPv6 is best effort: the host may have no physical IPv6 default route at all.
    iface6 = _populate_server_bypass_table(6)
    if iface6:
        v6 = run(
            [
                "/usr/bin/ip", "-6", "rule", "add",
                "pref", str(SERVER_BYPASS_RULE_PREF),
                "fwmark", mark,
                "lookup", str(SERVER_BYPASS_TABLE),
            ],
            check=False, capture=True
        )
        if v6.returncode == 0:
            _verify_server_bypass_route(6, iface6)
        else:
            warn("IPv6 SERVER-port policy rule не установлен: " + (v6.stderr or "").strip())


def _delete_waydroid_bypass_policy_rules() -> None:
    mark = f"0x{WAYDROID_BYPASS_MARK:08x}/0xffffffff"
    for _ in range(8):
        cp = run(
            [
                "/usr/bin/ip", "-4", "rule", "del",
                "pref", str(WAYDROID_BYPASS_RULE_PREF),
                "fwmark", mark,
                "lookup", str(WAYDROID_BYPASS_TABLE),
            ],
            check=False, capture=True
        )
        if cp.returncode != 0:
            break
    run(
        [
            "/usr/bin/ip", "-4", "route", "flush",
            "table", str(WAYDROID_BYPASS_TABLE),
        ],
        check=False, capture=True
    )


def _populate_waydroid_bypass_table() -> str | None:
    iface, routes = _physical_routes_from_main(4)
    run(
        [
            "/usr/bin/ip", "-4", "route", "flush",
            "table", str(WAYDROID_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if not iface:
        return None

    for route in routes:
        dst = str(route.get("dst", "default"))
        cmd = [
            "/usr/bin/ip", "-4", "route", "replace",
            "table", str(WAYDROID_BYPASS_TABLE), dst,
        ]
        gateway = route.get("gateway")
        if gateway:
            cmd += ["via", str(gateway)]
        cmd += ["dev", iface]
        prefsrc = route.get("prefsrc")
        if prefsrc:
            cmd += ["src", str(prefsrc)]
        metric = route.get("metric")
        if metric is not None:
            cmd += ["metric", str(metric)]
        cp = run(cmd, check=False, capture=True)
        if cp.returncode != 0:
            fail(
                f"Не удалось скопировать физический маршрут в table {WAYDROID_BYPASS_TABLE}: "
                + (cp.stderr or "").strip()
            )
    return iface


def _verify_waydroid_bypass_route(iface: str) -> None:
    cp = run(
        [
            "/usr/bin/ip", "-4", "route", "get", "1.1.1.1",
            "mark", f"0x{WAYDROID_BYPASS_MARK:08x}",
        ],
        check=False, capture=True
    )
    out = (cp.stdout or "").strip()
    if cp.returncode != 0 or TUN_NAME in out or f"dev {iface}" not in out:
        fail(
            "Waydroid DIRECT policy route не обходит TUN. "
            f"Ожидался dev {iface}, получено: {out or (cp.stderr or '').strip()}"
        )


def _install_waydroid_bypass_policy_rules(enabled: bool) -> None:
    _delete_waydroid_bypass_policy_rules()
    if not enabled:
        return

    iface = _populate_waydroid_bypass_table()
    if not iface:
        fail("Не найден физический IPv4 default route для Waydroid DIRECT.")

    cp = run(
        [
            "/usr/bin/ip", "-4", "rule", "add",
            "pref", str(WAYDROID_BYPASS_RULE_PREF),
            "fwmark", f"0x{WAYDROID_BYPASS_MARK:08x}/0xffffffff",
            "lookup", str(WAYDROID_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if cp.returncode != 0:
        fail("Не удалось поставить IPv4 policy rule для Waydroid DIRECT:\n" + (cp.stderr or ""))
    _verify_waydroid_bypass_route(iface)


def dns_routing_rules() -> list[dict]:
    return [
        {"type": "field", "inboundTag": ["dns-in-v4", "dns-in-v6"],
         "outboundTag": "dns-out", "ruleTag": "estonia-dns-always-vpn"},
        {"type": "field", "inboundTag": ["vpn-dns-upstream"],
         "outboundTag": "proxy", "ruleTag": "dns-upstream-always-vpn"},
    ]


def dns_config() -> dict:
    return {"tag": "vpn-dns-upstream", "queryStrategy": "UseIP",
            "enableParallelQuery": True,
            "servers": [{"address": address, "port": 53, "timeoutMs": 1500}
                        for address in ESTONIA_DNS_SERVERS]}


def dns_outbound() -> dict:
    return {"tag": "dns-out", "protocol": "dns",
            "settings": {"rewriteAddress": ESTONIA_DNS_IP, "rewritePort": 53,
                         "rules": [{"qType": "1,28", "action": "hijack"}, {"action": "direct"}]},
            "proxySettings": {"tag": "proxy"}}


def build_config(settings: dict, nodes: list[dict], selected: int = 0,
                 ipv6_enabled: bool = True) -> dict:
    if not nodes:
        fail("Нет VLESS nodes.")
    if not (0 <= selected < len(nodes)):
        selected = 0

    proxy = nodes[selected]["outbound"]

    apps = read_direct_apps(settings)
    domains = []
    for kind, domain in read_direct_sites(settings):
        domains.append(f"{kind}:{domain}")

    ips = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    ips += [n.compressed for n in read_direct_networks(settings)]

    rules = [{
        "type": "field",
        "inboundTag": ["direct-socks-in"],
        "outboundTag": "direct",
        "ruleTag": "local-direct-socks",
    }]
    rules.extend(dns_routing_rules())
    if apps:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "process": apps,
            "outboundTag": "direct",
            "ruleTag": "user-direct-applications",
        })
    if domains:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "domain": domains,
            "outboundTag": "direct",
            "ruleTag": "user-direct-domains",
        })
    if ips:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "ip": ips,
            "outboundTag": "direct",
            "ruleTag": "local-and-user-direct-networks",
        })
    rules.append({
        "type": "field",
        "inboundTag": ["tun-in"],
        "outboundTag": "proxy",
        "ruleTag": "default-vpn",
    })

    gateways = ["172.31.255.1/30"]
    auto_routes = ["0.0.0.0/0"]
    if ipv6_enabled:
        gateways.append("fd7a:115c:a1e0::1/126")
        auto_routes.append("::/0")

    return {
        "log": {
            "loglevel": "info",
        },
        "inbounds": [
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": TUN_NAME,
                    "mtu": 1500,
                    "gateway": gateways,
                    "autoSystemRoutingTable": auto_routes,
                    "autoOutboundsInterface": "auto",
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "metadataOnly": False,
                    "routeOnly": True,
                },
            },
            {
                "tag": "direct-socks-in",
                "listen": DIRECT_SOCKS_HOST,
                "port": DIRECT_SOCKS_PORT,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
            },
            *[{
                "tag": tag,
                "listen": address,
                "port": DNS_PROXY_PORT,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": ESTONIA_DNS_IP,
                    "port": 53,
                    "network": "tcp,udp",
                    "followRedirect": False,
                },
            } for tag, address in (("dns-in-v4", "127.0.0.1"),
                                   ("dns-in-v6", "::1"))],
        ],
        "dns": dns_config(),
        "outbounds": [
            proxy,
            dns_outbound(),
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "AsIs"},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }

def write_runtime_config(settings: dict, cfg: dict) -> None:
    ensure_runtime(settings)
    fd, tmpname = tempfile.mkstemp(
        prefix="config.", suffix=".json", dir=RUNTIME_DIR
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chown(tmpname, 0, int(settings["xray_gid"]))
        os.chmod(tmpname, 0o640)
        os.replace(tmpname, RUNTIME_CONFIG)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)

def test_config(path: pathlib.Path = RUNTIME_CONFIG,
                binary: pathlib.Path = XRAY) -> None:
    if not binary.exists():
        fail("Xray core не установлен. Выполни: vpn core-update")
    cp = run(
        [binary, "run", "-test", "-config", path],
        check=False, capture=True, timeout=20
    )
    if cp.returncode != 0:
        msg = ((cp.stderr or "") + "\n" + (cp.stdout or "")).strip()
        fail("Xray отклонил конфиг:\n" + msg[-5000:])

def nft_exists() -> bool:
    return run(
        ["/usr/bin/nft", "list", "table", "inet", NFT_TABLE],
        check=False, capture=True
    ).returncode == 0

def runtime_has_dns_proxy() -> bool:
    try:
        cfg = json.loads(RUNTIME_CONFIG.read_bytes())
        tags = {entry.get("tag") for entry in cfg.get("inbounds", [])}
        return {"dns-in-v4", "dns-in-v6"} <= tags
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def flush_dns_cache() -> None:
    resolver = shutil.which("resolvectl")
    if resolver:
        run([resolver, "flush-caches"], check=False, capture=True)


def validate_dns_guard(settings: dict) -> None:
    # Check kernel NAT support before touching a working core/guard. In
    # particular Arch can have a running kernel whose modules were replaced.
    rules = render_guard_rules(int(settings["xray_uid"]), set(), set(),
                               dns_redirect=True)
    if nft_exists():
        rules = f"delete table inet {NFT_TABLE}\n" + rules
    cp = run(["/usr/bin/nft", "--check", "-f", "-"], check=False,
             capture=True, input_text=rules)
    if cp.returncode:
        fail("Ядро не поддерживает перехват DNS (nftables NAT). "
             "Если ядро недавно обновлялось, перезагрузи ПК и повтори vpn update / vpn on. "
             "Действующее соединение не переключалось.\n" + (cp.stderr or ""))


def install_guard(settings: dict) -> None:
    uid = int(settings["xray_uid"])
    tcp_ports, udp_ports = _server_port_sets(settings)
    waydroid_direct = not bool(settings.get("waydroid_vpn_enabled", True))
    rules = render_guard_rules(
        uid, tcp_ports, udp_ports,
        waydroid_direct=waydroid_direct,
        waydroid_iface=WAYDROID_IFACE,
        dns_redirect=runtime_has_dns_proxy(),
    )

    script = rules
    if nft_exists():
        script = f"delete table inet {NFT_TABLE}\n" + rules

    cp = run(
        ["/usr/bin/nft", "-f", "-"],
        check=False, capture=True, input_text=script
    )
    if cp.returncode != 0:
        fail("Не удалось поставить kill switch:\n" + (cp.stderr or ""))

    _install_server_bypass_policy_rules(bool(tcp_ports or udp_ports))
    _install_waydroid_bypass_policy_rules(waydroid_direct)

def remove_guard() -> None:
    run(
        ["/usr/bin/nft", "delete", "table", "inet", NFT_TABLE],
        check=False, capture=True
    )
    _delete_server_bypass_policy_rules()
    _delete_waydroid_bypass_policy_rules()
    flush_dns_cache()

def service_active() -> bool:
    return run(
        ["/usr/bin/systemctl", "is-active", "--quiet", SERVICE],
        check=False
    ).returncode == 0

def wait_service(timeout=12) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service_active() and pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists():
            return True
        time.sleep(0.25)
    return False

def journal_tail(lines=100) -> str:
    cp = run(
        ["/usr/bin/journalctl", "-u", SERVICE, "-n", str(lines),
         "--no-pager", "-o", "cat"],
        check=False, capture=True
    )
    return cp.stdout or ""

def _health_check_v4_once(url: str, max_time: float = 12) -> tuple[bool, str]:
    try:
        cp = run(
            ["/usr/bin/curl", "-4", "--noproxy", "*", "--fail", "--silent", "--show-error",
             "--connect-timeout", str(min(5, max_time)), "--max-time", str(max_time), url],
            check=False, capture=True, timeout=max_time + 0.5
        )
    except subprocess.TimeoutExpired:
        return False, "HTTPS probe subprocess timed out"
    if cp.returncode != 0:
        return False, "IPv4 HTTPS через VPN не работает: " + (cp.stderr or "").strip()
    ip = (cp.stdout or "").strip()
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4:
            return False, f"Ожидался IPv4, получено: {ip!r}"
    except ValueError:
        return False, f"Health endpoint вернул неожиданный ответ: {ip[:120]!r}"
    return True, ip

def health_check_v4() -> tuple[bool, str]:
    # TUN presence is not transport readiness. Give the SAME core a bounded
    # startup window; never restart it or depend on one remote health provider.
    targets = ("https://api.ipify.org", "https://checkip.amazonaws.com")
    successes = set()
    last_ip = ""
    failures = []
    deadline = time.monotonic() + 45
    for _ in range(3):
        for url in targets:
            if time.monotonic() >= deadline:
                break
            remaining = min(12, max(0.25, deadline - time.monotonic()))
            good, detail = _health_check_v4_once(url, remaining)
            if good:
                successes.add(url)
                last_ip = detail
                if len(successes) == 2:
                    return True, last_ip
            else:
                failures.append(f"{urllib.parse.urlsplit(url).hostname}: {detail}")
        if time.monotonic() >= deadline:
            break
    return False, "IPv4 HTTPS readiness failed (two-provider quorum): " + "; ".join(failures[-4:])

def reuse_ipv4_mode(st: dict, path: pathlib.Path, old_config: bytes | None,
                   v4_config: dict) -> bool:
    # Reuse only the SAME actual configuration, not just a profile filename:
    # editing a profile/DIRECT rules must invalidate this decision.
    if st.get("active") != path.name or st.get("ipv6_mode") != "blocked":
        return False
    checked = st.get("ipv6_checked_at", st.get("since", 0))
    if not isinstance(checked, (int, float)) or not 0 <= time.time() - checked < 86400:
        return False
    try:
        saved = st.get("ipv4_config_sha256")
        if saved is not None and saved != config_fingerprint(v4_config):
            return False
        if old_config is not None:
            return json.loads(old_config) == v4_config
        return saved == config_fingerprint(v4_config)
    except (ValueError, TypeError):
        return False

def config_fingerprint(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def probe_ipv6_via_vpn(timeout: float = 4.0) -> tuple[bool, str]:
    """
    Проверяет не наличие IPv6 на локальной машине, а реальную возможность
    открыть TLS-соединение к публичному IPv6 ЧЕРЕЗ текущий Xray TUN/VLESS.

    Используется фиксированный IPv6 Cloudflare DNS, чтобы результат не зависел
    от локального DNS. Если VPS не имеет IPv6 egress, соединение не пройдёт.
    """
    raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(("2606:4700:4700::1111", 443, 0, 0))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname="cloudflare-dns.com") as tls:
            return True, tls.version() or "TLS OK"
    except Exception as exc:
        with contextlib.suppress(Exception):
            raw.close()
        return False, f"{type(exc).__name__}: {exc}"

def udp_dns_check(timeout: float = 5.0) -> tuple[bool, str]:
    tid = random.randrange(65536)
    qname = b""
    for part in "example.com".split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\0"
    packet = (
        struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", 1, 1)
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, ("1.1.1.1", 53))
        data, addr = s.recvfrom(4096)
        if len(data) < 12:
            return False, "слишком короткий UDP DNS reply"
        rid = struct.unpack("!H", data[:2])[0]
        if rid != tid:
            return False, "DNS transaction ID не совпал"
        return True, f"{addr[0]}:{addr[1]}, {len(data)} bytes"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        s.close()

def _diagnostic_udp_probe(resolver: str, timeout: float = 3.0) -> tuple[bool, str]:
    tid = random.randrange(65536)
    qname = b"\x07example\x03com\0"
    packet = (
        struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        + qname + struct.pack("!HH", 1, 1)
    )
    started = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (resolver, 53))
        data, _ = s.recvfrom(4096)
        if len(data) < 12 or struct.unpack("!H", data[:2])[0] != tid:
            return False, "invalid DNS response"
        return True, f"{(time.monotonic() - started) * 1000:.0f}ms"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        s.close()

def _diagnostic_tls_probe(address: str, server_name: str, timeout: float = 5.0) -> tuple[bool, str]:
    started = time.monotonic()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((address, 443))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            tls.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n".encode()
            )
            first = tls.recv(32)
            if not first.startswith(b"HTTP/"):
                return False, "unexpected HTTPS response"
        return True, f"{(time.monotonic() - started) * 1000:.0f}ms"
    except Exception as exc:
        with contextlib.suppress(Exception):
            raw.close()
        return False, f"{type(exc).__name__}: {exc}"

def _diagnostic_system_dns(name: str, timeout: float = 4.0) -> tuple[bool, str]:
    # getent has a bounded subprocess timeout; a stuck libc resolver must not
    # stall the monitor itself.
    try:
        cp = run(
            ["/usr/bin/getent", "ahostsv4", name], check=False,
            capture=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    if cp.returncode != 0 or not (cp.stdout or "").strip():
        return False, f"exit {cp.returncode}"
    return True, "ok"

def _diagnostic_cmd(args: list[str], timeout: float = 3.0) -> str:
    try:
        cp = run(args, check=False, capture=True, timeout=timeout)
        return ((cp.stdout or "") + (cp.stderr or "")).strip()[:4000]
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"

def _diagnostic_process_metrics() -> dict:
    pid_text = _diagnostic_cmd([
        "/usr/bin/systemctl", "show", SERVICE, "--property=MainPID", "--value",
    ])
    pid = int(pid_text) if pid_text.isdigit() else 0
    metrics: dict = {"pid": pid}
    if pid <= 0:
        return metrics
    with contextlib.suppress(Exception):
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        for key in ("VmRSS", "VmSize", "Threads"):
            match = re.search(rf"^{key}:\s*(.+)$", status, re.MULTILINE)
            if match:
                metrics[key] = match.group(1)
    with contextlib.suppress(Exception):
        metrics["fd_count"] = len(list(pathlib.Path(f"/proc/{pid}/fd").iterdir()))
    with contextlib.suppress(Exception):
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        metrics["cpu_ticks"] = int(stat[13]) + int(stat[14])
    return metrics

def _diagnostic_link_counters(interface: str) -> dict:
    out = {}
    stats_dir = pathlib.Path(f"/sys/class/net/{interface}/statistics")
    for key in (
        "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
        "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
    ):
        with contextlib.suppress(Exception):
            out[key] = int((stats_dir / key).read_text().strip())
    return out

def _diagnostic_kernel_tcp_counters() -> dict:
    wanted = {
        "Tcp": {"CurrEstab", "OutSegs", "RetransSegs", "InErrs", "OutRsts"},
        "TcpExt": {
            "TCPTimeouts", "TCPSynRetrans", "TCPAbortOnTimeout",
            "TCPFastRetrans", "TCPLostRetransmit",
        },
    }
    out = {}
    for path in (pathlib.Path("/proc/net/snmp"), pathlib.Path("/proc/net/netstat")):
        with contextlib.suppress(Exception):
            lines = path.read_text().splitlines()
            for index in range(len(lines) - 1):
                header = lines[index].split()
                values = lines[index + 1].split()
                if not header or not values or header[0] != values[0]:
                    continue
                section = header[0].rstrip(":")
                if section not in wanted:
                    continue
                for key, value in zip(header[1:], values[1:]):
                    if key in wanted[section]:
                        with contextlib.suppress(ValueError):
                            out[f"{section}.{key}"] = int(value)
    return out

def _diagnostic_tun_client_sockets() -> dict:
    raw = _diagnostic_cmd([
        "/usr/bin/ss", "-Htinp", "src", "172.31.255.1",
    ], timeout=4)
    result = {"connections": 0, "send_queue": 0, "stalled_endpoints": []}
    lines = raw.splitlines()
    for index in range(0, len(lines), 2):
        head = lines[index].split()
        if len(head) < 4 or not head[0].isdigit() or not head[1].isdigit():
            continue
        result["connections"] += 1
        send_queue = int(head[1])
        result["send_queue"] += send_queue
        detail = lines[index + 1] if index + 1 < len(lines) else ""
        retrans = re.search(r"\bretrans:(\d+)/(\d+)", detail)
        current_retrans = int(retrans.group(1)) if retrans else 0
        if send_queue >= 128 * 1024 or current_retrans >= 3:
            process = ""
            owner = re.search(r'users:\(\(\"([^\"]+)\"', lines[index])
            if owner:
                process = owner.group(1)[:80]
            result["stalled_endpoints"].append({
                "destination": head[3],
                "process": process,
                "send_queue": send_queue,
                "current_retrans": current_retrans,
            })
    result["stalled_endpoints"] = result["stalled_endpoints"][:20]
    return result

def _diagnostic_network_fingerprint() -> dict:
    iface = default_physical_iface()
    nameservers = []
    with contextlib.suppress(Exception):
        for line in pathlib.Path("/etc/resolv.conf").read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
    st = load_state()
    server_ip = str(st.get("server_ip") or "")
    return {
        "interface": iface,
        "default_route": _diagnostic_cmd([
            "/usr/bin/ip", "-4", "route", "show", "default", "table", "main",
        ]),
        "server_route": _diagnostic_cmd([
            "/usr/bin/ip", "-4", "route", "get", server_ip,
        ]) if server_ip else "unknown",
        "nameservers": nameservers,
    }

def _diagnostic_xray_errors() -> list[dict]:
    raw = _diagnostic_cmd([
        "/usr/bin/journalctl", "-u", SERVICE, "--since", "-30 seconds",
        "--no-pager", "-o", "cat", "-n", "500",
    ], timeout=5)
    patterns = (
        "failed", "timeout", "timed out", "reset", "broken pipe",
        "unexpected eof", "context canceled", "handshake", "invalid",
        "closed pipe", "no recent network activity",
    )
    ignored = (
        "unable to find local process", "unables to find local process",
        "not found in /proc/net", "no process found for inode",
    )
    counts: dict[str, int] = {}
    for line in raw.splitlines():
        low = line.lower()
        if not any(word in low for word in patterns):
            continue
        if any(word in low for word in ignored):
            continue
        # Keep the transport failure while removing connection IDs and
        # destination-specific endpoints. A single unavailable website must
        # not turn this into browsing-history collection.
        clean = re.sub(r"\[\d+\]", "[connection]", line)
        clean = re.sub(r"\b(?:tcp|udp):\S+", "endpoint", clean)
        clean = re.sub(r"\bvia\s+\S+", "via server", clean)
        clean = re.sub(r"https?://\S+", "https://endpoint", clean)
        clean = clean[-1200:]
        counts[clean] = counts.get(clean, 0) + 1
    return [
        {"count": count, "message": message}
        for message, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]

def _diagnostic_active_failures() -> list[dict]:
    """Return repeated failures for domains the user is actually using.

    Successful destinations are never retained. A domain is emitted only when
    Xray associates it with at least three transport-level failures in the
    rolling journal window, which filters an ordinary one-off unavailable site.
    """
    raw = _diagnostic_cmd([
        "/usr/bin/journalctl", "-u", SERVICE, "--since", "-45 seconds",
        "--no-pager", "-o", "cat", "-n", "1200",
    ], timeout=5)
    domains: dict[str, str] = {}
    failures: dict[str, list[str]] = {}
    failure_words = (
        "failed to process outbound", "failed to open", "timeout",
        "timed out", "connection reset", "broken pipe", "unexpected eof",
        "no recent network activity", "failed to transport",
    )
    for line in raw.splitlines():
        conn = re.search(r"\[(\d+)\]", line)
        if not conn:
            continue
        connection_id = conn.group(1)
        sniffed = re.search(r"sniffed domain:\s*([^\s]+)", line, re.IGNORECASE)
        if sniffed:
            domains[connection_id] = sniffed.group(1).lower().rstrip(".")[:253]
            continue
        low = line.lower()
        if not any(word in low for word in failure_words):
            continue
        domain = domains.get(connection_id)
        if not domain:
            continue
        clean = re.sub(r"\[\d+\]", "[connection]", line)
        clean = re.sub(r"\b(?:tcp|udp):\S+", "endpoint", clean)
        clean = re.sub(r"\bvia\s+\S+", "via server", clean)
        failures.setdefault(domain, []).append(clean[-700:])
    return [
        {"domain": domain, "count": len(messages), "last_error": messages[-1]}
        for domain, messages in sorted(failures.items())
        if len(messages) >= 3
    ][:20]

def _diagnostic_transport_sockets(server_ip: str) -> dict:
    if not server_ip:
        return {"connections": 0}
    raw = _diagnostic_cmd([
        "/usr/bin/ss", "-Htin", "dst", server_ip,
    ], timeout=4)
    totals = {
        "connections": 0, "send_queue": 0, "unacked": 0,
        "current_retrans": 0, "bytes_retrans": 0, "max_rto_ms": 0,
    }
    lines = raw.splitlines()
    for index in range(0, len(lines), 2):
        head = lines[index].split()
        if len(head) >= 2 and head[0].isdigit() and head[1].isdigit():
            totals["connections"] += 1
            totals["send_queue"] += int(head[1])
        detail = lines[index + 1] if index + 1 < len(lines) else ""
        for key, pattern in (
            ("unacked", r"\bunacked:(\d+)"),
            ("bytes_retrans", r"\bbytes_retrans:(\d+)"),
            ("max_rto_ms", r"\brto:(\d+)"),
        ):
            match = re.search(pattern, detail)
            if match:
                value = int(match.group(1))
                if key == "max_rto_ms":
                    totals[key] = max(totals[key], value)
                else:
                    totals[key] += value
        retrans = re.search(r"\bretrans:(\d+)/(\d+)", detail)
        if retrans:
            totals["current_retrans"] += int(retrans.group(1))
    return totals

def _diagnostic_snapshot(settings: dict, probes: dict, reasons: list[str]) -> dict:
    st = load_state()
    server_ip = str(st.get("server_ip") or "")
    return {
        "event": "degraded",
        "reasons": reasons,
        "profile": str(st.get("active") or ""),
        "probes": probes,
        "service_active": service_active(),
        "tun_exists": pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists(),
        "kill_switch": exp["guard"] or nft_exists(),
        "physical_interface": default_physical_iface(),
        "route_probe": _diagnostic_cmd(["/usr/bin/ip", "-4", "route", "get", "1.1.1.1"]),
        "route_server": _diagnostic_cmd(["/usr/bin/ip", "-4", "route", "get", server_ip]) if server_ip else "unknown",
        "ip_rules": _diagnostic_cmd(["/usr/bin/ip", "rule", "show"]),
        "socket_summary": _diagnostic_cmd(["/usr/bin/ss", "-s"]),
        "xhttp_transport_sockets": _diagnostic_transport_sockets(server_ip),
        "active_tun_sockets": _diagnostic_tun_client_sockets(),
        "kernel_tcp": _diagnostic_kernel_tcp_counters(),
        "xray_process": _diagnostic_process_metrics(),
        "tun_counters": _diagnostic_link_counters(TUN_NAME),
        "network": _diagnostic_network_fingerprint(),
        "xray_errors_30s": _diagnostic_xray_errors(),
    }

def _diagnostic_write(payload: dict) -> None:
    DIAGNOSTIC_LOG.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if DIAGNOSTIC_LOG.exists() and DIAGNOSTIC_LOG.stat().st_size > DIAGNOSTIC_LOG_SEGMENT_BYTES:
        previous = DIAGNOSTIC_LOG.with_suffix(".previous.jsonl")
        previous.unlink(missing_ok=True)
        os.replace(DIAGNOSTIC_LOG, previous)
    record = {"time": int(time.time()), **payload}
    with DIAGNOSTIC_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.chmod(DIAGNOSTIC_LOG, 0o600)

def _diagnostic_probe_round() -> tuple[dict, list[str]]:
    structural = {
        "service": service_active(),
        "tun": pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists(),
        "kill_switch": nft_exists(),
    }
    dns_targets = ("example.com", "github.com", "wikipedia.org")
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        for name in dns_targets:
            jobs[("dns", name)] = pool.submit(_diagnostic_system_dns, name)
        jobs[("tls", "cloudflare")] = pool.submit(
            _diagnostic_tls_probe, "1.1.1.1", "cloudflare-dns.com"
        )
        jobs[("tls", "google")] = pool.submit(
            _diagnostic_tls_probe, "8.8.8.8", "dns.google"
        )
        jobs[("udp", "cloudflare")] = pool.submit(_diagnostic_udp_probe, "1.1.1.1")
        jobs[("udp", "google")] = pool.submit(_diagnostic_udp_probe, "8.8.8.8")
        results = {key: future.result() for key, future in jobs.items()}
    dns = {name: results[("dns", name)] for name in dns_targets}
    tls = {name: results[("tls", name)] for name in ("cloudflare", "google")}
    udp = {name: results[("udp", name)] for name in ("cloudflare", "google")}
    st = load_state()
    transport = _diagnostic_transport_sockets(str(st.get("server_ip") or ""))
    tun_clients = _diagnostic_tun_client_sockets()
    active_failures = _diagnostic_active_failures()
    reasons = [name for name, good in structural.items() if not good]
    if sum(1 for good, _ in dns.values() if good) < 2:
        reasons.append("system_dns_quorum")
    if not any(good for good, _ in tls.values()):
        reasons.append("https_quorum")
    if not any(good for good, _ in udp.values()):
        reasons.append("udp_quorum")
    if (
        transport.get("current_retrans", 0) >= 3
        or transport.get("send_queue", 0) >= 512 * 1024
        or transport.get("max_rto_ms", 0) >= 5000
    ):
        reasons.append("xhttp_transport_stall")
    if active_failures:
        reasons.append("repeated_active_destination_failures")
    if tun_clients.get("stalled_endpoints"):
        reasons.append("active_tun_flow_stall")
    return {
        "structural": structural, "dns": dns, "tls": tls, "udp": udp,
        "xhttp_transport": transport,
        "active_tun_sockets": tun_clients,
        "active_destination_failures": active_failures,
    }, reasons

def diagnostic_service_active() -> bool:
    return run(
        ["/usr/bin/systemctl", "is-active", "--quiet", DIAGNOSTIC_SERVICE],
        check=False,
    ).returncode == 0

def stop_diagnostic() -> None:
    run(["/usr/bin/systemctl", "stop", DIAGNOSTIC_SERVICE], check=False, capture=True)

def cmd_diagnostic_mark(note_parts: list[str]) -> None:
    note = " ".join(note_parts).strip()
    if not note:
        fail('Добавьте описание, например: vpn diagnostic mark "Discord висит"')
    note = note.replace("\n", " ")[:500]
    _diagnostic_write({"event": "user_mark", "note": note})
    ok(f"Diagnostic mark saved: {note}")

def cmd_diagnostic_on(settings: dict, config: str | None) -> None:
    stop_diagnostic()
    profile_path = choose_config(settings, config)
    try:
        activate(settings, profile_path)
    except VPNError as exc:
        with contextlib.suppress(OSError, VPNError):
            _diagnostic_write({"event": "startup_failed", "profile": profile_path.name,
                               "error": str(exc)[:3000], "network": _diagnostic_network_fingerprint()})
        raise
    node = load_profile(profile_path)[0]
    stream = node.get("outbound", {}).get("streamSettings", {})
    xhttp = stream.get("xhttpSettings", {})
    DIAGNOSTIC_LOG.unlink(missing_ok=True)
    _diagnostic_write({
        "event": "started",
        "manager": MANAGER_VERSION,
        "xray": SAFE_XRAY_VERSION,
        "profile": str(load_state().get("active") or ""),
        "transport": stream.get("network"),
        "security": stream.get("security"),
        "xhttp_mode": xhttp.get("mode", "auto") if isinstance(xhttp, dict) else None,
        "network": _diagnostic_network_fingerprint(),
        "xray_process": _diagnostic_process_metrics(),
        "interval_seconds": DIAGNOSTIC_INTERVAL,
        "maximum_report_bytes": DIAGNOSTIC_LOG_SEGMENT_BYTES * 2,
        "policy": "quorum failures only; no automatic recovery",
    })
    cp = run(
        ["/usr/bin/systemctl", "start", DIAGNOSTIC_SERVICE],
        check=False, capture=True,
    )
    if cp.returncode != 0:
        fail("VPN включён, но diagnostic monitor не запустился: " + (cp.stderr or cp.stdout or ""))
    ok("Diagnostic mode ON: VPN работает обычно, монитор ничего не перезапускает.")
    print("Через 2–6 часов: vpn diagnostic report > ~/vpn-diagnostic.jsonl")

def cmd_diagnostic_monitor(settings: dict) -> None:
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    last_state = "healthy"
    last_sample = 0.0
    last_network: dict | None = None
    last_pid = 0
    while not stopping:
        if not service_active() or not load_state().get("active"):
            _diagnostic_write({"event": "monitor_stopped", "reason": "VPN is off"})
            return
        started = time.monotonic()
        probes, reasons = _diagnostic_probe_round()
        state = "degraded" if reasons else "healthy"
        now = time.monotonic()
        network = _diagnostic_network_fingerprint()
        process = _diagnostic_process_metrics()
        if last_network is not None and network != last_network:
            _diagnostic_write({
                "event": "network_changed", "before": last_network,
                "after": network,
            })
        if last_pid and process.get("pid") != last_pid:
            _diagnostic_write({
                "event": "xray_pid_changed", "before": last_pid,
                "after": process.get("pid", 0),
            })
        if reasons:
            _diagnostic_write(_diagnostic_snapshot(settings, probes, reasons))
        elif last_state == "degraded":
            _diagnostic_write({"event": "recovered", "probes": probes})
        if now - last_sample >= 60:
            _diagnostic_write({
                "event": "sample", "state": state, "probes": probes,
                "xray_process": process,
                "tun_counters": _diagnostic_link_counters(TUN_NAME),
                "physical_counters": _diagnostic_link_counters(str(network.get("interface") or "")),
                "kernel_tcp": _diagnostic_kernel_tcp_counters(),
                "network": network,
            })
            last_sample = now
        last_state = state
        last_network = network
        last_pid = int(process.get("pid") or 0)
        remaining = max(0.0, DIAGNOSTIC_INTERVAL - (time.monotonic() - started))
        deadline = time.monotonic() + remaining
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(0.5, deadline - time.monotonic()))

def ipv6_tun_route_present() -> bool:
    cp = run(
        ["/usr/bin/ip", "-6", "route", "get", "2606:4700:4700::1111"],
        check=False, capture=True
    )
    return cp.returncode == 0 and TUN_NAME in (cp.stdout or "")

def stop_core() -> None:
    run(["/usr/bin/systemctl", "stop", SERVICE], check=False)
    for _ in range(50):
        if not service_active():
            break
        time.sleep(0.1)

def validate_candidate(settings: dict, cfg: dict) -> None:
    ensure_runtime(settings)
    candidate = RUNTIME_DIR / "candidate.json"
    candidate.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    os.chown(candidate, 0, int(settings["xray_gid"]))
    os.chmod(candidate, 0o640)
    try:
        test_config(candidate)
    finally:
        candidate.unlink(missing_ok=True)

def start_config(settings: dict, cfg: dict) -> bool:
    write_runtime_config(settings, cfg)
    run(["/usr/bin/systemctl", "start", SERVICE], check=False, capture=True)
    ready = wait_service()
    if ready:
        install_guard(settings)
        flush_dns_cache()
    return ready

def startup_preflight(nodes: list[dict]) -> None:
    """Cold-start transport check before changing routes, DNS or the guard."""
    node = nodes[0]
    server = node["outbound"]["settings"]
    host, port = str(node["server_ip"]), int(server["port"])
    iface = default_physical_iface()
    if not iface:
        fail("Нет физического default route. Сеть не переключалась.")
    cp = run(["/usr/bin/ip", "-j", "-4", "route", "get", host],
             check=False, capture=True)
    try:
        route_iface = json.loads(cp.stdout)[0]["dev"]
    except (ValueError, KeyError, IndexError, TypeError):
        fail("Не удалось определить маршрут к VPN-серверу. Сеть не переключалась.")
    if route_iface != iface or pathlib.Path(f"/sys/class/net/{iface}/tun_flags").exists():
        fail(f"Маршрут к VPN-серверу идёт через {route_iface}, default interface: {iface}. "
             "Возможно, включён другой VPN. Действующее соединение не переключалось. "
             "Для проверки профиля без смены сети: vpn diagnostic probe.")
    error = ""
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(3)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
            sock.connect((host, port))
            return
        except OSError as exc:
            error = str(exc)
        finally:
            sock.close()
    fail(f"TCP к VPN-серверу {host}:{port} через {iface} недоступен до запуска TUN: {error}. "
         "Маршруты, DNS и kill switch не менялись. "
         "Проверь сервер/порт/доступ провайдера; vpn diagnostic probe проверяет профиль через текущую сеть.")


def _proxy_health_check(port: int, password: str) -> tuple[bool, str]:
    results = []
    for url in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
        try:
            cp = run(["/usr/bin/curl", "-4", "--proxy", f"socks5h://127.0.0.1:{port}",
                      "--proxy-user", f"probe:{password}", "--noproxy", "", "--fail",
                      "--silent", "--show-error", "--connect-timeout", "5", "--max-time", "12", url],
                     check=False, capture=True, timeout=13)
            address = ipaddress.ip_address((cp.stdout or "").strip()) if cp.returncode == 0 else None
            good = address is not None and address.version == 4
            results.append((good, str(address) if good else f"curl exit {cp.returncode}"))
        except (ValueError, subprocess.TimeoutExpired):
            results.append((False, "timeout or invalid IPv4 response"))
    return all(good for good, _ in results), "; ".join(detail for _, detail in results)


def _dns_listener_check(port: int, transport: str = "udp") -> tuple[bool, str]:
    tid = random.randrange(65536)
    query = struct.pack("!HHHHHH", tid, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(4)
            sock.connect(("127.0.0.1", port))
            if transport == "udp":
                sock.sendall(query)
                response = sock.recv(4096)
            else:
                sock.sendall(struct.pack("!H", len(query)) + query)
                def exact(size):
                    data = b""
                    while len(data) < size:
                        part = sock.recv(size - len(data))
                        if not part:
                            raise OSError("DNS TCP response truncated")
                        data += part
                    return data
                response = exact(struct.unpack("!H", exact(2))[0])
        if len(response) < 12:
            return False, "short DNS response"
        response_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
        good = response_id == tid and bool(flags & 0x8000) and flags & 15 == 0 and answers > 0
        return good, "ok" if good else f"invalid DNS response: rcode={flags & 15}, answers={answers}"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def cmd_diagnostic_probe(settings: dict, config: str | None) -> None:
    """An authenticated local SOCKS probe; never invokes TUN/guard/service operations."""
    path = choose_config(settings, config)
    node = load_profile(path)[0]
    password = os.urandom(24).hex()
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    finally:
        listener.close()
    dns_listener = socket.socket()
    try:
        dns_listener.bind(("127.0.0.1", 0))
        dns_port = dns_listener.getsockname()[1]
    finally:
        dns_listener.close()
    cfg = {"log": {"loglevel": "none"}, "inbounds": [{
        "listen": "127.0.0.1", "port": port, "protocol": "socks",
        "settings": {"auth": "password", "accounts": [{"user": "probe", "pass": password}], "udp": False},
    }, {"tag": "dns-in-v4", "listen": "127.0.0.1", "port": dns_port,
        "protocol": "dokodemo-door", "settings": {"address": ESTONIA_DNS_IP, "port": 53, "network": "tcp,udp"}}],
        "dns": dns_config(), "routing": {"rules": dns_routing_rules()},
        "outbounds": [node["outbound"], dns_outbound()]}
    ensure_runtime(settings)
    with tempfile.TemporaryDirectory(prefix="probe-", dir=RUNTIME_DIR) as td:
        candidate = pathlib.Path(td) / "config.json"
        candidate.write_text(json.dumps(cfg))
        candidate.chmod(0o600)
        test_config(candidate)
        proc = subprocess.Popen([str(XRAY), "run", "-config", str(candidate)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 3
            while True:
                if proc.poll() is not None:
                    fail("Изолированный Xray завершился; системный VPN не переключался.")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        fail("Изолированный SOCKS не запустился; системный VPN не переключался.")
                    time.sleep(0.05)
            good, detail = _proxy_health_check(port, password)
            dns_results = [_dns_listener_check(dns_port, transport) for transport in ("udp", "tcp")]
            good = good and all(ok for ok, _ in dns_results)
            detail += "; DNS UDP/TCP: " + "; ".join(result for _, result in dns_results)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    with contextlib.suppress(OSError, VPNError):
        _diagnostic_write({"event": "isolated_probe", "profile": path.name, "success": good, "detail": detail})
    if not good:
        fail("Профиль не прошёл изолированную HTTPS-проверку через текущую сеть: " + detail +
             ". Маршруты, DNS и kill switch не менялись.")
    ok(f"Профиль {path.name} работает через текущую сеть: {detail}")
    info("Проверены VLESS, HTTPS и DNS UDP/TCP через текущую сеть; TUN и прямой доступ провайдера не проверяются.")


def _recover_activation(settings: dict, transaction: dict) -> None:
    """Unexpected errors/signals must not strand a partially installed cold start."""
    stop_core()
    if transaction["was_active"] and transaction["old_config"] is None:
        fail("Нет предыдущего runtime config для восстановления; kill switch сохранён.")
    if transaction["was_active"]:
        RUNTIME_CONFIG.write_bytes(transaction["old_config"])
        os.chown(RUNTIME_CONFIG, 0, int(settings["xray_gid"]))
        os.chmod(RUNTIME_CONFIG, 0o640)
        run(["/usr/bin/systemctl", "start", SERVICE], check=False)
        if wait_service():
            install_guard(settings)
            flush_dns_cache()
            if health_check_v4()[0]:
                save_state(transaction["old_state"])
                return
        fail("Восстановление прежнего VPN не прошло; kill switch сохранён. Проверь vpn status / vpn logs.")
    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({**transaction["old_state"], "active": None})


def activate(settings: dict, path: pathlib.Path) -> None:
    transaction = {"touched": False, "handled": False}
    try:
        _activate(settings, path, transaction)
    except BaseException:
        if transaction["touched"] and not transaction["handled"]:
            try:
                old_handler = signal.getsignal(signal.SIGALRM)
                def cleanup_expired(signum, frame):
                    fail("Восстановление превысило 60 секунд; проверь vpn status / vpn logs.")
                signal.signal(signal.SIGALRM, cleanup_expired)
                signal.alarm(60)
                try:
                    _recover_activation(settings, transaction)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
            except Exception as cleanup_error:
                warn(f"Ошибка восстановления после сбоя запуска: {cleanup_error}")
        raise


def _activate(settings: dict, path: pathlib.Path, transaction: dict) -> None:
    if starfive.active_guard():
        fail("Сначала выключи экспериментальный StarFive VPN.")
    old_state = load_state()
    old_config = RUNTIME_CONFIG.read_bytes() if RUNTIME_CONFIG.exists() else None
    was_active = service_active()
    transaction.update(was_active=was_active, old_state=old_state, old_config=old_config)
    if was_active and old_config is None:
        fail("Xray работает без доступного runtime config; безопасный rollback невозможен. Действующее соединение не переключалось.")

    info(f"Разбираю конфиг: {path.name}")
    nodes = load_profile(path)

    # Сначала пробуем настоящий dual-stack. Если удалённый VPS не умеет IPv6,
    # автоматически перестраиваем TUN в IPv4-only fail-closed режиме.
    cfg_v4 = build_config(settings, nodes, ipv6_enabled=False)
    reuse_v4 = reuse_ipv4_mode(old_state, path, old_config, cfg_v4)
    cfg_dual = cfg_v4 if reuse_v4 else build_config(settings, nodes, ipv6_enabled=True)
    if reuse_v4:
        info("Использую проверенный IPv4-only режим этого конфига (IPv6 BLOCKED).")
    validate_candidate(settings, cfg_dual)
    validate_dns_guard(settings)
    if not was_active:
        startup_preflight(nodes)

    if was_active and old_config is not None:
        try:
            unchanged = json.loads(old_config) == cfg_dual
        except (ValueError, TypeError):
            unchanged = False
        if unchanged:
            healthy, detail = health_check_v4()
            if healthy:
                state = {**old_state, "active": path.name, "last_active": path.name,
                         "node": nodes[0]["name"], "server_ip": nodes[0]["server_ip"]}
                if reuse_v4:
                    state["ipv4_config_sha256"] = config_fingerprint(cfg_v4)
                save_state(state)
                ok(f"VPN уже работает: {path.name}; HTTPS проверен, Xray не перезапускаю.")
                return

    transaction["touched"] = True
    save_state({**old_state, "active": None,
                "last_active": old_state.get("last_active") or old_state.get("active")})
    if not was_active:
        install_guard(settings)
    else:
        stop_core()

    failure_reason = "неизвестная ошибка"

    if start_config(settings, cfg_dual):
        info("TUN поднят. Проверяю IPv4 через VLESS...")
        v4_ok, v4_detail = health_check_v4()

        if v4_ok:
            if reuse_v4:
                save_state({**old_state, "since": int(time.time()),
                            "ipv4_config_sha256": config_fingerprint(cfg_v4),
                            "ipv6_checked_at": old_state.get("ipv6_checked_at", old_state.get("since", 0))})
                ok(f"VPN включён: {path.name}")
                ok(f"IPv4: VPN, внешний адрес {v4_detail}")
                ok("IPv6: BLOCKED (повторно использован проверенный режим)")
                return
            info("IPv4 работает. Проверяю IPv6 egress через тот же VPN...")
            v6_ok, v6_detail = probe_ipv6_via_vpn()

            if v6_ok:
                save_state({
                    "active": path.name,
                    "last_active": path.name,
                    "node": nodes[0]["name"],
                    "server_ip": nodes[0]["server_ip"],
                    "ipv6_mode": "vpn",
                    "ipv6_checked_at": int(time.time()),
                    "since": int(time.time()),
                })
                ok(f"VPN включён: {path.name}")
                ok(f"IPv4: VPN, внешний адрес {v4_detail}")
                ok("IPv6: VPN")
                ok("Kill switch: ACTIVE")
                return

            warn(
                "IPv6 через VPN не работает. "
                "Переключаю TUN в IPv4-only режим; публичный IPv6 будет BLOCKED."
            )
            warn(f"IPv6 probe: {v6_detail}")

            # Guard не снимаем ни на мгновение.
            stop_core()
            validate_candidate(settings, cfg_v4)

            if start_config(settings, cfg_v4):
                info("ПроверяЎ IPv4 после IPv6 fallback...")
                v4_ok2, v4_detail2 = health_check_v4()
                if v4_ok2:
                    # В этом режиме Xray не создаёт ::/0 через TUN.
                    # Публичный IPv6 физического интерфейса режеч vpn_guard.
                    save_state({
                        "active": path.name,
                        "last_active": path.name,
                        "node": nodes[0]["name"],
                        "server_ip": nodes[0]["server_ip"],
                        "ipv6_mode": "blocked",
                        "ipv6_checked_at": int(time.time()),
                        "ipv4_config_sha256": config_fingerprint(cfg_v4),
                        "ipv6_probe_error": v6_detail,
                        "since": int(time.time()),
                    })
                    ok(f"VPN включён: {path.name}")
                    ok(f"IPv4: VPN, внешний адрес {v4_detail2}")
                    ok("IPv6: BLOCKED (у VPN нет рабочего IPv6 egress)")
                    ok("Kill switch: ACTIVE")
                    return
                failure_reason = v4_detail2
            else:
                failure_reason = "Xray не поднял IPv4-only TUN"
        else:
            failure_reason = v4_detail
    else:
        failure_reason = "Xray не поднял dual-stack TUN"

    warn("Новый VPN не прошёл реальную проверку. Откатываю.")
    log = journal_tail(100)
    stop_core()

    if was_active and old_config is not None:
        RUNTIME_CONFIG.write_bytes(old_config)
        os.chown(RUNTIME_CONFIG, 0, int(settings["xray_gid"]))
        os.chmod(RUNTIME_CONFIG, 0o640)
        run(["/usr/bin/systemctl", "start", SERVICE], check=False)
        if wait_service():
            install_guard(settings)
            flush_dns_cache()
            healthy, _ = health_check_v4()
            if healthy:
                save_state(old_state)
                transaction["handled"] = True
                fail(
                    "Новый конфиг не работает; предыдущий VPN восстановлен.\n"
                    f"Причина: {failure_reason}\n" + log[-5000:]
                )
        transaction["handled"] = True
        fail(
            "Новый VPN не работает и rollback старого тоже не прошёл. "
            "Kill switch ОСТАВЛЕН.\nИспользуй `vpn logs`; `vpn off` "
            "вернёт прямой интернет.\n"
            f"Причина: {failure_reason}\n" + log[-5000:]
        )

    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({
        "active": None,
        "last_active": old_state.get("last_active") or old_state.get("active"),
    })
    transaction["handled"] = True
    fail(
        "VPN не прошёл реальную проверку; прямой интернет "
        "автоматически восстановлен.\n"
        f"Причина: {failure_reason}\n" + log[-5000:]
    )

def deactivate() -> None:
    if starfive.active_guard():
        starfive.dispatch(_starfive_api(), {}, "off")
        return
    info("Выключаю VPN...")
    stop_diagnostic()
    st = load_state()
    last_active = st.get("active") or st.get("last_active")
    stop_core()
    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None, "last_active": last_active})
    ok("VPN выключен. Прямой интернет разрешён.")

def default_physical_iface() -> str | None:
    cp = run(
        ["/usr/bin/ip", "-4", "route", "show", "default", "table", "main"],
        check=False, capture=True
    )
    for line in (cp.stdout or "").splitlines():
        m = re.search(r"\bdev\s+(\S+)", line)
        if m and m.group(1) != TUN_NAME:
            return m.group(1)
    return None

def bound_direct_test(iface: str) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
            iface.encode() + b"\0"
        )
        return s.connect_ex(("1.1.1.1", 443)) == 0
    finally:
        s.close()

def bound_direct_test_v6(iface: str) -> bool:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
            iface.encode() + b"\0"
        )
        return s.connect_ex(("2606:4700:4700::1111", 443, 0, 0)) == 0
    finally:
        s.close()

def cmd_status(settings: dict, with_ip=False) -> None:
    exp = starfive.status()
    if exp["guard"]:
        print(f"Manager:      {MANAGER_VERSION}")
        print("Backend:      StarFive IKEv2 (experimental)")
        print(f"VPN:          {'ON' if exp['active'] else 'BLOCKED'}")
        print("Exit:         Russia (Estonia is not configured yet)")
        print("IPv6:         BLOCKED")
        print("Kill switch:  ACTIVE")
        print(f"Diagnostics:  {'ON' if exp['telemetry'] else 'OFF'}")
        if exp['last_error']:
            print(f"Last error:   {exp['last_error']}")
        return
    st = load_state()
    active = service_active()
    ipv6_mode = st.get("ipv6_mode", "unknown")

    print(f"Manager:      {MANAGER_VERSION}")
    print(f"Safe Xray:    {SAFE_XRAY_VERSION}")
    if XRAY.exists():
        cp = run([XRAY, "version"], check=False, capture=True)
        first = ((cp.stdout or cp.stderr or "").splitlines() or ["installed"])[0]
        print(f"Xray:         {first}")
    else:
        print("Xray:         NOT INSTALLED")
    print(f"VPN:          {'ON' if active else 'OFF'}")
    print(f"Config:       {st.get('active') or '-'}")
    print(f"TUN {TUN_NAME}:  {'YES' if pathlib.Path('/sys/class/net/'+TUN_NAME).exists() else 'NO'}")
    print(f"Kill switch:  {'ACTIVE' if nft_exists() else 'OFF'}")

    if active:
        print("IPv4:         VPN")
        if ipv6_mode == "vpn":
            print("IPv6:         VPN")
        elif ipv6_mode == "blocked":
            print("IPv6:         BLOCKED (remote VPN has no working IPv6)")
        else:
            print("IPv6:         UNKNOWN")
    else:
        print("IPv4:         DIRECT")
        print("IPv6:         DIRECT/system")

    print(f"Configs dir:  {settings['config_dir']}")
    print(
        f"DIRECT rules: {len(read_direct_sites(settings))} domains / "
        f"{len(read_direct_networks(settings))} networks / "
        f"{len(read_direct_apps(settings))} applications"
    )
    print(
        f"DIRECT SOCKS: {DIRECT_SOCKS_HOST}:{DIRECT_SOCKS_PORT} "
        f"({'ON' if active else 'available while VPN is ON'})"
    )
    tcp_ports, udp_ports = _server_port_sets(settings)
    print(f"SERVER ports: {len(tcp_ports)} TCP / {len(udp_ports)} UDP")

    if with_ip and active:
        v4_ok, v4_detail = health_check_v4()
        print(f"IPv4 health:  {'OK' if v4_ok else 'FAIL'}")
        print(f"Public IPv4:  {v4_detail if v4_ok else '-'}")
        if not v4_ok:
            print(f"IPv4 reason:  {v4_detail}")

        if ipv6_mode == "vpn":
            v6_ok, v6_detail = probe_ipv6_via_vpn()
            print(f"IPv6 health:  {'OK' if v6_ok else 'FAIL'}")
            if not v6_ok:
                print(f"IPv6 reason:  {v6_detail}")
        elif ipv6_mode == "blocked":
            print("IPv6 health:  BLOCKED BY DESIGN")


def _operation_payload() -> dict:
    try:
        operation = json.loads((RUNTIME_DIR / "operation.lock").read_text())
        pid = int(operation["pid"])
        if pid <= 0 or not pathlib.Path(f"/proc/{pid}").exists():
            return {}
        return {"command": str(operation.get("command", "")),
                "elapsed_seconds": max(0, int(time.time()) - int(operation.get("started", 0)))}
    except (OSError, ValueError, TypeError, KeyError):
        return {}


def _status_payload(settings: dict) -> dict:
    exp = starfive.status()
    st = load_state()
    active = service_active()
    operation = _operation_payload()
    connecting = bool(operation)
    return {
        "manager": MANAGER_VERSION,
        "active": ((active and bool(st.get("active"))) or exp["active"]) and not connecting,
        "operation": operation,
        "connecting": connecting,
        "backend": "ikev2" if exp["guard"] else "xray",
        "experimental": exp,
        "profile": "StarFive · Россия" if exp["guard"] else (str(st.get("active") or "") if active else ""),
        "last_profile": str(st.get("last_active") or st.get("active") or ""),
        "ipv6_mode": "blocked" if exp["guard"] else str(st.get("ipv6_mode") or "unknown"),
        "tun": pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists(),
        "kill_switch": exp["guard"] or nft_exists(),
        "direct_domains": len(read_direct_sites(settings)),
        "direct_networks": len(read_direct_networks(settings)),
        "direct_applications": len(read_direct_apps(settings)),
    }


def cmd_status_json(settings: dict) -> None:
    print(json.dumps(_status_payload(settings), ensure_ascii=False, separators=(",", ":")))


def _ui_direct_network_state(settings: dict) -> tuple[list[str], list[dict]]:
    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    block_ips = {value for values in blocks.values() for value in values}
    manual: set[str] = set()
    for raw_line in raw.splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#") or value in block_ips:
            continue
        with contextlib.suppress(ValueError):
            manual.add(ipaddress.ip_network(value, strict=False).compressed)
    snapshots = [
        {"domain": domain, "networks": list(values)}
        for domain, values in sorted(blocks.items())
    ]
    return sorted(
        manual,
        key=lambda value: (
            ipaddress.ip_network(value, strict=False).version,
            int(ipaddress.ip_network(value, strict=False).network_address),
            ipaddress.ip_network(value, strict=False).prefixlen,
        ),
    ), snapshots


def _direct_app_rule_matches(rule: str, process_name: str, executable: str) -> bool:
    if "/" not in rule:
        return rule == process_name
    if rule.endswith("/"):
        return executable.startswith(rule)
    return executable == rule


def _running_user_applications(settings: dict) -> list[dict]:
    uid, _gid = _owner_ids(settings)
    rules = read_direct_apps(settings)
    grouped: dict[tuple[str, str], dict] = {}

    try:
        proc_entries = list(os.scandir("/proc"))
    except OSError:
        return []

    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        proc_dir = pathlib.Path("/proc") / entry.name
        try:
            if proc_dir.stat().st_uid != uid:
                continue
            name = (proc_dir / "comm").read_text(errors="replace").strip()
            executable = os.readlink(proc_dir / "exe")
        except (OSError, PermissionError):
            continue

        if executable.endswith(" (deleted)"):
            executable = executable[:-10]
        if not name or not executable.startswith("/"):
            continue

        key = (name, executable)
        item = grouped.setdefault(
            key,
            {"name": name, "exe": executable, "count": 0, "excluded": False},
        )
        item["count"] += 1

    out = []
    for item in grouped.values():
        item["excluded"] = any(
            _direct_app_rule_matches(rule, str(item["name"]), str(item["exe"]))
            for rule in rules
        )
        out.append(item)

    return sorted(
        out,
        key=lambda item: (
            0 if item["excluded"] else 1,
            str(item["name"]).lower(),
            str(item["exe"]).lower(),
        ),
    )


def _ui_state_payload(settings: dict) -> dict:
    state = _status_payload(settings)
    waydroid_preference = bool(settings.get("waydroid_vpn_enabled", True))
    waydroid_effective = bool(state.get("active") and waydroid_preference)
    manual_networks, snapshots = _ui_direct_network_state(settings)
    tcp_ports, udp_ports = _server_port_sets(settings)
    ports = (
        [{"proto": "tcp", "port": port} for port in sorted(tcp_ports)]
        + [{"proto": "udp", "port": port} for port in sorted(udp_ports)]
    )
    stored = load_state()
    active_name = str(stored.get("active") or "")
    last_name = str(stored.get("last_active") or active_name)
    active_now = bool(state.get("active"))
    profiles = [
        {
            "name": path.name,
            "stem": path.stem,
            "active": bool(active_now and path.name == active_name),
            "last": bool(path.name == last_name),
        }
        for path in list_config_paths(settings)
    ]
    state.update(
        {
            "applications": read_direct_apps(settings),
            "domains": [
                ("=" if kind == "full" else "") + domain
                for kind, domain in read_direct_sites(settings)
            ],
            "networks": manual_networks,
            "dns_snapshots": snapshots,
            "server_ports": ports,
            "profiles": profiles,
            "config_dir": str(settings["config_dir"]),
            "waydroid_vpn_preference": waydroid_preference,
            "waydroid_vpn_effective": waydroid_effective,
            "waydroid_present": pathlib.Path(f"/sys/class/net/{WAYDROID_IFACE}").exists(),
            "waydroid_iface": WAYDROID_IFACE,
        }
    )
    return state


def cmd_ui_state(settings: dict) -> None:
    print(json.dumps(_ui_state_payload(settings), ensure_ascii=False, separators=(",", ":")))


def cmd_ui_running(settings: dict) -> None:
    print(
        json.dumps(
            {"applications": _running_user_applications(settings)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def _decode_ui_action_payload(token: str) -> dict:
    if not token or len(token) > 16384:
        fail("Некорректный UI payload.")
    try:
        encoded = base64.b64decode(token.encode("ascii"), validate=True).decode("ascii")
        payload = json.loads(urllib.parse.unquote(encoded))
    except Exception as exc:
        fail(f"Некорректный UI payload: {exc}")
    if not isinstance(payload, dict):
        fail("UI payload должен быть JSON object.")
    return payload


def _ui_payload_target(payload: dict) -> str:
    target = payload.get("target")
    if not isinstance(target, str):
        fail("UI action требует строковый target.")
    return target


def cmd_ui_action(settings: dict, token: str) -> None:
    payload = _decode_ui_action_payload(token)
    action = str(payload.get("action") or "")

    if action.startswith("experimental_"):
        starfive.dispatch(_starfive_api(), settings, action[len("experimental_"):], str(payload.get("target") or ""))
        return
    if action == "waydroid_vpn_set":
        mode = _ui_payload_target(payload).strip().lower()
        if mode not in {"on", "off"}:
            fail("Waydroid VPN ожидает on или off.")
        cmd_waydroid_vpn_set(settings, mode == "on")
        return
    if action == "profile_activate":
        stop_diagnostic()
        activate(settings, choose_config(settings, _ui_payload_target(payload)))
        return
    if action == "app_add":
        cmd_app_add(settings, _ui_payload_target(payload))
        return
    if action == "app_remove":
        cmd_app_remove(settings, _ui_payload_target(payload))
        return
    if action == "direct_add":
        cmd_direct_add(settings, _ui_payload_target(payload))
        return
    if action == "direct_remove":
        cmd_direct_remove(settings, _ui_payload_target(payload))
        return
    if action in {"port_add", "port_remove"}:
        try:
            port = int(payload.get("port"))
        except (TypeError, ValueError):
            fail("UI action содержит некорректный port.")
        proto = str(payload.get("proto") or "tcp").lower()
        if action == "port_add":
            cmd_port_add(settings, port, proto)
        else:
            cmd_port_remove(settings, port, proto)
        return

    fail(f"Неизвестная UI action: {action!r}.")


def cmd_toggle(settings: dict) -> None:
    if starfive.active_guard():
        starfive.dispatch(_starfive_api(), settings, "off")
        return
    if service_active():
        deactivate()
        return

    stop_diagnostic()
    st = load_state()
    requested = str(st.get("last_active") or st.get("active") or "").strip()
    if requested:
        activate(settings, choose_config(settings, requested))
        return

    paths = list_config_paths(settings)
    if len(paths) == 1:
        activate(settings, paths[0])
        return
    if not paths:
        fail("Нет VPN-конфигов. Добавь конфиг в папку VPN configs.")
    fail(
        "Виджет пока не знает, какой профиль включать. Один раз выполни "
        "`vpn on <имя>`; после этого переключатель запомнит последний профиль."
    )


def _widget_package_dir(settings: dict) -> pathlib.Path:
    home = pathlib.Path(str(settings["owner_home"]))
    return home / ".local" / "share" / "plasma" / "plasmoids" / PLASMOID_ID


def _widget_target_safe(settings: dict, package: pathlib.Path) -> None:
    home = pathlib.Path(str(settings["owner_home"])).resolve()
    try:
        package.resolve(strict=False).relative_to(home)
    except ValueError:
        fail("Некорректный путь установки Plasma-виджета.")
    for candidate in (
        package,
        package / "contents",
        package / "contents" / "ui",
        package / "contents" / "config",
    ):
        if candidate.is_symlink():
            fail(f"Отказываюсь изменять symlink Plasma-виджета: {candidate}")
        if candidate.exists() and not candidate.is_dir():
            fail(f"Ожидалась папка Plasma-виджета: {candidate}")


def _write_owner_text(path: pathlib.Path, text: str, uid: int, gid: int) -> None:
    fd, tmpname = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, 0o644)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def _gui_package_dir(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "evgenium-network"


def _gui_desktop_path(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "applications" / "evgenium-network.desktop"


def _gui_icon_path(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "icons" / "hicolor" / "scalable" / "apps" / "evgenium-network.svg"


def _gui_target_safe(settings: dict, target: pathlib.Path) -> None:
    home = pathlib.Path(str(settings["owner_home"])).resolve()
    try:
        target.resolve(strict=False).relative_to(home)
    except ValueError:
        fail(f"GUI path выходит за пределы home: {target}")
    if target.is_symlink():
        fail(f"Отказываюсь изменять symlink GUI: {target}")


def cmd_gui_install(settings: dict) -> None:
    package = _gui_package_dir(settings)
    desktop = _gui_desktop_path(settings)
    icon = _gui_icon_path(settings)
    _gui_target_safe(settings, package)
    _gui_target_safe(settings, desktop)
    _gui_target_safe(settings, icon)
    uid, gid = _owner_ids(settings)

    package.mkdir(parents=True, exist_ok=True)
    desktop.parent.mkdir(parents=True, exist_ok=True)
    icon.parent.mkdir(parents=True, exist_ok=True)
    for directory in (package, desktop.parent, icon.parent):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")
    gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")
    _write_owner_text(package / "evgenium_gui.py", gui_py, uid, gid)
    _write_owner_text(package / "evgenium_gui.qml", gui_qml, uid, gid)
    _write_owner_text(desktop, GUI_DESKTOP_ENTRY, uid, gid)
    _write_owner_text(icon, APP_ICON_SVG, uid, gid)
    os.chmod(package / "evgenium_gui.py", 0o755)
    os.chmod(package / "evgenium_gui.qml", 0o644)
    os.chmod(icon, 0o644)
    os.chmod(desktop, 0o644)

    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
    ok(f"Evgenium Network GUI установлен: {package}")


def cmd_gui_remove(settings: dict) -> None:
    package = _gui_package_dir(settings)
    desktop = _gui_desktop_path(settings)
    _gui_target_safe(settings, package)
    _gui_target_safe(settings, desktop)
    if package.exists():
        shutil.rmtree(package)
    desktop.unlink(missing_ok=True)
    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
    ok("Evgenium Network GUI удалён из профиля пользователя.")


def cmd_widget_install(settings: dict) -> None:
    cmd_gui_install(settings)
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    uid, gid = _owner_ids(settings)
    ui = package / "contents" / "ui"
    ui.mkdir(parents=True, exist_ok=True)
    for directory in (package, package / "contents", ui):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    stale_config = package / "contents" / "config"
    if stale_config.exists():
        if stale_config.is_symlink():
            fail(f"Отказываюсь удалять symlink Plasma config: {stale_config}")
        shutil.rmtree(stale_config)
    for stale in (
        "VpnBackend.qml", "configApplications.qml", "configNetwork.qml",
        "configPorts.qml", "configGeneral.qml",
    ):
        candidate = ui / stale
        if candidate.is_symlink():
            fail(f"Отказываюсь удалять symlink Plasma UI: {candidate}")
        candidate.unlink(missing_ok=True)

    _write_owner_text(package / "metadata.json", PLASMOID_METADATA, uid, gid)
    _write_owner_text(ui / "main.qml", PLASMOID_MAIN_QML, uid, gid)

    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))

    ok(f"Plasma 6 виджет установлен: {package}")
    print("Шестерёнка E-VPN открывает отдельное приложение Evgenium Network.")


def cmd_widget_remove(settings: dict) -> None:
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    if package.exists():
        shutil.rmtree(package)
        kbuild = shutil.which("kbuildsycoca6")
        if kbuild:
            run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
        ok("Plasma-виджет Evgenium Network удалён.")
    else:
        ok("Plasma-виджет не установлен.")

def cmd_test(settings: dict) -> None:
    if not service_active():
        fail("VPN выключен.")

    st = load_state()
    ipv6_mode = st.get("ipv6_mode", "unknown")

    checks: list[tuple[str, bool]] = [
        ("systemd service", service_active()),
        (f"{TUN_NAME} exists", pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists()),
        ("kill switch", nft_exists()),
    ]

    v4_ok, v4_detail = health_check_v4()
    checks.append(("real IPv4 DNS + HTTPS through VPN", v4_ok))

    udp_ok, udp_detail = udp_dns_check()
    checks.append(("real UDP through VLESS (DNS to 1.1.1.1:53)", udp_ok))

    if ipv6_mode == "vpn":
        v6_ok, v6_detail = probe_ipv6_via_vpn()
        checks.append(("real IPv6 TLS through VPN", v6_ok))
    elif ipv6_mode == "blocked":
        v6_ok = not ipv6_tun_route_present()
        v6_detail = "public IPv6 intentionally blocked"
        checks.append(("IPv6 ::/0 is NOT routed into broken VPN", v6_ok))
    else:
        v6_ok, v6_detail = False, "unknown IPv6 mode"
        checks.append(("IPv6 mode known", False))

    iface = default_physical_iface()
    if iface:
        try:
            leak4 = bound_direct_test(iface)
        except OSError:
            leak4 = False
        checks.append((f"direct IPv4 leak via {iface} BLOCKED", not leak4))

        try:
            leak6 = bound_direct_test_v6(iface)
        except OSError:
            leak6 = False
        checks.append((f"direct IPv6 leak via {iface} BLOCKED", not leak6))

    for name, passed in checks:
        print(f"{color('✓','1;32') if passed else color('✗','1;31')} {name}")

    print(f"IPv4: {v4_detail}")
    print(f"UDP:  {udp_detail}")
    print(f"IPv6: {v6_detail}")

    if not all(p for _, p in checks):
        fail("Одна или несколько проверок не пройдены.")

def cmd_route(settings: dict, target: str) -> None:
    t = target.strip().lower().rstrip(".")
    state = load_state()
    try:
        addr = ipaddress.ip_address(t)
    except ValueError:
        addr = None

    if addr:
        if (
            addr.version == 6
            and state.get("ipv6_mode") == "blocked"
            and not (addr.is_private or addr.is_loopback or addr.is_link_local)
        ):
            print(f"{target} -> BLOCKED (VPN has no working IPv6 egress)")
            return
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            print(f"{target} -> DIRECT (local/private)")
            return
        for net in read_direct_networks(settings):
            if addr in net:
                print(f"{target} -> DIRECT ({net})")
                return
        print(f"{target} -> VPN")
        return

    for kind, domain in read_direct_sites(settings):
        if kind == "full" and t == domain:
            print(f"{target} -> DIRECT (= {domain})")
            return
        if kind == "domain" and (t == domain or t.endswith("." + domain)):
            print(f"{target} -> DIRECT ({domain} + subdomains)")
            return
    print(f"{target} -> VPN")

def inspect_profile(settings: dict, requested: str | None) -> None:
    p = choose_config(settings, requested)
    nodes = load_profile(p)
    for i, n in enumerate(nodes, 1):
        out = n["outbound"]
        ss = out["streamSettings"]
        s = out["settings"]
        print(f"NODE {i}: {n['name']}")
        print(f"  server: [REDACTED] -> {n['server_ip']}")
        print(f"  port: {s['port']}")
        print(f"  uuid: [REDACTED]")
        print(f"  encryption: {s.get('encryption')}")
        print(f"  flow: {s.get('flow','-')}")
        print(f"  network: {ss.get('network')}")
        print(f"  security: {ss.get('security')}")
        if "realitySettings" in ss:
            r = ss["realitySettings"]
            print(f"  reality.serverName: {'[SET]' if r.get('serverName') else '[EMPTY]'}")
            print(f"  reality.publicKey: {'[SET]' if r.get('publicKey') else '[EMPTY]'}")
            print(f"  reality.shortId: {'[SET]' if r.get('shortId') else '[EMPTY]'}")
            print(f"  reality.spiderX: {r.get('spiderX','')!r}")
        if "xhttpSettings" in ss:
            x = ss["xhttpSettings"]
            print(f"  xhttp.path: {x.get('path','')!r}")
            print(f"  xhttp.host: {x.get('host','')!r}")
            print(f"  xhttp.mode: {x.get('mode','auto')!r}")
            print(f"  xhttp.extra: {'[SET]' if 'extra' in x else '[NONE]'}")

def github_xray_asset() -> tuple[str, str, str | None, str | None]:
    data = json.loads(http_get(XRAY_RELEASE_API, 5 * 1024 * 1024))
    tag = str(data.get("tag_name") or "")
    if tag != "v" + SAFE_XRAY_VERSION:
        fail(f"GitHub tag mismatch: {tag}")

    machine = os.uname().machine
    if machine in {"x86_64", "amd64"}:
        asset_name = "Xray-linux-64.zip"
    elif machine in {"aarch64", "arm64"}:
        asset_name = "Xray-linux-arm64-v8a.zip"
    else:
        fail(f"Автоустановка Xray пока не поддерживает {machine}.")

    assets = data.get("assets") or []
    asset = next((a for a in assets if a.get("name") == asset_name), None)
    if not asset:
        fail(f"В Xray release нет {asset_name}")

    digest = str(asset.get("digest") or "")
    expected = digest.split(":", 1)[1] if digest.startswith("sha256:") else None

    dgst_asset = next(
        (a for a in assets if a.get("name") in {
            asset_name + ".dgst",
            asset_name + ".sha256",
        }),
        None,
    )
    dgst_url = str(dgst_asset.get("browser_download_url")) if dgst_asset else None
    return asset_name, str(asset["browser_download_url"]), expected, dgst_url

def parse_checksum_text(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="ignore")
    m = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    return m.group(1).lower() if m else None

def core_update(settings: dict) -> bool:
    info(f"Проверяю совместимый Xray core v{SAFE_XRAY_VERSION}...")
    if XRAY.exists():
        cp = run([XRAY, "version"], check=False, capture=True)
        current = (cp.stdout or cp.stderr or "")
        if SAFE_XRAY_VERSION in current:
            ok(f"Xray уже на совместимой версии {SAFE_XRAY_VERSION}")
            return False

    asset_name, url, expected, dgst_url = github_xray_asset()
    blob = http_get(url, MAX_DOWNLOAD_BYTES)

    if expected is None and dgst_url:
        expected = parse_checksum_text(http_get(dgst_url, 1024 * 1024))
    if expected is None:
        fail(
            "GitHub release не дал SHA-256 ни через digest, ни через .dgst. "
            "Установка отменена."
        )

    got = hashlib.sha256(blob).hexdigest()
    if got != expected:
        fail(
            f"SHA-256 Xray НЕ СОВПАЛ.\nExpected: {expected}\nGot: {got}"
        )
    ok(f"SHA-256 официального {asset_name} подтверждён.")

    with tempfile.TemporaryDirectory() as td:
        zpath = pathlib.Path(td) / "xray.zip"
        zpath.write_bytes(blob)
        try:
            with zipfile.ZipFile(zpath) as zf:
                names = zf.namelist()
                if "xray" not in names:
                    fail("В официальном Xray zip нет файла xray.")
                extracted = pathlib.Path(td) / "xray"
                with zf.open("xray") as src, extracted.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        except zipfile.BadZipFile:
            fail("Скачанный Xray asset не является корректным ZIP.")

        os.chmod(extracted, 0o755)
        cp = run([extracted, "version"], check=False, capture=True)
        if cp.returncode != 0 or SAFE_XRAY_VERSION not in (
            (cp.stdout or "") + (cp.stderr or "")
        ):
            fail("Распакованный Xray binary не прошёл version check.")

        if RUNTIME_CONFIG.exists():
            test_config(RUNTIME_CONFIG, extracted)

        tmp_target = pathlib.Path("/opt/vpn-manager/bin/.xray.new")
        shutil.copy2(extracted, tmp_target)
        os.chmod(tmp_target, 0o755)

    active = service_active()
    if XRAY.exists():
        shutil.copy2(XRAY, XRAY_PREVIOUS)
        os.chmod(XRAY_PREVIOUS, 0o755)
    os.replace(tmp_target, XRAY)

    if active:
        info("Перезапускаю Xray; kill switch остаётся...")
        run(["/usr/bin/systemctl", "restart", SERVICE], check=False)
        if not wait_service():
            warn("Новый Xray не поднялся; откатываю binary.")
            if XRAY_PREVIOUS.exists():
                shutil.copy2(XRAY_PREVIOUS, XRAY)
                os.chmod(XRAY, 0o755)
                run(["/usr/bin/systemctl", "restart", SERVICE], check=False)
            fail("Xray core update откатился.")

    ok(f"Xray core установлен: {SAFE_XRAY_VERSION}")
    return True

def sync_system_files() -> None:
    if starfive.ROOT.joinpath("profile.json").exists():
        starfive.install_delivery()
        starfive.kick_delivery()
    pathlib.Path("/etc/systemd/system/vpn-xray.service").write_text(SERVICE_TEXT)
    os.chmod("/etc/systemd/system/vpn-xray.service", 0o644)

    pathlib.Path("/etc/systemd/system/vpn-diagnostic.service").write_text(DIAGNOSTIC_SERVICE_TEXT)
    os.chmod("/etc/systemd/system/vpn-diagnostic.service", 0o644)

    pathlib.Path("/usr/local/bin/vpn").write_text(WRAPPER_TEXT)
    os.chmod("/usr/local/bin/vpn", 0o755)

    pathlib.Path("/usr/local/bin/evgenium-network").write_text(GUI_WRAPPER_TEXT)
    os.chmod("/usr/local/bin/evgenium-network", 0o755)

    run(["/usr/bin/systemctl", "daemon-reload"], check=False)

def safe_extract_manager(tar_path: pathlib.Path, dest: pathlib.Path) -> str:
    allowed = {"vpnctl.py", "vpnadmin.py", "VERSION"}
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        names = {m.name for m in members}
        if names != allowed:
            fail(f"Manager archive: ожидались {sorted(allowed)}, получено {sorted(names)}")
        for m in members:
            pp = pathlib.PurePosixPath(m.name)
            if not m.isfile() or pp.is_absolute() or ".." in pp.parts:
                fail("Небезопасный manager archive.")
        tf.extractall(dest)
    version = (dest / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        fail("Некорректный VERSION.")
    os.chmod(dest / "vpnctl.py", 0o755)
    os.chmod(dest / "vpnadmin.py", 0o755)
    return version

def manager_update_manifest(settings: dict, manifest_url: str) -> bool:
    info("Проверяю обновление VPN Manager...")
    manifest = json.loads(http_get(manifest_url, 1024 * 1024))
    version = str(manifest.get("version") or "")
    url = str(manifest.get("url") or "")
    expected = str(manifest.get("sha256") or "").lower()

    if version == MANAGER_VERSION:
        ok(f"VPN Manager уже актуален: {MANAGER_VERSION}")
        return False
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        fail("Некорректная version в manager manifest.")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("Некорректный sha256 в manager manifest.")

    blob = http_get(url, 20 * 1024 * 1024)
    if hashlib.sha256(blob).hexdigest() != expected:
        fail("SHA-256 VPN Manager release НЕ СОВПАЛ.")

    with tempfile.TemporaryDirectory(dir="/opt/vpn-manager/releases") as td:
        tdpath = pathlib.Path(td)
        tarpath = tdpath / "release.tar.gz"
        tarpath.write_bytes(blob)
        unpack = tdpath / "unpack"
        unpack.mkdir()
        actual_version = safe_extract_manager(tarpath, unpack)
        if actual_version != version:
            fail("VERSION внутри manager archive не совпал с manifest.")

        cp = run(
            [sys.executable, str(unpack / "vpnctl.py"), "--self-test"],
            check=False, capture=True
        )
        if cp.returncode != 0:
            fail("Self-test новой версии manager не прошёл.")

        dest = RELEASES / version
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(unpack, dest)

    old = pathlib.Path(os.path.realpath(CURRENT)) if CURRENT.exists() else None
    PREVIOUS.unlink(missing_ok=True)
    if old and old.exists():
        PREVIOUS.symlink_to(old)

    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(dest)
    os.replace(newlink, CURRENT)
    os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")

    ok(f"VPN Manager обновлён: {MANAGER_VERSION} -> {version}")
    os.execv(
        "/usr/local/sbin/vpnctl",
        ["/usr/local/sbin/vpnctl", "internal-after-update"]
    )

def manager_rollback() -> None:
    if not PREVIOUS.exists():
        fail("Нет previous manager release.")
    target = pathlib.Path(os.path.realpath(PREVIOUS))
    cp = run(
        [sys.executable, str(target / "vpnctl.py"), "--self-test"],
        check=False, capture=True
    )
    if cp.returncode != 0:
        fail("Previous manager не проходит self-test.")
    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(target)
    os.replace(newlink, CURRENT)
    with contextlib.suppress(FileExistsError):
        os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")
    sync_system_files()
    ok("Manager rollback выполнен.")

def self_test() -> None:
    # Никакой сети. Проверяем парсер на VLESS + XHTTP + REALITY.
    old = globals()["resolve_server"]
    old_diagnostic_cmd = globals()["_diagnostic_cmd"]
    globals()["resolve_server"] = lambda host: "203.0.113.1"
    try:
        sample = (
            "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443"
            "?type=xhttp&encryption=none&security=reality&"
            "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&"
            "sni=www.microsoft.com&sid=aa11&spx=%2F&path=%2Fsync&mode=auto"
            "#Test"
        )
        node = parse_vless_url(sample, "Test")
        out = node["outbound"]
        assert out["protocol"] == "vless"
        assert out["settings"]["address"] == "203.0.113.1"
        assert out["streamSettings"]["network"] == "xhttp"
        assert out["streamSettings"]["realitySettings"]["spiderX"] == "/"
        assert out["streamSettings"]["xhttpSettings"]["path"] == "/sync"

        fake_settings = {
            "direct_sites": "/nonexistent/direct-sites",
            "direct_networks": "/nonexistent/direct-networks",
            "direct_apps": "/nonexistent/direct-apps",
        }
        dual = build_config(fake_settings, [node], ipv6_enabled=True)
        v4 = build_config(fake_settings, [node], ipv6_enabled=False)
        assert dual["inbounds"][0]["settings"]["autoSystemRoutingTable"] == ["0.0.0.0/0", "::/0"]
        assert v4["inbounds"][0]["settings"]["autoSystemRoutingTable"] == ["0.0.0.0/0"]
        assert len(v4["inbounds"][0]["settings"]["gateway"]) == 1
        assert v4["inbounds"][1]["tag"] == "direct-socks-in"
        assert v4["inbounds"][1]["listen"] == "127.0.0.1"
        assert v4["inbounds"][1]["port"] == 18443
        assert v4["routing"]["rules"][0]["outboundTag"] == "direct"
        assert _normalize_direct_app_target("evgenium-waydroid-mapper") == "evgenium-waydroid-mapper"
        assert _normalize_direct_app_target("/opt/example/bin/") == "/opt/example/bin/"

        d, exact = _normalize_domain_target("https://Example.COM/path")
        assert d == "example.com" and exact is False
        assert _classify_direct_target("1.2.3.4")[1] == "1.2.3.4/32"
        sample_rules = "1.2.3.0/24\n"
        sample_rules = _replace_dns_block_text(sample_rules, "example.com", ["203.0.113.1/32", "2001:db8::1/128"])
        blocks = _parse_dns_blocks(sample_rules)
        assert blocks["example.com"] == ["203.0.113.1/32", "2001:db8::1/128"]
        sample_rules = _replace_dns_block_text(sample_rules, "example.com", None)
        assert "EVGENIUM-DNS-BEGIN" not in sample_rules

        assert _parse_server_port_entry("tcp 25565") == ("tcp", 25565)
        guard = render_guard_rules(943, {25565}, {19132})
        assert "type route hook output priority mangle" in guard
        assert "tcp sport { 25565 }" in guard
        assert "udp sport { 19132 }" in guard
        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard
        assert f'iifname "{WAYDROID_IFACE}" oifname "{TUN_NAME}" accept' in guard
        waydroid_guard = render_guard_rules(943, set(), set(), waydroid_direct=True)
        assert "chain waydroid_mark" in waydroid_guard
        assert f"meta mark 0x{WAYDROID_BYPASS_MARK:08x}" in waydroid_guard
        assert f'iifname "{WAYDROID_IFACE}" reject with icmpx type admin-prohibited' in waydroid_guard

        metadata = json.loads(PLASMOID_METADATA)
        assert metadata["KPlugin"]["Id"] == PLASMOID_ID
        assert metadata["X-Plasma-API-Minimum-Version"] == "6.0"
        assert "PlasmoidItem" in PLASMOID_MAIN_QML
        assert 'engine: "executable"' in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML
        assert "/usr/local/bin/evgenium-network --detach" in PLASMOID_MAIN_QML
        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML
        assert 'text: "E-VPN"' in PLASMOID_MAIN_QML
        assert 'Plasmoid.icon: "evgenium-network"' in PLASMOID_MAIN_QML
        assert "E-VPN" in APP_ICON_SVG
        assert "internalAction" not in PLASMOID_MAIN_QML
        gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")
        gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")
        assert "ThreadingHTTPServer" in gui_py
        assert "/api/running" in gui_py and "/api/action" in gui_py
        assert "Evgenium Network" in gui_qml
        assert "Запущены сейчас" in gui_qml
        assert "Профили VPN" in gui_qml
        assert 'action: "profile_activate"' in gui_qml
        assert "VPN для Waydroid" in gui_qml
        assert 'action: "waydroid_vpn_set"' in gui_qml
        assert 'action: "app_add"' in gui_qml
        assert _direct_app_rule_matches("firefox", "firefox", "/usr/lib/firefox/firefox")
        assert _direct_app_rule_matches("/opt/example/", "helper", "/opt/example/bin/helper")
        payload = {"action": "app_add", "target": "firefox"}
        token = base64.b64encode(
            urllib.parse.quote(json.dumps(payload, ensure_ascii=False)).encode("ascii")
        ).decode("ascii")
        assert _decode_ui_action_payload(token) == payload
        assert "internal-diagnostic-monitor" in DIAGNOSTIC_SERVICE_TEXT
        assert "Restart=on-failure" in DIAGNOSTIC_SERVICE_TEXT
        assert "systemctl restart" not in DIAGNOSTIC_SERVICE_TEXT
        assert DIAGNOSTIC_INTERVAL == 5.0
        assert DIAGNOSTIC_LOG_SEGMENT_BYTES * 2 == 100 * 1024 * 1024 * 1024
        socket_sample = (
            "0 600000 192.0.2.10:41000 203.0.113.1:443\n"
            " cubic rto:6200 unacked:4 bytes_retrans:8192 retrans:3/8\n"
        )
        globals()["_diagnostic_cmd"] = lambda *_args, **_kwargs: socket_sample
        metrics = _diagnostic_transport_sockets("203.0.113.1")
        assert metrics["connections"] == 1
        assert metrics["send_queue"] == 600000
        assert metrics["current_retrans"] == 3
        assert metrics["max_rto_ms"] == 6200
        journal_sample = "\n".join([
            "[101] app/dispatcher: sniffed domain: discord.com",
            "[101] transport: failed to open endpoint: timeout",
            "[102] app/dispatcher: sniffed domain: discord.com",
            "[102] transport: failed to open endpoint: timeout",
            "[103] app/dispatcher: sniffed domain: discord.com",
            "[103] transport: failed to open endpoint: timeout",
            "[201] app/dispatcher: sniffed domain: one-off.example",
            "[201] transport: failed to open endpoint: timeout",
        ])
        globals()["_diagnostic_cmd"] = lambda *_args, **_kwargs: journal_sample
        active_failures = _diagnostic_active_failures()
        assert [item["domain"] for item in active_failures] == ["discord.com"]
    finally:
        globals()["resolve_server"] = old
        globals()["_diagnostic_cmd"] = old_diagnostic_cmd
    print("self-test OK")

@contextlib.contextmanager
def operation_guard(args, settings, *, wait_seconds=15, deadline_seconds=600):
    if not operation_requires_lock(args):
        yield
        return
    ensure_runtime(settings)
    # Never unlink a flock file: that would let two operations lock different inodes.
    with open(RUNTIME_DIR / "operation.lock", "a+") as lock:
        until = time.monotonic() + wait_seconds
        announced = False
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not announced:
                    info("Жду завершения другой операции VPN (до 15 с)...")
                    announced = True
                if time.monotonic() >= until:
                    lock.seek(0)
                    owner = lock.read(512).strip()
                    fail("Другая операция VPN ещё выполняется. "
                         f"Владелец: {owner or 'старая версия, PID неизвестен'}. "
                         "Повтори позже. Если старая версия зависла, перезагрузи ноутбук "
                         "и выполни vpn update. Блокировка не удалена.")
                time.sleep(0.1)
        lock.seek(0)
        lock.truncate()
        lock.write(json.dumps({"pid": os.getpid(), "command": args.cmd,
                               "started": int(time.time())}))
        lock.flush()
        def expired(signum, frame):
            fail("Операция VPN превысила лимит 10 минут и прервана. "
                 "Проверь vpn status и повтори команду.")
        old_handler = signal.signal(signal.SIGALRM, expired)
        signal.alarm(deadline_seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
            lock.seek(0)
            lock.truncate()
            fcntl.flock(lock, fcntl.LOCK_UN)

def operation_requires_lock(args) -> bool:
    if args.cmd == "diagnostic" and getattr(args, "diagnostic_cmd", None) == "probe":
        return False
    return (args.cmd in {"on", "switch", "off", "toggle", "reload-rules",
                         "core-update", "update", "internal-after-update", "internal-sync", "manager-rollback", "direct",
                         "app", "port", "diagnostic", "experimental"}
            or (args.cmd == "ui" and getattr(args, "ui_cmd", None) == "action"))

STARFIVE_EXPERIMENTAL_PY_B64 = (
    'IiIiT3B0LWluIElLRXYyIGJhY2tlbmQuIEVtYmVkZGVkIGluIHZwbmN0bCByZWxlYXNlczsgbm8gaW1wb3J0LXRpbWUgc2lk'
    'ZSBlZmZlY3RzLiIiIgppbXBvcnQgaGFzaGxpYgppbXBvcnQgaXBhZGRyZXNzCmltcG9ydCBqc29uCmltcG9ydCBvcwppbXBv'
    'cnQgcGF0aGxpYgppbXBvcnQgcmUKaW1wb3J0IHNodXRpbAppbXBvcnQgc29ja2V0CmltcG9ydCBzc2wKaW1wb3J0IHN1YnBy'
    'b2Nlc3MKaW1wb3J0IHRpbWUKaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCB1cmxsaWIuZXJyb3IKaW1wb3J0IGh0dHAu'
    'Y2xpZW50CmltcG9ydCB1dWlkCmltcG9ydCBmY250bAppbXBvcnQgcGxhdGZvcm0KaW1wb3J0IGlvCmltcG9ydCB0YXJmaWxl'
    'CgpST09UID0gcGF0aGxpYi5QYXRoKCIvZXRjL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlIikKU1RBVEUgPSBwYXRobGliLlBhdGgo'
    'Ii92YXIvbGliL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLmpzb24iKQpSVU5USU1FID0gcGF0aGxpYi5QYXRoKCIvcnVuL2V2Z2Vu'
    'aXVtLWlrZXYyIikKVU5JVCA9ICJldmdlbml1bS1pa2V2Mi5zZXJ2aWNlIgpNT05JVE9SID0gImV2Z2VuaXVtLWlrZXYyLWRp'
    'YWdub3N0aWMuc2VydmljZSIKR1VBUkQgPSAiZXZnZW5pdW0taWtldjItZ3VhcmQuc2VydmljZSIKVEFCTEUgPSAiZXZnZW5p'
    'dW1faWtldjJfZ3VhcmQiClVSSSA9ICJ1bml4Oi8vL3J1bi9ldmdlbml1bS1pa2V2Mi9jaGFyb24udmljaSIKU0VSVkVSID0g'
    'IjEwOS4xOTQuNjcuMTU5IgpIRUFMVEggPSAiaHR0cHM6Ly8xMC43Ny4wLjE6ODQ0MyIKUkVRSUQgPSA3NwpESVJFQ1RfUE9S'
    'VCA9IDg0NDMKRElSRUNUX01BUksgPSAweEU3NzEKREVMSVZFUlkgPSAiZXZnZW5pdW0taWtldjItZGVsaXZlcnkuc2Vydmlj'
    'ZSIKVVNFUlNQQUNFID0gcGF0aGxpYi5QYXRoKCcvb3B0L3Zwbi1tYW5hZ2VyL2lrZXYyLXVzZXJzcGFjZScpClVTRVJTUEFD'
    'RV9WRVJTSU9OID0gJzYuMS4wLW9wZW5zc2wzLjUuOS1tdXNsMS4yLjYtMScKVVNFUlNQQUNFX1NIQTI1NiA9ICdlZTY3ZWY2'
    'MGVkMTdkNjY0NWJkMmY4MTFjZTZmZWI2MWVhZTBmOWM2OTA4MjlhMTEwZGFkNDlhMTAwMWFkNDNjJwpVU0VSU1BBQ0VfVVJM'
    'ID0gJ2h0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS92ZWxpa2lpZXZnZW5pdXN1bHRpbWF0ZS9Fdmdlbml1bV9O'
    'ZXR3b3JrX0xpbnV4L21haW4vZGlzdC9zdGFyZml2ZS11c2Vyc3BhY2UteDg2XzY0LScgKyBVU0VSU1BBQ0VfVkVSU0lPTiAr'
    'ICcudGFyLmd6JwpUVU4gPSAnaXBzZWMwJwpJS0VfTUFSSyA9IDB4RTc3MgoKCmRlZiBiYWNrZW5kKCk6CiAgICBjaG9pY2U9'
    'c3RvcmVkKCkuZ2V0KCdpcHNlY19iYWNrZW5kJykKICAgIGlmIGNob2ljZSBpbiAoJ2tlcm5lbCcsJ3VzZXJzcGFjZScpOiBy'
    'ZXR1cm4gY2hvaWNlCiAgICB0cnk6IHN0ZWFtb3M9J3N0ZWFtb3MnIGluIHBhdGhsaWIuUGF0aCgnL2V0Yy9vcy1yZWxlYXNl'
    'JykucmVhZF90ZXh0KCkubG93ZXIoKQogICAgZXhjZXB0IE9TRXJyb3I6IHN0ZWFtb3M9RmFsc2UKICAgIHJldHVybiAndXNl'
    'cnNwYWNlJyBpZiBzdGVhbW9zIGVsc2UgJ2tlcm5lbCcKCgpkZWYgdXNlcnNwYWNlX3JlYWR5KCk6CiAgICB0cnk6CiAgICAg'
    'ICAgbWFuaWZlc3Q9anNvbi5sb2FkcygoVVNFUlNQQUNFLydCVUlMRC5qc29uJykucmVhZF90ZXh0KCkpCiAgICAgICAgcmV0'
    'dXJuIG1hbmlmZXN0LmdldCgndmVyc2lvbicpPT1VU0VSU1BBQ0VfVkVSU0lPTiBhbmQgYWxsKAogICAgICAgICAgICAoVVNF'
    'UlNQQUNFL25hbWUpLmlzX2ZpbGUoKSBhbmQgb3MuYWNjZXNzKFVTRVJTUEFDRS9uYW1lLG9zLlhfT0spCiAgICAgICAgICAg'
    'IGZvciBuYW1lIGluICgnY2hhcm9uJywnc3dhbmN0bCcpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOiByZXR1'
    'cm4gRmFsc2UKCgpkZWYgYXZhaWxhYmxlKCk6CiAgICByZXR1cm4gdXNlcnNwYWNlX3JlYWR5KCkgaWYgYmFja2VuZCgpPT0n'
    'dXNlcnNwYWNlJyBlbHNlIGJvb2woc2h1dGlsLndoaWNoKCdzd2FuY3RsJykpCgoKZGVmIHZhbGlkX3R1bigpOgogICAgdHJ5'
    'OiByZXR1cm4gYm9vbChpbnQocGF0aGxpYi5QYXRoKCcvc3lzL2NsYXNzL25ldCcsVFVOLCd0dW5fZmxhZ3MnKS5yZWFkX3Rl'
    'eHQoKS5zdHJpcCgpLDE2KSYxKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOiByZXR1cm4gRmFsc2UKCgpkZWYg'
    'c2VsZWN0X2JhY2tlbmQodmFsdWUpOgogICAgaWYgYWN0aXZlX2d1YXJkKCkgb3IgY29ubmVjdGVkKCk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQ'
    'u9GM0L3QvtC1INC/0L7QtNC60LvRjtGH0LXQvdC40LUuJykKICAgIHBhdGNoX3N0YXRlKHsnaXBzZWNfYmFja2VuZCc6dmFs'
    'dWV9KQogICAgcHJpbnQoJ9CS0YvQsdGA0LDQvSDRgNC10LbQuNC8OiAnKygnSVBzZWMg0YfQtdGA0LXQtyBUVU4nIGlmIHZh'
    'bHVlPT0ndXNlcnNwYWNlJyBlbHNlICdJUHNlYyDQsiDRj9C00YDQtScpKQoKCmRlZiBpbnN0YWxsX3VzZXJzcGFjZSgpOgog'
    'ICAgaWYgdXNlcnNwYWNlX3JlYWR5KCk6IHJldHVybgogICAgaWYgYWN0aXZlX2d1YXJkKCk6IHJhaXNlIFJ1bnRpbWVFcnJv'
    'cign0KHQvdCw0YfQsNC70LAg0LLRi9C60LvRjtGH0Lgg0Y3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90YvQuSDRgNC1'
    '0LbQuNC8LCDQt9Cw0YLQtdC8INC/0L7QtNCz0L7RgtC+0LLRjCDQtNCy0LjQttC+0LouJykKICAgIGlmIHBsYXRmb3JtLm1h'
    'Y2hpbmUoKS5sb3dlcigpIG5vdCBpbiAoJ3g4Nl82NCcsJ2FtZDY0Jyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQ'
    'kNCy0YLQvtC90L7QvNC90YvQuSDQtNCy0LjQttC+0Log0L/QvtC60LAg0YHQvtCx0YDQsNC9INGC0L7Qu9GM0LrQviDQtNC7'
    '0Y8geDg2XzY0IChTdGVhbSBEZWNrKS4nKQogICAgb3BlbmVyPXVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcih1cmxsaWIu'
    'cmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pKQogICAgd2l0aCBvcGVuZXIub3BlbihVU0VSU1BBQ0VfVVJMLHRpbWVvdXQ9NDUp'
    'IGFzIHJlc3BvbnNlOiBibG9iPXJlc3BvbnNlLnJlYWQoMzIqMTAyNCoxMDI0KzEpCiAgICBpZiBsZW4oYmxvYik+MzIqMTAy'
    'NCoxMDI0IG9yIGhhc2hsaWIuc2hhMjU2KGJsb2IpLmhleGRpZ2VzdCgpIT1VU0VSU1BBQ0VfU0hBMjU2OgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcign0JrQvtC90YLRgNC+0LvRjNC90LDRjyDRgdGD0LzQvNCwINCw0LLRgtC+0L3QvtC80L3QvtCz'
    '0L4g0LTQstC40LbQutCwINC90LUg0YHQvtCy0L/QsNC70LAuJykKICAgIGluc3RhbGxfdXNlcnNwYWNlX2FyY2hpdmUoYmxv'
    'YikKCgpkZWYgaW5zdGFsbF91c2Vyc3BhY2VfYXJjaGl2ZShibG9iKToKICAgIGV4cGVjdGVkPXsnY2hhcm9uJywnc3dhbmN0'
    'bCcsJ0JVSUxELmpzb24nLCdMSUNFTlNFLnN0cm9uZ3N3YW4nLCdMSUNFTlNFLm9wZW5zc2wnLCdMSUNFTlNFLm11c2wnfQog'
    'ICAgd2l0aCB0YXJmaWxlLm9wZW4oZmlsZW9iaj1pby5CeXRlc0lPKGJsb2IpLG1vZGU9J3I6Z3onKSBhcyBhcmNoaXZlOgog'
    'ICAgICAgIG1lbWJlcnM9YXJjaGl2ZS5nZXRtZW1iZXJzKCkKICAgICAgICBpZiBsZW4obWVtYmVycykhPWxlbihleHBlY3Rl'
    'ZCkgb3Ige3gubmFtZSBmb3IgeCBpbiBtZW1iZXJzfSE9ZXhwZWN0ZWQ6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cign0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INGB0L7RgdGC0LDQsiDQsNCy0YLQvtC90L7QvNC90L7Qs9C+INC00LLQuNC2'
    '0LrQsC4nKQogICAgICAgIGlmIHN1bSh4LnNpemUgZm9yIHggaW4gbWVtYmVycyk+NDgqMTAyNCoxMDI0IG9yIGFueShub3Qg'
    'eC5pc2ZpbGUoKSBvciB4LnNpemU+MzIqMTAyNCoxMDI0IGZvciB4IGluIG1lbWJlcnMpOgogICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ9Cd0LXQsdC10LfQvtC/0LDRgdC90YvQuSDQsNGA0YXQuNCyINCw0LLRgtC+0L3QvtC80L3QvtCz0L4g'
    '0LTQstC40LbQutCwLicpCiAgICAgICAgbWV0YWRhdGE9anNvbi5sb2FkKGFyY2hpdmUuZXh0cmFjdGZpbGUoJ0JVSUxELmpz'
    'b24nKSkKICAgICAgICBpZiBtZXRhZGF0YS5nZXQoJ3ZlcnNpb24nKSE9VVNFUlNQQUNFX1ZFUlNJT046IHJhaXNlIFJ1bnRp'
    'bWVFcnJvcign0J3QtdC60L7RgNGA0LXQutGC0L3QsNGPINCy0LXRgNGB0LjRjyDQtNCy0LjQttC60LAuJykKICAgICAgICBV'
    'U0VSU1BBQ0UubWtkaXIocGFyZW50cz1UcnVlLG1vZGU9MG83NTUsZXhpc3Rfb2s9VHJ1ZSkKICAgICAgICBmb3IgbWVtYmVy'
    'IGluIG1lbWJlcnM6CiAgICAgICAgICAgIHRhcmdldD1VU0VSU1BBQ0UvbWVtYmVyLm5hbWUKICAgICAgICAgICAgaWYgdGFy'
    'Z2V0LmlzX3N5bWxpbmsoKTogcmFpc2UgUnVudGltZUVycm9yKCfQndC10LTQvtC/0YPRgdGC0LjQvNCw0Y8g0YHRgdGL0LvQ'
    'utCwINCyINC60LDRgtCw0LvQvtCz0LUg0LTQstC40LbQutCwLicpCiAgICAgICAgICAgIHRlbXA9dGFyZ2V0LndpdGhfc3Vm'
    'Zml4KHRhcmdldC5zdWZmaXgrJy5uZXcnKQogICAgICAgICAgICBmZD1vcy5vcGVuKHRlbXAsb3MuT19XUk9OTFl8b3MuT19D'
    'UkVBVHxvcy5PX1RSVU5DfG9zLk9fTk9GT0xMT1csMG82MDApCiAgICAgICAgICAgIHdpdGggb3MuZmRvcGVuKGZkLCd3Yicp'
    'IGFzIGY6IGYud3JpdGUoYXJjaGl2ZS5leHRyYWN0ZmlsZShtZW1iZXIpLnJlYWQoKSkKICAgICAgICAgICAgdGVtcC5jaG1v'
    'ZCgwbzc1NSBpZiBtZW1iZXIubmFtZSBpbiAoJ2NoYXJvbicsJ3N3YW5jdGwnKSBlbHNlIDBvNjQ0KQogICAgICAgICAgICB0'
    'ZW1wLnJlcGxhY2UodGFyZ2V0KQoKCmRlZiBmYWlsdXJlX2NvZGUoZXhjKToKICAgIHRleHQgPSBzdHIoZXhjKS5sb3dlcigp'
    'CiAgICBpZiBpc2luc3RhbmNlKGV4Yywgc3NsLlNTTENlcnRWZXJpZmljYXRpb25FcnJvcik6IHJldHVybiAnY2VydGlmaWNh'
    'dGUnCiAgICBpZiBpc2luc3RhbmNlKGV4Yywgc3NsLlNTTEVycm9yKTogcmV0dXJuICd0bHMnCiAgICBpZiBpc2luc3RhbmNl'
    'KGV4YywgKFRpbWVvdXRFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkpOiByZXR1cm4gJ3RpbWVvdXQnCiAgICBp'
    'ZiAndW5hYmxlIHRvIGluc3RhbGwnIGluIHRleHQgYW5kICdpcHNlYyBzYScgaW4gdGV4dDogcmV0dXJuICdrZXJuZWxfaXBz'
    'ZWNfdW5hdmFpbGFibGUnCiAgICBpZiByZS5zZWFyY2gociJhdXRoZW50aWNhdGlvblteXG5dKihmYWlsZWR8ZmFpbHVyZSki'
    'LHRleHQpOiByZXR1cm4gJ2F1dGhlbnRpY2F0aW9uJwogICAgaWYgJ3Byb3Bvc2FsJyBpbiB0ZXh0OiByZXR1cm4gJ3Byb3Bv'
    'c2FsJwogICAgaWYgJ3JldHJhbnNtaXQnIGluIHRleHQgb3IgJ3RpbWVkIG91dCcgaW4gdGV4dDogcmV0dXJuICd0aW1lb3V0'
    'JwogICAgaWYgJ3Blcm1pc3Npb24nIGluIHRleHQgb3IgJ29wZXJhdGlvbiBub3QgcGVybWl0dGVkJyBpbiB0ZXh0OiByZXR1'
    'cm4gJ3Blcm1pc3Npb24nCiAgICBpZiBpc2luc3RhbmNlKGV4YywgT1NFcnJvcik6IHJldHVybiAnbmV0d29yaycKICAgIHJl'
    'dHVybiAnb3RoZXInCgoKZGVmIHF1ZXVlX2Nvbm5lY3Rpb24oc3RhZ2UsIGVycm9yLCBlbGFwc2VkPTApOgogICAgaWYgbm90'
    'IHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jyk6IHJldHVybgogICAgZGlyZWN0b3J5ID0gUk9PVCAvICdvdXRib3gnCiAgICBk'
    'aXJlY3RvcnkubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgZmlsZXMgPSBzb3J0'
    'ZWQoZGlyZWN0b3J5Lmdsb2IoJyouanNvbicpLCBrZXk9bGFtYmRhIHA6IHAuc3RhdCgpLnN0X210aW1lKQogICAgZm9yIG9s'
    'ZCBpbiBmaWxlc1s6LTldOiBvbGQudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHJlcG9ydF9pZCA9IHV1aWQudXVpZDQo'
    'KS5oZXgKICAgIGJvZHkgPSB7J3NjaGVtYSc6MSwgJ2V2ZW50JzonY29ubmVjdGlvbl9kaWFnbm9zdGljJywgJ21hbmFnZXIn'
    'OicwLjIuMjMnLAogICAgICAgICAgICAndGltZSc6aW50KHRpbWUudGltZSgpKSwKICAgICAgICAgICAgJ3JlcG9ydF9pZCc6'
    'cmVwb3J0X2lkLCAnc3RhZ2UnOnN0YWdlLCAnZXJyb3InOmVycm9yLAogICAgICAgICAgICAnZWxhcHNlZF9tcyc6bWluKDE4'
    'MDAwMDAsIG1heCgwLCBpbnQoZWxhcHNlZCkpKSwKICAgICAgICAgICAgJ2d1YXJkJzphY3RpdmVfZ3VhcmQoKSwgJ2lwc2Vj'
    'Jzpjb25uZWN0ZWQoKSwgJ2lwc2VjX2JhY2tlbmQnOmJhY2tlbmQoKX0KICAgIHRyeToKICAgICAgICAjIFNlbmQgY291bnRz'
    'IGFuZCBmaXhlZCBjYXRlZ29yaWVzLCBuZXZlciByYXcgam91cm5hbCBsaW5lcyBvciBhZGRyZXNzZXMuCiAgICAgICAgam91'
    'cm5hbD1jbWQoWydqb3VybmFsY3RsJywnLXUnLFVOSVQsJy0tc2luY2UnLCcyIG1pbnV0ZXMgYWdvJywnLW4nLCc4MCcsJy0t'
    'bm8tcGFnZXInXSxjaGVjaz1GYWxzZSx0aW1lb3V0PTMpLnN0ZG91dC5sb3dlcigpCiAgICAgICAgYm9keS51cGRhdGUoaWtl'
    'X3JlY2VpdmVkPWpvdXJuYWwuY291bnQoJ3JlY2VpdmVkIHBhY2tldDonKSwKICAgICAgICAgICAgICAgICAgICBpa2Vfc2Vu'
    'dD1qb3VybmFsLmNvdW50KCdzZW5kaW5nIHBhY2tldDonKSwKICAgICAgICAgICAgICAgICAgICByZXRyYW5zbWl0cz1qb3Vy'
    'bmFsLmNvdW50KCdyZXRyYW5zbWl0JykpCiAgICAgICAgaWYgZXJyb3IgIT0gJ25vbmUnOgogICAgICAgICAgICBpZiAndW5h'
    'YmxlIHRvIGluc3RhbGwgaW5ib3VuZCBhbmQgb3V0Ym91bmQgaXBzZWMgc2EnIGluIGpvdXJuYWw6IGJvZHlbJ2Vycm9yJ109'
    'J2tlcm5lbF9pcHNlY191bmF2YWlsYWJsZScKICAgICAgICAgICAgZWxpZiByZS5zZWFyY2gocidhdXRoZW50aWNhdGlvblte'
    'XG5dKihmYWlsZWR8ZmFpbHVyZSknLGpvdXJuYWwpOiBib2R5WydlcnJvciddPSdhdXRoZW50aWNhdGlvbicKICAgICAgICAg'
    'ICAgZWxpZiAnbm8gcHJvcG9zYWwnIGluIGpvdXJuYWw6IGJvZHlbJ2Vycm9yJ109J3Byb3Bvc2FsJwogICAgICAgIG9zX3Jl'
    'bGVhc2U9cGF0aGxpYi5QYXRoKCcvZXRjL29zLXJlbGVhc2UnKS5yZWFkX3RleHQoKS5sb3dlcigpCiAgICAgICAgYm9keVsn'
    'cGxhdGZvcm0nXT0nc3RlYW1vcycgaWYgJ3N0ZWFtb3MnIGluIG9zX3JlbGVhc2UgZWxzZSAoJ2ZlZG9yYScgaWYgJ2ZlZG9y'
    'YScgaW4gb3NfcmVsZWFzZSBlbHNlICgnYXJjaCcgaWYgJ2FyY2gnIGluIG9zX3JlbGVhc2UgZWxzZSAnb3RoZXInKSkKICAg'
    'IGV4Y2VwdCBFeGNlcHRpb246IHBhc3MKICAgIHdyaXRlKGRpcmVjdG9yeSAvIChyZXBvcnRfaWQgKyAnLmpzb24nKSwganNv'
    'bi5kdW1wcyhib2R5KSkKICAgIHBhdGNoX3N0YXRlKHsgJ2RlbGl2ZXJ5X3N0YXR1cyc6J3F1ZXVlZCcsICdkZWxpdmVyeV9l'
    'cnJvcic6Jyd9KQogICAga2lja19kZWxpdmVyeSgpCgoKZGVmIGtpY2tfZGVsaXZlcnkoKToKICAgIGlmIHN0b3JlZCgpLmdl'
    'dCgndGVsZW1ldHJ5Jyk6CiAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RhcnQnLCctLW5vLWJsb2NrJyxERUxJVkVSWV0s'
    'IGNoZWNrPUZhbHNlKQoKCmRlZiBkaXJlY3RfZW5kcG9pbnQoYm9keSk6CiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAscGFy'
    'ZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgICB3aXRoIChST09ULyJkZWxpdmVyeS5sb2NrIikub3BlbigiYSIpIGFzIGxv'
    'Y2s6CiAgICAgICAgZmNudGwuZmxvY2sobG9jayxmY250bC5MT0NLX0VYKQogICAgICAgIHJldHVybiBfZGlyZWN0X2VuZHBv'
    'aW50KGJvZHkpCgoKZGVmIF9kaXJlY3RfZW5kcG9pbnQoYm9keSk6CiAgICAjIE9ubHkgdGhpcyByb290LW93bmVkIHNvY2tl'
    'dCBjYW4gYnlwYXNzIHRoZSBndWFyZDsgbmV2ZXIgZW52aXJvbm1lbnQgcHJveGllcy4KICAgICMgVGhlIG1hcmtlZCBzb2Nr'
    'ZXQgc2VsZWN0cyB0aGUgcGh5c2ljYWwgcm91dGUgYmVmb3JlIElQc2VjIHNvdXJjZSBzZWxlY3Rpb24uCiAgICBzb2NrID0g'
    'Tm9uZQogICAgY29ubmVjdGlvbiA9IE5vbmUKICAgIHN0YWdlID0gJ2NyZWRlbnRpYWxzJwogICAgdHJ5OgogICAgICAgIGNv'
    'bnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWZpbGU9c3RyKFJPT1QgLyAnY2EucGVtJykpCiAgICAgICAg'
    'Y29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QgLyAnY2xpZW50LnBlbScpLHN0cihST09UIC8gJ2NsaWVudC1rZXku'
    'cGVtJykpCiAgICAgICAgc3RhZ2UgPSAncm91dGUnCiAgICAgICAgcnVsZT1bJ3ByaW9yaXR5JywnOTAnLCdmd21hcmsnLHN0'
    'cihESVJFQ1RfTUFSSyksJ3RvJyxTRVJWRVIrJy8zMicsJ2xvb2t1cCcsJ21haW4nXQogICAgICAgICMgQ2xlYW4gdXAgYW4g'
    'ZXhhY3Qgc3RhbGUgcnVsZSBsZWZ0IGJ5IHByb2Nlc3MgdGVybWluYXRpb24gYmVmb3JlIGFkZGluZyBpdC4KICAgICAgICBj'
    'bWQoWydpcCcsJ3J1bGUnLCdkZWwnLCpydWxlXSxjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWydpcCcsJ3J1bGUnLCdhZGQn'
    'LCpydWxlXSkKICAgICAgICBzb2NrID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFN'
    'KQogICAgICAgIHN0YWdlID0gJ3RjcCcKICAgICAgICBzb2NrLnNldHRpbWVvdXQoNikKICAgICAgICBzb2NrLnNldHNvY2tv'
    'cHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19NQVJLLCBESVJFQ1RfTUFSSykKICAgICAgICBzb2NrLmNvbm5lY3Qo'
    'KFNFUlZFUixESVJFQ1RfUE9SVCkpCiAgICAgICAgc3RhZ2UgPSAndGxzJwogICAgICAgIHRscyA9IGNvbnRleHQud3JhcF9z'
    'b2NrZXQoc29jayxzZXJ2ZXJfaG9zdG5hbWU9U0VSVkVSKQogICAgICAgIGNvbm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQ'
    'Q29ubmVjdGlvbihTRVJWRVIsRElSRUNUX1BPUlQsdGltZW91dD02KQogICAgICAgIGNvbm5lY3Rpb24uc29jayA9IHRscwog'
    'ICAgICAgIHN0YWdlID0gJ2h0dHAnCiAgICAgICAgZGF0YSA9IGpzb24uZHVtcHMoYm9keSxzZXBhcmF0b3JzPSgnLCcsJzon'
    'KSkuZW5jb2RlKCkKICAgICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ1BPU1QnLCcvcmVwb3J0Jyxib2R5PWRhdGEsCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJywnQ29ubmVj'
    'dGlvbic6J2Nsb3NlJ30pCiAgICAgICAgcmVzcG9uc2UgPSBjb25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICByZXBs'
    'eSA9IGpzb24ubG9hZHMocmVzcG9uc2UucmVhZCg0MDk2KSkKICAgICAgICBpZiByZXNwb25zZS5zdGF0dXMgIT0gMjAwIG9y'
    'IHJlcGx5LmdldCgnYWNjZXB0ZWQnKSBpcyBub3QgVHJ1ZToKICAgICAgICAgICAgZXJyb3I9UnVudGltZUVycm9yKCdSZXBv'
    'cnQgcmVqZWN0ZWQnKQogICAgICAgICAgICBlcnJvci5kZWxpdmVyeV9jb2RlPXs0MDM6J2Rpc2FibGVkJyw0MDA6J2ludmFs'
    'aWRfcmVwb3J0J30uZ2V0KHJlc3BvbnNlLnN0YXR1cywncmVqZWN0ZWQnKQogICAgICAgICAgICByYWlzZSBlcnJvcgogICAg'
    'ICAgIGlmIGJvZHkuZ2V0KCdyZXBvcnRfaWQnKSBhbmQgcmVwbHkuZ2V0KCdyZXBvcnRfaWQnKSAhPSBib2R5WydyZXBvcnRf'
    'aWQnXToKICAgICAgICAgICAgZXJyb3I9UnVudGltZUVycm9yKCdBY2tub3dsZWRnZW1lbnQgbWlzbWF0Y2gnKQogICAgICAg'
    'ICAgICBlcnJvci5kZWxpdmVyeV9jb2RlPSdhY2tfbWlzbWF0Y2gnCiAgICAgICAgICAgIHJhaXNlIGVycm9yCiAgICAgICAg'
    'cmV0dXJuIHJlcGx5CiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICBwYXRjaF9zdGF0ZSh7ICdkZWxpdmVy'
    'eV9zdGF0dXMnOidyZXRyeScsCiAgICAgICAgICAgICAgJ2RlbGl2ZXJ5X2Vycm9yJzpzdGFnZSsnXycrZ2V0YXR0cihleGMs'
    'J2RlbGl2ZXJ5X2NvZGUnLGZhaWx1cmVfY29kZShleGMpKX0pCiAgICAgICAgcmFpc2UKICAgIGZpbmFsbHk6CiAgICAgICAg'
    'aWYgY29ubmVjdGlvbjogY29ubmVjdGlvbi5jbG9zZSgpCiAgICAgICAgaWYgc29jazogc29jay5jbG9zZSgpCiAgICAgICAg'
    'IyBSZW1vdmUgb3VyIGV4YWN0IHNjb3BlZCBydWxlLCBpbmNsdWRpbmcgb24gZmFpbGVkIFRDUC9UTFMgaGFuZHNoYWtlcy4K'
    'ICAgICAgICBjbWQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzkwJywnZndtYXJrJyxzdHIoRElSRUNUX01BUksp'
    'LAogICAgICAgICAgICAgJ3RvJyxTRVJWRVIrJy8zMicsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKCgpkZWYgZGVs'
    'aXZlcl9yZXBvcnQoYm9keSk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKTogcmV0dXJuIEZhbHNlCiAg'
    'ICBwYXRjaF9zdGF0ZSh7ICdkZWxpdmVyeV9zdGF0dXMnOidzZW5kaW5nJywgJ2RlbGl2ZXJ5X2F0dGVtcHQnOmludCh0aW1l'
    'LnRpbWUoKSl9KQogICAgYm9keT17Kipib2R5LCAncHJldmlvdXNfZGVsaXZlcnlfZXJyb3InOnN0b3JlZCgpLmdldCgnZGVs'
    'aXZlcnlfZXJyb3InLCcnKX0KICAgIGRpcmVjdF9lbmRwb2ludChib2R5KQogICAgcGF0Y2hfc3RhdGUoeyAnZGVsaXZlcnlf'
    'c3RhdHVzJzonc2VudCcsICdkZWxpdmVyeV9lcnJvcic6JycsCiAgICAgICAgICAnbGFzdF9yZXBvcnQnOnRpbWUuc3RyZnRp'
    'bWUoJyVZLSVtLSVkICVIOiVNOiVTIFVUQycsdGltZS5nbXRpbWUoKSl9KQogICAgcmV0dXJuIFRydWUKCgpkZWYgZGVsaXZl'
    'cnlfd29ya2VyKCk6CiAgICBkZWxheT0xNQogICAgd2hpbGUgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKToKICAgICAgICBm'
    'aWxlcz1saXN0KChST09ULydvdXRib3gnKS5nbG9iKCcqLmpzb24nKSkKICAgICAgICBpZiBub3QgZmlsZXMgYW5kIG5vdCBQ'
    'RU5ESU5HX1RFU1QuZXhpc3RzKCk6IHJldHVybgogICAgICAgIHRyeToKICAgICAgICAgICAgZm9yIHBhdGggaW4gZmlsZXM6'
    'CiAgICAgICAgICAgICAgICBpZiBkZWxpdmVyX3JlcG9ydChqc29uLmxvYWRzKHBhdGgucmVhZF90ZXh0KCkpKTogcGF0aC51'
    'bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgICAgICAgICBmbHVzaF90ZXN0X3JlcG9ydCgpCiAgICAgICAgICAgIGRlbGF5'
    'PTE1CiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgdGltZS5zbGVlcChkZWxheSkKICAgICAgICAgICAg'
    'ZGVsYXk9bWluKGRlbGF5KjIsMzAwKQoKCmRlZiBjbWQoYXJncywgY2hlY2s9VHJ1ZSwgdGltZW91dD0yMCwgZGF0YT1Ob25l'
    'KToKICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVl'
    'LAogICAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBF'
    'LCB0aW1lb3V0PXRpbWVvdXQpCiAgICBpZiBjaGVjayBhbmQgY3AucmV0dXJuY29kZToKICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoKGNwLnN0ZGVyciBvciBjcC5zdGRvdXQgb3IgImNvbW1hbmQgZmFpbGVkIilbLTEyMDA6XSkKICAgIHJldHVybiBj'
    'cAoKCmRlZiB3cml0ZShwYXRoLCBkYXRhLCBtb2RlPTBvNjAwKToKICAgIHBhdGggPSBwYXRobGliLlBhdGgocGF0aCkKICAg'
    'IHBhdGgucGFyZW50Lm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHRtcCA9IHBh'
    'dGgud2l0aF9zdWZmaXgocGF0aC5zdWZmaXggKyAiLm5ldyIpCiAgICBmZCA9IG9zLm9wZW4odG1wLCBvcy5PX1dST05MWSB8'
    'IG9zLk9fQ1JFQVQgfCBvcy5PX1RSVU5DIHwgb3MuT19OT0ZPTExPVywgbW9kZSkKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAi'
    'dyIpIGFzIGY6CiAgICAgICAgZi53cml0ZShkYXRhKQogICAgdG1wLmNobW9kKG1vZGUpCiAgICB0bXAucmVwbGFjZShwYXRo'
    'KQoKCmRlZiBzdG9yZWQoKToKICAgIHRyeToKICAgICAgICByZXR1cm4ganNvbi5sb2FkcyhTVEFURS5yZWFkX3RleHQoKSkK'
    'ICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0dXJuIHt9CgoKZGVmIHNhdmUoc3RhdGUpOgog'
    'ICAgd3JpdGUoU1RBVEUsIGpzb24uZHVtcHMoc3RhdGUsIGVuc3VyZV9hc2NpaT1GYWxzZSkgKyAiXG4iKQoKCmRlZiBwYXRj'
    'aF9zdGF0ZShjaGFuZ2VzKToKICAgICMgS2VlcCBzZW5kZXIgdXBkYXRlcyBmcm9tIG92ZXJ3cml0aW5nIGEgY29uY3VycmVu'
    'dCB0ZWxlbWV0cnktb2ZmIG9wZXJhdGlvbi4KICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCxwYXJlbnRzPVRydWUsZXhpc3Rf'
    'b2s9VHJ1ZSkKICAgIHdpdGggKFJPT1QvJ3N0YXRlLmxvY2snKS5vcGVuKCdhJykgYXMgbG9jazoKICAgICAgICBmY250bC5m'
    'bG9jayhsb2NrLGZjbnRsLkxPQ0tfRVgpCiAgICAgICAgc2F2ZSh7KipzdG9yZWQoKSwqKmNoYW5nZXN9KQoKCmRlZiBhY3Rp'
    'dmVfZ3VhcmQoKToKICAgIGlmIG5vdCBzaHV0aWwud2hpY2goIm5mdCIpOgogICAgICAgIHJldHVybiBGYWxzZQogICAgcmV0'
    'dXJuIGNtZChbIm5mdCIsICJsaXN0IiwgInRhYmxlIiwgImluZXQiLCBUQUJMRV0sIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2Rl'
    'ID09IDAKCgpkZWYgc3dhbigqYXJncywgY2hlY2s9VHJ1ZSwgdGltZW91dD0yMCk6CiAgICBiaW5hcnkgPSBzdHIoVVNFUlNQ'
    'QUNFLyJzd2FuY3RsIikgaWYgYmFja2VuZCgpPT0idXNlcnNwYWNlIiBlbHNlIChzaHV0aWwud2hpY2goInN3YW5jdGwiKSBv'
    'ciAiL3Vzci9zYmluL3N3YW5jdGwiKQogICAgcmV0dXJuIGNtZChbYmluYXJ5LCAqYXJncywgIi0tdXJpIiwgVVJJXSwgY2hl'
    'Y2s9Y2hlY2ssIHRpbWVvdXQ9dGltZW91dCkKCgpkZWYgY29ubmVjdGVkKCk6CiAgICBpZiBub3QgUlVOVElNRS5qb2lucGF0'
    'aCgiY2hhcm9uLnZpY2kiKS5leGlzdHMoKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHRyeToKICAgICAgICBjcCA9IHN3'
    'YW4oIi0tbGlzdC1zYXMiLCAiLS1yYXciLCBjaGVjaz1GYWxzZSwgdGltZW91dD0zKQogICAgICAgIHJldHVybiAoY3AucmV0'
    'dXJuY29kZSA9PSAwIGFuZCAic3RhdGU9SU5TVEFMTEVEIiBpbiBjcC5zdGRvdXQgYW5kICJzdGF0ZT1FU1RBQkxJU0hFRCIg'
    'aW4gY3Auc3Rkb3V0CiAgICAgICAgICAgICAgICBhbmQgKGJhY2tlbmQoKSE9J3VzZXJzcGFjZScgb3IgdmFsaWRfdHVuKCkp'
    'KQogICAgZXhjZXB0IChPU0Vycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICByZXR1cm4gRmFsc2UK'
    'CgpkZWYgd2FpdF91c2Vyc3BhY2UoKToKICAgIGlmIGJhY2tlbmQoKSE9J3VzZXJzcGFjZSc6IHJldHVybgogICAgZm9yIF8g'
    'aW4gcmFuZ2UoNTApOgogICAgICAgIGlmIHZhbGlkX3R1bigpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBp'
    'ZiBzd2FuKCctLXN0YXRzJyxjaGVjaz1GYWxzZSx0aW1lb3V0PTEpLnJldHVybmNvZGU9PTA6IHJldHVybgogICAgICAgICAg'
    'ICBleGNlcHQgKE9TRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6IHBhc3MKICAgICAgICB0aW1lLnNsZWVwKC4x'
    'KQogICAgcmFpc2UgUnVudGltZUVycm9yKCdUVU4t0LTQstC40LbQvtC6INC90LUg0YHQvtC30LTQsNC7INGB0L7QsdGB0YLQ'
    'stC10L3QvdGL0Lkg0LjQvdGC0LXRgNGE0LXQudGBINC4IFZJQ0kt0YHQvtC60LXRgi4nKQoKCmRlZiBzdGF0dXMoKToKICAg'
    'IHN0YXRlID0gc3RvcmVkKCkKICAgIGd1YXJkID0gYWN0aXZlX2d1YXJkKCkKICAgIGxpdmUgPSBjb25uZWN0ZWQoKQogICAg'
    'cmV0dXJuIHsiY29uZmlndXJlZCI6IFJPT1Quam9pbnBhdGgoInByb2ZpbGUuanNvbiIpLmV4aXN0cygpLAogICAgICAgICAg'
    'ICAiYXZhaWxhYmxlIjogYXZhaWxhYmxlKCksICJpcHNlY19iYWNrZW5kIjpiYWNrZW5kKCksICJ1c2Vyc3BhY2VfdmVyc2lv'
    'biI6VVNFUlNQQUNFX1ZFUlNJT04sCiAgICAgICAgICAgICJhY3RpdmUiOiBsaXZlLCAiZ3VhcmQiOiBndWFyZCwKICAgICAg'
    'ICAgICAgInRlbGVtZXRyeSI6IGJvb2woc3RhdGUuZ2V0KCJ0ZWxlbWV0cnkiLCBGYWxzZSkpLAogICAgICAgICAgICAicGhh'
    'c2UiOiAiY29ubmVjdGVkIiBpZiBsaXZlIGVsc2UgKCJibG9ja2VkIiBpZiBndWFyZCBlbHNlICJvZmYiKSwKICAgICAgICAg'
    'ICAgInNlcnZlciI6IFNFUlZFUiwgImVncmVzcyI6ICLQoNC+0YHRgdC40Y8g4oCUINGC0LXRgdGC0L7QstGL0Lkg0LLRi9GF'
    '0L7QtCIsCiAgICAgICAgICAgICJsYXN0X3JlcG9ydCI6IHN0YXRlLmdldCgibGFzdF9yZXBvcnQiLCAiIiksCiAgICAgICAg'
    'ICAgICJsYXN0X2Vycm9yIjogc3RhdGUuZ2V0KCJsYXN0X2Vycm9yIiwgIiIpLAogICAgICAgICAgICAiZGVsaXZlcnkiOiB7'
    'InN0YXR1cyI6c3RhdGUuZ2V0KCdkZWxpdmVyeV9zdGF0dXMnLCdpZGxlJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAi'
    'ZXJyb3IiOnN0YXRlLmdldCgnZGVsaXZlcnlfZXJyb3InLCcnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICJhdHRlbXB0'
    'IjpzdGF0ZS5nZXQoJ2RlbGl2ZXJ5X2F0dGVtcHQnLDApLAogICAgICAgICAgICAgICAgICAgICAgICAgInBlbmRpbmciOmxl'
    'bihsaXN0KChST09ULydvdXRib3gnKS5nbG9iKCcqLmpzb24nKSkpICsgaW50KFBFTkRJTkdfVEVTVC5leGlzdHMoKSl9LAog'
    'ICAgICAgICAgICAidGVzdCI6IHRlc3Rfc3RhdHVzKCksCiAgICAgICAgICAgICJwcm9maWxlX3BhdGgiOiAifi9WcG4vU3Rh'
    'ckZpdmUvcHJvZmlsZS5qc29uIn0KCgpkZWYgdmFsaWRhdGVfcHJvZmlsZShwKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHAs'
    'IGRpY3QpIG9yIHAuZ2V0KCJzY2hlbWEiKSAhPSAxIG9yIHAuZ2V0KCJzZXJ2ZXIiKSAhPSBTRVJWRVI6CiAgICAgICAgcmFp'
    'c2UgVmFsdWVFcnJvcigi0J7QttC40LTQsNC10YLRgdGPINC/0LXRgNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvR'
    'jCBTdGFyRml2ZSBzY2hlbWE9MS4iKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyImRldmljZS1bYS1mMC05XXsyNH0iLCBz'
    'dHIocC5nZXQoImlkZW50aXR5IiwgIiIpKSk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC'
    '0L3Ri9C5INC40LTQtdC90YLQuNGE0LjQutCw0YLQvtGAINGD0YHRgtGA0L7QudGB0YLQstCwLiIpCiAgICBmb3IgZmllbGQs'
    'IG1hcmtlciBpbiAoKCJjYSIsICJDRVJUSUZJQ0FURSIpLCAoImNlcnRpZmljYXRlIiwgIkNFUlRJRklDQVRFIiksCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgKCJwcml2YXRlX2tleSIsICJQUklWQVRFIEtFWSIpKToKICAgICAgICBzID0gcC5nZXQo'
    'ZmllbGQpCiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2Uocywgc3RyKSBvciBsZW4ocykgPiAzMjc2OCBvciAoIi0tLS0tQkVH'
    'SU4gIiArIG1hcmtlciArICItLS0tLSIpIG5vdCBpbiBzOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQ'
    'vtGA0YDQtdC60YLQvdGL0LUg0LTQsNC90L3Ri9C1INGB0LXRgNGC0LjRhNC40LrQsNGC0L7Qsi4iKQogICAgcmV0dXJuIHAK'
    'CgpkZWYgaW1wb3J0X3Byb2ZpbGUoc2V0dGluZ3MsIG5hbWUpOgogICAgaWYgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQ'
    'u9GM0L3QvtC1INGB0L7QtdC00LjQvdC10L3QuNC1LiIpCiAgICBwYXRoID0gcGF0aGxpYi5QYXRoKG5hbWUpLmV4cGFuZHVz'
    'ZXIoKQogICAgaWYgbmFtZS5zdGFydHN3aXRoKCJ+LyIpOgogICAgICAgIHBhdGggPSBwYXRobGliLlBhdGgoc2V0dGluZ3Nb'
    'Im93bmVyX2hvbWUiXSkgLyBuYW1lWzI6XQogICAgaW1wb3J0IHB3ZAogICAgdWlkID0gcHdkLmdldHB3bmFtKHN0cihzZXR0'
    'aW5nc1sib3duZXJfdXNlciJdKSkucHdfdWlkCiAgICAjIE5ldmVyIGxldCBhIHBhc3N3b3JkbGVzcyBzdWRvIGFjdGlvbiBy'
    'ZWFkIGEgcm9vdCBzZWNyZXQgb3IgYSBzcGVjaWFsIGZpbGUuCiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkg'
    'fCBvcy5PX05PTkJMT0NLIHwgb3MuT19OT0ZPTExPVykKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAicmIiKSBhcyBmOgogICAg'
    'ICAgIHN0ID0gb3MuZnN0YXQoZi5maWxlbm8oKSkKICAgICAgICBpbXBvcnQgc3RhdAogICAgICAgIGlmIG5vdCBzdGF0LlNf'
    'SVNSRUcoc3Quc3RfbW9kZSkgb3Igc3Quc3RfdWlkICE9IHVpZCBvciBzdC5zdF9zaXplID4gMTEwMDAwOgogICAgICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoItCf0YDQvtGE0LjQu9GMINC00L7Qu9C20LXQvSDQsdGL0YLRjCDQvtCx0YvRh9C90YvQ'
    'vCDRhNCw0LnQu9C+0Lwg0LLQu9Cw0LTQtdC70YzRhtCwINC60LvQuNC10L3RgtCwLCDQvdC1INCx0L7Qu9C10LUgMTEwINCa'
    '0JEuIikKICAgICAgICBwID0gdmFsaWRhdGVfcHJvZmlsZShqc29uLmxvYWRzKGYucmVhZCgxMTAwMDEpKSkKICAgIGltcG9y'
    'dCB0ZW1wZmlsZQogICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXA6CiAgICAgICAgc3RhZ2Ug'
    'PSBwYXRobGliLlBhdGgodG1wKQogICAgICAgIGZvciBrZXksIGZpbGVuYW1lIGluICgoImNhIiwgImNhLnBlbSIpLCAoImNl'
    'cnRpZmljYXRlIiwgImNlcnQucGVtIiksICgicHJpdmF0ZV9rZXkiLCAia2V5LnBlbSIpKToKICAgICAgICAgICAgd3JpdGUo'
    'c3RhZ2UgLyBmaWxlbmFtZSwgcFtrZXldKQogICAgICAgIGN0eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNf'
    'Q0xJRU5UKQogICAgICAgIGN0eC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKHN0YWdlIC8gImNhLnBlbSIpKQogICAgICAg'
    'IGN0eC5sb2FkX2NlcnRfY2hhaW4oc3RyKHN0YWdlIC8gImNlcnQucGVtIiksIHN0cihzdGFnZSAvICJrZXkucGVtIikpCiAg'
    'ICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKFJPT1QgLyAi'
    'cHJvZmlsZS5qc29uIiwganNvbi5kdW1wcyhwKSkKICAgIHdyaXRlKFJPT1QgLyAiY2EucGVtIiwgcFsiY2EiXSkKICAgIHdy'
    'aXRlKFJPT1QgLyAiY2xpZW50LnBlbSIsIHBbImNlcnRpZmljYXRlIl0pCiAgICB3cml0ZShST09UIC8gImNsaWVudC1rZXku'
    'cGVtIiwgcFsicHJpdmF0ZV9rZXkiXSkKICAgIHdyaXRlKFJPT1QgLyAicHJpdmF0ZSIgLyAiY2xpZW50LWtleS5wZW0iLCBw'
    'WyJwcml2YXRlX2tleSJdKQogICAgd3JpdGUoUk9PVCAvICJ4NTA5IiAvICJjbGllbnQucGVtIiwgcFsiY2VydGlmaWNhdGUi'
    'XSkKICAgIHdyaXRlKFJPT1QgLyAieDUwOWNhIiAvICJjYS5wZW0iLCBwWyJjYSJdKQogICAgY29udGV4dCA9IHNzbC5TU0xD'
    'b250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgY29udGV4dC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKFJP'
    'T1QgLyAiY2EucGVtIikpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVCAvICJjbGllbnQucGVtIiksIHN0'
    'cihST09UIC8gImNsaWVudC1rZXkucGVtIikpCiAgICBzYXZlKHsidGVsZW1ldHJ5IjogVHJ1ZSwgImxhc3RfZXJyb3IiOiAi'
    'In0pCiAgICBwcmludCgi0J/RgNC+0YTQuNC70Ywg0YPRgdGC0LDQvdC+0LLQu9C10L0uINCS0YDQtdC80LXQvdC90LDRjyDQ'
    'tNC40LDQs9C90L7RgdGC0LjQutCwINCy0LrQu9GO0YfQtdC90LA7INC10ZEg0LzQvtC20L3QviDQstGL0LrQu9GO0YfQuNGC'
    '0Ywg0LfQtNC10YHRjCDQttC1LiIpCgoKZGVmIHByZXBhcmUoKToKICAgIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSI6CiAg'
    'ICAgICAgaW5zdGFsbF91c2Vyc3BhY2UoKQogICAgICAgIHByaW50KCLQkNCy0YLQvtC90L7QvNC90YvQuSBJUHNlYy9UVU4g'
    '0LTQstC40LbQvtC6INCz0L7RgtC+0LIuINCh0LjRgdGC0LXQvNC90YvQuSDQt9Cw0L/RgNC10YIgZXNwNCDRgdC+0YXRgNCw'
    '0L3RkdC9LiIpCiAgICAgICAgcmV0dXJuCiAgICBpZiBzaHV0aWwud2hpY2goInN3YW5jdGwiKToKICAgICAgICByZXR1cm4K'
    'ICAgIGlmIHNodXRpbC53aGljaCgicGFjbWFuIik6CiAgICAgICAgY21kKFsicGFjbWFuIiwgIi1TIiwgIi0tbmVlZGVkIiwg'
    'Ii0tbm9jb25maXJtIiwgInN0cm9uZ3N3YW4iXSwgdGltZW91dD0zMDApCiAgICBlbGlmIHNodXRpbC53aGljaCgiZG5mIik6'
    'CiAgICAgICAgY21kKFsiZG5mIiwgImluc3RhbGwiLCAiLXkiLCAiLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFsc2Ui'
    'LCAic3Ryb25nc3dhbiJdLCB0aW1lb3V0PTMwMCkKICAgIGVsc2U6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQo9GB'
    '0YLQsNC90L7QstC4IHN0cm9uZ1N3YW4g0YEgc3dhbmN0bCDRgdGA0LXQtNGB0YLQstCw0LzQuCDRgdCy0L7QtdCz0L4g0LTQ'
    'uNGB0YLRgNC40LHRg9GC0LjQstCwLiIpCiAgICBwcmludCgic3Ryb25nU3dhbiDRg9GB0YLQsNC90L7QstC70LXQvTsg0LDQ'
    'stGC0L7Qv9C+0LTQutC70Y7Rh9C10L3QuNC1INC90LUg0LLQutC70Y7Rh9C10L3Qvi4iKQoKCmRlZiByZW5kZXJfZ3VhcmQo'
    'KToKICAgIHRyYW5zcG9ydD0oZicgIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntUVU59IiBhY2NlcHQnIGlmIGJhY2tl'
    'bmQoKT09J3VzZXJzcGFjZScKICAgICAgICAgICAgICAgZWxzZSBmJyAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJl'
    'cWlkIHtSRVFJRH0gYWNjZXB0JykKICAgIHJldHVybiBmIiIidGFibGUgaW5ldCB7VEFCTEV9IHt7CiBjaGFpbiBvdXRwdXQg'
    'e3sKICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBh'
    'Y2NlcHQKICBpcCBkYWRkciB7U0VSVkVSfSB1ZHAgZHBvcnQge3sgNTAwLCA0NTAwIH19IGFjY2VwdAogIG1ldGEgc2t1aWQg'
    'MCBtZXRhIG1hcmsge0RJUkVDVF9NQVJLfSBpcCBkYWRkciB7U0VSVkVSfSB0Y3AgZHBvcnQge0RJUkVDVF9QT1JUfSBhY2Nl'
    'cHQKICBtZXRhIG5mcHJvdG8gaXB2NCB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3IGFjY2VwdAp7dHJhbnNwb3J0fQogfX0K'
    'IGNoYWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsK'
    'IH19Cn19CiIiIgoKCmRlZiByZW5kZXJfY29ubmVjdGlvbihwKToKICAgIHJldHVybiBmIiIiY29ubmVjdGlvbnMge3sKIHN0'
    'YXJmaXZlIHt7CiAgdmVyc2lvbiA9IDIKICByZW1vdGVfYWRkcnMgPSB7U0VSVkVSfQogIHZpcHMgPSAwLjAuMC4wCiAgcHJv'
    'cG9zYWxzID0gYWVzMjU2Z2NtMTYtcHJmc2hhMzg0LWVjcDM4NCxhZXMyNTYtc2hhMjU2LW1vZHAyMDQ4CiAgZW5jYXAgPSB5'
    'ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMzBzCiAgbG9jYWwge3sKICAg'
    'YXV0aCA9IGVhcC10bHMKICAgaWQgPSB7cFsnaWRlbnRpdHknXX0KICAgZWFwX2lkID0ge3BbJ2lkZW50aXR5J119CiAgIGNl'
    'cnRzID0ge1JPT1R9L2NsaWVudC5wZW0KICB9fQogIHJlbW90ZSB7ewogICBhdXRoID0gcHVia2V5CiAgIGlkID0ge1NFUlZF'
    'Un0KICAgY2FjZXJ0cyA9IHtST09UfS9jYS5wZW0KICB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5ldCB7ewogICAg'
    'bG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAgZXNw'
    'X3Byb3Bvc2FscyA9IGFlczI1NmdjbTE2LGFlczI1Ni1zaGEyNTYKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRf'
    'YWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQoiIiIKCgpkZWYgcmVuZGVyX3N0cm9uZ3N3YW4oaW5jbHVkZXM9Jycp'
    'OgogICAgaWYgYmFja2VuZCgpPT0ndXNlcnNwYWNlJzoKICAgICAgICBwbHVnaW5zPSdyYW5kb20gbm9uY2Ugb3BlbnNzbCBw'
    'ZW0gcGtjczEgcGtjczggeDUwOSBwdWJrZXkgcmV2b2NhdGlvbiBjb25zdHJhaW50cyBrZXJuZWwtbGliaXBzZWMga2VybmVs'
    'LW5ldGxpbmsgc29ja2V0LWRlZmF1bHQgZWFwLWlkZW50aXR5IGVhcC10bHMgdmljaScKICAgICAgICByZXR1cm4gZiIiImNo'
    'YXJvbiB7ewogbG9hZF9tb2R1bGFyID0gbm8KIGxvYWQgPSB7cGx1Z2luc30KIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0'
    'aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFibGVfcHJpbyA9IDEwMAogcGx1Z2lucyB7ewogIGtlcm5lbC1saWJpcHNl'
    'YyB7ewogICBsb2FkID0gMjAKICAgcmF3X2VzcCA9IG5vCiAgfX0KICBrZXJuZWwtbmV0bGluayB7ewogICBmd21hcmsgPSAh'
    'e2hleChJS0VfTUFSSyl9CiAgfX0KICBzb2NrZXQtZGVmYXVsdCB7ewogICBmd21hcmsgPSB7aGV4KElLRV9NQVJLKX0KICB9'
    'fQogIHZpY2kge3sKICAgc29ja2V0ID0ge1VSSX0KICB9fQogfX0KIGZpbGVsb2cge3sKICBzdGRlcnIge3sKICAgZGVmYXVs'
    'dCA9IDEKICAgZmx1c2hfbGluZSA9IHllcwogIH19CiB9fQp9fQoiIiIKICAgIHJldHVybiAgIiIiY2hhcm9uIHsKIGxvYWRf'
    'bW9kdWxhciA9IHllcwogaW5zdGFsbF9yb3V0ZXMgPSB5ZXMKIHJvdXRpbmdfdGFibGUgPSA1MTgyMgogcm91dGluZ190YWJs'
    'ZV9wcmlvID0gMTAwCiBwbHVnaW5zIHsKIiIiICsgaW5jbHVkZXMgKyBmIiIiCiAgdmljaSB7ewogICBzb2NrZXQgPSB7VVJJ'
    'fQogIH19CiAgcmVzb2x2ZSB7ewogICBsb2FkID0gbm8KICB9fQogIGtlcm5lbC1saWJpcHNlYyB7ewogICBsb2FkID0gbm8K'
    'ICB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sKIGpvdXJuYWwge3sKICBkZWZhdWx0ID0gMQogfX0KfX0KIiIiCgoKZGVm'
    'IHNlcnZpY2VfZmlsZXMoKToKICAgIGNhbmRpZGF0ZXMgPSBbIi91c3Ivc2Jpbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2Jp'
    'bi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYi9pcHNlYy9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYmV4ZWMvaXBzZWMv'
    'Y2hhcm9uLXN5c3RlbWQiLAogICAgICAgICAgICAgICAgICAiL3Vzci9saWIvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCIs'
    'ICIvdXNyL2xpYmV4ZWMvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCJdCiAgICBiaW5hcnkgPSBzdHIoVVNFUlNQQUNFLyJj'
    'aGFyb24iKSBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGFuZCB1c2Vyc3BhY2VfcmVhZHkoKSBlbHNlIG5leHQoKHggZm9y'
    'IHggaW4gY2FuZGlkYXRlcyBpZiBwYXRobGliLlBhdGgoeCkuaXNfZmlsZSgpKSwgTm9uZSkKICAgIGlmIGJhY2tlbmQoKT09'
    'InVzZXJzcGFjZSIgYW5kIG5vdCB1c2Vyc3BhY2VfcmVhZHkoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3Q'
    'sNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQvtCy0LjRgtGMIElLRXYywrsg0LTQu9GPINC30LDQs9GA0YPQ'
    't9C60LggVFVOLdC00LLQuNC20LrQsC4iKQogICAgaWYgbm90IGJpbmFyeToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'ItCd0LUg0L3QsNC50LTQtdC9IGNoYXJvbi1zeXN0ZW1kLiDQndGD0LbQtdC9INC/0LDQutC10YIgc3Ryb25nU3dhbiDRgSBz'
    'eXN0ZW1kIGJhY2tlbmQuIikKICAgIGNvbmZpZ3MgPSBbc3RyKHApIGZvciBwYXR0ZXJuIGluICgiL2V0Yy9zdHJvbmdzd2Fu'
    'LmQvY2hhcm9uLyouY29uZiIsICIvZXRjL3N0cm9uZ3N3YW4vc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYiKQogICAgICAg'
    'ICAgICAgICBmb3IgcCBpbiBwYXRobGliLlBhdGgoIi8iKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCIvIikpXQogICAgaW5jbHVk'
    'ZXMgPSAiXG4iLmpvaW4oImluY2x1ZGUgIiArIHggZm9yIHggaW4gY29uZmlncykKICAgICMgRE5TIGlzIG1hbmFnZWQgdHJh'
    'bnNhY3Rpb25hbGx5IGJ5IHRoaXMgYmFja2VuZCwgbm90IGJ5IHRoZSByZXNvbHZlIHBsdWdpbi4KICAgIHdyaXRlKFJPT1Qg'
    'LyAic3Ryb25nc3dhbi5jb25mIixyZW5kZXJfc3Ryb25nc3dhbihpbmNsdWRlcykpCiAgICB3cml0ZShwYXRobGliLlBhdGgo'
    'Ii9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIFVOSVQsIGYiIiJbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZXhwZXJpbWVu'
    'dGFsIFN0YXJGaXZlIElLRXYyCkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpUeXBlPXsic2ltcGxlIiBpZiBiYWNr'
    'ZW5kKCk9PSJ1c2Vyc3BhY2UiIGVsc2UgIm5vdGlmeSJ9CkVudmlyb25tZW50PVNUUk9OR1NXQU5fQ09ORj17Uk9PVH0vc3Ry'
    'b25nc3dhbi5jb25mCkV4ZWNTdGFydD17YmluYXJ5fQpSdW50aW1lRGlyZWN0b3J5PWV2Z2VuaXVtLWlrZXYyClJ1bnRpbWVE'
    'aXJlY3RvcnlNb2RlPTA3MDAKTWVtb3J5TWF4PTM4NE0KUmVzdGFydD1ubwpUaW1lb3V0U3RhcnRTZWM9MjAKIiIiLCAwbzY0'
    'NCkKICAgIHdyaXRlKFJPT1QgLyAiZ3VhcmQubmZ0IiwgcmVuZGVyX2d1YXJkKCkpCiAgICB3cml0ZShwYXRobGliLlBhdGgo'
    'Ii9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIEdVQVJELCBmIiIiW1VuaXRdCkRlc2NyaXB0aW9uPUZhaWwtY2xvc2VkIGd1YXJk'
    'IGZvciBleHBlcmltZW50YWwgSUtFdjIKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0'
    'CldhbnRzPW5ldHdvcmstcHJlLnRhcmdldApBZnRlcj1sb2NhbC1mcy50YXJnZXQgbmZ0YWJsZXMuc2VydmljZQpbU2Vydmlj'
    'ZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0PXtzaHV0aWwud2hpY2goIm5mdCIpfSAtZiB7'
    'Uk9PVH0vZ3VhcmQubmZ0CkV4ZWNTdG9wPS17c2h1dGlsLndoaWNoKCJuZnQiKX0gZGVsZXRlIHRhYmxlIGluZXQge1RBQkxF'
    'fQpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiLCAwbzY0NCkKICAgIHdyaXRlKHBhdGhsaWIuUGF0'
    'aCgiL2V0Yy9zeXN0ZW1kL3N5c3RlbSIpIC8gTU9OSVRPUiwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPVRlbXBvcmFyeSBTdGFy'
    'Rml2ZSBWUE4gZGlhZ25vc3RpY3MKQWZ0ZXI9ZXZnZW5pdW0taWtldjIuc2VydmljZQpbU2VydmljZV0KRXhlY1N0YXJ0PS91'
    'c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtbW9uaXRvcgpTdGFuZGFyZE91dHB1dD1udWxsClN0YW5k'
    'YXJkRXJyb3I9bnVsbApSZXN0YXJ0PW5vCiIiIiwgMG82NDQpCiAgICBpbnN0YWxsX2RlbGl2ZXJ5KCkKCgpkZWYgaW5zdGFs'
    'bF9kZWxpdmVyeSgpOgogICAgd3JpdGUocGF0aGxpYi5QYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtJykgLyBERUxJVkVSWSwg'
    'IiIiW1VuaXRdCkRlc2NyaXB0aW9uPUV4cGVyaW1lbnRhbCBkaXJlY3QgbVRMUyBkaWFnbm9zdGljIGRlbGl2ZXJ5CkFmdGVy'
    'PW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFy'
    'Zml2ZS1kZWxpdmVyeQpTdGFuZGFyZE91dHB1dD1udWxsClN0YW5kYXJkRXJyb3I9bnVsbApSZXN0YXJ0PW9uLWZhaWx1cmUK'
    'UmVzdGFydFNlYz0zMApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiLCAwbzY0NCkKICAgIGNtZChb'
    'InN5c3RlbWN0bCIsICJkYWVtb24tcmVsb2FkIl0pCiAgICBjbWQoWydzeXN0ZW1jdGwnLCdlbmFibGUnLERFTElWRVJZXSxj'
    'aGVjaz1GYWxzZSkKICAgICMgVXBncmFkZSBhbiBhbHJlYWR5IGFjdGl2ZSBleHBlcmltZW50YWwgZ3VhcmQgd2l0aG91dCBv'
    'cGVuaW5nIG9yZGluYXJ5IHRyYWZmaWMuCiAgICBpZiBhY3RpdmVfZ3VhcmQoKToKICAgICAgICBydWxlcz1jbWQoWyduZnQn'
    'LCdsaXN0JywnY2hhaW4nLCdpbmV0JyxUQUJMRSwnb3V0cHV0J10sY2hlY2s9RmFsc2UpLnN0ZG91dAogICAgICAgIGlmIHN0'
    'cihESVJFQ1RfTUFSSykgbm90IGluIHJ1bGVzIGFuZCBoZXgoRElSRUNUX01BUkspIG5vdCBpbiBydWxlczoKICAgICAgICAg'
    'ICAgY21kKFsnbmZ0JywnaW5zZXJ0JywncnVsZScsJ2luZXQnLFRBQkxFLCdvdXRwdXQnLCdtZXRhJywnc2t1aWQnLCcwJywK'
    'ICAgICAgICAgICAgICAgICAnbWV0YScsJ21hcmsnLHN0cihESVJFQ1RfTUFSSyksJ2lwJywnZGFkZHInLFNFUlZFUiwndGNw'
    'JywnZHBvcnQnLHN0cihESVJFQ1RfUE9SVCksJ2FjY2VwdCddKQoKCmRlZiBzZXRfZG5zKCk6CiAgICByZXNvbHZlZCA9IFJP'
    'T1QgLyAicmVzb2x2ZWQtYmFja3VwLmpzb24iCiAgICBiYWNrdXAgPSBST09UIC8gInJlc29sdi1iYWNrdXAiCiAgICBpZiBi'
    'YWNrdXAuZXhpc3RzKCkgb3IgcmVzb2x2ZWQuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQldGB0YLR'
    'jCDQvdC10LfQsNCy0LXRgNGI0ZHQvdC90L7QtSDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1IEROUy4g0KHQvdCw0YfQ'
    'sNC70LAgdnBuIGV4cGVyaW1lbnRhbCBvZmYuIikKICAgIGlmIHNodXRpbC53aGljaCgicmVzb2x2ZWN0bCIpIGFuZCBjbWQo'
    'WyJzeXN0ZW1jdGwiLCAiaXMtYWN0aXZlIiwgInN5c3RlbWQtcmVzb2x2ZWQiXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUg'
    'PT0gMDoKICAgICAgICByb3V0ZSA9IGpzb24ubG9hZHMoY21kKFsiaXAiLCAiLWoiLCAicm91dGUiLCAiZ2V0IiwgU0VSVkVS'
    'XSkuc3Rkb3V0KVswXQogICAgICAgIGlmYWNlID0gcm91dGVbImRldiJdCiAgICAgICAgZGVmIHByZXZpb3VzKGtpbmQpOgog'
    'ICAgICAgICAgICB0ZXh0ID0gY21kKFsicmVzb2x2ZWN0bCIsIGtpbmQsIGlmYWNlXSkuc3Rkb3V0CiAgICAgICAgICAgIHJl'
    'dHVybiB0ZXh0LnNwbGl0KCIpOiIsIDEpWzFdLnN0cmlwKCkuc3BsaXQoKSBpZiAiKToiIGluIHRleHQgZWxzZSBbXQogICAg'
    'ICAgIHdyaXRlKHJlc29sdmVkLCBqc29uLmR1bXBzKHsiaWZhY2UiOiBpZmFjZSwgImRucyI6IHByZXZpb3VzKCJkbnMiKSwg'
    'ImRvbWFpbiI6IHByZXZpb3VzKCJkb21haW4iKX0pKQogICAgICAgIGNtZChbInJlc29sdmVjdGwiLCAiZG5zIiwgaWZhY2Us'
    'ICI3Ny44OC44LjgiLCAiNzcuODguOC4xIl0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsICJkb21haW4iLCBpZmFjZSwg'
    'In4uIl0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsICJmbHVzaC1jYWNoZXMiXSwgY2hlY2s9RmFsc2UpCiAgICAgICAg'
    'cmV0dXJuCiAgICB3cml0ZShiYWNrdXAsIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYuY29uZiIpLnJlYWRfdGV4dCgpKQog'
    'ICAgIyBLZWVwIHRoZSBzeW1saW5rIGl0c2VsZiBpbnRhY3QgKE5ldHdvcmtNYW5hZ2VyL3N5c3RlbWQtcmVzb2x2ZWQgc2V0'
    'dXBzKS4KICAgIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYuY29uZiIpLndyaXRlX3RleHQoIiMgRXZnZW5pdW0gZXhwZXJp'
    'bWVudGFsIFZQTlxubmFtZXNlcnZlciA3Ny44OC44Ljhcbm5hbWVzZXJ2ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6'
    'MiBhdHRlbXB0czoyXG4iKQoKCmRlZiByZXN0b3JlX2RucygpOgogICAgcmVzb2x2ZWQgPSBST09UIC8gInJlc29sdmVkLWJh'
    'Y2t1cC5qc29uIgogICAgaWYgcmVzb2x2ZWQuZXhpc3RzKCk6CiAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMocmVzb2x2ZWQu'
    'cmVhZF90ZXh0KCkpCiAgICAgICAgZm9yIGtleSBpbiAoImRucyIsICJkb21haW4iKToKICAgICAgICAgICAgY21kKFsicmVz'
    'b2x2ZWN0bCIsIGtleSwgZGF0YVsiaWZhY2UiXSwgKihkYXRhW2tleV0gb3IgWyIiXSldKQogICAgICAgIGNtZChbInJlc29s'
    'dmVjdGwiLCAiZmx1c2gtY2FjaGVzIl0sIGNoZWNrPUZhbHNlKQogICAgICAgIHJlc29sdmVkLnVubGluaygpCiAgICBiYWNr'
    'dXAgPSBST09UIC8gInJlc29sdi1iYWNrdXAiCiAgICBpZiBiYWNrdXAuZXhpc3RzKCk6CiAgICAgICAgcGF0aGxpYi5QYXRo'
    'KCIvZXRjL3Jlc29sdi5jb25mIikud3JpdGVfdGV4dChiYWNrdXAucmVhZF90ZXh0KCkpCiAgICAgICAgYmFja3VwLnVubGlu'
    'aygpCgoKZGVmIGVuZHBvaW50KHBhdGgsIHBheWxvYWQ9Tm9uZSk6CiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0'
    'X2NvbnRleHQoY2FmaWxlPXN0cihST09UIC8gImNhLnBlbSIpKQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJP'
    'T1QgLyAiY2xpZW50LnBlbSIpLCBzdHIoUk9PVCAvICJjbGllbnQta2V5LnBlbSIpKQogICAgZGF0YSA9IE5vbmUgaWYgcGF5'
    'bG9hZCBpcyBOb25lIGVsc2UganNvbi5kdW1wcyhwYXlsb2FkLCBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29kZSgpCiAg'
    'ICByZXEgPSB1cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxUSCArIHBhdGgsIGRhdGE9ZGF0YSwgaGVhZGVycz17IkNvbnRl'
    'bnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAjIE5ldmVyIGNvbnN1bHQgZW52aXJvbm1lbnQgcHJveHkgdmFy'
    'aWFibGVzIGZvciBhIHByaXZhdGUgZGlhZ25vc3RpYyBlbmRwb2ludC4KICAgIG9wZW5lciA9IHVybGxpYi5yZXF1ZXN0LmJ1'
    'aWxkX29wZW5lcih1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pLCB1cmxsaWIucmVxdWVzdC5IVFRQU0hhbmRsZXIo'
    'Y29udGV4dD1jb250ZXh0KSkKICAgIHdpdGggb3BlbmVyLm9wZW4ocmVxLCB0aW1lb3V0PTgpIGFzIHJlc3BvbnNlOgogICAg'
    'ICAgIHJldHVybiBqc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQoNjU1MzYpKQoKCmRlZiBvbihhcGksIHNldHRpbmdzKToKICAg'
    'IHN0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKQogICAgc3RhZ2U9J3ByZXBhcmUnCiAgICBpZiBhcGkuc2VydmljZV9hY3RpdmUo'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINCy0YvQutC70Y7Rh9C4INC+0LHRi9GH0L3R'
    'i9C5IFhyYXkgVlBOLiDQntC00L3QvtCy0YDQtdC80LXQvdC90L4g0LTQstCwINGA0LXQttC40LzQsCDQvdC1INC30LDQv9GD'
    '0YHQutCw0Y7RgtGB0Y8uIikKICAgIGlmIGFjdGl2ZV9ndWFyZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KDQ'
    'tdC20LjQvCDRg9C20LUg0LLQutC70Y7Rh9GR0L0g0LjQu9C4INC30LDQsdC70L7QutC40YDQvtCy0LDQvSDQv9C+0YHQu9C1'
    'INGB0LHQvtGPLiDQktGL0LrQu9GO0YfQuCDQtdCz0L4g0L/QtdGA0LXQtCDQv9C+0LLRgtC+0YDQvtC8LiIpCiAgICBpZiBu'
    'b3QgUk9PVC5qb2lucGF0aCgicHJvZmlsZS5qc29uIikuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQ'
    'odC90LDRh9Cw0LvQsCDQuNC80L/QvtGA0YLQuNGA0YPQuSDQv9C10YDRgdC+0L3QsNC70YzQvdGL0Lkg0L/RgNC+0YTQuNC7'
    '0YwgU3RhckZpdmUuIikKICAgIGlmIG5vdCBhdmFpbGFibGUoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3Q'
    'sNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQvtCy0LjRgtGMIElLRXYywrsuIikKICAgICMgRXhpc3Rpbmcg'
    'dW5yZWxhdGVkIElQc2VjIHN0YXRlIG11c3QgbmV2ZXIgYmUgcmVwbGFjZWQuCiAgICBpZiBjbWQoWyJpcCIsICJ4ZnJtIiwg'
    'InN0YXRlIl0sIGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCe0LHQ'
    'vdCw0YDRg9C20LXQvSDQtNGA0YPQs9C+0LkgSVBzZWMgVlBOLiDQodC90LDRh9Cw0LvQsCDQvtGC0LrQu9GO0YfQuCDQtdCz'
    '0L4uIikKICAgIHAgPSB2YWxpZGF0ZV9wcm9maWxlKGpzb24ubG9hZHMoKFJPT1QgLyAicHJvZmlsZS5qc29uIikucmVhZF90'
    'ZXh0KCkpKQogICAgaWYgYmFja2VuZCgpPT0idXNlcnNwYWNlIiBhbmQgcGF0aGxpYi5QYXRoKCIvc3lzL2NsYXNzL25ldCIs'
    'VFVOKS5leGlzdHMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCY0L3RgtC10YDRhNC10LnRgSBpcHNlYzAg0YPQ'
    'ttC1INGB0YPRidC10YHRgtCy0YPQtdGCLiDQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDQuNGB0L/QvtC70YzQt9GD'
    '0Y7RidC10LUg0LXQs9C+INC/0L7QtNC60LvRjtGH0LXQvdC40LUuIikKICAgIHNlcnZpY2VfZmlsZXMoKQogICAgd3JpdGUo'
    'Uk9PVCAvICJjb25uZWN0aW9uLmNvbmYiLCByZW5kZXJfY29ubmVjdGlvbihwKSkKICAgIHRyeToKICAgICAgICBzdGFnZT0n'
    'ZGFlbW9uJwogICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIsIFVOSVRdKQogICAgICAgIHdhaXRfdXNlcnNwYWNl'
    'KCkKICAgICAgICBzdGFnZT0nY3JlZGVudGlhbHMnCiAgICAgICAgc3dhbigiLS1sb2FkLWNyZWRzIiwgIi0tZmlsZSIsIFJP'
    'T1QgLyAiY29ubmVjdGlvbi5jb25mIikKICAgICAgICBzd2FuKCItLWxvYWQtY29ubnMiLCAiLS1maWxlIiwgUk9PVCAvICJj'
    'b25uZWN0aW9uLmNvbmYiKQogICAgICAgIHN0YWdlPSdndWFyZCcKICAgICAgICB3cml0ZShSVU5USU1FIC8gImd1YXJkLm5m'
    'dCIsIHJlbmRlcl9ndWFyZCgpKQogICAgICAgIGNtZChbIm5mdCIsICItYyIsICItZiIsIFJVTlRJTUUgLyAiZ3VhcmQubmZ0'
    'Il0pCiAgICAgICAgIyBBbGwgcHJlcGFyYXRvcnkgY2hlY2tzIGFib3ZlIGFyZSBub24tZGlzcnVwdGl2ZS4gVGhlIGd1YXJk'
    'IGdvZXMgZmlyc3QuCiAgICAgICAgY21kKFsic3lzdGVtY3RsIiwgImVuYWJsZSIsICItLW5vdyIsIEdVQVJEXSkKICAgICAg'
    'ICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgICAgICMgUmVjb3ZlciBhIHN0YWxlIGFjdGl2ZSBzeXN0ZW1kIHVu'
    'aXQgd2hvc2UgdGFibGUgd2FzIGV4dGVybmFsbHkgcmVtb3ZlZC4KICAgICAgICAgICAgY21kKFsibmZ0IiwgIi1mIiwgUk9P'
    'VCAvICJndWFyZC5uZnQiXSkKICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRp'
    'bWVFcnJvcigi0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTRgtCy0LXRgNC00LjRgtGMINGD0YHRgtCw0L3QvtCy0LrRgyBr'
    'aWxsIHN3aXRjaC4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5lY3RpbmciLCAibGFzdF9lcnJvciI6'
    'ICIifSkKICAgICAgICBzdGFnZT0naGFuZHNoYWtlJwogICAgICAgIHN3YW4oIi0taW5pdGlhdGUiLCAiLS1jaGlsZCIsICJz'
    'dGFyZml2ZS1uZXQiLCB0aW1lb3V0PTU1KQogICAgICAgIGlmIG5vdCBjb25uZWN0ZWQoKToKICAgICAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCJJUHNlYyBDSElMRF9TQSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQtdC9LiIpCiAgICAgICAgc3RhZ2U9'
    'J2RucycKICAgICAgICBzZXRfZG5zKCkKICAgICAgICBzdGFnZT0naGVhbHRoJwogICAgICAgIGhlYWx0aCA9IGVuZHBvaW50'
    'KCIvaGVhbHRoIikKICAgICAgICBpZiBoZWFsdGguZ2V0KCJzZXJ2aWNlIikgIT0gImV2Z2VuaXVtLXN0YXJmaXZlIjoKICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQndC1INC/0L7QtNGC0LLQtdGA0LbQtNGR0L0g0LTQuNCw0LPQvdC+0YHR'
    'gtC40YfQtdGB0LrQuNC5INGB0LXRgNCy0LXRgCBTdGFyRml2ZS4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjog'
    'ImNvbm5lY3RlZCIsICJzaW5jZSI6IGludCh0aW1lLnRpbWUoKSksICJsYXN0X2Vycm9yIjogIiJ9KQogICAgICAgIGlmIHN0'
    'b3JlZCgpLmdldCgidGVsZW1ldHJ5Iik6CiAgICAgICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIsIE1PTklUT1Jd'
    'KQogICAgICAgIHRyeTogcXVldWVfY29ubmVjdGlvbignY29ubmVjdGVkJywnbm9uZScsKHRpbWUubW9ub3RvbmljKCktc3Rh'
    'cnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgcHJpbnQoIlN0YXJGaXZlINC/0L7Q'
    'tNC60LvRjtGH0ZHQvS4g0KLQtdGB0YLQvtCy0YvQuSDQstGL0YXQvtC0OiDQoNC+0YHRgdC40Y8uIElQdjYg0LggRElSRUNU'
    'LdC40YHQutC70Y7Rh9C10L3QuNGPINC30LDQsdC70L7QutC40YDQvtCy0LDQvdGLLiIpCiAgICBleGNlcHQgRXhjZXB0aW9u'
    'IGFzIGV4YzoKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgICAg'
    'ICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFVOSVRdLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXN0b3JlX2RucygpCiAg'
    'ICAgICAgZ3VhcmRlZD1hY3RpdmVfZ3VhcmQoKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImJsb2NrZWQiIGlm'
    'IGd1YXJkZWQgZWxzZSAib2ZmIiwgImxhc3RfZXJyb3IiOgogICAgICAgICAgICAgICAgICAgICAi0J/QvtC00LrQu9GO0YfQ'
    'tdC90LjQtSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQtdC90L47INC40L3RgtC10YDQvdC10YIg0LfQsNCx0LvQvtC60LjRgNC+'
    '0LLQsNC9INC00L4g0LLRi9C60LvRjtGH0LXQvdC40Y8g0YDQtdC20LjQvNCwLiIgaWYgZ3VhcmRlZCBlbHNlCiAgICAgICAg'
    'ICAgICAgICAgICAgICLQn9C+0LTQs9C+0YLQvtCy0LrQsCDQvdC1INC30LDQstC10YDRiNC10L3QsDsg0L/QvtC00LrQu9GO'
    '0YfQtdC90LjQtSDQuCDQt9Cw0YnQuNGC0LAg0L3QtSDQstC60LvRjtGH0LjQu9C40YHRjC4ifSkKICAgICAgICB0cnk6IHF1'
    'ZXVlX2Nvbm5lY3Rpb24oc3RhZ2UsZmFpbHVyZV9jb2RlKGV4YyksKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkK'
    'ICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgZXJyb3I9UnVudGltZUVycm9yKCLQn9C+0LTQutC70Y7R'
    'h9C10L3QuNC1IFN0YXJGaXZlINC90LUg0YPQtNCw0LvQvtGB0YwuICIgKwogICAgICAgICAgICAgICAgICAgICAgICAgICAo'
    'IktpbGwgc3dpdGNoINC+0YHRgtCw0LLQu9C10L0g0LLQutC70Y7Rh9GR0L3QvdGL0LwuINCS0YvQv9C+0LvQvdC4IHZwbiBl'
    'eHBlcmltZW50YWwgb2ZmLiAiIGlmIGd1YXJkZWQgZWxzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIktpbGwgc3dp'
    'dGNoINC90LUg0LDQutGC0LjQstC40YDQvtCy0LDQvTog0YHQsdC+0Lkg0L/RgNC+0LjQt9C+0YjRkdC7INC00L4g0LLQutC7'
    '0Y7Rh9C10L3QuNGPINGC0YPQvdC90LXQu9GPLiAiKSArIHN0cihleGMpKQogICAgICAgIGVycm9yLmRpYWdub3N0aWNfcXVl'
    'dWVkPVRydWUKICAgICAgICByYWlzZSBlcnJvciBmcm9tIGV4YwoKCmRlZiBvZmYoKToKICAgIGNtZChbInN5c3RlbWN0bCIs'
    'ICJzdG9wIiwgVEVTVF9VTklUXSwgY2hlY2s9RmFsc2UpCiAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIE1PTklUT1Jd'
    'LCBjaGVjaz1GYWxzZSkKICAgIGNtZChbInN5c3RlbWN0bCIsICJzdG9wIiwgVU5JVF0sIGNoZWNrPUZhbHNlKQogICAgcmVz'
    'dG9yZV9kbnMoKQogICAgY21kKFsic3lzdGVtY3RsIiwgImRpc2FibGUiLCAiLS1ub3ciLCBHVUFSRF0sIGNoZWNrPUZhbHNl'
    'KQogICAgY21kKFsibmZ0IiwgImRlbGV0ZSIsICJ0YWJsZSIsICJpbmV0IiwgVEFCTEVdLCBjaGVjaz1GYWxzZSkKICAgIHBh'
    'dGNoX3N0YXRlKHsgInBoYXNlIjogIm9mZiIsICJsYXN0X2Vycm9yIjogIiJ9KQogICAgcHJpbnQoItCt0LrRgdC/0LXRgNC4'
    '0LzQtdC90YLQsNC70YzQvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0LLRi9C60LvRjtGH0LXQvdC+LiDQntCx0YvRh9C9'
    '0YvQuSDQuNC90YLQtdGA0L3QtdGCINCy0L7RgdGB0YLQsNC90L7QstC70LXQvS4iKQoKCmRlZiB0ZWxlbWV0cnkoZW5hYmxl'
    'ZCk6CiAgICBwYXRjaF9zdGF0ZSh7ICJ0ZWxlbWV0cnkiOiBib29sKGVuYWJsZWQpfSkKICAgIGlmIG5vdCBlbmFibGVkOgog'
    'ICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLERFTElWRVJZXSxjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWyJzeXN0'
    'ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsic3lzdGVtY3RsIiwgInN0YXJ0IiBp'
    'ZiBlbmFibGVkIGFuZCBjb25uZWN0ZWQoKSBlbHNlICJzdG9wIiwgTU9OSVRPUl0sIGNoZWNrPUZhbHNlKQogICAgaWYgZW5h'
    'YmxlZDoga2lja19kZWxpdmVyeSgpCiAgICBwcmludCgi0JLRgNC10LzQtdC90L3QsNGPINC00LjQsNCz0L3QvtGB0YLQuNC6'
    '0LAgIiArICgi0LLQutC70Y7Rh9C10L3QsCIgaWYgZW5hYmxlZCBlbHNlICLQstGL0LrQu9GO0YfQtdC90LAiKSkKCgpkZWYg'
    'ZG9tYWluX29ubHkodmFsdWUpOgogICAgIyBFeHBsaWNpdCBkb21haW4tb25seSByZXBvcnQuIE5ldmVyIGFjY2VwdCBVUkxz'
    'LCBwYXRocywgdG9rZW5zIG9yIGFyYml0cmFyeSBsb2cgdGV4dC4KICAgIHZhbHVlID0gdmFsdWUuc3RyaXAoKS5sb3dlcigp'
    'LnJzdHJpcCgiLiIpCiAgICBpZiBsZW4odmFsdWUpID4gMjUzIG9yIG5vdCByZS5mdWxsbWF0Y2gociJbYS16MC05XSg/Olth'
    'LXowLTkuLV0qW2EtejAtOV0pPyIsIHZhbHVlKSBvciAiLiIgbm90IGluIHZhbHVlOgogICAgICAgIHJhaXNlIFZhbHVlRXJy'
    'b3IoItCS0LLQtdC00Lgg0LTQvtC80LXQvSDQsdC10LcgaHR0cHM6Ly8sINC/0YPRgtC4INC4INC/0LDRgNCw0LzQtdGC0YDQ'
    'vtCyLiIpCiAgICBmb3IgbGFiZWwgaW4gdmFsdWUuc3BsaXQoIi4iKToKICAgICAgICBpZiBub3QgbGFiZWwgb3IgbGVuKGxh'
    'YmVsKSA+IDYzIG9yIGxhYmVsLnN0YXJ0c3dpdGgoIi0iKSBvciBsYWJlbC5lbmRzd2l0aCgiLSIpOgogICAgICAgICAgICBy'
    'YWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0Lkg0LTQvtC80LXQvS4iKQogICAgdHJ5OgogICAgICAg'
    'IGlwYWRkcmVzcy5pcF9hZGRyZXNzKHZhbHVlKQogICAgZXhjZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgcmV0dXJuIHZhbHVl'
    'CiAgICByYWlzZSBWYWx1ZUVycm9yKCLQndGD0LbQtdC9INC00L7QvNC10L0g0YHQsNC50YLQsCwg0LAg0L3QtSBJUC3QsNC0'
    '0YDQtdGBLiIpCgoKZGVmIHByb2JlX2RvbWFpbihkb21haW4pOgogICAgZG9tYWluID0gZG9tYWluX29ubHkoZG9tYWluKQog'
    'ICAgc3RhcnQgPSB0aW1lLm1vbm90b25pYygpCiAgICB0cnk6CiAgICAgICAgcmVzb2x2ZWQgPSBzb2NrZXQuZ2V0YWRkcmlu'
    'Zm8oZG9tYWluLCA0NDMsIHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgYWRkcmVzc2VzID0g'
    'bGlzdChkaWN0LmZyb21rZXlzKHhbNF1bMF0gZm9yIHggaW4gcmVzb2x2ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeFs0XVswXSkuaXNfZ2xvYmFsKSlbOjNdCiAgICAgICAgZm9y'
    'IGFkZHJlc3MgaW4gYWRkcmVzc2VzOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB3aXRoIHNvY2tldC5jcmVh'
    'dGVfY29ubmVjdGlvbigoYWRkcmVzcywgNDQzKSwgdGltZW91dD00KSBhcyBzb2NrOgogICAgICAgICAgICAgICAgICAgIHdp'
    'dGggc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKS53cmFwX3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9ZG9tYWlu'
    'KSBhcyBjb25uOgogICAgICAgICAgICAgICAgICAgICAgICBjb25uLnNlbmRhbGwoKCJIRUFEIC8gSFRUUC8xLjFcclxuSG9z'
    'dDogIiArIGRvbWFpbiArICJcclxuQ29ubmVjdGlvbjogY2xvc2VcclxuXHJcbiIpLmVuY29kZSgpKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICBsaW5lID0gY29ubi5yZWN2KDI1Nikuc3BsaXQoYiJcclxuIiwgMSlbMF0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgcGFydHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICAgICAgICAgICAgICAgICAgY29kZSA9IGludChwYXJ0c1sxXSkg'
    'aWYgbGVuKHBhcnRzKSA+IDEgYW5kIHBhcnRzWzFdLmlzZGlnaXQoKSBlbHNlIDAKICAgICAgICAgICAgICAgICAgICAgICAg'
    'aWYgY29kZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB7ImRvbWFpbiI6IGRvbWFpbiwgIm9rIjogVHJ1'
    'ZSwgImh0dHBfc3RhdHVzIjogY29kZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImxhdGVuY3lfbXMi'
    'OiByb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydCkqMTAwMCl9CiAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgc3Ns'
    'LlNTTEVycm9yKToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBwYXNzCiAg'
    'ICByZXR1cm4geyJkb21haW4iOiBkb21haW4sICJvayI6IEZhbHNlLCAiZXJyb3IiOiAiZG5zX3RjcF9vcl90bHNfZmFpbGVk'
    'IiwKICAgICAgICAgICAgImxhdGVuY3lfbXMiOiByb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydCkqMTAwMCl9CgoKZGVm'
    'IHJlcG9ydChkb21haW49Tm9uZSk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCJ0ZWxlbWV0cnkiKToKICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoItCU0LjQsNCz0L3QvtGB0YLQuNC60LAg0LLRi9C60LvRjtGH0LXQvdCwLiDQktC60LvRjtGH0Lgg'
    '0LXRkSDRj9Cy0L3QviDQv9C10YDQtdC0INC+0YLQv9GA0LDQstC60L7QuS4iKQogICAgaWYgbm90IGNvbm5lY3RlZCgpOgog'
    'ICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J7RgtGH0ZHRgiDQvtGC0L/RgNCw0LLQu9GP0LXRgtGB0Y8g0YLQvtC70YzQ'
    'utC+INCy0L3Rg9GC0YDQuCDRg9GB0YLQsNC90L7QstC70LXQvdC90L7Qs9C+IFN0YXJGaXZlIFZQTi4iKQogICAgZG9tYWlu'
    'cyA9IFtkb21haW5fb25seShkb21haW4pXSBpZiBkb21haW4gZWxzZSBsaXN0KFJVX0RPTUFJTlMpCiAgICBwcm9iZXMgPSBb'
    'cHJvYmVfZG9tYWluKHgpIGZvciB4IGluIGRvbWFpbnNdCiAgICBib2R5ID0geyJzY2hlbWEiOiAxLCAiZXZlbnQiOiAic2l0'
    'ZV9yZXBvcnQiIGlmIGRvbWFpbiBlbHNlICJzYW1wbGUiLAogICAgICAgICAgICAidGltZSI6IGludCh0aW1lLnRpbWUoKSks'
    'ICJtYW5hZ2VyIjogIjAuMi4yMyIsICJwbGF0Zm9ybSI6ICJsaW51eCIsCiAgICAgICAgICAgICJwcm9iZXMiOiBwcm9iZXMs'
    'ICJpcHNlYyI6ICJpbnN0YWxsZWQifQogICAgZW5kcG9pbnQoIi9yZXBvcnQiLCBib2R5KQogICAgcGF0Y2hfc3RhdGUoeyAi'
    'bGFzdF9yZXBvcnQiOiB0aW1lLnN0cmZ0aW1lKCIlWS0lbS0lZCAlSDolTTolUyIsIHRpbWUuZ210aW1lKCkpICsgIiBVVEMi'
    'fSkKICAgIHByaW50KGpzb24uZHVtcHMoeyJzZW50IjogVHJ1ZSwgInByb2JlcyI6IHByb2Jlc30sIGVuc3VyZV9hc2NpaT1G'
    'YWxzZSkpCgoKZGVmIG1vbml0b3IoKToKICAgIHdoaWxlIHN0b3JlZCgpLmdldCgidGVsZW1ldHJ5IikgYW5kIGNvbm5lY3Rl'
    'ZCgpOgogICAgICAgIHRyeToKICAgICAgICAgICAgZmx1c2hfdGVzdF9yZXBvcnQoKQogICAgICAgICAgICByZXBvcnQoKQog'
    'ICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHBhc3MKICAgICAgICB0aW1lLnNsZWVwKDYwKQogICAgaWYg'
    'c3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBhbmQgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgdHJ5OiBxdWV1ZV9jb25uZWN0'
    'aW9uKCdkaXNjb25uZWN0ZWQnLCduZXR3b3JrJykKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCgoKZGVmIGRpc3Bh'
    'dGNoKGFwaSwgc2V0dGluZ3MsIGFjdGlvbiwgdGFyZ2V0PSIiKToKICAgIHRyeToKICAgICAgICBpZiBhY3Rpb24gPT0gImds'
    'b2JhbC10ZXN0Ijogc3RhcnRfZ2xvYmFsX3Rlc3QoKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJjYW5jZWwtdGVzdCI6IGNt'
    'ZChbInN5c3RlbWN0bCIsICJzdG9wIiwgVEVTVF9VTklUXSxjaGVjaz1GYWxzZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAi'
    'YmFja2VuZC11c2Vyc3BhY2UiOiBzZWxlY3RfYmFja2VuZCgidXNlcnNwYWNlIikKICAgICAgICBlbGlmIGFjdGlvbiA9PSAi'
    'YmFja2VuZC1rZXJuZWwiOiBzZWxlY3RfYmFja2VuZCgia2VybmVsIikKICAgICAgICBlbGlmIGFjdGlvbiA9PSAicHJlcGFy'
    'ZSI6IHByZXBhcmUoKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJpbXBvcnQiOiBpbXBvcnRfcHJvZmlsZShzZXR0aW5ncywg'
    'dGFyZ2V0KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJvbiI6IG9uKGFwaSwgc2V0dGluZ3MpCiAgICAgICAgZWxpZiBhY3Rp'
    'b24gPT0gIm9mZiI6IG9mZigpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInRlbGVtZXRyeS1vbiI6IHRlbGVtZXRyeShUcnVl'
    'KQogICAgICAgIGVsaWYgYWN0aW9uID09ICJ0ZWxlbWV0cnktb2ZmIjogdGVsZW1ldHJ5KEZhbHNlKQogICAgICAgIGVsaWYg'
    'YWN0aW9uID09ICJyZXBvcnQiOiByZXBvcnQodGFyZ2V0IG9yIE5vbmUpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInNlbmQt'
    'ZGlhZ25vc3RpY3MiOgogICAgICAgICAgICBpZiBub3QgUk9PVC5qb2lucGF0aCgncHJvZmlsZS5qc29uJykuZXhpc3RzKCk6'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0LjQvNC/0L7RgNGC0LjRgNGD0Lkg0L/RgNC+0YTQuNC70Ywu'
    'JykKICAgICAgICAgICAgaW5zdGFsbF9kZWxpdmVyeSgpCiAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ21hbnVhbCcs'
    'J25vbmUnKQogICAgICAgICAgICBwcmludCgn0JTQuNCw0LPQvdC+0YHRgtC40LrQsCDRgdC+0YXRgNCw0L3QtdC90LAuINCf'
    '0YDRj9C80LDRjyDQvtGC0L/RgNCw0LLQutCwINCy0YvQv9C+0LvQvdGP0LXRgtGB0Y8g0LIg0YTQvtC90LUuJykKICAgICAg'
    'ICBlbGlmIGFjdGlvbiA9PSAic3RhdHVzIjogcHJpbnQoanNvbi5kdW1wcyhzdGF0dXMoKSwgZW5zdXJlX2FzY2lpPUZhbHNl'
    'KSkKICAgICAgICBlbHNlOiByYWlzZSBWYWx1ZUVycm9yKCLQndC10LjQt9Cy0LXRgdGC0L3QsNGPINGN0LrRgdC/0LXRgNC4'
    '0LzQtdC90YLQsNC70YzQvdCw0Y8g0L7Qv9C10YDQsNGG0LjRjy4iKQogICAgZXhjZXB0IChWYWx1ZUVycm9yLCBSdW50aW1l'
    'RXJyb3IsIE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBhY3Rpb24gPT0g'
    'J29uJyBhbmQgbm90IGdldGF0dHIoZXhjLCdkaWFnbm9zdGljX3F1ZXVlZCcsRmFsc2UpOgogICAgICAgICAgICB0cnk6CiAg'
    'ICAgICAgICAgICAgICBpbnN0YWxsX2RlbGl2ZXJ5KCkKICAgICAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ3ByZXBh'
    'cmUnLGZhaWx1cmVfY29kZShleGMpKQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgcmFpc2Ug'
    'YXBpLlZQTkVycm9yKHN0cihleGMpKSBmcm9tIGV4YwoKClRFU1RfVU5JVCA9ICdldmdlbml1bS1pa2V2Mi1nbG9iYWwtdGVz'
    'dC5zZXJ2aWNlJwpURVNUX1NUQVRFID0gcGF0aGxpYi5QYXRoKCcvdmFyL2xpYi92cG4tbWFuYWdlci9zdGFyZml2ZS10ZXN0'
    'Lmpzb24nKQpQRU5ESU5HX1RFU1QgPSBST09UIC8gJ3BlbmRpbmctZ2xvYmFsLXRlc3QuanNvbicKUlVfRE9NQUlOUyA9ICgn'
    'eWFuZGV4LnJ1JywgJ21haWwucnUnLCAnd3d3LnJ0LnJ1JykKVEVTVF9CTE9DSyA9IGhhc2hsaWIuc2hha2VfMjU2KGInZXZn'
    'ZW5pdW0tc3RhcmZpdmUtaW50ZWdyaXR5LXYxJykuZGlnZXN0KDY1NTM2KQoKCmRlZiB0ZXN0X3N0YXR1cygpOgogICAgdHJ5'
    'OgogICAgICAgIHN0YXRlPWpzb24ubG9hZHMoVEVTVF9TVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixW'
    'YWx1ZUVycm9yKToKICAgICAgICByZXR1cm4geydwaGFzZSc6J2lkbGUnLCdwcm9ncmVzcyc6MH0KICAgIGlmIHN0YXRlLmdl'
    'dCgncGhhc2UnKT09J3J1bm5pbmcnIGFuZCBjbWQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLFRFU1RfVU5JVF0sY2hlY2s9'
    'RmFsc2UpLnJldHVybmNvZGU6CiAgICAgICAgc3RhdGUudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsbWVzc2FnZT0n0KLQ'
    'tdGB0YIg0L/RgNC10YDQstCw0L0uINCX0LDRidC40YLQsCBWUE4g0YHQvtGF0YDQsNC90Y/QtdGC0YHRjy4nKQogICAgcmV0'
    'dXJuIHN0YXRlCgoKZGVmIHRlc3Rfc3RhdGUoKipmaWVsZHMpOgogICAgdHJ5OiBzdGF0ZT1qc29uLmxvYWRzKFRFU1RfU1RB'
    'VEUucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6IHN0YXRlPXt9CiAgICB3cml0ZShURVNU'
    'X1NUQVRFLGpzb24uZHVtcHMoeyoqc3RhdGUsKipmaWVsZHN9LGVuc3VyZV9hc2NpaT1GYWxzZSkpCgoKZGVmIHRlc3RfcmVx'
    'dWVzdChwYXRoLCBkYXRhPU5vbmUsIGhlYWRlcnM9Tm9uZSwgdGltZW91dD0zMCk6CiAgICBjb250ZXh0PXNzbC5jcmVhdGVf'
    'ZGVmYXVsdF9jb250ZXh0KGNhZmlsZT1zdHIoUk9PVC8nY2EucGVtJykpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihz'
    'dHIoUk9PVC8nY2xpZW50LnBlbScpLHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgb3BlbmVyPXVybGxpYi5yZXF1'
    'ZXN0LmJ1aWxkX29wZW5lcih1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pLHVybGxpYi5yZXF1ZXN0LkhUVFBTSGFu'
    'ZGxlcihjb250ZXh0PWNvbnRleHQpKQogICAgcmVxdWVzdD11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxUSCtwYXRoLGRh'
    'dGE9ZGF0YSxoZWFkZXJzPWhlYWRlcnMgb3Ige30pCiAgICByZXR1cm4gb3BlbmVyLm9wZW4ocmVxdWVzdCx0aW1lb3V0PXRp'
    'bWVvdXQpCgoKZGVmIGV4cGVjdGVkX2hhc2goc2l6ZSwgb2Zmc2V0PTApOgogICAgZGlnZXN0PWhhc2hsaWIuc2hhMjU2KCkK'
    'ICAgIHdoaWxlIHNpemU6CiAgICAgICAgcGFydD1URVNUX0JMT0NLW29mZnNldCAlIGxlbihURVNUX0JMT0NLKTpdWzptaW4o'
    'c2l6ZSxsZW4oVEVTVF9CTE9DSyktb2Zmc2V0ICUgbGVuKFRFU1RfQkxPQ0spKV0KICAgICAgICBkaWdlc3QudXBkYXRlKHBh'
    'cnQpOyBzaXplLT1sZW4ocGFydCk7IG9mZnNldCs9bGVuKHBhcnQpCiAgICByZXR1cm4gZGlnZXN0LmhleGRpZ2VzdCgpCgoK'
    'ZGVmIHRyYW5zZmVyX2Rvd25sb2FkKHNpemUsIG9mZnNldD0wLCBsaW1pdD1Ob25lKToKICAgIHN0YXJ0PXRpbWUubW9ub3Rv'
    'bmljKCk7IHJlY2VpdmVkPTA7IGRpZ2VzdD1oYXNobGliLnNoYTI1NigpCiAgICBoZWFkZXJzPXsnUmFuZ2UnOmYnYnl0ZXM9'
    'e29mZnNldH0tJ30gaWYgb2Zmc2V0IGVsc2Uge30KICAgIHdpdGggdGVzdF9yZXF1ZXN0KCcvYmxvYj9zaXplPScrc3RyKHNp'
    'emUpLGhlYWRlcnM9aGVhZGVycykgYXMgcmVzcG9uc2U6CiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9ICgyMDYgaWYg'
    'b2Zmc2V0IGVsc2UgMjAwKTogcmFpc2UgUnVudGltZUVycm9yKCdVbmV4cGVjdGVkIGZpbGUgcmVzcG9uc2UnKQogICAgICAg'
    'IGlmIG9mZnNldCBhbmQgcmVzcG9uc2UuaGVhZGVycy5nZXQoJ0NvbnRlbnQtUmFuZ2UnKSE9ZidieXRlcyB7b2Zmc2V0fS17'
    'c2l6ZS0xfS97c2l6ZX0nOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ0ludmFsaWQgcmVzdW1lIHJhbmdlJykK'
    'ICAgICAgICB0b3RhbD1zaXplLW9mZnNldCBpZiBsaW1pdCBpcyBOb25lIGVsc2UgbWluKGxpbWl0LHNpemUtb2Zmc2V0KQog'
    'ICAgICAgIHdoaWxlIHJlY2VpdmVkPHRvdGFsOgogICAgICAgICAgICBibG9jaz1yZXNwb25zZS5yZWFkKG1pbig2NTUzNix0'
    'b3RhbC1yZWNlaXZlZCkpCiAgICAgICAgICAgIGlmIG5vdCBibG9jazogYnJlYWsKICAgICAgICAgICAgZGlnZXN0LnVwZGF0'
    'ZShibG9jayk7IHJlY2VpdmVkKz1sZW4oYmxvY2spCiAgICAgICAgaW50ZWdyaXR5PXJlY2VpdmVkPT10b3RhbCBhbmQgZGln'
    'ZXN0LmhleGRpZ2VzdCgpPT1leHBlY3RlZF9oYXNoKHRvdGFsLG9mZnNldCkKICAgICAgICBpZiBsaW1pdCBpcyBOb25lOgog'
    'ICAgICAgICAgICBpbnRlZ3JpdHk9aW50ZWdyaXR5IGFuZCByZXNwb25zZS5oZWFkZXJzLmdldCgnWC1Db250ZW50LVNIQTI1'
    'NicpPT1kaWdlc3QuaGV4ZGlnZXN0KCkKICAgIGVsYXBzZWQ9bWF4KHRpbWUubW9ub3RvbmljKCktc3RhcnQsMC4wMDEpCiAg'
    'ICByZXR1cm4geydraW5kJzonZG93bmxvYWQnLCdvayc6aW50ZWdyaXR5LCdpbnRlZ3JpdHknOmludGVncml0eSwnYnl0ZXMn'
    'OnJlY2VpdmVkLAogICAgICAgICAgICAnc2l6ZSc6c2l6ZSwnb2Zmc2V0JzpvZmZzZXQsJ2VsYXBzZWRfbXMnOnJvdW5kKGVs'
    'YXBzZWQqMTAwMCksCiAgICAgICAgICAgICdtYnBzX21pbGxpJzpyb3VuZChyZWNlaXZlZCo4L2VsYXBzZWQvMTAwMCl9CgoK'
    'ZGVmIHRyYW5zZmVyX3VwbG9hZChzaXplKToKICAgIGRhdGE9KFRFU1RfQkxPQ0sqKChzaXplK2xlbihURVNUX0JMT0NLKS0x'
    'KS8vbGVuKFRFU1RfQkxPQ0spKSlbOnNpemVdCiAgICBzdGFydD10aW1lLm1vbm90b25pYygpCiAgICB3aXRoIHRlc3RfcmVx'
    'dWVzdCgnL3VwbG9hZCcsZGF0YT1kYXRhLGhlYWRlcnM9eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9vY3RldC1zdHJl'
    'YW0nfSkgYXMgcmVzcG9uc2U6CiAgICAgICAgcmVwbHk9anNvbi5sb2FkcyhyZXNwb25zZS5yZWFkKDQwOTYpKQogICAgZWxh'
    'cHNlZD1tYXgodGltZS5tb25vdG9uaWMoKS1zdGFydCwwLjAwMSkKICAgIGludGVncml0eT1yZXBseS5nZXQoJ3JlY2VpdmVk'
    'X2J5dGVzJyk9PXNpemUgYW5kIHJlcGx5LmdldCgnc2hhMjU2Jyk9PWhhc2hsaWIuc2hhMjU2KGRhdGEpLmhleGRpZ2VzdCgp'
    'CiAgICByZXR1cm4geydraW5kJzondXBsb2FkJywnb2snOmludGVncml0eSwnaW50ZWdyaXR5JzppbnRlZ3JpdHksJ2J5dGVz'
    'JzpzaXplLAogICAgICAgICAgICAnZWxhcHNlZF9tcyc6cm91bmQoZWxhcHNlZCoxMDAwKSwnbWJwc19taWxsaSc6cm91bmQo'
    'c2l6ZSo4L2VsYXBzZWQvMTAwMCl9CgoKZGVmIHBpbmdfdGVzdChzaXplPTU2LCBjb3VudD0yMCk6CiAgICBjcD1jbWQoWydw'
    'aW5nJywnLW4nLCctTScsJ2RvJywnLXMnLHN0cihzaXplKSwnLWMnLHN0cihjb3VudCksJy1pJywnMC4yJywnLVcnLCcyJywn'
    'MTAuNzcuMC4xJ10sY2hlY2s9RmFsc2UsdGltZW91dD00NSkKICAgIHBhY2tldHM9cmUuc2VhcmNoKHInKFxkKykgcGFja2V0'
    'cyB0cmFuc21pdHRlZCwgKFxkKykgcmVjZWl2ZWQnLGNwLnN0ZG91dCkKICAgIHNlbnQscmVjZWl2ZWQ9KGludCh4KSBmb3Ig'
    'eCBpbiBwYWNrZXRzLmdyb3VwcygpKSBpZiBwYWNrZXRzIGVsc2UgKGNvdW50LDApCiAgICByb3c9eydraW5kJzoncGluZycs'
    'J29rJzpyZWNlaXZlZD09c2VudCwnc2VudCc6c2VudCwncmVjZWl2ZWQnOnJlY2VpdmVkLAogICAgICAgICAnbG9zc19taWxs'
    'aSc6cm91bmQoKHNlbnQtcmVjZWl2ZWQpKjEwMDAwMC9tYXgoc2VudCwxKSksJ3NpemUnOnNpemV9CiAgICBydHQ9cmUuc2Vh'
    'cmNoKHInPSAoW1xkLl0rKS8oW1xkLl0rKS8oW1xkLl0rKS8oW1xkLl0rKSBtcycsY3Auc3Rkb3V0KQogICAgaWYgcnR0Ogog'
    'ICAgICAgIHJvdy51cGRhdGUoe2tleTpyb3VuZChmbG9hdCh2YWx1ZSkqMTAwMCkgZm9yIGtleSx2YWx1ZSBpbiB6aXAoCiAg'
    'ICAgICAgICAgICgncnR0X21pbl91cycsJ3J0dF9hdmdfdXMnLCdydHRfbWF4X3VzJywncnR0X21kZXZfdXMnKSxydHQuZ3Jv'
    'dXBzKCkpfSkKICAgIHJldHVybiByb3cKCgpkZWYgdHJhbnNwb3J0X2NvdW50ZXJzKCk6CiAgICByZXN1bHQ9eydraW5kJzon'
    'Y291bnRlcnMnLCdvayc6VHJ1ZX0KICAgIHRyeToKICAgICAgICByYXc9c3dhbignLS1saXN0LXNhcycsJy0tcmF3Jykuc3Rk'
    'b3V0CiAgICAgICAgZm9yIHNvdXJjZSx0YXJnZXQgaW4gKCgnYnl0ZXMtaW4nLCdieXRlc19pbicpLCgnYnl0ZXMtb3V0Jywn'
    'Ynl0ZXNfb3V0JyksKCdwYWNrZXRzLWluJywncGFja2V0c19pbicpLCgncGFja2V0cy1vdXQnLCdwYWNrZXRzX291dCcpKToK'
    'ICAgICAgICAgICAgcmVzdWx0W3RhcmdldF09c3VtKGludCh4KSBmb3IgeCBpbiByZS5maW5kYWxsKHInXGInK3NvdXJjZSty'
    'Jz0oXGQrKScscmF3KSkKICAgICAgICBsaW5lcz1wYXRobGliLlBhdGgoJy9wcm9jL25ldC9zbm1wJykucmVhZF90ZXh0KCku'
    'c3BsaXRsaW5lcygpCiAgICAgICAgZm9yIGZpcnN0LHNlY29uZCBpbiB6aXAobGluZXMsbGluZXNbMTpdKToKICAgICAgICAg'
    'ICAgaWYgZmlyc3Quc3RhcnRzd2l0aCgnVGNwOicpIGFuZCBzZWNvbmQuc3RhcnRzd2l0aCgnVGNwOicpOgogICAgICAgICAg'
    'ICAgICAgdmFsdWVzPWRpY3QoemlwKGZpcnN0LnNwbGl0KClbMTpdLHNlY29uZC5zcGxpdCgpWzE6XSkpCiAgICAgICAgICAg'
    'ICAgICBpZiAnUmV0cmFuc1NlZ3MnIGluIHZhbHVlczoKICAgICAgICAgICAgICAgICAgICByZXN1bHRbJ3JldHJhbnNfc2Vn'
    'bWVudHMnXT1pbnQodmFsdWVzWydSZXRyYW5zU2VncyddKQogICAgICAgICAgICAgICAgICAgIHJlc3VsdFsnb3V0X3NlZ21l'
    'bnRzJ109aW50KHZhbHVlc1snT3V0U2VncyddKQogICAgICAgIGlmIGJhY2tlbmQoKT09J2tlcm5lbCc6CiAgICAgICAgICAg'
    'IHJlc3VsdFsneGZybV9lcnJvcnMnXT1zdW0oaW50KHguc3BsaXQoKVsxXSkgZm9yIHggaW4gcGF0aGxpYi5QYXRoKCcvcHJv'
    'Yy9uZXQveGZybV9zdGF0JykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJy'
    'b3IsUnVudGltZUVycm9yKTogcmVzdWx0WydvayddPUZhbHNlCiAgICByZXR1cm4gcmVzdWx0CgoKZGVmIGZsdXNoX3Rlc3Rf'
    'cmVwb3J0KCk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBvciBub3QgUEVORElOR19URVNULmV4aXN0'
    'cygpOiByZXR1cm4gRmFsc2UKICAgIGJvZHk9anNvbi5sb2FkcyhQRU5ESU5HX1RFU1QucmVhZF90ZXh0KCkpCiAgICBpZiBu'
    'b3QgZGVsaXZlcl9yZXBvcnQoYm9keSk6IHJldHVybiBGYWxzZQogICAgUEVORElOR19URVNULnVubGluayhtaXNzaW5nX29r'
    'PVRydWUpCiAgICB0ZXN0X3N0YXRlKHNlbnQ9VHJ1ZSxtZXNzYWdlPSfQotC10YHRgiDQt9Cw0LLQtdGA0YjRkdC9LiDQntGC'
    '0YfRkdGCINC00L7RgdGC0LDQstC70LXQvSDQvdCwIFN0YXJGaXZlLicpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBzdGFydF9n'
    'bG9iYWxfdGVzdCgpOgogICAgaWYgY21kKFsnc3lzdGVtY3RsJywnaXMtYWN0aXZlJyxURVNUX1VOSVRdLGNoZWNrPUZhbHNl'
    'KS5yZXR1cm5jb2RlPT0wOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB'
    '0YIg0YPQttC1INCy0YvQv9C+0LvQvdGP0LXRgtGB0Y8uJykKICAgIGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScp'
    'OiByYWlzZSBSdW50aW1lRXJyb3IoJ9CS0LrQu9GO0YfQuCDQstGA0LXQvNC10L3QvdGD0Y4g0LTQuNCw0LPQvdC+0YHRgtC4'
    '0LrRgyDQtNC70Y8g0L7RgtC/0YDQsNCy0LrQuCDRgNC10LfRg9C70YzRgtCw0YLQvtCyLicpCiAgICBpZiBub3QgY29ubmVj'
    'dGVkKCkgb3Igbm90IGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC/0L7QtNC6'
    '0LvRjtGH0LjRgdGMINC6IFN0YXJGaXZlLicpCiAgICBpZiBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgndGVzdF9hcGknKSE9'
    'MTogcmFpc2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQvtCx0L3QvtCy0LjRgtGMINGC0LXRgdGC0L7QstGL0Lkg'
    '0YHQtdGA0LLQuNGBIFN0YXJGaXZlLicpCiAgICBpZiBQRU5ESU5HX1RFU1QuZXhpc3RzKCkgYW5kIG5vdCBmbHVzaF90ZXN0'
    'X3JlcG9ydCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ce0LbQuNC00LDQtdGCINC+0YLQv9GA0LDQstC60Lgg0L/RgNC10LTR'
    'i9C00YPRidC40Lkg0L7RgtGH0ZHRgi4nKQogICAgdW5pdD0nJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZ2xvYmFs'
    'IFZQTiBzdGFiaWxpdHkgdGVzdApBZnRlcj1ldmdlbml1bS1pa2V2Mi5zZXJ2aWNlCltTZXJ2aWNlXQpUeXBlPWV4ZWMKRXhl'
    'Y1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtZ2xvYmFsLXRlc3QKU3RhbmRhcmRPdXRw'
    'dXQ9bnVsbApTdGFuZGFyZEVycm9yPW51bGwKVGltZW91dFN0b3BTZWM9MTIKUnVudGltZU1heFNlYz05MDAKUmVzdGFydD1u'
    'bwonJycKICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1RFU1RfVU5JVCx1bml0LDBvNjQ0'
    'KQogICAgY21kKFsnc3lzdGVtY3RsJywnZGFlbW9uLXJlbG9hZCddKQogICAgdGVzdF9zdGF0ZShwaGFzZT0ncnVubmluZycs'
    'cHJvZ3Jlc3M9MCxzZW50PUZhbHNlLHBhc3NlZD0wLGZhaWxlZD0wLGR1cmF0aW9uX3M9MCxtZXNzYWdlPSfQl9Cw0L/Rg9GB'
    '0Log0YLQtdGB0YLQsCcscnVuPW9zLnVyYW5kb20oMTIpLmhleCgpLHN0YXJ0ZWQ9aW50KHRpbWUudGltZSgpKSkKICAgIHRy'
    'eTogY21kKFsnc3lzdGVtY3RsJywnc3RhcnQnLFRFU1RfVU5JVF0pCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHRl'
    'c3Rfc3RhdGUocGhhc2U9J2ZhaWxlZCcsbWVzc2FnZT0n0J3QtSDRg9C00LDQu9C+0YHRjCDQt9Cw0L/Rg9GB0YLQuNGC0Ywg'
    '0YLQtdGB0YIuJyk7IHJhaXNlCiAgICBwcmludCgn0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIg0LfQsNC/0YPRidC1'
    '0L0g0LIg0YTQvtC90LUuINCY0L3RgtC10YDQvdC10YIg0L3QtdGB0LrQvtC70YzQutC+INGA0LDQtyDQv9GA0LXRgNCy0ZHR'
    'gtGB0Y87IGtpbGwgc3dpdGNoINC+0YHRgtCw0ZHRgtGB0Y8g0LLQutC70Y7Rh9GR0L3QvdGL0LwuJykKCgpjbGFzcyBUZXN0'
    'Q2FuY2VsbGVkKEV4Y2VwdGlvbik6IHBhc3MKCgpkZWYgcnVuX2dsb2JhbF90ZXN0KCk6CiAgICBpbXBvcnQgc2lnbmFsCiAg'
    'ICBmcm9tIGNvbmN1cnJlbnQuZnV0dXJlcyBpbXBvcnQgVGhyZWFkUG9vbEV4ZWN1dG9yCiAgICBkZWYgY2FuY2VsKCpfKTog'
    'cmFpc2UgVGVzdENhbmNlbGxlZCgpCiAgICBvbGQ9c2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSxjYW5jZWwpCiAgICBy'
    'ZWNvcmRzPVtdOyBvdXRjb21lPSdjb21wbGV0ZWQnOyBzdGFydGVkPXRpbWUubW9ub3RvbmljKCkKICAgIGRlZiBzdGFnZShw'
    'cm9ncmVzcyxtZXNzYWdlKTogdGVzdF9zdGF0ZShwaGFzZT0ncnVubmluZycscHJvZ3Jlc3M9cHJvZ3Jlc3MsbWVzc2FnZT1t'
    'ZXNzYWdlKQogICAgZGVmIG1lYXN1cmUoa2luZCxvcGVyYXRpb24sKipmaWVsZHMpOgogICAgICAgIGJlZm9yZT10aW1lLm1v'
    'bm90b25pYygpCiAgICAgICAgdHJ5OiByb3c9b3BlcmF0aW9uKCkKICAgICAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogcmFp'
    'c2UKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgZXJyb3I9J290aGVyJwogICAgICAgICAg'
    'ICBpZiBpc2luc3RhbmNlKGV4Yyx1cmxsaWIuZXJyb3IuSFRUUEVycm9yKTogZXJyb3I9J2h0dHAnCiAgICAgICAgICAgIGVs'
    'aWYgaXNpbnN0YW5jZShleGMsKFRpbWVvdXRFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSk6IGVycm9yPSd0aW1l'
    'b3V0JwogICAgICAgICAgICBlbGlmIGlzaW5zdGFuY2UoZXhjLHNzbC5TU0xFcnJvcik6IGVycm9yPSd0bHMnCiAgICAgICAg'
    'ICAgIGVsaWYgaXNpbnN0YW5jZShleGMsT1NFcnJvcik6IGVycm9yPSduZXR3b3JrJwogICAgICAgICAgICByb3c9eydraW5k'
    'JzpraW5kLCdvayc6RmFsc2UsJ2Vycm9yJzplcnJvcn0KICAgICAgICAgICAgaWYgaXNpbnN0YW5jZShleGMsdXJsbGliLmVy'
    'cm9yLkhUVFBFcnJvcik6IHJvd1snaHR0cF9zdGF0dXMnXT1leGMuY29kZQogICAgICAgIHJvdy5zZXRkZWZhdWx0KCdlbGFw'
    'c2VkX21zJyxyb3VuZCgodGltZS5tb25vdG9uaWMoKS1iZWZvcmUpKjEwMDApKQogICAgICAgIHJvd1snYXRfbXMnXT1yb3Vu'
    'ZCgodGltZS5tb25vdG9uaWMoKS1zdGFydGVkKSoxMDAwKQogICAgICAgIHJvdy51cGRhdGUoZmllbGRzKTsgcmVjb3Jkcy5h'
    'cHBlbmQocm93KTsgcmV0dXJuIHJvdwogICAgZGVmIHJlY29ubmVjdChyZXN0YXJ0PUZhbHNlKToKICAgICAgICBiZWZvcmU9'
    'dGltZS5tb25vdG9uaWMoKQogICAgICAgIGlmIHJlc3RhcnQ6CiAgICAgICAgICAgIGNhbmRpZGF0ZXM9c29ja2V0LmdldGFk'
    'ZHJpbmZvKCd5YW5kZXgucnUnLDQ0Myxzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgICAgIGFk'
    'ZHJlc3M9bmV4dCh4WzRdWzBdIGZvciB4IGluIGNhbmRpZGF0ZXMgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeFs0XVswXSku'
    'aXNfZ2xvYmFsKQogICAgICAgICAgICBjbWQoWydzeXN0ZW1jdGwnLCdzdG9wJyxVTklUXSkKICAgICAgICAgICAgbGVha2Vk'
    'PUZhbHNlCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChh'
    'ZGRyZXNzLDQ0MyksdGltZW91dD0yKTogbGVha2VkPVRydWUKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6IHBhc3MKICAg'
    'ICAgICAgICAgcmVjb3Jkcy5hcHBlbmQoeydraW5kJzonZ3VhcmQnLCdvayc6YWN0aXZlX2d1YXJkKCkgYW5kIG5vdCBsZWFr'
    'ZWR9KQogICAgICAgICAgICAjIE5ldmVyIHJlbW92ZSB0aGUgZ3VhcmQsIGV2ZW4gZHVyaW5nIGEgZGVsaWJlcmF0ZSBkYWVt'
    'b24gZmFpbHVyZS4KICAgICAgICAgICAgaWYgbm90IGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ0d1YXJk'
    'IG1pc3NpbmcnKQogICAgICAgICAgICBjbWQoWydzeXN0ZW1jdGwnLCdzdGFydCcsVU5JVF0pCiAgICAgICAgICAgIHdhaXRf'
    'dXNlcnNwYWNlKCkKICAgICAgICAgICAgc3dhbignLS1sb2FkLWNyZWRzJywnLS1maWxlJyxST09ULydjb25uZWN0aW9uLmNv'
    'bmYnKQogICAgICAgICAgICBzd2FuKCctLWxvYWQtY29ubnMnLCctLWZpbGUnLFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAg'
    'ICAgICAgZWxzZToKICAgICAgICAgICAgc3dhbignLS10ZXJtaW5hdGUnLCctLWlrZScsJ3N0YXJmaXZlJyxjaGVjaz1GYWxz'
    'ZSkKICAgICAgICBzd2FuKCctLWluaXRpYXRlJywnLS1jaGlsZCcsJ3N0YXJmaXZlLW5ldCcsdGltZW91dD01NSkKICAgICAg'
    'ICBnb29kPWNvbm5lY3RlZCgpIGFuZCBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3Rh'
    'cmZpdmUnCiAgICAgICAgcmV0dXJuIHsna2luZCc6J2RhZW1vbl9yZXN0YXJ0JyBpZiByZXN0YXJ0IGVsc2UgJ3JlY29ubmVj'
    'dCcsJ29rJzpnb29kLCdlbGFwc2VkX21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1iZWZvcmUpKjEwMDApfQogICAgZGVm'
    'IGNvbnRyb2woKToKICAgICAgICB3aXRoIHRlc3RfcmVxdWVzdCgnL2NvbnRyb2wnLHRpbWVvdXQ9NDUpIGFzIHJlc3BvbnNl'
    'OiBkYXRhPWpzb24ubG9hZHMocmVzcG9uc2UucmVhZCgxNjM4NCkpCiAgICAgICAgcmVjb3Jkcy5hcHBlbmQoeydraW5kJzon'
    'c2VydmVyX2NvbnRyb2wnLCdvayc6VHJ1ZSwqKmRhdGFbJ21ldHJpY3MnXX0pCiAgICAgICAgZm9yIHByb2JlIGluIGRhdGFb'
    'J3Byb2JlcyddOiByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidzZXJ2ZXJfY29udHJvbCcsKipwcm9iZX0pCiAgICAgICAgcmV0'
    'dXJuIHsna2luZCc6J2hlYWx0aCcsJ29rJzpUcnVlfQogICAgdHJ5OgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3An'
    'LE1PTklUT1JdLGNoZWNrPUZhbHNlKQogICAgICAgICMgVXNlIFJ1c3NpYW4gRE5TIGZvciB0aGlzIHRlc3QgZXZlbiBvbiBh'
    'IHNlc3Npb24gY3JlYXRlZCBieSBhbiBvbGRlciBjbGllbnQuCiAgICAgICAgaWYgbm90IChST09ULydyZXNvbHYtYmFja3Vw'
    'JykuZXhpc3RzKCkgYW5kIG5vdCAoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKTogc2V0X2RucygpCiAg'
    'ICAgICAgZWxpZiAoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKToKICAgICAgICAgICAgaW50ZXJmYWNl'
    'PWpzb24ubG9hZHMoKFJPT1QvJ3Jlc29sdmVkLWJhY2t1cC5qc29uJykucmVhZF90ZXh0KCkpWydpZmFjZSddCiAgICAgICAg'
    'ICAgIGNtZChbJ3Jlc29sdmVjdGwnLCdkbnMnLGludGVyZmFjZSwnNzcuODguOC44JywnNzcuODguOC4xJ10pCiAgICAgICAg'
    'ZWxzZToKICAgICAgICAgICAgcGF0aGxpYi5QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykud3JpdGVfdGV4dCgnbmFtZXNlcnZl'
    'ciA3Ny44OC44Ljhcbm5hbWVzZXJ2ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAg'
    'ICAgIHN0YWdlKDMsJ9Ca0L7QvdGC0YDQvtC70YzQvdGL0LUg0LfQsNC80LXRgNGLIFN0YXJGaXZlINC4INGA0L7RgdGB0LjQ'
    'udGB0LrQuNGFINGB0LXRgNCy0LjRgdC+0LInKQogICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsY29udHJvbCk7IHJlY29yZHMu'
    'YXBwZW5kKHRyYW5zcG9ydF9jb3VudGVycygpKQogICAgICAgIGZvciBkb21haW4gaW4gUlVfRE9NQUlOUzogbWVhc3VyZSgn'
    'cnVfcHJvYmUnLGxhbWJkYSBkPWRvbWFpbjp7J2tpbmQnOidydV9wcm9iZScsKipwcm9iZV9kb21haW4oZCl9KQogICAgICAg'
    'IHN0YWdlKDEyLCfQl9Cw0LTQtdGA0LbQutC4LCDQv9C+0YLQtdGA0Lgg0Lgg0YDQsNC30LzQtdGA0Ysg0L/QsNC60LXRgtC+'
    '0LInKQogICAgICAgIGZvciBzaXplIGluICg1NiwxMjAwLDEzNjApOiBtZWFzdXJlKCdwaW5nJyxsYW1iZGEgcz1zaXplOnBp'
    'bmdfdGVzdChzKSkKICAgICAgICBmb3IgYXR0ZW1wdCBpbiByYW5nZSgxMik6CiAgICAgICAgICAgIGJlZm9yZT10aW1lLm1v'
    'bm90b25pYygpCiAgICAgICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsbGFtYmRhOnsna2luZCc6J2hlYWx0aCcsJ29rJzplbmRw'
    'b2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUnfSkKICAgICAgICAgICAgdGltZS5z'
    'bGVlcCgwLjI1KQogICAgICAgIHN0YWdlKDI1LCfQodC60LDRh9C40LLQsNC90LjQtSDQuCDQvtGC0L/RgNCw0LLQutCwINGE'
    '0LDQudC70L7Qsjog0L/RgNC+0LLQtdGA0LrQsCBTSEEtMjU2JykKICAgICAgICBmb3Igc2l6ZSBpbiAoNjU1MzYsMTA0ODU3'
    'Niw4Mzg4NjA4LDMzNTU0NDMyKTogbWVhc3VyZSgnZG93bmxvYWQnLGxhbWJkYSBzPXNpemU6dHJhbnNmZXJfZG93bmxvYWQo'
    'cykpCiAgICAgICAgZm9yIHNpemUgaW4gKDUyNDI4OCw0MTk0MzA0KTogbWVhc3VyZSgndXBsb2FkJyxsYW1iZGEgcz1zaXpl'
    'OnRyYW5zZmVyX3VwbG9hZChzKSkKICAgICAgICBzdGFnZSg0MCwn0JTQvtC60LDRh9C60LAg0YTQsNC50LvQsCDQv9C+0YHQ'
    'u9C1INGA0LDQt9GA0YvQstCwINC4INC/0LXRgNC10L/QvtC00LrQu9GO0YfQtdC90LjRjycpCiAgICAgICAgbWVhc3VyZSgn'
    'cmVzdW1lJyxsYW1iZGE6eyoqdHJhbnNmZXJfZG93bmxvYWQoODM4ODYwOCxsaW1pdD0zMTQ1NzI4KSwna2luZCc6J3Jlc3Vt'
    'ZSd9KQogICAgICAgIG1lYXN1cmUoJ3JlY29ubmVjdCcscmVjb25uZWN0KQogICAgICAgIG1lYXN1cmUoJ3Jlc3VtZScsbGFt'
    'YmRhOnsqKnRyYW5zZmVyX2Rvd25sb2FkKDgzODg2MDgsb2Zmc2V0PTMxNDU3MjgpLCdraW5kJzoncmVzdW1lJ30pCiAgICAg'
    'ICAgc3RhZ2UoNTAsJ9Cf0LDRgNCw0LvQu9C10LvRjNC90LDRjyDQv9C10YDQtdC00LDRh9CwINCyINC+0LHQtSDRgdGC0L7R'
    'gNC+0L3RiycpCiAgICAgICAgd2l0aCBUaHJlYWRQb29sRXhlY3V0b3IobWF4X3dvcmtlcnM9MykgYXMgcG9vbDoKICAgICAg'
    'ICAgICAgZnV0dXJlcz1bcG9vbC5zdWJtaXQodHJhbnNmZXJfZG93bmxvYWQsODM4ODYwOCkscG9vbC5zdWJtaXQodHJhbnNm'
    'ZXJfZG93bmxvYWQsODM4ODYwOCkscG9vbC5zdWJtaXQodHJhbnNmZXJfdXBsb2FkLDQxOTQzMDQpXQogICAgICAgICAgICBm'
    'b3IgZnV0dXJlIGluIGZ1dHVyZXM6IG1lYXN1cmUoJ3BhcmFsbGVsJyxsYW1iZGEgZj1mdXR1cmU6eyoqZi5yZXN1bHQoKSwn'
    'a2luZCc6J3BhcmFsbGVsJ30pCiAgICAgICAgc3RhZ2UoNjIsJ9CU0LvQuNGC0LXQu9GM0L3QsNGPINC/0LXRgNC10LTQsNGH'
    '0LA6INC00L4gNjAg0YHQtdC60YPQvdC0IC8gNjQg0JzQuNCRJykKICAgICAgICBsb2FkX3N0YXJ0ZWQ9dGltZS5tb25vdG9u'
    'aWMoKTsgdW50aWw9bG9hZF9zdGFydGVkKzYwOyBjb3VudD0wCiAgICAgICAgd2hpbGUgdGltZS5tb25vdG9uaWMoKTx1bnRp'
    'bCBhbmQgY291bnQ8MTY6CiAgICAgICAgICAgIG1lYXN1cmUoJ2Rvd25sb2FkJyxsYW1iZGE6dHJhbnNmZXJfZG93bmxvYWQo'
    'NDE5NDMwNCkpOyBjb3VudCs9MQogICAgICAgICAgICBtZWFzdXJlKCdoZWFsdGgnLGxhbWJkYTp7J2tpbmQnOidoZWFsdGgn'
    'LCdvayc6ZW5kcG9pbnQoJy9oZWFsdGgnKS5nZXQoJ3NlcnZpY2UnKT09J2V2Z2VuaXVtLXN0YXJmaXZlJ30pCiAgICAgICAg'
    'ICAgIHRpbWUuc2xlZXAobWF4KDAsbG9hZF9zdGFydGVkK2NvdW50KjQtdGltZS5tb25vdG9uaWMoKSkpCiAgICAgICAgc3Rh'
    'Z2UoNzUsJ9Cf0YDQvtGB0YLQvtC5IDQ1INGB0LXQutGD0L3QtCDQuCDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1INCw'
    '0LrRgtC40LLQvdC+0YHRgtC4JykKICAgICAgICB0aW1lLnNsZWVwKDQ1KQogICAgICAgIG1lYXN1cmUoJ2lkbGUnLGxhbWJk'
    'YTp7J2tpbmQnOidpZGxlJywnb2snOmVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFy'
    'Zml2ZScsJ2VsYXBzZWRfbXMnOjQ1MDAwfSkKICAgICAgICBzdGFnZSg4Miwn0J/Rj9GC0Ywg0L/QvtCy0YLQvtGA0L3Ri9GF'
    'INC/0L7QtNC60LvRjtGH0LXQvdC40LknKQogICAgICAgIGZvciBhdHRlbXB0IGluIHJhbmdlKDUpOgogICAgICAgICAgICBt'
    'ZWFzdXJlKCdyZWNvbm5lY3QnLHJlY29ubmVjdCxhdHRlbXB0PWF0dGVtcHQrMSk7IHRpbWUuc2xlZXAoMSkKICAgICAgICBz'
    'dGFnZSg5Miwn0J/QtdGA0LXQt9Cw0L/Rg9GB0LogVlBOLdC00LXQvNC+0L3QsCDRgSDRgdC+0YXRgNCw0L3QtdC90LjQtdC8'
    'IGtpbGwgc3dpdGNoJykKICAgICAgICBtZWFzdXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkK'
    'ICAgICAgICByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidndWFyZCcsJ29rJzphY3RpdmVfZ3VhcmQoKX0pCiAgICAgICAgc3Rh'
    'Z2UoOTYsJ9CX0LDQutC70Y7Rh9C40YLQtdC70YzQvdGL0LUg0LfQsNC80LXRgNGLINC4INC+0YLQv9GA0LDQstC60LAg0L7R'
    'gtGH0ZHRgtCwJykKICAgICAgICBmb3IgZG9tYWluIGluIFJVX0RPTUFJTlM6IG1lYXN1cmUoJ3J1X3Byb2JlJyxsYW1iZGEg'
    'ZD1kb21haW46eydraW5kJzoncnVfcHJvYmUnLCoqcHJvYmVfZG9tYWluKGQpfSkKICAgICAgICBtZWFzdXJlKCdoZWFsdGgn'
    'LGNvbnRyb2wpOyByZWNvcmRzLmFwcGVuZCh0cmFuc3BvcnRfY291bnRlcnMoKSkKICAgICAgICBpZiBhbnkobm90IHguZ2V0'
    'KCdvaycpIGZvciB4IGluIHJlY29yZHMpOiBvdXRjb21lPSdmYWlsZWQnCiAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogb3V0'
    'Y29tZT0nY2FuY2VsbGVkJwogICAgZXhjZXB0IEV4Y2VwdGlvbjogb3V0Y29tZT0nZmFpbGVkJwogICAgZmluYWxseToKICAg'
    'ICAgICAjIFJlY292ZXIgb25seSBvdXIgZGFlbW9uL3Nlc3Npb24uIE5ldmVyIGRpc2FibGUgdGhlIGd1YXJkIG9yIHJlc3Rv'
    'cmUgZGlyZWN0IHRyYWZmaWMuCiAgICAgICAgaWYgb3V0Y29tZSE9J2NhbmNlbGxlZCcgYW5kIG5vdCBjb25uZWN0ZWQoKToK'
    'ICAgICAgICAgICAgdHJ5OiBtZWFzdXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkKICAgICAg'
    'ICAgICAgZXhjZXB0IEV4Y2VwdGlvbjogcGFzcwogICAgICAgIGJvZHk9eydzY2hlbWEnOjEsJ2V2ZW50JzonZ2xvYmFsX3Rl'
    'c3QnLCdtYW5hZ2VyJzonMC4yLjIzJywncnVuJzp0ZXN0X3N0YXR1cygpLmdldCgncnVuJyxvcy51cmFuZG9tKDEyKS5oZXgo'
    'KSksJ291dGNvbWUnOm91dGNvbWUsJ2R1cmF0aW9uX21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydGVkKSoxMDAw'
    'KSwncmVjb3Jkcyc6cmVjb3Jkc1s6MjU2XX0KICAgICAgICB3cml0ZShQRU5ESU5HX1RFU1QsanNvbi5kdW1wcyhib2R5KSkK'
    'ICAgICAgICB0ZXN0X3N0YXRlKHBoYXNlPW91dGNvbWUscHJvZ3Jlc3M9MTAwLHNlbnQ9RmFsc2UsZHVyYXRpb25fcz1yb3Vu'
    'ZCh0aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpLAogICAgICAgICAgICAgICAgICAgcGFzc2VkPXN1bShib29sKHguZ2V0KCdv'
    'aycpKSBmb3IgeCBpbiByZWNvcmRzKSxmYWlsZWQ9c3VtKG5vdCB4LmdldCgnb2snKSBmb3IgeCBpbiByZWNvcmRzKSwKICAg'
    'ICAgICAgICAgICAgICAgIG1lc3NhZ2U9J9Ce0YLRh9GR0YIg0YHQvtGF0YDQsNC90ZHQvS4g0J7QttC40LTQsNC10YIg0L7R'
    'gtC/0YDQsNCy0LrQuCDRh9C10YDQtdC3IFN0YXJGaXZlLicpCiAgICAgICAgdHJ5OiBmbHVzaF90ZXN0X3JlcG9ydCgpCiAg'
    'ICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoga2lja19kZWxpdmVyeSgpCiAgICAgICAgaWYgY29ubmVjdGVkKCkgYW5kIHN0b3Jl'
    'ZCgpLmdldCgndGVsZW1ldHJ5Jyk6CiAgICAgICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JyxNT05JVE9SXSxjaGVj'
    'az1GYWxzZSkKICAgICAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLG9sZCkK'
)

import types
starfive = types.ModuleType("starfive_experimental")
exec(compile(base64.b64decode(STARFIVE_EXPERIMENTAL_PY_B64), "starfive_experimental.py", "exec"), starfive.__dict__)

def _starfive_api():
    return types.SimpleNamespace(VPNError=VPNError, service_active=service_active)

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vpn", add_help=False)
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    pexp = sub.add_parser("experimental")
    pexp.add_argument("experimental_cmd", choices=["prepare", "import", "on", "off", "status", "report", "global-test", "cancel-test", "telemetry-on", "telemetry-off", "send-diagnostics", "backend-userspace", "backend-kernel"])
    pexp.add_argument("target", nargs="?", default="")
    sub.add_parser("internal-starfive-delivery")
    sub.add_parser("internal-starfive-monitor")
    sub.add_parser("internal-starfive-global-test")
    sub.add_parser("help")
    sub.add_parser("list")
    pon = sub.add_parser("on"); pon.add_argument("config", nargs="?")
    psw = sub.add_parser("switch"); psw.add_argument("config")
    sub.add_parser("off")
    sub.add_parser("toggle")
    pst = sub.add_parser("status"); pst.add_argument("--ip", action="store_true"); pst.add_argument("--json", action="store_true")
    sub.add_parser("test")
    pdiag = sub.add_parser("diagnostic")
    pdiagsub = pdiag.add_subparsers(dest="diagnostic_cmd")
    pdiagon = pdiagsub.add_parser("on"); pdiagon.add_argument("config", nargs="?")
    pdprobe = pdiagsub.add_parser("probe"); pdprobe.add_argument("config", nargs="?")
    pdiagsub.add_parser("off")
    pdiagsub.add_parser("status")
    pdiagsub.add_parser("report")
    pdiagmark = pdiagsub.add_parser("mark"); pdiagmark.add_argument("note", nargs="+")
    pr = sub.add_parser("route"); pr.add_argument("target")

    pd = sub.add_parser("direct")
    pdsub = pd.add_subparsers(dest="direct_cmd")
    pdsub.add_parser("list")
    pda = pdsub.add_parser("add"); pda.add_argument("target")
    pdr = pdsub.add_parser("remove"); pdr.add_argument("target")
    pdd = pdsub.add_parser("discover")
    pdd.add_argument("target")
    pdd.add_argument("--rounds", type=int, default=2)
    pdd.add_argument("--yes", action="store_true")
    pdf = pdsub.add_parser("refresh")
    pdf.add_argument("target", nargs="?")
    pdf.add_argument("--rounds", type=int, default=2)

    pa = sub.add_parser("app")
    pasub = pa.add_subparsers(dest="app_cmd")
    pasub.add_parser("list")
    paa = pasub.add_parser("add"); paa.add_argument("process")
    par = pasub.add_parser("remove"); par.add_argument("process")

    pw = sub.add_parser("widget")
    pwsub = pw.add_subparsers(dest="widget_cmd")
    pwsub.add_parser("install")
    pwsub.add_parser("remove")

    pg = sub.add_parser("gui")
    pgsub = pg.add_subparsers(dest="gui_cmd")
    pgsub.add_parser("install")
    pgsub.add_parser("remove")

    pui = sub.add_parser("ui")
    puisub = pui.add_subparsers(dest="ui_cmd")
    puisub.add_parser("state")
    puisub.add_parser("running")
    puia = puisub.add_parser("action")
    puia.add_argument("payload")

    pp = sub.add_parser("port")
    ppsub = pp.add_subparsers(dest="port_cmd")
    ppsub.add_parser("list")
    ppa = ppsub.add_parser("add")
    ppa.add_argument("port", type=int)
    ppa.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp", "both"])
    ppr = ppsub.add_parser("remove")
    ppr.add_argument("port", type=int)
    ppr.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp", "both"])

    pre = sub.add_parser("reload-rules")
    pl = sub.add_parser("logs"); pl.add_argument("-n", "--lines", type=int, default=100)
    pi = sub.add_parser("inspect"); pi.add_argument("config", nargs="?")
    sub.add_parser("doctor")
    sub.add_parser("core-update")
    sub.add_parser("update")
    sub.add_parser("version")
    sub.add_parser("internal-sync")
    sub.add_parser("internal-after-update")
    sub.add_parser("internal-diagnostic-monitor")
    sub.add_parser("manager-rollback")

    args = p.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    ensure_root()
    settings = load_settings()
    with operation_guard(args, settings):
        return dispatch_command(args, settings)


def dispatch_command(args, settings) -> int:
    ensure_direct_apps_file(settings)

    if args.cmd == "experimental":
        starfive.dispatch(_starfive_api(), settings, args.experimental_cmd, args.target)
        return 0
    if args.cmd == "internal-starfive-global-test":
        starfive.run_global_test()
        return 0
    if args.cmd == "internal-starfive-delivery":
        starfive.delivery_worker()
        return 0
    if args.cmd == "internal-starfive-monitor":
        starfive.monitor()
        return 0

    if args.cmd in {None, "help"}:
        print(f"""VPN Manager {MANAGER_VERSION} — Xray edition

  vpn experimental prepare|import FILE|on|off|status|report [DOMAIN]
  vpn experimental telemetry-on|telemetry-off
  vpn list
  vpn on [CONFIG]
  vpn switch CONFIG
  vpn off
  vpn toggle
  vpn status [--ip|--json]
  vpn test
  vpn diagnostic probe [CONFIG]  # без переключения сети
  vpn diagnostic on [CONFIG]
  vpn diagnostic status|report|off
  vpn route DOMAIN|IP
  vpn direct list
  vpn direct add DOMAIN|IP|CIDR
  vpn direct remove DOMAIN|IP|CIDR
  vpn direct discover DOMAIN [--yes] [--rounds N]
  vpn direct refresh [DOMAIN] [--rounds N]
  vpn app list
  vpn app add PROCESS|/absolute/path|/directory/
  vpn app remove PROCESS|/absolute/path|/directory/
  vpn widget install|remove
  vpn gui install|remove
  evgenium-network
  vpn port list
  vpn port add PORT [tcp|udp|both]
  vpn port remove PORT [tcp|udp|both]
  vpn reload-rules
  vpn inspect [CONFIG]
  vpn logs [-n 100]
  vpn doctor
  vpn update
  vpn core-update
  vpn version

Конфиги:
  {settings['config_dir']}

DIRECT domains:
  {settings['direct_sites']}

DIRECT networks:
  {settings['direct_networks']}

DIRECT applications:
  {settings['direct_apps']}

Local DIRECT SOCKS (only localhost, only while VPN is on):
  {DIRECT_SOCKS_HOST}:{DIRECT_SOCKS_PORT}
""")
        return 0

    if args.cmd == "list":
        paths = list_config_paths(settings)
        if not paths:
            print("(конфигов нет)")
        else:
            for x in paths:
                print(x.name)
        return 0

    if args.cmd in {"on", "switch"}:
        stop_diagnostic()
        activate(settings, choose_config(settings, args.config))
        return 0

    if args.cmd == "off":
        deactivate()
        return 0

    if args.cmd == "toggle":
        cmd_toggle(settings)
        return 0

    if args.cmd == "status":
        if args.json:
            cmd_status_json(settings)
        else:
            cmd_status(settings, args.ip)
        return 0

    if args.cmd == "test":
        cmd_test(settings)
        return 0

    if args.cmd == "diagnostic":
        if args.diagnostic_cmd == "probe":
            cmd_diagnostic_probe(settings, args.config)
            return 0
        if args.diagnostic_cmd == "on":
            cmd_diagnostic_on(settings, args.config)
            return 0
        if args.diagnostic_cmd == "off":
            stop_diagnostic()
            ok("Diagnostic mode OFF. VPN оставлен в текущем состоянии.")
            return 0
        if args.diagnostic_cmd in {None, "status"}:
            print(f"Diagnostic: {'ON' if diagnostic_service_active() else 'OFF'}")
            print(f"Log: {DIAGNOSTIC_LOG}")
            if DIAGNOSTIC_LOG.exists():
                print(f"Size: {DIAGNOSTIC_LOG.stat().st_size} bytes")
            return 0
        if args.diagnostic_cmd == "report":
            previous = DIAGNOSTIC_LOG.with_suffix(".previous.jsonl")
            for path in (previous, DIAGNOSTIC_LOG):
                if path.exists():
                    with path.open(encoding="utf-8", errors="replace") as fh:
                        shutil.copyfileobj(fh, sys.stdout)
            return 0
        if args.diagnostic_cmd == "mark":
            cmd_diagnostic_mark(args.note)
            return 0

    if args.cmd == "route":
        cmd_route(settings, args.target)
        return 0

    if args.cmd == "direct":
        if args.direct_cmd in {None, "list"}:
            cmd_direct_list(settings)
            return 0
        if args.direct_cmd == "add":
            cmd_direct_add(settings, args.target)
            return 0
        if args.direct_cmd == "remove":
            cmd_direct_remove(settings, args.target)
            return 0
        if args.direct_cmd == "discover":
            cmd_direct_discover(settings, args.target, args.rounds, args.yes)
            return 0
        if args.direct_cmd == "refresh":
            cmd_direct_refresh(settings, args.target, args.rounds)
            return 0

    if args.cmd == "app":
        if args.app_cmd in {None, "list"}:
            cmd_app_list(settings)
            return 0
        if args.app_cmd == "add":
            cmd_app_add(settings, args.process)
            return 0
        if args.app_cmd == "remove":
            cmd_app_remove(settings, args.process)
            return 0

    if args.cmd == "ui":
        if args.ui_cmd in {None, "state"}:
            cmd_ui_state(settings)
            return 0
        if args.ui_cmd == "running":
            cmd_ui_running(settings)
            return 0
        if args.ui_cmd == "action":
            cmd_ui_action(settings, args.payload)
            return 0

    if args.cmd == "gui":
        if args.gui_cmd in {None, "install"}:
            cmd_gui_install(settings)
            return 0
        if args.gui_cmd == "remove":
            cmd_gui_remove(settings)
            return 0

    if args.cmd == "widget":
        if args.widget_cmd in {None, "install"}:
            cmd_widget_install(settings)
            return 0
        if args.widget_cmd == "remove":
            cmd_widget_remove(settings)
            return 0

    if args.cmd == "port":
        if args.port_cmd in {None, "list"}:
            cmd_port_list(settings)
            return 0
        if args.port_cmd == "add":
            cmd_port_add(settings, args.port, args.proto)
            return 0
        if args.port_cmd == "remove":
            cmd_port_remove(settings, args.port, args.proto)
            return 0

    if args.cmd == "reload-rules":
        st = load_state()
        if not st.get("active"):
            ok("VPN выключен; правила применятся при следующем vpn on.")
            return 0
        activate(settings, choose_config(settings, st["active"]))
        return 0

    if args.cmd == "logs":
        print(journal_tail(max(1, min(args.lines, 1000))), end="")
        return 0

    if args.cmd == "inspect":
        inspect_profile(settings, args.config)
        return 0

    if args.cmd == "doctor":
        cmd_status(settings, False)
        print()
        for path in (
            "/usr/bin/nft", "/usr/bin/ip", "/usr/bin/curl",
            "/dev/net/tun", str(XRAY),
        ):
            print(f"{'OK' if pathlib.Path(path).exists() else 'MISSING'}  {path}")
        if RUNTIME_CONFIG.exists():
            try:
                test_config()
                print("OK  current Xray config")
            except VPNError as exc:
                print(f"FAIL current Xray config: {exc}")
        return 0

    if args.cmd == "core-update":
        core_update(settings)
        return 0

    if args.cmd == "update":
        manifest = str(settings.get("manager_manifest_url") or "")
        if manifest:
            manager_update_manifest(settings, manifest)
            # если обновился — exec, сюда не вернётся
        else:
            warn(
                "Источник обновлений VPN Manager пока не настроен; "
                "проверяю только совместимый Xray core."
            )
        core_update(settings)
        return 0

    if args.cmd == "version":
        print(f"VPN Manager {MANAGER_VERSION}")
        print(f"Safe Xray target: {SAFE_XRAY_VERSION}")
        if XRAY.exists():
            cp = run([XRAY, "version"], check=False, capture=True)
            print((cp.stdout or cp.stderr or "").strip())
        return 0

    if args.cmd == "internal-sync":
        sync_system_files()
        cmd_gui_install(settings)
        return 0

    if args.cmd == "internal-after-update":
        sync_system_files()
        cmd_gui_install(settings)
        if _widget_package_dir(settings).exists():
            cmd_widget_install(settings)
        # Refresh the active guard in-place so newly added policy features
        # (including the Waydroid switch) take effect without cycling the VPN.
        if service_active() and nft_exists():
            info("Обновляю активный kill switch и policy routing...")
            install_guard(settings)
        # Новый код сам решит свой safe core.
        core_update(settings)
        # The persistent lists were migrated above, but an already-running
        # Xray still has the previous in-memory routing graph. Rebuild it now
        # so a manager update really applies DIRECT apps/SOCKS without asking
        # the desktop user to cycle the VPN manually.
        st = load_state()
        if service_active() and st.get("active"):
            info("Применяю новые DIRECT-правила к активному VPN...")
            activate(settings, choose_config(settings, str(st["active"])))
        ok("Обновление manager полностью применено.")
        return 0

    if args.cmd == "internal-diagnostic-monitor":
        cmd_diagnostic_monitor(settings)
        return 0

    if args.cmd == "manager-rollback":
        manager_rollback()
        return 0

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VPNError as exc:
        print(color("ERROR:", "1;31"), str(exc), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nОтменено.", file=sys.stderr)
        raise SystemExit(130)
