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

MANAGER_VERSION = "0.2.22"

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
    "Version": "1.5"
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
    property string errorText: ""

    readonly property string statusCommand: "/usr/local/bin/vpn status --json"
    readonly property string toggleCommand: "/usr/local/bin/vpn toggle"
    readonly property string settingsCommand: "/usr/local/bin/evgenium-network --detach"

    Plasmoid.icon: "evgenium-network"
    toolTipMainText: "E-VPN"
    toolTipSubText: errorText.length > 0
        ? errorText
        : (busy ? "Переключаю VPN…" : (vpnActive ? "VPN включён" : "VPN выключен"))
    preferredRepresentation: fullRepresentation

    width: Kirigami.Units.gridUnit * 9
    height: Kirigami.Units.gridUnit * 2.7

    function requestStatus() {
        statusSource.connectSource(statusCommand)
    }

    function toggleVpn() {
        if (busy)
            return
        busy = true
        errorText = ""
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

    Plasma5Support.DataSource {
        id: statusSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== root.statusCommand)
                return
            const output = String(data["stdout"] || "").trim()
            if (output.length > 0) {
                try {
                    const state = JSON.parse(output)
                    root.vpnActive = Boolean(state.active)
                } catch (error) {
                    root.errorText = "Не удалось прочитать состояние VPN"
                }
            }
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
                    enabled: !root.busy
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
    'CmRlZiBydW5fdnBuKGFyZ3M6IGxpc3Rbc3RyXSwgdGltZW91dDogaW50ID0gMzYwKSAtPiBzdHI6CiAgICBjcCA9IHN1YnBy'
    'b2Nlc3MucnVuKAogICAgICAgIFtWUE4sICphcmdzXSwKICAgICAgICB0ZXh0PVRydWUsCiAgICAgICAgc3Rkb3V0PXN1YnBy'
    'b2Nlc3MuUElQRSwKICAgICAgICBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgIHRpbWVvdXQ9dGltZW91dCwKICAg'
    'ICAgICBjaGVjaz1GYWxzZSwKICAgICkKICAgIGlmIGNwLnJldHVybmNvZGUgIT0gMDoKICAgICAgICBkZXRhaWwgPSAoY3Au'
    'c3RkZXJyIG9yIGNwLnN0ZG91dCBvciBmImV4aXQge2NwLnJldHVybmNvZGV9Iikuc3RyaXAoKQogICAgICAgIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcihkZXRhaWwpCiAgICByZXR1cm4gKGNwLnN0ZG91dCBvciAiIikuc3RyaXAoKQoKCmRlZiBydW5fdnBuX2pz'
    'b24oYXJnczogbGlzdFtzdHJdKSAtPiBkaWN0OgogICAgcmF3ID0gcnVuX3ZwbihhcmdzKQogICAgdHJ5OgogICAgICAgIGRh'
    'dGEgPSBqc29uLmxvYWRzKHJhdykKICAgIGV4Y2VwdCBqc29uLkpTT05EZWNvZGVFcnJvciBhcyBleGM6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKGYiVlBOIE1hbmFnZXIg0LLQtdGA0L3Rg9C7INC90LXQutC+0YDRgNC10LrRgtC90YvQuSBKU09O'
    'OiB7ZXhjfSIpIGZyb20gZXhjCiAgICBpZiBub3QgaXNpbnN0YW5jZShkYXRhLCBkaWN0KToKICAgICAgICByYWlzZSBSdW50'
    'aW1lRXJyb3IoIlZQTiBNYW5hZ2VyINCy0LXRgNC90YPQuyDQvdC10L7QttC40LTQsNC90L3Ri9C5INC+0YLQstC10YIuIikK'
    'ICAgIHJldHVybiBkYXRhCgoKZGVmIGVuY29kZV91aV9wYXlsb2FkKHBheWxvYWQ6IGRpY3QpIC0+IHN0cjoKICAgIHJhdyA9'
    'IGpzb24uZHVtcHMocGF5bG9hZCwgZW5zdXJlX2FzY2lpPUZhbHNlLCBzZXBhcmF0b3JzPSgiLCIsICI6IikpCiAgICBxdW90'
    'ZWQgPSB1cmxsaWIucGFyc2UucXVvdGUocmF3LCBzYWZlPSIiKQogICAgcmV0dXJuIGJhc2U2NC5iNjRlbmNvZGUocXVvdGVk'
    'LmVuY29kZSgiYXNjaWkiKSkuZGVjb2RlKCJhc2NpaSIpCgoKY2xhc3MgQXBpU2VydmVyKGh0dHAuc2VydmVyLlRocmVhZGlu'
    'Z0hUVFBTZXJ2ZXIpOgogICAgZGFlbW9uX3RocmVhZHMgPSBUcnVlCiAgICBhbGxvd19yZXVzZV9hZGRyZXNzID0gRmFsc2UK'
    'CiAgICBkZWYgX19pbml0X18oc2VsZiwgYWRkcmVzcywgaGFuZGxlciwgdG9rZW46IHN0cik6CiAgICAgICAgc3VwZXIoKS5f'
    'X2luaXRfXyhhZGRyZXNzLCBoYW5kbGVyKQogICAgICAgIHNlbGYudG9rZW4gPSB0b2tlbgoKCmNsYXNzIEhhbmRsZXIoaHR0'
    'cC5zZXJ2ZXIuQmFzZUhUVFBSZXF1ZXN0SGFuZGxlcik6CiAgICBzZXJ2ZXI6IEFwaVNlcnZlcgoKICAgIGRlZiBsb2dfbWVz'
    'c2FnZShzZWxmLCBfZm9ybWF0OiBzdHIsICpfYXJncykgLT4gTm9uZToKICAgICAgICByZXR1cm4KCiAgICBkZWYgX2hlYWRl'
    'cnMoc2VsZiwgc3RhdHVzOiBpbnQgPSAyMDAsIGNvbnRlbnRfdHlwZTogc3RyID0gImFwcGxpY2F0aW9uL2pzb247IGNoYXJz'
    'ZXQ9dXRmLTgiKSAtPiBOb25lOgogICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZShzdGF0dXMpCiAgICAgICAgc2VsZi5zZW5k'
    'X2hlYWRlcigiQ29udGVudC1UeXBlIiwgY29udGVudF90eXBlKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNhY2hlLUNv'
    'bnRyb2wiLCAibm8tc3RvcmUiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdp'
    'biIsICIqIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzIiwgIkNvbnRl'
    'bnQtVHlwZSwgWC1Fdmdlbml1bS1Ub2tlbiIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxs'
    'b3ctTWV0aG9kcyIsICJHRVQsIFBPU1QsIE9QVElPTlMiKQogICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQoKICAgIGRlZiBf'
    'anNvbihzZWxmLCBwYXlsb2FkOiBkaWN0LCBzdGF0dXM6IGludCA9IDIwMCkgLT4gTm9uZToKICAgICAgICBkYXRhID0ganNv'
    'bi5kdW1wcyhwYXlsb2FkLCBlbnN1cmVfYXNjaWk9RmFsc2UsIHNlcGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCJ1dGYt'
    'OCIpCiAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKHN0YXR1cykKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50'
    'LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29u'
    'dGVudC1MZW5ndGgiLCBzdHIobGVuKGRhdGEpKSkKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDYWNoZS1Db250cm9sIiwg'
    'Im5vLXN0b3JlIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iLCAiKiIp'
    'CiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyIsICJDb250ZW50LVR5cGUs'
    'IFgtRXZnZW5pdW0tVG9rZW4iKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhv'
    'ZHMiLCAiR0VULCBQT1NULCBPUFRJT05TIikKICAgICAgICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICBzZWxmLndmaWxl'
    'LndyaXRlKGRhdGEpCgogICAgZGVmIF9hdXRob3JpemVkKHNlbGYpIC0+IGJvb2w6CiAgICAgICAgcmV0dXJuIHNlY3JldHMu'
    'Y29tcGFyZV9kaWdlc3QoCiAgICAgICAgICAgIHNlbGYuaGVhZGVycy5nZXQoIlgtRXZnZW5pdW0tVG9rZW4iLCAiIiksCiAg'
    'ICAgICAgICAgIHNlbGYuc2VydmVyLnRva2VuLAogICAgICAgICkKCiAgICBkZWYgX3JlcXVpcmVfYXV0aChzZWxmKSAtPiBi'
    'b29sOgogICAgICAgIGlmIHNlbGYuX2F1dGhvcml6ZWQoKToKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBzZWxm'
    'Ll9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogInVuYXV0aG9yaXplZCJ9LCA0MDMpCiAgICAgICAgcmV0dXJuIEZhbHNl'
    'CgogICAgZGVmIF9yZWFkX2pzb24oc2VsZikgLT4gZGljdDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGxlbmd0aCA9IGlu'
    'dChzZWxmLmhlYWRlcnMuZ2V0KCJDb250ZW50LUxlbmd0aCIsICIwIikpCiAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3IgYXMg'
    'ZXhjOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LXQutC+0YDRgNC10LrRgtC90YvQuSBDb250ZW50LUxl'
    'bmd0aC4iKSBmcm9tIGV4YwogICAgICAgIGlmIGxlbmd0aCA8IDAgb3IgbGVuZ3RoID4gTUFYX0JPRFk6CiAgICAgICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcigi0KHQu9C40YjQutC+0Lwg0LHQvtC70YzRiNC+0Lkg0LfQsNC/0YDQvtGBLiIpCiAgICAg'
    'ICAgcmF3ID0gc2VsZi5yZmlsZS5yZWFkKGxlbmd0aCkKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBheWxvYWQgPSBqc29u'
    'LmxvYWRzKHJhdy5kZWNvZGUoInV0Zi04IikgaWYgcmF3IGVsc2UgInt9IikKICAgICAgICBleGNlcHQgKFVuaWNvZGVEZWNv'
    'ZGVFcnJvciwganNvbi5KU09ORGVjb2RlRXJyb3IpIGFzIGV4YzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGYi'
    '0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5IEpTT046IHtleGN9IikgZnJvbSBleGMKICAgICAgICBpZiBub3QgaXNpbnN0YW5j'
    'ZShwYXlsb2FkLCBkaWN0KToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQntC20LjQtNCw0LvRgdGPIEpTT04g'
    'b2JqZWN0LiIpCiAgICAgICAgcmV0dXJuIHBheWxvYWQKCiAgICBkZWYgZG9fT1BUSU9OUyhzZWxmKSAtPiBOb25lOgogICAg'
    'ICAgIHNlbGYuX2hlYWRlcnMoMjA0KQoKICAgIGRlZiBkb19HRVQoc2VsZikgLT4gTm9uZToKICAgICAgICBpZiBub3Qgc2Vs'
    'Zi5fcmVxdWlyZV9hdXRoKCk6CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgc2VsZi5w'
    'YXRoID09ICIvYXBpL3N0YXRlIjoKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IFRydWUsICJzdGF0ZSI6IHJ1'
    'bl92cG5fanNvbihbInVpIiwgInN0YXRlIl0pfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBzZWxm'
    'LnBhdGggPT0gIi9hcGkvcnVubmluZyI6CiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAicnVubmlu'
    'ZyI6IHJ1bl92cG5fanNvbihbInVpIiwgInJ1bm5pbmciXSl9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAg'
    'IGlmIHNlbGYucGF0aCA9PSAiL2FwaS9oZWFsdGgiOgogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwg'
    'ImFwcCI6IEFQUF9OQU1FfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBG'
    'YWxzZSwgImVycm9yIjogIm5vdCBmb3VuZCJ9LCA0MDQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAg'
    'ICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAiZXJyb3IiOiBzdHIoZXhjKX0sIDUwMCkKCiAgICBkZWYgZG9fUE9T'
    'VChzZWxmKSAtPiBOb25lOgogICAgICAgIGlmIG5vdCBzZWxmLl9yZXF1aXJlX2F1dGgoKToKICAgICAgICAgICAgcmV0dXJu'
    'CiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYXlsb2FkID0gc2VsZi5fcmVhZF9qc29uKCkKICAgICAgICAgICAgaWYgc2Vs'
    'Zi5wYXRoID09ICIvYXBpL2FjdGlvbiI6CiAgICAgICAgICAgICAgICB0b2tlbiA9IGVuY29kZV91aV9wYXlsb2FkKHBheWxv'
    'YWQpCiAgICAgICAgICAgICAgICBvdXRwdXQgPSBydW5fdnBuKFsidWkiLCAiYWN0aW9uIiwgdG9rZW5dKQogICAgICAgICAg'
    'ICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgIm91dHB1dCI6IG91dHB1dH0pCiAgICAgICAgICAgICAgICByZXR1cm4K'
    'ICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL3RvZ2dsZSI6CiAgICAgICAgICAgICAgICBvdXRwdXQgPSBydW5f'
    'dnBuKFsidG9nZ2xlIl0pCiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAib3V0cHV0Ijogb3V0cHV0'
    'LCAic3RhdGUiOiBydW5fdnBuX2pzb24oWyJ1aSIsICJzdGF0ZSJdKX0pCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAg'
    'ICAgICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6ICJub3QgZm91bmQifSwgNDA0KQogICAgICAgIGV4Y2Vw'
    'dCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogc3RyKGV4'
    'Yyl9LCA1MDApCgoKZGVmIHN0YXRlX2xvZ19wYXRoKCkgLT4gcGF0aGxpYi5QYXRoOgogICAgcm9vdCA9IHBhdGhsaWIuUGF0'
    'aChvcy5lbnZpcm9uLmdldCgiWERHX1NUQVRFX0hPTUUiLCBwYXRobGliLlBhdGguaG9tZSgpIC8gIi5sb2NhbCIgLyAic3Rh'
    'dGUiKSkKICAgIHBhdGggPSByb290IC8gImV2Z2VuaXVtLW5ldHdvcmsiIC8gImd1aS5sb2ciCiAgICBwYXRoLnBhcmVudC5t'
    'a2RpcihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICByZXR1cm4gcGF0aAoKCmRlZiBsYXVuY2hfZGV0YWNoZWQo'
    'KSAtPiBpbnQ6CiAgICBpZiBub3QgUU1MX0ZJTEUuaXNfZmlsZSgpOgogICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC1'
    '0L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7UU1MX0ZJTEV9IiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAg'
    'ICBpZiBub3QgZmluZF9xbWxfcnVudGltZSgpOgogICAgICAgIHByaW50KCLQndC1INC90LDQudC00LXQvSBRdCA2IFFNTCBy'
    'dW50aW1lIChBcmNoOiBxdDYtZGVjbGFyYXRpdmU7IEZlZG9yYTogcXQ2LXF0ZGVjbGFyYXRpdmUtZGV2ZWwpLiIsIGZpbGU9'
    'c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQogICAgbG9nX3BhdGggPSBzdGF0ZV9sb2dfcGF0aCgpCiAgICB3aXRoIGxv'
    'Z19wYXRoLm9wZW4oImFiIiwgYnVmZmVyaW5nPTApIGFzIGxvZzoKICAgICAgICBzdWJwcm9jZXNzLlBvcGVuKAogICAgICAg'
    'ICAgICBbc3lzLmV4ZWN1dGFibGUsIHN0cihwYXRobGliLlBhdGgoX19maWxlX18pLnJlc29sdmUoKSldLAogICAgICAgICAg'
    'ICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgIHN0ZG91dD1sb2csCiAgICAgICAgICAgIHN0ZGVycj1s'
    'b2csCiAgICAgICAgICAgIHN0YXJ0X25ld19zZXNzaW9uPVRydWUsCiAgICAgICAgICAgIGNsb3NlX2Zkcz1UcnVlLAogICAg'
    'ICAgICkKICAgIHJldHVybiAwCgoKZGVmIHJ1bl9ndWkoKSAtPiBpbnQ6CiAgICBxbWwgPSBmaW5kX3FtbF9ydW50aW1lKCkK'
    'ICAgIGlmIG5vdCBxbWw6CiAgICAgICAgcHJpbnQoItCd0LUg0L3QsNC50LTQtdC9IFF0IDYgUU1MIHJ1bnRpbWUgKEFyY2g6'
    'IHF0Ni1kZWNsYXJhdGl2ZTsgRmVkb3JhOiBxdDYtcXRkZWNsYXJhdGl2ZS1kZXZlbCkuIiwgZmlsZT1zeXMuc3RkZXJyKQog'
    'ICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgUU1MX0ZJTEUuaXNfZmlsZSgpOgogICAgICAgIHByaW50KGYi0J3QtSDQvdCw'
    '0LnQtNC10L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7UU1MX0ZJTEV9IiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVy'
    'biAxCgogICAgdG9rZW4gPSBzZWNyZXRzLnRva2VuX3VybHNhZmUoMzIpCiAgICBzZXJ2ZXIgPSBBcGlTZXJ2ZXIoKCIxMjcu'
    'MC4wLjEiLCAwKSwgSGFuZGxlciwgdG9rZW4pCiAgICBwb3J0ID0gaW50KHNlcnZlci5zZXJ2ZXJfYWRkcmVzc1sxXSkKICAg'
    'IHRocmVhZCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXNlcnZlci5zZXJ2ZV9mb3JldmVyLCBuYW1lPSJldmdlbml1bS1n'
    'dWktYXBpIiwgZGFlbW9uPVRydWUpCiAgICB0aHJlYWQuc3RhcnQoKQoKICAgIGVudiA9IG9zLmVudmlyb24uY29weSgpCiAg'
    'ICBlbnYuc2V0ZGVmYXVsdCgiUVRfUVVJQ0tfQ09OVFJPTFNfU1RZTEUiLCAiQmFzaWMiKQogICAgZW52LnNldGRlZmF1bHQo'
    'IlFNTF9ESVNBQkxFX0RJU0tfQ0FDSEUiLCAiMCIpCgogICAgdHJ5OgogICAgICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oCiAg'
    'ICAgICAgICAgIFtxbWwsIHN0cihRTUxfRklMRSksICItLSIsIHN0cihwb3J0KSwgdG9rZW5dLAogICAgICAgICAgICBlbnY9'
    'ZW52LAogICAgICAgICAgICBjaGVjaz1GYWxzZSwKICAgICAgICApCiAgICAgICAgcmV0dXJuIGludChjcC5yZXR1cm5jb2Rl'
    'KQogICAgZmluYWxseToKICAgICAgICBzZXJ2ZXIuc2h1dGRvd24oKQogICAgICAgIHNlcnZlci5zZXJ2ZXJfY2xvc2UoKQog'
    'ICAgICAgIHRocmVhZC5qb2luKHRpbWVvdXQ9MikKCgpkZWYgc2VsZl90ZXN0KCkgLT4gaW50OgogICAgc2FtcGxlID0geyJh'
    'Y3Rpb24iOiAiYXBwX2FkZCIsICJ0YXJnZXQiOiAiL29wdC9leGFtcGxlL2Jpbi9hcHAifQogICAgdG9rZW4gPSBlbmNvZGVf'
    'dWlfcGF5bG9hZChzYW1wbGUpCiAgICBkZWNvZGVkID0gdXJsbGliLnBhcnNlLnVucXVvdGUoYmFzZTY0LmI2NGRlY29kZSh0'
    'b2tlbikuZGVjb2RlKCJhc2NpaSIpKQogICAgYXNzZXJ0IGpzb24ubG9hZHMoZGVjb2RlZCkgPT0gc2FtcGxlCiAgICBhc3Nl'
    'cnQgTUFYX0JPRFkgPD0gMTAyNCAqIDEwMjQKICAgIHFtbCA9IEhFUkUgLyAiZXZnZW5pdW1fZ3VpLnFtbCIKICAgIGlmIHFt'
    'bC5leGlzdHMoKToKICAgICAgICB0ZXh0ID0gcW1sLnJlYWRfdGV4dChlbmNvZGluZz0idXRmLTgiKQogICAgICAgIGFzc2Vy'
    'dCAiRXZnZW5pdW0gTmV0d29yayIgaW4gdGV4dAogICAgICAgIGFzc2VydCAiL2FwaS9ydW5uaW5nIiBpbiB0ZXh0CiAgICAg'
    'ICAgYXNzZXJ0ICIvYXBpL2FjdGlvbiIgaW4gdGV4dAogICAgcHJpbnQoImV2Z2VuaXVtLWd1aSBzZWxmLXRlc3QgT0siKQog'
    'ICAgcmV0dXJuIDAKCgpkZWYgbWFpbigpIC0+IGludDoKICAgIGlmICItLXNlbGYtdGVzdCIgaW4gc3lzLmFyZ3Y6CiAgICAg'
    'ICAgcmV0dXJuIHNlbGZfdGVzdCgpCiAgICBpZiAiLS1kZXRhY2giIGluIHN5cy5hcmd2OgogICAgICAgIHJldHVybiBsYXVu'
    'Y2hfZGV0YWNoZWQoKQogICAgcmV0dXJuIHJ1bl9ndWkoKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICByYWlz'
    'ZSBTeXN0ZW1FeGl0KG1haW4oKSkK'
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
    'ZXh0OiAiIgogICAgcHJvcGVydHkgdmFyIHN0YXRlOiAoe30pCiAgICBwcm9wZXJ0eSB2YXIgcnVubmluZ0FwcHM6IFtdCiAg'
    'ICByZWFkb25seSBwcm9wZXJ0eSB2YXIgZXhwZXJpbWVudDogcm9vdC5zdGF0ZS5leHBlcmltZW50YWwgfHwgKHt9KQoKICAg'
    'IHJlYWRvbmx5IHByb3BlcnR5IHZhciBhcmdzOiBRdC5hcHBsaWNhdGlvbi5hcmd1bWVudHMKICAgIHJlYWRvbmx5IHByb3Bl'
    'cnR5IHN0cmluZyBhcGlUb2tlbjogYXJncy5sZW5ndGggPj0gMiA/IFN0cmluZyhhcmdzW2FyZ3MubGVuZ3RoIC0gMV0pIDog'
    'IiIKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBhcGlQb3J0OiBhcmdzLmxlbmd0aCA+PSAzID8gU3RyaW5nKGFyZ3Nb'
    'YXJncy5sZW5ndGggLSAyXSkgOiAiMCIKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBhcGlCYXNlOiAiaHR0cDovLzEy'
    'Ny4wLjAuMToiICsgYXBpUG9ydAoKICAgIGZ1bmN0aW9uIHBhcnNlUmVwbHkoeGhyLCBjYWxsYmFjaykgewogICAgICAgIGxl'
    'dCBwYXlsb2FkID0gbnVsbAogICAgICAgIHRyeSB7CiAgICAgICAgICAgIHBheWxvYWQgPSBKU09OLnBhcnNlKFN0cmluZyh4'
    'aHIucmVzcG9uc2VUZXh0IHx8ICJ7fSIpKQogICAgICAgIH0gY2F0Y2ggKGUpIHsKICAgICAgICAgICAgZXJyb3JUZXh0ID0g'
    'ItCd0LUg0YPQtNCw0LvQvtGB0Ywg0YDQsNC30L7QsdGA0LDRgtGMINC+0YLQstC10YIg0LvQvtC60LDQu9GM0L3QvtCz0L4g'
    'QVBJIgogICAgICAgICAgICBidXN5ID0gZmFsc2UKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgfQogICAgICAgIGlmICh4'
    'aHIuc3RhdHVzIDwgMjAwIHx8IHhoci5zdGF0dXMgPj0gMzAwIHx8ICFwYXlsb2FkLm9rKSB7CiAgICAgICAgICAgIGVycm9y'
    'VGV4dCA9IFN0cmluZyhwYXlsb2FkLmVycm9yIHx8ICgiSFRUUCAiICsgeGhyLnN0YXR1cykpCiAgICAgICAgICAgIGJ1c3kg'
    'PSBmYWxzZQogICAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgZXJyb3JUZXh0ID0gIiIKICAgICAgICBpZiAo'
    'Y2FsbGJhY2spCiAgICAgICAgICAgIGNhbGxiYWNrKHBheWxvYWQpCiAgICB9CgogICAgZnVuY3Rpb24gYXBpKG1ldGhvZCwg'
    'cGF0aCwgYm9keSwgY2FsbGJhY2spIHsKICAgICAgICBjb25zdCB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKQogICAgICAg'
    'IHhoci5vcGVuKG1ldGhvZCwgYXBpQmFzZSArIHBhdGgsIHRydWUpCiAgICAgICAgeGhyLnNldFJlcXVlc3RIZWFkZXIoIlgt'
    'RXZnZW5pdW0tVG9rZW4iLCBhcGlUb2tlbikKICAgICAgICBpZiAoYm9keSAhPT0gbnVsbCkKICAgICAgICAgICAgeGhyLnNl'
    'dFJlcXVlc3RIZWFkZXIoIkNvbnRlbnQtVHlwZSIsICJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PXV0Zi04IikKICAgICAg'
    'ICB4aHIub25yZWFkeXN0YXRlY2hhbmdlID0gZnVuY3Rpb24oKSB7CiAgICAgICAgICAgIGlmICh4aHIucmVhZHlTdGF0ZSA9'
    'PT0gWE1MSHR0cFJlcXVlc3QuRE9ORSkKICAgICAgICAgICAgICAgIHJvb3QucGFyc2VSZXBseSh4aHIsIGNhbGxiYWNrKQog'
    'ICAgICAgIH0KICAgICAgICB4aHIuc2VuZChib2R5ID09PSBudWxsID8gbnVsbCA6IEpTT04uc3RyaW5naWZ5KGJvZHkpKQog'
    'ICAgfQoKICAgIGZ1bmN0aW9uIHJlZnJlc2hTdGF0ZSgpIHsKICAgICAgICBhcGkoIkdFVCIsICIvYXBpL3N0YXRlIiwgbnVs'
    'bCwgZnVuY3Rpb24ocGF5bG9hZCkgewogICAgICAgICAgICByb290LnN0YXRlID0gcGF5bG9hZC5zdGF0ZSB8fCAoe30pCiAg'
    'ICAgICAgfSkKICAgIH0KCiAgICBmdW5jdGlvbiByZWZyZXNoUnVubmluZygpIHsKICAgICAgICBhcGkoIkdFVCIsICIvYXBp'
    'L3J1bm5pbmciLCBudWxsLCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3QucnVubmluZ0FwcHMgPSAocGF5'
    'bG9hZC5ydW5uaW5nICYmIHBheWxvYWQucnVubmluZy5hcHBsaWNhdGlvbnMpIHx8IFtdCiAgICAgICAgfSkKICAgIH0KCiAg'
    'ICBmdW5jdGlvbiBhY3Rpb24ocGF5bG9hZCkgewogICAgICAgIGlmIChidXN5KQogICAgICAgICAgICByZXR1cm4KICAgICAg'
    'ICBidXN5ID0gdHJ1ZQogICAgICAgIGFwaSgiUE9TVCIsICIvYXBpL2FjdGlvbiIsIHBheWxvYWQsIGZ1bmN0aW9uKF9yZXBs'
    'eSkgewogICAgICAgICAgICByb290LmJ1c3kgPSBmYWxzZQogICAgICAgICAgICByb290LnJlZnJlc2hTdGF0ZSgpCiAgICAg'
    'ICAgICAgIHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gdG9nZ2xlVnBuKCkg'
    'ewogICAgICAgIGlmIChidXN5KQogICAgICAgICAgICByZXR1cm4KICAgICAgICBidXN5ID0gdHJ1ZQogICAgICAgIGFwaSgi'
    'UE9TVCIsICIvYXBpL3RvZ2dsZSIsIHt9LCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZh'
    'bHNlCiAgICAgICAgICAgIHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9KQogICAgfQoKICAg'
    'IGZ1bmN0aW9uIGZpbHRlcmVkUnVubmluZygpIHsKICAgICAgICBjb25zdCBuZWVkbGUgPSBhcHBTZWFyY2gudGV4dC50cmlt'
    'KCkudG9Mb3dlckNhc2UoKQogICAgICAgIGlmICghbmVlZGxlLmxlbmd0aCkKICAgICAgICAgICAgcmV0dXJuIHJ1bm5pbmdB'
    'cHBzCiAgICAgICAgcmV0dXJuIHJ1bm5pbmdBcHBzLmZpbHRlcihmdW5jdGlvbihhcHApIHsKICAgICAgICAgICAgcmV0dXJu'
    'IFN0cmluZyhhcHAubmFtZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVkbGUpCiAgICAgICAgICAgICAgICB8'
    'fCBTdHJpbmcoYXBwLmV4ZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVkbGUpCiAgICAgICAgfSkKICAgIH0K'
    'CiAgICBDb21wb25lbnQub25Db21wbGV0ZWQ6IHsKICAgICAgICByZWZyZXNoU3RhdGUoKQogICAgICAgIHJlZnJlc2hSdW5u'
    'aW5nKCkKICAgIH0KCiAgICBUaW1lciB7CiAgICAgICAgaW50ZXJ2YWw6IDI1MDAKICAgICAgICByZXBlYXQ6IHRydWUKICAg'
    'ICAgICBydW5uaW5nOiB0cnVlCiAgICAgICAgb25UcmlnZ2VyZWQ6IHJvb3QucmVmcmVzaFN0YXRlKCkKICAgIH0KCiAgICBj'
    'b21wb25lbnQgRmxhdEJ1dHRvbjogUmVjdGFuZ2xlIHsKICAgICAgICBpZDogZmxhdEJ1dHRvbgogICAgICAgIHJlcXVpcmVk'
    'IHByb3BlcnR5IHN0cmluZyBsYWJlbAogICAgICAgIHByb3BlcnR5IGJvb2wgcHJpbWFyeTogZmFsc2UKICAgICAgICBwcm9w'
    'ZXJ0eSBib29sIGRhbmdlcjogZmFsc2UKICAgICAgICBwcm9wZXJ0eSBib29sIGVuYWJsZWRCdXR0b246IHRydWUKICAgICAg'
    'ICBzaWduYWwgY2xpY2tlZCgpCiAgICAgICAgaW1wbGljaXRIZWlnaHQ6IDM4CiAgICAgICAgaW1wbGljaXRXaWR0aDogTWF0'
    'aC5tYXgoOTIsIGJ1dHRvblRleHQuaW1wbGljaXRXaWR0aCArIDI4KQogICAgICAgIHJhZGl1czogMTAKICAgICAgICBjb2xv'
    'cjogIWVuYWJsZWRCdXR0b24gPyAiI2VlZjBmMyIKICAgICAgICAgICAgICA6IGRhbmdlciA/IChidXR0b25Nb3VzZS5jb250'
    'YWluc01vdXNlID8gIiNmZWUyZTIiIDogIiNmZWYyZjIiKQogICAgICAgICAgICAgIDogcHJpbWFyeSA/IChidXR0b25Nb3Vz'
    'ZS5jb250YWluc01vdXNlID8gIiMyMDk5ZGMiIDogcm9vdC5hY2NlbnQpCiAgICAgICAgICAgICAgOiAoYnV0dG9uTW91c2Uu'
    'Y29udGFpbnNNb3VzZSA/ICIjZWVmMmY3IiA6ICIjZjdmOWZjIikKICAgICAgICBib3JkZXIud2lkdGg6IHByaW1hcnkgPyAw'
    'IDogMQogICAgICAgIGJvcmRlci5jb2xvcjogZGFuZ2VyID8gIiNmZWNhY2EiIDogcm9vdC5ib3JkZXIKICAgICAgICBvcGFj'
    'aXR5OiBlbmFibGVkQnV0dG9uID8gMSA6IDAuNgoKICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgaWQ6IGJ1dHRvblRl'
    'eHQKICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgIHRleHQ6IGZsYXRCdXR0b24ubGFi'
    'ZWwKICAgICAgICAgICAgY29sb3I6IGZsYXRCdXR0b24ucHJpbWFyeSA/ICJ3aGl0ZSIgOiAoZmxhdEJ1dHRvbi5kYW5nZXIg'
    'PyByb290LmJhZCA6IHJvb3QudGV4dE1haW4pCiAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMwogICAgICAgICAgICBm'
    'b250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgIH0KICAgICAgICBNb3VzZUFyZWEgewogICAgICAgICAgICBpZDog'
    'YnV0dG9uTW91c2UKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgZW5hYmxlZDogZmxhdEJ1'
    'dHRvbi5lbmFibGVkQnV0dG9uCiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JTaGFw'
    'ZTogZW5hYmxlZCA/IFF0LlBvaW50aW5nSGFuZEN1cnNvciA6IFF0LkFycm93Q3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tl'
    'ZDogZmxhdEJ1dHRvbi5jbGlja2VkKCkKICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IE5hdkJ1dHRvbjogUmVjdGFu'
    'Z2xlIHsKICAgICAgICBpZDogbmF2CiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgc3RyaW5nIGxhYmVsCiAgICAgICAgcmVx'
    'dWlyZWQgcHJvcGVydHkgaW50IGluZGV4CiAgICAgICAgcHJvcGVydHkgc3RyaW5nIHNob3J0TGFiZWw6ICIiCiAgICAgICAg'
    'c2lnbmFsIGNsaWNrZWQoKQogICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICBpbXBsaWNpdFdpZHRoOiAx'
    'ODYKICAgICAgICBoZWlnaHQ6IDQ4CiAgICAgICAgcmFkaXVzOiAxMQogICAgICAgIGNvbG9yOiByb290LnBhZ2VJbmRleCA9'
    'PT0gaW5kZXggPyAiIzI1MzI0NiIgOiAobmF2TW91c2UuY29udGFpbnNNb3VzZSA/IHJvb3Quc2lkZWJhckhvdmVyIDogInRy'
    'YW5zcGFyZW50IikKCiAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAg'
    'ICAgICAgYW5jaG9ycy5sZWZ0TWFyZ2luOiAxMgogICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiAxMgogICAgICAg'
    'ICAgICBzcGFjaW5nOiAxMQogICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgd2lkdGg6IDI4CiAgICAg'
    'ICAgICAgICAgICBoZWlnaHQ6IDI4CiAgICAgICAgICAgICAgICByYWRpdXM6IDgKICAgICAgICAgICAgICAgIGNvbG9yOiBy'
    'b290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gcm9vdC5hY2NlbnQgOiAiIzI3MzQ0OSIKICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgewogICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICAgICAgICAg'
    'IHRleHQ6IG5hdi5zaG9ydExhYmVsCiAgICAgICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAg'
    'ICAgICBmb250LnBpeGVsU2l6ZTogMTAKICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICB0ZXh0OiBuYXYubGFiZWwKICAgICAgICAgICAgICAgIGNvbG9yOiBy'
    'b290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gIndoaXRlIiA6ICIjY2JkNWUxIgogICAgICAgICAgICAgICAgZm9udC5w'
    'aXhlbFNpemU6IDE0CiAgICAgICAgICAgICAgICBmb250LndlaWdodDogcm9vdC5wYWdlSW5kZXggPT09IG5hdi5pbmRleCA/'
    'IEZvbnQuRGVtaUJvbGQgOiBGb250Lk5vcm1hbAogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIE1vdXNlQXJlYSB7'
    'CiAgICAgICAgICAgIGlkOiBuYXZNb3VzZQogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBo'
    'b3ZlckVuYWJsZWQ6IHRydWUKICAgICAgICAgICAgY3Vyc29yU2hhcGU6IFF0LlBvaW50aW5nSGFuZEN1cnNvcgogICAgICAg'
    'ICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgIHJvb3QucGFnZUluZGV4ID0gbmF2LmluZGV4CiAgICAgICAgICAg'
    'ICAgICBuYXYuY2xpY2tlZCgpCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IENhcmQ6IFJl'
    'Y3RhbmdsZSB7CiAgICAgICAgcmFkaXVzOiAxNgogICAgICAgIGNvbG9yOiByb290LnN1cmZhY2UKICAgICAgICBib3JkZXIu'
    'd2lkdGg6IDEKICAgICAgICBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyCiAgICB9CgogICAgUm93TGF5b3V0IHsKICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgIHNwYWNpbmc6IDAKCiAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAg'
    'ICAgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiAyMjIKICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAg'
    'ICAgICAgY29sb3I6IHJvb3Quc2lkZWJhcgoKICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGFu'
    'Y2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE4CiAgICAgICAgICAgICAgICBz'
    'cGFjaW5nOiA3CgogICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmJvdHRvbU1hcmdpbjogMjQKICAgICAgICAgICAgICAgICAg'
    'ICBzcGFjaW5nOiAxMQogICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgIHdp'
    'ZHRoOiA0MAogICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQwCiAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1'
    'czogMTIKICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYWNjZW50CiAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB0ZXh0OiAiRSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUi'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMjAKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQud2VpZ2h0OiBGb250LkJsYWNrCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzog'
    'MAogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJF'
    'dmdlbml1bSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBmb250LnBpeGVsU2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250'
    'LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJOZXR3b3JrIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'ICIjOTRhM2I4IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgTmF2'
    'QnV0dG9uIHsgbGFiZWw6ICJWUE4iOyBzaG9ydExhYmVsOiAiVlBOIjsgaW5kZXg6IDAgfQogICAgICAgICAgICAgICAgTmF2'
    'QnV0dG9uIHsgbGFiZWw6ICLQn9GA0L7RhNC40LvQuCBWUE4iOyBzaG9ydExhYmVsOiAiUFJGIjsgaW5kZXg6IDEgfQogICAg'
    'ICAgICAgICAgICAgTmF2QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCf0YDQuNC70L7QttC10L3QuNGP'
    'Ijsgc2hvcnRMYWJlbDogIkFQUCI7IGluZGV4OiAyCiAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LnJlZnJl'
    'c2hSdW5uaW5nKCkKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0KHQsNC5'
    '0YLRiyDQuCBJUCI7IHNob3J0TGFiZWw6ICJORVQiOyBpbmRleDogMyB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBs'
    'YWJlbDogItCf0L7RgNGC0YsiOyBzaG9ydExhYmVsOiAiUFJUIjsgaW5kZXg6IDQgfQogICAgICAgICAgICAgICAgTmF2QnV0'
    'dG9uIHsgbGFiZWw6ICLQlNC40LDQs9C90L7RgdGC0LjQutCwIjsgc2hvcnRMYWJlbDogIlNZUyI7IGluZGV4OiA1IH0KICAg'
    'ICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0K3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90L7QtSI7IHNo'
    'b3J0TGFiZWw6ICJFWFAiOyBpbmRleDogNiB9CgogICAgICAgICAgICAgICAgSXRlbSB7IExheW91dC5maWxsSGVpZ2h0OiB0'
    'cnVlIH0KCiAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDY0CiAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAg'
    'ICAgICAgICAgICAgICAgIGNvbG9yOiAiIzE3MjAzMyIKICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1h'
    'cmdpbnM6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB3aWR0aDogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogMTAKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHJhZGl1czogNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5h'
    'Y3RpdmUpID8gcm9vdC5nb29kIDogIiM2NDc0OGIiCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEKICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUp'
    'ID8gIlZQTiDQstC60LvRjtGH0ZHQvSIgOiAiVlBOINCy0YvQutC70Y7Rh9C10L0iCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTog'
    'MTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLnByb2ZpbGUgfHwgcm9vdC5zdGF0ZS5sYXN0X3Byb2ZpbGUgfHwgItCd0LXRgiDQ'
    'v9GA0L7RhNC40LvRjyIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICIjOTRhM2I4IgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGVsaWRlOiBUZXh0LkVsaWRlUmlnaHQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAg'
    'IH0KCiAgICAgICAgSXRlbSB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxIZWlnaHQ6IHRydWUKCiAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICBhbmNob3JzLmZp'
    'bGw6IHBhcmVudAogICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyOAogICAgICAgICAgICAgICAgc3BhY2luZzog'
    'MTgKCiAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBbIlZQTiIsICLQn9GA0L7RhNC40LvQuCBWUE4iLCAi0J/R'
    'gNC40LvQvtC20LXQvdC40Y8g0LHQtdC3IFZQTiIsICLQodCw0LnRgtGLINC4IElQINCx0LXQtyBWUE4iLCAi0JLRhdC+0LTR'
    'j9GJ0LjQtSDQv9C+0YDRgtGLIiwgItCU0LjQsNCz0L3QvtGB0YLQuNC60LAiLCAi0K3QutGB0L/QtdGA0LjQvNC10L3RgtCw'
    '0LvRjNC90L7QtSJdW3Jvb3QucGFnZUluZGV4XQogICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFp'
    'bgogICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMjUKICAgICAgICAgICAgICAgICAgICAgICAgZm9u'
    'dC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBDLkJ1c3lJbmRp'
    'Y2F0b3IgewogICAgICAgICAgICAgICAgICAgICAgICBydW5uaW5nOiByb290LmJ1c3kKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgdmlzaWJsZTogcnVubmluZwogICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdFdpZHRoOiAyOAogICAgICAgICAg'
    'ICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogMjgKICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J7QsdC90L7QstC40YLRjCIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeQogICAgICAgICAgICAgICAgICAgICAgICBvbkNs'
    'aWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QucmVmcmVzaFN0YXRlKCkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGlmIChyb290LnBhZ2VJbmRleCA9PT0gMikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBy'
    'b290LnJlZnJlc2hSdW5uaW5nKCkKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgIHZpc2libGU6'
    'IHJvb3QuZXJyb3JUZXh0Lmxlbmd0aCA+IDAKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAg'
    'ICAgICAgICAgICAgICAgICAgaW1wbGljaXRIZWlnaHQ6IGVycm9yTGFiZWwuaW1wbGljaXRIZWlnaHQgKyAyMgogICAgICAg'
    'ICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmZmYxZjIiCiAgICAgICAgICAg'
    'ICAgICAgICAgYm9yZGVyLndpZHRoOiAxCiAgICAgICAgICAgICAgICAgICAgYm9yZGVyLmNvbG9yOiAiI2ZlY2RkMyIKICAg'
    'ICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGVycm9yTGFiZWwKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5t'
    'YXJnaW5zOiAxMQogICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiByb290LmVycm9yVGV4dAogICAgICAgICAgICAgICAg'
    'ICAgICAgICBjb2xvcjogcm9vdC5iYWQKICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICAgICAgfQoKICAgICAgICAgICAgICAgIFN0YWNrTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICBjdXJyZW50SW5kZXg6IHJvb3QucGFnZUluZGV4CgogICAgICAgICAgICAgICAgICAgIC8vIFZQTgogICAgICAgICAg'
    'ICAgICAgICAgIEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDIw'
    'CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Bh'
    'Y2luZzogMTgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA3MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaGVpZ2h0OiA3MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAyMgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9v'
    'dC5hY2NlbnRTb2Z0IDogIiNlZWYyZjciCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0'
    'aXZlKSA/ICJPTiIgOiAiT0ZGIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBC'
    'b29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/IHJvb3QuYWNjZW50IDogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTgKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDUK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gItCX0LDRidC40YnRkdC9'
    '0L3QvtC1INGB0L7QtdC00LjQvdC10L3QuNC1INCw0LrRgtC40LLQvdC+IiA6ICJWUE4g0YHQtdC50YfQsNGBINCy0YvQutC7'
    '0Y7Rh9C10L0iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1h'
    'aW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMjAKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihyb290LnN0YXRl'
    'LmFjdGl2ZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAocm9vdC5zdGF0ZS5i'
    'YWNrZW5kID09PSAiaWtldjIiID8gItCS0LXRgdGMIElQdjQt0YLRgNCw0YTQuNC6INC40LTRkdGCINGH0LXRgNC10LcgU3Rh'
    'ckZpdmUg0LIg0KDQvtGB0YHQuNC4LiBJUHY2INC4IERJUkVDVC3QuNGB0LrQu9GO0YfQtdC90LjRjyDQvtGC0LrQu9GO0YfQ'
    'tdC90YsuIiA6ICLQktC10YHRjCDQvtCx0YvRh9C90YvQuSDRgtGA0LDRhNC40Log0LjQtNGR0YIg0YfQtdGA0LXQtyBWUE4s'
    'INC60YDQvtC80LUg0L3QsNGB0YLRgNC+0LXQvdC90YvRhSDQuNGB0LrQu9GO0YfQtdC90LjQuS4iKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6ICLQktC60LvRjtGH0LggVlBOINC+0LTQvdC40Lwg0L3QsNC2'
    '0LDRgtC40LXQvC4g0JHRg9C00LXRgiDQuNGB0L/QvtC70YzQt9C+0LLQsNC9INC/0L7RgdC70LXQtNC90LjQuSDQstGL0LHR'
    'gNCw0L3QvdGL0Lkg0L/RgNC+0YTQuNC70YwuIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBN'
    'b2RlOiBUZXh0LldvcmRXcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhl'
    'bFNpemU6IDEzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyAi'
    '0JLRi9C60LvRjtGH0LjRgtGMIFZQTiIgOiAi0JLQutC70Y7Rh9C40YLRjCBWUE4iCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBwcmltYXJ5OiAhQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGRhbmdlcjogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC50b2dnbGVWcG4oKQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBSZWN0YW5nbGUgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAxOyBj'
    'b2xvcjogcm9vdC5ib3JkZXIgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHcmlkTGF5b3V0IHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBjb2x1bW5zOiAyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtblNw'
    'YWNpbmc6IDI0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvd1NwYWNpbmc6IDE0CgogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCf0YDQvtGE0LjQu9GMIjsgY29sb3I6IHJvb3Qu'
    'dGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3RhdGUu'
    'bGFzdF9wcm9maWxlIHx8ICLigJQiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJv'
    'b3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRl'
    'bWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJJUHY2IjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0'
    'ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5pcHY2X21vZGUgfHwgInVua25vd24iKQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJLaWxsIHN3aXRjaCI7IGNvbG9yOiBy'
    'b290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/ICLQ'
    'kNC60YLQuNCy0LXQvSIgOiAi0JLRi9C60LvRjtGH0LXQvSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUua2lsbF9zd2l0Y2gpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TXV0ZWQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IHRleHQ6ICLQktC10YDRgdC40Y8gbWFuYWdlciI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUubWFuYWdlciB8fCAi4oCUIikKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0SGVpZ2h0OiA5MgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICByYWRpdXM6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyLndpZHRoOiAxCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGJvcmRlci5jb2xvcjogcm9vdC5ib3JkZXIKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6'
    'IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHdpZHRoOiA0NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEzCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKSA/'
    'IHJvb3QuYWNjZW50U29mdCA6ICIjZWVmMmY3IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRl'
    'ckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIldEIgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRl'
    'LndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpID8gcm9vdC5hY2NlbnQgOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTMKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBzcGFjaW5nOiA0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJWUE4g0LTQ'
    'u9GPIFdheWRyb2lkIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9v'
    'dC50ZXh0TWFpbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6'
    'ZTogMTUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQu'
    'RGVtaUJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgdGV4dDogIUJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICA/ICLQntCx0YnQuNC5IFZQTiDQstGL0LrQu9GO0YfQtdC9IOKAlCBXYXlkcm9p'
    'ZCDRgtC+0LbQtSDRgNCw0LHQvtGC0LDQtdGCINCx0LXQtyBWUE4uIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgOiAoQm9vbGVhbihyb290LnN0YXRlLndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAi0KLRgNCw0YTQuNC6IFdheWRy'
    'b2lkINC40LTRkdGCINGH0LXRgNC10LcgRS1WUE4uIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIDogIldheWRyb2lkINC40YHQv9C+0LvRjNC30YPQtdGCINC/0YDRj9C80L7QuSDQuNC90YLQtdGA'
    '0L3QtdGCINCyINC+0LHRhdC+0LQgRS1WUE4uIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3'
    'cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogd2F5ZHJvaWRT'
    'd2l0Y2gKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQucHJlZmVycmVkV2lkdGg6'
    'IDQ4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZEhlaWdodDog'
    'MjYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcGFjaXR5OiBCb29sZWFuKHJvb3Quc3Rh'
    'dGUuYWN0aXZlKSAmJiAhcm9vdC5idXN5ID8gMS4wIDogMC40NQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBh'
    'bmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRp'
    'dXM6IGhlaWdodCAvIDIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJv'
    'b2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKSA/IHJvb3QuYWNjZW50IDogIiNjYmQ1ZTEiCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHdpZHRoOiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDIwCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeTogMwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB4OiBCb29sZWFuKHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyB3YXlkcm9pZFN3'
    'aXRjaC53aWR0aCAtIHdpZHRoIC0gMyA6IDMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQmVoYXZp'
    'b3Igb24geCB7IE51bWJlckFuaW1hdGlvbiB7IGR1cmF0aW9uOiAxMjAgfSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIE1vdXNlQXJl'
    'YSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWQ6IEJvb2xlYW4ocm9vdC5z'
    'dGF0ZS5hY3RpdmUpICYmICFyb290LmJ1c3kKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgY3Vyc29yU2hhcGU6IGVuYWJsZWQgPyBRdC5Qb2ludGluZ0hhbmRDdXJzb3IgOiBRdC5BcnJvd0N1cnNvcgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFjdGlvbjogIndheWRyb2lkX3Zwbl9zZXQi'
    'LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGFyZ2V0OiBCb29sZWFuKHJv'
    'b3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyAib2ZmIiA6ICJvbiIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CgoKICAgICAgICAgICAgICAgICAgICAvLyBWUE4g'
    'cHJvZmlsZXMKICAgICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBzcGFjaW5nOiAxNAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBo'
    'ZWlnaHQ6IDc4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgd2lkdGg6IDQyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6'
    'IDQyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEyCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5hY2NlbnRTb2Z0CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi'
    'UFJGIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LmFjY2VudAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIlZQTi3Qv9GA0L7RhNC40LvQuCIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5jb25maWdfZGlyIHx8ICIiKQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0'
    'ZXh0OiBTdHJpbmcoKHJvb3Quc3RhdGUucHJvZmlsZXMgfHwgW10pLmxlbmd0aCkgKyAiINGI0YIuIgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFy'
    'Z2luczogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA3CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVs'
    'OiByb290LnN0YXRlLnByb2ZpbGVzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRl'
    'OiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHByb2ZpbGVSb3cKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDY2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByYWRpdXM6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9v'
    'bGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpID8gcm9vdC5hY2NlbnRTb2Z0IDogIiNmOGZhZmMiCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIud2lkdGg6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERh'
    'dGEuYWN0aXZlKSA/IDEgOiAwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIuY29sb3I6'
    'IHJvb3QuYWNjZW50CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubGVmdE1hcmdpbjogMTQKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiAxMAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEyCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRo'
    'OiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogNgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHJvb3QuZ29vZAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiAoQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0'
    'YS5sYXN0KSA/IHJvb3QuYWNjZW50IDogIiNjYmQ1ZTEiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAyCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHByb2ZpbGVSb3cubW9kZWxEYXRhLnN0ZW0gfHwgcHJvZmls'
    'ZVJvdy5tb2RlbERhdGEubmFtZSB8fCAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBlbGlkZTogVGV4dC5FbGlkZVJpZ2h0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHBy'
    'b2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICA/ICLQkNC60YLQuNCy0L3Ri9C5INC/0YDQvtGE0LjQu9GMIgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogKEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEubGFzdCkgPyAi'
    '0J/QvtGB0LvQtdC00L3QuNC5INC40YHQv9C+0LvRjNC30L7QstCw0L3QvdGL0LkiIDogU3RyaW5nKHByb2ZpbGVSb3cubW9k'
    'ZWxEYXRhLm5hbWUgfHwgIiIpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Y29sb3I6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVk'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTEK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsaWRlOiBUZXh0LkVsaWRlTWlk'
    'ZGxlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogQm9v'
    'bGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpID8gItCQ0LrRgtC40LLQtdC9IiA6ICLQn9C+0LTQutC70Y7Rh9C4'
    '0YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbWFyeTogIUJvb2xlYW4o'
    'cHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3Rpb246ICJwcm9maWxlX2Fj'
    'dGl2YXRlIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcmdldDogU3Ry'
    'aW5nKHByb2ZpbGVSb3cubW9kZWxEYXRhLm5hbWUgfHwgIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgdmlzaWJsZTogKHJvb3Quc3RhdGUucHJvZmlsZXMgfHwgW10pLmxlbmd0aCA9PT0gMAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogItCSINC/0LDQv9C60LUgVlBOIGNvbmZpZ3Mg0L/QvtC60LAg0L3QtdGC'
    'INC/0YDQvtGE0LjQu9C10LkiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50'
    'ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gQXBwbGljYXRpb25zCiAgICAgICAgICAgICAgICAgICAg'
    'SXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA4MgogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmls'
    'bDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTYKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQy5UZXh0RmllbGQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IG1hbnVhbEFw'
    'cAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGxhY2Vob2xkZXJUZXh0OiAi0JjQvNGPINC/0YDQvtGG0LXRgdGB'
    '0LAsIC/Qv9C+0LvQvdGL0Lkv0L/Rg9GC0Ywg0LjQu9C4IC/Qv9Cw0L/QutCwLyIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHNlbGVjdEJ5TW91c2U6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9yOiAiI2Y4ZmFmYyI7IGJvcmRlci5jb2xvcjog'
    'cm9vdC5ib3JkZXIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25BY2NlcHRlZDogaWYgKHRl'
    'eHQudHJpbSgpLmxlbmd0aCkgcm9vdC5hY3Rpb24oe2FjdGlvbjogImFwcF9hZGQiLCB0YXJnZXQ6IHRleHQudHJpbSgpfSkK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0JTQvtCx0LDQ'
    'stC40YLRjCDQstGA0YPRh9C90YPRjiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kg'
    'JiYgbWFudWFsQXBwLnRleHQudHJpbSgpLmxlbmd0aCA+IDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuYWN0aW9u'
    'KHthY3Rpb246ICJhcHBfYWRkIiwgdGFyZ2V0OiBtYW51YWxBcHAudGV4dC50cmltKCl9KQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIG1hbnVhbEFwcC5jbGVhcigpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Um93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQo9C20LUg0LjRgdC60LvRjtGH0LXQvdGLIjsg'
    'Y29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAxNTsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZDsgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmlu'
    'Zygocm9vdC5zdGF0ZS5hcHBsaWNhdGlvbnMgfHwgW10pLmxlbmd0aCk7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDE0NQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiA4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5zdGF0ZS5hcHBsaWNhdGlvbnMgfHwgW10KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZWdhdGU6IFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgaGVpZ2h0OiA0NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVz'
    'OiA5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgYW5jaG9ycy5sZWZ0TWFyZ2luOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMucmlnaHRNYXJnaW46IDgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5nKG1vZGVsRGF0YSk7IGNvbG9yOiByb290LnRleHRN'
    'YWluOyBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi'
    '0KPQtNCw0LvQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhbmdlcjog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9v'
    'dC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5h'
    'Y3Rpb24oe2FjdGlvbjogImFwcF9yZW1vdmUiLCB0YXJnZXQ6IFN0cmluZyhtb2RlbERhdGEpfSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjog'
    'cGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiAocm9vdC5zdGF0ZS5hcHBs'
    'aWNhdGlvbnMgfHwgW10pLmxlbmd0aCA9PT0gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4'
    'dDogItCf0L7QutCwINC90LXRgiDQv9GA0LjQu9C+0LbQtdC90LjQuS3QuNGB0LrQu9GO0YfQtdC90LjQuSIKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgeyB0ZXh0OiAi0JfQsNC/0YPRidC10L3RiyDRgdC10LnRh9Cw0YEiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5w'
    'aXhlbFNpemU6IDE1OyBmb250LndlaWdodDogRm9udC5Cb2xkOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntCx0L3QvtCy0LjRgtGMINGB0L/QuNGB0L7Q'
    'uiI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5yZWZyZXNoUnVubmluZygpIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGFwcFNlYXJjaAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6'
    'ICLQndCw0LnRgtC4INC30LDQv9GD0YnQtdC90L3QvtC1INC/0YDQuNC70L7QttC10L3QuNC1INC/0L4g0LjQvNC10L3QuCDQ'
    'uNC70Lgg0L/Rg9GC0LjigKYiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9y'
    'OiByb290LnN1cmZhY2U7IGJvcmRlci5jb2xvcjogcm9vdC5ib3JkZXIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5j'
    'aG9ycy5tYXJnaW5zOiA4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBtb2RlbDogcm9vdC5maWx0ZXJlZFJ1bm5pbmcoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxl'
    'Z2F0ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3Bl'
    'cnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmll'
    'dy52aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDY0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDExCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dM'
    'YXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiA5CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTAKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB3aWR0aDogNDA7IGhlaWdodDogNDA7IHJhZGl1czogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4obW9kZWxEYXRhLmV4Y2x1ZGVkKSA/ICIjZGNmY2U3IiA6IHJvb3Qu'
    'YWNjZW50U29mdAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVu'
    'dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKG1vZGVs'
    'RGF0YS5uYW1lIHx8ICI/Iikuc2xpY2UoMCwgMSkudG9VcHBlckNhc2UoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4obW9kZWxEYXRhLmV4Y2x1ZGVkKSA/IHJvb3QuZ29vZCA6'
    'IHJvb3QuYWNjZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250Lndl'
    'aWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250'
    'LnBpeGVsU2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHNwYWNpbmc6IDEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExh'
    'eW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2RlbERhdGEubmFtZSB8fCAiIik7IGNvbG9yOiByb290LnRl'
    'eHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZDsgZWxpZGU6IFRleHQuRWxpZGVSaWdodCB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0'
    'ZXh0OiBTdHJpbmcobW9kZWxEYXRhLmV4ZSB8fCAiIik7IGNvbG9yOiByb290LnRleHRNdXRlZDsgZm9udC5waXhlbFNpemU6'
    'IDExOyBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBOdW1iZXIobW9kZWxEYXRhLmNvdW50IHx8IDEp'
    'ID4gMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAiw5ciICsgU3RyaW5n'
    'KG1vZGVsRGF0YS5jb3VudCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogQm9vbGVhbihtb2RlbERhdGEuZXhjbHVkZWQpID8gItCj0LbQtSDQuNGB'
    '0LrQu9GO0YfQtdC90L4iIDogItCY0YHQutC70Y7Rh9C40YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgcHJpbWFyeTogIUJvb2xlYW4obW9kZWxEYXRhLmV4Y2x1ZGVkKQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKG1vZGVs'
    'RGF0YS5leGNsdWRlZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2Vk'
    'OiByb290LmFjdGlvbih7YWN0aW9uOiAiYXBwX2FkZCIsIHRhcmdldDogU3RyaW5nKG1vZGVsRGF0YS5leGUgfHwgbW9kZWxE'
    'YXRhLm5hbWUgfHwgIiIpfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAvLyBTaXRlcy9J'
    'UAogICAgICAgICAgICAgICAgICAgIEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHNwYWNpbmc6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA4'
    'MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMubWFyZ2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTAKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgaWQ6IGRpcmVjdFRhcmdldAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGxhY2Vob2xkZXJUZXh0'
    'OiAiZXhhbXBsZS5jb20sIDIwMy4wLjExMy4xMCDQuNC70LggMjAzLjAuMTEzLjAvMjQiCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBzZWxlY3RCeU1vdXNlOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBiYWNrZ3JvdW5kOiBSZWN0YW5nbGUgeyByYWRpdXM6IDEwOyBjb2xvcjogIiNmOGZhZmMiOyBib3JkZXIuY29s'
    'b3I6IHJvb3QuYm9yZGVyIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQWNjZXB0ZWQ6IGlm'
    'ICh0ZXh0LnRyaW0oKS5sZW5ndGgpIHJvb3QuYWN0aW9uKHthY3Rpb246ICJkaXJlY3RfYWRkIiwgdGFyZ2V0OiB0ZXh0LnRy'
    'aW0oKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCU'
    '0L7QsdCw0LLQuNGC0Ywg0LjRgdC60LvRjtGH0LXQvdC40LUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBwcmltYXJ5OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9u'
    'OiAhcm9vdC5idXN5ICYmIGRpcmVjdFRhcmdldC50ZXh0LnRyaW0oKS5sZW5ndGggPiAwCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICByb290LmFjdGlvbih7YWN0aW9uOiAiZGlyZWN0X2FkZCIsIHRhcmdldDogZGlyZWN0VGFyZ2V0LnRleHQudHJpbSgp'
    'fSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXJlY3RUYXJnZXQuY2xlYXIoKQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLkxhYmVsIHsgdGV4dDogItCU0L7QvNC10L3RiyI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9u'
    'dC5Cb2xkOyBmb250LnBpeGVsU2l6ZTogMTUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlz'
    'dFZpZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgbW9kZWw6IHJvb3Quc3RhdGUuZG9tYWlucyB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgcmFkaXVzOiA5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9y'
    'OiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'OyBhbmNob3JzLmxlZnRNYXJnaW46IDEwOyBhbmNob3JzLnJpZ2h0TWFyZ2luOiA3CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3Ry'
    'aW5nKG1vZGVsRGF0YSk7IGNvbG9yOiByb290LnRleHRNYWluOyBlbGlkZTogVGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCj0LTQsNC7'
    '0LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9u'
    'KHthY3Rpb246ICJkaXJlY3RfcmVtb3ZlIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhKX0pIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbEJhci52ZXJ0aWNh'
    'bDogQy5TY3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1'
    'ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgeyB0ZXh0OiAiSVAg0Lgg0YHQtdGC0LgiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQu'
    'Qm9sZDsgZm9udC5waXhlbFNpemU6IDE1IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RW'
    'aWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIG1vZGVsOiByb290LnN0YXRlLm5ldHdvcmtzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgZGVsZWdhdGU6IFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgd2lkdGg6IExpc3RWaWV3LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICByYWRpdXM6IDkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'ICIjZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQ7'
    'IGFuY2hvcnMubGVmdE1hcmdpbjogMTA7IGFuY2hvcnMucmlnaHRNYXJnaW46IDcKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJp'
    'bmcobW9kZWxEYXRhKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCj0LTQsNC7'
    '0LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9u'
    'KHthY3Rpb246ICJkaXJlY3RfcmVtb3ZlIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhKX0pIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbEJhci52ZXJ0aWNh'
    'bDogQy5TY3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAg'
    'ICAgICAgICAgICAgICAgLy8gUG9ydHMKICAgICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGhlaWdodDogMTA1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBzcGFjaW5nOiA4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgdGV4dDogItCU0LvRjyDQu9C+0LrQsNC70YzQvdGL0YUg0YHQtdGA0LLQtdGA0L7Qsjog'
    '0L7RgtCy0LXRgtGLINC90LAg0LLRhdC+0LTRj9GJ0LjQtSDQv9C+0LTQutC70Y7Rh9C10L3QuNGPINC6INGN0YLQuNC8INC/'
    '0L7RgNGC0LDQvCDQuNC00YPRgiDQvdCw0L/RgNGP0LzRg9GOINGH0LXRgNC10Lcg0YTQuNC30LjRh9C10YHQutGD0Y4g0YHQ'
    'tdGC0YwuIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBpZDogcG9ydEZpZWxkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVy'
    'VGV4dDogIjI1NTY1IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlucHV0TWV0aG9kSGlu'
    'dHM6IFF0LkltaERpZ2l0c09ubHkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3Jv'
    'dW5kOiBSZWN0YW5nbGUgeyByYWRpdXM6IDEwOyBjb2xvcjogIiNmOGZhZmMiOyBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVy'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuQ29tYm9Cb3ggewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlk'
    'OiBwcm90b0JveAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiBbIlRDUCIsICJV'
    'RFAiLCAiQk9USCJdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRXaWR0aDog'
    'MTEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBs'
    'YWJlbDogItCU0L7QsdCw0LLQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJp'
    'bWFyeTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFy'
    'b290LmJ1c3kgJiYgcG9ydEZpZWxkLnRleHQubGVuZ3RoID4gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBj'
    'b25zdCBwID0gTnVtYmVyKHBvcnRGaWVsZC50ZXh0KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBpZiAocCA+PSAxICYmIHAgPD0gNjU1MzUgJiYgcCA9PT0gTWF0aC5mbG9vcihwKSkgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogInBvcnRfYWRkIiwg'
    'cG9ydDogcCwgcHJvdG86IHByb3RvQm94LmN1cnJlbnRUZXh0LnRvTG93ZXJDYXNlKCl9KQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcG9ydEZpZWxkLmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5j'
    'aG9ycy5tYXJnaW5zOiAxMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDcKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgbW9kZWw6IHJvb3Quc3RhdGUuc2VydmVyX3BvcnRzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWly'
    'ZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6'
    'IExpc3RWaWV3LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNTQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxs'
    'OiBwYXJlbnQ7IGFuY2hvcnMubGVmdE1hcmdpbjogMTI7IGFuY2hvcnMucmlnaHRNYXJnaW46IDgKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB3aWR0aDogNTQ7IGhlaWdodDogMzA7IHJhZGl1czogODsgY29sb3I6IHJvb3QuYWNjZW50U29m'
    'dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgYW5jaG9ycy5jZW50'
    'ZXJJbjogcGFyZW50OyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLnByb3RvIHx8ICIiKS50b1VwcGVyQ2FzZSgpOyBjb2xvcjog'
    'cm9vdC5hY2NlbnQ7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQ7IGZvbnQucGl4ZWxTaXplOiAxMSB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLnBvcnQgfHwgIiIp'
    'OyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6IDE2OyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0KPQtNCw0LvQuNGC0YwiOyBkYW5nZXI6IHRydWU7'
    'IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAicG9ydF9yZW1vdmUiLCBwb3J0OiBOdW1iZXIobW9kZWxEYXRh'
    'LnBvcnQpLCBwcm90bzogU3RyaW5nKG1vZGVsRGF0YS5wcm90byl9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbEJhci52'
    'ZXJ0aWNhbDogQy5TY3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IGFu'
    'Y2hvcnMuY2VudGVySW46IHBhcmVudDsgdmlzaWJsZTogKHJvb3Quc3RhdGUuc2VydmVyX3BvcnRzIHx8IFtdKS5sZW5ndGgg'
    'PT09IDA7IHRleHQ6ICLQndC10YIg0YHQtdGA0LLQtdGA0L3Ri9GFINC/0L7RgNGC0L7QsiI7IGNvbG9yOiByb290LnRleHRN'
    'dXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAvLyBE'
    'aWFnbm9zdGljcwogICAgICAgICAgICAgICAgICAgIEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyNAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHNwYWNpbmc6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQ'
    'otC10LrRg9GJ0LXQtSDRgdC+0YHRgtC+0Y/QvdC40LUiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6'
    'IDE4OyBmb250LndlaWdodDogRm9udC5Cb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHcmlkTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zOiAyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGNvbHVtblNwYWNpbmc6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvd1NwYWNpbmc6IDEzCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiVlBOIjsgY29sb3I6IHJvb3QudGV4'
    'dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IEJvb2xlYW4ocm9v'
    'dC5zdGF0ZS5hY3RpdmUpID8gItCS0LrQu9GO0YfRkdC9IiA6ICLQktGL0LrQu9GO0YfQtdC9IjsgY29sb3I6IEJvb2xlYW4o'
    'cm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TXV0ZWQ7IGZvbnQud2VpZ2h0OiBGb250LkRlbWlC'
    'b2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQn9GA0L7RhNC40LvR'
    'jCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3RhdGUubGFzdF9wcm9maWxlIHx8ICLigJQiKTsg'
    'Y29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJUVU4iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLnR1bikgPyAieHJh'
    'eXR1biDQv9C+0LTQvdGP0YIiIDogItCd0LXRgiI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5E'
    'ZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiS2lsbCBzd2l0'
    'Y2giOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/ICLQkNC60YLQuNCy0LXQvSIgOiAi0JLRi9C60LvR'
    'jtGH0LXQvSI7IGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUua2lsbF9zd2l0Y2gpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0'
    'TXV0ZWQ7IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5MYWJlbCB7IHRleHQ6ICJJUHY2IjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLmlwdjZfbW9kZSB8fCAidW5rbm93biIpOyBj'
    'b2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkRJUkVDVCDQv9GA0LjQu9C+0LbQtdC90LjRjyI7IGNvbG9yOiByb290'
    'LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmco'
    'cm9vdC5zdGF0ZS5kaXJlY3RfYXBwbGljYXRpb25zIHx8IDApOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6'
    'IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkRJ'
    'UkVDVCDQtNC+0LzQtdC90YsiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUuZGlyZWN0X2RvbWFpbnMgfHwgMCk7IGNvbG9yOiBy'
    'b290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRElSRUNUIElQL9GB0LXRgtC4IjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLmRpcmVj'
    'dF9uZXR3b3JrcyB8fCAwKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJNYW5hZ2VyIjsgY29sb3I6IHJvb3Qu'
    'dGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhy'
    'b290LnN0YXRlLm1hbmFnZXIgfHwgIuKAlCIpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVt'
    'aUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQntC60L3QviDQvdCw0YHRgtGA0L7QtdC6INGA0LDQsdC+0YLQ'
    'sNC10YIg0L7RgtC00LXQu9GM0L3QviDQvtGCIFBsYXNtYS4gS0RFINC40YHQv9C+0LvRjNC30YPQtdGC0YHRjyDRgtC+0LvR'
    'jNC60L4g0LTQu9GPINC80LDQu9C10L3RjNC60L7Qs9C+INCy0LjQtNC20LXRgtCwINC90LAg0YDQsNCx0L7Rh9C10Lwg0YHR'
    'gtC+0LvQtS4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIEV4cGVyaW1lbnRhbCBJS0V2MiBpcyBkZWxpYmVyYXRlbHkgb3B0LWlu'
    'OyBubyBhdXRvbWF0aWMgYWN0aXZhdGlvbi4KICAgICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5TY3JvbGxWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogc3Rh'
    'cmZpdmVTY3JvbGwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMjQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBjb250ZW50V2lkdGg6IGF2YWlsYWJsZVdpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1u'
    'TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IHN0YXJmaXZlU2Nyb2xsLmF2YWls'
    'YWJsZVdpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE4CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiU3RhckZpdmUgwrcgSUtFdjIvSVBzZWMiOyBjb2xvcjog'
    'cm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6IDIwOyBmb250LndlaWdodDogRm9udC5Cb2xkIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi'
    '0KLQtdGB0YLQvtCy0YvQuSDQstGL0YXQvtC0INCyINC40L3RgtC10YDQvdC10YIg0YfQtdGA0LXQtyDQtNC+0LzQsNGI0L3Q'
    'uNC5IFN0YXJGaXZlINCyINCg0L7RgdGB0LjQuC4g0K3RgdGC0L7QvdGB0LrQuNC5INCy0YvRhdC+0LQg0L/QvtC60LAg0L3Q'
    'tSDQv9C+0LTQutC70Y7Rh9GR0L0uIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6'
    'IFRleHQuV29yZFdyYXA7IGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsgdGV4dDogItCf0L7QtNC60LvRjtGH0LXQvdC40LUg0LogU3RhckZpdmUiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9u'
    'dC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QuZXhwZXJp'
    'bWVudC5hY3RpdmUgPyAi0J/QvtC00LrQu9GO0YfQtdC90L4gwrcg0LLRi9GF0L7QtCDQoNC+0YHRgdC40Y8iIDogKHJvb3Qu'
    'ZXhwZXJpbWVudC5ndWFyZCA/ICLQodC+0LXQtNC40L3QtdC90LjQtSDQv9C+0YLQtdGA0Y/QvdC+IMK3INC40L3RgtC10YDQ'
    'vdC10YIg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9IiA6ICLQktGL0LrQu9GO0YfQtdC90L4iKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5leHBlcmltZW50LmFjdGl2ZSA/IHJvb3QuZ29v'
    'ZCA6IChyb290LmV4cGVyaW1lbnQuZ3VhcmQgPyByb290LmJhZCA6IHJvb3QudGV4dE11dGVkKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU3dpdGNoIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBjaGVja2VkOiBCb29sZWFuKHJvb3QuZXhwZXJpbWVudC5ndWFyZCkKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiAhcm9vdC5idXN5ICYmIChCb29sZWFuKHJvb3Qu'
    'ZXhwZXJpbWVudC5ndWFyZCkgfHwgKEJvb2xlYW4ocm9vdC5leHBlcmltZW50LmNvbmZpZ3VyZWQpICYmIEJvb2xlYW4ocm9v'
    'dC5leHBlcmltZW50LmF2YWlsYWJsZSkgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpKSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246IGNoZWNrZWQgPyAi'
    'ZXhwZXJpbWVudGFsX29uIiA6ICJleHBlcmltZW50YWxfb2ZmIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0KHQvdCw0YfQsNC7'
    '0LAg0LLRi9C60LvRjtGH0Lgg0L7QsdGL0YfQvdGL0LkgVlBOLiDQkiDRjdGC0L7QvCDRgNC10LbQuNC80LUgSVB2NiwgRElS'
    'RUNULdC40YHQutC70Y7Rh9C10L3QuNGPINC4INC00L7RgdGC0YPQvyDQuiDQu9C+0LrQsNC70YzQvdC+0Lkg0YHQtdGC0Lgg'
    '0LHQu9C+0LrQuNGA0YPRjtGC0YHRjy4g0J/RgNC4INC+0LHRgNGL0LLQtSDQuNC90YLQtdGA0L3QtdGCINC+0YHRgtCw0ZHR'
    'gtGB0Y8g0LfQsNC60YDRi9GC0YvQvCwg0L/QvtC60LAg0YLRiyDQvdC1INCy0YvQutC70Y7Rh9C40YjRjCDRgNC10LbQuNC8'
    'LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsgd3JhcE1v'
    'ZGU6IFRleHQuV29yZFdyYXA7IGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7IExheW91dC5maWxsV2lkdGg6IHRy'
    'dWU7IExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDE7IGNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFi'
    'ZWw6IHJvb3QuZXhwZXJpbWVudC5hdmFpbGFibGUgPyAiSUtFdjIg0LPQvtGC0L7QsiIgOiAi0J/QvtC00LPQvtGC0L7QstC4'
    '0YLRjCBJS0V2MiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290'
    'LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5leHBlcmltZW50LmF2YWlsYWJsZSkgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5hY3Rp'
    'dmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rp'
    'b246ICJleHBlcmltZW50YWxfcHJlcGFyZSJ9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBy'
    'b290LmV4cGVyaW1lbnQuY29uZmlndXJlZCA/ICLQn9C10YDRgdC+0L3QsNC70YzQvdGL0Lkg0L/RgNC+0YTQuNC70Ywg0YPR'
    'gdGC0LDQvdC+0LLQu9C10L0iIDogItCd0YPQttC10L0g0L/QtdGA0YHQvtC90LDQu9GM0L3Ri9C5INC/0YDQvtGE0LjQu9GM'
    'INGD0YHRgtGA0L7QudGB0YLQstCwIjsgY29sb3I6IHJvb3QuZXhwZXJpbWVudC5jb25maWd1cmVkID8gcm9vdC5nb29kIDog'
    'cm9vdC50ZXh0TXV0ZWQ7IHdyYXBNb2RlOiBUZXh0LldvcmRXcmFwIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IHN0YXJm'
    'aXZlUHJvZmlsZTsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgcGxhY2Vob2xkZXJUZXh0OiAifi9WcG4vU3RhckZpdmUvcHJv'
    'ZmlsZS5qc29uIjsgc2VsZWN0QnlNb3VzZTogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCY0LzQ'
    'v9C+0YDRgtC40YDQvtCy0LDRgtGMIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJs'
    'ZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5leHBlcmltZW50Lmd1YXJkKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4cGVyaW1lbnRh'
    'bF9pbXBvcnQiLCB0YXJnZXQ6IHN0YXJmaXZlUHJvZmlsZS50ZXh0LnRyaW0oKSB8fCAifi9WcG4vU3RhckZpdmUvcHJvZmls'
    'ZS5qc29uIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZTsgTGF5b3V0LnByZWZlcnJlZEhlaWdodDogMTsgY29sb3I6IHJvb3QuYm9yZGVyIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiAi0JLRgNC10LzQtdC90L3QsNGPINC00LjQsNCz0L3Q'
    'vtGB0YLQuNC60LAiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Td2l0Y2ggewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGNoZWNrZWQ6IEJvb2xlYW4ocm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSkKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiAhcm9vdC5idXN5ICYmIEJvb2xlYW4ocm9vdC5leHBl'
    'cmltZW50LmNvbmZpZ3VyZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2Vk'
    'OiByb290LmFjdGlvbih7YWN0aW9uOiBjaGVja2VkID8gImV4cGVyaW1lbnRhbF90ZWxlbWV0cnktb24iIDogImV4cGVyaW1l'
    'bnRhbF90ZWxlbWV0cnktb2ZmIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJl'
    'bCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0JrQsNC20LTRg9GOINC80LjQvdGD0YLRgyDQv9GA'
    '0L7QstC10YDRj9GO0YLRgdGPINCv0L3QtNC10LrRgSwgTWFpbCDQuCDQoNC+0YHRgtC10LvQtdC60L7QvC4g0J7RiNC40LHQ'
    'utC4INC/0L7QtNC60LvRjtGH0LXQvdC40Y8g0Lgg0YDQtdC30YPQu9GM0YLQsNGC0Ysg0YLQtdGB0YLQsCDQvtGC0L/RgNCw'
    '0LLQu9GP0Y7RgtGB0Y8g0L3QsNC/0YDRj9C80YPRjiDQvdCwIFN0YXJGaXZlINC/0L4gSFRUUFMg0YEg0L/QtdGA0YHQvtC9'
    '0LDQu9GM0L3Ri9C8INGB0LXRgNGC0LjRhNC40LrQsNGC0L7QvCwg0LTQsNC20LUg0L/RgNC4INC90LXRgNCw0LHQvtGC0LDR'
    'jtGJ0LXQvCBWUE4uINCi0L7Qu9GM0LrQviDRgdC70YPQttC10LHQvdGL0Lkg0LrQsNC90LDQuyDQvtCx0YXQvtC00LjRgiDQ'
    'sdC70L7QutC40YDQvtCy0LrRgyDQuNC90YLQtdGA0L3QtdGC0LAuINCd0LXQvtGC0L/RgNCw0LLQu9C10L3QvdGL0LUg0L7R'
    'gtGH0ZHRgtGLINGB0L7RhdGA0LDQvdGP0Y7RgtGB0Y8g0L3QsCDRg9GB0YLRgNC+0LnRgdGC0LLQtTsg0L/QvtC/0YvRgtC6'
    '0Lgg0L/QvtCy0YLQvtGA0Y/RjtGC0YHRjyDRgSDQv9Cw0YPQt9Cw0LzQuC4g0J/QsNGA0L7Qu9C4LCDQutC70Y7Rh9C4INC4'
    'INGB0L7QtNC10YDQttC40LzQvtC1INGC0YDQsNGE0LjQutCwINC90LUg0L7RgtC/0YDQsNCy0LvRj9GO0YLRgdGPLiDQpdGA'
    '0LDQvdC10L3QuNC1INC90LAg0YHQtdGA0LLQtdGA0LU6IDcg0LTQvdC10LkuINCh0LXRgNCy0LXRgCDQstC40LTQuNGCIElQ'
    'INGB0L7QtdC00LjQvdC10L3QuNGPOyDRjdGC0L4g0L/RgdC10LLQtNC+0L3QuNC80L3QsNGPINC00LjQsNCz0L3QvtGB0YLQ'
    'uNC60LAsINCwINC90LUg0L/QvtC70L3QsNGPINCw0L3QvtC90LjQvNC90L7RgdGC0YwuIgogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkOyB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcDsgZm9u'
    'dC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBs'
    'YWJlbDogItCe0YLQv9GA0LDQstC40YLRjCDQtNC40LDQs9C90L7RgdGC0LjQutGDINC90LDQv9GA0Y/QvNGD0Y4iCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIEJvb2xlYW4o'
    'cm9vdC5leHBlcmltZW50LmNvbmZpZ3VyZWQpICYmIEJvb2xlYW4ocm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSkKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4cGVy'
    'aW1lbnRhbF9zZW5kLWRpYWdub3N0aWNzIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0'
    'ZXh0OiAi0JTQvtGB0YLQsNCy0LrQsCDQvtGC0YfRkdGC0L7QsjogIiArICh7aWRsZToi0LXRidGRINC90LUg0LfQsNC/0YPR'
    'gdC60LDQu9Cw0YHRjCIscXVldWVkOiLQvtGC0YfRkdGCINCyINC+0YfQtdGA0LXQtNC4IixzZW5kaW5nOiLQvtGC0L/RgNCw'
    '0LLQu9GP0LXRgtGB0Y8iLHNlbnQ6ItC00L7RgdGC0LDQstC70LXQvSDQvdCwIFN0YXJGaXZlIixyZXRyeToi0L3QtSDQtNC+'
    '0YHRgtCw0LLQu9C10L07INC/0L7QstGC0L7RgNGP0LXQvCDRgSDQv9Cw0YPQt9Cw0LzQuCJ9W1N0cmluZygocm9vdC5leHBl'
    'cmltZW50LmRlbGl2ZXJ5IHx8IHt9KS5zdGF0dXMgfHwgImlkbGUiKV0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgKyAiLiDQkiDQvtGH0LXRgNC10LTQuDogIiArIE51bWJlcigocm9vdC5leHBlcmltZW50LmRlbGl2'
    'ZXJ5IHx8IHt9KS5wZW5kaW5nIHx8IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAo'
    'cm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSA/ICIiIDogIi4g0J7RgtC/0YDQsNCy0LrQsCDQstGL0LrQu9GO0YfQtdC90LAi'
    'KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsgKChyb290LmV4cGVyaW1lbnQuZGVsaXZl'
    'cnkgfHwge30pLmVycm9yID8gIi4g0J/RgNC40YfQuNC90LA6ICIgKyBTdHJpbmcocm9vdC5leHBlcmltZW50LmRlbGl2ZXJ5'
    'LmVycm9yKSA6ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11'
    'dGVkOyB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcDsgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IHN0YXJmaXZlRG9tYWluOyBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6ICLQlNC+0LzQtdC9INC90LXRgNCw0LHQvtGC0LDRjtGJ0LXQs9C+INGB0LDQudGC'
    '0LAsINC90LDQv9GA0LjQvNC10YAgeWFuZGV4LnJ1Ijsgc2VsZWN0QnlNb3VzZTogdHJ1ZSB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBsYWJlbDogItCf0YDQvtCy0LXRgNC40YLRjCDQuCDQvtGC0L/RgNCw0LLQuNGC0YwiCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiBCb29sZWFuKHJvb3Qu'
    'ZXhwZXJpbWVudC5hY3RpdmUpICYmIEJvb2xlYW4ocm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSkgJiYgc3RhcmZpdmVEb21h'
    'aW4udGV4dC50cmltKCkubGVuZ3RoID4gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9u'
    'Q2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImV4cGVyaW1lbnRhbF9yZXBvcnQiLCB0YXJnZXQ6IHN0YXJmaXZlRG9t'
    'YWluLnRleHQudHJpbSgpfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUg'
    'eyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAxOyBjb2xvcjogcm9vdC5ib3JkZXIg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCh0YLQsNCx0LjQu9GM0L3Q'
    'vtGB0YLRjCDRgNC+0YHRgdC40LnRgdC60L7Qs9C+INC80L7RgdGC0LAiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53'
    'ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQk9C70L7QsdCw0LvRjNC90YvQuSDRgtC10YHRgiDQt9Cw0LnQ'
    'vNGR0YIg0L/RgNC40LzQtdGA0L3QviA04oCTOCDQvNC40L3Rg9GCINC4INC00L4gMjAwINCc0LjQkSDRgtGA0LDRhNC40LrQ'
    'sC4g0JjQvdGC0LXRgNC90LXRgiDQvdC10YHQutC+0LvRjNC60L4g0YDQsNC3INC/0YDQtdGA0LLRkdGC0YHRjzog0L/RgNC+'
    '0LLQtdGA0Y/RjtGC0YHRjyDQv9C10YDQtdC/0L7QtNC60LvRjtGH0LXQvdC40Y8sINGE0LDQudC70Ysg0Lgg0LTQvtC60LDR'
    'h9C60LAsINC/0L7RgtC10YDQuCwg0L/RgNC+0YHRgtC+0Lkg0Lgg0L/QsNGA0LDQu9C70LXQu9GM0L3QsNGPINC90LDQs9GA'
    '0YPQt9C60LAuIEtpbGwgc3dpdGNoINC+0YHRgtCw0ZHRgtGB0Y8g0LLQutC70Y7Rh9GR0L3QvdGL0LwuINCf0YDQvtCy0LXR'
    'gNC60Lg6IFN0YXJGaXZlLCDQr9C90LTQtdC60YEsIE1haWwsINCg0L7RgdGC0LXQu9C10LrQvtC8LiDQmNGC0L7QsyDQvtGC'
    '0L/RgNCw0LLQuNGC0YHRjyDQvdCw0L/RgNGP0LzRg9GOINC/0L4gSFRUUFM7INC10YHQu9C4INGB0LXRgNCy0LXRgCDQvdC1'
    '0LTQvtGB0YLRg9C/0LXQvSwg0L7RgtGH0ZHRgiDQvtGB0YLQsNC90LXRgtGB0Y8g0LIg0L7Rh9C10YDQtdC00LguIgogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkOyB3cmFwTW9kZTogVGV4'
    'dC5Xb3JkV3JhcDsgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxh'
    'YmVsOiAi0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiBCb29sZWFuKHJvb3QuZXhwZXJpbWVudC5hY3RpdmUpICYm'
    'IEJvb2xlYW4ocm9vdC5leHBlcmltZW50LnRlbGVtZXRyeSkgJiYgU3RyaW5nKChyb290LmV4cGVyaW1lbnQudGVzdCB8fCB7'
    'fSkucGhhc2UpICE9PSAicnVubmluZyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNs'
    'aWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfZ2xvYmFsLXRlc3QifSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRC'
    'dXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J7RgdGC0LDQvdC+'
    '0LLQuNGC0Ywg0YLQtdGB0YIiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1'
    'dHRvbjogIXJvb3QuYnVzeSAmJiBTdHJpbmcoKHJvb3QuZXhwZXJpbWVudC50ZXN0IHx8IHt9KS5waGFzZSkgPT09ICJydW5u'
    'aW5nIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24o'
    'e2FjdGlvbjogImV4cGVyaW1lbnRhbF9jYW5jZWwtdGVzdCJ9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIEMuUHJvZ3Jlc3NCYXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZnJvbTogMDsgdG86IDEw'
    'MDsgdmFsdWU6IE51bWJlcigocm9vdC5leHBlcmltZW50LnRlc3QgfHwge30pLnByb2dyZXNzIHx8IDApCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBTdHJpbmcoKHJvb3QuZXhwZXJpbWVudC50ZXN0IHx8IHt9'
    'KS5waGFzZSkgPT09ICJydW5uaW5nIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDog'
    'U3RyaW5nKChyb290LmV4cGVyaW1lbnQudGVzdCB8fCB7fSkubWVzc2FnZSB8fCAi0KLQtdGB0YIg0LXRidGRINC90LUg0LfQ'
    'sNC/0YPRgdC60LDQu9GB0Y8iKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsgKChyb290'
    'LmV4cGVyaW1lbnQudGVzdCB8fCB7fSkucGFzc2VkICE9PSB1bmRlZmluZWQgPyAiINCf0YDQvtCy0LXRgNC+0Log0YPRgdC/'
    '0LXRiNC90L46ICIgKyAocm9vdC5leHBlcmltZW50LnRlc3QgfHwge30pLnBhc3NlZCArICI7INGB0L4g0YHQsdC+0Y/QvNC4'
    'OiAiICsgKHJvb3QuZXhwZXJpbWVudC50ZXN0IHx8IHt9KS5mYWlsZWQgKyAiLiIgOiAiIikKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogItCf0L7RgdC70LXQtNC90LjQuSDQvtGC0YfRkdGCOiAi'
    'ICsgU3RyaW5nKHJvb3QuZXhwZXJpbWVudC5sYXN0X3JlcG9ydCB8fCAi0LXRidGRINC90LUg0L7RgtC/0YDQsNCy0LvQtdC9'
    'Iik7IGNvbG9yOiByb290LnRleHRNdXRlZDsgd3JhcE1vZGU6IFRleHQuV29yZFdyYXA7IGZvbnQucGl4ZWxTaXplOiAxMiB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0'
    'ZXh0OiBTdHJpbmcocm9vdC5leHBlcmltZW50Lmxhc3RfZXJyb3IgfHwgIiIpOyBjb2xvcjogcm9vdC5iYWQ7IHdyYXBNb2Rl'
    'OiBUZXh0LldvcmRXcmFwIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0K'
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
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        input=input_text,
        timeout=timeout,
    )

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
                       waydroid_iface: str = WAYDROID_IFACE) -> str:
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
        ],
        "outbounds": [
            proxy,
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

def install_guard(settings: dict) -> None:
    uid = int(settings["xray_uid"])
    tcp_ports, udp_ports = _server_port_sets(settings)
    waydroid_direct = not bool(settings.get("waydroid_vpn_enabled", True))
    rules = render_guard_rules(
        uid, tcp_ports, udp_ports,
        waydroid_direct=waydroid_direct,
        waydroid_iface=WAYDROID_IFACE,
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
    activate(settings, profile_path)
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
    return wait_service()

def activate(settings: dict, path: pathlib.Path) -> None:
    if starfive.active_guard():
        fail("Сначала выключи экспериментальный StarFive VPN.")
    old_state = load_state()
    old_config = RUNTIME_CONFIG.read_bytes() if RUNTIME_CONFIG.exists() else None
    was_active = service_active()

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
            healthy, _ = health_check_v4()
            if healthy:
                save_state(old_state)
                fail(
                    "Новый конфиг не работает; предыдущий VPN восстановлен.\n"
                    f"Причина: {failure_reason}\n" + log[-5000:]
                )
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


def _status_payload(settings: dict) -> dict:
    exp = starfive.status()
    st = load_state()
    active = service_active()
    return {
        "manager": MANAGER_VERSION,
        "active": active or exp["active"],
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
    active_now = service_active()
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

def operation_requires_lock(args) -> bool:
    return (args.cmd in {"on", "switch", "off", "toggle", "reload-rules",
                         "core-update", "update", "manager-rollback", "direct",
                         "app", "port", "diagnostic", "experimental"}
            or (args.cmd == "ui" and getattr(args, "ui_cmd", None) == "action"))

STARFIVE_EXPERIMENTAL_PY_B64 = (
    'IiIiT3B0LWluIElLRXYyIGJhY2tlbmQuIEVtYmVkZGVkIGluIHZwbmN0bCByZWxlYXNlczsgbm8gaW1wb3J0LXRpbWUgc2lk'
    'ZSBlZmZlY3RzLiIiIgppbXBvcnQgaGFzaGxpYgppbXBvcnQgaXBhZGRyZXNzCmltcG9ydCBqc29uCmltcG9ydCBvcwppbXBv'
    'cnQgcGF0aGxpYgppbXBvcnQgcmUKaW1wb3J0IHNodXRpbAppbXBvcnQgc29ja2V0CmltcG9ydCBzc2wKaW1wb3J0IHN1YnBy'
    'b2Nlc3MKaW1wb3J0IHRpbWUKaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCB1cmxsaWIuZXJyb3IKaW1wb3J0IGh0dHAu'
    'Y2xpZW50CmltcG9ydCB1dWlkCmltcG9ydCBmY250bAoKUk9PVCA9IHBhdGhsaWIuUGF0aCgiL2V0Yy92cG4tbWFuYWdlci9z'
    'dGFyZml2ZSIpClNUQVRFID0gcGF0aGxpYi5QYXRoKCIvdmFyL2xpYi92cG4tbWFuYWdlci9zdGFyZml2ZS5qc29uIikKUlVO'
    'VElNRSA9IHBhdGhsaWIuUGF0aCgiL3J1bi9ldmdlbml1bS1pa2V2MiIpClVOSVQgPSAiZXZnZW5pdW0taWtldjIuc2Vydmlj'
    'ZSIKTU9OSVRPUiA9ICJldmdlbml1bS1pa2V2Mi1kaWFnbm9zdGljLnNlcnZpY2UiCkdVQVJEID0gImV2Z2VuaXVtLWlrZXYy'
    'LWd1YXJkLnNlcnZpY2UiClRBQkxFID0gImV2Z2VuaXVtX2lrZXYyX2d1YXJkIgpVUkkgPSAidW5peDovLy9ydW4vZXZnZW5p'
    'dW0taWtldjIvY2hhcm9uLnZpY2kiClNFUlZFUiA9ICIxMDkuMTk0LjY3LjE1OSIKSEVBTFRIID0gImh0dHBzOi8vMTAuNzcu'
    'MC4xOjg0NDMiClJFUUlEID0gNzcKRElSRUNUX1BPUlQgPSA4NDQzCkRJUkVDVF9NQVJLID0gMHhFNzcxCkRFTElWRVJZID0g'
    'ImV2Z2VuaXVtLWlrZXYyLWRlbGl2ZXJ5LnNlcnZpY2UiCgoKZGVmIGZhaWx1cmVfY29kZShleGMpOgogICAgdGV4dCA9IHN0'
    'cihleGMpLmxvd2VyKCkKICAgIGlmIGlzaW5zdGFuY2UoZXhjLCBzc2wuU1NMQ2VydFZlcmlmaWNhdGlvbkVycm9yKTogcmV0'
    'dXJuICdjZXJ0aWZpY2F0ZScKICAgIGlmIGlzaW5zdGFuY2UoZXhjLCBzc2wuU1NMRXJyb3IpOiByZXR1cm4gJ3RscycKICAg'
    'IGlmIGlzaW5zdGFuY2UoZXhjLCAoVGltZW91dEVycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSk6IHJldHVybiAn'
    'dGltZW91dCcKICAgIGlmICdjZXJ0aWZpY2F0ZScgaW4gdGV4dCBvciAnYXV0aGVudGljYXRpb24nIGluIHRleHQ6IHJldHVy'
    'biAnYXV0aGVudGljYXRpb24nCiAgICBpZiAncHJvcG9zYWwnIGluIHRleHQ6IHJldHVybiAncHJvcG9zYWwnCiAgICBpZiAn'
    'cmV0cmFuc21pdCcgaW4gdGV4dCBvciAndGltZWQgb3V0JyBpbiB0ZXh0OiByZXR1cm4gJ3RpbWVvdXQnCiAgICBpZiAncGVy'
    'bWlzc2lvbicgaW4gdGV4dCBvciAnb3BlcmF0aW9uIG5vdCBwZXJtaXR0ZWQnIGluIHRleHQ6IHJldHVybiAncGVybWlzc2lv'
    'bicKICAgIGlmIGlzaW5zdGFuY2UoZXhjLCBPU0Vycm9yKTogcmV0dXJuICduZXR3b3JrJwogICAgcmV0dXJuICdvdGhlcicK'
    'CgpkZWYgcXVldWVfY29ubmVjdGlvbihzdGFnZSwgZXJyb3IsIGVsYXBzZWQ9MCk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0'
    'KCd0ZWxlbWV0cnknKTogcmV0dXJuCiAgICBkaXJlY3RvcnkgPSBST09UIC8gJ291dGJveCcKICAgIGRpcmVjdG9yeS5ta2Rp'
    'cihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBmaWxlcyA9IHNvcnRlZChkaXJlY3Rvcnku'
    'Z2xvYignKi5qc29uJyksIGtleT1sYW1iZGEgcDogcC5zdGF0KCkuc3RfbXRpbWUpCiAgICBmb3Igb2xkIGluIGZpbGVzWzot'
    'OV06IG9sZC51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgcmVwb3J0X2lkID0gdXVpZC51dWlkNCgpLmhleAogICAgYm9k'
    'eSA9IHsnc2NoZW1hJzoxLCAnZXZlbnQnOidjb25uZWN0aW9uX2RpYWdub3N0aWMnLCAnbWFuYWdlcic6JzAuMi4yMicsCiAg'
    'ICAgICAgICAgICd0aW1lJzppbnQodGltZS50aW1lKCkpLAogICAgICAgICAgICAncmVwb3J0X2lkJzpyZXBvcnRfaWQsICdz'
    'dGFnZSc6c3RhZ2UsICdlcnJvcic6ZXJyb3IsCiAgICAgICAgICAgICdlbGFwc2VkX21zJzptaW4oMTgwMDAwMCwgbWF4KDAs'
    'IGludChlbGFwc2VkKSkpLAogICAgICAgICAgICAnZ3VhcmQnOmFjdGl2ZV9ndWFyZCgpLCAnaXBzZWMnOmNvbm5lY3RlZCgp'
    'fQogICAgdHJ5OgogICAgICAgICMgU2VuZCBjb3VudHMgYW5kIGZpeGVkIGNhdGVnb3JpZXMsIG5ldmVyIHJhdyBqb3VybmFs'
    'IGxpbmVzIG9yIGFkZHJlc3Nlcy4KICAgICAgICBqb3VybmFsPWNtZChbJ2pvdXJuYWxjdGwnLCctdScsVU5JVCwnLS1zaW5j'
    'ZScsJzIgbWludXRlcyBhZ28nLCctbicsJzgwJywnLS1uby1wYWdlciddLGNoZWNrPUZhbHNlLHRpbWVvdXQ9Mykuc3Rkb3V0'
    'Lmxvd2VyKCkKICAgICAgICBib2R5LnVwZGF0ZShpa2VfcmVjZWl2ZWQ9am91cm5hbC5jb3VudCgncmVjZWl2ZWQgcGFja2V0'
    'OicpLAogICAgICAgICAgICAgICAgICAgIGlrZV9zZW50PWpvdXJuYWwuY291bnQoJ3NlbmRpbmcgcGFja2V0OicpLAogICAg'
    'ICAgICAgICAgICAgICAgIHJldHJhbnNtaXRzPWpvdXJuYWwuY291bnQoJ3JldHJhbnNtaXQnKSkKICAgICAgICBpZiBlcnJv'
    'ciA9PSAnb3RoZXInOgogICAgICAgICAgICBpZiAnYXV0aGVudGljYXRpb24nIGluIGpvdXJuYWwgYW5kICdmYWlsZWQnIGlu'
    'IGpvdXJuYWw6IGJvZHlbJ2Vycm9yJ109J2F1dGhlbnRpY2F0aW9uJwogICAgICAgICAgICBlbGlmICdubyBwcm9wb3NhbCcg'
    'aW4gam91cm5hbDogYm9keVsnZXJyb3InXT0ncHJvcG9zYWwnCiAgICAgICAgb3NfcmVsZWFzZT1wYXRobGliLlBhdGgoJy9l'
    'dGMvb3MtcmVsZWFzZScpLnJlYWRfdGV4dCgpLmxvd2VyKCkKICAgICAgICBib2R5WydwbGF0Zm9ybSddPSdzdGVhbW9zJyBp'
    'ZiAnc3RlYW1vcycgaW4gb3NfcmVsZWFzZSBlbHNlICgnZmVkb3JhJyBpZiAnZmVkb3JhJyBpbiBvc19yZWxlYXNlIGVsc2Ug'
    'KCdhcmNoJyBpZiAnYXJjaCcgaW4gb3NfcmVsZWFzZSBlbHNlICdvdGhlcicpKQogICAgZXhjZXB0IEV4Y2VwdGlvbjogcGFz'
    'cwogICAgd3JpdGUoZGlyZWN0b3J5IC8gKHJlcG9ydF9pZCArICcuanNvbicpLCBqc29uLmR1bXBzKGJvZHkpKQogICAgcGF0'
    'Y2hfc3RhdGUoeyAnZGVsaXZlcnlfc3RhdHVzJzoncXVldWVkJywgJ2RlbGl2ZXJ5X2Vycm9yJzonJ30pCiAgICBraWNrX2Rl'
    'bGl2ZXJ5KCkKCgpkZWYga2lja19kZWxpdmVyeSgpOgogICAgaWYgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKToKICAgICAg'
    'ICBjbWQoWydzeXN0ZW1jdGwnLCdzdGFydCcsJy0tbm8tYmxvY2snLERFTElWRVJZXSwgY2hlY2s9RmFsc2UpCgoKZGVmIGRp'
    'cmVjdF9lbmRwb2ludChib2R5KToKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCxwYXJlbnRzPVRydWUsZXhpc3Rfb2s9VHJ1'
    'ZSkKICAgIHdpdGggKFJPT1QvImRlbGl2ZXJ5LmxvY2siKS5vcGVuKCJhIikgYXMgbG9jazoKICAgICAgICBmY250bC5mbG9j'
    'ayhsb2NrLGZjbnRsLkxPQ0tfRVgpCiAgICAgICAgcmV0dXJuIF9kaXJlY3RfZW5kcG9pbnQoYm9keSkKCgpkZWYgX2RpcmVj'
    'dF9lbmRwb2ludChib2R5KToKICAgICMgT25seSB0aGlzIHJvb3Qtb3duZWQgc29ja2V0IGNhbiBieXBhc3MgdGhlIGd1YXJk'
    'OyBuZXZlciBlbnZpcm9ubWVudCBwcm94aWVzLgogICAgIyBUaGUgbWFya2VkIHNvY2tldCBzZWxlY3RzIHRoZSBwaHlzaWNh'
    'bCByb3V0ZSBiZWZvcmUgSVBzZWMgc291cmNlIHNlbGVjdGlvbi4KICAgIHNvY2sgPSBOb25lCiAgICBjb25uZWN0aW9uID0g'
    'Tm9uZQogICAgc3RhZ2UgPSAnY3JlZGVudGlhbHMnCiAgICB0cnk6CiAgICAgICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVm'
    'YXVsdF9jb250ZXh0KGNhZmlsZT1zdHIoUk9PVCAvICdjYS5wZW0nKSkKICAgICAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFp'
    'bihzdHIoUk9PVCAvICdjbGllbnQucGVtJyksc3RyKFJPT1QgLyAnY2xpZW50LWtleS5wZW0nKSkKICAgICAgICBzdGFnZSA9'
    'ICdyb3V0ZScKICAgICAgICBydWxlPVsncHJpb3JpdHknLCc5MCcsJ2Z3bWFyaycsc3RyKERJUkVDVF9NQVJLKSwndG8nLFNF'
    'UlZFUisnLzMyJywnbG9va3VwJywnbWFpbiddCiAgICAgICAgIyBDbGVhbiB1cCBhbiBleGFjdCBzdGFsZSBydWxlIGxlZnQg'
    'YnkgcHJvY2VzcyB0ZXJtaW5hdGlvbiBiZWZvcmUgYWRkaW5nIGl0LgogICAgICAgIGNtZChbJ2lwJywncnVsZScsJ2RlbCcs'
    'KnJ1bGVdLGNoZWNrPUZhbHNlKQogICAgICAgIGNtZChbJ2lwJywncnVsZScsJ2FkZCcsKnJ1bGVdKQogICAgICAgIHNvY2sg'
    'PSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgc3RhZ2UgPSAndGNw'
    'JwogICAgICAgIHNvY2suc2V0dGltZW91dCg2KQogICAgICAgIHNvY2suc2V0c29ja29wdChzb2NrZXQuU09MX1NPQ0tFVCwg'
    'c29ja2V0LlNPX01BUkssIERJUkVDVF9NQVJLKQogICAgICAgIHNvY2suY29ubmVjdCgoU0VSVkVSLERJUkVDVF9QT1JUKSkK'
    'ICAgICAgICBzdGFnZSA9ICd0bHMnCiAgICAgICAgdGxzID0gY29udGV4dC53cmFwX3NvY2tldChzb2NrLHNlcnZlcl9ob3N0'
    'bmFtZT1TRVJWRVIpCiAgICAgICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKFNFUlZFUixESVJF'
    'Q1RfUE9SVCx0aW1lb3V0PTYpCiAgICAgICAgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAgICAgICAgc3RhZ2UgPSAnaHR0cCcK'
    'ICAgICAgICBkYXRhID0ganNvbi5kdW1wcyhib2R5LHNlcGFyYXRvcnM9KCcsJywnOicpKS5lbmNvZGUoKQogICAgICAgIGNv'
    'bm5lY3Rpb24ucmVxdWVzdCgnUE9TVCcsJy9yZXBvcnQnLGJvZHk9ZGF0YSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'aGVhZGVycz17J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nLCdDb25uZWN0aW9uJzonY2xvc2UnfSkKICAgICAg'
    'ICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgIHJlcGx5ID0ganNvbi5sb2FkcyhyZXNwb25z'
    'ZS5yZWFkKDQwOTYpKQogICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDAgb3IgcmVwbHkuZ2V0KCdhY2NlcHRlZCcp'
    'IGlzIG5vdCBUcnVlOgogICAgICAgICAgICBlcnJvcj1SdW50aW1lRXJyb3IoJ1JlcG9ydCByZWplY3RlZCcpCiAgICAgICAg'
    'ICAgIGVycm9yLmRlbGl2ZXJ5X2NvZGU9ezQwMzonZGlzYWJsZWQnLDQwMDonaW52YWxpZF9yZXBvcnQnfS5nZXQocmVzcG9u'
    'c2Uuc3RhdHVzLCdyZWplY3RlZCcpCiAgICAgICAgICAgIHJhaXNlIGVycm9yCiAgICAgICAgaWYgYm9keS5nZXQoJ3JlcG9y'
    'dF9pZCcpIGFuZCByZXBseS5nZXQoJ3JlcG9ydF9pZCcpICE9IGJvZHlbJ3JlcG9ydF9pZCddOgogICAgICAgICAgICBlcnJv'
    'cj1SdW50aW1lRXJyb3IoJ0Fja25vd2xlZGdlbWVudCBtaXNtYXRjaCcpCiAgICAgICAgICAgIGVycm9yLmRlbGl2ZXJ5X2Nv'
    'ZGU9J2Fja19taXNtYXRjaCcKICAgICAgICAgICAgcmFpc2UgZXJyb3IKICAgICAgICByZXR1cm4gcmVwbHkKICAgIGV4Y2Vw'
    'dCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgIHBhdGNoX3N0YXRlKHsgJ2RlbGl2ZXJ5X3N0YXR1cyc6J3JldHJ5JywKICAg'
    'ICAgICAgICAgICAnZGVsaXZlcnlfZXJyb3InOnN0YWdlKydfJytnZXRhdHRyKGV4YywnZGVsaXZlcnlfY29kZScsZmFpbHVy'
    'ZV9jb2RlKGV4YykpfSkKICAgICAgICByYWlzZQogICAgZmluYWxseToKICAgICAgICBpZiBjb25uZWN0aW9uOiBjb25uZWN0'
    'aW9uLmNsb3NlKCkKICAgICAgICBpZiBzb2NrOiBzb2NrLmNsb3NlKCkKICAgICAgICAjIFJlbW92ZSBvdXIgZXhhY3Qgc2Nv'
    'cGVkIHJ1bGUsIGluY2x1ZGluZyBvbiBmYWlsZWQgVENQL1RMUyBoYW5kc2hha2VzLgogICAgICAgIGNtZChbJ2lwJywncnVs'
    'ZScsJ2RlbCcsJ3ByaW9yaXR5JywnOTAnLCdmd21hcmsnLHN0cihESVJFQ1RfTUFSSyksCiAgICAgICAgICAgICAndG8nLFNF'
    'UlZFUisnLzMyJywnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQoKCmRlZiBkZWxpdmVyX3JlcG9ydChib2R5KToKICAg'
    'IGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOiByZXR1cm4gRmFsc2UKICAgIHBhdGNoX3N0YXRlKHsgJ2RlbGl2'
    'ZXJ5X3N0YXR1cyc6J3NlbmRpbmcnLCAnZGVsaXZlcnlfYXR0ZW1wdCc6aW50KHRpbWUudGltZSgpKX0pCiAgICBib2R5PXsq'
    'KmJvZHksICdwcmV2aW91c19kZWxpdmVyeV9lcnJvcic6c3RvcmVkKCkuZ2V0KCdkZWxpdmVyeV9lcnJvcicsJycpfQogICAg'
    'ZGlyZWN0X2VuZHBvaW50KGJvZHkpCiAgICBwYXRjaF9zdGF0ZSh7ICdkZWxpdmVyeV9zdGF0dXMnOidzZW50JywgJ2RlbGl2'
    'ZXJ5X2Vycm9yJzonJywKICAgICAgICAgICdsYXN0X3JlcG9ydCc6dGltZS5zdHJmdGltZSgnJVktJW0tJWQgJUg6JU06JVMg'
    'VVRDJyx0aW1lLmdtdGltZSgpKX0pCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBkZWxpdmVyeV93b3JrZXIoKToKICAgIGRlbGF5'
    'PTE1CiAgICB3aGlsZSBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOgogICAgICAgIGZpbGVzPWxpc3QoKFJPT1QvJ291dGJv'
    'eCcpLmdsb2IoJyouanNvbicpKQogICAgICAgIGlmIG5vdCBmaWxlcyBhbmQgbm90IFBFTkRJTkdfVEVTVC5leGlzdHMoKTog'
    'cmV0dXJuCiAgICAgICAgdHJ5OgogICAgICAgICAgICBmb3IgcGF0aCBpbiBmaWxlczoKICAgICAgICAgICAgICAgIGlmIGRl'
    'bGl2ZXJfcmVwb3J0KGpzb24ubG9hZHMocGF0aC5yZWFkX3RleHQoKSkpOiBwYXRoLnVubGluayhtaXNzaW5nX29rPVRydWUp'
    'CiAgICAgICAgICAgIGZsdXNoX3Rlc3RfcmVwb3J0KCkKICAgICAgICAgICAgZGVsYXk9MTUKICAgICAgICBleGNlcHQgRXhj'
    'ZXB0aW9uOgogICAgICAgICAgICB0aW1lLnNsZWVwKGRlbGF5KQogICAgICAgICAgICBkZWxheT1taW4oZGVsYXkqMiwzMDAp'
    'CgoKZGVmIGNtZChhcmdzLCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUpOgogICAgY3AgPSBzdWJwcm9jZXNz'
    'LnJ1bihbc3RyKHgpIGZvciB4IGluIGFyZ3NdLCBpbnB1dD1kYXRhLCB0ZXh0PVRydWUsCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsIHRpbWVvdXQ9dGltZW91dCkKICAg'
    'IGlmIGNoZWNrIGFuZCBjcC5yZXR1cm5jb2RlOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigoY3Auc3RkZXJyIG9yIGNw'
    'LnN0ZG91dCBvciAiY29tbWFuZCBmYWlsZWQiKVstMTIwMDpdKQogICAgcmV0dXJuIGNwCgoKZGVmIHdyaXRlKHBhdGgsIGRh'
    'dGEsIG1vZGU9MG82MDApOgogICAgcGF0aCA9IHBhdGhsaWIuUGF0aChwYXRoKQogICAgcGF0aC5wYXJlbnQubWtkaXIobW9k'
    'ZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgdG1wID0gcGF0aC53aXRoX3N1ZmZpeChwYXRoLnN1'
    'ZmZpeCArICIubmV3IikKICAgIGZkID0gb3Mub3Blbih0bXAsIG9zLk9fV1JPTkxZIHwgb3MuT19DUkVBVCB8IG9zLk9fVFJV'
    'TkMgfCBvcy5PX05PRk9MTE9XLCBtb2RlKQogICAgd2l0aCBvcy5mZG9wZW4oZmQsICJ3IikgYXMgZjoKICAgICAgICBmLndy'
    'aXRlKGRhdGEpCiAgICB0bXAuY2htb2QobW9kZSkKICAgIHRtcC5yZXBsYWNlKHBhdGgpCgoKZGVmIHN0b3JlZCgpOgogICAg'
    'dHJ5OgogICAgICAgIHJldHVybiBqc29uLmxvYWRzKFNUQVRFLnJlYWRfdGV4dCgpKQogICAgZXhjZXB0IChPU0Vycm9yLCBW'
    'YWx1ZUVycm9yKToKICAgICAgICByZXR1cm4ge30KCgpkZWYgc2F2ZShzdGF0ZSk6CiAgICB3cml0ZShTVEFURSwganNvbi5k'
    'dW1wcyhzdGF0ZSwgZW5zdXJlX2FzY2lpPUZhbHNlKSArICJcbiIpCgoKZGVmIHBhdGNoX3N0YXRlKGNoYW5nZXMpOgogICAg'
    'IyBLZWVwIHNlbmRlciB1cGRhdGVzIGZyb20gb3ZlcndyaXRpbmcgYSBjb25jdXJyZW50IHRlbGVtZXRyeS1vZmYgb3BlcmF0'
    'aW9uLgogICAgUk9PVC5ta2Rpcihtb2RlPTBvNzAwLHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd2l0aCAoUk9P'
    'VC8nc3RhdGUubG9jaycpLm9wZW4oJ2EnKSBhcyBsb2NrOgogICAgICAgIGZjbnRsLmZsb2NrKGxvY2ssZmNudGwuTE9DS19F'
    'WCkKICAgICAgICBzYXZlKHsqKnN0b3JlZCgpLCoqY2hhbmdlc30pCgoKZGVmIGFjdGl2ZV9ndWFyZCgpOgogICAgaWYgbm90'
    'IHNodXRpbC53aGljaCgibmZ0Iik6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICByZXR1cm4gY21kKFsibmZ0IiwgImxpc3Qi'
    'LCAidGFibGUiLCAiaW5ldCIsIFRBQkxFXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMAoKCmRlZiBzd2FuKCphcmdz'
    'LCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwKToKICAgIGJpbmFyeSA9IHNodXRpbC53aGljaCgic3dhbmN0bCIpIG9yICIvdXNy'
    'L3NiaW4vc3dhbmN0bCIKICAgIHJldHVybiBjbWQoW2JpbmFyeSwgKmFyZ3MsICItLXVyaSIsIFVSSV0sIGNoZWNrPWNoZWNr'
    'LCB0aW1lb3V0PXRpbWVvdXQpCgoKZGVmIGNvbm5lY3RlZCgpOgogICAgaWYgbm90IFJVTlRJTUUuam9pbnBhdGgoImNoYXJv'
    'bi52aWNpIikuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICB0cnk6CiAgICAgICAgY3AgPSBzd2FuKCItLWxp'
    'c3Qtc2FzIiwgIi0tcmF3IiwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MykKICAgICAgICByZXR1cm4gY3AucmV0dXJuY29kZSA9'
    'PSAwIGFuZCAic3RhdGU9SU5TVEFMTEVEIiBpbiBjcC5zdGRvdXQgYW5kICJzdGF0ZT1FU1RBQkxJU0hFRCIgaW4gY3Auc3Rk'
    'b3V0CiAgICBleGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgIHJldHVybiBGYWxz'
    'ZQoKCmRlZiBzdGF0dXMoKToKICAgIHN0YXRlID0gc3RvcmVkKCkKICAgIGd1YXJkID0gYWN0aXZlX2d1YXJkKCkKICAgIGxp'
    'dmUgPSBjb25uZWN0ZWQoKQogICAgcmV0dXJuIHsiY29uZmlndXJlZCI6IFJPT1Quam9pbnBhdGgoInByb2ZpbGUuanNvbiIp'
    'LmV4aXN0cygpLAogICAgICAgICAgICAiYXZhaWxhYmxlIjogYm9vbChzaHV0aWwud2hpY2goInN3YW5jdGwiKSksCiAgICAg'
    'ICAgICAgICJhY3RpdmUiOiBsaXZlLCAiZ3VhcmQiOiBndWFyZCwKICAgICAgICAgICAgInRlbGVtZXRyeSI6IGJvb2woc3Rh'
    'dGUuZ2V0KCJ0ZWxlbWV0cnkiLCBGYWxzZSkpLAogICAgICAgICAgICAicGhhc2UiOiAiY29ubmVjdGVkIiBpZiBsaXZlIGVs'
    'c2UgKCJibG9ja2VkIiBpZiBndWFyZCBlbHNlICJvZmYiKSwKICAgICAgICAgICAgInNlcnZlciI6IFNFUlZFUiwgImVncmVz'
    'cyI6ICLQoNC+0YHRgdC40Y8g4oCUINGC0LXRgdGC0L7QstGL0Lkg0LLRi9GF0L7QtCIsCiAgICAgICAgICAgICJsYXN0X3Jl'
    'cG9ydCI6IHN0YXRlLmdldCgibGFzdF9yZXBvcnQiLCAiIiksCiAgICAgICAgICAgICJsYXN0X2Vycm9yIjogc3RhdGUuZ2V0'
    'KCJsYXN0X2Vycm9yIiwgIiIpLAogICAgICAgICAgICAiZGVsaXZlcnkiOiB7InN0YXR1cyI6c3RhdGUuZ2V0KCdkZWxpdmVy'
    'eV9zdGF0dXMnLCdpZGxlJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAiZXJyb3IiOnN0YXRlLmdldCgnZGVsaXZlcnlf'
    'ZXJyb3InLCcnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICJhdHRlbXB0IjpzdGF0ZS5nZXQoJ2RlbGl2ZXJ5X2F0dGVt'
    'cHQnLDApLAogICAgICAgICAgICAgICAgICAgICAgICAgInBlbmRpbmciOmxlbihsaXN0KChST09ULydvdXRib3gnKS5nbG9i'
    'KCcqLmpzb24nKSkpICsgaW50KFBFTkRJTkdfVEVTVC5leGlzdHMoKSl9LAogICAgICAgICAgICAidGVzdCI6IHRlc3Rfc3Rh'
    'dHVzKCksCiAgICAgICAgICAgICJwcm9maWxlX3BhdGgiOiAifi9WcG4vU3RhckZpdmUvcHJvZmlsZS5qc29uIn0KCgpkZWYg'
    'dmFsaWRhdGVfcHJvZmlsZShwKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHAsIGRpY3QpIG9yIHAuZ2V0KCJzY2hlbWEiKSAh'
    'PSAxIG9yIHAuZ2V0KCJzZXJ2ZXIiKSAhPSBTRVJWRVI6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J7QttC40LTQsNC1'
    '0YLRgdGPINC/0LXRgNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvRjCBTdGFyRml2ZSBzY2hlbWE9MS4iKQogICAg'
    'aWYgbm90IHJlLmZ1bGxtYXRjaChyImRldmljZS1bYS1mMC05XXsyNH0iLCBzdHIocC5nZXQoImlkZW50aXR5IiwgIiIpKSk6'
    'CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC40LTQtdC90YLQuNGE0LjQutCw'
    '0YLQvtGAINGD0YHRgtGA0L7QudGB0YLQstCwLiIpCiAgICBmb3IgZmllbGQsIG1hcmtlciBpbiAoKCJjYSIsICJDRVJUSUZJ'
    'Q0FURSIpLCAoImNlcnRpZmljYXRlIiwgIkNFUlRJRklDQVRFIiksCiAgICAgICAgICAgICAgICAgICAgICAgICAgKCJwcml2'
    'YXRlX2tleSIsICJQUklWQVRFIEtFWSIpKToKICAgICAgICBzID0gcC5nZXQoZmllbGQpCiAgICAgICAgaWYgbm90IGlzaW5z'
    'dGFuY2Uocywgc3RyKSBvciBsZW4ocykgPiAzMjc2OCBvciAoIi0tLS0tQkVHSU4gIiArIG1hcmtlciArICItLS0tLSIpIG5v'
    'dCBpbiBzOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0LUg0LTQsNC90L3R'
    'i9C1INGB0LXRgNGC0LjRhNC40LrQsNGC0L7Qsi4iKQogICAgcmV0dXJuIHAKCgpkZWYgaW1wb3J0X3Byb2ZpbGUoc2V0dGlu'
    'Z3MsIG5hbWUpOgogICAgaWYgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw'
    '0LvQsCDQstGL0LrQu9GO0YfQuCDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1INGB0L7QtdC00LjQvdC10L3Q'
    'uNC1LiIpCiAgICBwYXRoID0gcGF0aGxpYi5QYXRoKG5hbWUpLmV4cGFuZHVzZXIoKQogICAgaWYgbmFtZS5zdGFydHN3aXRo'
    'KCJ+LyIpOgogICAgICAgIHBhdGggPSBwYXRobGliLlBhdGgoc2V0dGluZ3NbIm93bmVyX2hvbWUiXSkgLyBuYW1lWzI6XQog'
    'ICAgaW1wb3J0IHB3ZAogICAgdWlkID0gcHdkLmdldHB3bmFtKHN0cihzZXR0aW5nc1sib3duZXJfdXNlciJdKSkucHdfdWlk'
    'CiAgICAjIE5ldmVyIGxldCBhIHBhc3N3b3JkbGVzcyBzdWRvIGFjdGlvbiByZWFkIGEgcm9vdCBzZWNyZXQgb3IgYSBzcGVj'
    'aWFsIGZpbGUuCiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PTkJMT0NLIHwgb3MuT19OT0ZP'
    'TExPVykKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAicmIiKSBhcyBmOgogICAgICAgIHN0ID0gb3MuZnN0YXQoZi5maWxlbm8o'
    'KSkKICAgICAgICBpbXBvcnQgc3RhdAogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSkgb3Igc3Quc3Rf'
    'dWlkICE9IHVpZCBvciBzdC5zdF9zaXplID4gMTEwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCf0YDQ'
    'vtGE0LjQu9GMINC00L7Qu9C20LXQvSDQsdGL0YLRjCDQvtCx0YvRh9C90YvQvCDRhNCw0LnQu9C+0Lwg0LLQu9Cw0LTQtdC7'
    '0YzRhtCwINC60LvQuNC10L3RgtCwLCDQvdC1INCx0L7Qu9C10LUgMTEwINCa0JEuIikKICAgICAgICBwID0gdmFsaWRhdGVf'
    'cHJvZmlsZShqc29uLmxvYWRzKGYucmVhZCgxMTAwMDEpKSkKICAgIGltcG9ydCB0ZW1wZmlsZQogICAgd2l0aCB0ZW1wZmls'
    'ZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXA6CiAgICAgICAgc3RhZ2UgPSBwYXRobGliLlBhdGgodG1wKQogICAgICAg'
    'IGZvciBrZXksIGZpbGVuYW1lIGluICgoImNhIiwgImNhLnBlbSIpLCAoImNlcnRpZmljYXRlIiwgImNlcnQucGVtIiksICgi'
    'cHJpdmF0ZV9rZXkiLCAia2V5LnBlbSIpKToKICAgICAgICAgICAgd3JpdGUoc3RhZ2UgLyBmaWxlbmFtZSwgcFtrZXldKQog'
    'ICAgICAgIGN0eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgIGN0eC5sb2FkX3Zl'
    'cmlmeV9sb2NhdGlvbnMoc3RyKHN0YWdlIC8gImNhLnBlbSIpKQogICAgICAgIGN0eC5sb2FkX2NlcnRfY2hhaW4oc3RyKHN0'
    'YWdlIC8gImNlcnQucGVtIiksIHN0cihzdGFnZSAvICJrZXkucGVtIikpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBh'
    'cmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKFJPT1QgLyAicHJvZmlsZS5qc29uIiwganNvbi5kdW1wcyhw'
    'KSkKICAgIHdyaXRlKFJPT1QgLyAiY2EucGVtIiwgcFsiY2EiXSkKICAgIHdyaXRlKFJPT1QgLyAiY2xpZW50LnBlbSIsIHBb'
    'ImNlcnRpZmljYXRlIl0pCiAgICB3cml0ZShST09UIC8gImNsaWVudC1rZXkucGVtIiwgcFsicHJpdmF0ZV9rZXkiXSkKICAg'
    'IHdyaXRlKFJPT1QgLyAicHJpdmF0ZSIgLyAiY2xpZW50LWtleS5wZW0iLCBwWyJwcml2YXRlX2tleSJdKQogICAgd3JpdGUo'
    'Uk9PVCAvICJ4NTA5IiAvICJjbGllbnQucGVtIiwgcFsiY2VydGlmaWNhdGUiXSkKICAgIHdyaXRlKFJPT1QgLyAieDUwOWNh'
    'IiAvICJjYS5wZW0iLCBwWyJjYSJdKQogICAgY29udGV4dCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJ'
    'RU5UKQogICAgY29udGV4dC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKFJPT1QgLyAiY2EucGVtIikpCiAgICBjb250ZXh0'
    'LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVCAvICJjbGllbnQucGVtIiksIHN0cihST09UIC8gImNsaWVudC1rZXkucGVtIikp'
    'CiAgICBzYXZlKHsidGVsZW1ldHJ5IjogVHJ1ZSwgImxhc3RfZXJyb3IiOiAiIn0pCiAgICBwcmludCgi0J/RgNC+0YTQuNC7'
    '0Ywg0YPRgdGC0LDQvdC+0LLQu9C10L0uINCS0YDQtdC80LXQvdC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCwINCy0LrQ'
    'u9GO0YfQtdC90LA7INC10ZEg0LzQvtC20L3QviDQstGL0LrQu9GO0YfQuNGC0Ywg0LfQtNC10YHRjCDQttC1LiIpCgoKZGVm'
    'IHByZXBhcmUoKToKICAgIGlmIHNodXRpbC53aGljaCgic3dhbmN0bCIpOgogICAgICAgIHJldHVybgogICAgaWYgc2h1dGls'
    'LndoaWNoKCJwYWNtYW4iKToKICAgICAgICBjbWQoWyJwYWNtYW4iLCAiLVMiLCAiLS1uZWVkZWQiLCAiLS1ub2NvbmZpcm0i'
    'LCAic3Ryb25nc3dhbiJdLCB0aW1lb3V0PTMwMCkKICAgIGVsaWYgc2h1dGlsLndoaWNoKCJkbmYiKToKICAgICAgICBjbWQo'
    'WyJkbmYiLCAiaW5zdGFsbCIsICIteSIsICItLXNldG9wdD1pbnN0YWxsX3dlYWtfZGVwcz1GYWxzZSIsICJzdHJvbmdzd2Fu'
    'Il0sIHRpbWVvdXQ9MzAwKQogICAgZWxzZToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCj0YHRgtCw0L3QvtCy0Lgg'
    'c3Ryb25nU3dhbiDRgSBzd2FuY3RsINGB0YDQtdC00YHRgtCy0LDQvNC4INGB0LLQvtC10LPQviDQtNC40YHRgtGA0LjQsdGD'
    '0YLQuNCy0LAuIikKICAgIHByaW50KCJzdHJvbmdTd2FuINGD0YHRgtCw0L3QvtCy0LvQtdC9OyDQsNCy0YLQvtC/0L7QtNC6'
    '0LvRjtGH0LXQvdC40LUg0L3QtSDQstC60LvRjtGH0LXQvdC+LiIpCgoKZGVmIHJlbmRlcl9ndWFyZCgpOgogICAgcmV0dXJu'
    'IGYiIiJ0YWJsZSBpbmV0IHtUQUJMRX0ge3sKIGNoYWluIG91dHB1dCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgb3V0cHV0IHBy'
    'aW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAogIGlwIGRhZGRyIHtTRVJWRVJ9IHVkcCBk'
    'cG9ydCB7eyA1MDAsIDQ1MDAgfX0gYWNjZXB0CiAgbWV0YSBza3VpZCAwIG1ldGEgbWFyayB7RElSRUNUX01BUkt9IGlwIGRh'
    'ZGRyIHtTRVJWRVJ9IHRjcCBkcG9ydCB7RElSRUNUX1BPUlR9IGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IHVkcCBzcG9y'
    'dCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlkIHtSRVFJRH0gYWNj'
    'ZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtMTA7IHBvbGlj'
    'eSBkcm9wOwogfX0KfX0KIiIiCgoKZGVmIHJlbmRlcl9jb25uZWN0aW9uKHApOgogICAgcmV0dXJuIGYiIiJjb25uZWN0aW9u'
    'cyB7ewogc3RhcmZpdmUge3sKICB2ZXJzaW9uID0gMgogIHJlbW90ZV9hZGRycyA9IHtTRVJWRVJ9CiAgdmlwcyA9IDAuMC4w'
    'LjAKICBwcm9wb3NhbHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0LGFlczI1Ni1zaGEyNTYtbW9kcDIwNDgKICBl'
    'bmNhcCA9IHllcwogIGZyYWdtZW50YXRpb24gPSB5ZXMKICBtb2Jpa2UgPSB5ZXMKICBkcGRfZGVsYXkgPSAzMHMKICBsb2Nh'
    'bCB7ewogICBhdXRoID0gZWFwLXRscwogICBpZCA9IHtwWydpZGVudGl0eSddfQogICBlYXBfaWQgPSB7cFsnaWRlbnRpdHkn'
    'XX0KICAgY2VydHMgPSB7Uk9PVH0vY2xpZW50LnBlbQogIH19CiAgcmVtb3RlIHt7CiAgIGF1dGggPSBwdWJrZXkKICAgaWQg'
    'PSB7U0VSVkVSfQogICBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbQogIH19CiAgY2hpbGRyZW4ge3sKICAgc3RhcmZpdmUtbmV0'
    'IHt7CiAgICBsb2NhbF90cyA9IGR5bmFtaWMKICAgIHJlbW90ZV90cyA9IDAuMC4wLjAvMAogICAgcmVxaWQgPSB7UkVRSUR9'
    'CiAgICBlc3BfcHJvcG9zYWxzID0gYWVzMjU2Z2NtMTYsYWVzMjU2LXNoYTI1NgogICAgZHBkX2FjdGlvbiA9IGNsZWFyCiAg'
    'ICBzdGFydF9hY3Rpb24gPSBub25lCiAgIH19CiAgfX0KIH19Cn19CiIiIgoKCmRlZiBzZXJ2aWNlX2ZpbGVzKCk6CiAgICBj'
    'YW5kaWRhdGVzID0gWyIvdXNyL3NiaW4vY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9iaW4vY2hhcm9uLXN5c3RlbWQiLCAiL3Vz'
    'ci9saWIvaXBzZWMvY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9saWJleGVjL2lwc2VjL2NoYXJvbi1zeXN0ZW1kIiwKICAgICAg'
    'ICAgICAgICAgICAgIi91c3IvbGliL3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9saWJleGVjL3N0cm9uZ3N3'
    'YW4vY2hhcm9uLXN5c3RlbWQiXQogICAgYmluYXJ5ID0gbmV4dCgoeCBmb3IgeCBpbiBjYW5kaWRhdGVzIGlmIHBhdGhsaWIu'
    'UGF0aCh4KS5pc19maWxlKCkpLCBOb25lKQogICAgaWYgbm90IGJpbmFyeToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'ItCd0LUg0L3QsNC50LTQtdC9IGNoYXJvbi1zeXN0ZW1kLiDQndGD0LbQtdC9INC/0LDQutC10YIgc3Ryb25nU3dhbiDRgSBz'
    'eXN0ZW1kIGJhY2tlbmQuIikKICAgIGNvbmZpZ3MgPSBbc3RyKHApIGZvciBwYXR0ZXJuIGluICgiL2V0Yy9zdHJvbmdzd2Fu'
    'LmQvY2hhcm9uLyouY29uZiIsICIvZXRjL3N0cm9uZ3N3YW4vc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYiKQogICAgICAg'
    'ICAgICAgICBmb3IgcCBpbiBwYXRobGliLlBhdGgoIi8iKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCIvIikpXQogICAgaW5jbHVk'
    'ZXMgPSAiXG4iLmpvaW4oImluY2x1ZGUgIiArIHggZm9yIHggaW4gY29uZmlncykKICAgICMgRE5TIGlzIG1hbmFnZWQgdHJh'
    'bnNhY3Rpb25hbGx5IGJ5IHRoaXMgYmFja2VuZCwgbm90IGJ5IHRoZSByZXNvbHZlIHBsdWdpbi4KICAgIHdyaXRlKFJPT1Qg'
    'LyAic3Ryb25nc3dhbi5jb25mIiwgIiIiY2hhcm9uIHsKIGxvYWRfbW9kdWxhciA9IHllcwogaW5zdGFsbF9yb3V0ZXMgPSB5'
    'ZXMKIHJvdXRpbmdfdGFibGUgPSA1MTgyMgogcm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBwbHVnaW5zIHsKIiIiICsgaW5j'
    'bHVkZXMgKyBmIiIiCiAgdmljaSB7ewogICBzb2NrZXQgPSB7VVJJfQogIH19CiAgcmVzb2x2ZSB7ewogICBsb2FkID0gbm8K'
    'ICB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sKIGpvdXJuYWwge3sKICBkZWZhdWx0ID0gMQogfX0KfX0KIiIiKQogICAg'
    'd3JpdGUocGF0aGxpYi5QYXRoKCIvZXRjL3N5c3RlbWQvc3lzdGVtIikgLyBVTklULCBmIiIiW1VuaXRdCkRlc2NyaXB0aW9u'
    'PUV2Z2VuaXVtIGV4cGVyaW1lbnRhbCBTdGFyRml2ZSBJS0V2MgpBZnRlcj1uZXR3b3JrLnRhcmdldApbU2VydmljZV0KVHlw'
    'ZT1ub3RpZnkKRW52aXJvbm1lbnQ9U1RST05HU1dBTl9DT05GPXtST09UfS9zdHJvbmdzd2FuLmNvbmYKRXhlY1N0YXJ0PXti'
    'aW5hcnl9ClJ1bnRpbWVEaXJlY3Rvcnk9ZXZnZW5pdW0taWtldjIKUnVudGltZURpcmVjdG9yeU1vZGU9MDcwMApSZXN0YXJ0'
    'PW5vClRpbWVvdXRTdGFydFNlYz0yMAoiIiIsIDBvNjQ0KQogICAgd3JpdGUoUk9PVCAvICJndWFyZC5uZnQiLCByZW5kZXJf'
    'Z3VhcmQoKSkKICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgiL2V0Yy9zeXN0ZW1kL3N5c3RlbSIpIC8gR1VBUkQsIGYiIiJbVW5p'
    'dF0KRGVzY3JpcHRpb249RmFpbC1jbG9zZWQgZ3VhcmQgZm9yIGV4cGVyaW1lbnRhbCBJS0V2MgpEZWZhdWx0RGVwZW5kZW5j'
    'aWVzPW5vCkJlZm9yZT1uZXR3b3JrLXByZS50YXJnZXQKV2FudHM9bmV0d29yay1wcmUudGFyZ2V0CkFmdGVyPWxvY2FsLWZz'
    'LnRhcmdldCBuZnRhYmxlcy5zZXJ2aWNlCltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVtYWluQWZ0ZXJFeGl0PXllcwpFeGVj'
    'U3RhcnQ9e3NodXRpbC53aGljaCgibmZ0Iil9IC1mIHtST09UfS9ndWFyZC5uZnQKRXhlY1N0b3A9LXtzaHV0aWwud2hpY2go'
    'Im5mdCIpfSBkZWxldGUgdGFibGUgaW5ldCB7VEFCTEV9CltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAoi'
    'IiIsIDBvNjQ0KQogICAgd3JpdGUocGF0aGxpYi5QYXRoKCIvZXRjL3N5c3RlbWQvc3lzdGVtIikgLyBNT05JVE9SLCAiIiJb'
    'VW5pdF0KRGVzY3JpcHRpb249VGVtcG9yYXJ5IFN0YXJGaXZlIFZQTiBkaWFnbm9zdGljcwpBZnRlcj1ldmdlbml1bS1pa2V2'
    'Mi5zZXJ2aWNlCltTZXJ2aWNlXQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS1t'
    'b25pdG9yClN0YW5kYXJkT3V0cHV0PW51bGwKU3RhbmRhcmRFcnJvcj1udWxsClJlc3RhcnQ9bm8KIiIiLCAwbzY0NCkKICAg'
    'IGluc3RhbGxfZGVsaXZlcnkoKQoKCmRlZiBpbnN0YWxsX2RlbGl2ZXJ5KCk6CiAgICB3cml0ZShwYXRobGliLlBhdGgoJy9l'
    'dGMvc3lzdGVtZC9zeXN0ZW0nKSAvIERFTElWRVJZLCAiIiJbVW5pdF0KRGVzY3JpcHRpb249RXhwZXJpbWVudGFsIGRpcmVj'
    'dCBtVExTIGRpYWdub3N0aWMgZGVsaXZlcnkKQWZ0ZXI9bmV0d29yay50YXJnZXQKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNy'
    'L2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXN0YXJmaXZlLWRlbGl2ZXJ5ClN0YW5kYXJkT3V0cHV0PW51bGwKU3RhbmRh'
    'cmRFcnJvcj1udWxsClJlc3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0U2VjPTMwCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11'
    'c2VyLnRhcmdldAoiIiIsIDBvNjQ0KQogICAgY21kKFsic3lzdGVtY3RsIiwgImRhZW1vbi1yZWxvYWQiXSkKICAgIGNtZChb'
    'J3N5c3RlbWN0bCcsJ2VuYWJsZScsREVMSVZFUlldLGNoZWNrPUZhbHNlKQogICAgIyBVcGdyYWRlIGFuIGFscmVhZHkgYWN0'
    'aXZlIGV4cGVyaW1lbnRhbCBndWFyZCB3aXRob3V0IG9wZW5pbmcgb3JkaW5hcnkgdHJhZmZpYy4KICAgIGlmIGFjdGl2ZV9n'
    'dWFyZCgpOgogICAgICAgIHJ1bGVzPWNtZChbJ25mdCcsJ2xpc3QnLCdjaGFpbicsJ2luZXQnLFRBQkxFLCdvdXRwdXQnXSxj'
    'aGVjaz1GYWxzZSkuc3Rkb3V0CiAgICAgICAgaWYgc3RyKERJUkVDVF9NQVJLKSBub3QgaW4gcnVsZXMgYW5kIGhleChESVJF'
    'Q1RfTUFSSykgbm90IGluIHJ1bGVzOgogICAgICAgICAgICBjbWQoWyduZnQnLCdpbnNlcnQnLCdydWxlJywnaW5ldCcsVEFC'
    'TEUsJ291dHB1dCcsJ21ldGEnLCdza3VpZCcsJzAnLAogICAgICAgICAgICAgICAgICdtZXRhJywnbWFyaycsc3RyKERJUkVD'
    'VF9NQVJLKSwnaXAnLCdkYWRkcicsU0VSVkVSLCd0Y3AnLCdkcG9ydCcsc3RyKERJUkVDVF9QT1JUKSwnYWNjZXB0J10pCgoK'
    'ZGVmIHNldF9kbnMoKToKICAgIHJlc29sdmVkID0gUk9PVCAvICJyZXNvbHZlZC1iYWNrdXAuanNvbiIKICAgIGJhY2t1cCA9'
    'IFJPT1QgLyAicmVzb2x2LWJhY2t1cCIKICAgIGlmIGJhY2t1cC5leGlzdHMoKSBvciByZXNvbHZlZC5leGlzdHMoKToKICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCV0YHRgtGMINC90LXQt9Cw0LLQtdGA0YjRkdC90L3QvtC1INCy0L7RgdGB0YLQ'
    'sNC90L7QstC70LXQvdC40LUgRE5TLiDQodC90LDRh9Cw0LvQsCB2cG4gZXhwZXJpbWVudGFsIG9mZi4iKQogICAgaWYgc2h1'
    'dGlsLndoaWNoKCJyZXNvbHZlY3RsIikgYW5kIGNtZChbInN5c3RlbWN0bCIsICJpcy1hY3RpdmUiLCAic3lzdGVtZC1yZXNv'
    'bHZlZCJdLCBjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIHJvdXRlID0ganNvbi5sb2FkcyhjbWQoWyJp'
    'cCIsICItaiIsICJyb3V0ZSIsICJnZXQiLCBTRVJWRVJdKS5zdGRvdXQpWzBdCiAgICAgICAgaWZhY2UgPSByb3V0ZVsiZGV2'
    'Il0KICAgICAgICBkZWYgcHJldmlvdXMoa2luZCk6CiAgICAgICAgICAgIHRleHQgPSBjbWQoWyJyZXNvbHZlY3RsIiwga2lu'
    'ZCwgaWZhY2VdKS5zdGRvdXQKICAgICAgICAgICAgcmV0dXJuIHRleHQuc3BsaXQoIik6IiwgMSlbMV0uc3RyaXAoKS5zcGxp'
    'dCgpIGlmICIpOiIgaW4gdGV4dCBlbHNlIFtdCiAgICAgICAgd3JpdGUocmVzb2x2ZWQsIGpzb24uZHVtcHMoeyJpZmFjZSI6'
    'IGlmYWNlLCAiZG5zIjogcHJldmlvdXMoImRucyIpLCAiZG9tYWluIjogcHJldmlvdXMoImRvbWFpbiIpfSkpCiAgICAgICAg'
    'Y21kKFsicmVzb2x2ZWN0bCIsICJkbnMiLCBpZmFjZSwgIjc3Ljg4LjguOCIsICI3Ny44OC44LjEiXSkKICAgICAgICBjbWQo'
    'WyJyZXNvbHZlY3RsIiwgImRvbWFpbiIsIGlmYWNlLCAifi4iXSkKICAgICAgICBjbWQoWyJyZXNvbHZlY3RsIiwgImZsdXNo'
    'LWNhY2hlcyJdLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4KICAgIHdyaXRlKGJhY2t1cCwgcGF0aGxpYi5QYXRoKCIv'
    'ZXRjL3Jlc29sdi5jb25mIikucmVhZF90ZXh0KCkpCiAgICAjIEtlZXAgdGhlIHN5bWxpbmsgaXRzZWxmIGludGFjdCAoTmV0'
    'd29ya01hbmFnZXIvc3lzdGVtZC1yZXNvbHZlZCBzZXR1cHMpLgogICAgcGF0aGxpYi5QYXRoKCIvZXRjL3Jlc29sdi5jb25m'
    'Iikud3JpdGVfdGV4dCgiIyBFdmdlbml1bSBleHBlcmltZW50YWwgVlBOXG5uYW1lc2VydmVyIDc3Ljg4LjguOFxubmFtZXNl'
    'cnZlciA3Ny44OC44LjFcbm9wdGlvbnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbiIpCgoKZGVmIHJlc3RvcmVfZG5zKCk6CiAg'
    'ICByZXNvbHZlZCA9IFJPT1QgLyAicmVzb2x2ZWQtYmFja3VwLmpzb24iCiAgICBpZiByZXNvbHZlZC5leGlzdHMoKToKICAg'
    'ICAgICBkYXRhID0ganNvbi5sb2FkcyhyZXNvbHZlZC5yZWFkX3RleHQoKSkKICAgICAgICBmb3Iga2V5IGluICgiZG5zIiwg'
    'ImRvbWFpbiIpOgogICAgICAgICAgICBjbWQoWyJyZXNvbHZlY3RsIiwga2V5LCBkYXRhWyJpZmFjZSJdLCAqKGRhdGFba2V5'
    'XSBvciBbIiJdKV0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsICJmbHVzaC1jYWNoZXMiXSwgY2hlY2s9RmFsc2UpCiAg'
    'ICAgICAgcmVzb2x2ZWQudW5saW5rKCkKICAgIGJhY2t1cCA9IFJPT1QgLyAicmVzb2x2LWJhY2t1cCIKICAgIGlmIGJhY2t1'
    'cC5leGlzdHMoKToKICAgICAgICBwYXRobGliLlBhdGgoIi9ldGMvcmVzb2x2LmNvbmYiKS53cml0ZV90ZXh0KGJhY2t1cC5y'
    'ZWFkX3RleHQoKSkKICAgICAgICBiYWNrdXAudW5saW5rKCkKCgpkZWYgZW5kcG9pbnQocGF0aCwgcGF5bG9hZD1Ob25lKToK'
    'ICAgIGNvbnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWZpbGU9c3RyKFJPT1QgLyAiY2EucGVtIikpCiAg'
    'ICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVCAvICJjbGllbnQucGVtIiksIHN0cihST09UIC8gImNsaWVudC1r'
    'ZXkucGVtIikpCiAgICBkYXRhID0gTm9uZSBpZiBwYXlsb2FkIGlzIE5vbmUgZWxzZSBqc29uLmR1bXBzKHBheWxvYWQsIHNl'
    'cGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCkKICAgIHJlcSA9IHVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoSEVBTFRIICsg'
    'cGF0aCwgZGF0YT1kYXRhLCBoZWFkZXJzPXsiQ29udGVudC1UeXBlIjogImFwcGxpY2F0aW9uL2pzb24ifSkKICAgICMgTmV2'
    'ZXIgY29uc3VsdCBlbnZpcm9ubWVudCBwcm94eSB2YXJpYWJsZXMgZm9yIGEgcHJpdmF0ZSBkaWFnbm9zdGljIGVuZHBvaW50'
    'LgogICAgb3BlbmVyID0gdXJsbGliLnJlcXVlc3QuYnVpbGRfb3BlbmVyKHVybGxpYi5yZXF1ZXN0LlByb3h5SGFuZGxlcih7'
    'fSksIHVybGxpYi5yZXF1ZXN0LkhUVFBTSGFuZGxlcihjb250ZXh0PWNvbnRleHQpKQogICAgd2l0aCBvcGVuZXIub3Blbihy'
    'ZXEsIHRpbWVvdXQ9OCkgYXMgcmVzcG9uc2U6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMocmVzcG9uc2UucmVhZCg2NTUz'
    'NikpCgoKZGVmIG9uKGFwaSwgc2V0dGluZ3MpOgogICAgc3RhcnRlZD10aW1lLm1vbm90b25pYygpCiAgICBzdGFnZT0ncHJl'
    'cGFyZScKICAgIGlmIGFwaS5zZXJ2aWNlX2FjdGl2ZSgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KHQvdCw0YfQ'
    'sNC70LAg0LLRi9C60LvRjtGH0Lgg0L7QsdGL0YfQvdGL0LkgWHJheSBWUE4uINCe0LTQvdC+0LLRgNC10LzQtdC90L3QviDQ'
    'tNCy0LAg0YDQtdC20LjQvNCwINC90LUg0LfQsNC/0YPRgdC60LDRjtGC0YHRjy4iKQogICAgaWYgYWN0aXZlX2d1YXJkKCk6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQoNC10LbQuNC8INGD0LbQtSDQstC60LvRjtGH0ZHQvSDQuNC70Lgg0LfQ'
    'sNCx0LvQvtC60LjRgNC+0LLQsNC9INC/0L7RgdC70LUg0YHQsdC+0Y8uINCS0YvQutC70Y7Rh9C4INC10LPQviDQv9C10YDQ'
    'tdC0INC/0L7QstGC0L7RgNC+0LwuIikKICAgIGlmIG5vdCBST09ULmpvaW5wYXRoKCJwcm9maWxlLmpzb24iKS5leGlzdHMo'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINC40LzQv9C+0YDRgtC40YDRg9C5INC/0LXR'
    'gNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvRjCBTdGFyRml2ZS4iKQogICAgaWYgbm90IHNodXRpbC53aGljaCgi'
    'c3dhbmN0bCIpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KHQvdCw0YfQsNC70LAg0L3QsNC20LzQuCDCq9Cf0L7Q'
    'tNCz0L7RgtC+0LLQuNGC0YwgSUtFdjLCuy4iKQogICAgIyBFeGlzdGluZyB1bnJlbGF0ZWQgSVBzZWMgc3RhdGUgbXVzdCBu'
    'ZXZlciBiZSByZXBsYWNlZC4KICAgIGlmIGNtZChbImlwIiwgInhmcm0iLCAic3RhdGUiXSwgY2hlY2s9RmFsc2UpLnN0ZG91'
    'dC5zdHJpcCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J7QsdC90LDRgNGD0LbQtdC9INC00YDRg9Cz0L7QuSBJ'
    'UHNlYyBWUE4uINCh0L3QsNGH0LDQu9CwINC+0YLQutC70Y7Rh9C4INC10LPQvi4iKQogICAgcCA9IHZhbGlkYXRlX3Byb2Zp'
    'bGUoanNvbi5sb2FkcygoUk9PVCAvICJwcm9maWxlLmpzb24iKS5yZWFkX3RleHQoKSkpCiAgICBzZXJ2aWNlX2ZpbGVzKCkK'
    'ICAgIHdyaXRlKFJPT1QgLyAiY29ubmVjdGlvbi5jb25mIiwgcmVuZGVyX2Nvbm5lY3Rpb24ocCkpCiAgICB0cnk6CiAgICAg'
    'ICAgc3RhZ2U9J2RhZW1vbicKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RhcnQiLCBVTklUXSkKICAgICAgICBzdGFn'
    'ZT0nY3JlZGVudGlhbHMnCiAgICAgICAgc3dhbigiLS1sb2FkLWNyZWRzIiwgIi0tZmlsZSIsIFJPT1QgLyAiY29ubmVjdGlv'
    'bi5jb25mIikKICAgICAgICBzd2FuKCItLWxvYWQtY29ubnMiLCAiLS1maWxlIiwgUk9PVCAvICJjb25uZWN0aW9uLmNvbmYi'
    'KQogICAgICAgIHN0YWdlPSdndWFyZCcKICAgICAgICB3cml0ZShSVU5USU1FIC8gImd1YXJkLm5mdCIsIHJlbmRlcl9ndWFy'
    'ZCgpKQogICAgICAgIGNtZChbIm5mdCIsICItYyIsICItZiIsIFJVTlRJTUUgLyAiZ3VhcmQubmZ0Il0pCiAgICAgICAgIyBB'
    'bGwgcHJlcGFyYXRvcnkgY2hlY2tzIGFib3ZlIGFyZSBub24tZGlzcnVwdGl2ZS4gVGhlIGd1YXJkIGdvZXMgZmlyc3QuCiAg'
    'ICAgICAgY21kKFsic3lzdGVtY3RsIiwgImVuYWJsZSIsICItLW5vdyIsIEdVQVJEXSkKICAgICAgICBpZiBub3QgYWN0aXZl'
    'X2d1YXJkKCk6CiAgICAgICAgICAgICMgUmVjb3ZlciBhIHN0YWxlIGFjdGl2ZSBzeXN0ZW1kIHVuaXQgd2hvc2UgdGFibGUg'
    'd2FzIGV4dGVybmFsbHkgcmVtb3ZlZC4KICAgICAgICAgICAgY21kKFsibmZ0IiwgIi1mIiwgUk9PVCAvICJndWFyZC5uZnQi'
    'XSkKICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J3QtSDR'
    'g9C00LDQu9C+0YHRjCDQv9C+0LTRgtCy0LXRgNC00LjRgtGMINGD0YHRgtCw0L3QvtCy0LrRgyBraWxsIHN3aXRjaC4iKQog'
    'ICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5lY3RpbmciLCAibGFzdF9lcnJvciI6ICIifSkKICAgICAgICBz'
    'dGFnZT0naGFuZHNoYWtlJwogICAgICAgIHN3YW4oIi0taW5pdGlhdGUiLCAiLS1jaGlsZCIsICJzdGFyZml2ZS1uZXQiLCB0'
    'aW1lb3V0PTU1KQogICAgICAgIGlmIG5vdCBjb25uZWN0ZWQoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCJJ'
    'UHNlYyBDSElMRF9TQSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQtdC9LiIpCiAgICAgICAgc3RhZ2U9J2RucycKICAgICAgICBz'
    'ZXRfZG5zKCkKICAgICAgICBzdGFnZT0naGVhbHRoJwogICAgICAgIGhlYWx0aCA9IGVuZHBvaW50KCIvaGVhbHRoIikKICAg'
    'ICAgICBpZiBoZWFsdGguZ2V0KCJzZXJ2aWNlIikgIT0gImV2Z2VuaXVtLXN0YXJmaXZlIjoKICAgICAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCLQndC1INC/0L7QtNGC0LLQtdGA0LbQtNGR0L0g0LTQuNCw0LPQvdC+0YHRgtC40YfQtdGB0LrQuNC5'
    'INGB0LXRgNCy0LXRgCBTdGFyRml2ZS4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5lY3RlZCIsICJz'
    'aW5jZSI6IGludCh0aW1lLnRpbWUoKSksICJsYXN0X2Vycm9yIjogIiJ9KQogICAgICAgIGlmIHN0b3JlZCgpLmdldCgidGVs'
    'ZW1ldHJ5Iik6CiAgICAgICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIsIE1PTklUT1JdKQogICAgICAgIHRyeTog'
    'cXVldWVfY29ubmVjdGlvbignY29ubmVjdGVkJywnbm9uZScsKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAg'
    'ICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgcHJpbnQoIlN0YXJGaXZlINC/0L7QtNC60LvRjtGH0ZHQvS4g'
    '0KLQtdGB0YLQvtCy0YvQuSDQstGL0YXQvtC0OiDQoNC+0YHRgdC40Y8uIElQdjYg0LggRElSRUNULdC40YHQutC70Y7Rh9C1'
    '0L3QuNGPINC30LDQsdC70L7QutC40YDQvtCy0LDQvdGLLiIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAg'
    'ICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWyJzeXN0ZW1j'
    'dGwiLCAic3RvcCIsIFVOSVRdLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXN0b3JlX2RucygpCiAgICAgICAgcGF0Y2hfc3Rh'
    'dGUoeyAicGhhc2UiOiAiYmxvY2tlZCIsICJsYXN0X2Vycm9yIjogItCf0L7QtNC60LvRjtGH0LXQvdC40LUg0L3QtSDRg9GB'
    '0YLQsNC90L7QstC70LXQvdC+OyDQuNC90YLQtdGA0L3QtdGCINC30LDQsdC70L7QutC40YDQvtCy0LDQvSDQtNC+INCy0YvQ'
    'utC70Y7Rh9C10L3QuNGPINGA0LXQttC40LzQsC4ifSkKICAgICAgICB0cnk6IHF1ZXVlX2Nvbm5lY3Rpb24oc3RhZ2UsZmFp'
    'bHVyZV9jb2RlKGV4YyksKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9u'
    'OiBwYXNzCiAgICAgICAgZXJyb3I9UnVudGltZUVycm9yKCLQn9C+0LTQutC70Y7Rh9C10L3QuNC1IFN0YXJGaXZlINC90LUg'
    '0YPQtNCw0LvQvtGB0YwuIEtpbGwgc3dpdGNoINC+0YHRgtCw0LLQu9C10L0g0LLQutC70Y7Rh9GR0L3QvdGL0LwuICIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgItCd0LDQttC80Lgg0L/QtdGA0LXQutC70Y7Rh9Cw0YLQtdC70Ywg0LXRidGRINGA'
    '0LDQtyDQuNC70Lgg0LLRi9C/0L7Qu9C90LggdnBuIGV4cGVyaW1lbnRhbCBvZmYuICIgKyBzdHIoZXhjKSkKICAgICAgICBl'
    'cnJvci5kaWFnbm9zdGljX3F1ZXVlZD1UcnVlCiAgICAgICAgcmFpc2UgZXJyb3IgZnJvbSBleGMKCgpkZWYgb2ZmKCk6CiAg'
    'ICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsic3lzdGVtY3Rs'
    'IiwgInN0b3AiLCBNT05JVE9SXSwgY2hlY2s9RmFsc2UpCiAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFVOSVRdLCBj'
    'aGVjaz1GYWxzZSkKICAgIHJlc3RvcmVfZG5zKCkKICAgIGNtZChbInN5c3RlbWN0bCIsICJkaXNhYmxlIiwgIi0tbm93Iiwg'
    'R1VBUkRdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbIm5mdCIsICJkZWxldGUiLCAidGFibGUiLCAiaW5ldCIsIFRBQkxFXSwg'
    'Y2hlY2s9RmFsc2UpCiAgICBwYXRjaF9zdGF0ZSh7ICJwaGFzZSI6ICJvZmYiLCAibGFzdF9lcnJvciI6ICIifSkKICAgIHBy'
    'aW50KCLQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1INGB0L7QtdC00LjQvdC10L3QuNC1INCy0YvQutC70Y7R'
    'h9C10L3Qvi4g0J7QsdGL0YfQvdGL0Lkg0LjQvdGC0LXRgNC90LXRgiDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L0uIikKCgpk'
    'ZWYgdGVsZW1ldHJ5KGVuYWJsZWQpOgogICAgcGF0Y2hfc3RhdGUoeyAidGVsZW1ldHJ5IjogYm9vbChlbmFibGVkKX0pCiAg'
    'ICBpZiBub3QgZW5hYmxlZDoKICAgICAgICBjbWQoWydzeXN0ZW1jdGwnLCdzdG9wJyxERUxJVkVSWV0sY2hlY2s9RmFsc2Up'
    'CiAgICAgICAgY21kKFsic3lzdGVtY3RsIiwgInN0b3AiLCBURVNUX1VOSVRdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbInN5'
    'c3RlbWN0bCIsICJzdGFydCIgaWYgZW5hYmxlZCBhbmQgY29ubmVjdGVkKCkgZWxzZSAic3RvcCIsIE1PTklUT1JdLCBjaGVj'
    'az1GYWxzZSkKICAgIGlmIGVuYWJsZWQ6IGtpY2tfZGVsaXZlcnkoKQogICAgcHJpbnQoItCS0YDQtdC80LXQvdC90LDRjyDQ'
    'tNC40LDQs9C90L7RgdGC0LjQutCwICIgKyAoItCy0LrQu9GO0YfQtdC90LAiIGlmIGVuYWJsZWQgZWxzZSAi0LLRi9C60LvR'
    'jtGH0LXQvdCwIikpCgoKZGVmIGRvbWFpbl9vbmx5KHZhbHVlKToKICAgICMgRXhwbGljaXQgZG9tYWluLW9ubHkgcmVwb3J0'
    'LiBOZXZlciBhY2NlcHQgVVJMcywgcGF0aHMsIHRva2VucyBvciBhcmJpdHJhcnkgbG9nIHRleHQuCiAgICB2YWx1ZSA9IHZh'
    'bHVlLnN0cmlwKCkubG93ZXIoKS5yc3RyaXAoIi4iKQogICAgaWYgbGVuKHZhbHVlKSA+IDI1MyBvciBub3QgcmUuZnVsbG1h'
    'dGNoKHIiW2EtejAtOV0oPzpbYS16MC05Li1dKlthLXowLTldKT8iLCB2YWx1ZSkgb3IgIi4iIG5vdCBpbiB2YWx1ZToKICAg'
    'ICAgICByYWlzZSBWYWx1ZUVycm9yKCLQktCy0LXQtNC4INC00L7QvNC10L0g0LHQtdC3IGh0dHBzOi8vLCDQv9GD0YLQuCDQ'
    'uCDQv9Cw0YDQsNC80LXRgtGA0L7Qsi4iKQogICAgZm9yIGxhYmVsIGluIHZhbHVlLnNwbGl0KCIuIik6CiAgICAgICAgaWYg'
    'bm90IGxhYmVsIG9yIGxlbihsYWJlbCkgPiA2MyBvciBsYWJlbC5zdGFydHN3aXRoKCItIikgb3IgbGFiZWwuZW5kc3dpdGgo'
    'Ii0iKToKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC00L7QvNC10L0u'
    'IikKICAgIHRyeToKICAgICAgICBpcGFkZHJlc3MuaXBfYWRkcmVzcyh2YWx1ZSkKICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgog'
    'ICAgICAgIHJldHVybiB2YWx1ZQogICAgcmFpc2UgVmFsdWVFcnJvcigi0J3Rg9C20LXQvSDQtNC+0LzQtdC9INGB0LDQudGC'
    '0LAsINCwINC90LUgSVAt0LDQtNGA0LXRgS4iKQoKCmRlZiBwcm9iZV9kb21haW4oZG9tYWluKToKICAgIGRvbWFpbiA9IGRv'
    'bWFpbl9vbmx5KGRvbWFpbikKICAgIHN0YXJ0ID0gdGltZS5tb25vdG9uaWMoKQogICAgdHJ5OgogICAgICAgIHJlc29sdmVk'
    'ID0gc29ja2V0LmdldGFkZHJpbmZvKGRvbWFpbiwgNDQzLCBzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQog'
    'ICAgICAgIGFkZHJlc3NlcyA9IGxpc3QoZGljdC5mcm9ta2V5cyh4WzRdWzBdIGZvciB4IGluIHJlc29sdmVkCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHhbNF1bMF0pLmlzX2dsb2Jh'
    'bCkpWzozXQogICAgICAgIGZvciBhZGRyZXNzIGluIGFkZHJlc3NlczoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAg'
    'ICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGFkZHJlc3MsIDQ0MyksIHRpbWVvdXQ9NCkgYXMgc29jazoKICAg'
    'ICAgICAgICAgICAgICAgICB3aXRoIHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KCkud3JhcF9zb2NrZXQoc29jaywgc2Vy'
    'dmVyX2hvc3RuYW1lPWRvbWFpbikgYXMgY29ubjoKICAgICAgICAgICAgICAgICAgICAgICAgY29ubi5zZW5kYWxsKCgiSEVB'
    'RCAvIEhUVFAvMS4xXHJcbkhvc3Q6ICIgKyBkb21haW4gKyAiXHJcbkNvbm5lY3Rpb246IGNsb3NlXHJcblxyXG4iKS5lbmNv'
    'ZGUoKSkKICAgICAgICAgICAgICAgICAgICAgICAgbGluZSA9IGNvbm4ucmVjdigyNTYpLnNwbGl0KGIiXHJcbiIsIDEpWzBd'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIHBhcnRzID0gbGluZS5zcGxpdCgpCiAgICAgICAgICAgICAgICAgICAgICAgIGNv'
    'ZGUgPSBpbnQocGFydHNbMV0pIGlmIGxlbihwYXJ0cykgPiAxIGFuZCBwYXJ0c1sxXS5pc2RpZ2l0KCkgZWxzZSAwCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGlmIGNvZGU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4geyJkb21haW4i'
    'OiBkb21haW4sICJvayI6IFRydWUsICJodHRwX3N0YXR1cyI6IGNvZGUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICJsYXRlbmN5X21zIjogcm91bmQoKHRpbWUubW9ub3RvbmljKCktc3RhcnQpKjEwMDApfQogICAgICAgICAgICBl'
    'eGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgZXhjZXB0IE9TRXJy'
    'b3I6CiAgICAgICAgcGFzcwogICAgcmV0dXJuIHsiZG9tYWluIjogZG9tYWluLCAib2siOiBGYWxzZSwgImVycm9yIjogImRu'
    'c190Y3Bfb3JfdGxzX2ZhaWxlZCIsCiAgICAgICAgICAgICJsYXRlbmN5X21zIjogcm91bmQoKHRpbWUubW9ub3RvbmljKCkt'
    'c3RhcnQpKjEwMDApfQoKCmRlZiByZXBvcnQoZG9tYWluPU5vbmUpOgogICAgaWYgbm90IHN0b3JlZCgpLmdldCgidGVsZW1l'
    'dHJ5Iik6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQlNC40LDQs9C90L7RgdGC0LjQutCwINCy0YvQutC70Y7Rh9C1'
    '0L3QsC4g0JLQutC70Y7Rh9C4INC10ZEg0Y/QstC90L4g0L/QtdGA0LXQtCDQvtGC0L/RgNCw0LLQutC+0LkuIikKICAgIGlm'
    'IG5vdCBjb25uZWN0ZWQoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCe0YLRh9GR0YIg0L7RgtC/0YDQsNCy0LvR'
    'j9C10YLRgdGPINGC0L7Qu9GM0LrQviDQstC90YPRgtGA0Lgg0YPRgdGC0LDQvdC+0LLQu9C10L3QvdC+0LPQviBTdGFyRml2'
    'ZSBWUE4uIikKICAgIGRvbWFpbnMgPSBbZG9tYWluX29ubHkoZG9tYWluKV0gaWYgZG9tYWluIGVsc2UgbGlzdChSVV9ET01B'
    'SU5TKQogICAgcHJvYmVzID0gW3Byb2JlX2RvbWFpbih4KSBmb3IgeCBpbiBkb21haW5zXQogICAgYm9keSA9IHsic2NoZW1h'
    'IjogMSwgImV2ZW50IjogInNpdGVfcmVwb3J0IiBpZiBkb21haW4gZWxzZSAic2FtcGxlIiwKICAgICAgICAgICAgInRpbWUi'
    'OiBpbnQodGltZS50aW1lKCkpLCAibWFuYWdlciI6ICIwLjIuMjIiLCAicGxhdGZvcm0iOiAibGludXgiLAogICAgICAgICAg'
    'ICAicHJvYmVzIjogcHJvYmVzLCAiaXBzZWMiOiAiaW5zdGFsbGVkIn0KICAgIGVuZHBvaW50KCIvcmVwb3J0IiwgYm9keSkK'
    'ICAgIHBhdGNoX3N0YXRlKHsgImxhc3RfcmVwb3J0IjogdGltZS5zdHJmdGltZSgiJVktJW0tJWQgJUg6JU06JVMiLCB0aW1l'
    'LmdtdGltZSgpKSArICIgVVRDIn0pCiAgICBwcmludChqc29uLmR1bXBzKHsic2VudCI6IFRydWUsICJwcm9iZXMiOiBwcm9i'
    'ZXN9LCBlbnN1cmVfYXNjaWk9RmFsc2UpKQoKCmRlZiBtb25pdG9yKCk6CiAgICB3aGlsZSBzdG9yZWQoKS5nZXQoInRlbGVt'
    'ZXRyeSIpIGFuZCBjb25uZWN0ZWQoKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZsdXNoX3Rlc3RfcmVwb3J0KCkKICAg'
    'ICAgICAgICAgcmVwb3J0KCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzCiAgICAgICAgdGlt'
    'ZS5zbGVlcCg2MCkKICAgIGlmIHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5JykgYW5kIGFjdGl2ZV9ndWFyZCgpOgogICAgICAg'
    'IHRyeTogcXVldWVfY29ubmVjdGlvbignZGlzY29ubmVjdGVkJywnbmV0d29yaycpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlv'
    'bjogcGFzcwoKCmRlZiBkaXNwYXRjaChhcGksIHNldHRpbmdzLCBhY3Rpb24sIHRhcmdldD0iIik6CiAgICB0cnk6CiAgICAg'
    'ICAgaWYgYWN0aW9uID09ICJnbG9iYWwtdGVzdCI6IHN0YXJ0X2dsb2JhbF90ZXN0KCkKICAgICAgICBlbGlmIGFjdGlvbiA9'
    'PSAiY2FuY2VsLXRlc3QiOiBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sY2hlY2s9RmFsc2UpCiAgICAg'
    'ICAgZWxpZiBhY3Rpb24gPT0gInByZXBhcmUiOiBwcmVwYXJlKCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAiaW1wb3J0Ijog'
    'aW1wb3J0X3Byb2ZpbGUoc2V0dGluZ3MsIHRhcmdldCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAib24iOiBvbihhcGksIHNl'
    'dHRpbmdzKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJvZmYiOiBvZmYoKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJ0ZWxl'
    'bWV0cnktb24iOiB0ZWxlbWV0cnkoVHJ1ZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAidGVsZW1ldHJ5LW9mZiI6IHRlbGVt'
    'ZXRyeShGYWxzZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAicmVwb3J0IjogcmVwb3J0KHRhcmdldCBvciBOb25lKQogICAg'
    'ICAgIGVsaWYgYWN0aW9uID09ICJzZW5kLWRpYWdub3N0aWNzIjoKICAgICAgICAgICAgaWYgbm90IFJPT1Quam9pbnBhdGgo'
    'J3Byb2ZpbGUuanNvbicpLmV4aXN0cygpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC40LzQv9C+0YDR'
    'gtC40YDRg9C5INC/0YDQvtGE0LjQu9GMLicpCiAgICAgICAgICAgIGluc3RhbGxfZGVsaXZlcnkoKQogICAgICAgICAgICBx'
    'dWV1ZV9jb25uZWN0aW9uKCdtYW51YWwnLCdub25lJykKICAgICAgICAgICAgcHJpbnQoJ9CU0LjQsNCz0L3QvtGB0YLQuNC6'
    '0LAg0YHQvtGF0YDQsNC90LXQvdCwLiDQn9GA0Y/QvNCw0Y8g0L7RgtC/0YDQsNCy0LrQsCDQstGL0L/QvtC70L3Rj9C10YLR'
    'gdGPINCyINGE0L7QvdC1LicpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInN0YXR1cyI6IHByaW50KGpzb24uZHVtcHMoc3Rh'
    'dHVzKCksIGVuc3VyZV9hc2NpaT1GYWxzZSkpCiAgICAgICAgZWxzZTogcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC40LfQstC1'
    '0YHRgtC90LDRjyDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QsNGPINC+0L/QtdGA0LDRhtC40Y8uIikKICAgIGV4'
    'Y2VwdCAoVmFsdWVFcnJvciwgUnVudGltZUVycm9yLCBPU0Vycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSBhcyBl'
    'eGM6CiAgICAgICAgaWYgYWN0aW9uID09ICdvbicgYW5kIG5vdCBnZXRhdHRyKGV4YywnZGlhZ25vc3RpY19xdWV1ZWQnLEZh'
    'bHNlKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgaW5zdGFsbF9kZWxpdmVyeSgpCiAgICAgICAgICAgICAg'
    'ICBxdWV1ZV9jb25uZWN0aW9uKCdwcmVwYXJlJyxmYWlsdXJlX2NvZGUoZXhjKSkKICAgICAgICAgICAgZXhjZXB0IEV4Y2Vw'
    'dGlvbjogcGFzcwogICAgICAgIHJhaXNlIGFwaS5WUE5FcnJvcihzdHIoZXhjKSkgZnJvbSBleGMKCgpURVNUX1VOSVQgPSAn'
    'ZXZnZW5pdW0taWtldjItZ2xvYmFsLXRlc3Quc2VydmljZScKVEVTVF9TVEFURSA9IHBhdGhsaWIuUGF0aCgnL3Zhci9saWIv'
    'dnBuLW1hbmFnZXIvc3RhcmZpdmUtdGVzdC5qc29uJykKUEVORElOR19URVNUID0gUk9PVCAvICdwZW5kaW5nLWdsb2JhbC10'
    'ZXN0Lmpzb24nClJVX0RPTUFJTlMgPSAoJ3lhbmRleC5ydScsICdtYWlsLnJ1JywgJ3d3dy5ydC5ydScpClRFU1RfQkxPQ0sg'
    'PSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVtLXN0YXJmaXZlLWludGVncml0eS12MScpLmRpZ2VzdCg2NTUzNikKCgpk'
    'ZWYgdGVzdF9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICBzdGF0ZT1qc29uLmxvYWRzKFRFU1RfU1RBVEUucmVhZF90ZXh0'
    'KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6CiAgICAgICAgcmV0dXJuIHsncGhhc2UnOidpZGxlJywncHJv'
    'Z3Jlc3MnOjB9CiAgICBpZiBzdGF0ZS5nZXQoJ3BoYXNlJyk9PSdydW5uaW5nJyBhbmQgY21kKFsnc3lzdGVtY3RsJywnaXMt'
    'YWN0aXZlJyxURVNUX1VOSVRdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlOgogICAgICAgIHN0YXRlLnVwZGF0ZShwaGFzZT0n'
    'aW50ZXJydXB0ZWQnLG1lc3NhZ2U9J9Ci0LXRgdGCINC/0YDQtdGA0LLQsNC9LiDQl9Cw0YnQuNGC0LAgVlBOINGB0L7RhdGA'
    '0LDQvdGP0LXRgtGB0Y8uJykKICAgIHJldHVybiBzdGF0ZQoKCmRlZiB0ZXN0X3N0YXRlKCoqZmllbGRzKToKICAgIHRyeTog'
    'c3RhdGU9anNvbi5sb2FkcyhURVNUX1NUQVRFLnJlYWRfdGV4dCgpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3Ip'
    'OiBzdGF0ZT17fQogICAgd3JpdGUoVEVTVF9TVEFURSxqc29uLmR1bXBzKHsqKnN0YXRlLCoqZmllbGRzfSxlbnN1cmVfYXNj'
    'aWk9RmFsc2UpKQoKCmRlZiB0ZXN0X3JlcXVlc3QocGF0aCwgZGF0YT1Ob25lLCBoZWFkZXJzPU5vbmUsIHRpbWVvdXQ9MzAp'
    'OgogICAgY29udGV4dD1zc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWZpbGU9c3RyKFJPT1QvJ2NhLnBlbScpKQogICAg'
    'Y29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSxzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0n'
    'KSkKICAgIG9wZW5lcj11cmxsaWIucmVxdWVzdC5idWlsZF9vcGVuZXIodXJsbGliLnJlcXVlc3QuUHJveHlIYW5kbGVyKHt9'
    'KSx1cmxsaWIucmVxdWVzdC5IVFRQU0hhbmRsZXIoY29udGV4dD1jb250ZXh0KSkKICAgIHJlcXVlc3Q9dXJsbGliLnJlcXVl'
    'c3QuUmVxdWVzdChIRUFMVEgrcGF0aCxkYXRhPWRhdGEsaGVhZGVycz1oZWFkZXJzIG9yIHt9KQogICAgcmV0dXJuIG9wZW5l'
    'ci5vcGVuKHJlcXVlc3QsdGltZW91dD10aW1lb3V0KQoKCmRlZiBleHBlY3RlZF9oYXNoKHNpemUsIG9mZnNldD0wKToKICAg'
    'IGRpZ2VzdD1oYXNobGliLnNoYTI1NigpCiAgICB3aGlsZSBzaXplOgogICAgICAgIHBhcnQ9VEVTVF9CTE9DS1tvZmZzZXQg'
    'JSBsZW4oVEVTVF9CTE9DSyk6XVs6bWluKHNpemUsbGVuKFRFU1RfQkxPQ0spLW9mZnNldCAlIGxlbihURVNUX0JMT0NLKSld'
    'CiAgICAgICAgZGlnZXN0LnVwZGF0ZShwYXJ0KTsgc2l6ZS09bGVuKHBhcnQpOyBvZmZzZXQrPWxlbihwYXJ0KQogICAgcmV0'
    'dXJuIGRpZ2VzdC5oZXhkaWdlc3QoKQoKCmRlZiB0cmFuc2Zlcl9kb3dubG9hZChzaXplLCBvZmZzZXQ9MCwgbGltaXQ9Tm9u'
    'ZSk6CiAgICBzdGFydD10aW1lLm1vbm90b25pYygpOyByZWNlaXZlZD0wOyBkaWdlc3Q9aGFzaGxpYi5zaGEyNTYoKQogICAg'
    'aGVhZGVycz17J1JhbmdlJzpmJ2J5dGVzPXtvZmZzZXR9LSd9IGlmIG9mZnNldCBlbHNlIHt9CiAgICB3aXRoIHRlc3RfcmVx'
    'dWVzdCgnL2Jsb2I/c2l6ZT0nK3N0cihzaXplKSxoZWFkZXJzPWhlYWRlcnMpIGFzIHJlc3BvbnNlOgogICAgICAgIGlmIHJl'
    'c3BvbnNlLnN0YXR1cyAhPSAoMjA2IGlmIG9mZnNldCBlbHNlIDIwMCk6IHJhaXNlIFJ1bnRpbWVFcnJvcignVW5leHBlY3Rl'
    'ZCBmaWxlIHJlc3BvbnNlJykKICAgICAgICBpZiBvZmZzZXQgYW5kIHJlc3BvbnNlLmhlYWRlcnMuZ2V0KCdDb250ZW50LVJh'
    'bmdlJykhPWYnYnl0ZXMge29mZnNldH0te3NpemUtMX0ve3NpemV9JzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdJbnZhbGlkIHJlc3VtZSByYW5nZScpCiAgICAgICAgdG90YWw9c2l6ZS1vZmZzZXQgaWYgbGltaXQgaXMgTm9uZSBlbHNl'
    'IG1pbihsaW1pdCxzaXplLW9mZnNldCkKICAgICAgICB3aGlsZSByZWNlaXZlZDx0b3RhbDoKICAgICAgICAgICAgYmxvY2s9'
    'cmVzcG9uc2UucmVhZChtaW4oNjU1MzYsdG90YWwtcmVjZWl2ZWQpKQogICAgICAgICAgICBpZiBub3QgYmxvY2s6IGJyZWFr'
    'CiAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoYmxvY2spOyByZWNlaXZlZCs9bGVuKGJsb2NrKQogICAgICAgIGludGVncml0'
    'eT1yZWNlaXZlZD09dG90YWwgYW5kIGRpZ2VzdC5oZXhkaWdlc3QoKT09ZXhwZWN0ZWRfaGFzaCh0b3RhbCxvZmZzZXQpCiAg'
    'ICAgICAgaWYgbGltaXQgaXMgTm9uZToKICAgICAgICAgICAgaW50ZWdyaXR5PWludGVncml0eSBhbmQgcmVzcG9uc2UuaGVh'
    'ZGVycy5nZXQoJ1gtQ29udGVudC1TSEEyNTYnKT09ZGlnZXN0LmhleGRpZ2VzdCgpCiAgICBlbGFwc2VkPW1heCh0aW1lLm1v'
    'bm90b25pYygpLXN0YXJ0LDAuMDAxKQogICAgcmV0dXJuIHsna2luZCc6J2Rvd25sb2FkJywnb2snOmludGVncml0eSwnaW50'
    'ZWdyaXR5JzppbnRlZ3JpdHksJ2J5dGVzJzpyZWNlaXZlZCwKICAgICAgICAgICAgJ3NpemUnOnNpemUsJ29mZnNldCc6b2Zm'
    'c2V0LCdlbGFwc2VkX21zJzpyb3VuZChlbGFwc2VkKjEwMDApLAogICAgICAgICAgICAnbWJwc19taWxsaSc6cm91bmQocmVj'
    'ZWl2ZWQqOC9lbGFwc2VkLzEwMDApfQoKCmRlZiB0cmFuc2Zlcl91cGxvYWQoc2l6ZSk6CiAgICBkYXRhPShURVNUX0JMT0NL'
    'Kigoc2l6ZStsZW4oVEVTVF9CTE9DSyktMSkvL2xlbihURVNUX0JMT0NLKSkpWzpzaXplXQogICAgc3RhcnQ9dGltZS5tb25v'
    'dG9uaWMoKQogICAgd2l0aCB0ZXN0X3JlcXVlc3QoJy91cGxvYWQnLGRhdGE9ZGF0YSxoZWFkZXJzPXsnQ29udGVudC1UeXBl'
    'JzonYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtJ30pIGFzIHJlc3BvbnNlOgogICAgICAgIHJlcGx5PWpzb24ubG9hZHMocmVz'
    'cG9uc2UucmVhZCg0MDk2KSkKICAgIGVsYXBzZWQ9bWF4KHRpbWUubW9ub3RvbmljKCktc3RhcnQsMC4wMDEpCiAgICBpbnRl'
    'Z3JpdHk9cmVwbHkuZ2V0KCdyZWNlaXZlZF9ieXRlcycpPT1zaXplIGFuZCByZXBseS5nZXQoJ3NoYTI1NicpPT1oYXNobGli'
    'LnNoYTI1NihkYXRhKS5oZXhkaWdlc3QoKQogICAgcmV0dXJuIHsna2luZCc6J3VwbG9hZCcsJ29rJzppbnRlZ3JpdHksJ2lu'
    'dGVncml0eSc6aW50ZWdyaXR5LCdieXRlcyc6c2l6ZSwKICAgICAgICAgICAgJ2VsYXBzZWRfbXMnOnJvdW5kKGVsYXBzZWQq'
    'MTAwMCksJ21icHNfbWlsbGknOnJvdW5kKHNpemUqOC9lbGFwc2VkLzEwMDApfQoKCmRlZiBwaW5nX3Rlc3Qoc2l6ZT01Niwg'
    'Y291bnQ9MjApOgogICAgY3A9Y21kKFsncGluZycsJy1uJywnLU0nLCdkbycsJy1zJyxzdHIoc2l6ZSksJy1jJyxzdHIoY291'
    'bnQpLCctaScsJzAuMicsJy1XJywnMicsJzEwLjc3LjAuMSddLGNoZWNrPUZhbHNlLHRpbWVvdXQ9NDUpCiAgICBwYWNrZXRz'
    'PXJlLnNlYXJjaChyJyhcZCspIHBhY2tldHMgdHJhbnNtaXR0ZWQsIChcZCspIHJlY2VpdmVkJyxjcC5zdGRvdXQpCiAgICBz'
    'ZW50LHJlY2VpdmVkPShpbnQoeCkgZm9yIHggaW4gcGFja2V0cy5ncm91cHMoKSkgaWYgcGFja2V0cyBlbHNlIChjb3VudCww'
    'KQogICAgcm93PXsna2luZCc6J3BpbmcnLCdvayc6cmVjZWl2ZWQ9PXNlbnQsJ3NlbnQnOnNlbnQsJ3JlY2VpdmVkJzpyZWNl'
    'aXZlZCwKICAgICAgICAgJ2xvc3NfbWlsbGknOnJvdW5kKChzZW50LXJlY2VpdmVkKSoxMDAwMDAvbWF4KHNlbnQsMSkpLCdz'
    'aXplJzpzaXplfQogICAgcnR0PXJlLnNlYXJjaChyJz0gKFtcZC5dKykvKFtcZC5dKykvKFtcZC5dKykvKFtcZC5dKykgbXMn'
    'LGNwLnN0ZG91dCkKICAgIGlmIHJ0dDoKICAgICAgICByb3cudXBkYXRlKHtrZXk6cm91bmQoZmxvYXQodmFsdWUpKjEwMDAp'
    'IGZvciBrZXksdmFsdWUgaW4gemlwKAogICAgICAgICAgICAoJ3J0dF9taW5fdXMnLCdydHRfYXZnX3VzJywncnR0X21heF91'
    'cycsJ3J0dF9tZGV2X3VzJykscnR0Lmdyb3VwcygpKX0pCiAgICByZXR1cm4gcm93CgoKZGVmIHRyYW5zcG9ydF9jb3VudGVy'
    'cygpOgogICAgcmVzdWx0PXsna2luZCc6J2NvdW50ZXJzJywnb2snOlRydWV9CiAgICB0cnk6CiAgICAgICAgcmF3PXN3YW4o'
    'Jy0tbGlzdC1zYXMnLCctLXJhdycpLnN0ZG91dAogICAgICAgIGZvciBzb3VyY2UsdGFyZ2V0IGluICgoJ2J5dGVzLWluJywn'
    'Ynl0ZXNfaW4nKSwoJ2J5dGVzLW91dCcsJ2J5dGVzX291dCcpLCgncGFja2V0cy1pbicsJ3BhY2tldHNfaW4nKSwoJ3BhY2tl'
    'dHMtb3V0JywncGFja2V0c19vdXQnKSk6CiAgICAgICAgICAgIHJlc3VsdFt0YXJnZXRdPXN1bShpbnQoeCkgZm9yIHggaW4g'
    'cmUuZmluZGFsbChyJ1xiJytzb3VyY2Urcic9KFxkKyknLHJhdykpCiAgICAgICAgbGluZXM9cGF0aGxpYi5QYXRoKCcvcHJv'
    'Yy9uZXQvc25tcCcpLnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKQogICAgICAgIGZvciBmaXJzdCxzZWNvbmQgaW4gemlwKGxp'
    'bmVzLGxpbmVzWzE6XSk6CiAgICAgICAgICAgIGlmIGZpcnN0LnN0YXJ0c3dpdGgoJ1RjcDonKSBhbmQgc2Vjb25kLnN0YXJ0'
    'c3dpdGgoJ1RjcDonKToKICAgICAgICAgICAgICAgIHZhbHVlcz1kaWN0KHppcChmaXJzdC5zcGxpdCgpWzE6XSxzZWNvbmQu'
    'c3BsaXQoKVsxOl0pKQogICAgICAgICAgICAgICAgaWYgJ1JldHJhbnNTZWdzJyBpbiB2YWx1ZXM6CiAgICAgICAgICAgICAg'
    'ICAgICAgcmVzdWx0WydyZXRyYW5zX3NlZ21lbnRzJ109aW50KHZhbHVlc1snUmV0cmFuc1NlZ3MnXSkKICAgICAgICAgICAg'
    'ICAgICAgICByZXN1bHRbJ291dF9zZWdtZW50cyddPWludCh2YWx1ZXNbJ091dFNlZ3MnXSkKICAgICAgICByZXN1bHRbJ3hm'
    'cm1fZXJyb3JzJ109c3VtKGludCh4LnNwbGl0KClbMV0pIGZvciB4IGluIHBhdGhsaWIuUGF0aCgnL3Byb2MvbmV0L3hmcm1f'
    'c3RhdCcpLnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVF'
    'cnJvcik6IHJlc3VsdFsnb2snXT1GYWxzZQogICAgcmV0dXJuIHJlc3VsdAoKCmRlZiBmbHVzaF90ZXN0X3JlcG9ydCgpOgog'
    'ICAgaWYgbm90IHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jykgb3Igbm90IFBFTkRJTkdfVEVTVC5leGlzdHMoKTogcmV0dXJu'
    'IEZhbHNlCiAgICBib2R5PWpzb24ubG9hZHMoUEVORElOR19URVNULnJlYWRfdGV4dCgpKQogICAgaWYgbm90IGRlbGl2ZXJf'
    'cmVwb3J0KGJvZHkpOiByZXR1cm4gRmFsc2UKICAgIFBFTkRJTkdfVEVTVC51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAg'
    'dGVzdF9zdGF0ZShzZW50PVRydWUsbWVzc2FnZT0n0KLQtdGB0YIg0LfQsNCy0LXRgNGI0ZHQvS4g0J7RgtGH0ZHRgiDQtNC+'
    '0YHRgtCw0LLQu9C10L0g0L3QsCBTdGFyRml2ZS4nKQogICAgcmV0dXJuIFRydWUKCgpkZWYgc3RhcnRfZ2xvYmFsX3Rlc3Qo'
    'KToKICAgIGlmIGNtZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsVEVTVF9VTklUXSxjaGVjaz1GYWxzZSkucmV0dXJuY29k'
    'ZT09MDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9CT0LvQvtCx0LDQu9GM0L3Ri9C5INGC0LXRgdGCINGD0LbQtSDQ'
    'stGL0L/QvtC70L3Rj9C10YLRgdGPLicpCiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKTogcmFpc2UgUnVu'
    'dGltZUVycm9yKCfQktC60LvRjtGH0Lgg0LLRgNC10LzQtdC90L3Rg9GOINC00LjQsNCz0L3QvtGB0YLQuNC60YMg0LTQu9GP'
    'INC+0YLQv9GA0LDQstC60Lgg0YDQtdC30YPQu9GM0YLQsNGC0L7Qsi4nKQogICAgaWYgbm90IGNvbm5lY3RlZCgpIG9yIG5v'
    'dCBhY3RpdmVfZ3VhcmQoKTogcmFpc2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQv9C+0LTQutC70Y7Rh9C40YHR'
    'jCDQuiBTdGFyRml2ZS4nKQogICAgaWYgZW5kcG9pbnQoJy9oZWFsdGgnKS5nZXQoJ3Rlc3RfYXBpJykhPTE6IHJhaXNlIFJ1'
    'bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L7QsdC90L7QstC40YLRjCDRgtC10YHRgtC+0LLRi9C5INGB0LXRgNCy0LjR'
    'gSBTdGFyRml2ZS4nKQogICAgaWYgUEVORElOR19URVNULmV4aXN0cygpIGFuZCBub3QgZmx1c2hfdGVzdF9yZXBvcnQoKTog'
    'cmFpc2UgUnVudGltZUVycm9yKCfQntC20LjQtNCw0LXRgiDQvtGC0L/RgNCw0LLQutC4INC/0YDQtdC00YvQtNGD0YnQuNC5'
    'INC+0YLRh9GR0YIuJykKICAgIHVuaXQ9JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGdsb2JhbCBWUE4gc3RhYmls'
    'aXR5IHRlc3QKQWZ0ZXI9ZXZnZW5pdW0taWtldjIuc2VydmljZQpbU2VydmljZV0KVHlwZT1leGVjCkV4ZWNTdGFydD0vdXNy'
    'L2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXN0YXJmaXZlLWdsb2JhbC10ZXN0ClN0YW5kYXJkT3V0cHV0PW51bGwKU3Rh'
    'bmRhcmRFcnJvcj1udWxsClRpbWVvdXRTdG9wU2VjPTEyClJ1bnRpbWVNYXhTZWM9OTAwClJlc3RhcnQ9bm8KJycnCiAgICB3'
    'cml0ZShwYXRobGliLlBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9URVNUX1VOSVQsdW5pdCwwbzY0NCkKICAgIGNtZChb'
    'J3N5c3RlbWN0bCcsJ2RhZW1vbi1yZWxvYWQnXSkKICAgIHRlc3Rfc3RhdGUocGhhc2U9J3J1bm5pbmcnLHByb2dyZXNzPTAs'
    'c2VudD1GYWxzZSxwYXNzZWQ9MCxmYWlsZWQ9MCxkdXJhdGlvbl9zPTAsbWVzc2FnZT0n0JfQsNC/0YPRgdC6INGC0LXRgdGC'
    '0LAnLHJ1bj1vcy51cmFuZG9tKDEyKS5oZXgoKSxzdGFydGVkPWludCh0aW1lLnRpbWUoKSkpCiAgICB0cnk6IGNtZChbJ3N5'
    'c3RlbWN0bCcsJ3N0YXJ0JyxURVNUX1VOSVRdKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICB0ZXN0X3N0YXRlKHBo'
    'YXNlPSdmYWlsZWQnLG1lc3NhZ2U9J9Cd0LUg0YPQtNCw0LvQvtGB0Ywg0LfQsNC/0YPRgdGC0LjRgtGMINGC0LXRgdGCLicp'
    'OyByYWlzZQogICAgcHJpbnQoJ9CT0LvQvtCx0LDQu9GM0L3Ri9C5INGC0LXRgdGCINC30LDQv9GD0YnQtdC9INCyINGE0L7Q'
    'vdC1LiDQmNC90YLQtdGA0L3QtdGCINC90LXRgdC60L7Qu9GM0LrQviDRgNCw0Lcg0L/RgNC10YDQstGR0YLRgdGPOyBraWxs'
    'IHN3aXRjaCDQvtGB0YLQsNGR0YLRgdGPINCy0LrQu9GO0YfRkdC90L3Ri9C8LicpCgoKY2xhc3MgVGVzdENhbmNlbGxlZChF'
    'eGNlcHRpb24pOiBwYXNzCgoKZGVmIHJ1bl9nbG9iYWxfdGVzdCgpOgogICAgaW1wb3J0IHNpZ25hbAogICAgZnJvbSBjb25j'
    'dXJyZW50LmZ1dHVyZXMgaW1wb3J0IFRocmVhZFBvb2xFeGVjdXRvcgogICAgZGVmIGNhbmNlbCgqXyk6IHJhaXNlIFRlc3RD'
    'YW5jZWxsZWQoKQogICAgb2xkPXNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sY2FuY2VsKQogICAgcmVjb3Jkcz1bXTsg'
    'b3V0Y29tZT0nY29tcGxldGVkJzsgc3RhcnRlZD10aW1lLm1vbm90b25pYygpCiAgICBkZWYgc3RhZ2UocHJvZ3Jlc3MsbWVz'
    'c2FnZSk6IHRlc3Rfc3RhdGUocGhhc2U9J3J1bm5pbmcnLHByb2dyZXNzPXByb2dyZXNzLG1lc3NhZ2U9bWVzc2FnZSkKICAg'
    'IGRlZiBtZWFzdXJlKGtpbmQsb3BlcmF0aW9uLCoqZmllbGRzKToKICAgICAgICBiZWZvcmU9dGltZS5tb25vdG9uaWMoKQog'
    'ICAgICAgIHRyeTogcm93PW9wZXJhdGlvbigpCiAgICAgICAgZXhjZXB0IFRlc3RDYW5jZWxsZWQ6IHJhaXNlCiAgICAgICAg'
    'ZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIGVycm9yPSdvdGhlcicKICAgICAgICAgICAgaWYgaXNpbnN0'
    'YW5jZShleGMsdXJsbGliLmVycm9yLkhUVFBFcnJvcik6IGVycm9yPSdodHRwJwogICAgICAgICAgICBlbGlmIGlzaW5zdGFu'
    'Y2UoZXhjLChUaW1lb3V0RXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkpOiBlcnJvcj0ndGltZW91dCcKICAgICAg'
    'ICAgICAgZWxpZiBpc2luc3RhbmNlKGV4Yyxzc2wuU1NMRXJyb3IpOiBlcnJvcj0ndGxzJwogICAgICAgICAgICBlbGlmIGlz'
    'aW5zdGFuY2UoZXhjLE9TRXJyb3IpOiBlcnJvcj0nbmV0d29yaycKICAgICAgICAgICAgcm93PXsna2luZCc6a2luZCwnb2sn'
    'OkZhbHNlLCdlcnJvcic6ZXJyb3J9CiAgICAgICAgICAgIGlmIGlzaW5zdGFuY2UoZXhjLHVybGxpYi5lcnJvci5IVFRQRXJy'
    'b3IpOiByb3dbJ2h0dHBfc3RhdHVzJ109ZXhjLmNvZGUKICAgICAgICByb3cuc2V0ZGVmYXVsdCgnZWxhcHNlZF9tcycscm91'
    'bmQoKHRpbWUubW9ub3RvbmljKCktYmVmb3JlKSoxMDAwKSkKICAgICAgICByb3dbJ2F0X21zJ109cm91bmQoKHRpbWUubW9u'
    'b3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICByb3cudXBkYXRlKGZpZWxkcyk7IHJlY29yZHMuYXBwZW5kKHJvdyk7'
    'IHJldHVybiByb3cKICAgIGRlZiByZWNvbm5lY3QocmVzdGFydD1GYWxzZSk6CiAgICAgICAgYmVmb3JlPXRpbWUubW9ub3Rv'
    'bmljKCkKICAgICAgICBpZiByZXN0YXJ0OgogICAgICAgICAgICBjYW5kaWRhdGVzPXNvY2tldC5nZXRhZGRyaW5mbygneWFu'
    'ZGV4LnJ1Jyw0NDMsc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgICAgICAgICBhZGRyZXNzPW5leHQo'
    'eFs0XVswXSBmb3IgeCBpbiBjYW5kaWRhdGVzIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHhbNF1bMF0pLmlzX2dsb2JhbCkK'
    'ICAgICAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RvcCcsVU5JVF0pCiAgICAgICAgICAgIGxlYWtlZD1GYWxzZQogICAg'
    'ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB3aXRoIHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcyw0NDMp'
    'LHRpbWVvdXQ9Mik6IGxlYWtlZD1UcnVlCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yOiBwYXNzCiAgICAgICAgICAgIHJl'
    'Y29yZHMuYXBwZW5kKHsna2luZCc6J2d1YXJkJywnb2snOmFjdGl2ZV9ndWFyZCgpIGFuZCBub3QgbGVha2VkfSkKICAgICAg'
    'ICAgICAgIyBOZXZlciByZW1vdmUgdGhlIGd1YXJkLCBldmVuIGR1cmluZyBhIGRlbGliZXJhdGUgZGFlbW9uIGZhaWx1cmUu'
    'CiAgICAgICAgICAgIGlmIG5vdCBhY3RpdmVfZ3VhcmQoKTogcmFpc2UgUnVudGltZUVycm9yKCdHdWFyZCBtaXNzaW5nJykK'
    'ICAgICAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RhcnQnLFVOSVRdKQogICAgICAgICAgICBzd2FuKCctLWxvYWQtY3Jl'
    'ZHMnLCctLWZpbGUnLFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgICAgIHN3YW4oJy0tbG9hZC1jb25ucycsJy0t'
    'ZmlsZScsUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAgICBlbHNlOgogICAgICAgICAgICBzd2FuKCctLXRlcm1pbmF0'
    'ZScsJy0taWtlJywnc3RhcmZpdmUnLGNoZWNrPUZhbHNlKQogICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCctLWNoaWxkJywn'
    'c3RhcmZpdmUtbmV0Jyx0aW1lb3V0PTU1KQogICAgICAgIGdvb2Q9Y29ubmVjdGVkKCkgYW5kIGVuZHBvaW50KCcvaGVhbHRo'
    'JykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFyZml2ZScKICAgICAgICByZXR1cm4geydraW5kJzonZGFlbW9uX3Jl'
    'c3RhcnQnIGlmIHJlc3RhcnQgZWxzZSAncmVjb25uZWN0Jywnb2snOmdvb2QsJ2VsYXBzZWRfbXMnOnJvdW5kKCh0aW1lLm1v'
    'bm90b25pYygpLWJlZm9yZSkqMTAwMCl9CiAgICBkZWYgY29udHJvbCgpOgogICAgICAgIHdpdGggdGVzdF9yZXF1ZXN0KCcv'
    'Y29udHJvbCcsdGltZW91dD00NSkgYXMgcmVzcG9uc2U6IGRhdGE9anNvbi5sb2FkcyhyZXNwb25zZS5yZWFkKDE2Mzg0KSkK'
    'ICAgICAgICByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidzZXJ2ZXJfY29udHJvbCcsJ29rJzpUcnVlLCoqZGF0YVsnbWV0cmlj'
    'cyddfSkKICAgICAgICBmb3IgcHJvYmUgaW4gZGF0YVsncHJvYmVzJ106IHJlY29yZHMuYXBwZW5kKHsna2luZCc6J3NlcnZl'
    'cl9jb250cm9sJywqKnByb2JlfSkKICAgICAgICByZXR1cm4geydraW5kJzonaGVhbHRoJywnb2snOlRydWV9CiAgICB0cnk6'
    'CiAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RvcCcsTU9OSVRPUl0sY2hlY2s9RmFsc2UpCiAgICAgICAgIyBVc2UgUnVz'
    'c2lhbiBETlMgZm9yIHRoaXMgdGVzdCBldmVuIG9uIGEgc2Vzc2lvbiBjcmVhdGVkIGJ5IGFuIG9sZGVyIGNsaWVudC4KICAg'
    'ICAgICBpZiBub3QgKFJPT1QvJ3Jlc29sdi1iYWNrdXAnKS5leGlzdHMoKSBhbmQgbm90IChST09ULydyZXNvbHZlZC1iYWNr'
    'dXAuanNvbicpLmV4aXN0cygpOiBzZXRfZG5zKCkKICAgICAgICBlbGlmIChST09ULydyZXNvbHZlZC1iYWNrdXAuanNvbicp'
    'LmV4aXN0cygpOgogICAgICAgICAgICBpbnRlcmZhY2U9anNvbi5sb2FkcygoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24n'
    'KS5yZWFkX3RleHQoKSlbJ2lmYWNlJ10KICAgICAgICAgICAgY21kKFsncmVzb2x2ZWN0bCcsJ2RucycsaW50ZXJmYWNlLCc3'
    'Ny44OC44LjgnLCc3Ny44OC44LjEnXSkKICAgICAgICBlbHNlOgogICAgICAgICAgICBwYXRobGliLlBhdGgoJy9ldGMvcmVz'
    'b2x2LmNvbmYnKS53cml0ZV90ZXh0KCduYW1lc2VydmVyIDc3Ljg4LjguOFxubmFtZXNlcnZlciA3Ny44OC44LjFcbm9wdGlv'
    'bnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICAgICAgc3RhZ2UoMywn0JrQvtC90YLRgNC+0LvRjNC90YvQtSDQt9Cw'
    '0LzQtdGA0YsgU3RhckZpdmUg0Lgg0YDQvtGB0YHQuNC50YHQutC40YUg0YHQtdGA0LLQuNGB0L7QsicpCiAgICAgICAgbWVh'
    'c3VyZSgnaGVhbHRoJyxjb250cm9sKTsgcmVjb3Jkcy5hcHBlbmQodHJhbnNwb3J0X2NvdW50ZXJzKCkpCiAgICAgICAgZm9y'
    'IGRvbWFpbiBpbiBSVV9ET01BSU5TOiBtZWFzdXJlKCdydV9wcm9iZScsbGFtYmRhIGQ9ZG9tYWluOnsna2luZCc6J3J1X3By'
    'b2JlJywqKnByb2JlX2RvbWFpbihkKX0pCiAgICAgICAgc3RhZ2UoMTIsJ9CX0LDQtNC10YDQttC60LgsINC/0L7RgtC10YDQ'
    'uCDQuCDRgNCw0LfQvNC10YDRiyDQv9Cw0LrQtdGC0L7QsicpCiAgICAgICAgZm9yIHNpemUgaW4gKDU2LDEyMDAsMTM2MCk6'
    'IG1lYXN1cmUoJ3BpbmcnLGxhbWJkYSBzPXNpemU6cGluZ190ZXN0KHMpKQogICAgICAgIGZvciBhdHRlbXB0IGluIHJhbmdl'
    'KDEyKToKICAgICAgICAgICAgYmVmb3JlPXRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAgbWVhc3VyZSgnaGVhbHRoJyxs'
    'YW1iZGE6eydraW5kJzonaGVhbHRoJywnb2snOmVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1'
    'bS1zdGFyZml2ZSd9KQogICAgICAgICAgICB0aW1lLnNsZWVwKDAuMjUpCiAgICAgICAgc3RhZ2UoMjUsJ9Ch0LrQsNGH0LjQ'
    'stCw0L3QuNC1INC4INC+0YLQv9GA0LDQstC60LAg0YTQsNC50LvQvtCyOiDQv9GA0L7QstC10YDQutCwIFNIQS0yNTYnKQog'
    'ICAgICAgIGZvciBzaXplIGluICg2NTUzNiwxMDQ4NTc2LDgzODg2MDgsMzM1NTQ0MzIpOiBtZWFzdXJlKCdkb3dubG9hZCcs'
    'bGFtYmRhIHM9c2l6ZTp0cmFuc2Zlcl9kb3dubG9hZChzKSkKICAgICAgICBmb3Igc2l6ZSBpbiAoNTI0Mjg4LDQxOTQzMDQp'
    'OiBtZWFzdXJlKCd1cGxvYWQnLGxhbWJkYSBzPXNpemU6dHJhbnNmZXJfdXBsb2FkKHMpKQogICAgICAgIHN0YWdlKDQwLCfQ'
    'lNC+0LrQsNGH0LrQsCDRhNCw0LnQu9CwINC/0L7RgdC70LUg0YDQsNC30YDRi9Cy0LAg0Lgg0L/QtdGA0LXQv9C+0LTQutC7'
    '0Y7Rh9C10L3QuNGPJykKICAgICAgICBtZWFzdXJlKCdyZXN1bWUnLGxhbWJkYTp7Kip0cmFuc2Zlcl9kb3dubG9hZCg4Mzg4'
    'NjA4LGxpbWl0PTMxNDU3MjgpLCdraW5kJzoncmVzdW1lJ30pCiAgICAgICAgbWVhc3VyZSgncmVjb25uZWN0JyxyZWNvbm5l'
    'Y3QpCiAgICAgICAgbWVhc3VyZSgncmVzdW1lJyxsYW1iZGE6eyoqdHJhbnNmZXJfZG93bmxvYWQoODM4ODYwOCxvZmZzZXQ9'
    'MzE0NTcyOCksJ2tpbmQnOidyZXN1bWUnfSkKICAgICAgICBzdGFnZSg1MCwn0J/QsNGA0LDQu9C70LXQu9GM0L3QsNGPINC/'
    '0LXRgNC10LTQsNGH0LAg0LIg0L7QsdC1INGB0YLQvtGA0L7QvdGLJykKICAgICAgICB3aXRoIFRocmVhZFBvb2xFeGVjdXRv'
    'cihtYXhfd29ya2Vycz0zKSBhcyBwb29sOgogICAgICAgICAgICBmdXR1cmVzPVtwb29sLnN1Ym1pdCh0cmFuc2Zlcl9kb3du'
    'bG9hZCw4Mzg4NjA4KSxwb29sLnN1Ym1pdCh0cmFuc2Zlcl9kb3dubG9hZCw4Mzg4NjA4KSxwb29sLnN1Ym1pdCh0cmFuc2Zl'
    'cl91cGxvYWQsNDE5NDMwNCldCiAgICAgICAgICAgIGZvciBmdXR1cmUgaW4gZnV0dXJlczogbWVhc3VyZSgncGFyYWxsZWwn'
    'LGxhbWJkYSBmPWZ1dHVyZTp7KipmLnJlc3VsdCgpLCdraW5kJzoncGFyYWxsZWwnfSkKICAgICAgICBzdGFnZSg2Miwn0JTQ'
    'u9C40YLQtdC70YzQvdCw0Y8g0L/QtdGA0LXQtNCw0YfQsDog0LTQviA2MCDRgdC10LrRg9C90LQgLyA2NCDQnNC40JEnKQog'
    'ICAgICAgIGxvYWRfc3RhcnRlZD10aW1lLm1vbm90b25pYygpOyB1bnRpbD1sb2FkX3N0YXJ0ZWQrNjA7IGNvdW50PTAKICAg'
    'ICAgICB3aGlsZSB0aW1lLm1vbm90b25pYygpPHVudGlsIGFuZCBjb3VudDwxNjoKICAgICAgICAgICAgbWVhc3VyZSgnZG93'
    'bmxvYWQnLGxhbWJkYTp0cmFuc2Zlcl9kb3dubG9hZCg0MTk0MzA0KSk7IGNvdW50Kz0xCiAgICAgICAgICAgIG1lYXN1cmUo'
    'J2hlYWx0aCcsbGFtYmRhOnsna2luZCc6J2hlYWx0aCcsJ29rJzplbmRwb2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScp'
    'PT0nZXZnZW5pdW0tc3RhcmZpdmUnfSkKICAgICAgICAgICAgdGltZS5zbGVlcChtYXgoMCxsb2FkX3N0YXJ0ZWQrY291bnQq'
    'NC10aW1lLm1vbm90b25pYygpKSkKICAgICAgICBzdGFnZSg3NSwn0J/RgNC+0YHRgtC+0LkgNDUg0YHQtdC60YPQvdC0INC4'
    'INCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40LUg0LDQutGC0LjQstC90L7RgdGC0LgnKQogICAgICAgIHRpbWUuc2xlZXAo'
    'NDUpCiAgICAgICAgbWVhc3VyZSgnaWRsZScsbGFtYmRhOnsna2luZCc6J2lkbGUnLCdvayc6ZW5kcG9pbnQoJy9oZWFsdGgn'
    'KS5nZXQoJ3NlcnZpY2UnKT09J2V2Z2VuaXVtLXN0YXJmaXZlJywnZWxhcHNlZF9tcyc6NDUwMDB9KQogICAgICAgIHN0YWdl'
    'KDgyLCfQn9GP0YLRjCDQv9C+0LLRgtC+0YDQvdGL0YUg0L/QvtC00LrQu9GO0YfQtdC90LjQuScpCiAgICAgICAgZm9yIGF0'
    'dGVtcHQgaW4gcmFuZ2UoNSk6CiAgICAgICAgICAgIG1lYXN1cmUoJ3JlY29ubmVjdCcscmVjb25uZWN0LGF0dGVtcHQ9YXR0'
    'ZW1wdCsxKTsgdGltZS5zbGVlcCgxKQogICAgICAgIHN0YWdlKDkyLCfQn9C10YDQtdC30LDQv9GD0YHQuiBWUE4t0LTQtdC8'
    '0L7QvdCwINGBINGB0L7RhdGA0LDQvdC10L3QuNC10Lwga2lsbCBzd2l0Y2gnKQogICAgICAgIG1lYXN1cmUoJ2RhZW1vbl9y'
    'ZXN0YXJ0JyxsYW1iZGE6cmVjb25uZWN0KFRydWUpKQogICAgICAgIHJlY29yZHMuYXBwZW5kKHsna2luZCc6J2d1YXJkJywn'
    'b2snOmFjdGl2ZV9ndWFyZCgpfSkKICAgICAgICBzdGFnZSg5Niwn0JfQsNC60LvRjtGH0LjRgtC10LvRjNC90YvQtSDQt9Cw'
    '0LzQtdGA0Ysg0Lgg0L7RgtC/0YDQsNCy0LrQsCDQvtGC0YfRkdGC0LAnKQogICAgICAgIGZvciBkb21haW4gaW4gUlVfRE9N'
    'QUlOUzogbWVhc3VyZSgncnVfcHJvYmUnLGxhbWJkYSBkPWRvbWFpbjp7J2tpbmQnOidydV9wcm9iZScsKipwcm9iZV9kb21h'
    'aW4oZCl9KQogICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsY29udHJvbCk7IHJlY29yZHMuYXBwZW5kKHRyYW5zcG9ydF9jb3Vu'
    'dGVycygpKQogICAgICAgIGlmIGFueShub3QgeC5nZXQoJ29rJykgZm9yIHggaW4gcmVjb3Jkcyk6IG91dGNvbWU9J2ZhaWxl'
    'ZCcKICAgIGV4Y2VwdCBUZXN0Q2FuY2VsbGVkOiBvdXRjb21lPSdjYW5jZWxsZWQnCiAgICBleGNlcHQgRXhjZXB0aW9uOiBv'
    'dXRjb21lPSdmYWlsZWQnCiAgICBmaW5hbGx5OgogICAgICAgICMgUmVjb3ZlciBvbmx5IG91ciBkYWVtb24vc2Vzc2lvbi4g'
    'TmV2ZXIgZGlzYWJsZSB0aGUgZ3VhcmQgb3IgcmVzdG9yZSBkaXJlY3QgdHJhZmZpYy4KICAgICAgICBpZiBvdXRjb21lIT0n'
    'Y2FuY2VsbGVkJyBhbmQgbm90IGNvbm5lY3RlZCgpOgogICAgICAgICAgICB0cnk6IG1lYXN1cmUoJ2RhZW1vbl9yZXN0YXJ0'
    'JyxsYW1iZGE6cmVjb25uZWN0KFRydWUpKQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgYm9k'
    'eT17J3NjaGVtYSc6MSwnZXZlbnQnOidnbG9iYWxfdGVzdCcsJ21hbmFnZXInOicwLjIuMjInLCdydW4nOnRlc3Rfc3RhdHVz'
    'KCkuZ2V0KCdydW4nLG9zLnVyYW5kb20oMTIpLmhleCgpKSwnb3V0Y29tZSc6b3V0Y29tZSwnZHVyYXRpb25fbXMnOnJvdW5k'
    'KCh0aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpKjEwMDApLCdyZWNvcmRzJzpyZWNvcmRzWzoyNTZdfQogICAgICAgIHdyaXRl'
    'KFBFTkRJTkdfVEVTVCxqc29uLmR1bXBzKGJvZHkpKQogICAgICAgIHRlc3Rfc3RhdGUocGhhc2U9b3V0Y29tZSxwcm9ncmVz'
    'cz0xMDAsc2VudD1GYWxzZSxkdXJhdGlvbl9zPXJvdW5kKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCksCiAgICAgICAgICAg'
    'ICAgICAgICBwYXNzZWQ9c3VtKGJvb2woeC5nZXQoJ29rJykpIGZvciB4IGluIHJlY29yZHMpLGZhaWxlZD1zdW0obm90IHgu'
    'Z2V0KCdvaycpIGZvciB4IGluIHJlY29yZHMpLAogICAgICAgICAgICAgICAgICAgbWVzc2FnZT0n0J7RgtGH0ZHRgiDRgdC+'
    '0YXRgNCw0L3RkdC9LiDQntC20LjQtNCw0LXRgiDQvtGC0L/RgNCw0LLQutC4INGH0LXRgNC10LcgU3RhckZpdmUuJykKICAg'
    'ICAgICB0cnk6IGZsdXNoX3Rlc3RfcmVwb3J0KCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBraWNrX2RlbGl2ZXJ5KCkK'
    'ICAgICAgICBpZiBjb25uZWN0ZWQoKSBhbmQgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKToKICAgICAgICAgICAgY21kKFsn'
    'c3lzdGVtY3RsJywnc3RhcnQnLE1PTklUT1JdLGNoZWNrPUZhbHNlKQogICAgICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJ'
    'R1RFUk0sb2xkKQo='
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
    pexp.add_argument("experimental_cmd", choices=["prepare", "import", "on", "off", "status", "report", "global-test", "cancel-test", "telemetry-on", "telemetry-off", "send-diagnostics"])
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
    # CLI, GUI and autostart must not stop/reconfigure each other's core midway
    # through a transaction. Status/read-only commands remain lock-free.
    operation_lock = None
    if operation_requires_lock(args):
        ensure_runtime(settings)
        operation_lock = open(RUNTIME_DIR / "operation.lock", "a")
        try:
            fcntl.flock(operation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Другая операция VPN ещё выполняется. Дождись её завершения; Xray не изменён.")
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
