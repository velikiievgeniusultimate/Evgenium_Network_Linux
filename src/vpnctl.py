#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import pwd
import pathlib
import random
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
import urllib.parse
import urllib.request
import zipfile
from typing import NoReturn

MANAGER_VERSION = "0.2.14"

# Не "latest". Это намеренно совместимый pin.
# Его меняет следующая проверенная версия VPN Manager.
SAFE_XRAY_VERSION = "26.7.28"

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")
STATE = pathlib.Path("/var/lib/vpn-manager/state.json")
RUNTIME_DIR = pathlib.Path("/run/vpn-manager")
RUNTIME_CONFIG = RUNTIME_DIR / "config.json"

XRAY = pathlib.Path("/opt/vpn-manager/bin/xray")
XRAY_PREVIOUS = pathlib.Path("/opt/vpn-manager/bin/xray.previous")
SERVICE = "vpn-xray.service"
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
    'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zCgppbXBvcnQgYmFzZTY0Cmlt'
    'cG9ydCBodHRwLnNlcnZlcgppbXBvcnQganNvbgppbXBvcnQgb3MKaW1wb3J0IHBhdGhsaWIKaW1wb3J0IHNlY3JldHMKaW1wb3J0'
    'IHNodXRpbAppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgc3lzCmltcG9ydCB0aHJlYWRpbmcKaW1wb3J0IHVybGxpYi5wYXJzZQoK'
    'QVBQX05BTUUgPSAiRXZnZW5pdW0gTmV0d29yayIKVlBOID0gIi91c3IvbG9jYWwvYmluL3ZwbiIKSEVSRSA9IHBhdGhsaWIuUGF0'
    'aChfX2ZpbGVfXykucmVzb2x2ZSgpLnBhcmVudApRTUxfRklMRSA9IEhFUkUgLyAiZXZnZW5pdW1fZ3VpLnFtbCIKTUFYX0JPRFkg'
    'PSA2NCAqIDEwMjQKCgpkZWYgZmluZF9xbWxfcnVudGltZSgpIC0+IHN0ciB8IE5vbmU6CiAgICBmb3IgY2FuZGlkYXRlIGluICgi'
    'L3Vzci9iaW4vcW1sNiIsICIvdXNyL2xpYi9xdDYvYmluL3FtbCIsICIvdXNyL2Jpbi9xbWwiKToKICAgICAgICBpZiBwYXRobGli'
    'LlBhdGgoY2FuZGlkYXRlKS5pc19maWxlKCkgYW5kIG9zLmFjY2VzcyhjYW5kaWRhdGUsIG9zLlhfT0spOgogICAgICAgICAgICBy'
    'ZXR1cm4gY2FuZGlkYXRlCiAgICByZXR1cm4gc2h1dGlsLndoaWNoKCJxbWw2Iikgb3Igc2h1dGlsLndoaWNoKCJxbWwiKQoKCmRl'
    'ZiBydW5fdnBuKGFyZ3M6IGxpc3Rbc3RyXSwgdGltZW91dDogaW50ID0gMTIwKSAtPiBzdHI6CiAgICBjcCA9IHN1YnByb2Nlc3Mu'
    'cnVuKAogICAgICAgIFtWUE4sICphcmdzXSwKICAgICAgICB0ZXh0PVRydWUsCiAgICAgICAgc3Rkb3V0PXN1YnByb2Nlc3MuUElQ'
    'RSwKICAgICAgICBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgIHRpbWVvdXQ9dGltZW91dCwKICAgICAgICBjaGVjaz1G'
    'YWxzZSwKICAgICkKICAgIGlmIGNwLnJldHVybmNvZGUgIT0gMDoKICAgICAgICBkZXRhaWwgPSAoY3Auc3RkZXJyIG9yIGNwLnN0'
    'ZG91dCBvciBmImV4aXQge2NwLnJldHVybmNvZGV9Iikuc3RyaXAoKQogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihkZXRhaWwp'
    'CiAgICByZXR1cm4gKGNwLnN0ZG91dCBvciAiIikuc3RyaXAoKQoKCmRlZiBydW5fdnBuX2pzb24oYXJnczogbGlzdFtzdHJdKSAt'
    'PiBkaWN0OgogICAgcmF3ID0gcnVuX3ZwbihhcmdzKQogICAgdHJ5OgogICAgICAgIGRhdGEgPSBqc29uLmxvYWRzKHJhdykKICAg'
    'IGV4Y2VwdCBqc29uLkpTT05EZWNvZGVFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGYiVlBOIE1hbmFn'
    'ZXIg0LLQtdGA0L3Rg9C7INC90LXQutC+0YDRgNC10LrRgtC90YvQuSBKU09OOiB7ZXhjfSIpIGZyb20gZXhjCiAgICBpZiBub3Qg'
    'aXNpbnN0YW5jZShkYXRhLCBkaWN0KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoIlZQTiBNYW5hZ2VyINCy0LXRgNC90YPQ'
    'uyDQvdC10L7QttC40LTQsNC90L3Ri9C5INC+0YLQstC10YIuIikKICAgIHJldHVybiBkYXRhCgoKZGVmIGVuY29kZV91aV9wYXls'
    'b2FkKHBheWxvYWQ6IGRpY3QpIC0+IHN0cjoKICAgIHJhdyA9IGpzb24uZHVtcHMocGF5bG9hZCwgZW5zdXJlX2FzY2lpPUZhbHNl'
    'LCBzZXBhcmF0b3JzPSgiLCIsICI6IikpCiAgICBxdW90ZWQgPSB1cmxsaWIucGFyc2UucXVvdGUocmF3LCBzYWZlPSIiKQogICAg'
    'cmV0dXJuIGJhc2U2NC5iNjRlbmNvZGUocXVvdGVkLmVuY29kZSgiYXNjaWkiKSkuZGVjb2RlKCJhc2NpaSIpCgoKY2xhc3MgQXBp'
    'U2VydmVyKGh0dHAuc2VydmVyLlRocmVhZGluZ0hUVFBTZXJ2ZXIpOgogICAgZGFlbW9uX3RocmVhZHMgPSBUcnVlCiAgICBhbGxv'
    'd19yZXVzZV9hZGRyZXNzID0gRmFsc2UKCiAgICBkZWYgX19pbml0X18oc2VsZiwgYWRkcmVzcywgaGFuZGxlciwgdG9rZW46IHN0'
    'cik6CiAgICAgICAgc3VwZXIoKS5fX2luaXRfXyhhZGRyZXNzLCBoYW5kbGVyKQogICAgICAgIHNlbGYudG9rZW4gPSB0b2tlbgoK'
    'CmNsYXNzIEhhbmRsZXIoaHR0cC5zZXJ2ZXIuQmFzZUhUVFBSZXF1ZXN0SGFuZGxlcik6CiAgICBzZXJ2ZXI6IEFwaVNlcnZlcgoK'
    'ICAgIGRlZiBsb2dfbWVzc2FnZShzZWxmLCBfZm9ybWF0OiBzdHIsICpfYXJncykgLT4gTm9uZToKICAgICAgICByZXR1cm4KCiAg'
    'ICBkZWYgX2hlYWRlcnMoc2VsZiwgc3RhdHVzOiBpbnQgPSAyMDAsIGNvbnRlbnRfdHlwZTogc3RyID0gImFwcGxpY2F0aW9uL2pz'
    'b247IGNoYXJzZXQ9dXRmLTgiKSAtPiBOb25lOgogICAgICAgIHNlbGYuc2VuZF9yZXNwb25zZShzdGF0dXMpCiAgICAgICAgc2Vs'
    'Zi5zZW5kX2hlYWRlcigiQ29udGVudC1UeXBlIiwgY29udGVudF90eXBlKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNhY2hl'
    'LUNvbnRyb2wiLCAibm8tc3RvcmUiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdp'
    'biIsICIqIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzIiwgIkNvbnRlbnQt'
    'VHlwZSwgWC1Fdmdlbml1bS1Ub2tlbiIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0'
    'aG9kcyIsICJHRVQsIFBPU1QsIE9QVElPTlMiKQogICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQoKICAgIGRlZiBfanNvbihzZWxm'
    'LCBwYXlsb2FkOiBkaWN0LCBzdGF0dXM6IGludCA9IDIwMCkgLT4gTm9uZToKICAgICAgICBkYXRhID0ganNvbi5kdW1wcyhwYXls'
    'b2FkLCBlbnN1cmVfYXNjaWk9RmFsc2UsIHNlcGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCJ1dGYtOCIpCiAgICAgICAgc2Vs'
    'Zi5zZW5kX3Jlc3BvbnNlKHN0YXR1cykKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRp'
    'b24vanNvbjsgY2hhcnNldD11dGYtOCIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC1MZW5ndGgiLCBzdHIobGVu'
    'KGRhdGEpKSkKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDYWNoZS1Db250cm9sIiwgIm5vLXN0b3JlIikKICAgICAgICBzZWxm'
    'LnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iLCAiKiIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigi'
    'QWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycyIsICJDb250ZW50LVR5cGUsIFgtRXZnZW5pdW0tVG9rZW4iKQogICAgICAgIHNl'
    'bGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMiLCAiR0VULCBQT1NULCBPUFRJT05TIikKICAgICAg'
    'ICBzZWxmLmVuZF9oZWFkZXJzKCkKICAgICAgICBzZWxmLndmaWxlLndyaXRlKGRhdGEpCgogICAgZGVmIF9hdXRob3JpemVkKHNl'
    'bGYpIC0+IGJvb2w6CiAgICAgICAgcmV0dXJuIHNlY3JldHMuY29tcGFyZV9kaWdlc3QoCiAgICAgICAgICAgIHNlbGYuaGVhZGVy'
    'cy5nZXQoIlgtRXZnZW5pdW0tVG9rZW4iLCAiIiksCiAgICAgICAgICAgIHNlbGYuc2VydmVyLnRva2VuLAogICAgICAgICkKCiAg'
    'ICBkZWYgX3JlcXVpcmVfYXV0aChzZWxmKSAtPiBib29sOgogICAgICAgIGlmIHNlbGYuX2F1dGhvcml6ZWQoKToKICAgICAgICAg'
    'ICAgcmV0dXJuIFRydWUKICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogInVuYXV0aG9yaXplZCJ9LCA0'
    'MDMpCiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgZGVmIF9yZWFkX2pzb24oc2VsZikgLT4gZGljdDoKICAgICAgICB0cnk6CiAg'
    'ICAgICAgICAgIGxlbmd0aCA9IGludChzZWxmLmhlYWRlcnMuZ2V0KCJDb250ZW50LUxlbmd0aCIsICIwIikpCiAgICAgICAgZXhj'
    'ZXB0IFZhbHVlRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LXQutC+0YDRgNC10LrRgtC9'
    '0YvQuSBDb250ZW50LUxlbmd0aC4iKSBmcm9tIGV4YwogICAgICAgIGlmIGxlbmd0aCA8IDAgb3IgbGVuZ3RoID4gTUFYX0JPRFk6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KHQu9C40YjQutC+0Lwg0LHQvtC70YzRiNC+0Lkg0LfQsNC/0YDQvtGB'
    'LiIpCiAgICAgICAgcmF3ID0gc2VsZi5yZmlsZS5yZWFkKGxlbmd0aCkKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBheWxvYWQg'
    'PSBqc29uLmxvYWRzKHJhdy5kZWNvZGUoInV0Zi04IikgaWYgcmF3IGVsc2UgInt9IikKICAgICAgICBleGNlcHQgKFVuaWNvZGVE'
    'ZWNvZGVFcnJvciwganNvbi5KU09ORGVjb2RlRXJyb3IpIGFzIGV4YzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGYi'
    '0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5IEpTT046IHtleGN9IikgZnJvbSBleGMKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShw'
    'YXlsb2FkLCBkaWN0KToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQntC20LjQtNCw0LvRgdGPIEpTT04gb2JqZWN0'
    'LiIpCiAgICAgICAgcmV0dXJuIHBheWxvYWQKCiAgICBkZWYgZG9fT1BUSU9OUyhzZWxmKSAtPiBOb25lOgogICAgICAgIHNlbGYu'
    'X2hlYWRlcnMoMjA0KQoKICAgIGRlZiBkb19HRVQoc2VsZikgLT4gTm9uZToKICAgICAgICBpZiBub3Qgc2VsZi5fcmVxdWlyZV9h'
    'dXRoKCk6CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL3N0'
    'YXRlIjoKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IFRydWUsICJzdGF0ZSI6IHJ1bl92cG5fanNvbihbInVpIiwg'
    'InN0YXRlIl0pfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvcnVubmlu'
    'ZyI6CiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAicnVubmluZyI6IHJ1bl92cG5fanNvbihbInVpIiwg'
    'InJ1bm5pbmciXSl9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIHNlbGYucGF0aCA9PSAiL2FwaS9oZWFs'
    'dGgiOgogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgImFwcCI6IEFQUF9OQU1FfSkKICAgICAgICAgICAg'
    'ICAgIHJldHVybgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogIm5vdCBmb3VuZCJ9LCA0MDQp'
    'CiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAiZXJy'
    'b3IiOiBzdHIoZXhjKX0sIDUwMCkKCiAgICBkZWYgZG9fUE9TVChzZWxmKSAtPiBOb25lOgogICAgICAgIGlmIG5vdCBzZWxmLl9y'
    'ZXF1aXJlX2F1dGgoKToKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYXlsb2FkID0gc2VsZi5f'
    'cmVhZF9qc29uKCkKICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL2FjdGlvbiI6CiAgICAgICAgICAgICAgICB0b2tl'
    'biA9IGVuY29kZV91aV9wYXlsb2FkKHBheWxvYWQpCiAgICAgICAgICAgICAgICBvdXRwdXQgPSBydW5fdnBuKFsidWkiLCAiYWN0'
    'aW9uIiwgdG9rZW5dKQogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgIm91dHB1dCI6IG91dHB1dH0pCiAg'
    'ICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL3RvZ2dsZSI6CiAgICAgICAgICAg'
    'ICAgICBvdXRwdXQgPSBydW5fdnBuKFsidG9nZ2xlIl0pCiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAi'
    'b3V0cHV0Ijogb3V0cHV0LCAic3RhdGUiOiBydW5fdnBuX2pzb24oWyJ1aSIsICJzdGF0ZSJdKX0pCiAgICAgICAgICAgICAgICBy'
    'ZXR1cm4KICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6ICJub3QgZm91bmQifSwgNDA0KQogICAg'
    'ICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjog'
    'c3RyKGV4Yyl9LCA1MDApCgoKZGVmIHN0YXRlX2xvZ19wYXRoKCkgLT4gcGF0aGxpYi5QYXRoOgogICAgcm9vdCA9IHBhdGhsaWIu'
    'UGF0aChvcy5lbnZpcm9uLmdldCgiWERHX1NUQVRFX0hPTUUiLCBwYXRobGliLlBhdGguaG9tZSgpIC8gIi5sb2NhbCIgLyAic3Rh'
    'dGUiKSkKICAgIHBhdGggPSByb290IC8gImV2Z2VuaXVtLW5ldHdvcmsiIC8gImd1aS5sb2ciCiAgICBwYXRoLnBhcmVudC5ta2Rp'
    'cihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICByZXR1cm4gcGF0aAoKCmRlZiBsYXVuY2hfZGV0YWNoZWQoKSAtPiBp'
    'bnQ6CiAgICBpZiBub3QgUU1MX0ZJTEUuaXNfZmlsZSgpOgogICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC10L0g0LjQvdGC'
    '0LXRgNGE0LXQudGBOiB7UU1MX0ZJTEV9IiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgZmlu'
    'ZF9xbWxfcnVudGltZSgpOgogICAgICAgIHByaW50KCLQndC1INC90LDQudC00LXQvSBxbWw2LiDQndGD0LbQtdC9IFF0IDYgUU1M'
    'IHJ1bnRpbWUgKHF0Ni1kZWNsYXJhdGl2ZSkuIiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBsb2dfcGF0'
    'aCA9IHN0YXRlX2xvZ19wYXRoKCkKICAgIHdpdGggbG9nX3BhdGgub3BlbigiYWIiLCBidWZmZXJpbmc9MCkgYXMgbG9nOgogICAg'
    'ICAgIHN1YnByb2Nlc3MuUG9wZW4oCiAgICAgICAgICAgIFtzeXMuZXhlY3V0YWJsZSwgc3RyKHBhdGhsaWIuUGF0aChfX2ZpbGVf'
    'XykucmVzb2x2ZSgpKV0sCiAgICAgICAgICAgIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwKICAgICAgICAgICAgc3Rkb3V0PWxv'
    'ZywKICAgICAgICAgICAgc3RkZXJyPWxvZywKICAgICAgICAgICAgc3RhcnRfbmV3X3Nlc3Npb249VHJ1ZSwKICAgICAgICAgICAg'
    'Y2xvc2VfZmRzPVRydWUsCiAgICAgICAgKQogICAgcmV0dXJuIDAKCgpkZWYgcnVuX2d1aSgpIC0+IGludDoKICAgIHFtbCA9IGZp'
    'bmRfcW1sX3J1bnRpbWUoKQogICAgaWYgbm90IHFtbDoKICAgICAgICBwcmludCgi0J3QtSDQvdCw0LnQtNC10L0gcW1sNi4g0J3R'
    'g9C20LXQvSBRdCA2IFFNTCBydW50aW1lIChxdDYtZGVjbGFyYXRpdmUpLiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1'
    'cm4gMQogICAgaWYgbm90IFFNTF9GSUxFLmlzX2ZpbGUoKToKICAgICAgICBwcmludChmItCd0LUg0L3QsNC50LTQtdC9INC40L3R'
    'gtC10YDRhNC10LnRgToge1FNTF9GSUxFfSIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQoKICAgIHRva2VuID0g'
    'c2VjcmV0cy50b2tlbl91cmxzYWZlKDMyKQogICAgc2VydmVyID0gQXBpU2VydmVyKCgiMTI3LjAuMC4xIiwgMCksIEhhbmRsZXIs'
    'IHRva2VuKQogICAgcG9ydCA9IGludChzZXJ2ZXIuc2VydmVyX2FkZHJlc3NbMV0pCiAgICB0aHJlYWQgPSB0aHJlYWRpbmcuVGhy'
    'ZWFkKHRhcmdldD1zZXJ2ZXIuc2VydmVfZm9yZXZlciwgbmFtZT0iZXZnZW5pdW0tZ3VpLWFwaSIsIGRhZW1vbj1UcnVlKQogICAg'
    'dGhyZWFkLnN0YXJ0KCkKCiAgICBlbnYgPSBvcy5lbnZpcm9uLmNvcHkoKQogICAgZW52LnNldGRlZmF1bHQoIlFUX1FVSUNLX0NP'
    'TlRST0xTX1NUWUxFIiwgIkJhc2ljIikKICAgIGVudi5zZXRkZWZhdWx0KCJRTUxfRElTQUJMRV9ESVNLX0NBQ0hFIiwgIjAiKQoK'
    'ICAgIHRyeToKICAgICAgICBjcCA9IHN1YnByb2Nlc3MucnVuKAogICAgICAgICAgICBbcW1sLCBzdHIoUU1MX0ZJTEUpLCAiLS0i'
    'LCBzdHIocG9ydCksIHRva2VuXSwKICAgICAgICAgICAgZW52PWVudiwKICAgICAgICAgICAgY2hlY2s9RmFsc2UsCiAgICAgICAg'
    'KQogICAgICAgIHJldHVybiBpbnQoY3AucmV0dXJuY29kZSkKICAgIGZpbmFsbHk6CiAgICAgICAgc2VydmVyLnNodXRkb3duKCkK'
    'ICAgICAgICBzZXJ2ZXIuc2VydmVyX2Nsb3NlKCkKICAgICAgICB0aHJlYWQuam9pbih0aW1lb3V0PTIpCgoKZGVmIHNlbGZfdGVz'
    'dCgpIC0+IGludDoKICAgIHNhbXBsZSA9IHsiYWN0aW9uIjogImFwcF9hZGQiLCAidGFyZ2V0IjogIi9vcHQvZXhhbXBsZS9iaW4v'
    'YXBwIn0KICAgIHRva2VuID0gZW5jb2RlX3VpX3BheWxvYWQoc2FtcGxlKQogICAgZGVjb2RlZCA9IHVybGxpYi5wYXJzZS51bnF1'
    'b3RlKGJhc2U2NC5iNjRkZWNvZGUodG9rZW4pLmRlY29kZSgiYXNjaWkiKSkKICAgIGFzc2VydCBqc29uLmxvYWRzKGRlY29kZWQp'
    'ID09IHNhbXBsZQogICAgYXNzZXJ0IE1BWF9CT0RZIDw9IDEwMjQgKiAxMDI0CiAgICBxbWwgPSBIRVJFIC8gImV2Z2VuaXVtX2d1'
    'aS5xbWwiCiAgICBpZiBxbWwuZXhpc3RzKCk6CiAgICAgICAgdGV4dCA9IHFtbC5yZWFkX3RleHQoZW5jb2Rpbmc9InV0Zi04IikK'
    'ICAgICAgICBhc3NlcnQgIkV2Z2VuaXVtIE5ldHdvcmsiIGluIHRleHQKICAgICAgICBhc3NlcnQgIi9hcGkvcnVubmluZyIgaW4g'
    'dGV4dAogICAgICAgIGFzc2VydCAiL2FwaS9hY3Rpb24iIGluIHRleHQKICAgIHByaW50KCJldmdlbml1bS1ndWkgc2VsZi10ZXN0'
    'IE9LIikKICAgIHJldHVybiAwCgoKZGVmIG1haW4oKSAtPiBpbnQ6CiAgICBpZiAiLS1zZWxmLXRlc3QiIGluIHN5cy5hcmd2Ogog'
    'ICAgICAgIHJldHVybiBzZWxmX3Rlc3QoKQogICAgaWYgIi0tZGV0YWNoIiBpbiBzeXMuYXJndjoKICAgICAgICByZXR1cm4gbGF1'
    'bmNoX2RldGFjaGVkKCkKICAgIHJldHVybiBydW5fZ3VpKCkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgcmFpc2Ug'
    'U3lzdGVtRXhpdChtYWluKCkpCg=='
)
STANDALONE_GUI_QML_B64 = (
    'aW1wb3J0IFF0UXVpY2sKaW1wb3J0IFF0UW1sCmltcG9ydCBRdFF1aWNrLkNvbnRyb2xzIGFzIEMKaW1wb3J0IFF0UXVpY2suTGF5'
    'b3V0cwoKQy5BcHBsaWNhdGlvbldpbmRvdyB7CiAgICBpZDogcm9vdAogICAgd2lkdGg6IDEwNDAKICAgIGhlaWdodDogNzAwCiAg'
    'ICBtaW5pbXVtV2lkdGg6IDg2MAogICAgbWluaW11bUhlaWdodDogNTgwCiAgICB2aXNpYmxlOiB0cnVlCiAgICB0aXRsZTogIkV2'
    'Z2VuaXVtIE5ldHdvcmsiCiAgICBjb2xvcjogIiNmNGY2ZmEiCgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYmc6ICIjZjRm'
    'NmZhIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3Igc3VyZmFjZTogIiNmZmZmZmYiCiAgICByZWFkb25seSBwcm9wZXJ0eSBj'
    'b2xvciBzaWRlYmFyOiAiIzExMTgyNyIKICAgIHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIHNpZGViYXJIb3ZlcjogIiMxZjI5Mzci'
    'CiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciBhY2NlbnQ6ICIjMzlhZWYwIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3Ig'
    'YWNjZW50U29mdDogIiNlOGY2ZmUiCiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciB0ZXh0TWFpbjogIiMxMTE4MjciCiAgICBy'
    'ZWFkb25seSBwcm9wZXJ0eSBjb2xvciB0ZXh0TXV0ZWQ6ICIjNmI3MjgwIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYm9y'
    'ZGVyOiAiI2U1ZTdlYiIKICAgIHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIGdvb2Q6ICIjMTZhMzRhIgogICAgcmVhZG9ubHkgcHJv'
    'cGVydHkgY29sb3IgYmFkOiAiI2RjMjYyNiIKCiAgICBwcm9wZXJ0eSBpbnQgcGFnZUluZGV4OiAwCiAgICBwcm9wZXJ0eSBib29s'
    'IGJ1c3k6IGZhbHNlCiAgICBwcm9wZXJ0eSBzdHJpbmcgZXJyb3JUZXh0OiAiIgogICAgcHJvcGVydHkgdmFyIHN0YXRlOiAoe30p'
    'CiAgICBwcm9wZXJ0eSB2YXIgcnVubmluZ0FwcHM6IFtdCgogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIGFyZ3M6IFF0LmFwcGxp'
    'Y2F0aW9uLmFyZ3VtZW50cwogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVRva2VuOiBhcmdzLmxlbmd0aCA+PSAyID8g'
    'U3RyaW5nKGFyZ3NbYXJncy5sZW5ndGggLSAxXSkgOiAiIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVBvcnQ6IGFy'
    'Z3MubGVuZ3RoID49IDMgPyBTdHJpbmcoYXJnc1thcmdzLmxlbmd0aCAtIDJdKSA6ICIwIgogICAgcmVhZG9ubHkgcHJvcGVydHkg'
    'c3RyaW5nIGFwaUJhc2U6ICJodHRwOi8vMTI3LjAuMC4xOiIgKyBhcGlQb3J0CgogICAgZnVuY3Rpb24gcGFyc2VSZXBseSh4aHIs'
    'IGNhbGxiYWNrKSB7CiAgICAgICAgbGV0IHBheWxvYWQgPSBudWxsCiAgICAgICAgdHJ5IHsKICAgICAgICAgICAgcGF5bG9hZCA9'
    'IEpTT04ucGFyc2UoU3RyaW5nKHhoci5yZXNwb25zZVRleHQgfHwgInt9IikpCiAgICAgICAgfSBjYXRjaCAoZSkgewogICAgICAg'
    'ICAgICBlcnJvclRleHQgPSAi0J3QtSDRg9C00LDQu9C+0YHRjCDRgNCw0LfQvtCx0YDQsNGC0Ywg0L7RgtCy0LXRgiDQu9C+0LrQ'
    'sNC70YzQvdC+0LPQviBBUEkiCiAgICAgICAgICAgIGJ1c3kgPSBmYWxzZQogICAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAg'
    'ICAgICAgaWYgKHhoci5zdGF0dXMgPCAyMDAgfHwgeGhyLnN0YXR1cyA+PSAzMDAgfHwgIXBheWxvYWQub2spIHsKICAgICAgICAg'
    'ICAgZXJyb3JUZXh0ID0gU3RyaW5nKHBheWxvYWQuZXJyb3IgfHwgKCJIVFRQICIgKyB4aHIuc3RhdHVzKSkKICAgICAgICAgICAg'
    'YnVzeSA9IGZhbHNlCiAgICAgICAgICAgIHJldHVybgogICAgICAgIH0KICAgICAgICBlcnJvclRleHQgPSAiIgogICAgICAgIGlm'
    'IChjYWxsYmFjaykKICAgICAgICAgICAgY2FsbGJhY2socGF5bG9hZCkKICAgIH0KCiAgICBmdW5jdGlvbiBhcGkobWV0aG9kLCBw'
    'YXRoLCBib2R5LCBjYWxsYmFjaykgewogICAgICAgIGNvbnN0IHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpCiAgICAgICAgeGhy'
    'Lm9wZW4obWV0aG9kLCBhcGlCYXNlICsgcGF0aCwgdHJ1ZSkKICAgICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcigiWC1Fdmdlbml1'
    'bS1Ub2tlbiIsIGFwaVRva2VuKQogICAgICAgIGlmIChib2R5ICE9PSBudWxsKQogICAgICAgICAgICB4aHIuc2V0UmVxdWVzdEhl'
    'YWRlcigiQ29udGVudC1UeXBlIiwgImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgiKQogICAgICAgIHhoci5vbnJlYWR5'
    'c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHsKICAgICAgICAgICAgaWYgKHhoci5yZWFkeVN0YXRlID09PSBYTUxIdHRwUmVxdWVz'
    'dC5ET05FKQogICAgICAgICAgICAgICAgcm9vdC5wYXJzZVJlcGx5KHhociwgY2FsbGJhY2spCiAgICAgICAgfQogICAgICAgIHho'
    'ci5zZW5kKGJvZHkgPT09IG51bGwgPyBudWxsIDogSlNPTi5zdHJpbmdpZnkoYm9keSkpCiAgICB9CgogICAgZnVuY3Rpb24gcmVm'
    'cmVzaFN0YXRlKCkgewogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvc3RhdGUiLCBudWxsLCBmdW5jdGlvbihwYXlsb2FkKSB7CiAg'
    'ICAgICAgICAgIHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9KQogICAgfQoKICAgIGZ1bmN0aW9u'
    'IHJlZnJlc2hSdW5uaW5nKCkgewogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvcnVubmluZyIsIG51bGwsIGZ1bmN0aW9uKHBheWxv'
    'YWQpIHsKICAgICAgICAgICAgcm9vdC5ydW5uaW5nQXBwcyA9IChwYXlsb2FkLnJ1bm5pbmcgJiYgcGF5bG9hZC5ydW5uaW5nLmFw'
    'cGxpY2F0aW9ucykgfHwgW10KICAgICAgICB9KQogICAgfQoKICAgIGZ1bmN0aW9uIGFjdGlvbihwYXlsb2FkKSB7CiAgICAgICAg'
    'aWYgKGJ1c3kpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGJ1c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkv'
    'YWN0aW9uIiwgcGF5bG9hZCwgZnVuY3Rpb24oX3JlcGx5KSB7CiAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAg'
    'ICAgIHJvb3QucmVmcmVzaFN0YXRlKCkKICAgICAgICAgICAgcm9vdC5yZWZyZXNoUnVubmluZygpCiAgICAgICAgfSkKICAgIH0K'
    'CiAgICBmdW5jdGlvbiB0b2dnbGVWcG4oKSB7CiAgICAgICAgaWYgKGJ1c3kpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGJ1'
    'c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkvdG9nZ2xlIiwge30sIGZ1bmN0aW9uKHBheWxvYWQpIHsKICAgICAg'
    'ICAgICAgcm9vdC5idXN5ID0gZmFsc2UKICAgICAgICAgICAgcm9vdC5zdGF0ZSA9IHBheWxvYWQuc3RhdGUgfHwgKHt9KQogICAg'
    'ICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gZmlsdGVyZWRSdW5uaW5nKCkgewogICAgICAgIGNvbnN0IG5lZWRsZSA9IGFwcFNl'
    'YXJjaC50ZXh0LnRyaW0oKS50b0xvd2VyQ2FzZSgpCiAgICAgICAgaWYgKCFuZWVkbGUubGVuZ3RoKQogICAgICAgICAgICByZXR1'
    'cm4gcnVubmluZ0FwcHMKICAgICAgICByZXR1cm4gcnVubmluZ0FwcHMuZmlsdGVyKGZ1bmN0aW9uKGFwcCkgewogICAgICAgICAg'
    'ICByZXR1cm4gU3RyaW5nKGFwcC5uYW1lIHx8ICIiKS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICAgICAg'
    'ICAgIHx8IFN0cmluZyhhcHAuZXhlIHx8ICIiKS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICB9KQogICAg'
    'fQoKICAgIENvbXBvbmVudC5vbkNvbXBsZXRlZDogewogICAgICAgIHJlZnJlc2hTdGF0ZSgpCiAgICAgICAgcmVmcmVzaFJ1bm5p'
    'bmcoKQogICAgfQoKICAgIFRpbWVyIHsKICAgICAgICBpbnRlcnZhbDogMjUwMAogICAgICAgIHJlcGVhdDogdHJ1ZQogICAgICAg'
    'IHJ1bm5pbmc6IHRydWUKICAgICAgICBvblRyaWdnZXJlZDogcm9vdC5yZWZyZXNoU3RhdGUoKQogICAgfQoKICAgIGNvbXBvbmVu'
    'dCBGbGF0QnV0dG9uOiBSZWN0YW5nbGUgewogICAgICAgIGlkOiBmbGF0QnV0dG9uCiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkg'
    'c3RyaW5nIGxhYmVsCiAgICAgICAgcHJvcGVydHkgYm9vbCBwcmltYXJ5OiBmYWxzZQogICAgICAgIHByb3BlcnR5IGJvb2wgZGFu'
    'Z2VyOiBmYWxzZQogICAgICAgIHByb3BlcnR5IGJvb2wgZW5hYmxlZEJ1dHRvbjogdHJ1ZQogICAgICAgIHNpZ25hbCBjbGlja2Vk'
    'KCkKICAgICAgICBpbXBsaWNpdEhlaWdodDogMzgKICAgICAgICBpbXBsaWNpdFdpZHRoOiBNYXRoLm1heCg5MiwgYnV0dG9uVGV4'
    'dC5pbXBsaWNpdFdpZHRoICsgMjgpCiAgICAgICAgcmFkaXVzOiAxMAogICAgICAgIGNvbG9yOiAhZW5hYmxlZEJ1dHRvbiA/ICIj'
    'ZWVmMGYzIgogICAgICAgICAgICAgIDogZGFuZ2VyID8gKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiI2ZlZTJlMiIgOiAi'
    'I2ZlZjJmMiIpCiAgICAgICAgICAgICAgOiBwcmltYXJ5ID8gKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiIzIwOTlkYyIg'
    'OiByb290LmFjY2VudCkKICAgICAgICAgICAgICA6IChidXR0b25Nb3VzZS5jb250YWluc01vdXNlID8gIiNlZWYyZjciIDogIiNm'
    'N2Y5ZmMiKQogICAgICAgIGJvcmRlci53aWR0aDogcHJpbWFyeSA/IDAgOiAxCiAgICAgICAgYm9yZGVyLmNvbG9yOiBkYW5nZXIg'
    'PyAiI2ZlY2FjYSIgOiByb290LmJvcmRlcgogICAgICAgIG9wYWNpdHk6IGVuYWJsZWRCdXR0b24gPyAxIDogMC42CgogICAgICAg'
    'IEMuTGFiZWwgewogICAgICAgICAgICBpZDogYnV0dG9uVGV4dAogICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQK'
    'ICAgICAgICAgICAgdGV4dDogZmxhdEJ1dHRvbi5sYWJlbAogICAgICAgICAgICBjb2xvcjogZmxhdEJ1dHRvbi5wcmltYXJ5ID8g'
    'IndoaXRlIiA6IChmbGF0QnV0dG9uLmRhbmdlciA/IHJvb3QuYmFkIDogcm9vdC50ZXh0TWFpbikKICAgICAgICAgICAgZm9udC5w'
    'aXhlbFNpemU6IDEzCiAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgfQogICAgICAgIE1vdXNl'
    'QXJlYSB7CiAgICAgICAgICAgIGlkOiBidXR0b25Nb3VzZQogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAg'
    'ICAgICBlbmFibGVkOiBmbGF0QnV0dG9uLmVuYWJsZWRCdXR0b24KICAgICAgICAgICAgaG92ZXJFbmFibGVkOiB0cnVlCiAgICAg'
    'ICAgICAgIGN1cnNvclNoYXBlOiBlbmFibGVkID8gUXQuUG9pbnRpbmdIYW5kQ3Vyc29yIDogUXQuQXJyb3dDdXJzb3IKICAgICAg'
    'ICAgICAgb25DbGlja2VkOiBmbGF0QnV0dG9uLmNsaWNrZWQoKQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgTmF2QnV0'
    'dG9uOiBSZWN0YW5nbGUgewogICAgICAgIGlkOiBuYXYKICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbGFiZWwKICAg'
    'ICAgICByZXF1aXJlZCBwcm9wZXJ0eSBpbnQgaW5kZXgKICAgICAgICBwcm9wZXJ0eSBzdHJpbmcgc2hvcnRMYWJlbDogIiIKICAg'
    'ICAgICBzaWduYWwgY2xpY2tlZCgpCiAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgIGltcGxpY2l0V2lkdGg6'
    'IDE4NgogICAgICAgIGhlaWdodDogNDgKICAgICAgICByYWRpdXM6IDExCiAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09'
    'PSBpbmRleCA/ICIjMjUzMjQ2IiA6IChuYXZNb3VzZS5jb250YWluc01vdXNlID8gcm9vdC5zaWRlYmFySG92ZXIgOiAidHJhbnNw'
    'YXJlbnQiKQoKICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBh'
    'bmNob3JzLmxlZnRNYXJnaW46IDEyCiAgICAgICAgICAgIGFuY2hvcnMucmlnaHRNYXJnaW46IDEyCiAgICAgICAgICAgIHNwYWNp'
    'bmc6IDExCiAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICB3aWR0aDogMjgKICAgICAgICAgICAgICAgIGhl'
    'aWdodDogMjgKICAgICAgICAgICAgICAgIHJhZGl1czogOAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09'
    'PSBuYXYuaW5kZXggPyByb290LmFjY2VudCA6ICIjMjczNDQ5IgogICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgdGV4dDogbmF2LnNob3J0TGFiZWwK'
    'ICAgICAgICAgICAgICAgICAgICBjb2xvcjogIndoaXRlIgogICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMAog'
    'ICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'IHRleHQ6IG5hdi5sYWJlbAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyAid2hp'
    'dGUiIDogIiNjYmQ1ZTEiCiAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAgICAgICAgIGZvbnQud2Vp'
    'Z2h0OiByb290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gRm9udC5EZW1pQm9sZCA6IEZvbnQuTm9ybWFsCiAgICAgICAgICAg'
    'IH0KICAgICAgICB9CiAgICAgICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IG5hdk1vdXNlCiAgICAgICAgICAgIGFuY2hv'
    'cnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JTaGFwZTogUXQu'
    'UG9pbnRpbmdIYW5kQ3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgcm9vdC5wYWdlSW5kZXgg'
    'PSBuYXYuaW5kZXgKICAgICAgICAgICAgICAgIG5hdi5jbGlja2VkKCkKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAg'
    'ICBjb21wb25lbnQgQ2FyZDogUmVjdGFuZ2xlIHsKICAgICAgICByYWRpdXM6IDE2CiAgICAgICAgY29sb3I6IHJvb3Quc3VyZmFj'
    'ZQogICAgICAgIGJvcmRlci53aWR0aDogMQogICAgICAgIGJvcmRlci5jb2xvcjogcm9vdC5ib3JkZXIKICAgIH0KCiAgICBSb3dM'
    'YXlvdXQgewogICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgc3BhY2luZzogMAoKICAgICAgICBSZWN0YW5nbGUg'
    'ewogICAgICAgICAgICBMYXlvdXQucHJlZmVycmVkV2lkdGg6IDIyMgogICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1'
    'ZQogICAgICAgICAgICBjb2xvcjogcm9vdC5zaWRlYmFyCgogICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTgKICAgICAgICAgICAgICAg'
    'IHNwYWNpbmc6IDcKCiAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuYm90dG9tTWFyZ2luOiAyNAogICAgICAgICAgICAgICAgICAgIHNw'
    'YWNpbmc6IDExCiAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDQw'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDAKICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAg'
    'ICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5hY2NlbnQKICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHRleHQ6ICJFIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQu'
    'QmxhY2sKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBD'
    'b2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAwCiAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIkV2Z2VuaXVtIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxNgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIk5ldHdvcmsiCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiM5NGEzYjgiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250'
    'LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgIH0KCiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogIlZQTiI7IHNob3J0TGFiZWw6ICJWUE4iOyBpbmRleDog'
    'MCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCf0YDQvtGE0LjQu9C4IFZQTiI7IHNob3J0TGFiZWw6ICJQ'
    'UkYiOyBpbmRleDogMSB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24gewogICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J/R'
    'gNC40LvQvtC20LXQvdC40Y8iOyBzaG9ydExhYmVsOiAiQVBQIjsgaW5kZXg6IDIKICAgICAgICAgICAgICAgICAgICBvbkNsaWNr'
    'ZWQ6IHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFi'
    'ZWw6ICLQodCw0LnRgtGLINC4IElQIjsgc2hvcnRMYWJlbDogIk5FVCI7IGluZGV4OiAzIH0KICAgICAgICAgICAgICAgIE5hdkJ1'
    'dHRvbiB7IGxhYmVsOiAi0J/QvtGA0YLRiyI7IHNob3J0TGFiZWw6ICJQUlQiOyBpbmRleDogNCB9CiAgICAgICAgICAgICAgICBO'
    'YXZCdXR0b24geyBsYWJlbDogItCU0LjQsNCz0L3QvtGB0YLQuNC60LAiOyBzaG9ydExhYmVsOiAiU1lTIjsgaW5kZXg6IDUgfQoK'
    'ICAgICAgICAgICAgICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9CgogICAgICAgICAgICAgICAgUmVjdGFuZ2xl'
    'IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA2'
    'NAogICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTIKICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiMxNzIwMzMiCiAgICAg'
    'ICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxMgogICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6'
    'IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9y'
    'OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/IHJvb3QuZ29vZCA6ICIjNjQ3NDhiIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHJvb3Quc3Rh'
    'dGUuYWN0aXZlKSA/ICJWUE4g0LLQutC70Y7Rh9GR0L0iIDogIlZQTiDQstGL0LrQu9GO0YfQtdC9IgogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNp'
    'emU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0'
    'OiBTdHJpbmcocm9vdC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3RhdGUubGFzdF9wcm9maWxlIHx8ICLQndC10YIg0L/RgNC+0YTQ'
    'uNC70Y8iKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAiIzk0YTNiOCIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4'
    'dC5FbGlkZVJpZ2h0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CgogICAgICAgIEl0ZW0gewog'
    'ICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCgogICAg'
    'ICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMubWFyZ2luczogMjgKICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE4CgogICAgICAgICAgICAgICAgUm93TGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgdGV4'
    'dDogWyJWUE4iLCAi0J/RgNC+0YTQuNC70LggVlBOIiwgItCf0YDQuNC70L7QttC10L3QuNGPINCx0LXQtyBWUE4iLCAi0KHQsNC5'
    '0YLRiyDQuCBJUCDQsdC10LcgVlBOIiwgItCS0YXQvtC00Y/RidC40LUg0L/QvtGA0YLRiyIsICLQlNC40LDQs9C90L7RgdGC0LjQ'
    'utCwIl1bcm9vdC5wYWdlSW5kZXhdCiAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAyNQogICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9u'
    'dC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIEMuQnVzeUluZGljYXRvciB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHJ1bm5pbmc6IHJvb3QuYnVzeQogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBydW5uaW5n'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0'
    'SGVpZ2h0OiAyOAogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgbGFiZWw6ICLQntCx0L3QvtCy0LjRgtGMIgogICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0'
    'dG9uOiAhcm9vdC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgcm9vdC5yZWZyZXNoU3RhdGUoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJvb3QucGFnZUluZGV4ID09'
    'PSAyKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgIFJlY3Rhbmds'
    'ZSB7CiAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5lcnJvclRleHQubGVuZ3RoID4gMAogICAgICAgICAgICAgICAg'
    'ICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogZXJyb3JMYWJlbC5p'
    'bXBsaWNpdEhlaWdodCArIDIyCiAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMAogICAgICAgICAgICAgICAgICAgIGNvbG9y'
    'OiAiI2ZmZjFmMiIKICAgICAgICAgICAgICAgICAgICBib3JkZXIud2lkdGg6IDEKICAgICAgICAgICAgICAgICAgICBib3JkZXIu'
    'Y29sb3I6ICIjZmVjZGQzIgogICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICBpZDog'
    'ZXJyb3JMYWJlbAogICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAg'
    'ICAgICBhbmNob3JzLm1hcmdpbnM6IDExCiAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QuZXJyb3JUZXh0CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LmJhZAogICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5X'
    'b3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgU3RhY2tMYXlvdXQgewogICAgICAgICAgICAgICAgICAgIExheW91dC5m'
    'aWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgIGN1cnJlbnRJbmRleDogcm9vdC5wYWdlSW5kZXgKCiAgICAgICAgICAgICAgICAgICAgLy8gVlBOCiAgICAgICAgICAgICAg'
    'ICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5j'
    'aG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLm1hcmdpbnM6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMjAKCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxOAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'd2lkdGg6IDcyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDcyCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDIyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyByb290LmFjY2VudFNvZnQgOiAiI2VlZjJmNyIKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gIk9OIiA6ICJPRkYiCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9vdC5hY2NlbnQgOiByb290'
    'LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxOAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyAi0JfQsNGJ0LjR'
    'idGR0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0LDQutGC0LjQstC90L4iIDogIlZQTiDRgdC10LnRh9Cw0YEg0LLRi9C6'
    '0LvRjtGH0LXQvSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFp'
    'bgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAyMAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/ICLQktC10YHRjCDQvtCx0YvRh9C90YvQuSDRgtGA0LDR'
    'hNC40Log0LjQtNGR0YIg0YfQtdGA0LXQtyBWUE4sINC60YDQvtC80LUg0L3QsNGB0YLRgNC+0LXQvdC90YvRhSDQuNGB0LrQu9GO'
    '0YfQtdC90LjQuS4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogItCS0LrQu9GO0YfQ'
    'uCBWUE4g0L7QtNC90LjQvCDQvdCw0LbQsNGC0LjQtdC8LiDQkdGD0LTQtdGCINC40YHQv9C+0LvRjNC30L7QstCw0L0g0L/QvtGB'
    '0LvQtdC00L3QuNC5INCy0YvQsdGA0LDQvdC90YvQuSDQv9GA0L7RhNC40LvRjC4iCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBmb250LnBpeGVsU2l6ZTogMTMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/'
    'ICLQktGL0LrQu9GO0YfQuNGC0YwgVlBOIiA6ICLQktC60LvRjtGH0LjRgtGMIFZQTiIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZGFuZ2VyOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgb25DbGlja2VkOiByb290LnRvZ2dsZVZwbigpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3Rhbmds'
    'ZSB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IGhlaWdodDogMTsgY29sb3I6IHJvb3QuYm9yZGVyIH0KCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgR3JpZExheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5m'
    'aWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1uczogMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5TcGFjaW5nOiAyNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICByb3dTcGFjaW5nOiAxNAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQn9GA'
    '0L7RhNC40LvRjCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUucHJv'
    'ZmlsZSB8fCByb290LnN0YXRlLmxhc3RfcHJvZmlsZSB8fCAi4oCUIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250Lndl'
    'aWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiSVB2NiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUuaXB2Nl9tb2RlIHx8ICJ1bmtub3duIikKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiS2lsbCBzd2l0Y2giOyBjb2xvcjogcm9vdC50ZXh0'
    'TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5raWxsX3N3aXRjaCkgPyAi0JDQutGC0LjQstC10L0i'
    'IDogItCS0YvQutC70Y7Rh9C10L0iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVh'
    'bihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JLQtdGA0YHQuNGP'
    'IG1hbmFnZXIiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IFN0cmluZyhyb290LnN0YXRlLm1hbmFn'
    'ZXIgfHwgIuKAlCIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogOTIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci53aWR0aDogMQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyCgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'YW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2lu'
    'czogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE0CgogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB3aWR0aDogNDYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMwogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyByb290'
    'LmFjY2VudFNvZnQgOiAiI2VlZjJmNyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJXRCIKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZm'
    'ZWN0aXZlKSA/IHJvb3QuYWNjZW50IDogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB0ZXh0OiAiVlBOINC00LvRjyBXYXlkcm9pZCIKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICFCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAi0J7QsdGJ0LjQuSBWUE4g0LLRi9C60LvRjtGH0LXQvSDi'
    'gJQgV2F5ZHJvaWQg0YLQvtC20LUg0YDQsNCx0L7RgtCw0LXRgiDQsdC10LcgVlBOLiIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogKEJvb2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgID8gItCi0YDQsNGE0LjQuiBXYXlk'
    'cm9pZCDQuNC00ZHRgiDRh9C10YDQtdC3IEUtVlBOLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICA6ICJXYXlkcm9pZCDQuNGB0L/QvtC70YzQt9GD0LXRgiDQv9GA0Y/QvNC+0Lkg0LjQvdGC0LXRgNC90LXR'
    'giDQsiDQvtCx0YXQvtC0IEUtVlBOLiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNv'
    'bG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBp'
    'eGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6IFRleHQu'
    'V29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHdheWRyb2lkU3dpdGNoCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiA0OAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDI2CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgb3BhY2l0eTogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgJiYgIXJvb3QuYnVzeSA/IDEuMCA6'
    'IDAuNDUKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiBoZWlnaHQgLyAyCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyBy'
    'b290LmFjY2VudCA6ICIjY2JkNWUxIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgaGVpZ2h0OiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEw'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHk6IDMKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgeDogQm9vbGVhbihyb290LnN0YXRlLndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpID8g'
    'd2F5ZHJvaWRTd2l0Y2gud2lkdGggLSB3aWR0aCAtIDMgOiAzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEJl'
    'aGF2aW9yIG9uIHggeyBOdW1iZXJBbmltYXRpb24geyBkdXJhdGlvbjogMTIwIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBNb3VzZUFyZWEg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0'
    'aXZlKSAmJiAhcm9vdC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvclNo'
    'YXBlOiBlbmFibGVkID8gUXQuUG9pbnRpbmdIYW5kQ3Vyc29yIDogUXQuQXJyb3dDdXJzb3IKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhY3Rpb246ICJ3YXlkcm9pZF92cG5fc2V0IiwKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRhcmdldDogQm9vbGVhbihyb290LnN0YXRlLndheWRyb2lkX3Zwbl9l'
    'ZmZlY3RpdmUpID8gIm9mZiIgOiAib24iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0p'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgfQoKCiAgICAgICAgICAgICAgICAgICAgLy8gVlBOIHByb2ZpbGVzCiAgICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6'
    'IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA3OAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA0MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'aGVpZ2h0OiA0MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYWNjZW50U29mdAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9y'
    'cy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIlBSRiIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5hY2NlbnQKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxs'
    'V2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHRleHQ6ICJWUE4t0L/RgNC+0YTQuNC70LgiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBp'
    'eGVsU2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5C'
    'b2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHJvb3Qu'
    'c3RhdGUuY29uZmlnX2RpciB8fCAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjog'
    'cm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTog'
    'MTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgdGV4dDogU3RyaW5nKChyb290LnN0YXRlLnByb2ZpbGVzIHx8IFtdKS5sZW5ndGgpICsgIiDRiNGCLiIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxX'
    'aWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgTGlzdFZpZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDEwCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgc3BhY2luZzogNwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5zdGF0ZS5wcm9m'
    'aWxlcyB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBwcm9maWxlUm93CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaGVpZ2h0OiA2NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/'
    'IHJvb3QuYWNjZW50U29mdCA6ICIjZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVy'
    'LndpZHRoOiBCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkgPyAxIDogMAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgYm9yZGVyLmNvbG9yOiByb290LmFjY2VudAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5m'
    'aWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmxlZnRNYXJnaW46'
    'IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5yaWdodE1hcmdpbjogMTAKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgoKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB3aWR0aDogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAx'
    'MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDYKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZl'
    'KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyByb290Lmdvb2QKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogKEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEu'
    'bGFzdCkgPyByb290LmFjY2VudCA6ICIjY2JkNWUxIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHRleHQ6IFN0cmluZyhwcm9maWxlUm93Lm1vZGVsRGF0YS5zdGVtIHx8IHByb2ZpbGVSb3cubW9kZWxEYXRhLm5hbWUgfHwg'
    'IiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFp'
    'bgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE0CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9s'
    'ZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZGU6IFRleHQuRWxpZGVSaWdo'
    'dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgdGV4dDogQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAi0JDQutGC0LjQstC90YvQuSDQv9GA0L7RhNC40LvRjCIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IChCb29sZWFuKHByb2ZpbGVSb3cu'
    'bW9kZWxEYXRhLmxhc3QpID8gItCf0L7RgdC70LXQtNC90LjQuSDQuNGB0L/QvtC70YzQt9C+0LLQsNC90L3Ri9C5IiA6IFN0cmlu'
    'Zyhwcm9maWxlUm93Lm1vZGVsRGF0YS5uYW1lIHx8ICIiKSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkgPyByb290Lmdvb2QgOiByb290'
    'LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNp'
    'emU6IDExCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4dC5FbGlk'
    'ZU1pZGRsZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBG'
    'bGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IEJvb2xlYW4o'
    'cHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/ICLQkNC60YLQuNCy0LXQvSIgOiAi0J/QvtC00LrQu9GO0YfQuNGC0YwiCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKHByb2ZpbGVSb3cu'
    'bW9kZWxEYXRhLmFjdGl2ZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1'
    'dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9uOiAicHJvZmlsZV9hY3RpdmF0ZSIsCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0YXJnZXQ6IFN0cmluZyhwcm9maWxlUm93Lm1vZGVsRGF0YS5u'
    'YW1lIHx8ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LlNjcm9sbEJhci52ZXJ0aWNhbDogQy5TY3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IChyb290LnN0YXRlLnByb2ZpbGVzIHx8IFtdKS5s'
    'ZW5ndGggPT09IDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQkiDQv9Cw0L/QutC1IFZQ'
    'TiBjb25maWdzINC/0L7QutCwINC90LXRgiDQv9GA0L7RhNC40LvQtdC5IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIEFwcGxpY2F0aW9ucwogICAgICAg'
    'ICAgICAgICAgICAgIEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE0Cgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogODIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6'
    'IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE2CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'VGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBtYW51YWxBcHAKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyVGV4dDogItCY0LzRjyDQv9GA0L7RhtC10YHRgdCwLCAv0L/QvtC70L3Ri9C5'
    'L9C/0YPRgtGMINC40LvQuCAv0L/QsNC/0LrQsC8iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZWxl'
    'Y3RCeU1vdXNlOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiBSZWN0YW5n'
    'bGUgeyByYWRpdXM6IDEwOyBjb2xvcjogIiNmOGZhZmMiOyBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQWNjZXB0ZWQ6IGlmICh0ZXh0LnRyaW0oKS5sZW5ndGgpIHJvb3QuYWN0aW9u'
    'KHthY3Rpb246ICJhcHBfYWRkIiwgdGFyZ2V0OiB0ZXh0LnRyaW0oKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCU0L7QsdCw0LLQuNGC0Ywg0LLRgNGD0YfQvdGD0Y4iCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIG1hbnVhbEFwcC50ZXh0LnRyaW0oKS5sZW5ndGggPiAwCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICByb290LmFjdGlvbih7YWN0aW9uOiAiYXBwX2FkZCIsIHRhcmdldDogbWFudWFsQXBwLnRleHQudHJpbSgp'
    'fSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtYW51YWxBcHAuY2xlYXIoKQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KPQttC1INC40YHQutC70Y7Rh9C1'
    '0L3RiyI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTogMTU7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQ7IExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJp'
    'bmcoKHJvb3Quc3RhdGUuYXBwbGljYXRpb25zIHx8IFtdKS5sZW5ndGgpOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQucHJlZmVycmVkSGVpZ2h0OiAxNDUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgbW9kZWw6IHJvb3Quc3RhdGUuYXBwbGljYXRpb25zIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWly'
    'ZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IExp'
    'c3RWaWV3LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogOQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgY29sb3I6ICIjZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubGVmdE1hcmdpbjogMTIKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiA4CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2RlbERh'
    'dGEpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGUgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBsYWJlbDogItCj0LTQsNC70LjRgtGMIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBkYW5nZXI6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1'
    'dHRvbjogIXJvb3QuYnVzeQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6'
    'IHJvb3QuYWN0aW9uKHthY3Rpb246ICJhcHBfcmVtb3ZlIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhKX0pCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogKHJvb3Quc3RhdGUuYXBwbGljYXRpb25zIHx8'
    'IFtdKS5sZW5ndGggPT09IDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQn9C+0LrQsCDQ'
    'vdC10YIg0L/RgNC40LvQvtC20LXQvdC40Lkt0LjRgdC60LvRjtGH0LXQvdC40LkiCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCX0LDQv9GD0YnQtdC90Ysg'
    '0YHQtdC50YfQsNGBIjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAxNTsgZm9udC53ZWlnaHQ6IEZvbnQu'
    'Qm9sZDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7'
    'IGxhYmVsOiAi0J7QsdC90L7QstC40YLRjCDRgdC/0LjRgdC+0LoiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNsaWNr'
    'ZWQ6IHJvb3QucmVmcmVzaFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5UZXh0RmllbGQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBhcHBTZWFyY2gKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgcGxhY2Vob2xkZXJUZXh0OiAi0J3QsNC50YLQuCDQt9Cw0L/Rg9GJ0LXQvdC90L7QtSDQv9GA0LjQu9C+0LbQtdC9'
    '0LjQtSDQv9C+INC40LzQtdC90Lgg0LjQu9C4INC/0YPRgtC44oCmIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNl'
    'bGVjdEJ5TW91c2U6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiBSZWN0YW5nbGUgeyBy'
    'YWRpdXM6IDEwOyBjb2xvcjogcm9vdC5zdXJmYWNlOyBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxI'
    'ZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFu'
    'Y2hvcnMubWFyZ2luczogOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9k'
    'ZWw6IHJvb3QuZmlsdGVyZWRSdW5uaW5nKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZWdhdGU6IFJl'
    'Y3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9k'
    'ZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53aWR0aAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA2NAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgcmFkaXVzOiAxMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICIj'
    'ZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogOQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHNwYWNpbmc6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDQwOyBoZWlnaHQ6IDQwOyByYWRp'
    'dXM6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKG1vZGVs'
    'RGF0YS5leGNsdWRlZCkgPyAiI2RjZmNlNyIgOiByb290LmFjY2VudFNvZnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHRleHQ6IFN0cmluZyhtb2RlbERhdGEubmFtZSB8fCAiPyIpLnNsaWNlKDAsIDEpLnRvVXBwZXJDYXNlKCkKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKG1vZGVsRGF0YS5leGNs'
    'dWRlZCkgPyByb290Lmdvb2QgOiByb290LmFjY2VudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZm9udC5waXhlbFNpemU6IDE2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBzcGFjaW5nOiAxCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLm5hbWUgfHwgIiIpOyBjb2xvcjogcm9vdC50ZXh0TWFp'
    'bjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQ7IGVsaWRlOiBUZXh0LkVsaWRlUmlnaHQgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5n'
    'KG1vZGVsRGF0YS5leGUgfHwgIiIpOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQ7IGZvbnQucGl4ZWxTaXplOiAxMTsgZWxpZGU6IFRl'
    'eHQuRWxpZGVNaWRkbGUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdmlzaWJsZTogTnVtYmVyKG1vZGVsRGF0YS5jb3VudCB8fCAxKSA+IDEKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIsOXIiArIFN0cmluZyhtb2RlbERhdGEuY291bnQpCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IEJvb2xl'
    'YW4obW9kZWxEYXRhLmV4Y2x1ZGVkKSA/ICLQo9C20LUg0LjRgdC60LvRjtGH0LXQvdC+IiA6ICLQmNGB0LrQu9GO0YfQuNGC0Ywi'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKG1vZGVsRGF0'
    'YS5leGNsdWRlZCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjog'
    'IXJvb3QuYnVzeSAmJiAhQm9vbGVhbihtb2RlbERhdGEuZXhjbHVkZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImFwcF9hZGQiLCB0YXJnZXQ6IFN0cmluZyht'
    'b2RlbERhdGEuZXhlIHx8IG1vZGVsRGF0YS5uYW1lIHx8ICIiKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBD'
    'LlNjcm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8g'
    'U2l0ZXMvSVAKICAgICAgICAgICAgICAgICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBzcGFjaW5nOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogODIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6'
    'IDE2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEwCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBkaXJl'
    'Y3RUYXJnZXQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyVGV4dDogImV4YW1wbGUuY29tLCAyMDMuMC4x'
    'MTMuMTAg0LjQu9C4IDIwMy4wLjExMy4wLzI0IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0'
    'QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZDogUmVjdGFuZ2xl'
    'IHsgcmFkaXVzOiAxMDsgY29sb3I6ICIjZjhmYWZjIjsgYm9yZGVyLmNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjY2VwdGVkOiBpZiAodGV4dC50cmltKCkubGVuZ3RoKSByb290LmFjdGlvbih7'
    'YWN0aW9uOiAiZGlyZWN0X2FkZCIsIHRhcmdldDogdGV4dC50cmltKCl9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQlNC+0LHQsNCy0LjRgtGMINC40YHQutC70Y7Rh9C10L3QuNC1IgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbWFyeTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiBkaXJlY3RUYXJnZXQudGV4dC50cmltKCkubGVuZ3RoID4g'
    'MAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogImRpcmVjdF9hZGQiLCB0YXJnZXQ6IGRpcmVjdFRh'
    'cmdldC50ZXh0LnRyaW0oKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlyZWN0VGFyZ2V0'
    'LmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5tYXJnaW5zOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRl'
    'eHQ6ICLQlNC+0LzQtdC90YsiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZDsgZm9udC5waXhl'
    'bFNpemU6IDE1IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Bh'
    'Y2luZzogNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LnN0YXRlLmRvbWFp'
    'bnMgfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgdmFyIG1vZGVs'
    'RGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53'
    'aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogOQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBh'
    'bmNob3JzLmZpbGw6IHBhcmVudDsgYW5jaG9ycy5sZWZ0TWFyZ2luOiAxMDsgYW5jaG9ycy5yaWdodE1hcmdpbjogNwogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRy'
    'dWU7IHRleHQ6IFN0cmluZyhtb2RlbERhdGEpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZWxpZGU6IFRleHQuRWxpZGVSaWdodCB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQ'
    'o9C00LDQu9C40YLRjCI7IGRhbmdlcjogdHJ1ZTsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeTsgb25DbGlja2VkOiByb290LmFj'
    'dGlvbih7YWN0aW9uOiAiZGlyZWN0X3JlbW92ZSIsIHRhcmdldDogU3RyaW5nKG1vZGVsRGF0YSl9KSB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMu'
    'U2Nyb2xsQmFyIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdp'
    'bnM6IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIklQINC4INGB0LXR'
    'gtC4IjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkJvbGQ7IGZvbnQucGl4ZWxTaXplOiAxNSB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5zdGF0ZS5uZXR3b3JrcyB8fCBbXQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSZWN0YW5nbGUgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDYKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiA5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93'
    'TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDog'
    'cGFyZW50OyBhbmNob3JzLmxlZnRNYXJnaW46IDEwOyBhbmNob3JzLnJpZ2h0TWFyZ2luOiA3CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3Ry'
    'aW5nKG1vZGVsRGF0YSk7IGNvbG9yOiByb290LnRleHRNYWluOyBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQo9C00LDQu9C40YLR'
    'jCI7IGRhbmdlcjogdHJ1ZTsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeTsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9u'
    'OiAiZGlyZWN0X3JlbW92ZSIsIHRhcmdldDogU3RyaW5nKG1vZGVsRGF0YSl9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMuU2Nyb2xsQmFyIHt9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIFBvcnRzCiAg'
    'ICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzog'
    'MTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDEwNQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQlNC70Y8g0LvQvtC60LDQu9GM0L3Ri9GF'
    'INGB0LXRgNCy0LXRgNC+0LI6INC+0YLQstC10YLRiyDQvdCwINCy0YXQvtC00Y/RidC40LUg0L/QvtC00LrQu9GO0YfQtdC90LjR'
    'jyDQuiDRjdGC0LjQvCDQv9C+0YDRgtCw0Lwg0LjQtNGD0YIg0L3QsNC/0YDRj9C80YPRjiDRh9C10YDQtdC3INGE0LjQt9C40YfQ'
    'tdGB0LrRg9GOINGB0LXRgtGMLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRl'
    'eHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaWQ6IHBvcnRGaWVsZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6ICIyNTU2'
    'NSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnB1dE1ldGhvZEhpbnRzOiBRdC5JbWhEaWdp'
    'dHNPbmx5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZDogUmVjdGFuZ2xlIHsg'
    'cmFkaXVzOiAxMDsgY29sb3I6ICIjZjhmYWZjIjsgYm9yZGVyLmNvbG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJvQm94'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogcHJvdG9Cb3gKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogWyJUQ1AiLCAiVURQIiwgIkJPVEgiXQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDExMAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQlNC+0LHQsNCy0LjRgtGMIgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIHBvcnRGaWVsZC50ZXh0Lmxlbmd0aCA+IDAKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcCA9IE51bWJlcihwb3J0RmllbGQudGV4dCkKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHAgPj0gMSAmJiBwIDw9IDY1NTM1ICYmIHAgPT09IE1hdGguZmxvb3Io'
    'cCkpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuYWN0aW9uKHthY3Rp'
    'b246ICJwb3J0X2FkZCIsIHBvcnQ6IHAsIHByb3RvOiBwcm90b0JveC5jdXJyZW50VGV4dC50b0xvd2VyQ2FzZSgpfSkKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRGaWVsZC5jbGVhcigpCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2lu'
    'czogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBzcGFjaW5nOiA3CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LnN0'
    'YXRlLnNlcnZlcl9wb3J0cyB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFu'
    'Z2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERh'
    'dGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDU0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByYWRpdXM6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZh'
    'ZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50OyBhbmNob3JzLmxlZnRNYXJnaW46IDEyOyBhbmNo'
    'b3JzLnJpZ2h0TWFyZ2luOiA4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDU0OyBoZWlnaHQ6IDMwOyByYWRp'
    'dXM6IDg7IGNvbG9yOiByb290LmFjY2VudFNvZnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQy5MYWJlbCB7IGFuY2hvcnMuY2VudGVySW46IHBhcmVudDsgdGV4dDogU3RyaW5nKG1vZGVsRGF0YS5wcm90byB8fCAiIiku'
    'dG9VcHBlckNhc2UoKTsgY29sb3I6IHJvb3QuYWNjZW50OyBmb250LndlaWdodDogRm9udC5Cb2xkOyBmb250LnBpeGVsU2l6ZTog'
    'MTEgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5nKG1vZGVsRGF0'
    'YS5wb3J0IHx8ICIiKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAxNjsgZm9udC53ZWlnaHQ6IEZvbnQu'
    'RGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCj0LTQsNC70LjRgtGMIjsgZGFuZ2VyOiB0'
    'cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInBvcnRfcmVtb3ZlIiwgcG9ydDogTnVtYmVyKG1vZGVsRGF0YS5w'
    'b3J0KSwgcHJvdG86IFN0cmluZyhtb2RlbERhdGEucHJvdG8pfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5TY3JvbGxCYXIudmVydGljYWw6IEMu'
    'U2Nyb2xsQmFyIHt9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBhbmNob3JzLmNlbnRlcklu'
    'OiBwYXJlbnQ7IHZpc2libGU6IChyb290LnN0YXRlLnNlcnZlcl9wb3J0cyB8fCBbXSkubGVuZ3RoID09PSAwOyB0ZXh0OiAi0J3Q'
    'tdGCINGB0LXRgNCy0LXRgNC90YvRhSDQv9C+0YDRgtC+0LIiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gRGlhZ25vc3RpY3MKICAgICAgICAgICAgICAg'
    'ICAgICBJdGVtIHsKICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMubWFyZ2luczogMjQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KLQtdC60YPRidC10LUg0YHQvtGB0YLQvtGP0L3QuNC1IjsgY29sb3I6'
    'IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAxODsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZCB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgR3JpZExheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5m'
    'aWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1uczogMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5TcGFjaW5nOiAyOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICByb3dTcGFjaW5nOiAxMwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIlZQTiI7'
    'IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0'
    'OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/ICLQktC60LvRjtGH0ZHQvSIgOiAi0JLRi9C60LvRjtGH0LXQvSI7IGNvbG9y'
    'OiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkOyBmb250LndlaWdodDogRm9u'
    'dC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0J/RgNC+0YTQ'
    'uNC70YwiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUucHJvZmlsZSB8fCByb290LnN0YXRlLmxhc3RfcHJvZmlsZSB8fCAi4oCUIik7IGNv'
    'bG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiVFVOIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS50dW4pID8gInhyYXl0dW4g0L/QvtC0'
    '0L3Rj9GCIiA6ICLQndC10YIiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIktpbGwgc3dpdGNoIjsgY29sb3I6IHJvb3Qu'
    'dGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IEJvb2xlYW4ocm9v'
    'dC5zdGF0ZS5raWxsX3N3aXRjaCkgPyAi0JDQutGC0LjQstC10L0iIDogItCS0YvQutC70Y7Rh9C10L0iOyBjb2xvcjogQm9vbGVh'
    'bihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkOyBmb250LndlaWdodDogRm9udC5E'
    'ZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiSVB2NiI7IGNvbG9y'
    'OiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJp'
    'bmcocm9vdC5zdGF0ZS5pcHY2X21vZGUgfHwgInVua25vd24iKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBG'
    'b250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJESVJFQ1Qg'
    '0L/RgNC40LvQvtC20LXQvdC40Y8iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUuZGlyZWN0X2FwcGxpY2F0aW9ucyB8fCAwKTsgY29sb3I6'
    'IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQy5MYWJlbCB7IHRleHQ6ICJESVJFQ1Qg0LTQvtC80LXQvdGLIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLmRpcmVjdF9kb21h'
    'aW5zIHx8IDApOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkRJUkVDVCBJUC/RgdC10YLQuCI7IGNvbG9yOiByb290LnRl'
    'eHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmcocm9vdC5z'
    'dGF0ZS5kaXJlY3RfbmV0d29ya3MgfHwgMCk7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9s'
    'ZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiTWFuYWdlciI7IGNvbG9yOiBy'
    'b290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmco'
    'cm9vdC5zdGF0ZS5tYW5hZ2VyIHx8ICLigJQiKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlC'
    'b2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSXRl'
    'bSB7IExheW91dC5maWxsSGVpZ2h0OiB0cnVlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB0ZXh0OiAi0J7QutC90L4g0L3QsNGB0YLRgNC+0LXQuiDRgNCw0LHQvtGC0LDQtdGCINC+0YLQtNC1'
    '0LvRjNC90L4g0L7RgiBQbGFzbWEuIEtERSDQuNGB0L/QvtC70YzQt9GD0LXRgtGB0Y8g0YLQvtC70YzQutC+INC00LvRjyDQvNCw'
    '0LvQtdC90YzQutC+0LPQviDQstC40LTQttC10YLQsCDQvdCwINGA0LDQsdC+0YfQtdC8INGB0YLQvtC70LUuIgogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5w'
    'aXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAg'
    'ICAgICB9CiAgICAgICAgfQogICAgfQp9Cg=='
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
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"EvgeniusVPNManager/{MANAGER_VERSION}",
            "Accept": "application/vnd.github+json, application/json, text/plain, */*",
        },
    )
    ctx = ssl.create_default_context()
    try:
        r = urllib.request.urlopen(req, timeout=40, context=ctx)
    except Exception as exc:
        fail(f"HTTPS download failed: {exc}")
    with r:
        out = bytearray()
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > max_bytes:
                fail(f"Загрузка превысила лимит {max_bytes} bytes.")
        return bytes(out)

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
    deadline = time.time() + timeout
    while time.time() < deadline:
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

def health_check_v4() -> tuple[bool, str]:
    dns = run(
        ["/usr/bin/getent", "ahostsv4", "example.com"],
        check=False, capture=True, timeout=5
    )
    if dns.returncode != 0 or not (dns.stdout or "").strip():
        return False, "IPv4 DNS resolution через активный VPN не работает."

    cp = run(
        ["/usr/bin/curl", "-4", "--fail", "--silent", "--show-error",
         "--connect-timeout", "5", "--max-time", "12",
         "https://api.ipify.org"],
        check=False, capture=True, timeout=15
    )
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
    old_state = load_state()
    old_config = RUNTIME_CONFIG.read_bytes() if RUNTIME_CONFIG.exists() else None
    was_active = service_active()

    info(f"Разбираю конфиг: {path.name}")
    nodes = load_profile(path)

    # Сначала пробуем настоящий dual-stack. Если удалённый VPS не умеет IPv6,
    # автоматически перестраиваем TUN в IPv4-only fail-closed режиме.
    cfg_dual = build_config(settings, nodes, ipv6_enabled=True)
    validate_candidate(settings, cfg_dual)

    if not was_active:
        install_guard(settings)
    else:
        stop_core()

    failure_reason = "неизвестная ошибка"

    if start_config(settings, cfg_dual):
        info("TUN поднят. Проверяю IPv4 через VLESS...")
        v4_ok, v4_detail = health_check_v4()

        if v4_ok:
            info("IPv4 работает. Проверяю IPv6 egress через тот же VPN...")
            v6_ok, v6_detail = probe_ipv6_via_vpn()

            if v6_ok:
                save_state({
                    "active": path.name,
                    "last_active": path.name,
                    "node": nodes[0]["name"],
                    "server_ip": nodes[0]["server_ip"],
                    "ipv6_mode": "vpn",
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
            cfg_v4 = build_config(settings, nodes, ipv6_enabled=False)
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
    info("Выключаю VPN...")
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
    st = load_state()
    active = service_active()
    return {
        "manager": MANAGER_VERSION,
        "active": active,
        "profile": str(st.get("active") or "") if active else "",
        "last_profile": str(st.get("last_active") or st.get("active") or ""),
        "ipv6_mode": str(st.get("ipv6_mode") or "unknown"),
        "tun": pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists(),
        "kill_switch": nft_exists(),
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
    pathlib.Path("/etc/systemd/system/vpn-xray.service").write_text(SERVICE_TEXT)
    os.chmod("/etc/systemd/system/vpn-xray.service", 0o644)

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
    finally:
        globals()["resolve_server"] = old
    print("self-test OK")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vpn", add_help=False)
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("help")
    sub.add_parser("list")
    pon = sub.add_parser("on"); pon.add_argument("config", nargs="?")
    psw = sub.add_parser("switch"); psw.add_argument("config")
    sub.add_parser("off")
    sub.add_parser("toggle")
    pst = sub.add_parser("status"); pst.add_argument("--ip", action="store_true"); pst.add_argument("--json", action="store_true")
    sub.add_parser("test")
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
    sub.add_parser("manager-rollback")

    args = p.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    ensure_root()
    settings = load_settings()
    ensure_direct_apps_file(settings)

    if args.cmd in {None, "help"}:
        print(f"""VPN Manager {MANAGER_VERSION} — Xray edition

  vpn list
  vpn on [CONFIG]
  vpn switch CONFIG
  vpn off
  vpn toggle
  vpn status [--ip|--json]
  vpn test
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
