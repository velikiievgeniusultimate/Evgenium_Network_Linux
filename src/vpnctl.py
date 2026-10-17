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

MANAGER_VERSION = "0.3.1"

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
DNS_PRIMARY_IP = "1.1.1.1"
DNS_UPSTREAM_SERVERS = ("1.1.1.1", "8.8.8.8")

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
    'CmRlZiBydW5fdnBuKGFyZ3M6IGxpc3Rbc3RyXSwgdGltZW91dDogaW50ID0gNzUwLCBzZWNyZXRfaW5wdXQ6IHN0ciB8IE5v'
    'bmUgPSBOb25lKSAtPiBzdHI6CiAgICBzdGRpbl9vcHRpb25zID0geyJpbnB1dCI6IHNlY3JldF9pbnB1dH0gaWYgc2VjcmV0'
    'X2lucHV0IGlzIG5vdCBOb25lIGVsc2UgeyJzdGRpbiI6IHN1YnByb2Nlc3MuREVWTlVMTH0KICAgIGNwID0gc3VicHJvY2Vz'
    'cy5ydW4oCiAgICAgICAgW1ZQTiwgKmFyZ3NdLAogICAgICAgIHRleHQ9VHJ1ZSwKICAgICAgICBzdGRvdXQ9c3VicHJvY2Vz'
    'cy5QSVBFLAogICAgICAgIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsCiAgICAgICAgdGltZW91dD10aW1lb3V0LAogICAgICAg'
    'ICoqc3RkaW5fb3B0aW9ucywKICAgICAgICBjaGVjaz1GYWxzZSwKICAgICkKICAgIGlmIGNwLnJldHVybmNvZGUgIT0gMDoK'
    'ICAgICAgICBkZXRhaWwgPSAoY3Auc3RkZXJyIG9yIGNwLnN0ZG91dCBvciBmImV4aXQge2NwLnJldHVybmNvZGV9Iikuc3Ry'
    'aXAoKQogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihkZXRhaWwpCiAgICByZXR1cm4gKGNwLnN0ZG91dCBvciAiIikuc3Ry'
    'aXAoKQoKCmRlZiBydW5fdnBuX2pzb24oYXJnczogbGlzdFtzdHJdKSAtPiBkaWN0OgogICAgcmF3ID0gcnVuX3Zwbihhcmdz'
    'LCB0aW1lb3V0PTEwKQogICAgdHJ5OgogICAgICAgIGRhdGEgPSBqc29uLmxvYWRzKHJhdykKICAgIGV4Y2VwdCBqc29uLkpT'
    'T05EZWNvZGVFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGYiVlBOIE1hbmFnZXIg0LLQtdGA0L3R'
    'g9C7INC90LXQutC+0YDRgNC10LrRgtC90YvQuSBKU09OOiB7ZXhjfSIpIGZyb20gZXhjCiAgICBpZiBub3QgaXNpbnN0YW5j'
    'ZShkYXRhLCBkaWN0KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoIlZQTiBNYW5hZ2VyINCy0LXRgNC90YPQuyDQvdC1'
    '0L7QttC40LTQsNC90L3Ri9C5INC+0YLQstC10YIuIikKICAgIHJldHVybiBkYXRhCgoKZGVmIGVuY29kZV91aV9wYXlsb2Fk'
    'KHBheWxvYWQ6IGRpY3QpIC0+IHN0cjoKICAgIHJhdyA9IGpzb24uZHVtcHMocGF5bG9hZCwgZW5zdXJlX2FzY2lpPUZhbHNl'
    'LCBzZXBhcmF0b3JzPSgiLCIsICI6IikpCiAgICBxdW90ZWQgPSB1cmxsaWIucGFyc2UucXVvdGUocmF3LCBzYWZlPSIiKQog'
    'ICAgcmV0dXJuIGJhc2U2NC5iNjRlbmNvZGUocXVvdGVkLmVuY29kZSgiYXNjaWkiKSkuZGVjb2RlKCJhc2NpaSIpCgoKY2xh'
    'c3MgQXBpU2VydmVyKGh0dHAuc2VydmVyLlRocmVhZGluZ0hUVFBTZXJ2ZXIpOgogICAgZGFlbW9uX3RocmVhZHMgPSBUcnVl'
    'CiAgICBhbGxvd19yZXVzZV9hZGRyZXNzID0gRmFsc2UKCiAgICBkZWYgX19pbml0X18oc2VsZiwgYWRkcmVzcywgaGFuZGxl'
    'ciwgdG9rZW46IHN0cik6CiAgICAgICAgc3VwZXIoKS5fX2luaXRfXyhhZGRyZXNzLCBoYW5kbGVyKQogICAgICAgIHNlbGYu'
    'dG9rZW4gPSB0b2tlbgoKCmNsYXNzIEhhbmRsZXIoaHR0cC5zZXJ2ZXIuQmFzZUhUVFBSZXF1ZXN0SGFuZGxlcik6CiAgICBz'
    'ZXJ2ZXI6IEFwaVNlcnZlcgoKICAgIGRlZiBsb2dfbWVzc2FnZShzZWxmLCBfZm9ybWF0OiBzdHIsICpfYXJncykgLT4gTm9u'
    'ZToKICAgICAgICByZXR1cm4KCiAgICBkZWYgX2hlYWRlcnMoc2VsZiwgc3RhdHVzOiBpbnQgPSAyMDAsIGNvbnRlbnRfdHlw'
    'ZTogc3RyID0gImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgiKSAtPiBOb25lOgogICAgICAgIHNlbGYuc2VuZF9y'
    'ZXNwb25zZShzdGF0dXMpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC1UeXBlIiwgY29udGVudF90eXBlKQog'
    'ICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNhY2hlLUNvbnRyb2wiLCAibm8tc3RvcmUiKQogICAgICAgIHNlbGYuc2VuZF9o'
    'ZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbiIsICIqIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nl'
    'c3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzIiwgIkNvbnRlbnQtVHlwZSwgWC1Fdmdlbml1bS1Ub2tlbiIpCiAgICAgICAgc2Vs'
    'Zi5zZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcyIsICJHRVQsIFBPU1QsIE9QVElPTlMiKQogICAg'
    'ICAgIHNlbGYuZW5kX2hlYWRlcnMoKQoKICAgIGRlZiBfanNvbihzZWxmLCBwYXlsb2FkOiBkaWN0LCBzdGF0dXM6IGludCA9'
    'IDIwMCkgLT4gTm9uZToKICAgICAgICBkYXRhID0ganNvbi5kdW1wcyhwYXlsb2FkLCBlbnN1cmVfYXNjaWk9RmFsc2UsIHNl'
    'cGFyYXRvcnM9KCIsIiwgIjoiKSkuZW5jb2RlKCJ1dGYtOCIpCiAgICAgICAgc2VsZi5zZW5kX3Jlc3BvbnNlKHN0YXR1cykK'
    'ICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYt'
    'OCIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQ29udGVudC1MZW5ndGgiLCBzdHIobGVuKGRhdGEpKSkKICAgICAgICBz'
    'ZWxmLnNlbmRfaGVhZGVyKCJDYWNoZS1Db250cm9sIiwgIm5vLXN0b3JlIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJB'
    'Y2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4iLCAiKiIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRlcigiQWNjZXNzLUNvbnRy'
    'b2wtQWxsb3ctSGVhZGVycyIsICJDb250ZW50LVR5cGUsIFgtRXZnZW5pdW0tVG9rZW4iKQogICAgICAgIHNlbGYuc2VuZF9o'
    'ZWFkZXIoIkFjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMiLCAiR0VULCBQT1NULCBPUFRJT05TIikKICAgICAgICB0cnk6'
    'CiAgICAgICAgICAgIHNlbGYuZW5kX2hlYWRlcnMoKQogICAgICAgICAgICBzZWxmLndmaWxlLndyaXRlKGRhdGEpCiAgICAg'
    'ICAgZXhjZXB0IChCcm9rZW5QaXBlRXJyb3IsIENvbm5lY3Rpb25SZXNldEVycm9yKToKICAgICAgICAgICAgIyBUaGUgVUkg'
    'bWF5IGhhdmUgY2xvc2VkIG9yIGNhbmNlbGVkIGEgcG9sbC4gRG8gbm90IGVtaXQgYSBzZWNvbmQgcmVzcG9uc2UuCiAgICAg'
    'ICAgICAgIHJldHVybgoKICAgIGRlZiBfYXV0aG9yaXplZChzZWxmKSAtPiBib29sOgogICAgICAgIHJldHVybiBzZWNyZXRz'
    'LmNvbXBhcmVfZGlnZXN0KAogICAgICAgICAgICBzZWxmLmhlYWRlcnMuZ2V0KCJYLUV2Z2VuaXVtLVRva2VuIiwgIiIpLAog'
    'ICAgICAgICAgICBzZWxmLnNlcnZlci50b2tlbiwKICAgICAgICApCgogICAgZGVmIF9yZXF1aXJlX2F1dGgoc2VsZikgLT4g'
    'Ym9vbDoKICAgICAgICBpZiBzZWxmLl9hdXRob3JpemVkKCk6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgc2Vs'
    'Zi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6ICJ1bmF1dGhvcml6ZWQifSwgNDAzKQogICAgICAgIHJldHVybiBGYWxz'
    'ZQoKICAgIGRlZiBfcmVhZF9qc29uKHNlbGYpIC0+IGRpY3Q6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBsZW5ndGggPSBp'
    'bnQoc2VsZi5oZWFkZXJzLmdldCgiQ29udGVudC1MZW5ndGgiLCAiMCIpKQogICAgICAgIGV4Y2VwdCBWYWx1ZUVycm9yIGFz'
    'IGV4YzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0LkgQ29udGVudC1M'
    'ZW5ndGguIikgZnJvbSBleGMKICAgICAgICBpZiBsZW5ndGggPCAwIG9yIGxlbmd0aCA+IE1BWF9CT0RZOgogICAgICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoItCh0LvQuNGI0LrQvtC8INCx0L7Qu9GM0YjQvtC5INC30LDQv9GA0L7RgS4iKQogICAg'
    'ICAgIHJhdyA9IHNlbGYucmZpbGUucmVhZChsZW5ndGgpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBwYXlsb2FkID0ganNv'
    'bi5sb2FkcyhyYXcuZGVjb2RlKCJ1dGYtOCIpIGlmIHJhdyBlbHNlICJ7fSIpCiAgICAgICAgZXhjZXB0IChVbmljb2RlRGVj'
    'b2RlRXJyb3IsIGpzb24uSlNPTkRlY29kZUVycm9yKSBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihm'
    'ItCd0LXQutC+0YDRgNC10LrRgtC90YvQuSBKU09OOiB7ZXhjfSIpIGZyb20gZXhjCiAgICAgICAgaWYgbm90IGlzaW5zdGFu'
    'Y2UocGF5bG9hZCwgZGljdCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J7QttC40LTQsNC70YHRjyBKU09O'
    'IG9iamVjdC4iKQogICAgICAgIHJldHVybiBwYXlsb2FkCgogICAgZGVmIGRvX09QVElPTlMoc2VsZikgLT4gTm9uZToKICAg'
    'ICAgICBzZWxmLl9oZWFkZXJzKDIwNCkKCiAgICBkZWYgZG9fR0VUKHNlbGYpIC0+IE5vbmU6CiAgICAgICAgaWYgbm90IHNl'
    'bGYuX3JlcXVpcmVfYXV0aCgpOgogICAgICAgICAgICByZXR1cm4KICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIHNlbGYu'
    'cGF0aCA9PSAiL2FwaS9zdGF0ZSI6CiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAic3RhdGUiOiBy'
    'dW5fdnBuX2pzb24oWyJ1aSIsICJzdGF0ZSJdKX0pCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgaWYgc2Vs'
    'Zi5wYXRoID09ICIvYXBpL3J1bm5pbmciOgogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgInJ1bm5p'
    'bmciOiBydW5fdnBuX2pzb24oWyJ1aSIsICJydW5uaW5nIl0pfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAg'
    'ICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvaGVhbHRoIjoKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IFRydWUs'
    'ICJhcHAiOiBBUFBfTkFNRX0pCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjog'
    'RmFsc2UsICJlcnJvciI6ICJub3QgZm91bmQifSwgNDA0KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAg'
    'ICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxzZSwgImVycm9yIjogc3RyKGV4Yyl9LCA1MDApCgogICAgZGVmIGRvX1BP'
    'U1Qoc2VsZikgLT4gTm9uZToKICAgICAgICBpZiBub3Qgc2VsZi5fcmVxdWlyZV9hdXRoKCk6CiAgICAgICAgICAgIHJldHVy'
    'bgogICAgICAgIHRyeToKICAgICAgICAgICAgcGF5bG9hZCA9IHNlbGYuX3JlYWRfanNvbigpCiAgICAgICAgICAgIGlmIHNl'
    'bGYucGF0aCA9PSAiL2FwaS9hY3Rpb24iOgogICAgICAgICAgICAgICAgdG9rZW4gPSBlbmNvZGVfdWlfcGF5bG9hZChwYXls'
    'b2FkKQogICAgICAgICAgICAgICAgb3V0cHV0ID0gcnVuX3ZwbihbInVpIiwgImFjdGlvbiIsICItIl0sIHNlY3JldF9pbnB1'
    'dD10b2tlbikKICAgICAgICAgICAgICAgIHJlcGx5ID0geyJvayI6IFRydWUsICJvdXRwdXQiOiBvdXRwdXR9CiAgICAgICAg'
    'ICAgICAgICBpZiBwYXlsb2FkLmdldCgiYWN0aW9uIikgPT0gImV4cGVyaW1lbnRhbF90b2tlbi1zYXZlIjoKICAgICAgICAg'
    'ICAgICAgICAgICByZXBseVsic3RhdGUiXSA9IHJ1bl92cG5fanNvbihbInVpIiwgInN0YXRlIl0pCiAgICAgICAgICAgICAg'
    'ICBzZWxmLl9qc29uKHJlcGx5KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIHNlbGYucGF0aCA9PSAi'
    'L2FwaS90b2dnbGUiOgogICAgICAgICAgICAgICAgb3V0cHV0ID0gcnVuX3ZwbihbInRvZ2dsZSJdKQogICAgICAgICAgICAg'
    'ICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgIm91dHB1dCI6IG91dHB1dCwgInN0YXRlIjogcnVuX3Zwbl9qc29uKFsidWki'
    'LCAic3RhdGUiXSl9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNl'
    'LCAiZXJyb3IiOiAibm90IGZvdW5kIn0sIDQwNCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAg'
    'ICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6IHN0cihleGMpfSwgNTAwKQoKCmRlZiBzdGF0ZV9sb2dfcGF0'
    'aCgpIC0+IHBhdGhsaWIuUGF0aDoKICAgIHJvb3QgPSBwYXRobGliLlBhdGgob3MuZW52aXJvbi5nZXQoIlhER19TVEFURV9I'
    'T01FIiwgcGF0aGxpYi5QYXRoLmhvbWUoKSAvICIubG9jYWwiIC8gInN0YXRlIikpCiAgICBwYXRoID0gcm9vdCAvICJldmdl'
    'bml1bS1uZXR3b3JrIiAvICJndWkubG9nIgogICAgcGF0aC5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVlLCBleGlzdF9vaz1U'
    'cnVlKQogICAgcmV0dXJuIHBhdGgKCgpkZWYgbGF1bmNoX2RldGFjaGVkKCkgLT4gaW50OgogICAgaWYgbm90IFFNTF9GSUxF'
    'LmlzX2ZpbGUoKToKICAgICAgICBwcmludChmItCd0LUg0L3QsNC50LTQtdC9INC40L3RgtC10YDRhNC10LnRgToge1FNTF9G'
    'SUxFfSIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQogICAgaWYgbm90IGZpbmRfcW1sX3J1bnRpbWUoKToK'
    'ICAgICAgICBwcmludCgi0J3QtSDQvdCw0LnQtNC10L0gUXQgNiBRTUwgcnVudGltZSAoQXJjaDogcXQ2LWRlY2xhcmF0aXZl'
    'OyBGZWRvcmE6IHF0Ni1xdGRlY2xhcmF0aXZlLWRldmVsKS4iLCBmaWxlPXN5cy5zdGRlcnIpCiAgICAgICAgcmV0dXJuIDEK'
    'ICAgIGxvZ19wYXRoID0gc3RhdGVfbG9nX3BhdGgoKQogICAgd2l0aCBsb2dfcGF0aC5vcGVuKCJhYiIsIGJ1ZmZlcmluZz0w'
    'KSBhcyBsb2c6CiAgICAgICAgc3VicHJvY2Vzcy5Qb3BlbigKICAgICAgICAgICAgW3N5cy5leGVjdXRhYmxlLCBzdHIocGF0'
    'aGxpYi5QYXRoKF9fZmlsZV9fKS5yZXNvbHZlKCkpXSwKICAgICAgICAgICAgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLAog'
    'ICAgICAgICAgICBzdGRvdXQ9bG9nLAogICAgICAgICAgICBzdGRlcnI9bG9nLAogICAgICAgICAgICBzdGFydF9uZXdfc2Vz'
    'c2lvbj1UcnVlLAogICAgICAgICAgICBjbG9zZV9mZHM9VHJ1ZSwKICAgICAgICApCiAgICByZXR1cm4gMAoKCmRlZiBydW5f'
    'Z3VpKCkgLT4gaW50OgogICAgcW1sID0gZmluZF9xbWxfcnVudGltZSgpCiAgICBpZiBub3QgcW1sOgogICAgICAgIHByaW50'
    'KCLQndC1INC90LDQudC00LXQvSBRdCA2IFFNTCBydW50aW1lIChBcmNoOiBxdDYtZGVjbGFyYXRpdmU7IEZlZG9yYTogcXQ2'
    'LXF0ZGVjbGFyYXRpdmUtZGV2ZWwpLiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQogICAgaWYgbm90IFFN'
    'TF9GSUxFLmlzX2ZpbGUoKToKICAgICAgICBwcmludChmItCd0LUg0L3QsNC50LTQtdC9INC40L3RgtC10YDRhNC10LnRgTog'
    'e1FNTF9GSUxFfSIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQoKICAgIHRva2VuID0gc2VjcmV0cy50b2tl'
    'bl91cmxzYWZlKDMyKQogICAgc2VydmVyID0gQXBpU2VydmVyKCgiMTI3LjAuMC4xIiwgMCksIEhhbmRsZXIsIHRva2VuKQog'
    'ICAgcG9ydCA9IGludChzZXJ2ZXIuc2VydmVyX2FkZHJlc3NbMV0pCiAgICB0aHJlYWQgPSB0aHJlYWRpbmcuVGhyZWFkKHRh'
    'cmdldD1zZXJ2ZXIuc2VydmVfZm9yZXZlciwgbmFtZT0iZXZnZW5pdW0tZ3VpLWFwaSIsIGRhZW1vbj1UcnVlKQogICAgdGhy'
    'ZWFkLnN0YXJ0KCkKCiAgICBlbnYgPSBvcy5lbnZpcm9uLmNvcHkoKQogICAgZW52LnNldGRlZmF1bHQoIlFUX1FVSUNLX0NP'
    'TlRST0xTX1NUWUxFIiwgIkJhc2ljIikKICAgIGVudi5zZXRkZWZhdWx0KCJRTUxfRElTQUJMRV9ESVNLX0NBQ0hFIiwgIjAi'
    'KQoKICAgIHRyeToKICAgICAgICBjcCA9IHN1YnByb2Nlc3MucnVuKAogICAgICAgICAgICBbcW1sLCBzdHIoUU1MX0ZJTEUp'
    'LCAiLS0iLCBzdHIocG9ydCksIHRva2VuXSwKICAgICAgICAgICAgZW52PWVudiwKICAgICAgICAgICAgY2hlY2s9RmFsc2Us'
    'CiAgICAgICAgKQogICAgICAgIHJldHVybiBpbnQoY3AucmV0dXJuY29kZSkKICAgIGZpbmFsbHk6CiAgICAgICAgc2VydmVy'
    'LnNodXRkb3duKCkKICAgICAgICBzZXJ2ZXIuc2VydmVyX2Nsb3NlKCkKICAgICAgICB0aHJlYWQuam9pbih0aW1lb3V0PTIp'
    'CgoKZGVmIHNlbGZfdGVzdCgpIC0+IGludDoKICAgIHNhbXBsZSA9IHsiYWN0aW9uIjogImFwcF9hZGQiLCAidGFyZ2V0Ijog'
    'Ii9vcHQvZXhhbXBsZS9iaW4vYXBwIn0KICAgIHRva2VuID0gZW5jb2RlX3VpX3BheWxvYWQoc2FtcGxlKQogICAgZGVjb2Rl'
    'ZCA9IHVybGxpYi5wYXJzZS51bnF1b3RlKGJhc2U2NC5iNjRkZWNvZGUodG9rZW4pLmRlY29kZSgiYXNjaWkiKSkKICAgIGFz'
    'c2VydCBqc29uLmxvYWRzKGRlY29kZWQpID09IHNhbXBsZQogICAgYXNzZXJ0IE1BWF9CT0RZIDw9IDEwMjQgKiAxMDI0CiAg'
    'ICBxbWwgPSBIRVJFIC8gImV2Z2VuaXVtX2d1aS5xbWwiCiAgICBpZiBxbWwuZXhpc3RzKCk6CiAgICAgICAgdGV4dCA9IHFt'
    'bC5yZWFkX3RleHQoZW5jb2Rpbmc9InV0Zi04IikKICAgICAgICBhc3NlcnQgIkV2Z2VuaXVtIE5ldHdvcmsiIGluIHRleHQK'
    'ICAgICAgICBhc3NlcnQgIi9hcGkvcnVubmluZyIgaW4gdGV4dAogICAgICAgIGFzc2VydCAiL2FwaS9hY3Rpb24iIGluIHRl'
    'eHQKICAgIHByaW50KCJldmdlbml1bS1ndWkgc2VsZi10ZXN0IE9LIikKICAgIHJldHVybiAwCgoKZGVmIG1haW4oKSAtPiBp'
    'bnQ6CiAgICBpZiAiLS1zZWxmLXRlc3QiIGluIHN5cy5hcmd2OgogICAgICAgIHJldHVybiBzZWxmX3Rlc3QoKQogICAgaWYg'
    'Ii0tZGV0YWNoIiBpbiBzeXMuYXJndjoKICAgICAgICByZXR1cm4gbGF1bmNoX2RldGFjaGVkKCkKICAgIHJldHVybiBydW5f'
    'Z3VpKCkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgcmFpc2UgU3lzdGVtRXhpdChtYWluKCkpCg=='
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
    'fSkKICAgIHByb3BlcnR5IHZhciBydW5uaW5nQXBwczogW10KICAgIHByb3BlcnR5IGJvb2wgdG9rZW5FZGl0aW5nOiBmYWxz'
    'ZQogICAgcmVhZG9ubHkgcHJvcGVydHkgYm9vbCB0b2tlblNhdmVkOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVs'
    'IHx8IHt9KS5oYXNfdG9rZW4pCiAgICByZWFkb25seSBwcm9wZXJ0eSBib29sIHRva2VuTG9ja2VkOiB0b2tlblNhdmVkICYm'
    'ICF0b2tlbkVkaXRpbmcKICAgIHJlYWRvbmx5IHByb3BlcnR5IHZhciBleHBlcmltZW50OiByb290LnN0YXRlLmV4cGVyaW1l'
    'bnRhbCB8fCAoe30pCgogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIGFyZ3M6IFF0LmFwcGxpY2F0aW9uLmFyZ3VtZW50cwog'
    'ICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVRva2VuOiBhcmdzLmxlbmd0aCA+PSAyID8gU3RyaW5nKGFyZ3NbYXJn'
    'cy5sZW5ndGggLSAxXSkgOiAiIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVBvcnQ6IGFyZ3MubGVuZ3RoID49'
    'IDMgPyBTdHJpbmcoYXJnc1thcmdzLmxlbmd0aCAtIDJdKSA6ICIwIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFw'
    'aUJhc2U6ICJodHRwOi8vMTI3LjAuMC4xOiIgKyBhcGlQb3J0CgogICAgcHJvcGVydHkgYm9vbCBzdGF0ZVBlbmRpbmc6IGZh'
    'bHNlCiAgICBwcm9wZXJ0eSBib29sIHJ1bm5pbmdQZW5kaW5nOiBmYWxzZQoKICAgIGZ1bmN0aW9uIGFwaShtZXRob2QsIHBh'
    'dGgsIGJvZHksIGNhbGxiYWNrLCBvcGVyYXRpb24pIHsKICAgICAgICBjb25zdCB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3Qo'
    'KQogICAgICAgIGxldCBmaW5pc2hlZCA9IGZhbHNlCiAgICAgICAgY29uc3QgdGltZXIgPSByZXF1ZXN0VGltZXIuY3JlYXRl'
    'T2JqZWN0KHJvb3QpCiAgICAgICAgZnVuY3Rpb24gZmluaXNoKGVycm9yLCBwYXlsb2FkKSB7CiAgICAgICAgICAgIGlmIChm'
    'aW5pc2hlZCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBmaW5pc2hlZCA9IHRydWUKICAgICAgICAgICAg'
    'dGltZXIuc3RvcCgpCiAgICAgICAgICAgIHRpbWVyLmRlc3Ryb3koKQogICAgICAgICAgICBpZiAocGF0aCA9PT0gIi9hcGkv'
    'c3RhdGUiKSByb290LnN0YXRlUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChwYXRoID09PSAiL2FwaS9ydW5uaW5n'
    'Iikgcm9vdC5ydW5uaW5nUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChvcGVyYXRpb24pIHsKICAgICAgICAgICAg'
    'ICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAgICAgICByb290LmVycm9yVGV4dCA9IGVycm9yIHx8ICIiCiAgICAg'
    'ICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICByb290LnBvbGxFcnJvclRleHQgPSBlcnJvciB8fCAiIgogICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgIGlmICghZXJyb3IgJiYgY2FsbGJhY2spIGNhbGxiYWNrKHBheWxvYWQpCiAgICAgICAgfQog'
    'ICAgICAgIHRpbWVyLmludGVydmFsID0gb3BlcmF0aW9uID8gNzgwMDAwIDogMTIwMDAKICAgICAgICB0aW1lci50cmlnZ2Vy'
    'ZWQuY29ubmVjdChmdW5jdGlvbigpIHsKICAgICAgICAgICAgZmluaXNoKG9wZXJhdGlvbiA/ICLQntGC0LLQtdGCINC+0L/Q'
    'tdGA0LDRhtC40Lgg0L3QtSDQv9C+0LvRg9GH0LXQvS4g0J/RgNC+0LLQtdGA0YwgdnBuIHN0YXR1cyDQv9C10YDQtdC0INC/'
    '0L7QstGC0L7RgNC90YvQvCDQv9C10YDQtdC60LvRjtGH0LXQvdC40LXQvC4iIDogItCe0L/RgNC+0YEg0YHQvtGB0YLQvtGP'
    '0L3QuNGPINC90LUg0LfQsNCy0LXRgNGI0LjQu9GB0Y8iLCBudWxsKQogICAgICAgICAgICB4aHIuYWJvcnQoKQogICAgICAg'
    'IH0pCiAgICAgICAgeGhyLm9wZW4obWV0aG9kLCBhcGlCYXNlICsgcGF0aCwgdHJ1ZSkKICAgICAgICB4aHIuc2V0UmVxdWVz'
    'dEhlYWRlcigiWC1Fdmdlbml1bS1Ub2tlbiIsIGFwaVRva2VuKQogICAgICAgIGlmIChib2R5ICE9PSBudWxsKQogICAgICAg'
    'ICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcigiQ29udGVudC1UeXBlIiwgImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRm'
    'LTgiKQogICAgICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHsKICAgICAgICAgICAgaWYgKHhoci5y'
    'ZWFkeVN0YXRlICE9PSBYTUxIdHRwUmVxdWVzdC5ET05FIHx8IGZpbmlzaGVkKQogICAgICAgICAgICAgICAgcmV0dXJuCiAg'
    'ICAgICAgICAgIGxldCBwYXlsb2FkID0gbnVsbAogICAgICAgICAgICB0cnkgeyBwYXlsb2FkID0gSlNPTi5wYXJzZShTdHJp'
    'bmcoeGhyLnJlc3BvbnNlVGV4dCB8fCAie30iKSkgfQogICAgICAgICAgICBjYXRjaCAoZSkgeyBmaW5pc2goItCd0LUg0YPQ'
    'tNCw0LvQvtGB0Ywg0YDQsNC30L7QsdGA0LDRgtGMINC+0YLQstC10YIg0LvQvtC60LDQu9GM0L3QvtCz0L4gQVBJIiwgbnVs'
    'bCk7IHJldHVybiB9CiAgICAgICAgICAgIGlmICh4aHIuc3RhdHVzIDwgMjAwIHx8IHhoci5zdGF0dXMgPj0gMzAwIHx8ICFw'
    'YXlsb2FkLm9rKSB7CiAgICAgICAgICAgICAgICBmaW5pc2goU3RyaW5nKHBheWxvYWQuZXJyb3IgfHwgKCJIVFRQICIgKyB4'
    'aHIuc3RhdHVzKSksIG51bGwpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgfQogICAgICAgICAgICBmaW5p'
    'c2gobnVsbCwgcGF5bG9hZCkKICAgICAgICB9CiAgICAgICAgdGltZXIuc3RhcnQoKQogICAgICAgIHhoci5zZW5kKGJvZHkg'
    'PT09IG51bGwgPyBudWxsIDogSlNPTi5zdHJpbmdpZnkoYm9keSkpCiAgICB9CgogICAgQ29tcG9uZW50IHsKICAgICAgICBp'
    'ZDogcmVxdWVzdFRpbWVyCiAgICAgICAgVGltZXIgeyByZXBlYXQ6IGZhbHNlIH0KICAgIH0KCiAgICBmdW5jdGlvbiByZWZy'
    'ZXNoU3RhdGUoKSB7CiAgICAgICAgaWYgKHN0YXRlUGVuZGluZykgcmV0dXJuCiAgICAgICAgc3RhdGVQZW5kaW5nID0gdHJ1'
    'ZQogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvc3RhdGUiLCBudWxsLCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAg'
    'IHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9KQogICAgfQoKICAgIGZ1bmN0aW9uIHJlZnJl'
    'c2hSdW5uaW5nKCkgewogICAgICAgIGlmIChydW5uaW5nUGVuZGluZykgcmV0dXJuCiAgICAgICAgcnVubmluZ1BlbmRpbmcg'
    'PSB0cnVlCiAgICAgICAgYXBpKCJHRVQiLCAiL2FwaS9ydW5uaW5nIiwgbnVsbCwgZnVuY3Rpb24ocGF5bG9hZCkgewogICAg'
    'ICAgICAgICByb290LnJ1bm5pbmdBcHBzID0gKHBheWxvYWQucnVubmluZyAmJiBwYXlsb2FkLnJ1bm5pbmcuYXBwbGljYXRp'
    'b25zKSB8fCBbXQogICAgICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gYWN0aW9uKHBheWxvYWQsIG9uU3VjY2Vzcykgewog'
    'ICAgICAgIGlmIChidXN5IHx8IEJvb2xlYW4oc3RhdGUuY29ubmVjdGluZykpCiAgICAgICAgICAgIHJldHVybgogICAgICAg'
    'IGJ1c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkvYWN0aW9uIiwgcGF5bG9hZCwgZnVuY3Rpb24oX3JlcGx5'
    'KSB7CiAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAgIGlmIChfcmVwbHkuc3RhdGUpIHJvb3Quc3Rh'
    'dGUgPSBfcmVwbHkuc3RhdGUKICAgICAgICAgICAgaWYgKG9uU3VjY2Vzcykgb25TdWNjZXNzKCkKICAgICAgICAgICAgcm9v'
    'dC5yZWZyZXNoU3RhdGUoKQogICAgICAgICAgICByb290LnJlZnJlc2hSdW5uaW5nKCkKICAgICAgICB9LCB0cnVlKQogICAg'
    'fQoKICAgIGZ1bmN0aW9uIHRvZ2dsZVZwbigpIHsKICAgICAgICBpZiAoYnVzeSB8fCBCb29sZWFuKHN0YXRlLmNvbm5lY3Rp'
    'bmcpKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBidXN5ID0gdHJ1ZQogICAgICAgIGFwaSgiUE9TVCIsICIvYXBpL3Rv'
    'Z2dsZSIsIHt9LCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAg'
    'IHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9LCB0cnVlKQogICAgfQoKICAgIGZ1bmN0aW9u'
    'IGZpbHRlcmVkUnVubmluZygpIHsKICAgICAgICBjb25zdCBuZWVkbGUgPSBhcHBTZWFyY2gudGV4dC50cmltKCkudG9Mb3dl'
    'ckNhc2UoKQogICAgICAgIGlmICghbmVlZGxlLmxlbmd0aCkKICAgICAgICAgICAgcmV0dXJuIHJ1bm5pbmdBcHBzCiAgICAg'
    'ICAgcmV0dXJuIHJ1bm5pbmdBcHBzLmZpbHRlcihmdW5jdGlvbihhcHApIHsKICAgICAgICAgICAgcmV0dXJuIFN0cmluZyhh'
    'cHAubmFtZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVkbGUpCiAgICAgICAgICAgICAgICB8fCBTdHJpbmco'
    'YXBwLmV4ZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVkbGUpCiAgICAgICAgfSkKICAgIH0KCiAgICBDb21w'
    'b25lbnQub25Db21wbGV0ZWQ6IHsKICAgICAgICByZWZyZXNoU3RhdGUoKQogICAgICAgIHJlZnJlc2hSdW5uaW5nKCkKICAg'
    'IH0KCiAgICBUaW1lciB7CiAgICAgICAgaW50ZXJ2YWw6IDI1MDAKICAgICAgICByZXBlYXQ6IHRydWUKICAgICAgICBydW5u'
    'aW5nOiB0cnVlCiAgICAgICAgb25UcmlnZ2VyZWQ6IHJvb3QucmVmcmVzaFN0YXRlKCkKICAgIH0KCiAgICBjb21wb25lbnQg'
    'RmxhdEJ1dHRvbjogUmVjdGFuZ2xlIHsKICAgICAgICBpZDogZmxhdEJ1dHRvbgogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5'
    'IHN0cmluZyBsYWJlbAogICAgICAgIHByb3BlcnR5IGJvb2wgcHJpbWFyeTogZmFsc2UKICAgICAgICBwcm9wZXJ0eSBib29s'
    'IGRhbmdlcjogZmFsc2UKICAgICAgICBwcm9wZXJ0eSBib29sIGVuYWJsZWRCdXR0b246IHRydWUKICAgICAgICBzaWduYWwg'
    'Y2xpY2tlZCgpCiAgICAgICAgaW1wbGljaXRIZWlnaHQ6IDM4CiAgICAgICAgaW1wbGljaXRXaWR0aDogTWF0aC5tYXgoOTIs'
    'IGJ1dHRvblRleHQuaW1wbGljaXRXaWR0aCArIDI4KQogICAgICAgIHJhZGl1czogMTAKICAgICAgICBjb2xvcjogIWVuYWJs'
    'ZWRCdXR0b24gPyAiI2VlZjBmMyIKICAgICAgICAgICAgICA6IGRhbmdlciA/IChidXR0b25Nb3VzZS5jb250YWluc01vdXNl'
    'ID8gIiNmZWUyZTIiIDogIiNmZWYyZjIiKQogICAgICAgICAgICAgIDogcHJpbWFyeSA/IChidXR0b25Nb3VzZS5jb250YWlu'
    'c01vdXNlID8gIiMyMDk5ZGMiIDogcm9vdC5hY2NlbnQpCiAgICAgICAgICAgICAgOiAoYnV0dG9uTW91c2UuY29udGFpbnNN'
    'b3VzZSA/ICIjZWVmMmY3IiA6ICIjZjdmOWZjIikKICAgICAgICBib3JkZXIud2lkdGg6IHByaW1hcnkgPyAwIDogMQogICAg'
    'ICAgIGJvcmRlci5jb2xvcjogZGFuZ2VyID8gIiNmZWNhY2EiIDogcm9vdC5ib3JkZXIKICAgICAgICBvcGFjaXR5OiBlbmFi'
    'bGVkQnV0dG9uID8gMSA6IDAuNgoKICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgaWQ6IGJ1dHRvblRleHQKICAgICAg'
    'ICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgIHRleHQ6IGZsYXRCdXR0b24ubGFiZWwKICAgICAg'
    'ICAgICAgY29sb3I6IGZsYXRCdXR0b24ucHJpbWFyeSA/ICJ3aGl0ZSIgOiAoZmxhdEJ1dHRvbi5kYW5nZXIgPyByb290LmJh'
    'ZCA6IHJvb3QudGV4dE1haW4pCiAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMwogICAgICAgICAgICBmb250LndlaWdo'
    'dDogRm9udC5EZW1pQm9sZAogICAgICAgIH0KICAgICAgICBNb3VzZUFyZWEgewogICAgICAgICAgICBpZDogYnV0dG9uTW91'
    'c2UKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgZW5hYmxlZDogZmxhdEJ1dHRvbi5lbmFi'
    'bGVkQnV0dG9uCiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JTaGFwZTogZW5hYmxl'
    'ZCA/IFF0LlBvaW50aW5nSGFuZEN1cnNvciA6IFF0LkFycm93Q3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogZmxhdEJ1'
    'dHRvbi5jbGlja2VkKCkKICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IE5hdkJ1dHRvbjogUmVjdGFuZ2xlIHsKICAg'
    'ICAgICBpZDogbmF2CiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgc3RyaW5nIGxhYmVsCiAgICAgICAgcmVxdWlyZWQgcHJv'
    'cGVydHkgaW50IGluZGV4CiAgICAgICAgcHJvcGVydHkgc3RyaW5nIHNob3J0TGFiZWw6ICIiCiAgICAgICAgc2lnbmFsIGNs'
    'aWNrZWQoKQogICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICBpbXBsaWNpdFdpZHRoOiAxODYKICAgICAg'
    'ICBoZWlnaHQ6IDQ4CiAgICAgICAgcmFkaXVzOiAxMQogICAgICAgIGNvbG9yOiByb290LnBhZ2VJbmRleCA9PT0gaW5kZXgg'
    'PyAiIzI1MzI0NiIgOiAobmF2TW91c2UuY29udGFpbnNNb3VzZSA/IHJvb3Quc2lkZWJhckhvdmVyIDogInRyYW5zcGFyZW50'
    'IikKCiAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgYW5j'
    'aG9ycy5sZWZ0TWFyZ2luOiAxMgogICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiAxMgogICAgICAgICAgICBzcGFj'
    'aW5nOiAxMQogICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgd2lkdGg6IDI4CiAgICAgICAgICAgICAg'
    'ICBoZWlnaHQ6IDI4CiAgICAgICAgICAgICAgICByYWRpdXM6IDgKICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnBhZ2VJ'
    'bmRleCA9PT0gbmF2LmluZGV4ID8gcm9vdC5hY2NlbnQgOiAiIzI3MzQ0OSIKICAgICAgICAgICAgICAgIEMuTGFiZWwgewog'
    'ICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICAgICAgICAgIHRleHQ6IG5h'
    'di5zaG9ydExhYmVsCiAgICAgICAgICAgICAgICAgICAgY29sb3I6ICJ3aGl0ZSIKICAgICAgICAgICAgICAgICAgICBmb250'
    'LnBpeGVsU2l6ZTogMTAKICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgICAgICAgICB0ZXh0OiBuYXYubGFiZWwKICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnBhZ2VJ'
    'bmRleCA9PT0gbmF2LmluZGV4ID8gIndoaXRlIiA6ICIjY2JkNWUxIgogICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6'
    'IDE0CiAgICAgICAgICAgICAgICBmb250LndlaWdodDogcm9vdC5wYWdlSW5kZXggPT09IG5hdi5pbmRleCA/IEZvbnQuRGVt'
    'aUJvbGQgOiBGb250Lk5vcm1hbAogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIE1vdXNlQXJlYSB7CiAgICAgICAg'
    'ICAgIGlkOiBuYXZNb3VzZQogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBob3ZlckVuYWJs'
    'ZWQ6IHRydWUKICAgICAgICAgICAgY3Vyc29yU2hhcGU6IFF0LlBvaW50aW5nSGFuZEN1cnNvcgogICAgICAgICAgICBvbkNs'
    'aWNrZWQ6IHsKICAgICAgICAgICAgICAgIHJvb3QucGFnZUluZGV4ID0gbmF2LmluZGV4CiAgICAgICAgICAgICAgICBuYXYu'
    'Y2xpY2tlZCgpCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IENhcmQ6IFJlY3RhbmdsZSB7'
    'CiAgICAgICAgcmFkaXVzOiAxNgogICAgICAgIGNvbG9yOiByb290LnN1cmZhY2UKICAgICAgICBib3JkZXIud2lkdGg6IDEK'
    'ICAgICAgICBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyCiAgICB9CgogICAgUm93TGF5b3V0IHsKICAgICAgICBhbmNob3Jz'
    'LmZpbGw6IHBhcmVudAogICAgICAgIHNwYWNpbmc6IDAKCiAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgTGF5b3V0'
    'LnByZWZlcnJlZFdpZHRoOiAyMjIKICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgY29s'
    'b3I6IHJvb3Quc2lkZWJhcgoKICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGFuY2hvcnMuZmls'
    'bDogcGFyZW50CiAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE4CiAgICAgICAgICAgICAgICBzcGFjaW5nOiA3'
    'CgogICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmJvdHRvbU1hcmdpbjogMjQKICAgICAgICAgICAgICAgICAgICBzcGFjaW5n'
    'OiAxMQogICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA0MAog'
    'ICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQwCiAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYWNjZW50CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB0ZXh0OiAiRSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQu'
    'd2VpZ2h0OiBGb250LkJsYWNrCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMAogICAgICAg'
    'ICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJFdmdlbml1bSIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBm'
    'b250LnBpeGVsU2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHRleHQ6ICJOZXR3b3JrIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICIjOTRhM2I4'
    'IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEyCiAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsg'
    'bGFiZWw6ICJWUE4iOyBzaG9ydExhYmVsOiAiVlBOIjsgaW5kZXg6IDAgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsg'
    'bGFiZWw6ICLQn9GA0L7RhNC40LvQuCBWUE4iOyBzaG9ydExhYmVsOiAiUFJGIjsgaW5kZXg6IDEgfQogICAgICAgICAgICAg'
    'ICAgTmF2QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCf0YDQuNC70L7QttC10L3QuNGPIjsgc2hvcnRM'
    'YWJlbDogIkFQUCI7IGluZGV4OiAyCiAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LnJlZnJlc2hSdW5uaW5n'
    'KCkKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0KHQsNC50YLRiyDQuCBJ'
    'UCI7IHNob3J0TGFiZWw6ICJORVQiOyBpbmRleDogMyB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCf'
    '0L7RgNGC0YsiOyBzaG9ydExhYmVsOiAiUFJUIjsgaW5kZXg6IDQgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFi'
    'ZWw6ICLQlNC40LDQs9C90L7RgdGC0LjQutCwIjsgc2hvcnRMYWJlbDogIlNZUyI7IGluZGV4OiA1IH0KICAgICAgICAgICAg'
    'ICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0K3QutGB0L/QtdGA0LjQvNC10L3RgiI7IHNob3J0TGFiZWw6ICJFWFAiOyBpbmRl'
    'eDogNiB9CgogICAgICAgICAgICAgICAgSXRlbSB7IExheW91dC5maWxsSGVpZ2h0OiB0cnVlIH0KCiAgICAgICAgICAgICAg'
    'ICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICBoZWlnaHQ6IDY0CiAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAgICAgICAgICAgIGNvbG9y'
    'OiAiIzE3MjAzMyIKICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDEyCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGhlaWdodDogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogNQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9vdC5nb29kIDog'
    'IiM2NDc0OGIiCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHNwYWNpbmc6IDEKICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3Quc3RhdGUuY29ubmVjdGluZyA/ICLQktGL0L/QvtC70L3Rj9C10YLRgdGP'
    'INC+0L/QtdGA0LDRhtC40Y8gVlBO4oCmIiA6IChCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/ICJWUE4g0LLQutC70Y7R'
    'h9GR0L0iIDogIlZQTiDQstGL0LrQu9GO0YfQtdC9IikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjog'
    'IndoaXRlIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHJv'
    'b3Quc3RhdGUucHJvZmlsZSB8fCByb290LnN0YXRlLmxhc3RfcHJvZmlsZSB8fCAi0J3QtdGCINC/0YDQvtGE0LjQu9GPIikK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiM5NGEzYjgiCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZm9udC5waXhlbFNpemU6IDExCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZGU6IFRleHQu'
    'RWxpZGVSaWdodAogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQoKICAgICAgICBJdGVt'
    'IHsKICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1'
    'ZQoKICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAg'
    'ICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDI4CiAgICAgICAgICAgICAgICBzcGFjaW5nOiAxOAoKICAgICAgICAgICAg'
    'ICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAg'
    'ICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHRleHQ6IFsiVlBOIiwgItCf0YDQvtGE0LjQu9C4IFZQTiIsICLQn9GA0LjQu9C+0LbQtdC90LjR'
    'jyDQsdC10LcgVlBOIiwgItCh0LDQudGC0Ysg0LggSVAg0LHQtdC3IFZQTiIsICLQktGF0L7QtNGP0YnQuNC1INC/0L7RgNGC'
    '0YsiLCAi0JTQuNCw0LPQvdC+0YHRgtC40LrQsCIsICLQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1Il1bcm9v'
    'dC5wYWdlSW5kZXhdCiAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAyNQogICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5C'
    'b2xkCiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIEMuQnVzeUluZGljYXRvciB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHJ1bm5pbmc6IHJvb3QuYnVzeQogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBydW5u'
    'aW5nCiAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgIGlt'
    'cGxpY2l0SGVpZ2h0OiAyOAogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQntCx0L3QvtCy0LjRgtGMIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZykKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LnJlZnJlc2hTdGF0'
    'ZSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocm9vdC5wYWdlSW5kZXggPT09IDIpCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcm9vdC5yZWZyZXNoUnVubmluZygpCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAg'
    'ICAgICAgICAgICB2aXNpYmxlOiByb290LmVycm9yVGV4dC5sZW5ndGggPiAwIHx8IHJvb3QucG9sbEVycm9yVGV4dC5sZW5n'
    'dGggPiAwCiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgIGlt'
    'cGxpY2l0SGVpZ2h0OiBlcnJvckxhYmVsLmltcGxpY2l0SGVpZ2h0ICsgMjIKICAgICAgICAgICAgICAgICAgICByYWRpdXM6'
    'IDEwCiAgICAgICAgICAgICAgICAgICAgY29sb3I6ICIjZmZmMWYyIgogICAgICAgICAgICAgICAgICAgIGJvcmRlci53aWR0'
    'aDogMQogICAgICAgICAgICAgICAgICAgIGJvcmRlci5jb2xvcjogIiNmZWNkZDMiCiAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBlcnJvckxhYmVsCiAgICAgICAgICAgICAgICAgICAgICAgIGFu'
    'Y2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTEKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdGV4dDogcm9vdC5lcnJvclRleHQgfHwgcm9vdC5wb2xsRXJyb3JUZXh0CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGNvbG9yOiByb290LmJhZAogICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3Jh'
    'cAogICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgU3RhY2tMYXlvdXQgewogICAgICAgICAgICAgICAgICAgIExheW91dC5m'
    'aWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAg'
    'ICAgICAgIGN1cnJlbnRJbmRleDogcm9vdC5wYWdlSW5kZXgKCiAgICAgICAgICAgICAgICAgICAgLy8gVlBOCiAgICAgICAg'
    'ICAgICAgICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzog'
    'MjAKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBz'
    'cGFjaW5nOiAxOAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDcyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBoZWlnaHQ6IDcyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDIyCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyBy'
    'b290LmFjY2VudFNvZnQgOiAiI2VlZjJmNyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVu'
    'dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5h'
    'Y3RpdmUpID8gIk9OIiA6ICJPRkYiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9vdC5hY2NlbnQgOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxOAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzog'
    'NQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgPyAi0JfQsNGJ0LjRidGR'
    '0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0LDQutGC0LjQstC90L4iIDogIlZQTiDRgdC10LnRh9Cw0YEg0LLRi9C6'
    '0LvRjtGH0LXQvSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0'
    'TWFpbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAyMAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBCb29sZWFuKHJvb3Quc3Rh'
    'dGUuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IChyb290LnN0YXRl'
    'LmJhY2tlbmQgPT09ICJpa2V2MiIgPyAi0JLQtdGB0YwgSVB2NC3RgtGA0LDRhNC40Log0LjQtNGR0YIg0YfQtdGA0LXQtyBT'
    'dGFyRml2ZSDQsiDQoNC+0YHRgdC40LguIElQdjYg0LggRElSRUNULdC40YHQutC70Y7Rh9C10L3QuNGPINC+0YLQutC70Y7R'
    'h9C10L3Riy4iIDogItCS0LXRgdGMINC+0LHRi9GH0L3Ri9C5INGC0YDQsNGE0LjQuiDQuNC00ZHRgiDRh9C10YDQtdC3IFZQ'
    'Tiwg0LrRgNC+0LzQtSDQvdCw0YHRgtGA0L7QtdC90L3Ri9GFINC40YHQutC70Y7Rh9C10L3QuNC5LiIpCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogItCS0LrQu9GO0YfQuCBWUE4g0L7QtNC90LjQvCDQvdCw'
    '0LbQsNGC0LjQtdC8LiDQkdGD0LTQtdGCINC40YHQv9C+0LvRjNC30L7QstCw0L0g0L/QvtGB0LvQtdC00L3QuNC5INCy0YvQ'
    'sdGA0LDQvdC90YvQuSDQv9GA0L7RhNC40LvRjC4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3Jh'
    'cE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBp'
    'eGVsU2l6ZTogMTMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSA/'
    'ICLQktGL0LrQu9GO0YfQuNGC0YwgVlBOIiA6ICLQktC60LvRjtGH0LjRgtGMIFZQTiIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgZGFuZ2VyOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0'
    'YXRlLmNvbm5lY3RpbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3Qu'
    'dG9nZ2xlVnBuKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZTsgTGF5b3V0LnByZWZlcnJlZEhlaWdodDogMTsgY29sb3I6IHJvb3QuYm9yZGVyIH0KCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgR3JpZExheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1uczogMgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5TcGFjaW5nOiAyNAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByb3dTcGFjaW5nOiAxNAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'IHRleHQ6ICLQn9GA0L7RhNC40LvRjCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3Ry'
    'aW5nKHJvb3Quc3RhdGUucHJvZmlsZSB8fCByb290LnN0YXRlLmxhc3RfcHJvZmlsZSB8fCAi4oCUIikKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiSVB2NiI7IGNv'
    'bG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUuaXB2Nl9tb2RlIHx8'
    'ICJ1bmtub3duIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWlu'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgeyB0ZXh0OiAiS2lsbCBzd2l0Y2giOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6'
    'IEJvb2xlYW4ocm9vdC5zdGF0ZS5raWxsX3N3aXRjaCkgPyAi0JDQutGC0LjQstC10L0iIDogItCS0YvQutC70Y7Rh9C10L0i'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogQm9vbGVhbihyb290LnN0YXRlLmtpbGxf'
    'c3dpdGNoKSA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JLQtdGA0YHQuNGPIG1hbmFnZXIi'
    'OyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IFN0cmluZyhyb290LnN0YXRlLm1hbmFnZXIg'
    'fHwgIuKAlCIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhl'
    'aWdodDogOTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxNAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGJvcmRlci53aWR0aDogMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIuY29sb3I6IHJvb3Qu'
    'Ym9yZGVyCgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHNwYWNpbmc6IDE0CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogNDYKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgcmFkaXVzOiAxMwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFu'
    'KHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVjdGl2ZSkgPyByb290LmFjY2VudFNvZnQgOiAiI2VlZjJmNyIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICJXRCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKSA/IHJvb3QuYWNj'
    'ZW50IDogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9u'
    'dC5waXhlbFNpemU6IDEzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQud2Vp'
    'Z2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Q29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAiVlBOINC00LvRjyBXYXlkcm9pZCIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICFCb29sZWFuKHJvb3Quc3Rh'
    'dGUuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAi0J7QsdGJ'
    '0LjQuSBWUE4g0LLRi9C60LvRjtGH0LXQvSDigJQgV2F5ZHJvaWQg0YLQvtC20LUg0YDQsNCx0L7RgtCw0LXRgiDQsdC10Lcg'
    'VlBOLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogKEJvb2xlYW4ocm9v'
    'dC5zdGF0ZS53YXlkcm9pZF92cG5fZWZmZWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgID8gItCi0YDQsNGE0LjQuiBXYXlkcm9pZCDQuNC00ZHRgiDRh9C10YDQtdC3IEUtVlBOLiIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6ICJXYXlkcm9pZCDQuNGB0L/Q'
    'vtC70YzQt9GD0LXRgiDQv9GA0Y/QvNC+0Lkg0LjQvdGC0LXRgNC90LXRgiDQsiDQvtCx0YXQvtC0IEUtVlBOLiIpCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHdheWRyb2lkU3dpdGNoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiA0OAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDI2CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgb3BhY2l0eTogQm9vbGVhbihyb290LnN0YXRlLmFjdGl2ZSkgJiYgIXJvb3QuYnVzeSA/IDEuMCA6IDAu'
    'NDUKCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiBoZWlnaHQgLyAyCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUud2F5ZHJvaWRfdnBuX2VmZmVj'
    'dGl2ZSkgPyByb290LmFjY2VudCA6ICIjY2JkNWUxIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMjAKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByYWRpdXM6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHk6'
    'IDMKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgeDogQm9vbGVhbihyb290LnN0YXRl'
    'LndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpID8gd2F5ZHJvaWRTd2l0Y2gud2lkdGggLSB3aWR0aCAtIDMgOiAzCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEJlaGF2aW9yIG9uIHggeyBOdW1iZXJBbmltYXRpb24geyBkdXJhdGlv'
    'bjogMTIwIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBNb3VzZUFyZWEgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBlbmFibGVkOiBCb29sZWFuKHJvb3Quc3RhdGUuYWN0aXZlKSAmJiAhcm9vdC5idXN5CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvclNoYXBlOiBlbmFibGVkID8gUXQuUG9pbnRp'
    'bmdIYW5kQ3Vyc29yIDogUXQuQXJyb3dDdXJzb3IKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBhY3Rpb246ICJ3YXlkcm9pZF92cG5fc2V0IiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHRhcmdldDogQm9vbGVhbihyb290LnN0YXRlLndheWRyb2lkX3Zwbl9lZmZlY3RpdmUpID8g'
    'Im9mZiIgOiAib24iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgfQoKCiAgICAgICAgICAgICAgICAgICAgLy8gVlBOIHByb2ZpbGVzCiAgICAgICAgICAgICAgICAgICAgSXRlbSB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTQKCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA3OAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFy'
    'ZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTYKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'UmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiA0MgogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3Qu'
    'YWNjZW50U29mdAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogIlBSRiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBjb2xvcjogcm9vdC5hY2NlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBmb250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250'
    'LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5'
    'b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRl'
    'eHQ6ICJWUE4t0L/RgNC+0YTQuNC70LgiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29s'
    'b3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVs'
    'U2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5C'
    'b2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3Ry'
    'aW5nKHJvb3Quc3RhdGUuY29uZmlnX2RpciB8fCAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBm'
    'b250LnBpeGVsU2l6ZTogMTEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbGlkZTogVGV4'
    'dC5FbGlkZU1pZGRsZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKChyb290LnN0YXRlLnByb2ZpbGVzIHx8'
    'IFtdKS5sZW5ndGgpICsgIiDRiNGCLiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBy'
    'b290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEy'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlzdFZp'
    'ZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNwogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5zdGF0ZS5wcm9maWxlcyB8fCBbXQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGlkOiBwcm9maWxlUm93CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB3aWR0aDogTGlzdFZpZXcudmlldy53aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVp'
    'Z2h0OiA2NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmFkaXVzOiAxMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/'
    'IHJvb3QuYWNjZW50U29mdCA6ICIjZjhmYWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9y'
    'ZGVyLndpZHRoOiBCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkgPyAxIDogMAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyLmNvbG9yOiByb290LmFjY2VudAoKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLmxlZnRNYXJnaW46IDE0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5y'
    'aWdodE1hcmdpbjogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgoK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICByYWRpdXM6IDYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJv'
    'b2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgPyByb290Lmdvb2QKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIDogKEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEubGFzdCkgPyByb290LmFjY2VudCA6ICIjY2JkNWUxIikK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgc3BhY2luZzogMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IFN0cmlu'
    'Zyhwcm9maWxlUm93Lm1vZGVsRGF0YS5zdGVtIHx8IHByb2ZpbGVSb3cubW9kZWxEYXRhLm5hbWUgfHwgIiIpCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1pQm9sZAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxpZGU6IFRleHQuRWxpZGVSaWdo'
    'dAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgdGV4dDogQm9vbGVhbihwcm9maWxlUm93Lm1vZGVsRGF0YS5hY3RpdmUpCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyAi0JDQutGC0LjQstC90YvQuSDQv9GA'
    '0L7RhNC40LvRjCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IChC'
    'b29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmxhc3QpID8gItCf0L7RgdC70LXQtNC90LjQuSDQuNGB0L/QvtC70YzQt9C+'
    '0LLQsNC90L3Ri9C5IiA6IFN0cmluZyhwcm9maWxlUm93Lm1vZGVsRGF0YS5uYW1lIHx8ICIiKSkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRh'
    'LmFjdGl2ZSkgPyByb290Lmdvb2QgOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDExCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IEJvb2xlYW4ocHJvZmlsZVJvdy5tb2RlbERhdGEuYWN0aXZlKSA/'
    'ICLQkNC60YLQuNCy0LXQvSIgOiAi0J/QvtC00LrQu9GO0YfQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAh'
    'Qm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpICYmICFCb29sZWFuKHByb2ZpbGVSb3cubW9kZWxEYXRhLmFjdGl2ZSkK'
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
    'JiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKSAmJiBtYW51YWxBcHAudGV4dC50cmltKCkubGVuZ3RoID4gMAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogImFwcF9hZGQiLCB0YXJnZXQ6IG1hbnVhbEFw'
    'cC50ZXh0LnRyaW0oKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFudWFsQXBwLmNs'
    'ZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsg'
    'dGV4dDogItCj0LbQtSDQuNGB0LrQu9GO0YfQtdC90YsiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6'
    'IDE1OyBmb250LndlaWdodDogRm9udC5Cb2xkOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKChyb290LnN0YXRlLmFwcGxpY2F0aW9ucyB8fCBbXSkubGVu'
    'Z3RoKTsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZEhlaWdodDogMTQ1CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGlzdFZpZXcgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdp'
    'bnM6IDgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBzcGFjaW5nOiA1CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiBy'
    'b290LnN0YXRlLmFwcGxpY2F0aW9ucyB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0'
    'ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5'
    'IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52'
    'aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGNvbG9yOiAiI2Y4ZmFmYyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91'
    'dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmxlZnRNYXJnaW46IDEyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5yaWdodE1hcmdpbjogOAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBT'
    'dHJpbmcobW9kZWxEYXRhKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6ICLQo9C00LDQu9C40YLRjCIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgZGFuZ2VyOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0'
    'aW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0'
    'aW9uKHthY3Rpb246ICJhcHBfcmVtb3ZlIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhKX0pCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBh'
    'cmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogKHJvb3Quc3RhdGUuYXBwbGlj'
    'YXRpb25zIHx8IFtdKS5sZW5ndGggPT09IDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6'
    'ICLQn9C+0LrQsCDQvdC10YIg0L/RgNC40LvQvtC20LXQvdC40Lkt0LjRgdC60LvRjtGH0LXQvdC40LkiCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsgdGV4dDogItCX0LDQv9GD0YnQtdC90Ysg0YHQtdC50YfQsNGBIjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4'
    'ZWxTaXplOiAxNTsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0J7QsdC90L7QstC40YLRjCDRgdC/0LjRgdC+0Loi'
    'OyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZyk7IG9uQ2xpY2tl'
    'ZDogcm9vdC5yZWZyZXNoUnVubmluZygpIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGFwcFNlYXJj'
    'aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6ICLQndCw0LnRgtC4INC30LDQv9GD0YnQtdC90L3QvtC1INC/0YDQ'
    'uNC70L7QttC10L3QuNC1INC/0L4g0LjQvNC10L3QuCDQuNC70Lgg0L/Rg9GC0LjigKYiCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91'
    'bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9yOiByb290LnN1cmZhY2U7IGJvcmRlci5jb2xvcjogcm9vdC5ib3Jk'
    'ZXIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExp'
    'c3RWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiA4CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGNsaXA6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNgog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5maWx0ZXJlZFJ1bm5pbmcoKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmlldy52aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBoZWlnaHQ6IDY0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6'
    'IDExCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgYW5jaG9ycy5tYXJnaW5zOiA5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Bh'
    'Y2luZzogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZWN0YW5nbGUgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogNDA7IGhlaWdodDogNDA7IHJhZGl1czog'
    'MTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4obW9kZWxE'
    'YXRhLmV4Y2x1ZGVkKSA/ICIjZGNmY2U3IiA6IHJvb3QuYWNjZW50U29mdAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdGV4dDogU3RyaW5nKG1vZGVsRGF0YS5uYW1lIHx8ICI/Iikuc2xpY2UoMCwgMSkudG9VcHBlckNh'
    'c2UoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4o'
    'bW9kZWxEYXRhLmV4Y2x1ZGVkKSA/IHJvb3QuZ29vZCA6IHJvb3QuYWNjZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTYKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2Rl'
    'bERhdGEubmFtZSB8fCAiIik7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZDsgZWxp'
    'ZGU6IFRleHQuRWxpZGVSaWdodCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcobW9kZWxEYXRhLmV4ZSB8fCAiIik7IGNvbG9y'
    'OiByb290LnRleHRNdXRlZDsgZm9udC5waXhlbFNpemU6IDExOyBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZSB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNp'
    'YmxlOiBOdW1iZXIobW9kZWxEYXRhLmNvdW50IHx8IDEpID4gMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB0ZXh0OiAiw5ciICsgU3RyaW5nKG1vZGVsRGF0YS5jb3VudCkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRC'
    'dXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogQm9vbGVhbiht'
    'b2RlbERhdGEuZXhjbHVkZWQpID8gItCj0LbQtSDQuNGB0LrQu9GO0YfQtdC90L4iIDogItCY0YHQutC70Y7Rh9C40YLRjCIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbWFyeTogIUJvb2xlYW4obW9kZWxE'
    'YXRhLmV4Y2x1ZGVkKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0'
    'dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZykgJiYgIUJvb2xlYW4obW9kZWxEYXRh'
    'LmV4Y2x1ZGVkKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJv'
    'b3QuYWN0aW9uKHthY3Rpb246ICJhcHBfYWRkIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhLmV4ZSB8fCBtb2RlbERhdGEu'
    'bmFtZSB8fCAiIil9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbEJhci52ZXJ0aWNhbDogQy5TY3JvbGxCYXIge30KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIFNpdGVzL0lQCiAg'
    'ICAgICAgICAgICAgICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Bh'
    'Y2luZzogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDgyCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5t'
    'YXJnaW5zOiAxNgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBpZDogZGlyZWN0VGFyZ2V0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwbGFjZWhvbGRlclRleHQ6ICJl'
    'eGFtcGxlLmNvbSwgMjAzLjAuMTEzLjEwINC40LvQuCAyMDMuMC4xMTMuMC8yNCIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHNlbGVjdEJ5TW91c2U6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9yOiAiI2Y4ZmFmYyI7IGJvcmRlci5jb2xvcjog'
    'cm9vdC5ib3JkZXIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25BY2NlcHRlZDogaWYgKHRl'
    'eHQudHJpbSgpLmxlbmd0aCkgcm9vdC5hY3Rpb24oe2FjdGlvbjogImRpcmVjdF9hZGQiLCB0YXJnZXQ6IHRleHQudHJpbSgp'
    'fSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0JTQvtCx'
    '0LDQstC40YLRjCDQuNGB0LrQu9GO0YfQtdC90LjQtSIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHByaW1hcnk6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFy'
    'b290LmJ1c3kgJiYgIUJvb2xlYW4ocm9vdC5zdGF0ZS5jb25uZWN0aW5nKSAmJiBkaXJlY3RUYXJnZXQudGV4dC50cmltKCku'
    'bGVuZ3RoID4gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogImRpcmVjdF9hZGQiLCB0'
    'YXJnZXQ6IGRpcmVjdFRhcmdldC50ZXh0LnRyaW0oKX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgZGlyZWN0VGFyZ2V0LmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBzcGFjaW5nOiAxNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBh'
    'cmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAxNAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQlNC+0LzQtdC90YsiOyBjb2xvcjog'
    'cm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZDsgZm9udC5waXhlbFNpemU6IDE1IH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogNQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LnN0YXRlLmRvbWFpbnMgfHwgW10K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUmVjdGFuZ2xlIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0'
    'YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogTGlzdFZpZXcudmlldy53'
    'aWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQ2CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogOQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudDsgYW5jaG9ycy5sZWZ0TWFyZ2luOiAxMDsgYW5jaG9ycy5yaWdodE1h'
    'cmdpbjogNwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExh'
    'eW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IFN0cmluZyhtb2RlbERhdGEpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZWxp'
    'ZGU6IFRleHQuRWxpZGVSaWdodCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQo9C00LDQu9C40YLRjCI7IGRhbmdlcjogdHJ1ZTsgZW5hYmxlZEJ1dHRvbjogIXJv'
    'b3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3RpbmcpOyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rp'
    'b246ICJkaXJlY3RfcmVtb3ZlIiwgdGFyZ2V0OiBTdHJpbmcobW9kZWxEYXRhKX0pIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbEJhci52ZXJ0aWNhbDogQy5T'
    'Y3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMubWFyZ2luczogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiAiSVAg0Lgg0YHQtdGC0LgiOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZDsg'
    'Zm9udC5waXhlbFNpemU6IDE1IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExpc3RWaWV3IHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgc3BhY2luZzogNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IG1vZGVsOiByb290LnN0YXRlLm5ldHdvcmtzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgZGVsZWdhdGU6IFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgd2lkdGg6IExpc3RWaWV3LnZpZXcud2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgaGVpZ2h0OiA0NgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICByYWRpdXM6IDkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6ICIjZjhm'
    'YWZjIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQ7IGFuY2hv'
    'cnMubGVmdE1hcmdpbjogMTA7IGFuY2hvcnMucmlnaHRNYXJnaW46IDcKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB0ZXh0OiBTdHJpbmcobW9k'
    'ZWxEYXRhKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCj0LTQsNC70LjRgtGM'
    'IjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVj'
    'dGluZyk7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImRpcmVjdF9yZW1vdmUiLCB0YXJnZXQ6IFN0cmluZyht'
    'b2RlbERhdGEpfSkgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIEMuU2Nyb2xsQmFyLnZlcnRpY2FsOiBDLlNjcm9sbEJhciB7fQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgfQoKICAgICAgICAgICAgICAgICAgICAvLyBQb3J0cwogICAgICAgICAgICAgICAgICAg'
    'IEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMDUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3Jz'
    'LmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE1CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDgKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0JTQu9GPINC70L7QutCw'
    '0LvRjNC90YvRhSDRgdC10YDQstC10YDQvtCyOiDQvtGC0LLQtdGC0Ysg0L3QsCDQstGF0L7QtNGP0YnQuNC1INC/0L7QtNC6'
    '0LvRjtGH0LXQvdC40Y8g0Log0Y3RgtC40Lwg0L/QvtGA0YLQsNC8INC40LTRg9GCINC90LDQv9GA0Y/QvNGD0Y4g0YfQtdGA'
    '0LXQtyDRhNC40LfQuNGH0LXRgdC60YPRjiDRgdC10YLRjC4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBN'
    'b2RlOiBUZXh0LldvcmRXcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6'
    'ZTogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxX'
    'aWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBwb3J0RmllbGQKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcGxhY2Vob2xkZXJUZXh0OiAiMjU1NjUiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgaW5wdXRNZXRob2RIaW50czogUXQuSW1oRGlnaXRzT25seQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9yOiAiI2Y4ZmFm'
    'YyI7IGJvcmRlci5jb2xvcjogcm9vdC5ib3JkZXIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Db21ib0JveCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHByb3RvQm94CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgbW9kZWw6IFsiVENQIiwgIlVEUCIsICJCT1RIIl0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBpbXBsaWNpdFdpZHRoOiAxMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0JTQvtCx0LDQstC40YLRjCIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhQm9vbGVhbihyb290LnN0YXRlLmNvbm5lY3Rpbmcp'
    'ICYmIHBvcnRGaWVsZC50ZXh0Lmxlbmd0aCA+IDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgcCA9'
    'IE51bWJlcihwb3J0RmllbGQudGV4dCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'aWYgKHAgPj0gMSAmJiBwIDw9IDY1NTM1ICYmIHAgPT09IE1hdGguZmxvb3IocCkpIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuYWN0aW9uKHthY3Rpb246ICJwb3J0X2FkZCIsIHBvcnQ6IHAs'
    'IHByb3RvOiBwcm90b0JveC5jdXJyZW50VGV4dC50b0xvd2VyQ2FzZSgpfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHBvcnRGaWVsZC5jbGVhcigpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmls'
    'bFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMaXN0VmlldyB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFy'
    'Z2luczogMTAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiA3CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVs'
    'OiByb290LnN0YXRlLnNlcnZlcl9wb3J0cyB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxl'
    'Z2F0ZTogUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3Bl'
    'cnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBMaXN0Vmll'
    'dy52aWV3LndpZHRoCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDU0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBjb2xvcjogIiNmOGZhZmMiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dM'
    'YXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'OyBhbmNob3JzLmxlZnRNYXJnaW46IDEyOyBhbmNob3JzLnJpZ2h0TWFyZ2luOiA4CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgd2lkdGg6IDU0OyBoZWlnaHQ6IDMwOyByYWRpdXM6IDg7IGNvbG9yOiByb290LmFjY2VudFNvZnQKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IGFuY2hvcnMuY2VudGVySW46IHBh'
    'cmVudDsgdGV4dDogU3RyaW5nKG1vZGVsRGF0YS5wcm90byB8fCAiIikudG9VcHBlckNhc2UoKTsgY29sb3I6IHJvb3QuYWNj'
    'ZW50OyBmb250LndlaWdodDogRm9udC5Cb2xkOyBmb250LnBpeGVsU2l6ZTogMTEgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdGV4dDogU3RyaW5nKG1vZGVsRGF0YS5wb3J0IHx8ICIiKTsgY29sb3I6'
    'IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAxNjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCj0LTQsNC70LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVk'
    'QnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKHJvb3Quc3RhdGUuY29ubmVjdGluZykKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAicG9ydF9yZW1v'
    'dmUiLCBwb3J0OiBOdW1iZXIobW9kZWxEYXRhLnBvcnQpLCBwcm90bzogU3RyaW5nKG1vZGVsRGF0YS5wcm90byl9KQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLlNjcm9sbEJhci52ZXJ0aWNhbDogQy5TY3JvbGxCYXIge30KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7IGFuY2hvcnMuY2VudGVySW46IHBhcmVudDsgdmlzaWJsZTogKHJvb3Quc3RhdGUu'
    'c2VydmVyX3BvcnRzIHx8IFtdKS5sZW5ndGggPT09IDA7IHRleHQ6ICLQndC10YIg0YHQtdGA0LLQtdGA0L3Ri9GFINC/0L7R'
    'gNGC0L7QsiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'fQoKICAgICAgICAgICAgICAgICAgICAvLyBEaWFnbm9zdGljcwogICAgICAgICAgICAgICAgICAgIEl0ZW0gewogICAgICAg'
    'ICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5z'
    'OiAyNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE0CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQotC10LrRg9GJ0LXQtSDRgdC+0YHRgtC+0Y/QvdC40LUiOyBjb2xvcjogcm9v'
    'dC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6IDE4OyBmb250LndlaWdodDogRm9udC5Cb2xkIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBHcmlkTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zOiAyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtblNwYWNpbmc6IDI4CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHJvd1NwYWNpbmc6IDEzCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0'
    'ZXh0OiAiVlBOIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5MYWJlbCB7IHRleHQ6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gItCS0LrQu9GO0YfRkdC9IiA6ICLQktGL0LrQ'
    'u9GO0YfQtdC9IjsgY29sb3I6IEJvb2xlYW4ocm9vdC5zdGF0ZS5hY3RpdmUpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TXV0'
    'ZWQ7IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IHRleHQ6ICLQn9GA0L7RhNC40LvRjCI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5wcm9maWxlIHx8IHJvb3Quc3Rh'
    'dGUubGFzdF9wcm9maWxlIHx8ICLigJQiKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlC'
    'b2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJUVU4iOyBjb2xvcjog'
    'cm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogQm9v'
    'bGVhbihyb290LnN0YXRlLnR1bikgPyAieHJheXR1biDQv9C+0LTQvdGP0YIiIDogItCd0LXRgiI7IGNvbG9yOiByb290LnRl'
    'eHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgeyB0ZXh0OiAiS2lsbCBzd2l0Y2giOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogQm9vbGVhbihyb290LnN0YXRlLmtpbGxfc3dpdGNoKSA/ICLQ'
    'kNC60YLQuNCy0LXQvSIgOiAi0JLRi9C60LvRjtGH0LXQvSI7IGNvbG9yOiBCb29sZWFuKHJvb3Quc3RhdGUua2lsbF9zd2l0'
    'Y2gpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TXV0ZWQ7IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJJUHY2IjsgY29sb3I6IHJvb3QudGV4dE11dGVk'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRl'
    'LmlwdjZfbW9kZSB8fCAidW5rbm93biIpOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJv'
    'bGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkRJUkVDVCDQv9GA0LjQ'
    'u9C+0LbQtdC90LjRjyI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgeyB0ZXh0OiBTdHJpbmcocm9vdC5zdGF0ZS5kaXJlY3RfYXBwbGljYXRpb25zIHx8IDApOyBjb2xvcjog'
    'cm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkRJUkVDVCDQtNC+0LzQtdC90YsiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogU3RyaW5nKHJvb3Quc3RhdGUuZGly'
    'ZWN0X2RvbWFpbnMgfHwgMCk7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRElSRUNUIElQL9GB0LXRgtC4Ijsg'
    'Y29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRl'
    'eHQ6IFN0cmluZyhyb290LnN0YXRlLmRpcmVjdF9uZXR3b3JrcyB8fCAwKTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQu'
    'd2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRl'
    'eHQ6ICJNYW5hZ2VyIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQy5MYWJlbCB7IHRleHQ6IFN0cmluZyhyb290LnN0YXRlLm1hbmFnZXIgfHwgIuKAlCIpOyBjb2xvcjogcm9vdC50ZXh0'
    'TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQntC60L3QviDQ'
    'vdCw0YHRgtGA0L7QtdC6INGA0LDQsdC+0YLQsNC10YIg0L7RgtC00LXQu9GM0L3QviDQvtGCIFBsYXNtYS4gS0RFINC40YHQ'
    'v9C+0LvRjNC30YPQtdGC0YHRjyDRgtC+0LvRjNC60L4g0LTQu9GPINC80LDQu9C10L3RjNC60L7Qs9C+INCy0LjQtNC20LXR'
    'gtCwINC90LAg0YDQsNCx0L7Rh9C10Lwg0YHRgtC+0LvQtS4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4'
    'dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CgogICAgICAgICAgICAgICAgICAgIC8vIElzb2xhdGVkIGV4cGVy'
    'aW1lbnRhbCB0dW5uZWw6IHRoZSBvcmRpbmFyeSBWUE4vYnJvd3NlciByZW1haW4gdW50b3VjaGVkLgogICAgICAgICAgICAg'
    'ICAgICAgIEl0ZW0gewogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlNjcm9sbFZpZXcgewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBzdGFyZml2ZVNjcm9sbAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5z'
    'OiAyNAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRlbnRXaWR0aDogYXZhaWxhYmxlV2lkdGgKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB3aWR0aDogc3RhcmZpdmVTY3JvbGwuYXZhaWxhYmxlV2lkdGgKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgc3BhY2luZzogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiAi0K3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90YvQ'
    'uSBWUE4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9u'
    'dC5waXhlbFNpemU6IDIyOyBmb250LndlaWdodDogRm9udC5Cb2xkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB0ZXh0OiAi0JLQtdGB0Ywg0LjQvdGC0LXRgNC90LXRgiDRh9C10YDQtdC3IFN0YXJGaXZlINC4INCt0YHR'
    'gtC+0L3QuNGOLiDQl9Cw0LLQuNGB0LjQvNC+0YHRgtC4INGD0YHRgtCw0L3QvtCy0Y/RgtGB0Y8g0LDQstGC0L7QvNCw0YLQ'
    'uNGH0LXRgdC60LguIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11'
    'dGVkOyB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KLQvtC60LXQvSDQutC70LjQtdC90YLQ'
    'sCI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAx'
    'MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBzdGFyZml2ZVRva2VuCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGltcGxpY2l0SGVpZ2h0OiA0MgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGxlZnRQYWRkaW5nOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJpZ2h0UGFk'
    'ZGluZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TWFpbgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudG9rZW5Mb2NrZWQgPyAiI2YwZjhmYyIgOiByb290LnN1cmZh'
    'Y2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyLndpZHRoOiAxCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci5jb2xvcjogc3RhcmZpdmVUb2tlbi5h'
    'Y3RpdmVGb2N1cyA/IHJvb3QuYWNjZW50IDogcm9vdC5ib3JkZXIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGxhY2Vob2xkZXJUZXh0'
    'OiByb290LnRva2VuTG9ja2VkID8gU3RyaW5nKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS50b2tlbl9oaW50IHx8'
    'ICLQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0iKSA6ICLQktGB0YLQsNCy0YzRgtC1INGC0L7QutC10L0gRVZOMS3igKYi'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWNob01vZGU6IFRleHRJbnB1dC5QYXNzd29y'
    'ZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlYWRPbmx5OiByb290LnRva2VuTG9ja2Vk'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogIXJvb3QudG9rZW5M'
    'b2NrZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiAhcm9vdC5idXN5ICYm'
    'ICFCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIG1heGltdW1MZW5ndGg6IDY0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0KLQvtC60LXQvSDQutC70LjQtdC90YLQsCIKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjY2VwdGVkOiB0b2tlbkNvbmZpcm0uY29uZmlybSgpCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogdG9rZW5Db25m'
    'aXJtCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IHJvb3QudG9rZW5Mb2NrZWQg'
    'PyAi0JjQt9C80LXQvdC40YLRjCIgOiAi0J/QvtC00YLQstC10YDQtNC40YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiAhcm9vdC50b2tlbkxvY2tlZAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4oKHJvb3QuZXhwZXJpbWVu'
    'dC50dW5uZWwgfHwge30pLnJ1bm5pbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICYmIChyb290LnRva2VuTG9ja2VkIHx8IC9eRVZOMS1bQS1aYS16MC05Xy1dezQzfSQvLnRlc3Qoc3RhcmZpdmVUb2tlbi50'
    'ZXh0LnRyaW0oKSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZnVuY3Rpb24gY29uZmly'
    'bSgpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFlbmFibGVkQnV0dG9u'
    'KSByZXR1cm4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJvb3QudG9rZW5M'
    'b2NrZWQpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QudG9rZW5F'
    'ZGl0aW5nID0gdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhcmZp'
    'dmVUb2tlbi5mb3JjZUFjdGl2ZUZvY3VzKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuYWN0'
    'aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfdG9rZW4tc2F2ZSIsIHRhcmdldDogc3RhcmZpdmVUb2tlbi50ZXh0LnRyaW0o'
    'KX0sIGZ1bmN0aW9uKCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHN0YXJmaXZlVG9rZW4uY2xlYXIoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHJvb3QudG9rZW5FZGl0aW5nID0gZmFsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgb25DbGlja2VkOiBjb25maXJtKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiB0b2tlbkNhbmNlbAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGxhYmVsOiAi0J7RgtC80LXQvdCwIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHZpc2libGU6IHJvb3QudG9rZW5FZGl0aW5nICYmIHJvb3QudG9rZW5TYXZlZAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsgc3RhcmZpdmVUb2tlbi5jbGVhcigpOyByb290LnRva2Vu'
    'RWRpdGluZyA9IGZhbHNlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0LldvcmRXcmFwCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiByb290LnRva2VuTG9ja2VkID8gItCi0L7QutC10L0g0YHQvtGF0YDQsNC9'
    '0ZHQvSDQvdCwINGD0YHRgtGA0L7QudGB0YLQstC1LiDQn9GA0L7QstC10YDQutCwINC90LAg0YHQtdGA0LLQtdGA0LUg4oCU'
    'INC/0YDQuCDQv9C+0LTQutC70Y7Rh9C10L3QuNC4LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICA6IHJvb3QudG9rZW5FZGl0aW5nID8gItCS0YHRgtCw0LLRjNGC0LUg0L3QvtCy0YvQuSDRgtC+0LrQtdC9INC4INC9'
    '0LDQttC80LjRgtC1IMKr0J/QvtC00YLQstC10YDQtNC40YLRjMK7LiDQlNC+INGB0L7RhdGA0LDQvdC10L3QuNGPINC00LXQ'
    'udGB0YLQstGD0LXRgiDQv9GA0LXQttC90LjQuSDRgtC+0LrQtdC9LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICA6ICLQotC+0LrQtdC9INC10YnRkSDQvdC1INGB0L7RhdGA0LDQvdGR0L0uINCS0YHRgtCw0LLRjNGC'
    '0LUg0LXQs9C+INC4INC90LDQttC80LjRgtC1IMKr0J/QvtC00YLQstC10YDQtNC40YLRjMK7LiIKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRva2VuTG9ja2VkID8gcm9vdC5nb29kIDogcm9vdC50ZXh0'
    'TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5y'
    'dW5uaW5nKSA/ICLQntGC0LrQu9GO0YfQuNGC0YwiIDogItCf0L7QtNC60LvRjtGH0LjRgtGMIgogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8'
    'IHt9KS5ydW5uaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246'
    'ICFyb290LmJ1c3kgJiYgKEJvb2xlYW4oKHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLnJ1bm5pbmcpIHx8IHJvb3Qu'
    'dG9rZW5Mb2NrZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290'
    'LmFjdGlvbih7YWN0aW9uOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKSA/ICJleHBl'
    'cmltZW50YWxfZGlzY29ubmVjdCIgOiAiZXhwZXJpbWVudGFsX2Nvbm5lY3QifSkKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J/QvtGH0LjQvdC40YLRjCIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIHJv'
    'b3QudG9rZW5Mb2NrZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJv'
    'b3QuYWN0aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfcmVwYWlyIn0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgTGF5b3V0LnByZWZlcnJlZEhlaWdo'
    'dDogMTsgY29sb3I6IHJvb3QuYm9yZGVyIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'IHRleHQ6ICLQodGC0YDQvtC60LAg0YHQvtGB0YLQvtGP0L3QuNGPIjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQud2Vp'
    'Z2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0QXJlYSB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQubWluaW11bUhlaWdodDogMTIwCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICByZWFkT25seTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1v'
    'ZGU6IFRleHRFZGl0LldyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IFN0cmluZygo'
    'cm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkubWVzc2FnZSB8fCAi0KHQvtGF0YDQsNC90LjRgtC1INGC0L7QutC10L0g'
    '0LrQu9C40LXQvdGC0LAuINCf0L7QtNC60LvRjtGH0LXQvdC40LUg0L/QtdGA0LXQutC70Y7Rh9C40YIg0LLQtdGB0Ywg0LjQ'
    'vdGC0LXRgNC90LXRgiDQvdCwINGN0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0LkgVlBOLiIpCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAoU3RyaW5nKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9'
    'KS5zY29wZSB8fCAiIikgPT09ICJsYW4iID8gIlxu0J/RgNC+0LLQtdGA0LrQsCDQsiDQtNC+0LzQsNGI0L3QtdC5INGB0LXR'
    'gtC4OyDQstC90LXRiNC90LjQuSDQv9GD0YLRjCDRh9C10YDQtdC3INC/0YDQvtCy0LDQudC00LXRgNCwINC10YnRkSDQvdC1'
    'INC/0YDQvtCy0LXRgNC10L0uIiA6ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsg'
    'KEJvb2xlYW4oKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5pbnRlZ3JpdHkpID8gIlxu'
    '0J/QtdGA0LXQtNCw0YfQsCDQtNCw0L3QvdGL0YU6INGG0LXQu9C+0YHRgtC90L7RgdGC0Ywg0L/QvtC00YLQstC10YDQttC0'
    '0LXQvdCwLiIgOiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArICgoKChyb290LmV4'
    'cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5yZWZlcmVuY2UgfHwge30pLmVzdGltYXRlZF9tYnBzID8g'
    'Ilxu0K/QvdC00LXQutGBOiDQvtGG0LXQvdC60LAg0L/RgNGP0LzQvtC5INGB0LrQvtGA0L7RgdGC0LggIiArIE51bWJlcigo'
    'KChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5yZWZlcmVuY2UgfHwge30pLmVzdGltYXRl'
    'ZF9tYnBzKS50b0ZpeGVkKDEpICsgIiDQnNCx0LjRgi/RgSAo0LrQvtGA0L7RgtC60LjQuSDQt9Cw0LzQtdGAKS4iIDogIiIp'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAoKCgocm9vdC5leHBlcmltZW50LnR1bm5l'
    'bCB8fCB7fSkubWV0cmljcyB8fCB7fSkucmVmZXJlbmNlIHx8IHt9KS5hdmFpbGFibGUgPT09IGZhbHNlID8gIlxu0K/QvdC0'
    '0LXQutGBOiDQvtGA0LjQtdC90YLQuNGAINGB0LrQvtGA0L7RgdGC0Lgg0YHQtdC50YfQsNGBINC90LXQtNC+0YHRgtGD0L/Q'
    'tdC9LiIgOiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBCb29sZWFuKChyb290'
    'LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5hY3RpdmUpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TWFpbgogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0KHRgtGA0L7QutCwINGB0L7RgdGC0L7R'
    'j9C90LjRjyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBDLlByb2dyZXNzQmFyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZyb206IDA7IHRvOiAx'
    'MDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlOiBOdW1iZXIoKHJvb3QuZXhwZXJpbWVu'
    'dC50dW5uZWwgfHwge30pLnByb2dyZXNzIHx8IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2'
    'aXNpYmxlOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKSAmJiAhQm9vbGVhbigocm9v'
    'dC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAg'
    'ICAgICAgfQogICAgfQp9Cg=='
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


def restore_firefox_codex_exceptions(settings: dict) -> None:
    """Undo only the erroneous 0.3.0-ru.2 application-list migration."""
    if not settings.get('firefox_codex_exceptions_migrated'):
        return
    path = _safe_direct_path(settings, 'direct_apps')
    backup_settings = {**settings, 'direct_apps': str(path.with_name(path.name + '.before-0.3.0-ru.2'))}
    backup = _safe_direct_path(backup_settings, 'direct_apps')
    if backup.exists():
        original = backup.read_text()
        names = {'firefox', 'firefox-bin', 'firefox-esr', 'codex', 'codex-desktop'}
        removed, kept = [], []
        for line in original.splitlines(keepends=True):
            value = line.strip()
            if value and not value.startswith('#') and pathlib.PurePosixPath(value).name.lower() in names:
                removed.append(line)
            else:
                kept.append(line)
        current = path.read_text() if path.exists() else ''
        if current == ''.join(kept):
            restored = original  # No intervening edits: restore the exact original bytes.
        else:
            # Keep later edits and restore only the entries removed by our migration.
            existing = {line.strip() for line in current.splitlines() if line.strip()}
            additions = []
            for line in removed:
                if line.strip() not in existing:
                    additions.append(line.rstrip('\r\n') + '\n')
                    existing.add(line.strip())
            restored = current + ('\n' if additions and current and not current.endswith('\n') else '') + ''.join(additions)
        if restored != current:
            _write_direct_file(settings, 'direct_apps', restored)
            info('Прежние исключения Firefox и Codex восстановлены из резервной копии.')
    # No backup means the previous migration found no matching entries to remove.
    settings.pop('firefox_codex_exceptions_migrated', None)
    save_settings(settings)


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
                        for address in DNS_UPSTREAM_SERVERS]}


def dns_outbound() -> dict:
    return {"tag": "dns-out", "protocol": "dns",
            "settings": {"rewriteAddress": DNS_PRIMARY_IP, "rewritePort": 53,
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
                    "address": DNS_PRIMARY_IP,
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
        "protocol": "dokodemo-door", "settings": {"address": DNS_PRIMARY_IP, "port": 53, "network": "tcp,udp"}}],
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
        fail("Профиль не прошёл изолированную проверку HTTPS/DNS через текущую сеть: " + detail +
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
    if starfive_tunnel.full_guard_active():
        fail("Сначала отключите экспериментальный VPN через вкладку «Экспериментальное».")
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
    if starfive_tunnel.full_guard_active():
        starfive_tunnel.disconnect()
        return
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
        "profile": "StarFive → Эстония" if exp["guard"] else (str(st.get("active") or "") if active else ""),
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
    if token == "-":
        token = sys.stdin.read(16385)
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

STARFIVE_TUNNEL_PY_B64 = (
    'IiIiVG9rZW4gSUtFdjIgY2xpZW50OiBpc29sYXRlZCB0cmFuc3BvcnQgYW5kIGd1YXJkZWQgZnVsbC1kZXZpY2UgRXN0b25p'
    'YSBlZ3Jlc3MuIiIiCmltcG9ydCBjb250ZXh0bGliCmltcG9ydCBmY250bAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaHR0cC5j'
    'bGllbnQKaW1wb3J0IGlwYWRkcmVzcwppbXBvcnQganNvbgppbXBvcnQgb3MKZnJvbSBwYXRobGliIGltcG9ydCBQYXRoCmlt'
    'cG9ydCByZQppbXBvcnQgc2VjcmV0cwppbXBvcnQgc2h1dGlsCmltcG9ydCBzaWduYWwKaW1wb3J0IHNvY2tldAppbXBvcnQg'
    'c3NsCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCB0aW1lCgpST09UID0gUGF0aCgnL2V0Yy92cG4tbWFuYWdlci9zdGFyZml2'
    'ZS10dW5uZWwnKQpSVU5USU1FID0gUGF0aCgnL3J1bi9ldmdlbml1bS1zdGFyZml2ZS10dW5uZWwnKQpTVEFURSA9IFBhdGgo'
    'Jy92YXIvbGliL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXR1bm5lbC5qc29uJykKVU5JVCA9ICdldmdlbml1bS1zdGFyZml2ZS10'
    'dW5uZWwuc2VydmljZScKTlMgPSAnZXZuLXN0YXJmaXZlJwpIT1NUID0gJ2V2bi1zZi1ob3N0JwpQRUVSID0gJ2V2bi1zZi1w'
    'ZWVyJwpORVRXT1JLID0gJzE3Mi4yOS4yNDYuMC8zMCcKQ0xJRU5UID0gJzE3Mi4yOS4yNDYuMicKR0FURVdBWSA9ICcxNzIu'
    'MjkuMjQ2LjEnClRBQkxFID0gNTE4MjQKUFJJT1JJVFkgPSA3NQpORlQgPSAnZXZnZW5pdW1fc3RhcmZpdmVfbGFiX2hvc3Qn'
    'ClNFUlZFUiA9ICcxMDkuMTk0LjY3LjE1OScKU0VSVkVSX0xBTiA9ICcxOTIuMTY4LjAuMTYzJwpIRUFMVEggPSAnMTAuNzcu'
    'MC4xJwpSRVFJRCA9IDE3NwpUT0tFTl9QQVRURVJOID0gcidFVk4xLVtBLVphLXowLTlfLV17NDN9JwpTVE9QID0gRmFsc2UK'
    'UElOTkVEX0NBID0gJy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRU9EQ0NBcUNnQXdJQkFnSVVia0orOFNhcUFn'
    'd1kxUkRBalpSVGpjcVE5ZU13RFFZSktvWklodmNOQVFFTFxuQlFBd0lqRWdNQjRHQTFVRUF3d1hSWFpuWlc1cGRXMGdjSEpw'
    'ZG1GMFpTQldVRTRnUTBFd0hoY05Nall4TURBM1xuTVRreE16UXhXaGNOTXpZeE1EQTBNVGt4TXpReFdqQWlNU0F3SGdZRFZR'
    'UUREQmRGZG1kbGJtbDFiU0J3Y21sMlxuWVhSbElGWlFUaUJEUVRDQ0FhSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnR1BBREND'
    'QVlvQ2dnR0JBT1orbnZpRVxuMk9yRjdQZHRray9YSWFGVkl2Smx2QzExVlpmOXJsakNCSXZCeWtic3JBckdyeVFIR251dVhM'
    'TmFhUzhOdEx4WVxuTmVTQkRLNk1kZ1lKQWVqc1A0d0lUdWIzbk1qU0cydW1JSVZVNm1FK0dEb3pHUGxOTU5KK2Joa0thVmhh'
    'UGpGRVxueVlMWXJkUGU1VkE0dys1cDBOWk9ENkNCSEQzdEVYV0JOUkllVlNXYnRNSVRzT0VTMVBlL2FBTDd2M29OSVZrVlxu'
    'OG5EdzlqNyt3RzJ5NWRoYnA3S1VKSGJyREIwMjRyN2NZclEzYXhZRjZneWtqbXp0cEtYc2JreFF2MjdCdmhTQlxuZTBFa3RK'
    'L2pDUzZSOUlJbVlnSVFyQ3JhV1ptVlNjbkdGL0FxNFROdzFINE96RkNrUis3SlVsWW5TWVV2TVJpMVxuTHpLZWtVQysyLzBX'
    'Rm1obkNvRHRkamNvWWJ4cExwS0RlbEdpUzNSc05Ddnhuc2xNYVB6NWhDY0Y2NFk3UmlqWFxuajZEdUNZcEZZV2xyMTNCMjBx'
    'QW5Sb1VhcytBalg3UFhDa1I0eE9oSCtrVzgvSG1GSGlIa29oV0Uwd2xsSVNCWFxuVkJvN0tCT1pkOFNWZXd5YmQyckI0c29Y'
    'b3VUdGpYcy9qVGdlK0hXeFFER1BQMXVtZno4Y0ZMUi91UUlEQVFBQlxubzJZd1pEQWRCZ05WSFE0RUZnUVVvUWZUaWY3N3hX'
    'dDA2aGFYaDNoYTg5MHFrVDh3SHdZRFZSMGpCQmd3Rm9BVVxub1FmVGlmNzd4V3QwNmhhWGgzaGE4OTBxa1Q4d0VnWURWUjBU'
    'QVFIL0JBZ3dCZ0VCL3dJQkFEQU9CZ05WSFE4QlxuQWY4RUJBTUNBUVl3RFFZSktvWklodmNOQVFFTEJRQURnZ0dCQUk3R0tu'
    'bWZKanVMMVF2eVJ0bHcrSHI2QVkvWlxuT3hkRHZFQ2Vmb0ZMN1E0MVZaYStMN0RJODdrTUxZSHlnUkh1c2g2Nm9Vdjg3OFRX'
    'TXRhc25idC84d1lnNmpyd1xuQXlncGcvRjNWRDI0eVRybko3T0NkeUdpYjZMR3V1c3VUUDRyVUdzY2NXY3puUVhZRmt6UlZ6'
    'MVZlWU1aVU4rUFxudEFWaU5sNEVSUzFmaCtjR3pUNE9xWFFrSkRrUmVxSC9IQ1RFOGtVUVVVZ1hhU1hwaEtqR2E4cFIySFZl'
    'RnVrWFxuKzBwcDFpUis2ZGk0YUNLYXBrYVRpVlIzcjYydFJCVXdieG9GWVJ5eE5YeW5USzlFaG5NMjVXRXBuL3F1MGxzRFxu'
    'b1hyRlZtajBBUWZBVUhSTi8yclBMLy93NlJQRXBIZ1VjcnQ3enVTZ29YSlpoMERUMzBWRUlLOU5OYnVLU0ZkOVxuSWlXdnJ4'
    'YlZRUzZtUWd0RVpONExjMkhtMXB2WStXckkrSDAzdTgwNDIrY3BMSXNDbnhQbTlXdmk3ZE1YeHFvYlxubzIvYUwyeERHNUcv'
    'OFdWUi9XNUVBZnZLZHhkcmszSDYwMm9jY292NytKZzF2b3hpMDBJYmRNRXhvTXhkNWFlaFxuZlhSaUpoVEVGb3VJcG1FU0NG'
    'NHZWTWxXRnIzbXFsUTNHS1NQVkE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuJwoKCkZVTExfSE9TVCA9ICdldm4t'
    'ZnVsbC1ob3N0JwpGVUxMX1BFRVIgPSAnZXZuLWZ1bGwtcGVlcicKRlVMTF9ORVQgPSAnMTcyLjI5LjI0Ny4wLzMwJwpGVUxM'
    'X1RBQkxFID0gJzUxODI4JwpBRE1JTl9UQUJMRSA9ICc1MTgyOScKRlVMTF9HVUFSRCA9ICdldm5fc3RhcmZpdmVfZnVsbCcK'
    'ZGVmIGZ1bGxfc3RhdGUoKToKICAgIHJldHVybiBST09ULydmdWxsLW5ldHdvcmsuanNvbicKCgpkZWYgY2hhcm9uX2JpbmFy'
    'eSgpOgogICAgY2FuZGlkYXRlcyA9ICgnL3Vzci9zYmluL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvYmluL2NoYXJvbi1zeXN0'
    'ZW1kJywKICAgICAgICAgICAgICAgICAgJy91c3IvbGliL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvbGliZXhlYy9p'
    'cHNlYy9jaGFyb24tc3lzdGVtZCcsCiAgICAgICAgICAgICAgICAgICcvdXNyL2xpYi9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0'
    'ZW1kJywgJy91c3IvbGliZXhlYy9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0ZW1kJykKICAgIHJldHVybiBuZXh0KChwIGZvciBw'
    'IGluIGNhbmRpZGF0ZXMgaWYgUGF0aChwKS5pc19maWxlKCkpLCBOb25lKQoKCmRlZiBlbnN1cmVfZGVwZW5kZW5jaWVzKCk6'
    'CiAgICBpZiBjaGFyb25fYmluYXJ5KCkgYW5kIGFsbChzaHV0aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2FuY3RsJywnaXAn'
    'LCduZnQnLCdjdXJsJywnb3BlbnNzbCcsJ2Nvbm50cmFjaycpKToKICAgICAgICByZXR1cm4KICAgIHN0YWdlKCdkZXBlbmRl'
    'bmNpZXMnLCAn0KPRgdGC0LDQvdCw0LLQu9C40LLQsNGOINC90LXQvtCx0YXQvtC00LjQvNGL0LUg0YHQuNGB0YLQtdC80L3R'
    'i9C1INC60L7QvNC/0L7QvdC10L3RgtGLIFZQTi4nLCAzLCBhY3RpdmU9RmFsc2UpCiAgICBpZiBzaHV0aWwud2hpY2goJ3Bh'
    'Y21hbicpOgogICAgICAgIGFyZ3MgPSBbJ3BhY21hbicsJy1TJywnLS1uZWVkZWQnLCctLW5vY29uZmlybScsJ3N0cm9uZ3N3'
    'YW4nLCdpcHJvdXRlMicsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMnLCdjb25udHJhY2st'
    'dG9vbHMnXQogICAgZWxpZiBzaHV0aWwud2hpY2goJ2RuZicpOgogICAgICAgIGFyZ3MgPSBbJ2RuZicsJ2luc3RhbGwnLCct'
    'eScsJy0tc2V0b3B0PWluc3RhbGxfd2Vha19kZXBzPUZhbHNlJywnc3Ryb25nc3dhbicsJ2lwcm91dGUnLCduZnRhYmxlcycs'
    'J2N1cmwnLCdvcGVuc3NsJywnY2EtY2VydGlmaWNhdGVzJywnY29ubnRyYWNrLXRvb2xzJ10KICAgIGVsc2U6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCfQkNCy0YLQvtC80LDRgtC40YfQtdGB0LrQsNGPINGD0YHRgtCw0L3QvtCy0LrQsCDRjdC6'
    '0YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtCz0L4g0LrQu9C40LXQvdGC0LAg0L/QvtC00LTQtdGA0LbQuNCy0LDQtdGC'
    'IEFyY2gg0LggRmVkb3JhLicpCiAgICBjb21tYW5kKGFyZ3MsIHRpbWVvdXQ9MzAwKQogICAgaWYgbm90IGNoYXJvbl9iaW5h'
    'cnkoKSBvciBub3QgYWxsKHNodXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwnLCdjb25udHJhY2snKSk6CiAgICAg'
    'ICAgcmFpc2UgUnVudGltZUVycm9yKCfQn9Cw0LrQtdGCIHN0cm9uZ1N3YW4g0L3QtSDQv9GA0LXQtNC+0YHRgtCw0LLQuNC7'
    'INC90LXQvtCx0YXQvtC00LjQvNGL0LUg0L/RgNC+0LPRgNCw0LzQvNGLLicpCgoKZGVmIGNsZWFyX2Ruc19tYXBwaW5ncyhw'
    'cmV2aW91c192cG49RmFsc2UpOgogICAgIiIiRm9yZ2V0IG9ubHkgdGhpcyBtYW5hZ2VyJ3Mgb2Jzb2xldGUgRE5TIE5BVCwg'
    'bmV2ZXIgZmx1c2ggYWxsIGNvbm5lY3Rpb25zLgoKICAgIFJlbW92aW5nIGFuIG5mdCBOQVQgY2hhaW4gZG9lcyBub3QgcmVt'
    'b3ZlIGV4aXN0aW5nIGNvbm50cmFjayB0cmFuc2xhdGlvbnMuCiAgICBBIHJ1bm5pbmcgcmVzb2x2ZXIgY2FuIHJldXNlIGl0'
    'cyBVRFAgc29ja2V0IGluZGVmaW5pdGVseSBhZnRlciBhIFZQTiBzd2l0Y2guCiAgICAiIiIKICAgIGZpbHRlcnMgPSAoWyct'
    'LXJlcGx5LXBvcnQtc3JjJywnMTg1NTMnXSBpZiBwcmV2aW91c192cG4gZWxzZQogICAgICAgICAgICAgICBbJy0tcmVwbHkt'
    'cG9ydC1zcmMnLCc1MycsJy0tZHN0LW5hdCcsJzEuMS4xLjEnXSkKICAgIGZvciBwcm90b2NvbCBpbiAoJ3VkcCcsJ3RjcCcp'
    'OgogICAgICAgIHJlc3VsdCA9IGNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcsJy1wJyxwcm90b2NvbCwK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAnLS1kcG9ydCcsJzUzJywqZmlsdGVyc10sIGNoZWNrPUZhbHNlLAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZW52PXsqKm9zLmVudmlyb24sJ0xDX0FMTCc6J0MnfSkKICAgICAgICBlbXB0eSA9IHJlc3Vs'
    'dC5yZXR1cm5jb2RlID09IDEgYW5kICcwIGZsb3cgZW50cmllcyBoYXZlIGJlZW4gZGVsZXRlZCcgaW4gcmVzdWx0LnN0ZGVy'
    'cgogICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2RlICE9IDAgYW5kIG5vdCBlbXB0eToKICAgICAgICAgICAgcmFpc2UgUnVu'
    'dGltZUVycm9yKCdkbnNfdHJhbnNpdGlvbl9jbGVhbnVwX2ZhaWxlZCcpCgoKZGVmIGZ1bGxfZ3VhcmRfYWN0aXZlKCk6CiAg'
    'ICByZXR1cm4gY29tbWFuZChbJ25mdCcsJ2xpc3QnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKS5y'
    'ZXR1cm5jb2RlID09IDAKCgpkZWYgZnVsbF9maXJld2FsbCgpOgogICAgIyBObyBwcm9jZXNzLCBESVJFQ1QgbGlzdCwgZXN0'
    'YWJsaXNoZWQgc29ja2V0IG9yIElQdjYgZXhjZXB0aW9uIGNhbiBieXBhc3MgdGhpcyBndWFyZC4KICAgICMgS2VlcCBsb2Nh'
    'bCBzdHViIEROUyBvbiBsb29wYmFjay4gRE5BVCBvZiAxMjcvOCBvbnRvIGEgdmV0aCBmYWlscyBMaW51eCdzCiAgICAjIGxv'
    'b3BiYWNrIHJvdXRlIGNoZWNrczsgdXBzdHJlYW0gcmVzb2x2ZXIgdHJhZmZpYyBzdGlsbCBvYmV5cyB0aGUgZnVsbCBndWFy'
    'ZC4KICAgIHJldHVybiBmJycndGFibGUgaW5ldCB7RlVMTF9HVUFSRH0ge3sKIGNoYWluIGRucyB7eyB0eXBlIG5hdCBob29r'
    'IG91dHB1dCBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybgogIGlw'
    'IGRhZGRyIHt7IDEuMS4xLjEsIDkuOS45LjkgfX0gcmV0dXJuCiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHByb3RvIHt7'
    'IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUzIGRuYXQgaXAgdG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBlIG5h'
    'dCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2NCBv'
    'aWZuYW1lICJ7RlVMTF9IT1NUfSIgc25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKIH19CiBjaGFpbiBvdXRwdXQge3sgdHlwZSBm'
    'aWx0ZXIgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0CiAgbWV0'
    'YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4yNTUuMjU1LjI1NSB1'
    'ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBm'
    'b3J3YXJkIHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBp'
    'cCBkYWRkciB7eyB7U0VSVkVSfSwge1NFUlZFUl9MQU59IH19IHVkcCBkcG9ydCB7ezUwMCw0NTAwfX0gYWNjZXB0CiAgaWlm'
    'bmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSwge1NFUlZFUl9MQU59IH19IHRj'
    'cCBkcG9ydCA4NDQzIGFjY2VwdAogIG9pZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge0NMSUVOVH0gY3Qgc3RhdGUgZXN0YWJs'
    'aXNoZWQscmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAg'
    'bWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie0ZVTExfSE9TVH0iIGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNj'
    'ZXB0CiB9fQp9fScnJwoKCmRlZiB2aXJ0dWFsX2lwKCk6CiAgICBkYXRhID0ganNvbi5sb2FkcyhpbnNpZGUoWydpcCcsJy1q'
    'JywnLTQnLCdhZGRyJ10pLnN0ZG91dCkKICAgIGlwcyA9IFthWydsb2NhbCddIGZvciBsaW5rIGluIGRhdGEgZm9yIGEgaW4g'
    'bGluay5nZXQoJ2FkZHJfaW5mbycsIFtdKQogICAgICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKGFbJ2xvY2FsJ10p'
    'IGluIGlwYWRkcmVzcy5pcF9uZXR3b3JrKCcxMC43Ny4wLjAvMjQnKV0KICAgIGlmIGxlbihpcHMpICE9IDE6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCd2aXJ0dWFsX2lwX21pc3NpbmcnKQogICAgcmV0dXJuIGlwc1swXQoKCmRlZiBmdWxsX25h'
    'bWVzcGFjZShhZGRyZXNzKToKICAgIHZpcCA9IHZpcnR1YWxfaXAoKQogICAgaWYgbm90IFBhdGgoJy9zeXMvY2xhc3MvbmV0'
    'LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnYWRkJyxGVUxMX0hPU1QsJ3R5'
    'cGUnLCd2ZXRoJywncGVlcicsJ25hbWUnLEZVTExfUEVFUl0pCiAgICAgICAgY29tbWFuZChbJ2lwJywnbGluaycsJ3NldCcs'
    'RlVMTF9QRUVSLCduZXRucycsTlNdKQogICAgY29tbWFuZChbJ2lwJywnYWRkcicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjEv'
    'MzAnLCdkZXYnLEZVTExfSE9TVF0pCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX0hPU1QsJ210dScsJzEy'
    'ODAnLCd1cCddKQogICAgaW5zaWRlKFsnaXAnLCdhZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcuMi8zMCcsJ2RldicsRlVM'
    'TF9QRUVSXSkKICAgIGluc2lkZShbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9QRUVSLCdtdHUnLCcxMjgwJywndXAnXSkKICAg'
    'IGluc2lkZShbJ3N5c2N0bCcsJy1xdycsJ25ldC5pcHY0LmNvbmYuYWxsLmZvcndhcmRpbmc9MScsJ25ldC5pcHY0LmNvbmYu'
    'YWxsLnJwX2ZpbHRlcj0wJ10pCiAgICAjIFN0cm9uZ1N3YW4ncyBjYXRjaC1hbGwgcm91dGUgbXVzdCBub3QgY2FwdHVyZSBy'
    'ZXBsaWVzIHRvIHRoZSBob3N0LWZhY2luZyBpbnRlcmZhY2UuCiAgICBpbnNpZGUoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlv'
    'cml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBpbnNpZGUoWydpcCcs'
    'J3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10pCiAgICBkZWxldGlv'
    'bnMgPSAnJwogICAgZm9yIGZhbWlseSx0YWJsZSBpbiBbKCdpbmV0JywnZXZuX2Z1bGxfZm9yd2FyZCcpLCgnbmV0ZGV2Jywn'
    'ZXZuX2Z1bGxfd2lyZScpXToKICAgICAgICBpZiBpbnNpZGUoWyduZnQnLCdsaXN0JywndGFibGUnLGZhbWlseSx0YWJsZV0s'
    'Y2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICAgICAgZGVsZXRpb25zICs9IGYnZGVsZXRlIHRhYmxlIHtm'
    'YW1pbHl9IHt0YWJsZX1cbicKICAgIHJ1bGVzID0gZGVsZXRpb25zICsgZicnJ3RhYmxlIGluZXQgZXZuX2Z1bGxfZm9yd2Fy'
    'ZCB7ewogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTU7IHBvbGljeSBkcm9w'
    'OwogIGlpZm5hbWUgIntGVUxMX1BFRVJ9IiBvaWZuYW1lICJ7UEVFUn0iIGlwIHNhZGRyIDE3Mi4yOS4yNDcuMSBhY2NlcHQK'
    'ICBpaWZuYW1lICJ7UEVFUn0iIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBkYWRkciAxNzIuMjkuMjQ3LjEgaXBzZWMgaW4g'
    'cmVxaWQge1JFUUlEfSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KIGNoYWluIG5hdCB7eyB0eXBl'
    'IG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBzYWRkciAxNzIuMjku'
    'MjQ3LjEgb2lmbmFtZSAie1BFRVJ9IiBzbmF0IGlwIHRvIHt2aXB9CiB9fQp9fQp0YWJsZSBuZXRkZXYgZXZuX2Z1bGxfd2ly'
    'ZSB7ewogY2hhaW4gZWdyZXNzIHt7IHR5cGUgZmlsdGVyIGhvb2sgZWdyZXNzIGRldmljZSAie1BFRVJ9IiBwcmlvcml0eSAw'
    'OyBwb2xpY3kgZHJvcDsKICBldGhlciB0eXBlIGFycCBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdWRwIGRwb3J0IHt7'
    'NTAwLDQ1MDB9fSBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiB9fQp9fScnJwog'
    'ICAgaW5zaWRlKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywnLWYnLCctJ10s'
    'ZGF0YT1ydWxlcykKICAgICMgUmVwbGFjZSB0aGUgb3JpZ2luYWwgbGFiIGZvcndhcmQgZHJvcDsgaG9zdCBpbmdyZXNzIHJl'
    'bWFpbnMgY29uc3RyYWluZWQgYnkgZnVsbF9mb3J3YXJkLgogICAgaW5zaWRlKFsnbmZ0JywnZmx1c2gnLCdjaGFpbicsJ2lu'
    'ZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdmb3J3YXJkJ10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxlJywnaW5l'
    'dCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21ldGEnLCduZnByb3RvJywn'
    'aXB2NCcsJ2FjY2VwdCddKQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3Vh'
    'cmQnLCdmb3J3YXJkJywnb2lmbmFtZScsRlVMTF9QRUVSLCdpcHNlYycsJ2luJywncmVxaWQnLHN0cihSRVFJRCksJ2N0Jywn'
    'c3RhdGUnLCdlc3RhYmxpc2hlZCxyZWxhdGVkJywnYWNjZXB0J10pCgoKZGVmIGVncmVzc19oZWFsdGgoKToKICAgIGZvciB1'
    'cmwsZXhwZWN0ZWQgaW4gWygnaHR0cHM6Ly93d3cuY2xvdWRmbGFyZS5jb20vY2RuLWNnaS90cmFjZScsJ2lwPTM4LjE4MC4x'
    'NjQuNjcnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICgnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJywnMzguMTgwLjE2NC42'
    'NycpXToKICAgICAgICByZXN1bHQgPSBpbnNpZGUoWydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywnLS1z'
    'aWxlbnQnLCctLXNob3ctZXJyb3InLAogICAgICAgICAgICAgICAgICAgICAgICAgJy0tY29ubmVjdC10aW1lb3V0JywnMycs'
    'Jy0tbWF4LXRpbWUnLCc1Jyx1cmxdLHRpbWVvdXQ9NyxjaGVjaz1GYWxzZSkKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29k'
    'ZSA9PSAwIGFuZCBleHBlY3RlZCBpbiByZXN1bHQuc3Rkb3V0LnNwbGl0bGluZXMoKToKICAgICAgICAgICAgcmV0dXJuIFRy'
    'dWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiByZXRpcmVfcHJldmlvdXNfY29ubmVjdGlvbnMoYWRkcmVzc2VzKToKICAgICMg'
    'QSBjaGFuZ2VkIFZQTiBlZ3Jlc3MgY2Fubm90IHByZXNlcnZlIG9sZCBUQ1Agc2Vzc2lvbnMuIFdha2UgYXBwbGljYXRpb25z'
    'IG5vdwogICAgIyBpbnN0ZWFkIG9mIGxlYXZpbmcgc3RhbGUgc291cmNlIGFkZHJlc3NlcyBhbmQgVURQIE5BVCB1bnRpbCB0'
    'aGVpciB0aW1lb3V0cy4KICAgIGZvciBhZGRyZXNzIGluIGFkZHJlc3NlczoKICAgICAgICBjb21tYW5kKFsnc3MnLCctSycs'
    'J3NyYycsYWRkcmVzc10sY2hlY2s9RmFsc2UpCiAgICAgICAgZm9yIHByb3RvY29sIGluICgndGNwJywndWRwJyk6CiAgICAg'
    'ICAgICAgIGNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcsJy1wJyxwcm90b2NvbCwnLXMnLGFkZHJlc3Nd'
    'LGNoZWNrPUZhbHNlKQoKCmRlZiBzeXN0ZW1fZG5zX2hlYWx0aChyZXNvbHZfY29uZj1QYXRoKCcvZXRjL3Jlc29sdi5jb25m'
    'JykpOgogICAgIyBnZXRhZGRyaW5mby9jdXJsIG1heSB1c2UgbnNzLXJlc29sdmUgb3ZlciBhIFVuaXggc29ja2V0IGFuZCBt'
    'aXNzIGEgYnJva2VuCiAgICAjIFVEUCBzdHViIHVzZWQgYnkgb3RoZXIgYXBwbGljYXRpb25zLiBFeGVyY2lzZSByZXNvbHYu'
    'Y29uZiBpbmRlcGVuZGVudGx5LgogICAgc2VydmVycyA9IFtsaW5lLnNwbGl0KClbMV0gZm9yIGxpbmUgaW4gcmVzb2x2X2Nv'
    'bmYucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpCiAgICAgICAgICAgICAgIGlmIGxpbmUuc3BsaXQoKVs6MV0gPT0gWyduYW1l'
    'c2VydmVyJ10gYW5kIGxlbihsaW5lLnNwbGl0KCkpID49IDJdWzozXQogICAgZm9yIHNlcnZlciBpbiBzZXJ2ZXJzOgogICAg'
    'ICAgIHRyeToKICAgICAgICAgICAgZmFtaWx5ID0gc29ja2V0LkFGX0lORVQ2IGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHNl'
    'cnZlcikudmVyc2lvbiA9PSA2IGVsc2Ugc29ja2V0LkFGX0lORVQKICAgICAgICAgICAgdHJhbnNhY3Rpb24gPSBzZWNyZXRz'
    'LnRva2VuX2J5dGVzKDIpCiAgICAgICAgICAgIHF1ZXJ5ID0gdHJhbnNhY3Rpb24rYidceDAxXHgwMFx4MDBceDAxXHgwMFx4'
    'MDBceDAwXHgwMFx4MDBceDAwJwogICAgICAgICAgICBxdWVyeSArPSBiJ1x4MDNhcGlceDA1aXBpZnlceDAzb3JnXHgwMFx4'
    'MDBceDAxXHgwMFx4MDEnCiAgICAgICAgICAgIHdpdGggc29ja2V0LnNvY2tldChmYW1pbHksIHNvY2tldC5TT0NLX0RHUkFN'
    'KSBhcyByZXNvbHZlcjoKICAgICAgICAgICAgICAgIHJlc29sdmVyLnNldHRpbWVvdXQoMikKICAgICAgICAgICAgICAgIHJl'
    'c29sdmVyLmNvbm5lY3QoKHNlcnZlciwgNTMpKQogICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2VuZChxdWVyeSkKICAgICAg'
    'ICAgICAgICAgIGFuc3dlciA9IHJlc29sdmVyLnJlY3YoNDA5NikKICAgICAgICAgICAgaWYgKGxlbihhbnN3ZXIpID49IDEy'
    'IGFuZCBhbnN3ZXJbOjJdID09IHRyYW5zYWN0aW9uIGFuZAogICAgICAgICAgICAgICAgICAgIGFuc3dlclsyXSAmIDB4ODAg'
    'YW5kIGFuc3dlclszXSAmIDE1ID09IDAgYW5kCiAgICAgICAgICAgICAgICAgICAgaW50LmZyb21fYnl0ZXMoYW5zd2VyWzY6'
    'OF0sICdiaWcnKSA+IDApOgogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZh'
    'bHVlRXJyb3IpOgogICAgICAgICAgICBjb250aW51ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIGFjdGl2YXRlX2Z1bGwoYWRk'
    'cmVzcyk6CiAgICBvbGRfYWRkcmVzc2VzID0gW2FbJ2xvY2FsJ10gZm9yIGxpbmsgaW4ganNvbi5sb2Fkcyhjb21tYW5kKFsn'
    'aXAnLCctaicsJy00JywnYWRkcicsJ3Nob3cnLCdzY29wZScsJ2dsb2JhbCddKS5zdGRvdXQpCiAgICAgICAgICAgICAgICAg'
    'ICAgIGlmIGxpbmsuZ2V0KCdpZm5hbWUnKSBub3QgaW4gKEhPU1QsRlVMTF9IT1NUKQogICAgICAgICAgICAgICAgICAgICBm'
    'b3IgYSBpbiBsaW5rLmdldCgnYWRkcl9pbmZvJyxbXSkgaWYgYS5nZXQoJ3Njb3BlJykgPT0gJ2dsb2JhbCddCiAgICBpZiBu'
    'b3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAgIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5l'
    'eGlzdHMoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX2ludGVyZmFjZV9jb2xsaXNpb24nKQogICAg'
    'ICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rk'
    'b3V0LnN0cmlwKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF90YWJsZV9jb2xsaXNpb24nKQogICAg'
    'ICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0'
    'ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2FkbWluX3RhYmxlX2NvbGxpc2lvbicpCiAg'
    'ICAgICAgaWYgYW55KHIuZ2V0KCdwcmlvcml0eScpIGluICg3OSw4MCkgZm9yIHIgaW4ganNvbi5sb2Fkcyhjb21tYW5kKFsn'
    'aXAnLCctaicsJy00JywncnVsZSddKS5zdGRvdXQpKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3J1'
    'bGVfY29sbGlzaW9uJykKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyh7J2FjdGl2ZSc6RmFsc2V9KSkK'
    'ICAgIGZ1bGxfbmFtZXNwYWNlKGFkZHJlc3MpCiAgICAjIFZhbGlkYXRlIHRoZSBlZ3Jlc3MgZmlsdGVyIGJlZm9yZSBpbnRl'
    'cnJ1cHRpbmcgdGhlIHByZXZpb3VzIFZQTi4KICAgIGlmIG5vdCBlZ3Jlc3NfaGVhbHRoKCk6CiAgICAgICAgcmFpc2UgUnVu'
    'dGltZUVycm9yKCdlc3RvbmlhX2VncmVzc19mYWlsZWQnKQogICAgcnVsZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgICMgUmVw'
    'YWlyIG1heSBpbmhlcml0IGEgZ3VhcmQgZnJvbSBhbiBvbGRlciB2ZXJzaW9uLiBSZXBsYWNlIG91ciB0YWJsZSBpbgogICAg'
    'IyBvbmUgbmZ0IHRyYW5zYWN0aW9uLCBzbyBmaXhlcyBhcHBseSB3aXRob3V0IG9wZW5pbmcgYW4gdW5ndWFyZGVkIHdpbmRv'
    'dy4KICAgIHJlcGxhY2VtZW50ID0gKCdkZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJyBpZiBmdWxsX2d1YXJk'
    'X2FjdGl2ZSgpIGVsc2UgJycpK3J1bGVzCiAgICBjb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2Vt'
    'ZW50KQogICAgY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICAjIEd1YXJkIHBlcnNpc3Rl'
    'bmNlIHByZWNlZGVzIHN3aXRjaGluZy4gQ2xlYW51cCBhZnRlciBhIGNyYXNoIG5ldmVyIG9wZW5zIHRoZSBJbnRlcm5ldC4K'
    'ICAgIGd1YXJkX3VuaXQgPSAnJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZXhwZXJpbWVudGFsIGZ1bGwtZGV2aWNl'
    'IGtpbGwgc3dpdGNoCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9jYWwtZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3Jr'
    'LXByZS50YXJnZXQKW1NlcnZpY2VdClR5cGU9b25lc2hvdApSZW1haW5BZnRlckV4aXQ9eWVzCkV4ZWNTdGFydD0vdXNyL3Ni'
    'aW4vbmZ0IC1mIC9ldGMvdnBuLW1hbmFnZXIvc3RhcmZpdmUtdHVubmVsL2Z1bGwtZ3VhcmQubmZ0CltJbnN0YWxsXQpXYW50'
    'ZWRCeT1tdWx0aS11c2VyLnRhcmdldAonJycucmVwbGFjZSgnL3Vzci9zYmluL25mdCcsIHNodXRpbC53aGljaCgnbmZ0Jykp'
    'CiAgICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5mdCcscnVsZXMpCiAgICB3cml0ZShQYXRoKCcvZXRjL3N5c3RlbWQvc3lz'
    'dGVtL2V2Z2VuaXVtLXN0YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZScpLGd1YXJkX3VuaXQpCiAgICBjb21tYW5kKFsnc3lz'
    'dGVtY3RsJywnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2VuYWJsZScsJ2V2Z2VuaXVtLXN0'
    'YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZSddKQogICAgIyBUaGlzIGNvbW1hbmQgc3RvcHMgb25seSB0aGlzIG1hbmFnZXIn'
    'cyBwcmV2aW91cyBYcmF5IG1vZGUgYW5kIHJlbW92ZXMgaXRzIGd1YXJkLgogICAgY29tbWFuZChbJy91c3IvbG9jYWwvc2Jp'
    'bi92cG5jdGwnLCdpbnRlcm5hbC1zdGFyZml2ZS1wYXVzZS1tYWluJ10sdGltZW91dD00MCkKICAgIGNvbW1hbmQoWydpcCcs'
    'J3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywnZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLEZVTExf'
    'VEFCTEVdKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ3ZpYScsJzE3Mi4yOS4yNDcu'
    'MicsJ2RldicsRlVMTF9IT1NULCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydpcCcs'
    'J3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBy'
    'dWxlIGluIChbJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sCiAgICAgICAgICAg'
    'ICAgICAgWydwcmlvcml0eScsJzc5JywnaWlmJyxGVUxMX0hPU1QsJ2xvb2t1cCcsJ21haW4nXSk6CiAgICAgICAgY29tbWFu'
    'ZChbJ2lwJywncnVsZScsJ2RlbCcsKnJ1bGVdLGNoZWNrPUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdh'
    'ZGQnLCpydWxlXSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxM'
    'X1RBQkxFXSkKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBpZiBzaHV0aWwud2hp'
    'Y2goJ3Jlc29sdmVjdGwnKSBhbmQgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsJy0tcXVpZXQnLCdzeXN0ZW1k'
    'LXJlc29sdmVkJ10sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICBkYXRhWydkbnNfbW9kZSddPSdyZXNv'
    'bHZlZF9saW5rJwogICAgICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgICAgIGNvbW1hbmQo'
    'WydyZXNvbHZlY3RsJywnZG5zJyxGVUxMX0hPU1QsJzEuMS4xLjEnLCc5LjkuOS45J10pCiAgICAgICAgY29tbWFuZChbJ3Jl'
    'c29sdmVjdGwnLCdkb21haW4nLEZVTExfSE9TVCwnfi4nXSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RlZmF1'
    'bHQtcm91dGUnLEZVTExfSE9TVCwneWVzJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdmbHVzaC1jYWNoZXMn'
    'XSxjaGVjaz1GYWxzZSkKICAgIGVsc2U6CiAgICAgICAgaWYgJ2Ruc19iYWNrdXAnIG5vdCBpbiBkYXRhOgogICAgICAgICAg'
    'ICBkYXRhWydkbnNfYmFja3VwJ109UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpLnJlYWRfdGV4dCgpCiAgICAgICAgICAgIHdy'
    'aXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgICAgIFBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKS53cml0'
    'ZV90ZXh0KCduYW1lc2VydmVyIDEuMS4xLjFcbm5hbWVzZXJ2ZXIgOS45LjkuOVxub3B0aW9ucyB0aW1lb3V0OjIgYXR0ZW1w'
    'dHM6MlxuJykKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIHJldGlyZV9wcmV2aW91c19j'
    'b25uZWN0aW9ucyhvbGRfYWRkcmVzc2VzKQogICAgaWYgbm90IHN5c3RlbV9kbnNfaGVhbHRoKCk6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICAjIFRlc3QgdGhlIGFjdHVhbCBob3N0IHBhdGggYXMgd2Vs'
    'bCBhcyBuYW1lc3BhY2UgcHJvYmVzIGJlZm9yZSBhbm5vdW5jaW5nIGNvbm5lY3RlZC4KICAgIGNoZWNrID0gY29tbWFuZChb'
    'J2N1cmwnLCctNCcsJy0tbm9wcm94eScsJyonLCctLWZhaWwnLCctLXNpbGVudCcsJy0tbWF4LXRpbWUnLCcxMCcsJ2h0dHBz'
    'Oi8vYXBpLmlwaWZ5Lm9yZyddLHRpbWVvdXQ9MTIpCiAgICBpZiBjaGVjay5zdGRvdXQuc3RyaXAoKSAhPSAnMzguMTgwLjE2'
    'NC42Nyc6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdob3N0X2VncmVzc19mYWlsZWQnKQogICAgZGF0YVsnYWN0aXZl'
    'J109VHJ1ZQogICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCgoKZGVmIGNsZWFudXBfZnVsbChyZWxl'
    'YXNlPUZhbHNlKToKICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuCiAgICBkYXRhPWpz'
    'b24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdkZWwnLCdkZWZh'
    'dWx0JywnbWV0cmljJywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCds'
    'aW5rJywnZGVsJyxGVUxMX0hPU1RdLGNoZWNrPUZhbHNlKQogICAgIyBPbiBmYWlsdXJlOiByZXRhaW4gcm91dGluZywgRE5T'
    'IGFuZCB0aGUgcGVyc2lzdGVudCBndWFyZCB1bnRpbCBleHBsaWNpdCBkaXNjb25uZWN0LgogICAgaWYgbm90IHJlbGVhc2U6'
    'CiAgICAgICAgcmV0dXJuCiAgICBpZiAnZG5zX2JhY2t1cCcgaW4gZGF0YToKICAgICAgICBQYXRoKCcvZXRjL3Jlc29sdi5j'
    'b25mJykud3JpdGVfdGV4dChkYXRhWydkbnNfYmFja3VwJ10pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJp'
    'b3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywn'
    'ZGVsJywncHJpb3JpdHknLCc3OScsJ3RvJyxDTElFTlQrJy8zMicsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICAg'
    'IGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywnaWlmJyxGVUxMX0hPU1QsJ2xvb2t1cCcsJ21h'
    'aW4nXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsRlVMTF9UQUJMRV0s'
    'Y2hlY2s9RmFsc2UpCiAgICBmb3Igc2VydmVyIGluIChTRVJWRVJfTEFOLCAnMzguMTgwLjE2NC42NycpOgogICAgICAgIGNv'
    'bW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLHNlcnZlciwnaXBwcm90bycsJ3RjcCcsJ2Rw'
    'b3J0JywnMjInLCdsb29rdXAnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdk'
    'aXNhYmxlJywnLS1ub3cnLCdldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnXSxjaGVjaz1GYWxzZSkKICAg'
    'IGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKQogICAgY2xl'
    'YXJfZG5zX21hcHBpbmdzKCkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsQURNSU5fVEFCTEVd'
    'LGNoZWNrPUZhbHNlKQogICAgZnVsbF9zdGF0ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2ZsdXNo'
    'LWNhY2hlcyddLGNoZWNrPUZhbHNlKSBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNlIE5vbmUKCgpkZWYgY29t'
    'bWFuZChhcmdzLCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAgIGNwID0gc3VicHJv'
    'Y2Vzcy5ydW4oW3N0cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0dXJlX291dHB1dD1U'
    'cnVlLAogICAgICAgICAgICAgICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAg'
    'aWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4gYSBDU1IgcGF0aDsg'
    'ZG8gbm90IHByb3BhZ2F0ZSBwcm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'J2NvbW1hbmRfZmFpbGVkJykKICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJu'
    'IGNvbW1hbmQoWydpcCcsICduZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVmIHdyaXRlKHBhdGgs'
    'IHZhbHVlKToKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkK'
    'ICAgIHRlbXBvcmFyeSA9IHBhdGgud2l0aF9zdWZmaXgoJy5uZXcnKQogICAgZmQgPSBvcy5vcGVuKHRlbXBvcmFyeSwgb3Mu'
    'T19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIDBvNjAwKQogICAgd2l0aCBvcy5m'
    'ZG9wZW4oZmQsICd3JykgYXMgc3RyZWFtOgogICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgIHRlbXBvcmFyeS5yZXBs'
    'YWNlKHBhdGgpCgoKZGVmIHNhdmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoU1RBVEUucmVhZF90'
    'ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoKCmRlZiBzdGFnZShw'
    'aGFzZSwgbWVzc2FnZSwgcHJvZ3Jlc3MsICoqZmllbGRzKToKICAgIGRhdGEgPSB7KipzYXZlZCgpLCAncGhhc2UnOiBwaGFz'
    'ZSwgJ21lc3NhZ2UnOiBtZXNzYWdlLCAncHJvZ3Jlc3MnOiBwcm9ncmVzcywKICAgICAgICAgICAgJ3VwZGF0ZWQnOiBpbnQo'
    'dGltZS50aW1lKCkpLCAnaGVhcnRiZWF0JzogdGltZS5tb25vdG9uaWMoKSwgKipmaWVsZHN9CiAgICB3cml0ZShTVEFURSwg'
    'anNvbi5kdW1wcyhkYXRhLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQoKCmRlZiBzdGF0dXMoKToKICAgIGRhdGEgPSBzYXZlZCgp'
    'CiAgICBydW5uaW5nID0gY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcsIFVOSVRdLCBjaGVj'
    'az1GYWxzZSwgdGltZW91dD0yKS5yZXR1cm5jb2RlID09IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScpID09ICdjb25uZWN0'
    'ZWQnIGFuZCAobm90IHJ1bm5pbmcgb3IgdGltZS5tb25vdG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0JywgMCkgPiA0NSk6'
    'CiAgICAgICAgZGF0YS51cGRhdGUocGhhc2U9J2ludGVycnVwdGVkJywgbWVzc2FnZT0n0KHQvtC10LTQuNC90LXQvdC40LUg'
    '0L7RgdGC0LDQvdC+0LLQuNC70L7RgdGMLiDQn9GA0L7QstC10YDRjNGC0LUg0YHQvtGB0YLQvtGP0L3QuNC1INC30LDRidC4'
    '0YLRiyDQuCDQvdCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nLCBhY3RpdmU9RmFsc2UpCiAgICBwdWJsaWMg'
    'PSB7a2V5OiBkYXRhW2tleV0gZm9yIGtleSBpbiAoJ3BoYXNlJywgJ21lc3NhZ2UnLCAncHJvZ3Jlc3MnLCAnYWN0aXZlJywg'
    'J3VwZGF0ZWQnLCAnbWV0cmljcycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnc2NvcGUnLCAn'
    'c2luY2UnLCAncmV0cnknKSBpZiBrZXkgaW4gZGF0YX0KICAgIHRva2VuX2luZm8gPSB0b2tlbl9zdGF0dXMoKQogICAgcmV0'
    'dXJuIHsncGhhc2UnOiAnb2ZmJywgJ21lc3NhZ2UnOiAoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvS4g0J3QsNC20LzQ'
    'uNGC0LUgwqvQn9C+0LTQutC70Y7Rh9C40YLRjMK7LicgaWYgdG9rZW5faW5mb1snaGFzX3Rva2VuJ10gZWxzZSAn0JLQstC1'
    '0LTQuNGC0LUg0Lgg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCwLicpLAogICAgICAg'
    'ICAgICAncHJvZ3Jlc3MnOiAwLCAnYWN0aXZlJzogRmFsc2UsICoqcHVibGljLCAncnVubmluZyc6IHJ1bm5pbmcsCiAgICAg'
    'ICAgICAgICoqdG9rZW5faW5mbywgJ2lzb2xhdGVkJzogRmFsc2UsICdmdWxsX2RldmljZSc6IFRydWUsICdndWFyZCc6IGZ1'
    'bGxfZ3VhcmRfYWN0aXZlKCksICdwcm90b2NvbCc6ICdJS0V2MiDihpIg0K3RgdGC0L7QvdC40Y8nfQoKCkBjb250ZXh0bGli'
    'LmNvbnRleHRtYW5hZ2VyCmRlZiBuYW1lc3BhY2UoKToKICAgIGJlZm9yZSA9IG9zLm9wZW4oJy9wcm9jL3NlbGYvbnMvbmV0'
    'Jywgb3MuT19SRE9OTFkpCiAgICB0YXJnZXQgPSBvcy5vcGVuKCcvcnVuL25ldG5zLycrTlMsIG9zLk9fUkRPTkxZKQogICAg'
    'dHJ5OgogICAgICAgIG9zLnNldG5zKHRhcmdldCwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIHlpZWxkCiAgICBmaW5hbGx5'
    'OgogICAgICAgIG9zLnNldG5zKGJlZm9yZSwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIG9zLmNsb3NlKHRhcmdldCkKICAg'
    'ICAgICBvcy5jbG9zZShiZWZvcmUpCgoKZGVmIHBoeXNpY2FsX3JvdXRlKCk6CiAgICByb3V0ZXMgPSBqc29uLmxvYWRzKGNv'
    'bW1hbmQoWydpcCcsICctaicsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ21haW4nLCAnZGVmYXVsdCddKS5z'
    'dGRvdXQpCiAgICBjYW5kaWRhdGVzID0gW3IgZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdnYXRld2F5JykgYW5kIHIuZ2V0'
    'KCdkZXYnKSBhbmQKICAgICAgICAgICAgICAgICAgbm90IHJbJ2RldiddLnN0YXJ0c3dpdGgoKCd0dW4nLCAneHJheScsICd3'
    'ZycsICdldm4tJykpXQogICAgaWYgbm90IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdub19waHlz'
    'aWNhbF9yb3V0ZScpCiAgICByb3V0ZSA9IG1pbihjYW5kaWRhdGVzLCBrZXk9bGFtYmRhIHI6IHIuZ2V0KCdtZXRyaWMnLCAw'
    'KSkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidbQS1aYS16MC05Xy46LV17MSwxNX0nLCByb3V0ZVsnZGV2J10pOgogICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9pbnRlcmZhY2UnKQogICAgaXBhZGRyZXNzLklQdjRBZGRyZXNzKHJv'
    'dXRlWydnYXRld2F5J10pCiAgICByZXR1cm4gcm91dGUKCgpkZWYgaG9zdF9ydWxlcyhpZmFjZSwgcHJldmlvdXNfZm9yd2Fy'
    'ZD1UcnVlKToKICAgICMgU2NvcGUgZXZlcnkgbmV3IGZvcndhcmRpbmcvTkFUIHJ1bGUgdG8gb3VyIG9uZSBpbnRlcmZhY2Ug'
    'YW5kIHR3byBzZXJ2ZXIgYWRkcmVzc2VzLgogICAgcHJlc2VydmVfZGlzYWJsZWQgPSAnJyBpZiBwcmV2aW91c19mb3J3YXJk'
    'IGVsc2UgJyAgbWV0YSBuZnByb3RvIGlwdjQgZHJvcCcKICAgIHJldHVybiBmJycndGFibGUgaW5ldCB7TkZUfSB7ewogY2hh'
    'aW4gZm9yd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtMjA7IHBvbGljeSBhY2NlcHQ7CiAg'
    'aWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSwge1NFUlZFUl9MQU59IH19IHVkcCBkcG9ydCB7eyA1MDAs'
    'IDQ1MDAgfX0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSwge1NFUlZFUl9MQU59IH19'
    'IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgZHJvcAogIG9pZm5hbWUgIntIT1NUfSIgaXAgc2Fk'
    'ZHIge3sge1NFUlZFUn0sIHtTRVJWRVJfTEFOfSB9fSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG9p'
    'Zm5hbWUgIntIT1NUfSIgZHJvcAp7cHJlc2VydmVfZGlzYWJsZWR9CiB9fQogY2hhaW4gbmF0IHt7CiAgdHlwZSBuYXQgaG9v'
    'ayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2FkZHIge0NMSUVOVH0gb2lmbmFt'
    'ZSAie2lmYWNlfSIgbWFzcXVlcmFkZQogfX0KfX0nJycKCgpkZWYgc2V0dXBfbmV0d29yaygpOgogICAgcm91dGUgPSBwaHlz'
    'aWNhbF9yb3V0ZSgpCiAgICAjIFJlZnVzZSBuYW1lL2FkZHJlc3MgY29sbGlzaW9ucyByYXRoZXIgdGhhbiByZXB1cnBvc2lu'
    'ZyBhbm90aGVyIGFwcGxpY2F0aW9uJ3MgcmVzb3VyY2VzLgogICAgaWYgUGF0aCgnL3J1bi9uZXRucy8nK05TKS5leGlzdHMo'
    'KSBvciBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0hPU1QpLmV4aXN0cygpIG9yIChQYXRoKCcvZXRjL25ldG5zJykvTlMpLmV4'
    'aXN0cygpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF9uYW1lc3BhY2VfZXhpc3RzJykKICAgIGlmIGNvbW1h'
    'bmQoWydpcCcsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKS5zdGRv'
    'dXQuc3RyaXAoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfdGFibGVfaW5fdXNlJykKICAgIGlmIGFueShO'
    'RVRXT1JLIGluIGxpbmUgZm9yIGxpbmUgaW4gY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUn'
    'LCAnYWxsJ10pLnN0ZG91dC5zcGxpdGxpbmVzKCkpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF9uZXR3b3Jr'
    'X2luX3VzZScpCiAgICBvbGRfZm9yd2FyZCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykucmVhZF90'
    'ZXh0KCkuc3RyaXAoKQogICAgIyBSZWNvcmQgb3duZXJzaGlwIGJlZm9yZSBjcmVhdGluZyBhbnl0aGluZzogY2xlYW51cCBp'
    'cyB2YWxpZCBhZnRlciBldmVyeSBwYXJ0aWFsIHN0ZXAuCiAgICB1cGxpbmsgPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQv'
    'Y29uZicpL3JvdXRlWydkZXYnXS8nZm9yd2FyZGluZycKICAgIHdyaXRlKFJPT1QvJ25ldHdvcmsuanNvbicsIGpzb24uZHVt'
    'cHMoeydmb3J3YXJkJzogb2xkX2ZvcndhcmQsICdpbnRlcmZhY2UnOiByb3V0ZVsnZGV2J10sICd1cGxpbmtfZm9yd2FyZCc6'
    'IHVwbGluay5yZWFkX3RleHQoKS5zdHJpcCgpfSkpCiAgICBjb21tYW5kKFsnaXAnLCAnbmV0bnMnLCAnYWRkJywgTlNdKQog'
    'ICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicsICduYW1lc2VydmVyIDEuMS4xLjFcbm5hbWVz'
    'ZXJ2ZXIgOS45LjkuOVxub3B0aW9ucyB0aW1lb3V0OjIgYXR0ZW1wdHM6MlxuJykKICAgICMgbnNzLXJlc29sdmUgdGFsa3Mg'
    'dG8gdGhlIGhvc3QgZGFlbW9uIG92ZXIgYSBVbml4IHNvY2tldCBldmVuIGluc2lkZSBuZXRucy4KICAgIG5zcz1QYXRoKCcv'
    'ZXRjL25zc3dpdGNoLmNvbmYnKS5yZWFkX3RleHQoKQogICAgbnNzPXJlLnN1YihyJ15ob3N0czouKiQnLCAnaG9zdHM6IGZp'
    'bGVzIGRucycsIG5zcywgZmxhZ3M9cmUuTSkKICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8nbnNzd2l0Y2guY29u'
    'ZicsIG5zcykKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2FkZCcsIEhPU1QsICd0eXBlJywgJ3ZldGgnLCAncGVlcics'
    'ICduYW1lJywgUEVFUl0pCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdzZXQnLCBQRUVSLCAnbmV0bnMnLCBOU10pCiAg'
    'ICBjb21tYW5kKFsnaXAnLCAnYWRkcicsICdhZGQnLCBHQVRFV0FZKycvMzAnLCAnZGV2JywgSE9TVF0pCiAgICBjb21tYW5k'
    'KFsnaXAnLCAnbGluaycsICdzZXQnLCBIT1NULCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywgJ2FkZHInLCAnYWRkJywgQ0xJ'
    'RU5UKycvMzAnLCAnZGV2JywgUEVFUl0pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3NldCcsIFBFRVIsICd1cCddKQog'
    'ICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQnLCAnbG8nLCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywgJ3JvdXRlJywg'
    'J2FkZCcsICdkZWZhdWx0JywgJ3ZpYScsIEdBVEVXQVldKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2FkZCcsICd0'
    'YWJsZScsIHN0cihUQUJMRSksICdkZWZhdWx0JywgJ3ZpYScsIHJvdXRlWydnYXRld2F5J10sICdkZXYnLCByb3V0ZVsnZGV2'
    'J11dKQogICAgZm9yIGFkZHJlc3MgaW4gKFNFUlZFUiwgU0VSVkVSX0xBTik6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1'
    'bGUnLCAnYWRkJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAg'
    'ICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldKQogICAgcnVsZXMgPSBob3N0X3J1bGVz'
    'KHJvdXRlWydkZXYnXSwgcHJldmlvdXNfZm9yd2FyZD1vbGRfZm9yd2FyZCA9PSAnMScpCiAgICBjb21tYW5kKFsnbmZ0Jywg'
    'Jy1jJywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVz'
    'KQogICAgIyBQZXItaW50ZXJmYWNlIGZvcndhcmRpbmcgYXZvaWRzIGlwX2ZvcndhcmQncyBnbG9iYWwgZGVmYXVsdHMgcmVz'
    'ZXQuCiAgICAoUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9IT1NULydmb3J3YXJkaW5nJykud3JpdGVfdGV4dCgn'
    'MVxuJykKICAgIHVwbGluay53cml0ZV90ZXh0KCcxXG4nKQoKCmRlZiBjbGVhbnVwKCk6CiAgICBjbGVhbnVwX2Z1bGwoKQog'
    'ICAgIyBBbiB1bm93bmVkIG5hbWVzcGFjZS90YWJsZSBtdXN0IG5ldmVyIGJlIGRlbGV0ZWQgYnkgYSBnZW5lcmljIGNsZWFu'
    'dXAgY2FsbC4KICAgIGlmIG5vdCAoUk9PVC8nbmV0d29yay5qc29uJykuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuCiAgICBk'
    'YXRhID0ganNvbi5sb2FkcygoUk9PVC8nbmV0d29yay5qc29uJykucmVhZF90ZXh0KCkpCiAgICBjb21tYW5kKFsnbmZ0Jywg'
    'J2RlbGV0ZScsICd0YWJsZScsICdpbmV0JywgTkZUXSwgY2hlY2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVS'
    'LCBTRVJWRVJfTEFOKToKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCBzdHIoUFJJ'
    'T1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9v'
    'a3VwJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQogICAgZm9yIGFkZHJlc3MgaW4gZGF0YS5nZXQoJ21lYXN1cmVtZW50'
    'X2lwcycsIFtdKToKICAgICAgICBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhZGRyZXNzKS5pc19nbG9iYWw6CiAgICAgICAg'
    'ICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2RlbCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMy'
    'JywgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQo'
    'WydpcCcsICdyb3V0ZScsICdmbHVzaCcsICd0YWJsZScsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQo'
    'WydpcCcsICduZXRucycsICdkZWwnLCBOU10sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnZGVs'
    'JywgSE9TVF0sIGNoZWNrPUZhbHNlKQogICAgaWYgJ3VwbGlua19mb3J3YXJkJyBpbiBkYXRhOgogICAgICAgIHBhdGggPSBQ'
    'YXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvY29uZicpL2RhdGFbJ2ludGVyZmFjZSddLydmb3J3YXJkaW5nJwogICAgICAgIGlm'
    'IHBhdGguZXhpc3RzKCk6CiAgICAgICAgICAgIHBhdGgud3JpdGVfdGV4dChkYXRhWyd1cGxpbmtfZm9yd2FyZCddKydcbicp'
    'CiAgICBlbGlmIGRhdGEuZ2V0KCdmb3J3YXJkJykgPT0gJzAnIGFuZCBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9y'
    'd2FyZCcpLnJlYWRfdGV4dCgpLnN0cmlwKCkgPT0gJzEnOgogICAgICAgIFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9m'
    'b3J3YXJkJykud3JpdGVfdGV4dCgnMFxuJykKICAgIChQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25mJykudW5s'
    'aW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIChQYXRoKCcvZXRjL25ldG5zJykvTlMvJ25zc3dpdGNoLmNvbmYnKS51bmxpbmso'
    'bWlzc2luZ19vaz1UcnVlKQogICAgd2l0aCBjb250ZXh0bGliLnN1cHByZXNzKE9TRXJyb3IpOgogICAgICAgIChQYXRoKCcv'
    'ZXRjL25ldG5zJykvTlMpLnJtZGlyKCkKICAgIChST09ULyduZXR3b3JrLmpzb24nKS51bmxpbmsobWlzc2luZ19vaz1UcnVl'
    'KQoKCkBjb250ZXh0bGliLmNvbnRleHRtYW5hZ2VyCmRlZiBtZWFzdXJlbWVudF9yb3V0ZShhZGRyZXNzKToKICAgICIiIkEg'
    'c2hvcnQtbGl2ZWQgZGlyZWN0IHJvdXRlIGZvciBhIHZlcmlmaWVkIFlhbmRleCBIVFRQUyBtZWFzdXJlbWVudCwgbGFiIG9u'
    'bHkuIiIiCiAgICBpZiBub3QgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xvYmFsIG9yIGFkZHJlc3MgaW4g'
    'KFNFUlZFUiwgU0VSVkVSX0xBTik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9tZWFzdXJlbWVudF9hZGRy'
    'ZXNzJykKICAgIGxhYmVsID0gJ2V2bi1tZWFzdXJlLScrc2VjcmV0cy50b2tlbl9oZXgoOCkKICAgIGRhdGEgPSBqc29uLmxv'
    'YWRzKChST09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGRhdGFbJ21lYXN1cmVtZW50X2lwcyddID0gc29y'
    'dGVkKHNldChkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pK1thZGRyZXNzXSkpCiAgICB3cml0ZShST09ULyduZXR3'
    'b3JrLmpzb24nLCBqc29uLmR1bXBzKGRhdGEpKQogICAgdHJ5OgogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2Fk'
    'ZCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRy'
    'ZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICAgICAgY29tbWFuZChbJ25mdCcsICdpbnNlcnQnLCAncnVs'
    'ZScsICdpbmV0JywgTkZULCAnZm9yd2FyZCcsICdpaWZuYW1lJywgSE9TVCwKICAgICAgICAgICAgICAgICAnaXAnLCAnZGFk'
    'ZHInLCBhZGRyZXNzLCAndGNwJywgJ2Rwb3J0JywgJzQ0MycsICdhY2NlcHQnLCAnY29tbWVudCcsIGxhYmVsXSkKICAgICAg'
    'ICBjb21tYW5kKFsnbmZ0JywgJ2luc2VydCcsICdydWxlJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJywgJ29pZm5hbWUnLCBI'
    'T1NULAogICAgICAgICAgICAgICAgICdpcCcsICdzYWRkcicsIGFkZHJlc3MsICdjdCcsICdzdGF0ZScsICdlc3RhYmxpc2hl'
    'ZCxyZWxhdGVkJywgJ2FjY2VwdCcsICdjb21tZW50JywgbGFiZWxdKQogICAgICAgIHlpZWxkCiAgICBmaW5hbGx5OgogICAg'
    'ICAgIHJlc3VsdCA9IGNvbW1hbmQoWyduZnQnLCAnLWonLCAnLWEnLCAnbGlzdCcsICdjaGFpbicsICdpbmV0JywgTkZULCAn'
    'Zm9yd2FyZCddLCBjaGVjaz1GYWxzZSkKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICBm'
    'b3IgZW50cnkgaW4ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0KS5nZXQoJ25mdGFibGVzJywgW10pOgogICAgICAgICAgICAg'
    'ICAgcnVsZSA9IGVudHJ5LmdldCgncnVsZScsIHt9KQogICAgICAgICAgICAgICAgaWYgcnVsZS5nZXQoJ2NvbW1lbnQnKSA9'
    'PSBsYWJlbDoKICAgICAgICAgICAgICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2RlbGV0ZScsICdydWxlJywgJ2luZXQnLCBO'
    'RlQsICdmb3J3YXJkJywgJ2hhbmRsZScsIHN0cihydWxlWydoYW5kbGUnXSldLCBjaGVjaz1GYWxzZSkKICAgICAgICBjb21t'
    'YW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAg'
    'ICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKCgpk'
    'ZWYgcHJvdmlkZXJfYWRkcmVzc2VzKGhvc3QpOgogICAgIyBETlMgbWF5IHVzZSB0aGUgd29ya2luZyByZXNvbHZlciwgYnV0'
    'IG1lYXN1cmVkIEhUVFBTIGl0c2VsZiB0YWtlcyB0aGUgcGh5c2ljYWwgcm91dGUuCiAgICBhZGRyZXNzZXMgPSBbYW5zd2Vy'
    'WzRdWzBdIGZvciBhbnN3ZXIgaW4gc29ja2V0LmdldGFkZHJpbmZvKGhvc3QsIDQ0Mywgc29ja2V0LkFGX0lORVQsIHNvY2tl'
    'dC5TT0NLX1NUUkVBTSldCiAgICByZXR1cm4gbGlzdChkaWN0LmZyb21rZXlzKHggZm9yIHggaW4gYWRkcmVzc2VzIGlmIGlw'
    'YWRkcmVzcy5pcF9hZGRyZXNzKHgpLmlzX2dsb2JhbCkpWzoyXQoKCmRlZiBwcm92aWRlcl9nZXQoaG9zdCwgcGF0aCwgbWF4'
    'aW11bSwgbWVhc3VyZT1GYWxzZSk6CiAgICBsYXN0ID0gTm9uZQogICAgZm9yIGFkZHJlc3MgaW4gcHJvdmlkZXJfYWRkcmVz'
    'c2VzKGhvc3QpOgogICAgICAgIG91dHB1dCA9IFJPT1QvKCdyZWZlcmVuY2UtJytzZWNyZXRzLnRva2VuX2hleCg4KSsnLnRt'
    'cCcpCiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG1lYXN1cmVtZW50X3JvdXRlKGFkZHJlc3MpOgogICAgICAgICAg'
    'ICAgICAgYXJncyA9IFsnY3VybCcsICctNCcsICctLXNpbGVudCcsICctLXNob3ctZXJyb3InLCAnLS1mYWlsJywgJy0tbm9w'
    'cm94eScsICcqJywKICAgICAgICAgICAgICAgICAgICAgICAgJy0tcHJvdG8nLCAnPWh0dHBzJywgJy0tY29ubmVjdC10aW1l'
    'b3V0JywgJzQnLCAnLS1tYXgtdGltZScsICcxMCcsCiAgICAgICAgICAgICAgICAgICAgICAgICctLXJlc29sdmUnLCBob3N0'
    'Kyc6NDQzOicrYWRkcmVzcywgJy0tbWF4LWZpbGVzaXplJywgc3RyKG1heGltdW0pLAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAnLS1vdXRwdXQnLCBzdHIob3V0cHV0KSwgJy0td3JpdGUtb3V0JywgJyV7anNvbn0nXQogICAgICAgICAgICAgICAgaWYg'
    'bWVhc3VyZToKICAgICAgICAgICAgICAgICAgICBhcmdzICs9IFsnLS1yYW5nZScsICcwLScrc3RyKG1heGltdW0tMSldCiAg'
    'ICAgICAgICAgICAgICBhcmdzICs9IFsnaHR0cHM6Ly8nK2hvc3QrcGF0aF0KICAgICAgICAgICAgICAgIHJlc3VsdCA9IGlu'
    'c2lkZShhcmdzLCB0aW1lb3V0PTEyLCBjaGVjaz1GYWxzZSkKICAgICAgICAgICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2Rl'
    'OgogICAgICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignbWVhc3VyZW1lbnRfY3VybF8nK3N0cihyZXN1bHQu'
    'cmV0dXJuY29kZSkpCiAgICAgICAgICAgICAgICBzdGF0aXN0aWNzID0ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0KQogICAg'
    'ICAgICAgICAgICAgaWYgbWVhc3VyZToKICAgICAgICAgICAgICAgICAgICByZWNlaXZlZCA9IGludChzdGF0aXN0aWNzWydz'
    'aXplX2Rvd25sb2FkJ10pCiAgICAgICAgICAgICAgICAgICAgZWxhcHNlZCA9IGZsb2F0KHN0YXRpc3RpY3NbJ3RpbWVfdG90'
    'YWwnXSktZmxvYXQoc3RhdGlzdGljc1sndGltZV9zdGFydHRyYW5zZmVyJ10pCiAgICAgICAgICAgICAgICAgICAgaWYgcmVj'
    'ZWl2ZWQgPCAxMDI0KjEwMjQgb3IgcmVjZWl2ZWQgPiBtYXhpbXVtIG9yIGVsYXBzZWQgPD0gMDoKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdtZWFzdXJlbWVudF90b29fc2hvcnQnKQogICAgICAgICAgICAgICAgICAg'
    'IHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICdlc3RpbWF0ZWRfbWJwcyc6IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xZTYsIDIpfQog'
    'ICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dC5yZWFkX2J5dGVzKCkKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFJ1bnRp'
    'bWVFcnJvciwgVmFsdWVFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgICAgICBsYXN0'
    'ID0gZXhjCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgb3V0cHV0LnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ3JlZmVyZW5jZV91bmF2YWlsYWJsZScpIGZyb20gbGFzdAoKCmRlZiB2YWxpZGF0ZV95YW5k'
    'ZXhfcHJvYmUodXJsKToKICAgIGZyb20gdXJsbGliLnBhcnNlIGltcG9ydCB1cmxzcGxpdAogICAgcGFyc2VkID0gdXJsc3Bs'
    'aXQodXJsKQogICAgaWYgKGxlbih1cmwpID4gMjA0OCBvciBwYXJzZWQuc2NoZW1lICE9ICdodHRwcycgb3Igbm90IHBhcnNl'
    'ZC5ob3N0bmFtZSBvcgogICAgICAgIG5vdCBwYXJzZWQuaG9zdG5hbWUuZW5kc3dpdGgoJy5jZG4ueWFuZGV4Lm5ldCcpIG9y'
    'IHBhcnNlZC51c2VybmFtZSBvciBwYXJzZWQucGFzc3dvcmQgb3IKICAgICAgICBwYXJzZWQucG9ydCBub3QgaW4gKE5vbmUs'
    'IDQ0Mykgb3IgcGFyc2VkLmZyYWdtZW50KToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCd1bnRydXN0ZWRfcmVmZXJlbmNl'
    'X3VybCcpCiAgICByZXR1cm4gcGFyc2VkLmhvc3RuYW1lLCBwYXJzZWQucGF0aCsoJz8nICsgcGFyc2VkLnF1ZXJ5IGlmIHBh'
    'cnNlZC5xdWVyeSBlbHNlICcnKQoKCmRlZiByZWZlcmVuY2Vfc2FtcGxlKGZvcmNlPUZhbHNlKToKICAgIHJvdXRlID0gcGh5'
    'c2ljYWxfcm91dGUoKQogICAgZmluZ2VycHJpbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6IHJvdXRlLmdl'
    'dChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1ZSkuZW5jb2Rl'
    'KCkpLmhleGRpZ2VzdCgpCiAgICB0cnk6CiAgICAgICAgY2FjaGVkID0ganNvbi5sb2FkcygoUk9PVC8ncmVmZXJlbmNlLmpz'
    'b24nKS5yZWFkX3RleHQoKSkKICAgICAgICBpZiBub3QgZm9yY2UgYW5kIGNhY2hlZC5nZXQoJ25ldHdvcmsnKSA9PSBmaW5n'
    'ZXJwcmludCBhbmQgY2FjaGVkLmdldCgncHJvdmlkZXInKSA9PSAnWWFuZGV4IEludGVybmV0b21ldGVyJzoKICAgICAgICAg'
    'ICAgcmV0dXJuIGNhY2hlZAogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICBwYXNzCiAgICBzdGFn'
    'ZSgncmVmZXJlbmNlJywgJ9CX0LDQv9GD0YHQutCw0Y4g0LfQsNC80LXRgCDQv9GA0Y/QvNC+0LPQviDRgdC+0LXQtNC40L3Q'
    'tdC90LjRjzog0K/QvdC00LXQutGBINCY0L3RgtC10YDQvdC10YLQvtC80LXRgtGALicsIDEyKQogICAgY29uZmlnID0ganNv'
    'bi5sb2Fkcyhwcm92aWRlcl9nZXQoJ3lhbmRleC5ydScsICcvaW50ZXJuZXQvYXBpL3YwL2dldC1wcm9iZXM/ZnJvbT1pbnRl'
    'cm5ldCZub2NhY2hlPScrc3RyKGludCh0aW1lLnRpbWUoKSoxMDAwKSksIDY1NTM2KSkKICAgIHByb2JlcyA9IGNvbmZpZy5n'
    'ZXQoJ2Rvd25sb2FkJywge30pLmdldCgncHJvYmVzJywgW10pCiAgICBjYW5kaWRhdGVzID0gW10KICAgIGZvciBwcm9iZSBp'
    'biBwcm9iZXM6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBob3N0LCBwYXRoID0gdmFsaWRhdGVfeWFuZGV4X3Byb2JlKHBy'
    'b2JlLmdldCgndXJsJywgJycpKQogICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAgICAgICAgICAg'
    'Y29udGludWUKICAgICAgICBpZiAnNTBtYicgaW4gcGF0aCBvciAnMTAwbWInIGluIHBhdGg6CiAgICAgICAgICAgIGNhbmRp'
    'ZGF0ZXMuYXBwZW5kKChob3N0LCBwYXRoKSkKICAgIGlmIG5vdCBjYW5kaWRhdGVzOgogICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcigncmVmZXJlbmNlX3NjaGVtYV9jaGFuZ2VkJykKICAgIGhvc3QsIHBhdGggPSBjYW5kaWRhdGVzWzBdCiAgICAjIFNo'
    'b3J0IHNhbXBsZXMgYXZvaWQgYSBtaW51dGUtbG9uZyBzYXR1cmF0aW9uIHdoaWxlIHRoZSB1c2VyIHdhdGNoZXMgdmlkZW8u'
    'CiAgICBzYW1wbGVzID0gW3Byb3ZpZGVyX2dldChob3N0LCBwYXRoLCA4KjEwMjQqMTAyNCwgbWVhc3VyZT1UcnVlKSBmb3Ig'
    'XyBpbiByYW5nZSgyKV0KICAgIHJlc3VsdCA9IHsncHJvdmlkZXInOiAnWWFuZGV4IEludGVybmV0b21ldGVyJywgJ25ldHdv'
    'cmsnOiBmaW5nZXJwcmludCwgJ3RpbWUnOiBpbnQodGltZS50aW1lKCkpLAogICAgICAgICAgICAgICdlc3RpbWF0ZWRfbWJw'
    'cyc6IG1heCh4Wydlc3RpbWF0ZWRfbWJwcyddIGZvciB4IGluIHNhbXBsZXMpLCAnc2FtcGxlcyc6IHNhbXBsZXMsCiAgICAg'
    'ICAgICAgICAgJ3Nob3J0X3NhbXBsZSc6IFRydWUsICdkaXJlY3RfcGh5c2ljYWxfcm91dGUnOiBUcnVlfQogICAgd3JpdGUo'
    'Uk9PVC8ncmVmZXJlbmNlLmpzb24nLCBqc29uLmR1bXBzKHJlc3VsdCkpCiAgICByZXR1cm4gcmVzdWx0CgoKCmRlZiB0bHNf'
    'cmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNsaWVudD1GYWxzZSwgdGltZW91dD04KToKICAgIGNvbnRleHQg'
    'PSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgaWYgY2xpZW50OgogICAgICAgIGNv'
    'bnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScp'
    'KQogICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9dGltZW91dCkK'
    'ICAgIHRyeToKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1TRVJWRVIp'
    'CiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBzb2NrLmNsb3NlKCkKICAgICAgICByYWlzZQogICAgY29ubmVj'
    'dGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKGFkZHJlc3MsIDg0NDMsIHRpbWVvdXQ9dGltZW91dCkKICAgIGNv'
    'bm5lY3Rpb24uc29jayA9IHRscwogICAgZW5jb2RlZCA9IGpzb24uZHVtcHMoYm9keSwgc2VwYXJhdG9ycz0oJywnLCAnOicp'
    'KS5lbmNvZGUoKSBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgTm9uZQogICAgdHJ5OgogICAgICAgIGNvbm5lY3Rpb24ucmVx'
    'dWVzdCgnUE9TVCcgaWYgYm9keSBpcyBub3QgTm9uZSBlbHNlICdHRVQnLCBwYXRoLCBib2R5PWVuY29kZWQsCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9eydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsICdDb25uZWN0'
    'aW9uJzogJ2Nsb3NlJ30pCiAgICAgICAgcmVzcG9uc2UgPSBjb25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICByYXcg'
    'PSByZXNwb25zZS5yZWFkKDIwMDAxKQogICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDAgb3IgbGVuKHJhdykgPiAy'
    'MDAwMDoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdyZXF1ZXN0X3JlamVjdGVkJykKICAgICAgICByZXR1cm4g'
    'anNvbi5sb2FkcyhyYXcpCiAgICBmaW5hbGx5OgogICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQoKCmRlZiBlbnJvbGwoKToK'
    'ICAgIHRva2VuID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChU'
    'T0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX3Rva2VuJykKICAgIHRy'
    'eToKICAgICAgICBjYWNoZWQgPSBqc29uLmxvYWRzKChST09ULydwcm9maWxlLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAg'
    'ICBpZiAoY2FjaGVkLmdldCgnY2EnKSA9PSBQSU5ORURfQ0EgYW5kIGNhY2hlZC5nZXQoJ3NlcnZlcicpID09IFNFUlZFUiBh'
    'bmQKICAgICAgICAgICAgcmUuZnVsbG1hdGNoKHInZGV2aWNlLVthLWYwLTldezI0fScsIGNhY2hlZC5nZXQoJ2lkZW50aXR5'
    'JywgJycpKSBhbmQKICAgICAgICAgICAgY2FjaGVkLmdldCgnZW5kcG9pbnQnKSBpbiAoU0VSVkVSLCBTRVJWRVJfTEFOKSBh'
    'bmQgY2FjaGVkLmdldCgncGh5c2ljYWxfbmV0d29yaycpIGFuZAogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd4'
    'NTA5JywgJy1pbicsIFJPT1QvJ2NsaWVudC5wZW0nLCAnLWNoZWNrZW5kJywgc3RyKDcqODY0MDApLCAnLW5vb3V0J10sIGNo'
    'ZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDApOgogICAgICAgICAgICBjb250ZXh0ID0gc3NsLlNTTENvbnRleHQoc3NsLlBS'
    'T1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQu'
    'cGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkK'
    'ICAgICAgICAgICAgY3VycmVudCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9y'
    'IGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGln'
    'ZXN0KCkKICAgICAgICAgICAgYWRkcmVzcyA9IGNhY2hlZFsnZW5kcG9pbnQnXSBpZiBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9u'
    'ZXR3b3JrJykgPT0gY3VycmVudCBlbHNlIFNFUlZFUgogICAgICAgICAgICByZXR1cm4gY2FjaGVkWydpZGVudGl0eSddLCBh'
    'ZGRyZXNzCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAgICAgICAgcGFzcwogICAg'
    'c3RhZ2UoJ3Rva2VuJywgJ9Cf0L7Qu9GD0YfQsNGOINGB0LXRgNGC0LjRhNC40LrQsNGCINC00LvRjyDRjdGC0L7Qs9C+INGD'
    '0YHRgtGA0L7QudGB0YLQstCwLicsIDI1KQogICAgaWYgbm90IChST09ULydjbGllbnQta2V5LnBlbScpLmV4aXN0cygpOgog'
    'ICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ2dlbnBrZXknLCAnLWFsZ29yaXRobScsICdSU0EnLCAnLXBrZXlvcHQnLCAn'
    'cnNhX2tleWdlbl9iaXRzOjMwNzInLAogICAgICAgICAgICAgICAgICctb3V0JywgUk9PVC8nY2xpZW50LWtleS5wZW0nXSwg'
    'dGltZW91dD0zMCkKICAgICAgICAoUk9PVC8nY2xpZW50LWtleS5wZW0nKS5jaG1vZCgwbzYwMCkKICAgIGlmIG5vdCAoUk9P'
    'VC8nZGV2aWNlJykuZXhpc3RzKCk6CiAgICAgICAgd3JpdGUoUk9PVC8nZGV2aWNlJywgc2VjcmV0cy50b2tlbl9oZXgoMTYp'
    'KQogICAgY29tbWFuZChbJ29wZW5zc2wnLCAncmVxJywgJy1uZXcnLCAnLWtleScsIFJPT1QvJ2NsaWVudC1rZXkucGVtJywg'
    'Jy1zdWJqJywgJy9DTj1ldmdlbml1bS1kZXZpY2UnLAogICAgICAgICAgICAgJy1vdXQnLCBST09ULydyZXF1ZXN0LnBlbSdd'
    'KQogICAgcGF5bG9hZCA9IHsndG9rZW4nOiB0b2tlbiwgJ2RldmljZSc6IChST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5z'
    'dHJpcCgpLCAnY3NyJzogKFJPT1QvJ3JlcXVlc3QucGVtJykucmVhZF90ZXh0KCl9CiAgICBsYXN0ID0gTm9uZQogICAgZm9y'
    'IGFkZHJlc3MgaW4gKFNFUlZFUiwgU0VSVkVSX0xBTik6CiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG5hbWVzcGFj'
    'ZSgpOgogICAgICAgICAgICAgICAgcmVwbHkgPSB0bHNfcmVxdWVzdChhZGRyZXNzLCAnL2Vucm9sbCcsIHBheWxvYWQsIHRp'
    'bWVvdXQ9NikKICAgICAgICAgICAgcHJvZmlsZSA9IHJlcGx5LmdldCgncHJvZmlsZScsIHt9KQogICAgICAgICAgICBpZiBy'
    'ZXBseS5nZXQoJ29rJykgaXMgbm90IFRydWUgb3IgcHJvZmlsZS5nZXQoJ2NhJykgIT0gUElOTkVEX0NBIG9yIHByb2ZpbGUu'
    'Z2V0KCdzZXJ2ZXInKSAhPSBTRVJWRVI6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfcHJv'
    'ZmlsZScpCiAgICAgICAgICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgcHJvZmlsZS5n'
    'ZXQoJ2lkZW50aXR5JywgJycpKToKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9pZGVudGl0'
    'eScpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NsaWVudC5wZW0nLCBwcm9maWxlWydjZXJ0aWZpY2F0ZSddKQogICAgICAg'
    'ICAgICB3cml0ZShST09ULydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDknLydjbGll'
    'bnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8neDUwOWNhJy8nY2EucGVt'
    'JywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULydwcml2YXRlJy8nY2xpZW50LWtleS5wZW0nLCAoUk9PVC8n'
    'Y2xpZW50LWtleS5wZW0nKS5yZWFkX3RleHQoKSkKICAgICAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAndmVyaWZ5Jywg'
    'Jy1wdXJwb3NlJywgJ3NzbGNsaWVudCcsICctQ0FmaWxlJywgUk9PVC8nY2EucGVtJywgUk9PVC8nY2xpZW50LnBlbSddKQog'
    'ICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAgY3R4'
    'LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAg'
    'ICAgICAgICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAgICAgICAgIGZpbmdlcnByaW50ID0gaGFzaGxpYi5zaGEy'
    'NTYoanNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAncHJlZnNy'
    'YycpfSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICB3cml0ZShST09ULydwcm9m'
    'aWxlLmpzb24nLCBqc29uLmR1bXBzKHsqKnByb2ZpbGUsICdlbmRwb2ludCc6IGFkZHJlc3MsICdwaHlzaWNhbF9uZXR3b3Jr'
    'JzogZmluZ2VycHJpbnR9KSkKICAgICAgICAgICAgcmV0dXJuIHByb2ZpbGVbJ2lkZW50aXR5J10sIGFkZHJlc3MKICAgICAg'
    'ICBleGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvciwgUnVudGltZUVycm9yKSBhcyBleGM6CiAgICAgICAgICAgIGxhc3Qg'
    'PSBleGMKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZW5yb2xsbWVudF91bmF2YWlsYWJsZScpIGZyb20gbGFzdAoKCmRlZiBk'
    'YWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcyk6CiAgICBSVU5USU1FLm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9'
    'VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGluY2x1ZGVzID0gJ1xuJy5qb2luKCdpbmNsdWRlICcrc3RyKHApIGZvciBwYXR0'
    'ZXJuIGluICgnL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicsICcvZXRjL3N0cm9uZ3N3YW4vc3Ryb25nc3dhbi5k'
    'L2NoYXJvbi8qLmNvbmYnKQogICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHAgaW4gUGF0aCgnLycpLmdsb2IocGF0dGVy'
    'bi5sc3RyaXAoJy8nKSkpCiAgICB3cml0ZShST09ULydzdHJvbmdzd2FuLmNvbmYnLCBmJycnY2hhcm9uIHt7CiBsb2FkX21v'
    'ZHVsYXIgPSB5ZXMKIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFibGVf'
    'cHJpbyA9IDEwMAogcGx1Z2lucyB7ewp7aW5jbHVkZXN9CiAgdmljaSB7eyBzb2NrZXQgPSB1bml4Oi8ve1JVTlRJTUV9L2No'
    'YXJvbi52aWNpIH19CiAgcmVzb2x2ZSB7eyBsb2FkID0gbm8gfX0KICBrZXJuZWwtbGliaXBzZWMge3sgbG9hZCA9IG5vIH19'
    'CiB9fQp9fQpjaGFyb24tc3lzdGVtZCB7eyBqb3VybmFsIHt7IGRlZmF1bHQgPSAwOyBpa2UgPSAxIH19IH19CicnJykKICAg'
    'ICMgQWJzb2x1dGUgY3JlZGVudGlhbHMgYXJlIGxvY2FsIHRvIHRoaXMgZGV2aWNlLCBub3Qgc2hhcmVkIGJ5IHRoZSBhY2Nv'
    'dW50IHRva2VuLgogICAgd3JpdGUoUk9PVC8nY29ubmVjdGlvbi5jb25mJywgZicnJ2Nvbm5lY3Rpb25zIHt7CiBzdGFyZml2'
    'ZSB7ewogIHZlcnNpb24gPSAyCiAgcmVtb3RlX2FkZHJzID0ge2FkZHJlc3N9CiAgdmlwcyA9IDAuMC4wLjAKICBwcm9wb3Nh'
    'bHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAg'
    'bW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMTVzCiAgbG9jYWwge3sgYXV0aCA9IGVhcC10bHM7IGlkID0ge2lkZW50aXR5'
    'fTsgZWFwX2lkID0ge2lkZW50aXR5fTsgY2VydHMgPSB7Uk9PVH0vY2xpZW50LnBlbSB9fQogIHJlbW90ZSB7eyBhdXRoID0g'
    'cHVia2V5OyBpZCA9IHtTRVJWRVJ9OyBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbSB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJm'
    'aXZlLW5ldCB7ewogICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0g'
    'e1JFUUlEfQogICAgZXNwX3Byb3Bvc2FscyA9IGNoYWNoYTIwcG9seTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAg'
    'c3RhcnRfYWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQpzZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUg'
    'PSB7Uk9PVH0vY2xpZW50LWtleS5wZW0gfX0gfX0KJycnKQogICAgIyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVz'
    'LCBub3Qgc2VtaWNvbG9uIHNlcGFyYXRvcnMgKG5vcm1hbGl6ZSBjb21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAo'
    'J3N0cm9uZ3N3YW4uY29uZicsICdjb25uZWN0aW9uLmNvbmYnKToKICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAg'
    'cGF0aC53cml0ZV90ZXh0KHBhdGgucmVhZF90ZXh0KCkucmVwbGFjZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4n'
    'KS5yZXBsYWNlKCcgfScsICdcbn0nKSkKICAgIHJ1bGVzID0gZicnJ3RhYmxlIGluZXQgZXZuX3N0YXJmaXZlX2d1YXJkIHt7'
    'CiBjaGFpbiBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwog'
    'IG9pZm5hbWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdWRwIGRwb3J0IHt7IDUwMCwgNDUwMCB9fSBhY2Nl'
    'cHQKICBtZXRhIHNrdWlkIDAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG1ldGEgbmZwcm90'
    'byBpcHY0IGlwc2VjIG91dCByZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIg'
    'aG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCAnLWMn'
    'LCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKCgpk'
    'ZWYgc3dhbigqYXJncywgdGltZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRlKFsnc3dhbmN0bCcsICph'
    'cmdzLCAnLS11cmknLCAndW5peDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1lb3V0PXRpbWVvdXQsIGNo'
    'ZWNrPWNoZWNrKQoKCmRlZiBpbnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBzd2FuKCctLWxpc3Qtc2Fz'
    'JywgJy0tcmF3JywgdGltZW91dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0LnJldHVybmNvZGUgPT0g'
    'MCBhbmQgJ3N0YXRlPUVTVEFCTElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5TVEFMTEVEJyBpbiByZXN1'
    'bHQuc3Rkb3V0CiAgICBleGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgIHJldHVy'
    'biBGYWxzZQoKCmRlZiBoZWFsdGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0dXJuIHRsc19yZXF1ZXN0'
    'KEhFQUxUSCwgJy9oZWFsdGgnLCBjbGllbnQ9VHJ1ZSkuZ2V0KCdzZXJ2aWNlJykgPT0gJ2V2Z2VuaXVtLXN0YXJmaXZlJwoK'
    'CmRlZiBkb3dubG9hZChzaXplPTEwNDg1NzYpOgogICAgIyBBIGJvdW5kZWQgaW50ZWdyaXR5IGNoZWNrLCBub3QgYSBjbGFp'
    'bSB0byBoYXZlIG1lYXN1cmVkIHRoZSBJU1AncyBtYXhpbXVtIHJhdGUuCiAgICBibG9jayA9IGhhc2hsaWIuc2hha2VfMjU2'
    'KGInZXZnZW5pdW0tc3RhcmZpdmUtaW50ZWdyaXR5LXYxJykuZGlnZXN0KDY1NTM2KQogICAgZXhwZWN0ZWQgPSBoYXNobGli'
    'LnNoYTI1NigoYmxvY2sqKHNpemUvL2xlbihibG9jaykrMSkpWzpzaXplXSkuaGV4ZGlnZXN0KCkKICAgIGNvbnRleHQgPSBz'
    'c2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4o'
    'c3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICB3aXRoIG5hbWVzcGFjZSgp'
    'OgogICAgICAgIHNvY2sgPSBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKEhFQUxUSCwgODQ0MyksIHRpbWVvdXQ9MTApCiAg'
    'ICAgICAgdGxzID0gY29udGV4dC53cmFwX3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9U0VSVkVSKQogICAgICAgIGNv'
    'bm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbihIRUFMVEgsIDg0NDMsIHRpbWVvdXQ9MTApOyBjb25uZWN0'
    'aW9uLnNvY2sgPSB0bHMKICAgICAgICB0cnk6CiAgICAgICAgICAgIHN0YXJ0ID0gdGltZS5tb25vdG9uaWMoKQogICAgICAg'
    'ICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ0dFVCcsICcvYmxvYj9zaXplPScrc3RyKHNpemUpKQogICAgICAgICAgICByZXNw'
    'b25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgICAgICBpZiByZXNwb25zZS5zdGF0dXMgIT0gMjAwOgog'
    'ICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0cmFuc2Zlcl9odHRwJykKICAgICAgICAgICAgZGlnZXN0ID0g'
    'aGFzaGxpYi5zaGEyNTYoKTsgcmVjZWl2ZWQgPSAwCiAgICAgICAgICAgIHdoaWxlIHJlY2VpdmVkIDwgc2l6ZToKICAgICAg'
    'ICAgICAgICAgIGRhdGEgPSByZXNwb25zZS5yZWFkKG1pbig2NTUzNiwgc2l6ZS1yZWNlaXZlZCkpCiAgICAgICAgICAgICAg'
    'ICBpZiBub3QgZGF0YToKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZGlnZXN0LnVwZGF0ZShk'
    'YXRhKTsgcmVjZWl2ZWQgKz0gbGVuKGRhdGEpCiAgICAgICAgICAgIGVsYXBzZWQgPSB0aW1lLm1vbm90b25pYygpLXN0YXJ0'
    'CiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCiAgICBpZiByZWNlaXZlZCAhPSBzaXpl'
    'IG9yIGRpZ2VzdC5oZXhkaWdlc3QoKSAhPSBleHBlY3RlZDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludGVncml0'
    'eV9mYWlsZWQnKQogICAgcmV0dXJuIHsnYnl0ZXMnOiByZWNlaXZlZCwgJ2Rvd25sb2FkX21icHMnOiByb3VuZChyZWNlaXZl'
    'ZCo4L2VsYXBzZWQvMWU2LCAyKSwKICAgICAgICAgICAgJ2VsYXBzZWRfbXMnOiByb3VuZChlbGFwc2VkKjEwMDApLCAnaW50'
    'ZWdyaXR5JzogVHJ1ZSwgJ2xpbWl0ZWRfc2FtcGxlJzogVHJ1ZX0KCgpkZWYgdG9rZW5fc3RhdHVzKCk6CiAgICB0cnk6CiAg'
    'ICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5k'
    'RXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFsaWQgPSByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4p'
    'IGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9rZW4nOiB2YWxpZCwKICAgICAgICAgICAgJ3Rva2VuX2hpbnQnOiAn'
    'RVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hsaWIuc2hhMjU2KHRva2VuLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6'
    'OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90b2tlbih0b2tlbik6CiAgICB0b2tlbiA9IHRva2VuLnN0cmlwKCkK'
    'ICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3Io'
    'J9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC90YLQsCDRhNC+0YDQvNCw0YLQsCBFVk4xLeKApicpCiAgICBST09U'
    'Lm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIG9sZCA9IChST09ULyd0b2tlbicp'
    'LnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rva2VuJykuZXhpc3RzKCkgZWxzZSAnJwogICAgaWYgb2xkID09IHRv'
    'a2VuOgogICAgICAgIHJldHVybgogICAgaWYgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcs'
    'IFVOSVRdLCBjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw'
    '0YfQsNC70LAg0L7RgtC60LvRjtGH0LjRgtC1INGC0LXRgdGC0L7QstGL0Lkg0YLRg9C90L3QtdC70Ywg0L/QtdGA0LXQtCDR'
    'gdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicpCiAgICAjIEEgZGlmZmVyZW50IGFjY291bnQgbmVlZHMgaXRzIG93biBkZXZp'
    'Y2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNlIGl0cyBjZXJ0aWZpY2F0ZS4KICAgIGZvciBuYW1lIGluICgnZGV2aWNlJywg'
    'J2NsaWVudC1rZXkucGVtJywgJ2NsaWVudC5wZW0nLCAncHJvZmlsZS5qc29uJywgJ3JlcXVlc3QucGVtJywKICAgICAgICAg'
    'ICAgICAgICAncHJpdmF0ZS9jbGllbnQta2V5LnBlbScsICd4NTA5L2NsaWVudC5wZW0nKToKICAgICAgICAoUk9PVC9uYW1l'
    'KS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgd3JpdGUoUk9PVC8ndG9rZW4nLCB0b2tlbikKICAgIHN0YWdlKCdvZmYn'
    'LCAn0KLQvtC60LXQvSDRgdC+0YXRgNCw0L3RkdC9LiDQndCw0LbQvNC40YLQtSDCq9Cf0L7QtNC60LvRjtGH0LjRgtGMwrsu'
    'JywgMCwgYWN0aXZlPUZhbHNlLCBtZXRyaWNzPXt9KQoKCmRlZiBjb25uZWN0KHRva2VuPScnLCByZXBhaXI9RmFsc2UpOgog'
    'ICAgUk9PVC5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBpZiB0b2tlbjoKICAg'
    'ICAgICBzYXZlX3Rva2VuKHRva2VuKQogICAgaWYgbm90IHRva2VuX3N0YXR1cygpWydoYXNfdG9rZW4nXToKICAgICAgICBy'
    'YWlzZSBWYWx1ZUVycm9yKCfQktCy0LXQtNC40YLQtSDQuCDQv9C+0LTRgtCy0LXRgNC00LjRgtC1INGC0L7QutC10L0g0LrQ'
    'u9C40LXQvdGC0LAuJykKICAgIGVuc3VyZV9kZXBlbmRlbmNpZXMoKQogICAgaWYgcmVwYWlyOgogICAgICAgIHdyaXRlKFJP'
    'T1QvJ3JlY2FsaWJyYXRlJywgJzEnKQogICAgdW5pdCA9IGYnJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gU3RhckZp'
    'dmUgZnVsbC1kZXZpY2UgRXN0b25pYSBWUE4KQWZ0ZXI9bmV0d29yay50YXJnZXQKW1NlcnZpY2VdClR5cGU9c2ltcGxlCkV4'
    'ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXN0YXJmaXZlLXR1bm5lbApFeGVjU3RvcFBvc3Q9L3Vz'
    'ci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwtY2xlYW51cApUaW1lb3V0U3RvcFNlYz0yMApL'
    'aWxsTW9kZT1taXhlZApVTWFzaz0wMDc3Ck1lbW9yeU1heD0yNTZNClJlc3RhcnQ9bm8KJycnCiAgICB3cml0ZShQYXRoKCcv'
    'ZXRjL3N5c3RlbWQvc3lzdGVtJykvVU5JVCwgdW5pdCkKICAgIHJlY292ZXJ5ID0gImV2Z2VuaXVtLXN0YXJmaXZlLXR1bm5l'
    'bC1yZWNvdmVyLnNlcnZpY2UiCiAgICB3cml0ZShQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtJykvcmVjb3ZlcnksICIiIltV'
    'bml0XQpEZXNjcmlwdGlvbj1SZWNvdmVyIG9ubHkgaW50ZXJydXB0ZWQgRXZnZW5pdW0gdHVubmVsIHRlc3QgcmVzb3VyY2Vz'
    'CkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9jYWwtZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3JrLXByZS50YXJnZXQg'
    'dnBuLXhyYXkuc2VydmljZQpbU2VydmljZV0KVHlwZT1vbmVzaG90CkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3Rs'
    'IGludGVybmFsLXN0YXJmaXZlLXR1bm5lbC1jbGVhbnVwCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAoi'
    'IiIpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2RhZW1vbi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwn'
    'LCAnZW5hYmxlJywgcmVjb3ZlcnldKQogICAgc3RhZ2UoJ3N0YXJ0aW5nJyAsICfQk9C+0YLQvtCy0LvRjiDQv9C+0LTQutC7'
    '0Y7Rh9C10L3QuNC1INGH0LXRgNC10LcgU3RhckZpdmUg0LIg0K3RgdGC0L7QvdC40Y4uJywgMiwgYWN0aXZlPUZhbHNlLCBy'
    'ZXRyeT0wLCBlcnJvcl9jb2RlPScnKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdyZXN0YXJ0JyBpZiByZXBhaXIgZWxz'
    'ZSAnc3RhcnQnLCBVTklUXSkKICAgIHByaW50KCfQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3Ri9C5IFZQTiDQt9Cw'
    '0L/Rg9GB0LrQsNC10YLRgdGPLiDQrdGC0LDQv9GLINCy0LjQtNC90Ysg0LIg0YHRgtGA0L7QutC1INGB0L7RgdGC0L7Rj9C9'
    '0LjRjy4nKQoKCmRlZiBkaXNjb25uZWN0KCk6CiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ3N0b3AnLCBVTklUXSwgY2hl'
    'Y2s9RmFsc2UsIHRpbWVvdXQ9MjUpCiAgICBjbGVhbnVwKCkKICAgIGNsZWFudXBfZnVsbChyZWxlYXNlPVRydWUpCiAgICBz'
    'dGFnZSgnb2ZmJywgJ9Ct0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0LkgVlBOINCy0YvQutC70Y7Rh9C10L0uJywg'
    'MCwgYWN0aXZlPUZhbHNlKQogICAgcHJpbnQoJ9Ct0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0LkgVlBOINCy0YvQ'
    'utC70Y7Rh9C10L0uJykKCgpkZWYgc3RhcnRfZGFlbW9uKGVudik6CiAgICAoUlVOVElNRS8nY2hhcm9uLnZpY2knKS51bmxp'
    'bmsobWlzc2luZ19vaz1UcnVlKQogICAgbG9nID0gKFJPT1QvJ2NoYXJvbi5sb2cnKS5vcGVuKCd3JykKICAgIGRhZW1vbiA9'
    'IHN1YnByb2Nlc3MuUG9wZW4oWydpcCcsICduZXRucycsICdleGVjJywgTlMsIGNoYXJvbl9iaW5hcnkoKV0sCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGVudj1lbnYsIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwgc3Rkb3V0PWxvZywgc3Rk'
    'ZXJyPWxvZykKICAgIGxvZy5jbG9zZSgpCiAgICBmb3IgXyBpbiByYW5nZSg2MCk6CiAgICAgICAgaWYgU1RPUCBvciBkYWVt'
    'b24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2RhZW1vbl9zdG9wcGVkJykK'
    'ICAgICAgICBpZiAoUlVOVElNRS8nY2hhcm9uLnZpY2knKS5leGlzdHMoKSBhbmQgc3dhbignLS1zdGF0cycsIGNoZWNrPUZh'
    'bHNlLCB0aW1lb3V0PTEpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICAgICAgYnJlYWsKICAgICAgICB0aW1lLnNsZWVwKC4x'
    'KQogICAgc3dhbignLS1sb2FkLWNyZWRzJywgJy0tbm9wcm9tcHQnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25m'
    'JykKICAgIHN3YW4oJy0tbG9hZC1jb25ucycsICctLWZpbGUnLCBST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgcmV0dXJu'
    'IGRhZW1vbgoKCmRlZiB3b3JrZXIoKToKICAgIGdsb2JhbCBTVE9QCiAgICBTVE9QID0gRmFsc2UKICAgIHNpZ25hbC5zaWdu'
    'YWwoc2lnbmFsLlNJR1RFUk0sIGxhbWJkYSAqXzogZ2xvYmFscygpLl9fc2V0aXRlbV9fKCdTVE9QJywgVHJ1ZSkpCiAgICBz'
    'aWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIGxhbWJkYSAqXzogZ2xvYmFscygpLl9fc2V0aXRlbV9fKCdTVE9QJywgVHJ1'
    'ZSkpCiAgICBkYWVtb24gPSBOb25lCiAgICB0cnk6CiAgICAgICAgY2xlYW51cCgpCiAgICAgICAgc3RhZ2UoJ3ByZXBhcmUn'
    'LCAn0JPQvtGC0L7QstC70Y4g0LfQsNGJ0LjRidGR0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0YHQviBTdGFyRml2'
    'ZS4nLCA4LCBhY3RpdmU9RmFsc2UpCiAgICAgICAgc2V0dXBfbmV0d29yaygpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBy'
    'ZWZlcmVuY2UgPSAoeydza2lwcGVkJzogJ2d1YXJkX2FjdGl2ZSd9IGlmIGZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSByZWZl'
    'cmVuY2Vfc2FtcGxlKGZvcmNlPShST09ULydyZWNhbGlicmF0ZScpLmV4aXN0cygpKSkKICAgICAgICBleGNlcHQgKE9TRXJy'
    'b3IsIFJ1bnRpbWVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHJlZmVyZW5jZSA9IHsnYXZhaWxhYmxlJzogRmFs'
    'c2UsICdwcm92aWRlcic6ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInfQogICAgICAgIChST09ULydyZWNhbGlicmF0ZScpLnVu'
    'bGluayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgc3RhZ2UoJ3Rva2VuJywgJ9Cf0YDQvtCy0LXRgNGP0Y4g0YLQvtC60LXQ'
    'vSDQuCDRgdC+0YXRgNCw0L3RkdC90L3QvtC1INC/0L7QtNC60LvRjtGH0LXQvdC40LUg0Y3RgtC+0LPQviDRg9GB0YLRgNC+'
    '0LnRgdGC0LLQsC4nLCAyMCkKICAgICAgICBpZGVudGl0eSwgYWRkcmVzcyA9IGVucm9sbCgpCiAgICAgICAgc2NvcGUgPSAn'
    'bGFuJyBpZiBhZGRyZXNzID09IFNFUlZFUl9MQU4gZWxzZSAncHVibGljLWFkZHJlc3MnCiAgICAgICAgc3RhZ2UoJ2RhZW1v'
    'bicsICfQl9Cw0L/Rg9GB0LrQsNGOINGC0YPQvdC90LXQu9GMIElLRXYyINCg0L7RgdGB0LjRjyDihpIg0KDQvtGB0YHQuNGP'
    'LicsIDQwLCBzY29wZT1zY29wZSkKICAgICAgICBkYWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcykKICAgICAgICBl'
    'bnYgPSB7Kipvcy5lbnZpcm9uLCAnU1RST05HU1dBTl9DT05GJzogc3RyKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicpfQogICAg'
    'ICAgIGVudi5wb3AoJ05PVElGWV9TT0NLRVQnLCBOb25lKQogICAgICAgIGRhZW1vbiA9IHN0YXJ0X2RhZW1vbihlbnYpCiAg'
    'ICAgICAgc3RhZ2UoJ2hhbmRzaGFrZScsICfQo9GB0YLQsNC90LDQstC70LjQstCw0Y4g0LfQsNGJ0LjRidGR0L3QvdC+0LUg'
    '0YHQvtC10LTQuNC90LXQvdC40LUg0YHQviBTdGFyRml2ZS4nLCA2MCkKICAgICAgICBzd2FuKCctLWluaXRpYXRlJywgJy0t'
    'Y2hpbGQnLCAnc3RhcmZpdmUtbmV0JywgdGltZW91dD0zNSkKICAgICAgICBpZiBub3QgaW5zdGFsbGVkKCk6CiAgICAgICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignc2Ffbm90X2luc3RhbGxlZCcpCiAgICAgICAgc3RhZ2UoJ2hlYWx0aCcsICfQn9GA'
    '0L7QstC10YDRj9GOINGC0YPQvdC90LXQu9GMINC4INC30LDRidC40YnRkdC90L3Ri9C5INC+0YLQstC10YIg0YHQtdGA0LLQ'
    'tdGA0LAuJywgNzUpCiAgICAgICAgaWYgbm90IGhlYWx0aCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2hl'
    'YWx0aF9mYWlsZWQnKQogICAgICAgIHN0YWdlKCdtZWFzdXJlJywgJ9Cf0YDQvtCy0LXRgNGP0Y4g0L/QtdGA0LXQtNCw0YfR'
    'gyDQtNCw0L3QvdGL0YUg0Lgg0YbQtdC70L7RgdGC0L3QvtGB0YLRjCDRhNCw0LnQu9CwLicsIDg1KQogICAgICAgIG1ldHJp'
    'Y3MgPSBkb3dubG9hZCgpCiAgICAgICAgbWV0cmljc1sncmVmZXJlbmNlJ10gPSByZWZlcmVuY2UKICAgICAgICBzdGFnZSgn'
    'cm91dGluZycsICfQn9C+0LTQutC70Y7Rh9Cw0Y4g0LLQtdGB0Ywg0YLRgNCw0YTQuNC6INC60L7QvNC/0YzRjtGC0LXRgNCw'
    'INC6INCy0YvRhdC+0LTRgyDQsiDQrdGB0YLQvtC90LjQuC4nLCA5MikKICAgICAgICBhY3RpdmF0ZV9mdWxsKGFkZHJlc3Mp'
    'CiAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsICfQn9C+0LTQutC70Y7Rh9C10L3Qvjog0LrQvtC80L/RjNGO0YLQtdGAIOKG'
    'kiBTdGFyRml2ZSDihpIg0K3RgdGC0L7QvdC40Y8uIElQdjYg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9LicsIDEwMCwKICAg'
    'ICAgICAgICAgICBhY3RpdmU9VHJ1ZSwgbWV0cmljcz1tZXRyaWNzLCBzaW5jZT1pbnQodGltZS50aW1lKCkpKQogICAgICAg'
    'IGZhaWx1cmVzID0gMAogICAgICAgIHdoaWxlIG5vdCBTVE9QOgogICAgICAgICAgICBmb3IgXyBpbiByYW5nZSgxMDApOgog'
    'ICAgICAgICAgICAgICAgaWYgU1RPUDoKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgdGltZS5z'
    'bGVlcCguMSkKICAgICAgICAgICAgaWYgU1RPUDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRyeToKICAg'
    'ICAgICAgICAgICAgIG9rID0gZGFlbW9uLnBvbGwoKSBpcyBOb25lIGFuZCBpbnN0YWxsZWQoKSBhbmQgaGVhbHRoKCkKICAg'
    'ICAgICAgICAgICAgIGlmIG9rIGFuZCBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgICAgICAgICAgICAgIHN0YWdlKCdl'
    'Z3Jlc3Nfd2FpdCcsICdTdGFyRml2ZSDQtNC+0YHRgtGD0L/QtdC9OyDQvtC20LjQtNCw0Y4g0LLQvtGB0YHRgtCw0L3QvtCy'
    '0LvQtdC90LjRjyDQstGL0YXQvtC00LAg0LIg0K3RgdGC0L7QvdC40LguJywgOTAsIGFjdGl2ZT1GYWxzZSkKICAgICAgICAg'
    'ICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFJ1bnRpbWVFcnJvciwgc3VicHJvY2Vz'
    'cy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgICAgICAgICBvayA9IEZhbHNlCiAgICAgICAgICAgIGZhaWx1cmVzID0gMCBp'
    'ZiBvayBlbHNlIGZhaWx1cmVzKzEKICAgICAgICAgICAgaWYgZmFpbHVyZXMgPT0gMToKICAgICAgICAgICAgICAgIHN0YWdl'
    'KCdjaGVja2luZycsICfQntGC0LLQtdGCIFN0YXJGaXZlINC30LDQtNC10YDQttC40LLQsNC10YLRgdGPLiDQn9GA0L7QstC1'
    '0YDRj9GOINGC0LXRgdGC0L7QstC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUuJywgOTAsIGFjdGl2ZT1GYWxzZSkKICAgICAg'
    'ICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGlmIGZhaWx1cmVzID49IDI6CiAgICAgICAgICAgICAgICBzdGFnZSgn'
    'cmVwYWlyaW5nJywgJ9Ch0LLRj9C30Ywg0YHQviBTdGFyRml2ZSDQv9C+0YLQtdGA0Y/QvdCwLiDQktC+0YHRgdGC0LDQvdCw'
    '0LLQu9C40LLQsNGOINGC0LXRgdGC0L7QstGL0Lkg0YLRg9C90L3QtdC70YwuJywgNjAsIGFjdGl2ZT1GYWxzZSkKICAgICAg'
    'ICAgICAgICAgIGlmIGRhZW1vbi5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgaW5zaWRlKFsnaXAn'
    'LCAneGZybScsICdzdGF0ZScsICdmbHVzaCddKQogICAgICAgICAgICAgICAgICAgIGluc2lkZShbJ2lwJywgJ3hmcm0nLCAn'
    'cG9saWN5JywgJ2ZsdXNoJ10pCiAgICAgICAgICAgICAgICAgICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnZmx1c2gnLCAn'
    'dGFibGUnLCAnNTE4MjInXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgICAgICAgICAgICAgZGFlbW9uID0gc3RhcnRfZGFlbW9u'
    'KGVudikKICAgICAgICAgICAgICAgIHN3YW4oJy0tdGVybWluYXRlJywgJy0taWtlJywgJ3N0YXJmaXZlJywgY2hlY2s9RmFs'
    'c2UpCiAgICAgICAgICAgICAgICBzd2FuKCctLWluaXRpYXRlJywgJy0tY2hpbGQnLCAnc3RhcmZpdmUtbmV0JywgdGltZW91'
    'dD0zNSkKICAgICAgICAgICAgICAgIGlmIG5vdCBpbnN0YWxsZWQoKSBvciBub3QgaGVhbHRoKCk6CiAgICAgICAgICAgICAg'
    'ICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdyZWNvdmVyeV9mYWlsZWQnKQogICAgICAgICAgICAgICAgZnVsbF9uYW1lc3Bh'
    'Y2UoYWRkcmVzcykKICAgICAgICAgICAgICAgIGlmIG5vdCBlZ3Jlc3NfaGVhbHRoKCk6CiAgICAgICAgICAgICAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCdlc3RvbmlhX2VncmVzc19mYWlsZWQnKQogICAgICAgICAgICAgICAgZmFpbHVyZXMgPSAw'
    'CiAgICAgICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCAn0J/QvtC00LrQu9GO0YfQtdC90L46INC60L7QvNC/0YzRjtGC0LXR'
    'gCDihpIgU3RhckZpdmUg4oaSINCt0YHRgtC+0L3QuNGPLiBJUHY2INC30LDQsdC70L7QutC40YDQvtCy0LDQvS4nLCAxMDAs'
    'IGFjdGl2ZT1UcnVlKQogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yLCBSdW50aW1lRXJyb3IsIHN1YnByb2Nlc3Mu'
    'VGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBjb2RlID0gc3RyKGV4YykgaWYgcmUuZnVsbG1hdGNoKHIiW2Etel9d'
    'ezEsNjR9Iiwgc3RyKGV4YykpIGVsc2UgdHlwZShleGMpLl9fbmFtZV9fCiAgICAgICAgY3VycmVudCA9IHNhdmVkKCkuZ2V0'
    'KCdwaGFzZScsICdwcmVwYXJlJykKICAgICAgICBtZXNzYWdlID0geyd0b2tlbic6ICfQndC1INGD0LTQsNC70L7RgdGMINC/'
    '0L7QtNGC0LLQtdGA0LTQuNGC0Ywg0YLQvtC60LXQvSDQuNC70Lgg0L/QvtC70YPRh9C40YLRjCDRgdC10YDRgtC40YTQuNC6'
    '0LDRgiBTdGFyRml2ZS4nLAogICAgICAgICAgICAgICAgICAgJ2hhbmRzaGFrZSc6ICdTdGFyRml2ZSDQvdC1INC/0L7QtNGC'
    '0LLQtdGA0LTQuNC7INC/0L7QtNC60LvRjtGH0LXQvdC40LUgSUtFdjIuJywKICAgICAgICAgICAgICAgICAgICdtZWFzdXJl'
    'JzogJ9Cf0YDQvtCy0LXRgNC60LAg0L/QtdGA0LXQtNCw0YfQuCDQtNCw0L3QvdGL0YUg0L3QtSDQv9GA0L7RiNC70LAuJywK'
    'ICAgICAgICAgICAgICAgICAgICdyZXBhaXJpbmcnOiAn0JDQstGC0L7QstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1INC9'
    '0LUg0YPQtNCw0LvQvtGB0YwuINCd0LDQttC80LjRgtC1IMKr0J/QvtGH0LjQvdC40YLRjMK7Lid9LmdldChjdXJyZW50LCAn'
    '0KLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC10LvRjCDQvdC1INC30LDQv9GD0YHRgtC40LvRgdGPLiDQndCw0LbQvNC40YLQ'
    'tSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nKQogICAgICAgIHN0YWdlKCdmYWlsZWQnLCBtZXNzYWdlKygnINCY0L3RgtC10YDQ'
    'vdC10YIg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9INC00L4g0L7RgtC60LvRjtGH0LXQvdC40Y8g0YDQtdC20LjQvNCwLicg'
    'aWYgZnVsbF9ndWFyZF9hY3RpdmUoKSBlbHNlICcg0JzQsNGA0YjRgNGD0YLQuNC30LDRhtC40Y8g0LrQvtC80L/RjNGO0YLQ'
    'tdGA0LAg0L3QtSDQv9C10YDQtdC60LvRjtGH0LXQvdCwLicpLCAwLCBhY3RpdmU9RmFsc2UsIGVycm9yX2NvZGU9Y29kZSwg'
    'bWV0cmljcz17fSkKICAgIGZpbmFsbHk6CiAgICAgICAgaWYgZGFlbW9uIGFuZCBkYWVtb24ucG9sbCgpIGlzIE5vbmU6CiAg'
    'ICAgICAgICAgIGRhZW1vbi50ZXJtaW5hdGUoKQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBkYWVtb24ud2Fp'
    'dCh0aW1lb3V0PTYpCiAgICAgICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOgogICAgICAgICAgICAg'
    'ICAgZGFlbW9uLmtpbGwoKTsgZGFlbW9uLndhaXQodGltZW91dD0zKQogICAgICAgIGNsZWFudXAoKQogICAgICAgIGlmIFNU'
    'T1A6CiAgICAgICAgICAgIHN0YWdlKCdvZmYnLCAn0K3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90YvQuSBWUE4g0LLR'
    'i9C60LvRjtGH0LXQvS4nLCAwLCBhY3RpdmU9RmFsc2UpCg=='
)

STARFIVE_EXPERIMENTAL_PY_B64 = (
    'IiIiT3B0LWluIElLRXYyIGJhY2tlbmQuIEVtYmVkZGVkIGluIHZwbmN0bCByZWxlYXNlczsgbm8gaW1wb3J0LXRpbWUgc2lk'
    'ZSBlZmZlY3RzLiIiIgppbXBvcnQgaGFzaGxpYgppbXBvcnQgaXBhZGRyZXNzCmltcG9ydCBqc29uCmltcG9ydCBvcwppbXBv'
    'cnQgcGF0aGxpYgppbXBvcnQgcmUKaW1wb3J0IHNodXRpbAppbXBvcnQgc29ja2V0CmltcG9ydCBzc2wKaW1wb3J0IHN1YnBy'
    'b2Nlc3MKaW1wb3J0IHRpbWUKaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCB1cmxsaWIuZXJyb3IKaW1wb3J0IGh0dHAu'
    'Y2xpZW50CmltcG9ydCB1dWlkCmltcG9ydCBmY250bAppbXBvcnQgcGxhdGZvcm0KaW1wb3J0IGlvCmltcG9ydCB0YXJmaWxl'
    'Cgp0dW5uZWwgPSBOb25lICAjIFdpcmVkIHRvIHRoZSBlbWJlZGRlZCBpc29sYXRlZCB0ZXN0IGJhY2tlbmQgYnkgdnBuY3Rs'
    'LgoKUk9PVCA9IHBhdGhsaWIuUGF0aCgiL2V0Yy92cG4tbWFuYWdlci9zdGFyZml2ZSIpClNUQVRFID0gcGF0aGxpYi5QYXRo'
    'KCIvdmFyL2xpYi92cG4tbWFuYWdlci9zdGFyZml2ZS5qc29uIikKUlVOVElNRSA9IHBhdGhsaWIuUGF0aCgiL3J1bi9ldmdl'
    'bml1bS1pa2V2MiIpClVOSVQgPSAiZXZnZW5pdW0taWtldjIuc2VydmljZSIKTU9OSVRPUiA9ICJldmdlbml1bS1pa2V2Mi1k'
    'aWFnbm9zdGljLnNlcnZpY2UiCkdVQVJEID0gImV2Z2VuaXVtLWlrZXYyLWd1YXJkLnNlcnZpY2UiClRBQkxFID0gImV2Z2Vu'
    'aXVtX2lrZXYyX2d1YXJkIgpVUkkgPSAidW5peDovLy9ydW4vZXZnZW5pdW0taWtldjIvY2hhcm9uLnZpY2kiClNFUlZFUiA9'
    'ICIxMDkuMTk0LjY3LjE1OSIKSEVBTFRIID0gImh0dHBzOi8vMTAuNzcuMC4xOjg0NDMiClJFUUlEID0gNzcKRElSRUNUX1BP'
    'UlQgPSA4NDQzCkRJUkVDVF9NQVJLID0gMHhFNzcxCkRFTElWRVJZID0gImV2Z2VuaXVtLWlrZXYyLWRlbGl2ZXJ5LnNlcnZp'
    'Y2UiClVTRVJTUEFDRSA9IHBhdGhsaWIuUGF0aCgnL29wdC92cG4tbWFuYWdlci9pa2V2Mi11c2Vyc3BhY2UnKQpVU0VSU1BB'
    'Q0VfVkVSU0lPTiA9ICc2LjEuMC1vcGVuc3NsMy41LjktbXVzbDEuMi42LTEnClVTRVJTUEFDRV9TSEEyNTYgPSAnZWU2N2Vm'
    'NjBlZDE3ZDY2NDViZDJmODExY2U2ZmViNjFlYWUwZjljNjkwODI5YTExMGRhZDQ5YTEwMDFhZDQzYycKVVNFUlNQQUNFX1VS'
    'TCA9ICdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vdmVsaWtpaWV2Z2VuaXVzdWx0aW1hdGUvRXZnZW5pdW1f'
    'TmV0d29ya19MaW51eC9tYWluL2Rpc3Qvc3RhcmZpdmUtdXNlcnNwYWNlLXg4Nl82NC0nICsgVVNFUlNQQUNFX1ZFUlNJT04g'
    'KyAnLnRhci5neicKVFVOID0gJ2lwc2VjMCcKSUtFX01BUksgPSAweEU3NzIKCgpkZWYgYmFja2VuZCgpOgogICAgY2hvaWNl'
    'PXN0b3JlZCgpLmdldCgnaXBzZWNfYmFja2VuZCcpCiAgICBpZiBjaG9pY2UgaW4gKCdrZXJuZWwnLCd1c2Vyc3BhY2UnKTog'
    'cmV0dXJuIGNob2ljZQogICAgdHJ5OiBzdGVhbW9zPSdzdGVhbW9zJyBpbiBwYXRobGliLlBhdGgoJy9ldGMvb3MtcmVsZWFz'
    'ZScpLnJlYWRfdGV4dCgpLmxvd2VyKCkKICAgIGV4Y2VwdCBPU0Vycm9yOiBzdGVhbW9zPUZhbHNlCiAgICByZXR1cm4gJ3Vz'
    'ZXJzcGFjZScgaWYgc3RlYW1vcyBlbHNlICdrZXJuZWwnCgoKZGVmIHVzZXJzcGFjZV9yZWFkeSgpOgogICAgdHJ5OgogICAg'
    'ICAgIG1hbmlmZXN0PWpzb24ubG9hZHMoKFVTRVJTUEFDRS8nQlVJTEQuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIHJl'
    'dHVybiBtYW5pZmVzdC5nZXQoJ3ZlcnNpb24nKT09VVNFUlNQQUNFX1ZFUlNJT04gYW5kIGFsbCgKICAgICAgICAgICAgKFVT'
    'RVJTUEFDRS9uYW1lKS5pc19maWxlKCkgYW5kIG9zLmFjY2VzcyhVU0VSU1BBQ0UvbmFtZSxvcy5YX09LKQogICAgICAgICAg'
    'ICBmb3IgbmFtZSBpbiAoJ2NoYXJvbicsJ3N3YW5jdGwnKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTogcmV0'
    'dXJuIEZhbHNlCgoKZGVmIGF2YWlsYWJsZSgpOgogICAgcmV0dXJuIHVzZXJzcGFjZV9yZWFkeSgpIGlmIGJhY2tlbmQoKT09'
    'J3VzZXJzcGFjZScgZWxzZSBib29sKHNodXRpbC53aGljaCgnc3dhbmN0bCcpKQoKCmRlZiB2YWxpZF90dW4oKToKICAgIHRy'
    'eTogcmV0dXJuIGJvb2woaW50KHBhdGhsaWIuUGF0aCgnL3N5cy9jbGFzcy9uZXQnLFRVTiwndHVuX2ZsYWdzJykucmVhZF90'
    'ZXh0KCkuc3RyaXAoKSwxNikmMSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTogcmV0dXJuIEZhbHNlCgoKZGVm'
    'IHNlbGVjdF9iYWNrZW5kKHZhbHVlKToKICAgIGlmIGFjdGl2ZV9ndWFyZCgpIG9yIGNvbm5lY3RlZCgpOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0LLRi9C60LvRjtGH0Lgg0Y3QutGB0L/QtdGA0LjQvNC10L3RgtCw'
    '0LvRjNC90L7QtSDQv9C+0LTQutC70Y7Rh9C10L3QuNC1LicpCiAgICBwYXRjaF9zdGF0ZSh7J2lwc2VjX2JhY2tlbmQnOnZh'
    'bHVlfSkKICAgIHByaW50KCfQktGL0LHRgNCw0L0g0YDQtdC20LjQvDogJysoJ0lQc2VjINGH0LXRgNC10LcgVFVOJyBpZiB2'
    'YWx1ZT09J3VzZXJzcGFjZScgZWxzZSAnSVBzZWMg0LIg0Y/QtNGA0LUnKSkKCgpkZWYgaW5zdGFsbF91c2Vyc3BhY2UoKToK'
    'ICAgIGlmIHVzZXJzcGFjZV9yZWFkeSgpOiByZXR1cm4KICAgIGlmIGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ9Ch0L3QsNGH0LDQu9CwINCy0YvQutC70Y7Rh9C4INGN0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0Lkg0YDQ'
    'tdC20LjQvCwg0LfQsNGC0LXQvCDQv9C+0LTQs9C+0YLQvtCy0Ywg0LTQstC40LbQvtC6LicpCiAgICBpZiBwbGF0Zm9ybS5t'
    'YWNoaW5lKCkubG93ZXIoKSBub3QgaW4gKCd4ODZfNjQnLCdhbWQ2NCcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    '0JDQstGC0L7QvdC+0LzQvdGL0Lkg0LTQstC40LbQvtC6INC/0L7QutCwINGB0L7QsdGA0LDQvSDRgtC+0LvRjNC60L4g0LTQ'
    'u9GPIHg4Nl82NCAoU3RlYW0gRGVjaykuJykKICAgIG9wZW5lcj11cmxsaWIucmVxdWVzdC5idWlsZF9vcGVuZXIodXJsbGli'
    'LnJlcXVlc3QuUHJveHlIYW5kbGVyKHt9KSkKICAgIHdpdGggb3BlbmVyLm9wZW4oVVNFUlNQQUNFX1VSTCx0aW1lb3V0PTQ1'
    'KSBhcyByZXNwb25zZTogYmxvYj1yZXNwb25zZS5yZWFkKDMyKjEwMjQqMTAyNCsxKQogICAgaWYgbGVuKGJsb2IpPjMyKjEw'
    'MjQqMTAyNCBvciBoYXNobGliLnNoYTI1NihibG9iKS5oZXhkaWdlc3QoKSE9VVNFUlNQQUNFX1NIQTI1NjoKICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ9Ca0L7QvdGC0YDQvtC70YzQvdCw0Y8g0YHRg9C80LzQsCDQsNCy0YLQvtC90L7QvNC90L7Q'
    's9C+INC00LLQuNC20LrQsCDQvdC1INGB0L7QstC/0LDQu9CwLicpCiAgICBpbnN0YWxsX3VzZXJzcGFjZV9hcmNoaXZlKGJs'
    'b2IpCgoKZGVmIGluc3RhbGxfdXNlcnNwYWNlX2FyY2hpdmUoYmxvYik6CiAgICBleHBlY3RlZD17J2NoYXJvbicsJ3N3YW5j'
    'dGwnLCdCVUlMRC5qc29uJywnTElDRU5TRS5zdHJvbmdzd2FuJywnTElDRU5TRS5vcGVuc3NsJywnTElDRU5TRS5tdXNsJ30K'
    'ICAgIHdpdGggdGFyZmlsZS5vcGVuKGZpbGVvYmo9aW8uQnl0ZXNJTyhibG9iKSxtb2RlPSdyOmd6JykgYXMgYXJjaGl2ZToK'
    'ICAgICAgICBtZW1iZXJzPWFyY2hpdmUuZ2V0bWVtYmVycygpCiAgICAgICAgaWYgbGVuKG1lbWJlcnMpIT1sZW4oZXhwZWN0'
    'ZWQpIG9yIHt4Lm5hbWUgZm9yIHggaW4gbWVtYmVyc30hPWV4cGVjdGVkOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90YvQuSDRgdC+0YHRgtCw0LIg0LDQstGC0L7QvdC+0LzQvdC+0LPQviDQtNCy0LjQ'
    'ttC60LAuJykKICAgICAgICBpZiBzdW0oeC5zaXplIGZvciB4IGluIG1lbWJlcnMpPjQ4KjEwMjQqMTAyNCBvciBhbnkobm90'
    'IHguaXNmaWxlKCkgb3IgeC5zaXplPjMyKjEwMjQqMTAyNCBmb3IgeCBpbiBtZW1iZXJzKToKICAgICAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCfQndC10LHQtdC30L7Qv9Cw0YHQvdGL0Lkg0LDRgNGF0LjQsiDQsNCy0YLQvtC90L7QvNC90L7Qs9C+'
    'INC00LLQuNC20LrQsC4nKQogICAgICAgIG1ldGFkYXRhPWpzb24ubG9hZChhcmNoaXZlLmV4dHJhY3RmaWxlKCdCVUlMRC5q'
    'c29uJykpCiAgICAgICAgaWYgbWV0YWRhdGEuZ2V0KCd2ZXJzaW9uJykhPVVTRVJTUEFDRV9WRVJTSU9OOiByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90LDRjyDQstC10YDRgdC40Y8g0LTQstC40LbQutCwLicpCiAgICAgICAg'
    'VVNFUlNQQUNFLm1rZGlyKHBhcmVudHM9VHJ1ZSxtb2RlPTBvNzU1LGV4aXN0X29rPVRydWUpCiAgICAgICAgZm9yIG1lbWJl'
    'ciBpbiBtZW1iZXJzOgogICAgICAgICAgICB0YXJnZXQ9VVNFUlNQQUNFL21lbWJlci5uYW1lCiAgICAgICAgICAgIGlmIHRh'
    'cmdldC5pc19zeW1saW5rKCk6IHJhaXNlIFJ1bnRpbWVFcnJvcign0J3QtdC00L7Qv9GD0YHRgtC40LzQsNGPINGB0YHRi9C7'
    '0LrQsCDQsiDQutCw0YLQsNC70L7Qs9C1INC00LLQuNC20LrQsC4nKQogICAgICAgICAgICB0ZW1wPXRhcmdldC53aXRoX3N1'
    'ZmZpeCh0YXJnZXQuc3VmZml4KycubmV3JykKICAgICAgICAgICAgZmQ9b3Mub3Blbih0ZW1wLG9zLk9fV1JPTkxZfG9zLk9f'
    'Q1JFQVR8b3MuT19UUlVOQ3xvcy5PX05PRk9MTE9XLDBvNjAwKQogICAgICAgICAgICB3aXRoIG9zLmZkb3BlbihmZCwnd2In'
    'KSBhcyBmOiBmLndyaXRlKGFyY2hpdmUuZXh0cmFjdGZpbGUobWVtYmVyKS5yZWFkKCkpCiAgICAgICAgICAgIHRlbXAuY2ht'
    'b2QoMG83NTUgaWYgbWVtYmVyLm5hbWUgaW4gKCdjaGFyb24nLCdzd2FuY3RsJykgZWxzZSAwbzY0NCkKICAgICAgICAgICAg'
    'dGVtcC5yZXBsYWNlKHRhcmdldCkKCgpkZWYgZmFpbHVyZV9jb2RlKGV4Yyk6CiAgICB0ZXh0ID0gc3RyKGV4YykubG93ZXIo'
    'KQogICAgaWYgaXNpbnN0YW5jZShleGMsIHNzbC5TU0xDZXJ0VmVyaWZpY2F0aW9uRXJyb3IpOiByZXR1cm4gJ2NlcnRpZmlj'
    'YXRlJwogICAgaWYgaXNpbnN0YW5jZShleGMsIHNzbC5TU0xFcnJvcik6IHJldHVybiAndGxzJwogICAgaWYgaXNpbnN0YW5j'
    'ZShleGMsIChUaW1lb3V0RXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpKTogcmV0dXJuICd0aW1lb3V0JwogICAg'
    'aWYgJ3VuYWJsZSB0byBpbnN0YWxsJyBpbiB0ZXh0IGFuZCAnaXBzZWMgc2EnIGluIHRleHQ6IHJldHVybiAna2VybmVsX2lw'
    'c2VjX3VuYXZhaWxhYmxlJwogICAgaWYgcmUuc2VhcmNoKHIiYXV0aGVudGljYXRpb25bXlxuXSooZmFpbGVkfGZhaWx1cmUp'
    'Iix0ZXh0KTogcmV0dXJuICdhdXRoZW50aWNhdGlvbicKICAgIGlmICdwcm9wb3NhbCcgaW4gdGV4dDogcmV0dXJuICdwcm9w'
    'b3NhbCcKICAgIGlmICdyZXRyYW5zbWl0JyBpbiB0ZXh0IG9yICd0aW1lZCBvdXQnIGluIHRleHQ6IHJldHVybiAndGltZW91'
    'dCcKICAgIGlmICdwZXJtaXNzaW9uJyBpbiB0ZXh0IG9yICdvcGVyYXRpb24gbm90IHBlcm1pdHRlZCcgaW4gdGV4dDogcmV0'
    'dXJuICdwZXJtaXNzaW9uJwogICAgaWYgaXNpbnN0YW5jZShleGMsIE9TRXJyb3IpOiByZXR1cm4gJ25ldHdvcmsnCiAgICBy'
    'ZXR1cm4gJ290aGVyJwoKCmRlZiBxdWV1ZV9jb25uZWN0aW9uKHN0YWdlLCBlcnJvciwgZWxhcHNlZD0wKToKICAgIGlmIG5v'
    'dCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOiByZXR1cm4KICAgIGRpcmVjdG9yeSA9IFJPT1QgLyAnb3V0Ym94JwogICAg'
    'ZGlyZWN0b3J5Lm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGZpbGVzID0gc29y'
    'dGVkKGRpcmVjdG9yeS5nbG9iKCcqLmpzb24nKSwga2V5PWxhbWJkYSBwOiBwLnN0YXQoKS5zdF9tdGltZSkKICAgIGZvciBv'
    'bGQgaW4gZmlsZXNbOi05XTogb2xkLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICByZXBvcnRfaWQgPSB1dWlkLnV1aWQ0'
    'KCkuaGV4CiAgICBib2R5ID0geydzY2hlbWEnOjEsICdldmVudCc6J2Nvbm5lY3Rpb25fZGlhZ25vc3RpYycsICdtYW5hZ2Vy'
    'JzonMC4yLjIzJywKICAgICAgICAgICAgJ3RpbWUnOmludCh0aW1lLnRpbWUoKSksCiAgICAgICAgICAgICdyZXBvcnRfaWQn'
    'OnJlcG9ydF9pZCwgJ3N0YWdlJzpzdGFnZSwgJ2Vycm9yJzplcnJvciwKICAgICAgICAgICAgJ2VsYXBzZWRfbXMnOm1pbigx'
    'ODAwMDAwLCBtYXgoMCwgaW50KGVsYXBzZWQpKSksCiAgICAgICAgICAgICdndWFyZCc6YWN0aXZlX2d1YXJkKCksICdpcHNl'
    'Yyc6Y29ubmVjdGVkKCksICdpcHNlY19iYWNrZW5kJzpiYWNrZW5kKCl9CiAgICB0cnk6CiAgICAgICAgIyBTZW5kIGNvdW50'
    'cyBhbmQgZml4ZWQgY2F0ZWdvcmllcywgbmV2ZXIgcmF3IGpvdXJuYWwgbGluZXMgb3IgYWRkcmVzc2VzLgogICAgICAgIGpv'
    'dXJuYWw9Y21kKFsnam91cm5hbGN0bCcsJy11JyxVTklULCctLXNpbmNlJywnMiBtaW51dGVzIGFnbycsJy1uJywnODAnLCct'
    'LW5vLXBhZ2VyJ10sY2hlY2s9RmFsc2UsdGltZW91dD0zKS5zdGRvdXQubG93ZXIoKQogICAgICAgIGJvZHkudXBkYXRlKGlr'
    'ZV9yZWNlaXZlZD1qb3VybmFsLmNvdW50KCdyZWNlaXZlZCBwYWNrZXQ6JyksCiAgICAgICAgICAgICAgICAgICAgaWtlX3Nl'
    'bnQ9am91cm5hbC5jb3VudCgnc2VuZGluZyBwYWNrZXQ6JyksCiAgICAgICAgICAgICAgICAgICAgcmV0cmFuc21pdHM9am91'
    'cm5hbC5jb3VudCgncmV0cmFuc21pdCcpKQogICAgICAgIGlmIGVycm9yICE9ICdub25lJzoKICAgICAgICAgICAgaWYgJ3Vu'
    'YWJsZSB0byBpbnN0YWxsIGluYm91bmQgYW5kIG91dGJvdW5kIGlwc2VjIHNhJyBpbiBqb3VybmFsOiBib2R5WydlcnJvcidd'
    'PSdrZXJuZWxfaXBzZWNfdW5hdmFpbGFibGUnCiAgICAgICAgICAgIGVsaWYgcmUuc2VhcmNoKHInYXV0aGVudGljYXRpb25b'
    'XlxuXSooZmFpbGVkfGZhaWx1cmUpJyxqb3VybmFsKTogYm9keVsnZXJyb3InXT0nYXV0aGVudGljYXRpb24nCiAgICAgICAg'
    'ICAgIGVsaWYgJ25vIHByb3Bvc2FsJyBpbiBqb3VybmFsOiBib2R5WydlcnJvciddPSdwcm9wb3NhbCcKICAgICAgICBvc19y'
    'ZWxlYXNlPXBhdGhsaWIuUGF0aCgnL2V0Yy9vcy1yZWxlYXNlJykucmVhZF90ZXh0KCkubG93ZXIoKQogICAgICAgIGJvZHlb'
    'J3BsYXRmb3JtJ109J3N0ZWFtb3MnIGlmICdzdGVhbW9zJyBpbiBvc19yZWxlYXNlIGVsc2UgKCdmZWRvcmEnIGlmICdmZWRv'
    'cmEnIGluIG9zX3JlbGVhc2UgZWxzZSAoJ2FyY2gnIGlmICdhcmNoJyBpbiBvc19yZWxlYXNlIGVsc2UgJ290aGVyJykpCiAg'
    'ICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICB3cml0ZShkaXJlY3RvcnkgLyAocmVwb3J0X2lkICsgJy5qc29uJyksIGpz'
    'b24uZHVtcHMoYm9keSkpCiAgICBwYXRjaF9zdGF0ZSh7ICdkZWxpdmVyeV9zdGF0dXMnOidxdWV1ZWQnLCAnZGVsaXZlcnlf'
    'ZXJyb3InOicnfSkKICAgIGtpY2tfZGVsaXZlcnkoKQoKCmRlZiBraWNrX2RlbGl2ZXJ5KCk6CiAgICBpZiBzdG9yZWQoKS5n'
    'ZXQoJ3RlbGVtZXRyeScpOgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JywnLS1uby1ibG9jaycsREVMSVZFUlld'
    'LCBjaGVjaz1GYWxzZSkKCgpkZWYgZGlyZWN0X2VuZHBvaW50KGJvZHkpOgogICAgUk9PVC5ta2Rpcihtb2RlPTBvNzAwLHBh'
    'cmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd2l0aCAoUk9PVC8iZGVsaXZlcnkubG9jayIpLm9wZW4oImEiKSBhcyBs'
    'b2NrOgogICAgICAgIGZjbnRsLmZsb2NrKGxvY2ssZmNudGwuTE9DS19FWCkKICAgICAgICByZXR1cm4gX2RpcmVjdF9lbmRw'
    'b2ludChib2R5KQoKCmRlZiBfZGlyZWN0X2VuZHBvaW50KGJvZHkpOgogICAgIyBPbmx5IHRoaXMgcm9vdC1vd25lZCBzb2Nr'
    'ZXQgY2FuIGJ5cGFzcyB0aGUgZ3VhcmQ7IG5ldmVyIGVudmlyb25tZW50IHByb3hpZXMuCiAgICAjIFRoZSBtYXJrZWQgc29j'
    'a2V0IHNlbGVjdHMgdGhlIHBoeXNpY2FsIHJvdXRlIGJlZm9yZSBJUHNlYyBzb3VyY2Ugc2VsZWN0aW9uLgogICAgc29jayA9'
    'IE5vbmUKICAgIGNvbm5lY3Rpb24gPSBOb25lCiAgICBzdGFnZSA9ICdjcmVkZW50aWFscycKICAgIHRyeToKICAgICAgICBj'
    'b250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FmaWxlPXN0cihST09UIC8gJ2NhLnBlbScpKQogICAgICAg'
    'IGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09UIC8gJ2NsaWVudC5wZW0nKSxzdHIoUk9PVCAvICdjbGllbnQta2V5'
    'LnBlbScpKQogICAgICAgIHN0YWdlID0gJ3JvdXRlJwogICAgICAgIHJ1bGU9Wydwcmlvcml0eScsJzkwJywnZndtYXJrJyxz'
    'dHIoRElSRUNUX01BUkspLCd0bycsU0VSVkVSKycvMzInLCdsb29rdXAnLCdtYWluJ10KICAgICAgICAjIENsZWFuIHVwIGFu'
    'IGV4YWN0IHN0YWxlIHJ1bGUgbGVmdCBieSBwcm9jZXNzIHRlcm1pbmF0aW9uIGJlZm9yZSBhZGRpbmcgaXQuCiAgICAgICAg'
    'Y21kKFsnaXAnLCdydWxlJywnZGVsJywqcnVsZV0sY2hlY2s9RmFsc2UpCiAgICAgICAgY21kKFsnaXAnLCdydWxlJywnYWRk'
    'JywqcnVsZV0pCiAgICAgICAgc29jayA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX1NUUkVB'
    'TSkKICAgICAgICBzdGFnZSA9ICd0Y3AnCiAgICAgICAgc29jay5zZXR0aW1lb3V0KDYpCiAgICAgICAgc29jay5zZXRzb2Nr'
    'b3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fTUFSSywgRElSRUNUX01BUkspCiAgICAgICAgc29jay5jb25uZWN0'
    'KChTRVJWRVIsRElSRUNUX1BPUlQpKQogICAgICAgIHN0YWdlID0gJ3RscycKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBf'
    'c29ja2V0KHNvY2ssc2VydmVyX2hvc3RuYW1lPVNFUlZFUikKICAgICAgICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRU'
    'UENvbm5lY3Rpb24oU0VSVkVSLERJUkVDVF9QT1JULHRpbWVvdXQ9NikKICAgICAgICBjb25uZWN0aW9uLnNvY2sgPSB0bHMK'
    'ICAgICAgICBzdGFnZSA9ICdodHRwJwogICAgICAgIGRhdGEgPSBqc29uLmR1bXBzKGJvZHksc2VwYXJhdG9ycz0oJywnLCc6'
    'JykpLmVuY29kZSgpCiAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdQT1NUJywnL3JlcG9ydCcsYm9keT1kYXRhLAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJzPXsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbicsJ0Nvbm5l'
    'Y3Rpb24nOidjbG9zZSd9KQogICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlvbi5nZXRyZXNwb25zZSgpCiAgICAgICAgcmVw'
    'bHkgPSBqc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQoNDA5NikpCiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBv'
    'ciByZXBseS5nZXQoJ2FjY2VwdGVkJykgaXMgbm90IFRydWU6CiAgICAgICAgICAgIGVycm9yPVJ1bnRpbWVFcnJvcignUmVw'
    'b3J0IHJlamVjdGVkJykKICAgICAgICAgICAgZXJyb3IuZGVsaXZlcnlfY29kZT17NDAzOidkaXNhYmxlZCcsNDAwOidpbnZh'
    'bGlkX3JlcG9ydCd9LmdldChyZXNwb25zZS5zdGF0dXMsJ3JlamVjdGVkJykKICAgICAgICAgICAgcmFpc2UgZXJyb3IKICAg'
    'ICAgICBpZiBib2R5LmdldCgncmVwb3J0X2lkJykgYW5kIHJlcGx5LmdldCgncmVwb3J0X2lkJykgIT0gYm9keVsncmVwb3J0'
    'X2lkJ106CiAgICAgICAgICAgIGVycm9yPVJ1bnRpbWVFcnJvcignQWNrbm93bGVkZ2VtZW50IG1pc21hdGNoJykKICAgICAg'
    'ICAgICAgZXJyb3IuZGVsaXZlcnlfY29kZT0nYWNrX21pc21hdGNoJwogICAgICAgICAgICByYWlzZSBlcnJvcgogICAgICAg'
    'IHJldHVybiByZXBseQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgcGF0Y2hfc3RhdGUoeyAnZGVsaXZl'
    'cnlfc3RhdHVzJzoncmV0cnknLAogICAgICAgICAgICAgICdkZWxpdmVyeV9lcnJvcic6c3RhZ2UrJ18nK2dldGF0dHIoZXhj'
    'LCdkZWxpdmVyeV9jb2RlJyxmYWlsdXJlX2NvZGUoZXhjKSl9KQogICAgICAgIHJhaXNlCiAgICBmaW5hbGx5OgogICAgICAg'
    'IGlmIGNvbm5lY3Rpb246IGNvbm5lY3Rpb24uY2xvc2UoKQogICAgICAgIGlmIHNvY2s6IHNvY2suY2xvc2UoKQogICAgICAg'
    'ICMgUmVtb3ZlIG91ciBleGFjdCBzY29wZWQgcnVsZSwgaW5jbHVkaW5nIG9uIGZhaWxlZCBUQ1AvVExTIGhhbmRzaGFrZXMu'
    'CiAgICAgICAgY21kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc5MCcsJ2Z3bWFyaycsc3RyKERJUkVDVF9NQVJL'
    'KSwKICAgICAgICAgICAgICd0bycsU0VSVkVSKycvMzInLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCgoKZGVmIGRl'
    'bGl2ZXJfcmVwb3J0KGJvZHkpOgogICAgaWYgbm90IHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jyk6IHJldHVybiBGYWxzZQog'
    'ICAgcGF0Y2hfc3RhdGUoeyAnZGVsaXZlcnlfc3RhdHVzJzonc2VuZGluZycsICdkZWxpdmVyeV9hdHRlbXB0JzppbnQodGlt'
    'ZS50aW1lKCkpfSkKICAgIGJvZHk9eyoqYm9keSwgJ3ByZXZpb3VzX2RlbGl2ZXJ5X2Vycm9yJzpzdG9yZWQoKS5nZXQoJ2Rl'
    'bGl2ZXJ5X2Vycm9yJywnJyl9CiAgICBkaXJlY3RfZW5kcG9pbnQoYm9keSkKICAgIHBhdGNoX3N0YXRlKHsgJ2RlbGl2ZXJ5'
    'X3N0YXR1cyc6J3NlbnQnLCAnZGVsaXZlcnlfZXJyb3InOicnLAogICAgICAgICAgJ2xhc3RfcmVwb3J0Jzp0aW1lLnN0cmZ0'
    'aW1lKCclWS0lbS0lZCAlSDolTTolUyBVVEMnLHRpbWUuZ210aW1lKCkpfSkKICAgIHJldHVybiBUcnVlCgoKZGVmIGRlbGl2'
    'ZXJ5X3dvcmtlcigpOgogICAgZGVsYXk9MTUKICAgIHdoaWxlIHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jyk6CiAgICAgICAg'
    'ZmlsZXM9bGlzdCgoUk9PVC8nb3V0Ym94JykuZ2xvYignKi5qc29uJykpCiAgICAgICAgaWYgbm90IGZpbGVzIGFuZCBub3Qg'
    'UEVORElOR19URVNULmV4aXN0cygpOiByZXR1cm4KICAgICAgICB0cnk6CiAgICAgICAgICAgIGZvciBwYXRoIGluIGZpbGVz'
    'OgogICAgICAgICAgICAgICAgaWYgZGVsaXZlcl9yZXBvcnQoanNvbi5sb2FkcyhwYXRoLnJlYWRfdGV4dCgpKSk6IHBhdGgu'
    'dW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgICAgICAgICAgZmx1c2hfdGVzdF9yZXBvcnQoKQogICAgICAgICAgICBkZWxh'
    'eT0xNQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHRpbWUuc2xlZXAoZGVsYXkpCiAgICAgICAgICAg'
    'IGRlbGF5PW1pbihkZWxheSoyLDMwMCkKCgpkZWYgY21kKGFyZ3MsIGNoZWNrPVRydWUsIHRpbWVvdXQ9MjAsIGRhdGE9Tm9u'
    'ZSk6CiAgICBjcCA9IHN1YnByb2Nlc3MucnVuKFtzdHIoeCkgZm9yIHggaW4gYXJnc10sIGlucHV0PWRhdGEsIHRleHQ9VHJ1'
    'ZSwKICAgICAgICAgICAgICAgICAgICAgICAgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQ'
    'RSwgdGltZW91dD10aW1lb3V0KQogICAgaWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6CiAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKChjcC5zdGRlcnIgb3IgY3Auc3Rkb3V0IG9yICJjb21tYW5kIGZhaWxlZCIpWy0xMjAwOl0pCiAgICByZXR1cm4g'
    'Y3AKCgpkZWYgd3JpdGUocGF0aCwgZGF0YSwgbW9kZT0wbzYwMCk6CiAgICBwYXRoID0gcGF0aGxpYi5QYXRoKHBhdGgpCiAg'
    'ICBwYXRoLnBhcmVudC5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICB0bXAgPSBw'
    'YXRoLndpdGhfc3VmZml4KHBhdGguc3VmZml4ICsgIi5uZXciKQogICAgZmQgPSBvcy5vcGVuKHRtcCwgb3MuT19XUk9OTFkg'
    'fCBvcy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIG1vZGUpCiAgICB3aXRoIG9zLmZkb3BlbihmZCwg'
    'InciKSBhcyBmOgogICAgICAgIGYud3JpdGUoZGF0YSkKICAgIHRtcC5jaG1vZChtb2RlKQogICAgdG1wLnJlcGxhY2UocGF0'
    'aCkKCgpkZWYgc3RvcmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoU1RBVEUucmVhZF90ZXh0KCkp'
    'CiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoKCmRlZiBzYXZlKHN0YXRlKToK'
    'ICAgIHdyaXRlKFNUQVRFLCBqc29uLmR1bXBzKHN0YXRlLCBlbnN1cmVfYXNjaWk9RmFsc2UpICsgIlxuIikKCgpkZWYgcGF0'
    'Y2hfc3RhdGUoY2hhbmdlcyk6CiAgICAjIEtlZXAgc2VuZGVyIHVwZGF0ZXMgZnJvbSBvdmVyd3JpdGluZyBhIGNvbmN1cnJl'
    'bnQgdGVsZW1ldHJ5LW9mZiBvcGVyYXRpb24uCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAscGFyZW50cz1UcnVlLGV4aXN0'
    'X29rPVRydWUpCiAgICB3aXRoIChST09ULydzdGF0ZS5sb2NrJykub3BlbignYScpIGFzIGxvY2s6CiAgICAgICAgZmNudGwu'
    'ZmxvY2sobG9jayxmY250bC5MT0NLX0VYKQogICAgICAgIHNhdmUoeyoqc3RvcmVkKCksKipjaGFuZ2VzfSkKCgpkZWYgYWN0'
    'aXZlX2d1YXJkKCk6CiAgICBpZiBub3Qgc2h1dGlsLndoaWNoKCJuZnQiKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHJl'
    'dHVybiBjbWQoWyJuZnQiLCAibGlzdCIsICJ0YWJsZSIsICJpbmV0IiwgVEFCTEVdLCBjaGVjaz1GYWxzZSkucmV0dXJuY29k'
    'ZSA9PSAwCgoKZGVmIHN3YW4oKmFyZ3MsIGNoZWNrPVRydWUsIHRpbWVvdXQ9MjApOgogICAgYmluYXJ5ID0gc3RyKFVTRVJT'
    'UEFDRS8ic3dhbmN0bCIpIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSIgZWxzZSAoc2h1dGlsLndoaWNoKCJzd2FuY3RsIikg'
    'b3IgIi91c3Ivc2Jpbi9zd2FuY3RsIikKICAgIHJldHVybiBjbWQoW2JpbmFyeSwgKmFyZ3MsICItLXVyaSIsIFVSSV0sIGNo'
    'ZWNrPWNoZWNrLCB0aW1lb3V0PXRpbWVvdXQpCgoKZGVmIGNvbm5lY3RlZCgpOgogICAgaWYgbm90IFJVTlRJTUUuam9pbnBh'
    'dGgoImNoYXJvbi52aWNpIikuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICB0cnk6CiAgICAgICAgY3AgPSBz'
    'd2FuKCItLWxpc3Qtc2FzIiwgIi0tcmF3IiwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MykKICAgICAgICByZXR1cm4gKGNwLnJl'
    'dHVybmNvZGUgPT0gMCBhbmQgInN0YXRlPUlOU1RBTExFRCIgaW4gY3Auc3Rkb3V0IGFuZCAic3RhdGU9RVNUQUJMSVNIRUQi'
    'IGluIGNwLnN0ZG91dAogICAgICAgICAgICAgICAgYW5kIChiYWNrZW5kKCkhPSd1c2Vyc3BhY2UnIG9yIHZhbGlkX3R1bigp'
    'KSkKICAgIGV4Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNl'
    'CgoKZGVmIHdhaXRfdXNlcnNwYWNlKCk6CiAgICBpZiBiYWNrZW5kKCkhPSd1c2Vyc3BhY2UnOiByZXR1cm4KICAgIGZvciBf'
    'IGluIHJhbmdlKDUwKToKICAgICAgICBpZiB2YWxpZF90dW4oKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAg'
    'aWYgc3dhbignLS1zdGF0cycsY2hlY2s9RmFsc2UsdGltZW91dD0xKS5yZXR1cm5jb2RlPT0wOiByZXR1cm4KICAgICAgICAg'
    'ICAgZXhjZXB0IChPU0Vycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOiBwYXNzCiAgICAgICAgdGltZS5zbGVlcCgu'
    'MSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignVFVOLdC00LLQuNC20L7QuiDQvdC1INGB0L7Qt9C00LDQuyDRgdC+0LHRgdGC'
    '0LLQtdC90L3Ri9C5INC40L3RgtC10YDRhNC10LnRgSDQuCBWSUNJLdGB0L7QutC10YIuJykKCgpkZWYgc3RhdHVzKCk6CiAg'
    'ICBzdGF0ZSA9IHN0b3JlZCgpCiAgICBndWFyZCA9IGFjdGl2ZV9ndWFyZCgpCiAgICBsaXZlID0gY29ubmVjdGVkKCkKICAg'
    'IHRva2VuX3N0YXRlID0gdHVubmVsLnN0YXR1cygpIGlmIHR1bm5lbCBlbHNlIHt9CiAgICBpZiB0b2tlbl9zdGF0ZS5nZXQo'
    'J2d1YXJkJyk6CiAgICAgICAgZ3VhcmQgPSBUcnVlCiAgICAgICAgbGl2ZSA9IHRva2VuX3N0YXRlLmdldCgnYWN0aXZlJywg'
    'RmFsc2UpCiAgICByZXR1cm4geyJ0dW5uZWwiOiB0b2tlbl9zdGF0ZSwKICAgICAgICAgICAgImNvbmZpZ3VyZWQiOiBST09U'
    'LmpvaW5wYXRoKCJwcm9maWxlLmpzb24iKS5leGlzdHMoKSwKICAgICAgICAgICAgImF2YWlsYWJsZSI6IGF2YWlsYWJsZSgp'
    'LCAiaXBzZWNfYmFja2VuZCI6YmFja2VuZCgpLCAidXNlcnNwYWNlX3ZlcnNpb24iOlVTRVJTUEFDRV9WRVJTSU9OLAogICAg'
    'ICAgICAgICAiYWN0aXZlIjogbGl2ZSwgImd1YXJkIjogZ3VhcmQsCiAgICAgICAgICAgICJ0ZWxlbWV0cnkiOiBib29sKHN0'
    'YXRlLmdldCgidGVsZW1ldHJ5IiwgRmFsc2UpKSwKICAgICAgICAgICAgInBoYXNlIjogImNvbm5lY3RlZCIgaWYgbGl2ZSBl'
    'bHNlICgiYmxvY2tlZCIgaWYgZ3VhcmQgZWxzZSAib2ZmIiksCiAgICAgICAgICAgICJzZXJ2ZXIiOiBTRVJWRVIsICJlZ3Jl'
    'c3MiOiAi0K3RgdGC0L7QvdC40Y8g0YfQtdGA0LXQtyBTdGFyRml2ZSIsCiAgICAgICAgICAgICJsYXN0X3JlcG9ydCI6IHN0'
    'YXRlLmdldCgibGFzdF9yZXBvcnQiLCAiIiksCiAgICAgICAgICAgICJsYXN0X2Vycm9yIjogc3RhdGUuZ2V0KCJsYXN0X2Vy'
    'cm9yIiwgIiIpLAogICAgICAgICAgICAiZGVsaXZlcnkiOiB7InN0YXR1cyI6c3RhdGUuZ2V0KCdkZWxpdmVyeV9zdGF0dXMn'
    'LCdpZGxlJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAiZXJyb3IiOnN0YXRlLmdldCgnZGVsaXZlcnlfZXJyb3InLCcn'
    'KSwKICAgICAgICAgICAgICAgICAgICAgICAgICJhdHRlbXB0IjpzdGF0ZS5nZXQoJ2RlbGl2ZXJ5X2F0dGVtcHQnLDApLAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgInBlbmRpbmciOmxlbihsaXN0KChST09ULydvdXRib3gnKS5nbG9iKCcqLmpzb24n'
    'KSkpICsgaW50KFBFTkRJTkdfVEVTVC5leGlzdHMoKSl9LAogICAgICAgICAgICAidGVzdCI6IHRlc3Rfc3RhdHVzKCksCiAg'
    'ICAgICAgICAgICJwcm9maWxlX3BhdGgiOiAifi9WcG4vU3RhckZpdmUvcHJvZmlsZS5qc29uIn0KCgpkZWYgdmFsaWRhdGVf'
    'cHJvZmlsZShwKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHAsIGRpY3QpIG9yIHAuZ2V0KCJzY2hlbWEiKSAhPSAxIG9yIHAu'
    'Z2V0KCJzZXJ2ZXIiKSAhPSBTRVJWRVI6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J7QttC40LTQsNC10YLRgdGPINC/'
    '0LXRgNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvRjCBTdGFyRml2ZSBzY2hlbWE9MS4iKQogICAgaWYgbm90IHJl'
    'LmZ1bGxtYXRjaChyImRldmljZS1bYS1mMC05XXsyNH0iLCBzdHIocC5nZXQoImlkZW50aXR5IiwgIiIpKSk6CiAgICAgICAg'
    'cmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC40LTQtdC90YLQuNGE0LjQutCw0YLQvtGAINGD'
    '0YHRgtGA0L7QudGB0YLQstCwLiIpCiAgICBmb3IgZmllbGQsIG1hcmtlciBpbiAoKCJjYSIsICJDRVJUSUZJQ0FURSIpLCAo'
    'ImNlcnRpZmljYXRlIiwgIkNFUlRJRklDQVRFIiksCiAgICAgICAgICAgICAgICAgICAgICAgICAgKCJwcml2YXRlX2tleSIs'
    'ICJQUklWQVRFIEtFWSIpKToKICAgICAgICBzID0gcC5nZXQoZmllbGQpCiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2Uocywg'
    'c3RyKSBvciBsZW4ocykgPiAzMjc2OCBvciAoIi0tLS0tQkVHSU4gIiArIG1hcmtlciArICItLS0tLSIpIG5vdCBpbiBzOgog'
    'ICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0LUg0LTQsNC90L3Ri9C1INGB0LXR'
    'gNGC0LjRhNC40LrQsNGC0L7Qsi4iKQogICAgcmV0dXJuIHAKCgpkZWYgaW1wb3J0X3Byb2ZpbGUoc2V0dGluZ3MsIG5hbWUp'
    'OgogICAgaWYgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQstGL'
    '0LrQu9GO0YfQuCDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1INGB0L7QtdC00LjQvdC10L3QuNC1LiIpCiAg'
    'ICBwYXRoID0gcGF0aGxpYi5QYXRoKG5hbWUpLmV4cGFuZHVzZXIoKQogICAgaWYgbmFtZS5zdGFydHN3aXRoKCJ+LyIpOgog'
    'ICAgICAgIHBhdGggPSBwYXRobGliLlBhdGgoc2V0dGluZ3NbIm93bmVyX2hvbWUiXSkgLyBuYW1lWzI6XQogICAgaW1wb3J0'
    'IHB3ZAogICAgdWlkID0gcHdkLmdldHB3bmFtKHN0cihzZXR0aW5nc1sib3duZXJfdXNlciJdKSkucHdfdWlkCiAgICAjIE5l'
    'dmVyIGxldCBhIHBhc3N3b3JkbGVzcyBzdWRvIGFjdGlvbiByZWFkIGEgcm9vdCBzZWNyZXQgb3IgYSBzcGVjaWFsIGZpbGUu'
    'CiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PTkJMT0NLIHwgb3MuT19OT0ZPTExPVykKICAg'
    'IHdpdGggb3MuZmRvcGVuKGZkLCAicmIiKSBhcyBmOgogICAgICAgIHN0ID0gb3MuZnN0YXQoZi5maWxlbm8oKSkKICAgICAg'
    'ICBpbXBvcnQgc3RhdAogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSkgb3Igc3Quc3RfdWlkICE9IHVp'
    'ZCBvciBzdC5zdF9zaXplID4gMTEwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCf0YDQvtGE0LjQu9GM'
    'INC00L7Qu9C20LXQvSDQsdGL0YLRjCDQvtCx0YvRh9C90YvQvCDRhNCw0LnQu9C+0Lwg0LLQu9Cw0LTQtdC70YzRhtCwINC6'
    '0LvQuNC10L3RgtCwLCDQvdC1INCx0L7Qu9C10LUgMTEwINCa0JEuIikKICAgICAgICBwID0gdmFsaWRhdGVfcHJvZmlsZShq'
    'c29uLmxvYWRzKGYucmVhZCgxMTAwMDEpKSkKICAgIGltcG9ydCB0ZW1wZmlsZQogICAgd2l0aCB0ZW1wZmlsZS5UZW1wb3Jh'
    'cnlEaXJlY3RvcnkoKSBhcyB0bXA6CiAgICAgICAgc3RhZ2UgPSBwYXRobGliLlBhdGgodG1wKQogICAgICAgIGZvciBrZXks'
    'IGZpbGVuYW1lIGluICgoImNhIiwgImNhLnBlbSIpLCAoImNlcnRpZmljYXRlIiwgImNlcnQucGVtIiksICgicHJpdmF0ZV9r'
    'ZXkiLCAia2V5LnBlbSIpKToKICAgICAgICAgICAgd3JpdGUoc3RhZ2UgLyBmaWxlbmFtZSwgcFtrZXldKQogICAgICAgIGN0'
    'eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgIGN0eC5sb2FkX3ZlcmlmeV9sb2Nh'
    'dGlvbnMoc3RyKHN0YWdlIC8gImNhLnBlbSIpKQogICAgICAgIGN0eC5sb2FkX2NlcnRfY2hhaW4oc3RyKHN0YWdlIC8gImNl'
    'cnQucGVtIiksIHN0cihzdGFnZSAvICJrZXkucGVtIikpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1'
    'ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKFJPT1QgLyAicHJvZmlsZS5qc29uIiwganNvbi5kdW1wcyhwKSkKICAgIHdy'
    'aXRlKFJPT1QgLyAiY2EucGVtIiwgcFsiY2EiXSkKICAgIHdyaXRlKFJPT1QgLyAiY2xpZW50LnBlbSIsIHBbImNlcnRpZmlj'
    'YXRlIl0pCiAgICB3cml0ZShST09UIC8gImNsaWVudC1rZXkucGVtIiwgcFsicHJpdmF0ZV9rZXkiXSkKICAgIHdyaXRlKFJP'
    'T1QgLyAicHJpdmF0ZSIgLyAiY2xpZW50LWtleS5wZW0iLCBwWyJwcml2YXRlX2tleSJdKQogICAgd3JpdGUoUk9PVCAvICJ4'
    'NTA5IiAvICJjbGllbnQucGVtIiwgcFsiY2VydGlmaWNhdGUiXSkKICAgIHdyaXRlKFJPT1QgLyAieDUwOWNhIiAvICJjYS5w'
    'ZW0iLCBwWyJjYSJdKQogICAgY29udGV4dCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAg'
    'Y29udGV4dC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKFJPT1QgLyAiY2EucGVtIikpCiAgICBjb250ZXh0LmxvYWRfY2Vy'
    'dF9jaGFpbihzdHIoUk9PVCAvICJjbGllbnQucGVtIiksIHN0cihST09UIC8gImNsaWVudC1rZXkucGVtIikpCiAgICBzYXZl'
    'KHsidGVsZW1ldHJ5IjogVHJ1ZSwgImxhc3RfZXJyb3IiOiAiIn0pCiAgICBwcmludCgi0J/RgNC+0YTQuNC70Ywg0YPRgdGC'
    '0LDQvdC+0LLQu9C10L0uINCS0YDQtdC80LXQvdC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCwINCy0LrQu9GO0YfQtdC9'
    '0LA7INC10ZEg0LzQvtC20L3QviDQstGL0LrQu9GO0YfQuNGC0Ywg0LfQtNC10YHRjCDQttC1LiIpCgoKZGVmIHByZXBhcmUo'
    'KToKICAgIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSI6CiAgICAgICAgaW5zdGFsbF91c2Vyc3BhY2UoKQogICAgICAgIHBy'
    'aW50KCLQkNCy0YLQvtC90L7QvNC90YvQuSBJUHNlYy9UVU4g0LTQstC40LbQvtC6INCz0L7RgtC+0LIuINCh0LjRgdGC0LXQ'
    'vNC90YvQuSDQt9Cw0L/RgNC10YIgZXNwNCDRgdC+0YXRgNCw0L3RkdC9LiIpCiAgICAgICAgcmV0dXJuCiAgICBpZiBzaHV0'
    'aWwud2hpY2goInN3YW5jdGwiKToKICAgICAgICByZXR1cm4KICAgIGlmIHNodXRpbC53aGljaCgicGFjbWFuIik6CiAgICAg'
    'ICAgY21kKFsicGFjbWFuIiwgIi1TIiwgIi0tbmVlZGVkIiwgIi0tbm9jb25maXJtIiwgInN0cm9uZ3N3YW4iXSwgdGltZW91'
    'dD0zMDApCiAgICBlbGlmIHNodXRpbC53aGljaCgiZG5mIik6CiAgICAgICAgY21kKFsiZG5mIiwgImluc3RhbGwiLCAiLXki'
    'LCAiLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFsc2UiLCAic3Ryb25nc3dhbiJdLCB0aW1lb3V0PTMwMCkKICAgIGVs'
    'c2U6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQo9GB0YLQsNC90L7QstC4IHN0cm9uZ1N3YW4g0YEgc3dhbmN0bCDR'
    'gdGA0LXQtNGB0YLQstCw0LzQuCDRgdCy0L7QtdCz0L4g0LTQuNGB0YLRgNC40LHRg9GC0LjQstCwLiIpCiAgICBwcmludCgi'
    'c3Ryb25nU3dhbiDRg9GB0YLQsNC90L7QstC70LXQvTsg0LDQstGC0L7Qv9C+0LTQutC70Y7Rh9C10L3QuNC1INC90LUg0LLQ'
    'utC70Y7Rh9C10L3Qvi4iKQoKCmRlZiByZW5kZXJfZ3VhcmQoKToKICAgIHRyYW5zcG9ydD0oZicgIG1ldGEgbmZwcm90byBp'
    'cHY0IG9pZm5hbWUgIntUVU59IiBhY2NlcHQnIGlmIGJhY2tlbmQoKT09J3VzZXJzcGFjZScKICAgICAgICAgICAgICAgZWxz'
    'ZSBmJyAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlkIHtSRVFJRH0gYWNjZXB0JykKICAgIHJldHVybiBmIiIi'
    'dGFibGUgaW5ldCB7VEFCTEV9IHt7CiBjaGFpbiBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0'
    'eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciB7U0VSVkVSfSB1ZHAgZHBvcnQg'
    'e3sgNTAwLCA0NTAwIH19IGFjY2VwdAogIG1ldGEgc2t1aWQgMCBtZXRhIG1hcmsge0RJUkVDVF9NQVJLfSBpcCBkYWRkciB7'
    'U0VSVkVSfSB0Y3AgZHBvcnQge0RJUkVDVF9QT1JUfSBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCB1ZHAgc3BvcnQgNjgg'
    'dWRwIGRwb3J0IDY3IGFjY2VwdAp7dHJhbnNwb3J0fQogfX0KIGNoYWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29r'
    'IGZvcndhcmQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsKIH19Cn19CiIiIgoKCmRlZiByZW5kZXJfY29ubmVjdGlvbihw'
    'KToKICAgIHJldHVybiBmIiIiY29ubmVjdGlvbnMge3sKIHN0YXJmaXZlIHt7CiAgdmVyc2lvbiA9IDIKICByZW1vdGVfYWRk'
    'cnMgPSB7U0VSVkVSfQogIHZpcHMgPSAwLjAuMC4wCiAgcHJvcG9zYWxzID0gYWVzMjU2Z2NtMTYtcHJmc2hhMzg0LWVjcDM4'
    'NCxhZXMyNTYtc2hhMjU2LW1vZHAyMDQ4CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0g'
    'eWVzCiAgZHBkX2RlbGF5ID0gMzBzCiAgbG9jYWwge3sKICAgYXV0aCA9IGVhcC10bHMKICAgaWQgPSB7cFsnaWRlbnRpdHkn'
    'XX0KICAgZWFwX2lkID0ge3BbJ2lkZW50aXR5J119CiAgIGNlcnRzID0ge1JPT1R9L2NsaWVudC5wZW0KICB9fQogIHJlbW90'
    'ZSB7ewogICBhdXRoID0gcHVia2V5CiAgIGlkID0ge1NFUlZFUn0KICAgY2FjZXJ0cyA9IHtST09UfS9jYS5wZW0KICB9fQog'
    'IGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5ldCB7ewogICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAw'
    'LjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAgZXNwX3Byb3Bvc2FscyA9IGFlczI1NmdjbTE2LGFlczI1Ni1zaGEy'
    'NTYKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQoiIiIK'
    'CgpkZWYgcmVuZGVyX3N0cm9uZ3N3YW4oaW5jbHVkZXM9JycpOgogICAgaWYgYmFja2VuZCgpPT0ndXNlcnNwYWNlJzoKICAg'
    'ICAgICBwbHVnaW5zPSdyYW5kb20gbm9uY2Ugb3BlbnNzbCBwZW0gcGtjczEgcGtjczggeDUwOSBwdWJrZXkgcmV2b2NhdGlv'
    'biBjb25zdHJhaW50cyBrZXJuZWwtbGliaXBzZWMga2VybmVsLW5ldGxpbmsgc29ja2V0LWRlZmF1bHQgZWFwLWlkZW50aXR5'
    'IGVhcC10bHMgdmljaScKICAgICAgICByZXR1cm4gZiIiImNoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0gbm8KIGxvYWQgPSB7'
    'cGx1Z2luc30KIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFibGVfcHJp'
    'byA9IDEwMAogcGx1Z2lucyB7ewogIGtlcm5lbC1saWJpcHNlYyB7ewogICBsb2FkID0gMjAKICAgcmF3X2VzcCA9IG5vCiAg'
    'fX0KICBrZXJuZWwtbmV0bGluayB7ewogICBmd21hcmsgPSAhe2hleChJS0VfTUFSSyl9CiAgfX0KICBzb2NrZXQtZGVmYXVs'
    'dCB7ewogICBmd21hcmsgPSB7aGV4KElLRV9NQVJLKX0KICB9fQogIHZpY2kge3sKICAgc29ja2V0ID0ge1VSSX0KICB9fQog'
    'fX0KIGZpbGVsb2cge3sKICBzdGRlcnIge3sKICAgZGVmYXVsdCA9IDEKICAgZmx1c2hfbGluZSA9IHllcwogIH19CiB9fQp9'
    'fQoiIiIKICAgIHJldHVybiAgIiIiY2hhcm9uIHsKIGxvYWRfbW9kdWxhciA9IHllcwogaW5zdGFsbF9yb3V0ZXMgPSB5ZXMK'
    'IHJvdXRpbmdfdGFibGUgPSA1MTgyMgogcm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBwbHVnaW5zIHsKIiIiICsgaW5jbHVk'
    'ZXMgKyBmIiIiCiAgdmljaSB7ewogICBzb2NrZXQgPSB7VVJJfQogIH19CiAgcmVzb2x2ZSB7ewogICBsb2FkID0gbm8KICB9'
    'fQogIGtlcm5lbC1saWJpcHNlYyB7ewogICBsb2FkID0gbm8KICB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sKIGpvdXJu'
    'YWwge3sKICBkZWZhdWx0ID0gMQogfX0KfX0KIiIiCgoKZGVmIHNlcnZpY2VfZmlsZXMoKToKICAgIGNhbmRpZGF0ZXMgPSBb'
    'Ii91c3Ivc2Jpbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2Jpbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYi9pcHNlYy9j'
    'aGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYmV4ZWMvaXBzZWMvY2hhcm9uLXN5c3RlbWQiLAogICAgICAgICAgICAgICAgICAi'
    'L3Vzci9saWIvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYmV4ZWMvc3Ryb25nc3dhbi9jaGFyb24tc3lz'
    'dGVtZCJdCiAgICBiaW5hcnkgPSBzdHIoVVNFUlNQQUNFLyJjaGFyb24iKSBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGFu'
    'ZCB1c2Vyc3BhY2VfcmVhZHkoKSBlbHNlIG5leHQoKHggZm9yIHggaW4gY2FuZGlkYXRlcyBpZiBwYXRobGliLlBhdGgoeCku'
    'aXNfZmlsZSgpKSwgTm9uZSkKICAgIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSIgYW5kIG5vdCB1c2Vyc3BhY2VfcmVhZHko'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQ'
    'vtCy0LjRgtGMIElLRXYywrsg0LTQu9GPINC30LDQs9GA0YPQt9C60LggVFVOLdC00LLQuNC20LrQsC4iKQogICAgaWYgbm90'
    'IGJpbmFyeToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LUg0L3QsNC50LTQtdC9IGNoYXJvbi1zeXN0ZW1kLiDQ'
    'ndGD0LbQtdC9INC/0LDQutC10YIgc3Ryb25nU3dhbiDRgSBzeXN0ZW1kIGJhY2tlbmQuIikKICAgIGNvbmZpZ3MgPSBbc3Ry'
    'KHApIGZvciBwYXR0ZXJuIGluICgiL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZiIsICIvZXRjL3N0cm9uZ3N3YW4v'
    'c3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYiKQogICAgICAgICAgICAgICBmb3IgcCBpbiBwYXRobGliLlBhdGgoIi8iKS5n'
    'bG9iKHBhdHRlcm4ubHN0cmlwKCIvIikpXQogICAgaW5jbHVkZXMgPSAiXG4iLmpvaW4oImluY2x1ZGUgIiArIHggZm9yIHgg'
    'aW4gY29uZmlncykKICAgICMgRE5TIGlzIG1hbmFnZWQgdHJhbnNhY3Rpb25hbGx5IGJ5IHRoaXMgYmFja2VuZCwgbm90IGJ5'
    'IHRoZSByZXNvbHZlIHBsdWdpbi4KICAgIHdyaXRlKFJPT1QgLyAic3Ryb25nc3dhbi5jb25mIixyZW5kZXJfc3Ryb25nc3dh'
    'bihpbmNsdWRlcykpCiAgICB3cml0ZShwYXRobGliLlBhdGgoIi9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIFVOSVQsIGYiIiJb'
    'VW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZXhwZXJpbWVudGFsIFN0YXJGaXZlIElLRXYyCkFmdGVyPW5ldHdvcmsudGFy'
    'Z2V0CltTZXJ2aWNlXQpUeXBlPXsic2ltcGxlIiBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGVsc2UgIm5vdGlmeSJ9CkVu'
    'dmlyb25tZW50PVNUUk9OR1NXQU5fQ09ORj17Uk9PVH0vc3Ryb25nc3dhbi5jb25mCkV4ZWNTdGFydD17YmluYXJ5fQpSdW50'
    'aW1lRGlyZWN0b3J5PWV2Z2VuaXVtLWlrZXYyClJ1bnRpbWVEaXJlY3RvcnlNb2RlPTA3MDAKTWVtb3J5TWF4PTM4NE0KUmVz'
    'dGFydD1ubwpUaW1lb3V0U3RhcnRTZWM9MjAKIiIiLCAwbzY0NCkKICAgIHdyaXRlKFJPT1QgLyAiZ3VhcmQubmZ0IiwgcmVu'
    'ZGVyX2d1YXJkKCkpCiAgICB3cml0ZShwYXRobGliLlBhdGgoIi9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIEdVQVJELCBmIiIi'
    'W1VuaXRdCkRlc2NyaXB0aW9uPUZhaWwtY2xvc2VkIGd1YXJkIGZvciBleHBlcmltZW50YWwgSUtFdjIKRGVmYXVsdERlcGVu'
    'ZGVuY2llcz1ubwpCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0CldhbnRzPW5ldHdvcmstcHJlLnRhcmdldApBZnRlcj1sb2Nh'
    'bC1mcy50YXJnZXQgbmZ0YWJsZXMuc2VydmljZQpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMK'
    'RXhlY1N0YXJ0PXtzaHV0aWwud2hpY2goIm5mdCIpfSAtZiB7Uk9PVH0vZ3VhcmQubmZ0CkV4ZWNTdG9wPS17c2h1dGlsLndo'
    'aWNoKCJuZnQiKX0gZGVsZXRlIHRhYmxlIGluZXQge1RBQkxFfQpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJn'
    'ZXQKIiIiLCAwbzY0NCkKICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgiL2V0Yy9zeXN0ZW1kL3N5c3RlbSIpIC8gTU9OSVRPUiwg'
    'IiIiW1VuaXRdCkRlc2NyaXB0aW9uPVRlbXBvcmFyeSBTdGFyRml2ZSBWUE4gZGlhZ25vc3RpY3MKQWZ0ZXI9ZXZnZW5pdW0t'
    'aWtldjIuc2VydmljZQpbU2VydmljZV0KRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZp'
    'dmUtbW9uaXRvcgpTdGFuZGFyZE91dHB1dD1udWxsClN0YW5kYXJkRXJyb3I9bnVsbApSZXN0YXJ0PW5vCiIiIiwgMG82NDQp'
    'CiAgICBpbnN0YWxsX2RlbGl2ZXJ5KCkKCgpkZWYgaW5zdGFsbF9kZWxpdmVyeSgpOgogICAgd3JpdGUocGF0aGxpYi5QYXRo'
    'KCcvZXRjL3N5c3RlbWQvc3lzdGVtJykgLyBERUxJVkVSWSwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPUV4cGVyaW1lbnRhbCBk'
    'aXJlY3QgbVRMUyBkaWFnbm9zdGljIGRlbGl2ZXJ5CkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpFeGVjU3RhcnQ9'
    'L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS1kZWxpdmVyeQpTdGFuZGFyZE91dHB1dD1udWxsClN0'
    'YW5kYXJkRXJyb3I9bnVsbApSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zMApbSW5zdGFsbF0KV2FudGVkQnk9bXVs'
    'dGktdXNlci50YXJnZXQKIiIiLCAwbzY0NCkKICAgIGNtZChbInN5c3RlbWN0bCIsICJkYWVtb24tcmVsb2FkIl0pCiAgICBj'
    'bWQoWydzeXN0ZW1jdGwnLCdlbmFibGUnLERFTElWRVJZXSxjaGVjaz1GYWxzZSkKICAgICMgVXBncmFkZSBhbiBhbHJlYWR5'
    'IGFjdGl2ZSBleHBlcmltZW50YWwgZ3VhcmQgd2l0aG91dCBvcGVuaW5nIG9yZGluYXJ5IHRyYWZmaWMuCiAgICBpZiBhY3Rp'
    'dmVfZ3VhcmQoKToKICAgICAgICBydWxlcz1jbWQoWyduZnQnLCdsaXN0JywnY2hhaW4nLCdpbmV0JyxUQUJMRSwnb3V0cHV0'
    'J10sY2hlY2s9RmFsc2UpLnN0ZG91dAogICAgICAgIGlmIHN0cihESVJFQ1RfTUFSSykgbm90IGluIHJ1bGVzIGFuZCBoZXgo'
    'RElSRUNUX01BUkspIG5vdCBpbiBydWxlczoKICAgICAgICAgICAgY21kKFsnbmZ0JywnaW5zZXJ0JywncnVsZScsJ2luZXQn'
    'LFRBQkxFLCdvdXRwdXQnLCdtZXRhJywnc2t1aWQnLCcwJywKICAgICAgICAgICAgICAgICAnbWV0YScsJ21hcmsnLHN0cihE'
    'SVJFQ1RfTUFSSyksJ2lwJywnZGFkZHInLFNFUlZFUiwndGNwJywnZHBvcnQnLHN0cihESVJFQ1RfUE9SVCksJ2FjY2VwdCdd'
    'KQoKCmRlZiBzZXRfZG5zKCk6CiAgICByZXNvbHZlZCA9IFJPT1QgLyAicmVzb2x2ZWQtYmFja3VwLmpzb24iCiAgICBiYWNr'
    'dXAgPSBST09UIC8gInJlc29sdi1iYWNrdXAiCiAgICBpZiBiYWNrdXAuZXhpc3RzKCkgb3IgcmVzb2x2ZWQuZXhpc3RzKCk6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQldGB0YLRjCDQvdC10LfQsNCy0LXRgNGI0ZHQvdC90L7QtSDQstC+0YHR'
    'gdGC0LDQvdC+0LLQu9C10L3QuNC1IEROUy4g0KHQvdCw0YfQsNC70LAgdnBuIGV4cGVyaW1lbnRhbCBvZmYuIikKICAgIGlm'
    'IHNodXRpbC53aGljaCgicmVzb2x2ZWN0bCIpIGFuZCBjbWQoWyJzeXN0ZW1jdGwiLCAiaXMtYWN0aXZlIiwgInN5c3RlbWQt'
    'cmVzb2x2ZWQiXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICByb3V0ZSA9IGpzb24ubG9hZHMoY21k'
    'KFsiaXAiLCAiLWoiLCAicm91dGUiLCAiZ2V0IiwgU0VSVkVSXSkuc3Rkb3V0KVswXQogICAgICAgIGlmYWNlID0gcm91dGVb'
    'ImRldiJdCiAgICAgICAgZGVmIHByZXZpb3VzKGtpbmQpOgogICAgICAgICAgICB0ZXh0ID0gY21kKFsicmVzb2x2ZWN0bCIs'
    'IGtpbmQsIGlmYWNlXSkuc3Rkb3V0CiAgICAgICAgICAgIHJldHVybiB0ZXh0LnNwbGl0KCIpOiIsIDEpWzFdLnN0cmlwKCku'
    'c3BsaXQoKSBpZiAiKToiIGluIHRleHQgZWxzZSBbXQogICAgICAgIHdyaXRlKHJlc29sdmVkLCBqc29uLmR1bXBzKHsiaWZh'
    'Y2UiOiBpZmFjZSwgImRucyI6IHByZXZpb3VzKCJkbnMiKSwgImRvbWFpbiI6IHByZXZpb3VzKCJkb21haW4iKX0pKQogICAg'
    'ICAgIGNtZChbInJlc29sdmVjdGwiLCAiZG5zIiwgaWZhY2UsICI3Ny44OC44LjgiLCAiNzcuODguOC4xIl0pCiAgICAgICAg'
    'Y21kKFsicmVzb2x2ZWN0bCIsICJkb21haW4iLCBpZmFjZSwgIn4uIl0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsICJm'
    'bHVzaC1jYWNoZXMiXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgcmV0dXJuCiAgICB3cml0ZShiYWNrdXAsIHBhdGhsaWIuUGF0'
    'aCgiL2V0Yy9yZXNvbHYuY29uZiIpLnJlYWRfdGV4dCgpKQogICAgIyBLZWVwIHRoZSBzeW1saW5rIGl0c2VsZiBpbnRhY3Qg'
    'KE5ldHdvcmtNYW5hZ2VyL3N5c3RlbWQtcmVzb2x2ZWQgc2V0dXBzKS4KICAgIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYu'
    'Y29uZiIpLndyaXRlX3RleHQoIiMgRXZnZW5pdW0gZXhwZXJpbWVudGFsIFZQTlxubmFtZXNlcnZlciA3Ny44OC44Ljhcbm5h'
    'bWVzZXJ2ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4iKQoKCmRlZiByZXN0b3JlX2Rucygp'
    'OgogICAgcmVzb2x2ZWQgPSBST09UIC8gInJlc29sdmVkLWJhY2t1cC5qc29uIgogICAgaWYgcmVzb2x2ZWQuZXhpc3RzKCk6'
    'CiAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMocmVzb2x2ZWQucmVhZF90ZXh0KCkpCiAgICAgICAgZm9yIGtleSBpbiAoImRu'
    'cyIsICJkb21haW4iKToKICAgICAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsIGtleSwgZGF0YVsiaWZhY2UiXSwgKihkYXRh'
    'W2tleV0gb3IgWyIiXSldKQogICAgICAgIGNtZChbInJlc29sdmVjdGwiLCAiZmx1c2gtY2FjaGVzIl0sIGNoZWNrPUZhbHNl'
    'KQogICAgICAgIHJlc29sdmVkLnVubGluaygpCiAgICBiYWNrdXAgPSBST09UIC8gInJlc29sdi1iYWNrdXAiCiAgICBpZiBi'
    'YWNrdXAuZXhpc3RzKCk6CiAgICAgICAgcGF0aGxpYi5QYXRoKCIvZXRjL3Jlc29sdi5jb25mIikud3JpdGVfdGV4dChiYWNr'
    'dXAucmVhZF90ZXh0KCkpCiAgICAgICAgYmFja3VwLnVubGluaygpCgoKZGVmIGVuZHBvaW50KHBhdGgsIHBheWxvYWQ9Tm9u'
    'ZSk6CiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FmaWxlPXN0cihST09UIC8gImNhLnBlbSIp'
    'KQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QgLyAiY2xpZW50LnBlbSIpLCBzdHIoUk9PVCAvICJjbGll'
    'bnQta2V5LnBlbSIpKQogICAgZGF0YSA9IE5vbmUgaWYgcGF5bG9hZCBpcyBOb25lIGVsc2UganNvbi5kdW1wcyhwYXlsb2Fk'
    'LCBzZXBhcmF0b3JzPSgiLCIsICI6IikpLmVuY29kZSgpCiAgICByZXEgPSB1cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxU'
    'SCArIHBhdGgsIGRhdGE9ZGF0YSwgaGVhZGVycz17IkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAj'
    'IE5ldmVyIGNvbnN1bHQgZW52aXJvbm1lbnQgcHJveHkgdmFyaWFibGVzIGZvciBhIHByaXZhdGUgZGlhZ25vc3RpYyBlbmRw'
    'b2ludC4KICAgIG9wZW5lciA9IHVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcih1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRs'
    'ZXIoe30pLCB1cmxsaWIucmVxdWVzdC5IVFRQU0hhbmRsZXIoY29udGV4dD1jb250ZXh0KSkKICAgIHdpdGggb3BlbmVyLm9w'
    'ZW4ocmVxLCB0aW1lb3V0PTgpIGFzIHJlc3BvbnNlOgogICAgICAgIHJldHVybiBqc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQo'
    'NjU1MzYpKQoKCmRlZiBvbihhcGksIHNldHRpbmdzKToKICAgIHN0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKQogICAgc3RhZ2U9'
    'J3ByZXBhcmUnCiAgICBpZiBhcGkuc2VydmljZV9hY3RpdmUoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3Q'
    'sNGH0LDQu9CwINCy0YvQutC70Y7Rh9C4INC+0LHRi9GH0L3Ri9C5IFhyYXkgVlBOLiDQntC00L3QvtCy0YDQtdC80LXQvdC9'
    '0L4g0LTQstCwINGA0LXQttC40LzQsCDQvdC1INC30LDQv9GD0YHQutCw0Y7RgtGB0Y8uIikKICAgIGlmIGFjdGl2ZV9ndWFy'
    'ZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KDQtdC20LjQvCDRg9C20LUg0LLQutC70Y7Rh9GR0L0g0LjQu9C4'
    'INC30LDQsdC70L7QutC40YDQvtCy0LDQvSDQv9C+0YHQu9C1INGB0LHQvtGPLiDQktGL0LrQu9GO0YfQuCDQtdCz0L4g0L/Q'
    'tdGA0LXQtCDQv9C+0LLRgtC+0YDQvtC8LiIpCiAgICBpZiBub3QgUk9PVC5qb2lucGF0aCgicHJvZmlsZS5qc29uIikuZXhp'
    'c3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQuNC80L/QvtGA0YLQuNGA0YPQuSDQ'
    'v9C10YDRgdC+0L3QsNC70YzQvdGL0Lkg0L/RgNC+0YTQuNC70YwgU3RhckZpdmUuIikKICAgIGlmIG5vdCBhdmFpbGFibGUo'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQ'
    'vtCy0LjRgtGMIElLRXYywrsuIikKICAgICMgRXhpc3RpbmcgdW5yZWxhdGVkIElQc2VjIHN0YXRlIG11c3QgbmV2ZXIgYmUg'
    'cmVwbGFjZWQuCiAgICBpZiBjbWQoWyJpcCIsICJ4ZnJtIiwgInN0YXRlIl0sIGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAo'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCe0LHQvdCw0YDRg9C20LXQvSDQtNGA0YPQs9C+0LkgSVBzZWMgVlBO'
    'LiDQodC90LDRh9Cw0LvQsCDQvtGC0LrQu9GO0YfQuCDQtdCz0L4uIikKICAgIHAgPSB2YWxpZGF0ZV9wcm9maWxlKGpzb24u'
    'bG9hZHMoKFJPT1QgLyAicHJvZmlsZS5qc29uIikucmVhZF90ZXh0KCkpKQogICAgaWYgYmFja2VuZCgpPT0idXNlcnNwYWNl'
    'IiBhbmQgcGF0aGxpYi5QYXRoKCIvc3lzL2NsYXNzL25ldCIsVFVOKS5leGlzdHMoKToKICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoItCY0L3RgtC10YDRhNC10LnRgSBpcHNlYzAg0YPQttC1INGB0YPRidC10YHRgtCy0YPQtdGCLiDQodC90LDRh9Cw'
    '0LvQsCDQstGL0LrQu9GO0YfQuCDQuNGB0L/QvtC70YzQt9GD0Y7RidC10LUg0LXQs9C+INC/0L7QtNC60LvRjtGH0LXQvdC4'
    '0LUuIikKICAgIHNlcnZpY2VfZmlsZXMoKQogICAgd3JpdGUoUk9PVCAvICJjb25uZWN0aW9uLmNvbmYiLCByZW5kZXJfY29u'
    'bmVjdGlvbihwKSkKICAgIHRyeToKICAgICAgICBzdGFnZT0nZGFlbW9uJwogICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJz'
    'dGFydCIsIFVOSVRdKQogICAgICAgIHdhaXRfdXNlcnNwYWNlKCkKICAgICAgICBzdGFnZT0nY3JlZGVudGlhbHMnCiAgICAg'
    'ICAgc3dhbigiLS1sb2FkLWNyZWRzIiwgIi0tZmlsZSIsIFJPT1QgLyAiY29ubmVjdGlvbi5jb25mIikKICAgICAgICBzd2Fu'
    'KCItLWxvYWQtY29ubnMiLCAiLS1maWxlIiwgUk9PVCAvICJjb25uZWN0aW9uLmNvbmYiKQogICAgICAgIHN0YWdlPSdndWFy'
    'ZCcKICAgICAgICB3cml0ZShSVU5USU1FIC8gImd1YXJkLm5mdCIsIHJlbmRlcl9ndWFyZCgpKQogICAgICAgIGNtZChbIm5m'
    'dCIsICItYyIsICItZiIsIFJVTlRJTUUgLyAiZ3VhcmQubmZ0Il0pCiAgICAgICAgIyBBbGwgcHJlcGFyYXRvcnkgY2hlY2tz'
    'IGFib3ZlIGFyZSBub24tZGlzcnVwdGl2ZS4gVGhlIGd1YXJkIGdvZXMgZmlyc3QuCiAgICAgICAgY21kKFsic3lzdGVtY3Rs'
    'IiwgImVuYWJsZSIsICItLW5vdyIsIEdVQVJEXSkKICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgICAg'
    'ICMgUmVjb3ZlciBhIHN0YWxlIGFjdGl2ZSBzeXN0ZW1kIHVuaXQgd2hvc2UgdGFibGUgd2FzIGV4dGVybmFsbHkgcmVtb3Zl'
    'ZC4KICAgICAgICAgICAgY21kKFsibmZ0IiwgIi1mIiwgUk9PVCAvICJndWFyZC5uZnQiXSkKICAgICAgICBpZiBub3QgYWN0'
    'aXZlX2d1YXJkKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTR'
    'gtCy0LXRgNC00LjRgtGMINGD0YHRgtCw0L3QvtCy0LrRgyBraWxsIHN3aXRjaC4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsg'
    'InBoYXNlIjogImNvbm5lY3RpbmciLCAibGFzdF9lcnJvciI6ICIifSkKICAgICAgICBzdGFnZT0naGFuZHNoYWtlJwogICAg'
    'ICAgIHN3YW4oIi0taW5pdGlhdGUiLCAiLS1jaGlsZCIsICJzdGFyZml2ZS1uZXQiLCB0aW1lb3V0PTU1KQogICAgICAgIGlm'
    'IG5vdCBjb25uZWN0ZWQoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCJJUHNlYyBDSElMRF9TQSDQvdC1INGD'
    '0YHRgtCw0L3QvtCy0LvQtdC9LiIpCiAgICAgICAgc3RhZ2U9J2RucycKICAgICAgICBzZXRfZG5zKCkKICAgICAgICBzdGFn'
    'ZT0naGVhbHRoJwogICAgICAgIGhlYWx0aCA9IGVuZHBvaW50KCIvaGVhbHRoIikKICAgICAgICBpZiBoZWFsdGguZ2V0KCJz'
    'ZXJ2aWNlIikgIT0gImV2Z2VuaXVtLXN0YXJmaXZlIjoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQndC1INC/'
    '0L7QtNGC0LLQtdGA0LbQtNGR0L0g0LTQuNCw0LPQvdC+0YHRgtC40YfQtdGB0LrQuNC5INGB0LXRgNCy0LXRgCBTdGFyRml2'
    'ZS4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5lY3RlZCIsICJzaW5jZSI6IGludCh0aW1lLnRpbWUo'
    'KSksICJsYXN0X2Vycm9yIjogIiJ9KQogICAgICAgIGlmIHN0b3JlZCgpLmdldCgidGVsZW1ldHJ5Iik6CiAgICAgICAgICAg'
    'IGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIsIE1PTklUT1JdKQogICAgICAgIHRyeTogcXVldWVfY29ubmVjdGlvbignY29u'
    'bmVjdGVkJywnbm9uZScsKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9u'
    'OiBwYXNzCiAgICAgICAgcHJpbnQoIlN0YXJGaXZlINC/0L7QtNC60LvRjtGH0ZHQvS4g0KLQtdGB0YLQvtCy0YvQuSDQstGL'
    '0YXQvtC0OiDQoNC+0YHRgdC40Y8uIElQdjYg0LggRElSRUNULdC40YHQutC70Y7Rh9C10L3QuNGPINC30LDQsdC70L7QutC4'
    '0YDQvtCy0LDQvdGLLiIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAi'
    'c3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFVOSVRdLCBj'
    'aGVjaz1GYWxzZSkKICAgICAgICByZXN0b3JlX2RucygpCiAgICAgICAgZ3VhcmRlZD1hY3RpdmVfZ3VhcmQoKQogICAgICAg'
    'IHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImJsb2NrZWQiIGlmIGd1YXJkZWQgZWxzZSAib2ZmIiwgImxhc3RfZXJyb3IiOgog'
    'ICAgICAgICAgICAgICAgICAgICAi0J/QvtC00LrQu9GO0YfQtdC90LjQtSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQtdC90L47'
    'INC40L3RgtC10YDQvdC10YIg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9INC00L4g0LLRi9C60LvRjtGH0LXQvdC40Y8g0YDQ'
    'tdC20LjQvNCwLiIgaWYgZ3VhcmRlZCBlbHNlCiAgICAgICAgICAgICAgICAgICAgICLQn9C+0LTQs9C+0YLQvtCy0LrQsCDQ'
    'vdC1INC30LDQstC10YDRiNC10L3QsDsg0L/QvtC00LrQu9GO0YfQtdC90LjQtSDQuCDQt9Cw0YnQuNGC0LAg0L3QtSDQstC6'
    '0LvRjtGH0LjQu9C40YHRjC4ifSkKICAgICAgICB0cnk6IHF1ZXVlX2Nvbm5lY3Rpb24oc3RhZ2UsZmFpbHVyZV9jb2RlKGV4'
    'YyksKHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAg'
    'ICAgZXJyb3I9UnVudGltZUVycm9yKCLQn9C+0LTQutC70Y7Rh9C10L3QuNC1IFN0YXJGaXZlINC90LUg0YPQtNCw0LvQvtGB'
    '0YwuICIgKwogICAgICAgICAgICAgICAgICAgICAgICAgICAoIktpbGwgc3dpdGNoINC+0YHRgtCw0LLQu9C10L0g0LLQutC7'
    '0Y7Rh9GR0L3QvdGL0LwuINCS0YvQv9C+0LvQvdC4IHZwbiBleHBlcmltZW50YWwgb2ZmLiAiIGlmIGd1YXJkZWQgZWxzZQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIktpbGwgc3dpdGNoINC90LUg0LDQutGC0LjQstC40YDQvtCy0LDQvTog0YHQ'
    'sdC+0Lkg0L/RgNC+0LjQt9C+0YjRkdC7INC00L4g0LLQutC70Y7Rh9C10L3QuNGPINGC0YPQvdC90LXQu9GPLiAiKSArIHN0'
    'cihleGMpKQogICAgICAgIGVycm9yLmRpYWdub3N0aWNfcXVldWVkPVRydWUKICAgICAgICByYWlzZSBlcnJvciBmcm9tIGV4'
    'YwoKCmRlZiBvZmYoKToKICAgIGNtZChbInN5c3RlbWN0bCIsICJzdG9wIiwgVEVTVF9VTklUXSwgY2hlY2s9RmFsc2UpCiAg'
    'ICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbInN5c3RlbWN0bCIs'
    'ICJzdG9wIiwgVU5JVF0sIGNoZWNrPUZhbHNlKQogICAgcmVzdG9yZV9kbnMoKQogICAgY21kKFsic3lzdGVtY3RsIiwgImRp'
    'c2FibGUiLCAiLS1ub3ciLCBHVUFSRF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsibmZ0IiwgImRlbGV0ZSIsICJ0YWJsZSIs'
    'ICJpbmV0IiwgVEFCTEVdLCBjaGVjaz1GYWxzZSkKICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogIm9mZiIsICJsYXN0X2Vy'
    'cm9yIjogIiJ9KQogICAgcHJpbnQoItCt0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdC+0LUg0YHQvtC10LTQuNC90LXQ'
    'vdC40LUg0LLRi9C60LvRjtGH0LXQvdC+LiDQntCx0YvRh9C90YvQuSDQuNC90YLQtdGA0L3QtdGCINCy0L7RgdGB0YLQsNC9'
    '0L7QstC70LXQvS4iKQoKCmRlZiB0ZWxlbWV0cnkoZW5hYmxlZCk6CiAgICBwYXRjaF9zdGF0ZSh7ICJ0ZWxlbWV0cnkiOiBi'
    'b29sKGVuYWJsZWQpfSkKICAgIGlmIG5vdCBlbmFibGVkOgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLERFTElW'
    'RVJZXSxjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sIGNoZWNrPUZh'
    'bHNlKQogICAgY21kKFsic3lzdGVtY3RsIiwgInN0YXJ0IiBpZiBlbmFibGVkIGFuZCBjb25uZWN0ZWQoKSBlbHNlICJzdG9w'
    'IiwgTU9OSVRPUl0sIGNoZWNrPUZhbHNlKQogICAgaWYgZW5hYmxlZDoga2lja19kZWxpdmVyeSgpCiAgICBwcmludCgi0JLR'
    'gNC10LzQtdC90L3QsNGPINC00LjQsNCz0L3QvtGB0YLQuNC60LAgIiArICgi0LLQutC70Y7Rh9C10L3QsCIgaWYgZW5hYmxl'
    'ZCBlbHNlICLQstGL0LrQu9GO0YfQtdC90LAiKSkKCgpkZWYgZG9tYWluX29ubHkodmFsdWUpOgogICAgIyBFeHBsaWNpdCBk'
    'b21haW4tb25seSByZXBvcnQuIE5ldmVyIGFjY2VwdCBVUkxzLCBwYXRocywgdG9rZW5zIG9yIGFyYml0cmFyeSBsb2cgdGV4'
    'dC4KICAgIHZhbHVlID0gdmFsdWUuc3RyaXAoKS5sb3dlcigpLnJzdHJpcCgiLiIpCiAgICBpZiBsZW4odmFsdWUpID4gMjUz'
    'IG9yIG5vdCByZS5mdWxsbWF0Y2gociJbYS16MC05XSg/OlthLXowLTkuLV0qW2EtejAtOV0pPyIsIHZhbHVlKSBvciAiLiIg'
    'bm90IGluIHZhbHVlOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoItCS0LLQtdC00Lgg0LTQvtC80LXQvSDQsdC10LcgaHR0'
    'cHM6Ly8sINC/0YPRgtC4INC4INC/0LDRgNCw0LzQtdGC0YDQvtCyLiIpCiAgICBmb3IgbGFiZWwgaW4gdmFsdWUuc3BsaXQo'
    'Ii4iKToKICAgICAgICBpZiBub3QgbGFiZWwgb3IgbGVuKGxhYmVsKSA+IDYzIG9yIGxhYmVsLnN0YXJ0c3dpdGgoIi0iKSBv'
    'ciBsYWJlbC5lbmRzd2l0aCgiLSIpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQ'
    'vdGL0Lkg0LTQvtC80LXQvS4iKQogICAgdHJ5OgogICAgICAgIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHZhbHVlKQogICAgZXhj'
    'ZXB0IFZhbHVlRXJyb3I6CiAgICAgICAgcmV0dXJuIHZhbHVlCiAgICByYWlzZSBWYWx1ZUVycm9yKCLQndGD0LbQtdC9INC0'
    '0L7QvNC10L0g0YHQsNC50YLQsCwg0LAg0L3QtSBJUC3QsNC00YDQtdGBLiIpCgoKZGVmIHByb2JlX2RvbWFpbihkb21haW4p'
    'OgogICAgZG9tYWluID0gZG9tYWluX29ubHkoZG9tYWluKQogICAgc3RhcnQgPSB0aW1lLm1vbm90b25pYygpCiAgICB0cnk6'
    'CiAgICAgICAgcmVzb2x2ZWQgPSBzb2NrZXQuZ2V0YWRkcmluZm8oZG9tYWluLCA0NDMsIHNvY2tldC5BRl9JTkVULCBzb2Nr'
    'ZXQuU09DS19TVFJFQU0pCiAgICAgICAgYWRkcmVzc2VzID0gbGlzdChkaWN0LmZyb21rZXlzKHhbNF1bMF0gZm9yIHggaW4g'
    'cmVzb2x2ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3Mo'
    'eFs0XVswXSkuaXNfZ2xvYmFsKSlbOjNdCiAgICAgICAgZm9yIGFkZHJlc3MgaW4gYWRkcmVzc2VzOgogICAgICAgICAgICB0'
    'cnk6CiAgICAgICAgICAgICAgICB3aXRoIHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgNDQzKSwgdGltZW91'
    'dD00KSBhcyBzb2NrOgogICAgICAgICAgICAgICAgICAgIHdpdGggc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKS53cmFw'
    'X3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9ZG9tYWluKSBhcyBjb25uOgogICAgICAgICAgICAgICAgICAgICAgICBj'
    'b25uLnNlbmRhbGwoKCJIRUFEIC8gSFRUUC8xLjFcclxuSG9zdDogIiArIGRvbWFpbiArICJcclxuQ29ubmVjdGlvbjogY2xv'
    'c2VcclxuXHJcbiIpLmVuY29kZSgpKQogICAgICAgICAgICAgICAgICAgICAgICBsaW5lID0gY29ubi5yZWN2KDI1Nikuc3Bs'
    'aXQoYiJcclxuIiwgMSlbMF0KICAgICAgICAgICAgICAgICAgICAgICAgcGFydHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgY29kZSA9IGludChwYXJ0c1sxXSkgaWYgbGVuKHBhcnRzKSA+IDEgYW5kIHBhcnRzWzFdLmlzZGln'
    'aXQoKSBlbHNlIDAKICAgICAgICAgICAgICAgICAgICAgICAgaWYgY29kZToKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHJldHVybiB7ImRvbWFpbiI6IGRvbWFpbiwgIm9rIjogVHJ1ZSwgImh0dHBfc3RhdHVzIjogY29kZSwKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgImxhdGVuY3lfbXMiOiByb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydCkqMTAw'
    'MCl9CiAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgc3NsLlNTTEVycm9yKToKICAgICAgICAgICAgICAgIGNvbnRpbnVl'
    'CiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBwYXNzCiAgICByZXR1cm4geyJkb21haW4iOiBkb21haW4sICJvayI6IEZh'
    'bHNlLCAiZXJyb3IiOiAiZG5zX3RjcF9vcl90bHNfZmFpbGVkIiwKICAgICAgICAgICAgImxhdGVuY3lfbXMiOiByb3VuZCgo'
    'dGltZS5tb25vdG9uaWMoKS1zdGFydCkqMTAwMCl9CgoKZGVmIHJlcG9ydChkb21haW49Tm9uZSk6CiAgICBpZiBub3Qgc3Rv'
    'cmVkKCkuZ2V0KCJ0ZWxlbWV0cnkiKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCU0LjQsNCz0L3QvtGB0YLQuNC6'
    '0LAg0LLRi9C60LvRjtGH0LXQvdCwLiDQktC60LvRjtGH0Lgg0LXRkSDRj9Cy0L3QviDQv9C10YDQtdC0INC+0YLQv9GA0LDQ'
    'stC60L7QuS4iKQogICAgaWYgbm90IGNvbm5lY3RlZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J7RgtGH0ZHR'
    'giDQvtGC0L/RgNCw0LLQu9GP0LXRgtGB0Y8g0YLQvtC70YzQutC+INCy0L3Rg9GC0YDQuCDRg9GB0YLQsNC90L7QstC70LXQ'
    'vdC90L7Qs9C+IFN0YXJGaXZlIFZQTi4iKQogICAgZG9tYWlucyA9IFtkb21haW5fb25seShkb21haW4pXSBpZiBkb21haW4g'
    'ZWxzZSBsaXN0KFJVX0RPTUFJTlMpCiAgICBwcm9iZXMgPSBbcHJvYmVfZG9tYWluKHgpIGZvciB4IGluIGRvbWFpbnNdCiAg'
    'ICBib2R5ID0geyJzY2hlbWEiOiAxLCAiZXZlbnQiOiAic2l0ZV9yZXBvcnQiIGlmIGRvbWFpbiBlbHNlICJzYW1wbGUiLAog'
    'ICAgICAgICAgICAidGltZSI6IGludCh0aW1lLnRpbWUoKSksICJtYW5hZ2VyIjogIjAuMi4yMyIsICJwbGF0Zm9ybSI6ICJs'
    'aW51eCIsCiAgICAgICAgICAgICJwcm9iZXMiOiBwcm9iZXMsICJpcHNlYyI6ICJpbnN0YWxsZWQifQogICAgZW5kcG9pbnQo'
    'Ii9yZXBvcnQiLCBib2R5KQogICAgcGF0Y2hfc3RhdGUoeyAibGFzdF9yZXBvcnQiOiB0aW1lLnN0cmZ0aW1lKCIlWS0lbS0l'
    'ZCAlSDolTTolUyIsIHRpbWUuZ210aW1lKCkpICsgIiBVVEMifSkKICAgIHByaW50KGpzb24uZHVtcHMoeyJzZW50IjogVHJ1'
    'ZSwgInByb2JlcyI6IHByb2Jlc30sIGVuc3VyZV9hc2NpaT1GYWxzZSkpCgoKZGVmIG1vbml0b3IoKToKICAgIHdoaWxlIHN0'
    'b3JlZCgpLmdldCgidGVsZW1ldHJ5IikgYW5kIGNvbm5lY3RlZCgpOgogICAgICAgIHRyeToKICAgICAgICAgICAgZmx1c2hf'
    'dGVzdF9yZXBvcnQoKQogICAgICAgICAgICByZXBvcnQoKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAg'
    'IHBhc3MKICAgICAgICB0aW1lLnNsZWVwKDYwKQogICAgaWYgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBhbmQgYWN0aXZl'
    'X2d1YXJkKCk6CiAgICAgICAgdHJ5OiBxdWV1ZV9jb25uZWN0aW9uKCdkaXNjb25uZWN0ZWQnLCduZXR3b3JrJykKICAgICAg'
    'ICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCgoKZGVmIGRpc3BhdGNoKGFwaSwgc2V0dGluZ3MsIGFjdGlvbiwgdGFyZ2V0PSIi'
    'KToKICAgIHRyeToKICAgICAgICBpZiBhY3Rpb24gPT0gJ3Rva2VuLXNhdmUnIGFuZCB0dW5uZWw6CiAgICAgICAgICAgIHR1'
    'bm5lbC5zYXZlX3Rva2VuKHRhcmdldCkKICAgICAgICAgICAgcHJpbnQoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvSDQ'
    'vdCwINGN0YLQvtC8INGD0YHRgtGA0L7QudGB0YLQstC1LicpCiAgICAgICAgZWxpZiBhY3Rpb24gaW4gKCdjb25uZWN0Jywg'
    'J3JlcGFpcicpIGFuZCB0dW5uZWw6CiAgICAgICAgICAgIHR1bm5lbC5jb25uZWN0KHRhcmdldCwgcmVwYWlyPWFjdGlvbiA9'
    'PSAncmVwYWlyJykKICAgICAgICBlbGlmIGFjdGlvbiA9PSAnZGlzY29ubmVjdCcgYW5kIHR1bm5lbDoKICAgICAgICAgICAg'
    'dHVubmVsLmRpc2Nvbm5lY3QoKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJnbG9iYWwtdGVzdCI6IHN0YXJ0X2dsb2JhbF90'
    'ZXN0KCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAiY2FuY2VsLXRlc3QiOiBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRF'
    'U1RfVU5JVF0sY2hlY2s9RmFsc2UpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImJhY2tlbmQtdXNlcnNwYWNlIjogc2VsZWN0'
    'X2JhY2tlbmQoInVzZXJzcGFjZSIpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImJhY2tlbmQta2VybmVsIjogc2VsZWN0X2Jh'
    'Y2tlbmQoImtlcm5lbCIpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInByZXBhcmUiOiBwcmVwYXJlKCkKICAgICAgICBlbGlm'
    'IGFjdGlvbiA9PSAiaW1wb3J0IjogaW1wb3J0X3Byb2ZpbGUoc2V0dGluZ3MsIHRhcmdldCkKICAgICAgICBlbGlmIGFjdGlv'
    'biA9PSAib24iOiBvbihhcGksIHNldHRpbmdzKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJvZmYiOgogICAgICAgICAgICBp'
    'ZiB0dW5uZWwgYW5kIHR1bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpOiB0dW5uZWwuZGlzY29ubmVjdCgpCiAgICAgICAgICAg'
    'IGVsc2U6IG9mZigpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInRlbGVtZXRyeS1vbiI6IHRlbGVtZXRyeShUcnVlKQogICAg'
    'ICAgIGVsaWYgYWN0aW9uID09ICJ0ZWxlbWV0cnktb2ZmIjogdGVsZW1ldHJ5KEZhbHNlKQogICAgICAgIGVsaWYgYWN0aW9u'
    'ID09ICJyZXBvcnQiOiByZXBvcnQodGFyZ2V0IG9yIE5vbmUpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInNlbmQtZGlhZ25v'
    'c3RpY3MiOgogICAgICAgICAgICBpZiBub3QgUk9PVC5qb2lucGF0aCgncHJvZmlsZS5qc29uJykuZXhpc3RzKCk6IHJhaXNl'
    'IFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0LjQvNC/0L7RgNGC0LjRgNGD0Lkg0L/RgNC+0YTQuNC70YwuJykKICAg'
    'ICAgICAgICAgaW5zdGFsbF9kZWxpdmVyeSgpCiAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ21hbnVhbCcsJ25vbmUn'
    'KQogICAgICAgICAgICBwcmludCgn0JTQuNCw0LPQvdC+0YHRgtC40LrQsCDRgdC+0YXRgNCw0L3QtdC90LAuINCf0YDRj9C8'
    '0LDRjyDQvtGC0L/RgNCw0LLQutCwINCy0YvQv9C+0LvQvdGP0LXRgtGB0Y8g0LIg0YTQvtC90LUuJykKICAgICAgICBlbGlm'
    'IGFjdGlvbiA9PSAic3RhdHVzIjogcHJpbnQoanNvbi5kdW1wcyhzdGF0dXMoKSwgZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAg'
    'ICAgICBlbHNlOiByYWlzZSBWYWx1ZUVycm9yKCLQndC10LjQt9Cy0LXRgdGC0L3QsNGPINGN0LrRgdC/0LXRgNC40LzQtdC9'
    '0YLQsNC70YzQvdCw0Y8g0L7Qv9C10YDQsNGG0LjRjy4iKQogICAgZXhjZXB0IChWYWx1ZUVycm9yLCBSdW50aW1lRXJyb3Is'
    'IE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBhY3Rpb24gPT0gJ29uJyBh'
    'bmQgbm90IGdldGF0dHIoZXhjLCdkaWFnbm9zdGljX3F1ZXVlZCcsRmFsc2UpOgogICAgICAgICAgICB0cnk6CiAgICAgICAg'
    'ICAgICAgICBpbnN0YWxsX2RlbGl2ZXJ5KCkKICAgICAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ3ByZXBhcmUnLGZh'
    'aWx1cmVfY29kZShleGMpKQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgcmFpc2UgYXBpLlZQ'
    'TkVycm9yKHN0cihleGMpKSBmcm9tIGV4YwoKClRFU1RfVU5JVCA9ICdldmdlbml1bS1pa2V2Mi1nbG9iYWwtdGVzdC5zZXJ2'
    'aWNlJwpURVNUX1NUQVRFID0gcGF0aGxpYi5QYXRoKCcvdmFyL2xpYi92cG4tbWFuYWdlci9zdGFyZml2ZS10ZXN0Lmpzb24n'
    'KQpQRU5ESU5HX1RFU1QgPSBST09UIC8gJ3BlbmRpbmctZ2xvYmFsLXRlc3QuanNvbicKUlVfRE9NQUlOUyA9ICgneWFuZGV4'
    'LnJ1JywgJ21haWwucnUnLCAnd3d3LnJ0LnJ1JykKVEVTVF9CTE9DSyA9IGhhc2hsaWIuc2hha2VfMjU2KGInZXZnZW5pdW0t'
    'c3RhcmZpdmUtaW50ZWdyaXR5LXYxJykuZGlnZXN0KDY1NTM2KQoKCmRlZiB0ZXN0X3N0YXR1cygpOgogICAgdHJ5OgogICAg'
    'ICAgIHN0YXRlPWpzb24ubG9hZHMoVEVTVF9TVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVy'
    'cm9yKToKICAgICAgICByZXR1cm4geydwaGFzZSc6J2lkbGUnLCdwcm9ncmVzcyc6MH0KICAgIGlmIHN0YXRlLmdldCgncGhh'
    'c2UnKT09J3J1bm5pbmcnIGFuZCBjbWQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLFRFU1RfVU5JVF0sY2hlY2s9RmFsc2Up'
    'LnJldHVybmNvZGU6CiAgICAgICAgc3RhdGUudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsbWVzc2FnZT0n0KLQtdGB0YIg'
    '0L/RgNC10YDQstCw0L0uINCX0LDRidC40YLQsCBWUE4g0YHQvtGF0YDQsNC90Y/QtdGC0YHRjy4nKQogICAgcmV0dXJuIHN0'
    'YXRlCgoKZGVmIHRlc3Rfc3RhdGUoKipmaWVsZHMpOgogICAgdHJ5OiBzdGF0ZT1qc29uLmxvYWRzKFRFU1RfU1RBVEUucmVh'
    'ZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6IHN0YXRlPXt9CiAgICB3cml0ZShURVNUX1NUQVRF'
    'LGpzb24uZHVtcHMoeyoqc3RhdGUsKipmaWVsZHN9LGVuc3VyZV9hc2NpaT1GYWxzZSkpCgoKZGVmIHRlc3RfcmVxdWVzdChw'
    'YXRoLCBkYXRhPU5vbmUsIGhlYWRlcnM9Tm9uZSwgdGltZW91dD0zMCk6CiAgICBjb250ZXh0PXNzbC5jcmVhdGVfZGVmYXVs'
    'dF9jb250ZXh0KGNhZmlsZT1zdHIoUk9PVC8nY2EucGVtJykpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9P'
    'VC8nY2xpZW50LnBlbScpLHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgb3BlbmVyPXVybGxpYi5yZXF1ZXN0LmJ1'
    'aWxkX29wZW5lcih1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pLHVybGxpYi5yZXF1ZXN0LkhUVFBTSGFuZGxlcihj'
    'b250ZXh0PWNvbnRleHQpKQogICAgcmVxdWVzdD11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxUSCtwYXRoLGRhdGE9ZGF0'
    'YSxoZWFkZXJzPWhlYWRlcnMgb3Ige30pCiAgICByZXR1cm4gb3BlbmVyLm9wZW4ocmVxdWVzdCx0aW1lb3V0PXRpbWVvdXQp'
    'CgoKZGVmIGV4cGVjdGVkX2hhc2goc2l6ZSwgb2Zmc2V0PTApOgogICAgZGlnZXN0PWhhc2hsaWIuc2hhMjU2KCkKICAgIHdo'
    'aWxlIHNpemU6CiAgICAgICAgcGFydD1URVNUX0JMT0NLW29mZnNldCAlIGxlbihURVNUX0JMT0NLKTpdWzptaW4oc2l6ZSxs'
    'ZW4oVEVTVF9CTE9DSyktb2Zmc2V0ICUgbGVuKFRFU1RfQkxPQ0spKV0KICAgICAgICBkaWdlc3QudXBkYXRlKHBhcnQpOyBz'
    'aXplLT1sZW4ocGFydCk7IG9mZnNldCs9bGVuKHBhcnQpCiAgICByZXR1cm4gZGlnZXN0LmhleGRpZ2VzdCgpCgoKZGVmIHRy'
    'YW5zZmVyX2Rvd25sb2FkKHNpemUsIG9mZnNldD0wLCBsaW1pdD1Ob25lKToKICAgIHN0YXJ0PXRpbWUubW9ub3RvbmljKCk7'
    'IHJlY2VpdmVkPTA7IGRpZ2VzdD1oYXNobGliLnNoYTI1NigpCiAgICBoZWFkZXJzPXsnUmFuZ2UnOmYnYnl0ZXM9e29mZnNl'
    'dH0tJ30gaWYgb2Zmc2V0IGVsc2Uge30KICAgIHdpdGggdGVzdF9yZXF1ZXN0KCcvYmxvYj9zaXplPScrc3RyKHNpemUpLGhl'
    'YWRlcnM9aGVhZGVycykgYXMgcmVzcG9uc2U6CiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9ICgyMDYgaWYgb2Zmc2V0'
    'IGVsc2UgMjAwKTogcmFpc2UgUnVudGltZUVycm9yKCdVbmV4cGVjdGVkIGZpbGUgcmVzcG9uc2UnKQogICAgICAgIGlmIG9m'
    'ZnNldCBhbmQgcmVzcG9uc2UuaGVhZGVycy5nZXQoJ0NvbnRlbnQtUmFuZ2UnKSE9ZidieXRlcyB7b2Zmc2V0fS17c2l6ZS0x'
    'fS97c2l6ZX0nOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ0ludmFsaWQgcmVzdW1lIHJhbmdlJykKICAgICAg'
    'ICB0b3RhbD1zaXplLW9mZnNldCBpZiBsaW1pdCBpcyBOb25lIGVsc2UgbWluKGxpbWl0LHNpemUtb2Zmc2V0KQogICAgICAg'
    'IHdoaWxlIHJlY2VpdmVkPHRvdGFsOgogICAgICAgICAgICBibG9jaz1yZXNwb25zZS5yZWFkKG1pbig2NTUzNix0b3RhbC1y'
    'ZWNlaXZlZCkpCiAgICAgICAgICAgIGlmIG5vdCBibG9jazogYnJlYWsKICAgICAgICAgICAgZGlnZXN0LnVwZGF0ZShibG9j'
    'ayk7IHJlY2VpdmVkKz1sZW4oYmxvY2spCiAgICAgICAgaW50ZWdyaXR5PXJlY2VpdmVkPT10b3RhbCBhbmQgZGlnZXN0Lmhl'
    'eGRpZ2VzdCgpPT1leHBlY3RlZF9oYXNoKHRvdGFsLG9mZnNldCkKICAgICAgICBpZiBsaW1pdCBpcyBOb25lOgogICAgICAg'
    'ICAgICBpbnRlZ3JpdHk9aW50ZWdyaXR5IGFuZCByZXNwb25zZS5oZWFkZXJzLmdldCgnWC1Db250ZW50LVNIQTI1NicpPT1k'
    'aWdlc3QuaGV4ZGlnZXN0KCkKICAgIGVsYXBzZWQ9bWF4KHRpbWUubW9ub3RvbmljKCktc3RhcnQsMC4wMDEpCiAgICByZXR1'
    'cm4geydraW5kJzonZG93bmxvYWQnLCdvayc6aW50ZWdyaXR5LCdpbnRlZ3JpdHknOmludGVncml0eSwnYnl0ZXMnOnJlY2Vp'
    'dmVkLAogICAgICAgICAgICAnc2l6ZSc6c2l6ZSwnb2Zmc2V0JzpvZmZzZXQsJ2VsYXBzZWRfbXMnOnJvdW5kKGVsYXBzZWQq'
    'MTAwMCksCiAgICAgICAgICAgICdtYnBzX21pbGxpJzpyb3VuZChyZWNlaXZlZCo4L2VsYXBzZWQvMTAwMCl9CgoKZGVmIHRy'
    'YW5zZmVyX3VwbG9hZChzaXplKToKICAgIGRhdGE9KFRFU1RfQkxPQ0sqKChzaXplK2xlbihURVNUX0JMT0NLKS0xKS8vbGVu'
    'KFRFU1RfQkxPQ0spKSlbOnNpemVdCiAgICBzdGFydD10aW1lLm1vbm90b25pYygpCiAgICB3aXRoIHRlc3RfcmVxdWVzdCgn'
    'L3VwbG9hZCcsZGF0YT1kYXRhLGhlYWRlcnM9eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0nfSkg'
    'YXMgcmVzcG9uc2U6CiAgICAgICAgcmVwbHk9anNvbi5sb2FkcyhyZXNwb25zZS5yZWFkKDQwOTYpKQogICAgZWxhcHNlZD1t'
    'YXgodGltZS5tb25vdG9uaWMoKS1zdGFydCwwLjAwMSkKICAgIGludGVncml0eT1yZXBseS5nZXQoJ3JlY2VpdmVkX2J5dGVz'
    'Jyk9PXNpemUgYW5kIHJlcGx5LmdldCgnc2hhMjU2Jyk9PWhhc2hsaWIuc2hhMjU2KGRhdGEpLmhleGRpZ2VzdCgpCiAgICBy'
    'ZXR1cm4geydraW5kJzondXBsb2FkJywnb2snOmludGVncml0eSwnaW50ZWdyaXR5JzppbnRlZ3JpdHksJ2J5dGVzJzpzaXpl'
    'LAogICAgICAgICAgICAnZWxhcHNlZF9tcyc6cm91bmQoZWxhcHNlZCoxMDAwKSwnbWJwc19taWxsaSc6cm91bmQoc2l6ZSo4'
    'L2VsYXBzZWQvMTAwMCl9CgoKZGVmIHBpbmdfdGVzdChzaXplPTU2LCBjb3VudD0yMCk6CiAgICBjcD1jbWQoWydwaW5nJywn'
    'LW4nLCctTScsJ2RvJywnLXMnLHN0cihzaXplKSwnLWMnLHN0cihjb3VudCksJy1pJywnMC4yJywnLVcnLCcyJywnMTAuNzcu'
    'MC4xJ10sY2hlY2s9RmFsc2UsdGltZW91dD00NSkKICAgIHBhY2tldHM9cmUuc2VhcmNoKHInKFxkKykgcGFja2V0cyB0cmFu'
    'c21pdHRlZCwgKFxkKykgcmVjZWl2ZWQnLGNwLnN0ZG91dCkKICAgIHNlbnQscmVjZWl2ZWQ9KGludCh4KSBmb3IgeCBpbiBw'
    'YWNrZXRzLmdyb3VwcygpKSBpZiBwYWNrZXRzIGVsc2UgKGNvdW50LDApCiAgICByb3c9eydraW5kJzoncGluZycsJ29rJzpy'
    'ZWNlaXZlZD09c2VudCwnc2VudCc6c2VudCwncmVjZWl2ZWQnOnJlY2VpdmVkLAogICAgICAgICAnbG9zc19taWxsaSc6cm91'
    'bmQoKHNlbnQtcmVjZWl2ZWQpKjEwMDAwMC9tYXgoc2VudCwxKSksJ3NpemUnOnNpemV9CiAgICBydHQ9cmUuc2VhcmNoKHIn'
    'PSAoW1xkLl0rKS8oW1xkLl0rKS8oW1xkLl0rKS8oW1xkLl0rKSBtcycsY3Auc3Rkb3V0KQogICAgaWYgcnR0OgogICAgICAg'
    'IHJvdy51cGRhdGUoe2tleTpyb3VuZChmbG9hdCh2YWx1ZSkqMTAwMCkgZm9yIGtleSx2YWx1ZSBpbiB6aXAoCiAgICAgICAg'
    'ICAgICgncnR0X21pbl91cycsJ3J0dF9hdmdfdXMnLCdydHRfbWF4X3VzJywncnR0X21kZXZfdXMnKSxydHQuZ3JvdXBzKCkp'
    'fSkKICAgIHJldHVybiByb3cKCgpkZWYgdHJhbnNwb3J0X2NvdW50ZXJzKCk6CiAgICByZXN1bHQ9eydraW5kJzonY291bnRl'
    'cnMnLCdvayc6VHJ1ZX0KICAgIHRyeToKICAgICAgICByYXc9c3dhbignLS1saXN0LXNhcycsJy0tcmF3Jykuc3Rkb3V0CiAg'
    'ICAgICAgZm9yIHNvdXJjZSx0YXJnZXQgaW4gKCgnYnl0ZXMtaW4nLCdieXRlc19pbicpLCgnYnl0ZXMtb3V0JywnYnl0ZXNf'
    'b3V0JyksKCdwYWNrZXRzLWluJywncGFja2V0c19pbicpLCgncGFja2V0cy1vdXQnLCdwYWNrZXRzX291dCcpKToKICAgICAg'
    'ICAgICAgcmVzdWx0W3RhcmdldF09c3VtKGludCh4KSBmb3IgeCBpbiByZS5maW5kYWxsKHInXGInK3NvdXJjZStyJz0oXGQr'
    'KScscmF3KSkKICAgICAgICBsaW5lcz1wYXRobGliLlBhdGgoJy9wcm9jL25ldC9zbm1wJykucmVhZF90ZXh0KCkuc3BsaXRs'
    'aW5lcygpCiAgICAgICAgZm9yIGZpcnN0LHNlY29uZCBpbiB6aXAobGluZXMsbGluZXNbMTpdKToKICAgICAgICAgICAgaWYg'
    'Zmlyc3Quc3RhcnRzd2l0aCgnVGNwOicpIGFuZCBzZWNvbmQuc3RhcnRzd2l0aCgnVGNwOicpOgogICAgICAgICAgICAgICAg'
    'dmFsdWVzPWRpY3QoemlwKGZpcnN0LnNwbGl0KClbMTpdLHNlY29uZC5zcGxpdCgpWzE6XSkpCiAgICAgICAgICAgICAgICBp'
    'ZiAnUmV0cmFuc1NlZ3MnIGluIHZhbHVlczoKICAgICAgICAgICAgICAgICAgICByZXN1bHRbJ3JldHJhbnNfc2VnbWVudHMn'
    'XT1pbnQodmFsdWVzWydSZXRyYW5zU2VncyddKQogICAgICAgICAgICAgICAgICAgIHJlc3VsdFsnb3V0X3NlZ21lbnRzJ109'
    'aW50KHZhbHVlc1snT3V0U2VncyddKQogICAgICAgIGlmIGJhY2tlbmQoKT09J2tlcm5lbCc6CiAgICAgICAgICAgIHJlc3Vs'
    'dFsneGZybV9lcnJvcnMnXT1zdW0oaW50KHguc3BsaXQoKVsxXSkgZm9yIHggaW4gcGF0aGxpYi5QYXRoKCcvcHJvYy9uZXQv'
    'eGZybV9zdGF0JykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVu'
    'dGltZUVycm9yKTogcmVzdWx0WydvayddPUZhbHNlCiAgICByZXR1cm4gcmVzdWx0CgoKZGVmIGZsdXNoX3Rlc3RfcmVwb3J0'
    'KCk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBvciBub3QgUEVORElOR19URVNULmV4aXN0cygpOiBy'
    'ZXR1cm4gRmFsc2UKICAgIGJvZHk9anNvbi5sb2FkcyhQRU5ESU5HX1RFU1QucmVhZF90ZXh0KCkpCiAgICBpZiBub3QgZGVs'
    'aXZlcl9yZXBvcnQoYm9keSk6IHJldHVybiBGYWxzZQogICAgUEVORElOR19URVNULnVubGluayhtaXNzaW5nX29rPVRydWUp'
    'CiAgICB0ZXN0X3N0YXRlKHNlbnQ9VHJ1ZSxtZXNzYWdlPSfQotC10YHRgiDQt9Cw0LLQtdGA0YjRkdC9LiDQntGC0YfRkdGC'
    'INC00L7RgdGC0LDQstC70LXQvSDQvdCwIFN0YXJGaXZlLicpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBzdGFydF9nbG9iYWxf'
    'dGVzdCgpOgogICAgaWYgY21kKFsnc3lzdGVtY3RsJywnaXMtYWN0aXZlJyxURVNUX1VOSVRdLGNoZWNrPUZhbHNlKS5yZXR1'
    'cm5jb2RlPT0wOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIg0YPQ'
    'ttC1INCy0YvQv9C+0LvQvdGP0LXRgtGB0Y8uJykKICAgIGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOiByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ9CS0LrQu9GO0YfQuCDQstGA0LXQvNC10L3QvdGD0Y4g0LTQuNCw0LPQvdC+0YHRgtC40LrRgyDQ'
    'tNC70Y8g0L7RgtC/0YDQsNCy0LrQuCDRgNC10LfRg9C70YzRgtCw0YLQvtCyLicpCiAgICBpZiBub3QgY29ubmVjdGVkKCkg'
    'b3Igbm90IGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC/0L7QtNC60LvRjtGH'
    '0LjRgdGMINC6IFN0YXJGaXZlLicpCiAgICBpZiBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgndGVzdF9hcGknKSE9MTogcmFp'
    'c2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQvtCx0L3QvtCy0LjRgtGMINGC0LXRgdGC0L7QstGL0Lkg0YHQtdGA'
    '0LLQuNGBIFN0YXJGaXZlLicpCiAgICBpZiBQRU5ESU5HX1RFU1QuZXhpc3RzKCkgYW5kIG5vdCBmbHVzaF90ZXN0X3JlcG9y'
    'dCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ce0LbQuNC00LDQtdGCINC+0YLQv9GA0LDQstC60Lgg0L/RgNC10LTRi9C00YPR'
    'idC40Lkg0L7RgtGH0ZHRgi4nKQogICAgdW5pdD0nJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZ2xvYmFsIFZQTiBz'
    'dGFiaWxpdHkgdGVzdApBZnRlcj1ldmdlbml1bS1pa2V2Mi5zZXJ2aWNlCltTZXJ2aWNlXQpUeXBlPWV4ZWMKRXhlY1N0YXJ0'
    'PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtZ2xvYmFsLXRlc3QKU3RhbmRhcmRPdXRwdXQ9bnVs'
    'bApTdGFuZGFyZEVycm9yPW51bGwKVGltZW91dFN0b3BTZWM9MTIKUnVudGltZU1heFNlYz05MDAKUmVzdGFydD1ubwonJycK'
    'ICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1RFU1RfVU5JVCx1bml0LDBvNjQ0KQogICAg'
    'Y21kKFsnc3lzdGVtY3RsJywnZGFlbW9uLXJlbG9hZCddKQogICAgdGVzdF9zdGF0ZShwaGFzZT0ncnVubmluZycscHJvZ3Jl'
    'c3M9MCxzZW50PUZhbHNlLHBhc3NlZD0wLGZhaWxlZD0wLGR1cmF0aW9uX3M9MCxtZXNzYWdlPSfQl9Cw0L/Rg9GB0Log0YLQ'
    'tdGB0YLQsCcscnVuPW9zLnVyYW5kb20oMTIpLmhleCgpLHN0YXJ0ZWQ9aW50KHRpbWUudGltZSgpKSkKICAgIHRyeTogY21k'
    'KFsnc3lzdGVtY3RsJywnc3RhcnQnLFRFU1RfVU5JVF0pCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHRlc3Rfc3Rh'
    'dGUocGhhc2U9J2ZhaWxlZCcsbWVzc2FnZT0n0J3QtSDRg9C00LDQu9C+0YHRjCDQt9Cw0L/Rg9GB0YLQuNGC0Ywg0YLQtdGB'
    '0YIuJyk7IHJhaXNlCiAgICBwcmludCgn0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIg0LfQsNC/0YPRidC10L0g0LIg'
    '0YTQvtC90LUuINCY0L3RgtC10YDQvdC10YIg0L3QtdGB0LrQvtC70YzQutC+INGA0LDQtyDQv9GA0LXRgNCy0ZHRgtGB0Y87'
    'IGtpbGwgc3dpdGNoINC+0YHRgtCw0ZHRgtGB0Y8g0LLQutC70Y7Rh9GR0L3QvdGL0LwuJykKCgpjbGFzcyBUZXN0Q2FuY2Vs'
    'bGVkKEV4Y2VwdGlvbik6IHBhc3MKCgpkZWYgcnVuX2dsb2JhbF90ZXN0KCk6CiAgICBpbXBvcnQgc2lnbmFsCiAgICBmcm9t'
    'IGNvbmN1cnJlbnQuZnV0dXJlcyBpbXBvcnQgVGhyZWFkUG9vbEV4ZWN1dG9yCiAgICBkZWYgY2FuY2VsKCpfKTogcmFpc2Ug'
    'VGVzdENhbmNlbGxlZCgpCiAgICBvbGQ9c2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSxjYW5jZWwpCiAgICByZWNvcmRz'
    'PVtdOyBvdXRjb21lPSdjb21wbGV0ZWQnOyBzdGFydGVkPXRpbWUubW9ub3RvbmljKCkKICAgIGRlZiBzdGFnZShwcm9ncmVz'
    'cyxtZXNzYWdlKTogdGVzdF9zdGF0ZShwaGFzZT0ncnVubmluZycscHJvZ3Jlc3M9cHJvZ3Jlc3MsbWVzc2FnZT1tZXNzYWdl'
    'KQogICAgZGVmIG1lYXN1cmUoa2luZCxvcGVyYXRpb24sKipmaWVsZHMpOgogICAgICAgIGJlZm9yZT10aW1lLm1vbm90b25p'
    'YygpCiAgICAgICAgdHJ5OiByb3c9b3BlcmF0aW9uKCkKICAgICAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogcmFpc2UKICAg'
    'ICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgZXJyb3I9J290aGVyJwogICAgICAgICAgICBpZiBp'
    'c2luc3RhbmNlKGV4Yyx1cmxsaWIuZXJyb3IuSFRUUEVycm9yKTogZXJyb3I9J2h0dHAnCiAgICAgICAgICAgIGVsaWYgaXNp'
    'bnN0YW5jZShleGMsKFRpbWVvdXRFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSk6IGVycm9yPSd0aW1lb3V0Jwog'
    'ICAgICAgICAgICBlbGlmIGlzaW5zdGFuY2UoZXhjLHNzbC5TU0xFcnJvcik6IGVycm9yPSd0bHMnCiAgICAgICAgICAgIGVs'
    'aWYgaXNpbnN0YW5jZShleGMsT1NFcnJvcik6IGVycm9yPSduZXR3b3JrJwogICAgICAgICAgICByb3c9eydraW5kJzpraW5k'
    'LCdvayc6RmFsc2UsJ2Vycm9yJzplcnJvcn0KICAgICAgICAgICAgaWYgaXNpbnN0YW5jZShleGMsdXJsbGliLmVycm9yLkhU'
    'VFBFcnJvcik6IHJvd1snaHR0cF9zdGF0dXMnXT1leGMuY29kZQogICAgICAgIHJvdy5zZXRkZWZhdWx0KCdlbGFwc2VkX21z'
    'Jyxyb3VuZCgodGltZS5tb25vdG9uaWMoKS1iZWZvcmUpKjEwMDApKQogICAgICAgIHJvd1snYXRfbXMnXT1yb3VuZCgodGlt'
    'ZS5tb25vdG9uaWMoKS1zdGFydGVkKSoxMDAwKQogICAgICAgIHJvdy51cGRhdGUoZmllbGRzKTsgcmVjb3Jkcy5hcHBlbmQo'
    'cm93KTsgcmV0dXJuIHJvdwogICAgZGVmIHJlY29ubmVjdChyZXN0YXJ0PUZhbHNlKToKICAgICAgICBiZWZvcmU9dGltZS5t'
    'b25vdG9uaWMoKQogICAgICAgIGlmIHJlc3RhcnQ6CiAgICAgICAgICAgIGNhbmRpZGF0ZXM9c29ja2V0LmdldGFkZHJpbmZv'
    'KCd5YW5kZXgucnUnLDQ0Myxzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgICAgIGFkZHJlc3M9'
    'bmV4dCh4WzRdWzBdIGZvciB4IGluIGNhbmRpZGF0ZXMgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeFs0XVswXSkuaXNfZ2xv'
    'YmFsKQogICAgICAgICAgICBjbWQoWydzeXN0ZW1jdGwnLCdzdG9wJyxVTklUXSkKICAgICAgICAgICAgbGVha2VkPUZhbHNl'
    'CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChhZGRyZXNz'
    'LDQ0MyksdGltZW91dD0yKTogbGVha2VkPVRydWUKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6IHBhc3MKICAgICAgICAg'
    'ICAgcmVjb3Jkcy5hcHBlbmQoeydraW5kJzonZ3VhcmQnLCdvayc6YWN0aXZlX2d1YXJkKCkgYW5kIG5vdCBsZWFrZWR9KQog'
    'ICAgICAgICAgICAjIE5ldmVyIHJlbW92ZSB0aGUgZ3VhcmQsIGV2ZW4gZHVyaW5nIGEgZGVsaWJlcmF0ZSBkYWVtb24gZmFp'
    'bHVyZS4KICAgICAgICAgICAgaWYgbm90IGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ0d1YXJkIG1pc3Np'
    'bmcnKQogICAgICAgICAgICBjbWQoWydzeXN0ZW1jdGwnLCdzdGFydCcsVU5JVF0pCiAgICAgICAgICAgIHdhaXRfdXNlcnNw'
    'YWNlKCkKICAgICAgICAgICAgc3dhbignLS1sb2FkLWNyZWRzJywnLS1maWxlJyxST09ULydjb25uZWN0aW9uLmNvbmYnKQog'
    'ICAgICAgICAgICBzd2FuKCctLWxvYWQtY29ubnMnLCctLWZpbGUnLFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAg'
    'ZWxzZToKICAgICAgICAgICAgc3dhbignLS10ZXJtaW5hdGUnLCctLWlrZScsJ3N0YXJmaXZlJyxjaGVjaz1GYWxzZSkKICAg'
    'ICAgICBzd2FuKCctLWluaXRpYXRlJywnLS1jaGlsZCcsJ3N0YXJmaXZlLW5ldCcsdGltZW91dD01NSkKICAgICAgICBnb29k'
    'PWNvbm5lY3RlZCgpIGFuZCBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUn'
    'CiAgICAgICAgcmV0dXJuIHsna2luZCc6J2RhZW1vbl9yZXN0YXJ0JyBpZiByZXN0YXJ0IGVsc2UgJ3JlY29ubmVjdCcsJ29r'
    'Jzpnb29kLCdlbGFwc2VkX21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1iZWZvcmUpKjEwMDApfQogICAgZGVmIGNvbnRy'
    'b2woKToKICAgICAgICB3aXRoIHRlc3RfcmVxdWVzdCgnL2NvbnRyb2wnLHRpbWVvdXQ9NDUpIGFzIHJlc3BvbnNlOiBkYXRh'
    'PWpzb24ubG9hZHMocmVzcG9uc2UucmVhZCgxNjM4NCkpCiAgICAgICAgcmVjb3Jkcy5hcHBlbmQoeydraW5kJzonc2VydmVy'
    'X2NvbnRyb2wnLCdvayc6VHJ1ZSwqKmRhdGFbJ21ldHJpY3MnXX0pCiAgICAgICAgZm9yIHByb2JlIGluIGRhdGFbJ3Byb2Jl'
    'cyddOiByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidzZXJ2ZXJfY29udHJvbCcsKipwcm9iZX0pCiAgICAgICAgcmV0dXJuIHsn'
    'a2luZCc6J2hlYWx0aCcsJ29rJzpUcnVlfQogICAgdHJ5OgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLE1PTklU'
    'T1JdLGNoZWNrPUZhbHNlKQogICAgICAgICMgVXNlIFJ1c3NpYW4gRE5TIGZvciB0aGlzIHRlc3QgZXZlbiBvbiBhIHNlc3Np'
    'b24gY3JlYXRlZCBieSBhbiBvbGRlciBjbGllbnQuCiAgICAgICAgaWYgbm90IChST09ULydyZXNvbHYtYmFja3VwJykuZXhp'
    'c3RzKCkgYW5kIG5vdCAoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKTogc2V0X2RucygpCiAgICAgICAg'
    'ZWxpZiAoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKToKICAgICAgICAgICAgaW50ZXJmYWNlPWpzb24u'
    'bG9hZHMoKFJPT1QvJ3Jlc29sdmVkLWJhY2t1cC5qc29uJykucmVhZF90ZXh0KCkpWydpZmFjZSddCiAgICAgICAgICAgIGNt'
    'ZChbJ3Jlc29sdmVjdGwnLCdkbnMnLGludGVyZmFjZSwnNzcuODguOC44JywnNzcuODguOC4xJ10pCiAgICAgICAgZWxzZToK'
    'ICAgICAgICAgICAgcGF0aGxpYi5QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykud3JpdGVfdGV4dCgnbmFtZXNlcnZlciA3Ny44'
    'OC44Ljhcbm5hbWVzZXJ2ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAgICAgIHN0'
    'YWdlKDMsJ9Ca0L7QvdGC0YDQvtC70YzQvdGL0LUg0LfQsNC80LXRgNGLIFN0YXJGaXZlINC4INGA0L7RgdGB0LjQudGB0LrQ'
    'uNGFINGB0LXRgNCy0LjRgdC+0LInKQogICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsY29udHJvbCk7IHJlY29yZHMuYXBwZW5k'
    'KHRyYW5zcG9ydF9jb3VudGVycygpKQogICAgICAgIGZvciBkb21haW4gaW4gUlVfRE9NQUlOUzogbWVhc3VyZSgncnVfcHJv'
    'YmUnLGxhbWJkYSBkPWRvbWFpbjp7J2tpbmQnOidydV9wcm9iZScsKipwcm9iZV9kb21haW4oZCl9KQogICAgICAgIHN0YWdl'
    'KDEyLCfQl9Cw0LTQtdGA0LbQutC4LCDQv9C+0YLQtdGA0Lgg0Lgg0YDQsNC30LzQtdGA0Ysg0L/QsNC60LXRgtC+0LInKQog'
    'ICAgICAgIGZvciBzaXplIGluICg1NiwxMjAwLDEzNjApOiBtZWFzdXJlKCdwaW5nJyxsYW1iZGEgcz1zaXplOnBpbmdfdGVz'
    'dChzKSkKICAgICAgICBmb3IgYXR0ZW1wdCBpbiByYW5nZSgxMik6CiAgICAgICAgICAgIGJlZm9yZT10aW1lLm1vbm90b25p'
    'YygpCiAgICAgICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsbGFtYmRhOnsna2luZCc6J2hlYWx0aCcsJ29rJzplbmRwb2ludCgn'
    'L2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUnfSkKICAgICAgICAgICAgdGltZS5zbGVlcCgw'
    'LjI1KQogICAgICAgIHN0YWdlKDI1LCfQodC60LDRh9C40LLQsNC90LjQtSDQuCDQvtGC0L/RgNCw0LLQutCwINGE0LDQudC7'
    '0L7Qsjog0L/RgNC+0LLQtdGA0LrQsCBTSEEtMjU2JykKICAgICAgICBmb3Igc2l6ZSBpbiAoNjU1MzYsMTA0ODU3Niw4Mzg4'
    'NjA4LDMzNTU0NDMyKTogbWVhc3VyZSgnZG93bmxvYWQnLGxhbWJkYSBzPXNpemU6dHJhbnNmZXJfZG93bmxvYWQocykpCiAg'
    'ICAgICAgZm9yIHNpemUgaW4gKDUyNDI4OCw0MTk0MzA0KTogbWVhc3VyZSgndXBsb2FkJyxsYW1iZGEgcz1zaXplOnRyYW5z'
    'ZmVyX3VwbG9hZChzKSkKICAgICAgICBzdGFnZSg0MCwn0JTQvtC60LDRh9C60LAg0YTQsNC50LvQsCDQv9C+0YHQu9C1INGA'
    '0LDQt9GA0YvQstCwINC4INC/0LXRgNC10L/QvtC00LrQu9GO0YfQtdC90LjRjycpCiAgICAgICAgbWVhc3VyZSgncmVzdW1l'
    'JyxsYW1iZGE6eyoqdHJhbnNmZXJfZG93bmxvYWQoODM4ODYwOCxsaW1pdD0zMTQ1NzI4KSwna2luZCc6J3Jlc3VtZSd9KQog'
    'ICAgICAgIG1lYXN1cmUoJ3JlY29ubmVjdCcscmVjb25uZWN0KQogICAgICAgIG1lYXN1cmUoJ3Jlc3VtZScsbGFtYmRhOnsq'
    'KnRyYW5zZmVyX2Rvd25sb2FkKDgzODg2MDgsb2Zmc2V0PTMxNDU3MjgpLCdraW5kJzoncmVzdW1lJ30pCiAgICAgICAgc3Rh'
    'Z2UoNTAsJ9Cf0LDRgNCw0LvQu9C10LvRjNC90LDRjyDQv9C10YDQtdC00LDRh9CwINCyINC+0LHQtSDRgdGC0L7RgNC+0L3R'
    'iycpCiAgICAgICAgd2l0aCBUaHJlYWRQb29sRXhlY3V0b3IobWF4X3dvcmtlcnM9MykgYXMgcG9vbDoKICAgICAgICAgICAg'
    'ZnV0dXJlcz1bcG9vbC5zdWJtaXQodHJhbnNmZXJfZG93bmxvYWQsODM4ODYwOCkscG9vbC5zdWJtaXQodHJhbnNmZXJfZG93'
    'bmxvYWQsODM4ODYwOCkscG9vbC5zdWJtaXQodHJhbnNmZXJfdXBsb2FkLDQxOTQzMDQpXQogICAgICAgICAgICBmb3IgZnV0'
    'dXJlIGluIGZ1dHVyZXM6IG1lYXN1cmUoJ3BhcmFsbGVsJyxsYW1iZGEgZj1mdXR1cmU6eyoqZi5yZXN1bHQoKSwna2luZCc6'
    'J3BhcmFsbGVsJ30pCiAgICAgICAgc3RhZ2UoNjIsJ9CU0LvQuNGC0LXQu9GM0L3QsNGPINC/0LXRgNC10LTQsNGH0LA6INC0'
    '0L4gNjAg0YHQtdC60YPQvdC0IC8gNjQg0JzQuNCRJykKICAgICAgICBsb2FkX3N0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKTsg'
    'dW50aWw9bG9hZF9zdGFydGVkKzYwOyBjb3VudD0wCiAgICAgICAgd2hpbGUgdGltZS5tb25vdG9uaWMoKTx1bnRpbCBhbmQg'
    'Y291bnQ8MTY6CiAgICAgICAgICAgIG1lYXN1cmUoJ2Rvd25sb2FkJyxsYW1iZGE6dHJhbnNmZXJfZG93bmxvYWQoNDE5NDMw'
    'NCkpOyBjb3VudCs9MQogICAgICAgICAgICBtZWFzdXJlKCdoZWFsdGgnLGxhbWJkYTp7J2tpbmQnOidoZWFsdGgnLCdvayc6'
    'ZW5kcG9pbnQoJy9oZWFsdGgnKS5nZXQoJ3NlcnZpY2UnKT09J2V2Z2VuaXVtLXN0YXJmaXZlJ30pCiAgICAgICAgICAgIHRp'
    'bWUuc2xlZXAobWF4KDAsbG9hZF9zdGFydGVkK2NvdW50KjQtdGltZS5tb25vdG9uaWMoKSkpCiAgICAgICAgc3RhZ2UoNzUs'
    'J9Cf0YDQvtGB0YLQvtC5IDQ1INGB0LXQutGD0L3QtCDQuCDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1INCw0LrRgtC4'
    '0LLQvdC+0YHRgtC4JykKICAgICAgICB0aW1lLnNsZWVwKDQ1KQogICAgICAgIG1lYXN1cmUoJ2lkbGUnLGxhbWJkYTp7J2tp'
    'bmQnOidpZGxlJywnb2snOmVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFyZml2ZScs'
    'J2VsYXBzZWRfbXMnOjQ1MDAwfSkKICAgICAgICBzdGFnZSg4Miwn0J/Rj9GC0Ywg0L/QvtCy0YLQvtGA0L3Ri9GFINC/0L7Q'
    'tNC60LvRjtGH0LXQvdC40LknKQogICAgICAgIGZvciBhdHRlbXB0IGluIHJhbmdlKDUpOgogICAgICAgICAgICBtZWFzdXJl'
    'KCdyZWNvbm5lY3QnLHJlY29ubmVjdCxhdHRlbXB0PWF0dGVtcHQrMSk7IHRpbWUuc2xlZXAoMSkKICAgICAgICBzdGFnZSg5'
    'Miwn0J/QtdGA0LXQt9Cw0L/Rg9GB0LogVlBOLdC00LXQvNC+0L3QsCDRgSDRgdC+0YXRgNCw0L3QtdC90LjQtdC8IGtpbGwg'
    'c3dpdGNoJykKICAgICAgICBtZWFzdXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkKICAgICAg'
    'ICByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidndWFyZCcsJ29rJzphY3RpdmVfZ3VhcmQoKX0pCiAgICAgICAgc3RhZ2UoOTYs'
    'J9CX0LDQutC70Y7Rh9C40YLQtdC70YzQvdGL0LUg0LfQsNC80LXRgNGLINC4INC+0YLQv9GA0LDQstC60LAg0L7RgtGH0ZHR'
    'gtCwJykKICAgICAgICBmb3IgZG9tYWluIGluIFJVX0RPTUFJTlM6IG1lYXN1cmUoJ3J1X3Byb2JlJyxsYW1iZGEgZD1kb21h'
    'aW46eydraW5kJzoncnVfcHJvYmUnLCoqcHJvYmVfZG9tYWluKGQpfSkKICAgICAgICBtZWFzdXJlKCdoZWFsdGgnLGNvbnRy'
    'b2wpOyByZWNvcmRzLmFwcGVuZCh0cmFuc3BvcnRfY291bnRlcnMoKSkKICAgICAgICBpZiBhbnkobm90IHguZ2V0KCdvaycp'
    'IGZvciB4IGluIHJlY29yZHMpOiBvdXRjb21lPSdmYWlsZWQnCiAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogb3V0Y29tZT0n'
    'Y2FuY2VsbGVkJwogICAgZXhjZXB0IEV4Y2VwdGlvbjogb3V0Y29tZT0nZmFpbGVkJwogICAgZmluYWxseToKICAgICAgICAj'
    'IFJlY292ZXIgb25seSBvdXIgZGFlbW9uL3Nlc3Npb24uIE5ldmVyIGRpc2FibGUgdGhlIGd1YXJkIG9yIHJlc3RvcmUgZGly'
    'ZWN0IHRyYWZmaWMuCiAgICAgICAgaWYgb3V0Y29tZSE9J2NhbmNlbGxlZCcgYW5kIG5vdCBjb25uZWN0ZWQoKToKICAgICAg'
    'ICAgICAgdHJ5OiBtZWFzdXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkKICAgICAgICAgICAg'
    'ZXhjZXB0IEV4Y2VwdGlvbjogcGFzcwogICAgICAgIGJvZHk9eydzY2hlbWEnOjEsJ2V2ZW50JzonZ2xvYmFsX3Rlc3QnLCdt'
    'YW5hZ2VyJzonMC4yLjIzJywncnVuJzp0ZXN0X3N0YXR1cygpLmdldCgncnVuJyxvcy51cmFuZG9tKDEyKS5oZXgoKSksJ291'
    'dGNvbWUnOm91dGNvbWUsJ2R1cmF0aW9uX21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydGVkKSoxMDAwKSwncmVj'
    'b3Jkcyc6cmVjb3Jkc1s6MjU2XX0KICAgICAgICB3cml0ZShQRU5ESU5HX1RFU1QsanNvbi5kdW1wcyhib2R5KSkKICAgICAg'
    'ICB0ZXN0X3N0YXRlKHBoYXNlPW91dGNvbWUscHJvZ3Jlc3M9MTAwLHNlbnQ9RmFsc2UsZHVyYXRpb25fcz1yb3VuZCh0aW1l'
    'Lm1vbm90b25pYygpLXN0YXJ0ZWQpLAogICAgICAgICAgICAgICAgICAgcGFzc2VkPXN1bShib29sKHguZ2V0KCdvaycpKSBm'
    'b3IgeCBpbiByZWNvcmRzKSxmYWlsZWQ9c3VtKG5vdCB4LmdldCgnb2snKSBmb3IgeCBpbiByZWNvcmRzKSwKICAgICAgICAg'
    'ICAgICAgICAgIG1lc3NhZ2U9J9Ce0YLRh9GR0YIg0YHQvtGF0YDQsNC90ZHQvS4g0J7QttC40LTQsNC10YIg0L7RgtC/0YDQ'
    'sNCy0LrQuCDRh9C10YDQtdC3IFN0YXJGaXZlLicpCiAgICAgICAgdHJ5OiBmbHVzaF90ZXN0X3JlcG9ydCgpCiAgICAgICAg'
    'ZXhjZXB0IEV4Y2VwdGlvbjoga2lja19kZWxpdmVyeSgpCiAgICAgICAgaWYgY29ubmVjdGVkKCkgYW5kIHN0b3JlZCgpLmdl'
    'dCgndGVsZW1ldHJ5Jyk6CiAgICAgICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JyxNT05JVE9SXSxjaGVjaz1GYWxz'
    'ZSkKICAgICAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLG9sZCkK'
)

import types
starfive = types.ModuleType("starfive_experimental")
exec(compile(base64.b64decode(STARFIVE_EXPERIMENTAL_PY_B64), "starfive_experimental.py", "exec"), starfive.__dict__)

starfive_tunnel = types.ModuleType("starfive_tunnel")
exec(compile(base64.b64decode(STARFIVE_TUNNEL_PY_B64), "starfive_tunnel.py", "exec"), starfive_tunnel.__dict__)
starfive.tunnel = starfive_tunnel

def _starfive_api():
    return types.SimpleNamespace(VPNError=VPNError, service_active=service_active)

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vpn", add_help=False)
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    pexp = sub.add_parser("experimental")
    pexp.add_argument("experimental_cmd", choices=["token-save", "connect", "repair", "disconnect", "prepare", "import", "on", "off", "status", "report", "global-test", "cancel-test", "telemetry-on", "telemetry-off", "send-diagnostics", "backend-userspace", "backend-kernel"])
    pexp.add_argument("target", nargs="?", default="")
    sub.add_parser("internal-starfive-pause-main")
    sub.add_parser("internal-starfive-tunnel")
    sub.add_parser("internal-starfive-tunnel-cleanup")
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
    if args.cmd == "internal-starfive-pause-main":
        if not starfive_tunnel.full_guard_active():
            fail("Experimental kill switch must be installed before pausing Xray.")
        stop_diagnostic()
        stop_core()
        remove_guard()
        st = load_state()
        save_state({**st, "active": None, "last_active": st.get("active") or st.get("last_active")})
        return 0
    if args.cmd == "internal-starfive-tunnel":
        starfive_tunnel.worker()
        return 0
    if args.cmd == "internal-starfive-tunnel-cleanup":
        starfive_tunnel.cleanup()
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
        starfive_tunnel.ensure_dependencies()
        restore_firefox_codex_exceptions(settings)
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
        if not starfive_tunnel.full_guard_active():
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
