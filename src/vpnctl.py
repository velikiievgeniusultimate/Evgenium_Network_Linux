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

MANAGER_VERSION = "0.3.2"

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
    'LmJhY2tlbmQgPT09ICJpa2V2MiIgPyAi0JLQtdGB0YwgSVB2NC3RgtGA0LDRhNC40Log0LjQtNGR0YIg0YfQtdGA0LXQtyBI'
    'U1ZEUyDQsiDQrdGB0YLQvtC90LjRji4gSVB2NiDQuCBESVJFQ1Qt0LjRgdC60LvRjtGH0LXQvdC40Y8g0L7RgtC60LvRjtGH'
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
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KCiAgICAgICAgICAgICAgICAgICAgLy8gSXNvbGF0ZWQgZXhwZXJp'
    'bWVudGFsIHR1bm5lbDogdGhlIG9yZGluYXJ5IFZQTi9icm93c2VyIHJlbWFpbiB1bnRvdWNoZWQuCiAgICAgICAgICAgICAg'
    'ICAgICAgSXRlbSB7CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'YW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU2Nyb2xsVmlldyB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHN0YXJmaXZlU2Nyb2xsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6'
    'IDI0CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGVudFdpZHRoOiBhdmFpbGFibGVXaWR0aAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHdpZHRoOiBzdGFyZml2ZVNjcm9sbC5hdmFpbGFibGVXaWR0aAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBzcGFjaW5nOiAyMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6ICLQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3Ri9C5'
    'IFZQTiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNYWluOyBmb250'
    'LnBpeGVsU2l6ZTogMjI7IGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHRleHQ6ICLQktC10YHRjCDQuNC90YLQtdGA0L3QtdGCINGH0LXRgNC10LcgSFNWRFMg0LIg0JzQvtGB0LrQ'
    'stC1INC4INCt0YHRgtC+0L3QuNGOLiDQl9Cw0LLQuNGB0LjQvNC+0YHRgtC4INGD0YHRgtCw0L3QvtCy0Y/RgtGB0Y8g0LDQ'
    'stGC0L7QvNCw0YLQuNGH0LXRgdC60LguIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6'
    'IHJvb3QudGV4dE11dGVkOyB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KLQvtC60LXQvSDQ'
    'utC70LjQtdC90YLQsCI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9udC5EZW1pQm9sZCB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBzcGFjaW5nOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBzdGFyZml2ZVRva2VuCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0SGVpZ2h0OiA0MgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGxlZnRQYWRkaW5nOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHJpZ2h0UGFkZGluZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LnBp'
    'eGVsU2l6ZTogMTQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0'
    'TWFpbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJhZGl1czogMTAKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudG9rZW5Mb2NrZWQgPyAiI2YwZjhmYyIg'
    'OiByb290LnN1cmZhY2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYm9yZGVyLndp'
    'ZHRoOiAxCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci5jb2xvcjogc3Rh'
    'cmZpdmVUb2tlbi5hY3RpdmVGb2N1cyA/IHJvb3QuYWNjZW50IDogcm9vdC5ib3JkZXIKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGxh'
    'Y2Vob2xkZXJUZXh0OiByb290LnRva2VuTG9ja2VkID8gU3RyaW5nKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS50'
    'b2tlbl9oaW50IHx8ICLQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0iKSA6ICLQktGB0YLQsNCy0YzRgtC1INGC0L7QutC1'
    '0L0gRVZOMS3igKYiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWNob01vZGU6IFRleHRJ'
    'bnB1dC5QYXNzd29yZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlYWRPbmx5OiByb290'
    'LnRva2VuTG9ja2VkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTog'
    'IXJvb3QudG9rZW5Mb2NrZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiAh'
    'cm9vdC5idXN5ICYmICFCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1heGltdW1MZW5ndGg6IDY0CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0KLQvtC60LXQvSDQutC70LjQtdC90YLQsCIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFjY2VwdGVkOiB0b2tlbkNvbmZpcm0uY29uZmly'
    'bSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBp'
    'ZDogdG9rZW5Db25maXJtCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFiZWw6IHJvb3Qu'
    'dG9rZW5Mb2NrZWQgPyAi0JjQt9C80LXQvdC40YLRjCIgOiAi0J/QvtC00YLQstC10YDQtNC40YLRjCIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiAhcm9vdC50b2tlbkxvY2tlZAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIUJvb2xlYW4oKHJv'
    'b3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLnJ1bm5pbmcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICYmIChyb290LnRva2VuTG9ja2VkIHx8IC9eRVZOMS1bQS1aYS16MC05Xy1dezQzfSQvLnRlc3Qoc3Rh'
    'cmZpdmVUb2tlbi50ZXh0LnRyaW0oKSkpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZnVu'
    'Y3Rpb24gY29uZmlybSgpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFl'
    'bmFibGVkQnV0dG9uKSByZXR1cm4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYg'
    'KHJvb3QudG9rZW5Mb2NrZWQpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHJvb3QudG9rZW5FZGl0aW5nID0gdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgc3RhcmZpdmVUb2tlbi5mb3JjZUFjdGl2ZUZvY3VzKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHJvb3QuYWN0aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfdG9rZW4tc2F2ZSIsIHRhcmdldDogc3RhcmZpdmVUb2tl'
    'bi50ZXh0LnRyaW0oKX0sIGZ1bmN0aW9uKCkgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHN0YXJmaXZlVG9rZW4uY2xlYXIoKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIHJvb3QudG9rZW5FZGl0aW5nID0gZmFsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiBjb25maXJtKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiB0b2tlbkNhbmNlbAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J7RgtC80LXQvdCwIgogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJvb3QudG9rZW5FZGl0aW5nICYmIHJvb3QudG9rZW5TYXZlZAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHsgc3RhcmZpdmVUb2tlbi5jbGVhcigp'
    'OyByb290LnRva2VuRWRpdGluZyA9IGZhbHNlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0LldvcmRXcmFwCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiByb290LnRva2VuTG9ja2VkID8gItCi0L7QutC10L0g'
    '0YHQvtGF0YDQsNC90ZHQvSDQvdCwINGD0YHRgtGA0L7QudGB0YLQstC1LiDQn9GA0L7QstC10YDQutCwINC90LAg0YHQtdGA'
    '0LLQtdGA0LUg4oCUINC/0YDQuCDQv9C+0LTQutC70Y7Rh9C10L3QuNC4LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICA6IHJvb3QudG9rZW5FZGl0aW5nID8gItCS0YHRgtCw0LLRjNGC0LUg0L3QvtCy0YvQuSDRgtC+'
    '0LrQtdC9INC4INC90LDQttC80LjRgtC1IMKr0J/QvtC00YLQstC10YDQtNC40YLRjMK7LiDQlNC+INGB0L7RhdGA0LDQvdC1'
    '0L3QuNGPINC00LXQudGB0YLQstGD0LXRgiDQv9GA0LXQttC90LjQuSDRgtC+0LrQtdC9LiIKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICA6ICLQotC+0LrQtdC9INC10YnRkSDQvdC1INGB0L7RhdGA0LDQvdGR0L0uINCS'
    '0YHRgtCw0LLRjNGC0LUg0LXQs9C+INC4INC90LDQttC80LjRgtC1IMKr0J/QvtC00YLQstC10YDQtNC40YLRjMK7LiIKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRva2VuTG9ja2VkID8gcm9vdC5nb29k'
    'IDogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24gewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVu'
    'bmVsIHx8IHt9KS5ydW5uaW5nKSA/ICLQntGC0LrQu9GO0YfQuNGC0YwiIDogItCf0L7QtNC60LvRjtGH0LjRgtGMIgogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW1hcnk6ICFCb29sZWFuKChyb290LmV4cGVyaW1l'
    'bnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVu'
    'YWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgKEJvb2xlYW4oKHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLnJ1bm5p'
    'bmcpIHx8IHJvb3QudG9rZW5Mb2NrZWQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25D'
    'bGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5u'
    'aW5nKSA/ICJleHBlcmltZW50YWxfZGlzY29ubmVjdCIgOiAiZXhwZXJpbWVudGFsX2Nvbm5lY3QifSkKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZs'
    'YXRCdXR0b24gewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiAi0J/QvtGH0LjQ'
    'vdC40YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9v'
    'dC5idXN5ICYmIHJvb3QudG9rZW5Mb2NrZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBv'
    'bkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJleHBlcmltZW50YWxfcmVwYWlyIn0pCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgTGF5b3V0LnBy'
    'ZWZlcnJlZEhlaWdodDogMTsgY29sb3I6IHJvb3QuYm9yZGVyIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgQy5MYWJlbCB7IHRleHQ6ICLQodGC0YDQvtC60LAg0YHQvtGB0YLQvtGP0L3QuNGPIjsgY29sb3I6IHJvb3QudGV4dE1h'
    'aW47IGZvbnQud2VpZ2h0OiBGb250LkRlbWlCb2xkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5U'
    'ZXh0QXJlYSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQubWluaW11bUhlaWdodDogMTIwCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWFkT25seTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgc2VsZWN0QnlNb3VzZTogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgd3JhcE1vZGU6IFRleHRFZGl0LldyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRl'
    'eHQ6IFN0cmluZygocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkubWVzc2FnZSB8fCAi0KHQvtGF0YDQsNC90LjRgtC1'
    'INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAuINCf0L7QtNC60LvRjtGH0LXQvdC40LUg0L/QtdGA0LXQutC70Y7Rh9C40YIg'
    '0LLQtdGB0Ywg0LjQvdGC0LXRgNC90LXRgiDQvdCwINGN0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0LkgVlBOLiIp'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAoU3RyaW5nKChyb290LmV4cGVyaW1lbnQu'
    'dHVubmVsIHx8IHt9KS5zY29wZSB8fCAiIikgPT09ICJsYW4iID8gIlxu0J/RgNC+0LLQtdGA0LrQsCDQsiDQtNC+0LzQsNGI'
    '0L3QtdC5INGB0LXRgtC4OyDQstC90LXRiNC90LjQuSDQv9GD0YLRjCDRh9C10YDQtdC3INC/0YDQvtCy0LDQudC00LXRgNCw'
    'INC10YnRkSDQvdC1INC/0YDQvtCy0LXRgNC10L0uIiA6ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICsgKEJvb2xlYW4oKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5pbnRl'
    'Z3JpdHkpID8gIlxu0J/QtdGA0LXQtNCw0YfQsCDQtNCw0L3QvdGL0YU6INGG0LXQu9C+0YHRgtC90L7RgdGC0Ywg0L/QvtC0'
    '0YLQstC10YDQttC00LXQvdCwLiIgOiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAr'
    'ICgoKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5yZWZlcmVuY2UgfHwge30pLmVzdGlt'
    'YXRlZF9tYnBzID8gIlxu0K/QvdC00LXQutGBOiDQvtGG0LXQvdC60LAg0L/RgNGP0LzQvtC5INGB0LrQvtGA0L7RgdGC0Lgg'
    'IiArIE51bWJlcigoKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5yZWZlcmVuY2UgfHwg'
    'e30pLmVzdGltYXRlZF9tYnBzKS50b0ZpeGVkKDEpICsgIiDQnNCx0LjRgi/RgSAo0LrQvtGA0L7RgtC60LjQuSDQt9Cw0LzQ'
    'tdGAKS4iIDogIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKyAoKCgocm9vdC5leHBl'
    'cmltZW50LnR1bm5lbCB8fCB7fSkubWV0cmljcyB8fCB7fSkucmVmZXJlbmNlIHx8IHt9KS5hdmFpbGFibGUgPT09IGZhbHNl'
    'ID8gIlxu0K/QvdC00LXQutGBOiDQvtGA0LjQtdC90YLQuNGAINGB0LrQvtGA0L7RgdGC0Lgg0YHQtdC50YfQsNGBINC90LXQ'
    'tNC+0YHRgtGD0L/QtdC9LiIgOiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBC'
    'b29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5hY3RpdmUpID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TWFp'
    'bgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0KHRgtGA0L7QutCw'
    'INGB0L7RgdGC0L7Rj9C90LjRjyIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLlByb2dyZXNzQmFyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZy'
    'b206IDA7IHRvOiAxMDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlOiBOdW1iZXIoKHJv'
    'b3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLnByb2dyZXNzIHx8IDApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB2aXNpYmxlOiBCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKSAmJiAh'
    'Qm9vbGVhbigocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkuYWN0aXZlKQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEl0ZW0geyBMYXlvdXQuZmlsbEhlaWdo'
    'dDogdHJ1ZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICB9CiAgICAgICAgfQogICAgfQp9Cg=='
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
    'ClNFUlZFUiA9ICcxOTUuMjA5LjIxMS4xNjMnCklLRV9QT1JUID0gMjQ1NTAKRU5EUE9JTlRTID0gKFNFUlZFUiwpCiMgS2Vw'
    'dCBvbmx5IGZvciByZW1vdmluZyByb3V0ZXMgaW5zdGFsbGVkIGJ5IHByZS1taWdyYXRpb24gdmVyc2lvbnMuCkxFR0FDWV9F'
    'TkRQT0lOVFMgPSAoJzEwOS4xOTQuNjcuMTU5JywgJzE5Mi4xNjguMC4xNjMnKQpIRUFMVEggPSAnMTAuNzcuMC4xJwpSRVFJ'
    'RCA9IDE3NwpUT0tFTl9QQVRURVJOID0gcidFVk4xLVtBLVphLXowLTlfLV17NDN9JwpTVE9QID0gRmFsc2UKUElOTkVEX0NB'
    'ID0gJy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRU9EQ0NBcUNnQXdJQkFnSVVia0orOFNhcUFnd1kxUkRBalpS'
    'VGpjcVE5ZU13RFFZSktvWklodmNOQVFFTFxuQlFBd0lqRWdNQjRHQTFVRUF3d1hSWFpuWlc1cGRXMGdjSEpwZG1GMFpTQldV'
    'RTRnUTBFd0hoY05Nall4TURBM1xuTVRreE16UXhXaGNOTXpZeE1EQTBNVGt4TXpReFdqQWlNU0F3SGdZRFZRUUREQmRGZG1k'
    'bGJtbDFiU0J3Y21sMlxuWVhSbElGWlFUaUJEUVRDQ0FhSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnR1BBRENDQVlvQ2dnR0JB'
    'T1orbnZpRVxuMk9yRjdQZHRray9YSWFGVkl2Smx2QzExVlpmOXJsakNCSXZCeWtic3JBckdyeVFIR251dVhMTmFhUzhOdEx4'
    'WVxuTmVTQkRLNk1kZ1lKQWVqc1A0d0lUdWIzbk1qU0cydW1JSVZVNm1FK0dEb3pHUGxOTU5KK2Joa0thVmhhUGpGRVxueVlM'
    'WXJkUGU1VkE0dys1cDBOWk9ENkNCSEQzdEVYV0JOUkllVlNXYnRNSVRzT0VTMVBlL2FBTDd2M29OSVZrVlxuOG5EdzlqNyt3'
    'RzJ5NWRoYnA3S1VKSGJyREIwMjRyN2NZclEzYXhZRjZneWtqbXp0cEtYc2JreFF2MjdCdmhTQlxuZTBFa3RKL2pDUzZSOUlJ'
    'bVlnSVFyQ3JhV1ptVlNjbkdGL0FxNFROdzFINE96RkNrUis3SlVsWW5TWVV2TVJpMVxuTHpLZWtVQysyLzBXRm1obkNvRHRk'
    'amNvWWJ4cExwS0RlbEdpUzNSc05Ddnhuc2xNYVB6NWhDY0Y2NFk3UmlqWFxuajZEdUNZcEZZV2xyMTNCMjBxQW5Sb1VhcytB'
    'alg3UFhDa1I0eE9oSCtrVzgvSG1GSGlIa29oV0Uwd2xsSVNCWFxuVkJvN0tCT1pkOFNWZXd5YmQyckI0c29Yb3VUdGpYcy9q'
    'VGdlK0hXeFFER1BQMXVtZno4Y0ZMUi91UUlEQVFBQlxubzJZd1pEQWRCZ05WSFE0RUZnUVVvUWZUaWY3N3hXdDA2aGFYaDNo'
    'YTg5MHFrVDh3SHdZRFZSMGpCQmd3Rm9BVVxub1FmVGlmNzd4V3QwNmhhWGgzaGE4OTBxa1Q4d0VnWURWUjBUQVFIL0JBZ3dC'
    'Z0VCL3dJQkFEQU9CZ05WSFE4QlxuQWY4RUJBTUNBUVl3RFFZSktvWklodmNOQVFFTEJRQURnZ0dCQUk3R0tubWZKanVMMVF2'
    'eVJ0bHcrSHI2QVkvWlxuT3hkRHZFQ2Vmb0ZMN1E0MVZaYStMN0RJODdrTUxZSHlnUkh1c2g2Nm9Vdjg3OFRXTXRhc25idC84'
    'd1lnNmpyd1xuQXlncGcvRjNWRDI0eVRybko3T0NkeUdpYjZMR3V1c3VUUDRyVUdzY2NXY3puUVhZRmt6UlZ6MVZlWU1aVU4r'
    'UFxudEFWaU5sNEVSUzFmaCtjR3pUNE9xWFFrSkRrUmVxSC9IQ1RFOGtVUVVVZ1hhU1hwaEtqR2E4cFIySFZlRnVrWFxuKzBw'
    'cDFpUis2ZGk0YUNLYXBrYVRpVlIzcjYydFJCVXdieG9GWVJ5eE5YeW5USzlFaG5NMjVXRXBuL3F1MGxzRFxub1hyRlZtajBB'
    'UWZBVUhSTi8yclBMLy93NlJQRXBIZ1VjcnQ3enVTZ29YSlpoMERUMzBWRUlLOU5OYnVLU0ZkOVxuSWlXdnJ4YlZRUzZtUWd0'
    'RVpONExjMkhtMXB2WStXckkrSDAzdTgwNDIrY3BMSXNDbnhQbTlXdmk3ZE1YeHFvYlxubzIvYUwyeERHNUcvOFdWUi9XNUVB'
    'ZnZLZHhkcmszSDYwMm9jY292NytKZzF2b3hpMDBJYmRNRXhvTXhkNWFlaFxuZlhSaUpoVEVGb3VJcG1FU0NGNHZWTWxXRnIz'
    'bXFsUTNHS1NQVkE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuJwoKCkZVTExfSE9TVCA9ICdldm4tZnVsbC1ob3N0'
    'JwpGVUxMX1BFRVIgPSAnZXZuLWZ1bGwtcGVlcicKRlVMTF9ORVQgPSAnMTcyLjI5LjI0Ny4wLzMwJwpGVUxMX1RBQkxFID0g'
    'JzUxODI4JwpBRE1JTl9UQUJMRSA9ICc1MTgyOScKRlVMTF9HVUFSRCA9ICdldm5fc3RhcmZpdmVfZnVsbCcKZGVmIGZ1bGxf'
    'c3RhdGUoKToKICAgIHJldHVybiBST09ULydmdWxsLW5ldHdvcmsuanNvbicKCgpkZWYgY2hhcm9uX2JpbmFyeSgpOgogICAg'
    'Y2FuZGlkYXRlcyA9ICgnL3Vzci9zYmluL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvYmluL2NoYXJvbi1zeXN0ZW1kJywKICAg'
    'ICAgICAgICAgICAgICAgJy91c3IvbGliL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvbGliZXhlYy9pcHNlYy9jaGFy'
    'b24tc3lzdGVtZCcsCiAgICAgICAgICAgICAgICAgICcvdXNyL2xpYi9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0ZW1kJywgJy91'
    'c3IvbGliZXhlYy9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0ZW1kJykKICAgIHJldHVybiBuZXh0KChwIGZvciBwIGluIGNhbmRp'
    'ZGF0ZXMgaWYgUGF0aChwKS5pc19maWxlKCkpLCBOb25lKQoKCmRlZiBlbnN1cmVfZGVwZW5kZW5jaWVzKCk6CiAgICBpZiBj'
    'aGFyb25fYmluYXJ5KCkgYW5kIGFsbChzaHV0aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2FuY3RsJywnaXAnLCduZnQnLCdj'
    'dXJsJywnb3BlbnNzbCcsJ2Nvbm50cmFjaycpKToKICAgICAgICByZXR1cm4KICAgIHN0YWdlKCdkZXBlbmRlbmNpZXMnLCAn'
    '0KPRgdGC0LDQvdCw0LLQu9C40LLQsNGOINC90LXQvtCx0YXQvtC00LjQvNGL0LUg0YHQuNGB0YLQtdC80L3Ri9C1INC60L7Q'
    'vNC/0L7QvdC10L3RgtGLIFZQTi4nLCAzLCBhY3RpdmU9RmFsc2UpCiAgICBpZiBzaHV0aWwud2hpY2goJ3BhY21hbicpOgog'
    'ICAgICAgIGFyZ3MgPSBbJ3BhY21hbicsJy1TJywnLS1uZWVkZWQnLCctLW5vY29uZmlybScsJ3N0cm9uZ3N3YW4nLCdpcHJv'
    'dXRlMicsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMnLCdjb25udHJhY2stdG9vbHMnXQog'
    'ICAgZWxpZiBzaHV0aWwud2hpY2goJ2RuZicpOgogICAgICAgIGFyZ3MgPSBbJ2RuZicsJ2luc3RhbGwnLCcteScsJy0tc2V0'
    'b3B0PWluc3RhbGxfd2Vha19kZXBzPUZhbHNlJywnc3Ryb25nc3dhbicsJ2lwcm91dGUnLCduZnRhYmxlcycsJ2N1cmwnLCdv'
    'cGVuc3NsJywnY2EtY2VydGlmaWNhdGVzJywnY29ubnRyYWNrLXRvb2xzJ10KICAgIGVsc2U6CiAgICAgICAgcmFpc2UgUnVu'
    'dGltZUVycm9yKCfQkNCy0YLQvtC80LDRgtC40YfQtdGB0LrQsNGPINGD0YHRgtCw0L3QvtCy0LrQsCDRjdC60YHQv9C10YDQ'
    'uNC80LXQvdGC0LDQu9GM0L3QvtCz0L4g0LrQu9C40LXQvdGC0LAg0L/QvtC00LTQtdGA0LbQuNCy0LDQtdGCIEFyY2gg0Lgg'
    'RmVkb3JhLicpCiAgICBjb21tYW5kKGFyZ3MsIHRpbWVvdXQ9MzAwKQogICAgaWYgbm90IGNoYXJvbl9iaW5hcnkoKSBvciBu'
    'b3QgYWxsKHNodXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwnLCdjb25udHJhY2snKSk6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCfQn9Cw0LrQtdGCIHN0cm9uZ1N3YW4g0L3QtSDQv9GA0LXQtNC+0YHRgtCw0LLQuNC7INC90LXQvtCx'
    '0YXQvtC00LjQvNGL0LUg0L/RgNC+0LPRgNCw0LzQvNGLLicpCgoKZGVmIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192'
    'cG49RmFsc2UpOgogICAgIiIiRm9yZ2V0IG9ubHkgdGhpcyBtYW5hZ2VyJ3Mgb2Jzb2xldGUgRE5TIE5BVCwgbmV2ZXIgZmx1'
    'c2ggYWxsIGNvbm5lY3Rpb25zLgoKICAgIFJlbW92aW5nIGFuIG5mdCBOQVQgY2hhaW4gZG9lcyBub3QgcmVtb3ZlIGV4aXN0'
    'aW5nIGNvbm50cmFjayB0cmFuc2xhdGlvbnMuCiAgICBBIHJ1bm5pbmcgcmVzb2x2ZXIgY2FuIHJldXNlIGl0cyBVRFAgc29j'
    'a2V0IGluZGVmaW5pdGVseSBhZnRlciBhIFZQTiBzd2l0Y2guCiAgICAiIiIKICAgIGZpbHRlcnMgPSAoWyctLXJlcGx5LXBv'
    'cnQtc3JjJywnMTg1NTMnXSBpZiBwcmV2aW91c192cG4gZWxzZQogICAgICAgICAgICAgICBbJy0tcmVwbHktcG9ydC1zcmMn'
    'LCc1MycsJy0tZHN0LW5hdCcsJzEuMS4xLjEnXSkKICAgIGZvciBwcm90b2NvbCBpbiAoJ3VkcCcsJ3RjcCcpOgogICAgICAg'
    'IHJlc3VsdCA9IGNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcsJy1wJyxwcm90b2NvbCwKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAnLS1kcG9ydCcsJzUzJywqZmlsdGVyc10sIGNoZWNrPUZhbHNlLAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgZW52PXsqKm9zLmVudmlyb24sJ0xDX0FMTCc6J0MnfSkKICAgICAgICBlbXB0eSA9IHJlc3VsdC5yZXR1cm5j'
    'b2RlID09IDEgYW5kICcwIGZsb3cgZW50cmllcyBoYXZlIGJlZW4gZGVsZXRlZCcgaW4gcmVzdWx0LnN0ZGVycgogICAgICAg'
    'IGlmIHJlc3VsdC5yZXR1cm5jb2RlICE9IDAgYW5kIG5vdCBlbXB0eToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdkbnNfdHJhbnNpdGlvbl9jbGVhbnVwX2ZhaWxlZCcpCgoKZGVmIGZ1bGxfZ3VhcmRfYWN0aXZlKCk6CiAgICByZXR1cm4g'
    'Y29tbWFuZChbJ25mdCcsJ2xpc3QnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2Rl'
    'ID09IDAKCgpkZWYgZnVsbF9maXJld2FsbCgpOgogICAgIyBObyBwcm9jZXNzLCBESVJFQ1QgbGlzdCwgZXN0YWJsaXNoZWQg'
    'c29ja2V0IG9yIElQdjYgZXhjZXB0aW9uIGNhbiBieXBhc3MgdGhpcyBndWFyZC4KICAgICMgS2VlcCBsb2NhbCBzdHViIERO'
    'UyBvbiBsb29wYmFjay4gRE5BVCBvZiAxMjcvOCBvbnRvIGEgdmV0aCBmYWlscyBMaW51eCdzCiAgICAjIGxvb3BiYWNrIHJv'
    'dXRlIGNoZWNrczsgdXBzdHJlYW0gcmVzb2x2ZXIgdHJhZmZpYyBzdGlsbCBvYmV5cyB0aGUgZnVsbCBndWFyZC4KICAgIHJl'
    'dHVybiBmJycndGFibGUgaW5ldCB7RlVMTF9HVUFSRH0ge3sKIGNoYWluIGRucyB7eyB0eXBlIG5hdCBob29rIG91dHB1dCBw'
    'cmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybgogIGlwIGRhZGRyIHt7'
    'IDEuMS4xLjEsIDkuOS45LjkgfX0gcmV0dXJuCiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRw'
    'IH19IHRoIGRwb3J0IDUzIGRuYXQgaXAgdG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBlIG5hdCBob29rIHBv'
    'c3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7'
    'RlVMTF9IT1NUfSIgc25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKIH19CiBjaGFpbiBvdXRwdXQge3sgdHlwZSBmaWx0ZXIgaG9v'
    'ayBvdXRwdXQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0CiAgbWV0YSBuZnByb3Rv'
    'IGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4yNTUuMjU1LjI1NSB1ZHAgc3BvcnQg'
    'NjggdWRwIGRwb3J0IDY3IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHBy'
    'aW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7'
    'eyB7U0VSVkVSfSB9fSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtD'
    'TElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG9pZm5hbWUgIntIT1NUfSIg'
    'aXAgZGFkZHIge0NMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2'
    'NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie0ZVTExfSE9TVH0i'
    'IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiB9fQp9fScnJwoKCgpkZWYgcmVmcmVzaF9yZXRhaW5lZF9n'
    'dWFyZCgpOgogICAgIiIiTW92ZSBvbmx5IHRoZSBWUE4gdHJhbnNwb3J0IGV4Y2VwdGlvbiB3aGVuIGFuIGluZ3Jlc3MgZW5k'
    'cG9pbnQgY2hhbmdlcy4iIiIKICAgIGlmIG5vdCBmdWxsX2d1YXJkX2FjdGl2ZSgpOgogICAgICAgIHJldHVybgogICAgcnVs'
    'ZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgIHJlcGxhY2VtZW50ID0gJ2RlbGV0ZSB0YWJsZSBpbmV0ICcrRlVMTF9HVUFSRCsn'
    'XG4nK3J1bGVzCiAgICBjb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgIyBQZXJz'
    'aXN0IHRoZSBjbG9zZWQgZ3VhcmQgYmVmb3JlIGNoYW5naW5nIHRoZSBhY3RpdmUgZXhjZXB0aW9uOyBhIGNyYXNoIHN0YXlz'
    'IGNsb3NlZC4KICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKICAgIGNvbW1hbmQoWyduZnQnLCctZics'
    'Jy0nXSxkYXRhPXJlcGxhY2VtZW50KQoKCmRlZiB2aXJ0dWFsX2lwKCk6CiAgICBkYXRhID0ganNvbi5sb2FkcyhpbnNpZGUo'
    'WydpcCcsJy1qJywnLTQnLCdhZGRyJ10pLnN0ZG91dCkKICAgIGlwcyA9IFthWydsb2NhbCddIGZvciBsaW5rIGluIGRhdGEg'
    'Zm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsIFtdKQogICAgICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKGFb'
    'J2xvY2FsJ10pIGluIGlwYWRkcmVzcy5pcF9uZXR3b3JrKCcxMC43Ny4wLjAvMjQnKV0KICAgIGlmIGxlbihpcHMpICE9IDE6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd2aXJ0dWFsX2lwX21pc3NpbmcnKQogICAgcmV0dXJuIGlwc1swXQoKCmRl'
    'ZiBmdWxsX25hbWVzcGFjZShhZGRyZXNzKToKICAgIHZpcCA9IHZpcnR1YWxfaXAoKQogICAgaWYgbm90IFBhdGgoJy9zeXMv'
    'Y2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnYWRkJyxGVUxM'
    'X0hPU1QsJ3R5cGUnLCd2ZXRoJywncGVlcicsJ25hbWUnLEZVTExfUEVFUl0pCiAgICAgICAgY29tbWFuZChbJ2lwJywnbGlu'
    'aycsJ3NldCcsRlVMTF9QRUVSLCduZXRucycsTlNdKQogICAgY29tbWFuZChbJ2lwJywnYWRkcicsJ3JlcGxhY2UnLCcxNzIu'
    'MjkuMjQ3LjEvMzAnLCdkZXYnLEZVTExfSE9TVF0pCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX0hPU1Qs'
    'J210dScsJzEyODAnLCd1cCddKQogICAgaW5zaWRlKFsnaXAnLCdhZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcuMi8zMCcs'
    'J2RldicsRlVMTF9QRUVSXSkKICAgIGluc2lkZShbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9QRUVSLCdtdHUnLCcxMjgwJywn'
    'dXAnXSkKICAgIGluc2lkZShbJ3N5c2N0bCcsJy1xdycsJ25ldC5pcHY0LmNvbmYuYWxsLmZvcndhcmRpbmc9MScsJ25ldC5p'
    'cHY0LmNvbmYuYWxsLnJwX2ZpbHRlcj0wJ10pCiAgICAjIFN0cm9uZ1N3YW4ncyBjYXRjaC1hbGwgcm91dGUgbXVzdCBub3Qg'
    'Y2FwdHVyZSByZXBsaWVzIHRvIHRoZSBob3N0LWZhY2luZyBpbnRlcmZhY2UuCiAgICBpbnNpZGUoWydpcCcsJ3J1bGUnLCdk'
    'ZWwnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBpbnNp'
    'ZGUoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10pCiAg'
    'ICBkZWxldGlvbnMgPSAnJwogICAgZm9yIGZhbWlseSx0YWJsZSBpbiBbKCdpbmV0JywnZXZuX2Z1bGxfZm9yd2FyZCcpLCgn'
    'bmV0ZGV2JywnZXZuX2Z1bGxfd2lyZScpXToKICAgICAgICBpZiBpbnNpZGUoWyduZnQnLCdsaXN0JywndGFibGUnLGZhbWls'
    'eSx0YWJsZV0sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICAgICAgZGVsZXRpb25zICs9IGYnZGVsZXRl'
    'IHRhYmxlIHtmYW1pbHl9IHt0YWJsZX1cbicKICAgIHJ1bGVzID0gZGVsZXRpb25zICsgZicnJ3RhYmxlIGluZXQgZXZuX2Z1'
    'bGxfZm9yd2FyZCB7ewogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTU7IHBv'
    'bGljeSBkcm9wOwogIGlpZm5hbWUgIntGVUxMX1BFRVJ9IiBvaWZuYW1lICJ7UEVFUn0iIGlwIHNhZGRyIDE3Mi4yOS4yNDcu'
    'MSBhY2NlcHQKICBpaWZuYW1lICJ7UEVFUn0iIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBkYWRkciAxNzIuMjkuMjQ3LjEg'
    'aXBzZWMgaW4gcmVxaWQge1JFUUlEfSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KIGNoYWluIG5h'
    'dCB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBzYWRk'
    'ciAxNzIuMjkuMjQ3LjEgb2lmbmFtZSAie1BFRVJ9IiBzbmF0IGlwIHRvIHt2aXB9CiB9fQp9fQp0YWJsZSBuZXRkZXYgZXZu'
    'X2Z1bGxfd2lyZSB7ewogY2hhaW4gZWdyZXNzIHt7IHR5cGUgZmlsdGVyIGhvb2sgZWdyZXNzIGRldmljZSAie1BFRVJ9IiBw'
    'cmlvcml0eSAwOyBwb2xpY3kgZHJvcDsKICBldGhlciB0eXBlIGFycCBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdWRw'
    'IGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogfX0K'
    'fX0nJycKICAgIGluc2lkZShbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAgIGluc2lkZShbJ25mdCcsJy1m'
    'JywnLSddLGRhdGE9cnVsZXMpCiAgICAjIFJlcGxhY2UgdGhlIG9yaWdpbmFsIGxhYiBmb3J3YXJkIGRyb3A7IGhvc3QgaW5n'
    'cmVzcyByZW1haW5zIGNvbnN0cmFpbmVkIGJ5IGZ1bGxfZm9yd2FyZC4KICAgIGluc2lkZShbJ25mdCcsJ2ZsdXNoJywnY2hh'
    'aW4nLCdpbmV0JywnZXZuX3N0YXJmaXZlX2d1YXJkJywnZm9yd2FyZCddKQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVs'
    'ZScsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdmb3J3YXJkJywnaWlmbmFtZScsRlVMTF9QRUVSLCdtZXRhJywnbmZw'
    'cm90bycsJ2lwdjQnLCdhY2NlcHQnXSkKICAgIGluc2lkZShbJ25mdCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JywnZXZuX3N0YXJm'
    'aXZlX2d1YXJkJywnZm9yd2FyZCcsJ29pZm5hbWUnLEZVTExfUEVFUiwnaXBzZWMnLCdpbicsJ3JlcWlkJyxzdHIoUkVRSUQp'
    'LCdjdCcsJ3N0YXRlJywnZXN0YWJsaXNoZWQscmVsYXRlZCcsJ2FjY2VwdCddKQoKCmRlZiBlZ3Jlc3NfaGVhbHRoKCk6CiAg'
    'ICBmb3IgdXJsLGV4cGVjdGVkIGluIFsoJ2h0dHBzOi8vd3d3LmNsb3VkZmxhcmUuY29tL2Nkbi1jZ2kvdHJhY2UnLCdpcD0z'
    'OC4xODAuMTY0LjY3JyksCiAgICAgICAgICAgICAgICAgICAgICAgICAoJ2h0dHBzOi8vYXBpLmlwaWZ5Lm9yZycsJzM4LjE4'
    'MC4xNjQuNjcnKV06CiAgICAgICAgcmVzdWx0ID0gaW5zaWRlKFsnY3VybCcsJy00JywnLS1ub3Byb3h5JywnKicsJy0tZmFp'
    'bCcsJy0tc2lsZW50JywnLS1zaG93LWVycm9yJywKICAgICAgICAgICAgICAgICAgICAgICAgICctLWNvbm5lY3QtdGltZW91'
    'dCcsJzMnLCctLW1heC10aW1lJywnNScsdXJsXSx0aW1lb3V0PTcsY2hlY2s9RmFsc2UpCiAgICAgICAgaWYgcmVzdWx0LnJl'
    'dHVybmNvZGUgPT0gMCBhbmQgZXhwZWN0ZWQgaW4gcmVzdWx0LnN0ZG91dC5zcGxpdGxpbmVzKCk6CiAgICAgICAgICAgIHJl'
    'dHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgcmV0aXJlX3ByZXZpb3VzX2Nvbm5lY3Rpb25zKGFkZHJlc3Nlcyk6'
    'CiAgICAjIEEgY2hhbmdlZCBWUE4gZWdyZXNzIGNhbm5vdCBwcmVzZXJ2ZSBvbGQgVENQIHNlc3Npb25zLiBXYWtlIGFwcGxp'
    'Y2F0aW9ucyBub3cKICAgICMgaW5zdGVhZCBvZiBsZWF2aW5nIHN0YWxlIHNvdXJjZSBhZGRyZXNzZXMgYW5kIFVEUCBOQVQg'
    'dW50aWwgdGhlaXIgdGltZW91dHMuCiAgICBmb3IgYWRkcmVzcyBpbiBhZGRyZXNzZXM6CiAgICAgICAgY29tbWFuZChbJ3Nz'
    'JywnLUsnLCdzcmMnLGFkZHJlc3NdLGNoZWNrPUZhbHNlKQogICAgICAgIGZvciBwcm90b2NvbCBpbiAoJ3RjcCcsJ3VkcCcp'
    'OgogICAgICAgICAgICBjb21tYW5kKFsnY29ubnRyYWNrJywnLUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG9jb2wsJy1zJyxh'
    'ZGRyZXNzXSxjaGVjaz1GYWxzZSkKCgpkZWYgc3lzdGVtX2Ruc19oZWFsdGgocmVzb2x2X2NvbmY9UGF0aCgnL2V0Yy9yZXNv'
    'bHYuY29uZicpKToKICAgICMgZ2V0YWRkcmluZm8vY3VybCBtYXkgdXNlIG5zcy1yZXNvbHZlIG92ZXIgYSBVbml4IHNvY2tl'
    'dCBhbmQgbWlzcyBhIGJyb2tlbgogICAgIyBVRFAgc3R1YiB1c2VkIGJ5IG90aGVyIGFwcGxpY2F0aW9ucy4gRXhlcmNpc2Ug'
    'cmVzb2x2LmNvbmYgaW5kZXBlbmRlbnRseS4KICAgIHNlcnZlcnMgPSBbbGluZS5zcGxpdCgpWzFdIGZvciBsaW5lIGluIHJl'
    'c29sdl9jb25mLnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKQogICAgICAgICAgICAgICBpZiBsaW5lLnNwbGl0KClbOjFdID09'
    'IFsnbmFtZXNlcnZlciddIGFuZCBsZW4obGluZS5zcGxpdCgpKSA+PSAyXVs6M10KICAgIGZvciBzZXJ2ZXIgaW4gc2VydmVy'
    'czoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZhbWlseSA9IHNvY2tldC5BRl9JTkVUNiBpZiBpcGFkZHJlc3MuaXBfYWRk'
    'cmVzcyhzZXJ2ZXIpLnZlcnNpb24gPT0gNiBlbHNlIHNvY2tldC5BRl9JTkVUCiAgICAgICAgICAgIHRyYW5zYWN0aW9uID0g'
    'c2VjcmV0cy50b2tlbl9ieXRlcygyKQogICAgICAgICAgICBxdWVyeSA9IHRyYW5zYWN0aW9uK2InXHgwMVx4MDBceDAwXHgw'
    'MVx4MDBceDAwXHgwMFx4MDBceDAwXHgwMCcKICAgICAgICAgICAgcXVlcnkgKz0gYidceDAzYXBpXHgwNWlwaWZ5XHgwM29y'
    'Z1x4MDBceDAwXHgwMVx4MDBceDAxJwogICAgICAgICAgICB3aXRoIHNvY2tldC5zb2NrZXQoZmFtaWx5LCBzb2NrZXQuU09D'
    'S19ER1JBTSkgYXMgcmVzb2x2ZXI6CiAgICAgICAgICAgICAgICByZXNvbHZlci5zZXR0aW1lb3V0KDIpCiAgICAgICAgICAg'
    'ICAgICByZXNvbHZlci5jb25uZWN0KChzZXJ2ZXIsIDUzKSkKICAgICAgICAgICAgICAgIHJlc29sdmVyLnNlbmQocXVlcnkp'
    'CiAgICAgICAgICAgICAgICBhbnN3ZXIgPSByZXNvbHZlci5yZWN2KDQwOTYpCiAgICAgICAgICAgIGlmIChsZW4oYW5zd2Vy'
    'KSA+PSAxMiBhbmQgYW5zd2VyWzoyXSA9PSB0cmFuc2FjdGlvbiBhbmQKICAgICAgICAgICAgICAgICAgICBhbnN3ZXJbMl0g'
    'JiAweDgwIGFuZCBhbnN3ZXJbM10gJiAxNSA9PSAwIGFuZAogICAgICAgICAgICAgICAgICAgIGludC5mcm9tX2J5dGVzKGFu'
    'c3dlcls2OjhdLCAnYmlnJykgPiAwKToKICAgICAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgZXhjZXB0IChPU0Vy'
    'cm9yLCBWYWx1ZUVycm9yKToKICAgICAgICAgICAgY29udGludWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBhY3RpdmF0ZV9m'
    'dWxsKGFkZHJlc3MpOgogICAgb2xkX2FkZHJlc3NlcyA9IFthWydsb2NhbCddIGZvciBsaW5rIGluIGpzb24ubG9hZHMoY29t'
    'bWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdzaG93Jywnc2NvcGUnLCdnbG9iYWwnXSkuc3Rkb3V0KQogICAgICAgICAg'
    'ICAgICAgICAgICBpZiBsaW5rLmdldCgnaWZuYW1lJykgbm90IGluIChIT1NULEZVTExfSE9TVCkKICAgICAgICAgICAgICAg'
    'ICAgICAgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlmIGEuZ2V0KCdzY29wZScpID09ICdnbG9iYWwnXQog'
    'ICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToKICAgICAgICBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExf'
    'SE9TVCkuZXhpc3RzKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF9pbnRlcmZhY2VfY29sbGlzaW9u'
    'JykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFs'
    'c2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfdGFibGVfY29sbGlzaW9u'
    'JykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZh'
    'bHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdhZG1pbl90YWJsZV9jb2xsaXNp'
    'b24nKQogICAgICAgIGlmIGFueShyLmdldCgncHJpb3JpdHknKSBpbiAoNzksODApIGZvciByIGluIGpzb24ubG9hZHMoY29t'
    'bWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KSk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    'ZnVsbF9ydWxlX2NvbGxpc2lvbicpCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoeydhY3RpdmUnOkZh'
    'bHNlfSkpCiAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAgIyBWYWxpZGF0ZSB0aGUgZWdyZXNzIGZpbHRlciBiZWZv'
    'cmUgaW50ZXJydXB0aW5nIHRoZSBwcmV2aW91cyBWUE4uCiAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcignZXN0b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAg'
    'ICAjIFJlcGFpciBtYXkgaW5oZXJpdCBhIGd1YXJkIGZyb20gYW4gb2xkZXIgdmVyc2lvbi4gUmVwbGFjZSBvdXIgdGFibGUg'
    'aW4KICAgICMgb25lIG5mdCB0cmFuc2FjdGlvbiwgc28gZml4ZXMgYXBwbHkgd2l0aG91dCBvcGVuaW5nIGFuIHVuZ3VhcmRl'
    'ZCB3aW5kb3cuCiAgICByZXBsYWNlbWVudCA9ICgnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicgaWYgZnVs'
    'bF9ndWFyZF9hY3RpdmUoKSBlbHNlICcnKStydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1y'
    'ZXBsYWNlbWVudCkKICAgIGNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgIyBHdWFyZCBw'
    'ZXJzaXN0ZW5jZSBwcmVjZWRlcyBzd2l0Y2hpbmcuIENsZWFudXAgYWZ0ZXIgYSBjcmFzaCBuZXZlciBvcGVucyB0aGUgSW50'
    'ZXJuZXQuCiAgICBndWFyZF91bml0ID0gJycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGV4cGVyaW1lbnRhbCBmdWxs'
    'LWRldmljZSBraWxsIHN3aXRjaApEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9'
    'bmV0d29yay1wcmUudGFyZ2V0CltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVtYWluQWZ0ZXJFeGl0PXllcwpFeGVjU3RhcnQ9'
    'L3Vzci9zYmluL25mdCAtZiAvZXRjL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXR1bm5lbC9mdWxsLWd1YXJkLm5mdApbSW5zdGFs'
    'bF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKJycnLnJlcGxhY2UoJy91c3Ivc2Jpbi9uZnQnLCBzaHV0aWwud2hpY2go'
    'J25mdCcpKQogICAgd3JpdGUoUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0'
    'ZW1kL3N5c3RlbS9ldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnKSxndWFyZF91bml0KQogICAgY29tbWFu'
    'ZChbJ3N5c3RlbWN0bCcsJ2RhZW1vbi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdlbmFibGUnLCdldmdl'
    'bml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnXSkKICAgICMgVGhpcyBjb21tYW5kIHN0b3BzIG9ubHkgdGhpcyBt'
    'YW5hZ2VyJ3MgcHJldmlvdXMgWHJheSBtb2RlIGFuZCByZW1vdmVzIGl0cyBndWFyZC4KICAgIGNvbW1hbmQoWycvdXNyL2xv'
    'Y2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwtc3RhcmZpdmUtcGF1c2UtbWFpbiddLHRpbWVvdXQ9NDApCiAgICBjb21tYW5k'
    'KFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCd1bnJlYWNoYWJsZScsJ2RlZmF1bHQnLCdtZXRyaWMnLCczMjc2MCcsJ3RhYmxl'
    'JyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIu'
    'MjkuMjQ3LjInLCdkZXYnLEZVTExfSE9TVCwnbWV0cmljJywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0pCiAgICBjb21tYW5k'
    'KFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAg'
    'ICBmb3IgcnVsZSBpbiAoWydwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMyJywnbG9va3VwJywnbWFpbiddLAogICAg'
    'ICAgICAgICAgICAgIFsncHJpb3JpdHknLCc3OScsJ2lpZicsRlVMTF9IT1NULCdsb29rdXAnLCdtYWluJ10pOgogICAgICAg'
    'IGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCpydWxlXSxjaGVjaz1GYWxzZSkKICAgICAgICBjb21tYW5kKFsnaXAnLCdy'
    'dWxlJywnYWRkJywqcnVsZV0pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1'
    'cCcsRlVMTF9UQUJMRV0pCiAgICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgaWYgc2h1'
    'dGlsLndoaWNoKCdyZXNvbHZlY3RsJykgYW5kIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLCctLXF1aWV0Jywn'
    'c3lzdGVtZC1yZXNvbHZlZCddLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgZGF0YVsnZG5zX21vZGUn'
    'XT0ncmVzb2x2ZWRfbGluaycKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKICAgICAgICBj'
    'b21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RucycsRlVMTF9IT1NULCcxLjEuMS4xJywnOS45LjkuOSddKQogICAgICAgIGNvbW1h'
    'bmQoWydyZXNvbHZlY3RsJywnZG9tYWluJyxGVUxMX0hPU1QsJ34uJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwn'
    'LCdkZWZhdWx0LXJvdXRlJyxGVUxMX0hPU1QsJ3llcyddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZmx1c2gt'
    'Y2FjaGVzJ10sY2hlY2s9RmFsc2UpCiAgICBlbHNlOgogICAgICAgIGlmICdkbnNfYmFja3VwJyBub3QgaW4gZGF0YToKICAg'
    'ICAgICAgICAgZGF0YVsnZG5zX2JhY2t1cCddPVBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKS5yZWFkX3RleHQoKQogICAgICAg'
    'ICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKICAgICAgICBQYXRoKCcvZXRjL3Jlc29sdi5jb25m'
    'Jykud3JpdGVfdGV4dCgnbmFtZXNlcnZlciAxLjEuMS4xXG5uYW1lc2VydmVyIDkuOS45Ljlcbm9wdGlvbnMgdGltZW91dDoy'
    'IGF0dGVtcHRzOjJcbicpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPVRydWUpCiAgICByZXRpcmVfcHJl'
    'dmlvdXNfY29ubmVjdGlvbnMob2xkX2FkZHJlc3NlcykKICAgIGlmIG5vdCBzeXN0ZW1fZG5zX2hlYWx0aCgpOgogICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgIyBUZXN0IHRoZSBhY3R1YWwgaG9zdCBwYXRo'
    'IGFzIHdlbGwgYXMgbmFtZXNwYWNlIHByb2JlcyBiZWZvcmUgYW5ub3VuY2luZyBjb25uZWN0ZWQuCiAgICBjaGVjayA9IGNv'
    'bW1hbmQoWydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLW1heC10aW1lJywnMTAn'
    'LCdodHRwczovL2FwaS5pcGlmeS5vcmcnXSx0aW1lb3V0PTEyKQogICAgaWYgY2hlY2suc3Rkb3V0LnN0cmlwKCkgIT0gJzM4'
    'LjE4MC4xNjQuNjcnOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaG9zdF9lZ3Jlc3NfZmFpbGVkJykKICAgIGRhdGFb'
    'J2FjdGl2ZSddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQoKCmRlZiBjbGVhbnVwX2Z1'
    'bGwocmVsZWFzZT1GYWxzZSk6CiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAgIHJldHVybgogICAg'
    'ZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZGVs'
    'JywnZGVmYXVsdCcsJ21ldHJpYycsJzEwJywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChb'
    'J2lwJywnbGluaycsJ2RlbCcsRlVMTF9IT1NUXSxjaGVjaz1GYWxzZSkKICAgICMgT24gZmFpbHVyZTogcmV0YWluIHJvdXRp'
    'bmcsIEROUyBhbmQgdGhlIHBlcnNpc3RlbnQgZ3VhcmQgdW50aWwgZXhwbGljaXQgZGlzY29ubmVjdC4KICAgIGlmIG5vdCBy'
    'ZWxlYXNlOgogICAgICAgIHJldHVybgogICAgaWYgJ2Ruc19iYWNrdXAnIGluIGRhdGE6CiAgICAgICAgUGF0aCgnL2V0Yy9y'
    'ZXNvbHYuY29uZicpLndyaXRlX3RleHQoZGF0YVsnZG5zX2JhY2t1cCddKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2Rl'
    'bCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywn'
    'cnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFs'
    'c2UpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ2lpZicsRlVMTF9IT1NULCdsb29r'
    'dXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLEZVTExf'
    'VEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZm9yIHNlcnZlciBpbiAoJzE5Mi4xNjguMC4xNjMnLCAnMzguMTgwLjE2NC42Nycp'
    'OgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLHNlcnZlciwnaXBwcm90'
    'bycsJ3RjcCcsJ2Rwb3J0JywnMjInLCdsb29rdXAnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydz'
    'eXN0ZW1jdGwnLCdkaXNhYmxlJywnLS1ub3cnLCdldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnXSxjaGVj'
    'az1GYWxzZSkKICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZh'
    'bHNlKQogICAgY2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScs'
    'QURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZnVsbF9zdGF0ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVzb2x2'
    'ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNoZWNrPUZhbHNlKSBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNlIE5v'
    'bmUKCgpkZWYgY29tbWFuZChhcmdzLCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAg'
    'IGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0'
    'dXJlX291dHB1dD1UcnVlLAogICAgICAgICAgICAgICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNr'
    'PUZhbHNlKQogICAgaWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4g'
    'YSBDU1IgcGF0aDsgZG8gbm90IHByb3BhZ2F0ZSBwcm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ2NvbW1hbmRfZmFpbGVkJykKICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3Mp'
    'OgogICAgcmV0dXJuIGNvbW1hbmQoWydpcCcsICduZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVm'
    'IHdyaXRlKHBhdGgsIHZhbHVlKToKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhp'
    'c3Rfb2s9VHJ1ZSkKICAgIHRlbXBvcmFyeSA9IHBhdGgud2l0aF9zdWZmaXgoJy5uZXcnKQogICAgZmQgPSBvcy5vcGVuKHRl'
    'bXBvcmFyeSwgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIDBvNjAwKQog'
    'ICAgd2l0aCBvcy5mZG9wZW4oZmQsICd3JykgYXMgc3RyZWFtOgogICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgIHRl'
    'bXBvcmFyeS5yZXBsYWNlKHBhdGgpCgoKZGVmIHNhdmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMo'
    'U1RBVEUucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoK'
    'CmRlZiBzdGFnZShwaGFzZSwgbWVzc2FnZSwgcHJvZ3Jlc3MsICoqZmllbGRzKToKICAgIGRhdGEgPSB7KipzYXZlZCgpLCAn'
    'cGhhc2UnOiBwaGFzZSwgJ21lc3NhZ2UnOiBtZXNzYWdlLCAncHJvZ3Jlc3MnOiBwcm9ncmVzcywKICAgICAgICAgICAgJ3Vw'
    'ZGF0ZWQnOiBpbnQodGltZS50aW1lKCkpLCAnaGVhcnRiZWF0JzogdGltZS5tb25vdG9uaWMoKSwgKipmaWVsZHN9CiAgICB3'
    'cml0ZShTVEFURSwganNvbi5kdW1wcyhkYXRhLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQoKCmRlZiBzdGF0dXMoKToKICAgIGRh'
    'dGEgPSBzYXZlZCgpCiAgICBydW5uaW5nID0gY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcs'
    'IFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yKS5yZXR1cm5jb2RlID09IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScp'
    'ID09ICdjb25uZWN0ZWQnIGFuZCAobm90IHJ1bm5pbmcgb3IgdGltZS5tb25vdG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0'
    'JywgMCkgPiA0NSk6CiAgICAgICAgZGF0YS51cGRhdGUocGhhc2U9J2ludGVycnVwdGVkJywgbWVzc2FnZT0n0KHQvtC10LTQ'
    'uNC90LXQvdC40LUg0L7RgdGC0LDQvdC+0LLQuNC70L7RgdGMLiDQn9GA0L7QstC10YDRjNGC0LUg0YHQvtGB0YLQvtGP0L3Q'
    'uNC1INC30LDRidC40YLRiyDQuCDQvdCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nLCBhY3RpdmU9RmFsc2Up'
    'CiAgICBwdWJsaWMgPSB7a2V5OiBkYXRhW2tleV0gZm9yIGtleSBpbiAoJ3BoYXNlJywgJ21lc3NhZ2UnLCAncHJvZ3Jlc3Mn'
    'LCAnYWN0aXZlJywgJ3VwZGF0ZWQnLCAnbWV0cmljcycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAnc2NvcGUnLCAnc2luY2UnLCAncmV0cnknKSBpZiBrZXkgaW4gZGF0YX0KICAgIHRva2VuX2luZm8gPSB0b2tlbl9zdGF0'
    'dXMoKQogICAgcmV0dXJuIHsncGhhc2UnOiAnb2ZmJywgJ21lc3NhZ2UnOiAoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQ'
    'vS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC70Y7Rh9C40YLRjMK7LicgaWYgdG9rZW5faW5mb1snaGFzX3Rva2VuJ10g'
    'ZWxzZSAn0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCw'
    'LicpLAogICAgICAgICAgICAncHJvZ3Jlc3MnOiAwLCAnYWN0aXZlJzogRmFsc2UsICoqcHVibGljLCAncnVubmluZyc6IHJ1'
    'bm5pbmcsCiAgICAgICAgICAgICoqdG9rZW5faW5mbywgJ2lzb2xhdGVkJzogRmFsc2UsICdmdWxsX2RldmljZSc6IFRydWUs'
    'ICdndWFyZCc6IGZ1bGxfZ3VhcmRfYWN0aXZlKCksICdwcm90b2NvbCc6ICdJS0V2MiDihpIg0K3RgdGC0L7QvdC40Y8nfQoK'
    'CkBjb250ZXh0bGliLmNvbnRleHRtYW5hZ2VyCmRlZiBuYW1lc3BhY2UoKToKICAgIGJlZm9yZSA9IG9zLm9wZW4oJy9wcm9j'
    'L3NlbGYvbnMvbmV0Jywgb3MuT19SRE9OTFkpCiAgICB0YXJnZXQgPSBvcy5vcGVuKCcvcnVuL25ldG5zLycrTlMsIG9zLk9f'
    'UkRPTkxZKQogICAgdHJ5OgogICAgICAgIG9zLnNldG5zKHRhcmdldCwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIHlpZWxk'
    'CiAgICBmaW5hbGx5OgogICAgICAgIG9zLnNldG5zKGJlZm9yZSwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIG9zLmNsb3Nl'
    'KHRhcmdldCkKICAgICAgICBvcy5jbG9zZShiZWZvcmUpCgoKZGVmIHBoeXNpY2FsX3JvdXRlKCk6CiAgICByb3V0ZXMgPSBq'
    'c29uLmxvYWRzKGNvbW1hbmQoWydpcCcsICctaicsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ21haW4nLCAn'
    'ZGVmYXVsdCddKS5zdGRvdXQpCiAgICBjYW5kaWRhdGVzID0gW3IgZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdnYXRld2F5'
    'JykgYW5kIHIuZ2V0KCdkZXYnKSBhbmQKICAgICAgICAgICAgICAgICAgbm90IHJbJ2RldiddLnN0YXJ0c3dpdGgoKCd0dW4n'
    'LCAneHJheScsICd3ZycsICdldm4tJykpXQogICAgaWYgbm90IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVy'
    'cm9yKCdub19waHlzaWNhbF9yb3V0ZScpCiAgICByb3V0ZSA9IG1pbihjYW5kaWRhdGVzLCBrZXk9bGFtYmRhIHI6IHIuZ2V0'
    'KCdtZXRyaWMnLCAwKSkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidbQS1aYS16MC05Xy46LV17MSwxNX0nLCByb3V0ZVsn'
    'ZGV2J10pOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9pbnRlcmZhY2UnKQogICAgaXBhZGRyZXNzLklQ'
    'djRBZGRyZXNzKHJvdXRlWydnYXRld2F5J10pCiAgICByZXR1cm4gcm91dGUKCgpkZWYgaG9zdF9ydWxlcyhpZmFjZSwgcHJl'
    'dmlvdXNfZm9yd2FyZD1UcnVlKToKICAgICMgU2NvcGUgZXZlcnkgbmV3IGZvcndhcmRpbmcvTkFUIHJ1bGUgdG8gb3VyIG9u'
    'ZSBpbnRlcmZhY2UgYW5kIHRoZSBjb25maWd1cmVkIGluZ3Jlc3MgYWRkcmVzcy4KICAgIHByZXNlcnZlX2Rpc2FibGVkID0g'
    'JycgaWYgcHJldmlvdXNfZm9yd2FyZCBlbHNlICcgIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnCiAgICByZXR1cm4gZicnJ3Rh'
    'YmxlIGluZXQge05GVH0ge3sKIGNoYWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkg'
    'LTIwOyBwb2xpY3kgYWNjZXB0OwogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0'
    'IHtJS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQg'
    'ODQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGRyb3AKICBvaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJW'
    'RVJ9IH19IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBkcm9wCntwcmVz'
    'ZXJ2ZV9kaXNhYmxlZH0KIH19CiBjaGFpbiBuYXQge3sKICB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNy'
    'Y25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBzYWRkciB7Q0xJRU5UfSBvaWZuYW1lICJ7aWZhY2V9IiBtYXNxdWVyYWRlCiB9'
    'fQp9fScnJwoKCmRlZiBzZXR1cF9uZXR3b3JrKCk6CiAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICMgUmVmdXNl'
    'IG5hbWUvYWRkcmVzcyBjb2xsaXNpb25zIHJhdGhlciB0aGFuIHJlcHVycG9zaW5nIGFub3RoZXIgYXBwbGljYXRpb24ncyBy'
    'ZXNvdXJjZXMuCiAgICBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIG9yIFBhdGgoJy9zeXMvY2xhc3MvbmV0'
    'LycrSE9TVCkuZXhpc3RzKCkgb3IgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVu'
    'dGltZUVycm9yKCd0ZXN0X25hbWVzcGFjZV9leGlzdHMnKQogICAgaWYgY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywg'
    'J3Nob3cnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcigndGVzdF90YWJsZV9pbl91c2UnKQogICAgaWYgYW55KE5FVFdPUksgaW4gbGluZSBmb3IgbGluZSBp'
    'biBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsICdhbGwnXSkuc3Rkb3V0LnNwbGl0bGlu'
    'ZXMoKSk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X25ldHdvcmtfaW5fdXNlJykKICAgIG9sZF9mb3J3YXJk'
    'ID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICAjIFJlY29y'
    'ZCBvd25lcnNoaXAgYmVmb3JlIGNyZWF0aW5nIGFueXRoaW5nOiBjbGVhbnVwIGlzIHZhbGlkIGFmdGVyIGV2ZXJ5IHBhcnRp'
    'YWwgc3RlcC4KICAgIHVwbGluayA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvcm91dGVbJ2RldiddLydmb3J3'
    'YXJkaW5nJwogICAgd3JpdGUoUk9PVC8nbmV0d29yay5qc29uJywganNvbi5kdW1wcyh7J2ZvcndhcmQnOiBvbGRfZm9yd2Fy'
    'ZCwgJ2ludGVyZmFjZSc6IHJvdXRlWydkZXYnXSwgJ3VwbGlua19mb3J3YXJkJzogdXBsaW5rLnJlYWRfdGV4dCgpLnN0cmlw'
    'KCl9KSkKICAgIGNvbW1hbmQoWydpcCcsICduZXRucycsICdhZGQnLCBOU10pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5z'
    'JykvTlMvJ3Jlc29sdi5jb25mJywgJ25hbWVzZXJ2ZXIgMS4xLjEuMVxubmFtZXNlcnZlciA5LjkuOS45XG5vcHRpb25zIHRp'
    'bWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAgIyBuc3MtcmVzb2x2ZSB0YWxrcyB0byB0aGUgaG9zdCBkYWVtb24gb3ZlciBh'
    'IFVuaXggc29ja2V0IGV2ZW4gaW5zaWRlIG5ldG5zLgogICAgbnNzPVBhdGgoJy9ldGMvbnNzd2l0Y2guY29uZicpLnJlYWRf'
    'dGV4dCgpCiAgICBuc3M9cmUuc3ViKHInXmhvc3RzOi4qJCcsICdob3N0czogZmlsZXMgZG5zJywgbnNzLCBmbGFncz1yZS5N'
    'KQogICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJywgbnNzKQogICAgY29tbWFuZChbJ2lw'
    'JywgJ2xpbmsnLCAnYWRkJywgSE9TVCwgJ3R5cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUnLCBQRUVSXSkKICAgIGNvbW1h'
    'bmQoWydpcCcsICdsaW5rJywgJ3NldCcsIFBFRVIsICduZXRucycsIE5TXSkKICAgIGNvbW1hbmQoWydpcCcsICdhZGRyJywg'
    'J2FkZCcsIEdBVEVXQVkrJy8zMCcsICdkZXYnLCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIEhP'
    'U1QsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8zMCcsICdkZXYnLCBQRUVSXSkK'
    'ICAgIGluc2lkZShbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywg'
    'J3NldCcsICdsbycsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ2RlZmF1bHQnLCAndmlhJywg'
    'R0FURVdBWV0pCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywgc3RyKFRBQkxFKSwgJ2RlZmF1'
    'bHQnLCAndmlhJywgcm91dGVbJ2dhdGV3YXknXSwgJ2RldicsIHJvdXRlWydkZXYnXV0pCiAgICBmb3IgYWRkcmVzcyBpbiBF'
    'TkRQT0lOVFM6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZ'
    'KSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcs'
    'IHN0cihUQUJMRSldKQogICAgcnVsZXMgPSBob3N0X3J1bGVzKHJvdXRlWydkZXYnXSwgcHJldmlvdXNfZm9yd2FyZD1vbGRf'
    'Zm9yd2FyZCA9PSAnMScpCiAgICBjb21tYW5kKFsnbmZ0JywgJy1jJywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAgIGNv'
    'bW1hbmQoWyduZnQnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgIyBQZXItaW50ZXJmYWNlIGZvcndhcmRpbmcgYXZv'
    'aWRzIGlwX2ZvcndhcmQncyBnbG9iYWwgZGVmYXVsdHMgcmVzZXQuCiAgICAoUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2Nv'
    'bmYnKS9IT1NULydmb3J3YXJkaW5nJykud3JpdGVfdGV4dCgnMVxuJykKICAgIHVwbGluay53cml0ZV90ZXh0KCcxXG4nKQoK'
    'CmRlZiBjbGVhbnVwKCk6CiAgICBjbGVhbnVwX2Z1bGwoKQogICAgIyBBbiB1bm93bmVkIG5hbWVzcGFjZS90YWJsZSBtdXN0'
    'IG5ldmVyIGJlIGRlbGV0ZWQgYnkgYSBnZW5lcmljIGNsZWFudXAgY2FsbC4KICAgIGlmIG5vdCAoUk9PVC8nbmV0d29yay5q'
    'c29uJykuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuCiAgICBkYXRhID0ganNvbi5sb2FkcygoUk9PVC8nbmV0d29yay5qc29u'
    'JykucmVhZF90ZXh0KCkpCiAgICBjb21tYW5kKFsnbmZ0JywgJ2RlbGV0ZScsICd0YWJsZScsICdpbmV0JywgTkZUXSwgY2hl'
    'Y2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiAoKkVORFBPSU5UUywgKkxFR0FDWV9FTkRQT0lOVFMpOgogICAgICAgIGNv'
    'bW1hbmQoWydpcCcsICdydWxlJywgJ2RlbCcsICdwcmlvcml0eScsIHN0cihQUklPUklUWSksICdmcm9tJywgQ0xJRU5UKycv'
    'MzInLAogICAgICAgICAgICAgICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9'
    'RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiBkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pOgogICAgICAgIGlmIGlw'
    'YWRkcmVzcy5pcF9hZGRyZXNzKGFkZHJlc3MpLmlzX2dsb2JhbDoKICAgICAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUn'
    'LCAnZGVsJywgJ3ByaW9yaXR5JywgJzExMScsICdmcm9tJywgQ0xJRU5UKycvMzInLCAndG8nLCBhZGRyZXNzKycvMzInLCAn'
    'bG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2ZsdXNoJywg'
    'J3RhYmxlJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2RlbCcsIE5T'
    'XSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdkZWwnLCBIT1NUXSwgY2hlY2s9RmFsc2UpCiAg'
    'ICBpZiAndXBsaW5rX2ZvcndhcmQnIGluIGRhdGE6CiAgICAgICAgcGF0aCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9j'
    'b25mJykvZGF0YVsnaW50ZXJmYWNlJ10vJ2ZvcndhcmRpbmcnCiAgICAgICAgaWYgcGF0aC5leGlzdHMoKToKICAgICAgICAg'
    'ICAgcGF0aC53cml0ZV90ZXh0KGRhdGFbJ3VwbGlua19mb3J3YXJkJ10rJ1xuJykKICAgIGVsaWYgZGF0YS5nZXQoJ2Zvcndh'
    'cmQnKSA9PSAnMCcgYW5kIFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykucmVhZF90ZXh0KCkuc3RyaXAo'
    'KSA9PSAnMSc6CiAgICAgICAgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS53cml0ZV90ZXh0KCcwXG4n'
    'KQogICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAg'
    'KFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8nbnNzd2l0Y2guY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3aXRo'
    'IGNvbnRleHRsaWIuc3VwcHJlc3MoT1NFcnJvcik6CiAgICAgICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykucm1kaXIoKQog'
    'ICAgKFJPT1QvJ25ldHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKQGNvbnRleHRsaWIuY29udGV4dG1h'
    'bmFnZXIKZGVmIG1lYXN1cmVtZW50X3JvdXRlKGFkZHJlc3MpOgogICAgIiIiQSBzaG9ydC1saXZlZCBkaXJlY3Qgcm91dGUg'
    'Zm9yIGEgdmVyaWZpZWQgWWFuZGV4IEhUVFBTIG1lYXN1cmVtZW50LCBsYWIgb25seS4iIiIKICAgIGlmIG5vdCBpcGFkZHJl'
    'c3MuaXBfYWRkcmVzcyhhZGRyZXNzKS5pc19nbG9iYWwgb3IgYWRkcmVzcyBpbiBFTkRQT0lOVFM6CiAgICAgICAgcmFpc2Ug'
    'VmFsdWVFcnJvcignaW52YWxpZF9tZWFzdXJlbWVudF9hZGRyZXNzJykKICAgIGxhYmVsID0gJ2V2bi1tZWFzdXJlLScrc2Vj'
    'cmV0cy50b2tlbl9oZXgoOCkKICAgIGRhdGEgPSBqc29uLmxvYWRzKChST09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQo'
    'KSkKICAgIGRhdGFbJ21lYXN1cmVtZW50X2lwcyddID0gc29ydGVkKHNldChkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywg'
    'W10pK1thZGRyZXNzXSkpCiAgICB3cml0ZShST09ULyduZXR3b3JrLmpzb24nLCBqc29uLmR1bXBzKGRhdGEpKQogICAgdHJ5'
    'OgogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2FkZCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVO'
    'VCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAg'
    'ICAgICAgY29tbWFuZChbJ25mdCcsICdpbnNlcnQnLCAncnVsZScsICdpbmV0JywgTkZULCAnZm9yd2FyZCcsICdpaWZuYW1l'
    'JywgSE9TVCwKICAgICAgICAgICAgICAgICAnaXAnLCAnZGFkZHInLCBhZGRyZXNzLCAndGNwJywgJ2Rwb3J0JywgJzQ0Mycs'
    'ICdhY2NlcHQnLCAnY29tbWVudCcsIGxhYmVsXSkKICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2luc2VydCcsICdydWxlJywg'
    'J2luZXQnLCBORlQsICdmb3J3YXJkJywgJ29pZm5hbWUnLCBIT1NULAogICAgICAgICAgICAgICAgICdpcCcsICdzYWRkcics'
    'IGFkZHJlc3MsICdjdCcsICdzdGF0ZScsICdlc3RhYmxpc2hlZCxyZWxhdGVkJywgJ2FjY2VwdCcsICdjb21tZW50JywgbGFi'
    'ZWxdKQogICAgICAgIHlpZWxkCiAgICBmaW5hbGx5OgogICAgICAgIHJlc3VsdCA9IGNvbW1hbmQoWyduZnQnLCAnLWonLCAn'
    'LWEnLCAnbGlzdCcsICdjaGFpbicsICdpbmV0JywgTkZULCAnZm9yd2FyZCddLCBjaGVjaz1GYWxzZSkKICAgICAgICBpZiBy'
    'ZXN1bHQucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICBmb3IgZW50cnkgaW4ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0'
    'KS5nZXQoJ25mdGFibGVzJywgW10pOgogICAgICAgICAgICAgICAgcnVsZSA9IGVudHJ5LmdldCgncnVsZScsIHt9KQogICAg'
    'ICAgICAgICAgICAgaWYgcnVsZS5nZXQoJ2NvbW1lbnQnKSA9PSBsYWJlbDoKICAgICAgICAgICAgICAgICAgICBjb21tYW5k'
    'KFsnbmZ0JywgJ2RlbGV0ZScsICdydWxlJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJywgJ2hhbmRsZScsIHN0cihydWxlWydo'
    'YW5kbGUnXSldLCBjaGVjaz1GYWxzZSkKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHkn'
    'LCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xv'
    'b2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKCgpkZWYgcHJvdmlkZXJfYWRkcmVzc2VzKGhvc3QpOgogICAgIyBE'
    'TlMgbWF5IHVzZSB0aGUgd29ya2luZyByZXNvbHZlciwgYnV0IG1lYXN1cmVkIEhUVFBTIGl0c2VsZiB0YWtlcyB0aGUgcGh5'
    'c2ljYWwgcm91dGUuCiAgICBhZGRyZXNzZXMgPSBbYW5zd2VyWzRdWzBdIGZvciBhbnN3ZXIgaW4gc29ja2V0LmdldGFkZHJp'
    'bmZvKGhvc3QsIDQ0Mywgc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX1NUUkVBTSldCiAgICByZXR1cm4gbGlzdChkaWN0'
    'LmZyb21rZXlzKHggZm9yIHggaW4gYWRkcmVzc2VzIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHgpLmlzX2dsb2JhbCkpWzoy'
    'XQoKCmRlZiBwcm92aWRlcl9nZXQoaG9zdCwgcGF0aCwgbWF4aW11bSwgbWVhc3VyZT1GYWxzZSk6CiAgICBsYXN0ID0gTm9u'
    'ZQogICAgZm9yIGFkZHJlc3MgaW4gcHJvdmlkZXJfYWRkcmVzc2VzKGhvc3QpOgogICAgICAgIG91dHB1dCA9IFJPT1QvKCdy'
    'ZWZlcmVuY2UtJytzZWNyZXRzLnRva2VuX2hleCg4KSsnLnRtcCcpCiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG1l'
    'YXN1cmVtZW50X3JvdXRlKGFkZHJlc3MpOgogICAgICAgICAgICAgICAgYXJncyA9IFsnY3VybCcsICctNCcsICctLXNpbGVu'
    'dCcsICctLXNob3ctZXJyb3InLCAnLS1mYWlsJywgJy0tbm9wcm94eScsICcqJywKICAgICAgICAgICAgICAgICAgICAgICAg'
    'Jy0tcHJvdG8nLCAnPWh0dHBzJywgJy0tY29ubmVjdC10aW1lb3V0JywgJzQnLCAnLS1tYXgtdGltZScsICcxMCcsCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICctLXJlc29sdmUnLCBob3N0Kyc6NDQzOicrYWRkcmVzcywgJy0tbWF4LWZpbGVzaXplJywg'
    'c3RyKG1heGltdW0pLAogICAgICAgICAgICAgICAgICAgICAgICAnLS1vdXRwdXQnLCBzdHIob3V0cHV0KSwgJy0td3JpdGUt'
    'b3V0JywgJyV7anNvbn0nXQogICAgICAgICAgICAgICAgaWYgbWVhc3VyZToKICAgICAgICAgICAgICAgICAgICBhcmdzICs9'
    'IFsnLS1yYW5nZScsICcwLScrc3RyKG1heGltdW0tMSldCiAgICAgICAgICAgICAgICBhcmdzICs9IFsnaHR0cHM6Ly8nK2hv'
    'c3QrcGF0aF0KICAgICAgICAgICAgICAgIHJlc3VsdCA9IGluc2lkZShhcmdzLCB0aW1lb3V0PTEyLCBjaGVjaz1GYWxzZSkK'
    'ICAgICAgICAgICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2RlOgogICAgICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcignbWVhc3VyZW1lbnRfY3VybF8nK3N0cihyZXN1bHQucmV0dXJuY29kZSkpCiAgICAgICAgICAgICAgICBzdGF0aXN0'
    'aWNzID0ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0KQogICAgICAgICAgICAgICAgaWYgbWVhc3VyZToKICAgICAgICAgICAg'
    'ICAgICAgICByZWNlaXZlZCA9IGludChzdGF0aXN0aWNzWydzaXplX2Rvd25sb2FkJ10pCiAgICAgICAgICAgICAgICAgICAg'
    'ZWxhcHNlZCA9IGZsb2F0KHN0YXRpc3RpY3NbJ3RpbWVfdG90YWwnXSktZmxvYXQoc3RhdGlzdGljc1sndGltZV9zdGFydHRy'
    'YW5zZmVyJ10pCiAgICAgICAgICAgICAgICAgICAgaWYgcmVjZWl2ZWQgPCAxMDI0KjEwMjQgb3IgcmVjZWl2ZWQgPiBtYXhp'
    'bXVtIG9yIGVsYXBzZWQgPD0gMDoKICAgICAgICAgICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdtZWFzdXJl'
    'bWVudF90b29fc2hvcnQnKQogICAgICAgICAgICAgICAgICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdlbGFwc2Vk'
    'X21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICdlc3RpbWF0ZWRfbWJwcyc6'
    'IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xZTYsIDIpfQogICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dC5yZWFkX2J5'
    'dGVzKCkKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFJ1bnRpbWVFcnJvciwgVmFsdWVFcnJvciwgc3VicHJvY2Vzcy5UaW1l'
    'b3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgICAgICBsYXN0ID0gZXhjCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAg'
    'b3V0cHV0LnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlZmVyZW5jZV91bmF2YWls'
    'YWJsZScpIGZyb20gbGFzdAoKCmRlZiB2YWxpZGF0ZV95YW5kZXhfcHJvYmUodXJsKToKICAgIGZyb20gdXJsbGliLnBhcnNl'
    'IGltcG9ydCB1cmxzcGxpdAogICAgcGFyc2VkID0gdXJsc3BsaXQodXJsKQogICAgaWYgKGxlbih1cmwpID4gMjA0OCBvciBw'
    'YXJzZWQuc2NoZW1lICE9ICdodHRwcycgb3Igbm90IHBhcnNlZC5ob3N0bmFtZSBvcgogICAgICAgIG5vdCBwYXJzZWQuaG9z'
    'dG5hbWUuZW5kc3dpdGgoJy5jZG4ueWFuZGV4Lm5ldCcpIG9yIHBhcnNlZC51c2VybmFtZSBvciBwYXJzZWQucGFzc3dvcmQg'
    'b3IKICAgICAgICBwYXJzZWQucG9ydCBub3QgaW4gKE5vbmUsIDQ0Mykgb3IgcGFyc2VkLmZyYWdtZW50KToKICAgICAgICBy'
    'YWlzZSBWYWx1ZUVycm9yKCd1bnRydXN0ZWRfcmVmZXJlbmNlX3VybCcpCiAgICByZXR1cm4gcGFyc2VkLmhvc3RuYW1lLCBw'
    'YXJzZWQucGF0aCsoJz8nICsgcGFyc2VkLnF1ZXJ5IGlmIHBhcnNlZC5xdWVyeSBlbHNlICcnKQoKCmRlZiByZWZlcmVuY2Vf'
    'c2FtcGxlKGZvcmNlPUZhbHNlKToKICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgZmluZ2VycHJpbnQgPSBoYXNo'
    'bGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6IHJvdXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScs'
    'ICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1ZSkuZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICB0cnk6CiAgICAgICAgY2Fj'
    'aGVkID0ganNvbi5sb2FkcygoUk9PVC8ncmVmZXJlbmNlLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICBpZiBub3QgZm9y'
    'Y2UgYW5kIGNhY2hlZC5nZXQoJ25ldHdvcmsnKSA9PSBmaW5nZXJwcmludCBhbmQgY2FjaGVkLmdldCgncHJvdmlkZXInKSA9'
    'PSAnWWFuZGV4IEludGVybmV0b21ldGVyJzoKICAgICAgICAgICAgcmV0dXJuIGNhY2hlZAogICAgZXhjZXB0IChPU0Vycm9y'
    'LCBWYWx1ZUVycm9yKToKICAgICAgICBwYXNzCiAgICBzdGFnZSgncmVmZXJlbmNlJywgJ9CX0LDQv9GD0YHQutCw0Y4g0LfQ'
    'sNC80LXRgCDQv9GA0Y/QvNC+0LPQviDRgdC+0LXQtNC40L3QtdC90LjRjzog0K/QvdC00LXQutGBINCY0L3RgtC10YDQvdC1'
    '0YLQvtC80LXRgtGALicsIDEyKQogICAgY29uZmlnID0ganNvbi5sb2Fkcyhwcm92aWRlcl9nZXQoJ3lhbmRleC5ydScsICcv'
    'aW50ZXJuZXQvYXBpL3YwL2dldC1wcm9iZXM/ZnJvbT1pbnRlcm5ldCZub2NhY2hlPScrc3RyKGludCh0aW1lLnRpbWUoKSox'
    'MDAwKSksIDY1NTM2KSkKICAgIHByb2JlcyA9IGNvbmZpZy5nZXQoJ2Rvd25sb2FkJywge30pLmdldCgncHJvYmVzJywgW10p'
    'CiAgICBjYW5kaWRhdGVzID0gW10KICAgIGZvciBwcm9iZSBpbiBwcm9iZXM6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBo'
    'b3N0LCBwYXRoID0gdmFsaWRhdGVfeWFuZGV4X3Byb2JlKHByb2JlLmdldCgndXJsJywgJycpKQogICAgICAgIGV4Y2VwdCAo'
    'VmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiAnNTBtYicgaW4gcGF0aCBv'
    'ciAnMTAwbWInIGluIHBhdGg6CiAgICAgICAgICAgIGNhbmRpZGF0ZXMuYXBwZW5kKChob3N0LCBwYXRoKSkKICAgIGlmIG5v'
    'dCBjYW5kaWRhdGVzOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVmZXJlbmNlX3NjaGVtYV9jaGFuZ2VkJykKICAg'
    'IGhvc3QsIHBhdGggPSBjYW5kaWRhdGVzWzBdCiAgICAjIFNob3J0IHNhbXBsZXMgYXZvaWQgYSBtaW51dGUtbG9uZyBzYXR1'
    'cmF0aW9uIHdoaWxlIHRoZSB1c2VyIHdhdGNoZXMgdmlkZW8uCiAgICBzYW1wbGVzID0gW3Byb3ZpZGVyX2dldChob3N0LCBw'
    'YXRoLCA4KjEwMjQqMTAyNCwgbWVhc3VyZT1UcnVlKSBmb3IgXyBpbiByYW5nZSgyKV0KICAgIHJlc3VsdCA9IHsncHJvdmlk'
    'ZXInOiAnWWFuZGV4IEludGVybmV0b21ldGVyJywgJ25ldHdvcmsnOiBmaW5nZXJwcmludCwgJ3RpbWUnOiBpbnQodGltZS50'
    'aW1lKCkpLAogICAgICAgICAgICAgICdlc3RpbWF0ZWRfbWJwcyc6IG1heCh4Wydlc3RpbWF0ZWRfbWJwcyddIGZvciB4IGlu'
    'IHNhbXBsZXMpLCAnc2FtcGxlcyc6IHNhbXBsZXMsCiAgICAgICAgICAgICAgJ3Nob3J0X3NhbXBsZSc6IFRydWUsICdkaXJl'
    'Y3RfcGh5c2ljYWxfcm91dGUnOiBUcnVlfQogICAgd3JpdGUoUk9PVC8ncmVmZXJlbmNlLmpzb24nLCBqc29uLmR1bXBzKHJl'
    'c3VsdCkpCiAgICByZXR1cm4gcmVzdWx0CgoKCmRlZiB0bHNfcmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNs'
    'aWVudD1GYWxzZSwgdGltZW91dD04KToKICAgIGNvbnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9'
    'UElOTkVEX0NBKQogICAgaWYgY2xpZW50OgogICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGll'
    'bnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlv'
    'bigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9dGltZW91dCkKICAgIHRyeToKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBf'
    'c29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1TRVJWRVIpCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBz'
    'b2NrLmNsb3NlKCkKICAgICAgICByYWlzZQogICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKGFk'
    'ZHJlc3MsIDg0NDMsIHRpbWVvdXQ9dGltZW91dCkKICAgIGNvbm5lY3Rpb24uc29jayA9IHRscwogICAgZW5jb2RlZCA9IGpz'
    'b24uZHVtcHMoYm9keSwgc2VwYXJhdG9ycz0oJywnLCAnOicpKS5lbmNvZGUoKSBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2Ug'
    'Tm9uZQogICAgdHJ5OgogICAgICAgIGNvbm5lY3Rpb24ucmVxdWVzdCgnUE9TVCcgaWYgYm9keSBpcyBub3QgTm9uZSBlbHNl'
    'ICdHRVQnLCBwYXRoLCBib2R5PWVuY29kZWQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9eydDb250ZW50'
    'LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsICdDb25uZWN0aW9uJzogJ2Nsb3NlJ30pCiAgICAgICAgcmVzcG9uc2UgPSBj'
    'b25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICByYXcgPSByZXNwb25zZS5yZWFkKDIwMDAxKQogICAgICAgIGlmIHJl'
    'c3BvbnNlLnN0YXR1cyAhPSAyMDAgb3IgbGVuKHJhdykgPiAyMDAwMDoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdyZXF1ZXN0X3JlamVjdGVkJykKICAgICAgICByZXR1cm4ganNvbi5sb2FkcyhyYXcpCiAgICBmaW5hbGx5OgogICAgICAg'
    'IGNvbm5lY3Rpb24uY2xvc2UoKQoKCmRlZiBlbnJvbGwoKToKICAgIHRva2VuID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0'
    'KCkuc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCdpbnZhbGlkX3Rva2VuJykKICAgIHRyeToKICAgICAgICBjYWNoZWQgPSBqc29uLmxvYWRzKChST09U'
    'Lydwcm9maWxlLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICBpZiAoY2FjaGVkLmdldCgnY2EnKSA9PSBQSU5ORURfQ0Eg'
    'YW5kIGNhY2hlZC5nZXQoJ3NlcnZlcicpID09IFNFUlZFUiBhbmQKICAgICAgICAgICAgcmUuZnVsbG1hdGNoKHInZGV2aWNl'
    'LVthLWYwLTldezI0fScsIGNhY2hlZC5nZXQoJ2lkZW50aXR5JywgJycpKSBhbmQKICAgICAgICAgICAgY2FjaGVkLmdldCgn'
    'ZW5kcG9pbnQnKSBpbiBFTkRQT0lOVFMgYW5kIGNhY2hlZC5nZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSBhbmQKICAgICAgICAg'
    'ICAgY29tbWFuZChbJ29wZW5zc2wnLCAneDUwOScsICctaW4nLCBST09ULydjbGllbnQucGVtJywgJy1jaGVja2VuZCcsIHN0'
    'cig3Kjg2NDAwKSwgJy1ub291dCddLCBjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwKToKICAgICAgICAgICAgY29udGV4'
    'dCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgICAgICBjb250ZXh0LmxvYWRfY2Vy'
    'dF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAgICAgICAgICAg'
    'cm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAgICAgICAgIGN1cnJlbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBz'
    'KHtrZXk6IHJvdXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tl'
    'eXM9VHJ1ZSkuZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICAgICAgICAgIGFkZHJlc3MgPSBjYWNoZWRbJ2VuZHBvaW50J10g'
    'aWYgY2FjaGVkLmdldCgncGh5c2ljYWxfbmV0d29yaycpID09IGN1cnJlbnQgZWxzZSBTRVJWRVIKICAgICAgICAgICAgcmV0'
    'dXJuIGNhY2hlZFsnaWRlbnRpdHknXSwgYWRkcmVzcwogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yLCBzc2wuU1NM'
    'RXJyb3IpOgogICAgICAgIHBhc3MKICAgIHN0YWdlKCd0b2tlbicsICfQn9C+0LvRg9GH0LDRjiDRgdC10YDRgtC40YTQuNC6'
    '0LDRgiDQtNC70Y8g0Y3RgtC+0LPQviDRg9GB0YLRgNC+0LnRgdGC0LLQsC4nLCAyNSkKICAgIGlmIG5vdCAoUk9PVC8nY2xp'
    'ZW50LWtleS5wZW0nKS5leGlzdHMoKToKICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICdnZW5wa2V5JywgJy1hbGdvcml0'
    'aG0nLCAnUlNBJywgJy1wa2V5b3B0JywgJ3JzYV9rZXlnZW5fYml0czozMDcyJywKICAgICAgICAgICAgICAgICAnLW91dCcs'
    'IFJPT1QvJ2NsaWVudC1rZXkucGVtJ10sIHRpbWVvdXQ9MzApCiAgICAgICAgKFJPT1QvJ2NsaWVudC1rZXkucGVtJykuY2ht'
    'b2QoMG82MDApCiAgICBpZiBub3QgKFJPT1QvJ2RldmljZScpLmV4aXN0cygpOgogICAgICAgIHdyaXRlKFJPT1QvJ2Rldmlj'
    'ZScsIHNlY3JldHMudG9rZW5faGV4KDE2KSkKICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3JlcScsICctbmV3JywgJy1rZXkn'
    'LCBST09ULydjbGllbnQta2V5LnBlbScsICctc3ViaicsICcvQ049ZXZnZW5pdW0tZGV2aWNlJywKICAgICAgICAgICAgICct'
    'b3V0JywgUk9PVC8ncmVxdWVzdC5wZW0nXSkKICAgIHBheWxvYWQgPSB7J3Rva2VuJzogdG9rZW4sICdkZXZpY2UnOiAoUk9P'
    'VC8nZGV2aWNlJykucmVhZF90ZXh0KCkuc3RyaXAoKSwgJ2Nzcic6IChST09ULydyZXF1ZXN0LnBlbScpLnJlYWRfdGV4dCgp'
    'fQogICAgbGFzdCA9IE5vbmUKICAgIGZvciBhZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICB0cnk6CiAgICAgICAgICAg'
    'IHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgICAgICAgICByZXBseSA9IHRsc19yZXF1ZXN0KGFkZHJlc3MsICcvZW5yb2xs'
    'JywgcGF5bG9hZCwgdGltZW91dD02KQogICAgICAgICAgICBwcm9maWxlID0gcmVwbHkuZ2V0KCdwcm9maWxlJywge30pCiAg'
    'ICAgICAgICAgIGlmIHJlcGx5LmdldCgnb2snKSBpcyBub3QgVHJ1ZSBvciBwcm9maWxlLmdldCgnY2EnKSAhPSBQSU5ORURf'
    'Q0Egb3IgcHJvZmlsZS5nZXQoJ3NlcnZlcicpICE9IFNFUlZFUjoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cignaW52YWxpZF9wcm9maWxlJykKICAgICAgICAgICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyJ2RldmljZS1bYS1mMC05XXsy'
    'NH0nLCBwcm9maWxlLmdldCgnaWRlbnRpdHknLCAnJykpOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdp'
    'bnZhbGlkX2lkZW50aXR5JykKICAgICAgICAgICAgd3JpdGUoUk9PVC8nY2xpZW50LnBlbScsIHByb2ZpbGVbJ2NlcnRpZmlj'
    'YXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NhLnBlbScsIFBJTk5FRF9DQSkKICAgICAgICAgICAgd3JpdGUoUk9P'
    'VC8neDUwOScvJ2NsaWVudC5wZW0nLCBwcm9maWxlWydjZXJ0aWZpY2F0ZSddKQogICAgICAgICAgICB3cml0ZShST09ULyd4'
    'NTA5Y2EnLydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3ByaXZhdGUnLydjbGllbnQta2V5'
    'LnBlbScsIChST09ULydjbGllbnQta2V5LnBlbScpLnJlYWRfdGV4dCgpKQogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNz'
    'bCcsICd2ZXJpZnknLCAnLXB1cnBvc2UnLCAnc3NsY2xpZW50JywgJy1DQWZpbGUnLCBST09ULydjYS5wZW0nLCBST09ULydj'
    'bGllbnQucGVtJ10pCiAgICAgICAgICAgIGN0eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQog'
    'ICAgICAgICAgICBjdHgubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQt'
    'a2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICAgICAgICAgZmluZ2VycHJpbnQg'
    'PSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6IHJvdXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0'
    'ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1ZSkuZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICAgICAgICAgIHdy'
    'aXRlKFJPT1QvJ3Byb2ZpbGUuanNvbicsIGpzb24uZHVtcHMoeyoqcHJvZmlsZSwgJ2VuZHBvaW50JzogYWRkcmVzcywgJ3Bo'
    'eXNpY2FsX25ldHdvcmsnOiBmaW5nZXJwcmludH0pKQogICAgICAgICAgICByZXR1cm4gcHJvZmlsZVsnaWRlbnRpdHknXSwg'
    'YWRkcmVzcwogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgc3NsLlNTTEVycm9yLCBSdW50aW1lRXJyb3IpIGFzIGV4YzoKICAg'
    'ICAgICAgICAgbGFzdCA9IGV4YwogICAgcmFpc2UgUnVudGltZUVycm9yKCdlbnJvbGxtZW50X3VuYXZhaWxhYmxlJykgZnJv'
    'bSBsYXN0CgoKZGVmIGRhZW1vbl9jb25maWdzKGlkZW50aXR5LCBhZGRyZXNzKToKICAgIFJVTlRJTUUubWtkaXIobW9kZT0w'
    'bzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgaW5jbHVkZXMgPSAnXG4nLmpvaW4oJ2luY2x1ZGUgJytz'
    'dHIocCkgZm9yIHBhdHRlcm4gaW4gKCcvZXRjL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25mJywgJy9ldGMvc3Ryb25nc3dh'
    'bi9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicpCiAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgcCBpbiBQYXRoKCcv'
    'JykuZ2xvYihwYXR0ZXJuLmxzdHJpcCgnLycpKSkKICAgIHdyaXRlKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicsIGYnJydjaGFy'
    'b24ge3sKIGxvYWRfbW9kdWxhciA9IHllcwogaW5zdGFsbF9yb3V0ZXMgPSB5ZXMKIHJvdXRpbmdfdGFibGUgPSA1MTgyMgog'
    'cm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBwbHVnaW5zIHt7CntpbmNsdWRlc30KICB2aWNpIHt7IHNvY2tldCA9IHVuaXg6'
    'Ly97UlVOVElNRX0vY2hhcm9uLnZpY2kgfX0KICByZXNvbHZlIHt7IGxvYWQgPSBubyB9fQogIGtlcm5lbC1saWJpcHNlYyB7'
    'eyBsb2FkID0gbm8gfX0KIH19Cn19CmNoYXJvbi1zeXN0ZW1kIHt7IGpvdXJuYWwge3sgZGVmYXVsdCA9IDA7IGlrZSA9IDEg'
    'fX0gfX0KJycnKQogICAgIyBBYnNvbHV0ZSBjcmVkZW50aWFscyBhcmUgbG9jYWwgdG8gdGhpcyBkZXZpY2UsIG5vdCBzaGFy'
    'ZWQgYnkgdGhlIGFjY291bnQgdG9rZW4uCiAgICB3cml0ZShST09ULydjb25uZWN0aW9uLmNvbmYnLCBmJycnY29ubmVjdGlv'
    'bnMge3sKIHN0YXJmaXZlIHt7CiAgdmVyc2lvbiA9IDIKICByZW1vdGVfYWRkcnMgPSB7YWRkcmVzc30KICByZW1vdGVfcG9y'
    'dCA9IHtJS0VfUE9SVH0KICBsb2NhbF9wb3J0ID0gNDUwMAogIHZpcHMgPSAwLjAuMC4wCiAgcHJvcG9zYWxzID0gYWVzMjU2'
    'Z2NtMTYtcHJmc2hhMzg0LWVjcDM4NAogIGVuY2FwID0geWVzCiAgZnJhZ21lbnRhdGlvbiA9IHllcwogIG1vYmlrZSA9IHll'
    'cwogIGRwZF9kZWxheSA9IDE1cwogIGxvY2FsIHt7IGF1dGggPSBlYXAtdGxzOyBpZCA9IHtpZGVudGl0eX07IGVhcF9pZCA9'
    'IHtpZGVudGl0eX07IGNlcnRzID0ge1JPT1R9L2NsaWVudC5wZW0gfX0KICByZW1vdGUge3sgYXV0aCA9IHB1YmtleTsgaWQg'
    'PSB7U0VSVkVSfTsgY2FjZXJ0cyA9IHtST09UfS9jYS5wZW0gfX0KICBjaGlsZHJlbiB7ewogICBzdGFyZml2ZS1uZXQge3sK'
    'ICAgIGxvY2FsX3RzID0gZHluYW1pYwogICAgcmVtb3RlX3RzID0gMC4wLjAuMC8wCiAgICByZXFpZCA9IHtSRVFJRH0KICAg'
    'IGVzcF9wcm9wb3NhbHMgPSBjaGFjaGEyMHBvbHkxMzA1CiAgICBkcGRfYWN0aW9uID0gY2xlYXIKICAgIHN0YXJ0X2FjdGlv'
    'biA9IG5vbmUKICAgfX0KICB9fQogfX0KfX0Kc2VjcmV0cyB7eyBwcml2YXRlLWNsaWVudCB7eyBmaWxlID0ge1JPT1R9L2Ns'
    'aWVudC1rZXkucGVtIH19IH19CicnJykKICAgICMgU3Ryb25nU3dhbiBjb25maWcgdXNlcyBuZXdsaW5lcywgbm90IHNlbWlj'
    'b2xvbiBzZXBhcmF0b3JzIChub3JtYWxpemUgY29tcGFjdCBibG9ja3MpLgogICAgZm9yIG5hbWUgaW4gKCdzdHJvbmdzd2Fu'
    'LmNvbmYnLCAnY29ubmVjdGlvbi5jb25mJyk6CiAgICAgICAgcGF0aCA9IFJPT1QvbmFtZQogICAgICAgIHBhdGgud3JpdGVf'
    'dGV4dChwYXRoLnJlYWRfdGV4dCgpLnJlcGxhY2UoJzsgJywgJ1xuJykucmVwbGFjZSgneyAnLCAne1xuJykucmVwbGFjZSgn'
    'IH0nLCAnXG59JykpCiAgICBydWxlcyA9IGYnJyd0YWJsZSBpbmV0IGV2bl9zdGFyZml2ZV9ndWFyZCB7ewogY2hhaW4gb3V0'
    'cHV0IHt7CiAgdHlwZSBmaWx0ZXIgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJs'
    'byIgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAogIG1ldGEgc2t1aWQg'
    'MCBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0'
    'IHJlcWlkIHtSRVFJRH0gYWNjZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJp'
    'b3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsgfX0KfX0nJycKICAgIGluc2lkZShbJ25mdCcsICctYycsICctZicsICctJ10sIGRh'
    'dGE9cnVsZXMpCiAgICBpbnNpZGUoWyduZnQnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQoKCmRlZiBzd2FuKCphcmdzLCB0'
    'aW1lb3V0PTE1LCBjaGVjaz1UcnVlKToKICAgIHJldHVybiBpbnNpZGUoWydzd2FuY3RsJywgKmFyZ3MsICctLXVyaScsICd1'
    'bml4Oi8vJytzdHIoUlVOVElNRS8nY2hhcm9uLnZpY2knKV0sIHRpbWVvdXQ9dGltZW91dCwgY2hlY2s9Y2hlY2spCgoKZGVm'
    'IGluc3RhbGxlZCgpOgogICAgdHJ5OgogICAgICAgIHJlc3VsdCA9IHN3YW4oJy0tbGlzdC1zYXMnLCAnLS1yYXcnLCB0aW1l'
    'b3V0PTMsIGNoZWNrPUZhbHNlKQogICAgICAgIHJldHVybiByZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCAnc3RhdGU9RVNU'
    'QUJMSVNIRUQnIGluIHJlc3VsdC5zdGRvdXQgYW5kICdzdGF0ZT1JTlNUQUxMRUQnIGluIHJlc3VsdC5zdGRvdXQKICAgIGV4'
    'Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhl'
    'YWx0aCgpOgogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICByZXR1cm4gdGxzX3JlcXVlc3QoSEVBTFRILCAnL2hlYWx0'
    'aCcsIGNsaWVudD1UcnVlKS5nZXQoJ3NlcnZpY2UnKSA9PSAnZXZnZW5pdW0tc3RhcmZpdmUnCgoKZGVmIGRvd25sb2FkKHNp'
    'emU9MTA0ODU3Nik6CiAgICAjIEEgYm91bmRlZCBpbnRlZ3JpdHkgY2hlY2ssIG5vdCBhIGNsYWltIHRvIGhhdmUgbWVhc3Vy'
    'ZWQgdGhlIElTUCdzIG1heGltdW0gcmF0ZS4KICAgIGJsb2NrID0gaGFzaGxpYi5zaGFrZV8yNTYoYidldmdlbml1bS1zdGFy'
    'Zml2ZS1pbnRlZ3JpdHktdjEnKS5kaWdlc3QoNjU1MzYpCiAgICBleHBlY3RlZCA9IGhhc2hsaWIuc2hhMjU2KChibG9jayoo'
    'c2l6ZS8vbGVuKGJsb2NrKSsxKSlbOnNpemVdKS5oZXhkaWdlc3QoKQogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVs'
    'dF9jb250ZXh0KGNhZGF0YT1QSU5ORURfQ0EpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50'
    'LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgc29jayA9'
    'IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoSEVBTFRILCA4NDQzKSwgdGltZW91dD0xMCkKICAgICAgICB0bHMgPSBjb250'
    'ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1TRVJWRVIpCiAgICAgICAgY29ubmVjdGlvbiA9IGh0dHAu'
    'Y2xpZW50LkhUVFBDb25uZWN0aW9uKEhFQUxUSCwgODQ0MywgdGltZW91dD0xMCk7IGNvbm5lY3Rpb24uc29jayA9IHRscwog'
    'ICAgICAgIHRyeToKICAgICAgICAgICAgc3RhcnQgPSB0aW1lLm1vbm90b25pYygpCiAgICAgICAgICAgIGNvbm5lY3Rpb24u'
    'cmVxdWVzdCgnR0VUJywgJy9ibG9iP3NpemU9JytzdHIoc2l6ZSkpCiAgICAgICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlv'
    'bi5nZXRyZXNwb25zZSgpCiAgICAgICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDA6CiAgICAgICAgICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ3RyYW5zZmVyX2h0dHAnKQogICAgICAgICAgICBkaWdlc3QgPSBoYXNobGliLnNoYTI1Nigp'
    'OyByZWNlaXZlZCA9IDAKICAgICAgICAgICAgd2hpbGUgcmVjZWl2ZWQgPCBzaXplOgogICAgICAgICAgICAgICAgZGF0YSA9'
    'IHJlc3BvbnNlLnJlYWQobWluKDY1NTM2LCBzaXplLXJlY2VpdmVkKSkKICAgICAgICAgICAgICAgIGlmIG5vdCBkYXRhOgog'
    'ICAgICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBkaWdlc3QudXBkYXRlKGRhdGEpOyByZWNlaXZlZCAr'
    'PSBsZW4oZGF0YSkKICAgICAgICAgICAgZWxhcHNlZCA9IHRpbWUubW9ub3RvbmljKCktc3RhcnQKICAgICAgICBmaW5hbGx5'
    'OgogICAgICAgICAgICBjb25uZWN0aW9uLmNsb3NlKCkKICAgIGlmIHJlY2VpdmVkICE9IHNpemUgb3IgZGlnZXN0LmhleGRp'
    'Z2VzdCgpICE9IGV4cGVjdGVkOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW50ZWdyaXR5X2ZhaWxlZCcpCiAgICBy'
    'ZXR1cm4geydieXRlcyc6IHJlY2VpdmVkLCAnZG93bmxvYWRfbWJwcyc6IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xZTYs'
    'IDIpLAogICAgICAgICAgICAnZWxhcHNlZF9tcyc6IHJvdW5kKGVsYXBzZWQqMTAwMCksICdpbnRlZ3JpdHknOiBUcnVlLCAn'
    'bGltaXRlZF9zYW1wbGUnOiBUcnVlfQoKCmRlZiB0b2tlbl9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICB0b2tlbiA9IChS'
    'T09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICB0'
    'b2tlbiA9ICcnCiAgICB2YWxpZCA9IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbikgaXMgbm90IE5vbmUKICAg'
    'IHJldHVybiB7J2hhc190b2tlbic6IHZhbGlkLAogICAgICAgICAgICAndG9rZW5faGludCc6ICdFVk4xLeKAouKAouKAouKA'
    'oiDCtyBJRCAnICsgaGFzaGxpYi5zaGEyNTYodG9rZW4uZW5jb2RlKCkpLmhleGRpZ2VzdCgpWzo4XSBpZiB2YWxpZCBlbHNl'
    'ICcnfQoKCmRlZiBzYXZlX3Rva2VuKHRva2VuKToKICAgIHRva2VuID0gdG9rZW4uc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1'
    'bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0J3Rg9C20LXQvSDRgtC+'
    '0LrQtdC9INC60LvQuNC10L3RgtCwINGE0L7RgNC80LDRgtCwIEVWTjEt4oCmJykKICAgIFJPT1QubWtkaXIobW9kZT0wbzcw'
    'MCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgb2xkID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3Ry'
    'aXAoKSBpZiAoUk9PVC8ndG9rZW4nKS5leGlzdHMoKSBlbHNlICcnCiAgICBpZiBvbGQgPT0gdG9rZW46CiAgICAgICAgcmV0'
    'dXJuCiAgICBpZiBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2lzLWFjdGl2ZScsICctLXF1aWV0JywgVU5JVF0sIGNoZWNrPUZh'
    'bHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQvtGC0LrQ'
    'u9GO0YfQuNGC0LUg0YLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC10LvRjCDQv9C10YDQtdC0INGB0LzQtdC90L7QuSDRgtC+'
    '0LrQtdC90LAuJykKICAgICMgQSBkaWZmZXJlbnQgYWNjb3VudCBuZWVkcyBpdHMgb3duIGRldmljZSBjcmVkZW50aWFscy4g'
    'TmV2ZXIgcmV1c2UgaXRzIGNlcnRpZmljYXRlLgogICAgZm9yIG5hbWUgaW4gKCdkZXZpY2UnLCAnY2xpZW50LWtleS5wZW0n'
    'LCAnY2xpZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdwcml2YXRl'
    'L2NsaWVudC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScpOgogICAgICAgIChST09UL25hbWUpLnVubGluayhtaXNzaW5n'
    'X29rPVRydWUpCiAgICB3cml0ZShST09ULyd0b2tlbicsIHRva2VuKQogICAgc3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB'
    '0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFs'
    'c2UsIG1ldHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1v'
    'ZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4o'
    'dG9rZW4pCiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3Io'
    'J9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQog'
    'ICAgZW5zdXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUoUk9PVC8ncmVjYWxpYnJhdGUn'
    'LCAnMScpCiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBIU1ZEUyBmdWxsLWRldmljZSBFc3Rv'
    'bmlhIFZQTgpBZnRlcj1uZXR3b3JrLnRhcmdldApbU2VydmljZV0KVHlwZT1zaW1wbGUKRXhlY1N0YXJ0PS91c3IvbG9jYWwv'
    'c2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsCkV4ZWNTdG9wUG9zdD0vdXNyL2xvY2FsL3NiaW4vdnBuY3Rs'
    'IGludGVybmFsLXN0YXJmaXZlLXR1bm5lbC1jbGVhbnVwClRpbWVvdXRTdG9wU2VjPTIwCktpbGxNb2RlPW1peGVkClVNYXNr'
    'PTAwNzcKTWVtb3J5TWF4PTI1Nk0KUmVzdGFydD1ubwonJycKICAgIHdyaXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0n'
    'KS9VTklULCB1bml0KQogICAgcmVjb3ZlcnkgPSAiZXZnZW5pdW0tc3RhcmZpdmUtdHVubmVsLXJlY292ZXIuc2VydmljZSIK'
    'ICAgIHdyaXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9yZWNvdmVyeSwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPVJl'
    'Y292ZXIgb25seSBpbnRlcnJ1cHRlZCBFdmdlbml1bSB0dW5uZWwgdGVzdCByZXNvdXJjZXMKRGVmYXVsdERlcGVuZGVuY2ll'
    'cz1ubwpBZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldCB2cG4teHJheS5zZXJ2aWNlCltT'
    'ZXJ2aWNlXQpUeXBlPW9uZXNob3QKRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUt'
    'dHVubmVsLWNsZWFudXAKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CiIiIikKICAgIGNvbW1hbmQoWydz'
    'eXN0ZW1jdGwnLCAnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdlbmFibGUnLCByZWNvdmVy'
    'eV0pCiAgICBzdGFnZSgnc3RhcnRpbmcnICwgJ9CT0L7RgtC+0LLQu9GOINC/0L7QtNC60LvRjtGH0LXQvdC40LUg0YfQtdGA'
    '0LXQtyBIU1ZEUyDQsiDQrdGB0YLQvtC90LjRji4nLCAyLCBhY3RpdmU9RmFsc2UsIHJldHJ5PTAsIGVycm9yX2NvZGU9Jycp'
    'CiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ3Jlc3RhcnQnIGlmIHJlcGFpciBlbHNlICdzdGFydCcsIFVOSVRdKQogICAg'
    'cHJpbnQoJ9Ct0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdGL0LkgVlBOINC30LDQv9GD0YHQutCw0LXRgtGB0Y8uINCt'
    '0YLQsNC/0Ysg0LLQuNC00L3RiyDQsiDRgdGC0YDQvtC60LUg0YHQvtGB0YLQvtGP0L3QuNGPLicpCgoKZGVmIGRpc2Nvbm5l'
    'Y3QoKToKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnc3RvcCcsIFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yNSkK'
    'ICAgIGNsZWFudXAoKQogICAgY2xlYW51cF9mdWxsKHJlbGVhc2U9VHJ1ZSkKICAgIHN0YWdlKCdvZmYnLCAn0K3QutGB0L/Q'
    'tdGA0LjQvNC10L3RgtCw0LvRjNC90YvQuSBWUE4g0LLRi9C60LvRjtGH0LXQvS4nLCAwLCBhY3RpdmU9RmFsc2UpCiAgICBw'
    'cmludCgn0K3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90YvQuSBWUE4g0LLRi9C60LvRjtGH0LXQvS4nKQoKCmRlZiBz'
    'dGFydF9kYWVtb24oZW52KToKICAgIChSVU5USU1FLydjaGFyb24udmljaScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAg'
    'ICBsb2cgPSAoUk9PVC8nY2hhcm9uLmxvZycpLm9wZW4oJ3cnKQogICAgZGFlbW9uID0gc3VicHJvY2Vzcy5Qb3BlbihbJ2lw'
    'JywgJ25ldG5zJywgJ2V4ZWMnLCBOUywgY2hhcm9uX2JpbmFyeSgpXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ZW52PWVudiwgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRvdXQ9bG9nLCBzdGRlcnI9bG9nKQogICAgbG9nLmNsb3Nl'
    'KCkKICAgIGZvciBfIGluIHJhbmdlKDYwKToKICAgICAgICBpZiBTVE9QIG9yIGRhZW1vbi5wb2xsKCkgaXMgbm90IE5vbmU6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZGFlbW9uX3N0b3BwZWQnKQogICAgICAgIGlmIChSVU5USU1FLydj'
    'aGFyb24udmljaScpLmV4aXN0cygpIGFuZCBzd2FuKCctLXN0YXRzJywgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MSkucmV0dXJu'
    'Y29kZSA9PSAwOgogICAgICAgICAgICBicmVhawogICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICBzd2FuKCctLWxvYWQtY3Jl'
    'ZHMnLCAnLS1ub3Byb21wdCcsICctLWZpbGUnLCBST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgc3dhbignLS1sb2FkLWNv'
    'bm5zJywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICByZXR1cm4gZGFlbW9uCgoKZGVmIHdvcmtlcigp'
    'OgogICAgZ2xvYmFsIFNUT1AKICAgIFNUT1AgPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSwgbGFt'
    'YmRhICpfOiBnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLCBUcnVlKSkKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJ'
    'R0lOVCwgbGFtYmRhICpfOiBnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLCBUcnVlKSkKICAgIGRhZW1vbiA9IE5vbmUK'
    'ICAgIHRyeToKICAgICAgICBjbGVhbnVwKCkKICAgICAgICByZWZyZXNoX3JldGFpbmVkX2d1YXJkKCkKICAgICAgICBzdGFn'
    'ZSgncHJlcGFyZScsICfQk9C+0YLQvtCy0LvRjiDQt9Cw0YnQuNGJ0ZHQvdC90L7QtSDRgdC+0LXQtNC40L3QtdC90LjQtSDR'
    'gSBIU1ZEUy4nLCA4LCBhY3RpdmU9RmFsc2UpCiAgICAgICAgc2V0dXBfbmV0d29yaygpCiAgICAgICAgdHJ5OgogICAgICAg'
    'ICAgICByZWZlcmVuY2UgPSAoeydza2lwcGVkJzogJ2d1YXJkX2FjdGl2ZSd9IGlmIGZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxz'
    'ZSByZWZlcmVuY2Vfc2FtcGxlKGZvcmNlPShST09ULydyZWNhbGlicmF0ZScpLmV4aXN0cygpKSkKICAgICAgICBleGNlcHQg'
    'KE9TRXJyb3IsIFJ1bnRpbWVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHJlZmVyZW5jZSA9IHsnYXZhaWxhYmxl'
    'JzogRmFsc2UsICdwcm92aWRlcic6ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInfQogICAgICAgIChST09ULydyZWNhbGlicmF0'
    'ZScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgc3RhZ2UoJ3Rva2VuJywgJ9Cf0YDQvtCy0LXRgNGP0Y4g0YLQ'
    'vtC60LXQvSDQuCDRgdC+0YXRgNCw0L3RkdC90L3QvtC1INC/0L7QtNC60LvRjtGH0LXQvdC40LUg0Y3RgtC+0LPQviDRg9GB'
    '0YLRgNC+0LnRgdGC0LLQsC4nLCAyMCkKICAgICAgICBpZGVudGl0eSwgYWRkcmVzcyA9IGVucm9sbCgpCiAgICAgICAgc2Nv'
    'cGUgPSAncHVibGljLWFkZHJlc3MnCiAgICAgICAgc3RhZ2UoJ2RhZW1vbicsICfQl9Cw0L/Rg9GB0LrQsNGOINGC0YPQvdC9'
    '0LXQu9GMIElLRXYyINCg0L7RgdGB0LjRjyDihpIg0KDQvtGB0YHQuNGPLicsIDQwLCBzY29wZT1zY29wZSkKICAgICAgICBk'
    'YWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcykKICAgICAgICBlbnYgPSB7Kipvcy5lbnZpcm9uLCAnU1RST05HU1dB'
    'Tl9DT05GJzogc3RyKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicpfQogICAgICAgIGVudi5wb3AoJ05PVElGWV9TT0NLRVQnLCBO'
    'b25lKQogICAgICAgIGRhZW1vbiA9IHN0YXJ0X2RhZW1vbihlbnYpCiAgICAgICAgc3RhZ2UoJ2hhbmRzaGFrZScsICfQo9GB'
    '0YLQsNC90LDQstC70LjQstCw0Y4g0LfQsNGJ0LjRidGR0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0YEgSFNWRFMu'
    'JywgNjApCiAgICAgICAgc3dhbignLS1pbml0aWF0ZScsICctLWNoaWxkJywgJ3N0YXJmaXZlLW5ldCcsIHRpbWVvdXQ9MzUp'
    'CiAgICAgICAgaWYgbm90IGluc3RhbGxlZCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3NhX25vdF9pbnN0'
    'YWxsZWQnKQogICAgICAgIHN0YWdlKCdoZWFsdGgnLCAn0J/RgNC+0LLQtdGA0Y/RjiDRgtGD0L3QvdC10LvRjCDQuCDQt9Cw'
    '0YnQuNGJ0ZHQvdC90YvQuSDQvtGC0LLQtdGCINGB0LXRgNCy0LXRgNCwLicsIDc1KQogICAgICAgIGlmIG5vdCBoZWFsdGgo'
    'KToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdoZWFsdGhfZmFpbGVkJykKICAgICAgICBzdGFnZSgnbWVhc3Vy'
    'ZScsICfQn9GA0L7QstC10YDRj9GOINC/0LXRgNC10LTQsNGH0YMg0LTQsNC90L3Ri9GFINC4INGG0LXQu9C+0YHRgtC90L7R'
    'gdGC0Ywg0YTQsNC50LvQsC4nLCA4NSkKICAgICAgICBtZXRyaWNzID0gZG93bmxvYWQoKQogICAgICAgIG1ldHJpY3NbJ3Jl'
    'ZmVyZW5jZSddID0gcmVmZXJlbmNlCiAgICAgICAgc3RhZ2UoJ3JvdXRpbmcnLCAn0J/QvtC00LrQu9GO0YfQsNGOINCy0LXR'
    'gdGMINGC0YDQsNGE0LjQuiDQutC+0LzQv9GM0Y7RgtC10YDQsCDQuiDQstGL0YXQvtC00YMg0LIg0K3RgdGC0L7QvdC40Lgu'
    'JywgOTIpCiAgICAgICAgYWN0aXZhdGVfZnVsbChhZGRyZXNzKQogICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCAn0J/QvtC0'
    '0LrQu9GO0YfQtdC90L46INC60L7QvNC/0YzRjtGC0LXRgCDihpIgSFNWRFMg4oaSINCt0YHRgtC+0L3QuNGPLiBJUHY2INC3'
    '0LDQsdC70L7QutC40YDQvtCy0LDQvS4nLCAxMDAsCiAgICAgICAgICAgICAgYWN0aXZlPVRydWUsIG1ldHJpY3M9bWV0cmlj'
    'cywgc2luY2U9aW50KHRpbWUudGltZSgpKSkKICAgICAgICBmYWlsdXJlcyA9IDAKICAgICAgICB3aGlsZSBub3QgU1RPUDoK'
    'ICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoMTAwKToKICAgICAgICAgICAgICAgIGlmIFNUT1A6CiAgICAgICAgICAgICAg'
    'ICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgICAgIGlmIFNUT1A6CiAgICAgICAg'
    'ICAgICAgICBicmVhawogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBvayA9IGRhZW1vbi5wb2xsKCkgaXMgTm9u'
    'ZSBhbmQgaW5zdGFsbGVkKCkgYW5kIGhlYWx0aCgpCiAgICAgICAgICAgICAgICBpZiBvayBhbmQgbm90IGVncmVzc19oZWFs'
    'dGgoKToKICAgICAgICAgICAgICAgICAgICBzdGFnZSgnZWdyZXNzX3dhaXQnLCAnSFNWRFMg0LTQvtGB0YLRg9C/0LXQvTsg'
    '0L7QttC40LTQsNGOINCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40Y8g0LLRi9GF0L7QtNCwINCyINCt0YHRgtC+0L3QuNC4'
    'LicsIDkwLCBhY3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgZXhjZXB0IChP'
    'U0Vycm9yLCBSdW50aW1lRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgICAgICAgICAgb2sgPSBG'
    'YWxzZQogICAgICAgICAgICBmYWlsdXJlcyA9IDAgaWYgb2sgZWxzZSBmYWlsdXJlcysxCiAgICAgICAgICAgIGlmIGZhaWx1'
    'cmVzID09IDE6CiAgICAgICAgICAgICAgICBzdGFnZSgnY2hlY2tpbmcnLCAn0J7RgtCy0LXRgiBIU1ZEUyDQt9Cw0LTQtdGA'
    '0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgtC10YHRgtC+0LLQvtC1INGB0L7QtdC00LjQvdC10L3QuNC1'
    'LicsIDkwLCBhY3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBpZiBmYWlsdXJlcyA+'
    'PSAyOgogICAgICAgICAgICAgICAgc3RhZ2UoJ3JlcGFpcmluZycsICfQodCy0Y/Qt9GMINGBIEhTVkRTINC/0L7RgtC10YDR'
    'j9C90LAuINCS0L7RgdGB0YLQsNC90LDQstC70LjQstCw0Y4g0YLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC10LvRjC4nLCA2'
    'MCwgYWN0aXZlPUZhbHNlKQogICAgICAgICAgICAgICAgaWYgZGFlbW9uLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAg'
    'ICAgICAgICAgICBpbnNpZGUoWydpcCcsICd4ZnJtJywgJ3N0YXRlJywgJ2ZsdXNoJ10pCiAgICAgICAgICAgICAgICAgICAg'
    'aW5zaWRlKFsnaXAnLCAneGZybScsICdwb2xpY3knLCAnZmx1c2gnXSkKICAgICAgICAgICAgICAgICAgICBpbnNpZGUoWydp'
    'cCcsICdyb3V0ZScsICdmbHVzaCcsICd0YWJsZScsICc1MTgyMiddLCBjaGVjaz1GYWxzZSkKICAgICAgICAgICAgICAgICAg'
    'ICBkYWVtb24gPSBzdGFydF9kYWVtb24oZW52KQogICAgICAgICAgICAgICAgc3dhbignLS10ZXJtaW5hdGUnLCAnLS1pa2Un'
    'LCAnc3RhcmZpdmUnLCBjaGVjaz1GYWxzZSkKICAgICAgICAgICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCAnLS1jaGlsZCcs'
    'ICdzdGFyZml2ZS1uZXQnLCB0aW1lb3V0PTM1KQogICAgICAgICAgICAgICAgaWYgbm90IGluc3RhbGxlZCgpIG9yIG5vdCBo'
    'ZWFsdGgoKToKICAgICAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlY292ZXJ5X2ZhaWxlZCcpCiAgICAg'
    'ICAgICAgICAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAgICAgICAgICAgICAgaWYgbm90IGVncmVzc19oZWFsdGgo'
    'KToKICAgICAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2VzdG9uaWFfZWdyZXNzX2ZhaWxlZCcpCiAgICAg'
    'ICAgICAgICAgICBmYWlsdXJlcyA9IDAKICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsICfQn9C+0LTQutC70Y7Rh9C1'
    '0L3Qvjog0LrQvtC80L/RjNGO0YLQtdGAIOKGkiBIU1ZEUyDihpIg0K3RgdGC0L7QvdC40Y8uIElQdjYg0LfQsNCx0LvQvtC6'
    '0LjRgNC+0LLQsNC9LicsIDEwMCwgYWN0aXZlPVRydWUpCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIFJ1bnRp'
    'bWVFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgIGNvZGUgPSBzdHIoZXhjKSBpZiBy'
    'ZS5mdWxsbWF0Y2gociJbYS16X117MSw2NH0iLCBzdHIoZXhjKSkgZWxzZSB0eXBlKGV4YykuX19uYW1lX18KICAgICAgICBj'
    'dXJyZW50ID0gc2F2ZWQoKS5nZXQoJ3BoYXNlJywgJ3ByZXBhcmUnKQogICAgICAgIG1lc3NhZ2UgPSB7J3Rva2VuJzogJ9Cd'
    '0LUg0YPQtNCw0LvQvtGB0Ywg0L/QvtC00YLQstC10YDQtNC40YLRjCDRgtC+0LrQtdC9INC40LvQuCDQv9C+0LvRg9GH0LjR'
    'gtGMINGB0LXRgNGC0LjRhNC40LrQsNGCIEhTVkRTLicsCiAgICAgICAgICAgICAgICAgICAnaGFuZHNoYWtlJzogJ0hTVkRT'
    'INC90LUg0L/QvtC00YLQstC10YDQtNC40Lsg0L/QvtC00LrQu9GO0YfQtdC90LjQtSBJS0V2Mi4nLAogICAgICAgICAgICAg'
    'ICAgICAgJ21lYXN1cmUnOiAn0J/RgNC+0LLQtdGA0LrQsCDQv9C10YDQtdC00LDRh9C4INC00LDQvdC90YvRhSDQvdC1INC/'
    '0YDQvtGI0LvQsC4nLAogICAgICAgICAgICAgICAgICAgJ3JlcGFpcmluZyc6ICfQkNCy0YLQvtCy0L7RgdGB0YLQsNC90L7Q'
    'stC70LXQvdC40LUg0L3QtSDRg9C00LDQu9C+0YHRjC4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsuJ30u'
    'Z2V0KGN1cnJlbnQsICfQotC10YHRgtC+0LLRi9C5INGC0YPQvdC90LXQu9GMINC90LUg0LfQsNC/0YPRgdGC0LjQu9GB0Y8u'
    'INCd0LDQttC80LjRgtC1IMKr0J/QvtGH0LjQvdC40YLRjMK7LicpCiAgICAgICAgc3RhZ2UoJ2ZhaWxlZCcsIG1lc3NhZ2Ur'
    'KCcg0JjQvdGC0LXRgNC90LXRgiDQt9Cw0LHQu9C+0LrQuNGA0L7QstCw0L0g0LTQviDQvtGC0LrQu9GO0YfQtdC90LjRjyDR'
    'gNC10LbQuNC80LAuJyBpZiBmdWxsX2d1YXJkX2FjdGl2ZSgpIGVsc2UgJyDQnNCw0YDRiNGA0YPRgtC40LfQsNGG0LjRjyDQ'
    'utC+0LzQv9GM0Y7RgtC10YDQsCDQvdC1INC/0LXRgNC10LrQu9GO0YfQtdC90LAuJyksIDAsIGFjdGl2ZT1GYWxzZSwgZXJy'
    'b3JfY29kZT1jb2RlLCBtZXRyaWNzPXt9KQogICAgZmluYWxseToKICAgICAgICBpZiBkYWVtb24gYW5kIGRhZW1vbi5wb2xs'
    'KCkgaXMgTm9uZToKICAgICAgICAgICAgZGFlbW9uLnRlcm1pbmF0ZSgpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAg'
    'ICAgIGRhZW1vbi53YWl0KHRpbWVvdXQ9NikKICAgICAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6'
    'CiAgICAgICAgICAgICAgICBkYWVtb24ua2lsbCgpOyBkYWVtb24ud2FpdCh0aW1lb3V0PTMpCiAgICAgICAgY2xlYW51cCgp'
    'CiAgICAgICAgaWYgU1RPUDoKICAgICAgICAgICAgc3RhZ2UoJ29mZicsICfQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM'
    '0L3Ri9C5IFZQTiDQstGL0LrQu9GO0YfQtdC9LicsIDAsIGFjdGl2ZT1GYWxzZSkK'
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
    'ICIxOTUuMjA5LjIxMS4xNjMiCklLRV9QT1JUID0gMjQ1NTAKSEVBTFRIID0gImh0dHBzOi8vMTAuNzcuMC4xOjg0NDMiClJF'
    'UUlEID0gNzcKRElSRUNUX1BPUlQgPSA4NDQzCkRJUkVDVF9NQVJLID0gMHhFNzcxCkRFTElWRVJZID0gImV2Z2VuaXVtLWlr'
    'ZXYyLWRlbGl2ZXJ5LnNlcnZpY2UiClVTRVJTUEFDRSA9IHBhdGhsaWIuUGF0aCgnL29wdC92cG4tbWFuYWdlci9pa2V2Mi11'
    'c2Vyc3BhY2UnKQpVU0VSU1BBQ0VfVkVSU0lPTiA9ICc2LjEuMC1vcGVuc3NsMy41LjktbXVzbDEuMi42LTEnClVTRVJTUEFD'
    'RV9TSEEyNTYgPSAnZWU2N2VmNjBlZDE3ZDY2NDViZDJmODExY2U2ZmViNjFlYWUwZjljNjkwODI5YTExMGRhZDQ5YTEwMDFh'
    'ZDQzYycKVVNFUlNQQUNFX1VSTCA9ICdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vdmVsaWtpaWV2Z2VuaXVz'
    'dWx0aW1hdGUvRXZnZW5pdW1fTmV0d29ya19MaW51eC9tYWluL2Rpc3Qvc3RhcmZpdmUtdXNlcnNwYWNlLXg4Nl82NC0nICsg'
    'VVNFUlNQQUNFX1ZFUlNJT04gKyAnLnRhci5neicKVFVOID0gJ2lwc2VjMCcKSUtFX01BUksgPSAweEU3NzIKCgpkZWYgYmFj'
    'a2VuZCgpOgogICAgY2hvaWNlPXN0b3JlZCgpLmdldCgnaXBzZWNfYmFja2VuZCcpCiAgICBpZiBjaG9pY2UgaW4gKCdrZXJu'
    'ZWwnLCd1c2Vyc3BhY2UnKTogcmV0dXJuIGNob2ljZQogICAgdHJ5OiBzdGVhbW9zPSdzdGVhbW9zJyBpbiBwYXRobGliLlBh'
    'dGgoJy9ldGMvb3MtcmVsZWFzZScpLnJlYWRfdGV4dCgpLmxvd2VyKCkKICAgIGV4Y2VwdCBPU0Vycm9yOiBzdGVhbW9zPUZh'
    'bHNlCiAgICByZXR1cm4gJ3VzZXJzcGFjZScgaWYgc3RlYW1vcyBlbHNlICdrZXJuZWwnCgoKZGVmIHVzZXJzcGFjZV9yZWFk'
    'eSgpOgogICAgdHJ5OgogICAgICAgIG1hbmlmZXN0PWpzb24ubG9hZHMoKFVTRVJTUEFDRS8nQlVJTEQuanNvbicpLnJlYWRf'
    'dGV4dCgpKQogICAgICAgIHJldHVybiBtYW5pZmVzdC5nZXQoJ3ZlcnNpb24nKT09VVNFUlNQQUNFX1ZFUlNJT04gYW5kIGFs'
    'bCgKICAgICAgICAgICAgKFVTRVJTUEFDRS9uYW1lKS5pc19maWxlKCkgYW5kIG9zLmFjY2VzcyhVU0VSU1BBQ0UvbmFtZSxv'
    'cy5YX09LKQogICAgICAgICAgICBmb3IgbmFtZSBpbiAoJ2NoYXJvbicsJ3N3YW5jdGwnKSkKICAgIGV4Y2VwdCAoT1NFcnJv'
    'cixWYWx1ZUVycm9yKTogcmV0dXJuIEZhbHNlCgoKZGVmIGF2YWlsYWJsZSgpOgogICAgcmV0dXJuIHVzZXJzcGFjZV9yZWFk'
    'eSgpIGlmIGJhY2tlbmQoKT09J3VzZXJzcGFjZScgZWxzZSBib29sKHNodXRpbC53aGljaCgnc3dhbmN0bCcpKQoKCmRlZiB2'
    'YWxpZF90dW4oKToKICAgIHRyeTogcmV0dXJuIGJvb2woaW50KHBhdGhsaWIuUGF0aCgnL3N5cy9jbGFzcy9uZXQnLFRVTiwn'
    'dHVuX2ZsYWdzJykucmVhZF90ZXh0KCkuc3RyaXAoKSwxNikmMSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTog'
    'cmV0dXJuIEZhbHNlCgoKZGVmIHNlbGVjdF9iYWNrZW5kKHZhbHVlKToKICAgIGlmIGFjdGl2ZV9ndWFyZCgpIG9yIGNvbm5l'
    'Y3RlZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0LLRi9C60LvRjtGH0Lgg0Y3QutGB'
    '0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90L7QtSDQv9C+0LTQutC70Y7Rh9C10L3QuNC1LicpCiAgICBwYXRjaF9zdGF0ZSh7'
    'J2lwc2VjX2JhY2tlbmQnOnZhbHVlfSkKICAgIHByaW50KCfQktGL0LHRgNCw0L0g0YDQtdC20LjQvDogJysoJ0lQc2VjINGH'
    '0LXRgNC10LcgVFVOJyBpZiB2YWx1ZT09J3VzZXJzcGFjZScgZWxzZSAnSVBzZWMg0LIg0Y/QtNGA0LUnKSkKCgpkZWYgaW5z'
    'dGFsbF91c2Vyc3BhY2UoKToKICAgIGlmIHVzZXJzcGFjZV9yZWFkeSgpOiByZXR1cm4KICAgIGlmIGFjdGl2ZV9ndWFyZCgp'
    'OiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINCy0YvQutC70Y7Rh9C4INGN0LrRgdC/0LXRgNC40LzQtdC9'
    '0YLQsNC70YzQvdGL0Lkg0YDQtdC20LjQvCwg0LfQsNGC0LXQvCDQv9C+0LTQs9C+0YLQvtCy0Ywg0LTQstC40LbQvtC6Licp'
    'CiAgICBpZiBwbGF0Zm9ybS5tYWNoaW5lKCkubG93ZXIoKSBub3QgaW4gKCd4ODZfNjQnLCdhbWQ2NCcpOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcign0JDQstGC0L7QvdC+0LzQvdGL0Lkg0LTQstC40LbQvtC6INC/0L7QutCwINGB0L7QsdGA0LDQ'
    'vSDRgtC+0LvRjNC60L4g0LTQu9GPIHg4Nl82NCAoU3RlYW0gRGVjaykuJykKICAgIG9wZW5lcj11cmxsaWIucmVxdWVzdC5i'
    'dWlsZF9vcGVuZXIodXJsbGliLnJlcXVlc3QuUHJveHlIYW5kbGVyKHt9KSkKICAgIHdpdGggb3BlbmVyLm9wZW4oVVNFUlNQ'
    'QUNFX1VSTCx0aW1lb3V0PTQ1KSBhcyByZXNwb25zZTogYmxvYj1yZXNwb25zZS5yZWFkKDMyKjEwMjQqMTAyNCsxKQogICAg'
    'aWYgbGVuKGJsb2IpPjMyKjEwMjQqMTAyNCBvciBoYXNobGliLnNoYTI1NihibG9iKS5oZXhkaWdlc3QoKSE9VVNFUlNQQUNF'
    'X1NIQTI1NjoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Ca0L7QvdGC0YDQvtC70YzQvdCw0Y8g0YHRg9C80LzQsCDQ'
    'sNCy0YLQvtC90L7QvNC90L7Qs9C+INC00LLQuNC20LrQsCDQvdC1INGB0L7QstC/0LDQu9CwLicpCiAgICBpbnN0YWxsX3Vz'
    'ZXJzcGFjZV9hcmNoaXZlKGJsb2IpCgoKZGVmIGluc3RhbGxfdXNlcnNwYWNlX2FyY2hpdmUoYmxvYik6CiAgICBleHBlY3Rl'
    'ZD17J2NoYXJvbicsJ3N3YW5jdGwnLCdCVUlMRC5qc29uJywnTElDRU5TRS5zdHJvbmdzd2FuJywnTElDRU5TRS5vcGVuc3Ns'
    'JywnTElDRU5TRS5tdXNsJ30KICAgIHdpdGggdGFyZmlsZS5vcGVuKGZpbGVvYmo9aW8uQnl0ZXNJTyhibG9iKSxtb2RlPSdy'
    'Omd6JykgYXMgYXJjaGl2ZToKICAgICAgICBtZW1iZXJzPWFyY2hpdmUuZ2V0bWVtYmVycygpCiAgICAgICAgaWYgbGVuKG1l'
    'bWJlcnMpIT1sZW4oZXhwZWN0ZWQpIG9yIHt4Lm5hbWUgZm9yIHggaW4gbWVtYmVyc30hPWV4cGVjdGVkOgogICAgICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90YvQuSDRgdC+0YHRgtCw0LIg0LDQstGC0L7QvdC+'
    '0LzQvdC+0LPQviDQtNCy0LjQttC60LAuJykKICAgICAgICBpZiBzdW0oeC5zaXplIGZvciB4IGluIG1lbWJlcnMpPjQ4KjEw'
    'MjQqMTAyNCBvciBhbnkobm90IHguaXNmaWxlKCkgb3IgeC5zaXplPjMyKjEwMjQqMTAyNCBmb3IgeCBpbiBtZW1iZXJzKToK'
    'ICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQndC10LHQtdC30L7Qv9Cw0YHQvdGL0Lkg0LDRgNGF0LjQsiDQsNCy'
    '0YLQvtC90L7QvNC90L7Qs9C+INC00LLQuNC20LrQsC4nKQogICAgICAgIG1ldGFkYXRhPWpzb24ubG9hZChhcmNoaXZlLmV4'
    'dHJhY3RmaWxlKCdCVUlMRC5qc29uJykpCiAgICAgICAgaWYgbWV0YWRhdGEuZ2V0KCd2ZXJzaW9uJykhPVVTRVJTUEFDRV9W'
    'RVJTSU9OOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90LDRjyDQstC10YDRgdC40Y8g0LTQstC4'
    '0LbQutCwLicpCiAgICAgICAgVVNFUlNQQUNFLm1rZGlyKHBhcmVudHM9VHJ1ZSxtb2RlPTBvNzU1LGV4aXN0X29rPVRydWUp'
    'CiAgICAgICAgZm9yIG1lbWJlciBpbiBtZW1iZXJzOgogICAgICAgICAgICB0YXJnZXQ9VVNFUlNQQUNFL21lbWJlci5uYW1l'
    'CiAgICAgICAgICAgIGlmIHRhcmdldC5pc19zeW1saW5rKCk6IHJhaXNlIFJ1bnRpbWVFcnJvcign0J3QtdC00L7Qv9GD0YHR'
    'gtC40LzQsNGPINGB0YHRi9C70LrQsCDQsiDQutCw0YLQsNC70L7Qs9C1INC00LLQuNC20LrQsC4nKQogICAgICAgICAgICB0'
    'ZW1wPXRhcmdldC53aXRoX3N1ZmZpeCh0YXJnZXQuc3VmZml4KycubmV3JykKICAgICAgICAgICAgZmQ9b3Mub3Blbih0ZW1w'
    'LG9zLk9fV1JPTkxZfG9zLk9fQ1JFQVR8b3MuT19UUlVOQ3xvcy5PX05PRk9MTE9XLDBvNjAwKQogICAgICAgICAgICB3aXRo'
    'IG9zLmZkb3BlbihmZCwnd2InKSBhcyBmOiBmLndyaXRlKGFyY2hpdmUuZXh0cmFjdGZpbGUobWVtYmVyKS5yZWFkKCkpCiAg'
    'ICAgICAgICAgIHRlbXAuY2htb2QoMG83NTUgaWYgbWVtYmVyLm5hbWUgaW4gKCdjaGFyb24nLCdzd2FuY3RsJykgZWxzZSAw'
    'bzY0NCkKICAgICAgICAgICAgdGVtcC5yZXBsYWNlKHRhcmdldCkKCgpkZWYgZmFpbHVyZV9jb2RlKGV4Yyk6CiAgICB0ZXh0'
    'ID0gc3RyKGV4YykubG93ZXIoKQogICAgaWYgaXNpbnN0YW5jZShleGMsIHNzbC5TU0xDZXJ0VmVyaWZpY2F0aW9uRXJyb3Ip'
    'OiByZXR1cm4gJ2NlcnRpZmljYXRlJwogICAgaWYgaXNpbnN0YW5jZShleGMsIHNzbC5TU0xFcnJvcik6IHJldHVybiAndGxz'
    'JwogICAgaWYgaXNpbnN0YW5jZShleGMsIChUaW1lb3V0RXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpKTogcmV0'
    'dXJuICd0aW1lb3V0JwogICAgaWYgJ3VuYWJsZSB0byBpbnN0YWxsJyBpbiB0ZXh0IGFuZCAnaXBzZWMgc2EnIGluIHRleHQ6'
    'IHJldHVybiAna2VybmVsX2lwc2VjX3VuYXZhaWxhYmxlJwogICAgaWYgcmUuc2VhcmNoKHIiYXV0aGVudGljYXRpb25bXlxu'
    'XSooZmFpbGVkfGZhaWx1cmUpIix0ZXh0KTogcmV0dXJuICdhdXRoZW50aWNhdGlvbicKICAgIGlmICdwcm9wb3NhbCcgaW4g'
    'dGV4dDogcmV0dXJuICdwcm9wb3NhbCcKICAgIGlmICdyZXRyYW5zbWl0JyBpbiB0ZXh0IG9yICd0aW1lZCBvdXQnIGluIHRl'
    'eHQ6IHJldHVybiAndGltZW91dCcKICAgIGlmICdwZXJtaXNzaW9uJyBpbiB0ZXh0IG9yICdvcGVyYXRpb24gbm90IHBlcm1p'
    'dHRlZCcgaW4gdGV4dDogcmV0dXJuICdwZXJtaXNzaW9uJwogICAgaWYgaXNpbnN0YW5jZShleGMsIE9TRXJyb3IpOiByZXR1'
    'cm4gJ25ldHdvcmsnCiAgICByZXR1cm4gJ290aGVyJwoKCmRlZiBxdWV1ZV9jb25uZWN0aW9uKHN0YWdlLCBlcnJvciwgZWxh'
    'cHNlZD0wKToKICAgIGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOiByZXR1cm4KICAgIGRpcmVjdG9yeSA9IFJP'
    'T1QgLyAnb3V0Ym94JwogICAgZGlyZWN0b3J5Lm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1'
    'ZSkKICAgIGZpbGVzID0gc29ydGVkKGRpcmVjdG9yeS5nbG9iKCcqLmpzb24nKSwga2V5PWxhbWJkYSBwOiBwLnN0YXQoKS5z'
    'dF9tdGltZSkKICAgIGZvciBvbGQgaW4gZmlsZXNbOi05XTogb2xkLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICByZXBv'
    'cnRfaWQgPSB1dWlkLnV1aWQ0KCkuaGV4CiAgICBib2R5ID0geydzY2hlbWEnOjEsICdldmVudCc6J2Nvbm5lY3Rpb25fZGlh'
    'Z25vc3RpYycsICdtYW5hZ2VyJzonMC4yLjIzJywKICAgICAgICAgICAgJ3RpbWUnOmludCh0aW1lLnRpbWUoKSksCiAgICAg'
    'ICAgICAgICdyZXBvcnRfaWQnOnJlcG9ydF9pZCwgJ3N0YWdlJzpzdGFnZSwgJ2Vycm9yJzplcnJvciwKICAgICAgICAgICAg'
    'J2VsYXBzZWRfbXMnOm1pbigxODAwMDAwLCBtYXgoMCwgaW50KGVsYXBzZWQpKSksCiAgICAgICAgICAgICdndWFyZCc6YWN0'
    'aXZlX2d1YXJkKCksICdpcHNlYyc6Y29ubmVjdGVkKCksICdpcHNlY19iYWNrZW5kJzpiYWNrZW5kKCl9CiAgICB0cnk6CiAg'
    'ICAgICAgIyBTZW5kIGNvdW50cyBhbmQgZml4ZWQgY2F0ZWdvcmllcywgbmV2ZXIgcmF3IGpvdXJuYWwgbGluZXMgb3IgYWRk'
    'cmVzc2VzLgogICAgICAgIGpvdXJuYWw9Y21kKFsnam91cm5hbGN0bCcsJy11JyxVTklULCctLXNpbmNlJywnMiBtaW51dGVz'
    'IGFnbycsJy1uJywnODAnLCctLW5vLXBhZ2VyJ10sY2hlY2s9RmFsc2UsdGltZW91dD0zKS5zdGRvdXQubG93ZXIoKQogICAg'
    'ICAgIGJvZHkudXBkYXRlKGlrZV9yZWNlaXZlZD1qb3VybmFsLmNvdW50KCdyZWNlaXZlZCBwYWNrZXQ6JyksCiAgICAgICAg'
    'ICAgICAgICAgICAgaWtlX3NlbnQ9am91cm5hbC5jb3VudCgnc2VuZGluZyBwYWNrZXQ6JyksCiAgICAgICAgICAgICAgICAg'
    'ICAgcmV0cmFuc21pdHM9am91cm5hbC5jb3VudCgncmV0cmFuc21pdCcpKQogICAgICAgIGlmIGVycm9yICE9ICdub25lJzoK'
    'ICAgICAgICAgICAgaWYgJ3VuYWJsZSB0byBpbnN0YWxsIGluYm91bmQgYW5kIG91dGJvdW5kIGlwc2VjIHNhJyBpbiBqb3Vy'
    'bmFsOiBib2R5WydlcnJvciddPSdrZXJuZWxfaXBzZWNfdW5hdmFpbGFibGUnCiAgICAgICAgICAgIGVsaWYgcmUuc2VhcmNo'
    'KHInYXV0aGVudGljYXRpb25bXlxuXSooZmFpbGVkfGZhaWx1cmUpJyxqb3VybmFsKTogYm9keVsnZXJyb3InXT0nYXV0aGVu'
    'dGljYXRpb24nCiAgICAgICAgICAgIGVsaWYgJ25vIHByb3Bvc2FsJyBpbiBqb3VybmFsOiBib2R5WydlcnJvciddPSdwcm9w'
    'b3NhbCcKICAgICAgICBvc19yZWxlYXNlPXBhdGhsaWIuUGF0aCgnL2V0Yy9vcy1yZWxlYXNlJykucmVhZF90ZXh0KCkubG93'
    'ZXIoKQogICAgICAgIGJvZHlbJ3BsYXRmb3JtJ109J3N0ZWFtb3MnIGlmICdzdGVhbW9zJyBpbiBvc19yZWxlYXNlIGVsc2Ug'
    'KCdmZWRvcmEnIGlmICdmZWRvcmEnIGluIG9zX3JlbGVhc2UgZWxzZSAoJ2FyY2gnIGlmICdhcmNoJyBpbiBvc19yZWxlYXNl'
    'IGVsc2UgJ290aGVyJykpCiAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICB3cml0ZShkaXJlY3RvcnkgLyAocmVwb3J0'
    'X2lkICsgJy5qc29uJyksIGpzb24uZHVtcHMoYm9keSkpCiAgICBwYXRjaF9zdGF0ZSh7ICdkZWxpdmVyeV9zdGF0dXMnOidx'
    'dWV1ZWQnLCAnZGVsaXZlcnlfZXJyb3InOicnfSkKICAgIGtpY2tfZGVsaXZlcnkoKQoKCmRlZiBraWNrX2RlbGl2ZXJ5KCk6'
    'CiAgICBpZiBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JywnLS1u'
    'by1ibG9jaycsREVMSVZFUlldLCBjaGVjaz1GYWxzZSkKCgpkZWYgZGlyZWN0X2VuZHBvaW50KGJvZHkpOgogICAgUk9PVC5t'
    'a2Rpcihtb2RlPTBvNzAwLHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd2l0aCAoUk9PVC8iZGVsaXZlcnkubG9j'
    'ayIpLm9wZW4oImEiKSBhcyBsb2NrOgogICAgICAgIGZjbnRsLmZsb2NrKGxvY2ssZmNudGwuTE9DS19FWCkKICAgICAgICBy'
    'ZXR1cm4gX2RpcmVjdF9lbmRwb2ludChib2R5KQoKCmRlZiBfZGlyZWN0X2VuZHBvaW50KGJvZHkpOgogICAgIyBPbmx5IHRo'
    'aXMgcm9vdC1vd25lZCBzb2NrZXQgY2FuIGJ5cGFzcyB0aGUgZ3VhcmQ7IG5ldmVyIGVudmlyb25tZW50IHByb3hpZXMuCiAg'
    'ICAjIFRoZSBtYXJrZWQgc29ja2V0IHNlbGVjdHMgdGhlIHBoeXNpY2FsIHJvdXRlIGJlZm9yZSBJUHNlYyBzb3VyY2Ugc2Vs'
    'ZWN0aW9uLgogICAgc29jayA9IE5vbmUKICAgIGNvbm5lY3Rpb24gPSBOb25lCiAgICBzdGFnZSA9ICdjcmVkZW50aWFscycK'
    'ICAgIHRyeToKICAgICAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FmaWxlPXN0cihST09UIC8g'
    'J2NhLnBlbScpKQogICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09UIC8gJ2NsaWVudC5wZW0nKSxzdHIo'
    'Uk9PVCAvICdjbGllbnQta2V5LnBlbScpKQogICAgICAgIHN0YWdlID0gJ3JvdXRlJwogICAgICAgIHJ1bGU9Wydwcmlvcml0'
    'eScsJzkwJywnZndtYXJrJyxzdHIoRElSRUNUX01BUkspLCd0bycsU0VSVkVSKycvMzInLCdsb29rdXAnLCdtYWluJ10KICAg'
    'ICAgICAjIENsZWFuIHVwIGFuIGV4YWN0IHN0YWxlIHJ1bGUgbGVmdCBieSBwcm9jZXNzIHRlcm1pbmF0aW9uIGJlZm9yZSBh'
    'ZGRpbmcgaXQuCiAgICAgICAgY21kKFsnaXAnLCdydWxlJywnZGVsJywqcnVsZV0sY2hlY2s9RmFsc2UpCiAgICAgICAgY21k'
    'KFsnaXAnLCdydWxlJywnYWRkJywqcnVsZV0pCiAgICAgICAgc29jayA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQs'
    'IHNvY2tldC5TT0NLX1NUUkVBTSkKICAgICAgICBzdGFnZSA9ICd0Y3AnCiAgICAgICAgc29jay5zZXR0aW1lb3V0KDYpCiAg'
    'ICAgICAgc29jay5zZXRzb2Nrb3B0KHNvY2tldC5TT0xfU09DS0VULCBzb2NrZXQuU09fTUFSSywgRElSRUNUX01BUkspCiAg'
    'ICAgICAgc29jay5jb25uZWN0KChTRVJWRVIsRElSRUNUX1BPUlQpKQogICAgICAgIHN0YWdlID0gJ3RscycKICAgICAgICB0'
    'bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssc2VydmVyX2hvc3RuYW1lPVNFUlZFUikKICAgICAgICBjb25uZWN0aW9u'
    'ID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oU0VSVkVSLERJUkVDVF9QT1JULHRpbWVvdXQ9NikKICAgICAgICBjb25u'
    'ZWN0aW9uLnNvY2sgPSB0bHMKICAgICAgICBzdGFnZSA9ICdodHRwJwogICAgICAgIGRhdGEgPSBqc29uLmR1bXBzKGJvZHks'
    'c2VwYXJhdG9ycz0oJywnLCc6JykpLmVuY29kZSgpCiAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdQT1NUJywnL3JlcG9y'
    'dCcsYm9keT1kYXRhLAogICAgICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJzPXsnQ29udGVudC1UeXBlJzonYXBwbGlj'
    'YXRpb24vanNvbicsJ0Nvbm5lY3Rpb24nOidjbG9zZSd9KQogICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlvbi5nZXRyZXNw'
    'b25zZSgpCiAgICAgICAgcmVwbHkgPSBqc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQoNDA5NikpCiAgICAgICAgaWYgcmVzcG9u'
    'c2Uuc3RhdHVzICE9IDIwMCBvciByZXBseS5nZXQoJ2FjY2VwdGVkJykgaXMgbm90IFRydWU6CiAgICAgICAgICAgIGVycm9y'
    'PVJ1bnRpbWVFcnJvcignUmVwb3J0IHJlamVjdGVkJykKICAgICAgICAgICAgZXJyb3IuZGVsaXZlcnlfY29kZT17NDAzOidk'
    'aXNhYmxlZCcsNDAwOidpbnZhbGlkX3JlcG9ydCd9LmdldChyZXNwb25zZS5zdGF0dXMsJ3JlamVjdGVkJykKICAgICAgICAg'
    'ICAgcmFpc2UgZXJyb3IKICAgICAgICBpZiBib2R5LmdldCgncmVwb3J0X2lkJykgYW5kIHJlcGx5LmdldCgncmVwb3J0X2lk'
    'JykgIT0gYm9keVsncmVwb3J0X2lkJ106CiAgICAgICAgICAgIGVycm9yPVJ1bnRpbWVFcnJvcignQWNrbm93bGVkZ2VtZW50'
    'IG1pc21hdGNoJykKICAgICAgICAgICAgZXJyb3IuZGVsaXZlcnlfY29kZT0nYWNrX21pc21hdGNoJwogICAgICAgICAgICBy'
    'YWlzZSBlcnJvcgogICAgICAgIHJldHVybiByZXBseQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgcGF0'
    'Y2hfc3RhdGUoeyAnZGVsaXZlcnlfc3RhdHVzJzoncmV0cnknLAogICAgICAgICAgICAgICdkZWxpdmVyeV9lcnJvcic6c3Rh'
    'Z2UrJ18nK2dldGF0dHIoZXhjLCdkZWxpdmVyeV9jb2RlJyxmYWlsdXJlX2NvZGUoZXhjKSl9KQogICAgICAgIHJhaXNlCiAg'
    'ICBmaW5hbGx5OgogICAgICAgIGlmIGNvbm5lY3Rpb246IGNvbm5lY3Rpb24uY2xvc2UoKQogICAgICAgIGlmIHNvY2s6IHNv'
    'Y2suY2xvc2UoKQogICAgICAgICMgUmVtb3ZlIG91ciBleGFjdCBzY29wZWQgcnVsZSwgaW5jbHVkaW5nIG9uIGZhaWxlZCBU'
    'Q1AvVExTIGhhbmRzaGFrZXMuCiAgICAgICAgY21kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc5MCcsJ2Z3bWFy'
    'aycsc3RyKERJUkVDVF9NQVJLKSwKICAgICAgICAgICAgICd0bycsU0VSVkVSKycvMzInLCdsb29rdXAnLCdtYWluJ10sY2hl'
    'Y2s9RmFsc2UpCgoKZGVmIGRlbGl2ZXJfcmVwb3J0KGJvZHkpOgogICAgaWYgbm90IHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5'
    'Jyk6IHJldHVybiBGYWxzZQogICAgcGF0Y2hfc3RhdGUoeyAnZGVsaXZlcnlfc3RhdHVzJzonc2VuZGluZycsICdkZWxpdmVy'
    'eV9hdHRlbXB0JzppbnQodGltZS50aW1lKCkpfSkKICAgIGJvZHk9eyoqYm9keSwgJ3ByZXZpb3VzX2RlbGl2ZXJ5X2Vycm9y'
    'JzpzdG9yZWQoKS5nZXQoJ2RlbGl2ZXJ5X2Vycm9yJywnJyl9CiAgICBkaXJlY3RfZW5kcG9pbnQoYm9keSkKICAgIHBhdGNo'
    'X3N0YXRlKHsgJ2RlbGl2ZXJ5X3N0YXR1cyc6J3NlbnQnLCAnZGVsaXZlcnlfZXJyb3InOicnLAogICAgICAgICAgJ2xhc3Rf'
    'cmVwb3J0Jzp0aW1lLnN0cmZ0aW1lKCclWS0lbS0lZCAlSDolTTolUyBVVEMnLHRpbWUuZ210aW1lKCkpfSkKICAgIHJldHVy'
    'biBUcnVlCgoKZGVmIGRlbGl2ZXJ5X3dvcmtlcigpOgogICAgZGVsYXk9MTUKICAgIHdoaWxlIHN0b3JlZCgpLmdldCgndGVs'
    'ZW1ldHJ5Jyk6CiAgICAgICAgZmlsZXM9bGlzdCgoUk9PVC8nb3V0Ym94JykuZ2xvYignKi5qc29uJykpCiAgICAgICAgaWYg'
    'bm90IGZpbGVzIGFuZCBub3QgUEVORElOR19URVNULmV4aXN0cygpOiByZXR1cm4KICAgICAgICB0cnk6CiAgICAgICAgICAg'
    'IGZvciBwYXRoIGluIGZpbGVzOgogICAgICAgICAgICAgICAgaWYgZGVsaXZlcl9yZXBvcnQoanNvbi5sb2FkcyhwYXRoLnJl'
    'YWRfdGV4dCgpKSk6IHBhdGgudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgICAgICAgICAgZmx1c2hfdGVzdF9yZXBvcnQo'
    'KQogICAgICAgICAgICBkZWxheT0xNQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHRpbWUuc2xlZXAo'
    'ZGVsYXkpCiAgICAgICAgICAgIGRlbGF5PW1pbihkZWxheSoyLDMwMCkKCgpkZWYgY21kKGFyZ3MsIGNoZWNrPVRydWUsIHRp'
    'bWVvdXQ9MjAsIGRhdGE9Tm9uZSk6CiAgICBjcCA9IHN1YnByb2Nlc3MucnVuKFtzdHIoeCkgZm9yIHggaW4gYXJnc10sIGlu'
    'cHV0PWRhdGEsIHRleHQ9VHJ1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwgc3Rk'
    'ZXJyPXN1YnByb2Nlc3MuUElQRSwgdGltZW91dD10aW1lb3V0KQogICAgaWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6CiAg'
    'ICAgICAgcmFpc2UgUnVudGltZUVycm9yKChjcC5zdGRlcnIgb3IgY3Auc3Rkb3V0IG9yICJjb21tYW5kIGZhaWxlZCIpWy0x'
    'MjAwOl0pCiAgICByZXR1cm4gY3AKCgpkZWYgd3JpdGUocGF0aCwgZGF0YSwgbW9kZT0wbzYwMCk6CiAgICBwYXRoID0gcGF0'
    'aGxpYi5QYXRoKHBhdGgpCiAgICBwYXRoLnBhcmVudC5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29r'
    'PVRydWUpCiAgICB0bXAgPSBwYXRoLndpdGhfc3VmZml4KHBhdGguc3VmZml4ICsgIi5uZXciKQogICAgZmQgPSBvcy5vcGVu'
    'KHRtcCwgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIG1vZGUpCiAgICB3'
    'aXRoIG9zLmZkb3BlbihmZCwgInciKSBhcyBmOgogICAgICAgIGYud3JpdGUoZGF0YSkKICAgIHRtcC5jaG1vZChtb2RlKQog'
    'ICAgdG1wLnJlcGxhY2UocGF0aCkKCgpkZWYgc3RvcmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMo'
    'U1RBVEUucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoK'
    'CmRlZiBzYXZlKHN0YXRlKToKICAgIHdyaXRlKFNUQVRFLCBqc29uLmR1bXBzKHN0YXRlLCBlbnN1cmVfYXNjaWk9RmFsc2Up'
    'ICsgIlxuIikKCgpkZWYgcGF0Y2hfc3RhdGUoY2hhbmdlcyk6CiAgICAjIEtlZXAgc2VuZGVyIHVwZGF0ZXMgZnJvbSBvdmVy'
    'd3JpdGluZyBhIGNvbmN1cnJlbnQgdGVsZW1ldHJ5LW9mZiBvcGVyYXRpb24uCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAs'
    'cGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgICB3aXRoIChST09ULydzdGF0ZS5sb2NrJykub3BlbignYScpIGFzIGxv'
    'Y2s6CiAgICAgICAgZmNudGwuZmxvY2sobG9jayxmY250bC5MT0NLX0VYKQogICAgICAgIHNhdmUoeyoqc3RvcmVkKCksKipj'
    'aGFuZ2VzfSkKCgpkZWYgYWN0aXZlX2d1YXJkKCk6CiAgICBpZiBub3Qgc2h1dGlsLndoaWNoKCJuZnQiKToKICAgICAgICBy'
    'ZXR1cm4gRmFsc2UKICAgIHJldHVybiBjbWQoWyJuZnQiLCAibGlzdCIsICJ0YWJsZSIsICJpbmV0IiwgVEFCTEVdLCBjaGVj'
    'az1GYWxzZSkucmV0dXJuY29kZSA9PSAwCgoKZGVmIHN3YW4oKmFyZ3MsIGNoZWNrPVRydWUsIHRpbWVvdXQ9MjApOgogICAg'
    'YmluYXJ5ID0gc3RyKFVTRVJTUEFDRS8ic3dhbmN0bCIpIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSIgZWxzZSAoc2h1dGls'
    'LndoaWNoKCJzd2FuY3RsIikgb3IgIi91c3Ivc2Jpbi9zd2FuY3RsIikKICAgIHJldHVybiBjbWQoW2JpbmFyeSwgKmFyZ3Ms'
    'ICItLXVyaSIsIFVSSV0sIGNoZWNrPWNoZWNrLCB0aW1lb3V0PXRpbWVvdXQpCgoKZGVmIGNvbm5lY3RlZCgpOgogICAgaWYg'
    'bm90IFJVTlRJTUUuam9pbnBhdGgoImNoYXJvbi52aWNpIikuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICB0'
    'cnk6CiAgICAgICAgY3AgPSBzd2FuKCItLWxpc3Qtc2FzIiwgIi0tcmF3IiwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MykKICAg'
    'ICAgICByZXR1cm4gKGNwLnJldHVybmNvZGUgPT0gMCBhbmQgInN0YXRlPUlOU1RBTExFRCIgaW4gY3Auc3Rkb3V0IGFuZCAi'
    'c3RhdGU9RVNUQUJMSVNIRUQiIGluIGNwLnN0ZG91dAogICAgICAgICAgICAgICAgYW5kIChiYWNrZW5kKCkhPSd1c2Vyc3Bh'
    'Y2UnIG9yIHZhbGlkX3R1bigpKSkKICAgIGV4Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAg'
    'ICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIHdhaXRfdXNlcnNwYWNlKCk6CiAgICBpZiBiYWNrZW5kKCkhPSd1c2Vyc3BhY2Un'
    'OiByZXR1cm4KICAgIGZvciBfIGluIHJhbmdlKDUwKToKICAgICAgICBpZiB2YWxpZF90dW4oKToKICAgICAgICAgICAgdHJ5'
    'OgogICAgICAgICAgICAgICAgaWYgc3dhbignLS1zdGF0cycsY2hlY2s9RmFsc2UsdGltZW91dD0xKS5yZXR1cm5jb2RlPT0w'
    'OiByZXR1cm4KICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOiBwYXNzCiAg'
    'ICAgICAgdGltZS5zbGVlcCguMSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignVFVOLdC00LLQuNC20L7QuiDQvdC1INGB0L7Q'
    't9C00LDQuyDRgdC+0LHRgdGC0LLQtdC90L3Ri9C5INC40L3RgtC10YDRhNC10LnRgSDQuCBWSUNJLdGB0L7QutC10YIuJykK'
    'CgpkZWYgc3RhdHVzKCk6CiAgICBzdGF0ZSA9IHN0b3JlZCgpCiAgICBndWFyZCA9IGFjdGl2ZV9ndWFyZCgpCiAgICBsaXZl'
    'ID0gY29ubmVjdGVkKCkKICAgIHRva2VuX3N0YXRlID0gdHVubmVsLnN0YXR1cygpIGlmIHR1bm5lbCBlbHNlIHt9CiAgICBp'
    'ZiB0b2tlbl9zdGF0ZS5nZXQoJ2d1YXJkJyk6CiAgICAgICAgZ3VhcmQgPSBUcnVlCiAgICAgICAgbGl2ZSA9IHRva2VuX3N0'
    'YXRlLmdldCgnYWN0aXZlJywgRmFsc2UpCiAgICByZXR1cm4geyJ0dW5uZWwiOiB0b2tlbl9zdGF0ZSwKICAgICAgICAgICAg'
    'ImNvbmZpZ3VyZWQiOiBST09ULmpvaW5wYXRoKCJwcm9maWxlLmpzb24iKS5leGlzdHMoKSwKICAgICAgICAgICAgImF2YWls'
    'YWJsZSI6IGF2YWlsYWJsZSgpLCAiaXBzZWNfYmFja2VuZCI6YmFja2VuZCgpLCAidXNlcnNwYWNlX3ZlcnNpb24iOlVTRVJT'
    'UEFDRV9WRVJTSU9OLAogICAgICAgICAgICAiYWN0aXZlIjogbGl2ZSwgImd1YXJkIjogZ3VhcmQsCiAgICAgICAgICAgICJ0'
    'ZWxlbWV0cnkiOiBib29sKHN0YXRlLmdldCgidGVsZW1ldHJ5IiwgRmFsc2UpKSwKICAgICAgICAgICAgInBoYXNlIjogImNv'
    'bm5lY3RlZCIgaWYgbGl2ZSBlbHNlICgiYmxvY2tlZCIgaWYgZ3VhcmQgZWxzZSAib2ZmIiksCiAgICAgICAgICAgICJzZXJ2'
    'ZXIiOiBTRVJWRVIsICJlZ3Jlc3MiOiAi0K3RgdGC0L7QvdC40Y8g0YfQtdGA0LXQtyBIU1ZEUyIsCiAgICAgICAgICAgICJs'
    'YXN0X3JlcG9ydCI6IHN0YXRlLmdldCgibGFzdF9yZXBvcnQiLCAiIiksCiAgICAgICAgICAgICJsYXN0X2Vycm9yIjogc3Rh'
    'dGUuZ2V0KCJsYXN0X2Vycm9yIiwgIiIpLAogICAgICAgICAgICAiZGVsaXZlcnkiOiB7InN0YXR1cyI6c3RhdGUuZ2V0KCdk'
    'ZWxpdmVyeV9zdGF0dXMnLCdpZGxlJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAiZXJyb3IiOnN0YXRlLmdldCgnZGVs'
    'aXZlcnlfZXJyb3InLCcnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICJhdHRlbXB0IjpzdGF0ZS5nZXQoJ2RlbGl2ZXJ5'
    'X2F0dGVtcHQnLDApLAogICAgICAgICAgICAgICAgICAgICAgICAgInBlbmRpbmciOmxlbihsaXN0KChST09ULydvdXRib3gn'
    'KS5nbG9iKCcqLmpzb24nKSkpICsgaW50KFBFTkRJTkdfVEVTVC5leGlzdHMoKSl9LAogICAgICAgICAgICAidGVzdCI6IHRl'
    'c3Rfc3RhdHVzKCksCiAgICAgICAgICAgICJwcm9maWxlX3BhdGgiOiAifi9WcG4vU3RhckZpdmUvcHJvZmlsZS5qc29uIn0K'
    'CgpkZWYgdmFsaWRhdGVfcHJvZmlsZShwKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHAsIGRpY3QpIG9yIHAuZ2V0KCJzY2hl'
    'bWEiKSAhPSAxIG9yIHAuZ2V0KCJzZXJ2ZXIiKSAhPSBTRVJWRVI6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J7QttC4'
    '0LTQsNC10YLRgdGPINC/0LXRgNGB0L7QvdCw0LvRjNC90YvQuSDQv9GA0L7RhNC40LvRjCBTdGFyRml2ZSBzY2hlbWE9MS4i'
    'KQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyImRldmljZS1bYS1mMC05XXsyNH0iLCBzdHIocC5nZXQoImlkZW50aXR5Iiwg'
    'IiIpKSk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC40LTQtdC90YLQuNGE'
    '0LjQutCw0YLQvtGAINGD0YHRgtGA0L7QudGB0YLQstCwLiIpCiAgICBmb3IgZmllbGQsIG1hcmtlciBpbiAoKCJjYSIsICJD'
    'RVJUSUZJQ0FURSIpLCAoImNlcnRpZmljYXRlIiwgIkNFUlRJRklDQVRFIiksCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'KCJwcml2YXRlX2tleSIsICJQUklWQVRFIEtFWSIpKToKICAgICAgICBzID0gcC5nZXQoZmllbGQpCiAgICAgICAgaWYgbm90'
    'IGlzaW5zdGFuY2Uocywgc3RyKSBvciBsZW4ocykgPiAzMjc2OCBvciAoIi0tLS0tQkVHSU4gIiArIG1hcmtlciArICItLS0t'
    'LSIpIG5vdCBpbiBzOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0LUg0LTQ'
    'sNC90L3Ri9C1INGB0LXRgNGC0LjRhNC40LrQsNGC0L7Qsi4iKQogICAgcmV0dXJuIHAKCgpkZWYgaW1wb3J0X3Byb2ZpbGUo'
    'c2V0dGluZ3MsIG5hbWUpOgogICAgaWYgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC9'
    '0LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDRjdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM0L3QvtC1INGB0L7QtdC00LjQ'
    'vdC10L3QuNC1LiIpCiAgICBwYXRoID0gcGF0aGxpYi5QYXRoKG5hbWUpLmV4cGFuZHVzZXIoKQogICAgaWYgbmFtZS5zdGFy'
    'dHN3aXRoKCJ+LyIpOgogICAgICAgIHBhdGggPSBwYXRobGliLlBhdGgoc2V0dGluZ3NbIm93bmVyX2hvbWUiXSkgLyBuYW1l'
    'WzI6XQogICAgaW1wb3J0IHB3ZAogICAgdWlkID0gcHdkLmdldHB3bmFtKHN0cihzZXR0aW5nc1sib3duZXJfdXNlciJdKSku'
    'cHdfdWlkCiAgICAjIE5ldmVyIGxldCBhIHBhc3N3b3JkbGVzcyBzdWRvIGFjdGlvbiByZWFkIGEgcm9vdCBzZWNyZXQgb3Ig'
    'YSBzcGVjaWFsIGZpbGUuCiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PTkJMT0NLIHwgb3Mu'
    'T19OT0ZPTExPVykKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAicmIiKSBhcyBmOgogICAgICAgIHN0ID0gb3MuZnN0YXQoZi5m'
    'aWxlbm8oKSkKICAgICAgICBpbXBvcnQgc3RhdAogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSkgb3Ig'
    'c3Quc3RfdWlkICE9IHVpZCBvciBzdC5zdF9zaXplID4gMTEwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'ItCf0YDQvtGE0LjQu9GMINC00L7Qu9C20LXQvSDQsdGL0YLRjCDQvtCx0YvRh9C90YvQvCDRhNCw0LnQu9C+0Lwg0LLQu9Cw'
    '0LTQtdC70YzRhtCwINC60LvQuNC10L3RgtCwLCDQvdC1INCx0L7Qu9C10LUgMTEwINCa0JEuIikKICAgICAgICBwID0gdmFs'
    'aWRhdGVfcHJvZmlsZShqc29uLmxvYWRzKGYucmVhZCgxMTAwMDEpKSkKICAgIGltcG9ydCB0ZW1wZmlsZQogICAgd2l0aCB0'
    'ZW1wZmlsZS5UZW1wb3JhcnlEaXJlY3RvcnkoKSBhcyB0bXA6CiAgICAgICAgc3RhZ2UgPSBwYXRobGliLlBhdGgodG1wKQog'
    'ICAgICAgIGZvciBrZXksIGZpbGVuYW1lIGluICgoImNhIiwgImNhLnBlbSIpLCAoImNlcnRpZmljYXRlIiwgImNlcnQucGVt'
    'IiksICgicHJpdmF0ZV9rZXkiLCAia2V5LnBlbSIpKToKICAgICAgICAgICAgd3JpdGUoc3RhZ2UgLyBmaWxlbmFtZSwgcFtr'
    'ZXldKQogICAgICAgIGN0eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgIGN0eC5s'
    'b2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKHN0YWdlIC8gImNhLnBlbSIpKQogICAgICAgIGN0eC5sb2FkX2NlcnRfY2hhaW4o'
    'c3RyKHN0YWdlIC8gImNlcnQucGVtIiksIHN0cihzdGFnZSAvICJrZXkucGVtIikpCiAgICBST09ULm1rZGlyKG1vZGU9MG83'
    'MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKFJPT1QgLyAicHJvZmlsZS5qc29uIiwganNvbi5k'
    'dW1wcyhwKSkKICAgIHdyaXRlKFJPT1QgLyAiY2EucGVtIiwgcFsiY2EiXSkKICAgIHdyaXRlKFJPT1QgLyAiY2xpZW50LnBl'
    'bSIsIHBbImNlcnRpZmljYXRlIl0pCiAgICB3cml0ZShST09UIC8gImNsaWVudC1rZXkucGVtIiwgcFsicHJpdmF0ZV9rZXki'
    'XSkKICAgIHdyaXRlKFJPT1QgLyAicHJpdmF0ZSIgLyAiY2xpZW50LWtleS5wZW0iLCBwWyJwcml2YXRlX2tleSJdKQogICAg'
    'd3JpdGUoUk9PVCAvICJ4NTA5IiAvICJjbGllbnQucGVtIiwgcFsiY2VydGlmaWNhdGUiXSkKICAgIHdyaXRlKFJPT1QgLyAi'
    'eDUwOWNhIiAvICJjYS5wZW0iLCBwWyJjYSJdKQogICAgY29udGV4dCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9U'
    'TFNfQ0xJRU5UKQogICAgY29udGV4dC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKFJPT1QgLyAiY2EucGVtIikpCiAgICBj'
    'b250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVCAvICJjbGllbnQucGVtIiksIHN0cihST09UIC8gImNsaWVudC1rZXku'
    'cGVtIikpCiAgICBzYXZlKHsidGVsZW1ldHJ5IjogVHJ1ZSwgImxhc3RfZXJyb3IiOiAiIn0pCiAgICBwcmludCgi0J/RgNC+'
    '0YTQuNC70Ywg0YPRgdGC0LDQvdC+0LLQu9C10L0uINCS0YDQtdC80LXQvdC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCw'
    'INCy0LrQu9GO0YfQtdC90LA7INC10ZEg0LzQvtC20L3QviDQstGL0LrQu9GO0YfQuNGC0Ywg0LfQtNC10YHRjCDQttC1LiIp'
    'CgoKZGVmIHByZXBhcmUoKToKICAgIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSI6CiAgICAgICAgaW5zdGFsbF91c2Vyc3Bh'
    'Y2UoKQogICAgICAgIHByaW50KCLQkNCy0YLQvtC90L7QvNC90YvQuSBJUHNlYy9UVU4g0LTQstC40LbQvtC6INCz0L7RgtC+'
    '0LIuINCh0LjRgdGC0LXQvNC90YvQuSDQt9Cw0L/RgNC10YIgZXNwNCDRgdC+0YXRgNCw0L3RkdC9LiIpCiAgICAgICAgcmV0'
    'dXJuCiAgICBpZiBzaHV0aWwud2hpY2goInN3YW5jdGwiKToKICAgICAgICByZXR1cm4KICAgIGlmIHNodXRpbC53aGljaCgi'
    'cGFjbWFuIik6CiAgICAgICAgY21kKFsicGFjbWFuIiwgIi1TIiwgIi0tbmVlZGVkIiwgIi0tbm9jb25maXJtIiwgInN0cm9u'
    'Z3N3YW4iXSwgdGltZW91dD0zMDApCiAgICBlbGlmIHNodXRpbC53aGljaCgiZG5mIik6CiAgICAgICAgY21kKFsiZG5mIiwg'
    'Imluc3RhbGwiLCAiLXkiLCAiLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFsc2UiLCAic3Ryb25nc3dhbiJdLCB0aW1l'
    'b3V0PTMwMCkKICAgIGVsc2U6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQo9GB0YLQsNC90L7QstC4IHN0cm9uZ1N3'
    'YW4g0YEgc3dhbmN0bCDRgdGA0LXQtNGB0YLQstCw0LzQuCDRgdCy0L7QtdCz0L4g0LTQuNGB0YLRgNC40LHRg9GC0LjQstCw'
    'LiIpCiAgICBwcmludCgic3Ryb25nU3dhbiDRg9GB0YLQsNC90L7QstC70LXQvTsg0LDQstGC0L7Qv9C+0LTQutC70Y7Rh9C1'
    '0L3QuNC1INC90LUg0LLQutC70Y7Rh9C10L3Qvi4iKQoKCmRlZiByZW5kZXJfZ3VhcmQoKToKICAgIHRyYW5zcG9ydD0oZicg'
    'IG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntUVU59IiBhY2NlcHQnIGlmIGJhY2tlbmQoKT09J3VzZXJzcGFjZScKICAg'
    'ICAgICAgICAgICAgZWxzZSBmJyAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlkIHtSRVFJRH0gYWNjZXB0JykK'
    'ICAgIHJldHVybiBmIiIidGFibGUgaW5ldCB7VEFCTEV9IHt7CiBjaGFpbiBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29r'
    'IG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciB7U0VS'
    'VkVSfSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBtZXRhIHNrdWlkIDAgbWV0YSBtYXJrIHtESVJFQ1RfTUFSS30g'
    'aXAgZGFkZHIge1NFUlZFUn0gdGNwIGRwb3J0IHtESVJFQ1RfUE9SVH0gYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgdWRw'
    'IHNwb3J0IDY4IHVkcCBkcG9ydCA2NyBhY2NlcHQKe3RyYW5zcG9ydH0KIH19CiBjaGFpbiBmb3J3YXJkIHt7CiAgdHlwZSBm'
    'aWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiB9fQp9fQoiIiIKCgpkZWYgcmVuZGVyX2Nv'
    'bm5lY3Rpb24ocCk6CiAgICByZXR1cm4gZiIiImNvbm5lY3Rpb25zIHt7CiBzdGFyZml2ZSB7ewogIHZlcnNpb24gPSAyCiAg'
    'cmVtb3RlX2FkZHJzID0ge1NFUlZFUn0KICByZW1vdGVfcG9ydCA9IHtJS0VfUE9SVH0KICBsb2NhbF9wb3J0ID0gNDUwMAog'
    'IHZpcHMgPSAwLjAuMC4wCiAgcHJvcG9zYWxzID0gYWVzMjU2Z2NtMTYtcHJmc2hhMzg0LWVjcDM4NCxhZXMyNTYtc2hhMjU2'
    'LW1vZHAyMDQ4CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5'
    'ID0gMzBzCiAgbG9jYWwge3sKICAgYXV0aCA9IGVhcC10bHMKICAgaWQgPSB7cFsnaWRlbnRpdHknXX0KICAgZWFwX2lkID0g'
    'e3BbJ2lkZW50aXR5J119CiAgIGNlcnRzID0ge1JPT1R9L2NsaWVudC5wZW0KICB9fQogIHJlbW90ZSB7ewogICBhdXRoID0g'
    'cHVia2V5CiAgIGlkID0ge1NFUlZFUn0KICAgY2FjZXJ0cyA9IHtST09UfS9jYS5wZW0KICB9fQogIGNoaWxkcmVuIHt7CiAg'
    'IHN0YXJmaXZlLW5ldCB7ewogICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJl'
    'cWlkID0ge1JFUUlEfQogICAgZXNwX3Byb3Bvc2FscyA9IGFlczI1NmdjbTE2LGFlczI1Ni1zaGEyNTYKICAgIGRwZF9hY3Rp'
    'b24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQoiIiIKCgpkZWYgcmVuZGVyX3N0'
    'cm9uZ3N3YW4oaW5jbHVkZXM9JycpOgogICAgaWYgYmFja2VuZCgpPT0ndXNlcnNwYWNlJzoKICAgICAgICBwbHVnaW5zPSdy'
    'YW5kb20gbm9uY2Ugb3BlbnNzbCBwZW0gcGtjczEgcGtjczggeDUwOSBwdWJrZXkgcmV2b2NhdGlvbiBjb25zdHJhaW50cyBr'
    'ZXJuZWwtbGliaXBzZWMga2VybmVsLW5ldGxpbmsgc29ja2V0LWRlZmF1bHQgZWFwLWlkZW50aXR5IGVhcC10bHMgdmljaScK'
    'ICAgICAgICByZXR1cm4gZiIiImNoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0gbm8KIGxvYWQgPSB7cGx1Z2luc30KIGluc3Rh'
    'bGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFibGVfcHJpbyA9IDEwMAogcGx1Z2lu'
    'cyB7ewogIGtlcm5lbC1saWJpcHNlYyB7ewogICBsb2FkID0gMjAKICAgcmF3X2VzcCA9IG5vCiAgfX0KICBrZXJuZWwtbmV0'
    'bGluayB7ewogICBmd21hcmsgPSAhe2hleChJS0VfTUFSSyl9CiAgfX0KICBzb2NrZXQtZGVmYXVsdCB7ewogICBmd21hcmsg'
    'PSB7aGV4KElLRV9NQVJLKX0KICB9fQogIHZpY2kge3sKICAgc29ja2V0ID0ge1VSSX0KICB9fQogfX0KIGZpbGVsb2cge3sK'
    'ICBzdGRlcnIge3sKICAgZGVmYXVsdCA9IDEKICAgZmx1c2hfbGluZSA9IHllcwogIH19CiB9fQp9fQoiIiIKICAgIHJldHVy'
    'biAgIiIiY2hhcm9uIHsKIGxvYWRfbW9kdWxhciA9IHllcwogaW5zdGFsbF9yb3V0ZXMgPSB5ZXMKIHJvdXRpbmdfdGFibGUg'
    'PSA1MTgyMgogcm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBwbHVnaW5zIHsKIiIiICsgaW5jbHVkZXMgKyBmIiIiCiAgdmlj'
    'aSB7ewogICBzb2NrZXQgPSB7VVJJfQogIH19CiAgcmVzb2x2ZSB7ewogICBsb2FkID0gbm8KICB9fQogIGtlcm5lbC1saWJp'
    'cHNlYyB7ewogICBsb2FkID0gbm8KICB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sKIGpvdXJuYWwge3sKICBkZWZhdWx0'
    'ID0gMQogfX0KfX0KIiIiCgoKZGVmIHNlcnZpY2VfZmlsZXMoKToKICAgIGNhbmRpZGF0ZXMgPSBbIi91c3Ivc2Jpbi9jaGFy'
    'b24tc3lzdGVtZCIsICIvdXNyL2Jpbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYi9pcHNlYy9jaGFyb24tc3lzdGVtZCIs'
    'ICIvdXNyL2xpYmV4ZWMvaXBzZWMvY2hhcm9uLXN5c3RlbWQiLAogICAgICAgICAgICAgICAgICAiL3Vzci9saWIvc3Ryb25n'
    'c3dhbi9jaGFyb24tc3lzdGVtZCIsICIvdXNyL2xpYmV4ZWMvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCJdCiAgICBiaW5h'
    'cnkgPSBzdHIoVVNFUlNQQUNFLyJjaGFyb24iKSBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGFuZCB1c2Vyc3BhY2VfcmVh'
    'ZHkoKSBlbHNlIG5leHQoKHggZm9yIHggaW4gY2FuZGlkYXRlcyBpZiBwYXRobGliLlBhdGgoeCkuaXNfZmlsZSgpKSwgTm9u'
    'ZSkKICAgIGlmIGJhY2tlbmQoKT09InVzZXJzcGFjZSIgYW5kIG5vdCB1c2Vyc3BhY2VfcmVhZHkoKToKICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQvtCy0LjRgtGMIElLRXYy'
    'wrsg0LTQu9GPINC30LDQs9GA0YPQt9C60LggVFVOLdC00LLQuNC20LrQsC4iKQogICAgaWYgbm90IGJpbmFyeToKICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LUg0L3QsNC50LTQtdC9IGNoYXJvbi1zeXN0ZW1kLiDQndGD0LbQtdC9INC/0LDQ'
    'utC10YIgc3Ryb25nU3dhbiDRgSBzeXN0ZW1kIGJhY2tlbmQuIikKICAgIGNvbmZpZ3MgPSBbc3RyKHApIGZvciBwYXR0ZXJu'
    'IGluICgiL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZiIsICIvZXRjL3N0cm9uZ3N3YW4vc3Ryb25nc3dhbi5kL2No'
    'YXJvbi8qLmNvbmYiKQogICAgICAgICAgICAgICBmb3IgcCBpbiBwYXRobGliLlBhdGgoIi8iKS5nbG9iKHBhdHRlcm4ubHN0'
    'cmlwKCIvIikpXQogICAgaW5jbHVkZXMgPSAiXG4iLmpvaW4oImluY2x1ZGUgIiArIHggZm9yIHggaW4gY29uZmlncykKICAg'
    'ICMgRE5TIGlzIG1hbmFnZWQgdHJhbnNhY3Rpb25hbGx5IGJ5IHRoaXMgYmFja2VuZCwgbm90IGJ5IHRoZSByZXNvbHZlIHBs'
    'dWdpbi4KICAgIHdyaXRlKFJPT1QgLyAic3Ryb25nc3dhbi5jb25mIixyZW5kZXJfc3Ryb25nc3dhbihpbmNsdWRlcykpCiAg'
    'ICB3cml0ZShwYXRobGliLlBhdGgoIi9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIFVOSVQsIGYiIiJbVW5pdF0KRGVzY3JpcHRp'
    'b249RXZnZW5pdW0gZXhwZXJpbWVudGFsIFN0YXJGaXZlIElLRXYyCkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpU'
    'eXBlPXsic2ltcGxlIiBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGVsc2UgIm5vdGlmeSJ9CkVudmlyb25tZW50PVNUUk9O'
    'R1NXQU5fQ09ORj17Uk9PVH0vc3Ryb25nc3dhbi5jb25mCkV4ZWNTdGFydD17YmluYXJ5fQpSdW50aW1lRGlyZWN0b3J5PWV2'
    'Z2VuaXVtLWlrZXYyClJ1bnRpbWVEaXJlY3RvcnlNb2RlPTA3MDAKTWVtb3J5TWF4PTM4NE0KUmVzdGFydD1ubwpUaW1lb3V0'
    'U3RhcnRTZWM9MjAKIiIiLCAwbzY0NCkKICAgIHdyaXRlKFJPT1QgLyAiZ3VhcmQubmZ0IiwgcmVuZGVyX2d1YXJkKCkpCiAg'
    'ICB3cml0ZShwYXRobGliLlBhdGgoIi9ldGMvc3lzdGVtZC9zeXN0ZW0iKSAvIEdVQVJELCBmIiIiW1VuaXRdCkRlc2NyaXB0'
    'aW9uPUZhaWwtY2xvc2VkIGd1YXJkIGZvciBleHBlcmltZW50YWwgSUtFdjIKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpCZWZv'
    'cmU9bmV0d29yay1wcmUudGFyZ2V0CldhbnRzPW5ldHdvcmstcHJlLnRhcmdldApBZnRlcj1sb2NhbC1mcy50YXJnZXQgbmZ0'
    'YWJsZXMuc2VydmljZQpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0PXtzaHV0'
    'aWwud2hpY2goIm5mdCIpfSAtZiB7Uk9PVH0vZ3VhcmQubmZ0CkV4ZWNTdG9wPS17c2h1dGlsLndoaWNoKCJuZnQiKX0gZGVs'
    'ZXRlIHRhYmxlIGluZXQge1RBQkxFfQpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiLCAwbzY0NCkK'
    'ICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgiL2V0Yy9zeXN0ZW1kL3N5c3RlbSIpIC8gTU9OSVRPUiwgIiIiW1VuaXRdCkRlc2Ny'
    'aXB0aW9uPVRlbXBvcmFyeSBTdGFyRml2ZSBWUE4gZGlhZ25vc3RpY3MKQWZ0ZXI9ZXZnZW5pdW0taWtldjIuc2VydmljZQpb'
    'U2VydmljZV0KRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtbW9uaXRvcgpTdGFu'
    'ZGFyZE91dHB1dD1udWxsClN0YW5kYXJkRXJyb3I9bnVsbApSZXN0YXJ0PW5vCiIiIiwgMG82NDQpCiAgICBpbnN0YWxsX2Rl'
    'bGl2ZXJ5KCkKCgpkZWYgaW5zdGFsbF9kZWxpdmVyeSgpOgogICAgd3JpdGUocGF0aGxpYi5QYXRoKCcvZXRjL3N5c3RlbWQv'
    'c3lzdGVtJykgLyBERUxJVkVSWSwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPUV4cGVyaW1lbnRhbCBkaXJlY3QgbVRMUyBkaWFn'
    'bm9zdGljIGRlbGl2ZXJ5CkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmlu'
    'L3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS1kZWxpdmVyeQpTdGFuZGFyZE91dHB1dD1udWxsClN0YW5kYXJkRXJyb3I9bnVs'
    'bApSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zMApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQK'
    'IiIiLCAwbzY0NCkKICAgIGNtZChbInN5c3RlbWN0bCIsICJkYWVtb24tcmVsb2FkIl0pCiAgICBjbWQoWydzeXN0ZW1jdGwn'
    'LCdlbmFibGUnLERFTElWRVJZXSxjaGVjaz1GYWxzZSkKICAgICMgVXBncmFkZSBhbiBhbHJlYWR5IGFjdGl2ZSBleHBlcmlt'
    'ZW50YWwgZ3VhcmQgd2l0aG91dCBvcGVuaW5nIG9yZGluYXJ5IHRyYWZmaWMuCiAgICBpZiBhY3RpdmVfZ3VhcmQoKToKICAg'
    'ICAgICBydWxlcz1jbWQoWyduZnQnLCdsaXN0JywnY2hhaW4nLCdpbmV0JyxUQUJMRSwnb3V0cHV0J10sY2hlY2s9RmFsc2Up'
    'LnN0ZG91dAogICAgICAgIGlmIHN0cihESVJFQ1RfTUFSSykgbm90IGluIHJ1bGVzIGFuZCBoZXgoRElSRUNUX01BUkspIG5v'
    'dCBpbiBydWxlczoKICAgICAgICAgICAgY21kKFsnbmZ0JywnaW5zZXJ0JywncnVsZScsJ2luZXQnLFRBQkxFLCdvdXRwdXQn'
    'LCdtZXRhJywnc2t1aWQnLCcwJywKICAgICAgICAgICAgICAgICAnbWV0YScsJ21hcmsnLHN0cihESVJFQ1RfTUFSSyksJ2lw'
    'JywnZGFkZHInLFNFUlZFUiwndGNwJywnZHBvcnQnLHN0cihESVJFQ1RfUE9SVCksJ2FjY2VwdCddKQoKCmRlZiBzZXRfZG5z'
    'KCk6CiAgICByZXNvbHZlZCA9IFJPT1QgLyAicmVzb2x2ZWQtYmFja3VwLmpzb24iCiAgICBiYWNrdXAgPSBST09UIC8gInJl'
    'c29sdi1iYWNrdXAiCiAgICBpZiBiYWNrdXAuZXhpc3RzKCkgb3IgcmVzb2x2ZWQuZXhpc3RzKCk6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCLQldGB0YLRjCDQvdC10LfQsNCy0LXRgNGI0ZHQvdC90L7QtSDQstC+0YHRgdGC0LDQvdC+0LLQu9C1'
    '0L3QuNC1IEROUy4g0KHQvdCw0YfQsNC70LAgdnBuIGV4cGVyaW1lbnRhbCBvZmYuIikKICAgIGlmIHNodXRpbC53aGljaCgi'
    'cmVzb2x2ZWN0bCIpIGFuZCBjbWQoWyJzeXN0ZW1jdGwiLCAiaXMtYWN0aXZlIiwgInN5c3RlbWQtcmVzb2x2ZWQiXSwgY2hl'
    'Y2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICByb3V0ZSA9IGpzb24ubG9hZHMoY21kKFsiaXAiLCAiLWoiLCAi'
    'cm91dGUiLCAiZ2V0IiwgU0VSVkVSXSkuc3Rkb3V0KVswXQogICAgICAgIGlmYWNlID0gcm91dGVbImRldiJdCiAgICAgICAg'
    'ZGVmIHByZXZpb3VzKGtpbmQpOgogICAgICAgICAgICB0ZXh0ID0gY21kKFsicmVzb2x2ZWN0bCIsIGtpbmQsIGlmYWNlXSku'
    'c3Rkb3V0CiAgICAgICAgICAgIHJldHVybiB0ZXh0LnNwbGl0KCIpOiIsIDEpWzFdLnN0cmlwKCkuc3BsaXQoKSBpZiAiKToi'
    'IGluIHRleHQgZWxzZSBbXQogICAgICAgIHdyaXRlKHJlc29sdmVkLCBqc29uLmR1bXBzKHsiaWZhY2UiOiBpZmFjZSwgImRu'
    'cyI6IHByZXZpb3VzKCJkbnMiKSwgImRvbWFpbiI6IHByZXZpb3VzKCJkb21haW4iKX0pKQogICAgICAgIGNtZChbInJlc29s'
    'dmVjdGwiLCAiZG5zIiwgaWZhY2UsICI3Ny44OC44LjgiLCAiNzcuODguOC4xIl0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0'
    'bCIsICJkb21haW4iLCBpZmFjZSwgIn4uIl0pCiAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsICJmbHVzaC1jYWNoZXMiXSwg'
    'Y2hlY2s9RmFsc2UpCiAgICAgICAgcmV0dXJuCiAgICB3cml0ZShiYWNrdXAsIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYu'
    'Y29uZiIpLnJlYWRfdGV4dCgpKQogICAgIyBLZWVwIHRoZSBzeW1saW5rIGl0c2VsZiBpbnRhY3QgKE5ldHdvcmtNYW5hZ2Vy'
    'L3N5c3RlbWQtcmVzb2x2ZWQgc2V0dXBzKS4KICAgIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYuY29uZiIpLndyaXRlX3Rl'
    'eHQoIiMgRXZnZW5pdW0gZXhwZXJpbWVudGFsIFZQTlxubmFtZXNlcnZlciA3Ny44OC44Ljhcbm5hbWVzZXJ2ZXIgNzcuODgu'
    'OC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4iKQoKCmRlZiByZXN0b3JlX2RucygpOgogICAgcmVzb2x2ZWQg'
    'PSBST09UIC8gInJlc29sdmVkLWJhY2t1cC5qc29uIgogICAgaWYgcmVzb2x2ZWQuZXhpc3RzKCk6CiAgICAgICAgZGF0YSA9'
    'IGpzb24ubG9hZHMocmVzb2x2ZWQucmVhZF90ZXh0KCkpCiAgICAgICAgZm9yIGtleSBpbiAoImRucyIsICJkb21haW4iKToK'
    'ICAgICAgICAgICAgY21kKFsicmVzb2x2ZWN0bCIsIGtleSwgZGF0YVsiaWZhY2UiXSwgKihkYXRhW2tleV0gb3IgWyIiXSld'
    'KQogICAgICAgIGNtZChbInJlc29sdmVjdGwiLCAiZmx1c2gtY2FjaGVzIl0sIGNoZWNrPUZhbHNlKQogICAgICAgIHJlc29s'
    'dmVkLnVubGluaygpCiAgICBiYWNrdXAgPSBST09UIC8gInJlc29sdi1iYWNrdXAiCiAgICBpZiBiYWNrdXAuZXhpc3RzKCk6'
    'CiAgICAgICAgcGF0aGxpYi5QYXRoKCIvZXRjL3Jlc29sdi5jb25mIikud3JpdGVfdGV4dChiYWNrdXAucmVhZF90ZXh0KCkp'
    'CiAgICAgICAgYmFja3VwLnVubGluaygpCgoKZGVmIGVuZHBvaW50KHBhdGgsIHBheWxvYWQ9Tm9uZSk6CiAgICBjb250ZXh0'
    'ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FmaWxlPXN0cihST09UIC8gImNhLnBlbSIpKQogICAgY29udGV4dC5s'
    'b2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QgLyAiY2xpZW50LnBlbSIpLCBzdHIoUk9PVCAvICJjbGllbnQta2V5LnBlbSIpKQog'
    'ICAgZGF0YSA9IE5vbmUgaWYgcGF5bG9hZCBpcyBOb25lIGVsc2UganNvbi5kdW1wcyhwYXlsb2FkLCBzZXBhcmF0b3JzPSgi'
    'LCIsICI6IikpLmVuY29kZSgpCiAgICByZXEgPSB1cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxUSCArIHBhdGgsIGRhdGE9'
    'ZGF0YSwgaGVhZGVycz17IkNvbnRlbnQtVHlwZSI6ICJhcHBsaWNhdGlvbi9qc29uIn0pCiAgICAjIE5ldmVyIGNvbnN1bHQg'
    'ZW52aXJvbm1lbnQgcHJveHkgdmFyaWFibGVzIGZvciBhIHByaXZhdGUgZGlhZ25vc3RpYyBlbmRwb2ludC4KICAgIG9wZW5l'
    'ciA9IHVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcih1cmxsaWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pLCB1cmxsaWIu'
    'cmVxdWVzdC5IVFRQU0hhbmRsZXIoY29udGV4dD1jb250ZXh0KSkKICAgIHdpdGggb3BlbmVyLm9wZW4ocmVxLCB0aW1lb3V0'
    'PTgpIGFzIHJlc3BvbnNlOgogICAgICAgIHJldHVybiBqc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQoNjU1MzYpKQoKCmRlZiBv'
    'bihhcGksIHNldHRpbmdzKToKICAgIHN0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKQogICAgc3RhZ2U9J3ByZXBhcmUnCiAgICBp'
    'ZiBhcGkuc2VydmljZV9hY3RpdmUoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINCy0YvQ'
    'utC70Y7Rh9C4INC+0LHRi9GH0L3Ri9C5IFhyYXkgVlBOLiDQntC00L3QvtCy0YDQtdC80LXQvdC90L4g0LTQstCwINGA0LXQ'
    'ttC40LzQsCDQvdC1INC30LDQv9GD0YHQutCw0Y7RgtGB0Y8uIikKICAgIGlmIGFjdGl2ZV9ndWFyZCgpOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcigi0KDQtdC20LjQvCDRg9C20LUg0LLQutC70Y7Rh9GR0L0g0LjQu9C4INC30LDQsdC70L7QutC4'
    '0YDQvtCy0LDQvSDQv9C+0YHQu9C1INGB0LHQvtGPLiDQktGL0LrQu9GO0YfQuCDQtdCz0L4g0L/QtdGA0LXQtCDQv9C+0LLR'
    'gtC+0YDQvtC8LiIpCiAgICBpZiBub3QgUk9PVC5qb2lucGF0aCgicHJvZmlsZS5qc29uIikuZXhpc3RzKCk6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQuNC80L/QvtGA0YLQuNGA0YPQuSDQv9C10YDRgdC+0L3QsNC7'
    '0YzQvdGL0Lkg0L/RgNC+0YTQuNC70YwgU3RhckZpdmUuIikKICAgIGlmIG5vdCBhdmFpbGFibGUoKToKICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoItCh0L3QsNGH0LDQu9CwINC90LDQttC80LggwqvQn9C+0LTQs9C+0YLQvtCy0LjRgtGMIElLRXYy'
    'wrsuIikKICAgICMgRXhpc3RpbmcgdW5yZWxhdGVkIElQc2VjIHN0YXRlIG11c3QgbmV2ZXIgYmUgcmVwbGFjZWQuCiAgICBp'
    'ZiBjbWQoWyJpcCIsICJ4ZnJtIiwgInN0YXRlIl0sIGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoItCe0LHQvdCw0YDRg9C20LXQvSDQtNGA0YPQs9C+0LkgSVBzZWMgVlBOLiDQodC90LDRh9Cw0LvQ'
    'sCDQvtGC0LrQu9GO0YfQuCDQtdCz0L4uIikKICAgIHAgPSB2YWxpZGF0ZV9wcm9maWxlKGpzb24ubG9hZHMoKFJPT1QgLyAi'
    'cHJvZmlsZS5qc29uIikucmVhZF90ZXh0KCkpKQogICAgaWYgYmFja2VuZCgpPT0idXNlcnNwYWNlIiBhbmQgcGF0aGxpYi5Q'
    'YXRoKCIvc3lzL2NsYXNzL25ldCIsVFVOKS5leGlzdHMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCY0L3RgtC1'
    '0YDRhNC10LnRgSBpcHNlYzAg0YPQttC1INGB0YPRidC10YHRgtCy0YPQtdGCLiDQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO'
    '0YfQuCDQuNGB0L/QvtC70YzQt9GD0Y7RidC10LUg0LXQs9C+INC/0L7QtNC60LvRjtGH0LXQvdC40LUuIikKICAgIHNlcnZp'
    'Y2VfZmlsZXMoKQogICAgd3JpdGUoUk9PVCAvICJjb25uZWN0aW9uLmNvbmYiLCByZW5kZXJfY29ubmVjdGlvbihwKSkKICAg'
    'IHRyeToKICAgICAgICBzdGFnZT0nZGFlbW9uJwogICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIsIFVOSVRdKQog'
    'ICAgICAgIHdhaXRfdXNlcnNwYWNlKCkKICAgICAgICBzdGFnZT0nY3JlZGVudGlhbHMnCiAgICAgICAgc3dhbigiLS1sb2Fk'
    'LWNyZWRzIiwgIi0tZmlsZSIsIFJPT1QgLyAiY29ubmVjdGlvbi5jb25mIikKICAgICAgICBzd2FuKCItLWxvYWQtY29ubnMi'
    'LCAiLS1maWxlIiwgUk9PVCAvICJjb25uZWN0aW9uLmNvbmYiKQogICAgICAgIHN0YWdlPSdndWFyZCcKICAgICAgICB3cml0'
    'ZShSVU5USU1FIC8gImd1YXJkLm5mdCIsIHJlbmRlcl9ndWFyZCgpKQogICAgICAgIGNtZChbIm5mdCIsICItYyIsICItZiIs'
    'IFJVTlRJTUUgLyAiZ3VhcmQubmZ0Il0pCiAgICAgICAgIyBBbGwgcHJlcGFyYXRvcnkgY2hlY2tzIGFib3ZlIGFyZSBub24t'
    'ZGlzcnVwdGl2ZS4gVGhlIGd1YXJkIGdvZXMgZmlyc3QuCiAgICAgICAgY21kKFsic3lzdGVtY3RsIiwgImVuYWJsZSIsICIt'
    'LW5vdyIsIEdVQVJEXSkKICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgICAgICMgUmVjb3ZlciBhIHN0'
    'YWxlIGFjdGl2ZSBzeXN0ZW1kIHVuaXQgd2hvc2UgdGFibGUgd2FzIGV4dGVybmFsbHkgcmVtb3ZlZC4KICAgICAgICAgICAg'
    'Y21kKFsibmZ0IiwgIi1mIiwgUk9PVCAvICJndWFyZC5uZnQiXSkKICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6CiAg'
    'ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTRgtCy0LXRgNC00LjRgtGM'
    'INGD0YHRgtCw0L3QvtCy0LrRgyBraWxsIHN3aXRjaC4iKQogICAgICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5l'
    'Y3RpbmciLCAibGFzdF9lcnJvciI6ICIifSkKICAgICAgICBzdGFnZT0naGFuZHNoYWtlJwogICAgICAgIHN3YW4oIi0taW5p'
    'dGlhdGUiLCAiLS1jaGlsZCIsICJzdGFyZml2ZS1uZXQiLCB0aW1lb3V0PTU1KQogICAgICAgIGlmIG5vdCBjb25uZWN0ZWQo'
    'KToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCJJUHNlYyBDSElMRF9TQSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQ'
    'tdC9LiIpCiAgICAgICAgc3RhZ2U9J2RucycKICAgICAgICBzZXRfZG5zKCkKICAgICAgICBzdGFnZT0naGVhbHRoJwogICAg'
    'ICAgIGhlYWx0aCA9IGVuZHBvaW50KCIvaGVhbHRoIikKICAgICAgICBpZiBoZWFsdGguZ2V0KCJzZXJ2aWNlIikgIT0gImV2'
    'Z2VuaXVtLXN0YXJmaXZlIjoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQndC1INC/0L7QtNGC0LLQtdGA0LbQ'
    'tNGR0L0g0LTQuNCw0LPQvdC+0YHRgtC40YfQtdGB0LrQuNC5INGB0LXRgNCy0LXRgCBTdGFyRml2ZS4iKQogICAgICAgIHBh'
    'dGNoX3N0YXRlKHsgInBoYXNlIjogImNvbm5lY3RlZCIsICJzaW5jZSI6IGludCh0aW1lLnRpbWUoKSksICJsYXN0X2Vycm9y'
    'IjogIiJ9KQogICAgICAgIGlmIHN0b3JlZCgpLmdldCgidGVsZW1ldHJ5Iik6CiAgICAgICAgICAgIGNtZChbInN5c3RlbWN0'
    'bCIsICJzdGFydCIsIE1PTklUT1JdKQogICAgICAgIHRyeTogcXVldWVfY29ubmVjdGlvbignY29ubmVjdGVkJywnbm9uZScs'
    'KHRpbWUubW9ub3RvbmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAg'
    'cHJpbnQoIlN0YXJGaXZlINC/0L7QtNC60LvRjtGH0ZHQvS4g0KLQtdGB0YLQvtCy0YvQuSDQstGL0YXQvtC0OiDQoNC+0YHR'
    'gdC40Y8uIElQdjYg0LggRElSRUNULdC40YHQutC70Y7Rh9C10L3QuNGPINC30LDQsdC70L7QutC40YDQvtCy0LDQvdGLLiIp'
    'CiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIE1PTklUT1Jd'
    'LCBjaGVjaz1GYWxzZSkKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFVOSVRdLCBjaGVjaz1GYWxzZSkKICAg'
    'ICAgICByZXN0b3JlX2RucygpCiAgICAgICAgZ3VhcmRlZD1hY3RpdmVfZ3VhcmQoKQogICAgICAgIHBhdGNoX3N0YXRlKHsg'
    'InBoYXNlIjogImJsb2NrZWQiIGlmIGd1YXJkZWQgZWxzZSAib2ZmIiwgImxhc3RfZXJyb3IiOgogICAgICAgICAgICAgICAg'
    'ICAgICAi0J/QvtC00LrQu9GO0YfQtdC90LjQtSDQvdC1INGD0YHRgtCw0L3QvtCy0LvQtdC90L47INC40L3RgtC10YDQvdC1'
    '0YIg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9INC00L4g0LLRi9C60LvRjtGH0LXQvdC40Y8g0YDQtdC20LjQvNCwLiIgaWYg'
    'Z3VhcmRlZCBlbHNlCiAgICAgICAgICAgICAgICAgICAgICLQn9C+0LTQs9C+0YLQvtCy0LrQsCDQvdC1INC30LDQstC10YDR'
    'iNC10L3QsDsg0L/QvtC00LrQu9GO0YfQtdC90LjQtSDQuCDQt9Cw0YnQuNGC0LAg0L3QtSDQstC60LvRjtGH0LjQu9C40YHR'
    'jC4ifSkKICAgICAgICB0cnk6IHF1ZXVlX2Nvbm5lY3Rpb24oc3RhZ2UsZmFpbHVyZV9jb2RlKGV4YyksKHRpbWUubW9ub3Rv'
    'bmljKCktc3RhcnRlZCkqMTAwMCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgZXJyb3I9UnVudGlt'
    'ZUVycm9yKCLQn9C+0LTQutC70Y7Rh9C10L3QuNC1IFN0YXJGaXZlINC90LUg0YPQtNCw0LvQvtGB0YwuICIgKwogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAoIktpbGwgc3dpdGNoINC+0YHRgtCw0LLQu9C10L0g0LLQutC70Y7Rh9GR0L3QvdGL0Lwu'
    'INCS0YvQv9C+0LvQvdC4IHZwbiBleHBlcmltZW50YWwgb2ZmLiAiIGlmIGd1YXJkZWQgZWxzZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIktpbGwgc3dpdGNoINC90LUg0LDQutGC0LjQstC40YDQvtCy0LDQvTog0YHQsdC+0Lkg0L/RgNC+0LjQ'
    't9C+0YjRkdC7INC00L4g0LLQutC70Y7Rh9C10L3QuNGPINGC0YPQvdC90LXQu9GPLiAiKSArIHN0cihleGMpKQogICAgICAg'
    'IGVycm9yLmRpYWdub3N0aWNfcXVldWVkPVRydWUKICAgICAgICByYWlzZSBlcnJvciBmcm9tIGV4YwoKCmRlZiBvZmYoKToK'
    'ICAgIGNtZChbInN5c3RlbWN0bCIsICJzdG9wIiwgVEVTVF9VTklUXSwgY2hlY2s9RmFsc2UpCiAgICBjbWQoWyJzeXN0ZW1j'
    'dGwiLCAic3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbInN5c3RlbWN0bCIsICJzdG9wIiwgVU5JVF0s'
    'IGNoZWNrPUZhbHNlKQogICAgcmVzdG9yZV9kbnMoKQogICAgY21kKFsic3lzdGVtY3RsIiwgImRpc2FibGUiLCAiLS1ub3ci'
    'LCBHVUFSRF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsibmZ0IiwgImRlbGV0ZSIsICJ0YWJsZSIsICJpbmV0IiwgVEFCTEVd'
    'LCBjaGVjaz1GYWxzZSkKICAgIHBhdGNoX3N0YXRlKHsgInBoYXNlIjogIm9mZiIsICJsYXN0X2Vycm9yIjogIiJ9KQogICAg'
    'cHJpbnQoItCt0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0LLRi9C60LvR'
    'jtGH0LXQvdC+LiDQntCx0YvRh9C90YvQuSDQuNC90YLQtdGA0L3QtdGCINCy0L7RgdGB0YLQsNC90L7QstC70LXQvS4iKQoK'
    'CmRlZiB0ZWxlbWV0cnkoZW5hYmxlZCk6CiAgICBwYXRjaF9zdGF0ZSh7ICJ0ZWxlbWV0cnkiOiBib29sKGVuYWJsZWQpfSkK'
    'ICAgIGlmIG5vdCBlbmFibGVkOgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLERFTElWRVJZXSxjaGVjaz1GYWxz'
    'ZSkKICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsi'
    'c3lzdGVtY3RsIiwgInN0YXJ0IiBpZiBlbmFibGVkIGFuZCBjb25uZWN0ZWQoKSBlbHNlICJzdG9wIiwgTU9OSVRPUl0sIGNo'
    'ZWNrPUZhbHNlKQogICAgaWYgZW5hYmxlZDoga2lja19kZWxpdmVyeSgpCiAgICBwcmludCgi0JLRgNC10LzQtdC90L3QsNGP'
    'INC00LjQsNCz0L3QvtGB0YLQuNC60LAgIiArICgi0LLQutC70Y7Rh9C10L3QsCIgaWYgZW5hYmxlZCBlbHNlICLQstGL0LrQ'
    'u9GO0YfQtdC90LAiKSkKCgpkZWYgZG9tYWluX29ubHkodmFsdWUpOgogICAgIyBFeHBsaWNpdCBkb21haW4tb25seSByZXBv'
    'cnQuIE5ldmVyIGFjY2VwdCBVUkxzLCBwYXRocywgdG9rZW5zIG9yIGFyYml0cmFyeSBsb2cgdGV4dC4KICAgIHZhbHVlID0g'
    'dmFsdWUuc3RyaXAoKS5sb3dlcigpLnJzdHJpcCgiLiIpCiAgICBpZiBsZW4odmFsdWUpID4gMjUzIG9yIG5vdCByZS5mdWxs'
    'bWF0Y2gociJbYS16MC05XSg/OlthLXowLTkuLV0qW2EtejAtOV0pPyIsIHZhbHVlKSBvciAiLiIgbm90IGluIHZhbHVlOgog'
    'ICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoItCS0LLQtdC00Lgg0LTQvtC80LXQvSDQsdC10LcgaHR0cHM6Ly8sINC/0YPRgtC4'
    'INC4INC/0LDRgNCw0LzQtdGC0YDQvtCyLiIpCiAgICBmb3IgbGFiZWwgaW4gdmFsdWUuc3BsaXQoIi4iKToKICAgICAgICBp'
    'ZiBub3QgbGFiZWwgb3IgbGVuKGxhYmVsKSA+IDYzIG9yIGxhYmVsLnN0YXJ0c3dpdGgoIi0iKSBvciBsYWJlbC5lbmRzd2l0'
    'aCgiLSIpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQndC10LrQvtGA0YDQtdC60YLQvdGL0Lkg0LTQvtC80LXQ'
    'vS4iKQogICAgdHJ5OgogICAgICAgIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHZhbHVlKQogICAgZXhjZXB0IFZhbHVlRXJyb3I6'
    'CiAgICAgICAgcmV0dXJuIHZhbHVlCiAgICByYWlzZSBWYWx1ZUVycm9yKCLQndGD0LbQtdC9INC00L7QvNC10L0g0YHQsNC5'
    '0YLQsCwg0LAg0L3QtSBJUC3QsNC00YDQtdGBLiIpCgoKZGVmIHByb2JlX2RvbWFpbihkb21haW4pOgogICAgZG9tYWluID0g'
    'ZG9tYWluX29ubHkoZG9tYWluKQogICAgc3RhcnQgPSB0aW1lLm1vbm90b25pYygpCiAgICB0cnk6CiAgICAgICAgcmVzb2x2'
    'ZWQgPSBzb2NrZXQuZ2V0YWRkcmluZm8oZG9tYWluLCA0NDMsIHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0p'
    'CiAgICAgICAgYWRkcmVzc2VzID0gbGlzdChkaWN0LmZyb21rZXlzKHhbNF1bMF0gZm9yIHggaW4gcmVzb2x2ZWQKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeFs0XVswXSkuaXNfZ2xv'
    'YmFsKSlbOjNdCiAgICAgICAgZm9yIGFkZHJlc3MgaW4gYWRkcmVzc2VzOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAg'
    'ICAgICB3aXRoIHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgNDQzKSwgdGltZW91dD00KSBhcyBzb2NrOgog'
    'ICAgICAgICAgICAgICAgICAgIHdpdGggc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoKS53cmFwX3NvY2tldChzb2NrLCBz'
    'ZXJ2ZXJfaG9zdG5hbWU9ZG9tYWluKSBhcyBjb25uOgogICAgICAgICAgICAgICAgICAgICAgICBjb25uLnNlbmRhbGwoKCJI'
    'RUFEIC8gSFRUUC8xLjFcclxuSG9zdDogIiArIGRvbWFpbiArICJcclxuQ29ubmVjdGlvbjogY2xvc2VcclxuXHJcbiIpLmVu'
    'Y29kZSgpKQogICAgICAgICAgICAgICAgICAgICAgICBsaW5lID0gY29ubi5yZWN2KDI1Nikuc3BsaXQoYiJcclxuIiwgMSlb'
    'MF0KICAgICAgICAgICAgICAgICAgICAgICAgcGFydHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICAgICAgICAgICAgICAgICAg'
    'Y29kZSA9IGludChwYXJ0c1sxXSkgaWYgbGVuKHBhcnRzKSA+IDEgYW5kIHBhcnRzWzFdLmlzZGlnaXQoKSBlbHNlIDAKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgaWYgY29kZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB7ImRvbWFp'
    'biI6IGRvbWFpbiwgIm9rIjogVHJ1ZSwgImh0dHBfc3RhdHVzIjogY29kZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgImxhdGVuY3lfbXMiOiByb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydCkqMTAwMCl9CiAgICAgICAgICAg'
    'IGV4Y2VwdCAoT1NFcnJvciwgc3NsLlNTTEVycm9yKToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICBleGNlcHQgT1NF'
    'cnJvcjoKICAgICAgICBwYXNzCiAgICByZXR1cm4geyJkb21haW4iOiBkb21haW4sICJvayI6IEZhbHNlLCAiZXJyb3IiOiAi'
    'ZG5zX3RjcF9vcl90bHNfZmFpbGVkIiwKICAgICAgICAgICAgImxhdGVuY3lfbXMiOiByb3VuZCgodGltZS5tb25vdG9uaWMo'
    'KS1zdGFydCkqMTAwMCl9CgoKZGVmIHJlcG9ydChkb21haW49Tm9uZSk6CiAgICBpZiBub3Qgc3RvcmVkKCkuZ2V0KCJ0ZWxl'
    'bWV0cnkiKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCU0LjQsNCz0L3QvtGB0YLQuNC60LAg0LLRi9C60LvRjtGH'
    '0LXQvdCwLiDQktC60LvRjtGH0Lgg0LXRkSDRj9Cy0L3QviDQv9C10YDQtdC0INC+0YLQv9GA0LDQstC60L7QuS4iKQogICAg'
    'aWYgbm90IGNvbm5lY3RlZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0J7RgtGH0ZHRgiDQvtGC0L/RgNCw0LLQ'
    'u9GP0LXRgtGB0Y8g0YLQvtC70YzQutC+INCy0L3Rg9GC0YDQuCDRg9GB0YLQsNC90L7QstC70LXQvdC90L7Qs9C+IFN0YXJG'
    'aXZlIFZQTi4iKQogICAgZG9tYWlucyA9IFtkb21haW5fb25seShkb21haW4pXSBpZiBkb21haW4gZWxzZSBsaXN0KFJVX0RP'
    'TUFJTlMpCiAgICBwcm9iZXMgPSBbcHJvYmVfZG9tYWluKHgpIGZvciB4IGluIGRvbWFpbnNdCiAgICBib2R5ID0geyJzY2hl'
    'bWEiOiAxLCAiZXZlbnQiOiAic2l0ZV9yZXBvcnQiIGlmIGRvbWFpbiBlbHNlICJzYW1wbGUiLAogICAgICAgICAgICAidGlt'
    'ZSI6IGludCh0aW1lLnRpbWUoKSksICJtYW5hZ2VyIjogIjAuMi4yMyIsICJwbGF0Zm9ybSI6ICJsaW51eCIsCiAgICAgICAg'
    'ICAgICJwcm9iZXMiOiBwcm9iZXMsICJpcHNlYyI6ICJpbnN0YWxsZWQifQogICAgZW5kcG9pbnQoIi9yZXBvcnQiLCBib2R5'
    'KQogICAgcGF0Y2hfc3RhdGUoeyAibGFzdF9yZXBvcnQiOiB0aW1lLnN0cmZ0aW1lKCIlWS0lbS0lZCAlSDolTTolUyIsIHRp'
    'bWUuZ210aW1lKCkpICsgIiBVVEMifSkKICAgIHByaW50KGpzb24uZHVtcHMoeyJzZW50IjogVHJ1ZSwgInByb2JlcyI6IHBy'
    'b2Jlc30sIGVuc3VyZV9hc2NpaT1GYWxzZSkpCgoKZGVmIG1vbml0b3IoKToKICAgIHdoaWxlIHN0b3JlZCgpLmdldCgidGVs'
    'ZW1ldHJ5IikgYW5kIGNvbm5lY3RlZCgpOgogICAgICAgIHRyeToKICAgICAgICAgICAgZmx1c2hfdGVzdF9yZXBvcnQoKQog'
    'ICAgICAgICAgICByZXBvcnQoKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIHBhc3MKICAgICAgICB0'
    'aW1lLnNsZWVwKDYwKQogICAgaWYgc3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBhbmQgYWN0aXZlX2d1YXJkKCk6CiAgICAg'
    'ICAgdHJ5OiBxdWV1ZV9jb25uZWN0aW9uKCdkaXNjb25uZWN0ZWQnLCduZXR3b3JrJykKICAgICAgICBleGNlcHQgRXhjZXB0'
    'aW9uOiBwYXNzCgoKZGVmIGRpc3BhdGNoKGFwaSwgc2V0dGluZ3MsIGFjdGlvbiwgdGFyZ2V0PSIiKToKICAgIHRyeToKICAg'
    'ICAgICBpZiBhY3Rpb24gPT0gJ3Rva2VuLXNhdmUnIGFuZCB0dW5uZWw6CiAgICAgICAgICAgIHR1bm5lbC5zYXZlX3Rva2Vu'
    'KHRhcmdldCkKICAgICAgICAgICAgcHJpbnQoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvSDQvdCwINGN0YLQvtC8INGD'
    '0YHRgtGA0L7QudGB0YLQstC1LicpCiAgICAgICAgZWxpZiBhY3Rpb24gaW4gKCdjb25uZWN0JywgJ3JlcGFpcicpIGFuZCB0'
    'dW5uZWw6CiAgICAgICAgICAgIHR1bm5lbC5jb25uZWN0KHRhcmdldCwgcmVwYWlyPWFjdGlvbiA9PSAncmVwYWlyJykKICAg'
    'ICAgICBlbGlmIGFjdGlvbiA9PSAnZGlzY29ubmVjdCcgYW5kIHR1bm5lbDoKICAgICAgICAgICAgdHVubmVsLmRpc2Nvbm5l'
    'Y3QoKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJnbG9iYWwtdGVzdCI6IHN0YXJ0X2dsb2JhbF90ZXN0KCkKICAgICAgICBl'
    'bGlmIGFjdGlvbiA9PSAiY2FuY2VsLXRlc3QiOiBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1RfVU5JVF0sY2hlY2s9'
    'RmFsc2UpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImJhY2tlbmQtdXNlcnNwYWNlIjogc2VsZWN0X2JhY2tlbmQoInVzZXJz'
    'cGFjZSIpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImJhY2tlbmQta2VybmVsIjogc2VsZWN0X2JhY2tlbmQoImtlcm5lbCIp'
    'CiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInByZXBhcmUiOiBwcmVwYXJlKCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAiaW1w'
    'b3J0IjogaW1wb3J0X3Byb2ZpbGUoc2V0dGluZ3MsIHRhcmdldCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAib24iOiBvbihh'
    'cGksIHNldHRpbmdzKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJvZmYiOgogICAgICAgICAgICBpZiB0dW5uZWwgYW5kIHR1'
    'bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpOiB0dW5uZWwuZGlzY29ubmVjdCgpCiAgICAgICAgICAgIGVsc2U6IG9mZigpCiAg'
    'ICAgICAgZWxpZiBhY3Rpb24gPT0gInRlbGVtZXRyeS1vbiI6IHRlbGVtZXRyeShUcnVlKQogICAgICAgIGVsaWYgYWN0aW9u'
    'ID09ICJ0ZWxlbWV0cnktb2ZmIjogdGVsZW1ldHJ5KEZhbHNlKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJyZXBvcnQiOiBy'
    'ZXBvcnQodGFyZ2V0IG9yIE5vbmUpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gInNlbmQtZGlhZ25vc3RpY3MiOgogICAgICAg'
    'ICAgICBpZiBub3QgUk9PVC5qb2lucGF0aCgncHJvZmlsZS5qc29uJykuZXhpc3RzKCk6IHJhaXNlIFJ1bnRpbWVFcnJvcign'
    '0KHQvdCw0YfQsNC70LAg0LjQvNC/0L7RgNGC0LjRgNGD0Lkg0L/RgNC+0YTQuNC70YwuJykKICAgICAgICAgICAgaW5zdGFs'
    'bF9kZWxpdmVyeSgpCiAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ21hbnVhbCcsJ25vbmUnKQogICAgICAgICAgICBw'
    'cmludCgn0JTQuNCw0LPQvdC+0YHRgtC40LrQsCDRgdC+0YXRgNCw0L3QtdC90LAuINCf0YDRj9C80LDRjyDQvtGC0L/RgNCw'
    '0LLQutCwINCy0YvQv9C+0LvQvdGP0LXRgtGB0Y8g0LIg0YTQvtC90LUuJykKICAgICAgICBlbGlmIGFjdGlvbiA9PSAic3Rh'
    'dHVzIjogcHJpbnQoanNvbi5kdW1wcyhzdGF0dXMoKSwgZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAgICAgICBlbHNlOiByYWlz'
    'ZSBWYWx1ZUVycm9yKCLQndC10LjQt9Cy0LXRgdGC0L3QsNGPINGN0LrRgdC/0LXRgNC40LzQtdC90YLQsNC70YzQvdCw0Y8g'
    '0L7Qv9C10YDQsNGG0LjRjy4iKQogICAgZXhjZXB0IChWYWx1ZUVycm9yLCBSdW50aW1lRXJyb3IsIE9TRXJyb3IsIHN1YnBy'
    'b2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBhY3Rpb24gPT0gJ29uJyBhbmQgbm90IGdldGF0dHIo'
    'ZXhjLCdkaWFnbm9zdGljX3F1ZXVlZCcsRmFsc2UpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBpbnN0YWxs'
    'X2RlbGl2ZXJ5KCkKICAgICAgICAgICAgICAgIHF1ZXVlX2Nvbm5lY3Rpb24oJ3ByZXBhcmUnLGZhaWx1cmVfY29kZShleGMp'
    'KQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgcmFpc2UgYXBpLlZQTkVycm9yKHN0cihleGMp'
    'KSBmcm9tIGV4YwoKClRFU1RfVU5JVCA9ICdldmdlbml1bS1pa2V2Mi1nbG9iYWwtdGVzdC5zZXJ2aWNlJwpURVNUX1NUQVRF'
    'ID0gcGF0aGxpYi5QYXRoKCcvdmFyL2xpYi92cG4tbWFuYWdlci9zdGFyZml2ZS10ZXN0Lmpzb24nKQpQRU5ESU5HX1RFU1Qg'
    'PSBST09UIC8gJ3BlbmRpbmctZ2xvYmFsLXRlc3QuanNvbicKUlVfRE9NQUlOUyA9ICgneWFuZGV4LnJ1JywgJ21haWwucnUn'
    'LCAnd3d3LnJ0LnJ1JykKVEVTVF9CTE9DSyA9IGhhc2hsaWIuc2hha2VfMjU2KGInZXZnZW5pdW0tc3RhcmZpdmUtaW50ZWdy'
    'aXR5LXYxJykuZGlnZXN0KDY1NTM2KQoKCmRlZiB0ZXN0X3N0YXR1cygpOgogICAgdHJ5OgogICAgICAgIHN0YXRlPWpzb24u'
    'bG9hZHMoVEVTVF9TVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKToKICAgICAgICBy'
    'ZXR1cm4geydwaGFzZSc6J2lkbGUnLCdwcm9ncmVzcyc6MH0KICAgIGlmIHN0YXRlLmdldCgncGhhc2UnKT09J3J1bm5pbmcn'
    'IGFuZCBjbWQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLFRFU1RfVU5JVF0sY2hlY2s9RmFsc2UpLnJldHVybmNvZGU6CiAg'
    'ICAgICAgc3RhdGUudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsbWVzc2FnZT0n0KLQtdGB0YIg0L/RgNC10YDQstCw0L0u'
    'INCX0LDRidC40YLQsCBWUE4g0YHQvtGF0YDQsNC90Y/QtdGC0YHRjy4nKQogICAgcmV0dXJuIHN0YXRlCgoKZGVmIHRlc3Rf'
    'c3RhdGUoKipmaWVsZHMpOgogICAgdHJ5OiBzdGF0ZT1qc29uLmxvYWRzKFRFU1RfU1RBVEUucmVhZF90ZXh0KCkpCiAgICBl'
    'eGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6IHN0YXRlPXt9CiAgICB3cml0ZShURVNUX1NUQVRFLGpzb24uZHVtcHMoeyoq'
    'c3RhdGUsKipmaWVsZHN9LGVuc3VyZV9hc2NpaT1GYWxzZSkpCgoKZGVmIHRlc3RfcmVxdWVzdChwYXRoLCBkYXRhPU5vbmUs'
    'IGhlYWRlcnM9Tm9uZSwgdGltZW91dD0zMCk6CiAgICBjb250ZXh0PXNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZmls'
    'ZT1zdHIoUk9PVC8nY2EucGVtJykpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScp'
    'LHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgb3BlbmVyPXVybGxpYi5yZXF1ZXN0LmJ1aWxkX29wZW5lcih1cmxs'
    'aWIucmVxdWVzdC5Qcm94eUhhbmRsZXIoe30pLHVybGxpYi5yZXF1ZXN0LkhUVFBTSGFuZGxlcihjb250ZXh0PWNvbnRleHQp'
    'KQogICAgcmVxdWVzdD11cmxsaWIucmVxdWVzdC5SZXF1ZXN0KEhFQUxUSCtwYXRoLGRhdGE9ZGF0YSxoZWFkZXJzPWhlYWRl'
    'cnMgb3Ige30pCiAgICByZXR1cm4gb3BlbmVyLm9wZW4ocmVxdWVzdCx0aW1lb3V0PXRpbWVvdXQpCgoKZGVmIGV4cGVjdGVk'
    'X2hhc2goc2l6ZSwgb2Zmc2V0PTApOgogICAgZGlnZXN0PWhhc2hsaWIuc2hhMjU2KCkKICAgIHdoaWxlIHNpemU6CiAgICAg'
    'ICAgcGFydD1URVNUX0JMT0NLW29mZnNldCAlIGxlbihURVNUX0JMT0NLKTpdWzptaW4oc2l6ZSxsZW4oVEVTVF9CTE9DSykt'
    'b2Zmc2V0ICUgbGVuKFRFU1RfQkxPQ0spKV0KICAgICAgICBkaWdlc3QudXBkYXRlKHBhcnQpOyBzaXplLT1sZW4ocGFydCk7'
    'IG9mZnNldCs9bGVuKHBhcnQpCiAgICByZXR1cm4gZGlnZXN0LmhleGRpZ2VzdCgpCgoKZGVmIHRyYW5zZmVyX2Rvd25sb2Fk'
    'KHNpemUsIG9mZnNldD0wLCBsaW1pdD1Ob25lKToKICAgIHN0YXJ0PXRpbWUubW9ub3RvbmljKCk7IHJlY2VpdmVkPTA7IGRp'
    'Z2VzdD1oYXNobGliLnNoYTI1NigpCiAgICBoZWFkZXJzPXsnUmFuZ2UnOmYnYnl0ZXM9e29mZnNldH0tJ30gaWYgb2Zmc2V0'
    'IGVsc2Uge30KICAgIHdpdGggdGVzdF9yZXF1ZXN0KCcvYmxvYj9zaXplPScrc3RyKHNpemUpLGhlYWRlcnM9aGVhZGVycykg'
    'YXMgcmVzcG9uc2U6CiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9ICgyMDYgaWYgb2Zmc2V0IGVsc2UgMjAwKTogcmFp'
    'c2UgUnVudGltZUVycm9yKCdVbmV4cGVjdGVkIGZpbGUgcmVzcG9uc2UnKQogICAgICAgIGlmIG9mZnNldCBhbmQgcmVzcG9u'
    'c2UuaGVhZGVycy5nZXQoJ0NvbnRlbnQtUmFuZ2UnKSE9ZidieXRlcyB7b2Zmc2V0fS17c2l6ZS0xfS97c2l6ZX0nOgogICAg'
    'ICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ0ludmFsaWQgcmVzdW1lIHJhbmdlJykKICAgICAgICB0b3RhbD1zaXplLW9m'
    'ZnNldCBpZiBsaW1pdCBpcyBOb25lIGVsc2UgbWluKGxpbWl0LHNpemUtb2Zmc2V0KQogICAgICAgIHdoaWxlIHJlY2VpdmVk'
    'PHRvdGFsOgogICAgICAgICAgICBibG9jaz1yZXNwb25zZS5yZWFkKG1pbig2NTUzNix0b3RhbC1yZWNlaXZlZCkpCiAgICAg'
    'ICAgICAgIGlmIG5vdCBibG9jazogYnJlYWsKICAgICAgICAgICAgZGlnZXN0LnVwZGF0ZShibG9jayk7IHJlY2VpdmVkKz1s'
    'ZW4oYmxvY2spCiAgICAgICAgaW50ZWdyaXR5PXJlY2VpdmVkPT10b3RhbCBhbmQgZGlnZXN0LmhleGRpZ2VzdCgpPT1leHBl'
    'Y3RlZF9oYXNoKHRvdGFsLG9mZnNldCkKICAgICAgICBpZiBsaW1pdCBpcyBOb25lOgogICAgICAgICAgICBpbnRlZ3JpdHk9'
    'aW50ZWdyaXR5IGFuZCByZXNwb25zZS5oZWFkZXJzLmdldCgnWC1Db250ZW50LVNIQTI1NicpPT1kaWdlc3QuaGV4ZGlnZXN0'
    'KCkKICAgIGVsYXBzZWQ9bWF4KHRpbWUubW9ub3RvbmljKCktc3RhcnQsMC4wMDEpCiAgICByZXR1cm4geydraW5kJzonZG93'
    'bmxvYWQnLCdvayc6aW50ZWdyaXR5LCdpbnRlZ3JpdHknOmludGVncml0eSwnYnl0ZXMnOnJlY2VpdmVkLAogICAgICAgICAg'
    'ICAnc2l6ZSc6c2l6ZSwnb2Zmc2V0JzpvZmZzZXQsJ2VsYXBzZWRfbXMnOnJvdW5kKGVsYXBzZWQqMTAwMCksCiAgICAgICAg'
    'ICAgICdtYnBzX21pbGxpJzpyb3VuZChyZWNlaXZlZCo4L2VsYXBzZWQvMTAwMCl9CgoKZGVmIHRyYW5zZmVyX3VwbG9hZChz'
    'aXplKToKICAgIGRhdGE9KFRFU1RfQkxPQ0sqKChzaXplK2xlbihURVNUX0JMT0NLKS0xKS8vbGVuKFRFU1RfQkxPQ0spKSlb'
    'OnNpemVdCiAgICBzdGFydD10aW1lLm1vbm90b25pYygpCiAgICB3aXRoIHRlc3RfcmVxdWVzdCgnL3VwbG9hZCcsZGF0YT1k'
    'YXRhLGhlYWRlcnM9eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0nfSkgYXMgcmVzcG9uc2U6CiAg'
    'ICAgICAgcmVwbHk9anNvbi5sb2FkcyhyZXNwb25zZS5yZWFkKDQwOTYpKQogICAgZWxhcHNlZD1tYXgodGltZS5tb25vdG9u'
    'aWMoKS1zdGFydCwwLjAwMSkKICAgIGludGVncml0eT1yZXBseS5nZXQoJ3JlY2VpdmVkX2J5dGVzJyk9PXNpemUgYW5kIHJl'
    'cGx5LmdldCgnc2hhMjU2Jyk9PWhhc2hsaWIuc2hhMjU2KGRhdGEpLmhleGRpZ2VzdCgpCiAgICByZXR1cm4geydraW5kJzon'
    'dXBsb2FkJywnb2snOmludGVncml0eSwnaW50ZWdyaXR5JzppbnRlZ3JpdHksJ2J5dGVzJzpzaXplLAogICAgICAgICAgICAn'
    'ZWxhcHNlZF9tcyc6cm91bmQoZWxhcHNlZCoxMDAwKSwnbWJwc19taWxsaSc6cm91bmQoc2l6ZSo4L2VsYXBzZWQvMTAwMCl9'
    'CgoKZGVmIHBpbmdfdGVzdChzaXplPTU2LCBjb3VudD0yMCk6CiAgICBjcD1jbWQoWydwaW5nJywnLW4nLCctTScsJ2RvJywn'
    'LXMnLHN0cihzaXplKSwnLWMnLHN0cihjb3VudCksJy1pJywnMC4yJywnLVcnLCcyJywnMTAuNzcuMC4xJ10sY2hlY2s9RmFs'
    'c2UsdGltZW91dD00NSkKICAgIHBhY2tldHM9cmUuc2VhcmNoKHInKFxkKykgcGFja2V0cyB0cmFuc21pdHRlZCwgKFxkKykg'
    'cmVjZWl2ZWQnLGNwLnN0ZG91dCkKICAgIHNlbnQscmVjZWl2ZWQ9KGludCh4KSBmb3IgeCBpbiBwYWNrZXRzLmdyb3Vwcygp'
    'KSBpZiBwYWNrZXRzIGVsc2UgKGNvdW50LDApCiAgICByb3c9eydraW5kJzoncGluZycsJ29rJzpyZWNlaXZlZD09c2VudCwn'
    'c2VudCc6c2VudCwncmVjZWl2ZWQnOnJlY2VpdmVkLAogICAgICAgICAnbG9zc19taWxsaSc6cm91bmQoKHNlbnQtcmVjZWl2'
    'ZWQpKjEwMDAwMC9tYXgoc2VudCwxKSksJ3NpemUnOnNpemV9CiAgICBydHQ9cmUuc2VhcmNoKHInPSAoW1xkLl0rKS8oW1xk'
    'Ll0rKS8oW1xkLl0rKS8oW1xkLl0rKSBtcycsY3Auc3Rkb3V0KQogICAgaWYgcnR0OgogICAgICAgIHJvdy51cGRhdGUoe2tl'
    'eTpyb3VuZChmbG9hdCh2YWx1ZSkqMTAwMCkgZm9yIGtleSx2YWx1ZSBpbiB6aXAoCiAgICAgICAgICAgICgncnR0X21pbl91'
    'cycsJ3J0dF9hdmdfdXMnLCdydHRfbWF4X3VzJywncnR0X21kZXZfdXMnKSxydHQuZ3JvdXBzKCkpfSkKICAgIHJldHVybiBy'
    'b3cKCgpkZWYgdHJhbnNwb3J0X2NvdW50ZXJzKCk6CiAgICByZXN1bHQ9eydraW5kJzonY291bnRlcnMnLCdvayc6VHJ1ZX0K'
    'ICAgIHRyeToKICAgICAgICByYXc9c3dhbignLS1saXN0LXNhcycsJy0tcmF3Jykuc3Rkb3V0CiAgICAgICAgZm9yIHNvdXJj'
    'ZSx0YXJnZXQgaW4gKCgnYnl0ZXMtaW4nLCdieXRlc19pbicpLCgnYnl0ZXMtb3V0JywnYnl0ZXNfb3V0JyksKCdwYWNrZXRz'
    'LWluJywncGFja2V0c19pbicpLCgncGFja2V0cy1vdXQnLCdwYWNrZXRzX291dCcpKToKICAgICAgICAgICAgcmVzdWx0W3Rh'
    'cmdldF09c3VtKGludCh4KSBmb3IgeCBpbiByZS5maW5kYWxsKHInXGInK3NvdXJjZStyJz0oXGQrKScscmF3KSkKICAgICAg'
    'ICBsaW5lcz1wYXRobGliLlBhdGgoJy9wcm9jL25ldC9zbm1wJykucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpCiAgICAgICAg'
    'Zm9yIGZpcnN0LHNlY29uZCBpbiB6aXAobGluZXMsbGluZXNbMTpdKToKICAgICAgICAgICAgaWYgZmlyc3Quc3RhcnRzd2l0'
    'aCgnVGNwOicpIGFuZCBzZWNvbmQuc3RhcnRzd2l0aCgnVGNwOicpOgogICAgICAgICAgICAgICAgdmFsdWVzPWRpY3Qoemlw'
    'KGZpcnN0LnNwbGl0KClbMTpdLHNlY29uZC5zcGxpdCgpWzE6XSkpCiAgICAgICAgICAgICAgICBpZiAnUmV0cmFuc1NlZ3Mn'
    'IGluIHZhbHVlczoKICAgICAgICAgICAgICAgICAgICByZXN1bHRbJ3JldHJhbnNfc2VnbWVudHMnXT1pbnQodmFsdWVzWydS'
    'ZXRyYW5zU2VncyddKQogICAgICAgICAgICAgICAgICAgIHJlc3VsdFsnb3V0X3NlZ21lbnRzJ109aW50KHZhbHVlc1snT3V0'
    'U2VncyddKQogICAgICAgIGlmIGJhY2tlbmQoKT09J2tlcm5lbCc6CiAgICAgICAgICAgIHJlc3VsdFsneGZybV9lcnJvcnMn'
    'XT1zdW0oaW50KHguc3BsaXQoKVsxXSkgZm9yIHggaW4gcGF0aGxpYi5QYXRoKCcvcHJvYy9uZXQveGZybV9zdGF0JykucmVh'
    'ZF90ZXh0KCkuc3BsaXRsaW5lcygpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yKTogcmVz'
    'dWx0WydvayddPUZhbHNlCiAgICByZXR1cm4gcmVzdWx0CgoKZGVmIGZsdXNoX3Rlc3RfcmVwb3J0KCk6CiAgICBpZiBub3Qg'
    'c3RvcmVkKCkuZ2V0KCd0ZWxlbWV0cnknKSBvciBub3QgUEVORElOR19URVNULmV4aXN0cygpOiByZXR1cm4gRmFsc2UKICAg'
    'IGJvZHk9anNvbi5sb2FkcyhQRU5ESU5HX1RFU1QucmVhZF90ZXh0KCkpCiAgICBpZiBub3QgZGVsaXZlcl9yZXBvcnQoYm9k'
    'eSk6IHJldHVybiBGYWxzZQogICAgUEVORElOR19URVNULnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB0ZXN0X3N0YXRl'
    'KHNlbnQ9VHJ1ZSxtZXNzYWdlPSfQotC10YHRgiDQt9Cw0LLQtdGA0YjRkdC9LiDQntGC0YfRkdGCINC00L7RgdGC0LDQstC7'
    '0LXQvSDQvdCwIFN0YXJGaXZlLicpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBzdGFydF9nbG9iYWxfdGVzdCgpOgogICAgaWYg'
    'Y21kKFsnc3lzdGVtY3RsJywnaXMtYWN0aXZlJyxURVNUX1VOSVRdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlPT0wOgogICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIg0YPQttC1INCy0YvQv9C+0LvQ'
    'vdGP0LXRgtGB0Y8uJykKICAgIGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpOiByYWlzZSBSdW50aW1lRXJyb3Io'
    'J9CS0LrQu9GO0YfQuCDQstGA0LXQvNC10L3QvdGD0Y4g0LTQuNCw0LPQvdC+0YHRgtC40LrRgyDQtNC70Y8g0L7RgtC/0YDQ'
    'sNCy0LrQuCDRgNC10LfRg9C70YzRgtCw0YLQvtCyLicpCiAgICBpZiBub3QgY29ubmVjdGVkKCkgb3Igbm90IGFjdGl2ZV9n'
    'dWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC/0L7QtNC60LvRjtGH0LjRgdGMINC6IFN0YXJG'
    'aXZlLicpCiAgICBpZiBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgndGVzdF9hcGknKSE9MTogcmFpc2UgUnVudGltZUVycm9y'
    'KCfQodC90LDRh9Cw0LvQsCDQvtCx0L3QvtCy0LjRgtGMINGC0LXRgdGC0L7QstGL0Lkg0YHQtdGA0LLQuNGBIFN0YXJGaXZl'
    'LicpCiAgICBpZiBQRU5ESU5HX1RFU1QuZXhpc3RzKCkgYW5kIG5vdCBmbHVzaF90ZXN0X3JlcG9ydCgpOiByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ9Ce0LbQuNC00LDQtdGCINC+0YLQv9GA0LDQstC60Lgg0L/RgNC10LTRi9C00YPRidC40Lkg0L7RgtGH0ZHR'
    'gi4nKQogICAgdW5pdD0nJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZ2xvYmFsIFZQTiBzdGFiaWxpdHkgdGVzdApB'
    'ZnRlcj1ldmdlbml1bS1pa2V2Mi5zZXJ2aWNlCltTZXJ2aWNlXQpUeXBlPWV4ZWMKRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jp'
    'bi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtZ2xvYmFsLXRlc3QKU3RhbmRhcmRPdXRwdXQ9bnVsbApTdGFuZGFyZEVycm9y'
    'PW51bGwKVGltZW91dFN0b3BTZWM9MTIKUnVudGltZU1heFNlYz05MDAKUmVzdGFydD1ubwonJycKICAgIHdyaXRlKHBhdGhs'
    'aWIuUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1RFU1RfVU5JVCx1bml0LDBvNjQ0KQogICAgY21kKFsnc3lzdGVtY3Rs'
    'JywnZGFlbW9uLXJlbG9hZCddKQogICAgdGVzdF9zdGF0ZShwaGFzZT0ncnVubmluZycscHJvZ3Jlc3M9MCxzZW50PUZhbHNl'
    'LHBhc3NlZD0wLGZhaWxlZD0wLGR1cmF0aW9uX3M9MCxtZXNzYWdlPSfQl9Cw0L/Rg9GB0Log0YLQtdGB0YLQsCcscnVuPW9z'
    'LnVyYW5kb20oMTIpLmhleCgpLHN0YXJ0ZWQ9aW50KHRpbWUudGltZSgpKSkKICAgIHRyeTogY21kKFsnc3lzdGVtY3RsJywn'
    'c3RhcnQnLFRFU1RfVU5JVF0pCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHRlc3Rfc3RhdGUocGhhc2U9J2ZhaWxl'
    'ZCcsbWVzc2FnZT0n0J3QtSDRg9C00LDQu9C+0YHRjCDQt9Cw0L/Rg9GB0YLQuNGC0Ywg0YLQtdGB0YIuJyk7IHJhaXNlCiAg'
    'ICBwcmludCgn0JPQu9C+0LHQsNC70YzQvdGL0Lkg0YLQtdGB0YIg0LfQsNC/0YPRidC10L0g0LIg0YTQvtC90LUuINCY0L3R'
    'gtC10YDQvdC10YIg0L3QtdGB0LrQvtC70YzQutC+INGA0LDQtyDQv9GA0LXRgNCy0ZHRgtGB0Y87IGtpbGwgc3dpdGNoINC+'
    '0YHRgtCw0ZHRgtGB0Y8g0LLQutC70Y7Rh9GR0L3QvdGL0LwuJykKCgpjbGFzcyBUZXN0Q2FuY2VsbGVkKEV4Y2VwdGlvbik6'
    'IHBhc3MKCgpkZWYgcnVuX2dsb2JhbF90ZXN0KCk6CiAgICBpbXBvcnQgc2lnbmFsCiAgICBmcm9tIGNvbmN1cnJlbnQuZnV0'
    'dXJlcyBpbXBvcnQgVGhyZWFkUG9vbEV4ZWN1dG9yCiAgICBkZWYgY2FuY2VsKCpfKTogcmFpc2UgVGVzdENhbmNlbGxlZCgp'
    'CiAgICBvbGQ9c2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSxjYW5jZWwpCiAgICByZWNvcmRzPVtdOyBvdXRjb21lPSdj'
    'b21wbGV0ZWQnOyBzdGFydGVkPXRpbWUubW9ub3RvbmljKCkKICAgIGRlZiBzdGFnZShwcm9ncmVzcyxtZXNzYWdlKTogdGVz'
    'dF9zdGF0ZShwaGFzZT0ncnVubmluZycscHJvZ3Jlc3M9cHJvZ3Jlc3MsbWVzc2FnZT1tZXNzYWdlKQogICAgZGVmIG1lYXN1'
    'cmUoa2luZCxvcGVyYXRpb24sKipmaWVsZHMpOgogICAgICAgIGJlZm9yZT10aW1lLm1vbm90b25pYygpCiAgICAgICAgdHJ5'
    'OiByb3c9b3BlcmF0aW9uKCkKICAgICAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogcmFpc2UKICAgICAgICBleGNlcHQgRXhj'
    'ZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgZXJyb3I9J290aGVyJwogICAgICAgICAgICBpZiBpc2luc3RhbmNlKGV4Yyx1'
    'cmxsaWIuZXJyb3IuSFRUUEVycm9yKTogZXJyb3I9J2h0dHAnCiAgICAgICAgICAgIGVsaWYgaXNpbnN0YW5jZShleGMsKFRp'
    'bWVvdXRFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSk6IGVycm9yPSd0aW1lb3V0JwogICAgICAgICAgICBlbGlm'
    'IGlzaW5zdGFuY2UoZXhjLHNzbC5TU0xFcnJvcik6IGVycm9yPSd0bHMnCiAgICAgICAgICAgIGVsaWYgaXNpbnN0YW5jZShl'
    'eGMsT1NFcnJvcik6IGVycm9yPSduZXR3b3JrJwogICAgICAgICAgICByb3c9eydraW5kJzpraW5kLCdvayc6RmFsc2UsJ2Vy'
    'cm9yJzplcnJvcn0KICAgICAgICAgICAgaWYgaXNpbnN0YW5jZShleGMsdXJsbGliLmVycm9yLkhUVFBFcnJvcik6IHJvd1sn'
    'aHR0cF9zdGF0dXMnXT1leGMuY29kZQogICAgICAgIHJvdy5zZXRkZWZhdWx0KCdlbGFwc2VkX21zJyxyb3VuZCgodGltZS5t'
    'b25vdG9uaWMoKS1iZWZvcmUpKjEwMDApKQogICAgICAgIHJvd1snYXRfbXMnXT1yb3VuZCgodGltZS5tb25vdG9uaWMoKS1z'
    'dGFydGVkKSoxMDAwKQogICAgICAgIHJvdy51cGRhdGUoZmllbGRzKTsgcmVjb3Jkcy5hcHBlbmQocm93KTsgcmV0dXJuIHJv'
    'dwogICAgZGVmIHJlY29ubmVjdChyZXN0YXJ0PUZhbHNlKToKICAgICAgICBiZWZvcmU9dGltZS5tb25vdG9uaWMoKQogICAg'
    'ICAgIGlmIHJlc3RhcnQ6CiAgICAgICAgICAgIGNhbmRpZGF0ZXM9c29ja2V0LmdldGFkZHJpbmZvKCd5YW5kZXgucnUnLDQ0'
    'Myxzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgICAgIGFkZHJlc3M9bmV4dCh4WzRdWzBdIGZv'
    'ciB4IGluIGNhbmRpZGF0ZXMgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeFs0XVswXSkuaXNfZ2xvYmFsKQogICAgICAgICAg'
    'ICBjbWQoWydzeXN0ZW1jdGwnLCdzdG9wJyxVTklUXSkKICAgICAgICAgICAgbGVha2VkPUZhbHNlCiAgICAgICAgICAgIHRy'
    'eToKICAgICAgICAgICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChhZGRyZXNzLDQ0MyksdGltZW91dD0y'
    'KTogbGVha2VkPVRydWUKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6IHBhc3MKICAgICAgICAgICAgcmVjb3Jkcy5hcHBl'
    'bmQoeydraW5kJzonZ3VhcmQnLCdvayc6YWN0aXZlX2d1YXJkKCkgYW5kIG5vdCBsZWFrZWR9KQogICAgICAgICAgICAjIE5l'
    'dmVyIHJlbW92ZSB0aGUgZ3VhcmQsIGV2ZW4gZHVyaW5nIGEgZGVsaWJlcmF0ZSBkYWVtb24gZmFpbHVyZS4KICAgICAgICAg'
    'ICAgaWYgbm90IGFjdGl2ZV9ndWFyZCgpOiByYWlzZSBSdW50aW1lRXJyb3IoJ0d1YXJkIG1pc3NpbmcnKQogICAgICAgICAg'
    'ICBjbWQoWydzeXN0ZW1jdGwnLCdzdGFydCcsVU5JVF0pCiAgICAgICAgICAgIHdhaXRfdXNlcnNwYWNlKCkKICAgICAgICAg'
    'ICAgc3dhbignLS1sb2FkLWNyZWRzJywnLS1maWxlJyxST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgICAgICAgICBzd2Fu'
    'KCctLWxvYWQtY29ubnMnLCctLWZpbGUnLFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgZWxzZToKICAgICAgICAg'
    'ICAgc3dhbignLS10ZXJtaW5hdGUnLCctLWlrZScsJ3N0YXJmaXZlJyxjaGVjaz1GYWxzZSkKICAgICAgICBzd2FuKCctLWlu'
    'aXRpYXRlJywnLS1jaGlsZCcsJ3N0YXJmaXZlLW5ldCcsdGltZW91dD01NSkKICAgICAgICBnb29kPWNvbm5lY3RlZCgpIGFu'
    'ZCBlbmRwb2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUnCiAgICAgICAgcmV0dXJu'
    'IHsna2luZCc6J2RhZW1vbl9yZXN0YXJ0JyBpZiByZXN0YXJ0IGVsc2UgJ3JlY29ubmVjdCcsJ29rJzpnb29kLCdlbGFwc2Vk'
    'X21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1iZWZvcmUpKjEwMDApfQogICAgZGVmIGNvbnRyb2woKToKICAgICAgICB3'
    'aXRoIHRlc3RfcmVxdWVzdCgnL2NvbnRyb2wnLHRpbWVvdXQ9NDUpIGFzIHJlc3BvbnNlOiBkYXRhPWpzb24ubG9hZHMocmVz'
    'cG9uc2UucmVhZCgxNjM4NCkpCiAgICAgICAgcmVjb3Jkcy5hcHBlbmQoeydraW5kJzonc2VydmVyX2NvbnRyb2wnLCdvayc6'
    'VHJ1ZSwqKmRhdGFbJ21ldHJpY3MnXX0pCiAgICAgICAgZm9yIHByb2JlIGluIGRhdGFbJ3Byb2JlcyddOiByZWNvcmRzLmFw'
    'cGVuZCh7J2tpbmQnOidzZXJ2ZXJfY29udHJvbCcsKipwcm9iZX0pCiAgICAgICAgcmV0dXJuIHsna2luZCc6J2hlYWx0aCcs'
    'J29rJzpUcnVlfQogICAgdHJ5OgogICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLE1PTklUT1JdLGNoZWNrPUZhbHNl'
    'KQogICAgICAgICMgVXNlIFJ1c3NpYW4gRE5TIGZvciB0aGlzIHRlc3QgZXZlbiBvbiBhIHNlc3Npb24gY3JlYXRlZCBieSBh'
    'biBvbGRlciBjbGllbnQuCiAgICAgICAgaWYgbm90IChST09ULydyZXNvbHYtYmFja3VwJykuZXhpc3RzKCkgYW5kIG5vdCAo'
    'Uk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKTogc2V0X2RucygpCiAgICAgICAgZWxpZiAoUk9PVC8ncmVz'
    'b2x2ZWQtYmFja3VwLmpzb24nKS5leGlzdHMoKToKICAgICAgICAgICAgaW50ZXJmYWNlPWpzb24ubG9hZHMoKFJPT1QvJ3Jl'
    'c29sdmVkLWJhY2t1cC5qc29uJykucmVhZF90ZXh0KCkpWydpZmFjZSddCiAgICAgICAgICAgIGNtZChbJ3Jlc29sdmVjdGwn'
    'LCdkbnMnLGludGVyZmFjZSwnNzcuODguOC44JywnNzcuODguOC4xJ10pCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcGF0'
    'aGxpYi5QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykud3JpdGVfdGV4dCgnbmFtZXNlcnZlciA3Ny44OC44Ljhcbm5hbWVzZXJ2'
    'ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAgICAgIHN0YWdlKDMsJ9Ca0L7QvdGC'
    '0YDQvtC70YzQvdGL0LUg0LfQsNC80LXRgNGLIFN0YXJGaXZlINC4INGA0L7RgdGB0LjQudGB0LrQuNGFINGB0LXRgNCy0LjR'
    'gdC+0LInKQogICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsY29udHJvbCk7IHJlY29yZHMuYXBwZW5kKHRyYW5zcG9ydF9jb3Vu'
    'dGVycygpKQogICAgICAgIGZvciBkb21haW4gaW4gUlVfRE9NQUlOUzogbWVhc3VyZSgncnVfcHJvYmUnLGxhbWJkYSBkPWRv'
    'bWFpbjp7J2tpbmQnOidydV9wcm9iZScsKipwcm9iZV9kb21haW4oZCl9KQogICAgICAgIHN0YWdlKDEyLCfQl9Cw0LTQtdGA'
    '0LbQutC4LCDQv9C+0YLQtdGA0Lgg0Lgg0YDQsNC30LzQtdGA0Ysg0L/QsNC60LXRgtC+0LInKQogICAgICAgIGZvciBzaXpl'
    'IGluICg1NiwxMjAwLDEzNjApOiBtZWFzdXJlKCdwaW5nJyxsYW1iZGEgcz1zaXplOnBpbmdfdGVzdChzKSkKICAgICAgICBm'
    'b3IgYXR0ZW1wdCBpbiByYW5nZSgxMik6CiAgICAgICAgICAgIGJlZm9yZT10aW1lLm1vbm90b25pYygpCiAgICAgICAgICAg'
    'IG1lYXN1cmUoJ2hlYWx0aCcsbGFtYmRhOnsna2luZCc6J2hlYWx0aCcsJ29rJzplbmRwb2ludCgnL2hlYWx0aCcpLmdldCgn'
    'c2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUnfSkKICAgICAgICAgICAgdGltZS5zbGVlcCgwLjI1KQogICAgICAgIHN0'
    'YWdlKDI1LCfQodC60LDRh9C40LLQsNC90LjQtSDQuCDQvtGC0L/RgNCw0LLQutCwINGE0LDQudC70L7Qsjog0L/RgNC+0LLQ'
    'tdGA0LrQsCBTSEEtMjU2JykKICAgICAgICBmb3Igc2l6ZSBpbiAoNjU1MzYsMTA0ODU3Niw4Mzg4NjA4LDMzNTU0NDMyKTog'
    'bWVhc3VyZSgnZG93bmxvYWQnLGxhbWJkYSBzPXNpemU6dHJhbnNmZXJfZG93bmxvYWQocykpCiAgICAgICAgZm9yIHNpemUg'
    'aW4gKDUyNDI4OCw0MTk0MzA0KTogbWVhc3VyZSgndXBsb2FkJyxsYW1iZGEgcz1zaXplOnRyYW5zZmVyX3VwbG9hZChzKSkK'
    'ICAgICAgICBzdGFnZSg0MCwn0JTQvtC60LDRh9C60LAg0YTQsNC50LvQsCDQv9C+0YHQu9C1INGA0LDQt9GA0YvQstCwINC4'
    'INC/0LXRgNC10L/QvtC00LrQu9GO0YfQtdC90LjRjycpCiAgICAgICAgbWVhc3VyZSgncmVzdW1lJyxsYW1iZGE6eyoqdHJh'
    'bnNmZXJfZG93bmxvYWQoODM4ODYwOCxsaW1pdD0zMTQ1NzI4KSwna2luZCc6J3Jlc3VtZSd9KQogICAgICAgIG1lYXN1cmUo'
    'J3JlY29ubmVjdCcscmVjb25uZWN0KQogICAgICAgIG1lYXN1cmUoJ3Jlc3VtZScsbGFtYmRhOnsqKnRyYW5zZmVyX2Rvd25s'
    'b2FkKDgzODg2MDgsb2Zmc2V0PTMxNDU3MjgpLCdraW5kJzoncmVzdW1lJ30pCiAgICAgICAgc3RhZ2UoNTAsJ9Cf0LDRgNCw'
    '0LvQu9C10LvRjNC90LDRjyDQv9C10YDQtdC00LDRh9CwINCyINC+0LHQtSDRgdGC0L7RgNC+0L3RiycpCiAgICAgICAgd2l0'
    'aCBUaHJlYWRQb29sRXhlY3V0b3IobWF4X3dvcmtlcnM9MykgYXMgcG9vbDoKICAgICAgICAgICAgZnV0dXJlcz1bcG9vbC5z'
    'dWJtaXQodHJhbnNmZXJfZG93bmxvYWQsODM4ODYwOCkscG9vbC5zdWJtaXQodHJhbnNmZXJfZG93bmxvYWQsODM4ODYwOCks'
    'cG9vbC5zdWJtaXQodHJhbnNmZXJfdXBsb2FkLDQxOTQzMDQpXQogICAgICAgICAgICBmb3IgZnV0dXJlIGluIGZ1dHVyZXM6'
    'IG1lYXN1cmUoJ3BhcmFsbGVsJyxsYW1iZGEgZj1mdXR1cmU6eyoqZi5yZXN1bHQoKSwna2luZCc6J3BhcmFsbGVsJ30pCiAg'
    'ICAgICAgc3RhZ2UoNjIsJ9CU0LvQuNGC0LXQu9GM0L3QsNGPINC/0LXRgNC10LTQsNGH0LA6INC00L4gNjAg0YHQtdC60YPQ'
    'vdC0IC8gNjQg0JzQuNCRJykKICAgICAgICBsb2FkX3N0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKTsgdW50aWw9bG9hZF9zdGFy'
    'dGVkKzYwOyBjb3VudD0wCiAgICAgICAgd2hpbGUgdGltZS5tb25vdG9uaWMoKTx1bnRpbCBhbmQgY291bnQ8MTY6CiAgICAg'
    'ICAgICAgIG1lYXN1cmUoJ2Rvd25sb2FkJyxsYW1iZGE6dHJhbnNmZXJfZG93bmxvYWQoNDE5NDMwNCkpOyBjb3VudCs9MQog'
    'ICAgICAgICAgICBtZWFzdXJlKCdoZWFsdGgnLGxhbWJkYTp7J2tpbmQnOidoZWFsdGgnLCdvayc6ZW5kcG9pbnQoJy9oZWFs'
    'dGgnKS5nZXQoJ3NlcnZpY2UnKT09J2V2Z2VuaXVtLXN0YXJmaXZlJ30pCiAgICAgICAgICAgIHRpbWUuc2xlZXAobWF4KDAs'
    'bG9hZF9zdGFydGVkK2NvdW50KjQtdGltZS5tb25vdG9uaWMoKSkpCiAgICAgICAgc3RhZ2UoNzUsJ9Cf0YDQvtGB0YLQvtC5'
    'IDQ1INGB0LXQutGD0L3QtCDQuCDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1INCw0LrRgtC40LLQvdC+0YHRgtC4JykK'
    'ICAgICAgICB0aW1lLnNsZWVwKDQ1KQogICAgICAgIG1lYXN1cmUoJ2lkbGUnLGxhbWJkYTp7J2tpbmQnOidpZGxlJywnb2sn'
    'OmVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFyZml2ZScsJ2VsYXBzZWRfbXMnOjQ1'
    'MDAwfSkKICAgICAgICBzdGFnZSg4Miwn0J/Rj9GC0Ywg0L/QvtCy0YLQvtGA0L3Ri9GFINC/0L7QtNC60LvRjtGH0LXQvdC4'
    '0LknKQogICAgICAgIGZvciBhdHRlbXB0IGluIHJhbmdlKDUpOgogICAgICAgICAgICBtZWFzdXJlKCdyZWNvbm5lY3QnLHJl'
    'Y29ubmVjdCxhdHRlbXB0PWF0dGVtcHQrMSk7IHRpbWUuc2xlZXAoMSkKICAgICAgICBzdGFnZSg5Miwn0J/QtdGA0LXQt9Cw'
    '0L/Rg9GB0LogVlBOLdC00LXQvNC+0L3QsCDRgSDRgdC+0YXRgNCw0L3QtdC90LjQtdC8IGtpbGwgc3dpdGNoJykKICAgICAg'
    'ICBtZWFzdXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkKICAgICAgICByZWNvcmRzLmFwcGVu'
    'ZCh7J2tpbmQnOidndWFyZCcsJ29rJzphY3RpdmVfZ3VhcmQoKX0pCiAgICAgICAgc3RhZ2UoOTYsJ9CX0LDQutC70Y7Rh9C4'
    '0YLQtdC70YzQvdGL0LUg0LfQsNC80LXRgNGLINC4INC+0YLQv9GA0LDQstC60LAg0L7RgtGH0ZHRgtCwJykKICAgICAgICBm'
    'b3IgZG9tYWluIGluIFJVX0RPTUFJTlM6IG1lYXN1cmUoJ3J1X3Byb2JlJyxsYW1iZGEgZD1kb21haW46eydraW5kJzoncnVf'
    'cHJvYmUnLCoqcHJvYmVfZG9tYWluKGQpfSkKICAgICAgICBtZWFzdXJlKCdoZWFsdGgnLGNvbnRyb2wpOyByZWNvcmRzLmFw'
    'cGVuZCh0cmFuc3BvcnRfY291bnRlcnMoKSkKICAgICAgICBpZiBhbnkobm90IHguZ2V0KCdvaycpIGZvciB4IGluIHJlY29y'
    'ZHMpOiBvdXRjb21lPSdmYWlsZWQnCiAgICBleGNlcHQgVGVzdENhbmNlbGxlZDogb3V0Y29tZT0nY2FuY2VsbGVkJwogICAg'
    'ZXhjZXB0IEV4Y2VwdGlvbjogb3V0Y29tZT0nZmFpbGVkJwogICAgZmluYWxseToKICAgICAgICAjIFJlY292ZXIgb25seSBv'
    'dXIgZGFlbW9uL3Nlc3Npb24uIE5ldmVyIGRpc2FibGUgdGhlIGd1YXJkIG9yIHJlc3RvcmUgZGlyZWN0IHRyYWZmaWMuCiAg'
    'ICAgICAgaWYgb3V0Y29tZSE9J2NhbmNlbGxlZCcgYW5kIG5vdCBjb25uZWN0ZWQoKToKICAgICAgICAgICAgdHJ5OiBtZWFz'
    'dXJlKCdkYWVtb25fcmVzdGFydCcsbGFtYmRhOnJlY29ubmVjdChUcnVlKSkKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlv'
    'bjogcGFzcwogICAgICAgIGJvZHk9eydzY2hlbWEnOjEsJ2V2ZW50JzonZ2xvYmFsX3Rlc3QnLCdtYW5hZ2VyJzonMC4yLjIz'
    'JywncnVuJzp0ZXN0X3N0YXR1cygpLmdldCgncnVuJyxvcy51cmFuZG9tKDEyKS5oZXgoKSksJ291dGNvbWUnOm91dGNvbWUs'
    'J2R1cmF0aW9uX21zJzpyb3VuZCgodGltZS5tb25vdG9uaWMoKS1zdGFydGVkKSoxMDAwKSwncmVjb3Jkcyc6cmVjb3Jkc1s6'
    'MjU2XX0KICAgICAgICB3cml0ZShQRU5ESU5HX1RFU1QsanNvbi5kdW1wcyhib2R5KSkKICAgICAgICB0ZXN0X3N0YXRlKHBo'
    'YXNlPW91dGNvbWUscHJvZ3Jlc3M9MTAwLHNlbnQ9RmFsc2UsZHVyYXRpb25fcz1yb3VuZCh0aW1lLm1vbm90b25pYygpLXN0'
    'YXJ0ZWQpLAogICAgICAgICAgICAgICAgICAgcGFzc2VkPXN1bShib29sKHguZ2V0KCdvaycpKSBmb3IgeCBpbiByZWNvcmRz'
    'KSxmYWlsZWQ9c3VtKG5vdCB4LmdldCgnb2snKSBmb3IgeCBpbiByZWNvcmRzKSwKICAgICAgICAgICAgICAgICAgIG1lc3Nh'
    'Z2U9J9Ce0YLRh9GR0YIg0YHQvtGF0YDQsNC90ZHQvS4g0J7QttC40LTQsNC10YIg0L7RgtC/0YDQsNCy0LrQuCDRh9C10YDQ'
    'tdC3IFN0YXJGaXZlLicpCiAgICAgICAgdHJ5OiBmbHVzaF90ZXN0X3JlcG9ydCgpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlv'
    'bjoga2lja19kZWxpdmVyeSgpCiAgICAgICAgaWYgY29ubmVjdGVkKCkgYW5kIHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jyk6'
    'CiAgICAgICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JyxNT05JVE9SXSxjaGVjaz1GYWxzZSkKICAgICAgICBzaWdu'
    'YWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLG9sZCkK'
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
