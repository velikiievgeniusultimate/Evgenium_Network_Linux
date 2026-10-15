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

MANAGER_VERSION = "0.3.0-ru.2"

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
    'ICAgICAgICAgICB0ZXh0OiAi0J7QtNC40L0g0YLRg9C90L3QtdC70Ywg0KDQvtGB0YHQuNGPIOKGkiDQoNC+0YHRgdC40Y8u'
    'INCh0L7RhdGA0LDQvdC40YLQtSDRgtC+0LrQtdC9INC4INC/0L7QtNC60LvRjtGH0LjRgtC1INGD0YHRgtGA0L7QudGB0YLQ'
    'stC+LiIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZDsgd3Jh'
    'cE1vZGU6IFRleHQuV29yZFdyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCi0L7QutC10L0g0LrQu9C40LXQvdGC0LAiOyBjb2xv'
    'cjogcm9vdC50ZXh0TWFpbjsgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBpZDogc3RhcmZpdmVUb2tlbgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBpbXBsaWNpdEhlaWdodDogNDIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsZWZ0'
    'UGFkZGluZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByaWdodFBhZGRpbmc6IDEy'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDE0CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE1haW4KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWRpdXM6IDEwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRva2VuTG9ja2VkID8gIiNmMGY4ZmMiIDogcm9vdC5zdXJmYWNlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJvcmRlci53aWR0aDogMQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBib3JkZXIuY29sb3I6IHN0YXJmaXZlVG9rZW4uYWN0aXZlRm9j'
    'dXMgPyByb290LmFjY2VudCA6IHJvb3QuYm9yZGVyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBsYWNlaG9sZGVyVGV4dDogcm9vdC50'
    'b2tlbkxvY2tlZCA/IFN0cmluZygocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkudG9rZW5faGludCB8fCAi0KLQvtC6'
    '0LXQvSDRgdC+0YXRgNCw0L3RkdC9IikgOiAi0JLRgdGC0LDQstGM0YLQtSDRgtC+0LrQtdC9IEVWTjEt4oCmIgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVjaG9Nb2RlOiBUZXh0SW5wdXQuUGFzc3dvcmQKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZWFkT25seTogcm9vdC50b2tlbkxvY2tlZAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdEJ5TW91c2U6ICFyb290LnRva2VuTG9ja2VkCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZDogIXJvb3QuYnVzeSAmJiAhQm9vbGVh'
    'bigocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkucnVubmluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBtYXhpbXVtTGVuZ3RoOiA2NAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEFjY2Vzc2libGUubmFtZTogItCi0L7QutC10L0g0LrQu9C40LXQvdGC0LAiCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgb25BY2NlcHRlZDogdG9rZW5Db25maXJtLmNvbmZpcm0oKQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1'
    'dHRvbiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IHRva2VuQ29uZmlybQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhYmVsOiByb290LnRva2VuTG9ja2VkID8gItCY0LfQ'
    'vNC10L3QuNGC0YwiIDogItCf0L7QtNGC0LLQtdGA0LTQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgcHJpbWFyeTogIXJvb3QudG9rZW5Mb2NrZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVs'
    'IHx8IHt9KS5ydW5uaW5nKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAmJiAocm9v'
    'dC50b2tlbkxvY2tlZCB8fCAvXkVWTjEtW0EtWmEtejAtOV8tXXs0M30kLy50ZXN0KHN0YXJmaXZlVG9rZW4udGV4dC50cmlt'
    'KCkpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZ1bmN0aW9uIGNvbmZpcm0oKSB7CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmICghZW5hYmxlZEJ1dHRvbikgcmV0dXJu'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyb290LnRva2VuTG9ja2VkKSB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LnRva2VuRWRpdGluZyA9'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXJmaXZlVG9rZW4u'
    'Zm9yY2VBY3RpdmVGb2N1cygpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gZWxz'
    'ZSB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmFjdGlvbih7YWN0'
    'aW9uOiAiZXhwZXJpbWVudGFsX3Rva2VuLXNhdmUiLCB0YXJnZXQ6IHN0YXJmaXZlVG9rZW4udGV4dC50cmltKCl9LCBmdW5j'
    'dGlvbigpIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGFyZml2'
    'ZVRva2VuLmNsZWFyKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBy'
    'b290LnRva2VuRWRpdGluZyA9IGZhbHNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIG9uQ2xpY2tlZDogY29uZmlybSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBpZDogdG9rZW5DYW5jZWwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBsYWJlbDogItCe0YLQvNC10L3QsCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB2aXNpYmxlOiByb290LnRva2VuRWRpdGluZyAmJiByb290LnRva2VuU2F2ZWQKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiB7IHN0YXJmaXZlVG9rZW4uY2xlYXIoKTsgcm9vdC50b2tlbkVkaXRpbmcg'
    'PSBmYWxzZSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5Xb3JkV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdGV4dDogcm9vdC50b2tlbkxvY2tlZCA/ICLQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0g0L3Q'
    'sCDRg9GB0YLRgNC+0LnRgdGC0LLQtS4g0J/RgNC+0LLQtdGA0LrQsCDQvdCwINGB0LXRgNCy0LXRgNC1IOKAlCDQv9GA0Lgg'
    '0L/QvtC00LrQu9GO0YfQtdC90LjQuC4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBy'
    'b290LnRva2VuRWRpdGluZyA/ICLQktGB0YLQsNCy0YzRgtC1INC90L7QstGL0Lkg0YLQvtC60LXQvSDQuCDQvdCw0LbQvNC4'
    '0YLQtSDCq9Cf0L7QtNGC0LLQtdGA0LTQuNGC0YzCuy4g0JTQviDRgdC+0YXRgNCw0L3QtdC90LjRjyDQtNC10LnRgdGC0LLR'
    'g9C10YIg0L/RgNC10LbQvdC40Lkg0YLQvtC60LXQvS4iCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgOiAi0KLQvtC60LXQvSDQtdGJ0ZEg0L3QtSDRgdC+0YXRgNCw0L3RkdC9LiDQktGB0YLQsNCy0YzRgtC1INC10LPQ'
    'viDQuCDQvdCw0LbQvNC40YLQtSDCq9Cf0L7QtNGC0LLQtdGA0LTQuNGC0YzCuy4iCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50b2tlbkxvY2tlZCA/IHJvb3QuZ29vZCA6IHJvb3QudGV4dE11dGVkCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Um93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDEyCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBsYWJlbDogQm9vbGVhbigocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkucnVubmluZykg'
    'PyAi0J7RgtC60LvRjtGH0LjRgtGMIiA6ICLQn9C+0LTQutC70Y7Rh9C40YLRjCIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiAhQm9vbGVhbigocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkucnVu'
    'bmluZykKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5i'
    'dXN5ICYmIChCb29sZWFuKChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5ydW5uaW5nKSB8fCByb290LnRva2VuTG9j'
    'a2VkKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24o'
    'e2FjdGlvbjogQm9vbGVhbigocm9vdC5leHBlcmltZW50LnR1bm5lbCB8fCB7fSkucnVubmluZykgPyAiZXhwZXJpbWVudGFs'
    'X2Rpc2Nvbm5lY3QiIDogImV4cGVyaW1lbnRhbF9jb25uZWN0In0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYWJlbDogItCf0L7Rh9C40L3QuNGC0YwiCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiByb290LnRva2Vu'
    'TG9ja2VkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmFjdGlv'
    'bih7YWN0aW9uOiAiZXhwZXJpbWVudGFsX3JlcGFpciJ9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJlY3RhbmdsZSB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IExheW91dC5wcmVmZXJyZWRIZWlnaHQ6IDE7IGNv'
    'bG9yOiByb290LmJvcmRlciB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi'
    '0KHRgtGA0L7QutCwINGB0L7RgdGC0L7Rj9C90LjRjyI7IGNvbG9yOiByb290LnRleHRNYWluOyBmb250LndlaWdodDogRm9u'
    'dC5EZW1pQm9sZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEFyZWEgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgTGF5b3V0Lm1pbmltdW1IZWlnaHQ6IDEyMAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgcmVhZE9ubHk6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNl'
    'bGVjdEJ5TW91c2U6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0'
    'RWRpdC5XcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiBTdHJpbmcoKHJvb3QuZXhw'
    'ZXJpbWVudC50dW5uZWwgfHwge30pLm1lc3NhZ2UgfHwgItCS0LLQtdC00LjRgtC1INGC0L7QutC10L0g0LrQu9C40LXQvdGC'
    '0LAuINCg0LDQsdC+0YfQuNC5IFZQTiDQvtGB0YLQsNC90LXRgtGB0Y8g0LLQutC70Y7Rh9GR0L3QvdGL0LwuIikKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArIChTdHJpbmcoKHJvb3QuZXhwZXJpbWVudC50dW5uZWwg'
    'fHwge30pLnNjb3BlIHx8ICIiKSA9PT0gImxhbiIgPyAiXG7Qn9GA0L7QstC10YDQutCwINCyINC00L7QvNCw0YjQvdC10Lkg'
    '0YHQtdGC0Lg7INCy0L3QtdGI0L3QuNC5INC/0YPRgtGMINGH0LXRgNC10Lcg0L/RgNC+0LLQsNC50LTQtdGA0LAg0LXRidGR'
    'INC90LUg0L/RgNC+0LLQtdGA0LXQvS4iIDogIiIpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgKyAoQm9vbGVhbigoKHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLm1ldHJpY3MgfHwge30pLmludGVncml0eSkg'
    'PyAiXG7Qn9C10YDQtdC00LDRh9CwINC00LDQvdC90YvRhTog0YbQtdC70L7RgdGC0L3QvtGB0YLRjCDQv9C+0LTRgtCy0LXR'
    'gNC20LTQtdC90LAuIiA6ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICsgKCgoKHJv'
    'b3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLm1ldHJpY3MgfHwge30pLnJlZmVyZW5jZSB8fCB7fSkuZXN0aW1hdGVkX21i'
    'cHMgPyAiXG7Qr9C90LTQtdC60YE6INC+0YbQtdC90LrQsCDQv9GA0Y/QvNC+0Lkg0YHQutC+0YDQvtGB0YLQuCAiICsgTnVt'
    'YmVyKCgoKHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLm1ldHJpY3MgfHwge30pLnJlZmVyZW5jZSB8fCB7fSkuZXN0'
    'aW1hdGVkX21icHMpLnRvRml4ZWQoMSkgKyAiINCc0LHQuNGCL9GBICjQutC+0YDQvtGC0LrQuNC5INC30LDQvNC10YApLiIg'
    'OiAiIikKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArICgoKChyb290LmV4cGVyaW1lbnQu'
    'dHVubmVsIHx8IHt9KS5tZXRyaWNzIHx8IHt9KS5yZWZlcmVuY2UgfHwge30pLmF2YWlsYWJsZSA9PT0gZmFsc2UgPyAiXG7Q'
    'r9C90LTQtdC60YE6INC+0YDQuNC10L3RgtC40YAg0YHQutC+0YDQvtGB0YLQuCDRgdC10LnRh9Cw0YEg0L3QtdC00L7RgdGC'
    '0YPQv9C10L0uIiA6ICIiKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IEJvb2xlYW4o'
    'KHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLmFjdGl2ZSkgPyByb290Lmdvb2QgOiByb290LnRleHRNYWluCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBBY2Nlc3NpYmxlLm5hbWU6ICLQodGC0YDQvtC60LAg0YHQvtGB'
    '0YLQvtGP0L3QuNGPIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEMuUHJvZ3Jlc3NCYXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZnJvbTogMDsg'
    'dG86IDEwMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWU6IE51bWJlcigocm9vdC5leHBl'
    'cmltZW50LnR1bm5lbCB8fCB7fSkucHJvZ3Jlc3MgfHwgMCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHZpc2libGU6IEJvb2xlYW4oKHJvb3QuZXhwZXJpbWVudC50dW5uZWwgfHwge30pLnJ1bm5pbmcpICYmICFCb29sZWFu'
    'KChyb290LmV4cGVyaW1lbnQudHVubmVsIHx8IHt9KS5hY3RpdmUpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSXRlbSB7IExheW91dC5maWxsSGVpZ2h0OiB0cnVl'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'IH0KICAgICAgICB9CiAgICB9Cn0K'
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


def migrate_firefox_codex_exceptions(settings: dict) -> None:
    """Remove the old app bypasses once; later explicit user choices remain possible."""
    if settings.get('firefox_codex_exceptions_migrated'):
        return
    path = _safe_direct_path(settings, 'direct_apps')
    if path.exists():
        original = path.read_text()
        names = {'firefox', 'firefox-bin', 'firefox-esr', 'codex', 'codex-desktop'}
        kept = []
        for line in original.splitlines(keepends=True):
            value = line.strip()
            if value and not value.startswith('#') and pathlib.PurePosixPath(value).name.lower() in names:
                continue
            kept.append(line)
        updated = ''.join(kept)
        if updated != original:
            backup = path.with_name(path.name + '.before-0.3.0-ru.2')
            if not backup.exists():
                _write_direct_file({**settings, 'direct_apps': str(backup)}, 'direct_apps', original)
            _write_direct_file(settings, 'direct_apps', updated)
            info('Исключения Firefox и Codex удалены из DIRECT-приложений.')
    settings['firefox_codex_exceptions_migrated'] = True
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
    'IiIiT25lIGlzb2xhdGVkIFJ1c3NpYS10by1SdXNzaWEgSUtFdjIgdGVzdCB0dW5uZWwuIE5ldmVyIGNvbnRyb2xzIHRoZSB3'
    'b3JraW5nIFhyYXkuIiIiCmltcG9ydCBjb250ZXh0bGliCmltcG9ydCBmY250bAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaHR0'
    'cC5jbGllbnQKaW1wb3J0IGlwYWRkcmVzcwppbXBvcnQganNvbgppbXBvcnQgb3MKZnJvbSBwYXRobGliIGltcG9ydCBQYXRo'
    'CmltcG9ydCByZQppbXBvcnQgc2VjcmV0cwppbXBvcnQgc2h1dGlsCmltcG9ydCBzaWduYWwKaW1wb3J0IHNvY2tldAppbXBv'
    'cnQgc3NsCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCB0aW1lCgpST09UID0gUGF0aCgnL2V0Yy92cG4tbWFuYWdlci9zdGFy'
    'Zml2ZS10dW5uZWwnKQpSVU5USU1FID0gUGF0aCgnL3J1bi9ldmdlbml1bS1zdGFyZml2ZS10dW5uZWwnKQpTVEFURSA9IFBh'
    'dGgoJy92YXIvbGliL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXR1bm5lbC5qc29uJykKVU5JVCA9ICdldmdlbml1bS1zdGFyZml2'
    'ZS10dW5uZWwuc2VydmljZScKTlMgPSAnZXZuLXN0YXJmaXZlJwpIT1NUID0gJ2V2bi1zZi1ob3N0JwpQRUVSID0gJ2V2bi1z'
    'Zi1wZWVyJwpORVRXT1JLID0gJzE3Mi4yOS4yNDYuMC8zMCcKQ0xJRU5UID0gJzE3Mi4yOS4yNDYuMicKR0FURVdBWSA9ICcx'
    'NzIuMjkuMjQ2LjEnClRBQkxFID0gNTE4MjQKUFJJT1JJVFkgPSAxMTAKTkZUID0gJ2V2Z2VuaXVtX3N0YXJmaXZlX2xhYl9o'
    'b3N0JwpTRVJWRVIgPSAnMTA5LjE5NC42Ny4xNTknClNFUlZFUl9MQU4gPSAnMTkyLjE2OC4wLjE2MycKSEVBTFRIID0gJzEw'
    'Ljc3LjAuMScKUkVRSUQgPSAxNzcKVE9LRU5fUEFUVEVSTiA9IHInRVZOMS1bQS1aYS16MC05Xy1dezQzfScKU1RPUCA9IEZh'
    'bHNlClBJTk5FRF9DQSA9ICctLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1JSUVPRENDQXFDZ0F3SUJBZ0lVYmtKKzhT'
    'YXFBZ3dZMVJEQWpaUlRqY3FROWVNd0RRWUpLb1pJaHZjTkFRRUxcbkJRQXdJakVnTUI0R0ExVUVBd3dYUlhablpXNXBkVzBn'
    'Y0hKcGRtRjBaU0JXVUU0Z1EwRXdIaGNOTWpZeE1EQTNcbk1Ua3hNelF4V2hjTk16WXhNREEwTVRreE16UXhXakFpTVNBd0hn'
    'WURWUVFEREJkRmRtZGxibWwxYlNCd2NtbDJcbllYUmxJRlpRVGlCRFFUQ0NBYUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0dQ'
    'QURDQ0FZb0NnZ0dCQU9aK252aUVcbjJPckY3UGR0a2svWElhRlZJdkpsdkMxMVZaZjlybGpDQkl2QnlrYnNyQXJHcnlRSEdu'
    'dXVYTE5hYVM4TnRMeFlcbk5lU0JESzZNZGdZSkFlanNQNHdJVHViM25NalNHMnVtSUlWVTZtRStHRG96R1BsTk1OSitiaGtL'
    'YVZoYVBqRkVcbnlZTFlyZFBlNVZBNHcrNXAwTlpPRDZDQkhEM3RFWFdCTlJJZVZTV2J0TUlUc09FUzFQZS9hQUw3djNvTklW'
    'a1ZcbjhuRHc5ajcrd0cyeTVkaGJwN0tVSkhickRCMDI0cjdjWXJRM2F4WUY2Z3lram16dHBLWHNia3hRdjI3QnZoU0JcbmUw'
    'RWt0Si9qQ1M2UjlJSW1ZZ0lRckNyYVdabVZTY25HRi9BcTRUTncxSDRPekZDa1IrN0pVbFluU1lVdk1SaTFcbkx6S2VrVUMr'
    'Mi8wV0ZtaG5Db0R0ZGpjb1lieHBMcEtEZWxHaVMzUnNOQ3Z4bnNsTWFQejVoQ2NGNjRZN1Jpalhcbmo2RHVDWXBGWVdscjEz'
    'QjIwcUFuUm9VYXMrQWpYN1BYQ2tSNHhPaEgra1c4L0htRkhpSGtvaFdFMHdsbElTQlhcblZCbzdLQk9aZDhTVmV3eWJkMnJC'
    'NHNvWG91VHRqWHMvalRnZStIV3hRREdQUDF1bWZ6OGNGTFIvdVFJREFRQUJcbm8yWXdaREFkQmdOVkhRNEVGZ1FVb1FmVGlm'
    'Nzd4V3QwNmhhWGgzaGE4OTBxa1Q4d0h3WURWUjBqQkJnd0ZvQVVcbm9RZlRpZjc3eFd0MDZoYVhoM2hhODkwcWtUOHdFZ1lE'
    'VlIwVEFRSC9CQWd3QmdFQi93SUJBREFPQmdOVkhROEJcbkFmOEVCQU1DQVFZd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dHQkFJ'
    'N0dLbm1mSmp1TDFRdnlSdGx3K0hyNkFZL1pcbk94ZER2RUNlZm9GTDdRNDFWWmErTDdESTg3a01MWUh5Z1JIdXNoNjZvVXY4'
    'NzhUV010YXNuYnQvOHdZZzZqcndcbkF5Z3BnL0YzVkQyNHlUcm5KN09DZHlHaWI2TEd1dXN1VFA0clVHc2NjV2N6blFYWUZr'
    'elJWejFWZVlNWlVOK1BcbnRBVmlObDRFUlMxZmgrY0d6VDRPcVhRa0pEa1JlcUgvSENURThrVVFVVWdYYVNYcGhLakdhOHBS'
    'MkhWZUZ1a1hcbiswcHAxaVIrNmRpNGFDS2Fwa2FUaVZSM3I2MnRSQlV3YnhvRllSeXhOWHluVEs5RWhuTTI1V0Vwbi9xdTBs'
    'c0Rcbm9YckZWbWowQVFmQVVIUk4vMnJQTC8vdzZSUEVwSGdVY3J0N3p1U2dvWEpaaDBEVDMwVkVJSzlOTmJ1S1NGZDlcbklp'
    'V3ZyeGJWUVM2bVFndEVaTjRMYzJIbTFwdlkrV3JJK0gwM3U4MDQyK2NwTElzQ254UG05V3ZpN2RNWHhxb2Jcbm8yL2FMMnhE'
    'RzVHLzhXVlIvVzVFQWZ2S2R4ZHJrM0g2MDJvY2NvdjcrSmcxdm94aTAwSWJkTUV4b014ZDVhZWhcbmZYUmlKaFRFRm91SXBt'
    'RVNDRjR2Vk1sV0ZyM21xbFEzR0tTUFZBPT1cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS1cbicKCgpkZWYgY29tbWFuZChh'
    'cmdzLCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAgIGNwID0gc3VicHJvY2Vzcy5y'
    'dW4oW3N0cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0dXJlX291dHB1dD1UcnVlLAog'
    'ICAgICAgICAgICAgICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAgaWYgY2hl'
    'Y2sgYW5kIGNwLnJldHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4gYSBDU1IgcGF0aDsgZG8gbm90'
    'IHByb3BhZ2F0ZSBwcm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2NvbW1h'
    'bmRfZmFpbGVkJykKICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIGNvbW1h'
    'bmQoWydpcCcsICduZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVmIHdyaXRlKHBhdGgsIHZhbHVl'
    'KToKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHRl'
    'bXBvcmFyeSA9IHBhdGgud2l0aF9zdWZmaXgoJy5uZXcnKQogICAgZmQgPSBvcy5vcGVuKHRlbXBvcmFyeSwgb3MuT19XUk9O'
    'TFkgfCBvcy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIDBvNjAwKQogICAgd2l0aCBvcy5mZG9wZW4o'
    'ZmQsICd3JykgYXMgc3RyZWFtOgogICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgIHRlbXBvcmFyeS5yZXBsYWNlKHBh'
    'dGgpCgoKZGVmIHNhdmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoU1RBVEUucmVhZF90ZXh0KCkp'
    'CiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoKCmRlZiBzdGFnZShwaGFzZSwg'
    'bWVzc2FnZSwgcHJvZ3Jlc3MsICoqZmllbGRzKToKICAgIGRhdGEgPSB7KipzYXZlZCgpLCAncGhhc2UnOiBwaGFzZSwgJ21l'
    'c3NhZ2UnOiBtZXNzYWdlLCAncHJvZ3Jlc3MnOiBwcm9ncmVzcywKICAgICAgICAgICAgJ3VwZGF0ZWQnOiBpbnQodGltZS50'
    'aW1lKCkpLCAnaGVhcnRiZWF0JzogdGltZS5tb25vdG9uaWMoKSwgKipmaWVsZHN9CiAgICB3cml0ZShTVEFURSwganNvbi5k'
    'dW1wcyhkYXRhLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQoKCmRlZiBzdGF0dXMoKToKICAgIGRhdGEgPSBzYXZlZCgpCiAgICBy'
    'dW5uaW5nID0gY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcsIFVOSVRdLCBjaGVjaz1GYWxz'
    'ZSwgdGltZW91dD0yKS5yZXR1cm5jb2RlID09IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScpID09ICdjb25uZWN0ZWQnIGFu'
    'ZCAobm90IHJ1bm5pbmcgb3IgdGltZS5tb25vdG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0JywgMCkgPiA0NSk6CiAgICAg'
    'ICAgZGF0YS51cGRhdGUocGhhc2U9J2ludGVycnVwdGVkJywgbWVzc2FnZT0n0KLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC1'
    '0LvRjCDQvtGB0YLQsNC90L7QstC40LvRgdGPLiDQoNCw0LHQvtGH0LjQuSBWUE4g0YHQvtGF0YDQsNC90ZHQvS4nLCBhY3Rp'
    'dmU9RmFsc2UpCiAgICBwdWJsaWMgPSB7a2V5OiBkYXRhW2tleV0gZm9yIGtleSBpbiAoJ3BoYXNlJywgJ21lc3NhZ2UnLCAn'
    'cHJvZ3Jlc3MnLCAnYWN0aXZlJywgJ3VwZGF0ZWQnLCAnbWV0cmljcycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAnc2NvcGUnLCAnc2luY2UnLCAncmV0cnknKSBpZiBrZXkgaW4gZGF0YX0KICAgIHRva2VuX2luZm8gPSB0'
    'b2tlbl9zdGF0dXMoKQogICAgcmV0dXJuIHsncGhhc2UnOiAnb2ZmJywgJ21lc3NhZ2UnOiAoJ9Ci0L7QutC10L0g0YHQvtGF'
    '0YDQsNC90ZHQvS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC70Y7Rh9C40YLRjMK7LicgaWYgdG9rZW5faW5mb1snaGFz'
    'X3Rva2VuJ10gZWxzZSAn0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQ'
    'uNC10L3RgtCwLicpLAogICAgICAgICAgICAncHJvZ3Jlc3MnOiAwLCAnYWN0aXZlJzogRmFsc2UsICoqcHVibGljLCAncnVu'
    'bmluZyc6IHJ1bm5pbmcsCiAgICAgICAgICAgICoqdG9rZW5faW5mbywgJ2lzb2xhdGVkJzogVHJ1ZSwgJ3Byb3RvY29sJzog'
    'J0lLRXYyJ30KCgpAY29udGV4dGxpYi5jb250ZXh0bWFuYWdlcgpkZWYgbmFtZXNwYWNlKCk6CiAgICBiZWZvcmUgPSBvcy5v'
    'cGVuKCcvcHJvYy9zZWxmL25zL25ldCcsIG9zLk9fUkRPTkxZKQogICAgdGFyZ2V0ID0gb3Mub3BlbignL3J1bi9uZXRucy8n'
    'K05TLCBvcy5PX1JET05MWSkKICAgIHRyeToKICAgICAgICBvcy5zZXRucyh0YXJnZXQsIG9zLkNMT05FX05FV05FVCkKICAg'
    'ICAgICB5aWVsZAogICAgZmluYWxseToKICAgICAgICBvcy5zZXRucyhiZWZvcmUsIG9zLkNMT05FX05FV05FVCkKICAgICAg'
    'ICBvcy5jbG9zZSh0YXJnZXQpCiAgICAgICAgb3MuY2xvc2UoYmVmb3JlKQoKCmRlZiBwaHlzaWNhbF9yb3V0ZSgpOgogICAg'
    'cm91dGVzID0ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCAnLWonLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScs'
    'ICdtYWluJywgJ2RlZmF1bHQnXSkuc3Rkb3V0KQogICAgY2FuZGlkYXRlcyA9IFtyIGZvciByIGluIHJvdXRlcyBpZiByLmdl'
    'dCgnZ2F0ZXdheScpIGFuZCByLmdldCgnZGV2JykgYW5kCiAgICAgICAgICAgICAgICAgIG5vdCByWydkZXYnXS5zdGFydHN3'
    'aXRoKCgndHVuJywgJ3hyYXknLCAnd2cnLCAnZXZuLScpKV0KICAgIGlmIG5vdCBjYW5kaWRhdGVzOgogICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcignbm9fcGh5c2ljYWxfcm91dGUnKQogICAgcm91dGUgPSBtaW4oY2FuZGlkYXRlcywga2V5PWxhbWJk'
    'YSByOiByLmdldCgnbWV0cmljJywgMCkpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInW0EtWmEtejAtOV8uOi1dezEsMTV9'
    'Jywgcm91dGVbJ2RldiddKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaW50ZXJmYWNlJykKICAgIGlw'
    'YWRkcmVzcy5JUHY0QWRkcmVzcyhyb3V0ZVsnZ2F0ZXdheSddKQogICAgcmV0dXJuIHJvdXRlCgoKZGVmIGhvc3RfcnVsZXMo'
    'aWZhY2UsIHByZXZpb3VzX2ZvcndhcmQ9VHJ1ZSk6CiAgICAjIFNjb3BlIGV2ZXJ5IG5ldyBmb3J3YXJkaW5nL05BVCBydWxl'
    'IHRvIG91ciBvbmUgaW50ZXJmYWNlIGFuZCB0d28gc2VydmVyIGFkZHJlc3Nlcy4KICAgIHByZXNlcnZlX2Rpc2FibGVkID0g'
    'JycgaWYgcHJldmlvdXNfZm9yd2FyZCBlbHNlICcgIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnCiAgICByZXR1cm4gZicnJ3Rh'
    'YmxlIGluZXQge05GVH0ge3sKIGNoYWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkg'
    'LTIwOyBwb2xpY3kgYWNjZXB0OwogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NFUlZFUn0sIHtTRVJWRVJfTEFO'
    'fSB9fSB1ZHAgZHBvcnQge3sgNTAwLCA0NTAwIH19IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NF'
    'UlZFUn0sIHtTRVJWRVJfTEFOfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGRyb3AKICBv'
    'aWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJWRVJ9LCB7U0VSVkVSX0xBTn0gfX0gY3Qgc3RhdGUgZXN0YWJsaXNo'
    'ZWQscmVsYXRlZCBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGRyb3AKe3ByZXNlcnZlX2Rpc2FibGVkfQogfX0KIGNoYWlu'
    'IG5hdCB7ewogIHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlw'
    'IHNhZGRyIHtDTElFTlR9IG9pZm5hbWUgIntpZmFjZX0iIG1hc3F1ZXJhZGUKIH19Cn19JycnCgoKZGVmIHNldHVwX25ldHdv'
    'cmsoKToKICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgIyBSZWZ1c2UgbmFtZS9hZGRyZXNzIGNvbGxpc2lvbnMg'
    'cmF0aGVyIHRoYW4gcmVwdXJwb3NpbmcgYW5vdGhlciBhcHBsaWNhdGlvbidzIHJlc291cmNlcy4KICAgIGlmIFBhdGgoJy9y'
    'dW4vbmV0bnMvJytOUykuZXhpc3RzKCkgb3IgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytIT1NUKS5leGlzdHMoKSBvciAoUGF0'
    'aCgnL2V0Yy9uZXRucycpL05TKS5leGlzdHMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmFtZXNwYWNl'
    'X2V4aXN0cycpCiAgICBpZiBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsIHN0cihUQUJM'
    'RSldLCBjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X3RhYmxl'
    'X2luX3VzZScpCiAgICBpZiBhbnkoTkVUV09SSyBpbiBsaW5lIGZvciBsaW5lIGluIGNvbW1hbmQoWydpcCcsICctNCcsICdy'
    'b3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ2FsbCddKS5zdGRvdXQuc3BsaXRsaW5lcygpKToKICAgICAgICByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ3Rlc3RfbmV0d29ya19pbl91c2UnKQogICAgb2xkX2ZvcndhcmQgPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lw'
    'djQvaXBfZm9yd2FyZCcpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgICMgUmVjb3JkIG93bmVyc2hpcCBiZWZvcmUgY3JlYXRp'
    'bmcgYW55dGhpbmc6IGNsZWFudXAgaXMgdmFsaWQgYWZ0ZXIgZXZlcnkgcGFydGlhbCBzdGVwLgogICAgdXBsaW5rID0gUGF0'
    'aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9yb3V0ZVsnZGV2J10vJ2ZvcndhcmRpbmcnCiAgICB3cml0ZShST09ULydu'
    'ZXR3b3JrLmpzb24nLCBqc29uLmR1bXBzKHsnZm9yd2FyZCc6IG9sZF9mb3J3YXJkLCAnaW50ZXJmYWNlJzogcm91dGVbJ2Rl'
    'diddLCAndXBsaW5rX2ZvcndhcmQnOiB1cGxpbmsucmVhZF90ZXh0KCkuc3RyaXAoKX0pKQogICAgY29tbWFuZChbJ2lwJywg'
    'J25ldG5zJywgJ2FkZCcsIE5TXSkKICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCAnbmFt'
    'ZXNlcnZlciA3Ny44OC44Ljhcbm5hbWVzZXJ2ZXIgNzcuODguOC4xXG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4n'
    'KQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnYWRkJywgSE9TVCwgJ3R5cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUn'
    'LCBQRUVSXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIFBFRVIsICduZXRucycsIE5TXSkKICAgIGNvbW1h'
    'bmQoWydpcCcsICdhZGRyJywgJ2FkZCcsIEdBVEVXQVkrJy8zMCcsICdkZXYnLCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcs'
    'ICdsaW5rJywgJ3NldCcsIEhPU1QsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8z'
    'MCcsICdkZXYnLCBQRUVSXSkKICAgIGluc2lkZShbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNp'
    'ZGUoWydpcCcsICdsaW5rJywgJ3NldCcsICdsbycsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywg'
    'J2RlZmF1bHQnLCAndmlhJywgR0FURVdBWV0pCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywg'
    'c3RyKFRBQkxFKSwgJ2RlZmF1bHQnLCAndmlhJywgcm91dGVbJ2dhdGV3YXknXSwgJ2RldicsIHJvdXRlWydkZXYnXV0pCiAg'
    'ICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCBTRVJWRVJfTEFOKToKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdh'
    'ZGQnLCAncHJpb3JpdHknLCBzdHIoUFJJT1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAn'
    'dG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICBydWxlcyA9IGhvc3RfcnVsZXMocm91dGVb'
    'J2RldiddLCBwcmV2aW91c19mb3J3YXJkPW9sZF9mb3J3YXJkID09ICcxJykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWMnLCAn'
    'LWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICAj'
    'IFBlci1pbnRlcmZhY2UgZm9yd2FyZGluZyBhdm9pZHMgaXBfZm9yd2FyZCdzIGdsb2JhbCBkZWZhdWx0cyByZXNldC4KICAg'
    'IChQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvY29uZicpL0hPU1QvJ2ZvcndhcmRpbmcnKS53cml0ZV90ZXh0KCcxXG4nKQog'
    'ICAgdXBsaW5rLndyaXRlX3RleHQoJzFcbicpCgoKZGVmIGNsZWFudXAoKToKICAgICMgQW4gdW5vd25lZCBuYW1lc3BhY2Uv'
    'dGFibGUgbXVzdCBuZXZlciBiZSBkZWxldGVkIGJ5IGEgZ2VuZXJpYyBjbGVhbnVwIGNhbGwuCiAgICBpZiBub3QgKFJPT1Qv'
    'J25ldHdvcmsuanNvbicpLmV4aXN0cygpOgogICAgICAgIHJldHVybgogICAgZGF0YSA9IGpzb24ubG9hZHMoKFJPT1QvJ25l'
    'dHdvcmsuanNvbicpLnJlYWRfdGV4dCgpKQogICAgY29tbWFuZChbJ25mdCcsICdkZWxldGUnLCAndGFibGUnLCAnaW5ldCcs'
    'IE5GVF0sIGNoZWNrPUZhbHNlKQogICAgZm9yIGFkZHJlc3MgaW4gKFNFUlZFUiwgU0VSVkVSX0xBTik6CiAgICAgICAgY29t'
    'bWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElFTlQrJy8z'
    'MicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1G'
    'YWxzZSkKICAgIGZvciBhZGRyZXNzIGluIGRhdGEuZ2V0KCdtZWFzdXJlbWVudF9pcHMnLCBbXSk6CiAgICAgICAgaWYgaXBh'
    'ZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xvYmFsOgogICAgICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScs'
    'ICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsICd0bycsIGFkZHJlc3MrJy8zMicsICds'
    'b29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnZmx1c2gnLCAn'
    'dGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAnbmV0bnMnLCAnZGVsJywgTlNd'
    'LCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2RlbCcsIEhPU1RdLCBjaGVjaz1GYWxzZSkKICAg'
    'IGlmICd1cGxpbmtfZm9yd2FyZCcgaW4gZGF0YToKICAgICAgICBwYXRoID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2Nv'
    'bmYnKS9kYXRhWydpbnRlcmZhY2UnXS8nZm9yd2FyZGluZycKICAgICAgICBpZiBwYXRoLmV4aXN0cygpOgogICAgICAgICAg'
    'ICBwYXRoLndyaXRlX3RleHQoZGF0YVsndXBsaW5rX2ZvcndhcmQnXSsnXG4nKQogICAgZWxpZiBkYXRhLmdldCgnZm9yd2Fy'
    'ZCcpID09ICcwJyBhbmQgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgp'
    'ID09ICcxJzoKICAgICAgICBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcpLndyaXRlX3RleHQoJzBcbicp'
    'CiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3'
    'aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoT1NFcnJvcik6CiAgICAgICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykucm1kaXIo'
    'KQogICAgKFJPT1QvJ25ldHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKQGNvbnRleHRsaWIuY29udGV4'
    'dG1hbmFnZXIKZGVmIG1lYXN1cmVtZW50X3JvdXRlKGFkZHJlc3MpOgogICAgIiIiQSBzaG9ydC1saXZlZCBkaXJlY3Qgcm91'
    'dGUgZm9yIGEgdmVyaWZpZWQgWWFuZGV4IEhUVFBTIG1lYXN1cmVtZW50LCBsYWIgb25seS4iIiIKICAgIGlmIG5vdCBpcGFk'
    'ZHJlc3MuaXBfYWRkcmVzcyhhZGRyZXNzKS5pc19nbG9iYWwgb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCBTRVJWRVJfTEFOKToK'
    'ICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCdpbnZhbGlkX21lYXN1cmVtZW50X2FkZHJlc3MnKQogICAgbGFiZWwgPSAnZXZu'
    'LW1lYXN1cmUtJytzZWNyZXRzLnRva2VuX2hleCg4KQogICAgZGF0YSA9IGpzb24ubG9hZHMoKFJPT1QvJ25ldHdvcmsuanNv'
    'bicpLnJlYWRfdGV4dCgpKQogICAgZGF0YVsnbWVhc3VyZW1lbnRfaXBzJ10gPSBzb3J0ZWQoc2V0KGRhdGEuZ2V0KCdtZWFz'
    'dXJlbWVudF9pcHMnLCBbXSkrW2FkZHJlc3NdKSkKICAgIHdyaXRlKFJPT1QvJ25ldHdvcmsuanNvbicsIGpzb24uZHVtcHMo'
    'ZGF0YSkpCiAgICB0cnk6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5JywgJzExMScs'
    'ICdmcm9tJywgQ0xJRU5UKycvMzInLAogICAgICAgICAgICAgICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBz'
    'dHIoVEFCTEUpXSkKICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2luc2VydCcsICdydWxlJywgJ2luZXQnLCBORlQsICdmb3J3'
    'YXJkJywgJ2lpZm5hbWUnLCBIT1NULAogICAgICAgICAgICAgICAgICdpcCcsICdkYWRkcicsIGFkZHJlc3MsICd0Y3AnLCAn'
    'ZHBvcnQnLCAnNDQzJywgJ2FjY2VwdCcsICdjb21tZW50JywgbGFiZWxdKQogICAgICAgIGNvbW1hbmQoWyduZnQnLCAnaW5z'
    'ZXJ0JywgJ3J1bGUnLCAnaW5ldCcsIE5GVCwgJ2ZvcndhcmQnLCAnb2lmbmFtZScsIEhPU1QsCiAgICAgICAgICAgICAgICAg'
    'J2lwJywgJ3NhZGRyJywgYWRkcmVzcywgJ2N0JywgJ3N0YXRlJywgJ2VzdGFibGlzaGVkLHJlbGF0ZWQnLCAnYWNjZXB0Jywg'
    'J2NvbW1lbnQnLCBsYWJlbF0pCiAgICAgICAgeWllbGQKICAgIGZpbmFsbHk6CiAgICAgICAgcmVzdWx0ID0gY29tbWFuZChb'
    'J25mdCcsICctaicsICctYScsICdsaXN0JywgJ2NoYWluJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJ10sIGNoZWNrPUZhbHNl'
    'KQogICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgICAgIGZvciBlbnRyeSBpbiBqc29uLmxvYWRz'
    'KHJlc3VsdC5zdGRvdXQpLmdldCgnbmZ0YWJsZXMnLCBbXSk6CiAgICAgICAgICAgICAgICBydWxlID0gZW50cnkuZ2V0KCdy'
    'dWxlJywge30pCiAgICAgICAgICAgICAgICBpZiBydWxlLmdldCgnY29tbWVudCcpID09IGxhYmVsOgogICAgICAgICAgICAg'
    'ICAgICAgIGNvbW1hbmQoWyduZnQnLCAnZGVsZXRlJywgJ3J1bGUnLCAnaW5ldCcsIE5GVCwgJ2ZvcndhcmQnLCAnaGFuZGxl'
    'Jywgc3RyKHJ1bGVbJ2hhbmRsZSddKV0sIGNoZWNrPUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2Rl'
    'bCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRy'
    'ZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQoKCmRlZiBwcm92aWRlcl9hZGRyZXNzZXMo'
    'aG9zdCk6CiAgICAjIEROUyBtYXkgdXNlIHRoZSB3b3JraW5nIHJlc29sdmVyLCBidXQgbWVhc3VyZWQgSFRUUFMgaXRzZWxm'
    'IHRha2VzIHRoZSBwaHlzaWNhbCByb3V0ZS4KICAgIGFkZHJlc3NlcyA9IFthbnN3ZXJbNF1bMF0gZm9yIGFuc3dlciBpbiBz'
    'b2NrZXQuZ2V0YWRkcmluZm8oaG9zdCwgNDQzLCBzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKV0KICAgIHJl'
    'dHVybiBsaXN0KGRpY3QuZnJvbWtleXMoeCBmb3IgeCBpbiBhZGRyZXNzZXMgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeCku'
    'aXNfZ2xvYmFsKSlbOjJdCgoKZGVmIHByb3ZpZGVyX2dldChob3N0LCBwYXRoLCBtYXhpbXVtLCBtZWFzdXJlPUZhbHNlKToK'
    'ICAgIGxhc3QgPSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiBwcm92aWRlcl9hZGRyZXNzZXMoaG9zdCk6CiAgICAgICAgb3V0'
    'cHV0ID0gUk9PVC8oJ3JlZmVyZW5jZS0nK3NlY3JldHMudG9rZW5faGV4KDgpKycudG1wJykKICAgICAgICB0cnk6CiAgICAg'
    'ICAgICAgIHdpdGggbWVhc3VyZW1lbnRfcm91dGUoYWRkcmVzcyk6CiAgICAgICAgICAgICAgICBhcmdzID0gWydjdXJsJywg'
    'Jy00JywgJy0tc2lsZW50JywgJy0tc2hvdy1lcnJvcicsICctLWZhaWwnLCAnLS1ub3Byb3h5JywgJyonLAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAnLS1wcm90bycsICc9aHR0cHMnLCAnLS1jb25uZWN0LXRpbWVvdXQnLCAnNCcsICctLW1heC10aW1l'
    'JywgJzEwJywKICAgICAgICAgICAgICAgICAgICAgICAgJy0tcmVzb2x2ZScsIGhvc3QrJzo0NDM6JythZGRyZXNzLCAnLS1t'
    'YXgtZmlsZXNpemUnLCBzdHIobWF4aW11bSksCiAgICAgICAgICAgICAgICAgICAgICAgICctLW91dHB1dCcsIHN0cihvdXRw'
    'dXQpLCAnLS13cml0ZS1vdXQnLCAnJXtqc29ufSddCiAgICAgICAgICAgICAgICBpZiBtZWFzdXJlOgogICAgICAgICAgICAg'
    'ICAgICAgIGFyZ3MgKz0gWyctLXJhbmdlJywgJzAtJytzdHIobWF4aW11bS0xKV0KICAgICAgICAgICAgICAgIGFyZ3MgKz0g'
    'WydodHRwczovLycraG9zdCtwYXRoXQogICAgICAgICAgICAgICAgcmVzdWx0ID0gaW5zaWRlKGFyZ3MsIHRpbWVvdXQ9MTIs'
    'IGNoZWNrPUZhbHNlKQogICAgICAgICAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGU6CiAgICAgICAgICAgICAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCdtZWFzdXJlbWVudF9jdXJsXycrc3RyKHJlc3VsdC5yZXR1cm5jb2RlKSkKICAgICAgICAg'
    'ICAgICAgIHN0YXRpc3RpY3MgPSBqc29uLmxvYWRzKHJlc3VsdC5zdGRvdXQpCiAgICAgICAgICAgICAgICBpZiBtZWFzdXJl'
    'OgogICAgICAgICAgICAgICAgICAgIHJlY2VpdmVkID0gaW50KHN0YXRpc3RpY3NbJ3NpemVfZG93bmxvYWQnXSkKICAgICAg'
    'ICAgICAgICAgICAgICBlbGFwc2VkID0gZmxvYXQoc3RhdGlzdGljc1sndGltZV90b3RhbCddKS1mbG9hdChzdGF0aXN0aWNz'
    'Wyd0aW1lX3N0YXJ0dHJhbnNmZXInXSkKICAgICAgICAgICAgICAgICAgICBpZiByZWNlaXZlZCA8IDEwMjQqMTAyNCBvciBy'
    'ZWNlaXZlZCA+IG1heGltdW0gb3IgZWxhcHNlZCA8PSAwOgogICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ21lYXN1cmVtZW50X3Rvb19zaG9ydCcpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHsnYnl0ZXMnOiByZWNl'
    'aXZlZCwgJ2VsYXBzZWRfbXMnOiByb3VuZChlbGFwc2VkKjEwMDApLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2Vz'
    'dGltYXRlZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFwc2VkLzFlNiwgMil9CiAgICAgICAgICAgICAgICByZXR1cm4g'
    'b3V0cHV0LnJlYWRfYnl0ZXMoKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgUnVudGltZUVycm9yLCBWYWx1ZUVycm9yLCBz'
    'dWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKSBhcyBleGM6CiAgICAgICAgICAgIGxhc3QgPSBleGMKICAgICAgICBmaW5hbGx5'
    'OgogICAgICAgICAgICBvdXRwdXQudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVm'
    'ZXJlbmNlX3VuYXZhaWxhYmxlJykgZnJvbSBsYXN0CgoKZGVmIHZhbGlkYXRlX3lhbmRleF9wcm9iZSh1cmwpOgogICAgZnJv'
    'bSB1cmxsaWIucGFyc2UgaW1wb3J0IHVybHNwbGl0CiAgICBwYXJzZWQgPSB1cmxzcGxpdCh1cmwpCiAgICBpZiAobGVuKHVy'
    'bCkgPiAyMDQ4IG9yIHBhcnNlZC5zY2hlbWUgIT0gJ2h0dHBzJyBvciBub3QgcGFyc2VkLmhvc3RuYW1lIG9yCiAgICAgICAg'
    'bm90IHBhcnNlZC5ob3N0bmFtZS5lbmRzd2l0aCgnLmNkbi55YW5kZXgubmV0Jykgb3IgcGFyc2VkLnVzZXJuYW1lIG9yIHBh'
    'cnNlZC5wYXNzd29yZCBvcgogICAgICAgIHBhcnNlZC5wb3J0IG5vdCBpbiAoTm9uZSwgNDQzKSBvciBwYXJzZWQuZnJhZ21l'
    'bnQpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ3VudHJ1c3RlZF9yZWZlcmVuY2VfdXJsJykKICAgIHJldHVybiBwYXJz'
    'ZWQuaG9zdG5hbWUsIHBhcnNlZC5wYXRoKygnPycgKyBwYXJzZWQucXVlcnkgaWYgcGFyc2VkLnF1ZXJ5IGVsc2UgJycpCgoK'
    'ZGVmIHJlZmVyZW5jZV9zYW1wbGUoZm9yY2U9RmFsc2UpOgogICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICBmaW5n'
    'ZXJwcmludCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2Rl'
    'dicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgIHRy'
    'eToKICAgICAgICBjYWNoZWQgPSBqc29uLmxvYWRzKChST09ULydyZWZlcmVuY2UuanNvbicpLnJlYWRfdGV4dCgpKQogICAg'
    'ICAgIGlmIG5vdCBmb3JjZSBhbmQgY2FjaGVkLmdldCgnbmV0d29yaycpID09IGZpbmdlcnByaW50IGFuZCBjYWNoZWQuZ2V0'
    'KCdwcm92aWRlcicpID09ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInOgogICAgICAgICAgICByZXR1cm4gY2FjaGVkCiAgICBl'
    'eGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHBhc3MKICAgIHN0YWdlKCdyZWZlcmVuY2UnLCAn0JfQsNC/'
    '0YPRgdC60LDRjiDQt9Cw0LzQtdGAINC/0YDRj9C80L7Qs9C+INGB0L7QtdC00LjQvdC10L3QuNGPOiDQr9C90LTQtdC60YEg'
    '0JjQvdGC0LXRgNC90LXRgtC+0LzQtdGC0YAuJywgMTIpCiAgICBjb25maWcgPSBqc29uLmxvYWRzKHByb3ZpZGVyX2dldCgn'
    'eWFuZGV4LnJ1JywgJy9pbnRlcm5ldC9hcGkvdjAvZ2V0LXByb2Jlcz9mcm9tPWludGVybmV0Jm5vY2FjaGU9JytzdHIoaW50'
    'KHRpbWUudGltZSgpKjEwMDApKSwgNjU1MzYpKQogICAgcHJvYmVzID0gY29uZmlnLmdldCgnZG93bmxvYWQnLCB7fSkuZ2V0'
    'KCdwcm9iZXMnLCBbXSkKICAgIGNhbmRpZGF0ZXMgPSBbXQogICAgZm9yIHByb2JlIGluIHByb2JlczoKICAgICAgICB0cnk6'
    'CiAgICAgICAgICAgIGhvc3QsIHBhdGggPSB2YWxpZGF0ZV95YW5kZXhfcHJvYmUocHJvYmUuZ2V0KCd1cmwnLCAnJykpCiAg'
    'ICAgICAgZXhjZXB0IChWYWx1ZUVycm9yLCBUeXBlRXJyb3IpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmICc1'
    'MG1iJyBpbiBwYXRoIG9yICcxMDBtYicgaW4gcGF0aDoKICAgICAgICAgICAgY2FuZGlkYXRlcy5hcHBlbmQoKGhvc3QsIHBh'
    'dGgpKQogICAgaWYgbm90IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdyZWZlcmVuY2Vfc2NoZW1h'
    'X2NoYW5nZWQnKQogICAgaG9zdCwgcGF0aCA9IGNhbmRpZGF0ZXNbMF0KICAgICMgU2hvcnQgc2FtcGxlcyBhdm9pZCBhIG1p'
    'bnV0ZS1sb25nIHNhdHVyYXRpb24gd2hpbGUgdGhlIHVzZXIgd2F0Y2hlcyB2aWRlby4KICAgIHNhbXBsZXMgPSBbcHJvdmlk'
    'ZXJfZ2V0KGhvc3QsIHBhdGgsIDgqMTAyNCoxMDI0LCBtZWFzdXJlPVRydWUpIGZvciBfIGluIHJhbmdlKDIpXQogICAgcmVz'
    'dWx0ID0geydwcm92aWRlcic6ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInLCAnbmV0d29yayc6IGZpbmdlcnByaW50LCAndGlt'
    'ZSc6IGludCh0aW1lLnRpbWUoKSksCiAgICAgICAgICAgICAgJ2VzdGltYXRlZF9tYnBzJzogbWF4KHhbJ2VzdGltYXRlZF9t'
    'YnBzJ10gZm9yIHggaW4gc2FtcGxlcyksICdzYW1wbGVzJzogc2FtcGxlcywKICAgICAgICAgICAgICAnc2hvcnRfc2FtcGxl'
    'JzogVHJ1ZSwgJ2RpcmVjdF9waHlzaWNhbF9yb3V0ZSc6IFRydWV9CiAgICB3cml0ZShST09ULydyZWZlcmVuY2UuanNvbics'
    'IGpzb24uZHVtcHMocmVzdWx0KSkKICAgIHJldHVybiByZXN1bHQKCgoKZGVmIHRsc19yZXF1ZXN0KGFkZHJlc3MsIHBhdGgs'
    'IGJvZHk9Tm9uZSwgY2xpZW50PUZhbHNlLCB0aW1lb3V0PTgpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9j'
    'b250ZXh0KGNhZGF0YT1QSU5ORURfQ0EpCiAgICBpZiBjbGllbnQ6CiAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4o'
    'c3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBzb2NrID0gc29ja2V0LmNy'
    'ZWF0ZV9jb25uZWN0aW9uKChhZGRyZXNzLCA4NDQzKSwgdGltZW91dD10aW1lb3V0KQogICAgdHJ5OgogICAgICAgIHRscyA9'
    'IGNvbnRleHQud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPVNFUlZFUikKICAgIGV4Y2VwdCBCYXNlRXhjZXB0'
    'aW9uOgogICAgICAgIHNvY2suY2xvc2UoKQogICAgICAgIHJhaXNlCiAgICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRU'
    'UENvbm5lY3Rpb24oYWRkcmVzcywgODQ0MywgdGltZW91dD10aW1lb3V0KQogICAgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAg'
    'ICBlbmNvZGVkID0ganNvbi5kdW1wcyhib2R5LCBzZXBhcmF0b3JzPSgnLCcsICc6JykpLmVuY29kZSgpIGlmIGJvZHkgaXMg'
    'bm90IE5vbmUgZWxzZSBOb25lCiAgICB0cnk6CiAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdQT1NUJyBpZiBib2R5IGlz'
    'IG5vdCBOb25lIGVsc2UgJ0dFVCcsIHBhdGgsIGJvZHk9ZW5jb2RlZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVh'
    'ZGVycz17J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywgJ0Nvbm5lY3Rpb24nOiAnY2xvc2UnfSkKICAgICAg'
    'ICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgIHJhdyA9IHJlc3BvbnNlLnJlYWQoMjAwMDEp'
    'CiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBvciBsZW4ocmF3KSA+IDIwMDAwOgogICAgICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ3JlcXVlc3RfcmVqZWN0ZWQnKQogICAgICAgIHJldHVybiBqc29uLmxvYWRzKHJhdykKICAgIGZp'
    'bmFsbHk6CiAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCgoKZGVmIGVucm9sbCgpOgogICAgdG9rZW4gPSAoUk9PVC8ndG9r'
    'ZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2VuKToK'
    'ICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfdG9rZW4nKQogICAgdHJ5OgogICAgICAgIGNhY2hlZCA9IGpz'
    'b24ubG9hZHMoKFJPT1QvJ3Byb2ZpbGUuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIGlmIChjYWNoZWQuZ2V0KCdjYScp'
    'ID09IFBJTk5FRF9DQSBhbmQgY2FjaGVkLmdldCgnc2VydmVyJykgPT0gU0VSVkVSIGFuZAogICAgICAgICAgICByZS5mdWxs'
    'bWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgY2FjaGVkLmdldCgnaWRlbnRpdHknLCAnJykpIGFuZAogICAgICAgICAg'
    'ICBjYWNoZWQuZ2V0KCdlbmRwb2ludCcpIGluIChTRVJWRVIsIFNFUlZFUl9MQU4pIGFuZCBjYWNoZWQuZ2V0KCdwaHlzaWNh'
    'bF9uZXR3b3JrJykgYW5kCiAgICAgICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3g1MDknLCAnLWluJywgUk9PVC8nY2xp'
    'ZW50LnBlbScsICctY2hlY2tlbmQnLCBzdHIoNyo4NjQwMCksICctbm9vdXQnXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUg'
    'PT0gMCk6CiAgICAgICAgICAgIGNvbnRleHQgPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAg'
    'ICAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVu'
    'dC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBjdXJyZW50ID0g'
    'aGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3'
    'YXknLCAncHJlZnNyYycpfSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICBhZGRy'
    'ZXNzID0gY2FjaGVkWydlbmRwb2ludCddIGlmIGNhY2hlZC5nZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSA9PSBjdXJyZW50IGVs'
    'c2UgU0VSVkVSCiAgICAgICAgICAgIHJldHVybiBjYWNoZWRbJ2lkZW50aXR5J10sIGFkZHJlc3MKICAgIGV4Y2VwdCAoT1NF'
    'cnJvciwgVmFsdWVFcnJvciwgc3NsLlNTTEVycm9yKToKICAgICAgICBwYXNzCiAgICBzdGFnZSgndG9rZW4nLCAn0J/QvtC7'
    '0YPRh9Cw0Y4g0YHQtdGA0YLQuNGE0LjQutCw0YIg0LTQu9GPINGN0YLQvtCz0L4g0YPRgdGC0YDQvtC50YHRgtCy0LAuJywg'
    'MjUpCiAgICBpZiBub3QgKFJPT1QvJ2NsaWVudC1rZXkucGVtJykuZXhpc3RzKCk6CiAgICAgICAgY29tbWFuZChbJ29wZW5z'
    'c2wnLCAnZ2VucGtleScsICctYWxnb3JpdGhtJywgJ1JTQScsICctcGtleW9wdCcsICdyc2Ffa2V5Z2VuX2JpdHM6MzA3Mics'
    'CiAgICAgICAgICAgICAgICAgJy1vdXQnLCBST09ULydjbGllbnQta2V5LnBlbSddLCB0aW1lb3V0PTMwKQogICAgICAgIChS'
    'T09ULydjbGllbnQta2V5LnBlbScpLmNobW9kKDBvNjAwKQogICAgaWYgbm90IChST09ULydkZXZpY2UnKS5leGlzdHMoKToK'
    'ICAgICAgICB3cml0ZShST09ULydkZXZpY2UnLCBzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICBjb21tYW5kKFsnb3BlbnNz'
    'bCcsICdyZXEnLCAnLW5ldycsICcta2V5JywgUk9PVC8nY2xpZW50LWtleS5wZW0nLCAnLXN1YmonLCAnL0NOPWV2Z2VuaXVt'
    'LWRldmljZScsCiAgICAgICAgICAgICAnLW91dCcsIFJPT1QvJ3JlcXVlc3QucGVtJ10pCiAgICBwYXlsb2FkID0geyd0b2tl'
    'bic6IHRva2VuLCAnZGV2aWNlJzogKFJPT1QvJ2RldmljZScpLnJlYWRfdGV4dCgpLnN0cmlwKCksICdjc3InOiAoUk9PVC8n'
    'cmVxdWVzdC5wZW0nKS5yZWFkX3RleHQoKX0KICAgIGxhc3QgPSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCBT'
    'RVJWRVJfTEFOKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgICAgICAgICBy'
    'ZXBseSA9IHRsc19yZXF1ZXN0KGFkZHJlc3MsICcvZW5yb2xsJywgcGF5bG9hZCwgdGltZW91dD02KQogICAgICAgICAgICBw'
    'cm9maWxlID0gcmVwbHkuZ2V0KCdwcm9maWxlJywge30pCiAgICAgICAgICAgIGlmIHJlcGx5LmdldCgnb2snKSBpcyBub3Qg'
    'VHJ1ZSBvciBwcm9maWxlLmdldCgnY2EnKSAhPSBQSU5ORURfQ0Egb3IgcHJvZmlsZS5nZXQoJ3NlcnZlcicpICE9IFNFUlZF'
    'UjoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9wcm9maWxlJykKICAgICAgICAgICAgaWYg'
    'bm90IHJlLmZ1bGxtYXRjaChyJ2RldmljZS1bYS1mMC05XXsyNH0nLCBwcm9maWxlLmdldCgnaWRlbnRpdHknLCAnJykpOgog'
    'ICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX2lkZW50aXR5JykKICAgICAgICAgICAgd3JpdGUo'
    'Uk9PVC8nY2xpZW50LnBlbScsIHByb2ZpbGVbJ2NlcnRpZmljYXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NhLnBl'
    'bScsIFBJTk5FRF9DQSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8neDUwOScvJ2NsaWVudC5wZW0nLCBwcm9maWxlWydjZXJ0'
    'aWZpY2F0ZSddKQogICAgICAgICAgICB3cml0ZShST09ULyd4NTA5Y2EnLydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAg'
    'ICAgIHdyaXRlKFJPT1QvJ3ByaXZhdGUnLydjbGllbnQta2V5LnBlbScsIChST09ULydjbGllbnQta2V5LnBlbScpLnJlYWRf'
    'dGV4dCgpKQogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd2ZXJpZnknLCAnLXB1cnBvc2UnLCAnc3NsY2xpZW50'
    'JywgJy1DQWZpbGUnLCBST09ULydjYS5wZW0nLCBST09ULydjbGllbnQucGVtJ10pCiAgICAgICAgICAgIGN0eCA9IHNzbC5T'
    'U0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgICAgICBjdHgubG9hZF9jZXJ0X2NoYWluKHN0cihS'
    'T09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNp'
    'Y2FsX3JvdXRlKCkKICAgICAgICAgICAgZmluZ2VycHJpbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6IHJv'
    'dXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1ZSku'
    'ZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3Byb2ZpbGUuanNvbicsIGpzb24uZHVtcHMo'
    'eyoqcHJvZmlsZSwgJ2VuZHBvaW50JzogYWRkcmVzcywgJ3BoeXNpY2FsX25ldHdvcmsnOiBmaW5nZXJwcmludH0pKQogICAg'
    'ICAgICAgICByZXR1cm4gcHJvZmlsZVsnaWRlbnRpdHknXSwgYWRkcmVzcwogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgc3Ns'
    'LlNTTEVycm9yLCBSdW50aW1lRXJyb3IpIGFzIGV4YzoKICAgICAgICAgICAgbGFzdCA9IGV4YwogICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdlbnJvbGxtZW50X3VuYXZhaWxhYmxlJykgZnJvbSBsYXN0CgoKZGVmIGRhZW1vbl9jb25maWdzKGlkZW50aXR5'
    'LCBhZGRyZXNzKToKICAgIFJVTlRJTUUubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQog'
    'ICAgaW5jbHVkZXMgPSAnXG4nLmpvaW4oJ2luY2x1ZGUgJytzdHIocCkgZm9yIHBhdHRlcm4gaW4gKCcvZXRjL3N0cm9uZ3N3'
    'YW4uZC9jaGFyb24vKi5jb25mJywgJy9ldGMvc3Ryb25nc3dhbi9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicpCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBmb3IgcCBpbiBQYXRoKCcvJykuZ2xvYihwYXR0ZXJuLmxzdHJpcCgnLycpKSkKICAgIHdy'
    'aXRlKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicsIGYnJydjaGFyb24ge3sKIGxvYWRfbW9kdWxhciA9IHllcwogaW5zdGFsbF9y'
    'b3V0ZXMgPSB5ZXMKIHJvdXRpbmdfdGFibGUgPSA1MTgyMgogcm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBwbHVnaW5zIHt7'
    'CntpbmNsdWRlc30KICB2aWNpIHt7IHNvY2tldCA9IHVuaXg6Ly97UlVOVElNRX0vY2hhcm9uLnZpY2kgfX0KICByZXNvbHZl'
    'IHt7IGxvYWQgPSBubyB9fQogIGtlcm5lbC1saWJpcHNlYyB7eyBsb2FkID0gbm8gfX0KIH19Cn19CmNoYXJvbi1zeXN0ZW1k'
    'IHt7IGpvdXJuYWwge3sgZGVmYXVsdCA9IDA7IGlrZSA9IDEgfX0gfX0KJycnKQogICAgIyBBYnNvbHV0ZSBjcmVkZW50aWFs'
    'cyBhcmUgbG9jYWwgdG8gdGhpcyBkZXZpY2UsIG5vdCBzaGFyZWQgYnkgdGhlIGFjY291bnQgdG9rZW4uCiAgICB3cml0ZShS'
    'T09ULydjb25uZWN0aW9uLmNvbmYnLCBmJycnY29ubmVjdGlvbnMge3sKIHN0YXJmaXZlIHt7CiAgdmVyc2lvbiA9IDIKICBy'
    'ZW1vdGVfYWRkcnMgPSB7YWRkcmVzc30KICB2aXBzID0gMC4wLjAuMAogIHByb3Bvc2FscyA9IGFlczI1NmdjbTE2LXByZnNo'
    'YTM4NC1lY3AzODQKICBlbmNhcCA9IHllcwogIGZyYWdtZW50YXRpb24gPSB5ZXMKICBtb2Jpa2UgPSB5ZXMKICBkcGRfZGVs'
    'YXkgPSAxNXMKICBsb2NhbCB7eyBhdXRoID0gZWFwLXRsczsgaWQgPSB7aWRlbnRpdHl9OyBlYXBfaWQgPSB7aWRlbnRpdHl9'
    'OyBjZXJ0cyA9IHtST09UfS9jbGllbnQucGVtIH19CiAgcmVtb3RlIHt7IGF1dGggPSBwdWJrZXk7IGlkID0ge1NFUlZFUn07'
    'IGNhY2VydHMgPSB7Uk9PVH0vY2EucGVtIH19CiAgY2hpbGRyZW4ge3sKICAgc3RhcmZpdmUtbmV0IHt7CiAgICBsb2NhbF90'
    'cyA9IGR5bmFtaWMKICAgIHJlbW90ZV90cyA9IDAuMC4wLjAvMAogICAgcmVxaWQgPSB7UkVRSUR9CiAgICBlc3BfcHJvcG9z'
    'YWxzID0gY2hhY2hhMjBwb2x5MTMwNQogICAgZHBkX2FjdGlvbiA9IGNsZWFyCiAgICBzdGFydF9hY3Rpb24gPSBub25lCiAg'
    'IH19CiAgfX0KIH19Cn19CnNlY3JldHMge3sgcHJpdmF0ZS1jbGllbnQge3sgZmlsZSA9IHtST09UfS9jbGllbnQta2V5LnBl'
    'bSB9fSB9fQonJycpCiAgICAjIFN0cm9uZ1N3YW4gY29uZmlnIHVzZXMgbmV3bGluZXMsIG5vdCBzZW1pY29sb24gc2VwYXJh'
    'dG9ycyAobm9ybWFsaXplIGNvbXBhY3QgYmxvY2tzKS4KICAgIGZvciBuYW1lIGluICgnc3Ryb25nc3dhbi5jb25mJywgJ2Nv'
    'bm5lY3Rpb24uY29uZicpOgogICAgICAgIHBhdGggPSBST09UL25hbWUKICAgICAgICBwYXRoLndyaXRlX3RleHQocGF0aC5y'
    'ZWFkX3RleHQoKS5yZXBsYWNlKCc7ICcsICdcbicpLnJlcGxhY2UoJ3sgJywgJ3tcbicpLnJlcGxhY2UoJyB9JywgJ1xufScp'
    'KQogICAgcnVsZXMgPSBmJycndGFibGUgaW5ldCBldm5fc3RhcmZpdmVfZ3VhcmQge3sKIGNoYWluIG91dHB1dCB7ewogIHR5'
    'cGUgZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAog'
    'IGlwIGRhZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQge3sgNTAwLCA0NTAwIH19IGFjY2VwdAogIG1ldGEgc2t1aWQgMCBpcCBk'
    'YWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlk'
    'IHtSRVFJRH0gYWNjZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkg'
    'LTEwOyBwb2xpY3kgZHJvcDsgfX0KfX0nJycKICAgIGluc2lkZShbJ25mdCcsICctYycsICctZicsICctJ10sIGRhdGE9cnVs'
    'ZXMpCiAgICBpbnNpZGUoWyduZnQnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQoKCmRlZiBzd2FuKCphcmdzLCB0aW1lb3V0'
    'PTE1LCBjaGVjaz1UcnVlKToKICAgIHJldHVybiBpbnNpZGUoWydzd2FuY3RsJywgKmFyZ3MsICctLXVyaScsICd1bml4Oi8v'
    'JytzdHIoUlVOVElNRS8nY2hhcm9uLnZpY2knKV0sIHRpbWVvdXQ9dGltZW91dCwgY2hlY2s9Y2hlY2spCgoKZGVmIGluc3Rh'
    'bGxlZCgpOgogICAgdHJ5OgogICAgICAgIHJlc3VsdCA9IHN3YW4oJy0tbGlzdC1zYXMnLCAnLS1yYXcnLCB0aW1lb3V0PTMs'
    'IGNoZWNrPUZhbHNlKQogICAgICAgIHJldHVybiByZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCAnc3RhdGU9RVNUQUJMSVNI'
    'RUQnIGluIHJlc3VsdC5zdGRvdXQgYW5kICdzdGF0ZT1JTlNUQUxMRUQnIGluIHJlc3VsdC5zdGRvdXQKICAgIGV4Y2VwdCAo'
    'T1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhlYWx0aCgp'
    'OgogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICByZXR1cm4gdGxzX3JlcXVlc3QoSEVBTFRILCAnL2hlYWx0aCcsIGNs'
    'aWVudD1UcnVlKS5nZXQoJ3NlcnZpY2UnKSA9PSAnZXZnZW5pdW0tc3RhcmZpdmUnCgoKZGVmIGRvd25sb2FkKHNpemU9MTA0'
    'ODU3Nik6CiAgICAjIEEgYm91bmRlZCBpbnRlZ3JpdHkgY2hlY2ssIG5vdCBhIGNsYWltIHRvIGhhdmUgbWVhc3VyZWQgdGhl'
    'IElTUCdzIG1heGltdW0gcmF0ZS4KICAgIGJsb2NrID0gaGFzaGxpYi5zaGFrZV8yNTYoYidldmdlbml1bS1zdGFyZml2ZS1p'
    'bnRlZ3JpdHktdjEnKS5kaWdlc3QoNjU1MzYpCiAgICBleHBlY3RlZCA9IGhhc2hsaWIuc2hhMjU2KChibG9jayooc2l6ZS8v'
    'bGVuKGJsb2NrKSsxKSlbOnNpemVdKS5oZXhkaWdlc3QoKQogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250'
    'ZXh0KGNhZGF0YT1QSU5ORURfQ0EpCiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScp'
    'LCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgc29jayA9IHNvY2tl'
    'dC5jcmVhdGVfY29ubmVjdGlvbigoSEVBTFRILCA4NDQzKSwgdGltZW91dD0xMCkKICAgICAgICB0bHMgPSBjb250ZXh0Lndy'
    'YXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1TRVJWRVIpCiAgICAgICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50'
    'LkhUVFBDb25uZWN0aW9uKEhFQUxUSCwgODQ0MywgdGltZW91dD0xMCk7IGNvbm5lY3Rpb24uc29jayA9IHRscwogICAgICAg'
    'IHRyeToKICAgICAgICAgICAgc3RhcnQgPSB0aW1lLm1vbm90b25pYygpCiAgICAgICAgICAgIGNvbm5lY3Rpb24ucmVxdWVz'
    'dCgnR0VUJywgJy9ibG9iP3NpemU9JytzdHIoc2l6ZSkpCiAgICAgICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlvbi5nZXRy'
    'ZXNwb25zZSgpCiAgICAgICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDA6CiAgICAgICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ3RyYW5zZmVyX2h0dHAnKQogICAgICAgICAgICBkaWdlc3QgPSBoYXNobGliLnNoYTI1NigpOyByZWNl'
    'aXZlZCA9IDAKICAgICAgICAgICAgd2hpbGUgcmVjZWl2ZWQgPCBzaXplOgogICAgICAgICAgICAgICAgZGF0YSA9IHJlc3Bv'
    'bnNlLnJlYWQobWluKDY1NTM2LCBzaXplLXJlY2VpdmVkKSkKICAgICAgICAgICAgICAgIGlmIG5vdCBkYXRhOgogICAgICAg'
    'ICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBkaWdlc3QudXBkYXRlKGRhdGEpOyByZWNlaXZlZCArPSBsZW4o'
    'ZGF0YSkKICAgICAgICAgICAgZWxhcHNlZCA9IHRpbWUubW9ub3RvbmljKCktc3RhcnQKICAgICAgICBmaW5hbGx5OgogICAg'
    'ICAgICAgICBjb25uZWN0aW9uLmNsb3NlKCkKICAgIGlmIHJlY2VpdmVkICE9IHNpemUgb3IgZGlnZXN0LmhleGRpZ2VzdCgp'
    'ICE9IGV4cGVjdGVkOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW50ZWdyaXR5X2ZhaWxlZCcpCiAgICByZXR1cm4g'
    'eydieXRlcyc6IHJlY2VpdmVkLCAnZG93bmxvYWRfbWJwcyc6IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xZTYsIDIpLAog'
    'ICAgICAgICAgICAnZWxhcHNlZF9tcyc6IHJvdW5kKGVsYXBzZWQqMTAwMCksICdpbnRlZ3JpdHknOiBUcnVlLCAnbGltaXRl'
    'ZF9zYW1wbGUnOiBUcnVlfQoKCmRlZiB0b2tlbl9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICB0b2tlbiA9IChST09ULyd0'
    'b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICB0b2tlbiA9'
    'ICcnCiAgICB2YWxpZCA9IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbikgaXMgbm90IE5vbmUKICAgIHJldHVy'
    'biB7J2hhc190b2tlbic6IHZhbGlkLAogICAgICAgICAgICAndG9rZW5faGludCc6ICdFVk4xLeKAouKAouKAouKAoiDCtyBJ'
    'RCAnICsgaGFzaGxpYi5zaGEyNTYodG9rZW4uZW5jb2RlKCkpLmhleGRpZ2VzdCgpWzo4XSBpZiB2YWxpZCBlbHNlICcnfQoK'
    'CmRlZiBzYXZlX3Rva2VuKHRva2VuKToKICAgIHRva2VuID0gdG9rZW4uc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1bGxtYXRj'
    'aChUT0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0J3Rg9C20LXQvSDRgtC+0LrQtdC9'
    'INC60LvQuNC10L3RgtCwINGE0L7RgNC80LDRgtCwIEVWTjEt4oCmJykKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCwgcGFy'
    'ZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgb2xkID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAoKSBp'
    'ZiAoUk9PVC8ndG9rZW4nKS5leGlzdHMoKSBlbHNlICcnCiAgICBpZiBvbGQgPT0gdG9rZW46CiAgICAgICAgcmV0dXJuCiAg'
    'ICBpZiBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2lzLWFjdGl2ZScsICctLXF1aWV0JywgVU5JVF0sIGNoZWNrPUZhbHNlKS5y'
    'ZXR1cm5jb2RlID09IDA6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQvtGC0LrQu9GO0YfQ'
    'uNGC0LUg0YLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC10LvRjCDQv9C10YDQtdC0INGB0LzQtdC90L7QuSDRgtC+0LrQtdC9'
    '0LAuJykKICAgICMgQSBkaWZmZXJlbnQgYWNjb3VudCBuZWVkcyBpdHMgb3duIGRldmljZSBjcmVkZW50aWFscy4gTmV2ZXIg'
    'cmV1c2UgaXRzIGNlcnRpZmljYXRlLgogICAgZm9yIG5hbWUgaW4gKCdkZXZpY2UnLCAnY2xpZW50LWtleS5wZW0nLCAnY2xp'
    'ZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdwcml2YXRlL2NsaWVu'
    'dC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScpOgogICAgICAgIChST09UL25hbWUpLnVubGluayhtaXNzaW5nX29rPVRy'
    'dWUpCiAgICB3cml0ZShST09ULyd0b2tlbicsIHRva2VuKQogICAgc3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB0L7RhdGA'
    '0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFsc2UsIG1l'
    'dHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1vZGU9MG83'
    'MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4odG9rZW4p'
    'CiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQ'
    'tdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAgIyBE'
    'byBub3QgYXV0by1pbnN0YWxsIHBhY2thZ2VzIG9yIGNoYW5nZSB0aGUgd29ya2luZyBWUE4gdG8gbWFrZSBhIHRlc3Qgc3Vj'
    'Y2VlZC4KICAgIGlmIG5vdCBzaHV0aWwud2hpY2goJ3N3YW5jdGwnKSBvciBub3QgUGF0aCgnL3Vzci9zYmluL2NoYXJvbi1z'
    'eXN0ZW1kJykuaXNfZmlsZSgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0JTQu9GPINGC0LXRgdGC0L7QstC+0LPQ'
    'viDRgtGD0L3QvdC10LvRjyDQvdGD0LbQtdC9INGI0YLQsNGC0L3Ri9C5INC/0LDQutC10YIgc3Ryb25nU3dhbi4nKQogICAg'
    'aWYgcmVwYWlyOgogICAgICAgIHdyaXRlKFJPT1QvJ3JlY2FsaWJyYXRlJywgJzEnKQogICAgdW5pdCA9IGYnJydbVW5pdF0K'
    'RGVzY3JpcHRpb249RXZnZW5pdW0gaXNvbGF0ZWQgU3RhckZpdmUgUnVzc2lhLXRvLVJ1c3NpYSB0dW5uZWwKQWZ0ZXI9bmV0'
    'd29yay50YXJnZXQKW1NlcnZpY2VdClR5cGU9c2ltcGxlCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVy'
    'bmFsLXN0YXJmaXZlLXR1bm5lbApFeGVjU3RvcFBvc3Q9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2'
    'ZS10dW5uZWwtY2xlYW51cApUaW1lb3V0U3RvcFNlYz0yMApLaWxsTW9kZT1taXhlZApVTWFzaz0wMDc3Ck1lbW9yeU1heD0y'
    'NTZNClJlc3RhcnQ9bm8KJycnCiAgICB3cml0ZShQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtJykvVU5JVCwgdW5pdCkKICAg'
    'IHJlY292ZXJ5ID0gImV2Z2VuaXVtLXN0YXJmaXZlLXR1bm5lbC1yZWNvdmVyLnNlcnZpY2UiCiAgICB3cml0ZShQYXRoKCcv'
    'ZXRjL3N5c3RlbWQvc3lzdGVtJykvcmVjb3ZlcnksICIiIltVbml0XQpEZXNjcmlwdGlvbj1SZWNvdmVyIG9ubHkgaW50ZXJy'
    'dXB0ZWQgRXZnZW5pdW0gdHVubmVsIHRlc3QgcmVzb3VyY2VzCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9jYWwt'
    'ZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3JrLXByZS50YXJnZXQgdnBuLXhyYXkuc2VydmljZQpbU2VydmljZV0KVHlwZT1vbmVz'
    'aG90CkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXN0YXJmaXZlLXR1bm5lbC1jbGVhbnVwCltJ'
    'bnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAoiIiIpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2RhZW1v'
    'bi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZW5hYmxlJywgcmVjb3ZlcnldKQogICAgc3RhZ2UoJ3N0'
    'YXJ0aW5nJyAsICfQk9C+0YLQvtCy0LvRjiDRgtC10YHRgtC+0LLRi9C5INGC0YPQvdC90LXQu9GMLiDQoNCw0LHQvtGH0LjQ'
    'uSBWUE4g0YHQvtGF0YDQsNC90ZHQvS4nLCAyLCBhY3RpdmU9RmFsc2UsIHJldHJ5PTApCiAgICBjb21tYW5kKFsnc3lzdGVt'
    'Y3RsJywgJ3Jlc3RhcnQnIGlmIHJlcGFpciBlbHNlICdzdGFydCcsIFVOSVRdKQogICAgcHJpbnQoJ9Ci0LXRgdGC0L7QstGL'
    '0Lkg0YLRg9C90L3QtdC70Ywg0LfQsNC/0YPRgdC60LDQtdGC0YHRjy4g0K3RgtCw0L/RiyDQstC40LTQvdGLINCyINGB0YLR'
    'gNC+0LrQtSDRgdC+0YHRgtC+0Y/QvdC40Y8uJykKCgpkZWYgZGlzY29ubmVjdCgpOgogICAgY29tbWFuZChbJ3N5c3RlbWN0'
    'bCcsICdzdG9wJywgVU5JVF0sIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTI1KQogICAgY2xlYW51cCgpCiAgICBzdGFnZSgnb2Zm'
    'JywgJ9Ci0LXRgdGC0L7QstGL0Lkg0YLRg9C90L3QtdC70Ywg0LLRi9C60LvRjtGH0LXQvS4g0KDQsNCx0L7Rh9C40LkgVlBO'
    'INGB0L7RhdGA0LDQvdGR0L0uJywgMCwgYWN0aXZlPUZhbHNlKQogICAgcHJpbnQoJ9Ci0LXRgdGC0L7QstGL0Lkg0YLRg9C9'
    '0L3QtdC70Ywg0LLRi9C60LvRjtGH0LXQvS4nKQoKCmRlZiBzdGFydF9kYWVtb24oZW52KToKICAgIChSVU5USU1FLydjaGFy'
    'b24udmljaScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICBsb2cgPSAoUk9PVC8nY2hhcm9uLmxvZycpLm9wZW4oJ3cn'
    'KQogICAgZGFlbW9uID0gc3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywgJ25ldG5zJywgJ2V4ZWMnLCBOUywgJy91c3Ivc2Jpbi9j'
    'aGFyb24tc3lzdGVtZCddLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnY9ZW52LCBzdGRpbj1zdWJwcm9jZXNz'
    'LkRFVk5VTEwsIHN0ZG91dD1sb2csIHN0ZGVycj1sb2cpCiAgICBsb2cuY2xvc2UoKQogICAgZm9yIF8gaW4gcmFuZ2UoNjAp'
    'OgogICAgICAgIGlmIFNUT1Agb3IgZGFlbW9uLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdkYWVtb25fc3RvcHBlZCcpCiAgICAgICAgaWYgKFJVTlRJTUUvJ2NoYXJvbi52aWNpJykuZXhpc3RzKCkgYW5k'
    'IHN3YW4oJy0tc3RhdHMnLCBjaGVjaz1GYWxzZSwgdGltZW91dD0xKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgICAgIGJy'
    'ZWFrCiAgICAgICAgdGltZS5zbGVlcCguMSkKICAgIHN3YW4oJy0tbG9hZC1jcmVkcycsICctLW5vcHJvbXB0JywgJy0tZmls'
    'ZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICBzd2FuKCctLWxvYWQtY29ubnMnLCAnLS1maWxlJywgUk9PVC8nY29u'
    'bmVjdGlvbi5jb25mJykKICAgIHJldHVybiBkYWVtb24KCgpkZWYgd29ya2VyKCk6CiAgICBnbG9iYWwgU1RPUAogICAgU1RP'
    'UCA9IEZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLCBsYW1iZGEgKl86IGdsb2JhbHMoKS5fX3NldGl0'
    'ZW1fXygnU1RPUCcsIFRydWUpKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULCBsYW1iZGEgKl86IGdsb2JhbHMo'
    'KS5fX3NldGl0ZW1fXygnU1RPUCcsIFRydWUpKQogICAgZGFlbW9uID0gTm9uZQogICAgdHJ5OgogICAgICAgIGNsZWFudXAo'
    'KQogICAgICAgIHN0YWdlKCdwcmVwYXJlJywgJ9Ch0L7Qt9C00LDRjiDQvtGC0LTQtdC70YzQvdGD0Y4g0YHQtdGC0Ywg0LTQ'
    'u9GPINC40YHQv9GL0YLQsNC90LjQuS4nLCA4LCBhY3RpdmU9RmFsc2UpCiAgICAgICAgc2V0dXBfbmV0d29yaygpCiAgICAg'
    'ICAgdHJ5OgogICAgICAgICAgICByZWZlcmVuY2UgPSByZWZlcmVuY2Vfc2FtcGxlKGZvcmNlPShST09ULydyZWNhbGlicmF0'
    'ZScpLmV4aXN0cygpKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgUnVudGltZUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAg'
    'ICAgICAgcmVmZXJlbmNlID0geydhdmFpbGFibGUnOiBGYWxzZSwgJ3Byb3ZpZGVyJzogJ1lhbmRleCBJbnRlcm5ldG9tZXRl'
    'cid9CiAgICAgICAgKFJPT1QvJ3JlY2FsaWJyYXRlJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgICAgICBzdGFnZSgn'
    'dG9rZW4nLCAn0J/RgNC+0LLQtdGA0Y/RjiDRgtC+0LrQtdC9INC4INGB0L7RhdGA0LDQvdGR0L3QvdC+0LUg0L/QvtC00LrQ'
    'u9GO0YfQtdC90LjQtSDRjdGC0L7Qs9C+INGD0YHRgtGA0L7QudGB0YLQstCwLicsIDIwKQogICAgICAgIGlkZW50aXR5LCBh'
    'ZGRyZXNzID0gZW5yb2xsKCkKICAgICAgICBzY29wZSA9ICdsYW4nIGlmIGFkZHJlc3MgPT0gU0VSVkVSX0xBTiBlbHNlICdw'
    'dWJsaWMtYWRkcmVzcycKICAgICAgICBzdGFnZSgnZGFlbW9uJywgJ9CX0LDQv9GD0YHQutCw0Y4g0YLRg9C90L3QtdC70Ywg'
    'SUtFdjIg0KDQvtGB0YHQuNGPIOKGkiDQoNC+0YHRgdC40Y8uJywgNDAsIHNjb3BlPXNjb3BlKQogICAgICAgIGRhZW1vbl9j'
    'b25maWdzKGlkZW50aXR5LCBhZGRyZXNzKQogICAgICAgIGVudiA9IHsqKm9zLmVudmlyb24sICdTVFJPTkdTV0FOX0NPTkYn'
    'OiBzdHIoUk9PVC8nc3Ryb25nc3dhbi5jb25mJyl9CiAgICAgICAgZW52LnBvcCgnTk9USUZZX1NPQ0tFVCcsIE5vbmUpCiAg'
    'ICAgICAgZGFlbW9uID0gc3RhcnRfZGFlbW9uKGVudikKICAgICAgICBzdGFnZSgnaGFuZHNoYWtlJywgJ9Cj0YHRgtCw0L3Q'
    'sNCy0LvQuNCy0LDRjiDQt9Cw0YnQuNGJ0ZHQvdC90L7QtSDRgdC+0LXQtNC40L3QtdC90LjQtSDRgdC+IFN0YXJGaXZlLics'
    'IDYwKQogICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCAnLS1jaGlsZCcsICdzdGFyZml2ZS1uZXQnLCB0aW1lb3V0PTM1KQog'
    'ICAgICAgIGlmIG5vdCBpbnN0YWxsZWQoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdzYV9ub3RfaW5zdGFs'
    'bGVkJykKICAgICAgICBzdGFnZSgnaGVhbHRoJywgJ9Cf0YDQvtCy0LXRgNGP0Y4g0YLRg9C90L3QtdC70Ywg0Lgg0LfQsNGJ'
    '0LjRidGR0L3QvdGL0Lkg0L7RgtCy0LXRgiDRgdC10YDQstC10YDQsC4nLCA3NSkKICAgICAgICBpZiBub3QgaGVhbHRoKCk6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaGVhbHRoX2ZhaWxlZCcpCiAgICAgICAgc3RhZ2UoJ21lYXN1cmUn'
    'LCAn0J/RgNC+0LLQtdGA0Y/RjiDQv9C10YDQtdC00LDRh9GDINC00LDQvdC90YvRhSDQuCDRhtC10LvQvtGB0YLQvdC+0YHR'
    'gtGMINGE0LDQudC70LAuJywgODUpCiAgICAgICAgbWV0cmljcyA9IGRvd25sb2FkKCkKICAgICAgICBtZXRyaWNzWydyZWZl'
    'cmVuY2UnXSA9IHJlZmVyZW5jZQogICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCAn0KLRg9C90L3QtdC70Ywg0KDQvtGB0YHQ'
    'uNGPIOKGkiDQoNC+0YHRgdC40Y8g0YDQsNCx0L7RgtCw0LXRgi4g0KDQsNCx0L7Rh9C40LkgVlBOINC90LUg0L/QtdGA0LXQ'
    'utC70Y7Rh9Cw0LvRgdGPLicsIDEwMCwKICAgICAgICAgICAgICBhY3RpdmU9VHJ1ZSwgbWV0cmljcz1tZXRyaWNzLCBzaW5j'
    'ZT1pbnQodGltZS50aW1lKCkpKQogICAgICAgIGZhaWx1cmVzID0gMAogICAgICAgIHdoaWxlIG5vdCBTVE9QOgogICAgICAg'
    'ICAgICBmb3IgXyBpbiByYW5nZSgxMDApOgogICAgICAgICAgICAgICAgaWYgU1RPUDoKICAgICAgICAgICAgICAgICAgICBi'
    'cmVhawogICAgICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICAgICAgaWYgU1RPUDoKICAgICAgICAgICAgICAg'
    'IGJyZWFrCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIG9rID0gZGFlbW9uLnBvbGwoKSBpcyBOb25lIGFuZCBp'
    'bnN0YWxsZWQoKSBhbmQgaGVhbHRoKCkKICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBSdW50aW1lRXJyb3IsIHN1YnBy'
    'b2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgICAgICAgICAgb2sgPSBGYWxzZQogICAgICAgICAgICBmYWlsdXJlcyA9'
    'IDAgaWYgb2sgZWxzZSBmYWlsdXJlcysxCiAgICAgICAgICAgIGlmIGZhaWx1cmVzID09IDE6CiAgICAgICAgICAgICAgICBz'
    'dGFnZSgnY2hlY2tpbmcnLCAn0J7RgtCy0LXRgiBTdGFyRml2ZSDQt9Cw0LTQtdGA0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+'
    '0LLQtdGA0Y/RjiDRgtC10YHRgtC+0LLQvtC1INGB0L7QtdC00LjQvdC10L3QuNC1LicsIDkwLCBhY3RpdmU9RmFsc2UpCiAg'
    'ICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBpZiBmYWlsdXJlcyA+PSAyOgogICAgICAgICAgICAgICAgc3Rh'
    'Z2UoJ3JlcGFpcmluZycsICfQodCy0Y/Qt9GMINGB0L4gU3RhckZpdmUg0L/QvtGC0LXRgNGP0L3QsC4g0JLQvtGB0YHRgtCw'
    '0L3QsNCy0LvQuNCy0LDRjiDRgtC10YHRgtC+0LLRi9C5INGC0YPQvdC90LXQu9GMLicsIDYwLCBhY3RpdmU9RmFsc2UpCiAg'
    'ICAgICAgICAgICAgICBpZiBkYWVtb24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAgIGluc2lkZShb'
    'J2lwJywgJ3hmcm0nLCAnc3RhdGUnLCAnZmx1c2gnXSkKICAgICAgICAgICAgICAgICAgICBpbnNpZGUoWydpcCcsICd4ZnJt'
    'JywgJ3BvbGljeScsICdmbHVzaCddKQogICAgICAgICAgICAgICAgICAgIGluc2lkZShbJ2lwJywgJ3JvdXRlJywgJ2ZsdXNo'
    'JywgJ3RhYmxlJywgJzUxODIyJ10sIGNoZWNrPUZhbHNlKQogICAgICAgICAgICAgICAgICAgIGRhZW1vbiA9IHN0YXJ0X2Rh'
    'ZW1vbihlbnYpCiAgICAgICAgICAgICAgICBzd2FuKCctLXRlcm1pbmF0ZScsICctLWlrZScsICdzdGFyZml2ZScsIGNoZWNr'
    'PUZhbHNlKQogICAgICAgICAgICAgICAgc3dhbignLS1pbml0aWF0ZScsICctLWNoaWxkJywgJ3N0YXJmaXZlLW5ldCcsIHRp'
    'bWVvdXQ9MzUpCiAgICAgICAgICAgICAgICBpZiBub3QgaW5zdGFsbGVkKCkgb3Igbm90IGhlYWx0aCgpOgogICAgICAgICAg'
    'ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVjb3ZlcnlfZmFpbGVkJykKICAgICAgICAgICAgICAgIGZhaWx1cmVz'
    'ID0gMAogICAgICAgICAgICBzdGFnZSgnY29ubmVjdGVkJywgJ9Ci0YPQvdC90LXQu9GMINCg0L7RgdGB0LjRjyDihpIg0KDQ'
    'vtGB0YHQuNGPINGA0LDQsdC+0YLQsNC10YIuINCg0LDQsdC+0YfQuNC5IFZQTiDQvdC1INC/0LXRgNC10LrQu9GO0YfQsNC7'
    '0YHRjy4nLCAxMDAsIGFjdGl2ZT1UcnVlKQogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yLCBSdW50aW1lRXJyb3Is'
    'IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBjb2RlID0gc3RyKGV4YykgaWYgcmUuZnVsbG1h'
    'dGNoKHIiW2Etel9dezEsNjR9Iiwgc3RyKGV4YykpIGVsc2UgdHlwZShleGMpLl9fbmFtZV9fCiAgICAgICAgY3VycmVudCA9'
    'IHNhdmVkKCkuZ2V0KCdwaGFzZScsICdwcmVwYXJlJykKICAgICAgICBtZXNzYWdlID0geyd0b2tlbic6ICfQndC1INGD0LTQ'
    'sNC70L7RgdGMINC/0L7QtNGC0LLQtdGA0LTQuNGC0Ywg0YLQvtC60LXQvSDQuNC70Lgg0L/QvtC70YPRh9C40YLRjCDRgdC1'
    '0YDRgtC40YTQuNC60LDRgiBTdGFyRml2ZS4nLAogICAgICAgICAgICAgICAgICAgJ2hhbmRzaGFrZSc6ICdTdGFyRml2ZSDQ'
    'vdC1INC/0L7QtNGC0LLQtdGA0LTQuNC7INC/0L7QtNC60LvRjtGH0LXQvdC40LUgSUtFdjIuJywKICAgICAgICAgICAgICAg'
    'ICAgICdtZWFzdXJlJzogJ9Cf0YDQvtCy0LXRgNC60LAg0L/QtdGA0LXQtNCw0YfQuCDQtNCw0L3QvdGL0YUg0L3QtSDQv9GA'
    '0L7RiNC70LAuJywKICAgICAgICAgICAgICAgICAgICdyZXBhaXJpbmcnOiAn0JDQstGC0L7QstC+0YHRgdGC0LDQvdC+0LLQ'
    'u9C10L3QuNC1INC90LUg0YPQtNCw0LvQvtGB0YwuINCd0LDQttC80LjRgtC1IMKr0J/QvtGH0LjQvdC40YLRjMK7Lid9Lmdl'
    'dChjdXJyZW50LCAn0KLQtdGB0YLQvtCy0YvQuSDRgtGD0L3QvdC10LvRjCDQvdC1INC30LDQv9GD0YHRgtC40LvRgdGPLiDQ'
    'ndCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nKQogICAgICAgIHN0YWdlKCdmYWlsZWQnLCBtZXNzYWdlKycg'
    '0KDQsNCx0L7Rh9C40LkgVlBOINGB0L7RhdGA0LDQvdGR0L0uJywgMCwgYWN0aXZlPUZhbHNlLCBlcnJvcl9jb2RlPWNvZGUs'
    'IG1ldHJpY3M9e30pCiAgICBmaW5hbGx5OgogICAgICAgIGlmIGRhZW1vbiBhbmQgZGFlbW9uLnBvbGwoKSBpcyBOb25lOgog'
    'ICAgICAgICAgICBkYWVtb24udGVybWluYXRlKCkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgZGFlbW9uLndh'
    'aXQodGltZW91dD02KQogICAgICAgICAgICBleGNlcHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDoKICAgICAgICAgICAg'
    'ICAgIGRhZW1vbi5raWxsKCk7IGRhZW1vbi53YWl0KHRpbWVvdXQ9MykKICAgICAgICBjbGVhbnVwKCkKICAgICAgICBpZiBT'
    'VE9QOgogICAgICAgICAgICBzdGFnZSgnb2ZmJywgJ9Ci0LXRgdGC0L7QstGL0Lkg0YLRg9C90L3QtdC70Ywg0LLRi9C60LvR'
    'jtGH0LXQvS4g0KDQsNCx0L7Rh9C40LkgVlBOINGB0L7RhdGA0LDQvdGR0L0uJywgMCwgYWN0aXZlPUZhbHNlKQo='
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
    'IHJldHVybiB7InR1bm5lbCI6IHR1bm5lbC5zdGF0dXMoKSBpZiB0dW5uZWwgZWxzZSB7fSwKICAgICAgICAgICAgImNvbmZp'
    'Z3VyZWQiOiBST09ULmpvaW5wYXRoKCJwcm9maWxlLmpzb24iKS5leGlzdHMoKSwKICAgICAgICAgICAgImF2YWlsYWJsZSI6'
    'IGF2YWlsYWJsZSgpLCAiaXBzZWNfYmFja2VuZCI6YmFja2VuZCgpLCAidXNlcnNwYWNlX3ZlcnNpb24iOlVTRVJTUEFDRV9W'
    'RVJTSU9OLAogICAgICAgICAgICAiYWN0aXZlIjogbGl2ZSwgImd1YXJkIjogZ3VhcmQsCiAgICAgICAgICAgICJ0ZWxlbWV0'
    'cnkiOiBib29sKHN0YXRlLmdldCgidGVsZW1ldHJ5IiwgRmFsc2UpKSwKICAgICAgICAgICAgInBoYXNlIjogImNvbm5lY3Rl'
    'ZCIgaWYgbGl2ZSBlbHNlICgiYmxvY2tlZCIgaWYgZ3VhcmQgZWxzZSAib2ZmIiksCiAgICAgICAgICAgICJzZXJ2ZXIiOiBT'
    'RVJWRVIsICJlZ3Jlc3MiOiAi0KDQvtGB0YHQuNGPIOKAlCDRgtC10YHRgtC+0LLRi9C5INCy0YvRhdC+0LQiLAogICAgICAg'
    'ICAgICAibGFzdF9yZXBvcnQiOiBzdGF0ZS5nZXQoImxhc3RfcmVwb3J0IiwgIiIpLAogICAgICAgICAgICAibGFzdF9lcnJv'
    'ciI6IHN0YXRlLmdldCgibGFzdF9lcnJvciIsICIiKSwKICAgICAgICAgICAgImRlbGl2ZXJ5IjogeyJzdGF0dXMiOnN0YXRl'
    'LmdldCgnZGVsaXZlcnlfc3RhdHVzJywnaWRsZScpLAogICAgICAgICAgICAgICAgICAgICAgICAgImVycm9yIjpzdGF0ZS5n'
    'ZXQoJ2RlbGl2ZXJ5X2Vycm9yJywnJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAiYXR0ZW1wdCI6c3RhdGUuZ2V0KCdk'
    'ZWxpdmVyeV9hdHRlbXB0JywwKSwKICAgICAgICAgICAgICAgICAgICAgICAgICJwZW5kaW5nIjpsZW4obGlzdCgoUk9PVC8n'
    'b3V0Ym94JykuZ2xvYignKi5qc29uJykpKSArIGludChQRU5ESU5HX1RFU1QuZXhpc3RzKCkpfSwKICAgICAgICAgICAgInRl'
    'c3QiOiB0ZXN0X3N0YXR1cygpLAogICAgICAgICAgICAicHJvZmlsZV9wYXRoIjogIn4vVnBuL1N0YXJGaXZlL3Byb2ZpbGUu'
    'anNvbiJ9CgoKZGVmIHZhbGlkYXRlX3Byb2ZpbGUocCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShwLCBkaWN0KSBvciBwLmdl'
    'dCgic2NoZW1hIikgIT0gMSBvciBwLmdldCgic2VydmVyIikgIT0gU0VSVkVSOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3Io'
    'ItCe0LbQuNC00LDQtdGC0YHRjyDQv9C10YDRgdC+0L3QsNC70YzQvdGL0Lkg0L/RgNC+0YTQuNC70YwgU3RhckZpdmUgc2No'
    'ZW1hPTEuIikKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gociJkZXZpY2UtW2EtZjAtOV17MjR9Iiwgc3RyKHAuZ2V0KCJpZGVu'
    'dGl0eSIsICIiKSkpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoItCd0LXQutC+0YDRgNC10LrRgtC90YvQuSDQuNC00LXQ'
    'vdGC0LjRhNC40LrQsNGC0L7RgCDRg9GB0YLRgNC+0LnRgdGC0LLQsC4iKQogICAgZm9yIGZpZWxkLCBtYXJrZXIgaW4gKCgi'
    'Y2EiLCAiQ0VSVElGSUNBVEUiKSwgKCJjZXJ0aWZpY2F0ZSIsICJDRVJUSUZJQ0FURSIpLAogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICgicHJpdmF0ZV9rZXkiLCAiUFJJVkFURSBLRVkiKSk6CiAgICAgICAgcyA9IHAuZ2V0KGZpZWxkKQogICAgICAg'
    'IGlmIG5vdCBpc2luc3RhbmNlKHMsIHN0cikgb3IgbGVuKHMpID4gMzI3Njggb3IgKCItLS0tLUJFR0lOICIgKyBtYXJrZXIg'
    'KyAiLS0tLS0iKSBub3QgaW4gczoKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigi0J3QtdC60L7RgNGA0LXQutGC0L3R'
    'i9C1INC00LDQvdC90YvQtSDRgdC10YDRgtC40YTQuNC60LDRgtC+0LIuIikKICAgIHJldHVybiBwCgoKZGVmIGltcG9ydF9w'
    'cm9maWxlKHNldHRpbmdzLCBuYW1lKToKICAgIGlmIGFjdGl2ZV9ndWFyZCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cigi0KHQvdCw0YfQsNC70LAg0LLRi9C60LvRjtGH0Lgg0Y3QutGB0L/QtdGA0LjQvNC10L3RgtCw0LvRjNC90L7QtSDRgdC+'
    '0LXQtNC40L3QtdC90LjQtS4iKQogICAgcGF0aCA9IHBhdGhsaWIuUGF0aChuYW1lKS5leHBhbmR1c2VyKCkKICAgIGlmIG5h'
    'bWUuc3RhcnRzd2l0aCgifi8iKToKICAgICAgICBwYXRoID0gcGF0aGxpYi5QYXRoKHNldHRpbmdzWyJvd25lcl9ob21lIl0p'
    'IC8gbmFtZVsyOl0KICAgIGltcG9ydCBwd2QKICAgIHVpZCA9IHB3ZC5nZXRwd25hbShzdHIoc2V0dGluZ3NbIm93bmVyX3Vz'
    'ZXIiXSkpLnB3X3VpZAogICAgIyBOZXZlciBsZXQgYSBwYXNzd29yZGxlc3Mgc3VkbyBhY3Rpb24gcmVhZCBhIHJvb3Qgc2Vj'
    'cmV0IG9yIGEgc3BlY2lhbCBmaWxlLgogICAgZmQgPSBvcy5vcGVuKHBhdGgsIG9zLk9fUkRPTkxZIHwgb3MuT19OT05CTE9D'
    'SyB8IG9zLk9fTk9GT0xMT1cpCiAgICB3aXRoIG9zLmZkb3BlbihmZCwgInJiIikgYXMgZjoKICAgICAgICBzdCA9IG9zLmZz'
    'dGF0KGYuZmlsZW5vKCkpCiAgICAgICAgaW1wb3J0IHN0YXQKICAgICAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21v'
    'ZGUpIG9yIHN0LnN0X3VpZCAhPSB1aWQgb3Igc3Quc3Rfc2l6ZSA+IDExMDAwMDoKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCLQn9GA0L7RhNC40LvRjCDQtNC+0LvQttC10L0g0LHRi9GC0Ywg0L7QsdGL0YfQvdGL0Lwg0YTQsNC50LvQvtC8'
    'INCy0LvQsNC00LXQu9GM0YbQsCDQutC70LjQtdC90YLQsCwg0L3QtSDQsdC+0LvQtdC1IDExMCDQmtCRLiIpCiAgICAgICAg'
    'cCA9IHZhbGlkYXRlX3Byb2ZpbGUoanNvbi5sb2FkcyhmLnJlYWQoMTEwMDAxKSkpCiAgICBpbXBvcnQgdGVtcGZpbGUKICAg'
    'IHdpdGggdGVtcGZpbGUuVGVtcG9yYXJ5RGlyZWN0b3J5KCkgYXMgdG1wOgogICAgICAgIHN0YWdlID0gcGF0aGxpYi5QYXRo'
    'KHRtcCkKICAgICAgICBmb3Iga2V5LCBmaWxlbmFtZSBpbiAoKCJjYSIsICJjYS5wZW0iKSwgKCJjZXJ0aWZpY2F0ZSIsICJj'
    'ZXJ0LnBlbSIpLCAoInByaXZhdGVfa2V5IiwgImtleS5wZW0iKSk6CiAgICAgICAgICAgIHdyaXRlKHN0YWdlIC8gZmlsZW5h'
    'bWUsIHBba2V5XSkKICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAg'
    'ICBjdHgubG9hZF92ZXJpZnlfbG9jYXRpb25zKHN0cihzdGFnZSAvICJjYS5wZW0iKSkKICAgICAgICBjdHgubG9hZF9jZXJ0'
    'X2NoYWluKHN0cihzdGFnZSAvICJjZXJ0LnBlbSIpLCBzdHIoc3RhZ2UgLyAia2V5LnBlbSIpKQogICAgUk9PVC5ta2Rpciht'
    'b2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICB3cml0ZShST09UIC8gInByb2ZpbGUuanNvbiIs'
    'IGpzb24uZHVtcHMocCkpCiAgICB3cml0ZShST09UIC8gImNhLnBlbSIsIHBbImNhIl0pCiAgICB3cml0ZShST09UIC8gImNs'
    'aWVudC5wZW0iLCBwWyJjZXJ0aWZpY2F0ZSJdKQogICAgd3JpdGUoUk9PVCAvICJjbGllbnQta2V5LnBlbSIsIHBbInByaXZh'
    'dGVfa2V5Il0pCiAgICB3cml0ZShST09UIC8gInByaXZhdGUiIC8gImNsaWVudC1rZXkucGVtIiwgcFsicHJpdmF0ZV9rZXki'
    'XSkKICAgIHdyaXRlKFJPT1QgLyAieDUwOSIgLyAiY2xpZW50LnBlbSIsIHBbImNlcnRpZmljYXRlIl0pCiAgICB3cml0ZShS'
    'T09UIC8gIng1MDljYSIgLyAiY2EucGVtIiwgcFsiY2EiXSkKICAgIGNvbnRleHQgPSBzc2wuU1NMQ29udGV4dChzc2wuUFJP'
    'VE9DT0xfVExTX0NMSUVOVCkKICAgIGNvbnRleHQubG9hZF92ZXJpZnlfbG9jYXRpb25zKHN0cihST09UIC8gImNhLnBlbSIp'
    'KQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QgLyAiY2xpZW50LnBlbSIpLCBzdHIoUk9PVCAvICJjbGll'
    'bnQta2V5LnBlbSIpKQogICAgc2F2ZSh7InRlbGVtZXRyeSI6IFRydWUsICJsYXN0X2Vycm9yIjogIiJ9KQogICAgcHJpbnQo'
    'ItCf0YDQvtGE0LjQu9GMINGD0YHRgtCw0L3QvtCy0LvQtdC9LiDQktGA0LXQvNC10L3QvdCw0Y8g0LTQuNCw0LPQvdC+0YHR'
    'gtC40LrQsCDQstC60LvRjtGH0LXQvdCwOyDQtdGRINC80L7QttC90L4g0LLRi9C60LvRjtGH0LjRgtGMINC30LTQtdGB0Ywg'
    '0LbQtS4iKQoKCmRlZiBwcmVwYXJlKCk6CiAgICBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiOgogICAgICAgIGluc3RhbGxf'
    'dXNlcnNwYWNlKCkKICAgICAgICBwcmludCgi0JDQstGC0L7QvdC+0LzQvdGL0LkgSVBzZWMvVFVOINC00LLQuNC20L7QuiDQ'
    's9C+0YLQvtCyLiDQodC40YHRgtC10LzQvdGL0Lkg0LfQsNC/0YDQtdGCIGVzcDQg0YHQvtGF0YDQsNC90ZHQvS4iKQogICAg'
    'ICAgIHJldHVybgogICAgaWYgc2h1dGlsLndoaWNoKCJzd2FuY3RsIik6CiAgICAgICAgcmV0dXJuCiAgICBpZiBzaHV0aWwu'
    'd2hpY2goInBhY21hbiIpOgogICAgICAgIGNtZChbInBhY21hbiIsICItUyIsICItLW5lZWRlZCIsICItLW5vY29uZmlybSIs'
    'ICJzdHJvbmdzd2FuIl0sIHRpbWVvdXQ9MzAwKQogICAgZWxpZiBzaHV0aWwud2hpY2goImRuZiIpOgogICAgICAgIGNtZChb'
    'ImRuZiIsICJpbnN0YWxsIiwgIi15IiwgIi0tc2V0b3B0PWluc3RhbGxfd2Vha19kZXBzPUZhbHNlIiwgInN0cm9uZ3N3YW4i'
    'XSwgdGltZW91dD0zMDApCiAgICBlbHNlOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KPRgdGC0LDQvdC+0LLQuCBz'
    'dHJvbmdTd2FuINGBIHN3YW5jdGwg0YHRgNC10LTRgdGC0LLQsNC80Lgg0YHQstC+0LXQs9C+INC00LjRgdGC0YDQuNCx0YPR'
    'gtC40LLQsC4iKQogICAgcHJpbnQoInN0cm9uZ1N3YW4g0YPRgdGC0LDQvdC+0LLQu9C10L07INCw0LLRgtC+0L/QvtC00LrQ'
    'u9GO0YfQtdC90LjQtSDQvdC1INCy0LrQu9GO0YfQtdC90L4uIikKCgpkZWYgcmVuZGVyX2d1YXJkKCk6CiAgICB0cmFuc3Bv'
    'cnQ9KGYnICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7VFVOfSIgYWNjZXB0JyBpZiBiYWNrZW5kKCk9PSd1c2Vyc3Bh'
    'Y2UnCiAgICAgICAgICAgICAgIGVsc2UgZicgIG1ldGEgbmZwcm90byBpcHY0IGlwc2VjIG91dCByZXFpZCB7UkVRSUR9IGFj'
    'Y2VwdCcpCiAgICByZXR1cm4gZiIiInRhYmxlIGluZXQge1RBQkxFfSB7ewogY2hhaW4gb3V0cHV0IHt7CiAgdHlwZSBmaWx0'
    'ZXIgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0CiAgaXAgZGFk'
    'ZHIge1NFUlZFUn0gdWRwIGRwb3J0IHt7IDUwMCwgNDUwMCB9fSBhY2NlcHQKICBtZXRhIHNrdWlkIDAgbWV0YSBtYXJrIHtE'
    'SVJFQ1RfTUFSS30gaXAgZGFkZHIge1NFUlZFUn0gdGNwIGRwb3J0IHtESVJFQ1RfUE9SVH0gYWNjZXB0CiAgbWV0YSBuZnBy'
    'b3RvIGlwdjQgdWRwIHNwb3J0IDY4IHVkcCBkcG9ydCA2NyBhY2NlcHQKe3RyYW5zcG9ydH0KIH19CiBjaGFpbiBmb3J3YXJk'
    'IHt7CiAgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiB9fQp9fQoiIiIKCgpk'
    'ZWYgcmVuZGVyX2Nvbm5lY3Rpb24ocCk6CiAgICByZXR1cm4gZiIiImNvbm5lY3Rpb25zIHt7CiBzdGFyZml2ZSB7ewogIHZl'
    'cnNpb24gPSAyCiAgcmVtb3RlX2FkZHJzID0ge1NFUlZFUn0KICB2aXBzID0gMC4wLjAuMAogIHByb3Bvc2FscyA9IGFlczI1'
    'NmdjbTE2LXByZnNoYTM4NC1lY3AzODQsYWVzMjU2LXNoYTI1Ni1tb2RwMjA0OAogIGVuY2FwID0geWVzCiAgZnJhZ21lbnRh'
    'dGlvbiA9IHllcwogIG1vYmlrZSA9IHllcwogIGRwZF9kZWxheSA9IDMwcwogIGxvY2FsIHt7CiAgIGF1dGggPSBlYXAtdGxz'
    'CiAgIGlkID0ge3BbJ2lkZW50aXR5J119CiAgIGVhcF9pZCA9IHtwWydpZGVudGl0eSddfQogICBjZXJ0cyA9IHtST09UfS9j'
    'bGllbnQucGVtCiAgfX0KICByZW1vdGUge3sKICAgYXV0aCA9IHB1YmtleQogICBpZCA9IHtTRVJWRVJ9CiAgIGNhY2VydHMg'
    'PSB7Uk9PVH0vY2EucGVtCiAgfX0KICBjaGlsZHJlbiB7ewogICBzdGFyZml2ZS1uZXQge3sKICAgIGxvY2FsX3RzID0gZHlu'
    'YW1pYwogICAgcmVtb3RlX3RzID0gMC4wLjAuMC8wCiAgICByZXFpZCA9IHtSRVFJRH0KICAgIGVzcF9wcm9wb3NhbHMgPSBh'
    'ZXMyNTZnY20xNixhZXMyNTYtc2hhMjU2CiAgICBkcGRfYWN0aW9uID0gY2xlYXIKICAgIHN0YXJ0X2FjdGlvbiA9IG5vbmUK'
    'ICAgfX0KICB9fQogfX0KfX0KIiIiCgoKZGVmIHJlbmRlcl9zdHJvbmdzd2FuKGluY2x1ZGVzPScnKToKICAgIGlmIGJhY2tl'
    'bmQoKT09J3VzZXJzcGFjZSc6CiAgICAgICAgcGx1Z2lucz0ncmFuZG9tIG5vbmNlIG9wZW5zc2wgcGVtIHBrY3MxIHBrY3M4'
    'IHg1MDkgcHVia2V5IHJldm9jYXRpb24gY29uc3RyYWludHMga2VybmVsLWxpYmlwc2VjIGtlcm5lbC1uZXRsaW5rIHNvY2tl'
    'dC1kZWZhdWx0IGVhcC1pZGVudGl0eSBlYXAtdGxzIHZpY2knCiAgICAgICAgcmV0dXJuIGYiIiJjaGFyb24ge3sKIGxvYWRf'
    'bW9kdWxhciA9IG5vCiBsb2FkID0ge3BsdWdpbnN9CiBpbnN0YWxsX3JvdXRlcyA9IHllcwogcm91dGluZ190YWJsZSA9IDUx'
    'ODIyCiByb3V0aW5nX3RhYmxlX3ByaW8gPSAxMDAKIHBsdWdpbnMge3sKICBrZXJuZWwtbGliaXBzZWMge3sKICAgbG9hZCA9'
    'IDIwCiAgIHJhd19lc3AgPSBubwogIH19CiAga2VybmVsLW5ldGxpbmsge3sKICAgZndtYXJrID0gIXtoZXgoSUtFX01BUksp'
    'fQogIH19CiAgc29ja2V0LWRlZmF1bHQge3sKICAgZndtYXJrID0ge2hleChJS0VfTUFSSyl9CiAgfX0KICB2aWNpIHt7CiAg'
    'IHNvY2tldCA9IHtVUkl9CiAgfX0KIH19CiBmaWxlbG9nIHt7CiAgc3RkZXJyIHt7CiAgIGRlZmF1bHQgPSAxCiAgIGZsdXNo'
    'X2xpbmUgPSB5ZXMKICB9fQogfX0KfX0KIiIiCiAgICByZXR1cm4gICIiImNoYXJvbiB7CiBsb2FkX21vZHVsYXIgPSB5ZXMK'
    'IGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFibGVfcHJpbyA9IDEwMAog'
    'cGx1Z2lucyB7CiIiIiArIGluY2x1ZGVzICsgZiIiIgogIHZpY2kge3sKICAgc29ja2V0ID0ge1VSSX0KICB9fQogIHJlc29s'
    'dmUge3sKICAgbG9hZCA9IG5vCiAgfX0KICBrZXJuZWwtbGliaXBzZWMge3sKICAgbG9hZCA9IG5vCiAgfX0KIH19Cn19CmNo'
    'YXJvbi1zeXN0ZW1kIHt7CiBqb3VybmFsIHt7CiAgZGVmYXVsdCA9IDEKIH19Cn19CiIiIgoKCmRlZiBzZXJ2aWNlX2ZpbGVz'
    'KCk6CiAgICBjYW5kaWRhdGVzID0gWyIvdXNyL3NiaW4vY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9iaW4vY2hhcm9uLXN5c3Rl'
    'bWQiLCAiL3Vzci9saWIvaXBzZWMvY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9saWJleGVjL2lwc2VjL2NoYXJvbi1zeXN0ZW1k'
    'IiwKICAgICAgICAgICAgICAgICAgIi91c3IvbGliL3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQiLCAiL3Vzci9saWJleGVj'
    'L3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQiXQogICAgYmluYXJ5ID0gc3RyKFVTRVJTUEFDRS8iY2hhcm9uIikgaWYgYmFj'
    'a2VuZCgpPT0idXNlcnNwYWNlIiBhbmQgdXNlcnNwYWNlX3JlYWR5KCkgZWxzZSBuZXh0KCh4IGZvciB4IGluIGNhbmRpZGF0'
    'ZXMgaWYgcGF0aGxpYi5QYXRoKHgpLmlzX2ZpbGUoKSksIE5vbmUpCiAgICBpZiBiYWNrZW5kKCk9PSJ1c2Vyc3BhY2UiIGFu'
    'ZCBub3QgdXNlcnNwYWNlX3JlYWR5KCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQvdCw'
    '0LbQvNC4IMKr0J/QvtC00LPQvtGC0L7QstC40YLRjCBJS0V2MsK7INC00LvRjyDQt9Cw0LPRgNGD0LfQutC4IFRVTi3QtNCy'
    '0LjQttC60LAuIikKICAgIGlmIG5vdCBiaW5hcnk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQndC1INC90LDQudC0'
    '0LXQvSBjaGFyb24tc3lzdGVtZC4g0J3Rg9C20LXQvSDQv9Cw0LrQtdGCIHN0cm9uZ1N3YW4g0YEgc3lzdGVtZCBiYWNrZW5k'
    'LiIpCiAgICBjb25maWdzID0gW3N0cihwKSBmb3IgcGF0dGVybiBpbiAoIi9ldGMvc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNv'
    'bmYiLCAiL2V0Yy9zdHJvbmdzd2FuL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25mIikKICAgICAgICAgICAgICAgZm9yIHAg'
    'aW4gcGF0aGxpYi5QYXRoKCIvIikuZ2xvYihwYXR0ZXJuLmxzdHJpcCgiLyIpKV0KICAgIGluY2x1ZGVzID0gIlxuIi5qb2lu'
    'KCJpbmNsdWRlICIgKyB4IGZvciB4IGluIGNvbmZpZ3MpCiAgICAjIEROUyBpcyBtYW5hZ2VkIHRyYW5zYWN0aW9uYWxseSBi'
    'eSB0aGlzIGJhY2tlbmQsIG5vdCBieSB0aGUgcmVzb2x2ZSBwbHVnaW4uCiAgICB3cml0ZShST09UIC8gInN0cm9uZ3N3YW4u'
    'Y29uZiIscmVuZGVyX3N0cm9uZ3N3YW4oaW5jbHVkZXMpKQogICAgd3JpdGUocGF0aGxpYi5QYXRoKCIvZXRjL3N5c3RlbWQv'
    'c3lzdGVtIikgLyBVTklULCBmIiIiW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGV4cGVyaW1lbnRhbCBTdGFyRml2ZSBJ'
    'S0V2MgpBZnRlcj1uZXR3b3JrLnRhcmdldApbU2VydmljZV0KVHlwZT17InNpbXBsZSIgaWYgYmFja2VuZCgpPT0idXNlcnNw'
    'YWNlIiBlbHNlICJub3RpZnkifQpFbnZpcm9ubWVudD1TVFJPTkdTV0FOX0NPTkY9e1JPT1R9L3N0cm9uZ3N3YW4uY29uZgpF'
    'eGVjU3RhcnQ9e2JpbmFyeX0KUnVudGltZURpcmVjdG9yeT1ldmdlbml1bS1pa2V2MgpSdW50aW1lRGlyZWN0b3J5TW9kZT0w'
    'NzAwCk1lbW9yeU1heD0zODRNClJlc3RhcnQ9bm8KVGltZW91dFN0YXJ0U2VjPTIwCiIiIiwgMG82NDQpCiAgICB3cml0ZShS'
    'T09UIC8gImd1YXJkLm5mdCIsIHJlbmRlcl9ndWFyZCgpKQogICAgd3JpdGUocGF0aGxpYi5QYXRoKCIvZXRjL3N5c3RlbWQv'
    'c3lzdGVtIikgLyBHVUFSRCwgZiIiIltVbml0XQpEZXNjcmlwdGlvbj1GYWlsLWNsb3NlZCBndWFyZCBmb3IgZXhwZXJpbWVu'
    'dGFsIElLRXYyCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldApXYW50cz1uZXR3b3Jr'
    'LXByZS50YXJnZXQKQWZ0ZXI9bG9jYWwtZnMudGFyZ2V0IG5mdGFibGVzLnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9b25lc2hv'
    'dApSZW1haW5BZnRlckV4aXQ9eWVzCkV4ZWNTdGFydD17c2h1dGlsLndoaWNoKCJuZnQiKX0gLWYge1JPT1R9L2d1YXJkLm5m'
    'dApFeGVjU3RvcD0te3NodXRpbC53aGljaCgibmZ0Iil9IGRlbGV0ZSB0YWJsZSBpbmV0IHtUQUJMRX0KW0luc3RhbGxdCldh'
    'bnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CiIiIiwgMG82NDQpCiAgICB3cml0ZShwYXRobGliLlBhdGgoIi9ldGMvc3lzdGVt'
    'ZC9zeXN0ZW0iKSAvIE1PTklUT1IsICIiIltVbml0XQpEZXNjcmlwdGlvbj1UZW1wb3JhcnkgU3RhckZpdmUgVlBOIGRpYWdu'
    'b3N0aWNzCkFmdGVyPWV2Z2VuaXVtLWlrZXYyLnNlcnZpY2UKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4v'
    'dnBuY3RsIGludGVybmFsLXN0YXJmaXZlLW1vbml0b3IKU3RhbmRhcmRPdXRwdXQ9bnVsbApTdGFuZGFyZEVycm9yPW51bGwK'
    'UmVzdGFydD1ubwoiIiIsIDBvNjQ0KQogICAgaW5zdGFsbF9kZWxpdmVyeSgpCgoKZGVmIGluc3RhbGxfZGVsaXZlcnkoKToK'
    'ICAgIHdyaXRlKHBhdGhsaWIuUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpIC8gREVMSVZFUlksICIiIltVbml0XQpEZXNj'
    'cmlwdGlvbj1FeHBlcmltZW50YWwgZGlyZWN0IG1UTFMgZGlhZ25vc3RpYyBkZWxpdmVyeQpBZnRlcj1uZXR3b3JrLnRhcmdl'
    'dApbU2VydmljZV0KRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtZGVsaXZlcnkK'
    'U3RhbmRhcmRPdXRwdXQ9bnVsbApTdGFuZGFyZEVycm9yPW51bGwKUmVzdGFydD1vbi1mYWlsdXJlClJlc3RhcnRTZWM9MzAK'
    'W0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CiIiIiwgMG82NDQpCiAgICBjbWQoWyJzeXN0ZW1jdGwiLCAi'
    'ZGFlbW9uLXJlbG9hZCJdKQogICAgY21kKFsnc3lzdGVtY3RsJywnZW5hYmxlJyxERUxJVkVSWV0sY2hlY2s9RmFsc2UpCiAg'
    'ICAjIFVwZ3JhZGUgYW4gYWxyZWFkeSBhY3RpdmUgZXhwZXJpbWVudGFsIGd1YXJkIHdpdGhvdXQgb3BlbmluZyBvcmRpbmFy'
    'eSB0cmFmZmljLgogICAgaWYgYWN0aXZlX2d1YXJkKCk6CiAgICAgICAgcnVsZXM9Y21kKFsnbmZ0JywnbGlzdCcsJ2NoYWlu'
    'JywnaW5ldCcsVEFCTEUsJ291dHB1dCddLGNoZWNrPUZhbHNlKS5zdGRvdXQKICAgICAgICBpZiBzdHIoRElSRUNUX01BUksp'
    'IG5vdCBpbiBydWxlcyBhbmQgaGV4KERJUkVDVF9NQVJLKSBub3QgaW4gcnVsZXM6CiAgICAgICAgICAgIGNtZChbJ25mdCcs'
    'J2luc2VydCcsJ3J1bGUnLCdpbmV0JyxUQUJMRSwnb3V0cHV0JywnbWV0YScsJ3NrdWlkJywnMCcsCiAgICAgICAgICAgICAg'
    'ICAgJ21ldGEnLCdtYXJrJyxzdHIoRElSRUNUX01BUkspLCdpcCcsJ2RhZGRyJyxTRVJWRVIsJ3RjcCcsJ2Rwb3J0JyxzdHIo'
    'RElSRUNUX1BPUlQpLCdhY2NlcHQnXSkKCgpkZWYgc2V0X2RucygpOgogICAgcmVzb2x2ZWQgPSBST09UIC8gInJlc29sdmVk'
    'LWJhY2t1cC5qc29uIgogICAgYmFja3VwID0gUk9PVCAvICJyZXNvbHYtYmFja3VwIgogICAgaWYgYmFja3VwLmV4aXN0cygp'
    'IG9yIHJlc29sdmVkLmV4aXN0cygpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0JXRgdGC0Ywg0L3QtdC30LDQstC1'
    '0YDRiNGR0L3QvdC+0LUg0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjQtSBETlMuINCh0L3QsNGH0LDQu9CwIHZwbiBleHBl'
    'cmltZW50YWwgb2ZmLiIpCiAgICBpZiBzaHV0aWwud2hpY2goInJlc29sdmVjdGwiKSBhbmQgY21kKFsic3lzdGVtY3RsIiwg'
    'ImlzLWFjdGl2ZSIsICJzeXN0ZW1kLXJlc29sdmVkIl0sIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAg'
    'cm91dGUgPSBqc29uLmxvYWRzKGNtZChbImlwIiwgIi1qIiwgInJvdXRlIiwgImdldCIsIFNFUlZFUl0pLnN0ZG91dClbMF0K'
    'ICAgICAgICBpZmFjZSA9IHJvdXRlWyJkZXYiXQogICAgICAgIGRlZiBwcmV2aW91cyhraW5kKToKICAgICAgICAgICAgdGV4'
    'dCA9IGNtZChbInJlc29sdmVjdGwiLCBraW5kLCBpZmFjZV0pLnN0ZG91dAogICAgICAgICAgICByZXR1cm4gdGV4dC5zcGxp'
    'dCgiKToiLCAxKVsxXS5zdHJpcCgpLnNwbGl0KCkgaWYgIik6IiBpbiB0ZXh0IGVsc2UgW10KICAgICAgICB3cml0ZShyZXNv'
    'bHZlZCwganNvbi5kdW1wcyh7ImlmYWNlIjogaWZhY2UsICJkbnMiOiBwcmV2aW91cygiZG5zIiksICJkb21haW4iOiBwcmV2'
    'aW91cygiZG9tYWluIil9KSkKICAgICAgICBjbWQoWyJyZXNvbHZlY3RsIiwgImRucyIsIGlmYWNlLCAiNzcuODguOC44Iiwg'
    'Ijc3Ljg4LjguMSJdKQogICAgICAgIGNtZChbInJlc29sdmVjdGwiLCAiZG9tYWluIiwgaWZhY2UsICJ+LiJdKQogICAgICAg'
    'IGNtZChbInJlc29sdmVjdGwiLCAiZmx1c2gtY2FjaGVzIl0sIGNoZWNrPUZhbHNlKQogICAgICAgIHJldHVybgogICAgd3Jp'
    'dGUoYmFja3VwLCBwYXRobGliLlBhdGgoIi9ldGMvcmVzb2x2LmNvbmYiKS5yZWFkX3RleHQoKSkKICAgICMgS2VlcCB0aGUg'
    'c3ltbGluayBpdHNlbGYgaW50YWN0IChOZXR3b3JrTWFuYWdlci9zeXN0ZW1kLXJlc29sdmVkIHNldHVwcykuCiAgICBwYXRo'
    'bGliLlBhdGgoIi9ldGMvcmVzb2x2LmNvbmYiKS53cml0ZV90ZXh0KCIjIEV2Z2VuaXVtIGV4cGVyaW1lbnRhbCBWUE5cbm5h'
    'bWVzZXJ2ZXIgNzcuODguOC44XG5uYW1lc2VydmVyIDc3Ljg4LjguMVxub3B0aW9ucyB0aW1lb3V0OjIgYXR0ZW1wdHM6Mlxu'
    'IikKCgpkZWYgcmVzdG9yZV9kbnMoKToKICAgIHJlc29sdmVkID0gUk9PVCAvICJyZXNvbHZlZC1iYWNrdXAuanNvbiIKICAg'
    'IGlmIHJlc29sdmVkLmV4aXN0cygpOgogICAgICAgIGRhdGEgPSBqc29uLmxvYWRzKHJlc29sdmVkLnJlYWRfdGV4dCgpKQog'
    'ICAgICAgIGZvciBrZXkgaW4gKCJkbnMiLCAiZG9tYWluIik6CiAgICAgICAgICAgIGNtZChbInJlc29sdmVjdGwiLCBrZXks'
    'IGRhdGFbImlmYWNlIl0sICooZGF0YVtrZXldIG9yIFsiIl0pXSkKICAgICAgICBjbWQoWyJyZXNvbHZlY3RsIiwgImZsdXNo'
    'LWNhY2hlcyJdLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXNvbHZlZC51bmxpbmsoKQogICAgYmFja3VwID0gUk9PVCAvICJy'
    'ZXNvbHYtYmFja3VwIgogICAgaWYgYmFja3VwLmV4aXN0cygpOgogICAgICAgIHBhdGhsaWIuUGF0aCgiL2V0Yy9yZXNvbHYu'
    'Y29uZiIpLndyaXRlX3RleHQoYmFja3VwLnJlYWRfdGV4dCgpKQogICAgICAgIGJhY2t1cC51bmxpbmsoKQoKCmRlZiBlbmRw'
    'b2ludChwYXRoLCBwYXlsb2FkPU5vbmUpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZmls'
    'ZT1zdHIoUk9PVCAvICJjYS5wZW0iKSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09UIC8gImNsaWVudC5w'
    'ZW0iKSwgc3RyKFJPT1QgLyAiY2xpZW50LWtleS5wZW0iKSkKICAgIGRhdGEgPSBOb25lIGlmIHBheWxvYWQgaXMgTm9uZSBl'
    'bHNlIGpzb24uZHVtcHMocGF5bG9hZCwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKS5lbmNvZGUoKQogICAgcmVxID0gdXJsbGli'
    'LnJlcXVlc3QuUmVxdWVzdChIRUFMVEggKyBwYXRoLCBkYXRhPWRhdGEsIGhlYWRlcnM9eyJDb250ZW50LVR5cGUiOiAiYXBw'
    'bGljYXRpb24vanNvbiJ9KQogICAgIyBOZXZlciBjb25zdWx0IGVudmlyb25tZW50IHByb3h5IHZhcmlhYmxlcyBmb3IgYSBw'
    'cml2YXRlIGRpYWdub3N0aWMgZW5kcG9pbnQuCiAgICBvcGVuZXIgPSB1cmxsaWIucmVxdWVzdC5idWlsZF9vcGVuZXIodXJs'
    'bGliLnJlcXVlc3QuUHJveHlIYW5kbGVyKHt9KSwgdXJsbGliLnJlcXVlc3QuSFRUUFNIYW5kbGVyKGNvbnRleHQ9Y29udGV4'
    'dCkpCiAgICB3aXRoIG9wZW5lci5vcGVuKHJlcSwgdGltZW91dD04KSBhcyByZXNwb25zZToKICAgICAgICByZXR1cm4ganNv'
    'bi5sb2FkcyhyZXNwb25zZS5yZWFkKDY1NTM2KSkKCgpkZWYgb24oYXBpLCBzZXR0aW5ncyk6CiAgICBzdGFydGVkPXRpbWUu'
    'bW9ub3RvbmljKCkKICAgIHN0YWdlPSdwcmVwYXJlJwogICAgaWYgYXBpLnNlcnZpY2VfYWN0aXZlKCk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQstGL0LrQu9GO0YfQuCDQvtCx0YvRh9C90YvQuSBYcmF5IFZQTi4g'
    '0J7QtNC90L7QstGA0LXQvNC10L3QvdC+INC00LLQsCDRgNC10LbQuNC80LAg0L3QtSDQt9Cw0L/Rg9GB0LrQsNGO0YLRgdGP'
    'LiIpCiAgICBpZiBhY3RpdmVfZ3VhcmQoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCg0LXQttC40Lwg0YPQttC1'
    'INCy0LrQu9GO0YfRkdC9INC40LvQuCDQt9Cw0LHQu9C+0LrQuNGA0L7QstCw0L0g0L/QvtGB0LvQtSDRgdCx0L7Rjy4g0JLR'
    'i9C60LvRjtGH0Lgg0LXQs9C+INC/0LXRgNC10LQg0L/QvtCy0YLQvtGA0L7QvC4iKQogICAgaWYgbm90IFJPT1Quam9pbnBh'
    'dGgoInByb2ZpbGUuanNvbiIpLmV4aXN0cygpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi0KHQvdCw0YfQsNC70LAg'
    '0LjQvNC/0L7RgNGC0LjRgNGD0Lkg0L/QtdGA0YHQvtC90LDQu9GM0L3Ri9C5INC/0YDQvtGE0LjQu9GMIFN0YXJGaXZlLiIp'
    'CiAgICBpZiBub3QgYXZhaWxhYmxlKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQodC90LDRh9Cw0LvQsCDQvdCw'
    '0LbQvNC4IMKr0J/QvtC00LPQvtGC0L7QstC40YLRjCBJS0V2MsK7LiIpCiAgICAjIEV4aXN0aW5nIHVucmVsYXRlZCBJUHNl'
    'YyBzdGF0ZSBtdXN0IG5ldmVyIGJlIHJlcGxhY2VkLgogICAgaWYgY21kKFsiaXAiLCAieGZybSIsICJzdGF0ZSJdLCBjaGVj'
    'az1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQntCx0L3QsNGA0YPQttC10L0g'
    '0LTRgNGD0LPQvtC5IElQc2VjIFZQTi4g0KHQvdCw0YfQsNC70LAg0L7RgtC60LvRjtGH0Lgg0LXQs9C+LiIpCiAgICBwID0g'
    'dmFsaWRhdGVfcHJvZmlsZShqc29uLmxvYWRzKChST09UIC8gInByb2ZpbGUuanNvbiIpLnJlYWRfdGV4dCgpKSkKICAgIGlm'
    'IGJhY2tlbmQoKT09InVzZXJzcGFjZSIgYW5kIHBhdGhsaWIuUGF0aCgiL3N5cy9jbGFzcy9uZXQiLFRVTikuZXhpc3RzKCk6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQmNC90YLQtdGA0YTQtdC50YEgaXBzZWMwINGD0LbQtSDRgdGD0YnQtdGB'
    '0YLQstGD0LXRgi4g0KHQvdCw0YfQsNC70LAg0LLRi9C60LvRjtGH0Lgg0LjRgdC/0L7Qu9GM0LfRg9GO0YnQtdC1INC10LPQ'
    'viDQv9C+0LTQutC70Y7Rh9C10L3QuNC1LiIpCiAgICBzZXJ2aWNlX2ZpbGVzKCkKICAgIHdyaXRlKFJPT1QgLyAiY29ubmVj'
    'dGlvbi5jb25mIiwgcmVuZGVyX2Nvbm5lY3Rpb24ocCkpCiAgICB0cnk6CiAgICAgICAgc3RhZ2U9J2RhZW1vbicKICAgICAg'
    'ICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RhcnQiLCBVTklUXSkKICAgICAgICB3YWl0X3VzZXJzcGFjZSgpCiAgICAgICAgc3Rh'
    'Z2U9J2NyZWRlbnRpYWxzJwogICAgICAgIHN3YW4oIi0tbG9hZC1jcmVkcyIsICItLWZpbGUiLCBST09UIC8gImNvbm5lY3Rp'
    'b24uY29uZiIpCiAgICAgICAgc3dhbigiLS1sb2FkLWNvbm5zIiwgIi0tZmlsZSIsIFJPT1QgLyAiY29ubmVjdGlvbi5jb25m'
    'IikKICAgICAgICBzdGFnZT0nZ3VhcmQnCiAgICAgICAgd3JpdGUoUlVOVElNRSAvICJndWFyZC5uZnQiLCByZW5kZXJfZ3Vh'
    'cmQoKSkKICAgICAgICBjbWQoWyJuZnQiLCAiLWMiLCAiLWYiLCBSVU5USU1FIC8gImd1YXJkLm5mdCJdKQogICAgICAgICMg'
    'QWxsIHByZXBhcmF0b3J5IGNoZWNrcyBhYm92ZSBhcmUgbm9uLWRpc3J1cHRpdmUuIFRoZSBndWFyZCBnb2VzIGZpcnN0Lgog'
    'ICAgICAgIGNtZChbInN5c3RlbWN0bCIsICJlbmFibGUiLCAiLS1ub3ciLCBHVUFSRF0pCiAgICAgICAgaWYgbm90IGFjdGl2'
    'ZV9ndWFyZCgpOgogICAgICAgICAgICAjIFJlY292ZXIgYSBzdGFsZSBhY3RpdmUgc3lzdGVtZCB1bml0IHdob3NlIHRhYmxl'
    'IHdhcyBleHRlcm5hbGx5IHJlbW92ZWQuCiAgICAgICAgICAgIGNtZChbIm5mdCIsICItZiIsIFJPT1QgLyAiZ3VhcmQubmZ0'
    'Il0pCiAgICAgICAgaWYgbm90IGFjdGl2ZV9ndWFyZCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LUg'
    '0YPQtNCw0LvQvtGB0Ywg0L/QvtC00YLQstC10YDQtNC40YLRjCDRg9GB0YLQsNC90L7QstC60YMga2lsbCBzd2l0Y2guIikK'
    'ICAgICAgICBwYXRjaF9zdGF0ZSh7ICJwaGFzZSI6ICJjb25uZWN0aW5nIiwgImxhc3RfZXJyb3IiOiAiIn0pCiAgICAgICAg'
    'c3RhZ2U9J2hhbmRzaGFrZScKICAgICAgICBzd2FuKCItLWluaXRpYXRlIiwgIi0tY2hpbGQiLCAic3RhcmZpdmUtbmV0Iiwg'
    'dGltZW91dD01NSkKICAgICAgICBpZiBub3QgY29ubmVjdGVkKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigi'
    'SVBzZWMgQ0hJTERfU0Eg0L3QtSDRg9GB0YLQsNC90L7QstC70LXQvS4iKQogICAgICAgIHN0YWdlPSdkbnMnCiAgICAgICAg'
    'c2V0X2RucygpCiAgICAgICAgc3RhZ2U9J2hlYWx0aCcKICAgICAgICBoZWFsdGggPSBlbmRwb2ludCgiL2hlYWx0aCIpCiAg'
    'ICAgICAgaWYgaGVhbHRoLmdldCgic2VydmljZSIpICE9ICJldmdlbml1bS1zdGFyZml2ZSI6CiAgICAgICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcigi0J3QtSDQv9C+0LTRgtCy0LXRgNC20LTRkdC9INC00LjQsNCz0L3QvtGB0YLQuNGH0LXRgdC60LjQ'
    'uSDRgdC10YDQstC10YAgU3RhckZpdmUuIikKICAgICAgICBwYXRjaF9zdGF0ZSh7ICJwaGFzZSI6ICJjb25uZWN0ZWQiLCAi'
    'c2luY2UiOiBpbnQodGltZS50aW1lKCkpLCAibGFzdF9lcnJvciI6ICIifSkKICAgICAgICBpZiBzdG9yZWQoKS5nZXQoInRl'
    'bGVtZXRyeSIpOgogICAgICAgICAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RhcnQiLCBNT05JVE9SXSkKICAgICAgICB0cnk6'
    'IHF1ZXVlX2Nvbm5lY3Rpb24oJ2Nvbm5lY3RlZCcsJ25vbmUnLCh0aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpKjEwMDApCiAg'
    'ICAgICAgZXhjZXB0IEV4Y2VwdGlvbjogcGFzcwogICAgICAgIHByaW50KCJTdGFyRml2ZSDQv9C+0LTQutC70Y7Rh9GR0L0u'
    'INCi0LXRgdGC0L7QstGL0Lkg0LLRi9GF0L7QtDog0KDQvtGB0YHQuNGPLiBJUHY2INC4IERJUkVDVC3QuNGB0LrQu9GO0YfQ'
    'tdC90LjRjyDQt9Cw0LHQu9C+0LrQuNGA0L7QstCw0L3Riy4iKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAg'
    'ICAgY21kKFsic3lzdGVtY3RsIiwgInN0b3AiLCBNT05JVE9SXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgY21kKFsic3lzdGVt'
    'Y3RsIiwgInN0b3AiLCBVTklUXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgcmVzdG9yZV9kbnMoKQogICAgICAgIGd1YXJkZWQ9'
    'YWN0aXZlX2d1YXJkKCkKICAgICAgICBwYXRjaF9zdGF0ZSh7ICJwaGFzZSI6ICJibG9ja2VkIiBpZiBndWFyZGVkIGVsc2Ug'
    'Im9mZiIsICJsYXN0X2Vycm9yIjoKICAgICAgICAgICAgICAgICAgICAgItCf0L7QtNC60LvRjtGH0LXQvdC40LUg0L3QtSDR'
    'g9GB0YLQsNC90L7QstC70LXQvdC+OyDQuNC90YLQtdGA0L3QtdGCINC30LDQsdC70L7QutC40YDQvtCy0LDQvSDQtNC+INCy'
    '0YvQutC70Y7Rh9C10L3QuNGPINGA0LXQttC40LzQsC4iIGlmIGd1YXJkZWQgZWxzZQogICAgICAgICAgICAgICAgICAgICAi'
    '0J/QvtC00LPQvtGC0L7QstC60LAg0L3QtSDQt9Cw0LLQtdGA0YjQtdC90LA7INC/0L7QtNC60LvRjtGH0LXQvdC40LUg0Lgg'
    '0LfQsNGJ0LjRgtCwINC90LUg0LLQutC70Y7Rh9C40LvQuNGB0YwuIn0pCiAgICAgICAgdHJ5OiBxdWV1ZV9jb25uZWN0aW9u'
    'KHN0YWdlLGZhaWx1cmVfY29kZShleGMpLCh0aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpKjEwMDApCiAgICAgICAgZXhjZXB0'
    'IEV4Y2VwdGlvbjogcGFzcwogICAgICAgIGVycm9yPVJ1bnRpbWVFcnJvcigi0J/QvtC00LrQu9GO0YfQtdC90LjQtSBTdGFy'
    'Rml2ZSDQvdC1INGD0LTQsNC70L7RgdGMLiAiICsKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCJLaWxsIHN3aXRjaCDQ'
    'vtGB0YLQsNCy0LvQtdC9INCy0LrQu9GO0YfRkdC90L3Ri9C8LiDQktGL0L/QvtC70L3QuCB2cG4gZXhwZXJpbWVudGFsIG9m'
    'Zi4gIiBpZiBndWFyZGVkIGVsc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgICJLaWxsIHN3aXRjaCDQvdC1INCw0LrR'
    'gtC40LLQuNGA0L7QstCw0L06INGB0LHQvtC5INC/0YDQvtC40LfQvtGI0ZHQuyDQtNC+INCy0LrQu9GO0YfQtdC90LjRjyDR'
    'gtGD0L3QvdC10LvRjy4gIikgKyBzdHIoZXhjKSkKICAgICAgICBlcnJvci5kaWFnbm9zdGljX3F1ZXVlZD1UcnVlCiAgICAg'
    'ICAgcmFpc2UgZXJyb3IgZnJvbSBleGMKCgpkZWYgb2ZmKCk6CiAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFRFU1Rf'
    'VU5JVF0sIGNoZWNrPUZhbHNlKQogICAgY21kKFsic3lzdGVtY3RsIiwgInN0b3AiLCBNT05JVE9SXSwgY2hlY2s9RmFsc2Up'
    'CiAgICBjbWQoWyJzeXN0ZW1jdGwiLCAic3RvcCIsIFVOSVRdLCBjaGVjaz1GYWxzZSkKICAgIHJlc3RvcmVfZG5zKCkKICAg'
    'IGNtZChbInN5c3RlbWN0bCIsICJkaXNhYmxlIiwgIi0tbm93IiwgR1VBUkRdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbIm5m'
    'dCIsICJkZWxldGUiLCAidGFibGUiLCAiaW5ldCIsIFRBQkxFXSwgY2hlY2s9RmFsc2UpCiAgICBwYXRjaF9zdGF0ZSh7ICJw'
    'aGFzZSI6ICJvZmYiLCAibGFzdF9lcnJvciI6ICIifSkKICAgIHByaW50KCLQrdC60YHQv9C10YDQuNC80LXQvdGC0LDQu9GM'
    '0L3QvtC1INGB0L7QtdC00LjQvdC10L3QuNC1INCy0YvQutC70Y7Rh9C10L3Qvi4g0J7QsdGL0YfQvdGL0Lkg0LjQvdGC0LXR'
    'gNC90LXRgiDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L0uIikKCgpkZWYgdGVsZW1ldHJ5KGVuYWJsZWQpOgogICAgcGF0Y2hf'
    'c3RhdGUoeyAidGVsZW1ldHJ5IjogYm9vbChlbmFibGVkKX0pCiAgICBpZiBub3QgZW5hYmxlZDoKICAgICAgICBjbWQoWydz'
    'eXN0ZW1jdGwnLCdzdG9wJyxERUxJVkVSWV0sY2hlY2s9RmFsc2UpCiAgICAgICAgY21kKFsic3lzdGVtY3RsIiwgInN0b3Ai'
    'LCBURVNUX1VOSVRdLCBjaGVjaz1GYWxzZSkKICAgIGNtZChbInN5c3RlbWN0bCIsICJzdGFydCIgaWYgZW5hYmxlZCBhbmQg'
    'Y29ubmVjdGVkKCkgZWxzZSAic3RvcCIsIE1PTklUT1JdLCBjaGVjaz1GYWxzZSkKICAgIGlmIGVuYWJsZWQ6IGtpY2tfZGVs'
    'aXZlcnkoKQogICAgcHJpbnQoItCS0YDQtdC80LXQvdC90LDRjyDQtNC40LDQs9C90L7RgdGC0LjQutCwICIgKyAoItCy0LrQ'
    'u9GO0YfQtdC90LAiIGlmIGVuYWJsZWQgZWxzZSAi0LLRi9C60LvRjtGH0LXQvdCwIikpCgoKZGVmIGRvbWFpbl9vbmx5KHZh'
    'bHVlKToKICAgICMgRXhwbGljaXQgZG9tYWluLW9ubHkgcmVwb3J0LiBOZXZlciBhY2NlcHQgVVJMcywgcGF0aHMsIHRva2Vu'
    'cyBvciBhcmJpdHJhcnkgbG9nIHRleHQuCiAgICB2YWx1ZSA9IHZhbHVlLnN0cmlwKCkubG93ZXIoKS5yc3RyaXAoIi4iKQog'
    'ICAgaWYgbGVuKHZhbHVlKSA+IDI1MyBvciBub3QgcmUuZnVsbG1hdGNoKHIiW2EtejAtOV0oPzpbYS16MC05Li1dKlthLXow'
    'LTldKT8iLCB2YWx1ZSkgb3IgIi4iIG5vdCBpbiB2YWx1ZToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCLQktCy0LXQtNC4'
    'INC00L7QvNC10L0g0LHQtdC3IGh0dHBzOi8vLCDQv9GD0YLQuCDQuCDQv9Cw0YDQsNC80LXRgtGA0L7Qsi4iKQogICAgZm9y'
    'IGxhYmVsIGluIHZhbHVlLnNwbGl0KCIuIik6CiAgICAgICAgaWYgbm90IGxhYmVsIG9yIGxlbihsYWJlbCkgPiA2MyBvciBs'
    'YWJlbC5zdGFydHN3aXRoKCItIikgb3IgbGFiZWwuZW5kc3dpdGgoIi0iKToKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJv'
    'cigi0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC00L7QvNC10L0uIikKICAgIHRyeToKICAgICAgICBpcGFkZHJlc3MuaXBf'
    'YWRkcmVzcyh2YWx1ZSkKICAgIGV4Y2VwdCBWYWx1ZUVycm9yOgogICAgICAgIHJldHVybiB2YWx1ZQogICAgcmFpc2UgVmFs'
    'dWVFcnJvcigi0J3Rg9C20LXQvSDQtNC+0LzQtdC9INGB0LDQudGC0LAsINCwINC90LUgSVAt0LDQtNGA0LXRgS4iKQoKCmRl'
    'ZiBwcm9iZV9kb21haW4oZG9tYWluKToKICAgIGRvbWFpbiA9IGRvbWFpbl9vbmx5KGRvbWFpbikKICAgIHN0YXJ0ID0gdGlt'
    'ZS5tb25vdG9uaWMoKQogICAgdHJ5OgogICAgICAgIHJlc29sdmVkID0gc29ja2V0LmdldGFkZHJpbmZvKGRvbWFpbiwgNDQz'
    'LCBzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgICAgIGFkZHJlc3NlcyA9IGxpc3QoZGljdC5mcm9t'
    'a2V5cyh4WzRdWzBdIGZvciB4IGluIHJlc29sdmVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlm'
    'IGlwYWRkcmVzcy5pcF9hZGRyZXNzKHhbNF1bMF0pLmlzX2dsb2JhbCkpWzozXQogICAgICAgIGZvciBhZGRyZXNzIGluIGFk'
    'ZHJlc3NlczoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24o'
    'KGFkZHJlc3MsIDQ0MyksIHRpbWVvdXQ9NCkgYXMgc29jazoKICAgICAgICAgICAgICAgICAgICB3aXRoIHNzbC5jcmVhdGVf'
    'ZGVmYXVsdF9jb250ZXh0KCkud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPWRvbWFpbikgYXMgY29ubjoKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29ubi5zZW5kYWxsKCgiSEVBRCAvIEhUVFAvMS4xXHJcbkhvc3Q6ICIgKyBkb21haW4g'
    'KyAiXHJcbkNvbm5lY3Rpb246IGNsb3NlXHJcblxyXG4iKS5lbmNvZGUoKSkKICAgICAgICAgICAgICAgICAgICAgICAgbGlu'
    'ZSA9IGNvbm4ucmVjdigyNTYpLnNwbGl0KGIiXHJcbiIsIDEpWzBdCiAgICAgICAgICAgICAgICAgICAgICAgIHBhcnRzID0g'
    'bGluZS5zcGxpdCgpCiAgICAgICAgICAgICAgICAgICAgICAgIGNvZGUgPSBpbnQocGFydHNbMV0pIGlmIGxlbihwYXJ0cykg'
    'PiAxIGFuZCBwYXJ0c1sxXS5pc2RpZ2l0KCkgZWxzZSAwCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGNvZGU6CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4geyJkb21haW4iOiBkb21haW4sICJvayI6IFRydWUsICJodHRwX3N0YXR1'
    'cyI6IGNvZGUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJsYXRlbmN5X21zIjogcm91bmQoKHRpbWUu'
    'bW9ub3RvbmljKCktc3RhcnQpKjEwMDApfQogICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAg'
    'ICAgICAgICAgICAgICBjb250aW51ZQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcGFzcwogICAgcmV0dXJuIHsiZG9t'
    'YWluIjogZG9tYWluLCAib2siOiBGYWxzZSwgImVycm9yIjogImRuc190Y3Bfb3JfdGxzX2ZhaWxlZCIsCiAgICAgICAgICAg'
    'ICJsYXRlbmN5X21zIjogcm91bmQoKHRpbWUubW9ub3RvbmljKCktc3RhcnQpKjEwMDApfQoKCmRlZiByZXBvcnQoZG9tYWlu'
    'PU5vbmUpOgogICAgaWYgbm90IHN0b3JlZCgpLmdldCgidGVsZW1ldHJ5Iik6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCLQlNC40LDQs9C90L7RgdGC0LjQutCwINCy0YvQutC70Y7Rh9C10L3QsC4g0JLQutC70Y7Rh9C4INC10ZEg0Y/QstC90L4g'
    '0L/QtdGA0LXQtCDQvtGC0L/RgNCw0LLQutC+0LkuIikKICAgIGlmIG5vdCBjb25uZWN0ZWQoKToKICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoItCe0YLRh9GR0YIg0L7RgtC/0YDQsNCy0LvRj9C10YLRgdGPINGC0L7Qu9GM0LrQviDQstC90YPRgtGA'
    '0Lgg0YPRgdGC0LDQvdC+0LLQu9C10L3QvdC+0LPQviBTdGFyRml2ZSBWUE4uIikKICAgIGRvbWFpbnMgPSBbZG9tYWluX29u'
    'bHkoZG9tYWluKV0gaWYgZG9tYWluIGVsc2UgbGlzdChSVV9ET01BSU5TKQogICAgcHJvYmVzID0gW3Byb2JlX2RvbWFpbih4'
    'KSBmb3IgeCBpbiBkb21haW5zXQogICAgYm9keSA9IHsic2NoZW1hIjogMSwgImV2ZW50IjogInNpdGVfcmVwb3J0IiBpZiBk'
    'b21haW4gZWxzZSAic2FtcGxlIiwKICAgICAgICAgICAgInRpbWUiOiBpbnQodGltZS50aW1lKCkpLCAibWFuYWdlciI6ICIw'
    'LjIuMjMiLCAicGxhdGZvcm0iOiAibGludXgiLAogICAgICAgICAgICAicHJvYmVzIjogcHJvYmVzLCAiaXBzZWMiOiAiaW5z'
    'dGFsbGVkIn0KICAgIGVuZHBvaW50KCIvcmVwb3J0IiwgYm9keSkKICAgIHBhdGNoX3N0YXRlKHsgImxhc3RfcmVwb3J0Ijog'
    'dGltZS5zdHJmdGltZSgiJVktJW0tJWQgJUg6JU06JVMiLCB0aW1lLmdtdGltZSgpKSArICIgVVRDIn0pCiAgICBwcmludChq'
    'c29uLmR1bXBzKHsic2VudCI6IFRydWUsICJwcm9iZXMiOiBwcm9iZXN9LCBlbnN1cmVfYXNjaWk9RmFsc2UpKQoKCmRlZiBt'
    'b25pdG9yKCk6CiAgICB3aGlsZSBzdG9yZWQoKS5nZXQoInRlbGVtZXRyeSIpIGFuZCBjb25uZWN0ZWQoKToKICAgICAgICB0'
    'cnk6CiAgICAgICAgICAgIGZsdXNoX3Rlc3RfcmVwb3J0KCkKICAgICAgICAgICAgcmVwb3J0KCkKICAgICAgICBleGNlcHQg'
    'RXhjZXB0aW9uOgogICAgICAgICAgICBwYXNzCiAgICAgICAgdGltZS5zbGVlcCg2MCkKICAgIGlmIHN0b3JlZCgpLmdldCgn'
    'dGVsZW1ldHJ5JykgYW5kIGFjdGl2ZV9ndWFyZCgpOgogICAgICAgIHRyeTogcXVldWVfY29ubmVjdGlvbignZGlzY29ubmVj'
    'dGVkJywnbmV0d29yaycpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjogcGFzcwoKCmRlZiBkaXNwYXRjaChhcGksIHNldHRp'
    'bmdzLCBhY3Rpb24sIHRhcmdldD0iIik6CiAgICB0cnk6CiAgICAgICAgaWYgYWN0aW9uID09ICd0b2tlbi1zYXZlJyBhbmQg'
    'dHVubmVsOgogICAgICAgICAgICB0dW5uZWwuc2F2ZV90b2tlbih0YXJnZXQpCiAgICAgICAgICAgIHByaW50KCfQotC+0LrQ'
    'tdC9INGB0L7RhdGA0LDQvdGR0L0g0L3QsCDRjdGC0L7QvCDRg9GB0YLRgNC+0LnRgdGC0LLQtS4nKQogICAgICAgIGVsaWYg'
    'YWN0aW9uIGluICgnY29ubmVjdCcsICdyZXBhaXInKSBhbmQgdHVubmVsOgogICAgICAgICAgICB0dW5uZWwuY29ubmVjdCh0'
    'YXJnZXQsIHJlcGFpcj1hY3Rpb24gPT0gJ3JlcGFpcicpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gJ2Rpc2Nvbm5lY3QnIGFu'
    'ZCB0dW5uZWw6CiAgICAgICAgICAgIHR1bm5lbC5kaXNjb25uZWN0KCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAiZ2xvYmFs'
    'LXRlc3QiOiBzdGFydF9nbG9iYWxfdGVzdCgpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImNhbmNlbC10ZXN0IjogY21kKFsi'
    'c3lzdGVtY3RsIiwgInN0b3AiLCBURVNUX1VOSVRdLGNoZWNrPUZhbHNlKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJiYWNr'
    'ZW5kLXVzZXJzcGFjZSI6IHNlbGVjdF9iYWNrZW5kKCJ1c2Vyc3BhY2UiKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJiYWNr'
    'ZW5kLWtlcm5lbCI6IHNlbGVjdF9iYWNrZW5kKCJrZXJuZWwiKQogICAgICAgIGVsaWYgYWN0aW9uID09ICJwcmVwYXJlIjog'
    'cHJlcGFyZSgpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gImltcG9ydCI6IGltcG9ydF9wcm9maWxlKHNldHRpbmdzLCB0YXJn'
    'ZXQpCiAgICAgICAgZWxpZiBhY3Rpb24gPT0gIm9uIjogb24oYXBpLCBzZXR0aW5ncykKICAgICAgICBlbGlmIGFjdGlvbiA9'
    'PSAib2ZmIjogb2ZmKCkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAidGVsZW1ldHJ5LW9uIjogdGVsZW1ldHJ5KFRydWUpCiAg'
    'ICAgICAgZWxpZiBhY3Rpb24gPT0gInRlbGVtZXRyeS1vZmYiOiB0ZWxlbWV0cnkoRmFsc2UpCiAgICAgICAgZWxpZiBhY3Rp'
    'b24gPT0gInJlcG9ydCI6IHJlcG9ydCh0YXJnZXQgb3IgTm9uZSkKICAgICAgICBlbGlmIGFjdGlvbiA9PSAic2VuZC1kaWFn'
    'bm9zdGljcyI6CiAgICAgICAgICAgIGlmIG5vdCBST09ULmpvaW5wYXRoKCdwcm9maWxlLmpzb24nKS5leGlzdHMoKTogcmFp'
    'c2UgUnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQuNC80L/QvtGA0YLQuNGA0YPQuSDQv9GA0L7RhNC40LvRjC4nKQog'
    'ICAgICAgICAgICBpbnN0YWxsX2RlbGl2ZXJ5KCkKICAgICAgICAgICAgcXVldWVfY29ubmVjdGlvbignbWFudWFsJywnbm9u'
    'ZScpCiAgICAgICAgICAgIHByaW50KCfQlNC40LDQs9C90L7RgdGC0LjQutCwINGB0L7RhdGA0LDQvdC10L3QsC4g0J/RgNGP'
    '0LzQsNGPINC+0YLQv9GA0LDQstC60LAg0LLRi9C/0L7Qu9C90Y/QtdGC0YHRjyDQsiDRhNC+0L3QtS4nKQogICAgICAgIGVs'
    'aWYgYWN0aW9uID09ICJzdGF0dXMiOiBwcmludChqc29uLmR1bXBzKHN0YXR1cygpLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQog'
    'ICAgICAgIGVsc2U6IHJhaXNlIFZhbHVlRXJyb3IoItCd0LXQuNC30LLQtdGB0YLQvdCw0Y8g0Y3QutGB0L/QtdGA0LjQvNC1'
    '0L3RgtCw0LvRjNC90LDRjyDQvtC/0LXRgNCw0YbQuNGPLiIpCiAgICBleGNlcHQgKFZhbHVlRXJyb3IsIFJ1bnRpbWVFcnJv'
    'ciwgT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgIGlmIGFjdGlvbiA9PSAnb24n'
    'IGFuZCBub3QgZ2V0YXR0cihleGMsJ2RpYWdub3N0aWNfcXVldWVkJyxGYWxzZSk6CiAgICAgICAgICAgIHRyeToKICAgICAg'
    'ICAgICAgICAgIGluc3RhbGxfZGVsaXZlcnkoKQogICAgICAgICAgICAgICAgcXVldWVfY29ubmVjdGlvbigncHJlcGFyZScs'
    'ZmFpbHVyZV9jb2RlKGV4YykpCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb246IHBhc3MKICAgICAgICByYWlzZSBhcGku'
    'VlBORXJyb3Ioc3RyKGV4YykpIGZyb20gZXhjCgoKVEVTVF9VTklUID0gJ2V2Z2VuaXVtLWlrZXYyLWdsb2JhbC10ZXN0LnNl'
    'cnZpY2UnClRFU1RfU1RBVEUgPSBwYXRobGliLlBhdGgoJy92YXIvbGliL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXRlc3QuanNv'
    'bicpClBFTkRJTkdfVEVTVCA9IFJPT1QgLyAncGVuZGluZy1nbG9iYWwtdGVzdC5qc29uJwpSVV9ET01BSU5TID0gKCd5YW5k'
    'ZXgucnUnLCAnbWFpbC5ydScsICd3d3cucnQucnUnKQpURVNUX0JMT0NLID0gaGFzaGxpYi5zaGFrZV8yNTYoYidldmdlbml1'
    'bS1zdGFyZml2ZS1pbnRlZ3JpdHktdjEnKS5kaWdlc3QoNjU1MzYpCgoKZGVmIHRlc3Rfc3RhdHVzKCk6CiAgICB0cnk6CiAg'
    'ICAgICAgc3RhdGU9anNvbi5sb2FkcyhURVNUX1NUQVRFLnJlYWRfdGV4dCgpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVl'
    'RXJyb3IpOgogICAgICAgIHJldHVybiB7J3BoYXNlJzonaWRsZScsJ3Byb2dyZXNzJzowfQogICAgaWYgc3RhdGUuZ2V0KCdw'
    'aGFzZScpPT0ncnVubmluZycgYW5kIGNtZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsVEVTVF9VTklUXSxjaGVjaz1GYWxz'
    'ZSkucmV0dXJuY29kZToKICAgICAgICBzdGF0ZS51cGRhdGUocGhhc2U9J2ludGVycnVwdGVkJyxtZXNzYWdlPSfQotC10YHR'
    'giDQv9GA0LXRgNCy0LDQvS4g0JfQsNGJ0LjRgtCwIFZQTiDRgdC+0YXRgNCw0L3Rj9C10YLRgdGPLicpCiAgICByZXR1cm4g'
    'c3RhdGUKCgpkZWYgdGVzdF9zdGF0ZSgqKmZpZWxkcyk6CiAgICB0cnk6IHN0YXRlPWpzb24ubG9hZHMoVEVTVF9TVEFURS5y'
    'ZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTogc3RhdGU9e30KICAgIHdyaXRlKFRFU1RfU1RB'
    'VEUsanNvbi5kdW1wcyh7KipzdGF0ZSwqKmZpZWxkc30sZW5zdXJlX2FzY2lpPUZhbHNlKSkKCgpkZWYgdGVzdF9yZXF1ZXN0'
    'KHBhdGgsIGRhdGE9Tm9uZSwgaGVhZGVycz1Ob25lLCB0aW1lb3V0PTMwKToKICAgIGNvbnRleHQ9c3NsLmNyZWF0ZV9kZWZh'
    'dWx0X2NvbnRleHQoY2FmaWxlPXN0cihST09ULydjYS5wZW0nKSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihS'
    'T09ULydjbGllbnQucGVtJyksc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBvcGVuZXI9dXJsbGliLnJlcXVlc3Qu'
    'YnVpbGRfb3BlbmVyKHVybGxpYi5yZXF1ZXN0LlByb3h5SGFuZGxlcih7fSksdXJsbGliLnJlcXVlc3QuSFRUUFNIYW5kbGVy'
    'KGNvbnRleHQ9Y29udGV4dCkpCiAgICByZXF1ZXN0PXVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoSEVBTFRIK3BhdGgsZGF0YT1k'
    'YXRhLGhlYWRlcnM9aGVhZGVycyBvciB7fSkKICAgIHJldHVybiBvcGVuZXIub3BlbihyZXF1ZXN0LHRpbWVvdXQ9dGltZW91'
    'dCkKCgpkZWYgZXhwZWN0ZWRfaGFzaChzaXplLCBvZmZzZXQ9MCk6CiAgICBkaWdlc3Q9aGFzaGxpYi5zaGEyNTYoKQogICAg'
    'd2hpbGUgc2l6ZToKICAgICAgICBwYXJ0PVRFU1RfQkxPQ0tbb2Zmc2V0ICUgbGVuKFRFU1RfQkxPQ0spOl1bOm1pbihzaXpl'
    'LGxlbihURVNUX0JMT0NLKS1vZmZzZXQgJSBsZW4oVEVTVF9CTE9DSykpXQogICAgICAgIGRpZ2VzdC51cGRhdGUocGFydCk7'
    'IHNpemUtPWxlbihwYXJ0KTsgb2Zmc2V0Kz1sZW4ocGFydCkKICAgIHJldHVybiBkaWdlc3QuaGV4ZGlnZXN0KCkKCgpkZWYg'
    'dHJhbnNmZXJfZG93bmxvYWQoc2l6ZSwgb2Zmc2V0PTAsIGxpbWl0PU5vbmUpOgogICAgc3RhcnQ9dGltZS5tb25vdG9uaWMo'
    'KTsgcmVjZWl2ZWQ9MDsgZGlnZXN0PWhhc2hsaWIuc2hhMjU2KCkKICAgIGhlYWRlcnM9eydSYW5nZSc6ZidieXRlcz17b2Zm'
    'c2V0fS0nfSBpZiBvZmZzZXQgZWxzZSB7fQogICAgd2l0aCB0ZXN0X3JlcXVlc3QoJy9ibG9iP3NpemU9JytzdHIoc2l6ZSks'
    'aGVhZGVycz1oZWFkZXJzKSBhcyByZXNwb25zZToKICAgICAgICBpZiByZXNwb25zZS5zdGF0dXMgIT0gKDIwNiBpZiBvZmZz'
    'ZXQgZWxzZSAyMDApOiByYWlzZSBSdW50aW1lRXJyb3IoJ1VuZXhwZWN0ZWQgZmlsZSByZXNwb25zZScpCiAgICAgICAgaWYg'
    'b2Zmc2V0IGFuZCByZXNwb25zZS5oZWFkZXJzLmdldCgnQ29udGVudC1SYW5nZScpIT1mJ2J5dGVzIHtvZmZzZXR9LXtzaXpl'
    'LTF9L3tzaXplfSc6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignSW52YWxpZCByZXN1bWUgcmFuZ2UnKQogICAg'
    'ICAgIHRvdGFsPXNpemUtb2Zmc2V0IGlmIGxpbWl0IGlzIE5vbmUgZWxzZSBtaW4obGltaXQsc2l6ZS1vZmZzZXQpCiAgICAg'
    'ICAgd2hpbGUgcmVjZWl2ZWQ8dG90YWw6CiAgICAgICAgICAgIGJsb2NrPXJlc3BvbnNlLnJlYWQobWluKDY1NTM2LHRvdGFs'
    'LXJlY2VpdmVkKSkKICAgICAgICAgICAgaWYgbm90IGJsb2NrOiBicmVhawogICAgICAgICAgICBkaWdlc3QudXBkYXRlKGJs'
    'b2NrKTsgcmVjZWl2ZWQrPWxlbihibG9jaykKICAgICAgICBpbnRlZ3JpdHk9cmVjZWl2ZWQ9PXRvdGFsIGFuZCBkaWdlc3Qu'
    'aGV4ZGlnZXN0KCk9PWV4cGVjdGVkX2hhc2godG90YWwsb2Zmc2V0KQogICAgICAgIGlmIGxpbWl0IGlzIE5vbmU6CiAgICAg'
    'ICAgICAgIGludGVncml0eT1pbnRlZ3JpdHkgYW5kIHJlc3BvbnNlLmhlYWRlcnMuZ2V0KCdYLUNvbnRlbnQtU0hBMjU2Jyk9'
    'PWRpZ2VzdC5oZXhkaWdlc3QoKQogICAgZWxhcHNlZD1tYXgodGltZS5tb25vdG9uaWMoKS1zdGFydCwwLjAwMSkKICAgIHJl'
    'dHVybiB7J2tpbmQnOidkb3dubG9hZCcsJ29rJzppbnRlZ3JpdHksJ2ludGVncml0eSc6aW50ZWdyaXR5LCdieXRlcyc6cmVj'
    'ZWl2ZWQsCiAgICAgICAgICAgICdzaXplJzpzaXplLCdvZmZzZXQnOm9mZnNldCwnZWxhcHNlZF9tcyc6cm91bmQoZWxhcHNl'
    'ZCoxMDAwKSwKICAgICAgICAgICAgJ21icHNfbWlsbGknOnJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xMDAwKX0KCgpkZWYg'
    'dHJhbnNmZXJfdXBsb2FkKHNpemUpOgogICAgZGF0YT0oVEVTVF9CTE9DSyooKHNpemUrbGVuKFRFU1RfQkxPQ0spLTEpLy9s'
    'ZW4oVEVTVF9CTE9DSykpKVs6c2l6ZV0KICAgIHN0YXJ0PXRpbWUubW9ub3RvbmljKCkKICAgIHdpdGggdGVzdF9yZXF1ZXN0'
    'KCcvdXBsb2FkJyxkYXRhPWRhdGEsaGVhZGVycz17J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSd9'
    'KSBhcyByZXNwb25zZToKICAgICAgICByZXBseT1qc29uLmxvYWRzKHJlc3BvbnNlLnJlYWQoNDA5NikpCiAgICBlbGFwc2Vk'
    'PW1heCh0aW1lLm1vbm90b25pYygpLXN0YXJ0LDAuMDAxKQogICAgaW50ZWdyaXR5PXJlcGx5LmdldCgncmVjZWl2ZWRfYnl0'
    'ZXMnKT09c2l6ZSBhbmQgcmVwbHkuZ2V0KCdzaGEyNTYnKT09aGFzaGxpYi5zaGEyNTYoZGF0YSkuaGV4ZGlnZXN0KCkKICAg'
    'IHJldHVybiB7J2tpbmQnOid1cGxvYWQnLCdvayc6aW50ZWdyaXR5LCdpbnRlZ3JpdHknOmludGVncml0eSwnYnl0ZXMnOnNp'
    'emUsCiAgICAgICAgICAgICdlbGFwc2VkX21zJzpyb3VuZChlbGFwc2VkKjEwMDApLCdtYnBzX21pbGxpJzpyb3VuZChzaXpl'
    'KjgvZWxhcHNlZC8xMDAwKX0KCgpkZWYgcGluZ190ZXN0KHNpemU9NTYsIGNvdW50PTIwKToKICAgIGNwPWNtZChbJ3Bpbmcn'
    'LCctbicsJy1NJywnZG8nLCctcycsc3RyKHNpemUpLCctYycsc3RyKGNvdW50KSwnLWknLCcwLjInLCctVycsJzInLCcxMC43'
    'Ny4wLjEnXSxjaGVjaz1GYWxzZSx0aW1lb3V0PTQ1KQogICAgcGFja2V0cz1yZS5zZWFyY2gocicoXGQrKSBwYWNrZXRzIHRy'
    'YW5zbWl0dGVkLCAoXGQrKSByZWNlaXZlZCcsY3Auc3Rkb3V0KQogICAgc2VudCxyZWNlaXZlZD0oaW50KHgpIGZvciB4IGlu'
    'IHBhY2tldHMuZ3JvdXBzKCkpIGlmIHBhY2tldHMgZWxzZSAoY291bnQsMCkKICAgIHJvdz17J2tpbmQnOidwaW5nJywnb2sn'
    'OnJlY2VpdmVkPT1zZW50LCdzZW50JzpzZW50LCdyZWNlaXZlZCc6cmVjZWl2ZWQsCiAgICAgICAgICdsb3NzX21pbGxpJzpy'
    'b3VuZCgoc2VudC1yZWNlaXZlZCkqMTAwMDAwL21heChzZW50LDEpKSwnc2l6ZSc6c2l6ZX0KICAgIHJ0dD1yZS5zZWFyY2go'
    'cic9IChbXGQuXSspLyhbXGQuXSspLyhbXGQuXSspLyhbXGQuXSspIG1zJyxjcC5zdGRvdXQpCiAgICBpZiBydHQ6CiAgICAg'
    'ICAgcm93LnVwZGF0ZSh7a2V5OnJvdW5kKGZsb2F0KHZhbHVlKSoxMDAwKSBmb3Iga2V5LHZhbHVlIGluIHppcCgKICAgICAg'
    'ICAgICAgKCdydHRfbWluX3VzJywncnR0X2F2Z191cycsJ3J0dF9tYXhfdXMnLCdydHRfbWRldl91cycpLHJ0dC5ncm91cHMo'
    'KSl9KQogICAgcmV0dXJuIHJvdwoKCmRlZiB0cmFuc3BvcnRfY291bnRlcnMoKToKICAgIHJlc3VsdD17J2tpbmQnOidjb3Vu'
    'dGVycycsJ29rJzpUcnVlfQogICAgdHJ5OgogICAgICAgIHJhdz1zd2FuKCctLWxpc3Qtc2FzJywnLS1yYXcnKS5zdGRvdXQK'
    'ICAgICAgICBmb3Igc291cmNlLHRhcmdldCBpbiAoKCdieXRlcy1pbicsJ2J5dGVzX2luJyksKCdieXRlcy1vdXQnLCdieXRl'
    'c19vdXQnKSwoJ3BhY2tldHMtaW4nLCdwYWNrZXRzX2luJyksKCdwYWNrZXRzLW91dCcsJ3BhY2tldHNfb3V0JykpOgogICAg'
    'ICAgICAgICByZXN1bHRbdGFyZ2V0XT1zdW0oaW50KHgpIGZvciB4IGluIHJlLmZpbmRhbGwocidcYicrc291cmNlK3InPShc'
    'ZCspJyxyYXcpKQogICAgICAgIGxpbmVzPXBhdGhsaWIuUGF0aCgnL3Byb2MvbmV0L3NubXAnKS5yZWFkX3RleHQoKS5zcGxp'
    'dGxpbmVzKCkKICAgICAgICBmb3IgZmlyc3Qsc2Vjb25kIGluIHppcChsaW5lcyxsaW5lc1sxOl0pOgogICAgICAgICAgICBp'
    'ZiBmaXJzdC5zdGFydHN3aXRoKCdUY3A6JykgYW5kIHNlY29uZC5zdGFydHN3aXRoKCdUY3A6Jyk6CiAgICAgICAgICAgICAg'
    'ICB2YWx1ZXM9ZGljdCh6aXAoZmlyc3Quc3BsaXQoKVsxOl0sc2Vjb25kLnNwbGl0KClbMTpdKSkKICAgICAgICAgICAgICAg'
    'IGlmICdSZXRyYW5zU2VncycgaW4gdmFsdWVzOgogICAgICAgICAgICAgICAgICAgIHJlc3VsdFsncmV0cmFuc19zZWdtZW50'
    'cyddPWludCh2YWx1ZXNbJ1JldHJhbnNTZWdzJ10pCiAgICAgICAgICAgICAgICAgICAgcmVzdWx0WydvdXRfc2VnbWVudHMn'
    'XT1pbnQodmFsdWVzWydPdXRTZWdzJ10pCiAgICAgICAgaWYgYmFja2VuZCgpPT0na2VybmVsJzoKICAgICAgICAgICAgcmVz'
    'dWx0Wyd4ZnJtX2Vycm9ycyddPXN1bShpbnQoeC5zcGxpdCgpWzFdKSBmb3IgeCBpbiBwYXRobGliLlBhdGgoJy9wcm9jL25l'
    'dC94ZnJtX3N0YXQnKS5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixS'
    'dW50aW1lRXJyb3IpOiByZXN1bHRbJ29rJ109RmFsc2UKICAgIHJldHVybiByZXN1bHQKCgpkZWYgZmx1c2hfdGVzdF9yZXBv'
    'cnQoKToKICAgIGlmIG5vdCBzdG9yZWQoKS5nZXQoJ3RlbGVtZXRyeScpIG9yIG5vdCBQRU5ESU5HX1RFU1QuZXhpc3RzKCk6'
    'IHJldHVybiBGYWxzZQogICAgYm9keT1qc29uLmxvYWRzKFBFTkRJTkdfVEVTVC5yZWFkX3RleHQoKSkKICAgIGlmIG5vdCBk'
    'ZWxpdmVyX3JlcG9ydChib2R5KTogcmV0dXJuIEZhbHNlCiAgICBQRU5ESU5HX1RFU1QudW5saW5rKG1pc3Npbmdfb2s9VHJ1'
    'ZSkKICAgIHRlc3Rfc3RhdGUoc2VudD1UcnVlLG1lc3NhZ2U9J9Ci0LXRgdGCINC30LDQstC10YDRiNGR0L0uINCe0YLRh9GR'
    '0YIg0LTQvtGB0YLQsNCy0LvQtdC9INC90LAgU3RhckZpdmUuJykKICAgIHJldHVybiBUcnVlCgoKZGVmIHN0YXJ0X2dsb2Jh'
    'bF90ZXN0KCk6CiAgICBpZiBjbWQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLFRFU1RfVU5JVF0sY2hlY2s9RmFsc2UpLnJl'
    'dHVybmNvZGU9PTA6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQk9C70L7QsdCw0LvRjNC90YvQuSDRgtC10YHRgiDR'
    'g9C20LUg0LLRi9C/0L7Qu9C90Y/QtdGC0YHRjy4nKQogICAgaWYgbm90IHN0b3JlZCgpLmdldCgndGVsZW1ldHJ5Jyk6IHJh'
    'aXNlIFJ1bnRpbWVFcnJvcign0JLQutC70Y7Rh9C4INCy0YDQtdC80LXQvdC90YPRjiDQtNC40LDQs9C90L7RgdGC0LjQutGD'
    'INC00LvRjyDQvtGC0L/RgNCw0LLQutC4INGA0LXQt9GD0LvRjNGC0LDRgtC+0LIuJykKICAgIGlmIG5vdCBjb25uZWN0ZWQo'
    'KSBvciBub3QgYWN0aXZlX2d1YXJkKCk6IHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00LrQu9GO'
    '0YfQuNGB0Ywg0LogU3RhckZpdmUuJykKICAgIGlmIGVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCd0ZXN0X2FwaScpIT0xOiBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0LHQvdC+0LLQuNGC0Ywg0YLQtdGB0YLQvtCy0YvQuSDRgdC1'
    '0YDQstC40YEgU3RhckZpdmUuJykKICAgIGlmIFBFTkRJTkdfVEVTVC5leGlzdHMoKSBhbmQgbm90IGZsdXNoX3Rlc3RfcmVw'
    'b3J0KCk6IHJhaXNlIFJ1bnRpbWVFcnJvcign0J7QttC40LTQsNC10YIg0L7RgtC/0YDQsNCy0LrQuCDQv9GA0LXQtNGL0LTR'
    'g9GJ0LjQuSDQvtGC0YfRkdGCLicpCiAgICB1bml0PScnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBnbG9iYWwgVlBO'
    'IHN0YWJpbGl0eSB0ZXN0CkFmdGVyPWV2Z2VuaXVtLWlrZXYyLnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9ZXhlYwpFeGVjU3Rh'
    'cnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS1nbG9iYWwtdGVzdApTdGFuZGFyZE91dHB1dD1u'
    'dWxsClN0YW5kYXJkRXJyb3I9bnVsbApUaW1lb3V0U3RvcFNlYz0xMgpSdW50aW1lTWF4U2VjPTkwMApSZXN0YXJ0PW5vCicn'
    'JwogICAgd3JpdGUocGF0aGxpYi5QYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtJykvVEVTVF9VTklULHVuaXQsMG82NDQpCiAg'
    'ICBjbWQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICB0ZXN0X3N0YXRlKHBoYXNlPSdydW5uaW5nJyxwcm9n'
    'cmVzcz0wLHNlbnQ9RmFsc2UscGFzc2VkPTAsZmFpbGVkPTAsZHVyYXRpb25fcz0wLG1lc3NhZ2U9J9CX0LDQv9GD0YHQuiDR'
    'gtC10YHRgtCwJyxydW49b3MudXJhbmRvbSgxMikuaGV4KCksc3RhcnRlZD1pbnQodGltZS50aW1lKCkpKQogICAgdHJ5OiBj'
    'bWQoWydzeXN0ZW1jdGwnLCdzdGFydCcsVEVTVF9VTklUXSkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgdGVzdF9z'
    'dGF0ZShwaGFzZT0nZmFpbGVkJyxtZXNzYWdlPSfQndC1INGD0LTQsNC70L7RgdGMINC30LDQv9GD0YHRgtC40YLRjCDRgtC1'
    '0YHRgi4nKTsgcmFpc2UKICAgIHByaW50KCfQk9C70L7QsdCw0LvRjNC90YvQuSDRgtC10YHRgiDQt9Cw0L/Rg9GJ0LXQvSDQ'
    'siDRhNC+0L3QtS4g0JjQvdGC0LXRgNC90LXRgiDQvdC10YHQutC+0LvRjNC60L4g0YDQsNC3INC/0YDQtdGA0LLRkdGC0YHR'
    'jzsga2lsbCBzd2l0Y2gg0L7RgdGC0LDRkdGC0YHRjyDQstC60LvRjtGH0ZHQvdC90YvQvC4nKQoKCmNsYXNzIFRlc3RDYW5j'
    'ZWxsZWQoRXhjZXB0aW9uKTogcGFzcwoKCmRlZiBydW5fZ2xvYmFsX3Rlc3QoKToKICAgIGltcG9ydCBzaWduYWwKICAgIGZy'
    'b20gY29uY3VycmVudC5mdXR1cmVzIGltcG9ydCBUaHJlYWRQb29sRXhlY3V0b3IKICAgIGRlZiBjYW5jZWwoKl8pOiByYWlz'
    'ZSBUZXN0Q2FuY2VsbGVkKCkKICAgIG9sZD1zaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLGNhbmNlbCkKICAgIHJlY29y'
    'ZHM9W107IG91dGNvbWU9J2NvbXBsZXRlZCc7IHN0YXJ0ZWQ9dGltZS5tb25vdG9uaWMoKQogICAgZGVmIHN0YWdlKHByb2dy'
    'ZXNzLG1lc3NhZ2UpOiB0ZXN0X3N0YXRlKHBoYXNlPSdydW5uaW5nJyxwcm9ncmVzcz1wcm9ncmVzcyxtZXNzYWdlPW1lc3Nh'
    'Z2UpCiAgICBkZWYgbWVhc3VyZShraW5kLG9wZXJhdGlvbiwqKmZpZWxkcyk6CiAgICAgICAgYmVmb3JlPXRpbWUubW9ub3Rv'
    'bmljKCkKICAgICAgICB0cnk6IHJvdz1vcGVyYXRpb24oKQogICAgICAgIGV4Y2VwdCBUZXN0Q2FuY2VsbGVkOiByYWlzZQog'
    'ICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICBlcnJvcj0nb3RoZXInCiAgICAgICAgICAgIGlm'
    'IGlzaW5zdGFuY2UoZXhjLHVybGxpYi5lcnJvci5IVFRQRXJyb3IpOiBlcnJvcj0naHR0cCcKICAgICAgICAgICAgZWxpZiBp'
    'c2luc3RhbmNlKGV4YywoVGltZW91dEVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpKTogZXJyb3I9J3RpbWVvdXQn'
    'CiAgICAgICAgICAgIGVsaWYgaXNpbnN0YW5jZShleGMsc3NsLlNTTEVycm9yKTogZXJyb3I9J3RscycKICAgICAgICAgICAg'
    'ZWxpZiBpc2luc3RhbmNlKGV4YyxPU0Vycm9yKTogZXJyb3I9J25ldHdvcmsnCiAgICAgICAgICAgIHJvdz17J2tpbmQnOmtp'
    'bmQsJ29rJzpGYWxzZSwnZXJyb3InOmVycm9yfQogICAgICAgICAgICBpZiBpc2luc3RhbmNlKGV4Yyx1cmxsaWIuZXJyb3Iu'
    'SFRUUEVycm9yKTogcm93WydodHRwX3N0YXR1cyddPWV4Yy5jb2RlCiAgICAgICAgcm93LnNldGRlZmF1bHQoJ2VsYXBzZWRf'
    'bXMnLHJvdW5kKCh0aW1lLm1vbm90b25pYygpLWJlZm9yZSkqMTAwMCkpCiAgICAgICAgcm93WydhdF9tcyddPXJvdW5kKCh0'
    'aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpKjEwMDApCiAgICAgICAgcm93LnVwZGF0ZShmaWVsZHMpOyByZWNvcmRzLmFwcGVu'
    'ZChyb3cpOyByZXR1cm4gcm93CiAgICBkZWYgcmVjb25uZWN0KHJlc3RhcnQ9RmFsc2UpOgogICAgICAgIGJlZm9yZT10aW1l'
    'Lm1vbm90b25pYygpCiAgICAgICAgaWYgcmVzdGFydDoKICAgICAgICAgICAgY2FuZGlkYXRlcz1zb2NrZXQuZ2V0YWRkcmlu'
    'Zm8oJ3lhbmRleC5ydScsNDQzLHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKICAgICAgICAgICAgYWRkcmVz'
    'cz1uZXh0KHhbNF1bMF0gZm9yIHggaW4gY2FuZGlkYXRlcyBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyh4WzRdWzBdKS5pc19n'
    'bG9iYWwpCiAgICAgICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLFVOSVRdKQogICAgICAgICAgICBsZWFrZWQ9RmFs'
    'c2UKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd2l0aCBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGFkZHJl'
    'c3MsNDQzKSx0aW1lb3V0PTIpOiBsZWFrZWQ9VHJ1ZQogICAgICAgICAgICBleGNlcHQgT1NFcnJvcjogcGFzcwogICAgICAg'
    'ICAgICByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidndWFyZCcsJ29rJzphY3RpdmVfZ3VhcmQoKSBhbmQgbm90IGxlYWtlZH0p'
    'CiAgICAgICAgICAgICMgTmV2ZXIgcmVtb3ZlIHRoZSBndWFyZCwgZXZlbiBkdXJpbmcgYSBkZWxpYmVyYXRlIGRhZW1vbiBm'
    'YWlsdXJlLgogICAgICAgICAgICBpZiBub3QgYWN0aXZlX2d1YXJkKCk6IHJhaXNlIFJ1bnRpbWVFcnJvcignR3VhcmQgbWlz'
    'c2luZycpCiAgICAgICAgICAgIGNtZChbJ3N5c3RlbWN0bCcsJ3N0YXJ0JyxVTklUXSkKICAgICAgICAgICAgd2FpdF91c2Vy'
    'c3BhY2UoKQogICAgICAgICAgICBzd2FuKCctLWxvYWQtY3JlZHMnLCctLWZpbGUnLFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicp'
    'CiAgICAgICAgICAgIHN3YW4oJy0tbG9hZC1jb25ucycsJy0tZmlsZScsUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAg'
    'ICBlbHNlOgogICAgICAgICAgICBzd2FuKCctLXRlcm1pbmF0ZScsJy0taWtlJywnc3RhcmZpdmUnLGNoZWNrPUZhbHNlKQog'
    'ICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCctLWNoaWxkJywnc3RhcmZpdmUtbmV0Jyx0aW1lb3V0PTU1KQogICAgICAgIGdv'
    'b2Q9Y29ubmVjdGVkKCkgYW5kIGVuZHBvaW50KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFyZml2'
    'ZScKICAgICAgICByZXR1cm4geydraW5kJzonZGFlbW9uX3Jlc3RhcnQnIGlmIHJlc3RhcnQgZWxzZSAncmVjb25uZWN0Jywn'
    'b2snOmdvb2QsJ2VsYXBzZWRfbXMnOnJvdW5kKCh0aW1lLm1vbm90b25pYygpLWJlZm9yZSkqMTAwMCl9CiAgICBkZWYgY29u'
    'dHJvbCgpOgogICAgICAgIHdpdGggdGVzdF9yZXF1ZXN0KCcvY29udHJvbCcsdGltZW91dD00NSkgYXMgcmVzcG9uc2U6IGRh'
    'dGE9anNvbi5sb2FkcyhyZXNwb25zZS5yZWFkKDE2Mzg0KSkKICAgICAgICByZWNvcmRzLmFwcGVuZCh7J2tpbmQnOidzZXJ2'
    'ZXJfY29udHJvbCcsJ29rJzpUcnVlLCoqZGF0YVsnbWV0cmljcyddfSkKICAgICAgICBmb3IgcHJvYmUgaW4gZGF0YVsncHJv'
    'YmVzJ106IHJlY29yZHMuYXBwZW5kKHsna2luZCc6J3NlcnZlcl9jb250cm9sJywqKnByb2JlfSkKICAgICAgICByZXR1cm4g'
    'eydraW5kJzonaGVhbHRoJywnb2snOlRydWV9CiAgICB0cnk6CiAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RvcCcsTU9O'
    'SVRPUl0sY2hlY2s9RmFsc2UpCiAgICAgICAgIyBVc2UgUnVzc2lhbiBETlMgZm9yIHRoaXMgdGVzdCBldmVuIG9uIGEgc2Vz'
    'c2lvbiBjcmVhdGVkIGJ5IGFuIG9sZGVyIGNsaWVudC4KICAgICAgICBpZiBub3QgKFJPT1QvJ3Jlc29sdi1iYWNrdXAnKS5l'
    'eGlzdHMoKSBhbmQgbm90IChST09ULydyZXNvbHZlZC1iYWNrdXAuanNvbicpLmV4aXN0cygpOiBzZXRfZG5zKCkKICAgICAg'
    'ICBlbGlmIChST09ULydyZXNvbHZlZC1iYWNrdXAuanNvbicpLmV4aXN0cygpOgogICAgICAgICAgICBpbnRlcmZhY2U9anNv'
    'bi5sb2FkcygoUk9PVC8ncmVzb2x2ZWQtYmFja3VwLmpzb24nKS5yZWFkX3RleHQoKSlbJ2lmYWNlJ10KICAgICAgICAgICAg'
    'Y21kKFsncmVzb2x2ZWN0bCcsJ2RucycsaW50ZXJmYWNlLCc3Ny44OC44LjgnLCc3Ny44OC44LjEnXSkKICAgICAgICBlbHNl'
    'OgogICAgICAgICAgICBwYXRobGliLlBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKS53cml0ZV90ZXh0KCduYW1lc2VydmVyIDc3'
    'Ljg4LjguOFxubmFtZXNlcnZlciA3Ny44OC44LjFcbm9wdGlvbnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICAgICAg'
    'c3RhZ2UoMywn0JrQvtC90YLRgNC+0LvRjNC90YvQtSDQt9Cw0LzQtdGA0YsgU3RhckZpdmUg0Lgg0YDQvtGB0YHQuNC50YHQ'
    'utC40YUg0YHQtdGA0LLQuNGB0L7QsicpCiAgICAgICAgbWVhc3VyZSgnaGVhbHRoJyxjb250cm9sKTsgcmVjb3Jkcy5hcHBl'
    'bmQodHJhbnNwb3J0X2NvdW50ZXJzKCkpCiAgICAgICAgZm9yIGRvbWFpbiBpbiBSVV9ET01BSU5TOiBtZWFzdXJlKCdydV9w'
    'cm9iZScsbGFtYmRhIGQ9ZG9tYWluOnsna2luZCc6J3J1X3Byb2JlJywqKnByb2JlX2RvbWFpbihkKX0pCiAgICAgICAgc3Rh'
    'Z2UoMTIsJ9CX0LDQtNC10YDQttC60LgsINC/0L7RgtC10YDQuCDQuCDRgNCw0LfQvNC10YDRiyDQv9Cw0LrQtdGC0L7Qsicp'
    'CiAgICAgICAgZm9yIHNpemUgaW4gKDU2LDEyMDAsMTM2MCk6IG1lYXN1cmUoJ3BpbmcnLGxhbWJkYSBzPXNpemU6cGluZ190'
    'ZXN0KHMpKQogICAgICAgIGZvciBhdHRlbXB0IGluIHJhbmdlKDEyKToKICAgICAgICAgICAgYmVmb3JlPXRpbWUubW9ub3Rv'
    'bmljKCkKICAgICAgICAgICAgbWVhc3VyZSgnaGVhbHRoJyxsYW1iZGE6eydraW5kJzonaGVhbHRoJywnb2snOmVuZHBvaW50'
    'KCcvaGVhbHRoJykuZ2V0KCdzZXJ2aWNlJyk9PSdldmdlbml1bS1zdGFyZml2ZSd9KQogICAgICAgICAgICB0aW1lLnNsZWVw'
    'KDAuMjUpCiAgICAgICAgc3RhZ2UoMjUsJ9Ch0LrQsNGH0LjQstCw0L3QuNC1INC4INC+0YLQv9GA0LDQstC60LAg0YTQsNC5'
    '0LvQvtCyOiDQv9GA0L7QstC10YDQutCwIFNIQS0yNTYnKQogICAgICAgIGZvciBzaXplIGluICg2NTUzNiwxMDQ4NTc2LDgz'
    'ODg2MDgsMzM1NTQ0MzIpOiBtZWFzdXJlKCdkb3dubG9hZCcsbGFtYmRhIHM9c2l6ZTp0cmFuc2Zlcl9kb3dubG9hZChzKSkK'
    'ICAgICAgICBmb3Igc2l6ZSBpbiAoNTI0Mjg4LDQxOTQzMDQpOiBtZWFzdXJlKCd1cGxvYWQnLGxhbWJkYSBzPXNpemU6dHJh'
    'bnNmZXJfdXBsb2FkKHMpKQogICAgICAgIHN0YWdlKDQwLCfQlNC+0LrQsNGH0LrQsCDRhNCw0LnQu9CwINC/0L7RgdC70LUg'
    '0YDQsNC30YDRi9Cy0LAg0Lgg0L/QtdGA0LXQv9C+0LTQutC70Y7Rh9C10L3QuNGPJykKICAgICAgICBtZWFzdXJlKCdyZXN1'
    'bWUnLGxhbWJkYTp7Kip0cmFuc2Zlcl9kb3dubG9hZCg4Mzg4NjA4LGxpbWl0PTMxNDU3MjgpLCdraW5kJzoncmVzdW1lJ30p'
    'CiAgICAgICAgbWVhc3VyZSgncmVjb25uZWN0JyxyZWNvbm5lY3QpCiAgICAgICAgbWVhc3VyZSgncmVzdW1lJyxsYW1iZGE6'
    'eyoqdHJhbnNmZXJfZG93bmxvYWQoODM4ODYwOCxvZmZzZXQ9MzE0NTcyOCksJ2tpbmQnOidyZXN1bWUnfSkKICAgICAgICBz'
    'dGFnZSg1MCwn0J/QsNGA0LDQu9C70LXQu9GM0L3QsNGPINC/0LXRgNC10LTQsNGH0LAg0LIg0L7QsdC1INGB0YLQvtGA0L7Q'
    'vdGLJykKICAgICAgICB3aXRoIFRocmVhZFBvb2xFeGVjdXRvcihtYXhfd29ya2Vycz0zKSBhcyBwb29sOgogICAgICAgICAg'
    'ICBmdXR1cmVzPVtwb29sLnN1Ym1pdCh0cmFuc2Zlcl9kb3dubG9hZCw4Mzg4NjA4KSxwb29sLnN1Ym1pdCh0cmFuc2Zlcl9k'
    'b3dubG9hZCw4Mzg4NjA4KSxwb29sLnN1Ym1pdCh0cmFuc2Zlcl91cGxvYWQsNDE5NDMwNCldCiAgICAgICAgICAgIGZvciBm'
    'dXR1cmUgaW4gZnV0dXJlczogbWVhc3VyZSgncGFyYWxsZWwnLGxhbWJkYSBmPWZ1dHVyZTp7KipmLnJlc3VsdCgpLCdraW5k'
    'JzoncGFyYWxsZWwnfSkKICAgICAgICBzdGFnZSg2Miwn0JTQu9C40YLQtdC70YzQvdCw0Y8g0L/QtdGA0LXQtNCw0YfQsDog'
    '0LTQviA2MCDRgdC10LrRg9C90LQgLyA2NCDQnNC40JEnKQogICAgICAgIGxvYWRfc3RhcnRlZD10aW1lLm1vbm90b25pYygp'
    'OyB1bnRpbD1sb2FkX3N0YXJ0ZWQrNjA7IGNvdW50PTAKICAgICAgICB3aGlsZSB0aW1lLm1vbm90b25pYygpPHVudGlsIGFu'
    'ZCBjb3VudDwxNjoKICAgICAgICAgICAgbWVhc3VyZSgnZG93bmxvYWQnLGxhbWJkYTp0cmFuc2Zlcl9kb3dubG9hZCg0MTk0'
    'MzA0KSk7IGNvdW50Kz0xCiAgICAgICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsbGFtYmRhOnsna2luZCc6J2hlYWx0aCcsJ29r'
    'JzplbmRwb2ludCgnL2hlYWx0aCcpLmdldCgnc2VydmljZScpPT0nZXZnZW5pdW0tc3RhcmZpdmUnfSkKICAgICAgICAgICAg'
    'dGltZS5zbGVlcChtYXgoMCxsb2FkX3N0YXJ0ZWQrY291bnQqNC10aW1lLm1vbm90b25pYygpKSkKICAgICAgICBzdGFnZSg3'
    'NSwn0J/RgNC+0YHRgtC+0LkgNDUg0YHQtdC60YPQvdC0INC4INCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40LUg0LDQutGC'
    '0LjQstC90L7RgdGC0LgnKQogICAgICAgIHRpbWUuc2xlZXAoNDUpCiAgICAgICAgbWVhc3VyZSgnaWRsZScsbGFtYmRhOnsn'
    'a2luZCc6J2lkbGUnLCdvayc6ZW5kcG9pbnQoJy9oZWFsdGgnKS5nZXQoJ3NlcnZpY2UnKT09J2V2Z2VuaXVtLXN0YXJmaXZl'
    'JywnZWxhcHNlZF9tcyc6NDUwMDB9KQogICAgICAgIHN0YWdlKDgyLCfQn9GP0YLRjCDQv9C+0LLRgtC+0YDQvdGL0YUg0L/Q'
    'vtC00LrQu9GO0YfQtdC90LjQuScpCiAgICAgICAgZm9yIGF0dGVtcHQgaW4gcmFuZ2UoNSk6CiAgICAgICAgICAgIG1lYXN1'
    'cmUoJ3JlY29ubmVjdCcscmVjb25uZWN0LGF0dGVtcHQ9YXR0ZW1wdCsxKTsgdGltZS5zbGVlcCgxKQogICAgICAgIHN0YWdl'
    'KDkyLCfQn9C10YDQtdC30LDQv9GD0YHQuiBWUE4t0LTQtdC80L7QvdCwINGBINGB0L7RhdGA0LDQvdC10L3QuNC10Lwga2ls'
    'bCBzd2l0Y2gnKQogICAgICAgIG1lYXN1cmUoJ2RhZW1vbl9yZXN0YXJ0JyxsYW1iZGE6cmVjb25uZWN0KFRydWUpKQogICAg'
    'ICAgIHJlY29yZHMuYXBwZW5kKHsna2luZCc6J2d1YXJkJywnb2snOmFjdGl2ZV9ndWFyZCgpfSkKICAgICAgICBzdGFnZSg5'
    'Niwn0JfQsNC60LvRjtGH0LjRgtC10LvRjNC90YvQtSDQt9Cw0LzQtdGA0Ysg0Lgg0L7RgtC/0YDQsNCy0LrQsCDQvtGC0YfR'
    'kdGC0LAnKQogICAgICAgIGZvciBkb21haW4gaW4gUlVfRE9NQUlOUzogbWVhc3VyZSgncnVfcHJvYmUnLGxhbWJkYSBkPWRv'
    'bWFpbjp7J2tpbmQnOidydV9wcm9iZScsKipwcm9iZV9kb21haW4oZCl9KQogICAgICAgIG1lYXN1cmUoJ2hlYWx0aCcsY29u'
    'dHJvbCk7IHJlY29yZHMuYXBwZW5kKHRyYW5zcG9ydF9jb3VudGVycygpKQogICAgICAgIGlmIGFueShub3QgeC5nZXQoJ29r'
    'JykgZm9yIHggaW4gcmVjb3Jkcyk6IG91dGNvbWU9J2ZhaWxlZCcKICAgIGV4Y2VwdCBUZXN0Q2FuY2VsbGVkOiBvdXRjb21l'
    'PSdjYW5jZWxsZWQnCiAgICBleGNlcHQgRXhjZXB0aW9uOiBvdXRjb21lPSdmYWlsZWQnCiAgICBmaW5hbGx5OgogICAgICAg'
    'ICMgUmVjb3ZlciBvbmx5IG91ciBkYWVtb24vc2Vzc2lvbi4gTmV2ZXIgZGlzYWJsZSB0aGUgZ3VhcmQgb3IgcmVzdG9yZSBk'
    'aXJlY3QgdHJhZmZpYy4KICAgICAgICBpZiBvdXRjb21lIT0nY2FuY2VsbGVkJyBhbmQgbm90IGNvbm5lY3RlZCgpOgogICAg'
    'ICAgICAgICB0cnk6IG1lYXN1cmUoJ2RhZW1vbl9yZXN0YXJ0JyxsYW1iZGE6cmVjb25uZWN0KFRydWUpKQogICAgICAgICAg'
    'ICBleGNlcHQgRXhjZXB0aW9uOiBwYXNzCiAgICAgICAgYm9keT17J3NjaGVtYSc6MSwnZXZlbnQnOidnbG9iYWxfdGVzdCcs'
    'J21hbmFnZXInOicwLjIuMjMnLCdydW4nOnRlc3Rfc3RhdHVzKCkuZ2V0KCdydW4nLG9zLnVyYW5kb20oMTIpLmhleCgpKSwn'
    'b3V0Y29tZSc6b3V0Y29tZSwnZHVyYXRpb25fbXMnOnJvdW5kKCh0aW1lLm1vbm90b25pYygpLXN0YXJ0ZWQpKjEwMDApLCdy'
    'ZWNvcmRzJzpyZWNvcmRzWzoyNTZdfQogICAgICAgIHdyaXRlKFBFTkRJTkdfVEVTVCxqc29uLmR1bXBzKGJvZHkpKQogICAg'
    'ICAgIHRlc3Rfc3RhdGUocGhhc2U9b3V0Y29tZSxwcm9ncmVzcz0xMDAsc2VudD1GYWxzZSxkdXJhdGlvbl9zPXJvdW5kKHRp'
    'bWUubW9ub3RvbmljKCktc3RhcnRlZCksCiAgICAgICAgICAgICAgICAgICBwYXNzZWQ9c3VtKGJvb2woeC5nZXQoJ29rJykp'
    'IGZvciB4IGluIHJlY29yZHMpLGZhaWxlZD1zdW0obm90IHguZ2V0KCdvaycpIGZvciB4IGluIHJlY29yZHMpLAogICAgICAg'
    'ICAgICAgICAgICAgbWVzc2FnZT0n0J7RgtGH0ZHRgiDRgdC+0YXRgNCw0L3RkdC9LiDQntC20LjQtNCw0LXRgiDQvtGC0L/R'
    'gNCw0LLQutC4INGH0LXRgNC10LcgU3RhckZpdmUuJykKICAgICAgICB0cnk6IGZsdXNoX3Rlc3RfcmVwb3J0KCkKICAgICAg'
    'ICBleGNlcHQgRXhjZXB0aW9uOiBraWNrX2RlbGl2ZXJ5KCkKICAgICAgICBpZiBjb25uZWN0ZWQoKSBhbmQgc3RvcmVkKCku'
    'Z2V0KCd0ZWxlbWV0cnknKToKICAgICAgICAgICAgY21kKFsnc3lzdGVtY3RsJywnc3RhcnQnLE1PTklUT1JdLGNoZWNrPUZh'
    'bHNlKQogICAgICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sb2xkKQo='
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
        migrate_firefox_codex_exceptions(settings)
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
