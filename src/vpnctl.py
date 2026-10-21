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

MANAGER_VERSION = "0.4.3"

SAFE_XRAY_VERSION = "26.7.28"

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")

STATE = pathlib.Path("/var/lib/vpn-manager/state.json")

RUNTIME_DIR = pathlib.Path("/run/vpn-manager")

RUNTIME_CONFIG = RUNTIME_DIR / "policy.json"

XRAY = pathlib.Path("/opt/vpn-manager/bin/xray")

XRAY_PREVIOUS = pathlib.Path("/opt/vpn-manager/bin/xray.previous")

SERVICE = "evgenium-policy.service"

PLASMOID_ID = "com.evgenium.network"

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
    'CmltcG9ydCBmY250bAppbXBvcnQgaHR0cC5zZXJ2ZXIKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmltcG9ydCBwYXRobGliCmlt'
    'cG9ydCBzZWNyZXRzCmltcG9ydCBzaHV0aWwKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHN5cwppbXBvcnQgdGhyZWFkaW5n'
    'CmltcG9ydCB0aW1lCmltcG9ydCB1cmxsaWIucGFyc2UKCkFQUF9OQU1FID0gIkV2Z2VuaXVtIE5ldHdvcmsiClZQTiA9ICIv'
    'dXNyL2xvY2FsL2Jpbi92cG4iCkhFUkUgPSBwYXRobGliLlBhdGgoX19maWxlX18pLnJlc29sdmUoKS5wYXJlbnQKUU1MX0ZJ'
    'TEUgPSBIRVJFIC8gImV2Z2VuaXVtX2d1aS5xbWwiCldJREdFVF9GSUxFID0gSEVSRSAvICJldmdlbml1bV93aWRnZXQucW1s'
    'IgpNQVhfQk9EWSA9IDY0ICogMTAyNAoKCmRlZiBmaW5kX3FtbF9ydW50aW1lKCkgLT4gc3RyIHwgTm9uZToKICAgIGZvciBj'
    'YW5kaWRhdGUgaW4gKAogICAgICAgICIvdXNyL2Jpbi9xbWw2IiwKICAgICAgICAiL3Vzci9iaW4vcW1sLXF0NiIsCiAgICAg'
    'ICAgIi91c3IvbGliL3F0Ni9iaW4vcW1sIiwKICAgICAgICAiL3Vzci9saWI2NC9xdDYvYmluL3FtbCIsCiAgICAgICAgIi91'
    'c3IvYmluL3FtbCIsCiAgICApOgogICAgICAgIGlmIHBhdGhsaWIuUGF0aChjYW5kaWRhdGUpLmlzX2ZpbGUoKSBhbmQgb3Mu'
    'YWNjZXNzKGNhbmRpZGF0ZSwgb3MuWF9PSyk6CiAgICAgICAgICAgIHJldHVybiBjYW5kaWRhdGUKICAgIHJldHVybiBzaHV0'
    'aWwud2hpY2goInFtbDYiKSBvciBzaHV0aWwud2hpY2goInFtbC1xdDYiKSBvciBzaHV0aWwud2hpY2goInFtbCIpCgoKZGVm'
    'IHJ1bl92cG4oYXJnczogbGlzdFtzdHJdLCB0aW1lb3V0OiBpbnQgPSA3NTAsIHNlY3JldF9pbnB1dDogc3RyIHwgTm9uZSA9'
    'IE5vbmUpIC0+IHN0cjoKICAgIHN0ZGluX29wdGlvbnMgPSB7ImlucHV0Ijogc2VjcmV0X2lucHV0fSBpZiBzZWNyZXRfaW5w'
    'dXQgaXMgbm90IE5vbmUgZWxzZSB7InN0ZGluIjogc3VicHJvY2Vzcy5ERVZOVUxMfQogICAgY3AgPSBzdWJwcm9jZXNzLnJ1'
    'bigKICAgICAgICBbVlBOLCAqYXJnc10sCiAgICAgICAgdGV4dD1UcnVlLAogICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJ'
    'UEUsCiAgICAgICAgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSwKICAgICAgICB0aW1lb3V0PXRpbWVvdXQsCiAgICAgICAgKipz'
    'dGRpbl9vcHRpb25zLAogICAgICAgIGNoZWNrPUZhbHNlLAogICAgKQogICAgaWYgY3AucmV0dXJuY29kZSAhPSAwOgogICAg'
    'ICAgIGRldGFpbCA9IChjcC5zdGRlcnIgb3IgY3Auc3Rkb3V0IG9yIGYiZXhpdCB7Y3AucmV0dXJuY29kZX0iKS5zdHJpcCgp'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGRldGFpbCkKICAgIHJldHVybiAoY3Auc3Rkb3V0IG9yICIiKS5zdHJpcCgp'
    'CgoKZGVmIHJ1bl92cG5fanNvbihhcmdzOiBsaXN0W3N0cl0pIC0+IGRpY3Q6CiAgICByYXcgPSBydW5fdnBuKGFyZ3MsIHRp'
    'bWVvdXQ9MTApCiAgICB0cnk6CiAgICAgICAgZGF0YSA9IGpzb24ubG9hZHMocmF3KQogICAgZXhjZXB0IGpzb24uSlNPTkRl'
    'Y29kZUVycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoZiJWUE4gTWFuYWdlciDQstC10YDQvdGD0Lsg'
    '0L3QtdC60L7RgNGA0LXQutGC0L3Ri9C5IEpTT046IHtleGN9IikgZnJvbSBleGMKICAgIGlmIG5vdCBpc2luc3RhbmNlKGRh'
    'dGEsIGRpY3QpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigiVlBOIE1hbmFnZXIg0LLQtdGA0L3Rg9C7INC90LXQvtC2'
    '0LjQtNCw0L3QvdGL0Lkg0L7RgtCy0LXRgi4iKQogICAgcmV0dXJuIGRhdGEKCgpkZWYgZW5jb2RlX3VpX3BheWxvYWQocGF5'
    'bG9hZDogZGljdCkgLT4gc3RyOgogICAgcmF3ID0ganNvbi5kdW1wcyhwYXlsb2FkLCBlbnN1cmVfYXNjaWk9RmFsc2UsIHNl'
    'cGFyYXRvcnM9KCIsIiwgIjoiKSkKICAgIHF1b3RlZCA9IHVybGxpYi5wYXJzZS5xdW90ZShyYXcsIHNhZmU9IiIpCiAgICBy'
    'ZXR1cm4gYmFzZTY0LmI2NGVuY29kZShxdW90ZWQuZW5jb2RlKCJhc2NpaSIpKS5kZWNvZGUoImFzY2lpIikKCgpjbGFzcyBB'
    'cGlTZXJ2ZXIoaHR0cC5zZXJ2ZXIuVGhyZWFkaW5nSFRUUFNlcnZlcik6CiAgICBkYWVtb25fdGhyZWFkcyA9IFRydWUKICAg'
    'IGFsbG93X3JldXNlX2FkZHJlc3MgPSBGYWxzZQoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBhZGRyZXNzLCBoYW5kbGVyLCB0'
    'b2tlbjogc3RyKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKGFkZHJlc3MsIGhhbmRsZXIpCiAgICAgICAgc2VsZi50b2tl'
    'biA9IHRva2VuCgoKY2xhc3MgSGFuZGxlcihodHRwLnNlcnZlci5CYXNlSFRUUFJlcXVlc3RIYW5kbGVyKToKICAgIHNlcnZl'
    'cjogQXBpU2VydmVyCgogICAgZGVmIGxvZ19tZXNzYWdlKHNlbGYsIF9mb3JtYXQ6IHN0ciwgKl9hcmdzKSAtPiBOb25lOgog'
    'ICAgICAgIHJldHVybgoKICAgIGRlZiBfaGVhZGVycyhzZWxmLCBzdGF0dXM6IGludCA9IDIwMCwgY29udGVudF90eXBlOiBz'
    'dHIgPSAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCIpIC0+IE5vbmU6CiAgICAgICAgc2VsZi5zZW5kX3Jlc3Bv'
    'bnNlKHN0YXR1cykKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LVR5cGUiLCBjb250ZW50X3R5cGUpCiAgICAg'
    'ICAgc2VsZi5zZW5kX2hlYWRlcigiQ2FjaGUtQ29udHJvbCIsICJuby1zdG9yZSIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRl'
    'cigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luIiwgIioiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vzcy1D'
    'b250cm9sLUFsbG93LUhlYWRlcnMiLCAiQ29udGVudC1UeXBlLCBYLUV2Z2VuaXVtLVRva2VuIikKICAgICAgICBzZWxmLnNl'
    'bmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzIiwgIkdFVCwgUE9TVCwgT1BUSU9OUyIpCiAgICAgICAg'
    'c2VsZi5lbmRfaGVhZGVycygpCgogICAgZGVmIF9qc29uKHNlbGYsIHBheWxvYWQ6IGRpY3QsIHN0YXR1czogaW50ID0gMjAw'
    'KSAtPiBOb25lOgogICAgICAgIGRhdGEgPSBqc29uLmR1bXBzKHBheWxvYWQsIGVuc3VyZV9hc2NpaT1GYWxzZSwgc2VwYXJh'
    'dG9ycz0oIiwiLCAiOiIpKS5lbmNvZGUoInV0Zi04IikKICAgICAgICBzZWxmLnNlbmRfcmVzcG9uc2Uoc3RhdHVzKQogICAg'
    'ICAgIHNlbGYuc2VuZF9oZWFkZXIoIkNvbnRlbnQtVHlwZSIsICJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PXV0Zi04IikK'
    'ICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJDb250ZW50LUxlbmd0aCIsIHN0cihsZW4oZGF0YSkpKQogICAgICAgIHNlbGYu'
    'c2VuZF9oZWFkZXIoIkNhY2hlLUNvbnRyb2wiLCAibm8tc3RvcmUiKQogICAgICAgIHNlbGYuc2VuZF9oZWFkZXIoIkFjY2Vz'
    'cy1Db250cm9sLUFsbG93LU9yaWdpbiIsICIqIikKICAgICAgICBzZWxmLnNlbmRfaGVhZGVyKCJBY2Nlc3MtQ29udHJvbC1B'
    'bGxvdy1IZWFkZXJzIiwgIkNvbnRlbnQtVHlwZSwgWC1Fdmdlbml1bS1Ub2tlbiIpCiAgICAgICAgc2VsZi5zZW5kX2hlYWRl'
    'cigiQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcyIsICJHRVQsIFBPU1QsIE9QVElPTlMiKQogICAgICAgIHRyeToKICAg'
    'ICAgICAgICAgc2VsZi5lbmRfaGVhZGVycygpCiAgICAgICAgICAgIHNlbGYud2ZpbGUud3JpdGUoZGF0YSkKICAgICAgICBl'
    'eGNlcHQgKEJyb2tlblBpcGVFcnJvciwgQ29ubmVjdGlvblJlc2V0RXJyb3IpOgogICAgICAgICAgICAjIFRoZSBVSSBtYXkg'
    'aGF2ZSBjbG9zZWQgb3IgY2FuY2VsZWQgYSBwb2xsLiBEbyBub3QgZW1pdCBhIHNlY29uZCByZXNwb25zZS4KICAgICAgICAg'
    'ICAgcmV0dXJuCgogICAgZGVmIF9hdXRob3JpemVkKHNlbGYpIC0+IGJvb2w6CiAgICAgICAgcmV0dXJuIHNlY3JldHMuY29t'
    'cGFyZV9kaWdlc3QoCiAgICAgICAgICAgIHNlbGYuaGVhZGVycy5nZXQoIlgtRXZnZW5pdW0tVG9rZW4iLCAiIiksCiAgICAg'
    'ICAgICAgIHNlbGYuc2VydmVyLnRva2VuLAogICAgICAgICkKCiAgICBkZWYgX3JlcXVpcmVfYXV0aChzZWxmKSAtPiBib29s'
    'OgogICAgICAgIGlmIHNlbGYuX2F1dGhvcml6ZWQoKToKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBzZWxmLl9q'
    'c29uKHsib2siOiBGYWxzZSwgImVycm9yIjogInVuYXV0aG9yaXplZCJ9LCA0MDMpCiAgICAgICAgcmV0dXJuIEZhbHNlCgog'
    'ICAgZGVmIF9yZWFkX2pzb24oc2VsZikgLT4gZGljdDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGxlbmd0aCA9IGludChz'
    'ZWxmLmhlYWRlcnMuZ2V0KCJDb250ZW50LUxlbmd0aCIsICIwIikpCiAgICAgICAgZXhjZXB0IFZhbHVlRXJyb3IgYXMgZXhj'
    'OgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoItCd0LXQutC+0YDRgNC10LrRgtC90YvQuSBDb250ZW50LUxlbmd0'
    'aC4iKSBmcm9tIGV4YwogICAgICAgIGlmIGxlbmd0aCA8IDAgb3IgbGVuZ3RoID4gTUFYX0JPRFk6CiAgICAgICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcigi0KHQu9C40YjQutC+0Lwg0LHQvtC70YzRiNC+0Lkg0LfQsNC/0YDQvtGBLiIpCiAgICAgICAg'
    'cmF3ID0gc2VsZi5yZmlsZS5yZWFkKGxlbmd0aCkKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBheWxvYWQgPSBqc29uLmxv'
    'YWRzKHJhdy5kZWNvZGUoInV0Zi04IikgaWYgcmF3IGVsc2UgInt9IikKICAgICAgICBleGNlcHQgKFVuaWNvZGVEZWNvZGVF'
    'cnJvciwganNvbi5KU09ORGVjb2RlRXJyb3IpIGFzIGV4YzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKGYi0J3Q'
    'tdC60L7RgNGA0LXQutGC0L3Ri9C5IEpTT046IHtleGN9IikgZnJvbSBleGMKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShw'
    'YXlsb2FkLCBkaWN0KToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCLQntC20LjQtNCw0LvRgdGPIEpTT04gb2Jq'
    'ZWN0LiIpCiAgICAgICAgcmV0dXJuIHBheWxvYWQKCiAgICBkZWYgZG9fT1BUSU9OUyhzZWxmKSAtPiBOb25lOgogICAgICAg'
    'IHNlbGYuX2hlYWRlcnMoMjA0KQoKICAgIGRlZiBkb19HRVQoc2VsZikgLT4gTm9uZToKICAgICAgICBpZiBub3Qgc2VsZi5f'
    'cmVxdWlyZV9hdXRoKCk6CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgc2VsZi5wYXRo'
    'ID09ICIvYXBpL3N0YXRlIjoKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IFRydWUsICJzdGF0ZSI6IHJ1bl92'
    'cG5fanNvbihbInVpIiwgInN0YXRlIl0pfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBzZWxmLnBh'
    'dGggPT0gIi9hcGkvcnVubmluZyI6CiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBUcnVlLCAicnVubmluZyI6'
    'IHJ1bl92cG5fanNvbihbInVpIiwgInJ1bm5pbmciXSl9KQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlm'
    'IHNlbGYucGF0aCA9PSAiL2FwaS9oZWFsdGgiOgogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgImFw'
    'cCI6IEFQUF9OQU1FfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBzZWxmLl9qc29uKHsib2siOiBGYWxz'
    'ZSwgImVycm9yIjogIm5vdCBmb3VuZCJ9LCA0MDQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAg'
    'ICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAiZXJyb3IiOiBzdHIoZXhjKX0sIDUwMCkKCiAgICBkZWYgZG9fUE9TVChz'
    'ZWxmKSAtPiBOb25lOgogICAgICAgIGlmIG5vdCBzZWxmLl9yZXF1aXJlX2F1dGgoKToKICAgICAgICAgICAgcmV0dXJuCiAg'
    'ICAgICAgdHJ5OgogICAgICAgICAgICBwYXlsb2FkID0gc2VsZi5fcmVhZF9qc29uKCkKICAgICAgICAgICAgaWYgc2VsZi5w'
    'YXRoID09ICIvYXBpL3NldHRpbmdzIjoKICAgICAgICAgICAgICAgIHN1YnByb2Nlc3MuUG9wZW4oW3N5cy5leGVjdXRhYmxl'
    'LCBzdHIoSEVSRSAvICJldmdlbml1bV9ndWkucHkiKSwgIi0tZGV0YWNoIl0sIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwg'
    'Y2xvc2VfZmRzPVRydWUsIHN0YXJ0X25ld19zZXNzaW9uPVRydWUpCiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHsib2si'
    'OiBUcnVlfSkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBzZWxmLnBhdGggPT0gIi9hcGkvYWN0aW9u'
    'IjoKICAgICAgICAgICAgICAgIHRva2VuID0gZW5jb2RlX3VpX3BheWxvYWQocGF5bG9hZCkKICAgICAgICAgICAgICAgIG91'
    'dHB1dCA9IHJ1bl92cG4oWyJ1aSIsICJhY3Rpb24iLCAiLSJdLCBzZWNyZXRfaW5wdXQ9dG9rZW4pCiAgICAgICAgICAgICAg'
    'ICByZXBseSA9IHsib2siOiBUcnVlLCAib3V0cHV0Ijogb3V0cHV0fQogICAgICAgICAgICAgICAgaWYgcGF5bG9hZC5nZXQo'
    'ImFjdGlvbiIpID09ICJ0b2tlbi1zYXZlIjoKICAgICAgICAgICAgICAgICAgICByZXBseVsic3RhdGUiXSA9IHJ1bl92cG5f'
    'anNvbihbInVpIiwgInN0YXRlIl0pCiAgICAgICAgICAgICAgICBzZWxmLl9qc29uKHJlcGx5KQogICAgICAgICAgICAgICAg'
    'cmV0dXJuCiAgICAgICAgICAgIGlmIHNlbGYucGF0aCA9PSAiL2FwaS90b2dnbGUiOgogICAgICAgICAgICAgICAgb3V0cHV0'
    'ID0gcnVuX3ZwbihbInRvZ2dsZSJdKQogICAgICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogVHJ1ZSwgIm91dHB1dCI6'
    'IG91dHB1dCwgInN0YXRlIjogcnVuX3Zwbl9qc29uKFsidWkiLCAic3RhdGUiXSl9KQogICAgICAgICAgICAgICAgcmV0dXJu'
    'CiAgICAgICAgICAgIHNlbGYuX2pzb24oeyJvayI6IEZhbHNlLCAiZXJyb3IiOiAibm90IGZvdW5kIn0sIDQwNCkKICAgICAg'
    'ICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6'
    'IHN0cihleGMpfSwgNTAwKQoKCmRlZiBzdGF0ZV9sb2dfcGF0aCgpIC0+IHBhdGhsaWIuUGF0aDoKICAgIHJvb3QgPSBwYXRo'
    'bGliLlBhdGgob3MuZW52aXJvbi5nZXQoIlhER19TVEFURV9IT01FIiwgcGF0aGxpYi5QYXRoLmhvbWUoKSAvICIubG9jYWwi'
    'IC8gInN0YXRlIikpCiAgICBwYXRoID0gcm9vdCAvICJldmdlbml1bS1uZXR3b3JrIiAvICgid2lkZ2V0LmxvZyIgaWYgIi0t'
    'd2lkZ2V0IiBpbiBzeXMuYXJndiBlbHNlICJndWkubG9nIikKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwg'
    'ZXhpc3Rfb2s9VHJ1ZSkKICAgIHJldHVybiBwYXRoCgoKZGVmIGxhdW5jaF9kZXRhY2hlZCgpIC0+IGludDoKICAgIHFtbF9m'
    'aWxlID0gV0lER0VUX0ZJTEUgaWYgIi0td2lkZ2V0IiBpbiBzeXMuYXJndiBlbHNlIFFNTF9GSUxFCiAgICBpZiBub3QgcW1s'
    'X2ZpbGUuaXNfZmlsZSgpOgogICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC10L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7'
    'cW1sX2ZpbGV9IiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgZmluZF9xbWxfcnVudGlt'
    'ZSgpOgogICAgICAgIHByaW50KCLQndC1INC90LDQudC00LXQvSBRdCA2IFFNTCBydW50aW1lIChBcmNoOiBxdDYtZGVjbGFy'
    'YXRpdmU7IEZlZG9yYTogcXQ2LXF0ZGVjbGFyYXRpdmUtZGV2ZWwpLiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1'
    'cm4gMQogICAgbG9nX3BhdGggPSBzdGF0ZV9sb2dfcGF0aCgpCiAgICB3aXRoIGxvZ19wYXRoLm9wZW4oImFiIiwgYnVmZmVy'
    'aW5nPTApIGFzIGxvZzoKICAgICAgICBzdWJwcm9jZXNzLlBvcGVuKAogICAgICAgICAgICBbc3lzLmV4ZWN1dGFibGUsIHN0'
    'cihwYXRobGliLlBhdGgoX19maWxlX18pLnJlc29sdmUoKSksICpbYXJnIGZvciBhcmcgaW4gc3lzLmFyZ3ZbMTpdIGlmIGFy'
    'ZyAhPSAiLS1kZXRhY2giXV0sCiAgICAgICAgICAgIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwKICAgICAgICAgICAgc3Rk'
    'b3V0PWxvZywKICAgICAgICAgICAgc3RkZXJyPWxvZywKICAgICAgICAgICAgc3RhcnRfbmV3X3Nlc3Npb249VHJ1ZSwKICAg'
    'ICAgICAgICAgY2xvc2VfZmRzPVRydWUsCiAgICAgICAgKQogICAgcmV0dXJuIDAKCgpkZWYgcnVuX2d1aSgpIC0+IGludDoK'
    'ICAgIHFtbCA9IGZpbmRfcW1sX3J1bnRpbWUoKQogICAgaWYgbm90IHFtbDoKICAgICAgICBwcmludCgi0J3QtSDQvdCw0LnQ'
    'tNC10L0gUXQgNiBRTUwgcnVudGltZSAoQXJjaDogcXQ2LWRlY2xhcmF0aXZlOyBGZWRvcmE6IHF0Ni1xdGRlY2xhcmF0aXZl'
    'LWRldmVsKS4iLCBmaWxlPXN5cy5zdGRlcnIpCiAgICAgICAgcmV0dXJuIDEKICAgIHFtbF9maWxlID0gV0lER0VUX0ZJTEUg'
    'aWYgIi0td2lkZ2V0IiBpbiBzeXMuYXJndiBlbHNlIFFNTF9GSUxFCiAgICBpZiBub3QgcW1sX2ZpbGUuaXNfZmlsZSgpOgog'
    'ICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC10L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7cW1sX2ZpbGV9IiwgZmlsZT1z'
    'eXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCgogICAgdG9rZW4gPSBzZWNyZXRzLnRva2VuX3VybHNhZmUoMzIpCiAgICBz'
    'ZXJ2ZXIgPSBBcGlTZXJ2ZXIoKCIxMjcuMC4wLjEiLCAwKSwgSGFuZGxlciwgdG9rZW4pCiAgICBwb3J0ID0gaW50KHNlcnZl'
    'ci5zZXJ2ZXJfYWRkcmVzc1sxXSkKICAgIHRocmVhZCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXNlcnZlci5zZXJ2ZV9m'
    'b3JldmVyLCBuYW1lPSJldmdlbml1bS1ndWktYXBpIiwgZGFlbW9uPVRydWUpCiAgICB0aHJlYWQuc3RhcnQoKQoKICAgIGVu'
    'diA9IG9zLmVudmlyb24uY29weSgpCiAgICBlbnYuc2V0ZGVmYXVsdCgiUVRfUVVJQ0tfQ09OVFJPTFNfU1RZTEUiLCAiQmFz'
    'aWMiKQogICAgZW52LnNldGRlZmF1bHQoIlFNTF9ESVNBQkxFX0RJU0tfQ0FDSEUiLCAiMCIpCiAgICBlbnYuc2V0ZGVmYXVs'
    'dCgiUVRfRk9SQ0VfU1RERVJSX0xPR0dJTkciLCAiMSIpCgogICAgdHJ5OgogICAgICAgIHdpZGdldCA9ICItLXdpZGdldCIg'
    'aW4gc3lzLmFyZ3YKICAgICAgICAjIEtlZXAgb25lIHRyYXkgaWNvbiBwZXIgdXNlci9zZXNzaW9uOyB0aGUgbG9jayBpcyBy'
    'ZWxlYXNlZCBvbiBleGVjL2V4aXQuCiAgICAgICAgbG9jayA9IE5vbmUKICAgICAgICBpZiB3aWRnZXQ6CiAgICAgICAgICAg'
    'IGxvY2sgPSBzdGF0ZV9sb2dfcGF0aCgpLndpdGhfbmFtZSgid2lkZ2V0LmxvY2siKS5vcGVuKCJhKyIpCiAgICAgICAgICAg'
    'IHRyeToKICAgICAgICAgICAgICAgIGZjbnRsLmZsb2NrKGxvY2ssIGZjbnRsLkxPQ0tfRVggfCBmY250bC5MT0NLX05CKQog'
    'ICAgICAgICAgICBleGNlcHQgQmxvY2tpbmdJT0Vycm9yOgogICAgICAgICAgICAgICAgbG9jay5jbG9zZSgpCiAgICAgICAg'
    'ICAgICAgICByZXR1cm4gMAogICAgICAgIGNvbW1hbmQgPSBbcW1sLCAiLS1hcHB0eXBlIiwgIndpZGdldCIgaWYgd2lkZ2V0'
    'IGVsc2UgImd1aSIsIHN0cihxbWxfZmlsZSksICItLSJdCiAgICAgICAgY29tbWFuZCArPSBbYXJnIGZvciBhcmcgaW4gKCIt'
    'LXNob3ciLCAiLS1wcmV2aWV3IikgaWYgYXJnIGluIHN5cy5hcmd2XQogICAgICAgIGNvbW1hbmQgKz0gW3N0cihwb3J0KSwg'
    'dG9rZW5dCiAgICAgICAgaWYgbm90IHdpZGdldDoKICAgICAgICAgICAgcmV0dXJuIHN1YnByb2Nlc3MucnVuKGNvbW1hbmQs'
    'IGVudj1lbnYsIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlCiAgICAgICAgZGVmIGFzc2V0cygpOgogICAgICAgICAgICByZXR1'
    'cm4gdHVwbGUoKHAuc3RhdCgpLnN0X210aW1lX25zLCBwLnN0YXQoKS5zdF9zaXplKSBmb3IgcCBpbiAoSEVSRSAvICJldmdl'
    'bml1bV9ndWkucHkiLCBXSURHRVRfRklMRSkpCiAgICAgICAgYmVmb3JlID0gYXNzZXRzKCkKICAgICAgICBjaGlsZCA9IHN1'
    'YnByb2Nlc3MuUG9wZW4oY29tbWFuZCwgZW52PWVudikKICAgICAgICByZWxvYWRfd2lkZ2V0ID0gRmFsc2UKICAgICAgICB0'
    'cnk6CiAgICAgICAgICAgIHdoaWxlIGNoaWxkLnBvbGwoKSBpcyBOb25lOgogICAgICAgICAgICAgICAgdGltZS5zbGVlcCgx'
    'KQogICAgICAgICAgICAgICAgaWYgYXNzZXRzKCkgIT0gYmVmb3JlOgogICAgICAgICAgICAgICAgICAgICMgTGV0IGludGVy'
    'bmFsLWFmdGVyLXVwZGF0ZSBmaW5pc2ggcmVwbGFjaW5nIHRoZSBhc3NldCBzZXQuCiAgICAgICAgICAgICAgICAgICAgdGlt'
    'ZS5zbGVlcCgyKQogICAgICAgICAgICAgICAgICAgIHJlbG9hZF93aWRnZXQgPSBUcnVlCiAgICAgICAgICAgICAgICAgICAg'
    'YnJlYWsKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBpZiBjaGlsZC5wb2xsKCkgaXMgTm9uZToKICAgICAgICAgICAg'
    'ICAgIGNoaWxkLnRlcm1pbmF0ZSgpCiAgICAgICAgICAgICAgICB0cnk6IGNoaWxkLndhaXQodGltZW91dD0zKQogICAgICAg'
    'ICAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6CiAgICAgICAgICAgICAgICAgICAgY2hpbGQua2ls'
    'bCgpOyBjaGlsZC53YWl0KCkKICAgICAgICAgICAgbG9jay5jbG9zZSgpCiAgICAgICAgaWYgcmVsb2FkX3dpZGdldDoKICAg'
    'ICAgICAgICAgb3MuZXhlY3Yoc3lzLmV4ZWN1dGFibGUsIFtzeXMuZXhlY3V0YWJsZSwgc3RyKEhFUkUgLyAiZXZnZW5pdW1f'
    'Z3VpLnB5IiksICItLXdpZGdldCJdKQogICAgICAgIHJldHVybiBjaGlsZC5yZXR1cm5jb2RlCiAgICBmaW5hbGx5OgogICAg'
    'ICAgIHNlcnZlci5zaHV0ZG93bigpCiAgICAgICAgc2VydmVyLnNlcnZlcl9jbG9zZSgpCiAgICAgICAgdGhyZWFkLmpvaW4o'
    'dGltZW91dD0yKQoKCmRlZiBzZWxmX3Rlc3QoKSAtPiBpbnQ6CiAgICBzYW1wbGUgPSB7ImFjdGlvbiI6ICJhcHBfYWRkIiwg'
    'InRhcmdldCI6ICIvb3B0L2V4YW1wbGUvYmluL2FwcCJ9CiAgICB0b2tlbiA9IGVuY29kZV91aV9wYXlsb2FkKHNhbXBsZSkK'
    'ICAgIGRlY29kZWQgPSB1cmxsaWIucGFyc2UudW5xdW90ZShiYXNlNjQuYjY0ZGVjb2RlKHRva2VuKS5kZWNvZGUoImFzY2lp'
    'IikpCiAgICBhc3NlcnQganNvbi5sb2FkcyhkZWNvZGVkKSA9PSBzYW1wbGUKICAgIGFzc2VydCBNQVhfQk9EWSA8PSAxMDI0'
    'ICogMTAyNAogICAgcW1sID0gSEVSRSAvICJldmdlbml1bV9ndWkucW1sIgogICAgaWYgcW1sLmV4aXN0cygpOgogICAgICAg'
    'IHRleHQgPSBxbWwucmVhZF90ZXh0KGVuY29kaW5nPSJ1dGYtOCIpCiAgICAgICAgYXNzZXJ0ICJFdmdlbml1bSBOZXR3b3Jr'
    'IiBpbiB0ZXh0CiAgICAgICAgYXNzZXJ0ICIvYXBpL3J1bm5pbmciIGluIHRleHQKICAgICAgICBhc3NlcnQgIi9hcGkvYWN0'
    'aW9uIiBpbiB0ZXh0CiAgICBwcmludCgiZXZnZW5pdW0tZ3VpIHNlbGYtdGVzdCBPSyIpCiAgICByZXR1cm4gMAoKCmRlZiBt'
    'YWluKCkgLT4gaW50OgogICAgaWYgIi0tc2VsZi10ZXN0IiBpbiBzeXMuYXJndjoKICAgICAgICByZXR1cm4gc2VsZl90ZXN0'
    'KCkKICAgIGlmICItLWRldGFjaCIgaW4gc3lzLmFyZ3Y6CiAgICAgICAgcmV0dXJuIGxhdW5jaF9kZXRhY2hlZCgpCiAgICBy'
    'ZXR1cm4gcnVuX2d1aSgpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIHJhaXNlIFN5c3RlbUV4aXQobWFpbigp'
    'KQo='
)

DESKTOP_WIDGET_QML_B64 = (
    'aW1wb3J0IFF0UXVpY2sKaW1wb3J0IFF0UXVpY2suV2luZG93CmltcG9ydCBRdFF1aWNrLkNvbnRyb2xzIGFzIEMKaW1wb3J0'
    'IFF0UXVpY2suTGF5b3V0cwppbXBvcnQgUXQubGFicy5wbGF0Zm9ybSBhcyBQbGF0Zm9ybQoKQy5BcHBsaWNhdGlvbldpbmRv'
    'dyB7CiAgICBpZDogcm9vdAogICAgd2lkdGg6IDM4NAogICAgaGVpZ2h0OiBib2R5LmltcGxpY2l0SGVpZ2h0ICsgNDAKICAg'
    'IHZpc2libGU6IGZhbHNlCiAgICB0aXRsZTogIkV2Z2VuaXVtIMK3IFZQTiIKICAgIGZsYWdzOiBRdC5Ub29sIHwgUXQuRnJh'
    'bWVsZXNzV2luZG93SGludCB8IFF0LldpbmRvd1N0YXlzT25Ub3BIaW50CiAgICBjb2xvcjogInRyYW5zcGFyZW50IgogICAg'
    'cHJvcGVydHkgdmFyIHN0YXRlOiAoe30pCiAgICBwcm9wZXJ0eSBib29sIHJlYWR5OiBmYWxzZQogICAgcHJvcGVydHkgYm9v'
    'bCBidXN5OiBmYWxzZQogICAgcHJvcGVydHkgYm9vbCBzdGF0ZVBlbmRpbmc6IGZhbHNlCiAgICBwcm9wZXJ0eSBzdHJpbmcg'
    'ZXJyb3JUZXh0OiAiIgogICAgcHJvcGVydHkgc3RyaW5nIHBvbGxFcnJvclRleHQ6ICIiCiAgICByZWFkb25seSBwcm9wZXJ0'
    'eSB2YXIgdHVubmVsOiBzdGF0ZS50dW5uZWwgfHwgKHt9KQogICAgcmVhZG9ubHkgcHJvcGVydHkgYm9vbCBjb25uZWN0ZWQ6'
    'IHJlYWR5ICYmICFwb2xsRXJyb3JUZXh0ICYmIEJvb2xlYW4oc3RhdGUuYWN0aXZlKQogICAgcmVhZG9ubHkgcHJvcGVydHkg'
    'Ym9vbCBjb25uZWN0aW5nOiByZWFkeSAmJiAhcG9sbEVycm9yVGV4dCAmJiBCb29sZWFuKHN0YXRlLmNvbm5lY3RpbmcpCiAg'
    'ICByZWFkb25seSBwcm9wZXJ0eSBib29sIGVuZ2FnZWQ6IEJvb2xlYW4odHVubmVsLnJ1bm5pbmcgfHwgc3RhdGUuZ3VhcmQp'
    'CiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciBhY2NlbnQ6IHBvbGxFcnJvclRleHQgPyAiI2ZmYmQ2OSIgOiBjb25uZWN0'
    'ZWQgPyAiIzVjZTBiYyIgOiBjb25uZWN0aW5nID8gIiM3OWJhZmYiIDogIiM5YWFhYzAiCiAgICByZWFkb25seSBwcm9wZXJ0'
    'eSBzdHJpbmcgc3RhdHVzVGl0bGU6ICFyZWFkeSA/ICLQn9GA0L7QstC10YDRj9C10LwgVlBO4oCmIiA6IHBvbGxFcnJvclRl'
    'eHQgPyAi0KHQvtGB0YLQvtGP0L3QuNC1INC90LXQuNC30LLQtdGB0YLQvdC+IiA6IGNvbm5lY3RlZCA/ICLQktGLINC/0L7Q'
    'tNC60LvRjtGH0LXQvdGLIiA6IGNvbm5lY3RpbmcgPyAi0J/QvtC00LrQu9GO0YfQsNC10LzigKYiIDogc3RhdGUuZ3VhcmQg'
    'PyAi0KLRgNCw0YTQuNC6INC30LDRidC40YnRkdC9IiA6ICJWUE4g0LLRi9C60LvRjtGH0LXQvSIKICAgIHJlYWRvbmx5IHBy'
    'b3BlcnR5IHZhciBhcmdzOiBRdC5hcHBsaWNhdGlvbi5hcmd1bWVudHMKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBh'
    'cGlUb2tlbjogU3RyaW5nKGFyZ3NbYXJncy5sZW5ndGggLSAxXSkKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBhcGlC'
    'YXNlOiAiaHR0cDovLzEyNy4wLjAuMToiICsgU3RyaW5nKGFyZ3NbYXJncy5sZW5ndGggLSAyXSkKCiAgICBmdW5jdGlvbiBh'
    'cGkobWV0aG9kLCBwYXRoLCBwYXlsb2FkLCBjYWxsYmFjaywgb3BlcmF0aW9uKSB7CiAgICAgICAgY29uc3QgeGhyID0gbmV3'
    'IFhNTEh0dHBSZXF1ZXN0KCkKICAgICAgICBsZXQgZmluaXNoZWQgPSBmYWxzZQogICAgICAgIGNvbnN0IHRpbWVyID0gd2F0'
    'Y2hkb2cuY3JlYXRlT2JqZWN0KHJvb3QpCiAgICAgICAgZnVuY3Rpb24gZmluaXNoKGVycm9yLCBkYXRhKSB7CiAgICAgICAg'
    'ICAgIGlmIChmaW5pc2hlZCkgcmV0dXJuCiAgICAgICAgICAgIGZpbmlzaGVkID0gdHJ1ZQogICAgICAgICAgICB0aW1lci5z'
    'dG9wKCk7IHRpbWVyLmRlc3Ryb3koKQogICAgICAgICAgICBpZiAob3BlcmF0aW9uKSB7IHJvb3QuYnVzeSA9IGZhbHNlOyBy'
    'b290LmVycm9yVGV4dCA9IGVycm9yIHx8ICIiIH0KICAgICAgICAgICAgZWxzZSB7IHJvb3Quc3RhdGVQZW5kaW5nID0gZmFs'
    'c2U7IHJvb3QucG9sbEVycm9yVGV4dCA9IGVycm9yIHx8ICIiIH0KICAgICAgICAgICAgaWYgKCFlcnJvciAmJiBjYWxsYmFj'
    'aykgY2FsbGJhY2soZGF0YSkKICAgICAgICB9CiAgICAgICAgdGltZXIuaW50ZXJ2YWwgPSBvcGVyYXRpb24gPyA3ODAwMDAg'
    'OiAxMjAwMAogICAgICAgIHRpbWVyLnRyaWdnZXJlZC5jb25uZWN0KGZ1bmN0aW9uKCkgewogICAgICAgICAgICBmaW5pc2go'
    'b3BlcmF0aW9uID8gItCe0YLQstC10YIg0L7Qv9C10YDQsNGG0LjQuCDQvdC1INC/0L7Qu9GD0YfQtdC9LiDQn9GA0L7QstC1'
    '0YDRjNGC0LUgdnBuIHN0YXR1cy4iIDogItCd0LXRgiDQvtGC0LLQtdGC0LAg0L7RgiBWUE4uINCf0L7Qv9GA0L7QsdGD0LnR'
    'gtC1INC+0LHQvdC+0LLQuNGC0Ywg0YHQvtGB0YLQvtGP0L3QuNC1LiIsIG51bGwpCiAgICAgICAgICAgIHhoci5hYm9ydCgp'
    'CiAgICAgICAgfSkKICAgICAgICB4aHIub3BlbihtZXRob2QsIGFwaUJhc2UgKyBwYXRoLCB0cnVlKQogICAgICAgIHhoci5z'
    'ZXRSZXF1ZXN0SGVhZGVyKCJYLUV2Z2VuaXVtLVRva2VuIiwgYXBpVG9rZW4pCiAgICAgICAgaWYgKHBheWxvYWQgIT09IG51'
    'bGwpIHhoci5zZXRSZXF1ZXN0SGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbiIpCiAgICAgICAgeGhy'
    'Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9IGZ1bmN0aW9uKCkgewogICAgICAgICAgICBpZiAoeGhyLnJlYWR5U3RhdGUgIT09IFhN'
    'TEh0dHBSZXF1ZXN0LkRPTkUgfHwgZmluaXNoZWQpIHJldHVybgogICAgICAgICAgICBsZXQgZGF0YQogICAgICAgICAgICB0'
    'cnkgeyBkYXRhID0gSlNPTi5wYXJzZShTdHJpbmcoeGhyLnJlc3BvbnNlVGV4dCB8fCAie30iKSkgfQogICAgICAgICAgICBj'
    'YXRjaCAoZSkgeyBmaW5pc2goItCd0LXQutC+0YDRgNC10LrRgtC90YvQuSDQvtGC0LLQtdGCIFZQTiIsIG51bGwpOyByZXR1'
    'cm4gfQogICAgICAgICAgICBmaW5pc2goeGhyLnN0YXR1cyA+PSAyMDAgJiYgeGhyLnN0YXR1cyA8IDMwMCAmJiBkYXRhLm9r'
    'ID8gIiIgOiBTdHJpbmcoZGF0YS5lcnJvciB8fCAiVlBOINC90LXQtNC+0YHRgtGD0L/QtdC9IiksIGRhdGEpCiAgICAgICAg'
    'fQogICAgICAgIHRpbWVyLnN0YXJ0KCkKICAgICAgICB4aHIuc2VuZChwYXlsb2FkID09PSBudWxsID8gbnVsbCA6IEpTT04u'
    'c3RyaW5naWZ5KHBheWxvYWQpKQogICAgfQogICAgQ29tcG9uZW50IHsgaWQ6IHdhdGNoZG9nOyBUaW1lciB7IHJlcGVhdDog'
    'ZmFsc2UgfSB9CiAgICBmdW5jdGlvbiByZWZyZXNoU3RhdGUoKSB7CiAgICAgICAgaWYgKHN0YXRlUGVuZGluZykgcmV0dXJu'
    'CiAgICAgICAgc3RhdGVQZW5kaW5nID0gdHJ1ZQogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvc3RhdGUiLCBudWxsLCBmdW5j'
    'dGlvbihyZXBseSkgeyByb290LnN0YXRlID0gcmVwbHkuc3RhdGUgfHwgKHt9KTsgcm9vdC5yZWFkeSA9IHRydWUgfSkKICAg'
    'IH0KICAgIGZ1bmN0aW9uIGFjdGlvbihuYW1lKSB7CiAgICAgICAgaWYgKGJ1c3kgfHwgIXJlYWR5IHx8IHBvbGxFcnJvclRl'
    'eHQgfHwgKGNvbm5lY3RpbmcgJiYgbmFtZSAhPT0gImRpc2Nvbm5lY3QiKSkgcmV0dXJuCiAgICAgICAgYnVzeSA9IHRydWUK'
    'ICAgICAgICBhcGkoIlBPU1QiLCAiL2FwaS9hY3Rpb24iLCB7YWN0aW9uOiBuYW1lfSwgZnVuY3Rpb24oX3JlcGx5KSB7IHJv'
    'b3QucmVmcmVzaFN0YXRlKCkgfSwgdHJ1ZSkKICAgIH0KICAgIGZ1bmN0aW9uIG9wZW5TZXR0aW5ncygpIHsKICAgICAgICBp'
    'ZiAoYnVzeSkgcmV0dXJuCiAgICAgICAgYnVzeSA9IHRydWUKICAgICAgICBhcGkoIlBPU1QiLCAiL2FwaS9zZXR0aW5ncyIs'
    'IHt9LCBmdW5jdGlvbihfcmVwbHkpIHsgaWYgKHRyYXkuYXZhaWxhYmxlKSByb290LmhpZGUoKSB9LCB0cnVlKQogICAgfQog'
    'ICAgZnVuY3Rpb24gc2hvd1BhbmVsKCkgewogICAgICAgIC8vIFNlbGVjdCB0aGUgc2NyZWVuIGNvbnRhaW5pbmcgdGhlIHRy'
    'YXksIGFuZCBjbGFtcCBhZ2FpbnN0IGl0cyB3b3JrIGFyZWEuCiAgICAgICAgY29uc3QgZyA9IHRyYXkuZ2VvbWV0cnkKICAg'
    'ICAgICBmb3IgKGxldCBpID0gMDsgaSA8IFF0LmFwcGxpY2F0aW9uLnNjcmVlbnMubGVuZ3RoOyArK2kpIHsKICAgICAgICAg'
    'ICAgY29uc3QgcyA9IFF0LmFwcGxpY2F0aW9uLnNjcmVlbnNbaV0KICAgICAgICAgICAgaWYgKGcud2lkdGggPiAwICYmIGcu'
    'eCA+PSBzLnZpcnR1YWxYICYmIGcueCA8IHMudmlydHVhbFggKyBzLndpZHRoICYmIGcueSA+PSBzLnZpcnR1YWxZICYmIGcu'
    'eSA8IHMudmlydHVhbFkgKyBzLmhlaWdodCkgeyByb290LnNjcmVlbiA9IHM7IGJyZWFrIH0KICAgICAgICB9CiAgICAgICAg'
    'Y29uc3QgYXJlYSA9IHt4OiByb290LnNjcmVlbi52aXJ0dWFsWCwgeTogcm9vdC5zY3JlZW4udmlydHVhbFksIHdpZHRoOiBy'
    'b290LnNjcmVlbi5kZXNrdG9wQXZhaWxhYmxlV2lkdGgsIGhlaWdodDogcm9vdC5zY3JlZW4uZGVza3RvcEF2YWlsYWJsZUhl'
    'aWdodH0KICAgICAgICByb290LnggPSBNYXRoLnJvdW5kKE1hdGgubWF4KGFyZWEueCArIDgsIE1hdGgubWluKGcud2lkdGgg'
    'PiAwID8gZy54ICsgZy53aWR0aCAtIHdpZHRoIDogYXJlYS54ICsgYXJlYS53aWR0aCAtIHdpZHRoIC0gMTYsIGFyZWEueCAr'
    'IGFyZWEud2lkdGggLSB3aWR0aCAtIDgpKSkKICAgICAgICByb290LnkgPSBNYXRoLnJvdW5kKE1hdGgubWF4KGFyZWEueSAr'
    'IDgsIE1hdGgubWluKGcuaGVpZ2h0ID4gMCAmJiBnLnkgPCBhcmVhLnkgKyBhcmVhLmhlaWdodCAvIDIgPyBnLnkgKyBnLmhl'
    'aWdodCArIDggOiAoZy5oZWlnaHQgPiAwID8gZy55IC0gaGVpZ2h0IC0gOCA6IGFyZWEueSArIGFyZWEuaGVpZ2h0IC0gaGVp'
    'Z2h0IC0gMTYpLCBhcmVhLnkgKyBhcmVhLmhlaWdodCAtIGhlaWdodCAtIDgpKSkKICAgICAgICByb290LnNob3coKTsgcm9v'
    'dC5yYWlzZSgpOyByb290LnJlcXVlc3RBY3RpdmF0ZSgpOyByZWZyZXNoU3RhdGUoKQogICAgfQogICAgb25BY3RpdmVDaGFu'
    'Z2VkOiBpZiAoIWFjdGl2ZSAmJiB2aXNpYmxlICYmIHRyYXkuYXZhaWxhYmxlICYmICFhcmdzLmluY2x1ZGVzKCItLXByZXZp'
    'ZXciKSkgZGlzbWlzcy5zdGFydCgpCiAgICBUaW1lciB7IGlkOiBkaXNtaXNzOyBpbnRlcnZhbDogMTgwOyBvblRyaWdnZXJl'
    'ZDogaWYgKCFyb290LmFjdGl2ZSkgcm9vdC5oaWRlKCkgfQogICAgb25DbG9zaW5nOiBmdW5jdGlvbihldmVudCkgeyBpZiAo'
    'dHJheS5hdmFpbGFibGUpIHsgZXZlbnQuYWNjZXB0ZWQgPSBmYWxzZTsgcm9vdC5oaWRlKCkgfSB9CiAgICBTaG9ydGN1dCB7'
    'IHNlcXVlbmNlOiAiRXNjYXBlIjsgb25BY3RpdmF0ZWQ6IGlmICh0cmF5LmF2YWlsYWJsZSkgcm9vdC5oaWRlKCkgfQogICAg'
    'VGltZXIgeyBpbnRlcnZhbDogcm9vdC52aXNpYmxlIHx8IHJvb3QuY29ubmVjdGluZyA/IDE1MDAgOiA1MDAwOyBydW5uaW5n'
    'OiB0cnVlOyByZXBlYXQ6IHRydWU7IG9uVHJpZ2dlcmVkOiByb290LnJlZnJlc2hTdGF0ZSgpIH0KICAgIENvbXBvbmVudC5v'
    'bkNvbXBsZXRlZDogeyByZWZyZXNoU3RhdGUoKTsgaWYgKGFyZ3MuaW5jbHVkZXMoIi0tc2hvdyIpIHx8IGFyZ3MuaW5jbHVk'
    'ZXMoIi0tcHJldmlldyIpIHx8ICF0cmF5LmF2YWlsYWJsZSkgc2hvd1BhbmVsKCkgfQoKICAgIFBsYXRmb3JtLlN5c3RlbVRy'
    'YXlJY29uIHsKICAgICAgICBpZDogdHJheQogICAgICAgIHZpc2libGU6IHRydWUKICAgICAgICBpY29uLnNvdXJjZTogUXQu'
    'cmVzb2x2ZWRVcmwoIndpZGdldC0iICsgKHJvb3QucG9sbEVycm9yVGV4dCA/ICJ3YXJuaW5nIiA6IHJvb3QuY29ubmVjdGVk'
    'ID8gImFjdGl2ZSIgOiByb290LmNvbm5lY3RpbmcgfHwgcm9vdC5idXN5ID8gImNvbm5lY3RpbmciIDogcm9vdC5zdGF0ZS5n'
    'dWFyZCA/ICJ3YXJuaW5nIiA6ICJvZmYiKSArICIuc3ZnIikKICAgICAgICB0b29sdGlwOiAiRXZnZW5pdW0gwrcgIiArIHJv'
    'b3Quc3RhdHVzVGl0bGUKICAgICAgICBvbkFjdGl2YXRlZDogZnVuY3Rpb24ocmVhc29uKSB7CiAgICAgICAgICAgIGlmIChy'
    'ZWFzb24gPT09IFBsYXRmb3JtLlN5c3RlbVRyYXlJY29uLlRyaWdnZXIgfHwgcmVhc29uID09PSBQbGF0Zm9ybS5TeXN0ZW1U'
    'cmF5SWNvbi5Eb3VibGVDbGljaykgewogICAgICAgICAgICAgICAgaWYgKHJvb3QudmlzaWJsZSkgcm9vdC5oaWRlKCk7IGVs'
    'c2Ugcm9vdC5zaG93UGFuZWwoKQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIG1lbnU6IFBsYXRmb3JtLk1lbnUg'
    'ewogICAgICAgICAgICBQbGF0Zm9ybS5NZW51SXRlbSB7IHRleHQ6ICLQntGC0LrRgNGL0YLRjCDQstC40LTQttC10YIiOyBv'
    'blRyaWdnZXJlZDogcm9vdC5zaG93UGFuZWwoKSB9CiAgICAgICAgICAgIFBsYXRmb3JtLk1lbnVJdGVtIHsgdGV4dDogcm9v'
    'dC5lbmdhZ2VkID8gItCe0YLQutC70Y7Rh9C40YLRjCBWUE4iIDogItCf0L7QtNC60LvRjtGH0LjRgtGMIFZQTiI7IGVuYWJs'
    'ZWQ6IHJvb3QucmVhZHkgJiYgIXJvb3QuYnVzeSAmJiAhcm9vdC5wb2xsRXJyb3JUZXh0ICYmIChyb290LmVuZ2FnZWQgfHwg'
    'cm9vdC50dW5uZWwuaGFzX3Rva2VuKTsgb25UcmlnZ2VyZWQ6IHJvb3QuYWN0aW9uKHJvb3QuZW5nYWdlZCA/ICJkaXNjb25u'
    'ZWN0IiA6ICJjb25uZWN0IikgfQogICAgICAgICAgICBQbGF0Zm9ybS5NZW51SXRlbSB7IHRleHQ6ICLQndCw0YHRgtGA0L7Q'
    'udC60LgiOyBlbmFibGVkOiAhcm9vdC5idXN5OyBvblRyaWdnZXJlZDogcm9vdC5vcGVuU2V0dGluZ3MoKSB9CiAgICAgICAg'
    'ICAgIFBsYXRmb3JtLk1lbnVTZXBhcmF0b3Ige30KICAgICAgICAgICAgUGxhdGZvcm0uTWVudUl0ZW0geyB0ZXh0OiAi0JfQ'
    'sNC60YDRi9GC0Ywg0LLQuNC00LbQtdGCIChWUE4g0L/RgNC+0LTQvtC70LbQuNGCINGA0LDQsdC+0YLRgykiOyBvblRyaWdn'
    'ZXJlZDogUXQucXVpdCgpIH0KICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IE11dGVkOiBDLkxhYmVsIHsgY29sb3I6'
    'ICIjOWJhY2MxIjsgZm9udC5waXhlbFNpemU6IDEyIH0KICAgIGNvbXBvbmVudCBTbWFsbEJ1dHRvbjogQy5CdXR0b24gewog'
    'ICAgICAgIGlkOiBjb250cm9sCiAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgIGltcGxpY2l0SGVpZ2h0'
    'OiAzOAogICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMgogICAgICAgIGNvbnRlbnRJdGVtOiBUZXh0IHsgdGV4dDogY29udHJv'
    'bC50ZXh0OyBjb2xvcjogY29udHJvbC5lbmFibGVkID8gIiNkOGU2ZjUiIDogIiM2NTc1OGEiOyBmb250OiBjb250cm9sLmZv'
    'bnQ7IGhvcml6b250YWxBbGlnbm1lbnQ6IFRleHQuQWxpZ25IQ2VudGVyOyB2ZXJ0aWNhbEFsaWdubWVudDogVGV4dC5BbGln'
    'blZDZW50ZXIgfQogICAgICAgIGJhY2tncm91bmQ6IFJlY3RhbmdsZSB7IHJhZGl1czogMTA7IGNvbG9yOiBjb250cm9sLmRv'
    'd24gPyAiIzM1NDc1ZCIgOiBjb250cm9sLmhvdmVyZWQgPyAiIzJiM2I1MCIgOiAiIzIwMmU0MCI7IGJvcmRlci5jb2xvcjog'
    'IiMzNDQ0NWEiIH0KICAgIH0KICAgIEl0ZW0gewogICAgICAgIGlkOiBwYW5lbAogICAgICAgIGFuY2hvcnMuZmlsbDogcGFy'
    'ZW50CiAgICBSZWN0YW5nbGUgewogICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgcmFkaXVzOiAyMgogICAg'
    'ICAgIGNvbG9yOiAiIzEyMWMyYiIKICAgICAgICBib3JkZXIuY29sb3I6ICIjMzU0MjU0IgogICAgICAgIGJvcmRlci53aWR0'
    'aDogMQogICAgICAgIGdyYWRpZW50OiBHcmFkaWVudCB7IEdyYWRpZW50U3RvcCB7IHBvc2l0aW9uOiAwOyBjb2xvcjogIiMx'
    'ZDJkNDEiIH0gR3JhZGllbnRTdG9wIHsgcG9zaXRpb246IDE7IGNvbG9yOiAiIzExMWEyOCIgfSB9CiAgICB9CiAgICBDb2x1'
    'bW5MYXlvdXQgewogICAgICAgIGlkOiBib2R5CiAgICAgICAgYW5jaG9ycyB7IGxlZnQ6IHBhcmVudC5sZWZ0OyByaWdodDog'
    'cGFyZW50LnJpZ2h0OyB0b3A6IHBhcmVudC50b3A7IG1hcmdpbnM6IDIwIH0KICAgICAgICBzcGFjaW5nOiAxNgogICAgICAg'
    'IFJvd0xheW91dCB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgQ29sdW1uTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgIHNwYWNpbmc6IDMKICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRVZHRU5JVU0iOyBjb2xvcjogIiNlZmY2ZmYiOyBmb250LnBpeGVsU2l6'
    'ZTogMTU7IGZvbnQubGV0dGVyU3BhY2luZzogMi40OyBmb250LmJvbGQ6IHRydWUgfQogICAgICAgICAgICAgICAgTXV0ZWQg'
    'eyB0ZXh0OiAiTkVUV09SSyAvIFZQTiI7IGZvbnQucGl4ZWxTaXplOiAxMDsgZm9udC5sZXR0ZXJTcGFjaW5nOiAxLjggfQog'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgIEMuVG9vbEJ1dHRvbiB7CiAgICAgICAgICAgICAgICB0ZXh0OiAiw5ciOyBmb250'
    'LnBpeGVsU2l6ZTogMjM7IHBhbGV0dGUuYnV0dG9uVGV4dDogIiM5YmFjYzEiCiAgICAgICAgICAgICAgICBBY2Nlc3NpYmxl'
    'Lm5hbWU6ICLQodC60YDRi9GC0Ywg0LLQuNC00LbQtdGCIgogICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LmhpZGUo'
    'KQogICAgICAgICAgICAgICAgdmlzaWJsZTogdHJheS5hdmFpbGFibGUKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAg'
    'ICBSZWN0YW5nbGUgewogICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgIGltcGxpY2l0SGVp'
    'Z2h0OiBoZXJvLmltcGxpY2l0SGVpZ2h0ICsgMzIKICAgICAgICAgICAgcmFkaXVzOiAxNjsgY29sb3I6ICIjMjQzNTQ4Ijsg'
    'Ym9yZGVyLmNvbG9yOiAiIzNiNTI2NiIKICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGlkOiBo'
    'ZXJvCiAgICAgICAgICAgICAgICBhbmNob3JzIHsgbGVmdDogcGFyZW50LmxlZnQ7IHJpZ2h0OiBwYXJlbnQucmlnaHQ7IHRv'
    'cDogcGFyZW50LnRvcDsgbWFyZ2luczogMTYgfQogICAgICAgICAgICAgICAgc3BhY2luZzogMTUKICAgICAgICAgICAgICAg'
    'IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDUyOyBpbXBsaWNpdEhlaWdo'
    'dDogNTI7IHJhZGl1czogMTY7IGNvbG9yOiAiIzFhMmEzOSIKICAgICAgICAgICAgICAgICAgICAgICAgSW1hZ2UgeyBhbmNo'
    'b3JzLmNlbnRlckluOiBwYXJlbnQ7IHdpZHRoOiAzNDsgaGVpZ2h0OiAzNDsgc291cmNlOiB0cmF5Lmljb24uc291cmNlIH0K'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgc3BhY2luZzogNQogICAgICAgICAgICAgICAgICAgICAgICBDLkxh'
    'YmVsIHsgdGV4dDogcm9vdC5zdGF0dXNUaXRsZTsgZm9udC5waXhlbFNpemU6IDIwOyBmb250LmJvbGQ6IHRydWU7IGNvbG9y'
    'OiAiI2VmZjZmZiIgfQogICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgUmVjdGFuZ2xlIHsgaW1wbGljaXRXaWR0aDogNjsgaW1wbGljaXRIZWlnaHQ6IDY7IHJhZGl1czogMzsgY29sb3I6'
    'IHJvb3QuYWNjZW50IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIE11dGVkIHsgdGV4dDogcm9vdC5jb25uZWN0ZWQg'
    'PyAi0JfQsNGJ0LjRidGR0L3QvdC+0LUg0L/QvtC00LrQu9GO0YfQtdC90LjQtSIgOiByb290LmNvbm5lY3RpbmcgPyAi0KHQ'
    'vtC30LTQsNGR0Lwg0LfQsNGJ0LjRidGR0L3QvdGL0Lkg0YLRg9C90L3QtdC70YwiIDogcm9vdC5zdGF0ZS5ndWFyZCA/ICLQ'
    'ntC20LjQtNCw0LXRgiDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNGPIiA6ICLQn9GA0Y/QvNC+0LUg0L/QvtC00LrQu9GO'
    '0YfQtdC90LjQtSI7IGNvbG9yOiByb290LmFjY2VudDsgZm9udC5waXhlbFNpemU6IDExIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'ewogICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXAKICAgICAg'
    'ICAgICAgICAgICAgICB0ZXh0OiByb290LnBvbGxFcnJvclRleHQgfHwgcm9vdC50dW5uZWwubWVzc2FnZSB8fCAocm9vdC5y'
    'ZWFkeSA/ICLQn9C+0LTQutC70Y7Rh9C40YLQtdGB0Ywg0L7QtNC90LjQvCDQvdCw0LbQsNGC0LjQtdC8LiIgOiAi0J/QvtC7'
    '0YPRh9Cw0LXQvCDRgdC+0YHRgtC+0Y/QvdC40LUg0L/QvtC00LrQu9GO0YfQtdC90LjRjy4iKQogICAgICAgICAgICAgICAg'
    'ICAgIGNvbG9yOiAiI2I3YzhkYSI7IGZvbnQucGl4ZWxTaXplOiAxMjsgbGluZUhlaWdodDogMS4yCiAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICBDLlByb2dyZXNzQmFyIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdmlzaWJsZTogcm9v'
    'dC5jb25uZWN0aW5nOyBmcm9tOiAwOyB0bzogMTAwOyB2YWx1ZTogTnVtYmVyKHJvb3QudHVubmVsLnByb2dyZXNzIHx8IDAp'
    'OyBwYWxldHRlLmhpZ2hsaWdodDogIiM3OWJhZmYiIH0KICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWU7IHNwYWNpbmc6IDMKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQy5MYWJlbCB7IHRleHQ6IHJvb3QuYnVzeSA/ICLQktGL0L/QvtC70L3Rj9C10LzigKYiIDogcm9vdC5lbmdhZ2Vk'
    'ID8gItCe0YLQutC70Y7Rh9C40YLRjCBWUE4iIDogItCf0L7QtNC60LvRjtGH0LjRgtGMIFZQTiI7IGNvbG9yOiAiI2VmZjZm'
    'ZiI7IGZvbnQuYm9sZDogdHJ1ZTsgZm9udC5waXhlbFNpemU6IDE0IH0KICAgICAgICAgICAgICAgICAgICAgICAgTXV0ZWQg'
    'eyB0ZXh0OiByb290LmVuZ2FnZWQgPyAi0JLQtdGB0Ywg0YLRgNCw0YTQuNC6INC/0L7QtCDQt9Cw0YnQuNGC0L7QuSDQv9GA'
    '0LDQstC40LsiIDogItCX0LDRidC40YLQsCDQuNC90YLQtdGA0L3QtdGCLdGB0L7QtdC00LjQvdC10L3QuNGPIjsgZm9udC5w'
    'aXhlbFNpemU6IDEwIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQy5Td2l0Y2ggewogICAg'
    'ICAgICAgICAgICAgICAgICAgICBpZDogdnBuU3dpdGNoCiAgICAgICAgICAgICAgICAgICAgICAgIGNoZWNrZWQ6IHJvb3Qu'
    'ZW5nYWdlZAogICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkOiByb290LnJlYWR5ICYmICFyb290LmJ1c3kgJiYgIXJv'
    'b3QucG9sbEVycm9yVGV4dCAmJiAocm9vdC5lbmdhZ2VkIHx8IHJvb3QudHVubmVsLmhhc190b2tlbikKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiByb290LmVuZ2FnZWQgPyAi0J7RgtC60LvRjtGH0LjRgtGMIFZQTiIgOiAi'
    '0J/QvtC00LrQu9GO0YfQuNGC0YwgVlBOIgogICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9u'
    'KHJvb3QuZW5nYWdlZCA/ICJkaXNjb25uZWN0IiA6ICJjb25uZWN0IikKICAgICAgICAgICAgICAgICAgICAgICAgaW5kaWNh'
    'dG9yOiBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRXaWR0aDogNTI7IGltcGxpY2l0'
    'SGVpZ2h0OiAzMDsgcmFkaXVzOiAxNQogICAgICAgICAgICAgICAgICAgICAgICAgICAgeDogdnBuU3dpdGNoLmxlZnRQYWRk'
    'aW5nOyB5OiAodnBuU3dpdGNoLmhlaWdodCAtIGhlaWdodCkgLyAyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xv'
    'cjogdnBuU3dpdGNoLmVuYWJsZWQgPyByb290LmVuZ2FnZWQgPyAiIzVjZTBiYyIgOiAiIzRhNWI3MCIgOiAiIzNhNDk1YiIK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7IHg6IHJvb3QuZW5nYWdlZCA/IDI1IDogNDsgeTogNDsg'
    'd2lkdGg6IDIyOyBoZWlnaHQ6IDIyOyByYWRpdXM6IDExOyBjb2xvcjogcm9vdC5lbmdhZ2VkID8gIiMxNTNhMzIiIDogIiNk'
    'Y2U2ZjIiOyBCZWhhdmlvciBvbiB4IHsgTnVtYmVyQW5pbWF0aW9uIHsgZHVyYXRpb246IDE2MCB9IH0gfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAg'
    'ICAgICAgfQogICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWU7IHNwYWNpbmc6'
    'IDgKICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgbW9kZWw6IFsi0JrQntCc0J/QrNCu0KLQldCgIiwg'
    'IkhTVkRTIiwgItCt0KHQotCe0J3QmNCvIl0KICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewogICAgICAg'
    'ICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHN0cmluZyBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICByZXF1'
    'aXJlZCBwcm9wZXJ0eSBpbnQgaW5kZXgKICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBzcGFj'
    'aW5nOiA1CiAgICAgICAgICAgICAgICAgICAgUmVjdGFuZ2xlIHsgaW1wbGljaXRXaWR0aDogNTsgaW1wbGljaXRIZWlnaHQ6'
    'IDU7IHJhZGl1czogMzsgY29sb3I6IHJvb3QuY29ubmVjdGVkID8gcm9vdC5hY2NlbnQgOiAiIzU5Njk3YyIgfQogICAgICAg'
    'ICAgICAgICAgICAgIE11dGVkIHsgdGV4dDogbW9kZWxEYXRhOyBmb250LnBpeGVsU2l6ZTogOTsgZm9udC5sZXR0ZXJTcGFj'
    'aW5nOiAwLjcgfQogICAgICAgICAgICAgICAgICAgIE11dGVkIHsgdmlzaWJsZTogaW5kZXggPCAyOyB0ZXh0OiAi4oaSIjsg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgaG9yaXpvbnRhbEFsaWdubWVudDogVGV4dC5BbGlnbkhDZW50ZXIgfQogICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIFJlY3RhbmdsZSB7IExheW91dC5maWxsV2lkdGg6'
    'IHRydWU7IGltcGxpY2l0SGVpZ2h0OiAxOyBjb2xvcjogIiMyZTNjNTAiIH0KICAgICAgICBSb3dMYXlvdXQgewogICAgICAg'
    'ICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBzcGFjaW5nOiA1CiAgICAgICAgICAgICAgICBNdXRlZCB7IHRleHQ6ICLQo9Ch0KLQ'
    'oNCe0JnQodCi0JLQniI7IGZvbnQucGl4ZWxTaXplOiA5OyBmb250LmxldHRlclNwYWNpbmc6IDEgfQogICAgICAgICAgICAg'
    'ICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHRleHQ6IHJvb3QudHVubmVsLmRldmljZV9uYW1lIHx8ICLQ'
    'rdGC0L7RgiDQutC+0LzQv9GM0Y7RgtC10YAiOyBjb2xvcjogIiNkY2U4ZjYiOyBmb250LnBpeGVsU2l6ZTogMTM7IGVsaWRl'
    'OiBUZXh0LkVsaWRlUmlnaHQgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgICAg'
    'ICBpbXBsaWNpdFdpZHRoOiBndWFyZExhYmVsLmltcGxpY2l0V2lkdGggKyAxODsgaW1wbGljaXRIZWlnaHQ6IDI3OyByYWRp'
    'dXM6IDgKICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnJlYWR5ICYmICFyb290LnBvbGxFcnJvclRleHQgJiYgcm9vdC5z'
    'dGF0ZS5ndWFyZCA/ICIjMWUzZDM4IiA6ICIjMjczMjQ2IgogICAgICAgICAgICAgICAgQy5MYWJlbCB7IGlkOiBndWFyZExh'
    'YmVsOyBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQ7IHRleHQ6ICFyb290LnJlYWR5IHx8IHJvb3QucG9sbEVycm9yVGV4dCA/'
    'ICLQl9Cw0YnQuNGC0LAgwrcgPyIgOiByb290LnN0YXRlLmd1YXJkID8gItCX0LDRidC40YLQsCDCtyDQstC60LsiIDogItCX'
    '0LDRidC40YLQsCDCtyDQstGL0LrQuyI7IGNvbG9yOiByb290LnJlYWR5ICYmICFyb290LnBvbGxFcnJvclRleHQgJiYgcm9v'
    'dC5zdGF0ZS5ndWFyZCA/ICIjNzlkOWJkIiA6ICIjYTliNmM5IjsgZm9udC5waXhlbFNpemU6IDExIH0KICAgICAgICAgICAg'
    'fQogICAgICAgIH0KICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdmlzaWJsZTogcm9vdC5lcnJv'
    'clRleHQubGVuZ3RoID4gMDsgdGV4dDogcm9vdC5lcnJvclRleHQ7IGNvbG9yOiAiI2ZmYmNhZCI7IHdyYXBNb2RlOiBUZXh0'
    'LldyYXA7IGZvbnQucGl4ZWxTaXplOiAxMjsgQWNjZXNzaWJsZS5yb2xlOiBBY2Nlc3NpYmxlLkFsZXJ0TWVzc2FnZSB9CiAg'
    'ICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHZpc2libGU6IHJvb3QucmVhZHkgJiYgIXJvb3QudHVu'
    'bmVsLmhhc190b2tlbjsgdGV4dDogItCU0L7QsdCw0LLRjNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsCDQsiDQvdCw'
    '0YHRgtGA0L7QudC60LDRhS4iOyBjb2xvcjogIiNmZmNkODciOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBmb250LnBpeGVsU2l6'
    'ZTogMTIgfQogICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWU7IHNwYWNpbmc6'
    'IDgKICAgICAgICAgICAgU21hbGxCdXR0b24geyB0ZXh0OiAi0J3QsNGB0YLRgNC+0LnQutC4IjsgZW5hYmxlZDogIXJvb3Qu'
    'YnVzeTsgb25DbGlja2VkOiByb290Lm9wZW5TZXR0aW5ncygpIH0KICAgICAgICAgICAgU21hbGxCdXR0b24geyB0ZXh0OiBy'
    'b290LnBvbGxFcnJvclRleHQgPyAi0J7QsdC90L7QstC40YLRjCIgOiAi0JLQvtGB0YHRgtCw0L3QvtCy0LjRgtGMIjsgZW5h'
    'YmxlZDogIXJvb3QuYnVzeSAmJiAoQm9vbGVhbihyb290LnBvbGxFcnJvclRleHQpIHx8IChyb290LnJlYWR5ICYmIHJvb3Qu'
    'dHVubmVsLmhhc190b2tlbiAmJiAhcm9vdC5jb25uZWN0aW5nKSk7IG9uQ2xpY2tlZDogcm9vdC5wb2xsRXJyb3JUZXh0ID8g'
    'cm9vdC5yZWZyZXNoU3RhdGUoKSA6IHJvb3QuYWN0aW9uKCJyZXBhaXIiKSB9CiAgICAgICAgfQogICAgICAgIFJvd0xheW91'
    'dCB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgTXV0ZWQgeyB0ZXh0OiAiRXZnZW5p'
    'dW0gIiArIFN0cmluZyhyb290LnN0YXRlLm1hbmFnZXJfdmVyc2lvbiB8fCAiIik7IGZvbnQucGl4ZWxTaXplOiAxMDsgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZSB9CiAgICAgICAgICAgIE11dGVkIHsgdGV4dDogItCe0LHQvdC+0LLQu9GP0LXRgtGB0Y8g'
    '0YfQtdGA0LXQtyB2cG4gdXBkYXRlIjsgZm9udC5waXhlbFNpemU6IDEwIH0KICAgICAgICB9CiAgICB9CiAgICB9Cn0K'
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
    'ZQogICAgcHJvcGVydHkgYm9vbCBkZXZpY2VFZGl0aW5nOiBmYWxzZQogICAgcmVhZG9ubHkgcHJvcGVydHkgYm9vbCB0b2tl'
    'blNhdmVkOiBCb29sZWFuKHJvb3QudHVubmVsLmhhc190b2tlbikKICAgIHJlYWRvbmx5IHByb3BlcnR5IGJvb2wgdG9rZW5M'
    'b2NrZWQ6IHRva2VuU2F2ZWQgJiYgIXRva2VuRWRpdGluZwogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIHR1bm5lbDogcm9v'
    'dC5zdGF0ZS50dW5uZWwgfHwgKHt9KQogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIHBvbGljeTogcm9vdC5zdGF0ZS5wb2xp'
    'Y3kgfHwgKHt9KQogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGNhdGVnb3J5OiBbIiIsICJhcHBsaWNhdGlvbnMiLCAi'
    'bmV0d29ya3MiLCAicG9ydHMiLCAiZG5zIiwgIiJdW3BhZ2VJbmRleF0KICAgIHByb3BlcnR5IGJvb2wgc2hvd0Jhc2U6IGZh'
    'bHNlCgogICAgcmVhZG9ubHkgcHJvcGVydHkgdmFyIGFyZ3M6IFF0LmFwcGxpY2F0aW9uLmFyZ3VtZW50cwogICAgcmVhZG9u'
    'bHkgcHJvcGVydHkgc3RyaW5nIGFwaVRva2VuOiBhcmdzLmxlbmd0aCA+PSAyID8gU3RyaW5nKGFyZ3NbYXJncy5sZW5ndGgg'
    'LSAxXSkgOiAiIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaVBvcnQ6IGFyZ3MubGVuZ3RoID49IDMgPyBTdHJp'
    'bmcoYXJnc1thcmdzLmxlbmd0aCAtIDJdKSA6ICIwIgogICAgcmVhZG9ubHkgcHJvcGVydHkgc3RyaW5nIGFwaUJhc2U6ICJo'
    'dHRwOi8vMTI3LjAuMC4xOiIgKyBhcGlQb3J0CgogICAgcHJvcGVydHkgYm9vbCBzdGF0ZVBlbmRpbmc6IGZhbHNlCiAgICBw'
    'cm9wZXJ0eSBib29sIHJ1bm5pbmdQZW5kaW5nOiBmYWxzZQoKICAgIGZ1bmN0aW9uIGFwaShtZXRob2QsIHBhdGgsIGJvZHks'
    'IGNhbGxiYWNrLCBvcGVyYXRpb24pIHsKICAgICAgICBjb25zdCB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKQogICAgICAg'
    'IGxldCBmaW5pc2hlZCA9IGZhbHNlCiAgICAgICAgY29uc3QgdGltZXIgPSByZXF1ZXN0VGltZXIuY3JlYXRlT2JqZWN0KHJv'
    'b3QpCiAgICAgICAgZnVuY3Rpb24gZmluaXNoKGVycm9yLCBwYXlsb2FkKSB7CiAgICAgICAgICAgIGlmIChmaW5pc2hlZCkK'
    'ICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBmaW5pc2hlZCA9IHRydWUKICAgICAgICAgICAgdGltZXIuc3Rv'
    'cCgpCiAgICAgICAgICAgIHRpbWVyLmRlc3Ryb3koKQogICAgICAgICAgICBpZiAocGF0aCA9PT0gIi9hcGkvc3RhdGUiKSBy'
    'b290LnN0YXRlUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChwYXRoID09PSAiL2FwaS9ydW5uaW5nIikgcm9vdC5y'
    'dW5uaW5nUGVuZGluZyA9IGZhbHNlCiAgICAgICAgICAgIGlmIChvcGVyYXRpb24pIHsKICAgICAgICAgICAgICAgIHJvb3Qu'
    'YnVzeSA9IGZhbHNlCiAgICAgICAgICAgICAgICByb290LmVycm9yVGV4dCA9IGVycm9yIHx8ICIiCiAgICAgICAgICAgIH0g'
    'ZWxzZSB7CiAgICAgICAgICAgICAgICByb290LnBvbGxFcnJvclRleHQgPSBlcnJvciB8fCAiIgogICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgIGlmICghZXJyb3IgJiYgY2FsbGJhY2spIGNhbGxiYWNrKHBheWxvYWQpCiAgICAgICAgfQogICAgICAgIHRp'
    'bWVyLmludGVydmFsID0gb3BlcmF0aW9uID8gNzgwMDAwIDogMTIwMDAKICAgICAgICB0aW1lci50cmlnZ2VyZWQuY29ubmVj'
    'dChmdW5jdGlvbigpIHsKICAgICAgICAgICAgZmluaXNoKG9wZXJhdGlvbiA/ICLQntGC0LLQtdGCINC+0L/QtdGA0LDRhtC4'
    '0Lgg0L3QtSDQv9C+0LvRg9GH0LXQvS4g0J/RgNC+0LLQtdGA0YwgdnBuIHN0YXR1cyDQv9C10YDQtdC0INC/0L7QstGC0L7R'
    'gNC90YvQvCDQv9C10YDQtdC60LvRjtGH0LXQvdC40LXQvC4iIDogItCe0L/RgNC+0YEg0YHQvtGB0YLQvtGP0L3QuNGPINC9'
    '0LUg0LfQsNCy0LXRgNGI0LjQu9GB0Y8iLCBudWxsKQogICAgICAgICAgICB4aHIuYWJvcnQoKQogICAgICAgIH0pCiAgICAg'
    'ICAgeGhyLm9wZW4obWV0aG9kLCBhcGlCYXNlICsgcGF0aCwgdHJ1ZSkKICAgICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcigi'
    'WC1Fdmdlbml1bS1Ub2tlbiIsIGFwaVRva2VuKQogICAgICAgIGlmIChib2R5ICE9PSBudWxsKQogICAgICAgICAgICB4aHIu'
    'c2V0UmVxdWVzdEhlYWRlcigiQ29udGVudC1UeXBlIiwgImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgiKQogICAg'
    'ICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHsKICAgICAgICAgICAgaWYgKHhoci5yZWFkeVN0YXRl'
    'ICE9PSBYTUxIdHRwUmVxdWVzdC5ET05FIHx8IGZpbmlzaGVkKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAg'
    'IGxldCBwYXlsb2FkID0gbnVsbAogICAgICAgICAgICB0cnkgeyBwYXlsb2FkID0gSlNPTi5wYXJzZShTdHJpbmcoeGhyLnJl'
    'c3BvbnNlVGV4dCB8fCAie30iKSkgfQogICAgICAgICAgICBjYXRjaCAoZSkgeyBmaW5pc2goItCd0LUg0YPQtNCw0LvQvtGB'
    '0Ywg0YDQsNC30L7QsdGA0LDRgtGMINC+0YLQstC10YIg0LvQvtC60LDQu9GM0L3QvtCz0L4gQVBJIiwgbnVsbCk7IHJldHVy'
    'biB9CiAgICAgICAgICAgIGlmICh4aHIuc3RhdHVzIDwgMjAwIHx8IHhoci5zdGF0dXMgPj0gMzAwIHx8ICFwYXlsb2FkLm9r'
    'KSB7CiAgICAgICAgICAgICAgICBmaW5pc2goU3RyaW5nKHBheWxvYWQuZXJyb3IgfHwgKCJIVFRQICIgKyB4aHIuc3RhdHVz'
    'KSksIG51bGwpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgfQogICAgICAgICAgICBmaW5pc2gobnVsbCwg'
    'cGF5bG9hZCkKICAgICAgICB9CiAgICAgICAgdGltZXIuc3RhcnQoKQogICAgICAgIHhoci5zZW5kKGJvZHkgPT09IG51bGwg'
    'PyBudWxsIDogSlNPTi5zdHJpbmdpZnkoYm9keSkpCiAgICB9CgogICAgQ29tcG9uZW50IHsKICAgICAgICBpZDogcmVxdWVz'
    'dFRpbWVyCiAgICAgICAgVGltZXIgeyByZXBlYXQ6IGZhbHNlIH0KICAgIH0KCiAgICBmdW5jdGlvbiByZWZyZXNoU3RhdGUo'
    'KSB7CiAgICAgICAgaWYgKHN0YXRlUGVuZGluZykgcmV0dXJuCiAgICAgICAgc3RhdGVQZW5kaW5nID0gdHJ1ZQogICAgICAg'
    'IGFwaSgiR0VUIiwgIi9hcGkvc3RhdGUiLCBudWxsLCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3Quc3Rh'
    'dGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAgICB9KQogICAgfQoKICAgIGZ1bmN0aW9uIHJlZnJlc2hSdW5uaW5n'
    'KCkgewogICAgICAgIGlmIChydW5uaW5nUGVuZGluZykgcmV0dXJuCiAgICAgICAgcnVubmluZ1BlbmRpbmcgPSB0cnVlCiAg'
    'ICAgICAgYXBpKCJHRVQiLCAiL2FwaS9ydW5uaW5nIiwgbnVsbCwgZnVuY3Rpb24ocGF5bG9hZCkgewogICAgICAgICAgICBy'
    'b290LnJ1bm5pbmdBcHBzID0gKHBheWxvYWQucnVubmluZyAmJiBwYXlsb2FkLnJ1bm5pbmcuYXBwbGljYXRpb25zKSB8fCBb'
    'XQogICAgICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gYWN0aW9uKHBheWxvYWQsIG9uU3VjY2VzcykgewogICAgICAgIGlm'
    'IChidXN5IHx8IChCb29sZWFuKHN0YXRlLmNvbm5lY3RpbmcpICYmIHBheWxvYWQuYWN0aW9uICE9PSAiZGlzY29ubmVjdCIp'
    'KQogICAgICAgICAgICByZXR1cm4KICAgICAgICBidXN5ID0gdHJ1ZQogICAgICAgIGFwaSgiUE9TVCIsICIvYXBpL2FjdGlv'
    'biIsIHBheWxvYWQsIGZ1bmN0aW9uKF9yZXBseSkgewogICAgICAgICAgICByb290LmJ1c3kgPSBmYWxzZQogICAgICAgICAg'
    'ICBpZiAoX3JlcGx5LnN0YXRlKSByb290LnN0YXRlID0gX3JlcGx5LnN0YXRlCiAgICAgICAgICAgIGlmIChvblN1Y2Nlc3Mp'
    'IG9uU3VjY2VzcygpCiAgICAgICAgICAgIHJvb3QucmVmcmVzaFN0YXRlKCkKICAgICAgICAgICAgcm9vdC5yZWZyZXNoUnVu'
    'bmluZygpCiAgICAgICAgfSwgdHJ1ZSkKICAgIH0KCiAgICBmdW5jdGlvbiB0b2dnbGVWcG4oKSB7CiAgICAgICAgaWYgKGJ1'
    'c3kgfHwgQm9vbGVhbihzdGF0ZS5jb25uZWN0aW5nKSkKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgYnVzeSA9IHRydWUK'
    'ICAgICAgICBhcGkoIlBPU1QiLCAiL2FwaS90b2dnbGUiLCB7fSwgZnVuY3Rpb24ocGF5bG9hZCkgewogICAgICAgICAgICBy'
    'b290LmJ1c3kgPSBmYWxzZQogICAgICAgICAgICByb290LnN0YXRlID0gcGF5bG9hZC5zdGF0ZSB8fCAoe30pCiAgICAgICAg'
    'fSwgdHJ1ZSkKICAgIH0KCiAgICBmdW5jdGlvbiBmaWx0ZXJlZFJ1bm5pbmcoKSB7CiAgICAgICAgY29uc3QgbmVlZGxlID0g'
    'YXBwU2VhcmNoLnRleHQudHJpbSgpLnRvTG93ZXJDYXNlKCkKICAgICAgICBpZiAoIW5lZWRsZS5sZW5ndGgpCiAgICAgICAg'
    'ICAgIHJldHVybiBydW5uaW5nQXBwcwogICAgICAgIHJldHVybiBydW5uaW5nQXBwcy5maWx0ZXIoZnVuY3Rpb24oYXBwKSB7'
    'CiAgICAgICAgICAgIHJldHVybiBTdHJpbmcoYXBwLm5hbWUgfHwgIiIpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMobmVlZGxl'
    'KQogICAgICAgICAgICAgICAgfHwgU3RyaW5nKGFwcC5leGUgfHwgIiIpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMobmVlZGxl'
    'KQogICAgICAgIH0pCiAgICB9CgogICAgQ29tcG9uZW50Lm9uQ29tcGxldGVkOiB7CiAgICAgICAgcmVmcmVzaFN0YXRlKCkK'
    'ICAgICAgICByZWZyZXNoUnVubmluZygpCiAgICB9CgogICAgVGltZXIgewogICAgICAgIGludGVydmFsOiAyNTAwCiAgICAg'
    'ICAgcmVwZWF0OiB0cnVlCiAgICAgICAgcnVubmluZzogdHJ1ZQogICAgICAgIG9uVHJpZ2dlcmVkOiByb290LnJlZnJlc2hT'
    'dGF0ZSgpCiAgICB9CgogICAgY29tcG9uZW50IEZsYXRCdXR0b246IFJlY3RhbmdsZSB7CiAgICAgICAgaWQ6IGZsYXRCdXR0'
    'b24KICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbGFiZWwKICAgICAgICBwcm9wZXJ0eSBib29sIHByaW1hcnk6'
    'IGZhbHNlCiAgICAgICAgcHJvcGVydHkgYm9vbCBkYW5nZXI6IGZhbHNlCiAgICAgICAgcHJvcGVydHkgYm9vbCBlbmFibGVk'
    'QnV0dG9uOiB0cnVlCiAgICAgICAgc2lnbmFsIGNsaWNrZWQoKQogICAgICAgIGltcGxpY2l0SGVpZ2h0OiAzOAogICAgICAg'
    'IGltcGxpY2l0V2lkdGg6IE1hdGgubWF4KDkyLCBidXR0b25UZXh0LmltcGxpY2l0V2lkdGggKyAyOCkKICAgICAgICByYWRp'
    'dXM6IDEwCiAgICAgICAgY29sb3I6ICFlbmFibGVkQnV0dG9uID8gIiNlZWYwZjMiCiAgICAgICAgICAgICAgOiBkYW5nZXIg'
    'PyAoYnV0dG9uTW91c2UuY29udGFpbnNNb3VzZSA/ICIjZmVlMmUyIiA6ICIjZmVmMmYyIikKICAgICAgICAgICAgICA6IHBy'
    'aW1hcnkgPyAoYnV0dG9uTW91c2UuY29udGFpbnNNb3VzZSA/ICIjMjA5OWRjIiA6IHJvb3QuYWNjZW50KQogICAgICAgICAg'
    'ICAgIDogKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiI2VlZjJmNyIgOiAiI2Y3ZjlmYyIpCiAgICAgICAgYm9yZGVy'
    'LndpZHRoOiBwcmltYXJ5ID8gMCA6IDEKICAgICAgICBib3JkZXIuY29sb3I6IGRhbmdlciA/ICIjZmVjYWNhIiA6IHJvb3Qu'
    'Ym9yZGVyCiAgICAgICAgb3BhY2l0eTogZW5hYmxlZEJ1dHRvbiA/IDEgOiAwLjYKCiAgICAgICAgQy5MYWJlbCB7CiAgICAg'
    'ICAgICAgIGlkOiBidXR0b25UZXh0CiAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAogICAgICAgICAgICB0'
    'ZXh0OiBmbGF0QnV0dG9uLmxhYmVsCiAgICAgICAgICAgIGNvbG9yOiBmbGF0QnV0dG9uLnByaW1hcnkgPyAid2hpdGUiIDog'
    'KGZsYXRCdXR0b24uZGFuZ2VyID8gcm9vdC5iYWQgOiByb290LnRleHRNYWluKQogICAgICAgICAgICBmb250LnBpeGVsU2l6'
    'ZTogMTMKICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICB9CiAgICAgICAgTW91c2VBcmVh'
    'IHsKICAgICAgICAgICAgaWQ6IGJ1dHRvbk1vdXNlCiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAg'
    'ICAgIGVuYWJsZWQ6IGZsYXRCdXR0b24uZW5hYmxlZEJ1dHRvbgogICAgICAgICAgICBob3ZlckVuYWJsZWQ6IHRydWUKICAg'
    'ICAgICAgICAgY3Vyc29yU2hhcGU6IGVuYWJsZWQgPyBRdC5Qb2ludGluZ0hhbmRDdXJzb3IgOiBRdC5BcnJvd0N1cnNvcgog'
    'ICAgICAgICAgICBvbkNsaWNrZWQ6IGZsYXRCdXR0b24uY2xpY2tlZCgpCiAgICAgICAgfQogICAgfQoKICAgIGNvbXBvbmVu'
    'dCBOYXZCdXR0b246IFJlY3RhbmdsZSB7CiAgICAgICAgaWQ6IG5hdgogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHN0cmlu'
    'ZyBsYWJlbAogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IGludCBpbmRleAogICAgICAgIHByb3BlcnR5IHN0cmluZyBzaG9y'
    'dExhYmVsOiAiIgogICAgICAgIHNpZ25hbCBjbGlja2VkKCkKICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgaW1wbGljaXRXaWR0aDogMTg2CiAgICAgICAgaGVpZ2h0OiA0OAogICAgICAgIHJhZGl1czogMTEKICAgICAgICBjb2xv'
    'cjogcm9vdC5wYWdlSW5kZXggPT09IGluZGV4ID8gIiMyNTMyNDYiIDogKG5hdk1vdXNlLmNvbnRhaW5zTW91c2UgPyByb290'
    'LnNpZGViYXJIb3ZlciA6ICJ0cmFuc3BhcmVudCIpCgogICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgIGFuY2hvcnMu'
    'ZmlsbDogcGFyZW50CiAgICAgICAgICAgIGFuY2hvcnMubGVmdE1hcmdpbjogMTIKICAgICAgICAgICAgYW5jaG9ycy5yaWdo'
    'dE1hcmdpbjogMTIKICAgICAgICAgICAgc3BhY2luZzogMTEKICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAg'
    'ICAgIGltcGxpY2l0V2lkdGg6IDI4CiAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogMjgKICAgICAgICAgICAgICAg'
    'IHJhZGl1czogOAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyByb290LmFj'
    'Y2VudCA6ICIjMjczNDQ5IgogICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5j'
    'ZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgdGV4dDogbmF2LnNob3J0TGFiZWwKICAgICAgICAgICAgICAg'
    'ICAgICBjb2xvcjogIndoaXRlIgogICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMAogICAgICAgICAgICAg'
    'ICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgIHRleHQ6'
    'IG5hdi5sYWJlbAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyAid2hpdGUi'
    'IDogIiNjYmQ1ZTEiCiAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAgICAgICAgIGZvbnQud2Vp'
    'Z2h0OiByb290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gRm9udC5EZW1pQm9sZCA6IEZvbnQuTm9ybWFsCiAgICAgICAg'
    'ICAgIH0KICAgICAgICB9CiAgICAgICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IG5hdk1vdXNlCiAgICAgICAgICAg'
    'IGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JT'
    'aGFwZTogUXQuUG9pbnRpbmdIYW5kQ3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgcm9v'
    'dC5wYWdlSW5kZXggPSBuYXYuaW5kZXgKICAgICAgICAgICAgICAgIG5hdi5jbGlja2VkKCkKICAgICAgICAgICAgfQogICAg'
    'ICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgQ2FyZDogUmVjdGFuZ2xlIHsKICAgICAgICByYWRpdXM6IDE2CiAgICAgICAg'
    'Y29sb3I6IHJvb3Quc3VyZmFjZQogICAgICAgIGJvcmRlci53aWR0aDogMQogICAgICAgIGJvcmRlci5jb2xvcjogcm9vdC5i'
    'b3JkZXIKICAgIH0KCiAgICBSb3dMYXlvdXQgewogICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgc3BhY2lu'
    'ZzogMAogICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgIExheW91dC5wcmVmZXJyZWRXaWR0aDogMjIyCiAgICAgICAg'
    'ICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgIGNvbG9yOiByb290LnNpZGViYXIKICAgICAgICAgICAg'
    'Q29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLm1hcmdpbnM6IDE4CiAgICAgICAgICAgICAgICBzcGFjaW5nOiA4CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4'
    'dDogIkV2Z2VuaXVtIjsgY29sb3I6ICJ3aGl0ZSI7IGZvbnQucGl4ZWxTaXplOiAyMzsgZm9udC5ib2xkOiB0cnVlOyBMYXlv'
    'dXQudG9wTWFyZ2luOiAxMiB9CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIk5ldHdvcmsiOyBjb2xvcjogIiM5'
    'NGEzYjgiOyBMYXlvdXQuYm90dG9tTWFyZ2luOiAyOCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogIlZQ'
    'TiI7IHNob3J0TGFiZWw6ICJWUE4iOyBpbmRleDogMCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCf'
    '0YDQuNC70L7QttC10L3QuNGPIjsgc2hvcnRMYWJlbDogIkFQUCI7IGluZGV4OiAxOyBvbkNsaWNrZWQ6IHJvb3QucmVmcmVz'
    'aFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCh0LDQudGC0Ysg0LggSVAiOyBzaG9y'
    'dExhYmVsOiAiTkVUIjsgaW5kZXg6IDIgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6ICLQn9C+0YDRgtGL'
    'Ijsgc2hvcnRMYWJlbDogIlBSVCI7IGluZGV4OiAzIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAiRE5T'
    'Ijsgc2hvcnRMYWJlbDogIkROUyI7IGluZGV4OiA0IH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAiV2F5'
    'ZHJvaWQiOyBzaG9ydExhYmVsOiAiV0FZIjsgaW5kZXg6IDUgfQogICAgICAgICAgICAgICAgSXRlbSB7IExheW91dC5maWxs'
    'SGVpZ2h0OiB0cnVlIH0KICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiByb290LnN0YXRlLmFjdGl2ZSA/ICLil48g'
    '0J/QvtC00LrQu9GO0YfQtdC90L4iIDogKHJvb3Quc3RhdGUuZ3VhcmQgPyAi4pePINCX0LDRidC40YLQsCDQstC60LvRjtGH'
    '0LXQvdCwIiA6ICLil4sg0J7RgtC60LvRjtGH0LXQvdC+Iik7IGNvbG9yOiByb290LnN0YXRlLmFjdGl2ZSA/ICIjNGFkZTgw'
    'IiA6ICIjY2JkNWUxIiB9CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCS0LXRgNGB0LjRjyAiICsgKHJvb3Qu'
    'c3RhdGUubWFuYWdlcl92ZXJzaW9uIHx8ICLigKYiKTsgY29sb3I6ICIjOTRhM2I4IjsgZm9udC5waXhlbFNpemU6IDEyIH0K'
    'ICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgIExheW91dC5tYXJnaW5z'
    'OiAyOAogICAgICAgICAgICBzcGFjaW5nOiAxNgogICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogWyLQktCw0YggVlBOIiwg'
    'ItCY0YHQutC70Y7Rh9C10L3QuNGPINC/0YDQuNC70L7QttC10L3QuNC5IiwgItCh0LDQudGC0Ysg0LggSVAiLCAi0JjRgdC6'
    '0LvRjtGH0LXQvdC40Y8g0L/QvtGA0YLQvtCyIiwgIkROUyIsICJXYXlkcm9pZCJdW3Jvb3QucGFnZUluZGV4XTsgY29sb3I6'
    'IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAyNzsgZm9udC5ib2xkOiB0cnVlIH0KICAgICAgICAgICAgQy5MYWJl'
    'bCB7CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICB2aXNpYmxlOiBCb29s'
    'ZWFuKHJvb3QuZXJyb3JUZXh0IHx8IHJvb3QucG9sbEVycm9yVGV4dCkKICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QuZXJy'
    'b3JUZXh0IHx8IHJvb3QucG9sbEVycm9yVGV4dAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYmFkCiAgICAgICAgICAg'
    'ICAgICB3cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5CdXN5SW5kaWNhdG9yIHsgcnVu'
    'bmluZzogcm9vdC5idXN5OyB2aXNpYmxlOiBydW5uaW5nOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAyOCB9CiAgICAgICAg'
    'ICAgIEMuU2Nyb2xsVmlldyB7CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgY29u'
    'dGVudFdpZHRoOiBhdmFpbGFibGVXaWR0aAogICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICB3aWR0aDogcGFyZW50LndpZHRoCiAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgKICAgICAgICAgICAgICAg'
    'ICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0g'
    'MAogICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAg'
    'IHNwYWNpbmc6IDE4CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'dmlzaWJsZTogcm9vdC50b2tlblNhdmVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogZGV2aWNlQm9keS5pbXBsaWNpdEhlaWdo'
    'dCArIDMyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGlkOiBkZXZpY2VCb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBw'
    'YXJlbnQ7IGFuY2hvcnMubWFyZ2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNpYmxlOiAhcm9vdC5kZXZpY2VFZGl0aW5nOyB0ZXh0OiByb290'
    'LnR1bm5lbC5kZXZpY2VfbmFtZSB8fCAi0J/QvtC70YPRh9Cw0Y4g0LjQvNGPINGD0YHRgtGA0L7QudGB0YLQstCw4oCmIjsg'
    'Zm9udC5waXhlbFNpemU6IDE4OyBmb250LmJvbGQ6IHRydWU7IGNvbG9yOiByb290LnRleHRNYWluOyBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlOyBlbGlkZTogVGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5UZXh0RmllbGQgeyBpZDogZGV2aWNlTmFtZUlucHV0OyB2aXNpYmxlOiByb290LmRldmljZUVkaXRpbmc7IExheW91dC5m'
    'aWxsV2lkdGg6IHRydWU7IG1heGltdW1MZW5ndGg6IDY0OyBwbGFjZWhvbGRlclRleHQ6ICLQmNC80Y8g0YPRgdGC0YDQvtC5'
    '0YHRgtCy0LAiOyBzZWxlY3RCeU1vdXNlOiB0cnVlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxh'
    'dEJ1dHRvbiB7IGxhYmVsOiByb290LmRldmljZUVkaXRpbmcgPyAi0KHQvtGF0YDQsNC90LjRgtGMIiA6ICLQmNC30LzQtdC9'
    '0LjRgtGMINC40LzRjyI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZyAmJiAo'
    'IXJvb3QuZGV2aWNlRWRpdGluZyB8fCBkZXZpY2VOYW1lSW5wdXQudGV4dC50cmltKCkubGVuZ3RoID4gMCk7IG9uQ2xpY2tl'
    'ZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFyb290LmRldmljZUVkaXRpbmcpIHsg'
    'ZGV2aWNlTmFtZUlucHV0LnRleHQ9cm9vdC50dW5uZWwuZGV2aWNlX25hbWUgfHwgIiI7IHJvb3QuZGV2aWNlRWRpdGluZz10'
    'cnVlOyBkZXZpY2VOYW1lSW5wdXQuZm9yY2VBY3RpdmVGb2N1cygpIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGVsc2Ugcm9vdC5hY3Rpb24oe2FjdGlvbjoiZGV2aWNlLW5hbWUiLG5hbWU6ZGV2aWNlTmFtZUlucHV0LnRl'
    'eHQudHJpbSgpfSxmdW5jdGlvbigpe3Jvb3QuZGV2aWNlRWRpdGluZz1mYWxzZX0pCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgdmlzaWJs'
    'ZTogcm9vdC5kZXZpY2VFZGl0aW5nOyBsYWJlbDogItCe0YLQvNC10L3QsCI7IG9uQ2xpY2tlZDogcm9vdC5kZXZpY2VFZGl0'
    'aW5nPWZhbHNlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQy5MYWJlbCB7IHRleHQ6IHJvb3QudHVubmVsLmRldmljZV9uYW1lX3BlbmRpbmcgPyAi0JjQvNGPINGB0L7RhdGA'
    '0LDQvdC10L3QviDQvdCwINC60L7QvNC/0YzRjtGC0LXRgNC1INC4INCx0YPQtNC10YIg0L7RgtC/0YDQsNCy0LvQtdC90L4g'
    '0L/RgNC4INC/0L7QtNC60LvRjtGH0LXQvdC40LguIiA6ICLQrdGC0L4g0LjQvNGPINCy0LjQtNC90L4g0LIg0LLQtdCxLdC/'
    '0LDQvdC10LvQuCDRgdGA0LXQtNC4INCy0LDRiNC40YUg0L/QvtC00LrQu9GO0YfQtdC90LjQuS4iOyBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgaW1wbGljaXRIZWlnaHQ6IGNvbm5lY3Rpb25Cb2R5LmltcGxpY2l0SGVpZ2h0ICsgNDAKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGNvbm5lY3Rp'
    'b25Cb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDIwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'c3BhY2luZzogMTUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogcm9vdC5zdGF0ZS5h'
    'Y3RpdmUgPyAi0J/QvtC00LrQu9GO0YfQtdC90L4g0YfQtdGA0LXQtyDQrdGB0YLQvtC90LjRjiIgOiAocm9vdC50dW5uZWwu'
    'cnVubmluZyA/ICLQn9C+0LTQutC70Y7Rh9C10L3QuNC14oCmIiA6ICLQk9C+0YLQvtCyINC6INC/0L7QtNC60LvRjtGH0LXQ'
    'vdC40Y4iKTsgY29sb3I6IHJvb3Quc3RhdGUuYWN0aXZlID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhl'
    'bFNpemU6IDIxOyBmb250LmJvbGQ6IHRydWUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0'
    'ZXh0OiByb290LnR1bm5lbC5tZXNzYWdlIHx8ICLQktCy0LXQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCwIjsg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlByb2dyZXNzQmFyIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgdmlz'
    'aWJsZTogQm9vbGVhbihyb290LnR1bm5lbC5ydW5uaW5nKSAmJiAhcm9vdC5zdGF0ZS5hY3RpdmU7IGZyb206IDA7IHRvOiAx'
    'MDA7IHZhbHVlOiBOdW1iZXIocm9vdC50dW5uZWwucHJvZ3Jlc3MgfHwgMCkgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJl'
    'bDogcm9vdC50dW5uZWwucnVubmluZyB8fCByb290LnN0YXRlLmd1YXJkID8gItCe0YLQutC70Y7Rh9C40YLRjCIgOiAi0J/Q'
    'vtC00LrQu9GO0YfQuNGC0YwiOyBwcmltYXJ5OiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIChyb290LnRv'
    'a2VuU2F2ZWQgfHwgcm9vdC5zdGF0ZS5ndWFyZCk7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogcm9vdC50dW5u'
    'ZWwucnVubmluZyB8fCByb290LnN0YXRlLmd1YXJkID8gImRpc2Nvbm5lY3QiIDogImNvbm5lY3QifSkgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQktC+0YHRgdGC0LDQvdC+0LLQuNGC0Ywi'
    'OyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFyb290LnN0YXRlLmNvbm5lY3RpbmcgJiYgcm9vdC50b2tlblNhdmVk'
    'OyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJyZXBhaXIifSkgfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCS0LXRgdGMINGC0YDQ'
    'sNGE0LjQuiDQuNC00ZHRgiDRh9C10YDQtdC3IFZQTiwg0LrRgNC+0LzQtSDQstC60LvRjtGH0ZHQvdC90YvRhSDQuNGB0LrQ'
    'u9GO0YfQtdC90LjQuS4g0J/RgNC4INC+0LHRgNGL0LLQtSDQt9Cw0YnQuNGJ0ZHQvdC90YvQtSDQv9C+0LTQutC70Y7Rh9C1'
    '0L3QuNGPINCx0LvQvtC60LjRgNGD0Y7RgtGB0Y8uIjsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQu'
    'V3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0SGVpZ2h0OiB0b2tl'
    'bkJvZHkuaW1wbGljaXRIZWlnaHQgKyA0MAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogdG9rZW5Cb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6'
    'IDIwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTIKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCi0L7QutC10L0g0LrQu9C40LXQvdGC0LAiOyBmb250LnBpeGVsU2l6ZTogMTc7'
    'IGZvbnQuYm9sZDogdHJ1ZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgeyB2aXNpYmxlOiByb290LnRva2VuTG9ja2VkOyB0ZXh0OiByb290LnR1bm5lbC50b2tlbl9oaW50IHx8ICLQ'
    'otC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxs'
    'V2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgeyBpZDogdG9rZW5J'
    'bnB1dDsgdmlzaWJsZTogIXJvb3QudG9rZW5Mb2NrZWQ7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHBsYWNlaG9sZGVyVGV4'
    'dDogIkVWTjEt4oCmIjsgZWNob01vZGU6IFRleHRJbnB1dC5QYXNzd29yZDsgc2VsZWN0QnlNb3VzZTogdHJ1ZTsgZW5hYmxl'
    'ZDogIXJvb3QuYnVzeSAmJiAhcm9vdC50dW5uZWwucnVubmluZyB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEZsYXRCdXR0b24geyBsYWJlbDogcm9vdC50b2tlbkxvY2tlZCA/ICLQmNC30LzQtdC90LjRgtGMIiA6ICLQn9C+0LTR'
    'gtCy0LXRgNC00LjRgtGMIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhcm9vdC50dW5uZWwucnVubmluZyAmJiAo'
    'cm9vdC50b2tlbkxvY2tlZCB8fCAvXkVWTjEtW0EtWmEtejAtOV8tXXs0M30kLy50ZXN0KHRva2VuSW5wdXQudGV4dC50cmlt'
    'KCkpKTsgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAocm9vdC50b2tl'
    'bkxvY2tlZCkgcm9vdC50b2tlbkVkaXRpbmcgPSB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBlbHNlIHJvb3QuYWN0aW9uKHthY3Rpb246ICJ0b2tlbi1zYXZlIiwgdG9rZW46IHRva2VuSW5wdXQudGV4dC50cmltKCl9'
    'LCBmdW5jdGlvbigpIHsgdG9rZW5JbnB1dC5jbGVhcigpOyByb290LnRva2VuRWRpdGluZyA9IGZhbHNlIH0pCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0'
    'QnV0dG9uIHsgdmlzaWJsZTogcm9vdC50b2tlbkVkaXRpbmc7IGxhYmVsOiAi0J7RgtC80LXQvdCwIjsgb25DbGlja2VkOiB7'
    'IHRva2VuSW5wdXQuY2xlYXIoKTsgcm9vdC50b2tlbkVkaXRpbmcgPSBmYWxzZSB9IH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQntC00LjQvSDR'
    'gtC+0LrQtdC9INC90LAg0YfQtdC70L7QstC10LrQsCDigJQg0LTQu9GPINCy0YHQtdGFINC10LPQviDRg9GB0YLRgNC+0LnR'
    'gdGC0LIuIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQn9GA0L7QstC1'
    '0YDQuNGC0Ywg0L7QsdC90L7QstC70LXQvdC40Y8iOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNsaWNrZWQ6IHJv'
    'b3QuYWN0aW9uKHthY3Rpb246ICJ1cGRhdGUifSkgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA+PSAxICYm'
    'IHJvb3QucGFnZUluZGV4IDw9IDQKICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNgogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHdyYXBNb2RlOiBUZXh0LldyYXAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogcm9vdC5wYWdlSW5kZXggPT09IDEgPyAi0JLRi9Cx0YDQsNC90L3R'
    'i9C1INC/0YDQuNC70L7QttC10L3QuNGPINC/0L7QtNC60LvRjtGH0LDRjtGC0YHRjyDQvdCw0L/RgNGP0LzRg9GOLiDQntGB'
    '0YLQsNC70YzQvdGL0LUg0LjRgdC/0L7Qu9GM0LfRg9GO0YIgVlBOLiIgOiByb290LnBhZ2VJbmRleCA9PT0gMiA/ICLQlNC+'
    '0LHQsNCy0YzRgtC1INC00L7QvNC10L0sINCw0LTRgNC10YEg0LjQu9C4INC/0L7QtNGB0LXRgtGMLiDQlNC+0LzQtdC90Ysg'
    '0LLQutC70Y7Rh9Cw0Y7RgiDQv9C+0LTQtNC+0LzQtdC90Ys7INC30L3QsNC6ID0g0LfQsNC00LDRkdGCINGC0L7Rh9C90L7Q'
    'tSDRgdC+0LLQv9Cw0LTQtdC90LjQtS4g0J/RgNC4INC+0LHRidC10LwgSVAg0LvRg9GH0YjQtSDRg9C60LDQt9GL0LLQsNGC'
    '0Ywg0LTQvtC80LXQvS4iIDogcm9vdC5wYWdlSW5kZXggPT09IDMgPyAi0JjRgdGF0L7QtNGP0YnQuNC1IOKAlCDQv9C+0LTQ'
    'utC70Y7Rh9C10L3QuNGPINC6INGD0LrQsNC30LDQvdC90L7QvNGDINC/0L7RgNGC0YMuINCS0YXQvtC00Y/RidC40LUg4oCU'
    'INC/0YDRj9C80YvQtSDQvtGC0LLQtdGC0Ysg0LLQsNGI0LXQs9C+INGB0LXRgNCy0LXRgNCwLiDQntCx0LAg4oCUINC+0LHQ'
    'sCDQvdCw0L/RgNCw0LLQu9C10L3QuNGPLiIgOiAi0J7QsdGL0YfQvdGL0LkgRE5TINC+0YHRgtCw0ZHRgtGB0Y8g0LIgVlBO'
    'LiDQlNC+0LHQsNCy0LvQtdC90L3Ri9C1INC30LTQtdGB0YwgRE5TLdGB0LXRgNCy0LXRgNGLINC/0L7Qu9GD0YfQsNGO0YIg'
    '0LfQsNC/0YDQvtGB0Ysg0L3QsNC/0YDRj9C80YPRjiDQuCDQvNC+0LPRg9GCINCy0LjQtNC10YLRjCDQt9Cw0L/RgNCw0YjQ'
    'uNCy0LDQtdC80YvQtSDQuNC80LXQvdCwLiDQrdGC0L4g0L3QtSDRgdC/0LjRgdC+0Log0YHQsNC50YLQvtCyLiIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Db21ib0Jv'
    'eCB7IGlkOiBwb3J0UHJvdG9jb2w7IHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSAzOyBtb2RlbDogWyJUQ1AiLCAiVURQ'
    'IiwgIkJPVEgiXTsgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiAxMDAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5U'
    'ZXh0RmllbGQgeyBpZDogZXhjZXB0aW9uSW5wdXQ7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHNlbGVjdEJ5TW91c2U6IHRy'
    'dWU7IHBsYWNlaG9sZGVyVGV4dDogcm9vdC5wYWdlSW5kZXggPT09IDEgPyAi0JjQvNGPINC/0YDQvtGG0LXRgdGB0LAg0LjQ'
    'u9C4IC/Qv9C+0LvQvdGL0Lkv0L/Rg9GC0YwiIDogcm9vdC5wYWdlSW5kZXggPT09IDIgPyAiZXhhbXBsZS5jb20g0LjQu9C4'
    'IDE5Mi4xNjguMS4yMCIgOiByb290LnBhZ2VJbmRleCA9PT0gMyA/ICIyNTU2NSIgOiAi0JDQtNGA0LXRgSBETlMsINC90LDQ'
    'v9GA0LjQvNC10YAgMTkyLjE2OC4xLjEiIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuQ29tYm9Cb3ggeyBpZDog'
    'cG9ydERpcmVjdGlvbjsgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDM7IG1vZGVsOiBbItCY0YHRhdC+0LTRj9GJ0LjQ'
    'tSIsICLQktGF0L7QtNGP0YnQuNC1IiwgItCe0LHQsCJdOyBMYXlvdXQucHJlZmVycmVkV2lkdGg6IDE0MCB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQlNC+0LHQsNCy0LjRgtGMIjsgcHJpbWFyeTogdHJ1'
    'ZTsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiBleGNlcHRpb25JbnB1dC50ZXh0LnRyaW0oKS5sZW5ndGggPiAwOyBv'
    'bkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zdCB2YWx1ZSA9IHJvb3QucGFnZUluZGV4'
    'ID09PSAzID8gcG9ydFByb3RvY29sLmN1cnJlbnRUZXh0LnRvTG93ZXJDYXNlKCkgKyAiOiIgKyBleGNlcHRpb25JbnB1dC50'
    'ZXh0LnRyaW0oKSArICI6IiArIFsib3V0IiwgImluIiwgImJvdGgiXVtwb3J0RGlyZWN0aW9uLmN1cnJlbnRJbmRleF0gOiBl'
    'eGNlcHRpb25JbnB1dC50ZXh0LnRyaW0oKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvb3QuYWN0aW9uKHth'
    'Y3Rpb246ICJhZGQiLCBjYXRlZ29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IHZhbHVlfSwgZnVuY3Rpb24oKSB7IGV4Y2Vw'
    'dGlvbklucHV0LmNsZWFyKCkgfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIFJlcGVhdGVyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1v'
    'ZGVsOiByb290LnBvbGljeVtyb290LmNhdGVnb3J5XSB8fCBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZWdh'
    'dGU6IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgc3RyaW5n'
    'IG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhOyBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwQW55d2hlcmU7IGNvbG9yOiByb290LnRleHRNYWluIH0KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQo9C00LDQu9C40YLRjCI7IGRhbmdlcjogdHJ1ZTsgZW5h'
    'YmxlZEJ1dHRvbjogIXJvb3QuYnVzeTsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAicmVtb3ZlIiwgY2F0ZWdv'
    'cnk6IHJvb3QuY2F0ZWdvcnksIHZhbHVlOiBtb2RlbERhdGF9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHZpc2libGU6ICEocm9v'
    'dC5wb2xpY3lbcm9vdC5jYXRlZ29yeV0gfHwgW10pLmxlbmd0aDsgdGV4dDogItCS0LDRiNC40YUg0LjRgdC60LvRjtGH0LXQ'
    'vdC40Lkg0L/QvtC60LAg0L3QtdGCIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'Qy5Td2l0Y2ggeyB0ZXh0OiAi0J7RgtC+0LHRgNCw0LfQuNGC0Ywg0LHQsNC30L7QstGL0LUg0LjRgdC60LvRjtGH0LXQvdC4'
    '0Y8iOyBjaGVja2VkOiByb290LnNob3dCYXNlOyBvblRvZ2dsZWQ6IHJvb3Quc2hvd0Jhc2UgPSBjaGVja2VkIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxs'
    'V2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJvb3Quc2hvd0Jhc2UKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJlcGVhdGVyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogKHJv'
    'b3QucG9saWN5LmJhc2UgfHwge30pW3Jvb3QuY2F0ZWdvcnldIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgZGVsZWdhdGU6IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHBy'
    'b3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhLmxh'
    'YmVsOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuU3dpdGNoIHsgY2hlY2tlZDogQm9vbGVhbihtb2RlbERh'
    'dGEuZW5hYmxlZCk7IGVuYWJsZWQ6ICFyb290LmJ1c3k7IG9uVG9nZ2xlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImJhc2Ui'
    'LCBjYXRlZ29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IG1vZGVsRGF0YS5pZCwgZW5hYmxlZDogY2hlY2tlZH0pIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsg'
    'Y29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiAi0JLRiyDQvNC+0LbQtdGC0LUg0LLRi9C60LvRjtGH0LjRgtGMINC70Y7Q'
    'sdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uINCh0LrRgNGL0YLQuNC1INGB0L/QuNGB0LrQsCDQvdC1INC8'
    '0LXQvdGP0LXRgiDQtdCz0L4g0YHQvtGB0YLQvtGP0L3QuNC1LiIgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBy'
    'b290LnBhZ2VJbmRleCA9PT0gMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQl9Cw0L/Rg9GJ0LXQvdGLINGB0LXQudGH0LDR'
    'gSI7IGZvbnQucGl4ZWxTaXplOiAxODsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5m'
    'aWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7IGlkOiBhcHBTZWFy'
    'Y2g7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHBsYWNlaG9sZGVyVGV4dDogItCf0L7QuNGB0Log0L/RgNC40LvQvtC20LXQ'
    'vdC40Y8iIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntCx0L3QvtCy'
    '0LjRgtGMINGB0L/QuNGB0L7QuiI7IGVuYWJsZWRCdXR0b246ICFyb290LnJ1bm5pbmdQZW5kaW5nOyBvbkNsaWNrZWQ6IHJv'
    'b3QucmVmcmVzaFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IHJvb3QucGFnZUluZGV4'
    'ID09PSAxID8gcm9vdC5maWx0ZXJlZFJ1bm5pbmcoKSA6IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVs'
    'ZWdhdGU6IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5'
    'IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1'
    'ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YS5uYW1lOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhLmV4ZTsgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZTsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGU7IGNvbG9yOiByb290LnRleHRNdXRlZDsgZm9udC5w'
    'aXhlbFNpemU6IDExIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6IG1vZGVsRGF0YS5leGNsdWRlZCA/ICLQlNC+0LHQsNCy0LvQ'
    'tdC90L4iIDogItCSINC+0LHRhdC+0LQiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFtb2RlbERhdGEuZXhjbHVk'
    'ZWQ7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImFkZCIsIGNhdGVnb3J5OiAiYXBwbGljYXRpb25zIiwgdmFs'
    'dWU6IFN0cmluZyhtb2RlbERhdGEuZXhlIHx8IG1vZGVsRGF0YS5uYW1lIHx8ICIiKX0pIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDUKICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxOAogICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4'
    'dE11dGVkOyB0ZXh0OiAiV2F5ZHJvaWQg0YPQv9GA0LDQstC70Y/QtdGC0YHRjyDQvtGC0LTQtdC70YzQvdC+INC+0YIg0L/R'
    'gNC40LvQvtC20LXQvdC40Lkg0LrQvtC80L/RjNGO0YLQtdGA0LAuINCf0L4g0YPQvNC+0LvRh9Cw0L3QuNGOINCy0LXRgdGM'
    'INC10LPQviDRgtGA0LDRhNC40LosINCy0LrQu9GO0YfQsNGPIEROUywg0LjQtNGR0YIg0L3QsNC/0YDRj9C80YPRji4iIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5Td2l0Y2ggeyB0ZXh0OiAiV2F5ZHJvaWQg0LIg0L7QsdGF0L7QtCBWUE4iOyBj'
    'aGVja2VkOiByb290LnBvbGljeS53YXlkcm9pZF9kaXJlY3QgIT09IGZhbHNlOyBlbmFibGVkOiAhcm9vdC5idXN5OyBvblRv'
    'Z2dsZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJ3YXlkcm9pZCIsIGVuYWJsZWQ6IGNoZWNrZWR9KSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xv'
    'cjogcm9vdC50ZXh0TXV0ZWQ7IHRleHQ6IHJvb3QucG9saWN5LndheWRyb2lkX2RpcmVjdCAhPT0gZmFsc2UgPyAi0J/RgNGP'
    '0LzQvtC1INC/0L7QtNC60LvRjtGH0LXQvdC40LU6IFdheWRyb2lkINC40YHQv9C+0LvRjNC30YPQtdGCINCw0LTRgNC10YEg'
    '0LLQsNGI0LXQs9C+INC/0YDQvtCy0LDQudC00LXRgNCwLiDQntCx0YnQuNC1INC40YHQutC70Y7Rh9C10L3QuNGPINC90LUg'
    '0L7Qs9GA0LDQvdC40YfQuNCy0LDRjtGCINGN0YLQvtGCINGA0LXQttC40LwuIiA6ICJXYXlkcm9pZCDQuNGB0L/QvtC70YzQ'
    't9GD0LXRgiBWUE4uINCf0YDQuCDQvtCx0YDRi9Cy0LUg0YLRg9C90L3QtdC70Y8g0LXQs9C+INCy0L3QtdGI0L3QuNC1INC/'
    '0L7QtNC60LvRjtGH0LXQvdC40Y8g0LHQu9C+0LrQuNGA0YPRjtGC0YHRjy4iIH0KICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Cn0K'
)

RELEASES = pathlib.Path("/opt/vpn-manager/releases")

CURRENT = pathlib.Path("/opt/vpn-manager/current")

PREVIOUS = pathlib.Path("/opt/vpn-manager/previous")

MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024

XRAY_RELEASE_API = (
    "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v"
    + SAFE_XRAY_VERSION
)



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

def save_settings(data: dict) -> None:
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SETTINGS)

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

def _direct_app_rule_matches(rule: str, process_name: str, executable: str) -> bool:
    if "/" not in rule:
        return rule == process_name
    if rule.endswith("/"):
        return executable.startswith(rule)
    return executable == rule

def _running_user_applications(settings: dict) -> list[dict]:
    uid, _gid = _owner_ids(settings)
    rules = policy.load()['applications']
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

def cmd_ui_running(settings: dict) -> None:
    print(
        json.dumps(
            {"applications": _running_user_applications(settings)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
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
    _write_owner_text(package / "evgenium_widget.qml", base64.b64decode(DESKTOP_WIDGET_QML_B64).decode("utf-8"), uid, gid)
    for name, color in (("active", "#5ce0bc"), ("off", "#9aaac0"), ("connecting", "#79baff"), ("warning", "#ffbd69")):
        svg = '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><path d="M16 2 28 7v9c0 7-7 12-12 14C11 28 4 23 4 16V7Z" fill="'+color+'"/><path d="m10 16 4 4 8-9" fill="none" stroke="#132b30" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>'
        _write_owner_text(package / ("widget-" + name + ".svg"), svg, uid, gid)
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
    cmd_tray_remove(settings)
    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
    ok("Evgenium Network GUI удалён из профиля пользователя.")

TRAY_DESKTOP_ENTRY = """[Desktop Entry]
Type=Application
Name=Evgenium VPN Widget
Name[ru]=Виджет Evgenium VPN
Comment=VPN switch in the system tray
Exec=/usr/local/bin/evgenium-network --widget --detach
Icon=evgenium-network
Terminal=false
Categories=Network;
X-GNOME-Autostart-enabled=true
"""

def _tray_autostart_path(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".config" / "autostart" / "evgenium-vpn-widget.desktop"

def cmd_tray_install(settings: dict) -> None:
    cmd_gui_install(settings)
    uid, gid = _owner_ids(settings)
    for target in (_tray_autostart_path(settings), _gui_desktop_path(settings).with_name("evgenium-vpn-widget.desktop")):
        _gui_target_safe(settings, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.chown(target.parent, uid, gid)
        _write_owner_text(target, TRAY_DESKTOP_ENTRY, uid, gid)
    ok("Виджет VPN установлен в автозапуск. Запуск: evgenium-network --widget --detach")

def cmd_tray_remove(settings: dict) -> None:
    for target in (_tray_autostart_path(settings), _gui_desktop_path(settings).with_name("evgenium-vpn-widget.desktop")):
        _gui_target_safe(settings, target)
        target.unlink(missing_ok=True)
    ok("Виджет VPN убран из автозапуска. Текущий значок можно закрыть через его меню.")

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

def safe_extract_manager(tar_path: pathlib.Path, dest: pathlib.Path) -> str:
    allowed = {"vpnctl.py", "vpnadmin.py", "VERSION"}
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        names = {m.name for m in members}
        if names != allowed or len(members) != len(allowed):
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
        info(f"VPN Manager {MANAGER_VERSION}: проверяю завершение установки CLI и GUI...")
        finish_installation(settings, reconnect=False)
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
    pathlib.Path("/usr/local/sbin/vpnctl.new").unlink(missing_ok=True)
    os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")

    info(f"Файлы VPN Manager {version} получены. Завершаю установку...")
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

import types


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
    'RCA9IDE3NwpUT0tFTl9QQVRURVJOID0gcidFVk4xLVtBLVphLXowLTlfLV17NDN9JwpTVE9QID0gRmFsc2UKcG9saWN5ID0g'
    'Tm9uZQpQSU5ORURfQ0EgPSAnLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlFT0RDQ0FxQ2dBd0lCQWdJVWJrSis4'
    'U2FxQWd3WTFSREFqWlJUamNxUTllTXdEUVlKS29aSWh2Y05BUUVMXG5CUUF3SWpFZ01CNEdBMVVFQXd3WFJYWm5aVzVwZFcw'
    'Z2NISnBkbUYwWlNCV1VFNGdRMEV3SGhjTk1qWXhNREEzXG5NVGt4TXpReFdoY05Nell4TURBME1Ua3hNelF4V2pBaU1TQXdI'
    'Z1lEVlFRRERCZEZkbWRsYm1sMWJTQndjbWwyXG5ZWFJsSUZaUVRpQkRRVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dH'
    'UEFEQ0NBWW9DZ2dHQkFPWitudmlFXG4yT3JGN1BkdGtrL1hJYUZWSXZKbHZDMTFWWmY5cmxqQ0JJdkJ5a2JzckFyR3J5UUhH'
    'bnV1WExOYWFTOE50THhZXG5OZVNCREs2TWRnWUpBZWpzUDR3SVR1YjNuTWpTRzJ1bUlJVlU2bUUrR0RvekdQbE5NTkorYmhr'
    'S2FWaGFQakZFXG55WUxZcmRQZTVWQTR3KzVwME5aT0Q2Q0JIRDN0RVhXQk5SSWVWU1didE1JVHNPRVMxUGUvYUFMN3Yzb05J'
    'VmtWXG44bkR3OWo3K3dHMnk1ZGhicDdLVUpIYnJEQjAyNHI3Y1lyUTNheFlGNmd5a2ptenRwS1hzYmt4UXYyN0J2aFNCXG5l'
    'MEVrdEovakNTNlI5SUltWWdJUXJDcmFXWm1WU2NuR0YvQXE0VE53MUg0T3pGQ2tSKzdKVWxZblNZVXZNUmkxXG5Mektla1VD'
    'KzIvMFdGbWhuQ29EdGRqY29ZYnhwTHBLRGVsR2lTM1JzTkN2eG5zbE1hUHo1aENjRjY0WTdSaWpYXG5qNkR1Q1lwRllXbHIx'
    'M0IyMHFBblJvVWFzK0FqWDdQWENrUjR4T2hIK2tXOC9IbUZIaUhrb2hXRTB3bGxJU0JYXG5WQm83S0JPWmQ4U1Zld3liZDJy'
    'QjRzb1hvdVR0alhzL2pUZ2UrSFd4UURHUFAxdW1mejhjRkxSL3VRSURBUUFCXG5vMll3WkRBZEJnTlZIUTRFRmdRVW9RZlRp'
    'Zjc3eFd0MDZoYVhoM2hhODkwcWtUOHdId1lEVlIwakJCZ3dGb0FVXG5vUWZUaWY3N3hXdDA2aGFYaDNoYTg5MHFrVDh3RWdZ'
    'RFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBT0JnTlZIUThCXG5BZjhFQkFNQ0FRWXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnR0JB'
    'STdHS25tZkpqdUwxUXZ5UnRsdytIcjZBWS9aXG5PeGREdkVDZWZvRkw3UTQxVlphK0w3REk4N2tNTFlIeWdSSHVzaDY2b1V2'
    'ODc4VFdNdGFzbmJ0Lzh3WWc2anJ3XG5BeWdwZy9GM1ZEMjR5VHJuSjdPQ2R5R2liNkxHdXVzdVRQNHJVR3NjY1djem5RWFlG'
    'a3pSVnoxVmVZTVpVTitQXG50QVZpTmw0RVJTMWZoK2NHelQ0T3FYUWtKRGtSZXFIL0hDVEU4a1VRVVVnWGFTWHBoS2pHYThw'
    'UjJIVmVGdWtYXG4rMHBwMWlSKzZkaTRhQ0thcGthVGlWUjNyNjJ0UkJVd2J4b0ZZUnl4Tlh5blRLOUVobk0yNVdFcG4vcXUw'
    'bHNEXG5vWHJGVm1qMEFRZkFVSFJOLzJyUEwvL3c2UlBFcEhnVWNydDd6dVNnb1hKWmgwRFQzMFZFSUs5Tk5idUtTRmQ5XG5J'
    'aVd2cnhiVlFTNm1RZ3RFWk40TGMySG0xcHZZK1dySStIMDN1ODA0MitjcExJc0NueFBtOVd2aTdkTVh4cW9iXG5vMi9hTDJ4'
    'REc1Ry84V1ZSL1c1RUFmdktkeGRyazNINjAyb2Njb3Y3K0pnMXZveGkwMEliZE1FeG9NeGQ1YWVoXG5mWFJpSmhURUZvdUlw'
    'bUVTQ0Y0dlZNbFdGcjNtcWxRM0dLU1BWQT09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4nCgoKRlVMTF9IT1NUID0g'
    'J2V2bi1mdWxsLWhvc3QnCkZVTExfUEVFUiA9ICdldm4tZnVsbC1wZWVyJwpGVUxMX05FVCA9ICcxNzIuMjkuMjQ3LjAvMzAn'
    'CkZVTExfVEFCTEUgPSAnNTE4MjgnCkFETUlOX1RBQkxFID0gJzUxODI5JwpGVUxMX0dVQVJEID0gJ2V2bl9zdGFyZml2ZV9m'
    'dWxsJwpkZWYgZnVsbF9zdGF0ZSgpOgogICAgcmV0dXJuIFJPT1QvJ2Z1bGwtbmV0d29yay5qc29uJwoKCmRlZiBjaGFyb25f'
    'YmluYXJ5KCk6CiAgICBjYW5kaWRhdGVzID0gKCcvdXNyL3NiaW4vY2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9iaW4vY2hhcm9u'
    'LXN5c3RlbWQnLAogICAgICAgICAgICAgICAgICAnL3Vzci9saWIvaXBzZWMvY2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9saWJl'
    'eGVjL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywKICAgICAgICAgICAgICAgICAgJy91c3IvbGliL3N0cm9uZ3N3YW4vY2hhcm9u'
    'LXN5c3RlbWQnLCAnL3Vzci9saWJleGVjL3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQnKQogICAgcmV0dXJuIG5leHQoKHAg'
    'Zm9yIHAgaW4gY2FuZGlkYXRlcyBpZiBQYXRoKHApLmlzX2ZpbGUoKSksIE5vbmUpCgoKZGVmIGVuc3VyZV9kZXBlbmRlbmNp'
    'ZXMoKToKICAgIGlmIGNoYXJvbl9iaW5hcnkoKSBhbmQgYWxsKHNodXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwn'
    'LCdpcCcsJ25mdCcsJ2N1cmwnLCdvcGVuc3NsJywnY29ubnRyYWNrJykpOgogICAgICAgIHJldHVybgogICAgc3RhZ2UoJ2Rl'
    'cGVuZGVuY2llcycsICfQo9GB0YLQsNC90LDQstC70LjQstCw0Y4g0L3QtdC+0LHRhdC+0LTQuNC80YvQtSDRgdC40YHRgtC1'
    '0LzQvdGL0LUg0LrQvtC80L/QvtC90LXQvdGC0YsgVlBOLicsIDMsIGFjdGl2ZT1GYWxzZSkKICAgIGlmIHNodXRpbC53aGlj'
    'aCgncGFjbWFuJyk6CiAgICAgICAgYXJncyA9IFsncGFjbWFuJywnLVMnLCctLW5lZWRlZCcsJy0tbm9jb25maXJtJywnc3Ry'
    'b25nc3dhbicsJ2lwcm91dGUyJywnbmZ0YWJsZXMnLCdjdXJsJywnb3BlbnNzbCcsJ2NhLWNlcnRpZmljYXRlcycsJ2Nvbm50'
    'cmFjay10b29scyddCiAgICBlbGlmIHNodXRpbC53aGljaCgnZG5mJyk6CiAgICAgICAgYXJncyA9IFsnZG5mJywnaW5zdGFs'
    'bCcsJy15JywnLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFsc2UnLCdzdHJvbmdzd2FuJywnaXByb3V0ZScsJ25mdGFi'
    'bGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMnLCdjb25udHJhY2stdG9vbHMnXQogICAgZWxzZToKICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9CQ0LLRgtC+0LzQsNGC0LjRh9C10YHQutCw0Y8g0YPRgdGC0LDQvdC+0LLQutCw'
    'INC60LvQuNC10L3RgtCwINC/0L7QtNC00LXRgNC20LjQstCw0LXRgiBBcmNoINC4IEZlZG9yYS4nKQogICAgY29tbWFuZChh'
    'cmdzLCB0aW1lb3V0PTMwMCkKICAgIGlmIG5vdCBjaGFyb25fYmluYXJ5KCkgb3Igbm90IGFsbChzaHV0aWwud2hpY2gocCkg'
    'Zm9yIHAgaW4gKCdzd2FuY3RsJywnY29ubnRyYWNrJykpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0J/QsNC60LXR'
    'giBzdHJvbmdTd2FuINC90LUg0L/RgNC10LTQvtGB0YLQsNCy0LjQuyDQvdC10L7QsdGF0L7QtNC40LzRi9C1INC/0YDQvtCz'
    '0YDQsNC80LzRiy4nKQoKCmRlZiBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPUZhbHNlKToKICAgICIiIkZvcmdl'
    'dCBvbmx5IHRoaXMgbWFuYWdlcidzIG9ic29sZXRlIEROUyBOQVQsIG5ldmVyIGZsdXNoIGFsbCBjb25uZWN0aW9ucy4KCiAg'
    'ICBSZW1vdmluZyBhbiBuZnQgTkFUIGNoYWluIGRvZXMgbm90IHJlbW92ZSBleGlzdGluZyBjb25udHJhY2sgdHJhbnNsYXRp'
    'b25zLgogICAgQSBydW5uaW5nIHJlc29sdmVyIGNhbiByZXVzZSBpdHMgVURQIHNvY2tldCBpbmRlZmluaXRlbHkgYWZ0ZXIg'
    'YSBWUE4gc3dpdGNoLgogICAgIiIiCiAgICBmaWx0ZXJzID0gKFsnLS1yZXBseS1wb3J0LXNyYycsJzE4NTUzJ10gaWYgcHJl'
    'dmlvdXNfdnBuIGVsc2UKICAgICAgICAgICAgICAgWyctLXJlcGx5LXBvcnQtc3JjJywnNTMnLCctLWRzdC1uYXQnLCcxLjEu'
    'MS4xJ10pCiAgICBmb3IgcHJvdG9jb2wgaW4gKCd1ZHAnLCd0Y3AnKToKICAgICAgICByZXN1bHQgPSBjb21tYW5kKFsnY29u'
    'bnRyYWNrJywnLUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG9jb2wsCiAgICAgICAgICAgICAgICAgICAgICAgICAgJy0tZHBv'
    'cnQnLCc1MycsKmZpbHRlcnNdLCBjaGVjaz1GYWxzZSwKICAgICAgICAgICAgICAgICAgICAgICAgIGVudj17Kipvcy5lbnZp'
    'cm9uLCdMQ19BTEwnOidDJ30pCiAgICAgICAgZW1wdHkgPSByZXN1bHQucmV0dXJuY29kZSA9PSAxIGFuZCAnMCBmbG93IGVu'
    'dHJpZXMgaGF2ZSBiZWVuIGRlbGV0ZWQnIGluIHJlc3VsdC5zdGRlcnIKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSAh'
    'PSAwIGFuZCBub3QgZW1wdHk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZG5zX3RyYW5zaXRpb25fY2xlYW51'
    'cF9mYWlsZWQnKQoKCmRlZiBmdWxsX2d1YXJkX2FjdGl2ZSgpOgogICAgcmV0dXJuIGNvbW1hbmQoWyduZnQnLCdsaXN0Jywn'
    'dGFibGUnLCdpbmV0JyxGVUxMX0dVQVJEXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwCgoKZGVmIGZ1bGxfZmlyZXdh'
    'bGwoKToKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZToKICAgICAgICBzZXR0aW5ncz1wb2xpY3kuYXBpLmxvYWRfc2V0dGlu'
    'Z3MoKQogICAgICAgIHJldHVybiBwb2xpY3kuZmlyZXdhbGwocG9saWN5LmxvYWQoKSxwb2xpY3kubG9jYWxfbmV0d29ya3Mo'
    'cGh5c2ljYWxfcm91dGUoKSksaW50KHNldHRpbmdzWyJ4cmF5X3VpZCJdKSkKICAgICMgTWluaW1hbCBndWFyZCB1c2VkIGJ5'
    'IGlzb2xhdGVkIHByb3RvY29sIHRlc3RzLgogICAgIyBLZWVwIGxvY2FsIHN0dWIgRE5TIG9uIGxvb3BiYWNrLiBETkFUIG9m'
    'IDEyNy84IG9udG8gYSB2ZXRoIGZhaWxzIExpbnV4J3MKICAgICMgbG9vcGJhY2sgcm91dGUgY2hlY2tzOyB1cHN0cmVhbSBy'
    'ZXNvbHZlciB0cmFmZmljIHN0aWxsIG9iZXlzIHRoZSBmdWxsIGd1YXJkLgogICAgcmV0dXJuIGYnJyd0YWJsZSBpbmV0IHtG'
    'VUxMX0dVQVJEfSB7ewogY2hhaW4gZG5zIHt7IHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7IHBvbGljeSBh'
    'Y2NlcHQ7CiAgaXAgZGFkZHIgMTI3LjAuMC4wLzggcmV0dXJuCiAgaXAgZGFkZHIge3sgMS4xLjEuMSwgOS45LjkuOSB9fSBy'
    'ZXR1cm4KICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgZG5hdCBp'
    'cCB0byAxLjEuMS4xCiB9fQogY2hhaW4gc291cmNlIHt7IHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3Jj'
    'bmF0OyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBzbmF0IGlwIHRv'
    'IDE3Mi4yOS4yNDcuMQogfX0KIGNoYWluIG91dHB1dCB7eyB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMzA7'
    'IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9I'
    'T1NUfSIgYWNjZXB0CiAgaXAgZGFkZHIgMjU1LjI1NS4yNTUuMjU1IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0'
    'CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJv'
    'cDsKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHVkcCBkcG9y'
    'dCB7SUtFX1BPUlR9IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIge3sge1NF'
    'UlZFUn0gfX0gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7Q0xJRU5UfSBjdCBz'
    'dGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9'
    'IiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBpaWZuYW1lICJ7RlVMTF9IT1NUfSIgY3Qgc3RhdGUgZXN0YWJsaXNoZWQs'
    'cmVsYXRlZCBhY2NlcHQKIH19Cn19JycnCgoKCmRlZiByZWZyZXNoX3JldGFpbmVkX2d1YXJkKCk6CiAgICAiIiJNb3ZlIG9u'
    'bHkgdGhlIFZQTiB0cmFuc3BvcnQgZXhjZXB0aW9uIHdoZW4gYW4gaW5ncmVzcyBlbmRwb2ludCBjaGFuZ2VzLiIiIgogICAg'
    'aWYgbm90IGZ1bGxfZ3VhcmRfYWN0aXZlKCk6CiAgICAgICAgcmV0dXJuCiAgICBydWxlcyA9IGZ1bGxfZmlyZXdhbGwoKQog'
    'ICAgcmVwbGFjZW1lbnQgPSAnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicrcnVsZXMKICAgIGNvbW1hbmQo'
    'WyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICAjIFBlcnNpc3QgdGhlIGNsb3NlZCBndWFyZCBi'
    'ZWZvcmUgY2hhbmdpbmcgdGhlIGFjdGl2ZSBleGNlcHRpb247IGEgY3Jhc2ggc3RheXMgY2xvc2VkLgogICAgd3JpdGUoUk9P'
    'VC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQp'
    'CgoKZGVmIHZpcnR1YWxfaXAoKToKICAgIGRhdGEgPSBqc29uLmxvYWRzKGluc2lkZShbJ2lwJywnLWonLCctNCcsJ2FkZHIn'
    'XSkuc3Rkb3V0KQogICAgaXBzID0gW2FbJ2xvY2FsJ10gZm9yIGxpbmsgaW4gZGF0YSBmb3IgYSBpbiBsaW5rLmdldCgnYWRk'
    'cl9pbmZvJywgW10pCiAgICAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYVsnbG9jYWwnXSkgaW4gaXBhZGRyZXNz'
    'LmlwX25ldHdvcmsoJzEwLjc3LjAuMC8yNCcpXQogICAgaWYgbGVuKGlwcykgIT0gMToKICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ3ZpcnR1YWxfaXBfbWlzc2luZycpCiAgICByZXR1cm4gaXBzWzBdCgoKZGVmIGZ1bGxfbmFtZXNwYWNlKGFkZHJl'
    'c3MpOgogICAgdmlwID0gdmlydHVhbF9pcCgpCiAgICBpZiBub3QgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1Qp'
    'LmV4aXN0cygpOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdhZGQnLEZVTExfSE9TVCwndHlwZScsJ3ZldGgnLCdw'
    'ZWVyJywnbmFtZScsRlVMTF9QRUVSXSkKICAgICAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX1BFRVIsJ25l'
    'dG5zJyxOU10pCiAgICBjb21tYW5kKFsnaXAnLCdhZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcuMS8zMCcsJ2RldicsRlVM'
    'TF9IT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfSE9TVCwnbXR1JywnMTI4MCcsJ3VwJ10pCiAg'
    'ICBpbnNpZGUoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4yLzMwJywnZGV2JyxGVUxMX1BFRVJdKQogICAg'
    'aW5zaWRlKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX1BFRVIsJ210dScsJzEyODAnLCd1cCddKQogICAgaW5zaWRlKFsnc3lz'
    'Y3RsJywnLXF3JywnbmV0LmlwdjQuY29uZi5hbGwuZm9yd2FyZGluZz0xJywnbmV0LmlwdjQuY29uZi5hbGwucnBfZmlsdGVy'
    'PTAnXSkKICAgICMgU3Ryb25nU3dhbidzIGNhdGNoLWFsbCByb3V0ZSBtdXN0IG5vdCBjYXB0dXJlIHJlcGxpZXMgdG8gdGhl'
    'IGhvc3QtZmFjaW5nIGludGVyZmFjZS4KICAgIGluc2lkZShbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnOTAnLCd0'
    'bycsRlVMTF9ORVQsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICAgIGluc2lkZShbJ2lwJywncnVsZScsJ2FkZCcs'
    'J3ByaW9yaXR5JywnOTAnLCd0bycsRlVMTF9ORVQsJ2xvb2t1cCcsJ21haW4nXSkKICAgIGRlbGV0aW9ucyA9ICcnCiAgICBm'
    'b3IgZmFtaWx5LHRhYmxlIGluIFsoJ2luZXQnLCdldm5fZnVsbF9mb3J3YXJkJyksKCduZXRkZXYnLCdldm5fZnVsbF93aXJl'
    'JyldOgogICAgICAgIGlmIGluc2lkZShbJ25mdCcsJ2xpc3QnLCd0YWJsZScsZmFtaWx5LHRhYmxlXSxjaGVjaz1GYWxzZSku'
    'cmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICBkZWxldGlvbnMgKz0gZidkZWxldGUgdGFibGUge2ZhbWlseX0ge3RhYmxl'
    'fVxuJwogICAgcnVsZXMgPSBkZWxldGlvbnMgKyBmJycndGFibGUgaW5ldCBldm5fZnVsbF9mb3J3YXJkIHt7CiBjaGFpbiBm'
    'b3J3YXJkIHt7IHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtNTsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAi'
    'e0ZVTExfUEVFUn0iIG9pZm5hbWUgIntQRUVSfSIgaXAgc2FkZHIgMTcyLjI5LjI0Ny4xIGFjY2VwdAogIGlpZm5hbWUgIntQ'
    'RUVSfSIgb2lmbmFtZSAie0ZVTExfUEVFUn0iIGlwIGRhZGRyIDE3Mi4yOS4yNDcuMSBpcHNlYyBpbiByZXFpZCB7UkVRSUR9'
    'IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiB9fQogY2hhaW4gbmF0IHt7IHR5cGUgbmF0IGhvb2sgcG9z'
    'dHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlwIHNhZGRyIDE3Mi4yOS4yNDcuMSBvaWZuYW1l'
    'ICJ7UEVFUn0iIHNuYXQgaXAgdG8ge3ZpcH0KIH19Cn19CnRhYmxlIG5ldGRldiBldm5fZnVsbF93aXJlIHt7CiBjaGFpbiBl'
    'Z3Jlc3Mge3sgdHlwZSBmaWx0ZXIgaG9vayBlZ3Jlc3MgZGV2aWNlICJ7UEVFUn0iIHByaW9yaXR5IDA7IHBvbGljeSBkcm9w'
    'OwogIGV0aGVyIHR5cGUgYXJwIGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2Nl'
    'cHQKICBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiB9fQp9fScnJwogICAgaW5zaWRlKFsnbmZ0'
    'JywnLWMnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAg'
    'ICMgUmVwbGFjZSB0aGUgb3JpZ2luYWwgbGFiIGZvcndhcmQgZHJvcDsgaG9zdCBpbmdyZXNzIHJlbWFpbnMgY29uc3RyYWlu'
    'ZWQgYnkgZnVsbF9mb3J3YXJkLgogICAgaW5zaWRlKFsnbmZ0JywnZmx1c2gnLCdjaGFpbicsJ2luZXQnLCdldm5fc3RhcmZp'
    'dmVfZ3VhcmQnLCdmb3J3YXJkJ10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxlJywnaW5ldCcsJ2V2bl9zdGFyZml2'
    'ZV9ndWFyZCcsJ2ZvcndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21ldGEnLCduZnByb3RvJywnaXB2NCcsJ2FjY2VwdCdd'
    'KQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdmb3J3YXJkJywn'
    'b2lmbmFtZScsRlVMTF9QRUVSLCdpcHNlYycsJ2luJywncmVxaWQnLHN0cihSRVFJRCksJ2N0Jywnc3RhdGUnLCdlc3RhYmxp'
    'c2hlZCxyZWxhdGVkJywnYWNjZXB0J10pCgoKZGVmIGVncmVzc19oZWFsdGgoKToKICAgIGZvciB1cmwsZXhwZWN0ZWQgaW4g'
    'WygnaHR0cHM6Ly93d3cuY2xvdWRmbGFyZS5jb20vY2RuLWNnaS90cmFjZScsJ2lwPTM4LjE4MC4xNjQuNjcnKSwKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICgnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJywnMzguMTgwLjE2NC42NycpXToKICAgICAgICBy'
    'ZXN1bHQgPSBpbnNpZGUoWydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLXNob3ct'
    'ZXJyb3InLAogICAgICAgICAgICAgICAgICAgICAgICAgJy0tY29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCc1'
    'Jyx1cmxdLHRpbWVvdXQ9NyxjaGVjaz1GYWxzZSkKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCBleHBl'
    'Y3RlZCBpbiByZXN1bHQuc3Rkb3V0LnNwbGl0bGluZXMoKToKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBG'
    'YWxzZQoKCmRlZiByZXRpcmVfcHJldmlvdXNfY29ubmVjdGlvbnMoYWRkcmVzc2VzKToKICAgICMgQSBjaGFuZ2VkIFZQTiBl'
    'Z3Jlc3MgY2Fubm90IHByZXNlcnZlIG9sZCBUQ1Agc2Vzc2lvbnMuIFdha2UgYXBwbGljYXRpb25zIG5vdwogICAgIyBpbnN0'
    'ZWFkIG9mIGxlYXZpbmcgc3RhbGUgc291cmNlIGFkZHJlc3NlcyBhbmQgVURQIE5BVCB1bnRpbCB0aGVpciB0aW1lb3V0cy4K'
    'ICAgIGZvciBhZGRyZXNzIGluIGFkZHJlc3NlczoKICAgICAgICBjb21tYW5kKFsnc3MnLCctSycsJ3NyYycsYWRkcmVzc10s'
    'Y2hlY2s9RmFsc2UpCiAgICAgICAgZm9yIHByb3RvY29sIGluICgndGNwJywndWRwJyk6CiAgICAgICAgICAgIGNvbW1hbmQo'
    'Wydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcsJy1wJyxwcm90b2NvbCwnLXMnLGFkZHJlc3NdLGNoZWNrPUZhbHNlKQoK'
    'CmRlZiBzeXN0ZW1fZG5zX2hlYWx0aChyZXNvbHZfY29uZj1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgIyBnZXRh'
    'ZGRyaW5mby9jdXJsIG1heSB1c2UgbnNzLXJlc29sdmUgb3ZlciBhIFVuaXggc29ja2V0IGFuZCBtaXNzIGEgYnJva2VuCiAg'
    'ICAjIFVEUCBzdHViIHVzZWQgYnkgb3RoZXIgYXBwbGljYXRpb25zLiBFeGVyY2lzZSByZXNvbHYuY29uZiBpbmRlcGVuZGVu'
    'dGx5LgogICAgc2VydmVycyA9IFtsaW5lLnNwbGl0KClbMV0gZm9yIGxpbmUgaW4gcmVzb2x2X2NvbmYucmVhZF90ZXh0KCku'
    'c3BsaXRsaW5lcygpCiAgICAgICAgICAgICAgIGlmIGxpbmUuc3BsaXQoKVs6MV0gPT0gWyduYW1lc2VydmVyJ10gYW5kIGxl'
    'bihsaW5lLnNwbGl0KCkpID49IDJdWzozXQogICAgZm9yIHNlcnZlciBpbiBzZXJ2ZXJzOgogICAgICAgIHRyeToKICAgICAg'
    'ICAgICAgZmFtaWx5ID0gc29ja2V0LkFGX0lORVQ2IGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHNlcnZlcikudmVyc2lvbiA9'
    'PSA2IGVsc2Ugc29ja2V0LkFGX0lORVQKICAgICAgICAgICAgdHJhbnNhY3Rpb24gPSBzZWNyZXRzLnRva2VuX2J5dGVzKDIp'
    'CiAgICAgICAgICAgIHF1ZXJ5ID0gdHJhbnNhY3Rpb24rYidceDAxXHgwMFx4MDBceDAxXHgwMFx4MDBceDAwXHgwMFx4MDBc'
    'eDAwJwogICAgICAgICAgICBxdWVyeSArPSBiJ1x4MDNhcGlceDA1aXBpZnlceDAzb3JnXHgwMFx4MDBceDAxXHgwMFx4MDEn'
    'CiAgICAgICAgICAgIHdpdGggc29ja2V0LnNvY2tldChmYW1pbHksIHNvY2tldC5TT0NLX0RHUkFNKSBhcyByZXNvbHZlcjoK'
    'ICAgICAgICAgICAgICAgIHJlc29sdmVyLnNldHRpbWVvdXQoMikKICAgICAgICAgICAgICAgIHJlc29sdmVyLmNvbm5lY3Qo'
    'KHNlcnZlciwgNTMpKQogICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2VuZChxdWVyeSkKICAgICAgICAgICAgICAgIGFuc3dl'
    'ciA9IHJlc29sdmVyLnJlY3YoNDA5NikKICAgICAgICAgICAgaWYgKGxlbihhbnN3ZXIpID49IDEyIGFuZCBhbnN3ZXJbOjJd'
    'ID09IHRyYW5zYWN0aW9uIGFuZAogICAgICAgICAgICAgICAgICAgIGFuc3dlclsyXSAmIDB4ODAgYW5kIGFuc3dlclszXSAm'
    'IDE1ID09IDAgYW5kCiAgICAgICAgICAgICAgICAgICAgaW50LmZyb21fYnl0ZXMoYW5zd2VyWzY6OF0sICdiaWcnKSA+IDAp'
    'OgogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAg'
    'ICAgICAgICBjb250aW51ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIHBlcnNpc3RfZ3VhcmQocnVsZXMpOgogICAgIyBHdWFy'
    'ZCBwZXJzaXN0ZW5jZSBwcmVjZWRlcyBzd2l0Y2hpbmcuIENsZWFudXAgYWZ0ZXIgYSBjcmFzaCBuZXZlciBvcGVucyB0aGUg'
    'SW50ZXJuZXQuCiAgICBndWFyZF91bml0ID0gJycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGZ1bGwtZGV2aWNlIGtp'
    'bGwgc3dpdGNoCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9jYWwtZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3JrLXBy'
    'ZS50YXJnZXQKW1NlcnZpY2VdClR5cGU9b25lc2hvdApSZW1haW5BZnRlckV4aXQ9eWVzCkV4ZWNTdGFydD0vdXNyL3NiaW4v'
    'bmZ0IC1mIC9ldGMvdnBuLW1hbmFnZXIvc3RhcmZpdmUtdHVubmVsL2Z1bGwtZ3VhcmQubmZ0CltJbnN0YWxsXQpXYW50ZWRC'
    'eT1tdWx0aS11c2VyLnRhcmdldAonJycucmVwbGFjZSgnL3Vzci9zYmluL25mdCcsIHNodXRpbC53aGljaCgnbmZ0JykpCiAg'
    'ICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5mdCcscnVsZXMpCiAgICB3cml0ZShQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVt'
    'L2V2Z2VuaXVtLXN0YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZScpLGd1YXJkX3VuaXQpCiAgICBjb21tYW5kKFsnc3lzdGVt'
    'Y3RsJywnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2VuYWJsZScsJ2V2Z2VuaXVtLXN0YXJm'
    'aXZlLWZ1bGwtZ3VhcmQuc2VydmljZSddKQoKCmRlZiBhY3RpdmF0ZV9mdWxsKGFkZHJlc3MpOgogICAgb2xkX2FkZHJlc3Nl'
    'cyA9IFthWydsb2NhbCddIGZvciBsaW5rIGluIGpzb24ubG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdz'
    'aG93Jywnc2NvcGUnLCdnbG9iYWwnXSkuc3Rkb3V0KQogICAgICAgICAgICAgICAgICAgICBpZiBsaW5rLmdldCgnaWZuYW1l'
    'Jykgbm90IGluIChIT1NULEZVTExfSE9TVCkKICAgICAgICAgICAgICAgICAgICAgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJf'
    'aW5mbycsW10pIGlmIGEuZ2V0KCdzY29wZScpID09ICdnbG9iYWwnXQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMo'
    'KToKICAgICAgICBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcignZnVsbF9pbnRlcmZhY2VfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdy'
    'b3V0ZScsJ3Nob3cnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdy'
    'b3V0ZScsJ3Nob3cnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAg'
    'ICAgcmFpc2UgUnVudGltZUVycm9yKCdhZG1pbl90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGFueShyLmdldCgncHJp'
    'b3JpdHknKSBpbiAoNzksODApIGZvciByIGluIGpzb24ubG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSku'
    'c3Rkb3V0KSk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF9ydWxlX2NvbGxpc2lvbicpCiAgICAgICAg'
    'd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoeydhY3RpdmUnOkZhbHNlfSkpCiAgICBmdWxsX25hbWVzcGFjZShhZGRy'
    'ZXNzKQogICAgIyBWYWxpZGF0ZSB0aGUgZWdyZXNzIGZpbHRlciBiZWZvcmUgaW50ZXJydXB0aW5nIHRoZSBwcmV2aW91cyBW'
    'UE4uCiAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZXN0b25pYV9lZ3Jl'
    'c3NfZmFpbGVkJykKICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICAjIFJlcGFpciBtYXkgaW5oZXJpdCBhIGd1YXJk'
    'IGZyb20gYW4gb2xkZXIgdmVyc2lvbi4gUmVwbGFjZSBvdXIgdGFibGUgaW4KICAgICMgb25lIG5mdCB0cmFuc2FjdGlvbiwg'
    'c28gZml4ZXMgYXBwbHkgd2l0aG91dCBvcGVuaW5nIGFuIHVuZ3VhcmRlZCB3aW5kb3cuCiAgICByZXBsYWNlbWVudCA9ICgn'
    'ZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicgaWYgZnVsbF9ndWFyZF9hY3RpdmUoKSBlbHNlICcnKStydWxl'
    'cwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKICAgIGNvbW1hbmQoWyduZnQn'
    'LCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgcGVyc2lzdF9ndWFyZChydWxlcykKICAgICMgVGhpcyBjb21tYW5k'
    'IHN0b3BzIG9ubHkgdGhpcyBtYW5hZ2VyJ3MgcHJldmlvdXMgWHJheSBtb2RlIGFuZCByZW1vdmVzIGl0cyBndWFyZC4KICAg'
    'IGNvbW1hbmQoWycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwtc3RhcmZpdmUtcGF1c2UtbWFpbiddLHRpbWVv'
    'dXQ9NDApCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCd1bnJlYWNoYWJsZScsJ2RlZmF1bHQnLCdtZXRy'
    'aWMnLCczMjc2MCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2Rl'
    'ZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLEZVTExfSE9TVCwnbWV0cmljJywnMTAnLCd0YWJsZScsRlVMTF9U'
    'QUJMRV0pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJM'
    'RV0sY2hlY2s9RmFsc2UpCiAgICBmb3IgcnVsZSBpbiAoWydwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMyJywnbG9v'
    'a3VwJywnbWFpbiddLAogICAgICAgICAgICAgICAgIFsncHJpb3JpdHknLCc3OScsJ2lpZicsRlVMTF9IT1NULCdsb29rdXAn'
    'LCdtYWluJ10pOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCpydWxlXSxjaGVjaz1GYWxzZSkKICAgICAg'
    'ICBjb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywqcnVsZV0pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJp'
    'b3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0pCiAgICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRf'
    'dGV4dCgpKQogICAgaWYgc2h1dGlsLndoaWNoKCdyZXNvbHZlY3RsJykgYW5kIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdpcy1h'
    'Y3RpdmUnLCctLXF1aWV0Jywnc3lzdGVtZC1yZXNvbHZlZCddLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAg'
    'ICAgZGF0YVsnZG5zX21vZGUnXT0ncmVzb2x2ZWRfbGluaycKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1w'
    'cyhkYXRhKSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RucycsRlVMTF9IT1NULCcxLjEuMS4xJywnOS45Ljku'
    'OSddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG9tYWluJyxGVUxMX0hPU1QsJ34uJ10pCiAgICAgICAgY29t'
    'bWFuZChbJ3Jlc29sdmVjdGwnLCdkZWZhdWx0LXJvdXRlJyxGVUxMX0hPU1QsJ3llcyddKQogICAgICAgIGNvbW1hbmQoWydy'
    'ZXNvbHZlY3RsJywnZmx1c2gtY2FjaGVzJ10sY2hlY2s9RmFsc2UpCiAgICBlbHNlOgogICAgICAgIGlmICdkbnNfYmFja3Vw'
    'JyBub3QgaW4gZGF0YToKICAgICAgICAgICAgZGF0YVsnZG5zX2JhY2t1cCddPVBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKS5y'
    'ZWFkX3RleHQoKQogICAgICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKICAgICAgICBQYXRo'
    'KCcvZXRjL3Jlc29sdi5jb25mJykud3JpdGVfdGV4dCgnbmFtZXNlcnZlciAxLjEuMS4xXG5uYW1lc2VydmVyIDkuOS45Ljlc'
    'bm9wdGlvbnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPVRy'
    'dWUpCiAgICByZXRpcmVfcHJldmlvdXNfY29ubmVjdGlvbnMob2xkX2FkZHJlc3NlcykKICAgIGlmIHBvbGljeSBpcyBub3Qg'
    'Tm9uZToKICAgICAgICBwb2xpY3kuYXBwbHkoKQogICAgaWYgbm90IHN5c3RlbV9kbnNfaGVhbHRoKCk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICAjIFRlc3QgdGhlIGFjdHVhbCBob3N0IHBhdGggYXMg'
    'd2VsbCBhcyBuYW1lc3BhY2UgcHJvYmVzIGJlZm9yZSBhbm5vdW5jaW5nIGNvbm5lY3RlZC4KICAgIGNoZWNrID0gY29tbWFu'
    'ZChbJ2N1cmwnLCctNCcsJy0tbm9wcm94eScsJycgaWYgcG9saWN5IGlzIG5vdCBOb25lIGVsc2UgJyonLCctLWZhaWwnLCct'
    'LXNpbGVudCcsJy0tbWF4LXRpbWUnLCcxMCcsKihbJy0tc29ja3M1LWhvc3RuYW1lJywnMTI3LjAuMC4xOjE4NTU0J10gaWYg'
    'cG9saWN5IGlzIG5vdCBOb25lIGVsc2UgW10pLCdodHRwczovL2FwaS5pcGlmeS5vcmcnXSx0aW1lb3V0PTEyKQogICAgaWYg'
    'Y2hlY2suc3Rkb3V0LnN0cmlwKCkgIT0gJzM4LjE4MC4xNjQuNjcnOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaG9z'
    'dF9lZ3Jlc3NfZmFpbGVkJykKICAgIGRhdGFbJ2FjdGl2ZSddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1'
    'bXBzKGRhdGEpKQoKCmRlZiBjbGVhbnVwX2Z1bGwocmVsZWFzZT1GYWxzZSk6CiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6'
    'CiAgICAgICAgcG9saWN5LnN0b3AocmVsZWFzZT1yZWxlYXNlKQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToK'
    'ICAgICAgICByZXR1cm4KICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBjb21tYW5k'
    'KFsnaXAnLCdyb3V0ZScsJ2RlbCcsJ2RlZmF1bHQnLCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1G'
    'YWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdkZWwnLEZVTExfSE9TVF0sY2hlY2s9RmFsc2UpCiAgICAjIE9uIGZh'
    'aWx1cmU6IHJldGFpbiByb3V0aW5nLCBETlMgYW5kIHRoZSBwZXJzaXN0ZW50IGd1YXJkIHVudGlsIGV4cGxpY2l0IGRpc2Nv'
    'bm5lY3QuCiAgICBpZiBub3QgcmVsZWFzZToKICAgICAgICByZXR1cm4KICAgIGlmICdkbnNfYmFja3VwJyBpbiBkYXRhOgog'
    'ICAgICAgIFBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKS53cml0ZV90ZXh0KGRhdGFbJ2Ruc19iYWNrdXAnXSkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkK'
    'ICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMyJywnbG9va3Vw'
    'JywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCdp'
    'aWYnLEZVTExfSE9TVCwnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdm'
    'bHVzaCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBzZXJ2ZXIgaW4gKCcxOTIuMTY4LjAuMTYz'
    'JywgJzM4LjE4MC4xNjQuNjcnKToKICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScs'
    'J3RvJyxzZXJ2ZXIsJ2lwcHJvdG8nLCd0Y3AnLCdkcG9ydCcsJzIyJywnbG9va3VwJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFs'
    'c2UpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZGlzYWJsZScsJy0tbm93JywnZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1n'
    'dWFyZC5zZXJ2aWNlJ10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnbmZ0JywnZGVsZXRlJywndGFibGUnLCdpbmV0JyxG'
    'VUxMX0dVQVJEXSxjaGVjaz1GYWxzZSkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncygpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3Mo'
    'cHJldmlvdXNfdnBuPVRydWUpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLEFETUlOX1RBQkxF'
    'XSxjaGVjaz1GYWxzZSkKICAgIGZ1bGxfc3RhdGUoKS51bmxpbmsoKQogICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdmbHVz'
    'aC1jYWNoZXMnXSxjaGVjaz1GYWxzZSkgaWYgc2h1dGlsLndoaWNoKCdyZXNvbHZlY3RsJykgZWxzZSBOb25lCgoKZGVmIGNv'
    'bW1hbmQoYXJncywgY2hlY2s9VHJ1ZSwgdGltZW91dD0yMCwgZGF0YT1Ob25lLCBlbnY9Tm9uZSk6CiAgICBjcCA9IHN1YnBy'
    'b2Nlc3MucnVuKFtzdHIoeCkgZm9yIHggaW4gYXJnc10sIGlucHV0PWRhdGEsIHRleHQ9VHJ1ZSwgY2FwdHVyZV9vdXRwdXQ9'
    'VHJ1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgdGltZW91dD10aW1lb3V0LCBlbnY9ZW52LCBjaGVjaz1GYWxzZSkKICAg'
    'IGlmIGNoZWNrIGFuZCBjcC5yZXR1cm5jb2RlOgogICAgICAgICMgQXJndW1lbnRzIG1heSBjb250YWluIGEgQ1NSIHBhdGg7'
    'IGRvIG5vdCBwcm9wYWdhdGUgcHJvY2VzcyBvdXRwdXQgdG8gR1VJL2xvZ3MuCiAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdjb21tYW5kX2ZhaWxlZCcpCiAgICByZXR1cm4gY3AKCgpkZWYgaW5zaWRlKGFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVy'
    'biBjb21tYW5kKFsnaXAnLCAnbmV0bnMnLCAnZXhlYycsIE5TLCAqYXJnc10sICoqa3dhcmdzKQoKCmRlZiB3cml0ZShwYXRo'
    'LCB2YWx1ZSk6CiAgICBwYXRoLnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsIG1vZGU9MG83MDAsIGV4aXN0X29rPVRydWUp'
    'CiAgICB0ZW1wb3JhcnkgPSBwYXRoLndpdGhfc3VmZml4KCcubmV3JykKICAgIGZkID0gb3Mub3Blbih0ZW1wb3JhcnksIG9z'
    'Lk9fV1JPTkxZIHwgb3MuT19DUkVBVCB8IG9zLk9fVFJVTkMgfCBvcy5PX05PRk9MTE9XLCAwbzYwMCkKICAgIHdpdGggb3Mu'
    'ZmRvcGVuKGZkLCAndycpIGFzIHN0cmVhbToKICAgICAgICBzdHJlYW0ud3JpdGUodmFsdWUpCiAgICB0ZW1wb3JhcnkucmVw'
    'bGFjZShwYXRoKQoKCmRlZiBzYXZlZCgpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBqc29uLmxvYWRzKFNUQVRFLnJlYWRf'
    'dGV4dCgpKQogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4ge30KCgpkZWYgc3RhZ2Uo'
    'cGhhc2UsIG1lc3NhZ2UsIHByb2dyZXNzLCAqKmZpZWxkcyk6CiAgICBkYXRhID0geyoqc2F2ZWQoKSwgJ3BoYXNlJzogcGhh'
    'c2UsICdtZXNzYWdlJzogbWVzc2FnZSwgJ3Byb2dyZXNzJzogcHJvZ3Jlc3MsCiAgICAgICAgICAgICd1cGRhdGVkJzogaW50'
    'KHRpbWUudGltZSgpKSwgJ2hlYXJ0YmVhdCc6IHRpbWUubW9ub3RvbmljKCksICoqZmllbGRzfQogICAgd3JpdGUoU1RBVEUs'
    'IGpzb24uZHVtcHMoZGF0YSwgZW5zdXJlX2FzY2lpPUZhbHNlKSkKCgpkZWYgc3RhdHVzKCk6CiAgICBkYXRhID0gc2F2ZWQo'
    'KQogICAgcnVubmluZyA9IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hl'
    'Y2s9RmFsc2UsIHRpbWVvdXQ9MikucmV0dXJuY29kZSA9PSAwCiAgICBpZiBkYXRhLmdldCgncGhhc2UnKSA9PSAnY29ubmVj'
    'dGVkJyBhbmQgKG5vdCBydW5uaW5nIG9yIHRpbWUubW9ub3RvbmljKCktZGF0YS5nZXQoJ2hlYXJ0YmVhdCcsIDApID4gNDUp'
    'OgogICAgICAgIGRhdGEudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsIG1lc3NhZ2U9J9Ch0L7QtdC00LjQvdC10L3QuNC1'
    'INC+0YHRgtCw0L3QvtCy0LjQu9C+0YHRjC4g0J/RgNC+0LLQtdGA0YzRgtC1INGB0L7RgdGC0L7Rj9C90LjQtSDQt9Cw0YnQ'
    'uNGC0Ysg0Lgg0L3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsuJywgYWN0aXZlPUZhbHNlKQogICAgcHVibGlj'
    'ID0ge2tleTogZGF0YVtrZXldIGZvciBrZXkgaW4gKCdwaGFzZScsICdtZXNzYWdlJywgJ3Byb2dyZXNzJywgJ2FjdGl2ZScs'
    'ICd1cGRhdGVkJywgJ21ldHJpY3MnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3Njb3BlJywg'
    'J3NpbmNlJywgJ3JldHJ5JywgJ2Vycm9yX2NvZGUnKSBpZiBrZXkgaW4gZGF0YX0KICAgIHRva2VuX2luZm8gPSB0b2tlbl9z'
    'dGF0dXMoKQogICAgcmV0dXJuIHsncGhhc2UnOiAnb2ZmJywgJ21lc3NhZ2UnOiAoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC9'
    '0ZHQvS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC70Y7Rh9C40YLRjMK7LicgaWYgdG9rZW5faW5mb1snaGFzX3Rva2Vu'
    'J10gZWxzZSAn0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3R'
    'gtCwLicpLAogICAgICAgICAgICAncHJvZ3Jlc3MnOiAwLCAnYWN0aXZlJzogRmFsc2UsICoqcHVibGljLCAncnVubmluZyc6'
    'IHJ1bm5pbmcsCiAgICAgICAgICAgICoqdG9rZW5faW5mbywgKipkZXZpY2Vfc3RhdHVzKCksICdpc29sYXRlZCc6IEZhbHNl'
    'LCAnZnVsbF9kZXZpY2UnOiBUcnVlLCAnZ3VhcmQnOiBmdWxsX2d1YXJkX2FjdGl2ZSgpLCAncHJvdG9jb2wnOiAnSUtFdjIg'
    '4oaSINCt0YHRgtC+0L3QuNGPJ30KCgpAY29udGV4dGxpYi5jb250ZXh0bWFuYWdlcgpkZWYgbmFtZXNwYWNlKCk6CiAgICBi'
    'ZWZvcmUgPSBvcy5vcGVuKCcvcHJvYy9zZWxmL25zL25ldCcsIG9zLk9fUkRPTkxZKQogICAgdGFyZ2V0ID0gb3Mub3Blbign'
    'L3J1bi9uZXRucy8nK05TLCBvcy5PX1JET05MWSkKICAgIHRyeToKICAgICAgICBvcy5zZXRucyh0YXJnZXQsIG9zLkNMT05F'
    'X05FV05FVCkKICAgICAgICB5aWVsZAogICAgZmluYWxseToKICAgICAgICBvcy5zZXRucyhiZWZvcmUsIG9zLkNMT05FX05F'
    'V05FVCkKICAgICAgICBvcy5jbG9zZSh0YXJnZXQpCiAgICAgICAgb3MuY2xvc2UoYmVmb3JlKQoKCmRlZiBwaHlzaWNhbF9y'
    'b3V0ZSgpOgogICAgcm91dGVzID0ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCAnLWonLCAnLTQnLCAncm91dGUnLCAnc2hv'
    'dycsICd0YWJsZScsICdtYWluJywgJ2RlZmF1bHQnXSkuc3Rkb3V0KQogICAgY2FuZGlkYXRlcyA9IFtyIGZvciByIGluIHJv'
    'dXRlcyBpZiByLmdldCgnZ2F0ZXdheScpIGFuZCByLmdldCgnZGV2JykgYW5kCiAgICAgICAgICAgICAgICAgIG5vdCByWydk'
    'ZXYnXS5zdGFydHN3aXRoKCgndHVuJywgJ3hyYXknLCAnd2cnLCAnZXZuLScpKV0KICAgIGlmIG5vdCBjYW5kaWRhdGVzOgog'
    'ICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignbm9fcGh5c2ljYWxfcm91dGUnKQogICAgcm91dGUgPSBtaW4oY2FuZGlkYXRl'
    'cywga2V5PWxhbWJkYSByOiByLmdldCgnbWV0cmljJywgMCkpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInW0EtWmEtejAt'
    'OV8uOi1dezEsMTV9Jywgcm91dGVbJ2RldiddKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaW50ZXJm'
    'YWNlJykKICAgIGlwYWRkcmVzcy5JUHY0QWRkcmVzcyhyb3V0ZVsnZ2F0ZXdheSddKQogICAgcmV0dXJuIHJvdXRlCgoKZGVm'
    'IGhvc3RfcnVsZXMoaWZhY2UsIHByZXZpb3VzX2ZvcndhcmQ9VHJ1ZSk6CiAgICAjIFNjb3BlIGV2ZXJ5IG5ldyBmb3J3YXJk'
    'aW5nL05BVCBydWxlIHRvIG91ciBvbmUgaW50ZXJmYWNlIGFuZCB0aGUgY29uZmlndXJlZCBpbmdyZXNzIGFkZHJlc3MuCiAg'
    'ICBwcmVzZXJ2ZV9kaXNhYmxlZCA9ICcnIGlmIHByZXZpb3VzX2ZvcndhcmQgZWxzZSAnJycgIGlpZm5hbWUgIndheWRyb2lk'
    'MCIgbWV0YSBuZnByb3RvIGlwdjQgYWNjZXB0CiAgb2lmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBjdCBz'
    'dGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnJycKICAgIHJldHVybiBm'
    'JycndGFibGUgaW5ldCB7TkZUfSB7ewogY2hhaW4gZm9yd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlv'
    'cml0eSAtMjA7IHBvbGljeSBhY2NlcHQ7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB1ZHAg'
    'ZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHRjcCBk'
    'cG9ydCA4NDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgZHJvcAogIG9pZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge3sg'
    'e1NFUlZFUn0gfX0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGRyb3AK'
    'e3ByZXNlcnZlX2Rpc2FibGVkfQogfX0KIGNoYWluIG5hdCB7ewogIHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3Jp'
    'dHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlwIHNhZGRyIHtDTElFTlR9IG9pZm5hbWUgIntpZmFjZX0iIG1hc3F1ZXJh'
    'ZGUKIH19Cn19JycnCgoKZGVmIHNldHVwX25ldHdvcmsoKToKICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgIyBS'
    'ZWZ1c2UgbmFtZS9hZGRyZXNzIGNvbGxpc2lvbnMgcmF0aGVyIHRoYW4gcmVwdXJwb3NpbmcgYW5vdGhlciBhcHBsaWNhdGlv'
    'bidzIHJlc291cmNlcy4KICAgIGlmIFBhdGgoJy9ydW4vbmV0bnMvJytOUykuZXhpc3RzKCkgb3IgUGF0aCgnL3N5cy9jbGFz'
    'cy9uZXQvJytIT1NUKS5leGlzdHMoKSBvciAoUGF0aCgnL2V0Yy9uZXRucycpL05TKS5leGlzdHMoKToKICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmFtZXNwYWNlX2V4aXN0cycpCiAgICBpZiBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91'
    'dGUnLCAnc2hvdycsICd0YWJsZScsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X3RhYmxlX2luX3VzZScpCiAgICBpZiBhbnkoTkVUV09SSyBpbiBsaW5lIGZvciBs'
    'aW5lIGluIGNvbW1hbmQoWydpcCcsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ2FsbCddKS5zdGRvdXQuc3Bs'
    'aXRsaW5lcygpKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmV0d29ya19pbl91c2UnKQogICAgb2xkX2Zv'
    'cndhcmQgPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgICMg'
    'UmVjb3JkIG93bmVyc2hpcCBiZWZvcmUgY3JlYXRpbmcgYW55dGhpbmc6IGNsZWFudXAgaXMgdmFsaWQgYWZ0ZXIgZXZlcnkg'
    'cGFydGlhbCBzdGVwLgogICAgdXBsaW5rID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9yb3V0ZVsnZGV2J10v'
    'J2ZvcndhcmRpbmcnCiAgICB3cml0ZShST09ULyduZXR3b3JrLmpzb24nLCBqc29uLmR1bXBzKHsnZm9yd2FyZCc6IG9sZF9m'
    'b3J3YXJkLCAnaW50ZXJmYWNlJzogcm91dGVbJ2RldiddLCAndXBsaW5rX2ZvcndhcmQnOiB1cGxpbmsucmVhZF90ZXh0KCku'
    'c3RyaXAoKX0pKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2FkZCcsIE5TXSkKICAgIHdyaXRlKFBhdGgoJy9ldGMv'
    'bmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCAnbmFtZXNlcnZlciAxLjEuMS4xXG5uYW1lc2VydmVyIDkuOS45Ljlcbm9wdGlv'
    'bnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICAjIG5zcy1yZXNvbHZlIHRhbGtzIHRvIHRoZSBob3N0IGRhZW1vbiBv'
    'dmVyIGEgVW5peCBzb2NrZXQgZXZlbiBpbnNpZGUgbmV0bnMuCiAgICBuc3M9UGF0aCgnL2V0Yy9uc3N3aXRjaC5jb25mJyku'
    'cmVhZF90ZXh0KCkKICAgIG5zcz1yZS5zdWIocideaG9zdHM6LiokJywgJ2hvc3RzOiBmaWxlcyBkbnMnLCBuc3MsIGZsYWdz'
    'PXJlLk0pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ25zc3dpdGNoLmNvbmYnLCBuc3MpCiAgICBjb21tYW5k'
    'KFsnaXAnLCAnbGluaycsICdhZGQnLCBIT1NULCAndHlwZScsICd2ZXRoJywgJ3BlZXInLCAnbmFtZScsIFBFRVJdKQogICAg'
    'Y29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ25ldG5zJywgTlNdKQogICAgY29tbWFuZChbJ2lwJywgJ2Fk'
    'ZHInLCAnYWRkJywgR0FURVdBWSsnLzMwJywgJ2RldicsIEhPU1RdKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnc2V0'
    'JywgSE9TVCwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdhZGRyJywgJ2FkZCcsIENMSUVOVCsnLzMwJywgJ2RldicsIFBF'
    'RVJdKQogICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQnLCBQRUVSLCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywgJ2xp'
    'bmsnLCAnc2V0JywgJ2xvJywgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdyb3V0ZScsICdhZGQnLCAnZGVmYXVsdCcsICd2'
    'aWEnLCBHQVRFV0FZXSkKICAgIGNvbW1hbmQoWydpcCcsICdyb3V0ZScsICdhZGQnLCAndGFibGUnLCBzdHIoVEFCTEUpLCAn'
    'ZGVmYXVsdCcsICd2aWEnLCByb3V0ZVsnZ2F0ZXdheSddLCAnZGV2Jywgcm91dGVbJ2RldiddXSkKICAgIGZvciBhZGRyZXNz'
    'IGluIEVORFBPSU5UUzoKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdhZGQnLCAncHJpb3JpdHknLCBzdHIoUFJJ'
    'T1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9v'
    'a3VwJywgc3RyKFRBQkxFKV0pCiAgICBydWxlcyA9IGhvc3RfcnVsZXMocm91dGVbJ2RldiddLCBwcmV2aW91c19mb3J3YXJk'
    'PW9sZF9mb3J3YXJkID09ICcxJykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQog'
    'ICAgY29tbWFuZChbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICAjIFBlci1pbnRlcmZhY2UgZm9yd2FyZGlu'
    'ZyBhdm9pZHMgaXBfZm9yd2FyZCdzIGdsb2JhbCBkZWZhdWx0cyByZXNldC4KICAgIChQYXRoKCcvcHJvYy9zeXMvbmV0L2lw'
    'djQvY29uZicpL0hPU1QvJ2ZvcndhcmRpbmcnKS53cml0ZV90ZXh0KCcxXG4nKQogICAgdXBsaW5rLndyaXRlX3RleHQoJzFc'
    'bicpCgoKZGVmIGNsZWFudXAoKToKICAgIGNsZWFudXBfZnVsbCgpCiAgICAjIEFuIHVub3duZWQgbmFtZXNwYWNlL3RhYmxl'
    'IG11c3QgbmV2ZXIgYmUgZGVsZXRlZCBieSBhIGdlbmVyaWMgY2xlYW51cCBjYWxsLgogICAgaWYgbm90IChST09ULyduZXR3'
    'b3JrLmpzb24nKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGEgPSBqc29uLmxvYWRzKChST09ULyduZXR3b3Jr'
    'Lmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGNvbW1hbmQoWyduZnQnLCAnZGVsZXRlJywgJ3RhYmxlJywgJ2luZXQnLCBORlRd'
    'LCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluICgqRU5EUE9JTlRTLCAqTEVHQUNZX0VORFBPSU5UUyk6CiAgICAg'
    'ICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElF'
    'TlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBj'
    'aGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluIGRhdGEuZ2V0KCdtZWFzdXJlbWVudF9pcHMnLCBbXSk6CiAgICAgICAg'
    'aWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xvYmFsOgogICAgICAgICAgICBjb21tYW5kKFsnaXAnLCAn'
    'cnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsICd0bycsIGFkZHJlc3MrJy8z'
    'MicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnZmx1'
    'c2gnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAnbmV0bnMnLCAnZGVs'
    'JywgTlNdLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2RlbCcsIEhPU1RdLCBjaGVjaz1GYWxz'
    'ZSkKICAgIGlmICd1cGxpbmtfZm9yd2FyZCcgaW4gZGF0YToKICAgICAgICBwYXRoID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9p'
    'cHY0L2NvbmYnKS9kYXRhWydpbnRlcmZhY2UnXS8nZm9yd2FyZGluZycKICAgICAgICBpZiBwYXRoLmV4aXN0cygpOgogICAg'
    'ICAgICAgICBwYXRoLndyaXRlX3RleHQoZGF0YVsndXBsaW5rX2ZvcndhcmQnXSsnXG4nKQogICAgZWxpZiBkYXRhLmdldCgn'
    'Zm9yd2FyZCcpID09ICcwJyBhbmQgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5z'
    'dHJpcCgpID09ICcxJzoKICAgICAgICBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcpLndyaXRlX3RleHQo'
    'JzBcbicpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUp'
    'CiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAg'
    'IHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhPU0Vycm9yKToKICAgICAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TKS5ybWRp'
    'cigpCiAgICAoUk9PVC8nbmV0d29yay5qc29uJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgpAY29udGV4dGxpYi5jb250'
    'ZXh0bWFuYWdlcgpkZWYgbWVhc3VyZW1lbnRfcm91dGUoYWRkcmVzcyk6CiAgICAiIiJBIHNob3J0LWxpdmVkIGRpcmVjdCBy'
    'b3V0ZSBmb3IgYSB2ZXJpZmllZCBZYW5kZXggSFRUUFMgbWVhc3VyZW1lbnQsIGxhYiBvbmx5LiIiIgogICAgaWYgbm90IGlw'
    'YWRkcmVzcy5pcF9hZGRyZXNzKGFkZHJlc3MpLmlzX2dsb2JhbCBvciBhZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICBy'
    'YWlzZSBWYWx1ZUVycm9yKCdpbnZhbGlkX21lYXN1cmVtZW50X2FkZHJlc3MnKQogICAgbGFiZWwgPSAnZXZuLW1lYXN1cmUt'
    'JytzZWNyZXRzLnRva2VuX2hleCg4KQogICAgZGF0YSA9IGpzb24ubG9hZHMoKFJPT1QvJ25ldHdvcmsuanNvbicpLnJlYWRf'
    'dGV4dCgpKQogICAgZGF0YVsnbWVhc3VyZW1lbnRfaXBzJ10gPSBzb3J0ZWQoc2V0KGRhdGEuZ2V0KCdtZWFzdXJlbWVudF9p'
    'cHMnLCBbXSkrW2FkZHJlc3NdKSkKICAgIHdyaXRlKFJPT1QvJ25ldHdvcmsuanNvbicsIGpzb24uZHVtcHMoZGF0YSkpCiAg'
    'ICB0cnk6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5JywgJzExMScsICdmcm9tJywg'
    'Q0xJRU5UKycvMzInLAogICAgICAgICAgICAgICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUp'
    'XSkKICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2luc2VydCcsICdydWxlJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJywgJ2lp'
    'Zm5hbWUnLCBIT1NULAogICAgICAgICAgICAgICAgICdpcCcsICdkYWRkcicsIGFkZHJlc3MsICd0Y3AnLCAnZHBvcnQnLCAn'
    'NDQzJywgJ2FjY2VwdCcsICdjb21tZW50JywgbGFiZWxdKQogICAgICAgIGNvbW1hbmQoWyduZnQnLCAnaW5zZXJ0JywgJ3J1'
    'bGUnLCAnaW5ldCcsIE5GVCwgJ2ZvcndhcmQnLCAnb2lmbmFtZScsIEhPU1QsCiAgICAgICAgICAgICAgICAgJ2lwJywgJ3Nh'
    'ZGRyJywgYWRkcmVzcywgJ2N0JywgJ3N0YXRlJywgJ2VzdGFibGlzaGVkLHJlbGF0ZWQnLCAnYWNjZXB0JywgJ2NvbW1lbnQn'
    'LCBsYWJlbF0pCiAgICAgICAgeWllbGQKICAgIGZpbmFsbHk6CiAgICAgICAgcmVzdWx0ID0gY29tbWFuZChbJ25mdCcsICct'
    'aicsICctYScsICdsaXN0JywgJ2NoYWluJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJ10sIGNoZWNrPUZhbHNlKQogICAgICAg'
    'IGlmIHJlc3VsdC5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgICAgIGZvciBlbnRyeSBpbiBqc29uLmxvYWRzKHJlc3VsdC5z'
    'dGRvdXQpLmdldCgnbmZ0YWJsZXMnLCBbXSk6CiAgICAgICAgICAgICAgICBydWxlID0gZW50cnkuZ2V0KCdydWxlJywge30p'
    'CiAgICAgICAgICAgICAgICBpZiBydWxlLmdldCgnY29tbWVudCcpID09IGxhYmVsOgogICAgICAgICAgICAgICAgICAgIGNv'
    'bW1hbmQoWyduZnQnLCAnZGVsZXRlJywgJ3J1bGUnLCAnaW5ldCcsIE5GVCwgJ2ZvcndhcmQnLCAnaGFuZGxlJywgc3RyKHJ1'
    'bGVbJ2hhbmRsZSddKV0sIGNoZWNrPUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2RlbCcsICdwcmlv'
    'cml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNzKycvMzIn'
    'LCAnbG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQoKCmRlZiBwcm92aWRlcl9hZGRyZXNzZXMoaG9zdCk6CiAg'
    'ICAjIEROUyBtYXkgdXNlIHRoZSB3b3JraW5nIHJlc29sdmVyLCBidXQgbWVhc3VyZWQgSFRUUFMgaXRzZWxmIHRha2VzIHRo'
    'ZSBwaHlzaWNhbCByb3V0ZS4KICAgIGFkZHJlc3NlcyA9IFthbnN3ZXJbNF1bMF0gZm9yIGFuc3dlciBpbiBzb2NrZXQuZ2V0'
    'YWRkcmluZm8oaG9zdCwgNDQzLCBzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKV0KICAgIHJldHVybiBsaXN0'
    'KGRpY3QuZnJvbWtleXMoeCBmb3IgeCBpbiBhZGRyZXNzZXMgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoeCkuaXNfZ2xvYmFs'
    'KSlbOjJdCgoKZGVmIHByb3ZpZGVyX2dldChob3N0LCBwYXRoLCBtYXhpbXVtLCBtZWFzdXJlPUZhbHNlKToKICAgIGxhc3Qg'
    'PSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiBwcm92aWRlcl9hZGRyZXNzZXMoaG9zdCk6CiAgICAgICAgb3V0cHV0ID0gUk9P'
    'VC8oJ3JlZmVyZW5jZS0nK3NlY3JldHMudG9rZW5faGV4KDgpKycudG1wJykKICAgICAgICB0cnk6CiAgICAgICAgICAgIHdp'
    'dGggbWVhc3VyZW1lbnRfcm91dGUoYWRkcmVzcyk6CiAgICAgICAgICAgICAgICBhcmdzID0gWydjdXJsJywgJy00JywgJy0t'
    'c2lsZW50JywgJy0tc2hvdy1lcnJvcicsICctLWZhaWwnLCAnLS1ub3Byb3h5JywgJyonLAogICAgICAgICAgICAgICAgICAg'
    'ICAgICAnLS1wcm90bycsICc9aHR0cHMnLCAnLS1jb25uZWN0LXRpbWVvdXQnLCAnNCcsICctLW1heC10aW1lJywgJzEwJywK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgJy0tcmVzb2x2ZScsIGhvc3QrJzo0NDM6JythZGRyZXNzLCAnLS1tYXgtZmlsZXNp'
    'emUnLCBzdHIobWF4aW11bSksCiAgICAgICAgICAgICAgICAgICAgICAgICctLW91dHB1dCcsIHN0cihvdXRwdXQpLCAnLS13'
    'cml0ZS1vdXQnLCAnJXtqc29ufSddCiAgICAgICAgICAgICAgICBpZiBtZWFzdXJlOgogICAgICAgICAgICAgICAgICAgIGFy'
    'Z3MgKz0gWyctLXJhbmdlJywgJzAtJytzdHIobWF4aW11bS0xKV0KICAgICAgICAgICAgICAgIGFyZ3MgKz0gWydodHRwczov'
    'LycraG9zdCtwYXRoXQogICAgICAgICAgICAgICAgcmVzdWx0ID0gaW5zaWRlKGFyZ3MsIHRpbWVvdXQ9MTIsIGNoZWNrPUZh'
    'bHNlKQogICAgICAgICAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGU6CiAgICAgICAgICAgICAgICAgICAgcmFpc2UgUnVu'
    'dGltZUVycm9yKCdtZWFzdXJlbWVudF9jdXJsXycrc3RyKHJlc3VsdC5yZXR1cm5jb2RlKSkKICAgICAgICAgICAgICAgIHN0'
    'YXRpc3RpY3MgPSBqc29uLmxvYWRzKHJlc3VsdC5zdGRvdXQpCiAgICAgICAgICAgICAgICBpZiBtZWFzdXJlOgogICAgICAg'
    'ICAgICAgICAgICAgIHJlY2VpdmVkID0gaW50KHN0YXRpc3RpY3NbJ3NpemVfZG93bmxvYWQnXSkKICAgICAgICAgICAgICAg'
    'ICAgICBlbGFwc2VkID0gZmxvYXQoc3RhdGlzdGljc1sndGltZV90b3RhbCddKS1mbG9hdChzdGF0aXN0aWNzWyd0aW1lX3N0'
    'YXJ0dHJhbnNmZXInXSkKICAgICAgICAgICAgICAgICAgICBpZiByZWNlaXZlZCA8IDEwMjQqMTAyNCBvciByZWNlaXZlZCA+'
    'IG1heGltdW0gb3IgZWxhcHNlZCA8PSAwOgogICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ21l'
    'YXN1cmVtZW50X3Rvb19zaG9ydCcpCiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHsnYnl0ZXMnOiByZWNlaXZlZCwgJ2Vs'
    'YXBzZWRfbXMnOiByb3VuZChlbGFwc2VkKjEwMDApLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2VzdGltYXRlZF9t'
    'YnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFwc2VkLzFlNiwgMil9CiAgICAgICAgICAgICAgICByZXR1cm4gb3V0cHV0LnJl'
    'YWRfYnl0ZXMoKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgUnVudGltZUVycm9yLCBWYWx1ZUVycm9yLCBzdWJwcm9jZXNz'
    'LlRpbWVvdXRFeHBpcmVkKSBhcyBleGM6CiAgICAgICAgICAgIGxhc3QgPSBleGMKICAgICAgICBmaW5hbGx5OgogICAgICAg'
    'ICAgICBvdXRwdXQudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVmZXJlbmNlX3Vu'
    'YXZhaWxhYmxlJykgZnJvbSBsYXN0CgoKZGVmIHZhbGlkYXRlX3lhbmRleF9wcm9iZSh1cmwpOgogICAgZnJvbSB1cmxsaWIu'
    'cGFyc2UgaW1wb3J0IHVybHNwbGl0CiAgICBwYXJzZWQgPSB1cmxzcGxpdCh1cmwpCiAgICBpZiAobGVuKHVybCkgPiAyMDQ4'
    'IG9yIHBhcnNlZC5zY2hlbWUgIT0gJ2h0dHBzJyBvciBub3QgcGFyc2VkLmhvc3RuYW1lIG9yCiAgICAgICAgbm90IHBhcnNl'
    'ZC5ob3N0bmFtZS5lbmRzd2l0aCgnLmNkbi55YW5kZXgubmV0Jykgb3IgcGFyc2VkLnVzZXJuYW1lIG9yIHBhcnNlZC5wYXNz'
    'd29yZCBvcgogICAgICAgIHBhcnNlZC5wb3J0IG5vdCBpbiAoTm9uZSwgNDQzKSBvciBwYXJzZWQuZnJhZ21lbnQpOgogICAg'
    'ICAgIHJhaXNlIFZhbHVlRXJyb3IoJ3VudHJ1c3RlZF9yZWZlcmVuY2VfdXJsJykKICAgIHJldHVybiBwYXJzZWQuaG9zdG5h'
    'bWUsIHBhcnNlZC5wYXRoKygnPycgKyBwYXJzZWQucXVlcnkgaWYgcGFyc2VkLnF1ZXJ5IGVsc2UgJycpCgoKZGVmIHJlZmVy'
    'ZW5jZV9zYW1wbGUoZm9yY2U9RmFsc2UpOgogICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICBmaW5nZXJwcmludCA9'
    'IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRl'
    'd2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgIHRyeToKICAgICAg'
    'ICBjYWNoZWQgPSBqc29uLmxvYWRzKChST09ULydyZWZlcmVuY2UuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIGlmIG5v'
    'dCBmb3JjZSBhbmQgY2FjaGVkLmdldCgnbmV0d29yaycpID09IGZpbmdlcnByaW50IGFuZCBjYWNoZWQuZ2V0KCdwcm92aWRl'
    'cicpID09ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInOgogICAgICAgICAgICByZXR1cm4gY2FjaGVkCiAgICBleGNlcHQgKE9T'
    'RXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHBhc3MKICAgIHN0YWdlKCdyZWZlcmVuY2UnLCAn0JfQsNC/0YPRgdC60LDR'
    'jiDQt9Cw0LzQtdGAINC/0YDRj9C80L7Qs9C+INGB0L7QtdC00LjQvdC10L3QuNGPOiDQr9C90LTQtdC60YEg0JjQvdGC0LXR'
    'gNC90LXRgtC+0LzQtdGC0YAuJywgMTIpCiAgICBjb25maWcgPSBqc29uLmxvYWRzKHByb3ZpZGVyX2dldCgneWFuZGV4LnJ1'
    'JywgJy9pbnRlcm5ldC9hcGkvdjAvZ2V0LXByb2Jlcz9mcm9tPWludGVybmV0Jm5vY2FjaGU9JytzdHIoaW50KHRpbWUudGlt'
    'ZSgpKjEwMDApKSwgNjU1MzYpKQogICAgcHJvYmVzID0gY29uZmlnLmdldCgnZG93bmxvYWQnLCB7fSkuZ2V0KCdwcm9iZXMn'
    'LCBbXSkKICAgIGNhbmRpZGF0ZXMgPSBbXQogICAgZm9yIHByb2JlIGluIHByb2JlczoKICAgICAgICB0cnk6CiAgICAgICAg'
    'ICAgIGhvc3QsIHBhdGggPSB2YWxpZGF0ZV95YW5kZXhfcHJvYmUocHJvYmUuZ2V0KCd1cmwnLCAnJykpCiAgICAgICAgZXhj'
    'ZXB0IChWYWx1ZUVycm9yLCBUeXBlRXJyb3IpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmICc1MG1iJyBpbiBw'
    'YXRoIG9yICcxMDBtYicgaW4gcGF0aDoKICAgICAgICAgICAgY2FuZGlkYXRlcy5hcHBlbmQoKGhvc3QsIHBhdGgpKQogICAg'
    'aWYgbm90IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdyZWZlcmVuY2Vfc2NoZW1hX2NoYW5nZWQn'
    'KQogICAgaG9zdCwgcGF0aCA9IGNhbmRpZGF0ZXNbMF0KICAgICMgU2hvcnQgc2FtcGxlcyBhdm9pZCBhIG1pbnV0ZS1sb25n'
    'IHNhdHVyYXRpb24gd2hpbGUgdGhlIHVzZXIgd2F0Y2hlcyB2aWRlby4KICAgIHNhbXBsZXMgPSBbcHJvdmlkZXJfZ2V0KGhv'
    'c3QsIHBhdGgsIDgqMTAyNCoxMDI0LCBtZWFzdXJlPVRydWUpIGZvciBfIGluIHJhbmdlKDIpXQogICAgcmVzdWx0ID0geydw'
    'cm92aWRlcic6ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInLCAnbmV0d29yayc6IGZpbmdlcnByaW50LCAndGltZSc6IGludCh0'
    'aW1lLnRpbWUoKSksCiAgICAgICAgICAgICAgJ2VzdGltYXRlZF9tYnBzJzogbWF4KHhbJ2VzdGltYXRlZF9tYnBzJ10gZm9y'
    'IHggaW4gc2FtcGxlcyksICdzYW1wbGVzJzogc2FtcGxlcywKICAgICAgICAgICAgICAnc2hvcnRfc2FtcGxlJzogVHJ1ZSwg'
    'J2RpcmVjdF9waHlzaWNhbF9yb3V0ZSc6IFRydWV9CiAgICB3cml0ZShST09ULydyZWZlcmVuY2UuanNvbicsIGpzb24uZHVt'
    'cHMocmVzdWx0KSkKICAgIHJldHVybiByZXN1bHQKCgoKZGVmIHRsc19yZXF1ZXN0KGFkZHJlc3MsIHBhdGgsIGJvZHk9Tm9u'
    'ZSwgY2xpZW50PUZhbHNlLCB0aW1lb3V0PTgpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNh'
    'ZGF0YT1QSU5ORURfQ0EpCiAgICBpZiBjbGllbnQ6CiAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1Qv'
    'J2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBzb2NrID0gc29ja2V0LmNyZWF0ZV9jb25u'
    'ZWN0aW9uKChhZGRyZXNzLCA4NDQzKSwgdGltZW91dD10aW1lb3V0KQogICAgdHJ5OgogICAgICAgIHRscyA9IGNvbnRleHQu'
    'd3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPVNFUlZFUikKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAg'
    'ICAgIHNvY2suY2xvc2UoKQogICAgICAgIHJhaXNlCiAgICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rp'
    'b24oYWRkcmVzcywgODQ0MywgdGltZW91dD10aW1lb3V0KQogICAgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAgICBlbmNvZGVk'
    'ID0ganNvbi5kdW1wcyhib2R5LCBzZXBhcmF0b3JzPSgnLCcsICc6JykpLmVuY29kZSgpIGlmIGJvZHkgaXMgbm90IE5vbmUg'
    'ZWxzZSBOb25lCiAgICB0cnk6CiAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdQT1NUJyBpZiBib2R5IGlzIG5vdCBOb25l'
    'IGVsc2UgJ0dFVCcsIHBhdGgsIGJvZHk9ZW5jb2RlZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVycz17J0Nv'
    'bnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywgJ0Nvbm5lY3Rpb24nOiAnY2xvc2UnfSkKICAgICAgICByZXNwb25z'
    'ZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgIHJhdyA9IHJlc3BvbnNlLnJlYWQoMjAwMDEpCiAgICAgICAg'
    'aWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBvciBsZW4ocmF3KSA+IDIwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ3JlcXVlc3RfcmVqZWN0ZWQnKQogICAgICAgIHJldHVybiBqc29uLmxvYWRzKHJhdykKICAgIGZpbmFsbHk6CiAg'
    'ICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCgoKZGVmIGVucm9sbCgpOgogICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFk'
    'X3RleHQoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2VuKToKICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfdG9rZW4nKQogICAgdHJ5OgogICAgICAgIGNhY2hlZCA9IGpzb24ubG9hZHMo'
    'KFJPT1QvJ3Byb2ZpbGUuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIGlmIChjYWNoZWQuZ2V0KCdjYScpID09IFBJTk5F'
    'RF9DQSBhbmQgY2FjaGVkLmdldCgnc2VydmVyJykgPT0gU0VSVkVSIGFuZAogICAgICAgICAgICByZS5mdWxsbWF0Y2gocidk'
    'ZXZpY2UtW2EtZjAtOV17MjR9JywgY2FjaGVkLmdldCgnaWRlbnRpdHknLCAnJykpIGFuZAogICAgICAgICAgICBjYWNoZWQu'
    'Z2V0KCdlbmRwb2ludCcpIGluIEVORFBPSU5UUyBhbmQgY2FjaGVkLmdldCgncGh5c2ljYWxfbmV0d29yaycpIGFuZAogICAg'
    'ICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd4NTA5JywgJy1pbicsIFJPT1QvJ2NsaWVudC5wZW0nLCAnLWNoZWNrZW5k'
    'Jywgc3RyKDcqODY0MDApLCAnLW5vb3V0J10sIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDApOgogICAgICAgICAgICBj'
    'b250ZXh0ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGNvbnRleHQubG9h'
    'ZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAg'
    'ICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICAgICAgICAgY3VycmVudCA9IGhhc2hsaWIuc2hhMjU2KGpzb24u'
    'ZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNv'
    'cnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgICAgICAgICAgYWRkcmVzcyA9IGNhY2hlZFsnZW5kcG9p'
    'bnQnXSBpZiBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3b3JrJykgPT0gY3VycmVudCBlbHNlIFNFUlZFUgogICAgICAgICAg'
    'ICByZXR1cm4gY2FjaGVkWydpZGVudGl0eSddLCBhZGRyZXNzCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIHNz'
    'bC5TU0xFcnJvcik6CiAgICAgICAgcGFzcwogICAgc3RhZ2UoJ3Rva2VuJywgJ9Cf0L7Qu9GD0YfQsNGOINGB0LXRgNGC0LjR'
    'hNC40LrQsNGCINC00LvRjyDRjdGC0L7Qs9C+INGD0YHRgtGA0L7QudGB0YLQstCwLicsIDI1KQogICAgaWYgbm90IChST09U'
    'LydjbGllbnQta2V5LnBlbScpLmV4aXN0cygpOgogICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ2dlbnBrZXknLCAnLWFs'
    'Z29yaXRobScsICdSU0EnLCAnLXBrZXlvcHQnLCAncnNhX2tleWdlbl9iaXRzOjMwNzInLAogICAgICAgICAgICAgICAgICct'
    'b3V0JywgUk9PVC8nY2xpZW50LWtleS5wZW0nXSwgdGltZW91dD0zMCkKICAgICAgICAoUk9PVC8nY2xpZW50LWtleS5wZW0n'
    'KS5jaG1vZCgwbzYwMCkKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6CiAgICAgICAgd3JpdGUoUk9PVC8n'
    'ZGV2aWNlJywgc2VjcmV0cy50b2tlbl9oZXgoMTYpKQogICAgY29tbWFuZChbJ29wZW5zc2wnLCAncmVxJywgJy1uZXcnLCAn'
    'LWtleScsIFJPT1QvJ2NsaWVudC1rZXkucGVtJywgJy1zdWJqJywgJy9DTj1ldmdlbml1bS1kZXZpY2UnLAogICAgICAgICAg'
    'ICAgJy1vdXQnLCBST09ULydyZXF1ZXN0LnBlbSddKQogICAgcGF5bG9hZCA9IHsndG9rZW4nOiB0b2tlbiwgJ2RldmljZSc6'
    'IChST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5zdHJpcCgpLCAnY3NyJzogKFJPT1QvJ3JlcXVlc3QucGVtJykucmVhZF90'
    'ZXh0KCl9CiAgICBsYXN0ID0gTm9uZQogICAgZm9yIGFkZHJlc3MgaW4gRU5EUE9JTlRTOgogICAgICAgIHRyeToKICAgICAg'
    'ICAgICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICAgICAgICAgIHJlcGx5ID0gdGxzX3JlcXVlc3QoYWRkcmVzcywgJy9l'
    'bnJvbGwnLCBwYXlsb2FkLCB0aW1lb3V0PTYpCiAgICAgICAgICAgIHByb2ZpbGUgPSByZXBseS5nZXQoJ3Byb2ZpbGUnLCB7'
    'fSkKICAgICAgICAgICAgaWYgcmVwbHkuZ2V0KCdvaycpIGlzIG5vdCBUcnVlIG9yIHByb2ZpbGUuZ2V0KCdjYScpICE9IFBJ'
    'Tk5FRF9DQSBvciBwcm9maWxlLmdldCgnc2VydmVyJykgIT0gU0VSVkVSOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdpbnZhbGlkX3Byb2ZpbGUnKQogICAgICAgICAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInZGV2aWNlLVthLWYw'
    'LTldezI0fScsIHByb2ZpbGUuZ2V0KCdpZGVudGl0eScsICcnKSk6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ2ludmFsaWRfaWRlbnRpdHknKQogICAgICAgICAgICB3cml0ZShST09ULydjbGllbnQucGVtJywgcHJvZmlsZVsnY2Vy'
    'dGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8nY2EucGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0'
    'ZShST09ULyd4NTA5Jy8nY2xpZW50LnBlbScsIHByb2ZpbGVbJ2NlcnRpZmljYXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJP'
    'T1QvJ3g1MDljYScvJ2NhLnBlbScsIFBJTk5FRF9DQSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJpdmF0ZScvJ2NsaWVu'
    'dC1rZXkucGVtJywgKFJPT1QvJ2NsaWVudC1rZXkucGVtJykucmVhZF90ZXh0KCkpCiAgICAgICAgICAgIGNvbW1hbmQoWydv'
    'cGVuc3NsJywgJ3ZlcmlmeScsICctcHVycG9zZScsICdzc2xjbGllbnQnLCAnLUNBZmlsZScsIFJPT1QvJ2NhLnBlbScsIFJP'
    'T1QvJ2NsaWVudC5wZW0nXSkKICAgICAgICAgICAgY3R4ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19DTElF'
    'TlQpCiAgICAgICAgICAgIGN0eC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2Ns'
    'aWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBmaW5nZXJw'
    'cmludCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2Rldics'
    'ICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgICAgICAg'
    'ICAgd3JpdGUoUk9PVC8ncHJvZmlsZS5qc29uJywganNvbi5kdW1wcyh7Kipwcm9maWxlLCAnZW5kcG9pbnQnOiBhZGRyZXNz'
    'LCAncGh5c2ljYWxfbmV0d29yayc6IGZpbmdlcnByaW50fSkpCiAgICAgICAgICAgIHJldHVybiBwcm9maWxlWydpZGVudGl0'
    'eSddLCBhZGRyZXNzCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBzc2wuU1NMRXJyb3IsIFJ1bnRpbWVFcnJvcikgYXMgZXhj'
    'OgogICAgICAgICAgICBsYXN0ID0gZXhjCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Vucm9sbG1lbnRfdW5hdmFpbGFibGUn'
    'KSBmcm9tIGxhc3QKCgpkZWYgZGFlbW9uX2NvbmZpZ3MoaWRlbnRpdHksIGFkZHJlc3MpOgogICAgUlVOVElNRS5ta2Rpciht'
    'b2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBpbmNsdWRlcyA9ICdcbicuam9pbignaW5jbHVk'
    'ZSAnK3N0cihwKSBmb3IgcGF0dGVybiBpbiAoJy9ldGMvc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYnLCAnL2V0Yy9zdHJv'
    'bmdzd2FuL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25mJykKICAgICAgICAgICAgICAgICAgICAgICAgIGZvciBwIGluIFBh'
    'dGgoJy8nKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCcvJykpKQogICAgd3JpdGUoUk9PVC8nc3Ryb25nc3dhbi5jb25mJywgZicn'
    'J2NoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0geWVzCiBpbnN0YWxsX3JvdXRlcyA9IHllcwogcm91dGluZ190YWJsZSA9IDUx'
    'ODIyCiByb3V0aW5nX3RhYmxlX3ByaW8gPSAxMDAKIHBsdWdpbnMge3sKe2luY2x1ZGVzfQogIHZpY2kge3sgc29ja2V0ID0g'
    'dW5peDovL3tSVU5USU1FfS9jaGFyb24udmljaSB9fQogIHJlc29sdmUge3sgbG9hZCA9IG5vIH19CiAga2VybmVsLWxpYmlw'
    'c2VjIHt7IGxvYWQgPSBubyB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sgam91cm5hbCB7eyBkZWZhdWx0ID0gMDsgaWtl'
    'ID0gMSB9fSB9fQonJycpCiAgICAjIEFic29sdXRlIGNyZWRlbnRpYWxzIGFyZSBsb2NhbCB0byB0aGlzIGRldmljZSwgbm90'
    'IHNoYXJlZCBieSB0aGUgYWNjb3VudCB0b2tlbi4KICAgIHdyaXRlKFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicsIGYnJydjb25u'
    'ZWN0aW9ucyB7ewogc3RhcmZpdmUge3sKICB2ZXJzaW9uID0gMgogIHJlbW90ZV9hZGRycyA9IHthZGRyZXNzfQogIHJlbW90'
    'ZV9wb3J0ID0ge0lLRV9QT1JUfQogIGxvY2FsX3BvcnQgPSA0NTAwCiAgdmlwcyA9IDAuMC4wLjAKICBwcm9wb3NhbHMgPSBh'
    'ZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtl'
    'ID0geWVzCiAgZHBkX2RlbGF5ID0gMTVzCiAgbG9jYWwge3sgYXV0aCA9IGVhcC10bHM7IGlkID0ge2lkZW50aXR5fTsgZWFw'
    'X2lkID0ge2lkZW50aXR5fTsgY2VydHMgPSB7Uk9PVH0vY2xpZW50LnBlbSB9fQogIHJlbW90ZSB7eyBhdXRoID0gcHVia2V5'
    'OyBpZCA9IHtTRVJWRVJ9OyBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbSB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5l'
    'dCB7ewogICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlE'
    'fQogICAgZXNwX3Byb3Bvc2FscyA9IGNoYWNoYTIwcG9seTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRf'
    'YWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQpzZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUgPSB7Uk9P'
    'VH0vY2xpZW50LWtleS5wZW0gfX0gfX0KJycnKQogICAgIyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVzLCBub3Qg'
    'c2VtaWNvbG9uIHNlcGFyYXRvcnMgKG5vcm1hbGl6ZSBjb21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAoJ3N0cm9u'
    'Z3N3YW4uY29uZicsICdjb25uZWN0aW9uLmNvbmYnKToKICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAgcGF0aC53'
    'cml0ZV90ZXh0KHBhdGgucmVhZF90ZXh0KCkucmVwbGFjZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4nKS5yZXBs'
    'YWNlKCcgfScsICdcbn0nKSkKICAgIHJ1bGVzID0gZicnJ3RhYmxlIGluZXQgZXZuX3N0YXJmaXZlX2d1YXJkIHt7CiBjaGFp'
    'biBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5h'
    'bWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAgbWV0YSBz'
    'a3VpZCAwIGlwIGRhZGRyIHthZGRyZXNzfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBpcHNl'
    'YyBvdXQgcmVxaWQge1JFUUlEfSBhY2NlcHQKIH19CiBjaGFpbiBmb3J3YXJkIHt7IHR5cGUgZmlsdGVyIGhvb2sgZm9yd2Fy'
    'ZCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOyB9fQp9fScnJwogICAgaW5zaWRlKFsnbmZ0JywgJy1jJywgJy1mJywgJy0n'
    'XSwgZGF0YT1ydWxlcykKICAgIGluc2lkZShbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVsZXMpCgoKZGVmIHN3YW4oKmFy'
    'Z3MsIHRpbWVvdXQ9MTUsIGNoZWNrPVRydWUpOgogICAgcmV0dXJuIGluc2lkZShbJ3N3YW5jdGwnLCAqYXJncywgJy0tdXJp'
    'JywgJ3VuaXg6Ly8nK3N0cihSVU5USU1FLydjaGFyb24udmljaScpXSwgdGltZW91dD10aW1lb3V0LCBjaGVjaz1jaGVjaykK'
    'CgpkZWYgaW5zdGFsbGVkKCk6CiAgICB0cnk6CiAgICAgICAgcmVzdWx0ID0gc3dhbignLS1saXN0LXNhcycsICctLXJhdycs'
    'IHRpbWVvdXQ9MywgY2hlY2s9RmFsc2UpCiAgICAgICAgcmV0dXJuIHJlc3VsdC5yZXR1cm5jb2RlID09IDAgYW5kICdzdGF0'
    'ZT1FU1RBQkxJU0hFRCcgaW4gcmVzdWx0LnN0ZG91dCBhbmQgJ3N0YXRlPUlOU1RBTExFRCcgaW4gcmVzdWx0LnN0ZG91dAog'
    'ICAgZXhjZXB0IChPU0Vycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICByZXR1cm4gRmFsc2UKCgpk'
    'ZWYgaGVhbHRoKCk6CiAgICB3aXRoIG5hbWVzcGFjZSgpOgogICAgICAgIHJldHVybiB0bHNfcmVxdWVzdChIRUFMVEgsICcv'
    'aGVhbHRoJywgY2xpZW50PVRydWUpLmdldCgnc2VydmljZScpID09ICdldmdlbml1bS1zdGFyZml2ZScKCgpkZWYgZG93bmxv'
    'YWQoc2l6ZT0xMDQ4NTc2KToKICAgICMgQSBib3VuZGVkIGludGVncml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBt'
    'ZWFzdXJlZCB0aGUgSVNQJ3MgbWF4aW11bSByYXRlLgogICAgYmxvY2sgPSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVt'
    'LXN0YXJmaXZlLWludGVncml0eS12MScpLmRpZ2VzdCg2NTUzNikKICAgIGV4cGVjdGVkID0gaGFzaGxpYi5zaGEyNTYoKGJs'
    'b2NrKihzaXplLy9sZW4oYmxvY2spKzEpKVs6c2l6ZV0pLmhleGRpZ2VzdCgpCiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9k'
    'ZWZhdWx0X2NvbnRleHQoY2FkYXRhPVBJTk5FRF9DQSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydj'
    'bGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICBz'
    'b2NrID0gc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChIRUFMVEgsIDg0NDMpLCB0aW1lb3V0PTEwKQogICAgICAgIHRscyA9'
    'IGNvbnRleHQud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPVNFUlZFUikKICAgICAgICBjb25uZWN0aW9uID0g'
    'aHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oSEVBTFRILCA4NDQzLCB0aW1lb3V0PTEwKTsgY29ubmVjdGlvbi5zb2NrID0g'
    'dGxzCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdGFydCA9IHRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAgY29ubmVj'
    'dGlvbi5yZXF1ZXN0KCdHRVQnLCAnL2Jsb2I/c2l6ZT0nK3N0cihzaXplKSkKICAgICAgICAgICAgcmVzcG9uc2UgPSBjb25u'
    'ZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMDoKICAgICAgICAgICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndHJhbnNmZXJfaHR0cCcpCiAgICAgICAgICAgIGRpZ2VzdCA9IGhhc2hsaWIuc2hh'
    'MjU2KCk7IHJlY2VpdmVkID0gMAogICAgICAgICAgICB3aGlsZSByZWNlaXZlZCA8IHNpemU6CiAgICAgICAgICAgICAgICBk'
    'YXRhID0gcmVzcG9uc2UucmVhZChtaW4oNjU1MzYsIHNpemUtcmVjZWl2ZWQpKQogICAgICAgICAgICAgICAgaWYgbm90IGRh'
    'dGE6CiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoZGF0YSk7IHJlY2Vp'
    'dmVkICs9IGxlbihkYXRhKQogICAgICAgICAgICBlbGFwc2VkID0gdGltZS5tb25vdG9uaWMoKS1zdGFydAogICAgICAgIGZp'
    'bmFsbHk6CiAgICAgICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQogICAgaWYgcmVjZWl2ZWQgIT0gc2l6ZSBvciBkaWdlc3Qu'
    'aGV4ZGlnZXN0KCkgIT0gZXhwZWN0ZWQ6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnRlZ3JpdHlfZmFpbGVkJykK'
    'ICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdkb3dubG9hZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFwc2Vk'
    'LzFlNiwgMiksCiAgICAgICAgICAgICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwgJ2ludGVncml0eSc6IFRy'
    'dWUsICdsaW1pdGVkX3NhbXBsZSc6IFRydWV9CgoKZGVmIGRldmljZV9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICBpbmZv'
    'PWpzb24ubG9hZHMoKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICByZXR1cm4geydkZXZp'
    'Y2VfbmFtZSc6aW5mby5nZXQoJ25hbWUnLCcnKSwnZGV2aWNlX251bWJlcic6aW5mby5nZXQoJ251bWJlcicpLAogICAgICAg'
    'ICAgICAgICAgJ2RldmljZV9uYW1lX3BlbmRpbmcnOmJvb2woaW5mby5nZXQoJ3BlbmRpbmcnKSBvciBpbmZvLmdldCgnc3lu'
    'Y19lcnJvcicpKX0KICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTpyZXR1cm4geydkZXZpY2VfbmFtZSc6JycsJ2Rl'
    'dmljZV9udW1iZXInOk5vbmUsJ2RldmljZV9uYW1lX3BlbmRpbmcnOkZhbHNlfQoKCmRlZiBzeW5jX2RldmljZV9uYW1lKG5h'
    'bWU9Tm9uZSk6CiAgICBpbXBvcnQgdW5pY29kZWRhdGEKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rva2VuJ106'
    'cmFpc2UgVmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQ'
    'uNC10L3RgtCwLicpCiAgICBpZiBuYW1lIGlzIG5vdCBOb25lOgogICAgICAgIG5hbWU9dW5pY29kZWRhdGEubm9ybWFsaXpl'
    'KCdORkMnLHN0cihuYW1lKSkuc3RyaXAoKQogICAgICAgIGlmIG5vdCAxPD1sZW4obmFtZSk8PTY0IG9yIGFueSh1bmljb2Rl'
    'ZGF0YS5jYXRlZ29yeShjKS5zdGFydHN3aXRoKCdDJykgZm9yIGMgaW4gbmFtZSk6CiAgICAgICAgICAgIHJhaXNlIFZhbHVl'
    'RXJyb3IoJ9CY0LzRjyDQtNC+0LvQttC90L4g0YHQvtC00LXRgNC20LDRgtGMINC+0YIgMSDQtNC+IDY0INC+0LHRi9GH0L3R'
    'i9GFINGB0LjQvNCy0L7Qu9C+0LIuJykKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6d3JpdGUoUk9PVC8n'
    'ZGV2aWNlJyxzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICB0cnk6aW5mbz1qc29uLmxvYWRzKChST09ULydkZXZpY2UtaW5m'
    'by5qc29uJykucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6aW5mbz17fQogICAgaWYgbmFt'
    'ZSBpcyBub3QgTm9uZTppbmZvLnVwZGF0ZShuYW1lPW5hbWUscGVuZGluZz1UcnVlKQogICAgcGF5bG9hZD17J3Rva2VuJzoo'
    'Uk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpLCdkZXZpY2UnOihST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5z'
    'dHJpcCgpfQogICAgaWYgaW5mby5nZXQoJ3BlbmRpbmcnKTpwYXlsb2FkWyduYW1lJ109aW5mb1snbmFtZSddCiAgICB0cnk6'
    'CiAgICAgICAgd2l0aCBuYW1lc3BhY2UoKSBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIGVsc2UgY29udGV4'
    'dGxpYi5udWxsY29udGV4dCgpOgogICAgICAgICAgICByZXBseT10bHNfcmVxdWVzdChTRVJWRVIsJy9kZXZpY2UnLHBheWxv'
    'YWQsdGltZW91dD01KQogICAgICAgIHZhbHVlPXJlcGx5WydkZXZpY2UnXTtudW1iZXI9aW50KHZhbHVlWydudW1iZXInXSkK'
    'ICAgICAgICBpZiBub3QgaXNpbnN0YW5jZSh2YWx1ZVsnbmFtZSddLHN0cikgb3Igbm90IDE8PWxlbih2YWx1ZVsnbmFtZSdd'
    'KTw9NjQgb3IgbnVtYmVyPDE6cmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9kZXZpY2VfbWV0YWRhdGEnKQogICAgICAgIGlu'
    'Zm89eyduYW1lJzp2YWx1ZVsnbmFtZSddLCdudW1iZXInOm51bWJlciwncGVuZGluZyc6RmFsc2UsJ3N5bmNfZXJyb3InOkZh'
    'bHNlfQogICAgZXhjZXB0IChPU0Vycm9yLFJ1bnRpbWVFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yLGh0dHAuY2xpZW50LkhU'
    'VFBFeGNlcHRpb24pOgogICAgICAgIGluZm9bJ3N5bmNfZXJyb3InXT1UcnVlCiAgICB3cml0ZShST09ULydkZXZpY2UtaW5m'
    'by5qc29uJyxqc29uLmR1bXBzKGluZm8sZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAgIHJldHVybiBkZXZpY2Vfc3RhdHVzKCkK'
    'CgpkZWYgdG9rZW5fc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQo'
    'KS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFsaWQgPSBy'
    'ZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pIGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9rZW4nOiB2'
    'YWxpZCwKICAgICAgICAgICAgJ3Rva2VuX2hpbnQnOiAnRVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hsaWIuc2hh'
    'MjU2KHRva2VuLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90b2tlbih0'
    'b2tlbik6CiAgICB0b2tlbiA9IHRva2VuLnN0cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwg'
    'dG9rZW4pOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC90YLQsCDR'
    'hNC+0YDQvNCw0YLQsCBFVk4xLeKApicpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rf'
    'b2s9VHJ1ZSkKICAgIG9sZCA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rva2VuJyku'
    'ZXhpc3RzKCkgZWxzZSAnJwogICAgaWYgb2xkID09IHRva2VuOgogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKTtyZXR1cm4K'
    'ICAgIGlmIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9RmFsc2Up'
    'LnJldHVybmNvZGUgPT0gMDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0YLQutC70Y7R'
    'h9C40YLQtSBWUE4t0YLRg9C90L3QtdC70Ywg0L/QtdGA0LXQtCDRgdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicpCiAgICAj'
    'IEEgZGlmZmVyZW50IGFjY291bnQgbmVlZHMgaXRzIG93biBkZXZpY2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNlIGl0cyBj'
    'ZXJ0aWZpY2F0ZS4KICAgIGZvciBuYW1lIGluICgnZGV2aWNlLWluZm8uanNvbicsICdkZXZpY2UnLCAnY2xpZW50LWtleS5w'
    'ZW0nLCAnY2xpZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdwcml2'
    'YXRlL2NsaWVudC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScpOgogICAgICAgIChST09UL25hbWUpLnVubGluayhtaXNz'
    'aW5nX29rPVRydWUpCiAgICB3cml0ZShST09ULyd0b2tlbicsIHRva2VuKQogICAgc3luY19kZXZpY2VfbmFtZSgpCiAgICBz'
    'dGFnZSgnb2ZmJywgJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC70Y7R'
    'h9C40YLRjMK7LicsIDAsIGFjdGl2ZT1GYWxzZSwgbWV0cmljcz17fSkKCgpkZWYgY29ubmVjdCh0b2tlbj0nJywgcmVwYWly'
    'PUZhbHNlKToKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgaWYg'
    'dG9rZW46CiAgICAgICAgc2F2ZV90b2tlbih0b2tlbikKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rva2VuJ106'
    'CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+'
    '0LrQtdC9INC60LvQuNC10L3RgtCwLicpCiAgICBlbnN1cmVfZGVwZW5kZW5jaWVzKCkKICAgIGlmIHJlcGFpcjoKICAgICAg'
    'ICB3cml0ZShST09ULydyZWNhbGlicmF0ZScsICcxJykKICAgIHVuaXQgPSBmJycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2Vu'
    'aXVtIEhTVkRTIGZ1bGwtZGV2aWNlIEVzdG9uaWEgVlBOCkFmdGVyPW5ldHdvcmsudGFyZ2V0CltTZXJ2aWNlXQpUeXBlPXNp'
    'bXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwKRXhlY1N0b3BQ'
    'b3N0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BT'
    'ZWM9MjAKS2lsbE1vZGU9bWl4ZWQKVU1hc2s9MDA3NwpNZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PW5vCicnJwogICAgd3JpdGUo'
    'UGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1VOSVQsIHVuaXQpCiAgICByZWNvdmVyeSA9ICJldmdlbml1bS1zdGFyZml2'
    'ZS10dW5uZWwtcmVjb3Zlci5zZXJ2aWNlIgogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL3JlY292ZXJ5'
    'LCAiIiJbVW5pdF0KRGVzY3JpcHRpb249UmVjb3ZlciBvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0IHJl'
    'c291cmNlcwpEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUu'
    'dGFyZ2V0IHZwbi14cmF5LnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmlu'
    'L3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwtY2xlYW51cApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50'
    'YXJnZXQKIiIiKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lz'
    'dGVtY3RsJywgJ2VuYWJsZScsIHJlY292ZXJ5XSkKICAgIHN0YWdlKCdzdGFydGluZycgLCAn0JPQvtGC0L7QstC70Y4g0L/Q'
    'vtC00LrQu9GO0YfQtdC90LjQtSDRh9C10YDQtdC3IEhTVkRTINCyINCt0YHRgtC+0L3QuNGOLicsIDIsIGFjdGl2ZT1GYWxz'
    'ZSwgcmV0cnk9MCwgZXJyb3JfY29kZT0nJykKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAncmVzdGFydCcgaWYgcmVwYWly'
    'IGVsc2UgJ3N0YXJ0JywgVU5JVF0pCiAgICBwcmludCgnVlBOINC30LDQv9GD0YHQutCw0LXRgtGB0Y8uJyxmbHVzaD1UcnVl'
    'KQoKCmRlZiBkaXNjb25uZWN0KCk6CiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ3N0b3AnLCBVTklUXSwgY2hlY2s9RmFs'
    'c2UsIHRpbWVvdXQ9MjUpCiAgICBjbGVhbnVwKCkKICAgIGNsZWFudXBfZnVsbChyZWxlYXNlPVRydWUpCiAgICBzdGFnZSgn'
    'b2ZmJywgJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsIDAsIGFjdGl2ZT1GYWxzZSkKICAgIHByaW50KCdWUE4g0LLRi9C60LvR'
    'jtGH0LXQvS4nKQoKCmRlZiBzdGFydF9kYWVtb24oZW52KToKICAgIChSVU5USU1FLydjaGFyb24udmljaScpLnVubGluayht'
    'aXNzaW5nX29rPVRydWUpCiAgICBsb2cgPSAoUk9PVC8nY2hhcm9uLmxvZycpLm9wZW4oJ3cnKQogICAgZGFlbW9uID0gc3Vi'
    'cHJvY2Vzcy5Qb3BlbihbJ2lwJywgJ25ldG5zJywgJ2V4ZWMnLCBOUywgY2hhcm9uX2JpbmFyeSgpXSwKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgZW52PWVudiwgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRvdXQ9bG9nLCBzdGRlcnI9'
    'bG9nKQogICAgbG9nLmNsb3NlKCkKICAgIGZvciBfIGluIHJhbmdlKDYwKToKICAgICAgICBpZiBTVE9QIG9yIGRhZW1vbi5w'
    'b2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZGFlbW9uX3N0b3BwZWQnKQogICAg'
    'ICAgIGlmIChSVU5USU1FLydjaGFyb24udmljaScpLmV4aXN0cygpIGFuZCBzd2FuKCctLXN0YXRzJywgY2hlY2s9RmFsc2Us'
    'IHRpbWVvdXQ9MSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICBicmVhawogICAgICAgIHRpbWUuc2xlZXAoLjEpCiAg'
    'ICBzd2FuKCctLWxvYWQtY3JlZHMnLCAnLS1ub3Byb21wdCcsICctLWZpbGUnLCBST09ULydjb25uZWN0aW9uLmNvbmYnKQog'
    'ICAgc3dhbignLS1sb2FkLWNvbm5zJywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICByZXR1cm4gZGFl'
    'bW9uCgoKZGVmIHdvcmtlcigpOgogICAgZ2xvYmFsIFNUT1AKICAgIFNUT1AgPSBGYWxzZQogICAgc2lnbmFsLnNpZ25hbChz'
    'aWduYWwuU0lHVEVSTSwgbGFtYmRhICpfOiBnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLCBUcnVlKSkKICAgIHNpZ25h'
    'bC5zaWduYWwoc2lnbmFsLlNJR0lOVCwgbGFtYmRhICpfOiBnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLCBUcnVlKSkK'
    'ICAgIGRhZW1vbiA9IE5vbmUKICAgIHRyeToKICAgICAgICBjbGVhbnVwKCkKICAgICAgICByZWZyZXNoX3JldGFpbmVkX2d1'
    'YXJkKCkKICAgICAgICBzdGFnZSgncHJlcGFyZScsICfQk9C+0YLQvtCy0LvRjiDQt9Cw0YnQuNGJ0ZHQvdC90L7QtSDRgdC+'
    '0LXQtNC40L3QtdC90LjQtSDRgSBIU1ZEUy4nLCA4LCBhY3RpdmU9RmFsc2UpCiAgICAgICAgc2V0dXBfbmV0d29yaygpCiAg'
    'ICAgICAgdHJ5OgogICAgICAgICAgICByZWZlcmVuY2UgPSAoeydza2lwcGVkJzogJ2d1YXJkX2FjdGl2ZSd9IGlmIGZ1bGxf'
    'Z3VhcmRfYWN0aXZlKCkgZWxzZSByZWZlcmVuY2Vfc2FtcGxlKGZvcmNlPShST09ULydyZWNhbGlicmF0ZScpLmV4aXN0cygp'
    'KSkKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFJ1bnRpbWVFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHJlZmVy'
    'ZW5jZSA9IHsnYXZhaWxhYmxlJzogRmFsc2UsICdwcm92aWRlcic6ICdZYW5kZXggSW50ZXJuZXRvbWV0ZXInfQogICAgICAg'
    'IChST09ULydyZWNhbGlicmF0ZScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgc3RhZ2UoJ3Rva2VuJywgJ9Cf'
    '0YDQvtCy0LXRgNGP0Y4g0YLQvtC60LXQvSDQuCDRgdC+0YXRgNCw0L3RkdC90L3QvtC1INC/0L7QtNC60LvRjtGH0LXQvdC4'
    '0LUg0Y3RgtC+0LPQviDRg9GB0YLRgNC+0LnRgdGC0LLQsC4nLCAyMCkKICAgICAgICBpZGVudGl0eSwgYWRkcmVzcyA9IGVu'
    'cm9sbCgpCiAgICAgICAgc3luY19kZXZpY2VfbmFtZSgpCiAgICAgICAgc2NvcGUgPSAncHVibGljLWFkZHJlc3MnCiAgICAg'
    'ICAgc3RhZ2UoJ2RhZW1vbicsICfQl9Cw0L/Rg9GB0LrQsNGOINGC0YPQvdC90LXQu9GMIElLRXYyINCg0L7RgdGB0LjRjyDi'
    'hpIg0K3RgdGC0L7QvdC40Y8uJywgNDAsIHNjb3BlPXNjb3BlKQogICAgICAgIGRhZW1vbl9jb25maWdzKGlkZW50aXR5LCBh'
    'ZGRyZXNzKQogICAgICAgIGVudiA9IHsqKm9zLmVudmlyb24sICdTVFJPTkdTV0FOX0NPTkYnOiBzdHIoUk9PVC8nc3Ryb25n'
    'c3dhbi5jb25mJyl9CiAgICAgICAgZW52LnBvcCgnTk9USUZZX1NPQ0tFVCcsIE5vbmUpCiAgICAgICAgZGFlbW9uID0gc3Rh'
    'cnRfZGFlbW9uKGVudikKICAgICAgICBzdGFnZSgnaGFuZHNoYWtlJywgJ9Cj0YHRgtCw0L3QsNCy0LvQuNCy0LDRjiDQt9Cw'
    '0YnQuNGJ0ZHQvdC90L7QtSDRgdC+0LXQtNC40L3QtdC90LjQtSDRgSBIU1ZEUy4nLCA2MCkKICAgICAgICBzd2FuKCctLWlu'
    'aXRpYXRlJywgJy0tY2hpbGQnLCAnc3RhcmZpdmUtbmV0JywgdGltZW91dD0zNSkKICAgICAgICBpZiBub3QgaW5zdGFsbGVk'
    'KCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignc2Ffbm90X2luc3RhbGxlZCcpCiAgICAgICAgc3RhZ2UoJ2hl'
    'YWx0aCcsICfQn9GA0L7QstC10YDRj9GOINGC0YPQvdC90LXQu9GMINC4INC30LDRidC40YnRkdC90L3Ri9C5INC+0YLQstC1'
    '0YIg0YHQtdGA0LLQtdGA0LAuJywgNzUpCiAgICAgICAgaWYgbm90IGhlYWx0aCgpOgogICAgICAgICAgICByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ2hlYWx0aF9mYWlsZWQnKQogICAgICAgIHN0YWdlKCdtZWFzdXJlJywgJ9Cf0YDQvtCy0LXRgNGP0Y4g0L/Q'
    'tdGA0LXQtNCw0YfRgyDQtNCw0L3QvdGL0YUg0Lgg0YbQtdC70L7RgdGC0L3QvtGB0YLRjCDRhNCw0LnQu9CwLicsIDg1KQog'
    'ICAgICAgIG1ldHJpY3MgPSBkb3dubG9hZCgpCiAgICAgICAgbWV0cmljc1sncmVmZXJlbmNlJ10gPSByZWZlcmVuY2UKICAg'
    'ICAgICBzdGFnZSgncm91dGluZycsICfQn9C+0LTQutC70Y7Rh9Cw0Y4g0LLQtdGB0Ywg0YLRgNCw0YTQuNC6INC60L7QvNC/'
    '0YzRjtGC0LXRgNCwINC6INCy0YvRhdC+0LTRgyDQsiDQrdGB0YLQvtC90LjQuC4nLCA5MikKICAgICAgICBhY3RpdmF0ZV9m'
    'dWxsKGFkZHJlc3MpCiAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsICfQn9C+0LTQutC70Y7Rh9C10L3Qvjog0LrQvtC80L/R'
    'jNGO0YLQtdGAIOKGkiBIU1ZEUyDihpIg0K3RgdGC0L7QvdC40Y8uICcsIDEwMCwKICAgICAgICAgICAgICBhY3RpdmU9VHJ1'
    'ZSwgbWV0cmljcz1tZXRyaWNzLCBzaW5jZT1pbnQodGltZS50aW1lKCkpKQogICAgICAgIGZhaWx1cmVzID0gMAogICAgICAg'
    'IHdoaWxlIG5vdCBTVE9QOgogICAgICAgICAgICBmb3IgXyBpbiByYW5nZSgxMDApOgogICAgICAgICAgICAgICAgaWYgU1RP'
    'UDoKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICAgICAg'
    'aWYgU1RPUDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIGlmIHBvbGlj'
    'eSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICBwb2xpY3kuZW5zdXJlX3JvdXRlKCkKICAgICAgICAgICAgICAg'
    'IG9rID0gZGFlbW9uLnBvbGwoKSBpcyBOb25lIGFuZCBpbnN0YWxsZWQoKSBhbmQgaGVhbHRoKCkKICAgICAgICAgICAgICAg'
    'IGlmIG9rIGFuZCBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgICAgICAgICAgICAgIHN0YWdlKCdlZ3Jlc3Nfd2FpdCcs'
    'ICdIU1ZEUyDQtNC+0YHRgtGD0L/QtdC9OyDQvtC20LjQtNCw0Y4g0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjRjyDQstGL'
    '0YXQvtC00LAg0LIg0K3RgdGC0L7QvdC40LguJywgOTAsIGFjdGl2ZT1GYWxzZSkKICAgICAgICAgICAgICAgICAgICBjb250'
    'aW51ZQogICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFJ1bnRpbWVFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJl'
    'ZCk6CiAgICAgICAgICAgICAgICBvayA9IEZhbHNlCiAgICAgICAgICAgIGZhaWx1cmVzID0gMCBpZiBvayBlbHNlIGZhaWx1'
    'cmVzKzEKICAgICAgICAgICAgaWYgZmFpbHVyZXMgPT0gMToKICAgICAgICAgICAgICAgIHN0YWdlKCdjaGVja2luZycsICfQ'
    'ntGC0LLQtdGCIEhTVkRTINC30LDQtNC10YDQttC40LLQsNC10YLRgdGPLiDQn9GA0L7QstC10YDRj9GOINGB0L7QtdC00LjQ'
    'vdC10L3QuNC1LicsIDkwLCBhY3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBpZiBm'
    'YWlsdXJlcyA+PSAyOgogICAgICAgICAgICAgICAgc3RhZ2UoJ3JlcGFpcmluZycsICfQodCy0Y/Qt9GMINGBIEhTVkRTINC/'
    '0L7RgtC10YDRj9C90LAuINCS0L7RgdGB0YLQsNC90LDQstC70LjQstCw0Y4gVlBOLdGC0YPQvdC90LXQu9GMLicsIDYwLCBh'
    'Y3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICBpZiBkYWVtb24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICAg'
    'ICAgICAgIGluc2lkZShbJ2lwJywgJ3hmcm0nLCAnc3RhdGUnLCAnZmx1c2gnXSkKICAgICAgICAgICAgICAgICAgICBpbnNp'
    'ZGUoWydpcCcsICd4ZnJtJywgJ3BvbGljeScsICdmbHVzaCddKQogICAgICAgICAgICAgICAgICAgIGluc2lkZShbJ2lwJywg'
    'J3JvdXRlJywgJ2ZsdXNoJywgJ3RhYmxlJywgJzUxODIyJ10sIGNoZWNrPUZhbHNlKQogICAgICAgICAgICAgICAgICAgIGRh'
    'ZW1vbiA9IHN0YXJ0X2RhZW1vbihlbnYpCiAgICAgICAgICAgICAgICBzd2FuKCctLXRlcm1pbmF0ZScsICctLWlrZScsICdz'
    'dGFyZml2ZScsIGNoZWNrPUZhbHNlKQogICAgICAgICAgICAgICAgc3dhbignLS1pbml0aWF0ZScsICctLWNoaWxkJywgJ3N0'
    'YXJmaXZlLW5ldCcsIHRpbWVvdXQ9MzUpCiAgICAgICAgICAgICAgICBpZiBub3QgaW5zdGFsbGVkKCkgb3Igbm90IGhlYWx0'
    'aCgpOgogICAgICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVjb3ZlcnlfZmFpbGVkJykKICAgICAgICAg'
    'ICAgICAgIGZ1bGxfbmFtZXNwYWNlKGFkZHJlc3MpCiAgICAgICAgICAgICAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgog'
    'ICAgICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZXN0b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgICAgICAg'
    'ICAgICAgIGZhaWx1cmVzID0gMAogICAgICAgICAgICBzdGFnZSgnY29ubmVjdGVkJywgJ9Cf0L7QtNC60LvRjtGH0LXQvdC+'
    'OiDQutC+0LzQv9GM0Y7RgtC10YAg4oaSIEhTVkRTIOKGkiDQrdGB0YLQvtC90LjRjy4gJywgMTAwLCBhY3RpdmU9VHJ1ZSkK'
    'ICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvciwgUnVudGltZUVycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVk'
    'KSBhcyBleGM6CiAgICAgICAgY29kZSA9IHN0cihleGMpIGlmIHJlLmZ1bGxtYXRjaChyIlthLXpfXXsxLDY0fSIsIHN0cihl'
    'eGMpKSBlbHNlIHR5cGUoZXhjKS5fX25hbWVfXwogICAgICAgIGN1cnJlbnQgPSBzYXZlZCgpLmdldCgncGhhc2UnLCAncHJl'
    'cGFyZScpCiAgICAgICAgbWVzc2FnZSA9IHsndG9rZW4nOiAn0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTRgtCy0LXRgNC0'
    '0LjRgtGMINGC0L7QutC10L0g0LjQu9C4INC/0L7Qu9GD0YfQuNGC0Ywg0YHQtdGA0YLQuNGE0LjQutCw0YIgSFNWRFMuJywK'
    'ICAgICAgICAgICAgICAgICAgICdoYW5kc2hha2UnOiAnSFNWRFMg0L3QtSDQv9C+0LTRgtCy0LXRgNC00LjQuyDQv9C+0LTQ'
    'utC70Y7Rh9C10L3QuNC1IElLRXYyLicsCiAgICAgICAgICAgICAgICAgICAnbWVhc3VyZSc6ICfQn9GA0L7QstC10YDQutCw'
    'INC/0LXRgNC10LTQsNGH0Lgg0LTQsNC90L3Ri9GFINC90LUg0L/RgNC+0YjQu9CwLicsCiAgICAgICAgICAgICAgICAgICAn'
    'cmVwYWlyaW5nJzogJ9CQ0LLRgtC+0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjQtSDQvdC1INGD0LTQsNC70L7RgdGMLiDQ'
    'ndCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nfS5nZXQoY3VycmVudCwgJ1ZQTi3RgtGD0L3QvdC10LvRjCDQ'
    'vdC1INC30LDQv9GD0YHRgtC40LvRgdGPLiDQndCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nKQogICAgICAg'
    'IHN0YWdlKCdmYWlsZWQnLCBtZXNzYWdlKygnINCY0L3RgtC10YDQvdC10YIg0LfQsNCx0LvQvtC60LjRgNC+0LLQsNC9INC0'
    '0L4g0L7RgtC60LvRjtGH0LXQvdC40Y8g0YDQtdC20LjQvNCwLicgaWYgZnVsbF9ndWFyZF9hY3RpdmUoKSBlbHNlICcg0JzQ'
    'sNGA0YjRgNGD0YLQuNC30LDRhtC40Y8g0LrQvtC80L/RjNGO0YLQtdGA0LAg0L3QtSDQv9C10YDQtdC60LvRjtGH0LXQvdCw'
    'LicpLCAwLCBhY3RpdmU9RmFsc2UsIGVycm9yX2NvZGU9Y29kZSwgbWV0cmljcz17fSkKICAgIGZpbmFsbHk6CiAgICAgICAg'
    'aWYgZGFlbW9uIGFuZCBkYWVtb24ucG9sbCgpIGlzIE5vbmU6CiAgICAgICAgICAgIGRhZW1vbi50ZXJtaW5hdGUoKQogICAg'
    'ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBkYWVtb24ud2FpdCh0aW1lb3V0PTYpCiAgICAgICAgICAgIGV4Y2VwdCBz'
    'dWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOgogICAgICAgICAgICAgICAgZGFlbW9uLmtpbGwoKTsgZGFlbW9uLndhaXQodGlt'
    'ZW91dD0zKQogICAgICAgIGNsZWFudXAoKQogICAgICAgIGlmIFNUT1A6CiAgICAgICAgICAgIHN0YWdlKCdvZmYnLCAnVlBO'
    'INCy0YvQutC70Y7Rh9C10L0uJywgMCwgYWN0aXZlPUZhbHNlKQo='
)
NETWORK_POLICY_PY_B64 = (
    'IiIiTG9jYWwgdHJhZmZpYyBzZWxlY3Rpb24gZm9yIHRoZSB0b2tlbiB0dW5uZWwuIE5vIHJlbW90ZSBwcm94eSBwcm90b2Nv'
    'bC4iIiIKaW1wb3J0IGZjbnRsCmltcG9ydCBpcGFkZHJlc3MKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmZyb20gcGF0aGxpYiBp'
    'bXBvcnQgUGF0aAppbXBvcnQgcmUKaW1wb3J0IHRpbWUKCmFwaSA9IE5vbmUKdHVubmVsID0gTm9uZQpQQVRIID0gUGF0aCgn'
    'L2V0Yy92cG4tbWFuYWdlci9wb2xpY3kuanNvbicpClJVTiA9IFBhdGgoJy9ydW4vdnBuLW1hbmFnZXInKQpTRVJWSUNFID0g'
    'J2V2Z2VuaXVtLXBvbGljeS5zZXJ2aWNlJwpXQVlEUk9JRF9TRVJWSUNFID0gJ2V2Z2VuaXVtLXdheWRyb2lkLW5ldHdvcmsu'
    'c2VydmljZScKVFVOID0gJ2V2bi1wb2xpY3knCkRJUkVDVCA9IDB4NDU1NjRFMzEKVlBOID0gMHg0NTU2NEUzMgpQSFlTSUNB'
    'TF9UQUJMRSA9ICc1MTgzMCcKVlBOX1RBQkxFID0gJzUxODMxJwpETlNfUE9SVCA9IDE4NTUzCkNIRUNLX1BPUlQgPSAxODU1'
    'NApDQVRFR09SSUVTID0gKCdhcHBsaWNhdGlvbnMnLCduZXR3b3JrcycsJ3BvcnRzJywnZG5zJykKQkFTRSA9IHsKICdhcHBs'
    'aWNhdGlvbnMnOiBbeydpZCc6J21hcHBlcicsJ3ZhbHVlJzonZXZnZW5pdW0td2F5ZHJvaWQtbWFwcGVyJywnbGFiZWwnOidX'
    'YXlkcm9pZCBNYXBwZXInfV0sCiAnbmV0d29ya3MnOiBbeydpZCc6J2xhbicsJ3ZhbHVlJzonY29ubmVjdGVkJywnbGFiZWwn'
    'OifQo9GB0YLRgNC+0LnRgdGC0LLQsCDRgtC10LrRg9GJ0LXQuSDQu9C+0LrQsNC70YzQvdC+0Lkg0YHQtdGC0LgnfSwKICAg'
    'ICAgICAgICAgICB7J2lkJzonbGlua2xvY2FsJywndmFsdWUnOicxNjkuMjU0LjAuMC8xNicsJ2xhYmVsJzon0KPRgdGC0YDQ'
    'vtC50YHRgtCy0LAg0YEg0LDQstGC0L7QvNCw0YLQuNGH0LXRgdC60LjQvCDQu9C+0LrQsNC70YzQvdGL0Lwg0LDQtNGA0LXR'
    'gdC+0LwnfV0sCiAncG9ydHMnOiBbeydpZCc6J2Rpc2NvdmVyeScsJ3ZhbHVlJzonZGlzY292ZXJ5JywnbGFiZWwnOifQntCx'
    '0L3QsNGA0YPQttC10L3QuNC1INGD0YHRgtGA0L7QudGB0YLQsjogbUROUywgU1NEUCwgTExNTlIgKNGC0L7Qu9GM0LrQviDQ'
    'u9C+0LrQsNC70YzQvdCw0Y8g0YHQtdGC0YwpJ31dLAogJ2Rucyc6IFt7J2lkJzonc3R1YicsJ3ZhbHVlJzonMTI3LjAuMC4w'
    'LzgnLCdsYWJlbCc6J9Ch0LjRgdGC0LXQvNC90YvQuSBETlMg0LLQvdGD0YLRgNC4INC60L7QvNC/0YzRjtGC0LXRgNCwJ31d'
    'Cn0KCmRlZiBkZWZhdWx0cygpOgogcmV0dXJuIHsnc2NoZW1hJzoxLCd3YXlkcm9pZF9kaXJlY3QnOlRydWUsJ2Rpc2FibGVk'
    'X2Jhc2UnOltdLCAnYXBwbGljYXRpb25zJzpbXSwgJ25ldHdvcmtzJzpbXSwgJ3BvcnRzJzpbXSwgJ2Rucyc6W119CgpkZWYg'
    'bG9hZCgpOgogaWYgbm90IFBBVEguZXhpc3RzKCk6cmV0dXJuIGRlZmF1bHRzKCkKIHZhbHVlPWpzb24ubG9hZHMoUEFUSC5y'
    'ZWFkX3RleHQoKSkKIGlmIHZhbHVlLmdldCgnc2NoZW1hJykhPTE6cmFpc2UgUnVudGltZUVycm9yKCfQndC10LjQt9Cy0LXR'
    'gdGC0L3QsNGPINCy0LXRgNGB0LjRjyDQv9GA0LDQstC40Lsg0LjRgdC60LvRjtGH0LXQvdC40LkuJykKIHJldHVybiB7Kipk'
    'ZWZhdWx0cygpLCoqdmFsdWV9CgpkZWYgc2F2ZSh2YWx1ZSk6CiBQQVRILnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsZXhp'
    'c3Rfb2s9VHJ1ZSkKIHRtcD1QQVRILndpdGhfc3VmZml4KCcubmV3JykKIGZkPW9zLm9wZW4odG1wLG9zLk9fV1JPTkxZfG9z'
    'Lk9fQ1JFQVR8b3MuT19UUlVOQ3xvcy5PX05PRk9MTE9XLDBvNjAwKQogd2l0aCBvcy5mZG9wZW4oZmQsJ3cnKSBhcyBmOmpz'
    'b24uZHVtcCh2YWx1ZSxmLGVuc3VyZV9hc2NpaT1GYWxzZSxpbmRlbnQ9MikKIG9zLnJlcGxhY2UodG1wLFBBVEgpCgpkZWYg'
    'ZW5hYmxlZChwLGNhdCxrZXkpOnJldHVybiBjYXQrJzonK2tleSBub3QgaW4gcFsnZGlzYWJsZWRfYmFzZSddCgpkZWYgbm9y'
    'bWFsaXplKGNhdGVnb3J5LHZhbHVlKToKIHZhbHVlPXN0cih2YWx1ZSkuc3RyaXAoKQogaWYgbm90IHZhbHVlIG9yIGxlbih2'
    'YWx1ZSk+NTEyIG9yIGFueShvcmQoYyk8MzIgZm9yIGMgaW4gdmFsdWUpOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQutC+0YDR'
    'gNC10LrRgtC90L7QtSDQuNGB0LrQu9GO0YfQtdC90LjQtS4nKQogaWYgY2F0ZWdvcnk9PSdhcHBsaWNhdGlvbnMnOgogIGlm'
    'IG5vdCByZS5mdWxsbWF0Y2gocidbXHcuLyArQCgpXC1dKycsdmFsdWUpOnJhaXNlIFZhbHVlRXJyb3IoJ9Cj0LrQsNC20LjR'
    'gtC1INC40LzRjyDQv9GA0L7RhtC10YHRgdCwINC40LvQuCDQv9C+0LvQvdGL0Lkg0L/Rg9GC0YwuJykKICBpZiAnLycgaW4g'
    'dmFsdWUgYW5kIG5vdCB2YWx1ZS5zdGFydHN3aXRoKCcvJyk6cmFpc2UgVmFsdWVFcnJvcign0J/Rg9GC0Ywg0LTQvtC70LbQ'
    'tdC9INCx0YvRgtGMINCw0LHRgdC+0LvRjtGC0L3Ri9C8LicpCiAgcmV0dXJuIHZhbHVlCiBpZiBjYXRlZ29yeT09J25ldHdv'
    'cmtzJzoKICB0cnk6CiAgIG5ldD1pcGFkZHJlc3MuaXBfbmV0d29yayh2YWx1ZSxzdHJpY3Q9RmFsc2UpCiAgIGlmIG5ldC52'
    'ZXJzaW9uIT00OnJhaXNlIFZhbHVlRXJyb3IoJ9Cf0L7QtNC00LXRgNC20LjQstCw0Y7RgtGB0Y8g0LDQtNGA0LXRgdCwINCy'
    '0LjQtNCwIDE5Mi4xNjguMS4xMC4nKQogICAjIEFkZHJlc3NlcyBvd25lZCBieSBvdXIgdHVubmVscyBjYW5ub3QgYmUgcm91'
    'dGVkIHBoeXNpY2FsbHkuCiAgIHJlc2VydmVkPVsnMTAuNzcuMC4wLzI0Jyx0dW5uZWwuTkVUV09SSyx0dW5uZWwuRlVMTF9O'
    'RVQsJzE5OC4xOC4yNTQuMC8zMCddIGlmIHR1bm5lbCBlbHNlIFsnMTAuNzcuMC4wLzI0JywnMTcyLjI5LjI0Ni4wLzMwJywn'
    'MTcyLjI5LjI0Ny4wLzMwJywnMTk4LjE4LjI1NC4wLzMwJ10KICAgaWYgYW55KG5ldC5vdmVybGFwcyhpcGFkZHJlc3MuaXBf'
    'bmV0d29yayhuKSkgZm9yIG4gaW4gcmVzZXJ2ZWQpOnJhaXNlIFZhbHVlRXJyb3IoJ9CU0LjQsNC/0LDQt9C+0L0g0L/QtdGA'
    '0LXRgdC10LrQsNC10YLRgdGPINGB0L4g0YHQu9GD0LbQtdCx0L3QvtC5INGB0LXRgtGM0Y4gVlBOLiDQlNC+0LHQsNCy0YzR'
    'gtC1INCx0L7Qu9C10LUg0YPQt9C60YPRjiDRgdC10YLRjC4nKQogICByZXR1cm4gc3RyKG5ldCkKICBleGNlcHQgVmFsdWVF'
    'cnJvciBhcyBleGM6CiAgIGlmICcvJyBpbiB2YWx1ZSBvciByZS5mdWxsbWF0Y2gocidbXGQuXSsnLHZhbHVlKTpyYWlzZSBl'
    'eGMKICBleGFjdD12YWx1ZS5zdGFydHN3aXRoKCc9Jyk7dmFsdWU9dmFsdWUubHN0cmlwKCc9JykubG93ZXIoKS5yc3RyaXAo'
    'Jy4nKQogIHRyeTp2YWx1ZT12YWx1ZS5lbmNvZGUoJ2lkbmEnKS5kZWNvZGUoJ2FzY2lpJykKICBleGNlcHQgVW5pY29kZUVy'
    'cm9yOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90YvQuSDQtNC+0LzQtdC9LicpCiAgaWYgbGVuKHZh'
    'bHVlKT4yNTMgb3Igbm90IGFsbChyZS5mdWxsbWF0Y2gocidbYS16MC05XSg/OlthLXowLTktXXswLDYxfVthLXowLTldKT8n'
    'LHgpIGZvciB4IGluIHZhbHVlLnNwbGl0KCcuJykpOnJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC00L7QvNC1'
    '0L0g0LHQtdC3IGh0dHBzOi8vINC4INC/0YPRgtC4LicpCiAgcmV0dXJuICgnPScgaWYgZXhhY3QgZWxzZSAnJykrdmFsdWUK'
    'IGlmIGNhdGVnb3J5PT0nZG5zJzoKICBhZGRyPWlwYWRkcmVzcy5pcF9hZGRyZXNzKHZhbHVlKQogIGlmIGFkZHIudmVyc2lv'
    'biE9NCBvciBhZGRyLmlzX3Vuc3BlY2lmaWVkIG9yIGFkZHIuaXNfbXVsdGljYXN0IG9yIGFkZHIuaXNfbG9vcGJhY2s6cmFp'
    'c2UgVmFsdWVFcnJvcign0KPQutCw0LbQuNGC0LUg0LDQtNGA0LXRgSDQstC90LXRiNC90LXQs9C+INC40LvQuCDQtNC+0LzQ'
    'sNGI0L3QtdCz0L4gRE5TLdGB0LXRgNCy0LXRgNCwOyDQu9C+0LrQsNC70YzQvdGL0LkgRE5TINC90LDRhdC+0LTQuNGC0YHR'
    'jyDQsiDQsdCw0LfQvtCy0YvRhSDQv9GA0LDQstC40LvQsNGFLicpCiAgcmV0dXJuIHN0cihhZGRyKQogaWYgY2F0ZWdvcnk9'
    'PSdwb3J0cyc6CiAgbWF0Y2g9cmUuZnVsbG1hdGNoKHInKHRjcHx1ZHB8Ym90aCk6KFxkezEsNX0pKD86OihvdXR8aW58Ym90'
    'aCkpPycsdmFsdWUubG93ZXIoKSkKICBpZiBub3QgbWF0Y2ggb3Igbm90IDE8PWludChtYXRjaFsyXSk8PTY1NTM1OnJhaXNl'
    'IFZhbHVlRXJyb3IoJ9Ck0L7RgNC80LDRgjogdGNwOjQ0MzpvdXQsIHVkcDoyNTU2NTppbiDQuNC70LggYm90aDoyNTU2NTpi'
    'b3RoLicpCiAgaWYgaW50KG1hdGNoWzJdKT09NTM6cmFpc2UgVmFsdWVFcnJvcignRE5TINC90LDRgdGC0YDQsNC40LLQsNC1'
    '0YLRgdGPINCy0L4g0LLQutC70LDQtNC60LUgRE5TLicpCiAgcmV0dXJuIGYne21hdGNoWzFdfTp7aW50KG1hdGNoWzJdKX06'
    'e21hdGNoWzNdIG9yICJib3RoIn0nCiByYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGPINC60LDRgtC1'
    '0LPQvtGA0LjRjy4nKQoKZGVmIG1pZ3JhdGlvbihzZXR0aW5ncyk6CiBpZiBQQVRILmV4aXN0cygpOnJldHVybgogcD1kZWZh'
    'dWx0cygpOyByZWplY3RlZD1bXQogc291cmNlcz17J2FwcGxpY2F0aW9ucyc6c2V0dGluZ3MuZ2V0KCdkaXJlY3RfYXBwcycp'
    'LCduZXR3b3Jrcyc6c2V0dGluZ3MuZ2V0KCdkaXJlY3RfbmV0d29ya3MnKX0KIGZvciBjYXRlZ29yeSxrZXkgaW4gc291cmNl'
    'cy5pdGVtcygpOgogIGlmIGtleSBhbmQgUGF0aChrZXkpLmlzX2ZpbGUoKToKICAgZm9yIGxpbmUgaW4gUGF0aChrZXkpLnJl'
    'YWRfdGV4dCgpLnNwbGl0bGluZXMoKToKICAgIHM9bGluZS5zdHJpcCgpCiAgICBpZiBub3QgcyBvciBzLnN0YXJ0c3dpdGgo'
    'JyMnKTpjb250aW51ZQogICAgdHJ5OnBbY2F0ZWdvcnldLmFwcGVuZChub3JtYWxpemUoY2F0ZWdvcnkscykpCiAgICBleGNl'
    'cHQgVmFsdWVFcnJvcjpyZWplY3RlZC5hcHBlbmQoeydjYXRlZ29yeSc6Y2F0ZWdvcnksJ3ZhbHVlJzpzfSkKIGtleT1zZXR0'
    'aW5ncy5nZXQoJ2RpcmVjdF9zaXRlcycpCiBpZiBrZXkgYW5kIFBhdGgoa2V5KS5pc19maWxlKCk6CiAgZm9yIGxpbmUgaW4g'
    'UGF0aChrZXkpLnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKToKICAgcz1saW5lLnN0cmlwKCkKICAgaWYgbm90IHMgb3Igcy5z'
    'dGFydHN3aXRoKCcjJyk6Y29udGludWUKICAgcz1zLnJlcGxhY2UoJ2Z1bGw6JywnPScsMSkucmVtb3ZlcHJlZml4KCdkb21h'
    'aW46JykKICAgdHJ5OnBbJ25ldHdvcmtzJ10uYXBwZW5kKG5vcm1hbGl6ZSgnbmV0d29ya3MnLHMpKQogICBleGNlcHQgVmFs'
    'dWVFcnJvcjpyZWplY3RlZC5hcHBlbmQoeydjYXRlZ29yeSc6J25ldHdvcmtzJywndmFsdWUnOnN9KQogZm9yIHByb3RvLHBv'
    'cnQgaW4gYXBpLnJlYWRfc2VydmVyX3BvcnRzKHNldHRpbmdzKTpwWydwb3J0cyddLmFwcGVuZChmJ3twcm90b306e3BvcnR9'
    'OmluJykKIGZvciBjIGluIENBVEVHT1JJRVM6cFtjXT1saXN0KGRpY3QuZnJvbWtleXMocFtjXSkpCiBwWydtaWdyYXRpb25f'
    'c2tpcHBlZCddPXJlamVjdGVkCiBzYXZlKHApCgpkZWYgcHVibGljKCk6CiBwPWxvYWQoKTtiYXNlPXt9CiBmb3IgYyxlbnRy'
    'aWVzIGluIEJBU0UuaXRlbXMoKTpiYXNlW2NdPVt7KiplLCdlbmFibGVkJzplbmFibGVkKHAsYyxlWydpZCddKX0gZm9yIGUg'
    'aW4gZW50cmllc10KIHJldHVybiB7KipwLCdiYXNlJzpiYXNlfQoKZGVmIHBvcnRzKHAsZGlyZWN0aW9uKToKIHJlc3VsdD17'
    'J3RjcCc6c2V0KCksJ3VkcCc6c2V0KCl9CiBmb3IgdmFsdWUgaW4gcFsncG9ydHMnXToKICBwcm90byxudW1iZXIsc2lkZT12'
    'YWx1ZS5zcGxpdCgnOicpCiAgaWYgc2lkZSBub3QgaW4gKGRpcmVjdGlvbiwnYm90aCcpOmNvbnRpbnVlCiAgZm9yIHByb3Rv'
    'Y29sIGluICgndGNwJywndWRwJykgaWYgcHJvdG89PSdib3RoJyBlbHNlIChwcm90bywpOnJlc3VsdFtwcm90b2NvbF0uYWRk'
    'KGludChudW1iZXIpKQogcmV0dXJuIHJlc3VsdAoKZGVmIGxvY2FsX25ldHdvcmtzKHJvdXRlKToKIGRhdGE9anNvbi5sb2Fk'
    'cyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdzaG93JywnZGV2Jyxyb3V0ZVsnZGV2J11dKS5zdGRv'
    'dXQpCiByZXR1cm4gc29ydGVkKHtzdHIoaXBhZGRyZXNzLmlwX25ldHdvcmsoZiJ7YVsnbG9jYWwnXX0ve2FbJ3ByZWZpeGxl'
    'biddfSIsc3RyaWN0PUZhbHNlKSkgZm9yIGxpbmsgaW4gZGF0YSBmb3IgYSBpbiBsaW5rLmdldCgnYWRkcl9pbmZvJyxbXSkg'
    'aWYgYS5nZXQoJ3Njb3BlJyk9PSdnbG9iYWwnfSkKCmRlZiBkaXJlY3RfbmV0d29ya3MocCxsYW4pOgogdmFsdWVzPVtdCiBm'
    'b3IgdmFsdWUgaW4gcFsnbmV0d29ya3MnXToKICB0cnk6dmFsdWVzLmFwcGVuZChzdHIoaXBhZGRyZXNzLmlwX25ldHdvcmso'
    'dmFsdWUpKSkKICBleGNlcHQgVmFsdWVFcnJvcjpwYXNzCiBpZiBlbmFibGVkKHAsJ25ldHdvcmtzJywnbGFuJyk6CiAgZm9y'
    'IGl0ZW0gaW4gbGFuOgogICByZW1haW5pbmc9W2lwYWRkcmVzcy5pcF9uZXR3b3JrKGl0ZW0pXQogICBmb3IgcmVzZXJ2ZWQg'
    'aW4gWycxMC43Ny4wLjAvMjQnLCcxNzIuMjkuMjQ2LjAvMzAnLCcxNzIuMjkuMjQ3LjAvMzAnLCcxOTguMTguMjU0LjAvMzAn'
    'XToKICAgIGJsb2NrPWlwYWRkcmVzcy5pcF9uZXR3b3JrKHJlc2VydmVkKTt1cGRhdGVkPVtdCiAgICBmb3IgbmV0IGluIHJl'
    'bWFpbmluZzoKICAgICBpZiBub3QgbmV0Lm92ZXJsYXBzKGJsb2NrKTp1cGRhdGVkLmFwcGVuZChuZXQpCiAgICAgZWxpZiBi'
    'bG9jay5zdWJuZXRfb2YobmV0KTp1cGRhdGVkLmV4dGVuZChuZXQuYWRkcmVzc19leGNsdWRlKGJsb2NrKSkKICAgIHJlbWFp'
    'bmluZz11cGRhdGVkCiAgIHZhbHVlcyArPSBbc3RyKG4pIGZvciBuIGluIHJlbWFpbmluZ10KIGlmIGVuYWJsZWQocCwnbmV0'
    'd29ya3MnLCdsaW5rbG9jYWwnKTp2YWx1ZXMrPVsnMTY5LjI1NC4wLjAvMTYnXQogcmV0dXJuIHNvcnRlZChzZXQodmFsdWVz'
    'KSkKCmRlZiBjb25maWcocCk6CiBydWxlcz1beyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2NoZWNrJ10sJ291dGJv'
    'dW5kVGFnJzondnBuJ30sCiAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1pbiddLCdvdXRib3Vu'
    'ZFRhZyc6J2Rucyd9XQogYXBwcz1saXN0KHBbJ2FwcGxpY2F0aW9ucyddKQogaWYgZW5hYmxlZChwLCdhcHBsaWNhdGlvbnMn'
    'LCdtYXBwZXInKTphcHBzKz1bJ2V2Z2VuaXVtLXdheWRyb2lkLW1hcHBlciddCiBpZiBhcHBzOnJ1bGVzLmFwcGVuZCh7J3R5'
    'cGUnOidmaWVsZCcsJ3Byb2Nlc3MnOmFwcHMsJ2luYm91bmRUYWcnOlsndHVuJ10sJ291dGJvdW5kVGFnJzonZGlyZWN0J30p'
    'CiBkb21haW5zPVtdCiBmb3IgdmFsdWUgaW4gcFsnbmV0d29ya3MnXToKICB0cnk6aXBhZGRyZXNzLmlwX25ldHdvcmsodmFs'
    'dWUpCiAgZXhjZXB0IFZhbHVlRXJyb3I6ZG9tYWlucy5hcHBlbmQoKCdmdWxsOicrdmFsdWVbMTpdKSBpZiB2YWx1ZS5zdGFy'
    'dHN3aXRoKCc9JykgZWxzZSAnZG9tYWluOicrdmFsdWUpCiBpZiBkb21haW5zOnJ1bGVzLmFwcGVuZCh7J3R5cGUnOidmaWVs'
    'ZCcsJ2RvbWFpbic6ZG9tYWlucywnaW5ib3VuZFRhZyc6Wyd0dW4nXSwnb3V0Ym91bmRUYWcnOidkaXJlY3QnfSkKICMgRE5T'
    'IGVuZ2luZSByZXF1ZXN0cyBtdXN0IG5ldmVyIGluaGVyaXQgZG9tYWluL2FwcGxpY2F0aW9uIGJ5cGFzcyBydWxlcy4KIHJ1'
    'bGVzKz1beyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUnXSwnb3V0Ym91bmRUYWcnOid2cG4nfSwK'
    'ICAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ3R1biddLCdvdXRib3VuZFRhZyc6J3Zwbid9XQogcmV0'
    'dXJuIHsnbG9nJzp7J2xvZ2xldmVsJzond2FybmluZycsJ2FjY2Vzcyc6J25vbmUnfSwKICAnaW5ib3VuZHMnOlt7J3RhZyc6'
    'J3R1bicsJ3Byb3RvY29sJzondHVuJywnc2V0dGluZ3MnOnsnbmFtZSc6VFVOLCdtdHUnOjEyODAsJ2dhdGV3YXknOlsnMTk4'
    'LjE4LjI1NC4xLzMwJ119LAogICAgICAgICAgICAgICAnc25pZmZpbmcnOnsnZW5hYmxlZCc6VHJ1ZSwnZGVzdE92ZXJyaWRl'
    'JzpbJ2h0dHAnLCd0bHMnLCdxdWljJ10sJ3JvdXRlT25seSc6VHJ1ZX19LAogICAgICAgICAgICAgIHsndGFnJzonZG5zLWlu'
    'JywnbGlzdGVuJzonMTI3LjAuMC4xJywncG9ydCc6RE5TX1BPUlQsJ3Byb3RvY29sJzonZG9rb2RlbW8tZG9vcicsJ3NldHRp'
    'bmdzJzp7J2FkZHJlc3MnOicxLjEuMS4xJywncG9ydCc6NTMsJ25ldHdvcmsnOid0Y3AsdWRwJ319LAogICAgICAgICAgICAg'
    'IHsndGFnJzonY2hlY2snLCdsaXN0ZW4nOicxMjcuMC4wLjEnLCdwb3J0JzpDSEVDS19QT1JULCdwcm90b2NvbCc6J3NvY2tz'
    'Jywnc2V0dGluZ3MnOnsnYXV0aCc6J25vYXV0aCcsJ3VkcCc6RmFsc2V9fV0sCiAgJ2Rucyc6eydzZXJ2ZXJzJzpbJzEuMS4x'
    'LjEnLCc5LjkuOS45J10sJ3F1ZXJ5U3RyYXRlZ3knOidVc2VJUHY0JywndGFnJzonZG5zLWVuZ2luZScsJ2Rpc2FibGVGYWxs'
    'YmFjayc6RmFsc2V9LAogICdvdXRib3VuZHMnOlt7J3RhZyc6dGFnLCdwcm90b2NvbCc6J2ZyZWVkb20nLCdzZXR0aW5ncyc6'
    'eydkb21haW5TdHJhdGVneSc6J1VzZUlQdjQnfSwnc3RyZWFtU2V0dGluZ3MnOnsnc29ja29wdCc6eydtYXJrJzptYXJrfX19'
    'IGZvciB0YWcsbWFyayBpbiBbKCd2cG4nLFZQTiksKCdkaXJlY3QnLERJUkVDVCldXSsKICAgICAgICAgICAgICAgW3sndGFn'
    'JzonZG5zJywncHJvdG9jb2wnOidkbnMnLCdzZXR0aW5ncyc6eydydWxlcyc6W3sncVR5cGUnOicxLDI4JywnYWN0aW9uJzon'
    'aGlqYWNrJ30seydhY3Rpb24nOidkaXJlY3QnfV19LCdzdHJlYW1TZXR0aW5ncyc6eydzb2Nrb3B0Jzp7J21hcmsnOlZQTn19'
    'fV0sCiAgJ3JvdXRpbmcnOnsnZG9tYWluU3RyYXRlZ3knOidBc0lzJywncnVsZXMnOnJ1bGVzfX0KCmRlZiBuZnRfc2V0KGl0'
    'ZW1zKTpyZXR1cm4gJ3sgJysnLCAnLmpvaW4oc3RyKHgpIGZvciB4IGluIHNvcnRlZChpdGVtcykpKycgfScKCmRlZiBmaXJl'
    'd2FsbChwLGxhbix1aWQpOgogIyBSb3V0ZSBtYXJrcyBhcmUgc2V0IG9ubHkgYnkgdGhpcyBwcml2aWxlZ2VkIGNsYXNzaWZp'
    'ZXIgb3IgZXhwbGljaXQga2VybmVsIHJ1bGVzLgogbWFyaz1bXTtkbnM9W107Zm9yd2FyZD1bXTtuYXQ9WydtZXRhIG5mcHJv'
    'dG8gaXB2NCBtZXRhIG1hcmsgJytzdHIoRElSRUNUKSsnIG9pZm5hbWUgIT0gImxvIiBtYXNxdWVyYWRlJ10KIGlmIGVuYWJs'
    'ZWQocCwnZG5zJywnc3R1YicpOmRucy5hcHBlbmQoJ2lwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybicpCiBpZiBwWydkbnMn'
    'XToKICBkbnMuYXBwZW5kKGYnaXAgZGFkZHIge25mdF9zZXQocFsiZG5zIl0pfSByZXR1cm4nKQogIG1hcmsuYXBwZW5kKGYn'
    'aXAgZGFkZHIge25mdF9zZXQocFsiZG5zIl0pfSBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgbWV0'
    'YSBtYXJrIHNldCB7RElSRUNUfSByZXR1cm4nKQogIyBJbnRlcmZhY2UtYm91bmQgc3lzdGVtIHJlc29sdmVycyBtdXN0IGtl'
    'ZXAgRE5TIG9uIHRoZSB0dW5uZWwgaW50ZXJmYWNlLgogIyBSZWRpcmVjdGluZyB0aGVpciB1cHN0cmVhbSBzb2NrZXQgdG8g'
    'bG9vcGJhY2sgYnJlYWtzIFNPX0JJTkRUT0RFVklDRS4KICMgT25seSBhbiBleHBsaWNpdGx5IGRpc2FibGVkIGxvb3BiYWNr'
    'LXN0dWIgcnVsZSB1c2VzIHRoZSBsb2NhbCBETlMgbGlzdGVuZXIuCiBkbnMrPVsnaXAgZGFkZHIgMTI3LjAuMC4wLzggbWV0'
    'YSBsNHByb3RvIHsgdGNwLCB1ZHAgfSB0aCBkcG9ydCA1MyByZWRpcmVjdCB0byA6JytzdHIoRE5TX1BPUlQpLAogICAgICAg'
    'J21ldGEgbmZwcm90byBpcHY0IG1ldGEgbDRwcm90byB7IHRjcCwgdWRwIH0gdGggZHBvcnQgNTMgZG5hdCBpcCB0byAxLjEu'
    'MS4xJ10KIG1hcmsrPVsnbWV0YSBsNHByb3RvIHsgdGNwLCB1ZHAgfSB0aCBkcG9ydCA1MyBtZXRhIG1hcmsgc2V0ICcrc3Ry'
    'KFZQTikrJyByZXR1cm4nXQogd2F5bmV0cz13YXlkcm9pZF9uZXR3b3JrKClbJ25ldHdvcmtzJ10KIG1hcmsuYXBwZW5kKGYn'
    'aXAgZGFkZHIgQHdheWRyb2lkX25ldHdvcmtzIG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIG1hcmsuYXBwZW5k'
    'KGYnb2lmbmFtZSAid2F5ZHJvaWQwIiB1ZHAgc3BvcnQgNjcgdWRwIGRwb3J0IDY4IG1ldGEgbWFyayBzZXQge0RJUkVDVH0g'
    'cmV0dXJuJykKIG5ldHM9ZGlyZWN0X25ldHdvcmtzKHAsbGFuKQogaWYgbmV0czptYXJrLmFwcGVuZChmJ2lwIGRhZGRyIHtu'
    'ZnRfc2V0KG5ldHMpfSBtZXRhIG1hcmsgc2V0IHtESVJFQ1R9IHJldHVybicpCiBpZiBlbmFibGVkKHAsJ3BvcnRzJywnZGlz'
    'Y292ZXJ5Jyk6CiAgbWFyays9WydpcCBkYWRkciB7IDIyNC4wLjAuMjUxLCAyMjQuMC4wLjI1MiwgMjM5LjI1NS4yNTUuMjUw'
    'IH0gdWRwIGRwb3J0IHsgNTM1MywgNTM1NSwgMTkwMCB9IG1ldGEgbWFyayBzZXQgJytzdHIoRElSRUNUKSsnIHJldHVybidd'
    'CiBmb3IgZGlyZWN0aW9uIGluICgnb3V0JywnaW4nKToKICBmb3IgcHJvdG8sdmFsdWVzIGluIHBvcnRzKHAsZGlyZWN0aW9u'
    'KS5pdGVtcygpOgogICBpZiB2YWx1ZXM6bWFyay5hcHBlbmQoKCdjdCBkaXJlY3Rpb24gcmVwbHkgJyBpZiBkaXJlY3Rpb249'
    'PSdpbicgZWxzZSAnJykrZid7cHJvdG99IHsic3BvcnQiIGlmIGRpcmVjdGlvbj09ImluIiBlbHNlICJkcG9ydCJ9IHtuZnRf'
    'c2V0KHZhbHVlcyl9IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIGlmIHBbJ3dheWRyb2lkX2RpcmVjdCddOgog'
    'IGZvcndhcmQ9WydpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayBzZXQgJytzdHIoRElS'
    'RUNUKSsnIGN0IG1hcmsgc2V0ICcrc3RyKERJUkVDVCksICdjdCBkaXJlY3Rpb24gcmVwbHkgY3QgbWFyayAnK3N0cihESVJF'
    'Q1QpKycgbWV0YSBtYXJrIHNldCAnK3N0cihESVJFQ1QpXQoKIGRlZiBsaW5lcyhpdGVtcyk6cmV0dXJuICdcbicuam9pbign'
    'ICAnK3ggZm9yIHggaW4gaXRlbXMpCiByZXR1cm4gZicnJ3RhYmxlIGluZXQge3R1bm5lbC5GVUxMX0dVQVJEfSB7ewogc2V0'
    'IHdheWRyb2lkX25ldHdvcmtzIHt7IHR5cGUgaXB2NF9hZGRyOyBmbGFncyBpbnRlcnZhbDsgeygnZWxlbWVudHMgPSAnK25m'
    'dF9zZXQod2F5bmV0cykrJzsnKSBpZiB3YXluZXRzIGVsc2UgJyd9IH19CiBjaGFpbiByb3V0ZSB7eyB0eXBlIHJvdXRlIGhv'
    'b2sgb3V0cHV0IHByaW9yaXR5IC0xNTA7IHBvbGljeSBhY2NlcHQ7CiAgbWV0YSBza3VpZCB7dWlkfSByZXR1cm4KICBtZXRh'
    'IG1hcmsgc2V0IDAKICBpcCBkYWRkciAxMjcuMC4wLjAvOCByZXR1cm4Ke2xpbmVzKG1hcmspfQogfX0KIGNoYWluIGRucyB7'
    'eyB0eXBlIG5hdCBob29rIG91dHB1dCBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgc2t1aWQge3VpZH0g'
    'cmV0dXJuCntsaW5lcyhkbnMpfQogfX0KIGNoYWluIHByZXJvdXRlIHt7IHR5cGUgZmlsdGVyIGhvb2sgcHJlcm91dGluZyBw'
    'cmlvcml0eSAtMTUwOyBwb2xpY3kgYWNjZXB0Owp7bGluZXMoZm9yd2FyZCl9CiB9fQogY2hhaW4gd2F5ZHJvaWRfZG5zIHt7'
    'IHR5cGUgbmF0IGhvb2sgcHJlcm91dGluZyBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIGlpZm5hbWUgIndheWRy'
    'b2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUzIGRuYXQgaXAg'
    'dG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25h'
    'dDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIHNuYXQg'
    'aXAgdG8gMTcyLjI5LjI0Ny4xCntsaW5lcyhuYXQpfQogfX0KIGNoYWluIG91dHB1dCB7eyB0eXBlIGZpbHRlciBob29rIG91'
    'dHB1dCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2'
    'NCBtZXRhIG1hcmsge0RJUkVDVH0gYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBtYXJrIHtWUE59IG1ldGEgbDRw'
    'cm90byB7eyB0Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBvaWZuYW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIGFjY2VwdAogIG1l'
    'dGEgbmZwcm90byBpcHY0IG1ldGEgc2t1aWQge3VpZH0gbWV0YSBtYXJrIHtWUE59IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9I'
    'T1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie1RVTn0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4y'
    'NTUuMjU1LjI1NSB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBm'
    'aWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIg'
    'aXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0dW5uZWwuU0VSVkVSfSB1ZHAgZHBvcnQge3R1bm5lbC5JS0Vf'
    'UE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRy'
    'IHt0dW5uZWwuU0VSVkVSfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBkYWRk'
    'ciB7dHVubmVsLkNMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBpaWZuYW1lICJ3YXlkcm9p'
    'ZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBhY2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1l'
    'dGEgbmZwcm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQg'
    'b2lmbmFtZSAie1RVTn0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgIntUVU59IiBjdCBzdGF0ZSBlc3Rh'
    'Ymxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIg'
    'YWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie3R1bm5lbC5GVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxp'
    'c2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKClVOSVQ9JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGxvY2Fs'
    'IGFwcGxpY2F0aW9uIGFuZCBkb21haW4gcm91dGluZwpBZnRlcj1uZXR3b3JrLnRhcmdldApXYW50cz1ldmdlbml1bS13YXlk'
    'cm9pZC1uZXR3b3JrLnNlcnZpY2UKW1NlcnZpY2VdClVzZXI9dnBuLXhyYXkKR3JvdXA9dnBuLXhyYXkKRXhlY1N0YXJ0PS9v'
    'cHQvdnBuLW1hbmFnZXIvYmluL3hyYXkgcnVuIC1jb25maWcgL3J1bi92cG4tbWFuYWdlci9wb2xpY3kuanNvbgpSZXN0YXJ0'
    'PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0yCkFtYmllbnRDYXBhYmlsaXRpZXM9Q0FQX05FVF9BRE1JTiBDQVBfTkVUX1JBVyBD'
    'QVBfU1lTX1BUUkFDRSBDQVBfREFDX1JFQURfU0VBUkNICkNhcGFiaWxpdHlCb3VuZGluZ1NldD1DQVBfTkVUX0FETUlOIENB'
    'UF9ORVRfUkFXIENBUF9TWVNfUFRSQUNFIENBUF9EQUNfUkVBRF9TRUFSQ0gKTm9OZXdQcml2aWxlZ2VzPXRydWUKUHJvdGVj'
    'dFN5c3RlbT1zdHJpY3QKUHJvdGVjdEhvbWU9dHJ1ZQpQcml2YXRlVG1wPXRydWUKRGV2aWNlQWxsb3c9L2Rldi9uZXQvdHVu'
    'IHJ3ClVNYXNrPTAwNzcKJycnCgpXQVlEUk9JRF9VTklUPScnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBXYXlkcm9p'
    'ZCBuZXR3b3JrIGxpZmVjeWNsZQpBZnRlcj1ldmdlbml1bS1wb2xpY3kuc2VydmljZQpQYXJ0T2Y9ZXZnZW5pdW0tcG9saWN5'
    'LnNlcnZpY2UKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXdheWRyb2lkLXdh'
    'dGNoClJlc3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0U2VjPTIKVU1hc2s9MDA3NwonJycKCmRlZiB3YXlkcm9pZF9uZXR3b3Jr'
    'KCk6CiByZXN1bHQ9dHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hvdycsJ2RldicsJ3dheWRyb2lk'
    'MCddLGNoZWNrPUZhbHNlKQogaWYgcmVzdWx0LnJldHVybmNvZGU6cmV0dXJuIHsnaW5kZXgnOk5vbmUsJ25ldHdvcmtzJzpb'
    'XX0KIGxpbmtzPWpzb24ubG9hZHMocmVzdWx0LnN0ZG91dCkKIG5ldHdvcmtzPXNvcnRlZCh7c3RyKGlwYWRkcmVzcy5pcF9u'
    'ZXR3b3JrKGYie2FbJ2xvY2FsJ119L3thWydwcmVmaXhsZW4nXX0iLHN0cmljdD1GYWxzZSkpIGZvciBsaW5rIGluIGxpbmtz'
    'IGlmICdVUCcgaW4gbGluay5nZXQoJ2ZsYWdzJyxbXSkgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlmIGEu'
    'Z2V0KCdzY29wZScpPT0nZ2xvYmFsJ30pCiByZXR1cm4geydpbmRleCc6bGlua3NbMF0uZ2V0KCdpZmluZGV4JykgaWYgbGlu'
    'a3MgZWxzZSBOb25lLCduZXR3b3Jrcyc6bmV0d29ya3N9CgpkZWYgc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPUZhbHNl'
    'KToKICMgQ2FsbGVyIGhvbGRzIG9wZXJhdGlvbi5sb2NrLiBPbmx5IHRoaXMgVlBOJ3Mgc2V0L3RhYmxlIGFyZSBtb2RpZmll'
    'ZC4KIHN0YXRlPXdheWRyb2lkX25ldHdvcmsoKTtjYWNoZT1SVU4vJ3dheWRyb2lkLW5ldHdvcmsuanNvbicKIHRyeTpwcmV2'
    'aW91cz1qc29uLmxvYWRzKGNhY2hlLnJlYWRfdGV4dCgpKQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnByZXZpb3Vz'
    'PU5vbmUKIGlmIG5vdCBmb3JjZSBhbmQgc3RhdGU9PXByZXZpb3VzOnJldHVybgogcm91dGVzPWpzb24ubG9hZHModHVubmVs'
    'LmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKS5zdGRvdXQp'
    'CiBzdGFsZT17clsnZHN0J10gZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdkZXYnKT09J3dheWRyb2lkMCcgYW5kIHIuZ2V0'
    'KCdkc3QnKSBub3QgaW4gc3RhdGVbJ25ldHdvcmtzJ119CiBmb3IgbmV0d29yayBpbiBzdGF0ZVsnbmV0d29ya3MnXToKICB0'
    'dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLCd3YXlkcm9pZDAnLCdzY29wZScs'
    'J2xpbmsnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogcnVsZXM9J2ZsdXNoIHNldCBpbmV0ICcrdHVubmVsLkZVTExfR1VB'
    'UkQrJyB3YXlkcm9pZF9uZXR3b3Jrc1xuJwogaWYgc3RhdGVbJ25ldHdvcmtzJ106cnVsZXMrPSdhZGQgZWxlbWVudCBpbmV0'
    'ICcrdHVubmVsLkZVTExfR1VBUkQrJyB3YXlkcm9pZF9uZXR3b3JrcyAnK25mdF9zZXQoc3RhdGVbJ25ldHdvcmtzJ10pKydc'
    'bicKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKIGZvciBuZXR3b3JrIGluIHN0YWxlOnR1'
    'bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsbmV0d29yaywnZGV2Jywnd2F5ZHJvaWQwJywndGFibGUnLFBIWVNJ'
    'Q0FMX1RBQkxFXSxjaGVjaz1GYWxzZSkKIGNhY2hlLndyaXRlX3RleHQoanNvbi5kdW1wcyhzdGF0ZSkpO2NhY2hlLmNobW9k'
    'KDBvNjAwKQoKZGVmIHdhdGNoX3dheWRyb2lkKCk6CiBpbXBvcnQgc3lzCiBsYXN0X2Vycm9yPU5vbmUKIHdoaWxlIFRydWU6'
    'CiAgdHJ5OgogICBSVU4ubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgIHdpdGggKFJVTi8nb3BlcmF0aW9u'
    'LmxvY2snKS5vcGVuKCdhKycpIGFzIGxvY2s6CiAgICB0cnk6ZmNudGwuZmxvY2sobG9jayxmY250bC5MT0NLX0VYfGZjbnRs'
    'LkxPQ0tfTkIpCiAgICBleGNlcHQgQmxvY2tpbmdJT0Vycm9yOnBhc3MKICAgIGVsc2U6CiAgICAgaWYgdHVubmVsLmZ1bGxf'
    'Z3VhcmRfYWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKTpzeW5jX3dheWRyb2lkX25l'
    'dHdvcmsoKQogICBsYXN0X2Vycm9yPU5vbmUKICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgbWVzc2FnZT1zdHIoZXhj'
    'KQogICBpZiBtZXNzYWdlIT1sYXN0X2Vycm9yOnByaW50KCdXYXlkcm9pZCBuZXR3b3JrIHN5bmM6ICcrbWVzc2FnZSxmaWxl'
    'PXN5cy5zdGRlcnIsZmx1c2g9VHJ1ZSkKICAgbGFzdF9lcnJvcj1tZXNzYWdlCiAgdGltZS5zbGVlcCgxKQoKZGVmIGluc3Rh'
    'bGwoKToKIFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vJytTRVJWSUNFKS53cml0ZV90ZXh0KFVOSVQpCiBQYXRoKCcvZXRj'
    'L3N5c3RlbWQvc3lzdGVtLycrV0FZRFJPSURfU0VSVklDRSkud3JpdGVfdGV4dChXQVlEUk9JRF9VTklUKQogdHVubmVsLmNv'
    'bW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCgpkZWYgYXBwbHkoKToKIHA9bG9hZCgpO3NldHRpbmdzPWFw'
    'aS5sb2FkX3NldHRpbmdzKCk7cm91dGU9dHVubmVsLnBoeXNpY2FsX3JvdXRlKCk7bGFuPWxvY2FsX25ldHdvcmtzKHJvdXRl'
    'KQogYXBpLmVuc3VyZV9ydW50aW1lKHNldHRpbmdzKQogY2ZnPVJVTi8ncG9saWN5Lmpzb24nO3RtcD1SVU4vJ3BvbGljeS5u'
    'ZXcuanNvbicKIHRtcC53cml0ZV90ZXh0KGpzb24uZHVtcHMoY29uZmlnKHApKSk7b3MuY2htb2QodG1wLDBvNjQwKTtvcy5j'
    'aG93bih0bXAsMCxpbnQoc2V0dGluZ3NbJ3hyYXlfZ2lkJ10pKQogY2hlY2s9dHVubmVsLmNvbW1hbmQoW2FwaS5YUkFZLCdy'
    'dW4nLCctdGVzdCcsJy1jb25maWcnLHRtcF0sY2hlY2s9RmFsc2UpCiBpZiBjaGVjay5yZXR1cm5jb2RlOnJhaXNlIFJ1bnRp'
    'bWVFcnJvcign0J7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH0LXQvdC40Lkg0L3QtSDQv9GA0LjQvdGP0Lsg0L3Q'
    'sNGB0YLRgNC+0LnQutC4LicpCiBydWxlcz1maXJld2FsbChwLGxhbixpbnQoc2V0dGluZ3NbJ3hyYXlfdWlkJ10pKQogcmVw'
    'bGFjZW1lbnQ9KCdkZWxldGUgdGFibGUgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJEKydcbicgaWYgdHVubmVsLmZ1bGxfZ3Vh'
    'cmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJl'
    'cGxhY2VtZW50KQogb3duZXJzaGlwPVBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0d29yay5qc29uJykKIGlmIG5vdCBvd25l'
    'cnNoaXAuZXhpc3RzKCk6CiAgZm9yIHRhYmxlIGluIChQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEUpOgogICBpZiB0dW5uZWwu'
    'Y29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6'
    'cmFpc2UgUnVudGltZUVycm9yKCfQotCw0LHQu9C40YbQsCDQvNCw0YDRiNGA0YPRgtC40LfQsNGG0LjQuCDQuNGB0LrQu9GO'
    '0YfQtdC90LjQuSDQt9Cw0L3Rj9GC0LAg0LTRgNGD0LPQvtC5INC/0YDQvtCz0YDQsNC80LzQvtC5LicpCiAgZXhpc3Rpbmc9'
    'anNvbi5sb2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KQogIGlmIGFueShyLmdl'
    'dCgncHJpb3JpdHknKSBpbiAoNzYsNzcsNzgpIGZvciByIGluIGV4aXN0aW5nKTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cf0YDQ'
    'uNC+0YDQuNGC0LXRgtGLINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4INC40YHQutC70Y7Rh9C10L3QuNC5INC30LDQvdGP'
    '0YLRiyDQtNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykKICB0dW5uZWwud3JpdGUob3duZXJzaGlwLGpzb24u'
    'ZHVtcHMoeyd0YWJsZXMnOltQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEVdfSkpCiAjIEJ1aWxkIHBoeXNpY2FsIGFuZCBWUE4t'
    'b25seSB0YWJsZXMgYmVmb3JlIGFsbG93aW5nIGFueSBuZXcgbWFya3MuCiBmb3IgdGFibGUgaW4gKFBIWVNJQ0FMX1RBQkxF'
    'LFZQTl9UQUJMRSk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywnZGVm'
    'YXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLHRhYmxlXSkKIGZvciBuZXR3b3JrIGluIGxhbitbJzE2OS4yNTQuMC4w'
    'LzE2JywnMjI0LjAuMC4wLzQnXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdk'
    'ZXYnLHJvdXRlWydkZXYnXSwnc2NvcGUnLCdsaW5rJywndGFibGUnLFBIWVNJQ0FMX1RBQkxFXSkKIHR1bm5lbC5jb21tYW5k'
    'KFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJyxyb3V0ZVsnZ2F0ZXdheSddLCdkZXYnLHJvdXRlWydk'
    'ZXYnXSwnbWV0cmljJywnMTAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRl'
    'JywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLHR1bm5lbC5GVUxMX0hPU1QsJ21ldHJp'
    'YycsJzEwJywndGFibGUnLFZQTl9UQUJMRV0pCiBmb3IgcHJpb3JpdHksbWFyayx0YWJsZSBpbiBbKDc2LERJUkVDVCxQSFlT'
    'SUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3By'
    'aW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogIHR1bm5l'
    'bC5jb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLHByaW9yaXR5LCdmd21hcmsnLHN0cihtYXJrKSwnbG9v'
    'a3VwJyx0YWJsZV0pCiAjIFJlcGxpZXMgdG8gYSBmb3J3YXJkZWQgY29udGFpbmVyIHJldHVybiB0aHJvdWdoIGl0cyBjb25u'
    'ZWN0ZWQgbWFpbiByb3V0ZS4KIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lp'
    'ZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcs'
    'J3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbiddKQogIyBBIHRlbXBvcmFyeSBjbG9zZWQgc3RhdGUg'
    'aXMgYWNjZXB0YWJsZTsgYW4gdW5ndWFyZGVkIHN0YXRlIGlzIG5vdC4KIG9zLnJlcGxhY2UodG1wLGNmZykKIHR1bm5lbC53'
    'cml0ZSh0dW5uZWwuUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogdHVubmVsLmNvbW1hbmQoWyduZnQnLCctZicsJy0n'
    'XSxkYXRhPXJlcGxhY2VtZW50KQogc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPVRydWUpCiBpbnN0YWxsKCkKIHR1bm5l'
    'bC5jb21tYW5kKFsnc3lzdGVtY3RsJywncmVzdGFydCcsU0VSVklDRV0pCiBmb3IgXyBpbiByYW5nZSg4MCk6CiAgaWYgUGF0'
    'aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOmJyZWFrCiAgdGltZS5zbGVlcCguMSkKIGVsc2U6cmFpc2UgUnVu'
    'dGltZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC30LDQv9GD0YHRgtC40YLRjCDQvtCx0YDQsNCx0L7RgtGH0LjQuiDQ'
    'uNGB0LrQu9GO0YfQtdC90LjQuS4nKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQn'
    'LCdkZXYnLFRVTiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZVTExfVEFCTEVdKQogdHVubmVsLmNsZWFyX2Ruc19t'
    'YXBwaW5ncygpCiAjIEV4cGxpY2l0bHkgcmVxdWVzdGVkIEROUyBleGNlcHRpb25zIG5lZWQgc3RhbGUgcG9ydC01MyBtYXBw'
    'aW5ncyByZW1vdmVkIHRvby4KIGZvciBwcm90byBpbiAoJ3VkcCcsJ3RjcCcpOgogIHR1bm5lbC5jb21tYW5kKFsnY29ubnRy'
    'YWNrJywnLUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG8sJy0tZHBvcnQnLCc1MycsJy0tcmVwbHktcG9ydC1zcmMnLHN0cihE'
    'TlNfUE9SVCldLGNoZWNrPUZhbHNlKQoKCmRlZiBzdG9wKHJlbGVhc2U9RmFsc2UpOgogdHVubmVsLmNvbW1hbmQoWydzeXN0'
    'ZW1jdGwnLCdzdG9wJyxTRVJWSUNFXSxjaGVjaz1GYWxzZSkKIGlmIHJlbGVhc2UgYW5kIFBBVEgud2l0aF9uYW1lKCdwb2xp'
    'Y3ktbmV0d29yay5qc29uJykuZXhpc3RzKCk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0'
    'eScsJzc4JywnaWlmJyxUVU4sJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICBmb3IgcHJpb3JpdHksbWFyayx0YWJs'
    'ZSBpbiBbKDc2LERJUkVDVCxQSFlTSUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICAgdHVubmVsLmNvbW1hbmQo'
    'WydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScscHJpb3JpdHksJ2Z3bWFyaycsc3RyKG1hcmspLCdsb29rdXAnLHRhYmxl'
    'XSxjaGVjaz1GYWxzZSkKICAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsdGFibGVdLGNo'
    'ZWNrPUZhbHNlKQogIFBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0d29yay5qc29uJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1'
    'ZSkKCgpkZWYgY2hhbmdlKGFjdGlvbixjYXRlZ29yeT0nJyx2YWx1ZT0nJyxzdGF0ZT1Ob25lKToKIG9sZD1sb2FkKCk7cD1q'
    'c29uLmxvYWRzKGpzb24uZHVtcHMob2xkKSkKIGlmIGFjdGlvbj09J3dheWRyb2lkJzpwWyd3YXlkcm9pZF9kaXJlY3QnXT1i'
    'b29sKHN0YXRlKQogZWxpZiBhY3Rpb249PSdiYXNlJzoKICBpZiBjYXRlZ29yeSBub3QgaW4gQkFTRSBvciB2YWx1ZSBub3Qg'
    'aW4ge2VbJ2lkJ10gZm9yIGUgaW4gQkFTRVtjYXRlZ29yeV19OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQ'
    'vdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uJykKICBrZXk9Y2F0ZWdvcnkrJzonK3ZhbHVlCiAgcFsnZGlz'
    'YWJsZWRfYmFzZSddPVt4IGZvciB4IGluIHBbJ2Rpc2FibGVkX2Jhc2UnXSBpZiB4IT1rZXldCiAgaWYgbm90IHN0YXRlOnBb'
    'J2Rpc2FibGVkX2Jhc2UnXS5hcHBlbmQoa2V5KQogZWxpZiBhY3Rpb24gaW4gKCdhZGQnLCdyZW1vdmUnKToKICBpZiBjYXRl'
    'Z29yeSBub3QgaW4gQ0FURUdPUklFUzpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGPINC60LDRgtC1'
    '0LPQvtGA0LjRjy4nKQogIHZhbHVlPW5vcm1hbGl6ZShjYXRlZ29yeSx2YWx1ZSkKICBpZiBhY3Rpb249PSdhZGQnIGFuZCB2'
    'YWx1ZSBub3QgaW4gcFtjYXRlZ29yeV06cFtjYXRlZ29yeV0uYXBwZW5kKHZhbHVlKQogIGlmIGFjdGlvbj09J3JlbW92ZSc6'
    'cFtjYXRlZ29yeV09W3ggZm9yIHggaW4gcFtjYXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBlbHNlOnJhaXNlIFZhbHVlRXJyb3Io'
    'J9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg0LTQtdC50YHRgtCy0LjQtS4nKQogaWYgcD09b2xkOnJldHVybiBwdWJsaWMoKQog'
    'c2F2ZShwKQogaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrdHVubmVs'
    'LkZVTExfSE9TVCkuZXhpc3RzKCk6CiAgdHJ5OmFwcGx5KCkKICBleGNlcHQgRXhjZXB0aW9uOgogICBzYXZlKG9sZCkKICAg'
    'dHJ5OmFwcGx5KCkKICAgZXhjZXB0IEV4Y2VwdGlvbjpwYXNzCiAgIHJhaXNlCiByZXR1cm4gcHVibGljKCkKCmRlZiBlbnN1'
    'cmVfcm91dGUoKToKIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKToKICB0dW5uZWwuY29tbWFuZChb'
    'J2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ2RldicsVFVOLCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyx0dW5uZWwu'
    'RlVMTF9UQUJMRV0pCiBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcigncG9saWN5X2VuZ2luZV91bmF2YWlsYWJsZScpCg=='
)

import types

def embedded(name,source):
 module=types.ModuleType(name)
 exec(compile(base64.b64decode(source),name+'.py','exec'),module.__dict__)
 return module

starfive_tunnel=embedded('starfive_tunnel',STARFIVE_TUNNEL_PY_B64)
policy=embedded('network_policy',NETWORK_POLICY_PY_B64)
class ManagerAPI:
 def __getattr__(self,name):return globals()[name]
policy.api=ManagerAPI()
policy.tunnel=starfive_tunnel
starfive_tunnel.policy=policy

def load_settings():
 data=json.loads(SETTINGS.read_text())
 for key in ('owner_user','owner_home','xray_uid','xray_gid'):
  if key not in data:fail('Не найдена настройка '+key)
 data.setdefault('direct_apps',str(pathlib.Path(data['owner_home'])/'Vpn/DIRECT apps.txt'))
 return data


def service_active():return run(['systemctl','is-active','--quiet',SERVICE],check=False,capture=True).returncode==0

def wait_service(timeout=12):
 until=time.monotonic()+timeout
 while time.monotonic()<until:
  if service_active():return True
  time.sleep(.2)
 return False

def sync_system_files():
 pathlib.Path('/var/lib/vpn-manager').mkdir(parents=True,exist_ok=True)
 os.chown('/var/lib/vpn-manager',0,0);os.chmod('/var/lib/vpn-manager',0o755)
 for filename,value in [('/usr/local/bin/vpn',WRAPPER_TEXT),('/usr/local/bin/evgenium-network',GUI_WRAPPER_TEXT)]:
  pathlib.Path(filename).write_text(value);os.chmod(filename,0o755)
 admin=pathlib.Path('/usr/local/sbin/vpn-manager-admin')
 temp=admin.with_name(admin.name+'.new');temp.unlink(missing_ok=True)
 temp.symlink_to(CURRENT/'vpnadmin.py');os.replace(temp,admin)
 policy.install()

def ensure_gui_dependencies():
 """Older CLI-only installs never installed the Qt runner."""
 candidates=('/usr/bin/qml6','/usr/bin/qml-qt6','/usr/lib/qt6/bin/qml','/usr/lib64/qt6/bin/qml')
 if any(os.access(p,os.X_OK) for p in candidates):return
 if shutil.which('pacman'):
  run(['pacman','-S','--needed','--noconfirm','qt6-declarative'],timeout=300)
 elif shutil.which('dnf'):
  result=run(['rpm','-q','--qf','%{VERSION}-%{RELEASE}.%{ARCH}','qt6-qtdeclarative'],check=False,capture=True)
  if result.returncode:fail('Не найден Qt 6. Установите Fedora KDE или Qt 6, затем повторите установщик с --repair.')
  package='qt6-qtdeclarative-devel-'+result.stdout.strip()
  run(['dnf','install','-y','--no-best','--setopt=install_weak_deps=False',package],timeout=300)
 else:fail('Автоустановка Qt поддерживает Arch и Fedora.')
 if not any(os.access(p,os.X_OK) for p in candidates):fail('Qt QML runner не появился. Повторите установщик с --repair.')

INSTALL_PENDING=pathlib.Path('/var/lib/vpn-manager/install-pending')
INSTALL_COMPLETE=pathlib.Path('/var/lib/vpn-manager/install-complete.json')

def finish_installation(settings, *, reconnect=True):
 """Repeatable finalization, including entry from an unmodified 0.2.x updater.

 Refresh entrypoints first: a failed dependency download must not strand users
 with the previous shell wrapper and GUI pointing at a newer backend.
 """
 pending=INSTALL_PENDING.exists()
 INSTALL_PENDING.parent.mkdir(parents=True,exist_ok=True)
 INSTALL_PENDING.write_text(MANAGER_VERSION+'\n');INSTALL_PENDING.chmod(0o600)
 try:
  sync_system_files();cmd_gui_install(settings)
  if _widget_package_dir(settings).exists():cmd_widget_install(settings)
  if _tray_autostart_path(settings).exists():cmd_tray_install(settings)
  policy.migration(settings)
  starfive_tunnel.ensure_dependencies();ensure_gui_dependencies();core_update(settings)
  was_active=starfive_tunnel.status().get('running') or run(['systemctl','is-active','--quiet','vpn-xray.service'],check=False,capture=True).returncode==0
  retire_legacy(settings)
  has_token=starfive_tunnel.token_status()['has_token']
  if has_token:starfive_tunnel.sync_device_name()
  if was_active and has_token and (reconnect or pending):starfive_tunnel.connect(repair=True)
  INSTALL_COMPLETE.write_text(json.dumps({'version':MANAGER_VERSION,'completed':int(time.time())})+'\n')
  INSTALL_COMPLETE.chmod(0o600);INSTALL_PENDING.unlink()
 except Exception:
  warn('Установка не завершена. Токен и настройки сохранены. Повторите vpn update; если CLI не запускается — установщик с --repair из README.')
  raise
 print('CLI и GUI обновлены до '+MANAGER_VERSION+'. Закройте старое окно приложения и откройте заново.')
 if not has_token:print('Для нового VPN нужен клиентский токен: откройте Evgenium Network или выполните vpn token save.')

def retire_legacy(settings):
 """One-time retirement, preserving user lists and a private rollback snapshot."""
 marker=pathlib.Path('/var/lib/vpn-manager/unified-migrated')
 if marker.exists():return
 old_active=run(['systemctl','is-active','--quiet','vpn-xray.service'],check=False,capture=True).returncode==0
 if old_active and not starfive_tunnel.full_guard_active():
  # An active legacy installation must not acquire a direct window during migration.
  starfive_tunnel.write(starfive_tunnel.full_state(),json.dumps({'active':False,'migration_only':True}))
  rules=starfive_tunnel.full_firewall()
  run(['nft','-c','-f','-'],input_text=rules,capture=True)
  starfive_tunnel.persist_guard(rules)
  run(['nft','-f','-'],input_text=rules,capture=True)
  starfive_tunnel.stage('off','Для подключения нужен клиентский токен. Защита сохранена; отключение VPN вернёт обычную сеть.',0,active=False)
 backup=pathlib.Path('/var/lib/vpn-manager/legacy-before-0.4.0.tar.gz')
 paths=[pathlib.Path('/etc/systemd/system/vpn-xray.service'),pathlib.Path('/run/vpn-manager/config.json'),pathlib.Path('/var/lib/vpn-manager/state.json')]
 config_dir=pathlib.Path(settings.get('config_dir','/nonexistent'))
 # Only the configured VPN profile directory is retired; other user directories are untouched.
 if config_dir.is_dir() and config_dir.resolve().is_relative_to(pathlib.Path(settings['owner_home']).resolve()) and config_dir.name=='VPN configs':paths.append(config_dir)
 with tarfile.open(backup,'w:gz') as tar:
  for p in paths:
   if p.exists():tar.add(p,arcname=str(p).lstrip('/'))
 os.chmod(backup,0o600)
 for unit in ('vpn-xray.service','vpn-diagnostic.service','evgenium-ikev2-diagnostic.service','evgenium-ikev2-delivery.service'):
  run(['systemctl','disable','--now',unit],check=False,capture=True)
  pathlib.Path('/etc/systemd/system',unit).unlink(missing_ok=True)
 for p in paths:
  if p.is_dir():shutil.rmtree(p)
  else:p.unlink(missing_ok=True)
 run(['nft','delete','table','inet','vpn_guard'],check=False,capture=True)
 # Remove only exact old mark/table pairs, retaining unrelated routing rules.
 for family in ('-4','-6'):
  for pref,mark,table in [('50','0x45564e01/0xffffffff','51820'),('51','0x45564e02/0xffffffff','51821')]:
   for target in (table,'main'):
    while run(['ip',family,'rule','del','pref',pref,'fwmark',mark,'lookup',target],check=False,capture=True).returncode==0:pass
   run(['ip',family,'route','flush','table',table],check=False,capture=True)
 settings['engine']='token-ipsec';save_settings(settings)
 marker.write_text(MANAGER_VERSION);os.chmod(marker,0o600)
 run(['systemctl','daemon-reload'],capture=True)

def status_data():
 st=starfive_tunnel.status()
 active=bool(st.get('active')) and service_active()
 if st.get('active') and not active:st.update(active=False,message='Обработчик правил остановился. Нажмите «Восстановить».')
 connecting=bool(st.get('running')) and not active and st.get('phase') not in ('failed','off','interrupted')
 return {'connecting':connecting,'active':active,'guard':st['guard'],'manager_version':MANAGER_VERSION,'tunnel':st,'policy':policy.public(),'backend':'Evgenium','active_profile':'Evgenium' if active else None}

def cmd_ui_state(settings):print(json.dumps(status_data(),ensure_ascii=False))

def cmd_ui_action(settings,payload):
 if payload=='-':payload=sys.stdin.read(65537).strip()
 if len(payload)>65536:fail('Слишком большой запрос.')
 try:
  raw=base64.b64decode(payload+'='*(-len(payload)%4),altchars=b'-_',validate=True).decode('utf-8')
  data=json.loads(urllib.parse.unquote(raw) if raw.startswith('%') else raw)
 except Exception:fail('Некорректный запрос.')
 if not isinstance(data,dict):fail('Некорректный запрос.')
 action=data.get('action')
 if action=='token-save':starfive_tunnel.save_token(str(data.get('token','')))
 elif action=='device-name':starfive_tunnel.sync_device_name(str(data.get('name','')))
 elif action in ('connect','repair'):starfive_tunnel.connect(repair=action=='repair')
 elif action=='disconnect':starfive_tunnel.disconnect()
 elif action=='update':manager_update_manifest(settings,settings['manager_manifest_url'])
 elif action in ('add','remove','base','waydroid'):
  if action in ('base','waydroid') and not isinstance(data.get('enabled'),bool):fail('Ожидался переключатель.')
  policy.change(action,str(data.get('category','')),str(data.get('value','')),data.get('enabled'))
 else:fail('Неизвестное действие.')

def operation_requires_lock(args):
 return args.cmd not in (None,'status','version','logs','rules','watch','internal-waydroid-watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-starfive-pause-main') and not (args.cmd=='ui' and args.ui_cmd in ('state','running'))

def self_test():
 assert MANAGER_VERSION=='0.4.3'
 assert policy.config(policy.defaults())['outbounds'][0]['protocol']=='freedom'
 for source in (STANDALONE_GUI_PY_B64,STARFIVE_TUNNEL_PY_B64,NETWORK_POLICY_PY_B64):compile(base64.b64decode(source),'embedded','exec')
 assert 'VLESS' not in base64.b64decode(STANDALONE_GUI_QML_B64).decode()
 print('Evgenium token VPN self-test OK')

def terminal_status(st=None,check_ip=False):
 st=st or status_data();t=st['tunnel'];p=st['policy']
 print('Evgenium '+MANAGER_VERSION)
 print('Состояние: '+('ПОДКЛЮЧЕНО' if st['active'] else 'ЗАБЛОКИРОВАНО' if st['guard'] else 'ВЫКЛЮЧЕНО'))
 print('Маршрут: компьютер → HSVDS (195.209.211.163) → Эстония (38.180.164.67)')
 print('Этап: '+str(t.get('progress',0))+'% — '+t.get('message',''))
 print('Защита при обрыве: '+('включена; разрешённые DIRECT-исключения сохраняются' if st['guard'] else 'выключена, обычная сеть'))
 print('Токен: '+('сохранён ('+str(t.get('token_hint',''))+')' if t.get('has_token') else 'не задан; vpn token save'))
 if st['active'] and t.get('since'):
  seconds=max(0,int(time.time()-t['since']));print(f'Подключено: {seconds//3600} ч {(seconds//60)%60} мин {seconds%60} с')
 if t.get('device_name'):print('Устройство: '+t['device_name']+(' (ожидает отправки на сервер)' if t.get('device_name_pending') else ''))
 print('Исключения: приложения {applications}, сайты/IP {networks}, порты {ports}, DNS {dns}'.format(**{c:len(p[c]) for c in policy.CATEGORIES}))
 print('Базовые исключения: '+str(sum(len(x) for x in policy.BASE.values())-len(p['disabled_base']))+' включено; vpn base list')
 print('Waydroid: '+('напрямую' if p['waydroid_direct'] else 'через VPN'))
 if t.get('error_code'):print('Причина последнего сбоя: '+t['error_code'])
 if check_ip:
  if not st['active']:print('Проверка IP: VPN не подключён.');return
  cp=run(['curl','-4','--noproxy','','--socks5-hostname','127.0.0.1:18554','-fsS','--max-time','10','https://api.ipify.org'],check=False,capture=True)
  address=cp.stdout.strip()
  print('Проверенный IP через VPN: '+(address if cp.returncode==0 else 'проверка не удалась'))
  if cp.returncode or address!='38.180.164.67':raise VPNError('Ожидаемый выход в Эстонии не подтверждён.')


def terminal_wait(timeout=120):
 until=time.monotonic()+timeout;previous=None
 while time.monotonic()<until:
  st=status_data();t=st['tunnel'];step=(t.get('phase'),t.get('message'))
  if step!=previous:print(f"[{t.get('progress',0):3}%] {t.get('message','')}",flush=True);previous=step
  if st['active']:
   terminal_status(st,check_ip=True);return 0
  if t.get('phase') in ('failed','off','interrupted'):
   terminal_status(st);print('Повторить: vpn repair. Вернуть обычную сеть: vpn off. Журнал: vpn logs.');return 1
  time.sleep(.5)
 print('Ожидание завершилось, но служба ещё работает. Проверить: vpn status; остановить: vpn off.');return 1


def terminal_rules():
 p=policy.public()
 for category,label in [('applications','Приложения'),('networks','Сайты и IP'),('ports','Порты'),('dns','DNS')]:
  print(label+':')
  for v in p[category]:print('  DIRECT  '+v)
  if not p[category]:print('  Пользовательских исключений нет')
  for b in p['base'][category]:print('  База '+('ВКЛ' if b['enabled'] else 'ВЫКЛ')+'  '+category+':'+b['id']+' — '+b['label'])
 print('Waydroid: '+('DIRECT' if p['waydroid_direct'] else 'VPN'))


def main(argv=None):
 p=argparse.ArgumentParser(prog='vpn',description='Evgenium: VPN и прямые исключения без графического интерфейса')
 p.add_argument('--self-test',action='store_true')
 sub=p.add_subparsers(dest='cmd')
 for name in ('on','repair','toggle'):
  a=sub.add_parser(name,help={'on':'Подключить и показать этапы','repair':'Восстановить соединение','toggle':'Переключить VPN'}[name]);a.add_argument('--no-wait',action='store_true',help='Запустить в фоне')
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-waydroid-watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-starfive-pause-main','manager-rollback'):sub.add_parser(name)
 pst=sub.add_parser('status',help='Состояние, защита и исключения');pst.add_argument('--json',action='store_true');pst.add_argument('--ip',action='store_true',help='Проверить внешний IP именно через VPN')
 device=sub.add_parser('device',help='Имя устройства в веб-панели');device.add_argument('operation',choices=['show','name','sync']);device.add_argument('name',nargs='?')
 tok=sub.add_parser('token');tok.add_argument('token_cmd',choices=['save'])
 base=sub.add_parser('base',help='Управление базовыми исключениями');base.add_argument('operation',choices=['list','enable','disable']);base.add_argument('category',choices=policy.CATEGORIES,nargs='?');base.add_argument('rule',nargs='?')
 way=sub.add_parser('waydroid');way.add_argument('mode',choices=['status','direct','vpn'])
 ui=sub.add_parser('ui');uis=ui.add_subparsers(dest='ui_cmd');uis.add_parser('state');uis.add_parser('running');uis.add_parser('action').add_argument('payload')
 for name in ('gui','widget','tray'):
  x=sub.add_parser(name);x.add_argument('operation',choices=['install','remove'])
 logs=sub.add_parser('logs');logs.add_argument('-n',type=int,default=100)
 for name in ('app','direct','port','dns'):
  x=sub.add_parser(name);x.add_argument('operation',choices=['list','add','remove']);x.add_argument('value',nargs='?')
 args=p.parse_args(argv)
 if args.self_test:self_test();return 0
 ensure_root();settings=load_settings();wait=False
 with operation_guard(args,settings):
  cmd=args.cmd
  if cmd=='internal-waydroid-watch':policy.watch_waydroid()
  elif cmd=='internal-starfive-tunnel':starfive_tunnel.worker()
  elif cmd=='internal-starfive-tunnel-cleanup':starfive_tunnel.cleanup()
  elif cmd=='internal-starfive-pause-main':retire_legacy(settings)
  elif cmd in ('on','repair'):
   if cmd=='repair' or not status_data()['active']:starfive_tunnel.connect(repair=cmd=='repair')
   wait=not args.no_wait
  elif cmd=='off':starfive_tunnel.disconnect()
  elif cmd=='toggle':
   if starfive_tunnel.status().get('running'):starfive_tunnel.disconnect()
   else:starfive_tunnel.connect();wait=not args.no_wait
  elif cmd=='device':
   if args.operation=='name' and not args.name:raise ValueError('Укажите имя: vpn device name \"Мой ноутбук\"')
   d=starfive_tunnel.device_status() if args.operation=='show' else starfive_tunnel.sync_device_name(args.name if args.operation=='name' else None)
   print('Устройство: '+(d['device_name'] or 'имя ещё не получено с сервера')+(' · ожидает синхронизации' if d['device_name_pending'] else ''))
  elif cmd=='token':
   if sys.stdin.isatty():
    import getpass
    token=getpass.getpass('Токен клиента (ввод скрыт): ')
   else:token=sys.stdin.read(1024).strip()
   starfive_tunnel.save_token(token);print('Токен сохранён. Подключить: vpn on')
  elif cmd in ('status',None):
   st=status_data()
   if cmd and args.json:print(json.dumps(st,ensure_ascii=False))
   else:terminal_status(st,check_ip=bool(cmd and args.ip))
   if cmd is None:print('\nКоманды: vpn on | off | repair | status --ip | watch | rules | update\nНастройки: vpn app | direct | port | dns | base | waydroid | token\nПодробно: vpn --help')
  elif cmd=='rules':terminal_rules()
  elif cmd=='watch':pass
  elif cmd=='base':
   if args.operation=='list':terminal_rules()
   else:policy.change('base',args.category or '',args.rule or '',args.operation=='enable');terminal_rules()
  elif cmd=='waydroid':
   if args.mode!='status':policy.change('waydroid',state=args.mode=='direct')
   print('Waydroid: '+('напрямую' if policy.load()['waydroid_direct'] else 'через VPN'))
  elif cmd=='ui':
   if args.ui_cmd=='running':cmd_ui_running(settings)
   elif args.ui_cmd=='action':cmd_ui_action(settings,args.payload)
   else:cmd_ui_state(settings)
  elif cmd in ('app','direct','port','dns'):
   cat={'app':'applications','direct':'networks','port':'ports','dns':'dns'}[cmd]
   if args.operation!='list':
    if args.value is None:raise ValueError('Укажите правило для '+cmd+' '+args.operation)
    policy.change(args.operation,cat,args.value)
   values=policy.public()[cat]
   print('\n'.join('DIRECT  '+v for v in values) if values else 'Пользовательских исключений нет. Базовые: vpn base list')
  elif cmd=='update':manager_update_manifest(settings,settings['manager_manifest_url'])
  elif cmd in ('internal-sync','internal-after-update'):finish_installation(settings)
  elif cmd=='manager-rollback':manager_rollback()
  elif cmd=='gui':(cmd_gui_install if args.operation=='install' else cmd_gui_remove)(settings)
  elif cmd=='widget':(cmd_widget_install if args.operation=='install' else cmd_widget_remove)(settings)
  elif cmd=='tray':(cmd_tray_install if args.operation=='install' else cmd_tray_remove)(settings)
  elif cmd=='logs':print(run(['journalctl','-u',starfive_tunnel.UNIT,'-u',policy.SERVICE,'-n',str(max(1,min(args.n,500))),'--no-pager'],capture=True).stdout)
  elif cmd=='version':print('Evgenium '+MANAGER_VERSION)
 if wait:return terminal_wait()
 if args.cmd=='watch':
  previous=None
  try:
   while True:
    st=status_data();key=(st['active'],st['guard'],st['tunnel'].get('phase'),st['tunnel'].get('message'),st['policy'])
    if key!=previous:print('\n'+time.strftime('%H:%M:%S'));terminal_status(st);previous=key
    time.sleep(2)
  except KeyboardInterrupt:print('\nНаблюдение остановлено; состояние VPN не изменено.')
 return 0

if __name__=='__main__':
 try:raise SystemExit(main())
 except KeyboardInterrupt:print('\nОжидание прервано. Проверить VPN: vpn status; отключить: vpn off.');raise SystemExit(130)
 except (VPNError,ValueError,RuntimeError,OSError) as exc:
  print('Ошибка:',str(exc),file=sys.stderr);raise SystemExit(1)
