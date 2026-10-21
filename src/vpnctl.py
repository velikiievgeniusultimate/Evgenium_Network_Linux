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

MANAGER_VERSION = "0.5.0"

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
    'ICAgICAgICBpZiBwYXlsb2FkLmdldCgiYWN0aW9uIikgPT0gInRva2VuLXNhdmUiOgogICAgICAgICAgICAgICAgICAgIHJl'
    'cGx5WyJzdGF0ZSJdID0gcnVuX3Zwbl9qc29uKFsidWkiLCAic3RhdGUiXSkKICAgICAgICAgICAgICAgIHNlbGYuX2pzb24o'
    'cmVwbHkpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgaWYgc2VsZi5wYXRoID09ICIvYXBpL3RvZ2dsZSI6'
    'CiAgICAgICAgICAgICAgICBvdXRwdXQgPSBydW5fdnBuKFsidG9nZ2xlIl0pCiAgICAgICAgICAgICAgICBzZWxmLl9qc29u'
    'KHsib2siOiBUcnVlLCAib3V0cHV0Ijogb3V0cHV0LCAic3RhdGUiOiBydW5fdnBuX2pzb24oWyJ1aSIsICJzdGF0ZSJdKX0p'
    'CiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgc2VsZi5fanNvbih7Im9rIjogRmFsc2UsICJlcnJvciI6ICJu'
    'b3QgZm91bmQifSwgNDA0KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICBzZWxmLl9qc29u'
    'KHsib2siOiBGYWxzZSwgImVycm9yIjogc3RyKGV4Yyl9LCA1MDApCgoKZGVmIHN0YXRlX2xvZ19wYXRoKCkgLT4gcGF0aGxp'
    'Yi5QYXRoOgogICAgcm9vdCA9IHBhdGhsaWIuUGF0aChvcy5lbnZpcm9uLmdldCgiWERHX1NUQVRFX0hPTUUiLCBwYXRobGli'
    'LlBhdGguaG9tZSgpIC8gIi5sb2NhbCIgLyAic3RhdGUiKSkKICAgIHBhdGggPSByb290IC8gImV2Z2VuaXVtLW5ldHdvcmsi'
    'IC8gImd1aS5sb2ciCiAgICBwYXRoLnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICByZXR1'
    'cm4gcGF0aAoKCmRlZiBsYXVuY2hfZGV0YWNoZWQoKSAtPiBpbnQ6CiAgICBpZiBub3QgUU1MX0ZJTEUuaXNfZmlsZSgpOgog'
    'ICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC10L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7UU1MX0ZJTEV9IiwgZmlsZT1z'
    'eXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgZmluZF9xbWxfcnVudGltZSgpOgogICAgICAgIHByaW50'
    'KCLQndC1INC90LDQudC00LXQvSBRdCA2IFFNTCBydW50aW1lIChBcmNoOiBxdDYtZGVjbGFyYXRpdmU7IEZlZG9yYTogcXQ2'
    'LXF0ZGVjbGFyYXRpdmUtZGV2ZWwpLiIsIGZpbGU9c3lzLnN0ZGVycikKICAgICAgICByZXR1cm4gMQogICAgbG9nX3BhdGgg'
    'PSBzdGF0ZV9sb2dfcGF0aCgpCiAgICB3aXRoIGxvZ19wYXRoLm9wZW4oImFiIiwgYnVmZmVyaW5nPTApIGFzIGxvZzoKICAg'
    'ICAgICBzdWJwcm9jZXNzLlBvcGVuKAogICAgICAgICAgICBbc3lzLmV4ZWN1dGFibGUsIHN0cihwYXRobGliLlBhdGgoX19m'
    'aWxlX18pLnJlc29sdmUoKSldLAogICAgICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgIHN0'
    'ZG91dD1sb2csCiAgICAgICAgICAgIHN0ZGVycj1sb2csCiAgICAgICAgICAgIHN0YXJ0X25ld19zZXNzaW9uPVRydWUsCiAg'
    'ICAgICAgICAgIGNsb3NlX2Zkcz1UcnVlLAogICAgICAgICkKICAgIHJldHVybiAwCgoKZGVmIHJ1bl9ndWkoKSAtPiBpbnQ6'
    'CiAgICBxbWwgPSBmaW5kX3FtbF9ydW50aW1lKCkKICAgIGlmIG5vdCBxbWw6CiAgICAgICAgcHJpbnQoItCd0LUg0L3QsNC5'
    '0LTQtdC9IFF0IDYgUU1MIHJ1bnRpbWUgKEFyY2g6IHF0Ni1kZWNsYXJhdGl2ZTsgRmVkb3JhOiBxdDYtcXRkZWNsYXJhdGl2'
    'ZS1kZXZlbCkuIiwgZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCiAgICBpZiBub3QgUU1MX0ZJTEUuaXNfZmls'
    'ZSgpOgogICAgICAgIHByaW50KGYi0J3QtSDQvdCw0LnQtNC10L0g0LjQvdGC0LXRgNGE0LXQudGBOiB7UU1MX0ZJTEV9Iiwg'
    'ZmlsZT1zeXMuc3RkZXJyKQogICAgICAgIHJldHVybiAxCgogICAgdG9rZW4gPSBzZWNyZXRzLnRva2VuX3VybHNhZmUoMzIp'
    'CiAgICBzZXJ2ZXIgPSBBcGlTZXJ2ZXIoKCIxMjcuMC4wLjEiLCAwKSwgSGFuZGxlciwgdG9rZW4pCiAgICBwb3J0ID0gaW50'
    'KHNlcnZlci5zZXJ2ZXJfYWRkcmVzc1sxXSkKICAgIHRocmVhZCA9IHRocmVhZGluZy5UaHJlYWQodGFyZ2V0PXNlcnZlci5z'
    'ZXJ2ZV9mb3JldmVyLCBuYW1lPSJldmdlbml1bS1ndWktYXBpIiwgZGFlbW9uPVRydWUpCiAgICB0aHJlYWQuc3RhcnQoKQoK'
    'ICAgIGVudiA9IG9zLmVudmlyb24uY29weSgpCiAgICBlbnYuc2V0ZGVmYXVsdCgiUVRfUVVJQ0tfQ09OVFJPTFNfU1RZTEUi'
    'LCAiQmFzaWMiKQogICAgZW52LnNldGRlZmF1bHQoIlFNTF9ESVNBQkxFX0RJU0tfQ0FDSEUiLCAiMCIpCgogICAgdHJ5Ogog'
    'ICAgICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oCiAgICAgICAgICAgIFtxbWwsIHN0cihRTUxfRklMRSksICItLSIsIHN0cihw'
    'b3J0KSwgdG9rZW5dLAogICAgICAgICAgICBlbnY9ZW52LAogICAgICAgICAgICBjaGVjaz1GYWxzZSwKICAgICAgICApCiAg'
    'ICAgICAgcmV0dXJuIGludChjcC5yZXR1cm5jb2RlKQogICAgZmluYWxseToKICAgICAgICBzZXJ2ZXIuc2h1dGRvd24oKQog'
    'ICAgICAgIHNlcnZlci5zZXJ2ZXJfY2xvc2UoKQogICAgICAgIHRocmVhZC5qb2luKHRpbWVvdXQ9MikKCgpkZWYgc2VsZl90'
    'ZXN0KCkgLT4gaW50OgogICAgc2FtcGxlID0geyJhY3Rpb24iOiAiYXBwX2FkZCIsICJ0YXJnZXQiOiAiL29wdC9leGFtcGxl'
    'L2Jpbi9hcHAifQogICAgdG9rZW4gPSBlbmNvZGVfdWlfcGF5bG9hZChzYW1wbGUpCiAgICBkZWNvZGVkID0gdXJsbGliLnBh'
    'cnNlLnVucXVvdGUoYmFzZTY0LmI2NGRlY29kZSh0b2tlbikuZGVjb2RlKCJhc2NpaSIpKQogICAgYXNzZXJ0IGpzb24ubG9h'
    'ZHMoZGVjb2RlZCkgPT0gc2FtcGxlCiAgICBhc3NlcnQgTUFYX0JPRFkgPD0gMTAyNCAqIDEwMjQKICAgIHFtbCA9IEhFUkUg'
    'LyAiZXZnZW5pdW1fZ3VpLnFtbCIKICAgIGlmIHFtbC5leGlzdHMoKToKICAgICAgICB0ZXh0ID0gcW1sLnJlYWRfdGV4dChl'
    'bmNvZGluZz0idXRmLTgiKQogICAgICAgIGFzc2VydCAiRXZnZW5pdW0gTmV0d29yayIgaW4gdGV4dAogICAgICAgIGFzc2Vy'
    'dCAiL2FwaS9ydW5uaW5nIiBpbiB0ZXh0CiAgICAgICAgYXNzZXJ0ICIvYXBpL2FjdGlvbiIgaW4gdGV4dAogICAgcHJpbnQo'
    'ImV2Z2VuaXVtLWd1aSBzZWxmLXRlc3QgT0siKQogICAgcmV0dXJuIDAKCgpkZWYgbWFpbigpIC0+IGludDoKICAgIGlmICIt'
    'LXNlbGYtdGVzdCIgaW4gc3lzLmFyZ3Y6CiAgICAgICAgcmV0dXJuIHNlbGZfdGVzdCgpCiAgICBpZiAiLS1kZXRhY2giIGlu'
    'IHN5cy5hcmd2OgogICAgICAgIHJldHVybiBsYXVuY2hfZGV0YWNoZWQoKQogICAgcmV0dXJuIHJ1bl9ndWkoKQoKCmlmIF9f'
    'bmFtZV9fID09ICJfX21haW5fXyI6CiAgICByYWlzZSBTeXN0ZW1FeGl0KG1haW4oKSkK'
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
    'b2Q6ICIjMTZhMzRhIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYmFkOiAiI2RjMjYyNiIKCiAgICBwcm9wZXJ0eSBz'
    'dHJpbmcgcmVwb3J0VGV4dDogIiIKICAgIHByb3BlcnR5IHN0cmluZyByZXBvcnRJZDogIiIKICAgIHByb3BlcnR5IGludCBw'
    'YWdlSW5kZXg6IDAKICAgIHByb3BlcnR5IGJvb2wgYnVzeTogZmFsc2UKICAgIHByb3BlcnR5IHN0cmluZyBlcnJvclRleHQ6'
    'ICIiCiAgICBwcm9wZXJ0eSBzdHJpbmcgcG9sbEVycm9yVGV4dDogIiIKICAgIHByb3BlcnR5IHZhciBzdGF0ZTogKHt9KQog'
    'ICAgcHJvcGVydHkgdmFyIHJ1bm5pbmdBcHBzOiBbXQogICAgcHJvcGVydHkgYm9vbCB0b2tlbkVkaXRpbmc6IGZhbHNlCiAg'
    'ICBwcm9wZXJ0eSBib29sIGRldmljZUVkaXRpbmc6IGZhbHNlCiAgICByZWFkb25seSBwcm9wZXJ0eSBib29sIHRva2VuU2F2'
    'ZWQ6IEJvb2xlYW4ocm9vdC50dW5uZWwuaGFzX3Rva2VuKQogICAgcmVhZG9ubHkgcHJvcGVydHkgYm9vbCB0b2tlbkxvY2tl'
    'ZDogdG9rZW5TYXZlZCAmJiAhdG9rZW5FZGl0aW5nCiAgICByZWFkb25seSBwcm9wZXJ0eSB2YXIgdHVubmVsOiByb290LnN0'
    'YXRlLnR1bm5lbCB8fCAoe30pCiAgICByZWFkb25seSBwcm9wZXJ0eSB2YXIgcG9saWN5OiByb290LnN0YXRlLnBvbGljeSB8'
    'fCAoe30pCiAgICByZWFkb25seSBwcm9wZXJ0eSBzdHJpbmcgY2F0ZWdvcnk6IFsiIiwgImFwcGxpY2F0aW9ucyIsICJuZXR3'
    'b3JrcyIsICJwb3J0cyIsICJkbnMiLCAiIl1bcGFnZUluZGV4XQogICAgcHJvcGVydHkgYm9vbCBzaG93QmFzZTogZmFsc2UK'
    'CiAgICByZWFkb25seSBwcm9wZXJ0eSB2YXIgYXJnczogUXQuYXBwbGljYXRpb24uYXJndW1lbnRzCiAgICByZWFkb25seSBw'
    'cm9wZXJ0eSBzdHJpbmcgYXBpVG9rZW46IGFyZ3MubGVuZ3RoID49IDIgPyBTdHJpbmcoYXJnc1thcmdzLmxlbmd0aCAtIDFd'
    'KSA6ICIiCiAgICByZWFkb25seSBwcm9wZXJ0eSBzdHJpbmcgYXBpUG9ydDogYXJncy5sZW5ndGggPj0gMyA/IFN0cmluZyhh'
    'cmdzW2FyZ3MubGVuZ3RoIC0gMl0pIDogIjAiCiAgICByZWFkb25seSBwcm9wZXJ0eSBzdHJpbmcgYXBpQmFzZTogImh0dHA6'
    'Ly8xMjcuMC4wLjE6IiArIGFwaVBvcnQKCiAgICBwcm9wZXJ0eSBib29sIHN0YXRlUGVuZGluZzogZmFsc2UKICAgIHByb3Bl'
    'cnR5IGJvb2wgcnVubmluZ1BlbmRpbmc6IGZhbHNlCgogICAgZnVuY3Rpb24gYXBpKG1ldGhvZCwgcGF0aCwgYm9keSwgY2Fs'
    'bGJhY2ssIG9wZXJhdGlvbikgewogICAgICAgIGNvbnN0IHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpCiAgICAgICAgbGV0'
    'IGZpbmlzaGVkID0gZmFsc2UKICAgICAgICBjb25zdCB0aW1lciA9IHJlcXVlc3RUaW1lci5jcmVhdGVPYmplY3Qocm9vdCkK'
    'ICAgICAgICBmdW5jdGlvbiBmaW5pc2goZXJyb3IsIHBheWxvYWQpIHsKICAgICAgICAgICAgaWYgKGZpbmlzaGVkKQogICAg'
    'ICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGZpbmlzaGVkID0gdHJ1ZQogICAgICAgICAgICB0aW1lci5zdG9wKCkK'
    'ICAgICAgICAgICAgdGltZXIuZGVzdHJveSgpCiAgICAgICAgICAgIGlmIChwYXRoID09PSAiL2FwaS9zdGF0ZSIpIHJvb3Qu'
    'c3RhdGVQZW5kaW5nID0gZmFsc2UKICAgICAgICAgICAgaWYgKHBhdGggPT09ICIvYXBpL3J1bm5pbmciKSByb290LnJ1bm5p'
    'bmdQZW5kaW5nID0gZmFsc2UKICAgICAgICAgICAgaWYgKG9wZXJhdGlvbikgewogICAgICAgICAgICAgICAgcm9vdC5idXN5'
    'ID0gZmFsc2UKICAgICAgICAgICAgICAgIHJvb3QuZXJyb3JUZXh0ID0gZXJyb3IgfHwgIiIKICAgICAgICAgICAgfSBlbHNl'
    'IHsKICAgICAgICAgICAgICAgIHJvb3QucG9sbEVycm9yVGV4dCA9IGVycm9yIHx8ICIiCiAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgaWYgKCFlcnJvciAmJiBjYWxsYmFjaykgY2FsbGJhY2socGF5bG9hZCkKICAgICAgICB9CiAgICAgICAgdGltZXIu'
    'aW50ZXJ2YWwgPSBvcGVyYXRpb24gPyA3ODAwMDAgOiAxMjAwMAogICAgICAgIHRpbWVyLnRyaWdnZXJlZC5jb25uZWN0KGZ1'
    'bmN0aW9uKCkgewogICAgICAgICAgICBmaW5pc2gob3BlcmF0aW9uID8gItCe0YLQstC10YIg0L7Qv9C10YDQsNGG0LjQuCDQ'
    'vdC1INC/0L7Qu9GD0YfQtdC9LiDQn9GA0L7QstC10YDRjCB2cG4gc3RhdHVzINC/0LXRgNC10LQg0L/QvtCy0YLQvtGA0L3R'
    'i9C8INC/0LXRgNC10LrQu9GO0YfQtdC90LjQtdC8LiIgOiAi0J7Qv9GA0L7RgSDRgdC+0YHRgtC+0Y/QvdC40Y8g0L3QtSDQ'
    't9Cw0LLQtdGA0YjQuNC70YHRjyIsIG51bGwpCiAgICAgICAgICAgIHhoci5hYm9ydCgpCiAgICAgICAgfSkKICAgICAgICB4'
    'aHIub3BlbihtZXRob2QsIGFwaUJhc2UgKyBwYXRoLCB0cnVlKQogICAgICAgIHhoci5zZXRSZXF1ZXN0SGVhZGVyKCJYLUV2'
    'Z2VuaXVtLVRva2VuIiwgYXBpVG9rZW4pCiAgICAgICAgaWYgKGJvZHkgIT09IG51bGwpCiAgICAgICAgICAgIHhoci5zZXRS'
    'ZXF1ZXN0SGVhZGVyKCJDb250ZW50LVR5cGUiLCAiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOCIpCiAgICAgICAg'
    'eGhyLm9ucmVhZHlzdGF0ZWNoYW5nZSA9IGZ1bmN0aW9uKCkgewogICAgICAgICAgICBpZiAoeGhyLnJlYWR5U3RhdGUgIT09'
    'IFhNTEh0dHBSZXF1ZXN0LkRPTkUgfHwgZmluaXNoZWQpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgbGV0'
    'IHBheWxvYWQgPSBudWxsCiAgICAgICAgICAgIHRyeSB7IHBheWxvYWQgPSBKU09OLnBhcnNlKFN0cmluZyh4aHIucmVzcG9u'
    'c2VUZXh0IHx8ICJ7fSIpKSB9CiAgICAgICAgICAgIGNhdGNoIChlKSB7IGZpbmlzaCgi0J3QtSDRg9C00LDQu9C+0YHRjCDR'
    'gNCw0LfQvtCx0YDQsNGC0Ywg0L7RgtCy0LXRgiDQu9C+0LrQsNC70YzQvdC+0LPQviBBUEkiLCBudWxsKTsgcmV0dXJuIH0K'
    'ICAgICAgICAgICAgaWYgKHhoci5zdGF0dXMgPCAyMDAgfHwgeGhyLnN0YXR1cyA+PSAzMDAgfHwgIXBheWxvYWQub2spIHsK'
    'ICAgICAgICAgICAgICAgIGZpbmlzaChTdHJpbmcocGF5bG9hZC5lcnJvciB8fCAoIkhUVFAgIiArIHhoci5zdGF0dXMpKSwg'
    'bnVsbCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICB9CiAgICAgICAgICAgIGZpbmlzaChudWxsLCBwYXls'
    'b2FkKQogICAgICAgIH0KICAgICAgICB0aW1lci5zdGFydCgpCiAgICAgICAgeGhyLnNlbmQoYm9keSA9PT0gbnVsbCA/IG51'
    'bGwgOiBKU09OLnN0cmluZ2lmeShib2R5KSkKICAgIH0KCiAgICBDb21wb25lbnQgewogICAgICAgIGlkOiByZXF1ZXN0VGlt'
    'ZXIKICAgICAgICBUaW1lciB7IHJlcGVhdDogZmFsc2UgfQogICAgfQoKICAgIGZ1bmN0aW9uIHJlZnJlc2hTdGF0ZSgpIHsK'
    'ICAgICAgICBpZiAoc3RhdGVQZW5kaW5nKSByZXR1cm4KICAgICAgICBzdGF0ZVBlbmRpbmcgPSB0cnVlCiAgICAgICAgYXBp'
    'KCJHRVQiLCAiL2FwaS9zdGF0ZSIsIG51bGwsIGZ1bmN0aW9uKHBheWxvYWQpIHsKICAgICAgICAgICAgcm9vdC5zdGF0ZSA9'
    'IHBheWxvYWQuc3RhdGUgfHwgKHt9KQogICAgICAgIH0pCiAgICB9CgogICAgZnVuY3Rpb24gcmVmcmVzaFJ1bm5pbmcoKSB7'
    'CiAgICAgICAgaWYgKHJ1bm5pbmdQZW5kaW5nKSByZXR1cm4KICAgICAgICBydW5uaW5nUGVuZGluZyA9IHRydWUKICAgICAg'
    'ICBhcGkoIkdFVCIsICIvYXBpL3J1bm5pbmciLCBudWxsLCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAgIHJvb3Qu'
    'cnVubmluZ0FwcHMgPSAocGF5bG9hZC5ydW5uaW5nICYmIHBheWxvYWQucnVubmluZy5hcHBsaWNhdGlvbnMpIHx8IFtdCiAg'
    'ICAgICAgfSkKICAgIH0KCiAgICBmdW5jdGlvbiBhY3Rpb24ocGF5bG9hZCwgb25TdWNjZXNzKSB7CiAgICAgICAgaWYgKGJ1'
    'c3kgfHwgKEJvb2xlYW4oc3RhdGUuY29ubmVjdGluZykgJiYgcGF5bG9hZC5hY3Rpb24gIT09ICJkaXNjb25uZWN0IikpCiAg'
    'ICAgICAgICAgIHJldHVybgogICAgICAgIGJ1c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkvYWN0aW9uIiwg'
    'cGF5bG9hZCwgZnVuY3Rpb24oX3JlcGx5KSB7CiAgICAgICAgICAgIHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAgIGlm'
    'IChfcmVwbHkuc3RhdGUpIHJvb3Quc3RhdGUgPSBfcmVwbHkuc3RhdGUKICAgICAgICAgICAgaWYgKG9uU3VjY2Vzcykgb25T'
    'dWNjZXNzKF9yZXBseSkKICAgICAgICAgICAgcm9vdC5yZWZyZXNoU3RhdGUoKQogICAgICAgICAgICByb290LnJlZnJlc2hS'
    'dW5uaW5nKCkKICAgICAgICB9LCB0cnVlKQogICAgfQoKICAgIGZ1bmN0aW9uIHRvZ2dsZVZwbigpIHsKICAgICAgICBpZiAo'
    'YnVzeSB8fCBCb29sZWFuKHN0YXRlLmNvbm5lY3RpbmcpKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBidXN5ID0gdHJ1'
    'ZQogICAgICAgIGFwaSgiUE9TVCIsICIvYXBpL3RvZ2dsZSIsIHt9LCBmdW5jdGlvbihwYXlsb2FkKSB7CiAgICAgICAgICAg'
    'IHJvb3QuYnVzeSA9IGZhbHNlCiAgICAgICAgICAgIHJvb3Quc3RhdGUgPSBwYXlsb2FkLnN0YXRlIHx8ICh7fSkKICAgICAg'
    'ICB9LCB0cnVlKQogICAgfQoKICAgIGZ1bmN0aW9uIGZpbHRlcmVkUnVubmluZygpIHsKICAgICAgICBjb25zdCBuZWVkbGUg'
    'PSBhcHBTZWFyY2gudGV4dC50cmltKCkudG9Mb3dlckNhc2UoKQogICAgICAgIGlmICghbmVlZGxlLmxlbmd0aCkKICAgICAg'
    'ICAgICAgcmV0dXJuIHJ1bm5pbmdBcHBzCiAgICAgICAgcmV0dXJuIHJ1bm5pbmdBcHBzLmZpbHRlcihmdW5jdGlvbihhcHAp'
    'IHsKICAgICAgICAgICAgcmV0dXJuIFN0cmluZyhhcHAubmFtZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVk'
    'bGUpCiAgICAgICAgICAgICAgICB8fCBTdHJpbmcoYXBwLmV4ZSB8fCAiIikudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhuZWVk'
    'bGUpCiAgICAgICAgfSkKICAgIH0KCiAgICBDb21wb25lbnQub25Db21wbGV0ZWQ6IHsKICAgICAgICByZWZyZXNoU3RhdGUo'
    'KQogICAgICAgIHJlZnJlc2hSdW5uaW5nKCkKICAgIH0KCiAgICBUaW1lciB7CiAgICAgICAgaW50ZXJ2YWw6IDI1MDAKICAg'
    'ICAgICByZXBlYXQ6IHRydWUKICAgICAgICBydW5uaW5nOiB0cnVlCiAgICAgICAgb25UcmlnZ2VyZWQ6IHJvb3QucmVmcmVz'
    'aFN0YXRlKCkKICAgIH0KCiAgICBDLkRpYWxvZyB7CiAgICAgICAgaWQ6IHN1cHBvcnREaWFsb2cKICAgICAgICB0aXRsZTog'
    'ItCe0YLRh9GR0YIg0LTQu9GPINC/0L7QtNC00LXRgNC20LrQuCIKICAgICAgICBtb2RhbDogdHJ1ZQogICAgICAgIGFuY2hv'
    'cnMuY2VudGVySW46IHBhcmVudAogICAgICAgIHdpZHRoOiBNYXRoLm1pbihyb290LndpZHRoLTYwLDc2MCkKICAgICAgICBo'
    'ZWlnaHQ6IE1hdGgubWluKHJvb3QuaGVpZ2h0LTUwLDYyMCkKICAgICAgICBjb250ZW50SXRlbTogQ29sdW1uTGF5b3V0IHsK'
    'ICAgICAgICAgICAgc3BhY2luZzogMTIKICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdy'
    'YXBNb2RlOiBUZXh0LldyYXA7IHRleHQ6ICLQktC10YDRgdC40Y8sINGN0YLQsNC/0Ysg0L/QvtC00LrQu9GO0YfQtdC90LjR'
    'jywg0L7RiNC40LHQutC4INC4INC30LDQvNC10YDRiy4g0JHQtdC3INGC0L7QutC10L3QvtCyLCDQutC70Y7Rh9C10LksINC4'
    '0YHRgtC+0YDQuNC4INGB0LDQudGC0L7QsiDQuCDRgdC/0LjRgdC60LAg0L/RgNC40LvQvtC20LXQvdC40LkuINCe0YLQv9GA'
    '0LDQstC60LAg0LTQvtCx0YDQvtCy0L7Qu9GM0L3QsNGPOyDRgdC10YDQstC10YAg0YXRgNCw0L3QuNGCINC+0YLRh9GR0YIg'
    '0LTQviA3INC00L3QtdC5LiIgfQogICAgICAgICAgICBDLlNjcm9sbFZpZXcgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBM'
    'YXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAgQy5UZXh0QXJlYSB7IHRleHQ6IHJvb3QucmVwb3J0VGV4'
    'dDsgcmVhZE9ubHk6IHRydWU7IHNlbGVjdEJ5TW91c2U6IHRydWU7IHdyYXBNb2RlOiBUZXh0RWRpdC5XcmFwOyBmb250LmZh'
    'bWlseTogIm1vbm9zcGFjZSI7IGZvbnQucGl4ZWxTaXplOiAxMSB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5DaGVj'
    'a0JveCB7IGlkOiByZXBvcnRDb25zZW50OyB0ZXh0OiAi0KDQsNC30YDQtdGI0LDRjiDQvtGC0L/RgNCw0LLQuNGC0Ywg0L/Q'
    'vtC60LDQt9Cw0L3QvdGL0Lkg0L7RgtGH0ZHRgiDQstC70LDQtNC10LvRjNGG0YMgVlBOIiB9CiAgICAgICAgICAgIFJvd0xh'
    'eW91dCB7CiAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntGC0L/RgNCw0LLQuNGC0YwiOyBwcmltYXJ5'
    'OiB0cnVlOyBlbmFibGVkQnV0dG9uOiByZXBvcnRDb25zZW50LmNoZWNrZWQgJiYgIXJvb3QuYnVzeTsgb25DbGlja2VkOiBy'
    'b290LmFjdGlvbih7YWN0aW9uOiJyZXBvcnQtc2VuZCIscmVwb3J0X2lkOnJvb3QucmVwb3J0SWQsY29uc2VudDp0cnVlfSxm'
    'dW5jdGlvbigpe3N1cHBvcnREaWFsb2cuY2xvc2UoKTtyb290LmVycm9yVGV4dD0i0J7RgtGH0ZHRgiDQvtGC0L/RgNCw0LLQ'
    'u9C10L0uIElEOiAiK3Jvb3QucmVwb3J0SWR9KSB9CiAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQl9Cw'
    '0LrRgNGL0YLRjCI7IG9uQ2xpY2tlZDogc3VwcG9ydERpYWxvZy5jbG9zZSgpIH0KICAgICAgICAgICAgfQogICAgICAgICAg'
    'ICBDLkxhYmVsIHsgdmlzaWJsZTogIXJvb3Quc3RhdGUuYWN0aXZlOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9k'
    'ZTogVGV4dC5XcmFwOyB0ZXh0OiAi0JXRgdC70Lgg0LfQsNGJ0LjRgtCwINCx0LvQvtC60LjRgNGD0LXRgiDRgdC10YLRjCwg'
    '0L7RgtGH0ZHRgiDQvtGB0YLQsNC90LXRgtGB0Y8g0LvQvtC60LDQu9GM0L3QviDQtNC+INCy0L7RgdGB0YLQsNC90L7QstC7'
    '0LXQvdC40Y8g0LjQu9C4INGP0LLQvdC+0LPQviDQvtGC0LrQu9GO0YfQtdC90LjRjyBWUE4uIjsgY29sb3I6IHJvb3QudGV4'
    'dE11dGVkIH0KICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IEZsYXRCdXR0b246IFJlY3RhbmdsZSB7CiAgICAgICAg'
    'aWQ6IGZsYXRCdXR0b24KICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbGFiZWwKICAgICAgICBwcm9wZXJ0eSBi'
    'b29sIHByaW1hcnk6IGZhbHNlCiAgICAgICAgcHJvcGVydHkgYm9vbCBkYW5nZXI6IGZhbHNlCiAgICAgICAgcHJvcGVydHkg'
    'Ym9vbCBlbmFibGVkQnV0dG9uOiB0cnVlCiAgICAgICAgc2lnbmFsIGNsaWNrZWQoKQogICAgICAgIGltcGxpY2l0SGVpZ2h0'
    'OiAzOAogICAgICAgIGltcGxpY2l0V2lkdGg6IE1hdGgubWF4KDkyLCBidXR0b25UZXh0LmltcGxpY2l0V2lkdGggKyAyOCkK'
    'ICAgICAgICByYWRpdXM6IDEwCiAgICAgICAgY29sb3I6ICFlbmFibGVkQnV0dG9uID8gIiNlZWYwZjMiCiAgICAgICAgICAg'
    'ICAgOiBkYW5nZXIgPyAoYnV0dG9uTW91c2UuY29udGFpbnNNb3VzZSA/ICIjZmVlMmUyIiA6ICIjZmVmMmYyIikKICAgICAg'
    'ICAgICAgICA6IHByaW1hcnkgPyAoYnV0dG9uTW91c2UuY29udGFpbnNNb3VzZSA/ICIjMjA5OWRjIiA6IHJvb3QuYWNjZW50'
    'KQogICAgICAgICAgICAgIDogKGJ1dHRvbk1vdXNlLmNvbnRhaW5zTW91c2UgPyAiI2VlZjJmNyIgOiAiI2Y3ZjlmYyIpCiAg'
    'ICAgICAgYm9yZGVyLndpZHRoOiBwcmltYXJ5ID8gMCA6IDEKICAgICAgICBib3JkZXIuY29sb3I6IGRhbmdlciA/ICIjZmVj'
    'YWNhIiA6IHJvb3QuYm9yZGVyCiAgICAgICAgb3BhY2l0eTogZW5hYmxlZEJ1dHRvbiA/IDEgOiAwLjYKCiAgICAgICAgQy5M'
    'YWJlbCB7CiAgICAgICAgICAgIGlkOiBidXR0b25UZXh0CiAgICAgICAgICAgIGFuY2hvcnMuY2VudGVySW46IHBhcmVudAog'
    'ICAgICAgICAgICB0ZXh0OiBmbGF0QnV0dG9uLmxhYmVsCiAgICAgICAgICAgIGNvbG9yOiBmbGF0QnV0dG9uLnByaW1hcnkg'
    'PyAid2hpdGUiIDogKGZsYXRCdXR0b24uZGFuZ2VyID8gcm9vdC5iYWQgOiByb290LnRleHRNYWluKQogICAgICAgICAgICBm'
    'b250LnBpeGVsU2l6ZTogMTMKICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuRGVtaUJvbGQKICAgICAgICB9CiAgICAg'
    'ICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IGJ1dHRvbk1vdXNlCiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFy'
    'ZW50CiAgICAgICAgICAgIGVuYWJsZWQ6IGZsYXRCdXR0b24uZW5hYmxlZEJ1dHRvbgogICAgICAgICAgICBob3ZlckVuYWJs'
    'ZWQ6IHRydWUKICAgICAgICAgICAgY3Vyc29yU2hhcGU6IGVuYWJsZWQgPyBRdC5Qb2ludGluZ0hhbmRDdXJzb3IgOiBRdC5B'
    'cnJvd0N1cnNvcgogICAgICAgICAgICBvbkNsaWNrZWQ6IGZsYXRCdXR0b24uY2xpY2tlZCgpCiAgICAgICAgfQogICAgfQoK'
    'ICAgIGNvbXBvbmVudCBOYXZCdXR0b246IFJlY3RhbmdsZSB7CiAgICAgICAgaWQ6IG5hdgogICAgICAgIHJlcXVpcmVkIHBy'
    'b3BlcnR5IHN0cmluZyBsYWJlbAogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IGludCBpbmRleAogICAgICAgIHByb3BlcnR5'
    'IHN0cmluZyBzaG9ydExhYmVsOiAiIgogICAgICAgIHNpZ25hbCBjbGlja2VkKCkKICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgaW1wbGljaXRXaWR0aDogMTg2CiAgICAgICAgaGVpZ2h0OiA0OAogICAgICAgIHJhZGl1czogMTEK'
    'ICAgICAgICBjb2xvcjogcm9vdC5wYWdlSW5kZXggPT09IGluZGV4ID8gIiMyNTMyNDYiIDogKG5hdk1vdXNlLmNvbnRhaW5z'
    'TW91c2UgPyByb290LnNpZGViYXJIb3ZlciA6ICJ0cmFuc3BhcmVudCIpCgogICAgICAgIFJvd0xheW91dCB7CiAgICAgICAg'
    'ICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIGFuY2hvcnMubGVmdE1hcmdpbjogMTIKICAgICAgICAgICAg'
    'YW5jaG9ycy5yaWdodE1hcmdpbjogMTIKICAgICAgICAgICAgc3BhY2luZzogMTEKICAgICAgICAgICAgUmVjdGFuZ2xlIHsK'
    'ICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDI4CiAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogMjgKICAg'
    'ICAgICAgICAgICAgIHJhZGl1czogOAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5k'
    'ZXggPyByb290LmFjY2VudCA6ICIjMjczNDQ5IgogICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgICAgICAgICAgdGV4dDogbmF2LnNob3J0TGFiZWwKICAg'
    'ICAgICAgICAgICAgICAgICBjb2xvcjogIndoaXRlIgogICAgICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMAog'
    'ICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250LkJvbGQKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'fQogICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAg'
    'ICAgICAgIHRleHQ6IG5hdi5sYWJlbAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5k'
    'ZXggPyAid2hpdGUiIDogIiNjYmQ1ZTEiCiAgICAgICAgICAgICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAgICAg'
    'ICAgIGZvbnQud2VpZ2h0OiByb290LnBhZ2VJbmRleCA9PT0gbmF2LmluZGV4ID8gRm9udC5EZW1pQm9sZCA6IEZvbnQuTm9y'
    'bWFsCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IG5hdk1vdXNl'
    'CiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAg'
    'ICAgICBjdXJzb3JTaGFwZTogUXQuUG9pbnRpbmdIYW5kQ3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAg'
    'ICAgICAgICAgcm9vdC5wYWdlSW5kZXggPSBuYXYuaW5kZXgKICAgICAgICAgICAgICAgIG5hdi5jbGlja2VkKCkKICAgICAg'
    'ICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgQ2FyZDogUmVjdGFuZ2xlIHsKICAgICAgICByYWRpdXM6'
    'IDE2CiAgICAgICAgY29sb3I6IHJvb3Quc3VyZmFjZQogICAgICAgIGJvcmRlci53aWR0aDogMQogICAgICAgIGJvcmRlci5j'
    'b2xvcjogcm9vdC5ib3JkZXIKICAgIH0KCiAgICBSb3dMYXlvdXQgewogICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAg'
    'ICAgICAgc3BhY2luZzogMAogICAgICAgIFJlY3RhbmdsZSB7CiAgICAgICAgICAgIExheW91dC5wcmVmZXJyZWRXaWR0aDog'
    'MjIyCiAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgIGNvbG9yOiByb290LnNpZGViYXIK'
    'ICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAg'
    'ICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDE4CiAgICAgICAgICAgICAgICBzcGFjaW5nOiA4CiAgICAgICAgICAgICAgICBD'
    'LkxhYmVsIHsgdGV4dDogIkV2Z2VuaXVtIjsgY29sb3I6ICJ3aGl0ZSI7IGZvbnQucGl4ZWxTaXplOiAyMzsgZm9udC5ib2xk'
    'OiB0cnVlOyBMYXlvdXQudG9wTWFyZ2luOiAxMiB9CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIk5ldHdvcmsi'
    'OyBjb2xvcjogIiM5NGEzYjgiOyBMYXlvdXQuYm90dG9tTWFyZ2luOiAyOCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24g'
    'eyBsYWJlbDogIlZQTiI7IHNob3J0TGFiZWw6ICJWUE4iOyBpbmRleDogMCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24g'
    'eyBsYWJlbDogItCf0YDQuNC70L7QttC10L3QuNGPIjsgc2hvcnRMYWJlbDogIkFQUCI7IGluZGV4OiAxOyBvbkNsaWNrZWQ6'
    'IHJvb3QucmVmcmVzaFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBsYWJlbDogItCh0LDQudGC0Ysg'
    '0LggSVAiOyBzaG9ydExhYmVsOiAiTkVUIjsgaW5kZXg6IDIgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6'
    'ICLQn9C+0YDRgtGLIjsgc2hvcnRMYWJlbDogIlBSVCI7IGluZGV4OiAzIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7'
    'IGxhYmVsOiAiRE5TIjsgc2hvcnRMYWJlbDogIkROUyI7IGluZGV4OiA0IH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7'
    'IGxhYmVsOiAiV2F5ZHJvaWQiOyBzaG9ydExhYmVsOiAiV0FZIjsgaW5kZXg6IDUgfQogICAgICAgICAgICAgICAgSXRlbSB7'
    'IExheW91dC5maWxsSGVpZ2h0OiB0cnVlIH0KICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiByb290LnN0YXRlLmFj'
    'dGl2ZSA/ICLil48g0J/QvtC00LrQu9GO0YfQtdC90L4iIDogKHJvb3Quc3RhdGUuZ3VhcmQgPyAi4pePINCX0LDRidC40YLQ'
    'sCDQstC60LvRjtGH0LXQvdCwIiA6ICLil4sg0J7RgtC60LvRjtGH0LXQvdC+Iik7IGNvbG9yOiByb290LnN0YXRlLmFjdGl2'
    'ZSA/ICIjNGFkZTgwIiA6ICIjY2JkNWUxIiB9CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCS0LXRgNGB0LjR'
    'jyAiICsgKHJvb3Quc3RhdGUubWFuYWdlcl92ZXJzaW9uIHx8ICLigKYiKTsgY29sb3I6ICIjOTRhM2I4IjsgZm9udC5waXhl'
    'bFNpemU6IDEyIH0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgIExh'
    'eW91dC5tYXJnaW5zOiAyOAogICAgICAgICAgICBzcGFjaW5nOiAxNgogICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogWyLQ'
    'ktCw0YggVlBOIiwgItCY0YHQutC70Y7Rh9C10L3QuNGPINC/0YDQuNC70L7QttC10L3QuNC5IiwgItCh0LDQudGC0Ysg0Lgg'
    'SVAiLCAi0JjRgdC60LvRjtGH0LXQvdC40Y8g0L/QvtGA0YLQvtCyIiwgIkROUyIsICJXYXlkcm9pZCJdW3Jvb3QucGFnZUlu'
    'ZGV4XTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXplOiAyNzsgZm9udC5ib2xkOiB0cnVlIH0KICAgICAg'
    'ICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICB2'
    'aXNpYmxlOiBCb29sZWFuKHJvb3QuZXJyb3JUZXh0IHx8IHJvb3QucG9sbEVycm9yVGV4dCkKICAgICAgICAgICAgICAgIHRl'
    'eHQ6IHJvb3QuZXJyb3JUZXh0IHx8IHJvb3QucG9sbEVycm9yVGV4dAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYmFk'
    'CiAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5CdXN5SW5k'
    'aWNhdG9yIHsgcnVubmluZzogcm9vdC5idXN5OyB2aXNpYmxlOiBydW5uaW5nOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAy'
    'OCB9CiAgICAgICAgICAgIEMuU2Nyb2xsVmlldyB7CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAg'
    'ICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAg'
    'ICAgICAgICAgY29udGVudFdpZHRoOiBhdmFpbGFibGVXaWR0aAogICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAg'
    'ICAgICAgICAgICAgICAgICB3aWR0aDogcGFyZW50LndpZHRoCiAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgKICAg'
    'ICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiByb290LnBh'
    'Z2VJbmRleCA9PT0gMAogICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHNwYWNpbmc6IDE4CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgdmlzaWJsZTogcm9vdC50b2tlblNhdmVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogZGV2aWNlQm9keS5p'
    'bXBsaWNpdEhlaWdodCArIDMyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGlkOiBkZXZpY2VCb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5j'
    'aG9ycy5maWxsOiBwYXJlbnQ7IGFuY2hvcnMubWFyZ2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBS'
    'b3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNpYmxlOiAhcm9vdC5kZXZpY2VFZGl0aW5n'
    'OyB0ZXh0OiByb290LnR1bm5lbC5kZXZpY2VfbmFtZSB8fCAi0J/QvtC70YPRh9Cw0Y4g0LjQvNGPINGD0YHRgtGA0L7QudGB'
    '0YLQstCw4oCmIjsgZm9udC5waXhlbFNpemU6IDE4OyBmb250LmJvbGQ6IHRydWU7IGNvbG9yOiByb290LnRleHRNYWluOyBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBlbGlkZTogVGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQy5UZXh0RmllbGQgeyBpZDogZGV2aWNlTmFtZUlucHV0OyB2aXNpYmxlOiByb290LmRldmljZUVkaXRp'
    'bmc7IExheW91dC5maWxsV2lkdGg6IHRydWU7IG1heGltdW1MZW5ndGg6IDY0OyBwbGFjZWhvbGRlclRleHQ6ICLQmNC80Y8g'
    '0YPRgdGC0YDQvtC50YHRgtCy0LAiOyBzZWxlY3RCeU1vdXNlOiB0cnVlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiByb290LmRldmljZUVkaXRpbmcgPyAi0KHQvtGF0YDQsNC90LjRgtGMIiA6'
    'ICLQmNC30LzQtdC90LjRgtGMINC40LzRjyI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3RhdGUuY29u'
    'bmVjdGluZyAmJiAoIXJvb3QuZGV2aWNlRWRpdGluZyB8fCBkZXZpY2VOYW1lSW5wdXQudGV4dC50cmltKCkubGVuZ3RoID4g'
    'MCk7IG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFyb290LmRldmlj'
    'ZUVkaXRpbmcpIHsgZGV2aWNlTmFtZUlucHV0LnRleHQ9cm9vdC50dW5uZWwuZGV2aWNlX25hbWUgfHwgIiI7IHJvb3QuZGV2'
    'aWNlRWRpdGluZz10cnVlOyBkZXZpY2VOYW1lSW5wdXQuZm9yY2VBY3RpdmVGb2N1cygpIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGVsc2Ugcm9vdC5hY3Rpb24oe2FjdGlvbjoiZGV2aWNlLW5hbWUiLG5hbWU6ZGV2aWNl'
    'TmFtZUlucHV0LnRleHQudHJpbSgpfSxmdW5jdGlvbigpe3Jvb3QuZGV2aWNlRWRpdGluZz1mYWxzZX0pCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0'
    'dG9uIHsgdmlzaWJsZTogcm9vdC5kZXZpY2VFZGl0aW5nOyBsYWJlbDogItCe0YLQvNC10L3QsCI7IG9uQ2xpY2tlZDogcm9v'
    'dC5kZXZpY2VFZGl0aW5nPWZhbHNlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IHJvb3QudHVubmVsLmRldmljZV9uYW1lX3BlbmRpbmcgPyAi0JjQ'
    'vNGPINGB0L7RhdGA0LDQvdC10L3QviDQvdCwINC60L7QvNC/0YzRjtGC0LXRgNC1INC4INCx0YPQtNC10YIg0L7RgtC/0YDQ'
    'sNCy0LvQtdC90L4g0L/RgNC4INC/0L7QtNC60LvRjtGH0LXQvdC40LguIiA6ICLQrdGC0L4g0LjQvNGPINCy0LjQtNC90L4g'
    '0LIg0LLQtdCxLdC/0LDQvdC10LvQuCDRgdGA0LXQtNC4INCy0LDRiNC40YUg0L/QvtC00LrQu9GO0YfQtdC90LjQuS4iOyBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgaW1wbGljaXRIZWlnaHQ6IGNvbm5lY3Rpb25Cb2R5LmltcGxpY2l0SGVpZ2h0ICsgNDAKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'aWQ6IGNvbm5lY3Rpb25Cb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDIwCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgc3BhY2luZzogMTUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDog'
    'cm9vdC5zdGF0ZS5hY3RpdmUgPyAi0J/QvtC00LrQu9GO0YfQtdC90L4g0YfQtdGA0LXQtyDQrdGB0YLQvtC90LjRjiIgOiAo'
    'cm9vdC50dW5uZWwucnVubmluZyA/ICLQn9C+0LTQutC70Y7Rh9C10L3QuNC14oCmIiA6ICLQk9C+0YLQvtCyINC6INC/0L7Q'
    'tNC60LvRjtGH0LXQvdC40Y4iKTsgY29sb3I6IHJvb3Quc3RhdGUuYWN0aXZlID8gcm9vdC5nb29kIDogcm9vdC50ZXh0TWFp'
    'bjsgZm9udC5waXhlbFNpemU6IDIxOyBmb250LmJvbGQ6IHRydWUgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgeyB0ZXh0OiByb290LnR1bm5lbC5tZXNzYWdlIHx8ICLQktCy0LXQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQ'
    'uNC10L3RgtCwIjsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4'
    'dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlByb2dyZXNzQmFyIHsgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZTsgdmlzaWJsZTogQm9vbGVhbihyb290LnR1bm5lbC5ydW5uaW5nKSAmJiAhcm9vdC5zdGF0ZS5hY3RpdmU7IGZy'
    'b206IDA7IHRvOiAxMDA7IHZhbHVlOiBOdW1iZXIocm9vdC50dW5uZWwucHJvZ3Jlc3MgfHwgMCkgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRC'
    'dXR0b24geyBsYWJlbDogcm9vdC50dW5uZWwucnVubmluZyB8fCByb290LnN0YXRlLmd1YXJkID8gItCe0YLQutC70Y7Rh9C4'
    '0YLRjCIgOiAi0J/QvtC00LrQu9GO0YfQuNGC0YwiOyBwcmltYXJ5OiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5'
    'ICYmIChyb290LnRva2VuU2F2ZWQgfHwgcm9vdC5zdGF0ZS5ndWFyZCk7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlv'
    'bjogcm9vdC50dW5uZWwucnVubmluZyB8fCByb290LnN0YXRlLmd1YXJkID8gImRpc2Nvbm5lY3QiIDogImNvbm5lY3QifSkg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQktC+0YHRgdGC0LDQ'
    'vdC+0LLQuNGC0YwiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFyb290LnN0YXRlLmNvbm5lY3RpbmcgJiYgcm9v'
    'dC50b2tlblNhdmVkOyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJyZXBhaXIifSkgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCS'
    '0LXRgdGMINGC0YDQsNGE0LjQuiDQuNC00ZHRgiDRh9C10YDQtdC3IFZQTiwg0LrRgNC+0LzQtSDQstC60LvRjtGH0ZHQvdC9'
    '0YvRhSDQuNGB0LrQu9GO0YfQtdC90LjQuS4g0J/RgNC4INC+0LHRgNGL0LLQtSDQt9Cw0YnQuNGJ0ZHQvdC90YvQtSDQv9C+'
    '0LTQutC70Y7Rh9C10L3QuNGPINCx0LvQvtC60LjRgNGD0Y7RgtGB0Y8uIjsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3Jh'
    'cE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDYXJkIHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0'
    'SGVpZ2h0OiB0b2tlbkJvZHkuaW1wbGljaXRIZWlnaHQgKyA0MAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1u'
    'TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogdG9rZW5Cb2R5CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNo'
    'b3JzLm1hcmdpbnM6IDIwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTIKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCi0L7QutC10L0g0LrQu9C40LXQvdGC0LAiOyBmb250LnBp'
    'eGVsU2l6ZTogMTc7IGZvbnQuYm9sZDogdHJ1ZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNpYmxlOiByb290LnRva2VuTG9ja2VkOyB0ZXh0OiByb290LnR1bm5lbC50b2tl'
    'bl9oaW50IHx8ICLQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQg'
    'eyBpZDogdG9rZW5JbnB1dDsgdmlzaWJsZTogIXJvb3QudG9rZW5Mb2NrZWQ7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHBs'
    'YWNlaG9sZGVyVGV4dDogIkVWTjEt4oCmIjsgZWNob01vZGU6IFRleHRJbnB1dC5QYXNzd29yZDsgc2VsZWN0QnlNb3VzZTog'
    'dHJ1ZTsgZW5hYmxlZDogIXJvb3QuYnVzeSAmJiAhcm9vdC50dW5uZWwucnVubmluZyB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogcm9vdC50b2tlbkxvY2tlZCA/ICLQmNC30LzQtdC90LjRgtGM'
    'IiA6ICLQn9C+0LTRgtCy0LXRgNC00LjRgtGMIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhcm9vdC50dW5uZWwu'
    'cnVubmluZyAmJiAocm9vdC50b2tlbkxvY2tlZCB8fCAvXkVWTjEtW0EtWmEtejAtOV8tXXs0M30kLy50ZXN0KHRva2VuSW5w'
    'dXQudGV4dC50cmltKCkpKTsgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBp'
    'ZiAocm9vdC50b2tlbkxvY2tlZCkgcm9vdC50b2tlbkVkaXRpbmcgPSB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBlbHNlIHJvb3QuYWN0aW9uKHthY3Rpb246ICJ0b2tlbi1zYXZlIiwgdG9rZW46IHRva2VuSW5wdXQu'
    'dGV4dC50cmltKCl9LCBmdW5jdGlvbigpIHsgdG9rZW5JbnB1dC5jbGVhcigpOyByb290LnRva2VuRWRpdGluZyA9IGZhbHNl'
    'IH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBGbGF0QnV0dG9uIHsgdmlzaWJsZTogcm9vdC50b2tlbkVkaXRpbmc7IGxhYmVsOiAi0J7RgtC80LXQvdCwIjsg'
    'b25DbGlja2VkOiB7IHRva2VuSW5wdXQuY2xlYXIoKTsgcm9vdC50b2tlbkVkaXRpbmcgPSBmYWxzZSB9IH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6'
    'ICLQntC00LjQvSDRgtC+0LrQtdC9INC90LAg0YfQtdC70L7QstC10LrQsCDigJQg0LTQu9GPINCy0YHQtdGFINC10LPQviDR'
    'g9GB0YLRgNC+0LnRgdGC0LIuIjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6'
    'ICLQntGC0YfRkdGCINC00LvRjyDQv9C+0LTQtNC10YDQttC60LgiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFy'
    'b290LnN0YXRlLmNvbm5lY3Rpbmc7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjoicmVwb3J0LXByZXZpZXcifSxm'
    'dW5jdGlvbihyZXBseSl7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcmVwb3J0PUpTT04ucGFyc2UocmVwbHku'
    'b3V0cHV0KTtyb290LnJlcG9ydElkPXJlcG9ydC5yZXBvcnRfaWQ7cm9vdC5yZXBvcnRUZXh0PUpTT04uc3RyaW5naWZ5KHJl'
    'cG9ydCxudWxsLDIpO3JlcG9ydENvbnNlbnQuY2hlY2tlZD1mYWxzZTtzdXBwb3J0RGlhbG9nLm9wZW4oKQogICAgICAgICAg'
    'ICAgICAgICAgICAgICB9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCf0YDQvtCy'
    '0LXRgNC40YLRjCDQvtCx0L3QvtCy0LvQtdC90LjRjyI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDog'
    'cm9vdC5hY3Rpb24oe2FjdGlvbjogInVwZGF0ZSJ9KSB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAg'
    'ICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJvb3QucGFnZUluZGV4ID49IDEg'
    'JiYgcm9vdC5wYWdlSW5kZXggPD0gNAogICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE2CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgd3JhcE1vZGU6IFRleHQuV3JhcAogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVk'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiByb290LnBhZ2VJbmRleCA9PT0gMSA/ICLQktGL0LHRgNCw0L3Q'
    'vdGL0LUg0L/RgNC40LvQvtC20LXQvdC40Y8g0L/QvtC00LrQu9GO0YfQsNGO0YLRgdGPINC90LDQv9GA0Y/QvNGD0Y4uINCe'
    '0YHRgtCw0LvRjNC90YvQtSDQuNGB0L/QvtC70YzQt9GD0Y7RgiBWUE4uIiA6IHJvb3QucGFnZUluZGV4ID09PSAyID8gItCU'
    '0L7QsdCw0LLRjNGC0LUg0LTQvtC80LXQvSwg0LDQtNGA0LXRgSDQuNC70Lgg0L/QvtC00YHQtdGC0YwuINCU0L7QvNC10L3R'
    'iyDQstC60LvRjtGH0LDRjtGCINC/0L7QtNC00L7QvNC10L3Rizsg0LfQvdCw0LogPSDQt9Cw0LTQsNGR0YIg0YLQvtGH0L3Q'
    'vtC1INGB0L7QstC/0LDQtNC10L3QuNC1LiDQn9GA0Lgg0L7QsdGJ0LXQvCBJUCDQu9GD0YfRiNC1INGD0LrQsNC30YvQstCw'
    '0YLRjCDQtNC+0LzQtdC9LiIgOiByb290LnBhZ2VJbmRleCA9PT0gMyA/ICLQmNGB0YXQvtC00Y/RidC40LUg4oCUINC/0L7Q'
    'tNC60LvRjtGH0LXQvdC40Y8g0Log0YPQutCw0LfQsNC90L3QvtC80YMg0L/QvtGA0YLRgy4g0JLRhdC+0LTRj9GJ0LjQtSDi'
    'gJQg0L/RgNGP0LzRi9C1INC+0YLQstC10YLRiyDQstCw0YjQtdCz0L4g0YHQtdGA0LLQtdGA0LAuINCe0LHQsCDigJQg0L7Q'
    'sdCwINC90LDQv9GA0LDQstC70LXQvdC40Y8uIiA6ICLQntCx0YvRh9C90YvQuSBETlMg0L7RgdGC0LDRkdGC0YHRjyDQsiBW'
    'UE4uINCU0L7QsdCw0LLQu9C10L3QvdGL0LUg0LfQtNC10YHRjCBETlMt0YHQtdGA0LLQtdGA0Ysg0L/QvtC70YPRh9Cw0Y7R'
    'giDQt9Cw0L/RgNC+0YHRiyDQvdCw0L/RgNGP0LzRg9GOINC4INC80L7Qs9GD0YIg0LLQuNC00LXRgtGMINC30LDQv9GA0LDR'
    'iNC40LLQsNC10LzRi9C1INC40LzQtdC90LAuINCt0YLQviDQvdC1INGB0L/QuNGB0L7QuiDRgdCw0LnRgtC+0LIuIgogICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJv'
    'Qm94IHsgaWQ6IHBvcnRQcm90b2NvbDsgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDM7IG1vZGVsOiBbIlRDUCIsICJV'
    'RFAiLCAiQk9USCJdOyBMYXlvdXQucHJlZmVycmVkV2lkdGg6IDEwMCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBD'
    'LlRleHRGaWVsZCB7IGlkOiBleGNlcHRpb25JbnB1dDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgc2VsZWN0QnlNb3VzZTog'
    'dHJ1ZTsgcGxhY2Vob2xkZXJUZXh0OiByb290LnBhZ2VJbmRleCA9PT0gMSA/ICLQmNC80Y8g0L/RgNC+0YbQtdGB0YHQsCDQ'
    'uNC70LggL9C/0L7Qu9C90YvQuS/Qv9GD0YLRjCIgOiByb290LnBhZ2VJbmRleCA9PT0gMiA/ICJleGFtcGxlLmNvbSDQuNC7'
    '0LggMTkyLjE2OC4xLjIwIiA6IHJvb3QucGFnZUluZGV4ID09PSAzID8gIjI1NTY1IiA6ICLQkNC00YDQtdGBIEROUywg0L3Q'
    'sNC/0YDQuNC80LXRgCAxOTIuMTY4LjEuMSIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Db21ib0JveCB7IGlk'
    'OiBwb3J0RGlyZWN0aW9uOyB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gMzsgbW9kZWw6IFsi0JjRgdGF0L7QtNGP0YnQ'
    'uNC1IiwgItCS0YXQvtC00Y/RidC40LUiLCAi0J7QsdCwIl07IExheW91dC5wcmVmZXJyZWRXaWR0aDogMTQwIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCU0L7QsdCw0LLQuNGC0YwiOyBwcmltYXJ5OiB0'
    'cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIGV4Y2VwdGlvbklucHV0LnRleHQudHJpbSgpLmxlbmd0aCA+IDA7'
    'IG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IHZhbHVlID0gcm9vdC5wYWdlSW5k'
    'ZXggPT09IDMgPyBwb3J0UHJvdG9jb2wuY3VycmVudFRleHQudG9Mb3dlckNhc2UoKSArICI6IiArIGV4Y2VwdGlvbklucHV0'
    'LnRleHQudHJpbSgpICsgIjoiICsgWyJvdXQiLCAiaW4iLCAiYm90aCJdW3BvcnREaXJlY3Rpb24uY3VycmVudEluZGV4XSA6'
    'IGV4Y2VwdGlvbklucHV0LnRleHQudHJpbSgpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24o'
    'e2FjdGlvbjogImFkZCIsIGNhdGVnb3J5OiByb290LmNhdGVnb3J5LCB2YWx1ZTogdmFsdWV9LCBmdW5jdGlvbigpIHsgZXhj'
    'ZXB0aW9uSW5wdXQuY2xlYXIoKSB9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfSB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'bW9kZWw6IHJvb3QucG9saWN5W3Jvb3QuY2F0ZWdvcnldIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxl'
    'Z2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJp'
    'bmcgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBtb2RlbERhdGE7IExheW91dC5maWxsV2lkdGg6'
    'IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXBBbnl3aGVyZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCj0LTQsNC70LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBl'
    'bmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJyZW1vdmUiLCBjYXRl'
    'Z29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IG1vZGVsRGF0YX0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdmlzaWJsZTogIShy'
    'b290LnBvbGljeVtyb290LmNhdGVnb3J5XSB8fCBbXSkubGVuZ3RoOyB0ZXh0OiAi0JLQsNGI0LjRhSDQuNGB0LrQu9GO0YfQ'
    'tdC90LjQuSDQv9C+0LrQsCDQvdC10YIiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICBDLlN3aXRjaCB7IHRleHQ6ICLQntGC0L7QsdGA0LDQt9C40YLRjCDQsdCw0LfQvtCy0YvQtSDQuNGB0LrQu9GO0YfQtdC9'
    '0LjRjyI7IGNoZWNrZWQ6IHJvb3Quc2hvd0Jhc2U7IG9uVG9nZ2xlZDogcm9vdC5zaG93QmFzZSA9IGNoZWNrZWQgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5zaG93QmFzZQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiAo'
    'cm9vdC5wb2xpY3kuYmFzZSB8fCB7fSlbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBkZWxlZ2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQg'
    'cHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBtb2RlbERhdGEu'
    'bGFiZWw7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNYWlu'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Td2l0Y2ggeyBjaGVja2VkOiBCb29sZWFuKG1vZGVs'
    'RGF0YS5lbmFibGVkKTsgZW5hYmxlZDogIXJvb3QuYnVzeTsgb25Ub2dnbGVkOiByb290LmFjdGlvbih7YWN0aW9uOiAiYmFz'
    'ZSIsIGNhdGVnb3J5OiByb290LmNhdGVnb3J5LCB2YWx1ZTogbW9kZWxEYXRhLmlkLCBlbmFibGVkOiBjaGVja2VkfSkgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFw'
    'OyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQ7IHRleHQ6ICLQktGLINC80L7QttC10YLQtSDQstGL0LrQu9GO0YfQuNGC0Ywg0LvR'
    'jtCx0L7QtSDQsdCw0LfQvtCy0L7QtSDQv9GA0LDQstC40LvQvi4g0KHQutGA0YvRgtC40LUg0YHQv9C40YHQutCwINC90LUg'
    '0LzQtdC90Y/QtdGCINC10LPQviDRgdC+0YHRgtC+0Y/QvdC40LUuIiB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6'
    'IHJvb3QucGFnZUluZGV4ID09PSAxCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCX0LDQv9GD0YnQtdC90Ysg0YHQtdC50YfQ'
    'sNGBIjsgZm9udC5waXhlbFNpemU6IDE4OyBmb250LmJvbGQ6IHRydWU7IGNvbG9yOiByb290LnRleHRNYWluIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IGFwcFNl'
    'YXJjaDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgcGxhY2Vob2xkZXJUZXh0OiAi0J/QvtC40YHQuiDQv9GA0LjQu9C+0LbQ'
    'tdC90LjRjyIgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCe0LHQvdC+'
    '0LLQuNGC0Ywg0YHQv9C40YHQvtC6IjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QucnVubmluZ1BlbmRpbmc7IG9uQ2xpY2tlZDog'
    'cm9vdC5yZWZyZXNoUnVubmluZygpIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJlcGVhdGVyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5wYWdlSW5k'
    'ZXggPT09IDEgPyByb290LmZpbHRlcmVkUnVubmluZygpIDogW10KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBk'
    'ZWxlZ2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVy'
    'dHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhLm5hbWU7IGNvbG9yOiByb290LnRleHRNYWluIH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBtb2RlbERhdGEuZXhlOyBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlOyBlbGlkZTogVGV4dC5FbGlkZU1pZGRsZTsgY29sb3I6IHJvb3QudGV4dE11dGVkOyBmb250'
    'LnBpeGVsU2l6ZTogMTEgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogbW9kZWxEYXRhLmV4Y2x1ZGVkID8gItCU0L7QsdCw0LLQ'
    'u9C10L3QviIgOiAi0JIg0L7QsdGF0L7QtCI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIW1vZGVsRGF0YS5leGNs'
    'dWRlZDsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAiYWRkIiwgY2F0ZWdvcnk6ICJhcHBsaWNhdGlvbnMiLCB2'
    'YWx1ZTogU3RyaW5nKG1vZGVsRGF0YS5leGUgfHwgbW9kZWxEYXRhLm5hbWUgfHwgIiIpfSkgfQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gNQogICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE4CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50'
    'ZXh0TXV0ZWQ7IHRleHQ6ICJXYXlkcm9pZCDRg9C/0YDQsNCy0LvRj9C10YLRgdGPINC+0YLQtNC10LvRjNC90L4g0L7RgiDQ'
    'v9GA0LjQu9C+0LbQtdC90LjQuSDQutC+0LzQv9GM0Y7RgtC10YDQsC4g0J/QviDRg9C80L7Qu9GH0LDQvdC40Y4g0LLQtdGB'
    '0Ywg0LXQs9C+INGC0YDQsNGE0LjQuiwg0LLQutC70Y7Rh9Cw0Y8gRE5TLCDQuNC00ZHRgiDQvdCw0L/RgNGP0LzRg9GOLiIg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICBDLlN3aXRjaCB7IHRleHQ6ICJXYXlkcm9pZCDQsiDQvtCx0YXQvtC0IFZQTiI7'
    'IGNoZWNrZWQ6IHJvb3QucG9saWN5LndheWRyb2lkX2RpcmVjdCAhPT0gZmFsc2U7IGVuYWJsZWQ6ICFyb290LmJ1c3k7IG9u'
    'VG9nZ2xlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogIndheWRyb2lkIiwgZW5hYmxlZDogY2hlY2tlZH0pIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNv'
    'bG9yOiByb290LnRleHRNdXRlZDsgdGV4dDogcm9vdC5wb2xpY3kud2F5ZHJvaWRfZGlyZWN0ICE9PSBmYWxzZSA/ICLQn9GA'
    '0Y/QvNC+0LUg0L/QvtC00LrQu9GO0YfQtdC90LjQtTogV2F5ZHJvaWQg0LjRgdC/0L7Qu9GM0LfRg9C10YIg0LDQtNGA0LXR'
    'gSDQstCw0YjQtdCz0L4g0L/RgNC+0LLQsNC50LTQtdGA0LAuINCe0LHRidC40LUg0LjRgdC60LvRjtGH0LXQvdC40Y8g0L3Q'
    'tSDQvtCz0YDQsNC90LjRh9C40LLQsNGO0YIg0Y3RgtC+0YIg0YDQtdC20LjQvC4iIDogIldheWRyb2lkINC40YHQv9C+0LvR'
    'jNC30YPQtdGCIFZQTi4g0J/RgNC4INC+0LHRgNGL0LLQtSDRgtGD0L3QvdC10LvRjyDQtdCz0L4g0LLQvdC10YjQvdC40LUg'
    '0L/QvtC00LrQu9GO0YfQtdC90LjRjyDQsdC70L7QutC40YDRg9GO0YLRgdGPLiIgfQogICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KfQo='
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
    'c3NsCmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCB0aW1lCmltcG9ydCBzeXMKClJPT1QgPSBQYXRoKCcvZXRjL3Zwbi1tYW5h'
    'Z2VyL3N0YXJmaXZlLXR1bm5lbCcpClJVTlRJTUUgPSBQYXRoKCcvcnVuL2V2Z2VuaXVtLXN0YXJmaXZlLXR1bm5lbCcpClNU'
    'QVRFID0gUGF0aCgnL3Zhci9saWIvdnBuLW1hbmFnZXIvc3RhcmZpdmUtdHVubmVsLmpzb24nKQpVTklUID0gJ2V2Z2VuaXVt'
    'LXN0YXJmaXZlLXR1bm5lbC5zZXJ2aWNlJwpOUyA9ICdldm4tc3RhcmZpdmUnCkhPU1QgPSAnZXZuLXNmLWhvc3QnClBFRVIg'
    'PSAnZXZuLXNmLXBlZXInCk5FVFdPUksgPSAnMTcyLjI5LjI0Ni4wLzMwJwpDTElFTlQgPSAnMTcyLjI5LjI0Ni4yJwpHQVRF'
    'V0FZID0gJzE3Mi4yOS4yNDYuMScKVEFCTEUgPSA1MTgyNApQUklPUklUWSA9IDc1Ck5GVCA9ICdldmdlbml1bV9zdGFyZml2'
    'ZV9sYWJfaG9zdCcKU0VSVkVSID0gJzE5NS4yMDkuMjExLjE2MycKSUtFX1BPUlQgPSAyNDU1MApFTkRQT0lOVFMgPSAoU0VS'
    'VkVSLCAnMzguMTgwLjE2NC42NycpCkNBTkRJREFURVMgPSAoCiB7J2lkJzoncnUtdWRwJywnYWRkcmVzcyc6U0VSVkVSLCdp'
    'ZGVudGl0eSc6U0VSVkVSLCdwb3J0JzoyNDU1MCwndGxzJzpGYWxzZSwnbGFiZWwnOidIU1ZEUyDihpIg0K3RgdGC0L7QvdC4'
    '0Y8nfSwKIHsnaWQnOidlZS11ZHAnLCdhZGRyZXNzJzonMzguMTgwLjE2NC42NycsJ2lkZW50aXR5JzonMzguMTgwLjE2NC42'
    'NycsJ3BvcnQnOjQ0MywndGxzJzpGYWxzZSwnbGFiZWwnOifQrdGB0YLQvtC90LjRjyDQvdCw0L/RgNGP0LzRg9GOJ30sCiB7'
    'J2lkJzonZWUtdGxzJywnYWRkcmVzcyc6JzM4LjE4MC4xNjQuNjcnLCdpZGVudGl0eSc6JzM4LjE4MC4xNjQuNjcnLCdwb3J0'
    'Jzo0NDMsJ3Rscyc6VHJ1ZSwnbGFiZWwnOifQrdGB0YLQvtC90LjRjyDRh9C10YDQtdC3IFRMUyd9LAopCkFDVElWRSA9IENB'
    'TkRJREFURVNbMF0KcmFua19hcGkgPSBOb25lCnN1cHBvcnRfYXBpID0gTm9uZQp0bHNfYXBpID0gTm9uZQpUTFNfUFJPQ0VT'
    'UyA9IE5vbmUKIyBLZXB0IG9ubHkgZm9yIHJlbW92aW5nIHJvdXRlcyBpbnN0YWxsZWQgYnkgcHJlLW1pZ3JhdGlvbiB2ZXJz'
    'aW9ucy4KTEVHQUNZX0VORFBPSU5UUyA9ICgnMTA5LjE5NC42Ny4xNTknLCAnMTkyLjE2OC4wLjE2MycpCkhFQUxUSCA9ICcx'
    'MC43Ny4wLjEnClJFUUlEID0gMTc3ClRPS0VOX1BBVFRFUk4gPSByJ0VWTjEtW0EtWmEtejAtOV8tXXs0M30nClNUT1AgPSBG'
    'YWxzZQpETlNfUFJPQ0VTUyA9IE5vbmUKcG9saWN5ID0gTm9uZQpQSU5ORURfQ0EgPSAnLS0tLS1CRUdJTiBDRVJUSUZJQ0FU'
    'RS0tLS0tXG5NSUlFT0RDQ0FxQ2dBd0lCQWdJVWJrSis4U2FxQWd3WTFSREFqWlJUamNxUTllTXdEUVlKS29aSWh2Y05BUUVM'
    'XG5CUUF3SWpFZ01CNEdBMVVFQXd3WFJYWm5aVzVwZFcwZ2NISnBkbUYwWlNCV1VFNGdRMEV3SGhjTk1qWXhNREEzXG5NVGt4'
    'TXpReFdoY05Nell4TURBME1Ua3hNelF4V2pBaU1TQXdIZ1lEVlFRRERCZEZkbWRsYm1sMWJTQndjbWwyXG5ZWFJsSUZaUVRp'
    'QkRRVENDQWFJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFPWitudmlFXG4yT3JGN1BkdGtrL1hJYUZW'
    'SXZKbHZDMTFWWmY5cmxqQ0JJdkJ5a2JzckFyR3J5UUhHbnV1WExOYWFTOE50THhZXG5OZVNCREs2TWRnWUpBZWpzUDR3SVR1'
    'YjNuTWpTRzJ1bUlJVlU2bUUrR0RvekdQbE5NTkorYmhrS2FWaGFQakZFXG55WUxZcmRQZTVWQTR3KzVwME5aT0Q2Q0JIRDN0'
    'RVhXQk5SSWVWU1didE1JVHNPRVMxUGUvYUFMN3Yzb05JVmtWXG44bkR3OWo3K3dHMnk1ZGhicDdLVUpIYnJEQjAyNHI3Y1ly'
    'UTNheFlGNmd5a2ptenRwS1hzYmt4UXYyN0J2aFNCXG5lMEVrdEovakNTNlI5SUltWWdJUXJDcmFXWm1WU2NuR0YvQXE0VE53'
    'MUg0T3pGQ2tSKzdKVWxZblNZVXZNUmkxXG5Mektla1VDKzIvMFdGbWhuQ29EdGRqY29ZYnhwTHBLRGVsR2lTM1JzTkN2eG5z'
    'bE1hUHo1aENjRjY0WTdSaWpYXG5qNkR1Q1lwRllXbHIxM0IyMHFBblJvVWFzK0FqWDdQWENrUjR4T2hIK2tXOC9IbUZIaUhr'
    'b2hXRTB3bGxJU0JYXG5WQm83S0JPWmQ4U1Zld3liZDJyQjRzb1hvdVR0alhzL2pUZ2UrSFd4UURHUFAxdW1mejhjRkxSL3VR'
    'SURBUUFCXG5vMll3WkRBZEJnTlZIUTRFRmdRVW9RZlRpZjc3eFd0MDZoYVhoM2hhODkwcWtUOHdId1lEVlIwakJCZ3dGb0FV'
    'XG5vUWZUaWY3N3hXdDA2aGFYaDNoYTg5MHFrVDh3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBT0JnTlZIUThCXG5BZjhF'
    'QkFNQ0FRWXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnR0JBSTdHS25tZkpqdUwxUXZ5UnRsdytIcjZBWS9aXG5PeGREdkVDZWZv'
    'Rkw3UTQxVlphK0w3REk4N2tNTFlIeWdSSHVzaDY2b1V2ODc4VFdNdGFzbmJ0Lzh3WWc2anJ3XG5BeWdwZy9GM1ZEMjR5VHJu'
    'SjdPQ2R5R2liNkxHdXVzdVRQNHJVR3NjY1djem5RWFlGa3pSVnoxVmVZTVpVTitQXG50QVZpTmw0RVJTMWZoK2NHelQ0T3FY'
    'UWtKRGtSZXFIL0hDVEU4a1VRVVVnWGFTWHBoS2pHYThwUjJIVmVGdWtYXG4rMHBwMWlSKzZkaTRhQ0thcGthVGlWUjNyNjJ0'
    'UkJVd2J4b0ZZUnl4Tlh5blRLOUVobk0yNVdFcG4vcXUwbHNEXG5vWHJGVm1qMEFRZkFVSFJOLzJyUEwvL3c2UlBFcEhnVWNy'
    'dDd6dVNnb1hKWmgwRFQzMFZFSUs5Tk5idUtTRmQ5XG5JaVd2cnhiVlFTNm1RZ3RFWk40TGMySG0xcHZZK1dySStIMDN1ODA0'
    'MitjcExJc0NueFBtOVd2aTdkTVh4cW9iXG5vMi9hTDJ4REc1Ry84V1ZSL1c1RUFmdktkeGRyazNINjAyb2Njb3Y3K0pnMXZv'
    'eGkwMEliZE1FeG9NeGQ1YWVoXG5mWFJpSmhURUZvdUlwbUVTQ0Y0dlZNbFdGcjNtcWxRM0dLU1BWQT09XG4tLS0tLUVORCBD'
    'RVJUSUZJQ0FURS0tLS0tXG4nCgoKRlVMTF9IT1NUID0gJ2V2bi1mdWxsLWhvc3QnCkZVTExfUEVFUiA9ICdldm4tZnVsbC1w'
    'ZWVyJwpGVUxMX05FVCA9ICcxNzIuMjkuMjQ3LjAvMzAnCkZVTExfVEFCTEUgPSAnNTE4MjgnCkFETUlOX1RBQkxFID0gJzUx'
    'ODI5JwpGVUxMX0dVQVJEID0gJ2V2bl9zdGFyZml2ZV9mdWxsJwpkZWYgZnVsbF9zdGF0ZSgpOgogICAgcmV0dXJuIFJPT1Qv'
    'J2Z1bGwtbmV0d29yay5qc29uJwoKCmRlZiBjaGFyb25fYmluYXJ5KCk6CiAgICBjYW5kaWRhdGVzID0gKCcvdXNyL3NiaW4v'
    'Y2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9iaW4vY2hhcm9uLXN5c3RlbWQnLAogICAgICAgICAgICAgICAgICAnL3Vzci9saWIv'
    'aXBzZWMvY2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9saWJleGVjL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywKICAgICAgICAgICAg'
    'ICAgICAgJy91c3IvbGliL3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9saWJleGVjL3N0cm9uZ3N3YW4vY2hh'
    'cm9uLXN5c3RlbWQnKQogICAgcmV0dXJuIG5leHQoKHAgZm9yIHAgaW4gY2FuZGlkYXRlcyBpZiBQYXRoKHApLmlzX2ZpbGUo'
    'KSksIE5vbmUpCgoKZGVmIGVuc3VyZV9kZXBlbmRlbmNpZXMoKToKICAgIGlmIGNoYXJvbl9iaW5hcnkoKSBhbmQgYWxsKHNo'
    'dXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwnLCdpcCcsJ25mdCcsJ2N1cmwnLCdvcGVuc3NsJywnY29ubnRyYWNr'
    'JykpOgogICAgICAgIHJldHVybgogICAgc3RhZ2UoJ2RlcGVuZGVuY2llcycsICfQo9GB0YLQsNC90LDQstC70LjQstCw0Y4g'
    '0L3QtdC+0LHRhdC+0LTQuNC80YvQtSDRgdC40YHRgtC10LzQvdGL0LUg0LrQvtC80L/QvtC90LXQvdGC0YsgVlBOLicsIDMs'
    'IGFjdGl2ZT1GYWxzZSkKICAgIGlmIHNodXRpbC53aGljaCgncGFjbWFuJyk6CiAgICAgICAgYXJncyA9IFsncGFjbWFuJywn'
    'LVMnLCctLW5lZWRlZCcsJy0tbm9jb25maXJtJywnc3Ryb25nc3dhbicsJ2lwcm91dGUyJywnbmZ0YWJsZXMnLCdjdXJsJywn'
    'b3BlbnNzbCcsJ2NhLWNlcnRpZmljYXRlcycsJ2Nvbm50cmFjay10b29scyddCiAgICBlbGlmIHNodXRpbC53aGljaCgnZG5m'
    'Jyk6CiAgICAgICAgYXJncyA9IFsnZG5mJywnaW5zdGFsbCcsJy15JywnLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFs'
    'c2UnLCdzdHJvbmdzd2FuJywnaXByb3V0ZScsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMn'
    'LCdjb25udHJhY2stdG9vbHMnXQogICAgZWxzZToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9CQ0LLRgtC+0LzQsNGC'
    '0LjRh9C10YHQutCw0Y8g0YPRgdGC0LDQvdC+0LLQutCwINC60LvQuNC10L3RgtCwINC/0L7QtNC00LXRgNC20LjQstCw0LXR'
    'giBBcmNoINC4IEZlZG9yYS4nKQogICAgY29tbWFuZChhcmdzLCB0aW1lb3V0PTMwMCkKICAgIGlmIG5vdCBjaGFyb25fYmlu'
    'YXJ5KCkgb3Igbm90IGFsbChzaHV0aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2FuY3RsJywnY29ubnRyYWNrJykpOgogICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0J/QsNC60LXRgiBzdHJvbmdTd2FuINC90LUg0L/RgNC10LTQvtGB0YLQsNCy0LjQ'
    'uyDQvdC10L7QsdGF0L7QtNC40LzRi9C1INC/0YDQvtCz0YDQsNC80LzRiy4nKQoKCmRlZiBjbGVhcl9kbnNfbWFwcGluZ3Mo'
    'cHJldmlvdXNfdnBuPUZhbHNlKToKICAgICIiIkZvcmdldCBvbmx5IHRoaXMgbWFuYWdlcidzIG9ic29sZXRlIEROUyBOQVQs'
    'IG5ldmVyIGZsdXNoIGFsbCBjb25uZWN0aW9ucy4KCiAgICBSZW1vdmluZyBhbiBuZnQgTkFUIGNoYWluIGRvZXMgbm90IHJl'
    'bW92ZSBleGlzdGluZyBjb25udHJhY2sgdHJhbnNsYXRpb25zLgogICAgQSBydW5uaW5nIHJlc29sdmVyIGNhbiByZXVzZSBp'
    'dHMgVURQIHNvY2tldCBpbmRlZmluaXRlbHkgYWZ0ZXIgYSBWUE4gc3dpdGNoLgogICAgIiIiCiAgICBmaWx0ZXJzID0gKFsn'
    'LS1yZXBseS1wb3J0LXNyYycsJzE4NTUzJ10gaWYgcHJldmlvdXNfdnBuIGVsc2UKICAgICAgICAgICAgICAgWyctLXJlcGx5'
    'LXBvcnQtc3JjJywnNTMnLCctLWRzdC1uYXQnLCcxLjEuMS4xJ10pCiAgICBmb3IgcHJvdG9jb2wgaW4gKCd1ZHAnLCd0Y3An'
    'KToKICAgICAgICByZXN1bHQgPSBjb21tYW5kKFsnY29ubnRyYWNrJywnLUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG9jb2ws'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgJy0tZHBvcnQnLCc1MycsKmZpbHRlcnNdLCBjaGVjaz1GYWxzZSwKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGVudj17Kipvcy5lbnZpcm9uLCdMQ19BTEwnOidDJ30pCiAgICAgICAgZW1wdHkgPSByZXN1'
    'bHQucmV0dXJuY29kZSA9PSAxIGFuZCAnMCBmbG93IGVudHJpZXMgaGF2ZSBiZWVuIGRlbGV0ZWQnIGluIHJlc3VsdC5zdGRl'
    'cnIKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSAhPSAwIGFuZCBub3QgZW1wdHk6CiAgICAgICAgICAgIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcignZG5zX3RyYW5zaXRpb25fY2xlYW51cF9mYWlsZWQnKQoKCmRlZiBmdWxsX2d1YXJkX2FjdGl2ZSgpOgog'
    'ICAgcmV0dXJuIGNvbW1hbmQoWyduZnQnLCdsaXN0JywndGFibGUnLCdpbmV0JyxGVUxMX0dVQVJEXSxjaGVjaz1GYWxzZSku'
    'cmV0dXJuY29kZSA9PSAwCgoKZGVmIGZ1bGxfZmlyZXdhbGwoKToKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZToKICAgICAg'
    'ICBzZXR0aW5ncz1wb2xpY3kuYXBpLmxvYWRfc2V0dGluZ3MoKQogICAgICAgIHJldHVybiBwb2xpY3kuZmlyZXdhbGwocG9s'
    'aWN5LmxvYWQoKSxwb2xpY3kubG9jYWxfbmV0d29ya3MocGh5c2ljYWxfcm91dGUoKSksaW50KHNldHRpbmdzWyJ4cmF5X3Vp'
    'ZCJdKSkKICAgICMgTWluaW1hbCBndWFyZCB1c2VkIGJ5IGlzb2xhdGVkIHByb3RvY29sIHRlc3RzLgogICAgIyBLZWVwIGxv'
    'Y2FsIHN0dWIgRE5TIG9uIGxvb3BiYWNrLiBETkFUIG9mIDEyNy84IG9udG8gYSB2ZXRoIGZhaWxzIExpbnV4J3MKICAgICMg'
    'bG9vcGJhY2sgcm91dGUgY2hlY2tzOyB1cHN0cmVhbSByZXNvbHZlciB0cmFmZmljIHN0aWxsIG9iZXlzIHRoZSBmdWxsIGd1'
    'YXJkLgogICAgcmV0dXJuIGYnJyd0YWJsZSBpbmV0IHtGVUxMX0dVQVJEfSB7ewogY2hhaW4gZG5zIHt7IHR5cGUgbmF0IGhv'
    'b2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAgaXAgZGFkZHIgMTI3LjAuMC4wLzggcmV0dXJuCiAg'
    'aXAgZGFkZHIge3sgMS4xLjEuMSwgOS45LjkuOSB9fSByZXR1cm4KICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8g'
    'e3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgZG5hdCBpcCB0byAxLjEuMS4xCiB9fQogY2hhaW4gc291cmNlIHt7IHR5cGUg'
    'bmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgbmZwcm90byBpcHY0'
    'IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBzbmF0IGlwIHRvIDE3Mi4yOS4yNDcuMQogfX0KIGNoYWluIG91dHB1dCB7eyB0eXBl'
    'IGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBt'
    'ZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgaXAgZGFkZHIgMjU1LjI1NS4yNTUuMjU1'
    'IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29r'
    'IGZvcndhcmQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9'
    'IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIg'
    'aXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIGFjY2VwdAogIGlpZm5hbWUg'
    'IntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3AgZHBvcnQgMjQ1NzEgYWNjZXB0'
    'CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQg'
    'ODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHtDTElFTlR9IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJl'
    'bGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIG1ldGEgbmZw'
    'cm90byBpcHY0IGlpZm5hbWUgIntGVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0K'
    'fX0nJycKCgoKZGVmIHJlZnJlc2hfcmV0YWluZWRfZ3VhcmQoKToKICAgICIiIk1vdmUgb25seSB0aGUgVlBOIHRyYW5zcG9y'
    'dCBleGNlcHRpb24gd2hlbiBhbiBpbmdyZXNzIGVuZHBvaW50IGNoYW5nZXMuIiIiCiAgICBpZiBub3QgZnVsbF9ndWFyZF9h'
    'Y3RpdmUoKToKICAgICAgICByZXR1cm4KICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICByZXBsYWNlbWVudCA9ICdk'
    'ZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJytydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCct'
    'J10sZGF0YT1yZXBsYWNlbWVudCkKICAgICMgUGVyc2lzdCB0aGUgY2xvc2VkIGd1YXJkIGJlZm9yZSBjaGFuZ2luZyB0aGUg'
    'YWN0aXZlIGV4Y2VwdGlvbjsgYSBjcmFzaCBzdGF5cyBjbG9zZWQuCiAgICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5mdCcs'
    'cnVsZXMpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKCgpkZWYgdmlydHVhbF9pcCgp'
    'OgogICAgZGF0YSA9IGpzb24ubG9hZHMoaW5zaWRlKFsnaXAnLCctaicsJy00JywnYWRkciddKS5zdGRvdXQpCiAgICBpcHMg'
    'PSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBkYXRhIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRyX2luZm8nLCBbXSkKICAgICAg'
    'ICAgICBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhWydsb2NhbCddKSBpbiBpcGFkZHJlc3MuaXBfbmV0d29yaygnMTAuNzcu'
    'MC4wLzI0JyldCiAgICBpZiBsZW4oaXBzKSAhPSAxOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndmlydHVhbF9pcF9t'
    'aXNzaW5nJykKICAgIHJldHVybiBpcHNbMF0KCgpkZWYgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcyk6CiAgICB2aXAgPSB2aXJ0'
    'dWFsX2lwKCkKICAgIGlmIG5vdCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAg'
    'Y29tbWFuZChbJ2lwJywnbGluaycsJ2FkZCcsRlVMTF9IT1NULCd0eXBlJywndmV0aCcsJ3BlZXInLCduYW1lJyxGVUxMX1BF'
    'RVJdKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfUEVFUiwnbmV0bnMnLE5TXSkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4xLzMwJywnZGV2JyxGVUxMX0hPU1RdKQogICAgY29tbWFu'
    'ZChbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9IT1NULCdtdHUnLCcxMjgwJywndXAnXSkKICAgIGluc2lkZShbJ2lwJywnYWRk'
    'cicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjIvMzAnLCdkZXYnLEZVTExfUEVFUl0pCiAgICBpbnNpZGUoWydpcCcsJ2xpbmsn'
    'LCdzZXQnLEZVTExfUEVFUiwnbXR1JywnMTI4MCcsJ3VwJ10pCiAgICBpbnNpZGUoWydzeXNjdGwnLCctcXcnLCduZXQuaXB2'
    'NC5jb25mLmFsbC5mb3J3YXJkaW5nPTEnLCduZXQuaXB2NC5jb25mLmFsbC5ycF9maWx0ZXI9MCddKQogICAgIyBTdHJvbmdT'
    'd2FuJ3MgY2F0Y2gtYWxsIHJvdXRlIG11c3Qgbm90IGNhcHR1cmUgcmVwbGllcyB0byB0aGUgaG9zdC1mYWNpbmcgaW50ZXJm'
    'YWNlLgogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc5MCcsJ3RvJyxGVUxMX05FVCwnbG9va3Vw'
    'JywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc5MCcsJ3Rv'
    'JyxGVUxMX05FVCwnbG9va3VwJywnbWFpbiddKQogICAgZGVsZXRpb25zID0gJycKICAgIGZvciBmYW1pbHksdGFibGUgaW4g'
    'WygnaW5ldCcsJ2V2bl9mdWxsX2ZvcndhcmQnKSwoJ25ldGRldicsJ2V2bl9mdWxsX3dpcmUnKV06CiAgICAgICAgaWYgaW5z'
    'aWRlKFsnbmZ0JywnbGlzdCcsJ3RhYmxlJyxmYW1pbHksdGFibGVdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAg'
    'ICAgICAgICAgIGRlbGV0aW9ucyArPSBmJ2RlbGV0ZSB0YWJsZSB7ZmFtaWx5fSB7dGFibGV9XG4nCiAgICBydWxlcyA9IGRl'
    'bGV0aW9ucyArIGYnJyd0YWJsZSBpbmV0IGV2bl9mdWxsX2ZvcndhcmQge3sKIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0'
    'ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC01OyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7RlVMTF9QRUVSfSIgb2lmbmFt'
    'ZSAie1BFRVJ9IiBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgYWNjZXB0CiAgaWlmbmFtZSB7eyAie1BFRVJ9IiwgImxvIiB9fSBv'
    'aWZuYW1lICJ7RlVMTF9QRUVSfSIgaXAgZGFkZHIgMTcyLjI5LjI0Ny4xIGlwc2VjIGluIHJlcWlkIHtSRVFJRH0gY3Qgc3Rh'
    'dGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKIH19CiBjaGFpbiBuYXQge3sgdHlwZSBuYXQgaG9vayBwb3N0cm91dGlu'
    'ZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2FkZHIgMTcyLjI5LjI0Ny4xIG9pZm5hbWUgIntQRUVS'
    'fSIgc25hdCBpcCB0byB7dmlwfQogfX0KfX0KdGFibGUgbmV0ZGV2IGV2bl9mdWxsX3dpcmUge3sKIGNoYWluIGVncmVzcyB7'
    'eyB0eXBlIGZpbHRlciBob29rIGVncmVzcyBkZXZpY2UgIntQRUVSfSIgcHJpb3JpdHkgMDsgcG9saWN5IGRyb3A7CiAgZXRo'
    'ZXIgdHlwZSBhcnAgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFjY2Vw'
    'dAogIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IDI0NTcxIGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB0'
    'Y3AgZHBvcnQgODQ0MyBhY2NlcHQKIH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cnVs'
    'ZXMpCiAgICBpbnNpZGUoWyduZnQnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgIyBSZXBsYWNlIHRoZSBvcmlnaW5hbCBs'
    'YWIgZm9yd2FyZCBkcm9wOyBob3N0IGluZ3Jlc3MgcmVtYWlucyBjb25zdHJhaW5lZCBieSBmdWxsX2ZvcndhcmQuCiAgICBp'
    'bnNpZGUoWyduZnQnLCdmbHVzaCcsJ2NoYWluJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnXSkKICAg'
    'IGluc2lkZShbJ25mdCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JywnZXZuX3N0YXJmaXZlX2d1YXJkJywnZm9yd2FyZCcsJ2lpZm5h'
    'bWUnLEZVTExfUEVFUiwnbWV0YScsJ25mcHJvdG8nLCdpcHY0JywnYWNjZXB0J10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQn'
    'LCdydWxlJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnLCdvaWZuYW1lJyxGVUxMX1BFRVIsJ2lwc2Vj'
    'JywnaW4nLCdyZXFpZCcsc3RyKFJFUUlEKSwnY3QnLCdzdGF0ZScsJ2VzdGFibGlzaGVkLHJlbGF0ZWQnLCdhY2NlcHQnXSkK'
    'CgpkZWYgZWdyZXNzX2hlYWx0aCgpOgogICAgZm9yIHVybCxleHBlY3RlZCBpbiBbKCdodHRwczovLzEuMS4xLjEvY2RuLWNn'
    'aS90cmFjZScsJ2lwPTM4LjE4MC4xNjQuNjcnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICgnaHR0cHM6Ly9hcGkuaXBp'
    'Znkub3JnJywnMzguMTgwLjE2NC42NycpXToKICAgICAgICByZXN1bHQgPSBpbnNpZGUoWydjdXJsJywnLTQnLCctLW5vcHJv'
    'eHknLCcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLXNob3ctZXJyb3InLAogICAgICAgICAgICAgICAgICAgICAgICAgJy0t'
    'Y29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCc1Jyx1cmxdLHRpbWVvdXQ9NyxjaGVjaz1GYWxzZSkKICAgICAg'
    'ICBpZiByZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCBleHBlY3RlZCBpbiByZXN1bHQuc3Rkb3V0LnNwbGl0bGluZXMoKToK'
    'ICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiByZXRpcmVfcHJldmlvdXNfY29ubmVjdGlv'
    'bnMoYWRkcmVzc2VzKToKICAgICMgVGhlIGZpcmV3YWxsIGFscmVhZHkgYmxvY2tzIG9sZCBub24tZXhlbXB0IGZsb3dzLiBE'
    'byBub3Qga2lsbCBhbGwgc29ja2V0cwogICAgIyBzaGFyaW5nIGEgcGh5c2ljYWwgc291cmNlIGFkZHJlc3M6IHRoYXQgZGVz'
    'dHJveXMgU1NILCBMQU4gYW5kIGFwcCBleGNsdXNpb25zLgogICAgIyBPbmx5IHRoaXMgbWFuYWdlcidzIEROUyB0cmFuc2xh'
    'dGlvbnMgbmVlZCBleHBsaWNpdCByZXRpcmVtZW50IChoYW5kbGVkIGFib3ZlKS4KICAgIHJldHVybgoKCmRlZiBzeXN0ZW1f'
    'ZG5zX2hlYWx0aChyZXNvbHZfY29uZj1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgIyBnZXRhZGRyaW5mby9jdXJs'
    'IG1heSB1c2UgbnNzLXJlc29sdmUgb3ZlciBhIFVuaXggc29ja2V0IGFuZCBtaXNzIGEgYnJva2VuCiAgICAjIFVEUCBzdHVi'
    'IHVzZWQgYnkgb3RoZXIgYXBwbGljYXRpb25zLiBFeGVyY2lzZSByZXNvbHYuY29uZiBpbmRlcGVuZGVudGx5LgogICAgc2Vy'
    'dmVycyA9IFtsaW5lLnNwbGl0KClbMV0gZm9yIGxpbmUgaW4gcmVzb2x2X2NvbmYucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygp'
    'CiAgICAgICAgICAgICAgIGlmIGxpbmUuc3BsaXQoKVs6MV0gPT0gWyduYW1lc2VydmVyJ10gYW5kIGxlbihsaW5lLnNwbGl0'
    'KCkpID49IDJdWzozXQogICAgZm9yIHNlcnZlciBpbiBzZXJ2ZXJzOgogICAgICAgIHRyeToKICAgICAgICAgICAgZmFtaWx5'
    'ID0gc29ja2V0LkFGX0lORVQ2IGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHNlcnZlcikudmVyc2lvbiA9PSA2IGVsc2Ugc29j'
    'a2V0LkFGX0lORVQKICAgICAgICAgICAgdHJhbnNhY3Rpb24gPSBzZWNyZXRzLnRva2VuX2J5dGVzKDIpCiAgICAgICAgICAg'
    'IHF1ZXJ5ID0gdHJhbnNhY3Rpb24rYidceDAxXHgwMFx4MDBceDAxXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwJwogICAgICAg'
    'ICAgICBxdWVyeSArPSBiJ1x4MDNhcGlceDA1aXBpZnlceDAzb3JnXHgwMFx4MDBceDAxXHgwMFx4MDEnCiAgICAgICAgICAg'
    'IHdpdGggc29ja2V0LnNvY2tldChmYW1pbHksIHNvY2tldC5TT0NLX0RHUkFNKSBhcyByZXNvbHZlcjoKICAgICAgICAgICAg'
    'ICAgIHJlc29sdmVyLnNldHRpbWVvdXQoMikKICAgICAgICAgICAgICAgIHJlc29sdmVyLmNvbm5lY3QoKHNlcnZlciwgNTMp'
    'KQogICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2VuZChxdWVyeSkKICAgICAgICAgICAgICAgIGFuc3dlciA9IHJlc29sdmVy'
    'LnJlY3YoNDA5NikKICAgICAgICAgICAgaWYgKGxlbihhbnN3ZXIpID49IDEyIGFuZCBhbnN3ZXJbOjJdID09IHRyYW5zYWN0'
    'aW9uIGFuZAogICAgICAgICAgICAgICAgICAgIGFuc3dlclsyXSAmIDB4ODAgYW5kIGFuc3dlclszXSAmIDE1ID09IDAgYW5k'
    'CiAgICAgICAgICAgICAgICAgICAgaW50LmZyb21fYnl0ZXMoYW5zd2VyWzY6OF0sICdiaWcnKSA+IDApOgogICAgICAgICAg'
    'ICAgICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgICAgICBjb250'
    'aW51ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIHN0YXJ0X25hbWVzcGFjZV9kbnMoKToKICAgICIiIkEgcHJpdmF0ZSBETlMg'
    'ZW5kcG9pbnQgcmVhY2hhYmxlIG9ubHkgb3ZlciB0aGUgaG9zdC9uYW1lc3BhY2UgdmV0aC4iIiIKICAgIGdsb2JhbCBETlNf'
    'UFJPQ0VTUwogICAgaWYgRE5TX1BST0NFU1MgaXMgbm90IE5vbmUgYW5kIEROU19QUk9DRVNTLnBvbGwoKSBpcyBOb25lOnJl'
    'dHVybgogICAgY2ZnID0geydsb2cnOnsnbG9nbGV2ZWwnOid3YXJuaW5nJywnYWNjZXNzJzonbm9uZSd9LAogICAgICAnaW5i'
    'b3VuZHMnOlt7J3RhZyc6J2Rucy1pbicsJ2xpc3Rlbic6JzE3Mi4yOS4yNDcuMicsJ3BvcnQnOjUzLCdwcm90b2NvbCc6J2Rv'
    'a29kZW1vLWRvb3InLAogICAgICAgICAgICAgICAgICAgJ3NldHRpbmdzJzp7J2FkZHJlc3MnOicxLjEuMS4xJywncG9ydCc6'
    'NTMsJ25ldHdvcmsnOid0Y3AsdWRwJ319XSwKICAgICAgJ2Rucyc6eydzZXJ2ZXJzJzpbJzEuMS4xLjEnLCd0Y3A6Ly85Ljku'
    'OS45JywnaHR0cHM6Ly8xLjAuMC4xL2Rucy1xdWVyeSddLAogICAgICAgICAgICAgJ3F1ZXJ5U3RyYXRlZ3knOidVc2VJUHY0'
    'JywndGFnJzonZG5zLWVuZ2luZScsJ2VuYWJsZVBhcmFsbGVsUXVlcnknOlRydWV9LAogICAgICAnb3V0Ym91bmRzJzpbeyd0'
    'YWcnOid3aXJlJywncHJvdG9jb2wnOidmcmVlZG9tJ30sCiAgICAgICAgICAgICAgICAgICB7J3RhZyc6J2RucycsJ3Byb3Rv'
    'Y29sJzonZG5zJywnc2V0dGluZ3MnOnsncnVsZXMnOlt7J3FUeXBlJzonMSwyOCcsJ2FjdGlvbic6J2hpamFjayd9LHsnYWN0'
    'aW9uJzonZGlyZWN0J31dfX1dLAogICAgICAncm91dGluZyc6eydydWxlcyc6W3sndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRh'
    'Zyc6WydkbnMtaW4nXSwnb3V0Ym91bmRUYWcnOidkbnMnfSwKICAgICAgICAgICAgICAgICAgICAgICAgICB7J3R5cGUnOidm'
    'aWVsZCcsJ2luYm91bmRUYWcnOlsnZG5zLWVuZ2luZSddLCdvdXRib3VuZFRhZyc6J3dpcmUnfV19fQogICAgcGF0aD1ST09U'
    'LyduYW1lc3BhY2UtZG5zLmpzb24nO3dyaXRlKHBhdGgsanNvbi5kdW1wcyhjZmcpKQogICAgYmluYXJ5PScvb3B0L3Zwbi1t'
    'YW5hZ2VyL2Jpbi94cmF5JwogICAgaW5zaWRlKFtiaW5hcnksJ3J1bicsJy10ZXN0JywnLWNvbmZpZycscGF0aF0pCiAgICBE'
    'TlNfUFJPQ0VTUz1zdWJwcm9jZXNzLlBvcGVuKFsnaXAnLCduZXRucycsJ2V4ZWMnLE5TLGJpbmFyeSwncnVuJywnLWNvbmZp'
    'Zycsc3RyKHBhdGgpXSwKICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsc3Rkb3V0PXN1YnByb2Nlc3MuREVWTlVM'
    'TCxzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgZm9yIF8gaW4gcmFuZ2UoMzApOgogICAgICAgIGlmIEROU19QUk9D'
    'RVNTLnBvbGwoKSBpcyBub3QgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3ByaXZhdGVfZG5zX3N0b3BwZWQnKQogICAgICAg'
    'IGlmICcxNzIuMjkuMjQ3LjI6NTMnIGluIGluc2lkZShbJ3NzJywnLWxudSddLGNoZWNrPUZhbHNlKS5zdGRvdXQ6CiAgICAg'
    'ICAgICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCduYW1lc2VydmVyIDE3Mi4yOS4yNDcu'
    'Mlxub3B0aW9ucyB0aW1lb3V0OjMgYXR0ZW1wdHM6MlxuJykKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgdGltZS5zbGVl'
    'cCguMSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncHJpdmF0ZV9kbnNfbm90X3JlYWR5JykKCgpkZWYgdXNlX3Jlc29sdmVy'
    'X2ZpbGUocGF0aD1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5y'
    'ZWFkX3RleHQoKSkKICAgIHRhcmdldD1ST09ULydyZXNvbHYtdnBuLmNvbmYnCiAgICBpZiAncmVzb2x2ZXJfb3JpZ2luYWwn'
    'IG5vdCBpbiBkYXRhOgogICAgICAgIGRhdGFbJ3Jlc29sdmVyX29yaWdpbmFsJ109eydsaW5rJzpvcy5yZWFkbGluayhwYXRo'
    'KSBpZiBwYXRoLmlzX3N5bWxpbmsoKSBlbHNlIE5vbmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3Rl'
    'eHQnOnBhdGgucmVhZF90ZXh0KCkgaWYgcGF0aC5leGlzdHMoKSBlbHNlICcnLAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICdleGlzdGVkJzpwYXRoLmV4aXN0cygpIG9yIHBhdGguaXNfc3ltbGluaygpfQogICAgZGF0YVsnZG5zX2Zh'
    'bGxiYWNrJ109VHJ1ZQogICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCiAgICB3cml0ZSh0YXJnZXQs'
    'J25hbWVzZXJ2ZXIgMTcyLjI5LjI0Ny4yXG5vcHRpb25zIHRpbWVvdXQ6MyBhdHRlbXB0czoyXG4nKQogICAgdGFyZ2V0LmNo'
    'bW9kKDBvNjQ0KQogICAgIyBUaGUgcGFyZW50IG11c3QgYmUgdHJhdmVyc2FibGUgYnkgYXBwbGljYXRpb25zLiBTZWNyZXRz'
    'IHJlbWFpbiByb290LW9ubHkuCiAgICAjIFB1dCBvbmx5IHRoaXMgcHVibGljIHJlc29sdmVyIGZpbGUgb3V0c2lkZSB0aGUg'
    'Y3JlZGVudGlhbCBkaXJlY3RvcnkuCiAgICBwdWJsaWM9UGF0aCgnL3J1bi9ldmdlbml1bS1yZXNvbHYuY29uZicpCiAgICBw'
    'dWJsaWMucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd3JpdGUocHVibGljLHRhcmdldC5y'
    'ZWFkX3RleHQoKSk7cHVibGljLmNobW9kKDBvNjQ0KQogICAgdGVtcG9yYXJ5PXBhdGgud2l0aF9uYW1lKCcuZXZnZW5pdW0t'
    'cmVzb2x2Lm5ldycpCiAgICB0ZW1wb3JhcnkudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSk7dGVtcG9yYXJ5LnN5bWxpbmtfdG8o'
    'cHVibGljKQogICAgb3MucmVwbGFjZSh0ZW1wb3JhcnkscGF0aCkKCgpkZWYgcmVzdG9yZV9yZXNvbHZlcl9maWxlKGRhdGEs'
    'cGF0aD1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgc2F2ZWQ9ZGF0YS5nZXQoJ3Jlc29sdmVyX29yaWdpbmFsJykK'
    'ICAgIGlmIHNhdmVkIGFuZCBwYXRoLmlzX3N5bWxpbmsoKSBhbmQgb3MucmVhZGxpbmsocGF0aCk9PScvcnVuL2V2Z2VuaXVt'
    'LXJlc29sdi5jb25mJzoKICAgICAgICB0ZW1wb3Jhcnk9cGF0aC53aXRoX25hbWUoJy5ldmdlbml1bS1yZXNvbHYucmVzdG9y'
    'ZScpCiAgICAgICAgdGVtcG9yYXJ5LnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgaWYgc2F2ZWRbJ2xpbmsnXSBp'
    'cyBub3QgTm9uZTp0ZW1wb3Jhcnkuc3ltbGlua190byhzYXZlZFsnbGluayddKQogICAgICAgIGVsc2U6dGVtcG9yYXJ5Lndy'
    'aXRlX3RleHQoc2F2ZWRbJ3RleHQnXSk7dGVtcG9yYXJ5LmNobW9kKDBvNjQ0KQogICAgICAgIGlmIHNhdmVkLmdldCgnZXhp'
    'c3RlZCcsVHJ1ZSk6b3MucmVwbGFjZSh0ZW1wb3JhcnkscGF0aCkKICAgICAgICBlbHNlOnBhdGgudW5saW5rKCk7dGVtcG9y'
    'YXJ5LnVubGluaygpCiAgICBlbGlmIG5vdCBzYXZlZCBhbmQgJ2Ruc19iYWNrdXAnIGluIGRhdGE6CiAgICAgICAgcGF0aC53'
    'cml0ZV90ZXh0KGRhdGFbJ2Ruc19iYWNrdXAnXSkKCgpkZWYgcmVjb3Zlcl9zeXN0ZW1fZG5zKCk6CiAgICBmb3IgXyBpbiBy'
    'YW5nZSgyKToKICAgICAgICBpZiBzeXN0ZW1fZG5zX2hlYWx0aCgpOnJldHVybiBUcnVlCiAgICAgICAgaWYgU1RPUDpyZXR1'
    'cm4gRmFsc2UKICAgICAgICB0aW1lLnNsZWVwKC4zKQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKTpyZXR1cm4g'
    'RmFsc2UKICAgICMgU3dpdGNoIG9ubHkgdGhlIHJlc29sdmVyIGZpbGUgd2Ugb3duOyBuZXZlciBzdG9wIGFub3RoZXIgVlBO'
    'IG9yIHJlc29sdmVyLgogICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Cf0LXRgNC10LrQu9GO0YfQsNGOINC90LXQuNGB0L/RgNCw'
    '0LLQvdGL0Lkg0YHQuNGB0YLQtdC80L3Ri9C5IEROUyDQvdCwINC30LDRidC40YnRkdC90L3Ri9C5INGA0LXQt9C10YDQsi4n'
    'LDkwLGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPSdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICB1c2VfcmVzb2x2ZXJfZmlsZSgp'
    'CiAgICByZXR1cm4gc3lzdGVtX2Ruc19oZWFsdGgoKQoKCmRlZiBwZXJzaXN0X2d1YXJkKHJ1bGVzKToKICAgICMgR3VhcmQg'
    'cGVyc2lzdGVuY2UgcHJlY2VkZXMgc3dpdGNoaW5nLiBDbGVhbnVwIGFmdGVyIGEgY3Jhc2ggbmV2ZXIgb3BlbnMgdGhlIElu'
    'dGVybmV0LgogICAgZ3VhcmRfdW5pdCA9ICcnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxsLWRldmljZSBraWxs'
    'IHN3aXRjaApEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUu'
    'dGFyZ2V0CltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVtYWluQWZ0ZXJFeGl0PXllcwpFeGVjU3RhcnQ9L3Vzci9zYmluL25m'
    'dCAtZiAvZXRjL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXR1bm5lbC9mdWxsLWd1YXJkLm5mdApbSW5zdGFsbF0KV2FudGVkQnk9'
    'bXVsdGktdXNlci50YXJnZXQKJycnLnJlcGxhY2UoJy91c3Ivc2Jpbi9uZnQnLCBzaHV0aWwud2hpY2goJ25mdCcpKQogICAg'
    'd3JpdGUoUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbS9l'
    'dmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnKSxndWFyZF91bml0KQogICAgY29tbWFuZChbJ3N5c3RlbWN0'
    'bCcsJ2RhZW1vbi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdlbmFibGUnLCdldmdlbml1bS1zdGFyZml2'
    'ZS1mdWxsLWd1YXJkLnNlcnZpY2UnXSkKCgpkZWYgYWN0aXZhdGVfZnVsbChhZGRyZXNzKToKICAgIG9sZF9hZGRyZXNzZXMg'
    'PSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hv'
    'dycsJ3Njb3BlJywnZ2xvYmFsJ10pLnN0ZG91dCkKICAgICAgICAgICAgICAgICAgICAgaWYgbGluay5nZXQoJ2lmbmFtZScp'
    'IG5vdCBpbiAoSE9TVCxGVUxMX0hPU1QpCiAgICAgICAgICAgICAgICAgICAgIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRyX2lu'
    'Zm8nLFtdKSBpZiBhLmdldCgnc2NvcGUnKSA9PSAnZ2xvYmFsJ10KICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6'
    'CiAgICAgICAgaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1QpLmV4aXN0cygpOgogICAgICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ2Z1bGxfaW50ZXJmYWNlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywncm91'
    'dGUnLCdzaG93JywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywncm91'
    'dGUnLCdzaG93JywndGFibGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcignYWRtaW5fdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBhbnkoci5nZXQoJ3ByaW9y'
    'aXR5JykgaW4gKDc5LDgwKSBmb3IgciBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdydWxlJ10pLnN0'
    'ZG91dCkpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfcnVsZV9jb2xsaXNpb24nKQogICAgICAgIHdy'
    'aXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKHsnYWN0aXZlJzpGYWxzZX0pKQogICAgZnVsbF9uYW1lc3BhY2UoYWRkcmVz'
    'cykKICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQogICAgIyBWYWxpZGF0ZSB0aGUgZWdyZXNzIGZpbHRlciBiZWZvcmUgaW50'
    'ZXJydXB0aW5nIHRoZSBwcmV2aW91cyBWUE4uCiAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcignZXN0b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICAjIFJl'
    'cGFpciBtYXkgaW5oZXJpdCBhIGd1YXJkIGZyb20gYW4gb2xkZXIgdmVyc2lvbi4gUmVwbGFjZSBvdXIgdGFibGUgaW4KICAg'
    'ICMgb25lIG5mdCB0cmFuc2FjdGlvbiwgc28gZml4ZXMgYXBwbHkgd2l0aG91dCBvcGVuaW5nIGFuIHVuZ3VhcmRlZCB3aW5k'
    'b3cuCiAgICByZXBsYWNlbWVudCA9ICgnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicgaWYgZnVsbF9ndWFy'
    'ZF9hY3RpdmUoKSBlbHNlICcnKStydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNl'
    'bWVudCkKICAgIGNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgcGVyc2lzdF9ndWFyZChy'
    'dWxlcykKICAgICMgVGhpcyBjb21tYW5kIHN0b3BzIG9ubHkgdGhpcyBtYW5hZ2VyJ3MgcHJldmlvdXMgWHJheSBtb2RlIGFu'
    'ZCByZW1vdmVzIGl0cyBndWFyZC4KICAgIGNvbW1hbmQoWycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwtc3Rh'
    'cmZpdmUtcGF1c2UtbWFpbiddLHRpbWVvdXQ9NDApCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCd1bnJl'
    'YWNoYWJsZScsJ2RlZmF1bHQnLCdtZXRyaWMnLCczMjc2MCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydp'
    'cCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLEZVTExfSE9TVCwnbWV0'
    'cmljJywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHkn'
    'LCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBmb3IgcnVsZSBpbiAoWydwcmlvcml0eScsJzc5'
    'JywndG8nLENMSUVOVCsnLzMyJywnbG9va3VwJywnbWFpbiddLAogICAgICAgICAgICAgICAgIFsncHJpb3JpdHknLCc3OScs'
    'J2lpZicsRlVMTF9IT1NULCdsb29rdXAnLCdtYWluJ10pOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCpy'
    'dWxlXSxjaGVjaz1GYWxzZSkKICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywqcnVsZV0pCiAgICBjb21tYW5k'
    'KFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0pCiAgICBkYXRhPWpzb24u'
    'bG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgaWYgc2h1dGlsLndoaWNoKCdyZXNvbHZlY3RsJykgYW5kIGNv'
    'bW1hbmQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLCctLXF1aWV0Jywnc3lzdGVtZC1yZXNvbHZlZCddLGNoZWNrPUZhbHNl'
    'KS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgZGF0YVsnZG5zX21vZGUnXT0ncmVzb2x2ZWRfbGluaycKICAgICAgICB3cml0'
    'ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RucycsRlVM'
    'TF9IT1NULCcxNzIuMjkuMjQ3LjInXSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RvbWFpbicsRlVMTF9IT1NU'
    'LCd+LiddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZGVmYXVsdC1yb3V0ZScsRlVMTF9IT1NULCd5ZXMnXSkK'
    'ICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNoZWNrPUZhbHNlKQogICAgZWxzZToKICAg'
    'ICAgICB1c2VfcmVzb2x2ZXJfZmlsZSgpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPVRydWUpCiAgICBy'
    'ZXRpcmVfcHJldmlvdXNfY29ubmVjdGlvbnMob2xkX2FkZHJlc3NlcykKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZToKICAg'
    'ICAgICBwb2xpY3kuYXBwbHkoKQogICAgaWYgbm90IHJlY292ZXJfc3lzdGVtX2RucygpOgogICAgICAgIHJhaXNlIFJ1bnRp'
    'bWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgIyBUZXN0IHRoZSBhY3R1YWwgaG9zdCBwYXRoIGFzIHdlbGwgYXMg'
    'bmFtZXNwYWNlIHByb2JlcyBiZWZvcmUgYW5ub3VuY2luZyBjb25uZWN0ZWQuCiAgICBjaGVjayA9IGNvbW1hbmQoWydjdXJs'
    'JywnLTQnLCctLW5vcHJveHknLCcnIGlmIHBvbGljeSBpcyBub3QgTm9uZSBlbHNlICcqJywnLS1mYWlsJywnLS1zaWxlbnQn'
    'LCctLW1heC10aW1lJywnMTAnLCooWyctLXNvY2tzNS1ob3N0bmFtZScsJzEyNy4wLjAuMToxODU1NCddIGlmIHBvbGljeSBp'
    'cyBub3QgTm9uZSBlbHNlIFtdKSwnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJ10sdGltZW91dD0xMikKICAgIGlmIGNoZWNrLnN0'
    'ZG91dC5zdHJpcCgpICE9ICczOC4xODAuMTY0LjY3JzoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2hvc3RfZWdyZXNz'
    'X2ZhaWxlZCcpCiAgICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgZGF0YVsnYWN0aXZl'
    'J109VHJ1ZQogICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCgoKZGVmIGNsZWFudXBfZnVsbChyZWxl'
    'YXNlPUZhbHNlKToKICAgIGdsb2JhbCBETlNfUFJPQ0VTUwogICAgaWYgRE5TX1BST0NFU1MgaXMgbm90IE5vbmUgYW5kIERO'
    'U19QUk9DRVNTLnBvbGwoKSBpcyBOb25lOgogICAgICAgIEROU19QUk9DRVNTLnRlcm1pbmF0ZSgpCiAgICAgICAgdHJ5OkRO'
    'U19QUk9DRVNTLndhaXQodGltZW91dD0zKQogICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOkROU19Q'
    'Uk9DRVNTLmtpbGwoKTtETlNfUFJPQ0VTUy53YWl0KCkKICAgIEROU19QUk9DRVNTPU5vbmUKICAgIGlmIHBvbGljeSBpcyBu'
    'b3QgTm9uZToKICAgICAgICBwb2xpY3kuc3RvcChyZWxlYXNlPXJlbGVhc2UpCiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4'
    'aXN0cygpOgogICAgICAgIHJldHVybgogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkKICAg'
    'IGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZGVsJywnZGVmYXVsdCcsJ21ldHJpYycsJzEwJywndGFibGUnLEZVTExfVEFCTEVd'
    'LGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywnbGluaycsJ2RlbCcsRlVMTF9IT1NUXSxjaGVjaz1GYWxzZSkKICAg'
    'ICMgT24gZmFpbHVyZTogcmV0YWluIHJvdXRpbmcsIEROUyBhbmQgdGhlIHBlcnNpc3RlbnQgZ3VhcmQgdW50aWwgZXhwbGlj'
    'aXQgZGlzY29ubmVjdC4KICAgIGlmIG5vdCByZWxlYXNlOgogICAgICAgIHJldHVybgogICAgcmVzdG9yZV9yZXNvbHZlcl9m'
    'aWxlKGRhdGEpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9U'
    'QUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ3RvJyxD'
    'TElFTlQrJy8zMicsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwn'
    'LCdwcmlvcml0eScsJzc5JywnaWlmJyxGVUxMX0hPU1QsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBmb3Igc2VydmVy'
    'IGluICgnMTkyLjE2OC4wLjE2MycsICczOC4xODAuMTY0LjY3Jyk6CiAgICAgICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2Rl'
    'bCcsJ3ByaW9yaXR5JywnNzknLCd0bycsc2VydmVyLCdpcHByb3RvJywndGNwJywnZHBvcnQnLCcyMicsJ2xvb2t1cCcsQURN'
    'SU5fVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2Rpc2FibGUnLCctLW5vdycsJ2V2Z2Vu'
    'aXVtLXN0YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZSddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ25mdCcsJ2RlbGV0'
    'ZScsJ3RhYmxlJywnaW5ldCcsRlVMTF9HVUFSRF0sY2hlY2s9RmFsc2UpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MoKQogICAg'
    'Y2xlYXJfZG5zX21hcHBpbmdzKHByZXZpb3VzX3Zwbj1UcnVlKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdmbHVzaCcs'
    'J3RhYmxlJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBmdWxsX3N0YXRlKCkudW5saW5rKCkKICAgIGNvbW1hbmQo'
    'WydyZXNvbHZlY3RsJywnZmx1c2gtY2FjaGVzJ10sY2hlY2s9RmFsc2UpIGlmIHNodXRpbC53aGljaCgncmVzb2x2ZWN0bCcp'
    'IGVsc2UgTm9uZQoKCmRlZiBjb21tYW5kKGFyZ3MsIGNoZWNrPVRydWUsIHRpbWVvdXQ9MjAsIGRhdGE9Tm9uZSwgZW52PU5v'
    'bmUpOgogICAgY3AgPSBzdWJwcm9jZXNzLnJ1bihbc3RyKHgpIGZvciB4IGluIGFyZ3NdLCBpbnB1dD1kYXRhLCB0ZXh0PVRy'
    'dWUsIGNhcHR1cmVfb3V0cHV0PVRydWUsCiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9dGltZW91dCwgZW52PWVu'
    'diwgY2hlY2s9RmFsc2UpCiAgICBpZiBjaGVjayBhbmQgY3AucmV0dXJuY29kZToKICAgICAgICAjIEFyZ3VtZW50cyBtYXkg'
    'Y29udGFpbiBhIENTUiBwYXRoOyBkbyBub3QgcHJvcGFnYXRlIHByb2Nlc3Mgb3V0cHV0IHRvIEdVSS9sb2dzLgogICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcignY29tbWFuZF9mYWlsZWQnKQogICAgcmV0dXJuIGNwCgoKZGVmIGluc2lkZShhcmdzLCAq'
    'Kmt3YXJncyk6CiAgICByZXR1cm4gY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2V4ZWMnLCBOUywgKmFyZ3NdLCAqKmt3YXJn'
    'cykKCgpkZWYgd3JpdGUocGF0aCwgdmFsdWUpOgogICAgcGF0aC5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVlLCBtb2RlPTBv'
    'NzAwLCBleGlzdF9vaz1UcnVlKQogICAgdGVtcG9yYXJ5ID0gcGF0aC53aXRoX3N1ZmZpeCgnLm5ldycpCiAgICBmZCA9IG9z'
    'Lm9wZW4odGVtcG9yYXJ5LCBvcy5PX1dST05MWSB8IG9zLk9fQ1JFQVQgfCBvcy5PX1RSVU5DIHwgb3MuT19OT0ZPTExPVywg'
    'MG82MDApCiAgICB3aXRoIG9zLmZkb3BlbihmZCwgJ3cnKSBhcyBzdHJlYW06CiAgICAgICAgc3RyZWFtLndyaXRlKHZhbHVl'
    'KQogICAgdGVtcG9yYXJ5LnJlcGxhY2UocGF0aCkKCgpkZWYgc2F2ZWQoKToKICAgIHRyeToKICAgICAgICByZXR1cm4ganNv'
    'bi5sb2FkcyhTVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0'
    'dXJuIHt9CgoKZGVmIHN0YWdlKHBoYXNlLCBtZXNzYWdlLCBwcm9ncmVzcywgKipmaWVsZHMpOgogICAgZGF0YSA9IHsqKnNh'
    'dmVkKCksICdwaGFzZSc6IHBoYXNlLCAnbWVzc2FnZSc6IG1lc3NhZ2UsICdwcm9ncmVzcyc6IHByb2dyZXNzLAogICAgICAg'
    'ICAgICAndXBkYXRlZCc6IGludCh0aW1lLnRpbWUoKSksICdoZWFydGJlYXQnOiB0aW1lLm1vbm90b25pYygpLCAqKmZpZWxk'
    'c30KICAgIHdyaXRlKFNUQVRFLCBqc29uLmR1bXBzKGRhdGEsIGVuc3VyZV9hc2NpaT1GYWxzZSkpCiAgICBpZiBzdXBwb3J0'
    'X2FwaSBpcyBub3QgTm9uZToKICAgICAgICB0cnk6c3VwcG9ydF9hcGkucmVjb3JkKFJPT1Qsd3JpdGUsZGF0YSkKICAgICAg'
    'ICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixUeXBlRXJyb3IpOnBhc3MKCgpkZWYgc3RhdHVzKCk6CiAgICBkYXRhID0g'
    'c2F2ZWQoKQogICAgcnVubmluZyA9IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklU'
    'XSwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MikucmV0dXJuY29kZSA9PSAwCiAgICBpZiBkYXRhLmdldCgncGhhc2UnKSA9PSAn'
    'Y29ubmVjdGVkJyBhbmQgKG5vdCBydW5uaW5nIG9yIHRpbWUubW9ub3RvbmljKCktZGF0YS5nZXQoJ2hlYXJ0YmVhdCcsIDAp'
    'ID4gOTApOgogICAgICAgIGRhdGEudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsIG1lc3NhZ2U9J9Ch0L7QtdC00LjQvdC1'
    '0L3QuNC1INC+0YHRgtCw0L3QvtCy0LjQu9C+0YHRjC4g0J/RgNC+0LLQtdGA0YzRgtC1INGB0L7RgdGC0L7Rj9C90LjQtSDQ'
    't9Cw0YnQuNGC0Ysg0Lgg0L3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsuJywgYWN0aXZlPUZhbHNlKQogICAg'
    'cHVibGljID0ge2tleTogZGF0YVtrZXldIGZvciBrZXkgaW4gKCdwaGFzZScsICdtZXNzYWdlJywgJ3Byb2dyZXNzJywgJ2Fj'
    'dGl2ZScsICd1cGRhdGVkJywgJ21ldHJpY3MnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3Nj'
    'b3BlJywgJ3NpbmNlJywgJ3JldHJ5JywgJ2Vycm9yX2NvZGUnLCAncGF0aCcpIGlmIGtleSBpbiBkYXRhfQogICAgdG9rZW5f'
    'aW5mbyA9IHRva2VuX3N0YXR1cygpCiAgICByZXR1cm4geydwaGFzZSc6ICdvZmYnLCAnbWVzc2FnZSc6ICgn0KLQvtC60LXQ'
    'vSDRgdC+0YXRgNCw0L3RkdC9LiDQndCw0LbQvNC40YLQtSDCq9Cf0L7QtNC60LvRjtGH0LjRgtGMwrsuJyBpZiB0b2tlbl9p'
    'bmZvWydoYXNfdG9rZW4nXSBlbHNlICfQktCy0LXQtNC40YLQtSDQuCDQv9C+0LTRgtCy0LXRgNC00LjRgtC1INGC0L7QutC1'
    '0L0g0LrQu9C40LXQvdGC0LAuJyksCiAgICAgICAgICAgICdwcm9ncmVzcyc6IDAsICdhY3RpdmUnOiBGYWxzZSwgKipwdWJs'
    'aWMsICdydW5uaW5nJzogcnVubmluZywKICAgICAgICAgICAgKip0b2tlbl9pbmZvLCAqKmRldmljZV9zdGF0dXMoKSwgJ2lz'
    'b2xhdGVkJzogRmFsc2UsICdmdWxsX2RldmljZSc6IFRydWUsICdndWFyZCc6IGZ1bGxfZ3VhcmRfYWN0aXZlKCksICdwcm90'
    'b2NvbCc6ICdJS0V2MiDihpIg0K3RgdGC0L7QvdC40Y8nfQoKCkBjb250ZXh0bGliLmNvbnRleHRtYW5hZ2VyCmRlZiBuYW1l'
    'c3BhY2UoKToKICAgIGJlZm9yZSA9IG9zLm9wZW4oJy9wcm9jL3NlbGYvbnMvbmV0Jywgb3MuT19SRE9OTFkpCiAgICB0YXJn'
    'ZXQgPSBvcy5vcGVuKCcvcnVuL25ldG5zLycrTlMsIG9zLk9fUkRPTkxZKQogICAgdHJ5OgogICAgICAgIG9zLnNldG5zKHRh'
    'cmdldCwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIHlpZWxkCiAgICBmaW5hbGx5OgogICAgICAgIG9zLnNldG5zKGJlZm9y'
    'ZSwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIG9zLmNsb3NlKHRhcmdldCkKICAgICAgICBvcy5jbG9zZShiZWZvcmUpCgoK'
    'ZGVmIHBoeXNpY2FsX3JvdXRlKCk6CiAgICByb3V0ZXMgPSBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsICctaicsICctNCcs'
    'ICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ21haW4nLCAnZGVmYXVsdCddKS5zdGRvdXQpCiAgICBjYW5kaWRhdGVzID0g'
    'W3IgZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdnYXRld2F5JykgYW5kIHIuZ2V0KCdkZXYnKSBhbmQKICAgICAgICAgICAg'
    'ICAgICAgbm90IHJbJ2RldiddLnN0YXJ0c3dpdGgoKCd0dW4nLCAneHJheScsICd3ZycsICdldm4tJykpXQogICAgaWYgbm90'
    'IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdub19waHlzaWNhbF9yb3V0ZScpCiAgICByb3V0ZSA9'
    'IG1pbihjYW5kaWRhdGVzLCBrZXk9bGFtYmRhIHI6IHIuZ2V0KCdtZXRyaWMnLCAwKSkKICAgIGlmIG5vdCByZS5mdWxsbWF0'
    'Y2gocidbQS1aYS16MC05Xy46LV17MSwxNX0nLCByb3V0ZVsnZGV2J10pOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    'aW52YWxpZF9pbnRlcmZhY2UnKQogICAgaXBhZGRyZXNzLklQdjRBZGRyZXNzKHJvdXRlWydnYXRld2F5J10pCiAgICByZXR1'
    'cm4gcm91dGUKCgpkZWYgaG9zdF9ydWxlcyhpZmFjZSwgcHJldmlvdXNfZm9yd2FyZD1UcnVlKToKICAgICMgU2NvcGUgZXZl'
    'cnkgbmV3IGZvcndhcmRpbmcvTkFUIHJ1bGUgdG8gb3VyIG9uZSBpbnRlcmZhY2UgYW5kIHRoZSBjb25maWd1cmVkIGluZ3Jl'
    'c3MgYWRkcmVzcy4KICAgIHByZXNlcnZlX2Rpc2FibGVkID0gJycgaWYgcHJldmlvdXNfZm9yd2FyZCBlbHNlICcnJyAgaWlm'
    'bmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBhY2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZw'
    'cm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgZHJvcCcn'
    'JwogICAgcmV0dXJuIGYnJyd0YWJsZSBpbmV0IHtORlR9IHt7CiBjaGFpbiBmb3J3YXJkIHt7CiAgdHlwZSBmaWx0ZXIgaG9v'
    'ayBmb3J3YXJkIHByaW9yaXR5IC0yMDsgcG9saWN5IGFjY2VwdDsKICBpaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHt7IHtT'
    'RVJWRVJ9IH19IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVO'
    'VH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2Fk'
    'ZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3AgZHBvcnQgMjQ1NzEgYWNjZXB0CiAgaWlmbmFtZSAie0hP'
    'U1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGRy'
    'b3AKICBvaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJWRVJ9LCAzOC4xODAuMTY0LjY3IH19IGN0IHN0YXRlIGVz'
    'dGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBkcm9wCntwcmVzZXJ2ZV9kaXNhYmxlZH0KIH19'
    'CiBjaGFpbiBuYXQge3sKICB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2Vw'
    'dDsKICBpcCBzYWRkciB7Q0xJRU5UfSBvaWZuYW1lICJ7aWZhY2V9IiBtYXNxdWVyYWRlCiB9fQp9fScnJwoKCmRlZiBzZXR1'
    'cF9uZXR3b3JrKCk6CiAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICMgUmVmdXNlIG5hbWUvYWRkcmVzcyBjb2xs'
    'aXNpb25zIHJhdGhlciB0aGFuIHJlcHVycG9zaW5nIGFub3RoZXIgYXBwbGljYXRpb24ncyByZXNvdXJjZXMuCiAgICBpZiBQ'
    'YXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIG9yIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrSE9TVCkuZXhpc3RzKCkg'
    'b3IgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X25h'
    'bWVzcGFjZV9leGlzdHMnKQogICAgaWYgY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUnLCBz'
    'dHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVz'
    'dF90YWJsZV9pbl91c2UnKQogICAgaWYgYW55KE5FVFdPUksgaW4gbGluZSBmb3IgbGluZSBpbiBjb21tYW5kKFsnaXAnLCAn'
    'LTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsICdhbGwnXSkuc3Rkb3V0LnNwbGl0bGluZXMoKSk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCd0ZXN0X25ldHdvcmtfaW5fdXNlJykKICAgIG9sZF9mb3J3YXJkID0gUGF0aCgnL3Byb2Mvc3lz'
    'L25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICAjIFJlY29yZCBvd25lcnNoaXAgYmVmb3Jl'
    'IGNyZWF0aW5nIGFueXRoaW5nOiBjbGVhbnVwIGlzIHZhbGlkIGFmdGVyIGV2ZXJ5IHBhcnRpYWwgc3RlcC4KICAgIHVwbGlu'
    'ayA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvcm91dGVbJ2RldiddLydmb3J3YXJkaW5nJwogICAgd3JpdGUo'
    'Uk9PVC8nbmV0d29yay5qc29uJywganNvbi5kdW1wcyh7J2ZvcndhcmQnOiBvbGRfZm9yd2FyZCwgJ2ludGVyZmFjZSc6IHJv'
    'dXRlWydkZXYnXSwgJ3VwbGlua19mb3J3YXJkJzogdXBsaW5rLnJlYWRfdGV4dCgpLnN0cmlwKCl9KSkKICAgIGNvbW1hbmQo'
    'WydpcCcsICduZXRucycsICdhZGQnLCBOU10pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25m'
    'JywgJ25hbWVzZXJ2ZXIgMS4xLjEuMVxubmFtZXNlcnZlciA5LjkuOS45XG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoy'
    'XG4nKQogICAgIyBuc3MtcmVzb2x2ZSB0YWxrcyB0byB0aGUgaG9zdCBkYWVtb24gb3ZlciBhIFVuaXggc29ja2V0IGV2ZW4g'
    'aW5zaWRlIG5ldG5zLgogICAgbnNzPVBhdGgoJy9ldGMvbnNzd2l0Y2guY29uZicpLnJlYWRfdGV4dCgpCiAgICBuc3M9cmUu'
    'c3ViKHInXmhvc3RzOi4qJCcsICdob3N0czogZmlsZXMgZG5zJywgbnNzLCBmbGFncz1yZS5NKQogICAgd3JpdGUoUGF0aCgn'
    'L2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJywgbnNzKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnYWRkJywg'
    'SE9TVCwgJ3R5cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUnLCBQRUVSXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywg'
    'J3NldCcsIFBFRVIsICduZXRucycsIE5TXSkKICAgIGNvbW1hbmQoWydpcCcsICdhZGRyJywgJ2FkZCcsIEdBVEVXQVkrJy8z'
    'MCcsICdkZXYnLCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIEhPU1QsICd1cCddKQogICAgaW5z'
    'aWRlKFsnaXAnLCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8zMCcsICdkZXYnLCBQRUVSXSkKICAgIGluc2lkZShbJ2lwJywg'
    'J2xpbmsnLCAnc2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3NldCcsICdsbycsICd1cCdd'
    'KQogICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ2RlZmF1bHQnLCAndmlhJywgR0FURVdBWV0pCiAgICBjb21t'
    'YW5kKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywgc3RyKFRBQkxFKSwgJ2RlZmF1bHQnLCAndmlhJywgcm91dGVb'
    'J2dhdGV3YXknXSwgJ2RldicsIHJvdXRlWydkZXYnXV0pCiAgICBmb3IgYWRkcmVzcyBpbiBFTkRQT0lOVFM6CiAgICAgICAg'
    'Y29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElFTlQr'
    'Jy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldKQogICAg'
    'cnVsZXMgPSBob3N0X3J1bGVzKHJvdXRlWydkZXYnXSwgcHJldmlvdXNfZm9yd2FyZD1vbGRfZm9yd2FyZCA9PSAnMScpCiAg'
    'ICBjb21tYW5kKFsnbmZ0JywgJy1jJywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWYn'
    'LCAnLSddLCBkYXRhPXJ1bGVzKQogICAgIyBQZXItaW50ZXJmYWNlIGZvcndhcmRpbmcgYXZvaWRzIGlwX2ZvcndhcmQncyBn'
    'bG9iYWwgZGVmYXVsdHMgcmVzZXQuCiAgICAoUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9IT1NULydmb3J3YXJk'
    'aW5nJykud3JpdGVfdGV4dCgnMVxuJykKICAgIHVwbGluay53cml0ZV90ZXh0KCcxXG4nKQoKCmRlZiBjbGVhbnVwKCk6CiAg'
    'ICBjbGVhbnVwX2Z1bGwoKQogICAgIyBBbiB1bm93bmVkIG5hbWVzcGFjZS90YWJsZSBtdXN0IG5ldmVyIGJlIGRlbGV0ZWQg'
    'YnkgYSBnZW5lcmljIGNsZWFudXAgY2FsbC4KICAgIGlmIG5vdCAoUk9PVC8nbmV0d29yay5qc29uJykuZXhpc3RzKCk6CiAg'
    'ICAgICAgcmV0dXJuCiAgICBkYXRhID0ganNvbi5sb2FkcygoUk9PVC8nbmV0d29yay5qc29uJykucmVhZF90ZXh0KCkpCiAg'
    'ICBjb21tYW5kKFsnbmZ0JywgJ2RlbGV0ZScsICd0YWJsZScsICdpbmV0JywgTkZUXSwgY2hlY2s9RmFsc2UpCiAgICBmb3Ig'
    'YWRkcmVzcyBpbiAoKkVORFBPSU5UUywgKkxFR0FDWV9FTkRQT0lOVFMpOgogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxl'
    'JywgJ2RlbCcsICdwcmlvcml0eScsIHN0cihQUklPUklUWSksICdmcm9tJywgQ0xJRU5UKycvMzInLAogICAgICAgICAgICAg'
    'ICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBmb3IgYWRk'
    'cmVzcyBpbiBkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pOgogICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNz'
    'KGFkZHJlc3MpLmlzX2dsb2JhbDoKICAgICAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5'
    'JywgJzExMScsICdmcm9tJywgQ0xJRU5UKycvMzInLCAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxF'
    'KV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2ZsdXNoJywgJ3RhYmxlJywgc3RyKFRBQkxF'
    'KV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2RlbCcsIE5TXSwgY2hlY2s9RmFsc2UpCiAg'
    'ICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdkZWwnLCBIT1NUXSwgY2hlY2s9RmFsc2UpCiAgICBpZiAndXBsaW5rX2Zvcndh'
    'cmQnIGluIGRhdGE6CiAgICAgICAgcGF0aCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvZGF0YVsnaW50ZXJm'
    'YWNlJ10vJ2ZvcndhcmRpbmcnCiAgICAgICAgaWYgcGF0aC5leGlzdHMoKToKICAgICAgICAgICAgcGF0aC53cml0ZV90ZXh0'
    'KGRhdGFbJ3VwbGlua19mb3J3YXJkJ10rJ1xuJykKICAgIGVsaWYgZGF0YS5nZXQoJ2ZvcndhcmQnKSA9PSAnMCcgYW5kIFBh'
    'dGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykucmVhZF90ZXh0KCkuc3RyaXAoKSA9PSAnMSc6CiAgICAgICAg'
    'UGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS53cml0ZV90ZXh0KCcwXG4nKQogICAgKFBhdGgoJy9ldGMv'
    'bmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgKFBhdGgoJy9ldGMvbmV0bnMn'
    'KS9OUy8nbnNzd2l0Y2guY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3aXRoIGNvbnRleHRsaWIuc3VwcHJl'
    'c3MoT1NFcnJvcik6CiAgICAgICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykucm1kaXIoKQogICAgKFJPT1QvJ25ldHdvcmsu'
    'anNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKCgpkZWYgdGxzX3JlcXVlc3QoYWRkcmVzcywgcGF0aCwgYm9keT1O'
    'b25lLCBjbGllbnQ9RmFsc2UsIHRpbWVvdXQ9OCwgaWRlbnRpdHk9U0VSVkVSKToKICAgIGNvbnRleHQgPSBzc2wuY3JlYXRl'
    'X2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgaWYgY2xpZW50OgogICAgICAgIGNvbnRleHQubG9hZF9j'
    'ZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgc29jayA9'
    'IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9dGltZW91dCkKICAgIHRyeToKICAg'
    'ICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1pZGVudGl0eSkKICAgIGV4Y2Vw'
    'dCBCYXNlRXhjZXB0aW9uOgogICAgICAgIHNvY2suY2xvc2UoKQogICAgICAgIHJhaXNlCiAgICBjb25uZWN0aW9uID0gaHR0'
    'cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oYWRkcmVzcywgODQ0MywgdGltZW91dD10aW1lb3V0KQogICAgY29ubmVjdGlvbi5z'
    'b2NrID0gdGxzCiAgICBlbmNvZGVkID0ganNvbi5kdW1wcyhib2R5LCBzZXBhcmF0b3JzPSgnLCcsICc6JykpLmVuY29kZSgp'
    'IGlmIGJvZHkgaXMgbm90IE5vbmUgZWxzZSBOb25lCiAgICB0cnk6CiAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdQT1NU'
    'JyBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgJ0dFVCcsIHBhdGgsIGJvZHk9ZW5jb2RlZCwKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgaGVhZGVycz17J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywgJ0Nvbm5lY3Rpb24nOiAnY2xv'
    'c2UnfSkKICAgICAgICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgIHJhdyA9IHJlc3BvbnNl'
    'LnJlYWQoMjAwMDEpCiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBvciBsZW4ocmF3KSA+IDIwMDAwOgogICAg'
    'ICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlcXVlc3RfcmVqZWN0ZWQnKQogICAgICAgIHJldHVybiBqc29uLmxvYWRz'
    'KHJhdykKICAgIGZpbmFsbHk6CiAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCgoKZGVmIGVucm9sbCgpOgogICAgdG9rZW4g'
    'PSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKFRPS0VOX1BBVFRF'
    'Uk4sIHRva2VuKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfdG9rZW4nKQogICAgdHJ5OgogICAgICAg'
    'IGNhY2hlZCA9IGpzb24ubG9hZHMoKFJPT1QvJ3Byb2ZpbGUuanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIGlmIChjYWNo'
    'ZWQuZ2V0KCdjYScpID09IFBJTk5FRF9DQSBhbmQgY2FjaGVkLmdldCgnc2VydmVyJykgPT0gU0VSVkVSIGFuZAogICAgICAg'
    'ICAgICByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgY2FjaGVkLmdldCgnaWRlbnRpdHknLCAnJykpIGFu'
    'ZAogICAgICAgICAgICBjYWNoZWQuZ2V0KCdlbmRwb2ludCcpIGluIEVORFBPSU5UUyBhbmQgY2FjaGVkLmdldCgncGh5c2lj'
    'YWxfbmV0d29yaycpIGFuZAogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd4NTA5JywgJy1pbicsIFJPT1QvJ2Ns'
    'aWVudC5wZW0nLCAnLWNoZWNrZW5kJywgc3RyKDcqODY0MDApLCAnLW5vb3V0J10sIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2Rl'
    'ID09IDApOgogICAgICAgICAgICBjb250ZXh0ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19DTElFTlQpCiAg'
    'ICAgICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGll'
    'bnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICAgICAgICAgY3VycmVudCA9'
    'IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRl'
    'd2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgICAgICAgICAgYWRk'
    'cmVzcyA9IGNhY2hlZFsnZW5kcG9pbnQnXSBpZiBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3b3JrJykgPT0gY3VycmVudCBl'
    'bHNlIFNFUlZFUgogICAgICAgICAgICByZXR1cm4gY2FjaGVkWydpZGVudGl0eSddLCBhZGRyZXNzCiAgICBleGNlcHQgKE9T'
    'RXJyb3IsIFZhbHVlRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAgICAgICAgcGFzcwogICAgc3RhZ2UoJ3Rva2VuJywgJ9Cf0L7Q'
    'u9GD0YfQsNGOINGB0LXRgNGC0LjRhNC40LrQsNGCINC00LvRjyDRjdGC0L7Qs9C+INGD0YHRgtGA0L7QudGB0YLQstCwLics'
    'IDI1KQogICAgaWYgbm90IChST09ULydjbGllbnQta2V5LnBlbScpLmV4aXN0cygpOgogICAgICAgIGNvbW1hbmQoWydvcGVu'
    'c3NsJywgJ2dlbnBrZXknLCAnLWFsZ29yaXRobScsICdSU0EnLCAnLXBrZXlvcHQnLCAncnNhX2tleWdlbl9iaXRzOjMwNzIn'
    'LAogICAgICAgICAgICAgICAgICctb3V0JywgUk9PVC8nY2xpZW50LWtleS5wZW0nXSwgdGltZW91dD0zMCkKICAgICAgICAo'
    'Uk9PVC8nY2xpZW50LWtleS5wZW0nKS5jaG1vZCgwbzYwMCkKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6'
    'CiAgICAgICAgd3JpdGUoUk9PVC8nZGV2aWNlJywgc2VjcmV0cy50b2tlbl9oZXgoMTYpKQogICAgY29tbWFuZChbJ29wZW5z'
    'c2wnLCAncmVxJywgJy1uZXcnLCAnLWtleScsIFJPT1QvJ2NsaWVudC1rZXkucGVtJywgJy1zdWJqJywgJy9DTj1ldmdlbml1'
    'bS1kZXZpY2UnLAogICAgICAgICAgICAgJy1vdXQnLCBST09ULydyZXF1ZXN0LnBlbSddKQogICAgcGF5bG9hZCA9IHsndG9r'
    'ZW4nOiB0b2tlbiwgJ2RldmljZSc6IChST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5zdHJpcCgpLCAnY3NyJzogKFJPT1Qv'
    'J3JlcXVlc3QucGVtJykucmVhZF90ZXh0KCl9CiAgICBsYXN0ID0gTm9uZQogICAgZm9yIGFkZHJlc3MgaW4gKFNFUlZFUiwp'
    'OgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICAgICAgICAgIHJlcGx5ID0gdGxz'
    'X3JlcXVlc3QoYWRkcmVzcywgJy9lbnJvbGwnLCBwYXlsb2FkLCB0aW1lb3V0PTYpCiAgICAgICAgICAgIHByb2ZpbGUgPSBy'
    'ZXBseS5nZXQoJ3Byb2ZpbGUnLCB7fSkKICAgICAgICAgICAgaWYgcmVwbHkuZ2V0KCdvaycpIGlzIG5vdCBUcnVlIG9yIHBy'
    'b2ZpbGUuZ2V0KCdjYScpICE9IFBJTk5FRF9DQSBvciBwcm9maWxlLmdldCgnc2VydmVyJykgIT0gU0VSVkVSOgogICAgICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX3Byb2ZpbGUnKQogICAgICAgICAgICBpZiBub3QgcmUuZnVs'
    'bG1hdGNoKHInZGV2aWNlLVthLWYwLTldezI0fScsIHByb2ZpbGUuZ2V0KCdpZGVudGl0eScsICcnKSk6CiAgICAgICAgICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaWRlbnRpdHknKQogICAgICAgICAgICB3cml0ZShST09ULydjbGll'
    'bnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8nY2EucGVtJywgUElOTkVE'
    'X0NBKQogICAgICAgICAgICB3cml0ZShST09ULyd4NTA5Jy8nY2xpZW50LnBlbScsIHByb2ZpbGVbJ2NlcnRpZmljYXRlJ10p'
    'CiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDljYScvJ2NhLnBlbScsIFBJTk5FRF9DQSkKICAgICAgICAgICAgd3JpdGUo'
    'Uk9PVC8ncHJpdmF0ZScvJ2NsaWVudC1rZXkucGVtJywgKFJPT1QvJ2NsaWVudC1rZXkucGVtJykucmVhZF90ZXh0KCkpCiAg'
    'ICAgICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3ZlcmlmeScsICctcHVycG9zZScsICdzc2xjbGllbnQnLCAnLUNBZmls'
    'ZScsIFJPT1QvJ2NhLnBlbScsIFJPT1QvJ2NsaWVudC5wZW0nXSkKICAgICAgICAgICAgY3R4ID0gc3NsLlNTTENvbnRleHQo'
    'c3NsLlBST1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGN0eC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVu'
    'dC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUo'
    'KQogICAgICAgICAgICBmaW5nZXJwcmludCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtl'
    'eSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSku'
    'aGV4ZGlnZXN0KCkKICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJvZmlsZS5qc29uJywganNvbi5kdW1wcyh7Kipwcm9maWxl'
    'LCAnZW5kcG9pbnQnOiBhZGRyZXNzLCAncGh5c2ljYWxfbmV0d29yayc6IGZpbmdlcnByaW50fSkpCiAgICAgICAgICAgIHJl'
    'dHVybiBwcm9maWxlWydpZGVudGl0eSddLCBhZGRyZXNzCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBzc2wuU1NMRXJyb3Is'
    'IFJ1bnRpbWVFcnJvcikgYXMgZXhjOgogICAgICAgICAgICBsYXN0ID0gZXhjCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Vu'
    'cm9sbG1lbnRfdW5hdmFpbGFibGUnKSBmcm9tIGxhc3QKCgpkZWYgZGFlbW9uX2NvbmZpZ3MoaWRlbnRpdHksIGFkZHJlc3Mp'
    'OgogICAgUlVOVElNRS5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBpbmNsdWRl'
    'cyA9ICdcbicuam9pbignaW5jbHVkZSAnK3N0cihwKSBmb3IgcGF0dGVybiBpbiAoJy9ldGMvc3Ryb25nc3dhbi5kL2NoYXJv'
    'bi8qLmNvbmYnLCAnL2V0Yy9zdHJvbmdzd2FuL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25mJykKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGZvciBwIGluIFBhdGgoJy8nKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCcvJykpKQogICAgd3JpdGUoUk9PVC8n'
    'c3Ryb25nc3dhbi5jb25mJywgZicnJ2NoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0geWVzCiBpbnN0YWxsX3JvdXRlcyA9IHll'
    'cwogcm91dGluZ190YWJsZSA9IDUxODIyCiByb3V0aW5nX3RhYmxlX3ByaW8gPSAxMDAKIHBsdWdpbnMge3sKe2luY2x1ZGVz'
    'fQogIHZpY2kge3sgc29ja2V0ID0gdW5peDovL3tSVU5USU1FfS9jaGFyb24udmljaSB9fQogIHJlc29sdmUge3sgbG9hZCA9'
    'IG5vIH19CiAga2VybmVsLWxpYmlwc2VjIHt7IGxvYWQgPSBubyB9fQogfX0KfX0KY2hhcm9uLXN5c3RlbWQge3sgam91cm5h'
    'bCB7eyBkZWZhdWx0ID0gMDsgaWtlID0gMSB9fSB9fQonJycpCiAgICAjIEFic29sdXRlIGNyZWRlbnRpYWxzIGFyZSBsb2Nh'
    'bCB0byB0aGlzIGRldmljZSwgbm90IHNoYXJlZCBieSB0aGUgYWNjb3VudCB0b2tlbi4KICAgIHdyaXRlKFJPT1QvJ2Nvbm5l'
    'Y3Rpb24uY29uZicsIGYnJydjb25uZWN0aW9ucyB7ewogc3RhcmZpdmUge3sKICB2ZXJzaW9uID0gMgogIHJlbW90ZV9hZGRy'
    'cyA9IHthZGRyZXNzfQogIHJlbW90ZV9wb3J0ID0ge0FDVElWRVsncG9ydCddfQogIGxvY2FsX3BvcnQgPSA0NTAwCiAgdmlw'
    'cyA9IDAuMC4wLjAKICBwcm9wb3NhbHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0CiAgZW5jYXAgPSB5ZXMKICBm'
    'cmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMTVzCiAgbG9jYWwge3sgYXV0aCA9IGVh'
    'cC10bHM7IGlkID0ge2lkZW50aXR5fTsgZWFwX2lkID0ge2lkZW50aXR5fTsgY2VydHMgPSB7Uk9PVH0vY2xpZW50LnBlbSB9'
    'fQogIHJlbW90ZSB7eyBhdXRoID0gcHVia2V5OyBpZCA9IHtBQ1RJVkVbJ2lkZW50aXR5J119OyBjYWNlcnRzID0ge1JPT1R9'
    'L2NhLnBlbSB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5ldCB7ewogICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICBy'
    'ZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAgZXNwX3Byb3Bvc2FscyA9IGNoYWNoYTIwcG9s'
    'eTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9uID0gbm9uZQogICB9fQogIH19CiB9fQp9fQpz'
    'ZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUgPSB7Uk9PVH0vY2xpZW50LWtleS5wZW0gfX0gfX0KJycnKQogICAg'
    'IyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVzLCBub3Qgc2VtaWNvbG9uIHNlcGFyYXRvcnMgKG5vcm1hbGl6ZSBj'
    'b21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAoJ3N0cm9uZ3N3YW4uY29uZicsICdjb25uZWN0aW9uLmNvbmYnKToK'
    'ICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAgcGF0aC53cml0ZV90ZXh0KHBhdGgucmVhZF90ZXh0KCkucmVwbGFj'
    'ZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4nKS5yZXBsYWNlKCcgfScsICdcbn0nKSkKICAgIHJ1bGVzID0gZicn'
    'J3RhYmxlIGluZXQgZXZuX3N0YXJmaXZlX2d1YXJkIHt7CiBjaGFpbiBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29rIG91'
    'dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciAxMjcuMC4w'
    'LjEgdWRwIGRwb3J0IDI0NTczIGFjY2VwdAogIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBkYWRkciAxNzIuMjkuMjQ3LjEg'
    'bWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIHNwb3J0IDUzIGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB1ZHAg'
    'ZHBvcnQge0FDVElWRVsncG9ydCddfSBhY2NlcHQKICBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCAyNDU3MSBh'
    'Y2NlcHQKICBtZXRhIHNrdWlkIDAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG1ldGEgbmZw'
    'cm90byBpcHY0IGlwc2VjIG91dCByZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0'
    'ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCAn'
    'LWMnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykK'
    'CgpkZWYgc3dhbigqYXJncywgdGltZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRlKFsnc3dhbmN0bCcs'
    'ICphcmdzLCAnLS11cmknLCAndW5peDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1lb3V0PXRpbWVvdXQs'
    'IGNoZWNrPWNoZWNrKQoKCmRlZiBpbnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBzd2FuKCctLWxpc3Qt'
    'c2FzJywgJy0tcmF3JywgdGltZW91dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0LnJldHVybmNvZGUg'
    'PT0gMCBhbmQgJ3N0YXRlPUVTVEFCTElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5TVEFMTEVEJyBpbiBy'
    'ZXN1bHQuc3Rkb3V0CiAgICBleGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgIHJl'
    'dHVybiBGYWxzZQoKCmRlZiBoZWFsdGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0dXJuIHRsc19yZXF1'
    'ZXN0KEhFQUxUSCwgJy9oZWFsdGgnLCBjbGllbnQ9VHJ1ZSwgaWRlbnRpdHk9QUNUSVZFWydpZGVudGl0eSddLCB0aW1lb3V0'
    'PTMpLmdldCgnc2VydmljZScpID09ICdldmdlbml1bS1zdGFyZml2ZScKCgpkZWYgZG93bmxvYWQoc2l6ZT0xMDQ4NTc2KToK'
    'ICAgICMgQSBib3VuZGVkIGludGVncml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBtZWFzdXJlZCB0aGUgSVNQJ3Mg'
    'bWF4aW11bSByYXRlLgogICAgYmxvY2sgPSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVtLXN0YXJmaXZlLWludGVncml0'
    'eS12MScpLmRpZ2VzdCg2NTUzNikKICAgIGV4cGVjdGVkID0gaGFzaGxpYi5zaGEyNTYoKGJsb2NrKihzaXplLy9sZW4oYmxv'
    'Y2spKzEpKVs6c2l6ZV0pLmhleGRpZ2VzdCgpCiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2Fk'
    'YXRhPVBJTk5FRF9DQSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihS'
    'T09ULydjbGllbnQta2V5LnBlbScpKQogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICBzb2NrID0gc29ja2V0LmNyZWF0'
    'ZV9jb25uZWN0aW9uKChIRUFMVEgsIDg0NDMpLCB0aW1lb3V0PTEwKQogICAgICAgIHRscyA9IGNvbnRleHQud3JhcF9zb2Nr'
    'ZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPUFDVElWRVsnaWRlbnRpdHknXSkKICAgICAgICBjb25uZWN0aW9uID0gaHR0cC5j'
    'bGllbnQuSFRUUENvbm5lY3Rpb24oSEVBTFRILCA4NDQzLCB0aW1lb3V0PTEwKTsgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAg'
    'ICAgICAgdHJ5OgogICAgICAgICAgICBzdGFydCA9IHRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAgY29ubmVjdGlvbi5y'
    'ZXF1ZXN0KCdHRVQnLCAnL2Jsb2I/c2l6ZT0nK3N0cihzaXplKSkKICAgICAgICAgICAgcmVzcG9uc2UgPSBjb25uZWN0aW9u'
    'LmdldHJlc3BvbnNlKCkKICAgICAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMDoKICAgICAgICAgICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcigndHJhbnNmZXJfaHR0cCcpCiAgICAgICAgICAgIGRpZ2VzdCA9IGhhc2hsaWIuc2hhMjU2KCk7'
    'IHJlY2VpdmVkID0gMAogICAgICAgICAgICB3aGlsZSByZWNlaXZlZCA8IHNpemU6CiAgICAgICAgICAgICAgICBkYXRhID0g'
    'cmVzcG9uc2UucmVhZChtaW4oNjU1MzYsIHNpemUtcmVjZWl2ZWQpKQogICAgICAgICAgICAgICAgaWYgbm90IGRhdGE6CiAg'
    'ICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoZGF0YSk7IHJlY2VpdmVkICs9'
    'IGxlbihkYXRhKQogICAgICAgICAgICBlbGFwc2VkID0gdGltZS5tb25vdG9uaWMoKS1zdGFydAogICAgICAgIGZpbmFsbHk6'
    'CiAgICAgICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQogICAgaWYgcmVjZWl2ZWQgIT0gc2l6ZSBvciBkaWdlc3QuaGV4ZGln'
    'ZXN0KCkgIT0gZXhwZWN0ZWQ6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnRlZ3JpdHlfZmFpbGVkJykKICAgIHJl'
    'dHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdkb3dubG9hZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFwc2VkLzFlNiwg'
    'MiksCiAgICAgICAgICAgICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwgJ2ludGVncml0eSc6IFRydWUsICds'
    'aW1pdGVkX3NhbXBsZSc6IFRydWV9CgoKZGVmIGRldmljZV9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICBpbmZvPWpzb24u'
    'bG9hZHMoKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICByZXR1cm4geydkZXZpY2VfbmFt'
    'ZSc6aW5mby5nZXQoJ25hbWUnLCcnKSwnZGV2aWNlX251bWJlcic6aW5mby5nZXQoJ251bWJlcicpLAogICAgICAgICAgICAg'
    'ICAgJ2RldmljZV9uYW1lX3BlbmRpbmcnOmJvb2woaW5mby5nZXQoJ3BlbmRpbmcnKSBvciBpbmZvLmdldCgnc3luY19lcnJv'
    'cicpKX0KICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTpyZXR1cm4geydkZXZpY2VfbmFtZSc6JycsJ2RldmljZV9u'
    'dW1iZXInOk5vbmUsJ2RldmljZV9uYW1lX3BlbmRpbmcnOkZhbHNlfQoKCmRlZiBzeW5jX2RldmljZV9uYW1lKG5hbWU9Tm9u'
    'ZSk6CiAgICBpbXBvcnQgdW5pY29kZWRhdGEKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rva2VuJ106cmFpc2Ug'
    'VmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3R'
    'gtCwLicpCiAgICBpZiBuYW1lIGlzIG5vdCBOb25lOgogICAgICAgIG5hbWU9dW5pY29kZWRhdGEubm9ybWFsaXplKCdORkMn'
    'LHN0cihuYW1lKSkuc3RyaXAoKQogICAgICAgIGlmIG5vdCAxPD1sZW4obmFtZSk8PTY0IG9yIGFueSh1bmljb2RlZGF0YS5j'
    'YXRlZ29yeShjKS5zdGFydHN3aXRoKCdDJykgZm9yIGMgaW4gbmFtZSk6CiAgICAgICAgICAgIHJhaXNlIFZhbHVlRXJyb3Io'
    'J9CY0LzRjyDQtNC+0LvQttC90L4g0YHQvtC00LXRgNC20LDRgtGMINC+0YIgMSDQtNC+IDY0INC+0LHRi9GH0L3Ri9GFINGB'
    '0LjQvNCy0L7Qu9C+0LIuJykKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6d3JpdGUoUk9PVC8nZGV2aWNl'
    'JyxzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICB0cnk6aW5mbz1qc29uLmxvYWRzKChST09ULydkZXZpY2UtaW5mby5qc29u'
    'JykucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6aW5mbz17fQogICAgaWYgbmFtZSBpcyBu'
    'b3QgTm9uZTppbmZvLnVwZGF0ZShuYW1lPW5hbWUscGVuZGluZz1UcnVlKQogICAgcGF5bG9hZD17J3Rva2VuJzooUk9PVC8n'
    'dG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpLCdkZXZpY2UnOihST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5zdHJpcCgp'
    'fQogICAgaWYgaW5mby5nZXQoJ3BlbmRpbmcnKTpwYXlsb2FkWyduYW1lJ109aW5mb1snbmFtZSddCiAgICB0cnk6CiAgICAg'
    'ICAgd2l0aCBuYW1lc3BhY2UoKSBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIGVsc2UgY29udGV4dGxpYi5u'
    'dWxsY29udGV4dCgpOgogICAgICAgICAgICByZXBseT10bHNfcmVxdWVzdChTRVJWRVIsJy9kZXZpY2UnLHBheWxvYWQsdGlt'
    'ZW91dD01KQogICAgICAgIHZhbHVlPXJlcGx5WydkZXZpY2UnXTtudW1iZXI9aW50KHZhbHVlWydudW1iZXInXSkKICAgICAg'
    'ICBpZiBub3QgaXNpbnN0YW5jZSh2YWx1ZVsnbmFtZSddLHN0cikgb3Igbm90IDE8PWxlbih2YWx1ZVsnbmFtZSddKTw9NjQg'
    'b3IgbnVtYmVyPDE6cmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9kZXZpY2VfbWV0YWRhdGEnKQogICAgICAgIGluZm89eydu'
    'YW1lJzp2YWx1ZVsnbmFtZSddLCdudW1iZXInOm51bWJlciwncGVuZGluZyc6RmFsc2UsJ3N5bmNfZXJyb3InOkZhbHNlfQog'
    'ICAgZXhjZXB0IChPU0Vycm9yLFJ1bnRpbWVFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yLGh0dHAuY2xpZW50LkhUVFBFeGNl'
    'cHRpb24pOgogICAgICAgIGluZm9bJ3N5bmNfZXJyb3InXT1UcnVlCiAgICB3cml0ZShST09ULydkZXZpY2UtaW5mby5qc29u'
    'Jyxqc29uLmR1bXBzKGluZm8sZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAgIHJldHVybiBkZXZpY2Vfc3RhdHVzKCkKCgpkZWYg'
    'dG9rZW5fc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJp'
    'cCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFsaWQgPSByZS5mdWxs'
    'bWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pIGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9rZW4nOiB2YWxpZCwK'
    'ICAgICAgICAgICAgJ3Rva2VuX2hpbnQnOiAnRVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hsaWIuc2hhMjU2KHRv'
    'a2VuLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90b2tlbih0b2tlbik6'
    'CiAgICB0b2tlbiA9IHRva2VuLnN0cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4p'
    'OgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC90YLQsCDRhNC+0YDQ'
    'vNCw0YLQsCBFVk4xLeKApicpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1'
    'ZSkKICAgIG9sZCA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rva2VuJykuZXhpc3Rz'
    'KCkgZWxzZSAnJwogICAgaWYgb2xkID09IHRva2VuOgogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKTtyZXR1cm4KICAgIGlm'
    'IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9RmFsc2UpLnJldHVy'
    'bmNvZGUgPT0gMDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0YLQutC70Y7Rh9C40YLQ'
    'tSBWUE4t0YLRg9C90L3QtdC70Ywg0L/QtdGA0LXQtCDRgdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicpCiAgICAjIEEgZGlm'
    'ZmVyZW50IGFjY291bnQgbmVlZHMgaXRzIG93biBkZXZpY2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNlIGl0cyBjZXJ0aWZp'
    'Y2F0ZS4KICAgIGZvciBuYW1lIGluICgnZGV2aWNlLWluZm8uanNvbicsICdkZXZpY2UnLCAnY2xpZW50LWtleS5wZW0nLCAn'
    'Y2xpZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdwcml2YXRlL2Ns'
    'aWVudC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScsICdyYW5raW5nLmpzb24nLCAncmVjYWxpYnJhdGUnLCAnZXZlbnRz'
    'Lmpzb24nLCAnc3VwcG9ydC1wcmV2aWV3Lmpzb24nKToKICAgICAgICAoUk9PVC9uYW1lKS51bmxpbmsobWlzc2luZ19vaz1U'
    'cnVlKQogICAgd3JpdGUoUk9PVC8ndG9rZW4nLCB0b2tlbikKICAgIHN5bmNfZGV2aWNlX25hbWUoKQogICAgc3RhZ2UoJ29m'
    'ZicsICfQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzC'
    'uy4nLCAwLCBhY3RpdmU9RmFsc2UsIG1ldHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSk6'
    'CiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgog'
    'ICAgICAgIHNhdmVfdG9rZW4odG9rZW4pCiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAg'
    'IHJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQ'
    'utC70LjQtdC90YLQsC4nKQogICAgZW5zdXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUo'
    'Uk9PVC8ncmVjYWxpYnJhdGUnLCAnMScpCiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxs'
    'LWRldmljZSBFc3RvbmlhIFZQTgpBZnRlcj1uZXR3b3JrLnRhcmdldApTdGFydExpbWl0SW50ZXJ2YWxTZWM9MTgwClN0YXJ0'
    'TGltaXRCdXJzdD0zCltTZXJ2aWNlXQpUeXBlPXNpbXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRl'
    'cm5hbC1zdGFyZml2ZS10dW5uZWwKRXhlY1N0b3BQb3N0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZp'
    'dmUtdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9bWl4ZWQKVU1hc2s9MDA3NwpNZW1vcnlNYXg9'
    'MjU2TQpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zCicnJwogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5'
    'c3RlbScpL1VOSVQsIHVuaXQpCiAgICByZWNvdmVyeSA9ICJldmdlbml1bS1zdGFyZml2ZS10dW5uZWwtcmVjb3Zlci5zZXJ2'
    'aWNlIgogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL3JlY292ZXJ5LCAiIiJbVW5pdF0KRGVzY3JpcHRp'
    'b249UmVjb3ZlciBvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0IHJlc291cmNlcwpEZWZhdWx0RGVwZW5k'
    'ZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0IHZwbi14cmF5LnNlcnZp'
    'Y2UKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFy'
    'Zml2ZS10dW5uZWwtY2xlYW51cApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiKQogICAgY29tbWFu'
    'ZChbJ3N5c3RlbWN0bCcsICdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2VuYWJsZScsIHJl'
    'Y292ZXJ5XSkKICAgIGlmIHJlcGFpcjpjb21tYW5kKFsnc3lzdGVtY3RsJywncmVzZXQtZmFpbGVkJyxVTklUXSxjaGVjaz1G'
    'YWxzZSkKICAgIHN0YWdlKCdzdGFydGluZycgLCAn0JPQvtGC0L7QstC70Y4g0L/QvtC00LrQu9GO0YfQtdC90LjQtSDQsiDQ'
    'rdGB0YLQvtC90LjRji4nLCAyLCBhY3RpdmU9RmFsc2UsIHJldHJ5PTAsIGVycm9yX2NvZGU9JycpCiAgICBjb21tYW5kKFsn'
    'c3lzdGVtY3RsJywgJ3Jlc3RhcnQnIGlmIHJlcGFpciBlbHNlICdzdGFydCcsIFVOSVRdKQogICAgcHJpbnQoJ1ZQTiDQt9Cw'
    '0L/Rg9GB0LrQsNC10YLRgdGPLicsZmx1c2g9VHJ1ZSkKCgpkZWYgZGlzY29ubmVjdCgpOgogICAgY29tbWFuZChbJ3N5c3Rl'
    'bWN0bCcsICdzdG9wJywgVU5JVF0sIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTI1KQogICAgY2xlYW51cCgpCiAgICBjbGVhbnVw'
    'X2Z1bGwocmVsZWFzZT1UcnVlKQogICAgc3RhZ2UoJ29mZicsICdWUE4g0LLRi9C60LvRjtGH0LXQvS4nLCAwLCBhY3RpdmU9'
    'RmFsc2UpCiAgICBwcmludCgnVlBOINCy0YvQutC70Y7Rh9C10L0uJykKCgpkZWYgc3RhcnRfZGFlbW9uKGVudik6CiAgICAo'
    'UlVOVElNRS8nY2hhcm9uLnZpY2knKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgbG9nID0gKFJPT1QvJ2NoYXJvbi5s'
    'b2cnKS5vcGVuKCd3JykKICAgIGRhZW1vbiA9IHN1YnByb2Nlc3MuUG9wZW4oWydpcCcsICduZXRucycsICdleGVjJywgTlMs'
    'IGNoYXJvbl9iaW5hcnkoKV0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudj1lbnYsIHN0ZGluPXN1YnByb2Nl'
    'c3MuREVWTlVMTCwgc3Rkb3V0PWxvZywgc3RkZXJyPWxvZykKICAgIGxvZy5jbG9zZSgpCiAgICB0cnk6CiAgICAgICAgZm9y'
    'IF8gaW4gcmFuZ2UoNjApOgogICAgICAgICAgICBpZiBTVE9QIG9yIGRhZW1vbi5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAg'
    'ICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2RhZW1vbl9zdG9wcGVkJykKICAgICAgICAgICAgaWYgKFJVTlRJTUUv'
    'J2NoYXJvbi52aWNpJykuZXhpc3RzKCkgYW5kIHN3YW4oJy0tc3RhdHMnLCBjaGVjaz1GYWxzZSwgdGltZW91dD0xKS5yZXR1'
    'cm5jb2RlID09IDA6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgIHN3'
    'YW4oJy0tbG9hZC1jcmVkcycsICctLW5vcHJvbXB0JywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAg'
    'ICAgc3dhbignLS1sb2FkLWNvbm5zJywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgcmV0dXJu'
    'IGRhZW1vbgogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgc3RvcF9wcm9jZXNzKGRhZW1vbikKICAgICAgICBy'
    'YWlzZQoKCmRlZiBzdG9wX3Byb2Nlc3MocHJvY2Vzcyk6CiAgICBpZiBwcm9jZXNzIGlzIG5vdCBOb25lIGFuZCBwcm9jZXNz'
    'LnBvbGwoKSBpcyBOb25lOgogICAgICAgIHByb2Nlc3MudGVybWluYXRlKCkKICAgICAgICB0cnk6cHJvY2Vzcy53YWl0KHRp'
    'bWVvdXQ9NSkKICAgICAgICBleGNlcHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDpwcm9jZXNzLmtpbGwoKTtwcm9jZXNz'
    'LndhaXQodGltZW91dD0zKQoKCmRlZiBzdG9wX2NhbmRpZGF0ZShkYWVtb249Tm9uZSk6CiAgICBnbG9iYWwgVExTX1BST0NF'
    'U1MKICAgIHN0b3BfcHJvY2VzcyhkYWVtb24pCiAgICBzdG9wX3Byb2Nlc3MoVExTX1BST0NFU1MpO1RMU19QUk9DRVNTPU5v'
    'bmUKICAgIGNsZWFudXAoKQoKCmRlZiBwcmVwYXJlX2RhdGFfcGxhbmUoYWRkcmVzcyk6CiAgICBpZiBub3QgZnVsbF9zdGF0'
    'ZSgpLmV4aXN0cygpOgogICAgICAgIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX2ludGVyZmFjZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1h'
    'bmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1h'
    'bmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgp'
    'OgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2FkbWluX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgYW55'
    'KHIuZ2V0KCdwcmlvcml0eScpIGluICg3OSw4MCkgZm9yIHIgaW4ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCctaicsJy00'
    'JywncnVsZSddKS5zdGRvdXQpKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3J1bGVfY29sbGlzaW9u'
    'JykKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyh7J2FjdGl2ZSc6RmFsc2UsJ21lYXN1cmVtZW50X29u'
    'bHknOlRydWV9KSkKICAgIGZ1bGxfbmFtZXNwYWNlKGFkZHJlc3MpCiAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKCgpkZWYg'
    'c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVudGl0eSk6CiAgICBnbG9iYWwgQUNUSVZFLFRMU19QUk9DRVNTCiAgICBB'
    'Q1RJVkU9Y2FuZGlkYXRlCiAgICB3cml0ZShST09ULydhY3RpdmUtcGF0aC5qc29uJyxqc29uLmR1bXBzKHsnaWQnOmNhbmRp'
    'ZGF0ZVsnaWQnXX0pKQogICAgc2V0dXBfbmV0d29yaygpCiAgICBkYWVtb25fY29uZmlncyhpZGVudGl0eSxjYW5kaWRhdGVb'
    'J2FkZHJlc3MnXSkKICAgIGlmIGNhbmRpZGF0ZVsndGxzJ106CiAgICAgICAgVExTX1BST0NFU1M9c3VicHJvY2Vzcy5Qb3Bl'
    'bihbJ2lwJywnbmV0bnMnLCdleGVjJyxOUywnL3Vzci9sb2NhbC9zYmluL3ZwbmN0bCcsJ2ludGVybmFsLXRscy1jbGllbnQn'
    'XSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCxzdGRvdXQ9'
    'c3VicHJvY2Vzcy5ERVZOVUxMLHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpCiAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNTAp'
    'OgogICAgICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVkJykKICAgICAgICAgICAgaWYgVExT'
    'X1BST0NFU1MucG9sbCgpIGlzIG5vdCBOb25lOnJhaXNlIFJ1bnRpbWVFcnJvcigndGxzX2NhcnJpZXJfc3RvcHBlZCcpCiAg'
    'ICAgICAgICAgIGlmICcxMjcuMC4wLjE6MjQ1NzMnIGluIGluc2lkZShbJ3NzJywnLWxudSddLGNoZWNrPUZhbHNlKS5zdGRv'
    'dXQ6YnJlYWsKICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcigndGxz'
    'X2NhcnJpZXJfbm90X3JlYWR5JykKICAgICAgICBpbnNpZGUoWyduZnQnLCctZicsJy0nXSxkYXRhPSd0YWJsZSBpcCBldm5f'
    'dGxzX2NhcnJpZXIge1xuIGNoYWluIG91dHB1dCB7XG4gdHlwZSBuYXQgaG9vayBvdXRwdXQgcHJpb3JpdHkgZHN0bmF0OyBw'
    'b2xpY3kgYWNjZXB0O1xuIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyByZWRpcmVjdCB0byA6MjQ1NzNc'
    'biB9XG59XG4nKQogICAgZW52PXsqKm9zLmVudmlyb24sJ1NUUk9OR1NXQU5fQ09ORic6c3RyKFJPT1QvJ3N0cm9uZ3N3YW4u'
    'Y29uZicpfTtlbnYucG9wKCdOT1RJRllfU09DS0VUJyxOb25lKQogICAgZGFlbW9uPXN0YXJ0X2RhZW1vbihlbnYpCiAgICB0'
    'cnk6CiAgICAgICAgc3dhbignLS1pbml0aWF0ZScsJy0tY2hpbGQnLCdzdGFyZml2ZS1uZXQnLHRpbWVvdXQ9MzUpCiAgICAg'
    'ICAgaWYgU1RPUDpyYWlzZSBSdW50aW1lRXJyb3IoJ2NhbmNlbGxlZCcpCiAgICAgICAgaWYgbm90IGluc3RhbGxlZCgpIG9y'
    'IG5vdCBoZWFsdGgoKTpyYWlzZSBSdW50aW1lRXJyb3IoJ2hhbmRzaGFrZV9mYWlsZWQnKQogICAgICAgIHByZXBhcmVfZGF0'
    'YV9wbGFuZShjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgICAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOnJhaXNlIFJ1bnRp'
    'bWVFcnJvcignZXN0b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgICAgICByZXR1cm4gZGFlbW9uCiAgICBleGNlcHQgQmFzZUV4'
    'Y2VwdGlvbjoKICAgICAgICBzdG9wX3Byb2Nlc3MoZGFlbW9uKTtyYWlzZQoKCmRlZiBzcGVlZF9zYW1wbGUoc2l6ZT0yMDk3'
    'MTUyKToKICAgICIiIkJvdW5kZWQgc3ludGhldGljIGJpZGlyZWN0aW9uYWwgcHJvYmU7IG5ldmVyIHJlYWRzIHVzZXIgZmls'
    'ZXMuIiIiCiAgICBwYXlsb2FkPVJPT1QvJ3NwZWVkLXBheWxvYWQuYmluJwogICAgaWYgbm90IHBheWxvYWQuZXhpc3RzKCkg'
    'b3IgcGF5bG9hZC5zdGF0KCkuc3Rfc2l6ZSE9c2l6ZToKICAgICAgICB3aXRoIHBheWxvYWQub3Blbignd2InKSBhcyBmOgog'
    'ICAgICAgICAgICBmb3IgXyBpbiByYW5nZShzaXplLy82NTUzNik6Zi53cml0ZShzZWNyZXRzLnRva2VuX2J5dGVzKDY1NTM2'
    'KSkKICAgICAgICBwYXlsb2FkLmNobW9kKDBvNjAwKQogICAgYmFzZT1bJ2N1cmwnLCctNCcsJy0tbm9wcm94eScsJyonLCct'
    'LWZhaWwnLCctLXNpbGVudCcsJy0tc2hvdy1lcnJvcicsJy0tY29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCcx'
    'MicsCiAgICAgICAgICAnLS1vdXRwdXQnLCcvZGV2L251bGwnLCctLXdyaXRlLW91dCcsJyV7aHR0cF9jb2RlfSAle3NpemVf'
    'ZG93bmxvYWR9ICV7c2l6ZV91cGxvYWR9ICV7dGltZV90b3RhbH0gJXt0aW1lX2Nvbm5lY3R9J10KICAgIHJlc3VsdHM9W10K'
    'ICAgIGZvciBkaXJlY3Rpb24gaW4gKCdkb3duJywndXAnKToKICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcign'
    'Y2FuY2VsbGVkJykKICAgICAgICBleHRyYT1bJ2h0dHBzOi8vc3BlZWQuY2xvdWRmbGFyZS5jb20vX19kb3duP2J5dGVzPScr'
    'c3RyKHNpemUpXSBpZiBkaXJlY3Rpb249PSdkb3duJyBlbHNlIFsnLS1kYXRhLWJpbmFyeScsJ0AnK3N0cihwYXlsb2FkKSwn'
    'aHR0cHM6Ly9zcGVlZC5jbG91ZGZsYXJlLmNvbS9fX3VwJ10KICAgICAgICByPWluc2lkZShiYXNlK2V4dHJhLHRpbWVvdXQ9'
    'MTQsY2hlY2s9RmFsc2UpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBjb2RlLGRvd24sdXAsZWxhcHNlZCxsYXRlbmN5PXIu'
    'c3Rkb3V0LnNwbGl0KCkKICAgICAgICAgICAgY291bnQ9ZmxvYXQoZG93biBpZiBkaXJlY3Rpb249PSdkb3duJyBlbHNlIHVw'
    'KQogICAgICAgICAgICBpZiByLnJldHVybmNvZGUgb3IgY29kZSE9JzIwMCcgb3IgY291bnQ8c2l6ZTpyYWlzZSBWYWx1ZUVy'
    'cm9yKCkKICAgICAgICAgICAgcmVzdWx0cy5hcHBlbmQoKGNvdW50KjgvbWF4KC4wMDEsZmxvYXQoZWxhcHNlZCkpLzFlNixm'
    'bG9hdChsYXRlbmN5KSoxMDAwKSkKICAgICAgICBleGNlcHQgKFZhbHVlRXJyb3IsVHlwZUVycm9yKTpyZXR1cm4geydhdmFp'
    'bGFibGUnOkZhbHNlfQogICAgcmV0dXJuIHsnYXZhaWxhYmxlJzpUcnVlLCdkb3dubG9hZF9tYnBzJzpyb3VuZChyZXN1bHRz'
    'WzBdWzBdLDIpLCd1cGxvYWRfbWJwcyc6cm91bmQocmVzdWx0c1sxXVswXSwyKSwKICAgICAgICAgICAgJ2xhdGVuY3lfbXMn'
    'OnJvdW5kKG1heCh4WzFdIGZvciB4IGluIHJlc3VsdHMpLDEpLCdzYW1wbGVfYnl0ZXMnOnNpemV9CgoKZGVmIHRyYWZmaWNf'
    'dG90YWwoKToKICAgIHRyeToKICAgICAgICBzdGF0cz1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL0ZVTExfSE9TVC8nc3RhdGlz'
    'dGljcycKICAgICAgICByZXR1cm4gc3VtKGludCgoc3RhdHMvbmFtZSkucmVhZF90ZXh0KCkpIGZvciBuYW1lIGluICgncnhf'
    'Ynl0ZXMnLCd0eF9ieXRlcycpKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnJldHVybiAwCgoKZGVmIHNwZWVk'
    'X2RlZ3JhZGVkKHNhbXBsZSxiYXNlbGluZSk6CiAgICAjIFJlcXVpcmUgdXNhYmxlIHNhbXBsZXMgYW5kIGEgbWVhbmluZ2Z1'
    'bCBiYXNlbGluZSBpbiB0aGUgYWZmZWN0ZWQgZGlyZWN0aW9uLgogICAgcmV0dXJuIGJvb2woc2FtcGxlLmdldCgnYXZhaWxh'
    'YmxlJykgYW5kIGFueSgKICAgICAgICBiYXNlbGluZS5nZXQoaywwKT49MiBhbmQgc2FtcGxlLmdldChrLDApPGJhc2VsaW5l'
    'W2tdKi4yCiAgICAgICAgZm9yIGsgaW4gKCdkb3dubG9hZF9tYnBzJywndXBsb2FkX21icHMnKSkpCgoKZGVmIHdvcmtlcigp'
    'OgogICAgZ2xvYmFsIFNUT1AKICAgIFNUT1A9RmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sbGFtYmRh'
    'ICpfOmdsb2JhbHMoKS5fX3NldGl0ZW1fXygnU1RPUCcsVHJ1ZSkpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQs'
    'bGFtYmRhICpfOmdsb2JhbHMoKS5fX3NldGl0ZW1fXygnU1RPUCcsVHJ1ZSkpCiAgICBkYWVtb249Tm9uZQogICAgcmFuaz1y'
    'YW5rX2FwaS5SYW5raW5nKFJPT1QvJ3JhbmtpbmcuanNvbicsW3hbJ2lkJ10gZm9yIHggaW4gQ0FORElEQVRFU10pCiAgICB0'
    'cnk6CiAgICAgICAgY2xlYW51cCgpO3JlZnJlc2hfcmV0YWluZWRfZ3VhcmQoKQogICAgICAgIHN0YWdlKCdwcmVwYXJlJywn'
    '0JPQvtGC0L7QstC70Y4g0LfQsNGJ0LjRidGR0L3QvdGL0LUg0LzQsNGA0YjRgNGD0YLRiy4nLDUsYWN0aXZlPUZhbHNlLG1l'
    'dHJpY3M9e30sZXJyb3JfY29kZT0nJyxzY29wZT0nZnVsbC1kZXZpY2UnKQogICAgICAgIHNldHVwX25ldHdvcmsoKQogICAg'
    'ICAgIGlkZW50aXR5LF89ZW5yb2xsKCkKICAgICAgICBzeW5jX2RldmljZV9uYW1lKCkKICAgICAgICBjbGVhbnVwKCkKICAg'
    'ICAgICByZWJ1aWxkPShST09ULydyZWNhbGlicmF0ZScpLmV4aXN0cygpIG9yIG5vdCByYW5rLmxvYWQoKQogICAgICAgIGlm'
    'IHJlYnVpbGQ6CiAgICAgICAgICAgIG1lYXN1cmVtZW50cz17fQogICAgICAgICAgICBmb3IgaSxjYW5kaWRhdGUgaW4gZW51'
    'bWVyYXRlKENBTkRJREFURVMpOgogICAgICAgICAgICAgICAgaWYgU1RPUDpyZXR1cm4KICAgICAgICAgICAgICAgIHN0YWdl'
    'KCdyYW5raW5nJywn0J/RgNC+0LLQtdGA0Y/RjiDQvNCw0YDRiNGA0YPRgjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sMTAraSoy'
    'MCxhY3RpdmU9RmFsc2UscGF0aD1jYW5kaWRhdGVbJ2lkJ10pCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAg'
    'ICAgICAgZGFlbW9uPXN0YXJ0X2NhbmRpZGF0ZShjYW5kaWRhdGUsaWRlbnRpdHkpCiAgICAgICAgICAgICAgICAgICAgaW50'
    'ZWdyaXR5PWRvd25sb2FkKDEwNDg1NzYpCiAgICAgICAgICAgICAgICAgICAgbWVhc3VyZW1lbnRzW2NhbmRpZGF0ZVsnaWQn'
    'XV09eydvayc6VHJ1ZSwqKnNwZWVkX3NhbXBsZSgyMDk3MTUyKSwnaW50ZWdyaXR5JzppbnRlZ3JpdHlbJ2ludGVncml0eSdd'
    'fQogICAgICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGlt'
    'ZW91dEV4cGlyZWQpOgogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6cmV0dXJuCiAgICAgICAgICAgICAgICAgICAgbWVh'
    'c3VyZW1lbnRzW2NhbmRpZGF0ZVsnaWQnXV09eydvayc6RmFsc2V9CiAgICAgICAgICAgICAgICBmaW5hbGx5OgogICAgICAg'
    'ICAgICAgICAgICAgIHN0b3BfY2FuZGlkYXRlKGRhZW1vbik7ZGFlbW9uPU5vbmUKICAgICAgICAgICAgcmFuay5idWlsZCht'
    'ZWFzdXJlbWVudHMpCiAgICAgICAgICAgIChST09ULydyZWNhbGlicmF0ZScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAg'
    'ICAgICAgY2FuZGlkYXRlcz17eFsnaWQnXTp4IGZvciB4IGluIENBTkRJREFURVN9CiAgICAgICAgY3VycmVudD1uZXh0KGl0'
    'ZXIocmFuay5jYW5kaWRhdGVzKCkpLE5vbmUpCiAgICAgICAgd2hpbGUgY3VycmVudCBhbmQgbm90IFNUT1A6CiAgICAgICAg'
    'ICAgIGNhbmRpZGF0ZT1jYW5kaWRhdGVzW2N1cnJlbnRdCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHN0YWdl'
    'KCdoYW5kc2hha2UnLCfQn9C+0LTQutC70Y7Rh9Cw0Y46ICcrY2FuZGlkYXRlWydsYWJlbCddLDc1LGFjdGl2ZT1GYWxzZSxw'
    'YXRoPWN1cnJlbnQpCiAgICAgICAgICAgICAgICBkYWVtb249c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVudGl0eSkK'
    'ICAgICAgICAgICAgICAgIHN0YWdlKCdyb3V0aW5nJywn0J/QvtC00LrQu9GO0YfQsNGOINGC0YDQsNGE0LjQuiDQuiDQv9GA'
    '0L7QstC10YDQtdC90L3QvtC80YMg0LzQsNGA0YjRgNGD0YLRgy4nLDkyKQogICAgICAgICAgICAgICAgYWN0aXZhdGVfZnVs'
    'bChjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgICAgICAgICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCfQn9C+0LTQutC70Y7R'
    'h9C10L3QvjogJytjYW5kaWRhdGVbJ2xhYmVsJ10rJy4nLDEwMCxhY3RpdmU9VHJ1ZSxwYXRoPWN1cnJlbnQsCiAgICAgICAg'
    'ICAgICAgICAgICAgICBtZXRyaWNzPXJhbmsuZGF0YVsnZW50cmllcyddW2N1cnJlbnRdLHNpbmNlPWludCh0aW1lLnRpbWUo'
    'KSksZXJyb3JfY29kZT0nJykKICAgICAgICAgICAgICAgIGZhaWx1cmVzPTA7c2xvdz0wO2xhc3RfdHJhZmZpYz10cmFmZmlj'
    'X3RvdGFsKCk7bmV4dF9zcGVlZD10aW1lLm1vbm90b25pYygpKzYwMCtzZWNyZXRzLnJhbmRiZWxvdyg2MCkKICAgICAgICAg'
    'ICAgICAgIHdoaWxlIG5vdCBTVE9QOgogICAgICAgICAgICAgICAgICAgIGZvciBfIGluIHJhbmdlKDUwKToKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAg'
    'ICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZTpwb2xpY3kuZW5zdXJlX3JvdXRlKCkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaWYgRE5TX1BST0NFU1MgaXMgTm9uZSBvciBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBzdGFnZSgncmVwYWlyaW5nJywn0J/QtdGA0LXQt9Cw0L/Rg9GB0LrQsNGOINC30LDRidC40YnR'
    'kdC90L3Ri9C5IEROUy4nLDkwLGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPSdwcml2YXRlX2Ruc19zdG9wcGVkJykKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQogICAgICAgICAgICAgICAgICAgICAgICBoZWFs'
    'dGh5PWRhZW1vbi5wb2xsKCkgaXMgTm9uZSBhbmQgaW5zdGFsbGVkKCkgYW5kIGhlYWx0aCgpIGFuZCBlZ3Jlc3NfaGVhbHRo'
    'KCkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaGVhbHRoeSBhbmQgbm90IHJlY292ZXJfc3lzdGVtX2RucygpOnJhaXNl'
    'IFJ1bnRpbWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgICAgICAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvcixW'
    'YWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKTpoZWFsdGh5PUZhbHNlCiAgICAgICAg'
    'ICAgICAgICAgICAgZmFpbHVyZXM9MCBpZiBoZWFsdGh5IGVsc2UgZmFpbHVyZXMrMQogICAgICAgICAgICAgICAgICAgIGlm'
    'IGZhaWx1cmVzPj0yOnJhaXNlIFJ1bnRpbWVFcnJvcigncGF0aF9oZWFsdGhfZmFpbGVkJykKICAgICAgICAgICAgICAgICAg'
    'ICBpZiBub3QgaGVhbHRoeToKICAgICAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2NoZWNraW5nJywn0J7RgtCy0LXRgiDQ'
    't9Cw0LTQtdGA0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgtC10LrRg9GJ0LjQuSDQvNCw0YDRiNGA0YPR'
    'gi4nLDkwLGFjdGl2ZT1GYWxzZSkKICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgICAg'
    'ICBpZiB0aW1lLm1vbm90b25pYygpPj1uZXh0X3NwZWVkOgogICAgICAgICAgICAgICAgICAgICAgICB0cmFmZmljPXRyYWZm'
    'aWNfdG90YWwoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qgc2xvdyBhbmQgdHJhZmZpYy1sYXN0X3RyYWZmaWM8'
    'NDE5NDMwNDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhc3RfdHJhZmZpYz10cmFmZmljO25leHRfc3BlZWQ9dGlt'
    'ZS5tb25vdG9uaWMoKSs2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb250'
    'aW51ZQogICAgICAgICAgICAgICAgICAgICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYwogICAgICAgICAgICAgICAgICAgICAg'
    'ICBzYW1wbGU9c3BlZWRfc2FtcGxlKDIwOTcxNTIpO2Jhc2VsaW5lPXJhbmsuZGF0YVsnZW50cmllcyddW2N1cnJlbnRdCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGRlZ3JhZGVkPXNwZWVkX2RlZ3JhZGVkKHNhbXBsZSxiYXNlbGluZSkKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgc2xvdz1zbG93KzEgaWYgZGVncmFkZWQgZWxzZSAwCiAgICAgICAgICAgICAgICAgICAgICAgIG5l'
    'eHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSsoMjAgaWYgc2xvdyBlbHNlIDYwMCtzZWNyZXRzLnJhbmRiZWxvdyg2MCkpCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGlmIHNsb3c+PTM6cmFpc2UgUnVudGltZUVycm9yKCdjb25maXJtZWRfc3BlZWRfZHJv'
    'cCcpCiAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH0LXQvdC+OiAnK2NhbmRp'
    'ZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCxlcnJvcl9jb2RlPScnKQogICAgICAgICAg'
    'ICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMg'
    'ZXhjOgogICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgcmVhc29uPXN0cihleGMpIGlmIHJl'
    'LmZ1bGxtYXRjaCgnW2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlvbl9mYWlsZWQnCiAgICAgICAgICAg'
    'ICAgICAjIEEgbWlzc2luZyBwaHlzaWNhbCBpbnRlcmZhY2UgaXMgbm90IGEgdHJhbnNwb3J0J3MgZGVmZWF0LgogICAgICAg'
    'ICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIHJvdXRlPXBoeXNpY2FsX3JvdXRlKCk7Y2Fycmllcj1QYXRoKCcv'
    'c3lzL2NsYXNzL25ldCcpL3JvdXRlWydkZXYnXS8nY2FycmllcicKICAgICAgICAgICAgICAgICAgICBvZmZsaW5lPWNhcnJp'
    'ZXIuZXhpc3RzKCkgYW5kIGNhcnJpZXIucmVhZF90ZXh0KCkuc3RyaXAoKT09JzAnCiAgICAgICAgICAgICAgICBleGNlcHQg'
    'KE9TRXJyb3IsUnVudGltZUVycm9yKTpvZmZsaW5lPVRydWUKICAgICAgICAgICAgICAgIGlmIG5vdCBvZmZsaW5lOgogICAg'
    'ICAgICAgICAgICAgICAgIHJhbmsubG9zZShjdXJyZW50LHJlYXNvbikKICAgICAgICAgICAgICAgICAgICBmb2xsb3dpbmc9'
    'cmFuay5uZXh0X2FmdGVyKGN1cnJlbnQpCiAgICAgICAgICAgICAgICAgICAgY3VycmVudD1mb2xsb3dpbmcgb3IgbmV4dChp'
    'dGVyKHJhbmsuY2FuZGlkYXRlcygpKSxOb25lKQogICAgICAgICAgICAgICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Ch0LLRj9C3'
    '0Ywg0L/QvtGC0LXRgNGP0L3QsC4g0J/QtdGA0LXQutC70Y7Rh9Cw0Y4g0LfQsNGJ0LjRidGR0L3QvdGL0Lkg0LzQsNGA0YjR'
    'gNGD0YIuJyBpZiBub3Qgb2ZmbGluZSBlbHNlICfQntC20LjQtNCw0Y4g0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjRjyDR'
    'hNC40LfQuNGH0LXRgdC60L7QuSDRgdC10YLQuC4nLDY1LAogICAgICAgICAgICAgICAgICAgICAgYWN0aXZlPUZhbHNlLGVy'
    'cm9yX2NvZGU9cmVhc29uKQogICAgICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoMzAgaWYgbm90IG9mZmxpbmUgZWxzZSAx'
    'MDApOgogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKC4x'
    'KQogICAgICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKTtkYWVtb249Tm9u'
    'ZQogICAgICAgIGlmIG5vdCBTVE9QOgogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn0JTQvtGB0YLRg9C/0L3Ri9C1INC8'
    '0LDRgNGI0YDRg9GC0Ysg0LjRgdGH0LXRgNC/0LDQu9C4INGC0YDQuCDQv9C+0L/Ri9GC0LrQuC4g0J3QsNC20LzQuNGC0LUg'
    'wqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuyDQtNC70Y8g0L3QvtCy0L7Qs9C+INGA0LXQudGC0LjQvdCz0LAuJywwLAog'
    'ICAgICAgICAgICAgICAgICBhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0ncmFua2luZ19leGhhdXN0ZWQnKQogICAgZXhjZXB0'
    'IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAg'
    'ICAgICBpZiBub3QgU1RPUDoKICAgICAgICAgICAgY29kZT1zdHIoZXhjKSBpZiByZS5mdWxsbWF0Y2goJ1thLXpfXXsxLDY0'
    'fScsc3RyKGV4YykpIGVsc2UgJ2Nvbm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn0J3QtSDR'
    'g9C00LDQu9C+0YHRjCDQv9C+0LTQs9C+0YLQvtCy0LjRgtGMIFZQTi4g0J3QsNC20LzQuNGC0LUgwqvQktC+0YHRgdGC0LDQ'
    'vdC+0LLQuNGC0YzCuy4nLDAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9Y29kZSkKICAgIGZpbmFsbHk6CiAgICAgICAgc3Rv'
    'cF9jYW5kaWRhdGUoZGFlbW9uKQogICAgICAgIGlmIFNUT1A6c3RhZ2UoJ29mZicsJ1ZQTiDQstGL0LrQu9GO0YfQtdC9Lics'
    'MCxhY3RpdmU9RmFsc2UpCg=='
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
    'J21ldGEgbmZwcm90byBpcHY0IG1ldGEgbDRwcm90byB7IHRjcCwgdWRwIH0gdGggZHBvcnQgNTMgZG5hdCBpcCB0byAxNzIu'
    'MjkuMjQ3LjInXQogbWFyays9WydtZXRhIGw0cHJvdG8geyB0Y3AsIHVkcCB9IHRoIGRwb3J0IDUzIG1ldGEgbWFyayBzZXQg'
    'JytzdHIoVlBOKSsnIHJldHVybiddCiB3YXluZXRzPXdheWRyb2lkX25ldHdvcmsoKVsnbmV0d29ya3MnXQogbWFyay5hcHBl'
    'bmQoZidpcCBkYWRkciBAd2F5ZHJvaWRfbmV0d29ya3MgbWV0YSBtYXJrIHNldCB7RElSRUNUfSByZXR1cm4nKQogbWFyay5h'
    'cHBlbmQoZidvaWZuYW1lICJ3YXlkcm9pZDAiIHVkcCBzcG9ydCA2NyB1ZHAgZHBvcnQgNjggbWV0YSBtYXJrIHNldCB7RElS'
    'RUNUfSByZXR1cm4nKQogbmV0cz1kaXJlY3RfbmV0d29ya3MocCxsYW4pCiBpZiBuZXRzOm1hcmsuYXBwZW5kKGYnaXAgZGFk'
    'ZHIge25mdF9zZXQobmV0cyl9IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIGlmIGVuYWJsZWQocCwncG9ydHMn'
    'LCdkaXNjb3ZlcnknKToKICBtYXJrKz1bJ2lwIGRhZGRyIHsgMjI0LjAuMC4yNTEsIDIyNC4wLjAuMjUyLCAyMzkuMjU1LjI1'
    'NS4yNTAgfSB1ZHAgZHBvcnQgeyA1MzUzLCA1MzU1LCAxOTAwIH0gbWV0YSBtYXJrIHNldCAnK3N0cihESVJFQ1QpKycgcmV0'
    'dXJuJ10KIGZvciBkaXJlY3Rpb24gaW4gKCdvdXQnLCdpbicpOgogIGZvciBwcm90byx2YWx1ZXMgaW4gcG9ydHMocCxkaXJl'
    'Y3Rpb24pLml0ZW1zKCk6CiAgIGlmIHZhbHVlczptYXJrLmFwcGVuZCgoJ2N0IGRpcmVjdGlvbiByZXBseSAnIGlmIGRpcmVj'
    'dGlvbj09J2luJyBlbHNlICcnKStmJ3twcm90b30geyJzcG9ydCIgaWYgZGlyZWN0aW9uPT0iaW4iIGVsc2UgImRwb3J0In0g'
    'e25mdF9zZXQodmFsdWVzKX0gbWV0YSBtYXJrIHNldCB7RElSRUNUfSByZXR1cm4nKQogaWYgcFsnd2F5ZHJvaWRfZGlyZWN0'
    'J106CiAgZm9yd2FyZD1bJ2lpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBtYXJrIHNldCAnK3N0'
    'cihESVJFQ1QpKycgY3QgbWFyayBzZXQgJytzdHIoRElSRUNUKSwgJ2N0IGRpcmVjdGlvbiByZXBseSBjdCBtYXJrICcrc3Ry'
    'KERJUkVDVCkrJyBtZXRhIG1hcmsgc2V0ICcrc3RyKERJUkVDVCldCgogZGVmIGxpbmVzKGl0ZW1zKTpyZXR1cm4gJ1xuJy5q'
    'b2luKCcgICcreCBmb3IgeCBpbiBpdGVtcykKIHJldHVybiBmJycndGFibGUgaW5ldCB7dHVubmVsLkZVTExfR1VBUkR9IHt7'
    'CiBzZXQgd2F5ZHJvaWRfbmV0d29ya3Mge3sgdHlwZSBpcHY0X2FkZHI7IGZsYWdzIGludGVydmFsOyB7KCdlbGVtZW50cyA9'
    'ICcrbmZ0X3NldCh3YXluZXRzKSsnOycpIGlmIHdheW5ldHMgZWxzZSAnJ30gfX0KIGNoYWluIHJvdXRlIHt7IHR5cGUgcm91'
    'dGUgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTE1MDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIHNrdWlkIHt1aWR9IHJldHVybgog'
    'IG1ldGEgbWFyayBzZXQgMAogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybgp7bGluZXMobWFyayl9CiB9fQogY2hhaW4g'
    'ZG5zIHt7IHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAgbWV0YSBza3VpZCB7'
    'dWlkfSByZXR1cm4Ke2xpbmVzKGRucyl9CiB9fQogY2hhaW4gcHJlcm91dGUge3sgdHlwZSBmaWx0ZXIgaG9vayBwcmVyb3V0'
    'aW5nIHByaW9yaXR5IC0xNTA7IHBvbGljeSBhY2NlcHQ7CntsaW5lcyhmb3J3YXJkKX0KIH19CiBjaGFpbiB3YXlkcm9pZF9k'
    'bnMge3sgdHlwZSBuYXQgaG9vayBwcmVyb3V0aW5nIHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAgaWlmbmFtZSAi'
    'd2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgZG5h'
    'dCBpcCB0byAxLjEuMS4xCiB9fQogY2hhaW4gc291cmNlIHt7IHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkg'
    'c3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIg'
    'c25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKe2xpbmVzKG5hdCl9CiB9fQogY2hhaW4gb3V0cHV0IHt7IHR5cGUgZmlsdGVyIGhv'
    'b2sgb3V0cHV0IHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAogIG1ldGEgbmZwcm90'
    'byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIG1hcmsge1ZQTn0gbWV0'
    'YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUzIG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0'
    'CiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBza3VpZCB7dWlkfSBtZXRhIG1hcmsge1ZQTn0gb2lmbmFtZSAie3R1bm5lbC5G'
    'VUxMX0hPU1R9IiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7VFVOfSIgYWNjZXB0CiAgaXAgZGFkZHIg'
    'MjU1LjI1NS4yNTUuMjU1IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0'
    'eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7dHVubmVsLkhP'
    'U1R9IiBpcCBzYWRkciB7dHVubmVsLkNMSUVOVH0gaXAgZGFkZHIge3R1bm5lbC5TRVJWRVJ9IHVkcCBkcG9ydCB7dHVubmVs'
    'LklLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBzYWRkciB7dHVubmVsLkNMSUVOVH0gaXAg'
    'ZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIGFjY2VwdAogIGlpZm5hbWUgInt0dW5uZWwuSE9TVH0iIGlwIHNh'
    'ZGRyIHt0dW5uZWwuQ0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCAyNDU3MSBhY2NlcHQKICBpaWZu'
    'YW1lICJ7dHVubmVsLkhPU1R9IiBpcCBzYWRkciB7dHVubmVsLkNMSUVOVH0gaXAgZGFkZHIge3R1bm5lbC5TRVJWRVJ9IHRj'
    'cCBkcG9ydCA4NDQzIGFjY2VwdAogIG9pZm5hbWUgInt0dW5uZWwuSE9TVH0iIGlwIGRhZGRyIHt0dW5uZWwuQ0xJRU5UfSBj'
    'dCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIGlpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlw'
    'djQgbWV0YSBtYXJrIHtESVJFQ1R9IGFjY2VwdAogIG9pZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgY3Qg'
    'c3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7VFVOfSIgYWNj'
    'ZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie1RVTn0iIGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNj'
    'ZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie3R1bm5lbC5GVUxMX0hPU1R9IiBhY2NlcHQKICBtZXRhIG5mcHJv'
    'dG8gaXB2NCBpaWZuYW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0'
    'CiB9fQp9fScnJwoKVU5JVD0nJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gbG9jYWwgYXBwbGljYXRpb24gYW5kIGRv'
    'bWFpbiByb3V0aW5nCkFmdGVyPW5ldHdvcmsudGFyZ2V0CldhbnRzPWV2Z2VuaXVtLXdheWRyb2lkLW5ldHdvcmsuc2Vydmlj'
    'ZQpbU2VydmljZV0KVXNlcj12cG4teHJheQpHcm91cD12cG4teHJheQpFeGVjU3RhcnQ9L29wdC92cG4tbWFuYWdlci9iaW4v'
    'eHJheSBydW4gLWNvbmZpZyAvcnVuL3Zwbi1tYW5hZ2VyL3BvbGljeS5qc29uClJlc3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0'
    'U2VjPTIKQW1iaWVudENhcGFiaWxpdGllcz1DQVBfTkVUX0FETUlOIENBUF9ORVRfUkFXIENBUF9TWVNfUFRSQUNFIENBUF9E'
    'QUNfUkVBRF9TRUFSQ0gKQ2FwYWJpbGl0eUJvdW5kaW5nU2V0PUNBUF9ORVRfQURNSU4gQ0FQX05FVF9SQVcgQ0FQX1NZU19Q'
    'VFJBQ0UgQ0FQX0RBQ19SRUFEX1NFQVJDSApOb05ld1ByaXZpbGVnZXM9dHJ1ZQpQcm90ZWN0U3lzdGVtPXN0cmljdApQcm90'
    'ZWN0SG9tZT10cnVlClByaXZhdGVUbXA9dHJ1ZQpEZXZpY2VBbGxvdz0vZGV2L25ldC90dW4gcncKVU1hc2s9MDA3NwonJycK'
    'CldBWURST0lEX1VOSVQ9JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIFdheWRyb2lkIG5ldHdvcmsgbGlmZWN5Y2xl'
    'CkFmdGVyPWV2Z2VuaXVtLXBvbGljeS5zZXJ2aWNlClBhcnRPZj1ldmdlbml1bS1wb2xpY3kuc2VydmljZQpbU2VydmljZV0K'
    'RXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtd2F5ZHJvaWQtd2F0Y2gKUmVzdGFydD1vbi1mYWls'
    'dXJlClJlc3RhcnRTZWM9MgpVTWFzaz0wMDc3CicnJwoKZGVmIHdheWRyb2lkX25ldHdvcmsoKToKIHJlc3VsdD10dW5uZWwu'
    'Y29tbWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdzaG93JywnZGV2Jywnd2F5ZHJvaWQwJ10sY2hlY2s9RmFsc2UpCiBp'
    'ZiByZXN1bHQucmV0dXJuY29kZTpyZXR1cm4geydpbmRleCc6Tm9uZSwnbmV0d29ya3MnOltdfQogbGlua3M9anNvbi5sb2Fk'
    'cyhyZXN1bHQuc3Rkb3V0KQogbmV0d29ya3M9c29ydGVkKHtzdHIoaXBhZGRyZXNzLmlwX25ldHdvcmsoZiJ7YVsnbG9jYWwn'
    'XX0ve2FbJ3ByZWZpeGxlbiddfSIsc3RyaWN0PUZhbHNlKSkgZm9yIGxpbmsgaW4gbGlua3MgaWYgJ1VQJyBpbiBsaW5rLmdl'
    'dCgnZmxhZ3MnLFtdKSBmb3IgYSBpbiBsaW5rLmdldCgnYWRkcl9pbmZvJyxbXSkgaWYgYS5nZXQoJ3Njb3BlJyk9PSdnbG9i'
    'YWwnfSkKIHJldHVybiB7J2luZGV4JzpsaW5rc1swXS5nZXQoJ2lmaW5kZXgnKSBpZiBsaW5rcyBlbHNlIE5vbmUsJ25ldHdv'
    'cmtzJzpuZXR3b3Jrc30KCmRlZiBzeW5jX3dheWRyb2lkX25ldHdvcmsoZm9yY2U9RmFsc2UpOgogIyBDYWxsZXIgaG9sZHMg'
    'b3BlcmF0aW9uLmxvY2suIE9ubHkgdGhpcyBWUE4ncyBzZXQvdGFibGUgYXJlIG1vZGlmaWVkLgogc3RhdGU9d2F5ZHJvaWRf'
    'bmV0d29yaygpO2NhY2hlPVJVTi8nd2F5ZHJvaWQtbmV0d29yay5qc29uJwogdHJ5OnByZXZpb3VzPWpzb24ubG9hZHMoY2Fj'
    'aGUucmVhZF90ZXh0KCkpCiBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6cHJldmlvdXM9Tm9uZQogaWYgbm90IGZvcmNl'
    'IGFuZCBzdGF0ZT09cHJldmlvdXM6cmV0dXJuCiByb3V0ZXM9anNvbi5sb2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWon'
    'LCctNCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxQSFlTSUNBTF9UQUJMRV0pLnN0ZG91dCkKIHN0YWxlPXtyWydkc3QnXSBm'
    'b3IgciBpbiByb3V0ZXMgaWYgci5nZXQoJ2RldicpPT0nd2F5ZHJvaWQwJyBhbmQgci5nZXQoJ2RzdCcpIG5vdCBpbiBzdGF0'
    'ZVsnbmV0d29ya3MnXX0KIGZvciBuZXR3b3JrIGluIHN0YXRlWyduZXR3b3JrcyddOgogIHR1bm5lbC5jb21tYW5kKFsnaXAn'
    'LCdyb3V0ZScsJ3JlcGxhY2UnLG5ldHdvcmssJ2RldicsJ3dheWRyb2lkMCcsJ3Njb3BlJywnbGluaycsJ3RhYmxlJyxQSFlT'
    'SUNBTF9UQUJMRV0pCiBydWxlcz0nZmx1c2ggc2V0IGluZXQgJyt0dW5uZWwuRlVMTF9HVUFSRCsnIHdheWRyb2lkX25ldHdv'
    'cmtzXG4nCiBpZiBzdGF0ZVsnbmV0d29ya3MnXTpydWxlcys9J2FkZCBlbGVtZW50IGluZXQgJyt0dW5uZWwuRlVMTF9HVUFS'
    'RCsnIHdheWRyb2lkX25ldHdvcmtzICcrbmZ0X3NldChzdGF0ZVsnbmV0d29ya3MnXSkrJ1xuJwogdHVubmVsLmNvbW1hbmQo'
    'WyduZnQnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogZm9yIG5ldHdvcmsgaW4gc3RhbGU6dHVubmVsLmNvbW1hbmQoWydpcCcs'
    'J3JvdXRlJywnZGVsJyxuZXR3b3JrLCdkZXYnLCd3YXlkcm9pZDAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdLGNoZWNrPUZh'
    'bHNlKQogY2FjaGUud3JpdGVfdGV4dChqc29uLmR1bXBzKHN0YXRlKSk7Y2FjaGUuY2htb2QoMG82MDApCgpkZWYgd2F0Y2hf'
    'd2F5ZHJvaWQoKToKIGltcG9ydCBzeXMKIGxhc3RfZXJyb3I9Tm9uZQogd2hpbGUgVHJ1ZToKICB0cnk6CiAgIFJVTi5ta2Rp'
    'cihwYXJlbnRzPVRydWUsZXhpc3Rfb2s9VHJ1ZSkKICAgd2l0aCAoUlVOLydvcGVyYXRpb24ubG9jaycpLm9wZW4oJ2ErJykg'
    'YXMgbG9jazoKICAgIHRyeTpmY250bC5mbG9jayhsb2NrLGZjbnRsLkxPQ0tfRVh8ZmNudGwuTE9DS19OQikKICAgIGV4Y2Vw'
    'dCBCbG9ja2luZ0lPRXJyb3I6cGFzcwogICAgZWxzZToKICAgICBpZiB0dW5uZWwuZnVsbF9ndWFyZF9hY3RpdmUoKSBhbmQg'
    'UGF0aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOnN5bmNfd2F5ZHJvaWRfbmV0d29yaygpCiAgIGxhc3RfZXJy'
    'b3I9Tm9uZQogIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICBtZXNzYWdlPXN0cihleGMpCiAgIGlmIG1lc3NhZ2UhPWxh'
    'c3RfZXJyb3I6cHJpbnQoJ1dheWRyb2lkIG5ldHdvcmsgc3luYzogJyttZXNzYWdlLGZpbGU9c3lzLnN0ZGVycixmbHVzaD1U'
    'cnVlKQogICBsYXN0X2Vycm9yPW1lc3NhZ2UKICB0aW1lLnNsZWVwKDEpCgpkZWYgaW5zdGFsbCgpOgogUGF0aCgnL2V0Yy9z'
    'eXN0ZW1kL3N5c3RlbS8nK1NFUlZJQ0UpLndyaXRlX3RleHQoVU5JVCkKIFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vJytX'
    'QVlEUk9JRF9TRVJWSUNFKS53cml0ZV90ZXh0KFdBWURST0lEX1VOSVQpCiB0dW5uZWwuY29tbWFuZChbJ3N5c3RlbWN0bCcs'
    'J2RhZW1vbi1yZWxvYWQnXSkKCmRlZiBhcHBseSgpOgogcD1sb2FkKCk7c2V0dGluZ3M9YXBpLmxvYWRfc2V0dGluZ3MoKTty'
    'b3V0ZT10dW5uZWwucGh5c2ljYWxfcm91dGUoKTtsYW49bG9jYWxfbmV0d29ya3Mocm91dGUpCiBhcGkuZW5zdXJlX3J1bnRp'
    'bWUoc2V0dGluZ3MpCiBjZmc9UlVOLydwb2xpY3kuanNvbic7dG1wPVJVTi8ncG9saWN5Lm5ldy5qc29uJwogdG1wLndyaXRl'
    'X3RleHQoanNvbi5kdW1wcyhjb25maWcocCkpKTtvcy5jaG1vZCh0bXAsMG82NDApO29zLmNob3duKHRtcCwwLGludChzZXR0'
    'aW5nc1sneHJheV9naWQnXSkpCiBjaGVjaz10dW5uZWwuY29tbWFuZChbYXBpLlhSQVksJ3J1bicsJy10ZXN0JywnLWNvbmZp'
    'ZycsdG1wXSxjaGVjaz1GYWxzZSkKIGlmIGNoZWNrLnJldHVybmNvZGU6cmFpc2UgUnVudGltZUVycm9yKCfQntCx0YDQsNCx'
    '0L7RgtGH0LjQuiDQuNGB0LrQu9GO0YfQtdC90LjQuSDQvdC1INC/0YDQuNC90Y/QuyDQvdCw0YHRgtGA0L7QudC60LguJykK'
    'IHJ1bGVzPWZpcmV3YWxsKHAsbGFuLGludChzZXR0aW5nc1sneHJheV91aWQnXSkpCiByZXBsYWNlbWVudD0oJ2RlbGV0ZSB0'
    'YWJsZSBpbmV0ICcrdHVubmVsLkZVTExfR1VBUkQrJ1xuJyBpZiB0dW5uZWwuZnVsbF9ndWFyZF9hY3RpdmUoKSBlbHNlICcn'
    'KStydWxlcwogdHVubmVsLmNvbW1hbmQoWyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiBvd25lcnNo'
    'aXA9UEFUSC53aXRoX25hbWUoJ3BvbGljeS1uZXR3b3JrLmpzb24nKQogaWYgbm90IG93bmVyc2hpcC5leGlzdHMoKToKICBm'
    'b3IgdGFibGUgaW4gKFBIWVNJQ0FMX1RBQkxFLFZQTl9UQUJMRSk6CiAgIGlmIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0'
    'ZScsJ3Nob3cnLCd0YWJsZScsdGFibGVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKTpyYWlzZSBSdW50aW1lRXJyb3Io'
    'J9Ci0LDQsdC70LjRhtCwINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4INC40YHQutC70Y7Rh9C10L3QuNC5INC30LDQvdGP'
    '0YLQsCDQtNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykKICBleGlzdGluZz1qc29uLmxvYWRzKHR1bm5lbC5j'
    'b21tYW5kKFsnaXAnLCctaicsJy00JywncnVsZSddKS5zdGRvdXQpCiAgaWYgYW55KHIuZ2V0KCdwcmlvcml0eScpIGluICg3'
    'Niw3Nyw3OCkgZm9yIHIgaW4gZXhpc3RpbmcpOnJhaXNlIFJ1bnRpbWVFcnJvcign0J/RgNC40L7RgNC40YLQtdGC0Ysg0LzQ'
    'sNGA0YjRgNGD0YLQuNC30LDRhtC40Lgg0LjRgdC60LvRjtGH0LXQvdC40Lkg0LfQsNC90Y/RgtGLINC00YDRg9Cz0L7QuSDQ'
    'v9GA0L7Qs9GA0LDQvNC80L7QuS4nKQogIHR1bm5lbC53cml0ZShvd25lcnNoaXAsanNvbi5kdW1wcyh7J3RhYmxlcyc6W1BI'
    'WVNJQ0FMX1RBQkxFLFZQTl9UQUJMRV19KSkKICMgQnVpbGQgcGh5c2ljYWwgYW5kIFZQTi1vbmx5IHRhYmxlcyBiZWZvcmUg'
    'YWxsb3dpbmcgYW55IG5ldyBtYXJrcy4KIGZvciB0YWJsZSBpbiAoUEhZU0lDQUxfVEFCTEUsVlBOX1RBQkxFKToKICB0dW5u'
    'ZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywndW5yZWFjaGFibGUnLCdkZWZhdWx0JywnbWV0cmljJywnMzI3'
    'NjAnLCd0YWJsZScsdGFibGVdKQogZm9yIG5ldHdvcmsgaW4gbGFuK1snMTY5LjI1NC4wLjAvMTYnLCcyMjQuMC4wLjAvNCdd'
    'OgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLG5ldHdvcmssJ2Rldicscm91dGVbJ2RldiddLCdz'
    'Y29wZScsJ2xpbmsnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVw'
    'bGFjZScsJ2RlZmF1bHQnLCd2aWEnLHJvdXRlWydnYXRld2F5J10sJ2Rldicscm91dGVbJ2RldiddLCdtZXRyaWMnLCcxMCcs'
    'J3RhYmxlJyxQSFlTSUNBTF9UQUJMRV0pCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVs'
    'dCcsJ3ZpYScsJzE3Mi4yOS4yNDcuMicsJ2RldicsdHVubmVsLkZVTExfSE9TVCwnbWV0cmljJywnMTAnLCd0YWJsZScsVlBO'
    'X1RBQkxFXSkKIGZvciBwcmlvcml0eSxtYXJrLHRhYmxlIGluIFsoNzYsRElSRUNULFBIWVNJQ0FMX1RBQkxFKSwoNzcsVlBO'
    'LFZQTl9UQUJMRSldOgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLHByaW9yaXR5LCdm'
    'd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0sY2hlY2s9RmFsc2UpCiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3J1'
    'bGUnLCdhZGQnLCdwcmlvcml0eScscHJpb3JpdHksJ2Z3bWFyaycsc3RyKG1hcmspLCdsb29rdXAnLHRhYmxlXSkKICMgUmVw'
    'bGllcyB0byBhIGZvcndhcmRlZCBjb250YWluZXIgcmV0dXJuIHRocm91Z2ggaXRzIGNvbm5lY3RlZCBtYWluIHJvdXRlLgog'
    'dHVubmVsLmNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc4JywnaWlmJyxUVU4sJ2xvb2t1cCcsJ21h'
    'aW4nXSxjaGVjaz1GYWxzZSkKIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc3OCcsJ2lp'
    'ZicsVFVOLCdsb29rdXAnLCdtYWluJ10pCiAjIEEgdGVtcG9yYXJ5IGNsb3NlZCBzdGF0ZSBpcyBhY2NlcHRhYmxlOyBhbiB1'
    'bmd1YXJkZWQgc3RhdGUgaXMgbm90Lgogb3MucmVwbGFjZSh0bXAsY2ZnKQogdHVubmVsLndyaXRlKHR1bm5lbC5ST09ULydm'
    'dWxsLWd1YXJkLm5mdCcscnVsZXMpCiB0dW5uZWwuY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQp'
    'CiBzeW5jX3dheWRyb2lkX25ldHdvcmsoZm9yY2U9VHJ1ZSkKIGluc3RhbGwoKQogdHVubmVsLmNvbW1hbmQoWydzeXN0ZW1j'
    'dGwnLCdyZXN0YXJ0JyxTRVJWSUNFXSkKIGZvciBfIGluIHJhbmdlKDgwKToKICBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8n'
    'K1RVTikuZXhpc3RzKCk6YnJlYWsKICB0aW1lLnNsZWVwKC4xKQogZWxzZTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LUg0YPQ'
    'tNCw0LvQvtGB0Ywg0LfQsNC/0YPRgdGC0LjRgtGMINC+0LHRgNCw0LHQvtGC0YfQuNC6INC40YHQutC70Y7Rh9C10L3QuNC5'
    'LicpCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ2RldicsVFVOLCdtZXRyaWMn'
    'LCcxMCcsJ3RhYmxlJyx0dW5uZWwuRlVMTF9UQUJMRV0pCiB0dW5uZWwuY2xlYXJfZG5zX21hcHBpbmdzKCkKICMgRXhwbGlj'
    'aXRseSByZXF1ZXN0ZWQgRE5TIGV4Y2VwdGlvbnMgbmVlZCBzdGFsZSBwb3J0LTUzIG1hcHBpbmdzIHJlbW92ZWQgdG9vLgog'
    'Zm9yIHByb3RvIGluICgndWRwJywndGNwJyk6CiAgdHVubmVsLmNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2'
    'NCcsJy1wJyxwcm90bywnLS1kcG9ydCcsJzUzJywnLS1yZXBseS1wb3J0LXNyYycsc3RyKEROU19QT1JUKV0sY2hlY2s9RmFs'
    'c2UpCgoKZGVmIHN0b3AocmVsZWFzZT1GYWxzZSk6CiB0dW5uZWwuY29tbWFuZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLFNFUlZJ'
    'Q0VdLGNoZWNrPUZhbHNlKQogaWYgcmVsZWFzZSBhbmQgUEFUSC53aXRoX25hbWUoJ3BvbGljeS1uZXR3b3JrLmpzb24nKS5l'
    'eGlzdHMoKToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwn'
    'bG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogIGZvciBwcmlvcml0eSxtYXJrLHRhYmxlIGluIFsoNzYsRElSRUNULFBI'
    'WVNJQ0FMX1RBQkxFKSwoNzcsVlBOLFZQTl9UQUJMRSldOgogICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcs'
    'J3ByaW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogICB0'
    'dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdmbHVzaCcsJ3RhYmxlJyx0YWJsZV0sY2hlY2s9RmFsc2UpCiAgUEFUSC53'
    'aXRoX25hbWUoJ3BvbGljeS1uZXR3b3JrLmpzb24nKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQoKCmRlZiBjaGFuZ2UoYWN0'
    'aW9uLGNhdGVnb3J5PScnLHZhbHVlPScnLHN0YXRlPU5vbmUpOgogb2xkPWxvYWQoKTtwPWpzb24ubG9hZHMoanNvbi5kdW1w'
    'cyhvbGQpKQogaWYgYWN0aW9uPT0nd2F5ZHJvaWQnOnBbJ3dheWRyb2lkX2RpcmVjdCddPWJvb2woc3RhdGUpCiBlbGlmIGFj'
    'dGlvbj09J2Jhc2UnOgogIGlmIGNhdGVnb3J5IG5vdCBpbiBCQVNFIG9yIHZhbHVlIG5vdCBpbiB7ZVsnaWQnXSBmb3IgZSBp'
    'biBCQVNFW2NhdGVnb3J5XX06cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC90L7QtSDQsdCw0LfQvtCy0L7Q'
    'tSDQv9GA0LDQstC40LvQvi4nKQogIGtleT1jYXRlZ29yeSsnOicrdmFsdWUKICBwWydkaXNhYmxlZF9iYXNlJ109W3ggZm9y'
    'IHggaW4gcFsnZGlzYWJsZWRfYmFzZSddIGlmIHghPWtleV0KICBpZiBub3Qgc3RhdGU6cFsnZGlzYWJsZWRfYmFzZSddLmFw'
    'cGVuZChrZXkpCiBlbGlmIGFjdGlvbiBpbiAoJ2FkZCcsJ3JlbW92ZScpOgogIGlmIGNhdGVnb3J5IG5vdCBpbiBDQVRFR09S'
    'SUVTOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdCw0Y8g0LrQsNGC0LXQs9C+0YDQuNGPLicpCiAgdmFs'
    'dWU9bm9ybWFsaXplKGNhdGVnb3J5LHZhbHVlKQogIGlmIGFjdGlvbj09J2FkZCcgYW5kIHZhbHVlIG5vdCBpbiBwW2NhdGVn'
    'b3J5XTpwW2NhdGVnb3J5XS5hcHBlbmQodmFsdWUpCiAgaWYgYWN0aW9uPT0ncmVtb3ZlJzpwW2NhdGVnb3J5XT1beCBmb3Ig'
    'eCBpbiBwW2NhdGVnb3J5XSBpZiB4IT12YWx1ZV0KIGVsc2U6cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC9'
    '0L7QtSDQtNC10LnRgdGC0LLQuNC1LicpCiBpZiBwPT1vbGQ6cmV0dXJuIHB1YmxpYygpCiBzYXZlKHApCiBpZiB0dW5uZWwu'
    'ZnVsbF9ndWFyZF9hY3RpdmUoKSBhbmQgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJyt0dW5uZWwuRlVMTF9IT1NUKS5leGlzdHMo'
    'KToKICB0cnk6YXBwbHkoKQogIGV4Y2VwdCBFeGNlcHRpb246CiAgIHNhdmUob2xkKQogICB0cnk6YXBwbHkoKQogICBleGNl'
    'cHQgRXhjZXB0aW9uOnBhc3MKICAgcmFpc2UKIHJldHVybiBwdWJsaWMoKQoKZGVmIGVuc3VyZV9yb3V0ZSgpOgogaWYgUGF0'
    'aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxh'
    'Y2UnLCdkZWZhdWx0JywnZGV2JyxUVU4sJ21ldHJpYycsJzEwJywndGFibGUnLHR1bm5lbC5GVUxMX1RBQkxFXSkKIGVsc2U6'
    'cmFpc2UgUnVudGltZUVycm9yKCdwb2xpY3lfZW5naW5lX3VuYXZhaWxhYmxlJykK'
)

import types

def embedded(name,source):
 module=types.ModuleType(name)
 exec(compile(base64.b64decode(source),name+'.py','exec'),module.__dict__)
 return module

SUPPORT_REPORTS_PY_B64 = (
    'IiIiT3B0LWluIGRpYWdub3N0aWMgcmVwb3J0czogc3RyaWN0IGFsbG93bGlzdCwgbm8gcmF3IGxvZ3MsIGlkZW50aXRpZXMg'
    'b3Igc2VjcmV0cy4iIiIKaW1wb3J0IGpzb24sbWF0aCxwbGF0Zm9ybSxyZSxzZWNyZXRzLHRpbWUsc3VicHJvY2Vzcwpmcm9t'
    'IHBhdGhsaWIgaW1wb3J0IFBhdGgKUEhBU0VTPXsnb2ZmJywncHJlcGFyZScsJ3Rva2VuJywnZGFlbW9uJywnaGFuZHNoYWtl'
    'JywnaGVhbHRoJywnbWVhc3VyZScsJ3JvdXRpbmcnLCdjb25uZWN0ZWQnLCdjaGVja2luZycsJ3JlcGFpcmluZycsJ2ZhaWxl'
    'ZCcsJ3JhbmtpbmcnLCdyZWZlcmVuY2UnLCdzdGFydGluZycsJ2ludGVycnVwdGVkJywnZWdyZXNzX3dhaXQnfQpDT0RFUz17'
    'JycsJ25vbmUnLCdvdGhlcicsJ2Nvbm5lY3Rpb25fZmFpbGVkJywncGF0aF9oZWFsdGhfZmFpbGVkJywnY29uZmlybWVkX3Nw'
    'ZWVkX2Ryb3AnLCdyYW5raW5nX2V4aGF1c3RlZCcsJ3N5c3RlbV9kbnNfZmFpbGVkJywncHJpdmF0ZV9kbnNfc3RvcHBlZCcs'
    'J3ByaXZhdGVfZG5zX25vdF9yZWFkeScsJ2hhbmRzaGFrZV9mYWlsZWQnLCdlc3RvbmlhX2VncmVzc19mYWlsZWQnLCdob3N0'
    'X2VncmVzc19mYWlsZWQnLCdlbnJvbGxtZW50X3VuYXZhaWxhYmxlJywnaW50ZWdyaXR5X2ZhaWxlZCcsJ3NhX25vdF9pbnN0'
    'YWxsZWQnLCdoZWFsdGhfZmFpbGVkJywnY29tbWFuZF9mYWlsZWQnLCd0bHNfY2Fycmllcl9zdG9wcGVkJywndGxzX2NhcnJp'
    'ZXJfbm90X3JlYWR5J30KUEFUSFM9eydydS11ZHAnLCdlZS11ZHAnLCdlZS10bHMnLCcnfQpYRlJNPXsnWGZybUluRXJyb3In'
    'LCdYZnJtSW5Ob1N0YXRlcycsJ1hmcm1JblN0YXRlUHJvdG9FcnJvcicsJ1hmcm1JblN0YXRlU2VxRXJyb3InLCdYZnJtSW5T'
    'dGF0ZUV4cGlyZWQnLCdYZnJtSW5TdGF0ZU1pc21hdGNoJywnWGZybUluVG1wbE1pc21hdGNoJywnWGZybUluTm9Qb2xzJywn'
    'WGZybUluUG9sQmxvY2snLCdYZnJtT3V0RXJyb3InLCdYZnJtT3V0Tm9TdGF0ZXMnLCdYZnJtT3V0U3RhdGVFeHBpcmVkJywn'
    'WGZybU91dFBvbEJsb2NrJ30KTlVNQkVSUz1YRlJNfHsnZG93bmxvYWRfbWJwcycsJ3VwbG9hZF9tYnBzJywnbGF0ZW5jeV9t'
    'cycsJ3Njb3JlJywnbG9zc2VzJywnc2FtcGxlX2J5dGVzJywncnhfYnl0ZXMnLCd0eF9ieXRlcycsJ3J4X3BhY2tldHMnLCd0'
    'eF9wYWNrZXRzJywncnhfZXJyb3JzJywndHhfZXJyb3JzJywncnhfZHJvcHBlZCcsJ3R4X2Ryb3BwZWQnfQpkZWYgbnVtYmVy'
    'KHYpOgogaWYgdHlwZSh2KSBub3QgaW4gKGludCxmbG9hdCkgb3Igbm90IG1hdGguaXNmaW5pdGUodikgb3Igbm90IDA8PXY8'
    'PTIqKjYzOnJhaXNlIFZhbHVlRXJyb3IoJ21ldHJpYycpCiByZXR1cm4gcm91bmQodiwzKSBpZiBpc2luc3RhbmNlKHYsZmxv'
    'YXQpIGVsc2UgdgoKZGVmIGNsZWFuX2J1bmRsZShib2R5KToKIGlmIG5vdCBpc2luc3RhbmNlKGJvZHksZGljdCkgb3IgYm9k'
    'eS5nZXQoJ3NjaGVtYScpIT0xIG9yIGJvZHkuZ2V0KCdldmVudCcpIT0nc3VwcG9ydF9idW5kbGUnIG9yIGJvZHkuZ2V0KCdj'
    'b25zZW50JykgaXMgbm90IFRydWU6cmFpc2UgVmFsdWVFcnJvcignY29uc2VudCcpCiBpZiBub3QgcmUuZnVsbG1hdGNoKCdb'
    'YS1mMC05XXszMn0nLHN0cihib2R5LmdldCgncmVwb3J0X2lkJywnJykpKTpyYWlzZSBWYWx1ZUVycm9yKCdyZXBvcnRfaWQn'
    'KQogdmVyc2lvbj1ib2R5LmdldCgnbWFuYWdlcicsJycpCiBpZiBub3QgaXNpbnN0YW5jZSh2ZXJzaW9uLHN0cikgb3Igbm90'
    'IHJlLmZ1bGxtYXRjaChyJ1xkK1wuXGQrXC5cZCsnLHZlcnNpb24pOnJhaXNlIFZhbHVlRXJyb3IoJ3ZlcnNpb24nKQogaWYg'
    'Ym9keS5nZXQoJ2FyY2hpdGVjdHVyZScpIG5vdCBpbiB7J3g4Nl82NCcsJ2FhcmNoNjQnLCdyaXNjdjY0Jywnb3RoZXInfTpy'
    'YWlzZSBWYWx1ZUVycm9yKCdhcmNoaXRlY3R1cmUnKQogaWYgYm9keS5nZXQoJ3N5c3RlbScpIG5vdCBpbiB7J2FyY2gnLCdl'
    'bmRlYXZvdXJvcycsJ2ZlZG9yYScsJ3N0ZWFtb3MnLCdkZWJpYW4nLCd1YnVudHUnLCdvdGhlcid9OnJhaXNlIFZhbHVlRXJy'
    'b3IoJ3N5c3RlbScpCiByZXN1bHQ9e2s6Ym9keVtrXSBmb3IgayBpbiAoJ3NjaGVtYScsJ2V2ZW50JywnY29uc2VudCcsJ3Jl'
    'cG9ydF9pZCcsJ21hbmFnZXInLCdhcmNoaXRlY3R1cmUnLCdzeXN0ZW0nKX0KIHJlc3VsdFsndGltZSddPW51bWJlcihib2R5'
    'LmdldCgndGltZScsMCkpCiBldmVudHM9Ym9keS5nZXQoJ2V2ZW50cycsW10pCiBpZiBub3QgaXNpbnN0YW5jZShldmVudHMs'
    'bGlzdCkgb3IgbGVuKGV2ZW50cyk+MTI4OnJhaXNlIFZhbHVlRXJyb3IoJ2V2ZW50cycpCiByZXN1bHRbJ2V2ZW50cyddPVtd'
    'CiBmb3IgaXRlbSBpbiBldmVudHM6CiAgaWYgbm90IGlzaW5zdGFuY2UoaXRlbSxkaWN0KSBvciBpdGVtLmdldCgncGhhc2Un'
    'KSBub3QgaW4gUEhBU0VTIG9yIGl0ZW0uZ2V0KCdjb2RlJywnJykgbm90IGluIENPREVTIG9yIGl0ZW0uZ2V0KCdwYXRoJywn'
    'Jykgbm90IGluIFBBVEhTOnJhaXNlIFZhbHVlRXJyb3IoJ2V2ZW50JykKICByZXN1bHRbJ2V2ZW50cyddLmFwcGVuZCh7J3Rp'
    'bWUnOm51bWJlcihpdGVtWyd0aW1lJ10pLCdwaGFzZSc6aXRlbVsncGhhc2UnXSwnY29kZSc6aXRlbS5nZXQoJ2NvZGUnLCcn'
    'KSwncGF0aCc6aXRlbS5nZXQoJ3BhdGgnLCcnKSwnYWN0aXZlJzppdGVtLmdldCgnYWN0aXZlJykgaXMgVHJ1ZX0pCiBzdGF0'
    'ZT1ib2R5LmdldCgnc3RhdGUnLHt9KQogaWYgbm90IGlzaW5zdGFuY2Uoc3RhdGUsZGljdCk6cmFpc2UgVmFsdWVFcnJvcign'
    'c3RhdGUnKQogcmVzdWx0WydzdGF0ZSddPXtrOnN0YXRlLmdldChrKSBpcyBUcnVlIGZvciBrIGluICgnYWN0aXZlJywnZ3Vh'
    'cmQnLCduYW1lc3BhY2UnLCdkbnNfZmFsbGJhY2snKX0KIHJlc3VsdFsncGF0aHMnXT17fQogcGF0aHM9Ym9keS5nZXQoJ3Bh'
    'dGhzJyx7fSkKIGlmIG5vdCBpc2luc3RhbmNlKHBhdGhzLGRpY3QpIG9yIGxlbihwYXRocyk+MzpyYWlzZSBWYWx1ZUVycm9y'
    'KCdwYXRocycpCiBmb3IgbmFtZSx2YWx1ZXMgaW4gcGF0aHMuaXRlbXMoKToKICBpZiBuYW1lIG5vdCBpbiBQQVRIUy17Jyd9'
    'OnJhaXNlIFZhbHVlRXJyb3IoJ3BhdGgnKQogIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVlcyxkaWN0KTpyYWlzZSBWYWx1ZUVy'
    'cm9yKCdwYXRoJykKICByZXN1bHRbJ3BhdGhzJ11bbmFtZV09e2s6bnVtYmVyKHYpIGZvciBrLHYgaW4gdmFsdWVzLml0ZW1z'
    'KCkgaWYgayBpbiBOVU1CRVJTfQogY291bnRlcnM9Ym9keS5nZXQoJ2NvdW50ZXJzJyx7fSkKIGlmIG5vdCBpc2luc3RhbmNl'
    'KGNvdW50ZXJzLGRpY3QpOnJhaXNlIFZhbHVlRXJyb3IoJ2NvdW50ZXJzJykKIHJlc3VsdFsnY291bnRlcnMnXT17azpudW1i'
    'ZXIodikgZm9yIGssdiBpbiBjb3VudGVycy5pdGVtcygpIGlmIGsgaW4gTlVNQkVSU30KIHJldHVybiByZXN1bHQKCmRlZiBy'
    'ZWNvcmQocm9vdCx3cml0ZSxkYXRhKToKIGV2ZW50PXsndGltZSc6aW50KHRpbWUudGltZSgpKSwncGhhc2UnOmRhdGEuZ2V0'
    'KCdwaGFzZScpIGlmIGRhdGEuZ2V0KCdwaGFzZScpIGluIFBIQVNFUyBlbHNlICdmYWlsZWQnLAogICAgICAgICdjb2RlJzpk'
    'YXRhLmdldCgnZXJyb3JfY29kZScsJycpIGlmIGRhdGEuZ2V0KCdlcnJvcl9jb2RlJywnJykgaW4gQ09ERVMgZWxzZSAnb3Ro'
    'ZXInLAogICAgICAgICdwYXRoJzpkYXRhLmdldCgncGF0aCcsJycpIGlmIGRhdGEuZ2V0KCdwYXRoJywnJykgaW4gUEFUSFMg'
    'ZWxzZSAnJywgJ2FjdGl2ZSc6ZGF0YS5nZXQoJ2FjdGl2ZScpIGlzIFRydWV9CiBwYXRoPXJvb3QvJ2V2ZW50cy5qc29uJwog'
    'dHJ5OmV2ZW50cz1qc29uLmxvYWRzKHBhdGgucmVhZF90ZXh0KCkpCiBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6ZXZl'
    'bnRzPVtdCiBpZiBub3QgZXZlbnRzIG9yIGFueShldmVudHNbLTFdLmdldChrKSE9ZXZlbnRba10gZm9yIGsgaW4gKCdwaGFz'
    'ZScsJ2NvZGUnLCdwYXRoJywnYWN0aXZlJykpOgogIHdyaXRlKHBhdGgsanNvbi5kdW1wcygoZXZlbnRzK1tldmVudF0pWy0x'
    'Mjg6XSkpCgpkZWYgcHJlcGFyZSh0dW5uZWwsdmVyc2lvbik6CiB0cnk6ZXZlbnRzPWpzb24ubG9hZHMoKHR1bm5lbC5ST09U'
    'LydldmVudHMuanNvbicpLnJlYWRfdGV4dCgpKQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOmV2ZW50cz1bXQogdHJ5'
    'OnBhdGhzPWpzb24ubG9hZHMoKHR1bm5lbC5ST09ULydyYW5raW5nLmpzb24nKS5yZWFkX3RleHQoKSlbJ2VudHJpZXMnXQog'
    'ZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsS2V5RXJyb3IpOnBhdGhzPXt9CiB0cnk6bmV0d29yaz1qc29uLmxvYWRzKHR1'
    'bm5lbC5mdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6bmV0d29yaz17fQog'
    'dHJ5OnN5c3RlbT1wbGF0Zm9ybS5mcmVlZGVza3RvcF9vc19yZWxlYXNlKCkuZ2V0KCdJRCcsJ290aGVyJykKIGV4Y2VwdCBP'
    'U0Vycm9yOnN5c3RlbT0nb3RoZXInCiBpZiBzeXN0ZW0gbm90IGluIHsnYXJjaCcsJ2VuZGVhdm91cm9zJywnZmVkb3JhJywn'
    'c3RlYW1vcycsJ2RlYmlhbicsJ3VidW50dSd9OnN5c3RlbT0nb3RoZXInCiBhcmNoPXBsYXRmb3JtLm1hY2hpbmUoKTthcmNo'
    'PWFyY2ggaWYgYXJjaCBpbiB7J3g4Nl82NCcsJ2FhcmNoNjQnLCdyaXNjdjY0J30gZWxzZSAnb3RoZXInCiBjb3VudGVycz17'
    'fQogIyBPbmx5IHRoZSBWUE4ncyBvd24gaW50ZXJmYWNlLCBubyBwcm9jZXNzIGxpc3Qgb3IgcmVtb3RlIGFkZHJlc3Nlcy4K'
    'IHN0YXRzPVBhdGgoJy9zeXMvY2xhc3MvbmV0JykvdHVubmVsLkZVTExfSE9TVC8nc3RhdGlzdGljcycKIGZvciBrZXkgaW4g'
    'KCdyeF9ieXRlcycsJ3R4X2J5dGVzJywncnhfcGFja2V0cycsJ3R4X3BhY2tldHMnLCdyeF9lcnJvcnMnLCd0eF9lcnJvcnMn'
    'LCdyeF9kcm9wcGVkJywndHhfZHJvcHBlZCcpOgogIHRyeTpjb3VudGVyc1trZXldPWludCgoc3RhdHMva2V5KS5yZWFkX3Rl'
    'eHQoKSkKICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6cGFzcwogaWYgUGF0aCgnL3J1bi9uZXRucycsdHVubmVsLk5T'
    'KS5leGlzdHMoKToKICB0cnk6CiAgIHJlc3VsdD10dW5uZWwuaW5zaWRlKFsnY2F0JywnL3Byb2MvbmV0L3hmcm1fc3RhdCdd'
    'LGNoZWNrPUZhbHNlLHRpbWVvdXQ9MikKICAgZm9yIGxpbmUgaW4gcmVzdWx0LnN0ZG91dC5zcGxpdGxpbmVzKCk6CiAgICBr'
    'ZXksdmFsdWU9bGluZS5zcGxpdCgpCiAgICBpZiBrZXkgaW4gWEZSTTpjb3VudGVyc1trZXldPWludCh2YWx1ZSkKICBleGNl'
    'cHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6cGFzcwogcmVw'
    'b3J0PWNsZWFuX2J1bmRsZSh7J3NjaGVtYSc6MSwnZXZlbnQnOidzdXBwb3J0X2J1bmRsZScsJ2NvbnNlbnQnOlRydWUsJ3Jl'
    'cG9ydF9pZCc6c2VjcmV0cy50b2tlbl9oZXgoMTYpLAogICAnbWFuYWdlcic6dmVyc2lvbiwndGltZSc6aW50KHRpbWUudGlt'
    'ZSgpKSwnYXJjaGl0ZWN0dXJlJzphcmNoLCdzeXN0ZW0nOnN5c3RlbSwnZXZlbnRzJzpldmVudHMsCiAgICdwYXRocyc6cGF0'
    'aHMsJ2NvdW50ZXJzJzpjb3VudGVycywnc3RhdGUnOnsnYWN0aXZlJzp0dW5uZWwuc2F2ZWQoKS5nZXQoJ2FjdGl2ZScsRmFs'
    'c2UpLAogICAgJ2d1YXJkJzp0dW5uZWwuZnVsbF9ndWFyZF9hY3RpdmUoKSwnbmFtZXNwYWNlJzpQYXRoKCcvcnVuL25ldG5z'
    'Jyx0dW5uZWwuTlMpLmV4aXN0cygpLCdkbnNfZmFsbGJhY2snOm5ldHdvcmsuZ2V0KCdkbnNfZmFsbGJhY2snLEZhbHNlKX19'
    'KQogIyBQcmVwYXJpbmcgYSBwcmV2aWV3IGlzIG5ldmVyIHBlcm1pc3Npb24gdG8gdHJhbnNtaXQgaXQuCiByZXBvcnRbJ2Nv'
    'bnNlbnQnXT1GYWxzZQogdHVubmVsLndyaXRlKHR1bm5lbC5ST09ULydzdXBwb3J0LXByZXZpZXcuanNvbicsanNvbi5kdW1w'
    'cyhyZXBvcnQsZW5zdXJlX2FzY2lpPUZhbHNlLGluZGVudD0yKSkKIHJldHVybiByZXBvcnQKCmRlZiBzZW5kKHR1bm5lbCxy'
    'ZXBvcnRfaWQsY29uc2VudCk6CiBpZiBjb25zZW50IGlzIG5vdCBUcnVlOnJhaXNlIFZhbHVlRXJyb3IoJ9CU0LvRjyDQvtGC'
    '0L/RgNCw0LLQutC4INGC0YDQtdCx0YPQtdGC0YHRjyDRj9Cy0L3QvtC1INGB0L7Qs9C70LDRgdC40LUuJykKIHJlcG9ydD1q'
    'c29uLmxvYWRzKCh0dW5uZWwuUk9PVC8nc3VwcG9ydC1wcmV2aWV3Lmpzb24nKS5yZWFkX3RleHQoKSkKIGlmIHJlcG9ydC5n'
    'ZXQoJ3JlcG9ydF9pZCcpIT1yZXBvcnRfaWQgb3IgdGltZS50aW1lKCktcmVwb3J0LmdldCgndGltZScsMCk+ODY0MDA6cmFp'
    'c2UgVmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00LPQvtGC0L7QstGM0YLQtSDQvdC+0LLRi9C5INC+0YLRh9GR'
    '0YIuJykKIHJlcG9ydFsnY29uc2VudCddPVRydWU7cmVwb3J0PWNsZWFuX2J1bmRsZShyZXBvcnQpCiAjIE5ldmVyIGluc3Rh'
    'bGwgYSBieXBhc3MgYXJvdW5kIGFuIGFjdGl2ZSBraWxsIHN3aXRjaCB0byB1cGxvYWQgYSByZXBvcnQuCiBpZiBQYXRoKCcv'
    'cnVuL25ldG5zJyx0dW5uZWwuTlMpLmV4aXN0cygpIGFuZCB0dW5uZWwuaW5zdGFsbGVkKCk6CiAgdHJ5OnNlbGVjdGVkPWpz'
    'b24ubG9hZHMoKHR1bm5lbC5ST09ULydhY3RpdmUtcGF0aC5qc29uJykucmVhZF90ZXh0KCkpWydpZCddCiAgZXhjZXB0IChP'
    'U0Vycm9yLFZhbHVlRXJyb3IsS2V5RXJyb3IpOnNlbGVjdGVkPSdydS11ZHAnCiAgY2FuZGlkYXRlPW5leHQoeCBmb3IgeCBp'
    'biB0dW5uZWwuQ0FORElEQVRFUyBpZiB4WydpZCddPT1zZWxlY3RlZCkKICB3aXRoIHR1bm5lbC5uYW1lc3BhY2UoKTpyZXBs'
    'eT10dW5uZWwudGxzX3JlcXVlc3QodHVubmVsLkhFQUxUSCwnL3JlcG9ydCcscmVwb3J0LGNsaWVudD1UcnVlLGlkZW50aXR5'
    'PWNhbmRpZGF0ZVsnaWRlbnRpdHknXSkKIGVsaWYgbm90IHR1bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpOgogIHJlcGx5PXR1'
    'bm5lbC50bHNfcmVxdWVzdCh0dW5uZWwuU0VSVkVSLCcvcmVwb3J0JyxyZXBvcnQsY2xpZW50PVRydWUpCiBlbHNlOnJhaXNl'
    'IFJ1bnRpbWVFcnJvcign0JfQsNGJ0LjRgtCwINCx0LvQvtC60LjRgNGD0LXRgiDRgdC10YLRjC4g0J7RgtGH0ZHRgiDRgdC+'
    '0YXRgNCw0L3RkdC9OyDQvtGC0L/RgNCw0LLRjNGC0LUg0L/QvtGB0LvQtSDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNGP'
    'INC40LvQuCDRj9Cy0L3QvtCz0L4g0L7RgtC60LvRjtGH0LXQvdC40Y8gVlBOLicpCiBpZiByZXBseS5nZXQoJ2FjY2VwdGVk'
    'JykgaXMgbm90IFRydWUgb3IgcmVwbHkuZ2V0KCdyZXBvcnRfaWQnKSE9cmVwb3J0X2lkOnJhaXNlIFJ1bnRpbWVFcnJvcign'
    '0KHQtdGA0LLQtdGAINC90LUg0L/QvtC00YLQstC10YDQtNC40Lsg0L/QvtC70YPRh9C10L3QuNC1INC+0YLRh9GR0YLQsC4n'
    'KQogcmV0dXJuIHJlcG9ydF9pZAo='
)
PATH_RANKING_PY_B64 = (
    'IiIiUGVyc2lzdGVudCBjYW5kaWRhdGUgb3JkZXIuIExvc3NlcyBzdXJ2aXZlIHN1Y2Nlc3Nlcy9yZXN0YXJ0cyB1bnRpbCBl'
    'eHBsaWNpdCByZXBhaXIuIiIiCmltcG9ydCBqc29uLG1hdGgsb3MsdGltZQpmcm9tIHBhdGhsaWIgaW1wb3J0IFBhdGgKY2xh'
    'c3MgUmFua2luZzoKIGRlZiBfX2luaXRfXyhzZWxmLHBhdGgsaWRzKTpzZWxmLnBhdGg9UGF0aChwYXRoKTtzZWxmLmlkcz10'
    'dXBsZShpZHMpO3NlbGYuZGF0YT1Ob25lCiBkZWYgbG9hZChzZWxmKToKICB0cnk6CiAgIHZhbHVlPWpzb24ubG9hZHMoc2Vs'
    'Zi5wYXRoLnJlYWRfdGV4dCgpKQogICBpZiBub3QgaXNpbnN0YW5jZSh2YWx1ZSxkaWN0KTpyZXR1cm4gRmFsc2UKICAgaWYg'
    'dmFsdWUuZ2V0KCdzY2hlbWEnKSE9MSBvciBzZXQodmFsdWUuZ2V0KCdlbnRyaWVzJyx7fSkpIT1zZXQoc2VsZi5pZHMpOnJl'
    'dHVybiBGYWxzZQogICBpZiBzb3J0ZWQodmFsdWUuZ2V0KCdvcmRlcicsW10pKSE9c29ydGVkKHNlbGYuaWRzKTpyZXR1cm4g'
    'RmFsc2UKICAgZm9yIGUgaW4gdmFsdWVbJ2VudHJpZXMnXS52YWx1ZXMoKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKGUsZGlj'
    'dCk6cmV0dXJuIEZhbHNlCiAgICBmb3Iga2V5IGluICgnc2NvcmUnLCdkb3dubG9hZF9tYnBzJywndXBsb2FkX21icHMnLCds'
    'YXRlbmN5X21zJyk6CiAgICAgdj1lLmdldChrZXksMCkKICAgICBpZiB0eXBlKHYpIG5vdCBpbiAoaW50LGZsb2F0KSBvciBu'
    'b3QgbWF0aC5pc2Zpbml0ZSh2KSBvciB2PDA6cmV0dXJuIEZhbHNlCiAgICBpZiB0eXBlKGUuZ2V0KCdsb3NzZXMnKSkgaXMg'
    'bm90IGludCBvciBub3QgMDw9ZVsnbG9zc2VzJ108PTM6cmV0dXJuIEZhbHNlCiAgIHNlbGYuZGF0YT12YWx1ZTtyZXR1cm4g'
    'VHJ1ZQogIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFR5cGVFcnJvcixBdHRyaWJ1dGVFcnJvcik6cmV0dXJuIEZhbHNl'
    'CiBkZWYgc2F2ZShzZWxmKToKICBzZWxmLnBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQog'
    'IHRtcD1zZWxmLnBhdGgud2l0aF9zdWZmaXgoJy5uZXcnKTtmZD1vcy5vcGVuKHRtcCxvcy5PX1dST05MWXxvcy5PX0NSRUFU'
    'fG9zLk9fVFJVTkN8b3MuT19OT0ZPTExPVywwbzYwMCkKICB3aXRoIG9zLmZkb3BlbihmZCwndycpIGFzIGY6anNvbi5kdW1w'
    'KHNlbGYuZGF0YSxmLHNlcGFyYXRvcnM9KCcsJywnOicpKQogIG9zLnJlcGxhY2UodG1wLHNlbGYucGF0aCkKIGRlZiBidWls'
    'ZChzZWxmLG1lYXN1cmVtZW50cyk6CiAgZW50cmllcz17fQogIGZvciBpZGVudGl0eSBpbiBzZWxmLmlkczoKICAgbT1tZWFz'
    'dXJlbWVudHNbaWRlbnRpdHldO29rPW0uZ2V0KCdvaycsRmFsc2UpCiAgIGRvd249bWF4KDAsZmxvYXQobS5nZXQoJ2Rvd25s'
    'b2FkX21icHMnLDApKSk7dXA9bWF4KDAsZmxvYXQobS5nZXQoJ3VwbG9hZF9tYnBzJywwKSkpCiAgIHNjb3JlPSgyKmRvd24q'
    'dXAvKGRvd24rdXApIGlmIGRvd24rdXAgZWxzZSAxKS8oMSttYXgoMCxmbG9hdChtLmdldCgnbGF0ZW5jeV9tcycsMCkpKS8y'
    'MDApIGlmIG9rIGVsc2UgMAogICBlbnRyaWVzW2lkZW50aXR5XT17KiptLCdzY29yZSc6cm91bmQoc2NvcmUsMyksJ2xvc3Nl'
    'cyc6MCBpZiBvayBlbHNlIDF9CiAgc2VsZi5kYXRhPXsnc2NoZW1hJzoxLCdjcmVhdGVkJzppbnQodGltZS50aW1lKCkpLCdl'
    'bnRyaWVzJzplbnRyaWVzLAogICAgICAgICAgICAgJ29yZGVyJzpzb3J0ZWQoc2VsZi5pZHMsa2V5PWxhbWJkYSB4OmVudHJp'
    'ZXNbeF1bJ3Njb3JlJ10scmV2ZXJzZT1UcnVlKX0KICBzZWxmLnNhdmUoKQogZGVmIGNhbmRpZGF0ZXMoc2VsZik6cmV0dXJu'
    'IFt4IGZvciB4IGluIHNlbGYuZGF0YVsnb3JkZXInXSBpZiBzZWxmLmRhdGFbJ2VudHJpZXMnXVt4XVsnbG9zc2VzJ108M10K'
    'IGRlZiBsb3NlKHNlbGYsaWRlbnRpdHkscmVhc29uKToKICBlPXNlbGYuZGF0YVsnZW50cmllcyddW2lkZW50aXR5XTtlWyds'
    'b3NzZXMnXT1taW4oMyxlWydsb3NzZXMnXSsxKTtlWydsYXN0X2ZhaWx1cmUnXT1pbnQodGltZS50aW1lKCkpO2VbJ3JlYXNv'
    'biddPXJlYXNvbgogIHNlbGYuc2F2ZSgpCiBkZWYgbmV4dF9hZnRlcihzZWxmLGlkZW50aXR5KToKICBvcmRlcj1zZWxmLmRh'
    'dGFbJ29yZGVyJ107cmVzdD1vcmRlcltvcmRlci5pbmRleChpZGVudGl0eSkrMTpdCiAgcmV0dXJuIG5leHQoKHggZm9yIHgg'
    'aW4gcmVzdCBpZiBzZWxmLmRhdGFbJ2VudHJpZXMnXVt4XVsnbG9zc2VzJ108MyksTm9uZSkK'
)
TLS_TRANSPORT_PY_B64 = (
    'IiIiQm91bmRlZCBkYXRhZ3JhbSBmcmFtaW5nIG92ZXIgYXV0aGVudGljYXRlZCBUTFM7IElLRS9JUHNlYyBzdGF5cyBlbmQt'
    'dG8tZW5kLiIiIgppbXBvcnQgYXN5bmNpbyxjb250ZXh0bGliLGhhc2hsaWIsanNvbixzc2wsc3RydWN0LHRpbWUKZnJvbSBw'
    'YXRobGliIGltcG9ydCBQYXRoCk1BWF9QQUNLRVQ9NjU1MDcKY2xhc3MgRGF0YWdyYW1zKGFzeW5jaW8uRGF0YWdyYW1Qcm90'
    'b2NvbCk6CiBkZWYgX19pbml0X18oc2VsZik6c2VsZi5xdWV1ZT1hc3luY2lvLlF1ZXVlKDMyKTtzZWxmLnRyYW5zcG9ydD1O'
    'b25lO3NlbGYucGVlcj1Ob25lCiBkZWYgY29ubmVjdGlvbl9tYWRlKHNlbGYsdCk6c2VsZi50cmFuc3BvcnQ9dAogZGVmIGRh'
    'dGFncmFtX3JlY2VpdmVkKHNlbGYsZGF0YSxwZWVyKToKICBpZiBsZW4oZGF0YSk+TUFYX1BBQ0tFVDpyZXR1cm4KICBpZiBz'
    'ZWxmLnBlZXIgaXMgTm9uZTpzZWxmLnBlZXI9cGVlcgogIGlmIHNlbGYucGVlciE9cGVlcjpyZXR1cm4KICB0cnk6c2VsZi5x'
    'dWV1ZS5wdXRfbm93YWl0KGRhdGEpCiAgZXhjZXB0IGFzeW5jaW8uUXVldWVGdWxsOnBhc3MKIGRlZiBlcnJvcl9yZWNlaXZl'
    'ZChzZWxmLGVycm9yKTpwYXNzCgphc3luYyBkZWYgdHJhbnNmZXIocmVhZGVyLHdyaXRlcix1ZHAscmVtb3RlPU5vbmUpOgog'
    'YXN5bmMgZGVmIHRvX3RscygpOgogIHdoaWxlIFRydWU6CiAgIHRyeTpkYXRhPWF3YWl0IGFzeW5jaW8ud2FpdF9mb3IodWRw'
    'LnF1ZXVlLmdldCgpLDEwKQogICBleGNlcHQgYXN5bmNpby5UaW1lb3V0RXJyb3I6ZGF0YT1iJycKICAgd3JpdGVyLndyaXRl'
    'KHN0cnVjdC5wYWNrKCchSCcsbGVuKGRhdGEpKStkYXRhKTthd2FpdCB3cml0ZXIuZHJhaW4oKQogYXN5bmMgZGVmIGZyb21f'
    'dGxzKCk6CiAgd2hpbGUgVHJ1ZToKICAgc2l6ZT1zdHJ1Y3QudW5wYWNrKCchSCcsYXdhaXQgYXN5bmNpby53YWl0X2Zvcihy'
    'ZWFkZXIucmVhZGV4YWN0bHkoMiksMzApKVswXQogICBpZiBzaXplPk1BWF9QQUNLRVQ6cmFpc2UgVmFsdWVFcnJvcignb3Zl'
    'cnNpemVkX2ZyYW1lJykKICAgaWYgbm90IHNpemU6Y29udGludWUKICAgcGFja2V0PWF3YWl0IGFzeW5jaW8ud2FpdF9mb3Io'
    'cmVhZGVyLnJlYWRleGFjdGx5KHNpemUpLDEwKQogICBkZXN0aW5hdGlvbj1yZW1vdGUgb3IgdWRwLnBlZXIKICAgaWYgZGVz'
    'dGluYXRpb24gaXMgbm90IE5vbmU6dWRwLnRyYW5zcG9ydC5zZW5kdG8ocGFja2V0LGRlc3RpbmF0aW9uIGlmIHJlbW90ZSBp'
    'cyBOb25lIGVsc2UgTm9uZSkKIHRhc2tzPVthc3luY2lvLmNyZWF0ZV90YXNrKHRvX3RscygpKSxhc3luY2lvLmNyZWF0ZV90'
    'YXNrKGZyb21fdGxzKCkpXQogdHJ5OgogIGRvbmUsXz1hd2FpdCBhc3luY2lvLndhaXQodGFza3MscmV0dXJuX3doZW49YXN5'
    'bmNpby5GSVJTVF9DT01QTEVURUQpCiAgZm9yIHRhc2sgaW4gZG9uZTp0YXNrLnJlc3VsdCgpCiBmaW5hbGx5OgogIGZvciB0'
    'YXNrIGluIHRhc2tzOnRhc2suY2FuY2VsKCkKICBhd2FpdCBhc3luY2lvLmdhdGhlcigqdGFza3MscmV0dXJuX2V4Y2VwdGlv'
    'bnM9VHJ1ZSkKICB3cml0ZXIuY2xvc2UoKQogIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhFeGNlcHRpb24pOmF3YWl0IGFz'
    'eW5jaW8ud2FpdF9mb3Iod3JpdGVyLndhaXRfY2xvc2VkKCksMikKCmFzeW5jIGRlZiBjbGllbnRfYXN5bmMocm9vdCxhZGRy'
    'ZXNzLGlkZW50aXR5LHBvcnQ9MjQ1NzEpOgogY3R4PXNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZmlsZT1zdHIocm9v'
    'dC8nY2EucGVtJykpO2N0eC5taW5pbXVtX3ZlcnNpb249c3NsLlRMU1ZlcnNpb24uVExTdjFfMwogY3R4LmxvYWRfY2VydF9j'
    'aGFpbihzdHIocm9vdC8nY2xpZW50LnBlbScpLHN0cihyb290LydjbGllbnQta2V5LnBlbScpKQogbG9vcD1hc3luY2lvLmdl'
    'dF9ydW5uaW5nX2xvb3AoKTt1ZHA9RGF0YWdyYW1zKCkKIHRyYW5zcG9ydCxfPWF3YWl0IGxvb3AuY3JlYXRlX2RhdGFncmFt'
    'X2VuZHBvaW50KGxhbWJkYTp1ZHAsbG9jYWxfYWRkcj0oJzEyNy4wLjAuMScsMjQ1NzMpKQogdHJ5OgogIHdoaWxlIFRydWU6'
    'CiAgIHRyeToKICAgIHJlYWRlcix3cml0ZXI9YXdhaXQgYXN5bmNpby53YWl0X2Zvcihhc3luY2lvLm9wZW5fY29ubmVjdGlv'
    'bihhZGRyZXNzLHBvcnQsc3NsPWN0eCxzZXJ2ZXJfaG9zdG5hbWU9aWRlbnRpdHksc3NsX2hhbmRzaGFrZV90aW1lb3V0PTYp'
    'LDgpCiAgICBhd2FpdCB0cmFuc2ZlcihyZWFkZXIsd3JpdGVyLHVkcCkKICAgZXhjZXB0IChPU0Vycm9yLFRpbWVvdXRFcnJv'
    'cixFT0ZFcnJvcixWYWx1ZUVycm9yLGFzeW5jaW8uSW5jb21wbGV0ZVJlYWRFcnJvcik6CiAgICB3aGlsZSBub3QgdWRwLnF1'
    'ZXVlLmVtcHR5KCk6dWRwLnF1ZXVlLmdldF9ub3dhaXQoKQogICAgYXdhaXQgYXN5bmNpby5zbGVlcCgxKQogZmluYWxseTp0'
    'cmFuc3BvcnQuY2xvc2UoKQoKZGVmIGNsaWVudChyb290LGFkZHJlc3MsaWRlbnRpdHkscG9ydD0yNDU3MSk6YXN5bmNpby5y'
    'dW4oY2xpZW50X2FzeW5jKFBhdGgocm9vdCksYWRkcmVzcyxpZGVudGl0eSxwb3J0KSkKCmFzeW5jIGRlZiBzZXJ2ZXJfYXN5'
    'bmMocm9vdCk6CiBjdHg9c3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19TRVJWRVIpO2N0eC5taW5pbXVtX3ZlcnNp'
    'b249c3NsLlRMU1ZlcnNpb24uVExTdjFfMwogY3R4LmxvYWRfY2VydF9jaGFpbihzdHIocm9vdC8nc2VydmVyLnBlbScpLHN0'
    'cihyb290LydzZXJ2ZXIta2V5LnBlbScpKQogY3R4LmxvYWRfdmVyaWZ5X2xvY2F0aW9ucyhzdHIocm9vdC8nY2EucGVtJykp'
    'O2N0eC5sb2FkX3ZlcmlmeV9sb2NhdGlvbnMoc3RyKHJvb3QvJ2RldmljZXMucGVtJykpCiBjdHgudmVyaWZ5X21vZGU9c3Ns'
    'LkNFUlRfUkVRVUlSRUQ7Y3R4LnZlcmlmeV9mbGFnc3w9c3NsLlZFUklGWV9DUkxfQ0hFQ0tfTEVBRgogYWN0aXZlPXt9O3Rv'
    'dGFsPTAKIGFzeW5jIGRlZiBoYW5kbGUocmVhZGVyLHdyaXRlcik6CiAgbm9ubG9jYWwgdG90YWwKICBjZXJ0PXdyaXRlci5n'
    'ZXRfZXh0cmFfaW5mbygnc3NsX29iamVjdCcpLmdldHBlZXJjZXJ0KGJpbmFyeV9mb3JtPVRydWUpCiAga2V5PWhhc2hsaWIu'
    'c2hhMjU2KGNlcnQpLmRpZ2VzdCgpCiAgaWYgdG90YWw+PTY0IG9yIGFjdGl2ZS5nZXQoa2V5LDApPj0yOndyaXRlci5jbG9z'
    'ZSgpO3JldHVybgogIHRvdGFsKz0xO2FjdGl2ZVtrZXldPWFjdGl2ZS5nZXQoa2V5LDApKzE7dHJhbnNwb3J0PU5vbmUKICB0'
    'cnk6CiAgIHVkcD1EYXRhZ3JhbXMoKTt1ZHAucGVlcj0oJzEyNy4wLjAuMScsNDUwMCkKICAgdHJhbnNwb3J0LF89YXdhaXQg'
    'YXN5bmNpby5nZXRfcnVubmluZ19sb29wKCkuY3JlYXRlX2RhdGFncmFtX2VuZHBvaW50KGxhbWJkYTp1ZHAscmVtb3RlX2Fk'
    'ZHI9KCcxMjcuMC4wLjEnLDQ1MDApKQogICBhd2FpdCB0cmFuc2ZlcihyZWFkZXIsd3JpdGVyLHVkcCxyZW1vdGU9KCcxMjcu'
    'MC4wLjEnLDQ1MDApKQogIGV4Y2VwdCAoT1NFcnJvcixUaW1lb3V0RXJyb3IsRU9GRXJyb3IsVmFsdWVFcnJvcixhc3luY2lv'
    'LkluY29tcGxldGVSZWFkRXJyb3IpOnBhc3MKICBmaW5hbGx5OgogICBpZiB0cmFuc3BvcnQ6dHJhbnNwb3J0LmNsb3NlKCkK'
    'ICAgd3JpdGVyLmNsb3NlKCk7dG90YWwtPTE7YWN0aXZlW2tleV0tPTEKICAgaWYgbm90IGFjdGl2ZVtrZXldOmRlbCBhY3Rp'
    'dmVba2V5XQogc2VydmVyPWF3YWl0IGFzeW5jaW8uc3RhcnRfc2VydmVyKGhhbmRsZSwnMC4wLjAuMCcsMjQ1NzEsc3NsPWN0'
    'eCxzc2xfaGFuZHNoYWtlX3RpbWVvdXQ9NixsaW1pdD0xMzEwNzIpCiBhc3luYyB3aXRoIHNlcnZlcjphd2FpdCBzZXJ2ZXIu'
    'c2VydmVfZm9yZXZlcigpCgppZiBfX25hbWVfXz09J19fbWFpbl9fJzphc3luY2lvLnJ1bihzZXJ2ZXJfYXN5bmMoUGF0aCgn'
    'L2V0Yy9ldmdlbml1bS1kaXJlY3QnKSkpCg=='
)

starfive_tunnel=embedded('starfive_tunnel',STARFIVE_TUNNEL_PY_B64)
policy=embedded('network_policy',NETWORK_POLICY_PY_B64)
class ManagerAPI:
 def __getattr__(self,name):return globals()[name]
policy.api=ManagerAPI()
policy.tunnel=starfive_tunnel
starfive_tunnel.policy=policy
starfive_tunnel.support_api=embedded('support_reports',SUPPORT_REPORTS_PY_B64)
starfive_tunnel.rank_api=embedded('path_ranking',PATH_RANKING_PY_B64)
starfive_tunnel.tls_api=embedded('tls_transport',TLS_TRANSPORT_PY_B64)

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
 elif action=='report-preview':print(json.dumps(starfive_tunnel.support_api.prepare(starfive_tunnel,MANAGER_VERSION),ensure_ascii=False))
 elif action=='report-send':print('Отчёт принят: '+starfive_tunnel.support_api.send(starfive_tunnel,data.get('report_id'),data.get('consent')))
 elif action=='device-name':starfive_tunnel.sync_device_name(str(data.get('name','')))
 elif action in ('connect','repair'):starfive_tunnel.connect(repair=action=='repair')
 elif action=='disconnect':starfive_tunnel.disconnect()
 elif action=='update':manager_update_manifest(settings,settings['manager_manifest_url'])
 elif action in ('add','remove','base','waydroid'):
  if action in ('base','waydroid') and not isinstance(data.get('enabled'),bool):fail('Ожидался переключатель.')
  policy.change(action,str(data.get('category','')),str(data.get('value','')),data.get('enabled'))
 else:fail('Неизвестное действие.')

def operation_requires_lock(args):
 return args.cmd not in (None,'status','version','logs','rules','watch','internal-waydroid-watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-tls-client','internal-starfive-pause-main') and not (args.cmd=='ui' and args.ui_cmd in ('state','running'))

def self_test():
 assert re.fullmatch(r'\d+\.\d+\.\d+',MANAGER_VERSION)
 assert policy.config(policy.defaults())['outbounds'][0]['protocol']=='freedom'
 for source in (STANDALONE_GUI_PY_B64,STARFIVE_TUNNEL_PY_B64,NETWORK_POLICY_PY_B64,SUPPORT_REPORTS_PY_B64,PATH_RANKING_PY_B64,TLS_TRANSPORT_PY_B64):compile(base64.b64decode(source),'embedded','exec')
 assert 'VLESS' not in base64.b64decode(STANDALONE_GUI_QML_B64).decode()
 print('Evgenium token VPN self-test OK')

def terminal_status(st=None,check_ip=False):
 st=st or status_data();t=st['tunnel'];p=st['policy']
 print('Evgenium '+MANAGER_VERSION)
 print('Состояние: '+('ПОДКЛЮЧЕНО' if st['active'] else 'ЗАБЛОКИРОВАНО' if st['guard'] else 'ВЫКЛЮЧЕНО'))
 print('Маршрут: '+next((x['label'] for x in starfive_tunnel.CANDIDATES if x['id']==st['tunnel'].get('path')), 'автоматический выбор → Эстония'))
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


def terminal_wait(timeout=600):
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
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-waydroid-watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-tls-client','internal-starfive-pause-main','manager-rollback'):sub.add_parser(name)
 pst=sub.add_parser('status',help='Состояние, защита и исключения');pst.add_argument('--json',action='store_true');pst.add_argument('--ip',action='store_true',help='Проверить внешний IP именно через VPN')
 device=sub.add_parser('device',help='Имя устройства в веб-панели');device.add_argument('operation',choices=['show','name','sync']);device.add_argument('name',nargs='?')
 rep=sub.add_parser('report',help='Просмотреть и добровольно отправить отчёт');rep.add_argument('operation',choices=['preview','send']);rep.add_argument('--consent',action='store_true');rep.add_argument('--id')
 tok=sub.add_parser('token');tok.add_argument('token_cmd',choices=['save'])
 base=sub.add_parser('base',help='Управление базовыми исключениями');base.add_argument('operation',choices=['list','enable','disable']);base.add_argument('category',choices=policy.CATEGORIES,nargs='?');base.add_argument('rule',nargs='?')
 way=sub.add_parser('waydroid');way.add_argument('mode',choices=['status','direct','vpn'])
 ui=sub.add_parser('ui');uis=ui.add_subparsers(dest='ui_cmd');uis.add_parser('state');uis.add_parser('running');uis.add_parser('action').add_argument('payload')
 for name in ('gui','widget'):
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
  elif cmd=='internal-tls-client':
   selected=json.loads((starfive_tunnel.ROOT/'active-path.json').read_text())
   candidate=next(x for x in starfive_tunnel.CANDIDATES if x['id']==selected['id'])
   starfive_tunnel.tls_api.client(starfive_tunnel.ROOT,candidate['address'],candidate['identity'])
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
  elif cmd=='report':
   if args.operation=='preview':print(json.dumps(starfive_tunnel.support_api.prepare(starfive_tunnel,MANAGER_VERSION),ensure_ascii=False,indent=2))
   else:print('Отчёт принят: '+starfive_tunnel.support_api.send(starfive_tunnel,args.id,args.consent))
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
