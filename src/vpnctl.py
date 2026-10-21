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

MANAGER_VERSION = "0.5.1"

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
    'ZWlnaHQ6IE1hdGgubWluKHJvb3QuaGVpZ2h0LTUwLDYyMCkKICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICBh'
    'bmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBzcGFjaW5nOiAxMgogICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgdGV4dDogItCS0LXRgNGB0LjRjywg0Y3RgtCw0L/RiyDQ'
    'v9C+0LTQutC70Y7Rh9C10L3QuNGPLCDQvtGI0LjQsdC60Lgg0Lgg0LfQsNC80LXRgNGLLiDQkdC10Lcg0YLQvtC60LXQvdC+'
    '0LIsINC60LvRjtGH0LXQuSwg0LjRgdGC0L7RgNC40Lgg0YHQsNC50YLQvtCyINC4INGB0L/QuNGB0LrQsCDQv9GA0LjQu9C+'
    '0LbQtdC90LjQuS4g0J7RgtC/0YDQsNCy0LrQsCDQtNC+0LHRgNC+0LLQvtC70YzQvdCw0Y87INGB0LXRgNCy0LXRgCDRhdGA'
    '0LDQvdC40YIg0L7RgtGH0ZHRgiDQtNC+IDcg0LTQvdC10LkuIiB9CiAgICAgICAgICAgIEMuU2Nyb2xsVmlldyB7IExheW91'
    'dC5maWxsV2lkdGg6IHRydWU7IExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAgICBDLlRleHRBcmVhIHsg'
    'dGV4dDogcm9vdC5yZXBvcnRUZXh0OyByZWFkT25seTogdHJ1ZTsgc2VsZWN0QnlNb3VzZTogdHJ1ZTsgd3JhcE1vZGU6IFRl'
    'eHRFZGl0LldyYXA7IGZvbnQuZmFtaWx5OiAibW9ub3NwYWNlIjsgZm9udC5waXhlbFNpemU6IDExIH0KICAgICAgICAgICAg'
    'fQogICAgICAgICAgICBDLkNoZWNrQm94IHsgaWQ6IHJlcG9ydENvbnNlbnQ7IHRleHQ6ICLQoNCw0LfRgNC10YjQsNGOINC+'
    '0YLQv9GA0LDQstC40YLRjCDQv9C+0LrQsNC30LDQvdC90YvQuSDQvtGC0YfRkdGCINCy0LvQsNC00LXQu9GM0YbRgyBWUE4i'
    'IH0KICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCe0YLQv9GA'
    '0LDQstC40YLRjCI7IHByaW1hcnk6IHRydWU7IGVuYWJsZWRCdXR0b246IHJlcG9ydENvbnNlbnQuY2hlY2tlZCAmJiAhcm9v'
    'dC5idXN5OyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246InJlcG9ydC1zZW5kIixyZXBvcnRfaWQ6cm9vdC5yZXBv'
    'cnRJZCxjb25zZW50OnRydWV9LGZ1bmN0aW9uKCl7c3VwcG9ydERpYWxvZy5jbG9zZSgpO3Jvb3QuZXJyb3JUZXh0PSLQntGC'
    '0YfRkdGCINC+0YLQv9GA0LDQstC70LXQvS4gSUQ6ICIrcm9vdC5yZXBvcnRJZH0pIH0KICAgICAgICAgICAgICAgIEZsYXRC'
    'dXR0b24geyBsYWJlbDogItCX0LDQutGA0YvRgtGMIjsgb25DbGlja2VkOiBzdXBwb3J0RGlhbG9nLmNsb3NlKCkgfQogICAg'
    'ICAgICAgICB9CiAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNpYmxlOiAhcm9vdC5zdGF0ZS5hY3RpdmU7IExheW91dC5maWxs'
    'V2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IHRleHQ6ICLQldGB0LvQuCDQt9Cw0YnQuNGC0LAg0LHQu9C+0LrQ'
    'uNGA0YPQtdGCINGB0LXRgtGMLCDQvtGC0YfRkdGCINC+0YHRgtCw0L3QtdGC0YHRjyDQu9C+0LrQsNC70YzQvdC+INC00L4g'
    '0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjRjyDQuNC70Lgg0Y/QstC90L7Qs9C+INC+0YLQutC70Y7Rh9C10L3QuNGPIFZQ'
    'Ti4iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgRmxhdEJ1dHRvbjog'
    'UmVjdGFuZ2xlIHsKICAgICAgICBpZDogZmxhdEJ1dHRvbgogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHN0cmluZyBsYWJl'
    'bAogICAgICAgIHByb3BlcnR5IGJvb2wgcHJpbWFyeTogZmFsc2UKICAgICAgICBwcm9wZXJ0eSBib29sIGRhbmdlcjogZmFs'
    'c2UKICAgICAgICBwcm9wZXJ0eSBib29sIGVuYWJsZWRCdXR0b246IHRydWUKICAgICAgICBzaWduYWwgY2xpY2tlZCgpCiAg'
    'ICAgICAgaW1wbGljaXRIZWlnaHQ6IDM4CiAgICAgICAgaW1wbGljaXRXaWR0aDogTWF0aC5tYXgoOTIsIGJ1dHRvblRleHQu'
    'aW1wbGljaXRXaWR0aCArIDI4KQogICAgICAgIHJhZGl1czogMTAKICAgICAgICBjb2xvcjogIWVuYWJsZWRCdXR0b24gPyAi'
    'I2VlZjBmMyIKICAgICAgICAgICAgICA6IGRhbmdlciA/IChidXR0b25Nb3VzZS5jb250YWluc01vdXNlID8gIiNmZWUyZTIi'
    'IDogIiNmZWYyZjIiKQogICAgICAgICAgICAgIDogcHJpbWFyeSA/IChidXR0b25Nb3VzZS5jb250YWluc01vdXNlID8gIiMy'
    'MDk5ZGMiIDogcm9vdC5hY2NlbnQpCiAgICAgICAgICAgICAgOiAoYnV0dG9uTW91c2UuY29udGFpbnNNb3VzZSA/ICIjZWVm'
    'MmY3IiA6ICIjZjdmOWZjIikKICAgICAgICBib3JkZXIud2lkdGg6IHByaW1hcnkgPyAwIDogMQogICAgICAgIGJvcmRlci5j'
    'b2xvcjogZGFuZ2VyID8gIiNmZWNhY2EiIDogcm9vdC5ib3JkZXIKICAgICAgICBvcGFjaXR5OiBlbmFibGVkQnV0dG9uID8g'
    'MSA6IDAuNgoKICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgaWQ6IGJ1dHRvblRleHQKICAgICAgICAgICAgYW5jaG9y'
    'cy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAgIHRleHQ6IGZsYXRCdXR0b24ubGFiZWwKICAgICAgICAgICAgY29sb3I6'
    'IGZsYXRCdXR0b24ucHJpbWFyeSA/ICJ3aGl0ZSIgOiAoZmxhdEJ1dHRvbi5kYW5nZXIgPyByb290LmJhZCA6IHJvb3QudGV4'
    'dE1haW4pCiAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMwogICAgICAgICAgICBmb250LndlaWdodDogRm9udC5EZW1p'
    'Qm9sZAogICAgICAgIH0KICAgICAgICBNb3VzZUFyZWEgewogICAgICAgICAgICBpZDogYnV0dG9uTW91c2UKICAgICAgICAg'
    'ICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgZW5hYmxlZDogZmxhdEJ1dHRvbi5lbmFibGVkQnV0dG9uCiAg'
    'ICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JTaGFwZTogZW5hYmxlZCA/IFF0LlBvaW50'
    'aW5nSGFuZEN1cnNvciA6IFF0LkFycm93Q3Vyc29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogZmxhdEJ1dHRvbi5jbGlja2Vk'
    'KCkKICAgICAgICB9CiAgICB9CgogICAgY29tcG9uZW50IE5hdkJ1dHRvbjogUmVjdGFuZ2xlIHsKICAgICAgICBpZDogbmF2'
    'CiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgc3RyaW5nIGxhYmVsCiAgICAgICAgcmVxdWlyZWQgcHJvcGVydHkgaW50IGlu'
    'ZGV4CiAgICAgICAgcHJvcGVydHkgc3RyaW5nIHNob3J0TGFiZWw6ICIiCiAgICAgICAgc2lnbmFsIGNsaWNrZWQoKQogICAg'
    'ICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICBpbXBsaWNpdFdpZHRoOiAxODYKICAgICAgICBoZWlnaHQ6IDQ4'
    'CiAgICAgICAgcmFkaXVzOiAxMQogICAgICAgIGNvbG9yOiByb290LnBhZ2VJbmRleCA9PT0gaW5kZXggPyAiIzI1MzI0NiIg'
    'OiAobmF2TW91c2UuY29udGFpbnNNb3VzZSA/IHJvb3Quc2lkZWJhckhvdmVyIDogInRyYW5zcGFyZW50IikKCiAgICAgICAg'
    'Um93TGF5b3V0IHsKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgYW5jaG9ycy5sZWZ0TWFy'
    'Z2luOiAxMgogICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiAxMgogICAgICAgICAgICBzcGFjaW5nOiAxMQogICAg'
    'ICAgICAgICBSZWN0YW5nbGUgewogICAgICAgICAgICAgICAgaW1wbGljaXRXaWR0aDogMjgKICAgICAgICAgICAgICAgIGlt'
    'cGxpY2l0SGVpZ2h0OiAyOAogICAgICAgICAgICAgICAgcmFkaXVzOiA4CiAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5w'
    'YWdlSW5kZXggPT09IG5hdi5pbmRleCA/IHJvb3QuYWNjZW50IDogIiMyNzM0NDkiCiAgICAgICAgICAgICAgICBDLkxhYmVs'
    'IHsKICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmNlbnRlckluOiBwYXJlbnQKICAgICAgICAgICAgICAgICAgICB0ZXh0'
    'OiBuYXYuc2hvcnRMYWJlbAogICAgICAgICAgICAgICAgICAgIGNvbG9yOiAid2hpdGUiCiAgICAgICAgICAgICAgICAgICAg'
    'Zm9udC5waXhlbFNpemU6IDEwCiAgICAgICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IEZvbnQuQm9sZAogICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxX'
    'aWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgdGV4dDogbmF2LmxhYmVsCiAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC5w'
    'YWdlSW5kZXggPT09IG5hdi5pbmRleCA/ICJ3aGl0ZSIgOiAiI2NiZDVlMSIKICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxT'
    'aXplOiAxNAogICAgICAgICAgICAgICAgZm9udC53ZWlnaHQ6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyBGb250'
    'LkRlbWlCb2xkIDogRm9udC5Ob3JtYWwKICAgICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBNb3VzZUFyZWEgewogICAg'
    'ICAgICAgICBpZDogbmF2TW91c2UKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgaG92ZXJF'
    'bmFibGVkOiB0cnVlCiAgICAgICAgICAgIGN1cnNvclNoYXBlOiBRdC5Qb2ludGluZ0hhbmRDdXJzb3IKICAgICAgICAgICAg'
    'b25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICByb290LnBhZ2VJbmRleCA9IG5hdi5pbmRleAogICAgICAgICAgICAgICAg'
    'bmF2LmNsaWNrZWQoKQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQoKICAgIGNvbXBvbmVudCBDYXJkOiBSZWN0YW5n'
    'bGUgewogICAgICAgIHJhZGl1czogMTYKICAgICAgICBjb2xvcjogcm9vdC5zdXJmYWNlCiAgICAgICAgYm9yZGVyLndpZHRo'
    'OiAxCiAgICAgICAgYm9yZGVyLmNvbG9yOiByb290LmJvcmRlcgogICAgfQoKICAgIFJvd0xheW91dCB7CiAgICAgICAgYW5j'
    'aG9ycy5maWxsOiBwYXJlbnQKICAgICAgICBzcGFjaW5nOiAwCiAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgTGF5'
    'b3V0LnByZWZlcnJlZFdpZHRoOiAyMjIKICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAg'
    'Y29sb3I6IHJvb3Quc2lkZWJhcgogICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgYW5jaG9ycy5m'
    'aWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMTgKICAgICAgICAgICAgICAgIHNwYWNpbmc6'
    'IDgKICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAiRXZnZW5pdW0iOyBjb2xvcjogIndoaXRlIjsgZm9udC5waXhl'
    'bFNpemU6IDIzOyBmb250LmJvbGQ6IHRydWU7IExheW91dC50b3BNYXJnaW46IDEyIH0KICAgICAgICAgICAgICAgIEMuTGFi'
    'ZWwgeyB0ZXh0OiAiTmV0d29yayI7IGNvbG9yOiAiIzk0YTNiOCI7IExheW91dC5ib3R0b21NYXJnaW46IDI4IH0KICAgICAg'
    'ICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAiVlBOIjsgc2hvcnRMYWJlbDogIlZQTiI7IGluZGV4OiAwIH0KICAgICAg'
    'ICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi0J/RgNC40LvQvtC20LXQvdC40Y8iOyBzaG9ydExhYmVsOiAiQVBQIjsg'
    'aW5kZXg6IDE7IG9uQ2xpY2tlZDogcm9vdC5yZWZyZXNoUnVubmluZygpIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7'
    'IGxhYmVsOiAi0KHQsNC50YLRiyDQuCBJUCI7IHNob3J0TGFiZWw6ICJORVQiOyBpbmRleDogMiB9CiAgICAgICAgICAgICAg'
    'ICBOYXZCdXR0b24geyBsYWJlbDogItCf0L7RgNGC0YsiOyBzaG9ydExhYmVsOiAiUFJUIjsgaW5kZXg6IDMgfQogICAgICAg'
    'ICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6ICJETlMiOyBzaG9ydExhYmVsOiAiRE5TIjsgaW5kZXg6IDQgfQogICAgICAg'
    'ICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6ICJXYXlkcm9pZCI7IHNob3J0TGFiZWw6ICJXQVkiOyBpbmRleDogNSB9CiAg'
    'ICAgICAgICAgICAgICBJdGVtIHsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUgfQogICAgICAgICAgICAgICAgQy5MYWJlbCB7'
    'IHRleHQ6IHJvb3Quc3RhdGUuYWN0aXZlID8gIuKXjyDQn9C+0LTQutC70Y7Rh9C10L3QviIgOiAocm9vdC5zdGF0ZS5ndWFy'
    'ZCA/ICLil48g0JfQsNGJ0LjRgtCwINCy0LrQu9GO0YfQtdC90LAiIDogIuKXiyDQntGC0LrQu9GO0YfQtdC90L4iKTsgY29s'
    'b3I6IHJvb3Quc3RhdGUuYWN0aXZlID8gIiM0YWRlODAiIDogIiNjYmQ1ZTEiIH0KICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiAi0JLQtdGA0YHQuNGPICIgKyAocm9vdC5zdGF0ZS5tYW5hZ2VyX3ZlcnNpb24gfHwgIuKApiIpOyBjb2xvcjog'
    'IiM5NGEzYjgiOyBmb250LnBpeGVsU2l6ZTogMTIgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIENvbHVtbkxh'
    'eW91dCB7CiAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgTGF5b3V0LmZpbGxIZWlnaHQ6'
    'IHRydWUKICAgICAgICAgICAgTGF5b3V0Lm1hcmdpbnM6IDI4CiAgICAgICAgICAgIHNwYWNpbmc6IDE2CiAgICAgICAgICAg'
    'IEMuTGFiZWwgeyB0ZXh0OiBbItCS0LDRiCBWUE4iLCAi0JjRgdC60LvRjtGH0LXQvdC40Y8g0L/RgNC40LvQvtC20LXQvdC4'
    '0LkiLCAi0KHQsNC50YLRiyDQuCBJUCIsICLQmNGB0LrQu9GO0YfQtdC90LjRjyDQv9C+0YDRgtC+0LIiLCAiRE5TIiwgIldh'
    'eWRyb2lkIl1bcm9vdC5wYWdlSW5kZXhdOyBjb2xvcjogcm9vdC50ZXh0TWFpbjsgZm9udC5waXhlbFNpemU6IDI3OyBmb250'
    'LmJvbGQ6IHRydWUgfQogICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgIHZpc2libGU6IEJvb2xlYW4ocm9vdC5lcnJvclRleHQgfHwgcm9vdC5wb2xsRXJyb3JUZXh0'
    'KQogICAgICAgICAgICAgICAgdGV4dDogcm9vdC5lcnJvclRleHQgfHwgcm9vdC5wb2xsRXJyb3JUZXh0CiAgICAgICAgICAg'
    'ICAgICBjb2xvcjogcm9vdC5iYWQKICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0LldyYXAKICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICBDLkJ1c3lJbmRpY2F0b3IgeyBydW5uaW5nOiByb290LmJ1c3k7IHZpc2libGU6IHJ1bm5pbmc7IExheW91'
    'dC5wcmVmZXJyZWRIZWlnaHQ6IDI4IH0KICAgICAgICAgICAgQy5TY3JvbGxWaWV3IHsKICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgIExheW91dC5maWxsSGVpZ2h0OiB0cnVlCiAgICAgICAgICAgICAg'
    'ICBjbGlwOiB0cnVlCiAgICAgICAgICAgICAgICBjb250ZW50V2lkdGg6IGF2YWlsYWJsZVdpZHRoCiAgICAgICAgICAgICAg'
    'ICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgIHdpZHRoOiBwYXJlbnQud2lkdGgKICAgICAgICAgICAgICAg'
    'ICAgICBzcGFjaW5nOiAxOAogICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSAwCiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lk'
    'dGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgKICAgICAgICAgICAgICAgICAgICAgICAgQ2Fy'
    'ZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiByb290LnRva2VuU2F2ZWQKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGltcGxpY2l0'
    'SGVpZ2h0OiBkZXZpY2VCb2R5LmltcGxpY2l0SGVpZ2h0ICsgMzIKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVt'
    'bkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWQ6IGRldmljZUJvZHkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudDsgYW5jaG9ycy5tYXJnaW5zOiAxNgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHZpc2libGU6'
    'ICFyb290LmRldmljZUVkaXRpbmc7IHRleHQ6IHJvb3QudHVubmVsLmRldmljZV9uYW1lIHx8ICLQn9C+0LvRg9GH0LDRjiDQ'
    'uNC80Y8g0YPRgdGC0YDQvtC50YHRgtCy0LDigKYiOyBmb250LnBpeGVsU2l6ZTogMTg7IGZvbnQuYm9sZDogdHJ1ZTsgY29s'
    'b3I6IHJvb3QudGV4dE1haW47IExheW91dC5maWxsV2lkdGg6IHRydWU7IGVsaWRlOiBUZXh0LkVsaWRlUmlnaHQgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7IGlkOiBkZXZpY2VOYW1lSW5wdXQ7IHZpc2li'
    'bGU6IHJvb3QuZGV2aWNlRWRpdGluZzsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgbWF4aW11bUxlbmd0aDogNjQ7IHBsYWNl'
    'aG9sZGVyVGV4dDogItCY0LzRjyDRg9GB0YLRgNC+0LnRgdGC0LLQsCI7IHNlbGVjdEJ5TW91c2U6IHRydWUgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6IHJvb3QuZGV2aWNlRWRpdGluZyA/ICLQ'
    'odC+0YXRgNCw0L3QuNGC0YwiIDogItCY0LfQvNC10L3QuNGC0Ywg0LjQvNGPIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVz'
    'eSAmJiAhcm9vdC5zdGF0ZS5jb25uZWN0aW5nICYmICghcm9vdC5kZXZpY2VFZGl0aW5nIHx8IGRldmljZU5hbWVJbnB1dC50'
    'ZXh0LnRyaW0oKS5sZW5ndGggPiAwKTsgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBpZiAoIXJvb3QuZGV2aWNlRWRpdGluZykgeyBkZXZpY2VOYW1lSW5wdXQudGV4dD1yb290LnR1bm5lbC5kZXZpY2Vf'
    'bmFtZSB8fCAiIjsgcm9vdC5kZXZpY2VFZGl0aW5nPXRydWU7IGRldmljZU5hbWVJbnB1dC5mb3JjZUFjdGl2ZUZvY3VzKCkg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSByb290LmFjdGlvbih7YWN0aW9uOiJkZXZp'
    'Y2UtbmFtZSIsbmFtZTpkZXZpY2VOYW1lSW5wdXQudGV4dC50cmltKCl9LGZ1bmN0aW9uKCl7cm9vdC5kZXZpY2VFZGl0aW5n'
    'PWZhbHNlfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEZsYXRCdXR0b24geyB2aXNpYmxlOiByb290LmRldmljZUVkaXRpbmc7IGxhYmVsOiAi0J7RgtC80LXQ'
    'vdCwIjsgb25DbGlja2VkOiByb290LmRldmljZUVkaXRpbmc9ZmFsc2UgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogcm9vdC50dW5uZWwuZGV2aWNl'
    'X25hbWVfcGVuZGluZyA/ICLQmNC80Y8g0YHQvtGF0YDQsNC90LXQvdC+INC90LAg0LrQvtC80L/RjNGO0YLQtdGA0LUg0Lgg'
    '0LHRg9C00LXRgiDQvtGC0L/RgNCw0LLQu9C10L3QviDQv9GA0Lgg0L/QvtC00LrQu9GO0YfQtdC90LjQuC4iIDogItCt0YLQ'
    'viDQuNC80Y8g0LLQuNC00L3QviDQsiDQstC10LEt0L/QsNC90LXQu9C4INGB0YDQtdC00Lgg0LLQsNGI0LjRhSDQv9C+0LTQ'
    'utC70Y7Rh9C10L3QuNC5LiI7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiBy'
    'b290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogY29ubmVjdGlvbkJvZHkuaW1w'
    'bGljaXRIZWlnaHQgKyA0MAogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBpZDogY29ubmVjdGlvbkJvZHkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBh'
    'bmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMjAK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgeyB0ZXh0OiByb290LnN0YXRlLmFjdGl2ZSA/ICLQn9C+0LTQutC70Y7Rh9C10L3QviDRh9C10YDQtdC3'
    'INCt0YHRgtC+0L3QuNGOIiA6IChyb290LnR1bm5lbC5ydW5uaW5nID8gItCf0L7QtNC60LvRjtGH0LXQvdC40LXigKYiIDog'
    'ItCT0L7RgtC+0LIg0Log0L/QvtC00LrQu9GO0YfQtdC90LjRjiIpOyBjb2xvcjogcm9vdC5zdGF0ZS5hY3RpdmUgPyByb290'
    'Lmdvb2QgOiByb290LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTogMjE7IGZvbnQuYm9sZDogdHJ1ZSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IHJvb3QudHVubmVsLm1lc3NhZ2UgfHwgItCS0LLQtdC00LjR'
    'gtC1INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAiOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5X'
    'cmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuUHJvZ3Jlc3NC'
    'YXIgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB2aXNpYmxlOiBCb29sZWFuKHJvb3QudHVubmVsLnJ1bm5pbmcpICYmICFy'
    'b290LnN0YXRlLmFjdGl2ZTsgZnJvbTogMDsgdG86IDEwMDsgdmFsdWU6IE51bWJlcihyb290LnR1bm5lbC5wcm9ncmVzcyB8'
    'fCAwKSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiByb290LnR1bm5lbC5ydW5uaW5nIHx8IHJvb3Quc3RhdGUuZ3Vh'
    'cmQgPyAi0J7RgtC60LvRjtGH0LjRgtGMIiA6ICLQn9C+0LTQutC70Y7Rh9C40YLRjCI7IHByaW1hcnk6IHRydWU7IGVuYWJs'
    'ZWRCdXR0b246ICFyb290LmJ1c3kgJiYgKHJvb3QudG9rZW5TYXZlZCB8fCByb290LnN0YXRlLmd1YXJkKTsgb25DbGlja2Vk'
    'OiByb290LmFjdGlvbih7YWN0aW9uOiByb290LnR1bm5lbC5ydW5uaW5nIHx8IHJvb3Quc3RhdGUuZ3VhcmQgPyAiZGlzY29u'
    'bmVjdCIgOiAiY29ubmVjdCJ9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBs'
    'YWJlbDogItCS0L7RgdGB0YLQsNC90L7QstC40YLRjCI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3Rh'
    'dGUuY29ubmVjdGluZyAmJiByb290LnRva2VuU2F2ZWQ7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInJlcGFp'
    'ciJ9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuTGFiZWwgeyB0ZXh0OiAi0JLQtdGB0Ywg0YLRgNCw0YTQuNC6INC40LTRkdGCINGH0LXRgNC10LcgVlBOLCDQutGA0L7Q'
    'vNC1INCy0LrQu9GO0YfRkdC90L3Ri9GFINC40YHQutC70Y7Rh9C10L3QuNC5LiDQn9GA0Lgg0L7QsdGA0YvQstC1INC30LDR'
    'idC40YnRkdC90L3Ri9C1INC/0L7QtNC60LvRjtGH0LXQvdC40Y8g0LHQu9C+0LrQuNGA0YPRjtGC0YHRjy4iOyBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENh'
    'cmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgaW1wbGljaXRIZWlnaHQ6IHRva2VuQm9keS5pbXBsaWNpdEhlaWdodCArIDQwCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiB0b2tlbkJv'
    'ZHkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFj'
    'aW5nOiAxMgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KLQvtC60LXQvSDQutC7'
    '0LjQtdC90YLQsCI7IGZvbnQucGl4ZWxTaXplOiAxNzsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHZpc2libGU6IHJvb3QudG9rZW5Mb2NrZWQ7IHRl'
    'eHQ6IHJvb3QudHVubmVsLnRva2VuX2hpbnQgfHwgItCi0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvSI7IGNvbG9yOiByb290'
    'LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLlRleHRGaWVsZCB7IGlkOiB0b2tlbklucHV0OyB2aXNpYmxlOiAhcm9vdC50b2tlbkxvY2tlZDsgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZTsgcGxhY2Vob2xkZXJUZXh0OiAiRVZOMS3igKYiOyBlY2hvTW9kZTogVGV4dElucHV0LlBhc3N3'
    'b3JkOyBzZWxlY3RCeU1vdXNlOiB0cnVlOyBlbmFibGVkOiAhcm9vdC5idXN5ICYmICFyb290LnR1bm5lbC5ydW5uaW5nIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiByb290LnRva2VuTG9ja2Vk'
    'ID8gItCY0LfQvNC10L3QuNGC0YwiIDogItCf0L7QtNGC0LLQtdGA0LTQuNGC0YwiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5i'
    'dXN5ICYmICFyb290LnR1bm5lbC5ydW5uaW5nICYmIChyb290LnRva2VuTG9ja2VkIHx8IC9eRVZOMS1bQS1aYS16MC05Xy1d'
    'ezQzfSQvLnRlc3QodG9rZW5JbnB1dC50ZXh0LnRyaW0oKSkpOyBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGlmIChyb290LnRva2VuTG9ja2VkKSByb290LnRva2VuRWRpdGluZyA9IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2Ugcm9vdC5hY3Rpb24oe2FjdGlvbjogInRva2VuLXNhdmUi'
    'LCB0b2tlbjogdG9rZW5JbnB1dC50ZXh0LnRyaW0oKX0sIGZ1bmN0aW9uKCkgeyB0b2tlbklucHV0LmNsZWFyKCk7IHJvb3Qu'
    'dG9rZW5FZGl0aW5nID0gZmFsc2UgfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyB2aXNpYmxlOiByb290LnRva2VuRWRpdGluZzsgbGFi'
    'ZWw6ICLQntGC0LzQtdC90LAiOyBvbkNsaWNrZWQ6IHsgdG9rZW5JbnB1dC5jbGVhcigpOyByb290LnRva2VuRWRpdGluZyA9'
    'IGZhbHNlIH0gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBDLkxhYmVsIHsgdGV4dDogItCe0LTQuNC9INGC0L7QutC10L0g0L3QsCDRh9C10LvQvtCy0LXQutCwIOKAlCDQtNC7'
    '0Y8g0LLRgdC10YUg0LXQs9C+INGD0YHRgtGA0L7QudGB0YLQsi4iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'IEZsYXRCdXR0b24geyBsYWJlbDogItCe0YLRh9GR0YIg0LTQu9GPINC/0L7QtNC00LXRgNC20LrQuCI7IGVuYWJsZWRCdXR0'
    'b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZzsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9u'
    'OiJyZXBvcnQtcHJldmlldyJ9LGZ1bmN0aW9uKHJlcGx5KXsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXBv'
    'cnQ9SlNPTi5wYXJzZShyZXBseS5vdXRwdXQpO3Jvb3QucmVwb3J0SWQ9cmVwb3J0LnJlcG9ydF9pZDtyb290LnJlcG9ydFRl'
    'eHQ9SlNPTi5zdHJpbmdpZnkocmVwb3J0LG51bGwsMik7cmVwb3J0Q29uc2VudC5jaGVja2VkPWZhbHNlO3N1cHBvcnREaWFs'
    'b2cub3BlbigpCiAgICAgICAgICAgICAgICAgICAgICAgIH0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRv'
    'biB7IGxhYmVsOiAi0J/RgNC+0LLQtdGA0LjRgtGMINC+0LHQvdC+0LLQu9C10L3QuNGPIjsgZW5hYmxlZEJ1dHRvbjogIXJv'
    'b3QuYnVzeTsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAidXBkYXRlIn0pIH0KICAgICAgICAgICAgICAgICAg'
    'ICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTog'
    'cm9vdC5wYWdlSW5kZXggPj0gMSAmJiByb290LnBhZ2VJbmRleCA8PSA0CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91'
    'dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTYKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBj'
    'b2xvcjogcm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QucGFnZUluZGV4ID09'
    'PSAxID8gItCS0YvQsdGA0LDQvdC90YvQtSDQv9GA0LjQu9C+0LbQtdC90LjRjyDQv9C+0LTQutC70Y7Rh9Cw0Y7RgtGB0Y8g'
    '0L3QsNC/0YDRj9C80YPRji4g0J7RgdGC0LDQu9GM0L3Ri9C1INC40YHQv9C+0LvRjNC30YPRjtGCIFZQTi4iIDogcm9vdC5w'
    'YWdlSW5kZXggPT09IDIgPyAi0JTQvtCx0LDQstGM0YLQtSDQtNC+0LzQtdC9LCDQsNC00YDQtdGBINC40LvQuCDQv9C+0LTR'
    'gdC10YLRjC4g0JTQvtC80LXQvdGLINCy0LrQu9GO0YfQsNGO0YIg0L/QvtC00LTQvtC80LXQvdGLOyDQt9C90LDQuiA9INC3'
    '0LDQtNCw0ZHRgiDRgtC+0YfQvdC+0LUg0YHQvtCy0L/QsNC00LXQvdC40LUuINCf0YDQuCDQvtCx0YnQtdC8IElQINC70YPR'
    'h9GI0LUg0YPQutCw0LfRi9Cy0LDRgtGMINC00L7QvNC10L0uIiA6IHJvb3QucGFnZUluZGV4ID09PSAzID8gItCY0YHRhdC+'
    '0LTRj9GJ0LjQtSDigJQg0L/QvtC00LrQu9GO0YfQtdC90LjRjyDQuiDRg9C60LDQt9Cw0L3QvdC+0LzRgyDQv9C+0YDRgtGD'
    'LiDQktGF0L7QtNGP0YnQuNC1IOKAlCDQv9GA0Y/QvNGL0LUg0L7RgtCy0LXRgtGLINCy0LDRiNC10LPQviDRgdC10YDQstC1'
    '0YDQsC4g0J7QsdCwIOKAlCDQvtCx0LAg0L3QsNC/0YDQsNCy0LvQtdC90LjRjy4iIDogItCe0LHRi9GH0L3Ri9C5IEROUyDQ'
    'vtGB0YLQsNGR0YLRgdGPINCyIFZQTi4g0JTQvtCx0LDQstC70LXQvdC90YvQtSDQt9C00LXRgdGMIEROUy3RgdC10YDQstC1'
    '0YDRiyDQv9C+0LvRg9GH0LDRjtGCINC30LDQv9GA0L7RgdGLINC90LDQv9GA0Y/QvNGD0Y4g0Lgg0LzQvtCz0YPRgiDQstC4'
    '0LTQtdGC0Ywg0LfQsNC/0YDQsNGI0LjQstCw0LXQvNGL0LUg0LjQvNC10L3QsC4g0K3RgtC+INC90LUg0YHQv9C40YHQvtC6'
    'INGB0LDQudGC0L7Qsi4iCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5'
    'b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEMuQ29tYm9Cb3ggeyBpZDogcG9ydFByb3RvY29sOyB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0g'
    'MzsgbW9kZWw6IFsiVENQIiwgIlVEUCIsICJCT1RIIl07IExheW91dC5wcmVmZXJyZWRXaWR0aDogMTAwIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IGV4Y2VwdGlvbklucHV0OyBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlOyBzZWxlY3RCeU1vdXNlOiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6IHJvb3QucGFnZUluZGV4ID09PSAxID8gItCY0LzR'
    'jyDQv9GA0L7RhtC10YHRgdCwINC40LvQuCAv0L/QvtC70L3Ri9C5L9C/0YPRgtGMIiA6IHJvb3QucGFnZUluZGV4ID09PSAy'
    'ID8gImV4YW1wbGUuY29tINC40LvQuCAxOTIuMTY4LjEuMjAiIDogcm9vdC5wYWdlSW5kZXggPT09IDMgPyAiMjU1NjUiIDog'
    'ItCQ0LTRgNC10YEgRE5TLCDQvdCw0L/RgNC40LzQtdGAIDE5Mi4xNjguMS4xIiB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBDLkNvbWJvQm94IHsgaWQ6IHBvcnREaXJlY3Rpb247IHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSAzOyBtb2Rl'
    'bDogWyLQmNGB0YXQvtC00Y/RidC40LUiLCAi0JLRhdC+0LTRj9GJ0LjQtSIsICLQntCx0LAiXTsgTGF5b3V0LnByZWZlcnJl'
    'ZFdpZHRoOiAxNDAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0JTQvtCx0LDQ'
    'stC40YLRjCI7IHByaW1hcnk6IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgZXhjZXB0aW9uSW5wdXQudGV4'
    'dC50cmltKCkubGVuZ3RoID4gMDsgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qg'
    'dmFsdWUgPSByb290LnBhZ2VJbmRleCA9PT0gMyA/IHBvcnRQcm90b2NvbC5jdXJyZW50VGV4dC50b0xvd2VyQ2FzZSgpICsg'
    'IjoiICsgZXhjZXB0aW9uSW5wdXQudGV4dC50cmltKCkgKyAiOiIgKyBbIm91dCIsICJpbiIsICJib3RoIl1bcG9ydERpcmVj'
    'dGlvbi5jdXJyZW50SW5kZXhdIDogZXhjZXB0aW9uSW5wdXQudGV4dC50cmltKCkKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICByb290LmFjdGlvbih7YWN0aW9uOiAiYWRkIiwgY2F0ZWdvcnk6IHJvb3QuY2F0ZWdvcnksIHZhbHVlOiB2YWx1'
    'ZX0sIGZ1bmN0aW9uKCkgeyBleGNlcHRpb25JbnB1dC5jbGVhcigpIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBtb2RlbDogcm9vdC5wb2xpY3lbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJl'
    'cXVpcmVkIHByb3BlcnR5IHN0cmluZyBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQu'
    'ZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0'
    'YTsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcEFueXdoZXJlOyBjb2xvcjogcm9vdC50ZXh0'
    'TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0KPQtNCw0LvQuNGC'
    '0YwiOyBkYW5nZXI6IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2Fj'
    'dGlvbjogInJlbW92ZSIsIGNhdGVnb3J5OiByb290LmNhdGVnb3J5LCB2YWx1ZTogbW9kZWxEYXRhfSkgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgeyB2aXNpYmxlOiAhKHJvb3QucG9saWN5W3Jvb3QuY2F0ZWdvcnldIHx8IFtdKS5sZW5ndGg7IHRleHQ6ICLQktCw'
    '0YjQuNGFINC40YHQutC70Y7Rh9C10L3QuNC5INC/0L7QutCwINC90LXRgiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuU3dpdGNoIHsgdGV4dDogItCe0YLQvtCx0YDQsNC30LjRgtGMINCx0LDQt9C+0LLR'
    'i9C1INC40YHQutC70Y7Rh9C10L3QuNGPIjsgY2hlY2tlZDogcm9vdC5zaG93QmFzZTsgb25Ub2dnbGVkOiByb290LnNob3dC'
    'YXNlID0gY2hlY2tlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiBy'
    'b290LnNob3dCYXNlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgbW9kZWw6IChyb290LnBvbGljeS5iYXNlIHx8IHt9KVtyb290LmNhdGVnb3J5XSB8fCBbXQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJl'
    'bCB7IHRleHQ6IG1vZGVsRGF0YS5sYWJlbDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsg'
    'Y29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlN3aXRjaCB7IGNo'
    'ZWNrZWQ6IEJvb2xlYW4obW9kZWxEYXRhLmVuYWJsZWQpOyBlbmFibGVkOiAhcm9vdC5idXN5OyBvblRvZ2dsZWQ6IHJvb3Qu'
    'YWN0aW9uKHthY3Rpb246ICJiYXNlIiwgY2F0ZWdvcnk6IHJvb3QuY2F0ZWdvcnksIHZhbHVlOiBtb2RlbERhdGEuaWQsIGVu'
    'YWJsZWQ6IGNoZWNrZWR9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7'
    'IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRlZDsgdGV4dDogItCS0Ysg0LzQvtC20LXRgtC1INCy'
    '0YvQutC70Y7Rh9C40YLRjCDQu9GO0LHQvtC1INCx0LDQt9C+0LLQvtC1INC/0YDQsNCy0LjQu9C+LiDQodC60YDRi9GC0LjQ'
    'tSDRgdC/0LjRgdC60LAg0L3QtSDQvNC10L3Rj9C10YIg0LXQs9C+INGB0L7RgdGC0L7Rj9C90LjQtS4iIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDEKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JfQsNC/'
    '0YPRidC10L3RiyDRgdC10LnRh9Cw0YEiOyBmb250LnBpeGVsU2l6ZTogMTg7IGZvbnQuYm9sZDogdHJ1ZTsgY29sb3I6IHJv'
    'b3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5U'
    'ZXh0RmllbGQgeyBpZDogYXBwU2VhcmNoOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6ICLQn9C+'
    '0LjRgdC6INC/0YDQuNC70L7QttC10L3QuNGPIiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRv'
    'biB7IGxhYmVsOiAi0J7QsdC90L7QstC40YLRjCDRgdC/0LjRgdC+0LoiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5ydW5uaW5n'
    'UGVuZGluZzsgb25DbGlja2VkOiByb290LnJlZnJlc2hSdW5uaW5nKCkgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IG1vZGVsOiByb290LnBhZ2VJbmRleCA9PT0gMSA/IHJvb3QuZmlsdGVyZWRSdW5uaW5nKCkgOiBbXQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBtb2RlbERhdGEubmFtZTsgY29sb3I6'
    'IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6'
    'IG1vZGVsRGF0YS5leGU7IExheW91dC5maWxsV2lkdGg6IHRydWU7IGVsaWRlOiBUZXh0LkVsaWRlTWlkZGxlOyBjb2xvcjog'
    'cm9vdC50ZXh0TXV0ZWQ7IGZvbnQucGl4ZWxTaXplOiAxMSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiBtb2RlbERhdGEuZXhj'
    'bHVkZWQgPyAi0JTQvtCx0LDQstC70LXQvdC+IiA6ICLQkiDQvtCx0YXQvtC0IjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVz'
    'eSAmJiAhbW9kZWxEYXRhLmV4Y2x1ZGVkOyBvbkNsaWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJhZGQiLCBjYXRlZ29y'
    'eTogImFwcGxpY2F0aW9ucyIsIHZhbHVlOiBTdHJpbmcobW9kZWxEYXRhLmV4ZSB8fCBtb2RlbERhdGEubmFtZSB8fCAiIil9'
    'KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIENvbHVtbkxh'
    'eW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSA1CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0'
    'LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRlZDsgdGV4dDogIldheWRyb2lkINGD0L/RgNCw0LLQu9GP0LXRgtGB0Y8g0L7R'
    'gtC00LXQu9GM0L3QviDQvtGCINC/0YDQuNC70L7QttC10L3QuNC5INC60L7QvNC/0YzRjtGC0LXRgNCwLiDQn9C+INGD0LzQ'
    'vtC70YfQsNC90LjRjiDQstC10YHRjCDQtdCz0L4g0YLRgNCw0YTQuNC6LCDQstC60LvRjtGH0LDRjyBETlMsINC40LTRkdGC'
    'INC90LDQv9GA0Y/QvNGD0Y4uIiB9CiAgICAgICAgICAgICAgICAgICAgICAgIEMuU3dpdGNoIHsgdGV4dDogIldheWRyb2lk'
    'INCyINC+0LHRhdC+0LQgVlBOIjsgY2hlY2tlZDogcm9vdC5wb2xpY3kud2F5ZHJvaWRfZGlyZWN0ICE9PSBmYWxzZTsgZW5h'
    'YmxlZDogIXJvb3QuYnVzeTsgb25Ub2dnbGVkOiByb290LmFjdGlvbih7YWN0aW9uOiAid2F5ZHJvaWQiLCBlbmFibGVkOiBj'
    'aGVja2VkfSkgfQogICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3Jh'
    'cE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiByb290LnBvbGljeS53YXlkcm9pZF9kaXJl'
    'Y3QgIT09IGZhbHNlID8gItCf0YDRj9C80L7QtSDQv9C+0LTQutC70Y7Rh9C10L3QuNC1OiBXYXlkcm9pZCDQuNGB0L/QvtC7'
    '0YzQt9GD0LXRgiDQsNC00YDQtdGBINCy0LDRiNC10LPQviDQv9GA0L7QstCw0LnQtNC10YDQsC4g0J7QsdGJ0LjQtSDQuNGB'
    '0LrQu9GO0YfQtdC90LjRjyDQvdC1INC+0LPRgNCw0L3QuNGH0LjQstCw0Y7RgiDRjdGC0L7RgiDRgNC10LbQuNC8LiIgOiAi'
    'V2F5ZHJvaWQg0LjRgdC/0L7Qu9GM0LfRg9C10YIgVlBOLiDQn9GA0Lgg0L7QsdGA0YvQstC1INGC0YPQvdC90LXQu9GPINC1'
    '0LPQviDQstC90LXRiNC90LjQtSDQv9C+0LTQutC70Y7Rh9C10L3QuNGPINCx0LvQvtC60LjRgNGD0Y7RgtGB0Y8uIiB9CiAg'
    'ICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQp9Cg=='
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
    'cGxhdGZvcm0KaW1wb3J0IHVybGxpYi5yZXF1ZXN0CmltcG9ydCBzc2wKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHRpbWUK'
    'aW1wb3J0IHN5cwoKUk9PVCA9IFBhdGgoJy9ldGMvdnBuLW1hbmFnZXIvc3RhcmZpdmUtdHVubmVsJykKUlVOVElNRSA9IFBh'
    'dGgoJy9ydW4vZXZnZW5pdW0tc3RhcmZpdmUtdHVubmVsJykKU1RBVEUgPSBQYXRoKCcvdmFyL2xpYi92cG4tbWFuYWdlci9z'
    'dGFyZml2ZS10dW5uZWwuanNvbicpClVOSVQgPSAnZXZnZW5pdW0tc3RhcmZpdmUtdHVubmVsLnNlcnZpY2UnCk5TID0gJ2V2'
    'bi1zdGFyZml2ZScKSE9TVCA9ICdldm4tc2YtaG9zdCcKUEVFUiA9ICdldm4tc2YtcGVlcicKTkVUV09SSyA9ICcxNzIuMjku'
    'MjQ2LjAvMzAnCkNMSUVOVCA9ICcxNzIuMjkuMjQ2LjInCkdBVEVXQVkgPSAnMTcyLjI5LjI0Ni4xJwpUQUJMRSA9IDUxODI0'
    'ClBSSU9SSVRZID0gNzUKTkZUID0gJ2V2Z2VuaXVtX3N0YXJmaXZlX2xhYl9ob3N0JwpTRVJWRVIgPSAnMTk1LjIwOS4yMTEu'
    'MTYzJwpJS0VfUE9SVCA9IDI0NTUwCkVORFBPSU5UUyA9IChTRVJWRVIsICczOC4xODAuMTY0LjY3JykKQ0FORElEQVRFUyA9'
    'ICgKIHsnaWQnOidydS11ZHAnLCdhZGRyZXNzJzpTRVJWRVIsJ2lkZW50aXR5JzpTRVJWRVIsJ3BvcnQnOjI0NTUwLCd0bHMn'
    'OkZhbHNlLCdsYWJlbCc6J0hTVkRTIOKGkiDQrdGB0YLQvtC90LjRjyd9LAogeydpZCc6J2VlLXVkcCcsJ2FkZHJlc3MnOicz'
    'OC4xODAuMTY0LjY3JywnaWRlbnRpdHknOiczOC4xODAuMTY0LjY3JywncG9ydCc6NDQzLCd0bHMnOkZhbHNlLCdsYWJlbCc6'
    'J9Ct0YHRgtC+0L3QuNGPINC90LDQv9GA0Y/QvNGD0Y4nfSwKIHsnaWQnOidlZS10bHMnLCdhZGRyZXNzJzonMzguMTgwLjE2'
    'NC42NycsJ2lkZW50aXR5JzonMzguMTgwLjE2NC42NycsJ3BvcnQnOjQ0MywndGxzJzpUcnVlLCdsYWJlbCc6J9Ct0YHRgtC+'
    '0L3QuNGPINGH0LXRgNC10LcgVExTJ30sCiB7J2lkJzonZWUtZXZndCcsJ2FkZHJlc3MnOiczOC4xODAuMTY0LjY3JywnaWRl'
    'bnRpdHknOiczOC4xODAuMTY0LjY3JywncG9ydCc6NDQzLCd0bHMnOkZhbHNlLCdldmd0JzpUcnVlLCdsYWJlbCc6J9Ct0YHR'
    'gtC+0L3QuNGPINGH0LXRgNC10LcgRXZnZW5pdW1UdW5uZWwnfSwKKQpBQ1RJVkUgPSBDQU5ESURBVEVTWzBdCnJhbmtfYXBp'
    'ID0gTm9uZQpzdXBwb3J0X2FwaSA9IE5vbmUKdGxzX2FwaSA9IE5vbmUKVExTX1BST0NFU1MgPSBOb25lCiMgS2VwdCBvbmx5'
    'IGZvciByZW1vdmluZyByb3V0ZXMgaW5zdGFsbGVkIGJ5IHByZS1taWdyYXRpb24gdmVyc2lvbnMuCkxFR0FDWV9FTkRQT0lO'
    'VFMgPSAoJzEwOS4xOTQuNjcuMTU5JywgJzE5Mi4xNjguMC4xNjMnKQpIRUFMVEggPSAnMTAuNzcuMC4xJwpSRVFJRCA9IDE3'
    'NwpUT0tFTl9QQVRURVJOID0gcidFVk4xLVtBLVphLXowLTlfLV17NDN9JwpTVE9QID0gRmFsc2UKRE5TX1BST0NFU1MgPSBO'
    'b25lCnBvbGljeSA9IE5vbmUKUElOTkVEX0NBID0gJy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRU9EQ0NBcUNn'
    'QXdJQkFnSVVia0orOFNhcUFnd1kxUkRBalpSVGpjcVE5ZU13RFFZSktvWklodmNOQVFFTFxuQlFBd0lqRWdNQjRHQTFVRUF3'
    'd1hSWFpuWlc1cGRXMGdjSEpwZG1GMFpTQldVRTRnUTBFd0hoY05Nall4TURBM1xuTVRreE16UXhXaGNOTXpZeE1EQTBNVGt4'
    'TXpReFdqQWlNU0F3SGdZRFZRUUREQmRGZG1kbGJtbDFiU0J3Y21sMlxuWVhSbElGWlFUaUJEUVRDQ0FhSXdEUVlKS29aSWh2'
    'Y05BUUVCQlFBRGdnR1BBRENDQVlvQ2dnR0JBT1orbnZpRVxuMk9yRjdQZHRray9YSWFGVkl2Smx2QzExVlpmOXJsakNCSXZC'
    'eWtic3JBckdyeVFIR251dVhMTmFhUzhOdEx4WVxuTmVTQkRLNk1kZ1lKQWVqc1A0d0lUdWIzbk1qU0cydW1JSVZVNm1FK0dE'
    'b3pHUGxOTU5KK2Joa0thVmhhUGpGRVxueVlMWXJkUGU1VkE0dys1cDBOWk9ENkNCSEQzdEVYV0JOUkllVlNXYnRNSVRzT0VT'
    'MVBlL2FBTDd2M29OSVZrVlxuOG5EdzlqNyt3RzJ5NWRoYnA3S1VKSGJyREIwMjRyN2NZclEzYXhZRjZneWtqbXp0cEtYc2Jr'
    'eFF2MjdCdmhTQlxuZTBFa3RKL2pDUzZSOUlJbVlnSVFyQ3JhV1ptVlNjbkdGL0FxNFROdzFINE96RkNrUis3SlVsWW5TWVV2'
    'TVJpMVxuTHpLZWtVQysyLzBXRm1obkNvRHRkamNvWWJ4cExwS0RlbEdpUzNSc05Ddnhuc2xNYVB6NWhDY0Y2NFk3UmlqWFxu'
    'ajZEdUNZcEZZV2xyMTNCMjBxQW5Sb1VhcytBalg3UFhDa1I0eE9oSCtrVzgvSG1GSGlIa29oV0Uwd2xsSVNCWFxuVkJvN0tC'
    'T1pkOFNWZXd5YmQyckI0c29Yb3VUdGpYcy9qVGdlK0hXeFFER1BQMXVtZno4Y0ZMUi91UUlEQVFBQlxubzJZd1pEQWRCZ05W'
    'SFE0RUZnUVVvUWZUaWY3N3hXdDA2aGFYaDNoYTg5MHFrVDh3SHdZRFZSMGpCQmd3Rm9BVVxub1FmVGlmNzd4V3QwNmhhWGgz'
    'aGE4OTBxa1Q4d0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFEQU9CZ05WSFE4QlxuQWY4RUJBTUNBUVl3RFFZSktvWklodmNO'
    'QVFFTEJRQURnZ0dCQUk3R0tubWZKanVMMVF2eVJ0bHcrSHI2QVkvWlxuT3hkRHZFQ2Vmb0ZMN1E0MVZaYStMN0RJODdrTUxZ'
    'SHlnUkh1c2g2Nm9Vdjg3OFRXTXRhc25idC84d1lnNmpyd1xuQXlncGcvRjNWRDI0eVRybko3T0NkeUdpYjZMR3V1c3VUUDRy'
    'VUdzY2NXY3puUVhZRmt6UlZ6MVZlWU1aVU4rUFxudEFWaU5sNEVSUzFmaCtjR3pUNE9xWFFrSkRrUmVxSC9IQ1RFOGtVUVVV'
    'Z1hhU1hwaEtqR2E4cFIySFZlRnVrWFxuKzBwcDFpUis2ZGk0YUNLYXBrYVRpVlIzcjYydFJCVXdieG9GWVJ5eE5YeW5USzlF'
    'aG5NMjVXRXBuL3F1MGxzRFxub1hyRlZtajBBUWZBVUhSTi8yclBMLy93NlJQRXBIZ1VjcnQ3enVTZ29YSlpoMERUMzBWRUlL'
    'OU5OYnVLU0ZkOVxuSWlXdnJ4YlZRUzZtUWd0RVpONExjMkhtMXB2WStXckkrSDAzdTgwNDIrY3BMSXNDbnhQbTlXdmk3ZE1Y'
    'eHFvYlxubzIvYUwyeERHNUcvOFdWUi9XNUVBZnZLZHhkcmszSDYwMm9jY292NytKZzF2b3hpMDBJYmRNRXhvTXhkNWFlaFxu'
    'ZlhSaUpoVEVGb3VJcG1FU0NGNHZWTWxXRnIzbXFsUTNHS1NQVkE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuJwoK'
    'CkZVTExfSE9TVCA9ICdldm4tZnVsbC1ob3N0JwpGVUxMX1BFRVIgPSAnZXZuLWZ1bGwtcGVlcicKRlVMTF9ORVQgPSAnMTcy'
    'LjI5LjI0Ny4wLzMwJwpGVUxMX1RBQkxFID0gJzUxODI4JwpBRE1JTl9UQUJMRSA9ICc1MTgyOScKRlVMTF9HVUFSRCA9ICdl'
    'dm5fc3RhcmZpdmVfZnVsbCcKZGVmIGZ1bGxfc3RhdGUoKToKICAgIHJldHVybiBST09ULydmdWxsLW5ldHdvcmsuanNvbicK'
    'CgpkZWYgY2hhcm9uX2JpbmFyeSgpOgogICAgY2FuZGlkYXRlcyA9ICgnL3Vzci9zYmluL2NoYXJvbi1zeXN0ZW1kJywgJy91'
    'c3IvYmluL2NoYXJvbi1zeXN0ZW1kJywKICAgICAgICAgICAgICAgICAgJy91c3IvbGliL2lwc2VjL2NoYXJvbi1zeXN0ZW1k'
    'JywgJy91c3IvbGliZXhlYy9pcHNlYy9jaGFyb24tc3lzdGVtZCcsCiAgICAgICAgICAgICAgICAgICcvdXNyL2xpYi9zdHJv'
    'bmdzd2FuL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvbGliZXhlYy9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0ZW1kJykKICAgIHJl'
    'dHVybiBuZXh0KChwIGZvciBwIGluIGNhbmRpZGF0ZXMgaWYgUGF0aChwKS5pc19maWxlKCkpLCBOb25lKQoKCkVWR1RfVkVS'
    'U0lPTiA9ICcwLjIuMCcKRVZHVF9BU1NFVFMgPSB7CiAneDg2XzY0JzogKCdhbWQ2NCcsJzNmZmFmNjdiZDgxZDg1ZGQyODk0'
    'MmRiMGM3M2E2MDhjMDdmZTBhNWNhOGIyYWE1YTljM2RiYTFiYzc3MjA3NDQnKSwKICdhYXJjaDY0JzogKCdhcm02NCcsJzQ1'
    'OGY3N2I2YTU5NmI2NGY5ODQ2NTg3ZDQyMDhhZTk3YTczNjJkZjRmZTFkYmVmNmQyYTM2NGVhY2YwNzBjZTgnKSwKICdyaXNj'
    'djY0JzogKCdyaXNjdjY0JywnNTk1MmNiNTY3NzNhMTQ2MGJhMDFlZmQwYWYzNzhiNTAwZjUzZDBmNGZjYWM4MWIxZmU3OGIx'
    'YjM5ZDYyYTJiYicpLAp9CgpkZWYgZW5zdXJlX2V2Z3RfYmluYXJ5KCk6CiAgICBhc3NldD1FVkdUX0FTU0VUUy5nZXQocGxh'
    'dGZvcm0ubWFjaGluZSgpKQogICAgaWYgYXNzZXQgaXMgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ2V2Z3RfYXJjaF91bnN1'
    'cHBvcnRlZCcpCiAgICBhcmNoLGRpZ2VzdD1hc3NldAogICAgcGF0aD1ST09ULygnZXZnZW5pdW0tdHVubmVsLScrRVZHVF9W'
    'RVJTSU9OKQogICAgaWYgcGF0aC5pc19zeW1saW5rKCk6cmFpc2UgUnVudGltZUVycm9yKCdldmd0X2JpbmFyeV9zeW1saW5r'
    'JykKICAgIGlmIHBhdGguaXNfZmlsZSgpIGFuZCBoYXNobGliLnNoYTI1NihwYXRoLnJlYWRfYnl0ZXMoKSkuaGV4ZGlnZXN0'
    'KCk9PWRpZ2VzdDoKICAgICAgICBwYXRoLmNobW9kKDBvNzAwKTtyZXR1cm4gcGF0aAogICAgUk9PVC5ta2Rpcihtb2RlPTBv'
    'NzAwLHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgdXJsPSdodHRwczovL2dpdGh1Yi5jb20vdmVsaWtpaWV2Z2Vu'
    'aXVzdWx0aW1hdGUvRXZnZW5pdW1fTmV0d29ya19MaW51eC9yZWxlYXNlcy9kb3dubG9hZC9ldmdlbml1bS10dW5uZWwtdicr'
    'RVZHVF9WRVJTSU9OKycvZXZnZW5pdW0tdHVubmVsLWxpbnV4LScrYXJjaAogICAgd2l0aCB1cmxsaWIucmVxdWVzdC51cmxv'
    'cGVuKHVybCx0aW1lb3V0PTMwKSBhcyByZXNwb25zZTpibG9iPXJlc3BvbnNlLnJlYWQoMTYqMTAyNCoxMDI0KzEpCiAgICBp'
    'ZiBsZW4oYmxvYik+MTYqMTAyNCoxMDI0IG9yIGhhc2hsaWIuc2hhMjU2KGJsb2IpLmhleGRpZ2VzdCgpIT1kaWdlc3Q6CiAg'
    'ICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdldmd0X2JpbmFyeV9jaGVja3N1bV9mYWlsZWQnKQogICAgdG1wPXBhdGgud2l0'
    'aF9uYW1lKHBhdGgubmFtZSsnLm5ldycpCiAgICBmZD1vcy5vcGVuKHRtcCxvcy5PX1dST05MWXxvcy5PX0NSRUFUfG9zLk9f'
    'VFJVTkN8b3MuT19OT0ZPTExPVywwbzcwMCkKICAgIHRyeToKICAgICAgICB3aXRoIG9zLmZkb3BlbihmZCwnd2InKSBhcyBv'
    'dXRwdXQ6b3V0cHV0LndyaXRlKGJsb2IpO291dHB1dC5mbHVzaCgpO29zLmZzeW5jKG91dHB1dC5maWxlbm8oKSkKICAgICAg'
    'ICBvcy5jaG1vZCh0bXAsMG83MDApO29zLnJlcGxhY2UodG1wLHBhdGgpCiAgICBmaW5hbGx5OnRtcC51bmxpbmsobWlzc2lu'
    'Z19vaz1UcnVlKQogICAgcmV0dXJuIHBhdGgKCgpkZWYgZW5zdXJlX2RlcGVuZGVuY2llcygpOgogICAgaWYgY2hhcm9uX2Jp'
    'bmFyeSgpIGFuZCBhbGwoc2h1dGlsLndoaWNoKHApIGZvciBwIGluICgnc3dhbmN0bCcsJ2lwJywnbmZ0JywnY3VybCcsJ29w'
    'ZW5zc2wnLCdjb25udHJhY2snKSk6CiAgICAgICAgZW5zdXJlX2V2Z3RfYmluYXJ5KCkKICAgICAgICByZXR1cm4KICAgIHN0'
    'YWdlKCdkZXBlbmRlbmNpZXMnLCAn0KPRgdGC0LDQvdCw0LLQu9C40LLQsNGOINC90LXQvtCx0YXQvtC00LjQvNGL0LUg0YHQ'
    'uNGB0YLQtdC80L3Ri9C1INC60L7QvNC/0L7QvdC10L3RgtGLIFZQTi4nLCAzLCBhY3RpdmU9RmFsc2UpCiAgICBpZiBzaHV0'
    'aWwud2hpY2goJ3BhY21hbicpOgogICAgICAgIGFyZ3MgPSBbJ3BhY21hbicsJy1TJywnLS1uZWVkZWQnLCctLW5vY29uZmly'
    'bScsJ3N0cm9uZ3N3YW4nLCdpcHJvdXRlMicsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMn'
    'LCdjb25udHJhY2stdG9vbHMnXQogICAgZWxpZiBzaHV0aWwud2hpY2goJ2RuZicpOgogICAgICAgIGFyZ3MgPSBbJ2RuZics'
    'J2luc3RhbGwnLCcteScsJy0tc2V0b3B0PWluc3RhbGxfd2Vha19kZXBzPUZhbHNlJywnc3Ryb25nc3dhbicsJ2lwcm91dGUn'
    'LCduZnRhYmxlcycsJ2N1cmwnLCdvcGVuc3NsJywnY2EtY2VydGlmaWNhdGVzJywnY29ubnRyYWNrLXRvb2xzJ10KICAgIGVs'
    'c2U6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQkNCy0YLQvtC80LDRgtC40YfQtdGB0LrQsNGPINGD0YHRgtCw0L3Q'
    'vtCy0LrQsCDQutC70LjQtdC90YLQsCDQv9C+0LTQtNC10YDQttC40LLQsNC10YIgQXJjaCDQuCBGZWRvcmEuJykKICAgIGNv'
    'bW1hbmQoYXJncywgdGltZW91dD0zMDApCiAgICBpZiBub3QgY2hhcm9uX2JpbmFyeSgpIG9yIG5vdCBhbGwoc2h1dGlsLndo'
    'aWNoKHApIGZvciBwIGluICgnc3dhbmN0bCcsJ2Nvbm50cmFjaycpKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cf'
    '0LDQutC10YIgc3Ryb25nU3dhbiDQvdC1INC/0YDQtdC00L7RgdGC0LDQstC40Lsg0L3QtdC+0LHRhdC+0LTQuNC80YvQtSDQ'
    'v9GA0L7Qs9GA0LDQvNC80YsuJykKICAgIGVuc3VyZV9ldmd0X2JpbmFyeSgpCgoKZGVmIGNsZWFyX2Ruc19tYXBwaW5ncyhw'
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
    'ZXR1cm5jb2RlID09IDAKCgpkZWYgZnVsbF9maXJld2FsbCgpOgogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAg'
    'IHNldHRpbmdzPXBvbGljeS5hcGkubG9hZF9zZXR0aW5ncygpCiAgICAgICAgcmV0dXJuIHBvbGljeS5maXJld2FsbChwb2xp'
    'Y3kubG9hZCgpLHBvbGljeS5sb2NhbF9uZXR3b3JrcyhwaHlzaWNhbF9yb3V0ZSgpKSxpbnQoc2V0dGluZ3NbInhyYXlfdWlk'
    'Il0pKQogICAgIyBNaW5pbWFsIGd1YXJkIHVzZWQgYnkgaXNvbGF0ZWQgcHJvdG9jb2wgdGVzdHMuCiAgICAjIEtlZXAgbG9j'
    'YWwgc3R1YiBETlMgb24gbG9vcGJhY2suIEROQVQgb2YgMTI3Lzggb250byBhIHZldGggZmFpbHMgTGludXgncwogICAgIyBs'
    'b29wYmFjayByb3V0ZSBjaGVja3M7IHVwc3RyZWFtIHJlc29sdmVyIHRyYWZmaWMgc3RpbGwgb2JleXMgdGhlIGZ1bGwgZ3Vh'
    'cmQuCiAgICByZXR1cm4gZicnJ3RhYmxlIGluZXQge0ZVTExfR1VBUkR9IHt7CiBjaGFpbiBkbnMge3sgdHlwZSBuYXQgaG9v'
    'ayBvdXRwdXQgcHJpb3JpdHkgLTEwMTsgcG9saWN5IGFjY2VwdDsKICBpcCBkYWRkciAxMjcuMC4wLjAvOCByZXR1cm4KICBp'
    'cCBkYWRkciB7eyAxLjEuMS4xLCA5LjkuOS45IH19IHJldHVybgogIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbDRwcm90byB7'
    'eyB0Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBkbmF0IGlwIHRvIDEuMS4xLjEKIH19CiBjaGFpbiBzb3VyY2Uge3sgdHlwZSBu'
    'YXQgaG9vayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgbWV0YSBuZnByb3RvIGlwdjQg'
    'b2lmbmFtZSAie0ZVTExfSE9TVH0iIHNuYXQgaXAgdG8gMTcyLjI5LjI0Ny4xCiB9fQogY2hhaW4gb3V0cHV0IHt7IHR5cGUg'
    'ZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAogIG1l'
    'dGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBhY2NlcHQKICBpcCBkYWRkciAyNTUuMjU1LjI1NS4yNTUg'
    'dWRwIHNwb3J0IDY4IHVkcCBkcG9ydCA2NyBhY2NlcHQKIH19CiBjaGFpbiBmb3J3YXJkIHt7IHR5cGUgZmlsdGVyIGhvb2sg'
    'Zm9yd2FyZCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0g'
    'aXAgZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBp'
    'cCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHVkcCBkcG9ydCA0NDMgYWNjZXB0CiAgaWlmbmFtZSAi'
    'e0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1'
    'NzggfX0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSB9'
    'fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHtDTElFTlR9IGN0IHN0YXRlIGVz'
    'dGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2Vw'
    'dAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgIntGVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVk'
    'IGFjY2VwdAogfX0KfX0nJycKCgoKZGVmIHJlZnJlc2hfcmV0YWluZWRfZ3VhcmQoKToKICAgICIiIk1vdmUgb25seSB0aGUg'
    'VlBOIHRyYW5zcG9ydCBleGNlcHRpb24gd2hlbiBhbiBpbmdyZXNzIGVuZHBvaW50IGNoYW5nZXMuIiIiCiAgICBpZiBub3Qg'
    'ZnVsbF9ndWFyZF9hY3RpdmUoKToKICAgICAgICByZXR1cm4KICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICByZXBs'
    'YWNlbWVudCA9ICdkZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJytydWxlcwogICAgY29tbWFuZChbJ25mdCcs'
    'Jy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKICAgICMgUGVyc2lzdCB0aGUgY2xvc2VkIGd1YXJkIGJlZm9yZSBj'
    'aGFuZ2luZyB0aGUgYWN0aXZlIGV4Y2VwdGlvbjsgYSBjcmFzaCBzdGF5cyBjbG9zZWQuCiAgICB3cml0ZShST09ULydmdWxs'
    'LWd1YXJkLm5mdCcscnVsZXMpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKCgpkZWYg'
    'dmlydHVhbF9pcCgpOgogICAgZGF0YSA9IGpzb24ubG9hZHMoaW5zaWRlKFsnaXAnLCctaicsJy00JywnYWRkciddKS5zdGRv'
    'dXQpCiAgICBpcHMgPSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBkYXRhIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRyX2luZm8n'
    'LCBbXSkKICAgICAgICAgICBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhWydsb2NhbCddKSBpbiBpcGFkZHJlc3MuaXBfbmV0'
    'd29yaygnMTAuNzcuMC4wLzI0JyldCiAgICBpZiBsZW4oaXBzKSAhPSAxOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    'dmlydHVhbF9pcF9taXNzaW5nJykKICAgIHJldHVybiBpcHNbMF0KCgpkZWYgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcyk6CiAg'
    'ICB2aXAgPSB2aXJ0dWFsX2lwKCkKICAgIGlmIG5vdCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3Rz'
    'KCk6CiAgICAgICAgY29tbWFuZChbJ2lwJywnbGluaycsJ2FkZCcsRlVMTF9IT1NULCd0eXBlJywndmV0aCcsJ3BlZXInLCdu'
    'YW1lJyxGVUxMX1BFRVJdKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfUEVFUiwnbmV0bnMnLE5T'
    'XSkKICAgIGNvbW1hbmQoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4xLzMwJywnZGV2JyxGVUxMX0hPU1Rd'
    'KQogICAgY29tbWFuZChbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9IT1NULCdtdHUnLCcxMjgwJywndXAnXSkKICAgIGluc2lk'
    'ZShbJ2lwJywnYWRkcicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjIvMzAnLCdkZXYnLEZVTExfUEVFUl0pCiAgICBpbnNpZGUo'
    'WydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfUEVFUiwnbXR1JywnMTI4MCcsJ3VwJ10pCiAgICBpbnNpZGUoWydzeXNjdGwnLCct'
    'cXcnLCduZXQuaXB2NC5jb25mLmFsbC5mb3J3YXJkaW5nPTEnLCduZXQuaXB2NC5jb25mLmFsbC5ycF9maWx0ZXI9MCddKQog'
    'ICAgIyBTdHJvbmdTd2FuJ3MgY2F0Y2gtYWxsIHJvdXRlIG11c3Qgbm90IGNhcHR1cmUgcmVwbGllcyB0byB0aGUgaG9zdC1m'
    'YWNpbmcgaW50ZXJmYWNlLgogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc5MCcsJ3RvJyxGVUxM'
    'X05FVCwnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3Jp'
    'dHknLCc5MCcsJ3RvJyxGVUxMX05FVCwnbG9va3VwJywnbWFpbiddKQogICAgZGVsZXRpb25zID0gJycKICAgIGZvciBmYW1p'
    'bHksdGFibGUgaW4gWygnaW5ldCcsJ2V2bl9mdWxsX2ZvcndhcmQnKSwoJ25ldGRldicsJ2V2bl9mdWxsX3dpcmUnKV06CiAg'
    'ICAgICAgaWYgaW5zaWRlKFsnbmZ0JywnbGlzdCcsJ3RhYmxlJyxmYW1pbHksdGFibGVdLGNoZWNrPUZhbHNlKS5yZXR1cm5j'
    'b2RlID09IDA6CiAgICAgICAgICAgIGRlbGV0aW9ucyArPSBmJ2RlbGV0ZSB0YWJsZSB7ZmFtaWx5fSB7dGFibGV9XG4nCiAg'
    'ICBydWxlcyA9IGRlbGV0aW9ucyArIGYnJyd0YWJsZSBpbmV0IGV2bl9mdWxsX2ZvcndhcmQge3sKIGNoYWluIGZvcndhcmQg'
    'e3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC01OyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7RlVMTF9Q'
    'RUVSfSIgb2lmbmFtZSAie1BFRVJ9IiBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgYWNjZXB0CiAgaWlmbmFtZSB7eyAie1BFRVJ9'
    'IiwgImxvIiB9fSBvaWZuYW1lICJ7RlVMTF9QRUVSfSIgaXAgZGFkZHIgMTcyLjI5LjI0Ny4xIGlwc2VjIGluIHJlcWlkIHtS'
    'RVFJRH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKIH19CiBjaGFpbiBuYXQge3sgdHlwZSBuYXQgaG9v'
    'ayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2FkZHIgMTcyLjI5LjI0Ny4xIG9p'
    'Zm5hbWUgIntQRUVSfSIgc25hdCBpcCB0byB7dmlwfQogfX0KfX0KdGFibGUgbmV0ZGV2IGV2bl9mdWxsX3dpcmUge3sKIGNo'
    'YWluIGVncmVzcyB7eyB0eXBlIGZpbHRlciBob29rIGVncmVzcyBkZXZpY2UgIntQRUVSfSIgcHJpb3JpdHkgMDsgcG9saWN5'
    'IGRyb3A7CiAgZXRoZXIgdHlwZSBhcnAgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydw'
    'b3J0J119IGFjY2VwdAogIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2Nl'
    'cHQKICBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiB9fQp9fScnJwogICAgaW5zaWRlKFsnbmZ0'
    'JywnLWMnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAg'
    'ICMgUmVwbGFjZSB0aGUgb3JpZ2luYWwgbGFiIGZvcndhcmQgZHJvcDsgaG9zdCBpbmdyZXNzIHJlbWFpbnMgY29uc3RyYWlu'
    'ZWQgYnkgZnVsbF9mb3J3YXJkLgogICAgaW5zaWRlKFsnbmZ0JywnZmx1c2gnLCdjaGFpbicsJ2luZXQnLCdldm5fc3RhcmZp'
    'dmVfZ3VhcmQnLCdmb3J3YXJkJ10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxlJywnaW5ldCcsJ2V2bl9zdGFyZml2'
    'ZV9ndWFyZCcsJ2ZvcndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21ldGEnLCduZnByb3RvJywnaXB2NCcsJ2FjY2VwdCdd'
    'KQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdmb3J3YXJkJywn'
    'b2lmbmFtZScsRlVMTF9QRUVSLCdpcHNlYycsJ2luJywncmVxaWQnLHN0cihSRVFJRCksJ2N0Jywnc3RhdGUnLCdlc3RhYmxp'
    'c2hlZCxyZWxhdGVkJywnYWNjZXB0J10pCgoKZGVmIGVncmVzc19oZWFsdGgoKToKICAgIGZvciB1cmwsZXhwZWN0ZWQgaW4g'
    'WygnaHR0cHM6Ly8xLjEuMS4xL2Nkbi1jZ2kvdHJhY2UnLCdpcD0zOC4xODAuMTY0LjY3JyksCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAoJ2h0dHBzOi8vYXBpLmlwaWZ5Lm9yZycsJzM4LjE4MC4xNjQuNjcnKV06CiAgICAgICAgcmVzdWx0ID0gaW5z'
    'aWRlKFsnY3VybCcsJy00JywnLS1ub3Byb3h5JywnKicsJy0tZmFpbCcsJy0tc2lsZW50JywnLS1zaG93LWVycm9yJywKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICctLWNvbm5lY3QtdGltZW91dCcsJzMnLCctLW1heC10aW1lJywnNScsdXJsXSx0aW1l'
    'b3V0PTcsY2hlY2s9RmFsc2UpCiAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGUgPT0gMCBhbmQgZXhwZWN0ZWQgaW4gcmVz'
    'dWx0LnN0ZG91dC5zcGxpdGxpbmVzKCk6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYg'
    'cmV0aXJlX3ByZXZpb3VzX2Nvbm5lY3Rpb25zKGFkZHJlc3Nlcyk6CiAgICAjIFRoZSBmaXJld2FsbCBhbHJlYWR5IGJsb2Nr'
    'cyBvbGQgbm9uLWV4ZW1wdCBmbG93cy4gRG8gbm90IGtpbGwgYWxsIHNvY2tldHMKICAgICMgc2hhcmluZyBhIHBoeXNpY2Fs'
    'IHNvdXJjZSBhZGRyZXNzOiB0aGF0IGRlc3Ryb3lzIFNTSCwgTEFOIGFuZCBhcHAgZXhjbHVzaW9ucy4KICAgICMgT25seSB0'
    'aGlzIG1hbmFnZXIncyBETlMgdHJhbnNsYXRpb25zIG5lZWQgZXhwbGljaXQgcmV0aXJlbWVudCAoaGFuZGxlZCBhYm92ZSku'
    'CiAgICByZXR1cm4KCgpkZWYgc3lzdGVtX2Ruc19oZWFsdGgocmVzb2x2X2NvbmY9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicp'
    'KToKICAgICMgZ2V0YWRkcmluZm8vY3VybCBtYXkgdXNlIG5zcy1yZXNvbHZlIG92ZXIgYSBVbml4IHNvY2tldCBhbmQgbWlz'
    'cyBhIGJyb2tlbgogICAgIyBVRFAgc3R1YiB1c2VkIGJ5IG90aGVyIGFwcGxpY2F0aW9ucy4gRXhlcmNpc2UgcmVzb2x2LmNv'
    'bmYgaW5kZXBlbmRlbnRseS4KICAgIHNlcnZlcnMgPSBbbGluZS5zcGxpdCgpWzFdIGZvciBsaW5lIGluIHJlc29sdl9jb25m'
    'LnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKQogICAgICAgICAgICAgICBpZiBsaW5lLnNwbGl0KClbOjFdID09IFsnbmFtZXNl'
    'cnZlciddIGFuZCBsZW4obGluZS5zcGxpdCgpKSA+PSAyXVs6M10KICAgIGZvciBzZXJ2ZXIgaW4gc2VydmVyczoKICAgICAg'
    'ICB0cnk6CiAgICAgICAgICAgIGZhbWlseSA9IHNvY2tldC5BRl9JTkVUNiBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhzZXJ2'
    'ZXIpLnZlcnNpb24gPT0gNiBlbHNlIHNvY2tldC5BRl9JTkVUCiAgICAgICAgICAgIHRyYW5zYWN0aW9uID0gc2VjcmV0cy50'
    'b2tlbl9ieXRlcygyKQogICAgICAgICAgICBxdWVyeSA9IHRyYW5zYWN0aW9uK2InXHgwMVx4MDBceDAwXHgwMVx4MDBceDAw'
    'XHgwMFx4MDBceDAwXHgwMCcKICAgICAgICAgICAgcXVlcnkgKz0gYidceDAzYXBpXHgwNWlwaWZ5XHgwM29yZ1x4MDBceDAw'
    'XHgwMVx4MDBceDAxJwogICAgICAgICAgICB3aXRoIHNvY2tldC5zb2NrZXQoZmFtaWx5LCBzb2NrZXQuU09DS19ER1JBTSkg'
    'YXMgcmVzb2x2ZXI6CiAgICAgICAgICAgICAgICByZXNvbHZlci5zZXR0aW1lb3V0KDIpCiAgICAgICAgICAgICAgICByZXNv'
    'bHZlci5jb25uZWN0KChzZXJ2ZXIsIDUzKSkKICAgICAgICAgICAgICAgIHJlc29sdmVyLnNlbmQocXVlcnkpCiAgICAgICAg'
    'ICAgICAgICBhbnN3ZXIgPSByZXNvbHZlci5yZWN2KDQwOTYpCiAgICAgICAgICAgIGlmIChsZW4oYW5zd2VyKSA+PSAxMiBh'
    'bmQgYW5zd2VyWzoyXSA9PSB0cmFuc2FjdGlvbiBhbmQKICAgICAgICAgICAgICAgICAgICBhbnN3ZXJbMl0gJiAweDgwIGFu'
    'ZCBhbnN3ZXJbM10gJiAxNSA9PSAwIGFuZAogICAgICAgICAgICAgICAgICAgIGludC5mcm9tX2J5dGVzKGFuc3dlcls2Ojhd'
    'LCAnYmlnJykgPiAwKToKICAgICAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1'
    'ZUVycm9yKToKICAgICAgICAgICAgY29udGludWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBzdGFydF9uYW1lc3BhY2VfZG5z'
    'KCk6CiAgICAiIiJBIHByaXZhdGUgRE5TIGVuZHBvaW50IHJlYWNoYWJsZSBvbmx5IG92ZXIgdGhlIGhvc3QvbmFtZXNwYWNl'
    'IHZldGguIiIiCiAgICBnbG9iYWwgRE5TX1BST0NFU1MKICAgIGlmIEROU19QUk9DRVNTIGlzIG5vdCBOb25lIGFuZCBETlNf'
    'UFJPQ0VTUy5wb2xsKCkgaXMgTm9uZTpyZXR1cm4KICAgIGNmZyA9IHsnbG9nJzp7J2xvZ2xldmVsJzond2FybmluZycsJ2Fj'
    'Y2Vzcyc6J25vbmUnfSwKICAgICAgJ2luYm91bmRzJzpbeyd0YWcnOidkbnMtaW4nLCdsaXN0ZW4nOicxNzIuMjkuMjQ3LjIn'
    'LCdwb3J0Jzo1MywncHJvdG9jb2wnOidkb2tvZGVtby1kb29yJywKICAgICAgICAgICAgICAgICAgICdzZXR0aW5ncyc6eydh'
    'ZGRyZXNzJzonMS4xLjEuMScsJ3BvcnQnOjUzLCduZXR3b3JrJzondGNwLHVkcCd9fV0sCiAgICAgICdkbnMnOnsnc2VydmVy'
    'cyc6WycxLjEuMS4xJywndGNwOi8vOS45LjkuOScsJ2h0dHBzOi8vMS4wLjAuMS9kbnMtcXVlcnknXSwKICAgICAgICAgICAg'
    'ICdxdWVyeVN0cmF0ZWd5JzonVXNlSVB2NCcsJ3RhZyc6J2Rucy1lbmdpbmUnLCdlbmFibGVQYXJhbGxlbFF1ZXJ5JzpUcnVl'
    'fSwKICAgICAgJ291dGJvdW5kcyc6W3sndGFnJzond2lyZScsJ3Byb3RvY29sJzonZnJlZWRvbSd9LAogICAgICAgICAgICAg'
    'ICAgICAgeyd0YWcnOidkbnMnLCdwcm90b2NvbCc6J2RucycsJ3NldHRpbmdzJzp7J3J1bGVzJzpbeydxVHlwZSc6JzEsMjgn'
    'LCdhY3Rpb24nOidoaWphY2snfSx7J2FjdGlvbic6J2RpcmVjdCd9XX19XSwKICAgICAgJ3JvdXRpbmcnOnsncnVsZXMnOlt7'
    'J3R5cGUnOidmaWVsZCcsJ2luYm91bmRUYWcnOlsnZG5zLWluJ10sJ291dGJvdW5kVGFnJzonZG5zJ30sCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUnXSwnb3V0Ym91bmRUYWcn'
    'Oid3aXJlJ31dfX0KICAgIHBhdGg9Uk9PVC8nbmFtZXNwYWNlLWRucy5qc29uJzt3cml0ZShwYXRoLGpzb24uZHVtcHMoY2Zn'
    'KSkKICAgIGJpbmFyeT0nL29wdC92cG4tbWFuYWdlci9iaW4veHJheScKICAgIGluc2lkZShbYmluYXJ5LCdydW4nLCctdGVz'
    'dCcsJy1jb25maWcnLHBhdGhdKQogICAgRE5TX1BST0NFU1M9c3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywnbmV0bnMnLCdleGVj'
    'JyxOUyxiaW5hcnksJ3J1bicsJy1jb25maWcnLHN0cihwYXRoKV0sCiAgICAgICAgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxM'
    'LHN0ZG91dD1zdWJwcm9jZXNzLkRFVk5VTEwsc3RkZXJyPXN1YnByb2Nlc3MuREVWTlVMTCkKICAgIGZvciBfIGluIHJhbmdl'
    'KDMwKToKICAgICAgICBpZiBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6cmFpc2UgUnVudGltZUVycm9yKCdwcml2'
    'YXRlX2Ruc19zdG9wcGVkJykKICAgICAgICBpZiAnMTcyLjI5LjI0Ny4yOjUzJyBpbiBpbnNpZGUoWydzcycsJy1sbnUnXSxj'
    'aGVjaz1GYWxzZSkuc3Rkb3V0OgogICAgICAgICAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25m'
    'JywnbmFtZXNlcnZlciAxNzIuMjkuMjQ3LjJcbm9wdGlvbnMgdGltZW91dDozIGF0dGVtcHRzOjJcbicpCiAgICAgICAgICAg'
    'IHJldHVybgogICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3ByaXZhdGVfZG5zX25vdF9y'
    'ZWFkeScpCgoKZGVmIHVzZV9yZXNvbHZlcl9maWxlKHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToKICAgIGRhdGE9'
    'anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICB0YXJnZXQ9Uk9PVC8ncmVzb2x2LXZwbi5jb25mJwog'
    'ICAgaWYgJ3Jlc29sdmVyX29yaWdpbmFsJyBub3QgaW4gZGF0YToKICAgICAgICBkYXRhWydyZXNvbHZlcl9vcmlnaW5hbCdd'
    'PXsnbGluayc6b3MucmVhZGxpbmsocGF0aCkgaWYgcGF0aC5pc19zeW1saW5rKCkgZWxzZSBOb25lLAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICd0ZXh0JzpwYXRoLnJlYWRfdGV4dCgpIGlmIHBhdGguZXhpc3RzKCkgZWxzZSAnJywK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZXhpc3RlZCc6cGF0aC5leGlzdHMoKSBvciBwYXRoLmlzX3N5'
    'bWxpbmsoKX0KICAgIGRhdGFbJ2Ruc19mYWxsYmFjayddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBz'
    'KGRhdGEpKQogICAgd3JpdGUodGFyZ2V0LCduYW1lc2VydmVyIDE3Mi4yOS4yNDcuMlxub3B0aW9ucyB0aW1lb3V0OjMgYXR0'
    'ZW1wdHM6MlxuJykKICAgIHRhcmdldC5jaG1vZCgwbzY0NCkKICAgICMgVGhlIHBhcmVudCBtdXN0IGJlIHRyYXZlcnNhYmxl'
    'IGJ5IGFwcGxpY2F0aW9ucy4gU2VjcmV0cyByZW1haW4gcm9vdC1vbmx5LgogICAgIyBQdXQgb25seSB0aGlzIHB1YmxpYyBy'
    'ZXNvbHZlciBmaWxlIG91dHNpZGUgdGhlIGNyZWRlbnRpYWwgZGlyZWN0b3J5LgogICAgcHVibGljPVBhdGgoJy9ydW4vZXZn'
    'ZW5pdW0tcmVzb2x2LmNvbmYnKQogICAgcHVibGljLnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsZXhpc3Rfb2s9VHJ1ZSkK'
    'ICAgIHdyaXRlKHB1YmxpYyx0YXJnZXQucmVhZF90ZXh0KCkpO3B1YmxpYy5jaG1vZCgwbzY0NCkKICAgIHRlbXBvcmFyeT1w'
    'YXRoLndpdGhfbmFtZSgnLmV2Z2VuaXVtLXJlc29sdi5uZXcnKQogICAgdGVtcG9yYXJ5LnVubGluayhtaXNzaW5nX29rPVRy'
    'dWUpO3RlbXBvcmFyeS5zeW1saW5rX3RvKHB1YmxpYykKICAgIG9zLnJlcGxhY2UodGVtcG9yYXJ5LHBhdGgpCgoKZGVmIHJl'
    'c3RvcmVfcmVzb2x2ZXJfZmlsZShkYXRhLHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToKICAgIHNhdmVkPWRhdGEu'
    'Z2V0KCdyZXNvbHZlcl9vcmlnaW5hbCcpCiAgICBpZiBzYXZlZCBhbmQgcGF0aC5pc19zeW1saW5rKCkgYW5kIG9zLnJlYWRs'
    'aW5rKHBhdGgpPT0nL3J1bi9ldmdlbml1bS1yZXNvbHYuY29uZic6CiAgICAgICAgdGVtcG9yYXJ5PXBhdGgud2l0aF9uYW1l'
    'KCcuZXZnZW5pdW0tcmVzb2x2LnJlc3RvcmUnKQogICAgICAgIHRlbXBvcmFyeS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQog'
    'ICAgICAgIGlmIHNhdmVkWydsaW5rJ10gaXMgbm90IE5vbmU6dGVtcG9yYXJ5LnN5bWxpbmtfdG8oc2F2ZWRbJ2xpbmsnXSkK'
    'ICAgICAgICBlbHNlOnRlbXBvcmFyeS53cml0ZV90ZXh0KHNhdmVkWyd0ZXh0J10pO3RlbXBvcmFyeS5jaG1vZCgwbzY0NCkK'
    'ICAgICAgICBpZiBzYXZlZC5nZXQoJ2V4aXN0ZWQnLFRydWUpOm9zLnJlcGxhY2UodGVtcG9yYXJ5LHBhdGgpCiAgICAgICAg'
    'ZWxzZTpwYXRoLnVubGluaygpO3RlbXBvcmFyeS51bmxpbmsoKQogICAgZWxpZiBub3Qgc2F2ZWQgYW5kICdkbnNfYmFja3Vw'
    'JyBpbiBkYXRhOgogICAgICAgIHBhdGgud3JpdGVfdGV4dChkYXRhWydkbnNfYmFja3VwJ10pCgoKZGVmIHJlY292ZXJfc3lz'
    'dGVtX2RucygpOgogICAgZm9yIF8gaW4gcmFuZ2UoMik6CiAgICAgICAgaWYgc3lzdGVtX2Ruc19oZWFsdGgoKTpyZXR1cm4g'
    'VHJ1ZQogICAgICAgIGlmIFNUT1A6cmV0dXJuIEZhbHNlCiAgICAgICAgdGltZS5zbGVlcCguMykKICAgIGlmIG5vdCBmdWxs'
    'X3N0YXRlKCkuZXhpc3RzKCk6cmV0dXJuIEZhbHNlCiAgICAjIFN3aXRjaCBvbmx5IHRoZSByZXNvbHZlciBmaWxlIHdlIG93'
    'bjsgbmV2ZXIgc3RvcCBhbm90aGVyIFZQTiBvciByZXNvbHZlci4KICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9C10YDQtdC6'
    '0LvRjtGH0LDRjiDQvdC10LjRgdC/0YDQsNCy0L3Ri9C5INGB0LjRgdGC0LXQvNC90YvQuSBETlMg0L3QsCDQt9Cw0YnQuNGJ'
    '0ZHQvdC90YvQuSDRgNC10LfQtdGA0LIuJyw5MCxhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0nc3lzdGVtX2Ruc19mYWlsZWQn'
    'KQogICAgdXNlX3Jlc29sdmVyX2ZpbGUoKQogICAgcmV0dXJuIHN5c3RlbV9kbnNfaGVhbHRoKCkKCgpkZWYgcGVyc2lzdF9n'
    'dWFyZChydWxlcyk6CiAgICAjIEd1YXJkIHBlcnNpc3RlbmNlIHByZWNlZGVzIHN3aXRjaGluZy4gQ2xlYW51cCBhZnRlciBh'
    'IGNyYXNoIG5ldmVyIG9wZW5zIHRoZSBJbnRlcm5ldC4KICAgIGd1YXJkX3VuaXQgPSAnJydbVW5pdF0KRGVzY3JpcHRpb249'
    'RXZnZW5pdW0gZnVsbC1kZXZpY2Uga2lsbCBzd2l0Y2gKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpBZnRlcj1sb2NhbC1mcy50'
    'YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldApbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15'
    'ZXMKRXhlY1N0YXJ0PS91c3Ivc2Jpbi9uZnQgLWYgL2V0Yy92cG4tbWFuYWdlci9zdGFyZml2ZS10dW5uZWwvZnVsbC1ndWFy'
    'ZC5uZnQKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CicnJy5yZXBsYWNlKCcvdXNyL3NiaW4vbmZ0Jywg'
    'c2h1dGlsLndoaWNoKCduZnQnKSkKICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKICAgIHdyaXRlKFBh'
    'dGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJyksZ3VhcmRfdW5p'
    'dCkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywn'
    'ZW5hYmxlJywnZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJ10pCgoKZGVmIGFjdGl2YXRlX2Z1bGwoYWRk'
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
    'ICAgIGZ1bGxfbmFtZXNwYWNlKGFkZHJlc3MpCiAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKICAgICMgVmFsaWRhdGUgdGhl'
    'IGVncmVzcyBmaWx0ZXIgYmVmb3JlIGludGVycnVwdGluZyB0aGUgcHJldmlvdXMgVlBOLgogICAgaWYgbm90IGVncmVzc19o'
    'ZWFsdGgoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2VzdG9uaWFfZWdyZXNzX2ZhaWxlZCcpCiAgICBydWxlcyA9'
    'IGZ1bGxfZmlyZXdhbGwoKQogICAgIyBSZXBhaXIgbWF5IGluaGVyaXQgYSBndWFyZCBmcm9tIGFuIG9sZGVyIHZlcnNpb24u'
    'IFJlcGxhY2Ugb3VyIHRhYmxlIGluCiAgICAjIG9uZSBuZnQgdHJhbnNhY3Rpb24sIHNvIGZpeGVzIGFwcGx5IHdpdGhvdXQg'
    'b3BlbmluZyBhbiB1bmd1YXJkZWQgd2luZG93LgogICAgcmVwbGFjZW1lbnQgPSAoJ2RlbGV0ZSB0YWJsZSBpbmV0ICcrRlVM'
    'TF9HVUFSRCsnXG4nIGlmIGZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKICAgIGNvbW1hbmQoWyduZnQnLCct'
    'YycsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNl'
    'bWVudCkKICAgIHBlcnNpc3RfZ3VhcmQocnVsZXMpCiAgICAjIFRoaXMgY29tbWFuZCBzdG9wcyBvbmx5IHRoaXMgbWFuYWdl'
    'cidzIHByZXZpb3VzIFhyYXkgbW9kZSBhbmQgcmVtb3ZlcyBpdHMgZ3VhcmQuCiAgICBjb21tYW5kKFsnL3Vzci9sb2NhbC9z'
    'YmluL3ZwbmN0bCcsJ2ludGVybmFsLXN0YXJmaXZlLXBhdXNlLW1haW4nXSx0aW1lb3V0PTQwKQogICAgY29tbWFuZChbJ2lw'
    'Jywncm91dGUnLCdyZXBsYWNlJywndW5yZWFjaGFibGUnLCdkZWZhdWx0JywnbWV0cmljJywnMzI3NjAnLCd0YWJsZScsRlVM'
    'TF9UQUJMRV0pCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJywnMTcyLjI5LjI0'
    'Ny4yJywnZGV2JyxGVUxMX0hPU1QsJ21ldHJpYycsJzEwJywndGFibGUnLEZVTExfVEFCTEVdKQogICAgY29tbWFuZChbJ2lw'
    'JywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZm9y'
    'IHJ1bGUgaW4gKFsncHJpb3JpdHknLCc3OScsJ3RvJyxDTElFTlQrJy8zMicsJ2xvb2t1cCcsJ21haW4nXSwKICAgICAgICAg'
    'ICAgICAgICBbJ3ByaW9yaXR5JywnNzknLCdpaWYnLEZVTExfSE9TVCwnbG9va3VwJywnbWFpbiddKToKICAgICAgICBjb21t'
    'YW5kKFsnaXAnLCdydWxlJywnZGVsJywqcnVsZV0sY2hlY2s9RmFsc2UpCiAgICAgICAgY29tbWFuZChbJ2lwJywncnVsZScs'
    'J2FkZCcsKnJ1bGVdKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZV'
    'TExfVEFCTEVdKQogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkKICAgIGlmIHNodXRpbC53'
    'aGljaCgncmVzb2x2ZWN0bCcpIGFuZCBjb21tYW5kKFsnc3lzdGVtY3RsJywnaXMtYWN0aXZlJywnLS1xdWlldCcsJ3N5c3Rl'
    'bWQtcmVzb2x2ZWQnXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIGRhdGFbJ2Ruc19tb2RlJ109J3Jl'
    'c29sdmVkX2xpbmsnCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCiAgICAgICAgY29tbWFu'
    'ZChbJ3Jlc29sdmVjdGwnLCdkbnMnLEZVTExfSE9TVCwnMTcyLjI5LjI0Ny4yJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29s'
    'dmVjdGwnLCdkb21haW4nLEZVTExfSE9TVCwnfi4nXSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RlZmF1bHQt'
    'cm91dGUnLEZVTExfSE9TVCwneWVzJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdmbHVzaC1jYWNoZXMnXSxj'
    'aGVjaz1GYWxzZSkKICAgIGVsc2U6CiAgICAgICAgdXNlX3Jlc29sdmVyX2ZpbGUoKQogICAgY2xlYXJfZG5zX21hcHBpbmdz'
    'KHByZXZpb3VzX3Zwbj1UcnVlKQogICAgcmV0aXJlX3ByZXZpb3VzX2Nvbm5lY3Rpb25zKG9sZF9hZGRyZXNzZXMpCiAgICBp'
    'ZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgcG9saWN5LmFwcGx5KCkKICAgIGlmIG5vdCByZWNvdmVyX3N5c3RlbV9k'
    'bnMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3N5c3RlbV9kbnNfZmFpbGVkJykKICAgICMgVGVzdCB0aGUgYWN0'
    'dWFsIGhvc3QgcGF0aCBhcyB3ZWxsIGFzIG5hbWVzcGFjZSBwcm9iZXMgYmVmb3JlIGFubm91bmNpbmcgY29ubmVjdGVkLgog'
    'ICAgY2hlY2sgPSBjb21tYW5kKFsnY3VybCcsJy00JywnLS1ub3Byb3h5JywnJyBpZiBwb2xpY3kgaXMgbm90IE5vbmUgZWxz'
    'ZSAnKicsJy0tZmFpbCcsJy0tc2lsZW50JywnLS1tYXgtdGltZScsJzEwJywqKFsnLS1zb2NrczUtaG9zdG5hbWUnLCcxMjcu'
    'MC4wLjE6MTg1NTQnXSBpZiBwb2xpY3kgaXMgbm90IE5vbmUgZWxzZSBbXSksJ2h0dHBzOi8vYXBpLmlwaWZ5Lm9yZyddLHRp'
    'bWVvdXQ9MTIpCiAgICBpZiBjaGVjay5zdGRvdXQuc3RyaXAoKSAhPSAnMzguMTgwLjE2NC42Nyc6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCdob3N0X2VncmVzc19mYWlsZWQnKQogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFk'
    'X3RleHQoKSkKICAgIGRhdGFbJ2FjdGl2ZSddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEp'
    'KQoKCmRlZiBjbGVhbnVwX2Z1bGwocmVsZWFzZT1GYWxzZSk6CiAgICBnbG9iYWwgRE5TX1BST0NFU1MKICAgIGlmIEROU19Q'
    'Uk9DRVNTIGlzIG5vdCBOb25lIGFuZCBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgTm9uZToKICAgICAgICBETlNfUFJPQ0VTUy50'
    'ZXJtaW5hdGUoKQogICAgICAgIHRyeTpETlNfUFJPQ0VTUy53YWl0KHRpbWVvdXQ9MykKICAgICAgICBleGNlcHQgc3VicHJv'
    'Y2Vzcy5UaW1lb3V0RXhwaXJlZDpETlNfUFJPQ0VTUy5raWxsKCk7RE5TX1BST0NFU1Mud2FpdCgpCiAgICBETlNfUFJPQ0VT'
    'Uz1Ob25lCiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgcG9saWN5LnN0b3AocmVsZWFzZT1yZWxlYXNlKQog'
    'ICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGE9anNvbi5sb2FkcyhmdWxs'
    'X3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsJ2RlZmF1bHQnLCdtZXRyaWMn'
    'LCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdkZWwnLEZV'
    'TExfSE9TVF0sY2hlY2s9RmFsc2UpCiAgICAjIE9uIGZhaWx1cmU6IHJldGFpbiByb3V0aW5nLCBETlMgYW5kIHRoZSBwZXJz'
    'aXN0ZW50IGd1YXJkIHVudGlsIGV4cGxpY2l0IGRpc2Nvbm5lY3QuCiAgICBpZiBub3QgcmVsZWFzZToKICAgICAgICByZXR1'
    'cm4KICAgIHJlc3RvcmVfcmVzb2x2ZXJfZmlsZShkYXRhKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9y'
    'aXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2Rl'
    'bCcsJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBj'
    'b21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ2lpZicsRlVMTF9IT1NULCdsb29rdXAnLCdtYWlu'
    'J10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLEZVTExfVEFCTEVdLGNo'
    'ZWNrPUZhbHNlKQogICAgZm9yIHNlcnZlciBpbiAoJzE5Mi4xNjguMC4xNjMnLCAnMzguMTgwLjE2NC42NycpOgogICAgICAg'
    'IGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLHNlcnZlciwnaXBwcm90bycsJ3RjcCcs'
    'J2Rwb3J0JywnMjInLCdsb29rdXAnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwn'
    'LCdkaXNhYmxlJywnLS1ub3cnLCdldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnXSxjaGVjaz1GYWxzZSkK'
    'ICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKQogICAg'
    'Y2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZnVsbF9zdGF0'
    'ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNoZWNrPUZhbHNlKSBpZiBz'
    'aHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNlIE5vbmUKCgpkZWYgY29tbWFuZChhcmdzLCBjaGVjaz1UcnVlLCB0aW1l'
    'b3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0cih4KSBmb3IgeCBpbiBh'
    'cmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0dXJlX291dHB1dD1UcnVlLAogICAgICAgICAgICAgICAgICAgICAg'
    'ICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAgaWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6'
    'CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4gYSBDU1IgcGF0aDsgZG8gbm90IHByb3BhZ2F0ZSBwcm9jZXNzIG91'
    'dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2NvbW1hbmRfZmFpbGVkJykKICAgIHJldHVy'
    'biBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIGNvbW1hbmQoWydpcCcsICduZXRucycsICdl'
    'eGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVmIHdyaXRlKHBhdGgsIHZhbHVlKToKICAgIHBhdGgucGFyZW50Lm1r'
    'ZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHRlbXBvcmFyeSA9IHBhdGgud2l0aF9z'
    'dWZmaXgoJy5uZXcnKQogICAgZmQgPSBvcy5vcGVuKHRlbXBvcmFyeSwgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3Mu'
    'T19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIDBvNjAwKQogICAgd2l0aCBvcy5mZG9wZW4oZmQsICd3JykgYXMgc3RyZWFtOgog'
    'ICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgIHRlbXBvcmFyeS5yZXBsYWNlKHBhdGgpCgoKZGVmIHNhdmVkKCk6CiAg'
    'ICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoU1RBVEUucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3Is'
    'IFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoKCmRlZiBzdGFnZShwaGFzZSwgbWVzc2FnZSwgcHJvZ3Jlc3MsICoq'
    'ZmllbGRzKToKICAgIGRhdGEgPSB7KipzYXZlZCgpLCAncGhhc2UnOiBwaGFzZSwgJ21lc3NhZ2UnOiBtZXNzYWdlLCAncHJv'
    'Z3Jlc3MnOiBwcm9ncmVzcywKICAgICAgICAgICAgJ3VwZGF0ZWQnOiBpbnQodGltZS50aW1lKCkpLCAnaGVhcnRiZWF0Jzog'
    'dGltZS5tb25vdG9uaWMoKSwgKipmaWVsZHN9CiAgICB3cml0ZShTVEFURSwganNvbi5kdW1wcyhkYXRhLCBlbnN1cmVfYXNj'
    'aWk9RmFsc2UpKQogICAgaWYgc3VwcG9ydF9hcGkgaXMgbm90IE5vbmU6CiAgICAgICAgdHJ5OnN1cHBvcnRfYXBpLnJlY29y'
    'ZChST09ULHdyaXRlLGRhdGEpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsVHlwZUVycm9yKTpwYXNzCgoK'
    'ZGVmIHN0YXR1cygpOgogICAgZGF0YSA9IHNhdmVkKCkKICAgIHJ1bm5pbmcgPSBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2lz'
    'LWFjdGl2ZScsICctLXF1aWV0JywgVU5JVF0sIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTIpLnJldHVybmNvZGUgPT0gMAogICAg'
    'aWYgZGF0YS5nZXQoJ3BoYXNlJykgPT0gJ2Nvbm5lY3RlZCcgYW5kIChub3QgcnVubmluZyBvciB0aW1lLm1vbm90b25pYygp'
    'LWRhdGEuZ2V0KCdoZWFydGJlYXQnLCAwKSA+IDkwKToKICAgICAgICBkYXRhLnVwZGF0ZShwaGFzZT0naW50ZXJydXB0ZWQn'
    'LCBtZXNzYWdlPSfQodC+0LXQtNC40L3QtdC90LjQtSDQvtGB0YLQsNC90L7QstC40LvQvtGB0YwuINCf0YDQvtCy0LXRgNGM'
    '0YLQtSDRgdC+0YHRgtC+0Y/QvdC40LUg0LfQsNGJ0LjRgtGLINC4INC90LDQttC80LjRgtC1IMKr0J/QvtGH0LjQvdC40YLR'
    'jMK7LicsIGFjdGl2ZT1GYWxzZSkKICAgIHB1YmxpYyA9IHtrZXk6IGRhdGFba2V5XSBmb3Iga2V5IGluICgncGhhc2UnLCAn'
    'bWVzc2FnZScsICdwcm9ncmVzcycsICdhY3RpdmUnLCAndXBkYXRlZCcsICdtZXRyaWNzJywKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICdzY29wZScsICdzaW5jZScsICdyZXRyeScsICdlcnJvcl9jb2RlJywgJ3BhdGgnKSBp'
    'ZiBrZXkgaW4gZGF0YX0KICAgIHRva2VuX2luZm8gPSB0b2tlbl9zdGF0dXMoKQogICAgcmV0dXJuIHsncGhhc2UnOiAnb2Zm'
    'JywgJ21lc3NhZ2UnOiAoJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC7'
    '0Y7Rh9C40YLRjMK7LicgaWYgdG9rZW5faW5mb1snaGFzX3Rva2VuJ10gZWxzZSAn0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC0'
    '0YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCwLicpLAogICAgICAgICAgICAncHJvZ3Jlc3MnOiAw'
    'LCAnYWN0aXZlJzogRmFsc2UsICoqcHVibGljLCAncnVubmluZyc6IHJ1bm5pbmcsCiAgICAgICAgICAgICoqdG9rZW5faW5m'
    'bywgKipkZXZpY2Vfc3RhdHVzKCksICdpc29sYXRlZCc6IEZhbHNlLCAnZnVsbF9kZXZpY2UnOiBUcnVlLCAnZ3VhcmQnOiBm'
    'dWxsX2d1YXJkX2FjdGl2ZSgpLCAncHJvdG9jb2wnOiAnSUtFdjIg4oaSINCt0YHRgtC+0L3QuNGPJ30KCgpAY29udGV4dGxp'
    'Yi5jb250ZXh0bWFuYWdlcgpkZWYgbmFtZXNwYWNlKCk6CiAgICBiZWZvcmUgPSBvcy5vcGVuKCcvcHJvYy9zZWxmL25zL25l'
    'dCcsIG9zLk9fUkRPTkxZKQogICAgdGFyZ2V0ID0gb3Mub3BlbignL3J1bi9uZXRucy8nK05TLCBvcy5PX1JET05MWSkKICAg'
    'IHRyeToKICAgICAgICBvcy5zZXRucyh0YXJnZXQsIG9zLkNMT05FX05FV05FVCkKICAgICAgICB5aWVsZAogICAgZmluYWxs'
    'eToKICAgICAgICBvcy5zZXRucyhiZWZvcmUsIG9zLkNMT05FX05FV05FVCkKICAgICAgICBvcy5jbG9zZSh0YXJnZXQpCiAg'
    'ICAgICAgb3MuY2xvc2UoYmVmb3JlKQoKCmRlZiBwaHlzaWNhbF9yb3V0ZSgpOgogICAgcm91dGVzID0ganNvbi5sb2Fkcyhj'
    'b21tYW5kKFsnaXAnLCAnLWonLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsICdtYWluJywgJ2RlZmF1bHQnXSku'
    'c3Rkb3V0KQogICAgY2FuZGlkYXRlcyA9IFtyIGZvciByIGluIHJvdXRlcyBpZiByLmdldCgnZ2F0ZXdheScpIGFuZCByLmdl'
    'dCgnZGV2JykgYW5kCiAgICAgICAgICAgICAgICAgIG5vdCByWydkZXYnXS5zdGFydHN3aXRoKCgndHVuJywgJ3hyYXknLCAn'
    'd2cnLCAnZXZuLScpKV0KICAgIGlmIG5vdCBjYW5kaWRhdGVzOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignbm9fcGh5'
    'c2ljYWxfcm91dGUnKQogICAgcm91dGUgPSBtaW4oY2FuZGlkYXRlcywga2V5PWxhbWJkYSByOiByLmdldCgnbWV0cmljJywg'
    'MCkpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInW0EtWmEtejAtOV8uOi1dezEsMTV9Jywgcm91dGVbJ2RldiddKToKICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaW50ZXJmYWNlJykKICAgIGlwYWRkcmVzcy5JUHY0QWRkcmVzcyhy'
    'b3V0ZVsnZ2F0ZXdheSddKQogICAgcmV0dXJuIHJvdXRlCgoKZGVmIGhvc3RfcnVsZXMoaWZhY2UsIHByZXZpb3VzX2Zvcndh'
    'cmQ9VHJ1ZSk6CiAgICAjIFNjb3BlIGV2ZXJ5IG5ldyBmb3J3YXJkaW5nL05BVCBydWxlIHRvIG91ciBvbmUgaW50ZXJmYWNl'
    'IGFuZCB0aGUgY29uZmlndXJlZCBpbmdyZXNzIGFkZHJlc3MuCiAgICBwcmVzZXJ2ZV9kaXNhYmxlZCA9ICcnIGlmIHByZXZp'
    'b3VzX2ZvcndhcmQgZWxzZSAnJycgIGlpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgYWNjZXB0CiAgb2lm'
    'bmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAog'
    'IG1ldGEgbmZwcm90byBpcHY0IGRyb3AnJycKICAgIHJldHVybiBmJycndGFibGUgaW5ldCB7TkZUfSB7ewogY2hhaW4gZm9y'
    'd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtMjA7IHBvbGljeSBhY2NlcHQ7CiAgaWlmbmFt'
    'ZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1l'
    'ICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQK'
    'ICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7'
    'IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHRjcCBk'
    'cG9ydCA4NDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgZHJvcAogIG9pZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge3sg'
    'e1NFUlZFUn0sIDM4LjE4MC4xNjQuNjcgfX0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBvaWZuYW1l'
    'ICJ7SE9TVH0iIGRyb3AKe3ByZXNlcnZlX2Rpc2FibGVkfQogfX0KIGNoYWluIG5hdCB7ewogIHR5cGUgbmF0IGhvb2sgcG9z'
    'dHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlwIHNhZGRyIHtDTElFTlR9IG9pZm5hbWUgIntp'
    'ZmFjZX0iIG1hc3F1ZXJhZGUKIH19Cn19JycnCgoKZGVmIHNldHVwX25ldHdvcmsoKToKICAgIHJvdXRlID0gcGh5c2ljYWxf'
    'cm91dGUoKQogICAgIyBSZWZ1c2UgbmFtZS9hZGRyZXNzIGNvbGxpc2lvbnMgcmF0aGVyIHRoYW4gcmVwdXJwb3NpbmcgYW5v'
    'dGhlciBhcHBsaWNhdGlvbidzIHJlc291cmNlcy4KICAgIGlmIFBhdGgoJy9ydW4vbmV0bnMvJytOUykuZXhpc3RzKCkgb3Ig'
    'UGF0aCgnL3N5cy9jbGFzcy9uZXQvJytIT1NUKS5leGlzdHMoKSBvciAoUGF0aCgnL2V0Yy9uZXRucycpL05TKS5leGlzdHMo'
    'KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmFtZXNwYWNlX2V4aXN0cycpCiAgICBpZiBjb21tYW5kKFsn'
    'aXAnLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0'
    'cmlwKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X3RhYmxlX2luX3VzZScpCiAgICBpZiBhbnkoTkVUV09S'
    'SyBpbiBsaW5lIGZvciBsaW5lIGluIGNvbW1hbmQoWydpcCcsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ2Fs'
    'bCddKS5zdGRvdXQuc3BsaXRsaW5lcygpKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmV0d29ya19pbl91'
    'c2UnKQogICAgb2xkX2ZvcndhcmQgPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcpLnJlYWRfdGV4dCgp'
    'LnN0cmlwKCkKICAgICMgUmVjb3JkIG93bmVyc2hpcCBiZWZvcmUgY3JlYXRpbmcgYW55dGhpbmc6IGNsZWFudXAgaXMgdmFs'
    'aWQgYWZ0ZXIgZXZlcnkgcGFydGlhbCBzdGVwLgogICAgdXBsaW5rID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYn'
    'KS9yb3V0ZVsnZGV2J10vJ2ZvcndhcmRpbmcnCiAgICB3cml0ZShST09ULyduZXR3b3JrLmpzb24nLCBqc29uLmR1bXBzKHsn'
    'Zm9yd2FyZCc6IG9sZF9mb3J3YXJkLCAnaW50ZXJmYWNlJzogcm91dGVbJ2RldiddLCAndXBsaW5rX2ZvcndhcmQnOiB1cGxp'
    'bmsucmVhZF90ZXh0KCkuc3RyaXAoKX0pKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2FkZCcsIE5TXSkKICAgIHdy'
    'aXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCAnbmFtZXNlcnZlciAxLjEuMS4xXG5uYW1lc2VydmVy'
    'IDkuOS45Ljlcbm9wdGlvbnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICAjIG5zcy1yZXNvbHZlIHRhbGtzIHRvIHRo'
    'ZSBob3N0IGRhZW1vbiBvdmVyIGEgVW5peCBzb2NrZXQgZXZlbiBpbnNpZGUgbmV0bnMuCiAgICBuc3M9UGF0aCgnL2V0Yy9u'
    'c3N3aXRjaC5jb25mJykucmVhZF90ZXh0KCkKICAgIG5zcz1yZS5zdWIocideaG9zdHM6LiokJywgJ2hvc3RzOiBmaWxlcyBk'
    'bnMnLCBuc3MsIGZsYWdzPXJlLk0pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ25zc3dpdGNoLmNvbmYnLCBu'
    'c3MpCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdhZGQnLCBIT1NULCAndHlwZScsICd2ZXRoJywgJ3BlZXInLCAnbmFt'
    'ZScsIFBFRVJdKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ25ldG5zJywgTlNdKQogICAgY29t'
    'bWFuZChbJ2lwJywgJ2FkZHInLCAnYWRkJywgR0FURVdBWSsnLzMwJywgJ2RldicsIEhPU1RdKQogICAgY29tbWFuZChbJ2lw'
    'JywgJ2xpbmsnLCAnc2V0JywgSE9TVCwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdhZGRyJywgJ2FkZCcsIENMSUVOVCsn'
    'LzMwJywgJ2RldicsIFBFRVJdKQogICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQnLCBQRUVSLCAndXAnXSkKICAgIGlu'
    'c2lkZShbJ2lwJywgJ2xpbmsnLCAnc2V0JywgJ2xvJywgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdyb3V0ZScsICdhZGQn'
    'LCAnZGVmYXVsdCcsICd2aWEnLCBHQVRFV0FZXSkKICAgIGNvbW1hbmQoWydpcCcsICdyb3V0ZScsICdhZGQnLCAndGFibGUn'
    'LCBzdHIoVEFCTEUpLCAnZGVmYXVsdCcsICd2aWEnLCByb3V0ZVsnZ2F0ZXdheSddLCAnZGV2Jywgcm91dGVbJ2RldiddXSkK'
    'ICAgIGZvciBhZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdhZGQnLCAncHJp'
    'b3JpdHknLCBzdHIoUFJJT1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRy'
    'ZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICBydWxlcyA9IGhvc3RfcnVsZXMocm91dGVbJ2RldiddLCBw'
    'cmV2aW91c19mb3J3YXJkPW9sZF9mb3J3YXJkID09ICcxJykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSdd'
    'LCBkYXRhPXJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICAjIFBlci1pbnRl'
    'cmZhY2UgZm9yd2FyZGluZyBhdm9pZHMgaXBfZm9yd2FyZCdzIGdsb2JhbCBkZWZhdWx0cyByZXNldC4KICAgIChQYXRoKCcv'
    'cHJvYy9zeXMvbmV0L2lwdjQvY29uZicpL0hPU1QvJ2ZvcndhcmRpbmcnKS53cml0ZV90ZXh0KCcxXG4nKQogICAgdXBsaW5r'
    'LndyaXRlX3RleHQoJzFcbicpCgoKZGVmIGNsZWFudXAoKToKICAgIGNsZWFudXBfZnVsbCgpCiAgICAjIEFuIHVub3duZWQg'
    'bmFtZXNwYWNlL3RhYmxlIG11c3QgbmV2ZXIgYmUgZGVsZXRlZCBieSBhIGdlbmVyaWMgY2xlYW51cCBjYWxsLgogICAgaWYg'
    'bm90IChST09ULyduZXR3b3JrLmpzb24nKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGEgPSBqc29uLmxvYWRz'
    'KChST09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGNvbW1hbmQoWyduZnQnLCAnZGVsZXRlJywgJ3RhYmxl'
    'JywgJ2luZXQnLCBORlRdLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluICgqRU5EUE9JTlRTLCAqTEVHQUNZX0VO'
    'RFBPSU5UUyk6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZ'
    'KSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcs'
    'IHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluIGRhdGEuZ2V0KCdtZWFzdXJlbWVudF9pcHMn'
    'LCBbXSk6CiAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xvYmFsOgogICAgICAgICAgICBj'
    'b21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsICd0'
    'bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAn'
    'LCAncm91dGUnLCAnZmx1c2gnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAn'
    'LCAnbmV0bnMnLCAnZGVsJywgTlNdLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2RlbCcsIEhP'
    'U1RdLCBjaGVjaz1GYWxzZSkKICAgIGlmICd1cGxpbmtfZm9yd2FyZCcgaW4gZGF0YToKICAgICAgICBwYXRoID0gUGF0aCgn'
    'L3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9kYXRhWydpbnRlcmZhY2UnXS8nZm9yd2FyZGluZycKICAgICAgICBpZiBwYXRo'
    'LmV4aXN0cygpOgogICAgICAgICAgICBwYXRoLndyaXRlX3RleHQoZGF0YVsndXBsaW5rX2ZvcndhcmQnXSsnXG4nKQogICAg'
    'ZWxpZiBkYXRhLmdldCgnZm9yd2FyZCcpID09ICcwJyBhbmQgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQn'
    'KS5yZWFkX3RleHQoKS5zdHJpcCgpID09ICcxJzoKICAgICAgICBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2Fy'
    'ZCcpLndyaXRlX3RleHQoJzBcbicpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicpLnVubGluayht'
    'aXNzaW5nX29rPVRydWUpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJykudW5saW5rKG1pc3Np'
    'bmdfb2s9VHJ1ZSkKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhPU0Vycm9yKToKICAgICAgICAoUGF0aCgnL2V0Yy9u'
    'ZXRucycpL05TKS5ybWRpcigpCiAgICAoUk9PVC8nbmV0d29yay5qc29uJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgoK'
    'CmRlZiB0bHNfcmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNsaWVudD1GYWxzZSwgdGltZW91dD04LCBpZGVu'
    'dGl0eT1TRVJWRVIpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZGF0YT1QSU5ORURfQ0Ep'
    'CiAgICBpZiBjbGllbnQ6CiAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwg'
    'c3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBzb2NrID0gc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChhZGRyZXNz'
    'LCA4NDQzKSwgdGltZW91dD10aW1lb3V0KQogICAgdHJ5OgogICAgICAgIHRscyA9IGNvbnRleHQud3JhcF9zb2NrZXQoc29j'
    'aywgc2VydmVyX2hvc3RuYW1lPWlkZW50aXR5KQogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgc29jay5jbG9z'
    'ZSgpCiAgICAgICAgcmFpc2UKICAgIGNvbm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbihhZGRyZXNzLCA4'
    'NDQzLCB0aW1lb3V0PXRpbWVvdXQpCiAgICBjb25uZWN0aW9uLnNvY2sgPSB0bHMKICAgIGVuY29kZWQgPSBqc29uLmR1bXBz'
    'KGJvZHksIHNlcGFyYXRvcnM9KCcsJywgJzonKSkuZW5jb2RlKCkgaWYgYm9keSBpcyBub3QgTm9uZSBlbHNlIE5vbmUKICAg'
    'IHRyeToKICAgICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ1BPU1QnIGlmIGJvZHkgaXMgbm90IE5vbmUgZWxzZSAnR0VUJywg'
    'cGF0aCwgYm9keT1lbmNvZGVkLAogICAgICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJzPXsnQ29udGVudC1UeXBlJzog'
    'J2FwcGxpY2F0aW9uL2pzb24nLCAnQ29ubmVjdGlvbic6ICdjbG9zZSd9KQogICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlv'
    'bi5nZXRyZXNwb25zZSgpCiAgICAgICAgcmF3ID0gcmVzcG9uc2UucmVhZCgyMDAwMSkKICAgICAgICBpZiByZXNwb25zZS5z'
    'dGF0dXMgIT0gMjAwIG9yIGxlbihyYXcpID4gMjAwMDA6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVxdWVz'
    'dF9yZWplY3RlZCcpCiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMocmF3KQogICAgZmluYWxseToKICAgICAgICBjb25uZWN0'
    'aW9uLmNsb3NlKCkKCgpkZWYgZW5yb2xsKCk6CiAgICB0b2tlbiA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlw'
    'KCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcignaW52YWxpZF90b2tlbicpCiAgICB0cnk6CiAgICAgICAgY2FjaGVkID0ganNvbi5sb2FkcygoUk9PVC8ncHJvZmls'
    'ZS5qc29uJykucmVhZF90ZXh0KCkpCiAgICAgICAgaWYgKGNhY2hlZC5nZXQoJ2NhJykgPT0gUElOTkVEX0NBIGFuZCBjYWNo'
    'ZWQuZ2V0KCdzZXJ2ZXInKSA9PSBTRVJWRVIgYW5kCiAgICAgICAgICAgIHJlLmZ1bGxtYXRjaChyJ2RldmljZS1bYS1mMC05'
    'XXsyNH0nLCBjYWNoZWQuZ2V0KCdpZGVudGl0eScsICcnKSkgYW5kCiAgICAgICAgICAgIGNhY2hlZC5nZXQoJ2VuZHBvaW50'
    'JykgaW4gRU5EUE9JTlRTIGFuZCBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3b3JrJykgYW5kCiAgICAgICAgICAgIGNvbW1h'
    'bmQoWydvcGVuc3NsJywgJ3g1MDknLCAnLWluJywgUk9PVC8nY2xpZW50LnBlbScsICctY2hlY2tlbmQnLCBzdHIoNyo4NjQw'
    'MCksICctbm9vdXQnXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMCk6CiAgICAgICAgICAgIGNvbnRleHQgPSBzc2wu'
    'U1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4o'
    'c3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRlID0g'
    'cGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBjdXJyZW50ID0gaGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyh7a2V5OiBy'
    'b3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAncHJlZnNyYycpfSwgc29ydF9rZXlzPVRydWUp'
    'LmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICBhZGRyZXNzID0gY2FjaGVkWydlbmRwb2ludCddIGlmIGNhY2hl'
    'ZC5nZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSA9PSBjdXJyZW50IGVsc2UgU0VSVkVSCiAgICAgICAgICAgIHJldHVybiBjYWNo'
    'ZWRbJ2lkZW50aXR5J10sIGFkZHJlc3MKICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvciwgc3NsLlNTTEVycm9yKToK'
    'ICAgICAgICBwYXNzCiAgICBzdGFnZSgndG9rZW4nLCAn0J/QvtC70YPRh9Cw0Y4g0YHQtdGA0YLQuNGE0LjQutCw0YIg0LTQ'
    'u9GPINGN0YLQvtCz0L4g0YPRgdGC0YDQvtC50YHRgtCy0LAuJywgMjUpCiAgICBpZiBub3QgKFJPT1QvJ2NsaWVudC1rZXku'
    'cGVtJykuZXhpc3RzKCk6CiAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAnZ2VucGtleScsICctYWxnb3JpdGhtJywgJ1JT'
    'QScsICctcGtleW9wdCcsICdyc2Ffa2V5Z2VuX2JpdHM6MzA3MicsCiAgICAgICAgICAgICAgICAgJy1vdXQnLCBST09ULydj'
    'bGllbnQta2V5LnBlbSddLCB0aW1lb3V0PTMwKQogICAgICAgIChST09ULydjbGllbnQta2V5LnBlbScpLmNobW9kKDBvNjAw'
    'KQogICAgaWYgbm90IChST09ULydkZXZpY2UnKS5leGlzdHMoKToKICAgICAgICB3cml0ZShST09ULydkZXZpY2UnLCBzZWNy'
    'ZXRzLnRva2VuX2hleCgxNikpCiAgICBjb21tYW5kKFsnb3BlbnNzbCcsICdyZXEnLCAnLW5ldycsICcta2V5JywgUk9PVC8n'
    'Y2xpZW50LWtleS5wZW0nLCAnLXN1YmonLCAnL0NOPWV2Z2VuaXVtLWRldmljZScsCiAgICAgICAgICAgICAnLW91dCcsIFJP'
    'T1QvJ3JlcXVlc3QucGVtJ10pCiAgICBwYXlsb2FkID0geyd0b2tlbic6IHRva2VuLCAnZGV2aWNlJzogKFJPT1QvJ2Rldmlj'
    'ZScpLnJlYWRfdGV4dCgpLnN0cmlwKCksICdjc3InOiAoUk9PVC8ncmVxdWVzdC5wZW0nKS5yZWFkX3RleHQoKX0KICAgIGxh'
    'c3QgPSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG5h'
    'bWVzcGFjZSgpOgogICAgICAgICAgICAgICAgcmVwbHkgPSB0bHNfcmVxdWVzdChhZGRyZXNzLCAnL2Vucm9sbCcsIHBheWxv'
    'YWQsIHRpbWVvdXQ9NikKICAgICAgICAgICAgcHJvZmlsZSA9IHJlcGx5LmdldCgncHJvZmlsZScsIHt9KQogICAgICAgICAg'
    'ICBpZiByZXBseS5nZXQoJ29rJykgaXMgbm90IFRydWUgb3IgcHJvZmlsZS5nZXQoJ2NhJykgIT0gUElOTkVEX0NBIG9yIHBy'
    'b2ZpbGUuZ2V0KCdzZXJ2ZXInKSAhPSBTRVJWRVI6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFs'
    'aWRfcHJvZmlsZScpCiAgICAgICAgICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgcHJv'
    'ZmlsZS5nZXQoJ2lkZW50aXR5JywgJycpKToKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9p'
    'ZGVudGl0eScpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NsaWVudC5wZW0nLCBwcm9maWxlWydjZXJ0aWZpY2F0ZSddKQog'
    'ICAgICAgICAgICB3cml0ZShST09ULydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDkn'
    'LydjbGllbnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8neDUwOWNhJy8n'
    'Y2EucGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULydwcml2YXRlJy8nY2xpZW50LWtleS5wZW0nLCAo'
    'Uk9PVC8nY2xpZW50LWtleS5wZW0nKS5yZWFkX3RleHQoKSkKICAgICAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAndmVy'
    'aWZ5JywgJy1wdXJwb3NlJywgJ3NzbGNsaWVudCcsICctQ0FmaWxlJywgUk9PVC8nY2EucGVtJywgUk9PVC8nY2xpZW50LnBl'
    'bSddKQogICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAg'
    'ICAgY3R4LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0n'
    'KSkKICAgICAgICAgICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAgICAgICAgIGZpbmdlcnByaW50ID0gaGFzaGxp'
    'Yi5zaGEyNTYoanNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAn'
    'cHJlZnNyYycpfSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICB3cml0ZShST09U'
    'Lydwcm9maWxlLmpzb24nLCBqc29uLmR1bXBzKHsqKnByb2ZpbGUsICdlbmRwb2ludCc6IGFkZHJlc3MsICdwaHlzaWNhbF9u'
    'ZXR3b3JrJzogZmluZ2VycHJpbnR9KSkKICAgICAgICAgICAgcmV0dXJuIHByb2ZpbGVbJ2lkZW50aXR5J10sIGFkZHJlc3MK'
    'ICAgICAgICBleGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvciwgUnVudGltZUVycm9yKSBhcyBleGM6CiAgICAgICAgICAg'
    'IGxhc3QgPSBleGMKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZW5yb2xsbWVudF91bmF2YWlsYWJsZScpIGZyb20gbGFzdAoK'
    'CmRlZiBkYWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcyk6CiAgICBSVU5USU1FLm1rZGlyKG1vZGU9MG83MDAsIHBh'
    'cmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGluY2x1ZGVzID0gJ1xuJy5qb2luKCdpbmNsdWRlICcrc3RyKHApIGZv'
    'ciBwYXR0ZXJuIGluICgnL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicsICcvZXRjL3N0cm9uZ3N3YW4vc3Ryb25n'
    'c3dhbi5kL2NoYXJvbi8qLmNvbmYnKQogICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHAgaW4gUGF0aCgnLycpLmdsb2Io'
    'cGF0dGVybi5sc3RyaXAoJy8nKSkpCiAgICB3cml0ZShST09ULydzdHJvbmdzd2FuLmNvbmYnLCBmJycnY2hhcm9uIHt7CiBs'
    'b2FkX21vZHVsYXIgPSB5ZXMKIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdf'
    'dGFibGVfcHJpbyA9IDEwMAogcGx1Z2lucyB7ewp7aW5jbHVkZXN9CiAgdmljaSB7eyBzb2NrZXQgPSB1bml4Oi8ve1JVTlRJ'
    'TUV9L2NoYXJvbi52aWNpIH19CiAgcmVzb2x2ZSB7eyBsb2FkID0gbm8gfX0KICBrZXJuZWwtbGliaXBzZWMge3sgbG9hZCA9'
    'IG5vIH19CiB9fQp9fQpjaGFyb24tc3lzdGVtZCB7eyBqb3VybmFsIHt7IGRlZmF1bHQgPSAwOyBpa2UgPSAxIH19IH19Cicn'
    'JykKICAgICMgQWJzb2x1dGUgY3JlZGVudGlhbHMgYXJlIGxvY2FsIHRvIHRoaXMgZGV2aWNlLCBub3Qgc2hhcmVkIGJ5IHRo'
    'ZSBhY2NvdW50IHRva2VuLgogICAgd3JpdGUoUk9PVC8nY29ubmVjdGlvbi5jb25mJywgZicnJ2Nvbm5lY3Rpb25zIHt7CiBz'
    'dGFyZml2ZSB7ewogIHZlcnNpb24gPSAyCiAgcmVtb3RlX2FkZHJzID0ge2FkZHJlc3N9CiAgcmVtb3RlX3BvcnQgPSB7QUNU'
    'SVZFWydwb3J0J119CiAgbG9jYWxfcG9ydCA9IDQ1MDAKICB2aXBzID0gMC4wLjAuMAogIHByb3Bvc2FscyA9IGFlczI1Nmdj'
    'bTE2LXByZnNoYTM4NC1lY3AzODQKICBlbmNhcCA9IHllcwogIGZyYWdtZW50YXRpb24gPSB5ZXMKICBtb2Jpa2UgPSB5ZXMK'
    'ICBkcGRfZGVsYXkgPSAxNXMKICBsb2NhbCB7eyBhdXRoID0gZWFwLXRsczsgaWQgPSB7aWRlbnRpdHl9OyBlYXBfaWQgPSB7'
    'aWRlbnRpdHl9OyBjZXJ0cyA9IHtST09UfS9jbGllbnQucGVtIH19CiAgcmVtb3RlIHt7IGF1dGggPSBwdWJrZXk7IGlkID0g'
    'e0FDVElWRVsnaWRlbnRpdHknXX07IGNhY2VydHMgPSB7Uk9PVH0vY2EucGVtIH19CiAgY2hpbGRyZW4ge3sKICAgc3RhcmZp'
    'dmUtbmV0IHt7CiAgICBsb2NhbF90cyA9IGR5bmFtaWMKICAgIHJlbW90ZV90cyA9IDAuMC4wLjAvMAogICAgcmVxaWQgPSB7'
    'UkVRSUR9CiAgICBlc3BfcHJvcG9zYWxzID0gY2hhY2hhMjBwb2x5MTMwNQogICAgZHBkX2FjdGlvbiA9IGNsZWFyCiAgICBz'
    'dGFydF9hY3Rpb24gPSBub25lCiAgIH19CiAgfX0KIH19Cn19CnNlY3JldHMge3sgcHJpdmF0ZS1jbGllbnQge3sgZmlsZSA9'
    'IHtST09UfS9jbGllbnQta2V5LnBlbSB9fSB9fQonJycpCiAgICAjIFN0cm9uZ1N3YW4gY29uZmlnIHVzZXMgbmV3bGluZXMs'
    'IG5vdCBzZW1pY29sb24gc2VwYXJhdG9ycyAobm9ybWFsaXplIGNvbXBhY3QgYmxvY2tzKS4KICAgIGZvciBuYW1lIGluICgn'
    'c3Ryb25nc3dhbi5jb25mJywgJ2Nvbm5lY3Rpb24uY29uZicpOgogICAgICAgIHBhdGggPSBST09UL25hbWUKICAgICAgICBw'
    'YXRoLndyaXRlX3RleHQocGF0aC5yZWFkX3RleHQoKS5yZXBsYWNlKCc7ICcsICdcbicpLnJlcGxhY2UoJ3sgJywgJ3tcbicp'
    'LnJlcGxhY2UoJyB9JywgJ1xufScpKQogICAgcnVsZXMgPSBmJycndGFibGUgaW5ldCBldm5fc3RhcmZpdmVfZ3VhcmQge3sK'
    'IGNoYWluIG91dHB1dCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiAg'
    'b2lmbmFtZSAibG8iIGFjY2VwdAogIGlwIGRhZGRyIDEyNy4wLjAuMSB1ZHAgZHBvcnQgMjQ1NzMgYWNjZXB0CiAgb2lmbmFt'
    'ZSAie0ZVTExfUEVFUn0iIGlwIGRhZGRyIDE3Mi4yOS4yNDcuMSBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggc3Bv'
    'cnQgNTMgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFjY2VwdAogIGlw'
    'IGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBtZXRhIHNrdWlkIDAg'
    'aXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlwc2VjIG91dCBy'
    'ZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9y'
    'aXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBkYXRh'
    'PXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKCgpkZWYgc3dhbigqYXJncywgdGlt'
    'ZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRlKFsnc3dhbmN0bCcsICphcmdzLCAnLS11cmknLCAndW5p'
    'eDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1lb3V0PXRpbWVvdXQsIGNoZWNrPWNoZWNrKQoKCmRlZiBp'
    'bnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBzd2FuKCctLWxpc3Qtc2FzJywgJy0tcmF3JywgdGltZW91'
    'dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0LnJldHVybmNvZGUgPT0gMCBhbmQgJ3N0YXRlPUVTVEFC'
    'TElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5TVEFMTEVEJyBpbiByZXN1bHQuc3Rkb3V0CiAgICBleGNl'
    'cHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBoZWFs'
    'dGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0dXJuIHRsc19yZXF1ZXN0KEhFQUxUSCwgJy9oZWFsdGgn'
    'LCBjbGllbnQ9VHJ1ZSwgaWRlbnRpdHk9QUNUSVZFWydpZGVudGl0eSddLCB0aW1lb3V0PTMpLmdldCgnc2VydmljZScpID09'
    'ICdldmdlbml1bS1zdGFyZml2ZScKCgpkZWYgZG93bmxvYWQoc2l6ZT0xMDQ4NTc2KToKICAgICMgQSBib3VuZGVkIGludGVn'
    'cml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBtZWFzdXJlZCB0aGUgSVNQJ3MgbWF4aW11bSByYXRlLgogICAgYmxv'
    'Y2sgPSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVtLXN0YXJmaXZlLWludGVncml0eS12MScpLmRpZ2VzdCg2NTUzNikK'
    'ICAgIGV4cGVjdGVkID0gaGFzaGxpYi5zaGEyNTYoKGJsb2NrKihzaXplLy9sZW4oYmxvY2spKzEpKVs6c2l6ZV0pLmhleGRp'
    'Z2VzdCgpCiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FkYXRhPVBJTk5FRF9DQSkKICAgIGNv'
    'bnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScp'
    'KQogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICBzb2NrID0gc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChIRUFMVEgs'
    'IDg0NDMpLCB0aW1lb3V0PTEwKQogICAgICAgIHRscyA9IGNvbnRleHQud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3Ru'
    'YW1lPUFDVElWRVsnaWRlbnRpdHknXSkKICAgICAgICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24o'
    'SEVBTFRILCA4NDQzLCB0aW1lb3V0PTEwKTsgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAgICAgICAgdHJ5OgogICAgICAgICAg'
    'ICBzdGFydCA9IHRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAgY29ubmVjdGlvbi5yZXF1ZXN0KCdHRVQnLCAnL2Jsb2I/'
    'c2l6ZT0nK3N0cihzaXplKSkKICAgICAgICAgICAgcmVzcG9uc2UgPSBjb25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAg'
    'ICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMDoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndHJh'
    'bnNmZXJfaHR0cCcpCiAgICAgICAgICAgIGRpZ2VzdCA9IGhhc2hsaWIuc2hhMjU2KCk7IHJlY2VpdmVkID0gMAogICAgICAg'
    'ICAgICB3aGlsZSByZWNlaXZlZCA8IHNpemU6CiAgICAgICAgICAgICAgICBkYXRhID0gcmVzcG9uc2UucmVhZChtaW4oNjU1'
    'MzYsIHNpemUtcmVjZWl2ZWQpKQogICAgICAgICAgICAgICAgaWYgbm90IGRhdGE6CiAgICAgICAgICAgICAgICAgICAgYnJl'
    'YWsKICAgICAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoZGF0YSk7IHJlY2VpdmVkICs9IGxlbihkYXRhKQogICAgICAgICAg'
    'ICBlbGFwc2VkID0gdGltZS5tb25vdG9uaWMoKS1zdGFydAogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIGNvbm5lY3Rp'
    'b24uY2xvc2UoKQogICAgaWYgcmVjZWl2ZWQgIT0gc2l6ZSBvciBkaWdlc3QuaGV4ZGlnZXN0KCkgIT0gZXhwZWN0ZWQ6CiAg'
    'ICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnRlZ3JpdHlfZmFpbGVkJykKICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2'
    'ZWQsICdkb3dubG9hZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFwc2VkLzFlNiwgMiksCiAgICAgICAgICAgICdlbGFw'
    'c2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwgJ2ludGVncml0eSc6IFRydWUsICdsaW1pdGVkX3NhbXBsZSc6IFRydWV9'
    'CgoKZGVmIGRldmljZV9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICBpbmZvPWpzb24ubG9hZHMoKFJPT1QvJ2RldmljZS1p'
    'bmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICByZXR1cm4geydkZXZpY2VfbmFtZSc6aW5mby5nZXQoJ25hbWUnLCcn'
    'KSwnZGV2aWNlX251bWJlcic6aW5mby5nZXQoJ251bWJlcicpLAogICAgICAgICAgICAgICAgJ2RldmljZV9uYW1lX3BlbmRp'
    'bmcnOmJvb2woaW5mby5nZXQoJ3BlbmRpbmcnKSBvciBpbmZvLmdldCgnc3luY19lcnJvcicpKX0KICAgIGV4Y2VwdCAoT1NF'
    'cnJvcixWYWx1ZUVycm9yKTpyZXR1cm4geydkZXZpY2VfbmFtZSc6JycsJ2RldmljZV9udW1iZXInOk5vbmUsJ2RldmljZV9u'
    'YW1lX3BlbmRpbmcnOkZhbHNlfQoKCmRlZiBzeW5jX2RldmljZV9uYW1lKG5hbWU9Tm9uZSk6CiAgICBpbXBvcnQgdW5pY29k'
    'ZWRhdGEKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rva2VuJ106cmFpc2UgVmFsdWVFcnJvcign0KHQvdCw0YfQ'
    'sNC70LAg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCwLicpCiAgICBpZiBuYW1lIGlz'
    'IG5vdCBOb25lOgogICAgICAgIG5hbWU9dW5pY29kZWRhdGEubm9ybWFsaXplKCdORkMnLHN0cihuYW1lKSkuc3RyaXAoKQog'
    'ICAgICAgIGlmIG5vdCAxPD1sZW4obmFtZSk8PTY0IG9yIGFueSh1bmljb2RlZGF0YS5jYXRlZ29yeShjKS5zdGFydHN3aXRo'
    'KCdDJykgZm9yIGMgaW4gbmFtZSk6CiAgICAgICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CY0LzRjyDQtNC+0LvQttC90L4g'
    '0YHQvtC00LXRgNC20LDRgtGMINC+0YIgMSDQtNC+IDY0INC+0LHRi9GH0L3Ri9GFINGB0LjQvNCy0L7Qu9C+0LIuJykKICAg'
    'IGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6d3JpdGUoUk9PVC8nZGV2aWNlJyxzZWNyZXRzLnRva2VuX2hleCgx'
    'NikpCiAgICB0cnk6aW5mbz1qc29uLmxvYWRzKChST09ULydkZXZpY2UtaW5mby5qc29uJykucmVhZF90ZXh0KCkpCiAgICBl'
    'eGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6aW5mbz17fQogICAgaWYgbmFtZSBpcyBub3QgTm9uZTppbmZvLnVwZGF0ZShu'
    'YW1lPW5hbWUscGVuZGluZz1UcnVlKQogICAgcGF5bG9hZD17J3Rva2VuJzooUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5z'
    'dHJpcCgpLCdkZXZpY2UnOihST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5zdHJpcCgpfQogICAgaWYgaW5mby5nZXQoJ3Bl'
    'bmRpbmcnKTpwYXlsb2FkWyduYW1lJ109aW5mb1snbmFtZSddCiAgICB0cnk6CiAgICAgICAgd2l0aCBuYW1lc3BhY2UoKSBp'
    'ZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIGVsc2UgY29udGV4dGxpYi5udWxsY29udGV4dCgpOgogICAgICAg'
    'ICAgICByZXBseT10bHNfcmVxdWVzdChTRVJWRVIsJy9kZXZpY2UnLHBheWxvYWQsdGltZW91dD01KQogICAgICAgIHZhbHVl'
    'PXJlcGx5WydkZXZpY2UnXTtudW1iZXI9aW50KHZhbHVlWydudW1iZXInXSkKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZSh2'
    'YWx1ZVsnbmFtZSddLHN0cikgb3Igbm90IDE8PWxlbih2YWx1ZVsnbmFtZSddKTw9NjQgb3IgbnVtYmVyPDE6cmFpc2UgVmFs'
    'dWVFcnJvcignaW52YWxpZF9kZXZpY2VfbWV0YWRhdGEnKQogICAgICAgIGluZm89eyduYW1lJzp2YWx1ZVsnbmFtZSddLCdu'
    'dW1iZXInOm51bWJlciwncGVuZGluZyc6RmFsc2UsJ3N5bmNfZXJyb3InOkZhbHNlfQogICAgZXhjZXB0IChPU0Vycm9yLFJ1'
    'bnRpbWVFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yLGh0dHAuY2xpZW50LkhUVFBFeGNlcHRpb24pOgogICAgICAgIGluZm9b'
    'J3N5bmNfZXJyb3InXT1UcnVlCiAgICB3cml0ZShST09ULydkZXZpY2UtaW5mby5qc29uJyxqc29uLmR1bXBzKGluZm8sZW5z'
    'dXJlX2FzY2lpPUZhbHNlKSkKICAgIHJldHVybiBkZXZpY2Vfc3RhdHVzKCkKCgpkZWYgdG9rZW5fc3RhdHVzKCk6CiAgICB0'
    'cnk6CiAgICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5v'
    'dEZvdW5kRXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFsaWQgPSByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwg'
    'dG9rZW4pIGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9rZW4nOiB2YWxpZCwKICAgICAgICAgICAgJ3Rva2VuX2hp'
    'bnQnOiAnRVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hsaWIuc2hhMjU2KHRva2VuLmVuY29kZSgpKS5oZXhkaWdl'
    'c3QoKVs6OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90b2tlbih0b2tlbik6CiAgICB0b2tlbiA9IHRva2VuLnN0'
    'cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFZhbHVl'
    'RXJyb3IoJ9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC90YLQsCDRhNC+0YDQvNCw0YLQsCBFVk4xLeKApicpCiAg'
    'ICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIG9sZCA9IChST09ULyd0'
    'b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rva2VuJykuZXhpc3RzKCkgZWxzZSAnJwogICAgaWYgb2xk'
    'ID09IHRva2VuOgogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKTtyZXR1cm4KICAgIGlmIGNvbW1hbmQoWydzeXN0ZW1jdGwn'
    'LCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0YLQutC70Y7Rh9C40YLQtSBWUE4t0YLRg9C90L3QtdC70Ywg'
    '0L/QtdGA0LXQtCDRgdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicpCiAgICAjIEEgZGlmZmVyZW50IGFjY291bnQgbmVlZHMg'
    'aXRzIG93biBkZXZpY2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNlIGl0cyBjZXJ0aWZpY2F0ZS4KICAgIGZvciBuYW1lIGlu'
    'ICgnZGV2aWNlLWluZm8uanNvbicsICdkZXZpY2UnLCAnY2xpZW50LWtleS5wZW0nLCAnY2xpZW50LnBlbScsICdwcm9maWxl'
    'Lmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdwcml2YXRlL2NsaWVudC1rZXkucGVtJywgJ3g1MDkv'
    'Y2xpZW50LnBlbScsICdyYW5raW5nLmpzb24nLCAncmVjYWxpYnJhdGUnLCAnZXZlbnRzLmpzb24nLCAnc3VwcG9ydC1wcmV2'
    'aWV3Lmpzb24nKToKICAgICAgICAoUk9PVC9uYW1lKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgd3JpdGUoUk9PVC8n'
    'dG9rZW4nLCB0b2tlbikKICAgIHN5bmNfZGV2aWNlX25hbWUoKQogICAgc3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB0L7R'
    'hdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFsc2Us'
    'IG1ldHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1vZGU9'
    'MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4odG9r'
    'ZW4pCiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CS'
    '0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAg'
    'ZW5zdXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUoUk9PVC8ncmVjYWxpYnJhdGUnLCAn'
    'MScpCiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxsLWRldmljZSBFc3RvbmlhIFZQTgpB'
    'ZnRlcj1uZXR3b3JrLnRhcmdldApTdGFydExpbWl0SW50ZXJ2YWxTZWM9MTgwClN0YXJ0TGltaXRCdXJzdD0zCltTZXJ2aWNl'
    'XQpUeXBlPXNpbXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwK'
    'RXhlY1N0b3BQb3N0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKVGlt'
    'ZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9bWl4ZWQKVU1hc2s9MDA3NwpNZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PW9uLWZhaWx1'
    'cmUKUmVzdGFydFNlYz0zCicnJwogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1VOSVQsIHVuaXQpCiAg'
    'ICByZWNvdmVyeSA9ICJldmdlbml1bS1zdGFyZml2ZS10dW5uZWwtcmVjb3Zlci5zZXJ2aWNlIgogICAgd3JpdGUoUGF0aCgn'
    'L2V0Yy9zeXN0ZW1kL3N5c3RlbScpL3JlY292ZXJ5LCAiIiJbVW5pdF0KRGVzY3JpcHRpb249UmVjb3ZlciBvbmx5IGludGVy'
    'cnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0IHJlc291cmNlcwpEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2Fs'
    'LWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0IHZwbi14cmF5LnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9b25l'
    'c2hvdApFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwtY2xlYW51cApb'
    'SW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdkYWVt'
    'b24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2VuYWJsZScsIHJlY292ZXJ5XSkKICAgIGlmIHJlcGFp'
    'cjpjb21tYW5kKFsnc3lzdGVtY3RsJywncmVzZXQtZmFpbGVkJyxVTklUXSxjaGVjaz1GYWxzZSkKICAgIHN0YWdlKCdzdGFy'
    'dGluZycgLCAn0JPQvtGC0L7QstC70Y4g0L/QvtC00LrQu9GO0YfQtdC90LjQtSDQsiDQrdGB0YLQvtC90LjRji4nLCAyLCBh'
    'Y3RpdmU9RmFsc2UsIHJldHJ5PTAsIGVycm9yX2NvZGU9JycpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ3Jlc3RhcnQn'
    'IGlmIHJlcGFpciBlbHNlICdzdGFydCcsIFVOSVRdKQogICAgcHJpbnQoJ1ZQTiDQt9Cw0L/Rg9GB0LrQsNC10YLRgdGPLics'
    'Zmx1c2g9VHJ1ZSkKCgpkZWYgZGlzY29ubmVjdCgpOgogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdzdG9wJywgVU5JVF0s'
    'IGNoZWNrPUZhbHNlLCB0aW1lb3V0PTI1KQogICAgY2xlYW51cCgpCiAgICBjbGVhbnVwX2Z1bGwocmVsZWFzZT1UcnVlKQog'
    'ICAgc3RhZ2UoJ29mZicsICdWUE4g0LLRi9C60LvRjtGH0LXQvS4nLCAwLCBhY3RpdmU9RmFsc2UpCiAgICBwcmludCgnVlBO'
    'INCy0YvQutC70Y7Rh9C10L0uJykKCgpkZWYgc3RhcnRfZGFlbW9uKGVudik6CiAgICAoUlVOVElNRS8nY2hhcm9uLnZpY2kn'
    'KS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgbG9nID0gKFJPT1QvJ2NoYXJvbi5sb2cnKS5vcGVuKCd3JykKICAgIGRh'
    'ZW1vbiA9IHN1YnByb2Nlc3MuUG9wZW4oWydpcCcsICduZXRucycsICdleGVjJywgTlMsIGNoYXJvbl9iaW5hcnkoKV0sCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudj1lbnYsIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwgc3Rkb3V0PWxv'
    'Zywgc3RkZXJyPWxvZykKICAgIGxvZy5jbG9zZSgpCiAgICB0cnk6CiAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNjApOgogICAg'
    'ICAgICAgICBpZiBTVE9QIG9yIGRhZW1vbi5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ2RhZW1vbl9zdG9wcGVkJykKICAgICAgICAgICAgaWYgKFJVTlRJTUUvJ2NoYXJvbi52aWNpJykuZXhpc3Rz'
    'KCkgYW5kIHN3YW4oJy0tc3RhdHMnLCBjaGVjaz1GYWxzZSwgdGltZW91dD0xKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAg'
    'ICAgICAgICBicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgIHN3YW4oJy0tbG9hZC1jcmVkcycsICct'
    'LW5vcHJvbXB0JywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgc3dhbignLS1sb2FkLWNvbm5z'
    'JywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgcmV0dXJuIGRhZW1vbgogICAgZXhjZXB0IEJh'
    'c2VFeGNlcHRpb246CiAgICAgICAgc3RvcF9wcm9jZXNzKGRhZW1vbikKICAgICAgICByYWlzZQoKCmRlZiBzdG9wX3Byb2Nl'
    'c3MocHJvY2Vzcyk6CiAgICBpZiBwcm9jZXNzIGlzIG5vdCBOb25lIGFuZCBwcm9jZXNzLnBvbGwoKSBpcyBOb25lOgogICAg'
    'ICAgIHByb2Nlc3MudGVybWluYXRlKCkKICAgICAgICB0cnk6cHJvY2Vzcy53YWl0KHRpbWVvdXQ9NSkKICAgICAgICBleGNl'
    'cHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDpwcm9jZXNzLmtpbGwoKTtwcm9jZXNzLndhaXQodGltZW91dD0zKQoKCmRl'
    'ZiBzdG9wX2NhbmRpZGF0ZShkYWVtb249Tm9uZSk6CiAgICBnbG9iYWwgVExTX1BST0NFU1MKICAgIHN0b3BfcHJvY2Vzcyhk'
    'YWVtb24pCiAgICBzdG9wX3Byb2Nlc3MoVExTX1BST0NFU1MpO1RMU19QUk9DRVNTPU5vbmUKICAgIGNsZWFudXAoKQoKCmRl'
    'ZiBwcmVwYXJlX2RhdGFfcGxhbmUoYWRkcmVzcyk6CiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAg'
    'IGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdmdWxsX2ludGVyZmFjZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hv'
    'dycsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcignZnVsbF90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hv'
    'dycsJ3RhYmxlJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ2FkbWluX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgYW55KHIuZ2V0KCdwcmlvcml0eScpIGlu'
    'ICg3OSw4MCkgZm9yIHIgaW4ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCctaicsJy00JywncnVsZSddKS5zdGRvdXQpKToK'
    'ICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3J1bGVfY29sbGlzaW9uJykKICAgICAgICB3cml0ZShmdWxs'
    'X3N0YXRlKCksanNvbi5kdW1wcyh7J2FjdGl2ZSc6RmFsc2UsJ21lYXN1cmVtZW50X29ubHknOlRydWV9KSkKICAgIGZ1bGxf'
    'bmFtZXNwYWNlKGFkZHJlc3MpCiAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKCgpkZWYgc3RhcnRfY2FuZGlkYXRlKGNhbmRp'
    'ZGF0ZSxpZGVudGl0eSk6CiAgICBnbG9iYWwgQUNUSVZFLFRMU19QUk9DRVNTCiAgICBBQ1RJVkU9Y2FuZGlkYXRlCiAgICB3'
    'cml0ZShST09ULydhY3RpdmUtcGF0aC5qc29uJyxqc29uLmR1bXBzKHsnaWQnOmNhbmRpZGF0ZVsnaWQnXX0pKQogICAgc2V0'
    'dXBfbmV0d29yaygpCiAgICBkYWVtb25fY29uZmlncyhpZGVudGl0eSxjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgIGlmIGNh'
    'bmRpZGF0ZVsndGxzJ10gb3IgY2FuZGlkYXRlLmdldCgnZXZndCcpOgogICAgICAgIGlmIGNhbmRpZGF0ZS5nZXQoJ2V2Z3Qn'
    'KToKICAgICAgICAgICAgYmluYXJ5PWVuc3VyZV9ldmd0X2JpbmFyeSgpCiAgICAgICAgICAgIGNhcnJpZXI9W3N0cihiaW5h'
    'cnkpLCctbW9kZScsJ2NsaWVudCcsJy1zZXJ2ZXInLGNhbmRpZGF0ZVsnYWRkcmVzcyddKyc6MjQ1NzgnLCctc2VydmVyLW5h'
    'bWUnLGNhbmRpZGF0ZVsnaWRlbnRpdHknXSwKICAgICAgICAgICAgICAgICAgICAgJy11ZHAtbGlzdGVuJywnMTI3LjAuMC4x'
    'OjI0NTczJywnLXVkcC1wZWVyJyxDTElFTlQrJzo0NTAwJywKICAgICAgICAgICAgICAgICAgICAgJy1jYScsc3RyKFJPT1Qv'
    'J2NhLnBlbScpLCctY2VydCcsc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwnLWtleScsc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVt'
    'JyldCiAgICAgICAgZWxzZTpjYXJyaWVyPVsnL3Vzci9sb2NhbC9zYmluL3ZwbmN0bCcsJ2ludGVybmFsLXRscy1jbGllbnQn'
    'XQogICAgICAgIFRMU19QUk9DRVNTPXN1YnByb2Nlc3MuUG9wZW4oWydpcCcsJ25ldG5zJywnZXhlYycsTlMsKmNhcnJpZXJd'
    'LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLHN0ZG91dD1z'
    'dWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRlcnI9Tm9uZSBpZiBj'
    'YW5kaWRhdGUuZ2V0KCdldmd0JykgZWxzZSBzdWJwcm9jZXNzLkRFVk5VTEwpCiAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNTAp'
    'OgogICAgICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVkJykKICAgICAgICAgICAgaWYgVExT'
    'X1BST0NFU1MucG9sbCgpIGlzIG5vdCBOb25lOnJhaXNlIFJ1bnRpbWVFcnJvcigndGxzX2NhcnJpZXJfc3RvcHBlZCcpCiAg'
    'ICAgICAgICAgIGlmICcxMjcuMC4wLjE6MjQ1NzMnIGluIGluc2lkZShbJ3NzJywnLWFudSddLGNoZWNrPUZhbHNlKS5zdGRv'
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
    'KCdyYW5raW5nJywn0J/RgNC+0LLQtdGA0Y/RjiDQvNCw0YDRiNGA0YPRgjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sMTAraW50'
    'KGkqNjAvbGVuKENBTkRJREFURVMpKSxhY3RpdmU9RmFsc2UscGF0aD1jYW5kaWRhdGVbJ2lkJ10pCiAgICAgICAgICAgICAg'
    'ICB0cnk6CiAgICAgICAgICAgICAgICAgICAgZGFlbW9uPXN0YXJ0X2NhbmRpZGF0ZShjYW5kaWRhdGUsaWRlbnRpdHkpCiAg'
    'ICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PWRvd25sb2FkKDEwNDg1NzYpCiAgICAgICAgICAgICAgICAgICAgbWVhc3Vy'
    'ZW1lbnRzW2NhbmRpZGF0ZVsnaWQnXV09eydvayc6VHJ1ZSwqKnNwZWVkX3NhbXBsZSgyMDk3MTUyKSwnaW50ZWdyaXR5Jzpp'
    'bnRlZ3JpdHlbJ2ludGVncml0eSddfQogICAgICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGlt'
    'ZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6cmV0dXJuCiAg'
    'ICAgICAgICAgICAgICAgICAgbWVhc3VyZW1lbnRzW2NhbmRpZGF0ZVsnaWQnXV09eydvayc6RmFsc2V9CiAgICAgICAgICAg'
    'ICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgICAgIHN0b3BfY2FuZGlkYXRlKGRhZW1vbik7ZGFlbW9uPU5vbmUKICAg'
    'ICAgICAgICAgcmFuay5idWlsZChtZWFzdXJlbWVudHMpCiAgICAgICAgICAgIChST09ULydyZWNhbGlicmF0ZScpLnVubGlu'
    'ayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgY2FuZGlkYXRlcz17eFsnaWQnXTp4IGZvciB4IGluIENBTkRJREFURVN9CiAg'
    'ICAgICAgY3VycmVudD1uZXh0KGl0ZXIocmFuay5jYW5kaWRhdGVzKCkpLE5vbmUpCiAgICAgICAgd2hpbGUgY3VycmVudCBh'
    'bmQgbm90IFNUT1A6CiAgICAgICAgICAgIGNhbmRpZGF0ZT1jYW5kaWRhdGVzW2N1cnJlbnRdCiAgICAgICAgICAgIHRyeToK'
    'ICAgICAgICAgICAgICAgIHN0YWdlKCdoYW5kc2hha2UnLCfQn9C+0LTQutC70Y7Rh9Cw0Y46ICcrY2FuZGlkYXRlWydsYWJl'
    'bCddLDc1LGFjdGl2ZT1GYWxzZSxwYXRoPWN1cnJlbnQpCiAgICAgICAgICAgICAgICBkYWVtb249c3RhcnRfY2FuZGlkYXRl'
    'KGNhbmRpZGF0ZSxpZGVudGl0eSkKICAgICAgICAgICAgICAgIHN0YWdlKCdyb3V0aW5nJywn0J/QvtC00LrQu9GO0YfQsNGO'
    'INGC0YDQsNGE0LjQuiDQuiDQv9GA0L7QstC10YDQtdC90L3QvtC80YMg0LzQsNGA0YjRgNGD0YLRgy4nLDkyKQogICAgICAg'
    'ICAgICAgICAgYWN0aXZhdGVfZnVsbChjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgICAgICAgICAgICAgIHN0YWdlKCdjb25u'
    'ZWN0ZWQnLCfQn9C+0LTQutC70Y7Rh9C10L3QvjogJytjYW5kaWRhdGVbJ2xhYmVsJ10rJy4nLDEwMCxhY3RpdmU9VHJ1ZSxw'
    'YXRoPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgICBtZXRyaWNzPXJhbmsuZGF0YVsnZW50cmllcyddW2N1cnJlbnRd'
    'LHNpbmNlPWludCh0aW1lLnRpbWUoKSksZXJyb3JfY29kZT0nJykKICAgICAgICAgICAgICAgIGZhaWx1cmVzPTA7c2xvdz0w'
    'O2xhc3RfdHJhZmZpYz10cmFmZmljX3RvdGFsKCk7bmV4dF9zcGVlZD10aW1lLm1vbm90b25pYygpKzYwMCtzZWNyZXRzLnJh'
    'bmRiZWxvdyg2MCkKICAgICAgICAgICAgICAgIHdoaWxlIG5vdCBTVE9QOgogICAgICAgICAgICAgICAgICAgIGZvciBfIGlu'
    'IHJhbmdlKDUwKToKICAgICAgICAgICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgICAgICAg'
    'ICB0aW1lLnNsZWVwKC4xKQogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgICAgICB0'
    'cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZTpwb2xpY3kuZW5zdXJlX3JvdXRlKCkK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgaWYgRE5TX1BST0NFU1MgaXMgTm9uZSBvciBETlNfUFJPQ0VTUy5wb2xsKCkgaXMg'
    'bm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGFnZSgncmVwYWlyaW5nJywn0J/QtdGA0LXQt9Cw0L/R'
    'g9GB0LrQsNGOINC30LDRidC40YnRkdC90L3Ri9C5IEROUy4nLDkwLGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPSdwcml2YXRl'
    'X2Ruc19zdG9wcGVkJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICBoZWFsdGh5PWRhZW1vbi5wb2xsKCkgaXMgTm9uZSBhbmQgaW5zdGFsbGVkKCkgYW5kIGhlYWx0'
    'aCgpIGFuZCBlZ3Jlc3NfaGVhbHRoKCkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaGVhbHRoeSBhbmQgbm90IHJlY292'
    'ZXJfc3lzdGVtX2RucygpOnJhaXNlIFJ1bnRpbWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgICAgICAgICAgICAg'
    'ICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKTpo'
    'ZWFsdGh5PUZhbHNlCiAgICAgICAgICAgICAgICAgICAgZmFpbHVyZXM9MCBpZiBoZWFsdGh5IGVsc2UgZmFpbHVyZXMrMQog'
    'ICAgICAgICAgICAgICAgICAgIGlmIGZhaWx1cmVzPj0yOnJhaXNlIFJ1bnRpbWVFcnJvcigncGF0aF9oZWFsdGhfZmFpbGVk'
    'JykKICAgICAgICAgICAgICAgICAgICBpZiBub3QgaGVhbHRoeToKICAgICAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2No'
    'ZWNraW5nJywn0J7RgtCy0LXRgiDQt9Cw0LTQtdGA0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgtC10LrR'
    'g9GJ0LjQuSDQvNCw0YDRiNGA0YPRgi4nLDkwLGFjdGl2ZT1GYWxzZSkKICAgICAgICAgICAgICAgICAgICAgICAgY29udGlu'
    'dWUKICAgICAgICAgICAgICAgICAgICBpZiB0aW1lLm1vbm90b25pYygpPj1uZXh0X3NwZWVkOgogICAgICAgICAgICAgICAg'
    'ICAgICAgICB0cmFmZmljPXRyYWZmaWNfdG90YWwoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qgc2xvdyBhbmQg'
    'dHJhZmZpYy1sYXN0X3RyYWZmaWM8NDE5NDMwNDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhc3RfdHJhZmZpYz10'
    'cmFmZmljO25leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSs2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYwog'
    'ICAgICAgICAgICAgICAgICAgICAgICBzYW1wbGU9c3BlZWRfc2FtcGxlKDIwOTcxNTIpO2Jhc2VsaW5lPXJhbmsuZGF0YVsn'
    'ZW50cmllcyddW2N1cnJlbnRdCiAgICAgICAgICAgICAgICAgICAgICAgIGRlZ3JhZGVkPXNwZWVkX2RlZ3JhZGVkKHNhbXBs'
    'ZSxiYXNlbGluZSkKICAgICAgICAgICAgICAgICAgICAgICAgc2xvdz1zbG93KzEgaWYgZGVncmFkZWQgZWxzZSAwCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIG5leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSsoMjAgaWYgc2xvdyBlbHNlIDYwMCtzZWNy'
    'ZXRzLnJhbmRiZWxvdyg2MCkpCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHNsb3c+PTM6cmFpc2UgUnVudGltZUVycm9y'
    'KCdjb25maXJtZWRfc3BlZWRfZHJvcCcpCiAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC6'
    '0LvRjtGH0LXQvdC+OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCxlcnJv'
    'cl9jb2RlPScnKQogICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vz'
    'cy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAg'
    'cmVhc29uPXN0cihleGMpIGlmIHJlLmZ1bGxtYXRjaCgnW2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlv'
    'bl9mYWlsZWQnCiAgICAgICAgICAgICAgICAjIEEgbWlzc2luZyBwaHlzaWNhbCBpbnRlcmZhY2UgaXMgbm90IGEgdHJhbnNw'
    'b3J0J3MgZGVmZWF0LgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIHJvdXRlPXBoeXNpY2FsX3Jv'
    'dXRlKCk7Y2Fycmllcj1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL3JvdXRlWydkZXYnXS8nY2FycmllcicKICAgICAgICAgICAg'
    'ICAgICAgICBvZmZsaW5lPWNhcnJpZXIuZXhpc3RzKCkgYW5kIGNhcnJpZXIucmVhZF90ZXh0KCkuc3RyaXAoKT09JzAnCiAg'
    'ICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsUnVudGltZUVycm9yKTpvZmZsaW5lPVRydWUKICAgICAgICAgICAgICAg'
    'IGlmIG5vdCBvZmZsaW5lOgogICAgICAgICAgICAgICAgICAgIHJhbmsubG9zZShjdXJyZW50LHJlYXNvbikKICAgICAgICAg'
    'ICAgICAgICAgICBmb2xsb3dpbmc9cmFuay5uZXh0X2FmdGVyKGN1cnJlbnQpCiAgICAgICAgICAgICAgICAgICAgY3VycmVu'
    'dD1mb2xsb3dpbmcgb3IgbmV4dChpdGVyKHJhbmsuY2FuZGlkYXRlcygpKSxOb25lKQogICAgICAgICAgICAgICAgc3RhZ2Uo'
    'J3JlcGFpcmluZycsJ9Ch0LLRj9C30Ywg0L/QvtGC0LXRgNGP0L3QsC4g0J/QtdGA0LXQutC70Y7Rh9Cw0Y4g0LfQsNGJ0LjR'
    'idGR0L3QvdGL0Lkg0LzQsNGA0YjRgNGD0YIuJyBpZiBub3Qgb2ZmbGluZSBlbHNlICfQntC20LjQtNCw0Y4g0LLQvtGB0YHR'
    'gtCw0L3QvtCy0LvQtdC90LjRjyDRhNC40LfQuNGH0LXRgdC60L7QuSDRgdC10YLQuC4nLDY1LAogICAgICAgICAgICAgICAg'
    'ICAgICAgYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9cmVhc29uKQogICAgICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoMzAg'
    'aWYgbm90IG9mZmxpbmUgZWxzZSAxMDApOgogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAg'
    'ICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgc3RvcF9jYW5kaWRh'
    'dGUoZGFlbW9uKTtkYWVtb249Tm9uZQogICAgICAgIGlmIG5vdCBTVE9QOgogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn'
    '0JTQvtGB0YLRg9C/0L3Ri9C1INC80LDRgNGI0YDRg9GC0Ysg0LjRgdGH0LXRgNC/0LDQu9C4INGC0YDQuCDQv9C+0L/Ri9GC'
    '0LrQuC4g0J3QsNC20LzQuNGC0LUgwqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuyDQtNC70Y8g0L3QvtCy0L7Qs9C+INGA'
    '0LXQudGC0LjQvdCz0LAuJywwLAogICAgICAgICAgICAgICAgICBhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0ncmFua2luZ19l'
    'eGhhdXN0ZWQnKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91'
    'dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBub3QgU1RPUDoKICAgICAgICAgICAgY29kZT1zdHIoZXhjKSBpZiByZS5m'
    'dWxsbWF0Y2goJ1thLXpfXXsxLDY0fScsc3RyKGV4YykpIGVsc2UgJ2Nvbm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICBz'
    'dGFnZSgnZmFpbGVkJywn0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTQs9C+0YLQvtCy0LjRgtGMIFZQTi4g0J3QsNC20LzQ'
    'uNGC0LUgwqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuy4nLDAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9Y29kZSkKICAg'
    'IGZpbmFsbHk6CiAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKQogICAgICAgIGlmIFNUT1A6c3RhZ2UoJ29mZicsJ1ZQ'
    'TiDQstGL0LrQu9GO0YfQtdC9LicsMCxhY3RpdmU9RmFsc2UpCg=='
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
    'ZGRyIHt0dW5uZWwuQ0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1NzggfX0g'
    'YWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0dW5u'
    'ZWwuU0VSVkVSfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBkYWRkciB7dHVu'
    'bmVsLkNMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBpaWZuYW1lICJ3YXlkcm9pZDAiIG1l'
    'dGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBhY2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZw'
    'cm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFt'
    'ZSAie1RVTn0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgIntUVU59IiBjdCBzdGF0ZSBlc3RhYmxpc2hl'
    'ZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0'
    'CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie3R1bm5lbC5GVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxy'
    'ZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKClVOSVQ9JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGxvY2FsIGFwcGxp'
    'Y2F0aW9uIGFuZCBkb21haW4gcm91dGluZwpBZnRlcj1uZXR3b3JrLnRhcmdldApXYW50cz1ldmdlbml1bS13YXlkcm9pZC1u'
    'ZXR3b3JrLnNlcnZpY2UKW1NlcnZpY2VdClVzZXI9dnBuLXhyYXkKR3JvdXA9dnBuLXhyYXkKRXhlY1N0YXJ0PS9vcHQvdnBu'
    'LW1hbmFnZXIvYmluL3hyYXkgcnVuIC1jb25maWcgL3J1bi92cG4tbWFuYWdlci9wb2xpY3kuanNvbgpSZXN0YXJ0PW9uLWZh'
    'aWx1cmUKUmVzdGFydFNlYz0yCkFtYmllbnRDYXBhYmlsaXRpZXM9Q0FQX05FVF9BRE1JTiBDQVBfTkVUX1JBVyBDQVBfU1lT'
    'X1BUUkFDRSBDQVBfREFDX1JFQURfU0VBUkNICkNhcGFiaWxpdHlCb3VuZGluZ1NldD1DQVBfTkVUX0FETUlOIENBUF9ORVRf'
    'UkFXIENBUF9TWVNfUFRSQUNFIENBUF9EQUNfUkVBRF9TRUFSQ0gKTm9OZXdQcml2aWxlZ2VzPXRydWUKUHJvdGVjdFN5c3Rl'
    'bT1zdHJpY3QKUHJvdGVjdEhvbWU9dHJ1ZQpQcml2YXRlVG1wPXRydWUKRGV2aWNlQWxsb3c9L2Rldi9uZXQvdHVuIHJ3ClVN'
    'YXNrPTAwNzcKJycnCgpXQVlEUk9JRF9VTklUPScnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBXYXlkcm9pZCBuZXR3'
    'b3JrIGxpZmVjeWNsZQpBZnRlcj1ldmdlbml1bS1wb2xpY3kuc2VydmljZQpQYXJ0T2Y9ZXZnZW5pdW0tcG9saWN5LnNlcnZp'
    'Y2UKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXdheWRyb2lkLXdhdGNoClJl'
    'c3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0U2VjPTIKVU1hc2s9MDA3NwonJycKCmRlZiB3YXlkcm9pZF9uZXR3b3JrKCk6CiBy'
    'ZXN1bHQ9dHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hvdycsJ2RldicsJ3dheWRyb2lkMCddLGNo'
    'ZWNrPUZhbHNlKQogaWYgcmVzdWx0LnJldHVybmNvZGU6cmV0dXJuIHsnaW5kZXgnOk5vbmUsJ25ldHdvcmtzJzpbXX0KIGxp'
    'bmtzPWpzb24ubG9hZHMocmVzdWx0LnN0ZG91dCkKIG5ldHdvcmtzPXNvcnRlZCh7c3RyKGlwYWRkcmVzcy5pcF9uZXR3b3Jr'
    'KGYie2FbJ2xvY2FsJ119L3thWydwcmVmaXhsZW4nXX0iLHN0cmljdD1GYWxzZSkpIGZvciBsaW5rIGluIGxpbmtzIGlmICdV'
    'UCcgaW4gbGluay5nZXQoJ2ZsYWdzJyxbXSkgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlmIGEuZ2V0KCdz'
    'Y29wZScpPT0nZ2xvYmFsJ30pCiByZXR1cm4geydpbmRleCc6bGlua3NbMF0uZ2V0KCdpZmluZGV4JykgaWYgbGlua3MgZWxz'
    'ZSBOb25lLCduZXR3b3Jrcyc6bmV0d29ya3N9CgpkZWYgc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPUZhbHNlKToKICMg'
    'Q2FsbGVyIGhvbGRzIG9wZXJhdGlvbi5sb2NrLiBPbmx5IHRoaXMgVlBOJ3Mgc2V0L3RhYmxlIGFyZSBtb2RpZmllZC4KIHN0'
    'YXRlPXdheWRyb2lkX25ldHdvcmsoKTtjYWNoZT1SVU4vJ3dheWRyb2lkLW5ldHdvcmsuanNvbicKIHRyeTpwcmV2aW91cz1q'
    'c29uLmxvYWRzKGNhY2hlLnJlYWRfdGV4dCgpKQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnByZXZpb3VzPU5vbmUK'
    'IGlmIG5vdCBmb3JjZSBhbmQgc3RhdGU9PXByZXZpb3VzOnJldHVybgogcm91dGVzPWpzb24ubG9hZHModHVubmVsLmNvbW1h'
    'bmQoWydpcCcsJy1qJywnLTQnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKS5zdGRvdXQpCiBzdGFs'
    'ZT17clsnZHN0J10gZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdkZXYnKT09J3dheWRyb2lkMCcgYW5kIHIuZ2V0KCdkc3Qn'
    'KSBub3QgaW4gc3RhdGVbJ25ldHdvcmtzJ119CiBmb3IgbmV0d29yayBpbiBzdGF0ZVsnbmV0d29ya3MnXToKICB0dW5uZWwu'
    'Y29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLCd3YXlkcm9pZDAnLCdzY29wZScsJ2xpbmsn'
    'LCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogcnVsZXM9J2ZsdXNoIHNldCBpbmV0ICcrdHVubmVsLkZVTExfR1VBUkQrJyB3'
    'YXlkcm9pZF9uZXR3b3Jrc1xuJwogaWYgc3RhdGVbJ25ldHdvcmtzJ106cnVsZXMrPSdhZGQgZWxlbWVudCBpbmV0ICcrdHVu'
    'bmVsLkZVTExfR1VBUkQrJyB3YXlkcm9pZF9uZXR3b3JrcyAnK25mdF9zZXQoc3RhdGVbJ25ldHdvcmtzJ10pKydcbicKIHR1'
    'bm5lbC5jb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKIGZvciBuZXR3b3JrIGluIHN0YWxlOnR1bm5lbC5j'
    'b21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsbmV0d29yaywnZGV2Jywnd2F5ZHJvaWQwJywndGFibGUnLFBIWVNJQ0FMX1RB'
    'QkxFXSxjaGVjaz1GYWxzZSkKIGNhY2hlLndyaXRlX3RleHQoanNvbi5kdW1wcyhzdGF0ZSkpO2NhY2hlLmNobW9kKDBvNjAw'
    'KQoKZGVmIHdhdGNoX3dheWRyb2lkKCk6CiBpbXBvcnQgc3lzCiBsYXN0X2Vycm9yPU5vbmUKIHdoaWxlIFRydWU6CiAgdHJ5'
    'OgogICBSVU4ubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgIHdpdGggKFJVTi8nb3BlcmF0aW9uLmxvY2sn'
    'KS5vcGVuKCdhKycpIGFzIGxvY2s6CiAgICB0cnk6ZmNudGwuZmxvY2sobG9jayxmY250bC5MT0NLX0VYfGZjbnRsLkxPQ0tf'
    'TkIpCiAgICBleGNlcHQgQmxvY2tpbmdJT0Vycm9yOnBhc3MKICAgIGVsc2U6CiAgICAgaWYgdHVubmVsLmZ1bGxfZ3VhcmRf'
    'YWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKTpzeW5jX3dheWRyb2lkX25ldHdvcmso'
    'KQogICBsYXN0X2Vycm9yPU5vbmUKICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgbWVzc2FnZT1zdHIoZXhjKQogICBp'
    'ZiBtZXNzYWdlIT1sYXN0X2Vycm9yOnByaW50KCdXYXlkcm9pZCBuZXR3b3JrIHN5bmM6ICcrbWVzc2FnZSxmaWxlPXN5cy5z'
    'dGRlcnIsZmx1c2g9VHJ1ZSkKICAgbGFzdF9lcnJvcj1tZXNzYWdlCiAgdGltZS5zbGVlcCgxKQoKZGVmIGluc3RhbGwoKToK'
    'IFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vJytTRVJWSUNFKS53cml0ZV90ZXh0KFVOSVQpCiBQYXRoKCcvZXRjL3N5c3Rl'
    'bWQvc3lzdGVtLycrV0FZRFJPSURfU0VSVklDRSkud3JpdGVfdGV4dChXQVlEUk9JRF9VTklUKQogdHVubmVsLmNvbW1hbmQo'
    'WydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCgpkZWYgYXBwbHkoKToKIHA9bG9hZCgpO3NldHRpbmdzPWFwaS5sb2Fk'
    'X3NldHRpbmdzKCk7cm91dGU9dHVubmVsLnBoeXNpY2FsX3JvdXRlKCk7bGFuPWxvY2FsX25ldHdvcmtzKHJvdXRlKQogYXBp'
    'LmVuc3VyZV9ydW50aW1lKHNldHRpbmdzKQogY2ZnPVJVTi8ncG9saWN5Lmpzb24nO3RtcD1SVU4vJ3BvbGljeS5uZXcuanNv'
    'bicKIHRtcC53cml0ZV90ZXh0KGpzb24uZHVtcHMoY29uZmlnKHApKSk7b3MuY2htb2QodG1wLDBvNjQwKTtvcy5jaG93bih0'
    'bXAsMCxpbnQoc2V0dGluZ3NbJ3hyYXlfZ2lkJ10pKQogY2hlY2s9dHVubmVsLmNvbW1hbmQoW2FwaS5YUkFZLCdydW4nLCct'
    'dGVzdCcsJy1jb25maWcnLHRtcF0sY2hlY2s9RmFsc2UpCiBpZiBjaGVjay5yZXR1cm5jb2RlOnJhaXNlIFJ1bnRpbWVFcnJv'
    'cign0J7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH0LXQvdC40Lkg0L3QtSDQv9GA0LjQvdGP0Lsg0L3QsNGB0YLR'
    'gNC+0LnQutC4LicpCiBydWxlcz1maXJld2FsbChwLGxhbixpbnQoc2V0dGluZ3NbJ3hyYXlfdWlkJ10pKQogcmVwbGFjZW1l'
    'bnQ9KCdkZWxldGUgdGFibGUgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJEKydcbicgaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0'
    'aXZlKCkgZWxzZSAnJykrcnVsZXMKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2Vt'
    'ZW50KQogb3duZXJzaGlwPVBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0d29yay5qc29uJykKIGlmIG5vdCBvd25lcnNoaXAu'
    'ZXhpc3RzKCk6CiAgZm9yIHRhYmxlIGluIChQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEUpOgogICBpZiB0dW5uZWwuY29tbWFu'
    'ZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6cmFpc2Ug'
    'UnVudGltZUVycm9yKCfQotCw0LHQu9C40YbQsCDQvNCw0YDRiNGA0YPRgtC40LfQsNGG0LjQuCDQuNGB0LrQu9GO0YfQtdC9'
    '0LjQuSDQt9Cw0L3Rj9GC0LAg0LTRgNGD0LPQvtC5INC/0YDQvtCz0YDQsNC80LzQvtC5LicpCiAgZXhpc3Rpbmc9anNvbi5s'
    'b2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KQogIGlmIGFueShyLmdldCgncHJp'
    'b3JpdHknKSBpbiAoNzYsNzcsNzgpIGZvciByIGluIGV4aXN0aW5nKTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cf0YDQuNC+0YDQ'
    'uNGC0LXRgtGLINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4INC40YHQutC70Y7Rh9C10L3QuNC5INC30LDQvdGP0YLRiyDQ'
    'tNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykKICB0dW5uZWwud3JpdGUob3duZXJzaGlwLGpzb24uZHVtcHMo'
    'eyd0YWJsZXMnOltQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEVdfSkpCiAjIEJ1aWxkIHBoeXNpY2FsIGFuZCBWUE4tb25seSB0'
    'YWJsZXMgYmVmb3JlIGFsbG93aW5nIGFueSBuZXcgbWFya3MuCiBmb3IgdGFibGUgaW4gKFBIWVNJQ0FMX1RBQkxFLFZQTl9U'
    'QUJMRSk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywnZGVmYXVsdCcs'
    'J21ldHJpYycsJzMyNzYwJywndGFibGUnLHRhYmxlXSkKIGZvciBuZXR3b3JrIGluIGxhbitbJzE2OS4yNTQuMC4wLzE2Jywn'
    'MjI0LjAuMC4wLzQnXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLHJv'
    'dXRlWydkZXYnXSwnc2NvcGUnLCdsaW5rJywndGFibGUnLFBIWVNJQ0FMX1RBQkxFXSkKIHR1bm5lbC5jb21tYW5kKFsnaXAn'
    'LCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJyxyb3V0ZVsnZ2F0ZXdheSddLCdkZXYnLHJvdXRlWydkZXYnXSwn'
    'bWV0cmljJywnMTAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVw'
    'bGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLHR1bm5lbC5GVUxMX0hPU1QsJ21ldHJpYycsJzEw'
    'JywndGFibGUnLFZQTl9UQUJMRV0pCiBmb3IgcHJpb3JpdHksbWFyayx0YWJsZSBpbiBbKDc2LERJUkVDVCxQSFlTSUNBTF9U'
    'QUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5'
    'Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogIHR1bm5lbC5jb21t'
    'YW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLHByaW9yaXR5LCdmd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0'
    'YWJsZV0pCiAjIFJlcGxpZXMgdG8gYSBmb3J3YXJkZWQgY29udGFpbmVyIHJldHVybiB0aHJvdWdoIGl0cyBjb25uZWN0ZWQg'
    'bWFpbiByb3V0ZS4KIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lpZicsVFVO'
    'LCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9y'
    'aXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbiddKQogIyBBIHRlbXBvcmFyeSBjbG9zZWQgc3RhdGUgaXMgYWNj'
    'ZXB0YWJsZTsgYW4gdW5ndWFyZGVkIHN0YXRlIGlzIG5vdC4KIG9zLnJlcGxhY2UodG1wLGNmZykKIHR1bm5lbC53cml0ZSh0'
    'dW5uZWwuUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogdHVubmVsLmNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRh'
    'PXJlcGxhY2VtZW50KQogc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPVRydWUpCiBpbnN0YWxsKCkKIHR1bm5lbC5jb21t'
    'YW5kKFsnc3lzdGVtY3RsJywncmVzdGFydCcsU0VSVklDRV0pCiBmb3IgXyBpbiByYW5nZSg4MCk6CiAgaWYgUGF0aCgnL3N5'
    'cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOmJyZWFrCiAgdGltZS5zbGVlcCguMSkKIGVsc2U6cmFpc2UgUnVudGltZUVy'
    'cm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC30LDQv9GD0YHRgtC40YLRjCDQvtCx0YDQsNCx0L7RgtGH0LjQuiDQuNGB0LrQ'
    'u9GO0YfQtdC90LjQuS4nKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCdkZXYn'
    'LFRVTiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZVTExfVEFCTEVdKQogdHVubmVsLmNsZWFyX2Ruc19tYXBwaW5n'
    'cygpCiAjIEV4cGxpY2l0bHkgcmVxdWVzdGVkIEROUyBleGNlcHRpb25zIG5lZWQgc3RhbGUgcG9ydC01MyBtYXBwaW5ncyBy'
    'ZW1vdmVkIHRvby4KIGZvciBwcm90byBpbiAoJ3VkcCcsJ3RjcCcpOgogIHR1bm5lbC5jb21tYW5kKFsnY29ubnRyYWNrJywn'
    'LUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG8sJy0tZHBvcnQnLCc1MycsJy0tcmVwbHktcG9ydC1zcmMnLHN0cihETlNfUE9S'
    'VCldLGNoZWNrPUZhbHNlKQoKCmRlZiBzdG9wKHJlbGVhc2U9RmFsc2UpOgogdHVubmVsLmNvbW1hbmQoWydzeXN0ZW1jdGwn'
    'LCdzdG9wJyxTRVJWSUNFXSxjaGVjaz1GYWxzZSkKIGlmIHJlbGVhc2UgYW5kIFBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0'
    'd29yay5qc29uJykuZXhpc3RzKCk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc4'
    'JywnaWlmJyxUVU4sJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICBmb3IgcHJpb3JpdHksbWFyayx0YWJsZSBpbiBb'
    'KDc2LERJUkVDVCxQSFlTSUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICAgdHVubmVsLmNvbW1hbmQoWydpcCcs'
    'J3J1bGUnLCdkZWwnLCdwcmlvcml0eScscHJpb3JpdHksJ2Z3bWFyaycsc3RyKG1hcmspLCdsb29rdXAnLHRhYmxlXSxjaGVj'
    'az1GYWxzZSkKICAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsdGFibGVdLGNoZWNrPUZh'
    'bHNlKQogIFBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0d29yay5qc29uJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgpk'
    'ZWYgY2hhbmdlKGFjdGlvbixjYXRlZ29yeT0nJyx2YWx1ZT0nJyxzdGF0ZT1Ob25lKToKIG9sZD1sb2FkKCk7cD1qc29uLmxv'
    'YWRzKGpzb24uZHVtcHMob2xkKSkKIGlmIGFjdGlvbj09J3dheWRyb2lkJzpwWyd3YXlkcm9pZF9kaXJlY3QnXT1ib29sKHN0'
    'YXRlKQogZWxpZiBhY3Rpb249PSdiYXNlJzoKICBpZiBjYXRlZ29yeSBub3QgaW4gQkFTRSBvciB2YWx1ZSBub3QgaW4ge2Vb'
    'J2lkJ10gZm9yIGUgaW4gQkFTRVtjYXRlZ29yeV19OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg'
    '0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uJykKICBrZXk9Y2F0ZWdvcnkrJzonK3ZhbHVlCiAgcFsnZGlzYWJsZWRf'
    'YmFzZSddPVt4IGZvciB4IGluIHBbJ2Rpc2FibGVkX2Jhc2UnXSBpZiB4IT1rZXldCiAgaWYgbm90IHN0YXRlOnBbJ2Rpc2Fi'
    'bGVkX2Jhc2UnXS5hcHBlbmQoa2V5KQogZWxpZiBhY3Rpb24gaW4gKCdhZGQnLCdyZW1vdmUnKToKICBpZiBjYXRlZ29yeSBu'
    'b3QgaW4gQ0FURUdPUklFUzpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGPINC60LDRgtC10LPQvtGA'
    '0LjRjy4nKQogIHZhbHVlPW5vcm1hbGl6ZShjYXRlZ29yeSx2YWx1ZSkKICBpZiBhY3Rpb249PSdhZGQnIGFuZCB2YWx1ZSBu'
    'b3QgaW4gcFtjYXRlZ29yeV06cFtjYXRlZ29yeV0uYXBwZW5kKHZhbHVlKQogIGlmIGFjdGlvbj09J3JlbW92ZSc6cFtjYXRl'
    'Z29yeV09W3ggZm9yIHggaW4gcFtjYXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBlbHNlOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQ'
    'uNC30LLQtdGB0YLQvdC+0LUg0LTQtdC50YHRgtCy0LjQtS4nKQogaWYgcD09b2xkOnJldHVybiBwdWJsaWMoKQogc2F2ZShw'
    'KQogaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrdHVubmVsLkZVTExf'
    'SE9TVCkuZXhpc3RzKCk6CiAgdHJ5OmFwcGx5KCkKICBleGNlcHQgRXhjZXB0aW9uOgogICBzYXZlKG9sZCkKICAgdHJ5OmFw'
    'cGx5KCkKICAgZXhjZXB0IEV4Y2VwdGlvbjpwYXNzCiAgIHJhaXNlCiByZXR1cm4gcHVibGljKCkKCmRlZiBlbnN1cmVfcm91'
    'dGUoKToKIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywn'
    'cm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ2RldicsVFVOLCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyx0dW5uZWwuRlVMTF9U'
    'QUJMRV0pCiBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcigncG9saWN5X2VuZ2luZV91bmF2YWlsYWJsZScpCg=='
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
    'ZXJfbm90X3JlYWR5J30KUEFUSFM9eydydS11ZHAnLCdlZS11ZHAnLCdlZS10bHMnLCdlZS1ldmd0JywnJ30KWEZSTT17J1hm'
    'cm1JbkVycm9yJywnWGZybUluTm9TdGF0ZXMnLCdYZnJtSW5TdGF0ZVByb3RvRXJyb3InLCdYZnJtSW5TdGF0ZVNlcUVycm9y'
    'JywnWGZybUluU3RhdGVFeHBpcmVkJywnWGZybUluU3RhdGVNaXNtYXRjaCcsJ1hmcm1JblRtcGxNaXNtYXRjaCcsJ1hmcm1J'
    'bk5vUG9scycsJ1hmcm1JblBvbEJsb2NrJywnWGZybU91dEVycm9yJywnWGZybU91dE5vU3RhdGVzJywnWGZybU91dFN0YXRl'
    'RXhwaXJlZCcsJ1hmcm1PdXRQb2xCbG9jayd9Ck5VTUJFUlM9WEZSTXx7J2Rvd25sb2FkX21icHMnLCd1cGxvYWRfbWJwcycs'
    'J2xhdGVuY3lfbXMnLCdzY29yZScsJ2xvc3NlcycsJ3NhbXBsZV9ieXRlcycsJ3J4X2J5dGVzJywndHhfYnl0ZXMnLCdyeF9w'
    'YWNrZXRzJywndHhfcGFja2V0cycsJ3J4X2Vycm9ycycsJ3R4X2Vycm9ycycsJ3J4X2Ryb3BwZWQnLCd0eF9kcm9wcGVkJ30K'
    'ZGVmIG51bWJlcih2KToKIGlmIHR5cGUodikgbm90IGluIChpbnQsZmxvYXQpIG9yIG5vdCBtYXRoLmlzZmluaXRlKHYpIG9y'
    'IG5vdCAwPD12PD0yKio2MzpyYWlzZSBWYWx1ZUVycm9yKCdtZXRyaWMnKQogcmV0dXJuIHJvdW5kKHYsMykgaWYgaXNpbnN0'
    'YW5jZSh2LGZsb2F0KSBlbHNlIHYKCmRlZiBjbGVhbl9idW5kbGUoYm9keSk6CiBpZiBub3QgaXNpbnN0YW5jZShib2R5LGRp'
    'Y3QpIG9yIGJvZHkuZ2V0KCdzY2hlbWEnKSE9MSBvciBib2R5LmdldCgnZXZlbnQnKSE9J3N1cHBvcnRfYnVuZGxlJyBvciBi'
    'b2R5LmdldCgnY29uc2VudCcpIGlzIG5vdCBUcnVlOnJhaXNlIFZhbHVlRXJyb3IoJ2NvbnNlbnQnKQogaWYgbm90IHJlLmZ1'
    'bGxtYXRjaCgnW2EtZjAtOV17MzJ9JyxzdHIoYm9keS5nZXQoJ3JlcG9ydF9pZCcsJycpKSk6cmFpc2UgVmFsdWVFcnJvcign'
    'cmVwb3J0X2lkJykKIHZlcnNpb249Ym9keS5nZXQoJ21hbmFnZXInLCcnKQogaWYgbm90IGlzaW5zdGFuY2UodmVyc2lvbixz'
    'dHIpIG9yIG5vdCByZS5mdWxsbWF0Y2gocidcZCtcLlxkK1wuXGQrJyx2ZXJzaW9uKTpyYWlzZSBWYWx1ZUVycm9yKCd2ZXJz'
    'aW9uJykKIGlmIGJvZHkuZ2V0KCdhcmNoaXRlY3R1cmUnKSBub3QgaW4geyd4ODZfNjQnLCdhYXJjaDY0JywncmlzY3Y2NCcs'
    'J290aGVyJ306cmFpc2UgVmFsdWVFcnJvcignYXJjaGl0ZWN0dXJlJykKIGlmIGJvZHkuZ2V0KCdzeXN0ZW0nKSBub3QgaW4g'
    'eydhcmNoJywnZW5kZWF2b3Vyb3MnLCdmZWRvcmEnLCdzdGVhbW9zJywnZGViaWFuJywndWJ1bnR1Jywnb3RoZXInfTpyYWlz'
    'ZSBWYWx1ZUVycm9yKCdzeXN0ZW0nKQogcmVzdWx0PXtrOmJvZHlba10gZm9yIGsgaW4gKCdzY2hlbWEnLCdldmVudCcsJ2Nv'
    'bnNlbnQnLCdyZXBvcnRfaWQnLCdtYW5hZ2VyJywnYXJjaGl0ZWN0dXJlJywnc3lzdGVtJyl9CiByZXN1bHRbJ3RpbWUnXT1u'
    'dW1iZXIoYm9keS5nZXQoJ3RpbWUnLDApKQogZXZlbnRzPWJvZHkuZ2V0KCdldmVudHMnLFtdKQogaWYgbm90IGlzaW5zdGFu'
    'Y2UoZXZlbnRzLGxpc3QpIG9yIGxlbihldmVudHMpPjEyODpyYWlzZSBWYWx1ZUVycm9yKCdldmVudHMnKQogcmVzdWx0Wydl'
    'dmVudHMnXT1bXQogZm9yIGl0ZW0gaW4gZXZlbnRzOgogIGlmIG5vdCBpc2luc3RhbmNlKGl0ZW0sZGljdCkgb3IgaXRlbS5n'
    'ZXQoJ3BoYXNlJykgbm90IGluIFBIQVNFUyBvciBpdGVtLmdldCgnY29kZScsJycpIG5vdCBpbiBDT0RFUyBvciBpdGVtLmdl'
    'dCgncGF0aCcsJycpIG5vdCBpbiBQQVRIUzpyYWlzZSBWYWx1ZUVycm9yKCdldmVudCcpCiAgcmVzdWx0WydldmVudHMnXS5h'
    'cHBlbmQoeyd0aW1lJzpudW1iZXIoaXRlbVsndGltZSddKSwncGhhc2UnOml0ZW1bJ3BoYXNlJ10sJ2NvZGUnOml0ZW0uZ2V0'
    'KCdjb2RlJywnJyksJ3BhdGgnOml0ZW0uZ2V0KCdwYXRoJywnJyksJ2FjdGl2ZSc6aXRlbS5nZXQoJ2FjdGl2ZScpIGlzIFRy'
    'dWV9KQogc3RhdGU9Ym9keS5nZXQoJ3N0YXRlJyx7fSkKIGlmIG5vdCBpc2luc3RhbmNlKHN0YXRlLGRpY3QpOnJhaXNlIFZh'
    'bHVlRXJyb3IoJ3N0YXRlJykKIHJlc3VsdFsnc3RhdGUnXT17azpzdGF0ZS5nZXQoaykgaXMgVHJ1ZSBmb3IgayBpbiAoJ2Fj'
    'dGl2ZScsJ2d1YXJkJywnbmFtZXNwYWNlJywnZG5zX2ZhbGxiYWNrJyl9CiByZXN1bHRbJ3BhdGhzJ109e30KIHBhdGhzPWJv'
    'ZHkuZ2V0KCdwYXRocycse30pCiBpZiBub3QgaXNpbnN0YW5jZShwYXRocyxkaWN0KSBvciBsZW4ocGF0aHMpPmxlbihQQVRI'
    'UyktMTpyYWlzZSBWYWx1ZUVycm9yKCdwYXRocycpCiBmb3IgbmFtZSx2YWx1ZXMgaW4gcGF0aHMuaXRlbXMoKToKICBpZiBu'
    'YW1lIG5vdCBpbiBQQVRIUy17Jyd9OnJhaXNlIFZhbHVlRXJyb3IoJ3BhdGgnKQogIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVl'
    'cyxkaWN0KTpyYWlzZSBWYWx1ZUVycm9yKCdwYXRoJykKICByZXN1bHRbJ3BhdGhzJ11bbmFtZV09e2s6bnVtYmVyKHYpIGZv'
    'ciBrLHYgaW4gdmFsdWVzLml0ZW1zKCkgaWYgayBpbiBOVU1CRVJTfQogY291bnRlcnM9Ym9keS5nZXQoJ2NvdW50ZXJzJyx7'
    'fSkKIGlmIG5vdCBpc2luc3RhbmNlKGNvdW50ZXJzLGRpY3QpOnJhaXNlIFZhbHVlRXJyb3IoJ2NvdW50ZXJzJykKIHJlc3Vs'
    'dFsnY291bnRlcnMnXT17azpudW1iZXIodikgZm9yIGssdiBpbiBjb3VudGVycy5pdGVtcygpIGlmIGsgaW4gTlVNQkVSU30K'
    'IHJldHVybiByZXN1bHQKCmRlZiByZWNvcmQocm9vdCx3cml0ZSxkYXRhKToKIGV2ZW50PXsndGltZSc6aW50KHRpbWUudGlt'
    'ZSgpKSwncGhhc2UnOmRhdGEuZ2V0KCdwaGFzZScpIGlmIGRhdGEuZ2V0KCdwaGFzZScpIGluIFBIQVNFUyBlbHNlICdmYWls'
    'ZWQnLAogICAgICAgICdjb2RlJzpkYXRhLmdldCgnZXJyb3JfY29kZScsJycpIGlmIGRhdGEuZ2V0KCdlcnJvcl9jb2RlJywn'
    'JykgaW4gQ09ERVMgZWxzZSAnb3RoZXInLAogICAgICAgICdwYXRoJzpkYXRhLmdldCgncGF0aCcsJycpIGlmIGRhdGEuZ2V0'
    'KCdwYXRoJywnJykgaW4gUEFUSFMgZWxzZSAnJywgJ2FjdGl2ZSc6ZGF0YS5nZXQoJ2FjdGl2ZScpIGlzIFRydWV9CiBwYXRo'
    'PXJvb3QvJ2V2ZW50cy5qc29uJwogdHJ5OmV2ZW50cz1qc29uLmxvYWRzKHBhdGgucmVhZF90ZXh0KCkpCiBleGNlcHQgKE9T'
    'RXJyb3IsVmFsdWVFcnJvcik6ZXZlbnRzPVtdCiBpZiBub3QgZXZlbnRzIG9yIGFueShldmVudHNbLTFdLmdldChrKSE9ZXZl'
    'bnRba10gZm9yIGsgaW4gKCdwaGFzZScsJ2NvZGUnLCdwYXRoJywnYWN0aXZlJykpOgogIHdyaXRlKHBhdGgsanNvbi5kdW1w'
    'cygoZXZlbnRzK1tldmVudF0pWy0xMjg6XSkpCgpkZWYgcHJlcGFyZSh0dW5uZWwsdmVyc2lvbik6CiB0cnk6ZXZlbnRzPWpz'
    'b24ubG9hZHMoKHR1bm5lbC5ST09ULydldmVudHMuanNvbicpLnJlYWRfdGV4dCgpKQogZXhjZXB0IChPU0Vycm9yLFZhbHVl'
    'RXJyb3IpOmV2ZW50cz1bXQogdHJ5OnBhdGhzPWpzb24ubG9hZHMoKHR1bm5lbC5ST09ULydyYW5raW5nLmpzb24nKS5yZWFk'
    'X3RleHQoKSlbJ2VudHJpZXMnXQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsS2V5RXJyb3IpOnBhdGhzPXt9CiB0cnk6'
    'bmV0d29yaz1qc29uLmxvYWRzKHR1bm5lbC5mdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiBleGNlcHQgKE9TRXJyb3IsVmFs'
    'dWVFcnJvcik6bmV0d29yaz17fQogdHJ5OnN5c3RlbT1wbGF0Zm9ybS5mcmVlZGVza3RvcF9vc19yZWxlYXNlKCkuZ2V0KCdJ'
    'RCcsJ290aGVyJykKIGV4Y2VwdCBPU0Vycm9yOnN5c3RlbT0nb3RoZXInCiBpZiBzeXN0ZW0gbm90IGluIHsnYXJjaCcsJ2Vu'
    'ZGVhdm91cm9zJywnZmVkb3JhJywnc3RlYW1vcycsJ2RlYmlhbicsJ3VidW50dSd9OnN5c3RlbT0nb3RoZXInCiBhcmNoPXBs'
    'YXRmb3JtLm1hY2hpbmUoKTthcmNoPWFyY2ggaWYgYXJjaCBpbiB7J3g4Nl82NCcsJ2FhcmNoNjQnLCdyaXNjdjY0J30gZWxz'
    'ZSAnb3RoZXInCiBjb3VudGVycz17fQogIyBPbmx5IHRoZSBWUE4ncyBvd24gaW50ZXJmYWNlLCBubyBwcm9jZXNzIGxpc3Qg'
    'b3IgcmVtb3RlIGFkZHJlc3Nlcy4KIHN0YXRzPVBhdGgoJy9zeXMvY2xhc3MvbmV0JykvdHVubmVsLkZVTExfSE9TVC8nc3Rh'
    'dGlzdGljcycKIGZvciBrZXkgaW4gKCdyeF9ieXRlcycsJ3R4X2J5dGVzJywncnhfcGFja2V0cycsJ3R4X3BhY2tldHMnLCdy'
    'eF9lcnJvcnMnLCd0eF9lcnJvcnMnLCdyeF9kcm9wcGVkJywndHhfZHJvcHBlZCcpOgogIHRyeTpjb3VudGVyc1trZXldPWlu'
    'dCgoc3RhdHMva2V5KS5yZWFkX3RleHQoKSkKICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6cGFzcwogaWYgUGF0aCgn'
    'L3J1bi9uZXRucycsdHVubmVsLk5TKS5leGlzdHMoKToKICB0cnk6CiAgIHJlc3VsdD10dW5uZWwuaW5zaWRlKFsnY2F0Jywn'
    'L3Byb2MvbmV0L3hmcm1fc3RhdCddLGNoZWNrPUZhbHNlLHRpbWVvdXQ9MikKICAgZm9yIGxpbmUgaW4gcmVzdWx0LnN0ZG91'
    'dC5zcGxpdGxpbmVzKCk6CiAgICBrZXksdmFsdWU9bGluZS5zcGxpdCgpCiAgICBpZiBrZXkgaW4gWEZSTTpjb3VudGVyc1tr'
    'ZXldPWludCh2YWx1ZSkKICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1l'
    'b3V0RXhwaXJlZCk6cGFzcwogcmVwb3J0PWNsZWFuX2J1bmRsZSh7J3NjaGVtYSc6MSwnZXZlbnQnOidzdXBwb3J0X2J1bmRs'
    'ZScsJ2NvbnNlbnQnOlRydWUsJ3JlcG9ydF9pZCc6c2VjcmV0cy50b2tlbl9oZXgoMTYpLAogICAnbWFuYWdlcic6dmVyc2lv'
    'biwndGltZSc6aW50KHRpbWUudGltZSgpKSwnYXJjaGl0ZWN0dXJlJzphcmNoLCdzeXN0ZW0nOnN5c3RlbSwnZXZlbnRzJzpl'
    'dmVudHMsCiAgICdwYXRocyc6cGF0aHMsJ2NvdW50ZXJzJzpjb3VudGVycywnc3RhdGUnOnsnYWN0aXZlJzp0dW5uZWwuc2F2'
    'ZWQoKS5nZXQoJ2FjdGl2ZScsRmFsc2UpLAogICAgJ2d1YXJkJzp0dW5uZWwuZnVsbF9ndWFyZF9hY3RpdmUoKSwnbmFtZXNw'
    'YWNlJzpQYXRoKCcvcnVuL25ldG5zJyx0dW5uZWwuTlMpLmV4aXN0cygpLCdkbnNfZmFsbGJhY2snOm5ldHdvcmsuZ2V0KCdk'
    'bnNfZmFsbGJhY2snLEZhbHNlKX19KQogIyBQcmVwYXJpbmcgYSBwcmV2aWV3IGlzIG5ldmVyIHBlcm1pc3Npb24gdG8gdHJh'
    'bnNtaXQgaXQuCiByZXBvcnRbJ2NvbnNlbnQnXT1GYWxzZQogdHVubmVsLndyaXRlKHR1bm5lbC5ST09ULydzdXBwb3J0LXBy'
    'ZXZpZXcuanNvbicsanNvbi5kdW1wcyhyZXBvcnQsZW5zdXJlX2FzY2lpPUZhbHNlLGluZGVudD0yKSkKIHJldHVybiByZXBv'
    'cnQKCmRlZiBzZW5kKHR1bm5lbCxyZXBvcnRfaWQsY29uc2VudCk6CiBpZiBjb25zZW50IGlzIG5vdCBUcnVlOnJhaXNlIFZh'
    'bHVlRXJyb3IoJ9CU0LvRjyDQvtGC0L/RgNCw0LLQutC4INGC0YDQtdCx0YPQtdGC0YHRjyDRj9Cy0L3QvtC1INGB0L7Qs9C7'
    '0LDRgdC40LUuJykKIHJlcG9ydD1qc29uLmxvYWRzKCh0dW5uZWwuUk9PVC8nc3VwcG9ydC1wcmV2aWV3Lmpzb24nKS5yZWFk'
    'X3RleHQoKSkKIGlmIHJlcG9ydC5nZXQoJ3JlcG9ydF9pZCcpIT1yZXBvcnRfaWQgb3IgdGltZS50aW1lKCktcmVwb3J0Lmdl'
    'dCgndGltZScsMCk+ODY0MDA6cmFpc2UgVmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00LPQvtGC0L7QstGM0YLQ'
    'tSDQvdC+0LLRi9C5INC+0YLRh9GR0YIuJykKIHJlcG9ydFsnY29uc2VudCddPVRydWU7cmVwb3J0PWNsZWFuX2J1bmRsZShy'
    'ZXBvcnQpCiAjIE5ldmVyIGluc3RhbGwgYSBieXBhc3MgYXJvdW5kIGFuIGFjdGl2ZSBraWxsIHN3aXRjaCB0byB1cGxvYWQg'
    'YSByZXBvcnQuCiBpZiBQYXRoKCcvcnVuL25ldG5zJyx0dW5uZWwuTlMpLmV4aXN0cygpIGFuZCB0dW5uZWwuaW5zdGFsbGVk'
    'KCk6CiAgdHJ5OnNlbGVjdGVkPWpzb24ubG9hZHMoKHR1bm5lbC5ST09ULydhY3RpdmUtcGF0aC5qc29uJykucmVhZF90ZXh0'
    'KCkpWydpZCddCiAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsS2V5RXJyb3IpOnNlbGVjdGVkPSdydS11ZHAnCiAgY2Fu'
    'ZGlkYXRlPW5leHQoeCBmb3IgeCBpbiB0dW5uZWwuQ0FORElEQVRFUyBpZiB4WydpZCddPT1zZWxlY3RlZCkKICB3aXRoIHR1'
    'bm5lbC5uYW1lc3BhY2UoKTpyZXBseT10dW5uZWwudGxzX3JlcXVlc3QodHVubmVsLkhFQUxUSCwnL3JlcG9ydCcscmVwb3J0'
    'LGNsaWVudD1UcnVlLGlkZW50aXR5PWNhbmRpZGF0ZVsnaWRlbnRpdHknXSkKIGVsaWYgbm90IHR1bm5lbC5mdWxsX2d1YXJk'
    'X2FjdGl2ZSgpOgogIHJlcGx5PXR1bm5lbC50bHNfcmVxdWVzdCh0dW5uZWwuU0VSVkVSLCcvcmVwb3J0JyxyZXBvcnQsY2xp'
    'ZW50PVRydWUpCiBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcign0JfQsNGJ0LjRgtCwINCx0LvQvtC60LjRgNGD0LXRgiDRgdC1'
    '0YLRjC4g0J7RgtGH0ZHRgiDRgdC+0YXRgNCw0L3RkdC9OyDQvtGC0L/RgNCw0LLRjNGC0LUg0L/QvtGB0LvQtSDQstC+0YHR'
    'gdGC0LDQvdC+0LLQu9C10L3QuNGPINC40LvQuCDRj9Cy0L3QvtCz0L4g0L7RgtC60LvRjtGH0LXQvdC40Y8gVlBOLicpCiBp'
    'ZiByZXBseS5nZXQoJ2FjY2VwdGVkJykgaXMgbm90IFRydWUgb3IgcmVwbHkuZ2V0KCdyZXBvcnRfaWQnKSE9cmVwb3J0X2lk'
    'OnJhaXNlIFJ1bnRpbWVFcnJvcign0KHQtdGA0LLQtdGAINC90LUg0L/QvtC00YLQstC10YDQtNC40Lsg0L/QvtC70YPRh9C1'
    '0L3QuNC1INC+0YLRh9GR0YLQsC4nKQogcmV0dXJuIHJlcG9ydF9pZAo='
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
