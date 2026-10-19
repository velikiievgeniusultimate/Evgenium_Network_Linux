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

MANAGER_VERSION = "0.4.1"

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
    'ICBwcmVzZXJ2ZV9kaXNhYmxlZCA9ICcnIGlmIHByZXZpb3VzX2ZvcndhcmQgZWxzZSAnICBpaWZuYW1lICE9ICJ3YXlkcm9p'
    'ZDAiIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnCiAgICByZXR1cm4gZicnJ3RhYmxlIGluZXQge05GVH0ge3sKIGNoYWluIGZv'
    'cndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTIwOyBwb2xpY3kgYWNjZXB0OwogIGlpZm5h'
    'bWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFt'
    'ZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9T'
    'VH0iIGRyb3AKICBvaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJWRVJ9IH19IGN0IHN0YXRlIGVzdGFibGlzaGVk'
    'LHJlbGF0ZWQgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBkcm9wCntwcmVzZXJ2ZV9kaXNhYmxlZH0KIH19CiBjaGFpbiBu'
    'YXQge3sKICB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBz'
    'YWRkciB7Q0xJRU5UfSBvaWZuYW1lICJ7aWZhY2V9IiBtYXNxdWVyYWRlCiB9fQp9fScnJwoKCmRlZiBzZXR1cF9uZXR3b3Jr'
    'KCk6CiAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICMgUmVmdXNlIG5hbWUvYWRkcmVzcyBjb2xsaXNpb25zIHJh'
    'dGhlciB0aGFuIHJlcHVycG9zaW5nIGFub3RoZXIgYXBwbGljYXRpb24ncyByZXNvdXJjZXMuCiAgICBpZiBQYXRoKCcvcnVu'
    'L25ldG5zLycrTlMpLmV4aXN0cygpIG9yIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrSE9TVCkuZXhpc3RzKCkgb3IgKFBhdGgo'
    'Jy9ldGMvbmV0bnMnKS9OUykuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X25hbWVzcGFjZV9l'
    'eGlzdHMnKQogICAgaWYgY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUnLCBzdHIoVEFCTEUp'
    'XSwgY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF90YWJsZV9p'
    'bl91c2UnKQogICAgaWYgYW55KE5FVFdPUksgaW4gbGluZSBmb3IgbGluZSBpbiBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91'
    'dGUnLCAnc2hvdycsICd0YWJsZScsICdhbGwnXSkuc3Rkb3V0LnNwbGl0bGluZXMoKSk6CiAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCd0ZXN0X25ldHdvcmtfaW5fdXNlJykKICAgIG9sZF9mb3J3YXJkID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0'
    'L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICAjIFJlY29yZCBvd25lcnNoaXAgYmVmb3JlIGNyZWF0aW5n'
    'IGFueXRoaW5nOiBjbGVhbnVwIGlzIHZhbGlkIGFmdGVyIGV2ZXJ5IHBhcnRpYWwgc3RlcC4KICAgIHVwbGluayA9IFBhdGgo'
    'Jy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvcm91dGVbJ2RldiddLydmb3J3YXJkaW5nJwogICAgd3JpdGUoUk9PVC8nbmV0'
    'd29yay5qc29uJywganNvbi5kdW1wcyh7J2ZvcndhcmQnOiBvbGRfZm9yd2FyZCwgJ2ludGVyZmFjZSc6IHJvdXRlWydkZXYn'
    'XSwgJ3VwbGlua19mb3J3YXJkJzogdXBsaW5rLnJlYWRfdGV4dCgpLnN0cmlwKCl9KSkKICAgIGNvbW1hbmQoWydpcCcsICdu'
    'ZXRucycsICdhZGQnLCBOU10pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25mJywgJ25hbWVz'
    'ZXJ2ZXIgMS4xLjEuMVxubmFtZXNlcnZlciA5LjkuOS45XG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAg'
    'IyBuc3MtcmVzb2x2ZSB0YWxrcyB0byB0aGUgaG9zdCBkYWVtb24gb3ZlciBhIFVuaXggc29ja2V0IGV2ZW4gaW5zaWRlIG5l'
    'dG5zLgogICAgbnNzPVBhdGgoJy9ldGMvbnNzd2l0Y2guY29uZicpLnJlYWRfdGV4dCgpCiAgICBuc3M9cmUuc3ViKHInXmhv'
    'c3RzOi4qJCcsICdob3N0czogZmlsZXMgZG5zJywgbnNzLCBmbGFncz1yZS5NKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRu'
    'cycpL05TLyduc3N3aXRjaC5jb25mJywgbnNzKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnYWRkJywgSE9TVCwgJ3R5'
    'cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUnLCBQRUVSXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIFBF'
    'RVIsICduZXRucycsIE5TXSkKICAgIGNvbW1hbmQoWydpcCcsICdhZGRyJywgJ2FkZCcsIEdBVEVXQVkrJy8zMCcsICdkZXYn'
    'LCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIEhPU1QsICd1cCddKQogICAgaW5zaWRlKFsnaXAn'
    'LCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8zMCcsICdkZXYnLCBQRUVSXSkKICAgIGluc2lkZShbJ2lwJywgJ2xpbmsnLCAn'
    'c2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3NldCcsICdsbycsICd1cCddKQogICAgaW5z'
    'aWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ2RlZmF1bHQnLCAndmlhJywgR0FURVdBWV0pCiAgICBjb21tYW5kKFsnaXAn'
    'LCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywgc3RyKFRBQkxFKSwgJ2RlZmF1bHQnLCAndmlhJywgcm91dGVbJ2dhdGV3YXkn'
    'XSwgJ2RldicsIHJvdXRlWydkZXYnXV0pCiAgICBmb3IgYWRkcmVzcyBpbiBFTkRQT0lOVFM6CiAgICAgICAgY29tbWFuZChb'
    'J2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAg'
    'ICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldKQogICAgcnVsZXMgPSBo'
    'b3N0X3J1bGVzKHJvdXRlWydkZXYnXSwgcHJldmlvdXNfZm9yd2FyZD1vbGRfZm9yd2FyZCA9PSAnMScpCiAgICBjb21tYW5k'
    'KFsnbmZ0JywgJy1jJywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWYnLCAnLSddLCBk'
    'YXRhPXJ1bGVzKQogICAgIyBQZXItaW50ZXJmYWNlIGZvcndhcmRpbmcgYXZvaWRzIGlwX2ZvcndhcmQncyBnbG9iYWwgZGVm'
    'YXVsdHMgcmVzZXQuCiAgICAoUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9IT1NULydmb3J3YXJkaW5nJykud3Jp'
    'dGVfdGV4dCgnMVxuJykKICAgIHVwbGluay53cml0ZV90ZXh0KCcxXG4nKQoKCmRlZiBjbGVhbnVwKCk6CiAgICBjbGVhbnVw'
    'X2Z1bGwoKQogICAgIyBBbiB1bm93bmVkIG5hbWVzcGFjZS90YWJsZSBtdXN0IG5ldmVyIGJlIGRlbGV0ZWQgYnkgYSBnZW5l'
    'cmljIGNsZWFudXAgY2FsbC4KICAgIGlmIG5vdCAoUk9PVC8nbmV0d29yay5qc29uJykuZXhpc3RzKCk6CiAgICAgICAgcmV0'
    'dXJuCiAgICBkYXRhID0ganNvbi5sb2FkcygoUk9PVC8nbmV0d29yay5qc29uJykucmVhZF90ZXh0KCkpCiAgICBjb21tYW5k'
    'KFsnbmZ0JywgJ2RlbGV0ZScsICd0YWJsZScsICdpbmV0JywgTkZUXSwgY2hlY2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBp'
    'biAoKkVORFBPSU5UUywgKkxFR0FDWV9FTkRQT0lOVFMpOgogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2RlbCcs'
    'ICdwcmlvcml0eScsIHN0cihQUklPUklUWSksICdmcm9tJywgQ0xJRU5UKycvMzInLAogICAgICAgICAgICAgICAgICd0bycs'
    'IGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiBk'
    'YXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pOgogICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKGFkZHJlc3Mp'
    'LmlzX2dsb2JhbDoKICAgICAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5JywgJzExMScs'
    'ICdmcm9tJywgQ0xJRU5UKycvMzInLCAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNr'
    'PUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2ZsdXNoJywgJ3RhYmxlJywgc3RyKFRBQkxFKV0sIGNoZWNr'
    'PUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2RlbCcsIE5TXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5k'
    'KFsnaXAnLCAnbGluaycsICdkZWwnLCBIT1NUXSwgY2hlY2s9RmFsc2UpCiAgICBpZiAndXBsaW5rX2ZvcndhcmQnIGluIGRh'
    'dGE6CiAgICAgICAgcGF0aCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvZGF0YVsnaW50ZXJmYWNlJ10vJ2Zv'
    'cndhcmRpbmcnCiAgICAgICAgaWYgcGF0aC5leGlzdHMoKToKICAgICAgICAgICAgcGF0aC53cml0ZV90ZXh0KGRhdGFbJ3Vw'
    'bGlua19mb3J3YXJkJ10rJ1xuJykKICAgIGVsaWYgZGF0YS5nZXQoJ2ZvcndhcmQnKSA9PSAnMCcgYW5kIFBhdGgoJy9wcm9j'
    'L3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykucmVhZF90ZXh0KCkuc3RyaXAoKSA9PSAnMSc6CiAgICAgICAgUGF0aCgnL3By'
    'b2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS53cml0ZV90ZXh0KCcwXG4nKQogICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9O'
    'Uy8ncmVzb2x2LmNvbmYnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8nbnNz'
    'd2l0Y2guY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoT1NFcnJv'
    'cik6CiAgICAgICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykucm1kaXIoKQogICAgKFJPT1QvJ25ldHdvcmsuanNvbicpLnVu'
    'bGluayhtaXNzaW5nX29rPVRydWUpCgoKQGNvbnRleHRsaWIuY29udGV4dG1hbmFnZXIKZGVmIG1lYXN1cmVtZW50X3JvdXRl'
    'KGFkZHJlc3MpOgogICAgIiIiQSBzaG9ydC1saXZlZCBkaXJlY3Qgcm91dGUgZm9yIGEgdmVyaWZpZWQgWWFuZGV4IEhUVFBT'
    'IG1lYXN1cmVtZW50LCBsYWIgb25seS4iIiIKICAgIGlmIG5vdCBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhZGRyZXNzKS5pc19n'
    'bG9iYWwgb3IgYWRkcmVzcyBpbiBFTkRQT0lOVFM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9tZWFzdXJl'
    'bWVudF9hZGRyZXNzJykKICAgIGxhYmVsID0gJ2V2bi1tZWFzdXJlLScrc2VjcmV0cy50b2tlbl9oZXgoOCkKICAgIGRhdGEg'
    'PSBqc29uLmxvYWRzKChST09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGRhdGFbJ21lYXN1cmVtZW50X2lw'
    'cyddID0gc29ydGVkKHNldChkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pK1thZGRyZXNzXSkpCiAgICB3cml0ZShS'
    'T09ULyduZXR3b3JrLmpzb24nLCBqc29uLmR1bXBzKGRhdGEpKQogICAgdHJ5OgogICAgICAgIGNvbW1hbmQoWydpcCcsICdy'
    'dWxlJywgJ2FkZCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAn'
    'dG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICAgICAgY29tbWFuZChbJ25mdCcsICdpbnNl'
    'cnQnLCAncnVsZScsICdpbmV0JywgTkZULCAnZm9yd2FyZCcsICdpaWZuYW1lJywgSE9TVCwKICAgICAgICAgICAgICAgICAn'
    'aXAnLCAnZGFkZHInLCBhZGRyZXNzLCAndGNwJywgJ2Rwb3J0JywgJzQ0MycsICdhY2NlcHQnLCAnY29tbWVudCcsIGxhYmVs'
    'XSkKICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2luc2VydCcsICdydWxlJywgJ2luZXQnLCBORlQsICdmb3J3YXJkJywgJ29p'
    'Zm5hbWUnLCBIT1NULAogICAgICAgICAgICAgICAgICdpcCcsICdzYWRkcicsIGFkZHJlc3MsICdjdCcsICdzdGF0ZScsICdl'
    'c3RhYmxpc2hlZCxyZWxhdGVkJywgJ2FjY2VwdCcsICdjb21tZW50JywgbGFiZWxdKQogICAgICAgIHlpZWxkCiAgICBmaW5h'
    'bGx5OgogICAgICAgIHJlc3VsdCA9IGNvbW1hbmQoWyduZnQnLCAnLWonLCAnLWEnLCAnbGlzdCcsICdjaGFpbicsICdpbmV0'
    'JywgTkZULCAnZm9yd2FyZCddLCBjaGVjaz1GYWxzZSkKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSA9PSAwOgogICAg'
    'ICAgICAgICBmb3IgZW50cnkgaW4ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0KS5nZXQoJ25mdGFibGVzJywgW10pOgogICAg'
    'ICAgICAgICAgICAgcnVsZSA9IGVudHJ5LmdldCgncnVsZScsIHt9KQogICAgICAgICAgICAgICAgaWYgcnVsZS5nZXQoJ2Nv'
    'bW1lbnQnKSA9PSBsYWJlbDoKICAgICAgICAgICAgICAgICAgICBjb21tYW5kKFsnbmZ0JywgJ2RlbGV0ZScsICdydWxlJywg'
    'J2luZXQnLCBORlQsICdmb3J3YXJkJywgJ2hhbmRsZScsIHN0cihydWxlWydoYW5kbGUnXSldLCBjaGVjaz1GYWxzZSkKICAg'
    'ICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8z'
    'MicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1G'
    'YWxzZSkKCgpkZWYgcHJvdmlkZXJfYWRkcmVzc2VzKGhvc3QpOgogICAgIyBETlMgbWF5IHVzZSB0aGUgd29ya2luZyByZXNv'
    'bHZlciwgYnV0IG1lYXN1cmVkIEhUVFBTIGl0c2VsZiB0YWtlcyB0aGUgcGh5c2ljYWwgcm91dGUuCiAgICBhZGRyZXNzZXMg'
    'PSBbYW5zd2VyWzRdWzBdIGZvciBhbnN3ZXIgaW4gc29ja2V0LmdldGFkZHJpbmZvKGhvc3QsIDQ0Mywgc29ja2V0LkFGX0lO'
    'RVQsIHNvY2tldC5TT0NLX1NUUkVBTSldCiAgICByZXR1cm4gbGlzdChkaWN0LmZyb21rZXlzKHggZm9yIHggaW4gYWRkcmVz'
    'c2VzIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHgpLmlzX2dsb2JhbCkpWzoyXQoKCmRlZiBwcm92aWRlcl9nZXQoaG9zdCwg'
    'cGF0aCwgbWF4aW11bSwgbWVhc3VyZT1GYWxzZSk6CiAgICBsYXN0ID0gTm9uZQogICAgZm9yIGFkZHJlc3MgaW4gcHJvdmlk'
    'ZXJfYWRkcmVzc2VzKGhvc3QpOgogICAgICAgIG91dHB1dCA9IFJPT1QvKCdyZWZlcmVuY2UtJytzZWNyZXRzLnRva2VuX2hl'
    'eCg4KSsnLnRtcCcpCiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG1lYXN1cmVtZW50X3JvdXRlKGFkZHJlc3MpOgog'
    'ICAgICAgICAgICAgICAgYXJncyA9IFsnY3VybCcsICctNCcsICctLXNpbGVudCcsICctLXNob3ctZXJyb3InLCAnLS1mYWls'
    'JywgJy0tbm9wcm94eScsICcqJywKICAgICAgICAgICAgICAgICAgICAgICAgJy0tcHJvdG8nLCAnPWh0dHBzJywgJy0tY29u'
    'bmVjdC10aW1lb3V0JywgJzQnLCAnLS1tYXgtdGltZScsICcxMCcsCiAgICAgICAgICAgICAgICAgICAgICAgICctLXJlc29s'
    'dmUnLCBob3N0Kyc6NDQzOicrYWRkcmVzcywgJy0tbWF4LWZpbGVzaXplJywgc3RyKG1heGltdW0pLAogICAgICAgICAgICAg'
    'ICAgICAgICAgICAnLS1vdXRwdXQnLCBzdHIob3V0cHV0KSwgJy0td3JpdGUtb3V0JywgJyV7anNvbn0nXQogICAgICAgICAg'
    'ICAgICAgaWYgbWVhc3VyZToKICAgICAgICAgICAgICAgICAgICBhcmdzICs9IFsnLS1yYW5nZScsICcwLScrc3RyKG1heGlt'
    'dW0tMSldCiAgICAgICAgICAgICAgICBhcmdzICs9IFsnaHR0cHM6Ly8nK2hvc3QrcGF0aF0KICAgICAgICAgICAgICAgIHJl'
    'c3VsdCA9IGluc2lkZShhcmdzLCB0aW1lb3V0PTEyLCBjaGVjaz1GYWxzZSkKICAgICAgICAgICAgICAgIGlmIHJlc3VsdC5y'
    'ZXR1cm5jb2RlOgogICAgICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignbWVhc3VyZW1lbnRfY3VybF8nK3N0'
    'cihyZXN1bHQucmV0dXJuY29kZSkpCiAgICAgICAgICAgICAgICBzdGF0aXN0aWNzID0ganNvbi5sb2FkcyhyZXN1bHQuc3Rk'
    'b3V0KQogICAgICAgICAgICAgICAgaWYgbWVhc3VyZToKICAgICAgICAgICAgICAgICAgICByZWNlaXZlZCA9IGludChzdGF0'
    'aXN0aWNzWydzaXplX2Rvd25sb2FkJ10pCiAgICAgICAgICAgICAgICAgICAgZWxhcHNlZCA9IGZsb2F0KHN0YXRpc3RpY3Nb'
    'J3RpbWVfdG90YWwnXSktZmxvYXQoc3RhdGlzdGljc1sndGltZV9zdGFydHRyYW5zZmVyJ10pCiAgICAgICAgICAgICAgICAg'
    'ICAgaWYgcmVjZWl2ZWQgPCAxMDI0KjEwMjQgb3IgcmVjZWl2ZWQgPiBtYXhpbXVtIG9yIGVsYXBzZWQgPD0gMDoKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdtZWFzdXJlbWVudF90b29fc2hvcnQnKQogICAgICAgICAg'
    'ICAgICAgICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICdlc3RpbWF0ZWRfbWJwcyc6IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8x'
    'ZTYsIDIpfQogICAgICAgICAgICAgICAgcmV0dXJuIG91dHB1dC5yZWFkX2J5dGVzKCkKICAgICAgICBleGNlcHQgKE9TRXJy'
    'b3IsIFJ1bnRpbWVFcnJvciwgVmFsdWVFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAg'
    'ICAgICBsYXN0ID0gZXhjCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgb3V0cHV0LnVubGluayhtaXNzaW5nX29rPVRy'
    'dWUpCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlZmVyZW5jZV91bmF2YWlsYWJsZScpIGZyb20gbGFzdAoKCmRlZiB2YWxp'
    'ZGF0ZV95YW5kZXhfcHJvYmUodXJsKToKICAgIGZyb20gdXJsbGliLnBhcnNlIGltcG9ydCB1cmxzcGxpdAogICAgcGFyc2Vk'
    'ID0gdXJsc3BsaXQodXJsKQogICAgaWYgKGxlbih1cmwpID4gMjA0OCBvciBwYXJzZWQuc2NoZW1lICE9ICdodHRwcycgb3Ig'
    'bm90IHBhcnNlZC5ob3N0bmFtZSBvcgogICAgICAgIG5vdCBwYXJzZWQuaG9zdG5hbWUuZW5kc3dpdGgoJy5jZG4ueWFuZGV4'
    'Lm5ldCcpIG9yIHBhcnNlZC51c2VybmFtZSBvciBwYXJzZWQucGFzc3dvcmQgb3IKICAgICAgICBwYXJzZWQucG9ydCBub3Qg'
    'aW4gKE5vbmUsIDQ0Mykgb3IgcGFyc2VkLmZyYWdtZW50KToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCd1bnRydXN0ZWRf'
    'cmVmZXJlbmNlX3VybCcpCiAgICByZXR1cm4gcGFyc2VkLmhvc3RuYW1lLCBwYXJzZWQucGF0aCsoJz8nICsgcGFyc2VkLnF1'
    'ZXJ5IGlmIHBhcnNlZC5xdWVyeSBlbHNlICcnKQoKCmRlZiByZWZlcmVuY2Vfc2FtcGxlKGZvcmNlPUZhbHNlKToKICAgIHJv'
    'dXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgZmluZ2VycHJpbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6'
    'IHJvdXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1'
    'ZSkuZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICB0cnk6CiAgICAgICAgY2FjaGVkID0ganNvbi5sb2FkcygoUk9PVC8ncmVm'
    'ZXJlbmNlLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICBpZiBub3QgZm9yY2UgYW5kIGNhY2hlZC5nZXQoJ25ldHdvcmsn'
    'KSA9PSBmaW5nZXJwcmludCBhbmQgY2FjaGVkLmdldCgncHJvdmlkZXInKSA9PSAnWWFuZGV4IEludGVybmV0b21ldGVyJzoK'
    'ICAgICAgICAgICAgcmV0dXJuIGNhY2hlZAogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICBwYXNz'
    'CiAgICBzdGFnZSgncmVmZXJlbmNlJywgJ9CX0LDQv9GD0YHQutCw0Y4g0LfQsNC80LXRgCDQv9GA0Y/QvNC+0LPQviDRgdC+'
    '0LXQtNC40L3QtdC90LjRjzog0K/QvdC00LXQutGBINCY0L3RgtC10YDQvdC10YLQvtC80LXRgtGALicsIDEyKQogICAgY29u'
    'ZmlnID0ganNvbi5sb2Fkcyhwcm92aWRlcl9nZXQoJ3lhbmRleC5ydScsICcvaW50ZXJuZXQvYXBpL3YwL2dldC1wcm9iZXM/'
    'ZnJvbT1pbnRlcm5ldCZub2NhY2hlPScrc3RyKGludCh0aW1lLnRpbWUoKSoxMDAwKSksIDY1NTM2KSkKICAgIHByb2JlcyA9'
    'IGNvbmZpZy5nZXQoJ2Rvd25sb2FkJywge30pLmdldCgncHJvYmVzJywgW10pCiAgICBjYW5kaWRhdGVzID0gW10KICAgIGZv'
    'ciBwcm9iZSBpbiBwcm9iZXM6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBob3N0LCBwYXRoID0gdmFsaWRhdGVfeWFuZGV4'
    'X3Byb2JlKHByb2JlLmdldCgndXJsJywgJycpKQogICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgVHlwZUVycm9yKToKICAg'
    'ICAgICAgICAgY29udGludWUKICAgICAgICBpZiAnNTBtYicgaW4gcGF0aCBvciAnMTAwbWInIGluIHBhdGg6CiAgICAgICAg'
    'ICAgIGNhbmRpZGF0ZXMuYXBwZW5kKChob3N0LCBwYXRoKSkKICAgIGlmIG5vdCBjYW5kaWRhdGVzOgogICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcigncmVmZXJlbmNlX3NjaGVtYV9jaGFuZ2VkJykKICAgIGhvc3QsIHBhdGggPSBjYW5kaWRhdGVzWzBd'
    'CiAgICAjIFNob3J0IHNhbXBsZXMgYXZvaWQgYSBtaW51dGUtbG9uZyBzYXR1cmF0aW9uIHdoaWxlIHRoZSB1c2VyIHdhdGNo'
    'ZXMgdmlkZW8uCiAgICBzYW1wbGVzID0gW3Byb3ZpZGVyX2dldChob3N0LCBwYXRoLCA4KjEwMjQqMTAyNCwgbWVhc3VyZT1U'
    'cnVlKSBmb3IgXyBpbiByYW5nZSgyKV0KICAgIHJlc3VsdCA9IHsncHJvdmlkZXInOiAnWWFuZGV4IEludGVybmV0b21ldGVy'
    'JywgJ25ldHdvcmsnOiBmaW5nZXJwcmludCwgJ3RpbWUnOiBpbnQodGltZS50aW1lKCkpLAogICAgICAgICAgICAgICdlc3Rp'
    'bWF0ZWRfbWJwcyc6IG1heCh4Wydlc3RpbWF0ZWRfbWJwcyddIGZvciB4IGluIHNhbXBsZXMpLCAnc2FtcGxlcyc6IHNhbXBs'
    'ZXMsCiAgICAgICAgICAgICAgJ3Nob3J0X3NhbXBsZSc6IFRydWUsICdkaXJlY3RfcGh5c2ljYWxfcm91dGUnOiBUcnVlfQog'
    'ICAgd3JpdGUoUk9PVC8ncmVmZXJlbmNlLmpzb24nLCBqc29uLmR1bXBzKHJlc3VsdCkpCiAgICByZXR1cm4gcmVzdWx0CgoK'
    'CmRlZiB0bHNfcmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNsaWVudD1GYWxzZSwgdGltZW91dD04KToKICAg'
    'IGNvbnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgaWYgY2xpZW50Ogog'
    'ICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQt'
    'a2V5LnBlbScpKQogICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9'
    'dGltZW91dCkKICAgIHRyeToKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFt'
    'ZT1TRVJWRVIpCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBzb2NrLmNsb3NlKCkKICAgICAgICByYWlzZQog'
    'ICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKGFkZHJlc3MsIDg0NDMsIHRpbWVvdXQ9dGltZW91'
    'dCkKICAgIGNvbm5lY3Rpb24uc29jayA9IHRscwogICAgZW5jb2RlZCA9IGpzb24uZHVtcHMoYm9keSwgc2VwYXJhdG9ycz0o'
    'JywnLCAnOicpKS5lbmNvZGUoKSBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgTm9uZQogICAgdHJ5OgogICAgICAgIGNvbm5l'
    'Y3Rpb24ucmVxdWVzdCgnUE9TVCcgaWYgYm9keSBpcyBub3QgTm9uZSBlbHNlICdHRVQnLCBwYXRoLCBib2R5PWVuY29kZWQs'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlYWRlcnM9eydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbics'
    'ICdDb25uZWN0aW9uJzogJ2Nsb3NlJ30pCiAgICAgICAgcmVzcG9uc2UgPSBjb25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAg'
    'ICAgICByYXcgPSByZXNwb25zZS5yZWFkKDIwMDAxKQogICAgICAgIGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDAgb3IgbGVu'
    'KHJhdykgPiAyMDAwMDoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdyZXF1ZXN0X3JlamVjdGVkJykKICAgICAg'
    'ICByZXR1cm4ganNvbi5sb2FkcyhyYXcpCiAgICBmaW5hbGx5OgogICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQoKCmRlZiBl'
    'bnJvbGwoKToKICAgIHRva2VuID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1'
    'bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX3Rva2Vu'
    'JykKICAgIHRyeToKICAgICAgICBjYWNoZWQgPSBqc29uLmxvYWRzKChST09ULydwcm9maWxlLmpzb24nKS5yZWFkX3RleHQo'
    'KSkKICAgICAgICBpZiAoY2FjaGVkLmdldCgnY2EnKSA9PSBQSU5ORURfQ0EgYW5kIGNhY2hlZC5nZXQoJ3NlcnZlcicpID09'
    'IFNFUlZFUiBhbmQKICAgICAgICAgICAgcmUuZnVsbG1hdGNoKHInZGV2aWNlLVthLWYwLTldezI0fScsIGNhY2hlZC5nZXQo'
    'J2lkZW50aXR5JywgJycpKSBhbmQKICAgICAgICAgICAgY2FjaGVkLmdldCgnZW5kcG9pbnQnKSBpbiBFTkRQT0lOVFMgYW5k'
    'IGNhY2hlZC5nZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSBhbmQKICAgICAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAneDUw'
    'OScsICctaW4nLCBST09ULydjbGllbnQucGVtJywgJy1jaGVja2VuZCcsIHN0cig3Kjg2NDAwKSwgJy1ub291dCddLCBjaGVj'
    'az1GYWxzZSkucmV0dXJuY29kZSA9PSAwKToKICAgICAgICAgICAgY29udGV4dCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9U'
    'T0NPTF9UTFNfQ0xJRU5UKQogICAgICAgICAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBl'
    'bScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAgICAgICAgICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAg'
    'ICAgICAgICAgIGN1cnJlbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBzKHtrZXk6IHJvdXRlLmdldChrZXkpIGZvciBr'
    'ZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tleXM9VHJ1ZSkuZW5jb2RlKCkpLmhleGRpZ2Vz'
    'dCgpCiAgICAgICAgICAgIGFkZHJlc3MgPSBjYWNoZWRbJ2VuZHBvaW50J10gaWYgY2FjaGVkLmdldCgncGh5c2ljYWxfbmV0'
    'd29yaycpID09IGN1cnJlbnQgZWxzZSBTRVJWRVIKICAgICAgICAgICAgcmV0dXJuIGNhY2hlZFsnaWRlbnRpdHknXSwgYWRk'
    'cmVzcwogICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yLCBzc2wuU1NMRXJyb3IpOgogICAgICAgIHBhc3MKICAgIHN0'
    'YWdlKCd0b2tlbicsICfQn9C+0LvRg9GH0LDRjiDRgdC10YDRgtC40YTQuNC60LDRgiDQtNC70Y8g0Y3RgtC+0LPQviDRg9GB'
    '0YLRgNC+0LnRgdGC0LLQsC4nLCAyNSkKICAgIGlmIG5vdCAoUk9PVC8nY2xpZW50LWtleS5wZW0nKS5leGlzdHMoKToKICAg'
    'ICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICdnZW5wa2V5JywgJy1hbGdvcml0aG0nLCAnUlNBJywgJy1wa2V5b3B0JywgJ3Jz'
    'YV9rZXlnZW5fYml0czozMDcyJywKICAgICAgICAgICAgICAgICAnLW91dCcsIFJPT1QvJ2NsaWVudC1rZXkucGVtJ10sIHRp'
    'bWVvdXQ9MzApCiAgICAgICAgKFJPT1QvJ2NsaWVudC1rZXkucGVtJykuY2htb2QoMG82MDApCiAgICBpZiBub3QgKFJPT1Qv'
    'J2RldmljZScpLmV4aXN0cygpOgogICAgICAgIHdyaXRlKFJPT1QvJ2RldmljZScsIHNlY3JldHMudG9rZW5faGV4KDE2KSkK'
    'ICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3JlcScsICctbmV3JywgJy1rZXknLCBST09ULydjbGllbnQta2V5LnBlbScsICct'
    'c3ViaicsICcvQ049ZXZnZW5pdW0tZGV2aWNlJywKICAgICAgICAgICAgICctb3V0JywgUk9PVC8ncmVxdWVzdC5wZW0nXSkK'
    'ICAgIHBheWxvYWQgPSB7J3Rva2VuJzogdG9rZW4sICdkZXZpY2UnOiAoUk9PVC8nZGV2aWNlJykucmVhZF90ZXh0KCkuc3Ry'
    'aXAoKSwgJ2Nzcic6IChST09ULydyZXF1ZXN0LnBlbScpLnJlYWRfdGV4dCgpfQogICAgbGFzdCA9IE5vbmUKICAgIGZvciBh'
    'ZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAg'
    'ICAgICAgICByZXBseSA9IHRsc19yZXF1ZXN0KGFkZHJlc3MsICcvZW5yb2xsJywgcGF5bG9hZCwgdGltZW91dD02KQogICAg'
    'ICAgICAgICBwcm9maWxlID0gcmVwbHkuZ2V0KCdwcm9maWxlJywge30pCiAgICAgICAgICAgIGlmIHJlcGx5LmdldCgnb2sn'
    'KSBpcyBub3QgVHJ1ZSBvciBwcm9maWxlLmdldCgnY2EnKSAhPSBQSU5ORURfQ0Egb3IgcHJvZmlsZS5nZXQoJ3NlcnZlcicp'
    'ICE9IFNFUlZFUjoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9wcm9maWxlJykKICAgICAg'
    'ICAgICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyJ2RldmljZS1bYS1mMC05XXsyNH0nLCBwcm9maWxlLmdldCgnaWRlbnRpdHkn'
    'LCAnJykpOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX2lkZW50aXR5JykKICAgICAgICAg'
    'ICAgd3JpdGUoUk9PVC8nY2xpZW50LnBlbScsIHByb2ZpbGVbJ2NlcnRpZmljYXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJP'
    'T1QvJ2NhLnBlbScsIFBJTk5FRF9DQSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8neDUwOScvJ2NsaWVudC5wZW0nLCBwcm9m'
    'aWxlWydjZXJ0aWZpY2F0ZSddKQogICAgICAgICAgICB3cml0ZShST09ULyd4NTA5Y2EnLydjYS5wZW0nLCBQSU5ORURfQ0Ep'
    'CiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3ByaXZhdGUnLydjbGllbnQta2V5LnBlbScsIChST09ULydjbGllbnQta2V5LnBl'
    'bScpLnJlYWRfdGV4dCgpKQogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd2ZXJpZnknLCAnLXB1cnBvc2UnLCAn'
    'c3NsY2xpZW50JywgJy1DQWZpbGUnLCBST09ULydjYS5wZW0nLCBST09ULydjbGllbnQucGVtJ10pCiAgICAgICAgICAgIGN0'
    'eCA9IHNzbC5TU0xDb250ZXh0KHNzbC5QUk9UT0NPTF9UTFNfQ0xJRU5UKQogICAgICAgICAgICBjdHgubG9hZF9jZXJ0X2No'
    'YWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0'
    'ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICAgICAgICAgZmluZ2VycHJpbnQgPSBoYXNobGliLnNoYTI1Nihqc29uLmR1bXBz'
    'KHtrZXk6IHJvdXRlLmdldChrZXkpIGZvciBrZXkgaW4gKCdkZXYnLCAnZ2F0ZXdheScsICdwcmVmc3JjJyl9LCBzb3J0X2tl'
    'eXM9VHJ1ZSkuZW5jb2RlKCkpLmhleGRpZ2VzdCgpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3Byb2ZpbGUuanNvbicsIGpz'
    'b24uZHVtcHMoeyoqcHJvZmlsZSwgJ2VuZHBvaW50JzogYWRkcmVzcywgJ3BoeXNpY2FsX25ldHdvcmsnOiBmaW5nZXJwcmlu'
    'dH0pKQogICAgICAgICAgICByZXR1cm4gcHJvZmlsZVsnaWRlbnRpdHknXSwgYWRkcmVzcwogICAgICAgIGV4Y2VwdCAoT1NF'
    'cnJvciwgc3NsLlNTTEVycm9yLCBSdW50aW1lRXJyb3IpIGFzIGV4YzoKICAgICAgICAgICAgbGFzdCA9IGV4YwogICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCdlbnJvbGxtZW50X3VuYXZhaWxhYmxlJykgZnJvbSBsYXN0CgoKZGVmIGRhZW1vbl9jb25maWdz'
    'KGlkZW50aXR5LCBhZGRyZXNzKToKICAgIFJVTlRJTUUubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlzdF9v'
    'az1UcnVlKQogICAgaW5jbHVkZXMgPSAnXG4nLmpvaW4oJ2luY2x1ZGUgJytzdHIocCkgZm9yIHBhdHRlcm4gaW4gKCcvZXRj'
    'L3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25mJywgJy9ldGMvc3Ryb25nc3dhbi9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29u'
    'ZicpCiAgICAgICAgICAgICAgICAgICAgICAgICBmb3IgcCBpbiBQYXRoKCcvJykuZ2xvYihwYXR0ZXJuLmxzdHJpcCgnLycp'
    'KSkKICAgIHdyaXRlKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicsIGYnJydjaGFyb24ge3sKIGxvYWRfbW9kdWxhciA9IHllcwog'
    'aW5zdGFsbF9yb3V0ZXMgPSB5ZXMKIHJvdXRpbmdfdGFibGUgPSA1MTgyMgogcm91dGluZ190YWJsZV9wcmlvID0gMTAwCiBw'
    'bHVnaW5zIHt7CntpbmNsdWRlc30KICB2aWNpIHt7IHNvY2tldCA9IHVuaXg6Ly97UlVOVElNRX0vY2hhcm9uLnZpY2kgfX0K'
    'ICByZXNvbHZlIHt7IGxvYWQgPSBubyB9fQogIGtlcm5lbC1saWJpcHNlYyB7eyBsb2FkID0gbm8gfX0KIH19Cn19CmNoYXJv'
    'bi1zeXN0ZW1kIHt7IGpvdXJuYWwge3sgZGVmYXVsdCA9IDA7IGlrZSA9IDEgfX0gfX0KJycnKQogICAgIyBBYnNvbHV0ZSBj'
    'cmVkZW50aWFscyBhcmUgbG9jYWwgdG8gdGhpcyBkZXZpY2UsIG5vdCBzaGFyZWQgYnkgdGhlIGFjY291bnQgdG9rZW4uCiAg'
    'ICB3cml0ZShST09ULydjb25uZWN0aW9uLmNvbmYnLCBmJycnY29ubmVjdGlvbnMge3sKIHN0YXJmaXZlIHt7CiAgdmVyc2lv'
    'biA9IDIKICByZW1vdGVfYWRkcnMgPSB7YWRkcmVzc30KICByZW1vdGVfcG9ydCA9IHtJS0VfUE9SVH0KICBsb2NhbF9wb3J0'
    'ID0gNDUwMAogIHZpcHMgPSAwLjAuMC4wCiAgcHJvcG9zYWxzID0gYWVzMjU2Z2NtMTYtcHJmc2hhMzg0LWVjcDM4NAogIGVu'
    'Y2FwID0geWVzCiAgZnJhZ21lbnRhdGlvbiA9IHllcwogIG1vYmlrZSA9IHllcwogIGRwZF9kZWxheSA9IDE1cwogIGxvY2Fs'
    'IHt7IGF1dGggPSBlYXAtdGxzOyBpZCA9IHtpZGVudGl0eX07IGVhcF9pZCA9IHtpZGVudGl0eX07IGNlcnRzID0ge1JPT1R9'
    'L2NsaWVudC5wZW0gfX0KICByZW1vdGUge3sgYXV0aCA9IHB1YmtleTsgaWQgPSB7U0VSVkVSfTsgY2FjZXJ0cyA9IHtST09U'
    'fS9jYS5wZW0gfX0KICBjaGlsZHJlbiB7ewogICBzdGFyZml2ZS1uZXQge3sKICAgIGxvY2FsX3RzID0gZHluYW1pYwogICAg'
    'cmVtb3RlX3RzID0gMC4wLjAuMC8wCiAgICByZXFpZCA9IHtSRVFJRH0KICAgIGVzcF9wcm9wb3NhbHMgPSBjaGFjaGEyMHBv'
    'bHkxMzA1CiAgICBkcGRfYWN0aW9uID0gY2xlYXIKICAgIHN0YXJ0X2FjdGlvbiA9IG5vbmUKICAgfX0KICB9fQogfX0KfX0K'
    'c2VjcmV0cyB7eyBwcml2YXRlLWNsaWVudCB7eyBmaWxlID0ge1JPT1R9L2NsaWVudC1rZXkucGVtIH19IH19CicnJykKICAg'
    'ICMgU3Ryb25nU3dhbiBjb25maWcgdXNlcyBuZXdsaW5lcywgbm90IHNlbWljb2xvbiBzZXBhcmF0b3JzIChub3JtYWxpemUg'
    'Y29tcGFjdCBibG9ja3MpLgogICAgZm9yIG5hbWUgaW4gKCdzdHJvbmdzd2FuLmNvbmYnLCAnY29ubmVjdGlvbi5jb25mJyk6'
    'CiAgICAgICAgcGF0aCA9IFJPT1QvbmFtZQogICAgICAgIHBhdGgud3JpdGVfdGV4dChwYXRoLnJlYWRfdGV4dCgpLnJlcGxh'
    'Y2UoJzsgJywgJ1xuJykucmVwbGFjZSgneyAnLCAne1xuJykucmVwbGFjZSgnIH0nLCAnXG59JykpCiAgICBydWxlcyA9IGYn'
    'Jyd0YWJsZSBpbmV0IGV2bl9zdGFyZml2ZV9ndWFyZCB7ewogY2hhaW4gb3V0cHV0IHt7CiAgdHlwZSBmaWx0ZXIgaG9vayBv'
    'dXRwdXQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJl'
    'c3N9IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAogIG1ldGEgc2t1aWQgMCBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRw'
    'b3J0IDg0NDMgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlkIHtSRVFJRH0gYWNjZXB0CiB9fQog'
    'Y2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsgfX0K'
    'fX0nJycKICAgIGluc2lkZShbJ25mdCcsICctYycsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICBpbnNpZGUoWyduZnQn'
    'LCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQoKCmRlZiBzd2FuKCphcmdzLCB0aW1lb3V0PTE1LCBjaGVjaz1UcnVlKToKICAg'
    'IHJldHVybiBpbnNpZGUoWydzd2FuY3RsJywgKmFyZ3MsICctLXVyaScsICd1bml4Oi8vJytzdHIoUlVOVElNRS8nY2hhcm9u'
    'LnZpY2knKV0sIHRpbWVvdXQ9dGltZW91dCwgY2hlY2s9Y2hlY2spCgoKZGVmIGluc3RhbGxlZCgpOgogICAgdHJ5OgogICAg'
    'ICAgIHJlc3VsdCA9IHN3YW4oJy0tbGlzdC1zYXMnLCAnLS1yYXcnLCB0aW1lb3V0PTMsIGNoZWNrPUZhbHNlKQogICAgICAg'
    'IHJldHVybiByZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCAnc3RhdGU9RVNUQUJMSVNIRUQnIGluIHJlc3VsdC5zdGRvdXQg'
    'YW5kICdzdGF0ZT1JTlNUQUxMRUQnIGluIHJlc3VsdC5zdGRvdXQKICAgIGV4Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5U'
    'aW1lb3V0RXhwaXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhlYWx0aCgpOgogICAgd2l0aCBuYW1lc3BhY2Uo'
    'KToKICAgICAgICByZXR1cm4gdGxzX3JlcXVlc3QoSEVBTFRILCAnL2hlYWx0aCcsIGNsaWVudD1UcnVlKS5nZXQoJ3NlcnZp'
    'Y2UnKSA9PSAnZXZnZW5pdW0tc3RhcmZpdmUnCgoKZGVmIGRvd25sb2FkKHNpemU9MTA0ODU3Nik6CiAgICAjIEEgYm91bmRl'
    'ZCBpbnRlZ3JpdHkgY2hlY2ssIG5vdCBhIGNsYWltIHRvIGhhdmUgbWVhc3VyZWQgdGhlIElTUCdzIG1heGltdW0gcmF0ZS4K'
    'ICAgIGJsb2NrID0gaGFzaGxpYi5zaGFrZV8yNTYoYidldmdlbml1bS1zdGFyZml2ZS1pbnRlZ3JpdHktdjEnKS5kaWdlc3Qo'
    'NjU1MzYpCiAgICBleHBlY3RlZCA9IGhhc2hsaWIuc2hhMjU2KChibG9jayooc2l6ZS8vbGVuKGJsb2NrKSsxKSlbOnNpemVd'
    'KS5oZXhkaWdlc3QoKQogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZGF0YT1QSU5ORURfQ0Ep'
    'CiAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtl'
    'eS5wZW0nKSkKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigo'
    'SEVBTFRILCA4NDQzKSwgdGltZW91dD0xMCkKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZl'
    'cl9ob3N0bmFtZT1TRVJWRVIpCiAgICAgICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKEhFQUxU'
    'SCwgODQ0MywgdGltZW91dD0xMCk7IGNvbm5lY3Rpb24uc29jayA9IHRscwogICAgICAgIHRyeToKICAgICAgICAgICAgc3Rh'
    'cnQgPSB0aW1lLm1vbm90b25pYygpCiAgICAgICAgICAgIGNvbm5lY3Rpb24ucmVxdWVzdCgnR0VUJywgJy9ibG9iP3NpemU9'
    'JytzdHIoc2l6ZSkpCiAgICAgICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlvbi5nZXRyZXNwb25zZSgpCiAgICAgICAgICAg'
    'IGlmIHJlc3BvbnNlLnN0YXR1cyAhPSAyMDA6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3RyYW5zZmVy'
    'X2h0dHAnKQogICAgICAgICAgICBkaWdlc3QgPSBoYXNobGliLnNoYTI1NigpOyByZWNlaXZlZCA9IDAKICAgICAgICAgICAg'
    'd2hpbGUgcmVjZWl2ZWQgPCBzaXplOgogICAgICAgICAgICAgICAgZGF0YSA9IHJlc3BvbnNlLnJlYWQobWluKDY1NTM2LCBz'
    'aXplLXJlY2VpdmVkKSkKICAgICAgICAgICAgICAgIGlmIG5vdCBkYXRhOgogICAgICAgICAgICAgICAgICAgIGJyZWFrCiAg'
    'ICAgICAgICAgICAgICBkaWdlc3QudXBkYXRlKGRhdGEpOyByZWNlaXZlZCArPSBsZW4oZGF0YSkKICAgICAgICAgICAgZWxh'
    'cHNlZCA9IHRpbWUubW9ub3RvbmljKCktc3RhcnQKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBjb25uZWN0aW9uLmNs'
    'b3NlKCkKICAgIGlmIHJlY2VpdmVkICE9IHNpemUgb3IgZGlnZXN0LmhleGRpZ2VzdCgpICE9IGV4cGVjdGVkOgogICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcignaW50ZWdyaXR5X2ZhaWxlZCcpCiAgICByZXR1cm4geydieXRlcyc6IHJlY2VpdmVkLCAn'
    'ZG93bmxvYWRfbWJwcyc6IHJvdW5kKHJlY2VpdmVkKjgvZWxhcHNlZC8xZTYsIDIpLAogICAgICAgICAgICAnZWxhcHNlZF9t'
    'cyc6IHJvdW5kKGVsYXBzZWQqMTAwMCksICdpbnRlZ3JpdHknOiBUcnVlLCAnbGltaXRlZF9zYW1wbGUnOiBUcnVlfQoKCmRl'
    'ZiBkZXZpY2Vfc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAgaW5mbz1qc29uLmxvYWRzKChST09ULydkZXZpY2UtaW5mby5q'
    'c29uJykucmVhZF90ZXh0KCkpCiAgICAgICAgcmV0dXJuIHsnZGV2aWNlX25hbWUnOmluZm8uZ2V0KCduYW1lJywnJyksJ2Rl'
    'dmljZV9udW1iZXInOmluZm8uZ2V0KCdudW1iZXInKSwKICAgICAgICAgICAgICAgICdkZXZpY2VfbmFtZV9wZW5kaW5nJzpi'
    'b29sKGluZm8uZ2V0KCdwZW5kaW5nJykgb3IgaW5mby5nZXQoJ3N5bmNfZXJyb3InKSl9CiAgICBleGNlcHQgKE9TRXJyb3Is'
    'VmFsdWVFcnJvcik6cmV0dXJuIHsnZGV2aWNlX25hbWUnOicnLCdkZXZpY2VfbnVtYmVyJzpOb25lLCdkZXZpY2VfbmFtZV9w'
    'ZW5kaW5nJzpGYWxzZX0KCgpkZWYgc3luY19kZXZpY2VfbmFtZShuYW1lPU5vbmUpOgogICAgaW1wb3J0IHVuaWNvZGVkYXRh'
    'CiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOnJhaXNlIFZhbHVlRXJyb3IoJ9Ch0L3QsNGH0LDQu9Cw'
    'INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAgaWYgbmFtZSBpcyBub3Qg'
    'Tm9uZToKICAgICAgICBuYW1lPXVuaWNvZGVkYXRhLm5vcm1hbGl6ZSgnTkZDJyxzdHIobmFtZSkpLnN0cmlwKCkKICAgICAg'
    'ICBpZiBub3QgMTw9bGVuKG5hbWUpPD02NCBvciBhbnkodW5pY29kZWRhdGEuY2F0ZWdvcnkoYykuc3RhcnRzd2l0aCgnQycp'
    'IGZvciBjIGluIG5hbWUpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCfQmNC80Y8g0LTQvtC70LbQvdC+INGB0L7Q'
    'tNC10YDQttCw0YLRjCDQvtGCIDEg0LTQviA2NCDQvtCx0YvRh9C90YvRhSDRgdC40LzQstC+0LvQvtCyLicpCiAgICBpZiBu'
    'b3QgKFJPT1QvJ2RldmljZScpLmV4aXN0cygpOndyaXRlKFJPT1QvJ2RldmljZScsc2VjcmV0cy50b2tlbl9oZXgoMTYpKQog'
    'ICAgdHJ5OmluZm89anNvbi5sb2FkcygoUk9PVC8nZGV2aWNlLWluZm8uanNvbicpLnJlYWRfdGV4dCgpKQogICAgZXhjZXB0'
    'IChPU0Vycm9yLFZhbHVlRXJyb3IpOmluZm89e30KICAgIGlmIG5hbWUgaXMgbm90IE5vbmU6aW5mby51cGRhdGUobmFtZT1u'
    'YW1lLHBlbmRpbmc9VHJ1ZSkKICAgIHBheWxvYWQ9eyd0b2tlbic6KFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAo'
    'KSwnZGV2aWNlJzooUk9PVC8nZGV2aWNlJykucmVhZF90ZXh0KCkuc3RyaXAoKX0KICAgIGlmIGluZm8uZ2V0KCdwZW5kaW5n'
    'Jyk6cGF5bG9hZFsnbmFtZSddPWluZm9bJ25hbWUnXQogICAgdHJ5OgogICAgICAgIHdpdGggbmFtZXNwYWNlKCkgaWYgUGF0'
    'aCgnL3J1bi9uZXRucy8nK05TKS5leGlzdHMoKSBlbHNlIGNvbnRleHRsaWIubnVsbGNvbnRleHQoKToKICAgICAgICAgICAg'
    'cmVwbHk9dGxzX3JlcXVlc3QoU0VSVkVSLCcvZGV2aWNlJyxwYXlsb2FkLHRpbWVvdXQ9NSkKICAgICAgICB2YWx1ZT1yZXBs'
    'eVsnZGV2aWNlJ107bnVtYmVyPWludCh2YWx1ZVsnbnVtYmVyJ10pCiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UodmFsdWVb'
    'J25hbWUnXSxzdHIpIG9yIG5vdCAxPD1sZW4odmFsdWVbJ25hbWUnXSk8PTY0IG9yIG51bWJlcjwxOnJhaXNlIFZhbHVlRXJy'
    'b3IoJ2ludmFsaWRfZGV2aWNlX21ldGFkYXRhJykKICAgICAgICBpbmZvPXsnbmFtZSc6dmFsdWVbJ25hbWUnXSwnbnVtYmVy'
    'JzpudW1iZXIsJ3BlbmRpbmcnOkZhbHNlLCdzeW5jX2Vycm9yJzpGYWxzZX0KICAgIGV4Y2VwdCAoT1NFcnJvcixSdW50aW1l'
    'RXJyb3IsVmFsdWVFcnJvcixLZXlFcnJvcixodHRwLmNsaWVudC5IVFRQRXhjZXB0aW9uKToKICAgICAgICBpbmZvWydzeW5j'
    'X2Vycm9yJ109VHJ1ZQogICAgd3JpdGUoUk9PVC8nZGV2aWNlLWluZm8uanNvbicsanNvbi5kdW1wcyhpbmZvLGVuc3VyZV9h'
    'c2NpaT1GYWxzZSkpCiAgICByZXR1cm4gZGV2aWNlX3N0YXR1cygpCgoKZGVmIHRva2VuX3N0YXR1cygpOgogICAgdHJ5Ogog'
    'ICAgICAgIHRva2VuID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAoKQogICAgZXhjZXB0IEZpbGVOb3RGb3Vu'
    'ZEVycm9yOgogICAgICAgIHRva2VuID0gJycKICAgIHZhbGlkID0gcmUuZnVsbG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2Vu'
    'KSBpcyBub3QgTm9uZQogICAgcmV0dXJuIHsnaGFzX3Rva2VuJzogdmFsaWQsCiAgICAgICAgICAgICd0b2tlbl9oaW50Jzog'
    'J0VWTjEt4oCi4oCi4oCi4oCiIMK3IElEICcgKyBoYXNobGliLnNoYTI1Nih0b2tlbi5lbmNvZGUoKSkuaGV4ZGlnZXN0KClb'
    'OjhdIGlmIHZhbGlkIGVsc2UgJyd9CgoKZGVmIHNhdmVfdG9rZW4odG9rZW4pOgogICAgdG9rZW4gPSB0b2tlbi5zdHJpcCgp'
    'CiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2VuKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9y'
    'KCfQndGD0LbQtdC9INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAg0YTQvtGA0LzQsNGC0LAgRVZOMS3igKYnKQogICAgUk9P'
    'VC5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBvbGQgPSAoUk9PVC8ndG9rZW4n'
    'KS5yZWFkX3RleHQoKS5zdHJpcCgpIGlmIChST09ULyd0b2tlbicpLmV4aXN0cygpIGVsc2UgJycKICAgIGlmIG9sZCA9PSB0'
    'b2tlbjoKICAgICAgICBzeW5jX2RldmljZV9uYW1lKCk7cmV0dXJuCiAgICBpZiBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2lz'
    'LWFjdGl2ZScsICctLXF1aWV0JywgVU5JVF0sIGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgcmFpc2Ug'
    'UnVudGltZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQvtGC0LrQu9GO0YfQuNGC0LUgVlBOLdGC0YPQvdC90LXQu9GMINC/0LXR'
    'gNC10LQg0YHQvNC10L3QvtC5INGC0L7QutC10L3QsC4nKQogICAgIyBBIGRpZmZlcmVudCBhY2NvdW50IG5lZWRzIGl0cyBv'
    'd24gZGV2aWNlIGNyZWRlbnRpYWxzLiBOZXZlciByZXVzZSBpdHMgY2VydGlmaWNhdGUuCiAgICBmb3IgbmFtZSBpbiAoJ2Rl'
    'dmljZS1pbmZvLmpzb24nLCAnZGV2aWNlJywgJ2NsaWVudC1rZXkucGVtJywgJ2NsaWVudC5wZW0nLCAncHJvZmlsZS5qc29u'
    'JywgJ3JlcXVlc3QucGVtJywKICAgICAgICAgICAgICAgICAncHJpdmF0ZS9jbGllbnQta2V5LnBlbScsICd4NTA5L2NsaWVu'
    'dC5wZW0nKToKICAgICAgICAoUk9PVC9uYW1lKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgd3JpdGUoUk9PVC8ndG9r'
    'ZW4nLCB0b2tlbikKICAgIHN5bmNfZGV2aWNlX25hbWUoKQogICAgc3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB0L7RhdGA'
    '0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFsc2UsIG1l'
    'dHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1vZGU9MG83'
    'MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4odG9rZW4p'
    'CiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQ'
    'tdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAgZW5z'
    'dXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUoUk9PVC8ncmVjYWxpYnJhdGUnLCAnMScp'
    'CiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBIU1ZEUyBmdWxsLWRldmljZSBFc3RvbmlhIFZQ'
    'TgpBZnRlcj1uZXR3b3JrLnRhcmdldApbU2VydmljZV0KVHlwZT1zaW1wbGUKRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92'
    'cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsCkV4ZWNTdG9wUG9zdD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVy'
    'bmFsLXN0YXJmaXZlLXR1bm5lbC1jbGVhbnVwClRpbWVvdXRTdG9wU2VjPTIwCktpbGxNb2RlPW1peGVkClVNYXNrPTAwNzcK'
    'TWVtb3J5TWF4PTI1Nk0KUmVzdGFydD1ubwonJycKICAgIHdyaXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9VTklU'
    'LCB1bml0KQogICAgcmVjb3ZlcnkgPSAiZXZnZW5pdW0tc3RhcmZpdmUtdHVubmVsLXJlY292ZXIuc2VydmljZSIKICAgIHdy'
    'aXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9yZWNvdmVyeSwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPVJlY292ZXIg'
    'b25seSBpbnRlcnJ1cHRlZCBFdmdlbml1bSB0dW5uZWwgdGVzdCByZXNvdXJjZXMKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpB'
    'ZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldCB2cG4teHJheS5zZXJ2aWNlCltTZXJ2aWNl'
    'XQpUeXBlPW9uZXNob3QKRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVs'
    'LWNsZWFudXAKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CiIiIikKICAgIGNvbW1hbmQoWydzeXN0ZW1j'
    'dGwnLCAnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdlbmFibGUnLCByZWNvdmVyeV0pCiAg'
    'ICBzdGFnZSgnc3RhcnRpbmcnICwgJ9CT0L7RgtC+0LLQu9GOINC/0L7QtNC60LvRjtGH0LXQvdC40LUg0YfQtdGA0LXQtyBI'
    'U1ZEUyDQsiDQrdGB0YLQvtC90LjRji4nLCAyLCBhY3RpdmU9RmFsc2UsIHJldHJ5PTAsIGVycm9yX2NvZGU9JycpCiAgICBj'
    'b21tYW5kKFsnc3lzdGVtY3RsJywgJ3Jlc3RhcnQnIGlmIHJlcGFpciBlbHNlICdzdGFydCcsIFVOSVRdKQogICAgcHJpbnQo'
    'J1ZQTiDQt9Cw0L/Rg9GB0LrQsNC10YLRgdGPLicsZmx1c2g9VHJ1ZSkKCgpkZWYgZGlzY29ubmVjdCgpOgogICAgY29tbWFu'
    'ZChbJ3N5c3RlbWN0bCcsICdzdG9wJywgVU5JVF0sIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTI1KQogICAgY2xlYW51cCgpCiAg'
    'ICBjbGVhbnVwX2Z1bGwocmVsZWFzZT1UcnVlKQogICAgc3RhZ2UoJ29mZicsICdWUE4g0LLRi9C60LvRjtGH0LXQvS4nLCAw'
    'LCBhY3RpdmU9RmFsc2UpCiAgICBwcmludCgnVlBOINCy0YvQutC70Y7Rh9C10L0uJykKCgpkZWYgc3RhcnRfZGFlbW9uKGVu'
    'dik6CiAgICAoUlVOVElNRS8nY2hhcm9uLnZpY2knKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgbG9nID0gKFJPT1Qv'
    'J2NoYXJvbi5sb2cnKS5vcGVuKCd3JykKICAgIGRhZW1vbiA9IHN1YnByb2Nlc3MuUG9wZW4oWydpcCcsICduZXRucycsICdl'
    'eGVjJywgTlMsIGNoYXJvbl9iaW5hcnkoKV0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVudj1lbnYsIHN0ZGlu'
    'PXN1YnByb2Nlc3MuREVWTlVMTCwgc3Rkb3V0PWxvZywgc3RkZXJyPWxvZykKICAgIGxvZy5jbG9zZSgpCiAgICBmb3IgXyBp'
    'biByYW5nZSg2MCk6CiAgICAgICAgaWYgU1RPUCBvciBkYWVtb24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ2RhZW1vbl9zdG9wcGVkJykKICAgICAgICBpZiAoUlVOVElNRS8nY2hhcm9uLnZpY2knKS5l'
    'eGlzdHMoKSBhbmQgc3dhbignLS1zdGF0cycsIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTEpLnJldHVybmNvZGUgPT0gMDoKICAg'
    'ICAgICAgICAgYnJlYWsKICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgc3dhbignLS1sb2FkLWNyZWRzJywgJy0tbm9wcm9t'
    'cHQnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgIHN3YW4oJy0tbG9hZC1jb25ucycsICctLWZpbGUn'
    'LCBST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgcmV0dXJuIGRhZW1vbgoKCmRlZiB3b3JrZXIoKToKICAgIGdsb2JhbCBT'
    'VE9QCiAgICBTVE9QID0gRmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sIGxhbWJkYSAqXzogZ2xvYmFs'
    'cygpLl9fc2V0aXRlbV9fKCdTVE9QJywgVHJ1ZSkpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsIGxhbWJkYSAq'
    'XzogZ2xvYmFscygpLl9fc2V0aXRlbV9fKCdTVE9QJywgVHJ1ZSkpCiAgICBkYWVtb24gPSBOb25lCiAgICB0cnk6CiAgICAg'
    'ICAgY2xlYW51cCgpCiAgICAgICAgcmVmcmVzaF9yZXRhaW5lZF9ndWFyZCgpCiAgICAgICAgc3RhZ2UoJ3ByZXBhcmUnLCAn'
    '0JPQvtGC0L7QstC70Y4g0LfQsNGJ0LjRidGR0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQvdC40LUg0YEgSFNWRFMuJywgOCwg'
    'YWN0aXZlPUZhbHNlKQogICAgICAgIHNldHVwX25ldHdvcmsoKQogICAgICAgIHRyeToKICAgICAgICAgICAgcmVmZXJlbmNl'
    'ID0gKHsnc2tpcHBlZCc6ICdndWFyZF9hY3RpdmUnfSBpZiBmdWxsX2d1YXJkX2FjdGl2ZSgpIGVsc2UgcmVmZXJlbmNlX3Nh'
    'bXBsZShmb3JjZT0oUk9PVC8ncmVjYWxpYnJhdGUnKS5leGlzdHMoKSkpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBSdW50'
    'aW1lRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgICAgICByZWZlcmVuY2UgPSB7J2F2YWlsYWJsZSc6IEZhbHNlLCAncHJv'
    'dmlkZXInOiAnWWFuZGV4IEludGVybmV0b21ldGVyJ30KICAgICAgICAoUk9PVC8ncmVjYWxpYnJhdGUnKS51bmxpbmsobWlz'
    'c2luZ19vaz1UcnVlKQogICAgICAgIHN0YWdlKCd0b2tlbicsICfQn9GA0L7QstC10YDRj9GOINGC0L7QutC10L0g0Lgg0YHQ'
    'vtGF0YDQsNC90ZHQvdC90L7QtSDQv9C+0LTQutC70Y7Rh9C10L3QuNC1INGN0YLQvtCz0L4g0YPRgdGC0YDQvtC50YHRgtCy'
    '0LAuJywgMjApCiAgICAgICAgaWRlbnRpdHksIGFkZHJlc3MgPSBlbnJvbGwoKQogICAgICAgIHN5bmNfZGV2aWNlX25hbWUo'
    'KQogICAgICAgIHNjb3BlID0gJ3B1YmxpYy1hZGRyZXNzJwogICAgICAgIHN0YWdlKCdkYWVtb24nLCAn0JfQsNC/0YPRgdC6'
    '0LDRjiDRgtGD0L3QvdC10LvRjCBJS0V2MiDQoNC+0YHRgdC40Y8g4oaSINCt0YHRgtC+0L3QuNGPLicsIDQwLCBzY29wZT1z'
    'Y29wZSkKICAgICAgICBkYWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcykKICAgICAgICBlbnYgPSB7Kipvcy5lbnZp'
    'cm9uLCAnU1RST05HU1dBTl9DT05GJzogc3RyKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicpfQogICAgICAgIGVudi5wb3AoJ05P'
    'VElGWV9TT0NLRVQnLCBOb25lKQogICAgICAgIGRhZW1vbiA9IHN0YXJ0X2RhZW1vbihlbnYpCiAgICAgICAgc3RhZ2UoJ2hh'
    'bmRzaGFrZScsICfQo9GB0YLQsNC90LDQstC70LjQstCw0Y4g0LfQsNGJ0LjRidGR0L3QvdC+0LUg0YHQvtC10LTQuNC90LXQ'
    'vdC40LUg0YEgSFNWRFMuJywgNjApCiAgICAgICAgc3dhbignLS1pbml0aWF0ZScsICctLWNoaWxkJywgJ3N0YXJmaXZlLW5l'
    'dCcsIHRpbWVvdXQ9MzUpCiAgICAgICAgaWYgbm90IGluc3RhbGxlZCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ3NhX25vdF9pbnN0YWxsZWQnKQogICAgICAgIHN0YWdlKCdoZWFsdGgnLCAn0J/RgNC+0LLQtdGA0Y/RjiDRgtGD0L3Q'
    'vdC10LvRjCDQuCDQt9Cw0YnQuNGJ0ZHQvdC90YvQuSDQvtGC0LLQtdGCINGB0LXRgNCy0LXRgNCwLicsIDc1KQogICAgICAg'
    'IGlmIG5vdCBoZWFsdGgoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdoZWFsdGhfZmFpbGVkJykKICAgICAg'
    'ICBzdGFnZSgnbWVhc3VyZScsICfQn9GA0L7QstC10YDRj9GOINC/0LXRgNC10LTQsNGH0YMg0LTQsNC90L3Ri9GFINC4INGG'
    '0LXQu9C+0YHRgtC90L7RgdGC0Ywg0YTQsNC50LvQsC4nLCA4NSkKICAgICAgICBtZXRyaWNzID0gZG93bmxvYWQoKQogICAg'
    'ICAgIG1ldHJpY3NbJ3JlZmVyZW5jZSddID0gcmVmZXJlbmNlCiAgICAgICAgc3RhZ2UoJ3JvdXRpbmcnLCAn0J/QvtC00LrQ'
    'u9GO0YfQsNGOINCy0LXRgdGMINGC0YDQsNGE0LjQuiDQutC+0LzQv9GM0Y7RgtC10YDQsCDQuiDQstGL0YXQvtC00YMg0LIg'
    '0K3RgdGC0L7QvdC40LguJywgOTIpCiAgICAgICAgYWN0aXZhdGVfZnVsbChhZGRyZXNzKQogICAgICAgIHN0YWdlKCdjb25u'
    'ZWN0ZWQnLCAn0J/QvtC00LrQu9GO0YfQtdC90L46INC60L7QvNC/0YzRjtGC0LXRgCDihpIgSFNWRFMg4oaSINCt0YHRgtC+'
    '0L3QuNGPLiAnLCAxMDAsCiAgICAgICAgICAgICAgYWN0aXZlPVRydWUsIG1ldHJpY3M9bWV0cmljcywgc2luY2U9aW50KHRp'
    'bWUudGltZSgpKSkKICAgICAgICBmYWlsdXJlcyA9IDAKICAgICAgICB3aGlsZSBub3QgU1RPUDoKICAgICAgICAgICAgZm9y'
    'IF8gaW4gcmFuZ2UoMTAwKToKICAgICAgICAgICAgICAgIGlmIFNUT1A6CiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAg'
    'ICAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgICAgIGlmIFNUT1A6CiAgICAgICAgICAgICAgICBicmVhawog'
    'ICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAg'
    'ICAgcG9saWN5LmVuc3VyZV9yb3V0ZSgpCiAgICAgICAgICAgICAgICBvayA9IGRhZW1vbi5wb2xsKCkgaXMgTm9uZSBhbmQg'
    'aW5zdGFsbGVkKCkgYW5kIGhlYWx0aCgpCiAgICAgICAgICAgICAgICBpZiBvayBhbmQgbm90IGVncmVzc19oZWFsdGgoKToK'
    'ICAgICAgICAgICAgICAgICAgICBzdGFnZSgnZWdyZXNzX3dhaXQnLCAnSFNWRFMg0LTQvtGB0YLRg9C/0LXQvTsg0L7QttC4'
    '0LTQsNGOINCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40Y8g0LLRi9GF0L7QtNCwINCyINCt0YHRgtC+0L3QuNC4LicsIDkw'
    'LCBhY3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9y'
    'LCBSdW50aW1lRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgICAgICAgICAgb2sgPSBGYWxzZQog'
    'ICAgICAgICAgICBmYWlsdXJlcyA9IDAgaWYgb2sgZWxzZSBmYWlsdXJlcysxCiAgICAgICAgICAgIGlmIGZhaWx1cmVzID09'
    'IDE6CiAgICAgICAgICAgICAgICBzdGFnZSgnY2hlY2tpbmcnLCAn0J7RgtCy0LXRgiBIU1ZEUyDQt9Cw0LTQtdGA0LbQuNCy'
    '0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgdC+0LXQtNC40L3QtdC90LjQtS4nLCA5MCwgYWN0aXZlPUZhbHNlKQog'
    'ICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgaWYgZmFpbHVyZXMgPj0gMjoKICAgICAgICAgICAgICAgIHN0'
    'YWdlKCdyZXBhaXJpbmcnLCAn0KHQstGP0LfRjCDRgSBIU1ZEUyDQv9C+0YLQtdGA0Y/QvdCwLiDQktC+0YHRgdGC0LDQvdCw'
    '0LLQu9C40LLQsNGOIFZQTi3RgtGD0L3QvdC10LvRjC4nLCA2MCwgYWN0aXZlPUZhbHNlKQogICAgICAgICAgICAgICAgaWYg'
    'ZGFlbW9uLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICBpbnNpZGUoWydpcCcsICd4ZnJtJywgJ3N0'
    'YXRlJywgJ2ZsdXNoJ10pCiAgICAgICAgICAgICAgICAgICAgaW5zaWRlKFsnaXAnLCAneGZybScsICdwb2xpY3knLCAnZmx1'
    'c2gnXSkKICAgICAgICAgICAgICAgICAgICBpbnNpZGUoWydpcCcsICdyb3V0ZScsICdmbHVzaCcsICd0YWJsZScsICc1MTgy'
    'MiddLCBjaGVjaz1GYWxzZSkKICAgICAgICAgICAgICAgICAgICBkYWVtb24gPSBzdGFydF9kYWVtb24oZW52KQogICAgICAg'
    'ICAgICAgICAgc3dhbignLS10ZXJtaW5hdGUnLCAnLS1pa2UnLCAnc3RhcmZpdmUnLCBjaGVjaz1GYWxzZSkKICAgICAgICAg'
    'ICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCAnLS1jaGlsZCcsICdzdGFyZml2ZS1uZXQnLCB0aW1lb3V0PTM1KQogICAgICAg'
    'ICAgICAgICAgaWYgbm90IGluc3RhbGxlZCgpIG9yIG5vdCBoZWFsdGgoKToKICAgICAgICAgICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ3JlY292ZXJ5X2ZhaWxlZCcpCiAgICAgICAgICAgICAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQog'
    'ICAgICAgICAgICAgICAgaWYgbm90IGVncmVzc19oZWFsdGgoKToKICAgICAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ2VzdG9uaWFfZWdyZXNzX2ZhaWxlZCcpCiAgICAgICAgICAgICAgICBmYWlsdXJlcyA9IDAKICAgICAgICAgICAg'
    'c3RhZ2UoJ2Nvbm5lY3RlZCcsICfQn9C+0LTQutC70Y7Rh9C10L3Qvjog0LrQvtC80L/RjNGO0YLQtdGAIOKGkiBIU1ZEUyDi'
    'hpIg0K3RgdGC0L7QvdC40Y8uICcsIDEwMCwgYWN0aXZlPVRydWUpCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3Is'
    'IFJ1bnRpbWVFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgIGNvZGUgPSBzdHIoZXhj'
    'KSBpZiByZS5mdWxsbWF0Y2gociJbYS16X117MSw2NH0iLCBzdHIoZXhjKSkgZWxzZSB0eXBlKGV4YykuX19uYW1lX18KICAg'
    'ICAgICBjdXJyZW50ID0gc2F2ZWQoKS5nZXQoJ3BoYXNlJywgJ3ByZXBhcmUnKQogICAgICAgIG1lc3NhZ2UgPSB7J3Rva2Vu'
    'JzogJ9Cd0LUg0YPQtNCw0LvQvtGB0Ywg0L/QvtC00YLQstC10YDQtNC40YLRjCDRgtC+0LrQtdC9INC40LvQuCDQv9C+0LvR'
    'g9GH0LjRgtGMINGB0LXRgNGC0LjRhNC40LrQsNGCIEhTVkRTLicsCiAgICAgICAgICAgICAgICAgICAnaGFuZHNoYWtlJzog'
    'J0hTVkRTINC90LUg0L/QvtC00YLQstC10YDQtNC40Lsg0L/QvtC00LrQu9GO0YfQtdC90LjQtSBJS0V2Mi4nLAogICAgICAg'
    'ICAgICAgICAgICAgJ21lYXN1cmUnOiAn0J/RgNC+0LLQtdGA0LrQsCDQv9C10YDQtdC00LDRh9C4INC00LDQvdC90YvRhSDQ'
    'vdC1INC/0YDQvtGI0LvQsC4nLAogICAgICAgICAgICAgICAgICAgJ3JlcGFpcmluZyc6ICfQkNCy0YLQvtCy0L7RgdGB0YLQ'
    'sNC90L7QstC70LXQvdC40LUg0L3QtSDRg9C00LDQu9C+0YHRjC4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGM'
    'wrsuJ30uZ2V0KGN1cnJlbnQsICdWUE4t0YLRg9C90L3QtdC70Ywg0L3QtSDQt9Cw0L/Rg9GB0YLQuNC70YHRjy4g0J3QsNC2'
    '0LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsuJykKICAgICAgICBzdGFnZSgnZmFpbGVkJywgbWVzc2FnZSsoJyDQmNC9'
    '0YLQtdGA0L3QtdGCINC30LDQsdC70L7QutC40YDQvtCy0LDQvSDQtNC+INC+0YLQutC70Y7Rh9C10L3QuNGPINGA0LXQttC4'
    '0LzQsC4nIGlmIGZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSAnINCc0LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNGPINC60L7QvNC/'
    '0YzRjtGC0LXRgNCwINC90LUg0L/QtdGA0LXQutC70Y7Rh9C10L3QsC4nKSwgMCwgYWN0aXZlPUZhbHNlLCBlcnJvcl9jb2Rl'
    'PWNvZGUsIG1ldHJpY3M9e30pCiAgICBmaW5hbGx5OgogICAgICAgIGlmIGRhZW1vbiBhbmQgZGFlbW9uLnBvbGwoKSBpcyBO'
    'b25lOgogICAgICAgICAgICBkYWVtb24udGVybWluYXRlKCkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgZGFl'
    'bW9uLndhaXQodGltZW91dD02KQogICAgICAgICAgICBleGNlcHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDoKICAgICAg'
    'ICAgICAgICAgIGRhZW1vbi5raWxsKCk7IGRhZW1vbi53YWl0KHRpbWVvdXQ9MykKICAgICAgICBjbGVhbnVwKCkKICAgICAg'
    'ICBpZiBTVE9QOgogICAgICAgICAgICBzdGFnZSgnb2ZmJywgJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsIDAsIGFjdGl2ZT1G'
    'YWxzZSkK'
)
NETWORK_POLICY_PY_B64 = (
    'IiIiTG9jYWwgdHJhZmZpYyBzZWxlY3Rpb24gZm9yIHRoZSB0b2tlbiB0dW5uZWwuIE5vIHJlbW90ZSBwcm94eSBwcm90b2Nv'
    'bC4iIiIKaW1wb3J0IGlwYWRkcmVzcwppbXBvcnQganNvbgppbXBvcnQgb3MKZnJvbSBwYXRobGliIGltcG9ydCBQYXRoCmlt'
    'cG9ydCByZQppbXBvcnQgdGltZQoKYXBpID0gTm9uZQp0dW5uZWwgPSBOb25lClBBVEggPSBQYXRoKCcvZXRjL3Zwbi1tYW5h'
    'Z2VyL3BvbGljeS5qc29uJykKUlVOID0gUGF0aCgnL3J1bi92cG4tbWFuYWdlcicpClNFUlZJQ0UgPSAnZXZnZW5pdW0tcG9s'
    'aWN5LnNlcnZpY2UnClRVTiA9ICdldm4tcG9saWN5JwpESVJFQ1QgPSAweDQ1NTY0RTMxClZQTiA9IDB4NDU1NjRFMzIKUEhZ'
    'U0lDQUxfVEFCTEUgPSAnNTE4MzAnClZQTl9UQUJMRSA9ICc1MTgzMScKRE5TX1BPUlQgPSAxODU1MwpDSEVDS19QT1JUID0g'
    'MTg1NTQKQ0FURUdPUklFUyA9ICgnYXBwbGljYXRpb25zJywnbmV0d29ya3MnLCdwb3J0cycsJ2RucycpCkJBU0UgPSB7CiAn'
    'YXBwbGljYXRpb25zJzogW3snaWQnOidtYXBwZXInLCd2YWx1ZSc6J2V2Z2VuaXVtLXdheWRyb2lkLW1hcHBlcicsJ2xhYmVs'
    'JzonV2F5ZHJvaWQgTWFwcGVyJ31dLAogJ25ldHdvcmtzJzogW3snaWQnOidsYW4nLCd2YWx1ZSc6J2Nvbm5lY3RlZCcsJ2xh'
    'YmVsJzon0KPRgdGC0YDQvtC50YHRgtCy0LAg0YLQtdC60YPRidC10Lkg0LvQvtC60LDQu9GM0L3QvtC5INGB0LXRgtC4J30s'
    'CiAgICAgICAgICAgICAgeydpZCc6J2xpbmtsb2NhbCcsJ3ZhbHVlJzonMTY5LjI1NC4wLjAvMTYnLCdsYWJlbCc6J9Cj0YHR'
    'gtGA0L7QudGB0YLQstCwINGBINCw0LLRgtC+0LzQsNGC0LjRh9C10YHQutC40Lwg0LvQvtC60LDQu9GM0L3Ri9C8INCw0LTR'
    'gNC10YHQvtC8J31dLAogJ3BvcnRzJzogW3snaWQnOidkaXNjb3ZlcnknLCd2YWx1ZSc6J2Rpc2NvdmVyeScsJ2xhYmVsJzon'
    '0J7QsdC90LDRgNGD0LbQtdC90LjQtSDRg9GB0YLRgNC+0LnRgdGC0LI6IG1ETlMsIFNTRFAsIExMTU5SICjRgtC+0LvRjNC6'
    '0L4g0LvQvtC60LDQu9GM0L3QsNGPINGB0LXRgtGMKSd9XSwKICdkbnMnOiBbeydpZCc6J3N0dWInLCd2YWx1ZSc6JzEyNy4w'
    'LjAuMC84JywnbGFiZWwnOifQodC40YHRgtC10LzQvdGL0LkgRE5TINCy0L3Rg9GC0YDQuCDQutC+0LzQv9GM0Y7RgtC10YDQ'
    'sCd9XQp9CgpkZWYgZGVmYXVsdHMoKToKIHJldHVybiB7J3NjaGVtYSc6MSwnd2F5ZHJvaWRfZGlyZWN0JzpUcnVlLCdkaXNh'
    'YmxlZF9iYXNlJzpbXSwgJ2FwcGxpY2F0aW9ucyc6W10sICduZXR3b3Jrcyc6W10sICdwb3J0cyc6W10sICdkbnMnOltdfQoK'
    'ZGVmIGxvYWQoKToKIGlmIG5vdCBQQVRILmV4aXN0cygpOnJldHVybiBkZWZhdWx0cygpCiB2YWx1ZT1qc29uLmxvYWRzKFBB'
    'VEgucmVhZF90ZXh0KCkpCiBpZiB2YWx1ZS5nZXQoJ3NjaGVtYScpIT0xOnJhaXNlIFJ1bnRpbWVFcnJvcign0J3QtdC40LfQ'
    'stC10YHRgtC90LDRjyDQstC10YDRgdC40Y8g0L/RgNCw0LLQuNC7INC40YHQutC70Y7Rh9C10L3QuNC5LicpCiByZXR1cm4g'
    'eyoqZGVmYXVsdHMoKSwqKnZhbHVlfQoKZGVmIHNhdmUodmFsdWUpOgogUEFUSC5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVl'
    'LGV4aXN0X29rPVRydWUpCiB0bXA9UEFUSC53aXRoX3N1ZmZpeCgnLm5ldycpCiBmZD1vcy5vcGVuKHRtcCxvcy5PX1dST05M'
    'WXxvcy5PX0NSRUFUfG9zLk9fVFJVTkN8b3MuT19OT0ZPTExPVywwbzYwMCkKIHdpdGggb3MuZmRvcGVuKGZkLCd3JykgYXMg'
    'Zjpqc29uLmR1bXAodmFsdWUsZixlbnN1cmVfYXNjaWk9RmFsc2UsaW5kZW50PTIpCiBvcy5yZXBsYWNlKHRtcCxQQVRIKQoK'
    'ZGVmIGVuYWJsZWQocCxjYXQsa2V5KTpyZXR1cm4gY2F0Kyc6JytrZXkgbm90IGluIHBbJ2Rpc2FibGVkX2Jhc2UnXQoKZGVm'
    'IG5vcm1hbGl6ZShjYXRlZ29yeSx2YWx1ZSk6CiB2YWx1ZT1zdHIodmFsdWUpLnN0cmlwKCkKIGlmIG5vdCB2YWx1ZSBvciBs'
    'ZW4odmFsdWUpPjUxMiBvciBhbnkob3JkKGMpPDMyIGZvciBjIGluIHZhbHVlKTpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LrQ'
    'vtGA0YDQtdC60YLQvdC+0LUg0LjRgdC60LvRjtGH0LXQvdC40LUuJykKIGlmIGNhdGVnb3J5PT0nYXBwbGljYXRpb25zJzoK'
    'ICBpZiBub3QgcmUuZnVsbG1hdGNoKHInW1x3Li8gK0AoKVwtXSsnLHZhbHVlKTpyYWlzZSBWYWx1ZUVycm9yKCfQo9C60LDQ'
    'ttC40YLQtSDQuNC80Y8g0L/RgNC+0YbQtdGB0YHQsCDQuNC70Lgg0L/QvtC70L3Ri9C5INC/0YPRgtGMLicpCiAgaWYgJy8n'
    'IGluIHZhbHVlIGFuZCBub3QgdmFsdWUuc3RhcnRzd2l0aCgnLycpOnJhaXNlIFZhbHVlRXJyb3IoJ9Cf0YPRgtGMINC00L7Q'
    'u9C20LXQvSDQsdGL0YLRjCDQsNCx0YHQvtC70Y7RgtC90YvQvC4nKQogIHJldHVybiB2YWx1ZQogaWYgY2F0ZWdvcnk9PSdu'
    'ZXR3b3Jrcyc6CiAgdHJ5OgogICBuZXQ9aXBhZGRyZXNzLmlwX25ldHdvcmsodmFsdWUsc3RyaWN0PUZhbHNlKQogICBpZiBu'
    'ZXQudmVyc2lvbiE9NDpyYWlzZSBWYWx1ZUVycm9yKCfQn9C+0LTQtNC10YDQttC40LLQsNGO0YLRgdGPINCw0LTRgNC10YHQ'
    'sCDQstC40LTQsCAxOTIuMTY4LjEuMTAuJykKICAgIyBBZGRyZXNzZXMgb3duZWQgYnkgb3VyIHR1bm5lbHMgY2Fubm90IGJl'
    'IHJvdXRlZCBwaHlzaWNhbGx5LgogICByZXNlcnZlZD1bJzEwLjc3LjAuMC8yNCcsdHVubmVsLk5FVFdPUkssdHVubmVsLkZV'
    'TExfTkVULCcxOTguMTguMjU0LjAvMzAnXSBpZiB0dW5uZWwgZWxzZSBbJzEwLjc3LjAuMC8yNCcsJzE3Mi4yOS4yNDYuMC8z'
    'MCcsJzE3Mi4yOS4yNDcuMC8zMCcsJzE5OC4xOC4yNTQuMC8zMCddCiAgIGlmIGFueShuZXQub3ZlcmxhcHMoaXBhZGRyZXNz'
    'LmlwX25ldHdvcmsobikpIGZvciBuIGluIHJlc2VydmVkKTpyYWlzZSBWYWx1ZUVycm9yKCfQlNC40LDQv9Cw0LfQvtC9INC/'
    '0LXRgNC10YHQtdC60LDQtdGC0YHRjyDRgdC+INGB0LvRg9C20LXQsdC90L7QuSDRgdC10YLRjNGOIFZQTi4g0JTQvtCx0LDQ'
    'stGM0YLQtSDQsdC+0LvQtdC1INGD0LfQutGD0Y4g0YHQtdGC0YwuJykKICAgcmV0dXJuIHN0cihuZXQpCiAgZXhjZXB0IFZh'
    'bHVlRXJyb3IgYXMgZXhjOgogICBpZiAnLycgaW4gdmFsdWUgb3IgcmUuZnVsbG1hdGNoKHInW1xkLl0rJyx2YWx1ZSk6cmFp'
    'c2UgZXhjCiAgZXhhY3Q9dmFsdWUuc3RhcnRzd2l0aCgnPScpO3ZhbHVlPXZhbHVlLmxzdHJpcCgnPScpLmxvd2VyKCkucnN0'
    'cmlwKCcuJykKICB0cnk6dmFsdWU9dmFsdWUuZW5jb2RlKCdpZG5hJykuZGVjb2RlKCdhc2NpaScpCiAgZXhjZXB0IFVuaWNv'
    'ZGVFcnJvcjpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LrQvtGA0YDQtdC60YLQvdGL0Lkg0LTQvtC80LXQvS4nKQogIGlmIGxl'
    'bih2YWx1ZSk+MjUzIG9yIG5vdCBhbGwocmUuZnVsbG1hdGNoKHInW2EtejAtOV0oPzpbYS16MC05LV17MCw2MX1bYS16MC05'
    'XSk/Jyx4KSBmb3IgeCBpbiB2YWx1ZS5zcGxpdCgnLicpKTpyYWlzZSBWYWx1ZUVycm9yKCfQktCy0LXQtNC40YLQtSDQtNC+'
    '0LzQtdC9INCx0LXQtyBodHRwczovLyDQuCDQv9GD0YLQuC4nKQogIHJldHVybiAoJz0nIGlmIGV4YWN0IGVsc2UgJycpK3Zh'
    'bHVlCiBpZiBjYXRlZ29yeT09J2Rucyc6CiAgYWRkcj1pcGFkZHJlc3MuaXBfYWRkcmVzcyh2YWx1ZSkKICBpZiBhZGRyLnZl'
    'cnNpb24hPTQgb3IgYWRkci5pc191bnNwZWNpZmllZCBvciBhZGRyLmlzX211bHRpY2FzdCBvciBhZGRyLmlzX2xvb3BiYWNr'
    'OnJhaXNlIFZhbHVlRXJyb3IoJ9Cj0LrQsNC20LjRgtC1INCw0LTRgNC10YEg0LLQvdC10YjQvdC10LPQviDQuNC70Lgg0LTQ'
    'vtC80LDRiNC90LXQs9C+IEROUy3RgdC10YDQstC10YDQsDsg0LvQvtC60LDQu9GM0L3Ri9C5IEROUyDQvdCw0YXQvtC00LjR'
    'gtGB0Y8g0LIg0LHQsNC30L7QstGL0YUg0L/RgNCw0LLQuNC70LDRhS4nKQogIHJldHVybiBzdHIoYWRkcikKIGlmIGNhdGVn'
    'b3J5PT0ncG9ydHMnOgogIG1hdGNoPXJlLmZ1bGxtYXRjaChyJyh0Y3B8dWRwfGJvdGgpOihcZHsxLDV9KSg/Ojoob3V0fGlu'
    'fGJvdGgpKT8nLHZhbHVlLmxvd2VyKCkpCiAgaWYgbm90IG1hdGNoIG9yIG5vdCAxPD1pbnQobWF0Y2hbMl0pPD02NTUzNTpy'
    'YWlzZSBWYWx1ZUVycm9yKCfQpNC+0YDQvNCw0YI6IHRjcDo0NDM6b3V0LCB1ZHA6MjU1NjU6aW4g0LjQu9C4IGJvdGg6MjU1'
    'NjU6Ym90aC4nKQogIGlmIGludChtYXRjaFsyXSk9PTUzOnJhaXNlIFZhbHVlRXJyb3IoJ0ROUyDQvdCw0YHRgtGA0LDQuNCy'
    '0LDQtdGC0YHRjyDQstC+INCy0LrQu9Cw0LTQutC1IEROUy4nKQogIHJldHVybiBmJ3ttYXRjaFsxXX06e2ludChtYXRjaFsy'
    'XSl9OnttYXRjaFszXSBvciAiYm90aCJ9JwogcmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC90LDRjyDQutCw'
    '0YLQtdCz0L7RgNC40Y8uJykKCmRlZiBtaWdyYXRpb24oc2V0dGluZ3MpOgogaWYgUEFUSC5leGlzdHMoKTpyZXR1cm4KIHA9'
    'ZGVmYXVsdHMoKTsgcmVqZWN0ZWQ9W10KIHNvdXJjZXM9eydhcHBsaWNhdGlvbnMnOnNldHRpbmdzLmdldCgnZGlyZWN0X2Fw'
    'cHMnKSwnbmV0d29ya3MnOnNldHRpbmdzLmdldCgnZGlyZWN0X25ldHdvcmtzJyl9CiBmb3IgY2F0ZWdvcnksa2V5IGluIHNv'
    'dXJjZXMuaXRlbXMoKToKICBpZiBrZXkgYW5kIFBhdGgoa2V5KS5pc19maWxlKCk6CiAgIGZvciBsaW5lIGluIFBhdGgoa2V5'
    'KS5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCk6CiAgICBzPWxpbmUuc3RyaXAoKQogICAgaWYgbm90IHMgb3Igcy5zdGFydHN3'
    'aXRoKCcjJyk6Y29udGludWUKICAgIHRyeTpwW2NhdGVnb3J5XS5hcHBlbmQobm9ybWFsaXplKGNhdGVnb3J5LHMpKQogICAg'
    'ZXhjZXB0IFZhbHVlRXJyb3I6cmVqZWN0ZWQuYXBwZW5kKHsnY2F0ZWdvcnknOmNhdGVnb3J5LCd2YWx1ZSc6c30pCiBrZXk9'
    'c2V0dGluZ3MuZ2V0KCdkaXJlY3Rfc2l0ZXMnKQogaWYga2V5IGFuZCBQYXRoKGtleSkuaXNfZmlsZSgpOgogIGZvciBsaW5l'
    'IGluIFBhdGgoa2V5KS5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCk6CiAgIHM9bGluZS5zdHJpcCgpCiAgIGlmIG5vdCBzIG9y'
    'IHMuc3RhcnRzd2l0aCgnIycpOmNvbnRpbnVlCiAgIHM9cy5yZXBsYWNlKCdmdWxsOicsJz0nLDEpLnJlbW92ZXByZWZpeCgn'
    'ZG9tYWluOicpCiAgIHRyeTpwWyduZXR3b3JrcyddLmFwcGVuZChub3JtYWxpemUoJ25ldHdvcmtzJyxzKSkKICAgZXhjZXB0'
    'IFZhbHVlRXJyb3I6cmVqZWN0ZWQuYXBwZW5kKHsnY2F0ZWdvcnknOiduZXR3b3JrcycsJ3ZhbHVlJzpzfSkKIGZvciBwcm90'
    'byxwb3J0IGluIGFwaS5yZWFkX3NlcnZlcl9wb3J0cyhzZXR0aW5ncyk6cFsncG9ydHMnXS5hcHBlbmQoZid7cHJvdG99Ontw'
    'b3J0fTppbicpCiBmb3IgYyBpbiBDQVRFR09SSUVTOnBbY109bGlzdChkaWN0LmZyb21rZXlzKHBbY10pKQogcFsnbWlncmF0'
    'aW9uX3NraXBwZWQnXT1yZWplY3RlZAogc2F2ZShwKQoKZGVmIHB1YmxpYygpOgogcD1sb2FkKCk7YmFzZT17fQogZm9yIGMs'
    'ZW50cmllcyBpbiBCQVNFLml0ZW1zKCk6YmFzZVtjXT1beyoqZSwnZW5hYmxlZCc6ZW5hYmxlZChwLGMsZVsnaWQnXSl9IGZv'
    'ciBlIGluIGVudHJpZXNdCiByZXR1cm4geyoqcCwnYmFzZSc6YmFzZX0KCmRlZiBwb3J0cyhwLGRpcmVjdGlvbik6CiByZXN1'
    'bHQ9eyd0Y3AnOnNldCgpLCd1ZHAnOnNldCgpfQogZm9yIHZhbHVlIGluIHBbJ3BvcnRzJ106CiAgcHJvdG8sbnVtYmVyLHNp'
    'ZGU9dmFsdWUuc3BsaXQoJzonKQogIGlmIHNpZGUgbm90IGluIChkaXJlY3Rpb24sJ2JvdGgnKTpjb250aW51ZQogIGZvciBw'
    'cm90b2NvbCBpbiAoJ3RjcCcsJ3VkcCcpIGlmIHByb3RvPT0nYm90aCcgZWxzZSAocHJvdG8sKTpyZXN1bHRbcHJvdG9jb2xd'
    'LmFkZChpbnQobnVtYmVyKSkKIHJldHVybiByZXN1bHQKCmRlZiBsb2NhbF9uZXR3b3Jrcyhyb3V0ZSk6CiBkYXRhPWpzb24u'
    'bG9hZHModHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hvdycsJ2Rldicscm91dGVbJ2RldiddXSku'
    'c3Rkb3V0KQogcmV0dXJuIHNvcnRlZCh7c3RyKGlwYWRkcmVzcy5pcF9uZXR3b3JrKGYie2FbJ2xvY2FsJ119L3thWydwcmVm'
    'aXhsZW4nXX0iLHN0cmljdD1GYWxzZSkpIGZvciBsaW5rIGluIGRhdGEgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycs'
    'W10pIGlmIGEuZ2V0KCdzY29wZScpPT0nZ2xvYmFsJ30pCgpkZWYgZGlyZWN0X25ldHdvcmtzKHAsbGFuKToKIHZhbHVlcz1b'
    'XQogZm9yIHZhbHVlIGluIHBbJ25ldHdvcmtzJ106CiAgdHJ5OnZhbHVlcy5hcHBlbmQoc3RyKGlwYWRkcmVzcy5pcF9uZXR3'
    'b3JrKHZhbHVlKSkpCiAgZXhjZXB0IFZhbHVlRXJyb3I6cGFzcwogaWYgZW5hYmxlZChwLCduZXR3b3JrcycsJ2xhbicpOgog'
    'IGZvciBpdGVtIGluIGxhbjoKICAgcmVtYWluaW5nPVtpcGFkZHJlc3MuaXBfbmV0d29yayhpdGVtKV0KICAgZm9yIHJlc2Vy'
    'dmVkIGluIFsnMTAuNzcuMC4wLzI0JywnMTcyLjI5LjI0Ni4wLzMwJywnMTcyLjI5LjI0Ny4wLzMwJywnMTk4LjE4LjI1NC4w'
    'LzMwJ106CiAgICBibG9jaz1pcGFkZHJlc3MuaXBfbmV0d29yayhyZXNlcnZlZCk7dXBkYXRlZD1bXQogICAgZm9yIG5ldCBp'
    'biByZW1haW5pbmc6CiAgICAgaWYgbm90IG5ldC5vdmVybGFwcyhibG9jayk6dXBkYXRlZC5hcHBlbmQobmV0KQogICAgIGVs'
    'aWYgYmxvY2suc3VibmV0X29mKG5ldCk6dXBkYXRlZC5leHRlbmQobmV0LmFkZHJlc3NfZXhjbHVkZShibG9jaykpCiAgICBy'
    'ZW1haW5pbmc9dXBkYXRlZAogICB2YWx1ZXMgKz0gW3N0cihuKSBmb3IgbiBpbiByZW1haW5pbmddCiBpZiBlbmFibGVkKHAs'
    'J25ldHdvcmtzJywnbGlua2xvY2FsJyk6dmFsdWVzKz1bJzE2OS4yNTQuMC4wLzE2J10KIHJldHVybiBzb3J0ZWQoc2V0KHZh'
    'bHVlcykpCgpkZWYgY29uZmlnKHApOgogcnVsZXM9W3sndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6WydjaGVjayddLCdv'
    'dXRib3VuZFRhZyc6J3Zwbid9LAogICAgICAgIHsndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6WydkbnMtaW4nXSwnb3V0'
    'Ym91bmRUYWcnOidkbnMnfV0KIGFwcHM9bGlzdChwWydhcHBsaWNhdGlvbnMnXSkKIGlmIGVuYWJsZWQocCwnYXBwbGljYXRp'
    'b25zJywnbWFwcGVyJyk6YXBwcys9Wydldmdlbml1bS13YXlkcm9pZC1tYXBwZXInXQogaWYgYXBwczpydWxlcy5hcHBlbmQo'
    'eyd0eXBlJzonZmllbGQnLCdwcm9jZXNzJzphcHBzLCdpbmJvdW5kVGFnJzpbJ3R1biddLCdvdXRib3VuZFRhZyc6J2RpcmVj'
    'dCd9KQogZG9tYWlucz1bXQogZm9yIHZhbHVlIGluIHBbJ25ldHdvcmtzJ106CiAgdHJ5OmlwYWRkcmVzcy5pcF9uZXR3b3Jr'
    'KHZhbHVlKQogIGV4Y2VwdCBWYWx1ZUVycm9yOmRvbWFpbnMuYXBwZW5kKCgnZnVsbDonK3ZhbHVlWzE6XSkgaWYgdmFsdWUu'
    'c3RhcnRzd2l0aCgnPScpIGVsc2UgJ2RvbWFpbjonK3ZhbHVlKQogaWYgZG9tYWluczpydWxlcy5hcHBlbmQoeyd0eXBlJzon'
    'ZmllbGQnLCdkb21haW4nOmRvbWFpbnMsJ2luYm91bmRUYWcnOlsndHVuJ10sJ291dGJvdW5kVGFnJzonZGlyZWN0J30pCiAj'
    'IEROUyBlbmdpbmUgcmVxdWVzdHMgbXVzdCBuZXZlciBpbmhlcml0IGRvbWFpbi9hcHBsaWNhdGlvbiBieXBhc3MgcnVsZXMu'
    'CiBydWxlcys9W3sndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6WydkbnMtZW5naW5lJ10sJ291dGJvdW5kVGFnJzondnBu'
    'J30sCiAgICAgICAgIHsndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6Wyd0dW4nXSwnb3V0Ym91bmRUYWcnOid2cG4nfV0K'
    'IHJldHVybiB7J2xvZyc6eydsb2dsZXZlbCc6J3dhcm5pbmcnLCdhY2Nlc3MnOidub25lJ30sCiAgJ2luYm91bmRzJzpbeyd0'
    'YWcnOid0dW4nLCdwcm90b2NvbCc6J3R1bicsJ3NldHRpbmdzJzp7J25hbWUnOlRVTiwnbXR1JzoxMjgwLCdnYXRld2F5Jzpb'
    'JzE5OC4xOC4yNTQuMS8zMCddfSwKICAgICAgICAgICAgICAgJ3NuaWZmaW5nJzp7J2VuYWJsZWQnOlRydWUsJ2Rlc3RPdmVy'
    'cmlkZSc6WydodHRwJywndGxzJywncXVpYyddLCdyb3V0ZU9ubHknOlRydWV9fSwKICAgICAgICAgICAgICB7J3RhZyc6J2Ru'
    'cy1pbicsJ2xpc3Rlbic6JzEyNy4wLjAuMScsJ3BvcnQnOkROU19QT1JULCdwcm90b2NvbCc6J2Rva29kZW1vLWRvb3InLCdz'
    'ZXR0aW5ncyc6eydhZGRyZXNzJzonMS4xLjEuMScsJ3BvcnQnOjUzLCduZXR3b3JrJzondGNwLHVkcCd9fSwKICAgICAgICAg'
    'ICAgICB7J3RhZyc6J2NoZWNrJywnbGlzdGVuJzonMTI3LjAuMC4xJywncG9ydCc6Q0hFQ0tfUE9SVCwncHJvdG9jb2wnOidz'
    'b2NrcycsJ3NldHRpbmdzJzp7J2F1dGgnOidub2F1dGgnLCd1ZHAnOkZhbHNlfX1dLAogICdkbnMnOnsnc2VydmVycyc6Wycx'
    'LjEuMS4xJywnOS45LjkuOSddLCdxdWVyeVN0cmF0ZWd5JzonVXNlSVB2NCcsJ3RhZyc6J2Rucy1lbmdpbmUnLCdkaXNhYmxl'
    'RmFsbGJhY2snOkZhbHNlfSwKICAnb3V0Ym91bmRzJzpbeyd0YWcnOnRhZywncHJvdG9jb2wnOidmcmVlZG9tJywnc2V0dGlu'
    'Z3MnOnsnZG9tYWluU3RyYXRlZ3knOidVc2VJUHY0J30sJ3N0cmVhbVNldHRpbmdzJzp7J3NvY2tvcHQnOnsnbWFyayc6bWFy'
    'a319fSBmb3IgdGFnLG1hcmsgaW4gWygndnBuJyxWUE4pLCgnZGlyZWN0JyxESVJFQ1QpXV0rCiAgICAgICAgICAgICAgIFt7'
    'J3RhZyc6J2RucycsJ3Byb3RvY29sJzonZG5zJywnc2V0dGluZ3MnOnsncnVsZXMnOlt7J3FUeXBlJzonMSwyOCcsJ2FjdGlv'
    'bic6J2hpamFjayd9LHsnYWN0aW9uJzonZGlyZWN0J31dfSwnc3RyZWFtU2V0dGluZ3MnOnsnc29ja29wdCc6eydtYXJrJzpW'
    'UE59fX1dLAogICdyb3V0aW5nJzp7J2RvbWFpblN0cmF0ZWd5JzonQXNJcycsJ3J1bGVzJzpydWxlc319CgpkZWYgbmZ0X3Nl'
    'dChpdGVtcyk6cmV0dXJuICd7ICcrJywgJy5qb2luKHN0cih4KSBmb3IgeCBpbiBzb3J0ZWQoaXRlbXMpKSsnIH0nCgpkZWYg'
    'ZmlyZXdhbGwocCxsYW4sdWlkKToKICMgUm91dGUgbWFya3MgYXJlIHNldCBvbmx5IGJ5IHRoaXMgcHJpdmlsZWdlZCBjbGFz'
    'c2lmaWVyIG9yIGV4cGxpY2l0IGtlcm5lbCBydWxlcy4KIG1hcms9W107ZG5zPVtdO2ZvcndhcmQ9W107bmF0PVsnbWV0YSBu'
    'ZnByb3RvIGlwdjQgbWV0YSBtYXJrICcrc3RyKERJUkVDVCkrJyBvaWZuYW1lICE9ICJsbyIgbWFzcXVlcmFkZSddCiBpZiBl'
    'bmFibGVkKHAsJ2RucycsJ3N0dWInKTpkbnMuYXBwZW5kKCdpcCBkYWRkciAxMjcuMC4wLjAvOCByZXR1cm4nKQogaWYgcFsn'
    'ZG5zJ106CiAgZG5zLmFwcGVuZChmJ2lwIGRhZGRyIHtuZnRfc2V0KHBbImRucyJdKX0gcmV0dXJuJykKICBtYXJrLmFwcGVu'
    'ZChmJ2lwIGRhZGRyIHtuZnRfc2V0KHBbImRucyJdKX0gbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUz'
    'IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKICMgSW50ZXJmYWNlLWJvdW5kIHN5c3RlbSByZXNvbHZlcnMgbXVz'
    'dCBrZWVwIEROUyBvbiB0aGUgdHVubmVsIGludGVyZmFjZS4KICMgUmVkaXJlY3RpbmcgdGhlaXIgdXBzdHJlYW0gc29ja2V0'
    'IHRvIGxvb3BiYWNrIGJyZWFrcyBTT19CSU5EVE9ERVZJQ0UuCiAjIE9ubHkgYW4gZXhwbGljaXRseSBkaXNhYmxlZCBsb29w'
    'YmFjay1zdHViIHJ1bGUgdXNlcyB0aGUgbG9jYWwgRE5TIGxpc3RlbmVyLgogZG5zKz1bJ2lwIGRhZGRyIDEyNy4wLjAuMC84'
    'IG1ldGEgbDRwcm90byB7IHRjcCwgdWRwIH0gdGggZHBvcnQgNTMgcmVkaXJlY3QgdG8gOicrc3RyKEROU19QT1JUKSwKICAg'
    'ICAgICdtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8geyB0Y3AsIHVkcCB9IHRoIGRwb3J0IDUzIGRuYXQgaXAgdG8g'
    'MS4xLjEuMSddCiBtYXJrKz1bJ21ldGEgbDRwcm90byB7IHRjcCwgdWRwIH0gdGggZHBvcnQgNTMgbWV0YSBtYXJrIHNldCAn'
    'K3N0cihWUE4pKycgcmV0dXJuJ10KIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0L3dheWRyb2lkMCcpLmV4aXN0cygpOgogIHdh'
    'eW5ldHM9bG9jYWxfbmV0d29ya3MoeydkZXYnOid3YXlkcm9pZDAnfSkKICBpZiB3YXluZXRzOm1hcmsuYXBwZW5kKGYnaXAg'
    'ZGFkZHIge25mdF9zZXQod2F5bmV0cyl9IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIG5ldHM9ZGlyZWN0X25l'
    'dHdvcmtzKHAsbGFuKQogaWYgbmV0czptYXJrLmFwcGVuZChmJ2lwIGRhZGRyIHtuZnRfc2V0KG5ldHMpfSBtZXRhIG1hcmsg'
    'c2V0IHtESVJFQ1R9IHJldHVybicpCiBpZiBlbmFibGVkKHAsJ3BvcnRzJywnZGlzY292ZXJ5Jyk6CiAgbWFyays9WydpcCBk'
    'YWRkciB7IDIyNC4wLjAuMjUxLCAyMjQuMC4wLjI1MiwgMjM5LjI1NS4yNTUuMjUwIH0gdWRwIGRwb3J0IHsgNTM1MywgNTM1'
    'NSwgMTkwMCB9IG1ldGEgbWFyayBzZXQgJytzdHIoRElSRUNUKSsnIHJldHVybiddCiBmb3IgZGlyZWN0aW9uIGluICgnb3V0'
    'JywnaW4nKToKICBmb3IgcHJvdG8sdmFsdWVzIGluIHBvcnRzKHAsZGlyZWN0aW9uKS5pdGVtcygpOgogICBpZiB2YWx1ZXM6'
    'bWFyay5hcHBlbmQoKCdjdCBkaXJlY3Rpb24gcmVwbHkgJyBpZiBkaXJlY3Rpb249PSdpbicgZWxzZSAnJykrZid7cHJvdG99'
    'IHsic3BvcnQiIGlmIGRpcmVjdGlvbj09ImluIiBlbHNlICJkcG9ydCJ9IHtuZnRfc2V0KHZhbHVlcyl9IG1ldGEgbWFyayBz'
    'ZXQge0RJUkVDVH0gcmV0dXJuJykKIGlmIHBbJ3dheWRyb2lkX2RpcmVjdCddOgogIGZvcndhcmQ9WydpaWZuYW1lICJ3YXlk'
    'cm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayBzZXQgJytzdHIoRElSRUNUKSsnIGN0IG1hcmsgc2V0ICcrc3Ry'
    'KERJUkVDVCksICdjdCBkaXJlY3Rpb24gcmVwbHkgY3QgbWFyayAnK3N0cihESVJFQ1QpKycgbWV0YSBtYXJrIHNldCAnK3N0'
    'cihESVJFQ1QpXQoKIGRlZiBsaW5lcyhpdGVtcyk6cmV0dXJuICdcbicuam9pbignICAnK3ggZm9yIHggaW4gaXRlbXMpCiBy'
    'ZXR1cm4gZicnJ3RhYmxlIGluZXQge3R1bm5lbC5GVUxMX0dVQVJEfSB7ewogY2hhaW4gcm91dGUge3sgdHlwZSByb3V0ZSBo'
    'b29rIG91dHB1dCBwcmlvcml0eSAtMTUwOyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgc2t1aWQge3VpZH0gcmV0dXJuCiAgbWV0'
    'YSBtYXJrIHNldCAwCiAgaXAgZGFkZHIgMTI3LjAuMC4wLzggcmV0dXJuCntsaW5lcyhtYXJrKX0KIH19CiBjaGFpbiBkbnMg'
    'e3sgdHlwZSBuYXQgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTEwMTsgcG9saWN5IGFjY2VwdDsKICBtZXRhIHNrdWlkIHt1aWR9'
    'IHJldHVybgp7bGluZXMoZG5zKX0KIH19CiBjaGFpbiBwcmVyb3V0ZSB7eyB0eXBlIGZpbHRlciBob29rIHByZXJvdXRpbmcg'
    'cHJpb3JpdHkgLTE1MDsgcG9saWN5IGFjY2VwdDsKe2xpbmVzKGZvcndhcmQpfQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBl'
    'IG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2'
    'NCBvaWZuYW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIHNuYXQgaXAgdG8gMTcyLjI5LjI0Ny4xCntsaW5lcyhuYXQpfQogfX0K'
    'IGNoYWluIG91dHB1dCB7eyB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9p'
    'Zm5hbWUgImxvIiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIG1hcmsge0RJUkVDVH0gYWNjZXB0CiAgbWV0YSBu'
    'ZnByb3RvIGlwdjQgbWV0YSBtYXJrIHtWUE59IG1ldGEgbDRwcm90byB7eyB0Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBvaWZu'
    'YW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgc2t1aWQge3VpZH0gbWV0'
    'YSBtYXJrIHtWUE59IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lm'
    'bmFtZSAie1RVTn0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4yNTUuMjU1LjI1NSB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3'
    'IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0zMDsgcG9s'
    'aWN5IGRyb3A7CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0'
    'dW5uZWwuU0VSVkVSfSB1ZHAgZHBvcnQge3R1bm5lbC5JS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NU'
    'fSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0dW5uZWwuU0VSVkVSfSB0Y3AgZHBvcnQgODQ0MyBhY2Nl'
    'cHQKICBvaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBkYWRkciB7dHVubmVsLkNMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNo'
    'ZWQscmVsYXRlZCBhY2NlcHQKICBpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElS'
    'RUNUfSBhY2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVk'
    'LHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie1RVTn0iIGFjY2VwdAogIG1ldGEgbmZwcm90'
    'byBpcHY0IGlpZm5hbWUgIntUVU59IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90'
    'byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAi'
    'e3R1bm5lbC5GVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKClVOSVQ9'
    'JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGxvY2FsIGFwcGxpY2F0aW9uIGFuZCBkb21haW4gcm91dGluZwpBZnRl'
    'cj1uZXR3b3JrLnRhcmdldApbU2VydmljZV0KVXNlcj12cG4teHJheQpHcm91cD12cG4teHJheQpFeGVjU3RhcnQ9L29wdC92'
    'cG4tbWFuYWdlci9iaW4veHJheSBydW4gLWNvbmZpZyAvcnVuL3Zwbi1tYW5hZ2VyL3BvbGljeS5qc29uClJlc3RhcnQ9b24t'
    'ZmFpbHVyZQpSZXN0YXJ0U2VjPTIKQW1iaWVudENhcGFiaWxpdGllcz1DQVBfTkVUX0FETUlOIENBUF9ORVRfUkFXIENBUF9T'
    'WVNfUFRSQUNFIENBUF9EQUNfUkVBRF9TRUFSQ0gKQ2FwYWJpbGl0eUJvdW5kaW5nU2V0PUNBUF9ORVRfQURNSU4gQ0FQX05F'
    'VF9SQVcgQ0FQX1NZU19QVFJBQ0UgQ0FQX0RBQ19SRUFEX1NFQVJDSApOb05ld1ByaXZpbGVnZXM9dHJ1ZQpQcm90ZWN0U3lz'
    'dGVtPXN0cmljdApQcm90ZWN0SG9tZT10cnVlClByaXZhdGVUbXA9dHJ1ZQpEZXZpY2VBbGxvdz0vZGV2L25ldC90dW4gcncK'
    'VU1hc2s9MDA3NwonJycKCmRlZiBpbnN0YWxsKCk6CiBQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtLycrU0VSVklDRSkud3Jp'
    'dGVfdGV4dChVTklUKQogdHVubmVsLmNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCgpkZWYgYXBwbHko'
    'KToKIHA9bG9hZCgpO3NldHRpbmdzPWFwaS5sb2FkX3NldHRpbmdzKCk7cm91dGU9dHVubmVsLnBoeXNpY2FsX3JvdXRlKCk7'
    'bGFuPWxvY2FsX25ldHdvcmtzKHJvdXRlKQogYXBpLmVuc3VyZV9ydW50aW1lKHNldHRpbmdzKQogY2ZnPVJVTi8ncG9saWN5'
    'Lmpzb24nO3RtcD1SVU4vJ3BvbGljeS5uZXcuanNvbicKIHRtcC53cml0ZV90ZXh0KGpzb24uZHVtcHMoY29uZmlnKHApKSk7'
    'b3MuY2htb2QodG1wLDBvNjQwKTtvcy5jaG93bih0bXAsMCxpbnQoc2V0dGluZ3NbJ3hyYXlfZ2lkJ10pKQogY2hlY2s9dHVu'
    'bmVsLmNvbW1hbmQoW2FwaS5YUkFZLCdydW4nLCctdGVzdCcsJy1jb25maWcnLHRtcF0sY2hlY2s9RmFsc2UpCiBpZiBjaGVj'
    'ay5yZXR1cm5jb2RlOnJhaXNlIFJ1bnRpbWVFcnJvcign0J7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH0LXQvdC4'
    '0Lkg0L3QtSDQv9GA0LjQvdGP0Lsg0L3QsNGB0YLRgNC+0LnQutC4LicpCiBydWxlcz1maXJld2FsbChwLGxhbixpbnQoc2V0'
    'dGluZ3NbJ3hyYXlfdWlkJ10pKQogcmVwbGFjZW1lbnQ9KCdkZWxldGUgdGFibGUgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJE'
    'KydcbicgaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKIHR1bm5lbC5jb21tYW5kKFsnbmZ0'
    'JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogb3duZXJzaGlwPVBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0'
    'd29yay5qc29uJykKIGlmIG5vdCBvd25lcnNoaXAuZXhpc3RzKCk6CiAgZm9yIHRhYmxlIGluIChQSFlTSUNBTF9UQUJMRSxW'
    'UE5fVEFCTEUpOgogICBpZiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLHRhYmxlXSxjaGVj'
    'az1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6cmFpc2UgUnVudGltZUVycm9yKCfQotCw0LHQu9C40YbQsCDQvNCw0YDRiNGA0YPR'
    'gtC40LfQsNGG0LjQuCDQuNGB0LrQu9GO0YfQtdC90LjQuSDQt9Cw0L3Rj9GC0LAg0LTRgNGD0LPQvtC5INC/0YDQvtCz0YDQ'
    'sNC80LzQvtC5LicpCiAgZXhpc3Rpbmc9anNvbi5sb2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUn'
    'XSkuc3Rkb3V0KQogIGlmIGFueShyLmdldCgncHJpb3JpdHknKSBpbiAoNzYsNzcsNzgpIGZvciByIGluIGV4aXN0aW5nKTpy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ9Cf0YDQuNC+0YDQuNGC0LXRgtGLINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4INC40YHQ'
    'utC70Y7Rh9C10L3QuNC5INC30LDQvdGP0YLRiyDQtNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykKICB0dW5u'
    'ZWwud3JpdGUob3duZXJzaGlwLGpzb24uZHVtcHMoeyd0YWJsZXMnOltQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEVdfSkpCiAj'
    'IEJ1aWxkIHBoeXNpY2FsIGFuZCBWUE4tb25seSB0YWJsZXMgYmVmb3JlIGFsbG93aW5nIGFueSBuZXcgbWFya3MuCiBmb3Ig'
    'dGFibGUgaW4gKFBIWVNJQ0FMX1RBQkxFLFZQTl9UQUJMRSk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVw'
    'bGFjZScsJ3VucmVhY2hhYmxlJywnZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLHRhYmxlXSkKIGZvciBuZXR3'
    'b3JrIGluIGxhbitbJzE2OS4yNTQuMC4wLzE2JywnMjI0LjAuMC4wLzQnXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91'
    'dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLHJvdXRlWydkZXYnXSwnc2NvcGUnLCdsaW5rJywndGFibGUnLFBIWVNJQ0FM'
    'X1RBQkxFXSkKIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJyxyb3V0ZVsn'
    'Z2F0ZXdheSddLCdkZXYnLHJvdXRlWydkZXYnXSwnbWV0cmljJywnMTAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogdHVu'
    'bmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYn'
    'LHR1bm5lbC5GVUxMX0hPU1QsJ21ldHJpYycsJzEwJywndGFibGUnLFZQTl9UQUJMRV0pCiBmb3IgcHJpb3JpdHksbWFyayx0'
    'YWJsZSBpbiBbKDc2LERJUkVDVCxQSFlTSUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICB0dW5uZWwuY29tbWFu'
    'ZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFi'
    'bGVdLGNoZWNrPUZhbHNlKQogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLHByaW9yaXR5'
    'LCdmd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0pCiAjIFJlcGxpZXMgdG8gYSBmb3J3YXJkZWQgY29udGFpbmVy'
    'IHJldHVybiB0aHJvdWdoIGl0cyBjb25uZWN0ZWQgbWFpbiByb3V0ZS4KIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywn'
    'ZGVsJywncHJpb3JpdHknLCc3OCcsJ2lpZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiB0dW5uZWwuY29t'
    'bWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbiddKQogaWYg'
    'UGF0aCgnL3N5cy9jbGFzcy9uZXQvd2F5ZHJvaWQwJykuZXhpc3RzKCk6CiAgZm9yIG5ldCBpbiBsb2NhbF9uZXR3b3Jrcyh7'
    'J2Rldic6J3dheWRyb2lkMCd9KToKICAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsbmV0LCdkZXYn'
    'LCd3YXlkcm9pZDAnLCdzY29wZScsJ2xpbmsnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogICMgUmVzdG9yZSBkaXJlY3Qg'
    'Y29ubnRyYWNrIHJlcGxpZXMgdG8gdGhlIHBoeXNpY2FsIHJvdXRpbmcgdGFibGUgYXMgd2VsbC4KICMgQSB0ZW1wb3Jhcnkg'
    'Y2xvc2VkIHN0YXRlIGlzIGFjY2VwdGFibGU7IGFuIHVuZ3VhcmRlZCBzdGF0ZSBpcyBub3QuCiBvcy5yZXBsYWNlKHRtcCxj'
    'ZmcpCiB0dW5uZWwud3JpdGUodHVubmVsLlJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKIHR1bm5lbC5jb21tYW5kKFsn'
    'bmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKIGluc3RhbGwoKQogdHVubmVsLmNvbW1hbmQoWydzeXN0ZW1jdGwn'
    'LCdyZXN0YXJ0JyxTRVJWSUNFXSkKIGZvciBfIGluIHJhbmdlKDgwKToKICBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK1RV'
    'TikuZXhpc3RzKCk6YnJlYWsKICB0aW1lLnNsZWVwKC4xKQogZWxzZTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LUg0YPQtNCw'
    '0LvQvtGB0Ywg0LfQsNC/0YPRgdGC0LjRgtGMINC+0LHRgNCw0LHQvtGC0YfQuNC6INC40YHQutC70Y7Rh9C10L3QuNC5Licp'
    'CiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ2RldicsVFVOLCdtZXRyaWMnLCcx'
    'MCcsJ3RhYmxlJyx0dW5uZWwuRlVMTF9UQUJMRV0pCiB0dW5uZWwuY2xlYXJfZG5zX21hcHBpbmdzKCkKICMgRXhwbGljaXRs'
    'eSByZXF1ZXN0ZWQgRE5TIGV4Y2VwdGlvbnMgbmVlZCBzdGFsZSBwb3J0LTUzIG1hcHBpbmdzIHJlbW92ZWQgdG9vLgogZm9y'
    'IHByb3RvIGluICgndWRwJywndGNwJyk6CiAgdHVubmVsLmNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcs'
    'Jy1wJyxwcm90bywnLS1kcG9ydCcsJzUzJywnLS1yZXBseS1wb3J0LXNyYycsc3RyKEROU19QT1JUKV0sY2hlY2s9RmFsc2Up'
    'CgoKZGVmIHN0b3AocmVsZWFzZT1GYWxzZSk6CiB0dW5uZWwuY29tbWFuZChbJ3N5c3RlbWN0bCcsJ3N0b3AnLFNFUlZJQ0Vd'
    'LGNoZWNrPUZhbHNlKQogaWYgcmVsZWFzZSBhbmQgUEFUSC53aXRoX25hbWUoJ3BvbGljeS1uZXR3b3JrLmpzb24nKS5leGlz'
    'dHMoKToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9v'
    'a3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogIGZvciBwcmlvcml0eSxtYXJrLHRhYmxlIGluIFsoNzYsRElSRUNULFBIWVNJ'
    'Q0FMX1RBQkxFKSwoNzcsVlBOLFZQTl9UQUJMRSldOgogICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3By'
    'aW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogICB0dW5u'
    'ZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdmbHVzaCcsJ3RhYmxlJyx0YWJsZV0sY2hlY2s9RmFsc2UpCiAgUEFUSC53aXRo'
    'X25hbWUoJ3BvbGljeS1uZXR3b3JrLmpzb24nKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQoKCmRlZiBjaGFuZ2UoYWN0aW9u'
    'LGNhdGVnb3J5PScnLHZhbHVlPScnLHN0YXRlPU5vbmUpOgogb2xkPWxvYWQoKTtwPWpzb24ubG9hZHMoanNvbi5kdW1wcyhv'
    'bGQpKQogaWYgYWN0aW9uPT0nd2F5ZHJvaWQnOnBbJ3dheWRyb2lkX2RpcmVjdCddPWJvb2woc3RhdGUpCiBlbGlmIGFjdGlv'
    'bj09J2Jhc2UnOgogIGlmIGNhdGVnb3J5IG5vdCBpbiBCQVNFIG9yIHZhbHVlIG5vdCBpbiB7ZVsnaWQnXSBmb3IgZSBpbiBC'
    'QVNFW2NhdGVnb3J5XX06cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC90L7QtSDQsdCw0LfQvtCy0L7QtSDQ'
    'v9GA0LDQstC40LvQvi4nKQogIGtleT1jYXRlZ29yeSsnOicrdmFsdWUKICBwWydkaXNhYmxlZF9iYXNlJ109W3ggZm9yIHgg'
    'aW4gcFsnZGlzYWJsZWRfYmFzZSddIGlmIHghPWtleV0KICBpZiBub3Qgc3RhdGU6cFsnZGlzYWJsZWRfYmFzZSddLmFwcGVu'
    'ZChrZXkpCiBlbGlmIGFjdGlvbiBpbiAoJ2FkZCcsJ3JlbW92ZScpOgogIGlmIGNhdGVnb3J5IG5vdCBpbiBDQVRFR09SSUVT'
    'OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdCw0Y8g0LrQsNGC0LXQs9C+0YDQuNGPLicpCiAgdmFsdWU9'
    'bm9ybWFsaXplKGNhdGVnb3J5LHZhbHVlKQogIGlmIGFjdGlvbj09J2FkZCcgYW5kIHZhbHVlIG5vdCBpbiBwW2NhdGVnb3J5'
    'XTpwW2NhdGVnb3J5XS5hcHBlbmQodmFsdWUpCiAgaWYgYWN0aW9uPT0ncmVtb3ZlJzpwW2NhdGVnb3J5XT1beCBmb3IgeCBp'
    'biBwW2NhdGVnb3J5XSBpZiB4IT12YWx1ZV0KIGVsc2U6cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC90L7Q'
    'tSDQtNC10LnRgdGC0LLQuNC1LicpCiBpZiBwPT1vbGQ6cmV0dXJuIHB1YmxpYygpCiBzYXZlKHApCiBpZiB0dW5uZWwuZnVs'
    'bF9ndWFyZF9hY3RpdmUoKSBhbmQgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJyt0dW5uZWwuRlVMTF9IT1NUKS5leGlzdHMoKToK'
    'ICB0cnk6YXBwbHkoKQogIGV4Y2VwdCBFeGNlcHRpb246CiAgIHNhdmUob2xkKQogICB0cnk6YXBwbHkoKQogICBleGNlcHQg'
    'RXhjZXB0aW9uOnBhc3MKICAgcmFpc2UKIHJldHVybiBwdWJsaWMoKQoKZGVmIGVuc3VyZV9yb3V0ZSgpOgogaWYgUGF0aCgn'
    'L3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2Un'
    'LCdkZWZhdWx0JywnZGV2JyxUVU4sJ21ldHJpYycsJzEwJywndGFibGUnLHR1bm5lbC5GVUxMX1RBQkxFXSkKIGVsc2U6cmFp'
    'c2UgUnVudGltZUVycm9yKCdwb2xpY3lfZW5naW5lX3VuYXZhaWxhYmxlJykK'
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
 return args.cmd not in (None,'status','version','logs','rules','watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-starfive-pause-main') and not (args.cmd=='ui' and args.ui_cmd in ('state','running'))

def self_test():
 assert MANAGER_VERSION=='0.4.1'
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
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-starfive-pause-main','manager-rollback'):sub.add_parser(name)
 pst=sub.add_parser('status',help='Состояние, защита и исключения');pst.add_argument('--json',action='store_true');pst.add_argument('--ip',action='store_true',help='Проверить внешний IP именно через VPN')
 device=sub.add_parser('device',help='Имя устройства в веб-панели');device.add_argument('operation',choices=['show','name','sync']);device.add_argument('name',nargs='?')
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
  if cmd=='internal-starfive-tunnel':starfive_tunnel.worker()
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
