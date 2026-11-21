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
import stat

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

MANAGER_VERSION = "0.5.12"

SAFE_XRAY_VERSION = "26.7.28"

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")

STATE = pathlib.Path("/var/lib/vpn-manager/state.json")

RUNTIME_DIR = pathlib.Path("/run/vpn-manager")

RUNTIME_CONFIG = RUNTIME_DIR / "policy.json"

XRAY = pathlib.Path("/opt/vpn-manager/bin/xray")

XRAY_PREVIOUS = pathlib.Path("/opt/vpn-manager/bin/xray.previous")

SERVICE = "evgenium-policy.service"

PLASMOID_ID = "com.evgenium.network"

APP_ICON_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><title>Evgenium Network</title><rect x="8" y="8" width="496" height="496" rx="96" fill="#19151c"/><g transform="translate(80 64) scale(3.2)" color="#ff586d"><g><path d="M10 6 C-4 17 1 29 12 38 C4 52 13 63 22 70 C17 82 28 98 34 112 C37 95 44 82 37 68 C48 55 49 46 41 36 C58 13 40 -4 10 6 Z" fill="#702a40"/><path d="M44 7 C10 -4 -8 12 8 27 C15 34 32 38 41 43 L46 31 C33 24 13 22 12 15 C18 9 31 8 44 7 Z" fill="currentColor"/><path d="M5 26 C-3 44 13 53 34 59 C38 61 40 64 41 67 L45 53 C31 44 10 42 11 34 Z" fill="currentColor"/><path d="M12 51 C8 67 21 77 33 80 L38 90 L41 75 C30 66 19 63 18 58 Z" fill="currentColor"/><path d="M22 76 C20 89 31 101 34 112 L39 93 C31 88 29 83 29 81 Z" fill="currentColor"/><path d="M39 8 C21 3 4 11 8 20 M7 34 C7 43 23 48 34 52 M16 60 C17 67 27 71 33 73" fill="none" stroke="#ffacb8" stroke-width="1.2" stroke-linecap="round"/></g><g transform="translate(110 0) scale(-1 1)"><path d="M10 6 C-4 17 1 29 12 38 C4 52 13 63 22 70 C17 82 28 98 34 112 C37 95 44 82 37 68 C48 55 49 46 41 36 C58 13 40 -4 10 6 Z" fill="#702a40"/><path d="M44 7 C10 -4 -8 12 8 27 C15 34 32 38 41 43 L46 31 C33 24 13 22 12 15 C18 9 31 8 44 7 Z" fill="currentColor"/><path d="M5 26 C-3 44 13 53 34 59 C38 61 40 64 41 67 L45 53 C31 44 10 42 11 34 Z" fill="currentColor"/><path d="M12 51 C8 67 21 77 33 80 L38 90 L41 75 C30 66 19 63 18 58 Z" fill="currentColor"/><path d="M22 76 C20 89 31 101 34 112 L39 93 C31 88 29 83 29 81 Z" fill="currentColor"/><path d="M39 8 C21 3 4 11 8 20 M7 34 C7 43 23 48 34 52 M16 60 C17 67 27 71 33 73" fill="none" stroke="#ffacb8" stroke-width="1.2" stroke-linecap="round"/></g></g></svg>'''

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
    'aXRsZTogIkV2Z2VuaXVtIE5ldHdvcmsiCiAgICBjb2xvcjogIiMxNDEyMTciCiAgICBmbGFnczogUXQuV2luZG93IHwgUXQu'
    'RnJhbWVsZXNzV2luZG93SGludCB8IFF0LldpbmRvd1N5c3RlbU1lbnVIaW50IHwgUXQuV2luZG93TWluaW1pemVCdXR0b25I'
    'aW50CgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYmc6ICIjMTQxMjE3IgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29s'
    'b3Igc3VyZmFjZTogIiMyMTFjMjQiCiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciBzaWRlYmFyOiAiIzE5MTUxYyIKICAg'
    'IHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIHNpZGViYXJIb3ZlcjogIiMyYjIwMmEiCiAgICByZWFkb25seSBwcm9wZXJ0eSBj'
    'b2xvciBhY2NlbnQ6ICIjZmY1ODZkIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYWNjZW50U29mdDogIiMzYTIwMmQi'
    'CiAgICByZWFkb25seSBwcm9wZXJ0eSBjb2xvciB0ZXh0TWFpbjogIiNmZmYxZTkiCiAgICByZWFkb25seSBwcm9wZXJ0eSBj'
    'b2xvciB0ZXh0TXV0ZWQ6ICIjYmFhOGFmIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3IgYm9yZGVyOiAiIzQ4MzAzYyIK'
    'ICAgIHJlYWRvbmx5IHByb3BlcnR5IGNvbG9yIGdvb2Q6ICIjYTZkOGMyIgogICAgcmVhZG9ubHkgcHJvcGVydHkgY29sb3Ig'
    'YmFkOiAiI2ZmYWQ5ZSIKCiAgICBmb250LmZhbWlseTogIk5vdG8gU2FucyIKICAgIHBhbGV0dGUud2luZG93OiBiZwogICAg'
    'cGFsZXR0ZS53aW5kb3dUZXh0OiB0ZXh0TWFpbgogICAgcGFsZXR0ZS5iYXNlOiAiIzE4MTMxYiIKICAgIHBhbGV0dGUuYWx0'
    'ZXJuYXRlQmFzZTogc3VyZmFjZQogICAgcGFsZXR0ZS50ZXh0OiB0ZXh0TWFpbgogICAgcGFsZXR0ZS5idXR0b246ICIjMjky'
    'MDJiIgogICAgcGFsZXR0ZS5idXR0b25UZXh0OiB0ZXh0TWFpbgogICAgcGFsZXR0ZS5oaWdobGlnaHQ6IGFjY2VudAogICAg'
    'cGFsZXR0ZS5oaWdobGlnaHRlZFRleHQ6ICIjMTgwZDEzIgogICAgcGFsZXR0ZS5wbGFjZWhvbGRlclRleHQ6IHRleHRNdXRl'
    'ZAogICAgcGFsZXR0ZS5taWQ6IGJvcmRlcgogICAgcGFsZXR0ZS5saWdodDogYm9yZGVyCiAgICBwYWxldHRlLmRhcms6IHRl'
    'eHRNdXRlZAoKICAgIHByb3BlcnR5IHN0cmluZyByZXBvcnRUZXh0OiAiIgogICAgcHJvcGVydHkgc3RyaW5nIHJlcG9ydElk'
    'OiAiIgogICAgcHJvcGVydHkgaW50IHBhZ2VJbmRleDogMAogICAgcHJvcGVydHkgYm9vbCBidXN5OiBmYWxzZQogICAgcHJv'
    'cGVydHkgc3RyaW5nIGVycm9yVGV4dDogIiIKICAgIHByb3BlcnR5IHN0cmluZyBwb2xsRXJyb3JUZXh0OiAiIgogICAgcHJv'
    'cGVydHkgdmFyIHN0YXRlOiAoe30pCiAgICBwcm9wZXJ0eSB2YXIgcnVubmluZ0FwcHM6IFtdCiAgICBwcm9wZXJ0eSBib29s'
    'IHRva2VuRWRpdGluZzogZmFsc2UKICAgIHByb3BlcnR5IGJvb2wgZGV2aWNlRWRpdGluZzogZmFsc2UKICAgIHJlYWRvbmx5'
    'IHByb3BlcnR5IGJvb2wgdG9rZW5TYXZlZDogQm9vbGVhbihyb290LnR1bm5lbC5oYXNfdG9rZW4pCiAgICByZWFkb25seSBw'
    'cm9wZXJ0eSBib29sIHRva2VuTG9ja2VkOiB0b2tlblNhdmVkICYmICF0b2tlbkVkaXRpbmcKICAgIHJlYWRvbmx5IHByb3Bl'
    'cnR5IHZhciB0dW5uZWw6IHJvb3Quc3RhdGUudHVubmVsIHx8ICh7fSkKICAgIHJlYWRvbmx5IHByb3BlcnR5IHZhciBwb2xp'
    'Y3k6IHJvb3Quc3RhdGUucG9saWN5IHx8ICh7fSkKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBjYXRlZ29yeTogWyIi'
    'LCAiYXBwbGljYXRpb25zIiwgIm5ldHdvcmtzIiwgInBvcnRzIiwgImRucyIsICIiXVtwYWdlSW5kZXhdCiAgICBwcm9wZXJ0'
    'eSBib29sIHNob3dCYXNlOiBmYWxzZQoKICAgIHJlYWRvbmx5IHByb3BlcnR5IHZhciBhcmdzOiBRdC5hcHBsaWNhdGlvbi5h'
    'cmd1bWVudHMKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBhcGlUb2tlbjogYXJncy5sZW5ndGggPj0gMiA/IFN0cmlu'
    'ZyhhcmdzW2FyZ3MubGVuZ3RoIC0gMV0pIDogIiIKICAgIHJlYWRvbmx5IHByb3BlcnR5IHN0cmluZyBhcGlQb3J0OiBhcmdz'
    'Lmxlbmd0aCA+PSAzID8gU3RyaW5nKGFyZ3NbYXJncy5sZW5ndGggLSAyXSkgOiAiMCIKICAgIHJlYWRvbmx5IHByb3BlcnR5'
    'IHN0cmluZyBhcGlCYXNlOiAiaHR0cDovLzEyNy4wLjAuMToiICsgYXBpUG9ydAoKICAgIHByb3BlcnR5IGJvb2wgc3RhdGVQ'
    'ZW5kaW5nOiBmYWxzZQogICAgcHJvcGVydHkgYm9vbCBydW5uaW5nUGVuZGluZzogZmFsc2UKCiAgICBmdW5jdGlvbiBhcGko'
    'bWV0aG9kLCBwYXRoLCBib2R5LCBjYWxsYmFjaywgb3BlcmF0aW9uKSB7CiAgICAgICAgY29uc3QgeGhyID0gbmV3IFhNTEh0'
    'dHBSZXF1ZXN0KCkKICAgICAgICBsZXQgZmluaXNoZWQgPSBmYWxzZQogICAgICAgIGNvbnN0IHRpbWVyID0gcmVxdWVzdFRp'
    'bWVyLmNyZWF0ZU9iamVjdChyb290KQogICAgICAgIGZ1bmN0aW9uIGZpbmlzaChlcnJvciwgcGF5bG9hZCkgewogICAgICAg'
    'ICAgICBpZiAoZmluaXNoZWQpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgZmluaXNoZWQgPSB0cnVlCiAg'
    'ICAgICAgICAgIHRpbWVyLnN0b3AoKQogICAgICAgICAgICB0aW1lci5kZXN0cm95KCkKICAgICAgICAgICAgaWYgKHBhdGgg'
    'PT09ICIvYXBpL3N0YXRlIikgcm9vdC5zdGF0ZVBlbmRpbmcgPSBmYWxzZQogICAgICAgICAgICBpZiAocGF0aCA9PT0gIi9h'
    'cGkvcnVubmluZyIpIHJvb3QucnVubmluZ1BlbmRpbmcgPSBmYWxzZQogICAgICAgICAgICBpZiAob3BlcmF0aW9uKSB7CiAg'
    'ICAgICAgICAgICAgICByb290LmJ1c3kgPSBmYWxzZQogICAgICAgICAgICAgICAgcm9vdC5lcnJvclRleHQgPSBlcnJvciB8'
    'fCAiIgogICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgcm9vdC5wb2xsRXJyb3JUZXh0ID0gZXJyb3IgfHwg'
    'IiIKICAgICAgICAgICAgfQogICAgICAgICAgICBpZiAoIWVycm9yICYmIGNhbGxiYWNrKSBjYWxsYmFjayhwYXlsb2FkKQog'
    'ICAgICAgIH0KICAgICAgICB0aW1lci5pbnRlcnZhbCA9IG9wZXJhdGlvbiA/IDc4MDAwMCA6IDEyMDAwCiAgICAgICAgdGlt'
    'ZXIudHJpZ2dlcmVkLmNvbm5lY3QoZnVuY3Rpb24oKSB7CiAgICAgICAgICAgIGZpbmlzaChvcGVyYXRpb24gPyAi0J7RgtCy'
    '0LXRgiDQvtC/0LXRgNCw0YbQuNC4INC90LUg0L/QvtC70YPRh9C10L0uINCf0YDQvtCy0LXRgNGMIHZwbiBzdGF0dXMg0L/Q'
    'tdGA0LXQtCDQv9C+0LLRgtC+0YDQvdGL0Lwg0L/QtdGA0LXQutC70Y7Rh9C10L3QuNC10LwuIiA6ICLQntC/0YDQvtGBINGB'
    '0L7RgdGC0L7Rj9C90LjRjyDQvdC1INC30LDQstC10YDRiNC40LvRgdGPIiwgbnVsbCkKICAgICAgICAgICAgeGhyLmFib3J0'
    'KCkKICAgICAgICB9KQogICAgICAgIHhoci5vcGVuKG1ldGhvZCwgYXBpQmFzZSArIHBhdGgsIHRydWUpCiAgICAgICAgeGhy'
    'LnNldFJlcXVlc3RIZWFkZXIoIlgtRXZnZW5pdW0tVG9rZW4iLCBhcGlUb2tlbikKICAgICAgICBpZiAoYm9keSAhPT0gbnVs'
    'bCkKICAgICAgICAgICAgeGhyLnNldFJlcXVlc3RIZWFkZXIoIkNvbnRlbnQtVHlwZSIsICJhcHBsaWNhdGlvbi9qc29uOyBj'
    'aGFyc2V0PXV0Zi04IikKICAgICAgICB4aHIub25yZWFkeXN0YXRlY2hhbmdlID0gZnVuY3Rpb24oKSB7CiAgICAgICAgICAg'
    'IGlmICh4aHIucmVhZHlTdGF0ZSAhPT0gWE1MSHR0cFJlcXVlc3QuRE9ORSB8fCBmaW5pc2hlZCkKICAgICAgICAgICAgICAg'
    'IHJldHVybgogICAgICAgICAgICBsZXQgcGF5bG9hZCA9IG51bGwKICAgICAgICAgICAgdHJ5IHsgcGF5bG9hZCA9IEpTT04u'
    'cGFyc2UoU3RyaW5nKHhoci5yZXNwb25zZVRleHQgfHwgInt9IikpIH0KICAgICAgICAgICAgY2F0Y2ggKGUpIHsgZmluaXNo'
    'KCLQndC1INGD0LTQsNC70L7RgdGMINGA0LDQt9C+0LHRgNCw0YLRjCDQvtGC0LLQtdGCINC70L7QutCw0LvRjNC90L7Qs9C+'
    'IEFQSSIsIG51bGwpOyByZXR1cm4gfQogICAgICAgICAgICBpZiAoeGhyLnN0YXR1cyA8IDIwMCB8fCB4aHIuc3RhdHVzID49'
    'IDMwMCB8fCAhcGF5bG9hZC5vaykgewogICAgICAgICAgICAgICAgZmluaXNoKFN0cmluZyhwYXlsb2FkLmVycm9yIHx8ICgi'
    'SFRUUCAiICsgeGhyLnN0YXR1cykpLCBudWxsKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIH0KICAgICAg'
    'ICAgICAgZmluaXNoKG51bGwsIHBheWxvYWQpCiAgICAgICAgfQogICAgICAgIHRpbWVyLnN0YXJ0KCkKICAgICAgICB4aHIu'
    'c2VuZChib2R5ID09PSBudWxsID8gbnVsbCA6IEpTT04uc3RyaW5naWZ5KGJvZHkpKQogICAgfQoKICAgIENvbXBvbmVudCB7'
    'CiAgICAgICAgaWQ6IHJlcXVlc3RUaW1lcgogICAgICAgIFRpbWVyIHsgcmVwZWF0OiBmYWxzZSB9CiAgICB9CgogICAgZnVu'
    'Y3Rpb24gcmVmcmVzaFN0YXRlKCkgewogICAgICAgIGlmIChzdGF0ZVBlbmRpbmcpIHJldHVybgogICAgICAgIHN0YXRlUGVu'
    'ZGluZyA9IHRydWUKICAgICAgICBhcGkoIkdFVCIsICIvYXBpL3N0YXRlIiwgbnVsbCwgZnVuY3Rpb24ocGF5bG9hZCkgewog'
    'ICAgICAgICAgICByb290LnN0YXRlID0gcGF5bG9hZC5zdGF0ZSB8fCAoe30pCiAgICAgICAgfSkKICAgIH0KCiAgICBmdW5j'
    'dGlvbiByZWZyZXNoUnVubmluZygpIHsKICAgICAgICBpZiAocnVubmluZ1BlbmRpbmcpIHJldHVybgogICAgICAgIHJ1bm5p'
    'bmdQZW5kaW5nID0gdHJ1ZQogICAgICAgIGFwaSgiR0VUIiwgIi9hcGkvcnVubmluZyIsIG51bGwsIGZ1bmN0aW9uKHBheWxv'
    'YWQpIHsKICAgICAgICAgICAgcm9vdC5ydW5uaW5nQXBwcyA9IChwYXlsb2FkLnJ1bm5pbmcgJiYgcGF5bG9hZC5ydW5uaW5n'
    'LmFwcGxpY2F0aW9ucykgfHwgW10KICAgICAgICB9KQogICAgfQoKICAgIGZ1bmN0aW9uIGFjdGlvbihwYXlsb2FkLCBvblN1'
    'Y2Nlc3MpIHsKICAgICAgICBpZiAoYnVzeSB8fCAoQm9vbGVhbihzdGF0ZS5jb25uZWN0aW5nKSAmJiBwYXlsb2FkLmFjdGlv'
    'biAhPT0gImRpc2Nvbm5lY3QiKSkKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgYnVzeSA9IHRydWUKICAgICAgICBhcGko'
    'IlBPU1QiLCAiL2FwaS9hY3Rpb24iLCBwYXlsb2FkLCBmdW5jdGlvbihfcmVwbHkpIHsKICAgICAgICAgICAgcm9vdC5idXN5'
    'ID0gZmFsc2UKICAgICAgICAgICAgaWYgKF9yZXBseS5zdGF0ZSkgcm9vdC5zdGF0ZSA9IF9yZXBseS5zdGF0ZQogICAgICAg'
    'ICAgICBpZiAob25TdWNjZXNzKSBvblN1Y2Nlc3MoX3JlcGx5KQogICAgICAgICAgICByb290LnJlZnJlc2hTdGF0ZSgpCiAg'
    'ICAgICAgICAgIHJvb3QucmVmcmVzaFJ1bm5pbmcoKQogICAgICAgIH0sIHRydWUpCiAgICB9CgogICAgZnVuY3Rpb24gdG9n'
    'Z2xlVnBuKCkgewogICAgICAgIGlmIChidXN5IHx8IEJvb2xlYW4oc3RhdGUuY29ubmVjdGluZykpCiAgICAgICAgICAgIHJl'
    'dHVybgogICAgICAgIGJ1c3kgPSB0cnVlCiAgICAgICAgYXBpKCJQT1NUIiwgIi9hcGkvdG9nZ2xlIiwge30sIGZ1bmN0aW9u'
    'KHBheWxvYWQpIHsKICAgICAgICAgICAgcm9vdC5idXN5ID0gZmFsc2UKICAgICAgICAgICAgcm9vdC5zdGF0ZSA9IHBheWxv'
    'YWQuc3RhdGUgfHwgKHt9KQogICAgICAgIH0sIHRydWUpCiAgICB9CgogICAgZnVuY3Rpb24gZmlsdGVyZWRSdW5uaW5nKCkg'
    'ewogICAgICAgIGNvbnN0IG5lZWRsZSA9IGFwcFNlYXJjaC50ZXh0LnRyaW0oKS50b0xvd2VyQ2FzZSgpCiAgICAgICAgaWYg'
    'KCFuZWVkbGUubGVuZ3RoKQogICAgICAgICAgICByZXR1cm4gcnVubmluZ0FwcHMKICAgICAgICByZXR1cm4gcnVubmluZ0Fw'
    'cHMuZmlsdGVyKGZ1bmN0aW9uKGFwcCkgewogICAgICAgICAgICByZXR1cm4gU3RyaW5nKGFwcC5uYW1lIHx8ICIiKS50b0xv'
    'd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICAgICAgICAgIHx8IFN0cmluZyhhcHAuZXhlIHx8ICIiKS50b0xv'
    'd2VyQ2FzZSgpLmluY2x1ZGVzKG5lZWRsZSkKICAgICAgICB9KQogICAgfQoKICAgIENvbXBvbmVudC5vbkNvbXBsZXRlZDog'
    'ewogICAgICAgIHJlZnJlc2hTdGF0ZSgpCiAgICAgICAgcmVmcmVzaFJ1bm5pbmcoKQogICAgfQoKICAgIFRpbWVyIHsKICAg'
    'ICAgICBpbnRlcnZhbDogMjUwMAogICAgICAgIHJlcGVhdDogdHJ1ZQogICAgICAgIHJ1bm5pbmc6IHRydWUKICAgICAgICBv'
    'blRyaWdnZXJlZDogcm9vdC5yZWZyZXNoU3RhdGUoKQogICAgfQoKICAgIEMuRGlhbG9nIHsKICAgICAgICBpZDogc3VwcG9y'
    'dERpYWxvZwogICAgICAgIHRpdGxlOiAi0J7RgtGH0ZHRgiDQtNC70Y8g0L/QvtC00LTQtdGA0LbQutC4IgogICAgICAgIG1v'
    'ZGFsOiB0cnVlCiAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgd2lkdGg6IE1hdGgubWluKHJvb3Qu'
    'd2lkdGgtNjAsNzYwKQogICAgICAgIGhlaWdodDogTWF0aC5taW4ocm9vdC5oZWlnaHQtNTAsNjIwKQogICAgICAgIENvbHVt'
    'bkxheW91dCB7CiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAgIHNwYWNpbmc6IDEyCiAgICAg'
    'ICAgICAgIEMuTGFiZWwgeyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyB0ZXh0OiAi0JLQ'
    'tdGA0YHQuNGPLCDRjdGC0LDQv9GLINC/0L7QtNC60LvRjtGH0LXQvdC40Y8sINC+0YjQuNCx0LrQuCDQuCDQt9Cw0LzQtdGA'
    '0YsuINCR0LXQtyDRgtC+0LrQtdC90L7Qsiwg0LrQu9GO0YfQtdC5LCDQuNGB0YLQvtGA0LjQuCDRgdCw0LnRgtC+0LIg0Lgg'
    '0YHQv9C40YHQutCwINC/0YDQuNC70L7QttC10L3QuNC5LiDQntGC0L/RgNCw0LLQutCwINC00L7QsdGA0L7QstC+0LvRjNC9'
    '0LDRjzsg0YHQtdGA0LLQtdGAINGF0YDQsNC90LjRgiDQvtGC0YfRkdGCINC00L4gNyDQtNC90LXQuS4iIH0KICAgICAgICAg'
    'ICAgQy5TY3JvbGxWaWV3IHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgTGF5b3V0LmZpbGxIZWlnaHQ6IHRydWUKICAgICAg'
    'ICAgICAgICAgIEMuVGV4dEFyZWEgeyB0ZXh0OiByb290LnJlcG9ydFRleHQ7IHJlYWRPbmx5OiB0cnVlOyBzZWxlY3RCeU1v'
    'dXNlOiB0cnVlOyB3cmFwTW9kZTogVGV4dEVkaXQuV3JhcDsgZm9udC5mYW1pbHk6ICJtb25vc3BhY2UiOyBmb250LnBpeGVs'
    'U2l6ZTogMTEgfQogICAgICAgICAgICB9CiAgICAgICAgICAgIEMuQ2hlY2tCb3ggeyBpZDogcmVwb3J0Q29uc2VudDsgdGV4'
    'dDogItCg0LDQt9GA0LXRiNCw0Y4g0L7RgtC/0YDQsNCy0LjRgtGMINC/0L7QutCw0LfQsNC90L3Ri9C5INC+0YLRh9GR0YIg'
    '0LLQu9Cw0LTQtdC70YzRhtGDIFZQTiIgfQogICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgRmxhdEJ1'
    'dHRvbiB7IGxhYmVsOiAi0J7RgtC/0YDQsNCy0LjRgtGMIjsgcHJpbWFyeTogdHJ1ZTsgZW5hYmxlZEJ1dHRvbjogcmVwb3J0'
    'Q29uc2VudC5jaGVja2VkICYmICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjoicmVwb3J0LXNl'
    'bmQiLHJlcG9ydF9pZDpyb290LnJlcG9ydElkLGNvbnNlbnQ6dHJ1ZX0sZnVuY3Rpb24oKXtzdXBwb3J0RGlhbG9nLmNsb3Nl'
    'KCk7cm9vdC5lcnJvclRleHQ9ItCe0YLRh9GR0YIg0L7RgtC/0YDQsNCy0LvQtdC9LiBJRDogIityb290LnJlcG9ydElkfSkg'
    'fQogICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0JfQsNC60YDRi9GC0YwiOyBvbkNsaWNrZWQ6IHN1cHBv'
    'cnREaWFsb2cuY2xvc2UoKSB9CiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5MYWJlbCB7IHZpc2libGU6ICFyb290LnN0'
    'YXRlLmFjdGl2ZTsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgdGV4dDogItCV0YHQu9C4'
    'INC30LDRidC40YLQsCDQsdC70L7QutC40YDRg9C10YIg0YHQtdGC0YwsINC+0YLRh9GR0YIg0L7RgdGC0LDQvdC10YLRgdGP'
    'INC70L7QutCw0LvRjNC90L4g0LTQviDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNGPINC40LvQuCDRj9Cy0L3QvtCz0L4g'
    '0L7RgtC60LvRjtGH0LXQvdC40Y8gVlBOLiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgfQogICAgfQoKICAg'
    'IGNvbXBvbmVudCBGbGF0QnV0dG9uOiBSZWN0YW5nbGUgewogICAgICAgIGlkOiBmbGF0QnV0dG9uCiAgICAgICAgcmVxdWly'
    'ZWQgcHJvcGVydHkgc3RyaW5nIGxhYmVsCiAgICAgICAgcHJvcGVydHkgYm9vbCBwcmltYXJ5OiBmYWxzZQogICAgICAgIHBy'
    'b3BlcnR5IGJvb2wgZGFuZ2VyOiBmYWxzZQogICAgICAgIHByb3BlcnR5IGJvb2wgZW5hYmxlZEJ1dHRvbjogdHJ1ZQogICAg'
    'ICAgIHNpZ25hbCBjbGlja2VkKCkKICAgICAgICBpbXBsaWNpdEhlaWdodDogNDIKICAgICAgICBpbXBsaWNpdFdpZHRoOiBN'
    'YXRoLm1heCg5MiwgYnV0dG9uVGV4dC5pbXBsaWNpdFdpZHRoICsgMjgpCiAgICAgICAgcmFkaXVzOiA1CiAgICAgICAgY29s'
    'b3I6ICFlbmFibGVkQnV0dG9uID8gIiMyYzI0MmYiCiAgICAgICAgICAgICAgOiBkYW5nZXIgPyAoYnV0dG9uTW91c2UuY29u'
    'dGFpbnNNb3VzZSA/ICIjNWIyOTM5IiA6ICIjM2EyMDJkIikKICAgICAgICAgICAgICA6IHByaW1hcnkgPyAoYnV0dG9uTW91'
    'c2UuY29udGFpbnNNb3VzZSA/ICIjZmY3Yjg5IiA6IHJvb3QuYWNjZW50KQogICAgICAgICAgICAgIDogKGJ1dHRvbk1vdXNl'
    'LmNvbnRhaW5zTW91c2UgPyAiIzM4MjQzMiIgOiAiIzI5MjAyYiIpCiAgICAgICAgYm9yZGVyLndpZHRoOiBwcmltYXJ5ID8g'
    'MCA6IDEKICAgICAgICBib3JkZXIuY29sb3I6IGRhbmdlciA/ICIjODc1NTY4IiA6IHJvb3QuYm9yZGVyCiAgICAgICAgb3Bh'
    'Y2l0eTogZW5hYmxlZEJ1dHRvbiA/IDEgOiAwLjQ1CiAgICAgICAgYWN0aXZlRm9jdXNPblRhYjogZW5hYmxlZEJ1dHRvbgog'
    'ICAgICAgIEFjY2Vzc2libGUucm9sZTogQWNjZXNzaWJsZS5CdXR0b24KICAgICAgICBBY2Nlc3NpYmxlLm5hbWU6IGxhYmVs'
    'CiAgICAgICAgQWNjZXNzaWJsZS5vblByZXNzQWN0aW9uOiBpZiAoZW5hYmxlZEJ1dHRvbikgY2xpY2tlZCgpCiAgICAgICAg'
    'S2V5cy5vblJldHVyblByZXNzZWQ6IGlmIChlbmFibGVkQnV0dG9uKSBjbGlja2VkKCkKICAgICAgICBLZXlzLm9uU3BhY2VQ'
    'cmVzc2VkOiBpZiAoZW5hYmxlZEJ1dHRvbikgY2xpY2tlZCgpCiAgICAgICAgUmVjdGFuZ2xlIHsgYW5jaG9ycy5maWxsOiBw'
    'YXJlbnQ7IGFuY2hvcnMubWFyZ2luczogLTM7IHJhZGl1czogNzsgY29sb3I6ICJ0cmFuc3BhcmVudCI7IGJvcmRlci5jb2xv'
    'cjogcm9vdC5hY2NlbnQ7IHZpc2libGU6IGZsYXRCdXR0b24uYWN0aXZlRm9jdXMgfQoKICAgICAgICBDLkxhYmVsIHsKICAg'
    'ICAgICAgICAgaWQ6IGJ1dHRvblRleHQKICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAgICAg'
    'IHRleHQ6IGZsYXRCdXR0b24ubGFiZWwKICAgICAgICAgICAgY29sb3I6ICFmbGF0QnV0dG9uLmVuYWJsZWRCdXR0b24gPyBy'
    'b290LnRleHRNdXRlZCA6IGZsYXRCdXR0b24ucHJpbWFyeSA/ICIjMTgwZDEzIiA6IChmbGF0QnV0dG9uLmRhbmdlciA/IHJv'
    'b3QuYmFkIDogcm9vdC50ZXh0TWFpbikKICAgICAgICAgICAgZm9udC5waXhlbFNpemU6IDEzCiAgICAgICAgICAgIGZvbnQu'
    'd2VpZ2h0OiBGb250LkRlbWlCb2xkCiAgICAgICAgfQogICAgICAgIE1vdXNlQXJlYSB7CiAgICAgICAgICAgIGlkOiBidXR0'
    'b25Nb3VzZQogICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICBlbmFibGVkOiBmbGF0QnV0dG9u'
    'LmVuYWJsZWRCdXR0b24KICAgICAgICAgICAgaG92ZXJFbmFibGVkOiB0cnVlCiAgICAgICAgICAgIGN1cnNvclNoYXBlOiBl'
    'bmFibGVkID8gUXQuUG9pbnRpbmdIYW5kQ3Vyc29yIDogUXQuQXJyb3dDdXJzb3IKICAgICAgICAgICAgb25DbGlja2VkOiBm'
    'bGF0QnV0dG9uLmNsaWNrZWQoKQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25lbnQgTmF2QnV0dG9uOiBSZWN0YW5nbGUg'
    'ewogICAgICAgIGlkOiBuYXYKICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbGFiZWwKICAgICAgICByZXF1aXJl'
    'ZCBwcm9wZXJ0eSBpbnQgaW5kZXgKICAgICAgICBwcm9wZXJ0eSBzdHJpbmcgc2hvcnRMYWJlbDogIiIKICAgICAgICBzaWdu'
    'YWwgY2xpY2tlZCgpCiAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgIGltcGxpY2l0V2lkdGg6IDE4Ngog'
    'ICAgICAgIGhlaWdodDogNDgKICAgICAgICByYWRpdXM6IDQKICAgICAgICBjb2xvcjogcm9vdC5wYWdlSW5kZXggPT09IGlu'
    'ZGV4ID8gIiMzYTIwMmQiIDogKG5hdk1vdXNlLmNvbnRhaW5zTW91c2UgPyByb290LnNpZGViYXJIb3ZlciA6ICJ0cmFuc3Bh'
    'cmVudCIpCgogICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAgICAgICAgICAg'
    'IGFuY2hvcnMubGVmdE1hcmdpbjogMTIKICAgICAgICAgICAgYW5jaG9ycy5yaWdodE1hcmdpbjogMTIKICAgICAgICAgICAg'
    'c3BhY2luZzogMTEKICAgICAgICAgICAgUmVjdGFuZ2xlIHsKICAgICAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDI4CiAg'
    'ICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogMjgKICAgICAgICAgICAgICAgIHJhZGl1czogMwogICAgICAgICAgICAg'
    'ICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyByb290LmFjY2VudCA6ICIjMzAyMzMwIgogICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5jZW50ZXJJbjogcGFyZW50CiAgICAgICAg'
    'ICAgICAgICAgICAgdGV4dDogbmF2LnNob3J0TGFiZWwKICAgICAgICAgICAgICAgICAgICBjb2xvcjogIndoaXRlIgogICAg'
    'ICAgICAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMAogICAgICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiBGb250'
    'LkJvbGQKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgICAgICBDLkxhYmVsIHsKICAgICAgICAgICAg'
    'ICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgIHRleHQ6IG5hdi5sYWJlbAogICAgICAgICAgICAg'
    'ICAgY29sb3I6IHJvb3QucGFnZUluZGV4ID09PSBuYXYuaW5kZXggPyAid2hpdGUiIDogIiNiYWE4YWYiCiAgICAgICAgICAg'
    'ICAgICBmb250LnBpeGVsU2l6ZTogMTQKICAgICAgICAgICAgICAgIGZvbnQud2VpZ2h0OiByb290LnBhZ2VJbmRleCA9PT0g'
    'bmF2LmluZGV4ID8gRm9udC5EZW1pQm9sZCA6IEZvbnQuTm9ybWFsCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAg'
    'TW91c2VBcmVhIHsKICAgICAgICAgICAgaWQ6IG5hdk1vdXNlCiAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAg'
    'ICAgICAgICAgIGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICBjdXJzb3JTaGFwZTogUXQuUG9pbnRpbmdIYW5kQ3Vy'
    'c29yCiAgICAgICAgICAgIG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAgcm9vdC5wYWdlSW5kZXggPSBuYXYuaW5kZXgK'
    'ICAgICAgICAgICAgICAgIG5hdi5jbGlja2VkKCkKICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KCiAgICBjb21wb25l'
    'bnQgUmliYm9uU3dpdGNoOiBDLlN3aXRjaCB7CiAgICAgICAgaWQ6IGNvbnRyb2wKICAgICAgICBpbmRpY2F0b3I6IFJlY3Rh'
    'bmdsZSB7CiAgICAgICAgICAgIHg6IGNvbnRyb2wubGVmdFBhZGRpbmc7IHk6IChjb250cm9sLmhlaWdodCAtIGhlaWdodCkg'
    'LyAyCiAgICAgICAgICAgIGltcGxpY2l0V2lkdGg6IDQ0OyBpbXBsaWNpdEhlaWdodDogMjQ7IHJhZGl1czogMTIKICAgICAg'
    'ICAgICAgY29sb3I6IGNvbnRyb2wuY2hlY2tlZCA/IHJvb3QuYWNjZW50IDogIiM0ODMwM2MiCiAgICAgICAgICAgIGJvcmRl'
    'ci5jb2xvcjogY29udHJvbC5hY3RpdmVGb2N1cyA/IHJvb3QudGV4dE1haW4gOiByb290LmJvcmRlcgogICAgICAgICAgICBS'
    'ZWN0YW5nbGUgewogICAgICAgICAgICAgICAgd2lkdGg6IDE4OyBoZWlnaHQ6IDE4OyByYWRpdXM6IDk7IHk6IDMKICAgICAg'
    'ICAgICAgICAgIHg6IGNvbnRyb2wuY2hlY2tlZCA/IHBhcmVudC53aWR0aCAtIHdpZHRoIC0gMyA6IDMKICAgICAgICAgICAg'
    'ICAgIGNvbG9yOiBjb250cm9sLmNoZWNrZWQgPyAiIzE4MGQxMyIgOiByb290LnRleHRNYWluCiAgICAgICAgICAgIH0KICAg'
    'ICAgICB9CiAgICAgICAgY29udGVudEl0ZW06IEMuTGFiZWwgewogICAgICAgICAgICB0ZXh0OiBjb250cm9sLnRleHQ7IGNv'
    'bG9yOiByb290LnRleHRNYWluCiAgICAgICAgICAgIGxlZnRQYWRkaW5nOiBjb250cm9sLmluZGljYXRvci53aWR0aCArIGNv'
    'bnRyb2wuc3BhY2luZwogICAgICAgICAgICB2ZXJ0aWNhbEFsaWdubWVudDogVGV4dC5BbGlnblZDZW50ZXIKICAgICAgICB9'
    'CiAgICB9CgogICAgY29tcG9uZW50IFJpYmJvbk1hcms6IENhbnZhcyB7CiAgICAgICAgb25QYWludDogewogICAgICAgICAg'
    'ICBjb25zdCBjdHggPSBnZXRDb250ZXh0KCIyZCIpCiAgICAgICAgICAgIGN0eC5yZXNldCgpOyBjdHguc2NhbGUod2lkdGgg'
    'LyAxMTAsIGhlaWdodCAvIDEyMCkKICAgICAgICAgICAgZm9yIChsZXQgc2lkZSA9IDA7IHNpZGUgPCAyOyBzaWRlKyspIHsK'
    'ICAgICAgICAgICAgICAgIGN0eC5zYXZlKCkKICAgICAgICAgICAgICAgIGlmIChzaWRlKSB7IGN0eC50cmFuc2xhdGUoMTEw'
    'LCAwKTsgY3R4LnNjYWxlKC0xLCAxKSB9CmN0eC5iZWdpblBhdGgoKTsKY3R4Lm1vdmVUbygxMCwgNik7CmN0eC5iZXppZXJD'
    'dXJ2ZVRvKC00LCAxNywgMSwgMjksIDEyLCAzOCk7CmN0eC5iZXppZXJDdXJ2ZVRvKDQsIDUyLCAxMywgNjMsIDIyLCA3MCk7'
    'CmN0eC5iZXppZXJDdXJ2ZVRvKDE3LCA4MiwgMjgsIDk4LCAzNCwgMTEyKTsKY3R4LmJlemllckN1cnZlVG8oMzcsIDk1LCA0'
    'NCwgODIsIDM3LCA2OCk7CmN0eC5iZXppZXJDdXJ2ZVRvKDQ4LCA1NSwgNDksIDQ2LCA0MSwgMzYpOwpjdHguYmV6aWVyQ3Vy'
    'dmVUbyg1OCwgMTMsIDQwLCAtNCwgMTAsIDYpOwpjdHguY2xvc2VQYXRoKCk7CmN0eC5maWxsU3R5bGUgPSAiIzcwMmE0MCI7'
    'IGN0eC5maWxsKCk7CmN0eC5iZWdpblBhdGgoKTsKY3R4Lm1vdmVUbyg0NCwgNyk7CmN0eC5iZXppZXJDdXJ2ZVRvKDEwLCAt'
    'NCwgLTgsIDEyLCA4LCAyNyk7CmN0eC5iZXppZXJDdXJ2ZVRvKDE1LCAzNCwgMzIsIDM4LCA0MSwgNDMpOwpjdHgubGluZVRv'
    'KDQ2LCAzMSk7CmN0eC5iZXppZXJDdXJ2ZVRvKDMzLCAyNCwgMTMsIDIyLCAxMiwgMTUpOwpjdHguYmV6aWVyQ3VydmVUbygx'
    'OCwgOSwgMzEsIDgsIDQ0LCA3KTsKY3R4LmNsb3NlUGF0aCgpOwpjdHguZmlsbFN0eWxlID0gcm9vdC5hY2NlbnQ7IGN0eC5m'
    'aWxsKCk7CmN0eC5iZWdpblBhdGgoKTsKY3R4Lm1vdmVUbyg1LCAyNik7CmN0eC5iZXppZXJDdXJ2ZVRvKC0zLCA0NCwgMTMs'
    'IDUzLCAzNCwgNTkpOwpjdHguYmV6aWVyQ3VydmVUbygzOCwgNjEsIDQwLCA2NCwgNDEsIDY3KTsKY3R4LmxpbmVUbyg0NSwg'
    'NTMpOwpjdHguYmV6aWVyQ3VydmVUbygzMSwgNDQsIDEwLCA0MiwgMTEsIDM0KTsKY3R4LmNsb3NlUGF0aCgpOwpjdHguZmls'
    'bFN0eWxlID0gcm9vdC5hY2NlbnQ7IGN0eC5maWxsKCk7CmN0eC5iZWdpblBhdGgoKTsKY3R4Lm1vdmVUbygxMiwgNTEpOwpj'
    'dHguYmV6aWVyQ3VydmVUbyg4LCA2NywgMjEsIDc3LCAzMywgODApOwpjdHgubGluZVRvKDM4LCA5MCk7CmN0eC5saW5lVG8o'
    'NDEsIDc1KTsKY3R4LmJlemllckN1cnZlVG8oMzAsIDY2LCAxOSwgNjMsIDE4LCA1OCk7CmN0eC5jbG9zZVBhdGgoKTsKY3R4'
    'LmZpbGxTdHlsZSA9IHJvb3QuYWNjZW50OyBjdHguZmlsbCgpOwpjdHguYmVnaW5QYXRoKCk7CmN0eC5tb3ZlVG8oMjIsIDc2'
    'KTsKY3R4LmJlemllckN1cnZlVG8oMjAsIDg5LCAzMSwgMTAxLCAzNCwgMTEyKTsKY3R4LmxpbmVUbygzOSwgOTMpOwpjdHgu'
    'YmV6aWVyQ3VydmVUbygzMSwgODgsIDI5LCA4MywgMjksIDgxKTsKY3R4LmNsb3NlUGF0aCgpOwpjdHguZmlsbFN0eWxlID0g'
    'cm9vdC5hY2NlbnQ7IGN0eC5maWxsKCk7CmN0eC5iZWdpblBhdGgoKTsKY3R4Lm1vdmVUbygzOSwgOCk7CmN0eC5iZXppZXJD'
    'dXJ2ZVRvKDIxLCAzLCA0LCAxMSwgOCwgMjApOwpjdHgubW92ZVRvKDcsIDM0KTsKY3R4LmJlemllckN1cnZlVG8oNywgNDMs'
    'IDIzLCA0OCwgMzQsIDUyKTsKY3R4Lm1vdmVUbygxNiwgNjApOwpjdHguYmV6aWVyQ3VydmVUbygxNywgNjcsIDI3LCA3MSwg'
    'MzMsIDczKTsKY3R4LnN0cm9rZVN0eWxlID0gIiNmZmFjYjgiOyBjdHgubGluZVdpZHRoID0gMS4yOyBjdHguc3Ryb2tlKCk7'
    'CmN0eC5yZXN0b3JlKCkKfQp9Cn0KCiAgICBjb21wb25lbnQgQ2FyZDogUmVjdGFuZ2xlIHsKICAgICAgICByYWRpdXM6IDcK'
    'ICAgICAgICBjb2xvcjogcm9vdC5zdXJmYWNlCiAgICAgICAgYm9yZGVyLndpZHRoOiAxCiAgICAgICAgYm9yZGVyLmNvbG9y'
    'OiByb290LmJvcmRlcgogICAgfQoKICAgIC8vIE5hdGl2ZSBzeXN0ZW0gb3BlcmF0aW9ucyBwcmVzZXJ2ZSBzbmFwcGluZywg'
    'Y29tcG9zaXRvciBzY2FsaW5nIGFuZCByZXNpemUgbGltaXRzLgogICAgUmVjdGFuZ2xlIHsKICAgICAgICBpZDogdGl0bGVC'
    'YXIKICAgICAgICBvYmplY3ROYW1lOiAid2luZG93VGl0bGVCYXIiCiAgICAgICAgYW5jaG9ycyB7IGxlZnQ6IHBhcmVudC5s'
    'ZWZ0OyByaWdodDogcGFyZW50LnJpZ2h0OyB0b3A6IHBhcmVudC50b3AgfQogICAgICAgIGhlaWdodDogMzgKICAgICAgICBj'
    'b2xvcjogcm9vdC5zaWRlYmFyCiAgICAgICAgTW91c2VBcmVhIHsKICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQK'
    'ICAgICAgICAgICAgYWNjZXB0ZWRCdXR0b25zOiBRdC5MZWZ0QnV0dG9uCiAgICAgICAgICAgIG9uUHJlc3NlZDogZnVuY3Rp'
    'b24obW91c2UpIHsgcm9vdC5zdGFydFN5c3RlbU1vdmUoKSB9CiAgICAgICAgICAgIG9uRG91YmxlQ2xpY2tlZDogZnVuY3Rp'
    'b24obW91c2UpIHsgbW91c2UuYWNjZXB0ZWQgPSB0cnVlIH0KICAgICAgICB9CiAgICAgICAgQy5MYWJlbCB7CiAgICAgICAg'
    'ICAgIGFuY2hvcnMgeyBsZWZ0OiBwYXJlbnQubGVmdDsgbGVmdE1hcmdpbjogMTg7IHZlcnRpY2FsQ2VudGVyOiBwYXJlbnQu'
    'dmVydGljYWxDZW50ZXIgfQogICAgICAgICAgICB0ZXh0OiAiRVZHRU5JVU0gTkVUV09SSyIKICAgICAgICAgICAgY29sb3I6'
    'IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgIGZvbnQucGl4ZWxTaXplOiAxMAogICAgICAgICAgICBmb250LmxldHRlclNw'
    'YWNpbmc6IDEuNgogICAgICAgIH0KICAgICAgICBSb3cgewogICAgICAgICAgICBhbmNob3JzIHsgcmlnaHQ6IHBhcmVudC5y'
    'aWdodDsgcmlnaHRNYXJnaW46IDc7IHRvcDogcGFyZW50LnRvcDsgYm90dG9tOiBwYXJlbnQuYm90dG9tIH0KICAgICAgICAg'
    'ICAgQy5Ub29sQnV0dG9uIHsKICAgICAgICAgICAgICAgIGlkOiBtaW5pbWl6ZVdpbmRvdwogICAgICAgICAgICAgICAgb2Jq'
    'ZWN0TmFtZTogIm1pbmltaXplV2luZG93IgogICAgICAgICAgICAgICAgd2lkdGg6IDQ0OyBoZWlnaHQ6IHRpdGxlQmFyLmhl'
    'aWdodAogICAgICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0KHQstC10YDQvdGD0YLRjCIKICAgICAgICAgICAgICAg'
    'IGhvdmVyRW5hYmxlZDogdHJ1ZQogICAgICAgICAgICAgICAgb25DbGlja2VkOiByb290LnNob3dNaW5pbWl6ZWQoKQogICAg'
    'ICAgICAgICAgICAgYmFja2dyb3VuZDogUmVjdGFuZ2xlIHsgY29sb3I6IG1pbmltaXplV2luZG93LmhvdmVyZWQgPyByb290'
    'LnNpZGViYXJIb3ZlciA6ICJ0cmFuc3BhcmVudCIgfQogICAgICAgICAgICAgICAgY29udGVudEl0ZW06IEl0ZW0gewogICAg'
    'ICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7IGFuY2hvcnMuY2VudGVySW46IHBhcmVudDsgd2lkdGg6IDEyOyBoZWlnaHQ6'
    'IDE7IGNvbG9yOiByb290LnRleHRNYWluIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIEMuVG9vbFRpcC52'
    'aXNpYmxlOiBob3ZlcmVkCiAgICAgICAgICAgICAgICBDLlRvb2xUaXAudGV4dDogItCh0LLQtdGA0L3Rg9GC0YwiCiAgICAg'
    'ICAgICAgIH0KICAgICAgICAgICAgQy5Ub29sQnV0dG9uIHsKICAgICAgICAgICAgICAgIGlkOiBjbG9zZVdpbmRvdwogICAg'
    'ICAgICAgICAgICAgb2JqZWN0TmFtZTogImNsb3NlV2luZG93IgogICAgICAgICAgICAgICAgd2lkdGg6IDQ0OyBoZWlnaHQ6'
    'IHRpdGxlQmFyLmhlaWdodAogICAgICAgICAgICAgICAgQWNjZXNzaWJsZS5uYW1lOiAi0JfQsNC60YDRi9GC0YwiCiAgICAg'
    'ICAgICAgICAgICBob3ZlckVuYWJsZWQ6IHRydWUKICAgICAgICAgICAgICAgIG9uQ2xpY2tlZDogcm9vdC5jbG9zZSgpCiAg'
    'ICAgICAgICAgICAgICBiYWNrZ3JvdW5kOiBSZWN0YW5nbGUgeyBjb2xvcjogY2xvc2VXaW5kb3cuaG92ZXJlZCA/IHJvb3Qu'
    'YWNjZW50U29mdCA6ICJ0cmFuc3BhcmVudCIgfQogICAgICAgICAgICAgICAgY29udGVudEl0ZW06IEl0ZW0gewogICAgICAg'
    'ICAgICAgICAgICAgIFJlY3RhbmdsZSB7IGFuY2hvcnMuY2VudGVySW46IHBhcmVudDsgd2lkdGg6IDE0OyBoZWlnaHQ6IDE7'
    'IHJvdGF0aW9uOiA0NTsgY29sb3I6IGNsb3NlV2luZG93LmhvdmVyZWQgPyByb290LmFjY2VudCA6IHJvb3QudGV4dE1haW4g'
    'fQogICAgICAgICAgICAgICAgICAgIFJlY3RhbmdsZSB7IGFuY2hvcnMuY2VudGVySW46IHBhcmVudDsgd2lkdGg6IDE0OyBo'
    'ZWlnaHQ6IDE7IHJvdGF0aW9uOiAtNDU7IGNvbG9yOiBjbG9zZVdpbmRvdy5ob3ZlcmVkID8gcm9vdC5hY2NlbnQgOiByb290'
    'LnRleHRNYWluIH0KICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIEMuVG9vbFRpcC52aXNpYmxlOiBob3ZlcmVk'
    'CiAgICAgICAgICAgICAgICBDLlRvb2xUaXAudGV4dDogItCX0LDQutGA0YvRgtGMIgogICAgICAgICAgICB9CiAgICAgICAg'
    'fQogICAgICAgIFJlY3RhbmdsZSB7IGFuY2hvcnMgeyBsZWZ0OiBwYXJlbnQubGVmdDsgcmlnaHQ6IHBhcmVudC5yaWdodDsg'
    'Ym90dG9tOiBwYXJlbnQuYm90dG9tIH0gaGVpZ2h0OiAxOyBjb2xvcjogcm9vdC5ib3JkZXIgfQogICAgfQoKICAgIC8vIFNl'
    'cGFyYXRlIGNvcm5lciB6b25lcyBrZWVwIHJlc2l6aW5nIHVzYWJsZSB3aXRob3V0IGNvdmVyaW5nIGNhcHRpb24gYnV0dG9u'
    'cy4KICAgIGNvbXBvbmVudCBSZXNpemVab25lOiBNb3VzZUFyZWEgewogICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IGludCBl'
    'ZGdlcwogICAgICAgIHo6IDEwMAogICAgICAgIGFjY2VwdGVkQnV0dG9uczogUXQuTGVmdEJ1dHRvbgogICAgICAgIG9uUHJl'
    'c3NlZDogZnVuY3Rpb24obW91c2UpIHsgcm9vdC5zdGFydFN5c3RlbVJlc2l6ZShlZGdlcykgfQogICAgfQogICAgUmVzaXpl'
    'Wm9uZSB7IG9iamVjdE5hbWU6ICJyZXNpemVUb3BMZWZ0IjsgYW5jaG9ycyB7IHRvcDogcGFyZW50LnRvcDsgbGVmdDogcGFy'
    'ZW50LmxlZnQgfSB3aWR0aDogMTA7IGhlaWdodDogMTA7IGVkZ2VzOiBRdC5Ub3BFZGdlIHwgUXQuTGVmdEVkZ2U7IGN1cnNv'
    'clNoYXBlOiBRdC5TaXplRkRpYWdDdXJzb3IgfQogICAgUmVzaXplWm9uZSB7IG9iamVjdE5hbWU6ICJyZXNpemVUb3BSaWdo'
    'dCI7IGFuY2hvcnMgeyB0b3A6IHBhcmVudC50b3A7IHJpZ2h0OiBwYXJlbnQucmlnaHQgfSB3aWR0aDogMTA7IGhlaWdodDog'
    'MTA7IGVkZ2VzOiBRdC5Ub3BFZGdlIHwgUXQuUmlnaHRFZGdlOyBjdXJzb3JTaGFwZTogUXQuU2l6ZUJEaWFnQ3Vyc29yIH0K'
    'ICAgIFJlc2l6ZVpvbmUgeyBvYmplY3ROYW1lOiAicmVzaXplQm90dG9tTGVmdCI7IGFuY2hvcnMgeyBib3R0b206IHBhcmVu'
    'dC5ib3R0b207IGxlZnQ6IHBhcmVudC5sZWZ0IH0gd2lkdGg6IDEwOyBoZWlnaHQ6IDEwOyBlZGdlczogUXQuQm90dG9tRWRn'
    'ZSB8IFF0LkxlZnRFZGdlOyBjdXJzb3JTaGFwZTogUXQuU2l6ZUJEaWFnQ3Vyc29yIH0KICAgIFJlc2l6ZVpvbmUgeyBvYmpl'
    'Y3ROYW1lOiAicmVzaXplQm90dG9tUmlnaHQiOyBhbmNob3JzIHsgYm90dG9tOiBwYXJlbnQuYm90dG9tOyByaWdodDogcGFy'
    'ZW50LnJpZ2h0IH0gd2lkdGg6IDEwOyBoZWlnaHQ6IDEwOyBlZGdlczogUXQuQm90dG9tRWRnZSB8IFF0LlJpZ2h0RWRnZTsg'
    'Y3Vyc29yU2hhcGU6IFF0LlNpemVGRGlhZ0N1cnNvciB9CiAgICBSZXNpemVab25lIHsgYW5jaG9ycyB7IHRvcDogcGFyZW50'
    'LnRvcDsgbGVmdDogcGFyZW50LmxlZnQ7IHJpZ2h0OiBwYXJlbnQucmlnaHQ7IGxlZnRNYXJnaW46IDEwOyByaWdodE1hcmdp'
    'bjogMTAgfSBoZWlnaHQ6IDU7IGVkZ2VzOiBRdC5Ub3BFZGdlOyBjdXJzb3JTaGFwZTogUXQuU2l6ZVZlckN1cnNvciB9CiAg'
    'ICBSZXNpemVab25lIHsgYW5jaG9ycyB7IGJvdHRvbTogcGFyZW50LmJvdHRvbTsgbGVmdDogcGFyZW50LmxlZnQ7IHJpZ2h0'
    'OiBwYXJlbnQucmlnaHQ7IGxlZnRNYXJnaW46IDEwOyByaWdodE1hcmdpbjogMTAgfSBoZWlnaHQ6IDU7IGVkZ2VzOiBRdC5C'
    'b3R0b21FZGdlOyBjdXJzb3JTaGFwZTogUXQuU2l6ZVZlckN1cnNvciB9CiAgICBSZXNpemVab25lIHsgYW5jaG9ycyB7IHRv'
    'cDogcGFyZW50LnRvcDsgYm90dG9tOiBwYXJlbnQuYm90dG9tOyBsZWZ0OiBwYXJlbnQubGVmdDsgdG9wTWFyZ2luOiAxMDsg'
    'Ym90dG9tTWFyZ2luOiAxMCB9IHdpZHRoOiA1OyBlZGdlczogUXQuTGVmdEVkZ2U7IGN1cnNvclNoYXBlOiBRdC5TaXplSG9y'
    'Q3Vyc29yIH0KICAgIFJlc2l6ZVpvbmUgeyBhbmNob3JzIHsgdG9wOiBwYXJlbnQudG9wOyBib3R0b206IHBhcmVudC5ib3R0'
    'b207IHJpZ2h0OiBwYXJlbnQucmlnaHQ7IHRvcE1hcmdpbjogMTA7IGJvdHRvbU1hcmdpbjogMTAgfSB3aWR0aDogNTsgZWRn'
    'ZXM6IFF0LlJpZ2h0RWRnZTsgY3Vyc29yU2hhcGU6IFF0LlNpemVIb3JDdXJzb3IgfQogICAgUmVjdGFuZ2xlIHsgYW5jaG9y'
    'cy5maWxsOiBwYXJlbnQ7IGNvbG9yOiAidHJhbnNwYXJlbnQiOyBib3JkZXIuY29sb3I6IHJvb3QuYm9yZGVyOyB6OiA5OSB9'
    'CgogICAgUm93TGF5b3V0IHsKICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgIGFuY2hvcnMudG9wTWFyZ2lu'
    'OiB0aXRsZUJhci5oZWlnaHQKICAgICAgICBhbmNob3JzLm1hcmdpbnM6IDEKICAgICAgICBzcGFjaW5nOiAwCiAgICAgICAg'
    'UmVjdGFuZ2xlIHsKICAgICAgICAgICAgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiAyMjIKICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxIZWlnaHQ6IHRydWUKICAgICAgICAgICAgY29sb3I6IHJvb3Quc2lkZWJhcgogICAgICAgICAgICBDb2x1bW5MYXlvdXQg'
    'ewogICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQKICAgICAgICAgICAgICAgIGFuY2hvcnMubWFyZ2luczog'
    'MTgKICAgICAgICAgICAgICAgIHNwYWNpbmc6IDgKICAgICAgICAgICAgICAgIFJpYmJvbk1hcmsgeyBMYXlvdXQucHJlZmVy'
    'cmVkV2lkdGg6IDQyOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiA1MDsgTGF5b3V0LnRvcE1hcmdpbjogOCB9CiAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgdGV4dDogIkVWR0VOSVVNIjsgY29sb3I6IHJvb3QudGV4dE1haW47IGZvbnQucGl4ZWxTaXpl'
    'OiAyMTsgZm9udC5ib2xkOiB0cnVlOyBmb250LmxldHRlclNwYWNpbmc6IDEuNTsgTGF5b3V0LnRvcE1hcmdpbjogOCB9CiAg'
    'ICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogIk4gRSBUIFcgTyBSIEsiOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQ7IGZv'
    'bnQucGl4ZWxTaXplOiAxMDsgTGF5b3V0LmJvdHRvbU1hcmdpbjogMjggfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsg'
    'bGFiZWw6ICJWUE4iOyBzaG9ydExhYmVsOiAiVlBOIjsgaW5kZXg6IDAgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsg'
    'bGFiZWw6ICLQn9GA0LjQu9C+0LbQtdC90LjRjyI7IHNob3J0TGFiZWw6ICJBUFAiOyBpbmRleDogMTsgb25DbGlja2VkOiBy'
    'b290LnJlZnJlc2hSdW5uaW5nKCkgfQogICAgICAgICAgICAgICAgTmF2QnV0dG9uIHsgbGFiZWw6ICLQodCw0LnRgtGLINC4'
    'IElQIjsgc2hvcnRMYWJlbDogIk5FVCI7IGluZGV4OiAyIH0KICAgICAgICAgICAgICAgIE5hdkJ1dHRvbiB7IGxhYmVsOiAi'
    '0J/QvtGA0YLRiyI7IHNob3J0TGFiZWw6ICJQUlQiOyBpbmRleDogMyB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBs'
    'YWJlbDogIkROUyI7IHNob3J0TGFiZWw6ICJETlMiOyBpbmRleDogNCB9CiAgICAgICAgICAgICAgICBOYXZCdXR0b24geyBs'
    'YWJlbDogIldheWRyb2lkIjsgc2hvcnRMYWJlbDogIldBWSI7IGluZGV4OiA1IH0KICAgICAgICAgICAgICAgIEl0ZW0geyBM'
    'YXlvdXQuZmlsbEhlaWdodDogdHJ1ZSB9CiAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogcm9vdC5zdGF0ZS5hY3Rp'
    'dmUgPyAi4pePINCf0L7QtNC60LvRjtGH0LXQvdC+IiA6IChyb290LnN0YXRlLmd1YXJkID8gIuKXjyDQl9Cw0YnQuNGC0LAg'
    '0LLQutC70Y7Rh9C10L3QsCIgOiAi4peLINCe0YLQutC70Y7Rh9C10L3QviIpOyBjb2xvcjogcm9vdC5zdGF0ZS5hY3RpdmUg'
    'PyAiI2E2ZDhjMiIgOiAiI2JhYThhZiIgfQogICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQktC10YDRgdC40Y8g'
    'IiArIChyb290LnN0YXRlLm1hbmFnZXJfdmVyc2lvbiB8fCAi4oCmIik7IGNvbG9yOiAiI2FkOTI5ZSI7IGZvbnQucGl4ZWxT'
    'aXplOiAxMiB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdodDogdHJ1ZQogICAgICAgICAgICBMYXlv'
    'dXQubWFyZ2luczogMjgKICAgICAgICAgICAgc3BhY2luZzogMTYKICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICJFVkdF'
    'TklVTSAgLyAgIiArIChyb290LnBhZ2VJbmRleCA9PT0gMCA/ICLQn9Ce0JTQmtCb0K7Qp9CV0J3QmNCVIiA6ICLQmNCh0JrQ'
    'm9Cu0KfQldCd0JjQryIpOyBjb2xvcjogcm9vdC5hY2NlbnQ7IGZvbnQucGl4ZWxTaXplOiAxMDsgZm9udC5sZXR0ZXJTcGFj'
    'aW5nOiAxLjQgfQogICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogWyLQktCw0YggVlBOIiwgItCY0YHQutC70Y7Rh9C10L3Q'
    'uNGPINC/0YDQuNC70L7QttC10L3QuNC5IiwgItCh0LDQudGC0Ysg0LggSVAiLCAi0JjRgdC60LvRjtGH0LXQvdC40Y8g0L/Q'
    'vtGA0YLQvtCyIiwgIkROUyIsICJXYXlkcm9pZCJdW3Jvb3QucGFnZUluZGV4XTsgY29sb3I6IHJvb3QudGV4dE1haW47IGZv'
    'bnQucGl4ZWxTaXplOiAyNzsgZm9udC5ib2xkOiB0cnVlIH0KICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAgICAgICAg'
    'ICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICB2aXNpYmxlOiBCb29sZWFuKHJvb3QuZXJyb3JUZXh0'
    'IHx8IHJvb3QucG9sbEVycm9yVGV4dCkKICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QuZXJyb3JUZXh0IHx8IHJvb3QucG9s'
    'bEVycm9yVGV4dAogICAgICAgICAgICAgICAgY29sb3I6IHJvb3QuYmFkCiAgICAgICAgICAgICAgICB3cmFwTW9kZTogVGV4'
    'dC5XcmFwCiAgICAgICAgICAgIH0KICAgICAgICAgICAgQy5CdXN5SW5kaWNhdG9yIHsgcnVubmluZzogcm9vdC5idXN5OyB2'
    'aXNpYmxlOiBydW5uaW5nOyBMYXlvdXQucHJlZmVycmVkSGVpZ2h0OiAyOCB9CiAgICAgICAgICAgIEMuU2Nyb2xsVmlldyB7'
    'CiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbEhlaWdo'
    'dDogdHJ1ZQogICAgICAgICAgICAgICAgY2xpcDogdHJ1ZQogICAgICAgICAgICAgICAgY29udGVudFdpZHRoOiBhdmFpbGFi'
    'bGVXaWR0aAogICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICB3aWR0aDogcGFyZW50'
    'LndpZHRoCiAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgKICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQg'
    'ewogICAgICAgICAgICAgICAgICAgICAgICB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gMAogICAgICAgICAgICAgICAg'
    'ICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6IDE4CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC50b2tl'
    'blNhdmVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogZGV2aWNlQm9keS5pbXBsaWNpdEhlaWdodCArIDMyCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiBkZXZp'
    'Y2VCb2R5CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5maWxsOiBwYXJlbnQ7IGFuY2hvcnMubWFy'
    'Z2luczogMTYKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEMuTGFiZWwgeyB2aXNpYmxlOiAhcm9vdC5kZXZpY2VFZGl0aW5nOyB0ZXh0OiByb290LnR1bm5lbC5kZXZpY2VfbmFt'
    'ZSB8fCAi0J/QvtC70YPRh9Cw0Y4g0LjQvNGPINGD0YHRgtGA0L7QudGB0YLQstCw4oCmIjsgZm9udC5waXhlbFNpemU6IDE4'
    'OyBmb250LmJvbGQ6IHRydWU7IGNvbG9yOiByb290LnRleHRNYWluOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBlbGlkZTog'
    'VGV4dC5FbGlkZVJpZ2h0IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgeyBpZDog'
    'ZGV2aWNlTmFtZUlucHV0OyB2aXNpYmxlOiByb290LmRldmljZUVkaXRpbmc7IExheW91dC5maWxsV2lkdGg6IHRydWU7IG1h'
    'eGltdW1MZW5ndGg6IDY0OyBwbGFjZWhvbGRlclRleHQ6ICLQmNC80Y8g0YPRgdGC0YDQvtC50YHRgtCy0LAiOyBzZWxlY3RC'
    'eU1vdXNlOiB0cnVlIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiBy'
    'b290LmRldmljZUVkaXRpbmcgPyAi0KHQvtGF0YDQsNC90LjRgtGMIiA6ICLQmNC30LzQtdC90LjRgtGMINC40LzRjyI7IGVu'
    'YWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZyAmJiAoIXJvb3QuZGV2aWNlRWRpdGlu'
    'ZyB8fCBkZXZpY2VOYW1lSW5wdXQudGV4dC50cmltKCkubGVuZ3RoID4gMCk7IG9uQ2xpY2tlZDogewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFyb290LmRldmljZUVkaXRpbmcpIHsgZGV2aWNlTmFtZUlucHV0LnRl'
    'eHQ9cm9vdC50dW5uZWwuZGV2aWNlX25hbWUgfHwgIiI7IHJvb3QuZGV2aWNlRWRpdGluZz10cnVlOyBkZXZpY2VOYW1lSW5w'
    'dXQuZm9yY2VBY3RpdmVGb2N1cygpIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2Ugcm9v'
    'dC5hY3Rpb24oe2FjdGlvbjoiZGV2aWNlLW5hbWUiLG5hbWU6ZGV2aWNlTmFtZUlucHV0LnRleHQudHJpbSgpfSxmdW5jdGlv'
    'bigpe3Jvb3QuZGV2aWNlRWRpdGluZz1mYWxzZX0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0gfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgdmlzaWJsZTogcm9vdC5kZXZpY2VFZGl0'
    'aW5nOyBsYWJlbDogItCe0YLQvNC10L3QsCI7IG9uQ2xpY2tlZDogcm9vdC5kZXZpY2VFZGl0aW5nPWZhbHNlIH0KICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRl'
    'eHQ6IHJvb3QudHVubmVsLmRldmljZV9uYW1lX3BlbmRpbmcgPyAi0JjQvNGPINGB0L7RhdGA0LDQvdC10L3QviDQvdCwINC6'
    '0L7QvNC/0YzRjtGC0LXRgNC1INC4INCx0YPQtNC10YIg0L7RgtC/0YDQsNCy0LvQtdC90L4g0L/RgNC4INC/0L7QtNC60LvR'
    'jtGH0LXQvdC40LguIiA6ICLQrdGC0L4g0LjQvNGPINCy0LjQtNC90L4g0LIg0LLQtdCxLdC/0LDQvdC10LvQuCDRgdGA0LXQ'
    'tNC4INCy0LDRiNC40YUg0L/QvtC00LrQu9GO0YfQtdC90LjQuS4iOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9k'
    'ZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRIZWln'
    'aHQ6IE1hdGgubWF4KDI0MCwgY29ubmVjdGlvbkJvZHkuaW1wbGljaXRIZWlnaHQgKyA0OCkKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJlY3RhbmdsZSB7IGFuY2hvcnMubGVmdDogcGFyZW50LmxlZnQ7IGFuY2hvcnMudG9wOiBwYXJlbnQudG9w'
    'OyBhbmNob3JzLmxlZnRNYXJnaW46IDIwOyB3aWR0aDogNDQ7IGhlaWdodDogMzsgY29sb3I6IHJvb3QuYWNjZW50IH0KICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIFJpYmJvbk1hcmsgeyBhbmNob3JzLnJpZ2h0OiBwYXJlbnQucmlnaHQ7IGFuY2hv'
    'cnMudmVydGljYWxDZW50ZXI6IHBhcmVudC52ZXJ0aWNhbENlbnRlcjsgYW5jaG9ycy5yaWdodE1hcmdpbjogMjA7IHdpZHRo'
    'OiAxMDU7IGhlaWdodDogMTUwOyBvcGFjaXR5OiAwLjggfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5'
    'b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogY29ubmVjdGlvbkJvZHkKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFu'
    'Y2hvcnMubWFyZ2luczogMjQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbmNob3JzLnJpZ2h0TWFyZ2luOiAx'
    'NDUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxNQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIEMuTGFiZWwgeyB0ZXh0OiByb290LnN0YXRlLmFjdGl2ZSA/ICLQn9C+0LTQutC70Y7Rh9C10L3QviDRh9C10YDQ'
    'tdC3INCt0YHRgtC+0L3QuNGOIiA6IChyb290LnR1bm5lbC5ydW5uaW5nID8gItCf0L7QtNC60LvRjtGH0LXQvdC40LXigKYi'
    'IDogItCT0L7RgtC+0LIg0Log0L/QvtC00LrQu9GO0YfQtdC90LjRjiIpOyBjb2xvcjogcm9vdC5zdGF0ZS5hY3RpdmUgPyBy'
    'b290Lmdvb2QgOiByb290LnRleHRNYWluOyBmb250LnBpeGVsU2l6ZTogMjM7IGZvbnQuYm9sZDogdHJ1ZTsgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IHRleHQ6IHJvb3QudHVubmVsLm1lc3NhZ2UgfHwgItCS0LLQtdC00LjRgtC1INGC0L7QutC10L0g0LrQu9C40LXQ'
    'vdGC0LAiOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0'
    'ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuUHJvZ3Jlc3NCYXIgeyBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlOyB2aXNpYmxlOiBCb29sZWFuKHJvb3QudHVubmVsLnJ1bm5pbmcpICYmICFyb290LnN0YXRlLmFjdGl2ZTsgZnJvbTog'
    'MDsgdG86IDEwMDsgdmFsdWU6IE51bWJlcihyb290LnR1bm5lbC5wcm9ncmVzcyB8fCAwKSB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRv'
    'biB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogY29ubmVjdGlvbkJ1dHRvbgogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVhZG9ubHkgcHJvcGVydHkgYm9vbCBjYW5EaXNjb25uZWN0OiBC'
    'b29sZWFuKHJvb3QudHVubmVsLnJ1bm5pbmcgfHwgcm9vdC5zdGF0ZS5ndWFyZCkKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGxhYmVsOiBjYW5EaXNjb25uZWN0ID8gItCe0YLQutC70Y7Rh9C40YLRjCIgOiAi0J/QvtC00LrQ'
    'u9GO0YfQuNGC0YwiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcmltYXJ5OiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmIChyb290LnRv'
    'a2VuU2F2ZWQgfHwgY2FuRGlzY29ubmVjdCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xp'
    'Y2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogY2FuRGlzY29ubmVjdCA/ICJkaXNjb25uZWN0IiA6ICJjb25uZWN0In0pCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'RmxhdEJ1dHRvbiB7IGxhYmVsOiAi0JLQvtGB0YHRgtCw0L3QvtCy0LjRgtGMIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVz'
    'eSAmJiAhcm9vdC5zdGF0ZS5jb25uZWN0aW5nICYmIHJvb3QudG9rZW5TYXZlZDsgb25DbGlja2VkOiByb290LmFjdGlvbih7'
    'YWN0aW9uOiAicmVwYWlyIn0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQktC10YHRjCDRgtGA0LDRhNC40Log0LjQtNGR0YIg0YfQtdGA0LXQ'
    'tyBWUE4sINC60YDQvtC80LUg0LLQutC70Y7Rh9GR0L3QvdGL0YUg0LjRgdC60LvRjtGH0LXQvdC40LkuINCf0YDQuCDQvtCx'
    '0YDRi9Cy0LUg0LfQsNGJ0LjRidGR0L3QvdGL0LUg0L/QvtC00LrQu9GO0YfQtdC90LjRjyDQsdC70L7QutC40YDRg9GO0YLR'
    'gdGPLiI7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRl'
    'ZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogdG9rZW5Cb2R5LmltcGxpY2l0SGVpZ2h0ICsgNDAK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaWQ6IHRva2VuQm9keQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyMAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHNwYWNpbmc6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQ'
    'otC+0LrQtdC9INC60LvQuNC10L3RgtCwIjsgZm9udC5waXhlbFNpemU6IDE3OyBmb250LmJvbGQ6IHRydWU7IGNvbG9yOiBy'
    'b290LnRleHRNYWluIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdmlzaWJsZTogcm9vdC50'
    'b2tlbkxvY2tlZDsgdGV4dDogcm9vdC50dW5uZWwudG9rZW5faGludCB8fCAi0KLQvtC60LXQvSDRgdC+0YXRgNCw0L3RkdC9'
    'IjsgY29sb3I6IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IHRva2VuSW5wdXQ7IHZpc2libGU6ICFyb290LnRva2Vu'
    'TG9ja2VkOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6ICJFVk4xLeKApiI7IGVjaG9Nb2RlOiBU'
    'ZXh0SW5wdXQuUGFzc3dvcmQ7IHNlbGVjdEJ5TW91c2U6IHRydWU7IGVuYWJsZWQ6ICFyb290LmJ1c3kgJiYgIXJvb3QudHVu'
    'bmVsLnJ1bm5pbmcgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6IHJv'
    'b3QudG9rZW5Mb2NrZWQgPyAi0JjQt9C80LXQvdC40YLRjCIgOiAi0J/QvtC00YLQstC10YDQtNC40YLRjCI7IGVuYWJsZWRC'
    'dXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3QudHVubmVsLnJ1bm5pbmcgJiYgKHJvb3QudG9rZW5Mb2NrZWQgfHwgL15FVk4x'
    'LVtBLVphLXowLTlfLV17NDN9JC8udGVzdCh0b2tlbklucHV0LnRleHQudHJpbSgpKSk7IG9uQ2xpY2tlZDogewogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHJvb3QudG9rZW5Mb2NrZWQpIHJvb3QudG9rZW5FZGl0aW5n'
    'ID0gdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSByb290LmFjdGlvbih7YWN0aW9u'
    'OiAidG9rZW4tc2F2ZSIsIHRva2VuOiB0b2tlbklucHV0LnRleHQudHJpbSgpfSwgZnVuY3Rpb24oKSB7IHRva2VuSW5wdXQu'
    'Y2xlYXIoKTsgcm9vdC50b2tlbkVkaXRpbmcgPSBmYWxzZSB9KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB9IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IHZpc2libGU6IHJvb3QudG9r'
    'ZW5FZGl0aW5nOyBsYWJlbDogItCe0YLQvNC10L3QsCI7IG9uQ2xpY2tlZDogeyB0b2tlbklucHV0LmNsZWFyKCk7IHJvb3Qu'
    'dG9rZW5FZGl0aW5nID0gZmFsc2UgfSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0J7QtNC40L0g0YLQvtC60LXQvSDQvdCwINGH0LXQu9C+0LLQ'
    'tdC60LAg4oCUINC00LvRjyDQstGB0LXRhSDQtdCz0L4g0YPRgdGC0YDQvtC50YHRgtCyLiI7IGNvbG9yOiByb290LnRleHRN'
    'dXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQ2FyZCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVl'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbXBsaWNpdEhlaWdodDogcm91dGVCb2R5LmltcGxpY2l0SGVpZ2h0ICsg'
    'NDAKICAgICAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgaWQ6IHJvdXRlQm9keQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMuZmlsbDogcGFyZW50'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYW5jaG9ycy5tYXJnaW5zOiAyMAogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHNwYWNpbmc6IDEyCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6'
    'ICLQnNCw0YDRiNGA0YPRgiI7IGZvbnQucGl4ZWxTaXplOiAxNzsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50ZXh0'
    'TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Db21ib0JveCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGlkOiByb3V0ZVBpY2tlcgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlv'
    'dXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuYWJsZWQ6ICFyb290LmJ1'
    'c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBwcm9wZXJ0'
    'eSB2YXIgY2hvaWNlczogW3tpZDoiYXV0byIsbGFiZWw6ItCQ0LLRgtC+0LzQsNGC0LjRh9C10YHQutC4In1dLmNvbmNhdCgo'
    'cm9vdC50dW5uZWwucm91dGVzIHx8IHt9KS5jaG9pY2VzIHx8IFtdKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBtb2RlbDogY2hvaWNlcwogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0Um9sZTogImxhYmVs'
    'IgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50SW5kZXg6IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHZhciBzZWxlY3RlZCA9IChyb290LnR1bm5lbC5yb3V0ZXMgfHwge30pLnNlbGVjdGVk'
    'IHx8ICJhdXRvIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaT0wO2k8Y2hvaWNl'
    'cy5sZW5ndGg7aSsrKSBpZiAoY2hvaWNlc1tpXS5pZCA9PT0gc2VsZWN0ZWQpIHJldHVybiBpCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQWN0aXZhdGVkOiByb290LmFjdGlvbih7YWN0aW9uOiJyb3V0'
    'ZSIsdmFsdWU6Y2hvaWNlc1tjdXJyZW50SW5kZXhdLmlkfSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQkNCy0YLQvtC80LDRgtC40YfQtdGB0LrQ'
    'uDog0L7QtNC40L0g0LfQsNC80LXRgCwg0LfQsNGC0LXQvCDQv9C+0LTQutC70Y7Rh9C10L3QuNC1INC/0L4g0YHQvtGF0YDQ'
    'sNC90ZHQvdC90L7QvNGDINC/0L7RgNGP0LTQutGDLiDQmtCw0LbQtNGL0Lkg0L3QvtCy0YvQuSDQt9Cw0L/Rg9GB0Log4oCU'
    'INGBINC/0LXRgNCy0L7Qs9C+INC80LXRgdGC0LAuIMKr0JLQvtGB0YHRgtCw0L3QvtCy0LjRgtGMwrsg0L/QvtCy0YLQvtGA'
    '0Y/QtdGCINC30LDQvNC10YAuIjsgd3JhcE1vZGU6IFRleHQuV3JhcDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgY29sb3I6'
    'IHJvb3QudGV4dE11dGVkIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiAocm9vdC50dW5uZWwucm91dGVzIHx8IHt9KS5vcmRlciB8fCBbXQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogQy5MYWJlbCB7CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbW9kZWxEYXRhCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBpbnQgaW5kZXgKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICB2YXIgY2hvaWNlcyA9IChyb290LnR1bm5lbC5yb3V0ZXMgfHwge30pLmNob2ljZXMgfHwgW10KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFiZWwgPSBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBpPTA7aTxjaG9pY2VzLmxlbmd0aDtpKyspIGlmIChjaG9pY2VzW2ld'
    'LmlkID09PSBtb2RlbERhdGEpIGxhYmVsPWNob2ljZXNbaV0ubGFiZWwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICByZXR1cm4gKGluZGV4KzEpKyIuICIrbGFiZWwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRy'
    'dWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdyYXBNb2RlOiBUZXh0LldyYXAKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiByb290LnRleHRNdXRlZAogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24g'
    'eyBsYWJlbDogItCe0YLRh9GR0YIg0LTQu9GPINC/0L7QtNC00LXRgNC20LrQuCI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1'
    'c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZzsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiJyZXBvcnQtcHJl'
    'dmlldyJ9LGZ1bmN0aW9uKHJlcGx5KXsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXBvcnQ9SlNPTi5wYXJz'
    'ZShyZXBseS5vdXRwdXQpO3Jvb3QucmVwb3J0SWQ9cmVwb3J0LnJlcG9ydF9pZDtyb290LnJlcG9ydFRleHQ9SlNPTi5zdHJp'
    'bmdpZnkocmVwb3J0LG51bGwsMik7cmVwb3J0Q29uc2VudC5jaGVja2VkPWZhbHNlO3N1cHBvcnREaWFsb2cub3BlbigpCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgIH0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi'
    '0J/RgNC+0LLQtdGA0LjRgtGMINC+0LHQvdC+0LLQu9C10L3QuNGPIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeTsgb25D'
    'bGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiAidXBkYXRlIn0pIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5k'
    'ZXggPj0gMSAmJiByb290LnBhZ2VJbmRleCA8PSA0CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6'
    'IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTYKICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJl'
    'bCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICB3cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50'
    'ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QucGFnZUluZGV4ID09PSAxID8gItCS0YvQ'
    'sdGA0LDQvdC90YvQtSDQv9GA0LjQu9C+0LbQtdC90LjRjyDQv9C+0LTQutC70Y7Rh9Cw0Y7RgtGB0Y8g0L3QsNC/0YDRj9C8'
    '0YPRji4g0J7RgdGC0LDQu9GM0L3Ri9C1INC40YHQv9C+0LvRjNC30YPRjtGCIFZQTi4iIDogcm9vdC5wYWdlSW5kZXggPT09'
    'IDIgPyAi0JTQvtCx0LDQstGM0YLQtSDQtNC+0LzQtdC9LCDQsNC00YDQtdGBINC40LvQuCDQv9C+0LTRgdC10YLRjC4g0JTQ'
    'vtC80LXQvdGLINCy0LrQu9GO0YfQsNGO0YIg0L/QvtC00LTQvtC80LXQvdGLOyDQt9C90LDQuiA9INC30LDQtNCw0ZHRgiDR'
    'gtC+0YfQvdC+0LUg0YHQvtCy0L/QsNC00LXQvdC40LUuINCf0YDQuCDQvtCx0YnQtdC8IElQINC70YPRh9GI0LUg0YPQutCw'
    '0LfRi9Cy0LDRgtGMINC00L7QvNC10L0uIiA6IHJvb3QucGFnZUluZGV4ID09PSAzID8gItCY0YHRhdC+0LTRj9GJ0LjQtSDi'
    'gJQg0L/QvtC00LrQu9GO0YfQtdC90LjRjyDQuiDRg9C60LDQt9Cw0L3QvdC+0LzRgyDQv9C+0YDRgtGDLiDQktGF0L7QtNGP'
    '0YnQuNC1IOKAlCDQv9GA0Y/QvNGL0LUg0L7RgtCy0LXRgtGLINCy0LDRiNC10LPQviDRgdC10YDQstC10YDQsC4g0J7QsdCw'
    'IOKAlCDQvtCx0LAg0L3QsNC/0YDQsNCy0LvQtdC90LjRjy4iIDogItCe0LHRi9GH0L3Ri9C5IEROUyDQvtGB0YLQsNGR0YLR'
    'gdGPINCyIFZQTi4g0JTQvtCx0LDQstC70LXQvdC90YvQtSDQt9C00LXRgdGMIEROUy3RgdC10YDQstC10YDRiyDQv9C+0LvR'
    'g9GH0LDRjtGCINC30LDQv9GA0L7RgdGLINC90LDQv9GA0Y/QvNGD0Y4g0Lgg0LzQvtCz0YPRgiDQstC40LTQtdGC0Ywg0LfQ'
    'sNC/0YDQsNGI0LjQstCw0LXQvNGL0LUg0LjQvNC10L3QsC4g0K3RgtC+INC90LUg0YHQv9C40YHQvtC6INGB0LDQudGC0L7Q'
    'si4iCiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuQ29tYm9Cb3ggeyBpZDogcG9ydFByb3RvY29sOyB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gMzsgbW9kZWw6IFsi'
    'VENQIiwgIlVEUCIsICJCT1RIIl07IExheW91dC5wcmVmZXJyZWRXaWR0aDogMTAwIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIEMuVGV4dEZpZWxkIHsgaWQ6IGV4Y2VwdGlvbklucHV0OyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBzZWxlY3RC'
    'eU1vdXNlOiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6IHJvb3QucGFnZUluZGV4ID09PSAxID8gItCY0LzRjyDQv9GA0L7RhtC1'
    '0YHRgdCwINC40LvQuCAv0L/QvtC70L3Ri9C5L9C/0YPRgtGMIiA6IHJvb3QucGFnZUluZGV4ID09PSAyID8gImV4YW1wbGUu'
    'Y29tINC40LvQuCAxOTIuMTY4LjEuMjAiIDogcm9vdC5wYWdlSW5kZXggPT09IDMgPyAiMjU1NjUiIDogItCQ0LTRgNC10YEg'
    'RE5TLCDQvdCw0L/RgNC40LzQtdGAIDE5Mi4xNjguMS4xIiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJv'
    'Qm94IHsgaWQ6IHBvcnREaXJlY3Rpb247IHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSAzOyBtb2RlbDogWyLQmNGB0YXQ'
    'vtC00Y/RidC40LUiLCAi0JLRhdC+0LTRj9GJ0LjQtSIsICLQntCx0LAiXTsgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiAxNDAg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0JTQvtCx0LDQstC40YLRjCI7IHBy'
    'aW1hcnk6IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgZXhjZXB0aW9uSW5wdXQudGV4dC50cmltKCkubGVu'
    'Z3RoID4gMDsgb25DbGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdmFsdWUgPSByb290'
    'LnBhZ2VJbmRleCA9PT0gMyA/IHBvcnRQcm90b2NvbC5jdXJyZW50VGV4dC50b0xvd2VyQ2FzZSgpICsgIjoiICsgZXhjZXB0'
    'aW9uSW5wdXQudGV4dC50cmltKCkgKyAiOiIgKyBbIm91dCIsICJpbiIsICJib3RoIl1bcG9ydERpcmVjdGlvbi5jdXJyZW50'
    'SW5kZXhdIDogZXhjZXB0aW9uSW5wdXQudGV4dC50cmltKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290'
    'LmFjdGlvbih7YWN0aW9uOiAiYWRkIiwgY2F0ZWdvcnk6IHJvb3QuY2F0ZWdvcnksIHZhbHVlOiB2YWx1ZX0sIGZ1bmN0aW9u'
    'KCkgeyBleGNlcHRpb25JbnB1dC5jbGVhcigpIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9IH0KICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICBtb2RlbDogcm9vdC5wb2xpY3lbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3Bl'
    'cnR5IHN0cmluZyBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YTsgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcEFueXdoZXJlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0KPQtNCw0LvQuNGC0YwiOyBkYW5nZXI6'
    'IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInJlbW92'
    'ZSIsIGNhdGVnb3J5OiByb290LmNhdGVnb3J5LCB2YWx1ZTogbW9kZWxEYXRhfSkgfQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNp'
    'YmxlOiAhKHJvb3QucG9saWN5W3Jvb3QuY2F0ZWdvcnldIHx8IFtdKS5sZW5ndGg7IHRleHQ6ICLQktCw0YjQuNGFINC40YHQ'
    'utC70Y7Rh9C10L3QuNC5INC/0L7QutCwINC90LXRgiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIFJpYmJvblN3aXRjaCB7IHRleHQ6ICLQntGC0L7QsdGA0LDQt9C40YLRjCDQsdCw0LfQvtCy0YvQtSDQuNGB'
    '0LrQu9GO0YfQtdC90LjRjyI7IGNoZWNrZWQ6IHJvb3Quc2hvd0Jhc2U7IG9uVG9nZ2xlZDogcm9vdC5zaG93QmFzZSA9IGNo'
    'ZWNrZWQgfQogICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5zaG93'
    'QmFzZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIG1vZGVsOiAocm9vdC5wb2xpY3kuYmFzZSB8fCB7fSlbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgcmVxdWlyZWQgcHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBM'
    'YXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0'
    'OiBtb2RlbERhdGEubGFiZWw7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiBy'
    'b290LnRleHRNYWluIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmliYm9uU3dpdGNoIHsgY2hlY2tl'
    'ZDogQm9vbGVhbihtb2RlbERhdGEuZW5hYmxlZCk7IGVuYWJsZWQ6ICFyb290LmJ1c3k7IG9uVG9nZ2xlZDogcm9vdC5hY3Rp'
    'b24oe2FjdGlvbjogImJhc2UiLCBjYXRlZ29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IG1vZGVsRGF0YS5pZCwgZW5hYmxl'
    'ZDogY2hlY2tlZH0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3Jh'
    'cE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiAi0JLRiyDQvNC+0LbQtdGC0LUg0LLRi9C6'
    '0LvRjtGH0LjRgtGMINC70Y7QsdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uINCh0LrRgNGL0YLQuNC1INGB'
    '0L/QuNGB0LrQsCDQvdC1INC80LXQvdGP0LXRgiDQtdCz0L4g0YHQvtGB0YLQvtGP0L3QuNC1LiIgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQl9Cw0L/Rg9GJ'
    '0LXQvdGLINGB0LXQudGH0LDRgSI7IGZvbnQucGl4ZWxTaXplOiAxODsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50'
    'ZXh0TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRG'
    'aWVsZCB7IGlkOiBhcHBTZWFyY2g7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHBsYWNlaG9sZGVyVGV4dDogItCf0L7QuNGB'
    '0Log0L/RgNC40LvQvtC20LXQvdC40Y8iIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsg'
    'bGFiZWw6ICLQntCx0L3QvtCy0LjRgtGMINGB0L/QuNGB0L7QuiI7IGVuYWJsZWRCdXR0b246ICFyb290LnJ1bm5pbmdQZW5k'
    'aW5nOyBvbkNsaWNrZWQ6IHJvb3QucmVmcmVzaFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9k'
    'ZWw6IHJvb3QucGFnZUluZGV4ID09PSAxID8gcm9vdC5maWx0ZXJlZFJ1bm5pbmcoKSA6IFtdCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgZGVsZWdhdGU6IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YS5uYW1lOyBjb2xvcjogcm9v'
    'dC50ZXh0TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9k'
    'ZWxEYXRhLmV4ZTsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGU7IGNvbG9yOiByb290'
    'LnRleHRNdXRlZDsgZm9udC5waXhlbFNpemU6IDExIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6IG1vZGVsRGF0YS5leGNsdWRl'
    'ZCA/ICLQlNC+0LHQsNCy0LvQtdC90L4iIDogItCSINC+0LHRhdC+0LQiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYm'
    'ICFtb2RlbERhdGEuZXhjbHVkZWQ7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImFkZCIsIGNhdGVnb3J5OiAi'
    'YXBwbGljYXRpb25zIiwgdmFsdWU6IFN0cmluZyhtb2RlbERhdGEuZXhlIHx8IG1vZGVsRGF0YS5uYW1lIHx8ICIiKX0pIH0K'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0'
    'IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDUKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxOAogICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3Jh'
    'cDsgY29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiAiV2F5ZHJvaWQg0YPQv9GA0LDQstC70Y/QtdGC0YHRjyDQvtGC0LTQ'
    'tdC70YzQvdC+INC+0YIg0L/RgNC40LvQvtC20LXQvdC40Lkg0LrQvtC80L/RjNGO0YLQtdGA0LAuINCf0L4g0YPQvNC+0LvR'
    'h9Cw0L3QuNGOINCy0LXRgdGMINC10LPQviDRgtGA0LDRhNC40LosINCy0LrQu9GO0YfQsNGPIEROUywg0LjQtNGR0YIg0L3Q'
    'sNC/0YDRj9C80YPRji4iIH0KICAgICAgICAgICAgICAgICAgICAgICAgUmliYm9uU3dpdGNoIHsgdGV4dDogIldheWRyb2lk'
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

def _write_owner_text(path: pathlib.Path, text: str, uid: int, gid: int, mode=0o644) -> None:
    fd, tmpname = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fchown(f.fileno(), uid, gid)
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmpname, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)

def _registration_matches(home: pathlib.Path, path: pathlib.Path, expected: bytes, uid: int, gid: int) -> bool:
    # The owner's home is a configured destination. Below it, never follow links
    # while comparing these small user-controlled files with packaged metadata.
    relative = path.relative_to(home)
    dir_flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
    try:
        with contextlib.ExitStack() as opened:
            directory = os.open(home, dir_flags)
            opened.callback(os.close, directory)
            for name in relative.parts[:-1]:
                directory = os.open(name, dir_flags | os.O_NOFOLLOW, dir_fd=directory)
                opened.callback(os.close, directory)
            fd = os.open(relative.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            opened.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_size != len(expected) or
                    info.st_uid != uid or info.st_gid != gid or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o644):
                return False
            # Reopen the pinned regular inode, not the user-controlled pathname.
            with open(f"/proc/self/fd/{fd}", "rb", buffering=0) as current:
                if current.read(len(expected) + 1) != expected:
                    return False
            after = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
            return os.path.samestat(info, after) and info.st_ctime_ns == after.st_ctime_ns
    except OSError:
        return False

def _install_registration(settings: dict, path: pathlib.Path, text: str, uid: int, gid: int) -> bool:
    if _registration_matches(pathlib.Path(settings["owner_home"]), path, text.encode("utf-8"), uid, gid):
        return False
    _write_owner_text(path, text, uid, gid)
    return True

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

def _install_gui_files(settings: dict) -> bool:
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
    _write_owner_text(package / "evgenium_gui.py", gui_py, uid, gid, mode=0o755)
    _write_owner_text(package / "evgenium_gui.qml", gui_qml, uid, gid)
    _write_owner_text(icon, APP_ICON_SVG, uid, gid)
    changed = _install_registration(settings, desktop, GUI_DESKTOP_ENTRY, uid, gid)
    ok(f"Evgenium Network GUI установлен: {package}")
    return changed

def _install_desktop_integration(settings: dict, *, widget: bool, force_cache: bool) -> None:
    changed = _install_gui_files(settings)
    try:
        if widget:
            widget_changed = _install_widget_files(settings)
            changed = changed or widget_changed
    finally:
        # A widget install can fail after the desktop entry was already published.
        if force_cache or changed:
            kbuild = shutil.which("kbuildsycoca6")
            if kbuild:
                run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))

def cmd_gui_install(settings: dict) -> None:
    _install_desktop_integration(settings, widget=False, force_cache=True)

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

def _install_widget_files(settings: dict) -> bool:
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

    _write_owner_text(ui / "main.qml", PLASMOID_MAIN_QML, uid, gid)
    changed = _install_registration(settings, package / "metadata.json", PLASMOID_METADATA, uid, gid)
    ok(f"Plasma 6 виджет установлен: {package}")
    print("Шестерёнка E-VPN открывает отдельное приложение Evgenium Network.")
    return changed

def cmd_widget_install(settings: dict) -> None:
    _install_desktop_integration(settings, widget=True, force_cache=True)

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
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", version):
        fail("Некорректный VERSION.")
    os.chmod(dest / "vpnctl.py", 0o755)
    os.chmod(dest / "vpnadmin.py", 0o755)
    return version

def uses_legacy_tunnel_layout(release):
    with (release / "vpnctl.py").open("rb") as program:
        return any(line.startswith(b"STARFIVE_TUNNEL_PY_B64 =") for line in program)

def install_manager_release(unpack, version):
    """Activate a verified bundle while holding operation.lock. Keep installed releases intact."""
    if uses_legacy_tunnel_layout(unpack):
        vpn_tunnel.select_installed_layout()
        pending = vpn_tunnel.transition_layouts()
        if pending and not vpn_tunnel.move_idle_layout(*pending):
            fail("Для установки предыдущей версии сначала отключите VPN.")
        if vpn_tunnel.layout_in_use(vpn_tunnel.LAYOUT):
            fail("Для установки предыдущей версии отключите VPN или используйте vpn-manager-admin rollback.")
        if vpn_tunnel.LAYOUT == vpn_tunnel.CURRENT and not vpn_tunnel.move_idle_layout(vpn_tunnel.CURRENT, vpn_tunnel.LEGACY):
            fail("Предыдущая версия не может прочитать текущие файлы служб VPN. Установка сохранена.")

    dest = RELEASES / version
    if dest.exists():
        # A local reinstall can have the same version but different contents.
        # Never replace the files of the running manager or the rollback copy.
        if not all((dest / name).is_file() and (dest / name).read_bytes() == (unpack / name).read_bytes()
                   for name in ("vpnctl.py", "vpnadmin.py", "VERSION")):
            dest = pathlib.Path(tempfile.mkdtemp(prefix=version + "-install-", dir=RELEASES))
            unpack.replace(dest)
    else:
        unpack.rename(dest)

    old = CURRENT.resolve() if CURRENT.exists() else None
    if old and old != dest:
        link = PREVIOUS.with_name(".previous.new")
        link.unlink(missing_ok=True)
        link.symlink_to(old)
        os.replace(link, PREVIOUS)
    for path, target in ((CURRENT, dest), (pathlib.Path("/usr/local/sbin/vpnctl"), CURRENT / "vpnctl.py"),
                         (pathlib.Path("/usr/local/sbin/vpn-manager-admin"), CURRENT / "vpnadmin.py")):
        link = path.with_name(path.name + ".new")
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        os.replace(link, path)

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

        install_manager_release(unpack, version)

    info(f"Файлы VPN Manager {version} получены. Завершаю установку...")
    os.execv(
        "/usr/local/sbin/vpnctl",
        ["/usr/local/sbin/vpnctl", "internal-after-update"]
    )

def manager_rollback() -> None:
    if not PREVIOUS.exists():
        fail("Нет previous manager release.")
    target = pathlib.Path(os.path.realpath(PREVIOUS))
    if target.parent != RELEASES.resolve():
        fail("Предыдущая версия должна находиться в каталоге установленных выпусков.")
    cp = run(
        [sys.executable, str(target / "vpnctl.py"), "--self-test"],
        check=False, capture=True
    )
    if cp.returncode != 0:
        fail("Previous manager не проходит self-test.")
    # Older token clients can only read the original installation layout.
    if uses_legacy_tunnel_layout(target):
        pending = vpn_tunnel.transition_layouts()
        if pending and not vpn_tunnel.move_idle_layout(*pending):
            fail("Для завершения переноса и отката сначала отключите VPN.")
        if vpn_tunnel.LAYOUT == vpn_tunnel.CURRENT:
            if vpn_tunnel.layout_in_use(vpn_tunnel.CURRENT):
                vpn_tunnel.write(ROLLBACK_PENDING, str(target))
                info("Откат сохранён и завершится при обычном отключении VPN.")
                return
            if not vpn_tunnel.move_idle_layout(vpn_tunnel.CURRENT, vpn_tunnel.LEGACY):
                fail("Конфликт локальных файлов служб VPN. Текущая установка сохранена.")
    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(target)
    os.replace(newlink, CURRENT)
    pathlib.Path("/usr/local/sbin/vpnctl.new").unlink(missing_ok=True)
    os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")
    ROLLBACK_PENDING.unlink(missing_ok=True)
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


VPN_TUNNEL_PY_B64 = (
    'IiIiVG9rZW4gSUtFdjIgY2xpZW50OiBpc29sYXRlZCB0cmFuc3BvcnQgYW5kIGd1YXJkZWQgZnVsbC1kZXZpY2UgRXN0b25p'
    'YSBlZ3Jlc3MuIiIiCmltcG9ydCBjb250ZXh0bGliCmltcG9ydCBlcnJubwppbXBvcnQgZmNudGwKaW1wb3J0IGhhc2hsaWIK'
    'aW1wb3J0IGh0dHAuY2xpZW50CmltcG9ydCBpcGFkZHJlc3MKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmZyb20gcGF0aGxpYiBp'
    'bXBvcnQgUGF0aAppbXBvcnQgcmUKaW1wb3J0IHNlY3JldHMKaW1wb3J0IHNodXRpbAppbXBvcnQgc2lnbmFsCmltcG9ydCBz'
    'b2NrZXQKaW1wb3J0IHBsYXRmb3JtCmltcG9ydCB1cmxsaWIucmVxdWVzdAppbXBvcnQgc3NsCmltcG9ydCBzdGF0CmltcG9y'
    'dCBzdWJwcm9jZXNzCmltcG9ydCB0ZW1wZmlsZQppbXBvcnQgdGltZQppbXBvcnQgc3lzCmZyb20gdHlwaW5nIGltcG9ydCBO'
    'YW1lZFR1cGxlCgpjbGFzcyBMYXlvdXQoTmFtZWRUdXBsZSk6CiAgICByb290OiBQYXRoCiAgICBydW50aW1lOiBQYXRoCiAg'
    'ICBzdGF0ZTogUGF0aAogICAgdW5pdDogc3RyCiAgICByZWNvdmVyeTogc3RyCiAgICBndWFyZDogc3RyCiAgICBuYW1lc3Bh'
    'Y2U6IHN0cgogICAgaG9zdDogc3RyCiAgICBwZWVyOiBzdHIKICAgIGhvc3RfdGFibGU6IHN0cgogICAgbmFtZXNwYWNlX3Rh'
    'YmxlOiBzdHIKICAgIGd1YXJkX3RhYmxlOiBzdHIKICAgIGNvbW1hbmRfcHJlZml4OiBzdHIKICAgIGlrZTogc3RyCgoKQ1VS'
    'UkVOVCA9IExheW91dChQYXRoKCcvZXRjL3Zwbi1tYW5hZ2VyL3R1bm5lbCcpLCBQYXRoKCcvcnVuL2V2Z2VuaXVtLXZwbicp'
    'LAogICAgICAgICAgICAgICAgIFBhdGgoJy92YXIvbGliL3Zwbi1tYW5hZ2VyL3R1bm5lbC5qc29uJyksCiAgICAgICAgICAg'
    'ICAgICAgJ2V2Z2VuaXVtLXZwbi5zZXJ2aWNlJywgJ2V2Z2VuaXVtLXZwbi1yZWNvdmVyeS5zZXJ2aWNlJywgJ2V2Z2VuaXVt'
    'LXZwbi1raWxsc3dpdGNoLnNlcnZpY2UnLAogICAgICAgICAgICAgICAgICdldm4tdnBuJywgJ2V2bi12cG4taG9zdCcsICdl'
    'dm4tdnBuLXBlZXInLCAnZXZnZW5pdW1fdnBuX2hvc3QnLAogICAgICAgICAgICAgICAgICdldmdlbml1bV92cG5fbmFtZXNw'
    'YWNlJywgJ2V2Z2VuaXVtX3Zwbl9ndWFyZCcsICdpbnRlcm5hbC12cG4nLCAnZXZnZW5pdW0tdnBuJykKIyBWZXJzaW9ucyB0'
    'aHJvdWdoIDAuNS44IHVzZWQgdGhlIGZvcm1lciBpbmdyZXNzIGhvc3QncyBuYW1lIGZvciBsb2NhbCByZXNvdXJjZXMuCkxF'
    'R0FDWSA9IExheW91dChQYXRoKCcvZXRjL3Zwbi1tYW5hZ2VyL3N0YXJmaXZlLXR1bm5lbCcpLCBQYXRoKCcvcnVuL2V2Z2Vu'
    'aXVtLXN0YXJmaXZlLXR1bm5lbCcpLAogICAgICAgICAgICAgICAgUGF0aCgnL3Zhci9saWIvdnBuLW1hbmFnZXIvc3RhcmZp'
    'dmUtdHVubmVsLmpzb24nKSwKICAgICAgICAgICAgICAgICdldmdlbml1bS1zdGFyZml2ZS10dW5uZWwuc2VydmljZScsICdl'
    'dmdlbml1bS1zdGFyZml2ZS10dW5uZWwtcmVjb3Zlci5zZXJ2aWNlJywKICAgICAgICAgICAgICAgICdldmdlbml1bS1zdGFy'
    'Zml2ZS1mdWxsLWd1YXJkLnNlcnZpY2UnLCAnZXZuLXN0YXJmaXZlJywgJ2V2bi1zZi1ob3N0JywgJ2V2bi1zZi1wZWVyJywK'
    'ICAgICAgICAgICAgICAgICdldmdlbml1bV9zdGFyZml2ZV9sYWJfaG9zdCcsICdldm5fc3RhcmZpdmVfZ3VhcmQnLCAnZXZu'
    'X3N0YXJmaXZlX2Z1bGwnLCAnaW50ZXJuYWwtc3RhcmZpdmUnLCAnc3RhcmZpdmUnKQpVTklUX0RJUiA9IFBhdGgoJy9ldGMv'
    'c3lzdGVtZC9zeXN0ZW0nKQpMQVlPVVRfVFJBTlNBQ1RJT04gPSBQYXRoKCcvdmFyL2xpYi92cG4tbWFuYWdlci90dW5uZWwt'
    'bGF5b3V0LXRyYW5zaXRpb24nKQoKCmRlZiB1c2VfbGF5b3V0KGxheW91dCk6CiAgICBnbG9iYWwgTEFZT1VULCBST09ULCBS'
    'VU5USU1FLCBTVEFURSwgVU5JVCwgUkVDT1ZFUllfVU5JVCwgR1VBUkRfVU5JVCwgTlMsIEhPU1QsIFBFRVIsIE5GVCwgTkFN'
    'RVNQQUNFX0dVQVJELCBGVUxMX0dVQVJECiAgICBMQVlPVVQgPSBsYXlvdXQKICAgIFJPT1QsIFJVTlRJTUUsIFNUQVRFID0g'
    'bGF5b3V0LnJvb3QsIGxheW91dC5ydW50aW1lLCBsYXlvdXQuc3RhdGUKICAgIFVOSVQsIFJFQ09WRVJZX1VOSVQsIEdVQVJE'
    'X1VOSVQgPSBsYXlvdXQudW5pdCwgbGF5b3V0LnJlY292ZXJ5LCBsYXlvdXQuZ3VhcmQKICAgIE5TLCBIT1NULCBQRUVSID0g'
    'bGF5b3V0Lm5hbWVzcGFjZSwgbGF5b3V0Lmhvc3QsIGxheW91dC5wZWVyCiAgICBORlQsIE5BTUVTUEFDRV9HVUFSRCwgRlVM'
    'TF9HVUFSRCA9IGxheW91dC5ob3N0X3RhYmxlLCBsYXlvdXQubmFtZXNwYWNlX3RhYmxlLCBsYXlvdXQuZ3VhcmRfdGFibGUK'
    'Cgp1c2VfbGF5b3V0KENVUlJFTlQpCk5FVFdPUksgPSAnMTcyLjI5LjI0Ni4wLzMwJwpDTElFTlQgPSAnMTcyLjI5LjI0Ni4y'
    'JwpHQVRFV0FZID0gJzE3Mi4yOS4yNDYuMScKVEFCTEUgPSA1MTgyNApQUklPUklUWSA9IDc1ClNFUlZFUiA9ICcxOTUuMjA5'
    'LjIxMS4xNjMnCklLRV9QT1JUID0gMjQ1NTAKRU5EUE9JTlRTID0gKFNFUlZFUiwgJzM4LjE4MC4xNjQuNjcnKQpDQU5ESURB'
    'VEVTID0gKAogeydpZCc6J3J1LXVkcCcsJ2FkZHJlc3MnOlNFUlZFUiwnaWRlbnRpdHknOlNFUlZFUiwncG9ydCc6MjQ1NTAs'
    'J3Rscyc6RmFsc2UsJ2xhYmVsJzonSFNWRFMg4oaSINCt0YHRgtC+0L3QuNGPJ30sCiB7J2lkJzonZWUtdGxzJywnYWRkcmVz'
    'cyc6JzM4LjE4MC4xNjQuNjcnLCdpZGVudGl0eSc6JzM4LjE4MC4xNjQuNjcnLCdwb3J0Jzo0NDMsJ3Rscyc6VHJ1ZSwnbGFi'
    'ZWwnOifQrdGB0YLQvtC90LjRjyDRh9C10YDQtdC3IFRMUyd9LAogeydpZCc6J2VlLWV2Z3QnLCdhZGRyZXNzJzonMzguMTgw'
    'LjE2NC42NycsJ2lkZW50aXR5JzonMzguMTgwLjE2NC42NycsJ3BvcnQnOjQ0MywndGxzJzpGYWxzZSwnZXZndCc6VHJ1ZSwn'
    'bGFiZWwnOifQrdGB0YLQvtC90LjRjyDRh9C10YDQtdC3IEV2Z2VuaXVtVHVubmVsJ30sCiB7J2lkJzonZWUtZXZndC1ydScs'
    'J2FkZHJlc3MnOiczOC4xODAuMTY0LjY3JywnaWRlbnRpdHknOiczOC4xODAuMTY0LjY3JywncG9ydCc6NDQzLCd0bHMnOkZh'
    'bHNlLCdldmd0JzpUcnVlLCd0cmFuc3BvcnRfYWRkcmVzcyc6U0VSVkVSLCd0cmFuc3BvcnRfcG9ydCc6MjQ1NzksJ2xhYmVs'
    'JzonRXZnZW5pdW1UdW5uZWwgwrcgSFNWRFMg4oaSINCt0YHRgtC+0L3QuNGPJ30sCikKQUNUSVZFID0gQ0FORElEQVRFU1sw'
    'XQpyYW5rX2FwaSA9IE5vbmUKc3VwcG9ydF9hcGkgPSBOb25lCnRsc19hcGkgPSBOb25lClRMU19QUk9DRVNTID0gTm9uZQoj'
    'IEtlcHQgb25seSBmb3IgcmVtb3Zpbmcgcm91dGVzIGluc3RhbGxlZCBieSBwcmUtbWlncmF0aW9uIHZlcnNpb25zLgpMRUdB'
    'Q1lfRU5EUE9JTlRTID0gKCcxMDkuMTk0LjY3LjE1OScsICcxOTIuMTY4LjAuMTYzJykKSEVBTFRIID0gJzEwLjc3LjAuMScK'
    'UkVRSUQgPSAxNzcKVE9LRU5fUEFUVEVSTiA9IHInRVZOMS1bQS1aYS16MC05Xy1dezQzfScKU1RPUCA9IEZhbHNlCkROU19Q'
    'Uk9DRVNTID0gTm9uZQpwb2xpY3kgPSBOb25lClBJTk5FRF9DQSA9ICctLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS1cbk1J'
    'SUVPRENDQXFDZ0F3SUJBZ0lVYmtKKzhTYXFBZ3dZMVJEQWpaUlRqY3FROWVNd0RRWUpLb1pJaHZjTkFRRUxcbkJRQXdJakVn'
    'TUI0R0ExVUVBd3dYUlhablpXNXBkVzBnY0hKcGRtRjBaU0JXVUU0Z1EwRXdIaGNOTWpZeE1EQTNcbk1Ua3hNelF4V2hjTk16'
    'WXhNREEwTVRreE16UXhXakFpTVNBd0hnWURWUVFEREJkRmRtZGxibWwxYlNCd2NtbDJcbllYUmxJRlpRVGlCRFFUQ0NBYUl3'
    'RFFZSktvWklodmNOQVFFQkJRQURnZ0dQQURDQ0FZb0NnZ0dCQU9aK252aUVcbjJPckY3UGR0a2svWElhRlZJdkpsdkMxMVZa'
    'ZjlybGpDQkl2QnlrYnNyQXJHcnlRSEdudXVYTE5hYVM4TnRMeFlcbk5lU0JESzZNZGdZSkFlanNQNHdJVHViM25NalNHMnVt'
    'SUlWVTZtRStHRG96R1BsTk1OSitiaGtLYVZoYVBqRkVcbnlZTFlyZFBlNVZBNHcrNXAwTlpPRDZDQkhEM3RFWFdCTlJJZVZT'
    'V2J0TUlUc09FUzFQZS9hQUw3djNvTklWa1ZcbjhuRHc5ajcrd0cyeTVkaGJwN0tVSkhickRCMDI0cjdjWXJRM2F4WUY2Z3lr'
    'am16dHBLWHNia3hRdjI3QnZoU0JcbmUwRWt0Si9qQ1M2UjlJSW1ZZ0lRckNyYVdabVZTY25HRi9BcTRUTncxSDRPekZDa1Ir'
    'N0pVbFluU1lVdk1SaTFcbkx6S2VrVUMrMi8wV0ZtaG5Db0R0ZGpjb1lieHBMcEtEZWxHaVMzUnNOQ3Z4bnNsTWFQejVoQ2NG'
    'NjRZN1Jpalhcbmo2RHVDWXBGWVdscjEzQjIwcUFuUm9VYXMrQWpYN1BYQ2tSNHhPaEgra1c4L0htRkhpSGtvaFdFMHdsbElT'
    'QlhcblZCbzdLQk9aZDhTVmV3eWJkMnJCNHNvWG91VHRqWHMvalRnZStIV3hRREdQUDF1bWZ6OGNGTFIvdVFJREFRQUJcbm8y'
    'WXdaREFkQmdOVkhRNEVGZ1FVb1FmVGlmNzd4V3QwNmhhWGgzaGE4OTBxa1Q4d0h3WURWUjBqQkJnd0ZvQVVcbm9RZlRpZjc3'
    'eFd0MDZoYVhoM2hhODkwcWtUOHdFZ1lEVlIwVEFRSC9CQWd3QmdFQi93SUJBREFPQmdOVkhROEJcbkFmOEVCQU1DQVFZd0RR'
    'WUpLb1pJaHZjTkFRRUxCUUFEZ2dHQkFJN0dLbm1mSmp1TDFRdnlSdGx3K0hyNkFZL1pcbk94ZER2RUNlZm9GTDdRNDFWWmEr'
    'TDdESTg3a01MWUh5Z1JIdXNoNjZvVXY4NzhUV010YXNuYnQvOHdZZzZqcndcbkF5Z3BnL0YzVkQyNHlUcm5KN09DZHlHaWI2'
    'TEd1dXN1VFA0clVHc2NjV2N6blFYWUZrelJWejFWZVlNWlVOK1BcbnRBVmlObDRFUlMxZmgrY0d6VDRPcVhRa0pEa1JlcUgv'
    'SENURThrVVFVVWdYYVNYcGhLakdhOHBSMkhWZUZ1a1hcbiswcHAxaVIrNmRpNGFDS2Fwa2FUaVZSM3I2MnRSQlV3YnhvRllS'
    'eXhOWHluVEs5RWhuTTI1V0Vwbi9xdTBsc0Rcbm9YckZWbWowQVFmQVVIUk4vMnJQTC8vdzZSUEVwSGdVY3J0N3p1U2dvWEpa'
    'aDBEVDMwVkVJSzlOTmJ1S1NGZDlcbklpV3ZyeGJWUVM2bVFndEVaTjRMYzJIbTFwdlkrV3JJK0gwM3U4MDQyK2NwTElzQ254'
    'UG05V3ZpN2RNWHhxb2Jcbm8yL2FMMnhERzVHLzhXVlIvVzVFQWZ2S2R4ZHJrM0g2MDJvY2NvdjcrSmcxdm94aTAwSWJkTUV4'
    'b014ZDVhZWhcbmZYUmlKaFRFRm91SXBtRVNDRjR2Vk1sV0ZyM21xbFEzR0tTUFZBPT1cbi0tLS0tRU5EIENFUlRJRklDQVRF'
    'LS0tLS1cbicKCgpGVUxMX0hPU1QgPSAnZXZuLWZ1bGwtaG9zdCcKRlVMTF9QRUVSID0gJ2V2bi1mdWxsLXBlZXInCkZVTExf'
    'TkVUID0gJzE3Mi4yOS4yNDcuMC8zMCcKRlVMTF9UQUJMRSA9ICc1MTgyOCcKQURNSU5fVEFCTEUgPSAnNTE4MjknCmRlZiBm'
    'dWxsX3N0YXRlKCk6CiAgICByZXR1cm4gUk9PVC8nZnVsbC1uZXR3b3JrLmpzb24nCgoKZGVmIGNoYXJvbl9iaW5hcnkoKToK'
    'ICAgIGNhbmRpZGF0ZXMgPSAoJy91c3Ivc2Jpbi9jaGFyb24tc3lzdGVtZCcsICcvdXNyL2Jpbi9jaGFyb24tc3lzdGVtZCcs'
    'CiAgICAgICAgICAgICAgICAgICcvdXNyL2xpYi9pcHNlYy9jaGFyb24tc3lzdGVtZCcsICcvdXNyL2xpYmV4ZWMvaXBzZWMv'
    'Y2hhcm9uLXN5c3RlbWQnLAogICAgICAgICAgICAgICAgICAnL3Vzci9saWIvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCcs'
    'ICcvdXNyL2xpYmV4ZWMvc3Ryb25nc3dhbi9jaGFyb24tc3lzdGVtZCcpCiAgICByZXR1cm4gbmV4dCgocCBmb3IgcCBpbiBj'
    'YW5kaWRhdGVzIGlmIFBhdGgocCkuaXNfZmlsZSgpKSwgTm9uZSkKCgpFVkdUX1ZFUlNJT04gPSAnMC4zLjAnCkVWR1RfQVNT'
    'RVRTID0gewogJ3g4Nl82NCc6ICgnYW1kNjQnLCdmZGNjOTRkNjVlYTZjM2RhNzY4ZjY2NjYwMDIxNzgzZGFhNDVjMzY1NmNj'
    'OTQ2YmFmZDUxMTFhODZiYjI4NWE2JyksCiAnYWFyY2g2NCc6ICgnYXJtNjQnLCc0MzMzYzFhNzRiYWRhYjYzODdlOGE1YmJm'
    'MmYxZTJmNGY0MDlkYTIwMzdlOTRiMzJlODQ2NmI3MDA2ODhjMDJkJyksCiAncmlzY3Y2NCc6ICgncmlzY3Y2NCcsJ2ZjMGMx'
    'NGMwZmI0YmQwYWVjMjJkNzcxYmFkMjEzMWY3YTVkZjA1OWQ2ZjdmYjUzN2M0NjVmMWYyYWUyNWEyMWYnKSwKfQoKZGVmIGVu'
    'c3VyZV9ldmd0X2JpbmFyeSgpOgogICAgYXNzZXQ9RVZHVF9BU1NFVFMuZ2V0KHBsYXRmb3JtLm1hY2hpbmUoKSkKICAgIGlm'
    'IGFzc2V0IGlzIE5vbmU6cmFpc2UgUnVudGltZUVycm9yKCdldmd0X2FyY2hfdW5zdXBwb3J0ZWQnKQogICAgYXJjaCxkaWdl'
    'c3Q9YXNzZXQKICAgIHBhdGg9Uk9PVC8oJ2V2Z2VuaXVtLXR1bm5lbC0nK0VWR1RfVkVSU0lPTikKICAgIGlmIHBhdGguaXNf'
    'c3ltbGluaygpOnJhaXNlIFJ1bnRpbWVFcnJvcignZXZndF9iaW5hcnlfc3ltbGluaycpCiAgICBpZiBwYXRoLmlzX2ZpbGUo'
    'KSBhbmQgaGFzaGxpYi5zaGEyNTYocGF0aC5yZWFkX2J5dGVzKCkpLmhleGRpZ2VzdCgpPT1kaWdlc3Q6CiAgICAgICAgcGF0'
    'aC5jaG1vZCgwbzcwMCk7cmV0dXJuIHBhdGgKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCxwYXJlbnRzPVRydWUsZXhpc3Rf'
    'b2s9VHJ1ZSkKICAgIHVybD0naHR0cHM6Ly9naXRodWIuY29tL3ZlbGlraWlldmdlbml1c3VsdGltYXRlL0V2Z2VuaXVtX05l'
    'dHdvcmtfTGludXgvcmVsZWFzZXMvZG93bmxvYWQvZXZnZW5pdW0tdHVubmVsLXYnK0VWR1RfVkVSU0lPTisnL2V2Z2VuaXVt'
    'LXR1bm5lbC1saW51eC0nK2FyY2gKICAgIHdpdGggdXJsbGliLnJlcXVlc3QudXJsb3Blbih1cmwsdGltZW91dD0zMCkgYXMg'
    'cmVzcG9uc2U6YmxvYj1yZXNwb25zZS5yZWFkKDE2KjEwMjQqMTAyNCsxKQogICAgaWYgbGVuKGJsb2IpPjE2KjEwMjQqMTAy'
    'NCBvciBoYXNobGliLnNoYTI1NihibG9iKS5oZXhkaWdlc3QoKSE9ZGlnZXN0OgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cignZXZndF9iaW5hcnlfY2hlY2tzdW1fZmFpbGVkJykKICAgIHRtcD1wYXRoLndpdGhfbmFtZShwYXRoLm5hbWUrJy5uZXcn'
    'KQogICAgZmQ9b3Mub3Blbih0bXAsb3MuT19XUk9OTFl8b3MuT19DUkVBVHxvcy5PX1RSVU5DfG9zLk9fTk9GT0xMT1csMG83'
    'MDApCiAgICB0cnk6CiAgICAgICAgd2l0aCBvcy5mZG9wZW4oZmQsJ3diJykgYXMgb3V0cHV0Om91dHB1dC53cml0ZShibG9i'
    'KTtvdXRwdXQuZmx1c2goKTtvcy5mc3luYyhvdXRwdXQuZmlsZW5vKCkpCiAgICAgICAgb3MuY2htb2QodG1wLDBvNzAwKTtv'
    'cy5yZXBsYWNlKHRtcCxwYXRoKQogICAgZmluYWxseTp0bXAudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHJldHVybiBw'
    'YXRoCgoKZGVmIGVuc3VyZV9kZXBlbmRlbmNpZXMoKToKICAgIGlmIGNoYXJvbl9iaW5hcnkoKSBhbmQgYWxsKHNodXRpbC53'
    'aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwnLCdpcCcsJ25mdCcsJ2N1cmwnLCdvcGVuc3NsJywnY29ubnRyYWNrJykpOgog'
    'ICAgICAgIGVuc3VyZV9ldmd0X2JpbmFyeSgpCiAgICAgICAgcmV0dXJuCiAgICBzdGFnZSgnZGVwZW5kZW5jaWVzJywgJ9Cj'
    '0YHRgtCw0L3QsNCy0LvQuNCy0LDRjiDQvdC10L7QsdGF0L7QtNC40LzRi9C1INGB0LjRgdGC0LXQvNC90YvQtSDQutC+0LzQ'
    'v9C+0L3QtdC90YLRiyBWUE4uJywgMywgYWN0aXZlPUZhbHNlKQogICAgaWYgc2h1dGlsLndoaWNoKCdwYWNtYW4nKToKICAg'
    'ICAgICBhcmdzID0gWydwYWNtYW4nLCctUycsJy0tbmVlZGVkJywnLS1ub2NvbmZpcm0nLCdzdHJvbmdzd2FuJywnaXByb3V0'
    'ZTInLCduZnRhYmxlcycsJ2N1cmwnLCdvcGVuc3NsJywnY2EtY2VydGlmaWNhdGVzJywnY29ubnRyYWNrLXRvb2xzJ10KICAg'
    'IGVsaWYgc2h1dGlsLndoaWNoKCdkbmYnKToKICAgICAgICBhcmdzID0gWydkbmYnLCdpbnN0YWxsJywnLXknLCctLXNldG9w'
    'dD1pbnN0YWxsX3dlYWtfZGVwcz1GYWxzZScsJ3N0cm9uZ3N3YW4nLCdpcHJvdXRlJywnbmZ0YWJsZXMnLCdjdXJsJywnb3Bl'
    'bnNzbCcsJ2NhLWNlcnRpZmljYXRlcycsJ2Nvbm50cmFjay10b29scyddCiAgICBlbHNlOgogICAgICAgIHJhaXNlIFJ1bnRp'
    'bWVFcnJvcign0JDQstGC0L7QvNCw0YLQuNGH0LXRgdC60LDRjyDRg9GB0YLQsNC90L7QstC60LAg0LrQu9C40LXQvdGC0LAg'
    '0L/QvtC00LTQtdGA0LbQuNCy0LDQtdGCIEFyY2gg0LggRmVkb3JhLicpCiAgICBjb21tYW5kKGFyZ3MsIHRpbWVvdXQ9MzAw'
    'KQogICAgaWYgbm90IGNoYXJvbl9iaW5hcnkoKSBvciBub3QgYWxsKHNodXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5j'
    'dGwnLCdjb25udHJhY2snKSk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQn9Cw0LrQtdGCIHN0cm9uZ1N3YW4g0L3Q'
    'tSDQv9GA0LXQtNC+0YHRgtCw0LLQuNC7INC90LXQvtCx0YXQvtC00LjQvNGL0LUg0L/RgNC+0LPRgNCw0LzQvNGLLicpCiAg'
    'ICBlbnN1cmVfZXZndF9iaW5hcnkoKQoKCmRlZiBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPUZhbHNlKToKICAg'
    'ICIiIkZvcmdldCBvbmx5IHRoaXMgbWFuYWdlcidzIG9ic29sZXRlIEROUyBOQVQsIG5ldmVyIGZsdXNoIGFsbCBjb25uZWN0'
    'aW9ucy4KCiAgICBSZW1vdmluZyBhbiBuZnQgTkFUIGNoYWluIGRvZXMgbm90IHJlbW92ZSBleGlzdGluZyBjb25udHJhY2sg'
    'dHJhbnNsYXRpb25zLgogICAgQSBydW5uaW5nIHJlc29sdmVyIGNhbiByZXVzZSBpdHMgVURQIHNvY2tldCBpbmRlZmluaXRl'
    'bHkgYWZ0ZXIgYSBWUE4gc3dpdGNoLgogICAgIiIiCiAgICBmaWx0ZXJzID0gKFsnLS1yZXBseS1wb3J0LXNyYycsJzE4NTUz'
    'J10gaWYgcHJldmlvdXNfdnBuIGVsc2UKICAgICAgICAgICAgICAgWyctLXJlcGx5LXBvcnQtc3JjJywnNTMnLCctLWRzdC1u'
    'YXQnLCcxLjEuMS4xJ10pCiAgICBmb3IgcHJvdG9jb2wgaW4gKCd1ZHAnLCd0Y3AnKToKICAgICAgICByZXN1bHQgPSBjb21t'
    'YW5kKFsnY29ubnRyYWNrJywnLUQnLCctZicsJ2lwdjQnLCctcCcscHJvdG9jb2wsCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgJy0tZHBvcnQnLCc1MycsKmZpbHRlcnNdLCBjaGVjaz1GYWxzZSwKICAgICAgICAgICAgICAgICAgICAgICAgIGVudj17'
    'Kipvcy5lbnZpcm9uLCdMQ19BTEwnOidDJ30pCiAgICAgICAgZW1wdHkgPSByZXN1bHQucmV0dXJuY29kZSA9PSAxIGFuZCAn'
    'MCBmbG93IGVudHJpZXMgaGF2ZSBiZWVuIGRlbGV0ZWQnIGluIHJlc3VsdC5zdGRlcnIKICAgICAgICBpZiByZXN1bHQucmV0'
    'dXJuY29kZSAhPSAwIGFuZCBub3QgZW1wdHk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZG5zX3RyYW5zaXRp'
    'b25fY2xlYW51cF9mYWlsZWQnKQoKCmRlZiBmdWxsX2d1YXJkX2FjdGl2ZSgpOgogICAgcmV0dXJuIGNvbW1hbmQoWyduZnQn'
    'LCdsaXN0JywndGFibGUnLCdpbmV0JyxGVUxMX0dVQVJEXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwCgoKZGVmIGZ1'
    'bGxfZmlyZXdhbGwoKToKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZToKICAgICAgICBzZXR0aW5ncz1wb2xpY3kuYXBpLmxv'
    'YWRfc2V0dGluZ3MoKQogICAgICAgIHJldHVybiBwb2xpY3kuZmlyZXdhbGwocG9saWN5LmxvYWQoKSxwb2xpY3kubG9jYWxf'
    'bmV0d29ya3MocGh5c2ljYWxfcm91dGUoKSksaW50KHNldHRpbmdzWyJ4cmF5X3VpZCJdKSkKICAgICMgTWluaW1hbCBndWFy'
    'ZCB1c2VkIGJ5IGlzb2xhdGVkIHByb3RvY29sIHRlc3RzLgogICAgIyBLZWVwIGxvY2FsIHN0dWIgRE5TIG9uIGxvb3BiYWNr'
    'LiBETkFUIG9mIDEyNy84IG9udG8gYSB2ZXRoIGZhaWxzIExpbnV4J3MKICAgICMgbG9vcGJhY2sgcm91dGUgY2hlY2tzOyB1'
    'cHN0cmVhbSByZXNvbHZlciB0cmFmZmljIHN0aWxsIG9iZXlzIHRoZSBmdWxsIGd1YXJkLgogICAgcmV0dXJuIGYnJyd0YWJs'
    'ZSBpbmV0IHtGVUxMX0dVQVJEfSB7ewogY2hhaW4gZG5zIHt7IHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7'
    'IHBvbGljeSBhY2NlcHQ7CiAgaXAgZGFkZHIgMTI3LjAuMC4wLzggcmV0dXJuCiAgaXAgZGFkZHIge3sgMS4xLjEuMSwgOS45'
    'LjkuOSB9fSByZXR1cm4KICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQg'
    'NTMgZG5hdCBpcCB0byAxLjEuMS4xCiB9fQogY2hhaW4gc291cmNlIHt7IHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJp'
    'b3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBz'
    'bmF0IGlwIHRvIDE3Mi4yOS4yNDcuMQogfX0KIGNoYWluIG91dHB1dCB7eyB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlv'
    'cml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1l'
    'ICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgaXAgZGFkZHIgMjU1LjI1NS4yNTUuMjU1IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQg'
    'NjcgYWNjZXB0CiB9fQogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTMwOyBw'
    'b2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19'
    'IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFk'
    'ZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVO'
    'VH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3AgZHBvcnQge3sgMjQ1NzEsIDI0NTc4IH19IGFjY2VwdAogIGlpZm5hbWUg'
    'IntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9ydCAyNDU3OSBhY2Nl'
    'cHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHRjcCBkcG9y'
    'dCA4NDQzIGFjY2VwdAogIG9pZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge0NMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQs'
    'cmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBu'
    'ZnByb3RvIGlwdjQgaWlmbmFtZSAie0ZVTExfSE9TVH0iIGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiB9'
    'fQp9fScnJwoKCgpkZWYgcmVmcmVzaF9yZXRhaW5lZF9ndWFyZCgpOgogICAgIiIiTW92ZSBvbmx5IHRoZSBWUE4gdHJhbnNw'
    'b3J0IGV4Y2VwdGlvbiB3aGVuIGFuIGluZ3Jlc3MgZW5kcG9pbnQgY2hhbmdlcy4iIiIKICAgIGlmIG5vdCBmdWxsX2d1YXJk'
    'X2FjdGl2ZSgpOgogICAgICAgIHJldHVybgogICAgcnVsZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgIHJlcGxhY2VtZW50ID0g'
    'J2RlbGV0ZSB0YWJsZSBpbmV0ICcrRlVMTF9HVUFSRCsnXG4nK3J1bGVzCiAgICBjb21tYW5kKFsnbmZ0JywnLWMnLCctZics'
    'Jy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgIyBQZXJzaXN0IHRoZSBjbG9zZWQgZ3VhcmQgYmVmb3JlIGNoYW5naW5nIHRo'
    'ZSBhY3RpdmUgZXhjZXB0aW9uOyBhIGNyYXNoIHN0YXlzIGNsb3NlZC4KICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0'
    'JyxydWxlcykKICAgIGNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQoKCmRlZiB2aXJ0dWFsX2lw'
    'KCk6CiAgICBkYXRhID0ganNvbi5sb2FkcyhpbnNpZGUoWydpcCcsJy1qJywnLTQnLCdhZGRyJ10pLnN0ZG91dCkKICAgIGlw'
    'cyA9IFthWydsb2NhbCddIGZvciBsaW5rIGluIGRhdGEgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsIFtdKQogICAg'
    'ICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKGFbJ2xvY2FsJ10pIGluIGlwYWRkcmVzcy5pcF9uZXR3b3JrKCcxMC43'
    'Ny4wLjAvMjQnKV0KICAgIGlmIGxlbihpcHMpICE9IDE6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd2aXJ0dWFsX2lw'
    'X21pc3NpbmcnKQogICAgcmV0dXJuIGlwc1swXQoKCmRlZiBmdWxsX25hbWVzcGFjZShhZGRyZXNzKToKICAgIHZpcCA9IHZp'
    'cnR1YWxfaXAoKQogICAgaWYgbm90IFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAg'
    'ICBjb21tYW5kKFsnaXAnLCdsaW5rJywnYWRkJyxGVUxMX0hPU1QsJ3R5cGUnLCd2ZXRoJywncGVlcicsJ25hbWUnLEZVTExf'
    'UEVFUl0pCiAgICAgICAgY29tbWFuZChbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9QRUVSLCduZXRucycsTlNdKQogICAgY29t'
    'bWFuZChbJ2lwJywnYWRkcicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjEvMzAnLCdkZXYnLEZVTExfSE9TVF0pCiAgICBjb21t'
    'YW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX0hPU1QsJ210dScsJzEyODAnLCd1cCddKQogICAgaW5zaWRlKFsnaXAnLCdh'
    'ZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcuMi8zMCcsJ2RldicsRlVMTF9QRUVSXSkKICAgIGluc2lkZShbJ2lwJywnbGlu'
    'aycsJ3NldCcsRlVMTF9QRUVSLCdtdHUnLCcxMjgwJywndXAnXSkKICAgIGluc2lkZShbJ3N5c2N0bCcsJy1xdycsJ25ldC5p'
    'cHY0LmNvbmYuYWxsLmZvcndhcmRpbmc9MScsJ25ldC5pcHY0LmNvbmYuYWxsLnJwX2ZpbHRlcj0wJ10pCiAgICAjIFN0cm9u'
    'Z1N3YW4ncyBjYXRjaC1hbGwgcm91dGUgbXVzdCBub3QgY2FwdHVyZSByZXBsaWVzIHRvIHRoZSBob3N0LWZhY2luZyBpbnRl'
    'cmZhY2UuCiAgICBpbnNpZGUoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29r'
    'dXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBpbnNpZGUoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzkwJywn'
    'dG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10pCiAgICBkZWxldGlvbnMgPSAnJwogICAgZm9yIGZhbWlseSx0YWJsZSBp'
    'biBbKCdpbmV0JywnZXZuX2Z1bGxfZm9yd2FyZCcpLCgnbmV0ZGV2JywnZXZuX2Z1bGxfd2lyZScpXToKICAgICAgICBpZiBp'
    'bnNpZGUoWyduZnQnLCdsaXN0JywndGFibGUnLGZhbWlseSx0YWJsZV0sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoK'
    'ICAgICAgICAgICAgZGVsZXRpb25zICs9IGYnZGVsZXRlIHRhYmxlIHtmYW1pbHl9IHt0YWJsZX1cbicKICAgIHJ1bGVzID0g'
    'ZGVsZXRpb25zICsgZicnJ3RhYmxlIGluZXQgZXZuX2Z1bGxfZm9yd2FyZCB7ewogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZp'
    'bHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTU7IHBvbGljeSBkcm9wOwogIGlpZm5hbWUgIntGVUxMX1BFRVJ9IiBvaWZu'
    'YW1lICJ7UEVFUn0iIGlwIHNhZGRyIDE3Mi4yOS4yNDcuMSBhY2NlcHQKICBpaWZuYW1lIHt7ICJ7UEVFUn0iLCAibG8iIH19'
    'IG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBkYWRkciAxNzIuMjkuMjQ3LjEgaXBzZWMgaW4gcmVxaWQge1JFUUlEfSBjdCBz'
    'dGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KIGNoYWluIG5hdCB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0'
    'aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgb2lmbmFtZSAie1BF'
    'RVJ9IiBzbmF0IGlwIHRvIHt2aXB9CiB9fQp9fQp0YWJsZSBuZXRkZXYgZXZuX2Z1bGxfd2lyZSB7ewogY2hhaW4gZWdyZXNz'
    'IHt7IHR5cGUgZmlsdGVyIGhvb2sgZWdyZXNzIGRldmljZSAie1BFRVJ9IiBwcmlvcml0eSAwOyBwb2xpY3kgZHJvcDsKICBl'
    'dGhlciB0eXBlIGFycCBhY2NlcHQKICBpcCBkYWRkciB7YWRkcmVzc30gdWRwIGRwb3J0IHtBQ1RJVkVbJ3BvcnQnXX0gYWNj'
    'ZXB0CiAgaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3AgZHBvcnQge3sgMjQ1NzEsIDI0NTc4IH19IGFjY2VwdAogIGlwIGRh'
    'ZGRyIDE5NS4yMDkuMjExLjE2MyB0Y3AgZHBvcnQgMjQ1NzkgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9y'
    'dCA4NDQzIGFjY2VwdAogfX0KfX0nJycKICAgIGluc2lkZShbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAg'
    'IGluc2lkZShbJ25mdCcsJy1mJywnLSddLGRhdGE9cnVsZXMpCiAgICAjIFJlcGxhY2UgdGhlIG9yaWdpbmFsIGxhYiBmb3J3'
    'YXJkIGRyb3A7IGhvc3QgaW5ncmVzcyByZW1haW5zIGNvbnN0cmFpbmVkIGJ5IGZ1bGxfZm9yd2FyZC4KICAgIGluc2lkZShb'
    'J25mdCcsJ2ZsdXNoJywnY2hhaW4nLCdpbmV0JyxOQU1FU1BBQ0VfR1VBUkQsJ2ZvcndhcmQnXSkKICAgIGluc2lkZShbJ25m'
    'dCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JyxOQU1FU1BBQ0VfR1VBUkQsJ2ZvcndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21l'
    'dGEnLCduZnByb3RvJywnaXB2NCcsJ2FjY2VwdCddKQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLE5B'
    'TUVTUEFDRV9HVUFSRCwnZm9yd2FyZCcsJ29pZm5hbWUnLEZVTExfUEVFUiwnaXBzZWMnLCdpbicsJ3JlcWlkJyxzdHIoUkVR'
    'SUQpLCdjdCcsJ3N0YXRlJywnZXN0YWJsaXNoZWQscmVsYXRlZCcsJ2FjY2VwdCddKQoKCl9FR1JFU1NfUFJPQkVTID0gKCdo'
    'dHRwczovLzEuMS4xLjEvY2RuLWNnaS90cmFjZScsICdodHRwczovL2FwaS5pcGlmeS5vcmcnKQpfZWdyZXNzX3ByZWZlcnJl'
    'ZCA9IDAKCgpkZWYgcGFyc2VfZXhpdChib2R5LCB0cmFjZSk6CiAgICB2YWx1ZXMgPSBbbGluZVszOl0gZm9yIGxpbmUgaW4g'
    'Ym9keS5zcGxpdGxpbmVzKCkgaWYgbGluZS5zdGFydHN3aXRoKCdpcD0nKV0gaWYgdHJhY2UgZWxzZSBbYm9keS5zdHJpcCgp'
    'XQogICAgaWYgbGVuKHZhbHVlcykgIT0gMToKICAgICAgICByZXR1cm4gTm9uZQogICAgdHJ5OgogICAgICAgIHJldHVybiBz'
    'dHIoaXBhZGRyZXNzLklQdjRBZGRyZXNzKHZhbHVlc1swXSkpCiAgICBleGNlcHQgaXBhZGRyZXNzLkFkZHJlc3NWYWx1ZUVy'
    'cm9yOgogICAgICAgIHJldHVybiBOb25lCgoKZGVmIGVncmVzc19oZWFsdGgoKToKICAgICIiIkluZGVwZW5kZW50IEhUVFBT'
    'IHByb3ZpZGVyczsgYSB2ZXJpZmllZCB3cm9uZyBJUCBtdXN0IG5ldmVyIGJlIG1hc2tlZCBieSBmYWxsYmFjay4iIiIKICAg'
    'IGdsb2JhbCBfZWdyZXNzX3ByZWZlcnJlZAogICAgZm9yIGluZGV4IGluIChfZWdyZXNzX3ByZWZlcnJlZCwgMS1fZWdyZXNz'
    'X3ByZWZlcnJlZCk6CiAgICAgICAgdXJsID0gX0VHUkVTU19QUk9CRVNbaW5kZXhdCiAgICAgICAgdHJ5OgogICAgICAgICAg'
    'ICByZXN1bHQgPSBpbnNpZGUoWydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLXNo'
    'b3ctZXJyb3InLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICctLWNvbm5lY3QtdGltZW91dCcsJzMnLCctLW1heC10'
    'aW1lJywnNScsJy0tbWF4LWZpbGVzaXplJywnMzI3NjgnLHVybF0sdGltZW91dD03LGNoZWNrPUZhbHNlKQogICAgICAgIGV4'
    'Y2VwdCAoT1NFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBp'
    'ZiByZXN1bHQucmV0dXJuY29kZSAhPSAwOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIG9ic2VydmVkID0gcGFyc2Vf'
    'ZXhpdChyZXN1bHQuc3Rkb3V0LCBpbmRleCA9PSAwKQogICAgICAgIGlmIG9ic2VydmVkIGlzIG5vdCBOb25lOgogICAgICAg'
    'ICAgICBpZiBvYnNlcnZlZCAhPSAnMzguMTgwLjE2NC42Nyc6CiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAg'
    'ICAgICAgX2VncmVzc19wcmVmZXJyZWQgPSBpbmRleAogICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgcmV0dXJuIEZhbHNl'
    'CgoKZGVmIHBhdGhfaGVhbHRoeShkYWVtb24pOgogICAgIyBUaGUgcHJpdmF0ZSBkaWFnbm9zdGljIEhUVFAgY29sbGVjdG9y'
    'IGlzIG5vdCBwYXJ0IG9mIHRoZSBWUE4gZGF0YSBwbGFuZS4KICAgICMgSXRzIG91dGFnZS9yZXN0YXJ0IG11c3Qgbm90IGRp'
    'c2NhcmQgYSB3b3JraW5nIHJvdXRlJ3MgdGhyZWUtbG9zcyBidWRnZXQuCiAgICByZXR1cm4gKGRhZW1vbi5wb2xsKCkgaXMg'
    'Tm9uZSBhbmQgaW5zdGFsbGVkKCkKICAgICAgICAgICAgYW5kIChUTFNfUFJPQ0VTUyBpcyBOb25lIG9yIFRMU19QUk9DRVNT'
    'LnBvbGwoKSBpcyBOb25lKSBhbmQgZWdyZXNzX2hlYWx0aCgpKQoKCmRlZiByZXRpcmVfcHJldmlvdXNfY29ubmVjdGlvbnMo'
    'YWRkcmVzc2VzKToKICAgICMgVGhlIGZpcmV3YWxsIGFscmVhZHkgYmxvY2tzIG9sZCBub24tZXhlbXB0IGZsb3dzLiBEbyBu'
    'b3Qga2lsbCBhbGwgc29ja2V0cwogICAgIyBzaGFyaW5nIGEgcGh5c2ljYWwgc291cmNlIGFkZHJlc3M6IHRoYXQgZGVzdHJv'
    'eXMgU1NILCBMQU4gYW5kIGFwcCBleGNsdXNpb25zLgogICAgIyBPbmx5IHRoaXMgbWFuYWdlcidzIEROUyB0cmFuc2xhdGlv'
    'bnMgbmVlZCBleHBsaWNpdCByZXRpcmVtZW50IChoYW5kbGVkIGFib3ZlKS4KICAgIHJldHVybgoKCmRlZiBzeXN0ZW1fZG5z'
    'X2hlYWx0aChyZXNvbHZfY29uZj1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgIyBnZXRhZGRyaW5mby9jdXJsIG1h'
    'eSB1c2UgbnNzLXJlc29sdmUgb3ZlciBhIFVuaXggc29ja2V0IGFuZCBtaXNzIGEgYnJva2VuCiAgICAjIFVEUCBzdHViIHVz'
    'ZWQgYnkgb3RoZXIgYXBwbGljYXRpb25zLiBFeGVyY2lzZSByZXNvbHYuY29uZiBpbmRlcGVuZGVudGx5LgogICAgc2VydmVy'
    'cyA9IFtsaW5lLnNwbGl0KClbMV0gZm9yIGxpbmUgaW4gcmVzb2x2X2NvbmYucmVhZF90ZXh0KCkuc3BsaXRsaW5lcygpCiAg'
    'ICAgICAgICAgICAgIGlmIGxpbmUuc3BsaXQoKVs6MV0gPT0gWyduYW1lc2VydmVyJ10gYW5kIGxlbihsaW5lLnNwbGl0KCkp'
    'ID49IDJdWzozXQogICAgZm9yIHNlcnZlciBpbiBzZXJ2ZXJzOgogICAgICAgIHRyeToKICAgICAgICAgICAgZmFtaWx5ID0g'
    'c29ja2V0LkFGX0lORVQ2IGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHNlcnZlcikudmVyc2lvbiA9PSA2IGVsc2Ugc29ja2V0'
    'LkFGX0lORVQKICAgICAgICAgICAgdHJhbnNhY3Rpb24gPSBzZWNyZXRzLnRva2VuX2J5dGVzKDIpCiAgICAgICAgICAgIHF1'
    'ZXJ5ID0gdHJhbnNhY3Rpb24rYidceDAxXHgwMFx4MDBceDAxXHgwMFx4MDBceDAwXHgwMFx4MDBceDAwJwogICAgICAgICAg'
    'ICBxdWVyeSArPSBiJ1x4MDNhcGlceDA1aXBpZnlceDAzb3JnXHgwMFx4MDBceDAxXHgwMFx4MDEnCiAgICAgICAgICAgIHdp'
    'dGggc29ja2V0LnNvY2tldChmYW1pbHksIHNvY2tldC5TT0NLX0RHUkFNKSBhcyByZXNvbHZlcjoKICAgICAgICAgICAgICAg'
    'IHJlc29sdmVyLnNldHRpbWVvdXQoMikKICAgICAgICAgICAgICAgIHJlc29sdmVyLmNvbm5lY3QoKHNlcnZlciwgNTMpKQog'
    'ICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2VuZChxdWVyeSkKICAgICAgICAgICAgICAgIGFuc3dlciA9IHJlc29sdmVyLnJl'
    'Y3YoNDA5NikKICAgICAgICAgICAgaWYgKGxlbihhbnN3ZXIpID49IDEyIGFuZCBhbnN3ZXJbOjJdID09IHRyYW5zYWN0aW9u'
    'IGFuZAogICAgICAgICAgICAgICAgICAgIGFuc3dlclsyXSAmIDB4ODAgYW5kIGFuc3dlclszXSAmIDE1ID09IDAgYW5kCiAg'
    'ICAgICAgICAgICAgICAgICAgaW50LmZyb21fYnl0ZXMoYW5zd2VyWzY6OF0sICdiaWcnKSA+IDApOgogICAgICAgICAgICAg'
    'ICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgICAgICBjb250aW51'
    'ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIHN0YXJ0X25hbWVzcGFjZV9kbnMoKToKICAgICIiIkEgcHJpdmF0ZSBETlMgZW5k'
    'cG9pbnQgcmVhY2hhYmxlIG9ubHkgb3ZlciB0aGUgaG9zdC9uYW1lc3BhY2UgdmV0aC4iIiIKICAgIGdsb2JhbCBETlNfUFJP'
    'Q0VTUwogICAgaWYgRE5TX1BST0NFU1MgaXMgbm90IE5vbmUgYW5kIEROU19QUk9DRVNTLnBvbGwoKSBpcyBOb25lOnJldHVy'
    'bgogICAgY2ZnID0geydsb2cnOnsnbG9nbGV2ZWwnOid3YXJuaW5nJywnYWNjZXNzJzonbm9uZSd9LAogICAgICAnaW5ib3Vu'
    'ZHMnOlt7J3RhZyc6J2Rucy1pbicsJ2xpc3Rlbic6JzE3Mi4yOS4yNDcuMicsJ3BvcnQnOjUzLCdwcm90b2NvbCc6J2Rva29k'
    'ZW1vLWRvb3InLAogICAgICAgICAgICAgICAgICAgJ3NldHRpbmdzJzp7J2FkZHJlc3MnOicxLjEuMS4xJywncG9ydCc6NTMs'
    'J25ldHdvcmsnOid0Y3AsdWRwJ319XSwKICAgICAgJ2Rucyc6eydzZXJ2ZXJzJzpbJzEuMS4xLjEnLCd0Y3A6Ly85LjkuOS45'
    'JywnaHR0cHM6Ly8xLjAuMC4xL2Rucy1xdWVyeSddLAogICAgICAgICAgICAgJ3F1ZXJ5U3RyYXRlZ3knOidVc2VJUHY0Jywn'
    'dGFnJzonZG5zLWVuZ2luZScsJ2VuYWJsZVBhcmFsbGVsUXVlcnknOlRydWV9LAogICAgICAnb3V0Ym91bmRzJzpbeyd0YWcn'
    'Oid3aXJlJywncHJvdG9jb2wnOidmcmVlZG9tJ30sCiAgICAgICAgICAgICAgICAgICB7J3RhZyc6J2RucycsJ3Byb3RvY29s'
    'JzonZG5zJywnc2V0dGluZ3MnOnsncnVsZXMnOlt7J3FUeXBlJzonMSwyOCcsJ2FjdGlvbic6J2hpamFjayd9LHsnYWN0aW9u'
    'JzonZGlyZWN0J31dfX1dLAogICAgICAncm91dGluZyc6eydydWxlcyc6W3sndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6'
    'WydkbnMtaW4nXSwnb3V0Ym91bmRUYWcnOidkbnMnfSwKICAgICAgICAgICAgICAgICAgICAgICAgICB7J3R5cGUnOidmaWVs'
    'ZCcsJ2luYm91bmRUYWcnOlsnZG5zLWVuZ2luZSddLCdvdXRib3VuZFRhZyc6J3dpcmUnfV19fQogICAgcGF0aD1ST09ULydu'
    'YW1lc3BhY2UtZG5zLmpzb24nO3dyaXRlKHBhdGgsanNvbi5kdW1wcyhjZmcpKQogICAgYmluYXJ5PScvb3B0L3Zwbi1tYW5h'
    'Z2VyL2Jpbi94cmF5JwogICAgaW5zaWRlKFtiaW5hcnksJ3J1bicsJy10ZXN0JywnLWNvbmZpZycscGF0aF0pCiAgICBETlNf'
    'UFJPQ0VTUz1zdWJwcm9jZXNzLlBvcGVuKFsnaXAnLCduZXRucycsJ2V4ZWMnLE5TLGJpbmFyeSwncnVuJywnLWNvbmZpZycs'
    'c3RyKHBhdGgpXSwKICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsc3Rkb3V0PXN1YnByb2Nlc3MuREVWTlVMTCxz'
    'dGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgZm9yIF8gaW4gcmFuZ2UoMzApOgogICAgICAgIGlmIEROU19QUk9DRVNT'
    'LnBvbGwoKSBpcyBub3QgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3ByaXZhdGVfZG5zX3N0b3BwZWQnKQogICAgICAgIGlm'
    'ICcxNzIuMjkuMjQ3LjI6NTMnIGluIGluc2lkZShbJ3NzJywnLWxudSddLGNoZWNrPUZhbHNlKS5zdGRvdXQ6CiAgICAgICAg'
    'ICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCduYW1lc2VydmVyIDE3Mi4yOS4yNDcuMlxu'
    'b3B0aW9ucyB0aW1lb3V0OjMgYXR0ZW1wdHM6MlxuJykKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgdGltZS5zbGVlcCgu'
    'MSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncHJpdmF0ZV9kbnNfbm90X3JlYWR5JykKCgpkZWYgdXNlX3Jlc29sdmVyX2Zp'
    'bGUocGF0aD1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFk'
    'X3RleHQoKSkKICAgIHRhcmdldD1ST09ULydyZXNvbHYtdnBuLmNvbmYnCiAgICBpZiAncmVzb2x2ZXJfb3JpZ2luYWwnIG5v'
    'dCBpbiBkYXRhOgogICAgICAgIGRhdGFbJ3Jlc29sdmVyX29yaWdpbmFsJ109eydsaW5rJzpvcy5yZWFkbGluayhwYXRoKSBp'
    'ZiBwYXRoLmlzX3N5bWxpbmsoKSBlbHNlIE5vbmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3RleHQn'
    'OnBhdGgucmVhZF90ZXh0KCkgaWYgcGF0aC5leGlzdHMoKSBlbHNlICcnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICdleGlzdGVkJzpwYXRoLmV4aXN0cygpIG9yIHBhdGguaXNfc3ltbGluaygpfQogICAgZGF0YVsnZG5zX2ZhbGxi'
    'YWNrJ109VHJ1ZQogICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCiAgICB3cml0ZSh0YXJnZXQsJ25h'
    'bWVzZXJ2ZXIgMTcyLjI5LjI0Ny4yXG5vcHRpb25zIHRpbWVvdXQ6MyBhdHRlbXB0czoyXG4nKQogICAgdGFyZ2V0LmNobW9k'
    'KDBvNjQ0KQogICAgIyBUaGUgcGFyZW50IG11c3QgYmUgdHJhdmVyc2FibGUgYnkgYXBwbGljYXRpb25zLiBTZWNyZXRzIHJl'
    'bWFpbiByb290LW9ubHkuCiAgICAjIFB1dCBvbmx5IHRoaXMgcHVibGljIHJlc29sdmVyIGZpbGUgb3V0c2lkZSB0aGUgY3Jl'
    'ZGVudGlhbCBkaXJlY3RvcnkuCiAgICBwdWJsaWM9UGF0aCgnL3J1bi9ldmdlbml1bS1yZXNvbHYuY29uZicpCiAgICBwdWJs'
    'aWMucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd3JpdGUocHVibGljLHRhcmdldC5yZWFk'
    'X3RleHQoKSxtb2RlPTBvNjQ0KQogICAgdGVtcG9yYXJ5PXBhdGgud2l0aF9uYW1lKCcuZXZnZW5pdW0tcmVzb2x2Lm5ldycp'
    'CiAgICB0ZW1wb3JhcnkudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSk7dGVtcG9yYXJ5LnN5bWxpbmtfdG8ocHVibGljKQogICAg'
    'b3MucmVwbGFjZSh0ZW1wb3JhcnkscGF0aCkKCgpkZWYgcmVzdG9yZV9yZXNvbHZlcl9maWxlKGRhdGEscGF0aD1QYXRoKCcv'
    'ZXRjL3Jlc29sdi5jb25mJykpOgogICAgc2F2ZWQ9ZGF0YS5nZXQoJ3Jlc29sdmVyX29yaWdpbmFsJykKICAgIGlmIHNhdmVk'
    'IGFuZCBwYXRoLmlzX3N5bWxpbmsoKSBhbmQgb3MucmVhZGxpbmsocGF0aCk9PScvcnVuL2V2Z2VuaXVtLXJlc29sdi5jb25m'
    'JzoKICAgICAgICB0ZW1wb3Jhcnk9cGF0aC53aXRoX25hbWUoJy5ldmdlbml1bS1yZXNvbHYucmVzdG9yZScpCiAgICAgICAg'
    'dGVtcG9yYXJ5LnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICAgICAgaWYgc2F2ZWRbJ2xpbmsnXSBpcyBub3QgTm9uZTp0'
    'ZW1wb3Jhcnkuc3ltbGlua190byhzYXZlZFsnbGluayddKQogICAgICAgIGVsc2U6dGVtcG9yYXJ5LndyaXRlX3RleHQoc2F2'
    'ZWRbJ3RleHQnXSk7dGVtcG9yYXJ5LmNobW9kKDBvNjQ0KQogICAgICAgIGlmIHNhdmVkLmdldCgnZXhpc3RlZCcsVHJ1ZSk6'
    'b3MucmVwbGFjZSh0ZW1wb3JhcnkscGF0aCkKICAgICAgICBlbHNlOnBhdGgudW5saW5rKCk7dGVtcG9yYXJ5LnVubGluaygp'
    'CiAgICBlbGlmIG5vdCBzYXZlZCBhbmQgJ2Ruc19iYWNrdXAnIGluIGRhdGE6CiAgICAgICAgcGF0aC53cml0ZV90ZXh0KGRh'
    'dGFbJ2Ruc19iYWNrdXAnXSkKCgpkZWYgcmVjb3Zlcl9zeXN0ZW1fZG5zKCk6CiAgICBmb3IgXyBpbiByYW5nZSgyKToKICAg'
    'ICAgICBpZiBzeXN0ZW1fZG5zX2hlYWx0aCgpOnJldHVybiBUcnVlCiAgICAgICAgaWYgU1RPUDpyZXR1cm4gRmFsc2UKICAg'
    'ICAgICB0aW1lLnNsZWVwKC4zKQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKTpyZXR1cm4gRmFsc2UKICAgICMg'
    'U3dpdGNoIG9ubHkgdGhlIHJlc29sdmVyIGZpbGUgd2Ugb3duOyBuZXZlciBzdG9wIGFub3RoZXIgVlBOIG9yIHJlc29sdmVy'
    'LgogICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Cf0LXRgNC10LrQu9GO0YfQsNGOINC90LXQuNGB0L/RgNCw0LLQvdGL0Lkg0YHQ'
    'uNGB0YLQtdC80L3Ri9C5IEROUyDQvdCwINC30LDRidC40YnRkdC90L3Ri9C5INGA0LXQt9C10YDQsi4nLDkwLGFjdGl2ZT1G'
    'YWxzZSxlcnJvcl9jb2RlPSdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICB1c2VfcmVzb2x2ZXJfZmlsZSgpCiAgICByZXR1cm4g'
    'c3lzdGVtX2Ruc19oZWFsdGgoKQoKClRVTk5FTF9TRVJWSUNFID0gJycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGZ1'
    'bGwtZGV2aWNlIEVzdG9uaWEgVlBOCkFmdGVyPW5ldHdvcmsudGFyZ2V0ClN0YXJ0TGltaXRJbnRlcnZhbFNlYz0xODAKU3Rh'
    'cnRMaW1pdEJ1cnN0PTMKW1NlcnZpY2VdClR5cGU9c2ltcGxlCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIHtw'
    'cmVmaXh9LXR1bm5lbApFeGVjU3RvcFBvc3Q9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCB7cHJlZml4fS10dW5uZWwtY2xlYW51'
    'cApUaW1lb3V0U3RvcFNlYz0yMApLaWxsTW9kZT1taXhlZApVTWFzaz0wMDc3Ck1lbW9yeU1heD0yNTZNClJlc3RhcnQ9b24t'
    'ZmFpbHVyZQpSZXN0YXJ0U2VjPTMKJycnCgpSRUNPVkVSWV9TRVJWSUNFID0gJycnW1VuaXRdCkRlc2NyaXB0aW9uPVJlY292'
    'ZXIgaW50ZXJydXB0ZWQgRXZnZW5pdW0gVlBOIHR1bm5lbCByZXNvdXJjZXMKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpBZnRl'
    'cj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldCB2cG4teHJheS5zZXJ2aWNlCltTZXJ2aWNlXQpU'
    'eXBlPW9uZXNob3QKRXhlY1N0YXJ0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwge3ByZWZpeH0tdHVubmVsLWNsZWFudXAKW0lu'
    'c3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CicnJwoKR1VBUkRfU0VSVklDRSA9ICcnJ1tVbml0XQpEZXNjcmlw'
    'dGlvbj1Fdmdlbml1bSBmdWxsLWRldmljZSBraWxsIHN3aXRjaApEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2Fs'
    'LWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0CltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVtYWluQWZ0ZXJF'
    'eGl0PXllcwpFeGVjU3RhcnQ9e25mdH0gLWYge3Jvb3R9L2Z1bGwtZ3VhcmQubmZ0CltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0'
    'aS11c2VyLnRhcmdldAonJycKCgpVTklUX1RFTVBMQVRFUyA9IHsndW5pdCc6IFRVTk5FTF9TRVJWSUNFLCAncmVjb3Zlcnkn'
    'OiBSRUNPVkVSWV9TRVJWSUNFLCAnZ3VhcmQnOiBHVUFSRF9TRVJWSUNFfQoKCmRlZiB1bml0X3RleHQobGF5b3V0LCByb2xl'
    'LCBuZnQ9Jy91c3IvYmluL25mdCcpOgogICAgdGVtcGxhdGUgPSBVTklUX1RFTVBMQVRFU1tyb2xlXQogICAgaWYgbGF5b3V0'
    'ID09IExFR0FDWSBhbmQgcm9sZSA9PSAncmVjb3ZlcnknOgogICAgICAgIHRlbXBsYXRlID0gdGVtcGxhdGUucmVwbGFjZSgn'
    'aW50ZXJydXB0ZWQgRXZnZW5pdW0gVlBOIHR1bm5lbCcsICdvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0'
    'JykKICAgIHJldHVybiB0ZW1wbGF0ZS5mb3JtYXQocHJlZml4PWxheW91dC5jb21tYW5kX3ByZWZpeCwgcm9vdD1sYXlvdXQu'
    'cm9vdCwgbmZ0PW5mdCkKCgpkZWYga25vd25fdW5pdChsYXlvdXQsIHJvbGUsIGRhdGEpOgogICAgYmluYXJpZXMgPSAoJy91'
    'c3IvYmluL25mdCcsICcvdXNyL3NiaW4vbmZ0JywgJy9zYmluL25mdCcsIHNodXRpbC53aGljaCgnbmZ0JykpCiAgICByZXR1'
    'cm4gYW55KGRhdGEgPT0gdW5pdF90ZXh0KGxheW91dCwgcm9sZSwgbmZ0KS5lbmNvZGUoKSBmb3IgbmZ0IGluIGJpbmFyaWVz'
    'IGlmIG5mdCkKCgpkZWYgaGFzX2xheW91dChsYXlvdXQpOgogICAgcGF0aHMgPSAobGF5b3V0LnJvb3QsIGxheW91dC5zdGF0'
    'ZSwgbGF5b3V0LnJ1bnRpbWUsICooVU5JVF9ESVIgLyBnZXRhdHRyKGxheW91dCwgcm9sZSkgZm9yIHJvbGUgaW4gVU5JVF9U'
    'RU1QTEFURVMpKQogICAgcmV0dXJuIGFueShvcy5wYXRoLmxleGlzdHMocGF0aCkgZm9yIHBhdGggaW4gcGF0aHMpCgoKZGVm'
    'IHRyYW5zaXRpb25fbGF5b3V0cygpOgogICAgdHJ5OgogICAgICAgIGRpcmVjdGlvbiA9IExBWU9VVF9UUkFOU0FDVElPTi5y'
    'ZWFkX3RleHQoKS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKICAg'
    'IGlmIGRpcmVjdGlvbiA9PSAndXBncmFkZSc6CiAgICAgICAgcmV0dXJuIExFR0FDWSwgQ1VSUkVOVAogICAgaWYgZGlyZWN0'
    'aW9uID09ICdyb2xsYmFjayc6CiAgICAgICAgcmV0dXJuIENVUlJFTlQsIExFR0FDWQogICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCfQndC10LrQvtGA0YDQtdC60YLQvdCw0Y8g0LfQsNC/0LjRgdGMINC+INC/0LXRgNC10L3QvtGB0LUg0YTQsNC50LvQvtCy'
    'IFZQTi4nKQoKCmRlZiBzZWxlY3RfaW5zdGFsbGVkX2xheW91dCgpOgogICAgIyBBbHNvIHdvcmtzIGJldHdlZW4gdGhlIG9s'
    'ZCB1cGRhdGVyIHN3YXBwaW5nICJjdXJyZW50IiBhbmQgc3RhcnRpbmcgb3VyIGZpbmFsaXplci4KICAgIHBlbmRpbmcgPSB0'
    'cmFuc2l0aW9uX2xheW91dHMoKQogICAgaWYgcGVuZGluZzoKICAgICAgICBzb3VyY2UsIHRhcmdldCA9IHBlbmRpbmcKICAg'
    'ICAgICB1c2VfbGF5b3V0KHRhcmdldCBpZiB0YXJnZXQucm9vdC5pc19kaXIoKSBhbmQgbm90IHNvdXJjZS5yb290LmV4aXN0'
    'cygpIGVsc2Ugc291cmNlKQogICAgZWxzZToKICAgICAgICBpZiBub3QgTEVHQUNZLnJvb3QuZXhpc3RzKCkgYW5kIENVUlJF'
    'TlQucm9vdC5pc19kaXIoKToKICAgICAgICAgICAgdXNlX2xheW91dChDVVJSRU5UKQogICAgICAgIGVsc2U6CiAgICAgICAg'
    'ICAgIHVzZV9sYXlvdXQoTEVHQUNZIGlmIGhhc19sYXlvdXQoTEVHQUNZKSBlbHNlIENVUlJFTlQpCgoKZGVmIHVuaXRfbGlu'
    'a3MobmFtZSk6CiAgICBmb3Iga2luZCBpbiAoJ3dhbnRzJywgJ3JlcXVpcmVzJywgJ3VwaG9sZHMnKToKICAgICAgICB5aWVs'
    'ZCBmcm9tIFVOSVRfRElSLmdsb2IoJyouJyArIGtpbmQgKyAnLycgKyBuYW1lKQoKCmRlZiBsYXlvdXRfaW5fdXNlKGxheW91'
    'dCwgKiwgY2hlY2tfZGVzdGluYXRpb249RmFsc2UpOgogICAgIiIiS2VlcCBsaXZlIHdvcmtlcnMgYW5kIHJldGFpbmVkIGZh'
    'aWwtY2xvc2VkIGNvbmZpZ3VyYXRpb25zIHdpdGggdGhlaXIgb3JpZ2luYWwgbmFtZXMuIiIiCiAgICBpZiAoKGxheW91dC5y'
    'b290IC8gJ25ldHdvcmsuanNvbicpLmV4aXN0cygpIG9yIChsYXlvdXQucm9vdCAvICdmdWxsLW5ldHdvcmsuanNvbicpLmV4'
    'aXN0cygpCiAgICAgICAgICAgIG9yIChQYXRoKCcvcnVuL25ldG5zJykgLyBsYXlvdXQubmFtZXNwYWNlKS5leGlzdHMoKQog'
    'ICAgICAgICAgICBvciAoUGF0aCgnL2V0Yy9uZXRucycpIC8gbGF5b3V0Lm5hbWVzcGFjZSkuZXhpc3RzKCkKICAgICAgICAg'
    'ICAgb3IgKFBhdGgoJy9zeXMvY2xhc3MvbmV0JykgLyBsYXlvdXQuaG9zdCkuZXhpc3RzKCkKICAgICAgICAgICAgb3IgYW55'
    'KHVuaXRfbGlua3MobGF5b3V0Lmd1YXJkKSkgb3IgYW55KHVuaXRfbGlua3MobGF5b3V0LnVuaXQpKSk6CiAgICAgICAgcmV0'
    'dXJuIFRydWUKICAgIGlmIG5vdCBoYXNfbGF5b3V0KGxheW91dCkgYW5kIG5vdCBjaGVja19kZXN0aW5hdGlvbjoKICAgICAg'
    'ICByZXR1cm4gRmFsc2UKICAgIGZvciBuYW1lIGluIChsYXlvdXQudW5pdCwgbGF5b3V0Lmd1YXJkLCBsYXlvdXQucmVjb3Zl'
    'cnkpOgogICAgICAgIHJlc3VsdCA9IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnc2hvdycsICctcCcsICdBY3RpdmVTdGF0ZScs'
    'ICctLXZhbHVlJywgbmFtZV0sIGNoZWNrPUZhbHNlKQogICAgICAgIHN0YXRlID0gcmVzdWx0LnN0ZG91dC5zdHJpcCgpCiAg'
    'ICAgICAgaWYgbm90IHN0YXRlOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LUg0YPQtNCw0LvQvtGB0Ywg'
    '0L7Qv9GA0LXQtNC10LvQuNGC0Ywg0YHQvtGB0YLQvtGP0L3QuNC1INGB0LvRg9C20LEgVlBOINC00LvRjyDQvtCx0L3QvtCy'
    '0LvQtdC90LjRjy4g0J/QvtCy0YLQvtGA0LjRgtC1IHZwbiB1cGRhdGUuJykKICAgICAgICBpZiBzdGF0ZSBub3QgaW4gKCdp'
    'bmFjdGl2ZScsICdmYWlsZWQnKToKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIGlmIG5vdCBzaHV0aWwud2hpY2goJ25m'
    'dCcpOgogICAgICAgIHJldHVybiAoVU5JVF9ESVIgLyBsYXlvdXQuZ3VhcmQpLmV4aXN0cygpCiAgICByZXN1bHQgPSBjb21t'
    'YW5kKFsnbmZ0JywgJy1qJywgJ2xpc3QnLCAndGFibGVzJ10sIGNoZWNrPUZhbHNlKQogICAgaWYgcmVzdWx0LnJldHVybmNv'
    'ZGU6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC/0YDQvtCy0LXRgNC40YLRjCDR'
    'gdC+0YXRgNCw0L3RkdC90L3Ri9C1INC/0YDQsNCy0LjQu9CwIFZQTi4g0J/QvtCy0YLQvtGA0LjRgtC1IHZwbiB1cGRhdGUu'
    'JykKICAgIHRyeToKICAgICAgICB0YWJsZXMgPSBbcmVjb3JkWyd0YWJsZSddIGZvciByZWNvcmQgaW4ganNvbi5sb2Fkcyhy'
    'ZXN1bHQuc3Rkb3V0IG9yICd7Im5mdGFibGVzIjpbXX0nKVsnbmZ0YWJsZXMnXSBpZiAndGFibGUnIGluIHJlY29yZF0KICAg'
    'IGV4Y2VwdCAoVmFsdWVFcnJvciwgS2V5RXJyb3IsIFR5cGVFcnJvcikgYXMgZXJyb3I6CiAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC/0YDQvtGH0LjRgtCw0YLRjCDRgdC/0LjRgdC+0Log0YLQsNCx0LvQuNGG'
    'IFZQTiDQtNC70Y8g0L7QsdC90L7QstC70LXQvdC40Y8uJykgZnJvbSBlcnJvcgogICAgcmV0dXJuIGFueSh0LmdldCgnZmFt'
    'aWx5JykgPT0gJ2luZXQnIGFuZCB0LmdldCgnbmFtZScpIGluIChsYXlvdXQuZ3VhcmRfdGFibGUsIGxheW91dC5ob3N0X3Rh'
    'YmxlKSBmb3IgdCBpbiB0YWJsZXMpCgoKZGVmIG1hbmFnZWRfdW5pdChwYXRoLCBsYXlvdXQsIHJvbGUpOgogICAgaW5mbyA9'
    'IHBhdGgubHN0YXQoKQogICAgcmV0dXJuIChzdGF0LlNfSVNSRUcoaW5mby5zdF9tb2RlKSBhbmQgaW5mby5zdF91aWQgPT0g'
    'b3MuZ2V0ZXVpZCgpIGFuZCBpbmZvLnN0X25saW5rID09IDEKICAgICAgICAgICAgYW5kIGluZm8uc3Rfc2l6ZSA8IDQwOTYg'
    'YW5kIGtub3duX3VuaXQobGF5b3V0LCByb2xlLCBwYXRoLnJlYWRfYnl0ZXMoKSkpCgoKZGVmIGNhbl9tb3ZlX2ZpbGVzKHNv'
    'dXJjZSwgdGFyZ2V0LCByZXN1bWluZyk6CiAgICBmb3Igb2xkLCBuZXcgaW4gKChzb3VyY2Uucm9vdCwgdGFyZ2V0LnJvb3Qp'
    'LCAoc291cmNlLnJ1bnRpbWUsIHRhcmdldC5ydW50aW1lKSwgKHNvdXJjZS5zdGF0ZSwgdGFyZ2V0LnN0YXRlKSk6CiAgICAg'
    'ICAgaWYgb2xkLmlzX3N5bWxpbmsoKSBvciBuZXcuaXNfc3ltbGluaygpIG9yIChvbGQuZXhpc3RzKCkgYW5kIG5ldy5leGlz'
    'dHMoKSk6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGlmIG5ldy5leGlzdHMoKSBhbmQgbm90IHJlc3VtaW5n'
    'OgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBmb3IgcGF0aCBpbiAob2xkLCBuZXcpOgogICAgICAgICAgICBp'
    'ZiBub3QgcGF0aC5leGlzdHMoKToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGluZm8gPSBwYXRoLmxz'
    'dGF0KCkKICAgICAgICAgICAgaWYgaW5mby5zdF91aWQgIT0gb3MuZ2V0ZXVpZCgpOgogICAgICAgICAgICAgICAgcmV0dXJu'
    'IEZhbHNlCiAgICAgICAgICAgIGlmIG9sZCA9PSBzb3VyY2Uuc3RhdGU6CiAgICAgICAgICAgICAgICBpZiBub3Qgc3RhdC5T'
    'X0lTUkVHKGluZm8uc3RfbW9kZSkgb3IgaW5mby5zdF9ubGluayAhPSAxOgogICAgICAgICAgICAgICAgICAgIHJldHVybiBG'
    'YWxzZQogICAgICAgICAgICBlbGlmIG5vdCBzdGF0LlNfSVNESVIoaW5mby5zdF9tb2RlKToKICAgICAgICAgICAgICAgIHJl'
    'dHVybiBGYWxzZQogICAgZm9yIHJvbGUgaW4gVU5JVF9URU1QTEFURVM6CiAgICAgICAgb2xkID0gVU5JVF9ESVIgLyBnZXRh'
    'dHRyKHNvdXJjZSwgcm9sZSkKICAgICAgICBuZXcgPSBVTklUX0RJUiAvIGdldGF0dHIodGFyZ2V0LCByb2xlKQogICAgICAg'
    'IGlmIGFueShvcy5wYXRoLmxleGlzdHModW5pdC53aXRoX25hbWUodW5pdC5uYW1lICsgJy5kJykpIGZvciB1bml0IGluIChv'
    'bGQsIG5ldykpOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICBpZiBvcy5wYXRoLmxleGlzdHMob2xkKSBhbmQg'
    'bm90IG1hbmFnZWRfdW5pdChvbGQsIHNvdXJjZSwgcm9sZSk6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGlm'
    'IG9zLnBhdGgubGV4aXN0cyhuZXcpIGFuZCBub3QgKHJlc3VtaW5nIGFuZCBtYW5hZ2VkX3VuaXQobmV3LCB0YXJnZXQsIHJv'
    'bGUpKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgZm9yIGxpbmsgaW4gdW5pdF9saW5rcyhvbGQubmFtZSk6'
    'CiAgICAgICAgICAgIHJlcGxhY2VtZW50ID0gbGluay53aXRoX25hbWUobmV3Lm5hbWUpCiAgICAgICAgICAgIGlmIG5vdCBs'
    'aW5rLmlzX3N5bWxpbmsoKSBvciBsaW5rLnJlc29sdmUoKSAhPSBvbGQ6CiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UK'
    'ICAgICAgICAgICAgaWYgb3MucGF0aC5sZXhpc3RzKHJlcGxhY2VtZW50KSBhbmQgbm90IChyZXN1bWluZyBhbmQgcmVwbGFj'
    'ZW1lbnQuaXNfc3ltbGluaygpIGFuZCByZXBsYWNlbWVudC5yZXNvbHZlKCkgPT0gbmV3KToKICAgICAgICAgICAgICAgIHJl'
    'dHVybiBGYWxzZQogICAgICAgIGlmIG5vdCByZXN1bWluZyBhbmQgYW55KHVuaXRfbGlua3MobmV3Lm5hbWUpKToKICAgICAg'
    'ICAgICAgcmV0dXJuIEZhbHNlCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiB1cGRhdGVfZ2VuZXJhdGVkX3BhdGhzKHJvb3QsIHNv'
    'dXJjZSwgdGFyZ2V0KToKICAgICMgVGhlc2UgdGhyZWUgcHJpdmF0ZSBmaWxlcyBhcmUgZ2VuZXJhdGVkIGJ5IHRoaXMgY2xp'
    'ZW50LiBJZGVudGl0eSBhbmQgY3JlZGVudGlhbCBmaWxlcyBtb3ZlIHVuY2hhbmdlZC4KICAgIHJlcGxhY2VtZW50cyA9IHsK'
    'ICAgICAgICAnc3Ryb25nc3dhbi5jb25mJzogWyhzdHIoc291cmNlLnJ1bnRpbWUpICsgJy8nLCBzdHIodGFyZ2V0LnJ1bnRp'
    'bWUpICsgJy8nKV0sCiAgICAgICAgJ2Nvbm5lY3Rpb24uY29uZic6IFsoc3RyKHNvdXJjZS5yb290KSArICcvJywgc3RyKHRh'
    'cmdldC5yb290KSArICcvJyksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoJ1xuICcgKyBzb3VyY2UuaWtlICsgJyB7'
    'JywgJ1xuICcgKyB0YXJnZXQuaWtlICsgJyB7JyksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoJ1xuICAgJyArIHNv'
    'dXJjZS5pa2UgKyAnLW5ldCB7JywgJ1xuICAgJyArIHRhcmdldC5pa2UgKyAnLW5ldCB7JyldLAogICAgICAgICdmdWxsLWd1'
    'YXJkLm5mdCc6IFsoJ3RhYmxlIGluZXQgJyArIHNvdXJjZS5ndWFyZF90YWJsZSArICcgeycsICd0YWJsZSBpbmV0ICcgKyB0'
    'YXJnZXQuZ3VhcmRfdGFibGUgKyAnIHsnKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKCciJyArIHNvdXJjZS5ob3N0'
    'ICsgJyInLCAnIicgKyB0YXJnZXQuaG9zdCArICciJyldLAogICAgfQogICAgZm9yIG5hbWUsIGNoYW5nZXMgaW4gcmVwbGFj'
    'ZW1lbnRzLml0ZW1zKCk6CiAgICAgICAgcGF0aCA9IHJvb3QgLyBuYW1lCiAgICAgICAgaWYgcGF0aC5pc19zeW1saW5rKCkg'
    'b3Igbm90IHBhdGguaXNfZmlsZSgpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGJlZm9yZSA9IHBhdGgucmVhZF90'
    'ZXh0KCkKICAgICAgICBhZnRlciA9IGJlZm9yZQogICAgICAgIGZvciBvbGQsIG5ldyBpbiBjaGFuZ2VzOgogICAgICAgICAg'
    'ICBhZnRlciA9IGFmdGVyLnJlcGxhY2Uob2xkLCBuZXcpCiAgICAgICAgaWYgYWZ0ZXIgIT0gYmVmb3JlOgogICAgICAgICAg'
    'ICB3cml0ZShwYXRoLCBhZnRlcikKCgpkZWYgbW92ZV9pZGxlX2xheW91dChzb3VyY2UsIHRhcmdldCk6CiAgICAiIiJDYWxs'
    'ZWQgdW5kZXIgdGhlIENMSSBvcGVyYXRpb24gbG9jay4gRWFjaCBkaXNrIHN0ZXAgY2FuIHJlc3VtZSBhZnRlciBpbnRlcnJ1'
    'cHRpb24uIiIiCiAgICBwZW5kaW5nID0gdHJhbnNpdGlvbl9sYXlvdXRzKCkKICAgIGlmIHBlbmRpbmcgYW5kIHBlbmRpbmcg'
    'IT0gKHNvdXJjZSwgdGFyZ2V0KToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cj0LbQtSDQstGL0L/QvtC70L3Rj9C1'
    '0YLRgdGPINC00YDRg9Cz0L7QuSDQv9C10YDQtdC90L7RgSDRhNCw0LnQu9C+0LIgVlBOLicpCiAgICBpZiBub3QgcGVuZGlu'
    'ZyBhbmQgbm90IGhhc19sYXlvdXQoc291cmNlKToKICAgICAgICB1c2VfbGF5b3V0KHRhcmdldCkKICAgICAgICByZXR1cm4g'
    'VHJ1ZQogICAgaWYgbGF5b3V0X2luX3VzZShzb3VyY2UpIG9yIGxheW91dF9pbl91c2UodGFyZ2V0LCBjaGVja19kZXN0aW5h'
    'dGlvbj1UcnVlKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlmIG5vdCBjYW5fbW92ZV9maWxlcyhzb3VyY2UsIHRhcmdl'
    'dCwgYm9vbChwZW5kaW5nKSk6CiAgICAgICAgaWYgcGVuZGluZzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQ'
    'n9C10YDQtdC90L7RgSDQv9GA0LjQvtGB0YLQsNC90L7QstC70LXQvSDQuNC3LdC30LAg0LrQvtC90YTQu9C40LrRgtCwINGE'
    '0LDQudC70L7QsiBWUE4uJykKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlmIG5vdCBwZW5kaW5nOgogICAgICAgIHdyaXRl'
    'KExBWU9VVF9UUkFOU0FDVElPTiwgJ3VwZ3JhZGUnIGlmIHRhcmdldCA9PSBDVVJSRU5UIGVsc2UgJ3JvbGxiYWNrJykKCiAg'
    'ICBmb3Igcm9sZSBpbiBVTklUX1RFTVBMQVRFUzoKICAgICAgICBvbGQgPSBVTklUX0RJUiAvIGdldGF0dHIoc291cmNlLCBy'
    'b2xlKQogICAgICAgIG5ldyA9IFVOSVRfRElSIC8gZ2V0YXR0cih0YXJnZXQsIHJvbGUpCiAgICAgICAgaWYgbm90IG9sZC5l'
    'eGlzdHMoKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiBub3QgbmV3LmV4aXN0cygpOgogICAgICAgICAgICBu'
    'ZnQgPSBzaHV0aWwud2hpY2goJ25mdCcpIG9yICcvdXNyL3NiaW4vbmZ0JwogICAgICAgICAgICB3cml0ZShuZXcsIHVuaXRf'
    'dGV4dCh0YXJnZXQsIHJvbGUsIG5mdCksIG1vZGU9MG82NDQpCiAgICAgICAgZm9yIGxpbmsgaW4gdW5pdF9saW5rcyhvbGQu'
    'bmFtZSk6CiAgICAgICAgICAgIHJlcGxhY2VtZW50ID0gbGluay53aXRoX25hbWUobmV3Lm5hbWUpCiAgICAgICAgICAgIGlm'
    'IG5vdCByZXBsYWNlbWVudC5pc19zeW1saW5rKCk6CiAgICAgICAgICAgICAgICByZXBsYWNlbWVudC5zeW1saW5rX3RvKG9z'
    'LnBhdGgucmVscGF0aChuZXcsIGxpbmsucGFyZW50KSkKICAgICAgICAgICAgbGluay51bmxpbmsoKQogICAgICAgIG9sZC51'
    'bmxpbmsoKQogICAgZm9yIG9sZCwgbmV3IGluICgoc291cmNlLnN0YXRlLCB0YXJnZXQuc3RhdGUpLCAoc291cmNlLnJ1bnRp'
    'bWUsIHRhcmdldC5ydW50aW1lKSwgKHNvdXJjZS5yb290LCB0YXJnZXQucm9vdCkpOgogICAgICAgIGlmIG9sZC5leGlzdHMo'
    'KToKICAgICAgICAgICAgb2xkLnJlbmFtZShuZXcpCiAgICB1cGRhdGVfZ2VuZXJhdGVkX3BhdGhzKHRhcmdldC5yb290LCBz'
    'b3VyY2UsIHRhcmdldCkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZGFlbW9uLXJlbG9hZCddKQogICAgTEFZT1VUX1RS'
    'QU5TQUNUSU9OLnVubGluaygpCiAgICB1c2VfbGF5b3V0KHRhcmdldCkKICAgIHJldHVybiBUcnVlCgoKZGVmIGZpbmlzaF9u'
    'YW1lX3RyYW5zaXRpb24oKToKICAgIHBlbmRpbmcgPSB0cmFuc2l0aW9uX2xheW91dHMoKQogICAgaWYgcGVuZGluZzoKICAg'
    'ICAgICBpZiBub3QgbW92ZV9pZGxlX2xheW91dCgqcGVuZGluZyk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    '0J/QtdGA0LXQvdC+0YEg0LjQvNGR0L0gVlBOINC10YnRkSDQvdC1INC30LDQstC10YDRiNGR0L0uJykKICAgIGVsaWYgTEFZ'
    'T1VUID09IExFR0FDWToKICAgICAgICBtb3ZlX2lkbGVfbGF5b3V0KExFR0FDWSwgQ1VSUkVOVCkKCgpkZWYgbWlncmF0ZV91'
    'bml0X21vZGVzKCk6CiAgICAiIiJNYWtlIGVhcmxpZXIgZ2VuZXJhdGVkIHNlcnZpY2UgZGVzY3JpcHRpb25zIHJlYWRhYmxl'
    'LCBpbmNsdWRpbmcgb24gaWRsZSBjbGllbnRzLiIiIgogICAgZm9yIHJvbGUgaW4gVU5JVF9URU1QTEFURVM6CiAgICAgICAg'
    'bmFtZSA9IGdldGF0dHIoTEFZT1VULCByb2xlKQogICAgICAgIHRyeToKICAgICAgICAgICAgZmQgPSBvcy5vcGVuKFVOSVRf'
    'RElSIC8gbmFtZSwgb3MuT19SRE9OTFkgfCBvcy5PX05PRk9MTE9XIHwgb3MuT19OT05CTE9DSykKICAgICAgICBleGNlcHQg'
    'T1NFcnJvciBhcyBlcnJvcjoKICAgICAgICAgICAgaWYgZXJyb3IuZXJybm8gaW4gKGVycm5vLkVOT0VOVCwgZXJybm8uRUxP'
    'T1ApOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgcmFpc2UKICAgICAgICB0cnk6CiAgICAgICAgICAg'
    'IGluZm8gPSBvcy5mc3RhdChmZCkKICAgICAgICAgICAgaWYgKG5vdCBzdGF0LlNfSVNSRUcoaW5mby5zdF9tb2RlKSBvciBp'
    'bmZvLnN0X25saW5rICE9IDEKICAgICAgICAgICAgICAgICAgICBvciBpbmZvLnN0X3VpZCAhPSBvcy5nZXRldWlkKCkgb3Ig'
    'c3RhdC5TX0lNT0RFKGluZm8uc3RfbW9kZSkgIT0gMG82MDApOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg'
    'ICAgIyBBIGxvY2FsIHJlcGxhY2VtZW50IG1heSBjb250YWluIGNyZWRlbnRpYWxzLiBPbmx5IG1pZ3JhdGUgb3VyIG93biB0'
    'ZW1wbGF0ZXMuCiAgICAgICAgICAgIGlmIGluZm8uc3Rfc2l6ZSA8IDQwOTYgYW5kIGtub3duX3VuaXQoTEFZT1VULCByb2xl'
    'LCBvcy5yZWFkKGZkLCA0MDk2KSk6CiAgICAgICAgICAgICAgICBvcy5mY2htb2QoZmQsIDBvNjQ0KQogICAgICAgIGZpbmFs'
    'bHk6CiAgICAgICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBwZXJzaXN0X2d1YXJkKHJ1bGVzKToKICAgICMgR3VhcmQgcGVy'
    'c2lzdGVuY2UgcHJlY2VkZXMgc3dpdGNoaW5nLiBDbGVhbnVwIGFmdGVyIGEgY3Jhc2ggbmV2ZXIgb3BlbnMgdGhlIEludGVy'
    'bmV0LgogICAgbmZ0ID0gc2h1dGlsLndoaWNoKCduZnQnKQogICAgaWYgbm90IG5mdDoKICAgICAgICByYWlzZSBGaWxlTm90'
    'Rm91bmRFcnJvcignbmZ0JykKICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKICAgIHdyaXRlKFVOSVRf'
    'RElSIC8gR1VBUkRfVU5JVCwgdW5pdF90ZXh0KExBWU9VVCwgJ2d1YXJkJywgbmZ0KSwgbW9kZT0wbzY0NCkKICAgIGNvbW1h'
    'bmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZW5hYmxlJyxHVUFS'
    'RF9VTklUXSkKCgpkZWYgYWN0aXZhdGVfZnVsbChhZGRyZXNzKToKICAgIG9sZF9hZGRyZXNzZXMgPSBbYVsnbG9jYWwnXSBm'
    'b3IgbGluayBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hvdycsJ3Njb3BlJywnZ2xv'
    'YmFsJ10pLnN0ZG91dCkKICAgICAgICAgICAgICAgICAgICAgaWYgbGluay5nZXQoJ2lmbmFtZScpIG5vdCBpbiAoSE9TVCxG'
    'VUxMX0hPU1QpCiAgICAgICAgICAgICAgICAgICAgIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRyX2luZm8nLFtdKSBpZiBhLmdl'
    'dCgnc2NvcGUnKSA9PSAnZ2xvYmFsJ10KICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6CiAgICAgICAgaWYgUGF0'
    'aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1QpLmV4aXN0cygpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'J2Z1bGxfaW50ZXJmYWNlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFi'
    'bGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVy'
    'cm9yKCdmdWxsX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFi'
    'bGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcignYWRtaW5fdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBhbnkoci5nZXQoJ3ByaW9yaXR5JykgaW4gKDc5LDgw'
    'KSBmb3IgciBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdydWxlJ10pLnN0ZG91dCkpOgogICAgICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfcnVsZV9jb2xsaXNpb24nKQogICAgICAgIHdyaXRlKGZ1bGxfc3RhdGUo'
    'KSxqc29uLmR1bXBzKHsnYWN0aXZlJzpGYWxzZX0pKQogICAgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcykKICAgIHN0YXJ0X25h'
    'bWVzcGFjZV9kbnMoKQogICAgIyBWYWxpZGF0ZSB0aGUgZWdyZXNzIGZpbHRlciBiZWZvcmUgaW50ZXJydXB0aW5nIHRoZSBw'
    'cmV2aW91cyBWUE4uCiAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZXN0'
    'b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICAjIFJlcGFpciBtYXkgaW5oZXJp'
    'dCBhIGd1YXJkIGZyb20gYW4gb2xkZXIgdmVyc2lvbi4gUmVwbGFjZSBvdXIgdGFibGUgaW4KICAgICMgb25lIG5mdCB0cmFu'
    'c2FjdGlvbiwgc28gZml4ZXMgYXBwbHkgd2l0aG91dCBvcGVuaW5nIGFuIHVuZ3VhcmRlZCB3aW5kb3cuCiAgICByZXBsYWNl'
    'bWVudCA9ICgnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicgaWYgZnVsbF9ndWFyZF9hY3RpdmUoKSBlbHNl'
    'ICcnKStydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKICAgIGNvbW1h'
    'bmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgcGVyc2lzdF9ndWFyZChydWxlcykKICAgICMgVGhp'
    'cyBjb21tYW5kIHN0b3BzIG9ubHkgdGhpcyBtYW5hZ2VyJ3MgcHJldmlvdXMgWHJheSBtb2RlIGFuZCByZW1vdmVzIGl0cyBn'
    'dWFyZC4KICAgIGNvbW1hbmQoWycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJyxMQVlPVVQuY29tbWFuZF9wcmVmaXgrJy1wYXVz'
    'ZS1tYWluJ10sdGltZW91dD00MCkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywn'
    'ZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLEZVTExfVEFCTEVdKQogICAgY29tbWFuZChbJ2lwJywncm91dGUn'
    'LCdyZXBsYWNlJywnZGVmYXVsdCcsJ3ZpYScsJzE3Mi4yOS4yNDcuMicsJ2RldicsRlVMTF9IT1NULCdtZXRyaWMnLCcxMCcs'
    'J3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzgwJywnbG9v'
    'a3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBydWxlIGluIChbJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJ'
    'RU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sCiAgICAgICAgICAgICAgICAgWydwcmlvcml0eScsJzc5JywnaWlmJyxGVUxM'
    'X0hPU1QsJ2xvb2t1cCcsJ21haW4nXSk6CiAgICAgICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsKnJ1bGVdLGNoZWNr'
    'PUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCpydWxlXSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1'
    'bGUnLCdhZGQnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSkKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxs'
    'X3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBhbmQgY29tbWFuZChbJ3N5'
    'c3RlbWN0bCcsJ2lzLWFjdGl2ZScsJy0tcXVpZXQnLCdzeXN0ZW1kLXJlc29sdmVkJ10sY2hlY2s9RmFsc2UpLnJldHVybmNv'
    'ZGUgPT0gMDoKICAgICAgICBkYXRhWydkbnNfbW9kZSddPSdyZXNvbHZlZF9saW5rJwogICAgICAgIHdyaXRlKGZ1bGxfc3Rh'
    'dGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG5zJyxGVUxMX0hPU1QsJzE3'
    'Mi4yOS4yNDcuMiddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG9tYWluJyxGVUxMX0hPU1QsJ34uJ10pCiAg'
    'ICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkZWZhdWx0LXJvdXRlJyxGVUxMX0hPU1QsJ3llcyddKQogICAgICAgIGNv'
    'bW1hbmQoWydyZXNvbHZlY3RsJywnZmx1c2gtY2FjaGVzJ10sY2hlY2s9RmFsc2UpCiAgICBlbHNlOgogICAgICAgIHVzZV9y'
    'ZXNvbHZlcl9maWxlKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIHJldGlyZV9wcmV2'
    'aW91c19jb25uZWN0aW9ucyhvbGRfYWRkcmVzc2VzKQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAgIHBvbGlj'
    'eS5hcHBseSgpCiAgICBpZiBub3QgcmVjb3Zlcl9zeXN0ZW1fZG5zKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdz'
    'eXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICAjIFRlc3QgdGhlIGFjdHVhbCBob3N0IHBhdGggYXMgd2VsbCBhcyBuYW1lc3BhY2Ug'
    'cHJvYmVzIGJlZm9yZSBhbm5vdW5jaW5nIGNvbm5lY3RlZC4KICAgIGNoZWNrID0gY29tbWFuZChbJ2N1cmwnLCctNCcsJy0t'
    'bm9wcm94eScsJycgaWYgcG9saWN5IGlzIG5vdCBOb25lIGVsc2UgJyonLCctLWZhaWwnLCctLXNpbGVudCcsJy0tbWF4LXRp'
    'bWUnLCcxMCcsKihbJy0tc29ja3M1LWhvc3RuYW1lJywnMTI3LjAuMC4xOjE4NTU0J10gaWYgcG9saWN5IGlzIG5vdCBOb25l'
    'IGVsc2UgW10pLCdodHRwczovL2FwaS5pcGlmeS5vcmcnXSx0aW1lb3V0PTEyKQogICAgaWYgY2hlY2suc3Rkb3V0LnN0cmlw'
    'KCkgIT0gJzM4LjE4MC4xNjQuNjcnOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaG9zdF9lZ3Jlc3NfZmFpbGVkJykK'
    'ICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBkYXRhWydhY3RpdmUnXT1UcnVlCiAg'
    'ICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKCgpkZWYgY2xlYW51cF9mdWxsKHJlbGVhc2U9RmFsc2Up'
    'OgogICAgZ2xvYmFsIEROU19QUk9DRVNTCiAgICBpZiBETlNfUFJPQ0VTUyBpcyBub3QgTm9uZSBhbmQgRE5TX1BST0NFU1Mu'
    'cG9sbCgpIGlzIE5vbmU6CiAgICAgICAgRE5TX1BST0NFU1MudGVybWluYXRlKCkKICAgICAgICB0cnk6RE5TX1BST0NFU1Mu'
    'd2FpdCh0aW1lb3V0PTMpCiAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6RE5TX1BST0NFU1Mua2ls'
    'bCgpO0ROU19QUk9DRVNTLndhaXQoKQogICAgRE5TX1BST0NFU1M9Tm9uZQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgog'
    'ICAgICAgIHBvbGljeS5zdG9wKHJlbGVhc2U9cmVsZWFzZSkKICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6CiAg'
    'ICAgICAgcmV0dXJuCiAgICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgY29tbWFuZChb'
    'J2lwJywncm91dGUnLCdkZWwnLCdkZWZhdWx0JywnbWV0cmljJywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFs'
    'c2UpCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnZGVsJyxGVUxMX0hPU1RdLGNoZWNrPUZhbHNlKQogICAgIyBPbiBmYWls'
    'dXJlOiByZXRhaW4gcm91dGluZywgRE5TIGFuZCB0aGUgcGVyc2lzdGVudCBndWFyZCB1bnRpbCBleHBsaWNpdCBkaXNjb25u'
    'ZWN0LgogICAgaWYgbm90IHJlbGVhc2U6CiAgICAgICAgcmV0dXJuCiAgICByZXN0b3JlX3Jlc29sdmVyX2ZpbGUoZGF0YSkK'
    'ICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVj'
    'az1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMy'
    'JywnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5'
    'JywnNzknLCdpaWYnLEZVTExfSE9TVCwnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywn'
    'cm91dGUnLCdmbHVzaCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBzZXJ2ZXIgaW4gKCcxOTIu'
    'MTY4LjAuMTYzJywgJzM4LjE4MC4xNjQuNjcnKToKICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3Jp'
    'dHknLCc3OScsJ3RvJyxzZXJ2ZXIsJ2lwcHJvdG8nLCd0Y3AnLCdkcG9ydCcsJzIyJywnbG9va3VwJyxBRE1JTl9UQUJMRV0s'
    'Y2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZGlzYWJsZScsJy0tbm93JyxHVUFSRF9VTklUXSxjaGVj'
    'az1GYWxzZSkKICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZh'
    'bHNlKQogICAgY2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkK'
    'ICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKQogICAg'
    'ZnVsbF9zdGF0ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNoZWNrPUZh'
    'bHNlKSBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNlIE5vbmUKCgpkZWYgY29tbWFuZChhcmdzLCBjaGVjaz1U'
    'cnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0cih4KSBm'
    'b3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0dXJlX291dHB1dD1UcnVlLAogICAgICAgICAgICAg'
    'ICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAgaWYgY2hlY2sgYW5kIGNwLnJl'
    'dHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4gYSBDU1IgcGF0aDsgZG8gbm90IHByb3BhZ2F0ZSBw'
    'cm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2NvbW1hbmRfZmFpbGVkJykK'
    'ICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIGNvbW1hbmQoWydpcCcsICdu'
    'ZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVmIHdyaXRlKHBhdGgsIHZhbHVlLCAqLCBtb2RlPTBv'
    'NjAwKToKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkKICAg'
    'IGZkLCB0ZW1wb3JhcnkgPSB0ZW1wZmlsZS5ta3N0ZW1wKHByZWZpeD0nLicgKyBwYXRoLm5hbWUgKyAnLicsIGRpcj1wYXRo'
    'LnBhcmVudCkKICAgIHRyeToKICAgICAgICB3aXRoIG9zLmZkb3BlbihmZCwgJ3cnKSBhcyBzdHJlYW06CiAgICAgICAgICAg'
    'IHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgICAgICAgICAgc3RyZWFtLmZsdXNoKCkKICAgICAgICAgICAgb3MuZmNobW9kKGZk'
    'LCBtb2RlKQogICAgICAgIG9zLnJlcGxhY2UodGVtcG9yYXJ5LCBwYXRoKQogICAgZmluYWxseToKICAgICAgICBQYXRoKHRl'
    'bXBvcmFyeSkudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgpkZWYgc2F2ZWQoKToKICAgIHRyeToKICAgICAgICByZXR1cm4g'
    'anNvbi5sb2FkcyhTVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAg'
    'cmV0dXJuIHt9CgoKZGVmIHN0YWdlKHBoYXNlLCBtZXNzYWdlLCBwcm9ncmVzcywgKipmaWVsZHMpOgogICAgZGF0YSA9IHsq'
    'KnNhdmVkKCksICdwaGFzZSc6IHBoYXNlLCAnbWVzc2FnZSc6IG1lc3NhZ2UsICdwcm9ncmVzcyc6IHByb2dyZXNzLAogICAg'
    'ICAgICAgICAndXBkYXRlZCc6IGludCh0aW1lLnRpbWUoKSksICdoZWFydGJlYXQnOiB0aW1lLm1vbm90b25pYygpLCAqKmZp'
    'ZWxkc30KICAgIHdyaXRlKFNUQVRFLCBqc29uLmR1bXBzKGRhdGEsIGVuc3VyZV9hc2NpaT1GYWxzZSkpCiAgICBpZiBzdXBw'
    'b3J0X2FwaSBpcyBub3QgTm9uZToKICAgICAgICB0cnk6c3VwcG9ydF9hcGkucmVjb3JkKFJPT1Qsd3JpdGUsZGF0YSkKICAg'
    'ICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixUeXBlRXJyb3IpOnBhc3MKCgpkZWYgc2VsZWN0ZWRfcm91dGUoKToK'
    'ICAgIHRyeTp2YWx1ZT1qc29uLmxvYWRzKChST09ULydzZWxlY3Rpb24uanNvbicpLnJlYWRfdGV4dCgpKS5nZXQoJ3JvdXRl'
    'JywnYXV0bycpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixBdHRyaWJ1dGVFcnJvcik6dmFsdWU9J2F1dG8nCiAg'
    'ICByZXR1cm4gdmFsdWUgaWYgdmFsdWUgaW4geydhdXRvJywqKGNbJ2lkJ10gZm9yIGMgaW4gQ0FORElEQVRFUyl9IGVsc2Ug'
    'J2F1dG8nCgoKZGVmIHNlbGVjdF9yb3V0ZSh2YWx1ZSk6CiAgICBpZiB2YWx1ZSBub3QgaW4geydhdXRvJywqKGNbJ2lkJ10g'
    'Zm9yIGMgaW4gQ0FORElEQVRFUyl9OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdGL0Lkg0LzQsNGA0YjR'
    'gNGD0YIuJykKICAgIHdyaXRlKFJPT1QvJ3NlbGVjdGlvbi5qc29uJyxqc29uLmR1bXBzKHsncm91dGUnOnZhbHVlfSkpCgoK'
    'ZGVmIHJvdXRlX2Nob2ljZXMoKToKICAgIHJhbmtpbmc9cmFua19hcGkuUmFua2luZyhST09ULydyYW5raW5nLmpzb24nLFtj'
    'WydpZCddIGZvciBjIGluIENBTkRJREFURVNdKSBpZiByYW5rX2FwaSBlbHNlIE5vbmUKICAgIG9yZGVyPXJhbmtpbmcuY2Fu'
    'ZGlkYXRlcygpIGlmIHJhbmtpbmcgYW5kIHJhbmtpbmcubG9hZCgpIGVsc2UgW10KICAgIHJldHVybiB7J3NlbGVjdGVkJzpz'
    'ZWxlY3RlZF9yb3V0ZSgpLCdjaG9pY2VzJzpbeydpZCc6Y1snaWQnXSwnbGFiZWwnOmNbJ2xhYmVsJ119IGZvciBjIGluIENB'
    'TkRJREFURVNdLAogICAgICAgICAgICAnb3JkZXInOm9yZGVyLCdlbnRyaWVzJzpyYW5raW5nLmRhdGFbJ2VudHJpZXMnXSBp'
    'ZiBvcmRlciBlbHNlIHt9fQoKCmRlZiBzdGF0dXMoKToKICAgIGRhdGEgPSBzYXZlZCgpCiAgICBydW5uaW5nID0gY29tbWFu'
    'ZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcsIFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yKS5y'
    'ZXR1cm5jb2RlID09IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScpID09ICdjb25uZWN0ZWQnIGFuZCAobm90IHJ1bm5pbmcg'
    'b3IgdGltZS5tb25vdG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0JywgMCkgPiA5MCk6CiAgICAgICAgZGF0YS51cGRhdGUo'
    'cGhhc2U9J2ludGVycnVwdGVkJywgbWVzc2FnZT0n0KHQvtC10LTQuNC90LXQvdC40LUg0L7RgdGC0LDQvdC+0LLQuNC70L7R'
    'gdGMLiDQn9GA0L7QstC10YDRjNGC0LUg0YHQvtGB0YLQvtGP0L3QuNC1INC30LDRidC40YLRiyDQuCDQvdCw0LbQvNC40YLQ'
    'tSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nLCBhY3RpdmU9RmFsc2UpCiAgICBwdWJsaWMgPSB7a2V5OiBkYXRhW2tleV0gZm9y'
    'IGtleSBpbiAoJ3BoYXNlJywgJ21lc3NhZ2UnLCAncHJvZ3Jlc3MnLCAnYWN0aXZlJywgJ3VwZGF0ZWQnLCAnbWV0cmljcycs'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnc2NvcGUnLCAnc2luY2UnLCAncmV0cnknLCAnZXJy'
    'b3JfY29kZScsICdwYXRoJykgaWYga2V5IGluIGRhdGF9CiAgICB0b2tlbl9pbmZvID0gdG9rZW5fc3RhdHVzKCkKICAgIHJl'
    'dHVybiB7J3BoYXNlJzogJ29mZicsICdtZXNzYWdlJzogKCfQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC8'
    '0LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nIGlmIHRva2VuX2luZm9bJ2hhc190b2tlbiddIGVsc2UgJ9CS0LLQ'
    'tdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKSwKICAgICAg'
    'ICAgICAgJ3Byb2dyZXNzJzogMCwgJ2FjdGl2ZSc6IEZhbHNlLCAqKnB1YmxpYywgJ3J1bm5pbmcnOiBydW5uaW5nLAogICAg'
    'ICAgICAgICAqKnRva2VuX2luZm8sICoqZGV2aWNlX3N0YXR1cygpLCAncm91dGVzJzpyb3V0ZV9jaG9pY2VzKCksICdpc29s'
    'YXRlZCc6IEZhbHNlLCAnZnVsbF9kZXZpY2UnOiBUcnVlLCAnZ3VhcmQnOiBmdWxsX2d1YXJkX2FjdGl2ZSgpLCAncHJvdG9j'
    'b2wnOiAnSUtFdjIg4oaSINCt0YHRgtC+0L3QuNGPJ30KCgpAY29udGV4dGxpYi5jb250ZXh0bWFuYWdlcgpkZWYgbmFtZXNw'
    'YWNlKCk6CiAgICBiZWZvcmUgPSBvcy5vcGVuKCcvcHJvYy9zZWxmL25zL25ldCcsIG9zLk9fUkRPTkxZKQogICAgdGFyZ2V0'
    'ID0gb3Mub3BlbignL3J1bi9uZXRucy8nK05TLCBvcy5PX1JET05MWSkKICAgIHRyeToKICAgICAgICBvcy5zZXRucyh0YXJn'
    'ZXQsIG9zLkNMT05FX05FV05FVCkKICAgICAgICB5aWVsZAogICAgZmluYWxseToKICAgICAgICBvcy5zZXRucyhiZWZvcmUs'
    'IG9zLkNMT05FX05FV05FVCkKICAgICAgICBvcy5jbG9zZSh0YXJnZXQpCiAgICAgICAgb3MuY2xvc2UoYmVmb3JlKQoKCmRl'
    'ZiBwaHlzaWNhbF9yb3V0ZSgpOgogICAgcm91dGVzID0ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCAnLWonLCAnLTQnLCAn'
    'cm91dGUnLCAnc2hvdycsICd0YWJsZScsICdtYWluJywgJ2RlZmF1bHQnXSkuc3Rkb3V0KQogICAgY2FuZGlkYXRlcyA9IFty'
    'IGZvciByIGluIHJvdXRlcyBpZiByLmdldCgnZ2F0ZXdheScpIGFuZCByLmdldCgnZGV2JykgYW5kCiAgICAgICAgICAgICAg'
    'ICAgIG5vdCByWydkZXYnXS5zdGFydHN3aXRoKCgndHVuJywgJ3hyYXknLCAnd2cnLCAnZXZuLScpKV0KICAgIGlmIG5vdCBj'
    'YW5kaWRhdGVzOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignbm9fcGh5c2ljYWxfcm91dGUnKQogICAgcm91dGUgPSBt'
    'aW4oY2FuZGlkYXRlcywga2V5PWxhbWJkYSByOiByLmdldCgnbWV0cmljJywgMCkpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNo'
    'KHInW0EtWmEtejAtOV8uOi1dezEsMTV9Jywgcm91dGVbJ2RldiddKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2lu'
    'dmFsaWRfaW50ZXJmYWNlJykKICAgIGlwYWRkcmVzcy5JUHY0QWRkcmVzcyhyb3V0ZVsnZ2F0ZXdheSddKQogICAgcmV0dXJu'
    'IHJvdXRlCgoKZGVmIGhvc3RfcnVsZXMoaWZhY2UsIHByZXZpb3VzX2ZvcndhcmQ9VHJ1ZSk6CiAgICAjIFNjb3BlIGV2ZXJ5'
    'IG5ldyBmb3J3YXJkaW5nL05BVCBydWxlIHRvIG91ciBvbmUgaW50ZXJmYWNlIGFuZCB0aGUgY29uZmlndXJlZCBpbmdyZXNz'
    'IGFkZHJlc3MuCiAgICBwcmVzZXJ2ZV9kaXNhYmxlZCA9ICcnIGlmIHByZXZpb3VzX2ZvcndhcmQgZWxzZSAnJycgIGlpZm5h'
    'bWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgYWNjZXB0CiAgb2lmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJv'
    'dG8gaXB2NCBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnJycK'
    'ICAgIHJldHVybiBmJycndGFibGUgaW5ldCB7TkZUfSB7ewogY2hhaW4gZm9yd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sg'
    'Zm9yd2FyZCBwcmlvcml0eSAtMjA7IHBvbGljeSBhY2NlcHQ7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VS'
    'VkVSfSB9fSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9'
    'IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRy'
    'IHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBp'
    'aWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDE5NS4yMDkuMjExLjE2MyB0Y3AgZHBvcnQgMjQ1'
    'NzkgYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2Nl'
    'cHQKICBpaWZuYW1lICJ7SE9TVH0iIGRyb3AKICBvaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJWRVJ9LCAzOC4x'
    'ODAuMTY0LjY3IH19IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBkcm9w'
    'CntwcmVzZXJ2ZV9kaXNhYmxlZH0KIH19CiBjaGFpbiBuYXQge3sKICB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9y'
    'aXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBpcCBzYWRkciB7Q0xJRU5UfSBvaWZuYW1lICJ7aWZhY2V9IiBtYXNxdWVy'
    'YWRlCiB9fQp9fScnJwoKCmRlZiBzZXR1cF9uZXR3b3JrKCk6CiAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICMg'
    'UmVmdXNlIG5hbWUvYWRkcmVzcyBjb2xsaXNpb25zIHJhdGhlciB0aGFuIHJlcHVycG9zaW5nIGFub3RoZXIgYXBwbGljYXRp'
    'b24ncyByZXNvdXJjZXMuCiAgICBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIG9yIFBhdGgoJy9zeXMvY2xh'
    'c3MvbmV0LycrSE9TVCkuZXhpc3RzKCkgb3IgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykuZXhpc3RzKCk6CiAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCd0ZXN0X25hbWVzcGFjZV9leGlzdHMnKQogICAgaWYgY29tbWFuZChbJ2lwJywgJy00JywgJ3Jv'
    'dXRlJywgJ3Nob3cnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF90YWJsZV9pbl91c2UnKQogICAgaWYgYW55KE5FVFdPUksgaW4gbGluZSBmb3Ig'
    'bGluZSBpbiBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsICdhbGwnXSkuc3Rkb3V0LnNw'
    'bGl0bGluZXMoKSk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X25ldHdvcmtfaW5fdXNlJykKICAgIG9sZF9m'
    'b3J3YXJkID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICAj'
    'IFJlY29yZCBvd25lcnNoaXAgYmVmb3JlIGNyZWF0aW5nIGFueXRoaW5nOiBjbGVhbnVwIGlzIHZhbGlkIGFmdGVyIGV2ZXJ5'
    'IHBhcnRpYWwgc3RlcC4KICAgIHVwbGluayA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvcm91dGVbJ2Rldidd'
    'Lydmb3J3YXJkaW5nJwogICAgd3JpdGUoUk9PVC8nbmV0d29yay5qc29uJywganNvbi5kdW1wcyh7J2ZvcndhcmQnOiBvbGRf'
    'Zm9yd2FyZCwgJ2ludGVyZmFjZSc6IHJvdXRlWydkZXYnXSwgJ3VwbGlua19mb3J3YXJkJzogdXBsaW5rLnJlYWRfdGV4dCgp'
    'LnN0cmlwKCl9KSkKICAgIGNvbW1hbmQoWydpcCcsICduZXRucycsICdhZGQnLCBOU10pCiAgICB3cml0ZShQYXRoKCcvZXRj'
    'L25ldG5zJykvTlMvJ3Jlc29sdi5jb25mJywgJ25hbWVzZXJ2ZXIgMS4xLjEuMVxubmFtZXNlcnZlciA5LjkuOS45XG5vcHRp'
    'b25zIHRpbWVvdXQ6MiBhdHRlbXB0czoyXG4nKQogICAgIyBuc3MtcmVzb2x2ZSB0YWxrcyB0byB0aGUgaG9zdCBkYWVtb24g'
    'b3ZlciBhIFVuaXggc29ja2V0IGV2ZW4gaW5zaWRlIG5ldG5zLgogICAgbnNzPVBhdGgoJy9ldGMvbnNzd2l0Y2guY29uZicp'
    'LnJlYWRfdGV4dCgpCiAgICBuc3M9cmUuc3ViKHInXmhvc3RzOi4qJCcsICdob3N0czogZmlsZXMgZG5zJywgbnNzLCBmbGFn'
    'cz1yZS5NKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJywgbnNzKQogICAgY29tbWFu'
    'ZChbJ2lwJywgJ2xpbmsnLCAnYWRkJywgSE9TVCwgJ3R5cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUnLCBQRUVSXSkKICAg'
    'IGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIFBFRVIsICduZXRucycsIE5TXSkKICAgIGNvbW1hbmQoWydpcCcsICdh'
    'ZGRyJywgJ2FkZCcsIEdBVEVXQVkrJy8zMCcsICdkZXYnLCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3Nl'
    'dCcsIEhPU1QsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8zMCcsICdkZXYnLCBQ'
    'RUVSXSkKICAgIGluc2lkZShbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICds'
    'aW5rJywgJ3NldCcsICdsbycsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ2RlZmF1bHQnLCAn'
    'dmlhJywgR0FURVdBWV0pCiAgICAjIEEgcmVjb25uZWN0IGNyZWF0ZXMgYSBORVcgVENQIHNvY2tldCBhZnRlciBJS0UgaW5z'
    'dGFsbHMgaXRzIGRlZmF1bHQgcm91dGUuCiAgICAjIEtlZXAgdGhlIHJlbGF5IHNvY2tldCBvbiB0aGUgbmFtZXNwYWNlIHVw'
    'bGluayB3aXRoIHRoZSBwaHlzaWNhbCB2ZXRoIHNvdXJjZTsKICAgICMgb3RoZXJ3aXNlIHNvdXJjZSBzZWxlY3Rpb24gZ2l2'
    'ZXMgaXQgdGhlIFZQTiBWSVAgYW5kIHR1bm5lbHMgaXQgaW50byBpdHNlbGYuCiAgICBpZiBBQ1RJVkUuZ2V0KCd0cmFuc3Bv'
    'cnRfYWRkcmVzcycpOgogICAgICAgIGluc2lkZShbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5JywnODknLCd0bycsQUNU'
    'SVZFWyd0cmFuc3BvcnRfYWRkcmVzcyddKycvMzInLAogICAgICAgICAgICAgICAgJ2lwcHJvdG8nLCd0Y3AnLCdkcG9ydCcs'
    'c3RyKEFDVElWRVsndHJhbnNwb3J0X3BvcnQnXSksJ2xvb2t1cCcsJ21haW4nXSkKICAgIGNvbW1hbmQoWydpcCcsICdyb3V0'
    'ZScsICdhZGQnLCAndGFibGUnLCBzdHIoVEFCTEUpLCAnZGVmYXVsdCcsICd2aWEnLCByb3V0ZVsnZ2F0ZXdheSddLCAnZGV2'
    'Jywgcm91dGVbJ2RldiddXSkKICAgIGZvciBhZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICBjb21tYW5kKFsnaXAnLCAn'
    'cnVsZScsICdhZGQnLCAncHJpb3JpdHknLCBzdHIoUFJJT1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAg'
    'ICAgICAgICAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICBydWxlcyA9IGhvc3RfcnVs'
    'ZXMocm91dGVbJ2RldiddLCBwcmV2aW91c19mb3J3YXJkPW9sZF9mb3J3YXJkID09ICcxJykKICAgIGNvbW1hbmQoWyduZnQn'
    'LCAnLWMnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVs'
    'ZXMpCiAgICAjIFBlci1pbnRlcmZhY2UgZm9yd2FyZGluZyBhdm9pZHMgaXBfZm9yd2FyZCdzIGdsb2JhbCBkZWZhdWx0cyBy'
    'ZXNldC4KICAgIChQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvY29uZicpL0hPU1QvJ2ZvcndhcmRpbmcnKS53cml0ZV90ZXh0'
    'KCcxXG4nKQogICAgdXBsaW5rLndyaXRlX3RleHQoJzFcbicpCgoKZGVmIGNsZWFudXAoKToKICAgIGNsZWFudXBfZnVsbCgp'
    'CiAgICAjIEFuIHVub3duZWQgbmFtZXNwYWNlL3RhYmxlIG11c3QgbmV2ZXIgYmUgZGVsZXRlZCBieSBhIGdlbmVyaWMgY2xl'
    'YW51cCBjYWxsLgogICAgaWYgbm90IChST09ULyduZXR3b3JrLmpzb24nKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAg'
    'IGRhdGEgPSBqc29uLmxvYWRzKChST09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGNvbW1hbmQoWyduZnQn'
    'LCAnZGVsZXRlJywgJ3RhYmxlJywgJ2luZXQnLCBORlRdLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluICgqRU5E'
    'UE9JTlRTLCAqTEVHQUNZX0VORFBPSU5UUyk6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9y'
    'aXR5Jywgc3RyKFBSSU9SSVRZKSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVz'
    'cysnLzMyJywgJ2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluIGRhdGEuZ2V0'
    'KCdtZWFzdXJlbWVudF9pcHMnLCBbXSk6CiAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xv'
    'YmFsOgogICAgICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20n'
    'LCBDTElFTlQrJy8zMicsICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2Up'
    'CiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnZmx1c2gnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2Up'
    'CiAgICBjb21tYW5kKFsnaXAnLCAnbmV0bnMnLCAnZGVsJywgTlNdLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcs'
    'ICdsaW5rJywgJ2RlbCcsIEhPU1RdLCBjaGVjaz1GYWxzZSkKICAgIGlmICd1cGxpbmtfZm9yd2FyZCcgaW4gZGF0YToKICAg'
    'ICAgICBwYXRoID0gUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9kYXRhWydpbnRlcmZhY2UnXS8nZm9yd2FyZGlu'
    'ZycKICAgICAgICBpZiBwYXRoLmV4aXN0cygpOgogICAgICAgICAgICBwYXRoLndyaXRlX3RleHQoZGF0YVsndXBsaW5rX2Zv'
    'cndhcmQnXSsnXG4nKQogICAgZWxpZiBkYXRhLmdldCgnZm9yd2FyZCcpID09ICcwJyBhbmQgUGF0aCgnL3Byb2Mvc3lzL25l'
    'dC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpID09ICcxJzoKICAgICAgICBQYXRoKCcvcHJvYy9zeXMv'
    'bmV0L2lwdjQvaXBfZm9yd2FyZCcpLndyaXRlX3RleHQoJzBcbicpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNv'
    'bHYuY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5j'
    'b25mJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhPU0Vycm9yKToKICAg'
    'ICAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TKS5ybWRpcigpCiAgICAoUk9PVC8nbmV0d29yay5qc29uJykudW5saW5rKG1p'
    'c3Npbmdfb2s9VHJ1ZSkKCgoKCmRlZiB0bHNfcmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNsaWVudD1GYWxz'
    'ZSwgdGltZW91dD04LCBpZGVudGl0eT1TRVJWRVIpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0'
    'KGNhZGF0YT1QSU5ORURfQ0EpCiAgICBpZiBjbGllbnQ6CiAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJP'
    'T1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBzb2NrID0gc29ja2V0LmNyZWF0ZV9j'
    'b25uZWN0aW9uKChhZGRyZXNzLCA4NDQzKSwgdGltZW91dD10aW1lb3V0KQogICAgdHJ5OgogICAgICAgIHRscyA9IGNvbnRl'
    'eHQud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPWlkZW50aXR5KQogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246'
    'CiAgICAgICAgc29jay5jbG9zZSgpCiAgICAgICAgcmFpc2UKICAgIGNvbm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQQ29u'
    'bmVjdGlvbihhZGRyZXNzLCA4NDQzLCB0aW1lb3V0PXRpbWVvdXQpCiAgICBjb25uZWN0aW9uLnNvY2sgPSB0bHMKICAgIGVu'
    'Y29kZWQgPSBqc29uLmR1bXBzKGJvZHksIHNlcGFyYXRvcnM9KCcsJywgJzonKSkuZW5jb2RlKCkgaWYgYm9keSBpcyBub3Qg'
    'Tm9uZSBlbHNlIE5vbmUKICAgIHRyeToKICAgICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ1BPU1QnIGlmIGJvZHkgaXMgbm90'
    'IE5vbmUgZWxzZSAnR0VUJywgcGF0aCwgYm9keT1lbmNvZGVkLAogICAgICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJz'
    'PXsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAnQ29ubmVjdGlvbic6ICdjbG9zZSd9KQogICAgICAgIHJl'
    'c3BvbnNlID0gY29ubmVjdGlvbi5nZXRyZXNwb25zZSgpCiAgICAgICAgcmF3ID0gcmVzcG9uc2UucmVhZCgyMDAwMSkKICAg'
    'ICAgICBpZiByZXNwb25zZS5zdGF0dXMgIT0gMjAwIG9yIGxlbihyYXcpID4gMjAwMDA6CiAgICAgICAgICAgIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcigncmVxdWVzdF9yZWplY3RlZCcpCiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMocmF3KQogICAgZmluYWxs'
    'eToKICAgICAgICBjb25uZWN0aW9uLmNsb3NlKCkKCgpkZWYgZW5yb2xsKCk6CiAgICB0b2tlbiA9IChST09ULyd0b2tlbicp'
    'LnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pOgogICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF90b2tlbicpCiAgICB0cnk6CiAgICAgICAgY2FjaGVkID0ganNvbi5s'
    'b2FkcygoUk9PVC8ncHJvZmlsZS5qc29uJykucmVhZF90ZXh0KCkpCiAgICAgICAgaWYgKGNhY2hlZC5nZXQoJ2NhJykgPT0g'
    'UElOTkVEX0NBIGFuZCBjYWNoZWQuZ2V0KCdzZXJ2ZXInKSA9PSBTRVJWRVIgYW5kCiAgICAgICAgICAgIHJlLmZ1bGxtYXRj'
    'aChyJ2RldmljZS1bYS1mMC05XXsyNH0nLCBjYWNoZWQuZ2V0KCdpZGVudGl0eScsICcnKSkgYW5kCiAgICAgICAgICAgIGNh'
    'Y2hlZC5nZXQoJ2VuZHBvaW50JykgaW4gRU5EUE9JTlRTIGFuZCBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3b3JrJykgYW5k'
    'CiAgICAgICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3g1MDknLCAnLWluJywgUk9PVC8nY2xpZW50LnBlbScsICctY2hl'
    'Y2tlbmQnLCBzdHIoNyo4NjQwMCksICctbm9vdXQnXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMCk6CiAgICAgICAg'
    'ICAgIGNvbnRleHQgPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAgY29udGV4'
    'dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAg'
    'ICAgICAgICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBjdXJyZW50ID0gaGFzaGxpYi5zaGEyNTYo'
    'anNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAncHJlZnNyYycp'
    'fSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICBhZGRyZXNzID0gY2FjaGVkWydl'
    'bmRwb2ludCddIGlmIGNhY2hlZC5nZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSA9PSBjdXJyZW50IGVsc2UgU0VSVkVSCiAgICAg'
    'ICAgICAgIHJldHVybiBjYWNoZWRbJ2lkZW50aXR5J10sIGFkZHJlc3MKICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJv'
    'ciwgc3NsLlNTTEVycm9yKToKICAgICAgICBwYXNzCiAgICBzdGFnZSgndG9rZW4nLCAn0J/QvtC70YPRh9Cw0Y4g0YHQtdGA'
    '0YLQuNGE0LjQutCw0YIg0LTQu9GPINGN0YLQvtCz0L4g0YPRgdGC0YDQvtC50YHRgtCy0LAuJywgMjUpCiAgICBpZiBub3Qg'
    'KFJPT1QvJ2NsaWVudC1rZXkucGVtJykuZXhpc3RzKCk6CiAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAnZ2VucGtleScs'
    'ICctYWxnb3JpdGhtJywgJ1JTQScsICctcGtleW9wdCcsICdyc2Ffa2V5Z2VuX2JpdHM6MzA3MicsCiAgICAgICAgICAgICAg'
    'ICAgJy1vdXQnLCBST09ULydjbGllbnQta2V5LnBlbSddLCB0aW1lb3V0PTMwKQogICAgICAgIChST09ULydjbGllbnQta2V5'
    'LnBlbScpLmNobW9kKDBvNjAwKQogICAgaWYgbm90IChST09ULydkZXZpY2UnKS5leGlzdHMoKToKICAgICAgICB3cml0ZShS'
    'T09ULydkZXZpY2UnLCBzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICBjb21tYW5kKFsnb3BlbnNzbCcsICdyZXEnLCAnLW5l'
    'dycsICcta2V5JywgUk9PVC8nY2xpZW50LWtleS5wZW0nLCAnLXN1YmonLCAnL0NOPWV2Z2VuaXVtLWRldmljZScsCiAgICAg'
    'ICAgICAgICAnLW91dCcsIFJPT1QvJ3JlcXVlc3QucGVtJ10pCiAgICBwYXlsb2FkID0geyd0b2tlbic6IHRva2VuLCAnZGV2'
    'aWNlJzogKFJPT1QvJ2RldmljZScpLnJlYWRfdGV4dCgpLnN0cmlwKCksICdjc3InOiAoUk9PVC8ncmVxdWVzdC5wZW0nKS5y'
    'ZWFkX3RleHQoKX0KICAgIGxhc3QgPSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCk6CiAgICAgICAgdHJ5Ogog'
    'ICAgICAgICAgICB3aXRoIG5hbWVzcGFjZSgpOgogICAgICAgICAgICAgICAgcmVwbHkgPSB0bHNfcmVxdWVzdChhZGRyZXNz'
    'LCAnL2Vucm9sbCcsIHBheWxvYWQsIHRpbWVvdXQ9NikKICAgICAgICAgICAgcHJvZmlsZSA9IHJlcGx5LmdldCgncHJvZmls'
    'ZScsIHt9KQogICAgICAgICAgICBpZiByZXBseS5nZXQoJ29rJykgaXMgbm90IFRydWUgb3IgcHJvZmlsZS5nZXQoJ2NhJykg'
    'IT0gUElOTkVEX0NBIG9yIHByb2ZpbGUuZ2V0KCdzZXJ2ZXInKSAhPSBTRVJWRVI6CiAgICAgICAgICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ2ludmFsaWRfcHJvZmlsZScpCiAgICAgICAgICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidkZXZpY2Ut'
    'W2EtZjAtOV17MjR9JywgcHJvZmlsZS5nZXQoJ2lkZW50aXR5JywgJycpKToKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRp'
    'bWVFcnJvcignaW52YWxpZF9pZGVudGl0eScpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NsaWVudC5wZW0nLCBwcm9maWxl'
    'WydjZXJ0aWZpY2F0ZSddKQogICAgICAgICAgICB3cml0ZShST09ULydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAgICAg'
    'IHdyaXRlKFJPT1QvJ3g1MDknLydjbGllbnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3Jp'
    'dGUoUk9PVC8neDUwOWNhJy8nY2EucGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULydwcml2YXRlJy8n'
    'Y2xpZW50LWtleS5wZW0nLCAoUk9PVC8nY2xpZW50LWtleS5wZW0nKS5yZWFkX3RleHQoKSkKICAgICAgICAgICAgY29tbWFu'
    'ZChbJ29wZW5zc2wnLCAndmVyaWZ5JywgJy1wdXJwb3NlJywgJ3NzbGNsaWVudCcsICctQ0FmaWxlJywgUk9PVC8nY2EucGVt'
    'JywgUk9PVC8nY2xpZW50LnBlbSddKQogICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExT'
    'X0NMSUVOVCkKICAgICAgICAgICAgY3R4LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9P'
    'VC8nY2xpZW50LWtleS5wZW0nKSkKICAgICAgICAgICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAgICAgICAgIGZp'
    'bmdlcnByaW50ID0gaGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgn'
    'ZGV2JywgJ2dhdGV3YXknLCAncHJlZnNyYycpfSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAg'
    'ICAgICAgICB3cml0ZShST09ULydwcm9maWxlLmpzb24nLCBqc29uLmR1bXBzKHsqKnByb2ZpbGUsICdlbmRwb2ludCc6IGFk'
    'ZHJlc3MsICdwaHlzaWNhbF9uZXR3b3JrJzogZmluZ2VycHJpbnR9KSkKICAgICAgICAgICAgcmV0dXJuIHByb2ZpbGVbJ2lk'
    'ZW50aXR5J10sIGFkZHJlc3MKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvciwgUnVudGltZUVycm9yKSBh'
    'cyBleGM6CiAgICAgICAgICAgIGxhc3QgPSBleGMKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZW5yb2xsbWVudF91bmF2YWls'
    'YWJsZScpIGZyb20gbGFzdAoKCmRlZiBkYWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcyk6CiAgICBSVU5USU1FLm1r'
    'ZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGluY2x1ZGVzID0gJ1xuJy5qb2luKCdp'
    'bmNsdWRlICcrc3RyKHApIGZvciBwYXR0ZXJuIGluICgnL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicsICcvZXRj'
    'L3N0cm9uZ3N3YW4vc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYnKQogICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHAg'
    'aW4gUGF0aCgnLycpLmdsb2IocGF0dGVybi5sc3RyaXAoJy8nKSkpCiAgICB3cml0ZShST09ULydzdHJvbmdzd2FuLmNvbmYn'
    'LCBmJycnY2hhcm9uIHt7CiBsb2FkX21vZHVsYXIgPSB5ZXMKIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxl'
    'ID0gNTE4MjIKIHJvdXRpbmdfdGFibGVfcHJpbyA9IDEwMAogcGx1Z2lucyB7ewp7aW5jbHVkZXN9CiAgdmljaSB7eyBzb2Nr'
    'ZXQgPSB1bml4Oi8ve1JVTlRJTUV9L2NoYXJvbi52aWNpIH19CiAgcmVzb2x2ZSB7eyBsb2FkID0gbm8gfX0KICBrZXJuZWwt'
    'bGliaXBzZWMge3sgbG9hZCA9IG5vIH19CiB9fQp9fQpjaGFyb24tc3lzdGVtZCB7eyBqb3VybmFsIHt7IGRlZmF1bHQgPSAw'
    'OyBpa2UgPSAxIH19IH19CicnJykKICAgICMgQWJzb2x1dGUgY3JlZGVudGlhbHMgYXJlIGxvY2FsIHRvIHRoaXMgZGV2aWNl'
    'LCBub3Qgc2hhcmVkIGJ5IHRoZSBhY2NvdW50IHRva2VuLgogICAgd3JpdGUoUk9PVC8nY29ubmVjdGlvbi5jb25mJywgZicn'
    'J2Nvbm5lY3Rpb25zIHt7CiB7TEFZT1VULmlrZX0ge3sKICB2ZXJzaW9uID0gMgogIHJlbW90ZV9hZGRycyA9IHthZGRyZXNz'
    'fQogIHJlbW90ZV9wb3J0ID0ge0FDVElWRVsncG9ydCddfQogIGxvY2FsX3BvcnQgPSA0NTAwCiAgdmlwcyA9IDAuMC4wLjAK'
    'ICBwcm9wb3NhbHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9u'
    'ID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMTVzCiAgbG9jYWwge3sgYXV0aCA9IGVhcC10bHM7IGlkID0g'
    'e2lkZW50aXR5fTsgZWFwX2lkID0ge2lkZW50aXR5fTsgY2VydHMgPSB7Uk9PVH0vY2xpZW50LnBlbSB9fQogIHJlbW90ZSB7'
    'eyBhdXRoID0gcHVia2V5OyBpZCA9IHtBQ1RJVkVbJ2lkZW50aXR5J119OyBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbSB9fQog'
    'IGNoaWxkcmVuIHt7CiAgIHtMQVlPVVQuaWtlfS1uZXQge3sKICAgIGxvY2FsX3RzID0gZHluYW1pYwogICAgcmVtb3RlX3Rz'
    'ID0gMC4wLjAuMC8wCiAgICByZXFpZCA9IHtSRVFJRH0KICAgIGVzcF9wcm9wb3NhbHMgPSBjaGFjaGEyMHBvbHkxMzA1CiAg'
    'ICBkcGRfYWN0aW9uID0gY2xlYXIKICAgIHN0YXJ0X2FjdGlvbiA9IG5vbmUKICAgfX0KICB9fQogfX0KfX0Kc2VjcmV0cyB7'
    'eyBwcml2YXRlLWNsaWVudCB7eyBmaWxlID0ge1JPT1R9L2NsaWVudC1rZXkucGVtIH19IH19CicnJykKICAgICMgU3Ryb25n'
    'U3dhbiBjb25maWcgdXNlcyBuZXdsaW5lcywgbm90IHNlbWljb2xvbiBzZXBhcmF0b3JzIChub3JtYWxpemUgY29tcGFjdCBi'
    'bG9ja3MpLgogICAgZm9yIG5hbWUgaW4gKCdzdHJvbmdzd2FuLmNvbmYnLCAnY29ubmVjdGlvbi5jb25mJyk6CiAgICAgICAg'
    'cGF0aCA9IFJPT1QvbmFtZQogICAgICAgIHBhdGgud3JpdGVfdGV4dChwYXRoLnJlYWRfdGV4dCgpLnJlcGxhY2UoJzsgJywg'
    'J1xuJykucmVwbGFjZSgneyAnLCAne1xuJykucmVwbGFjZSgnIH0nLCAnXG59JykpCiAgICBydWxlcyA9IGYnJyd0YWJsZSBp'
    'bmV0IHtOQU1FU1BBQ0VfR1VBUkR9IHt7CiBjaGFpbiBvdXRwdXQge3sKICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlv'
    'cml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBpcCBkYWRkciAxMjcuMC4wLjEgdWRwIGRw'
    'b3J0IDI0NTczIGFjY2VwdAogIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBkYWRkciAxNzIuMjkuMjQ3LjEgbWV0YSBsNHBy'
    'b3RvIHt7IHRjcCwgdWRwIH19IHRoIHNwb3J0IDUzIGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQge0FD'
    'VElWRVsncG9ydCddfSBhY2NlcHQKICBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1Nzgg'
    'fX0gYWNjZXB0CiAgaXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9ydCAyNDU3OSBhY2NlcHQKICBtZXRhIHNrdWlk'
    'IDAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlwc2VjIG91'
    'dCByZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHBy'
    'aW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBk'
    'YXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKCgpkZWYgc3dhbigqYXJncywg'
    'dGltZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRlKFsnc3dhbmN0bCcsICphcmdzLCAnLS11cmknLCAn'
    'dW5peDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1lb3V0PXRpbWVvdXQsIGNoZWNrPWNoZWNrKQoKCmRl'
    'ZiBpbnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBzd2FuKCctLWxpc3Qtc2FzJywgJy0tcmF3JywgdGlt'
    'ZW91dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0LnJldHVybmNvZGUgPT0gMCBhbmQgJ3N0YXRlPUVT'
    'VEFCTElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5TVEFMTEVEJyBpbiByZXN1bHQuc3Rkb3V0CiAgICBl'
    'eGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBo'
    'ZWFsdGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0dXJuIHRsc19yZXF1ZXN0KEhFQUxUSCwgJy9oZWFs'
    'dGgnLCBjbGllbnQ9VHJ1ZSwgaWRlbnRpdHk9QUNUSVZFWydpZGVudGl0eSddLCB0aW1lb3V0PTMpLmdldCgnc2VydmljZScp'
    'IGluICgnZXZnZW5pdW0tdnBuJywgJ2V2Z2VuaXVtLXN0YXJmaXZlJykKCgpkZWYgZG93bmxvYWQoc2l6ZT0xMDQ4NTc2KToK'
    'ICAgICMgQSBib3VuZGVkIGludGVncml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBtZWFzdXJlZCB0aGUgSVNQJ3Mg'
    'bWF4aW11bSByYXRlLgogICAgIyBQcm90b2NvbCB2MSB1c2VzIHRoaXMgZml4ZWQgc2VlZCBvbiBkZXBsb3llZCBjb2xsZWN0'
    'b3JzIGFuZCBlYXJsaWVyIGNsaWVudHMuCiAgICBibG9jayA9IGhhc2hsaWIuc2hha2VfMjU2KGInZXZnZW5pdW0tc3RhcmZp'
    'dmUtaW50ZWdyaXR5LXYxJykuZGlnZXN0KDY1NTM2KQogICAgZXhwZWN0ZWQgPSBoYXNobGliLnNoYTI1NigoYmxvY2sqKHNp'
    'emUvL2xlbihibG9jaykrMSkpWzpzaXplXSkuaGV4ZGlnZXN0KCkKICAgIGNvbnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRf'
    'Y29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5w'
    'ZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICB3aXRoIG5hbWVzcGFjZSgpOgogICAgICAgIHNvY2sgPSBz'
    'b2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKEhFQUxUSCwgODQ0MyksIHRpbWVvdXQ9MTApCiAgICAgICAgdGxzID0gY29udGV4'
    'dC53cmFwX3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9QUNUSVZFWydpZGVudGl0eSddKQogICAgICAgIGNvbm5lY3Rp'
    'b24gPSBodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbihIRUFMVEgsIDg0NDMsIHRpbWVvdXQ9MTApOyBjb25uZWN0aW9uLnNv'
    'Y2sgPSB0bHMKICAgICAgICB0cnk6CiAgICAgICAgICAgIHN0YXJ0ID0gdGltZS5tb25vdG9uaWMoKQogICAgICAgICAgICBj'
    'b25uZWN0aW9uLnJlcXVlc3QoJ0dFVCcsICcvYmxvYj9zaXplPScrc3RyKHNpemUpKQogICAgICAgICAgICByZXNwb25zZSA9'
    'IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgICAgICBpZiByZXNwb25zZS5zdGF0dXMgIT0gMjAwOgogICAgICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0cmFuc2Zlcl9odHRwJykKICAgICAgICAgICAgZGlnZXN0ID0gaGFzaGxp'
    'Yi5zaGEyNTYoKTsgcmVjZWl2ZWQgPSAwCiAgICAgICAgICAgIHdoaWxlIHJlY2VpdmVkIDwgc2l6ZToKICAgICAgICAgICAg'
    'ICAgIGRhdGEgPSByZXNwb25zZS5yZWFkKG1pbig2NTUzNiwgc2l6ZS1yZWNlaXZlZCkpCiAgICAgICAgICAgICAgICBpZiBu'
    'b3QgZGF0YToKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZGlnZXN0LnVwZGF0ZShkYXRhKTsg'
    'cmVjZWl2ZWQgKz0gbGVuKGRhdGEpCiAgICAgICAgICAgIGVsYXBzZWQgPSB0aW1lLm1vbm90b25pYygpLXN0YXJ0CiAgICAg'
    'ICAgZmluYWxseToKICAgICAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCiAgICBpZiByZWNlaXZlZCAhPSBzaXplIG9yIGRp'
    'Z2VzdC5oZXhkaWdlc3QoKSAhPSBleHBlY3RlZDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludGVncml0eV9mYWls'
    'ZWQnKQogICAgcmV0dXJuIHsnYnl0ZXMnOiByZWNlaXZlZCwgJ2Rvd25sb2FkX21icHMnOiByb3VuZChyZWNlaXZlZCo4L2Vs'
    'YXBzZWQvMWU2LCAyKSwKICAgICAgICAgICAgJ2VsYXBzZWRfbXMnOiByb3VuZChlbGFwc2VkKjEwMDApLCAnaW50ZWdyaXR5'
    'JzogVHJ1ZSwgJ2xpbWl0ZWRfc2FtcGxlJzogVHJ1ZX0KCgpkZWYgZGV2aWNlX3N0YXR1cygpOgogICAgdHJ5OgogICAgICAg'
    'IGluZm89anNvbi5sb2FkcygoUk9PVC8nZGV2aWNlLWluZm8uanNvbicpLnJlYWRfdGV4dCgpKQogICAgICAgIHJldHVybiB7'
    'J2RldmljZV9uYW1lJzppbmZvLmdldCgnbmFtZScsJycpLCdkZXZpY2VfbnVtYmVyJzppbmZvLmdldCgnbnVtYmVyJyksCiAg'
    'ICAgICAgICAgICAgICAnZGV2aWNlX25hbWVfcGVuZGluZyc6Ym9vbChpbmZvLmdldCgncGVuZGluZycpIG9yIGluZm8uZ2V0'
    'KCdzeW5jX2Vycm9yJykpfQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnJldHVybiB7J2RldmljZV9uYW1lJzon'
    'JywnZGV2aWNlX251bWJlcic6Tm9uZSwnZGV2aWNlX25hbWVfcGVuZGluZyc6RmFsc2V9CgoKZGVmIHN5bmNfZGV2aWNlX25h'
    'bWUobmFtZT1Ob25lKToKICAgIGltcG9ydCB1bmljb2RlZGF0YQogICAgaWYgbm90IHRva2VuX3N0YXR1cygpWydoYXNfdG9r'
    'ZW4nXTpyYWlzZSBWYWx1ZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQv9C+0LTRgtCy0LXRgNC00LjRgtC1INGC0L7QutC10L0g'
    '0LrQu9C40LXQvdGC0LAuJykKICAgIGlmIG5hbWUgaXMgbm90IE5vbmU6CiAgICAgICAgbmFtZT11bmljb2RlZGF0YS5ub3Jt'
    'YWxpemUoJ05GQycsc3RyKG5hbWUpKS5zdHJpcCgpCiAgICAgICAgaWYgbm90IDE8PWxlbihuYW1lKTw9NjQgb3IgYW55KHVu'
    'aWNvZGVkYXRhLmNhdGVnb3J5KGMpLnN0YXJ0c3dpdGgoJ0MnKSBmb3IgYyBpbiBuYW1lKToKICAgICAgICAgICAgcmFpc2Ug'
    'VmFsdWVFcnJvcign0JjQvNGPINC00L7Qu9C20L3QviDRgdC+0LTQtdGA0LbQsNGC0Ywg0L7RgiAxINC00L4gNjQg0L7QsdGL'
    '0YfQvdGL0YUg0YHQuNC80LLQvtC70L7Qsi4nKQogICAgaWYgbm90IChST09ULydkZXZpY2UnKS5leGlzdHMoKTp3cml0ZShS'
    'T09ULydkZXZpY2UnLHNlY3JldHMudG9rZW5faGV4KDE2KSkKICAgIHRyeTppbmZvPWpzb24ubG9hZHMoKFJPT1QvJ2Rldmlj'
    'ZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTppbmZvPXt9CiAgICBp'
    'ZiBuYW1lIGlzIG5vdCBOb25lOmluZm8udXBkYXRlKG5hbWU9bmFtZSxwZW5kaW5nPVRydWUpCiAgICBwYXlsb2FkPXsndG9r'
    'ZW4nOihST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCksJ2RldmljZSc6KFJPT1QvJ2RldmljZScpLnJlYWRfdGV4'
    'dCgpLnN0cmlwKCl9CiAgICBpZiBpbmZvLmdldCgncGVuZGluZycpOnBheWxvYWRbJ25hbWUnXT1pbmZvWyduYW1lJ10KICAg'
    'IHRyeToKICAgICAgICB3aXRoIG5hbWVzcGFjZSgpIGlmIFBhdGgoJy9ydW4vbmV0bnMvJytOUykuZXhpc3RzKCkgZWxzZSBj'
    'b250ZXh0bGliLm51bGxjb250ZXh0KCk6CiAgICAgICAgICAgIHJlcGx5PXRsc19yZXF1ZXN0KFNFUlZFUiwnL2RldmljZScs'
    'cGF5bG9hZCx0aW1lb3V0PTUpCiAgICAgICAgdmFsdWU9cmVwbHlbJ2RldmljZSddO251bWJlcj1pbnQodmFsdWVbJ251bWJl'
    'ciddKQogICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVlWyduYW1lJ10sc3RyKSBvciBub3QgMTw9bGVuKHZhbHVlWydu'
    'YW1lJ10pPD02NCBvciBudW1iZXI8MTpyYWlzZSBWYWx1ZUVycm9yKCdpbnZhbGlkX2RldmljZV9tZXRhZGF0YScpCiAgICAg'
    'ICAgaW5mbz17J25hbWUnOnZhbHVlWyduYW1lJ10sJ251bWJlcic6bnVtYmVyLCdwZW5kaW5nJzpGYWxzZSwnc3luY19lcnJv'
    'cic6RmFsc2V9CiAgICBleGNlcHQgKE9TRXJyb3IsUnVudGltZUVycm9yLFZhbHVlRXJyb3IsS2V5RXJyb3IsaHR0cC5jbGll'
    'bnQuSFRUUEV4Y2VwdGlvbik6CiAgICAgICAgaW5mb1snc3luY19lcnJvciddPVRydWUKICAgIHdyaXRlKFJPT1QvJ2Rldmlj'
    'ZS1pbmZvLmpzb24nLGpzb24uZHVtcHMoaW5mbyxlbnN1cmVfYXNjaWk9RmFsc2UpKQogICAgcmV0dXJuIGRldmljZV9zdGF0'
    'dXMoKQoKCmRlZiB0b2tlbl9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICB0b2tlbiA9IChST09ULyd0b2tlbicpLnJlYWRf'
    'dGV4dCgpLnN0cmlwKCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICB0b2tlbiA9ICcnCiAgICB2YWxp'
    'ZCA9IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbikgaXMgbm90IE5vbmUKICAgIHJldHVybiB7J2hhc190b2tl'
    'bic6IHZhbGlkLAogICAgICAgICAgICAndG9rZW5faGludCc6ICdFVk4xLeKAouKAouKAouKAoiDCtyBJRCAnICsgaGFzaGxp'
    'Yi5zaGEyNTYodG9rZW4uZW5jb2RlKCkpLmhleGRpZ2VzdCgpWzo4XSBpZiB2YWxpZCBlbHNlICcnfQoKCmRlZiBzYXZlX3Rv'
    'a2VuKHRva2VuKToKICAgIHRva2VuID0gdG9rZW4uc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRU'
    'RVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0J3Rg9C20LXQvSDRgtC+0LrQtdC9INC60LvQuNC10L3R'
    'gtCwINGE0L7RgNC80LDRgtCwIEVWTjEt4oCmJykKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBl'
    'eGlzdF9vaz1UcnVlKQogICAgb2xkID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAoKSBpZiAoUk9PVC8ndG9r'
    'ZW4nKS5leGlzdHMoKSBlbHNlICcnCiAgICBpZiBvbGQgPT0gdG9rZW46CiAgICAgICAgc3luY19kZXZpY2VfbmFtZSgpO3Jl'
    'dHVybgogICAgaWYgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcsIFVOSVRdLCBjaGVjaz1G'
    'YWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L7RgtC6'
    '0LvRjtGH0LjRgtC1IFZQTi3RgtGD0L3QvdC10LvRjCDQv9C10YDQtdC0INGB0LzQtdC90L7QuSDRgtC+0LrQtdC90LAuJykK'
    'ICAgICMgQSBkaWZmZXJlbnQgYWNjb3VudCBuZWVkcyBpdHMgb3duIGRldmljZSBjcmVkZW50aWFscy4gTmV2ZXIgcmV1c2Ug'
    'aXRzIGNlcnRpZmljYXRlLgogICAgZm9yIG5hbWUgaW4gKCdkZXZpY2UtaW5mby5qc29uJywgJ2RldmljZScsICdjbGllbnQt'
    'a2V5LnBlbScsICdjbGllbnQucGVtJywgJ3Byb2ZpbGUuanNvbicsICdyZXF1ZXN0LnBlbScsCiAgICAgICAgICAgICAgICAg'
    'J3ByaXZhdGUvY2xpZW50LWtleS5wZW0nLCAneDUwOS9jbGllbnQucGVtJywgJ3JhbmtpbmcuanNvbicsICdyZWNhbGlicmF0'
    'ZScsICdldmVudHMuanNvbicsICdzdXBwb3J0LXByZXZpZXcuanNvbicpOgogICAgICAgIChST09UL25hbWUpLnVubGluayht'
    'aXNzaW5nX29rPVRydWUpCiAgICB3cml0ZShST09ULyd0b2tlbicsIHRva2VuKQogICAgc3luY19kZXZpY2VfbmFtZSgpCiAg'
    'ICBzdGFnZSgnb2ZmJywgJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvS4g0J3QsNC20LzQuNGC0LUgwqvQn9C+0LTQutC7'
    '0Y7Rh9C40YLRjMK7LicsIDAsIGFjdGl2ZT1GYWxzZSwgbWV0cmljcz17fSkKCgpkZWYgY29ubmVjdCh0b2tlbj0nJywgcmVw'
    'YWlyPUZhbHNlLCByZXN0YXJ0PUZhbHNlKToKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCwgcGFyZW50cz1UcnVlLCBleGlz'
    'dF9vaz1UcnVlKQogICAgaWYgdG9rZW46CiAgICAgICAgc2F2ZV90b2tlbih0b2tlbikKICAgIGlmIG5vdCB0b2tlbl9zdGF0'
    'dXMoKVsnaGFzX3Rva2VuJ106CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0JLQstC10LTQuNGC0LUg0Lgg0L/QvtC00YLQ'
    'stC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC60LvQuNC10L3RgtCwLicpCiAgICBlbnN1cmVfZGVwZW5kZW5jaWVzKCkKICAg'
    'IGlmIHJlcGFpcjoKICAgICAgICB3cml0ZShST09ULydyZWNhbGlicmF0ZScsICcxJykKICAgIHdyaXRlKFVOSVRfRElSIC8g'
    'VU5JVCwgdW5pdF90ZXh0KExBWU9VVCwgJ3VuaXQnKSwgbW9kZT0wbzY0NCkKICAgIHdyaXRlKFVOSVRfRElSIC8gUkVDT1ZF'
    'UllfVU5JVCwgdW5pdF90ZXh0KExBWU9VVCwgJ3JlY292ZXJ5JyksIG1vZGU9MG82NDQpCiAgICBjb21tYW5kKFsnc3lzdGVt'
    'Y3RsJywgJ2RhZW1vbi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZW5hYmxlJywgUkVDT1ZFUllfVU5J'
    'VF0pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywncmVzZXQtZmFpbGVkJyxVTklUXSxjaGVjaz1GYWxzZSkKICAgIHN0YWdl'
    'KCdzdGFydGluZycgLCAn0JPQvtGC0L7QstC70Y4g0L/QvtC00LrQu9GO0YfQtdC90LjQtSDQsiDQrdGB0YLQvtC90LjRji4n'
    'LCAyLCBhY3RpdmU9RmFsc2UsIHJldHJ5PTAsIGVycm9yX2NvZGU9JycpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ3Jl'
    'c3RhcnQnIGlmIHJlcGFpciBvciByZXN0YXJ0IGVsc2UgJ3N0YXJ0JywgVU5JVF0pCiAgICBwcmludCgnVlBOINC30LDQv9GD'
    '0YHQutCw0LXRgtGB0Y8uJyxmbHVzaD1UcnVlKQoKCmRlZiBkaXNjb25uZWN0KCk6CiAgICBjb21tYW5kKFsnc3lzdGVtY3Rs'
    'JywgJ3N0b3AnLCBVTklUXSwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MjUpCiAgICBjbGVhbnVwKCkKICAgIGNsZWFudXBfZnVs'
    'bChyZWxlYXNlPVRydWUpCiAgICBzdGFnZSgnb2ZmJywgJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsIDAsIGFjdGl2ZT1GYWxz'
    'ZSkKICAgIHByaW50KCdWUE4g0LLRi9C60LvRjtGH0LXQvS4nKQoKCmRlZiBzdGFydF9kYWVtb24oZW52KToKICAgIChSVU5U'
    'SU1FLydjaGFyb24udmljaScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICBsb2cgPSAoUk9PVC8nY2hhcm9uLmxvZycp'
    'Lm9wZW4oJ3cnKQogICAgZGFlbW9uID0gc3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywgJ25ldG5zJywgJ2V4ZWMnLCBOUywgY2hh'
    'cm9uX2JpbmFyeSgpXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW52PWVudiwgc3RkaW49c3VicHJvY2Vzcy5E'
    'RVZOVUxMLCBzdGRvdXQ9bG9nLCBzdGRlcnI9bG9nKQogICAgbG9nLmNsb3NlKCkKICAgIHRyeToKICAgICAgICBmb3IgXyBp'
    'biByYW5nZSg2MCk6CiAgICAgICAgICAgIGlmIFNUT1Agb3IgZGFlbW9uLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAg'
    'ICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZGFlbW9uX3N0b3BwZWQnKQogICAgICAgICAgICBpZiAoUlVOVElNRS8nY2hh'
    'cm9uLnZpY2knKS5leGlzdHMoKSBhbmQgc3dhbignLS1zdGF0cycsIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTEpLnJldHVybmNv'
    'ZGUgPT0gMDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgc3dhbign'
    'LS1sb2FkLWNyZWRzJywgJy0tbm9wcm9tcHQnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAgICBz'
    'd2FuKCctLWxvYWQtY29ubnMnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAgICByZXR1cm4gZGFl'
    'bW9uCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBzdG9wX3Byb2Nlc3MoZGFlbW9uKQogICAgICAgIHJhaXNl'
    'CgoKZGVmIHN0b3BfcHJvY2Vzcyhwcm9jZXNzKToKICAgIGlmIHByb2Nlc3MgaXMgbm90IE5vbmUgYW5kIHByb2Nlc3MucG9s'
    'bCgpIGlzIE5vbmU6CiAgICAgICAgcHJvY2Vzcy50ZXJtaW5hdGUoKQogICAgICAgIHRyeTpwcm9jZXNzLndhaXQodGltZW91'
    'dD01KQogICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOnByb2Nlc3Mua2lsbCgpO3Byb2Nlc3Mud2Fp'
    'dCh0aW1lb3V0PTMpCgoKZGVmIHN0b3BfY2FuZGlkYXRlKGRhZW1vbj1Ob25lKToKICAgIGdsb2JhbCBUTFNfUFJPQ0VTUwog'
    'ICAgc3RvcF9wcm9jZXNzKGRhZW1vbikKICAgIHN0b3BfcHJvY2VzcyhUTFNfUFJPQ0VTUyk7VExTX1BST0NFU1M9Tm9uZQog'
    'ICAgY2xlYW51cCgpCgoKZGVmIHByZXBhcmVfZGF0YV9wbGFuZShhZGRyZXNzKToKICAgIGlmIG5vdCBmdWxsX3N0YXRlKCku'
    'ZXhpc3RzKCk6CiAgICAgICAgaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1QpLmV4aXN0cygpOgogICAgICAg'
    'ICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfaW50ZXJmYWNlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChb'
    'J2lwJywncm91dGUnLCdzaG93JywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAg'
    'ICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChb'
    'J2lwJywncm91dGUnLCdzaG93JywndGFibGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAg'
    'ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignYWRtaW5fdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBhbnkoci5n'
    'ZXQoJ3ByaW9yaXR5JykgaW4gKDc5LDgwKSBmb3IgciBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdy'
    'dWxlJ10pLnN0ZG91dCkpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfcnVsZV9jb2xsaXNpb24nKQog'
    'ICAgICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKHsnYWN0aXZlJzpGYWxzZSwnbWVhc3VyZW1lbnRfb25seSc6'
    'VHJ1ZX0pKQogICAgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcykKICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQoKCmRlZiBzdGFy'
    'dF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KToKICAgIGdsb2JhbCBBQ1RJVkUsVExTX1BST0NFU1MKICAgIEFDVElW'
    'RT1jYW5kaWRhdGUKICAgIHdyaXRlKFJPT1QvJ2FjdGl2ZS1wYXRoLmpzb24nLGpzb24uZHVtcHMoeydpZCc6Y2FuZGlkYXRl'
    'WydpZCddfSkpCiAgICBzZXR1cF9uZXR3b3JrKCkKICAgIGRhZW1vbl9jb25maWdzKGlkZW50aXR5LGNhbmRpZGF0ZVsnYWRk'
    'cmVzcyddKQogICAgaWYgY2FuZGlkYXRlWyd0bHMnXSBvciBjYW5kaWRhdGUuZ2V0KCdldmd0Jyk6CiAgICAgICAgaWYgY2Fu'
    'ZGlkYXRlLmdldCgnZXZndCcpOgogICAgICAgICAgICBiaW5hcnk9ZW5zdXJlX2V2Z3RfYmluYXJ5KCkKICAgICAgICAgICAg'
    'Y2Fycmllcj1bc3RyKGJpbmFyeSksJy1tb2RlJywnY2xpZW50JywnLXNlcnZlcicsY2FuZGlkYXRlLmdldCgndHJhbnNwb3J0'
    'X2FkZHJlc3MnLGNhbmRpZGF0ZVsnYWRkcmVzcyddKSsnOicrc3RyKGNhbmRpZGF0ZS5nZXQoJ3RyYW5zcG9ydF9wb3J0Jywy'
    'NDU3OCkpLCctc2VydmVyLW5hbWUnLGNhbmRpZGF0ZVsnaWRlbnRpdHknXSwKICAgICAgICAgICAgICAgICAgICAgJy11ZHAt'
    'bGlzdGVuJywnMTI3LjAuMC4xOjI0NTczJywnLXVkcC1wZWVyJyxDTElFTlQrJzo0NTAwJywKICAgICAgICAgICAgICAgICAg'
    'ICAgJy1jYScsc3RyKFJPT1QvJ2NhLnBlbScpLCctY2VydCcsc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwnLWtleScsc3RyKFJP'
    'T1QvJ2NsaWVudC1rZXkucGVtJyldCiAgICAgICAgZWxzZTpjYXJyaWVyPVsnL3Vzci9sb2NhbC9zYmluL3ZwbmN0bCcsJ2lu'
    'dGVybmFsLXRscy1jbGllbnQnXQogICAgICAgIFRMU19QUk9DRVNTPXN1YnByb2Nlc3MuUG9wZW4oWydpcCcsJ25ldG5zJywn'
    'ZXhlYycsTlMsKmNhcnJpZXJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkaW49c3VicHJvY2Vz'
    'cy5ERVZOVUxMLHN0ZG91dD1zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICBzdGRlcnI9Tm9uZSBpZiBjYW5kaWRhdGUuZ2V0KCdldmd0JykgZWxzZSBzdWJwcm9jZXNzLkRFVk5VTEwpCiAgICAgICAg'
    'Zm9yIF8gaW4gcmFuZ2UoNTApOgogICAgICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVkJykK'
    'ICAgICAgICAgICAgaWYgVExTX1BST0NFU1MucG9sbCgpIGlzIG5vdCBOb25lOnJhaXNlIFJ1bnRpbWVFcnJvcigndGxzX2Nh'
    'cnJpZXJfc3RvcHBlZCcpCiAgICAgICAgICAgIGlmICcxMjcuMC4wLjE6MjQ1NzMnIGluIGluc2lkZShbJ3NzJywnLWFudSdd'
    'LGNoZWNrPUZhbHNlKS5zdGRvdXQ6YnJlYWsKICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICBlbHNlOnJhaXNl'
    'IFJ1bnRpbWVFcnJvcigndGxzX2NhcnJpZXJfbm90X3JlYWR5JykKICAgICAgICBpbnNpZGUoWyduZnQnLCctZicsJy0nXSxk'
    'YXRhPSd0YWJsZSBpcCBldm5fdGxzX2NhcnJpZXIge1xuIGNoYWluIG91dHB1dCB7XG4gdHlwZSBuYXQgaG9vayBvdXRwdXQg'
    'cHJpb3JpdHkgZHN0bmF0OyBwb2xpY3kgYWNjZXB0O1xuIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBy'
    'ZWRpcmVjdCB0byA6MjQ1NzNcbiB9XG59XG4nKQogICAgZW52PXsqKm9zLmVudmlyb24sJ1NUUk9OR1NXQU5fQ09ORic6c3Ry'
    'KFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicpfTtlbnYucG9wKCdOT1RJRllfU09DS0VUJyxOb25lKQogICAgZGFlbW9uPXN0YXJ0'
    'X2RhZW1vbihlbnYpCiAgICB0cnk6CiAgICAgICAgc3dhbignLS1pbml0aWF0ZScsJy0tY2hpbGQnLExBWU9VVC5pa2UrJy1u'
    'ZXQnLHRpbWVvdXQ9MzUpCiAgICAgICAgaWYgU1RPUDpyYWlzZSBSdW50aW1lRXJyb3IoJ2NhbmNlbGxlZCcpCiAgICAgICAg'
    'aWYgbm90IGluc3RhbGxlZCgpOnJhaXNlIFJ1bnRpbWVFcnJvcignaGFuZHNoYWtlX2ZhaWxlZCcpCiAgICAgICAgcHJlcGFy'
    'ZV9kYXRhX3BsYW5lKGNhbmRpZGF0ZVsnYWRkcmVzcyddKQogICAgICAgIGlmIG5vdCBlZ3Jlc3NfaGVhbHRoKCk6cmFpc2Ug'
    'UnVudGltZUVycm9yKCdlc3RvbmlhX2VncmVzc19mYWlsZWQnKQogICAgICAgIHJldHVybiBkYWVtb24KICAgIGV4Y2VwdCBC'
    'YXNlRXhjZXB0aW9uOgogICAgICAgIHN0b3BfcHJvY2VzcyhkYWVtb24pO3JhaXNlCgoKZGVmIHNwZWVkX3NhbXBsZShzaXpl'
    'PTIwOTcxNTIpOgogICAgIiIiQm91bmRlZCBzeW50aGV0aWMgYmlkaXJlY3Rpb25hbCBwcm9iZTsgbmV2ZXIgcmVhZHMgdXNl'
    'ciBmaWxlcy4iIiIKICAgIHBheWxvYWQ9Uk9PVC8nc3BlZWQtcGF5bG9hZC5iaW4nCiAgICBpZiBub3QgcGF5bG9hZC5leGlz'
    'dHMoKSBvciBwYXlsb2FkLnN0YXQoKS5zdF9zaXplIT1zaXplOgogICAgICAgIHdpdGggcGF5bG9hZC5vcGVuKCd3YicpIGFz'
    'IGY6CiAgICAgICAgICAgIGZvciBfIGluIHJhbmdlKHNpemUvLzY1NTM2KTpmLndyaXRlKHNlY3JldHMudG9rZW5fYnl0ZXMo'
    'NjU1MzYpKQogICAgICAgIHBheWxvYWQuY2htb2QoMG82MDApCiAgICBiYXNlPVsnY3VybCcsJy00JywnLS1ub3Byb3h5Jywn'
    'KicsJy0tZmFpbCcsJy0tc2lsZW50JywnLS1zaG93LWVycm9yJywnLS1jb25uZWN0LXRpbWVvdXQnLCczJywnLS1tYXgtdGlt'
    'ZScsJzEyJywKICAgICAgICAgICctLW91dHB1dCcsJy9kZXYvbnVsbCcsJy0td3JpdGUtb3V0JywnJXtodHRwX2NvZGV9ICV7'
    'c2l6ZV9kb3dubG9hZH0gJXtzaXplX3VwbG9hZH0gJXt0aW1lX3RvdGFsfSAle3RpbWVfY29ubmVjdH0nXQogICAgcmVzdWx0'
    'cz1bXQogICAgZm9yIGRpcmVjdGlvbiBpbiAoJ2Rvd24nLCd1cCcpOgogICAgICAgIGlmIFNUT1A6cmFpc2UgUnVudGltZUVy'
    'cm9yKCdjYW5jZWxsZWQnKQogICAgICAgIGV4dHJhPVsnaHR0cHM6Ly9zcGVlZC5jbG91ZGZsYXJlLmNvbS9fX2Rvd24/Ynl0'
    'ZXM9JytzdHIoc2l6ZSldIGlmIGRpcmVjdGlvbj09J2Rvd24nIGVsc2UgWyctLWRhdGEtYmluYXJ5JywnQCcrc3RyKHBheWxv'
    'YWQpLCdodHRwczovL3NwZWVkLmNsb3VkZmxhcmUuY29tL19fdXAnXQogICAgICAgIHI9aW5zaWRlKGJhc2UrZXh0cmEsdGlt'
    'ZW91dD0xNCxjaGVjaz1GYWxzZSkKICAgICAgICB0cnk6CiAgICAgICAgICAgIGNvZGUsZG93bix1cCxlbGFwc2VkLGxhdGVu'
    'Y3k9ci5zdGRvdXQuc3BsaXQoKQogICAgICAgICAgICBjb3VudD1mbG9hdChkb3duIGlmIGRpcmVjdGlvbj09J2Rvd24nIGVs'
    'c2UgdXApCiAgICAgICAgICAgIGlmIHIucmV0dXJuY29kZSBvciBjb2RlIT0nMjAwJyBvciBjb3VudDxzaXplOnJhaXNlIFZh'
    'bHVlRXJyb3IoKQogICAgICAgICAgICByZXN1bHRzLmFwcGVuZCgoY291bnQqOC9tYXgoLjAwMSxmbG9hdChlbGFwc2VkKSkv'
    'MWU2LGZsb2F0KGxhdGVuY3kpKjEwMDApKQogICAgICAgIGV4Y2VwdCAoVmFsdWVFcnJvcixUeXBlRXJyb3IpOnJldHVybiB7'
    'J2F2YWlsYWJsZSc6RmFsc2V9CiAgICByZXR1cm4geydhdmFpbGFibGUnOlRydWUsJ2Rvd25sb2FkX21icHMnOnJvdW5kKHJl'
    'c3VsdHNbMF1bMF0sMiksJ3VwbG9hZF9tYnBzJzpyb3VuZChyZXN1bHRzWzFdWzBdLDIpLAogICAgICAgICAgICAnbGF0ZW5j'
    'eV9tcyc6cm91bmQobWF4KHhbMV0gZm9yIHggaW4gcmVzdWx0cyksMSksJ3NhbXBsZV9ieXRlcyc6c2l6ZX0KCgpkZWYgdHJh'
    'ZmZpY190b3RhbCgpOgogICAgdHJ5OgogICAgICAgIHN0YXRzPVBhdGgoJy9zeXMvY2xhc3MvbmV0JykvRlVMTF9IT1NULydz'
    'dGF0aXN0aWNzJwogICAgICAgIHJldHVybiBzdW0oaW50KChzdGF0cy9uYW1lKS5yZWFkX3RleHQoKSkgZm9yIG5hbWUgaW4g'
    'KCdyeF9ieXRlcycsJ3R4X2J5dGVzJykpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6cmV0dXJuIDAKCgpkZWYg'
    'c3BlZWRfZGVncmFkZWQoc2FtcGxlLGJhc2VsaW5lKToKICAgICMgUmVxdWlyZSB1c2FibGUgc2FtcGxlcyBhbmQgYSBtZWFu'
    'aW5nZnVsIGJhc2VsaW5lIGluIHRoZSBhZmZlY3RlZCBkaXJlY3Rpb24uCiAgICByZXR1cm4gYm9vbChzYW1wbGUuZ2V0KCdh'
    'dmFpbGFibGUnKSBhbmQgYW55KAogICAgICAgIGJhc2VsaW5lLmdldChrLDApPj0yIGFuZCBzYW1wbGUuZ2V0KGssMCk8YmFz'
    'ZWxpbmVba10qLjIKICAgICAgICBmb3IgayBpbiAoJ2Rvd25sb2FkX21icHMnLCd1cGxvYWRfbWJwcycpKSkKCgpkZWYgd29y'
    'a2VyKCk6CiAgICBnbG9iYWwgU1RPUAogICAgU1RPUD1GYWxzZQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHVEVSTSxs'
    'YW1iZGEgKl86Z2xvYmFscygpLl9fc2V0aXRlbV9fKCdTVE9QJyxUcnVlKSkKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJ'
    'R0lOVCxsYW1iZGEgKl86Z2xvYmFscygpLl9fc2V0aXRlbV9fKCdTVE9QJyxUcnVlKSkKICAgIGRhZW1vbj1Ob25lCiAgICBy'
    'YW5rPXJhbmtfYXBpLlJhbmtpbmcoUk9PVC8ncmFua2luZy5qc29uJyxbeFsnaWQnXSBmb3IgeCBpbiBDQU5ESURBVEVTXSkK'
    'ICAgIHRyeToKICAgICAgICBjbGVhbnVwKCk7cmVmcmVzaF9yZXRhaW5lZF9ndWFyZCgpCiAgICAgICAgc3RhZ2UoJ3ByZXBh'
    'cmUnLCfQk9C+0YLQvtCy0LvRjiDQt9Cw0YnQuNGJ0ZHQvdC90YvQtSDQvNCw0YDRiNGA0YPRgtGLLicsNSxhY3RpdmU9RmFs'
    'c2UsbWV0cmljcz17fSxlcnJvcl9jb2RlPScnLHNjb3BlPSdmdWxsLWRldmljZScpCiAgICAgICAgc2V0dXBfbmV0d29yaygp'
    'CiAgICAgICAgaWRlbnRpdHksXz1lbnJvbGwoKQogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKQogICAgICAgIGNsZWFudXAo'
    'KQogICAgICAgIGxvYWRlZD1yYW5rLmxvYWQoKQogICAgICAgIHNlbGVjdGVkPXNlbGVjdGVkX3JvdXRlKCkKICAgICAgICBy'
    'ZWJ1aWxkPShST09ULydyZWNhbGlicmF0ZScpLmV4aXN0cygpIG9yIChzZWxlY3RlZD09J2F1dG8nIGFuZCBub3QgbG9hZGVk'
    'KQogICAgICAgIGlmIG5vdCBsb2FkZWQ6cmFuay5ib290c3RyYXAoKQogICAgICAgIGlmIHJlYnVpbGQ6CiAgICAgICAgICAg'
    'IG1lYXN1cmVtZW50cz17fQogICAgICAgICAgICBmb3IgaSxjYW5kaWRhdGUgaW4gZW51bWVyYXRlKENBTkRJREFURVMpOgog'
    'ICAgICAgICAgICAgICAgaWYgU1RPUDpyZXR1cm4KICAgICAgICAgICAgICAgIHN0YWdlKCdyYW5raW5nJywn0J/RgNC+0LLQ'
    'tdGA0Y/RjiDQvNCw0YDRiNGA0YPRgjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sMTAraW50KGkqNjAvbGVuKENBTkRJREFURVMp'
    'KSxhY3RpdmU9RmFsc2UscGF0aD1jYW5kaWRhdGVbJ2lkJ10pCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAg'
    'ICAgICAgZGFlbW9uPXN0YXJ0X2NhbmRpZGF0ZShjYW5kaWRhdGUsaWRlbnRpdHkpCiAgICAgICAgICAgICAgICAgICAgdHJ5'
    'OgogICAgICAgICAgICAgICAgICAgICAgICBpbnRlZ3JpdHk9ZG93bmxvYWQoMTA0ODU3NilbJ2ludGVncml0eSddCiAgICAg'
    'ICAgICAgICAgICAgICAgZXhjZXB0IFJ1bnRpbWVFcnJvciBhcyBlcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgaWYg'
    'c3RyKGVycm9yKT09J2ludGVncml0eV9mYWlsZWQnOnJhaXNlCiAgICAgICAgICAgICAgICAgICAgICAgIGludGVncml0eT1O'
    'b25lCiAgICAgICAgICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhw'
    'aXJlZCk6CiAgICAgICAgICAgICAgICAgICAgICAgIGludGVncml0eT1Ob25lCiAgICAgICAgICAgICAgICAgICAgbWVhc3Vy'
    'ZW1lbnRzW2NhbmRpZGF0ZVsnaWQnXV09eydvayc6VHJ1ZSwqKnNwZWVkX3NhbXBsZSgyMDk3MTUyKSwnaW50ZWdyaXR5Jzpp'
    'bnRlZ3JpdHl9CiAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJv'
    'Y2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgICAgICAgICAgICAgaWYgU1RPUDpyZXR1cm4KICAgICAgICAgICAgICAg'
    'ICAgICBtZWFzdXJlbWVudHNbY2FuZGlkYXRlWydpZCddXT17J29rJzpGYWxzZX0KICAgICAgICAgICAgICAgIGZpbmFsbHk6'
    'CiAgICAgICAgICAgICAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKTtkYWVtb249Tm9uZQogICAgICAgICAgICByYW5r'
    'LmJ1aWxkKG1lYXN1cmVtZW50cykKICAgICAgICAgICAgKFJPT1QvJ3JlY2FsaWJyYXRlJykudW5saW5rKG1pc3Npbmdfb2s9'
    'VHJ1ZSkKICAgICAgICBjYW5kaWRhdGVzPXt4WydpZCddOnggZm9yIHggaW4gQ0FORElEQVRFU30KICAgICAgICBjdXJyZW50'
    'PXNlbGVjdGVkIGlmIHNlbGVjdGVkIT0nYXV0bycgZWxzZSBuZXh0KGl0ZXIocmFuay5jYW5kaWRhdGVzKCkpLE5vbmUpCiAg'
    'ICAgICAgd2hpbGUgY3VycmVudCBhbmQgbm90IFNUT1A6CiAgICAgICAgICAgIGNhbmRpZGF0ZT1jYW5kaWRhdGVzW2N1cnJl'
    'bnRdCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHN0YWdlKCdoYW5kc2hha2UnLCfQn9C+0LTQutC70Y7Rh9Cw'
    '0Y46ICcrY2FuZGlkYXRlWydsYWJlbCddLDc1LGFjdGl2ZT1GYWxzZSxwYXRoPWN1cnJlbnQpCiAgICAgICAgICAgICAgICBk'
    'YWVtb249c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVudGl0eSkKICAgICAgICAgICAgICAgIHN0YWdlKCdyb3V0aW5n'
    'Jywn0J/QvtC00LrQu9GO0YfQsNGOINGC0YDQsNGE0LjQuiDQuiDQv9GA0L7QstC10YDQtdC90L3QvtC80YMg0LzQsNGA0YjR'
    'gNGD0YLRgy4nLDkyKQogICAgICAgICAgICAgICAgYWN0aXZhdGVfZnVsbChjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgICAg'
    'ICAgICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCfQn9C+0LTQutC70Y7Rh9C10L3QvjogJytjYW5kaWRhdGVbJ2xhYmVsJ10r'
    'Jy4nLDEwMCxhY3RpdmU9VHJ1ZSxwYXRoPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgICBtZXRyaWNzPXJhbmsuZGF0'
    'YVsnZW50cmllcyddW2N1cnJlbnRdLHNpbmNlPWludCh0aW1lLnRpbWUoKSksZXJyb3JfY29kZT0nJykKICAgICAgICAgICAg'
    'ICAgIGZhaWx1cmVzPTA7c2xvdz0wO2xhc3RfdHJhZmZpYz10cmFmZmljX3RvdGFsKCk7bmV4dF9zcGVlZD10aW1lLm1vbm90'
    'b25pYygpKzYwMCtzZWNyZXRzLnJhbmRiZWxvdyg2MCkKICAgICAgICAgICAgICAgIHdoaWxlIG5vdCBTVE9QOgogICAgICAg'
    'ICAgICAgICAgICAgIGZvciBfIGluIHJhbmdlKDUwKToKICAgICAgICAgICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawog'
    'ICAgICAgICAgICAgICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsK'
    'ICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZTpw'
    'b2xpY3kuZW5zdXJlX3JvdXRlKCkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgRE5TX1BST0NFU1MgaXMgTm9uZSBvciBE'
    'TlNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGFnZSgncmVwYWly'
    'aW5nJywn0J/QtdGA0LXQt9Cw0L/Rg9GB0LrQsNGOINC30LDRidC40YnRkdC90L3Ri9C5IEROUy4nLDkwLGFjdGl2ZT1GYWxz'
    'ZSxlcnJvcl9jb2RlPSdwcml2YXRlX2Ruc19zdG9wcGVkJykKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0YXJ0X25h'
    'bWVzcGFjZV9kbnMoKQogICAgICAgICAgICAgICAgICAgICAgICBoZWFsdGh5PXBhdGhfaGVhbHRoeShkYWVtb24pCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgIGlmIGhlYWx0aHkgYW5kIG5vdCByZWNvdmVyX3N5c3RlbV9kbnMoKTpyYWlzZSBSdW50aW1l'
    'RXJyb3IoJ3N5c3RlbV9kbnNfZmFpbGVkJykKICAgICAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJv'
    'cixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6aGVhbHRoeT1GYWxzZQogICAgICAgICAgICAgICAg'
    'ICAgIGZhaWx1cmVzPTAgaWYgaGVhbHRoeSBlbHNlIGZhaWx1cmVzKzEKICAgICAgICAgICAgICAgICAgICBpZiBmYWlsdXJl'
    'cz49MjpyYWlzZSBSdW50aW1lRXJyb3IoJ3BhdGhfaGVhbHRoX2ZhaWxlZCcpCiAgICAgICAgICAgICAgICAgICAgaWYgbm90'
    'IGhlYWx0aHk6CiAgICAgICAgICAgICAgICAgICAgICAgIHN0YWdlKCdjaGVja2luZycsJ9Ce0YLQstC10YIg0LfQsNC00LXR'
    'gNC20LjQstCw0LXRgtGB0Y8uINCf0YDQvtCy0LXRgNGP0Y4g0YLQtdC60YPRidC40Lkg0LzQsNGA0YjRgNGD0YIuJyw5MCxh'
    'Y3RpdmU9RmFsc2UpCiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAgICAgaWYgdGlt'
    'ZS5tb25vdG9uaWMoKT49bmV4dF9zcGVlZDoKICAgICAgICAgICAgICAgICAgICAgICAgdHJhZmZpYz10cmFmZmljX3RvdGFs'
    'KCkKICAgICAgICAgICAgICAgICAgICAgICAgaWYgbm90IHNsb3cgYW5kIHRyYWZmaWMtbGFzdF90cmFmZmljPDQxOTQzMDQ6'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYztuZXh0X3NwZWVkPXRpbWUubW9ub3Rv'
    'bmljKCkrNjAwK3NlY3JldHMucmFuZGJlbG93KDYwKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgbGFzdF90cmFmZmljPXRyYWZmaWMKICAgICAgICAgICAgICAgICAgICAgICAgc2FtcGxl'
    'PXNwZWVkX3NhbXBsZSgyMDk3MTUyKTtiYXNlbGluZT1yYW5rLmRhdGFbJ2VudHJpZXMnXVtjdXJyZW50XQogICAgICAgICAg'
    'ICAgICAgICAgICAgICBkZWdyYWRlZD1zcGVlZF9kZWdyYWRlZChzYW1wbGUsYmFzZWxpbmUpCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgIHNsb3c9c2xvdysxIGlmIGRlZ3JhZGVkIGVsc2UgMAogICAgICAgICAgICAgICAgICAgICAgICBuZXh0X3NwZWVk'
    'PXRpbWUubW9ub3RvbmljKCkrKDIwIGlmIHNsb3cgZWxzZSA2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApKQogICAgICAgICAg'
    'ICAgICAgICAgICAgICBpZiBzbG93Pj0zOnJhaXNlIFJ1bnRpbWVFcnJvcignY29uZmlybWVkX3NwZWVkX2Ryb3AnKQogICAg'
    'ICAgICAgICAgICAgICAgIHN0YWdlKCdjb25uZWN0ZWQnLCfQn9C+0LTQutC70Y7Rh9C10L3QvjogJytjYW5kaWRhdGVbJ2xh'
    'YmVsJ10rJy4nLDEwMCxhY3RpdmU9VHJ1ZSxwYXRoPWN1cnJlbnQsZXJyb3JfY29kZT0nJykKICAgICAgICAgICAgZXhjZXB0'
    'IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAg'
    'ICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgIHJlYXNvbj1zdHIoZXhjKSBpZiByZS5mdWxsbWF0'
    'Y2goJ1thLXpfXXsxLDY0fScsc3RyKGV4YykpIGVsc2UgJ2Nvbm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICAgICAgIyBB'
    'IG1pc3NpbmcgcGh5c2ljYWwgaW50ZXJmYWNlIGlzIG5vdCBhIHRyYW5zcG9ydCdzIGRlZmVhdC4KICAgICAgICAgICAgICAg'
    'IHRyeToKICAgICAgICAgICAgICAgICAgICByb3V0ZT1waHlzaWNhbF9yb3V0ZSgpO2NhcnJpZXI9UGF0aCgnL3N5cy9jbGFz'
    'cy9uZXQnKS9yb3V0ZVsnZGV2J10vJ2NhcnJpZXInCiAgICAgICAgICAgICAgICAgICAgb2ZmbGluZT1jYXJyaWVyLmV4aXN0'
    'cygpIGFuZCBjYXJyaWVyLnJlYWRfdGV4dCgpLnN0cmlwKCk9PScwJwogICAgICAgICAgICAgICAgZXhjZXB0IChPU0Vycm9y'
    'LFJ1bnRpbWVFcnJvcik6b2ZmbGluZT1UcnVlCiAgICAgICAgICAgICAgICBpZiBub3Qgb2ZmbGluZToKICAgICAgICAgICAg'
    'ICAgICAgICBpZiBzZWxlY3RlZD09J2F1dG8nOgogICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50PXJhbmsubmV4dF9h'
    'ZnRlcihjdXJyZW50KSBvciBuZXh0KGl0ZXIocmFuay5jYW5kaWRhdGVzKCkpLE5vbmUpCiAgICAgICAgICAgICAgICBzdGFn'
    'ZSgncmVwYWlyaW5nJywn0KHQstGP0LfRjCDQv9C+0YLQtdGA0Y/QvdCwLiDQn9C10YDQtdC60LvRjtGH0LDRjiDQt9Cw0YnQ'
    'uNGJ0ZHQvdC90YvQuSDQvNCw0YDRiNGA0YPRgi4nIGlmIG5vdCBvZmZsaW5lIGVsc2UgJ9Ce0LbQuNC00LDRjiDQstC+0YHR'
    'gdGC0LDQvdC+0LLQu9C10L3QuNGPINGE0LjQt9C40YfQtdGB0LrQvtC5INGB0LXRgtC4LicsNjUsCiAgICAgICAgICAgICAg'
    'ICAgICAgICBhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT1yZWFzb24pCiAgICAgICAgICAgICAgICBmb3IgXyBpbiByYW5nZSgz'
    'MCBpZiBub3Qgb2ZmbGluZSBlbHNlIDEwMCk6CiAgICAgICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAg'
    'ICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgICAgICBzdG9wX2NhbmRp'
    'ZGF0ZShkYWVtb24pO2RhZW1vbj1Ob25lCiAgICAgICAgaWYgbm90IFNUT1A6CiAgICAgICAgICAgIHN0YWdlKCdmYWlsZWQn'
    'LCfQndC10YIg0L3QsNGB0YLRgNC+0LXQvdC90YvRhSDQvNCw0YDRiNGA0YPRgtC+0LIuJywwLAogICAgICAgICAgICAgICAg'
    'ICBhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0ncmFua2luZ19leGhhdXN0ZWQnKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVl'
    'RXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBub3QgU1RP'
    'UDoKICAgICAgICAgICAgY29kZT1zdHIoZXhjKSBpZiByZS5mdWxsbWF0Y2goJ1thLXpfXXsxLDY0fScsc3RyKGV4YykpIGVs'
    'c2UgJ2Nvbm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn0J3QtSDRg9C00LDQu9C+0YHRjCDQ'
    'v9C+0LTQs9C+0YLQvtCy0LjRgtGMIFZQTi4g0J3QsNC20LzQuNGC0LUgwqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuy4n'
    'LDAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9Y29kZSkKICAgIGZpbmFsbHk6CiAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFl'
    'bW9uKQogICAgICAgIGlmIFNUT1A6c3RhZ2UoJ29mZicsJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsMCxhY3RpdmU9RmFsc2Up'
    'Cg=='
)
NETWORK_POLICY_PY_B64 = (
    'IiIiTG9jYWwgdHJhZmZpYyBzZWxlY3Rpb24gZm9yIHRoZSB0b2tlbiB0dW5uZWwuIE5vIHJlbW90ZSBwcm94eSBwcm90b2Nv'
    'bC4iIiIKaW1wb3J0IGZjbnRsCmltcG9ydCBpcGFkZHJlc3MKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmZyb20gcGF0aGxpYiBp'
    'bXBvcnQgUGF0aAppbXBvcnQgcmUKaW1wb3J0IHRpbWUKCmFwaSA9IE5vbmUKdHVubmVsID0gTm9uZQpQQVRIID0gUGF0aCgn'
    'L2V0Yy92cG4tbWFuYWdlci9wb2xpY3kuanNvbicpClJVTiA9IFBhdGgoJy9ydW4vdnBuLW1hbmFnZXInKQpTRVJWSUNFID0g'
    'J2V2Z2VuaXVtLXBvbGljeS5zZXJ2aWNlJwpXQVlEUk9JRF9TRVJWSUNFID0gJ2V2Z2VuaXVtLXdheWRyb2lkLW5ldHdvcmsu'
    'c2VydmljZScKVFVOID0gJ2V2bi1wb2xpY3knCkRJUkVDVCA9IDB4NDU1NjRFMzEKVlBOID0gMHg0NTU2NEUzMgpQSFlTSUNB'
    'TF9UQUJMRSA9ICc1MTgzMCcKVlBOX1RBQkxFID0gJzUxODMxJwpETlNfUE9SVCA9IDE4NTUzCkNIRUNLX1BPUlQgPSAxODU1'
    'NAojIFNuYXBzaG90IG9mIFZhbHZlIEdldFNEUkNvbmZpZyBmb3IgYXBwIDE0MjI0NTAsIHN5bmNocm9uaXplZCBkdXJpbmcg'
    'cmVsZWFzZSBidWlsZHMuCkRFQURMT0NLX1NEUiA9IHsncmV2aXNpb24nOiAxNzk0MjY4NDMzLCAnZ3JvdXBzJzogW3snZmly'
    'c3QnOiAyNzAxNSwgJ2xhc3QnOiAyNzA2MCwgJ2FkZHJlc3Nlcyc6IFsnNDUuMTIxLjE4NC41JywgJzQ1LjEyMS4xODQuNics'
    'ICc0NS4xMjEuMTg0LjI0JywgJzQ1LjEyMS4xODQuMjUnLCAnNDUuMTIxLjE4NC4yNicsICc0NS4xMjEuMTg0LjI3JywgJzg5'
    'LjIyMi4xMDguMTYxJywgJzg5LjIyMi4xMDguMTYyJywgJzg5LjIyMi4xMTcuMTk0JywgJzg5LjIyMi4xMTcuMjAwJywgJzEw'
    'My4xMC4xMjQuMTE2JywgJzEwMy4xMC4xMjQuMTE3JywgJzEwMy4xMC4xMjQuMTE4JywgJzEwMy4xMC4xMjQuMTE5JywgJzEw'
    'My4xMC4xMjQuMTIwJywgJzEwMy4xMC4xMjQuMTIxJywgJzEwMy4yOC41NC4xNjMnLCAnMTAzLjI4LjU0LjE2NCcsICcxMDMu'
    'MjguNTQuMTY3JywgJzEwMy4yOC41NC4xNzInLCAnMTAzLjI4LjU0LjE3NCcsICcxMDMuMjguNTQuMTc5JywgJzEwMy4yOC41'
    'NC4xODAnLCAnMTAzLjI4LjU0LjE4MycsICcxMDMuMjguNTQuMTg4JywgJzEwMy4yOC41NC4xODknLCAnMTQ2LjY2LjE1Mi4z'
    'NicsICcxNDYuNjYuMTUyLjM3JywgJzE0Ni42Ni4xNTIuNDEnLCAnMTQ2LjY2LjE1Mi40MicsICcxNDYuNjYuMTU1LjY2Jywg'
    'JzE0Ni42Ni4xNTUuNjcnLCAnMTQ2LjY2LjE1NS42OCcsICcxNDYuNjYuMTU1LjY5JywgJzE0Ni42Ni4xNTUuNzInLCAnMTQ2'
    'LjY2LjE1NS43MycsICcxNTIuMjMzLjUyLjk3JywgJzE1Mi4yMzMuNTIuOTgnLCAnMTU1LjEzMy4yMjQuMjAnLCAnMTU1LjEz'
    'My4yMjQuMjEnLCAnMTU1LjEzMy4yMjcuMzUnLCAnMTU1LjEzMy4yMjcuNDAnLCAnMTU1LjEzMy4yMjcuNDEnLCAnMTU1LjEz'
    'My4yMjcuNTEnLCAnMTU1LjEzMy4yMjcuNTYnLCAnMTU1LjEzMy4yMjcuNTcnLCAnMTU1LjEzMy4yMzguMTc4JywgJzE1NS4x'
    'MzMuMjM4LjE5NCcsICcxNTUuMTMzLjI0NC4zNScsICcxNTUuMTMzLjI0NC4zNicsICcxNTUuMTMzLjI0NC41MScsICcxNTUu'
    'MTMzLjI0NC41MicsICcxNTUuMTMzLjI0Ni4zNCcsICcxNTUuMTMzLjI0Ni4zOScsICcxNTUuMTMzLjI0Ni40MCcsICcxNTUu'
    'MTMzLjI0Ni41MCcsICcxNTUuMTMzLjI0OC4zNicsICcxNTUuMTMzLjI0OC4zNycsICcxNTUuMTMzLjI0OC40MCcsICcxNTUu'
    'MTMzLjI0OC40MScsICcxNTUuMTMzLjI0OS4xNjMnLCAnMTU1LjEzMy4yNDkuMTc5JywgJzE1NS4xMzMuMjUyLjM3JywgJzE1'
    'NS4xMzMuMjUyLjM4JywgJzE1NS4xMzMuMjUyLjUyJywgJzE1NS4xMzMuMjUyLjUzJywgJzE1NS4xMzMuMjUyLjg0JywgJzE1'
    'NS4xMzMuMjUyLjg1JywgJzE1NS4xMzMuMjUyLjg2JywgJzE1NS4xMzMuMjUyLjg3JywgJzE1NS4xMzMuMjUyLjg4JywgJzE1'
    'NS4xMzMuMjUyLjg5JywgJzE1NS4xMzMuMjU1Ljk4JywgJzE1NS4xMzMuMjU1Ljk5JywgJzE1NS4xMzMuMjU1LjE2MicsICcx'
    'NTUuMTMzLjI1NS4xNjMnLCAnMTYyLjI1NC4xOTYuNjYnLCAnMTYyLjI1NC4xOTYuNzAnLCAnMTYyLjI1NC4xOTYuODInLCAn'
    'MTYyLjI1NC4xOTYuODUnLCAnMTYyLjI1NC4xOTguNDEnLCAnMTYyLjI1NC4xOTguNDInLCAnMTYyLjI1NC4xOTguNDMnLCAn'
    'MTYyLjI1NC4xOTguNDcnLCAnMTYyLjI1NC4xOTguNDknLCAnMTYyLjI1NC4xOTguNTAnLCAnMTYyLjI1NC4xOTguNTEnLCAn'
    'MTYyLjI1NC4xOTguMTAxJywgJzE2Mi4yNTQuMTk4LjEwMicsICcxNjIuMjU0LjE5OC4xMDMnLCAnMTg1LjI1LjE4MC4xOCcs'
    'ICcxODUuMjUuMTgwLjE5JywgJzE4NS4yNS4xODIuMTgnLCAnMTg1LjI1LjE4Mi4xOScsICcxODUuMjUuMTgyLjUwJywgJzE4'
    'NS4yNS4xODIuNTEnLCAnMTg1LjI1LjE4My4xNjMnLCAnMTg1LjI1LjE4My4xNzknLCAnMjEyLjEwMi42My4xMzknLCAnMjEy'
    'LjEwMi42My4xNDAnXX0sIHsnZmlyc3QnOiAyNzAxNSwgJ2xhc3QnOiAyNzA3OCwgJ2FkZHJlc3Nlcyc6IFsnMTU1LjEzMy4y'
    'MjUuMTgnLCAnMTU1LjEzMy4yMjUuMTknXX0sIHsnZmlyc3QnOiAyNzAxNSwgJ2xhc3QnOiAyNzE0MCwgJ2FkZHJlc3Nlcyc6'
    'IFsnMTAzLjEwLjEyNS4yMCcsICcxMDMuMTAuMTI1LjIxJywgJzEwMy4xMC4xMjUuNDAnLCAnMTAzLjEwLjEyNS40MScsICcx'
    'NTUuMTMzLjIyNi42OCcsICcxNTUuMTMzLjIyNi43MCcsICcxNTUuMTMzLjIyNi43MicsICcxNTUuMTMzLjIyNi43NycsICcx'
    'NTUuMTMzLjIyNi44NCcsICcxNTUuMTMzLjIyNi44NScsICcxNTUuMTMzLjIyNi44NicsICcxNTUuMTMzLjIyNi44NycsICcx'
    'NTUuMTMzLjIzMC4xMDAnLCAnMTU1LjEzMy4yMzAuMTAxJywgJzE1NS4xMzMuMjMwLjEwMicsICcxNTUuMTMzLjIzMC4xMTcn'
    'LCAnMTU1LjEzMy4yMzAuMTE5JywgJzE1NS4xMzMuMjMwLjEyMScsICcxNjIuMjU0LjE5Mi44OCcsICcxNjIuMjU0LjE5Mi44'
    'OScsICcxNjIuMjU0LjE5Mi4xMDInLCAnMTYyLjI1NC4xOTIuMTAzJywgJzE2Mi4yNTQuMTkzLjcxJywgJzE2Mi4yNTQuMTkz'
    'LjczJywgJzE2Mi4yNTQuMTkzLjk4JywgJzE2Mi4yNTQuMTkzLjk5JywgJzE2Mi4yNTQuMTk0LjM3JywgJzE2Mi4yNTQuMTk0'
    'LjM4JywgJzE2Mi4yNTQuMTk0LjUzJywgJzE2Mi4yNTQuMTk0LjU0JywgJzE2Mi4yNTQuMTk1LjUyJywgJzE2Mi4yNTQuMTk1'
    'LjUzJywgJzE2Mi4yNTQuMTk1LjcwJywgJzE2Mi4yNTQuMTk1LjcyJywgJzE2Mi4yNTQuMTk3LjM2JywgJzE2Mi4yNTQuMTk3'
    'LjM3JywgJzE2Mi4yNTQuMTk3LjQzJywgJzE2Mi4yNTQuMTk3LjQ1JywgJzE2Mi4yNTQuMTk3LjUyJywgJzE2Mi4yNTQuMTk3'
    'LjUzJywgJzE2Mi4yNTQuMTk3LjU1JywgJzE2Mi4yNTQuMTk3LjU2JywgJzE2Mi4yNTQuMTk4LjE1NicsICcxNjIuMjU0LjE5'
    'OS4xNzAnLCAnMTYyLjI1NC4xOTkuMTczJywgJzE2Mi4yNTQuMTk5LjE3OCcsICcxNjIuMjU0LjE5OS4xODAnLCAnMjA1LjE5'
    'Ni42LjEzNScsICcyMDUuMTk2LjYuMTQ5J119XX0KQ0FURUdPUklFUyA9ICgnYXBwbGljYXRpb25zJywnbmV0d29ya3MnLCdw'
    'b3J0cycsJ2RucycpCkJBU0UgPSB7CiAnYXBwbGljYXRpb25zJzogW3snaWQnOidtYXBwZXInLCd2YWx1ZSc6J2V2Z2VuaXVt'
    'LXdheWRyb2lkLW1hcHBlcicsJ2xhYmVsJzonV2F5ZHJvaWQgTWFwcGVyJ31dLAogJ25ldHdvcmtzJzogW3snaWQnOidsYW4n'
    'LCd2YWx1ZSc6J2Nvbm5lY3RlZCcsJ2xhYmVsJzon0KPRgdGC0YDQvtC50YHRgtCy0LAg0YLQtdC60YPRidC10Lkg0LvQvtC6'
    '0LDQu9GM0L3QvtC5INGB0LXRgtC4J30sCiAgICAgICAgICAgICAgeydpZCc6J2xpbmtsb2NhbCcsJ3ZhbHVlJzonMTY5LjI1'
    'NC4wLjAvMTYnLCdsYWJlbCc6J9Cj0YHRgtGA0L7QudGB0YLQstCwINGBINCw0LLRgtC+0LzQsNGC0LjRh9C10YHQutC40Lwg'
    '0LvQvtC60LDQu9GM0L3Ri9C8INCw0LTRgNC10YHQvtC8J30sCiAgICAgICAgICAgICAgeydpZCc6J2RlYWRsb2NrLXNkcics'
    'J3ZhbHVlJzonVURQJywnbGFiZWwnOidEZWFkbG9jazog0YHQtdGA0LLQtdGA0YsgU3RlYW0gRGF0YWdyYW0gUmVsYXknfV0s'
    'CiAncG9ydHMnOiBbeydpZCc6J2Rpc2NvdmVyeScsJ3ZhbHVlJzonZGlzY292ZXJ5JywnbGFiZWwnOifQntCx0L3QsNGA0YPQ'
    'ttC10L3QuNC1INGD0YHRgtGA0L7QudGB0YLQsjogbUROUywgU1NEUCwgTExNTlIgKNGC0L7Qu9GM0LrQviDQu9C+0LrQsNC7'
    '0YzQvdCw0Y8g0YHQtdGC0YwpJ31dLAogJ2Rucyc6IFt7J2lkJzonc3R1YicsJ3ZhbHVlJzonMTI3LjAuMC4wLzgnLCdsYWJl'
    'bCc6J9Ch0LjRgdGC0LXQvNC90YvQuSBETlMg0LLQvdGD0YLRgNC4INC60L7QvNC/0YzRjtGC0LXRgNCwJ31dCn0KCmRlZiBk'
    'ZWZhdWx0cygpOgogcmV0dXJuIHsnc2NoZW1hJzoxLCd3YXlkcm9pZF9kaXJlY3QnOlRydWUsJ2Rpc2FibGVkX2Jhc2UnOltd'
    'LCAnYXBwbGljYXRpb25zJzpbXSwgJ25ldHdvcmtzJzpbXSwgJ3BvcnRzJzpbXSwgJ2Rucyc6W119CgpkZWYgbG9hZCgpOgog'
    'aWYgbm90IFBBVEguZXhpc3RzKCk6cmV0dXJuIGRlZmF1bHRzKCkKIHZhbHVlPWpzb24ubG9hZHMoUEFUSC5yZWFkX3RleHQo'
    'KSkKIGlmIHZhbHVlLmdldCgnc2NoZW1hJykhPTE6cmFpc2UgUnVudGltZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGP'
    'INCy0LXRgNGB0LjRjyDQv9GA0LDQstC40Lsg0LjRgdC60LvRjtGH0LXQvdC40LkuJykKIHJldHVybiB7KipkZWZhdWx0cygp'
    'LCoqdmFsdWV9CgpkZWYgc2F2ZSh2YWx1ZSk6CiBQQVRILnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsZXhpc3Rfb2s9VHJ1'
    'ZSkKIHRtcD1QQVRILndpdGhfc3VmZml4KCcubmV3JykKIGZkPW9zLm9wZW4odG1wLG9zLk9fV1JPTkxZfG9zLk9fQ1JFQVR8'
    'b3MuT19UUlVOQ3xvcy5PX05PRk9MTE9XLDBvNjAwKQogd2l0aCBvcy5mZG9wZW4oZmQsJ3cnKSBhcyBmOmpzb24uZHVtcCh2'
    'YWx1ZSxmLGVuc3VyZV9hc2NpaT1GYWxzZSxpbmRlbnQ9MikKIG9zLnJlcGxhY2UodG1wLFBBVEgpCgpkZWYgZW5hYmxlZChw'
    'LGNhdCxrZXkpOnJldHVybiBjYXQrJzonK2tleSBub3QgaW4gcFsnZGlzYWJsZWRfYmFzZSddCgpkZWYgbm9ybWFsaXplKGNh'
    'dGVnb3J5LHZhbHVlKToKIHZhbHVlPXN0cih2YWx1ZSkuc3RyaXAoKQogaWYgbm90IHZhbHVlIG9yIGxlbih2YWx1ZSk+NTEy'
    'IG9yIGFueShvcmQoYyk8MzIgZm9yIGMgaW4gdmFsdWUpOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC9'
    '0L7QtSDQuNGB0LrQu9GO0YfQtdC90LjQtS4nKQogaWYgY2F0ZWdvcnk9PSdhcHBsaWNhdGlvbnMnOgogIGlmIG5vdCByZS5m'
    'dWxsbWF0Y2gocidbXHcuLyArQCgpXC1dKycsdmFsdWUpOnJhaXNlIFZhbHVlRXJyb3IoJ9Cj0LrQsNC20LjRgtC1INC40LzR'
    'jyDQv9GA0L7RhtC10YHRgdCwINC40LvQuCDQv9C+0LvQvdGL0Lkg0L/Rg9GC0YwuJykKICBpZiAnLycgaW4gdmFsdWUgYW5k'
    'IG5vdCB2YWx1ZS5zdGFydHN3aXRoKCcvJyk6cmFpc2UgVmFsdWVFcnJvcign0J/Rg9GC0Ywg0LTQvtC70LbQtdC9INCx0YvR'
    'gtGMINCw0LHRgdC+0LvRjtGC0L3Ri9C8LicpCiAgcmV0dXJuIHZhbHVlCiBpZiBjYXRlZ29yeT09J25ldHdvcmtzJzoKICB0'
    'cnk6CiAgIG5ldD1pcGFkZHJlc3MuaXBfbmV0d29yayh2YWx1ZSxzdHJpY3Q9RmFsc2UpCiAgIGlmIG5ldC52ZXJzaW9uIT00'
    'OnJhaXNlIFZhbHVlRXJyb3IoJ9Cf0L7QtNC00LXRgNC20LjQstCw0Y7RgtGB0Y8g0LDQtNGA0LXRgdCwINCy0LjQtNCwIDE5'
    'Mi4xNjguMS4xMC4nKQogICAjIEFkZHJlc3NlcyBvd25lZCBieSBvdXIgdHVubmVscyBjYW5ub3QgYmUgcm91dGVkIHBoeXNp'
    'Y2FsbHkuCiAgIHJlc2VydmVkPVsnMTAuNzcuMC4wLzI0Jyx0dW5uZWwuTkVUV09SSyx0dW5uZWwuRlVMTF9ORVQsJzE5OC4x'
    'OC4yNTQuMC8zMCddIGlmIHR1bm5lbCBlbHNlIFsnMTAuNzcuMC4wLzI0JywnMTcyLjI5LjI0Ni4wLzMwJywnMTcyLjI5LjI0'
    'Ny4wLzMwJywnMTk4LjE4LjI1NC4wLzMwJ10KICAgaWYgYW55KG5ldC5vdmVybGFwcyhpcGFkZHJlc3MuaXBfbmV0d29yayhu'
    'KSkgZm9yIG4gaW4gcmVzZXJ2ZWQpOnJhaXNlIFZhbHVlRXJyb3IoJ9CU0LjQsNC/0LDQt9C+0L0g0L/QtdGA0LXRgdC10LrQ'
    'sNC10YLRgdGPINGB0L4g0YHQu9GD0LbQtdCx0L3QvtC5INGB0LXRgtGM0Y4gVlBOLiDQlNC+0LHQsNCy0YzRgtC1INCx0L7Q'
    'u9C10LUg0YPQt9C60YPRjiDRgdC10YLRjC4nKQogICByZXR1cm4gc3RyKG5ldCkKICBleGNlcHQgVmFsdWVFcnJvciBhcyBl'
    'eGM6CiAgIGlmICcvJyBpbiB2YWx1ZSBvciByZS5mdWxsbWF0Y2gocidbXGQuXSsnLHZhbHVlKTpyYWlzZSBleGMKICBleGFj'
    'dD12YWx1ZS5zdGFydHN3aXRoKCc9Jyk7dmFsdWU9dmFsdWUubHN0cmlwKCc9JykubG93ZXIoKS5yc3RyaXAoJy4nKQogIHRy'
    'eTp2YWx1ZT12YWx1ZS5lbmNvZGUoJ2lkbmEnKS5kZWNvZGUoJ2FzY2lpJykKICBleGNlcHQgVW5pY29kZUVycm9yOnJhaXNl'
    'IFZhbHVlRXJyb3IoJ9Cd0LXQutC+0YDRgNC10LrRgtC90YvQuSDQtNC+0LzQtdC9LicpCiAgaWYgbGVuKHZhbHVlKT4yNTMg'
    'b3Igbm90IGFsbChyZS5mdWxsbWF0Y2gocidbYS16MC05XSg/OlthLXowLTktXXswLDYxfVthLXowLTldKT8nLHgpIGZvciB4'
    'IGluIHZhbHVlLnNwbGl0KCcuJykpOnJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC00L7QvNC10L0g0LHQtdC3'
    'IGh0dHBzOi8vINC4INC/0YPRgtC4LicpCiAgcmV0dXJuICgnPScgaWYgZXhhY3QgZWxzZSAnJykrdmFsdWUKIGlmIGNhdGVn'
    'b3J5PT0nZG5zJzoKICBhZGRyPWlwYWRkcmVzcy5pcF9hZGRyZXNzKHZhbHVlKQogIGlmIGFkZHIudmVyc2lvbiE9NCBvciBh'
    'ZGRyLmlzX3Vuc3BlY2lmaWVkIG9yIGFkZHIuaXNfbXVsdGljYXN0IG9yIGFkZHIuaXNfbG9vcGJhY2s6cmFpc2UgVmFsdWVF'
    'cnJvcign0KPQutCw0LbQuNGC0LUg0LDQtNGA0LXRgSDQstC90LXRiNC90LXQs9C+INC40LvQuCDQtNC+0LzQsNGI0L3QtdCz'
    '0L4gRE5TLdGB0LXRgNCy0LXRgNCwOyDQu9C+0LrQsNC70YzQvdGL0LkgRE5TINC90LDRhdC+0LTQuNGC0YHRjyDQsiDQsdCw'
    '0LfQvtCy0YvRhSDQv9GA0LDQstC40LvQsNGFLicpCiAgcmV0dXJuIHN0cihhZGRyKQogaWYgY2F0ZWdvcnk9PSdwb3J0cyc6'
    'CiAgbWF0Y2g9cmUuZnVsbG1hdGNoKHInKHRjcHx1ZHB8Ym90aCk6KFxkezEsNX0pKD86OihvdXR8aW58Ym90aCkpPycsdmFs'
    'dWUubG93ZXIoKSkKICBpZiBub3QgbWF0Y2ggb3Igbm90IDE8PWludChtYXRjaFsyXSk8PTY1NTM1OnJhaXNlIFZhbHVlRXJy'
    'b3IoJ9Ck0L7RgNC80LDRgjogdGNwOjQ0MzpvdXQsIHVkcDoyNTU2NTppbiDQuNC70LggYm90aDoyNTU2NTpib3RoLicpCiAg'
    'aWYgaW50KG1hdGNoWzJdKT09NTM6cmFpc2UgVmFsdWVFcnJvcignRE5TINC90LDRgdGC0YDQsNC40LLQsNC10YLRgdGPINCy'
    '0L4g0LLQutC70LDQtNC60LUgRE5TLicpCiAgcmV0dXJuIGYne21hdGNoWzFdfTp7aW50KG1hdGNoWzJdKX06e21hdGNoWzNd'
    'IG9yICJib3RoIn0nCiByYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGPINC60LDRgtC10LPQvtGA0LjR'
    'jy4nKQoKZGVmIG1pZ3JhdGlvbihzZXR0aW5ncyk6CiBpZiBQQVRILmV4aXN0cygpOnJldHVybgogcD1kZWZhdWx0cygpOyBy'
    'ZWplY3RlZD1bXQogc291cmNlcz17J2FwcGxpY2F0aW9ucyc6c2V0dGluZ3MuZ2V0KCdkaXJlY3RfYXBwcycpLCduZXR3b3Jr'
    'cyc6c2V0dGluZ3MuZ2V0KCdkaXJlY3RfbmV0d29ya3MnKX0KIGZvciBjYXRlZ29yeSxrZXkgaW4gc291cmNlcy5pdGVtcygp'
    'OgogIGlmIGtleSBhbmQgUGF0aChrZXkpLmlzX2ZpbGUoKToKICAgZm9yIGxpbmUgaW4gUGF0aChrZXkpLnJlYWRfdGV4dCgp'
    'LnNwbGl0bGluZXMoKToKICAgIHM9bGluZS5zdHJpcCgpCiAgICBpZiBub3QgcyBvciBzLnN0YXJ0c3dpdGgoJyMnKTpjb250'
    'aW51ZQogICAgdHJ5OnBbY2F0ZWdvcnldLmFwcGVuZChub3JtYWxpemUoY2F0ZWdvcnkscykpCiAgICBleGNlcHQgVmFsdWVF'
    'cnJvcjpyZWplY3RlZC5hcHBlbmQoeydjYXRlZ29yeSc6Y2F0ZWdvcnksJ3ZhbHVlJzpzfSkKIGtleT1zZXR0aW5ncy5nZXQo'
    'J2RpcmVjdF9zaXRlcycpCiBpZiBrZXkgYW5kIFBhdGgoa2V5KS5pc19maWxlKCk6CiAgZm9yIGxpbmUgaW4gUGF0aChrZXkp'
    'LnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKToKICAgcz1saW5lLnN0cmlwKCkKICAgaWYgbm90IHMgb3Igcy5zdGFydHN3aXRo'
    'KCcjJyk6Y29udGludWUKICAgcz1zLnJlcGxhY2UoJ2Z1bGw6JywnPScsMSkucmVtb3ZlcHJlZml4KCdkb21haW46JykKICAg'
    'dHJ5OnBbJ25ldHdvcmtzJ10uYXBwZW5kKG5vcm1hbGl6ZSgnbmV0d29ya3MnLHMpKQogICBleGNlcHQgVmFsdWVFcnJvcjpy'
    'ZWplY3RlZC5hcHBlbmQoeydjYXRlZ29yeSc6J25ldHdvcmtzJywndmFsdWUnOnN9KQogZm9yIHByb3RvLHBvcnQgaW4gYXBp'
    'LnJlYWRfc2VydmVyX3BvcnRzKHNldHRpbmdzKTpwWydwb3J0cyddLmFwcGVuZChmJ3twcm90b306e3BvcnR9OmluJykKIGZv'
    'ciBjIGluIENBVEVHT1JJRVM6cFtjXT1saXN0KGRpY3QuZnJvbWtleXMocFtjXSkpCiBwWydtaWdyYXRpb25fc2tpcHBlZCdd'
    'PXJlamVjdGVkCiBzYXZlKHApCgpkZWYgcHVibGljKCk6CiBwPWxvYWQoKTtiYXNlPXt9CiBmb3IgYyxlbnRyaWVzIGluIEJB'
    'U0UuaXRlbXMoKTpiYXNlW2NdPVt7KiplLCdlbmFibGVkJzplbmFibGVkKHAsYyxlWydpZCddKX0gZm9yIGUgaW4gZW50cmll'
    'c10KIHJldHVybiB7KipwLCdiYXNlJzpiYXNlfQoKZGVmIHBvcnRzKHAsZGlyZWN0aW9uKToKIHJlc3VsdD17J3RjcCc6c2V0'
    'KCksJ3VkcCc6c2V0KCl9CiBmb3IgdmFsdWUgaW4gcFsncG9ydHMnXToKICBwcm90byxudW1iZXIsc2lkZT12YWx1ZS5zcGxp'
    'dCgnOicpCiAgaWYgc2lkZSBub3QgaW4gKGRpcmVjdGlvbiwnYm90aCcpOmNvbnRpbnVlCiAgZm9yIHByb3RvY29sIGluICgn'
    'dGNwJywndWRwJykgaWYgcHJvdG89PSdib3RoJyBlbHNlIChwcm90bywpOnJlc3VsdFtwcm90b2NvbF0uYWRkKGludChudW1i'
    'ZXIpKQogcmV0dXJuIHJlc3VsdAoKZGVmIGxvY2FsX25ldHdvcmtzKHJvdXRlKToKIGRhdGE9anNvbi5sb2Fkcyh0dW5uZWwu'
    'Y29tbWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdzaG93JywnZGV2Jyxyb3V0ZVsnZGV2J11dKS5zdGRvdXQpCiByZXR1'
    'cm4gc29ydGVkKHtzdHIoaXBhZGRyZXNzLmlwX25ldHdvcmsoZiJ7YVsnbG9jYWwnXX0ve2FbJ3ByZWZpeGxlbiddfSIsc3Ry'
    'aWN0PUZhbHNlKSkgZm9yIGxpbmsgaW4gZGF0YSBmb3IgYSBpbiBsaW5rLmdldCgnYWRkcl9pbmZvJyxbXSkgaWYgYS5nZXQo'
    'J3Njb3BlJyk9PSdnbG9iYWwnfSkKCmRlZiBkaXJlY3RfbmV0d29ya3MocCxsYW4pOgogdmFsdWVzPVtdCiBmb3IgdmFsdWUg'
    'aW4gcFsnbmV0d29ya3MnXToKICB0cnk6dmFsdWVzLmFwcGVuZChzdHIoaXBhZGRyZXNzLmlwX25ldHdvcmsodmFsdWUpKSkK'
    'ICBleGNlcHQgVmFsdWVFcnJvcjpwYXNzCiBpZiBlbmFibGVkKHAsJ25ldHdvcmtzJywnbGFuJyk6CiAgZm9yIGl0ZW0gaW4g'
    'bGFuOgogICByZW1haW5pbmc9W2lwYWRkcmVzcy5pcF9uZXR3b3JrKGl0ZW0pXQogICBmb3IgcmVzZXJ2ZWQgaW4gWycxMC43'
    'Ny4wLjAvMjQnLCcxNzIuMjkuMjQ2LjAvMzAnLCcxNzIuMjkuMjQ3LjAvMzAnLCcxOTguMTguMjU0LjAvMzAnXToKICAgIGJs'
    'b2NrPWlwYWRkcmVzcy5pcF9uZXR3b3JrKHJlc2VydmVkKTt1cGRhdGVkPVtdCiAgICBmb3IgbmV0IGluIHJlbWFpbmluZzoK'
    'ICAgICBpZiBub3QgbmV0Lm92ZXJsYXBzKGJsb2NrKTp1cGRhdGVkLmFwcGVuZChuZXQpCiAgICAgZWxpZiBibG9jay5zdWJu'
    'ZXRfb2YobmV0KTp1cGRhdGVkLmV4dGVuZChuZXQuYWRkcmVzc19leGNsdWRlKGJsb2NrKSkKICAgIHJlbWFpbmluZz11cGRh'
    'dGVkCiAgIHZhbHVlcyArPSBbc3RyKG4pIGZvciBuIGluIHJlbWFpbmluZ10KIGlmIGVuYWJsZWQocCwnbmV0d29ya3MnLCds'
    'aW5rbG9jYWwnKTp2YWx1ZXMrPVsnMTY5LjI1NC4wLjAvMTYnXQogcmV0dXJuIHNvcnRlZChzZXQodmFsdWVzKSkKCmRlZiBj'
    'b25maWcocCk6CiBydWxlcz1beyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2NoZWNrJ10sJ291dGJvdW5kVGFnJzon'
    'dnBuJ30sCiAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1pbiddLCdvdXRib3VuZFRhZyc6J2Ru'
    'cyd9XQogYXBwcz1saXN0KHBbJ2FwcGxpY2F0aW9ucyddKQogaWYgZW5hYmxlZChwLCdhcHBsaWNhdGlvbnMnLCdtYXBwZXIn'
    'KTphcHBzKz1bJ2V2Z2VuaXVtLXdheWRyb2lkLW1hcHBlciddCiBpZiBhcHBzOnJ1bGVzLmFwcGVuZCh7J3R5cGUnOidmaWVs'
    'ZCcsJ3Byb2Nlc3MnOmFwcHMsJ2luYm91bmRUYWcnOlsndHVuJ10sJ291dGJvdW5kVGFnJzonZGlyZWN0J30pCiBkb21haW5z'
    'PVtdCiBmb3IgdmFsdWUgaW4gcFsnbmV0d29ya3MnXToKICB0cnk6aXBhZGRyZXNzLmlwX25ldHdvcmsodmFsdWUpCiAgZXhj'
    'ZXB0IFZhbHVlRXJyb3I6ZG9tYWlucy5hcHBlbmQoKCdmdWxsOicrdmFsdWVbMTpdKSBpZiB2YWx1ZS5zdGFydHN3aXRoKCc9'
    'JykgZWxzZSAnZG9tYWluOicrdmFsdWUpCiBpZiBkb21haW5zOnJ1bGVzLmFwcGVuZCh7J3R5cGUnOidmaWVsZCcsJ2RvbWFp'
    'bic6ZG9tYWlucywnaW5ib3VuZFRhZyc6Wyd0dW4nXSwnb3V0Ym91bmRUYWcnOidkaXJlY3QnfSkKICMgRE5TIGVuZ2luZSBy'
    'ZXF1ZXN0cyBtdXN0IG5ldmVyIGluaGVyaXQgZG9tYWluL2FwcGxpY2F0aW9uIGJ5cGFzcyBydWxlcy4KIHJ1bGVzKz1beyd0'
    'eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUnXSwnb3V0Ym91bmRUYWcnOid2cG4nfSwKICAgICAgICAg'
    'eyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ3R1biddLCdvdXRib3VuZFRhZyc6J3Zwbid9XQogcmV0dXJuIHsnbG9n'
    'Jzp7J2xvZ2xldmVsJzond2FybmluZycsJ2FjY2Vzcyc6J25vbmUnfSwKICAnaW5ib3VuZHMnOlt7J3RhZyc6J3R1bicsJ3By'
    'b3RvY29sJzondHVuJywnc2V0dGluZ3MnOnsnbmFtZSc6VFVOLCdtdHUnOjEyODAsJ2dhdGV3YXknOlsnMTk4LjE4LjI1NC4x'
    'LzMwJ119LAogICAgICAgICAgICAgICAnc25pZmZpbmcnOnsnZW5hYmxlZCc6VHJ1ZSwnZGVzdE92ZXJyaWRlJzpbJ2h0dHAn'
    'LCd0bHMnLCdxdWljJ10sJ3JvdXRlT25seSc6VHJ1ZX19LAogICAgICAgICAgICAgIHsndGFnJzonZG5zLWluJywnbGlzdGVu'
    'JzonMTI3LjAuMC4xJywncG9ydCc6RE5TX1BPUlQsJ3Byb3RvY29sJzonZG9rb2RlbW8tZG9vcicsJ3NldHRpbmdzJzp7J2Fk'
    'ZHJlc3MnOicxLjEuMS4xJywncG9ydCc6NTMsJ25ldHdvcmsnOid0Y3AsdWRwJ319LAogICAgICAgICAgICAgIHsndGFnJzon'
    'Y2hlY2snLCdsaXN0ZW4nOicxMjcuMC4wLjEnLCdwb3J0JzpDSEVDS19QT1JULCdwcm90b2NvbCc6J3NvY2tzJywnc2V0dGlu'
    'Z3MnOnsnYXV0aCc6J25vYXV0aCcsJ3VkcCc6RmFsc2V9fV0sCiAgJ2Rucyc6eydzZXJ2ZXJzJzpbJzEuMS4xLjEnLCc5Ljku'
    'OS45J10sJ3F1ZXJ5U3RyYXRlZ3knOidVc2VJUHY0JywndGFnJzonZG5zLWVuZ2luZScsJ2Rpc2FibGVGYWxsYmFjayc6RmFs'
    'c2V9LAogICdvdXRib3VuZHMnOlt7J3RhZyc6dGFnLCdwcm90b2NvbCc6J2ZyZWVkb20nLCdzZXR0aW5ncyc6eydkb21haW5T'
    'dHJhdGVneSc6J1VzZUlQdjQnfSwnc3RyZWFtU2V0dGluZ3MnOnsnc29ja29wdCc6eydtYXJrJzptYXJrfX19IGZvciB0YWcs'
    'bWFyayBpbiBbKCd2cG4nLFZQTiksKCdkaXJlY3QnLERJUkVDVCldXSsKICAgICAgICAgICAgICAgW3sndGFnJzonZG5zJywn'
    'cHJvdG9jb2wnOidkbnMnLCdzZXR0aW5ncyc6eydydWxlcyc6W3sncVR5cGUnOicxLDI4JywnYWN0aW9uJzonaGlqYWNrJ30s'
    'eydhY3Rpb24nOidkaXJlY3QnfV19LCdzdHJlYW1TZXR0aW5ncyc6eydzb2Nrb3B0Jzp7J21hcmsnOlZQTn19fV0sCiAgJ3Jv'
    'dXRpbmcnOnsnZG9tYWluU3RyYXRlZ3knOidBc0lzJywncnVsZXMnOnJ1bGVzfX0KCmRlZiBuZnRfc2V0KGl0ZW1zKTpyZXR1'
    'cm4gJ3sgJysnLCAnLmpvaW4oc3RyKHgpIGZvciB4IGluIHNvcnRlZChpdGVtcykpKycgfScKCmRlZiBmaXJld2FsbChwLGxh'
    'bix1aWQpOgogIyBSb3V0ZSBtYXJrcyBhcmUgc2V0IG9ubHkgYnkgdGhpcyBwcml2aWxlZ2VkIGNsYXNzaWZpZXIgb3IgZXhw'
    'bGljaXQga2VybmVsIHJ1bGVzLgogbWFyaz1bXTtkbnM9W107Zm9yd2FyZD1bXTtuYXQ9WydtZXRhIG5mcHJvdG8gaXB2NCBt'
    'ZXRhIG1hcmsgJytzdHIoRElSRUNUKSsnIG9pZm5hbWUgIT0gImxvIiBtYXNxdWVyYWRlJ10KIGlmIGVuYWJsZWQocCwnZG5z'
    'Jywnc3R1YicpOmRucy5hcHBlbmQoJ2lwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybicpCiBpZiBwWydkbnMnXToKICBkbnMu'
    'YXBwZW5kKGYnaXAgZGFkZHIge25mdF9zZXQocFsiZG5zIl0pfSByZXR1cm4nKQogIG1hcmsuYXBwZW5kKGYnaXAgZGFkZHIg'
    'e25mdF9zZXQocFsiZG5zIl0pfSBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgbWV0YSBtYXJrIHNl'
    'dCB7RElSRUNUfSByZXR1cm4nKQogIyBJbnRlcmZhY2UtYm91bmQgc3lzdGVtIHJlc29sdmVycyBtdXN0IGtlZXAgRE5TIG9u'
    'IHRoZSB0dW5uZWwgaW50ZXJmYWNlLgogIyBSZWRpcmVjdGluZyB0aGVpciB1cHN0cmVhbSBzb2NrZXQgdG8gbG9vcGJhY2sg'
    'YnJlYWtzIFNPX0JJTkRUT0RFVklDRS4KICMgT25seSBhbiBleHBsaWNpdGx5IGRpc2FibGVkIGxvb3BiYWNrLXN0dWIgcnVs'
    'ZSB1c2VzIHRoZSBsb2NhbCBETlMgbGlzdGVuZXIuCiBkbnMrPVsnaXAgZGFkZHIgMTI3LjAuMC4wLzggbWV0YSBsNHByb3Rv'
    'IHsgdGNwLCB1ZHAgfSB0aCBkcG9ydCA1MyByZWRpcmVjdCB0byA6JytzdHIoRE5TX1BPUlQpLAogICAgICAgJ21ldGEgbmZw'
    'cm90byBpcHY0IG1ldGEgbDRwcm90byB7IHRjcCwgdWRwIH0gdGggZHBvcnQgNTMgZG5hdCBpcCB0byAxNzIuMjkuMjQ3LjIn'
    'XQogbWFyays9WydtZXRhIGw0cHJvdG8geyB0Y3AsIHVkcCB9IHRoIGRwb3J0IDUzIG1ldGEgbWFyayBzZXQgJytzdHIoVlBO'
    'KSsnIHJldHVybiddCiB3YXluZXRzPXdheWRyb2lkX25ldHdvcmsoKVsnbmV0d29ya3MnXQogbWFyay5hcHBlbmQoZidpcCBk'
    'YWRkciBAd2F5ZHJvaWRfbmV0d29ya3MgbWV0YSBtYXJrIHNldCB7RElSRUNUfSByZXR1cm4nKQogbWFyay5hcHBlbmQoZidv'
    'aWZuYW1lICJ3YXlkcm9pZDAiIHVkcCBzcG9ydCA2NyB1ZHAgZHBvcnQgNjggbWV0YSBtYXJrIHNldCB7RElSRUNUfSByZXR1'
    'cm4nKQogaWYgZW5hYmxlZChwLCduZXR3b3JrcycsJ2RlYWRsb2NrLXNkcicpOgogIGZvciBncm91cCBpbiBERUFETE9DS19T'
    'RFJbJ2dyb3VwcyddOgogICBhZGRyZXNzZXM9bmZ0X3NldChncm91cFsnYWRkcmVzc2VzJ10pCiAgIG1hcmsuYXBwZW5kKGYi'
    'aXAgZGFkZHIge2FkZHJlc3Nlc30gdWRwIGRwb3J0IHtncm91cFsnZmlyc3QnXX0te2dyb3VwWydsYXN0J119IG1ldGEgbWFy'
    'ayBzZXQge0RJUkVDVH0gcmV0dXJuIikKIG5ldHM9ZGlyZWN0X25ldHdvcmtzKHAsbGFuKQogaWYgbmV0czptYXJrLmFwcGVu'
    'ZChmJ2lwIGRhZGRyIHtuZnRfc2V0KG5ldHMpfSBtZXRhIG1hcmsgc2V0IHtESVJFQ1R9IHJldHVybicpCiBpZiBlbmFibGVk'
    'KHAsJ3BvcnRzJywnZGlzY292ZXJ5Jyk6CiAgbWFyays9WydpcCBkYWRkciB7IDIyNC4wLjAuMjUxLCAyMjQuMC4wLjI1Miwg'
    'MjM5LjI1NS4yNTUuMjUwIH0gdWRwIGRwb3J0IHsgNTM1MywgNTM1NSwgMTkwMCB9IG1ldGEgbWFyayBzZXQgJytzdHIoRElS'
    'RUNUKSsnIHJldHVybiddCiBmb3IgZGlyZWN0aW9uIGluICgnb3V0JywnaW4nKToKICBmb3IgcHJvdG8sdmFsdWVzIGluIHBv'
    'cnRzKHAsZGlyZWN0aW9uKS5pdGVtcygpOgogICBpZiB2YWx1ZXM6bWFyay5hcHBlbmQoKCdjdCBkaXJlY3Rpb24gcmVwbHkg'
    'JyBpZiBkaXJlY3Rpb249PSdpbicgZWxzZSAnJykrZid7cHJvdG99IHsic3BvcnQiIGlmIGRpcmVjdGlvbj09ImluIiBlbHNl'
    'ICJkcG9ydCJ9IHtuZnRfc2V0KHZhbHVlcyl9IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIGlmIHBbJ3dheWRy'
    'b2lkX2RpcmVjdCddOgogIGZvcndhcmQ9WydpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFy'
    'ayBzZXQgJytzdHIoRElSRUNUKSsnIGN0IG1hcmsgc2V0ICcrc3RyKERJUkVDVCksICdjdCBkaXJlY3Rpb24gcmVwbHkgY3Qg'
    'bWFyayAnK3N0cihESVJFQ1QpKycgbWV0YSBtYXJrIHNldCAnK3N0cihESVJFQ1QpXQoKIGRlZiBsaW5lcyhpdGVtcyk6cmV0'
    'dXJuICdcbicuam9pbignICAnK3ggZm9yIHggaW4gaXRlbXMpCiByZXR1cm4gZicnJ3RhYmxlIGluZXQge3R1bm5lbC5GVUxM'
    'X0dVQVJEfSB7ewogc2V0IHdheWRyb2lkX25ldHdvcmtzIHt7IHR5cGUgaXB2NF9hZGRyOyBmbGFncyBpbnRlcnZhbDsgeygn'
    'ZWxlbWVudHMgPSAnK25mdF9zZXQod2F5bmV0cykrJzsnKSBpZiB3YXluZXRzIGVsc2UgJyd9IH19CiBjaGFpbiByb3V0ZSB7'
    'eyB0eXBlIHJvdXRlIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xNTA7IHBvbGljeSBhY2NlcHQ7CiAgbWV0YSBza3VpZCB7dWlk'
    'fSByZXR1cm4KICBtZXRhIG1hcmsgc2V0IDAKICBpcCBkYWRkciAxMjcuMC4wLjAvOCByZXR1cm4Ke2xpbmVzKG1hcmspfQog'
    'fX0KIGNoYWluIGRucyB7eyB0eXBlIG5hdCBob29rIG91dHB1dCBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIG1l'
    'dGEgc2t1aWQge3VpZH0gcmV0dXJuCntsaW5lcyhkbnMpfQogfX0KIGNoYWluIHByZXJvdXRlIHt7IHR5cGUgZmlsdGVyIGhv'
    'b2sgcHJlcm91dGluZyBwcmlvcml0eSAtMTUwOyBwb2xpY3kgYWNjZXB0Owp7bGluZXMoZm9yd2FyZCl9CiB9fQogY2hhaW4g'
    'd2F5ZHJvaWRfZG5zIHt7IHR5cGUgbmF0IGhvb2sgcHJlcm91dGluZyBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0Owog'
    'IGlpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRw'
    'b3J0IDUzIGRuYXQgaXAgdG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5n'
    'IHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7dHVubmVsLkZV'
    'TExfSE9TVH0iIHNuYXQgaXAgdG8gMTcyLjI5LjI0Ny4xCntsaW5lcyhuYXQpfQogfX0KIGNoYWluIG91dHB1dCB7eyB0eXBl'
    'IGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQKICBt'
    'ZXRhIG5mcHJvdG8gaXB2NCBtZXRhIG1hcmsge0RJUkVDVH0gYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBtYXJr'
    'IHtWUE59IG1ldGEgbDRwcm90byB7eyB0Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBvaWZuYW1lICJ7dHVubmVsLkZVTExfSE9T'
    'VH0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgc2t1aWQge3VpZH0gbWV0YSBtYXJrIHtWUE59IG9pZm5hbWUg'
    'Int0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie1RVTn0iIGFjY2VwdAog'
    'IGlwIGRhZGRyIDI1NS4yNTUuMjU1LjI1NSB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3IGFjY2VwdAogfX0KIGNoYWluIGZv'
    'cndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAi'
    'e3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0dW5uZWwuU0VSVkVSfSB1ZHAgZHBv'
    'cnQge3R1bm5lbC5JS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5D'
    'TElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7dHVubmVsLkhP'
    'U1R9IiBpcCBzYWRkciB7dHVubmVsLkNMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3AgZHBvcnQge3sgMjQ1NzEs'
    'IDI0NTc4IH19IGFjY2VwdAogIGlpZm5hbWUgInt0dW5uZWwuSE9TVH0iIGlwIHNhZGRyIHt0dW5uZWwuQ0xJRU5UfSBpcCBk'
    'YWRkciB7dHVubmVsLlNFUlZFUn0gdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIGlpZm5hbWUgInt0dW5uZWwuSE9TVH0iIGlw'
    'IHNhZGRyIHt0dW5uZWwuQ0xJRU5UfSBpcCBkYWRkciB7dHVubmVsLlNFUlZFUn0gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAg'
    'b2lmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgZGFkZHIge3R1bm5lbC5DTElFTlR9IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJl'
    'bGF0ZWQgYWNjZXB0CiAgaWlmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIG1hcmsge0RJUkVDVH0g'
    'YWNjZXB0CiAgb2lmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxh'
    'dGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntUVU59IiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2'
    'NCBpaWZuYW1lICJ7VFVOfSIgY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2'
    'NCBvaWZuYW1lICJ7dHVubmVsLkZVTExfSE9TVH0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgInt0dW5u'
    'ZWwuRlVMTF9IT1NUfSIgY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKIH19Cn19JycnCgpVTklUPScnJ1tV'
    'bml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBsb2NhbCBhcHBsaWNhdGlvbiBhbmQgZG9tYWluIHJvdXRpbmcKQWZ0ZXI9bmV0'
    'd29yay50YXJnZXQKV2FudHM9ZXZnZW5pdW0td2F5ZHJvaWQtbmV0d29yay5zZXJ2aWNlCltTZXJ2aWNlXQpVc2VyPXZwbi14'
    'cmF5Ckdyb3VwPXZwbi14cmF5CkV4ZWNTdGFydD0vb3B0L3Zwbi1tYW5hZ2VyL2Jpbi94cmF5IHJ1biAtY29uZmlnIC9ydW4v'
    'dnBuLW1hbmFnZXIvcG9saWN5Lmpzb24KUmVzdGFydD1vbi1mYWlsdXJlClJlc3RhcnRTZWM9MgpBbWJpZW50Q2FwYWJpbGl0'
    'aWVzPUNBUF9ORVRfQURNSU4gQ0FQX05FVF9SQVcgQ0FQX1NZU19QVFJBQ0UgQ0FQX0RBQ19SRUFEX1NFQVJDSApDYXBhYmls'
    'aXR5Qm91bmRpbmdTZXQ9Q0FQX05FVF9BRE1JTiBDQVBfTkVUX1JBVyBDQVBfU1lTX1BUUkFDRSBDQVBfREFDX1JFQURfU0VB'
    'UkNICk5vTmV3UHJpdmlsZWdlcz10cnVlClByb3RlY3RTeXN0ZW09c3RyaWN0ClByb3RlY3RIb21lPXRydWUKUHJpdmF0ZVRt'
    'cD10cnVlCkRldmljZUFsbG93PS9kZXYvbmV0L3R1biBydwpVTWFzaz0wMDc3CicnJwoKV0FZRFJPSURfVU5JVD0nJydbVW5p'
    'dF0KRGVzY3JpcHRpb249RXZnZW5pdW0gV2F5ZHJvaWQgbmV0d29yayBsaWZlY3ljbGUKQWZ0ZXI9ZXZnZW5pdW0tcG9saWN5'
    'LnNlcnZpY2UKUGFydE9mPWV2Z2VuaXVtLXBvbGljeS5zZXJ2aWNlCltTZXJ2aWNlXQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9z'
    'YmluL3ZwbmN0bCBpbnRlcm5hbC13YXlkcm9pZC13YXRjaApSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0yClVNYXNr'
    'PTAwNzcKJycnCgpkZWYgd2F5ZHJvaWRfbmV0d29yaygpOgogcmVzdWx0PXR1bm5lbC5jb21tYW5kKFsnaXAnLCctaicsJy00'
    'JywnYWRkcicsJ3Nob3cnLCdkZXYnLCd3YXlkcm9pZDAnXSxjaGVjaz1GYWxzZSkKIGlmIHJlc3VsdC5yZXR1cm5jb2RlOnJl'
    'dHVybiB7J2luZGV4JzpOb25lLCduZXR3b3Jrcyc6W119CiBsaW5rcz1qc29uLmxvYWRzKHJlc3VsdC5zdGRvdXQpCiBuZXR3'
    'b3Jrcz1zb3J0ZWQoe3N0cihpcGFkZHJlc3MuaXBfbmV0d29yayhmInthWydsb2NhbCddfS97YVsncHJlZml4bGVuJ119Iixz'
    'dHJpY3Q9RmFsc2UpKSBmb3IgbGluayBpbiBsaW5rcyBpZiAnVVAnIGluIGxpbmsuZ2V0KCdmbGFncycsW10pIGZvciBhIGlu'
    'IGxpbmsuZ2V0KCdhZGRyX2luZm8nLFtdKSBpZiBhLmdldCgnc2NvcGUnKT09J2dsb2JhbCd9KQogcmV0dXJuIHsnaW5kZXgn'
    'OmxpbmtzWzBdLmdldCgnaWZpbmRleCcpIGlmIGxpbmtzIGVsc2UgTm9uZSwnbmV0d29ya3MnOm5ldHdvcmtzfQoKZGVmIHN5'
    'bmNfd2F5ZHJvaWRfbmV0d29yayhmb3JjZT1GYWxzZSk6CiAjIENhbGxlciBob2xkcyBvcGVyYXRpb24ubG9jay4gT25seSB0'
    'aGlzIFZQTidzIHNldC90YWJsZSBhcmUgbW9kaWZpZWQuCiBzdGF0ZT13YXlkcm9pZF9uZXR3b3JrKCk7Y2FjaGU9UlVOLyd3'
    'YXlkcm9pZC1uZXR3b3JrLmpzb24nCiB0cnk6cHJldmlvdXM9anNvbi5sb2FkcyhjYWNoZS5yZWFkX3RleHQoKSkKIGV4Y2Vw'
    'dCAoT1NFcnJvcixWYWx1ZUVycm9yKTpwcmV2aW91cz1Ob25lCiBpZiBub3QgZm9yY2UgYW5kIHN0YXRlPT1wcmV2aW91czpy'
    'ZXR1cm4KIHJvdXRlcz1qc29uLmxvYWRzKHR1bm5lbC5jb21tYW5kKFsnaXAnLCctaicsJy00Jywncm91dGUnLCdzaG93Jywn'
    'dGFibGUnLFBIWVNJQ0FMX1RBQkxFXSkuc3Rkb3V0KQogc3RhbGU9e3JbJ2RzdCddIGZvciByIGluIHJvdXRlcyBpZiByLmdl'
    'dCgnZGV2Jyk9PSd3YXlkcm9pZDAnIGFuZCByLmdldCgnZHN0Jykgbm90IGluIHN0YXRlWyduZXR3b3JrcyddfQogZm9yIG5l'
    'dHdvcmsgaW4gc3RhdGVbJ25ldHdvcmtzJ106CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsbmV0'
    'd29yaywnZGV2Jywnd2F5ZHJvaWQwJywnc2NvcGUnLCdsaW5rJywndGFibGUnLFBIWVNJQ0FMX1RBQkxFXSkKIHJ1bGVzPSdm'
    'bHVzaCBzZXQgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJEKycgd2F5ZHJvaWRfbmV0d29ya3NcbicKIGlmIHN0YXRlWyduZXR3'
    'b3JrcyddOnJ1bGVzKz0nYWRkIGVsZW1lbnQgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJEKycgd2F5ZHJvaWRfbmV0d29ya3Mg'
    'JytuZnRfc2V0KHN0YXRlWyduZXR3b3JrcyddKSsnXG4nCiB0dW5uZWwuY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9'
    'cnVsZXMpCiBmb3IgbmV0d29yayBpbiBzdGFsZTp0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdkZWwnLG5ldHdvcmss'
    'J2RldicsJ3dheWRyb2lkMCcsJ3RhYmxlJyxQSFlTSUNBTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiBjYWNoZS53cml0ZV90ZXh0'
    'KGpzb24uZHVtcHMoc3RhdGUpKTtjYWNoZS5jaG1vZCgwbzYwMCkKCmRlZiB3YXRjaF93YXlkcm9pZCgpOgogaW1wb3J0IHN5'
    'cwogbGFzdF9lcnJvcj1Ob25lCiB3aGlsZSBUcnVlOgogIHRyeToKICAgUlVOLm1rZGlyKHBhcmVudHM9VHJ1ZSxleGlzdF9v'
    'az1UcnVlKQogICB3aXRoIChSVU4vJ29wZXJhdGlvbi5sb2NrJykub3BlbignYSsnKSBhcyBsb2NrOgogICAgdHJ5OmZjbnRs'
    'LmZsb2NrKGxvY2ssZmNudGwuTE9DS19FWHxmY250bC5MT0NLX05CKQogICAgZXhjZXB0IEJsb2NraW5nSU9FcnJvcjpwYXNz'
    'CiAgICBlbHNlOgogICAgIGlmIHR1bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpIGFuZCBQYXRoKCcvc3lzL2NsYXNzL25ldC8n'
    'K1RVTikuZXhpc3RzKCk6c3luY193YXlkcm9pZF9uZXR3b3JrKCkKICAgbGFzdF9lcnJvcj1Ob25lCiAgZXhjZXB0IEV4Y2Vw'
    'dGlvbiBhcyBleGM6CiAgIG1lc3NhZ2U9c3RyKGV4YykKICAgaWYgbWVzc2FnZSE9bGFzdF9lcnJvcjpwcmludCgnV2F5ZHJv'
    'aWQgbmV0d29yayBzeW5jOiAnK21lc3NhZ2UsZmlsZT1zeXMuc3RkZXJyLGZsdXNoPVRydWUpCiAgIGxhc3RfZXJyb3I9bWVz'
    'c2FnZQogIHRpbWUuc2xlZXAoMSkKCmRlZiBpbnN0YWxsKCk6CiBQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtLycrU0VSVklD'
    'RSkud3JpdGVfdGV4dChVTklUKQogUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbS8nK1dBWURST0lEX1NFUlZJQ0UpLndyaXRl'
    'X3RleHQoV0FZRFJPSURfVU5JVCkKIHR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywnZGFlbW9uLXJlbG9hZCddKQoKZGVm'
    'IGFwcGx5KCk6CiBwPWxvYWQoKTtzZXR0aW5ncz1hcGkubG9hZF9zZXR0aW5ncygpO3JvdXRlPXR1bm5lbC5waHlzaWNhbF9y'
    'b3V0ZSgpO2xhbj1sb2NhbF9uZXR3b3Jrcyhyb3V0ZSkKIGFwaS5lbnN1cmVfcnVudGltZShzZXR0aW5ncykKIGNmZz1SVU4v'
    'J3BvbGljeS5qc29uJzt0bXA9UlVOLydwb2xpY3kubmV3Lmpzb24nCiB0bXAud3JpdGVfdGV4dChqc29uLmR1bXBzKGNvbmZp'
    'ZyhwKSkpO29zLmNobW9kKHRtcCwwbzY0MCk7b3MuY2hvd24odG1wLDAsaW50KHNldHRpbmdzWyd4cmF5X2dpZCddKSkKIGNo'
    'ZWNrPXR1bm5lbC5jb21tYW5kKFthcGkuWFJBWSwncnVuJywnLXRlc3QnLCctY29uZmlnJyx0bXBdLGNoZWNrPUZhbHNlKQog'
    'aWYgY2hlY2sucmV0dXJuY29kZTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Ce0LHRgNCw0LHQvtGC0YfQuNC6INC40YHQutC70Y7R'
    'h9C10L3QuNC5INC90LUg0L/RgNC40L3Rj9C7INC90LDRgdGC0YDQvtC50LrQuC4nKQogcnVsZXM9ZmlyZXdhbGwocCxsYW4s'
    'aW50KHNldHRpbmdzWyd4cmF5X3VpZCddKSkKIHJlcGxhY2VtZW50PSgnZGVsZXRlIHRhYmxlIGluZXQgJyt0dW5uZWwuRlVM'
    'TF9HVUFSRCsnXG4nIGlmIHR1bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpIGVsc2UgJycpK3J1bGVzCiB0dW5uZWwuY29tbWFu'
    'ZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKIG93bmVyc2hpcD1QQVRILndpdGhfbmFtZSgncG9s'
    'aWN5LW5ldHdvcmsuanNvbicpCiBpZiBub3Qgb3duZXJzaGlwLmV4aXN0cygpOgogIGZvciB0YWJsZSBpbiAoUEhZU0lDQUxf'
    'VEFCTEUsVlBOX1RBQkxFKToKICAgaWYgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyx0YWJs'
    'ZV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOnJhaXNlIFJ1bnRpbWVFcnJvcign0KLQsNCx0LvQuNGG0LAg0LzQsNGA'
    '0YjRgNGD0YLQuNC30LDRhtC40Lgg0LjRgdC60LvRjtGH0LXQvdC40Lkg0LfQsNC90Y/RgtCwINC00YDRg9Cz0L7QuSDQv9GA'
    '0L7Qs9GA0LDQvNC80L7QuS4nKQogIGV4aXN0aW5nPWpzb24ubG9hZHModHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQn'
    'LCdydWxlJ10pLnN0ZG91dCkKICBpZiBhbnkoci5nZXQoJ3ByaW9yaXR5JykgaW4gKDc2LDc3LDc4KSBmb3IgciBpbiBleGlz'
    'dGluZyk6cmFpc2UgUnVudGltZUVycm9yKCfQn9GA0LjQvtGA0LjRgtC10YLRiyDQvNCw0YDRiNGA0YPRgtC40LfQsNGG0LjQ'
    'uCDQuNGB0LrQu9GO0YfQtdC90LjQuSDQt9Cw0L3Rj9GC0Ysg0LTRgNGD0LPQvtC5INC/0YDQvtCz0YDQsNC80LzQvtC5Licp'
    'CiAgdHVubmVsLndyaXRlKG93bmVyc2hpcCxqc29uLmR1bXBzKHsndGFibGVzJzpbUEhZU0lDQUxfVEFCTEUsVlBOX1RBQkxF'
    'XX0pKQogIyBCdWlsZCBwaHlzaWNhbCBhbmQgVlBOLW9ubHkgdGFibGVzIGJlZm9yZSBhbGxvd2luZyBhbnkgbmV3IG1hcmtz'
    'LgogZm9yIHRhYmxlIGluIChQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEUpOgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0'
    'ZScsJ3JlcGxhY2UnLCd1bnJlYWNoYWJsZScsJ2RlZmF1bHQnLCdtZXRyaWMnLCczMjc2MCcsJ3RhYmxlJyx0YWJsZV0pCiBm'
    'b3IgbmV0d29yayBpbiBsYW4rWycxNjkuMjU0LjAuMC8xNicsJzIyNC4wLjAuMC80J106CiAgdHVubmVsLmNvbW1hbmQoWydp'
    'cCcsJ3JvdXRlJywncmVwbGFjZScsbmV0d29yaywnZGV2Jyxyb3V0ZVsnZGV2J10sJ3Njb3BlJywnbGluaycsJ3RhYmxlJyxQ'
    'SFlTSUNBTF9UQUJMRV0pCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ3ZpYScs'
    'cm91dGVbJ2dhdGV3YXknXSwnZGV2Jyxyb3V0ZVsnZGV2J10sJ21ldHJpYycsJzEwJywndGFibGUnLFBIWVNJQ0FMX1RBQkxF'
    'XSkKIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJywnMTcyLjI5LjI0Ny4y'
    'JywnZGV2Jyx0dW5uZWwuRlVMTF9IT1NULCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxWUE5fVEFCTEVdKQogZm9yIHByaW9yaXR5'
    'LG1hcmssdGFibGUgaW4gWyg3NixESVJFQ1QsUEhZU0lDQUxfVEFCTEUpLCg3NyxWUE4sVlBOX1RBQkxFKV06CiAgdHVubmVs'
    'LmNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScscHJpb3JpdHksJ2Z3bWFyaycsc3RyKG1hcmspLCdsb29r'
    'dXAnLHRhYmxlXSxjaGVjaz1GYWxzZSkKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5Jyxw'
    'cmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdKQogIyBSZXBsaWVzIHRvIGEgZm9yd2FyZGVkIGNv'
    'bnRhaW5lciByZXR1cm4gdGhyb3VnaCBpdHMgY29ubmVjdGVkIG1haW4gcm91dGUuCiB0dW5uZWwuY29tbWFuZChbJ2lwJywn'
    'cnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogdHVu'
    'bmVsLmNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzc4JywnaWlmJyxUVU4sJ2xvb2t1cCcsJ21haW4n'
    'XSkKICMgQSB0ZW1wb3JhcnkgY2xvc2VkIHN0YXRlIGlzIGFjY2VwdGFibGU7IGFuIHVuZ3VhcmRlZCBzdGF0ZSBpcyBub3Qu'
    'CiBvcy5yZXBsYWNlKHRtcCxjZmcpCiB0dW5uZWwud3JpdGUodHVubmVsLlJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykK'
    'IHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKIHN5bmNfd2F5ZHJvaWRfbmV0d29y'
    'ayhmb3JjZT1UcnVlKQogaW5zdGFsbCgpCiB0dW5uZWwuY29tbWFuZChbJ3N5c3RlbWN0bCcsJ3Jlc3RhcnQnLFNFUlZJQ0Vd'
    'KQogZm9yIF8gaW4gcmFuZ2UoODApOgogIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKTpicmVhawog'
    'IHRpbWUuc2xlZXAoLjEpCiBlbHNlOnJhaXNlIFJ1bnRpbWVFcnJvcign0J3QtSDRg9C00LDQu9C+0YHRjCDQt9Cw0L/Rg9GB'
    '0YLQuNGC0Ywg0L7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH0LXQvdC40LkuJykKIHR1bm5lbC5jb21tYW5kKFsn'
    'aXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywnZGV2JyxUVU4sJ21ldHJpYycsJzEwJywndGFibGUnLHR1bm5lbC5G'
    'VUxMX1RBQkxFXSkKIHR1bm5lbC5jbGVhcl9kbnNfbWFwcGluZ3MoKQogIyBFeHBsaWNpdGx5IHJlcXVlc3RlZCBETlMgZXhj'
    'ZXB0aW9ucyBuZWVkIHN0YWxlIHBvcnQtNTMgbWFwcGluZ3MgcmVtb3ZlZCB0b28uCiBmb3IgcHJvdG8gaW4gKCd1ZHAnLCd0'
    'Y3AnKToKICB0dW5uZWwuY29tbWFuZChbJ2Nvbm50cmFjaycsJy1EJywnLWYnLCdpcHY0JywnLXAnLHByb3RvLCctLWRwb3J0'
    'JywnNTMnLCctLXJlcGx5LXBvcnQtc3JjJyxzdHIoRE5TX1BPUlQpXSxjaGVjaz1GYWxzZSkKCgpkZWYgc3RvcChyZWxlYXNl'
    'PUZhbHNlKToKIHR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywnc3RvcCcsU0VSVklDRV0sY2hlY2s9RmFsc2UpCiBpZiBy'
    'ZWxlYXNlIGFuZCBQQVRILndpdGhfbmFtZSgncG9saWN5LW5ldHdvcmsuanNvbicpLmV4aXN0cygpOgogIHR1bm5lbC5jb21t'
    'YW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lpZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9'
    'RmFsc2UpCiAgZm9yIHByaW9yaXR5LG1hcmssdGFibGUgaW4gWyg3NixESVJFQ1QsUEhZU0lDQUxfVEFCTEUpLCg3NyxWUE4s'
    'VlBOX1RBQkxFKV06CiAgIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLHByaW9yaXR5LCdm'
    'd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0sY2hlY2s9RmFsc2UpCiAgIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdy'
    'b3V0ZScsJ2ZsdXNoJywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkKICBQQVRILndpdGhfbmFtZSgncG9saWN5LW5ldHdv'
    'cmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKZGVmIGNoYW5nZShhY3Rpb24sY2F0ZWdvcnk9JycsdmFsdWU9'
    'Jycsc3RhdGU9Tm9uZSk6CiBvbGQ9bG9hZCgpO3A9anNvbi5sb2Fkcyhqc29uLmR1bXBzKG9sZCkpCiBpZiBhY3Rpb249PSd3'
    'YXlkcm9pZCc6cFsnd2F5ZHJvaWRfZGlyZWN0J109Ym9vbChzdGF0ZSkKIGVsaWYgYWN0aW9uPT0nYmFzZSc6CiAgaWYgY2F0'
    'ZWdvcnkgbm90IGluIEJBU0Ugb3IgdmFsdWUgbm90IGluIHtlWydpZCddIGZvciBlIGluIEJBU0VbY2F0ZWdvcnldfTpyYWlz'
    'ZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QvtC1INCx0LDQt9C+0LLQvtC1INC/0YDQsNCy0LjQu9C+LicpCiAg'
    'a2V5PWNhdGVnb3J5Kyc6Jyt2YWx1ZQogIHBbJ2Rpc2FibGVkX2Jhc2UnXT1beCBmb3IgeCBpbiBwWydkaXNhYmxlZF9iYXNl'
    'J10gaWYgeCE9a2V5XQogIGlmIG5vdCBzdGF0ZTpwWydkaXNhYmxlZF9iYXNlJ10uYXBwZW5kKGtleSkKIGVsaWYgYWN0aW9u'
    'IGluICgnYWRkJywncmVtb3ZlJyk6CiAgaWYgY2F0ZWdvcnkgbm90IGluIENBVEVHT1JJRVM6cmFpc2UgVmFsdWVFcnJvcign'
    '0J3QtdC40LfQstC10YHRgtC90LDRjyDQutCw0YLQtdCz0L7RgNC40Y8uJykKICB2YWx1ZT1ub3JtYWxpemUoY2F0ZWdvcnks'
    'dmFsdWUpCiAgaWYgYWN0aW9uPT0nYWRkJyBhbmQgdmFsdWUgbm90IGluIHBbY2F0ZWdvcnldOnBbY2F0ZWdvcnldLmFwcGVu'
    'ZCh2YWx1ZSkKICBpZiBhY3Rpb249PSdyZW1vdmUnOnBbY2F0ZWdvcnldPVt4IGZvciB4IGluIHBbY2F0ZWdvcnldIGlmIHgh'
    'PXZhbHVlXQogZWxzZTpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QvtC1INC00LXQudGB0YLQstC40LUu'
    'JykKIGlmIHA9PW9sZDpyZXR1cm4gcHVibGljKCkKIHNhdmUocCkKIGlmIHR1bm5lbC5mdWxsX2d1YXJkX2FjdGl2ZSgpIGFu'
    'ZCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK3R1bm5lbC5GVUxMX0hPU1QpLmV4aXN0cygpOgogIHRyeTphcHBseSgpCiAgZXhj'
    'ZXB0IEV4Y2VwdGlvbjoKICAgc2F2ZShvbGQpCiAgIHRyeTphcHBseSgpCiAgIGV4Y2VwdCBFeGNlcHRpb246cGFzcwogICBy'
    'YWlzZQogcmV0dXJuIHB1YmxpYygpCgpkZWYgZW5zdXJlX3JvdXRlKCk6CiBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK1RV'
    'TikuZXhpc3RzKCk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCdkZXYnLFRV'
    'TiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZVTExfVEFCTEVdKQogZWxzZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3Bv'
    'bGljeV9lbmdpbmVfdW5hdmFpbGFibGUnKQo='
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
    'ZXJfbm90X3JlYWR5J30KUEFUSFM9eydydS11ZHAnLCdlZS11ZHAnLCdlZS10bHMnLCdlZS1ldmd0JywnZWUtZXZndC1ydScs'
    'Jyd9ClhGUk09eydYZnJtSW5FcnJvcicsJ1hmcm1Jbk5vU3RhdGVzJywnWGZybUluU3RhdGVQcm90b0Vycm9yJywnWGZybUlu'
    'U3RhdGVTZXFFcnJvcicsJ1hmcm1JblN0YXRlRXhwaXJlZCcsJ1hmcm1JblN0YXRlTWlzbWF0Y2gnLCdYZnJtSW5UbXBsTWlz'
    'bWF0Y2gnLCdYZnJtSW5Ob1BvbHMnLCdYZnJtSW5Qb2xCbG9jaycsJ1hmcm1PdXRFcnJvcicsJ1hmcm1PdXROb1N0YXRlcycs'
    'J1hmcm1PdXRTdGF0ZUV4cGlyZWQnLCdYZnJtT3V0UG9sQmxvY2snfQpOVU1CRVJTPVhGUk18eydkb3dubG9hZF9tYnBzJywn'
    'dXBsb2FkX21icHMnLCdsYXRlbmN5X21zJywnc2NvcmUnLCdsb3NzZXMnLCdzYW1wbGVfYnl0ZXMnLCdyeF9ieXRlcycsJ3R4'
    'X2J5dGVzJywncnhfcGFja2V0cycsJ3R4X3BhY2tldHMnLCdyeF9lcnJvcnMnLCd0eF9lcnJvcnMnLCdyeF9kcm9wcGVkJywn'
    'dHhfZHJvcHBlZCd9CmRlZiBudW1iZXIodik6CiBpZiB0eXBlKHYpIG5vdCBpbiAoaW50LGZsb2F0KSBvciBub3QgbWF0aC5p'
    'c2Zpbml0ZSh2KSBvciBub3QgMDw9djw9MioqNjM6cmFpc2UgVmFsdWVFcnJvcignbWV0cmljJykKIHJldHVybiByb3VuZCh2'
    'LDMpIGlmIGlzaW5zdGFuY2UodixmbG9hdCkgZWxzZSB2CgpkZWYgY2xlYW5fYnVuZGxlKGJvZHkpOgogaWYgbm90IGlzaW5z'
    'dGFuY2UoYm9keSxkaWN0KSBvciBib2R5LmdldCgnc2NoZW1hJykhPTEgb3IgYm9keS5nZXQoJ2V2ZW50JykhPSdzdXBwb3J0'
    'X2J1bmRsZScgb3IgYm9keS5nZXQoJ2NvbnNlbnQnKSBpcyBub3QgVHJ1ZTpyYWlzZSBWYWx1ZUVycm9yKCdjb25zZW50JykK'
    'IGlmIG5vdCByZS5mdWxsbWF0Y2goJ1thLWYwLTldezMyfScsc3RyKGJvZHkuZ2V0KCdyZXBvcnRfaWQnLCcnKSkpOnJhaXNl'
    'IFZhbHVlRXJyb3IoJ3JlcG9ydF9pZCcpCiB2ZXJzaW9uPWJvZHkuZ2V0KCdtYW5hZ2VyJywnJykKIGlmIG5vdCBpc2luc3Rh'
    'bmNlKHZlcnNpb24sc3RyKSBvciBub3QgcmUuZnVsbG1hdGNoKHInXGQrXC5cZCtcLlxkKycsdmVyc2lvbik6cmFpc2UgVmFs'
    'dWVFcnJvcigndmVyc2lvbicpCiBpZiBib2R5LmdldCgnYXJjaGl0ZWN0dXJlJykgbm90IGluIHsneDg2XzY0JywnYWFyY2g2'
    'NCcsJ3Jpc2N2NjQnLCdvdGhlcid9OnJhaXNlIFZhbHVlRXJyb3IoJ2FyY2hpdGVjdHVyZScpCiBpZiBib2R5LmdldCgnc3lz'
    'dGVtJykgbm90IGluIHsnYXJjaCcsJ2VuZGVhdm91cm9zJywnZmVkb3JhJywnc3RlYW1vcycsJ2RlYmlhbicsJ3VidW50dScs'
    'J290aGVyJ306cmFpc2UgVmFsdWVFcnJvcignc3lzdGVtJykKIHJlc3VsdD17azpib2R5W2tdIGZvciBrIGluICgnc2NoZW1h'
    'JywnZXZlbnQnLCdjb25zZW50JywncmVwb3J0X2lkJywnbWFuYWdlcicsJ2FyY2hpdGVjdHVyZScsJ3N5c3RlbScpfQogcmVz'
    'dWx0Wyd0aW1lJ109bnVtYmVyKGJvZHkuZ2V0KCd0aW1lJywwKSkKIGV2ZW50cz1ib2R5LmdldCgnZXZlbnRzJyxbXSkKIGlm'
    'IG5vdCBpc2luc3RhbmNlKGV2ZW50cyxsaXN0KSBvciBsZW4oZXZlbnRzKT4xMjg6cmFpc2UgVmFsdWVFcnJvcignZXZlbnRz'
    'JykKIHJlc3VsdFsnZXZlbnRzJ109W10KIGZvciBpdGVtIGluIGV2ZW50czoKICBpZiBub3QgaXNpbnN0YW5jZShpdGVtLGRp'
    'Y3QpIG9yIGl0ZW0uZ2V0KCdwaGFzZScpIG5vdCBpbiBQSEFTRVMgb3IgaXRlbS5nZXQoJ2NvZGUnLCcnKSBub3QgaW4gQ09E'
    'RVMgb3IgaXRlbS5nZXQoJ3BhdGgnLCcnKSBub3QgaW4gUEFUSFM6cmFpc2UgVmFsdWVFcnJvcignZXZlbnQnKQogIHJlc3Vs'
    'dFsnZXZlbnRzJ10uYXBwZW5kKHsndGltZSc6bnVtYmVyKGl0ZW1bJ3RpbWUnXSksJ3BoYXNlJzppdGVtWydwaGFzZSddLCdj'
    'b2RlJzppdGVtLmdldCgnY29kZScsJycpLCdwYXRoJzppdGVtLmdldCgncGF0aCcsJycpLCdhY3RpdmUnOml0ZW0uZ2V0KCdh'
    'Y3RpdmUnKSBpcyBUcnVlfSkKIHN0YXRlPWJvZHkuZ2V0KCdzdGF0ZScse30pCiBpZiBub3QgaXNpbnN0YW5jZShzdGF0ZSxk'
    'aWN0KTpyYWlzZSBWYWx1ZUVycm9yKCdzdGF0ZScpCiByZXN1bHRbJ3N0YXRlJ109e2s6c3RhdGUuZ2V0KGspIGlzIFRydWUg'
    'Zm9yIGsgaW4gKCdhY3RpdmUnLCdndWFyZCcsJ25hbWVzcGFjZScsJ2Ruc19mYWxsYmFjaycpfQogcmVzdWx0WydwYXRocydd'
    'PXt9CiBwYXRocz1ib2R5LmdldCgncGF0aHMnLHt9KQogaWYgbm90IGlzaW5zdGFuY2UocGF0aHMsZGljdCkgb3IgbGVuKHBh'
    'dGhzKT5sZW4oUEFUSFMpLTE6cmFpc2UgVmFsdWVFcnJvcigncGF0aHMnKQogZm9yIG5hbWUsdmFsdWVzIGluIHBhdGhzLml0'
    'ZW1zKCk6CiAgaWYgbmFtZSBub3QgaW4gUEFUSFMteycnfTpyYWlzZSBWYWx1ZUVycm9yKCdwYXRoJykKICBpZiBub3QgaXNp'
    'bnN0YW5jZSh2YWx1ZXMsZGljdCk6cmFpc2UgVmFsdWVFcnJvcigncGF0aCcpCiAgcmVzdWx0WydwYXRocyddW25hbWVdPXtr'
    'Om51bWJlcih2KSBmb3Igayx2IGluIHZhbHVlcy5pdGVtcygpIGlmIGsgaW4gTlVNQkVSU30KIGNvdW50ZXJzPWJvZHkuZ2V0'
    'KCdjb3VudGVycycse30pCiBpZiBub3QgaXNpbnN0YW5jZShjb3VudGVycyxkaWN0KTpyYWlzZSBWYWx1ZUVycm9yKCdjb3Vu'
    'dGVycycpCiByZXN1bHRbJ2NvdW50ZXJzJ109e2s6bnVtYmVyKHYpIGZvciBrLHYgaW4gY291bnRlcnMuaXRlbXMoKSBpZiBr'
    'IGluIE5VTUJFUlN9CiByZXR1cm4gcmVzdWx0CgpkZWYgcmVjb3JkKHJvb3Qsd3JpdGUsZGF0YSk6CiBldmVudD17J3RpbWUn'
    'OmludCh0aW1lLnRpbWUoKSksJ3BoYXNlJzpkYXRhLmdldCgncGhhc2UnKSBpZiBkYXRhLmdldCgncGhhc2UnKSBpbiBQSEFT'
    'RVMgZWxzZSAnZmFpbGVkJywKICAgICAgICAnY29kZSc6ZGF0YS5nZXQoJ2Vycm9yX2NvZGUnLCcnKSBpZiBkYXRhLmdldCgn'
    'ZXJyb3JfY29kZScsJycpIGluIENPREVTIGVsc2UgJ290aGVyJywKICAgICAgICAncGF0aCc6ZGF0YS5nZXQoJ3BhdGgnLCcn'
    'KSBpZiBkYXRhLmdldCgncGF0aCcsJycpIGluIFBBVEhTIGVsc2UgJycsICdhY3RpdmUnOmRhdGEuZ2V0KCdhY3RpdmUnKSBp'
    'cyBUcnVlfQogcGF0aD1yb290LydldmVudHMuanNvbicKIHRyeTpldmVudHM9anNvbi5sb2FkcyhwYXRoLnJlYWRfdGV4dCgp'
    'KQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOmV2ZW50cz1bXQogaWYgbm90IGV2ZW50cyBvciBhbnkoZXZlbnRzWy0x'
    'XS5nZXQoaykhPWV2ZW50W2tdIGZvciBrIGluICgncGhhc2UnLCdjb2RlJywncGF0aCcsJ2FjdGl2ZScpKToKICB3cml0ZShw'
    'YXRoLGpzb24uZHVtcHMoKGV2ZW50cytbZXZlbnRdKVstMTI4Ol0pKQoKZGVmIHByZXBhcmUodHVubmVsLHZlcnNpb24pOgog'
    'dHJ5OmV2ZW50cz1qc29uLmxvYWRzKCh0dW5uZWwuUk9PVC8nZXZlbnRzLmpzb24nKS5yZWFkX3RleHQoKSkKIGV4Y2VwdCAo'
    'T1NFcnJvcixWYWx1ZUVycm9yKTpldmVudHM9W10KIHRyeTpwYXRocz1qc29uLmxvYWRzKCh0dW5uZWwuUk9PVC8ncmFua2lu'
    'Zy5qc29uJykucmVhZF90ZXh0KCkpWydlbnRyaWVzJ10KIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yKTpw'
    'YXRocz17fQogdHJ5Om5ldHdvcms9anNvbi5sb2Fkcyh0dW5uZWwuZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogZXhjZXB0'
    'IChPU0Vycm9yLFZhbHVlRXJyb3IpOm5ldHdvcms9e30KIHRyeTpzeXN0ZW09cGxhdGZvcm0uZnJlZWRlc2t0b3Bfb3NfcmVs'
    'ZWFzZSgpLmdldCgnSUQnLCdvdGhlcicpCiBleGNlcHQgT1NFcnJvcjpzeXN0ZW09J290aGVyJwogaWYgc3lzdGVtIG5vdCBp'
    'biB7J2FyY2gnLCdlbmRlYXZvdXJvcycsJ2ZlZG9yYScsJ3N0ZWFtb3MnLCdkZWJpYW4nLCd1YnVudHUnfTpzeXN0ZW09J290'
    'aGVyJwogYXJjaD1wbGF0Zm9ybS5tYWNoaW5lKCk7YXJjaD1hcmNoIGlmIGFyY2ggaW4geyd4ODZfNjQnLCdhYXJjaDY0Jywn'
    'cmlzY3Y2NCd9IGVsc2UgJ290aGVyJwogY291bnRlcnM9e30KICMgT25seSB0aGUgVlBOJ3Mgb3duIGludGVyZmFjZSwgbm8g'
    'cHJvY2VzcyBsaXN0IG9yIHJlbW90ZSBhZGRyZXNzZXMuCiBzdGF0cz1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL3R1bm5lbC5G'
    'VUxMX0hPU1QvJ3N0YXRpc3RpY3MnCiBmb3Iga2V5IGluICgncnhfYnl0ZXMnLCd0eF9ieXRlcycsJ3J4X3BhY2tldHMnLCd0'
    'eF9wYWNrZXRzJywncnhfZXJyb3JzJywndHhfZXJyb3JzJywncnhfZHJvcHBlZCcsJ3R4X2Ryb3BwZWQnKToKICB0cnk6Y291'
    'bnRlcnNba2V5XT1pbnQoKHN0YXRzL2tleSkucmVhZF90ZXh0KCkpCiAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnBh'
    'c3MKIGlmIFBhdGgoJy9ydW4vbmV0bnMnLHR1bm5lbC5OUykuZXhpc3RzKCk6CiAgdHJ5OgogICByZXN1bHQ9dHVubmVsLmlu'
    'c2lkZShbJ2NhdCcsJy9wcm9jL25ldC94ZnJtX3N0YXQnXSxjaGVjaz1GYWxzZSx0aW1lb3V0PTIpCiAgIGZvciBsaW5lIGlu'
    'IHJlc3VsdC5zdGRvdXQuc3BsaXRsaW5lcygpOgogICAga2V5LHZhbHVlPWxpbmUuc3BsaXQoKQogICAgaWYga2V5IGluIFhG'
    'Uk06Y291bnRlcnNba2V5XT1pbnQodmFsdWUpCiAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1'
    'YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOnBhc3MKIHJlcG9ydD1jbGVhbl9idW5kbGUoeydzY2hlbWEnOjEsJ2V2ZW50Jzon'
    'c3VwcG9ydF9idW5kbGUnLCdjb25zZW50JzpUcnVlLCdyZXBvcnRfaWQnOnNlY3JldHMudG9rZW5faGV4KDE2KSwKICAgJ21h'
    'bmFnZXInOnZlcnNpb24sJ3RpbWUnOmludCh0aW1lLnRpbWUoKSksJ2FyY2hpdGVjdHVyZSc6YXJjaCwnc3lzdGVtJzpzeXN0'
    'ZW0sJ2V2ZW50cyc6ZXZlbnRzLAogICAncGF0aHMnOnBhdGhzLCdjb3VudGVycyc6Y291bnRlcnMsJ3N0YXRlJzp7J2FjdGl2'
    'ZSc6dHVubmVsLnNhdmVkKCkuZ2V0KCdhY3RpdmUnLEZhbHNlKSwKICAgICdndWFyZCc6dHVubmVsLmZ1bGxfZ3VhcmRfYWN0'
    'aXZlKCksJ25hbWVzcGFjZSc6UGF0aCgnL3J1bi9uZXRucycsdHVubmVsLk5TKS5leGlzdHMoKSwnZG5zX2ZhbGxiYWNrJzpu'
    'ZXR3b3JrLmdldCgnZG5zX2ZhbGxiYWNrJyxGYWxzZSl9fSkKICMgUHJlcGFyaW5nIGEgcHJldmlldyBpcyBuZXZlciBwZXJt'
    'aXNzaW9uIHRvIHRyYW5zbWl0IGl0LgogcmVwb3J0Wydjb25zZW50J109RmFsc2UKIHR1bm5lbC53cml0ZSh0dW5uZWwuUk9P'
    'VC8nc3VwcG9ydC1wcmV2aWV3Lmpzb24nLGpzb24uZHVtcHMocmVwb3J0LGVuc3VyZV9hc2NpaT1GYWxzZSxpbmRlbnQ9Mikp'
    'CiByZXR1cm4gcmVwb3J0CgpkZWYgc2VuZCh0dW5uZWwscmVwb3J0X2lkLGNvbnNlbnQpOgogaWYgY29uc2VudCBpcyBub3Qg'
    'VHJ1ZTpyYWlzZSBWYWx1ZUVycm9yKCfQlNC70Y8g0L7RgtC/0YDQsNCy0LrQuCDRgtGA0LXQsdGD0LXRgtGB0Y8g0Y/QstC9'
    '0L7QtSDRgdC+0LPQu9Cw0YHQuNC1LicpCiByZXBvcnQ9anNvbi5sb2FkcygodHVubmVsLlJPT1QvJ3N1cHBvcnQtcHJldmll'
    'dy5qc29uJykucmVhZF90ZXh0KCkpCiBpZiByZXBvcnQuZ2V0KCdyZXBvcnRfaWQnKSE9cmVwb3J0X2lkIG9yIHRpbWUudGlt'
    'ZSgpLXJlcG9ydC5nZXQoJ3RpbWUnLDApPjg2NDAwOnJhaXNlIFZhbHVlRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC/0L7QtNCz'
    '0L7RgtC+0LLRjNGC0LUg0L3QvtCy0YvQuSDQvtGC0YfRkdGCLicpCiByZXBvcnRbJ2NvbnNlbnQnXT1UcnVlO3JlcG9ydD1j'
    'bGVhbl9idW5kbGUocmVwb3J0KQogIyBOZXZlciBpbnN0YWxsIGEgYnlwYXNzIGFyb3VuZCBhbiBhY3RpdmUga2lsbCBzd2l0'
    'Y2ggdG8gdXBsb2FkIGEgcmVwb3J0LgogaWYgUGF0aCgnL3J1bi9uZXRucycsdHVubmVsLk5TKS5leGlzdHMoKSBhbmQgdHVu'
    'bmVsLmluc3RhbGxlZCgpOgogIHRyeTpzZWxlY3RlZD1qc29uLmxvYWRzKCh0dW5uZWwuUk9PVC8nYWN0aXZlLXBhdGguanNv'
    'bicpLnJlYWRfdGV4dCgpKVsnaWQnXQogIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yKTpzZWxlY3RlZD0n'
    'cnUtdWRwJwogIGNhbmRpZGF0ZT1uZXh0KHggZm9yIHggaW4gdHVubmVsLkNBTkRJREFURVMgaWYgeFsnaWQnXT09c2VsZWN0'
    'ZWQpCiAgd2l0aCB0dW5uZWwubmFtZXNwYWNlKCk6cmVwbHk9dHVubmVsLnRsc19yZXF1ZXN0KHR1bm5lbC5IRUFMVEgsJy9y'
    'ZXBvcnQnLHJlcG9ydCxjbGllbnQ9VHJ1ZSxpZGVudGl0eT1jYW5kaWRhdGVbJ2lkZW50aXR5J10pCiBlbGlmIG5vdCB0dW5u'
    'ZWwuZnVsbF9ndWFyZF9hY3RpdmUoKToKICByZXBseT10dW5uZWwudGxzX3JlcXVlc3QodHVubmVsLlNFUlZFUiwnL3JlcG9y'
    'dCcscmVwb3J0LGNsaWVudD1UcnVlKQogZWxzZTpyYWlzZSBSdW50aW1lRXJyb3IoJ9CX0LDRidC40YLQsCDQsdC70L7QutC4'
    '0YDRg9C10YIg0YHQtdGC0YwuINCe0YLRh9GR0YIg0YHQvtGF0YDQsNC90ZHQvTsg0L7RgtC/0YDQsNCy0YzRgtC1INC/0L7R'
    'gdC70LUg0LLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90LjRjyDQuNC70Lgg0Y/QstC90L7Qs9C+INC+0YLQutC70Y7Rh9C10L3Q'
    'uNGPIFZQTi4nKQogaWYgcmVwbHkuZ2V0KCdhY2NlcHRlZCcpIGlzIG5vdCBUcnVlIG9yIHJlcGx5LmdldCgncmVwb3J0X2lk'
    'JykhPXJlcG9ydF9pZDpyYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0LXRgNCy0LXRgCDQvdC1INC/0L7QtNGC0LLQtdGA0LTQuNC7'
    'INC/0L7Qu9GD0YfQtdC90LjQtSDQvtGC0YfRkdGC0LAuJykKIHJldHVybiByZXBvcnRfaWQK'
)
PATH_RANKING_PY_B64 = (
    'IiIiQSBtZWFzdXJlZCwgcGVyc2lzdGVudCBvcmRlcjsgdHJhbnNpZW50IGZhaWx1cmVzIG5ldmVyIGRpc3F1YWxpZnkgYSBy'
    'b3V0ZS4iIiIKaW1wb3J0IGpzb24sbWF0aCxvcyx0aW1lCmZyb20gcGF0aGxpYiBpbXBvcnQgUGF0aApjbGFzcyBSYW5raW5n'
    'OgogZGVmIF9faW5pdF9fKHNlbGYscGF0aCxpZHMpOnNlbGYucGF0aD1QYXRoKHBhdGgpO3NlbGYuaWRzPXR1cGxlKGlkcyk7'
    'c2VsZi5kYXRhPU5vbmUKIGRlZiBsb2FkKHNlbGYpOgogIHRyeToKICAgdmFsdWU9anNvbi5sb2FkcyhzZWxmLnBhdGgucmVh'
    'ZF90ZXh0KCkpCiAgIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVlLGRpY3QpOnJldHVybiBGYWxzZQogICBpZiB2YWx1ZS5nZXQo'
    'J3NjaGVtYScpIT0yIG9yIHNldCh2YWx1ZS5nZXQoJ2VudHJpZXMnLHt9KSkhPXNldChzZWxmLmlkcyk6cmV0dXJuIEZhbHNl'
    'CiAgIGlmIHNvcnRlZCh2YWx1ZS5nZXQoJ29yZGVyJyxbXSkpIT1zb3J0ZWQoc2VsZi5pZHMpOnJldHVybiBGYWxzZQogICBm'
    'b3IgZSBpbiB2YWx1ZVsnZW50cmllcyddLnZhbHVlcygpOgogICAgaWYgbm90IGlzaW5zdGFuY2UoZSxkaWN0KTpyZXR1cm4g'
    'RmFsc2UKICAgIGZvciBrZXkgaW4gKCdzY29yZScsJ2Rvd25sb2FkX21icHMnLCd1cGxvYWRfbWJwcycsJ2xhdGVuY3lfbXMn'
    'KToKICAgICB2PWUuZ2V0KGtleSwwKQogICAgIGlmIHR5cGUodikgbm90IGluIChpbnQsZmxvYXQpIG9yIG5vdCBtYXRoLmlz'
    'ZmluaXRlKHYpIG9yIHY8MDpyZXR1cm4gRmFsc2UKICAgc2VsZi5kYXRhPXZhbHVlO3JldHVybiBUcnVlCiAgZXhjZXB0IChP'
    'U0Vycm9yLFZhbHVlRXJyb3IsVHlwZUVycm9yLEF0dHJpYnV0ZUVycm9yKTpyZXR1cm4gRmFsc2UKIGRlZiBzYXZlKHNlbGYp'
    'OgogIHNlbGYucGF0aC5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgdG1wPXNlbGYucGF0aC53'
    'aXRoX3N1ZmZpeCgnLm5ldycpO2ZkPW9zLm9wZW4odG1wLG9zLk9fV1JPTkxZfG9zLk9fQ1JFQVR8b3MuT19UUlVOQ3xvcy5P'
    'X05PRk9MTE9XLDBvNjAwKQogIHdpdGggb3MuZmRvcGVuKGZkLCd3JykgYXMgZjpqc29uLmR1bXAoc2VsZi5kYXRhLGYsc2Vw'
    'YXJhdG9ycz0oJywnLCc6JykpCiAgb3MucmVwbGFjZSh0bXAsc2VsZi5wYXRoKQogZGVmIGJ1aWxkKHNlbGYsbWVhc3VyZW1l'
    'bnRzKToKICBlbnRyaWVzPXt9CiAgZm9yIGlkZW50aXR5IGluIHNlbGYuaWRzOgogICBtPW1lYXN1cmVtZW50c1tpZGVudGl0'
    'eV07b2s9bS5nZXQoJ29rJyxGYWxzZSkKICAgZG93bj1tYXgoMCxmbG9hdChtLmdldCgnZG93bmxvYWRfbWJwcycsMCkpKTt1'
    'cD1tYXgoMCxmbG9hdChtLmdldCgndXBsb2FkX21icHMnLDApKSkKICAgc2NvcmU9KDIqZG93bip1cC8oZG93bit1cCkgaWYg'
    'ZG93bit1cCBlbHNlIDEpLygxK21heCgwLGZsb2F0KG0uZ2V0KCdsYXRlbmN5X21zJywwKSkpLzIwMCkgaWYgb2sgZWxzZSAw'
    'CiAgIGVudHJpZXNbaWRlbnRpdHldPXtrOnYgZm9yIGssdiBpbiBtLml0ZW1zKCkgaWYgayBub3QgaW4gKCdsb3NzZXMnLCdy'
    'ZWFzb24nLCdsYXN0X2ZhaWx1cmUnKX0KICAgZW50cmllc1tpZGVudGl0eV1bJ3Njb3JlJ109cm91bmQoc2NvcmUsMykKICBz'
    'ZWxmLmRhdGE9eydzY2hlbWEnOjIsJ2NyZWF0ZWQnOmludCh0aW1lLnRpbWUoKSksJ2VudHJpZXMnOmVudHJpZXMsCiAgICAg'
    'ICAgICAgICAnb3JkZXInOnNvcnRlZChzZWxmLmlkcyxrZXk9bGFtYmRhIHg6ZW50cmllc1t4XVsnc2NvcmUnXSxyZXZlcnNl'
    'PVRydWUpfQogIHNlbGYuc2F2ZSgpCiBkZWYgY2FuZGlkYXRlcyhzZWxmKTpyZXR1cm4gbGlzdChzZWxmLmRhdGFbJ29yZGVy'
    'J10pCiBkZWYgYm9vdHN0cmFwKHNlbGYpOgogIHNlbGYuZGF0YT17J3NjaGVtYSc6MiwnY3JlYXRlZCc6MCwnZW50cmllcyc6'
    'e2lkZW50aXR5Onsnc2NvcmUnOjB9IGZvciBpZGVudGl0eSBpbiBzZWxmLmlkc30sJ29yZGVyJzpsaXN0KHNlbGYuaWRzKX0K'
    'IGRlZiBuZXh0X2FmdGVyKHNlbGYsaWRlbnRpdHkpOgogIG9yZGVyPXNlbGYuZGF0YVsnb3JkZXInXTtwb3M9b3JkZXIuaW5k'
    'ZXgoaWRlbnRpdHkpKzEKICByZXR1cm4gb3JkZXJbcG9zXSBpZiBwb3M8bGVuKG9yZGVyKSBlbHNlIE5vbmUK'
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

vpn_tunnel=embedded('vpn_tunnel',VPN_TUNNEL_PY_B64)
policy=embedded('network_policy',NETWORK_POLICY_PY_B64)
class ManagerAPI:
 def __getattr__(self,name):return globals()[name]
policy.api=ManagerAPI()
policy.tunnel=vpn_tunnel
vpn_tunnel.policy=policy
vpn_tunnel.support_api=embedded('support_reports',SUPPORT_REPORTS_PY_B64)
vpn_tunnel.rank_api=embedded('path_ranking',PATH_RANKING_PY_B64)
vpn_tunnel.tls_api=embedded('tls_transport',TLS_TRANSPORT_PY_B64)

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

def sync_system_files(*, install_policy=True):
 pathlib.Path('/var/lib/vpn-manager').mkdir(parents=True,exist_ok=True)
 os.chown('/var/lib/vpn-manager',0,0);os.chmod('/var/lib/vpn-manager',0o755)
 for filename,value in [('/usr/local/bin/vpn',WRAPPER_TEXT),('/usr/local/bin/evgenium-network',GUI_WRAPPER_TEXT)]:
  pathlib.Path(filename).write_text(value);os.chmod(filename,0o755)
 admin=pathlib.Path('/usr/local/sbin/vpn-manager-admin')
 temp=admin.with_name(admin.name+'.new');temp.unlink(missing_ok=True)
 temp.symlink_to(CURRENT/'vpnadmin.py');os.replace(temp,admin)
 vpn_tunnel.migrate_unit_modes()
 if install_policy:policy.install()

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
ROLLBACK_PENDING=pathlib.Path('/var/lib/vpn-manager/rollback-on-disconnect')

def disconnect_vpn():
 vpn_tunnel.disconnect()
 if ROLLBACK_PENDING.is_file():
  requested=ROLLBACK_PENDING.read_text()
  if PREVIOUS.exists() and str(PREVIOUS.resolve())==requested:
   manager_rollback()
   return
  # A newer update changed the rollback target. Do not select a different release.
  ROLLBACK_PENDING.unlink()
 vpn_tunnel.finish_name_transition()

def finish_installation(settings, *, reconnect=True):
 """Repeatable finalization, including entry from an unmodified 0.2.x updater.

 Refresh entrypoints first: a failed dependency download must not strand users
 with the previous shell wrapper and GUI pointing at a newer backend.
 """
 pending=INSTALL_PENDING.exists()
 INSTALL_PENDING.parent.mkdir(parents=True,exist_ok=True)
 INSTALL_PENDING.write_text(MANAGER_VERSION+'\n');INSTALL_PENDING.chmod(0o600)
 try:
  vpn_tunnel.finish_name_transition()
  live=vpn_tunnel.layout_in_use(vpn_tunnel.LAYOUT)
  if live:sync_system_files(install_policy=False)
  else:sync_system_files()
  _install_desktop_integration(settings, widget=_widget_package_dir(settings).exists(), force_cache=False)
  if live:
   # The worker may still be running the previous release. Keep its credentials,
   # firewall, policy process and resolver intact, including a retained kill switch.
   has_token=vpn_tunnel.token_status()['has_token']
  else:
   policy.migration(settings)
   vpn_tunnel.ensure_dependencies();ensure_gui_dependencies();core_update(settings)
   was_active=run(['systemctl','is-active','--quiet','vpn-xray.service'],check=False,capture=True).returncode==0
   retire_legacy(settings)
   has_token=vpn_tunnel.token_status()['has_token']
   if has_token:vpn_tunnel.sync_device_name()
   if was_active and has_token and (reconnect or pending):vpn_tunnel.connect(repair=True)
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
 if old_active and not vpn_tunnel.full_guard_active():
  # An active legacy installation must not acquire a direct window during migration.
  vpn_tunnel.write(vpn_tunnel.full_state(),json.dumps({'active':False,'migration_only':True}))
  rules=vpn_tunnel.full_firewall()
  run(['nft','-c','-f','-'],input_text=rules,capture=True)
  vpn_tunnel.persist_guard(rules)
  run(['nft','-f','-'],input_text=rules,capture=True)
  vpn_tunnel.stage('off','Для подключения нужен клиентский токен. Защита сохранена; отключение VPN вернёт обычную сеть.',0,active=False)
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
 st=vpn_tunnel.status()
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
 if action=='token-save':vpn_tunnel.save_token(str(data.get('token','')))
 elif action=='report-preview':print(json.dumps(vpn_tunnel.support_api.prepare(vpn_tunnel,MANAGER_VERSION),ensure_ascii=False))
 elif action=='report-send':print('Отчёт принят: '+vpn_tunnel.support_api.send(vpn_tunnel,data.get('report_id'),data.get('consent')))
 elif action=='device-name':vpn_tunnel.sync_device_name(str(data.get('name','')))
 elif action in ('connect','repair'):vpn_tunnel.connect(repair=action=='repair')
 elif action=='route':
  vpn_tunnel.select_route(str(data.get('value','auto')))
  if vpn_tunnel.status().get('running'):vpn_tunnel.connect(restart=True)
 elif action=='disconnect':disconnect_vpn()
 elif action=='update':manager_update_manifest(settings,settings['manager_manifest_url'])
 elif action in ('add','remove','base','waydroid'):
  if action in ('base','waydroid') and not isinstance(data.get('enabled'),bool):fail('Ожидался переключатель.')
  policy.change(action,str(data.get('category','')),str(data.get('value','')),data.get('enabled'))
 else:fail('Неизвестное действие.')

def operation_requires_lock(args):
 return args.cmd not in (None,'status','version','logs','rules','watch','internal-waydroid-watch','internal-vpn-tunnel','internal-vpn-tunnel-cleanup','internal-tls-client','internal-vpn-pause-main') and not (args.cmd=='ui' and args.ui_cmd in ('state','running'))

def self_test():
 assert re.fullmatch(r'\d+\.\d+\.\d+',MANAGER_VERSION)
 assert policy.config(policy.defaults())['outbounds'][0]['protocol']=='freedom'
 for source in (STANDALONE_GUI_PY_B64,VPN_TUNNEL_PY_B64,NETWORK_POLICY_PY_B64,SUPPORT_REPORTS_PY_B64,PATH_RANKING_PY_B64,TLS_TRANSPORT_PY_B64):compile(base64.b64decode(source),'embedded','exec')
 assert 'VLESS' not in base64.b64decode(STANDALONE_GUI_QML_B64).decode()
 print('Evgenium token VPN self-test OK')

def terminal_status(st=None,check_ip=False):
 st=st or status_data();t=st['tunnel'];p=st['policy']
 print('Evgenium '+MANAGER_VERSION)
 print('Состояние: '+('ПОДКЛЮЧЕНО' if st['active'] else 'ЗАБЛОКИРОВАНО' if st['guard'] else 'ВЫКЛЮЧЕНО'))
 print('Маршрут: '+next((x['label'] for x in vpn_tunnel.CANDIDATES if x['id']==st['tunnel'].get('path')), 'автоматический выбор → Эстония'))
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
 argv=list(sys.argv[1:] if argv is None else argv)
 # A running worker or an existing systemd unit may invoke its original command
 # during an upgrade. Only the matching installation can service these callbacks.
 callbacks={vpn_tunnel.LEGACY.command_prefix+suffix:'internal-vpn'+suffix for suffix in ('-tunnel','-tunnel-cleanup','-pause-main')}
 legacy_callback=bool(argv and argv[0] in callbacks)
 if legacy_callback:argv[0]=callbacks[argv[0]]
 p=argparse.ArgumentParser(prog='vpn',description='Evgenium: VPN и прямые исключения без графического интерфейса')
 p.add_argument('--self-test',action='store_true')
 sub=p.add_subparsers(dest='cmd')
 for name in ('on','repair','toggle'):
  a=sub.add_parser(name,help={'on':'Подключить и показать этапы','repair':'Восстановить соединение','toggle':'Переключить VPN'}[name]);a.add_argument('--no-wait',action='store_true',help='Запустить в фоне')
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-waydroid-watch','internal-vpn-tunnel','internal-vpn-tunnel-cleanup','internal-tls-client','internal-vpn-pause-main','manager-rollback'):sub.add_parser(name)
 pst=sub.add_parser('status',help='Состояние, защита и исключения');pst.add_argument('--json',action='store_true');pst.add_argument('--ip',action='store_true',help='Проверить внешний IP именно через VPN')
 route=sub.add_parser('route',help='Выбор туннеля: auto или идентификатор');route.add_argument('value',nargs='?',default='list')
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
  vpn_tunnel.select_installed_layout()
  if cmd in callbacks.values() and (vpn_tunnel.transition_layouts() or legacy_callback!=(vpn_tunnel.LAYOUT==vpn_tunnel.LEGACY)):return 0
  if cmd in ('on','repair','token') or (cmd=='ui' and args.ui_cmd=='action') or cmd=='toggle':
   if not ROLLBACK_PENDING.exists():vpn_tunnel.finish_name_transition()
  if cmd=='internal-waydroid-watch':policy.watch_waydroid()
  elif cmd=='internal-vpn-tunnel':vpn_tunnel.worker()
  elif cmd=='internal-vpn-tunnel-cleanup':vpn_tunnel.cleanup()
  elif cmd=='internal-tls-client':
   selected=json.loads((vpn_tunnel.ROOT/'active-path.json').read_text())
   candidate=next(x for x in vpn_tunnel.CANDIDATES if x['id']==selected['id'])
   vpn_tunnel.tls_api.client(vpn_tunnel.ROOT,candidate['address'],candidate['identity'])
  elif cmd=='internal-vpn-pause-main':retire_legacy(settings)
  elif cmd in ('on','repair'):
   if cmd=='repair' or not status_data()['active']:vpn_tunnel.connect(repair=cmd=='repair')
   wait=not args.no_wait
  elif cmd=='off':disconnect_vpn()
  elif cmd=='toggle':
   if vpn_tunnel.status().get('running'):disconnect_vpn()
   else:vpn_tunnel.connect();wait=not args.no_wait
  elif cmd=='route':
   if args.value!='list':
    vpn_tunnel.select_route(args.value)
    if vpn_tunnel.status().get('running'):vpn_tunnel.connect(restart=True)
   routes=vpn_tunnel.route_choices()
   print('Выбран: '+routes['selected']);print('auto  Автоматически · сохранённый порядок')
   for c in routes['choices']:print(c['id']+'  '+c['label'])
  elif cmd=='device':
   if args.operation=='name' and not args.name:raise ValueError('Укажите имя: vpn device name \"Мой ноутбук\"')
   d=vpn_tunnel.device_status() if args.operation=='show' else vpn_tunnel.sync_device_name(args.name if args.operation=='name' else None)
   print('Устройство: '+(d['device_name'] or 'имя ещё не получено с сервера')+(' · ожидает синхронизации' if d['device_name_pending'] else ''))
  elif cmd=='report':
   if args.operation=='preview':print(json.dumps(vpn_tunnel.support_api.prepare(vpn_tunnel,MANAGER_VERSION),ensure_ascii=False,indent=2))
   else:print('Отчёт принят: '+vpn_tunnel.support_api.send(vpn_tunnel,args.id,args.consent))
  elif cmd=='token':
   if sys.stdin.isatty():
    import getpass
    token=getpass.getpass('Токен клиента (ввод скрыт): ')
   else:token=sys.stdin.read(1024).strip()
   vpn_tunnel.save_token(token);print('Токен сохранён. Подключить: vpn on')
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
  elif cmd=='logs':print(run(['journalctl','-u',vpn_tunnel.UNIT,'-u',policy.SERVICE,'-n',str(max(1,min(args.n,500))),'--no-pager'],capture=True).stdout)
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
