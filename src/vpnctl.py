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

MANAGER_VERSION = "0.6.2"

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
    elif machine == "riscv64":
        asset_name = "Xray-linux-riscv64.zip"
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
    'bnNzbCcsJ2NhLWNlcnRpZmljYXRlcycsJ2Nvbm50cmFjay10b29scyddCiAgICBlbGlmIHNodXRpbC53aGljaCgnYXB0LWdl'
    'dCcpOgogICAgICAgIGNvbW1hbmQoWydhcHQtZ2V0JywndXBkYXRlJ10sdGltZW91dD0zMDApCiAgICAgICAgYXJncyA9IFsn'
    'YXB0LWdldCcsJ2luc3RhbGwnLCcteScsJy0tbm8taW5zdGFsbC1yZWNvbW1lbmRzJywnY2hhcm9uLXN5c3RlbWQnLCdzdHJv'
    'bmdzd2FuLXN3YW5jdGwnLCdsaWJzdHJvbmdzd2FuLXN0YW5kYXJkLXBsdWdpbnMnLCdsaWJjaGFyb24tZXh0cmEtcGx1Z2lu'
    'cycsJ2lwcm91dGUyJywnbmZ0YWJsZXMnLCdjdXJsJywnb3BlbnNzbCcsJ2NhLWNlcnRpZmljYXRlcycsJ2Nvbm50cmFjaydd'
    'CiAgICBlbHNlOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0JDQstGC0L7QvNCw0YLQuNGH0LXRgdC60LDRjyDRg9GB'
    '0YLQsNC90L7QstC60LAg0LrQu9C40LXQvdGC0LAg0L/QvtC00LTQtdGA0LbQuNCy0LDQtdGCIEFyY2gsIEZlZG9yYSDQuCBE'
    'ZWJpYW4vVWJ1bnR1LicpCiAgICBjb21tYW5kKGFyZ3MsIHRpbWVvdXQ9MzAwKQogICAgaWYgbm90IGNoYXJvbl9iaW5hcnko'
    'KSBvciBub3QgYWxsKHNodXRpbC53aGljaChwKSBmb3IgcCBpbiAoJ3N3YW5jdGwnLCdjb25udHJhY2snKSk6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCfQn9Cw0LrQtdGCIHN0cm9uZ1N3YW4g0L3QtSDQv9GA0LXQtNC+0YHRgtCw0LLQuNC7INC9'
    '0LXQvtCx0YXQvtC00LjQvNGL0LUg0L/RgNC+0LPRgNCw0LzQvNGLLicpCiAgICBlbnN1cmVfZXZndF9iaW5hcnkoKQoKCmRl'
    'ZiBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPUZhbHNlKToKICAgICIiIkZvcmdldCBvbmx5IHRoaXMgbWFuYWdl'
    'cidzIG9ic29sZXRlIEROUyBOQVQsIG5ldmVyIGZsdXNoIGFsbCBjb25uZWN0aW9ucy4KCiAgICBSZW1vdmluZyBhbiBuZnQg'
    'TkFUIGNoYWluIGRvZXMgbm90IHJlbW92ZSBleGlzdGluZyBjb25udHJhY2sgdHJhbnNsYXRpb25zLgogICAgQSBydW5uaW5n'
    'IHJlc29sdmVyIGNhbiByZXVzZSBpdHMgVURQIHNvY2tldCBpbmRlZmluaXRlbHkgYWZ0ZXIgYSBWUE4gc3dpdGNoLgogICAg'
    'IiIiCiAgICBmaWx0ZXJzID0gKFsnLS1yZXBseS1wb3J0LXNyYycsJzE4NTUzJ10gaWYgcHJldmlvdXNfdnBuIGVsc2UKICAg'
    'ICAgICAgICAgICAgWyctLXJlcGx5LXBvcnQtc3JjJywnNTMnLCctLWRzdC1uYXQnLCcxLjEuMS4xJ10pCiAgICBmb3IgcHJv'
    'dG9jb2wgaW4gKCd1ZHAnLCd0Y3AnKToKICAgICAgICByZXN1bHQgPSBjb21tYW5kKFsnY29ubnRyYWNrJywnLUQnLCctZics'
    'J2lwdjQnLCctcCcscHJvdG9jb2wsCiAgICAgICAgICAgICAgICAgICAgICAgICAgJy0tZHBvcnQnLCc1MycsKmZpbHRlcnNd'
    'LCBjaGVjaz1GYWxzZSwKICAgICAgICAgICAgICAgICAgICAgICAgIGVudj17Kipvcy5lbnZpcm9uLCdMQ19BTEwnOidDJ30p'
    'CiAgICAgICAgZW1wdHkgPSByZXN1bHQucmV0dXJuY29kZSA9PSAxIGFuZCAnMCBmbG93IGVudHJpZXMgaGF2ZSBiZWVuIGRl'
    'bGV0ZWQnIGluIHJlc3VsdC5zdGRlcnIKICAgICAgICBpZiByZXN1bHQucmV0dXJuY29kZSAhPSAwIGFuZCBub3QgZW1wdHk6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZG5zX3RyYW5zaXRpb25fY2xlYW51cF9mYWlsZWQnKQoKCmRlZiBm'
    'dWxsX2d1YXJkX2FjdGl2ZSgpOgogICAgcmV0dXJuIGNvbW1hbmQoWyduZnQnLCdsaXN0JywndGFibGUnLCdpbmV0JyxGVUxM'
    'X0dVQVJEXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwCgoKZGVmIGZ1bGxfZmlyZXdhbGwoKToKICAgIGlmIHBvbGlj'
    'eSBpcyBub3QgTm9uZToKICAgICAgICBzZXR0aW5ncz1wb2xpY3kuYXBpLmxvYWRfc2V0dGluZ3MoKQogICAgICAgIHJldHVy'
    'biBwb2xpY3kuZmlyZXdhbGwocG9saWN5LmxvYWQoKSxwb2xpY3kubG9jYWxfbmV0d29ya3MocGh5c2ljYWxfcm91dGUoKSks'
    'aW50KHNldHRpbmdzWyJ4cmF5X3VpZCJdKSkKICAgICMgTWluaW1hbCBndWFyZCB1c2VkIGJ5IGlzb2xhdGVkIHByb3RvY29s'
    'IHRlc3RzLgogICAgIyBLZWVwIGxvY2FsIHN0dWIgRE5TIG9uIGxvb3BiYWNrLiBETkFUIG9mIDEyNy84IG9udG8gYSB2ZXRo'
    'IGZhaWxzIExpbnV4J3MKICAgICMgbG9vcGJhY2sgcm91dGUgY2hlY2tzOyB1cHN0cmVhbSByZXNvbHZlciB0cmFmZmljIHN0'
    'aWxsIG9iZXlzIHRoZSBmdWxsIGd1YXJkLgogICAgcmV0dXJuIGYnJyd0YWJsZSBpbmV0IHtGVUxMX0dVQVJEfSB7ewogY2hh'
    'aW4gZG5zIHt7IHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAgaXAgZGFkZHIg'
    'MTI3LjAuMC4wLzggcmV0dXJuCiAgaXAgZGFkZHIge3sgMS4xLjEuMSwgOS45LjkuOSB9fSByZXR1cm4KICBtZXRhIG5mcHJv'
    'dG8gaXB2NCBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBvcnQgNTMgZG5hdCBpcCB0byAxLjEuMS4xCiB9fQog'
    'Y2hhaW4gc291cmNlIHt7IHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0'
    'OwogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBzbmF0IGlwIHRvIDE3Mi4yOS4yNDcuMQogfX0K'
    'IGNoYWluIG91dHB1dCB7eyB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIG9p'
    'Zm5hbWUgImxvIiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgaXAg'
    'ZGFkZHIgMjU1LjI1NS4yNTUuMjU1IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0CiB9fQogY2hhaW4gZm9yd2Fy'
    'ZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7SE9T'
    'VH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2Vw'
    'dAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQg'
    'NDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0'
    'Y3AgZHBvcnQge3sgMjQ1NzEsIDI0NTc4IH19IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0g'
    'aXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9ydCAyNDU3OSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNh'
    'ZGRyIHtDTElFTlR9IGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIG9pZm5hbWUgIntI'
    'T1NUfSIgaXAgZGFkZHIge0NMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBtZXRhIG5mcHJv'
    'dG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie0ZVTExf'
    'SE9TVH0iIGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiB9fQp9fScnJwoKCgpkZWYgcmVmcmVzaF9yZXRh'
    'aW5lZF9ndWFyZCgpOgogICAgIiIiTW92ZSBvbmx5IHRoZSBWUE4gdHJhbnNwb3J0IGV4Y2VwdGlvbiB3aGVuIGFuIGluZ3Jl'
    'c3MgZW5kcG9pbnQgY2hhbmdlcy4iIiIKICAgIGlmIG5vdCBmdWxsX2d1YXJkX2FjdGl2ZSgpOgogICAgICAgIHJldHVybgog'
    'ICAgcnVsZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgIHJlcGxhY2VtZW50ID0gJ2RlbGV0ZSB0YWJsZSBpbmV0ICcrRlVMTF9H'
    'VUFSRCsnXG4nK3J1bGVzCiAgICBjb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAg'
    'IyBQZXJzaXN0IHRoZSBjbG9zZWQgZ3VhcmQgYmVmb3JlIGNoYW5naW5nIHRoZSBhY3RpdmUgZXhjZXB0aW9uOyBhIGNyYXNo'
    'IHN0YXlzIGNsb3NlZC4KICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKICAgIGNvbW1hbmQoWyduZnQn'
    'LCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQoKCmRlZiB2aXJ0dWFsX2lwKCk6CiAgICBkYXRhID0ganNvbi5sb2Fkcyhp'
    'bnNpZGUoWydpcCcsJy1qJywnLTQnLCdhZGRyJ10pLnN0ZG91dCkKICAgIGlwcyA9IFthWydsb2NhbCddIGZvciBsaW5rIGlu'
    'IGRhdGEgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsIFtdKQogICAgICAgICAgIGlmIGlwYWRkcmVzcy5pcF9hZGRy'
    'ZXNzKGFbJ2xvY2FsJ10pIGluIGlwYWRkcmVzcy5pcF9uZXR3b3JrKCcxMC43Ny4wLjAvMjQnKV0KICAgIGlmIGxlbihpcHMp'
    'ICE9IDE6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd2aXJ0dWFsX2lwX21pc3NpbmcnKQogICAgcmV0dXJuIGlwc1sw'
    'XQoKCmRlZiBmdWxsX25hbWVzcGFjZShhZGRyZXNzKToKICAgIHZpcCA9IHZpcnR1YWxfaXAoKQogICAgaWYgbm90IFBhdGgo'
    'Jy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnYWRk'
    'JyxGVUxMX0hPU1QsJ3R5cGUnLCd2ZXRoJywncGVlcicsJ25hbWUnLEZVTExfUEVFUl0pCiAgICAgICAgY29tbWFuZChbJ2lw'
    'JywnbGluaycsJ3NldCcsRlVMTF9QRUVSLCduZXRucycsTlNdKQogICAgY29tbWFuZChbJ2lwJywnYWRkcicsJ3JlcGxhY2Un'
    'LCcxNzIuMjkuMjQ3LjEvMzAnLCdkZXYnLEZVTExfSE9TVF0pCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxM'
    'X0hPU1QsJ210dScsJzEyODAnLCd1cCddKQogICAgaW5zaWRlKFsnaXAnLCdhZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcu'
    'Mi8zMCcsJ2RldicsRlVMTF9QRUVSXSkKICAgIGluc2lkZShbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9QRUVSLCdtdHUnLCcx'
    'MjgwJywndXAnXSkKICAgIGluc2lkZShbJ3N5c2N0bCcsJy1xdycsJ25ldC5pcHY0LmNvbmYuYWxsLmZvcndhcmRpbmc9MScs'
    'J25ldC5pcHY0LmNvbmYuYWxsLnJwX2ZpbHRlcj0wJ10pCiAgICAjIFN0cm9uZ1N3YW4ncyBjYXRjaC1hbGwgcm91dGUgbXVz'
    'dCBub3QgY2FwdHVyZSByZXBsaWVzIHRvIHRoZSBob3N0LWZhY2luZyBpbnRlcmZhY2UuCiAgICBpbnNpZGUoWydpcCcsJ3J1'
    'bGUnLCdkZWwnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAg'
    'ICBpbnNpZGUoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzkwJywndG8nLEZVTExfTkVULCdsb29rdXAnLCdtYWlu'
    'J10pCiAgICBkZWxldGlvbnMgPSAnJwogICAgZm9yIGZhbWlseSx0YWJsZSBpbiBbKCdpbmV0JywnZXZuX2Z1bGxfZm9yd2Fy'
    'ZCcpLCgnbmV0ZGV2JywnZXZuX2Z1bGxfd2lyZScpXToKICAgICAgICBpZiBpbnNpZGUoWyduZnQnLCdsaXN0JywndGFibGUn'
    'LGZhbWlseSx0YWJsZV0sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICAgICAgZGVsZXRpb25zICs9IGYn'
    'ZGVsZXRlIHRhYmxlIHtmYW1pbHl9IHt0YWJsZX1cbicKICAgIHJ1bGVzID0gZGVsZXRpb25zICsgZicnJ3RhYmxlIGluZXQg'
    'ZXZuX2Z1bGxfZm9yd2FyZCB7ewogY2hhaW4gZm9yd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkg'
    'LTU7IHBvbGljeSBkcm9wOwogIGlpZm5hbWUgIntGVUxMX1BFRVJ9IiBvaWZuYW1lICJ7UEVFUn0iIGlwIHNhZGRyIDE3Mi4y'
    'OS4yNDcuMSBhY2NlcHQKICBpaWZuYW1lIHt7ICJ7UEVFUn0iLCAibG8iIH19IG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBk'
    'YWRkciAxNzIuMjkuMjQ3LjEgaXBzZWMgaW4gcmVxaWQge1JFUUlEfSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFj'
    'Y2VwdAogfX0KIGNoYWluIG5hdCB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5'
    'IGFjY2VwdDsKICBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgb2lmbmFtZSAie1BFRVJ9IiBzbmF0IGlwIHRvIHt2aXB9CiB9fQp9'
    'fQp0YWJsZSBuZXRkZXYgZXZuX2Z1bGxfd2lyZSB7ewogY2hhaW4gZWdyZXNzIHt7IHR5cGUgZmlsdGVyIGhvb2sgZWdyZXNz'
    'IGRldmljZSAie1BFRVJ9IiBwcmlvcml0eSAwOyBwb2xpY3kgZHJvcDsKICBldGhlciB0eXBlIGFycCBhY2NlcHQKICBpcCBk'
    'YWRkciB7YWRkcmVzc30gdWRwIGRwb3J0IHtBQ1RJVkVbJ3BvcnQnXX0gYWNjZXB0CiAgaXAgZGFkZHIgMzguMTgwLjE2NC42'
    'NyB0Y3AgZHBvcnQge3sgMjQ1NzEsIDI0NTc4IH19IGFjY2VwdAogIGlwIGRhZGRyIDE5NS4yMDkuMjExLjE2MyB0Y3AgZHBv'
    'cnQgMjQ1NzkgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogfX0KfX0nJycKICAg'
    'IGluc2lkZShbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAgIGluc2lkZShbJ25mdCcsJy1mJywnLSddLGRh'
    'dGE9cnVsZXMpCiAgICAjIFJlcGxhY2UgdGhlIG9yaWdpbmFsIGxhYiBmb3J3YXJkIGRyb3A7IGhvc3QgaW5ncmVzcyByZW1h'
    'aW5zIGNvbnN0cmFpbmVkIGJ5IGZ1bGxfZm9yd2FyZC4KICAgIGluc2lkZShbJ25mdCcsJ2ZsdXNoJywnY2hhaW4nLCdpbmV0'
    'JyxOQU1FU1BBQ0VfR1VBUkQsJ2ZvcndhcmQnXSkKICAgIGluc2lkZShbJ25mdCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JyxOQU1F'
    'U1BBQ0VfR1VBUkQsJ2ZvcndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21ldGEnLCduZnByb3RvJywnaXB2NCcsJ2FjY2Vw'
    'dCddKQogICAgaW5zaWRlKFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLE5BTUVTUEFDRV9HVUFSRCwnZm9yd2FyZCcsJ29p'
    'Zm5hbWUnLEZVTExfUEVFUiwnaXBzZWMnLCdpbicsJ3JlcWlkJyxzdHIoUkVRSUQpLCdjdCcsJ3N0YXRlJywnZXN0YWJsaXNo'
    'ZWQscmVsYXRlZCcsJ2FjY2VwdCddKQoKCl9FR1JFU1NfUFJPQkVTID0gKCdodHRwczovLzEuMS4xLjEvY2RuLWNnaS90cmFj'
    'ZScsICdodHRwczovL2FwaS5pcGlmeS5vcmcnKQpfZWdyZXNzX3ByZWZlcnJlZCA9IDAKCgpkZWYgcGFyc2VfZXhpdChib2R5'
    'LCB0cmFjZSk6CiAgICB2YWx1ZXMgPSBbbGluZVszOl0gZm9yIGxpbmUgaW4gYm9keS5zcGxpdGxpbmVzKCkgaWYgbGluZS5z'
    'dGFydHN3aXRoKCdpcD0nKV0gaWYgdHJhY2UgZWxzZSBbYm9keS5zdHJpcCgpXQogICAgaWYgbGVuKHZhbHVlcykgIT0gMToK'
    'ICAgICAgICByZXR1cm4gTm9uZQogICAgdHJ5OgogICAgICAgIHJldHVybiBzdHIoaXBhZGRyZXNzLklQdjRBZGRyZXNzKHZh'
    'bHVlc1swXSkpCiAgICBleGNlcHQgaXBhZGRyZXNzLkFkZHJlc3NWYWx1ZUVycm9yOgogICAgICAgIHJldHVybiBOb25lCgoK'
    'ZGVmIHByb2JlX2VncmVzcyhydW4sIG9yZGVyLCBwcm94eV9hcmdzPSgpKToKICAgICIiIlJldHVybiB0aGUgZmlyc3QgdmVy'
    'aWZpZWQgSVAsIGluY2x1ZGluZyBhIHdyb25nIGV4aXQsIGFuZCBpdHMgcHJvYmUgaW5kZXguIiIiCiAgICBmb3IgaW5kZXgg'
    'aW4gb3JkZXI6CiAgICAgICAgdXJsID0gX0VHUkVTU19QUk9CRVNbaW5kZXhdCiAgICAgICAgdHJ5OgogICAgICAgICAgICBy'
    'ZXN1bHQgPSBydW4oWydjdXJsJywnLTQnLCpwcm94eV9hcmdzLCctLWZhaWwnLCctLXNpbGVudCcsJy0tc2hvdy1lcnJvcics'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgJy0tY29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCc1JywnLS1t'
    'YXgtZmlsZXNpemUnLCczMjc2OCcsdXJsXSx0aW1lb3V0PTcsY2hlY2s9RmFsc2UpCiAgICAgICAgZXhjZXB0IChPU0Vycm9y'
    'LHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIHJlc3VsdC5yZXR1'
    'cm5jb2RlICE9IDA6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgb2JzZXJ2ZWQgPSBwYXJzZV9leGl0KHJlc3VsdC5z'
    'dGRvdXQsIGluZGV4ID09IDApCiAgICAgICAgaWYgb2JzZXJ2ZWQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIHJldHVybiBv'
    'YnNlcnZlZCwgaW5kZXgKICAgIHJldHVybiBOb25lLCBOb25lCgoKZGVmIGVncmVzc19oZWFsdGgoKToKICAgIGdsb2JhbCBf'
    'ZWdyZXNzX3ByZWZlcnJlZAogICAgb2JzZXJ2ZWQsIGluZGV4ID0gcHJvYmVfZWdyZXNzKGluc2lkZSwgKF9lZ3Jlc3NfcHJl'
    'ZmVycmVkLCAxLV9lZ3Jlc3NfcHJlZmVycmVkKSwgKCctLW5vcHJveHknLCcqJykpCiAgICBpZiBvYnNlcnZlZCAhPSAnMzgu'
    'MTgwLjE2NC42Nyc6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBfZWdyZXNzX3ByZWZlcnJlZCA9IGluZGV4CiAgICByZXR1'
    'cm4gVHJ1ZQoKCmRlZiBzZWxlY3RlZF9ob3N0X2VncmVzcygpOgogICAgIyBDaGVjayB0aGUgaG9zdCBjbGFzc2lmaWVyIGFu'
    'ZCBWUE4gcm91dGUgd2l0aCBhIG51bWVyaWMgSFRUUFMgZW5kcG9pbnQgZmlyc3QuCiAgICAjIFNPQ0tTIHJlc29sdmVzIHRo'
    'ZSBmYWxsYmFjayBob3N0bmFtZSBpdHNlbGYsIGluZGVwZW5kZW50bHkgb2YgcmVzb2x2LmNvbmYuCiAgICBvYnNlcnZlZCwg'
    'XyA9IHByb2JlX2VncmVzcyhjb21tYW5kLCAoMCwgMSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoJy0tbm9w'
    'cm94eScsJycsJy0tc29ja3M1LWhvc3RuYW1lJywnMTI3LjAuMC4xOjE4NTU0JykpCiAgICByZXR1cm4gb2JzZXJ2ZWQKCgpk'
    'ZWYgcGF0aF9oZWFsdGh5KGRhZW1vbik6CiAgICAjIFRoZSBwcml2YXRlIGRpYWdub3N0aWMgSFRUUCBjb2xsZWN0b3IgaXMg'
    'bm90IHBhcnQgb2YgdGhlIFZQTiBkYXRhIHBsYW5lLgogICAgIyBJdHMgb3V0YWdlL3Jlc3RhcnQgbXVzdCBub3QgZGlzY2Fy'
    'ZCBhIHdvcmtpbmcgcm91dGUncyB0aHJlZS1sb3NzIGJ1ZGdldC4KICAgIHJldHVybiAoZGFlbW9uLnBvbGwoKSBpcyBOb25l'
    'IGFuZCBpbnN0YWxsZWQoKQogICAgICAgICAgICBhbmQgKFRMU19QUk9DRVNTIGlzIE5vbmUgb3IgVExTX1BST0NFU1MucG9s'
    'bCgpIGlzIE5vbmUpIGFuZCBlZ3Jlc3NfaGVhbHRoKCkpCgoKZGVmIHJldGlyZV9wcmV2aW91c19jb25uZWN0aW9ucyhhZGRy'
    'ZXNzZXMpOgogICAgIyBUaGUgZmlyZXdhbGwgYWxyZWFkeSBibG9ja3Mgb2xkIG5vbi1leGVtcHQgZmxvd3MuIERvIG5vdCBr'
    'aWxsIGFsbCBzb2NrZXRzCiAgICAjIHNoYXJpbmcgYSBwaHlzaWNhbCBzb3VyY2UgYWRkcmVzczogdGhhdCBkZXN0cm95cyBT'
    'U0gsIExBTiBhbmQgYXBwIGV4Y2x1c2lvbnMuCiAgICAjIE9ubHkgdGhpcyBtYW5hZ2VyJ3MgRE5TIHRyYW5zbGF0aW9ucyBu'
    'ZWVkIGV4cGxpY2l0IHJldGlyZW1lbnQgKGhhbmRsZWQgYWJvdmUpLgogICAgcmV0dXJuCgoKZGVmIHN5c3RlbV9kbnNfaGVh'
    'bHRoKHJlc29sdl9jb25mPVBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKSk6CiAgICAjIGdldGFkZHJpbmZvL2N1cmwgbWF5IHVz'
    'ZSBuc3MtcmVzb2x2ZSBvdmVyIGEgVW5peCBzb2NrZXQgYW5kIG1pc3MgYSBicm9rZW4KICAgICMgVURQIHN0dWIgdXNlZCBi'
    'eSBvdGhlciBhcHBsaWNhdGlvbnMuIEV4ZXJjaXNlIHJlc29sdi5jb25mIGluZGVwZW5kZW50bHkuCiAgICB0cnk6CiAgICAg'
    'ICAgbGluZXMgPSByZXNvbHZfY29uZi5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCkKICAgIGV4Y2VwdCAoT1NFcnJvciwgVW5p'
    'Y29kZUVycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHNlcnZlcnMgPSBbbGluZS5zcGxpdCgpWzFdIGZvciBsaW5l'
    'IGluIGxpbmVzCiAgICAgICAgICAgICAgIGlmIGxpbmUuc3BsaXQoKVs6MV0gPT0gWyduYW1lc2VydmVyJ10gYW5kIGxlbihs'
    'aW5lLnNwbGl0KCkpID49IDJdWzozXQogICAgZm9yIHNlcnZlciBpbiBzZXJ2ZXJzOgogICAgICAgIHRyeToKICAgICAgICAg'
    'ICAgZmFtaWx5ID0gc29ja2V0LkFGX0lORVQ2IGlmIGlwYWRkcmVzcy5pcF9hZGRyZXNzKHNlcnZlcikudmVyc2lvbiA9PSA2'
    'IGVsc2Ugc29ja2V0LkFGX0lORVQKICAgICAgICAgICAgdHJhbnNhY3Rpb24gPSBzZWNyZXRzLnRva2VuX2J5dGVzKDIpCiAg'
    'ICAgICAgICAgIHF1ZXJ5ID0gdHJhbnNhY3Rpb24rYidceDAxXHgwMFx4MDBceDAxXHgwMFx4MDBceDAwXHgwMFx4MDBceDAw'
    'JwogICAgICAgICAgICBxdWVyeSArPSBiJ1x4MDNhcGlceDA1aXBpZnlceDAzb3JnXHgwMFx4MDBceDAxXHgwMFx4MDEnCiAg'
    'ICAgICAgICAgIHdpdGggc29ja2V0LnNvY2tldChmYW1pbHksIHNvY2tldC5TT0NLX0RHUkFNKSBhcyByZXNvbHZlcjoKICAg'
    'ICAgICAgICAgICAgIHJlc29sdmVyLnNldHRpbWVvdXQoMikKICAgICAgICAgICAgICAgIHJlc29sdmVyLmNvbm5lY3QoKHNl'
    'cnZlciwgNTMpKQogICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2VuZChxdWVyeSkKICAgICAgICAgICAgICAgIGFuc3dlciA9'
    'IHJlc29sdmVyLnJlY3YoNDA5NikKICAgICAgICAgICAgaWYgKGxlbihhbnN3ZXIpID49IDEyIGFuZCBhbnN3ZXJbOjJdID09'
    'IHRyYW5zYWN0aW9uIGFuZAogICAgICAgICAgICAgICAgICAgIGFuc3dlclsyXSAmIDB4ODAgYW5kIGFuc3dlclszXSAmIDE1'
    'ID09IDAgYW5kCiAgICAgICAgICAgICAgICAgICAgaW50LmZyb21fYnl0ZXMoYW5zd2VyWzY6OF0sICdiaWcnKSA+IDApOgog'
    'ICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAg'
    'ICAgICBjb250aW51ZQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIHN0YXJ0X25hbWVzcGFjZV9kbnMoKToKICAgICIiIkEgcHJp'
    'dmF0ZSBETlMgZW5kcG9pbnQgcmVhY2hhYmxlIG9ubHkgb3ZlciB0aGUgaG9zdC9uYW1lc3BhY2UgdmV0aC4iIiIKICAgIGds'
    'b2JhbCBETlNfUFJPQ0VTUwogICAgaWYgRE5TX1BST0NFU1MgaXMgbm90IE5vbmUgYW5kIEROU19QUk9DRVNTLnBvbGwoKSBp'
    'cyBOb25lOnJldHVybgogICAgY2ZnID0geydsb2cnOnsnbG9nbGV2ZWwnOid3YXJuaW5nJywnYWNjZXNzJzonbm9uZSd9LAog'
    'ICAgICAnaW5ib3VuZHMnOlt7J3RhZyc6J2Rucy1pbicsJ2xpc3Rlbic6JzE3Mi4yOS4yNDcuMicsJ3BvcnQnOjUzLCdwcm90'
    'b2NvbCc6J2Rva29kZW1vLWRvb3InLAogICAgICAgICAgICAgICAgICAgJ3NldHRpbmdzJzp7J2FkZHJlc3MnOicxLjEuMS4x'
    'JywncG9ydCc6NTMsJ25ldHdvcmsnOid0Y3AsdWRwJ319XSwKICAgICAgJ2Rucyc6eydzZXJ2ZXJzJzpbJzEuMS4xLjEnLCd0'
    'Y3A6Ly85LjkuOS45JywnaHR0cHM6Ly8xLjAuMC4xL2Rucy1xdWVyeSddLAogICAgICAgICAgICAgJ3F1ZXJ5U3RyYXRlZ3kn'
    'OidVc2VJUHY0JywndGFnJzonZG5zLWVuZ2luZScsJ2VuYWJsZVBhcmFsbGVsUXVlcnknOlRydWV9LAogICAgICAnb3V0Ym91'
    'bmRzJzpbeyd0YWcnOid3aXJlJywncHJvdG9jb2wnOidmcmVlZG9tJ30sCiAgICAgICAgICAgICAgICAgICB7J3RhZyc6J2Ru'
    'cycsJ3Byb3RvY29sJzonZG5zJywnc2V0dGluZ3MnOnsncnVsZXMnOlt7J3FUeXBlJzonMSwyOCcsJ2FjdGlvbic6J2hpamFj'
    'ayd9LHsnYWN0aW9uJzonZGlyZWN0J31dfX1dLAogICAgICAncm91dGluZyc6eydydWxlcyc6W3sndHlwZSc6J2ZpZWxkJywn'
    'aW5ib3VuZFRhZyc6WydkbnMtaW4nXSwnb3V0Ym91bmRUYWcnOidkbnMnfSwKICAgICAgICAgICAgICAgICAgICAgICAgICB7'
    'J3R5cGUnOidmaWVsZCcsJ2luYm91bmRUYWcnOlsnZG5zLWVuZ2luZSddLCdvdXRib3VuZFRhZyc6J3dpcmUnfV19fQogICAg'
    'cGF0aD1ST09ULyduYW1lc3BhY2UtZG5zLmpzb24nO3dyaXRlKHBhdGgsanNvbi5kdW1wcyhjZmcpKQogICAgYmluYXJ5PScv'
    'b3B0L3Zwbi1tYW5hZ2VyL2Jpbi94cmF5JwogICAgaW5zaWRlKFtiaW5hcnksJ3J1bicsJy10ZXN0JywnLWNvbmZpZycscGF0'
    'aF0pCiAgICBETlNfUFJPQ0VTUz1zdWJwcm9jZXNzLlBvcGVuKFsnaXAnLCduZXRucycsJ2V4ZWMnLE5TLGJpbmFyeSwncnVu'
    'JywnLWNvbmZpZycsc3RyKHBhdGgpXSwKICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsc3Rkb3V0PXN1YnByb2Nl'
    'c3MuREVWTlVMTCxzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQogICAgZm9yIF8gaW4gcmFuZ2UoMzApOgogICAgICAgIGlm'
    'IEROU19QUk9DRVNTLnBvbGwoKSBpcyBub3QgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3ByaXZhdGVfZG5zX3N0b3BwZWQn'
    'KQogICAgICAgIGlmICcxNzIuMjkuMjQ3LjI6NTMnIGluIGluc2lkZShbJ3NzJywnLWxudSddLGNoZWNrPUZhbHNlKS5zdGRv'
    'dXQ6CiAgICAgICAgICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCduYW1lc2VydmVyIDE3'
    'Mi4yOS4yNDcuMlxub3B0aW9ucyB0aW1lb3V0OjMgYXR0ZW1wdHM6MlxuJykKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAg'
    'dGltZS5zbGVlcCguMSkKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncHJpdmF0ZV9kbnNfbm90X3JlYWR5JykKCgpkZWYgdXNl'
    'X3Jlc29sdmVyX2ZpbGUocGF0aD1QYXRoKCcvZXRjL3Jlc29sdi5jb25mJykpOgogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxf'
    'c3RhdGUoKS5yZWFkX3RleHQoKSkKICAgIHRhcmdldD1ST09ULydyZXNvbHYtdnBuLmNvbmYnCiAgICBpZiAncmVzb2x2ZXJf'
    'b3JpZ2luYWwnIG5vdCBpbiBkYXRhOgogICAgICAgIGRhdGFbJ3Jlc29sdmVyX29yaWdpbmFsJ109eydsaW5rJzpvcy5yZWFk'
    'bGluayhwYXRoKSBpZiBwYXRoLmlzX3N5bWxpbmsoKSBlbHNlIE5vbmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgJ3RleHQnOnBhdGgucmVhZF90ZXh0KCkgaWYgcGF0aC5leGlzdHMoKSBlbHNlICcnLAogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICdleGlzdGVkJzpwYXRoLmV4aXN0cygpIG9yIHBhdGguaXNfc3ltbGluaygpfQogICAgZGF0'
    'YVsnZG5zX2ZhbGxiYWNrJ109VHJ1ZQogICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkpCiAgICB3cml0'
    'ZSh0YXJnZXQsJ25hbWVzZXJ2ZXIgMTcyLjI5LjI0Ny4yXG5vcHRpb25zIHRpbWVvdXQ6MyBhdHRlbXB0czoyXG4nKQogICAg'
    'dGFyZ2V0LmNobW9kKDBvNjQ0KQogICAgIyBUaGUgcGFyZW50IG11c3QgYmUgdHJhdmVyc2FibGUgYnkgYXBwbGljYXRpb25z'
    'LiBTZWNyZXRzIHJlbWFpbiByb290LW9ubHkuCiAgICAjIFB1dCBvbmx5IHRoaXMgcHVibGljIHJlc29sdmVyIGZpbGUgb3V0'
    'c2lkZSB0aGUgY3JlZGVudGlhbCBkaXJlY3RvcnkuCiAgICBwdWJsaWM9UGF0aCgnL3J1bi9ldmdlbml1bS1yZXNvbHYuY29u'
    'ZicpCiAgICBwdWJsaWMucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgd3JpdGUocHVibGlj'
    'LHRhcmdldC5yZWFkX3RleHQoKSxtb2RlPTBvNjQ0KQogICAgdGVtcG9yYXJ5PXBhdGgud2l0aF9uYW1lKCcuZXZnZW5pdW0t'
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
    'RmFsc2UKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZSBhbmQgcG9saWN5LmluY2x1c2l2ZShwb2xpY3kubG9hZCgpKTpyZXR1'
    'cm4gRmFsc2UKICAgICMgU3dpdGNoIG9ubHkgdGhlIHJlc29sdmVyIGZpbGUgd2Ugb3duOyBuZXZlciBzdG9wIGFub3RoZXIg'
    'VlBOIG9yIHJlc29sdmVyLgogICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Cf0LXRgNC10LrQu9GO0YfQsNGOINC90LXQuNGB0L/R'
    'gNCw0LLQvdGL0Lkg0YHQuNGB0YLQtdC80L3Ri9C5IEROUyDQvdCwINC30LDRidC40YnRkdC90L3Ri9C5INGA0LXQt9C10YDQ'
    'si4nLDkwLGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPSdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICB1c2VfcmVzb2x2ZXJfZmls'
    'ZSgpCiAgICByZXR1cm4gc3lzdGVtX2Ruc19oZWFsdGgoKQoKCmRlZiBjaGVja19zeXN0ZW1fZG5zKCk6CiAgICBpZiBwb2xp'
    'Y3kgaXMgbm90IE5vbmUgYW5kIHBvbGljeS5pbmNsdXNpdmUocG9saWN5LmxvYWQoKSk6CiAgICAgICAgaWYgbm90IHN5c3Rl'
    'bV9kbnNfaGVhbHRoKCk6CiAgICAgICAgICAgIHJldHVybiAn0KHQuNGB0YLQtdC80L3Ri9C5IEROUyDQvdC10LTQvtGB0YLR'
    'g9C/0LXQvS4g0J/RgNC40LvQvtC20LXQvdC40Y8g0LzQvtCz0YPRgiDQvdC1INC+0YLQutGA0YvQstCw0YLRjCDRgdCw0LnR'
    'gtGLINC/0L4g0LjQvNC10L3QuC4nCiAgICBlbGlmIG5vdCByZWNvdmVyX3N5c3RlbV9kbnMoKToKICAgICAgICByYWlzZSBS'
    'dW50aW1lRXJyb3IoJ3N5c3RlbV9kbnNfZmFpbGVkJykKICAgIHJldHVybiAnJwoKCmRlZiBjb25uZWN0ZWRfbWVzc2FnZShs'
    'YWJlbCwgZG5zX3dhcm5pbmcpOgogICAgbWVzc2FnZSA9ICfQn9C+0LTQutC70Y7Rh9C10L3QvjogJytsYWJlbCsnLicKICAg'
    'IHJldHVybiBtZXNzYWdlKycgJytkbnNfd2FybmluZyBpZiBkbnNfd2FybmluZyBlbHNlIG1lc3NhZ2UKCgpUVU5ORUxfU0VS'
    'VklDRSA9ICcnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxsLWRldmljZSBFc3RvbmlhIFZQTgpBZnRlcj1uZXR3'
    'b3JrLnRhcmdldApTdGFydExpbWl0SW50ZXJ2YWxTZWM9MTgwClN0YXJ0TGltaXRCdXJzdD0zCltTZXJ2aWNlXQpUeXBlPXNp'
    'bXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCB7cHJlZml4fS10dW5uZWwKRXhlY1N0b3BQb3N0PS91c3Iv'
    'bG9jYWwvc2Jpbi92cG5jdGwge3ByZWZpeH0tdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9bWl4'
    'ZWQKVU1hc2s9MDA3NwpNZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zCicnJwoKUkVDT1ZF'
    'UllfU0VSVklDRSA9ICcnJ1tVbml0XQpEZXNjcmlwdGlvbj1SZWNvdmVyIGludGVycnVwdGVkIEV2Z2VuaXVtIFZQTiB0dW5u'
    'ZWwgcmVzb3VyY2VzCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9jYWwtZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3Jr'
    'LXByZS50YXJnZXQgdnBuLXhyYXkuc2VydmljZQpbU2VydmljZV0KVHlwZT1vbmVzaG90CkV4ZWNTdGFydD0vdXNyL2xvY2Fs'
    'L3NiaW4vdnBuY3RsIHtwcmVmaXh9LXR1bm5lbC1jbGVhbnVwCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdl'
    'dAonJycKCkdVQVJEX1NFUlZJQ0UgPSAnJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZnVsbC1kZXZpY2Uga2lsbCBz'
    'd2l0Y2gKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpBZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRh'
    'cmdldApbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0PXtuZnR9IC1mIHtyb290'
    'fS9mdWxsLWd1YXJkLm5mdApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKJycnCgoKVU5JVF9URU1QTEFU'
    'RVMgPSB7J3VuaXQnOiBUVU5ORUxfU0VSVklDRSwgJ3JlY292ZXJ5JzogUkVDT1ZFUllfU0VSVklDRSwgJ2d1YXJkJzogR1VB'
    'UkRfU0VSVklDRX0KCgpCT09UX1RBUkdFVCA9ICdbSW5zdGFsbF1cbldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0XG4nCgoK'
    'ZGVmIHVuaXRfdGV4dChsYXlvdXQsIHJvbGUsIG5mdD0nL3Vzci9iaW4vbmZ0JywgKiwgcGFuaWM9RmFsc2UpOgogICAgdGVt'
    'cGxhdGUgPSBVTklUX1RFTVBMQVRFU1tyb2xlXQogICAgaWYgbGF5b3V0ID09IExFR0FDWSBhbmQgcm9sZSA9PSAncmVjb3Zl'
    'cnknOgogICAgICAgIHRlbXBsYXRlID0gdGVtcGxhdGUucmVwbGFjZSgnaW50ZXJydXB0ZWQgRXZnZW5pdW0gVlBOIHR1bm5l'
    'bCcsICdvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0JykKICAgIGlmIHBhbmljIGFuZCByb2xlID09ICd1'
    'bml0JzoKICAgICAgICB0ZW1wbGF0ZSA9ICh0ZW1wbGF0ZS5yZXBsYWNlKCdTdGFydExpbWl0SW50ZXJ2YWxTZWM9MTgwJywg'
    'J1N0YXJ0TGltaXRJbnRlcnZhbFNlYz0wJykKICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgnUmVzdGFydD1vbi1mYWls'
    'dXJlJywgJ1Jlc3RhcnQ9YWx3YXlzJykKICAgICAgICAgICAgICAgICAgICAucmVwbGFjZSgnUmVzdGFydFNlYz0zJywgJ1Jl'
    'c3RhcnRTZWM9NScpICsgQk9PVF9UQVJHRVQpCiAgICByZXR1cm4gdGVtcGxhdGUuZm9ybWF0KHByZWZpeD1sYXlvdXQuY29t'
    'bWFuZF9wcmVmaXgsIHJvb3Q9bGF5b3V0LnJvb3QsIG5mdD1uZnQpCgoKZGVmIGtub3duX3VuaXQobGF5b3V0LCByb2xlLCBk'
    'YXRhKToKICAgIGlmIHJvbGUgPT0gJ3VuaXQnOgogICAgICAgIHJldHVybiBkYXRhIGluICgKICAgICAgICAgICAgdW5pdF90'
    'ZXh0KGxheW91dCwgcm9sZSkuZW5jb2RlKCksCiAgICAgICAgICAgIHVuaXRfdGV4dChsYXlvdXQsIHJvbGUsIHBhbmljPVRy'
    'dWUpLmVuY29kZSgpLAogICAgICAgICAgICAodW5pdF90ZXh0KGxheW91dCwgcm9sZSkgKyBCT09UX1RBUkdFVCkuZW5jb2Rl'
    'KCksICAjIDAuNi4xCiAgICAgICAgKQogICAgYmluYXJpZXMgPSAoJy91c3IvYmluL25mdCcsICcvdXNyL3NiaW4vbmZ0Jywg'
    'Jy9zYmluL25mdCcsIHNodXRpbC53aGljaCgnbmZ0JykpCiAgICByZXR1cm4gYW55KGRhdGEgPT0gdW5pdF90ZXh0KGxheW91'
    'dCwgcm9sZSwgbmZ0KS5lbmNvZGUoKSBmb3IgbmZ0IGluIGJpbmFyaWVzIGlmIG5mdCkKCgpkZWYgaGFzX2xheW91dChsYXlv'
    'dXQpOgogICAgcGF0aHMgPSAobGF5b3V0LnJvb3QsIGxheW91dC5zdGF0ZSwgbGF5b3V0LnJ1bnRpbWUsICooVU5JVF9ESVIg'
    'LyBnZXRhdHRyKGxheW91dCwgcm9sZSkgZm9yIHJvbGUgaW4gVU5JVF9URU1QTEFURVMpKQogICAgcmV0dXJuIGFueShvcy5w'
    'YXRoLmxleGlzdHMocGF0aCkgZm9yIHBhdGggaW4gcGF0aHMpCgoKZGVmIHRyYW5zaXRpb25fbGF5b3V0cygpOgogICAgdHJ5'
    'OgogICAgICAgIGRpcmVjdGlvbiA9IExBWU9VVF9UUkFOU0FDVElPTi5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBleGNlcHQg'
    'RmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGlmIGRpcmVjdGlvbiA9PSAndXBncmFkZSc6CiAg'
    'ICAgICAgcmV0dXJuIExFR0FDWSwgQ1VSUkVOVAogICAgaWYgZGlyZWN0aW9uID09ICdyb2xsYmFjayc6CiAgICAgICAgcmV0'
    'dXJuIENVUlJFTlQsIExFR0FDWQogICAgcmFpc2UgUnVudGltZUVycm9yKCfQndC10LrQvtGA0YDQtdC60YLQvdCw0Y8g0LfQ'
    'sNC/0LjRgdGMINC+INC/0LXRgNC10L3QvtGB0LUg0YTQsNC50LvQvtCyIFZQTi4nKQoKCmRlZiBzZWxlY3RfaW5zdGFsbGVk'
    'X2xheW91dCgpOgogICAgIyBBbHNvIHdvcmtzIGJldHdlZW4gdGhlIG9sZCB1cGRhdGVyIHN3YXBwaW5nICJjdXJyZW50IiBh'
    'bmQgc3RhcnRpbmcgb3VyIGZpbmFsaXplci4KICAgIHBlbmRpbmcgPSB0cmFuc2l0aW9uX2xheW91dHMoKQogICAgaWYgcGVu'
    'ZGluZzoKICAgICAgICBzb3VyY2UsIHRhcmdldCA9IHBlbmRpbmcKICAgICAgICB1c2VfbGF5b3V0KHRhcmdldCBpZiB0YXJn'
    'ZXQucm9vdC5pc19kaXIoKSBhbmQgbm90IHNvdXJjZS5yb290LmV4aXN0cygpIGVsc2Ugc291cmNlKQogICAgZWxzZToKICAg'
    'ICAgICBpZiBub3QgTEVHQUNZLnJvb3QuZXhpc3RzKCkgYW5kIENVUlJFTlQucm9vdC5pc19kaXIoKToKICAgICAgICAgICAg'
    'dXNlX2xheW91dChDVVJSRU5UKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHVzZV9sYXlvdXQoTEVHQUNZIGlmIGhhc19s'
    'YXlvdXQoTEVHQUNZKSBlbHNlIENVUlJFTlQpCgoKZGVmIHVuaXRfbGlua3MobmFtZSk6CiAgICBmb3Iga2luZCBpbiAoJ3dh'
    'bnRzJywgJ3JlcXVpcmVzJywgJ3VwaG9sZHMnKToKICAgICAgICB5aWVsZCBmcm9tIFVOSVRfRElSLmdsb2IoJyouJyArIGtp'
    'bmQgKyAnLycgKyBuYW1lKQoKCmRlZiBsYXlvdXRfaW5fdXNlKGxheW91dCwgKiwgY2hlY2tfZGVzdGluYXRpb249RmFsc2Up'
    'OgogICAgIiIiS2VlcCBsaXZlIHdvcmtlcnMgYW5kIHJldGFpbmVkIGZhaWwtY2xvc2VkIGNvbmZpZ3VyYXRpb25zIHdpdGgg'
    'dGhlaXIgb3JpZ2luYWwgbmFtZXMuIiIiCiAgICBpZiAoKGxheW91dC5yb290IC8gJ25ldHdvcmsuanNvbicpLmV4aXN0cygp'
    'IG9yIChsYXlvdXQucm9vdCAvICdmdWxsLW5ldHdvcmsuanNvbicpLmV4aXN0cygpCiAgICAgICAgICAgIG9yIChQYXRoKCcv'
    'cnVuL25ldG5zJykgLyBsYXlvdXQubmFtZXNwYWNlKS5leGlzdHMoKQogICAgICAgICAgICBvciAoUGF0aCgnL2V0Yy9uZXRu'
    'cycpIC8gbGF5b3V0Lm5hbWVzcGFjZSkuZXhpc3RzKCkKICAgICAgICAgICAgb3IgKFBhdGgoJy9zeXMvY2xhc3MvbmV0Jykg'
    'LyBsYXlvdXQuaG9zdCkuZXhpc3RzKCkKICAgICAgICAgICAgb3IgYW55KHVuaXRfbGlua3MobGF5b3V0Lmd1YXJkKSkgb3Ig'
    'YW55KHVuaXRfbGlua3MobGF5b3V0LnVuaXQpKSk6CiAgICAgICAgcmV0dXJuIFRydWUKICAgIGlmIG5vdCBoYXNfbGF5b3V0'
    'KGxheW91dCkgYW5kIG5vdCBjaGVja19kZXN0aW5hdGlvbjoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGZvciBuYW1lIGlu'
    'IChsYXlvdXQudW5pdCwgbGF5b3V0Lmd1YXJkLCBsYXlvdXQucmVjb3ZlcnkpOgogICAgICAgIHJlc3VsdCA9IGNvbW1hbmQo'
    'WydzeXN0ZW1jdGwnLCAnc2hvdycsICctcCcsICdBY3RpdmVTdGF0ZScsICctLXZhbHVlJywgbmFtZV0sIGNoZWNrPUZhbHNl'
    'KQogICAgICAgIHN0YXRlID0gcmVzdWx0LnN0ZG91dC5zdHJpcCgpCiAgICAgICAgaWYgbm90IHN0YXRlOgogICAgICAgICAg'
    'ICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LUg0YPQtNCw0LvQvtGB0Ywg0L7Qv9GA0LXQtNC10LvQuNGC0Ywg0YHQvtGB0YLQ'
    'vtGP0L3QuNC1INGB0LvRg9C20LEgVlBOINC00LvRjyDQvtCx0L3QvtCy0LvQtdC90LjRjy4g0J/QvtCy0YLQvtGA0LjRgtC1'
    'IHZwbiB1cGRhdGUuJykKICAgICAgICBpZiBzdGF0ZSBub3QgaW4gKCdpbmFjdGl2ZScsICdmYWlsZWQnKToKICAgICAgICAg'
    'ICAgcmV0dXJuIFRydWUKICAgIGlmIG5vdCBzaHV0aWwud2hpY2goJ25mdCcpOgogICAgICAgIHJldHVybiAoVU5JVF9ESVIg'
    'LyBsYXlvdXQuZ3VhcmQpLmV4aXN0cygpCiAgICByZXN1bHQgPSBjb21tYW5kKFsnbmZ0JywgJy1qJywgJ2xpc3QnLCAndGFi'
    'bGVzJ10sIGNoZWNrPUZhbHNlKQogICAgaWYgcmVzdWx0LnJldHVybmNvZGU6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCfQndC1INGD0LTQsNC70L7RgdGMINC/0YDQvtCy0LXRgNC40YLRjCDRgdC+0YXRgNCw0L3RkdC90L3Ri9C1INC/0YDQsNCy'
    '0LjQu9CwIFZQTi4g0J/QvtCy0YLQvtGA0LjRgtC1IHZwbiB1cGRhdGUuJykKICAgIHRyeToKICAgICAgICB0YWJsZXMgPSBb'
    'cmVjb3JkWyd0YWJsZSddIGZvciByZWNvcmQgaW4ganNvbi5sb2FkcyhyZXN1bHQuc3Rkb3V0IG9yICd7Im5mdGFibGVzIjpb'
    'XX0nKVsnbmZ0YWJsZXMnXSBpZiAndGFibGUnIGluIHJlY29yZF0KICAgIGV4Y2VwdCAoVmFsdWVFcnJvciwgS2V5RXJyb3Is'
    'IFR5cGVFcnJvcikgYXMgZXJyb3I6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC/'
    '0YDQvtGH0LjRgtCw0YLRjCDRgdC/0LjRgdC+0Log0YLQsNCx0LvQuNGGIFZQTiDQtNC70Y8g0L7QsdC90L7QstC70LXQvdC4'
    '0Y8uJykgZnJvbSBlcnJvcgogICAgcmV0dXJuIGFueSh0LmdldCgnZmFtaWx5JykgPT0gJ2luZXQnIGFuZCB0LmdldCgnbmFt'
    'ZScpIGluIChsYXlvdXQuZ3VhcmRfdGFibGUsIGxheW91dC5ob3N0X3RhYmxlKSBmb3IgdCBpbiB0YWJsZXMpCgoKZGVmIG1h'
    'bmFnZWRfdW5pdChwYXRoLCBsYXlvdXQsIHJvbGUpOgogICAgaW5mbyA9IHBhdGgubHN0YXQoKQogICAgcmV0dXJuIChzdGF0'
    'LlNfSVNSRUcoaW5mby5zdF9tb2RlKSBhbmQgaW5mby5zdF91aWQgPT0gb3MuZ2V0ZXVpZCgpIGFuZCBpbmZvLnN0X25saW5r'
    'ID09IDEKICAgICAgICAgICAgYW5kIGluZm8uc3Rfc2l6ZSA8IDQwOTYgYW5kIGtub3duX3VuaXQobGF5b3V0LCByb2xlLCBw'
    'YXRoLnJlYWRfYnl0ZXMoKSkpCgoKZGVmIGNhbl9tb3ZlX2ZpbGVzKHNvdXJjZSwgdGFyZ2V0LCByZXN1bWluZyk6CiAgICBm'
    'b3Igb2xkLCBuZXcgaW4gKChzb3VyY2Uucm9vdCwgdGFyZ2V0LnJvb3QpLCAoc291cmNlLnJ1bnRpbWUsIHRhcmdldC5ydW50'
    'aW1lKSwgKHNvdXJjZS5zdGF0ZSwgdGFyZ2V0LnN0YXRlKSk6CiAgICAgICAgaWYgb2xkLmlzX3N5bWxpbmsoKSBvciBuZXcu'
    'aXNfc3ltbGluaygpIG9yIChvbGQuZXhpc3RzKCkgYW5kIG5ldy5leGlzdHMoKSk6CiAgICAgICAgICAgIHJldHVybiBGYWxz'
    'ZQogICAgICAgIGlmIG5ldy5leGlzdHMoKSBhbmQgbm90IHJlc3VtaW5nOgogICAgICAgICAgICByZXR1cm4gRmFsc2UKICAg'
    'ICAgICBmb3IgcGF0aCBpbiAob2xkLCBuZXcpOgogICAgICAgICAgICBpZiBub3QgcGF0aC5leGlzdHMoKToKICAgICAgICAg'
    'ICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGluZm8gPSBwYXRoLmxzdGF0KCkKICAgICAgICAgICAgaWYgaW5mby5zdF91'
    'aWQgIT0gb3MuZ2V0ZXVpZCgpOgogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgICAgIGlmIG9sZCA9PSBz'
    'b3VyY2Uuc3RhdGU6CiAgICAgICAgICAgICAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKGluZm8uc3RfbW9kZSkgb3IgaW5mby5z'
    'dF9ubGluayAhPSAxOgogICAgICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgICAgICBlbGlmIG5vdCBzdGF0'
    'LlNfSVNESVIoaW5mby5zdF9tb2RlKToKICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgZm9yIHJvbGUgaW4gVU5J'
    'VF9URU1QTEFURVM6CiAgICAgICAgb2xkID0gVU5JVF9ESVIgLyBnZXRhdHRyKHNvdXJjZSwgcm9sZSkKICAgICAgICBuZXcg'
    'PSBVTklUX0RJUiAvIGdldGF0dHIodGFyZ2V0LCByb2xlKQogICAgICAgIGlmIGFueShvcy5wYXRoLmxleGlzdHModW5pdC53'
    'aXRoX25hbWUodW5pdC5uYW1lICsgJy5kJykpIGZvciB1bml0IGluIChvbGQsIG5ldykpOgogICAgICAgICAgICByZXR1cm4g'
    'RmFsc2UKICAgICAgICBpZiBvcy5wYXRoLmxleGlzdHMob2xkKSBhbmQgbm90IG1hbmFnZWRfdW5pdChvbGQsIHNvdXJjZSwg'
    'cm9sZSk6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGlmIG9zLnBhdGgubGV4aXN0cyhuZXcpIGFuZCBub3Qg'
    'KHJlc3VtaW5nIGFuZCBtYW5hZ2VkX3VuaXQobmV3LCB0YXJnZXQsIHJvbGUpKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNl'
    'CiAgICAgICAgZm9yIGxpbmsgaW4gdW5pdF9saW5rcyhvbGQubmFtZSk6CiAgICAgICAgICAgIHJlcGxhY2VtZW50ID0gbGlu'
    'ay53aXRoX25hbWUobmV3Lm5hbWUpCiAgICAgICAgICAgIGlmIG5vdCBsaW5rLmlzX3N5bWxpbmsoKSBvciBsaW5rLnJlc29s'
    'dmUoKSAhPSBvbGQ6CiAgICAgICAgICAgICAgICByZXR1cm4gRmFsc2UKICAgICAgICAgICAgaWYgb3MucGF0aC5sZXhpc3Rz'
    'KHJlcGxhY2VtZW50KSBhbmQgbm90IChyZXN1bWluZyBhbmQgcmVwbGFjZW1lbnQuaXNfc3ltbGluaygpIGFuZCByZXBsYWNl'
    'bWVudC5yZXNvbHZlKCkgPT0gbmV3KToKICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIGlmIG5vdCByZXN1'
    'bWluZyBhbmQgYW55KHVuaXRfbGlua3MobmV3Lm5hbWUpKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICByZXR1cm4g'
    'VHJ1ZQoKCmRlZiB1cGRhdGVfZ2VuZXJhdGVkX3BhdGhzKHJvb3QsIHNvdXJjZSwgdGFyZ2V0KToKICAgICMgVGhlc2UgdGhy'
    'ZWUgcHJpdmF0ZSBmaWxlcyBhcmUgZ2VuZXJhdGVkIGJ5IHRoaXMgY2xpZW50LiBJZGVudGl0eSBhbmQgY3JlZGVudGlhbCBm'
    'aWxlcyBtb3ZlIHVuY2hhbmdlZC4KICAgIHJlcGxhY2VtZW50cyA9IHsKICAgICAgICAnc3Ryb25nc3dhbi5jb25mJzogWyhz'
    'dHIoc291cmNlLnJ1bnRpbWUpICsgJy8nLCBzdHIodGFyZ2V0LnJ1bnRpbWUpICsgJy8nKV0sCiAgICAgICAgJ2Nvbm5lY3Rp'
    'b24uY29uZic6IFsoc3RyKHNvdXJjZS5yb290KSArICcvJywgc3RyKHRhcmdldC5yb290KSArICcvJyksCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAoJ1xuICcgKyBzb3VyY2UuaWtlICsgJyB7JywgJ1xuICcgKyB0YXJnZXQuaWtlICsgJyB7Jyks'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAoJ1xuICAgJyArIHNvdXJjZS5pa2UgKyAnLW5ldCB7JywgJ1xuICAgJyAr'
    'IHRhcmdldC5pa2UgKyAnLW5ldCB7JyldLAogICAgICAgICdmdWxsLWd1YXJkLm5mdCc6IFsoJ3RhYmxlIGluZXQgJyArIHNv'
    'dXJjZS5ndWFyZF90YWJsZSArICcgeycsICd0YWJsZSBpbmV0ICcgKyB0YXJnZXQuZ3VhcmRfdGFibGUgKyAnIHsnKSwKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgKCciJyArIHNvdXJjZS5ob3N0ICsgJyInLCAnIicgKyB0YXJnZXQuaG9zdCArICci'
    'JyldLAogICAgfQogICAgZm9yIG5hbWUsIGNoYW5nZXMgaW4gcmVwbGFjZW1lbnRzLml0ZW1zKCk6CiAgICAgICAgcGF0aCA9'
    'IHJvb3QgLyBuYW1lCiAgICAgICAgaWYgcGF0aC5pc19zeW1saW5rKCkgb3Igbm90IHBhdGguaXNfZmlsZSgpOgogICAgICAg'
    'ICAgICBjb250aW51ZQogICAgICAgIGJlZm9yZSA9IHBhdGgucmVhZF90ZXh0KCkKICAgICAgICBhZnRlciA9IGJlZm9yZQog'
    'ICAgICAgIGZvciBvbGQsIG5ldyBpbiBjaGFuZ2VzOgogICAgICAgICAgICBhZnRlciA9IGFmdGVyLnJlcGxhY2Uob2xkLCBu'
    'ZXcpCiAgICAgICAgaWYgYWZ0ZXIgIT0gYmVmb3JlOgogICAgICAgICAgICB3cml0ZShwYXRoLCBhZnRlcikKCgpkZWYgbW92'
    'ZV9pZGxlX2xheW91dChzb3VyY2UsIHRhcmdldCk6CiAgICAiIiJDYWxsZWQgdW5kZXIgdGhlIENMSSBvcGVyYXRpb24gbG9j'
    'ay4gRWFjaCBkaXNrIHN0ZXAgY2FuIHJlc3VtZSBhZnRlciBpbnRlcnJ1cHRpb24uIiIiCiAgICBwZW5kaW5nID0gdHJhbnNp'
    'dGlvbl9sYXlvdXRzKCkKICAgIGlmIHBlbmRpbmcgYW5kIHBlbmRpbmcgIT0gKHNvdXJjZSwgdGFyZ2V0KToKICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ9Cj0LbQtSDQstGL0L/QvtC70L3Rj9C10YLRgdGPINC00YDRg9Cz0L7QuSDQv9C10YDQtdC9'
    '0L7RgSDRhNCw0LnQu9C+0LIgVlBOLicpCiAgICBpZiBub3QgcGVuZGluZyBhbmQgbm90IGhhc19sYXlvdXQoc291cmNlKToK'
    'ICAgICAgICB1c2VfbGF5b3V0KHRhcmdldCkKICAgICAgICByZXR1cm4gVHJ1ZQogICAgaWYgbGF5b3V0X2luX3VzZShzb3Vy'
    'Y2UpIG9yIGxheW91dF9pbl91c2UodGFyZ2V0LCBjaGVja19kZXN0aW5hdGlvbj1UcnVlKToKICAgICAgICByZXR1cm4gRmFs'
    'c2UKICAgIGlmIG5vdCBjYW5fbW92ZV9maWxlcyhzb3VyY2UsIHRhcmdldCwgYm9vbChwZW5kaW5nKSk6CiAgICAgICAgaWYg'
    'cGVuZGluZzoKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQn9C10YDQtdC90L7RgSDQv9GA0LjQvtGB0YLQsNC9'
    '0L7QstC70LXQvSDQuNC3LdC30LAg0LrQvtC90YTQu9C40LrRgtCwINGE0LDQudC70L7QsiBWUE4uJykKICAgICAgICByZXR1'
    'cm4gRmFsc2UKICAgIGlmIG5vdCBwZW5kaW5nOgogICAgICAgIHdyaXRlKExBWU9VVF9UUkFOU0FDVElPTiwgJ3VwZ3JhZGUn'
    'IGlmIHRhcmdldCA9PSBDVVJSRU5UIGVsc2UgJ3JvbGxiYWNrJykKCiAgICBmb3Igcm9sZSBpbiBVTklUX1RFTVBMQVRFUzoK'
    'ICAgICAgICBvbGQgPSBVTklUX0RJUiAvIGdldGF0dHIoc291cmNlLCByb2xlKQogICAgICAgIG5ldyA9IFVOSVRfRElSIC8g'
    'Z2V0YXR0cih0YXJnZXQsIHJvbGUpCiAgICAgICAgaWYgbm90IG9sZC5leGlzdHMoKToKICAgICAgICAgICAgY29udGludWUK'
    'ICAgICAgICBpZiBub3QgbmV3LmV4aXN0cygpOgogICAgICAgICAgICBuZnQgPSBzaHV0aWwud2hpY2goJ25mdCcpIG9yICcv'
    'dXNyL3NiaW4vbmZ0JwogICAgICAgICAgICBwYW5pYyA9IHJvbGUgPT0gJ3VuaXQnIGFuZCBvbGQucmVhZF9ieXRlcygpID09'
    'IHVuaXRfdGV4dChzb3VyY2UsIHJvbGUsIHBhbmljPVRydWUpLmVuY29kZSgpCiAgICAgICAgICAgIHdyaXRlKG5ldywgdW5p'
    'dF90ZXh0KHRhcmdldCwgcm9sZSwgbmZ0LCBwYW5pYz1wYW5pYyksIG1vZGU9MG82NDQpCiAgICAgICAgZm9yIGxpbmsgaW4g'
    'dW5pdF9saW5rcyhvbGQubmFtZSk6CiAgICAgICAgICAgIHJlcGxhY2VtZW50ID0gbGluay53aXRoX25hbWUobmV3Lm5hbWUp'
    'CiAgICAgICAgICAgIGlmIG5vdCByZXBsYWNlbWVudC5pc19zeW1saW5rKCk6CiAgICAgICAgICAgICAgICByZXBsYWNlbWVu'
    'dC5zeW1saW5rX3RvKG9zLnBhdGgucmVscGF0aChuZXcsIGxpbmsucGFyZW50KSkKICAgICAgICAgICAgbGluay51bmxpbmso'
    'KQogICAgICAgIG9sZC51bmxpbmsoKQogICAgZm9yIG9sZCwgbmV3IGluICgoc291cmNlLnN0YXRlLCB0YXJnZXQuc3RhdGUp'
    'LCAoc291cmNlLnJ1bnRpbWUsIHRhcmdldC5ydW50aW1lKSwgKHNvdXJjZS5yb290LCB0YXJnZXQucm9vdCkpOgogICAgICAg'
    'IGlmIG9sZC5leGlzdHMoKToKICAgICAgICAgICAgb2xkLnJlbmFtZShuZXcpCiAgICB1cGRhdGVfZ2VuZXJhdGVkX3BhdGhz'
    'KHRhcmdldC5yb290LCBzb3VyY2UsIHRhcmdldCkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZGFlbW9uLXJlbG9hZCdd'
    'KQogICAgTEFZT1VUX1RSQU5TQUNUSU9OLnVubGluaygpCiAgICB1c2VfbGF5b3V0KHRhcmdldCkKICAgIHJldHVybiBUcnVl'
    'CgoKZGVmIGZpbmlzaF9uYW1lX3RyYW5zaXRpb24oKToKICAgIHBlbmRpbmcgPSB0cmFuc2l0aW9uX2xheW91dHMoKQogICAg'
    'aWYgcGVuZGluZzoKICAgICAgICBpZiBub3QgbW92ZV9pZGxlX2xheW91dCgqcGVuZGluZyk6CiAgICAgICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcign0J/QtdGA0LXQvdC+0YEg0LjQvNGR0L0gVlBOINC10YnRkSDQvdC1INC30LDQstC10YDRiNGR0L0u'
    'JykKICAgIGVsaWYgTEFZT1VUID09IExFR0FDWToKICAgICAgICBtb3ZlX2lkbGVfbGF5b3V0KExFR0FDWSwgQ1VSUkVOVCkK'
    'CgpkZWYgbWlncmF0ZV91bml0X21vZGVzKCk6CiAgICAiIiJNYWtlIGVhcmxpZXIgZ2VuZXJhdGVkIHNlcnZpY2UgZGVzY3Jp'
    'cHRpb25zIHJlYWRhYmxlLCBpbmNsdWRpbmcgb24gaWRsZSBjbGllbnRzLiIiIgogICAgZm9yIHJvbGUgaW4gVU5JVF9URU1Q'
    'TEFURVM6CiAgICAgICAgbmFtZSA9IGdldGF0dHIoTEFZT1VULCByb2xlKQogICAgICAgIHRyeToKICAgICAgICAgICAgZmQg'
    'PSBvcy5vcGVuKFVOSVRfRElSIC8gbmFtZSwgb3MuT19SRE9OTFkgfCBvcy5PX05PRk9MTE9XIHwgb3MuT19OT05CTE9DSykK'
    'ICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBlcnJvcjoKICAgICAgICAgICAgaWYgZXJyb3IuZXJybm8gaW4gKGVycm5vLkVO'
    'T0VOVCwgZXJybm8uRUxPT1ApOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgcmFpc2UKICAgICAgICB0'
    'cnk6CiAgICAgICAgICAgIGluZm8gPSBvcy5mc3RhdChmZCkKICAgICAgICAgICAgaWYgKG5vdCBzdGF0LlNfSVNSRUcoaW5m'
    'by5zdF9tb2RlKSBvciBpbmZvLnN0X25saW5rICE9IDEKICAgICAgICAgICAgICAgICAgICBvciBpbmZvLnN0X3VpZCAhPSBv'
    'cy5nZXRldWlkKCkgb3Igc3RhdC5TX0lNT0RFKGluZm8uc3RfbW9kZSkgIT0gMG82MDApOgogICAgICAgICAgICAgICAgY29u'
    'dGludWUKICAgICAgICAgICAgIyBBIGxvY2FsIHJlcGxhY2VtZW50IG1heSBjb250YWluIGNyZWRlbnRpYWxzLiBPbmx5IG1p'
    'Z3JhdGUgb3VyIG93biB0ZW1wbGF0ZXMuCiAgICAgICAgICAgIGlmIGluZm8uc3Rfc2l6ZSA8IDQwOTYgYW5kIGtub3duX3Vu'
    'aXQoTEFZT1VULCByb2xlLCBvcy5yZWFkKGZkLCA0MDk2KSk6CiAgICAgICAgICAgICAgICBvcy5mY2htb2QoZmQsIDBvNjQ0'
    'KQogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBwZXJzaXN0X2d1YXJkKHJ1bGVzKToK'
    'ICAgICMgR3VhcmQgcGVyc2lzdGVuY2UgcHJlY2VkZXMgc3dpdGNoaW5nLiBDbGVhbnVwIGFmdGVyIGEgY3Jhc2ggbmV2ZXIg'
    'b3BlbnMgdGhlIEludGVybmV0LgogICAgbmZ0ID0gc2h1dGlsLndoaWNoKCduZnQnKQogICAgaWYgbm90IG5mdDoKICAgICAg'
    'ICByYWlzZSBGaWxlTm90Rm91bmRFcnJvcignbmZ0JykKICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykK'
    'ICAgIHdyaXRlKFVOSVRfRElSIC8gR1VBUkRfVU5JVCwgdW5pdF90ZXh0KExBWU9VVCwgJ2d1YXJkJywgbmZ0KSwgbW9kZT0w'
    'bzY0NCkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3Rs'
    'JywnZW5hYmxlJyxHVUFSRF9VTklUXSkKCgpkZWYgY29uZmlndXJlX3N5c3RlbV9kbnMoKToKICAgIGlmIG5vdCBmdWxsX3N0'
    'YXRlKCkuZXhpc3RzKCk6cmV0dXJuCiAgICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAg'
    'aWYgcG9saWN5IGlzIG5vdCBOb25lIGFuZCBwb2xpY3kuaW5jbHVzaXZlKHBvbGljeS5sb2FkKCkpOgogICAgICAgIHJlc3Rv'
    'cmVfcmVzb2x2ZXJfZmlsZShkYXRhKQogICAgICAgIGlmIGRhdGEuZ2V0KCdkbnNfbW9kZScpPT0ncmVzb2x2ZWRfbGluayc6'
    'CiAgICAgICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywncmV2ZXJ0JyxGVUxMX0hPU1RdLGNoZWNrPUZhbHNlKQogICAg'
    'ICAgIGRhdGFbJ2Ruc19tb2RlJ109J2RpcmVjdCcKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRh'
    'KSkKICAgICAgICByZXR1cm4KICAgIGlmIHNodXRpbC53aGljaCgncmVzb2x2ZWN0bCcpIGFuZCBjb21tYW5kKFsnc3lzdGVt'
    'Y3RsJywnaXMtYWN0aXZlJywnLS1xdWlldCcsJ3N5c3RlbWQtcmVzb2x2ZWQnXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9'
    'PSAwOgogICAgICAgIGRhdGFbJ2Ruc19tb2RlJ109J3Jlc29sdmVkX2xpbmsnCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgp'
    'LGpzb24uZHVtcHMoZGF0YSkpCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkbnMnLEZVTExfSE9TVCwnMTcyLjI5'
    'LjI0Ny4yJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkb21haW4nLEZVTExfSE9TVCwnfi4nXSkKICAgICAg'
    'ICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2RlZmF1bHQtcm91dGUnLEZVTExfSE9TVCwneWVzJ10pCiAgICAgICAgY29tbWFu'
    'ZChbJ3Jlc29sdmVjdGwnLCdmbHVzaC1jYWNoZXMnXSxjaGVjaz1GYWxzZSkKICAgIGVsc2U6CiAgICAgICAgdXNlX3Jlc29s'
    'dmVyX2ZpbGUoKQoKCmRlZiBhY3RpdmF0ZV9mdWxsKGFkZHJlc3MpOgogICAgb2xkX2FkZHJlc3NlcyA9IFthWydsb2NhbCdd'
    'IGZvciBsaW5rIGluIGpzb24ubG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ2FkZHInLCdzaG93Jywnc2NvcGUnLCdn'
    'bG9iYWwnXSkuc3Rkb3V0KQogICAgICAgICAgICAgICAgICAgICBpZiBsaW5rLmdldCgnaWZuYW1lJykgbm90IGluIChIT1NU'
    'LEZVTExfSE9TVCkKICAgICAgICAgICAgICAgICAgICAgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlmIGEu'
    'Z2V0KCdzY29wZScpID09ICdnbG9iYWwnXQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToKICAgICAgICBpZiBQ'
    'YXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cignZnVsbF9pbnRlcmZhY2VfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0'
    'YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ2Z1bGxfdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0'
    'YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdhZG1pbl90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGFueShyLmdldCgncHJpb3JpdHknKSBpbiAoNzks'
    'ODApIGZvciByIGluIGpzb24ubG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KSk6CiAgICAg'
    'ICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF9ydWxlX2NvbGxpc2lvbicpCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0'
    'ZSgpLGpzb24uZHVtcHMoeydhY3RpdmUnOkZhbHNlfSkpCiAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAgc3RhcnRf'
    'bmFtZXNwYWNlX2RucygpCiAgICAjIFZhbGlkYXRlIHRoZSBlZ3Jlc3MgZmlsdGVyIGJlZm9yZSBpbnRlcnJ1cHRpbmcgdGhl'
    'IHByZXZpb3VzIFZQTi4KICAgIGlmIG5vdCBlZ3Jlc3NfaGVhbHRoKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdl'
    'c3RvbmlhX2VncmVzc19mYWlsZWQnKQogICAgcnVsZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgICMgUmVwYWlyIG1heSBpbmhl'
    'cml0IGEgZ3VhcmQgZnJvbSBhbiBvbGRlciB2ZXJzaW9uLiBSZXBsYWNlIG91ciB0YWJsZSBpbgogICAgIyBvbmUgbmZ0IHRy'
    'YW5zYWN0aW9uLCBzbyBmaXhlcyBhcHBseSB3aXRob3V0IG9wZW5pbmcgYW4gdW5ndWFyZGVkIHdpbmRvdy4KICAgIHJlcGxh'
    'Y2VtZW50ID0gKCdkZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJyBpZiBmdWxsX2d1YXJkX2FjdGl2ZSgpIGVs'
    'c2UgJycpK3J1bGVzCiAgICBjb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgY29t'
    'bWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICBwZXJzaXN0X2d1YXJkKHJ1bGVzKQogICAgIyBU'
    'aGlzIGNvbW1hbmQgc3RvcHMgb25seSB0aGlzIG1hbmFnZXIncyBwcmV2aW91cyBYcmF5IG1vZGUgYW5kIHJlbW92ZXMgaXRz'
    'IGd1YXJkLgogICAgY29tbWFuZChbJy91c3IvbG9jYWwvc2Jpbi92cG5jdGwnLExBWU9VVC5jb21tYW5kX3ByZWZpeCsnLXBh'
    'dXNlLW1haW4nXSx0aW1lb3V0PTQwKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywndW5yZWFjaGFibGUn'
    'LCdkZWZhdWx0JywnbWV0cmljJywnMzI3NjAnLCd0YWJsZScsRlVMTF9UQUJMRV0pCiAgICAjIEluY2x1c2lvbiBtb2RlIG5l'
    'dmVyIGluc3RhbGxzIGFuIGludGVyaW0gZnVsbC1kZXZpY2UgVlBOIHJvdXRlLCBldmVuCiAgICAjIGR1cmluZyByZWNvbm5l'
    'Y3QuIFRoZSBjbGFzc2lmaWVyIHJldGFpbnMgaXRzIFRVTiBkZWZhdWx0IG9yIGZhaWxzIGNsb3NlZC4KICAgIGlmIHBvbGlj'
    'eSBpcyBOb25lIG9yIG5vdCBwb2xpY3kuaW5jbHVzaXZlKHBvbGljeS5sb2FkKCkpOgogICAgICAgIGNvbW1hbmQoWydpcCcs'
    'J3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLEZVTExfSE9TVCwnbWV0cmlj'
    'JywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0pCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc4'
    'MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBmb3IgcnVsZSBpbiAoWydwcmlvcml0eScsJzc5Jywn'
    'dG8nLENMSUVOVCsnLzMyJywnbG9va3VwJywnbWFpbiddLAogICAgICAgICAgICAgICAgIFsncHJpb3JpdHknLCc3OScsJ2lp'
    'ZicsRlVMTF9IT1NULCdsb29rdXAnLCdtYWluJ10pOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCpydWxl'
    'XSxjaGVjaz1GYWxzZSkKICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywqcnVsZV0pCiAgICBjb21tYW5kKFsn'
    'aXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc4MCcsJ2xvb2t1cCcsRlVMTF9UQUJMRV0pCiAgICBjb25maWd1cmVfc3lz'
    'dGVtX2RucygpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPVRydWUpCiAgICByZXRpcmVfcHJldmlvdXNf'
    'Y29ubmVjdGlvbnMob2xkX2FkZHJlc3NlcykKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZToKICAgICAgICBwb2xpY3kuYXBw'
    'bHkoKQogICAgZG5zX3dhcm5pbmcgPSBjaGVja19zeXN0ZW1fZG5zKCkKICAgICMgVGVzdCB0aGUgYWN0dWFsIGhvc3QgcGF0'
    'aCBhcyB3ZWxsIGFzIG5hbWVzcGFjZSBwcm9iZXMgYmVmb3JlIGFubm91bmNpbmcgY29ubmVjdGVkLgogICAgaWYgcG9saWN5'
    'IGlzIG5vdCBOb25lIGFuZCBwb2xpY3kuaW5jbHVzaXZlKHBvbGljeS5sb2FkKCkpOgogICAgICAgIG9ic2VydmVkID0gc2Vs'
    'ZWN0ZWRfaG9zdF9lZ3Jlc3MoKQogICAgZWxzZToKICAgICAgICBjaGVjayA9IGNvbW1hbmQoWydjdXJsJywnLTQnLCctLW5v'
    'cHJveHknLCcnIGlmIHBvbGljeSBpcyBub3QgTm9uZSBlbHNlICcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLW1heC10aW1l'
    'JywnMTAnLCooWyctLXNvY2tzNS1ob3N0bmFtZScsJzEyNy4wLjAuMToxODU1NCddIGlmIHBvbGljeSBpcyBub3QgTm9uZSBl'
    'bHNlIFtdKSwnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJ10sdGltZW91dD0xMikKICAgICAgICBvYnNlcnZlZCA9IGNoZWNrLnN0'
    'ZG91dC5zdHJpcCgpCiAgICBpZiBvYnNlcnZlZCAhPSAnMzguMTgwLjE2NC42Nyc6CiAgICAgICAgcmFpc2UgUnVudGltZUVy'
    'cm9yKCdob3N0X2VncmVzc19mYWlsZWQnKQogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkK'
    'ICAgIGRhdGFbJ2FjdGl2ZSddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgcmV0'
    'dXJuIGRuc193YXJuaW5nCgoKZGVmIGNsZWFudXBfZnVsbChyZWxlYXNlPUZhbHNlKToKICAgIGdsb2JhbCBETlNfUFJPQ0VT'
    'UwogICAgaWYgRE5TX1BST0NFU1MgaXMgbm90IE5vbmUgYW5kIEROU19QUk9DRVNTLnBvbGwoKSBpcyBOb25lOgogICAgICAg'
    'IEROU19QUk9DRVNTLnRlcm1pbmF0ZSgpCiAgICAgICAgdHJ5OkROU19QUk9DRVNTLndhaXQodGltZW91dD0zKQogICAgICAg'
    'IGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOkROU19QUk9DRVNTLmtpbGwoKTtETlNfUFJPQ0VTUy53YWl0KCkK'
    'ICAgIEROU19QUk9DRVNTPU5vbmUKICAgIGtlZXBfZGlyZWN0ID0gbm90IHJlbGVhc2UgYW5kIHBvbGljeSBpcyBub3QgTm9u'
    'ZSBhbmQgcG9saWN5LmluY2x1c2l2ZShwb2xpY3kubG9hZCgpKQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lIGFuZCBub3Qg'
    'a2VlcF9kaXJlY3Q6CiAgICAgICAgcG9saWN5LnN0b3AocmVsZWFzZT1yZWxlYXNlKQogICAgaWYgbm90IGZ1bGxfc3RhdGUo'
    'KS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkp'
    'CiAgICBpZiBub3Qga2VlcF9kaXJlY3Q6Y29tbWFuZChbJ2lwJywncm91dGUnLCdkZWwnLCdkZWZhdWx0JywnbWV0cmljJywn'
    'MTAnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnZGVsJyxGVUxM'
    'X0hPU1RdLGNoZWNrPUZhbHNlKQogICAgIyBPbiBmYWlsdXJlOiByZXRhaW4gcm91dGluZywgRE5TIGFuZCB0aGUgcGVyc2lz'
    'dGVudCBndWFyZCB1bnRpbCBleHBsaWNpdCBkaXNjb25uZWN0LgogICAgaWYgbm90IHJlbGVhc2U6CiAgICAgICAgcmV0dXJu'
    'CiAgICByZXN0b3JlX3Jlc29sdmVyX2ZpbGUoZGF0YSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0'
    'eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwn'
    'LCdwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMyJywnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29t'
    'bWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCdpaWYnLEZVTExfSE9TVCwnbG9va3VwJywnbWFpbidd'
    'LGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdmbHVzaCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVj'
    'az1GYWxzZSkKICAgIGZvciBzZXJ2ZXIgaW4gKCcxOTIuMTY4LjAuMTYzJywgJzM4LjE4MC4xNjQuNjcnKToKICAgICAgICBj'
    'b21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ3RvJyxzZXJ2ZXIsJ2lwcHJvdG8nLCd0Y3AnLCdk'
    'cG9ydCcsJzIyJywnbG9va3VwJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywn'
    'ZGlzYWJsZScsJy0tbm93JyxHVUFSRF9VTklUXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0'
    'YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKQogICAgY2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNsZWFy'
    'X2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJs'
    'ZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZnVsbF9zdGF0ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVz'
    'b2x2ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNoZWNrPUZhbHNlKSBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNl'
    'IE5vbmUKCgpkZWYgY29tbWFuZChhcmdzLCBjaGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToK'
    'ICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBj'
    'YXB0dXJlX291dHB1dD1UcnVlLAogICAgICAgICAgICAgICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNo'
    'ZWNrPUZhbHNlKQogICAgaWYgY2hlY2sgYW5kIGNwLnJldHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRh'
    'aW4gYSBDU1IgcGF0aDsgZG8gbm90IHByb3BhZ2F0ZSBwcm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ2NvbW1hbmRfZmFpbGVkJykKICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2Fy'
    'Z3MpOgogICAgcmV0dXJuIGNvbW1hbmQoWydpcCcsICduZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoK'
    'ZGVmIHdyaXRlKHBhdGgsIHZhbHVlLCAqLCBtb2RlPTBvNjAwKToKICAgIHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1'
    'ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGZkLCB0ZW1wb3JhcnkgPSB0ZW1wZmlsZS5ta3N0ZW1wKHByZWZp'
    'eD0nLicgKyBwYXRoLm5hbWUgKyAnLicsIGRpcj1wYXRoLnBhcmVudCkKICAgIHRyeToKICAgICAgICB3aXRoIG9zLmZkb3Bl'
    'bihmZCwgJ3cnKSBhcyBzdHJlYW06CiAgICAgICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgICAgICAgICAgc3RyZWFt'
    'LmZsdXNoKCkKICAgICAgICAgICAgb3MuZmNobW9kKGZkLCBtb2RlKQogICAgICAgIG9zLnJlcGxhY2UodGVtcG9yYXJ5LCBw'
    'YXRoKQogICAgZmluYWxseToKICAgICAgICBQYXRoKHRlbXBvcmFyeSkudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgpkZWYg'
    'c2F2ZWQoKToKICAgIHRyeToKICAgICAgICByZXR1cm4ganNvbi5sb2FkcyhTVEFURS5yZWFkX3RleHQoKSkKICAgIGV4Y2Vw'
    'dCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgcmV0dXJuIHt9CgoKZGVmIHN0YWdlKHBoYXNlLCBtZXNzYWdlLCBw'
    'cm9ncmVzcywgKipmaWVsZHMpOgogICAgZGF0YSA9IHsqKnNhdmVkKCksICdwaGFzZSc6IHBoYXNlLCAnbWVzc2FnZSc6IG1l'
    'c3NhZ2UsICdwcm9ncmVzcyc6IHByb2dyZXNzLAogICAgICAgICAgICAndXBkYXRlZCc6IGludCh0aW1lLnRpbWUoKSksICdo'
    'ZWFydGJlYXQnOiB0aW1lLm1vbm90b25pYygpLCAqKmZpZWxkc30KICAgIHdyaXRlKFNUQVRFLCBqc29uLmR1bXBzKGRhdGEs'
    'IGVuc3VyZV9hc2NpaT1GYWxzZSkpCiAgICBpZiBzdXBwb3J0X2FwaSBpcyBub3QgTm9uZToKICAgICAgICB0cnk6c3VwcG9y'
    'dF9hcGkucmVjb3JkKFJPT1Qsd3JpdGUsZGF0YSkKICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixUeXBlRXJy'
    'b3IpOnBhc3MKCgpkZWYgc2VsZWN0ZWRfcm91dGUoKToKICAgIHRyeTp2YWx1ZT1qc29uLmxvYWRzKChST09ULydzZWxlY3Rp'
    'b24uanNvbicpLnJlYWRfdGV4dCgpKS5nZXQoJ3JvdXRlJywnYXV0bycpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJv'
    'cixBdHRyaWJ1dGVFcnJvcik6dmFsdWU9J2F1dG8nCiAgICByZXR1cm4gdmFsdWUgaWYgdmFsdWUgaW4geydhdXRvJywqKGNb'
    'J2lkJ10gZm9yIGMgaW4gQ0FORElEQVRFUyl9IGVsc2UgJ2F1dG8nCgoKZGVmIHNlbGVjdF9yb3V0ZSh2YWx1ZSk6CiAgICBp'
    'ZiB2YWx1ZSBub3QgaW4geydhdXRvJywqKGNbJ2lkJ10gZm9yIGMgaW4gQ0FORElEQVRFUyl9OnJhaXNlIFZhbHVlRXJyb3Io'
    'J9Cd0LXQuNC30LLQtdGB0YLQvdGL0Lkg0LzQsNGA0YjRgNGD0YIuJykKICAgIHdyaXRlKFJPT1QvJ3NlbGVjdGlvbi5qc29u'
    'Jyxqc29uLmR1bXBzKHsncm91dGUnOnZhbHVlfSkpCgoKZGVmIHJvdXRlX2Nob2ljZXMoKToKICAgIHJhbmtpbmc9cmFua19h'
    'cGkuUmFua2luZyhST09ULydyYW5raW5nLmpzb24nLFtjWydpZCddIGZvciBjIGluIENBTkRJREFURVNdKSBpZiByYW5rX2Fw'
    'aSBlbHNlIE5vbmUKICAgIG9yZGVyPXJhbmtpbmcuY2FuZGlkYXRlcygpIGlmIHJhbmtpbmcgYW5kIHJhbmtpbmcubG9hZCgp'
    'IGVsc2UgW10KICAgIHJldHVybiB7J3NlbGVjdGVkJzpzZWxlY3RlZF9yb3V0ZSgpLCdjaG9pY2VzJzpbeydpZCc6Y1snaWQn'
    'XSwnbGFiZWwnOmNbJ2xhYmVsJ119IGZvciBjIGluIENBTkRJREFURVNdLAogICAgICAgICAgICAnb3JkZXInOm9yZGVyLCdl'
    'bnRyaWVzJzpyYW5raW5nLmRhdGFbJ2VudHJpZXMnXSBpZiBvcmRlciBlbHNlIHt9fQoKCmRlZiBzdGF0dXMoKToKICAgIGRh'
    'dGEgPSBzYXZlZCgpCiAgICBydW5uaW5nID0gY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcs'
    'IFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yKS5yZXR1cm5jb2RlID09IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScp'
    'ID09ICdjb25uZWN0ZWQnIGFuZCAobm90IHJ1bm5pbmcgb3IgdGltZS5tb25vdG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0'
    'JywgMCkgPiA5MCk6CiAgICAgICAgZGF0YS51cGRhdGUocGhhc2U9J2ludGVycnVwdGVkJywgbWVzc2FnZT0n0KHQvtC10LTQ'
    'uNC90LXQvdC40LUg0L7RgdGC0LDQvdC+0LLQuNC70L7RgdGMLiDQn9GA0L7QstC10YDRjNGC0LUg0YHQvtGB0YLQvtGP0L3Q'
    'uNC1INC30LDRidC40YLRiyDQuCDQvdCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C40L3QuNGC0YzCuy4nLCBhY3RpdmU9RmFsc2Up'
    'CiAgICBwdWJsaWMgPSB7a2V5OiBkYXRhW2tleV0gZm9yIGtleSBpbiAoJ3BoYXNlJywgJ21lc3NhZ2UnLCAncHJvZ3Jlc3Mn'
    'LCAnYWN0aXZlJywgJ3VwZGF0ZWQnLCAnbWV0cmljcycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAnc2NvcGUnLCAnc2luY2UnLCAncmV0cnknLCAnZXJyb3JfY29kZScsICdwYXRoJykgaWYga2V5IGluIGRhdGF9CiAgICB0'
    'b2tlbl9pbmZvID0gdG9rZW5fc3RhdHVzKCkKICAgIHJldHVybiB7J3BoYXNlJzogJ29mZicsICdtZXNzYWdlJzogKCfQotC+'
    '0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO0YfQuNGC0YzCuy4nIGlmIHRv'
    'a2VuX2luZm9bJ2hhc190b2tlbiddIGVsc2UgJ9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQ'
    'vtC60LXQvSDQutC70LjQtdC90YLQsC4nKSwKICAgICAgICAgICAgJ3Byb2dyZXNzJzogMCwgJ2FjdGl2ZSc6IEZhbHNlLCAq'
    'KnB1YmxpYywgJ3J1bm5pbmcnOiBydW5uaW5nLCAncGFuaWMnOnBhbmljX2VuYWJsZWQoKSwKICAgICAgICAgICAgKip0b2tl'
    'bl9pbmZvLCAqKmRldmljZV9zdGF0dXMoKSwgJ3JvdXRlcyc6cm91dGVfY2hvaWNlcygpLCAnaXNvbGF0ZWQnOiBGYWxzZSwg'
    'J2Z1bGxfZGV2aWNlJzogcG9saWN5IGlzIE5vbmUgb3Igbm90IHBvbGljeS5pbmNsdXNpdmUocG9saWN5LmxvYWQoKSksICdn'
    'dWFyZCc6IGZ1bGxfZ3VhcmRfYWN0aXZlKCksICdwcm90b2NvbCc6ICdJS0V2MiDihpIg0K3RgdGC0L7QvdC40Y8nfQoKCkBj'
    'b250ZXh0bGliLmNvbnRleHRtYW5hZ2VyCmRlZiBuYW1lc3BhY2UoKToKICAgIGJlZm9yZSA9IG9zLm9wZW4oJy9wcm9jL3Nl'
    'bGYvbnMvbmV0Jywgb3MuT19SRE9OTFkpCiAgICB0YXJnZXQgPSBvcy5vcGVuKCcvcnVuL25ldG5zLycrTlMsIG9zLk9fUkRP'
    'TkxZKQogICAgdHJ5OgogICAgICAgIG9zLnNldG5zKHRhcmdldCwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIHlpZWxkCiAg'
    'ICBmaW5hbGx5OgogICAgICAgIG9zLnNldG5zKGJlZm9yZSwgb3MuQ0xPTkVfTkVXTkVUKQogICAgICAgIG9zLmNsb3NlKHRh'
    'cmdldCkKICAgICAgICBvcy5jbG9zZShiZWZvcmUpCgoKZGVmIHBoeXNpY2FsX3JvdXRlKCk6CiAgICByb3V0ZXMgPSBqc29u'
    'LmxvYWRzKGNvbW1hbmQoWydpcCcsICctaicsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgJ21haW4nLCAnZGVm'
    'YXVsdCddKS5zdGRvdXQpCiAgICBjYW5kaWRhdGVzID0gW3IgZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdnYXRld2F5Jykg'
    'YW5kIHIuZ2V0KCdkZXYnKSBhbmQKICAgICAgICAgICAgICAgICAgbm90IHJbJ2RldiddLnN0YXJ0c3dpdGgoKCd0dW4nLCAn'
    'eHJheScsICd3ZycsICdldm4tJykpXQogICAgaWYgbm90IGNhbmRpZGF0ZXM6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdub19waHlzaWNhbF9yb3V0ZScpCiAgICByb3V0ZSA9IG1pbihjYW5kaWRhdGVzLCBrZXk9bGFtYmRhIHI6IHIuZ2V0KCdt'
    'ZXRyaWMnLCAwKSkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidbQS1aYS16MC05Xy46LV17MSwxNX0nLCByb3V0ZVsnZGV2'
    'J10pOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9pbnRlcmZhY2UnKQogICAgaXBhZGRyZXNzLklQdjRB'
    'ZGRyZXNzKHJvdXRlWydnYXRld2F5J10pCiAgICByZXR1cm4gcm91dGUKCgpkZWYgaG9zdF9ydWxlcyhpZmFjZSwgcHJldmlv'
    'dXNfZm9yd2FyZD1UcnVlKToKICAgICMgU2NvcGUgZXZlcnkgbmV3IGZvcndhcmRpbmcvTkFUIHJ1bGUgdG8gb3VyIG9uZSBp'
    'bnRlcmZhY2UgYW5kIHRoZSBjb25maWd1cmVkIGluZ3Jlc3MgYWRkcmVzcy4KICAgIHByZXNlcnZlX2Rpc2FibGVkID0gJycg'
    'aWYgcHJldmlvdXNfZm9yd2FyZCBlbHNlICcnJyAgaWlmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBhY2Nl'
    'cHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQg'
    'YWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgZHJvcCcnJwogICAgcmV0dXJuIGYnJyd0YWJsZSBpbmV0IHtORlR9IHt7CiBj'
    'aGFpbiBmb3J3YXJkIHt7CiAgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0yMDsgcG9saWN5IGFjY2VwdDsK'
    'ICBpaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHt7IHtTRVJWRVJ9IH19IHVkcCBkcG9ydCB7SUtFX1BPUlR9IGFjY2VwdAog'
    'IGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQz'
    'IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB0Y3Ag'
    'ZHBvcnQge3sgMjQ1NzEsIDI0NTc4IH19IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAg'
    'ZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9ydCAyNDU3OSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRy'
    'IHt7IHtTRVJWRVJ9IH19IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgZHJvcAogIG9pZm5hbWUg'
    'IntIT1NUfSIgaXAgc2FkZHIge3sge1NFUlZFUn0sIDM4LjE4MC4xNjQuNjcgfX0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVs'
    'YXRlZCBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGRyb3AKe3ByZXNlcnZlX2Rpc2FibGVkfQogfX0KIGNoYWluIG5hdCB7'
    'ewogIHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlwIHNhZGRy'
    'IHtDTElFTlR9IG9pZm5hbWUgIntpZmFjZX0iIG1hc3F1ZXJhZGUKIH19Cn19JycnCgoKZGVmIHNldHVwX25ldHdvcmsoKToK'
    'ICAgIHJvdXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgIyBSZWZ1c2UgbmFtZS9hZGRyZXNzIGNvbGxpc2lvbnMgcmF0aGVy'
    'IHRoYW4gcmVwdXJwb3NpbmcgYW5vdGhlciBhcHBsaWNhdGlvbidzIHJlc291cmNlcy4KICAgIGlmIFBhdGgoJy9ydW4vbmV0'
    'bnMvJytOUykuZXhpc3RzKCkgb3IgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytIT1NUKS5leGlzdHMoKSBvciAoUGF0aCgnL2V0'
    'Yy9uZXRucycpL05TKS5leGlzdHMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfbmFtZXNwYWNlX2V4aXN0'
    'cycpCiAgICBpZiBjb21tYW5kKFsnaXAnLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsIHN0cihUQUJMRSldLCBj'
    'aGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X3RhYmxlX2luX3Vz'
    'ZScpCiAgICBpZiBhbnkoTkVUV09SSyBpbiBsaW5lIGZvciBsaW5lIGluIGNvbW1hbmQoWydpcCcsICctNCcsICdyb3V0ZScs'
    'ICdzaG93JywgJ3RhYmxlJywgJ2FsbCddKS5zdGRvdXQuc3BsaXRsaW5lcygpKToKICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ3Rlc3RfbmV0d29ya19pbl91c2UnKQogICAgb2xkX2ZvcndhcmQgPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBf'
    'Zm9yd2FyZCcpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgICMgUmVjb3JkIG93bmVyc2hpcCBiZWZvcmUgY3JlYXRpbmcgYW55'
    'dGhpbmc6IGNsZWFudXAgaXMgdmFsaWQgYWZ0ZXIgZXZlcnkgcGFydGlhbCBzdGVwLgogICAgdXBsaW5rID0gUGF0aCgnL3By'
    'b2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9yb3V0ZVsnZGV2J10vJ2ZvcndhcmRpbmcnCiAgICB3cml0ZShST09ULyduZXR3b3Jr'
    'Lmpzb24nLCBqc29uLmR1bXBzKHsnZm9yd2FyZCc6IG9sZF9mb3J3YXJkLCAnaW50ZXJmYWNlJzogcm91dGVbJ2RldiddLCAn'
    'dXBsaW5rX2ZvcndhcmQnOiB1cGxpbmsucmVhZF90ZXh0KCkuc3RyaXAoKX0pKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5z'
    'JywgJ2FkZCcsIE5TXSkKICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnLCAnbmFtZXNlcnZl'
    'ciAxLjEuMS4xXG5uYW1lc2VydmVyIDkuOS45Ljlcbm9wdGlvbnMgdGltZW91dDoyIGF0dGVtcHRzOjJcbicpCiAgICAjIG5z'
    'cy1yZXNvbHZlIHRhbGtzIHRvIHRoZSBob3N0IGRhZW1vbiBvdmVyIGEgVW5peCBzb2NrZXQgZXZlbiBpbnNpZGUgbmV0bnMu'
    'CiAgICBuc3M9UGF0aCgnL2V0Yy9uc3N3aXRjaC5jb25mJykucmVhZF90ZXh0KCkKICAgIG5zcz1yZS5zdWIocideaG9zdHM6'
    'LiokJywgJ2hvc3RzOiBmaWxlcyBkbnMnLCBuc3MsIGZsYWdzPXJlLk0pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykv'
    'TlMvJ25zc3dpdGNoLmNvbmYnLCBuc3MpCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdhZGQnLCBIT1NULCAndHlwZScs'
    'ICd2ZXRoJywgJ3BlZXInLCAnbmFtZScsIFBFRVJdKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnc2V0JywgUEVFUiwg'
    'J25ldG5zJywgTlNdKQogICAgY29tbWFuZChbJ2lwJywgJ2FkZHInLCAnYWRkJywgR0FURVdBWSsnLzMwJywgJ2RldicsIEhP'
    'U1RdKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnc2V0JywgSE9TVCwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdh'
    'ZGRyJywgJ2FkZCcsIENMSUVOVCsnLzMwJywgJ2RldicsIFBFRVJdKQogICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQn'
    'LCBQRUVSLCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywgJ2xpbmsnLCAnc2V0JywgJ2xvJywgJ3VwJ10pCiAgICBpbnNpZGUo'
    'WydpcCcsICdyb3V0ZScsICdhZGQnLCAnZGVmYXVsdCcsICd2aWEnLCBHQVRFV0FZXSkKICAgICMgQSByZWNvbm5lY3QgY3Jl'
    'YXRlcyBhIE5FVyBUQ1Agc29ja2V0IGFmdGVyIElLRSBpbnN0YWxscyBpdHMgZGVmYXVsdCByb3V0ZS4KICAgICMgS2VlcCB0'
    'aGUgcmVsYXkgc29ja2V0IG9uIHRoZSBuYW1lc3BhY2UgdXBsaW5rIHdpdGggdGhlIHBoeXNpY2FsIHZldGggc291cmNlOwog'
    'ICAgIyBvdGhlcndpc2Ugc291cmNlIHNlbGVjdGlvbiBnaXZlcyBpdCB0aGUgVlBOIFZJUCBhbmQgdHVubmVscyBpdCBpbnRv'
    'IGl0c2VsZi4KICAgIGlmIEFDVElWRS5nZXQoJ3RyYW5zcG9ydF9hZGRyZXNzJyk6CiAgICAgICAgaW5zaWRlKFsnaXAnLCdy'
    'dWxlJywnYWRkJywncHJpb3JpdHknLCc4OScsJ3RvJyxBQ1RJVkVbJ3RyYW5zcG9ydF9hZGRyZXNzJ10rJy8zMicsCiAgICAg'
    'ICAgICAgICAgICAnaXBwcm90bycsJ3RjcCcsJ2Rwb3J0JyxzdHIoQUNUSVZFWyd0cmFuc3BvcnRfcG9ydCddKSwnbG9va3Vw'
    'JywnbWFpbiddKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2FkZCcsICd0YWJsZScsIHN0cihUQUJMRSksICdkZWZh'
    'dWx0JywgJ3ZpYScsIHJvdXRlWydnYXRld2F5J10sICdkZXYnLCByb3V0ZVsnZGV2J11dKQogICAgZm9yIGFkZHJlc3MgaW4g'
    'RU5EUE9JTlRTOgogICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2FkZCcsICdwcmlvcml0eScsIHN0cihQUklPUklU'
    'WSksICdmcm9tJywgQ0xJRU5UKycvMzInLAogICAgICAgICAgICAgICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAn'
    'LCBzdHIoVEFCTEUpXSkKICAgIHJ1bGVzID0gaG9zdF9ydWxlcyhyb3V0ZVsnZGV2J10sIHByZXZpb3VzX2ZvcndhcmQ9b2xk'
    'X2ZvcndhcmQgPT0gJzEnKQogICAgY29tbWFuZChbJ25mdCcsICctYycsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICBj'
    'b21tYW5kKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAgICMgUGVyLWludGVyZmFjZSBmb3J3YXJkaW5nIGF2'
    'b2lkcyBpcF9mb3J3YXJkJ3MgZ2xvYmFsIGRlZmF1bHRzIHJlc2V0LgogICAgKFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9j'
    'b25mJykvSE9TVC8nZm9yd2FyZGluZycpLndyaXRlX3RleHQoJzFcbicpCiAgICB1cGxpbmsud3JpdGVfdGV4dCgnMVxuJykK'
    'CgpkZWYgY2xlYW51cCgpOgogICAgY2xlYW51cF9mdWxsKCkKICAgICMgQW4gdW5vd25lZCBuYW1lc3BhY2UvdGFibGUgbXVz'
    'dCBuZXZlciBiZSBkZWxldGVkIGJ5IGEgZ2VuZXJpYyBjbGVhbnVwIGNhbGwuCiAgICBpZiBub3QgKFJPT1QvJ25ldHdvcmsu'
    'anNvbicpLmV4aXN0cygpOgogICAgICAgIHJldHVybgogICAgZGF0YSA9IGpzb24ubG9hZHMoKFJPT1QvJ25ldHdvcmsuanNv'
    'bicpLnJlYWRfdGV4dCgpKQogICAgY29tbWFuZChbJ25mdCcsICdkZWxldGUnLCAndGFibGUnLCAnaW5ldCcsIE5GVF0sIGNo'
    'ZWNrPUZhbHNlKQogICAgZm9yIGFkZHJlc3MgaW4gKCpFTkRQT0lOVFMsICpMRUdBQ1lfRU5EUE9JTlRTKToKICAgICAgICBj'
    'b21tYW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCBzdHIoUFJJT1JJVFkpLCAnZnJvbScsIENMSUVOVCsn'
    'LzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNzKycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNr'
    'PUZhbHNlKQogICAgZm9yIGFkZHJlc3MgaW4gZGF0YS5nZXQoJ21lYXN1cmVtZW50X2lwcycsIFtdKToKICAgICAgICBpZiBp'
    'cGFkZHJlc3MuaXBfYWRkcmVzcyhhZGRyZXNzKS5pc19nbG9iYWw6CiAgICAgICAgICAgIGNvbW1hbmQoWydpcCcsICdydWxl'
    'JywgJ2RlbCcsICdwcmlvcml0eScsICcxMTEnLCAnZnJvbScsIENMSUVOVCsnLzMyJywgJ3RvJywgYWRkcmVzcysnLzMyJywg'
    'J2xvb2t1cCcsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICdyb3V0ZScsICdmbHVzaCcs'
    'ICd0YWJsZScsIHN0cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICduZXRucycsICdkZWwnLCBO'
    'U10sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnZGVsJywgSE9TVF0sIGNoZWNrPUZhbHNlKQog'
    'ICAgaWYgJ3VwbGlua19mb3J3YXJkJyBpbiBkYXRhOgogICAgICAgIHBhdGggPSBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQv'
    'Y29uZicpL2RhdGFbJ2ludGVyZmFjZSddLydmb3J3YXJkaW5nJwogICAgICAgIGlmIHBhdGguZXhpc3RzKCk6CiAgICAgICAg'
    'ICAgIHBhdGgud3JpdGVfdGV4dChkYXRhWyd1cGxpbmtfZm9yd2FyZCddKydcbicpCiAgICBlbGlmIGRhdGEuZ2V0KCdmb3J3'
    'YXJkJykgPT0gJzAnIGFuZCBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcpLnJlYWRfdGV4dCgpLnN0cmlw'
    'KCkgPT0gJzEnOgogICAgICAgIFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykud3JpdGVfdGV4dCgnMFxu'
    'JykKICAgIChQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25mJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAg'
    'IChQYXRoKCcvZXRjL25ldG5zJykvTlMvJ25zc3dpdGNoLmNvbmYnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgd2l0'
    'aCBjb250ZXh0bGliLnN1cHByZXNzKE9TRXJyb3IpOgogICAgICAgIChQYXRoKCcvZXRjL25ldG5zJykvTlMpLnJtZGlyKCkK'
    'ICAgIChST09ULyduZXR3b3JrLmpzb24nKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQoKCgoKZGVmIHRsc19yZXF1ZXN0KGFk'
    'ZHJlc3MsIHBhdGgsIGJvZHk9Tm9uZSwgY2xpZW50PUZhbHNlLCB0aW1lb3V0PTgsIGlkZW50aXR5PVNFUlZFUik6CiAgICBj'
    'b250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2NvbnRleHQoY2FkYXRhPVBJTk5FRF9DQSkKICAgIGlmIGNsaWVudDoKICAg'
    'ICAgICBjb250ZXh0LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtl'
    'eS5wZW0nKSkKICAgIHNvY2sgPSBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGFkZHJlc3MsIDg0NDMpLCB0aW1lb3V0PXRp'
    'bWVvdXQpCiAgICB0cnk6CiAgICAgICAgdGxzID0gY29udGV4dC53cmFwX3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9'
    'aWRlbnRpdHkpCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBzb2NrLmNsb3NlKCkKICAgICAgICByYWlzZQog'
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
    'ZGRyZXNzIGluIChTRVJWRVIsKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAg'
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
    'ICB3cml0ZShST09ULydjb25uZWN0aW9uLmNvbmYnLCBmJycnY29ubmVjdGlvbnMge3sKIHtMQVlPVVQuaWtlfSB7ewogIHZl'
    'cnNpb24gPSAyCiAgcmVtb3RlX2FkZHJzID0ge2FkZHJlc3N9CiAgcmVtb3RlX3BvcnQgPSB7QUNUSVZFWydwb3J0J119CiAg'
    'bG9jYWxfcG9ydCA9IDQ1MDAKICB2aXBzID0gMC4wLjAuMAogIHByb3Bvc2FscyA9IGFlczI1NmdjbTE2LXByZnNoYTM4NC1l'
    'Y3AzODQKICBlbmNhcCA9IHllcwogIGZyYWdtZW50YXRpb24gPSB5ZXMKICBtb2Jpa2UgPSB5ZXMKICBkcGRfZGVsYXkgPSAx'
    'NXMKICBsb2NhbCB7eyBhdXRoID0gZWFwLXRsczsgaWQgPSB7aWRlbnRpdHl9OyBlYXBfaWQgPSB7aWRlbnRpdHl9OyBjZXJ0'
    'cyA9IHtST09UfS9jbGllbnQucGVtIH19CiAgcmVtb3RlIHt7IGF1dGggPSBwdWJrZXk7IGlkID0ge0FDVElWRVsnaWRlbnRp'
    'dHknXX07IGNhY2VydHMgPSB7Uk9PVH0vY2EucGVtIH19CiAgY2hpbGRyZW4ge3sKICAge0xBWU9VVC5pa2V9LW5ldCB7ewog'
    'ICAgbG9jYWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAg'
    'ZXNwX3Byb3Bvc2FscyA9IGNoYWNoYTIwcG9seTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9u'
    'ID0gbm9uZQogICB9fQogIH19CiB9fQp9fQpzZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUgPSB7Uk9PVH0vY2xp'
    'ZW50LWtleS5wZW0gfX0gfX0KJycnKQogICAgIyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVzLCBub3Qgc2VtaWNv'
    'bG9uIHNlcGFyYXRvcnMgKG5vcm1hbGl6ZSBjb21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAoJ3N0cm9uZ3N3YW4u'
    'Y29uZicsICdjb25uZWN0aW9uLmNvbmYnKToKICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAgcGF0aC53cml0ZV90'
    'ZXh0KHBhdGgucmVhZF90ZXh0KCkucmVwbGFjZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4nKS5yZXBsYWNlKCcg'
    'fScsICdcbn0nKSkKICAgIHJ1bGVzID0gZicnJ3RhYmxlIGluZXQge05BTUVTUEFDRV9HVUFSRH0ge3sKIGNoYWluIG91dHB1'
    'dCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8i'
    'IGFjY2VwdAogIGlwIGRhZGRyIDEyNy4wLjAuMSB1ZHAgZHBvcnQgMjQ1NzMgYWNjZXB0CiAgb2lmbmFtZSAie0ZVTExfUEVF'
    'Un0iIGlwIGRhZGRyIDE3Mi4yOS4yNDcuMSBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggc3BvcnQgNTMgYWNjZXB0'
    'CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFjY2VwdAogIGlwIGRhZGRyIDM4LjE4'
    'MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpcCBkYWRkciAxOTUuMjA5LjIxMS4xNjMg'
    'dGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIG1ldGEgc2t1aWQgMCBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMg'
    'YWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaXBzZWMgb3V0IHJlcWlkIHtSRVFJRH0gYWNjZXB0CiB9fQogY2hhaW4gZm9y'
    'd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTEwOyBwb2xpY3kgZHJvcDsgfX0KfX0nJycKICAg'
    'IGluc2lkZShbJ25mdCcsICctYycsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICBpbnNpZGUoWyduZnQnLCAnLWYnLCAn'
    'LSddLCBkYXRhPXJ1bGVzKQoKCmRlZiBzd2FuKCphcmdzLCB0aW1lb3V0PTE1LCBjaGVjaz1UcnVlKToKICAgIHJldHVybiBp'
    'bnNpZGUoWydzd2FuY3RsJywgKmFyZ3MsICctLXVyaScsICd1bml4Oi8vJytzdHIoUlVOVElNRS8nY2hhcm9uLnZpY2knKV0s'
    'IHRpbWVvdXQ9dGltZW91dCwgY2hlY2s9Y2hlY2spCgoKZGVmIGluc3RhbGxlZCgpOgogICAgdHJ5OgogICAgICAgIHJlc3Vs'
    'dCA9IHN3YW4oJy0tbGlzdC1zYXMnLCAnLS1yYXcnLCB0aW1lb3V0PTMsIGNoZWNrPUZhbHNlKQogICAgICAgIHJldHVybiBy'
    'ZXN1bHQucmV0dXJuY29kZSA9PSAwIGFuZCAnc3RhdGU9RVNUQUJMSVNIRUQnIGluIHJlc3VsdC5zdGRvdXQgYW5kICdzdGF0'
    'ZT1JTlNUQUxMRUQnIGluIHJlc3VsdC5zdGRvdXQKICAgIGV4Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhw'
    'aXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCgoKZGVmIGhlYWx0aCgpOgogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAg'
    'ICByZXR1cm4gdGxzX3JlcXVlc3QoSEVBTFRILCAnL2hlYWx0aCcsIGNsaWVudD1UcnVlLCBpZGVudGl0eT1BQ1RJVkVbJ2lk'
    'ZW50aXR5J10sIHRpbWVvdXQ9MykuZ2V0KCdzZXJ2aWNlJykgaW4gKCdldmdlbml1bS12cG4nLCAnZXZnZW5pdW0tc3RhcmZp'
    'dmUnKQoKCmRlZiBkb3dubG9hZChzaXplPTEwNDg1NzYpOgogICAgIyBBIGJvdW5kZWQgaW50ZWdyaXR5IGNoZWNrLCBub3Qg'
    'YSBjbGFpbSB0byBoYXZlIG1lYXN1cmVkIHRoZSBJU1AncyBtYXhpbXVtIHJhdGUuCiAgICAjIFByb3RvY29sIHYxIHVzZXMg'
    'dGhpcyBmaXhlZCBzZWVkIG9uIGRlcGxveWVkIGNvbGxlY3RvcnMgYW5kIGVhcmxpZXIgY2xpZW50cy4KICAgIGJsb2NrID0g'
    'aGFzaGxpYi5zaGFrZV8yNTYoYidldmdlbml1bS1zdGFyZml2ZS1pbnRlZ3JpdHktdjEnKS5kaWdlc3QoNjU1MzYpCiAgICBl'
    'eHBlY3RlZCA9IGhhc2hsaWIuc2hhMjU2KChibG9jayooc2l6ZS8vbGVuKGJsb2NrKSsxKSlbOnNpemVdKS5oZXhkaWdlc3Qo'
    'KQogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZGF0YT1QSU5ORURfQ0EpCiAgICBjb250ZXh0'
    'LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkKICAg'
    'IHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoSEVBTFRILCA4NDQz'
    'KSwgdGltZW91dD0xMCkKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1B'
    'Q1RJVkVbJ2lkZW50aXR5J10pCiAgICAgICAgY29ubmVjdGlvbiA9IGh0dHAuY2xpZW50LkhUVFBDb25uZWN0aW9uKEhFQUxU'
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
    'dC5wZW0nLCAncmFua2luZy5qc29uJywgJ3JlY2FsaWJyYXRlJywgJ2V2ZW50cy5qc29uJywgJ3N1cHBvcnQtcHJldmlldy5q'
    'c29uJyk6CiAgICAgICAgKFJPT1QvbmFtZSkudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIHdyaXRlKFJPT1QvJ3Rva2Vu'
    'JywgdG9rZW4pCiAgICBzeW5jX2RldmljZV9uYW1lKCkKICAgIHN0YWdlKCdvZmYnLCAn0KLQvtC60LXQvSDRgdC+0YXRgNCw'
    '0L3RkdC9LiDQndCw0LbQvNC40YLQtSDCq9Cf0L7QtNC60LvRjtGH0LjRgtGMwrsuJywgMCwgYWN0aXZlPUZhbHNlLCBtZXRy'
    'aWNzPXt9KQoKCmRlZiBwYW5pY19lbmFibGVkKCk6CiAgICB0cnk6cmV0dXJuIGpzb24ubG9hZHMoKFJPT1QvJ3BhbmljLmpz'
    'b24nKS5yZWFkX3RleHQoKSkuZ2V0KCdlbmFibGVkJykgaXMgVHJ1ZQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3Is'
    'QXR0cmlidXRlRXJyb3IpOnJldHVybiBGYWxzZQoKCmRlZiBzZXRfcGFuaWMoZW5hYmxlZCk6CiAgICBpZiB0eXBlKGVuYWJs'
    'ZWQpIGlzIG5vdCBib29sOnJhaXNlIFZhbHVlRXJyb3IoJ3BhbmljIGV4cGVjdHMgYSBib29sZWFuJykKICAgIHdyaXRlKFJP'
    'T1QvJ3BhbmljLmpzb24nLGpzb24uZHVtcHMoeydlbmFibGVkJzplbmFibGVkfSkpCiAgICBpZiBlbmFibGVkOgogICAgICAg'
    'IGNvbm5lY3QocmVzdGFydD1UcnVlKQogICAgZWxzZToKICAgICAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZGlzYWJsZScs'
    'VU5JVF0sY2hlY2s9RmFsc2UpCiAgICAgICAgaWYgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsJy0tcXVpZXQn'
    'LFVOSVRdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlPT0wOgogICAgICAgICAgICBjb25uZWN0KHJlc3RhcnQ9VHJ1ZSkKCgpk'
    'ZWYgcmVjb3ZlcnlfcGF1c2Uoc2Vjb25kcyk6CiAgICAjIEtlZXAgU0lHVEVSTSByZXNwb25zaXZlIGV2ZW4gZHVyaW5nIGFu'
    'IGluZGVmaW5pdGVseSBsb25nIG91dGFnZS4KICAgIGZvciBfIGluIHJhbmdlKGludChzZWNvbmRzKjEwKSk6CiAgICAgICAg'
    'aWYgU1RPUDpyZXR1cm4KICAgICAgICB0aW1lLnNsZWVwKC4xKQoKCmRlZiByZWNvdmVyeV9yb3V0ZShyYW5rLGN1cnJlbnQs'
    'c2VsZWN0ZWQscGFuaWM9RmFsc2UpOgogICAgaWYgcGFuaWMgb3Igc2VsZWN0ZWQ9PSdhdXRvJzoKICAgICAgICByZXR1cm4g'
    'cmFuay5uZXh0X2FmdGVyKGN1cnJlbnQpIG9yIG5leHQoaXRlcihyYW5rLmNhbmRpZGF0ZXMoKSksTm9uZSkKICAgIHJldHVy'
    'biBjdXJyZW50CgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFpcj1GYWxzZSwgcmVzdGFydD1GYWxzZSk6CiAgICBST09U'
    'Lm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNh'
    'dmVfdG9rZW4odG9rZW4pCiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZh'
    'bHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC9'
    '0YLQsC4nKQogICAgZW5zdXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUoUk9PVC8ncmVj'
    'YWxpYnJhdGUnLCAnMScpCiAgICBwYW5pYyA9IHBhbmljX2VuYWJsZWQoKQogICAgd3JpdGUoVU5JVF9ESVIgLyBVTklULCB1'
    'bml0X3RleHQoTEFZT1VULCAndW5pdCcsIHBhbmljPXBhbmljKSwgbW9kZT0wbzY0NCkKICAgIHdyaXRlKFVOSVRfRElSIC8g'
    'UkVDT1ZFUllfVU5JVCwgdW5pdF90ZXh0KExBWU9VVCwgJ3JlY292ZXJ5JyksIG1vZGU9MG82NDQpCiAgICBjb21tYW5kKFsn'
    'c3lzdGVtY3RsJywgJ2RhZW1vbi1yZWxvYWQnXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZW5hYmxlJywgUkVDT1ZF'
    'UllfVU5JVF0pCiAgICBpZiBwYW5pYzoKICAgICAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2VuYWJsZScsIFVOSVRdKQog'
    'ICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ3Jlc2V0LWZhaWxlZCcsVU5JVF0sY2hlY2s9RmFsc2UpCiAgICBzdGFnZSgnc3Rh'
    'cnRpbmcnICwgJ9CT0L7RgtC+0LLQu9GOINC/0L7QtNC60LvRjtGH0LXQvdC40LUg0LIg0K3RgdGC0L7QvdC40Y4uJywgMiwg'
    'YWN0aXZlPUZhbHNlLCByZXRyeT0wLCBlcnJvcl9jb2RlPScnKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdyZXN0YXJ0'
    'JyBpZiByZXBhaXIgb3IgcmVzdGFydCBlbHNlICdzdGFydCcsIFVOSVRdKQogICAgcHJpbnQoJ1ZQTiDQt9Cw0L/Rg9GB0LrQ'
    'sNC10YLRgdGPLicsZmx1c2g9VHJ1ZSkKCgpkZWYgZGlzY29ubmVjdCgpOgogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2Rp'
    'c2FibGUnLFVOSVRdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdzdG9wJywgVU5JVF0sIGNoZWNr'
    'PUZhbHNlLCB0aW1lb3V0PTI1KQogICAgY2xlYW51cCgpCiAgICBjbGVhbnVwX2Z1bGwocmVsZWFzZT1UcnVlKQogICAgc3Rh'
    'Z2UoJ29mZicsICdWUE4g0LLRi9C60LvRjtGH0LXQvS4nLCAwLCBhY3RpdmU9RmFsc2UpCiAgICBwcmludCgnVlBOINCy0YvQ'
    'utC70Y7Rh9C10L0uJykKCgpkZWYgc3RhcnRfZGFlbW9uKGVudik6CiAgICAoUlVOVElNRS8nY2hhcm9uLnZpY2knKS51bmxp'
    'bmsobWlzc2luZ19vaz1UcnVlKQogICAgbG9nID0gKFJPT1QvJ2NoYXJvbi5sb2cnKS5vcGVuKCd3JykKICAgIGRhZW1vbiA9'
    'IHN1YnByb2Nlc3MuUG9wZW4oWydpcCcsICduZXRucycsICdleGVjJywgTlMsIGNoYXJvbl9iaW5hcnkoKV0sCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIGVudj1lbnYsIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCwgc3Rkb3V0PWxvZywgc3Rk'
    'ZXJyPWxvZykKICAgIGxvZy5jbG9zZSgpCiAgICB0cnk6CiAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNjApOgogICAgICAgICAg'
    'ICBpZiBTVE9QIG9yIGRhZW1vbi5wb2xsKCkgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ2RhZW1vbl9zdG9wcGVkJykKICAgICAgICAgICAgaWYgKFJVTlRJTUUvJ2NoYXJvbi52aWNpJykuZXhpc3RzKCkgYW5k'
    'IHN3YW4oJy0tc3RhdHMnLCBjaGVjaz1GYWxzZSwgdGltZW91dD0xKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgICAgICAg'
    'ICBicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgIHN3YW4oJy0tbG9hZC1jcmVkcycsICctLW5vcHJv'
    'bXB0JywgJy0tZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgc3dhbignLS1sb2FkLWNvbm5zJywgJy0t'
    'ZmlsZScsIFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicpCiAgICAgICAgcmV0dXJuIGRhZW1vbgogICAgZXhjZXB0IEJhc2VFeGNl'
    'cHRpb246CiAgICAgICAgc3RvcF9wcm9jZXNzKGRhZW1vbikKICAgICAgICByYWlzZQoKCmRlZiBzdG9wX3Byb2Nlc3MocHJv'
    'Y2Vzcyk6CiAgICBpZiBwcm9jZXNzIGlzIG5vdCBOb25lIGFuZCBwcm9jZXNzLnBvbGwoKSBpcyBOb25lOgogICAgICAgIHBy'
    'b2Nlc3MudGVybWluYXRlKCkKICAgICAgICB0cnk6cHJvY2Vzcy53YWl0KHRpbWVvdXQ9NSkKICAgICAgICBleGNlcHQgc3Vi'
    'cHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDpwcm9jZXNzLmtpbGwoKTtwcm9jZXNzLndhaXQodGltZW91dD0zKQoKCmRlZiBzdG9w'
    'X2NhbmRpZGF0ZShkYWVtb249Tm9uZSk6CiAgICBnbG9iYWwgVExTX1BST0NFU1MKICAgIHN0b3BfcHJvY2VzcyhkYWVtb24p'
    'CiAgICBzdG9wX3Byb2Nlc3MoVExTX1BST0NFU1MpO1RMU19QUk9DRVNTPU5vbmUKICAgIGNsZWFudXAoKQoKCmRlZiBwcmVw'
    'YXJlX2RhdGFfcGxhbmUoYWRkcmVzcyk6CiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAgIGlmIFBh'
    'dGgoJy9zeXMvY2xhc3MvbmV0LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9y'
    'KCdmdWxsX2ludGVyZmFjZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3Rh'
    'YmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcignZnVsbF90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3Rh'
    'YmxlJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1l'
    'RXJyb3IoJ2FkbWluX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgYW55KHIuZ2V0KCdwcmlvcml0eScpIGluICg3OSw4'
    'MCkgZm9yIHIgaW4ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCctaicsJy00JywncnVsZSddKS5zdGRvdXQpKToKICAgICAg'
    'ICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3J1bGVfY29sbGlzaW9uJykKICAgICAgICB3cml0ZShmdWxsX3N0YXRl'
    'KCksanNvbi5kdW1wcyh7J2FjdGl2ZSc6RmFsc2UsJ21lYXN1cmVtZW50X29ubHknOlRydWV9KSkKICAgIGZ1bGxfbmFtZXNw'
    'YWNlKGFkZHJlc3MpCiAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKCgpkZWYgc3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxp'
    'ZGVudGl0eSk6CiAgICBnbG9iYWwgQUNUSVZFLFRMU19QUk9DRVNTCiAgICBBQ1RJVkU9Y2FuZGlkYXRlCiAgICB3cml0ZShS'
    'T09ULydhY3RpdmUtcGF0aC5qc29uJyxqc29uLmR1bXBzKHsnaWQnOmNhbmRpZGF0ZVsnaWQnXX0pKQogICAgc2V0dXBfbmV0'
    'd29yaygpCiAgICBkYWVtb25fY29uZmlncyhpZGVudGl0eSxjYW5kaWRhdGVbJ2FkZHJlc3MnXSkKICAgIGlmIGNhbmRpZGF0'
    'ZVsndGxzJ10gb3IgY2FuZGlkYXRlLmdldCgnZXZndCcpOgogICAgICAgIGlmIGNhbmRpZGF0ZS5nZXQoJ2V2Z3QnKToKICAg'
    'ICAgICAgICAgYmluYXJ5PWVuc3VyZV9ldmd0X2JpbmFyeSgpCiAgICAgICAgICAgIGNhcnJpZXI9W3N0cihiaW5hcnkpLCct'
    'bW9kZScsJ2NsaWVudCcsJy1zZXJ2ZXInLGNhbmRpZGF0ZS5nZXQoJ3RyYW5zcG9ydF9hZGRyZXNzJyxjYW5kaWRhdGVbJ2Fk'
    'ZHJlc3MnXSkrJzonK3N0cihjYW5kaWRhdGUuZ2V0KCd0cmFuc3BvcnRfcG9ydCcsMjQ1NzgpKSwnLXNlcnZlci1uYW1lJyxj'
    'YW5kaWRhdGVbJ2lkZW50aXR5J10sCiAgICAgICAgICAgICAgICAgICAgICctdWRwLWxpc3RlbicsJzEyNy4wLjAuMToyNDU3'
    'MycsJy11ZHAtcGVlcicsQ0xJRU5UKyc6NDUwMCcsCiAgICAgICAgICAgICAgICAgICAgICctY2EnLHN0cihST09ULydjYS5w'
    'ZW0nKSwnLWNlcnQnLHN0cihST09ULydjbGllbnQucGVtJyksJy1rZXknLHN0cihST09ULydjbGllbnQta2V5LnBlbScpXQog'
    'ICAgICAgIGVsc2U6Y2Fycmllcj1bJy91c3IvbG9jYWwvc2Jpbi92cG5jdGwnLCdpbnRlcm5hbC10bHMtY2xpZW50J10KICAg'
    'ICAgICBUTFNfUFJPQ0VTUz1zdWJwcm9jZXNzLlBvcGVuKFsnaXAnLCduZXRucycsJ2V4ZWMnLE5TLCpjYXJyaWVyXSwKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZGluPXN1YnByb2Nlc3MuREVWTlVMTCxzdGRvdXQ9c3VicHJv'
    'Y2Vzcy5ERVZOVUxMLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkZXJyPU5vbmUgaWYgY2FuZGlk'
    'YXRlLmdldCgnZXZndCcpIGVsc2Ugc3VicHJvY2Vzcy5ERVZOVUxMKQogICAgICAgIGZvciBfIGluIHJhbmdlKDUwKToKICAg'
    'ICAgICAgICAgaWYgU1RPUDpyYWlzZSBSdW50aW1lRXJyb3IoJ2NhbmNlbGxlZCcpCiAgICAgICAgICAgIGlmIFRMU19QUk9D'
    'RVNTLnBvbGwoKSBpcyBub3QgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3Rsc19jYXJyaWVyX3N0b3BwZWQnKQogICAgICAg'
    'ICAgICBpZiAnMTI3LjAuMC4xOjI0NTczJyBpbiBpbnNpZGUoWydzcycsJy1hbnUnXSxjaGVjaz1GYWxzZSkuc3Rkb3V0OmJy'
    'ZWFrCiAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgZWxzZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3Rsc19jYXJy'
    'aWVyX25vdF9yZWFkeScpCiAgICAgICAgaW5zaWRlKFsnbmZ0JywnLWYnLCctJ10sZGF0YT0ndGFibGUgaXAgZXZuX3Rsc19j'
    'YXJyaWVyIHtcbiBjaGFpbiBvdXRwdXQge1xuIHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IGRzdG5hdDsgcG9saWN5'
    'IGFjY2VwdDtcbiBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHVkcCBkcG9ydCA0NDMgcmVkaXJlY3QgdG8gOjI0NTczXG4gfVxu'
    'fVxuJykKICAgIGVudj17Kipvcy5lbnZpcm9uLCdTVFJPTkdTV0FOX0NPTkYnOnN0cihST09ULydzdHJvbmdzd2FuLmNvbmYn'
    'KX07ZW52LnBvcCgnTk9USUZZX1NPQ0tFVCcsTm9uZSkKICAgIGRhZW1vbj1zdGFydF9kYWVtb24oZW52KQogICAgdHJ5Ogog'
    'ICAgICAgIHN3YW4oJy0taW5pdGlhdGUnLCctLWNoaWxkJyxMQVlPVVQuaWtlKyctbmV0Jyx0aW1lb3V0PTM1KQogICAgICAg'
    'IGlmIFNUT1A6cmFpc2UgUnVudGltZUVycm9yKCdjYW5jZWxsZWQnKQogICAgICAgIGlmIG5vdCBpbnN0YWxsZWQoKTpyYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ2hhbmRzaGFrZV9mYWlsZWQnKQogICAgICAgIHByZXBhcmVfZGF0YV9wbGFuZShjYW5kaWRhdGVb'
    'J2FkZHJlc3MnXSkKICAgICAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOnJhaXNlIFJ1bnRpbWVFcnJvcignZXN0b25pYV9l'
    'Z3Jlc3NfZmFpbGVkJykKICAgICAgICByZXR1cm4gZGFlbW9uCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBz'
    'dG9wX3Byb2Nlc3MoZGFlbW9uKTtyYWlzZQoKCmRlZiBzcGVlZF9zYW1wbGUoc2l6ZT0yMDk3MTUyKToKICAgICIiIkJvdW5k'
    'ZWQgc3ludGhldGljIGJpZGlyZWN0aW9uYWwgcHJvYmU7IG5ldmVyIHJlYWRzIHVzZXIgZmlsZXMuIiIiCiAgICBwYXlsb2Fk'
    'PVJPT1QvJ3NwZWVkLXBheWxvYWQuYmluJwogICAgaWYgbm90IHBheWxvYWQuZXhpc3RzKCkgb3IgcGF5bG9hZC5zdGF0KCku'
    'c3Rfc2l6ZSE9c2l6ZToKICAgICAgICB3aXRoIHBheWxvYWQub3Blbignd2InKSBhcyBmOgogICAgICAgICAgICBmb3IgXyBp'
    'biByYW5nZShzaXplLy82NTUzNik6Zi53cml0ZShzZWNyZXRzLnRva2VuX2J5dGVzKDY1NTM2KSkKICAgICAgICBwYXlsb2Fk'
    'LmNobW9kKDBvNjAwKQogICAgYmFzZT1bJ2N1cmwnLCctNCcsJy0tbm9wcm94eScsJyonLCctLWZhaWwnLCctLXNpbGVudCcs'
    'Jy0tc2hvdy1lcnJvcicsJy0tY29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCcxMicsCiAgICAgICAgICAnLS1v'
    'dXRwdXQnLCcvZGV2L251bGwnLCctLXdyaXRlLW91dCcsJyV7aHR0cF9jb2RlfSAle3NpemVfZG93bmxvYWR9ICV7c2l6ZV91'
    'cGxvYWR9ICV7dGltZV90b3RhbH0gJXt0aW1lX2Nvbm5lY3R9J10KICAgIHJlc3VsdHM9W10KICAgIGZvciBkaXJlY3Rpb24g'
    'aW4gKCdkb3duJywndXAnKToKICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVkJykKICAgICAg'
    'ICBleHRyYT1bJ2h0dHBzOi8vc3BlZWQuY2xvdWRmbGFyZS5jb20vX19kb3duP2J5dGVzPScrc3RyKHNpemUpXSBpZiBkaXJl'
    'Y3Rpb249PSdkb3duJyBlbHNlIFsnLS1kYXRhLWJpbmFyeScsJ0AnK3N0cihwYXlsb2FkKSwnaHR0cHM6Ly9zcGVlZC5jbG91'
    'ZGZsYXJlLmNvbS9fX3VwJ10KICAgICAgICByPWluc2lkZShiYXNlK2V4dHJhLHRpbWVvdXQ9MTQsY2hlY2s9RmFsc2UpCiAg'
    'ICAgICAgdHJ5OgogICAgICAgICAgICBjb2RlLGRvd24sdXAsZWxhcHNlZCxsYXRlbmN5PXIuc3Rkb3V0LnNwbGl0KCkKICAg'
    'ICAgICAgICAgY291bnQ9ZmxvYXQoZG93biBpZiBkaXJlY3Rpb249PSdkb3duJyBlbHNlIHVwKQogICAgICAgICAgICBpZiBy'
    'LnJldHVybmNvZGUgb3IgY29kZSE9JzIwMCcgb3IgY291bnQ8c2l6ZTpyYWlzZSBWYWx1ZUVycm9yKCkKICAgICAgICAgICAg'
    'cmVzdWx0cy5hcHBlbmQoKGNvdW50KjgvbWF4KC4wMDEsZmxvYXQoZWxhcHNlZCkpLzFlNixmbG9hdChsYXRlbmN5KSoxMDAw'
    'KSkKICAgICAgICBleGNlcHQgKFZhbHVlRXJyb3IsVHlwZUVycm9yKTpyZXR1cm4geydhdmFpbGFibGUnOkZhbHNlfQogICAg'
    'cmV0dXJuIHsnYXZhaWxhYmxlJzpUcnVlLCdkb3dubG9hZF9tYnBzJzpyb3VuZChyZXN1bHRzWzBdWzBdLDIpLCd1cGxvYWRf'
    'bWJwcyc6cm91bmQocmVzdWx0c1sxXVswXSwyKSwKICAgICAgICAgICAgJ2xhdGVuY3lfbXMnOnJvdW5kKG1heCh4WzFdIGZv'
    'ciB4IGluIHJlc3VsdHMpLDEpLCdzYW1wbGVfYnl0ZXMnOnNpemV9CgoKZGVmIHRyYWZmaWNfdG90YWwoKToKICAgIHRyeToK'
    'ICAgICAgICBzdGF0cz1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL0ZVTExfSE9TVC8nc3RhdGlzdGljcycKICAgICAgICByZXR1'
    'cm4gc3VtKGludCgoc3RhdHMvbmFtZSkucmVhZF90ZXh0KCkpIGZvciBuYW1lIGluICgncnhfYnl0ZXMnLCd0eF9ieXRlcycp'
    'KQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnJldHVybiAwCgoKZGVmIHNwZWVkX2RlZ3JhZGVkKHNhbXBsZSxi'
    'YXNlbGluZSk6CiAgICAjIFJlcXVpcmUgdXNhYmxlIHNhbXBsZXMgYW5kIGEgbWVhbmluZ2Z1bCBiYXNlbGluZSBpbiB0aGUg'
    'YWZmZWN0ZWQgZGlyZWN0aW9uLgogICAgcmV0dXJuIGJvb2woc2FtcGxlLmdldCgnYXZhaWxhYmxlJykgYW5kIGFueSgKICAg'
    'ICAgICBiYXNlbGluZS5nZXQoaywwKT49MiBhbmQgc2FtcGxlLmdldChrLDApPGJhc2VsaW5lW2tdKi4yCiAgICAgICAgZm9y'
    'IGsgaW4gKCdkb3dubG9hZF9tYnBzJywndXBsb2FkX21icHMnKSkpCgoKZGVmIHdvcmtlcigpOgogICAgZ2xvYmFsIFNUT1AK'
    'ICAgIFNUT1A9RmFsc2UKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1RFUk0sbGFtYmRhICpfOmdsb2JhbHMoKS5fX3Nl'
    'dGl0ZW1fXygnU1RPUCcsVHJ1ZSkpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdJTlQsbGFtYmRhICpfOmdsb2JhbHMo'
    'KS5fX3NldGl0ZW1fXygnU1RPUCcsVHJ1ZSkpCiAgICBhdHRlbXB0cz0wCiAgICB3aGlsZSBub3QgU1RPUDoKICAgICAgICB3'
    'b3JrZXJfb25jZSgpCiAgICAgICAgaWYgU1RPUCBvciBub3QgcGFuaWNfZW5hYmxlZCgpOnJldHVybgogICAgICAgIGF0dGVt'
    'cHRzKz0xCiAgICAgICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Cf0LDQvdC40YfQtdGB0LrQuNC5INC/0L7QuNGB0Lo6INC/0L7Q'
    'stGC0L7RgNGP0Y4g0L/QvtC00LPQvtGC0L7QstC60YMgVlBOLicsNSwKICAgICAgICAgICAgICBhY3RpdmU9RmFsc2UscmV0'
    'cnk9YXR0ZW1wdHMpCiAgICAgICAgcmVjb3ZlcnlfcGF1c2UobWluKDMwLDUqYXR0ZW1wdHMpKQoKCmRlZiB3b3JrZXJfb25j'
    'ZSgpOgogICAgZGFlbW9uPU5vbmUKICAgIHJhbms9cmFua19hcGkuUmFua2luZyhST09ULydyYW5raW5nLmpzb24nLFt4Wydp'
    'ZCddIGZvciB4IGluIENBTkRJREFURVNdKQogICAgdHJ5OgogICAgICAgIGNsZWFudXAoKTtyZWZyZXNoX3JldGFpbmVkX2d1'
    'YXJkKCkKICAgICAgICBzdGFnZSgncHJlcGFyZScsJ9CT0L7RgtC+0LLQu9GOINC30LDRidC40YnRkdC90L3Ri9C1INC80LDR'
    'gNGI0YDRg9GC0YsuJyw1LGFjdGl2ZT1GYWxzZSxtZXRyaWNzPXt9LGVycm9yX2NvZGU9Jycsc2NvcGU9J3NlbGVjdGVkJyBp'
    'ZiBwb2xpY3kgaXMgbm90IE5vbmUgYW5kIHBvbGljeS5pbmNsdXNpdmUocG9saWN5LmxvYWQoKSkgZWxzZSAnZnVsbC1kZXZp'
    'Y2UnLHJvdXRpbmdfd29ya2VyX3BpZD1vcy5nZXRwaWQoKSkKICAgICAgICBzZXR1cF9uZXR3b3JrKCkKICAgICAgICBpZGVu'
    'dGl0eSxfPWVucm9sbCgpCiAgICAgICAgc3luY19kZXZpY2VfbmFtZSgpCiAgICAgICAgY2xlYW51cCgpCiAgICAgICAgbG9h'
    'ZGVkPXJhbmsubG9hZCgpCiAgICAgICAgc2VsZWN0ZWQ9c2VsZWN0ZWRfcm91dGUoKQogICAgICAgIHJlYnVpbGQ9KFJPT1Qv'
    'J3JlY2FsaWJyYXRlJykuZXhpc3RzKCkgb3IgKHNlbGVjdGVkPT0nYXV0bycgYW5kIG5vdCBsb2FkZWQpCiAgICAgICAgaWYg'
    'bm90IGxvYWRlZDpyYW5rLmJvb3RzdHJhcCgpCiAgICAgICAgaWYgcmVidWlsZCBhbmQgbm90IHBhbmljX2VuYWJsZWQoKToK'
    'ICAgICAgICAgICAgbWVhc3VyZW1lbnRzPXt9CiAgICAgICAgICAgIGZvciBpLGNhbmRpZGF0ZSBpbiBlbnVtZXJhdGUoQ0FO'
    'RElEQVRFUyk6CiAgICAgICAgICAgICAgICBpZiBTVE9QOnJldHVybgogICAgICAgICAgICAgICAgc3RhZ2UoJ3Jhbmtpbmcn'
    'LCfQn9GA0L7QstC10YDRj9GOINC80LDRgNGI0YDRg9GCOiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSwxMCtpbnQoaSo2MC9sZW4o'
    'Q0FORElEQVRFUykpLGFjdGl2ZT1GYWxzZSxwYXRoPWNhbmRpZGF0ZVsnaWQnXSkKICAgICAgICAgICAgICAgIHRyeToKICAg'
    'ICAgICAgICAgICAgICAgICBkYWVtb249c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVudGl0eSkKICAgICAgICAgICAg'
    'ICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGludGVncml0eT1kb3dubG9hZCgxMDQ4NTc2KVsnaW50ZWdy'
    'aXR5J10KICAgICAgICAgICAgICAgICAgICBleGNlcHQgUnVudGltZUVycm9yIGFzIGVycm9yOgogICAgICAgICAgICAgICAg'
    'ICAgICAgICBpZiBzdHIoZXJyb3IpPT0naW50ZWdyaXR5X2ZhaWxlZCc6cmFpc2UKICAgICAgICAgICAgICAgICAgICAgICAg'
    'aW50ZWdyaXR5PU5vbmUKICAgICAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixzdWJwcm9jZXNz'
    'LlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PU5vbmUKICAgICAgICAgICAgICAg'
    'ICAgICBtZWFzdXJlbWVudHNbY2FuZGlkYXRlWydpZCddXT17J29rJzpUcnVlLCoqc3BlZWRfc2FtcGxlKDIwOTcxNTIpLCdp'
    'bnRlZ3JpdHknOmludGVncml0eX0KICAgICAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVF'
    'cnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgICAgICAgICBpZiBTVE9QOnJldHVybgogICAg'
    'ICAgICAgICAgICAgICAgIG1lYXN1cmVtZW50c1tjYW5kaWRhdGVbJ2lkJ11dPXsnb2snOkZhbHNlfQogICAgICAgICAgICAg'
    'ICAgZmluYWxseToKICAgICAgICAgICAgICAgICAgICBzdG9wX2NhbmRpZGF0ZShkYWVtb24pO2RhZW1vbj1Ob25lCiAgICAg'
    'ICAgICAgIHJhbmsuYnVpbGQobWVhc3VyZW1lbnRzKQogICAgICAgICAgICAoUk9PVC8ncmVjYWxpYnJhdGUnKS51bmxpbmso'
    'bWlzc2luZ19vaz1UcnVlKQogICAgICAgIGNhbmRpZGF0ZXM9e3hbJ2lkJ106eCBmb3IgeCBpbiBDQU5ESURBVEVTfQogICAg'
    'ICAgIGN1cnJlbnQ9c2VsZWN0ZWQgaWYgc2VsZWN0ZWQhPSdhdXRvJyBlbHNlIG5leHQoaXRlcihyYW5rLmNhbmRpZGF0ZXMo'
    'KSksTm9uZSkKICAgICAgICB3aGlsZSBjdXJyZW50IGFuZCBub3QgU1RPUDoKICAgICAgICAgICAgY2FuZGlkYXRlPWNhbmRp'
    'ZGF0ZXNbY3VycmVudF0KICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc3RhZ2UoJ2hhbmRzaGFrZScsJ9Cf0L7Q'
    'tNC60LvRjtGH0LDRjjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sNzUsYWN0aXZlPUZhbHNlLHBhdGg9Y3VycmVudCkKICAgICAg'
    'ICAgICAgICAgIGRhZW1vbj1zdGFydF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KQogICAgICAgICAgICAgICAgc3Rh'
    'Z2UoJ3JvdXRpbmcnLCfQn9C+0LTQutC70Y7Rh9Cw0Y4g0YLRgNCw0YTQuNC6INC6INC/0YDQvtCy0LXRgNC10L3QvdC+0LzR'
    'gyDQvNCw0YDRiNGA0YPRgtGDLicsOTIpCiAgICAgICAgICAgICAgICBkbnNfd2FybmluZyA9IGFjdGl2YXRlX2Z1bGwoY2Fu'
    'ZGlkYXRlWydhZGRyZXNzJ10pCiAgICAgICAgICAgICAgICBzdGFnZSgnY29ubmVjdGVkJyxjb25uZWN0ZWRfbWVzc2FnZShj'
    'YW5kaWRhdGVbJ2xhYmVsJ10sIGRuc193YXJuaW5nKSwxMDAsYWN0aXZlPVRydWUscGF0aD1jdXJyZW50LAogICAgICAgICAg'
    'ICAgICAgICAgICAgbWV0cmljcz1yYW5rLmRhdGFbJ2VudHJpZXMnXVtjdXJyZW50XSxzaW5jZT1pbnQodGltZS50aW1lKCkp'
    'LGVycm9yX2NvZGU9JycpCiAgICAgICAgICAgICAgICBmYWlsdXJlcz0wO3Nsb3c9MDtsYXN0X3RyYWZmaWM9dHJhZmZpY190'
    'b3RhbCgpO25leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSs2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApCiAgICAgICAgICAg'
    'ICAgICB3aGlsZSBub3QgU1RPUDoKICAgICAgICAgICAgICAgICAgICBmb3IgXyBpbiByYW5nZSgyMCBpZiBwYW5pY19lbmFi'
    'bGVkKCkgZWxzZSA1MCk6CiAgICAgICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICAgICAgICAgICAgICBpZiBTVE9QOmJyZWFrCiAgICAgICAgICAgICAgICAg'
    'ICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6cG9saWN5LmVuc3VyZV9yb3V0'
    'ZSgpCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIEROU19QUk9DRVNTIGlzIE5vbmUgb3IgRE5TX1BST0NFU1MucG9sbCgp'
    'IGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ3JlcGFpcmluZycsJ9Cf0LXRgNC10LfQ'
    'sNC/0YPRgdC60LDRjiDQt9Cw0YnQuNGJ0ZHQvdC90YvQuSBETlMuJyw5MCxhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0ncHJp'
    'dmF0ZV9kbnNfc3RvcHBlZCcpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgaGVhbHRoeT1wYXRoX2hlYWx0aHkoZGFlbW9uKQogICAgICAgICAgICAgICAgICAgICAg'
    'ICBpZiBoZWFsdGh5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgZG5zX3dhcm5pbmcgPSBjaGVja19zeXN0ZW1fZG5z'
    'KCkKICAgICAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vz'
    'cy5UaW1lb3V0RXhwaXJlZCk6aGVhbHRoeT1GYWxzZQogICAgICAgICAgICAgICAgICAgIGZhaWx1cmVzPTAgaWYgaGVhbHRo'
    'eSBlbHNlIGZhaWx1cmVzKzEKICAgICAgICAgICAgICAgICAgICBpZiBmYWlsdXJlcz49MjpyYWlzZSBSdW50aW1lRXJyb3Io'
    'J3BhdGhfaGVhbHRoX2ZhaWxlZCcpCiAgICAgICAgICAgICAgICAgICAgaWYgbm90IGhlYWx0aHk6CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHN0YWdlKCdjaGVja2luZycsJ9Ce0YLQstC10YIg0LfQsNC00LXRgNC20LjQstCw0LXRgtGB0Y8uINCf0YDQ'
    'vtCy0LXRgNGP0Y4g0YLQtdC60YPRidC40Lkg0LzQsNGA0YjRgNGD0YIuJyw5MCxhY3RpdmU9RmFsc2UpCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICAgICAgaWYgdGltZS5tb25vdG9uaWMoKT49bmV4dF9zcGVl'
    'ZDoKICAgICAgICAgICAgICAgICAgICAgICAgdHJhZmZpYz10cmFmZmljX3RvdGFsKCkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgaWYgbm90IHNsb3cgYW5kIHRyYWZmaWMtbGFzdF90cmFmZmljPDQxOTQzMDQ6CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYztuZXh0X3NwZWVkPXRpbWUubW9ub3RvbmljKCkrNjAwK3NlY3JldHMucmFuZGJl'
    'bG93KDYwKQogICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgbGFzdF90'
    'cmFmZmljPXRyYWZmaWMKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhbXBsZT1zcGVlZF9zYW1wbGUoMjA5NzE1Mik7'
    'YmFzZWxpbmU9cmFuay5kYXRhWydlbnRyaWVzJ11bY3VycmVudF0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlZ3Jh'
    'ZGVkPXNwZWVkX2RlZ3JhZGVkKHNhbXBsZSxiYXNlbGluZSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNsb3c9c2xv'
    'dysxIGlmIGRlZ3JhZGVkIGVsc2UgMAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbmV4dF9zcGVlZD10aW1lLm1vbm90'
    'b25pYygpKygyMCBpZiBzbG93IGVsc2UgNjAwK3NlY3JldHMucmFuZGJlbG93KDYwKSkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIGlmIHNsb3c+PTM6cmFpc2UgUnVudGltZUVycm9yKCdjb25maXJtZWRfc3BlZWRfZHJvcCcpCiAgICAgICAgICAg'
    'ICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsY29ubmVjdGVkX21lc3NhZ2UoY2FuZGlkYXRlWydsYWJlbCddLCBkbnNfd2Fy'
    'bmluZyksMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCxlcnJvcl9jb2RlPScnKQogICAgICAgICAgICBleGNlcHQgKE9T'
    'RXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAg'
    'ICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgcmVhc29uPXN0cihleGMpIGlmIHJlLmZ1bGxtYXRjaCgn'
    'W2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlvbl9mYWlsZWQnCiAgICAgICAgICAgICAgICAjIEEgbWlz'
    'c2luZyBwaHlzaWNhbCBpbnRlcmZhY2UgaXMgbm90IGEgdHJhbnNwb3J0J3MgZGVmZWF0LgogICAgICAgICAgICAgICAgdHJ5'
    'OgogICAgICAgICAgICAgICAgICAgIHJvdXRlPXBoeXNpY2FsX3JvdXRlKCk7Y2Fycmllcj1QYXRoKCcvc3lzL2NsYXNzL25l'
    'dCcpL3JvdXRlWydkZXYnXS8nY2FycmllcicKICAgICAgICAgICAgICAgICAgICBvZmZsaW5lPWNhcnJpZXIuZXhpc3RzKCkg'
    'YW5kIGNhcnJpZXIucmVhZF90ZXh0KCkuc3RyaXAoKT09JzAnCiAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsUnVu'
    'dGltZUVycm9yKTpvZmZsaW5lPVRydWUKICAgICAgICAgICAgICAgIGlmIG5vdCBvZmZsaW5lOgogICAgICAgICAgICAgICAg'
    'ICAgIGN1cnJlbnQ9cmVjb3Zlcnlfcm91dGUocmFuayxjdXJyZW50LHNlbGVjdGVkLHBhbmljX2VuYWJsZWQoKSkKICAgICAg'
    'ICAgICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQodCy0Y/Qt9GMINC/0L7RgtC10YDRj9C90LAuINCf0LXRgNC10LrQu9GO'
    '0YfQsNGOINC30LDRidC40YnRkdC90L3Ri9C5INC80LDRgNGI0YDRg9GCLicgaWYgbm90IG9mZmxpbmUgZWxzZSAn0J7QttC4'
    '0LTQsNGOINCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40Y8g0YTQuNC30LjRh9C10YHQutC+0Lkg0YHQtdGC0LguJyw2NSwK'
    'ICAgICAgICAgICAgICAgICAgICAgIGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPXJlYXNvbikKICAgICAgICAgICAgICAgIHJl'
    'Y292ZXJ5X3BhdXNlKCgxIGlmIG5vdCBvZmZsaW5lIGVsc2UgMykgaWYgcGFuaWNfZW5hYmxlZCgpIGVsc2UgKDMgaWYgbm90'
    'IG9mZmxpbmUgZWxzZSAxMCkpCiAgICAgICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgICAgICBzdG9wX2NhbmRpZGF0ZShk'
    'YWVtb24pO2RhZW1vbj1Ob25lCiAgICAgICAgaWYgbm90IFNUT1A6CiAgICAgICAgICAgIHN0YWdlKCdmYWlsZWQnLCfQndC1'
    '0YIg0L3QsNGB0YLRgNC+0LXQvdC90YvRhSDQvNCw0YDRiNGA0YPRgtC+0LIuJywwLAogICAgICAgICAgICAgICAgICBhY3Rp'
    'dmU9RmFsc2UsZXJyb3JfY29kZT0ncmFua2luZ19leGhhdXN0ZWQnKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3Is'
    'UnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpIGFzIGV4YzoKICAgICAgICBpZiBub3QgU1RPUDoKICAg'
    'ICAgICAgICAgY29kZT1zdHIoZXhjKSBpZiByZS5mdWxsbWF0Y2goJ1thLXpfXXsxLDY0fScsc3RyKGV4YykpIGVsc2UgJ2Nv'
    'bm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTQ'
    's9C+0YLQvtCy0LjRgtGMIFZQTi4g0J3QsNC20LzQuNGC0LUgwqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuy4nLDAsYWN0'
    'aXZlPUZhbHNlLGVycm9yX2NvZGU9Y29kZSkKICAgIGZpbmFsbHk6CiAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKQog'
    'ICAgICAgIGlmIFNUT1A6c3RhZ2UoJ29mZicsJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsMCxhY3RpdmU9RmFsc2UpCg=='
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
    'ZWZhdWx0cygpOgogcmV0dXJuIHsnc2NoZW1hJzoxLCdtb2RlJzonYWxsJywnaW5jbHVkZSc6e2M6W10gZm9yIGMgaW4gQ0FU'
    'RUdPUklFU30sJ3dheWRyb2lkX2RpcmVjdCc6VHJ1ZSwnZGlzYWJsZWRfYmFzZSc6W10sICdhcHBsaWNhdGlvbnMnOltdLCAn'
    'bmV0d29ya3MnOltdLCAncG9ydHMnOltdLCAnZG5zJzpbXX0KCmRlZiBsb2FkKCk6CiBpZiBub3QgUEFUSC5leGlzdHMoKTpy'
    'ZXR1cm4gZGVmYXVsdHMoKQogdmFsdWU9anNvbi5sb2FkcyhQQVRILnJlYWRfdGV4dCgpKQogaWYgdmFsdWUuZ2V0KCdzY2hl'
    'bWEnKSE9MTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdCw0Y8g0LLQtdGA0YHQuNGPINC/0YDQsNCy'
    '0LjQuyDQuNGB0LrQu9GO0YfQtdC90LjQuS4nKQogcmVzdWx0PXsqKmRlZmF1bHRzKCksKip2YWx1ZX0KIGlmIHJlc3VsdFsn'
    'bW9kZSddIG5vdCBpbiAoJ2FsbCcsJ2luY2x1ZGUnKTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdGL'
    '0Lkg0YDQtdC20LjQvCDQvNCw0YDRiNGA0YPRgtC40LfQsNGG0LjQuC4nKQogcmVzdWx0WydpbmNsdWRlJ109eyoqZGVmYXVs'
    'dHMoKVsnaW5jbHVkZSddLCoqcmVzdWx0WydpbmNsdWRlJ119CiByZXR1cm4gcmVzdWx0CgpkZWYgaW5jbHVzaXZlKHApOnJl'
    'dHVybiBwLmdldCgnbW9kZScsJ2FsbCcpPT0naW5jbHVkZScKCmRlZiBzYXZlKHZhbHVlKToKIFBBVEgucGFyZW50Lm1rZGly'
    'KHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogdG1wPVBBVEgud2l0aF9zdWZmaXgoJy5uZXcnKQogZmQ9b3Mub3Blbih0'
    'bXAsb3MuT19XUk9OTFl8b3MuT19DUkVBVHxvcy5PX1RSVU5DfG9zLk9fTk9GT0xMT1csMG82MDApCiB3aXRoIG9zLmZkb3Bl'
    'bihmZCwndycpIGFzIGY6anNvbi5kdW1wKHZhbHVlLGYsZW5zdXJlX2FzY2lpPUZhbHNlLGluZGVudD0yKQogb3MucmVwbGFj'
    'ZSh0bXAsUEFUSCkKCmRlZiBlbmFibGVkKHAsY2F0LGtleSk6cmV0dXJuIGNhdCsnOicra2V5IG5vdCBpbiBwWydkaXNhYmxl'
    'ZF9iYXNlJ10KCmRlZiBub3JtYWxpemUoY2F0ZWdvcnksdmFsdWUpOgogdmFsdWU9c3RyKHZhbHVlKS5zdHJpcCgpCiBpZiBu'
    'b3QgdmFsdWUgb3IgbGVuKHZhbHVlKT41MTIgb3IgYW55KG9yZChjKTwzMiBmb3IgYyBpbiB2YWx1ZSk6cmFpc2UgVmFsdWVF'
    'cnJvcign0J3QtdC60L7RgNGA0LXQutGC0L3QvtC1INC40YHQutC70Y7Rh9C10L3QuNC1LicpCiBpZiBjYXRlZ29yeT09J2Fw'
    'cGxpY2F0aW9ucyc6CiAgaWYgbm90IHJlLmZ1bGxtYXRjaChyJ1tcdy4vICtAKClcLV0rJyx2YWx1ZSk6cmFpc2UgVmFsdWVF'
    'cnJvcign0KPQutCw0LbQuNGC0LUg0LjQvNGPINC/0YDQvtGG0LXRgdGB0LAg0LjQu9C4INC/0L7Qu9C90YvQuSDQv9GD0YLR'
    'jC4nKQogIGlmICcvJyBpbiB2YWx1ZSBhbmQgbm90IHZhbHVlLnN0YXJ0c3dpdGgoJy8nKTpyYWlzZSBWYWx1ZUVycm9yKCfQ'
    'n9GD0YLRjCDQtNC+0LvQttC10L0g0LHRi9GC0Ywg0LDQsdGB0L7Qu9GO0YLQvdGL0LwuJykKICByZXR1cm4gdmFsdWUKIGlm'
    'IGNhdGVnb3J5PT0nbmV0d29ya3MnOgogIHRyeToKICAgbmV0PWlwYWRkcmVzcy5pcF9uZXR3b3JrKHZhbHVlLHN0cmljdD1G'
    'YWxzZSkKICAgaWYgbmV0LnZlcnNpb24hPTQ6cmFpc2UgVmFsdWVFcnJvcign0J/QvtC00LTQtdGA0LbQuNCy0LDRjtGC0YHR'
    'jyDQsNC00YDQtdGB0LAg0LLQuNC00LAgMTkyLjE2OC4xLjEwLicpCiAgICMgQWRkcmVzc2VzIG93bmVkIGJ5IG91ciB0dW5u'
    'ZWxzIGNhbm5vdCBiZSByb3V0ZWQgcGh5c2ljYWxseS4KICAgcmVzZXJ2ZWQ9WycxMC43Ny4wLjAvMjQnLHR1bm5lbC5ORVRX'
    'T1JLLHR1bm5lbC5GVUxMX05FVCwnMTk4LjE4LjI1NC4wLzMwJ10gaWYgdHVubmVsIGVsc2UgWycxMC43Ny4wLjAvMjQnLCcx'
    'NzIuMjkuMjQ2LjAvMzAnLCcxNzIuMjkuMjQ3LjAvMzAnLCcxOTguMTguMjU0LjAvMzAnXQogICBpZiBhbnkobmV0Lm92ZXJs'
    'YXBzKGlwYWRkcmVzcy5pcF9uZXR3b3JrKG4pKSBmb3IgbiBpbiByZXNlcnZlZCk6cmFpc2UgVmFsdWVFcnJvcign0JTQuNCw'
    '0L/QsNC30L7QvSDQv9C10YDQtdGB0LXQutCw0LXRgtGB0Y8g0YHQviDRgdC70YPQttC10LHQvdC+0Lkg0YHQtdGC0YzRjiBW'
    'UE4uINCU0L7QsdCw0LLRjNGC0LUg0LHQvtC70LXQtSDRg9C30LrRg9GOINGB0LXRgtGMLicpCiAgIHJldHVybiBzdHIobmV0'
    'KQogIGV4Y2VwdCBWYWx1ZUVycm9yIGFzIGV4YzoKICAgaWYgJy8nIGluIHZhbHVlIG9yIHJlLmZ1bGxtYXRjaChyJ1tcZC5d'
    'KycsdmFsdWUpOnJhaXNlIGV4YwogIGV4YWN0PXZhbHVlLnN0YXJ0c3dpdGgoJz0nKTt2YWx1ZT12YWx1ZS5sc3RyaXAoJz0n'
    'KS5sb3dlcigpLnJzdHJpcCgnLicpCiAgdHJ5OnZhbHVlPXZhbHVlLmVuY29kZSgnaWRuYScpLmRlY29kZSgnYXNjaWknKQog'
    'IGV4Y2VwdCBVbmljb2RlRXJyb3I6cmFpc2UgVmFsdWVFcnJvcign0J3QtdC60L7RgNGA0LXQutGC0L3Ri9C5INC00L7QvNC1'
    '0L0uJykKICBpZiBsZW4odmFsdWUpPjI1MyBvciBub3QgYWxsKHJlLmZ1bGxtYXRjaChyJ1thLXowLTldKD86W2EtejAtOS1d'
    'ezAsNjF9W2EtejAtOV0pPycseCkgZm9yIHggaW4gdmFsdWUuc3BsaXQoJy4nKSk6cmFpc2UgVmFsdWVFcnJvcign0JLQstC1'
    '0LTQuNGC0LUg0LTQvtC80LXQvSDQsdC10LcgaHR0cHM6Ly8g0Lgg0L/Rg9GC0LguJykKICByZXR1cm4gKCc9JyBpZiBleGFj'
    'dCBlbHNlICcnKSt2YWx1ZQogaWYgY2F0ZWdvcnk9PSdkbnMnOgogIGFkZHI9aXBhZGRyZXNzLmlwX2FkZHJlc3ModmFsdWUp'
    'CiAgaWYgYWRkci52ZXJzaW9uIT00IG9yIGFkZHIuaXNfdW5zcGVjaWZpZWQgb3IgYWRkci5pc19tdWx0aWNhc3Qgb3IgYWRk'
    'ci5pc19sb29wYmFjazpyYWlzZSBWYWx1ZUVycm9yKCfQo9C60LDQttC40YLQtSDQsNC00YDQtdGBINCy0L3QtdGI0L3QtdCz'
    '0L4g0LjQu9C4INC00L7QvNCw0YjQvdC10LPQviBETlMt0YHQtdGA0LLQtdGA0LA7INC70L7QutCw0LvRjNC90YvQuSBETlMg'
    '0L3QsNGF0L7QtNC40YLRgdGPINCyINCx0LDQt9C+0LLRi9GFINC/0YDQsNCy0LjQu9Cw0YUuJykKICByZXR1cm4gc3RyKGFk'
    'ZHIpCiBpZiBjYXRlZ29yeT09J3BvcnRzJzoKICBtYXRjaD1yZS5mdWxsbWF0Y2gocicodGNwfHVkcHxib3RoKTooXGR7MSw1'
    'fSkoPzo6KG91dHxpbnxib3RoKSk/Jyx2YWx1ZS5sb3dlcigpKQogIGlmIG5vdCBtYXRjaCBvciBub3QgMTw9aW50KG1hdGNo'
    'WzJdKTw9NjU1MzU6cmFpc2UgVmFsdWVFcnJvcign0KTQvtGA0LzQsNGCOiB0Y3A6NDQzOm91dCwgdWRwOjI1NTY1OmluINC4'
    '0LvQuCBib3RoOjI1NTY1OmJvdGguJykKICBpZiBpbnQobWF0Y2hbMl0pPT01MzpyYWlzZSBWYWx1ZUVycm9yKCdETlMg0L3Q'
    'sNGB0YLRgNCw0LjQstCw0LXRgtGB0Y8g0LLQviDQstC60LvQsNC00LrQtSBETlMuJykKICByZXR1cm4gZid7bWF0Y2hbMV19'
    'OntpbnQobWF0Y2hbMl0pfTp7bWF0Y2hbM10gb3IgImJvdGgifScKIHJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB'
    '0YLQvdCw0Y8g0LrQsNGC0LXQs9C+0YDQuNGPLicpCgpkZWYgbWlncmF0aW9uKHNldHRpbmdzKToKIGlmIFBBVEguZXhpc3Rz'
    'KCk6cmV0dXJuCiBwPWRlZmF1bHRzKCk7IHJlamVjdGVkPVtdCiBpZiBzZXR0aW5ncy5nZXQoJ2NsaV9vbmx5JyxGYWxzZSk6'
    'cFsnbW9kZSddPSdpbmNsdWRlJwogc291cmNlcz17J2FwcGxpY2F0aW9ucyc6c2V0dGluZ3MuZ2V0KCdkaXJlY3RfYXBwcycp'
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
    'ZCcsJ2RvbWFpbic6ZG9tYWlucywnaW5ib3VuZFRhZyc6Wyd0dW4nXSwnb3V0Ym91bmRUYWcnOidkaXJlY3QnfSkKICMgSW5j'
    'bHVzaW9uIGxpc3RzIGFyZSBpbmRlcGVuZGVudCBvZiB0aGUgc2F2ZWQgRElSRUNUIGV4Y2VwdGlvbnMuCiBpZiBpbmNsdXNp'
    'dmUocCk6CiAgY2hvc2VuPXBbJ2luY2x1ZGUnXQogIGZvciBmaWVsZCx2YWx1ZXMgaW4gWygncHJvY2VzcycsY2hvc2VuWydh'
    'cHBsaWNhdGlvbnMnXSksCiAgICAgICAgICAgICAgICAgICAgICAgKCdpcCcsW3YgZm9yIHYgaW4gY2hvc2VuWyduZXR3b3Jr'
    'cyddIGlmICcvJyBpbiB2XSksCiAgICAgICAgICAgICAgICAgICAgICAgKCdkb21haW4nLFsoJ2Z1bGw6Jyt2WzE6XSkgaWYg'
    'di5zdGFydHN3aXRoKCc9JykgZWxzZSAnZG9tYWluOicrdiBmb3IgdiBpbiBjaG9zZW5bJ25ldHdvcmtzJ10gaWYgJy8nIG5v'
    'dCBpbiB2XSldOgogICBpZiB2YWx1ZXM6cnVsZXMuYXBwZW5kKHsndHlwZSc6J2ZpZWxkJyxmaWVsZDp2YWx1ZXMsJ2luYm91'
    'bmRUYWcnOlsndHVuJ10sJ291dGJvdW5kVGFnJzondnBuJ30pCiAgZm9yIHByb3RvLHZhbHVlcyBpbiBwb3J0cyhjaG9zZW4s'
    'J291dCcpLml0ZW1zKCk6CiAgIGlmIHZhbHVlczpydWxlcy5hcHBlbmQoeyd0eXBlJzonZmllbGQnLCduZXR3b3JrJzpwcm90'
    'bywncG9ydCc6JywnLmpvaW4oc3RyKHYpIGZvciB2IGluIHNvcnRlZCh2YWx1ZXMpKSwnaW5ib3VuZFRhZyc6Wyd0dW4nXSwn'
    'b3V0Ym91bmRUYWcnOid2cG4nfSkKIGZhbGxiYWNrPSdkaXJlY3QnIGlmIGluY2x1c2l2ZShwKSBlbHNlICd2cG4nCiAjIElu'
    'IGluY2x1c2lvbiBtb2RlIHN5c3RlbSBETlMgaXMgRElSRUNUIHVubGVzcyBhIEROUyBzZXJ2ZXIgaXMgZXhwbGljaXRseSBz'
    'ZWxlY3RlZC4KIHJ1bGVzKz1beyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUnXSwnb3V0Ym91bmRU'
    'YWcnOmZhbGxiYWNrfSwKICAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ3R1biddLCdvdXRib3VuZFRh'
    'Zyc6ZmFsbGJhY2t9XQogcmV0dXJuIHsnbG9nJzp7J2xvZ2xldmVsJzond2FybmluZycsJ2FjY2Vzcyc6J25vbmUnfSwKICAn'
    'aW5ib3VuZHMnOlt7J3RhZyc6J3R1bicsJ3Byb3RvY29sJzondHVuJywnc2V0dGluZ3MnOnsnbmFtZSc6VFVOLCdtdHUnOjEy'
    'ODAsJ2dhdGV3YXknOlsnMTk4LjE4LjI1NC4xLzMwJ119LAogICAgICAgICAgICAgICAnc25pZmZpbmcnOnsnZW5hYmxlZCc6'
    'VHJ1ZSwnZGVzdE92ZXJyaWRlJzpbJ2h0dHAnLCd0bHMnLCdxdWljJ10sJ3JvdXRlT25seSc6VHJ1ZX19LAogICAgICAgICAg'
    'ICAgIHsndGFnJzonZG5zLWluJywnbGlzdGVuJzonMTI3LjAuMC4xJywncG9ydCc6RE5TX1BPUlQsJ3Byb3RvY29sJzonZG9r'
    'b2RlbW8tZG9vcicsJ3NldHRpbmdzJzp7J2FkZHJlc3MnOicxLjEuMS4xJywncG9ydCc6NTMsJ25ldHdvcmsnOid0Y3AsdWRw'
    'J319LAogICAgICAgICAgICAgIHsndGFnJzonY2hlY2snLCdsaXN0ZW4nOicxMjcuMC4wLjEnLCdwb3J0JzpDSEVDS19QT1JU'
    'LCdwcm90b2NvbCc6J3NvY2tzJywnc2V0dGluZ3MnOnsnYXV0aCc6J25vYXV0aCcsJ3VkcCc6RmFsc2V9fV0sCiAgJ2Rucyc6'
    'eydzZXJ2ZXJzJzpbJzEuMS4xLjEnLCc5LjkuOS45J10sJ3F1ZXJ5U3RyYXRlZ3knOidVc2VJUHY0JywndGFnJzonZG5zLWVu'
    'Z2luZScsJ2Rpc2FibGVGYWxsYmFjayc6RmFsc2V9LAogICdvdXRib3VuZHMnOlt7J3RhZyc6dGFnLCdwcm90b2NvbCc6J2Zy'
    'ZWVkb20nLCdzZXR0aW5ncyc6eydkb21haW5TdHJhdGVneSc6J1VzZUlQdjQnfSwnc3RyZWFtU2V0dGluZ3MnOnsnc29ja29w'
    'dCc6eydtYXJrJzptYXJrfX19IGZvciB0YWcsbWFyayBpbiBbKCd2cG4nLFZQTiksKCdkaXJlY3QnLERJUkVDVCldXSsKICAg'
    'ICAgICAgICAgICAgW3sndGFnJzonZG5zJywncHJvdG9jb2wnOidkbnMnLCdzZXR0aW5ncyc6eydydWxlcyc6W3sncVR5cGUn'
    'OicxLDI4JywnYWN0aW9uJzonaGlqYWNrJ30seydhY3Rpb24nOidkaXJlY3QnfV19LCdzdHJlYW1TZXR0aW5ncyc6eydzb2Nr'
    'b3B0Jzp7J21hcmsnOkRJUkVDVCBpZiBpbmNsdXNpdmUocCkgZWxzZSBWUE59fX1dLAogICdyb3V0aW5nJzp7J2RvbWFpblN0'
    'cmF0ZWd5JzonQXNJcycsJ3J1bGVzJzpydWxlc319CgpkZWYgbmZ0X3NldChpdGVtcyk6cmV0dXJuICd7ICcrJywgJy5qb2lu'
    'KHN0cih4KSBmb3IgeCBpbiBzb3J0ZWQoaXRlbXMpKSsnIH0nCgpkZWYgZmlyZXdhbGwocCxsYW4sdWlkKToKICMgUm91dGUg'
    'bWFya3MgYXJlIHNldCBvbmx5IGJ5IHRoaXMgcHJpdmlsZWdlZCBjbGFzc2lmaWVyIG9yIGV4cGxpY2l0IGtlcm5lbCBydWxl'
    'cy4KIG1hcms9WydjdCBkaXJlY3Rpb24gcmVwbHkgbWV0YSBtYXJrIHNldCAnK3N0cihESVJFQ1QpKycgcmV0dXJuJ10gaWYg'
    'aW5jbHVzaXZlKHApIGVsc2UgW10KIGRucz1bXTtmb3J3YXJkPVtdO25hdD1bJ21ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFy'
    'ayAnK3N0cihESVJFQ1QpKycgb2lmbmFtZSAhPSAibG8iIG1hc3F1ZXJhZGUnXQogaWYgZW5hYmxlZChwLCdkbnMnLCdzdHVi'
    'Jyk6ZG5zLmFwcGVuZCgnaXAgZGFkZHIgMTI3LjAuMC4wLzggcmV0dXJuJykKIGlmIHBbJ2RucyddOgogIGRucy5hcHBlbmQo'
    'ZidpcCBkYWRkciB7bmZ0X3NldChwWyJkbnMiXSl9IHJldHVybicpCiAgbWFyay5hcHBlbmQoZidpcCBkYWRkciB7bmZ0X3Nl'
    'dChwWyJkbnMiXSl9IG1ldGEgbDRwcm90byB7eyB0Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBtZXRhIG1hcmsgc2V0IHtESVJF'
    'Q1R9IHJldHVybicpCiAjIEludGVyZmFjZS1ib3VuZCBzeXN0ZW0gcmVzb2x2ZXJzIG11c3Qga2VlcCBETlMgb24gdGhlIHR1'
    'bm5lbCBpbnRlcmZhY2UuCiAjIFJlZGlyZWN0aW5nIHRoZWlyIHVwc3RyZWFtIHNvY2tldCB0byBsb29wYmFjayBicmVha3Mg'
    'U09fQklORFRPREVWSUNFLgogIyBPbmx5IGFuIGV4cGxpY2l0bHkgZGlzYWJsZWQgbG9vcGJhY2stc3R1YiBydWxlIHVzZXMg'
    'dGhlIGxvY2FsIEROUyBsaXN0ZW5lci4KIGRucys9WydpcCBkYWRkciAxMjcuMC4wLjAvOCBtZXRhIGw0cHJvdG8geyB0Y3As'
    'IHVkcCB9IHRoIGRwb3J0IDUzIHJlZGlyZWN0IHRvIDonK3N0cihETlNfUE9SVCksCiAgICAgICAnbWV0YSBuZnByb3RvIGlw'
    'djQgbWV0YSBsNHByb3RvIHsgdGNwLCB1ZHAgfSB0aCBkcG9ydCA1MyBkbmF0IGlwIHRvIDE3Mi4yOS4yNDcuMiddCiBpZiBp'
    'bmNsdXNpdmUocCk6CiAgIyBLZWVwIHRoZSBzeXN0ZW0gcmVzb2x2ZXIgY29uZmlndXJhdGlvbiBhbmQgcm91dGUgaXRzIG9y'
    'ZGluYXJ5IHF1ZXJpZXMgRElSRUNULgogICMgVGhlIG9yaWdpbmFsIGRlc3RpbmF0aW9uIHN0YXlzIGludGFjdCAoaW5jbHVk'
    'aW5nIFNPX0JJTkRUT0RFVklDRSByZXNvbHZlcnMpLgogIGRucz1bXQogIGlmIHBbJ2luY2x1ZGUnXVsnZG5zJ106CiAgIHNl'
    'bGVjdGVkPW5mdF9zZXQocFsnaW5jbHVkZSddWydkbnMnXSkKICAgZG5zLmluc2VydCgwLGYnaXAgZGFkZHIge3NlbGVjdGVk'
    'fSByZXR1cm4nKQogICBtYXJrLmFwcGVuZChmJ2lwIGRhZGRyIHtzZWxlY3RlZH0gbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRw'
    'IH19IHRoIGRwb3J0IDUzIG1ldGEgbWFyayBzZXQge1ZQTn0gcmV0dXJuJykKIG1hcmsrPVsnbWV0YSBsNHByb3RvIHsgdGNw'
    'LCB1ZHAgfSB0aCBkcG9ydCA1MyBtZXRhIG1hcmsgc2V0ICcrc3RyKERJUkVDVCBpZiBpbmNsdXNpdmUocCkgZWxzZSBWUE4p'
    'KycgcmV0dXJuJ10KIHdheW5ldHM9d2F5ZHJvaWRfbmV0d29yaygpWyduZXR3b3JrcyddCiBtYXJrLmFwcGVuZChmJ2lwIGRh'
    'ZGRyIEB3YXlkcm9pZF9uZXR3b3JrcyBtZXRhIG1hcmsgc2V0IHtESVJFQ1R9IHJldHVybicpCiBtYXJrLmFwcGVuZChmJ29p'
    'Zm5hbWUgIndheWRyb2lkMCIgdWRwIHNwb3J0IDY3IHVkcCBkcG9ydCA2OCBtZXRhIG1hcmsgc2V0IHtESVJFQ1R9IHJldHVy'
    'bicpCiBpZiBlbmFibGVkKHAsJ25ldHdvcmtzJywnZGVhZGxvY2stc2RyJyk6CiAgZm9yIGdyb3VwIGluIERFQURMT0NLX1NE'
    'UlsnZ3JvdXBzJ106CiAgIGFkZHJlc3Nlcz1uZnRfc2V0KGdyb3VwWydhZGRyZXNzZXMnXSkKICAgbWFyay5hcHBlbmQoZiJp'
    'cCBkYWRkciB7YWRkcmVzc2VzfSB1ZHAgZHBvcnQge2dyb3VwWydmaXJzdCddfS17Z3JvdXBbJ2xhc3QnXX0gbWV0YSBtYXJr'
    'IHNldCB7RElSRUNUfSByZXR1cm4iKQogbmV0cz1kaXJlY3RfbmV0d29ya3MocCxsYW4pCiBpZiBuZXRzOm1hcmsuYXBwZW5k'
    'KGYnaXAgZGFkZHIge25mdF9zZXQobmV0cyl9IG1ldGEgbWFyayBzZXQge0RJUkVDVH0gcmV0dXJuJykKIGlmIGVuYWJsZWQo'
    'cCwncG9ydHMnLCdkaXNjb3ZlcnknKToKICBtYXJrKz1bJ2lwIGRhZGRyIHsgMjI0LjAuMC4yNTEsIDIyNC4wLjAuMjUyLCAy'
    'MzkuMjU1LjI1NS4yNTAgfSB1ZHAgZHBvcnQgeyA1MzUzLCA1MzU1LCAxOTAwIH0gbWV0YSBtYXJrIHNldCAnK3N0cihESVJF'
    'Q1QpKycgcmV0dXJuJ10KIGZvciBkaXJlY3Rpb24gaW4gKCdvdXQnLCdpbicpOgogIGZvciBwcm90byx2YWx1ZXMgaW4gcG9y'
    'dHMocCxkaXJlY3Rpb24pLml0ZW1zKCk6CiAgIGlmIHZhbHVlczptYXJrLmFwcGVuZCgoJ2N0IGRpcmVjdGlvbiByZXBseSAn'
    'IGlmIGRpcmVjdGlvbj09J2luJyBlbHNlICcnKStmJ3twcm90b30geyJzcG9ydCIgaWYgZGlyZWN0aW9uPT0iaW4iIGVsc2Ug'
    'ImRwb3J0In0ge25mdF9zZXQodmFsdWVzKX0gbWV0YSBtYXJrIHNldCB7RElSRUNUfSByZXR1cm4nKQogaWYgcFsnd2F5ZHJv'
    'aWRfZGlyZWN0J106CiAgZm9yd2FyZD1bJ2lpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBtYXJr'
    'IHNldCAnK3N0cihESVJFQ1QpKycgY3QgbWFyayBzZXQgJytzdHIoRElSRUNUKSwgJ2N0IGRpcmVjdGlvbiByZXBseSBjdCBt'
    'YXJrICcrc3RyKERJUkVDVCkrJyBtZXRhIG1hcmsgc2V0ICcrc3RyKERJUkVDVCldCgogZGVmIGxpbmVzKGl0ZW1zKTpyZXR1'
    'cm4gJ1xuJy5qb2luKCcgICcreCBmb3IgeCBpbiBpdGVtcykKIHJldHVybiBmJycndGFibGUgaW5ldCB7dHVubmVsLkZVTExf'
    'R1VBUkR9IHt7CiBzZXQgd2F5ZHJvaWRfbmV0d29ya3Mge3sgdHlwZSBpcHY0X2FkZHI7IGZsYWdzIGludGVydmFsOyB7KCdl'
    'bGVtZW50cyA9ICcrbmZ0X3NldCh3YXluZXRzKSsnOycpIGlmIHdheW5ldHMgZWxzZSAnJ30gfX0KIGNoYWluIHJvdXRlIHt7'
    'IHR5cGUgcm91dGUgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTE1MDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIHNrdWlkIHt1aWR9'
    'IHJldHVybgogIG1ldGEgbWFyayBzZXQgMAogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybgp7bGluZXMobWFyayl9CiB9'
    'fQogY2hhaW4gZG5zIHt7IHR5cGUgbmF0IGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAgbWV0'
    'YSBza3VpZCB7dWlkfSByZXR1cm4Ke2xpbmVzKGRucyl9CiB9fQogY2hhaW4gcHJlcm91dGUge3sgdHlwZSBmaWx0ZXIgaG9v'
    'ayBwcmVyb3V0aW5nIHByaW9yaXR5IC0xNTA7IHBvbGljeSBhY2NlcHQ7CntsaW5lcyhmb3J3YXJkKX0KIH19CiBjaGFpbiB3'
    'YXlkcm9pZF9kbnMge3sgdHlwZSBuYXQgaG9vayBwcmVyb3V0aW5nIHByaW9yaXR5IC0xMDE7IHBvbGljeSBhY2NlcHQ7CiAg'
    'aWlmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggZHBv'
    'cnQgNTMgZG5hdCBpcCB0byAxLjEuMS4xCiB9fQogY2hhaW4gc291cmNlIHt7IHR5cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcg'
    'cHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVM'
    'TF9IT1NUfSIgc25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKe2xpbmVzKG5hdCl9CiB9fQogY2hhaW4gb3V0cHV0IHt7IHR5cGUg'
    'ZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAogIG1l'
    'dGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBtZXRhIG1hcmsg'
    'e1ZQTn0gbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUzIG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NU'
    'fSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBza3VpZCB7dWlkfSBtZXRhIG1hcmsge1ZQTn0gb2lmbmFtZSAi'
    'e3R1bm5lbC5GVUxMX0hPU1R9IiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7VFVOfSIgYWNjZXB0CiAg'
    'aXAgZGFkZHIgMjU1LjI1NS4yNTUuMjU1IHVkcCBzcG9ydCA2OCB1ZHAgZHBvcnQgNjcgYWNjZXB0CiB9fQogY2hhaW4gZm9y'
    'd2FyZCB7eyB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7'
    'dHVubmVsLkhPU1R9IiBpcCBzYWRkciB7dHVubmVsLkNMSUVOVH0gaXAgZGFkZHIge3R1bm5lbC5TRVJWRVJ9IHVkcCBkcG9y'
    'dCB7dHVubmVsLklLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBzYWRkciB7dHVubmVsLkNM'
    'SUVOVH0gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIGFjY2VwdAogIGlpZm5hbWUgInt0dW5uZWwuSE9T'
    'VH0iIGlwIHNhZGRyIHt0dW5uZWwuQ0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwg'
    'MjQ1NzggfX0gYWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAgc2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRh'
    'ZGRyIHt0dW5uZWwuU0VSVkVSfSB0Y3AgZHBvcnQgMjQ1NzkgYWNjZXB0CiAgaWlmbmFtZSAie3R1bm5lbC5IT1NUfSIgaXAg'
    'c2FkZHIge3R1bm5lbC5DTElFTlR9IGlwIGRhZGRyIHt0dW5uZWwuU0VSVkVSfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBv'
    'aWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBkYWRkciB7dHVubmVsLkNMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVs'
    'YXRlZCBhY2NlcHQKICBpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBh'
    'Y2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0'
    'ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie1RVTn0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0'
    'IGlpZm5hbWUgIntUVU59IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0'
    'IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NUfSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie3R1bm5l'
    'bC5GVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKClVOSVQ9JycnW1Vu'
    'aXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGxvY2FsIGFwcGxpY2F0aW9uIGFuZCBkb21haW4gcm91dGluZwpBZnRlcj1uZXR3'
    'b3JrLnRhcmdldApXYW50cz1ldmdlbml1bS13YXlkcm9pZC1uZXR3b3JrLnNlcnZpY2UKW1NlcnZpY2VdClVzZXI9dnBuLXhy'
    'YXkKR3JvdXA9dnBuLXhyYXkKRXhlY1N0YXJ0PS9vcHQvdnBuLW1hbmFnZXIvYmluL3hyYXkgcnVuIC1jb25maWcgL3J1bi92'
    'cG4tbWFuYWdlci9wb2xpY3kuanNvbgpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0yCkFtYmllbnRDYXBhYmlsaXRp'
    'ZXM9Q0FQX05FVF9BRE1JTiBDQVBfTkVUX1JBVyBDQVBfU1lTX1BUUkFDRSBDQVBfREFDX1JFQURfU0VBUkNICkNhcGFiaWxp'
    'dHlCb3VuZGluZ1NldD1DQVBfTkVUX0FETUlOIENBUF9ORVRfUkFXIENBUF9TWVNfUFRSQUNFIENBUF9EQUNfUkVBRF9TRUFS'
    'Q0gKTm9OZXdQcml2aWxlZ2VzPXRydWUKUHJvdGVjdFN5c3RlbT1zdHJpY3QKUHJvdGVjdEhvbWU9dHJ1ZQpQcml2YXRlVG1w'
    'PXRydWUKRGV2aWNlQWxsb3c9L2Rldi9uZXQvdHVuIHJ3ClVNYXNrPTAwNzcKJycnCgpXQVlEUk9JRF9VTklUPScnJ1tVbml0'
    'XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBXYXlkcm9pZCBuZXR3b3JrIGxpZmVjeWNsZQpBZnRlcj1ldmdlbml1bS1wb2xpY3ku'
    'c2VydmljZQpQYXJ0T2Y9ZXZnZW5pdW0tcG9saWN5LnNlcnZpY2UKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3Ni'
    'aW4vdnBuY3RsIGludGVybmFsLXdheWRyb2lkLXdhdGNoClJlc3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0U2VjPTIKVU1hc2s9'
    'MDA3NwonJycKCmRlZiB3YXlkcm9pZF9uZXR3b3JrKCk6CiByZXN1bHQ9dHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQn'
    'LCdhZGRyJywnc2hvdycsJ2RldicsJ3dheWRyb2lkMCddLGNoZWNrPUZhbHNlKQogaWYgcmVzdWx0LnJldHVybmNvZGU6cmV0'
    'dXJuIHsnaW5kZXgnOk5vbmUsJ25ldHdvcmtzJzpbXX0KIGxpbmtzPWpzb24ubG9hZHMocmVzdWx0LnN0ZG91dCkKIG5ldHdv'
    'cmtzPXNvcnRlZCh7c3RyKGlwYWRkcmVzcy5pcF9uZXR3b3JrKGYie2FbJ2xvY2FsJ119L3thWydwcmVmaXhsZW4nXX0iLHN0'
    'cmljdD1GYWxzZSkpIGZvciBsaW5rIGluIGxpbmtzIGlmICdVUCcgaW4gbGluay5nZXQoJ2ZsYWdzJyxbXSkgZm9yIGEgaW4g'
    'bGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlmIGEuZ2V0KCdzY29wZScpPT0nZ2xvYmFsJ30pCiByZXR1cm4geydpbmRleCc6'
    'bGlua3NbMF0uZ2V0KCdpZmluZGV4JykgaWYgbGlua3MgZWxzZSBOb25lLCduZXR3b3Jrcyc6bmV0d29ya3N9CgpkZWYgc3lu'
    'Y193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPUZhbHNlKToKICMgQ2FsbGVyIGhvbGRzIG9wZXJhdGlvbi5sb2NrLiBPbmx5IHRo'
    'aXMgVlBOJ3Mgc2V0L3RhYmxlIGFyZSBtb2RpZmllZC4KIHN0YXRlPXdheWRyb2lkX25ldHdvcmsoKTtjYWNoZT1SVU4vJ3dh'
    'eWRyb2lkLW5ldHdvcmsuanNvbicKIHRyeTpwcmV2aW91cz1qc29uLmxvYWRzKGNhY2hlLnJlYWRfdGV4dCgpKQogZXhjZXB0'
    'IChPU0Vycm9yLFZhbHVlRXJyb3IpOnByZXZpb3VzPU5vbmUKIGlmIG5vdCBmb3JjZSBhbmQgc3RhdGU9PXByZXZpb3VzOnJl'
    'dHVybgogcm91dGVzPWpzb24ubG9hZHModHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdyb3V0ZScsJ3Nob3cnLCd0'
    'YWJsZScsUEhZU0lDQUxfVEFCTEVdKS5zdGRvdXQpCiBzdGFsZT17clsnZHN0J10gZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0'
    'KCdkZXYnKT09J3dheWRyb2lkMCcgYW5kIHIuZ2V0KCdkc3QnKSBub3QgaW4gc3RhdGVbJ25ldHdvcmtzJ119CiBmb3IgbmV0'
    'd29yayBpbiBzdGF0ZVsnbmV0d29ya3MnXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3'
    'b3JrLCdkZXYnLCd3YXlkcm9pZDAnLCdzY29wZScsJ2xpbmsnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogcnVsZXM9J2Zs'
    'dXNoIHNldCBpbmV0ICcrdHVubmVsLkZVTExfR1VBUkQrJyB3YXlkcm9pZF9uZXR3b3Jrc1xuJwogaWYgc3RhdGVbJ25ldHdv'
    'cmtzJ106cnVsZXMrPSdhZGQgZWxlbWVudCBpbmV0ICcrdHVubmVsLkZVTExfR1VBUkQrJyB3YXlkcm9pZF9uZXR3b3JrcyAn'
    'K25mdF9zZXQoc3RhdGVbJ25ldHdvcmtzJ10pKydcbicKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1y'
    'dWxlcykKIGZvciBuZXR3b3JrIGluIHN0YWxlOnR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsbmV0d29yaywn'
    'ZGV2Jywnd2F5ZHJvaWQwJywndGFibGUnLFBIWVNJQ0FMX1RBQkxFXSxjaGVjaz1GYWxzZSkKIGNhY2hlLndyaXRlX3RleHQo'
    'anNvbi5kdW1wcyhzdGF0ZSkpO2NhY2hlLmNobW9kKDBvNjAwKQoKZGVmIHdhdGNoX3dheWRyb2lkKCk6CiBpbXBvcnQgc3lz'
    'CiBsYXN0X2Vycm9yPU5vbmUKIHdoaWxlIFRydWU6CiAgdHJ5OgogICBSVU4ubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29r'
    'PVRydWUpCiAgIHdpdGggKFJVTi8nb3BlcmF0aW9uLmxvY2snKS5vcGVuKCdhKycpIGFzIGxvY2s6CiAgICB0cnk6ZmNudGwu'
    'ZmxvY2sobG9jayxmY250bC5MT0NLX0VYfGZjbnRsLkxPQ0tfTkIpCiAgICBleGNlcHQgQmxvY2tpbmdJT0Vycm9yOnBhc3MK'
    'ICAgIGVsc2U6CiAgICAgaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0Lycr'
    'VFVOKS5leGlzdHMoKTpzeW5jX3dheWRyb2lkX25ldHdvcmsoKQogICBsYXN0X2Vycm9yPU5vbmUKICBleGNlcHQgRXhjZXB0'
    'aW9uIGFzIGV4YzoKICAgbWVzc2FnZT1zdHIoZXhjKQogICBpZiBtZXNzYWdlIT1sYXN0X2Vycm9yOnByaW50KCdXYXlkcm9p'
    'ZCBuZXR3b3JrIHN5bmM6ICcrbWVzc2FnZSxmaWxlPXN5cy5zdGRlcnIsZmx1c2g9VHJ1ZSkKICAgbGFzdF9lcnJvcj1tZXNz'
    'YWdlCiAgdGltZS5zbGVlcCgxKQoKZGVmIGluc3RhbGwoKToKIFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vJytTRVJWSUNF'
    'KS53cml0ZV90ZXh0KFVOSVQpCiBQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtLycrV0FZRFJPSURfU0VSVklDRSkud3JpdGVf'
    'dGV4dChXQVlEUk9JRF9VTklUKQogdHVubmVsLmNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCgpkZWYg'
    'YXBwbHkoKToKIHA9bG9hZCgpO3NldHRpbmdzPWFwaS5sb2FkX3NldHRpbmdzKCk7cm91dGU9dHVubmVsLnBoeXNpY2FsX3Jv'
    'dXRlKCk7bGFuPWxvY2FsX25ldHdvcmtzKHJvdXRlKQogYXBpLmVuc3VyZV9ydW50aW1lKHNldHRpbmdzKQogY2ZnPVJVTi8n'
    'cG9saWN5Lmpzb24nO3RtcD1SVU4vJ3BvbGljeS5uZXcuanNvbicKIHRtcC53cml0ZV90ZXh0KGpzb24uZHVtcHMoY29uZmln'
    'KHApKSk7b3MuY2htb2QodG1wLDBvNjQwKTtvcy5jaG93bih0bXAsMCxpbnQoc2V0dGluZ3NbJ3hyYXlfZ2lkJ10pKQogY2hl'
    'Y2s9dHVubmVsLmNvbW1hbmQoW2FwaS5YUkFZLCdydW4nLCctdGVzdCcsJy1jb25maWcnLHRtcF0sY2hlY2s9RmFsc2UpCiBp'
    'ZiBjaGVjay5yZXR1cm5jb2RlOnJhaXNlIFJ1bnRpbWVFcnJvcign0J7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH'
    '0LXQvdC40Lkg0L3QtSDQv9GA0LjQvdGP0Lsg0L3QsNGB0YLRgNC+0LnQutC4LicpCiBydWxlcz1maXJld2FsbChwLGxhbixp'
    'bnQoc2V0dGluZ3NbJ3hyYXlfdWlkJ10pKQogcmVwbGFjZW1lbnQ9KCdkZWxldGUgdGFibGUgaW5ldCAnK3R1bm5lbC5GVUxM'
    'X0dVQVJEKydcbicgaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKIHR1bm5lbC5jb21tYW5k'
    'KFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogb3duZXJzaGlwPVBBVEgud2l0aF9uYW1lKCdwb2xp'
    'Y3ktbmV0d29yay5qc29uJykKIGlmIG5vdCBvd25lcnNoaXAuZXhpc3RzKCk6CiAgZm9yIHRhYmxlIGluIChQSFlTSUNBTF9U'
    'QUJMRSxWUE5fVEFCTEUpOgogICBpZiB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLHRhYmxl'
    'XSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6cmFpc2UgUnVudGltZUVycm9yKCfQotCw0LHQu9C40YbQsCDQvNCw0YDR'
    'iNGA0YPRgtC40LfQsNGG0LjQuCDQuNGB0LrQu9GO0YfQtdC90LjQuSDQt9Cw0L3Rj9GC0LAg0LTRgNGD0LPQvtC5INC/0YDQ'
    'vtCz0YDQsNC80LzQvtC5LicpCiAgZXhpc3Rpbmc9anNvbi5sb2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcs'
    'J3J1bGUnXSkuc3Rkb3V0KQogIGlmIGFueShyLmdldCgncHJpb3JpdHknKSBpbiAoNzYsNzcsNzgpIGZvciByIGluIGV4aXN0'
    'aW5nKTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cf0YDQuNC+0YDQuNGC0LXRgtGLINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4'
    'INC40YHQutC70Y7Rh9C10L3QuNC5INC30LDQvdGP0YLRiyDQtNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykK'
    'ICB0dW5uZWwud3JpdGUob3duZXJzaGlwLGpzb24uZHVtcHMoeyd0YWJsZXMnOltQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEVd'
    'fSkpCiAjIEJ1aWxkIHBoeXNpY2FsIGFuZCBWUE4tb25seSB0YWJsZXMgYmVmb3JlIGFsbG93aW5nIGFueSBuZXcgbWFya3Mu'
    'CiBmb3IgdGFibGUgaW4gKFBIWVNJQ0FMX1RBQkxFLFZQTl9UQUJMRSk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRl'
    'JywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywnZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLHRhYmxlXSkKIGZv'
    'ciBuZXR3b3JrIGluIGxhbitbJzE2OS4yNTQuMC4wLzE2JywnMjI0LjAuMC4wLzQnXToKICB0dW5uZWwuY29tbWFuZChbJ2lw'
    'Jywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLHJvdXRlWydkZXYnXSwnc2NvcGUnLCdsaW5rJywndGFibGUnLFBI'
    'WVNJQ0FMX1RBQkxFXSkKIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJyxy'
    'b3V0ZVsnZ2F0ZXdheSddLCdkZXYnLHJvdXRlWydkZXYnXSwnbWV0cmljJywnMTAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVd'
    'KQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjIn'
    'LCdkZXYnLHR1bm5lbC5GVUxMX0hPU1QsJ21ldHJpYycsJzEwJywndGFibGUnLFZQTl9UQUJMRV0pCiBmb3IgcHJpb3JpdHks'
    'bWFyayx0YWJsZSBpbiBbKDc2LERJUkVDVCxQSFlTSUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICB0dW5uZWwu'
    'Y29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1'
    'cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLHBy'
    'aW9yaXR5LCdmd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0pCiAjIFJlcGxpZXMgdG8gYSBmb3J3YXJkZWQgY29u'
    'dGFpbmVyIHJldHVybiB0aHJvdWdoIGl0cyBjb25uZWN0ZWQgbWFpbiByb3V0ZS4KIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdy'
    'dWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lpZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiB0dW5u'
    'ZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbidd'
    'KQogIyBBIHRlbXBvcmFyeSBjbG9zZWQgc3RhdGUgaXMgYWNjZXB0YWJsZTsgYW4gdW5ndWFyZGVkIHN0YXRlIGlzIG5vdC4K'
    'IG9zLnJlcGxhY2UodG1wLGNmZykKIHR1bm5lbC53cml0ZSh0dW5uZWwuUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQog'
    'dHVubmVsLmNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogc3luY193YXlkcm9pZF9uZXR3b3Jr'
    'KGZvcmNlPVRydWUpCiBpbnN0YWxsKCkKIHR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywncmVzdGFydCcsU0VSVklDRV0p'
    'CiBmb3IgXyBpbiByYW5nZSg4MCk6CiAgaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOmJyZWFrCiAg'
    'dGltZS5zbGVlcCguMSkKIGVsc2U6cmFpc2UgUnVudGltZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC30LDQv9GD0YHR'
    'gtC40YLRjCDQvtCx0YDQsNCx0L7RgtGH0LjQuiDQuNGB0LrQu9GO0YfQtdC90LjQuS4nKQogdHVubmVsLmNvbW1hbmQoWydp'
    'cCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCdkZXYnLFRVTiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZV'
    'TExfVEFCTEVdKQogdHVubmVsLmNvbmZpZ3VyZV9zeXN0ZW1fZG5zKCkKIHR1bm5lbC5jbGVhcl9kbnNfbWFwcGluZ3MoKQog'
    'IyBFeHBsaWNpdGx5IHJlcXVlc3RlZCBETlMgZXhjZXB0aW9ucyBuZWVkIHN0YWxlIHBvcnQtNTMgbWFwcGluZ3MgcmVtb3Zl'
    'ZCB0b28uCiBmb3IgcHJvdG8gaW4gKCd1ZHAnLCd0Y3AnKToKICB0dW5uZWwuY29tbWFuZChbJ2Nvbm50cmFjaycsJy1EJywn'
    'LWYnLCdpcHY0JywnLXAnLHByb3RvLCctLWRwb3J0JywnNTMnLCctLXJlcGx5LXBvcnQtc3JjJyxzdHIoRE5TX1BPUlQpXSxj'
    'aGVjaz1GYWxzZSkKCgpkZWYgc3RvcChyZWxlYXNlPUZhbHNlKToKIHR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywnc3Rv'
    'cCcsU0VSVklDRV0sY2hlY2s9RmFsc2UpCiBpZiByZWxlYXNlIGFuZCBQQVRILndpdGhfbmFtZSgncG9saWN5LW5ldHdvcmsu'
    'anNvbicpLmV4aXN0cygpOgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lp'
    'ZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgZm9yIHByaW9yaXR5LG1hcmssdGFibGUgaW4gWyg3NixE'
    'SVJFQ1QsUEhZU0lDQUxfVEFCTEUpLCg3NyxWUE4sVlBOX1RBQkxFKV06CiAgIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxl'
    'JywnZGVsJywncHJpb3JpdHknLHByaW9yaXR5LCdmd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0sY2hlY2s9RmFs'
    'c2UpCiAgIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkK'
    'ICBQQVRILndpdGhfbmFtZSgncG9saWN5LW5ldHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKZGVmIGNo'
    'YW5nZShhY3Rpb24sY2F0ZWdvcnk9JycsdmFsdWU9Jycsc3RhdGU9Tm9uZSk6CiBvbGQ9bG9hZCgpO3A9anNvbi5sb2Fkcyhq'
    'c29uLmR1bXBzKG9sZCkpCiBpZiBhY3Rpb249PSdtb2RlJzoKICBpZiB2YWx1ZSBub3QgaW4gKCdhbGwnLCdpbmNsdWRlJyk6'
    'cmFpc2UgVmFsdWVFcnJvcign0KDQtdC20LjQvDogYWxsINC40LvQuCBpbmNsdWRlLicpCiAgcFsnbW9kZSddPXZhbHVlCiBl'
    'bGlmIGFjdGlvbi5zdGFydHN3aXRoKCdpbmNsdWRlLScpOgogIGlmIGFjdGlvbiBub3QgaW4gKCdpbmNsdWRlLWFkZCcsJ2lu'
    'Y2x1ZGUtcmVtb3ZlJykgb3IgY2F0ZWdvcnkgbm90IGluIENBVEVHT1JJRVM6cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQ'
    'stC10YHRgtC90L7QtSDQtNC10LnRgdGC0LLQuNC1INGB0L/QuNGB0LrQsCBWUE4uJykKICBpZiBjYXRlZ29yeT09J3BvcnRz'
    'JyBhbmQgc3RyKHZhbHVlKS5jb3VudCgnOicpPT0xOnZhbHVlPXN0cih2YWx1ZSkrJzpvdXQnCiAgdmFsdWU9bm9ybWFsaXpl'
    'KGNhdGVnb3J5LHZhbHVlKQogIGlmIGNhdGVnb3J5PT0ncG9ydHMnIGFuZCBub3QgdmFsdWUuZW5kc3dpdGgoJzpvdXQnKTpy'
    'YWlzZSBWYWx1ZUVycm9yKCfQkiDRgdC/0LjRgdC60LUgVlBOINCy0YvQsdC40YDQsNGO0YLRgdGPINC40YHRhdC+0LTRj9GJ'
    '0LjQtSDQv9C+0YDRgtGLICg6b3V0KTsg0L7RgtCy0LXRgtGLINGB0LXRgNCy0LXRgNC+0LIg0L7RgdGC0LDRjtGC0YHRjyBE'
    'SVJFQ1QuJykKICBpZiBhY3Rpb249PSdpbmNsdWRlLWFkZCcgYW5kIHZhbHVlIG5vdCBpbiBwWydpbmNsdWRlJ11bY2F0ZWdv'
    'cnldOnBbJ2luY2x1ZGUnXVtjYXRlZ29yeV0uYXBwZW5kKHZhbHVlKQogIGlmIGFjdGlvbj09J2luY2x1ZGUtcmVtb3ZlJzpw'
    'WydpbmNsdWRlJ11bY2F0ZWdvcnldPVt4IGZvciB4IGluIHBbJ2luY2x1ZGUnXVtjYXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBl'
    'bGlmIGFjdGlvbj09J3dheWRyb2lkJzpwWyd3YXlkcm9pZF9kaXJlY3QnXT1ib29sKHN0YXRlKQogZWxpZiBhY3Rpb249PSdi'
    'YXNlJzoKICBpZiBjYXRlZ29yeSBub3QgaW4gQkFTRSBvciB2YWx1ZSBub3QgaW4ge2VbJ2lkJ10gZm9yIGUgaW4gQkFTRVtj'
    'YXRlZ29yeV19OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw'
    '0LLQuNC70L4uJykKICBrZXk9Y2F0ZWdvcnkrJzonK3ZhbHVlCiAgcFsnZGlzYWJsZWRfYmFzZSddPVt4IGZvciB4IGluIHBb'
    'J2Rpc2FibGVkX2Jhc2UnXSBpZiB4IT1rZXldCiAgaWYgbm90IHN0YXRlOnBbJ2Rpc2FibGVkX2Jhc2UnXS5hcHBlbmQoa2V5'
    'KQogZWxpZiBhY3Rpb24gaW4gKCdhZGQnLCdyZW1vdmUnKToKICBpZiBjYXRlZ29yeSBub3QgaW4gQ0FURUdPUklFUzpyYWlz'
    'ZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3QsNGPINC60LDRgtC10LPQvtGA0LjRjy4nKQogIHZhbHVlPW5vcm1h'
    'bGl6ZShjYXRlZ29yeSx2YWx1ZSkKICBpZiBhY3Rpb249PSdhZGQnIGFuZCB2YWx1ZSBub3QgaW4gcFtjYXRlZ29yeV06cFtj'
    'YXRlZ29yeV0uYXBwZW5kKHZhbHVlKQogIGlmIGFjdGlvbj09J3JlbW92ZSc6cFtjYXRlZ29yeV09W3ggZm9yIHggaW4gcFtj'
    'YXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBlbHNlOnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg0LTQ'
    'tdC50YHRgtCy0LjQtS4nKQogaWYgcD09b2xkOnJldHVybiBwdWJsaWMoKQogaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZl'
    'KCkgYW5kIG5vdCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK3R1bm5lbC5GVUxMX0hPU1QpLmV4aXN0cygpOgogIHJhaXNlIFJ1'
    'bnRpbWVFcnJvcignVlBOINCy0L7RgdGB0YLQsNC90LDQstC70LjQstCw0LXRgtGB0Y8uINCf0L7QstGC0L7RgNC40YLQtSDQ'
    'uNC30LzQtdC90LXQvdC40LUg0L/RgNCw0LLQuNC7INC/0L7RgdC70LUg0L/QvtC00LrQu9GO0YfQtdC90LjRjzsg0L/RgNC1'
    '0LbQvdC40LUg0L/RgNCw0LLQuNC70LAg0YHQvtGF0YDQsNC90LXQvdGLLicpCiBpZiBhY3Rpb249PSdtb2RlJzoKICAjIEFu'
    'IHVwZGF0ZSBjYW4gbGVhdmUgdGhlIG9sZCB3b3JrZXIgcnVubmluZyB0byBwcmVzZXJ2ZSBhIGxpdmUgdHVubmVsLiBBCiAg'
    'IyB3b3JrZXIgZnJvbSBiZWZvcmUgaW5jbHVkZSBtb2RlIHdvdWxkIHJlYXBwbHkgZnVsbCBtb2RlIG9uIGl0cyBuZXh0IHJl'
    'dHJ5LgogIG1haW5fcGlkPXR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywnc2hvdycsJy1wJywnTWFpblBJRCcsJy0tdmFs'
    'dWUnLHR1bm5lbC5VTklUXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCkKICBpZiBtYWluX3BpZC5pc2RlY2ltYWwoKSBh'
    'bmQgbWFpbl9waWQhPScwJyBhbmQgbWFpbl9waWQhPXN0cih0dW5uZWwuc2F2ZWQoKS5nZXQoJ3JvdXRpbmdfd29ya2VyX3Bp'
    'ZCcpKToKICAgcmFpc2UgUnVudGltZUVycm9yKCfQoNCw0LHQvtGC0LDQtdGCINGC0YPQvdC90LXQu9GMLCDQt9Cw0L/Rg9GJ'
    '0LXQvdC90YvQuSDQtNC+INC+0LHQvdC+0LLQu9C10L3QuNGPLiDQktGL0L/QvtC70L3QuNGC0LUgdnBuIHJlcGFpciwg0LfQ'
    'sNGC0LXQvCDQv9C+0LLRgtC+0YDQuNGC0LUg0YHQvNC10L3RgyDRgNC10LbQuNC80LAuJykKIHNhdmUocCkKIGlmIHR1bm5l'
    'bC5mdWxsX2d1YXJkX2FjdGl2ZSgpIGFuZCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK3R1bm5lbC5GVUxMX0hPU1QpLmV4aXN0'
    'cygpOgogIHRyeTphcHBseSgpCiAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgc2F2ZShvbGQpCiAgIHRyeTphcHBseSgpCiAgIGV4'
    'Y2VwdCBFeGNlcHRpb246cGFzcwogICByYWlzZQogcmV0dXJuIHB1YmxpYygpCgpkZWYgZW5zdXJlX3JvdXRlKCk6CiBpZiBQ'
    'YXRoKCcvc3lzL2NsYXNzL25ldC8nK1RVTikuZXhpc3RzKCk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVw'
    'bGFjZScsJ2RlZmF1bHQnLCdkZXYnLFRVTiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZVTExfVEFCTEVdKQogZWxz'
    'ZTpyYWlzZSBSdW50aW1lRXJyb3IoJ3BvbGljeV9lbmdpbmVfdW5hdmFpbGFibGUnKQo='
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
  if not settings.get('cli_only',False):
   _install_desktop_integration(settings, widget=_widget_package_dir(settings).exists(), force_cache=False)
  if live:
   # The worker may still be running the previous release. Keep its credentials,
   # firewall, policy process and resolver intact, including a retained kill switch.
   has_token=vpn_tunnel.token_status()['has_token']
  else:
   policy.migration(settings)
   vpn_tunnel.ensure_dependencies()
   if not settings.get('cli_only',False):ensure_gui_dependencies()
   core_update(settings)
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
 print(('CLI обновлён до ' if settings.get('cli_only',False) else 'CLI и GUI обновлены до ')+MANAGER_VERSION+'.')
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
 print('Панический поиск: '+('ВКЛЮЧЁН; восстановление без лимита попыток' if t.get('panic') else 'выключен'))
 print('Этап: '+str(t.get('progress',0))+'% — '+t.get('message',''))
 print('Защита при обрыве: '+('включена; разрешённые DIRECT-исключения сохраняются' if st['guard'] else 'выключена, обычная сеть'))
 print('Токен: '+('сохранён ('+str(t.get('token_hint',''))+')' if t.get('has_token') else 'не задан; vpn token save'))
 if st['active'] and t.get('since'):
  seconds=max(0,int(time.time()-t['since']));print(f'Подключено: {seconds//3600} ч {(seconds//60)%60} мин {seconds%60} с')
 if t.get('device_name'):print('Устройство: '+t['device_name']+(' (ожидает отправки на сервер)' if t.get('device_name_pending') else ''))
 print('Режим: '+('только выбранное через VPN; остальное DIRECT' if policy.inclusive(p) else 'весь трафик через VPN с DIRECT-исключениями'))
 print('Исключения: приложения {applications}, сайты/IP {networks}, порты {ports}, DNS {dns}'.format(**{c:len(p[c]) for c in policy.CATEGORIES}))
 print('Базовые исключения: '+str(sum(len(x) for x in policy.BASE.values())-len(p['disabled_base']))+' включено; vpn base list')
 print('Waydroid: '+('напрямую' if p['waydroid_direct'] else 'через VPN'))
 if t.get('error_code'):print('Причина последнего сбоя: '+t['error_code'])
 if check_ip:
  if not st['active']:print('Проверка IP: VPN не подключён.');return
  if policy.inclusive(p):
   address=vpn_tunnel.selected_host_egress()
  else:
   cp=run(['curl','-4','--noproxy','','--socks5-hostname','127.0.0.1:18554','-fsS','--max-time','10','https://api.ipify.org'],check=False,capture=True)
   address=cp.stdout.strip() if cp.returncode==0 else None
  print('Проверенный IP через VPN: '+(address or 'проверка не удалась'))
  if address!='38.180.164.67':raise VPNError('Ожидаемый выход в Эстонии не подтверждён.')


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
 print('Режим: '+('только выбранное через VPN, остальное DIRECT' if policy.inclusive(p) else 'всё через VPN, кроме DIRECT-исключений'))
 for cat in policy.CATEGORIES:
  for value in p['include'][cat]:print('  VPN  '+cat+'  '+value)
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
 p=argparse.ArgumentParser(prog='vpn',description='Evgenium: VPN для всего трафика или только выбранных приложений и адресов')
 p.add_argument('--self-test',action='store_true')
 sub=p.add_subparsers(dest='cmd')
 for name in ('on','repair','toggle'):
  a=sub.add_parser(name,help={'on':'Подключить и показать этапы','repair':'Восстановить соединение','toggle':'Переключить VPN'}[name]);a.add_argument('--no-wait',action='store_true',help='Запустить в фоне')
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-waydroid-watch','internal-vpn-tunnel','internal-vpn-tunnel-cleanup','internal-tls-client','internal-vpn-pause-main','manager-rollback'):sub.add_parser(name)
 pst=sub.add_parser('status',help='Состояние, защита и исключения');pst.add_argument('--json',action='store_true');pst.add_argument('--ip',action='store_true',help='Проверить внешний IP именно через VPN')
 panic=sub.add_parser('panic',help='Бесконечное восстановление VPN и автозапуск');panic.add_argument('value',choices=['on','off','status'],nargs='?',default='status')
 mode=sub.add_parser('mode',help='all: весь трафик; include: через VPN только выбранное');mode.add_argument('value',choices=['all','include'],nargs='?')
 inc=sub.add_parser('include',help='Отдельный список VPN для режима include')
 inc.add_argument('category',choices=['app','site','port','dns'])
 inc.add_argument('operation',choices=['list','add','remove'])
 inc.add_argument('value',nargs='?')
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
  elif cmd=='panic':
   if args.value!='status':vpn_tunnel.set_panic(args.value=='on')
   print('Панический поиск: '+('ВКЛЮЧЁН' if vpn_tunnel.panic_enabled() else 'выключен'))
  elif cmd=='mode':
   if args.value:policy.change('mode',value=args.value)
   print(policy.load()['mode'])
  elif cmd=='include':
   cat={'app':'applications','site':'networks','port':'ports','dns':'dns'}[args.category]
   if args.operation!='list':
    if args.value is None:raise ValueError('Укажите правило для списка VPN.')
    policy.change('include-'+args.operation,cat,args.value)
   print('\n'.join('VPN  '+v for v in policy.load()['include'][cat]) or 'Список VPN пуст.')
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
   if cmd is None:print('\nКоманды: vpn on | off | repair | status --ip | watch | rules | update\nНастройки: vpn mode | include | app | direct | port | dns | base | waydroid | token\nПодробно: vpn --help')
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
