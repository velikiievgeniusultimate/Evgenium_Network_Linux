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

MANAGER_VERSION = "0.6.1"

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
    'biB7IGxhYmVsOiByb290LnR1bm5lbC5ydW5uaW5nIHx8IHJvb3Quc3RhdGUuZ3VhcmQgPyAi0J7RgtC60LvRjtGH0LjRgtGM'
    'IiA6ICLQn9C+0LTQutC70Y7Rh9C40YLRjCI7IHByaW1hcnk6IHRydWU7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYg'
    'KHJvb3QudG9rZW5TYXZlZCB8fCByb290LnN0YXRlLmd1YXJkKTsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiBy'
    'b290LnR1bm5lbC5ydW5uaW5nIHx8IHJvb3Quc3RhdGUuZ3VhcmQgPyAiZGlzY29ubmVjdCIgOiAiY29ubmVjdCJ9KSB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCS0L7RgdGB0YLQsNC90L7Q'
    'stC40YLRjCI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Quc3RhdGUuY29ubmVjdGluZyAmJiByb290LnRv'
    'a2VuU2F2ZWQ7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInJlcGFpciJ9KSB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JLQtdGB'
    '0Ywg0YLRgNCw0YTQuNC6INC40LTRkdGCINGH0LXRgNC10LcgVlBOLCDQutGA0L7QvNC1INCy0LrQu9GO0YfRkdC90L3Ri9GF'
    'INC40YHQutC70Y7Rh9C10L3QuNC5LiDQn9GA0Lgg0L7QsdGA0YvQstC1INC30LDRidC40YnRkdC90L3Ri9C1INC/0L7QtNC6'
    '0LvRjtGH0LXQvdC40Y8g0LHQu9C+0LrQuNGA0YPRjtGC0YHRjy4iOyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyB3cmFwTW9k'
    'ZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRIZWln'
    'aHQ6IHRva2VuQm9keS5pbXBsaWNpdEhlaWdodCArIDQwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlv'
    'dXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiB0b2tlbkJvZHkKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hvcnMu'
    'bWFyZ2luczogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0KLQvtC60LXQvSDQutC70LjQtdC90YLQsCI7IGZvbnQucGl4ZWxT'
    'aXplOiAxNzsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgQy5MYWJlbCB7IHZpc2libGU6IHJvb3QudG9rZW5Mb2NrZWQ7IHRleHQ6IHJvb3QudHVubmVsLnRva2VuX2hp'
    'bnQgfHwgItCi0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvSI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7IGlk'
    'OiB0b2tlbklucHV0OyB2aXNpYmxlOiAhcm9vdC50b2tlbkxvY2tlZDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgcGxhY2Vo'
    'b2xkZXJUZXh0OiAiRVZOMS3igKYiOyBlY2hvTW9kZTogVGV4dElucHV0LlBhc3N3b3JkOyBzZWxlY3RCeU1vdXNlOiB0cnVl'
    'OyBlbmFibGVkOiAhcm9vdC5idXN5ICYmICFyb290LnR1bm5lbC5ydW5uaW5nIH0KICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiByb290LnRva2VuTG9ja2VkID8gItCY0LfQvNC10L3QuNGC0YwiIDog'
    'ItCf0L7QtNGC0LLQtdGA0LTQuNGC0YwiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFyb290LnR1bm5lbC5ydW5u'
    'aW5nICYmIChyb290LnRva2VuTG9ja2VkIHx8IC9eRVZOMS1bQS1aYS16MC05Xy1dezQzfSQvLnRlc3QodG9rZW5JbnB1dC50'
    'ZXh0LnRyaW0oKSkpOyBvbkNsaWNrZWQ6IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChy'
    'b290LnRva2VuTG9ja2VkKSByb290LnRva2VuRWRpdGluZyA9IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGVsc2Ugcm9vdC5hY3Rpb24oe2FjdGlvbjogInRva2VuLXNhdmUiLCB0b2tlbjogdG9rZW5JbnB1dC50ZXh0'
    'LnRyaW0oKX0sIGZ1bmN0aW9uKCkgeyB0b2tlbklucHV0LmNsZWFyKCk7IHJvb3QudG9rZW5FZGl0aW5nID0gZmFsc2UgfSkK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIEZsYXRCdXR0b24geyB2aXNpYmxlOiByb290LnRva2VuRWRpdGluZzsgbGFiZWw6ICLQntGC0LzQtdC90LAiOyBvbkNs'
    'aWNrZWQ6IHsgdG9rZW5JbnB1dC5jbGVhcigpOyByb290LnRva2VuRWRpdGluZyA9IGZhbHNlIH0gfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogItCe'
    '0LTQuNC9INGC0L7QutC10L0g0L3QsCDRh9C10LvQvtCy0LXQutCwIOKAlCDQtNC70Y8g0LLRgdC10YUg0LXQs9C+INGD0YHR'
    'gtGA0L7QudGB0YLQsi4iOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIENhcmQgewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgaW1wbGljaXRI'
    'ZWlnaHQ6IHJvdXRlQm9keS5pbXBsaWNpdEhlaWdodCArIDQwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5M'
    'YXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlkOiByb3V0ZUJvZHkKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBhbmNob3JzLmZpbGw6IHBhcmVudAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFuY2hv'
    'cnMubWFyZ2luczogMjAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxMgogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JzQsNGA0YjRgNGD0YIiOyBmb250LnBpeGVsU2l6ZTogMTc7'
    'IGZvbnQuYm9sZDogdHJ1ZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IEMuQ29tYm9Cb3ggewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZDogcm91dGVQaWNrZXIKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBlbmFibGVkOiAhcm9vdC5idXN5ICYmICFyb290LnN0YXRlLmNvbm5lY3RpbmcKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJvcGVydHkgdmFyIGNob2ljZXM6IFt7aWQ6ImF1dG8iLGxhYmVsOiLQkNCy'
    '0YLQvtC80LDRgtC40YfQtdGB0LrQuCJ9XS5jb25jYXQoKHJvb3QudHVubmVsLnJvdXRlcyB8fCB7fSkuY2hvaWNlcyB8fCBb'
    'XSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IGNob2ljZXMKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgdGV4dFJvbGU6ICJsYWJlbCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Y3VycmVudEluZGV4OiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc2VsZWN0ZWQgPSAo'
    'cm9vdC50dW5uZWwucm91dGVzIHx8IHt9KS5zZWxlY3RlZCB8fCAiYXV0byIKICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIGZvciAobGV0IGk9MDtpPGNob2ljZXMubGVuZ3RoO2krKykgaWYgKGNob2ljZXNbaV0uaWQgPT09IHNl'
    'bGVjdGVkKSByZXR1cm4gaQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIDAKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkFj'
    'dGl2YXRlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjoicm91dGUiLHZhbHVlOmNob2ljZXNbY3VycmVudEluZGV4XS5pZH0pCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiAi0JDQstGC0L7QvNCw0YLQuNGH0LXRgdC60Lg6INC+0LTQuNC9INC30LDQvNC10YAsINC30LDRgtC10Lwg0L/Q'
    'vtC00LrQu9GO0YfQtdC90LjQtSDQv9C+INGB0L7RhdGA0LDQvdGR0L3QvdC+0LzRgyDQv9C+0YDRj9C00LrRgy4g0JrQsNC2'
    '0LTRi9C5INC90L7QstGL0Lkg0LfQsNC/0YPRgdC6IOKAlCDRgSDQv9C10YDQstC+0LPQviDQvNC10YHRgtCwLiDCq9CS0L7R'
    'gdGB0YLQsNC90L7QstC40YLRjMK7INC/0L7QstGC0L7RgNGP0LXRgiDQt9Cw0LzQtdGALiI7IHdyYXBNb2RlOiBUZXh0Lldy'
    'YXA7IExheW91dC5maWxsV2lkdGg6IHRydWU7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogKHJvb3Qu'
    'dHVubmVsLnJvdXRlcyB8fCB7fSkub3JkZXIgfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVs'
    'ZWdhdGU6IEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJvcGVy'
    'dHkgc3RyaW5nIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQgcHJv'
    'cGVydHkgaW50IGluZGV4CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZXh0OiB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNob2ljZXMgPSAocm9vdC50dW5uZWwucm91dGVzIHx8'
    'IHt9KS5jaG9pY2VzIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhYmVs'
    'ID0gbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChsZXQgaT0wO2k8'
    'Y2hvaWNlcy5sZW5ndGg7aSsrKSBpZiAoY2hvaWNlc1tpXS5pZCA9PT0gbW9kZWxEYXRhKSBsYWJlbD1jaG9pY2VzW2ldLmxh'
    'YmVsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIChpbmRleCsxKSsiLiAiK2xh'
    'YmVsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICB3cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjog'
    'cm9vdC50ZXh0TXV0ZWQKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntGC0YfRkdGCINC00LvRjyDQv9C+0LTQtNC1'
    '0YDQttC60LgiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFyb290LnN0YXRlLmNvbm5lY3Rpbmc7IG9uQ2xpY2tl'
    'ZDogcm9vdC5hY3Rpb24oe2FjdGlvbjoicmVwb3J0LXByZXZpZXcifSxmdW5jdGlvbihyZXBseSl7CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICB2YXIgcmVwb3J0PUpTT04ucGFyc2UocmVwbHkub3V0cHV0KTtyb290LnJlcG9ydElkPXJlcG9ydC5y'
    'ZXBvcnRfaWQ7cm9vdC5yZXBvcnRUZXh0PUpTT04uc3RyaW5naWZ5KHJlcG9ydCxudWxsLDIpO3JlcG9ydENvbnNlbnQuY2hl'
    'Y2tlZD1mYWxzZTtzdXBwb3J0RGlhbG9nLm9wZW4oKQogICAgICAgICAgICAgICAgICAgICAgICB9KSB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCf0YDQvtCy0LXRgNC40YLRjCDQvtCx0L3QvtCy0LvQtdC90LjR'
    'jyI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInVwZGF0ZSJ9'
    'KSB9CiAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIHZpc2libGU6IHJvb3QucGFnZUluZGV4ID49IDEgJiYgcm9vdC5wYWdlSW5kZXggPD0gNAogICAgICAg'
    'ICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgIHNwYWNpbmc6'
    'IDE2CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0'
    'LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgd3JhcE1vZGU6IFRleHQuV3JhcAogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJvb3QudGV4dE11dGVkCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0'
    'ZXh0OiByb290LnBhZ2VJbmRleCA9PT0gMSA/ICLQktGL0LHRgNCw0L3QvdGL0LUg0L/RgNC40LvQvtC20LXQvdC40Y8g0L/Q'
    'vtC00LrQu9GO0YfQsNGO0YLRgdGPINC90LDQv9GA0Y/QvNGD0Y4uINCe0YHRgtCw0LvRjNC90YvQtSDQuNGB0L/QvtC70YzQ'
    't9GD0Y7RgiBWUE4uIiA6IHJvb3QucGFnZUluZGV4ID09PSAyID8gItCU0L7QsdCw0LLRjNGC0LUg0LTQvtC80LXQvSwg0LDQ'
    'tNGA0LXRgSDQuNC70Lgg0L/QvtC00YHQtdGC0YwuINCU0L7QvNC10L3RiyDQstC60LvRjtGH0LDRjtGCINC/0L7QtNC00L7Q'
    'vNC10L3Rizsg0LfQvdCw0LogPSDQt9Cw0LTQsNGR0YIg0YLQvtGH0L3QvtC1INGB0L7QstC/0LDQtNC10L3QuNC1LiDQn9GA'
    '0Lgg0L7QsdGJ0LXQvCBJUCDQu9GD0YfRiNC1INGD0LrQsNC30YvQstCw0YLRjCDQtNC+0LzQtdC9LiIgOiByb290LnBhZ2VJ'
    'bmRleCA9PT0gMyA/ICLQmNGB0YXQvtC00Y/RidC40LUg4oCUINC/0L7QtNC60LvRjtGH0LXQvdC40Y8g0Log0YPQutCw0LfQ'
    'sNC90L3QvtC80YMg0L/QvtGA0YLRgy4g0JLRhdC+0LTRj9GJ0LjQtSDigJQg0L/RgNGP0LzRi9C1INC+0YLQstC10YLRiyDQ'
    'stCw0YjQtdCz0L4g0YHQtdGA0LLQtdGA0LAuINCe0LHQsCDigJQg0L7QsdCwINC90LDQv9GA0LDQstC70LXQvdC40Y8uIiA6'
    'ICLQntCx0YvRh9C90YvQuSBETlMg0L7RgdGC0LDRkdGC0YHRjyDQsiBWUE4uINCU0L7QsdCw0LLQu9C10L3QvdGL0LUg0LfQ'
    'tNC10YHRjCBETlMt0YHQtdGA0LLQtdGA0Ysg0L/QvtC70YPRh9Cw0Y7RgiDQt9Cw0L/RgNC+0YHRiyDQvdCw0L/RgNGP0LzR'
    'g9GOINC4INC80L7Qs9GD0YIg0LLQuNC00LXRgtGMINC30LDQv9GA0LDRiNC40LLQsNC10LzRi9C1INC40LzQtdC90LAuINCt'
    '0YLQviDQvdC1INGB0L/QuNGB0L7QuiDRgdCw0LnRgtC+0LIuIgogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJvQm94IHsgaWQ6IHBvcnRQcm90b2NvbDsgdmlzaWJs'
    'ZTogcm9vdC5wYWdlSW5kZXggPT09IDM7IG1vZGVsOiBbIlRDUCIsICJVRFAiLCAiQk9USCJdOyBMYXlvdXQucHJlZmVycmVk'
    'V2lkdGg6IDEwMCB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7IGlkOiBleGNlcHRpb25JbnB1'
    'dDsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgc2VsZWN0QnlNb3VzZTogdHJ1ZTsgcGxhY2Vob2xkZXJUZXh0OiByb290LnBh'
    'Z2VJbmRleCA9PT0gMSA/ICLQmNC80Y8g0L/RgNC+0YbQtdGB0YHQsCDQuNC70LggL9C/0L7Qu9C90YvQuS/Qv9GD0YLRjCIg'
    'OiByb290LnBhZ2VJbmRleCA9PT0gMiA/ICJleGFtcGxlLmNvbSDQuNC70LggMTkyLjE2OC4xLjIwIiA6IHJvb3QucGFnZUlu'
    'ZGV4ID09PSAzID8gIjI1NTY1IiA6ICLQkNC00YDQtdGBIEROUywg0L3QsNC/0YDQuNC80LXRgCAxOTIuMTY4LjEuMSIgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5Db21ib0JveCB7IGlkOiBwb3J0RGlyZWN0aW9uOyB2aXNpYmxlOiByb290'
    'LnBhZ2VJbmRleCA9PT0gMzsgbW9kZWw6IFsi0JjRgdGF0L7QtNGP0YnQuNC1IiwgItCS0YXQvtC00Y/RidC40LUiLCAi0J7Q'
    'sdCwIl07IExheW91dC5wcmVmZXJyZWRXaWR0aDogMTQwIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0'
    'b24geyBsYWJlbDogItCU0L7QsdCw0LLQuNGC0YwiOyBwcmltYXJ5OiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5'
    'ICYmIGV4Y2VwdGlvbklucHV0LnRleHQudHJpbSgpLmxlbmd0aCA+IDA7IG9uQ2xpY2tlZDogewogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGNvbnN0IHZhbHVlID0gcm9vdC5wYWdlSW5kZXggPT09IDMgPyBwb3J0UHJvdG9jb2wuY3VycmVu'
    'dFRleHQudG9Mb3dlckNhc2UoKSArICI6IiArIGV4Y2VwdGlvbklucHV0LnRleHQudHJpbSgpICsgIjoiICsgWyJvdXQiLCAi'
    'aW4iLCAiYm90aCJdW3BvcnREaXJlY3Rpb24uY3VycmVudEluZGV4XSA6IGV4Y2VwdGlvbklucHV0LnRleHQudHJpbSgpCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcm9vdC5hY3Rpb24oe2FjdGlvbjogImFkZCIsIGNhdGVnb3J5OiByb290'
    'LmNhdGVnb3J5LCB2YWx1ZTogdmFsdWV9LCBmdW5jdGlvbigpIHsgZXhjZXB0aW9uSW5wdXQuY2xlYXIoKSB9KQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgfSB9CiAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IHJvb3QucG9saWN5W3Jvb3QuY2F0ZWdv'
    'cnldIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxlZ2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSBzdHJpbmcgbW9kZWxEYXRhCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMu'
    'TGFiZWwgeyB0ZXh0OiBtb2RlbERhdGE7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXBBbnl3'
    'aGVyZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24g'
    'eyBsYWJlbDogItCj0LTQsNC70LjRgtGMIjsgZGFuZ2VyOiB0cnVlOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5OyBvbkNs'
    'aWNrZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJyZW1vdmUiLCBjYXRlZ29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IG1v'
    'ZGVsRGF0YX0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdmlzaWJsZTogIShyb290LnBvbGljeVtyb290LmNhdGVnb3J5XSB8fCBb'
    'XSkubGVuZ3RoOyB0ZXh0OiAi0JLQsNGI0LjRhSDQuNGB0LrQu9GO0YfQtdC90LjQuSDQv9C+0LrQsCDQvdC10YIiOyBjb2xv'
    'cjogcm9vdC50ZXh0TXV0ZWQgfQogICAgICAgICAgICAgICAgICAgICAgICBSaWJib25Td2l0Y2ggeyB0ZXh0OiAi0J7RgtC+'
    '0LHRgNCw0LfQuNGC0Ywg0LHQsNC30L7QstGL0LUg0LjRgdC60LvRjtGH0LXQvdC40Y8iOyBjaGVja2VkOiByb290LnNob3dC'
    'YXNlOyBvblRvZ2dsZWQ6IHJvb3Quc2hvd0Jhc2UgPSBjaGVja2VkIH0KICAgICAgICAgICAgICAgICAgICAgICAgQ29sdW1u'
    'TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHZpc2libGU6IHJvb3Quc2hvd0Jhc2UKICAgICAgICAgICAgICAgICAgICAgICAgICAgIFJlcGVh'
    'dGVyIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2RlbDogKHJvb3QucG9saWN5LmJhc2UgfHwge30pW3Jv'
    'b3QuY2F0ZWdvcnldIHx8IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsZWdhdGU6IFJvd0xheW91dCB7'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHZhciBtb2RlbERhdGEKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhLmxhYmVsOyBMYXlvdXQuZmlsbFdpZHRoOiB0'
    'cnVlOyB3cmFwTW9kZTogVGV4dC5XcmFwOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgIFJpYmJvblN3aXRjaCB7IGNoZWNrZWQ6IEJvb2xlYW4obW9kZWxEYXRhLmVuYWJsZWQpOyBlbmFibGVk'
    'OiAhcm9vdC5idXN5OyBvblRvZ2dsZWQ6IHJvb3QuYWN0aW9uKHthY3Rpb246ICJiYXNlIiwgY2F0ZWdvcnk6IHJvb3QuY2F0'
    'ZWdvcnksIHZhbHVlOiBtb2RlbERhdGEuaWQsIGVuYWJsZWQ6IGNoZWNrZWR9KSB9CiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRl'
    'ZDsgdGV4dDogItCS0Ysg0LzQvtC20LXRgtC1INCy0YvQutC70Y7Rh9C40YLRjCDQu9GO0LHQvtC1INCx0LDQt9C+0LLQvtC1'
    'INC/0YDQsNCy0LjQu9C+LiDQodC60YDRi9GC0LjQtSDRgdC/0LjRgdC60LAg0L3QtSDQvNC10L3Rj9C10YIg0LXQs9C+INGB'
    '0L7RgdGC0L7Rj9C90LjQtS4iIH0KICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICBD'
    'b2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDEK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgIEMuTGFiZWwgeyB0ZXh0OiAi0JfQsNC/0YPRidC10L3RiyDRgdC10LnRh9Cw0YEiOyBmb250LnBpeGVsU2l6ZTog'
    'MTg7IGZvbnQuYm9sZDogdHJ1ZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'Um93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5UZXh0RmllbGQgeyBpZDogYXBwU2VhcmNoOyBMYXlvdXQuZmlsbFdpZHRo'
    'OiB0cnVlOyBwbGFjZWhvbGRlclRleHQ6ICLQn9C+0LjRgdC6INC/0YDQuNC70L7QttC10L3QuNGPIiB9CiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0J7QsdC90L7QstC40YLRjCDRgdC/0LjRgdC+0Loi'
    'OyBlbmFibGVkQnV0dG9uOiAhcm9vdC5ydW5uaW5nUGVuZGluZzsgb25DbGlja2VkOiByb290LnJlZnJlc2hSdW5uaW5nKCkg'
    'fQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiByb290LnBhZ2VJbmRleCA9PT0gMSA/IHJvb3QuZmlsdGVy'
    'ZWRSdW5uaW5nKCkgOiBbXQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRlOiBSb3dMYXlvdXQgewog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXF1aXJlZCBwcm9wZXJ0eSB2YXIgbW9kZWxEYXRhCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'IExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwg'
    'eyB0ZXh0OiBtb2RlbERhdGEubmFtZTsgY29sb3I6IHJvb3QudGV4dE1haW4gfQogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YS5leGU7IExheW91dC5maWxsV2lkdGg6IHRydWU7IGVs'
    'aWRlOiBUZXh0LkVsaWRlTWlkZGxlOyBjb2xvcjogcm9vdC50ZXh0TXV0ZWQ7IGZvbnQucGl4ZWxTaXplOiAxMSB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRmxh'
    'dEJ1dHRvbiB7IGxhYmVsOiBtb2RlbERhdGEuZXhjbHVkZWQgPyAi0JTQvtCx0LDQstC70LXQvdC+IiA6ICLQkiDQvtCx0YXQ'
    'vtC0IjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeSAmJiAhbW9kZWxEYXRhLmV4Y2x1ZGVkOyBvbkNsaWNrZWQ6IHJvb3Qu'
    'YWN0aW9uKHthY3Rpb246ICJhZGQiLCBjYXRlZ29yeTogImFwcGxpY2F0aW9ucyIsIHZhbHVlOiBTdHJpbmcobW9kZWxEYXRh'
    'LmV4ZSB8fCBtb2RlbERhdGEubmFtZSB8fCAiIil9KSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'fQogICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgIHZpc2libGU6IHJv'
    'b3QucGFnZUluZGV4ID09PSA1CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTgKICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IExheW91dC5m'
    'aWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRlZDsgdGV4dDogIldheWRy'
    'b2lkINGD0L/RgNCw0LLQu9GP0LXRgtGB0Y8g0L7RgtC00LXQu9GM0L3QviDQvtGCINC/0YDQuNC70L7QttC10L3QuNC5INC6'
    '0L7QvNC/0YzRjtGC0LXRgNCwLiDQn9C+INGD0LzQvtC70YfQsNC90LjRjiDQstC10YHRjCDQtdCz0L4g0YLRgNCw0YTQuNC6'
    'LCDQstC60LvRjtGH0LDRjyBETlMsINC40LTRkdGCINC90LDQv9GA0Y/QvNGD0Y4uIiB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIFJpYmJvblN3aXRjaCB7IHRleHQ6ICJXYXlkcm9pZCDQsiDQvtCx0YXQvtC0IFZQTiI7IGNoZWNrZWQ6IHJvb3QucG9s'
    'aWN5LndheWRyb2lkX2RpcmVjdCAhPT0gZmFsc2U7IGVuYWJsZWQ6ICFyb290LmJ1c3k7IG9uVG9nZ2xlZDogcm9vdC5hY3Rp'
    'b24oe2FjdGlvbjogIndheWRyb2lkIiwgZW5hYmxlZDogY2hlY2tlZH0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgQy5M'
    'YWJlbCB7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNdXRl'
    'ZDsgdGV4dDogcm9vdC5wb2xpY3kud2F5ZHJvaWRfZGlyZWN0ICE9PSBmYWxzZSA/ICLQn9GA0Y/QvNC+0LUg0L/QvtC00LrQ'
    'u9GO0YfQtdC90LjQtTogV2F5ZHJvaWQg0LjRgdC/0L7Qu9GM0LfRg9C10YIg0LDQtNGA0LXRgSDQstCw0YjQtdCz0L4g0L/R'
    'gNC+0LLQsNC50LTQtdGA0LAuINCe0LHRidC40LUg0LjRgdC60LvRjtGH0LXQvdC40Y8g0L3QtSDQvtCz0YDQsNC90LjRh9C4'
    '0LLQsNGO0YIg0Y3RgtC+0YIg0YDQtdC20LjQvC4iIDogIldheWRyb2lkINC40YHQv9C+0LvRjNC30YPQtdGCIFZQTi4g0J/R'
    'gNC4INC+0LHRgNGL0LLQtSDRgtGD0L3QvdC10LvRjyDQtdCz0L4g0LLQvdC10YjQvdC40LUg0L/QvtC00LrQu9GO0YfQtdC9'
    '0LjRjyDQsdC70L7QutC40YDRg9GO0YLRgdGPLiIgfQogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIH0K'
    'ICAgICAgICAgICAgfQogICAgICAgIH0KICAgIH0KfQo='
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
    'OkZhbHNlLCdsYWJlbCc6J0hTVkRTIOKGkiDQrdGB0YLQvtC90LjRjyd9LAogeydpZCc6J2VlLXRscycsJ2FkZHJlc3MnOicz'
    'OC4xODAuMTY0LjY3JywnaWRlbnRpdHknOiczOC4xODAuMTY0LjY3JywncG9ydCc6NDQzLCd0bHMnOlRydWUsJ2xhYmVsJzon'
    '0K3RgdGC0L7QvdC40Y8g0YfQtdGA0LXQtyBUTFMnfSwKIHsnaWQnOidlZS1ldmd0JywnYWRkcmVzcyc6JzM4LjE4MC4xNjQu'
    'NjcnLCdpZGVudGl0eSc6JzM4LjE4MC4xNjQuNjcnLCdwb3J0Jzo0NDMsJ3Rscyc6RmFsc2UsJ2V2Z3QnOlRydWUsJ2xhYmVs'
    'Jzon0K3RgdGC0L7QvdC40Y8g0YfQtdGA0LXQtyBFdmdlbml1bVR1bm5lbCd9LAogeydpZCc6J2VlLWV2Z3QtcnUnLCdhZGRy'
    'ZXNzJzonMzguMTgwLjE2NC42NycsJ2lkZW50aXR5JzonMzguMTgwLjE2NC42NycsJ3BvcnQnOjQ0MywndGxzJzpGYWxzZSwn'
    'ZXZndCc6VHJ1ZSwndHJhbnNwb3J0X2FkZHJlc3MnOlNFUlZFUiwndHJhbnNwb3J0X3BvcnQnOjI0NTc5LCdsYWJlbCc6J0V2'
    'Z2VuaXVtVHVubmVsIMK3IEhTVkRTIOKGkiDQrdGB0YLQvtC90LjRjyd9LAopCkFDVElWRSA9IENBTkRJREFURVNbMF0KcmFu'
    'a19hcGkgPSBOb25lCnN1cHBvcnRfYXBpID0gTm9uZQp0bHNfYXBpID0gTm9uZQpUTFNfUFJPQ0VTUyA9IE5vbmUKIyBLZXB0'
    'IG9ubHkgZm9yIHJlbW92aW5nIHJvdXRlcyBpbnN0YWxsZWQgYnkgcHJlLW1pZ3JhdGlvbiB2ZXJzaW9ucy4KTEVHQUNZX0VO'
    'RFBPSU5UUyA9ICgnMTA5LjE5NC42Ny4xNTknLCAnMTkyLjE2OC4wLjE2MycpCkhFQUxUSCA9ICcxMC43Ny4wLjEnClJFUUlE'
    'ID0gMTc3ClRPS0VOX1BBVFRFUk4gPSByJ0VWTjEtW0EtWmEtejAtOV8tXXs0M30nClNUT1AgPSBGYWxzZQpETlNfUFJPQ0VT'
    'UyA9IE5vbmUKcG9saWN5ID0gTm9uZQpQSU5ORURfQ0EgPSAnLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlFT0RD'
    'Q0FxQ2dBd0lCQWdJVWJrSis4U2FxQWd3WTFSREFqWlJUamNxUTllTXdEUVlKS29aSWh2Y05BUUVMXG5CUUF3SWpFZ01CNEdB'
    'MVVFQXd3WFJYWm5aVzVwZFcwZ2NISnBkbUYwWlNCV1VFNGdRMEV3SGhjTk1qWXhNREEzXG5NVGt4TXpReFdoY05Nell4TURB'
    'ME1Ua3hNelF4V2pBaU1TQXdIZ1lEVlFRRERCZEZkbWRsYm1sMWJTQndjbWwyXG5ZWFJsSUZaUVRpQkRRVENDQWFJd0RRWUpL'
    'b1pJaHZjTkFRRUJCUUFEZ2dHUEFEQ0NBWW9DZ2dHQkFPWitudmlFXG4yT3JGN1BkdGtrL1hJYUZWSXZKbHZDMTFWWmY5cmxq'
    'Q0JJdkJ5a2JzckFyR3J5UUhHbnV1WExOYWFTOE50THhZXG5OZVNCREs2TWRnWUpBZWpzUDR3SVR1YjNuTWpTRzJ1bUlJVlU2'
    'bUUrR0RvekdQbE5NTkorYmhrS2FWaGFQakZFXG55WUxZcmRQZTVWQTR3KzVwME5aT0Q2Q0JIRDN0RVhXQk5SSWVWU1didE1J'
    'VHNPRVMxUGUvYUFMN3Yzb05JVmtWXG44bkR3OWo3K3dHMnk1ZGhicDdLVUpIYnJEQjAyNHI3Y1lyUTNheFlGNmd5a2ptenRw'
    'S1hzYmt4UXYyN0J2aFNCXG5lMEVrdEovakNTNlI5SUltWWdJUXJDcmFXWm1WU2NuR0YvQXE0VE53MUg0T3pGQ2tSKzdKVWxZ'
    'blNZVXZNUmkxXG5Mektla1VDKzIvMFdGbWhuQ29EdGRqY29ZYnhwTHBLRGVsR2lTM1JzTkN2eG5zbE1hUHo1aENjRjY0WTdS'
    'aWpYXG5qNkR1Q1lwRllXbHIxM0IyMHFBblJvVWFzK0FqWDdQWENrUjR4T2hIK2tXOC9IbUZIaUhrb2hXRTB3bGxJU0JYXG5W'
    'Qm83S0JPWmQ4U1Zld3liZDJyQjRzb1hvdVR0alhzL2pUZ2UrSFd4UURHUFAxdW1mejhjRkxSL3VRSURBUUFCXG5vMll3WkRB'
    'ZEJnTlZIUTRFRmdRVW9RZlRpZjc3eFd0MDZoYVhoM2hhODkwcWtUOHdId1lEVlIwakJCZ3dGb0FVXG5vUWZUaWY3N3hXdDA2'
    'aGFYaDNoYTg5MHFrVDh3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBT0JnTlZIUThCXG5BZjhFQkFNQ0FRWXdEUVlKS29a'
    'SWh2Y05BUUVMQlFBRGdnR0JBSTdHS25tZkpqdUwxUXZ5UnRsdytIcjZBWS9aXG5PeGREdkVDZWZvRkw3UTQxVlphK0w3REk4'
    'N2tNTFlIeWdSSHVzaDY2b1V2ODc4VFdNdGFzbmJ0Lzh3WWc2anJ3XG5BeWdwZy9GM1ZEMjR5VHJuSjdPQ2R5R2liNkxHdXVz'
    'dVRQNHJVR3NjY1djem5RWFlGa3pSVnoxVmVZTVpVTitQXG50QVZpTmw0RVJTMWZoK2NHelQ0T3FYUWtKRGtSZXFIL0hDVEU4'
    'a1VRVVVnWGFTWHBoS2pHYThwUjJIVmVGdWtYXG4rMHBwMWlSKzZkaTRhQ0thcGthVGlWUjNyNjJ0UkJVd2J4b0ZZUnl4Tlh5'
    'blRLOUVobk0yNVdFcG4vcXUwbHNEXG5vWHJGVm1qMEFRZkFVSFJOLzJyUEwvL3c2UlBFcEhnVWNydDd6dVNnb1hKWmgwRFQz'
    'MFZFSUs5Tk5idUtTRmQ5XG5JaVd2cnhiVlFTNm1RZ3RFWk40TGMySG0xcHZZK1dySStIMDN1ODA0MitjcExJc0NueFBtOVd2'
    'aTdkTVh4cW9iXG5vMi9hTDJ4REc1Ry84V1ZSL1c1RUFmdktkeGRyazNINjAyb2Njb3Y3K0pnMXZveGkwMEliZE1FeG9NeGQ1'
    'YWVoXG5mWFJpSmhURUZvdUlwbUVTQ0Y0dlZNbFdGcjNtcWxRM0dLU1BWQT09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t'
    'XG4nCgoKRlVMTF9IT1NUID0gJ2V2bi1mdWxsLWhvc3QnCkZVTExfUEVFUiA9ICdldm4tZnVsbC1wZWVyJwpGVUxMX05FVCA9'
    'ICcxNzIuMjkuMjQ3LjAvMzAnCkZVTExfVEFCTEUgPSAnNTE4MjgnCkFETUlOX1RBQkxFID0gJzUxODI5JwpGVUxMX0dVQVJE'
    'ID0gJ2V2bl9zdGFyZml2ZV9mdWxsJwpkZWYgZnVsbF9zdGF0ZSgpOgogICAgcmV0dXJuIFJPT1QvJ2Z1bGwtbmV0d29yay5q'
    'c29uJwoKCmRlZiBjaGFyb25fYmluYXJ5KCk6CiAgICBjYW5kaWRhdGVzID0gKCcvdXNyL3NiaW4vY2hhcm9uLXN5c3RlbWQn'
    'LCAnL3Vzci9iaW4vY2hhcm9uLXN5c3RlbWQnLAogICAgICAgICAgICAgICAgICAnL3Vzci9saWIvaXBzZWMvY2hhcm9uLXN5'
    'c3RlbWQnLCAnL3Vzci9saWJleGVjL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywKICAgICAgICAgICAgICAgICAgJy91c3IvbGli'
    'L3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQnLCAnL3Vzci9saWJleGVjL3N0cm9uZ3N3YW4vY2hhcm9uLXN5c3RlbWQnKQog'
    'ICAgcmV0dXJuIG5leHQoKHAgZm9yIHAgaW4gY2FuZGlkYXRlcyBpZiBQYXRoKHApLmlzX2ZpbGUoKSksIE5vbmUpCgoKRVZH'
    'VF9WRVJTSU9OID0gJzAuMy4wJwpFVkdUX0FTU0VUUyA9IHsKICd4ODZfNjQnOiAoJ2FtZDY0JywnZmRjYzk0ZDY1ZWE2YzNk'
    'YTc2OGY2NjY2MDAyMTc4M2RhYTQ1YzM2NTZjYzk0NmJhZmQ1MTExYTg2YmIyODVhNicpLAogJ2FhcmNoNjQnOiAoJ2FybTY0'
    'JywnNDMzM2MxYTc0YmFkYWI2Mzg3ZThhNWJiZjJmMWUyZjRmNDA5ZGEyMDM3ZTk0YjMyZTg0NjZiNzAwNjg4YzAyZCcpLAog'
    'J3Jpc2N2NjQnOiAoJ3Jpc2N2NjQnLCdmYzBjMTRjMGZiNGJkMGFlYzIyZDc3MWJhZDIxMzFmN2E1ZGYwNTlkNmY3ZmI1Mzdj'
    'NDY1ZjFmMmFlMjVhMjFmJyksCn0KCmRlZiBlbnN1cmVfZXZndF9iaW5hcnkoKToKICAgIGFzc2V0PUVWR1RfQVNTRVRTLmdl'
    'dChwbGF0Zm9ybS5tYWNoaW5lKCkpCiAgICBpZiBhc3NldCBpcyBOb25lOnJhaXNlIFJ1bnRpbWVFcnJvcignZXZndF9hcmNo'
    'X3Vuc3VwcG9ydGVkJykKICAgIGFyY2gsZGlnZXN0PWFzc2V0CiAgICBwYXRoPVJPT1QvKCdldmdlbml1bS10dW5uZWwtJytF'
    'VkdUX1ZFUlNJT04pCiAgICBpZiBwYXRoLmlzX3N5bWxpbmsoKTpyYWlzZSBSdW50aW1lRXJyb3IoJ2V2Z3RfYmluYXJ5X3N5'
    'bWxpbmsnKQogICAgaWYgcGF0aC5pc19maWxlKCkgYW5kIGhhc2hsaWIuc2hhMjU2KHBhdGgucmVhZF9ieXRlcygpKS5oZXhk'
    'aWdlc3QoKT09ZGlnZXN0OgogICAgICAgIHBhdGguY2htb2QoMG83MDApO3JldHVybiBwYXRoCiAgICBST09ULm1rZGlyKG1v'
    'ZGU9MG83MDAscGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgICB1cmw9J2h0dHBzOi8vZ2l0aHViLmNvbS92ZWxpa2lp'
    'ZXZnZW5pdXN1bHRpbWF0ZS9Fdmdlbml1bV9OZXR3b3JrX0xpbnV4L3JlbGVhc2VzL2Rvd25sb2FkL2V2Z2VuaXVtLXR1bm5l'
    'bC12JytFVkdUX1ZFUlNJT04rJy9ldmdlbml1bS10dW5uZWwtbGludXgtJythcmNoCiAgICB3aXRoIHVybGxpYi5yZXF1ZXN0'
    'LnVybG9wZW4odXJsLHRpbWVvdXQ9MzApIGFzIHJlc3BvbnNlOmJsb2I9cmVzcG9uc2UucmVhZCgxNioxMDI0KjEwMjQrMSkK'
    'ICAgIGlmIGxlbihibG9iKT4xNioxMDI0KjEwMjQgb3IgaGFzaGxpYi5zaGEyNTYoYmxvYikuaGV4ZGlnZXN0KCkhPWRpZ2Vz'
    'dDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2V2Z3RfYmluYXJ5X2NoZWNrc3VtX2ZhaWxlZCcpCiAgICB0bXA9cGF0'
    'aC53aXRoX25hbWUocGF0aC5uYW1lKycubmV3JykKICAgIGZkPW9zLm9wZW4odG1wLG9zLk9fV1JPTkxZfG9zLk9fQ1JFQVR8'
    'b3MuT19UUlVOQ3xvcy5PX05PRk9MTE9XLDBvNzAwKQogICAgdHJ5OgogICAgICAgIHdpdGggb3MuZmRvcGVuKGZkLCd3Yicp'
    'IGFzIG91dHB1dDpvdXRwdXQud3JpdGUoYmxvYik7b3V0cHV0LmZsdXNoKCk7b3MuZnN5bmMob3V0cHV0LmZpbGVubygpKQog'
    'ICAgICAgIG9zLmNobW9kKHRtcCwwbzcwMCk7b3MucmVwbGFjZSh0bXAscGF0aCkKICAgIGZpbmFsbHk6dG1wLnVubGluayht'
    'aXNzaW5nX29rPVRydWUpCiAgICByZXR1cm4gcGF0aAoKCmRlZiBlbnN1cmVfZGVwZW5kZW5jaWVzKCk6CiAgICBpZiBjaGFy'
    'b25fYmluYXJ5KCkgYW5kIGFsbChzaHV0aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2FuY3RsJywnaXAnLCduZnQnLCdjdXJs'
    'Jywnb3BlbnNzbCcsJ2Nvbm50cmFjaycpKToKICAgICAgICBlbnN1cmVfZXZndF9iaW5hcnkoKQogICAgICAgIHJldHVybgog'
    'ICAgc3RhZ2UoJ2RlcGVuZGVuY2llcycsICfQo9GB0YLQsNC90LDQstC70LjQstCw0Y4g0L3QtdC+0LHRhdC+0LTQuNC80YvQ'
    'tSDRgdC40YHRgtC10LzQvdGL0LUg0LrQvtC80L/QvtC90LXQvdGC0YsgVlBOLicsIDMsIGFjdGl2ZT1GYWxzZSkKICAgIGlm'
    'IHNodXRpbC53aGljaCgncGFjbWFuJyk6CiAgICAgICAgYXJncyA9IFsncGFjbWFuJywnLVMnLCctLW5lZWRlZCcsJy0tbm9j'
    'b25maXJtJywnc3Ryb25nc3dhbicsJ2lwcm91dGUyJywnbmZ0YWJsZXMnLCdjdXJsJywnb3BlbnNzbCcsJ2NhLWNlcnRpZmlj'
    'YXRlcycsJ2Nvbm50cmFjay10b29scyddCiAgICBlbGlmIHNodXRpbC53aGljaCgnZG5mJyk6CiAgICAgICAgYXJncyA9IFsn'
    'ZG5mJywnaW5zdGFsbCcsJy15JywnLS1zZXRvcHQ9aW5zdGFsbF93ZWFrX2RlcHM9RmFsc2UnLCdzdHJvbmdzd2FuJywnaXBy'
    'b3V0ZScsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMnLCdjb25udHJhY2stdG9vbHMnXQog'
    'ICAgZWxpZiBzaHV0aWwud2hpY2goJ2FwdC1nZXQnKToKICAgICAgICBjb21tYW5kKFsnYXB0LWdldCcsJ3VwZGF0ZSddLHRp'
    'bWVvdXQ9MzAwKQogICAgICAgIGFyZ3MgPSBbJ2FwdC1nZXQnLCdpbnN0YWxsJywnLXknLCctLW5vLWluc3RhbGwtcmVjb21t'
    'ZW5kcycsJ2NoYXJvbi1zeXN0ZW1kJywnc3Ryb25nc3dhbi1zd2FuY3RsJywnbGlic3Ryb25nc3dhbi1zdGFuZGFyZC1wbHVn'
    'aW5zJywnbGliY2hhcm9uLWV4dHJhLXBsdWdpbnMnLCdpcHJvdXRlMicsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdj'
    'YS1jZXJ0aWZpY2F0ZXMnLCdjb25udHJhY2snXQogICAgZWxzZToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9CQ0LLR'
    'gtC+0LzQsNGC0LjRh9C10YHQutCw0Y8g0YPRgdGC0LDQvdC+0LLQutCwINC60LvQuNC10L3RgtCwINC/0L7QtNC00LXRgNC2'
    '0LjQstCw0LXRgiBBcmNoLCBGZWRvcmEg0LggRGViaWFuL1VidW50dS4nKQogICAgY29tbWFuZChhcmdzLCB0aW1lb3V0PTMw'
    'MCkKICAgIGlmIG5vdCBjaGFyb25fYmluYXJ5KCkgb3Igbm90IGFsbChzaHV0aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2Fu'
    'Y3RsJywnY29ubnRyYWNrJykpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0J/QsNC60LXRgiBzdHJvbmdTd2FuINC9'
    '0LUg0L/RgNC10LTQvtGB0YLQsNCy0LjQuyDQvdC10L7QsdGF0L7QtNC40LzRi9C1INC/0YDQvtCz0YDQsNC80LzRiy4nKQog'
    'ICAgZW5zdXJlX2V2Z3RfYmluYXJ5KCkKCgpkZWYgY2xlYXJfZG5zX21hcHBpbmdzKHByZXZpb3VzX3Zwbj1GYWxzZSk6CiAg'
    'ICAiIiJGb3JnZXQgb25seSB0aGlzIG1hbmFnZXIncyBvYnNvbGV0ZSBETlMgTkFULCBuZXZlciBmbHVzaCBhbGwgY29ubmVj'
    'dGlvbnMuCgogICAgUmVtb3ZpbmcgYW4gbmZ0IE5BVCBjaGFpbiBkb2VzIG5vdCByZW1vdmUgZXhpc3RpbmcgY29ubnRyYWNr'
    'IHRyYW5zbGF0aW9ucy4KICAgIEEgcnVubmluZyByZXNvbHZlciBjYW4gcmV1c2UgaXRzIFVEUCBzb2NrZXQgaW5kZWZpbml0'
    'ZWx5IGFmdGVyIGEgVlBOIHN3aXRjaC4KICAgICIiIgogICAgZmlsdGVycyA9IChbJy0tcmVwbHktcG9ydC1zcmMnLCcxODU1'
    'MyddIGlmIHByZXZpb3VzX3ZwbiBlbHNlCiAgICAgICAgICAgICAgIFsnLS1yZXBseS1wb3J0LXNyYycsJzUzJywnLS1kc3Qt'
    'bmF0JywnMS4xLjEuMSddKQogICAgZm9yIHByb3RvY29sIGluICgndWRwJywndGNwJyk6CiAgICAgICAgcmVzdWx0ID0gY29t'
    'bWFuZChbJ2Nvbm50cmFjaycsJy1EJywnLWYnLCdpcHY0JywnLXAnLHByb3RvY29sLAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICctLWRwb3J0JywnNTMnLCpmaWx0ZXJzXSwgY2hlY2s9RmFsc2UsCiAgICAgICAgICAgICAgICAgICAgICAgICBlbnY9'
    'eyoqb3MuZW52aXJvbiwnTENfQUxMJzonQyd9KQogICAgICAgIGVtcHR5ID0gcmVzdWx0LnJldHVybmNvZGUgPT0gMSBhbmQg'
    'JzAgZmxvdyBlbnRyaWVzIGhhdmUgYmVlbiBkZWxldGVkJyBpbiByZXN1bHQuc3RkZXJyCiAgICAgICAgaWYgcmVzdWx0LnJl'
    'dHVybmNvZGUgIT0gMCBhbmQgbm90IGVtcHR5OgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Ruc190cmFuc2l0'
    'aW9uX2NsZWFudXBfZmFpbGVkJykKCgpkZWYgZnVsbF9ndWFyZF9hY3RpdmUoKToKICAgIHJldHVybiBjb21tYW5kKFsnbmZ0'
    'JywnbGlzdCcsJ3RhYmxlJywnaW5ldCcsRlVMTF9HVUFSRF0sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMAoKCmRlZiBm'
    'dWxsX2ZpcmV3YWxsKCk6CiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgc2V0dGluZ3M9cG9saWN5LmFwaS5s'
    'b2FkX3NldHRpbmdzKCkKICAgICAgICByZXR1cm4gcG9saWN5LmZpcmV3YWxsKHBvbGljeS5sb2FkKCkscG9saWN5LmxvY2Fs'
    'X25ldHdvcmtzKHBoeXNpY2FsX3JvdXRlKCkpLGludChzZXR0aW5nc1sieHJheV91aWQiXSkpCiAgICAjIE1pbmltYWwgZ3Vh'
    'cmQgdXNlZCBieSBpc29sYXRlZCBwcm90b2NvbCB0ZXN0cy4KICAgICMgS2VlcCBsb2NhbCBzdHViIEROUyBvbiBsb29wYmFj'
    'ay4gRE5BVCBvZiAxMjcvOCBvbnRvIGEgdmV0aCBmYWlscyBMaW51eCdzCiAgICAjIGxvb3BiYWNrIHJvdXRlIGNoZWNrczsg'
    'dXBzdHJlYW0gcmVzb2x2ZXIgdHJhZmZpYyBzdGlsbCBvYmV5cyB0aGUgZnVsbCBndWFyZC4KICAgIHJldHVybiBmJycndGFi'
    'bGUgaW5ldCB7RlVMTF9HVUFSRH0ge3sKIGNoYWluIGRucyB7eyB0eXBlIG5hdCBob29rIG91dHB1dCBwcmlvcml0eSAtMTAx'
    'OyBwb2xpY3kgYWNjZXB0OwogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVybgogIGlwIGRhZGRyIHt7IDEuMS4xLjEsIDku'
    'OS45LjkgfX0gcmV0dXJuCiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0'
    'IDUzIGRuYXQgaXAgdG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHBy'
    'aW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8gaXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIg'
    'c25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKIH19CiBjaGFpbiBvdXRwdXQge3sgdHlwZSBmaWx0ZXIgaG9vayBvdXRwdXQgcHJp'
    'b3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFt'
    'ZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4yNTUuMjU1LjI1NSB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0'
    'IDY3IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0zMDsg'
    'cG9saWN5IGRyb3A7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSB9'
    'fSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRh'
    'ZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElF'
    'TlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpaWZuYW1l'
    'ICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDE5NS4yMDkuMjExLjE2MyB0Y3AgZHBvcnQgMjQ1NzkgYWNj'
    'ZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBv'
    'cnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHtDTElFTlR9IGN0IHN0YXRlIGVzdGFibGlzaGVk'
    'LHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIG1ldGEg'
    'bmZwcm90byBpcHY0IGlpZm5hbWUgIntGVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAog'
    'fX0KfX0nJycKCgoKZGVmIHJlZnJlc2hfcmV0YWluZWRfZ3VhcmQoKToKICAgICIiIk1vdmUgb25seSB0aGUgVlBOIHRyYW5z'
    'cG9ydCBleGNlcHRpb24gd2hlbiBhbiBpbmdyZXNzIGVuZHBvaW50IGNoYW5nZXMuIiIiCiAgICBpZiBub3QgZnVsbF9ndWFy'
    'ZF9hY3RpdmUoKToKICAgICAgICByZXR1cm4KICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICByZXBsYWNlbWVudCA9'
    'ICdkZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJytydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYn'
    'LCctJ10sZGF0YT1yZXBsYWNlbWVudCkKICAgICMgUGVyc2lzdCB0aGUgY2xvc2VkIGd1YXJkIGJlZm9yZSBjaGFuZ2luZyB0'
    'aGUgYWN0aXZlIGV4Y2VwdGlvbjsgYSBjcmFzaCBzdGF5cyBjbG9zZWQuCiAgICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5m'
    'dCcscnVsZXMpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKCgpkZWYgdmlydHVhbF9p'
    'cCgpOgogICAgZGF0YSA9IGpzb24ubG9hZHMoaW5zaWRlKFsnaXAnLCctaicsJy00JywnYWRkciddKS5zdGRvdXQpCiAgICBp'
    'cHMgPSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBkYXRhIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRyX2luZm8nLCBbXSkKICAg'
    'ICAgICAgICBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhWydsb2NhbCddKSBpbiBpcGFkZHJlc3MuaXBfbmV0d29yaygnMTAu'
    'NzcuMC4wLzI0JyldCiAgICBpZiBsZW4oaXBzKSAhPSAxOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndmlydHVhbF9p'
    'cF9taXNzaW5nJykKICAgIHJldHVybiBpcHNbMF0KCgpkZWYgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcyk6CiAgICB2aXAgPSB2'
    'aXJ0dWFsX2lwKCkKICAgIGlmIG5vdCBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAg'
    'ICAgY29tbWFuZChbJ2lwJywnbGluaycsJ2FkZCcsRlVMTF9IT1NULCd0eXBlJywndmV0aCcsJ3BlZXInLCduYW1lJyxGVUxM'
    'X1BFRVJdKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfUEVFUiwnbmV0bnMnLE5TXSkKICAgIGNv'
    'bW1hbmQoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4xLzMwJywnZGV2JyxGVUxMX0hPU1RdKQogICAgY29t'
    'bWFuZChbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9IT1NULCdtdHUnLCcxMjgwJywndXAnXSkKICAgIGluc2lkZShbJ2lwJywn'
    'YWRkcicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjIvMzAnLCdkZXYnLEZVTExfUEVFUl0pCiAgICBpbnNpZGUoWydpcCcsJ2xp'
    'bmsnLCdzZXQnLEZVTExfUEVFUiwnbXR1JywnMTI4MCcsJ3VwJ10pCiAgICBpbnNpZGUoWydzeXNjdGwnLCctcXcnLCduZXQu'
    'aXB2NC5jb25mLmFsbC5mb3J3YXJkaW5nPTEnLCduZXQuaXB2NC5jb25mLmFsbC5ycF9maWx0ZXI9MCddKQogICAgIyBTdHJv'
    'bmdTd2FuJ3MgY2F0Y2gtYWxsIHJvdXRlIG11c3Qgbm90IGNhcHR1cmUgcmVwbGllcyB0byB0aGUgaG9zdC1mYWNpbmcgaW50'
    'ZXJmYWNlLgogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc5MCcsJ3RvJyxGVUxMX05FVCwnbG9v'
    'a3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLCc5MCcs'
    'J3RvJyxGVUxMX05FVCwnbG9va3VwJywnbWFpbiddKQogICAgZGVsZXRpb25zID0gJycKICAgIGZvciBmYW1pbHksdGFibGUg'
    'aW4gWygnaW5ldCcsJ2V2bl9mdWxsX2ZvcndhcmQnKSwoJ25ldGRldicsJ2V2bl9mdWxsX3dpcmUnKV06CiAgICAgICAgaWYg'
    'aW5zaWRlKFsnbmZ0JywnbGlzdCcsJ3RhYmxlJyxmYW1pbHksdGFibGVdLGNoZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6'
    'CiAgICAgICAgICAgIGRlbGV0aW9ucyArPSBmJ2RlbGV0ZSB0YWJsZSB7ZmFtaWx5fSB7dGFibGV9XG4nCiAgICBydWxlcyA9'
    'IGRlbGV0aW9ucyArIGYnJyd0YWJsZSBpbmV0IGV2bl9mdWxsX2ZvcndhcmQge3sKIGNoYWluIGZvcndhcmQge3sgdHlwZSBm'
    'aWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC01OyBwb2xpY3kgZHJvcDsKICBpaWZuYW1lICJ7RlVMTF9QRUVSfSIgb2lm'
    'bmFtZSAie1BFRVJ9IiBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgYWNjZXB0CiAgaWlmbmFtZSB7eyAie1BFRVJ9IiwgImxvIiB9'
    'fSBvaWZuYW1lICJ7RlVMTF9QRUVSfSIgaXAgZGFkZHIgMTcyLjI5LjI0Ny4xIGlwc2VjIGluIHJlcWlkIHtSRVFJRH0gY3Qg'
    'c3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKIH19CiBjaGFpbiBuYXQge3sgdHlwZSBuYXQgaG9vayBwb3N0cm91'
    'dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2FkZHIgMTcyLjI5LjI0Ny4xIG9pZm5hbWUgIntQ'
    'RUVSfSIgc25hdCBpcCB0byB7dmlwfQogfX0KfX0KdGFibGUgbmV0ZGV2IGV2bl9mdWxsX3dpcmUge3sKIGNoYWluIGVncmVz'
    'cyB7eyB0eXBlIGZpbHRlciBob29rIGVncmVzcyBkZXZpY2UgIntQRUVSfSIgcHJpb3JpdHkgMDsgcG9saWN5IGRyb3A7CiAg'
    'ZXRoZXIgdHlwZSBhcnAgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFj'
    'Y2VwdAogIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpcCBk'
    'YWRkciAxOTUuMjA5LjIxMS4xNjMgdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB0Y3AgZHBv'
    'cnQgODQ0MyBhY2NlcHQKIH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cnVsZXMpCiAg'
    'ICBpbnNpZGUoWyduZnQnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgIyBSZXBsYWNlIHRoZSBvcmlnaW5hbCBsYWIgZm9y'
    'd2FyZCBkcm9wOyBob3N0IGluZ3Jlc3MgcmVtYWlucyBjb25zdHJhaW5lZCBieSBmdWxsX2ZvcndhcmQuCiAgICBpbnNpZGUo'
    'WyduZnQnLCdmbHVzaCcsJ2NoYWluJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnXSkKICAgIGluc2lk'
    'ZShbJ25mdCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JywnZXZuX3N0YXJmaXZlX2d1YXJkJywnZm9yd2FyZCcsJ2lpZm5hbWUnLEZV'
    'TExfUEVFUiwnbWV0YScsJ25mcHJvdG8nLCdpcHY0JywnYWNjZXB0J10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxl'
    'JywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnLCdvaWZuYW1lJyxGVUxMX1BFRVIsJ2lwc2VjJywnaW4n'
    'LCdyZXFpZCcsc3RyKFJFUUlEKSwnY3QnLCdzdGF0ZScsJ2VzdGFibGlzaGVkLHJlbGF0ZWQnLCdhY2NlcHQnXSkKCgpfRUdS'
    'RVNTX1BST0JFUyA9ICgnaHR0cHM6Ly8xLjEuMS4xL2Nkbi1jZ2kvdHJhY2UnLCAnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJykK'
    'X2VncmVzc19wcmVmZXJyZWQgPSAwCgoKZGVmIHBhcnNlX2V4aXQoYm9keSwgdHJhY2UpOgogICAgdmFsdWVzID0gW2xpbmVb'
    'MzpdIGZvciBsaW5lIGluIGJvZHkuc3BsaXRsaW5lcygpIGlmIGxpbmUuc3RhcnRzd2l0aCgnaXA9JyldIGlmIHRyYWNlIGVs'
    'c2UgW2JvZHkuc3RyaXAoKV0KICAgIGlmIGxlbih2YWx1ZXMpICE9IDE6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToK'
    'ICAgICAgICByZXR1cm4gc3RyKGlwYWRkcmVzcy5JUHY0QWRkcmVzcyh2YWx1ZXNbMF0pKQogICAgZXhjZXB0IGlwYWRkcmVz'
    'cy5BZGRyZXNzVmFsdWVFcnJvcjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBlZ3Jlc3NfaGVhbHRoKCk6CiAgICAiIiJJ'
    'bmRlcGVuZGVudCBIVFRQUyBwcm92aWRlcnM7IGEgdmVyaWZpZWQgd3JvbmcgSVAgbXVzdCBuZXZlciBiZSBtYXNrZWQgYnkg'
    'ZmFsbGJhY2suIiIiCiAgICBnbG9iYWwgX2VncmVzc19wcmVmZXJyZWQKICAgIGZvciBpbmRleCBpbiAoX2VncmVzc19wcmVm'
    'ZXJyZWQsIDEtX2VncmVzc19wcmVmZXJyZWQpOgogICAgICAgIHVybCA9IF9FR1JFU1NfUFJPQkVTW2luZGV4XQogICAgICAg'
    'IHRyeToKICAgICAgICAgICAgcmVzdWx0ID0gaW5zaWRlKFsnY3VybCcsJy00JywnLS1ub3Byb3h5JywnKicsJy0tZmFpbCcs'
    'Jy0tc2lsZW50JywnLS1zaG93LWVycm9yJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnLS1jb25uZWN0LXRpbWVv'
    'dXQnLCczJywnLS1tYXgtdGltZScsJzUnLCctLW1heC1maWxlc2l6ZScsJzMyNzY4Jyx1cmxdLHRpbWVvdXQ9NyxjaGVjaz1G'
    'YWxzZSkKICAgICAgICBleGNlcHQgKE9TRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgICAgIGNv'
    'bnRpbnVlCiAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBv'
    'YnNlcnZlZCA9IHBhcnNlX2V4aXQocmVzdWx0LnN0ZG91dCwgaW5kZXggPT0gMCkKICAgICAgICBpZiBvYnNlcnZlZCBpcyBu'
    'b3QgTm9uZToKICAgICAgICAgICAgaWYgb2JzZXJ2ZWQgIT0gJzM4LjE4MC4xNjQuNjcnOgogICAgICAgICAgICAgICAgcmV0'
    'dXJuIEZhbHNlCiAgICAgICAgICAgIF9lZ3Jlc3NfcHJlZmVycmVkID0gaW5kZXgKICAgICAgICAgICAgcmV0dXJuIFRydWUK'
    'ICAgIHJldHVybiBGYWxzZQoKCmRlZiBwYXRoX2hlYWx0aHkoZGFlbW9uKToKICAgICMgVGhlIHByaXZhdGUgZGlhZ25vc3Rp'
    'YyBIVFRQIGNvbGxlY3RvciBpcyBub3QgcGFydCBvZiB0aGUgVlBOIGRhdGEgcGxhbmUuCiAgICAjIEl0cyBvdXRhZ2UvcmVz'
    'dGFydCBtdXN0IG5vdCBkaXNjYXJkIGEgd29ya2luZyByb3V0ZSdzIHRocmVlLWxvc3MgYnVkZ2V0LgogICAgcmV0dXJuIChk'
    'YWVtb24ucG9sbCgpIGlzIE5vbmUgYW5kIGluc3RhbGxlZCgpCiAgICAgICAgICAgIGFuZCAoVExTX1BST0NFU1MgaXMgTm9u'
    'ZSBvciBUTFNfUFJPQ0VTUy5wb2xsKCkgaXMgTm9uZSkgYW5kIGVncmVzc19oZWFsdGgoKSkKCgpkZWYgcmV0aXJlX3ByZXZp'
    'b3VzX2Nvbm5lY3Rpb25zKGFkZHJlc3Nlcyk6CiAgICAjIFRoZSBmaXJld2FsbCBhbHJlYWR5IGJsb2NrcyBvbGQgbm9uLWV4'
    'ZW1wdCBmbG93cy4gRG8gbm90IGtpbGwgYWxsIHNvY2tldHMKICAgICMgc2hhcmluZyBhIHBoeXNpY2FsIHNvdXJjZSBhZGRy'
    'ZXNzOiB0aGF0IGRlc3Ryb3lzIFNTSCwgTEFOIGFuZCBhcHAgZXhjbHVzaW9ucy4KICAgICMgT25seSB0aGlzIG1hbmFnZXIn'
    'cyBETlMgdHJhbnNsYXRpb25zIG5lZWQgZXhwbGljaXQgcmV0aXJlbWVudCAoaGFuZGxlZCBhYm92ZSkuCiAgICByZXR1cm4K'
    'CgpkZWYgc3lzdGVtX2Ruc19oZWFsdGgocmVzb2x2X2NvbmY9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToKICAgICMgZ2V0'
    'YWRkcmluZm8vY3VybCBtYXkgdXNlIG5zcy1yZXNvbHZlIG92ZXIgYSBVbml4IHNvY2tldCBhbmQgbWlzcyBhIGJyb2tlbgog'
    'ICAgIyBVRFAgc3R1YiB1c2VkIGJ5IG90aGVyIGFwcGxpY2F0aW9ucy4gRXhlcmNpc2UgcmVzb2x2LmNvbmYgaW5kZXBlbmRl'
    'bnRseS4KICAgIHNlcnZlcnMgPSBbbGluZS5zcGxpdCgpWzFdIGZvciBsaW5lIGluIHJlc29sdl9jb25mLnJlYWRfdGV4dCgp'
    'LnNwbGl0bGluZXMoKQogICAgICAgICAgICAgICBpZiBsaW5lLnNwbGl0KClbOjFdID09IFsnbmFtZXNlcnZlciddIGFuZCBs'
    'ZW4obGluZS5zcGxpdCgpKSA+PSAyXVs6M10KICAgIGZvciBzZXJ2ZXIgaW4gc2VydmVyczoKICAgICAgICB0cnk6CiAgICAg'
    'ICAgICAgIGZhbWlseSA9IHNvY2tldC5BRl9JTkVUNiBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhzZXJ2ZXIpLnZlcnNpb24g'
    'PT0gNiBlbHNlIHNvY2tldC5BRl9JTkVUCiAgICAgICAgICAgIHRyYW5zYWN0aW9uID0gc2VjcmV0cy50b2tlbl9ieXRlcygy'
    'KQogICAgICAgICAgICBxdWVyeSA9IHRyYW5zYWN0aW9uK2InXHgwMVx4MDBceDAwXHgwMVx4MDBceDAwXHgwMFx4MDBceDAw'
    'XHgwMCcKICAgICAgICAgICAgcXVlcnkgKz0gYidceDAzYXBpXHgwNWlwaWZ5XHgwM29yZ1x4MDBceDAwXHgwMVx4MDBceDAx'
    'JwogICAgICAgICAgICB3aXRoIHNvY2tldC5zb2NrZXQoZmFtaWx5LCBzb2NrZXQuU09DS19ER1JBTSkgYXMgcmVzb2x2ZXI6'
    'CiAgICAgICAgICAgICAgICByZXNvbHZlci5zZXR0aW1lb3V0KDIpCiAgICAgICAgICAgICAgICByZXNvbHZlci5jb25uZWN0'
    'KChzZXJ2ZXIsIDUzKSkKICAgICAgICAgICAgICAgIHJlc29sdmVyLnNlbmQocXVlcnkpCiAgICAgICAgICAgICAgICBhbnN3'
    'ZXIgPSByZXNvbHZlci5yZWN2KDQwOTYpCiAgICAgICAgICAgIGlmIChsZW4oYW5zd2VyKSA+PSAxMiBhbmQgYW5zd2VyWzoy'
    'XSA9PSB0cmFuc2FjdGlvbiBhbmQKICAgICAgICAgICAgICAgICAgICBhbnN3ZXJbMl0gJiAweDgwIGFuZCBhbnN3ZXJbM10g'
    'JiAxNSA9PSAwIGFuZAogICAgICAgICAgICAgICAgICAgIGludC5mcm9tX2J5dGVzKGFuc3dlcls2OjhdLCAnYmlnJykgPiAw'
    'KToKICAgICAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAg'
    'ICAgICAgICAgY29udGludWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBzdGFydF9uYW1lc3BhY2VfZG5zKCk6CiAgICAiIiJB'
    'IHByaXZhdGUgRE5TIGVuZHBvaW50IHJlYWNoYWJsZSBvbmx5IG92ZXIgdGhlIGhvc3QvbmFtZXNwYWNlIHZldGguIiIiCiAg'
    'ICBnbG9iYWwgRE5TX1BST0NFU1MKICAgIGlmIEROU19QUk9DRVNTIGlzIG5vdCBOb25lIGFuZCBETlNfUFJPQ0VTUy5wb2xs'
    'KCkgaXMgTm9uZTpyZXR1cm4KICAgIGNmZyA9IHsnbG9nJzp7J2xvZ2xldmVsJzond2FybmluZycsJ2FjY2Vzcyc6J25vbmUn'
    'fSwKICAgICAgJ2luYm91bmRzJzpbeyd0YWcnOidkbnMtaW4nLCdsaXN0ZW4nOicxNzIuMjkuMjQ3LjInLCdwb3J0Jzo1Mywn'
    'cHJvdG9jb2wnOidkb2tvZGVtby1kb29yJywKICAgICAgICAgICAgICAgICAgICdzZXR0aW5ncyc6eydhZGRyZXNzJzonMS4x'
    'LjEuMScsJ3BvcnQnOjUzLCduZXR3b3JrJzondGNwLHVkcCd9fV0sCiAgICAgICdkbnMnOnsnc2VydmVycyc6WycxLjEuMS4x'
    'JywndGNwOi8vOS45LjkuOScsJ2h0dHBzOi8vMS4wLjAuMS9kbnMtcXVlcnknXSwKICAgICAgICAgICAgICdxdWVyeVN0cmF0'
    'ZWd5JzonVXNlSVB2NCcsJ3RhZyc6J2Rucy1lbmdpbmUnLCdlbmFibGVQYXJhbGxlbFF1ZXJ5JzpUcnVlfSwKICAgICAgJ291'
    'dGJvdW5kcyc6W3sndGFnJzond2lyZScsJ3Byb3RvY29sJzonZnJlZWRvbSd9LAogICAgICAgICAgICAgICAgICAgeyd0YWcn'
    'OidkbnMnLCdwcm90b2NvbCc6J2RucycsJ3NldHRpbmdzJzp7J3J1bGVzJzpbeydxVHlwZSc6JzEsMjgnLCdhY3Rpb24nOido'
    'aWphY2snfSx7J2FjdGlvbic6J2RpcmVjdCd9XX19XSwKICAgICAgJ3JvdXRpbmcnOnsncnVsZXMnOlt7J3R5cGUnOidmaWVs'
    'ZCcsJ2luYm91bmRUYWcnOlsnZG5zLWluJ10sJ291dGJvdW5kVGFnJzonZG5zJ30sCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUnXSwnb3V0Ym91bmRUYWcnOid3aXJlJ31dfX0K'
    'ICAgIHBhdGg9Uk9PVC8nbmFtZXNwYWNlLWRucy5qc29uJzt3cml0ZShwYXRoLGpzb24uZHVtcHMoY2ZnKSkKICAgIGJpbmFy'
    'eT0nL29wdC92cG4tbWFuYWdlci9iaW4veHJheScKICAgIGluc2lkZShbYmluYXJ5LCdydW4nLCctdGVzdCcsJy1jb25maWcn'
    'LHBhdGhdKQogICAgRE5TX1BST0NFU1M9c3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywnbmV0bnMnLCdleGVjJyxOUyxiaW5hcnks'
    'J3J1bicsJy1jb25maWcnLHN0cihwYXRoKV0sCiAgICAgICAgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLHN0ZG91dD1zdWJw'
    'cm9jZXNzLkRFVk5VTEwsc3RkZXJyPXN1YnByb2Nlc3MuREVWTlVMTCkKICAgIGZvciBfIGluIHJhbmdlKDMwKToKICAgICAg'
    'ICBpZiBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6cmFpc2UgUnVudGltZUVycm9yKCdwcml2YXRlX2Ruc19zdG9w'
    'cGVkJykKICAgICAgICBpZiAnMTcyLjI5LjI0Ny4yOjUzJyBpbiBpbnNpZGUoWydzcycsJy1sbnUnXSxjaGVjaz1GYWxzZSku'
    'c3Rkb3V0OgogICAgICAgICAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5jb25mJywnbmFtZXNlcnZl'
    'ciAxNzIuMjkuMjQ3LjJcbm9wdGlvbnMgdGltZW91dDozIGF0dGVtcHRzOjJcbicpCiAgICAgICAgICAgIHJldHVybgogICAg'
    'ICAgIHRpbWUuc2xlZXAoLjEpCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3ByaXZhdGVfZG5zX25vdF9yZWFkeScpCgoKZGVm'
    'IHVzZV9yZXNvbHZlcl9maWxlKHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToKICAgIGRhdGE9anNvbi5sb2Fkcyhm'
    'dWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICB0YXJnZXQ9Uk9PVC8ncmVzb2x2LXZwbi5jb25mJwogICAgaWYgJ3Jlc29s'
    'dmVyX29yaWdpbmFsJyBub3QgaW4gZGF0YToKICAgICAgICBkYXRhWydyZXNvbHZlcl9vcmlnaW5hbCddPXsnbGluayc6b3Mu'
    'cmVhZGxpbmsocGF0aCkgaWYgcGF0aC5pc19zeW1saW5rKCkgZWxzZSBOb25lLAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICd0ZXh0JzpwYXRoLnJlYWRfdGV4dCgpIGlmIHBhdGguZXhpc3RzKCkgZWxzZSAnJywKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAnZXhpc3RlZCc6cGF0aC5leGlzdHMoKSBvciBwYXRoLmlzX3N5bWxpbmsoKX0KICAg'
    'IGRhdGFbJ2Ruc19mYWxsYmFjayddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAg'
    'd3JpdGUodGFyZ2V0LCduYW1lc2VydmVyIDE3Mi4yOS4yNDcuMlxub3B0aW9ucyB0aW1lb3V0OjMgYXR0ZW1wdHM6MlxuJykK'
    'ICAgIHRhcmdldC5jaG1vZCgwbzY0NCkKICAgICMgVGhlIHBhcmVudCBtdXN0IGJlIHRyYXZlcnNhYmxlIGJ5IGFwcGxpY2F0'
    'aW9ucy4gU2VjcmV0cyByZW1haW4gcm9vdC1vbmx5LgogICAgIyBQdXQgb25seSB0aGlzIHB1YmxpYyByZXNvbHZlciBmaWxl'
    'IG91dHNpZGUgdGhlIGNyZWRlbnRpYWwgZGlyZWN0b3J5LgogICAgcHVibGljPVBhdGgoJy9ydW4vZXZnZW5pdW0tcmVzb2x2'
    'LmNvbmYnKQogICAgcHVibGljLnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUsZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKHB1'
    'YmxpYyx0YXJnZXQucmVhZF90ZXh0KCkpO3B1YmxpYy5jaG1vZCgwbzY0NCkKICAgIHRlbXBvcmFyeT1wYXRoLndpdGhfbmFt'
    'ZSgnLmV2Z2VuaXVtLXJlc29sdi5uZXcnKQogICAgdGVtcG9yYXJ5LnVubGluayhtaXNzaW5nX29rPVRydWUpO3RlbXBvcmFy'
    'eS5zeW1saW5rX3RvKHB1YmxpYykKICAgIG9zLnJlcGxhY2UodGVtcG9yYXJ5LHBhdGgpCgoKZGVmIHJlc3RvcmVfcmVzb2x2'
    'ZXJfZmlsZShkYXRhLHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToKICAgIHNhdmVkPWRhdGEuZ2V0KCdyZXNvbHZl'
    'cl9vcmlnaW5hbCcpCiAgICBpZiBzYXZlZCBhbmQgcGF0aC5pc19zeW1saW5rKCkgYW5kIG9zLnJlYWRsaW5rKHBhdGgpPT0n'
    'L3J1bi9ldmdlbml1bS1yZXNvbHYuY29uZic6CiAgICAgICAgdGVtcG9yYXJ5PXBhdGgud2l0aF9uYW1lKCcuZXZnZW5pdW0t'
    'cmVzb2x2LnJlc3RvcmUnKQogICAgICAgIHRlbXBvcmFyeS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgICAgIGlmIHNh'
    'dmVkWydsaW5rJ10gaXMgbm90IE5vbmU6dGVtcG9yYXJ5LnN5bWxpbmtfdG8oc2F2ZWRbJ2xpbmsnXSkKICAgICAgICBlbHNl'
    'OnRlbXBvcmFyeS53cml0ZV90ZXh0KHNhdmVkWyd0ZXh0J10pO3RlbXBvcmFyeS5jaG1vZCgwbzY0NCkKICAgICAgICBpZiBz'
    'YXZlZC5nZXQoJ2V4aXN0ZWQnLFRydWUpOm9zLnJlcGxhY2UodGVtcG9yYXJ5LHBhdGgpCiAgICAgICAgZWxzZTpwYXRoLnVu'
    'bGluaygpO3RlbXBvcmFyeS51bmxpbmsoKQogICAgZWxpZiBub3Qgc2F2ZWQgYW5kICdkbnNfYmFja3VwJyBpbiBkYXRhOgog'
    'ICAgICAgIHBhdGgud3JpdGVfdGV4dChkYXRhWydkbnNfYmFja3VwJ10pCgoKZGVmIHJlY292ZXJfc3lzdGVtX2RucygpOgog'
    'ICAgZm9yIF8gaW4gcmFuZ2UoMik6CiAgICAgICAgaWYgc3lzdGVtX2Ruc19oZWFsdGgoKTpyZXR1cm4gVHJ1ZQogICAgICAg'
    'IGlmIFNUT1A6cmV0dXJuIEZhbHNlCiAgICAgICAgdGltZS5zbGVlcCguMykKICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhp'
    'c3RzKCk6cmV0dXJuIEZhbHNlCiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmUgYW5kIHBvbGljeS5pbmNsdXNpdmUocG9saWN5'
    'LmxvYWQoKSk6cmV0dXJuIEZhbHNlCiAgICAjIFN3aXRjaCBvbmx5IHRoZSByZXNvbHZlciBmaWxlIHdlIG93bjsgbmV2ZXIg'
    'c3RvcCBhbm90aGVyIFZQTiBvciByZXNvbHZlci4KICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9C10YDQtdC60LvRjtGH0LDR'
    'jiDQvdC10LjRgdC/0YDQsNCy0L3Ri9C5INGB0LjRgdGC0LXQvNC90YvQuSBETlMg0L3QsCDQt9Cw0YnQuNGJ0ZHQvdC90YvQ'
    'uSDRgNC10LfQtdGA0LIuJyw5MCxhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0nc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgdXNl'
    'X3Jlc29sdmVyX2ZpbGUoKQogICAgcmV0dXJuIHN5c3RlbV9kbnNfaGVhbHRoKCkKCgpkZWYgcGVyc2lzdF9ndWFyZChydWxl'
    'cyk6CiAgICAjIEd1YXJkIHBlcnNpc3RlbmNlIHByZWNlZGVzIHN3aXRjaGluZy4gQ2xlYW51cCBhZnRlciBhIGNyYXNoIG5l'
    'dmVyIG9wZW5zIHRoZSBJbnRlcm5ldC4KICAgIGd1YXJkX3VuaXQgPSAnJydbVW5pdF0KRGVzY3JpcHRpb249RXZnZW5pdW0g'
    'ZnVsbC1kZXZpY2Uga2lsbCBzd2l0Y2gKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpBZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVm'
    'b3JlPW5ldHdvcmstcHJlLnRhcmdldApbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0'
    'YXJ0PS91c3Ivc2Jpbi9uZnQgLWYgL2V0Yy92cG4tbWFuYWdlci9zdGFyZml2ZS10dW5uZWwvZnVsbC1ndWFyZC5uZnQKW0lu'
    'c3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CicnJy5yZXBsYWNlKCcvdXNyL3NiaW4vbmZ0Jywgc2h1dGlsLndo'
    'aWNoKCduZnQnKSkKICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxlcykKICAgIHdyaXRlKFBhdGgoJy9ldGMv'
    'c3lzdGVtZC9zeXN0ZW0vZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJyksZ3VhcmRfdW5pdCkKICAgIGNv'
    'bW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZW5hYmxlJywn'
    'ZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJ10pCgoKZGVmIGNvbmZpZ3VyZV9zeXN0ZW1fZG5zKCk6CiAg'
    'ICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOnJldHVybgogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5y'
    'ZWFkX3RleHQoKSkKICAgIGlmIHBvbGljeSBpcyBub3QgTm9uZSBhbmQgcG9saWN5LmluY2x1c2l2ZShwb2xpY3kubG9hZCgp'
    'KToKICAgICAgICByZXN0b3JlX3Jlc29sdmVyX2ZpbGUoZGF0YSkKICAgICAgICBpZiBkYXRhLmdldCgnZG5zX21vZGUnKT09'
    'J3Jlc29sdmVkX2xpbmsnOgogICAgICAgICAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ3JldmVydCcsRlVMTF9IT1NUXSxj'
    'aGVjaz1GYWxzZSkKICAgICAgICBkYXRhWydkbnNfbW9kZSddPSdkaXJlY3QnCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgp'
    'LGpzb24uZHVtcHMoZGF0YSkpCiAgICAgICAgcmV0dXJuCiAgICBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBhbmQg'
    'Y29tbWFuZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsJy0tcXVpZXQnLCdzeXN0ZW1kLXJlc29sdmVkJ10sY2hlY2s9RmFs'
    'c2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICBkYXRhWydkbnNfbW9kZSddPSdyZXNvbHZlZF9saW5rJwogICAgICAgIHdy'
    'aXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG5zJyxG'
    'VUxMX0hPU1QsJzE3Mi4yOS4yNDcuMiddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG9tYWluJyxGVUxMX0hP'
    'U1QsJ34uJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkZWZhdWx0LXJvdXRlJyxGVUxMX0hPU1QsJ3llcydd'
    'KQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZmx1c2gtY2FjaGVzJ10sY2hlY2s9RmFsc2UpCiAgICBlbHNlOgog'
    'ICAgICAgIHVzZV9yZXNvbHZlcl9maWxlKCkKCgpkZWYgYWN0aXZhdGVfZnVsbChhZGRyZXNzKToKICAgIG9sZF9hZGRyZXNz'
    'ZXMgPSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywn'
    'c2hvdycsJ3Njb3BlJywnZ2xvYmFsJ10pLnN0ZG91dCkKICAgICAgICAgICAgICAgICAgICAgaWYgbGluay5nZXQoJ2lmbmFt'
    'ZScpIG5vdCBpbiAoSE9TVCxGVUxMX0hPU1QpCiAgICAgICAgICAgICAgICAgICAgIGZvciBhIGluIGxpbmsuZ2V0KCdhZGRy'
    'X2luZm8nLFtdKSBpZiBhLmdldCgnc2NvcGUnKSA9PSAnZ2xvYmFsJ10KICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3Rz'
    'KCk6CiAgICAgICAgaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1QpLmV4aXN0cygpOgogICAgICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfaW50ZXJmYWNlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywn'
    'cm91dGUnLCdzaG93JywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAg'
    'ICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFuZChbJ2lwJywn'
    'cm91dGUnLCdzaG93JywndGFibGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAg'
    'ICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignYWRtaW5fdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBhbnkoci5nZXQoJ3By'
    'aW9yaXR5JykgaW4gKDc5LDgwKSBmb3IgciBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdydWxlJ10p'
    'LnN0ZG91dCkpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfcnVsZV9jb2xsaXNpb24nKQogICAgICAg'
    'IHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKHsnYWN0aXZlJzpGYWxzZX0pKQogICAgZnVsbF9uYW1lc3BhY2UoYWRk'
    'cmVzcykKICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQogICAgIyBWYWxpZGF0ZSB0aGUgZWdyZXNzIGZpbHRlciBiZWZvcmUg'
    'aW50ZXJydXB0aW5nIHRoZSBwcmV2aW91cyBWUE4uCiAgICBpZiBub3QgZWdyZXNzX2hlYWx0aCgpOgogICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcignZXN0b25pYV9lZ3Jlc3NfZmFpbGVkJykKICAgIHJ1bGVzID0gZnVsbF9maXJld2FsbCgpCiAgICAj'
    'IFJlcGFpciBtYXkgaW5oZXJpdCBhIGd1YXJkIGZyb20gYW4gb2xkZXIgdmVyc2lvbi4gUmVwbGFjZSBvdXIgdGFibGUgaW4K'
    'ICAgICMgb25lIG5mdCB0cmFuc2FjdGlvbiwgc28gZml4ZXMgYXBwbHkgd2l0aG91dCBvcGVuaW5nIGFuIHVuZ3VhcmRlZCB3'
    'aW5kb3cuCiAgICByZXBsYWNlbWVudCA9ICgnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicgaWYgZnVsbF9n'
    'dWFyZF9hY3RpdmUoKSBlbHNlICcnKStydWxlcwogICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBs'
    'YWNlbWVudCkKICAgIGNvbW1hbmQoWyduZnQnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgcGVyc2lzdF9ndWFy'
    'ZChydWxlcykKICAgICMgVGhpcyBjb21tYW5kIHN0b3BzIG9ubHkgdGhpcyBtYW5hZ2VyJ3MgcHJldmlvdXMgWHJheSBtb2Rl'
    'IGFuZCByZW1vdmVzIGl0cyBndWFyZC4KICAgIGNvbW1hbmQoWycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwt'
    'c3RhcmZpdmUtcGF1c2UtbWFpbiddLHRpbWVvdXQ9NDApCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCd1'
    'bnJlYWNoYWJsZScsJ2RlZmF1bHQnLCdtZXRyaWMnLCczMjc2MCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgICMgSW5jbHVz'
    'aW9uIG1vZGUgbmV2ZXIgaW5zdGFsbHMgYW4gaW50ZXJpbSBmdWxsLWRldmljZSBWUE4gcm91dGUsIGV2ZW4KICAgICMgZHVy'
    'aW5nIHJlY29ubmVjdC4gVGhlIGNsYXNzaWZpZXIgcmV0YWlucyBpdHMgVFVOIGRlZmF1bHQgb3IgZmFpbHMgY2xvc2VkLgog'
    'ICAgaWYgcG9saWN5IGlzIE5vbmUgb3Igbm90IHBvbGljeS5pbmNsdXNpdmUocG9saWN5LmxvYWQoKSk6CiAgICAgICAgY29t'
    'bWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ3ZpYScsJzE3Mi4yOS4yNDcuMicsJ2RldicsRlVMTF9I'
    'T1NULCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdw'
    'cmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBydWxlIGluIChbJ3ByaW9y'
    'aXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sCiAgICAgICAgICAgICAgICAgWydwcmlvcml0'
    'eScsJzc5JywnaWlmJyxGVUxMX0hPU1QsJ2xvb2t1cCcsJ21haW4nXSk6CiAgICAgICAgY29tbWFuZChbJ2lwJywncnVsZScs'
    'J2RlbCcsKnJ1bGVdLGNoZWNrPUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCpydWxlXSkKICAg'
    'IGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSkKICAgIGNv'
    'bmZpZ3VyZV9zeXN0ZW1fZG5zKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIHJldGly'
    'ZV9wcmV2aW91c19jb25uZWN0aW9ucyhvbGRfYWRkcmVzc2VzKQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAg'
    'IHBvbGljeS5hcHBseSgpCiAgICBpZiBub3QgcmVjb3Zlcl9zeXN0ZW1fZG5zKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVy'
    'cm9yKCdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICAjIFRlc3QgdGhlIGFjdHVhbCBob3N0IHBhdGggYXMgd2VsbCBhcyBuYW1l'
    'c3BhY2UgcHJvYmVzIGJlZm9yZSBhbm5vdW5jaW5nIGNvbm5lY3RlZC4KICAgIGNoZWNrID0gY29tbWFuZChbJ2N1cmwnLCct'
    'NCcsJy0tbm9wcm94eScsJycgaWYgcG9saWN5IGlzIG5vdCBOb25lIGVsc2UgJyonLCctLWZhaWwnLCctLXNpbGVudCcsJy0t'
    'bWF4LXRpbWUnLCcxMCcsKihbJy0tc29ja3M1LWhvc3RuYW1lJywnMTI3LjAuMC4xOjE4NTU0J10gaWYgcG9saWN5IGlzIG5v'
    'dCBOb25lIGVsc2UgW10pLCdodHRwczovL2FwaS5pcGlmeS5vcmcnXSx0aW1lb3V0PTEyKQogICAgaWYgY2hlY2suc3Rkb3V0'
    'LnN0cmlwKCkgIT0gJzM4LjE4MC4xNjQuNjcnOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaG9zdF9lZ3Jlc3NfZmFp'
    'bGVkJykKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBkYXRhWydhY3RpdmUnXT1U'
    'cnVlCiAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyhkYXRhKSkKCgpkZWYgY2xlYW51cF9mdWxsKHJlbGVhc2U9'
    'RmFsc2UpOgogICAgZ2xvYmFsIEROU19QUk9DRVNTCiAgICBpZiBETlNfUFJPQ0VTUyBpcyBub3QgTm9uZSBhbmQgRE5TX1BS'
    'T0NFU1MucG9sbCgpIGlzIE5vbmU6CiAgICAgICAgRE5TX1BST0NFU1MudGVybWluYXRlKCkKICAgICAgICB0cnk6RE5TX1BS'
    'T0NFU1Mud2FpdCh0aW1lb3V0PTMpCiAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6RE5TX1BST0NF'
    'U1Mua2lsbCgpO0ROU19QUk9DRVNTLndhaXQoKQogICAgRE5TX1BST0NFU1M9Tm9uZQogICAga2VlcF9kaXJlY3QgPSBub3Qg'
    'cmVsZWFzZSBhbmQgcG9saWN5IGlzIG5vdCBOb25lIGFuZCBwb2xpY3kuaW5jbHVzaXZlKHBvbGljeS5sb2FkKCkpCiAgICBp'
    'ZiBwb2xpY3kgaXMgbm90IE5vbmUgYW5kIG5vdCBrZWVwX2RpcmVjdDoKICAgICAgICBwb2xpY3kuc3RvcChyZWxlYXNlPXJl'
    'bGVhc2UpCiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAgIHJldHVybgogICAgZGF0YT1qc29uLmxv'
    'YWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkKICAgIGlmIG5vdCBrZWVwX2RpcmVjdDpjb21tYW5kKFsnaXAnLCdyb3V0'
    'ZScsJ2RlbCcsJ2RlZmF1bHQnLCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNv'
    'bW1hbmQoWydpcCcsJ2xpbmsnLCdkZWwnLEZVTExfSE9TVF0sY2hlY2s9RmFsc2UpCiAgICAjIE9uIGZhaWx1cmU6IHJldGFp'
    'biByb3V0aW5nLCBETlMgYW5kIHRoZSBwZXJzaXN0ZW50IGd1YXJkIHVudGlsIGV4cGxpY2l0IGRpc2Nvbm5lY3QuCiAgICBp'
    'ZiBub3QgcmVsZWFzZToKICAgICAgICByZXR1cm4KICAgIHJlc3RvcmVfcmVzb2x2ZXJfZmlsZShkYXRhKQogICAgY29tbWFu'
    'ZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQog'
    'ICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAn'
    'LCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ2lp'
    'ZicsRlVMTF9IT1NULCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2Zs'
    'dXNoJywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZm9yIHNlcnZlciBpbiAoJzE5Mi4xNjguMC4xNjMn'
    'LCAnMzguMTgwLjE2NC42NycpOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5Jywn'
    'dG8nLHNlcnZlciwnaXBwcm90bycsJ3RjcCcsJ2Rwb3J0JywnMjInLCdsb29rdXAnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxz'
    'ZSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkaXNhYmxlJywnLS1ub3cnLCdldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1'
    'YXJkLnNlcnZpY2UnXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZV'
    'TExfR1VBUkRdLGNoZWNrPUZhbHNlKQogICAgY2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhw'
    'cmV2aW91c192cG49VHJ1ZSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsQURNSU5fVEFCTEVd'
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
    'anNvbi5kdW1wcyhkYXRhLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQogICAgaWYgc3VwcG9ydF9hcGkgaXMgbm90IE5vbmU6CiAg'
    'ICAgICAgdHJ5OnN1cHBvcnRfYXBpLnJlY29yZChST09ULHdyaXRlLGRhdGEpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZh'
    'bHVlRXJyb3IsVHlwZUVycm9yKTpwYXNzCgoKZGVmIHNlbGVjdGVkX3JvdXRlKCk6CiAgICB0cnk6dmFsdWU9anNvbi5sb2Fk'
    'cygoUk9PVC8nc2VsZWN0aW9uLmpzb24nKS5yZWFkX3RleHQoKSkuZ2V0KCdyb3V0ZScsJ2F1dG8nKQogICAgZXhjZXB0IChP'
    'U0Vycm9yLFZhbHVlRXJyb3IsQXR0cmlidXRlRXJyb3IpOnZhbHVlPSdhdXRvJwogICAgcmV0dXJuIHZhbHVlIGlmIHZhbHVl'
    'IGluIHsnYXV0bycsKihjWydpZCddIGZvciBjIGluIENBTkRJREFURVMpfSBlbHNlICdhdXRvJwoKCmRlZiBzZWxlY3Rfcm91'
    'dGUodmFsdWUpOgogICAgaWYgdmFsdWUgbm90IGluIHsnYXV0bycsKihjWydpZCddIGZvciBjIGluIENBTkRJREFURVMpfTpy'
    'YWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXRgdGC0L3Ri9C5INC80LDRgNGI0YDRg9GCLicpCiAgICB3cml0ZShST09U'
    'LydzZWxlY3Rpb24uanNvbicsanNvbi5kdW1wcyh7J3JvdXRlJzp2YWx1ZX0pKQoKCmRlZiByb3V0ZV9jaG9pY2VzKCk6CiAg'
    'ICByYW5raW5nPXJhbmtfYXBpLlJhbmtpbmcoUk9PVC8ncmFua2luZy5qc29uJyxbY1snaWQnXSBmb3IgYyBpbiBDQU5ESURB'
    'VEVTXSkgaWYgcmFua19hcGkgZWxzZSBOb25lCiAgICBvcmRlcj1yYW5raW5nLmNhbmRpZGF0ZXMoKSBpZiByYW5raW5nIGFu'
    'ZCByYW5raW5nLmxvYWQoKSBlbHNlIFtdCiAgICByZXR1cm4geydzZWxlY3RlZCc6c2VsZWN0ZWRfcm91dGUoKSwnY2hvaWNl'
    'cyc6W3snaWQnOmNbJ2lkJ10sJ2xhYmVsJzpjWydsYWJlbCddfSBmb3IgYyBpbiBDQU5ESURBVEVTXSwKICAgICAgICAgICAg'
    'J29yZGVyJzpvcmRlciwnZW50cmllcyc6cmFua2luZy5kYXRhWydlbnRyaWVzJ10gaWYgb3JkZXIgZWxzZSB7fX0KCgpkZWYg'
    'c3RhdHVzKCk6CiAgICBkYXRhID0gc2F2ZWQoKQogICAgcnVubmluZyA9IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0'
    'aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MikucmV0dXJuY29kZSA9PSAwCiAgICBpZiBk'
    'YXRhLmdldCgncGhhc2UnKSA9PSAnY29ubmVjdGVkJyBhbmQgKG5vdCBydW5uaW5nIG9yIHRpbWUubW9ub3RvbmljKCktZGF0'
    'YS5nZXQoJ2hlYXJ0YmVhdCcsIDApID4gOTApOgogICAgICAgIGRhdGEudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsIG1l'
    'c3NhZ2U9J9Ch0L7QtdC00LjQvdC10L3QuNC1INC+0YHRgtCw0L3QvtCy0LjQu9C+0YHRjC4g0J/RgNC+0LLQtdGA0YzRgtC1'
    'INGB0L7RgdGC0L7Rj9C90LjQtSDQt9Cw0YnQuNGC0Ysg0Lgg0L3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsu'
    'JywgYWN0aXZlPUZhbHNlKQogICAgcHVibGljID0ge2tleTogZGF0YVtrZXldIGZvciBrZXkgaW4gKCdwaGFzZScsICdtZXNz'
    'YWdlJywgJ3Byb2dyZXNzJywgJ2FjdGl2ZScsICd1cGRhdGVkJywgJ21ldHJpY3MnLAogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgJ3Njb3BlJywgJ3NpbmNlJywgJ3JldHJ5JywgJ2Vycm9yX2NvZGUnLCAncGF0aCcpIGlmIGtl'
    'eSBpbiBkYXRhfQogICAgdG9rZW5faW5mbyA9IHRva2VuX3N0YXR1cygpCiAgICByZXR1cm4geydwaGFzZSc6ICdvZmYnLCAn'
    'bWVzc2FnZSc6ICgn0KLQvtC60LXQvSDRgdC+0YXRgNCw0L3RkdC9LiDQndCw0LbQvNC40YLQtSDCq9Cf0L7QtNC60LvRjtGH'
    '0LjRgtGMwrsuJyBpZiB0b2tlbl9pbmZvWydoYXNfdG9rZW4nXSBlbHNlICfQktCy0LXQtNC40YLQtSDQuCDQv9C+0LTRgtCy'
    '0LXRgNC00LjRgtC1INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAuJyksCiAgICAgICAgICAgICdwcm9ncmVzcyc6IDAsICdh'
    'Y3RpdmUnOiBGYWxzZSwgKipwdWJsaWMsICdydW5uaW5nJzogcnVubmluZywgJ3BhbmljJzpwYW5pY19lbmFibGVkKCksCiAg'
    'ICAgICAgICAgICoqdG9rZW5faW5mbywgKipkZXZpY2Vfc3RhdHVzKCksICdyb3V0ZXMnOnJvdXRlX2Nob2ljZXMoKSwgJ2lz'
    'b2xhdGVkJzogRmFsc2UsICdmdWxsX2RldmljZSc6IHBvbGljeSBpcyBOb25lIG9yIG5vdCBwb2xpY3kuaW5jbHVzaXZlKHBv'
    'bGljeS5sb2FkKCkpLCAnZ3VhcmQnOiBmdWxsX2d1YXJkX2FjdGl2ZSgpLCAncHJvdG9jb2wnOiAnSUtFdjIg4oaSINCt0YHR'
    'gtC+0L3QuNGPJ30KCgpAY29udGV4dGxpYi5jb250ZXh0bWFuYWdlcgpkZWYgbmFtZXNwYWNlKCk6CiAgICBiZWZvcmUgPSBv'
    'cy5vcGVuKCcvcHJvYy9zZWxmL25zL25ldCcsIG9zLk9fUkRPTkxZKQogICAgdGFyZ2V0ID0gb3Mub3BlbignL3J1bi9uZXRu'
    'cy8nK05TLCBvcy5PX1JET05MWSkKICAgIHRyeToKICAgICAgICBvcy5zZXRucyh0YXJnZXQsIG9zLkNMT05FX05FV05FVCkK'
    'ICAgICAgICB5aWVsZAogICAgZmluYWxseToKICAgICAgICBvcy5zZXRucyhiZWZvcmUsIG9zLkNMT05FX05FV05FVCkKICAg'
    'ICAgICBvcy5jbG9zZSh0YXJnZXQpCiAgICAgICAgb3MuY2xvc2UoYmVmb3JlKQoKCmRlZiBwaHlzaWNhbF9yb3V0ZSgpOgog'
    'ICAgcm91dGVzID0ganNvbi5sb2Fkcyhjb21tYW5kKFsnaXAnLCAnLWonLCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJs'
    'ZScsICdtYWluJywgJ2RlZmF1bHQnXSkuc3Rkb3V0KQogICAgY2FuZGlkYXRlcyA9IFtyIGZvciByIGluIHJvdXRlcyBpZiBy'
    'LmdldCgnZ2F0ZXdheScpIGFuZCByLmdldCgnZGV2JykgYW5kCiAgICAgICAgICAgICAgICAgIG5vdCByWydkZXYnXS5zdGFy'
    'dHN3aXRoKCgndHVuJywgJ3hyYXknLCAnd2cnLCAnZXZuLScpKV0KICAgIGlmIG5vdCBjYW5kaWRhdGVzOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcignbm9fcGh5c2ljYWxfcm91dGUnKQogICAgcm91dGUgPSBtaW4oY2FuZGlkYXRlcywga2V5PWxh'
    'bWJkYSByOiByLmdldCgnbWV0cmljJywgMCkpCiAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInW0EtWmEtejAtOV8uOi1dezEs'
    'MTV9Jywgcm91dGVbJ2RldiddKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaW50ZXJmYWNlJykKICAg'
    'IGlwYWRkcmVzcy5JUHY0QWRkcmVzcyhyb3V0ZVsnZ2F0ZXdheSddKQogICAgcmV0dXJuIHJvdXRlCgoKZGVmIGhvc3RfcnVs'
    'ZXMoaWZhY2UsIHByZXZpb3VzX2ZvcndhcmQ9VHJ1ZSk6CiAgICAjIFNjb3BlIGV2ZXJ5IG5ldyBmb3J3YXJkaW5nL05BVCBy'
    'dWxlIHRvIG91ciBvbmUgaW50ZXJmYWNlIGFuZCB0aGUgY29uZmlndXJlZCBpbmdyZXNzIGFkZHJlc3MuCiAgICBwcmVzZXJ2'
    'ZV9kaXNhYmxlZCA9ICcnIGlmIHByZXZpb3VzX2ZvcndhcmQgZWxzZSAnJycgIGlpZm5hbWUgIndheWRyb2lkMCIgbWV0YSBu'
    'ZnByb3RvIGlwdjQgYWNjZXB0CiAgb2lmbmFtZSAid2F5ZHJvaWQwIiBtZXRhIG5mcHJvdG8gaXB2NCBjdCBzdGF0ZSBlc3Rh'
    'Ymxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGRyb3AnJycKICAgIHJldHVybiBmJycndGFibGUg'
    'aW5ldCB7TkZUfSB7ewogY2hhaW4gZm9yd2FyZCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtMjA7'
    'IHBvbGljeSBhY2NlcHQ7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB1ZHAgZHBvcnQge0lL'
    'RV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQu'
    'NjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4'
    'LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNh'
    'ZGRyIHtDTElFTlR9IGlwIGRhZGRyIDE5NS4yMDkuMjExLjE2MyB0Y3AgZHBvcnQgMjQ1NzkgYWNjZXB0CiAgaWlmbmFtZSAi'
    'e0hPU1R9IiBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0i'
    'IGRyb3AKICBvaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHt7IHtTRVJWRVJ9LCAzOC4xODAuMTY0LjY3IH19IGN0IHN0YXRl'
    'IGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBkcm9wCntwcmVzZXJ2ZV9kaXNhYmxlZH0K'
    'IH19CiBjaGFpbiBuYXQge3sKICB0eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFj'
    'Y2VwdDsKICBpcCBzYWRkciB7Q0xJRU5UfSBvaWZuYW1lICJ7aWZhY2V9IiBtYXNxdWVyYWRlCiB9fQp9fScnJwoKCmRlZiBz'
    'ZXR1cF9uZXR3b3JrKCk6CiAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAgICMgUmVmdXNlIG5hbWUvYWRkcmVzcyBj'
    'b2xsaXNpb25zIHJhdGhlciB0aGFuIHJlcHVycG9zaW5nIGFub3RoZXIgYXBwbGljYXRpb24ncyByZXNvdXJjZXMuCiAgICBp'
    'ZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIG9yIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrSE9TVCkuZXhpc3Rz'
    'KCkgb3IgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykuZXhpc3RzKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0ZXN0'
    'X25hbWVzcGFjZV9leGlzdHMnKQogICAgaWYgY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUn'
    'LCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign'
    'dGVzdF90YWJsZV9pbl91c2UnKQogICAgaWYgYW55KE5FVFdPUksgaW4gbGluZSBmb3IgbGluZSBpbiBjb21tYW5kKFsnaXAn'
    'LCAnLTQnLCAncm91dGUnLCAnc2hvdycsICd0YWJsZScsICdhbGwnXSkuc3Rkb3V0LnNwbGl0bGluZXMoKSk6CiAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCd0ZXN0X25ldHdvcmtfaW5fdXNlJykKICAgIG9sZF9mb3J3YXJkID0gUGF0aCgnL3Byb2Mv'
    'c3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICAjIFJlY29yZCBvd25lcnNoaXAgYmVm'
    'b3JlIGNyZWF0aW5nIGFueXRoaW5nOiBjbGVhbnVwIGlzIHZhbGlkIGFmdGVyIGV2ZXJ5IHBhcnRpYWwgc3RlcC4KICAgIHVw'
    'bGluayA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9jb25mJykvcm91dGVbJ2RldiddLydmb3J3YXJkaW5nJwogICAgd3Jp'
    'dGUoUk9PVC8nbmV0d29yay5qc29uJywganNvbi5kdW1wcyh7J2ZvcndhcmQnOiBvbGRfZm9yd2FyZCwgJ2ludGVyZmFjZSc6'
    'IHJvdXRlWydkZXYnXSwgJ3VwbGlua19mb3J3YXJkJzogdXBsaW5rLnJlYWRfdGV4dCgpLnN0cmlwKCl9KSkKICAgIGNvbW1h'
    'bmQoWydpcCcsICduZXRucycsICdhZGQnLCBOU10pCiAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykvTlMvJ3Jlc29sdi5j'
    'b25mJywgJ25hbWVzZXJ2ZXIgMS4xLjEuMVxubmFtZXNlcnZlciA5LjkuOS45XG5vcHRpb25zIHRpbWVvdXQ6MiBhdHRlbXB0'
    'czoyXG4nKQogICAgIyBuc3MtcmVzb2x2ZSB0YWxrcyB0byB0aGUgaG9zdCBkYWVtb24gb3ZlciBhIFVuaXggc29ja2V0IGV2'
    'ZW4gaW5zaWRlIG5ldG5zLgogICAgbnNzPVBhdGgoJy9ldGMvbnNzd2l0Y2guY29uZicpLnJlYWRfdGV4dCgpCiAgICBuc3M9'
    'cmUuc3ViKHInXmhvc3RzOi4qJCcsICdob3N0czogZmlsZXMgZG5zJywgbnNzLCBmbGFncz1yZS5NKQogICAgd3JpdGUoUGF0'
    'aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJywgbnNzKQogICAgY29tbWFuZChbJ2lwJywgJ2xpbmsnLCAnYWRk'
    'JywgSE9TVCwgJ3R5cGUnLCAndmV0aCcsICdwZWVyJywgJ25hbWUnLCBQRUVSXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5r'
    'JywgJ3NldCcsIFBFRVIsICduZXRucycsIE5TXSkKICAgIGNvbW1hbmQoWydpcCcsICdhZGRyJywgJ2FkZCcsIEdBVEVXQVkr'
    'Jy8zMCcsICdkZXYnLCBIT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ3NldCcsIEhPU1QsICd1cCddKQogICAg'
    'aW5zaWRlKFsnaXAnLCAnYWRkcicsICdhZGQnLCBDTElFTlQrJy8zMCcsICdkZXYnLCBQRUVSXSkKICAgIGluc2lkZShbJ2lw'
    'JywgJ2xpbmsnLCAnc2V0JywgUEVFUiwgJ3VwJ10pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3NldCcsICdsbycsICd1'
    'cCddKQogICAgaW5zaWRlKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ2RlZmF1bHQnLCAndmlhJywgR0FURVdBWV0pCiAgICAj'
    'IEEgcmVjb25uZWN0IGNyZWF0ZXMgYSBORVcgVENQIHNvY2tldCBhZnRlciBJS0UgaW5zdGFsbHMgaXRzIGRlZmF1bHQgcm91'
    'dGUuCiAgICAjIEtlZXAgdGhlIHJlbGF5IHNvY2tldCBvbiB0aGUgbmFtZXNwYWNlIHVwbGluayB3aXRoIHRoZSBwaHlzaWNh'
    'bCB2ZXRoIHNvdXJjZTsKICAgICMgb3RoZXJ3aXNlIHNvdXJjZSBzZWxlY3Rpb24gZ2l2ZXMgaXQgdGhlIFZQTiBWSVAgYW5k'
    'IHR1bm5lbHMgaXQgaW50byBpdHNlbGYuCiAgICBpZiBBQ1RJVkUuZ2V0KCd0cmFuc3BvcnRfYWRkcmVzcycpOgogICAgICAg'
    'IGluc2lkZShbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5JywnODknLCd0bycsQUNUSVZFWyd0cmFuc3BvcnRfYWRkcmVz'
    'cyddKycvMzInLAogICAgICAgICAgICAgICAgJ2lwcHJvdG8nLCd0Y3AnLCdkcG9ydCcsc3RyKEFDVElWRVsndHJhbnNwb3J0'
    'X3BvcnQnXSksJ2xvb2t1cCcsJ21haW4nXSkKICAgIGNvbW1hbmQoWydpcCcsICdyb3V0ZScsICdhZGQnLCAndGFibGUnLCBz'
    'dHIoVEFCTEUpLCAnZGVmYXVsdCcsICd2aWEnLCByb3V0ZVsnZ2F0ZXdheSddLCAnZGV2Jywgcm91dGVbJ2RldiddXSkKICAg'
    'IGZvciBhZGRyZXNzIGluIEVORFBPSU5UUzoKICAgICAgICBjb21tYW5kKFsnaXAnLCAncnVsZScsICdhZGQnLCAncHJpb3Jp'
    'dHknLCBzdHIoUFJJT1JJVFkpLCAnZnJvbScsIENMSUVOVCsnLzMyJywKICAgICAgICAgICAgICAgICAndG8nLCBhZGRyZXNz'
    'KycvMzInLCAnbG9va3VwJywgc3RyKFRBQkxFKV0pCiAgICBydWxlcyA9IGhvc3RfcnVsZXMocm91dGVbJ2RldiddLCBwcmV2'
    'aW91c19mb3J3YXJkPW9sZF9mb3J3YXJkID09ICcxJykKICAgIGNvbW1hbmQoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBk'
    'YXRhPXJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsICctZicsICctJ10sIGRhdGE9cnVsZXMpCiAgICAjIFBlci1pbnRlcmZh'
    'Y2UgZm9yd2FyZGluZyBhdm9pZHMgaXBfZm9yd2FyZCdzIGdsb2JhbCBkZWZhdWx0cyByZXNldC4KICAgIChQYXRoKCcvcHJv'
    'Yy9zeXMvbmV0L2lwdjQvY29uZicpL0hPU1QvJ2ZvcndhcmRpbmcnKS53cml0ZV90ZXh0KCcxXG4nKQogICAgdXBsaW5rLndy'
    'aXRlX3RleHQoJzFcbicpCgoKZGVmIGNsZWFudXAoKToKICAgIGNsZWFudXBfZnVsbCgpCiAgICAjIEFuIHVub3duZWQgbmFt'
    'ZXNwYWNlL3RhYmxlIG11c3QgbmV2ZXIgYmUgZGVsZXRlZCBieSBhIGdlbmVyaWMgY2xlYW51cCBjYWxsLgogICAgaWYgbm90'
    'IChST09ULyduZXR3b3JrLmpzb24nKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGEgPSBqc29uLmxvYWRzKChS'
    'T09ULyduZXR3b3JrLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGNvbW1hbmQoWyduZnQnLCAnZGVsZXRlJywgJ3RhYmxlJywg'
    'J2luZXQnLCBORlRdLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluICgqRU5EUE9JTlRTLCAqTEVHQUNZX0VORFBP'
    'SU5UUyk6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnZGVsJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9SSVRZKSwg'
    'J2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1cCcsIHN0'
    'cihUQUJMRSldLCBjaGVjaz1GYWxzZSkKICAgIGZvciBhZGRyZXNzIGluIGRhdGEuZ2V0KCdtZWFzdXJlbWVudF9pcHMnLCBb'
    'XSk6CiAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYWRkcmVzcykuaXNfZ2xvYmFsOgogICAgICAgICAgICBjb21t'
    'YW5kKFsnaXAnLCAncnVsZScsICdkZWwnLCAncHJpb3JpdHknLCAnMTExJywgJ2Zyb20nLCBDTElFTlQrJy8zMicsICd0bycs'
    'IGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAn'
    'cm91dGUnLCAnZmx1c2gnLCAndGFibGUnLCBzdHIoVEFCTEUpXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAn'
    'bmV0bnMnLCAnZGVsJywgTlNdLCBjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2RlbCcsIEhPU1Rd'
    'LCBjaGVjaz1GYWxzZSkKICAgIGlmICd1cGxpbmtfZm9yd2FyZCcgaW4gZGF0YToKICAgICAgICBwYXRoID0gUGF0aCgnL3By'
    'b2Mvc3lzL25ldC9pcHY0L2NvbmYnKS9kYXRhWydpbnRlcmZhY2UnXS8nZm9yd2FyZGluZycKICAgICAgICBpZiBwYXRoLmV4'
    'aXN0cygpOgogICAgICAgICAgICBwYXRoLndyaXRlX3RleHQoZGF0YVsndXBsaW5rX2ZvcndhcmQnXSsnXG4nKQogICAgZWxp'
    'ZiBkYXRhLmdldCgnZm9yd2FyZCcpID09ICcwJyBhbmQgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS5y'
    'ZWFkX3RleHQoKS5zdHJpcCgpID09ICcxJzoKICAgICAgICBQYXRoKCcvcHJvYy9zeXMvbmV0L2lwdjQvaXBfZm9yd2FyZCcp'
    'LndyaXRlX3RleHQoJzBcbicpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicpLnVubGluayhtaXNz'
    'aW5nX29rPVRydWUpCiAgICAoUGF0aCgnL2V0Yy9uZXRucycpL05TLyduc3N3aXRjaC5jb25mJykudW5saW5rKG1pc3Npbmdf'
    'b2s9VHJ1ZSkKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhPU0Vycm9yKToKICAgICAgICAoUGF0aCgnL2V0Yy9uZXRu'
    'cycpL05TKS5ybWRpcigpCiAgICAoUk9PVC8nbmV0d29yay5qc29uJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKCgoKCmRl'
    'ZiB0bHNfcmVxdWVzdChhZGRyZXNzLCBwYXRoLCBib2R5PU5vbmUsIGNsaWVudD1GYWxzZSwgdGltZW91dD04LCBpZGVudGl0'
    'eT1TRVJWRVIpOgogICAgY29udGV4dCA9IHNzbC5jcmVhdGVfZGVmYXVsdF9jb250ZXh0KGNhZGF0YT1QSU5ORURfQ0EpCiAg'
    'ICBpZiBjbGllbnQ6CiAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3Ry'
    'KFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICBzb2NrID0gc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChhZGRyZXNzLCA4'
    'NDQzKSwgdGltZW91dD10aW1lb3V0KQogICAgdHJ5OgogICAgICAgIHRscyA9IGNvbnRleHQud3JhcF9zb2NrZXQoc29jaywg'
    'c2VydmVyX2hvc3RuYW1lPWlkZW50aXR5KQogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgc29jay5jbG9zZSgp'
    'CiAgICAgICAgcmFpc2UKICAgIGNvbm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbihhZGRyZXNzLCA4NDQz'
    'LCB0aW1lb3V0PXRpbWVvdXQpCiAgICBjb25uZWN0aW9uLnNvY2sgPSB0bHMKICAgIGVuY29kZWQgPSBqc29uLmR1bXBzKGJv'
    'ZHksIHNlcGFyYXRvcnM9KCcsJywgJzonKSkuZW5jb2RlKCkgaWYgYm9keSBpcyBub3QgTm9uZSBlbHNlIE5vbmUKICAgIHRy'
    'eToKICAgICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ1BPU1QnIGlmIGJvZHkgaXMgbm90IE5vbmUgZWxzZSAnR0VUJywgcGF0'
    'aCwgYm9keT1lbmNvZGVkLAogICAgICAgICAgICAgICAgICAgICAgICAgICBoZWFkZXJzPXsnQ29udGVudC1UeXBlJzogJ2Fw'
    'cGxpY2F0aW9uL2pzb24nLCAnQ29ubmVjdGlvbic6ICdjbG9zZSd9KQogICAgICAgIHJlc3BvbnNlID0gY29ubmVjdGlvbi5n'
    'ZXRyZXNwb25zZSgpCiAgICAgICAgcmF3ID0gcmVzcG9uc2UucmVhZCgyMDAwMSkKICAgICAgICBpZiByZXNwb25zZS5zdGF0'
    'dXMgIT0gMjAwIG9yIGxlbihyYXcpID4gMjAwMDA6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigncmVxdWVzdF9y'
    'ZWplY3RlZCcpCiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMocmF3KQogICAgZmluYWxseToKICAgICAgICBjb25uZWN0aW9u'
    'LmNsb3NlKCkKCgpkZWYgZW5yb2xsKCk6CiAgICB0b2tlbiA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkK'
    'ICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cignaW52YWxpZF90b2tlbicpCiAgICB0cnk6CiAgICAgICAgY2FjaGVkID0ganNvbi5sb2FkcygoUk9PVC8ncHJvZmlsZS5q'
    'c29uJykucmVhZF90ZXh0KCkpCiAgICAgICAgaWYgKGNhY2hlZC5nZXQoJ2NhJykgPT0gUElOTkVEX0NBIGFuZCBjYWNoZWQu'
    'Z2V0KCdzZXJ2ZXInKSA9PSBTRVJWRVIgYW5kCiAgICAgICAgICAgIHJlLmZ1bGxtYXRjaChyJ2RldmljZS1bYS1mMC05XXsy'
    'NH0nLCBjYWNoZWQuZ2V0KCdpZGVudGl0eScsICcnKSkgYW5kCiAgICAgICAgICAgIGNhY2hlZC5nZXQoJ2VuZHBvaW50Jykg'
    'aW4gRU5EUE9JTlRTIGFuZCBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3b3JrJykgYW5kCiAgICAgICAgICAgIGNvbW1hbmQo'
    'WydvcGVuc3NsJywgJ3g1MDknLCAnLWluJywgUk9PVC8nY2xpZW50LnBlbScsICctY2hlY2tlbmQnLCBzdHIoNyo4NjQwMCks'
    'ICctbm9vdXQnXSwgY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMCk6CiAgICAgICAgICAgIGNvbnRleHQgPSBzc2wuU1NM'
    'Q29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3Ry'
    'KFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRlID0gcGh5'
    'c2ljYWxfcm91dGUoKQogICAgICAgICAgICBjdXJyZW50ID0gaGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyh7a2V5OiByb3V0'
    'ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAncHJlZnNyYycpfSwgc29ydF9rZXlzPVRydWUpLmVu'
    'Y29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICBhZGRyZXNzID0gY2FjaGVkWydlbmRwb2ludCddIGlmIGNhY2hlZC5n'
    'ZXQoJ3BoeXNpY2FsX25ldHdvcmsnKSA9PSBjdXJyZW50IGVsc2UgU0VSVkVSCiAgICAgICAgICAgIHJldHVybiBjYWNoZWRb'
    'J2lkZW50aXR5J10sIGFkZHJlc3MKICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvciwgc3NsLlNTTEVycm9yKToKICAg'
    'ICAgICBwYXNzCiAgICBzdGFnZSgndG9rZW4nLCAn0J/QvtC70YPRh9Cw0Y4g0YHQtdGA0YLQuNGE0LjQutCw0YIg0LTQu9GP'
    'INGN0YLQvtCz0L4g0YPRgdGC0YDQvtC50YHRgtCy0LAuJywgMjUpCiAgICBpZiBub3QgKFJPT1QvJ2NsaWVudC1rZXkucGVt'
    'JykuZXhpc3RzKCk6CiAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAnZ2VucGtleScsICctYWxnb3JpdGhtJywgJ1JTQScs'
    'ICctcGtleW9wdCcsICdyc2Ffa2V5Z2VuX2JpdHM6MzA3MicsCiAgICAgICAgICAgICAgICAgJy1vdXQnLCBST09ULydjbGll'
    'bnQta2V5LnBlbSddLCB0aW1lb3V0PTMwKQogICAgICAgIChST09ULydjbGllbnQta2V5LnBlbScpLmNobW9kKDBvNjAwKQog'
    'ICAgaWYgbm90IChST09ULydkZXZpY2UnKS5leGlzdHMoKToKICAgICAgICB3cml0ZShST09ULydkZXZpY2UnLCBzZWNyZXRz'
    'LnRva2VuX2hleCgxNikpCiAgICBjb21tYW5kKFsnb3BlbnNzbCcsICdyZXEnLCAnLW5ldycsICcta2V5JywgUk9PVC8nY2xp'
    'ZW50LWtleS5wZW0nLCAnLXN1YmonLCAnL0NOPWV2Z2VuaXVtLWRldmljZScsCiAgICAgICAgICAgICAnLW91dCcsIFJPT1Qv'
    'J3JlcXVlc3QucGVtJ10pCiAgICBwYXlsb2FkID0geyd0b2tlbic6IHRva2VuLCAnZGV2aWNlJzogKFJPT1QvJ2RldmljZScp'
    'LnJlYWRfdGV4dCgpLnN0cmlwKCksICdjc3InOiAoUk9PVC8ncmVxdWVzdC5wZW0nKS5yZWFkX3RleHQoKX0KICAgIGxhc3Qg'
    'PSBOb25lCiAgICBmb3IgYWRkcmVzcyBpbiAoU0VSVkVSLCk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG5hbWVz'
    'cGFjZSgpOgogICAgICAgICAgICAgICAgcmVwbHkgPSB0bHNfcmVxdWVzdChhZGRyZXNzLCAnL2Vucm9sbCcsIHBheWxvYWQs'
    'IHRpbWVvdXQ9NikKICAgICAgICAgICAgcHJvZmlsZSA9IHJlcGx5LmdldCgncHJvZmlsZScsIHt9KQogICAgICAgICAgICBp'
    'ZiByZXBseS5nZXQoJ29rJykgaXMgbm90IFRydWUgb3IgcHJvZmlsZS5nZXQoJ2NhJykgIT0gUElOTkVEX0NBIG9yIHByb2Zp'
    'bGUuZ2V0KCdzZXJ2ZXInKSAhPSBTRVJWRVI6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRf'
    'cHJvZmlsZScpCiAgICAgICAgICAgIGlmIG5vdCByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgcHJvZmls'
    'ZS5nZXQoJ2lkZW50aXR5JywgJycpKToKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignaW52YWxpZF9pZGVu'
    'dGl0eScpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ2NsaWVudC5wZW0nLCBwcm9maWxlWydjZXJ0aWZpY2F0ZSddKQogICAg'
    'ICAgICAgICB3cml0ZShST09ULydjYS5wZW0nLCBQSU5ORURfQ0EpCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDknLydj'
    'bGllbnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8neDUwOWNhJy8nY2Eu'
    'cGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULydwcml2YXRlJy8nY2xpZW50LWtleS5wZW0nLCAoUk9P'
    'VC8nY2xpZW50LWtleS5wZW0nKS5yZWFkX3RleHQoKSkKICAgICAgICAgICAgY29tbWFuZChbJ29wZW5zc2wnLCAndmVyaWZ5'
    'JywgJy1wdXJwb3NlJywgJ3NzbGNsaWVudCcsICctQ0FmaWxlJywgUk9PVC8nY2EucGVtJywgUk9PVC8nY2xpZW50LnBlbSdd'
    'KQogICAgICAgICAgICBjdHggPSBzc2wuU1NMQ29udGV4dChzc2wuUFJPVE9DT0xfVExTX0NMSUVOVCkKICAgICAgICAgICAg'
    'Y3R4LmxvYWRfY2VydF9jaGFpbihzdHIoUk9PVC8nY2xpZW50LnBlbScpLCBzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKSkK'
    'ICAgICAgICAgICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAgICAgICAgIGZpbmdlcnByaW50ID0gaGFzaGxpYi5z'
    'aGEyNTYoanNvbi5kdW1wcyh7a2V5OiByb3V0ZS5nZXQoa2V5KSBmb3Iga2V5IGluICgnZGV2JywgJ2dhdGV3YXknLCAncHJl'
    'ZnNyYycpfSwgc29ydF9rZXlzPVRydWUpLmVuY29kZSgpKS5oZXhkaWdlc3QoKQogICAgICAgICAgICB3cml0ZShST09ULydw'
    'cm9maWxlLmpzb24nLCBqc29uLmR1bXBzKHsqKnByb2ZpbGUsICdlbmRwb2ludCc6IGFkZHJlc3MsICdwaHlzaWNhbF9uZXR3'
    'b3JrJzogZmluZ2VycHJpbnR9KSkKICAgICAgICAgICAgcmV0dXJuIHByb2ZpbGVbJ2lkZW50aXR5J10sIGFkZHJlc3MKICAg'
    'ICAgICBleGNlcHQgKE9TRXJyb3IsIHNzbC5TU0xFcnJvciwgUnVudGltZUVycm9yKSBhcyBleGM6CiAgICAgICAgICAgIGxh'
    'c3QgPSBleGMKICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZW5yb2xsbWVudF91bmF2YWlsYWJsZScpIGZyb20gbGFzdAoKCmRl'
    'ZiBkYWVtb25fY29uZmlncyhpZGVudGl0eSwgYWRkcmVzcyk6CiAgICBSVU5USU1FLm1rZGlyKG1vZGU9MG83MDAsIHBhcmVu'
    'dHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGluY2x1ZGVzID0gJ1xuJy5qb2luKCdpbmNsdWRlICcrc3RyKHApIGZvciBw'
    'YXR0ZXJuIGluICgnL2V0Yy9zdHJvbmdzd2FuLmQvY2hhcm9uLyouY29uZicsICcvZXRjL3N0cm9uZ3N3YW4vc3Ryb25nc3dh'
    'bi5kL2NoYXJvbi8qLmNvbmYnKQogICAgICAgICAgICAgICAgICAgICAgICAgZm9yIHAgaW4gUGF0aCgnLycpLmdsb2IocGF0'
    'dGVybi5sc3RyaXAoJy8nKSkpCiAgICB3cml0ZShST09ULydzdHJvbmdzd2FuLmNvbmYnLCBmJycnY2hhcm9uIHt7CiBsb2Fk'
    'X21vZHVsYXIgPSB5ZXMKIGluc3RhbGxfcm91dGVzID0geWVzCiByb3V0aW5nX3RhYmxlID0gNTE4MjIKIHJvdXRpbmdfdGFi'
    'bGVfcHJpbyA9IDEwMAogcGx1Z2lucyB7ewp7aW5jbHVkZXN9CiAgdmljaSB7eyBzb2NrZXQgPSB1bml4Oi8ve1JVTlRJTUV9'
    'L2NoYXJvbi52aWNpIH19CiAgcmVzb2x2ZSB7eyBsb2FkID0gbm8gfX0KICBrZXJuZWwtbGliaXBzZWMge3sgbG9hZCA9IG5v'
    'IH19CiB9fQp9fQpjaGFyb24tc3lzdGVtZCB7eyBqb3VybmFsIHt7IGRlZmF1bHQgPSAwOyBpa2UgPSAxIH19IH19CicnJykK'
    'ICAgICMgQWJzb2x1dGUgY3JlZGVudGlhbHMgYXJlIGxvY2FsIHRvIHRoaXMgZGV2aWNlLCBub3Qgc2hhcmVkIGJ5IHRoZSBh'
    'Y2NvdW50IHRva2VuLgogICAgd3JpdGUoUk9PVC8nY29ubmVjdGlvbi5jb25mJywgZicnJ2Nvbm5lY3Rpb25zIHt7CiBzdGFy'
    'Zml2ZSB7ewogIHZlcnNpb24gPSAyCiAgcmVtb3RlX2FkZHJzID0ge2FkZHJlc3N9CiAgcmVtb3RlX3BvcnQgPSB7QUNUSVZF'
    'Wydwb3J0J119CiAgbG9jYWxfcG9ydCA9IDQ1MDAKICB2aXBzID0gMC4wLjAuMAogIHByb3Bvc2FscyA9IGFlczI1NmdjbTE2'
    'LXByZnNoYTM4NC1lY3AzODQKICBlbmNhcCA9IHllcwogIGZyYWdtZW50YXRpb24gPSB5ZXMKICBtb2Jpa2UgPSB5ZXMKICBk'
    'cGRfZGVsYXkgPSAxNXMKICBsb2NhbCB7eyBhdXRoID0gZWFwLXRsczsgaWQgPSB7aWRlbnRpdHl9OyBlYXBfaWQgPSB7aWRl'
    'bnRpdHl9OyBjZXJ0cyA9IHtST09UfS9jbGllbnQucGVtIH19CiAgcmVtb3RlIHt7IGF1dGggPSBwdWJrZXk7IGlkID0ge0FD'
    'VElWRVsnaWRlbnRpdHknXX07IGNhY2VydHMgPSB7Uk9PVH0vY2EucGVtIH19CiAgY2hpbGRyZW4ge3sKICAgc3RhcmZpdmUt'
    'bmV0IHt7CiAgICBsb2NhbF90cyA9IGR5bmFtaWMKICAgIHJlbW90ZV90cyA9IDAuMC4wLjAvMAogICAgcmVxaWQgPSB7UkVR'
    'SUR9CiAgICBlc3BfcHJvcG9zYWxzID0gY2hhY2hhMjBwb2x5MTMwNQogICAgZHBkX2FjdGlvbiA9IGNsZWFyCiAgICBzdGFy'
    'dF9hY3Rpb24gPSBub25lCiAgIH19CiAgfX0KIH19Cn19CnNlY3JldHMge3sgcHJpdmF0ZS1jbGllbnQge3sgZmlsZSA9IHtS'
    'T09UfS9jbGllbnQta2V5LnBlbSB9fSB9fQonJycpCiAgICAjIFN0cm9uZ1N3YW4gY29uZmlnIHVzZXMgbmV3bGluZXMsIG5v'
    'dCBzZW1pY29sb24gc2VwYXJhdG9ycyAobm9ybWFsaXplIGNvbXBhY3QgYmxvY2tzKS4KICAgIGZvciBuYW1lIGluICgnc3Ry'
    'b25nc3dhbi5jb25mJywgJ2Nvbm5lY3Rpb24uY29uZicpOgogICAgICAgIHBhdGggPSBST09UL25hbWUKICAgICAgICBwYXRo'
    'LndyaXRlX3RleHQocGF0aC5yZWFkX3RleHQoKS5yZXBsYWNlKCc7ICcsICdcbicpLnJlcGxhY2UoJ3sgJywgJ3tcbicpLnJl'
    'cGxhY2UoJyB9JywgJ1xufScpKQogICAgcnVsZXMgPSBmJycndGFibGUgaW5ldCBldm5fc3RhcmZpdmVfZ3VhcmQge3sKIGNo'
    'YWluIG91dHB1dCB7ewogIHR5cGUgZmlsdGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7CiAgb2lm'
    'bmFtZSAibG8iIGFjY2VwdAogIGlwIGRhZGRyIDEyNy4wLjAuMSB1ZHAgZHBvcnQgMjQ1NzMgYWNjZXB0CiAgb2lmbmFtZSAi'
    'e0ZVTExfUEVFUn0iIGlwIGRhZGRyIDE3Mi4yOS4yNDcuMSBtZXRhIGw0cHJvdG8ge3sgdGNwLCB1ZHAgfX0gdGggc3BvcnQg'
    'NTMgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVkcCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFjY2VwdAogIGlwIGRh'
    'ZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpcCBkYWRkciAxOTUuMjA5'
    'LjIxMS4xNjMgdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIG1ldGEgc2t1aWQgMCBpcCBkYWRkciB7YWRkcmVzc30gdGNwIGRw'
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
    'KToKICAgICAgICByZXR1cm4gdGxzX3JlcXVlc3QoSEVBTFRILCAnL2hlYWx0aCcsIGNsaWVudD1UcnVlLCBpZGVudGl0eT1B'
    'Q1RJVkVbJ2lkZW50aXR5J10sIHRpbWVvdXQ9MykuZ2V0KCdzZXJ2aWNlJykgPT0gJ2V2Z2VuaXVtLXN0YXJmaXZlJwoKCmRl'
    'ZiBkb3dubG9hZChzaXplPTEwNDg1NzYpOgogICAgIyBBIGJvdW5kZWQgaW50ZWdyaXR5IGNoZWNrLCBub3QgYSBjbGFpbSB0'
    'byBoYXZlIG1lYXN1cmVkIHRoZSBJU1AncyBtYXhpbXVtIHJhdGUuCiAgICBibG9jayA9IGhhc2hsaWIuc2hha2VfMjU2KGIn'
    'ZXZnZW5pdW0tc3RhcmZpdmUtaW50ZWdyaXR5LXYxJykuZGlnZXN0KDY1NTM2KQogICAgZXhwZWN0ZWQgPSBoYXNobGliLnNo'
    'YTI1NigoYmxvY2sqKHNpemUvL2xlbihibG9jaykrMSkpWzpzaXplXSkuaGV4ZGlnZXN0KCkKICAgIGNvbnRleHQgPSBzc2wu'
    'Y3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgY29udGV4dC5sb2FkX2NlcnRfY2hhaW4oc3Ry'
    'KFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICB3aXRoIG5hbWVzcGFjZSgpOgog'
    'ICAgICAgIHNvY2sgPSBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKEhFQUxUSCwgODQ0MyksIHRpbWVvdXQ9MTApCiAgICAg'
    'ICAgdGxzID0gY29udGV4dC53cmFwX3NvY2tldChzb2NrLCBzZXJ2ZXJfaG9zdG5hbWU9QUNUSVZFWydpZGVudGl0eSddKQog'
    'ICAgICAgIGNvbm5lY3Rpb24gPSBodHRwLmNsaWVudC5IVFRQQ29ubmVjdGlvbihIRUFMVEgsIDg0NDMsIHRpbWVvdXQ9MTAp'
    'OyBjb25uZWN0aW9uLnNvY2sgPSB0bHMKICAgICAgICB0cnk6CiAgICAgICAgICAgIHN0YXJ0ID0gdGltZS5tb25vdG9uaWMo'
    'KQogICAgICAgICAgICBjb25uZWN0aW9uLnJlcXVlc3QoJ0dFVCcsICcvYmxvYj9zaXplPScrc3RyKHNpemUpKQogICAgICAg'
    'ICAgICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAgICAgICAgICBpZiByZXNwb25zZS5zdGF0dXMg'
    'IT0gMjAwOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCd0cmFuc2Zlcl9odHRwJykKICAgICAgICAgICAg'
    'ZGlnZXN0ID0gaGFzaGxpYi5zaGEyNTYoKTsgcmVjZWl2ZWQgPSAwCiAgICAgICAgICAgIHdoaWxlIHJlY2VpdmVkIDwgc2l6'
    'ZToKICAgICAgICAgICAgICAgIGRhdGEgPSByZXNwb25zZS5yZWFkKG1pbig2NTUzNiwgc2l6ZS1yZWNlaXZlZCkpCiAgICAg'
    'ICAgICAgICAgICBpZiBub3QgZGF0YToKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICAgICAgZGlnZXN0'
    'LnVwZGF0ZShkYXRhKTsgcmVjZWl2ZWQgKz0gbGVuKGRhdGEpCiAgICAgICAgICAgIGVsYXBzZWQgPSB0aW1lLm1vbm90b25p'
    'YygpLXN0YXJ0CiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCiAgICBpZiByZWNlaXZl'
    'ZCAhPSBzaXplIG9yIGRpZ2VzdC5oZXhkaWdlc3QoKSAhPSBleHBlY3RlZDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'J2ludGVncml0eV9mYWlsZWQnKQogICAgcmV0dXJuIHsnYnl0ZXMnOiByZWNlaXZlZCwgJ2Rvd25sb2FkX21icHMnOiByb3Vu'
    'ZChyZWNlaXZlZCo4L2VsYXBzZWQvMWU2LCAyKSwKICAgICAgICAgICAgJ2VsYXBzZWRfbXMnOiByb3VuZChlbGFwc2VkKjEw'
    'MDApLCAnaW50ZWdyaXR5JzogVHJ1ZSwgJ2xpbWl0ZWRfc2FtcGxlJzogVHJ1ZX0KCgpkZWYgZGV2aWNlX3N0YXR1cygpOgog'
    'ICAgdHJ5OgogICAgICAgIGluZm89anNvbi5sb2FkcygoUk9PVC8nZGV2aWNlLWluZm8uanNvbicpLnJlYWRfdGV4dCgpKQog'
    'ICAgICAgIHJldHVybiB7J2RldmljZV9uYW1lJzppbmZvLmdldCgnbmFtZScsJycpLCdkZXZpY2VfbnVtYmVyJzppbmZvLmdl'
    'dCgnbnVtYmVyJyksCiAgICAgICAgICAgICAgICAnZGV2aWNlX25hbWVfcGVuZGluZyc6Ym9vbChpbmZvLmdldCgncGVuZGlu'
    'ZycpIG9yIGluZm8uZ2V0KCdzeW5jX2Vycm9yJykpfQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnJldHVybiB7'
    'J2RldmljZV9uYW1lJzonJywnZGV2aWNlX251bWJlcic6Tm9uZSwnZGV2aWNlX25hbWVfcGVuZGluZyc6RmFsc2V9CgoKZGVm'
    'IHN5bmNfZGV2aWNlX25hbWUobmFtZT1Ob25lKToKICAgIGltcG9ydCB1bmljb2RlZGF0YQogICAgaWYgbm90IHRva2VuX3N0'
    'YXR1cygpWydoYXNfdG9rZW4nXTpyYWlzZSBWYWx1ZUVycm9yKCfQodC90LDRh9Cw0LvQsCDQv9C+0LTRgtCy0LXRgNC00LjR'
    'gtC1INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAuJykKICAgIGlmIG5hbWUgaXMgbm90IE5vbmU6CiAgICAgICAgbmFtZT11'
    'bmljb2RlZGF0YS5ub3JtYWxpemUoJ05GQycsc3RyKG5hbWUpKS5zdHJpcCgpCiAgICAgICAgaWYgbm90IDE8PWxlbihuYW1l'
    'KTw9NjQgb3IgYW55KHVuaWNvZGVkYXRhLmNhdGVnb3J5KGMpLnN0YXJ0c3dpdGgoJ0MnKSBmb3IgYyBpbiBuYW1lKToKICAg'
    'ICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0JjQvNGPINC00L7Qu9C20L3QviDRgdC+0LTQtdGA0LbQsNGC0Ywg0L7RgiAx'
    'INC00L4gNjQg0L7QsdGL0YfQvdGL0YUg0YHQuNC80LLQvtC70L7Qsi4nKQogICAgaWYgbm90IChST09ULydkZXZpY2UnKS5l'
    'eGlzdHMoKTp3cml0ZShST09ULydkZXZpY2UnLHNlY3JldHMudG9rZW5faGV4KDE2KSkKICAgIHRyeTppbmZvPWpzb24ubG9h'
    'ZHMoKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9y'
    'KTppbmZvPXt9CiAgICBpZiBuYW1lIGlzIG5vdCBOb25lOmluZm8udXBkYXRlKG5hbWU9bmFtZSxwZW5kaW5nPVRydWUpCiAg'
    'ICBwYXlsb2FkPXsndG9rZW4nOihST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCksJ2RldmljZSc6KFJPT1QvJ2Rl'
    'dmljZScpLnJlYWRfdGV4dCgpLnN0cmlwKCl9CiAgICBpZiBpbmZvLmdldCgncGVuZGluZycpOnBheWxvYWRbJ25hbWUnXT1p'
    'bmZvWyduYW1lJ10KICAgIHRyeToKICAgICAgICB3aXRoIG5hbWVzcGFjZSgpIGlmIFBhdGgoJy9ydW4vbmV0bnMvJytOUyku'
    'ZXhpc3RzKCkgZWxzZSBjb250ZXh0bGliLm51bGxjb250ZXh0KCk6CiAgICAgICAgICAgIHJlcGx5PXRsc19yZXF1ZXN0KFNF'
    'UlZFUiwnL2RldmljZScscGF5bG9hZCx0aW1lb3V0PTUpCiAgICAgICAgdmFsdWU9cmVwbHlbJ2RldmljZSddO251bWJlcj1p'
    'bnQodmFsdWVbJ251bWJlciddKQogICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHZhbHVlWyduYW1lJ10sc3RyKSBvciBub3Qg'
    'MTw9bGVuKHZhbHVlWyduYW1lJ10pPD02NCBvciBudW1iZXI8MTpyYWlzZSBWYWx1ZUVycm9yKCdpbnZhbGlkX2RldmljZV9t'
    'ZXRhZGF0YScpCiAgICAgICAgaW5mbz17J25hbWUnOnZhbHVlWyduYW1lJ10sJ251bWJlcic6bnVtYmVyLCdwZW5kaW5nJzpG'
    'YWxzZSwnc3luY19lcnJvcic6RmFsc2V9CiAgICBleGNlcHQgKE9TRXJyb3IsUnVudGltZUVycm9yLFZhbHVlRXJyb3IsS2V5'
    'RXJyb3IsaHR0cC5jbGllbnQuSFRUUEV4Y2VwdGlvbik6CiAgICAgICAgaW5mb1snc3luY19lcnJvciddPVRydWUKICAgIHdy'
    'aXRlKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nLGpzb24uZHVtcHMoaW5mbyxlbnN1cmVfYXNjaWk9RmFsc2UpKQogICAgcmV0'
    'dXJuIGRldmljZV9zdGF0dXMoKQoKCmRlZiB0b2tlbl9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICB0b2tlbiA9IChST09U'
    'Lyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICB0b2tl'
    'biA9ICcnCiAgICB2YWxpZCA9IHJlLmZ1bGxtYXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbikgaXMgbm90IE5vbmUKICAgIHJl'
    'dHVybiB7J2hhc190b2tlbic6IHZhbGlkLAogICAgICAgICAgICAndG9rZW5faGludCc6ICdFVk4xLeKAouKAouKAouKAoiDC'
    'tyBJRCAnICsgaGFzaGxpYi5zaGEyNTYodG9rZW4uZW5jb2RlKCkpLmhleGRpZ2VzdCgpWzo4XSBpZiB2YWxpZCBlbHNlICcn'
    'fQoKCmRlZiBzYXZlX3Rva2VuKHRva2VuKToKICAgIHRva2VuID0gdG9rZW4uc3RyaXAoKQogICAgaWYgbm90IHJlLmZ1bGxt'
    'YXRjaChUT0tFTl9QQVRURVJOLCB0b2tlbik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcign0J3Rg9C20LXQvSDRgtC+0LrQ'
    'tdC9INC60LvQuNC10L3RgtCwINGE0L7RgNC80LDRgtCwIEVWTjEt4oCmJykKICAgIFJPT1QubWtkaXIobW9kZT0wbzcwMCwg'
    'cGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgb2xkID0gKFJPT1QvJ3Rva2VuJykucmVhZF90ZXh0KCkuc3RyaXAo'
    'KSBpZiAoUk9PVC8ndG9rZW4nKS5leGlzdHMoKSBlbHNlICcnCiAgICBpZiBvbGQgPT0gdG9rZW46CiAgICAgICAgc3luY19k'
    'ZXZpY2VfbmFtZSgpO3JldHVybgogICAgaWYgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcs'
    'IFVOSVRdLCBjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcign0KHQvdCw'
    '0YfQsNC70LAg0L7RgtC60LvRjtGH0LjRgtC1IFZQTi3RgtGD0L3QvdC10LvRjCDQv9C10YDQtdC0INGB0LzQtdC90L7QuSDR'
    'gtC+0LrQtdC90LAuJykKICAgICMgQSBkaWZmZXJlbnQgYWNjb3VudCBuZWVkcyBpdHMgb3duIGRldmljZSBjcmVkZW50aWFs'
    'cy4gTmV2ZXIgcmV1c2UgaXRzIGNlcnRpZmljYXRlLgogICAgZm9yIG5hbWUgaW4gKCdkZXZpY2UtaW5mby5qc29uJywgJ2Rl'
    'dmljZScsICdjbGllbnQta2V5LnBlbScsICdjbGllbnQucGVtJywgJ3Byb2ZpbGUuanNvbicsICdyZXF1ZXN0LnBlbScsCiAg'
    'ICAgICAgICAgICAgICAgJ3ByaXZhdGUvY2xpZW50LWtleS5wZW0nLCAneDUwOS9jbGllbnQucGVtJywgJ3JhbmtpbmcuanNv'
    'bicsICdyZWNhbGlicmF0ZScsICdldmVudHMuanNvbicsICdzdXBwb3J0LXByZXZpZXcuanNvbicpOgogICAgICAgIChST09U'
    'L25hbWUpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3cml0ZShST09ULyd0b2tlbicsIHRva2VuKQogICAgc3luY19k'
    'ZXZpY2VfbmFtZSgpCiAgICBzdGFnZSgnb2ZmJywgJ9Ci0L7QutC10L0g0YHQvtGF0YDQsNC90ZHQvS4g0J3QsNC20LzQuNGC'
    '0LUgwqvQn9C+0LTQutC70Y7Rh9C40YLRjMK7LicsIDAsIGFjdGl2ZT1GYWxzZSwgbWV0cmljcz17fSkKCgpkZWYgcGFuaWNf'
    'ZW5hYmxlZCgpOgogICAgdHJ5OnJldHVybiBqc29uLmxvYWRzKChST09ULydwYW5pYy5qc29uJykucmVhZF90ZXh0KCkpLmdl'
    'dCgnZW5hYmxlZCcpIGlzIFRydWUKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLEF0dHJpYnV0ZUVycm9yKTpyZXR1'
    'cm4gRmFsc2UKCgpkZWYgc2V0X3BhbmljKGVuYWJsZWQpOgogICAgaWYgdHlwZShlbmFibGVkKSBpcyBub3QgYm9vbDpyYWlz'
    'ZSBWYWx1ZUVycm9yKCdwYW5pYyBleHBlY3RzIGEgYm9vbGVhbicpCiAgICB3cml0ZShST09ULydwYW5pYy5qc29uJyxqc29u'
    'LmR1bXBzKHsnZW5hYmxlZCc6ZW5hYmxlZH0pKQogICAgaWYgZW5hYmxlZDoKICAgICAgICBjb25uZWN0KHJlc3RhcnQ9VHJ1'
    'ZSkKICAgIGVsc2U6CiAgICAgICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2Rpc2FibGUnLFVOSVRdLGNoZWNrPUZhbHNlKQog'
    'ICAgICAgIGlmIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdpcy1hY3RpdmUnLCctLXF1aWV0JyxVTklUXSxjaGVjaz1GYWxzZSku'
    'cmV0dXJuY29kZT09MDoKICAgICAgICAgICAgY29ubmVjdChyZXN0YXJ0PVRydWUpCgoKZGVmIHJlY292ZXJ5X3BhdXNlKHNl'
    'Y29uZHMpOgogICAgIyBLZWVwIFNJR1RFUk0gcmVzcG9uc2l2ZSBldmVuIGR1cmluZyBhbiBpbmRlZmluaXRlbHkgbG9uZyBv'
    'dXRhZ2UuCiAgICBmb3IgXyBpbiByYW5nZShpbnQoc2Vjb25kcyoxMCkpOgogICAgICAgIGlmIFNUT1A6cmV0dXJuCiAgICAg'
    'ICAgdGltZS5zbGVlcCguMSkKCgpkZWYgcmVjb3Zlcnlfcm91dGUocmFuayxjdXJyZW50LHNlbGVjdGVkLHBhbmljPUZhbHNl'
    'KToKICAgIGlmIHBhbmljIG9yIHNlbGVjdGVkPT0nYXV0byc6CiAgICAgICAgcmV0dXJuIHJhbmsubmV4dF9hZnRlcihjdXJy'
    'ZW50KSBvciBuZXh0KGl0ZXIocmFuay5jYW5kaWRhdGVzKCkpLE5vbmUpCiAgICByZXR1cm4gY3VycmVudAoKCmRlZiBjb25u'
    'ZWN0KHRva2VuPScnLCByZXBhaXI9RmFsc2UsIHJlc3RhcnQ9RmFsc2UpOgogICAgUk9PVC5ta2Rpcihtb2RlPTBvNzAwLCBw'
    'YXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBpZiB0b2tlbjoKICAgICAgICBzYXZlX3Rva2VuKHRva2VuKQogICAg'
    'aWYgbm90IHRva2VuX3N0YXR1cygpWydoYXNfdG9rZW4nXToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCfQktCy0LXQtNC4'
    '0YLQtSDQuCDQv9C+0LTRgtCy0LXRgNC00LjRgtC1INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAuJykKICAgIGVuc3VyZV9k'
    'ZXBlbmRlbmNpZXMoKQogICAgaWYgcmVwYWlyOgogICAgICAgIHdyaXRlKFJPT1QvJ3JlY2FsaWJyYXRlJywgJzEnKQogICAg'
    'cGFuaWM9cGFuaWNfZW5hYmxlZCgpCiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxsLWRl'
    'dmljZSBFc3RvbmlhIFZQTgpBZnRlcj1uZXR3b3JrLnRhcmdldApTdGFydExpbWl0SW50ZXJ2YWxTZWM9ezAgaWYgcGFuaWMg'
    'ZWxzZSAxODB9ClN0YXJ0TGltaXRCdXJzdD0zCltTZXJ2aWNlXQpUeXBlPXNpbXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9z'
    'YmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwKRXhlY1N0b3BQb3N0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwg'
    'aW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9bWl4ZWQKVU1hc2s9'
    'MDA3NwpNZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PXsnYWx3YXlzJyBpZiBwYW5pYyBlbHNlICdvbi1mYWlsdXJlJ30KUmVzdGFy'
    'dFNlYz17NSBpZiBwYW5pYyBlbHNlIDN9CltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAonJycKICAgIHdy'
    'aXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9VTklULCB1bml0KQogICAgcmVjb3ZlcnkgPSAiZXZnZW5pdW0tc3Rh'
    'cmZpdmUtdHVubmVsLXJlY292ZXIuc2VydmljZSIKICAgIHdyaXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0nKS9yZWNv'
    'dmVyeSwgIiIiW1VuaXRdCkRlc2NyaXB0aW9uPVJlY292ZXIgb25seSBpbnRlcnJ1cHRlZCBFdmdlbml1bSB0dW5uZWwgdGVz'
    'dCByZXNvdXJjZXMKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpBZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmst'
    'cHJlLnRhcmdldCB2cG4teHJheS5zZXJ2aWNlCltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKRXhlY1N0YXJ0PS91c3IvbG9jYWwv'
    'c2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVz'
    'ZXIudGFyZ2V0CiIiIikKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChb'
    'J3N5c3RlbWN0bCcsICdlbmFibGUnLCByZWNvdmVyeV0pCiAgICBpZiBwYW5pYzpjb21tYW5kKFsnc3lzdGVtY3RsJywnZW5h'
    'YmxlJyxVTklUXSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdyZXNldC1mYWlsZWQnLFVOSVRdLGNoZWNrPUZhbHNlKQog'
    'ICAgc3RhZ2UoJ3N0YXJ0aW5nJyAsICfQk9C+0YLQvtCy0LvRjiDQv9C+0LTQutC70Y7Rh9C10L3QuNC1INCyINCt0YHRgtC+'
    '0L3QuNGOLicsIDIsIGFjdGl2ZT1GYWxzZSwgcmV0cnk9MCwgZXJyb3JfY29kZT0nJykKICAgIGNvbW1hbmQoWydzeXN0ZW1j'
    'dGwnLCAncmVzdGFydCcgaWYgcmVwYWlyIG9yIHJlc3RhcnQgZWxzZSAnc3RhcnQnLCBVTklUXSkKICAgIHByaW50KCdWUE4g'
    '0LfQsNC/0YPRgdC60LDQtdGC0YHRjy4nLGZsdXNoPVRydWUpCgoKZGVmIGRpc2Nvbm5lY3QoKToKICAgIGNvbW1hbmQoWydz'
    'eXN0ZW1jdGwnLCdkaXNhYmxlJyxVTklUXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnc3RvcCcs'
    'IFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yNSkKICAgIGNsZWFudXAoKQogICAgY2xlYW51cF9mdWxsKHJlbGVhc2U9'
    'VHJ1ZSkKICAgIHN0YWdlKCdvZmYnLCAnVlBOINCy0YvQutC70Y7Rh9C10L0uJywgMCwgYWN0aXZlPUZhbHNlKQogICAgcHJp'
    'bnQoJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicpCgoKZGVmIHN0YXJ0X2RhZW1vbihlbnYpOgogICAgKFJVTlRJTUUvJ2NoYXJv'
    'bi52aWNpJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgIGxvZyA9IChST09ULydjaGFyb24ubG9nJykub3Blbigndycp'
    'CiAgICBkYWVtb24gPSBzdWJwcm9jZXNzLlBvcGVuKFsnaXAnLCAnbmV0bnMnLCAnZXhlYycsIE5TLCBjaGFyb25fYmluYXJ5'
    'KCldLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnY9ZW52LCBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsIHN0'
    'ZG91dD1sb2csIHN0ZGVycj1sb2cpCiAgICBsb2cuY2xvc2UoKQogICAgdHJ5OgogICAgICAgIGZvciBfIGluIHJhbmdlKDYw'
    'KToKICAgICAgICAgICAgaWYgU1RPUCBvciBkYWVtb24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgcmFp'
    'c2UgUnVudGltZUVycm9yKCdkYWVtb25fc3RvcHBlZCcpCiAgICAgICAgICAgIGlmIChSVU5USU1FLydjaGFyb24udmljaScp'
    'LmV4aXN0cygpIGFuZCBzd2FuKCctLXN0YXRzJywgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MSkucmV0dXJuY29kZSA9PSAwOgog'
    'ICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICBzd2FuKCctLWxvYWQtY3Jl'
    'ZHMnLCAnLS1ub3Byb21wdCcsICctLWZpbGUnLCBST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgICAgIHN3YW4oJy0tbG9h'
    'ZC1jb25ucycsICctLWZpbGUnLCBST09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgICAgIHJldHVybiBkYWVtb24KICAgIGV4'
    'Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgIHN0b3BfcHJvY2VzcyhkYWVtb24pCiAgICAgICAgcmFpc2UKCgpkZWYgc3Rv'
    'cF9wcm9jZXNzKHByb2Nlc3MpOgogICAgaWYgcHJvY2VzcyBpcyBub3QgTm9uZSBhbmQgcHJvY2Vzcy5wb2xsKCkgaXMgTm9u'
    'ZToKICAgICAgICBwcm9jZXNzLnRlcm1pbmF0ZSgpCiAgICAgICAgdHJ5OnByb2Nlc3Mud2FpdCh0aW1lb3V0PTUpCiAgICAg'
    'ICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6cHJvY2Vzcy5raWxsKCk7cHJvY2Vzcy53YWl0KHRpbWVvdXQ9'
    'MykKCgpkZWYgc3RvcF9jYW5kaWRhdGUoZGFlbW9uPU5vbmUpOgogICAgZ2xvYmFsIFRMU19QUk9DRVNTCiAgICBzdG9wX3By'
    'b2Nlc3MoZGFlbW9uKQogICAgc3RvcF9wcm9jZXNzKFRMU19QUk9DRVNTKTtUTFNfUFJPQ0VTUz1Ob25lCiAgICBjbGVhbnVw'
    'KCkKCgpkZWYgcHJlcGFyZV9kYXRhX3BsYW5lKGFkZHJlc3MpOgogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToK'
    'ICAgICAgICBpZiBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAgICAgIHJhaXNl'
    'IFJ1bnRpbWVFcnJvcignZnVsbF9pbnRlcmZhY2VfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0'
    'ZScsJ3Nob3cnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0'
    'ZScsJ3Nob3cnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAg'
    'cmFpc2UgUnVudGltZUVycm9yKCdhZG1pbl90YWJsZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGFueShyLmdldCgncHJpb3Jp'
    'dHknKSBpbiAoNzksODApIGZvciByIGluIGpzb24ubG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rk'
    'b3V0KSk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF9ydWxlX2NvbGxpc2lvbicpCiAgICAgICAgd3Jp'
    'dGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoeydhY3RpdmUnOkZhbHNlLCdtZWFzdXJlbWVudF9vbmx5JzpUcnVlfSkpCiAg'
    'ICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAgc3RhcnRfbmFtZXNwYWNlX2RucygpCgoKZGVmIHN0YXJ0X2NhbmRpZGF0'
    'ZShjYW5kaWRhdGUsaWRlbnRpdHkpOgogICAgZ2xvYmFsIEFDVElWRSxUTFNfUFJPQ0VTUwogICAgQUNUSVZFPWNhbmRpZGF0'
    'ZQogICAgd3JpdGUoUk9PVC8nYWN0aXZlLXBhdGguanNvbicsanNvbi5kdW1wcyh7J2lkJzpjYW5kaWRhdGVbJ2lkJ119KSkK'
    'ICAgIHNldHVwX25ldHdvcmsoKQogICAgZGFlbW9uX2NvbmZpZ3MoaWRlbnRpdHksY2FuZGlkYXRlWydhZGRyZXNzJ10pCiAg'
    'ICBpZiBjYW5kaWRhdGVbJ3RscyddIG9yIGNhbmRpZGF0ZS5nZXQoJ2V2Z3QnKToKICAgICAgICBpZiBjYW5kaWRhdGUuZ2V0'
    'KCdldmd0Jyk6CiAgICAgICAgICAgIGJpbmFyeT1lbnN1cmVfZXZndF9iaW5hcnkoKQogICAgICAgICAgICBjYXJyaWVyPVtz'
    'dHIoYmluYXJ5KSwnLW1vZGUnLCdjbGllbnQnLCctc2VydmVyJyxjYW5kaWRhdGUuZ2V0KCd0cmFuc3BvcnRfYWRkcmVzcycs'
    'Y2FuZGlkYXRlWydhZGRyZXNzJ10pKyc6JytzdHIoY2FuZGlkYXRlLmdldCgndHJhbnNwb3J0X3BvcnQnLDI0NTc4KSksJy1z'
    'ZXJ2ZXItbmFtZScsY2FuZGlkYXRlWydpZGVudGl0eSddLAogICAgICAgICAgICAgICAgICAgICAnLXVkcC1saXN0ZW4nLCcx'
    'MjcuMC4wLjE6MjQ1NzMnLCctdWRwLXBlZXInLENMSUVOVCsnOjQ1MDAnLAogICAgICAgICAgICAgICAgICAgICAnLWNhJyxz'
    'dHIoUk9PVC8nY2EucGVtJyksJy1jZXJ0JyxzdHIoUk9PVC8nY2xpZW50LnBlbScpLCcta2V5JyxzdHIoUk9PVC8nY2xpZW50'
    'LWtleS5wZW0nKV0KICAgICAgICBlbHNlOmNhcnJpZXI9WycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwtdGxz'
    'LWNsaWVudCddCiAgICAgICAgVExTX1BST0NFU1M9c3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywnbmV0bnMnLCdleGVjJyxOUywq'
    'Y2Fycmllcl0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEws'
    'c3Rkb3V0PXN1YnByb2Nlc3MuREVWTlVMTCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZGVycj1O'
    'b25lIGlmIGNhbmRpZGF0ZS5nZXQoJ2V2Z3QnKSBlbHNlIHN1YnByb2Nlc3MuREVWTlVMTCkKICAgICAgICBmb3IgXyBpbiBy'
    'YW5nZSg1MCk6CiAgICAgICAgICAgIGlmIFNUT1A6cmFpc2UgUnVudGltZUVycm9yKCdjYW5jZWxsZWQnKQogICAgICAgICAg'
    'ICBpZiBUTFNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6cmFpc2UgUnVudGltZUVycm9yKCd0bHNfY2Fycmllcl9zdG9w'
    'cGVkJykKICAgICAgICAgICAgaWYgJzEyNy4wLjAuMToyNDU3MycgaW4gaW5zaWRlKFsnc3MnLCctYW51J10sY2hlY2s9RmFs'
    'c2UpLnN0ZG91dDpicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgICAgIGVsc2U6cmFpc2UgUnVudGltZUVy'
    'cm9yKCd0bHNfY2Fycmllcl9ub3RfcmVhZHknKQogICAgICAgIGluc2lkZShbJ25mdCcsJy1mJywnLSddLGRhdGE9J3RhYmxl'
    'IGlwIGV2bl90bHNfY2FycmllciB7XG4gY2hhaW4gb3V0cHV0IHtcbiB0eXBlIG5hdCBob29rIG91dHB1dCBwcmlvcml0eSBk'
    'c3RuYXQ7IHBvbGljeSBhY2NlcHQ7XG4gaXAgZGFkZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIHJlZGlyZWN0IHRv'
    'IDoyNDU3M1xuIH1cbn1cbicpCiAgICBlbnY9eyoqb3MuZW52aXJvbiwnU1RST05HU1dBTl9DT05GJzpzdHIoUk9PVC8nc3Ry'
    'b25nc3dhbi5jb25mJyl9O2Vudi5wb3AoJ05PVElGWV9TT0NLRVQnLE5vbmUpCiAgICBkYWVtb249c3RhcnRfZGFlbW9uKGVu'
    'dikKICAgIHRyeToKICAgICAgICBzd2FuKCctLWluaXRpYXRlJywnLS1jaGlsZCcsJ3N0YXJmaXZlLW5ldCcsdGltZW91dD0z'
    'NSkKICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVkJykKICAgICAgICBpZiBub3QgaW5zdGFs'
    'bGVkKCk6cmFpc2UgUnVudGltZUVycm9yKCdoYW5kc2hha2VfZmFpbGVkJykKICAgICAgICBwcmVwYXJlX2RhdGFfcGxhbmUo'
    'Y2FuZGlkYXRlWydhZGRyZXNzJ10pCiAgICAgICAgaWYgbm90IGVncmVzc19oZWFsdGgoKTpyYWlzZSBSdW50aW1lRXJyb3Io'
    'J2VzdG9uaWFfZWdyZXNzX2ZhaWxlZCcpCiAgICAgICAgcmV0dXJuIGRhZW1vbgogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246'
    'CiAgICAgICAgc3RvcF9wcm9jZXNzKGRhZW1vbik7cmFpc2UKCgpkZWYgc3BlZWRfc2FtcGxlKHNpemU9MjA5NzE1Mik6CiAg'
    'ICAiIiJCb3VuZGVkIHN5bnRoZXRpYyBiaWRpcmVjdGlvbmFsIHByb2JlOyBuZXZlciByZWFkcyB1c2VyIGZpbGVzLiIiIgog'
    'ICAgcGF5bG9hZD1ST09ULydzcGVlZC1wYXlsb2FkLmJpbicKICAgIGlmIG5vdCBwYXlsb2FkLmV4aXN0cygpIG9yIHBheWxv'
    'YWQuc3RhdCgpLnN0X3NpemUhPXNpemU6CiAgICAgICAgd2l0aCBwYXlsb2FkLm9wZW4oJ3diJykgYXMgZjoKICAgICAgICAg'
    'ICAgZm9yIF8gaW4gcmFuZ2Uoc2l6ZS8vNjU1MzYpOmYud3JpdGUoc2VjcmV0cy50b2tlbl9ieXRlcyg2NTUzNikpCiAgICAg'
    'ICAgcGF5bG9hZC5jaG1vZCgwbzYwMCkKICAgIGJhc2U9WydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywn'
    'LS1zaWxlbnQnLCctLXNob3ctZXJyb3InLCctLWNvbm5lY3QtdGltZW91dCcsJzMnLCctLW1heC10aW1lJywnMTInLAogICAg'
    'ICAgICAgJy0tb3V0cHV0JywnL2Rldi9udWxsJywnLS13cml0ZS1vdXQnLCcle2h0dHBfY29kZX0gJXtzaXplX2Rvd25sb2Fk'
    'fSAle3NpemVfdXBsb2FkfSAle3RpbWVfdG90YWx9ICV7dGltZV9jb25uZWN0fSddCiAgICByZXN1bHRzPVtdCiAgICBmb3Ig'
    'ZGlyZWN0aW9uIGluICgnZG93bicsJ3VwJyk6CiAgICAgICAgaWYgU1RPUDpyYWlzZSBSdW50aW1lRXJyb3IoJ2NhbmNlbGxl'
    'ZCcpCiAgICAgICAgZXh0cmE9WydodHRwczovL3NwZWVkLmNsb3VkZmxhcmUuY29tL19fZG93bj9ieXRlcz0nK3N0cihzaXpl'
    'KV0gaWYgZGlyZWN0aW9uPT0nZG93bicgZWxzZSBbJy0tZGF0YS1iaW5hcnknLCdAJytzdHIocGF5bG9hZCksJ2h0dHBzOi8v'
    'c3BlZWQuY2xvdWRmbGFyZS5jb20vX191cCddCiAgICAgICAgcj1pbnNpZGUoYmFzZStleHRyYSx0aW1lb3V0PTE0LGNoZWNr'
    'PUZhbHNlKQogICAgICAgIHRyeToKICAgICAgICAgICAgY29kZSxkb3duLHVwLGVsYXBzZWQsbGF0ZW5jeT1yLnN0ZG91dC5z'
    'cGxpdCgpCiAgICAgICAgICAgIGNvdW50PWZsb2F0KGRvd24gaWYgZGlyZWN0aW9uPT0nZG93bicgZWxzZSB1cCkKICAgICAg'
    'ICAgICAgaWYgci5yZXR1cm5jb2RlIG9yIGNvZGUhPScyMDAnIG9yIGNvdW50PHNpemU6cmFpc2UgVmFsdWVFcnJvcigpCiAg'
    'ICAgICAgICAgIHJlc3VsdHMuYXBwZW5kKChjb3VudCo4L21heCguMDAxLGZsb2F0KGVsYXBzZWQpKS8xZTYsZmxvYXQobGF0'
    'ZW5jeSkqMTAwMCkpCiAgICAgICAgZXhjZXB0IChWYWx1ZUVycm9yLFR5cGVFcnJvcik6cmV0dXJuIHsnYXZhaWxhYmxlJzpG'
    'YWxzZX0KICAgIHJldHVybiB7J2F2YWlsYWJsZSc6VHJ1ZSwnZG93bmxvYWRfbWJwcyc6cm91bmQocmVzdWx0c1swXVswXSwy'
    'KSwndXBsb2FkX21icHMnOnJvdW5kKHJlc3VsdHNbMV1bMF0sMiksCiAgICAgICAgICAgICdsYXRlbmN5X21zJzpyb3VuZCht'
    'YXgoeFsxXSBmb3IgeCBpbiByZXN1bHRzKSwxKSwnc2FtcGxlX2J5dGVzJzpzaXplfQoKCmRlZiB0cmFmZmljX3RvdGFsKCk6'
    'CiAgICB0cnk6CiAgICAgICAgc3RhdHM9UGF0aCgnL3N5cy9jbGFzcy9uZXQnKS9GVUxMX0hPU1QvJ3N0YXRpc3RpY3MnCiAg'
    'ICAgICAgcmV0dXJuIHN1bShpbnQoKHN0YXRzL25hbWUpLnJlYWRfdGV4dCgpKSBmb3IgbmFtZSBpbiAoJ3J4X2J5dGVzJywn'
    'dHhfYnl0ZXMnKSkKICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTpyZXR1cm4gMAoKCmRlZiBzcGVlZF9kZWdyYWRl'
    'ZChzYW1wbGUsYmFzZWxpbmUpOgogICAgIyBSZXF1aXJlIHVzYWJsZSBzYW1wbGVzIGFuZCBhIG1lYW5pbmdmdWwgYmFzZWxp'
    'bmUgaW4gdGhlIGFmZmVjdGVkIGRpcmVjdGlvbi4KICAgIHJldHVybiBib29sKHNhbXBsZS5nZXQoJ2F2YWlsYWJsZScpIGFu'
    'ZCBhbnkoCiAgICAgICAgYmFzZWxpbmUuZ2V0KGssMCk+PTIgYW5kIHNhbXBsZS5nZXQoaywwKTxiYXNlbGluZVtrXSouMgog'
    'ICAgICAgIGZvciBrIGluICgnZG93bmxvYWRfbWJwcycsJ3VwbG9hZF9tYnBzJykpKQoKCmRlZiB3b3JrZXIoKToKICAgIGds'
    'b2JhbCBTVE9QCiAgICBTVE9QPUZhbHNlCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLGxhbWJkYSAqXzpnbG9i'
    'YWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLFRydWUpKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULGxhbWJkYSAq'
    'XzpnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLFRydWUpKQogICAgYXR0ZW1wdHM9MAogICAgd2hpbGUgbm90IFNUT1A6'
    'CiAgICAgICAgd29ya2VyX29uY2UoKQogICAgICAgIGlmIFNUT1Agb3Igbm90IHBhbmljX2VuYWJsZWQoKTpyZXR1cm4KICAg'
    'ICAgICBhdHRlbXB0cys9MQogICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9Cw0L3QuNGH0LXRgdC60LjQuSDQv9C+0LjR'
    'gdC6OiDQv9C+0LLRgtC+0YDRj9GOINC/0L7QtNCz0L7RgtC+0LLQutGDIFZQTi4nLDUsCiAgICAgICAgICAgICAgYWN0aXZl'
    'PUZhbHNlLHJldHJ5PWF0dGVtcHRzKQogICAgICAgIHJlY292ZXJ5X3BhdXNlKG1pbigzMCw1KmF0dGVtcHRzKSkKCgpkZWYg'
    'd29ya2VyX29uY2UoKToKICAgIGRhZW1vbj1Ob25lCiAgICByYW5rPXJhbmtfYXBpLlJhbmtpbmcoUk9PVC8ncmFua2luZy5q'
    'c29uJyxbeFsnaWQnXSBmb3IgeCBpbiBDQU5ESURBVEVTXSkKICAgIHRyeToKICAgICAgICBjbGVhbnVwKCk7cmVmcmVzaF9y'
    'ZXRhaW5lZF9ndWFyZCgpCiAgICAgICAgc3RhZ2UoJ3ByZXBhcmUnLCfQk9C+0YLQvtCy0LvRjiDQt9Cw0YnQuNGJ0ZHQvdC9'
    '0YvQtSDQvNCw0YDRiNGA0YPRgtGLLicsNSxhY3RpdmU9RmFsc2UsbWV0cmljcz17fSxlcnJvcl9jb2RlPScnLHNjb3BlPSdz'
    'ZWxlY3RlZCcgaWYgcG9saWN5IGlzIG5vdCBOb25lIGFuZCBwb2xpY3kuaW5jbHVzaXZlKHBvbGljeS5sb2FkKCkpIGVsc2Ug'
    'J2Z1bGwtZGV2aWNlJykKICAgICAgICBzZXR1cF9uZXR3b3JrKCkKICAgICAgICBpZGVudGl0eSxfPWVucm9sbCgpCiAgICAg'
    'ICAgc3luY19kZXZpY2VfbmFtZSgpCiAgICAgICAgY2xlYW51cCgpCiAgICAgICAgbG9hZGVkPXJhbmsubG9hZCgpCiAgICAg'
    'ICAgc2VsZWN0ZWQ9c2VsZWN0ZWRfcm91dGUoKQogICAgICAgIHJlYnVpbGQ9KFJPT1QvJ3JlY2FsaWJyYXRlJykuZXhpc3Rz'
    'KCkgb3IgKHNlbGVjdGVkPT0nYXV0bycgYW5kIG5vdCBsb2FkZWQpCiAgICAgICAgaWYgbm90IGxvYWRlZDpyYW5rLmJvb3Rz'
    'dHJhcCgpCiAgICAgICAgaWYgcmVidWlsZCBhbmQgbm90IHBhbmljX2VuYWJsZWQoKToKICAgICAgICAgICAgbWVhc3VyZW1l'
    'bnRzPXt9CiAgICAgICAgICAgIGZvciBpLGNhbmRpZGF0ZSBpbiBlbnVtZXJhdGUoQ0FORElEQVRFUyk6CiAgICAgICAgICAg'
    'ICAgICBpZiBTVE9QOnJldHVybgogICAgICAgICAgICAgICAgc3RhZ2UoJ3JhbmtpbmcnLCfQn9GA0L7QstC10YDRj9GOINC8'
    '0LDRgNGI0YDRg9GCOiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSwxMCtpbnQoaSo2MC9sZW4oQ0FORElEQVRFUykpLGFjdGl2ZT1G'
    'YWxzZSxwYXRoPWNhbmRpZGF0ZVsnaWQnXSkKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBkYWVt'
    'b249c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVudGl0eSkKICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGludGVncml0eT1kb3dubG9hZCgxMDQ4NTc2KVsnaW50ZWdyaXR5J10KICAgICAgICAgICAgICAg'
    'ICAgICBleGNlcHQgUnVudGltZUVycm9yIGFzIGVycm9yOgogICAgICAgICAgICAgICAgICAgICAgICBpZiBzdHIoZXJyb3Ip'
    'PT0naW50ZWdyaXR5X2ZhaWxlZCc6cmFpc2UKICAgICAgICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PU5vbmUKICAgICAg'
    'ICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PU5vbmUKICAgICAgICAgICAgICAgICAgICBtZWFzdXJlbWVudHNbY2Fu'
    'ZGlkYXRlWydpZCddXT17J29rJzpUcnVlLCoqc3BlZWRfc2FtcGxlKDIwOTcxNTIpLCdpbnRlZ3JpdHknOmludGVncml0eX0K'
    'ICAgICAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVv'
    'dXRFeHBpcmVkKToKICAgICAgICAgICAgICAgICAgICBpZiBTVE9QOnJldHVybgogICAgICAgICAgICAgICAgICAgIG1lYXN1'
    'cmVtZW50c1tjYW5kaWRhdGVbJ2lkJ11dPXsnb2snOkZhbHNlfQogICAgICAgICAgICAgICAgZmluYWxseToKICAgICAgICAg'
    'ICAgICAgICAgICBzdG9wX2NhbmRpZGF0ZShkYWVtb24pO2RhZW1vbj1Ob25lCiAgICAgICAgICAgIHJhbmsuYnVpbGQobWVh'
    'c3VyZW1lbnRzKQogICAgICAgICAgICAoUk9PVC8ncmVjYWxpYnJhdGUnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAg'
    'ICAgIGNhbmRpZGF0ZXM9e3hbJ2lkJ106eCBmb3IgeCBpbiBDQU5ESURBVEVTfQogICAgICAgIGN1cnJlbnQ9c2VsZWN0ZWQg'
    'aWYgc2VsZWN0ZWQhPSdhdXRvJyBlbHNlIG5leHQoaXRlcihyYW5rLmNhbmRpZGF0ZXMoKSksTm9uZSkKICAgICAgICB3aGls'
    'ZSBjdXJyZW50IGFuZCBub3QgU1RPUDoKICAgICAgICAgICAgY2FuZGlkYXRlPWNhbmRpZGF0ZXNbY3VycmVudF0KICAgICAg'
    'ICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc3RhZ2UoJ2hhbmRzaGFrZScsJ9Cf0L7QtNC60LvRjtGH0LDRjjogJytjYW5k'
    'aWRhdGVbJ2xhYmVsJ10sNzUsYWN0aXZlPUZhbHNlLHBhdGg9Y3VycmVudCkKICAgICAgICAgICAgICAgIGRhZW1vbj1zdGFy'
    'dF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KQogICAgICAgICAgICAgICAgc3RhZ2UoJ3JvdXRpbmcnLCfQn9C+0LTQ'
    'utC70Y7Rh9Cw0Y4g0YLRgNCw0YTQuNC6INC6INC/0YDQvtCy0LXRgNC10L3QvdC+0LzRgyDQvNCw0YDRiNGA0YPRgtGDLics'
    'OTIpCiAgICAgICAgICAgICAgICBhY3RpdmF0ZV9mdWxsKGNhbmRpZGF0ZVsnYWRkcmVzcyddKQogICAgICAgICAgICAgICAg'
    'c3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH0LXQvdC+OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFj'
    'dGl2ZT1UcnVlLHBhdGg9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICAgIG1ldHJpY3M9cmFuay5kYXRhWydlbnRyaWVz'
    'J11bY3VycmVudF0sc2luY2U9aW50KHRpbWUudGltZSgpKSxlcnJvcl9jb2RlPScnKQogICAgICAgICAgICAgICAgZmFpbHVy'
    'ZXM9MDtzbG93PTA7bGFzdF90cmFmZmljPXRyYWZmaWNfdG90YWwoKTtuZXh0X3NwZWVkPXRpbWUubW9ub3RvbmljKCkrNjAw'
    'K3NlY3JldHMucmFuZGJlbG93KDYwKQogICAgICAgICAgICAgICAgd2hpbGUgbm90IFNUT1A6CiAgICAgICAgICAgICAgICAg'
    'ICAgZm9yIF8gaW4gcmFuZ2UoMjAgaWYgcGFuaWNfZW5hYmxlZCgpIGVsc2UgNTApOgogICAgICAgICAgICAgICAgICAgICAg'
    'ICBpZiBTVE9QOmJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgICAgICAgICAg'
    'ICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAgaWYgcG9s'
    'aWN5IGlzIG5vdCBOb25lOnBvbGljeS5lbnN1cmVfcm91dGUoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBETlNfUFJP'
    'Q0VTUyBpcyBOb25lIG9yIEROU19QUk9DRVNTLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9C10YDQtdC30LDQv9GD0YHQutCw0Y4g0LfQsNGJ0LjRidGR0L3QvdGL0LkgRE5T'
    'LicsOTAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9J3ByaXZhdGVfZG5zX3N0b3BwZWQnKQogICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgc3RhcnRfbmFtZXNwYWNlX2RucygpCiAgICAgICAgICAgICAgICAgICAgICAgIGhlYWx0aHk9cGF0aF9oZWFs'
    'dGh5KGRhZW1vbikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaGVhbHRoeSBhbmQgbm90IHJlY292ZXJfc3lzdGVtX2Ru'
    'cygpOnJhaXNlIFJ1bnRpbWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgICAgICAgICAgICAgICAgIGV4Y2VwdCAo'
    'T1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKTpoZWFsdGh5PUZhbHNl'
    'CiAgICAgICAgICAgICAgICAgICAgZmFpbHVyZXM9MCBpZiBoZWFsdGh5IGVsc2UgZmFpbHVyZXMrMQogICAgICAgICAgICAg'
    'ICAgICAgIGlmIGZhaWx1cmVzPj0yOnJhaXNlIFJ1bnRpbWVFcnJvcigncGF0aF9oZWFsdGhfZmFpbGVkJykKICAgICAgICAg'
    'ICAgICAgICAgICBpZiBub3QgaGVhbHRoeToKICAgICAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2NoZWNraW5nJywn0J7R'
    'gtCy0LXRgiDQt9Cw0LTQtdGA0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgtC10LrRg9GJ0LjQuSDQvNCw'
    '0YDRiNGA0YPRgi4nLDkwLGFjdGl2ZT1GYWxzZSkKICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAg'
    'ICAgICAgICAgICBpZiB0aW1lLm1vbm90b25pYygpPj1uZXh0X3NwZWVkOgogICAgICAgICAgICAgICAgICAgICAgICB0cmFm'
    'ZmljPXRyYWZmaWNfdG90YWwoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qgc2xvdyBhbmQgdHJhZmZpYy1sYXN0'
    'X3RyYWZmaWM8NDE5NDMwNDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhc3RfdHJhZmZpYz10cmFmZmljO25leHRf'
    'c3BlZWQ9dGltZS5tb25vdG9uaWMoKSs2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApCiAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYwogICAgICAgICAgICAg'
    'ICAgICAgICAgICBzYW1wbGU9c3BlZWRfc2FtcGxlKDIwOTcxNTIpO2Jhc2VsaW5lPXJhbmsuZGF0YVsnZW50cmllcyddW2N1'
    'cnJlbnRdCiAgICAgICAgICAgICAgICAgICAgICAgIGRlZ3JhZGVkPXNwZWVkX2RlZ3JhZGVkKHNhbXBsZSxiYXNlbGluZSkK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgc2xvdz1zbG93KzEgaWYgZGVncmFkZWQgZWxzZSAwCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgIG5leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSsoMjAgaWYgc2xvdyBlbHNlIDYwMCtzZWNyZXRzLnJhbmRiZWxv'
    'dyg2MCkpCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHNsb3c+PTM6cmFpc2UgUnVudGltZUVycm9yKCdjb25maXJtZWRf'
    'c3BlZWRfZHJvcCcpCiAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH0LXQvdC+'
    'OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCxlcnJvcl9jb2RlPScnKQog'
    'ICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhw'
    'aXJlZCkgYXMgZXhjOgogICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgcmVhc29uPXN0cihl'
    'eGMpIGlmIHJlLmZ1bGxtYXRjaCgnW2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlvbl9mYWlsZWQnCiAg'
    'ICAgICAgICAgICAgICAjIEEgbWlzc2luZyBwaHlzaWNhbCBpbnRlcmZhY2UgaXMgbm90IGEgdHJhbnNwb3J0J3MgZGVmZWF0'
    'LgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIHJvdXRlPXBoeXNpY2FsX3JvdXRlKCk7Y2Fycmll'
    'cj1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL3JvdXRlWydkZXYnXS8nY2FycmllcicKICAgICAgICAgICAgICAgICAgICBvZmZs'
    'aW5lPWNhcnJpZXIuZXhpc3RzKCkgYW5kIGNhcnJpZXIucmVhZF90ZXh0KCkuc3RyaXAoKT09JzAnCiAgICAgICAgICAgICAg'
    'ICBleGNlcHQgKE9TRXJyb3IsUnVudGltZUVycm9yKTpvZmZsaW5lPVRydWUKICAgICAgICAgICAgICAgIGlmIG5vdCBvZmZs'
    'aW5lOgogICAgICAgICAgICAgICAgICAgIGN1cnJlbnQ9cmVjb3Zlcnlfcm91dGUocmFuayxjdXJyZW50LHNlbGVjdGVkLHBh'
    'bmljX2VuYWJsZWQoKSkKICAgICAgICAgICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQodCy0Y/Qt9GMINC/0L7RgtC10YDR'
    'j9C90LAuINCf0LXRgNC10LrQu9GO0YfQsNGOINC30LDRidC40YnRkdC90L3Ri9C5INC80LDRgNGI0YDRg9GCLicgaWYgbm90'
    'IG9mZmxpbmUgZWxzZSAn0J7QttC40LTQsNGOINCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40Y8g0YTQuNC30LjRh9C10YHQ'
    'utC+0Lkg0YHQtdGC0LguJyw2NSwKICAgICAgICAgICAgICAgICAgICAgIGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPXJlYXNv'
    'bikKICAgICAgICAgICAgICAgIHJlY292ZXJ5X3BhdXNlKCgxIGlmIG5vdCBvZmZsaW5lIGVsc2UgMykgaWYgcGFuaWNfZW5h'
    'YmxlZCgpIGVsc2UgKDMgaWYgbm90IG9mZmxpbmUgZWxzZSAxMCkpCiAgICAgICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAg'
    'ICAgICBzdG9wX2NhbmRpZGF0ZShkYWVtb24pO2RhZW1vbj1Ob25lCiAgICAgICAgaWYgbm90IFNUT1A6CiAgICAgICAgICAg'
    'IHN0YWdlKCdmYWlsZWQnLCfQndC10YIg0L3QsNGB0YLRgNC+0LXQvdC90YvRhSDQvNCw0YDRiNGA0YPRgtC+0LIuJywwLAog'
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
    'ZGRyIHt0dW5uZWwuU0VSVkVSfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7dHVubmVsLkhPU1R9IiBpcCBk'
    'YWRkciB7dHVubmVsLkNMSUVOVH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKICBpaWZuYW1lICJ3YXlk'
    'cm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbWFyayB7RElSRUNUfSBhY2NlcHQKICBvaWZuYW1lICJ3YXlkcm9pZDAi'
    'IG1ldGEgbmZwcm90byBpcHY0IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlw'
    'djQgb2lmbmFtZSAie1RVTn0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgIntUVU59IiBjdCBzdGF0ZSBl'
    'c3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgInt0dW5uZWwuRlVMTF9IT1NU'
    'fSIgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgaWlmbmFtZSAie3R1bm5lbC5GVUxMX0hPU1R9IiBjdCBzdGF0ZSBlc3Rh'
    'Ymxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKClVOSVQ9JycnW1VuaXRdCkRlc2NyaXB0aW9uPUV2Z2VuaXVtIGxv'
    'Y2FsIGFwcGxpY2F0aW9uIGFuZCBkb21haW4gcm91dGluZwpBZnRlcj1uZXR3b3JrLnRhcmdldApXYW50cz1ldmdlbml1bS13'
    'YXlkcm9pZC1uZXR3b3JrLnNlcnZpY2UKW1NlcnZpY2VdClVzZXI9dnBuLXhyYXkKR3JvdXA9dnBuLXhyYXkKRXhlY1N0YXJ0'
    'PS9vcHQvdnBuLW1hbmFnZXIvYmluL3hyYXkgcnVuIC1jb25maWcgL3J1bi92cG4tbWFuYWdlci9wb2xpY3kuanNvbgpSZXN0'
    'YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0yCkFtYmllbnRDYXBhYmlsaXRpZXM9Q0FQX05FVF9BRE1JTiBDQVBfTkVUX1JB'
    'VyBDQVBfU1lTX1BUUkFDRSBDQVBfREFDX1JFQURfU0VBUkNICkNhcGFiaWxpdHlCb3VuZGluZ1NldD1DQVBfTkVUX0FETUlO'
    'IENBUF9ORVRfUkFXIENBUF9TWVNfUFRSQUNFIENBUF9EQUNfUkVBRF9TRUFSQ0gKTm9OZXdQcml2aWxlZ2VzPXRydWUKUHJv'
    'dGVjdFN5c3RlbT1zdHJpY3QKUHJvdGVjdEhvbWU9dHJ1ZQpQcml2YXRlVG1wPXRydWUKRGV2aWNlQWxsb3c9L2Rldi9uZXQv'
    'dHVuIHJ3ClVNYXNrPTAwNzcKJycnCgpXQVlEUk9JRF9VTklUPScnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBXYXlk'
    'cm9pZCBuZXR3b3JrIGxpZmVjeWNsZQpBZnRlcj1ldmdlbml1bS1wb2xpY3kuc2VydmljZQpQYXJ0T2Y9ZXZnZW5pdW0tcG9s'
    'aWN5LnNlcnZpY2UKW1NlcnZpY2VdCkV4ZWNTdGFydD0vdXNyL2xvY2FsL3NiaW4vdnBuY3RsIGludGVybmFsLXdheWRyb2lk'
    'LXdhdGNoClJlc3RhcnQ9b24tZmFpbHVyZQpSZXN0YXJ0U2VjPTIKVU1hc2s9MDA3NwonJycKCmRlZiB3YXlkcm9pZF9uZXR3'
    'b3JrKCk6CiByZXN1bHQ9dHVubmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdhZGRyJywnc2hvdycsJ2RldicsJ3dheWRy'
    'b2lkMCddLGNoZWNrPUZhbHNlKQogaWYgcmVzdWx0LnJldHVybmNvZGU6cmV0dXJuIHsnaW5kZXgnOk5vbmUsJ25ldHdvcmtz'
    'JzpbXX0KIGxpbmtzPWpzb24ubG9hZHMocmVzdWx0LnN0ZG91dCkKIG5ldHdvcmtzPXNvcnRlZCh7c3RyKGlwYWRkcmVzcy5p'
    'cF9uZXR3b3JrKGYie2FbJ2xvY2FsJ119L3thWydwcmVmaXhsZW4nXX0iLHN0cmljdD1GYWxzZSkpIGZvciBsaW5rIGluIGxp'
    'bmtzIGlmICdVUCcgaW4gbGluay5nZXQoJ2ZsYWdzJyxbXSkgZm9yIGEgaW4gbGluay5nZXQoJ2FkZHJfaW5mbycsW10pIGlm'
    'IGEuZ2V0KCdzY29wZScpPT0nZ2xvYmFsJ30pCiByZXR1cm4geydpbmRleCc6bGlua3NbMF0uZ2V0KCdpZmluZGV4JykgaWYg'
    'bGlua3MgZWxzZSBOb25lLCduZXR3b3Jrcyc6bmV0d29ya3N9CgpkZWYgc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPUZh'
    'bHNlKToKICMgQ2FsbGVyIGhvbGRzIG9wZXJhdGlvbi5sb2NrLiBPbmx5IHRoaXMgVlBOJ3Mgc2V0L3RhYmxlIGFyZSBtb2Rp'
    'ZmllZC4KIHN0YXRlPXdheWRyb2lkX25ldHdvcmsoKTtjYWNoZT1SVU4vJ3dheWRyb2lkLW5ldHdvcmsuanNvbicKIHRyeTpw'
    'cmV2aW91cz1qc29uLmxvYWRzKGNhY2hlLnJlYWRfdGV4dCgpKQogZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IpOnByZXZp'
    'b3VzPU5vbmUKIGlmIG5vdCBmb3JjZSBhbmQgc3RhdGU9PXByZXZpb3VzOnJldHVybgogcm91dGVzPWpzb24ubG9hZHModHVu'
    'bmVsLmNvbW1hbmQoWydpcCcsJy1qJywnLTQnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKS5zdGRv'
    'dXQpCiBzdGFsZT17clsnZHN0J10gZm9yIHIgaW4gcm91dGVzIGlmIHIuZ2V0KCdkZXYnKT09J3dheWRyb2lkMCcgYW5kIHIu'
    'Z2V0KCdkc3QnKSBub3QgaW4gc3RhdGVbJ25ldHdvcmtzJ119CiBmb3IgbmV0d29yayBpbiBzdGF0ZVsnbmV0d29ya3MnXToK'
    'ICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3JrLCdkZXYnLCd3YXlkcm9pZDAnLCdzY29w'
    'ZScsJ2xpbmsnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogcnVsZXM9J2ZsdXNoIHNldCBpbmV0ICcrdHVubmVsLkZVTExf'
    'R1VBUkQrJyB3YXlkcm9pZF9uZXR3b3Jrc1xuJwogaWYgc3RhdGVbJ25ldHdvcmtzJ106cnVsZXMrPSdhZGQgZWxlbWVudCBp'
    'bmV0ICcrdHVubmVsLkZVTExfR1VBUkQrJyB3YXlkcm9pZF9uZXR3b3JrcyAnK25mdF9zZXQoc3RhdGVbJ25ldHdvcmtzJ10p'
    'KydcbicKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKIGZvciBuZXR3b3JrIGluIHN0YWxl'
    'OnR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsbmV0d29yaywnZGV2Jywnd2F5ZHJvaWQwJywndGFibGUnLFBI'
    'WVNJQ0FMX1RBQkxFXSxjaGVjaz1GYWxzZSkKIGNhY2hlLndyaXRlX3RleHQoanNvbi5kdW1wcyhzdGF0ZSkpO2NhY2hlLmNo'
    'bW9kKDBvNjAwKQoKZGVmIHdhdGNoX3dheWRyb2lkKCk6CiBpbXBvcnQgc3lzCiBsYXN0X2Vycm9yPU5vbmUKIHdoaWxlIFRy'
    'dWU6CiAgdHJ5OgogICBSVU4ubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29rPVRydWUpCiAgIHdpdGggKFJVTi8nb3BlcmF0'
    'aW9uLmxvY2snKS5vcGVuKCdhKycpIGFzIGxvY2s6CiAgICB0cnk6ZmNudGwuZmxvY2sobG9jayxmY250bC5MT0NLX0VYfGZj'
    'bnRsLkxPQ0tfTkIpCiAgICBleGNlcHQgQmxvY2tpbmdJT0Vycm9yOnBhc3MKICAgIGVsc2U6CiAgICAgaWYgdHVubmVsLmZ1'
    'bGxfZ3VhcmRfYWN0aXZlKCkgYW5kIFBhdGgoJy9zeXMvY2xhc3MvbmV0LycrVFVOKS5leGlzdHMoKTpzeW5jX3dheWRyb2lk'
    'X25ldHdvcmsoKQogICBsYXN0X2Vycm9yPU5vbmUKICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgbWVzc2FnZT1zdHIo'
    'ZXhjKQogICBpZiBtZXNzYWdlIT1sYXN0X2Vycm9yOnByaW50KCdXYXlkcm9pZCBuZXR3b3JrIHN5bmM6ICcrbWVzc2FnZSxm'
    'aWxlPXN5cy5zdGRlcnIsZmx1c2g9VHJ1ZSkKICAgbGFzdF9lcnJvcj1tZXNzYWdlCiAgdGltZS5zbGVlcCgxKQoKZGVmIGlu'
    'c3RhbGwoKToKIFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vJytTRVJWSUNFKS53cml0ZV90ZXh0KFVOSVQpCiBQYXRoKCcv'
    'ZXRjL3N5c3RlbWQvc3lzdGVtLycrV0FZRFJPSURfU0VSVklDRSkud3JpdGVfdGV4dChXQVlEUk9JRF9VTklUKQogdHVubmVs'
    'LmNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCgpkZWYgYXBwbHkoKToKIHA9bG9hZCgpO3NldHRpbmdz'
    'PWFwaS5sb2FkX3NldHRpbmdzKCk7cm91dGU9dHVubmVsLnBoeXNpY2FsX3JvdXRlKCk7bGFuPWxvY2FsX25ldHdvcmtzKHJv'
    'dXRlKQogYXBpLmVuc3VyZV9ydW50aW1lKHNldHRpbmdzKQogY2ZnPVJVTi8ncG9saWN5Lmpzb24nO3RtcD1SVU4vJ3BvbGlj'
    'eS5uZXcuanNvbicKIHRtcC53cml0ZV90ZXh0KGpzb24uZHVtcHMoY29uZmlnKHApKSk7b3MuY2htb2QodG1wLDBvNjQwKTtv'
    'cy5jaG93bih0bXAsMCxpbnQoc2V0dGluZ3NbJ3hyYXlfZ2lkJ10pKQogY2hlY2s9dHVubmVsLmNvbW1hbmQoW2FwaS5YUkFZ'
    'LCdydW4nLCctdGVzdCcsJy1jb25maWcnLHRtcF0sY2hlY2s9RmFsc2UpCiBpZiBjaGVjay5yZXR1cm5jb2RlOnJhaXNlIFJ1'
    'bnRpbWVFcnJvcign0J7QsdGA0LDQsdC+0YLRh9C40Log0LjRgdC60LvRjtGH0LXQvdC40Lkg0L3QtSDQv9GA0LjQvdGP0Lsg'
    '0L3QsNGB0YLRgNC+0LnQutC4LicpCiBydWxlcz1maXJld2FsbChwLGxhbixpbnQoc2V0dGluZ3NbJ3hyYXlfdWlkJ10pKQog'
    'cmVwbGFjZW1lbnQ9KCdkZWxldGUgdGFibGUgaW5ldCAnK3R1bm5lbC5GVUxMX0dVQVJEKydcbicgaWYgdHVubmVsLmZ1bGxf'
    'Z3VhcmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKIHR1bm5lbC5jb21tYW5kKFsnbmZ0JywnLWMnLCctZicsJy0nXSxkYXRh'
    'PXJlcGxhY2VtZW50KQogb3duZXJzaGlwPVBBVEgud2l0aF9uYW1lKCdwb2xpY3ktbmV0d29yay5qc29uJykKIGlmIG5vdCBv'
    'd25lcnNoaXAuZXhpc3RzKCk6CiAgZm9yIHRhYmxlIGluIChQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEUpOgogICBpZiB0dW5u'
    'ZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlw'
    'KCk6cmFpc2UgUnVudGltZUVycm9yKCfQotCw0LHQu9C40YbQsCDQvNCw0YDRiNGA0YPRgtC40LfQsNGG0LjQuCDQuNGB0LrQ'
    'u9GO0YfQtdC90LjQuSDQt9Cw0L3Rj9GC0LAg0LTRgNGD0LPQvtC5INC/0YDQvtCz0YDQsNC80LzQvtC5LicpCiAgZXhpc3Rp'
    'bmc9anNvbi5sb2Fkcyh0dW5uZWwuY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KQogIGlmIGFueShy'
    'LmdldCgncHJpb3JpdHknKSBpbiAoNzYsNzcsNzgpIGZvciByIGluIGV4aXN0aW5nKTpyYWlzZSBSdW50aW1lRXJyb3IoJ9Cf'
    '0YDQuNC+0YDQuNGC0LXRgtGLINC80LDRgNGI0YDRg9GC0LjQt9Cw0YbQuNC4INC40YHQutC70Y7Rh9C10L3QuNC5INC30LDQ'
    'vdGP0YLRiyDQtNGA0YPQs9C+0Lkg0L/RgNC+0LPRgNCw0LzQvNC+0LkuJykKICB0dW5uZWwud3JpdGUob3duZXJzaGlwLGpz'
    'b24uZHVtcHMoeyd0YWJsZXMnOltQSFlTSUNBTF9UQUJMRSxWUE5fVEFCTEVdfSkpCiAjIEJ1aWxkIHBoeXNpY2FsIGFuZCBW'
    'UE4tb25seSB0YWJsZXMgYmVmb3JlIGFsbG93aW5nIGFueSBuZXcgbWFya3MuCiBmb3IgdGFibGUgaW4gKFBIWVNJQ0FMX1RB'
    'QkxFLFZQTl9UQUJMRSk6CiAgdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywn'
    'ZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFibGUnLHRhYmxlXSkKIGZvciBuZXR3b3JrIGluIGxhbitbJzE2OS4yNTQu'
    'MC4wLzE2JywnMjI0LjAuMC4wLzQnXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJyxuZXR3b3Jr'
    'LCdkZXYnLHJvdXRlWydkZXYnXSwnc2NvcGUnLCdsaW5rJywndGFibGUnLFBIWVNJQ0FMX1RBQkxFXSkKIHR1bm5lbC5jb21t'
    'YW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywndmlhJyxyb3V0ZVsnZ2F0ZXdheSddLCdkZXYnLHJvdXRl'
    'WydkZXYnXSwnbWV0cmljJywnMTAnLCd0YWJsZScsUEhZU0lDQUxfVEFCTEVdKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3Jv'
    'dXRlJywncmVwbGFjZScsJ2RlZmF1bHQnLCd2aWEnLCcxNzIuMjkuMjQ3LjInLCdkZXYnLHR1bm5lbC5GVUxMX0hPU1QsJ21l'
    'dHJpYycsJzEwJywndGFibGUnLFZQTl9UQUJMRV0pCiBmb3IgcHJpb3JpdHksbWFyayx0YWJsZSBpbiBbKDc2LERJUkVDVCxQ'
    'SFlTSUNBTF9UQUJMRSksKDc3LFZQTixWUE5fVEFCTEUpXToKICB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcs'
    'J3ByaW9yaXR5Jyxwcmlvcml0eSwnZndtYXJrJyxzdHIobWFyayksJ2xvb2t1cCcsdGFibGVdLGNoZWNrPUZhbHNlKQogIHR1'
    'bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnYWRkJywncHJpb3JpdHknLHByaW9yaXR5LCdmd21hcmsnLHN0cihtYXJrKSwn'
    'bG9va3VwJyx0YWJsZV0pCiAjIFJlcGxpZXMgdG8gYSBmb3J3YXJkZWQgY29udGFpbmVyIHJldHVybiB0aHJvdWdoIGl0cyBj'
    'b25uZWN0ZWQgbWFpbiByb3V0ZS4KIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcs'
    'J2lpZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiB0dW5uZWwuY29tbWFuZChbJ2lwJywncnVsZScsJ2Fk'
    'ZCcsJ3ByaW9yaXR5JywnNzgnLCdpaWYnLFRVTiwnbG9va3VwJywnbWFpbiddKQogIyBBIHRlbXBvcmFyeSBjbG9zZWQgc3Rh'
    'dGUgaXMgYWNjZXB0YWJsZTsgYW4gdW5ndWFyZGVkIHN0YXRlIGlzIG5vdC4KIG9zLnJlcGxhY2UodG1wLGNmZykKIHR1bm5l'
    'bC53cml0ZSh0dW5uZWwuUk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogdHVubmVsLmNvbW1hbmQoWyduZnQnLCctZics'
    'Jy0nXSxkYXRhPXJlcGxhY2VtZW50KQogc3luY193YXlkcm9pZF9uZXR3b3JrKGZvcmNlPVRydWUpCiBpbnN0YWxsKCkKIHR1'
    'bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywncmVzdGFydCcsU0VSVklDRV0pCiBmb3IgXyBpbiByYW5nZSg4MCk6CiAgaWYg'
    'UGF0aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygpOmJyZWFrCiAgdGltZS5zbGVlcCguMSkKIGVsc2U6cmFpc2Ug'
    'UnVudGltZUVycm9yKCfQndC1INGD0LTQsNC70L7RgdGMINC30LDQv9GD0YHRgtC40YLRjCDQvtCx0YDQsNCx0L7RgtGH0LjQ'
    'uiDQuNGB0LrQu9GO0YfQtdC90LjQuS4nKQogdHVubmVsLmNvbW1hbmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ2RlZmF1'
    'bHQnLCdkZXYnLFRVTiwnbWV0cmljJywnMTAnLCd0YWJsZScsdHVubmVsLkZVTExfVEFCTEVdKQogdHVubmVsLmNvbmZpZ3Vy'
    'ZV9zeXN0ZW1fZG5zKCkKIHR1bm5lbC5jbGVhcl9kbnNfbWFwcGluZ3MoKQogIyBFeHBsaWNpdGx5IHJlcXVlc3RlZCBETlMg'
    'ZXhjZXB0aW9ucyBuZWVkIHN0YWxlIHBvcnQtNTMgbWFwcGluZ3MgcmVtb3ZlZCB0b28uCiBmb3IgcHJvdG8gaW4gKCd1ZHAn'
    'LCd0Y3AnKToKICB0dW5uZWwuY29tbWFuZChbJ2Nvbm50cmFjaycsJy1EJywnLWYnLCdpcHY0JywnLXAnLHByb3RvLCctLWRw'
    'b3J0JywnNTMnLCctLXJlcGx5LXBvcnQtc3JjJyxzdHIoRE5TX1BPUlQpXSxjaGVjaz1GYWxzZSkKCgpkZWYgc3RvcChyZWxl'
    'YXNlPUZhbHNlKToKIHR1bm5lbC5jb21tYW5kKFsnc3lzdGVtY3RsJywnc3RvcCcsU0VSVklDRV0sY2hlY2s9RmFsc2UpCiBp'
    'ZiByZWxlYXNlIGFuZCBQQVRILndpdGhfbmFtZSgncG9saWN5LW5ldHdvcmsuanNvbicpLmV4aXN0cygpOgogIHR1bm5lbC5j'
    'b21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OCcsJ2lpZicsVFVOLCdsb29rdXAnLCdtYWluJ10sY2hl'
    'Y2s9RmFsc2UpCiAgZm9yIHByaW9yaXR5LG1hcmssdGFibGUgaW4gWyg3NixESVJFQ1QsUEhZU0lDQUxfVEFCTEUpLCg3NyxW'
    'UE4sVlBOX1RBQkxFKV06CiAgIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLHByaW9yaXR5'
    'LCdmd21hcmsnLHN0cihtYXJrKSwnbG9va3VwJyx0YWJsZV0sY2hlY2s9RmFsc2UpCiAgIHR1bm5lbC5jb21tYW5kKFsnaXAn'
    'LCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLHRhYmxlXSxjaGVjaz1GYWxzZSkKICBQQVRILndpdGhfbmFtZSgncG9saWN5LW5l'
    'dHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKZGVmIGNoYW5nZShhY3Rpb24sY2F0ZWdvcnk9JycsdmFs'
    'dWU9Jycsc3RhdGU9Tm9uZSk6CiBvbGQ9bG9hZCgpO3A9anNvbi5sb2Fkcyhqc29uLmR1bXBzKG9sZCkpCiBpZiBhY3Rpb249'
    'PSdtb2RlJzoKICBpZiB2YWx1ZSBub3QgaW4gKCdhbGwnLCdpbmNsdWRlJyk6cmFpc2UgVmFsdWVFcnJvcign0KDQtdC20LjQ'
    'vDogYWxsINC40LvQuCBpbmNsdWRlLicpCiAgcFsnbW9kZSddPXZhbHVlCiBlbGlmIGFjdGlvbi5zdGFydHN3aXRoKCdpbmNs'
    'dWRlLScpOgogIGlmIGFjdGlvbiBub3QgaW4gKCdpbmNsdWRlLWFkZCcsJ2luY2x1ZGUtcmVtb3ZlJykgb3IgY2F0ZWdvcnkg'
    'bm90IGluIENBVEVHT1JJRVM6cmFpc2UgVmFsdWVFcnJvcign0J3QtdC40LfQstC10YHRgtC90L7QtSDQtNC10LnRgdGC0LLQ'
    'uNC1INGB0L/QuNGB0LrQsCBWUE4uJykKICBpZiBjYXRlZ29yeT09J3BvcnRzJyBhbmQgc3RyKHZhbHVlKS5jb3VudCgnOicp'
    'PT0xOnZhbHVlPXN0cih2YWx1ZSkrJzpvdXQnCiAgdmFsdWU9bm9ybWFsaXplKGNhdGVnb3J5LHZhbHVlKQogIGlmIGNhdGVn'
    'b3J5PT0ncG9ydHMnIGFuZCBub3QgdmFsdWUuZW5kc3dpdGgoJzpvdXQnKTpyYWlzZSBWYWx1ZUVycm9yKCfQkiDRgdC/0LjR'
    'gdC60LUgVlBOINCy0YvQsdC40YDQsNGO0YLRgdGPINC40YHRhdC+0LTRj9GJ0LjQtSDQv9C+0YDRgtGLICg6b3V0KTsg0L7R'
    'gtCy0LXRgtGLINGB0LXRgNCy0LXRgNC+0LIg0L7RgdGC0LDRjtGC0YHRjyBESVJFQ1QuJykKICBpZiBhY3Rpb249PSdpbmNs'
    'dWRlLWFkZCcgYW5kIHZhbHVlIG5vdCBpbiBwWydpbmNsdWRlJ11bY2F0ZWdvcnldOnBbJ2luY2x1ZGUnXVtjYXRlZ29yeV0u'
    'YXBwZW5kKHZhbHVlKQogIGlmIGFjdGlvbj09J2luY2x1ZGUtcmVtb3ZlJzpwWydpbmNsdWRlJ11bY2F0ZWdvcnldPVt4IGZv'
    'ciB4IGluIHBbJ2luY2x1ZGUnXVtjYXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBlbGlmIGFjdGlvbj09J3dheWRyb2lkJzpwWyd3'
    'YXlkcm9pZF9kaXJlY3QnXT1ib29sKHN0YXRlKQogZWxpZiBhY3Rpb249PSdiYXNlJzoKICBpZiBjYXRlZ29yeSBub3QgaW4g'
    'QkFTRSBvciB2YWx1ZSBub3QgaW4ge2VbJ2lkJ10gZm9yIGUgaW4gQkFTRVtjYXRlZ29yeV19OnJhaXNlIFZhbHVlRXJyb3Io'
    'J9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uJykKICBrZXk9Y2F0ZWdvcnkr'
    'JzonK3ZhbHVlCiAgcFsnZGlzYWJsZWRfYmFzZSddPVt4IGZvciB4IGluIHBbJ2Rpc2FibGVkX2Jhc2UnXSBpZiB4IT1rZXld'
    'CiAgaWYgbm90IHN0YXRlOnBbJ2Rpc2FibGVkX2Jhc2UnXS5hcHBlbmQoa2V5KQogZWxpZiBhY3Rpb24gaW4gKCdhZGQnLCdy'
    'ZW1vdmUnKToKICBpZiBjYXRlZ29yeSBub3QgaW4gQ0FURUdPUklFUzpyYWlzZSBWYWx1ZUVycm9yKCfQndC10LjQt9Cy0LXR'
    'gdGC0L3QsNGPINC60LDRgtC10LPQvtGA0LjRjy4nKQogIHZhbHVlPW5vcm1hbGl6ZShjYXRlZ29yeSx2YWx1ZSkKICBpZiBh'
    'Y3Rpb249PSdhZGQnIGFuZCB2YWx1ZSBub3QgaW4gcFtjYXRlZ29yeV06cFtjYXRlZ29yeV0uYXBwZW5kKHZhbHVlKQogIGlm'
    'IGFjdGlvbj09J3JlbW92ZSc6cFtjYXRlZ29yeV09W3ggZm9yIHggaW4gcFtjYXRlZ29yeV0gaWYgeCE9dmFsdWVdCiBlbHNl'
    'OnJhaXNlIFZhbHVlRXJyb3IoJ9Cd0LXQuNC30LLQtdGB0YLQvdC+0LUg0LTQtdC50YHRgtCy0LjQtS4nKQogaWYgcD09b2xk'
    'OnJldHVybiBwdWJsaWMoKQogaWYgdHVubmVsLmZ1bGxfZ3VhcmRfYWN0aXZlKCkgYW5kIG5vdCBQYXRoKCcvc3lzL2NsYXNz'
    'L25ldC8nK3R1bm5lbC5GVUxMX0hPU1QpLmV4aXN0cygpOgogIHJhaXNlIFJ1bnRpbWVFcnJvcignVlBOINCy0L7RgdGB0YLQ'
    'sNC90LDQstC70LjQstCw0LXRgtGB0Y8uINCf0L7QstGC0L7RgNC40YLQtSDQuNC30LzQtdC90LXQvdC40LUg0L/RgNCw0LLQ'
    'uNC7INC/0L7RgdC70LUg0L/QvtC00LrQu9GO0YfQtdC90LjRjzsg0L/RgNC10LbQvdC40LUg0L/RgNCw0LLQuNC70LAg0YHQ'
    'vtGF0YDQsNC90LXQvdGLLicpCiBzYXZlKHApCiBpZiB0dW5uZWwuZnVsbF9ndWFyZF9hY3RpdmUoKSBhbmQgUGF0aCgnL3N5'
    'cy9jbGFzcy9uZXQvJyt0dW5uZWwuRlVMTF9IT1NUKS5leGlzdHMoKToKICB0cnk6YXBwbHkoKQogIGV4Y2VwdCBFeGNlcHRp'
    'b246CiAgIHNhdmUob2xkKQogICB0cnk6YXBwbHkoKQogICBleGNlcHQgRXhjZXB0aW9uOnBhc3MKICAgcmFpc2UKIHJldHVy'
    'biBwdWJsaWMoKQoKZGVmIGVuc3VyZV9yb3V0ZSgpOgogaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytUVU4pLmV4aXN0cygp'
    'OgogIHR1bm5lbC5jb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0JywnZGV2JyxUVU4sJ21ldHJpYycs'
    'JzEwJywndGFibGUnLHR1bm5lbC5GVUxMX1RBQkxFXSkKIGVsc2U6cmFpc2UgUnVudGltZUVycm9yKCdwb2xpY3lfZW5naW5l'
    'X3VuYXZhaWxhYmxlJykK'
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
  sync_system_files()
  if not settings.get('cli_only',False):
   cmd_gui_install(settings)
   if _widget_package_dir(settings).exists():cmd_widget_install(settings)
  policy.migration(settings)
  starfive_tunnel.ensure_dependencies()
  if not settings.get('cli_only',False):ensure_gui_dependencies()
  core_update(settings)
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
 print(('CLI обновлён до ' if settings.get('cli_only',False) else 'CLI и GUI обновлены до ')+MANAGER_VERSION+'.')
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
 elif action=='route':
  starfive_tunnel.select_route(str(data.get('value','auto')))
  if starfive_tunnel.status().get('running'):starfive_tunnel.connect(restart=True)
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
 p=argparse.ArgumentParser(prog='vpn',description='Evgenium: VPN для всего трафика или только выбранных приложений и адресов')
 p.add_argument('--self-test',action='store_true')
 sub=p.add_subparsers(dest='cmd')
 for name in ('on','repair','toggle'):
  a=sub.add_parser(name,help={'on':'Подключить и показать этапы','repair':'Восстановить соединение','toggle':'Переключить VPN'}[name]);a.add_argument('--no-wait',action='store_true',help='Запустить в фоне')
 for name in ('off','rules','watch','update','version','internal-sync','internal-after-update','internal-waydroid-watch','internal-starfive-tunnel','internal-starfive-tunnel-cleanup','internal-tls-client','internal-starfive-pause-main','manager-rollback'):sub.add_parser(name)
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
  elif cmd=='panic':
   if args.value!='status':starfive_tunnel.set_panic(args.value=='on')
   print('Панический поиск: '+('ВКЛЮЧЁН' if starfive_tunnel.panic_enabled() else 'выключен'))
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
    starfive_tunnel.select_route(args.value)
    if starfive_tunnel.status().get('running'):starfive_tunnel.connect(restart=True)
   routes=starfive_tunnel.route_choices()
   print('Выбран: '+routes['selected']);print('auto  Автоматически · сохранённый порядок')
   for c in routes['choices']:print(c['id']+'  '+c['label'])
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
