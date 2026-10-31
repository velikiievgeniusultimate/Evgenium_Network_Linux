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

MANAGER_VERSION = "0.5.6"

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
    'ICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEZsYXRCdXR0b24geyBsYWJlbDogItCe'
    '0YLRh9GR0YIg0LTQu9GPINC/0L7QtNC00LXRgNC20LrQuCI7IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgIXJvb3Qu'
    'c3RhdGUuY29ubmVjdGluZzsgb25DbGlja2VkOiByb290LmFjdGlvbih7YWN0aW9uOiJyZXBvcnQtcHJldmlldyJ9LGZ1bmN0'
    'aW9uKHJlcGx5KXsKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXBvcnQ9SlNPTi5wYXJzZShyZXBseS5vdXRw'
    'dXQpO3Jvb3QucmVwb3J0SWQ9cmVwb3J0LnJlcG9ydF9pZDtyb290LnJlcG9ydFRleHQ9SlNPTi5zdHJpbmdpZnkocmVwb3J0'
    'LG51bGwsMik7cmVwb3J0Q29uc2VudC5jaGVja2VkPWZhbHNlO3N1cHBvcnREaWFsb2cub3BlbigpCiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIH0pIH0KICAgICAgICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0J/RgNC+0LLQtdGA'
    '0LjRgtGMINC+0LHQvdC+0LLQu9C10L3QuNGPIjsgZW5hYmxlZEJ1dHRvbjogIXJvb3QuYnVzeTsgb25DbGlja2VkOiByb290'
    'LmFjdGlvbih7YWN0aW9uOiAidXBkYXRlIn0pIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'Q29sdW1uTGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPj0gMSAmJiBy'
    'b290LnBhZ2VJbmRleCA8PSA0CiAgICAgICAgICAgICAgICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgc3BhY2luZzogMTYKICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB3'
    'cmFwTW9kZTogVGV4dC5XcmFwCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogcm9vdC50ZXh0TXV0ZWQKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgIHRleHQ6IHJvb3QucGFnZUluZGV4ID09PSAxID8gItCS0YvQsdGA0LDQvdC90YvQ'
    'tSDQv9GA0LjQu9C+0LbQtdC90LjRjyDQv9C+0LTQutC70Y7Rh9Cw0Y7RgtGB0Y8g0L3QsNC/0YDRj9C80YPRji4g0J7RgdGC'
    '0LDQu9GM0L3Ri9C1INC40YHQv9C+0LvRjNC30YPRjtGCIFZQTi4iIDogcm9vdC5wYWdlSW5kZXggPT09IDIgPyAi0JTQvtCx'
    '0LDQstGM0YLQtSDQtNC+0LzQtdC9LCDQsNC00YDQtdGBINC40LvQuCDQv9C+0LTRgdC10YLRjC4g0JTQvtC80LXQvdGLINCy'
    '0LrQu9GO0YfQsNGO0YIg0L/QvtC00LTQvtC80LXQvdGLOyDQt9C90LDQuiA9INC30LDQtNCw0ZHRgiDRgtC+0YfQvdC+0LUg'
    '0YHQvtCy0L/QsNC00LXQvdC40LUuINCf0YDQuCDQvtCx0YnQtdC8IElQINC70YPRh9GI0LUg0YPQutCw0LfRi9Cy0LDRgtGM'
    'INC00L7QvNC10L0uIiA6IHJvb3QucGFnZUluZGV4ID09PSAzID8gItCY0YHRhdC+0LTRj9GJ0LjQtSDigJQg0L/QvtC00LrQ'
    'u9GO0YfQtdC90LjRjyDQuiDRg9C60LDQt9Cw0L3QvdC+0LzRgyDQv9C+0YDRgtGDLiDQktGF0L7QtNGP0YnQuNC1IOKAlCDQ'
    'v9GA0Y/QvNGL0LUg0L7RgtCy0LXRgtGLINCy0LDRiNC10LPQviDRgdC10YDQstC10YDQsC4g0J7QsdCwIOKAlCDQvtCx0LAg'
    '0L3QsNC/0YDQsNCy0LvQtdC90LjRjy4iIDogItCe0LHRi9GH0L3Ri9C5IEROUyDQvtGB0YLQsNGR0YLRgdGPINCyIFZQTi4g'
    '0JTQvtCx0LDQstC70LXQvdC90YvQtSDQt9C00LXRgdGMIEROUy3RgdC10YDQstC10YDRiyDQv9C+0LvRg9GH0LDRjtGCINC3'
    '0LDQv9GA0L7RgdGLINC90LDQv9GA0Y/QvNGD0Y4g0Lgg0LzQvtCz0YPRgiDQstC40LTQtdGC0Ywg0LfQsNC/0YDQsNGI0LjQ'
    'stCw0LXQvNGL0LUg0LjQvNC10L3QsC4g0K3RgtC+INC90LUg0YHQv9C40YHQvtC6INGB0LDQudGC0L7Qsi4iCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIExheW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuQ29tYm9Cb3gg'
    'eyBpZDogcG9ydFByb3RvY29sOyB2aXNpYmxlOiByb290LnBhZ2VJbmRleCA9PT0gMzsgbW9kZWw6IFsiVENQIiwgIlVEUCIs'
    'ICJCT1RIIl07IExheW91dC5wcmVmZXJyZWRXaWR0aDogMTAwIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuVGV4'
    'dEZpZWxkIHsgaWQ6IGV4Y2VwdGlvbklucHV0OyBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlOyBzZWxlY3RCeU1vdXNlOiB0cnVl'
    'OyBwbGFjZWhvbGRlclRleHQ6IHJvb3QucGFnZUluZGV4ID09PSAxID8gItCY0LzRjyDQv9GA0L7RhtC10YHRgdCwINC40LvQ'
    'uCAv0L/QvtC70L3Ri9C5L9C/0YPRgtGMIiA6IHJvb3QucGFnZUluZGV4ID09PSAyID8gImV4YW1wbGUuY29tINC40LvQuCAx'
    'OTIuMTY4LjEuMjAiIDogcm9vdC5wYWdlSW5kZXggPT09IDMgPyAiMjU1NjUiIDogItCQ0LTRgNC10YEgRE5TLCDQvdCw0L/R'
    'gNC40LzQtdGAIDE5Mi4xNjguMS4xIiB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkNvbWJvQm94IHsgaWQ6IHBv'
    'cnREaXJlY3Rpb247IHZpc2libGU6IHJvb3QucGFnZUluZGV4ID09PSAzOyBtb2RlbDogWyLQmNGB0YXQvtC00Y/RidC40LUi'
    'LCAi0JLRhdC+0LTRj9GJ0LjQtSIsICLQntCx0LAiXTsgTGF5b3V0LnByZWZlcnJlZFdpZHRoOiAxNDAgfQogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0JTQvtCx0LDQstC40YLRjCI7IHByaW1hcnk6IHRydWU7'
    'IGVuYWJsZWRCdXR0b246ICFyb290LmJ1c3kgJiYgZXhjZXB0aW9uSW5wdXQudGV4dC50cmltKCkubGVuZ3RoID4gMDsgb25D'
    'bGlja2VkOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgdmFsdWUgPSByb290LnBhZ2VJbmRleCA9'
    'PT0gMyA/IHBvcnRQcm90b2NvbC5jdXJyZW50VGV4dC50b0xvd2VyQ2FzZSgpICsgIjoiICsgZXhjZXB0aW9uSW5wdXQudGV4'
    'dC50cmltKCkgKyAiOiIgKyBbIm91dCIsICJpbiIsICJib3RoIl1bcG9ydERpcmVjdGlvbi5jdXJyZW50SW5kZXhdIDogZXhj'
    'ZXB0aW9uSW5wdXQudGV4dC50cmltKCkKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb290LmFjdGlvbih7YWN0'
    'aW9uOiAiYWRkIiwgY2F0ZWdvcnk6IHJvb3QuY2F0ZWdvcnksIHZhbHVlOiB2YWx1ZX0sIGZ1bmN0aW9uKCkgeyBleGNlcHRp'
    'b25JbnB1dC5jbGVhcigpIH0pCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9IH0KICAgICAgICAgICAgICAgICAgICAg'
    'ICAgfQogICAgICAgICAgICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtb2Rl'
    'bDogcm9vdC5wb2xpY3lbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRlbGVnYXRl'
    'OiBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHByb3BlcnR5IHN0cmluZyBt'
    'b2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdpZHRoOiB0cnVlCiAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YTsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1'
    'ZTsgd3JhcE1vZGU6IFRleHQuV3JhcEFueXdoZXJlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgRmxhdEJ1dHRvbiB7IGxhYmVsOiAi0KPQtNCw0LvQuNGC0YwiOyBkYW5nZXI6IHRydWU7IGVuYWJs'
    'ZWRCdXR0b246ICFyb290LmJ1c3k7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogInJlbW92ZSIsIGNhdGVnb3J5'
    'OiByb290LmNhdGVnb3J5LCB2YWx1ZTogbW9kZWxEYXRhfSkgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB2aXNpYmxlOiAhKHJvb3Qu'
    'cG9saWN5W3Jvb3QuY2F0ZWdvcnldIHx8IFtdKS5sZW5ndGg7IHRleHQ6ICLQktCw0YjQuNGFINC40YHQutC70Y7Rh9C10L3Q'
    'uNC5INC/0L7QutCwINC90LXRgiI7IGNvbG9yOiByb290LnRleHRNdXRlZCB9CiAgICAgICAgICAgICAgICAgICAgICAgIFJp'
    'YmJvblN3aXRjaCB7IHRleHQ6ICLQntGC0L7QsdGA0LDQt9C40YLRjCDQsdCw0LfQvtCy0YvQtSDQuNGB0LrQu9GO0YfQtdC9'
    '0LjRjyI7IGNoZWNrZWQ6IHJvb3Quc2hvd0Jhc2U7IG9uVG9nZ2xlZDogcm9vdC5zaG93QmFzZSA9IGNoZWNrZWQgfQogICAg'
    'ICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZp'
    'bGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5zaG93QmFzZQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgUmVwZWF0ZXIgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1vZGVsOiAo'
    'cm9vdC5wb2xpY3kuYmFzZSB8fCB7fSlbcm9vdC5jYXRlZ29yeV0gfHwgW10KICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBkZWxlZ2F0ZTogUm93TGF5b3V0IHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVxdWlyZWQg'
    'cHJvcGVydHkgdmFyIG1vZGVsRGF0YQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBMYXlvdXQuZmlsbFdp'
    'ZHRoOiB0cnVlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEMuTGFiZWwgeyB0ZXh0OiBtb2RlbERhdGEu'
    'bGFiZWw7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHdyYXBNb2RlOiBUZXh0LldyYXA7IGNvbG9yOiByb290LnRleHRNYWlu'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgUmliYm9uU3dpdGNoIHsgY2hlY2tlZDogQm9vbGVhbiht'
    'b2RlbERhdGEuZW5hYmxlZCk7IGVuYWJsZWQ6ICFyb290LmJ1c3k7IG9uVG9nZ2xlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjog'
    'ImJhc2UiLCBjYXRlZ29yeTogcm9vdC5jYXRlZ29yeSwgdmFsdWU6IG1vZGVsRGF0YS5pZCwgZW5hYmxlZDogY2hlY2tlZH0p'
    'IH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQu'
    'V3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiAi0JLRiyDQvNC+0LbQtdGC0LUg0LLRi9C60LvRjtGH0LjRgtGM'
    'INC70Y7QsdC+0LUg0LHQsNC30L7QstC+0LUg0L/RgNCw0LLQuNC70L4uINCh0LrRgNGL0YLQuNC1INGB0L/QuNGB0LrQsCDQ'
    'vdC1INC80LXQvdGP0LXRgiDQtdCz0L4g0YHQvtGB0YLQvtGP0L3QuNC1LiIgfQogICAgICAgICAgICAgICAgICAgICAgICB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgIENvbHVtbkxheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aXNp'
    'YmxlOiByb290LnBhZ2VJbmRleCA9PT0gMQogICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDog'
    'dHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6ICLQl9Cw0L/Rg9GJ0LXQvdGLINGB0LXQ'
    'udGH0LDRgSI7IGZvbnQucGl4ZWxTaXplOiAxODsgZm9udC5ib2xkOiB0cnVlOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9CiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICBSb3dMYXlvdXQgewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIExh'
    'eW91dC5maWxsV2lkdGg6IHRydWUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLlRleHRGaWVsZCB7IGlkOiBh'
    'cHBTZWFyY2g7IExheW91dC5maWxsV2lkdGg6IHRydWU7IHBsYWNlaG9sZGVyVGV4dDogItCf0L7QuNGB0Log0L/RgNC40LvQ'
    'vtC20LXQvdC40Y8iIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6ICLQntCx'
    '0L3QvtCy0LjRgtGMINGB0L/QuNGB0L7QuiI7IGVuYWJsZWRCdXR0b246ICFyb290LnJ1bm5pbmdQZW5kaW5nOyBvbkNsaWNr'
    'ZWQ6IHJvb3QucmVmcmVzaFJ1bm5pbmcoKSB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICBSZXBlYXRlciB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbW9kZWw6IHJvb3QucGFn'
    'ZUluZGV4ID09PSAxID8gcm9vdC5maWx0ZXJlZFJ1bm5pbmcoKSA6IFtdCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgZGVsZWdhdGU6IFJvd0xheW91dCB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlcXVpcmVkIHBy'
    'b3BlcnR5IHZhciBtb2RlbERhdGEKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0'
    'aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDb2x1bW5MYXlvdXQgewogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgQy5MYWJlbCB7IHRleHQ6IG1vZGVsRGF0YS5uYW1lOyBjb2xvcjogcm9vdC50ZXh0TWFpbiB9'
    'CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgdGV4dDogbW9kZWxEYXRhLmV4ZTsg'
    'TGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgZWxpZGU6IFRleHQuRWxpZGVNaWRkbGU7IGNvbG9yOiByb290LnRleHRNdXRlZDsg'
    'Zm9udC5waXhlbFNpemU6IDExIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBGbGF0QnV0dG9uIHsgbGFiZWw6IG1vZGVsRGF0YS5leGNsdWRlZCA/ICLQlNC+0LHQ'
    'sNCy0LvQtdC90L4iIDogItCSINC+0LHRhdC+0LQiOyBlbmFibGVkQnV0dG9uOiAhcm9vdC5idXN5ICYmICFtb2RlbERhdGEu'
    'ZXhjbHVkZWQ7IG9uQ2xpY2tlZDogcm9vdC5hY3Rpb24oe2FjdGlvbjogImFkZCIsIGNhdGVnb3J5OiAiYXBwbGljYXRpb25z'
    'IiwgdmFsdWU6IFN0cmluZyhtb2RlbERhdGEuZXhlIHx8IG1vZGVsRGF0YS5uYW1lIHx8ICIiKX0pIH0KICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAg'
    'ICAgIH0KICAgICAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAgICAgQ29sdW1uTGF5b3V0IHsKICAgICAgICAg'
    'ICAgICAgICAgICAgICAgdmlzaWJsZTogcm9vdC5wYWdlSW5kZXggPT09IDUKICAgICAgICAgICAgICAgICAgICAgICAgTGF5'
    'b3V0LmZpbGxXaWR0aDogdHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBzcGFjaW5nOiAxOAogICAgICAgICAgICAgICAg'
    'ICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQuV3JhcDsgY29sb3I6IHJv'
    'b3QudGV4dE11dGVkOyB0ZXh0OiAiV2F5ZHJvaWQg0YPQv9GA0LDQstC70Y/QtdGC0YHRjyDQvtGC0LTQtdC70YzQvdC+INC+'
    '0YIg0L/RgNC40LvQvtC20LXQvdC40Lkg0LrQvtC80L/RjNGO0YLQtdGA0LAuINCf0L4g0YPQvNC+0LvRh9Cw0L3QuNGOINCy'
    '0LXRgdGMINC10LPQviDRgtGA0LDRhNC40LosINCy0LrQu9GO0YfQsNGPIEROUywg0LjQtNGR0YIg0L3QsNC/0YDRj9C80YPR'
    'ji4iIH0KICAgICAgICAgICAgICAgICAgICAgICAgUmliYm9uU3dpdGNoIHsgdGV4dDogIldheWRyb2lkINCyINC+0LHRhdC+'
    '0LQgVlBOIjsgY2hlY2tlZDogcm9vdC5wb2xpY3kud2F5ZHJvaWRfZGlyZWN0ICE9PSBmYWxzZTsgZW5hYmxlZDogIXJvb3Qu'
    'YnVzeTsgb25Ub2dnbGVkOiByb290LmFjdGlvbih7YWN0aW9uOiAid2F5ZHJvaWQiLCBlbmFibGVkOiBjaGVja2VkfSkgfQog'
    'ICAgICAgICAgICAgICAgICAgICAgICBDLkxhYmVsIHsgTGF5b3V0LmZpbGxXaWR0aDogdHJ1ZTsgd3JhcE1vZGU6IFRleHQu'
    'V3JhcDsgY29sb3I6IHJvb3QudGV4dE11dGVkOyB0ZXh0OiByb290LnBvbGljeS53YXlkcm9pZF9kaXJlY3QgIT09IGZhbHNl'
    'ID8gItCf0YDRj9C80L7QtSDQv9C+0LTQutC70Y7Rh9C10L3QuNC1OiBXYXlkcm9pZCDQuNGB0L/QvtC70YzQt9GD0LXRgiDQ'
    'sNC00YDQtdGBINCy0LDRiNC10LPQviDQv9GA0L7QstCw0LnQtNC10YDQsC4g0J7QsdGJ0LjQtSDQuNGB0LrQu9GO0YfQtdC9'
    '0LjRjyDQvdC1INC+0LPRgNCw0L3QuNGH0LjQstCw0Y7RgiDRjdGC0L7RgiDRgNC10LbQuNC8LiIgOiAiV2F5ZHJvaWQg0LjR'
    'gdC/0L7Qu9GM0LfRg9C10YIgVlBOLiDQn9GA0Lgg0L7QsdGA0YvQstC1INGC0YPQvdC90LXQu9GPINC10LPQviDQstC90LXR'
    'iNC90LjQtSDQv9C+0LTQutC70Y7Rh9C10L3QuNGPINCx0LvQvtC60LjRgNGD0Y7RgtGB0Y8uIiB9CiAgICAgICAgICAgICAg'
    'ICAgICAgfQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgfQogICAgfQp9Cg=='
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
    'gtC+0L3QuNGPINGH0LXRgNC10LcgRXZnZW5pdW1UdW5uZWwnfSwKIHsnaWQnOidlZS1ldmd0LXJ1JywnYWRkcmVzcyc6JzM4'
    'LjE4MC4xNjQuNjcnLCdpZGVudGl0eSc6JzM4LjE4MC4xNjQuNjcnLCdwb3J0Jzo0NDMsJ3Rscyc6RmFsc2UsJ2V2Z3QnOlRy'
    'dWUsJ3RyYW5zcG9ydF9hZGRyZXNzJzpTRVJWRVIsJ3RyYW5zcG9ydF9wb3J0JzoyNDU3OSwnbGFiZWwnOidFdmdlbml1bVR1'
    'bm5lbCDCtyBIU1ZEUyDihpIg0K3RgdGC0L7QvdC40Y8nfSwKKQpBQ1RJVkUgPSBDQU5ESURBVEVTWzBdCnJhbmtfYXBpID0g'
    'Tm9uZQpzdXBwb3J0X2FwaSA9IE5vbmUKdGxzX2FwaSA9IE5vbmUKVExTX1BST0NFU1MgPSBOb25lCiMgS2VwdCBvbmx5IGZv'
    'ciByZW1vdmluZyByb3V0ZXMgaW5zdGFsbGVkIGJ5IHByZS1taWdyYXRpb24gdmVyc2lvbnMuCkxFR0FDWV9FTkRQT0lOVFMg'
    'PSAoJzEwOS4xOTQuNjcuMTU5JywgJzE5Mi4xNjguMC4xNjMnKQpIRUFMVEggPSAnMTAuNzcuMC4xJwpSRVFJRCA9IDE3NwpU'
    'T0tFTl9QQVRURVJOID0gcidFVk4xLVtBLVphLXowLTlfLV17NDN9JwpTVE9QID0gRmFsc2UKRE5TX1BST0NFU1MgPSBOb25l'
    'CnBvbGljeSA9IE5vbmUKUElOTkVEX0NBID0gJy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRU9EQ0NBcUNnQXdJ'
    'QkFnSVVia0orOFNhcUFnd1kxUkRBalpSVGpjcVE5ZU13RFFZSktvWklodmNOQVFFTFxuQlFBd0lqRWdNQjRHQTFVRUF3d1hS'
    'WFpuWlc1cGRXMGdjSEpwZG1GMFpTQldVRTRnUTBFd0hoY05Nall4TURBM1xuTVRreE16UXhXaGNOTXpZeE1EQTBNVGt4TXpR'
    'eFdqQWlNU0F3SGdZRFZRUUREQmRGZG1kbGJtbDFiU0J3Y21sMlxuWVhSbElGWlFUaUJEUVRDQ0FhSXdEUVlKS29aSWh2Y05B'
    'UUVCQlFBRGdnR1BBRENDQVlvQ2dnR0JBT1orbnZpRVxuMk9yRjdQZHRray9YSWFGVkl2Smx2QzExVlpmOXJsakNCSXZCeWti'
    'c3JBckdyeVFIR251dVhMTmFhUzhOdEx4WVxuTmVTQkRLNk1kZ1lKQWVqc1A0d0lUdWIzbk1qU0cydW1JSVZVNm1FK0dEb3pH'
    'UGxOTU5KK2Joa0thVmhhUGpGRVxueVlMWXJkUGU1VkE0dys1cDBOWk9ENkNCSEQzdEVYV0JOUkllVlNXYnRNSVRzT0VTMVBl'
    'L2FBTDd2M29OSVZrVlxuOG5EdzlqNyt3RzJ5NWRoYnA3S1VKSGJyREIwMjRyN2NZclEzYXhZRjZneWtqbXp0cEtYc2JreFF2'
    'MjdCdmhTQlxuZTBFa3RKL2pDUzZSOUlJbVlnSVFyQ3JhV1ptVlNjbkdGL0FxNFROdzFINE96RkNrUis3SlVsWW5TWVV2TVJp'
    'MVxuTHpLZWtVQysyLzBXRm1obkNvRHRkamNvWWJ4cExwS0RlbEdpUzNSc05Ddnhuc2xNYVB6NWhDY0Y2NFk3UmlqWFxuajZE'
    'dUNZcEZZV2xyMTNCMjBxQW5Sb1VhcytBalg3UFhDa1I0eE9oSCtrVzgvSG1GSGlIa29oV0Uwd2xsSVNCWFxuVkJvN0tCT1pk'
    'OFNWZXd5YmQyckI0c29Yb3VUdGpYcy9qVGdlK0hXeFFER1BQMXVtZno4Y0ZMUi91UUlEQVFBQlxubzJZd1pEQWRCZ05WSFE0'
    'RUZnUVVvUWZUaWY3N3hXdDA2aGFYaDNoYTg5MHFrVDh3SHdZRFZSMGpCQmd3Rm9BVVxub1FmVGlmNzd4V3QwNmhhWGgzaGE4'
    'OTBxa1Q4d0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFEQU9CZ05WSFE4QlxuQWY4RUJBTUNBUVl3RFFZSktvWklodmNOQVFF'
    'TEJRQURnZ0dCQUk3R0tubWZKanVMMVF2eVJ0bHcrSHI2QVkvWlxuT3hkRHZFQ2Vmb0ZMN1E0MVZaYStMN0RJODdrTUxZSHln'
    'Ukh1c2g2Nm9Vdjg3OFRXTXRhc25idC84d1lnNmpyd1xuQXlncGcvRjNWRDI0eVRybko3T0NkeUdpYjZMR3V1c3VUUDRyVUdz'
    'Y2NXY3puUVhZRmt6UlZ6MVZlWU1aVU4rUFxudEFWaU5sNEVSUzFmaCtjR3pUNE9xWFFrSkRrUmVxSC9IQ1RFOGtVUVVVZ1hh'
    'U1hwaEtqR2E4cFIySFZlRnVrWFxuKzBwcDFpUis2ZGk0YUNLYXBrYVRpVlIzcjYydFJCVXdieG9GWVJ5eE5YeW5USzlFaG5N'
    'MjVXRXBuL3F1MGxzRFxub1hyRlZtajBBUWZBVUhSTi8yclBMLy93NlJQRXBIZ1VjcnQ3enVTZ29YSlpoMERUMzBWRUlLOU5O'
    'YnVLU0ZkOVxuSWlXdnJ4YlZRUzZtUWd0RVpONExjMkhtMXB2WStXckkrSDAzdTgwNDIrY3BMSXNDbnhQbTlXdmk3ZE1YeHFv'
    'YlxubzIvYUwyeERHNUcvOFdWUi9XNUVBZnZLZHhkcmszSDYwMm9jY292NytKZzF2b3hpMDBJYmRNRXhvTXhkNWFlaFxuZlhS'
    'aUpoVEVGb3VJcG1FU0NGNHZWTWxXRnIzbXFsUTNHS1NQVkE9PVxuLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLVxuJwoKCkZV'
    'TExfSE9TVCA9ICdldm4tZnVsbC1ob3N0JwpGVUxMX1BFRVIgPSAnZXZuLWZ1bGwtcGVlcicKRlVMTF9ORVQgPSAnMTcyLjI5'
    'LjI0Ny4wLzMwJwpGVUxMX1RBQkxFID0gJzUxODI4JwpBRE1JTl9UQUJMRSA9ICc1MTgyOScKRlVMTF9HVUFSRCA9ICdldm5f'
    'c3RhcmZpdmVfZnVsbCcKZGVmIGZ1bGxfc3RhdGUoKToKICAgIHJldHVybiBST09ULydmdWxsLW5ldHdvcmsuanNvbicKCgpk'
    'ZWYgY2hhcm9uX2JpbmFyeSgpOgogICAgY2FuZGlkYXRlcyA9ICgnL3Vzci9zYmluL2NoYXJvbi1zeXN0ZW1kJywgJy91c3Iv'
    'YmluL2NoYXJvbi1zeXN0ZW1kJywKICAgICAgICAgICAgICAgICAgJy91c3IvbGliL2lwc2VjL2NoYXJvbi1zeXN0ZW1kJywg'
    'Jy91c3IvbGliZXhlYy9pcHNlYy9jaGFyb24tc3lzdGVtZCcsCiAgICAgICAgICAgICAgICAgICcvdXNyL2xpYi9zdHJvbmdz'
    'd2FuL2NoYXJvbi1zeXN0ZW1kJywgJy91c3IvbGliZXhlYy9zdHJvbmdzd2FuL2NoYXJvbi1zeXN0ZW1kJykKICAgIHJldHVy'
    'biBuZXh0KChwIGZvciBwIGluIGNhbmRpZGF0ZXMgaWYgUGF0aChwKS5pc19maWxlKCkpLCBOb25lKQoKCkVWR1RfVkVSU0lP'
    'TiA9ICcwLjMuMCcKRVZHVF9BU1NFVFMgPSB7CiAneDg2XzY0JzogKCdhbWQ2NCcsJ2ZkY2M5NGQ2NWVhNmMzZGE3NjhmNjY2'
    'NjAwMjE3ODNkYWE0NWMzNjU2Y2M5NDZiYWZkNTExMWE4NmJiMjg1YTYnKSwKICdhYXJjaDY0JzogKCdhcm02NCcsJzQzMzNj'
    'MWE3NGJhZGFiNjM4N2U4YTViYmYyZjFlMmY0ZjQwOWRhMjAzN2U5NGIzMmU4NDY2YjcwMDY4OGMwMmQnKSwKICdyaXNjdjY0'
    'JzogKCdyaXNjdjY0JywnZmMwYzE0YzBmYjRiZDBhZWMyMmQ3NzFiYWQyMTMxZjdhNWRmMDU5ZDZmN2ZiNTM3YzQ2NWYxZjJh'
    'ZTI1YTIxZicpLAp9CgpkZWYgZW5zdXJlX2V2Z3RfYmluYXJ5KCk6CiAgICBhc3NldD1FVkdUX0FTU0VUUy5nZXQocGxhdGZv'
    'cm0ubWFjaGluZSgpKQogICAgaWYgYXNzZXQgaXMgTm9uZTpyYWlzZSBSdW50aW1lRXJyb3IoJ2V2Z3RfYXJjaF91bnN1cHBv'
    'cnRlZCcpCiAgICBhcmNoLGRpZ2VzdD1hc3NldAogICAgcGF0aD1ST09ULygnZXZnZW5pdW0tdHVubmVsLScrRVZHVF9WRVJT'
    'SU9OKQogICAgaWYgcGF0aC5pc19zeW1saW5rKCk6cmFpc2UgUnVudGltZUVycm9yKCdldmd0X2JpbmFyeV9zeW1saW5rJykK'
    'ICAgIGlmIHBhdGguaXNfZmlsZSgpIGFuZCBoYXNobGliLnNoYTI1NihwYXRoLnJlYWRfYnl0ZXMoKSkuaGV4ZGlnZXN0KCk9'
    'PWRpZ2VzdDoKICAgICAgICBwYXRoLmNobW9kKDBvNzAwKTtyZXR1cm4gcGF0aAogICAgUk9PVC5ta2Rpcihtb2RlPTBvNzAw'
    'LHBhcmVudHM9VHJ1ZSxleGlzdF9vaz1UcnVlKQogICAgdXJsPSdodHRwczovL2dpdGh1Yi5jb20vdmVsaWtpaWV2Z2VuaXVz'
    'dWx0aW1hdGUvRXZnZW5pdW1fTmV0d29ya19MaW51eC9yZWxlYXNlcy9kb3dubG9hZC9ldmdlbml1bS10dW5uZWwtdicrRVZH'
    'VF9WRVJTSU9OKycvZXZnZW5pdW0tdHVubmVsLWxpbnV4LScrYXJjaAogICAgd2l0aCB1cmxsaWIucmVxdWVzdC51cmxvcGVu'
    'KHVybCx0aW1lb3V0PTMwKSBhcyByZXNwb25zZTpibG9iPXJlc3BvbnNlLnJlYWQoMTYqMTAyNCoxMDI0KzEpCiAgICBpZiBs'
    'ZW4oYmxvYik+MTYqMTAyNCoxMDI0IG9yIGhhc2hsaWIuc2hhMjU2KGJsb2IpLmhleGRpZ2VzdCgpIT1kaWdlc3Q6CiAgICAg'
    'ICAgcmFpc2UgUnVudGltZUVycm9yKCdldmd0X2JpbmFyeV9jaGVja3N1bV9mYWlsZWQnKQogICAgdG1wPXBhdGgud2l0aF9u'
    'YW1lKHBhdGgubmFtZSsnLm5ldycpCiAgICBmZD1vcy5vcGVuKHRtcCxvcy5PX1dST05MWXxvcy5PX0NSRUFUfG9zLk9fVFJV'
    'TkN8b3MuT19OT0ZPTExPVywwbzcwMCkKICAgIHRyeToKICAgICAgICB3aXRoIG9zLmZkb3BlbihmZCwnd2InKSBhcyBvdXRw'
    'dXQ6b3V0cHV0LndyaXRlKGJsb2IpO291dHB1dC5mbHVzaCgpO29zLmZzeW5jKG91dHB1dC5maWxlbm8oKSkKICAgICAgICBv'
    'cy5jaG1vZCh0bXAsMG83MDApO29zLnJlcGxhY2UodG1wLHBhdGgpCiAgICBmaW5hbGx5OnRtcC51bmxpbmsobWlzc2luZ19v'
    'az1UcnVlKQogICAgcmV0dXJuIHBhdGgKCgpkZWYgZW5zdXJlX2RlcGVuZGVuY2llcygpOgogICAgaWYgY2hhcm9uX2JpbmFy'
    'eSgpIGFuZCBhbGwoc2h1dGlsLndoaWNoKHApIGZvciBwIGluICgnc3dhbmN0bCcsJ2lwJywnbmZ0JywnY3VybCcsJ29wZW5z'
    'c2wnLCdjb25udHJhY2snKSk6CiAgICAgICAgZW5zdXJlX2V2Z3RfYmluYXJ5KCkKICAgICAgICByZXR1cm4KICAgIHN0YWdl'
    'KCdkZXBlbmRlbmNpZXMnLCAn0KPRgdGC0LDQvdCw0LLQu9C40LLQsNGOINC90LXQvtCx0YXQvtC00LjQvNGL0LUg0YHQuNGB'
    '0YLQtdC80L3Ri9C1INC60L7QvNC/0L7QvdC10L3RgtGLIFZQTi4nLCAzLCBhY3RpdmU9RmFsc2UpCiAgICBpZiBzaHV0aWwu'
    'd2hpY2goJ3BhY21hbicpOgogICAgICAgIGFyZ3MgPSBbJ3BhY21hbicsJy1TJywnLS1uZWVkZWQnLCctLW5vY29uZmlybScs'
    'J3N0cm9uZ3N3YW4nLCdpcHJvdXRlMicsJ25mdGFibGVzJywnY3VybCcsJ29wZW5zc2wnLCdjYS1jZXJ0aWZpY2F0ZXMnLCdj'
    'b25udHJhY2stdG9vbHMnXQogICAgZWxpZiBzaHV0aWwud2hpY2goJ2RuZicpOgogICAgICAgIGFyZ3MgPSBbJ2RuZicsJ2lu'
    'c3RhbGwnLCcteScsJy0tc2V0b3B0PWluc3RhbGxfd2Vha19kZXBzPUZhbHNlJywnc3Ryb25nc3dhbicsJ2lwcm91dGUnLCdu'
    'ZnRhYmxlcycsJ2N1cmwnLCdvcGVuc3NsJywnY2EtY2VydGlmaWNhdGVzJywnY29ubnRyYWNrLXRvb2xzJ10KICAgIGVsc2U6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCfQkNCy0YLQvtC80LDRgtC40YfQtdGB0LrQsNGPINGD0YHRgtCw0L3QvtCy'
    '0LrQsCDQutC70LjQtdC90YLQsCDQv9C+0LTQtNC10YDQttC40LLQsNC10YIgQXJjaCDQuCBGZWRvcmEuJykKICAgIGNvbW1h'
    'bmQoYXJncywgdGltZW91dD0zMDApCiAgICBpZiBub3QgY2hhcm9uX2JpbmFyeSgpIG9yIG5vdCBhbGwoc2h1dGlsLndoaWNo'
    'KHApIGZvciBwIGluICgnc3dhbmN0bCcsJ2Nvbm50cmFjaycpKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Cf0LDQ'
    'utC10YIgc3Ryb25nU3dhbiDQvdC1INC/0YDQtdC00L7RgdGC0LDQstC40Lsg0L3QtdC+0LHRhdC+0LTQuNC80YvQtSDQv9GA'
    '0L7Qs9GA0LDQvNC80YsuJykKICAgIGVuc3VyZV9ldmd0X2JpbmFyeSgpCgoKZGVmIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2'
    'aW91c192cG49RmFsc2UpOgogICAgIiIiRm9yZ2V0IG9ubHkgdGhpcyBtYW5hZ2VyJ3Mgb2Jzb2xldGUgRE5TIE5BVCwgbmV2'
    'ZXIgZmx1c2ggYWxsIGNvbm5lY3Rpb25zLgoKICAgIFJlbW92aW5nIGFuIG5mdCBOQVQgY2hhaW4gZG9lcyBub3QgcmVtb3Zl'
    'IGV4aXN0aW5nIGNvbm50cmFjayB0cmFuc2xhdGlvbnMuCiAgICBBIHJ1bm5pbmcgcmVzb2x2ZXIgY2FuIHJldXNlIGl0cyBV'
    'RFAgc29ja2V0IGluZGVmaW5pdGVseSBhZnRlciBhIFZQTiBzd2l0Y2guCiAgICAiIiIKICAgIGZpbHRlcnMgPSAoWyctLXJl'
    'cGx5LXBvcnQtc3JjJywnMTg1NTMnXSBpZiBwcmV2aW91c192cG4gZWxzZQogICAgICAgICAgICAgICBbJy0tcmVwbHktcG9y'
    'dC1zcmMnLCc1MycsJy0tZHN0LW5hdCcsJzEuMS4xLjEnXSkKICAgIGZvciBwcm90b2NvbCBpbiAoJ3VkcCcsJ3RjcCcpOgog'
    'ICAgICAgIHJlc3VsdCA9IGNvbW1hbmQoWydjb25udHJhY2snLCctRCcsJy1mJywnaXB2NCcsJy1wJyxwcm90b2NvbCwKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAnLS1kcG9ydCcsJzUzJywqZmlsdGVyc10sIGNoZWNrPUZhbHNlLAogICAgICAgICAg'
    'ICAgICAgICAgICAgICAgZW52PXsqKm9zLmVudmlyb24sJ0xDX0FMTCc6J0MnfSkKICAgICAgICBlbXB0eSA9IHJlc3VsdC5y'
    'ZXR1cm5jb2RlID09IDEgYW5kICcwIGZsb3cgZW50cmllcyBoYXZlIGJlZW4gZGVsZXRlZCcgaW4gcmVzdWx0LnN0ZGVycgog'
    'ICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2RlICE9IDAgYW5kIG5vdCBlbXB0eToKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdkbnNfdHJhbnNpdGlvbl9jbGVhbnVwX2ZhaWxlZCcpCgoKZGVmIGZ1bGxfZ3VhcmRfYWN0aXZlKCk6CiAgICBy'
    'ZXR1cm4gY29tbWFuZChbJ25mdCcsJ2xpc3QnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNoZWNrPUZhbHNlKS5yZXR1'
    'cm5jb2RlID09IDAKCgpkZWYgZnVsbF9maXJld2FsbCgpOgogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAgIHNl'
    'dHRpbmdzPXBvbGljeS5hcGkubG9hZF9zZXR0aW5ncygpCiAgICAgICAgcmV0dXJuIHBvbGljeS5maXJld2FsbChwb2xpY3ku'
    'bG9hZCgpLHBvbGljeS5sb2NhbF9uZXR3b3JrcyhwaHlzaWNhbF9yb3V0ZSgpKSxpbnQoc2V0dGluZ3NbInhyYXlfdWlkIl0p'
    'KQogICAgIyBNaW5pbWFsIGd1YXJkIHVzZWQgYnkgaXNvbGF0ZWQgcHJvdG9jb2wgdGVzdHMuCiAgICAjIEtlZXAgbG9jYWwg'
    'c3R1YiBETlMgb24gbG9vcGJhY2suIEROQVQgb2YgMTI3Lzggb250byBhIHZldGggZmFpbHMgTGludXgncwogICAgIyBsb29w'
    'YmFjayByb3V0ZSBjaGVja3M7IHVwc3RyZWFtIHJlc29sdmVyIHRyYWZmaWMgc3RpbGwgb2JleXMgdGhlIGZ1bGwgZ3VhcmQu'
    'CiAgICByZXR1cm4gZicnJ3RhYmxlIGluZXQge0ZVTExfR1VBUkR9IHt7CiBjaGFpbiBkbnMge3sgdHlwZSBuYXQgaG9vayBv'
    'dXRwdXQgcHJpb3JpdHkgLTEwMTsgcG9saWN5IGFjY2VwdDsKICBpcCBkYWRkciAxMjcuMC4wLjAvOCByZXR1cm4KICBpcCBk'
    'YWRkciB7eyAxLjEuMS4xLCA5LjkuOS45IH19IHJldHVybgogIG1ldGEgbmZwcm90byBpcHY0IG1ldGEgbDRwcm90byB7eyB0'
    'Y3AsIHVkcCB9fSB0aCBkcG9ydCA1MyBkbmF0IGlwIHRvIDEuMS4xLjEKIH19CiBjaGFpbiBzb3VyY2Uge3sgdHlwZSBuYXQg'
    'aG9vayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lm'
    'bmFtZSAie0ZVTExfSE9TVH0iIHNuYXQgaXAgdG8gMTcyLjI5LjI0Ny4xCiB9fQogY2hhaW4gb3V0cHV0IHt7IHR5cGUgZmls'
    'dGVyIGhvb2sgb3V0cHV0IHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgb2lmbmFtZSAibG8iIGFjY2VwdAogIG1ldGEg'
    'bmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hPU1R9IiBhY2NlcHQKICBpcCBkYWRkciAyNTUuMjU1LjI1NS4yNTUgdWRw'
    'IHNwb3J0IDY4IHVkcCBkcG9ydCA2NyBhY2NlcHQKIH19CiBjaGFpbiBmb3J3YXJkIHt7IHR5cGUgZmlsdGVyIGhvb2sgZm9y'
    'd2FyZCBwcmlvcml0eSAtMzA7IHBvbGljeSBkcm9wOwogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAg'
    'ZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBz'
    'YWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHVkcCBkcG9ydCA0NDMgYWNjZXB0CiAgaWlmbmFtZSAie0hP'
    'U1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1Nzgg'
    'fX0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAxOTUuMjA5LjIxMS4xNjMg'
    'dGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgc2FkZHIge0NMSUVOVH0gaXAgZGFkZHIge3sg'
    'e1NFUlZFUn0gfX0gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgb2lmbmFtZSAie0hPU1R9IiBpcCBkYWRkciB7Q0xJRU5UfSBj'
    'dCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IG9pZm5hbWUgIntGVUxMX0hP'
    'U1R9IiBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBpaWZuYW1lICJ7RlVMTF9IT1NUfSIgY3Qgc3RhdGUgZXN0YWJsaXNo'
    'ZWQscmVsYXRlZCBhY2NlcHQKIH19Cn19JycnCgoKCmRlZiByZWZyZXNoX3JldGFpbmVkX2d1YXJkKCk6CiAgICAiIiJNb3Zl'
    'IG9ubHkgdGhlIFZQTiB0cmFuc3BvcnQgZXhjZXB0aW9uIHdoZW4gYW4gaW5ncmVzcyBlbmRwb2ludCBjaGFuZ2VzLiIiIgog'
    'ICAgaWYgbm90IGZ1bGxfZ3VhcmRfYWN0aXZlKCk6CiAgICAgICAgcmV0dXJuCiAgICBydWxlcyA9IGZ1bGxfZmlyZXdhbGwo'
    'KQogICAgcmVwbGFjZW1lbnQgPSAnZGVsZXRlIHRhYmxlIGluZXQgJytGVUxMX0dVQVJEKydcbicrcnVsZXMKICAgIGNvbW1h'
    'bmQoWyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICAjIFBlcnNpc3QgdGhlIGNsb3NlZCBndWFy'
    'ZCBiZWZvcmUgY2hhbmdpbmcgdGhlIGFjdGl2ZSBleGNlcHRpb247IGEgY3Jhc2ggc3RheXMgY2xvc2VkLgogICAgd3JpdGUo'
    'Uk9PVC8nZnVsbC1ndWFyZC5uZnQnLHJ1bGVzKQogICAgY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1l'
    'bnQpCgoKZGVmIHZpcnR1YWxfaXAoKToKICAgIGRhdGEgPSBqc29uLmxvYWRzKGluc2lkZShbJ2lwJywnLWonLCctNCcsJ2Fk'
    'ZHInXSkuc3Rkb3V0KQogICAgaXBzID0gW2FbJ2xvY2FsJ10gZm9yIGxpbmsgaW4gZGF0YSBmb3IgYSBpbiBsaW5rLmdldCgn'
    'YWRkcl9pbmZvJywgW10pCiAgICAgICAgICAgaWYgaXBhZGRyZXNzLmlwX2FkZHJlc3MoYVsnbG9jYWwnXSkgaW4gaXBhZGRy'
    'ZXNzLmlwX25ldHdvcmsoJzEwLjc3LjAuMC8yNCcpXQogICAgaWYgbGVuKGlwcykgIT0gMToKICAgICAgICByYWlzZSBSdW50'
    'aW1lRXJyb3IoJ3ZpcnR1YWxfaXBfbWlzc2luZycpCiAgICByZXR1cm4gaXBzWzBdCgoKZGVmIGZ1bGxfbmFtZXNwYWNlKGFk'
    'ZHJlc3MpOgogICAgdmlwID0gdmlydHVhbF9pcCgpCiAgICBpZiBub3QgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hP'
    'U1QpLmV4aXN0cygpOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdhZGQnLEZVTExfSE9TVCwndHlwZScsJ3ZldGgn'
    'LCdwZWVyJywnbmFtZScsRlVMTF9QRUVSXSkKICAgICAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX1BFRVIs'
    'J25ldG5zJyxOU10pCiAgICBjb21tYW5kKFsnaXAnLCdhZGRyJywncmVwbGFjZScsJzE3Mi4yOS4yNDcuMS8zMCcsJ2Rldics'
    'RlVMTF9IT1NUXSkKICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfSE9TVCwnbXR1JywnMTI4MCcsJ3VwJ10p'
    'CiAgICBpbnNpZGUoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4yLzMwJywnZGV2JyxGVUxMX1BFRVJdKQog'
    'ICAgaW5zaWRlKFsnaXAnLCdsaW5rJywnc2V0JyxGVUxMX1BFRVIsJ210dScsJzEyODAnLCd1cCddKQogICAgaW5zaWRlKFsn'
    'c3lzY3RsJywnLXF3JywnbmV0LmlwdjQuY29uZi5hbGwuZm9yd2FyZGluZz0xJywnbmV0LmlwdjQuY29uZi5hbGwucnBfZmls'
    'dGVyPTAnXSkKICAgICMgU3Ryb25nU3dhbidzIGNhdGNoLWFsbCByb3V0ZSBtdXN0IG5vdCBjYXB0dXJlIHJlcGxpZXMgdG8g'
    'dGhlIGhvc3QtZmFjaW5nIGludGVyZmFjZS4KICAgIGluc2lkZShbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnOTAn'
    'LCd0bycsRlVMTF9ORVQsJ2xvb2t1cCcsJ21haW4nXSxjaGVjaz1GYWxzZSkKICAgIGluc2lkZShbJ2lwJywncnVsZScsJ2Fk'
    'ZCcsJ3ByaW9yaXR5JywnOTAnLCd0bycsRlVMTF9ORVQsJ2xvb2t1cCcsJ21haW4nXSkKICAgIGRlbGV0aW9ucyA9ICcnCiAg'
    'ICBmb3IgZmFtaWx5LHRhYmxlIGluIFsoJ2luZXQnLCdldm5fZnVsbF9mb3J3YXJkJyksKCduZXRkZXYnLCdldm5fZnVsbF93'
    'aXJlJyldOgogICAgICAgIGlmIGluc2lkZShbJ25mdCcsJ2xpc3QnLCd0YWJsZScsZmFtaWx5LHRhYmxlXSxjaGVjaz1GYWxz'
    'ZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICBkZWxldGlvbnMgKz0gZidkZWxldGUgdGFibGUge2ZhbWlseX0ge3Rh'
    'YmxlfVxuJwogICAgcnVsZXMgPSBkZWxldGlvbnMgKyBmJycndGFibGUgaW5ldCBldm5fZnVsbF9mb3J3YXJkIHt7CiBjaGFp'
    'biBmb3J3YXJkIHt7IHR5cGUgZmlsdGVyIGhvb2sgZm9yd2FyZCBwcmlvcml0eSAtNTsgcG9saWN5IGRyb3A7CiAgaWlmbmFt'
    'ZSAie0ZVTExfUEVFUn0iIG9pZm5hbWUgIntQRUVSfSIgaXAgc2FkZHIgMTcyLjI5LjI0Ny4xIGFjY2VwdAogIGlpZm5hbWUg'
    'e3sgIntQRUVSfSIsICJsbyIgfX0gb2lmbmFtZSAie0ZVTExfUEVFUn0iIGlwIGRhZGRyIDE3Mi4yOS4yNDcuMSBpcHNlYyBp'
    'biByZXFpZCB7UkVRSUR9IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiB9fQogY2hhaW4gbmF0IHt7IHR5'
    'cGUgbmF0IGhvb2sgcG9zdHJvdXRpbmcgcHJpb3JpdHkgc3JjbmF0OyBwb2xpY3kgYWNjZXB0OwogIGlwIHNhZGRyIDE3Mi4y'
    'OS4yNDcuMSBvaWZuYW1lICJ7UEVFUn0iIHNuYXQgaXAgdG8ge3ZpcH0KIH19Cn19CnRhYmxlIG5ldGRldiBldm5fZnVsbF93'
    'aXJlIHt7CiBjaGFpbiBlZ3Jlc3Mge3sgdHlwZSBmaWx0ZXIgaG9vayBlZ3Jlc3MgZGV2aWNlICJ7UEVFUn0iIHByaW9yaXR5'
    'IDA7IHBvbGljeSBkcm9wOwogIGV0aGVyIHR5cGUgYXJwIGFjY2VwdAogIGlwIGRhZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQg'
    'e0FDVElWRVsncG9ydCddfSBhY2NlcHQKICBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1'
    'NzggfX0gYWNjZXB0CiAgaXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9ydCAyNDU3OSBhY2NlcHQKICBpcCBkYWRk'
    'ciB7YWRkcmVzc30gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiB9fQp9fScnJwogICAgaW5zaWRlKFsnbmZ0JywnLWMnLCctZics'
    'Jy0nXSxkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1ydWxlcykKICAgICMgUmVwbGFjZSB0'
    'aGUgb3JpZ2luYWwgbGFiIGZvcndhcmQgZHJvcDsgaG9zdCBpbmdyZXNzIHJlbWFpbnMgY29uc3RyYWluZWQgYnkgZnVsbF9m'
    'b3J3YXJkLgogICAgaW5zaWRlKFsnbmZ0JywnZmx1c2gnLCdjaGFpbicsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdm'
    'b3J3YXJkJ10pCiAgICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxlJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2Zv'
    'cndhcmQnLCdpaWZuYW1lJyxGVUxMX1BFRVIsJ21ldGEnLCduZnByb3RvJywnaXB2NCcsJ2FjY2VwdCddKQogICAgaW5zaWRl'
    'KFsnbmZ0JywnYWRkJywncnVsZScsJ2luZXQnLCdldm5fc3RhcmZpdmVfZ3VhcmQnLCdmb3J3YXJkJywnb2lmbmFtZScsRlVM'
    'TF9QRUVSLCdpcHNlYycsJ2luJywncmVxaWQnLHN0cihSRVFJRCksJ2N0Jywnc3RhdGUnLCdlc3RhYmxpc2hlZCxyZWxhdGVk'
    'JywnYWNjZXB0J10pCgoKX0VHUkVTU19QUk9CRVMgPSAoJ2h0dHBzOi8vMS4xLjEuMS9jZG4tY2dpL3RyYWNlJywgJ2h0dHBz'
    'Oi8vYXBpLmlwaWZ5Lm9yZycpCl9lZ3Jlc3NfcHJlZmVycmVkID0gMAoKCmRlZiBwYXJzZV9leGl0KGJvZHksIHRyYWNlKToK'
    'ICAgIHZhbHVlcyA9IFtsaW5lWzM6XSBmb3IgbGluZSBpbiBib2R5LnNwbGl0bGluZXMoKSBpZiBsaW5lLnN0YXJ0c3dpdGgo'
    'J2lwPScpXSBpZiB0cmFjZSBlbHNlIFtib2R5LnN0cmlwKCldCiAgICBpZiBsZW4odmFsdWVzKSAhPSAxOgogICAgICAgIHJl'
    'dHVybiBOb25lCiAgICB0cnk6CiAgICAgICAgcmV0dXJuIHN0cihpcGFkZHJlc3MuSVB2NEFkZHJlc3ModmFsdWVzWzBdKSkK'
    'ICAgIGV4Y2VwdCBpcGFkZHJlc3MuQWRkcmVzc1ZhbHVlRXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYgZWdyZXNz'
    'X2hlYWx0aCgpOgogICAgIiIiSW5kZXBlbmRlbnQgSFRUUFMgcHJvdmlkZXJzOyBhIHZlcmlmaWVkIHdyb25nIElQIG11c3Qg'
    'bmV2ZXIgYmUgbWFza2VkIGJ5IGZhbGxiYWNrLiIiIgogICAgZ2xvYmFsIF9lZ3Jlc3NfcHJlZmVycmVkCiAgICBmb3IgaW5k'
    'ZXggaW4gKF9lZ3Jlc3NfcHJlZmVycmVkLCAxLV9lZ3Jlc3NfcHJlZmVycmVkKToKICAgICAgICB1cmwgPSBfRUdSRVNTX1BS'
    'T0JFU1tpbmRleF0KICAgICAgICB0cnk6CiAgICAgICAgICAgIHJlc3VsdCA9IGluc2lkZShbJ2N1cmwnLCctNCcsJy0tbm9w'
    'cm94eScsJyonLCctLWZhaWwnLCctLXNpbGVudCcsJy0tc2hvdy1lcnJvcicsCiAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgJy0tY29ubmVjdC10aW1lb3V0JywnMycsJy0tbWF4LXRpbWUnLCc1JywnLS1tYXgtZmlsZXNpemUnLCczMjc2OCcsdXJs'
    'XSx0aW1lb3V0PTcsY2hlY2s9RmFsc2UpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGly'
    'ZWQpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIHJlc3VsdC5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgICAg'
    'IGNvbnRpbnVlCiAgICAgICAgb2JzZXJ2ZWQgPSBwYXJzZV9leGl0KHJlc3VsdC5zdGRvdXQsIGluZGV4ID09IDApCiAgICAg'
    'ICAgaWYgb2JzZXJ2ZWQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIGlmIG9ic2VydmVkICE9ICczOC4xODAuMTY0LjY3JzoK'
    'ICAgICAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgICAgICBfZWdyZXNzX3ByZWZlcnJlZCA9IGluZGV4CiAgICAg'
    'ICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgcGF0aF9oZWFsdGh5KGRhZW1vbik6CiAgICAjIFRo'
    'ZSBwcml2YXRlIGRpYWdub3N0aWMgSFRUUCBjb2xsZWN0b3IgaXMgbm90IHBhcnQgb2YgdGhlIFZQTiBkYXRhIHBsYW5lLgog'
    'ICAgIyBJdHMgb3V0YWdlL3Jlc3RhcnQgbXVzdCBub3QgZGlzY2FyZCBhIHdvcmtpbmcgcm91dGUncyB0aHJlZS1sb3NzIGJ1'
    'ZGdldC4KICAgIHJldHVybiAoZGFlbW9uLnBvbGwoKSBpcyBOb25lIGFuZCBpbnN0YWxsZWQoKQogICAgICAgICAgICBhbmQg'
    'KFRMU19QUk9DRVNTIGlzIE5vbmUgb3IgVExTX1BST0NFU1MucG9sbCgpIGlzIE5vbmUpIGFuZCBlZ3Jlc3NfaGVhbHRoKCkp'
    'CgoKZGVmIHJldGlyZV9wcmV2aW91c19jb25uZWN0aW9ucyhhZGRyZXNzZXMpOgogICAgIyBUaGUgZmlyZXdhbGwgYWxyZWFk'
    'eSBibG9ja3Mgb2xkIG5vbi1leGVtcHQgZmxvd3MuIERvIG5vdCBraWxsIGFsbCBzb2NrZXRzCiAgICAjIHNoYXJpbmcgYSBw'
    'aHlzaWNhbCBzb3VyY2UgYWRkcmVzczogdGhhdCBkZXN0cm95cyBTU0gsIExBTiBhbmQgYXBwIGV4Y2x1c2lvbnMuCiAgICAj'
    'IE9ubHkgdGhpcyBtYW5hZ2VyJ3MgRE5TIHRyYW5zbGF0aW9ucyBuZWVkIGV4cGxpY2l0IHJldGlyZW1lbnQgKGhhbmRsZWQg'
    'YWJvdmUpLgogICAgcmV0dXJuCgoKZGVmIHN5c3RlbV9kbnNfaGVhbHRoKHJlc29sdl9jb25mPVBhdGgoJy9ldGMvcmVzb2x2'
    'LmNvbmYnKSk6CiAgICAjIGdldGFkZHJpbmZvL2N1cmwgbWF5IHVzZSBuc3MtcmVzb2x2ZSBvdmVyIGEgVW5peCBzb2NrZXQg'
    'YW5kIG1pc3MgYSBicm9rZW4KICAgICMgVURQIHN0dWIgdXNlZCBieSBvdGhlciBhcHBsaWNhdGlvbnMuIEV4ZXJjaXNlIHJl'
    'c29sdi5jb25mIGluZGVwZW5kZW50bHkuCiAgICBzZXJ2ZXJzID0gW2xpbmUuc3BsaXQoKVsxXSBmb3IgbGluZSBpbiByZXNv'
    'bHZfY29uZi5yZWFkX3RleHQoKS5zcGxpdGxpbmVzKCkKICAgICAgICAgICAgICAgaWYgbGluZS5zcGxpdCgpWzoxXSA9PSBb'
    'J25hbWVzZXJ2ZXInXSBhbmQgbGVuKGxpbmUuc3BsaXQoKSkgPj0gMl1bOjNdCiAgICBmb3Igc2VydmVyIGluIHNlcnZlcnM6'
    'CiAgICAgICAgdHJ5OgogICAgICAgICAgICBmYW1pbHkgPSBzb2NrZXQuQUZfSU5FVDYgaWYgaXBhZGRyZXNzLmlwX2FkZHJl'
    'c3Moc2VydmVyKS52ZXJzaW9uID09IDYgZWxzZSBzb2NrZXQuQUZfSU5FVAogICAgICAgICAgICB0cmFuc2FjdGlvbiA9IHNl'
    'Y3JldHMudG9rZW5fYnl0ZXMoMikKICAgICAgICAgICAgcXVlcnkgPSB0cmFuc2FjdGlvbitiJ1x4MDFceDAwXHgwMFx4MDFc'
    'eDAwXHgwMFx4MDBceDAwXHgwMFx4MDAnCiAgICAgICAgICAgIHF1ZXJ5ICs9IGInXHgwM2FwaVx4MDVpcGlmeVx4MDNvcmdc'
    'eDAwXHgwMFx4MDFceDAwXHgwMScKICAgICAgICAgICAgd2l0aCBzb2NrZXQuc29ja2V0KGZhbWlseSwgc29ja2V0LlNPQ0tf'
    'REdSQU0pIGFzIHJlc29sdmVyOgogICAgICAgICAgICAgICAgcmVzb2x2ZXIuc2V0dGltZW91dCgyKQogICAgICAgICAgICAg'
    'ICAgcmVzb2x2ZXIuY29ubmVjdCgoc2VydmVyLCA1MykpCiAgICAgICAgICAgICAgICByZXNvbHZlci5zZW5kKHF1ZXJ5KQog'
    'ICAgICAgICAgICAgICAgYW5zd2VyID0gcmVzb2x2ZXIucmVjdig0MDk2KQogICAgICAgICAgICBpZiAobGVuKGFuc3dlcikg'
    'Pj0gMTIgYW5kIGFuc3dlcls6Ml0gPT0gdHJhbnNhY3Rpb24gYW5kCiAgICAgICAgICAgICAgICAgICAgYW5zd2VyWzJdICYg'
    'MHg4MCBhbmQgYW5zd2VyWzNdICYgMTUgPT0gMCBhbmQKICAgICAgICAgICAgICAgICAgICBpbnQuZnJvbV9ieXRlcyhhbnN3'
    'ZXJbNjo4XSwgJ2JpZycpID4gMCk6CiAgICAgICAgICAgICAgICByZXR1cm4gVHJ1ZQogICAgICAgIGV4Y2VwdCAoT1NFcnJv'
    'ciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgc3RhcnRfbmFtZXNw'
    'YWNlX2RucygpOgogICAgIiIiQSBwcml2YXRlIEROUyBlbmRwb2ludCByZWFjaGFibGUgb25seSBvdmVyIHRoZSBob3N0L25h'
    'bWVzcGFjZSB2ZXRoLiIiIgogICAgZ2xvYmFsIEROU19QUk9DRVNTCiAgICBpZiBETlNfUFJPQ0VTUyBpcyBub3QgTm9uZSBh'
    'bmQgRE5TX1BST0NFU1MucG9sbCgpIGlzIE5vbmU6cmV0dXJuCiAgICBjZmcgPSB7J2xvZyc6eydsb2dsZXZlbCc6J3dhcm5p'
    'bmcnLCdhY2Nlc3MnOidub25lJ30sCiAgICAgICdpbmJvdW5kcyc6W3sndGFnJzonZG5zLWluJywnbGlzdGVuJzonMTcyLjI5'
    'LjI0Ny4yJywncG9ydCc6NTMsJ3Byb3RvY29sJzonZG9rb2RlbW8tZG9vcicsCiAgICAgICAgICAgICAgICAgICAnc2V0dGlu'
    'Z3MnOnsnYWRkcmVzcyc6JzEuMS4xLjEnLCdwb3J0Jzo1MywnbmV0d29yayc6J3RjcCx1ZHAnfX1dLAogICAgICAnZG5zJzp7'
    'J3NlcnZlcnMnOlsnMS4xLjEuMScsJ3RjcDovLzkuOS45LjknLCdodHRwczovLzEuMC4wLjEvZG5zLXF1ZXJ5J10sCiAgICAg'
    'ICAgICAgICAncXVlcnlTdHJhdGVneSc6J1VzZUlQdjQnLCd0YWcnOidkbnMtZW5naW5lJywnZW5hYmxlUGFyYWxsZWxRdWVy'
    'eSc6VHJ1ZX0sCiAgICAgICdvdXRib3VuZHMnOlt7J3RhZyc6J3dpcmUnLCdwcm90b2NvbCc6J2ZyZWVkb20nfSwKICAgICAg'
    'ICAgICAgICAgICAgIHsndGFnJzonZG5zJywncHJvdG9jb2wnOidkbnMnLCdzZXR0aW5ncyc6eydydWxlcyc6W3sncVR5cGUn'
    'OicxLDI4JywnYWN0aW9uJzonaGlqYWNrJ30seydhY3Rpb24nOidkaXJlY3QnfV19fV0sCiAgICAgICdyb3V0aW5nJzp7J3J1'
    'bGVzJzpbeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1pbiddLCdvdXRib3VuZFRhZyc6J2Rucyd9LAogICAg'
    'ICAgICAgICAgICAgICAgICAgICAgIHsndHlwZSc6J2ZpZWxkJywnaW5ib3VuZFRhZyc6WydkbnMtZW5naW5lJ10sJ291dGJv'
    'dW5kVGFnJzond2lyZSd9XX19CiAgICBwYXRoPVJPT1QvJ25hbWVzcGFjZS1kbnMuanNvbic7d3JpdGUocGF0aCxqc29uLmR1'
    'bXBzKGNmZykpCiAgICBiaW5hcnk9Jy9vcHQvdnBuLW1hbmFnZXIvYmluL3hyYXknCiAgICBpbnNpZGUoW2JpbmFyeSwncnVu'
    'JywnLXRlc3QnLCctY29uZmlnJyxwYXRoXSkKICAgIEROU19QUk9DRVNTPXN1YnByb2Nlc3MuUG9wZW4oWydpcCcsJ25ldG5z'
    'JywnZXhlYycsTlMsYmluYXJ5LCdydW4nLCctY29uZmlnJyxzdHIocGF0aCldLAogICAgICAgIHN0ZGluPXN1YnByb2Nlc3Mu'
    'REVWTlVMTCxzdGRvdXQ9c3VicHJvY2Vzcy5ERVZOVUxMLHN0ZGVycj1zdWJwcm9jZXNzLkRFVk5VTEwpCiAgICBmb3IgXyBp'
    'biByYW5nZSgzMCk6CiAgICAgICAgaWYgRE5TX1BST0NFU1MucG9sbCgpIGlzIG5vdCBOb25lOnJhaXNlIFJ1bnRpbWVFcnJv'
    'cigncHJpdmF0ZV9kbnNfc3RvcHBlZCcpCiAgICAgICAgaWYgJzE3Mi4yOS4yNDcuMjo1MycgaW4gaW5zaWRlKFsnc3MnLCct'
    'bG51J10sY2hlY2s9RmFsc2UpLnN0ZG91dDoKICAgICAgICAgICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNv'
    'bHYuY29uZicsJ25hbWVzZXJ2ZXIgMTcyLjI5LjI0Ny4yXG5vcHRpb25zIHRpbWVvdXQ6MyBhdHRlbXB0czoyXG4nKQogICAg'
    'ICAgICAgICByZXR1cm4KICAgICAgICB0aW1lLnNsZWVwKC4xKQogICAgcmFpc2UgUnVudGltZUVycm9yKCdwcml2YXRlX2Ru'
    'c19ub3RfcmVhZHknKQoKCmRlZiB1c2VfcmVzb2x2ZXJfZmlsZShwYXRoPVBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKSk6CiAg'
    'ICBkYXRhPWpzb24ubG9hZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgdGFyZ2V0PVJPT1QvJ3Jlc29sdi12cG4u'
    'Y29uZicKICAgIGlmICdyZXNvbHZlcl9vcmlnaW5hbCcgbm90IGluIGRhdGE6CiAgICAgICAgZGF0YVsncmVzb2x2ZXJfb3Jp'
    'Z2luYWwnXT17J2xpbmsnOm9zLnJlYWRsaW5rKHBhdGgpIGlmIHBhdGguaXNfc3ltbGluaygpIGVsc2UgTm9uZSwKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAndGV4dCc6cGF0aC5yZWFkX3RleHQoKSBpZiBwYXRoLmV4aXN0cygpIGVs'
    'c2UgJycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2V4aXN0ZWQnOnBhdGguZXhpc3RzKCkgb3IgcGF0'
    'aC5pc19zeW1saW5rKCl9CiAgICBkYXRhWydkbnNfZmFsbGJhY2snXT1UcnVlCiAgICB3cml0ZShmdWxsX3N0YXRlKCksanNv'
    'bi5kdW1wcyhkYXRhKSkKICAgIHdyaXRlKHRhcmdldCwnbmFtZXNlcnZlciAxNzIuMjkuMjQ3LjJcbm9wdGlvbnMgdGltZW91'
    'dDozIGF0dGVtcHRzOjJcbicpCiAgICB0YXJnZXQuY2htb2QoMG82NDQpCiAgICAjIFRoZSBwYXJlbnQgbXVzdCBiZSB0cmF2'
    'ZXJzYWJsZSBieSBhcHBsaWNhdGlvbnMuIFNlY3JldHMgcmVtYWluIHJvb3Qtb25seS4KICAgICMgUHV0IG9ubHkgdGhpcyBw'
    'dWJsaWMgcmVzb2x2ZXIgZmlsZSBvdXRzaWRlIHRoZSBjcmVkZW50aWFsIGRpcmVjdG9yeS4KICAgIHB1YmxpYz1QYXRoKCcv'
    'cnVuL2V2Z2VuaXVtLXJlc29sdi5jb25mJykKICAgIHB1YmxpYy5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVlLGV4aXN0X29r'
    'PVRydWUpCiAgICB3cml0ZShwdWJsaWMsdGFyZ2V0LnJlYWRfdGV4dCgpKTtwdWJsaWMuY2htb2QoMG82NDQpCiAgICB0ZW1w'
    'b3Jhcnk9cGF0aC53aXRoX25hbWUoJy5ldmdlbml1bS1yZXNvbHYubmV3JykKICAgIHRlbXBvcmFyeS51bmxpbmsobWlzc2lu'
    'Z19vaz1UcnVlKTt0ZW1wb3Jhcnkuc3ltbGlua190byhwdWJsaWMpCiAgICBvcy5yZXBsYWNlKHRlbXBvcmFyeSxwYXRoKQoK'
    'CmRlZiByZXN0b3JlX3Jlc29sdmVyX2ZpbGUoZGF0YSxwYXRoPVBhdGgoJy9ldGMvcmVzb2x2LmNvbmYnKSk6CiAgICBzYXZl'
    'ZD1kYXRhLmdldCgncmVzb2x2ZXJfb3JpZ2luYWwnKQogICAgaWYgc2F2ZWQgYW5kIHBhdGguaXNfc3ltbGluaygpIGFuZCBv'
    'cy5yZWFkbGluayhwYXRoKT09Jy9ydW4vZXZnZW5pdW0tcmVzb2x2LmNvbmYnOgogICAgICAgIHRlbXBvcmFyeT1wYXRoLndp'
    'dGhfbmFtZSgnLmV2Z2VuaXVtLXJlc29sdi5yZXN0b3JlJykKICAgICAgICB0ZW1wb3JhcnkudW5saW5rKG1pc3Npbmdfb2s9'
    'VHJ1ZSkKICAgICAgICBpZiBzYXZlZFsnbGluayddIGlzIG5vdCBOb25lOnRlbXBvcmFyeS5zeW1saW5rX3RvKHNhdmVkWyds'
    'aW5rJ10pCiAgICAgICAgZWxzZTp0ZW1wb3Jhcnkud3JpdGVfdGV4dChzYXZlZFsndGV4dCddKTt0ZW1wb3JhcnkuY2htb2Qo'
    'MG82NDQpCiAgICAgICAgaWYgc2F2ZWQuZ2V0KCdleGlzdGVkJyxUcnVlKTpvcy5yZXBsYWNlKHRlbXBvcmFyeSxwYXRoKQog'
    'ICAgICAgIGVsc2U6cGF0aC51bmxpbmsoKTt0ZW1wb3JhcnkudW5saW5rKCkKICAgIGVsaWYgbm90IHNhdmVkIGFuZCAnZG5z'
    'X2JhY2t1cCcgaW4gZGF0YToKICAgICAgICBwYXRoLndyaXRlX3RleHQoZGF0YVsnZG5zX2JhY2t1cCddKQoKCmRlZiByZWNv'
    'dmVyX3N5c3RlbV9kbnMoKToKICAgIGZvciBfIGluIHJhbmdlKDIpOgogICAgICAgIGlmIHN5c3RlbV9kbnNfaGVhbHRoKCk6'
    'cmV0dXJuIFRydWUKICAgICAgICBpZiBTVE9QOnJldHVybiBGYWxzZQogICAgICAgIHRpbWUuc2xlZXAoLjMpCiAgICBpZiBu'
    'b3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOnJldHVybiBGYWxzZQogICAgIyBTd2l0Y2ggb25seSB0aGUgcmVzb2x2ZXIgZmls'
    'ZSB3ZSBvd247IG5ldmVyIHN0b3AgYW5vdGhlciBWUE4gb3IgcmVzb2x2ZXIuCiAgICBzdGFnZSgncmVwYWlyaW5nJywn0J/Q'
    'tdGA0LXQutC70Y7Rh9Cw0Y4g0L3QtdC40YHQv9GA0LDQstC90YvQuSDRgdC40YHRgtC10LzQvdGL0LkgRE5TINC90LAg0LfQ'
    'sNGJ0LjRidGR0L3QvdGL0Lkg0YDQtdC30LXRgNCyLicsOTAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9J3N5c3RlbV9kbnNf'
    'ZmFpbGVkJykKICAgIHVzZV9yZXNvbHZlcl9maWxlKCkKICAgIHJldHVybiBzeXN0ZW1fZG5zX2hlYWx0aCgpCgoKZGVmIHBl'
    'cnNpc3RfZ3VhcmQocnVsZXMpOgogICAgIyBHdWFyZCBwZXJzaXN0ZW5jZSBwcmVjZWRlcyBzd2l0Y2hpbmcuIENsZWFudXAg'
    'YWZ0ZXIgYSBjcmFzaCBuZXZlciBvcGVucyB0aGUgSW50ZXJuZXQuCiAgICBndWFyZF91bml0ID0gJycnW1VuaXRdCkRlc2Ny'
    'aXB0aW9uPUV2Z2VuaXVtIGZ1bGwtZGV2aWNlIGtpbGwgc3dpdGNoCkRlZmF1bHREZXBlbmRlbmNpZXM9bm8KQWZ0ZXI9bG9j'
    'YWwtZnMudGFyZ2V0CkJlZm9yZT1uZXR3b3JrLXByZS50YXJnZXQKW1NlcnZpY2VdClR5cGU9b25lc2hvdApSZW1haW5BZnRl'
    'ckV4aXQ9eWVzCkV4ZWNTdGFydD0vdXNyL3NiaW4vbmZ0IC1mIC9ldGMvdnBuLW1hbmFnZXIvc3RhcmZpdmUtdHVubmVsL2Z1'
    'bGwtZ3VhcmQubmZ0CltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAonJycucmVwbGFjZSgnL3Vzci9zYmlu'
    'L25mdCcsIHNodXRpbC53aGljaCgnbmZ0JykpCiAgICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5mdCcscnVsZXMpCiAgICB3'
    'cml0ZShQYXRoKCcvZXRjL3N5c3RlbWQvc3lzdGVtL2V2Z2VuaXVtLXN0YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZScpLGd1'
    'YXJkX3VuaXQpCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywnZGFlbW9uLXJlbG9hZCddKQogICAgY29tbWFuZChbJ3N5c3Rl'
    'bWN0bCcsJ2VuYWJsZScsJ2V2Z2VuaXVtLXN0YXJmaXZlLWZ1bGwtZ3VhcmQuc2VydmljZSddKQoKCmRlZiBhY3RpdmF0ZV9m'
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
    'bHNlfSkpCiAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAgc3RhcnRfbmFtZXNwYWNlX2RucygpCiAgICAjIFZhbGlk'
    'YXRlIHRoZSBlZ3Jlc3MgZmlsdGVyIGJlZm9yZSBpbnRlcnJ1cHRpbmcgdGhlIHByZXZpb3VzIFZQTi4KICAgIGlmIG5vdCBl'
    'Z3Jlc3NfaGVhbHRoKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdlc3RvbmlhX2VncmVzc19mYWlsZWQnKQogICAg'
    'cnVsZXMgPSBmdWxsX2ZpcmV3YWxsKCkKICAgICMgUmVwYWlyIG1heSBpbmhlcml0IGEgZ3VhcmQgZnJvbSBhbiBvbGRlciB2'
    'ZXJzaW9uLiBSZXBsYWNlIG91ciB0YWJsZSBpbgogICAgIyBvbmUgbmZ0IHRyYW5zYWN0aW9uLCBzbyBmaXhlcyBhcHBseSB3'
    'aXRob3V0IG9wZW5pbmcgYW4gdW5ndWFyZGVkIHdpbmRvdy4KICAgIHJlcGxhY2VtZW50ID0gKCdkZWxldGUgdGFibGUgaW5l'
    'dCAnK0ZVTExfR1VBUkQrJ1xuJyBpZiBmdWxsX2d1YXJkX2FjdGl2ZSgpIGVsc2UgJycpK3J1bGVzCiAgICBjb21tYW5kKFsn'
    'bmZ0JywnLWMnLCctZicsJy0nXSxkYXRhPXJlcGxhY2VtZW50KQogICAgY29tbWFuZChbJ25mdCcsJy1mJywnLSddLGRhdGE9'
    'cmVwbGFjZW1lbnQpCiAgICBwZXJzaXN0X2d1YXJkKHJ1bGVzKQogICAgIyBUaGlzIGNvbW1hbmQgc3RvcHMgb25seSB0aGlz'
    'IG1hbmFnZXIncyBwcmV2aW91cyBYcmF5IG1vZGUgYW5kIHJlbW92ZXMgaXRzIGd1YXJkLgogICAgY29tbWFuZChbJy91c3Iv'
    'bG9jYWwvc2Jpbi92cG5jdGwnLCdpbnRlcm5hbC1zdGFyZml2ZS1wYXVzZS1tYWluJ10sdGltZW91dD00MCkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ3JvdXRlJywncmVwbGFjZScsJ3VucmVhY2hhYmxlJywnZGVmYXVsdCcsJ21ldHJpYycsJzMyNzYwJywndGFi'
    'bGUnLEZVTExfVEFCTEVdKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywnZGVmYXVsdCcsJ3ZpYScsJzE3'
    'Mi4yOS4yNDcuMicsJ2RldicsRlVMTF9IT1NULCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSkKICAgIGNvbW1h'
    'bmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkK'
    'ICAgIGZvciBydWxlIGluIChbJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sCiAg'
    'ICAgICAgICAgICAgICAgWydwcmlvcml0eScsJzc5JywnaWlmJyxGVUxMX0hPU1QsJ2xvb2t1cCcsJ21haW4nXSk6CiAgICAg'
    'ICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsKnJ1bGVdLGNoZWNrPUZhbHNlKQogICAgICAgIGNvbW1hbmQoWydpcCcs'
    'J3J1bGUnLCdhZGQnLCpydWxlXSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzgwJywnbG9v'
    'a3VwJyxGVUxMX1RBQkxFXSkKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBpZiBz'
    'aHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBhbmQgY29tbWFuZChbJ3N5c3RlbWN0bCcsJ2lzLWFjdGl2ZScsJy0tcXVpZXQn'
    'LCdzeXN0ZW1kLXJlc29sdmVkJ10sY2hlY2s9RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICBkYXRhWydkbnNfbW9k'
    'ZSddPSdyZXNvbHZlZF9saW5rJwogICAgICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgICAg'
    'IGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZG5zJyxGVUxMX0hPU1QsJzE3Mi4yOS4yNDcuMiddKQogICAgICAgIGNvbW1hbmQo'
    'WydyZXNvbHZlY3RsJywnZG9tYWluJyxGVUxMX0hPU1QsJ34uJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdk'
    'ZWZhdWx0LXJvdXRlJyxGVUxMX0hPU1QsJ3llcyddKQogICAgICAgIGNvbW1hbmQoWydyZXNvbHZlY3RsJywnZmx1c2gtY2Fj'
    'aGVzJ10sY2hlY2s9RmFsc2UpCiAgICBlbHNlOgogICAgICAgIHVzZV9yZXNvbHZlcl9maWxlKCkKICAgIGNsZWFyX2Ruc19t'
    'YXBwaW5ncyhwcmV2aW91c192cG49VHJ1ZSkKICAgIHJldGlyZV9wcmV2aW91c19jb25uZWN0aW9ucyhvbGRfYWRkcmVzc2Vz'
    'KQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAgIHBvbGljeS5hcHBseSgpCiAgICBpZiBub3QgcmVjb3Zlcl9z'
    'eXN0ZW1fZG5zKCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdzeXN0ZW1fZG5zX2ZhaWxlZCcpCiAgICAjIFRlc3Qg'
    'dGhlIGFjdHVhbCBob3N0IHBhdGggYXMgd2VsbCBhcyBuYW1lc3BhY2UgcHJvYmVzIGJlZm9yZSBhbm5vdW5jaW5nIGNvbm5l'
    'Y3RlZC4KICAgIGNoZWNrID0gY29tbWFuZChbJ2N1cmwnLCctNCcsJy0tbm9wcm94eScsJycgaWYgcG9saWN5IGlzIG5vdCBO'
    'b25lIGVsc2UgJyonLCctLWZhaWwnLCctLXNpbGVudCcsJy0tbWF4LXRpbWUnLCcxMCcsKihbJy0tc29ja3M1LWhvc3RuYW1l'
    'JywnMTI3LjAuMC4xOjE4NTU0J10gaWYgcG9saWN5IGlzIG5vdCBOb25lIGVsc2UgW10pLCdodHRwczovL2FwaS5pcGlmeS5v'
    'cmcnXSx0aW1lb3V0PTEyKQogICAgaWYgY2hlY2suc3Rkb3V0LnN0cmlwKCkgIT0gJzM4LjE4MC4xNjQuNjcnOgogICAgICAg'
    'IHJhaXNlIFJ1bnRpbWVFcnJvcignaG9zdF9lZ3Jlc3NfZmFpbGVkJykKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRl'
    'KCkucmVhZF90ZXh0KCkpCiAgICBkYXRhWydhY3RpdmUnXT1UcnVlCiAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1w'
    'cyhkYXRhKSkKCgpkZWYgY2xlYW51cF9mdWxsKHJlbGVhc2U9RmFsc2UpOgogICAgZ2xvYmFsIEROU19QUk9DRVNTCiAgICBp'
    'ZiBETlNfUFJPQ0VTUyBpcyBub3QgTm9uZSBhbmQgRE5TX1BST0NFU1MucG9sbCgpIGlzIE5vbmU6CiAgICAgICAgRE5TX1BS'
    'T0NFU1MudGVybWluYXRlKCkKICAgICAgICB0cnk6RE5TX1BST0NFU1Mud2FpdCh0aW1lb3V0PTMpCiAgICAgICAgZXhjZXB0'
    'IHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQ6RE5TX1BST0NFU1Mua2lsbCgpO0ROU19QUk9DRVNTLndhaXQoKQogICAgRE5T'
    'X1BST0NFU1M9Tm9uZQogICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOgogICAgICAgIHBvbGljeS5zdG9wKHJlbGVhc2U9cmVs'
    'ZWFzZSkKICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuCiAgICBkYXRhPWpzb24ubG9h'
    'ZHMoZnVsbF9zdGF0ZSgpLnJlYWRfdGV4dCgpKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdkZWwnLCdkZWZhdWx0Jywn'
    'bWV0cmljJywnMTAnLCd0YWJsZScsRlVMTF9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdsaW5rJywn'
    'ZGVsJyxGVUxMX0hPU1RdLGNoZWNrPUZhbHNlKQogICAgIyBPbiBmYWlsdXJlOiByZXRhaW4gcm91dGluZywgRE5TIGFuZCB0'
    'aGUgcGVyc2lzdGVudCBndWFyZCB1bnRpbCBleHBsaWNpdCBkaXNjb25uZWN0LgogICAgaWYgbm90IHJlbGVhc2U6CiAgICAg'
    'ICAgcmV0dXJuCiAgICByZXN0b3JlX3Jlc29sdmVyX2ZpbGUoZGF0YSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwn'
    'LCdwcmlvcml0eScsJzgwJywnbG9va3VwJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcsJ3J1'
    'bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLENMSUVOVCsnLzMyJywnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNl'
    'KQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCdpaWYnLEZVTExfSE9TVCwnbG9va3Vw'
    'JywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdmbHVzaCcsJ3RhYmxlJyxGVUxMX1RB'
    'QkxFXSxjaGVjaz1GYWxzZSkKICAgIGZvciBzZXJ2ZXIgaW4gKCcxOTIuMTY4LjAuMTYzJywgJzM4LjE4MC4xNjQuNjcnKToK'
    'ICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ3RvJyxzZXJ2ZXIsJ2lwcHJvdG8n'
    'LCd0Y3AnLCdkcG9ydCcsJzIyJywnbG9va3VwJyxBRE1JTl9UQUJMRV0sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnc3lz'
    'dGVtY3RsJywnZGlzYWJsZScsJy0tbm93JywnZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJ10sY2hlY2s9'
    'RmFsc2UpCiAgICBjb21tYW5kKFsnbmZ0JywnZGVsZXRlJywndGFibGUnLCdpbmV0JyxGVUxMX0dVQVJEXSxjaGVjaz1GYWxz'
    'ZSkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncygpCiAgICBjbGVhcl9kbnNfbWFwcGluZ3MocHJldmlvdXNfdnBuPVRydWUpCiAg'
    'ICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGZ1'
    'bGxfc3RhdGUoKS51bmxpbmsoKQogICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdmbHVzaC1jYWNoZXMnXSxjaGVjaz1GYWxz'
    'ZSkgaWYgc2h1dGlsLndoaWNoKCdyZXNvbHZlY3RsJykgZWxzZSBOb25lCgoKZGVmIGNvbW1hbmQoYXJncywgY2hlY2s9VHJ1'
    'ZSwgdGltZW91dD0yMCwgZGF0YT1Ob25lLCBlbnY9Tm9uZSk6CiAgICBjcCA9IHN1YnByb2Nlc3MucnVuKFtzdHIoeCkgZm9y'
    'IHggaW4gYXJnc10sIGlucHV0PWRhdGEsIHRleHQ9VHJ1ZSwgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwKICAgICAgICAgICAgICAg'
    'ICAgICAgICAgdGltZW91dD10aW1lb3V0LCBlbnY9ZW52LCBjaGVjaz1GYWxzZSkKICAgIGlmIGNoZWNrIGFuZCBjcC5yZXR1'
    'cm5jb2RlOgogICAgICAgICMgQXJndW1lbnRzIG1heSBjb250YWluIGEgQ1NSIHBhdGg7IGRvIG5vdCBwcm9wYWdhdGUgcHJv'
    'Y2VzcyBvdXRwdXQgdG8gR1VJL2xvZ3MuCiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdjb21tYW5kX2ZhaWxlZCcpCiAg'
    'ICByZXR1cm4gY3AKCgpkZWYgaW5zaWRlKGFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBjb21tYW5kKFsnaXAnLCAnbmV0'
    'bnMnLCAnZXhlYycsIE5TLCAqYXJnc10sICoqa3dhcmdzKQoKCmRlZiB3cml0ZShwYXRoLCB2YWx1ZSk6CiAgICBwYXRoLnBh'
    'cmVudC5ta2RpcihwYXJlbnRzPVRydWUsIG1vZGU9MG83MDAsIGV4aXN0X29rPVRydWUpCiAgICB0ZW1wb3JhcnkgPSBwYXRo'
    'LndpdGhfc3VmZml4KCcubmV3JykKICAgIGZkID0gb3Mub3Blbih0ZW1wb3JhcnksIG9zLk9fV1JPTkxZIHwgb3MuT19DUkVB'
    'VCB8IG9zLk9fVFJVTkMgfCBvcy5PX05PRk9MTE9XLCAwbzYwMCkKICAgIHdpdGggb3MuZmRvcGVuKGZkLCAndycpIGFzIHN0'
    'cmVhbToKICAgICAgICBzdHJlYW0ud3JpdGUodmFsdWUpCiAgICB0ZW1wb3JhcnkucmVwbGFjZShwYXRoKQoKCmRlZiBzYXZl'
    'ZCgpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBqc29uLmxvYWRzKFNUQVRFLnJlYWRfdGV4dCgpKQogICAgZXhjZXB0IChP'
    'U0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICByZXR1cm4ge30KCgpkZWYgc3RhZ2UocGhhc2UsIG1lc3NhZ2UsIHByb2dy'
    'ZXNzLCAqKmZpZWxkcyk6CiAgICBkYXRhID0geyoqc2F2ZWQoKSwgJ3BoYXNlJzogcGhhc2UsICdtZXNzYWdlJzogbWVzc2Fn'
    'ZSwgJ3Byb2dyZXNzJzogcHJvZ3Jlc3MsCiAgICAgICAgICAgICd1cGRhdGVkJzogaW50KHRpbWUudGltZSgpKSwgJ2hlYXJ0'
    'YmVhdCc6IHRpbWUubW9ub3RvbmljKCksICoqZmllbGRzfQogICAgd3JpdGUoU1RBVEUsIGpzb24uZHVtcHMoZGF0YSwgZW5z'
    'dXJlX2FzY2lpPUZhbHNlKSkKICAgIGlmIHN1cHBvcnRfYXBpIGlzIG5vdCBOb25lOgogICAgICAgIHRyeTpzdXBwb3J0X2Fw'
    'aS5yZWNvcmQoUk9PVCx3cml0ZSxkYXRhKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFR5cGVFcnJvcik6'
    'cGFzcwoKCmRlZiBzdGF0dXMoKToKICAgIGRhdGEgPSBzYXZlZCgpCiAgICBydW5uaW5nID0gY29tbWFuZChbJ3N5c3RlbWN0'
    'bCcsICdpcy1hY3RpdmUnLCAnLS1xdWlldCcsIFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0yKS5yZXR1cm5jb2RlID09'
    'IDAKICAgIGlmIGRhdGEuZ2V0KCdwaGFzZScpID09ICdjb25uZWN0ZWQnIGFuZCAobm90IHJ1bm5pbmcgb3IgdGltZS5tb25v'
    'dG9uaWMoKS1kYXRhLmdldCgnaGVhcnRiZWF0JywgMCkgPiA5MCk6CiAgICAgICAgZGF0YS51cGRhdGUocGhhc2U9J2ludGVy'
    'cnVwdGVkJywgbWVzc2FnZT0n0KHQvtC10LTQuNC90LXQvdC40LUg0L7RgdGC0LDQvdC+0LLQuNC70L7RgdGMLiDQn9GA0L7Q'
    'stC10YDRjNGC0LUg0YHQvtGB0YLQvtGP0L3QuNC1INC30LDRidC40YLRiyDQuCDQvdCw0LbQvNC40YLQtSDCq9Cf0L7Rh9C4'
    '0L3QuNGC0YzCuy4nLCBhY3RpdmU9RmFsc2UpCiAgICBwdWJsaWMgPSB7a2V5OiBkYXRhW2tleV0gZm9yIGtleSBpbiAoJ3Bo'
    'YXNlJywgJ21lc3NhZ2UnLCAncHJvZ3Jlc3MnLCAnYWN0aXZlJywgJ3VwZGF0ZWQnLCAnbWV0cmljcycsCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnc2NvcGUnLCAnc2luY2UnLCAncmV0cnknLCAnZXJyb3JfY29kZScsICdw'
    'YXRoJykgaWYga2V5IGluIGRhdGF9CiAgICB0b2tlbl9pbmZvID0gdG9rZW5fc3RhdHVzKCkKICAgIHJldHVybiB7J3BoYXNl'
    'JzogJ29mZicsICdtZXNzYWdlJzogKCfQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/Q'
    'vtC00LrQu9GO0YfQuNGC0YzCuy4nIGlmIHRva2VuX2luZm9bJ2hhc190b2tlbiddIGVsc2UgJ9CS0LLQtdC00LjRgtC1INC4'
    'INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKSwKICAgICAgICAgICAgJ3Byb2dy'
    'ZXNzJzogMCwgJ2FjdGl2ZSc6IEZhbHNlLCAqKnB1YmxpYywgJ3J1bm5pbmcnOiBydW5uaW5nLAogICAgICAgICAgICAqKnRv'
    'a2VuX2luZm8sICoqZGV2aWNlX3N0YXR1cygpLCAnaXNvbGF0ZWQnOiBGYWxzZSwgJ2Z1bGxfZGV2aWNlJzogVHJ1ZSwgJ2d1'
    'YXJkJzogZnVsbF9ndWFyZF9hY3RpdmUoKSwgJ3Byb3RvY29sJzogJ0lLRXYyIOKGkiDQrdGB0YLQvtC90LjRjyd9CgoKQGNv'
    'bnRleHRsaWIuY29udGV4dG1hbmFnZXIKZGVmIG5hbWVzcGFjZSgpOgogICAgYmVmb3JlID0gb3Mub3BlbignL3Byb2Mvc2Vs'
    'Zi9ucy9uZXQnLCBvcy5PX1JET05MWSkKICAgIHRhcmdldCA9IG9zLm9wZW4oJy9ydW4vbmV0bnMvJytOUywgb3MuT19SRE9O'
    'TFkpCiAgICB0cnk6CiAgICAgICAgb3Muc2V0bnModGFyZ2V0LCBvcy5DTE9ORV9ORVdORVQpCiAgICAgICAgeWllbGQKICAg'
    'IGZpbmFsbHk6CiAgICAgICAgb3Muc2V0bnMoYmVmb3JlLCBvcy5DTE9ORV9ORVdORVQpCiAgICAgICAgb3MuY2xvc2UodGFy'
    'Z2V0KQogICAgICAgIG9zLmNsb3NlKGJlZm9yZSkKCgpkZWYgcGh5c2ljYWxfcm91dGUoKToKICAgIHJvdXRlcyA9IGpzb24u'
    'bG9hZHMoY29tbWFuZChbJ2lwJywgJy1qJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUnLCAnbWFpbicsICdkZWZh'
    'dWx0J10pLnN0ZG91dCkKICAgIGNhbmRpZGF0ZXMgPSBbciBmb3IgciBpbiByb3V0ZXMgaWYgci5nZXQoJ2dhdGV3YXknKSBh'
    'bmQgci5nZXQoJ2RldicpIGFuZAogICAgICAgICAgICAgICAgICBub3QgclsnZGV2J10uc3RhcnRzd2l0aCgoJ3R1bicsICd4'
    'cmF5JywgJ3dnJywgJ2V2bi0nKSldCiAgICBpZiBub3QgY2FuZGlkYXRlczoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3Io'
    'J25vX3BoeXNpY2FsX3JvdXRlJykKICAgIHJvdXRlID0gbWluKGNhbmRpZGF0ZXMsIGtleT1sYW1iZGEgcjogci5nZXQoJ21l'
    'dHJpYycsIDApKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyJ1tBLVphLXowLTlfLjotXXsxLDE1fScsIHJvdXRlWydkZXYn'
    'XSk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX2ludGVyZmFjZScpCiAgICBpcGFkZHJlc3MuSVB2NEFk'
    'ZHJlc3Mocm91dGVbJ2dhdGV3YXknXSkKICAgIHJldHVybiByb3V0ZQoKCmRlZiBob3N0X3J1bGVzKGlmYWNlLCBwcmV2aW91'
    'c19mb3J3YXJkPVRydWUpOgogICAgIyBTY29wZSBldmVyeSBuZXcgZm9yd2FyZGluZy9OQVQgcnVsZSB0byBvdXIgb25lIGlu'
    'dGVyZmFjZSBhbmQgdGhlIGNvbmZpZ3VyZWQgaW5ncmVzcyBhZGRyZXNzLgogICAgcHJlc2VydmVfZGlzYWJsZWQgPSAnJyBp'
    'ZiBwcmV2aW91c19mb3J3YXJkIGVsc2UgJycnICBpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IGFjY2Vw'
    'dAogIG9pZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBh'
    'Y2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBkcm9wJycnCiAgICByZXR1cm4gZicnJ3RhYmxlIGluZXQge05GVH0ge3sKIGNo'
    'YWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTIwOyBwb2xpY3kgYWNjZXB0Owog'
    'IGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0CiAg'
    'aWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHVkcCBkcG9ydCA0NDMg'
    'YWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRjcCBk'
    'cG9ydCB7eyAyNDU3MSwgMjQ1NzggfX0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBk'
    'YWRkciAxOTUuMjA5LjIxMS4xNjMgdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIg'
    'e3sge1NFUlZFUn0gfX0gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBkcm9wCiAgb2lmbmFtZSAi'
    'e0hPU1R9IiBpcCBzYWRkciB7eyB7U0VSVkVSfSwgMzguMTgwLjE2NC42NyB9fSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxyZWxh'
    'dGVkIGFjY2VwdAogIG9pZm5hbWUgIntIT1NUfSIgZHJvcAp7cHJlc2VydmVfZGlzYWJsZWR9CiB9fQogY2hhaW4gbmF0IHt7'
    'CiAgdHlwZSBuYXQgaG9vayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2FkZHIg'
    'e0NMSUVOVH0gb2lmbmFtZSAie2lmYWNlfSIgbWFzcXVlcmFkZQogfX0KfX0nJycKCgpkZWYgc2V0dXBfbmV0d29yaygpOgog'
    'ICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAjIFJlZnVzZSBuYW1lL2FkZHJlc3MgY29sbGlzaW9ucyByYXRoZXIg'
    'dGhhbiByZXB1cnBvc2luZyBhbm90aGVyIGFwcGxpY2F0aW9uJ3MgcmVzb3VyY2VzLgogICAgaWYgUGF0aCgnL3J1bi9uZXRu'
    'cy8nK05TKS5leGlzdHMoKSBvciBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0hPU1QpLmV4aXN0cygpIG9yIChQYXRoKCcvZXRj'
    'L25ldG5zJykvTlMpLmV4aXN0cygpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF9uYW1lc3BhY2VfZXhpc3Rz'
    'JykKICAgIGlmIGNvbW1hbmQoWydpcCcsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgc3RyKFRBQkxFKV0sIGNo'
    'ZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfdGFibGVfaW5fdXNl'
    'JykKICAgIGlmIGFueShORVRXT1JLIGluIGxpbmUgZm9yIGxpbmUgaW4gY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRlJywg'
    'J3Nob3cnLCAndGFibGUnLCAnYWxsJ10pLnN0ZG91dC5zcGxpdGxpbmVzKCkpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cigndGVzdF9uZXR3b3JrX2luX3VzZScpCiAgICBvbGRfZm9yd2FyZCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9m'
    'b3J3YXJkJykucmVhZF90ZXh0KCkuc3RyaXAoKQogICAgIyBSZWNvcmQgb3duZXJzaGlwIGJlZm9yZSBjcmVhdGluZyBhbnl0'
    'aGluZzogY2xlYW51cCBpcyB2YWxpZCBhZnRlciBldmVyeSBwYXJ0aWFsIHN0ZXAuCiAgICB1cGxpbmsgPSBQYXRoKCcvcHJv'
    'Yy9zeXMvbmV0L2lwdjQvY29uZicpL3JvdXRlWydkZXYnXS8nZm9yd2FyZGluZycKICAgIHdyaXRlKFJPT1QvJ25ldHdvcmsu'
    'anNvbicsIGpzb24uZHVtcHMoeydmb3J3YXJkJzogb2xkX2ZvcndhcmQsICdpbnRlcmZhY2UnOiByb3V0ZVsnZGV2J10sICd1'
    'cGxpbmtfZm9yd2FyZCc6IHVwbGluay5yZWFkX3RleHQoKS5zdHJpcCgpfSkpCiAgICBjb21tYW5kKFsnaXAnLCAnbmV0bnMn'
    'LCAnYWRkJywgTlNdKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicsICduYW1lc2VydmVy'
    'IDEuMS4xLjFcbm5hbWVzZXJ2ZXIgOS45LjkuOVxub3B0aW9ucyB0aW1lb3V0OjIgYXR0ZW1wdHM6MlxuJykKICAgICMgbnNz'
    'LXJlc29sdmUgdGFsa3MgdG8gdGhlIGhvc3QgZGFlbW9uIG92ZXIgYSBVbml4IHNvY2tldCBldmVuIGluc2lkZSBuZXRucy4K'
    'ICAgIG5zcz1QYXRoKCcvZXRjL25zc3dpdGNoLmNvbmYnKS5yZWFkX3RleHQoKQogICAgbnNzPXJlLnN1YihyJ15ob3N0czou'
    'KiQnLCAnaG9zdHM6IGZpbGVzIGRucycsIG5zcywgZmxhZ3M9cmUuTSkKICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMnKS9O'
    'Uy8nbnNzd2l0Y2guY29uZicsIG5zcykKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2FkZCcsIEhPU1QsICd0eXBlJywg'
    'J3ZldGgnLCAncGVlcicsICduYW1lJywgUEVFUl0pCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdzZXQnLCBQRUVSLCAn'
    'bmV0bnMnLCBOU10pCiAgICBjb21tYW5kKFsnaXAnLCAnYWRkcicsICdhZGQnLCBHQVRFV0FZKycvMzAnLCAnZGV2JywgSE9T'
    'VF0pCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdzZXQnLCBIT1NULCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywgJ2Fk'
    'ZHInLCAnYWRkJywgQ0xJRU5UKycvMzAnLCAnZGV2JywgUEVFUl0pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3NldCcs'
    'IFBFRVIsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQnLCAnbG8nLCAndXAnXSkKICAgIGluc2lkZShb'
    'J2lwJywgJ3JvdXRlJywgJ2FkZCcsICdkZWZhdWx0JywgJ3ZpYScsIEdBVEVXQVldKQogICAgIyBBIHJlY29ubmVjdCBjcmVh'
    'dGVzIGEgTkVXIFRDUCBzb2NrZXQgYWZ0ZXIgSUtFIGluc3RhbGxzIGl0cyBkZWZhdWx0IHJvdXRlLgogICAgIyBLZWVwIHRo'
    'ZSByZWxheSBzb2NrZXQgb24gdGhlIG5hbWVzcGFjZSB1cGxpbmsgd2l0aCB0aGUgcGh5c2ljYWwgdmV0aCBzb3VyY2U7CiAg'
    'ICAjIG90aGVyd2lzZSBzb3VyY2Ugc2VsZWN0aW9uIGdpdmVzIGl0IHRoZSBWUE4gVklQIGFuZCB0dW5uZWxzIGl0IGludG8g'
    'aXRzZWxmLgogICAgaWYgQUNUSVZFLmdldCgndHJhbnNwb3J0X2FkZHJlc3MnKToKICAgICAgICBpbnNpZGUoWydpcCcsJ3J1'
    'bGUnLCdhZGQnLCdwcmlvcml0eScsJzg5JywndG8nLEFDVElWRVsndHJhbnNwb3J0X2FkZHJlc3MnXSsnLzMyJywKICAgICAg'
    'ICAgICAgICAgICdpcHByb3RvJywndGNwJywnZHBvcnQnLHN0cihBQ1RJVkVbJ3RyYW5zcG9ydF9wb3J0J10pLCdsb29rdXAn'
    'LCdtYWluJ10pCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywgc3RyKFRBQkxFKSwgJ2RlZmF1'
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
    'ICAgKFJPT1QvJ25ldHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKCgpkZWYgdGxzX3JlcXVlc3QoYWRk'
    'cmVzcywgcGF0aCwgYm9keT1Ob25lLCBjbGllbnQ9RmFsc2UsIHRpbWVvdXQ9OCwgaWRlbnRpdHk9U0VSVkVSKToKICAgIGNv'
    'bnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgaWYgY2xpZW50OgogICAg'
    'ICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQta2V5'
    'LnBlbScpKQogICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9dGlt'
    'ZW91dCkKICAgIHRyeToKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFtZT1p'
    'ZGVudGl0eSkKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgIHNvY2suY2xvc2UoKQogICAgICAgIHJhaXNlCiAg'
    'ICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oYWRkcmVzcywgODQ0MywgdGltZW91dD10aW1lb3V0'
    'KQogICAgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAgICBlbmNvZGVkID0ganNvbi5kdW1wcyhib2R5LCBzZXBhcmF0b3JzPSgn'
    'LCcsICc6JykpLmVuY29kZSgpIGlmIGJvZHkgaXMgbm90IE5vbmUgZWxzZSBOb25lCiAgICB0cnk6CiAgICAgICAgY29ubmVj'
    'dGlvbi5yZXF1ZXN0KCdQT1NUJyBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgJ0dFVCcsIHBhdGgsIGJvZHk9ZW5jb2RlZCwK'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVycz17J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJywg'
    'J0Nvbm5lY3Rpb24nOiAnY2xvc2UnfSkKICAgICAgICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQogICAg'
    'ICAgIHJhdyA9IHJlc3BvbnNlLnJlYWQoMjAwMDEpCiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBvciBsZW4o'
    'cmF3KSA+IDIwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlcXVlc3RfcmVqZWN0ZWQnKQogICAgICAg'
    'IHJldHVybiBqc29uLmxvYWRzKHJhdykKICAgIGZpbmFsbHk6CiAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCgoKZGVmIGVu'
    'cm9sbCgpOgogICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUuZnVs'
    'bG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2VuKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfdG9rZW4n'
    'KQogICAgdHJ5OgogICAgICAgIGNhY2hlZCA9IGpzb24ubG9hZHMoKFJPT1QvJ3Byb2ZpbGUuanNvbicpLnJlYWRfdGV4dCgp'
    'KQogICAgICAgIGlmIChjYWNoZWQuZ2V0KCdjYScpID09IFBJTk5FRF9DQSBhbmQgY2FjaGVkLmdldCgnc2VydmVyJykgPT0g'
    'U0VSVkVSIGFuZAogICAgICAgICAgICByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgY2FjaGVkLmdldCgn'
    'aWRlbnRpdHknLCAnJykpIGFuZAogICAgICAgICAgICBjYWNoZWQuZ2V0KCdlbmRwb2ludCcpIGluIEVORFBPSU5UUyBhbmQg'
    'Y2FjaGVkLmdldCgncGh5c2ljYWxfbmV0d29yaycpIGFuZAogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd4NTA5'
    'JywgJy1pbicsIFJPT1QvJ2NsaWVudC5wZW0nLCAnLWNoZWNrZW5kJywgc3RyKDcqODY0MDApLCAnLW5vb3V0J10sIGNoZWNr'
    'PUZhbHNlKS5yZXR1cm5jb2RlID09IDApOgogICAgICAgICAgICBjb250ZXh0ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RP'
    'Q09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVt'
    'JyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkKICAg'
    'ICAgICAgICAgY3VycmVudCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtl'
    'eSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0'
    'KCkKICAgICAgICAgICAgYWRkcmVzcyA9IGNhY2hlZFsnZW5kcG9pbnQnXSBpZiBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9uZXR3'
    'b3JrJykgPT0gY3VycmVudCBlbHNlIFNFUlZFUgogICAgICAgICAgICByZXR1cm4gY2FjaGVkWydpZGVudGl0eSddLCBhZGRy'
    'ZXNzCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAgICAgICAgcGFzcwogICAgc3Rh'
    'Z2UoJ3Rva2VuJywgJ9Cf0L7Qu9GD0YfQsNGOINGB0LXRgNGC0LjRhNC40LrQsNGCINC00LvRjyDRjdGC0L7Qs9C+INGD0YHR'
    'gtGA0L7QudGB0YLQstCwLicsIDI1KQogICAgaWYgbm90IChST09ULydjbGllbnQta2V5LnBlbScpLmV4aXN0cygpOgogICAg'
    'ICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ2dlbnBrZXknLCAnLWFsZ29yaXRobScsICdSU0EnLCAnLXBrZXlvcHQnLCAncnNh'
    'X2tleWdlbl9iaXRzOjMwNzInLAogICAgICAgICAgICAgICAgICctb3V0JywgUk9PVC8nY2xpZW50LWtleS5wZW0nXSwgdGlt'
    'ZW91dD0zMCkKICAgICAgICAoUk9PVC8nY2xpZW50LWtleS5wZW0nKS5jaG1vZCgwbzYwMCkKICAgIGlmIG5vdCAoUk9PVC8n'
    'ZGV2aWNlJykuZXhpc3RzKCk6CiAgICAgICAgd3JpdGUoUk9PVC8nZGV2aWNlJywgc2VjcmV0cy50b2tlbl9oZXgoMTYpKQog'
    'ICAgY29tbWFuZChbJ29wZW5zc2wnLCAncmVxJywgJy1uZXcnLCAnLWtleScsIFJPT1QvJ2NsaWVudC1rZXkucGVtJywgJy1z'
    'dWJqJywgJy9DTj1ldmdlbml1bS1kZXZpY2UnLAogICAgICAgICAgICAgJy1vdXQnLCBST09ULydyZXF1ZXN0LnBlbSddKQog'
    'ICAgcGF5bG9hZCA9IHsndG9rZW4nOiB0b2tlbiwgJ2RldmljZSc6IChST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5zdHJp'
    'cCgpLCAnY3NyJzogKFJPT1QvJ3JlcXVlc3QucGVtJykucmVhZF90ZXh0KCl9CiAgICBsYXN0ID0gTm9uZQogICAgZm9yIGFk'
    'ZHJlc3MgaW4gKFNFUlZFUiwpOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICAg'
    'ICAgICAgIHJlcGx5ID0gdGxzX3JlcXVlc3QoYWRkcmVzcywgJy9lbnJvbGwnLCBwYXlsb2FkLCB0aW1lb3V0PTYpCiAgICAg'
    'ICAgICAgIHByb2ZpbGUgPSByZXBseS5nZXQoJ3Byb2ZpbGUnLCB7fSkKICAgICAgICAgICAgaWYgcmVwbHkuZ2V0KCdvaycp'
    'IGlzIG5vdCBUcnVlIG9yIHByb2ZpbGUuZ2V0KCdjYScpICE9IFBJTk5FRF9DQSBvciBwcm9maWxlLmdldCgnc2VydmVyJykg'
    'IT0gU0VSVkVSOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX3Byb2ZpbGUnKQogICAgICAg'
    'ICAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInZGV2aWNlLVthLWYwLTldezI0fScsIHByb2ZpbGUuZ2V0KCdpZGVudGl0eScs'
    'ICcnKSk6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaWRlbnRpdHknKQogICAgICAgICAg'
    'ICB3cml0ZShST09ULydjbGllbnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUoUk9P'
    'VC8nY2EucGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULyd4NTA5Jy8nY2xpZW50LnBlbScsIHByb2Zp'
    'bGVbJ2NlcnRpZmljYXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDljYScvJ2NhLnBlbScsIFBJTk5FRF9DQSkK'
    'ICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJpdmF0ZScvJ2NsaWVudC1rZXkucGVtJywgKFJPT1QvJ2NsaWVudC1rZXkucGVt'
    'JykucmVhZF90ZXh0KCkpCiAgICAgICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3ZlcmlmeScsICctcHVycG9zZScsICdz'
    'c2xjbGllbnQnLCAnLUNBZmlsZScsIFJPT1QvJ2NhLnBlbScsIFJPT1QvJ2NsaWVudC5wZW0nXSkKICAgICAgICAgICAgY3R4'
    'ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGN0eC5sb2FkX2NlcnRfY2hh'
    'aW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJvdXRl'
    'ID0gcGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBmaW5nZXJwcmludCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMo'
    'e2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5'
    'cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJvZmlsZS5qc29uJywganNv'
    'bi5kdW1wcyh7Kipwcm9maWxlLCAnZW5kcG9pbnQnOiBhZGRyZXNzLCAncGh5c2ljYWxfbmV0d29yayc6IGZpbmdlcnByaW50'
    'fSkpCiAgICAgICAgICAgIHJldHVybiBwcm9maWxlWydpZGVudGl0eSddLCBhZGRyZXNzCiAgICAgICAgZXhjZXB0IChPU0Vy'
    'cm9yLCBzc2wuU1NMRXJyb3IsIFJ1bnRpbWVFcnJvcikgYXMgZXhjOgogICAgICAgICAgICBsYXN0ID0gZXhjCiAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ2Vucm9sbG1lbnRfdW5hdmFpbGFibGUnKSBmcm9tIGxhc3QKCgpkZWYgZGFlbW9uX2NvbmZpZ3Mo'
    'aWRlbnRpdHksIGFkZHJlc3MpOgogICAgUlVOVElNRS5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0X29r'
    'PVRydWUpCiAgICBpbmNsdWRlcyA9ICdcbicuam9pbignaW5jbHVkZSAnK3N0cihwKSBmb3IgcGF0dGVybiBpbiAoJy9ldGMv'
    'c3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYnLCAnL2V0Yy9zdHJvbmdzd2FuL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5jb25m'
    'JykKICAgICAgICAgICAgICAgICAgICAgICAgIGZvciBwIGluIFBhdGgoJy8nKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCcvJykp'
    'KQogICAgd3JpdGUoUk9PVC8nc3Ryb25nc3dhbi5jb25mJywgZicnJ2NoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0geWVzCiBp'
    'bnN0YWxsX3JvdXRlcyA9IHllcwogcm91dGluZ190YWJsZSA9IDUxODIyCiByb3V0aW5nX3RhYmxlX3ByaW8gPSAxMDAKIHBs'
    'dWdpbnMge3sKe2luY2x1ZGVzfQogIHZpY2kge3sgc29ja2V0ID0gdW5peDovL3tSVU5USU1FfS9jaGFyb24udmljaSB9fQog'
    'IHJlc29sdmUge3sgbG9hZCA9IG5vIH19CiAga2VybmVsLWxpYmlwc2VjIHt7IGxvYWQgPSBubyB9fQogfX0KfX0KY2hhcm9u'
    'LXN5c3RlbWQge3sgam91cm5hbCB7eyBkZWZhdWx0ID0gMDsgaWtlID0gMSB9fSB9fQonJycpCiAgICAjIEFic29sdXRlIGNy'
    'ZWRlbnRpYWxzIGFyZSBsb2NhbCB0byB0aGlzIGRldmljZSwgbm90IHNoYXJlZCBieSB0aGUgYWNjb3VudCB0b2tlbi4KICAg'
    'IHdyaXRlKFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicsIGYnJydjb25uZWN0aW9ucyB7ewogc3RhcmZpdmUge3sKICB2ZXJzaW9u'
    'ID0gMgogIHJlbW90ZV9hZGRycyA9IHthZGRyZXNzfQogIHJlbW90ZV9wb3J0ID0ge0FDVElWRVsncG9ydCddfQogIGxvY2Fs'
    'X3BvcnQgPSA0NTAwCiAgdmlwcyA9IDAuMC4wLjAKICBwcm9wb3NhbHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNwMzg0'
    'CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMTVzCiAg'
    'bG9jYWwge3sgYXV0aCA9IGVhcC10bHM7IGlkID0ge2lkZW50aXR5fTsgZWFwX2lkID0ge2lkZW50aXR5fTsgY2VydHMgPSB7'
    'Uk9PVH0vY2xpZW50LnBlbSB9fQogIHJlbW90ZSB7eyBhdXRoID0gcHVia2V5OyBpZCA9IHtBQ1RJVkVbJ2lkZW50aXR5J119'
    'OyBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbSB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5ldCB7ewogICAgbG9jYWxf'
    'dHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAgZXNwX3Byb3Bv'
    'c2FscyA9IGNoYWNoYTIwcG9seTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9uID0gbm9uZQog'
    'ICB9fQogIH19CiB9fQp9fQpzZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUgPSB7Uk9PVH0vY2xpZW50LWtleS5w'
    'ZW0gfX0gfX0KJycnKQogICAgIyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVzLCBub3Qgc2VtaWNvbG9uIHNlcGFy'
    'YXRvcnMgKG5vcm1hbGl6ZSBjb21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAoJ3N0cm9uZ3N3YW4uY29uZicsICdj'
    'b25uZWN0aW9uLmNvbmYnKToKICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAgcGF0aC53cml0ZV90ZXh0KHBhdGgu'
    'cmVhZF90ZXh0KCkucmVwbGFjZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4nKS5yZXBsYWNlKCcgfScsICdcbn0n'
    'KSkKICAgIHJ1bGVzID0gZicnJ3RhYmxlIGluZXQgZXZuX3N0YXJmaXZlX2d1YXJkIHt7CiBjaGFpbiBvdXRwdXQge3sKICB0'
    'eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2NlcHQK'
    'ICBpcCBkYWRkciAxMjcuMC4wLjEgdWRwIGRwb3J0IDI0NTczIGFjY2VwdAogIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBpcCBk'
    'YWRkciAxNzIuMjkuMjQ3LjEgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIHNwb3J0IDUzIGFjY2VwdAogIGlwIGRh'
    'ZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQge0FDVElWRVsncG9ydCddfSBhY2NlcHQKICBpcCBkYWRkciAzOC4xODAuMTY0LjY3'
    'IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1NzggfX0gYWNjZXB0CiAgaXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBkcG9y'
    'dCAyNDU3OSBhY2NlcHQKICBtZXRhIHNrdWlkIDAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2VwdAog'
    'IG1ldGEgbmZwcm90byBpcHY0IGlwc2VjIG91dCByZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sg'
    'dHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNpZGUo'
    'WyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwgZGF0'
    'YT1ydWxlcykKCgpkZWYgc3dhbigqYXJncywgdGltZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRlKFsn'
    'c3dhbmN0bCcsICphcmdzLCAnLS11cmknLCAndW5peDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1lb3V0'
    'PXRpbWVvdXQsIGNoZWNrPWNoZWNrKQoKCmRlZiBpbnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBzd2Fu'
    'KCctLWxpc3Qtc2FzJywgJy0tcmF3JywgdGltZW91dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0LnJl'
    'dHVybmNvZGUgPT0gMCBhbmQgJ3N0YXRlPUVTVEFCTElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5TVEFM'
    'TEVEJyBpbiByZXN1bHQuc3Rkb3V0CiAgICBleGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQpOgog'
    'ICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBoZWFsdGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0dXJu'
    'IHRsc19yZXF1ZXN0KEhFQUxUSCwgJy9oZWFsdGgnLCBjbGllbnQ9VHJ1ZSwgaWRlbnRpdHk9QUNUSVZFWydpZGVudGl0eSdd'
    'LCB0aW1lb3V0PTMpLmdldCgnc2VydmljZScpID09ICdldmdlbml1bS1zdGFyZml2ZScKCgpkZWYgZG93bmxvYWQoc2l6ZT0x'
    'MDQ4NTc2KToKICAgICMgQSBib3VuZGVkIGludGVncml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBtZWFzdXJlZCB0'
    'aGUgSVNQJ3MgbWF4aW11bSByYXRlLgogICAgYmxvY2sgPSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVtLXN0YXJmaXZl'
    'LWludGVncml0eS12MScpLmRpZ2VzdCg2NTUzNikKICAgIGV4cGVjdGVkID0gaGFzaGxpYi5zaGEyNTYoKGJsb2NrKihzaXpl'
    'Ly9sZW4oYmxvY2spKzEpKVs6c2l6ZV0pLmhleGRpZ2VzdCgpCiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0X2Nv'
    'bnRleHQoY2FkYXRhPVBJTk5FRF9DQSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVt'
    'JyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICBzb2NrID0gc29j'
    'a2V0LmNyZWF0ZV9jb25uZWN0aW9uKChIRUFMVEgsIDg0NDMpLCB0aW1lb3V0PTEwKQogICAgICAgIHRscyA9IGNvbnRleHQu'
    'd3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPUFDVElWRVsnaWRlbnRpdHknXSkKICAgICAgICBjb25uZWN0aW9u'
    'ID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oSEVBTFRILCA4NDQzLCB0aW1lb3V0PTEwKTsgY29ubmVjdGlvbi5zb2Nr'
    'ID0gdGxzCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdGFydCA9IHRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAgY29u'
    'bmVjdGlvbi5yZXF1ZXN0KCdHRVQnLCAnL2Jsb2I/c2l6ZT0nK3N0cihzaXplKSkKICAgICAgICAgICAgcmVzcG9uc2UgPSBj'
    'b25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMDoKICAgICAgICAg'
    'ICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndHJhbnNmZXJfaHR0cCcpCiAgICAgICAgICAgIGRpZ2VzdCA9IGhhc2hsaWIu'
    'c2hhMjU2KCk7IHJlY2VpdmVkID0gMAogICAgICAgICAgICB3aGlsZSByZWNlaXZlZCA8IHNpemU6CiAgICAgICAgICAgICAg'
    'ICBkYXRhID0gcmVzcG9uc2UucmVhZChtaW4oNjU1MzYsIHNpemUtcmVjZWl2ZWQpKQogICAgICAgICAgICAgICAgaWYgbm90'
    'IGRhdGE6CiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoZGF0YSk7IHJl'
    'Y2VpdmVkICs9IGxlbihkYXRhKQogICAgICAgICAgICBlbGFwc2VkID0gdGltZS5tb25vdG9uaWMoKS1zdGFydAogICAgICAg'
    'IGZpbmFsbHk6CiAgICAgICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQogICAgaWYgcmVjZWl2ZWQgIT0gc2l6ZSBvciBkaWdl'
    'c3QuaGV4ZGlnZXN0KCkgIT0gZXhwZWN0ZWQ6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnRlZ3JpdHlfZmFpbGVk'
    'JykKICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdkb3dubG9hZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9lbGFw'
    'c2VkLzFlNiwgMiksCiAgICAgICAgICAgICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwgJ2ludGVncml0eSc6'
    'IFRydWUsICdsaW1pdGVkX3NhbXBsZSc6IFRydWV9CgoKZGVmIGRldmljZV9zdGF0dXMoKToKICAgIHRyeToKICAgICAgICBp'
    'bmZvPWpzb24ubG9hZHMoKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICByZXR1cm4geydk'
    'ZXZpY2VfbmFtZSc6aW5mby5nZXQoJ25hbWUnLCcnKSwnZGV2aWNlX251bWJlcic6aW5mby5nZXQoJ251bWJlcicpLAogICAg'
    'ICAgICAgICAgICAgJ2RldmljZV9uYW1lX3BlbmRpbmcnOmJvb2woaW5mby5nZXQoJ3BlbmRpbmcnKSBvciBpbmZvLmdldCgn'
    'c3luY19lcnJvcicpKX0KICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTpyZXR1cm4geydkZXZpY2VfbmFtZSc6Jycs'
    'J2RldmljZV9udW1iZXInOk5vbmUsJ2RldmljZV9uYW1lX3BlbmRpbmcnOkZhbHNlfQoKCmRlZiBzeW5jX2RldmljZV9uYW1l'
    'KG5hbWU9Tm9uZSk6CiAgICBpbXBvcnQgdW5pY29kZWRhdGEKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rva2Vu'
    'J106cmFpc2UgVmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9INC6'
    '0LvQuNC10L3RgtCwLicpCiAgICBpZiBuYW1lIGlzIG5vdCBOb25lOgogICAgICAgIG5hbWU9dW5pY29kZWRhdGEubm9ybWFs'
    'aXplKCdORkMnLHN0cihuYW1lKSkuc3RyaXAoKQogICAgICAgIGlmIG5vdCAxPD1sZW4obmFtZSk8PTY0IG9yIGFueSh1bmlj'
    'b2RlZGF0YS5jYXRlZ29yeShjKS5zdGFydHN3aXRoKCdDJykgZm9yIGMgaW4gbmFtZSk6CiAgICAgICAgICAgIHJhaXNlIFZh'
    'bHVlRXJyb3IoJ9CY0LzRjyDQtNC+0LvQttC90L4g0YHQvtC00LXRgNC20LDRgtGMINC+0YIgMSDQtNC+IDY0INC+0LHRi9GH'
    '0L3Ri9GFINGB0LjQvNCy0L7Qu9C+0LIuJykKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6d3JpdGUoUk9P'
    'VC8nZGV2aWNlJyxzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICB0cnk6aW5mbz1qc29uLmxvYWRzKChST09ULydkZXZpY2Ut'
    'aW5mby5qc29uJykucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6aW5mbz17fQogICAgaWYg'
    'bmFtZSBpcyBub3QgTm9uZTppbmZvLnVwZGF0ZShuYW1lPW5hbWUscGVuZGluZz1UcnVlKQogICAgcGF5bG9hZD17J3Rva2Vu'
    'JzooUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpLCdkZXZpY2UnOihST09ULydkZXZpY2UnKS5yZWFkX3RleHQo'
    'KS5zdHJpcCgpfQogICAgaWYgaW5mby5nZXQoJ3BlbmRpbmcnKTpwYXlsb2FkWyduYW1lJ109aW5mb1snbmFtZSddCiAgICB0'
    'cnk6CiAgICAgICAgd2l0aCBuYW1lc3BhY2UoKSBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIGVsc2UgY29u'
    'dGV4dGxpYi5udWxsY29udGV4dCgpOgogICAgICAgICAgICByZXBseT10bHNfcmVxdWVzdChTRVJWRVIsJy9kZXZpY2UnLHBh'
    'eWxvYWQsdGltZW91dD01KQogICAgICAgIHZhbHVlPXJlcGx5WydkZXZpY2UnXTtudW1iZXI9aW50KHZhbHVlWydudW1iZXIn'
    'XSkKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZSh2YWx1ZVsnbmFtZSddLHN0cikgb3Igbm90IDE8PWxlbih2YWx1ZVsnbmFt'
    'ZSddKTw9NjQgb3IgbnVtYmVyPDE6cmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9kZXZpY2VfbWV0YWRhdGEnKQogICAgICAg'
    'IGluZm89eyduYW1lJzp2YWx1ZVsnbmFtZSddLCdudW1iZXInOm51bWJlciwncGVuZGluZyc6RmFsc2UsJ3N5bmNfZXJyb3In'
    'OkZhbHNlfQogICAgZXhjZXB0IChPU0Vycm9yLFJ1bnRpbWVFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yLGh0dHAuY2xpZW50'
    'LkhUVFBFeGNlcHRpb24pOgogICAgICAgIGluZm9bJ3N5bmNfZXJyb3InXT1UcnVlCiAgICB3cml0ZShST09ULydkZXZpY2Ut'
    'aW5mby5qc29uJyxqc29uLmR1bXBzKGluZm8sZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAgIHJldHVybiBkZXZpY2Vfc3RhdHVz'
    'KCkKCgpkZWYgdG9rZW5fc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3Rl'
    'eHQoKS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFsaWQg'
    'PSByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pIGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9rZW4n'
    'OiB2YWxpZCwKICAgICAgICAgICAgJ3Rva2VuX2hpbnQnOiAnRVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hsaWIu'
    'c2hhMjU2KHRva2VuLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90b2tl'
    'bih0b2tlbik6CiAgICB0b2tlbiA9IHRva2VuLnN0cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVS'
    'TiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC90YLQ'
    'sCDRhNC+0YDQvNCw0YLQsCBFVk4xLeKApicpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhp'
    'c3Rfb2s9VHJ1ZSkKICAgIG9sZCA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rva2Vu'
    'JykuZXhpc3RzKCkgZWxzZSAnJwogICAgaWYgb2xkID09IHRva2VuOgogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKTtyZXR1'
    'cm4KICAgIGlmIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9RmFs'
    'c2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0YLQutC7'
    '0Y7Rh9C40YLQtSBWUE4t0YLRg9C90L3QtdC70Ywg0L/QtdGA0LXQtCDRgdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicpCiAg'
    'ICAjIEEgZGlmZmVyZW50IGFjY291bnQgbmVlZHMgaXRzIG93biBkZXZpY2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNlIGl0'
    'cyBjZXJ0aWZpY2F0ZS4KICAgIGZvciBuYW1lIGluICgnZGV2aWNlLWluZm8uanNvbicsICdkZXZpY2UnLCAnY2xpZW50LWtl'
    'eS5wZW0nLCAnY2xpZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAgICdw'
    'cml2YXRlL2NsaWVudC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScsICdyYW5raW5nLmpzb24nLCAncmVjYWxpYnJhdGUn'
    'LCAnZXZlbnRzLmpzb24nLCAnc3VwcG9ydC1wcmV2aWV3Lmpzb24nKToKICAgICAgICAoUk9PVC9uYW1lKS51bmxpbmsobWlz'
    'c2luZ19vaz1UcnVlKQogICAgd3JpdGUoUk9PVC8ndG9rZW4nLCB0b2tlbikKICAgIHN5bmNfZGV2aWNlX25hbWUoKQogICAg'
    'c3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQu9GO'
    '0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFsc2UsIG1ldHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJlcGFp'
    'cj1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGlm'
    'IHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4odG9rZW4pCiAgICBpZiBub3QgdG9rZW5fc3RhdHVzKClbJ2hhc190b2tlbidd'
    'OgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC0LLQtdGA0LTQuNGC0LUg0YLQ'
    'vtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAgZW5zdXJlX2RlcGVuZGVuY2llcygpCiAgICBpZiByZXBhaXI6CiAgICAg'
    'ICAgd3JpdGUoUk9PVC8ncmVjYWxpYnJhdGUnLCAnMScpCiAgICB1bml0ID0gZicnJ1tVbml0XQpEZXNjcmlwdGlvbj1Fdmdl'
    'bml1bSBmdWxsLWRldmljZSBFc3RvbmlhIFZQTgpBZnRlcj1uZXR3b3JrLnRhcmdldApTdGFydExpbWl0SW50ZXJ2YWxTZWM9'
    'MTgwClN0YXJ0TGltaXRCdXJzdD0zCltTZXJ2aWNlXQpUeXBlPXNpbXBsZQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3Zw'
    'bmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwKRXhlY1N0b3BQb3N0PS91c3IvbG9jYWwvc2Jpbi92cG5jdGwgaW50ZXJu'
    'YWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9bWl4ZWQKVU1hc2s9MDA3NwpN'
    'ZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zCicnJwogICAgd3JpdGUoUGF0aCgnL2V0Yy9z'
    'eXN0ZW1kL3N5c3RlbScpL1VOSVQsIHVuaXQpCiAgICByZWNvdmVyeSA9ICJldmdlbml1bS1zdGFyZml2ZS10dW5uZWwtcmVj'
    'b3Zlci5zZXJ2aWNlIgogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL3JlY292ZXJ5LCAiIiJbVW5pdF0K'
    'RGVzY3JpcHRpb249UmVjb3ZlciBvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0ZXN0IHJlc291cmNlcwpEZWZh'
    'dWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9bmV0d29yay1wcmUudGFyZ2V0IHZwbi14'
    'cmF5LnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRl'
    'cm5hbC1zdGFyZml2ZS10dW5uZWwtY2xlYW51cApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiKQog'
    'ICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5kKFsnc3lzdGVtY3RsJywgJ2Vu'
    'YWJsZScsIHJlY292ZXJ5XSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdyZXNldC1mYWlsZWQnLFVOSVRdLGNoZWNrPUZh'
    'bHNlKQogICAgc3RhZ2UoJ3N0YXJ0aW5nJyAsICfQk9C+0YLQvtCy0LvRjiDQv9C+0LTQutC70Y7Rh9C10L3QuNC1INCyINCt'
    '0YHRgtC+0L3QuNGOLicsIDIsIGFjdGl2ZT1GYWxzZSwgcmV0cnk9MCwgZXJyb3JfY29kZT0nJykKICAgIGNvbW1hbmQoWydz'
    'eXN0ZW1jdGwnLCAncmVzdGFydCcgaWYgcmVwYWlyIGVsc2UgJ3N0YXJ0JywgVU5JVF0pCiAgICBwcmludCgnVlBOINC30LDQ'
    'v9GD0YHQutCw0LXRgtGB0Y8uJyxmbHVzaD1UcnVlKQoKCmRlZiBkaXNjb25uZWN0KCk6CiAgICBjb21tYW5kKFsnc3lzdGVt'
    'Y3RsJywgJ3N0b3AnLCBVTklUXSwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MjUpCiAgICBjbGVhbnVwKCkKICAgIGNsZWFudXBf'
    'ZnVsbChyZWxlYXNlPVRydWUpCiAgICBzdGFnZSgnb2ZmJywgJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicsIDAsIGFjdGl2ZT1G'
    'YWxzZSkKICAgIHByaW50KCdWUE4g0LLRi9C60LvRjtGH0LXQvS4nKQoKCmRlZiBzdGFydF9kYWVtb24oZW52KToKICAgIChS'
    'VU5USU1FLydjaGFyb24udmljaScpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICBsb2cgPSAoUk9PVC8nY2hhcm9uLmxv'
    'ZycpLm9wZW4oJ3cnKQogICAgZGFlbW9uID0gc3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywgJ25ldG5zJywgJ2V4ZWMnLCBOUywg'
    'Y2hhcm9uX2JpbmFyeSgpXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW52PWVudiwgc3RkaW49c3VicHJvY2Vz'
    'cy5ERVZOVUxMLCBzdGRvdXQ9bG9nLCBzdGRlcnI9bG9nKQogICAgbG9nLmNsb3NlKCkKICAgIHRyeToKICAgICAgICBmb3Ig'
    'XyBpbiByYW5nZSg2MCk6CiAgICAgICAgICAgIGlmIFNUT1Agb3IgZGFlbW9uLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAg'
    'ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZGFlbW9uX3N0b3BwZWQnKQogICAgICAgICAgICBpZiAoUlVOVElNRS8n'
    'Y2hhcm9uLnZpY2knKS5leGlzdHMoKSBhbmQgc3dhbignLS1zdGF0cycsIGNoZWNrPUZhbHNlLCB0aW1lb3V0PTEpLnJldHVy'
    'bmNvZGUgPT0gMDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgc3dh'
    'bignLS1sb2FkLWNyZWRzJywgJy0tbm9wcm9tcHQnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAg'
    'ICBzd2FuKCctLWxvYWQtY29ubnMnLCAnLS1maWxlJywgUk9PVC8nY29ubmVjdGlvbi5jb25mJykKICAgICAgICByZXR1cm4g'
    'ZGFlbW9uCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbjoKICAgICAgICBzdG9wX3Byb2Nlc3MoZGFlbW9uKQogICAgICAgIHJh'
    'aXNlCgoKZGVmIHN0b3BfcHJvY2Vzcyhwcm9jZXNzKToKICAgIGlmIHByb2Nlc3MgaXMgbm90IE5vbmUgYW5kIHByb2Nlc3Mu'
    'cG9sbCgpIGlzIE5vbmU6CiAgICAgICAgcHJvY2Vzcy50ZXJtaW5hdGUoKQogICAgICAgIHRyeTpwcm9jZXNzLndhaXQodGlt'
    'ZW91dD01KQogICAgICAgIGV4Y2VwdCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkOnByb2Nlc3Mua2lsbCgpO3Byb2Nlc3Mu'
    'd2FpdCh0aW1lb3V0PTMpCgoKZGVmIHN0b3BfY2FuZGlkYXRlKGRhZW1vbj1Ob25lKToKICAgIGdsb2JhbCBUTFNfUFJPQ0VT'
    'UwogICAgc3RvcF9wcm9jZXNzKGRhZW1vbikKICAgIHN0b3BfcHJvY2VzcyhUTFNfUFJPQ0VTUyk7VExTX1BST0NFU1M9Tm9u'
    'ZQogICAgY2xlYW51cCgpCgoKZGVmIHByZXBhcmVfZGF0YV9wbGFuZShhZGRyZXNzKToKICAgIGlmIG5vdCBmdWxsX3N0YXRl'
    'KCkuZXhpc3RzKCk6CiAgICAgICAgaWYgUGF0aCgnL3N5cy9jbGFzcy9uZXQvJytGVUxMX0hPU1QpLmV4aXN0cygpOgogICAg'
    'ICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfaW50ZXJmYWNlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFu'
    'ZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToK'
    'ICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX3RhYmxlX2NvbGxpc2lvbicpCiAgICAgICAgaWYgY29tbWFu'
    'ZChbJ2lwJywncm91dGUnLCdzaG93JywndGFibGUnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6'
    'CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignYWRtaW5fdGFibGVfY29sbGlzaW9uJykKICAgICAgICBpZiBhbnko'
    'ci5nZXQoJ3ByaW9yaXR5JykgaW4gKDc5LDgwKSBmb3IgciBpbiBqc29uLmxvYWRzKGNvbW1hbmQoWydpcCcsJy1qJywnLTQn'
    'LCdydWxlJ10pLnN0ZG91dCkpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfcnVsZV9jb2xsaXNpb24n'
    'KQogICAgICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxqc29uLmR1bXBzKHsnYWN0aXZlJzpGYWxzZSwnbWVhc3VyZW1lbnRfb25s'
    'eSc6VHJ1ZX0pKQogICAgZnVsbF9uYW1lc3BhY2UoYWRkcmVzcykKICAgIHN0YXJ0X25hbWVzcGFjZV9kbnMoKQoKCmRlZiBz'
    'dGFydF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KToKICAgIGdsb2JhbCBBQ1RJVkUsVExTX1BST0NFU1MKICAgIEFD'
    'VElWRT1jYW5kaWRhdGUKICAgIHdyaXRlKFJPT1QvJ2FjdGl2ZS1wYXRoLmpzb24nLGpzb24uZHVtcHMoeydpZCc6Y2FuZGlk'
    'YXRlWydpZCddfSkpCiAgICBzZXR1cF9uZXR3b3JrKCkKICAgIGRhZW1vbl9jb25maWdzKGlkZW50aXR5LGNhbmRpZGF0ZVsn'
    'YWRkcmVzcyddKQogICAgaWYgY2FuZGlkYXRlWyd0bHMnXSBvciBjYW5kaWRhdGUuZ2V0KCdldmd0Jyk6CiAgICAgICAgaWYg'
    'Y2FuZGlkYXRlLmdldCgnZXZndCcpOgogICAgICAgICAgICBiaW5hcnk9ZW5zdXJlX2V2Z3RfYmluYXJ5KCkKICAgICAgICAg'
    'ICAgY2Fycmllcj1bc3RyKGJpbmFyeSksJy1tb2RlJywnY2xpZW50JywnLXNlcnZlcicsY2FuZGlkYXRlLmdldCgndHJhbnNw'
    'b3J0X2FkZHJlc3MnLGNhbmRpZGF0ZVsnYWRkcmVzcyddKSsnOicrc3RyKGNhbmRpZGF0ZS5nZXQoJ3RyYW5zcG9ydF9wb3J0'
    'JywyNDU3OCkpLCctc2VydmVyLW5hbWUnLGNhbmRpZGF0ZVsnaWRlbnRpdHknXSwKICAgICAgICAgICAgICAgICAgICAgJy11'
    'ZHAtbGlzdGVuJywnMTI3LjAuMC4xOjI0NTczJywnLXVkcC1wZWVyJyxDTElFTlQrJzo0NTAwJywKICAgICAgICAgICAgICAg'
    'ICAgICAgJy1jYScsc3RyKFJPT1QvJ2NhLnBlbScpLCctY2VydCcsc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwnLWtleScsc3Ry'
    'KFJPT1QvJ2NsaWVudC1rZXkucGVtJyldCiAgICAgICAgZWxzZTpjYXJyaWVyPVsnL3Vzci9sb2NhbC9zYmluL3ZwbmN0bCcs'
    'J2ludGVybmFsLXRscy1jbGllbnQnXQogICAgICAgIFRMU19QUk9DRVNTPXN1YnByb2Nlc3MuUG9wZW4oWydpcCcsJ25ldG5z'
    'JywnZXhlYycsTlMsKmNhcnJpZXJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RkaW49c3VicHJv'
    'Y2Vzcy5ERVZOVUxMLHN0ZG91dD1zdWJwcm9jZXNzLkRFVk5VTEwsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBzdGRlcnI9Tm9uZSBpZiBjYW5kaWRhdGUuZ2V0KCdldmd0JykgZWxzZSBzdWJwcm9jZXNzLkRFVk5VTEwpCiAgICAg'
    'ICAgZm9yIF8gaW4gcmFuZ2UoNTApOgogICAgICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRpbWVFcnJvcignY2FuY2VsbGVk'
    'JykKICAgICAgICAgICAgaWYgVExTX1BST0NFU1MucG9sbCgpIGlzIG5vdCBOb25lOnJhaXNlIFJ1bnRpbWVFcnJvcigndGxz'
    'X2NhcnJpZXJfc3RvcHBlZCcpCiAgICAgICAgICAgIGlmICcxMjcuMC4wLjE6MjQ1NzMnIGluIGluc2lkZShbJ3NzJywnLWFu'
    'dSddLGNoZWNrPUZhbHNlKS5zdGRvdXQ6YnJlYWsKICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICBlbHNlOnJh'
    'aXNlIFJ1bnRpbWVFcnJvcigndGxzX2NhcnJpZXJfbm90X3JlYWR5JykKICAgICAgICBpbnNpZGUoWyduZnQnLCctZicsJy0n'
    'XSxkYXRhPSd0YWJsZSBpcCBldm5fdGxzX2NhcnJpZXIge1xuIGNoYWluIG91dHB1dCB7XG4gdHlwZSBuYXQgaG9vayBvdXRw'
    'dXQgcHJpb3JpdHkgZHN0bmF0OyBwb2xpY3kgYWNjZXB0O1xuIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0'
    'MyByZWRpcmVjdCB0byA6MjQ1NzNcbiB9XG59XG4nKQogICAgZW52PXsqKm9zLmVudmlyb24sJ1NUUk9OR1NXQU5fQ09ORic6'
    'c3RyKFJPT1QvJ3N0cm9uZ3N3YW4uY29uZicpfTtlbnYucG9wKCdOT1RJRllfU09DS0VUJyxOb25lKQogICAgZGFlbW9uPXN0'
    'YXJ0X2RhZW1vbihlbnYpCiAgICB0cnk6CiAgICAgICAgc3dhbignLS1pbml0aWF0ZScsJy0tY2hpbGQnLCdzdGFyZml2ZS1u'
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
    'KQogICAgICAgIGxvYWRlZD1yYW5rLmxvYWQoKQogICAgICAgIHJlYnVpbGQ9KFJPT1QvJ3JlY2FsaWJyYXRlJykuZXhpc3Rz'
    'KCkKICAgICAgICBpZiBub3QgcmVidWlsZCBhbmQgKG5vdCBsb2FkZWQgb3Igbm90IHJhbmsuY2FuZGlkYXRlcygpKToKICAg'
    'ICAgICAgICAgcmFuay5ib290c3RyYXAoKQogICAgICAgIGlmIHJlYnVpbGQ6CiAgICAgICAgICAgIG1lYXN1cmVtZW50cz17'
    'fQogICAgICAgICAgICBmb3IgaSxjYW5kaWRhdGUgaW4gZW51bWVyYXRlKENBTkRJREFURVMpOgogICAgICAgICAgICAgICAg'
    'aWYgU1RPUDpyZXR1cm4KICAgICAgICAgICAgICAgIHN0YWdlKCdyYW5raW5nJywn0J/RgNC+0LLQtdGA0Y/RjiDQvNCw0YDR'
    'iNGA0YPRgjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sMTAraW50KGkqNjAvbGVuKENBTkRJREFURVMpKSxhY3RpdmU9RmFsc2Us'
    'cGF0aD1jYW5kaWRhdGVbJ2lkJ10pCiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgZGFlbW9uPXN0'
    'YXJ0X2NhbmRpZGF0ZShjYW5kaWRhdGUsaWRlbnRpdHkpCiAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAg'
    'ICAgICAgICAgICBpbnRlZ3JpdHk9ZG93bmxvYWQoMTA0ODU3NilbJ2ludGVncml0eSddCiAgICAgICAgICAgICAgICAgICAg'
    'ZXhjZXB0IFJ1bnRpbWVFcnJvciBhcyBlcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgaWYgc3RyKGVycm9yKT09J2lu'
    'dGVncml0eV9mYWlsZWQnOnJhaXNlCiAgICAgICAgICAgICAgICAgICAgICAgIGludGVncml0eT1Ob25lCiAgICAgICAgICAg'
    'ICAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAg'
    'ICAgICAgICAgICAgICAgIGludGVncml0eT1Ob25lCiAgICAgICAgICAgICAgICAgICAgbWVhc3VyZW1lbnRzW2NhbmRpZGF0'
    'ZVsnaWQnXV09eydvayc6VHJ1ZSwqKnNwZWVkX3NhbXBsZSgyMDk3MTUyKSwnaW50ZWdyaXR5JzppbnRlZ3JpdHl9CiAgICAg'
    'ICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhw'
    'aXJlZCk6CiAgICAgICAgICAgICAgICAgICAgaWYgU1RPUDpyZXR1cm4KICAgICAgICAgICAgICAgICAgICBtZWFzdXJlbWVu'
    'dHNbY2FuZGlkYXRlWydpZCddXT17J29rJzpGYWxzZX0KICAgICAgICAgICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgICAg'
    'ICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKTtkYWVtb249Tm9uZQogICAgICAgICAgICByYW5rLmJ1aWxkKG1lYXN1cmVt'
    'ZW50cykKICAgICAgICAgICAgKFJPT1QvJ3JlY2FsaWJyYXRlJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1ZSkKICAgICAgICBj'
    'YW5kaWRhdGVzPXt4WydpZCddOnggZm9yIHggaW4gQ0FORElEQVRFU30KICAgICAgICBjdXJyZW50PW5leHQoaXRlcihyYW5r'
    'LmNhbmRpZGF0ZXMoKSksTm9uZSkKICAgICAgICB3aGlsZSBjdXJyZW50IGFuZCBub3QgU1RPUDoKICAgICAgICAgICAgY2Fu'
    'ZGlkYXRlPWNhbmRpZGF0ZXNbY3VycmVudF0KICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc3RhZ2UoJ2hhbmRz'
    'aGFrZScsJ9Cf0L7QtNC60LvRjtGH0LDRjjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sNzUsYWN0aXZlPUZhbHNlLHBhdGg9Y3Vy'
    'cmVudCkKICAgICAgICAgICAgICAgIGRhZW1vbj1zdGFydF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KQogICAgICAg'
    'ICAgICAgICAgc3RhZ2UoJ3JvdXRpbmcnLCfQn9C+0LTQutC70Y7Rh9Cw0Y4g0YLRgNCw0YTQuNC6INC6INC/0YDQvtCy0LXR'
    'gNC10L3QvdC+0LzRgyDQvNCw0YDRiNGA0YPRgtGDLicsOTIpCiAgICAgICAgICAgICAgICBhY3RpdmF0ZV9mdWxsKGNhbmRp'
    'ZGF0ZVsnYWRkcmVzcyddKQogICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH0LXQvdC+'
    'OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCwKICAgICAgICAgICAgICAg'
    'ICAgICAgIG1ldHJpY3M9cmFuay5kYXRhWydlbnRyaWVzJ11bY3VycmVudF0sc2luY2U9aW50KHRpbWUudGltZSgpKSxlcnJv'
    'cl9jb2RlPScnKQogICAgICAgICAgICAgICAgZmFpbHVyZXM9MDtzbG93PTA7bGFzdF90cmFmZmljPXRyYWZmaWNfdG90YWwo'
    'KTtuZXh0X3NwZWVkPXRpbWUubW9ub3RvbmljKCkrNjAwK3NlY3JldHMucmFuZGJlbG93KDYwKQogICAgICAgICAgICAgICAg'
    'd2hpbGUgbm90IFNUT1A6CiAgICAgICAgICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNTApOgogICAgICAgICAgICAgICAg'
    'ICAgICAgICBpZiBTVE9QOmJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAgICAgICAg'
    'ICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICAgICAg'
    'aWYgcG9saWN5IGlzIG5vdCBOb25lOnBvbGljeS5lbnN1cmVfcm91dGUoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBE'
    'TlNfUFJPQ0VTUyBpcyBOb25lIG9yIEROU19QUk9DRVNTLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9C10YDQtdC30LDQv9GD0YHQutCw0Y4g0LfQsNGJ0LjRidGR0L3QvdGL'
    '0LkgRE5TLicsOTAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9J3ByaXZhdGVfZG5zX3N0b3BwZWQnKQogICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgc3RhcnRfbmFtZXNwYWNlX2RucygpCiAgICAgICAgICAgICAgICAgICAgICAgIGhlYWx0aHk9cGF0'
    'aF9oZWFsdGh5KGRhZW1vbikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaGVhbHRoeSBhbmQgbm90IHJlY292ZXJfc3lz'
    'dGVtX2RucygpOnJhaXNlIFJ1bnRpbWVFcnJvcignc3lzdGVtX2Ruc19mYWlsZWQnKQogICAgICAgICAgICAgICAgICAgIGV4'
    'Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKTpoZWFsdGh5'
    'PUZhbHNlCiAgICAgICAgICAgICAgICAgICAgZmFpbHVyZXM9MCBpZiBoZWFsdGh5IGVsc2UgZmFpbHVyZXMrMQogICAgICAg'
    'ICAgICAgICAgICAgIGlmIGZhaWx1cmVzPj0yOnJhaXNlIFJ1bnRpbWVFcnJvcigncGF0aF9oZWFsdGhfZmFpbGVkJykKICAg'
    'ICAgICAgICAgICAgICAgICBpZiBub3QgaGVhbHRoeToKICAgICAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2NoZWNraW5n'
    'Jywn0J7RgtCy0LXRgiDQt9Cw0LTQtdGA0LbQuNCy0LDQtdGC0YHRjy4g0J/RgNC+0LLQtdGA0Y/RjiDRgtC10LrRg9GJ0LjQ'
    'uSDQvNCw0YDRiNGA0YPRgi4nLDkwLGFjdGl2ZT1GYWxzZSkKICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAg'
    'ICAgICAgICAgICAgICAgICBpZiB0aW1lLm1vbm90b25pYygpPj1uZXh0X3NwZWVkOgogICAgICAgICAgICAgICAgICAgICAg'
    'ICB0cmFmZmljPXRyYWZmaWNfdG90YWwoKQogICAgICAgICAgICAgICAgICAgICAgICBpZiBub3Qgc2xvdyBhbmQgdHJhZmZp'
    'Yy1sYXN0X3RyYWZmaWM8NDE5NDMwNDoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxhc3RfdHJhZmZpYz10cmFmZmlj'
    'O25leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSs2MDArc2VjcmV0cy5yYW5kYmVsb3coNjApCiAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgICAgICBsYXN0X3RyYWZmaWM9dHJhZmZpYwogICAgICAg'
    'ICAgICAgICAgICAgICAgICBzYW1wbGU9c3BlZWRfc2FtcGxlKDIwOTcxNTIpO2Jhc2VsaW5lPXJhbmsuZGF0YVsnZW50cmll'
    'cyddW2N1cnJlbnRdCiAgICAgICAgICAgICAgICAgICAgICAgIGRlZ3JhZGVkPXNwZWVkX2RlZ3JhZGVkKHNhbXBsZSxiYXNl'
    'bGluZSkKICAgICAgICAgICAgICAgICAgICAgICAgc2xvdz1zbG93KzEgaWYgZGVncmFkZWQgZWxzZSAwCiAgICAgICAgICAg'
    'ICAgICAgICAgICAgIG5leHRfc3BlZWQ9dGltZS5tb25vdG9uaWMoKSsoMjAgaWYgc2xvdyBlbHNlIDYwMCtzZWNyZXRzLnJh'
    'bmRiZWxvdyg2MCkpCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIHNsb3c+PTM6cmFpc2UgUnVudGltZUVycm9yKCdjb25m'
    'aXJtZWRfc3BlZWRfZHJvcCcpCiAgICAgICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH'
    '0LXQvdC+OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCxlcnJvcl9jb2Rl'
    'PScnKQogICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1l'
    'b3V0RXhwaXJlZCkgYXMgZXhjOgogICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgcmVhc29u'
    'PXN0cihleGMpIGlmIHJlLmZ1bGxtYXRjaCgnW2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlvbl9mYWls'
    'ZWQnCiAgICAgICAgICAgICAgICAjIEEgbWlzc2luZyBwaHlzaWNhbCBpbnRlcmZhY2UgaXMgbm90IGEgdHJhbnNwb3J0J3Mg'
    'ZGVmZWF0LgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIHJvdXRlPXBoeXNpY2FsX3JvdXRlKCk7'
    'Y2Fycmllcj1QYXRoKCcvc3lzL2NsYXNzL25ldCcpL3JvdXRlWydkZXYnXS8nY2FycmllcicKICAgICAgICAgICAgICAgICAg'
    'ICBvZmZsaW5lPWNhcnJpZXIuZXhpc3RzKCkgYW5kIGNhcnJpZXIucmVhZF90ZXh0KCkuc3RyaXAoKT09JzAnCiAgICAgICAg'
    'ICAgICAgICBleGNlcHQgKE9TRXJyb3IsUnVudGltZUVycm9yKTpvZmZsaW5lPVRydWUKICAgICAgICAgICAgICAgIGlmIG5v'
    'dCBvZmZsaW5lOgogICAgICAgICAgICAgICAgICAgIHJhbmsubG9zZShjdXJyZW50LHJlYXNvbikKICAgICAgICAgICAgICAg'
    'ICAgICBmb2xsb3dpbmc9cmFuay5uZXh0X2FmdGVyKGN1cnJlbnQpCiAgICAgICAgICAgICAgICAgICAgY3VycmVudD1mb2xs'
    'b3dpbmcgb3IgbmV4dChpdGVyKHJhbmsuY2FuZGlkYXRlcygpKSxOb25lKQogICAgICAgICAgICAgICAgc3RhZ2UoJ3JlcGFp'
    'cmluZycsJ9Ch0LLRj9C30Ywg0L/QvtGC0LXRgNGP0L3QsC4g0J/QtdGA0LXQutC70Y7Rh9Cw0Y4g0LfQsNGJ0LjRidGR0L3Q'
    'vdGL0Lkg0LzQsNGA0YjRgNGD0YIuJyBpZiBub3Qgb2ZmbGluZSBlbHNlICfQntC20LjQtNCw0Y4g0LLQvtGB0YHRgtCw0L3Q'
    'vtCy0LvQtdC90LjRjyDRhNC40LfQuNGH0LXRgdC60L7QuSDRgdC10YLQuC4nLDY1LAogICAgICAgICAgICAgICAgICAgICAg'
    'YWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9cmVhc29uKQogICAgICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoMzAgaWYgbm90'
    'IG9mZmxpbmUgZWxzZSAxMDApOgogICAgICAgICAgICAgICAgICAgIGlmIFNUT1A6YnJlYWsKICAgICAgICAgICAgICAgICAg'
    'ICB0aW1lLnNsZWVwKC4xKQogICAgICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFl'
    'bW9uKTtkYWVtb249Tm9uZQogICAgICAgIGlmIG5vdCBTVE9QOgogICAgICAgICAgICBzdGFnZSgnZmFpbGVkJywn0JTQvtGB'
    '0YLRg9C/0L3Ri9C1INC80LDRgNGI0YDRg9GC0Ysg0LjRgdGH0LXRgNC/0LDQu9C4INGC0YDQuCDQv9C+0L/Ri9GC0LrQuC4g'
    '0J3QsNC20LzQuNGC0LUgwqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuyDQtNC70Y8g0L3QvtCy0L7Qs9C+INGA0LXQudGC'
    '0LjQvdCz0LAuJywwLAogICAgICAgICAgICAgICAgICBhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0ncmFua2luZ19leGhhdXN0'
    'ZWQnKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsUnVudGltZUVycm9yLHN1YnByb2Nlc3MuVGltZW91dEV4cGly'
    'ZWQpIGFzIGV4YzoKICAgICAgICBpZiBub3QgU1RPUDoKICAgICAgICAgICAgY29kZT1zdHIoZXhjKSBpZiByZS5mdWxsbWF0'
    'Y2goJ1thLXpfXXsxLDY0fScsc3RyKGV4YykpIGVsc2UgJ2Nvbm5lY3Rpb25fZmFpbGVkJwogICAgICAgICAgICBzdGFnZSgn'
    'ZmFpbGVkJywn0J3QtSDRg9C00LDQu9C+0YHRjCDQv9C+0LTQs9C+0YLQvtCy0LjRgtGMIFZQTi4g0J3QsNC20LzQuNGC0LUg'
    'wqvQktC+0YHRgdGC0LDQvdC+0LLQuNGC0YzCuy4nLDAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9Y29kZSkKICAgIGZpbmFs'
    'bHk6CiAgICAgICAgc3RvcF9jYW5kaWRhdGUoZGFlbW9uKQogICAgICAgIGlmIFNUT1A6c3RhZ2UoJ29mZicsJ1ZQTiDQstGL'
    '0LrQu9GO0YfQtdC9LicsMCxhY3RpdmU9RmFsc2UpCg=='
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
    'IGRlZiBib290c3RyYXAoc2VsZik6CiAgIyBObyBzeW50aGV0aWMgc3BlZWQvaGVhbHRoIHJlc3VsdDogdHJ5IHRoZSBSVSBp'
    'bmdyZXNzIGZpcnN0LCB0aGVuIGZhbGxiYWNrcy4KICBvcmRlcj1zb3J0ZWQoc2VsZi5pZHMsa2V5PWxhbWJkYSBpZGVudGl0'
    'eTppZGVudGl0eSE9J3J1LXVkcCcpCiAgc2VsZi5kYXRhPXsnc2NoZW1hJzoxLCdjcmVhdGVkJzppbnQodGltZS50aW1lKCkp'
    'LCdlbnRyaWVzJzp7aWRlbnRpdHk6eydzY29yZSc6MCwnbG9zc2VzJzowfSBmb3IgaWRlbnRpdHkgaW4gc2VsZi5pZHN9LCdv'
    'cmRlcic6b3JkZXJ9CiAgc2VsZi5zYXZlKCkKIGRlZiBsb3NlKHNlbGYsaWRlbnRpdHkscmVhc29uKToKICBlPXNlbGYuZGF0'
    'YVsnZW50cmllcyddW2lkZW50aXR5XTtlWydsb3NzZXMnXT1taW4oMyxlWydsb3NzZXMnXSsxKTtlWydsYXN0X2ZhaWx1cmUn'
    'XT1pbnQodGltZS50aW1lKCkpO2VbJ3JlYXNvbiddPXJlYXNvbgogIHNlbGYuc2F2ZSgpCiBkZWYgbmV4dF9hZnRlcihzZWxm'
    'LGlkZW50aXR5KToKICBvcmRlcj1zZWxmLmRhdGFbJ29yZGVyJ107cmVzdD1vcmRlcltvcmRlci5pbmRleChpZGVudGl0eSkr'
    'MTpdCiAgcmV0dXJuIG5leHQoKHggZm9yIHggaW4gcmVzdCBpZiBzZWxmLmRhdGFbJ2VudHJpZXMnXVt4XVsnbG9zc2VzJ108'
    'MyksTm9uZSkK'
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
