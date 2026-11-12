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

MANAGER_VERSION = "0.5.7"

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
    'ICAgZWxzZToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9CQ0LLRgtC+0LzQsNGC0LjRh9C10YHQutCw0Y8g0YPRgdGC'
    '0LDQvdC+0LLQutCwINC60LvQuNC10L3RgtCwINC/0L7QtNC00LXRgNC20LjQstCw0LXRgiBBcmNoINC4IEZlZG9yYS4nKQog'
    'ICAgY29tbWFuZChhcmdzLCB0aW1lb3V0PTMwMCkKICAgIGlmIG5vdCBjaGFyb25fYmluYXJ5KCkgb3Igbm90IGFsbChzaHV0'
    'aWwud2hpY2gocCkgZm9yIHAgaW4gKCdzd2FuY3RsJywnY29ubnRyYWNrJykpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJv'
    'cign0J/QsNC60LXRgiBzdHJvbmdTd2FuINC90LUg0L/RgNC10LTQvtGB0YLQsNCy0LjQuyDQvdC10L7QsdGF0L7QtNC40LzR'
    'i9C1INC/0YDQvtCz0YDQsNC80LzRiy4nKQogICAgZW5zdXJlX2V2Z3RfYmluYXJ5KCkKCgpkZWYgY2xlYXJfZG5zX21hcHBp'
    'bmdzKHByZXZpb3VzX3Zwbj1GYWxzZSk6CiAgICAiIiJGb3JnZXQgb25seSB0aGlzIG1hbmFnZXIncyBvYnNvbGV0ZSBETlMg'
    'TkFULCBuZXZlciBmbHVzaCBhbGwgY29ubmVjdGlvbnMuCgogICAgUmVtb3ZpbmcgYW4gbmZ0IE5BVCBjaGFpbiBkb2VzIG5v'
    'dCByZW1vdmUgZXhpc3RpbmcgY29ubnRyYWNrIHRyYW5zbGF0aW9ucy4KICAgIEEgcnVubmluZyByZXNvbHZlciBjYW4gcmV1'
    'c2UgaXRzIFVEUCBzb2NrZXQgaW5kZWZpbml0ZWx5IGFmdGVyIGEgVlBOIHN3aXRjaC4KICAgICIiIgogICAgZmlsdGVycyA9'
    'IChbJy0tcmVwbHktcG9ydC1zcmMnLCcxODU1MyddIGlmIHByZXZpb3VzX3ZwbiBlbHNlCiAgICAgICAgICAgICAgIFsnLS1y'
    'ZXBseS1wb3J0LXNyYycsJzUzJywnLS1kc3QtbmF0JywnMS4xLjEuMSddKQogICAgZm9yIHByb3RvY29sIGluICgndWRwJywn'
    'dGNwJyk6CiAgICAgICAgcmVzdWx0ID0gY29tbWFuZChbJ2Nvbm50cmFjaycsJy1EJywnLWYnLCdpcHY0JywnLXAnLHByb3Rv'
    'Y29sLAogICAgICAgICAgICAgICAgICAgICAgICAgICctLWRwb3J0JywnNTMnLCpmaWx0ZXJzXSwgY2hlY2s9RmFsc2UsCiAg'
    'ICAgICAgICAgICAgICAgICAgICAgICBlbnY9eyoqb3MuZW52aXJvbiwnTENfQUxMJzonQyd9KQogICAgICAgIGVtcHR5ID0g'
    'cmVzdWx0LnJldHVybmNvZGUgPT0gMSBhbmQgJzAgZmxvdyBlbnRyaWVzIGhhdmUgYmVlbiBkZWxldGVkJyBpbiByZXN1bHQu'
    'c3RkZXJyCiAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGUgIT0gMCBhbmQgbm90IGVtcHR5OgogICAgICAgICAgICByYWlz'
    'ZSBSdW50aW1lRXJyb3IoJ2Ruc190cmFuc2l0aW9uX2NsZWFudXBfZmFpbGVkJykKCgpkZWYgZnVsbF9ndWFyZF9hY3RpdmUo'
    'KToKICAgIHJldHVybiBjb21tYW5kKFsnbmZ0JywnbGlzdCcsJ3RhYmxlJywnaW5ldCcsRlVMTF9HVUFSRF0sY2hlY2s9RmFs'
    'c2UpLnJldHVybmNvZGUgPT0gMAoKCmRlZiBmdWxsX2ZpcmV3YWxsKCk6CiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAg'
    'ICAgICAgc2V0dGluZ3M9cG9saWN5LmFwaS5sb2FkX3NldHRpbmdzKCkKICAgICAgICByZXR1cm4gcG9saWN5LmZpcmV3YWxs'
    'KHBvbGljeS5sb2FkKCkscG9saWN5LmxvY2FsX25ldHdvcmtzKHBoeXNpY2FsX3JvdXRlKCkpLGludChzZXR0aW5nc1sieHJh'
    'eV91aWQiXSkpCiAgICAjIE1pbmltYWwgZ3VhcmQgdXNlZCBieSBpc29sYXRlZCBwcm90b2NvbCB0ZXN0cy4KICAgICMgS2Vl'
    'cCBsb2NhbCBzdHViIEROUyBvbiBsb29wYmFjay4gRE5BVCBvZiAxMjcvOCBvbnRvIGEgdmV0aCBmYWlscyBMaW51eCdzCiAg'
    'ICAjIGxvb3BiYWNrIHJvdXRlIGNoZWNrczsgdXBzdHJlYW0gcmVzb2x2ZXIgdHJhZmZpYyBzdGlsbCBvYmV5cyB0aGUgZnVs'
    'bCBndWFyZC4KICAgIHJldHVybiBmJycndGFibGUgaW5ldCB7RlVMTF9HVUFSRH0ge3sKIGNoYWluIGRucyB7eyB0eXBlIG5h'
    'dCBob29rIG91dHB1dCBwcmlvcml0eSAtMTAxOyBwb2xpY3kgYWNjZXB0OwogIGlwIGRhZGRyIDEyNy4wLjAuMC84IHJldHVy'
    'bgogIGlwIGRhZGRyIHt7IDEuMS4xLjEsIDkuOS45LjkgfX0gcmV0dXJuCiAgbWV0YSBuZnByb3RvIGlwdjQgbWV0YSBsNHBy'
    'b3RvIHt7IHRjcCwgdWRwIH19IHRoIGRwb3J0IDUzIGRuYXQgaXAgdG8gMS4xLjEuMQogfX0KIGNoYWluIHNvdXJjZSB7eyB0'
    'eXBlIG5hdCBob29rIHBvc3Ryb3V0aW5nIHByaW9yaXR5IHNyY25hdDsgcG9saWN5IGFjY2VwdDsKICBtZXRhIG5mcHJvdG8g'
    'aXB2NCBvaWZuYW1lICJ7RlVMTF9IT1NUfSIgc25hdCBpcCB0byAxNzIuMjkuMjQ3LjEKIH19CiBjaGFpbiBvdXRwdXQge3sg'
    'dHlwZSBmaWx0ZXIgaG9vayBvdXRwdXQgcHJpb3JpdHkgLTMwOyBwb2xpY3kgZHJvcDsKICBvaWZuYW1lICJsbyIgYWNjZXB0'
    'CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAie0ZVTExfSE9TVH0iIGFjY2VwdAogIGlwIGRhZGRyIDI1NS4yNTUuMjU1'
    'LjI1NSB1ZHAgc3BvcnQgNjggdWRwIGRwb3J0IDY3IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIg'
    'aG9vayBmb3J3YXJkIHByaW9yaXR5IC0zMDsgcG9saWN5IGRyb3A7CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJ'
    'RU5UfSBpcCBkYWRkciB7eyB7U0VSVkVSfSB9fSB1ZHAgZHBvcnQge0lLRV9QT1JUfSBhY2NlcHQKICBpaWZuYW1lICJ7SE9T'
    'VH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdWRwIGRwb3J0IDQ0MyBhY2NlcHQKICBpaWZu'
    'YW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0NTcx'
    'LCAyNDU3OCB9fSBhY2NlcHQKICBpaWZuYW1lICJ7SE9TVH0iIGlwIHNhZGRyIHtDTElFTlR9IGlwIGRhZGRyIDE5NS4yMDku'
    'MjExLjE2MyB0Y3AgZHBvcnQgMjQ1NzkgYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBk'
    'YWRkciB7eyB7U0VSVkVSfSB9fSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKICBvaWZuYW1lICJ7SE9TVH0iIGlwIGRhZGRyIHtD'
    'TElFTlR9IGN0IHN0YXRlIGVzdGFibGlzaGVkLHJlbGF0ZWQgYWNjZXB0CiAgbWV0YSBuZnByb3RvIGlwdjQgb2lmbmFtZSAi'
    'e0ZVTExfSE9TVH0iIGFjY2VwdAogIG1ldGEgbmZwcm90byBpcHY0IGlpZm5hbWUgIntGVUxMX0hPU1R9IiBjdCBzdGF0ZSBl'
    'c3RhYmxpc2hlZCxyZWxhdGVkIGFjY2VwdAogfX0KfX0nJycKCgoKZGVmIHJlZnJlc2hfcmV0YWluZWRfZ3VhcmQoKToKICAg'
    'ICIiIk1vdmUgb25seSB0aGUgVlBOIHRyYW5zcG9ydCBleGNlcHRpb24gd2hlbiBhbiBpbmdyZXNzIGVuZHBvaW50IGNoYW5n'
    'ZXMuIiIiCiAgICBpZiBub3QgZnVsbF9ndWFyZF9hY3RpdmUoKToKICAgICAgICByZXR1cm4KICAgIHJ1bGVzID0gZnVsbF9m'
    'aXJld2FsbCgpCiAgICByZXBsYWNlbWVudCA9ICdkZWxldGUgdGFibGUgaW5ldCAnK0ZVTExfR1VBUkQrJ1xuJytydWxlcwog'
    'ICAgY29tbWFuZChbJ25mdCcsJy1jJywnLWYnLCctJ10sZGF0YT1yZXBsYWNlbWVudCkKICAgICMgUGVyc2lzdCB0aGUgY2xv'
    'c2VkIGd1YXJkIGJlZm9yZSBjaGFuZ2luZyB0aGUgYWN0aXZlIGV4Y2VwdGlvbjsgYSBjcmFzaCBzdGF5cyBjbG9zZWQuCiAg'
    'ICB3cml0ZShST09ULydmdWxsLWd1YXJkLm5mdCcscnVsZXMpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCctJ10sZGF0YT1y'
    'ZXBsYWNlbWVudCkKCgpkZWYgdmlydHVhbF9pcCgpOgogICAgZGF0YSA9IGpzb24ubG9hZHMoaW5zaWRlKFsnaXAnLCctaics'
    'Jy00JywnYWRkciddKS5zdGRvdXQpCiAgICBpcHMgPSBbYVsnbG9jYWwnXSBmb3IgbGluayBpbiBkYXRhIGZvciBhIGluIGxp'
    'bmsuZ2V0KCdhZGRyX2luZm8nLCBbXSkKICAgICAgICAgICBpZiBpcGFkZHJlc3MuaXBfYWRkcmVzcyhhWydsb2NhbCddKSBp'
    'biBpcGFkZHJlc3MuaXBfbmV0d29yaygnMTAuNzcuMC4wLzI0JyldCiAgICBpZiBsZW4oaXBzKSAhPSAxOgogICAgICAgIHJh'
    'aXNlIFJ1bnRpbWVFcnJvcigndmlydHVhbF9pcF9taXNzaW5nJykKICAgIHJldHVybiBpcHNbMF0KCgpkZWYgZnVsbF9uYW1l'
    'c3BhY2UoYWRkcmVzcyk6CiAgICB2aXAgPSB2aXJ0dWFsX2lwKCkKICAgIGlmIG5vdCBQYXRoKCcvc3lzL2NsYXNzL25ldC8n'
    'K0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAgY29tbWFuZChbJ2lwJywnbGluaycsJ2FkZCcsRlVMTF9IT1NULCd0eXBl'
    'JywndmV0aCcsJ3BlZXInLCduYW1lJyxGVUxMX1BFRVJdKQogICAgICAgIGNvbW1hbmQoWydpcCcsJ2xpbmsnLCdzZXQnLEZV'
    'TExfUEVFUiwnbmV0bnMnLE5TXSkKICAgIGNvbW1hbmQoWydpcCcsJ2FkZHInLCdyZXBsYWNlJywnMTcyLjI5LjI0Ny4xLzMw'
    'JywnZGV2JyxGVUxMX0hPU1RdKQogICAgY29tbWFuZChbJ2lwJywnbGluaycsJ3NldCcsRlVMTF9IT1NULCdtdHUnLCcxMjgw'
    'JywndXAnXSkKICAgIGluc2lkZShbJ2lwJywnYWRkcicsJ3JlcGxhY2UnLCcxNzIuMjkuMjQ3LjIvMzAnLCdkZXYnLEZVTExf'
    'UEVFUl0pCiAgICBpbnNpZGUoWydpcCcsJ2xpbmsnLCdzZXQnLEZVTExfUEVFUiwnbXR1JywnMTI4MCcsJ3VwJ10pCiAgICBp'
    'bnNpZGUoWydzeXNjdGwnLCctcXcnLCduZXQuaXB2NC5jb25mLmFsbC5mb3J3YXJkaW5nPTEnLCduZXQuaXB2NC5jb25mLmFs'
    'bC5ycF9maWx0ZXI9MCddKQogICAgIyBTdHJvbmdTd2FuJ3MgY2F0Y2gtYWxsIHJvdXRlIG11c3Qgbm90IGNhcHR1cmUgcmVw'
    'bGllcyB0byB0aGUgaG9zdC1mYWNpbmcgaW50ZXJmYWNlLgogICAgaW5zaWRlKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3Jp'
    'dHknLCc5MCcsJ3RvJyxGVUxMX05FVCwnbG9va3VwJywnbWFpbiddLGNoZWNrPUZhbHNlKQogICAgaW5zaWRlKFsnaXAnLCdy'
    'dWxlJywnYWRkJywncHJpb3JpdHknLCc5MCcsJ3RvJyxGVUxMX05FVCwnbG9va3VwJywnbWFpbiddKQogICAgZGVsZXRpb25z'
    'ID0gJycKICAgIGZvciBmYW1pbHksdGFibGUgaW4gWygnaW5ldCcsJ2V2bl9mdWxsX2ZvcndhcmQnKSwoJ25ldGRldicsJ2V2'
    'bl9mdWxsX3dpcmUnKV06CiAgICAgICAgaWYgaW5zaWRlKFsnbmZ0JywnbGlzdCcsJ3RhYmxlJyxmYW1pbHksdGFibGVdLGNo'
    'ZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgICAgIGRlbGV0aW9ucyArPSBmJ2RlbGV0ZSB0YWJsZSB7ZmFt'
    'aWx5fSB7dGFibGV9XG4nCiAgICBydWxlcyA9IGRlbGV0aW9ucyArIGYnJyd0YWJsZSBpbmV0IGV2bl9mdWxsX2ZvcndhcmQg'
    'e3sKIGNoYWluIGZvcndhcmQge3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC01OyBwb2xpY3kgZHJvcDsK'
    'ICBpaWZuYW1lICJ7RlVMTF9QRUVSfSIgb2lmbmFtZSAie1BFRVJ9IiBpcCBzYWRkciAxNzIuMjkuMjQ3LjEgYWNjZXB0CiAg'
    'aWlmbmFtZSB7eyAie1BFRVJ9IiwgImxvIiB9fSBvaWZuYW1lICJ7RlVMTF9QRUVSfSIgaXAgZGFkZHIgMTcyLjI5LjI0Ny4x'
    'IGlwc2VjIGluIHJlcWlkIHtSRVFJRH0gY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRlZCBhY2NlcHQKIH19CiBjaGFpbiBu'
    'YXQge3sgdHlwZSBuYXQgaG9vayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2Fk'
    'ZHIgMTcyLjI5LjI0Ny4xIG9pZm5hbWUgIntQRUVSfSIgc25hdCBpcCB0byB7dmlwfQogfX0KfX0KdGFibGUgbmV0ZGV2IGV2'
    'bl9mdWxsX3dpcmUge3sKIGNoYWluIGVncmVzcyB7eyB0eXBlIGZpbHRlciBob29rIGVncmVzcyBkZXZpY2UgIntQRUVSfSIg'
    'cHJpb3JpdHkgMDsgcG9saWN5IGRyb3A7CiAgZXRoZXIgdHlwZSBhcnAgYWNjZXB0CiAgaXAgZGFkZHIge2FkZHJlc3N9IHVk'
    'cCBkcG9ydCB7QUNUSVZFWydwb3J0J119IGFjY2VwdAogIGlwIGRhZGRyIDM4LjE4MC4xNjQuNjcgdGNwIGRwb3J0IHt7IDI0'
    'NTcxLCAyNDU3OCB9fSBhY2NlcHQKICBpcCBkYWRkciAxOTUuMjA5LjIxMS4xNjMgdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAog'
    'IGlwIGRhZGRyIHthZGRyZXNzfSB0Y3AgZHBvcnQgODQ0MyBhY2NlcHQKIH19Cn19JycnCiAgICBpbnNpZGUoWyduZnQnLCct'
    'YycsJy1mJywnLSddLGRhdGE9cnVsZXMpCiAgICBpbnNpZGUoWyduZnQnLCctZicsJy0nXSxkYXRhPXJ1bGVzKQogICAgIyBS'
    'ZXBsYWNlIHRoZSBvcmlnaW5hbCBsYWIgZm9yd2FyZCBkcm9wOyBob3N0IGluZ3Jlc3MgcmVtYWlucyBjb25zdHJhaW5lZCBi'
    'eSBmdWxsX2ZvcndhcmQuCiAgICBpbnNpZGUoWyduZnQnLCdmbHVzaCcsJ2NoYWluJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9n'
    'dWFyZCcsJ2ZvcndhcmQnXSkKICAgIGluc2lkZShbJ25mdCcsJ2FkZCcsJ3J1bGUnLCdpbmV0JywnZXZuX3N0YXJmaXZlX2d1'
    'YXJkJywnZm9yd2FyZCcsJ2lpZm5hbWUnLEZVTExfUEVFUiwnbWV0YScsJ25mcHJvdG8nLCdpcHY0JywnYWNjZXB0J10pCiAg'
    'ICBpbnNpZGUoWyduZnQnLCdhZGQnLCdydWxlJywnaW5ldCcsJ2V2bl9zdGFyZml2ZV9ndWFyZCcsJ2ZvcndhcmQnLCdvaWZu'
    'YW1lJyxGVUxMX1BFRVIsJ2lwc2VjJywnaW4nLCdyZXFpZCcsc3RyKFJFUUlEKSwnY3QnLCdzdGF0ZScsJ2VzdGFibGlzaGVk'
    'LHJlbGF0ZWQnLCdhY2NlcHQnXSkKCgpfRUdSRVNTX1BST0JFUyA9ICgnaHR0cHM6Ly8xLjEuMS4xL2Nkbi1jZ2kvdHJhY2Un'
    'LCAnaHR0cHM6Ly9hcGkuaXBpZnkub3JnJykKX2VncmVzc19wcmVmZXJyZWQgPSAwCgoKZGVmIHBhcnNlX2V4aXQoYm9keSwg'
    'dHJhY2UpOgogICAgdmFsdWVzID0gW2xpbmVbMzpdIGZvciBsaW5lIGluIGJvZHkuc3BsaXRsaW5lcygpIGlmIGxpbmUuc3Rh'
    'cnRzd2l0aCgnaXA9JyldIGlmIHRyYWNlIGVsc2UgW2JvZHkuc3RyaXAoKV0KICAgIGlmIGxlbih2YWx1ZXMpICE9IDE6CiAg'
    'ICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToKICAgICAgICByZXR1cm4gc3RyKGlwYWRkcmVzcy5JUHY0QWRkcmVzcyh2YWx1'
    'ZXNbMF0pKQogICAgZXhjZXB0IGlwYWRkcmVzcy5BZGRyZXNzVmFsdWVFcnJvcjoKICAgICAgICByZXR1cm4gTm9uZQoKCmRl'
    'ZiBlZ3Jlc3NfaGVhbHRoKCk6CiAgICAiIiJJbmRlcGVuZGVudCBIVFRQUyBwcm92aWRlcnM7IGEgdmVyaWZpZWQgd3Jvbmcg'
    'SVAgbXVzdCBuZXZlciBiZSBtYXNrZWQgYnkgZmFsbGJhY2suIiIiCiAgICBnbG9iYWwgX2VncmVzc19wcmVmZXJyZWQKICAg'
    'IGZvciBpbmRleCBpbiAoX2VncmVzc19wcmVmZXJyZWQsIDEtX2VncmVzc19wcmVmZXJyZWQpOgogICAgICAgIHVybCA9IF9F'
    'R1JFU1NfUFJPQkVTW2luZGV4XQogICAgICAgIHRyeToKICAgICAgICAgICAgcmVzdWx0ID0gaW5zaWRlKFsnY3VybCcsJy00'
    'JywnLS1ub3Byb3h5JywnKicsJy0tZmFpbCcsJy0tc2lsZW50JywnLS1zaG93LWVycm9yJywKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAnLS1jb25uZWN0LXRpbWVvdXQnLCczJywnLS1tYXgtdGltZScsJzUnLCctLW1heC1maWxlc2l6ZScsJzMy'
    'NzY4Jyx1cmxdLHRpbWVvdXQ9NyxjaGVjaz1GYWxzZSkKICAgICAgICBleGNlcHQgKE9TRXJyb3Isc3VicHJvY2Vzcy5UaW1l'
    'b3V0RXhwaXJlZCk6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgcmVzdWx0LnJldHVybmNvZGUgIT0gMDoKICAg'
    'ICAgICAgICAgY29udGludWUKICAgICAgICBvYnNlcnZlZCA9IHBhcnNlX2V4aXQocmVzdWx0LnN0ZG91dCwgaW5kZXggPT0g'
    'MCkKICAgICAgICBpZiBvYnNlcnZlZCBpcyBub3QgTm9uZToKICAgICAgICAgICAgaWYgb2JzZXJ2ZWQgIT0gJzM4LjE4MC4x'
    'NjQuNjcnOgogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgICAgIF9lZ3Jlc3NfcHJlZmVycmVkID0gaW5k'
    'ZXgKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBwYXRoX2hlYWx0aHkoZGFlbW9uKToK'
    'ICAgICMgVGhlIHByaXZhdGUgZGlhZ25vc3RpYyBIVFRQIGNvbGxlY3RvciBpcyBub3QgcGFydCBvZiB0aGUgVlBOIGRhdGEg'
    'cGxhbmUuCiAgICAjIEl0cyBvdXRhZ2UvcmVzdGFydCBtdXN0IG5vdCBkaXNjYXJkIGEgd29ya2luZyByb3V0ZSdzIHRocmVl'
    'LWxvc3MgYnVkZ2V0LgogICAgcmV0dXJuIChkYWVtb24ucG9sbCgpIGlzIE5vbmUgYW5kIGluc3RhbGxlZCgpCiAgICAgICAg'
    'ICAgIGFuZCAoVExTX1BST0NFU1MgaXMgTm9uZSBvciBUTFNfUFJPQ0VTUy5wb2xsKCkgaXMgTm9uZSkgYW5kIGVncmVzc19o'
    'ZWFsdGgoKSkKCgpkZWYgcmV0aXJlX3ByZXZpb3VzX2Nvbm5lY3Rpb25zKGFkZHJlc3Nlcyk6CiAgICAjIFRoZSBmaXJld2Fs'
    'bCBhbHJlYWR5IGJsb2NrcyBvbGQgbm9uLWV4ZW1wdCBmbG93cy4gRG8gbm90IGtpbGwgYWxsIHNvY2tldHMKICAgICMgc2hh'
    'cmluZyBhIHBoeXNpY2FsIHNvdXJjZSBhZGRyZXNzOiB0aGF0IGRlc3Ryb3lzIFNTSCwgTEFOIGFuZCBhcHAgZXhjbHVzaW9u'
    'cy4KICAgICMgT25seSB0aGlzIG1hbmFnZXIncyBETlMgdHJhbnNsYXRpb25zIG5lZWQgZXhwbGljaXQgcmV0aXJlbWVudCAo'
    'aGFuZGxlZCBhYm92ZSkuCiAgICByZXR1cm4KCgpkZWYgc3lzdGVtX2Ruc19oZWFsdGgocmVzb2x2X2NvbmY9UGF0aCgnL2V0'
    'Yy9yZXNvbHYuY29uZicpKToKICAgICMgZ2V0YWRkcmluZm8vY3VybCBtYXkgdXNlIG5zcy1yZXNvbHZlIG92ZXIgYSBVbml4'
    'IHNvY2tldCBhbmQgbWlzcyBhIGJyb2tlbgogICAgIyBVRFAgc3R1YiB1c2VkIGJ5IG90aGVyIGFwcGxpY2F0aW9ucy4gRXhl'
    'cmNpc2UgcmVzb2x2LmNvbmYgaW5kZXBlbmRlbnRseS4KICAgIHNlcnZlcnMgPSBbbGluZS5zcGxpdCgpWzFdIGZvciBsaW5l'
    'IGluIHJlc29sdl9jb25mLnJlYWRfdGV4dCgpLnNwbGl0bGluZXMoKQogICAgICAgICAgICAgICBpZiBsaW5lLnNwbGl0KClb'
    'OjFdID09IFsnbmFtZXNlcnZlciddIGFuZCBsZW4obGluZS5zcGxpdCgpKSA+PSAyXVs6M10KICAgIGZvciBzZXJ2ZXIgaW4g'
    'c2VydmVyczoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZhbWlseSA9IHNvY2tldC5BRl9JTkVUNiBpZiBpcGFkZHJlc3Mu'
    'aXBfYWRkcmVzcyhzZXJ2ZXIpLnZlcnNpb24gPT0gNiBlbHNlIHNvY2tldC5BRl9JTkVUCiAgICAgICAgICAgIHRyYW5zYWN0'
    'aW9uID0gc2VjcmV0cy50b2tlbl9ieXRlcygyKQogICAgICAgICAgICBxdWVyeSA9IHRyYW5zYWN0aW9uK2InXHgwMVx4MDBc'
    'eDAwXHgwMVx4MDBceDAwXHgwMFx4MDBceDAwXHgwMCcKICAgICAgICAgICAgcXVlcnkgKz0gYidceDAzYXBpXHgwNWlwaWZ5'
    'XHgwM29yZ1x4MDBceDAwXHgwMVx4MDBceDAxJwogICAgICAgICAgICB3aXRoIHNvY2tldC5zb2NrZXQoZmFtaWx5LCBzb2Nr'
    'ZXQuU09DS19ER1JBTSkgYXMgcmVzb2x2ZXI6CiAgICAgICAgICAgICAgICByZXNvbHZlci5zZXR0aW1lb3V0KDIpCiAgICAg'
    'ICAgICAgICAgICByZXNvbHZlci5jb25uZWN0KChzZXJ2ZXIsIDUzKSkKICAgICAgICAgICAgICAgIHJlc29sdmVyLnNlbmQo'
    'cXVlcnkpCiAgICAgICAgICAgICAgICBhbnN3ZXIgPSByZXNvbHZlci5yZWN2KDQwOTYpCiAgICAgICAgICAgIGlmIChsZW4o'
    'YW5zd2VyKSA+PSAxMiBhbmQgYW5zd2VyWzoyXSA9PSB0cmFuc2FjdGlvbiBhbmQKICAgICAgICAgICAgICAgICAgICBhbnN3'
    'ZXJbMl0gJiAweDgwIGFuZCBhbnN3ZXJbM10gJiAxNSA9PSAwIGFuZAogICAgICAgICAgICAgICAgICAgIGludC5mcm9tX2J5'
    'dGVzKGFuc3dlcls2OjhdLCAnYmlnJykgPiAwKToKICAgICAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICAgICAgZXhjZXB0'
    'IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICAgICAgY29udGludWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBzdGFy'
    'dF9uYW1lc3BhY2VfZG5zKCk6CiAgICAiIiJBIHByaXZhdGUgRE5TIGVuZHBvaW50IHJlYWNoYWJsZSBvbmx5IG92ZXIgdGhl'
    'IGhvc3QvbmFtZXNwYWNlIHZldGguIiIiCiAgICBnbG9iYWwgRE5TX1BST0NFU1MKICAgIGlmIEROU19QUk9DRVNTIGlzIG5v'
    'dCBOb25lIGFuZCBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgTm9uZTpyZXR1cm4KICAgIGNmZyA9IHsnbG9nJzp7J2xvZ2xldmVs'
    'Jzond2FybmluZycsJ2FjY2Vzcyc6J25vbmUnfSwKICAgICAgJ2luYm91bmRzJzpbeyd0YWcnOidkbnMtaW4nLCdsaXN0ZW4n'
    'OicxNzIuMjkuMjQ3LjInLCdwb3J0Jzo1MywncHJvdG9jb2wnOidkb2tvZGVtby1kb29yJywKICAgICAgICAgICAgICAgICAg'
    'ICdzZXR0aW5ncyc6eydhZGRyZXNzJzonMS4xLjEuMScsJ3BvcnQnOjUzLCduZXR3b3JrJzondGNwLHVkcCd9fV0sCiAgICAg'
    'ICdkbnMnOnsnc2VydmVycyc6WycxLjEuMS4xJywndGNwOi8vOS45LjkuOScsJ2h0dHBzOi8vMS4wLjAuMS9kbnMtcXVlcnkn'
    'XSwKICAgICAgICAgICAgICdxdWVyeVN0cmF0ZWd5JzonVXNlSVB2NCcsJ3RhZyc6J2Rucy1lbmdpbmUnLCdlbmFibGVQYXJh'
    'bGxlbFF1ZXJ5JzpUcnVlfSwKICAgICAgJ291dGJvdW5kcyc6W3sndGFnJzond2lyZScsJ3Byb3RvY29sJzonZnJlZWRvbSd9'
    'LAogICAgICAgICAgICAgICAgICAgeyd0YWcnOidkbnMnLCdwcm90b2NvbCc6J2RucycsJ3NldHRpbmdzJzp7J3J1bGVzJzpb'
    'eydxVHlwZSc6JzEsMjgnLCdhY3Rpb24nOidoaWphY2snfSx7J2FjdGlvbic6J2RpcmVjdCd9XX19XSwKICAgICAgJ3JvdXRp'
    'bmcnOnsncnVsZXMnOlt7J3R5cGUnOidmaWVsZCcsJ2luYm91bmRUYWcnOlsnZG5zLWluJ10sJ291dGJvdW5kVGFnJzonZG5z'
    'J30sCiAgICAgICAgICAgICAgICAgICAgICAgICAgeyd0eXBlJzonZmllbGQnLCdpbmJvdW5kVGFnJzpbJ2Rucy1lbmdpbmUn'
    'XSwnb3V0Ym91bmRUYWcnOid3aXJlJ31dfX0KICAgIHBhdGg9Uk9PVC8nbmFtZXNwYWNlLWRucy5qc29uJzt3cml0ZShwYXRo'
    'LGpzb24uZHVtcHMoY2ZnKSkKICAgIGJpbmFyeT0nL29wdC92cG4tbWFuYWdlci9iaW4veHJheScKICAgIGluc2lkZShbYmlu'
    'YXJ5LCdydW4nLCctdGVzdCcsJy1jb25maWcnLHBhdGhdKQogICAgRE5TX1BST0NFU1M9c3VicHJvY2Vzcy5Qb3BlbihbJ2lw'
    'JywnbmV0bnMnLCdleGVjJyxOUyxiaW5hcnksJ3J1bicsJy1jb25maWcnLHN0cihwYXRoKV0sCiAgICAgICAgc3RkaW49c3Vi'
    'cHJvY2Vzcy5ERVZOVUxMLHN0ZG91dD1zdWJwcm9jZXNzLkRFVk5VTEwsc3RkZXJyPXN1YnByb2Nlc3MuREVWTlVMTCkKICAg'
    'IGZvciBfIGluIHJhbmdlKDMwKToKICAgICAgICBpZiBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90IE5vbmU6cmFpc2UgUnVu'
    'dGltZUVycm9yKCdwcml2YXRlX2Ruc19zdG9wcGVkJykKICAgICAgICBpZiAnMTcyLjI5LjI0Ny4yOjUzJyBpbiBpbnNpZGUo'
    'WydzcycsJy1sbnUnXSxjaGVjaz1GYWxzZSkuc3Rkb3V0OgogICAgICAgICAgICB3cml0ZShQYXRoKCcvZXRjL25ldG5zJykv'
    'TlMvJ3Jlc29sdi5jb25mJywnbmFtZXNlcnZlciAxNzIuMjkuMjQ3LjJcbm9wdGlvbnMgdGltZW91dDozIGF0dGVtcHRzOjJc'
    'bicpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3By'
    'aXZhdGVfZG5zX25vdF9yZWFkeScpCgoKZGVmIHVzZV9yZXNvbHZlcl9maWxlKHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29u'
    'ZicpKToKICAgIGRhdGE9anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICB0YXJnZXQ9Uk9PVC8ncmVz'
    'b2x2LXZwbi5jb25mJwogICAgaWYgJ3Jlc29sdmVyX29yaWdpbmFsJyBub3QgaW4gZGF0YToKICAgICAgICBkYXRhWydyZXNv'
    'bHZlcl9vcmlnaW5hbCddPXsnbGluayc6b3MucmVhZGxpbmsocGF0aCkgaWYgcGF0aC5pc19zeW1saW5rKCkgZWxzZSBOb25l'
    'LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICd0ZXh0JzpwYXRoLnJlYWRfdGV4dCgpIGlmIHBhdGguZXhp'
    'c3RzKCkgZWxzZSAnJywKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnZXhpc3RlZCc6cGF0aC5leGlzdHMo'
    'KSBvciBwYXRoLmlzX3N5bWxpbmsoKX0KICAgIGRhdGFbJ2Ruc19mYWxsYmFjayddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3Rh'
    'dGUoKSxqc29uLmR1bXBzKGRhdGEpKQogICAgd3JpdGUodGFyZ2V0LCduYW1lc2VydmVyIDE3Mi4yOS4yNDcuMlxub3B0aW9u'
    'cyB0aW1lb3V0OjMgYXR0ZW1wdHM6MlxuJykKICAgIHRhcmdldC5jaG1vZCgwbzY0NCkKICAgICMgVGhlIHBhcmVudCBtdXN0'
    'IGJlIHRyYXZlcnNhYmxlIGJ5IGFwcGxpY2F0aW9ucy4gU2VjcmV0cyByZW1haW4gcm9vdC1vbmx5LgogICAgIyBQdXQgb25s'
    'eSB0aGlzIHB1YmxpYyByZXNvbHZlciBmaWxlIG91dHNpZGUgdGhlIGNyZWRlbnRpYWwgZGlyZWN0b3J5LgogICAgcHVibGlj'
    'PVBhdGgoJy9ydW4vZXZnZW5pdW0tcmVzb2x2LmNvbmYnKQogICAgcHVibGljLnBhcmVudC5ta2RpcihwYXJlbnRzPVRydWUs'
    'ZXhpc3Rfb2s9VHJ1ZSkKICAgIHdyaXRlKHB1YmxpYyx0YXJnZXQucmVhZF90ZXh0KCkpO3B1YmxpYy5jaG1vZCgwbzY0NCkK'
    'ICAgIHRlbXBvcmFyeT1wYXRoLndpdGhfbmFtZSgnLmV2Z2VuaXVtLXJlc29sdi5uZXcnKQogICAgdGVtcG9yYXJ5LnVubGlu'
    'ayhtaXNzaW5nX29rPVRydWUpO3RlbXBvcmFyeS5zeW1saW5rX3RvKHB1YmxpYykKICAgIG9zLnJlcGxhY2UodGVtcG9yYXJ5'
    'LHBhdGgpCgoKZGVmIHJlc3RvcmVfcmVzb2x2ZXJfZmlsZShkYXRhLHBhdGg9UGF0aCgnL2V0Yy9yZXNvbHYuY29uZicpKToK'
    'ICAgIHNhdmVkPWRhdGEuZ2V0KCdyZXNvbHZlcl9vcmlnaW5hbCcpCiAgICBpZiBzYXZlZCBhbmQgcGF0aC5pc19zeW1saW5r'
    'KCkgYW5kIG9zLnJlYWRsaW5rKHBhdGgpPT0nL3J1bi9ldmdlbml1bS1yZXNvbHYuY29uZic6CiAgICAgICAgdGVtcG9yYXJ5'
    'PXBhdGgud2l0aF9uYW1lKCcuZXZnZW5pdW0tcmVzb2x2LnJlc3RvcmUnKQogICAgICAgIHRlbXBvcmFyeS51bmxpbmsobWlz'
    'c2luZ19vaz1UcnVlKQogICAgICAgIGlmIHNhdmVkWydsaW5rJ10gaXMgbm90IE5vbmU6dGVtcG9yYXJ5LnN5bWxpbmtfdG8o'
    'c2F2ZWRbJ2xpbmsnXSkKICAgICAgICBlbHNlOnRlbXBvcmFyeS53cml0ZV90ZXh0KHNhdmVkWyd0ZXh0J10pO3RlbXBvcmFy'
    'eS5jaG1vZCgwbzY0NCkKICAgICAgICBpZiBzYXZlZC5nZXQoJ2V4aXN0ZWQnLFRydWUpOm9zLnJlcGxhY2UodGVtcG9yYXJ5'
    'LHBhdGgpCiAgICAgICAgZWxzZTpwYXRoLnVubGluaygpO3RlbXBvcmFyeS51bmxpbmsoKQogICAgZWxpZiBub3Qgc2F2ZWQg'
    'YW5kICdkbnNfYmFja3VwJyBpbiBkYXRhOgogICAgICAgIHBhdGgud3JpdGVfdGV4dChkYXRhWydkbnNfYmFja3VwJ10pCgoK'
    'ZGVmIHJlY292ZXJfc3lzdGVtX2RucygpOgogICAgZm9yIF8gaW4gcmFuZ2UoMik6CiAgICAgICAgaWYgc3lzdGVtX2Ruc19o'
    'ZWFsdGgoKTpyZXR1cm4gVHJ1ZQogICAgICAgIGlmIFNUT1A6cmV0dXJuIEZhbHNlCiAgICAgICAgdGltZS5zbGVlcCguMykK'
    'ICAgIGlmIG5vdCBmdWxsX3N0YXRlKCkuZXhpc3RzKCk6cmV0dXJuIEZhbHNlCiAgICAjIFN3aXRjaCBvbmx5IHRoZSByZXNv'
    'bHZlciBmaWxlIHdlIG93bjsgbmV2ZXIgc3RvcCBhbm90aGVyIFZQTiBvciByZXNvbHZlci4KICAgIHN0YWdlKCdyZXBhaXJp'
    'bmcnLCfQn9C10YDQtdC60LvRjtGH0LDRjiDQvdC10LjRgdC/0YDQsNCy0L3Ri9C5INGB0LjRgdGC0LXQvNC90YvQuSBETlMg'
    '0L3QsCDQt9Cw0YnQuNGJ0ZHQvdC90YvQuSDRgNC10LfQtdGA0LIuJyw5MCxhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT0nc3lz'
    'dGVtX2Ruc19mYWlsZWQnKQogICAgdXNlX3Jlc29sdmVyX2ZpbGUoKQogICAgcmV0dXJuIHN5c3RlbV9kbnNfaGVhbHRoKCkK'
    'CgpkZWYgcGVyc2lzdF9ndWFyZChydWxlcyk6CiAgICAjIEd1YXJkIHBlcnNpc3RlbmNlIHByZWNlZGVzIHN3aXRjaGluZy4g'
    'Q2xlYW51cCBhZnRlciBhIGNyYXNoIG5ldmVyIG9wZW5zIHRoZSBJbnRlcm5ldC4KICAgIGd1YXJkX3VuaXQgPSAnJydbVW5p'
    'dF0KRGVzY3JpcHRpb249RXZnZW5pdW0gZnVsbC1kZXZpY2Uga2lsbCBzd2l0Y2gKRGVmYXVsdERlcGVuZGVuY2llcz1ubwpB'
    'ZnRlcj1sb2NhbC1mcy50YXJnZXQKQmVmb3JlPW5ldHdvcmstcHJlLnRhcmdldApbU2VydmljZV0KVHlwZT1vbmVzaG90ClJl'
    'bWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0PS91c3Ivc2Jpbi9uZnQgLWYgL2V0Yy92cG4tbWFuYWdlci9zdGFyZml2ZS10'
    'dW5uZWwvZnVsbC1ndWFyZC5uZnQKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CicnJy5yZXBsYWNlKCcv'
    'dXNyL3NiaW4vbmZ0Jywgc2h1dGlsLndoaWNoKCduZnQnKSkKICAgIHdyaXRlKFJPT1QvJ2Z1bGwtZ3VhcmQubmZ0JyxydWxl'
    'cykKICAgIHdyaXRlKFBhdGgoJy9ldGMvc3lzdGVtZC9zeXN0ZW0vZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2'
    'aWNlJyksZ3VhcmRfdW5pdCkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5k'
    'KFsnc3lzdGVtY3RsJywnZW5hYmxlJywnZXZnZW5pdW0tc3RhcmZpdmUtZnVsbC1ndWFyZC5zZXJ2aWNlJ10pCgoKZGVmIGFj'
    'dGl2YXRlX2Z1bGwoYWRkcmVzcyk6CiAgICBvbGRfYWRkcmVzc2VzID0gW2FbJ2xvY2FsJ10gZm9yIGxpbmsgaW4ganNvbi5s'
    'b2Fkcyhjb21tYW5kKFsnaXAnLCctaicsJy00JywnYWRkcicsJ3Nob3cnLCdzY29wZScsJ2dsb2JhbCddKS5zdGRvdXQpCiAg'
    'ICAgICAgICAgICAgICAgICAgIGlmIGxpbmsuZ2V0KCdpZm5hbWUnKSBub3QgaW4gKEhPU1QsRlVMTF9IT1NUKQogICAgICAg'
    'ICAgICAgICAgICAgICBmb3IgYSBpbiBsaW5rLmdldCgnYWRkcl9pbmZvJyxbXSkgaWYgYS5nZXQoJ3Njb3BlJykgPT0gJ2ds'
    'b2JhbCddCiAgICBpZiBub3QgZnVsbF9zdGF0ZSgpLmV4aXN0cygpOgogICAgICAgIGlmIFBhdGgoJy9zeXMvY2xhc3MvbmV0'
    'LycrRlVMTF9IT1NUKS5leGlzdHMoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdmdWxsX2ludGVyZmFjZV9j'
    'b2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxGVUxMX1RBQkxFXSxj'
    'aGVjaz1GYWxzZSkuc3Rkb3V0LnN0cmlwKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF90YWJsZV9j'
    'b2xsaXNpb24nKQogICAgICAgIGlmIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnc2hvdycsJ3RhYmxlJyxBRE1JTl9UQUJMRV0s'
    'Y2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2FkbWluX3RhYmxl'
    'X2NvbGxpc2lvbicpCiAgICAgICAgaWYgYW55KHIuZ2V0KCdwcmlvcml0eScpIGluICg3OSw4MCkgZm9yIHIgaW4ganNvbi5s'
    'b2Fkcyhjb21tYW5kKFsnaXAnLCctaicsJy00JywncnVsZSddKS5zdGRvdXQpKToKICAgICAgICAgICAgcmFpc2UgUnVudGlt'
    'ZUVycm9yKCdmdWxsX3J1bGVfY29sbGlzaW9uJykKICAgICAgICB3cml0ZShmdWxsX3N0YXRlKCksanNvbi5kdW1wcyh7J2Fj'
    'dGl2ZSc6RmFsc2V9KSkKICAgIGZ1bGxfbmFtZXNwYWNlKGFkZHJlc3MpCiAgICBzdGFydF9uYW1lc3BhY2VfZG5zKCkKICAg'
    'ICMgVmFsaWRhdGUgdGhlIGVncmVzcyBmaWx0ZXIgYmVmb3JlIGludGVycnVwdGluZyB0aGUgcHJldmlvdXMgVlBOLgogICAg'
    'aWYgbm90IGVncmVzc19oZWFsdGgoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2VzdG9uaWFfZWdyZXNzX2ZhaWxl'
    'ZCcpCiAgICBydWxlcyA9IGZ1bGxfZmlyZXdhbGwoKQogICAgIyBSZXBhaXIgbWF5IGluaGVyaXQgYSBndWFyZCBmcm9tIGFu'
    'IG9sZGVyIHZlcnNpb24uIFJlcGxhY2Ugb3VyIHRhYmxlIGluCiAgICAjIG9uZSBuZnQgdHJhbnNhY3Rpb24sIHNvIGZpeGVz'
    'IGFwcGx5IHdpdGhvdXQgb3BlbmluZyBhbiB1bmd1YXJkZWQgd2luZG93LgogICAgcmVwbGFjZW1lbnQgPSAoJ2RlbGV0ZSB0'
    'YWJsZSBpbmV0ICcrRlVMTF9HVUFSRCsnXG4nIGlmIGZ1bGxfZ3VhcmRfYWN0aXZlKCkgZWxzZSAnJykrcnVsZXMKICAgIGNv'
    'bW1hbmQoWyduZnQnLCctYycsJy1mJywnLSddLGRhdGE9cmVwbGFjZW1lbnQpCiAgICBjb21tYW5kKFsnbmZ0JywnLWYnLCct'
    'J10sZGF0YT1yZXBsYWNlbWVudCkKICAgIHBlcnNpc3RfZ3VhcmQocnVsZXMpCiAgICAjIFRoaXMgY29tbWFuZCBzdG9wcyBv'
    'bmx5IHRoaXMgbWFuYWdlcidzIHByZXZpb3VzIFhyYXkgbW9kZSBhbmQgcmVtb3ZlcyBpdHMgZ3VhcmQuCiAgICBjb21tYW5k'
    'KFsnL3Vzci9sb2NhbC9zYmluL3ZwbmN0bCcsJ2ludGVybmFsLXN0YXJmaXZlLXBhdXNlLW1haW4nXSx0aW1lb3V0PTQwKQog'
    'ICAgY29tbWFuZChbJ2lwJywncm91dGUnLCdyZXBsYWNlJywndW5yZWFjaGFibGUnLCdkZWZhdWx0JywnbWV0cmljJywnMzI3'
    'NjAnLCd0YWJsZScsRlVMTF9UQUJMRV0pCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3JlcGxhY2UnLCdkZWZhdWx0Jywn'
    'dmlhJywnMTcyLjI5LjI0Ny4yJywnZGV2JyxGVUxMX0hPU1QsJ21ldHJpYycsJzEwJywndGFibGUnLEZVTExfVEFCTEVdKQog'
    'ICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNr'
    'PUZhbHNlKQogICAgZm9yIHJ1bGUgaW4gKFsncHJpb3JpdHknLCc3OScsJ3RvJyxDTElFTlQrJy8zMicsJ2xvb2t1cCcsJ21h'
    'aW4nXSwKICAgICAgICAgICAgICAgICBbJ3ByaW9yaXR5JywnNzknLCdpaWYnLEZVTExfSE9TVCwnbG9va3VwJywnbWFpbidd'
    'KToKICAgICAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywqcnVsZV0sY2hlY2s9RmFsc2UpCiAgICAgICAgY29tbWFu'
    'ZChbJ2lwJywncnVsZScsJ2FkZCcsKnJ1bGVdKQogICAgY29tbWFuZChbJ2lwJywncnVsZScsJ2FkZCcsJ3ByaW9yaXR5Jywn'
    'ODAnLCdsb29rdXAnLEZVTExfVEFCTEVdKQogICAgZGF0YT1qc29uLmxvYWRzKGZ1bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkK'
    'ICAgIGlmIHNodXRpbC53aGljaCgncmVzb2x2ZWN0bCcpIGFuZCBjb21tYW5kKFsnc3lzdGVtY3RsJywnaXMtYWN0aXZlJywn'
    'LS1xdWlldCcsJ3N5c3RlbWQtcmVzb2x2ZWQnXSxjaGVjaz1GYWxzZSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgIGRhdGFb'
    'J2Ruc19tb2RlJ109J3Jlc29sdmVkX2xpbmsnCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoZGF0YSkp'
    'CiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkbnMnLEZVTExfSE9TVCwnMTcyLjI5LjI0Ny4yJ10pCiAgICAgICAg'
    'Y29tbWFuZChbJ3Jlc29sdmVjdGwnLCdkb21haW4nLEZVTExfSE9TVCwnfi4nXSkKICAgICAgICBjb21tYW5kKFsncmVzb2x2'
    'ZWN0bCcsJ2RlZmF1bHQtcm91dGUnLEZVTExfSE9TVCwneWVzJ10pCiAgICAgICAgY29tbWFuZChbJ3Jlc29sdmVjdGwnLCdm'
    'bHVzaC1jYWNoZXMnXSxjaGVjaz1GYWxzZSkKICAgIGVsc2U6CiAgICAgICAgdXNlX3Jlc29sdmVyX2ZpbGUoKQogICAgY2xl'
    'YXJfZG5zX21hcHBpbmdzKHByZXZpb3VzX3Zwbj1UcnVlKQogICAgcmV0aXJlX3ByZXZpb3VzX2Nvbm5lY3Rpb25zKG9sZF9h'
    'ZGRyZXNzZXMpCiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgcG9saWN5LmFwcGx5KCkKICAgIGlmIG5vdCBy'
    'ZWNvdmVyX3N5c3RlbV9kbnMoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3N5c3RlbV9kbnNfZmFpbGVkJykKICAg'
    'ICMgVGVzdCB0aGUgYWN0dWFsIGhvc3QgcGF0aCBhcyB3ZWxsIGFzIG5hbWVzcGFjZSBwcm9iZXMgYmVmb3JlIGFubm91bmNp'
    'bmcgY29ubmVjdGVkLgogICAgY2hlY2sgPSBjb21tYW5kKFsnY3VybCcsJy00JywnLS1ub3Byb3h5JywnJyBpZiBwb2xpY3kg'
    'aXMgbm90IE5vbmUgZWxzZSAnKicsJy0tZmFpbCcsJy0tc2lsZW50JywnLS1tYXgtdGltZScsJzEwJywqKFsnLS1zb2NrczUt'
    'aG9zdG5hbWUnLCcxMjcuMC4wLjE6MTg1NTQnXSBpZiBwb2xpY3kgaXMgbm90IE5vbmUgZWxzZSBbXSksJ2h0dHBzOi8vYXBp'
    'LmlwaWZ5Lm9yZyddLHRpbWVvdXQ9MTIpCiAgICBpZiBjaGVjay5zdGRvdXQuc3RyaXAoKSAhPSAnMzguMTgwLjE2NC42Nyc6'
    'CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdob3N0X2VncmVzc19mYWlsZWQnKQogICAgZGF0YT1qc29uLmxvYWRzKGZ1'
    'bGxfc3RhdGUoKS5yZWFkX3RleHQoKSkKICAgIGRhdGFbJ2FjdGl2ZSddPVRydWUKICAgIHdyaXRlKGZ1bGxfc3RhdGUoKSxq'
    'c29uLmR1bXBzKGRhdGEpKQoKCmRlZiBjbGVhbnVwX2Z1bGwocmVsZWFzZT1GYWxzZSk6CiAgICBnbG9iYWwgRE5TX1BST0NF'
    'U1MKICAgIGlmIEROU19QUk9DRVNTIGlzIG5vdCBOb25lIGFuZCBETlNfUFJPQ0VTUy5wb2xsKCkgaXMgTm9uZToKICAgICAg'
    'ICBETlNfUFJPQ0VTUy50ZXJtaW5hdGUoKQogICAgICAgIHRyeTpETlNfUFJPQ0VTUy53YWl0KHRpbWVvdXQ9MykKICAgICAg'
    'ICBleGNlcHQgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZDpETlNfUFJPQ0VTUy5raWxsKCk7RE5TX1BST0NFU1Mud2FpdCgp'
    'CiAgICBETlNfUFJPQ0VTUz1Ob25lCiAgICBpZiBwb2xpY3kgaXMgbm90IE5vbmU6CiAgICAgICAgcG9saWN5LnN0b3AocmVs'
    'ZWFzZT1yZWxlYXNlKQogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToKICAgICAgICByZXR1cm4KICAgIGRhdGE9'
    'anNvbi5sb2FkcyhmdWxsX3N0YXRlKCkucmVhZF90ZXh0KCkpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2RlbCcsJ2Rl'
    'ZmF1bHQnLCdtZXRyaWMnLCcxMCcsJ3RhYmxlJyxGVUxMX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWydpcCcs'
    'J2xpbmsnLCdkZWwnLEZVTExfSE9TVF0sY2hlY2s9RmFsc2UpCiAgICAjIE9uIGZhaWx1cmU6IHJldGFpbiByb3V0aW5nLCBE'
    'TlMgYW5kIHRoZSBwZXJzaXN0ZW50IGd1YXJkIHVudGlsIGV4cGxpY2l0IGRpc2Nvbm5lY3QuCiAgICBpZiBub3QgcmVsZWFz'
    'ZToKICAgICAgICByZXR1cm4KICAgIHJlc3RvcmVfcmVzb2x2ZXJfZmlsZShkYXRhKQogICAgY29tbWFuZChbJ2lwJywncnVs'
    'ZScsJ2RlbCcsJ3ByaW9yaXR5JywnODAnLCdsb29rdXAnLEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChb'
    'J2lwJywncnVsZScsJ2RlbCcsJ3ByaW9yaXR5JywnNzknLCd0bycsQ0xJRU5UKycvMzInLCdsb29rdXAnLCdtYWluJ10sY2hl'
    'Y2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdydWxlJywnZGVsJywncHJpb3JpdHknLCc3OScsJ2lpZicsRlVMTF9IT1NU'
    'LCdsb29rdXAnLCdtYWluJ10sY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ2ZsdXNoJywndGFibGUn'
    'LEZVTExfVEFCTEVdLGNoZWNrPUZhbHNlKQogICAgZm9yIHNlcnZlciBpbiAoJzE5Mi4xNjguMC4xNjMnLCAnMzguMTgwLjE2'
    'NC42NycpOgogICAgICAgIGNvbW1hbmQoWydpcCcsJ3J1bGUnLCdkZWwnLCdwcmlvcml0eScsJzc5JywndG8nLHNlcnZlciwn'
    'aXBwcm90bycsJ3RjcCcsJ2Rwb3J0JywnMjInLCdsb29rdXAnLEFETUlOX1RBQkxFXSxjaGVjaz1GYWxzZSkKICAgIGNvbW1h'
    'bmQoWydzeXN0ZW1jdGwnLCdkaXNhYmxlJywnLS1ub3cnLCdldmdlbml1bS1zdGFyZml2ZS1mdWxsLWd1YXJkLnNlcnZpY2Un'
    'XSxjaGVjaz1GYWxzZSkKICAgIGNvbW1hbmQoWyduZnQnLCdkZWxldGUnLCd0YWJsZScsJ2luZXQnLEZVTExfR1VBUkRdLGNo'
    'ZWNrPUZhbHNlKQogICAgY2xlYXJfZG5zX21hcHBpbmdzKCkKICAgIGNsZWFyX2Ruc19tYXBwaW5ncyhwcmV2aW91c192cG49'
    'VHJ1ZSkKICAgIGNvbW1hbmQoWydpcCcsJ3JvdXRlJywnZmx1c2gnLCd0YWJsZScsQURNSU5fVEFCTEVdLGNoZWNrPUZhbHNl'
    'KQogICAgZnVsbF9zdGF0ZSgpLnVubGluaygpCiAgICBjb21tYW5kKFsncmVzb2x2ZWN0bCcsJ2ZsdXNoLWNhY2hlcyddLGNo'
    'ZWNrPUZhbHNlKSBpZiBzaHV0aWwud2hpY2goJ3Jlc29sdmVjdGwnKSBlbHNlIE5vbmUKCgpkZWYgY29tbWFuZChhcmdzLCBj'
    'aGVjaz1UcnVlLCB0aW1lb3V0PTIwLCBkYXRhPU5vbmUsIGVudj1Ob25lKToKICAgIGNwID0gc3VicHJvY2Vzcy5ydW4oW3N0'
    'cih4KSBmb3IgeCBpbiBhcmdzXSwgaW5wdXQ9ZGF0YSwgdGV4dD1UcnVlLCBjYXB0dXJlX291dHB1dD1UcnVlLAogICAgICAg'
    'ICAgICAgICAgICAgICAgICB0aW1lb3V0PXRpbWVvdXQsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAgaWYgY2hlY2sgYW5k'
    'IGNwLnJldHVybmNvZGU6CiAgICAgICAgIyBBcmd1bWVudHMgbWF5IGNvbnRhaW4gYSBDU1IgcGF0aDsgZG8gbm90IHByb3Bh'
    'Z2F0ZSBwcm9jZXNzIG91dHB1dCB0byBHVUkvbG9ncy4KICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2NvbW1hbmRfZmFp'
    'bGVkJykKICAgIHJldHVybiBjcAoKCmRlZiBpbnNpZGUoYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIGNvbW1hbmQoWydp'
    'cCcsICduZXRucycsICdleGVjJywgTlMsICphcmdzXSwgKiprd2FyZ3MpCgoKZGVmIHdyaXRlKHBhdGgsIHZhbHVlKToKICAg'
    'IHBhdGgucGFyZW50Lm1rZGlyKHBhcmVudHM9VHJ1ZSwgbW9kZT0wbzcwMCwgZXhpc3Rfb2s9VHJ1ZSkKICAgIHRlbXBvcmFy'
    'eSA9IHBhdGgud2l0aF9zdWZmaXgoJy5uZXcnKQogICAgZmQgPSBvcy5vcGVuKHRlbXBvcmFyeSwgb3MuT19XUk9OTFkgfCBv'
    'cy5PX0NSRUFUIHwgb3MuT19UUlVOQyB8IG9zLk9fTk9GT0xMT1csIDBvNjAwKQogICAgd2l0aCBvcy5mZG9wZW4oZmQsICd3'
    'JykgYXMgc3RyZWFtOgogICAgICAgIHN0cmVhbS53cml0ZSh2YWx1ZSkKICAgIHRlbXBvcmFyeS5yZXBsYWNlKHBhdGgpCgoK'
    'ZGVmIHNhdmVkKCk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuIGpzb24ubG9hZHMoU1RBVEUucmVhZF90ZXh0KCkpCiAgICBl'
    'eGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IpOgogICAgICAgIHJldHVybiB7fQoKCmRlZiBzdGFnZShwaGFzZSwgbWVzc2Fn'
    'ZSwgcHJvZ3Jlc3MsICoqZmllbGRzKToKICAgIGRhdGEgPSB7KipzYXZlZCgpLCAncGhhc2UnOiBwaGFzZSwgJ21lc3NhZ2Un'
    'OiBtZXNzYWdlLCAncHJvZ3Jlc3MnOiBwcm9ncmVzcywKICAgICAgICAgICAgJ3VwZGF0ZWQnOiBpbnQodGltZS50aW1lKCkp'
    'LCAnaGVhcnRiZWF0JzogdGltZS5tb25vdG9uaWMoKSwgKipmaWVsZHN9CiAgICB3cml0ZShTVEFURSwganNvbi5kdW1wcyhk'
    'YXRhLCBlbnN1cmVfYXNjaWk9RmFsc2UpKQogICAgaWYgc3VwcG9ydF9hcGkgaXMgbm90IE5vbmU6CiAgICAgICAgdHJ5OnN1'
    'cHBvcnRfYXBpLnJlY29yZChST09ULHdyaXRlLGRhdGEpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLFZhbHVlRXJyb3IsVHlw'
    'ZUVycm9yKTpwYXNzCgoKZGVmIHNlbGVjdGVkX3JvdXRlKCk6CiAgICB0cnk6dmFsdWU9anNvbi5sb2FkcygoUk9PVC8nc2Vs'
    'ZWN0aW9uLmpzb24nKS5yZWFkX3RleHQoKSkuZ2V0KCdyb3V0ZScsJ2F1dG8nKQogICAgZXhjZXB0IChPU0Vycm9yLFZhbHVl'
    'RXJyb3IsQXR0cmlidXRlRXJyb3IpOnZhbHVlPSdhdXRvJwogICAgcmV0dXJuIHZhbHVlIGlmIHZhbHVlIGluIHsnYXV0bycs'
    'KihjWydpZCddIGZvciBjIGluIENBTkRJREFURVMpfSBlbHNlICdhdXRvJwoKCmRlZiBzZWxlY3Rfcm91dGUodmFsdWUpOgog'
    'ICAgaWYgdmFsdWUgbm90IGluIHsnYXV0bycsKihjWydpZCddIGZvciBjIGluIENBTkRJREFURVMpfTpyYWlzZSBWYWx1ZUVy'
    'cm9yKCfQndC10LjQt9Cy0LXRgdGC0L3Ri9C5INC80LDRgNGI0YDRg9GCLicpCiAgICB3cml0ZShST09ULydzZWxlY3Rpb24u'
    'anNvbicsanNvbi5kdW1wcyh7J3JvdXRlJzp2YWx1ZX0pKQoKCmRlZiByb3V0ZV9jaG9pY2VzKCk6CiAgICByYW5raW5nPXJh'
    'bmtfYXBpLlJhbmtpbmcoUk9PVC8ncmFua2luZy5qc29uJyxbY1snaWQnXSBmb3IgYyBpbiBDQU5ESURBVEVTXSkgaWYgcmFu'
    'a19hcGkgZWxzZSBOb25lCiAgICBvcmRlcj1yYW5raW5nLmNhbmRpZGF0ZXMoKSBpZiByYW5raW5nIGFuZCByYW5raW5nLmxv'
    'YWQoKSBlbHNlIFtdCiAgICByZXR1cm4geydzZWxlY3RlZCc6c2VsZWN0ZWRfcm91dGUoKSwnY2hvaWNlcyc6W3snaWQnOmNb'
    'J2lkJ10sJ2xhYmVsJzpjWydsYWJlbCddfSBmb3IgYyBpbiBDQU5ESURBVEVTXSwKICAgICAgICAgICAgJ29yZGVyJzpvcmRl'
    'ciwnZW50cmllcyc6cmFua2luZy5kYXRhWydlbnRyaWVzJ10gaWYgb3JkZXIgZWxzZSB7fX0KCgpkZWYgc3RhdHVzKCk6CiAg'
    'ICBkYXRhID0gc2F2ZWQoKQogICAgcnVubmluZyA9IGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVp'
    'ZXQnLCBVTklUXSwgY2hlY2s9RmFsc2UsIHRpbWVvdXQ9MikucmV0dXJuY29kZSA9PSAwCiAgICBpZiBkYXRhLmdldCgncGhh'
    'c2UnKSA9PSAnY29ubmVjdGVkJyBhbmQgKG5vdCBydW5uaW5nIG9yIHRpbWUubW9ub3RvbmljKCktZGF0YS5nZXQoJ2hlYXJ0'
    'YmVhdCcsIDApID4gOTApOgogICAgICAgIGRhdGEudXBkYXRlKHBoYXNlPSdpbnRlcnJ1cHRlZCcsIG1lc3NhZ2U9J9Ch0L7Q'
    'tdC00LjQvdC10L3QuNC1INC+0YHRgtCw0L3QvtCy0LjQu9C+0YHRjC4g0J/RgNC+0LLQtdGA0YzRgtC1INGB0L7RgdGC0L7R'
    'j9C90LjQtSDQt9Cw0YnQuNGC0Ysg0Lgg0L3QsNC20LzQuNGC0LUgwqvQn9C+0YfQuNC90LjRgtGMwrsuJywgYWN0aXZlPUZh'
    'bHNlKQogICAgcHVibGljID0ge2tleTogZGF0YVtrZXldIGZvciBrZXkgaW4gKCdwaGFzZScsICdtZXNzYWdlJywgJ3Byb2dy'
    'ZXNzJywgJ2FjdGl2ZScsICd1cGRhdGVkJywgJ21ldHJpY3MnLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgJ3Njb3BlJywgJ3NpbmNlJywgJ3JldHJ5JywgJ2Vycm9yX2NvZGUnLCAncGF0aCcpIGlmIGtleSBpbiBkYXRhfQog'
    'ICAgdG9rZW5faW5mbyA9IHRva2VuX3N0YXR1cygpCiAgICByZXR1cm4geydwaGFzZSc6ICdvZmYnLCAnbWVzc2FnZSc6ICgn'
    '0KLQvtC60LXQvSDRgdC+0YXRgNCw0L3RkdC9LiDQndCw0LbQvNC40YLQtSDCq9Cf0L7QtNC60LvRjtGH0LjRgtGMwrsuJyBp'
    'ZiB0b2tlbl9pbmZvWydoYXNfdG9rZW4nXSBlbHNlICfQktCy0LXQtNC40YLQtSDQuCDQv9C+0LTRgtCy0LXRgNC00LjRgtC1'
    'INGC0L7QutC10L0g0LrQu9C40LXQvdGC0LAuJyksCiAgICAgICAgICAgICdwcm9ncmVzcyc6IDAsICdhY3RpdmUnOiBGYWxz'
    'ZSwgKipwdWJsaWMsICdydW5uaW5nJzogcnVubmluZywKICAgICAgICAgICAgKip0b2tlbl9pbmZvLCAqKmRldmljZV9zdGF0'
    'dXMoKSwgJ3JvdXRlcyc6cm91dGVfY2hvaWNlcygpLCAnaXNvbGF0ZWQnOiBGYWxzZSwgJ2Z1bGxfZGV2aWNlJzogVHJ1ZSwg'
    'J2d1YXJkJzogZnVsbF9ndWFyZF9hY3RpdmUoKSwgJ3Byb3RvY29sJzogJ0lLRXYyIOKGkiDQrdGB0YLQvtC90LjRjyd9CgoK'
    'QGNvbnRleHRsaWIuY29udGV4dG1hbmFnZXIKZGVmIG5hbWVzcGFjZSgpOgogICAgYmVmb3JlID0gb3Mub3BlbignL3Byb2Mv'
    'c2VsZi9ucy9uZXQnLCBvcy5PX1JET05MWSkKICAgIHRhcmdldCA9IG9zLm9wZW4oJy9ydW4vbmV0bnMvJytOUywgb3MuT19S'
    'RE9OTFkpCiAgICB0cnk6CiAgICAgICAgb3Muc2V0bnModGFyZ2V0LCBvcy5DTE9ORV9ORVdORVQpCiAgICAgICAgeWllbGQK'
    'ICAgIGZpbmFsbHk6CiAgICAgICAgb3Muc2V0bnMoYmVmb3JlLCBvcy5DTE9ORV9ORVdORVQpCiAgICAgICAgb3MuY2xvc2Uo'
    'dGFyZ2V0KQogICAgICAgIG9zLmNsb3NlKGJlZm9yZSkKCgpkZWYgcGh5c2ljYWxfcm91dGUoKToKICAgIHJvdXRlcyA9IGpz'
    'b24ubG9hZHMoY29tbWFuZChbJ2lwJywgJy1qJywgJy00JywgJ3JvdXRlJywgJ3Nob3cnLCAndGFibGUnLCAnbWFpbicsICdk'
    'ZWZhdWx0J10pLnN0ZG91dCkKICAgIGNhbmRpZGF0ZXMgPSBbciBmb3IgciBpbiByb3V0ZXMgaWYgci5nZXQoJ2dhdGV3YXkn'
    'KSBhbmQgci5nZXQoJ2RldicpIGFuZAogICAgICAgICAgICAgICAgICBub3QgclsnZGV2J10uc3RhcnRzd2l0aCgoJ3R1bics'
    'ICd4cmF5JywgJ3dnJywgJ2V2bi0nKSldCiAgICBpZiBub3QgY2FuZGlkYXRlczoKICAgICAgICByYWlzZSBSdW50aW1lRXJy'
    'b3IoJ25vX3BoeXNpY2FsX3JvdXRlJykKICAgIHJvdXRlID0gbWluKGNhbmRpZGF0ZXMsIGtleT1sYW1iZGEgcjogci5nZXQo'
    'J21ldHJpYycsIDApKQogICAgaWYgbm90IHJlLmZ1bGxtYXRjaChyJ1tBLVphLXowLTlfLjotXXsxLDE1fScsIHJvdXRlWydk'
    'ZXYnXSk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX2ludGVyZmFjZScpCiAgICBpcGFkZHJlc3MuSVB2'
    'NEFkZHJlc3Mocm91dGVbJ2dhdGV3YXknXSkKICAgIHJldHVybiByb3V0ZQoKCmRlZiBob3N0X3J1bGVzKGlmYWNlLCBwcmV2'
    'aW91c19mb3J3YXJkPVRydWUpOgogICAgIyBTY29wZSBldmVyeSBuZXcgZm9yd2FyZGluZy9OQVQgcnVsZSB0byBvdXIgb25l'
    'IGludGVyZmFjZSBhbmQgdGhlIGNvbmZpZ3VyZWQgaW5ncmVzcyBhZGRyZXNzLgogICAgcHJlc2VydmVfZGlzYWJsZWQgPSAn'
    'JyBpZiBwcmV2aW91c19mb3J3YXJkIGVsc2UgJycnICBpaWZuYW1lICJ3YXlkcm9pZDAiIG1ldGEgbmZwcm90byBpcHY0IGFj'
    'Y2VwdAogIG9pZm5hbWUgIndheWRyb2lkMCIgbWV0YSBuZnByb3RvIGlwdjQgY3Qgc3RhdGUgZXN0YWJsaXNoZWQscmVsYXRl'
    'ZCBhY2NlcHQKICBtZXRhIG5mcHJvdG8gaXB2NCBkcm9wJycnCiAgICByZXR1cm4gZicnJ3RhYmxlIGluZXQge05GVH0ge3sK'
    'IGNoYWluIGZvcndhcmQge3sKICB0eXBlIGZpbHRlciBob29rIGZvcndhcmQgcHJpb3JpdHkgLTIwOyBwb2xpY3kgYWNjZXB0'
    'OwogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFkZHIge3sge1NFUlZFUn0gfX0gdWRwIGRwb3J0IHtJS0VfUE9SVH0gYWNjZXB0'
    'CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHVkcCBkcG9ydCA0'
    'NDMgYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBpcCBkYWRkciAzOC4xODAuMTY0LjY3IHRj'
    'cCBkcG9ydCB7eyAyNDU3MSwgMjQ1NzggfX0gYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBpcCBzYWRkciB7Q0xJRU5UfSBp'
    'cCBkYWRkciAxOTUuMjA5LjIxMS4xNjMgdGNwIGRwb3J0IDI0NTc5IGFjY2VwdAogIGlpZm5hbWUgIntIT1NUfSIgaXAgZGFk'
    'ZHIge3sge1NFUlZFUn0gfX0gdGNwIGRwb3J0IDg0NDMgYWNjZXB0CiAgaWlmbmFtZSAie0hPU1R9IiBkcm9wCiAgb2lmbmFt'
    'ZSAie0hPU1R9IiBpcCBzYWRkciB7eyB7U0VSVkVSfSwgMzguMTgwLjE2NC42NyB9fSBjdCBzdGF0ZSBlc3RhYmxpc2hlZCxy'
    'ZWxhdGVkIGFjY2VwdAogIG9pZm5hbWUgIntIT1NUfSIgZHJvcAp7cHJlc2VydmVfZGlzYWJsZWR9CiB9fQogY2hhaW4gbmF0'
    'IHt7CiAgdHlwZSBuYXQgaG9vayBwb3N0cm91dGluZyBwcmlvcml0eSBzcmNuYXQ7IHBvbGljeSBhY2NlcHQ7CiAgaXAgc2Fk'
    'ZHIge0NMSUVOVH0gb2lmbmFtZSAie2lmYWNlfSIgbWFzcXVlcmFkZQogfX0KfX0nJycKCgpkZWYgc2V0dXBfbmV0d29yaygp'
    'OgogICAgcm91dGUgPSBwaHlzaWNhbF9yb3V0ZSgpCiAgICAjIFJlZnVzZSBuYW1lL2FkZHJlc3MgY29sbGlzaW9ucyByYXRo'
    'ZXIgdGhhbiByZXB1cnBvc2luZyBhbm90aGVyIGFwcGxpY2F0aW9uJ3MgcmVzb3VyY2VzLgogICAgaWYgUGF0aCgnL3J1bi9u'
    'ZXRucy8nK05TKS5leGlzdHMoKSBvciBQYXRoKCcvc3lzL2NsYXNzL25ldC8nK0hPU1QpLmV4aXN0cygpIG9yIChQYXRoKCcv'
    'ZXRjL25ldG5zJykvTlMpLmV4aXN0cygpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndGVzdF9uYW1lc3BhY2VfZXhp'
    'c3RzJykKICAgIGlmIGNvbW1hbmQoWydpcCcsICctNCcsICdyb3V0ZScsICdzaG93JywgJ3RhYmxlJywgc3RyKFRBQkxFKV0s'
    'IGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3Rlc3RfdGFibGVfaW5f'
    'dXNlJykKICAgIGlmIGFueShORVRXT1JLIGluIGxpbmUgZm9yIGxpbmUgaW4gY29tbWFuZChbJ2lwJywgJy00JywgJ3JvdXRl'
    'JywgJ3Nob3cnLCAndGFibGUnLCAnYWxsJ10pLnN0ZG91dC5zcGxpdGxpbmVzKCkpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVF'
    'cnJvcigndGVzdF9uZXR3b3JrX2luX3VzZScpCiAgICBvbGRfZm9yd2FyZCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9p'
    'cF9mb3J3YXJkJykucmVhZF90ZXh0KCkuc3RyaXAoKQogICAgIyBSZWNvcmQgb3duZXJzaGlwIGJlZm9yZSBjcmVhdGluZyBh'
    'bnl0aGluZzogY2xlYW51cCBpcyB2YWxpZCBhZnRlciBldmVyeSBwYXJ0aWFsIHN0ZXAuCiAgICB1cGxpbmsgPSBQYXRoKCcv'
    'cHJvYy9zeXMvbmV0L2lwdjQvY29uZicpL3JvdXRlWydkZXYnXS8nZm9yd2FyZGluZycKICAgIHdyaXRlKFJPT1QvJ25ldHdv'
    'cmsuanNvbicsIGpzb24uZHVtcHMoeydmb3J3YXJkJzogb2xkX2ZvcndhcmQsICdpbnRlcmZhY2UnOiByb3V0ZVsnZGV2J10s'
    'ICd1cGxpbmtfZm9yd2FyZCc6IHVwbGluay5yZWFkX3RleHQoKS5zdHJpcCgpfSkpCiAgICBjb21tYW5kKFsnaXAnLCAnbmV0'
    'bnMnLCAnYWRkJywgTlNdKQogICAgd3JpdGUoUGF0aCgnL2V0Yy9uZXRucycpL05TLydyZXNvbHYuY29uZicsICduYW1lc2Vy'
    'dmVyIDEuMS4xLjFcbm5hbWVzZXJ2ZXIgOS45LjkuOVxub3B0aW9ucyB0aW1lb3V0OjIgYXR0ZW1wdHM6MlxuJykKICAgICMg'
    'bnNzLXJlc29sdmUgdGFsa3MgdG8gdGhlIGhvc3QgZGFlbW9uIG92ZXIgYSBVbml4IHNvY2tldCBldmVuIGluc2lkZSBuZXRu'
    'cy4KICAgIG5zcz1QYXRoKCcvZXRjL25zc3dpdGNoLmNvbmYnKS5yZWFkX3RleHQoKQogICAgbnNzPXJlLnN1YihyJ15ob3N0'
    'czouKiQnLCAnaG9zdHM6IGZpbGVzIGRucycsIG5zcywgZmxhZ3M9cmUuTSkKICAgIHdyaXRlKFBhdGgoJy9ldGMvbmV0bnMn'
    'KS9OUy8nbnNzd2l0Y2guY29uZicsIG5zcykKICAgIGNvbW1hbmQoWydpcCcsICdsaW5rJywgJ2FkZCcsIEhPU1QsICd0eXBl'
    'JywgJ3ZldGgnLCAncGVlcicsICduYW1lJywgUEVFUl0pCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdzZXQnLCBQRUVS'
    'LCAnbmV0bnMnLCBOU10pCiAgICBjb21tYW5kKFsnaXAnLCAnYWRkcicsICdhZGQnLCBHQVRFV0FZKycvMzAnLCAnZGV2Jywg'
    'SE9TVF0pCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdzZXQnLCBIT1NULCAndXAnXSkKICAgIGluc2lkZShbJ2lwJywg'
    'J2FkZHInLCAnYWRkJywgQ0xJRU5UKycvMzAnLCAnZGV2JywgUEVFUl0pCiAgICBpbnNpZGUoWydpcCcsICdsaW5rJywgJ3Nl'
    'dCcsIFBFRVIsICd1cCddKQogICAgaW5zaWRlKFsnaXAnLCAnbGluaycsICdzZXQnLCAnbG8nLCAndXAnXSkKICAgIGluc2lk'
    'ZShbJ2lwJywgJ3JvdXRlJywgJ2FkZCcsICdkZWZhdWx0JywgJ3ZpYScsIEdBVEVXQVldKQogICAgIyBBIHJlY29ubmVjdCBj'
    'cmVhdGVzIGEgTkVXIFRDUCBzb2NrZXQgYWZ0ZXIgSUtFIGluc3RhbGxzIGl0cyBkZWZhdWx0IHJvdXRlLgogICAgIyBLZWVw'
    'IHRoZSByZWxheSBzb2NrZXQgb24gdGhlIG5hbWVzcGFjZSB1cGxpbmsgd2l0aCB0aGUgcGh5c2ljYWwgdmV0aCBzb3VyY2U7'
    'CiAgICAjIG90aGVyd2lzZSBzb3VyY2Ugc2VsZWN0aW9uIGdpdmVzIGl0IHRoZSBWUE4gVklQIGFuZCB0dW5uZWxzIGl0IGlu'
    'dG8gaXRzZWxmLgogICAgaWYgQUNUSVZFLmdldCgndHJhbnNwb3J0X2FkZHJlc3MnKToKICAgICAgICBpbnNpZGUoWydpcCcs'
    'J3J1bGUnLCdhZGQnLCdwcmlvcml0eScsJzg5JywndG8nLEFDVElWRVsndHJhbnNwb3J0X2FkZHJlc3MnXSsnLzMyJywKICAg'
    'ICAgICAgICAgICAgICdpcHByb3RvJywndGNwJywnZHBvcnQnLHN0cihBQ1RJVkVbJ3RyYW5zcG9ydF9wb3J0J10pLCdsb29r'
    'dXAnLCdtYWluJ10pCiAgICBjb21tYW5kKFsnaXAnLCAncm91dGUnLCAnYWRkJywgJ3RhYmxlJywgc3RyKFRBQkxFKSwgJ2Rl'
    'ZmF1bHQnLCAndmlhJywgcm91dGVbJ2dhdGV3YXknXSwgJ2RldicsIHJvdXRlWydkZXYnXV0pCiAgICBmb3IgYWRkcmVzcyBp'
    'biBFTkRQT0lOVFM6CiAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1bGUnLCAnYWRkJywgJ3ByaW9yaXR5Jywgc3RyKFBSSU9S'
    'SVRZKSwgJ2Zyb20nLCBDTElFTlQrJy8zMicsCiAgICAgICAgICAgICAgICAgJ3RvJywgYWRkcmVzcysnLzMyJywgJ2xvb2t1'
    'cCcsIHN0cihUQUJMRSldKQogICAgcnVsZXMgPSBob3N0X3J1bGVzKHJvdXRlWydkZXYnXSwgcHJldmlvdXNfZm9yd2FyZD1v'
    'bGRfZm9yd2FyZCA9PSAnMScpCiAgICBjb21tYW5kKFsnbmZ0JywgJy1jJywgJy1mJywgJy0nXSwgZGF0YT1ydWxlcykKICAg'
    'IGNvbW1hbmQoWyduZnQnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgIyBQZXItaW50ZXJmYWNlIGZvcndhcmRpbmcg'
    'YXZvaWRzIGlwX2ZvcndhcmQncyBnbG9iYWwgZGVmYXVsdHMgcmVzZXQuCiAgICAoUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0'
    'L2NvbmYnKS9IT1NULydmb3J3YXJkaW5nJykud3JpdGVfdGV4dCgnMVxuJykKICAgIHVwbGluay53cml0ZV90ZXh0KCcxXG4n'
    'KQoKCmRlZiBjbGVhbnVwKCk6CiAgICBjbGVhbnVwX2Z1bGwoKQogICAgIyBBbiB1bm93bmVkIG5hbWVzcGFjZS90YWJsZSBt'
    'dXN0IG5ldmVyIGJlIGRlbGV0ZWQgYnkgYSBnZW5lcmljIGNsZWFudXAgY2FsbC4KICAgIGlmIG5vdCAoUk9PVC8nbmV0d29y'
    'ay5qc29uJykuZXhpc3RzKCk6CiAgICAgICAgcmV0dXJuCiAgICBkYXRhID0ganNvbi5sb2FkcygoUk9PVC8nbmV0d29yay5q'
    'c29uJykucmVhZF90ZXh0KCkpCiAgICBjb21tYW5kKFsnbmZ0JywgJ2RlbGV0ZScsICd0YWJsZScsICdpbmV0JywgTkZUXSwg'
    'Y2hlY2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiAoKkVORFBPSU5UUywgKkxFR0FDWV9FTkRQT0lOVFMpOgogICAgICAg'
    'IGNvbW1hbmQoWydpcCcsICdydWxlJywgJ2RlbCcsICdwcmlvcml0eScsIHN0cihQUklPUklUWSksICdmcm9tJywgQ0xJRU5U'
    'KycvMzInLAogICAgICAgICAgICAgICAgICd0bycsIGFkZHJlc3MrJy8zMicsICdsb29rdXAnLCBzdHIoVEFCTEUpXSwgY2hl'
    'Y2s9RmFsc2UpCiAgICBmb3IgYWRkcmVzcyBpbiBkYXRhLmdldCgnbWVhc3VyZW1lbnRfaXBzJywgW10pOgogICAgICAgIGlm'
    'IGlwYWRkcmVzcy5pcF9hZGRyZXNzKGFkZHJlc3MpLmlzX2dsb2JhbDoKICAgICAgICAgICAgY29tbWFuZChbJ2lwJywgJ3J1'
    'bGUnLCAnZGVsJywgJ3ByaW9yaXR5JywgJzExMScsICdmcm9tJywgQ0xJRU5UKycvMzInLCAndG8nLCBhZGRyZXNzKycvMzIn'
    'LCAnbG9va3VwJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ3JvdXRlJywgJ2ZsdXNo'
    'JywgJ3RhYmxlJywgc3RyKFRBQkxFKV0sIGNoZWNrPUZhbHNlKQogICAgY29tbWFuZChbJ2lwJywgJ25ldG5zJywgJ2RlbCcs'
    'IE5TXSwgY2hlY2s9RmFsc2UpCiAgICBjb21tYW5kKFsnaXAnLCAnbGluaycsICdkZWwnLCBIT1NUXSwgY2hlY2s9RmFsc2Up'
    'CiAgICBpZiAndXBsaW5rX2ZvcndhcmQnIGluIGRhdGE6CiAgICAgICAgcGF0aCA9IFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2'
    'NC9jb25mJykvZGF0YVsnaW50ZXJmYWNlJ10vJ2ZvcndhcmRpbmcnCiAgICAgICAgaWYgcGF0aC5leGlzdHMoKToKICAgICAg'
    'ICAgICAgcGF0aC53cml0ZV90ZXh0KGRhdGFbJ3VwbGlua19mb3J3YXJkJ10rJ1xuJykKICAgIGVsaWYgZGF0YS5nZXQoJ2Zv'
    'cndhcmQnKSA9PSAnMCcgYW5kIFBhdGgoJy9wcm9jL3N5cy9uZXQvaXB2NC9pcF9mb3J3YXJkJykucmVhZF90ZXh0KCkuc3Ry'
    'aXAoKSA9PSAnMSc6CiAgICAgICAgUGF0aCgnL3Byb2Mvc3lzL25ldC9pcHY0L2lwX2ZvcndhcmQnKS53cml0ZV90ZXh0KCcw'
    'XG4nKQogICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8ncmVzb2x2LmNvbmYnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQog'
    'ICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUy8nbnNzd2l0Y2guY29uZicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCiAgICB3'
    'aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoT1NFcnJvcik6CiAgICAgICAgKFBhdGgoJy9ldGMvbmV0bnMnKS9OUykucm1kaXIo'
    'KQogICAgKFJPT1QvJ25ldHdvcmsuanNvbicpLnVubGluayhtaXNzaW5nX29rPVRydWUpCgoKCgpkZWYgdGxzX3JlcXVlc3Qo'
    'YWRkcmVzcywgcGF0aCwgYm9keT1Ob25lLCBjbGllbnQ9RmFsc2UsIHRpbWVvdXQ9OCwgaWRlbnRpdHk9U0VSVkVSKToKICAg'
    'IGNvbnRleHQgPSBzc2wuY3JlYXRlX2RlZmF1bHRfY29udGV4dChjYWRhdGE9UElOTkVEX0NBKQogICAgaWYgY2xpZW50Ogog'
    'ICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQucGVtJyksIHN0cihST09ULydjbGllbnQt'
    'a2V5LnBlbScpKQogICAgc29jayA9IHNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigoYWRkcmVzcywgODQ0MyksIHRpbWVvdXQ9'
    'dGltZW91dCkKICAgIHRyeToKICAgICAgICB0bHMgPSBjb250ZXh0LndyYXBfc29ja2V0KHNvY2ssIHNlcnZlcl9ob3N0bmFt'
    'ZT1pZGVudGl0eSkKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgIHNvY2suY2xvc2UoKQogICAgICAgIHJhaXNl'
    'CiAgICBjb25uZWN0aW9uID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oYWRkcmVzcywgODQ0MywgdGltZW91dD10aW1l'
    'b3V0KQogICAgY29ubmVjdGlvbi5zb2NrID0gdGxzCiAgICBlbmNvZGVkID0ganNvbi5kdW1wcyhib2R5LCBzZXBhcmF0b3Jz'
    'PSgnLCcsICc6JykpLmVuY29kZSgpIGlmIGJvZHkgaXMgbm90IE5vbmUgZWxzZSBOb25lCiAgICB0cnk6CiAgICAgICAgY29u'
    'bmVjdGlvbi5yZXF1ZXN0KCdQT1NUJyBpZiBib2R5IGlzIG5vdCBOb25lIGVsc2UgJ0dFVCcsIHBhdGgsIGJvZHk9ZW5jb2Rl'
    'ZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgaGVhZGVycz17J0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29u'
    'JywgJ0Nvbm5lY3Rpb24nOiAnY2xvc2UnfSkKICAgICAgICByZXNwb25zZSA9IGNvbm5lY3Rpb24uZ2V0cmVzcG9uc2UoKQog'
    'ICAgICAgIHJhdyA9IHJlc3BvbnNlLnJlYWQoMjAwMDEpCiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMCBvciBs'
    'ZW4ocmF3KSA+IDIwMDAwOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ3JlcXVlc3RfcmVqZWN0ZWQnKQogICAg'
    'ICAgIHJldHVybiBqc29uLmxvYWRzKHJhdykKICAgIGZpbmFsbHk6CiAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpCgoKZGVm'
    'IGVucm9sbCgpOgogICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpCiAgICBpZiBub3QgcmUu'
    'ZnVsbG1hdGNoKFRPS0VOX1BBVFRFUk4sIHRva2VuKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfdG9r'
    'ZW4nKQogICAgdHJ5OgogICAgICAgIGNhY2hlZCA9IGpzb24ubG9hZHMoKFJPT1QvJ3Byb2ZpbGUuanNvbicpLnJlYWRfdGV4'
    'dCgpKQogICAgICAgIGlmIChjYWNoZWQuZ2V0KCdjYScpID09IFBJTk5FRF9DQSBhbmQgY2FjaGVkLmdldCgnc2VydmVyJykg'
    'PT0gU0VSVkVSIGFuZAogICAgICAgICAgICByZS5mdWxsbWF0Y2gocidkZXZpY2UtW2EtZjAtOV17MjR9JywgY2FjaGVkLmdl'
    'dCgnaWRlbnRpdHknLCAnJykpIGFuZAogICAgICAgICAgICBjYWNoZWQuZ2V0KCdlbmRwb2ludCcpIGluIEVORFBPSU5UUyBh'
    'bmQgY2FjaGVkLmdldCgncGh5c2ljYWxfbmV0d29yaycpIGFuZAogICAgICAgICAgICBjb21tYW5kKFsnb3BlbnNzbCcsICd4'
    'NTA5JywgJy1pbicsIFJPT1QvJ2NsaWVudC5wZW0nLCAnLWNoZWNrZW5kJywgc3RyKDcqODY0MDApLCAnLW5vb3V0J10sIGNo'
    'ZWNrPUZhbHNlKS5yZXR1cm5jb2RlID09IDApOgogICAgICAgICAgICBjb250ZXh0ID0gc3NsLlNTTENvbnRleHQoc3NsLlBS'
    'T1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQu'
    'cGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgICAgICAgICByb3V0ZSA9IHBoeXNpY2FsX3JvdXRlKCkK'
    'ICAgICAgICAgICAgY3VycmVudCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVtcHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9y'
    'IGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRfa2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGln'
    'ZXN0KCkKICAgICAgICAgICAgYWRkcmVzcyA9IGNhY2hlZFsnZW5kcG9pbnQnXSBpZiBjYWNoZWQuZ2V0KCdwaHlzaWNhbF9u'
    'ZXR3b3JrJykgPT0gY3VycmVudCBlbHNlIFNFUlZFUgogICAgICAgICAgICByZXR1cm4gY2FjaGVkWydpZGVudGl0eSddLCBh'
    'ZGRyZXNzCiAgICBleGNlcHQgKE9TRXJyb3IsIFZhbHVlRXJyb3IsIHNzbC5TU0xFcnJvcik6CiAgICAgICAgcGFzcwogICAg'
    'c3RhZ2UoJ3Rva2VuJywgJ9Cf0L7Qu9GD0YfQsNGOINGB0LXRgNGC0LjRhNC40LrQsNGCINC00LvRjyDRjdGC0L7Qs9C+INGD'
    '0YHRgtGA0L7QudGB0YLQstCwLicsIDI1KQogICAgaWYgbm90IChST09ULydjbGllbnQta2V5LnBlbScpLmV4aXN0cygpOgog'
    'ICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ2dlbnBrZXknLCAnLWFsZ29yaXRobScsICdSU0EnLCAnLXBrZXlvcHQnLCAn'
    'cnNhX2tleWdlbl9iaXRzOjMwNzInLAogICAgICAgICAgICAgICAgICctb3V0JywgUk9PVC8nY2xpZW50LWtleS5wZW0nXSwg'
    'dGltZW91dD0zMCkKICAgICAgICAoUk9PVC8nY2xpZW50LWtleS5wZW0nKS5jaG1vZCgwbzYwMCkKICAgIGlmIG5vdCAoUk9P'
    'VC8nZGV2aWNlJykuZXhpc3RzKCk6CiAgICAgICAgd3JpdGUoUk9PVC8nZGV2aWNlJywgc2VjcmV0cy50b2tlbl9oZXgoMTYp'
    'KQogICAgY29tbWFuZChbJ29wZW5zc2wnLCAncmVxJywgJy1uZXcnLCAnLWtleScsIFJPT1QvJ2NsaWVudC1rZXkucGVtJywg'
    'Jy1zdWJqJywgJy9DTj1ldmdlbml1bS1kZXZpY2UnLAogICAgICAgICAgICAgJy1vdXQnLCBST09ULydyZXF1ZXN0LnBlbSdd'
    'KQogICAgcGF5bG9hZCA9IHsndG9rZW4nOiB0b2tlbiwgJ2RldmljZSc6IChST09ULydkZXZpY2UnKS5yZWFkX3RleHQoKS5z'
    'dHJpcCgpLCAnY3NyJzogKFJPT1QvJ3JlcXVlc3QucGVtJykucmVhZF90ZXh0KCl9CiAgICBsYXN0ID0gTm9uZQogICAgZm9y'
    'IGFkZHJlc3MgaW4gKFNFUlZFUiwpOgogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAg'
    'ICAgICAgICAgIHJlcGx5ID0gdGxzX3JlcXVlc3QoYWRkcmVzcywgJy9lbnJvbGwnLCBwYXlsb2FkLCB0aW1lb3V0PTYpCiAg'
    'ICAgICAgICAgIHByb2ZpbGUgPSByZXBseS5nZXQoJ3Byb2ZpbGUnLCB7fSkKICAgICAgICAgICAgaWYgcmVwbHkuZ2V0KCdv'
    'aycpIGlzIG5vdCBUcnVlIG9yIHByb2ZpbGUuZ2V0KCdjYScpICE9IFBJTk5FRF9DQSBvciBwcm9maWxlLmdldCgnc2VydmVy'
    'JykgIT0gU0VSVkVSOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnZhbGlkX3Byb2ZpbGUnKQogICAg'
    'ICAgICAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHInZGV2aWNlLVthLWYwLTldezI0fScsIHByb2ZpbGUuZ2V0KCdpZGVudGl0'
    'eScsICcnKSk6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2ludmFsaWRfaWRlbnRpdHknKQogICAgICAg'
    'ICAgICB3cml0ZShST09ULydjbGllbnQucGVtJywgcHJvZmlsZVsnY2VydGlmaWNhdGUnXSkKICAgICAgICAgICAgd3JpdGUo'
    'Uk9PVC8nY2EucGVtJywgUElOTkVEX0NBKQogICAgICAgICAgICB3cml0ZShST09ULyd4NTA5Jy8nY2xpZW50LnBlbScsIHBy'
    'b2ZpbGVbJ2NlcnRpZmljYXRlJ10pCiAgICAgICAgICAgIHdyaXRlKFJPT1QvJ3g1MDljYScvJ2NhLnBlbScsIFBJTk5FRF9D'
    'QSkKICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJpdmF0ZScvJ2NsaWVudC1rZXkucGVtJywgKFJPT1QvJ2NsaWVudC1rZXku'
    'cGVtJykucmVhZF90ZXh0KCkpCiAgICAgICAgICAgIGNvbW1hbmQoWydvcGVuc3NsJywgJ3ZlcmlmeScsICctcHVycG9zZScs'
    'ICdzc2xjbGllbnQnLCAnLUNBZmlsZScsIFJPT1QvJ2NhLnBlbScsIFJPT1QvJ2NsaWVudC5wZW0nXSkKICAgICAgICAgICAg'
    'Y3R4ID0gc3NsLlNTTENvbnRleHQoc3NsLlBST1RPQ09MX1RMU19DTElFTlQpCiAgICAgICAgICAgIGN0eC5sb2FkX2NlcnRf'
    'Y2hhaW4oc3RyKFJPT1QvJ2NsaWVudC5wZW0nKSwgc3RyKFJPT1QvJ2NsaWVudC1rZXkucGVtJykpCiAgICAgICAgICAgIHJv'
    'dXRlID0gcGh5c2ljYWxfcm91dGUoKQogICAgICAgICAgICBmaW5nZXJwcmludCA9IGhhc2hsaWIuc2hhMjU2KGpzb24uZHVt'
    'cHMoe2tleTogcm91dGUuZ2V0KGtleSkgZm9yIGtleSBpbiAoJ2RldicsICdnYXRld2F5JywgJ3ByZWZzcmMnKX0sIHNvcnRf'
    'a2V5cz1UcnVlKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgICAgICAgICAgd3JpdGUoUk9PVC8ncHJvZmlsZS5qc29uJywg'
    'anNvbi5kdW1wcyh7Kipwcm9maWxlLCAnZW5kcG9pbnQnOiBhZGRyZXNzLCAncGh5c2ljYWxfbmV0d29yayc6IGZpbmdlcnBy'
    'aW50fSkpCiAgICAgICAgICAgIHJldHVybiBwcm9maWxlWydpZGVudGl0eSddLCBhZGRyZXNzCiAgICAgICAgZXhjZXB0IChP'
    'U0Vycm9yLCBzc2wuU1NMRXJyb3IsIFJ1bnRpbWVFcnJvcikgYXMgZXhjOgogICAgICAgICAgICBsYXN0ID0gZXhjCiAgICBy'
    'YWlzZSBSdW50aW1lRXJyb3IoJ2Vucm9sbG1lbnRfdW5hdmFpbGFibGUnKSBmcm9tIGxhc3QKCgpkZWYgZGFlbW9uX2NvbmZp'
    'Z3MoaWRlbnRpdHksIGFkZHJlc3MpOgogICAgUlVOVElNRS5ta2Rpcihtb2RlPTBvNzAwLCBwYXJlbnRzPVRydWUsIGV4aXN0'
    'X29rPVRydWUpCiAgICBpbmNsdWRlcyA9ICdcbicuam9pbignaW5jbHVkZSAnK3N0cihwKSBmb3IgcGF0dGVybiBpbiAoJy9l'
    'dGMvc3Ryb25nc3dhbi5kL2NoYXJvbi8qLmNvbmYnLCAnL2V0Yy9zdHJvbmdzd2FuL3N0cm9uZ3N3YW4uZC9jaGFyb24vKi5j'
    'b25mJykKICAgICAgICAgICAgICAgICAgICAgICAgIGZvciBwIGluIFBhdGgoJy8nKS5nbG9iKHBhdHRlcm4ubHN0cmlwKCcv'
    'JykpKQogICAgd3JpdGUoUk9PVC8nc3Ryb25nc3dhbi5jb25mJywgZicnJ2NoYXJvbiB7ewogbG9hZF9tb2R1bGFyID0geWVz'
    'CiBpbnN0YWxsX3JvdXRlcyA9IHllcwogcm91dGluZ190YWJsZSA9IDUxODIyCiByb3V0aW5nX3RhYmxlX3ByaW8gPSAxMDAK'
    'IHBsdWdpbnMge3sKe2luY2x1ZGVzfQogIHZpY2kge3sgc29ja2V0ID0gdW5peDovL3tSVU5USU1FfS9jaGFyb24udmljaSB9'
    'fQogIHJlc29sdmUge3sgbG9hZCA9IG5vIH19CiAga2VybmVsLWxpYmlwc2VjIHt7IGxvYWQgPSBubyB9fQogfX0KfX0KY2hh'
    'cm9uLXN5c3RlbWQge3sgam91cm5hbCB7eyBkZWZhdWx0ID0gMDsgaWtlID0gMSB9fSB9fQonJycpCiAgICAjIEFic29sdXRl'
    'IGNyZWRlbnRpYWxzIGFyZSBsb2NhbCB0byB0aGlzIGRldmljZSwgbm90IHNoYXJlZCBieSB0aGUgYWNjb3VudCB0b2tlbi4K'
    'ICAgIHdyaXRlKFJPT1QvJ2Nvbm5lY3Rpb24uY29uZicsIGYnJydjb25uZWN0aW9ucyB7ewogc3RhcmZpdmUge3sKICB2ZXJz'
    'aW9uID0gMgogIHJlbW90ZV9hZGRycyA9IHthZGRyZXNzfQogIHJlbW90ZV9wb3J0ID0ge0FDVElWRVsncG9ydCddfQogIGxv'
    'Y2FsX3BvcnQgPSA0NTAwCiAgdmlwcyA9IDAuMC4wLjAKICBwcm9wb3NhbHMgPSBhZXMyNTZnY20xNi1wcmZzaGEzODQtZWNw'
    'Mzg0CiAgZW5jYXAgPSB5ZXMKICBmcmFnbWVudGF0aW9uID0geWVzCiAgbW9iaWtlID0geWVzCiAgZHBkX2RlbGF5ID0gMTVz'
    'CiAgbG9jYWwge3sgYXV0aCA9IGVhcC10bHM7IGlkID0ge2lkZW50aXR5fTsgZWFwX2lkID0ge2lkZW50aXR5fTsgY2VydHMg'
    'PSB7Uk9PVH0vY2xpZW50LnBlbSB9fQogIHJlbW90ZSB7eyBhdXRoID0gcHVia2V5OyBpZCA9IHtBQ1RJVkVbJ2lkZW50aXR5'
    'J119OyBjYWNlcnRzID0ge1JPT1R9L2NhLnBlbSB9fQogIGNoaWxkcmVuIHt7CiAgIHN0YXJmaXZlLW5ldCB7ewogICAgbG9j'
    'YWxfdHMgPSBkeW5hbWljCiAgICByZW1vdGVfdHMgPSAwLjAuMC4wLzAKICAgIHJlcWlkID0ge1JFUUlEfQogICAgZXNwX3By'
    'b3Bvc2FscyA9IGNoYWNoYTIwcG9seTEzMDUKICAgIGRwZF9hY3Rpb24gPSBjbGVhcgogICAgc3RhcnRfYWN0aW9uID0gbm9u'
    'ZQogICB9fQogIH19CiB9fQp9fQpzZWNyZXRzIHt7IHByaXZhdGUtY2xpZW50IHt7IGZpbGUgPSB7Uk9PVH0vY2xpZW50LWtl'
    'eS5wZW0gfX0gfX0KJycnKQogICAgIyBTdHJvbmdTd2FuIGNvbmZpZyB1c2VzIG5ld2xpbmVzLCBub3Qgc2VtaWNvbG9uIHNl'
    'cGFyYXRvcnMgKG5vcm1hbGl6ZSBjb21wYWN0IGJsb2NrcykuCiAgICBmb3IgbmFtZSBpbiAoJ3N0cm9uZ3N3YW4uY29uZics'
    'ICdjb25uZWN0aW9uLmNvbmYnKToKICAgICAgICBwYXRoID0gUk9PVC9uYW1lCiAgICAgICAgcGF0aC53cml0ZV90ZXh0KHBh'
    'dGgucmVhZF90ZXh0KCkucmVwbGFjZSgnOyAnLCAnXG4nKS5yZXBsYWNlKCd7ICcsICd7XG4nKS5yZXBsYWNlKCcgfScsICdc'
    'bn0nKSkKICAgIHJ1bGVzID0gZicnJ3RhYmxlIGluZXQgZXZuX3N0YXJmaXZlX2d1YXJkIHt7CiBjaGFpbiBvdXRwdXQge3sK'
    'ICB0eXBlIGZpbHRlciBob29rIG91dHB1dCBwcmlvcml0eSAtMTA7IHBvbGljeSBkcm9wOwogIG9pZm5hbWUgImxvIiBhY2Nl'
    'cHQKICBpcCBkYWRkciAxMjcuMC4wLjEgdWRwIGRwb3J0IDI0NTczIGFjY2VwdAogIG9pZm5hbWUgIntGVUxMX1BFRVJ9IiBp'
    'cCBkYWRkciAxNzIuMjkuMjQ3LjEgbWV0YSBsNHByb3RvIHt7IHRjcCwgdWRwIH19IHRoIHNwb3J0IDUzIGFjY2VwdAogIGlw'
    'IGRhZGRyIHthZGRyZXNzfSB1ZHAgZHBvcnQge0FDVElWRVsncG9ydCddfSBhY2NlcHQKICBpcCBkYWRkciAzOC4xODAuMTY0'
    'LjY3IHRjcCBkcG9ydCB7eyAyNDU3MSwgMjQ1NzggfX0gYWNjZXB0CiAgaXAgZGFkZHIgMTk1LjIwOS4yMTEuMTYzIHRjcCBk'
    'cG9ydCAyNDU3OSBhY2NlcHQKICBtZXRhIHNrdWlkIDAgaXAgZGFkZHIge2FkZHJlc3N9IHRjcCBkcG9ydCA4NDQzIGFjY2Vw'
    'dAogIG1ldGEgbmZwcm90byBpcHY0IGlwc2VjIG91dCByZXFpZCB7UkVRSUR9IGFjY2VwdAogfX0KIGNoYWluIGZvcndhcmQg'
    'e3sgdHlwZSBmaWx0ZXIgaG9vayBmb3J3YXJkIHByaW9yaXR5IC0xMDsgcG9saWN5IGRyb3A7IH19Cn19JycnCiAgICBpbnNp'
    'ZGUoWyduZnQnLCAnLWMnLCAnLWYnLCAnLSddLCBkYXRhPXJ1bGVzKQogICAgaW5zaWRlKFsnbmZ0JywgJy1mJywgJy0nXSwg'
    'ZGF0YT1ydWxlcykKCgpkZWYgc3dhbigqYXJncywgdGltZW91dD0xNSwgY2hlY2s9VHJ1ZSk6CiAgICByZXR1cm4gaW5zaWRl'
    'KFsnc3dhbmN0bCcsICphcmdzLCAnLS11cmknLCAndW5peDovLycrc3RyKFJVTlRJTUUvJ2NoYXJvbi52aWNpJyldLCB0aW1l'
    'b3V0PXRpbWVvdXQsIGNoZWNrPWNoZWNrKQoKCmRlZiBpbnN0YWxsZWQoKToKICAgIHRyeToKICAgICAgICByZXN1bHQgPSBz'
    'd2FuKCctLWxpc3Qtc2FzJywgJy0tcmF3JywgdGltZW91dD0zLCBjaGVjaz1GYWxzZSkKICAgICAgICByZXR1cm4gcmVzdWx0'
    'LnJldHVybmNvZGUgPT0gMCBhbmQgJ3N0YXRlPUVTVEFCTElTSEVEJyBpbiByZXN1bHQuc3Rkb3V0IGFuZCAnc3RhdGU9SU5T'
    'VEFMTEVEJyBpbiByZXN1bHQuc3Rkb3V0CiAgICBleGNlcHQgKE9TRXJyb3IsIHN1YnByb2Nlc3MuVGltZW91dEV4cGlyZWQp'
    'OgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBoZWFsdGgoKToKICAgIHdpdGggbmFtZXNwYWNlKCk6CiAgICAgICAgcmV0'
    'dXJuIHRsc19yZXF1ZXN0KEhFQUxUSCwgJy9oZWFsdGgnLCBjbGllbnQ9VHJ1ZSwgaWRlbnRpdHk9QUNUSVZFWydpZGVudGl0'
    'eSddLCB0aW1lb3V0PTMpLmdldCgnc2VydmljZScpID09ICdldmdlbml1bS1zdGFyZml2ZScKCgpkZWYgZG93bmxvYWQoc2l6'
    'ZT0xMDQ4NTc2KToKICAgICMgQSBib3VuZGVkIGludGVncml0eSBjaGVjaywgbm90IGEgY2xhaW0gdG8gaGF2ZSBtZWFzdXJl'
    'ZCB0aGUgSVNQJ3MgbWF4aW11bSByYXRlLgogICAgYmxvY2sgPSBoYXNobGliLnNoYWtlXzI1NihiJ2V2Z2VuaXVtLXN0YXJm'
    'aXZlLWludGVncml0eS12MScpLmRpZ2VzdCg2NTUzNikKICAgIGV4cGVjdGVkID0gaGFzaGxpYi5zaGEyNTYoKGJsb2NrKihz'
    'aXplLy9sZW4oYmxvY2spKzEpKVs6c2l6ZV0pLmhleGRpZ2VzdCgpCiAgICBjb250ZXh0ID0gc3NsLmNyZWF0ZV9kZWZhdWx0'
    'X2NvbnRleHQoY2FkYXRhPVBJTk5FRF9DQSkKICAgIGNvbnRleHQubG9hZF9jZXJ0X2NoYWluKHN0cihST09ULydjbGllbnQu'
    'cGVtJyksIHN0cihST09ULydjbGllbnQta2V5LnBlbScpKQogICAgd2l0aCBuYW1lc3BhY2UoKToKICAgICAgICBzb2NrID0g'
    'c29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChIRUFMVEgsIDg0NDMpLCB0aW1lb3V0PTEwKQogICAgICAgIHRscyA9IGNvbnRl'
    'eHQud3JhcF9zb2NrZXQoc29jaywgc2VydmVyX2hvc3RuYW1lPUFDVElWRVsnaWRlbnRpdHknXSkKICAgICAgICBjb25uZWN0'
    'aW9uID0gaHR0cC5jbGllbnQuSFRUUENvbm5lY3Rpb24oSEVBTFRILCA4NDQzLCB0aW1lb3V0PTEwKTsgY29ubmVjdGlvbi5z'
    'b2NrID0gdGxzCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdGFydCA9IHRpbWUubW9ub3RvbmljKCkKICAgICAgICAgICAg'
    'Y29ubmVjdGlvbi5yZXF1ZXN0KCdHRVQnLCAnL2Jsb2I/c2l6ZT0nK3N0cihzaXplKSkKICAgICAgICAgICAgcmVzcG9uc2Ug'
    'PSBjb25uZWN0aW9uLmdldHJlc3BvbnNlKCkKICAgICAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzICE9IDIwMDoKICAgICAg'
    'ICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigndHJhbnNmZXJfaHR0cCcpCiAgICAgICAgICAgIGRpZ2VzdCA9IGhhc2hs'
    'aWIuc2hhMjU2KCk7IHJlY2VpdmVkID0gMAogICAgICAgICAgICB3aGlsZSByZWNlaXZlZCA8IHNpemU6CiAgICAgICAgICAg'
    'ICAgICBkYXRhID0gcmVzcG9uc2UucmVhZChtaW4oNjU1MzYsIHNpemUtcmVjZWl2ZWQpKQogICAgICAgICAgICAgICAgaWYg'
    'bm90IGRhdGE6CiAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIGRpZ2VzdC51cGRhdGUoZGF0YSk7'
    'IHJlY2VpdmVkICs9IGxlbihkYXRhKQogICAgICAgICAgICBlbGFwc2VkID0gdGltZS5tb25vdG9uaWMoKS1zdGFydAogICAg'
    'ICAgIGZpbmFsbHk6CiAgICAgICAgICAgIGNvbm5lY3Rpb24uY2xvc2UoKQogICAgaWYgcmVjZWl2ZWQgIT0gc2l6ZSBvciBk'
    'aWdlc3QuaGV4ZGlnZXN0KCkgIT0gZXhwZWN0ZWQ6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdpbnRlZ3JpdHlfZmFp'
    'bGVkJykKICAgIHJldHVybiB7J2J5dGVzJzogcmVjZWl2ZWQsICdkb3dubG9hZF9tYnBzJzogcm91bmQocmVjZWl2ZWQqOC9l'
    'bGFwc2VkLzFlNiwgMiksCiAgICAgICAgICAgICdlbGFwc2VkX21zJzogcm91bmQoZWxhcHNlZCoxMDAwKSwgJ2ludGVncml0'
    'eSc6IFRydWUsICdsaW1pdGVkX3NhbXBsZSc6IFRydWV9CgoKZGVmIGRldmljZV9zdGF0dXMoKToKICAgIHRyeToKICAgICAg'
    'ICBpbmZvPWpzb24ubG9hZHMoKFJPT1QvJ2RldmljZS1pbmZvLmpzb24nKS5yZWFkX3RleHQoKSkKICAgICAgICByZXR1cm4g'
    'eydkZXZpY2VfbmFtZSc6aW5mby5nZXQoJ25hbWUnLCcnKSwnZGV2aWNlX251bWJlcic6aW5mby5nZXQoJ251bWJlcicpLAog'
    'ICAgICAgICAgICAgICAgJ2RldmljZV9uYW1lX3BlbmRpbmcnOmJvb2woaW5mby5nZXQoJ3BlbmRpbmcnKSBvciBpbmZvLmdl'
    'dCgnc3luY19lcnJvcicpKX0KICAgIGV4Y2VwdCAoT1NFcnJvcixWYWx1ZUVycm9yKTpyZXR1cm4geydkZXZpY2VfbmFtZSc6'
    'JycsJ2RldmljZV9udW1iZXInOk5vbmUsJ2RldmljZV9uYW1lX3BlbmRpbmcnOkZhbHNlfQoKCmRlZiBzeW5jX2RldmljZV9u'
    'YW1lKG5hbWU9Tm9uZSk6CiAgICBpbXBvcnQgdW5pY29kZWRhdGEKICAgIGlmIG5vdCB0b2tlbl9zdGF0dXMoKVsnaGFzX3Rv'
    'a2VuJ106cmFpc2UgVmFsdWVFcnJvcign0KHQvdCw0YfQsNC70LAg0L/QvtC00YLQstC10YDQtNC40YLQtSDRgtC+0LrQtdC9'
    'INC60LvQuNC10L3RgtCwLicpCiAgICBpZiBuYW1lIGlzIG5vdCBOb25lOgogICAgICAgIG5hbWU9dW5pY29kZWRhdGEubm9y'
    'bWFsaXplKCdORkMnLHN0cihuYW1lKSkuc3RyaXAoKQogICAgICAgIGlmIG5vdCAxPD1sZW4obmFtZSk8PTY0IG9yIGFueSh1'
    'bmljb2RlZGF0YS5jYXRlZ29yeShjKS5zdGFydHN3aXRoKCdDJykgZm9yIGMgaW4gbmFtZSk6CiAgICAgICAgICAgIHJhaXNl'
    'IFZhbHVlRXJyb3IoJ9CY0LzRjyDQtNC+0LvQttC90L4g0YHQvtC00LXRgNC20LDRgtGMINC+0YIgMSDQtNC+IDY0INC+0LHR'
    'i9GH0L3Ri9GFINGB0LjQvNCy0L7Qu9C+0LIuJykKICAgIGlmIG5vdCAoUk9PVC8nZGV2aWNlJykuZXhpc3RzKCk6d3JpdGUo'
    'Uk9PVC8nZGV2aWNlJyxzZWNyZXRzLnRva2VuX2hleCgxNikpCiAgICB0cnk6aW5mbz1qc29uLmxvYWRzKChST09ULydkZXZp'
    'Y2UtaW5mby5qc29uJykucmVhZF90ZXh0KCkpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcik6aW5mbz17fQogICAg'
    'aWYgbmFtZSBpcyBub3QgTm9uZTppbmZvLnVwZGF0ZShuYW1lPW5hbWUscGVuZGluZz1UcnVlKQogICAgcGF5bG9hZD17J3Rv'
    'a2VuJzooUk9PVC8ndG9rZW4nKS5yZWFkX3RleHQoKS5zdHJpcCgpLCdkZXZpY2UnOihST09ULydkZXZpY2UnKS5yZWFkX3Rl'
    'eHQoKS5zdHJpcCgpfQogICAgaWYgaW5mby5nZXQoJ3BlbmRpbmcnKTpwYXlsb2FkWyduYW1lJ109aW5mb1snbmFtZSddCiAg'
    'ICB0cnk6CiAgICAgICAgd2l0aCBuYW1lc3BhY2UoKSBpZiBQYXRoKCcvcnVuL25ldG5zLycrTlMpLmV4aXN0cygpIGVsc2Ug'
    'Y29udGV4dGxpYi5udWxsY29udGV4dCgpOgogICAgICAgICAgICByZXBseT10bHNfcmVxdWVzdChTRVJWRVIsJy9kZXZpY2Un'
    'LHBheWxvYWQsdGltZW91dD01KQogICAgICAgIHZhbHVlPXJlcGx5WydkZXZpY2UnXTtudW1iZXI9aW50KHZhbHVlWydudW1i'
    'ZXInXSkKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZSh2YWx1ZVsnbmFtZSddLHN0cikgb3Igbm90IDE8PWxlbih2YWx1ZVsn'
    'bmFtZSddKTw9NjQgb3IgbnVtYmVyPDE6cmFpc2UgVmFsdWVFcnJvcignaW52YWxpZF9kZXZpY2VfbWV0YWRhdGEnKQogICAg'
    'ICAgIGluZm89eyduYW1lJzp2YWx1ZVsnbmFtZSddLCdudW1iZXInOm51bWJlciwncGVuZGluZyc6RmFsc2UsJ3N5bmNfZXJy'
    'b3InOkZhbHNlfQogICAgZXhjZXB0IChPU0Vycm9yLFJ1bnRpbWVFcnJvcixWYWx1ZUVycm9yLEtleUVycm9yLGh0dHAuY2xp'
    'ZW50LkhUVFBFeGNlcHRpb24pOgogICAgICAgIGluZm9bJ3N5bmNfZXJyb3InXT1UcnVlCiAgICB3cml0ZShST09ULydkZXZp'
    'Y2UtaW5mby5qc29uJyxqc29uLmR1bXBzKGluZm8sZW5zdXJlX2FzY2lpPUZhbHNlKSkKICAgIHJldHVybiBkZXZpY2Vfc3Rh'
    'dHVzKCkKCgpkZWYgdG9rZW5fc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAgdG9rZW4gPSAoUk9PVC8ndG9rZW4nKS5yZWFk'
    'X3RleHQoKS5zdHJpcCgpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgdG9rZW4gPSAnJwogICAgdmFs'
    'aWQgPSByZS5mdWxsbWF0Y2goVE9LRU5fUEFUVEVSTiwgdG9rZW4pIGlzIG5vdCBOb25lCiAgICByZXR1cm4geydoYXNfdG9r'
    'ZW4nOiB2YWxpZCwKICAgICAgICAgICAgJ3Rva2VuX2hpbnQnOiAnRVZOMS3igKLigKLigKLigKIgwrcgSUQgJyArIGhhc2hs'
    'aWIuc2hhMjU2KHRva2VuLmVuY29kZSgpKS5oZXhkaWdlc3QoKVs6OF0gaWYgdmFsaWQgZWxzZSAnJ30KCgpkZWYgc2F2ZV90'
    'b2tlbih0b2tlbik6CiAgICB0b2tlbiA9IHRva2VuLnN0cmlwKCkKICAgIGlmIG5vdCByZS5mdWxsbWF0Y2goVE9LRU5fUEFU'
    'VEVSTiwgdG9rZW4pOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9Cd0YPQttC10L0g0YLQvtC60LXQvSDQutC70LjQtdC9'
    '0YLQsCDRhNC+0YDQvNCw0YLQsCBFVk4xLeKApicpCiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwg'
    'ZXhpc3Rfb2s9VHJ1ZSkKICAgIG9sZCA9IChST09ULyd0b2tlbicpLnJlYWRfdGV4dCgpLnN0cmlwKCkgaWYgKFJPT1QvJ3Rv'
    'a2VuJykuZXhpc3RzKCkgZWxzZSAnJwogICAgaWYgb2xkID09IHRva2VuOgogICAgICAgIHN5bmNfZGV2aWNlX25hbWUoKTty'
    'ZXR1cm4KICAgIGlmIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnaXMtYWN0aXZlJywgJy0tcXVpZXQnLCBVTklUXSwgY2hlY2s9'
    'RmFsc2UpLnJldHVybmNvZGUgPT0gMDoKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ9Ch0L3QsNGH0LDQu9CwINC+0YLQ'
    'utC70Y7Rh9C40YLQtSBWUE4t0YLRg9C90L3QtdC70Ywg0L/QtdGA0LXQtCDRgdC80LXQvdC+0Lkg0YLQvtC60LXQvdCwLicp'
    'CiAgICAjIEEgZGlmZmVyZW50IGFjY291bnQgbmVlZHMgaXRzIG93biBkZXZpY2UgY3JlZGVudGlhbHMuIE5ldmVyIHJldXNl'
    'IGl0cyBjZXJ0aWZpY2F0ZS4KICAgIGZvciBuYW1lIGluICgnZGV2aWNlLWluZm8uanNvbicsICdkZXZpY2UnLCAnY2xpZW50'
    'LWtleS5wZW0nLCAnY2xpZW50LnBlbScsICdwcm9maWxlLmpzb24nLCAncmVxdWVzdC5wZW0nLAogICAgICAgICAgICAgICAg'
    'ICdwcml2YXRlL2NsaWVudC1rZXkucGVtJywgJ3g1MDkvY2xpZW50LnBlbScsICdyYW5raW5nLmpzb24nLCAncmVjYWxpYnJh'
    'dGUnLCAnZXZlbnRzLmpzb24nLCAnc3VwcG9ydC1wcmV2aWV3Lmpzb24nKToKICAgICAgICAoUk9PVC9uYW1lKS51bmxpbmso'
    'bWlzc2luZ19vaz1UcnVlKQogICAgd3JpdGUoUk9PVC8ndG9rZW4nLCB0b2tlbikKICAgIHN5bmNfZGV2aWNlX25hbWUoKQog'
    'ICAgc3RhZ2UoJ29mZicsICfQotC+0LrQtdC9INGB0L7RhdGA0LDQvdGR0L0uINCd0LDQttC80LjRgtC1IMKr0J/QvtC00LrQ'
    'u9GO0YfQuNGC0YzCuy4nLCAwLCBhY3RpdmU9RmFsc2UsIG1ldHJpY3M9e30pCgoKZGVmIGNvbm5lY3QodG9rZW49JycsIHJl'
    'cGFpcj1GYWxzZSwgcmVzdGFydD1GYWxzZSk6CiAgICBST09ULm1rZGlyKG1vZGU9MG83MDAsIHBhcmVudHM9VHJ1ZSwgZXhp'
    'c3Rfb2s9VHJ1ZSkKICAgIGlmIHRva2VuOgogICAgICAgIHNhdmVfdG9rZW4odG9rZW4pCiAgICBpZiBub3QgdG9rZW5fc3Rh'
    'dHVzKClbJ2hhc190b2tlbiddOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ9CS0LLQtdC00LjRgtC1INC4INC/0L7QtNGC'
    '0LLQtdGA0LTQuNGC0LUg0YLQvtC60LXQvSDQutC70LjQtdC90YLQsC4nKQogICAgZW5zdXJlX2RlcGVuZGVuY2llcygpCiAg'
    'ICBpZiByZXBhaXI6CiAgICAgICAgd3JpdGUoUk9PVC8ncmVjYWxpYnJhdGUnLCAnMScpCiAgICB1bml0ID0gZicnJ1tVbml0'
    'XQpEZXNjcmlwdGlvbj1Fdmdlbml1bSBmdWxsLWRldmljZSBFc3RvbmlhIFZQTgpBZnRlcj1uZXR3b3JrLnRhcmdldApTdGFy'
    'dExpbWl0SW50ZXJ2YWxTZWM9MTgwClN0YXJ0TGltaXRCdXJzdD0zCltTZXJ2aWNlXQpUeXBlPXNpbXBsZQpFeGVjU3RhcnQ9'
    'L3Vzci9sb2NhbC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwKRXhlY1N0b3BQb3N0PS91c3IvbG9jYWwv'
    'c2Jpbi92cG5jdGwgaW50ZXJuYWwtc3RhcmZpdmUtdHVubmVsLWNsZWFudXAKVGltZW91dFN0b3BTZWM9MjAKS2lsbE1vZGU9'
    'bWl4ZWQKVU1hc2s9MDA3NwpNZW1vcnlNYXg9MjU2TQpSZXN0YXJ0PW9uLWZhaWx1cmUKUmVzdGFydFNlYz0zCicnJwogICAg'
    'd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL1VOSVQsIHVuaXQpCiAgICByZWNvdmVyeSA9ICJldmdlbml1bS1z'
    'dGFyZml2ZS10dW5uZWwtcmVjb3Zlci5zZXJ2aWNlIgogICAgd3JpdGUoUGF0aCgnL2V0Yy9zeXN0ZW1kL3N5c3RlbScpL3Jl'
    'Y292ZXJ5LCAiIiJbVW5pdF0KRGVzY3JpcHRpb249UmVjb3ZlciBvbmx5IGludGVycnVwdGVkIEV2Z2VuaXVtIHR1bm5lbCB0'
    'ZXN0IHJlc291cmNlcwpEZWZhdWx0RGVwZW5kZW5jaWVzPW5vCkFmdGVyPWxvY2FsLWZzLnRhcmdldApCZWZvcmU9bmV0d29y'
    'ay1wcmUudGFyZ2V0IHZwbi14cmF5LnNlcnZpY2UKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9sb2Nh'
    'bC9zYmluL3ZwbmN0bCBpbnRlcm5hbC1zdGFyZml2ZS10dW5uZWwtY2xlYW51cApbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGkt'
    'dXNlci50YXJnZXQKIiIiKQogICAgY29tbWFuZChbJ3N5c3RlbWN0bCcsICdkYWVtb24tcmVsb2FkJ10pCiAgICBjb21tYW5k'
    'KFsnc3lzdGVtY3RsJywgJ2VuYWJsZScsIHJlY292ZXJ5XSkKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCdyZXNldC1mYWls'
    'ZWQnLFVOSVRdLGNoZWNrPUZhbHNlKQogICAgc3RhZ2UoJ3N0YXJ0aW5nJyAsICfQk9C+0YLQvtCy0LvRjiDQv9C+0LTQutC7'
    '0Y7Rh9C10L3QuNC1INCyINCt0YHRgtC+0L3QuNGOLicsIDIsIGFjdGl2ZT1GYWxzZSwgcmV0cnk9MCwgZXJyb3JfY29kZT0n'
    'JykKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAncmVzdGFydCcgaWYgcmVwYWlyIG9yIHJlc3RhcnQgZWxzZSAnc3RhcnQn'
    'LCBVTklUXSkKICAgIHByaW50KCdWUE4g0LfQsNC/0YPRgdC60LDQtdGC0YHRjy4nLGZsdXNoPVRydWUpCgoKZGVmIGRpc2Nv'
    'bm5lY3QoKToKICAgIGNvbW1hbmQoWydzeXN0ZW1jdGwnLCAnc3RvcCcsIFVOSVRdLCBjaGVjaz1GYWxzZSwgdGltZW91dD0y'
    'NSkKICAgIGNsZWFudXAoKQogICAgY2xlYW51cF9mdWxsKHJlbGVhc2U9VHJ1ZSkKICAgIHN0YWdlKCdvZmYnLCAnVlBOINCy'
    '0YvQutC70Y7Rh9C10L0uJywgMCwgYWN0aXZlPUZhbHNlKQogICAgcHJpbnQoJ1ZQTiDQstGL0LrQu9GO0YfQtdC9LicpCgoK'
    'ZGVmIHN0YXJ0X2RhZW1vbihlbnYpOgogICAgKFJVTlRJTUUvJ2NoYXJvbi52aWNpJykudW5saW5rKG1pc3Npbmdfb2s9VHJ1'
    'ZSkKICAgIGxvZyA9IChST09ULydjaGFyb24ubG9nJykub3BlbigndycpCiAgICBkYWVtb24gPSBzdWJwcm9jZXNzLlBvcGVu'
    'KFsnaXAnLCAnbmV0bnMnLCAnZXhlYycsIE5TLCBjaGFyb25fYmluYXJ5KCldLAogICAgICAgICAgICAgICAgICAgICAgICAg'
    'ICAgICBlbnY9ZW52LCBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsIHN0ZG91dD1sb2csIHN0ZGVycj1sb2cpCiAgICBsb2cu'
    'Y2xvc2UoKQogICAgdHJ5OgogICAgICAgIGZvciBfIGluIHJhbmdlKDYwKToKICAgICAgICAgICAgaWYgU1RPUCBvciBkYWVt'
    'b24ucG9sbCgpIGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdkYWVtb25fc3RvcHBl'
    'ZCcpCiAgICAgICAgICAgIGlmIChSVU5USU1FLydjaGFyb24udmljaScpLmV4aXN0cygpIGFuZCBzd2FuKCctLXN0YXRzJywg'
    'Y2hlY2s9RmFsc2UsIHRpbWVvdXQ9MSkucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAg'
    'ICAgdGltZS5zbGVlcCguMSkKICAgICAgICBzd2FuKCctLWxvYWQtY3JlZHMnLCAnLS1ub3Byb21wdCcsICctLWZpbGUnLCBS'
    'T09ULydjb25uZWN0aW9uLmNvbmYnKQogICAgICAgIHN3YW4oJy0tbG9hZC1jb25ucycsICctLWZpbGUnLCBST09ULydjb25u'
    'ZWN0aW9uLmNvbmYnKQogICAgICAgIHJldHVybiBkYWVtb24KICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgIHN0'
    'b3BfcHJvY2VzcyhkYWVtb24pCiAgICAgICAgcmFpc2UKCgpkZWYgc3RvcF9wcm9jZXNzKHByb2Nlc3MpOgogICAgaWYgcHJv'
    'Y2VzcyBpcyBub3QgTm9uZSBhbmQgcHJvY2Vzcy5wb2xsKCkgaXMgTm9uZToKICAgICAgICBwcm9jZXNzLnRlcm1pbmF0ZSgp'
    'CiAgICAgICAgdHJ5OnByb2Nlc3Mud2FpdCh0aW1lb3V0PTUpCiAgICAgICAgZXhjZXB0IHN1YnByb2Nlc3MuVGltZW91dEV4'
    'cGlyZWQ6cHJvY2Vzcy5raWxsKCk7cHJvY2Vzcy53YWl0KHRpbWVvdXQ9MykKCgpkZWYgc3RvcF9jYW5kaWRhdGUoZGFlbW9u'
    'PU5vbmUpOgogICAgZ2xvYmFsIFRMU19QUk9DRVNTCiAgICBzdG9wX3Byb2Nlc3MoZGFlbW9uKQogICAgc3RvcF9wcm9jZXNz'
    'KFRMU19QUk9DRVNTKTtUTFNfUFJPQ0VTUz1Ob25lCiAgICBjbGVhbnVwKCkKCgpkZWYgcHJlcGFyZV9kYXRhX3BsYW5lKGFk'
    'ZHJlc3MpOgogICAgaWYgbm90IGZ1bGxfc3RhdGUoKS5leGlzdHMoKToKICAgICAgICBpZiBQYXRoKCcvc3lzL2NsYXNzL25l'
    'dC8nK0ZVTExfSE9TVCkuZXhpc3RzKCk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignZnVsbF9pbnRlcmZhY2Vf'
    'Y29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsRlVMTF9UQUJMRV0s'
    'Y2hlY2s9RmFsc2UpLnN0ZG91dC5zdHJpcCgpOgogICAgICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ2Z1bGxfdGFibGVf'
    'Y29sbGlzaW9uJykKICAgICAgICBpZiBjb21tYW5kKFsnaXAnLCdyb3V0ZScsJ3Nob3cnLCd0YWJsZScsQURNSU5fVEFCTEVd'
    'LGNoZWNrPUZhbHNlKS5zdGRvdXQuc3RyaXAoKToKICAgICAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdhZG1pbl90YWJs'
    'ZV9jb2xsaXNpb24nKQogICAgICAgIGlmIGFueShyLmdldCgncHJpb3JpdHknKSBpbiAoNzksODApIGZvciByIGluIGpzb24u'
    'bG9hZHMoY29tbWFuZChbJ2lwJywnLWonLCctNCcsJ3J1bGUnXSkuc3Rkb3V0KSk6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRp'
    'bWVFcnJvcignZnVsbF9ydWxlX2NvbGxpc2lvbicpCiAgICAgICAgd3JpdGUoZnVsbF9zdGF0ZSgpLGpzb24uZHVtcHMoeydh'
    'Y3RpdmUnOkZhbHNlLCdtZWFzdXJlbWVudF9vbmx5JzpUcnVlfSkpCiAgICBmdWxsX25hbWVzcGFjZShhZGRyZXNzKQogICAg'
    'c3RhcnRfbmFtZXNwYWNlX2RucygpCgoKZGVmIHN0YXJ0X2NhbmRpZGF0ZShjYW5kaWRhdGUsaWRlbnRpdHkpOgogICAgZ2xv'
    'YmFsIEFDVElWRSxUTFNfUFJPQ0VTUwogICAgQUNUSVZFPWNhbmRpZGF0ZQogICAgd3JpdGUoUk9PVC8nYWN0aXZlLXBhdGgu'
    'anNvbicsanNvbi5kdW1wcyh7J2lkJzpjYW5kaWRhdGVbJ2lkJ119KSkKICAgIHNldHVwX25ldHdvcmsoKQogICAgZGFlbW9u'
    'X2NvbmZpZ3MoaWRlbnRpdHksY2FuZGlkYXRlWydhZGRyZXNzJ10pCiAgICBpZiBjYW5kaWRhdGVbJ3RscyddIG9yIGNhbmRp'
    'ZGF0ZS5nZXQoJ2V2Z3QnKToKICAgICAgICBpZiBjYW5kaWRhdGUuZ2V0KCdldmd0Jyk6CiAgICAgICAgICAgIGJpbmFyeT1l'
    'bnN1cmVfZXZndF9iaW5hcnkoKQogICAgICAgICAgICBjYXJyaWVyPVtzdHIoYmluYXJ5KSwnLW1vZGUnLCdjbGllbnQnLCct'
    'c2VydmVyJyxjYW5kaWRhdGUuZ2V0KCd0cmFuc3BvcnRfYWRkcmVzcycsY2FuZGlkYXRlWydhZGRyZXNzJ10pKyc6JytzdHIo'
    'Y2FuZGlkYXRlLmdldCgndHJhbnNwb3J0X3BvcnQnLDI0NTc4KSksJy1zZXJ2ZXItbmFtZScsY2FuZGlkYXRlWydpZGVudGl0'
    'eSddLAogICAgICAgICAgICAgICAgICAgICAnLXVkcC1saXN0ZW4nLCcxMjcuMC4wLjE6MjQ1NzMnLCctdWRwLXBlZXInLENM'
    'SUVOVCsnOjQ1MDAnLAogICAgICAgICAgICAgICAgICAgICAnLWNhJyxzdHIoUk9PVC8nY2EucGVtJyksJy1jZXJ0JyxzdHIo'
    'Uk9PVC8nY2xpZW50LnBlbScpLCcta2V5JyxzdHIoUk9PVC8nY2xpZW50LWtleS5wZW0nKV0KICAgICAgICBlbHNlOmNhcnJp'
    'ZXI9WycvdXNyL2xvY2FsL3NiaW4vdnBuY3RsJywnaW50ZXJuYWwtdGxzLWNsaWVudCddCiAgICAgICAgVExTX1BST0NFU1M9'
    'c3VicHJvY2Vzcy5Qb3BlbihbJ2lwJywnbmV0bnMnLCdleGVjJyxOUywqY2Fycmllcl0sCiAgICAgICAgICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLkRFVk5VTEwsc3Rkb3V0PXN1YnByb2Nlc3MuREVWTlVMTCwKICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZGVycj1Ob25lIGlmIGNhbmRpZGF0ZS5nZXQoJ2V2Z3QnKSBl'
    'bHNlIHN1YnByb2Nlc3MuREVWTlVMTCkKICAgICAgICBmb3IgXyBpbiByYW5nZSg1MCk6CiAgICAgICAgICAgIGlmIFNUT1A6'
    'cmFpc2UgUnVudGltZUVycm9yKCdjYW5jZWxsZWQnKQogICAgICAgICAgICBpZiBUTFNfUFJPQ0VTUy5wb2xsKCkgaXMgbm90'
    'IE5vbmU6cmFpc2UgUnVudGltZUVycm9yKCd0bHNfY2Fycmllcl9zdG9wcGVkJykKICAgICAgICAgICAgaWYgJzEyNy4wLjAu'
    'MToyNDU3MycgaW4gaW5zaWRlKFsnc3MnLCctYW51J10sY2hlY2s9RmFsc2UpLnN0ZG91dDpicmVhawogICAgICAgICAgICB0'
    'aW1lLnNsZWVwKC4xKQogICAgICAgIGVsc2U6cmFpc2UgUnVudGltZUVycm9yKCd0bHNfY2Fycmllcl9ub3RfcmVhZHknKQog'
    'ICAgICAgIGluc2lkZShbJ25mdCcsJy1mJywnLSddLGRhdGE9J3RhYmxlIGlwIGV2bl90bHNfY2FycmllciB7XG4gY2hhaW4g'
    'b3V0cHV0IHtcbiB0eXBlIG5hdCBob29rIG91dHB1dCBwcmlvcml0eSBkc3RuYXQ7IHBvbGljeSBhY2NlcHQ7XG4gaXAgZGFk'
    'ZHIgMzguMTgwLjE2NC42NyB1ZHAgZHBvcnQgNDQzIHJlZGlyZWN0IHRvIDoyNDU3M1xuIH1cbn1cbicpCiAgICBlbnY9eyoq'
    'b3MuZW52aXJvbiwnU1RST05HU1dBTl9DT05GJzpzdHIoUk9PVC8nc3Ryb25nc3dhbi5jb25mJyl9O2Vudi5wb3AoJ05PVElG'
    'WV9TT0NLRVQnLE5vbmUpCiAgICBkYWVtb249c3RhcnRfZGFlbW9uKGVudikKICAgIHRyeToKICAgICAgICBzd2FuKCctLWlu'
    'aXRpYXRlJywnLS1jaGlsZCcsJ3N0YXJmaXZlLW5ldCcsdGltZW91dD0zNSkKICAgICAgICBpZiBTVE9QOnJhaXNlIFJ1bnRp'
    'bWVFcnJvcignY2FuY2VsbGVkJykKICAgICAgICBpZiBub3QgaW5zdGFsbGVkKCk6cmFpc2UgUnVudGltZUVycm9yKCdoYW5k'
    'c2hha2VfZmFpbGVkJykKICAgICAgICBwcmVwYXJlX2RhdGFfcGxhbmUoY2FuZGlkYXRlWydhZGRyZXNzJ10pCiAgICAgICAg'
    'aWYgbm90IGVncmVzc19oZWFsdGgoKTpyYWlzZSBSdW50aW1lRXJyb3IoJ2VzdG9uaWFfZWdyZXNzX2ZhaWxlZCcpCiAgICAg'
    'ICAgcmV0dXJuIGRhZW1vbgogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgc3RvcF9wcm9jZXNzKGRhZW1vbik7'
    'cmFpc2UKCgpkZWYgc3BlZWRfc2FtcGxlKHNpemU9MjA5NzE1Mik6CiAgICAiIiJCb3VuZGVkIHN5bnRoZXRpYyBiaWRpcmVj'
    'dGlvbmFsIHByb2JlOyBuZXZlciByZWFkcyB1c2VyIGZpbGVzLiIiIgogICAgcGF5bG9hZD1ST09ULydzcGVlZC1wYXlsb2Fk'
    'LmJpbicKICAgIGlmIG5vdCBwYXlsb2FkLmV4aXN0cygpIG9yIHBheWxvYWQuc3RhdCgpLnN0X3NpemUhPXNpemU6CiAgICAg'
    'ICAgd2l0aCBwYXlsb2FkLm9wZW4oJ3diJykgYXMgZjoKICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2Uoc2l6ZS8vNjU1MzYp'
    'OmYud3JpdGUoc2VjcmV0cy50b2tlbl9ieXRlcyg2NTUzNikpCiAgICAgICAgcGF5bG9hZC5jaG1vZCgwbzYwMCkKICAgIGJh'
    'c2U9WydjdXJsJywnLTQnLCctLW5vcHJveHknLCcqJywnLS1mYWlsJywnLS1zaWxlbnQnLCctLXNob3ctZXJyb3InLCctLWNv'
    'bm5lY3QtdGltZW91dCcsJzMnLCctLW1heC10aW1lJywnMTInLAogICAgICAgICAgJy0tb3V0cHV0JywnL2Rldi9udWxsJywn'
    'LS13cml0ZS1vdXQnLCcle2h0dHBfY29kZX0gJXtzaXplX2Rvd25sb2FkfSAle3NpemVfdXBsb2FkfSAle3RpbWVfdG90YWx9'
    'ICV7dGltZV9jb25uZWN0fSddCiAgICByZXN1bHRzPVtdCiAgICBmb3IgZGlyZWN0aW9uIGluICgnZG93bicsJ3VwJyk6CiAg'
    'ICAgICAgaWYgU1RPUDpyYWlzZSBSdW50aW1lRXJyb3IoJ2NhbmNlbGxlZCcpCiAgICAgICAgZXh0cmE9WydodHRwczovL3Nw'
    'ZWVkLmNsb3VkZmxhcmUuY29tL19fZG93bj9ieXRlcz0nK3N0cihzaXplKV0gaWYgZGlyZWN0aW9uPT0nZG93bicgZWxzZSBb'
    'Jy0tZGF0YS1iaW5hcnknLCdAJytzdHIocGF5bG9hZCksJ2h0dHBzOi8vc3BlZWQuY2xvdWRmbGFyZS5jb20vX191cCddCiAg'
    'ICAgICAgcj1pbnNpZGUoYmFzZStleHRyYSx0aW1lb3V0PTE0LGNoZWNrPUZhbHNlKQogICAgICAgIHRyeToKICAgICAgICAg'
    'ICAgY29kZSxkb3duLHVwLGVsYXBzZWQsbGF0ZW5jeT1yLnN0ZG91dC5zcGxpdCgpCiAgICAgICAgICAgIGNvdW50PWZsb2F0'
    'KGRvd24gaWYgZGlyZWN0aW9uPT0nZG93bicgZWxzZSB1cCkKICAgICAgICAgICAgaWYgci5yZXR1cm5jb2RlIG9yIGNvZGUh'
    'PScyMDAnIG9yIGNvdW50PHNpemU6cmFpc2UgVmFsdWVFcnJvcigpCiAgICAgICAgICAgIHJlc3VsdHMuYXBwZW5kKChjb3Vu'
    'dCo4L21heCguMDAxLGZsb2F0KGVsYXBzZWQpKS8xZTYsZmxvYXQobGF0ZW5jeSkqMTAwMCkpCiAgICAgICAgZXhjZXB0IChW'
    'YWx1ZUVycm9yLFR5cGVFcnJvcik6cmV0dXJuIHsnYXZhaWxhYmxlJzpGYWxzZX0KICAgIHJldHVybiB7J2F2YWlsYWJsZSc6'
    'VHJ1ZSwnZG93bmxvYWRfbWJwcyc6cm91bmQocmVzdWx0c1swXVswXSwyKSwndXBsb2FkX21icHMnOnJvdW5kKHJlc3VsdHNb'
    'MV1bMF0sMiksCiAgICAgICAgICAgICdsYXRlbmN5X21zJzpyb3VuZChtYXgoeFsxXSBmb3IgeCBpbiByZXN1bHRzKSwxKSwn'
    'c2FtcGxlX2J5dGVzJzpzaXplfQoKCmRlZiB0cmFmZmljX3RvdGFsKCk6CiAgICB0cnk6CiAgICAgICAgc3RhdHM9UGF0aCgn'
    'L3N5cy9jbGFzcy9uZXQnKS9GVUxMX0hPU1QvJ3N0YXRpc3RpY3MnCiAgICAgICAgcmV0dXJuIHN1bShpbnQoKHN0YXRzL25h'
    'bWUpLnJlYWRfdGV4dCgpKSBmb3IgbmFtZSBpbiAoJ3J4X2J5dGVzJywndHhfYnl0ZXMnKSkKICAgIGV4Y2VwdCAoT1NFcnJv'
    'cixWYWx1ZUVycm9yKTpyZXR1cm4gMAoKCmRlZiBzcGVlZF9kZWdyYWRlZChzYW1wbGUsYmFzZWxpbmUpOgogICAgIyBSZXF1'
    'aXJlIHVzYWJsZSBzYW1wbGVzIGFuZCBhIG1lYW5pbmdmdWwgYmFzZWxpbmUgaW4gdGhlIGFmZmVjdGVkIGRpcmVjdGlvbi4K'
    'ICAgIHJldHVybiBib29sKHNhbXBsZS5nZXQoJ2F2YWlsYWJsZScpIGFuZCBhbnkoCiAgICAgICAgYmFzZWxpbmUuZ2V0KGss'
    'MCk+PTIgYW5kIHNhbXBsZS5nZXQoaywwKTxiYXNlbGluZVtrXSouMgogICAgICAgIGZvciBrIGluICgnZG93bmxvYWRfbWJw'
    'cycsJ3VwbG9hZF9tYnBzJykpKQoKCmRlZiB3b3JrZXIoKToKICAgIGdsb2JhbCBTVE9QCiAgICBTVE9QPUZhbHNlCiAgICBz'
    'aWduYWwuc2lnbmFsKHNpZ25hbC5TSUdURVJNLGxhbWJkYSAqXzpnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1AnLFRydWUp'
    'KQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSU5ULGxhbWJkYSAqXzpnbG9iYWxzKCkuX19zZXRpdGVtX18oJ1NUT1An'
    'LFRydWUpKQogICAgZGFlbW9uPU5vbmUKICAgIHJhbms9cmFua19hcGkuUmFua2luZyhST09ULydyYW5raW5nLmpzb24nLFt4'
    'WydpZCddIGZvciB4IGluIENBTkRJREFURVNdKQogICAgdHJ5OgogICAgICAgIGNsZWFudXAoKTtyZWZyZXNoX3JldGFpbmVk'
    'X2d1YXJkKCkKICAgICAgICBzdGFnZSgncHJlcGFyZScsJ9CT0L7RgtC+0LLQu9GOINC30LDRidC40YnRkdC90L3Ri9C1INC8'
    '0LDRgNGI0YDRg9GC0YsuJyw1LGFjdGl2ZT1GYWxzZSxtZXRyaWNzPXt9LGVycm9yX2NvZGU9Jycsc2NvcGU9J2Z1bGwtZGV2'
    'aWNlJykKICAgICAgICBzZXR1cF9uZXR3b3JrKCkKICAgICAgICBpZGVudGl0eSxfPWVucm9sbCgpCiAgICAgICAgc3luY19k'
    'ZXZpY2VfbmFtZSgpCiAgICAgICAgY2xlYW51cCgpCiAgICAgICAgbG9hZGVkPXJhbmsubG9hZCgpCiAgICAgICAgc2VsZWN0'
    'ZWQ9c2VsZWN0ZWRfcm91dGUoKQogICAgICAgIHJlYnVpbGQ9KFJPT1QvJ3JlY2FsaWJyYXRlJykuZXhpc3RzKCkgb3IgKHNl'
    'bGVjdGVkPT0nYXV0bycgYW5kIG5vdCBsb2FkZWQpCiAgICAgICAgaWYgbm90IGxvYWRlZDpyYW5rLmJvb3RzdHJhcCgpCiAg'
    'ICAgICAgaWYgcmVidWlsZDoKICAgICAgICAgICAgbWVhc3VyZW1lbnRzPXt9CiAgICAgICAgICAgIGZvciBpLGNhbmRpZGF0'
    'ZSBpbiBlbnVtZXJhdGUoQ0FORElEQVRFUyk6CiAgICAgICAgICAgICAgICBpZiBTVE9QOnJldHVybgogICAgICAgICAgICAg'
    'ICAgc3RhZ2UoJ3JhbmtpbmcnLCfQn9GA0L7QstC10YDRj9GOINC80LDRgNGI0YDRg9GCOiAnK2NhbmRpZGF0ZVsnbGFiZWwn'
    'XSwxMCtpbnQoaSo2MC9sZW4oQ0FORElEQVRFUykpLGFjdGl2ZT1GYWxzZSxwYXRoPWNhbmRpZGF0ZVsnaWQnXSkKICAgICAg'
    'ICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBkYWVtb249c3RhcnRfY2FuZGlkYXRlKGNhbmRpZGF0ZSxpZGVu'
    'dGl0eSkKICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGludGVncml0eT1kb3dubG9h'
    'ZCgxMDQ4NTc2KVsnaW50ZWdyaXR5J10KICAgICAgICAgICAgICAgICAgICBleGNlcHQgUnVudGltZUVycm9yIGFzIGVycm9y'
    'OgogICAgICAgICAgICAgICAgICAgICAgICBpZiBzdHIoZXJyb3IpPT0naW50ZWdyaXR5X2ZhaWxlZCc6cmFpc2UKICAgICAg'
    'ICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PU5vbmUKICAgICAgICAgICAgICAgICAgICBleGNlcHQgKE9TRXJyb3IsVmFs'
    'dWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgICAgICAgICAgICAgaW50ZWdyaXR5PU5v'
    'bmUKICAgICAgICAgICAgICAgICAgICBtZWFzdXJlbWVudHNbY2FuZGlkYXRlWydpZCddXT17J29rJzpUcnVlLCoqc3BlZWRf'
    'c2FtcGxlKDIwOTcxNTIpLCdpbnRlZ3JpdHknOmludGVncml0eX0KICAgICAgICAgICAgICAgIGV4Y2VwdCAoT1NFcnJvcixW'
    'YWx1ZUVycm9yLFJ1bnRpbWVFcnJvcixzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICAgICAgICAgICAgICBp'
    'ZiBTVE9QOnJldHVybgogICAgICAgICAgICAgICAgICAgIG1lYXN1cmVtZW50c1tjYW5kaWRhdGVbJ2lkJ11dPXsnb2snOkZh'
    'bHNlfQogICAgICAgICAgICAgICAgZmluYWxseToKICAgICAgICAgICAgICAgICAgICBzdG9wX2NhbmRpZGF0ZShkYWVtb24p'
    'O2RhZW1vbj1Ob25lCiAgICAgICAgICAgIHJhbmsuYnVpbGQobWVhc3VyZW1lbnRzKQogICAgICAgICAgICAoUk9PVC8ncmVj'
    'YWxpYnJhdGUnKS51bmxpbmsobWlzc2luZ19vaz1UcnVlKQogICAgICAgIGNhbmRpZGF0ZXM9e3hbJ2lkJ106eCBmb3IgeCBp'
    'biBDQU5ESURBVEVTfQogICAgICAgIGN1cnJlbnQ9c2VsZWN0ZWQgaWYgc2VsZWN0ZWQhPSdhdXRvJyBlbHNlIG5leHQoaXRl'
    'cihyYW5rLmNhbmRpZGF0ZXMoKSksTm9uZSkKICAgICAgICB3aGlsZSBjdXJyZW50IGFuZCBub3QgU1RPUDoKICAgICAgICAg'
    'ICAgY2FuZGlkYXRlPWNhbmRpZGF0ZXNbY3VycmVudF0KICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc3RhZ2Uo'
    'J2hhbmRzaGFrZScsJ9Cf0L7QtNC60LvRjtGH0LDRjjogJytjYW5kaWRhdGVbJ2xhYmVsJ10sNzUsYWN0aXZlPUZhbHNlLHBh'
    'dGg9Y3VycmVudCkKICAgICAgICAgICAgICAgIGRhZW1vbj1zdGFydF9jYW5kaWRhdGUoY2FuZGlkYXRlLGlkZW50aXR5KQog'
    'ICAgICAgICAgICAgICAgc3RhZ2UoJ3JvdXRpbmcnLCfQn9C+0LTQutC70Y7Rh9Cw0Y4g0YLRgNCw0YTQuNC6INC6INC/0YDQ'
    'vtCy0LXRgNC10L3QvdC+0LzRgyDQvNCw0YDRiNGA0YPRgtGDLicsOTIpCiAgICAgICAgICAgICAgICBhY3RpdmF0ZV9mdWxs'
    'KGNhbmRpZGF0ZVsnYWRkcmVzcyddKQogICAgICAgICAgICAgICAgc3RhZ2UoJ2Nvbm5lY3RlZCcsJ9Cf0L7QtNC60LvRjtGH'
    '0LXQvdC+OiAnK2NhbmRpZGF0ZVsnbGFiZWwnXSsnLicsMTAwLGFjdGl2ZT1UcnVlLHBhdGg9Y3VycmVudCwKICAgICAgICAg'
    'ICAgICAgICAgICAgIG1ldHJpY3M9cmFuay5kYXRhWydlbnRyaWVzJ11bY3VycmVudF0sc2luY2U9aW50KHRpbWUudGltZSgp'
    'KSxlcnJvcl9jb2RlPScnKQogICAgICAgICAgICAgICAgZmFpbHVyZXM9MDtzbG93PTA7bGFzdF90cmFmZmljPXRyYWZmaWNf'
    'dG90YWwoKTtuZXh0X3NwZWVkPXRpbWUubW9ub3RvbmljKCkrNjAwK3NlY3JldHMucmFuZGJlbG93KDYwKQogICAgICAgICAg'
    'ICAgICAgd2hpbGUgbm90IFNUT1A6CiAgICAgICAgICAgICAgICAgICAgZm9yIF8gaW4gcmFuZ2UoNTApOgogICAgICAgICAg'
    'ICAgICAgICAgICAgICBpZiBTVE9QOmJyZWFrCiAgICAgICAgICAgICAgICAgICAgICAgIHRpbWUuc2xlZXAoLjEpCiAgICAg'
    'ICAgICAgICAgICAgICAgaWYgU1RPUDpicmVhawogICAgICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAg'
    'ICAgICAgaWYgcG9saWN5IGlzIG5vdCBOb25lOnBvbGljeS5lbnN1cmVfcm91dGUoKQogICAgICAgICAgICAgICAgICAgICAg'
    'ICBpZiBETlNfUFJPQ0VTUyBpcyBOb25lIG9yIEROU19QUk9DRVNTLnBvbGwoKSBpcyBub3QgTm9uZToKICAgICAgICAgICAg'
    'ICAgICAgICAgICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQn9C10YDQtdC30LDQv9GD0YHQutCw0Y4g0LfQsNGJ0LjRidGR'
    '0L3QvdGL0LkgRE5TLicsOTAsYWN0aXZlPUZhbHNlLGVycm9yX2NvZGU9J3ByaXZhdGVfZG5zX3N0b3BwZWQnKQogICAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgc3RhcnRfbmFtZXNwYWNlX2RucygpCiAgICAgICAgICAgICAgICAgICAgICAgIGhlYWx0'
    'aHk9cGF0aF9oZWFsdGh5KGRhZW1vbikKICAgICAgICAgICAgICAgICAgICAgICAgaWYgaGVhbHRoeSBhbmQgbm90IHJlY292'
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
    'IGlmIG5vdCBvZmZsaW5lOgogICAgICAgICAgICAgICAgICAgIGlmIHNlbGVjdGVkPT0nYXV0byc6CiAgICAgICAgICAgICAg'
    'ICAgICAgICAgIGN1cnJlbnQ9cmFuay5uZXh0X2FmdGVyKGN1cnJlbnQpIG9yIG5leHQoaXRlcihyYW5rLmNhbmRpZGF0ZXMo'
    'KSksTm9uZSkKICAgICAgICAgICAgICAgIHN0YWdlKCdyZXBhaXJpbmcnLCfQodCy0Y/Qt9GMINC/0L7RgtC10YDRj9C90LAu'
    'INCf0LXRgNC10LrQu9GO0YfQsNGOINC30LDRidC40YnRkdC90L3Ri9C5INC80LDRgNGI0YDRg9GCLicgaWYgbm90IG9mZmxp'
    'bmUgZWxzZSAn0J7QttC40LTQsNGOINCy0L7RgdGB0YLQsNC90L7QstC70LXQvdC40Y8g0YTQuNC30LjRh9C10YHQutC+0Lkg'
    '0YHQtdGC0LguJyw2NSwKICAgICAgICAgICAgICAgICAgICAgIGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPXJlYXNvbikKICAg'
    'ICAgICAgICAgICAgIGZvciBfIGluIHJhbmdlKDMwIGlmIG5vdCBvZmZsaW5lIGVsc2UgMTAwKToKICAgICAgICAgICAgICAg'
    'ICAgICBpZiBTVE9QOmJyZWFrCiAgICAgICAgICAgICAgICAgICAgdGltZS5zbGVlcCguMSkKICAgICAgICAgICAgZmluYWxs'
    'eToKICAgICAgICAgICAgICAgIHN0b3BfY2FuZGlkYXRlKGRhZW1vbik7ZGFlbW9uPU5vbmUKICAgICAgICBpZiBub3QgU1RP'
    'UDoKICAgICAgICAgICAgc3RhZ2UoJ2ZhaWxlZCcsJ9Cd0LXRgiDQvdCw0YHRgtGA0L7QtdC90L3Ri9GFINC80LDRgNGI0YDR'
    'g9GC0L7Qsi4nLDAsCiAgICAgICAgICAgICAgICAgIGFjdGl2ZT1GYWxzZSxlcnJvcl9jb2RlPSdyYW5raW5nX2V4aGF1c3Rl'
    'ZCcpCiAgICBleGNlcHQgKE9TRXJyb3IsVmFsdWVFcnJvcixSdW50aW1lRXJyb3Isc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJl'
    'ZCkgYXMgZXhjOgogICAgICAgIGlmIG5vdCBTVE9QOgogICAgICAgICAgICBjb2RlPXN0cihleGMpIGlmIHJlLmZ1bGxtYXRj'
    'aCgnW2Etel9dezEsNjR9JyxzdHIoZXhjKSkgZWxzZSAnY29ubmVjdGlvbl9mYWlsZWQnCiAgICAgICAgICAgIHN0YWdlKCdm'
    'YWlsZWQnLCfQndC1INGD0LTQsNC70L7RgdGMINC/0L7QtNCz0L7RgtC+0LLQuNGC0YwgVlBOLiDQndCw0LbQvNC40YLQtSDC'
    'q9CS0L7RgdGB0YLQsNC90L7QstC40YLRjMK7LicsMCxhY3RpdmU9RmFsc2UsZXJyb3JfY29kZT1jb2RlKQogICAgZmluYWxs'
    'eToKICAgICAgICBzdG9wX2NhbmRpZGF0ZShkYWVtb24pCiAgICAgICAgaWYgU1RPUDpzdGFnZSgnb2ZmJywnVlBOINCy0YvQ'
    'utC70Y7Rh9C10L0uJywwLGFjdGl2ZT1GYWxzZSkK'
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
