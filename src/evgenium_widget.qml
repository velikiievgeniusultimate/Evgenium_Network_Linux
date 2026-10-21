import QtQuick
import QtQuick.Window
import QtQuick.Controls as C
import QtQuick.Layouts
import Qt.labs.platform as Platform

C.ApplicationWindow {
    id: root
    width: 384
    height: body.implicitHeight + 40
    visible: false
    title: "Evgenium · VPN"
    flags: Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
    color: "transparent"
    property var state: ({})
    property bool ready: false
    property bool busy: false
    property bool statePending: false
    property string errorText: ""
    property string pollErrorText: ""
    readonly property var tunnel: state.tunnel || ({})
    readonly property bool connected: ready && !pollErrorText && Boolean(state.active)
    readonly property bool connecting: ready && !pollErrorText && Boolean(state.connecting)
    readonly property bool engaged: Boolean(tunnel.running || state.guard)
    readonly property color accent: pollErrorText ? "#ffbd69" : connected ? "#5ce0bc" : connecting ? "#79baff" : "#9aaac0"
    readonly property string statusTitle: !ready ? "Проверяем VPN…" : pollErrorText ? "Состояние неизвестно" : connected ? "Вы подключены" : connecting ? "Подключаем…" : state.guard ? "Трафик защищён" : "VPN выключен"
    readonly property var args: Qt.application.arguments
    readonly property string apiToken: String(args[args.length - 1])
    readonly property string apiBase: "http://127.0.0.1:" + String(args[args.length - 2])

    function api(method, path, payload, callback, operation) {
        const xhr = new XMLHttpRequest()
        let finished = false
        const timer = watchdog.createObject(root)
        function finish(error, data) {
            if (finished) return
            finished = true
            timer.stop(); timer.destroy()
            if (operation) { root.busy = false; root.errorText = error || "" }
            else { root.statePending = false; root.pollErrorText = error || "" }
            if (!error && callback) callback(data)
        }
        timer.interval = operation ? 780000 : 12000
        timer.triggered.connect(function() {
            finish(operation ? "Ответ операции не получен. Проверьте vpn status." : "Нет ответа от VPN. Попробуйте обновить состояние.", null)
            xhr.abort()
        })
        xhr.open(method, apiBase + path, true)
        xhr.setRequestHeader("X-Evgenium-Token", apiToken)
        if (payload !== null) xhr.setRequestHeader("Content-Type", "application/json")
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE || finished) return
            let data
            try { data = JSON.parse(String(xhr.responseText || "{}")) }
            catch (e) { finish("Некорректный ответ VPN", null); return }
            finish(xhr.status >= 200 && xhr.status < 300 && data.ok ? "" : String(data.error || "VPN недоступен"), data)
        }
        timer.start()
        xhr.send(payload === null ? null : JSON.stringify(payload))
    }
    Component { id: watchdog; Timer { repeat: false } }
    function refreshState() {
        if (statePending) return
        statePending = true
        api("GET", "/api/state", null, function(reply) { root.state = reply.state || ({}); root.ready = true })
    }
    function action(name) {
        if (busy || !ready || pollErrorText || (connecting && name !== "disconnect")) return
        busy = true
        api("POST", "/api/action", {action: name}, function(_reply) { root.refreshState() }, true)
    }
    function openSettings() {
        if (busy) return
        busy = true
        api("POST", "/api/settings", {}, function(_reply) { if (tray.available) root.hide() }, true)
    }
    function showPanel() {
        // Select the screen containing the tray, and clamp against its work area.
        const g = tray.geometry
        for (let i = 0; i < Qt.application.screens.length; ++i) {
            const s = Qt.application.screens[i]
            if (g.width > 0 && g.x >= s.virtualX && g.x < s.virtualX + s.width && g.y >= s.virtualY && g.y < s.virtualY + s.height) { root.screen = s; break }
        }
        const area = {x: root.screen.virtualX, y: root.screen.virtualY, width: root.screen.desktopAvailableWidth, height: root.screen.desktopAvailableHeight}
        root.x = Math.round(Math.max(area.x + 8, Math.min(g.width > 0 ? g.x + g.width - width : area.x + area.width - width - 16, area.x + area.width - width - 8)))
        root.y = Math.round(Math.max(area.y + 8, Math.min(g.height > 0 && g.y < area.y + area.height / 2 ? g.y + g.height + 8 : (g.height > 0 ? g.y - height - 8 : area.y + area.height - height - 16), area.y + area.height - height - 8)))
        root.show(); root.raise(); root.requestActivate(); refreshState()
    }
    onActiveChanged: if (!active && visible && tray.available && !args.includes("--preview")) dismiss.start()
    Timer { id: dismiss; interval: 180; onTriggered: if (!root.active) root.hide() }
    onClosing: function(event) { if (tray.available) { event.accepted = false; root.hide() } }
    Shortcut { sequence: "Escape"; onActivated: if (tray.available) root.hide() }
    Timer { interval: root.visible || root.connecting ? 1500 : 5000; running: true; repeat: true; onTriggered: root.refreshState() }
    Component.onCompleted: { refreshState(); if (args.includes("--show") || args.includes("--preview") || !tray.available) showPanel() }

    Platform.SystemTrayIcon {
        id: tray
        visible: true
        icon.source: Qt.resolvedUrl("widget-" + (root.pollErrorText ? "warning" : root.connected ? "active" : root.connecting || root.busy ? "connecting" : root.state.guard ? "warning" : "off") + ".svg")
        tooltip: "Evgenium · " + root.statusTitle
        onActivated: function(reason) {
            if (reason === Platform.SystemTrayIcon.Trigger || reason === Platform.SystemTrayIcon.DoubleClick) {
                if (root.visible) root.hide(); else root.showPanel()
            }
        }
        menu: Platform.Menu {
            Platform.MenuItem { text: "Открыть виджет"; onTriggered: root.showPanel() }
            Platform.MenuItem { text: root.engaged ? "Отключить VPN" : "Подключить VPN"; enabled: root.ready && !root.busy && !root.pollErrorText && (root.engaged || root.tunnel.has_token); onTriggered: root.action(root.engaged ? "disconnect" : "connect") }
            Platform.MenuItem { text: "Настройки"; enabled: !root.busy; onTriggered: root.openSettings() }
            Platform.MenuSeparator {}
            Platform.MenuItem { text: "Закрыть виджет (VPN продолжит работу)"; onTriggered: Qt.quit() }
        }
    }

    component Muted: C.Label { color: "#9bacc1"; font.pixelSize: 12 }
    component SmallButton: C.Button {
        id: control
        Layout.fillWidth: true
        implicitHeight: 38
        font.pixelSize: 12
        contentItem: Text { text: control.text; color: control.enabled ? "#d8e6f5" : "#65758a"; font: control.font; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
        background: Rectangle { radius: 10; color: control.down ? "#35475d" : control.hovered ? "#2b3b50" : "#202e40"; border.color: "#34445a" }
    }
    Item {
        id: panel
        anchors.fill: parent
    Rectangle {
        anchors.fill: parent
        radius: 22
        color: "#121c2b"
        border.color: "#354254"
        border.width: 1
        gradient: Gradient { GradientStop { position: 0; color: "#1d2d41" } GradientStop { position: 1; color: "#111a28" } }
    }
    ColumnLayout {
        id: body
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: 20 }
        spacing: 16
        RowLayout {
            Layout.fillWidth: true
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 3
                C.Label { text: "EVGENIUM"; color: "#eff6ff"; font.pixelSize: 15; font.letterSpacing: 2.4; font.bold: true }
                Muted { text: "NETWORK / VPN"; font.pixelSize: 10; font.letterSpacing: 1.8 }
            }
            C.ToolButton {
                text: "×"; font.pixelSize: 23; palette.buttonText: "#9bacc1"
                Accessible.name: "Скрыть виджет"
                onClicked: root.hide()
                visible: tray.available
            }
        }
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: hero.implicitHeight + 32
            radius: 16; color: "#243548"; border.color: "#3b5266"
            ColumnLayout {
                id: hero
                anchors { left: parent.left; right: parent.right; top: parent.top; margins: 16 }
                spacing: 15
                RowLayout {
                    Layout.fillWidth: true
                    Rectangle {
                        implicitWidth: 52; implicitHeight: 52; radius: 16; color: "#1a2a39"
                        Image { anchors.centerIn: parent; width: 34; height: 34; source: tray.icon.source }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 5
                        C.Label { text: root.statusTitle; font.pixelSize: 20; font.bold: true; color: "#eff6ff" }
                        RowLayout {
                            Rectangle { implicitWidth: 6; implicitHeight: 6; radius: 3; color: root.accent }
                            Muted { text: root.connected ? "Защищённое подключение" : root.connecting ? "Создаём защищённый туннель" : root.state.guard ? "Ожидает восстановления" : "Прямое подключение"; color: root.accent; font.pixelSize: 11 }
                        }
                    }
                }
                C.Label {
                    Layout.fillWidth: true; wrapMode: Text.Wrap
                    text: root.pollErrorText || root.tunnel.message || (root.ready ? "Подключитесь одним нажатием." : "Получаем состояние подключения.")
                    color: "#b7c8da"; font.pixelSize: 12; lineHeight: 1.2
                }
                C.ProgressBar { Layout.fillWidth: true; visible: root.connecting; from: 0; to: 100; value: Number(root.tunnel.progress || 0); palette.highlight: "#79baff" }
                RowLayout {
                    Layout.fillWidth: true
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 3
                        C.Label { text: root.busy ? "Выполняем…" : root.engaged ? "Отключить VPN" : "Подключить VPN"; color: "#eff6ff"; font.bold: true; font.pixelSize: 14 }
                        Muted { text: root.engaged ? "Весь трафик под защитой правил" : "Защита интернет-соединения"; font.pixelSize: 10 }
                    }
                    C.Switch {
                        id: vpnSwitch
                        checked: root.engaged
                        enabled: root.ready && !root.busy && !root.pollErrorText && (root.engaged || root.tunnel.has_token)
                        Accessible.name: root.engaged ? "Отключить VPN" : "Подключить VPN"
                        onClicked: root.action(root.engaged ? "disconnect" : "connect")
                        indicator: Rectangle {
                            implicitWidth: 52; implicitHeight: 30; radius: 15
                            x: vpnSwitch.leftPadding; y: (vpnSwitch.height - height) / 2
                            color: vpnSwitch.enabled ? root.engaged ? "#5ce0bc" : "#4a5b70" : "#3a495b"
                            Rectangle { x: root.engaged ? 25 : 4; y: 4; width: 22; height: 22; radius: 11; color: root.engaged ? "#153a32" : "#dce6f2"; Behavior on x { NumberAnimation { duration: 160 } } }
                        }
                    }
                }
            }
        }
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            Repeater {
                model: ["КОМПЬЮТЕР", "HSVDS", "ЭСТОНИЯ"]
                delegate: RowLayout {
                    required property string modelData
                    required property int index
                    Layout.fillWidth: true; spacing: 5
                    Rectangle { implicitWidth: 5; implicitHeight: 5; radius: 3; color: root.connected ? root.accent : "#59697c" }
                    Muted { text: modelData; font.pixelSize: 9; font.letterSpacing: 0.7 }
                    Muted { visible: index < 2; text: "→"; Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter }
                }
            }
        }
        Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: "#2e3c50" }
        RowLayout {
            Layout.fillWidth: true
            ColumnLayout {
                Layout.fillWidth: true; spacing: 5
                Muted { text: "УСТРОЙСТВО"; font.pixelSize: 9; font.letterSpacing: 1 }
                C.Label { Layout.fillWidth: true; text: root.tunnel.device_name || "Этот компьютер"; color: "#dce8f6"; font.pixelSize: 13; elide: Text.ElideRight }
            }
            Rectangle {
                implicitWidth: guardLabel.implicitWidth + 18; implicitHeight: 27; radius: 8
                color: root.ready && !root.pollErrorText && root.state.guard ? "#1e3d38" : "#273246"
                C.Label { id: guardLabel; anchors.centerIn: parent; text: !root.ready || root.pollErrorText ? "Защита · ?" : root.state.guard ? "Защита · вкл" : "Защита · выкл"; color: root.ready && !root.pollErrorText && root.state.guard ? "#79d9bd" : "#a9b6c9"; font.pixelSize: 11 }
            }
        }
        C.Label { Layout.fillWidth: true; visible: root.errorText.length > 0; text: root.errorText; color: "#ffbcad"; wrapMode: Text.Wrap; font.pixelSize: 12; Accessible.role: Accessible.AlertMessage }
        C.Label { Layout.fillWidth: true; visible: root.ready && !root.tunnel.has_token; text: "Добавьте токен клиента в настройках."; color: "#ffcd87"; wrapMode: Text.Wrap; font.pixelSize: 12 }
        RowLayout {
            Layout.fillWidth: true; spacing: 8
            SmallButton { text: "Настройки"; enabled: !root.busy; onClicked: root.openSettings() }
            SmallButton { text: root.pollErrorText ? "Обновить" : "Восстановить"; enabled: !root.busy && (Boolean(root.pollErrorText) || (root.ready && root.tunnel.has_token && !root.connecting)); onClicked: root.pollErrorText ? root.refreshState() : root.action("repair") }
        }
        RowLayout {
            Layout.fillWidth: true
            Muted { text: "Evgenium " + String(root.state.manager_version || ""); font.pixelSize: 10; Layout.fillWidth: true }
            Muted { text: "Обновляется через vpn update"; font.pixelSize: 10 }
        }
    }
    }
}
