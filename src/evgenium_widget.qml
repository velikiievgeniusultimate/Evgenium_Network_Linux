import QtQuick
import QtQuick.Window
import QtQuick.Controls as C
import QtQuick.Layouts
import Qt.labs.settings as Storage

C.ApplicationWindow {
    id: root
    width: 164
    height: 48
    visible: true
    title: "Evgenium VPN Widget"
    flags: Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnBottomHint | Qt.WindowDoesNotAcceptFocus
    color: "transparent"
    x: Screen.virtualX + Screen.width - width - 32
    y: Screen.virtualY + 80
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
    readonly property var args: Qt.application.arguments
    readonly property string apiToken: String(args[args.length - 1])
    readonly property string apiBase: "http://127.0.0.1:" + String(args[args.length - 2])
    readonly property string statusText: errorText || pollErrorText || (!ready ? "Проверяем состояние VPN…" : busy ? "Выполняется операция…" : connecting ? "Подключение…" : connected ? "VPN включён" : state.guard ? "Трафик заблокирован защитой" : "VPN выключен")

    Storage.Settings {
        id: position
        fileName: root.args[root.args.length - 3]
        category: "desktop-widget"
        property alias x: root.x
        property alias y: root.y
    }

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
        api("POST", "/api/settings", {}, null, true)
    }
    Timer { interval: 1500; running: true; repeat: true; onTriggered: root.refreshState() }
    Component.onCompleted: {
        // Recover a widget saved on a display that is no longer connected.
        let onScreen = false
        for (let i = 0; i < Qt.application.screens.length; ++i) {
            const s = Qt.application.screens[i]
            if (root.x >= s.virtualX && root.x + root.width <= s.virtualX + s.width && root.y >= s.virtualY && root.y + root.height <= s.virtualY + s.height) onScreen = true
        }
        if (!onScreen) { root.x = Screen.virtualX + Screen.width - width - 32; root.y = Screen.virtualY + 80 }
        refreshState()
    }
    C.Menu {
        id: contextMenu
        C.MenuItem { text: "Настройки"; enabled: !root.busy; onTriggered: root.openSettings() }
        C.MenuItem { text: "Закрыть виджет"; onTriggered: Qt.quit() }
    }
    Rectangle {
        id: panel
        anchors.fill: parent
        radius: 6
        color: "#292e32"
        border.color: "#50575d"
        border.width: 1
        MouseArea {
            id: mover
            anchors.fill: parent
            hoverEnabled: true
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            property point pressPosition
            property point windowPosition
            onPressed: function(mouse) {
                if (mouse.button === Qt.RightButton) { contextMenu.popup(); return }
                pressPosition = mapToGlobal(mouse.x, mouse.y)
                windowPosition = Qt.point(root.x, root.y)
            }
            onPositionChanged: function(mouse) {
                if (!(pressedButtons & Qt.LeftButton)) return
                const cursor = mapToGlobal(mouse.x, mouse.y)
                root.x = Math.round(windowPosition.x + cursor.x - pressPosition.x)
                root.y = Math.round(windowPosition.y + cursor.y - pressPosition.y)
            }
            onReleased: position.sync()
        }
        C.ToolTip.visible: mover.containsMouse
        C.ToolTip.delay: 700
        C.ToolTip.text: root.statusText
        RowLayout {
            anchors.fill: parent
            anchors.margins: 12
            spacing: 12
            C.Label { text: "E-VPN"; font.bold: true; font.pixelSize: 14; color: "#eff0f1"; Layout.fillWidth: true }
            C.Switch {
                id: vpnSwitch
                Layout.preferredWidth: 44
                Layout.preferredHeight: 24
                padding: 0
                checked: root.engaged
                enabled: root.ready && !root.busy && !root.pollErrorText && (root.engaged || root.tunnel.has_token)
                opacity: enabled ? 1 : 0.55
                Accessible.name: root.engaged ? "Отключить VPN" : "Подключить VPN"
                onClicked: root.action(root.engaged ? "disconnect" : "connect")
                C.ToolTip.visible: hovered
                C.ToolTip.delay: 700
                C.ToolTip.text: root.statusText
                indicator: Rectangle {
                    implicitWidth: 44
                    implicitHeight: 24
                    radius: 12
                    color: root.pollErrorText || root.errorText ? "#9f7b42" : root.connected ? "#3daee9" : "#6d7479"
                    Rectangle {
                        width: 18; height: 18; radius: 9; y: 3
                        x: root.engaged ? 23 : 3
                        color: "#eff0f1"
                        Behavior on x { NumberAnimation { duration: 120 } }
                    }
                }
            }
        }
    }
}
