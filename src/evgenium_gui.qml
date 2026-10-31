import QtQuick
import QtQml
import QtQuick.Controls as C
import QtQuick.Layouts

C.ApplicationWindow {
    id: root
    width: 1040
    height: 700
    minimumWidth: 860
    minimumHeight: 580
    visible: true
    title: "Evgenium Network"
    color: "#141217"
    flags: Qt.Window | Qt.FramelessWindowHint | Qt.WindowSystemMenuHint | Qt.WindowMinimizeButtonHint

    readonly property color bg: "#141217"
    readonly property color surface: "#211c24"
    readonly property color sidebar: "#19151c"
    readonly property color sidebarHover: "#2b202a"
    readonly property color accent: "#ff586d"
    readonly property color accentSoft: "#3a202d"
    readonly property color textMain: "#fff1e9"
    readonly property color textMuted: "#baa8af"
    readonly property color border: "#48303c"
    readonly property color good: "#a6d8c2"
    readonly property color bad: "#ffad9e"

    font.family: "Noto Sans"
    palette.window: bg
    palette.windowText: textMain
    palette.base: "#18131b"
    palette.alternateBase: surface
    palette.text: textMain
    palette.button: "#29202b"
    palette.buttonText: textMain
    palette.highlight: accent
    palette.highlightedText: "#180d13"
    palette.placeholderText: textMuted
    palette.mid: border
    palette.light: border
    palette.dark: textMuted

    property string reportText: ""
    property string reportId: ""
    property int pageIndex: 0
    property bool busy: false
    property string errorText: ""
    property string pollErrorText: ""
    property var state: ({})
    property var runningApps: []
    property bool tokenEditing: false
    property bool deviceEditing: false
    readonly property bool tokenSaved: Boolean(root.tunnel.has_token)
    readonly property bool tokenLocked: tokenSaved && !tokenEditing
    readonly property var tunnel: root.state.tunnel || ({})
    readonly property var policy: root.state.policy || ({})
    readonly property string category: ["", "applications", "networks", "ports", "dns", ""][pageIndex]
    property bool showBase: false

    readonly property var args: Qt.application.arguments
    readonly property string apiToken: args.length >= 2 ? String(args[args.length - 1]) : ""
    readonly property string apiPort: args.length >= 3 ? String(args[args.length - 2]) : "0"
    readonly property string apiBase: "http://127.0.0.1:" + apiPort

    property bool statePending: false
    property bool runningPending: false

    function api(method, path, body, callback, operation) {
        const xhr = new XMLHttpRequest()
        let finished = false
        const timer = requestTimer.createObject(root)
        function finish(error, payload) {
            if (finished)
                return
            finished = true
            timer.stop()
            timer.destroy()
            if (path === "/api/state") root.statePending = false
            if (path === "/api/running") root.runningPending = false
            if (operation) {
                root.busy = false
                root.errorText = error || ""
            } else {
                root.pollErrorText = error || ""
            }
            if (!error && callback) callback(payload)
        }
        timer.interval = operation ? 780000 : 12000
        timer.triggered.connect(function() {
            finish(operation ? "Ответ операции не получен. Проверь vpn status перед повторным переключением." : "Опрос состояния не завершился", null)
            xhr.abort()
        })
        xhr.open(method, apiBase + path, true)
        xhr.setRequestHeader("X-Evgenium-Token", apiToken)
        if (body !== null)
            xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8")
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE || finished)
                return
            let payload = null
            try { payload = JSON.parse(String(xhr.responseText || "{}")) }
            catch (e) { finish("Не удалось разобрать ответ локального API", null); return }
            if (xhr.status < 200 || xhr.status >= 300 || !payload.ok) {
                finish(String(payload.error || ("HTTP " + xhr.status)), null)
                return
            }
            finish(null, payload)
        }
        timer.start()
        xhr.send(body === null ? null : JSON.stringify(body))
    }

    Component {
        id: requestTimer
        Timer { repeat: false }
    }

    function refreshState() {
        if (statePending) return
        statePending = true
        api("GET", "/api/state", null, function(payload) {
            root.state = payload.state || ({})
        })
    }

    function refreshRunning() {
        if (runningPending) return
        runningPending = true
        api("GET", "/api/running", null, function(payload) {
            root.runningApps = (payload.running && payload.running.applications) || []
        })
    }

    function action(payload, onSuccess) {
        if (busy || (Boolean(state.connecting) && payload.action !== "disconnect"))
            return
        busy = true
        api("POST", "/api/action", payload, function(_reply) {
            root.busy = false
            if (_reply.state) root.state = _reply.state
            if (onSuccess) onSuccess(_reply)
            root.refreshState()
            root.refreshRunning()
        }, true)
    }

    function toggleVpn() {
        if (busy || Boolean(state.connecting))
            return
        busy = true
        api("POST", "/api/toggle", {}, function(payload) {
            root.busy = false
            root.state = payload.state || ({})
        }, true)
    }

    function filteredRunning() {
        const needle = appSearch.text.trim().toLowerCase()
        if (!needle.length)
            return runningApps
        return runningApps.filter(function(app) {
            return String(app.name || "").toLowerCase().includes(needle)
                || String(app.exe || "").toLowerCase().includes(needle)
        })
    }

    Component.onCompleted: {
        refreshState()
        refreshRunning()
    }

    Timer {
        interval: 2500
        repeat: true
        running: true
        onTriggered: root.refreshState()
    }

    C.Dialog {
        id: supportDialog
        title: "Отчёт для поддержки"
        modal: true
        anchors.centerIn: parent
        width: Math.min(root.width-60,760)
        height: Math.min(root.height-50,620)
        ColumnLayout {
            anchors.fill: parent
            spacing: 12
            C.Label { Layout.fillWidth: true; wrapMode: Text.Wrap; text: "Версия, этапы подключения, ошибки и замеры. Без токенов, ключей, истории сайтов и списка приложений. Отправка добровольная; сервер хранит отчёт до 7 дней." }
            C.ScrollView { Layout.fillWidth: true; Layout.fillHeight: true
                C.TextArea { text: root.reportText; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; font.family: "monospace"; font.pixelSize: 11 }
            }
            C.CheckBox { id: reportConsent; text: "Разрешаю отправить показанный отчёт владельцу VPN" }
            RowLayout {
                FlatButton { label: "Отправить"; primary: true; enabledButton: reportConsent.checked && !root.busy; onClicked: root.action({action:"report-send",report_id:root.reportId,consent:true},function(){supportDialog.close();root.errorText="Отчёт отправлен. ID: "+root.reportId}) }
                FlatButton { label: "Закрыть"; onClicked: supportDialog.close() }
            }
            C.Label { visible: !root.state.active; Layout.fillWidth: true; wrapMode: Text.Wrap; text: "Если защита блокирует сеть, отчёт останется локально до восстановления или явного отключения VPN."; color: root.textMuted }
        }
    }

    component FlatButton: Rectangle {
        id: flatButton
        required property string label
        property bool primary: false
        property bool danger: false
        property bool enabledButton: true
        signal clicked()
        implicitHeight: 42
        implicitWidth: Math.max(92, buttonText.implicitWidth + 28)
        radius: 5
        color: !enabledButton ? "#2c242f"
              : danger ? (buttonMouse.containsMouse ? "#5b2939" : "#3a202d")
              : primary ? (buttonMouse.containsMouse ? "#ff7b89" : root.accent)
              : (buttonMouse.containsMouse ? "#382432" : "#29202b")
        border.width: primary ? 0 : 1
        border.color: danger ? "#875568" : root.border
        opacity: enabledButton ? 1 : 0.45
        activeFocusOnTab: enabledButton
        Accessible.role: Accessible.Button
        Accessible.name: label
        Accessible.onPressAction: if (enabledButton) clicked()
        Keys.onReturnPressed: if (enabledButton) clicked()
        Keys.onSpacePressed: if (enabledButton) clicked()
        Rectangle { anchors.fill: parent; anchors.margins: -3; radius: 7; color: "transparent"; border.color: root.accent; visible: flatButton.activeFocus }

        C.Label {
            id: buttonText
            anchors.centerIn: parent
            text: flatButton.label
            color: !flatButton.enabledButton ? root.textMuted : flatButton.primary ? "#180d13" : (flatButton.danger ? root.bad : root.textMain)
            font.pixelSize: 13
            font.weight: Font.DemiBold
        }
        MouseArea {
            id: buttonMouse
            anchors.fill: parent
            enabled: flatButton.enabledButton
            hoverEnabled: true
            cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: flatButton.clicked()
        }
    }

    component NavButton: Rectangle {
        id: nav
        required property string label
        required property int index
        property string shortLabel: ""
        signal clicked()
        Layout.fillWidth: true
        implicitWidth: 186
        height: 48
        radius: 4
        color: root.pageIndex === index ? "#3a202d" : (navMouse.containsMouse ? root.sidebarHover : "transparent")

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12
            spacing: 11
            Rectangle {
                implicitWidth: 28
                implicitHeight: 28
                radius: 3
                color: root.pageIndex === nav.index ? root.accent : "#302330"
                C.Label {
                    anchors.centerIn: parent
                    text: nav.shortLabel
                    color: "white"
                    font.pixelSize: 10
                    font.weight: Font.Bold
                }
            }
            C.Label {
                Layout.fillWidth: true
                text: nav.label
                color: root.pageIndex === nav.index ? "white" : "#baa8af"
                font.pixelSize: 14
                font.weight: root.pageIndex === nav.index ? Font.DemiBold : Font.Normal
            }
        }
        MouseArea {
            id: navMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                root.pageIndex = nav.index
                nav.clicked()
            }
        }
    }

    component RibbonSwitch: C.Switch {
        id: control
        indicator: Rectangle {
            x: control.leftPadding; y: (control.height - height) / 2
            implicitWidth: 44; implicitHeight: 24; radius: 12
            color: control.checked ? root.accent : "#48303c"
            border.color: control.activeFocus ? root.textMain : root.border
            Rectangle {
                width: 18; height: 18; radius: 9; y: 3
                x: control.checked ? parent.width - width - 3 : 3
                color: control.checked ? "#180d13" : root.textMain
            }
        }
        contentItem: C.Label {
            text: control.text; color: root.textMain
            leftPadding: control.indicator.width + control.spacing
            verticalAlignment: Text.AlignVCenter
        }
    }

    component RibbonMark: Canvas {
        onPaint: {
            const ctx = getContext("2d")
            ctx.reset(); ctx.scale(width / 110, height / 120)
            for (let side = 0; side < 2; side++) {
                ctx.save()
                if (side) { ctx.translate(110, 0); ctx.scale(-1, 1) }
ctx.beginPath();
ctx.moveTo(10, 6);
ctx.bezierCurveTo(-4, 17, 1, 29, 12, 38);
ctx.bezierCurveTo(4, 52, 13, 63, 22, 70);
ctx.bezierCurveTo(17, 82, 28, 98, 34, 112);
ctx.bezierCurveTo(37, 95, 44, 82, 37, 68);
ctx.bezierCurveTo(48, 55, 49, 46, 41, 36);
ctx.bezierCurveTo(58, 13, 40, -4, 10, 6);
ctx.closePath();
ctx.fillStyle = "#702a40"; ctx.fill();
ctx.beginPath();
ctx.moveTo(44, 7);
ctx.bezierCurveTo(10, -4, -8, 12, 8, 27);
ctx.bezierCurveTo(15, 34, 32, 38, 41, 43);
ctx.lineTo(46, 31);
ctx.bezierCurveTo(33, 24, 13, 22, 12, 15);
ctx.bezierCurveTo(18, 9, 31, 8, 44, 7);
ctx.closePath();
ctx.fillStyle = root.accent; ctx.fill();
ctx.beginPath();
ctx.moveTo(5, 26);
ctx.bezierCurveTo(-3, 44, 13, 53, 34, 59);
ctx.bezierCurveTo(38, 61, 40, 64, 41, 67);
ctx.lineTo(45, 53);
ctx.bezierCurveTo(31, 44, 10, 42, 11, 34);
ctx.closePath();
ctx.fillStyle = root.accent; ctx.fill();
ctx.beginPath();
ctx.moveTo(12, 51);
ctx.bezierCurveTo(8, 67, 21, 77, 33, 80);
ctx.lineTo(38, 90);
ctx.lineTo(41, 75);
ctx.bezierCurveTo(30, 66, 19, 63, 18, 58);
ctx.closePath();
ctx.fillStyle = root.accent; ctx.fill();
ctx.beginPath();
ctx.moveTo(22, 76);
ctx.bezierCurveTo(20, 89, 31, 101, 34, 112);
ctx.lineTo(39, 93);
ctx.bezierCurveTo(31, 88, 29, 83, 29, 81);
ctx.closePath();
ctx.fillStyle = root.accent; ctx.fill();
ctx.beginPath();
ctx.moveTo(39, 8);
ctx.bezierCurveTo(21, 3, 4, 11, 8, 20);
ctx.moveTo(7, 34);
ctx.bezierCurveTo(7, 43, 23, 48, 34, 52);
ctx.moveTo(16, 60);
ctx.bezierCurveTo(17, 67, 27, 71, 33, 73);
ctx.strokeStyle = "#ffacb8"; ctx.lineWidth = 1.2; ctx.stroke();
ctx.restore()
}
}
}

    component Card: Rectangle {
        radius: 7
        color: root.surface
        border.width: 1
        border.color: root.border
    }

    // Native system operations preserve snapping, compositor scaling and resize limits.
    Rectangle {
        id: titleBar
        objectName: "windowTitleBar"
        anchors { left: parent.left; right: parent.right; top: parent.top }
        height: 38
        color: root.sidebar
        MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton
            onPressed: function(mouse) { root.startSystemMove() }
            onDoubleClicked: function(mouse) { mouse.accepted = true }
        }
        C.Label {
            anchors { left: parent.left; leftMargin: 18; verticalCenter: parent.verticalCenter }
            text: "EVGENIUM NETWORK"
            color: root.textMuted
            font.pixelSize: 10
            font.letterSpacing: 1.6
        }
        Row {
            anchors { right: parent.right; rightMargin: 7; top: parent.top; bottom: parent.bottom }
            C.ToolButton {
                id: minimizeWindow
                objectName: "minimizeWindow"
                width: 44; height: titleBar.height
                Accessible.name: "Свернуть"
                hoverEnabled: true
                onClicked: root.showMinimized()
                background: Rectangle { color: minimizeWindow.hovered ? root.sidebarHover : "transparent" }
                contentItem: Item {
                    Rectangle { anchors.centerIn: parent; width: 12; height: 1; color: root.textMain }
                }
                C.ToolTip.visible: hovered
                C.ToolTip.text: "Свернуть"
            }
            C.ToolButton {
                id: closeWindow
                objectName: "closeWindow"
                width: 44; height: titleBar.height
                Accessible.name: "Закрыть"
                hoverEnabled: true
                onClicked: root.close()
                background: Rectangle { color: closeWindow.hovered ? root.accentSoft : "transparent" }
                contentItem: Item {
                    Rectangle { anchors.centerIn: parent; width: 14; height: 1; rotation: 45; color: closeWindow.hovered ? root.accent : root.textMain }
                    Rectangle { anchors.centerIn: parent; width: 14; height: 1; rotation: -45; color: closeWindow.hovered ? root.accent : root.textMain }
                }
                C.ToolTip.visible: hovered
                C.ToolTip.text: "Закрыть"
            }
        }
        Rectangle { anchors { left: parent.left; right: parent.right; bottom: parent.bottom } height: 1; color: root.border }
    }

    // Separate corner zones keep resizing usable without covering caption buttons.
    component ResizeZone: MouseArea {
        required property int edges
        z: 100
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) { root.startSystemResize(edges) }
    }
    ResizeZone { objectName: "resizeTopLeft"; anchors { top: parent.top; left: parent.left } width: 10; height: 10; edges: Qt.TopEdge | Qt.LeftEdge; cursorShape: Qt.SizeFDiagCursor }
    ResizeZone { objectName: "resizeTopRight"; anchors { top: parent.top; right: parent.right } width: 10; height: 10; edges: Qt.TopEdge | Qt.RightEdge; cursorShape: Qt.SizeBDiagCursor }
    ResizeZone { objectName: "resizeBottomLeft"; anchors { bottom: parent.bottom; left: parent.left } width: 10; height: 10; edges: Qt.BottomEdge | Qt.LeftEdge; cursorShape: Qt.SizeBDiagCursor }
    ResizeZone { objectName: "resizeBottomRight"; anchors { bottom: parent.bottom; right: parent.right } width: 10; height: 10; edges: Qt.BottomEdge | Qt.RightEdge; cursorShape: Qt.SizeFDiagCursor }
    ResizeZone { anchors { top: parent.top; left: parent.left; right: parent.right; leftMargin: 10; rightMargin: 10 } height: 5; edges: Qt.TopEdge; cursorShape: Qt.SizeVerCursor }
    ResizeZone { anchors { bottom: parent.bottom; left: parent.left; right: parent.right; leftMargin: 10; rightMargin: 10 } height: 5; edges: Qt.BottomEdge; cursorShape: Qt.SizeVerCursor }
    ResizeZone { anchors { top: parent.top; bottom: parent.bottom; left: parent.left; topMargin: 10; bottomMargin: 10 } width: 5; edges: Qt.LeftEdge; cursorShape: Qt.SizeHorCursor }
    ResizeZone { anchors { top: parent.top; bottom: parent.bottom; right: parent.right; topMargin: 10; bottomMargin: 10 } width: 5; edges: Qt.RightEdge; cursorShape: Qt.SizeHorCursor }
    Rectangle { anchors.fill: parent; color: "transparent"; border.color: root.border; z: 99 }

    RowLayout {
        anchors.fill: parent
        anchors.topMargin: titleBar.height
        anchors.margins: 1
        spacing: 0
        Rectangle {
            Layout.preferredWidth: 222
            Layout.fillHeight: true
            color: root.sidebar
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 18
                spacing: 8
                RibbonMark { Layout.preferredWidth: 42; Layout.preferredHeight: 50; Layout.topMargin: 8 }
                C.Label { text: "EVGENIUM"; color: root.textMain; font.pixelSize: 21; font.bold: true; font.letterSpacing: 1.5; Layout.topMargin: 8 }
                C.Label { text: "N E T W O R K"; color: root.textMuted; font.pixelSize: 10; Layout.bottomMargin: 28 }
                NavButton { label: "VPN"; shortLabel: "VPN"; index: 0 }
                NavButton { label: "Приложения"; shortLabel: "APP"; index: 1; onClicked: root.refreshRunning() }
                NavButton { label: "Сайты и IP"; shortLabel: "NET"; index: 2 }
                NavButton { label: "Порты"; shortLabel: "PRT"; index: 3 }
                NavButton { label: "DNS"; shortLabel: "DNS"; index: 4 }
                NavButton { label: "Waydroid"; shortLabel: "WAY"; index: 5 }
                Item { Layout.fillHeight: true }
                C.Label { text: root.state.active ? "● Подключено" : (root.state.guard ? "● Защита включена" : "○ Отключено"); color: root.state.active ? "#a6d8c2" : "#baa8af" }
                C.Label { text: "Версия " + (root.state.manager_version || "…"); color: "#ad929e"; font.pixelSize: 12 }
            }
        }
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: 28
            spacing: 16
            C.Label { text: "EVGENIUM  /  " + (root.pageIndex === 0 ? "ПОДКЛЮЧЕНИЕ" : "ИСКЛЮЧЕНИЯ"); color: root.accent; font.pixelSize: 10; font.letterSpacing: 1.4 }
            C.Label { text: ["Ваш VPN", "Исключения приложений", "Сайты и IP", "Исключения портов", "DNS", "Waydroid"][root.pageIndex]; color: root.textMain; font.pixelSize: 27; font.bold: true }
            C.Label {
                Layout.fillWidth: true
                visible: Boolean(root.errorText || root.pollErrorText)
                text: root.errorText || root.pollErrorText
                color: root.bad
                wrapMode: Text.Wrap
            }
            C.BusyIndicator { running: root.busy; visible: running; Layout.preferredHeight: 28 }
            C.ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentWidth: availableWidth
                ColumnLayout {
                    width: parent.width
                    spacing: 18
                    ColumnLayout {
                        visible: root.pageIndex === 0
                        Layout.fillWidth: true
                        spacing: 18
                        Card {
                            visible: root.tokenSaved
                            Layout.fillWidth: true
                            implicitHeight: deviceBody.implicitHeight + 32
                            ColumnLayout {
                                id: deviceBody
                                anchors.fill: parent; anchors.margins: 16
                                RowLayout {
                                    Layout.fillWidth: true
                                    C.Label { visible: !root.deviceEditing; text: root.tunnel.device_name || "Получаю имя устройства…"; font.pixelSize: 18; font.bold: true; color: root.textMain; Layout.fillWidth: true; elide: Text.ElideRight }
                                    C.TextField { id: deviceNameInput; visible: root.deviceEditing; Layout.fillWidth: true; maximumLength: 64; placeholderText: "Имя устройства"; selectByMouse: true }
                                    FlatButton { label: root.deviceEditing ? "Сохранить" : "Изменить имя"; enabledButton: !root.busy && !root.state.connecting && (!root.deviceEditing || deviceNameInput.text.trim().length > 0); onClicked: {
                                        if (!root.deviceEditing) { deviceNameInput.text=root.tunnel.device_name || ""; root.deviceEditing=true; deviceNameInput.forceActiveFocus() }
                                        else root.action({action:"device-name",name:deviceNameInput.text.trim()},function(){root.deviceEditing=false})
                                    } }
                                    FlatButton { visible: root.deviceEditing; label: "Отмена"; onClicked: root.deviceEditing=false }
                                }
                                C.Label { text: root.tunnel.device_name_pending ? "Имя сохранено на компьютере и будет отправлено при подключении." : "Это имя видно в веб-панели среди ваших подключений."; Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted }
                            }
                        }
                        Card {
                            Layout.fillWidth: true
                            implicitHeight: Math.max(240, connectionBody.implicitHeight + 48)
                            Rectangle { anchors.left: parent.left; anchors.top: parent.top; anchors.leftMargin: 20; width: 44; height: 3; color: root.accent }
                            RibbonMark { anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; anchors.rightMargin: 20; width: 105; height: 150; opacity: 0.8 }
                            ColumnLayout {
                                id: connectionBody
                                anchors.fill: parent
                                anchors.margins: 24
                                anchors.rightMargin: 145
                                spacing: 15
                                C.Label { text: root.state.active ? "Подключено через Эстонию" : (root.tunnel.running ? "Подключение…" : "Готов к подключению"); color: root.state.active ? root.good : root.textMain; font.pixelSize: 23; font.bold: true; Layout.fillWidth: true; wrapMode: Text.Wrap }
                                C.Label { text: root.tunnel.message || "Введите токен клиента"; Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted }
                                C.ProgressBar { Layout.fillWidth: true; visible: Boolean(root.tunnel.running) && !root.state.active; from: 0; to: 100; value: Number(root.tunnel.progress || 0) }
                                RowLayout {
                                    FlatButton { label: root.tunnel.running || root.state.guard ? "Отключить" : "Подключить"; primary: true; enabledButton: !root.busy && (root.tokenSaved || root.state.guard); onClicked: root.action({action: root.tunnel.running || root.state.guard ? "disconnect" : "connect"}) }
                                    FlatButton { label: "Восстановить"; enabledButton: !root.busy && !root.state.connecting && root.tokenSaved; onClicked: root.action({action: "repair"}) }
                                }
                                C.Label { text: "Весь трафик идёт через VPN, кроме включённых исключений. При обрыве защищённые подключения блокируются."; Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted }
                            }
                        }
                        Card {
                            Layout.fillWidth: true
                            implicitHeight: tokenBody.implicitHeight + 40
                            ColumnLayout {
                                id: tokenBody
                                anchors.fill: parent
                                anchors.margins: 20
                                spacing: 12
                                C.Label { text: "Токен клиента"; font.pixelSize: 17; font.bold: true; color: root.textMain }
                                C.Label { visible: root.tokenLocked; text: root.tunnel.token_hint || "Токен сохранён"; color: root.textMuted }
                                RowLayout {
                                    Layout.fillWidth: true
                                    C.TextField { id: tokenInput; visible: !root.tokenLocked; Layout.fillWidth: true; placeholderText: "EVN1-…"; echoMode: TextInput.Password; selectByMouse: true; enabled: !root.busy && !root.tunnel.running }
                                    FlatButton { label: root.tokenLocked ? "Изменить" : "Подтвердить"; enabledButton: !root.busy && !root.tunnel.running && (root.tokenLocked || /^EVN1-[A-Za-z0-9_-]{43}$/.test(tokenInput.text.trim())); onClicked: {
                                        if (root.tokenLocked) root.tokenEditing = true
                                        else root.action({action: "token-save", token: tokenInput.text.trim()}, function() { tokenInput.clear(); root.tokenEditing = false })
                                    } }
                                    FlatButton { visible: root.tokenEditing; label: "Отмена"; onClicked: { tokenInput.clear(); root.tokenEditing = false } }
                                }
                                C.Label { text: "Один токен на человека — для всех его устройств."; color: root.textMuted }
                            }
                        }
                        FlatButton { label: "Отчёт для поддержки"; enabledButton: !root.busy && !root.state.connecting; onClicked: root.action({action:"report-preview"},function(reply){
                            var report=JSON.parse(reply.output);root.reportId=report.report_id;root.reportText=JSON.stringify(report,null,2);reportConsent.checked=false;supportDialog.open()
                        }) }
                        FlatButton { label: "Проверить обновления"; enabledButton: !root.busy; onClicked: root.action({action: "update"}) }
                    }
                    ColumnLayout {
                        visible: root.pageIndex >= 1 && root.pageIndex <= 4
                        Layout.fillWidth: true
                        spacing: 16
                        C.Label {
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                            color: root.textMuted
                            text: root.pageIndex === 1 ? "Выбранные приложения подключаются напрямую. Остальные используют VPN." : root.pageIndex === 2 ? "Добавьте домен, адрес или подсеть. Домены включают поддомены; знак = задаёт точное совпадение. При общем IP лучше указывать домен." : root.pageIndex === 3 ? "Исходящие — подключения к указанному порту. Входящие — прямые ответы вашего сервера. Оба — оба направления." : "Обычный DNS остаётся в VPN. Добавленные здесь DNS-серверы получают запросы напрямую и могут видеть запрашиваемые имена. Это не список сайтов."
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            C.ComboBox { id: portProtocol; visible: root.pageIndex === 3; model: ["TCP", "UDP", "BOTH"]; Layout.preferredWidth: 100 }
                            C.TextField { id: exceptionInput; Layout.fillWidth: true; selectByMouse: true; placeholderText: root.pageIndex === 1 ? "Имя процесса или /полный/путь" : root.pageIndex === 2 ? "example.com или 192.168.1.20" : root.pageIndex === 3 ? "25565" : "Адрес DNS, например 192.168.1.1" }
                            C.ComboBox { id: portDirection; visible: root.pageIndex === 3; model: ["Исходящие", "Входящие", "Оба"]; Layout.preferredWidth: 140 }
                            FlatButton { label: "Добавить"; primary: true; enabledButton: !root.busy && exceptionInput.text.trim().length > 0; onClicked: {
                                const value = root.pageIndex === 3 ? portProtocol.currentText.toLowerCase() + ":" + exceptionInput.text.trim() + ":" + ["out", "in", "both"][portDirection.currentIndex] : exceptionInput.text.trim()
                                root.action({action: "add", category: root.category, value: value}, function() { exceptionInput.clear() })
                            } }
                        }
                        Repeater {
                            model: root.policy[root.category] || []
                            delegate: RowLayout {
                                required property string modelData
                                Layout.fillWidth: true
                                C.Label { text: modelData; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: root.textMain }
                                FlatButton { label: "Удалить"; danger: true; enabledButton: !root.busy; onClicked: root.action({action: "remove", category: root.category, value: modelData}) }
                            }
                        }
                        C.Label { visible: !(root.policy[root.category] || []).length; text: "Ваших исключений пока нет"; color: root.textMuted }
                        RibbonSwitch { text: "Отобразить базовые исключения"; checked: root.showBase; onToggled: root.showBase = checked }
                        ColumnLayout {
                            Layout.fillWidth: true
                            visible: root.showBase
                            Repeater {
                                model: (root.policy.base || {})[root.category] || []
                                delegate: RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    C.Label { text: modelData.label; Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMain }
                                    RibbonSwitch { checked: Boolean(modelData.enabled); enabled: !root.busy; onToggled: root.action({action: "base", category: root.category, value: modelData.id, enabled: checked}) }
                                }
                            }
                            C.Label { Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted; text: "Вы можете выключить любое базовое правило. Скрытие списка не меняет его состояние." }
                        }
                        ColumnLayout {
                            visible: root.pageIndex === 1
                            Layout.fillWidth: true
                            C.Label { text: "Запущены сейчас"; font.pixelSize: 18; font.bold: true; color: root.textMain }
                            RowLayout {
                                Layout.fillWidth: true
                                C.TextField { id: appSearch; Layout.fillWidth: true; placeholderText: "Поиск приложения" }
                                FlatButton { label: "Обновить список"; enabledButton: !root.runningPending; onClicked: root.refreshRunning() }
                            }
                            Repeater {
                                model: root.pageIndex === 1 ? root.filteredRunning() : []
                                delegate: RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        C.Label { text: modelData.name; color: root.textMain }
                                        C.Label { text: modelData.exe; Layout.fillWidth: true; elide: Text.ElideMiddle; color: root.textMuted; font.pixelSize: 11 }
                                    }
                                    FlatButton { label: modelData.excluded ? "Добавлено" : "В обход"; enabledButton: !root.busy && !modelData.excluded; onClicked: root.action({action: "add", category: "applications", value: String(modelData.exe || modelData.name || "")}) }
                                }
                            }
                        }
                    }
                    ColumnLayout {
                        visible: root.pageIndex === 5
                        Layout.fillWidth: true
                        spacing: 18
                        C.Label { Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted; text: "Waydroid управляется отдельно от приложений компьютера. По умолчанию весь его трафик, включая DNS, идёт напрямую." }
                        RibbonSwitch { text: "Waydroid в обход VPN"; checked: root.policy.waydroid_direct !== false; enabled: !root.busy; onToggled: root.action({action: "waydroid", enabled: checked}) }
                        C.Label { Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted; text: root.policy.waydroid_direct !== false ? "Прямое подключение: Waydroid использует адрес вашего провайдера. Общие исключения не ограничивают этот режим." : "Waydroid использует VPN. При обрыве туннеля его внешние подключения блокируются." }
                    }
                }
            }
        }
    }
}
