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
    color: "#f4f6fa"

    readonly property color bg: "#f4f6fa"
    readonly property color surface: "#ffffff"
    readonly property color sidebar: "#111827"
    readonly property color sidebarHover: "#1f2937"
    readonly property color accent: "#39aef0"
    readonly property color accentSoft: "#e8f6fe"
    readonly property color textMain: "#111827"
    readonly property color textMuted: "#6b7280"
    readonly property color border: "#e5e7eb"
    readonly property color good: "#16a34a"
    readonly property color bad: "#dc2626"

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
            if (onSuccess) onSuccess()
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

    component FlatButton: Rectangle {
        id: flatButton
        required property string label
        property bool primary: false
        property bool danger: false
        property bool enabledButton: true
        signal clicked()
        implicitHeight: 38
        implicitWidth: Math.max(92, buttonText.implicitWidth + 28)
        radius: 10
        color: !enabledButton ? "#eef0f3"
              : danger ? (buttonMouse.containsMouse ? "#fee2e2" : "#fef2f2")
              : primary ? (buttonMouse.containsMouse ? "#2099dc" : root.accent)
              : (buttonMouse.containsMouse ? "#eef2f7" : "#f7f9fc")
        border.width: primary ? 0 : 1
        border.color: danger ? "#fecaca" : root.border
        opacity: enabledButton ? 1 : 0.6

        C.Label {
            id: buttonText
            anchors.centerIn: parent
            text: flatButton.label
            color: flatButton.primary ? "white" : (flatButton.danger ? root.bad : root.textMain)
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
        radius: 11
        color: root.pageIndex === index ? "#253246" : (navMouse.containsMouse ? root.sidebarHover : "transparent")

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12
            spacing: 11
            Rectangle {
                implicitWidth: 28
                implicitHeight: 28
                radius: 8
                color: root.pageIndex === nav.index ? root.accent : "#273449"
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
                color: root.pageIndex === nav.index ? "white" : "#cbd5e1"
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

    component Card: Rectangle {
        radius: 16
        color: root.surface
        border.width: 1
        border.color: root.border
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0
        Rectangle {
            Layout.preferredWidth: 222
            Layout.fillHeight: true
            color: root.sidebar
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 18
                spacing: 8
                C.Label { text: "Evgenium"; color: "white"; font.pixelSize: 23; font.bold: true; Layout.topMargin: 12 }
                C.Label { text: "Network"; color: "#94a3b8"; Layout.bottomMargin: 28 }
                NavButton { label: "VPN"; shortLabel: "VPN"; index: 0 }
                NavButton { label: "Приложения"; shortLabel: "APP"; index: 1; onClicked: root.refreshRunning() }
                NavButton { label: "Сайты и IP"; shortLabel: "NET"; index: 2 }
                NavButton { label: "Порты"; shortLabel: "PRT"; index: 3 }
                NavButton { label: "DNS"; shortLabel: "DNS"; index: 4 }
                NavButton { label: "Waydroid"; shortLabel: "WAY"; index: 5 }
                Item { Layout.fillHeight: true }
                C.Label { text: root.state.active ? "● Подключено" : (root.state.guard ? "● Защита включена" : "○ Отключено"); color: root.state.active ? "#4ade80" : "#cbd5e1" }
                C.Label { text: "Версия " + (root.state.manager_version || "…"); color: "#94a3b8"; font.pixelSize: 12 }
            }
        }
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: 28
            spacing: 16
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
                            implicitHeight: connectionBody.implicitHeight + 40
                            ColumnLayout {
                                id: connectionBody
                                anchors.fill: parent
                                anchors.margins: 20
                                spacing: 15
                                C.Label { text: root.state.active ? "Подключено через Эстонию" : (root.tunnel.running ? "Подключение…" : "Готов к подключению"); color: root.state.active ? root.good : root.textMain; font.pixelSize: 21; font.bold: true }
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
                        C.Switch { text: "Отобразить базовые исключения"; checked: root.showBase; onToggled: root.showBase = checked }
                        ColumnLayout {
                            Layout.fillWidth: true
                            visible: root.showBase
                            Repeater {
                                model: (root.policy.base || {})[root.category] || []
                                delegate: RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    C.Label { text: modelData.label; Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMain }
                                    C.Switch { checked: Boolean(modelData.enabled); enabled: !root.busy; onToggled: root.action({action: "base", category: root.category, value: modelData.id, enabled: checked}) }
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
                        C.Switch { text: "Waydroid в обход VPN"; checked: root.policy.waydroid_direct !== false; enabled: !root.busy; onToggled: root.action({action: "waydroid", enabled: checked}) }
                        C.Label { Layout.fillWidth: true; wrapMode: Text.Wrap; color: root.textMuted; text: root.policy.waydroid_direct !== false ? "Прямое подключение: Waydroid использует адрес вашего провайдера. Общие исключения не ограничивают этот режим." : "Waydroid использует VPN. При обрыве туннеля его внешние подключения блокируются." }
                    }
                }
            }
        }
    }
}
