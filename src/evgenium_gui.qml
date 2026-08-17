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
    property var state: ({})
    property var runningApps: []

    readonly property var args: Qt.application.arguments
    readonly property string apiToken: args.length >= 2 ? String(args[args.length - 1]) : ""
    readonly property string apiPort: args.length >= 3 ? String(args[args.length - 2]) : "0"
    readonly property string apiBase: "http://127.0.0.1:" + apiPort

    function parseReply(xhr, callback) {
        let payload = null
        try {
            payload = JSON.parse(String(xhr.responseText || "{}"))
        } catch (e) {
            errorText = "Не удалось разобрать ответ локального API"
            busy = false
            return
        }
        if (xhr.status < 200 || xhr.status >= 300 || !payload.ok) {
            errorText = String(payload.error || ("HTTP " + xhr.status))
            busy = false
            return
        }
        errorText = ""
        if (callback)
            callback(payload)
    }

    function api(method, path, body, callback) {
        const xhr = new XMLHttpRequest()
        xhr.open(method, apiBase + path, true)
        xhr.setRequestHeader("X-Evgenium-Token", apiToken)
        if (body !== null)
            xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8")
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE)
                root.parseReply(xhr, callback)
        }
        xhr.send(body === null ? null : JSON.stringify(body))
    }

    function refreshState() {
        api("GET", "/api/state", null, function(payload) {
            root.state = payload.state || ({})
        })
    }

    function refreshRunning() {
        api("GET", "/api/running", null, function(payload) {
            root.runningApps = (payload.running && payload.running.applications) || []
        })
    }

    function action(payload) {
        if (busy)
            return
        busy = true
        api("POST", "/api/action", payload, function(_reply) {
            root.busy = false
            root.refreshState()
            root.refreshRunning()
        })
    }

    function toggleVpn() {
        if (busy)
            return
        busy = true
        api("POST", "/api/toggle", {}, function(payload) {
            root.busy = false
            root.state = payload.state || ({})
        })
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
                width: 28
                height: 28
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
                spacing: 7

                RowLayout {
                    Layout.fillWidth: true
                    Layout.bottomMargin: 24
                    spacing: 11
                    Rectangle {
                        width: 40
                        height: 40
                        radius: 12
                        color: root.accent
                        C.Label {
                            anchors.centerIn: parent
                            text: "E"
                            color: "white"
                            font.pixelSize: 20
                            font.weight: Font.Black
                        }
                    }
                    ColumnLayout {
                        spacing: 0
                        C.Label {
                            text: "Evgenium"
                            color: "white"
                            font.pixelSize: 16
                            font.weight: Font.Bold
                        }
                        C.Label {
                            text: "Network"
                            color: "#94a3b8"
                            font.pixelSize: 12
                        }
                    }
                }

                NavButton { label: "VPN"; shortLabel: "VPN"; index: 0 }
                NavButton { label: "Профили VPN"; shortLabel: "PRF"; index: 1 }
                NavButton {
                    label: "Приложения"; shortLabel: "APP"; index: 2
                    onClicked: root.refreshRunning()
                }
                NavButton { label: "Сайты и IP"; shortLabel: "NET"; index: 3 }
                NavButton { label: "Порты"; shortLabel: "PRT"; index: 4 }
                NavButton { label: "Диагностика"; shortLabel: "SYS"; index: 5 }

                Item { Layout.fillHeight: true }

                Rectangle {
                    Layout.fillWidth: true
                    height: 64
                    radius: 12
                    color: "#172033"
                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: 12
                        Rectangle {
                            width: 10
                            height: 10
                            radius: 5
                            color: Boolean(root.state.active) ? root.good : "#64748b"
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 1
                            C.Label {
                                text: Boolean(root.state.active) ? "VPN включён" : "VPN выключен"
                                color: "white"
                                font.pixelSize: 12
                                font.weight: Font.DemiBold
                            }
                            C.Label {
                                Layout.fillWidth: true
                                text: String(root.state.profile || root.state.last_profile || "Нет профиля")
                                color: "#94a3b8"
                                font.pixelSize: 11
                                elide: Text.ElideRight
                            }
                        }
                    }
                }
            }
        }

        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 28
                spacing: 18

                RowLayout {
                    Layout.fillWidth: true
                    C.Label {
                        Layout.fillWidth: true
                        text: ["VPN", "Профили VPN", "Приложения без VPN", "Сайты и IP без VPN", "Входящие порты", "Диагностика"][root.pageIndex]
                        color: root.textMain
                        font.pixelSize: 25
                        font.weight: Font.Bold
                    }
                    C.BusyIndicator {
                        running: root.busy
                        visible: running
                        implicitWidth: 28
                        implicitHeight: 28
                    }
                    FlatButton {
                        label: "Обновить"
                        enabledButton: !root.busy
                        onClicked: {
                            root.refreshState()
                            if (root.pageIndex === 2)
                                root.refreshRunning()
                        }
                    }
                }

                Rectangle {
                    visible: root.errorText.length > 0
                    Layout.fillWidth: true
                    implicitHeight: errorLabel.implicitHeight + 22
                    radius: 10
                    color: "#fff1f2"
                    border.width: 1
                    border.color: "#fecdd3"
                    C.Label {
                        id: errorLabel
                        anchors.fill: parent
                        anchors.margins: 11
                        text: root.errorText
                        color: root.bad
                        wrapMode: Text.WordWrap
                        font.pixelSize: 12
                    }
                }

                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: root.pageIndex

                    // VPN
                    Item {
                        Card {
                            anchors.fill: parent
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 28
                                spacing: 20

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 18
                                    Rectangle {
                                        width: 72
                                        height: 72
                                        radius: 22
                                        color: Boolean(root.state.active) ? root.accentSoft : "#eef2f7"
                                        C.Label {
                                            anchors.centerIn: parent
                                            text: Boolean(root.state.active) ? "ON" : "OFF"
                                            color: Boolean(root.state.active) ? root.accent : root.textMuted
                                            font.pixelSize: 18
                                            font.weight: Font.Bold
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 5
                                        C.Label {
                                            text: Boolean(root.state.active) ? "Защищённое соединение активно" : "VPN сейчас выключен"
                                            color: root.textMain
                                            font.pixelSize: 20
                                            font.weight: Font.Bold
                                        }
                                        C.Label {
                                            Layout.fillWidth: true
                                            text: Boolean(root.state.active)
                                                ? "Весь обычный трафик идёт через VPN, кроме настроенных исключений."
                                                : "Включи VPN одним нажатием. Будет использован последний выбранный профиль."
                                            color: root.textMuted
                                            wrapMode: Text.WordWrap
                                            font.pixelSize: 13
                                        }
                                    }
                                    FlatButton {
                                        label: Boolean(root.state.active) ? "Выключить VPN" : "Включить VPN"
                                        primary: !Boolean(root.state.active)
                                        danger: Boolean(root.state.active)
                                        enabledButton: !root.busy
                                        onClicked: root.toggleVpn()
                                    }
                                }

                                Rectangle { Layout.fillWidth: true; height: 1; color: root.border }

                                GridLayout {
                                    Layout.fillWidth: true
                                    columns: 2
                                    columnSpacing: 24
                                    rowSpacing: 14

                                    C.Label { text: "Профиль"; color: root.textMuted }
                                    C.Label {
                                        text: String(root.state.profile || root.state.last_profile || "—")
                                        color: root.textMain
                                        font.weight: Font.DemiBold
                                    }
                                    C.Label { text: "IPv6"; color: root.textMuted }
                                    C.Label {
                                        text: String(root.state.ipv6_mode || "unknown")
                                        color: root.textMain
                                        font.weight: Font.DemiBold
                                    }
                                    C.Label { text: "Kill switch"; color: root.textMuted }
                                    C.Label {
                                        text: Boolean(root.state.kill_switch) ? "Активен" : "Выключен"
                                        color: Boolean(root.state.kill_switch) ? root.good : root.textMuted
                                        font.weight: Font.DemiBold
                                    }
                                    C.Label { text: "Версия manager"; color: root.textMuted }
                                    C.Label {
                                        text: String(root.state.manager || "—")
                                        color: root.textMain
                                        font.weight: Font.DemiBold
                                    }
                                }

                                Item { Layout.fillHeight: true }
                            }
                        }
                    }


                    // VPN profiles
                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 14

                            Card {
                                Layout.fillWidth: true
                                height: 78
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 16
                                    spacing: 12
                                    Rectangle {
                                        width: 42
                                        height: 42
                                        radius: 12
                                        color: root.accentSoft
                                        C.Label {
                                            anchors.centerIn: parent
                                            text: "PRF"
                                            color: root.accent
                                            font.pixelSize: 11
                                            font.weight: Font.Bold
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2
                                        C.Label {
                                            text: "VPN-профили"
                                            color: root.textMain
                                            font.pixelSize: 16
                                            font.weight: Font.Bold
                                        }
                                        C.Label {
                                            Layout.fillWidth: true
                                            text: String(root.state.config_dir || "")
                                            color: root.textMuted
                                            font.pixelSize: 11
                                            elide: Text.ElideMiddle
                                        }
                                    }
                                    C.Label {
                                        text: String((root.state.profiles || []).length) + " шт."
                                        color: root.textMuted
                                        font.pixelSize: 12
                                    }
                                }
                            }

                            Card {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                ListView {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    clip: true
                                    spacing: 7
                                    model: root.state.profiles || []
                                    delegate: Rectangle {
                                        id: profileRow
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 66
                                        radius: 12
                                        color: Boolean(profileRow.modelData.active) ? root.accentSoft : "#f8fafc"
                                        border.width: Boolean(profileRow.modelData.active) ? 1 : 0
                                        border.color: root.accent

                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 14
                                            anchors.rightMargin: 10
                                            spacing: 12

                                            Rectangle {
                                                width: 12
                                                height: 12
                                                radius: 6
                                                color: Boolean(profileRow.modelData.active)
                                                    ? root.good
                                                    : (Boolean(profileRow.modelData.last) ? root.accent : "#cbd5e1")
                                            }

                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 2
                                                C.Label {
                                                    Layout.fillWidth: true
                                                    text: String(profileRow.modelData.stem || profileRow.modelData.name || "")
                                                    color: root.textMain
                                                    font.pixelSize: 14
                                                    font.weight: Font.DemiBold
                                                    elide: Text.ElideRight
                                                }
                                                C.Label {
                                                    Layout.fillWidth: true
                                                    text: Boolean(profileRow.modelData.active)
                                                        ? "Активный профиль"
                                                        : (Boolean(profileRow.modelData.last) ? "Последний использованный" : String(profileRow.modelData.name || ""))
                                                    color: Boolean(profileRow.modelData.active) ? root.good : root.textMuted
                                                    font.pixelSize: 11
                                                    elide: Text.ElideMiddle
                                                }
                                            }

                                            FlatButton {
                                                label: Boolean(profileRow.modelData.active) ? "Активен" : "Подключить"
                                                primary: !Boolean(profileRow.modelData.active)
                                                enabledButton: !root.busy && !Boolean(profileRow.modelData.active)
                                                onClicked: root.action({
                                                    action: "profile_activate",
                                                    target: String(profileRow.modelData.name || "")
                                                })
                                            }
                                        }
                                    }
                                    C.ScrollBar.vertical: C.ScrollBar {}
                                    C.Label {
                                        anchors.centerIn: parent
                                        visible: (root.state.profiles || []).length === 0
                                        text: "В папке VPN configs пока нет профилей"
                                        color: root.textMuted
                                    }
                                }
                            }
                        }
                    }

                    // Applications
                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 14

                            Card {
                                Layout.fillWidth: true
                                height: 82
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 16
                                    spacing: 10
                                    C.TextField {
                                        id: manualApp
                                        Layout.fillWidth: true
                                        placeholderText: "Имя процесса, /полный/путь или /папка/"
                                        selectByMouse: true
                                        background: Rectangle { radius: 10; color: "#f8fafc"; border.color: root.border }
                                        onAccepted: if (text.trim().length) root.action({action: "app_add", target: text.trim()})
                                    }
                                    FlatButton {
                                        label: "Добавить вручную"
                                        primary: true
                                        enabledButton: !root.busy && manualApp.text.trim().length > 0
                                        onClicked: {
                                            root.action({action: "app_add", target: manualApp.text.trim()})
                                            manualApp.clear()
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                C.Label { text: "Уже исключены"; color: root.textMain; font.pixelSize: 15; font.weight: Font.Bold; Layout.fillWidth: true }
                                C.Label { text: String((root.state.applications || []).length); color: root.textMuted }
                            }

                            Card {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 145
                                ListView {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    clip: true
                                    spacing: 5
                                    model: root.state.applications || []
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 46
                                        radius: 9
                                        color: "#f8fafc"
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 12
                                            anchors.rightMargin: 8
                                            C.Label { Layout.fillWidth: true; text: String(modelData); color: root.textMain; elide: Text.ElideMiddle }
                                            FlatButton {
                                                label: "Удалить"
                                                danger: true
                                                enabledButton: !root.busy
                                                onClicked: root.action({action: "app_remove", target: String(modelData)})
                                            }
                                        }
                                    }
                                    C.ScrollBar.vertical: C.ScrollBar {}
                                    C.Label {
                                        anchors.centerIn: parent
                                        visible: (root.state.applications || []).length === 0
                                        text: "Пока нет приложений-исключений"
                                        color: root.textMuted
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                C.Label { text: "Запущены сейчас"; color: root.textMain; font.pixelSize: 15; font.weight: Font.Bold; Layout.fillWidth: true }
                                FlatButton { label: "Обновить список"; enabledButton: !root.busy; onClicked: root.refreshRunning() }
                            }

                            C.TextField {
                                id: appSearch
                                Layout.fillWidth: true
                                placeholderText: "Найти запущенное приложение по имени или пути…"
                                selectByMouse: true
                                background: Rectangle { radius: 10; color: root.surface; border.color: root.border }
                            }

                            Card {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                ListView {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    clip: true
                                    spacing: 6
                                    model: root.filteredRunning()
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 64
                                        radius: 11
                                        color: "#f8fafc"
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.margins: 9
                                            spacing: 10
                                            Rectangle {
                                                width: 40; height: 40; radius: 12
                                                color: Boolean(modelData.excluded) ? "#dcfce7" : root.accentSoft
                                                C.Label {
                                                    anchors.centerIn: parent
                                                    text: String(modelData.name || "?").slice(0, 1).toUpperCase()
                                                    color: Boolean(modelData.excluded) ? root.good : root.accent
                                                    font.weight: Font.Bold
                                                    font.pixelSize: 16
                                                }
                                            }
                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 1
                                                C.Label { Layout.fillWidth: true; text: String(modelData.name || ""); color: root.textMain; font.weight: Font.DemiBold; elide: Text.ElideRight }
                                                C.Label { Layout.fillWidth: true; text: String(modelData.exe || ""); color: root.textMuted; font.pixelSize: 11; elide: Text.ElideMiddle }
                                            }
                                            C.Label {
                                                visible: Number(modelData.count || 1) > 1
                                                text: "×" + String(modelData.count)
                                                color: root.textMuted
                                            }
                                            FlatButton {
                                                label: Boolean(modelData.excluded) ? "Уже исключено" : "Исключить"
                                                primary: !Boolean(modelData.excluded)
                                                enabledButton: !root.busy && !Boolean(modelData.excluded)
                                                onClicked: root.action({action: "app_add", target: String(modelData.exe || modelData.name || "")})
                                            }
                                        }
                                    }
                                    C.ScrollBar.vertical: C.ScrollBar {}
                                }
                            }
                        }
                    }

                    // Sites/IP
                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 14
                            Card {
                                Layout.fillWidth: true
                                height: 82
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 16
                                    spacing: 10
                                    C.TextField {
                                        id: directTarget
                                        Layout.fillWidth: true
                                        placeholderText: "example.com, 203.0.113.10 или 203.0.113.0/24"
                                        selectByMouse: true
                                        background: Rectangle { radius: 10; color: "#f8fafc"; border.color: root.border }
                                        onAccepted: if (text.trim().length) root.action({action: "direct_add", target: text.trim()})
                                    }
                                    FlatButton {
                                        label: "Добавить исключение"
                                        primary: true
                                        enabledButton: !root.busy && directTarget.text.trim().length > 0
                                        onClicked: {
                                            root.action({action: "direct_add", target: directTarget.text.trim()})
                                            directTarget.clear()
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 14
                                Card {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 14
                                        C.Label { text: "Домены"; color: root.textMain; font.weight: Font.Bold; font.pixelSize: 15 }
                                        ListView {
                                            Layout.fillWidth: true
                                            Layout.fillHeight: true
                                            clip: true
                                            spacing: 5
                                            model: root.state.domains || []
                                            delegate: Rectangle {
                                                required property var modelData
                                                width: ListView.view.width
                                                height: 46
                                                radius: 9
                                                color: "#f8fafc"
                                                RowLayout {
                                                    anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 7
                                                    C.Label { Layout.fillWidth: true; text: String(modelData); color: root.textMain; elide: Text.ElideRight }
                                                    FlatButton { label: "Удалить"; danger: true; enabledButton: !root.busy; onClicked: root.action({action: "direct_remove", target: String(modelData)}) }
                                                }
                                            }
                                            C.ScrollBar.vertical: C.ScrollBar {}
                                        }
                                    }
                                }
                                Card {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 14
                                        C.Label { text: "IP и сети"; color: root.textMain; font.weight: Font.Bold; font.pixelSize: 15 }
                                        ListView {
                                            Layout.fillWidth: true
                                            Layout.fillHeight: true
                                            clip: true
                                            spacing: 5
                                            model: root.state.networks || []
                                            delegate: Rectangle {
                                                required property var modelData
                                                width: ListView.view.width
                                                height: 46
                                                radius: 9
                                                color: "#f8fafc"
                                                RowLayout {
                                                    anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 7
                                                    C.Label { Layout.fillWidth: true; text: String(modelData); color: root.textMain; elide: Text.ElideMiddle }
                                                    FlatButton { label: "Удалить"; danger: true; enabledButton: !root.busy; onClicked: root.action({action: "direct_remove", target: String(modelData)}) }
                                                }
                                            }
                                            C.ScrollBar.vertical: C.ScrollBar {}
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Ports
                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 14
                            Card {
                                Layout.fillWidth: true
                                height: 105
                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 15
                                    spacing: 8
                                    C.Label {
                                        Layout.fillWidth: true
                                        text: "Для локальных серверов: ответы на входящие подключения к этим портам идут напрямую через физическую сеть."
                                        color: root.textMuted
                                        wrapMode: Text.WordWrap
                                        font.pixelSize: 12
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        C.TextField {
                                            id: portField
                                            Layout.fillWidth: true
                                            placeholderText: "25565"
                                            inputMethodHints: Qt.ImhDigitsOnly
                                            background: Rectangle { radius: 10; color: "#f8fafc"; border.color: root.border }
                                        }
                                        C.ComboBox {
                                            id: protoBox
                                            model: ["TCP", "UDP", "BOTH"]
                                            implicitWidth: 110
                                        }
                                        FlatButton {
                                            label: "Добавить"
                                            primary: true
                                            enabledButton: !root.busy && portField.text.length > 0
                                            onClicked: {
                                                const p = Number(portField.text)
                                                if (p >= 1 && p <= 65535 && p === Math.floor(p)) {
                                                    root.action({action: "port_add", port: p, proto: protoBox.currentText.toLowerCase()})
                                                    portField.clear()
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Card {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                ListView {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    clip: true
                                    spacing: 7
                                    model: root.state.server_ports || []
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 54
                                        radius: 10
                                        color: "#f8fafc"
                                        RowLayout {
                                            anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 8
                                            Rectangle {
                                                width: 54; height: 30; radius: 8; color: root.accentSoft
                                                C.Label { anchors.centerIn: parent; text: String(modelData.proto || "").toUpperCase(); color: root.accent; font.weight: Font.Bold; font.pixelSize: 11 }
                                            }
                                            C.Label { Layout.fillWidth: true; text: String(modelData.port || ""); color: root.textMain; font.pixelSize: 16; font.weight: Font.DemiBold }
                                            FlatButton {
                                                label: "Удалить"; danger: true; enabledButton: !root.busy
                                                onClicked: root.action({action: "port_remove", port: Number(modelData.port), proto: String(modelData.proto)})
                                            }
                                        }
                                    }
                                    C.ScrollBar.vertical: C.ScrollBar {}
                                    C.Label { anchors.centerIn: parent; visible: (root.state.server_ports || []).length === 0; text: "Нет серверных портов"; color: root.textMuted }
                                }
                            }
                        }
                    }

                    // Diagnostics
                    Item {
                        Card {
                            anchors.fill: parent
                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 24
                                spacing: 14
                                C.Label { text: "Текущее состояние"; color: root.textMain; font.pixelSize: 18; font.weight: Font.Bold }
                                GridLayout {
                                    Layout.fillWidth: true
                                    columns: 2
                                    columnSpacing: 28
                                    rowSpacing: 13
                                    C.Label { text: "VPN"; color: root.textMuted }
                                    C.Label { text: Boolean(root.state.active) ? "Включён" : "Выключен"; color: Boolean(root.state.active) ? root.good : root.textMuted; font.weight: Font.DemiBold }
                                    C.Label { text: "Профиль"; color: root.textMuted }
                                    C.Label { text: String(root.state.profile || root.state.last_profile || "—"); color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "TUN"; color: root.textMuted }
                                    C.Label { text: Boolean(root.state.tun) ? "xraytun поднят" : "Нет"; color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "Kill switch"; color: root.textMuted }
                                    C.Label { text: Boolean(root.state.kill_switch) ? "Активен" : "Выключен"; color: Boolean(root.state.kill_switch) ? root.good : root.textMuted; font.weight: Font.DemiBold }
                                    C.Label { text: "IPv6"; color: root.textMuted }
                                    C.Label { text: String(root.state.ipv6_mode || "unknown"); color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "DIRECT приложения"; color: root.textMuted }
                                    C.Label { text: String(root.state.direct_applications || 0); color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "DIRECT домены"; color: root.textMuted }
                                    C.Label { text: String(root.state.direct_domains || 0); color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "DIRECT IP/сети"; color: root.textMuted }
                                    C.Label { text: String(root.state.direct_networks || 0); color: root.textMain; font.weight: Font.DemiBold }
                                    C.Label { text: "Manager"; color: root.textMuted }
                                    C.Label { text: String(root.state.manager || "—"); color: root.textMain; font.weight: Font.DemiBold }
                                }
                                Item { Layout.fillHeight: true }
                                C.Label {
                                    Layout.fillWidth: true
                                    text: "Окно настроек работает отдельно от Plasma. KDE используется только для маленького виджета на рабочем столе."
                                    color: root.textMuted
                                    wrapMode: Text.WordWrap
                                    font.pixelSize: 12
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
