import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Item {
    id: page
    implicitWidth: Kirigami.Units.gridUnit * 38
    implicitHeight: Kirigami.Units.gridUnit * 30

    property var excludedApps: []
    property var runningApps: []
    property string messageText: ""

    function filteredRunningApps() {
        const needle = searchField.text.trim().toLowerCase()
        if (needle.length === 0)
            return runningApps
        return runningApps.filter(function(app) {
            return String(app.name || "").toLowerCase().includes(needle)
                || String(app.exe || "").toLowerCase().includes(needle)
        })
    }

    function addManual() {
        const value = manualField.text.trim()
        if (value.length === 0)
            return
        backend.runAction({action: "app_add", target: value})
    }

    Component.onCompleted: {
        backend.refreshState()
        backend.refreshRunning()
    }

    VpnBackend {
        id: backend
        onStateReady: function(state) {
            page.excludedApps = state.applications || []
        }
        onRunningReady: function(applications) {
            page.runningApps = applications || []
        }
        onActionFinished: function(ok, message) {
            page.messageText = ok ? "" : message
            if (ok)
                manualField.clear()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Kirigami.Units.smallSpacing * 2

        QQC2.Label {
            text: "Приложения-исключения"
            font.bold: true
        }

        QQC2.Label {
            Layout.fillWidth: true
            text: "Эти процессы работают напрямую, минуя VPN. Изменения применяются сразу."
            wrapMode: Text.WordWrap
            opacity: 0.72
        }

        RowLayout {
            Layout.fillWidth: true

            QQC2.TextField {
                id: manualField
                Layout.fillWidth: true
                placeholderText: "Имя процесса, /полный/путь или /папка/"
                enabled: !backend.busy
                onAccepted: page.addManual()
            }

            QQC2.Button {
                text: "Добавить"
                enabled: !backend.busy && manualField.text.trim().length > 0
                onClicked: page.addManual()
            }
        }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.preferredHeight: Kirigami.Units.gridUnit * 7

            ListView {
                anchors.fill: parent
                clip: true
                model: page.excludedApps
                spacing: Kirigami.Units.smallSpacing

                delegate: RowLayout {
                    required property var modelData
                    width: ListView.view.width

                    QQC2.Label {
                        Layout.fillWidth: true
                        text: String(modelData)
                        elide: Text.ElideMiddle
                    }

                    QQC2.ToolButton {
                        icon.name: "list-remove"
                        text: "Удалить"
                        enabled: !backend.busy
                        onClicked: backend.runAction({action: "app_remove", target: String(modelData)})
                    }
                }

                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
            }
        }

        RowLayout {
            Layout.fillWidth: true

            QQC2.Label {
                text: "Запущенные приложения"
                font.bold: true
                Layout.fillWidth: true
            }

            QQC2.Button {
                text: "Обновить"
                icon.name: "view-refresh"
                enabled: !backend.busy
                onClicked: backend.refreshRunning()
            }
        }

        QQC2.TextField {
            id: searchField
            Layout.fillWidth: true
            placeholderText: "Найти запущенное приложение…"
        }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                anchors.fill: parent
                clip: true
                model: page.filteredRunningApps()
                spacing: Kirigami.Units.smallSpacing

                delegate: RowLayout {
                    required property var modelData
                    width: ListView.view.width
                    spacing: Kirigami.Units.smallSpacing

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        QQC2.Label {
                            Layout.fillWidth: true
                            text: String(modelData.name || "")
                            font.bold: true
                            elide: Text.ElideRight
                        }

                        QQC2.Label {
                            Layout.fillWidth: true
                            text: String(modelData.exe || "")
                            opacity: 0.62
                            font.pixelSize: Kirigami.Theme.smallFont.pixelSize
                            elide: Text.ElideMiddle
                        }
                    }

                    QQC2.Label {
                        visible: Boolean(modelData.excluded)
                        text: "Исключено"
                        opacity: 0.7
                    }

                    QQC2.Button {
                        visible: !Boolean(modelData.excluded)
                        text: "Исключить"
                        enabled: !backend.busy
                        onClicked: backend.runAction({
                            action: "app_add",
                            target: String(modelData.name || "")
                        })
                    }
                }

                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
            }
        }

        QQC2.Label {
            visible: backend.lastError.length > 0 || page.messageText.length > 0
            Layout.fillWidth: true
            text: page.messageText.length > 0 ? page.messageText : backend.lastError
            color: Kirigami.Theme.negativeTextColor
            wrapMode: Text.WordWrap
        }
    }
}
