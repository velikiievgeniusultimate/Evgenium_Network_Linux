import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Item {
    id: page
    implicitWidth: Kirigami.Units.gridUnit * 38
    implicitHeight: Kirigami.Units.gridUnit * 24

    property var ports: []

    function addPort() {
        const value = Number(portField.text)
        if (isNaN(value) || value !== Math.floor(value) || value < 1 || value > 65535)
            return
        backend.runAction({
            action: "port_add",
            port: value,
            proto: protoBox.currentText.toLowerCase()
        })
    }

    Component.onCompleted: backend.refreshState()

    VpnBackend {
        id: backend
        onStateReady: function(state) {
            page.ports = state.server_ports || []
        }
        onActionFinished: function(ok, message) {
            if (ok)
                portField.clear()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Kirigami.Units.smallSpacing * 2

        QQC2.Label {
            text: "Входящие серверные порты"
            font.bold: true
        }

        QQC2.Label {
            Layout.fillWidth: true
            text: "Ответы на входящие соединения к этим портам отправляются напрямую через физическую сеть, а остальной трафик остаётся в VPN."
            wrapMode: Text.WordWrap
            opacity: 0.72
        }

        RowLayout {
            Layout.fillWidth: true

            QQC2.TextField {
                id: portField
                Layout.fillWidth: true
                placeholderText: "25565"
                inputMethodHints: Qt.ImhDigitsOnly
                enabled: !backend.busy
                onAccepted: page.addPort()
            }

            QQC2.ComboBox {
                id: protoBox
                model: ["TCP", "UDP", "BOTH"]
            }

            QQC2.Button {
                text: "Добавить"
                enabled: !backend.busy && portField.text.length > 0
                onClicked: page.addPort()
            }
        }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                anchors.fill: parent
                clip: true
                model: page.ports
                spacing: Kirigami.Units.smallSpacing

                delegate: RowLayout {
                    required property var modelData
                    width: ListView.view.width

                    QQC2.Label {
                        Layout.fillWidth: true
                        text: String(modelData.proto || "").toUpperCase() + "  " + String(modelData.port || "")
                    }

                    QQC2.ToolButton {
                        icon.name: "list-remove"
                        text: "Удалить"
                        enabled: !backend.busy
                        onClicked: backend.runAction({
                            action: "port_remove",
                            port: Number(modelData.port),
                            proto: String(modelData.proto)
                        })
                    }
                }

                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
            }
        }

        QQC2.Label {
            visible: backend.lastError.length > 0
            Layout.fillWidth: true
            text: backend.lastError
            color: Kirigami.Theme.negativeTextColor
            wrapMode: Text.WordWrap
        }
    }
}
