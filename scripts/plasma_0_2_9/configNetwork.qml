import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Item {
    id: page
    implicitWidth: Kirigami.Units.gridUnit * 38
    implicitHeight: Kirigami.Units.gridUnit * 30

    property var domains: []
    property var networks: []
    property var snapshots: []

    function addManual() {
        const value = targetField.text.trim()
        if (value.length === 0)
            return
        backend.runAction({action: "direct_add", target: value})
    }

    Component.onCompleted: backend.refreshState()

    VpnBackend {
        id: backend
        onStateReady: function(state) {
            page.domains = state.domains || []
            page.networks = state.networks || []
            page.snapshots = state.dns_snapshots || []
        }
        onActionFinished: function(ok, message) {
            if (ok)
                targetField.clear()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Kirigami.Units.smallSpacing * 2

        QQC2.Label {
            text: "Сайты и IP без VPN"
            font.bold: true
        }

        QQC2.Label {
            Layout.fillWidth: true
            text: "Добавь домен, IP или CIDR. Например: example.com, 203.0.113.10, 203.0.113.0/24."
            wrapMode: Text.WordWrap
            opacity: 0.72
        }

        RowLayout {
            Layout.fillWidth: true

            QQC2.TextField {
                id: targetField
                Layout.fillWidth: true
                placeholderText: "example.com / IP / CIDR"
                enabled: !backend.busy
                onAccepted: page.addManual()
            }

            QQC2.Button {
                text: "Добавить"
                enabled: !backend.busy && targetField.text.trim().length > 0
                onClicked: page.addManual()
            }
        }

        QQC2.Label { text: "Домены"; font.bold: true }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.preferredHeight: Kirigami.Units.gridUnit * 6
            ListView {
                anchors.fill: parent
                clip: true
                model: page.domains
                delegate: RowLayout {
                    required property var modelData
                    width: ListView.view.width
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: String(modelData)
                        elide: Text.ElideRight
                    }
                    QQC2.ToolButton {
                        icon.name: "list-remove"
                        text: "Удалить"
                        enabled: !backend.busy
                        onClicked: backend.runAction({action: "direct_remove", target: String(modelData)})
                    }
                }
                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
            }
        }

        QQC2.Label { text: "IP и сети"; font.bold: true }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.preferredHeight: Kirigami.Units.gridUnit * 6
            ListView {
                anchors.fill: parent
                clip: true
                model: page.networks
                delegate: RowLayout {
                    required property var modelData
                    width: ListView.view.width
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: String(modelData)
                        elide: Text.ElideRight
                    }
                    QQC2.ToolButton {
                        icon.name: "list-remove"
                        text: "Удалить"
                        enabled: !backend.busy
                        onClicked: backend.runAction({action: "direct_remove", target: String(modelData)})
                    }
                }
                QQC2.ScrollBar.vertical: QQC2.ScrollBar {}
            }
        }

        QQC2.Label {
            text: "DNS snapshots"
            font.bold: true
            visible: page.snapshots.length > 0
        }

        QQC2.Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: page.snapshots.length > 0
            ListView {
                anchors.fill: parent
                clip: true
                model: page.snapshots
                delegate: ColumnLayout {
                    required property var modelData
                    width: ListView.view.width
                    QQC2.Label {
                        text: String(modelData.domain || "")
                        font.bold: true
                    }
                    QQC2.Label {
                        Layout.fillWidth: true
                        text: (modelData.networks || []).join(", ")
                        wrapMode: Text.WrapAnywhere
                        opacity: 0.65
                        font.pixelSize: Kirigami.Theme.smallFont.pixelSize
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
