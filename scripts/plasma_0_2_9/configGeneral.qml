import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Item {
    id: page
    implicitWidth: Kirigami.Units.gridUnit * 34
    implicitHeight: Kirigami.Units.gridUnit * 20

    property var state: ({})

    Component.onCompleted: backend.refreshState()

    VpnBackend {
        id: backend
        onStateReady: function(newState) {
            page.state = newState
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Kirigami.Units.smallSpacing * 2

        RowLayout {
            Layout.fillWidth: true
            QQC2.Label {
                text: "Состояние E-VPN"
                font.bold: true
                Layout.fillWidth: true
            }
            QQC2.Button {
                text: "Обновить"
                icon.name: "view-refresh"
                onClicked: backend.refreshState()
            }
        }

        Kirigami.FormLayout {
            Layout.fillWidth: true

            QQC2.Label {
                Kirigami.FormData.label: "VPN:"
                text: Boolean(page.state.active) ? "Включён" : "Выключен"
            }

            QQC2.Label {
                Kirigami.FormData.label: "Профиль:"
                text: String(page.state.profile || page.state.last_profile || "—")
            }

            QQC2.Label {
                Kirigami.FormData.label: "IPv6:"
                text: String(page.state.ipv6_mode || "unknown")
            }

            QQC2.Label {
                Kirigami.FormData.label: "Kill switch:"
                text: Boolean(page.state.kill_switch) ? "Активен" : "Выключен"
            }

            QQC2.Label {
                Kirigami.FormData.label: "Manager:"
                text: String(page.state.manager || "")
            }
        }

        Item { Layout.fillHeight: true }

        QQC2.Label {
            visible: backend.lastError.length > 0
            Layout.fillWidth: true
            text: backend.lastError
            color: Kirigami.Theme.negativeTextColor
            wrapMode: Text.WordWrap
        }
    }
}
