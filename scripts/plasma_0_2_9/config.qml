import QtQuick
import org.kde.plasma.configuration

ConfigModel {
    ConfigCategory {
        name: "Приложения"
        icon: "applications-system"
        source: "configApplications.qml"
    }
    ConfigCategory {
        name: "Сайты и IP"
        icon: "network-server"
        source: "configNetwork.qml"
    }
    ConfigCategory {
        name: "Порты"
        icon: "network-connect"
        source: "configPorts.qml"
    }
    ConfigCategory {
        name: "Состояние"
        icon: "dialog-information"
        source: "configGeneral.qml"
    }
}
