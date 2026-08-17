import QtQuick
import org.kde.plasma.plasma5support as Plasma5Support

Item {
    id: backend
    visible: false
    width: 0
    height: 0

    property bool busy: false
    property string lastError: ""

    signal stateReady(var state)
    signal runningReady(var applications)
    signal actionFinished(bool ok, string message)

    readonly property string stateCommand: "/usr/local/bin/vpn ui state"
    readonly property string runningCommand: "/usr/local/bin/vpn ui running"

    function refreshState() {
        stateSource.connectSource(stateCommand)
    }

    function refreshRunning() {
        runningSource.connectSource(runningCommand)
    }

    function encodePayload(payload) {
        return Qt.btoa(encodeURIComponent(JSON.stringify(payload)))
    }

    function runAction(payload) {
        if (busy)
            return
        busy = true
        lastError = ""
        const command = "/usr/local/bin/vpn ui action " + encodePayload(payload)
        actionSource.connectSource(command)
    }

    Plasma5Support.DataSource {
        id: stateSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== backend.stateCommand)
                return
            const output = String(data["stdout"] || "").trim()
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            if (exitCode === 0 && output.length > 0) {
                try {
                    backend.stateReady(JSON.parse(output))
                } catch (error) {
                    backend.lastError = "Не удалось прочитать настройки VPN"
                }
            } else {
                backend.lastError = String(data["stderr"] || output || "Ошибка чтения настроек")
            }
            stateSource.disconnectSource(sourceName)
        }
    }

    Plasma5Support.DataSource {
        id: runningSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== backend.runningCommand)
                return
            const output = String(data["stdout"] || "").trim()
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            if (exitCode === 0 && output.length > 0) {
                try {
                    const parsed = JSON.parse(output)
                    backend.runningReady(parsed.applications || [])
                } catch (error) {
                    backend.lastError = "Не удалось прочитать список запущенных приложений"
                }
            } else {
                backend.lastError = String(data["stderr"] || output || "Ошибка чтения процессов")
            }
            runningSource.disconnectSource(sourceName)
        }
    }

    Plasma5Support.DataSource {
        id: actionSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            const stderrText = String(data["stderr"] || "").trim()
            const stdoutText = String(data["stdout"] || "").trim()
            backend.busy = false
            actionSource.disconnectSource(sourceName)
            if (exitCode !== 0) {
                backend.lastError = stderrText.length > 0 ? stderrText : stdoutText
                backend.actionFinished(false, backend.lastError)
            } else {
                backend.lastError = ""
                backend.actionFinished(true, "")
                backend.refreshState()
                backend.refreshRunning()
            }
        }
    }
}
