#include <QDir>

#include "version.h"
#include "localserver.h"
#include "logger.h"
#include "systemservice.h"
#include "core/utils/utilities.h"

#ifdef Q_OS_WIN
#include "platforms/windows/daemon/windowsdaemontunnel.h"

namespace {
int s_argc = 0;
char** s_argv = nullptr;
}  // namespace

#endif

int runApplication(int argc, char** argv)
{
    QCoreApplication app(argc,argv);

#ifdef Q_OS_WIN
    if(argc > 2){
        s_argc = argc;
        s_argv = argv;
        QStringList tokens;
        for (int i = 1; i < argc; ++i) {
            tokens.append(QString(argv[i]));
        }

        if (!tokens.empty() && tokens[0] == "tunneldaemon") {
            // Mayak: the tunnel service process only runs tunnel.dll and then exits. Falling through
            // made it a second Mayak service after every disconnect (same IPC pipe names, its own
            // daemon, split-tunnel driver and kill switch), so some app commands reached a stateless
            // process (the app then said "VPN service is not responding").
            WindowsDaemonTunnel daemon;
            return daemon.run(tokens);
        }
    }
#endif

    LocalServer localServer;
    return app.exec();

}


int main(int argc, char **argv)
{
    Utils::initializePath(Logger::systemLogDir());

    if (argc >= 2) {
        qInfo() << "Started as console application";
        return runApplication(argc, argv);
    }
    else {
        qInfo() << "Started as system service";
#ifdef Q_OS_WIN
        SystemService systemService(argc, argv);
        return systemService.exec();
#else
    return runApplication(argc, argv);
#endif

    }
}
