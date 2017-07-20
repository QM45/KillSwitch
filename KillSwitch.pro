QT += core gui webchannel websockets webenginewidgets
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++11

QMAKE_CXXFLAGS += /Zc:strictStrings-

TARGET = KillSwitch

TEMPLATE = app

SOURCES += \
    websocketclientwrapper.cpp \
    websockettransport.cpp \
    main.cpp

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += \
    QT_DEPRECATED_WARNINGS \

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
    websocketclientwrapper.h \
    websockettransport.h

DISTFILES += \
    ui.html \
    qwebchannel.js

copydata.commands += $(COPY_DIR) $$shell_path($$PWD/ui.html) $$shell_path($$OUT_PWD) \
    & $(COPY_DIR) $$shell_path($$PWD/qwebchannel.js) $$shell_path($$OUT_PWD)
first.depends = $(first) copydata
export(first.depends)
export(copydata.commands)
QMAKE_EXTRA_TARGETS += first copydata


