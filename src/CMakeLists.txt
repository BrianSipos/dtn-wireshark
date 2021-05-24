
add_library(
    wscbor SHARED
    epan/wscbor.h epan/wscbor.c
)
target_link_libraries(wscbor PUBLIC PkgConfig::WIRESHARK)

add_library(
    wscose MODULE
    packet-cose.h packet-cose.c
)
target_link_libraries(wscose PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(wscose PRIVATE wscbor)

add_library(
    tcpclv4 MODULE
    packet-tcpclv4.h packet-tcpclv4.c
)
target_link_libraries(tcpclv4 PUBLIC PkgConfig::WIRESHARK)

add_library(
    udpcl MODULE
    packet-udpcl.h packet-udpcl.c
)
target_link_libraries(udpcl PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(udpcl PRIVATE wscbor)

add_library(
    bpv7 MODULE
    plugin_bpv7.c
    packet-bpv7.h packet-bpv7.c
    packet-bpsec.h packet-bpsec.c
    packet-bpv7-acme.c
    packet-bpsec-cose.c
)
target_link_libraries(bpv7 PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpv7 PRIVATE wscbor)

if(INSTALL_MODULE_PATH)
    install(
        TARGETS wscbor wscose tcpclv4 udpcl bpv7
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
