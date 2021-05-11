
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
target_link_libraries(udpcl PRIVATE bpv7)

add_library(
    bpv7 SHARED
    packet-bpv7.h packet-bpv7.c
    epan/wscbor.h epan/wscbor.c
)
target_link_libraries(bpv7 PUBLIC PkgConfig::WIRESHARK)

add_library(
    bpv7_acme MODULE
    packet-bpv7-acme.c
)
target_link_libraries(bpv7_acme PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpv7_acme PRIVATE bpv7)

add_library(
    bpsec SHARED
    packet-bpsec.h packet-bpsec.c
)
target_link_libraries(bpsec PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpsec PRIVATE bpv7)

add_library(
    wscose MODULE
    packet-cose.h packet-cose.c
)
target_link_libraries(wscose PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(wscose PRIVATE bpv7)

add_library(
    bpsec_cose MODULE
    packet-bpsec-cose.c
)
target_link_libraries(bpsec_cose PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpsec_cose PRIVATE bpsec)

if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpclv4 udpcl bpv7 bpv7_acme bpsec wscose bpsec_cose
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
