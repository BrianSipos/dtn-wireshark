
add_library(
    tcpclv4 SHARED
    packet-tcpclv4.h packet-tcpclv4.c
)
target_link_libraries(tcpclv4 PUBLIC PkgConfig::WIRESHARK)

add_library(
    udpcl SHARED
    packet-udpcl.c
)
target_link_libraries(udpcl PUBLIC PkgConfig::WIRESHARK)

add_library(
    bpv7 SHARED
    packet-bpv7.h packet-bpv7.c
    bp_cbor.h bp_cbor.c
)
target_link_libraries(bpv7 PUBLIC PkgConfig::WIRESHARK)

add_library(
    bpsec SHARED
    packet-bpsec.h packet-bpsec.c
)
target_link_libraries(bpsec PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpsec PRIVATE bpv7)

add_library(
    bpsec_cose SHARED
    packet-bpsec-cose.c
)
target_link_libraries(bpsec_cose PUBLIC PkgConfig::WIRESHARK)
target_link_libraries(bpsec_cose PRIVATE bpsec)

if(INSTALL_MODULE_PATH)
    install(
        TARGETS tcpclv4 udpcl bpv7 bpsec bpsec_cose
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
