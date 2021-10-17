
add_library(
    udpcl MODULE
    packet-udpcl.h packet-udpcl.c
)
target_link_libraries(udpcl PUBLIC PkgConfig::WIRESHARK)

add_library(
    bpv7 MODULE
    plugin_bpv7.c
    packet-bpv7-acme.c
    packet-bpsec-cose.c
)
target_link_libraries(bpv7 PUBLIC PkgConfig::WIRESHARK)

if(INSTALL_MODULE_PATH)
    install(
        TARGETS udpcl bpv7
        LIBRARY DESTINATION ${INSTALL_MODULE_PATH}
    )
endif(INSTALL_MODULE_PATH)

if (GTEST_FOUND)
    add_subdirectory(test)
endif()
