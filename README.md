# Wireshark Dissectors for BPv7-related Protocols

These wireshark modules require development environment for wireshark itself, cmake, and some build tool.
The reference commands below use the Ninja build tool, but that is not required.

Building the wireshark modules can be done with a command sequence similar to:
```
if (pkg-config --print-errors --exists 'wireshark > 3'); then
PLUGIN_PATH=$(pkg-config --define-variable=libdir=${HOME}/.local/lib --variable=plugindir wireshark)
else
MODULE_VERS=$(pkg-config --variable=VERSION_RELEASE wireshark)
PLUGIN_PATH="${HOME}/.local/lib/wireshark/plugins/${MODULE_VERS}"
fi
mkdir -p build
(cd build/ && cmake .. -DCMAKE_BUILD_TYPE=Debug -DINSTALL_MODULE_PATH=${PLUGIN_PATH}/epan/ -G Ninja)
cmake --build build --target install
```

At this point the two modules "libtcpclv4" and "libbpv7" will be installed in the wireshark plugin path and will be loaded at next wireshark application startup.

The protocol names registered are "tcpclv4" and "bpv7", each of which has some set of parameters and field names.

Running wireshark to immediately start capturing TCPCL data on interface "lo" (local loopback) and TCP port 4556 is the command:
```
wireshark -i lo -f 'tcp port 4556' -k
```
