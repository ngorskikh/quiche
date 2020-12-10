cmake_minimum_required(VERSION 3.10)

project(examples)

include_directories(quiche-0.6.0-darwin-x86_64-test1/include)
link_libraries(${CMAKE_CURRENT_SOURCE_DIR}/quiche-0.6.0-darwin-x86_64-test1/libquiche.a)

include_directories(./uthash)

include_directories(/usr/local/Cellar/libev/4.33/include/)
link_libraries(/usr/local/Cellar/libev/4.33/lib/libev.4.dylib)

link_libraries(/Users/ngorskikh/src/boringssl/cmake-build-debug/crypto/libcrypto.a)
link_libraries(/Users/ngorskikh/src/boringssl/cmake-build-debug/ssl/libssl.a)

link_libraries("-framework Security")

add_executable(server http3-server.c)
add_executable(client http3-client.c)

configure_file(cert-big.crt cert-big.crt COPYONLY)
configure_file(cert.crt cert.crt COPYONLY)
configure_file(cert.key cert.key COPYONLY)
configure_file(rootca.crt rootca.key COPYONLY)
