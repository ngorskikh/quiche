cmake_minimum_required(VERSION 3.10)

project(examples)

include_directories(/Users/ngorskikh/nginx/build/quiche/include)
link_libraries(/Users/ngorskikh/nginx/build/quiche/target/debug/libquiche.dylib)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include_directories(/usr/local/Cellar/libev/4.33/include/)
link_libraries(/usr/local/Cellar/libev/4.33/lib/libev.4.dylib)

add_executable(server http3-server.c)
add_executable(client http3-client.c)

configure_file(cert-big.crt cert-big.crt COPYONLY)
configure_file(cert.crt cert.crt COPYONLY)
configure_file(cert.key cert.key COPYONLY)
configure_file(rootca.crt rootca.key COPYONLY)
