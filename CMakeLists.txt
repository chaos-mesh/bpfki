cmake_minimum_required(VERSION 3.11.4)
project(bpfki)

include(ExternalProject)

# c-ares
set(CARES_VERSION 1_14_0)
set(CARES_URL URL https://github.com/c-ares/c-ares/archive/cares-${CARES_VERSION}.zip)

ExternalProject_Add(c-ares
  PREFIX c-ares
  URL ${CARES_URL}
  CMAKE_CACHE_ARGS
    -DCARES_SHARED:BOOL=OFF
    -DCARES_STATIC:BOOL=ON
    -DCARES_STATIC_PIC:BOOL=ON
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/c-ares
)

# protobuf
set(PROTOBUF_VERSION v3.9.2)
set(PROTOBUF_URL https://github.com/google/protobuf/archive/${PROTOBUF_VERSION}.zip)

ExternalProject_Add(protobuf
  PREFIX protobuf
  URL ${PROTOBUF_URL}
  SOURCE_SUBDIR cmake
  CMAKE_CACHE_ARGS
    -Dprotobuf_BUILD_TESTS:BOOL=OFF
    -Dprotobuf_WITH_ZLIB:BOOL=OFF
    -Dprotobuf_MSVC_STATIC_RUNTIME:BOOL=OFF
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/protobuf
)

if (EXISTS "/etc/lsb-release")
  set(_FINDPACKAGE_PROTOBUF_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/protobuf/lib/cmake/protobuf")
elseif (EXISTS "/etc/redhat-release")
  set(_FINDPACKAGE_PROTOBUF_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/protobuf/lib64/cmake/protobuf")
endif()

set(PROTOC "${CMAKE_CURRENT_BINARY_DIR}/protobuf/bin/protoc")

# zlib
set(ZLIB_VERSION 1.2.11)
set(ZLIB_URL https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz)

ExternalProject_Add(zlib
  PREFIX zlib
  URL ${ZLIB_URL}
  CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/zlib
)

# gRPC
set(GRPC_VERSION v1.24.3)
set(GRPC_URL https://github.com/grpc/grpc/archive/${GRPC_VERSION}.zip)

ExternalProject_Add(grpc
  PREFIX grpc
  URL ${GRPC_URL}
  DEPENDS c-ares protobuf zlib
  CMAKE_CACHE_ARGS
    -DgRPC_INSTALL:BOOL=ON
    -DgRPC_BUILD_TESTS:BOOL=OFF
    -DgRPC_PROTOBUF_PROVIDER:STRING=package
    -DgRPC_PROTOBUF_PACKAGE_TYPE:STRING=CONFIG
    -DProtobuf_DIR:PATH=${_FINDPACKAGE_PROTOBUF_CONFIG_DIR}
    -DgRPC_ZLIB_PROVIDER:STRING=package
    -DZLIB_ROOT:STRING=${CMAKE_CURRENT_BINARY_DIR}/zlib
    -DgRPC_CARES_PROVIDER:STRING=package
    -Dc-ares_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/c-ares/lib/cmake/c-ares
    -DgRPC_SSL_PROVIDER:STRING=package
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/grpc
)

# gflags
set(GFLAGS_VERSION v2.2.2)
set(GFLAGS_URL https://github.com/gflags/gflags/archive/${GFLAGS_VERSION}.zip)

ExternalProject_Add(gflags
  PREFIX gflags
  URL ${GFLAGS_URL}
  CMAKE_CACHE_ARGS
    -Dgflags_INSTALL:BOOL=ON
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/gflags
)

# spdlog
set(SPDLOG_VERSION v1.5.0)
set(SPDLOG_URL https://github.com/gabime/spdlog/archive/${SPDLOG_VERSION}.zip)

ExternalProject_Add(spdlog
  PREFIX spdlog
  URL ${SPDLOG_URL}
  CMAKE_CACHE_ARGS
    -Dspdlog_INSTALL:BOOL=ON
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/spdlog
)

# abseilcpp
set(ABSL_VERSION 20190808)
set(ABSL_URL https://github.com/abseil/abseil-cpp/archive/${ABSL_VERSION}.zip)
ExternalProject_Add(absl
  PREFIX absl
  URL ${ABSL_URL}
  CMAKE_CACHE_ARGS
    -Dabsl_INSTALL:BOOL=ON
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/absl
)

if (EXISTS "/etc/lsb-release")
  set(_FINDPACKAGE_ABSL_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/absl/lib/cmake/absl")
elseif (EXISTS "/etc/redhat-release")
  set(_FINDPACKAGE_ABSL_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/absl/lib64/cmake/absl")
endif()

# examples
ExternalProject_Add(examples
  PREFIX examples 
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/examples"
  BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/examples"
  INSTALL_COMMAND ""
  CMAKE_CACHE_ARGS
        -DProtobuf_DIR:PATH=${_FINDPACKAGE_PROTOBUF_CONFIG_DIR}
        -Dc-ares_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/c-ares/lib/cmake/c-ares
        -DZLIB_ROOT:STRING=${CMAKE_CURRENT_BINARY_DIR}/zlib
        -DgRPC_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/cmake/grpc
        -Dgflags_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/gflags/lib/cmake/gflags
        -Dspdlog_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/spdlog/lib/cmake/spdlog
        -Dabsl_DIR:PATH=${_FINDPACKAGE_ABSL_CONFIG_DIR}
  DEPENDS protobuf grpc spdlog gflags absl
)

# bpfki
ExternalProject_Add(bpfki
  PREFIX bpfki
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src"
  BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/bin"
  CMAKE_CACHE_ARGS
        -DProtobuf_DIR:PATH=${_FINDPACKAGE_PROTOBUF_CONFIG_DIR}
        -Dc-ares_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/c-ares/lib/cmake/c-ares
        -DZLIB_ROOT:STRING=${CMAKE_CURRENT_BINARY_DIR}/zlib
        -DgRPC_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/cmake/grpc
        -Dgflags_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/gflags/lib/cmake/gflags
        -Dspdlog_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/spdlog/lib/cmake/spdlog
        -Dabsl_DIR:PATH=${_FINDPACKAGE_ABSL_CONFIG_DIR}
  DEPENDS protobuf grpc spdlog gflags absl
)
