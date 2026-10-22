cmake_minimum_required(VERSION 3.18)
project(bpfki LANGUAGES CXX)

include(GNUInstallDirs)

find_package(Protobuf REQUIRED)
find_package(gRPC CONFIG REQUIRED)
set(GFLAGS_USE_TARGET_NAMESPACE TRUE)
find_package(gflags CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(absl CONFIG REQUIRED)
find_path(BCC_INCLUDE_DIR NAMES bcc/BPF.h REQUIRED)
find_library(BCC_LIBRARY NAMES bcc REQUIRED)

add_library(BCC::BCC UNKNOWN IMPORTED)
set_target_properties(BCC::BCC PROPERTIES
  IMPORTED_LOCATION "${BCC_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${BCC_INCLUDE_DIR};${BCC_INCLUDE_DIR}/bcc/compat"
)

set(bpfki_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${bpfki_generated_dir}")
set(bpfki_proto "${CMAKE_CURRENT_SOURCE_DIR}/proto/bpfki.proto")
set(bpfki_proto_sources
  "${bpfki_generated_dir}/bpfki.pb.cc"
  "${bpfki_generated_dir}/bpfki.grpc.pb.cc"
)
set(bpfki_proto_headers
  "${bpfki_generated_dir}/bpfki.pb.h"
  "${bpfki_generated_dir}/bpfki.grpc.pb.h"
)
add_custom_command(
  OUTPUT ${bpfki_proto_sources} ${bpfki_proto_headers}
  COMMAND protobuf::protoc
  ARGS --cpp_out "${bpfki_generated_dir}"
    --grpc_out "${bpfki_generated_dir}"
    --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
    -I "${CMAKE_CURRENT_SOURCE_DIR}/proto" "${bpfki_proto}"
  DEPENDS "${bpfki_proto}" protobuf::protoc gRPC::grpc_cpp_plugin
  VERBATIM
)
add_library(bpfki_proto STATIC ${bpfki_proto_sources} ${bpfki_proto_headers})
target_compile_features(bpfki_proto PUBLIC cxx_std_17)
target_include_directories(bpfki_proto PUBLIC "${bpfki_generated_dir}")
target_link_libraries(bpfki_proto PUBLIC protobuf::libprotobuf gRPC::grpc++)

add_subdirectory(src)
add_subdirectory(examples)

option(BPFKI_BUILD_SMOKE_TEST "Build the no-fault gRPC smoke client" OFF)
if(BPFKI_BUILD_SMOKE_TEST)
  add_subdirectory(tests/smoke)
endif()

option(BPFKI_BUILD_KERNEL_TESTS "Build the disposable hosted-runner kernel test driver" OFF)
if(BPFKI_BUILD_KERNEL_TESTS)
  add_subdirectory(tests/kernel)
endif()
