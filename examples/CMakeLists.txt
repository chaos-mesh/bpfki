cmake_minimum_required(VERSION 3.11.4)
project(examples)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

# Find 3rd parties
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${protobuf_VERSION}")
set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)

find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")
set(_GRPC_GRPCPP_UNSECURE gRPC::grpc++_unsecure)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

find_package(gflags CONFIG REQUIRED)
message(STATUS "Using gflags ${gflags_VERSION}")
set(_GFLAGS_STATIC gflags)

find_package(spdlog CONFIG REQUIRED)
message(STATUS "Using spdlog ${spdlog_VERSION}")
set(_SPDLOG_STATIC spdlog::spdlog)

find_package(absl CONFIG REQUIRED)
message(STATUS "Using absl ${absl_VERSION}")
set(_ABSL_STATIC absl::base absl::strings absl::str_format)

# Proto file
get_filename_component(bpfki_proto "../proto/bpfki.proto" ABSOLUTE)
get_filename_component(bpfki_proto_path "${bpfki_proto}" PATH)

# Generated sources
set(bpfki_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/bpfki.pb.cc")
set(bpfki_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/bpfki.pb.h")
set(bpfki_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/bpfki.grpc.pb.cc")
set(bpfki_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/bpfki.grpc.pb.h")
add_custom_command(
      OUTPUT "${bpfki_proto_srcs}" "${bpfki_proto_hdrs}" "${bpfki_grpc_srcs}" "${bpfki_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${bpfki_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${bpfki_proto}"
      DEPENDS "${bpfki_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Targets greeter_[async_](client|server)
foreach(_target time-chaos fail-bio fail-mount fail-ext4-mount fail-alloc-page)
  add_executable(${_target} "${_target}.cc"
    ${bpfki_proto_srcs}
    ${bpfki_grpc_srcs})

  target_link_libraries(${_target}
    ${_GRPC_GRPCPP_UNSECURE}
    ${_PROTOBUF_LIBPROTOBUF}
    ${_SPDLOG_STATIC}
    ${_GFLAGS_STATIC}
    ${_ABSL_STATIC})
endforeach()
