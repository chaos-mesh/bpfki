add_executable(bio-probe-test bio_probe_test.cc "${PROJECT_SOURCE_DIR}/src/bio_probe.cc")
target_compile_features(bio-probe-test PRIVATE cxx_std_17)
target_include_directories(bio-probe-test PRIVATE "${PROJECT_SOURCE_DIR}/src")

add_executable(failkern-update-test failkern_update_test.cc
  "${PROJECT_SOURCE_DIR}/src/bpfki.cc"
  "${PROJECT_SOURCE_DIR}/src/service.cc"
  "${PROJECT_SOURCE_DIR}/src/bio_probe.cc"
)
target_include_directories(failkern-update-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(failkern-update-test PRIVATE
  bpfki_proto BCC::BCC spdlog::spdlog
  absl::base absl::strings absl::str_format absl::hash
)

add_executable(kernel-fault-test kernel_fault_test.cc
  "${PROJECT_SOURCE_DIR}/src/bpfki.cc"
  "${PROJECT_SOURCE_DIR}/src/service.cc"
  "${PROJECT_SOURCE_DIR}/src/bio_probe.cc"
  "${PROJECT_SOURCE_DIR}/src/bio_probe_linux.cc"
)
target_include_directories(kernel-fault-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(kernel-fault-test PRIVATE
  bpfki_proto BCC::BCC spdlog::spdlog
  absl::base absl::strings absl::str_format absl::hash
)

add_executable(failkern-probe-test failkern_probe_test.cc
  "${PROJECT_SOURCE_DIR}/src/bpfki.cc"
  "${PROJECT_SOURCE_DIR}/src/service.cc"
  "${PROJECT_SOURCE_DIR}/src/bio_probe.cc"
)
target_include_directories(failkern-probe-test PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(failkern-probe-test PRIVATE
  bpfki_proto BCC::BCC spdlog::spdlog
  absl::base absl::strings absl::str_format absl::hash
)
target_link_options(failkern-probe-test PRIVATE "-Wl,--wrap=getrandom")

foreach(test_target bio-probe-test failkern-update-test kernel-fault-test failkern-probe-test)
  add_test(NAME ${test_target} COMMAND ${test_target})
endforeach()
