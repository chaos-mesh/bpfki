add_executable(bpfki-smoke smoke.cc)
target_link_libraries(bpfki-smoke PRIVATE bpfki_proto)

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
