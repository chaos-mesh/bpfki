add_executable(bpfki-smoke smoke.cc)
target_link_libraries(bpfki-smoke PRIVATE bpfki_proto)
