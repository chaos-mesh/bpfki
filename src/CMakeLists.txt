add_executable(bpfki main.cc service.cc bpfki.cc)
set_target_properties(bpfki PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
target_link_libraries(bpfki PRIVATE
  bpfki_proto BCC::BCC spdlog::spdlog gflags::gflags
  absl::base absl::strings absl::str_format absl::hash
)

foreach(prog clock_gettime gettimeofday)
  configure_file("${PROJECT_SOURCE_DIR}/progs/${prog}"
    "${CMAKE_BINARY_DIR}/bin/${prog}" COPYONLY)
endforeach()

install(TARGETS bpfki RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES
  "${PROJECT_SOURCE_DIR}/progs/clock_gettime"
  "${PROJECT_SOURCE_DIR}/progs/gettimeofday"
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
