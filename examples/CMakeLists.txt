foreach(example time-chaos fail-bio fail-mount fail-ext4-mount fail-alloc-page)
  add_executable(${example} "${example}.cc")
  target_link_libraries(${example} PRIVATE
    bpfki_proto spdlog::spdlog gflags::gflags
  )
  install(TARGETS ${example} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endforeach()
