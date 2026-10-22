if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Kernel tests require Linux")
endif()
add_executable(kernel-tests driver.cc)
target_compile_features(kernel-tests PRIVATE cxx_std_17)
target_compile_options(kernel-tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(kernel-tests PRIVATE bpfki_proto)
set_target_properties(kernel-tests PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
