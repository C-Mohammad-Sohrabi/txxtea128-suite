cmake_minimum_required(VERSION 3.16)
project(variant_A LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)
include(CTest)
add_library(variant_A SHARED src/xxtea128.c)
add_library(variant_A_static STATIC src/xxtea128.c)
set_target_properties(variant_A_static PROPERTIES OUTPUT_NAME variant_A)
install(TARGETS variant_A variant_A_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/xxtea128.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
add_executable(bench_a src/bench_a.c)
target_link_libraries(bench_a PRIVATE variant_A_static)
if(BUILD_TESTING)
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME correctness COMMAND ${CMAKE_COMMAND} -E env
      "CC=${CMAKE_C_COMPILER}" ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  endif()
endif()
