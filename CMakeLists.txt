cmake_minimum_required(VERSION 3.16)
project(variant_B LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)
include(CTest)
add_library(variant_B SHARED src/txxtea128.c)
add_library(variant_B_static STATIC src/txxtea128.c)
set_target_properties(variant_B_static PROPERTIES OUTPUT_NAME variant_B)
install(TARGETS variant_B variant_B_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/txxtea128.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
add_executable(bench_b src/bench_b.c)
target_link_libraries(bench_b PRIVATE variant_B_static)
if(BUILD_TESTING)
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME correctness COMMAND ${CMAKE_COMMAND} -E env
      "CC=${CMAKE_C_COMPILER}" ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  endif()
endif()
