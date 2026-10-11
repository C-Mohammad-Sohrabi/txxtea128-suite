cmake_minimum_required(VERSION 3.16)
project(variant_C LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)
include(CTest)
add_library(variant_C SHARED src/txxtea128_rs.c)
add_library(variant_C_static STATIC src/txxtea128_rs.c)
set_target_properties(variant_C_static PROPERTIES OUTPUT_NAME variant_C)
install(TARGETS variant_C variant_C_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/txxtea128_rs.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
add_executable(bench_c src/bench_c.c)
target_link_libraries(bench_c PRIVATE variant_C_static)
if(BUILD_TESTING)
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME correctness COMMAND ${CMAKE_COMMAND} -E env
      "CC=${CMAKE_C_COMPILER}" ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  endif()
endif()
