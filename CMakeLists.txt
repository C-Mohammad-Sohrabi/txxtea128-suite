cmake_minimum_required(VERSION 3.16)
project(variant_G LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
include(GNUInstallDirs)
include(CTest)
add_library(variant_G SHARED src/txxtea128_h.c)
add_library(variant_G_static STATIC src/txxtea128_h.c)
set_target_properties(variant_G_static PROPERTIES OUTPUT_NAME variant_G)
install(TARGETS variant_G variant_G_static
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/txxtea128_h.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
add_executable(bench_g src/bench_g.c)
target_link_libraries(bench_g PRIVATE variant_G_static)
if(BUILD_TESTING)
  find_package(Python3 QUIET COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME correctness COMMAND ${CMAKE_COMMAND} -E env
      "CC=${CMAKE_C_COMPILER}" ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  endif()
endif()
