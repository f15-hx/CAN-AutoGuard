cmake_minimum_required(VERSION 3.20)
project(CANGuard CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()

# ---- Settings shared by everything (include paths, threads, Windows sockets) ----
find_package(Threads REQUIRED)
add_library(canguard_deps INTERFACE)
target_include_directories(canguard_deps INTERFACE
    ${CMAKE_SOURCE_DIR}/backend/include
    ${CMAKE_SOURCE_DIR}/backend/third_party)
target_link_libraries(canguard_deps INTERFACE Threads::Threads)
if(WIN32)
  target_link_libraries(canguard_deps INTERFACE ws2_32)
  target_compile_definitions(canguard_deps INTERFACE _WIN32_WINNT=0x0A00)
endif()

# ---- Core library: every .cpp in backend/src except main.cpp (new files are picked up automatically) ----
file(GLOB_RECURSE BACKEND_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/backend/src/*.cpp)
list(FILTER BACKEND_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")
if(BACKEND_SOURCES)
  add_library(canguard_core STATIC ${BACKEND_SOURCES})
  target_link_libraries(canguard_core PUBLIC canguard_deps)
  set(CORE_LIB canguard_core)
else()
  set(CORE_LIB canguard_deps)
endif()

# ---- The program ----
add_executable(canguard backend/src/main.cpp)
target_link_libraries(canguard PRIVATE ${CORE_LIB})

# ---- Tests: every .cpp in backend/tests that contains "int main" becomes its own program ----
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/backend/tests/*.cpp)
foreach(test_src ${TEST_SOURCES})
  file(READ ${test_src} test_text)
  string(FIND "${test_text}" "int main" has_main)
  if(has_main GREATER -1)
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name} PRIVATE ${CORE_LIB})
    add_test(NAME ${test_name} COMMAND ${test_name})
  endif()
endforeach()
