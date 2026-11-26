cmake_minimum_required(VERSION 3.20)
project(CANGuard CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(canguard backend/src/main.cpp)
target_include_directories(canguard PRIVATE backend/include backend/third_party)

find_package(Threads REQUIRED)
target_link_libraries(canguard PRIVATE Threads::Threads)

if(WIN32)
  target_link_libraries(canguard PRIVATE ws2_32)
  target_compile_definitions(canguard PRIVATE _WIN32_WINNT=0x0A00)
endif()