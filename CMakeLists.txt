cmake_minimum_required(VERSION 3.20)
project(CANGuard CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Owner: M3. Add backend sources here once classes exist.
add_executable(canguard backend/src/main.cpp)
target_include_directories(canguard PRIVATE backend/include backend/third_party)
