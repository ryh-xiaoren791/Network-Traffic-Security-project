cmake_minimum_required(VERSION 3.20)
project(traffic_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(traffic_core src/module.cpp)
target_compile_definitions(traffic_core PRIVATE TRAFFIC_CORE_ABI_VERSION=1)

if(MSVC)
  target_compile_options(traffic_core PRIVATE /EHsc /permissive- /Zc:__cplusplus)
endif()
