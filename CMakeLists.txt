cmake_minimum_required(VERSION 3.16)
project(SmartMeterProtocol VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/main.c
)

add_executable(smart_meter_simulation ${SOURCES})