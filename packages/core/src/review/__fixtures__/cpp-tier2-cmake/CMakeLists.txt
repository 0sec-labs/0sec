# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.10)
project(gadget C)

add_library(gadget
    src/gadget.c
    src/util.c
)
target_include_directories(gadget PUBLIC include)
