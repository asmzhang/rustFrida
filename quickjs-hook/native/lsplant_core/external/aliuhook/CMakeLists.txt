# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.18.1)
#project("lsplant_test")
project("aliuhook")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include_directories(
    xz/linux/lib/xz 
    xz/linux/include/linux 
    xz/userspace
    ../LSPDobby
)

add_library(aliuhook
#        SHARED
        STATIC
        elf_img.cpp
        profile_saver.cpp
        hidden_api.cpp
        invoke_constructor.cpp
        aliuhook.cpp
        xz/linux/lib/xz/xz_crc32.c
        xz/linux/lib/xz/xz_crc64.c
        xz/linux/lib/xz/xz_dec_bcj.c
        xz/linux/lib/xz/xz_dec_lzma2.c
        xz/linux/lib/xz/xz_dec_stream.c
)

set_target_properties(aliuhook PROPERTIES CXX_SCAN_FOR_MODULES ON)

#find_package(dobby REQUIRED CONFIG)
#find_package(lsplant REQUIRED CONFIG)
#
#get_property(lsplant_INCLUDE TARGET lsplant::lsplant PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
#file(GLOB_RECURSE lsplant_MODULES "${lsplant_INCLUDE}/*.ixx")
#target_sources(lsplant::lsplant INTERFACE FILE_SET CXX_MODULES BASE_DIRS ${lsplant_INCLUDE} FILES ${lsplant_MODULES})
#set_target_properties(lsplant::lsplant PROPERTIES IMPORTED_CXX_MODULES_COMPILE_FEATURES "cxx_std_23")
#set_target_properties(lsplant::lsplant PROPERTIES IMPORTED_CXX_MODULES_INCLUDE_DIRECTORIES "${lsplant_INCLUDE}")

#target_link_libraries(aliuhook log dobby::dobby lsplant::lsplant)



target_link_libraries(aliuhook log dobby)
#
#
#
#
#
#
#cmake_minimum_required(VERSION 3.18.1)
#project("lsplant_test")
#
#set(CMAKE_CXX_STANDARD 23)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
#
## xz include
#include_directories(
#        xz/linux/lib/xz
#        xz/linux/include/linux
#        xz/userspace
#)
#
## 你的 native 源文件
#add_library(test SHARED
#        test.cpp
#        elf_img.cpp
#        profile_saver.cpp
#        hidden_api.cpp
#        invoke_constructor.cpp
#        xz/linux/lib/xz/xz_crc32.c
#        xz/linux/lib/xz/xz_crc64.c
#        xz/linux/lib/xz/xz_dec_bcj.c
#        xz/linux/lib/xz/xz_dec_lzma2.c
#        xz/linux/lib/xz/xz_dec_stream.c
#)
#
#set_target_properties(test PROPERTIES CXX_SCAN_FOR_MODULES ON)
#
## Dobby Prefab
#find_package(dobby REQUIRED CONFIG)
#
## LSPlant 直接用 IMPORTED 库
#add_library(lsplant_lib SHARED IMPORTED)
#set_target_properties(lsplant_lib PROPERTIES
#        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../../../libs/splant-debug.aar/prefab/modules/lsplant/libs/${ANDROID_ABI}/liblsplant.so"
#        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../../../splant-debug.aar/prefab/modules/lsplant/include"
#)
#
## 如果 LSPlant 有 C++ module，可以用 FILE_SET 方式
#file(GLOB_RECURSE lsplant_MODULES "${CMAKE_SOURCE_DIR}/../../../splant-debug.aar/prefab/modules/lsplant/include/*.ixx")
#target_sources(lsplant_lib INTERFACE FILE_SET CXX_MODULES
#        BASE_DIRS "${CMAKE_SOURCE_DIR}/../../../splant-debug.aar/prefab/modules/lsplant/include"
#        FILES ${lsplant_MODULES}
#)
#set_target_properties(lsplant_lib PROPERTIES
#        IMPORTED_CXX_MODULES_COMPILE_FEATURES "cxx_std_23"
#        IMPORTED_CXX_MODULES_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../../../splant-debug.aar/prefab/modules/lsplant/include"
#)
#
## 链接
#target_link_libraries(test
#        log
#        dobby::dobby
#        lsplant_lib
#)
#
