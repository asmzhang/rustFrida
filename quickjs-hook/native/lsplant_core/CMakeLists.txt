cmake_minimum_required(VERSION 3.18)
project(lsplant-core LANGUAGES C CXX)

find_program(CCACHE ccache)

set(CMAKE_CXX_STANDARD 23)

if (CCACHE)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
endif ()

set(SOURCES common.cxx)
file(GLOB_RECURSE MODULE_SOURCES CONFIGURE_DEPENDS "*.cxx")
file(GLOB_RECURSE MODULE_INTERFACES CONFIGURE_DEPENDS "*.ixx")
file(GLOB_RECURSE NORMAL_SOURCES CONFIGURE_DEPENDS "*.cc" "*.cpp")
list(FILTER MODULE_SOURCES EXCLUDE REGEX "${PROJECT_SOURCE_DIR}.external.+")
list(FILTER MODULE_INTERFACES EXCLUDE REGEX "${PROJECT_SOURCE_DIR}.external.+")
list(FILTER NORMAL_SOURCES EXCLUDE REGEX "${PROJECT_SOURCE_DIR}.external.+")

set(DEX_BUILDER_BUILD_SHARED OFF CACHE INTERNAL "" FORCE)
add_subdirectory(external/dex_builder)

if(NOT TARGET dobby)
    set(DOBBY_DIR external/LSPDobby)
    macro(SET_OPTION option value)
        set(${option} ${value} CACHE INTERNAL "" FORCE)
    endmacro()
    SET_OPTION(DOBBY_DEBUG OFF)
    SET_OPTION(DOBBY_GENERATE_SHARED OFF)
    add_subdirectory(${DOBBY_DIR} dobby)
    get_property(DOBBY_INCLUDE_DIRECTORIES
            TARGET dobby
            PROPERTY INCLUDE_DIRECTORIES)
    include_directories(
            .
            ${DOBBY_INCLUDE_DIRECTORIES}
            $<TARGET_PROPERTY:dobby,INCLUDE_DIRECTORIES>
    )
endif()

# Add aliuhook module
add_subdirectory(external/aliuhook)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${NORMAL_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_SCAN_FOR_MODULES ON)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "rf_lsplant")

# Add C++ modules
target_sources(${PROJECT_NAME} PRIVATE
    FILE_SET CXX_MODULES
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
    FILES ${MODULE_SOURCES} ${MODULE_INTERFACES}
)
target_include_directories(${PROJECT_NAME} PUBLIC
    include
    ${CMAKE_CURRENT_SOURCE_DIR}
    external/dex_builder/external/parallel_hashmap
    external/LSPDobby/
)
target_include_directories(${PROJECT_NAME} PRIVATE
    external/aliuhook/
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    dobby
    dex_builder_static
    aliuhook
)
target_link_libraries(${PROJECT_NAME} PUBLIC
    log
    z
)

install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
