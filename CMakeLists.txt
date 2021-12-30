cmake_minimum_required(
   VERSION 3.20.0)

project(
   pcap-test-project)

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
   message(
      FATAL_ERROR
      "64-bit platfomrs supported only!")
endif ( )


if (WIN32)
   set(
      CMAKE_CONFIGURATION_TYPES
      Debug
      Release)

   set(
      CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} /W4 /permissive- /D_WINSOCK_DEPRECATED_NO_WARNINGS 
      /Zc:__cplusplus")
endif ( )

set(
   CMAKE_CXX_STANDARD
   20)

function(
   find_pcap )

   if (WIN32)

      set(
         NPCAP_SDK_LIB_PATH
         "${NPCAP_SDK_ROOT}/lib/${CMAKE_GENERATOR_PLATFORM}")
      set(
         WINPCAP_SDK_LIB_PATH
         "${WINPCAP_SDK_ROOT}/lib/${CMAKE_GENERATOR_PLATFORM}")

      if (WINPCAP_SDK_ROOT)
         message(
            AUTHOR_WARNING
            "WinPcap is no longer supported!  It has not seen "
            "any updates since 2015.  It is recommended to use "
            "Npcap instead.  https://www.winpcap.org/install/default.htm")
      endif ( )

   endif ( )

   find_path(
      PCAP_ROOT_DIR
      NAMES
         pcap/pcap.h
      PATH_SUFFIXES
         include
      HINTS
         "${NPCAP_SDK_ROOT}"
         "${WINPCAP_SDK_ROOT}"
      REQUIRED)

   find_library(
      PCAP_LIBRARY
      NAMES
         pcap wpcap
      HINTS
         "${NPCAP_SDK_LIB_PATH}"
         "${WINPCAP_SDK_LIB_PATH}"
      REQUIRED)

   add_library(
      pcap::pcap
      SHARED
      IMPORTED
      GLOBAL)

   set_target_properties(
      pcap::pcap
      PROPERTIES
      IMPORTED_LOCATION ${PCAP_LIBRARY}
      INTERFACE_INCLUDE_DIRECTORIES ${PCAP_ROOT_DIR})

   if (WIN32)

      find_file(
         PCAP_LOCATION
         NAMES
            pcap.dll wpcap.dll
         PATH_SUFFIXES
            bin)
   
      set_target_properties(
         pcap::pcap
         PROPERTIES
         IMPORTED_IMPLIB ${PCAP_LIBRARY}
         IMPORTED_LOCATION ${PCAP_LOCATION})

      mark_as_advanced(
         PCAP_LOCATION)

      if (NPCAP_SDK_ROOT)
         set(
            pcap_compile_definitions
            PCAP_NPCAP)
      elseif (WINPCAP_SDK_ROOT)
         set(
            pcap_compile_definitions
            PCAP_WINPCAP)
      else ( )
         set(
            pcap_compile_definitions
            PCAP_UNKNOWN)
      endif ( )

      set_target_properties(
         pcap::pcap
         PROPERTIES
         INTERFACE_COMPILE_DEFINITIONS ${pcap_compile_definitions})
   endif ( )

   mark_as_advanced(
      PCAP_ROOT_DIR
      PCAP_LIBRARY)

endfunction(
   find_pcap )

set(
   CMAKE_AUTOMOC
      yes)

set(
   proj_name
   pcap-test)

add_executable(
   pcap-test
   main.cpp)

find_pcap()
find_package(
   Qt5
   COMPONENTS
   Core
   Gui
   Widgets)
find_package(
   Threads)

target_link_libraries(
   ${proj_name}
   PRIVATE
   pcap::pcap
   Qt5::Core
   Qt5::Gui
   Qt5::Widgets
   Threads::Threads
   $<IF:$<BOOL:${WIN32}>,ws2_32.lib,>)
