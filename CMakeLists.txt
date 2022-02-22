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
      CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} /W4 /permissive- /D_WINSOCK_DEPRECATED_NO_WARNINGS")
   set(
      CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} /W4 /permissive- /D_WINSOCK_DEPRECATED_NO_WARNINGS \
      /Zc:__cplusplus")
endif ( )

set(
   CMAKE_CXX_STANDARD
   20)

function(
   dynamically_load_pcap )

   message(
      STATUS
      "Using internal pcap implementation that will "
      "dynamically load libpcap on the system.")

   add_subdirectory(
      pcap-internal)

endfunction(
   dynamically_load_pcap )

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
         "${WINPCAP_SDK_ROOT}")

   find_library(
      PCAP_LIBRARY
      NAMES
         pcap wpcap
      HINTS
         "${NPCAP_SDK_LIB_PATH}"
         "${WINPCAP_SDK_LIB_PATH}")

   if (NOT PCAP_ROOT_DIR OR
       NOT PCAP_LIBRARY)

      dynamically_load_pcap()

      return()

   endif ( )

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
   Threads)

find_package(
   Qt6
   QUIET
   COMPONENTS
   Core
   Gui
   Widgets)

if (NOT Qt6_FOUND)
   find_package(
      Qt5 5.15
      QUIET
      COMPONENTS
      Core
      Gui
      Widgets)
endif ( )

if (Qt6_FOUND OR Qt5_FOUND)
   target_link_libraries(
      ${proj_name}
      PRIVATE
      Qt::Core
      Qt::Gui
      Qt::Widgets)
else ( )
   message(
      FATAL_ERROR
      "Qt 5.15 or greater or Qt 6 required!")
endif ( )

target_link_libraries(
   ${proj_name}
   PRIVATE
   pcap::pcap
   Threads::Threads
   $<IF:$<BOOL:${WIN32}>,ws2_32.lib,>)

get_target_property(
   pcap_target
   pcap::pcap
   ALIASED_TARGET)

string(
   CONCAT
   pcap_runtime_output_directory
   "$<IF:"
      "$<IN_LIST:"
         "pcap_internal_AS_SHARED_LIB,"
         "$<TARGET_PROPERTY:"
            "pcap::pcap,"
            "INTERFACE_COMPILE_DEFINITIONS"
         ">"
      ">,"
      "$<TARGET_FILE_DIR:${proj_name}>,"
   ">")

set_target_properties(
   ${pcap_target}
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY ${pcap_runtime_output_directory})
