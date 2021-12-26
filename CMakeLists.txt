# tested under linux mint
# will need to modify this for windows

cmake_minimum_required(
   VERSION 3.20.0)

project(
   pcap-test-project)

set(
   CMAKE_CXX_STANDARD
   17)

function(
   find_pcap )

   find_path(
      PCAP_ROOT_DIR
      NAMES
      pcap/pcap.h)

   if (NOT PCAP_ROOT_DIR)

      message(
         FATAL_ERROR
         "Unable to find the pcap.h header file!")

   endif ( )

   find_library(
      PCAP_LIBRARY
      NAMES
      pcap)

   if (NOT PCAP_LIBRARY)

      message(
         FATAL_ERROR
         "Unable to find the pcap library!")

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
      INTERFACE_INCLUDE_DIRECTORES ${PCAP_ROOT_DIR})

   mark_as_advanced(
      PCAP_ROOT_DIR
      PCAP_LIBRARY)

endfunction(
   find_pcap )

set(
   CMAKE_AUTOMOC yes)

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
   Widgets)
find_package(
   Threads)

target_link_libraries(
   ${proj_name}
   PRIVATE
   pcap::pcap
   Qt5::Core
   Qt5::Widgets
   Threads::Threads)
