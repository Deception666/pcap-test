cmake_minimum_required(
   VERSION 3.20.0)

set(
   lib_name
   pcap-internal)
set(
   lib_name_alias
   pcap::pcap)

add_library(
   ${lib_name}
   STATIC
   public/pcap/pcap.h
   source/pcap.cpp)

add_library(
   ${lib_name_alias}
   ALIAS
   ${lib_name})

set_target_properties(
   ${lib_name}
   PROPERTIES
   AUTOMOC no
   AUTOUIC no
   AUTORCC no)

target_compile_definitions(
   ${lib_name}
   PUBLIC
   $<$<STREQUAL:$<TARGET_PROPERTY:${lib_name},TYPE>,SHARED_LIBRARY>:pcap_internal_AS_SHARED_LIB>)

target_include_directories(
   ${lib_name}
   PUBLIC
   "${CMAKE_CURRENT_SOURCE_DIR}/public"
   PRIVATE
   "${CMAKE_CURRENT_SOURCE_DIR}/public/pcap")
