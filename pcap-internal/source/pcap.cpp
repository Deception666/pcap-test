/// This pcap implementation is a compatibility implementation that
/// dynamically loads the pcap library and forwards all calls onto the
/// loaded library.  This pcap implementation only provides the required
/// declarations needed to properly compile the pcap-test application.

#include "pcap.h"

#include <atomic>
#include <cstdio>
#include <memory>
#include <mutex>
#include <type_traits>
#include <utility>

#if _WIN32
#include <libloaderapi.h>

using LibraryHandle =
   std::shared_ptr<
      std::remove_pointer_t< HMODULE >
   >;

using FunctionProcedure =
   FARPROC;

#else // !_WIN32
#errro "Define for this platform!"
#endif // _WIN32

using LibraryHandleAtomic =
   std::atomic< LibraryHandle >;

static std::mutex pcap_library_mutex;
static LibraryHandleAtomic pcap_library;

static std::atomic_bool pcap_geterr_init;

static FunctionProcedure GetPCAPFunction(
   const char * const function_name )
{
   FunctionProcedure procedure { nullptr };

   std::atomic_thread_fence(
      std::memory_order_acquire);

   auto library_handle =
      pcap_library.load(
         std::memory_order_relaxed);

   if (!library_handle)
   {
      std::lock_guard lock {
         pcap_library_mutex };

      library_handle =
         pcap_library.load(
            std::memory_order_relaxed);

      if (!library_handle)
      {
#if _WIN32
         library_handle.reset(
            LoadLibraryW(L"wpcap.dll"),
            &FreeLibrary);
#else // !_WIN32
#error "Define for this platform!"
#endif // _WIN32

         std::atomic_thread_fence(
            std::memory_order_release);

         pcap_library.store(
            library_handle,
            std::memory_order_relaxed);
      }
   }

   if (library_handle)
   {
#if _WIN32
      procedure =
         GetProcAddress(
            library_handle.get(),
            function_name);
#else // !_WIN32
#error "Define for this platform!"
#endif // _WIN32
   }

   return
      procedure;
}

#if __cplusplus
extern "C"
{
#endif // __cplusplus

void pcap_close(
   pcap_t * capture_instance )
{
   const auto function =
      GetPCAPFunction(
         "pcap_close");
   
   if (function)
   {
      reinterpret_cast< decltype(&pcap_close) >(function)(
         capture_instance);
   }
}

pcap_t * pcap_open_live(
   const char * device_name,
   int capture_size,
   int promiscuous_mode,
   int read_timeout_ms,
   char * error_buffer )
{
   pcap_t * capture_instance { nullptr };

   const auto function =
      GetPCAPFunction(
         "pcap_open_live");
   
   if (function)
   {
      capture_instance =
         reinterpret_cast< decltype(&pcap_open_live) >(function)(
            device_name,
            capture_size,
            promiscuous_mode,
            read_timeout_ms,
            error_buffer);
   }

   return
      capture_instance;
}

int pcap_dispatch(
   pcap_t * capture_instance,
   int max_packets_to_process,
   pcap_handler callback,
   u_char * user_data )
{
   int packets_read { 0 };

   const auto function =
      GetPCAPFunction(
         "pcap_dispatch");
   
   if (function)
   {
      packets_read =
         reinterpret_cast< decltype(&pcap_dispatch) >(function)(
            capture_instance,
            max_packets_to_process,
            callback,
            user_data);
   }

   return
      packets_read;
}

int pcap_findalldevs(
   pcap_if_t ** interface_list,
   char * error_buffer )
{
   int error { -1 };

   const auto function =
      GetPCAPFunction(
         "pcap_findalldevs");
   
   if (!function)
   {
      if (error_buffer)
      {
         std::snprintf(
            error_buffer,
            PCAP_ERRBUF_SIZE,
            "Pcap library not loaded or 'pcap_findalldevs' "
            "function could not be found!");
      }
   }
   else
   {
      error =
         reinterpret_cast< decltype(&pcap_findalldevs) >(function)(
            interface_list,
            error_buffer);
   }

   return
      error;
}

void pcap_freealldevs(
   pcap_if_t * interface_list )
{
   const auto function =
      GetPCAPFunction(
         "pcap_freealldevs");
   
   if (function)
   {
      reinterpret_cast< decltype(&pcap_freealldevs) >(function)(
         interface_list);
   }
}

void pcap_freecode(
   struct bpf_program * filter_program )
{
   const auto function =
      GetPCAPFunction(
         "pcap_freecode");
   
   if (function)
   {
      reinterpret_cast< decltype(&pcap_freecode) >(function)(
         filter_program);
   }
}

int pcap_compile(
    pcap_t * capture_instance,
    struct bpf_program * filter_program,
    const char * filter_expression,
    int optimize_filter,
    uint32_t network_mask )
{
   int error { -1 };

   const auto function =
      GetPCAPFunction(
         "pcap_compile");
   
   if (function)
   {
      error =
         reinterpret_cast< decltype(&pcap_compile) >(function)(
            capture_instance,
            filter_program,
            filter_expression,
            optimize_filter,
            network_mask);
   }

   return
      error;
}

char * pcap_geterr(
   pcap_t * capture_instance )
{
   static char library_error[PCAP_ERRBUF_SIZE] { };

   if (!pcap_geterr_init)
   {
      std::snprintf(
         library_error,
         PCAP_ERRBUF_SIZE,
         "Pcap library not loaded or 'pcap_geterr' "
         "function could not be found!");

      pcap_geterr_init = true;
   }

   char * error {
      library_error
   };

   const auto function =
      GetPCAPFunction(
         "pcap_geterr");
   
   if (function)
   {
      error =
         reinterpret_cast< decltype(&pcap_geterr) >(function)(
            capture_instance);
   }

   return
      error;
}

int pcap_setfilter(
   pcap_t * capture_instance, 
   struct bpf_program * filter_program )
{
   int error { -1 };

   const auto function =
      GetPCAPFunction(
         "pcap_setfilter");
   
   if (function)
   {
      error =
         reinterpret_cast< decltype(&pcap_setfilter) >(function)(
            capture_instance,
            filter_program);
   }

   return
      error;
}

void pcap_breakloop(
   pcap_t * capture_instance )
{
   const auto function =
      GetPCAPFunction(
         "pcap_breakloop");
   
   if (function)
   {
      reinterpret_cast< decltype(&pcap_breakloop) >(function)(
         capture_instance);
   }
}

int pcap_datalink(
   pcap_t * capture_instance )
{
   int link_layer {
      PCAP_ERROR_NOT_ACTIVATED };

   const auto function =
      GetPCAPFunction(
         "pcap_datalink");
   
   if (function)
   {
      link_layer =
         reinterpret_cast< decltype(&pcap_datalink) >(function)(
            capture_instance);
   }

   return
      link_layer;
}

#if __cplusplus
}
#endif // __cplusplus
