// program designed and tested for little-endian byte order machine

// note: winpcap redefines inline.  it needs to be commented out.
// note: while winpcap worked on win10 21H1 (19043.1415), certain
// aspects of the descriptions were not present as compared to npcap
// and this functionality may not work in later builds of the os.

#include <pcap/pcap.h>

#if _WIN32

#include <ws2def.h>
#include <WinSock2.h>

#elif __linux__

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>

#else

#error "Define for this platform!"

#endif // _WIN32

#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMenu>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTreeView>

#include <QtGui/QFont>
#include <QtGui/QCursor>
#include <QtGui/QGuiApplication>

#include <QtCore/QAbstractItemModel>
#include <QtCore/QDebug>
#include <QtCore/QItemSelection>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QMetaType>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtCore/QVariant>

#include <Qt>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace osi
{

// osi layer 2
namespace data_link
{

// ethernet packet header
struct ethernet
{
   uint8_t dest_mac[6];
   uint8_t src_mac[6];
   uint16_t type;
};

// vlan ethernet packet header
struct ethernet_vlan
{
   uint8_t dest_mac[6];
   uint8_t src_mac[6];
   uint16_t vlan_tpid;
   uint16_t vlan_tci;
   uint16_t type;
};

namespace msb
{
// constants in big-endian format describing the ethernet type
static constexpr uint16_t ETHERNET_TYPE_IPV4 { 0x0008 };
static constexpr uint16_t ETHERNET_TYPE_IPV6 { 0xDD86 };
static constexpr uint16_t ETHERNET_TYPE_VLAN { 0x0081 };
} // namespace msb

} // namespace data_link

// osi layer 3
namespace network
{

// ipv4 packet header
struct ipv4
{
   // these two are reversed due to bit ordering
   // of big-endian (network order) to little-endian
   uint8_t header_length : 4;
   uint8_t version : 4;
   uint8_t service_type;
   uint16_t total_length;
   uint16_t fragment_id;
   uint16_t fragment_flags_offset;
   uint8_t time_to_live;
   uint8_t protocol;
   uint16_t header_checksum;
   uint8_t source_ip[4];
   uint8_t destination_ip[4];
};

// types that describe the payload of ipv4 packet
static constexpr uint8_t PROTOCOL_ICMP { 1 };
static constexpr uint8_t PROTOCOL_TCP { 6 };
static constexpr uint8_t PROTOCOL_UDP { 17 };

// fragment flags and offset.  the first three bits
// represent the flags.  the rest represents the offset.
// these are in host byte order so swap the bytes of the packet.
static constexpr uint16_t FRAGMENT_OFFSET_MASK { 0x1FFF };
static constexpr uint16_t FRAGMENT_FLAG_MASK { 0xE000 };
static constexpr uint16_t FRAGMENT_FLAG_RESERVED { 0x8000 };
static constexpr uint16_t FRAGMENT_FLAG_DO_NOT_FRAGMENT { 0x4000 };
static constexpr uint16_t FRAGMENT_FLAG_MORE_FRAGMENTS { 0x2000 };

} // namespace network

// osi layer 4
namespace transport
{

// ipv4 packet payload for tcp
struct tcp
{
   uint16_t src_port;
   uint16_t dst_port;
   uint32_t sequence;
   uint32_t acknowledgement;
   // due to bit ordering of big-endian (network order)
   // to little-endian, the bits are in the right locations
   // to be used directly from the wire.
   uint8_t reserved1 : 4;
   uint8_t header_length : 4;
   uint8_t terminate_bit : 1;
   uint8_t synchronize_bit : 1;
   uint8_t reset_bit : 1;
   uint8_t push_bit : 1;
   uint8_t acknowledgement_bit : 1;
   uint8_t urgent_bit : 1;
   uint8_t reserved2 : 2;
   uint16_t window_size;
   uint16_t checksum;
   uint16_t urgent_pointer;
   // options are 0 - 40 bytes
   // tcp data follows the options
};

// ipv4 packet payload for icmp
struct icmp
{
   uint8_t type;
   uint8_t code;
   uint16_t checksum;
   // next 32-bits is defined by type and code
};

// ipv4 packet payload for icmp ping request / reply
struct icmp_echo :
   public icmp
{
   uint16_t id;
   uint16_t sequence;
};

// ipv4 packet payload for udp
struct udp
{
   uint16_t src_port;
   uint16_t dst_port;
   uint16_t total_length;
   uint16_t checksum;
};

} // namespace transport

} // namespace osi

/// @brief Defines a single packet of data that is setup to point
/// to the different locations within the packet.
using PacketData =
   std::tuple<
      double, /* time seconds */
      size_t, /* length of packet */
      std::unique_ptr< const char [] >, /* packet data */
      const osi::data_link::ethernet * const, /* ethernet header */
      const osi::network::ipv4 * const, /* ip header */
      const void * const /* ip payload */
   >;

/// @brief Defines a collection of packets.
using Packets =
   std::vector< PacketData >;

/// @brief Allows the qt system to recognize packet data
/// that will be signaled and slotted within the qt system.
static const auto qt_meta_type_std_vector_PacketData =
   qRegisterMetaType< std::shared_ptr< Packets > >(
      "std::shared_ptr< Packets >");

/// @brief The pcap capture handle that automatically
/// releases the memory once no longer needed.
using PCAPCapture =
   std::unique_ptr<
      pcap_t,
      void (*) ( pcap_t * const )
   >;

/// @brief A utility function to release a pcap capture
/// handle once no longer needed.  This is mainly used
/// by the PCAPCature handle declaration.
/// 
/// @param capture An instance of a pcap capture device.
void PCAPCloseCapture(
   pcap_t * const capture )
{
   if (capture)
   {
      pcap_close( 
         capture);
   }
}

/// @brief Opens a source on the specified interface.
/// 
/// @param device_name The interface name to open for
/// capturing ethernet packets.
/// 
/// @return A valid instance to a capture device; otherwise
/// a nullptr.
PCAPCapture OpenSource(
   const std::string & device_name )
{
   std::cout
      << "\n"
      << "Capturing packets for device '"
      << device_name
      << "'\n";

   char error[PCAP_ERRBUF_SIZE] { };

   const auto open_handle =
      pcap_open_live(
         device_name.c_str(),
         0x10000, /* maximum bytes to capture */
         1, /* on / off promiscuous mode */
         33, /* packet timeout ms */
         error);

   if (!open_handle)
   {
      std::cerr
         << "Unable to open device '"
         << device_name << "'!  Error: "
         << error
         << "\n";
   }
   else if (*error != '\0')
   {
      std::cout
         << "Warning: "
         << error
         << "\n";
   }

   return {
      open_handle,
      &PCAPCloseCapture
   };
}

/// @brief Defines the type of packet associated with
/// the ethernet packet.
/// 
/// @param nbo_type The network byte order representation
/// of the ethernet type to be identified.
/// 
/// @return A string representation of the type.
std::string IdentifyPacketType(
   const uint16_t nbo_type )
{
   std::string stype { "Unknown Type" };

   switch (nbo_type)
   {
   case osi::data_link::msb::ETHERNET_TYPE_IPV4:
      stype = "IPv4";
      break;
   case osi::data_link::msb::ETHERNET_TYPE_IPV6:
      stype = "IPv6";
      break;
   case osi::data_link::msb::ETHERNET_TYPE_VLAN:
      stype = "VLAN";
      break;
   }

   return
      stype;
}

/// @brief Formats a MAC address into a hexadecimal
/// dot notation for display.
/// 
/// @param mac The MAC address to format.
/// 
/// @return A formatted MAC address in hexadecimal
/// dot notation.
std::string FormatMediaAccessControl(
   const uint8_t (&mac)[6] )
{
   std::string smac;

   if (mac)
   {
      char buffer[32];

      std::snprintf(
         buffer,
         sizeof(buffer),
         "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
         mac[0],
         mac[1],
         mac[2],
         mac[3],
         mac[4],
         mac[5]);

      smac.assign(
         buffer);
   }

   return smac;
}

/// @brief Defines the type of payload associated within
/// an ipv4 packet.
/// 
/// @param protocol The ipv4 protocol type to identify.
/// 
/// @return A string representation of the protocol.
std::string IdentifyProtocol(
   const uint8_t protocol )
{
   std::string sprotocol { "Unknown Protocol" };

   switch (protocol)
   {
   case osi::network::PROTOCOL_ICMP:
      sprotocol = "ICMP";
      break;
   case osi::network::PROTOCOL_TCP:
      sprotocol = "TCP";
      break;
   case osi::network::PROTOCOL_UDP:
      sprotocol = "UDP";
      break;
   }

   return
      sprotocol;
}

/// @brief Defines the flags that are set within an
/// ipv4 packet header.
/// 
/// @param nbo_fragment_flags_offset The network byte
/// order of the fragment and flags attribute of the ipv4
/// packet header.
/// 
/// @return A string representation of the flags that are
/// currently set in the ipv4 packet header.
std::string InterpretFragmentFlags(
   const uint16_t nbo_fragment_flags_offset )
{
   const uint16_t fragment_flags_offset =
      ntohs(nbo_fragment_flags_offset);

   std::string sflags { "None" };

   if (fragment_flags_offset & osi::network::FRAGMENT_FLAG_MASK)
   {
      sflags.clear();

      const auto AddFlag =
         [ ] (
            const bool flag,
            const char * const flag_name,
            std::string & flags )
         {
            if (flag)
            {
               if (!flags.empty())
               {
                  flags += " and ";
               }

               flags += flag_name;
            }
         };

      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_RESERVED,
         "Reserved",
         sflags);
      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_DO_NOT_FRAGMENT,
         "Do Not Fragment",
         sflags);
      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_MORE_FRAGMENTS,
         "More Fragments",
         sflags);
   }

   return
      sflags;
}

/// @brief Calculates the fragment's byte offset.
/// 
/// @param nbo_fragment_flags_offset The network byte
/// order of the fragment and flags attribute of the ipv4
/// packet header.
/// 
/// @return The size in bytes of the fragment's offset.
uint32_t CalculateFragmentOffset(
   const uint16_t nbo_fragment_flags_offset )
{
   const uint16_t fragment_flags_offset =
      ntohs(nbo_fragment_flags_offset);

   const uint16_t offset =
      fragment_flags_offset &
      osi::network::FRAGMENT_OFFSET_MASK;
   
   return
      offset * 8;
}

/// @brief Calculates the ipv4 header's size.  The
/// header size from the packet represents the number
/// of 32-bit words that makup the header.
/// 
/// @param ip_header_size The number of 32-bit words.
/// 
/// @return The header size in bytes.
size_t CalculateIPHeaderSize(
   const uint8_t ip_header_size )
{
   return
      ip_header_size * sizeof(uint32_t);
}

/// @brief Formats an IPv4 address into a string
/// decimal dot notation.
/// 
/// @param address The ipv4 address to format.
/// 
/// @return A string decimal dot notation of a ipv4
/// address.
std::string FormatIPAddress(
   const uint8_t (&address)[4] )
{
   std::string saddress;

   if (address)
   {
      char buffer[32];

      std::snprintf(
         buffer,
         sizeof(buffer),
         "%u.%u.%u.%u",
         address[0],
         address[1],
         address[2],
         address[3]);

      saddress.assign(
         buffer);
   }

   return
      saddress;
}

/// @brief A utility function to capture data from the
/// capture source upto the captured timeout period.
/// This function can block longer than the configured
/// timeout and should be offloaded to a thread.
/// 
/// @param capture The capture device to read ethernet
/// packets from.
/// 
/// @return A collection of packets that have been
/// captured in the order they were received.
std::vector< PacketData > CapturePackets(
   const PCAPCapture & capture )
{
   std::vector< PacketData >
      packets;

   if (capture)
   {
      /// @brief The packet capture callback called when a packet
      /// is received.
      /// 
      /// @param user_data User defined data associated with the callback.
      /// This data is a vector of packet data that will be returned to the
      /// calling function.
      /// @param packet_header Describes the time and size of the packet.
      /// @param packet_data The captured packet data.  The size of the captured
      /// data is defined by the configured capture size.
      const auto packet_handler =
         [ ] (
            uint8_t * user_data,
            const pcap_pkthdr * const packet_header,
            const uint8_t * const  packet_data )
         {
            auto & packets =
               *reinterpret_cast< std::vector< PacketData > * >(
                  user_data);

            const double seconds =
               packet_header->ts.tv_sec +
               std::chrono::duration_cast<
               std::chrono::duration< double, std::ratio< 1, 1 > > >(
                  std::chrono::microseconds{ packet_header->ts.tv_usec }).count();

            // create a buffer to hold the captured buffer
#if __cplusplus >= 202002L
            auto data =
               std::make_unique_for_overwrite< char [] >(
                  packet_header->caplen);
#else
            auto data =
               std::make_unique< char [] >(
                  packet_header->caplen);
#endif

            // copy the data into the buffer
            std::memcpy(
               data.get(),
               packet_data,
               packet_header->caplen);

            // obtain the locations of the ethernet and ipv4 packets
            const auto ethernet_header =
               reinterpret_cast< const osi::data_link::ethernet * >(
                  data.get());
            const auto ipv4_header =
               reinterpret_cast< const osi::network::ipv4 * >(
                  ethernet_header + 1);

            // store the data in the packet at the back
            // the last value stores the ipv4 payload
            packets.emplace_back(
               seconds,
               packet_header->caplen,
               std::move(data),
               ethernet_header,
               osi::data_link::msb::ETHERNET_TYPE_IPV4 == ethernet_header->type ?
                  ipv4_header :
                  nullptr,
               reinterpret_cast< const uint8_t * >(ipv4_header) +
               CalculateIPHeaderSize(ipv4_header->header_length));
         };

      // capture data from the device and store them in
      // the packet data container.  due to how the timeout
      // works, this may block longer than the timeout, so
      // this function should be offloaded to a thread.
      pcap_dispatch(
         capture.get(),
         -1,
         packet_handler,
         reinterpret_cast< uint8_t * >(
            &packets));
   }

   return
      packets;
}

/// @brief The pcap devices handle supported by this device
/// for packet capture.  Once the handle is no longer needed,
/// the device memory will be released.
using PCAPDevices =
   std::unique_ptr<
      const pcap_if_t,
      void (*) ( const pcap_if_t * const )
   >;

/// @brief A utility function to release the memory
/// allocated by pcap_findalldevs.  This is mainly
/// used by the PCAPDevices handle.
/// 
/// @param devices A pointer to the capture pointer
/// interface list returned by pcap_findalldevs.
void PCAPFreeAllDevices(
   const pcap_if_t * const devices )
{
   if (devices)
   {
      pcap_freealldevs(
         const_cast< pcap_if_t * >(
            devices));
   }
}

/// @brief Obtains all of the devcies that pcap has
/// found and stores them in the pcap devices handle.
/// 
/// @return A pointer to a list of pcap devices found
/// for the system; otherwise, a nullptr.
PCAPDevices FindAllDevices( )
{
   PCAPDevices all_devices {
      nullptr,
      &PCAPFreeAllDevices
   };

   pcap_if_t * devices;
   char error[PCAP_ERRBUF_SIZE];

   const int32_t find_result =
      pcap_findalldevs(
         &devices,
         error);

   if (find_result <= PCAP_ERROR)
   {
      std::cerr
         << "Error in pcap_findalldevs: "
         << find_result
         << "\n";
   }
   else if (!devices)
   {
      std::cerr
         << "No capture devices found!\n";
   }
   else
   {
      all_devices.reset(
         devices);
   }
   
   return
      all_devices;
}

/// @brief Obtains a vector of interface names and
/// descriptions associated with the found pcap devices.
///   
/// @param devices A pointer to a list of pcap devices found
/// for the system.
/// 
/// @return A vector of name and description pairs.  The first
/// argument is the device name and the second argument is the
/// device description.  The order of the pairs is defined the
/// same as the order of the list of pcap devices.
std::vector< std::pair< std::string, std::string > >
GetInterfaceNames(
   const PCAPDevices & devices )
{
   std::vector< std::pair< std::string, std::string > >
      device_names;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         device_names.emplace_back(
            current_device->name,
            current_device->description ?
            current_device->description :
            std::string { });
      }
   }

   return
      device_names;
}

/// @brief Obtains all of device flags in human readable format
/// associated with the found pcap devices.
/// 
/// @param devices A pointer to a list of pcap devices found
/// for the system.
/// 
/// @return A vector of flags in human readable format.  The
/// order of the flags is defined the same as the order of the
/// list of pcap devices.
std::vector< std::string >
GetInterfaceFlags(
   const PCAPDevices & devices )
{
   std::vector< std::string >
      device_flags;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         std::string flags;

         flags +=
            current_device->flags & PCAP_IF_LOOPBACK ?
            "Is Loopback" :
            "Is Not Loopback";

// remove these flag checks if winpcap is defined
// winpcap has not been updated in a long time
// version checks cannot be done, as npcap has the
// same version as winpcap.
#ifndef PCAP_WINPCAP
         flags += "\n";

         flags +=
            current_device->flags & PCAP_IF_UP ?
            "Is Up\n" :
            "Is Down\n";

         flags +=
            current_device->flags & PCAP_IF_RUNNING ?
            "Is Running\n" :
            "Is Not Running\n";

         flags +=
            current_device->flags & PCAP_IF_WIRELESS ?
            "Is Wireless\n" :
            "Is Not Wireless\n";

         const auto connection_status =
            current_device->flags & PCAP_IF_CONNECTION_STATUS;

         switch (connection_status)
         {
         case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            flags +=
               "Connection Status Unknown";
            break;

         case PCAP_IF_CONNECTION_STATUS_CONNECTED:
            flags +=
               "Connection Status Connected";
            break;

         case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            flags +=
               "Connection Status Disconnected";
            break;

         case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
            flags +=
               "Connection Status Not Applicable";
            break;
         }
#endif // PCAP_WINPCAP

         device_flags.emplace_back(
            std::move(flags));
      }
   }

   return
      device_flags;
}

/// @brief Obtains all of the device addresses in human
/// readable format associated with the found interface's
/// socket address family.  This function decodes the IPv4
/// and IPv6 socket address families.
/// 
/// @param pcap_address An instance of the pcap addresses
/// associated witha device interface.
/// 
/// @return A human readable format of addresses for the device's
/// interface. 
std::string AddressToString(
   const pcap_addr_t * const pcap_address )
{
   std::string addresses;

   if (pcap_address)
   {
      addresses +=
         "Address Family: " +
         (pcap_address->addr ?
            std::to_string(
               pcap_address->addr->sa_family) :
            std::string { "Unknown" }) +
         "\n";

      if (pcap_address->addr)
      {
         switch (pcap_address->addr->sa_family)
         {
         case AF_INET:
            {
               const auto DecodeAddress =
                  [ ] (
                     const sockaddr * addr,
                     std::string prefix )
                  {
                     std::string decoded;

                     if (addr)
                     {
                        const auto addr_in =
                           reinterpret_cast< const sockaddr_in * >(
                              addr);

                        decoded +=
                           std::move(prefix) +
                           inet_ntoa(addr_in->sin_addr) +
                           "\n";
                     }

                     return
                        decoded;
                  };

               addresses +=
                  DecodeAddress(
                     pcap_address->addr,
                     "Addr Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->netmask,
                     "Net Mask Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->broadaddr,
                     "Broadcast Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->dstaddr,
                     "Destination Address: ");
            }

            break;

         case AF_INET6:
            {
               const auto DecodeAddress =
                  [ ] (
                     const sockaddr * addr,
                     std::string prefix )
                  {
                     std::string decoded;

                     if (addr)
                     {
                        char ipv6_address[INET6_ADDRSTRLEN];

                        const auto converted =
                           inet_ntop(
                              AF_INET6,
                              &reinterpret_cast< const sockaddr_in6 * >(
                                 addr)->sin6_addr,
                              ipv6_address,
                              sizeof(ipv6_address));

                        if (!converted)
                        {
                           decoded +=
                              "Unable to convert IPv6 address!\n";
                        }
                        else
                        {
                           decoded.append(
                              converted) +=
                              "\n";
                        }
                     }

                     return
                        decoded;
                  };

               addresses +=
                  DecodeAddress(
                     pcap_address->addr,
                     "Addr Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->netmask,
                     "Net Mask Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->broadaddr,
                     "Broadcast Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->dstaddr,
                     "Destination Address: ");
            }

            break;

         default:
            addresses +=
               "Not decoding address family!\n";

            break;
         }
      }
   }

   return
      addresses;
}

// obtains all of the device addresses in human readable format

/// @brief A utility function to decode the interface addresses
/// for the found capture devices.
///   
/// @param devices A pointer to a list of pcap devices found
/// for the system.
/// 
/// @return A vector of decoded interface addresses.  The order
/// of the addresses is defined the same as the order of the
/// list of pcap devices.
std::vector< std::string >
GetInterfaceAddresses(
   const PCAPDevices & devices )
{
   std::vector< std::string >
      device_addresses;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         std::string addresses;

         for (const auto * current_address { current_device->addresses };
              current_address;
              current_address = current_address->next)
         {
            addresses +=
               AddressToString(
                  current_address);
         }

         device_addresses.emplace_back(
            std::move(addresses));
      }
   }

   return
      device_addresses;
}

/// @brief A pcap filter associated with a capture
/// device.  The filter is used to capture certain
/// packets from the interface.  Once the handle is
/// no longer needed, it will be released back to
/// the system.
using PCAPFilter =
   std::unique_ptr<
      bpf_program,
      void (*) ( bpf_program * const ) >;

/// @brief A utility function to release the resources
/// associated with a pcap filter.  This is mainly used
/// by the PCAPFilter handle.
/// 
/// @param filter An instnace to a pcap filter.
void PCAPFreeFilter(
   bpf_program * const filter )
{
   if (filter)
   {
      pcap_freecode(
         filter);

      delete filter;
   }
}

/// @brief A utility function to create a filter on a
/// capture device.  The filter will filter for tcp,
/// udp, and icmp ip packets.
/// 
/// @param capture The capture device to create a filter
/// for.
/// 
/// @return An instance to a newly created filter; otherwise,
/// a nullptr.
PCAPFilter CreateAndSetFilter(
   const PCAPCapture & capture )
{
   PCAPFilter filter {
      nullptr,
      &PCAPFreeFilter
   };

   if (capture)
   {
      bpf_program raw_filter;

      auto error =
         pcap_compile(
            capture.get(),
            &raw_filter,
            "(ip and tcp) or (ip and udp) or (ip and icmp)",
            1, /* optimize */
            0 /* no net mask filter */);

      if (error <= PCAP_ERROR)
      {
         std::cerr
            << "Error creating filter: "
            << pcap_geterr(capture.get())
            << "\n";
      }
      else
      {
         filter.reset(
            new bpf_program { raw_filter });

         error =
            pcap_setfilter(
               capture.get(),
               filter.get());

         if (error <= PCAP_ERROR)
         {
            std::cerr
               << "Error setting filter: "
               << pcap_geterr(capture.get())
               << "\n";

            filter.reset();
         }
      }
   }

   return
      filter;
}

/// @brief A Qt abstract item model that displays
/// eithernet and ip packet information for a tree view.
class PCAPItemModel :
   public QAbstractItemModel
{
   Q_OBJECT;

public:
   PCAPItemModel(
      PCAPCapture capture,
      QObject * parent );
   virtual ~PCAPItemModel( );

   virtual int32_t columnCount(
      const QModelIndex & parent ) const override;
   virtual int32_t rowCount(
      const QModelIndex & parent ) const override;
   virtual QVariant headerData(
      int32_t section,
      Qt::Orientation orientation,
      int32_t role ) const override;
   virtual QModelIndex parent(
      const QModelIndex & index ) const override;
   virtual QVariant data(
      const QModelIndex & index,
      int32_t role ) const override;
   virtual QModelIndex index(
      int32_t row,
      int32_t column,
      const QModelIndex & parent ) const override;

signals:
   void NewCapturedPackets(
      const std::shared_ptr< Packets > & packets ) const;

public slots:
   void OnClearCapturedData( );

private slots:
   void OnNewCapturedPackets(
      const std::shared_ptr< Packets > & packets );

private:
   std::vector< PacketData > packets_;

   PCAPCapture capture_device_;

   bool quit_capture_;
   std::thread capture_thread_;

};

/// @brief Constructor - Constructs a new model for the tree view
/// and assigns capturing of packets to a thread.
/// 
/// @param capture The capture device to capture packets from.
/// @param parent The parent object that owns this model.
PCAPItemModel::PCAPItemModel(
   PCAPCapture capture,
   QObject * parent ) :
QAbstractItemModel { parent },
capture_device_ { std::move(capture) },
quit_capture_ { false }
{
   // start a new thread to capture packets on
   // continue to capture packets until told to quit
   capture_thread_ =
      std::thread {
         [ this ] ( )
         {
            do
            {
               // capture some packets
               auto packets =
                  CapturePackets(
                     capture_device_);

               if (!packets.empty())
               {
                  // if packets were captured, then
                  // return them to the model on the
                  // main thread of the application.
                  emit
                     NewCapturedPackets(
                        std::make_shared< Packets >(
                           std::move(packets)));
               }
            }
            while (!quit_capture_);
         }
      };

   // connect the thread to main thread for
   // when new packets have arrived.
   QObject::connect(
      this,
      &PCAPItemModel::NewCapturedPackets,
      this,
      &PCAPItemModel::OnNewCapturedPackets);
}

/// @brief Destructor - Releases the resources of the class
/// and joins the capture thread to the main thread.  This
/// function will block until thread is joined.
PCAPItemModel::~PCAPItemModel( )
{
   if (capture_thread_.joinable())
   {
      quit_capture_ = true;

      // force the loop and dispatch functions to
      // break from their internal loops.
      pcap_breakloop(
         capture_device_.get());

      capture_thread_.join();
   }
}

/// @brief Returns the number of columns associated
/// for the parent.  This model assumes only one level
/// of parents.
/// 
/// @param parent The parent level to define the number
/// of columns.
/// 
/// @return Returns the number of columns for the top-level
/// parent; otherwise, 0.
int32_t PCAPItemModel::columnCount(
   const QModelIndex & parent ) const
{
   int32_t count { };
   
   if (!parent.isValid())
   {
      count = 15;
   }

   return
      count;
}

/// @brief Returns the number of rows associated for the
/// parent.  This model assumes only one level of parents.
/// 
/// @param parent The parent level to define the number of
/// rows.
/// 
/// @return Returns the number of rows for the top-level
/// parent; otherwise, 0
int32_t PCAPItemModel::rowCount(
   const QModelIndex & parent ) const
{
   int32_t count { };

   if (!parent.isValid())
   {
      count =
         static_cast< int32_t >(
            packets_.size());
   }

   return
      count;
}

/// @brief Obtains the column names.  Columns cannot
/// be modified.
/// 
/// @param section The column location.
/// @param orientation The orientation of the column data.
/// @param role The defined role for the columns.
/// 
/// @return The column name associated with the section.
QVariant PCAPItemModel::headerData(
   int32_t section,
   Qt::Orientation orientation,
   int32_t role) const
{
   QVariant header;

   if (Qt::DisplayRole == role &&
       Qt::Horizontal == orientation)
   {
      switch (section)
      {
      case 0:
         header = QString { "#" };
         break;
      case 1:
         header = QString { "Time" };
         break;
      case 2:
         header = QString { "Length" };
         break;
      case 3:
         header = QString { "Ethernet Type" };
         break;
      case 4:
         header = QString { "Src MAC" };
         break;
      case 5:
         header = QString { "Dst MAC" };
         break;
      case 6:
         header = QString { "IP Version" };
         break;
      case 7:
         header = QString { "IP Header Size" };
         break;
      case 8:
         header = QString { "IP Total Length" };
         break;
      case 9:
         header = QString { "IP Frag ID" };
         break;
      case 10:
         header = QString { "IP Frag Flags" };
         break;
      case 11:
         header = QString { "IP Frag Offset" };
         break;
      case 12:
         header = QString { "IP Protocol" };
         break;
      case 13:
         header = QString { "IP Src" };
         break;
      case 14:
         header = QString { "IP Dst" };
         break;
      }
   }

   return
      header;
}

/// @brief A slot that defines when new packets have
/// been captured.  The packets will be sorted in the
/// order that they have been recieved.
/// 
/// @param packets A collection of recieved packets
/// sorted in the order they were recieved.
void PCAPItemModel::OnNewCapturedPackets(
   const std::shared_ptr< Packets > & packets )
{
   if (packets &&
       !packets->empty())
   {
      const auto current_packets_size =
         static_cast< int32_t >(packets_.size());
      const auto new_packets_size =
         static_cast< int32_t >(packets->size());

      beginInsertRows(
         QModelIndex { },
         current_packets_size,
         current_packets_size + new_packets_size - 1);

      for (auto & packet : *packets)
      {
         packets_.emplace_back(
            std::move(packet));
      }

      endInsertRows();
   }
}

/// @brief Obtains the parent index of the associated
/// index.  This model assumes just a top-level parent.
/// 
/// @param index The index to obtain the parent from.
/// 
/// @return The parent index.  This is always the top-level
/// parent.
QModelIndex PCAPItemModel::parent(
   const QModelIndex & index ) const
{
   std::ignore = index;

   return
      QModelIndex { };
}

/// @brief Obtains the data associated with the specified
/// index.
/// 
/// @param index The location of the data to be obtained.
/// @param role The defined role for the given index.  This
/// model will only display data.
/// 
/// @return A QString of data to be displayed at the
/// specified location.
QVariant PCAPItemModel::data(
   const QModelIndex & index,
   int32_t role ) const
{
   QVariant value;

   if (Qt::DisplayRole == role &&
       index.isValid() &&
       packets_.size() > index.row())
   {
      switch (index.column())
      {
      case 0:
         value =
            QString::number(
               index.row() + 1);
         break;

      case 1:
         value =
            QString::number(
               std::get< 0 >(packets_[index.row()]),
               'f',
               8);
         break;

      case 2:
         value =
            QString::number(
               std::get< 1 >(packets_[index.row()]));
         break;

      case 3:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     IdentifyPacketType(
                        ethernet_header->type));
            }
         }

         break;

      case 4:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     FormatMediaAccessControl(
                        ethernet_header->src_mac));
            }
         }

         break;

      case 5:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     FormatMediaAccessControl(
                        ethernet_header->dest_mac));
            }
         }

         break;

      case 6:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ipv4_header->version);
            }
         }

         break;

      case 7:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     CalculateIPHeaderSize(
                        ipv4_header->header_length));
            }
         }

         break;

      case 8:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ntohs(ipv4_header->total_length));
            }
         }

         break;

      case 9:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ntohs(ipv4_header->fragment_id));
            }
         }

         break;

      case 10:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     InterpretFragmentFlags(
                        ipv4_header->fragment_flags_offset));
            }
         }

         break;

      case 11:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     CalculateFragmentOffset(
                        ipv4_header->fragment_flags_offset));
            }
         }

         break;

      case 12:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     IdentifyProtocol(
                        ipv4_header->protocol));
            }
         }

         break;

      case 13:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     FormatIPAddress(
                        ipv4_header->source_ip));
            }
         }

         break;

      case 14:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     FormatIPAddress(
                        ipv4_header->destination_ip));
            }
         }

         break;
      }
   }

   return
      value;
}

/// @brief Returns an index for the row, column, and parent.
/// This model assume a single top-level parent.
/// 
/// @param row The current row of the index.
/// @param column The current column of the index.
/// @param parent The parent index for the row and column.
/// 
/// @return A model index with row, column, and packet data
/// for the specified row.
QModelIndex PCAPItemModel::index(
   int32_t row,
   int32_t column,
   const QModelIndex & parent ) const
{
   QModelIndex index;

   if (!parent.isValid())
   {
      index =
         createIndex(
            row,
            column,
            const_cast< PacketData * >(
               &packets_[row]));
   }

   return
      index;
}

/// @brief A slot that clears all of the currently captured
/// packets from the model.
void PCAPItemModel::OnClearCapturedData( )
{
   if (!packets_.empty())
   {
      beginRemoveRows(
         QModelIndex { },
         0,
         static_cast< int32_t >(
            packets_.size() - 1));

      packets_.clear();

      endRemoveRows();
   }
}

/// @brief A utility function that calculates the size
/// of the TCP header.
/// 
/// @param tcp_header_size The tcp header size expressed
/// as the number of 32-bit words.
/// 
/// @return The size in bytes of the TCP header.
size_t CalculateTCPHeaderSize(
   const uint8_t tcp_header_size )
{
   return
      tcp_header_size * sizeof(uint32_t);
}

/// @brief A utility function that formats data into a block
/// of hexadecimal rows and columns followed by their
/// ascii representation.
/// 
/// @param begin The start of the data block.
/// @param end The end of the data block (not inclusive)
/// @param stream The stream to format the data into.
void FormatDataBlocks(
   const uint8_t * begin,
   const uint8_t * const end,
   QTextStream & stream )
{
   const std::ptrdiff_t BYTES_PER_LINE { 16 };
   const std::ptrdiff_t EXTRA_SPACE_AT_BYTES { 8 };

   // save the current state to restore with
   const auto orig_number_flags =
      stream.numberFlags();
   const auto orig_field_width =
      stream.fieldWidth();
   const auto orig_pad_char =
      stream.padChar();

   // pad the bytes with '0' and make uppercase
   stream.setNumberFlags(
      QTextStream::UppercaseDigits);
   stream.setPadChar('0');

   while (begin < end)
   {
      // determine the number of bytes that
      // the current row will format
      const auto distance =
         end - begin;
      const auto stride =
         distance > BYTES_PER_LINE ?
         BYTES_PER_LINE :
         distance;

      // start off with hexadecimal
      stream.setIntegerBase(16);

      for (std::ptrdiff_t i { }; i < stride; ++i)
      {
         // if we reach the bytes that represent extra
         // space, add it now.  do not do the first byte.
         if (i && i % EXTRA_SPACE_AT_BYTES == 0)
         {
            stream
               << qSetFieldWidth(0)
               << " ";
         }

         // print the hexadecimal value
         stream
            << qSetFieldWidth(2)
            << *(begin + i)
            << qSetFieldWidth(0)
            << " ";
      }

      // we want to line up the ascii characters
      // correctly.  this if block checks when the
      // last line is reached to correctly space the
      // ascii characters to their starting location.
      if (BYTES_PER_LINE > stride)
      {
         // each hexadecimal value that is not inserted
         // into the stream takes up three spaces
         const auto gap =
            BYTES_PER_LINE - stride;

         for (std::ptrdiff_t i { }; gap > i; ++i)
         {
            stream << "   ";
         }

         // we determine how many extra spaces due to
         // block partioning is required.
         const auto extra_spaces =
            gap / EXTRA_SPACE_AT_BYTES;

         for (std::ptrdiff_t i { }; extra_spaces > i; ++i)
         {
            stream << " ";
         }
      }

      // move the next part of the line several spaces away
      // to start the ascii representation that was formatted
      stream << "     ";

      // print the decimal values now
      stream.setIntegerBase(10);

      for (std::ptrdiff_t i { }; i < stride; ++i)
      {
         // if we reach the bytes that represent extra
         // space, add it now.  do not do the first byte.
         if (i && i % EXTRA_SPACE_AT_BYTES == 0)
         {
            stream << " ";
         }

         // get the current value of the byte
         const auto value =
            *(begin + i);

         // determine if we can visualize the ascii value;
         // otherwise, just print a . if it cannot.
         if (0 <= value && value <= 31 || value >= 127)
         {
            stream << ".";
         }
         else
         {
            stream
               << static_cast< char >(value);
         }

         stream << " ";
      }

      // start a new line
      stream << "\n";

      // move the begin pointer the number of
      // bytes that were just formatted
      begin += stride;
   }

   // restore the stream flags
   stream.setNumberFlags(
      orig_number_flags);
   stream.setFieldWidth(
      orig_field_width);
   stream.setPadChar(
      orig_pad_char);
}

/// @brief A utility function to format the TCP packet
/// and its associated payload.
/// 
/// @param packet The packet to format.  This packet is
/// expected to have a TCP packet for the IP's payload.
/// 
/// @return A formatted string of formatted data for a
/// TCP packet.
QString FormatTCPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto tcp_header =
      reinterpret_cast< const osi::transport::tcp * >(
         std::get< 5 >(packet));

   if (tcp_header)
   {
      QTextStream stream {
         &spacket };

      const auto tcp_header_size =
         CalculateTCPHeaderSize(
            tcp_header->header_length);

      stream
         << "-- TCP Header --\n"
         << "        Source Port: " << ntohs(tcp_header->src_port) << "\n"
         << "   Destination Port: " << ntohs(tcp_header->dst_port) << "\n"
         << "         Sequence #: " << ntohl(tcp_header->sequence) << "\n"
         << "  Acknowledgement #: " << ntohl(tcp_header->acknowledgement) << "\n"
         << "        Header Size: " << tcp_header_size << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "           Reserved: " << (tcp_header->reserved1 | tcp_header->reserved2 << 4) << "\n";

      stream.setIntegerBase(10);

      stream
         << "         Urgent Bit: " << tcp_header->urgent_bit << "\n"
         << "Acknowledgement Bit: " << tcp_header->acknowledgement_bit << "\n"
         << "           Push Bit: " << tcp_header->push_bit << "\n"
         << "          Reset Bit: " << tcp_header->reset_bit << "\n"
         << "    Synchronize Bit: " << tcp_header->synchronize_bit << "\n"
         << "      Terminate Bit: " << tcp_header->terminate_bit << "\n"
         << "        Window Size: " << ntohs(tcp_header->window_size) << "\n";

      stream.setIntegerBase(16);

      stream
         << "           Checksum: " << ntohs(tcp_header->checksum) << "\n";

      stream.setIntegerBase(10);

      stream
         << "     Urgent Pointer: " << ntohs(tcp_header->urgent_pointer) << "\n";

      if (tcp_header_size > 20)
      {
         stream
            << "\n-- TCP Options --\n";

         const auto tcp_options =
            reinterpret_cast< const uint8_t * >(
               tcp_header + 1);

         FormatDataBlocks(
            tcp_options,
            tcp_options + tcp_header_size - 20,
            stream);
      }

      const auto ipv4_header =
         std::get< 4 >(packet);

      if (ipv4_header)
      {
         const auto tcp_data_begin =
            reinterpret_cast< const uint8_t * >(
               tcp_header) + tcp_header_size;
         const auto tcp_data_end =
            reinterpret_cast< const uint8_t * >(
               ipv4_header) + ntohs(ipv4_header->total_length);

         if (tcp_data_end > tcp_data_begin)
         {
            stream
               << "\n-- TCP Data --\n";

            FormatDataBlocks(
               tcp_data_begin,
               tcp_data_end,
               stream);
         }
      }
   }

   return
      spacket;
}

/// @brief A utility function to format the ICMP packet
/// and its associated payload.
/// 
/// @param packet The packet to format.  This packet is
/// expected to have a ICMP packet for the IP's payload.
/// 
/// @return A formatted string of formatted data for a
/// ICMP packet.
QString FormatICMPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto icmp_header =
      reinterpret_cast< const osi::transport::icmp * >(
         std::get< 5 >(packet));

   if (icmp_header)
   {
      QTextStream stream {
         &spacket };

      stream
         << "-- ICMP Header --\n"
         << "    Type: " << icmp_header->type << "\n"
         << "    Code: " << icmp_header->code << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "Checksum: " << ntohs(icmp_header->checksum) << "\n";

      stream.setIntegerBase(10);

      if (icmp_header->type == 0 || icmp_header->type == 8)
      {
         stream
            << "\n-- ICMP Echo "
            << (icmp_header->type == 0 ? "Reply --\n" : "Request --\n");

         const auto icmp_echo_header =
            reinterpret_cast< const osi::transport::icmp_echo * >(
               icmp_header);

         stream
            << "      ID: " << ntohs(icmp_echo_header->id) << "\n"
            << "Sequence: " << ntohs(icmp_echo_header->sequence) << "\n";
      }

      const auto ipv4_header =
         std::get< 4 >(packet);

      if (ipv4_header)
      {
         const auto header_size =
            icmp_header->type == 0 || icmp_header->type == 8 ?
               sizeof(osi::transport::icmp_echo) :
               sizeof(osi::transport::icmp);

         const auto icmp_data_begin =
            reinterpret_cast< const uint8_t * >(
               icmp_header) + header_size;
         const auto icmp_data_end =
            reinterpret_cast< const uint8_t * >(
               ipv4_header) + ntohs(ipv4_header->total_length);

         if (icmp_data_end > icmp_data_begin)
         {
            stream
               << "\n-- ICMP Data --\n";

            FormatDataBlocks(
               icmp_data_begin,
               icmp_data_end,
               stream);
         }
      }
   }

   return
      spacket;
}

/// @brief A utility function to format the UDP packet
/// and its associated payload.
/// 
/// @param packet The packet to format.  This packet is
/// expected to have a UPD packet for the IP's payload.
/// 
/// @return A formatted string of formatted data for a
/// UDP packet.
QString FormatUDPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto udp_header =
      reinterpret_cast< const osi::transport::udp * >(
         std::get< 5 >(packet));

   if (udp_header)
   {
      QTextStream stream {
         &spacket };

      const auto total_udp_size =
         ntohs(udp_header->total_length);

      stream
         << "-- UDP Header --\n"
         << "     Source Port: " << ntohs(udp_header->src_port) << "\n"
         << "Destination Port: " << ntohs(udp_header->dst_port) << "\n"
         << "      Total Size: " << total_udp_size << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "        Checksum: " << ntohs(udp_header->checksum) << "\n";

      stream.setIntegerBase(10);

         const auto udp_data_begin =
            reinterpret_cast< const uint8_t * >(
               udp_header + 1);
         const auto udp_data_end =
            reinterpret_cast< const uint8_t * >(
               udp_header) + total_udp_size;

         if (udp_data_end > udp_data_begin)
         {
            stream
               << "\n-- UDP Data --\n";

            FormatDataBlocks(
               udp_data_begin,
               udp_data_end,
               stream);
         }
   }

   return
      spacket;
}

/// @brief A utility function to call the associated
/// format function based on the IPv4's protocol.
/// 
/// @param packet The packet to format.
/// 
/// @return A formatted string of formatted data for the
/// specified packet.  If the packet cannot be decoded,
/// the return value is "Protocol Undefined".
QString FormatProtocol(
   const PacketData & packet )
{
   QString protocol { "Protocol Undefined" };

   const auto ipv4_header =
      std::get< 4 >(packet);

   if (ipv4_header)
   {
      switch (ipv4_header->protocol)
      {
      case osi::network::PROTOCOL_TCP:
         protocol =
           FormatTCPPacket(
              packet);
         break;
      case osi::network::PROTOCOL_UDP:
         protocol =
            FormatUDPPacket(
               packet);
         break;
      case osi::network::PROTOCOL_ICMP:
         protocol =
            FormatICMPPacket(
               packet);
         break;
      }
   }

   return
      protocol;
}

/// @brief A utility function used to format the packet
/// based on the incoming index.
/// 
/// @param index The index with the associated packet
/// data.
/// 
/// @return A formatted string that represents the packet;
/// otherwise, an empty string if the index containes no
/// packet.
QString FormatSelection(
   const QModelIndex & index )
{
   QString formatted;

   const auto packet =
      reinterpret_cast< const PacketData * >(
         index.internalPointer());

   if (packet)
   {
      formatted =
         FormatProtocol(
            *packet);
   }

   return
      formatted;
}

/// @brief The main entry point for the application.
/// 
/// @param argc The number of arguments associated with
/// the application.  This is not used by the program.
/// @param argv An array of argument values associated
/// with the application.  This is not used by the program.
/// 
/// @return 0 on success; otherwise, a error code.
int32_t main(
   int32_t argc,
   char * argv[] )
{
   // find all the devices associated with the system
   const auto all_devices =
      FindAllDevices();

   if (!all_devices)
   {
      return -1;
   }

   // obtain attributes about the devices
   // all of the returned vectors will be
   // the same in size and indices will be
   // the same for the devices found.
   const auto device_names =
      GetInterfaceNames(
         all_devices);

   const auto device_flags =
      GetInterfaceFlags(
         all_devices);

   const auto device_addresses =
      GetInterfaceAddresses(
         all_devices);

   // print out the information found to the console
   for (const auto & device_name : device_names)
   {
      // determine the current index within the container
      const auto index =
         std::distance(
            device_names.data(),
            &device_name);

      // print the name and description
      std::cout
         << index
         << ". "
         << device_name.first
         << " - "
         << device_name.second
         << "\n";

      // print out the associated flags
      const auto & device_flag =
         device_flags[index];

      std::cout
         << device_flag
         << "\n";

      // print the associated addresses
      const auto & device_address =
         device_addresses[index];

      std::cout
         << device_address
         << "\n\n";
   }

   // ask the user to select a device
   std::cout
      << "Which device to capture from: ";
   
   size_t device_index { ~0u };

   std::cin >> device_index;

   if (device_index > device_names.size())
   {
      // they chose poorly
      return -2;
   }
   else
   {
      // try to open the interface for capture
      auto capture_device =
         OpenSource(
            device_names[device_index].first);

      if (!capture_device)
      {
         // some kind of error happened
         return -3;
      }

      // make sure to capture for ethernet
      const auto datalink =
         pcap_datalink(
            capture_device.get());

      // we only want to capture eithernet packets
      if (datalink != DLT_EN10MB)
      {
         std::cerr
            << "Data link layer for this adapter must be "
               "10 / 100 / 1000 Mb and up ethernet!\n";

         return -4;
      }

      // try to create a filter to capture tcp, udp, and icmp
      const auto filter_code =
         CreateAndSetFilter(
            capture_device);

      if (!filter_code)
      {
         return -5;
      }

      // create a gui application
      QApplication application {
        argc,
        argv
      };

      // we are goingn to split the view into a
      // tree view on the left and a text display
      // on the right.
      QSplitter splitter;

      // the three view will hold the incoming packet
      // and the required eithernet and ipv4 data
      QTreeView tree_view;

      // assign the PCAP model to the tree view
      tree_view.setModel(
         std::make_unique< PCAPItemModel >(
            std::move(capture_device),
            &tree_view).release());

      // use this option to increase the performance
      // of the tree view.  with this option set, the
      // tree view can simplify calculations when trying
      // to scroll or perform mouse presses; otherwise,
      // it has to ask each row and its associated column
      // data for their heights.
      tree_view.setUniformRowHeights(
         true);

      // add the tree view first to have it be on the left.
      splitter.addWidget(
         &tree_view);

      // add a text display that does not wrap and cannot edit
      QPlainTextEdit text_edit;

      text_edit.setReadOnly(
         true);
      text_edit.setLineWrapMode(
         QPlainTextEdit::NoWrap);

      // set the associated font to be monospaced
#if _WIN32
      QFont font_text_edit {
         "Consolas",
         10
      };
#elif __linux__
      QFont font_text_edit {
         "FreeMono",
         10
      };
#else
#error "Define for this platform!"
#endif // _WIN32

      font_text_edit.setBold(
         true);

      text_edit.setFont(
         font_text_edit);

      // connect the tree view's selection model
      // to the specified lambda.  when a selection
      // changes, format the text of the index and
      // have it be displayed.
      QObject::connect(
         tree_view.selectionModel(),
         &QItemSelectionModel::selectionChanged,
         [ & ] (
            const QItemSelection & selected,
            const QItemSelection & deselected )
         {
            std::ignore = deselected;

            const auto indexes =
               selected.indexes();

            if (indexes.empty())
            {
               text_edit.setPlainText(
                  QString { });
            }
            else
            {
               text_edit.setPlainText(
                  FormatSelection(
                     indexes[0]));
            }
         }
      );

      // connect the tree view's button press signal
      // to the specified lambda.  when the button is
      // pressed on an item, a context menu will be
      // presented to allow the user to clear all the
      // packets from the tree view.
      QObject::connect(
         &tree_view,
         &QTreeView::pressed,
         [ & ] (
            const QModelIndex & index )
         {
            // only perform this on a right button click
            if (index.isValid() &&
                QGuiApplication::mouseButtons() & Qt::RightButton)
            {
               QMenu menu;

               const auto action =
                  menu.addAction(
                     "Clear Packets");

               if (action)
               {
                  const auto model =
                     dynamic_cast< PCAPItemModel * >(
                        tree_view.model());

                  if (model)
                  {
                     // connect the triggered action to the
                     // model's clear packets slot.
                     QObject::connect(
                        action,
                        &QAction::triggered,
                        model,
                        &PCAPItemModel::OnClearCapturedData);

                     menu.exec(
                        QCursor::pos());
                  }
               }
            }
         });

      // add the text display to the right
      splitter.addWidget(
         &text_edit);

      // show the splitter to show all items
      splitter.show();

      // allow the main loop to process messages
      const auto exec_results =
         application.exec();

      return
        exec_results;
   }
}

#include "main.moc"
