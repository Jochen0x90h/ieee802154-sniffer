#pragma once

#include <coco/platform/Loop_native.hpp>
#include <coco/platform/Ieee802154Radio_usb.hpp>
#include <coco/platform/File_native.hpp>
#include <coco/pcap.hpp>


using namespace coco;

constexpr int FILE_BUFFER_SIZE = sizeof(pcap::PacketHeader) + Ieee802154Radio::MAX_PAYLOAD_LENGTH;

// drivers for sniffer and pcap writing
struct Drivers {
	Loop_native loop;

	// usb
	UsbHost_native host{loop};
	UsbHost_native::Device device{host, [](const usb::DeviceDescriptor &deviceDescriptor) {
		return deviceDescriptor.idVendor == 0x1915 && deviceDescriptor.idProduct == 0x1337;
	}};

	// radio on usb
	Ieee802154Radio_usb radio{device};
	Ieee802154Radio_usb::Node node{radio, 1};
	Ieee802154Radio_usb::Buffer radioBuffer{node};

	// file
	File_native file{loop};
	File_native::Buffer<FILE_BUFFER_SIZE> fileBuffer{file};
};

// drivers pcap reading
struct DriversReader {
	Loop_native loop;

	// file
	File_native file{loop};
	File_native::Buffer<FILE_BUFFER_SIZE> fileBuffer{file};
};
