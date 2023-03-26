#include <ieeeSniffer.hpp>
#include <coco/PcapReader.hpp>
#include <coco/PcapWriter.hpp>
#include <coco/crypt.hpp>
#include <coco/hash.hpp>
#include <coco/Nonce.hpp>
#include <coco/zigbee.hpp>
#include <coco/zcl.hpp>
#include <coco/greenpower.hpp>
#include <coco/CryptReader.hpp>
#include <coco/Ieee802154Radio.hpp>
#include <coco/ieee802154.hpp>
#include <coco/StringBuffer.hpp>
#include <coco/StreamOperators.hpp>
#include <map>
#include <string>
#include <filesystem>
#include <iostream>
#include <iomanip>


// logs ieee 802.15.4 traffic to a .pcap file

// PTM 215Z/216Z: Press A0 for 7 seconds to commission on channel 15, then A0 and B1 together to confirm

namespace fs = std::filesystem;
using namespace coco;
namespace ieee = ieee802154;
namespace zb = zigbee;
namespace gp = greenpower;


// security level to use, encrypted + 32 bit message integrity code
constexpr zb::SecurityControl securityLevel = zb::SecurityControl::LEVEL_ENC_MIC32;


// network key used by nwk layer, prepared for aes encryption/decryption
AesKey networkAesKey;

// link key used by aps layer, prepared for aes encryption/decryption
// todo: one link key per device
AesKey linkAesKey;


std::ostream &operator <<(std::ostream &s, String str) {
	s << std::string(str.data(), str.size());
	return s;
}

template <typename T>
std::ostream &operator <<(std::ostream &s, Dec<T> dec) {
	s << std::setw(dec.digitCount) << std::setfill('0') << std::dec << int64_t(dec.value);
	return s;
}

template <typename T>
std::ostream &operator <<(std::ostream &s, Hex<T> hex) {
	s << std::setw(hex.digitCount) << std::setfill('0') << std::hex << int64_t(hex.value);
	return s;
}


// print tinycrypt aes key
void printKey(char const *name, AesKey const &key) {
	std::cout << "AesKey const " << name << " = {{";
	bool first = true;
	for (auto w : key.words) {
		if (!first)
			std::cout << ", ";
		first = false;
		std::cout << "0x" << hex(w);
	}
	std::cout << "}};" << std::endl;
}



class PacketReader : public CryptReader {
public:
	/**
	 * Construct on data
	 */
	PacketReader(uint8_t *buffer, int size) : CryptReader(buffer, size) {}
	PacketReader(Buffer &buffer) : CryptReader(buffer) {}

	void restoreSecurityLevel(zb::SecurityControl securityLevel) {
		*this->current |= uint8_t(securityLevel);
	}
};



void handleGp(uint8_t const *mac, PacketReader &r);
void handleGpCommission(uint32_t deviceId, PacketReader &r);

void handleNwk(PacketReader &r);
void handleAps(PacketReader &r, uint8_t const *extendedSource);
void handleZdp(PacketReader &r);
void handleZcl(PacketReader &r, uint8_t destinationEndpoint);


void handleIeee(PacketReader &r) {
	// ieee 802.15.4 mac
	// -----------------
	uint8_t const *mac = r.current;

	// frame control
	auto frameControl = r.e16L<ieee::FrameControl>();

	uint8_t sequenceNumber = 0;
	if ((frameControl & ieee::FrameControl::SEQUENCE_NUMBER_SUPPRESSION) == 0) {
		sequenceNumber = r.u8();
		std::cout << "Seq " << dec(sequenceNumber) << "; ";
	}

	// destination pan/address
	bool haveDestination = (frameControl & ieee::FrameControl::DESTINATION_ADDRESSING_FLAG) != 0;
	if (haveDestination) {
		// destination address present

		// destination pan
		uint16_t destinationPan = r.u16L();
		std::cout << hex(destinationPan) << ':';

		// check if short or long addrssing
		if ((frameControl & ieee::FrameControl::DESTINATION_ADDRESSING_LONG_FLAG) == 0) {
			// short destination address
			uint16_t destination = r.u16L();

			std::cout << hex(destination);
		} else {
			// long destination address
			uint64_t destination = r.u64L();

			std::cout << hex(destination);
		}
		std::cout << " <- ";
	}

	// source pan/address
	bool haveSource = (frameControl & ieee::FrameControl::SOURCE_ADDRESSING_FLAG) != 0;
	if (haveSource) {
		// source address present

		// check if pan is present
		if ((frameControl & ieee::FrameControl::PAN_ID_COMPRESSION) == 0 || !haveDestination) {
			uint16_t sourcePan = r.u16L();
			std::cout << hex(sourcePan) << ':';
		}

		// check if short or long addrssing
		if ((frameControl & ieee::FrameControl::SOURCE_ADDRESSING_LONG_FLAG) == 0) {
			// short source address
			uint16_t source = r.u16L();

			std::cout << hex(source);
		} else {
			// long source address
			uint64_t source = r.u64L();

			std::cout << hex(source);
		}
	}
	if (haveDestination || haveSource)
		std::cout << "; ";

	auto frameType = frameControl & ieee::FrameControl::TYPE_MASK;
	switch (frameType) {
	case ieee::FrameControl::TYPE_BEACON:
		{
			uint16_t superframeSpecification = r.u16L();

			uint8_t gts = r.u8();

			uint8_t pending = r.u8();

			uint8_t protocolId = r.u8();

			uint16_t stackProfile = r.u16L();
			int type = stackProfile & 15;
			int protocolVersion = (stackProfile >> 4) & 15;
			bool routerFlag = stackProfile & 0x400;

			std::cout << "Beacon: " << dec(type) << ", " << dec(protocolVersion);
			if (routerFlag)
				std::cout << ", router";
			std::cout << std::endl;
		}
		break;
	case ieee::FrameControl::TYPE_COMMAND:
		{
			auto command = r.e8<ieee::Command>();

			switch (command) {
			case ieee::Command::ASSOCIATION_REQUEST:
				std::cout << "Association Request" << std::endl;
				break;
			case ieee::Command::ASSOCIATION_RESPONSE:
				std::cout << "Association Response" << std::endl;
				break;
			case ieee::Command::DATA_REQUEST:
				std::cout << "Data Request" << std::endl;
				break;
			case ieee::Command::ORPHAN_NOTIFICATION:
				std::cout << "Orphan Notification" << std::endl;
				break;
			case ieee::Command::BEACON_REQUEST:
				std::cout << "Beacon Request" << std::endl;
				break;
			default:
				std::cout << "Unknown Command" << std::endl;
			}
		}
		break;
	case ieee::FrameControl::TYPE_ACK:
		std::cout << "Ack" << std::endl;
		break;
	case ieee::FrameControl::TYPE_DATA:
		{
			auto version = r.peekE8<gp::NwkFrameControl>() & gp::NwkFrameControl::VERSION_MASK;
			switch (version) {
			case gp::NwkFrameControl::VERSION_2:
				handleNwk(r);
				break;
			case gp::NwkFrameControl::VERSION_3_GP:
				handleGp(mac, r);
				break;
			default:
				std::cout << "Unknown NWK Frame Version!" << std::endl;
			}
		}
		break;
	default:
		std::cout << "Unknown IEEE Frame Type" << std::endl;
	}
}


// Self-powered Devices
// --------------------

struct GpDevice {
	AesKey aesKey;
};

std::map<uint32_t, GpDevice> gpDevices;

void handleGp(uint8_t const *mac, PacketReader &r) {
	// zgp stub nwk header (encryption header starts here)
	r.setHeader();

	// frame control
	auto frameControl = r.e8<gp::NwkFrameControl>();

	// extended frame conrol
	gp::NwkExtendedFrameControl extendedFrameControl = gp::NwkExtendedFrameControl::NONE;
	if ((frameControl & gp::NwkFrameControl::EXTENDED) != 0)
		extendedFrameControl = r.e8<gp::NwkExtendedFrameControl>();
	auto securityLevel = extendedFrameControl & gp::NwkExtendedFrameControl::SECURITY_LEVEL_MASK;

	// device id
	uint32_t deviceId = r.u32L();
	std::cout << "Device Id: " << hex(deviceId) << "; ";

	if (securityLevel == gp::NwkExtendedFrameControl::SECURITY_LEVEL_NONE
		&& r.peekE8<gp::Command>() == gp::Command::COMMISSIONING)
	{
		// commissioning (PTM215Z/216Z: hold A0 down for 7 seconds)
		handleGpCommission(deviceId, r);
		return;
	}

	// get device (when the device was not commissioned, decryption will fail)
	GpDevice &device = gpDevices[deviceId];

	// security
	// --------
	// header: header that is not encrypted, payload is part of header for security levels 0 and 1
	// payload: payload that is encrypted, has zero length for security levels 0 and 1
	// mic: message integrity code, 2 or 4 bytes
	uint32_t securityCounter;
	int micLength;
	switch (securityLevel) {
	case gp::NwkExtendedFrameControl::SECURITY_LEVEL_CNT8_MIC16:
		// security level 1: 1 byte counter, 2 byte mic

		// header starts at mac sequence number and includes also payload
		r.setHeader(mac + 2);

		// use mac sequence number as security counter
		securityCounter = mac[2];

		// only decrypt message integrity code of length 2
		micLength = 2;
		r.setMessageFromEnd(micLength);
		break;
	case gp::NwkExtendedFrameControl::SECURITY_LEVEL_CNT32_MIC32:
		// security level 2: 4 byte counter, 4 byte mic

		// security counter
		securityCounter = r.u32L();

		// only decrypt message integrity code of length 4
		micLength = 4;
		r.setMessageFromEnd(micLength);
		break;
	case gp::NwkExtendedFrameControl::SECURITY_LEVEL_ENC_CNT32_MIC32:
		// security level 3: 4 byte counter, encrypted message, 4 byte mic

		// security counter
		securityCounter = r.u32L();

		// decrypt message and message integrity code of length 4
		r.setMessage();
		micLength = 4;
		break;
	default:
		// security is required
		return;
	}

	// check message integrity code or decrypt message, depending on security level
	Nonce nonce(deviceId, securityCounter);
	if (!r.decrypt(micLength, nonce, device.aesKey)) {
		if (securityLevel <= gp::NwkExtendedFrameControl::SECURITY_LEVEL_CNT32_MIC32) {
			std::cout << "Decrypt Error; ";
			// we can continue as data is not encrypted
		} else {
			std::cout << "Error while decrypting message!" << std::endl;
			return;
		}
	}

	std::cout << "Data:";
	int l = r.remaining();
	for (int i = 0; i < l; ++i)
		std::cout << ' ' << hex(r.current[i]);
	std::cout << std::endl;
}

void handleGpCommission(uint32_t deviceId, PacketReader &r) {
	// remove commissioning command (0xe0)
	r.u8();

	GpDevice device;

	// A.4.2.1.1 Commissioning

	// device type
	// 0x02: on/off switch
	auto deviceType = r.e8<gp::DeviceType>();

	// options
	auto options = r.e8<gp::Options>();
	if ((options & gp::Options::EXTENDED) != 0) {
		auto extendedOptions = r.e8<gp::ExtendedOptions>();;

		// security level capability (used in messages)
		auto securityLevel = extendedOptions & gp::ExtendedOptions::SECURITY_LEVEL_CAPABILITY_MASK;

		// check for key
		if ((extendedOptions & gp::ExtendedOptions::KEY_PRESENT) != 0) {
			uint8_t *key = r.current;
			if ((extendedOptions & gp::ExtendedOptions::KEY_ENCRYPTED) != 0) {
				// Green Power A.1.5.3.3.3

				// nonce
				Nonce nonce(deviceId, deviceId);

				// construct a header containing the device id
				DataBuffer<4> header;
				header.setU32L(0, deviceId);

				// in-place decrypt
				if (!decrypt(key, header.data(), 4, key, 16, 4, nonce, zb::za09LinkAesKey)) {
					std::cout << "Error while decrypting key!" << std::endl;
					return;
				}

				// skip key and MIC
				r.skip(16 + 4);
			} else {
				// skip key
				r.skip(16);
			}

			// print key
			std::cout << "Key: ";
			for (int i = 0; i < 16; ++i) {
				if (i > 0)
					std::cout << ":";
				std::cout << hex(key[i]);
			}
			std::cout << std::endl;

			// set key for device
			setKey(device.aesKey, Array<uint8_t const, 16>(key));
		}
		if ((extendedOptions & gp::ExtendedOptions::COUNTER_PRESENT) != 0) {
			uint32_t counter = r.u32L();
			std::cout << "Counter: 0x" << hex(counter) << std::endl;
		}
	}

	// check if we exceeded the end
	if (r.remaining() < 0)
		return;

	switch (deviceType) {
	case gp::DeviceType::ON_OFF_SWITCH:
		// hue switch

		break;
	case gp::DeviceType::GENERIC_SWITCH:
		// generic switch

		break;
	}

	gpDevices[deviceId] = device;
}


// zbee
// ----

void handleNwk(PacketReader &r) {
	// nwk header (encryption header starts here)
	r.setHeader();

	auto frameControl = r.e16L<zb::NwkFrameControl>();
	uint16_t destination = r.u16L();
	uint16_t source = r.u16L();
	uint8_t radius = r.u8();
	uint8_t nwkCounter = r.u8();
	std::cout << hex(destination) << " <- " << hex(source) << " (r " << dec(radius) << "); ";

	// destination
	if ((frameControl & zb::NwkFrameControl::DESTINATION) != 0) {
		uint8_t const *destination = r.current;
		r.skip(8);
	}

	// extended source
	if ((frameControl & zb::NwkFrameControl::EXTENDED_SOURCE) != 0) {
		uint8_t const *extendedSource = r.current;
		r.skip(8);
	}

	// source route
	if ((frameControl & zb::NwkFrameControl::SOURCE_ROUTE) != 0) {
		uint8_t relayCount = r.u8();
		uint8_t relayIndex = r.u8();
		std::cout << "source route";
		for (int i = 0; i < relayCount; ++i) {
			uint16_t relay = r.u16L();
			std::cout << ' ' << hex(relay);
		}
		std::cout << "; ";
	}

	// security header
	// note: does in-place decryption of the payload
	uint8_t const *extendedSource = nullptr;
	if ((frameControl & zb::NwkFrameControl::SECURITY) != 0) {
		// restore security level according to 4.3.1.2 step 1.
		r.restoreSecurityLevel(securityLevel);

		// security control field (4.5.1.1)
		auto securityControl = r.e8<zb::SecurityControl>();

		// key type
		if ((securityControl & zb::SecurityControl::KEY_MASK) != zb::SecurityControl::KEY_NETWORK) {
			std::cout << "Error: Only network key supported!" << std::endl;
			return;
		}

		// security counter
		uint32_t securityCounter = r.u32L();
		std::cout << "SecCnt " << hex(securityCounter) << "; ";

		// extended source
		if ((securityControl & zb::SecurityControl::EXTENDED_NONCE) == 0) {
			std::cout << "Error: Only extended nonce supported!" << std::endl;
			return;
		}
		extendedSource = r.current;
		r.skip(8);

		// key sequence number
		uint8_t keySequenceNumber = r.u8();

		// nonce (4.5.2.2)
		Nonce nonce(extendedSource, securityCounter, securityControl);

		// decrypt in-place (whole message, mic length of 4)
		r.setMessage();
		if (!r.decrypt(4, nonce, networkAesKey)) {
			std::cout << "Error: NWK Decryption failed!" << std::endl;
			return;
		}
	}

	auto frameType = frameControl & zb::NwkFrameControl::TYPE_MASK;
	if (frameType == zb::NwkFrameControl::TYPE_COMMAND) {
		// nwk command
		auto command = r.e8<zb::NwkCommand>();
		switch (command) {
		case zb::NwkCommand::ROUTE_REQUEST:
			std::cout << "Route Request ";
			{
				auto options = r.e8<zb::NwkCommandRouteRequestOptions>();
				uint8_t routeId = r.u8();
				uint16_t destinationAddress = r.u16L();
				uint8_t cost = r.u8();

				switch (options & zb::NwkCommandRouteRequestOptions::DISCOVERY_MASK) {
				case zb::NwkCommandRouteRequestOptions::DISCOVERY_SINGLE:
					std::cout << hex(destinationAddress);
					if ((options & zb::NwkCommandRouteRequestOptions::EXTENDED_DESTINATION) != 0)
						std::cout << " ext. dest.";
					break;
				case zb::NwkCommandRouteRequestOptions::DISCOVERY_MANY_TO_ONE_WITH_SOURCE_ROUTING:
					// https://www.digi.com/resources/documentation/Digidocs/90002002/Concepts/c_zb_many_to_one_routing.htm
					std::cout << "Many-to-One";
					break;
				default:
					break;
				}
			}
			std::cout << std::endl;
			break;
		case zb::NwkCommand::ROUTE_REPLY:
			std::cout << "Route Reply ";
			{
				auto options = r.e8<zb::NwkCommandRouteReplyOptions>();
				uint8_t routeId = r.u8();
				uint16_t originatorAddress = r.u16L();
				uint16_t destinationAddress = r.u16L(); // "Responder" in Wireshark
				uint8_t cost = r.u8();
			}
			std::cout << std::endl;
			break;
		case zb::NwkCommand::NETWORK_STATUS:
			std::cout << "Network Status" << std::endl;
			break;
		case zb::NwkCommand::LEAVE:
			std::cout << "Leave" << std::endl;
			break;
		case zb::NwkCommand::ROUTE_RECORD:
			// https://www.digi.com/resources/documentation/Digidocs/90001942-13/concepts/c_source_routing.htm
			std::cout << "Route Record:";
			{
				uint8_t relayCount = r.u8();
				for (int i = 0; i < relayCount; ++i) {
					uint16_t relay = r.u16L();
					std::cout << ' ' << hex(relay);
				}
			}
			std::cout << std::endl;
			break;
		case zb::NwkCommand::REJOIN_REQUEST:
			std::cout << "Rejoin Request" << std::endl;
			break;
		case zb::NwkCommand::REJOIN_RESPONSE:
			std::cout << "Rejoin Response" << std::endl;
			break;
		case zb::NwkCommand::LINK_STATUS:
			std::cout << "Link Status" << std::endl;
			break;
		default:
			std::cout << "Unknown NWK Command" << std::endl;
		}
	} else if (frameType == zb::NwkFrameControl::TYPE_DATA) {
		// nwk data
		handleAps(r, extendedSource);
	} else {
		std::cout << "Unknown NWK Frame Type!" << std::endl;
	}
}

void handleAps(PacketReader &r, uint8_t const *extendedSource) {
	// application support layer (encryption header starts here)
	r.setHeader();

	// frame control
	auto frameControl = r.e8<zb::ApsFrameControl>();
	auto frameType = frameControl & zb::ApsFrameControl::TYPE_MASK;
	if (frameType == zb::ApsFrameControl::TYPE_COMMAND) {
		// aps command
		uint8_t apsCounter = r.u8();

		// security header
		// note: does in-place decryption of the payload
		if ((frameControl & zb::ApsFrameControl::SECURITY) != 0) {
			// restore security level according to 4.4.1.2 step 5.
			r.restoreSecurityLevel(securityLevel);

			// security control field (4.5.1.1)
			auto securityControl = r.e8<zb::SecurityControl>();

			// security counter
			uint32_t securityCounter = r.u32L();

			// nonce (4.5.2.2)
			if ((securityControl & zb::SecurityControl::EXTENDED_NONCE) == 0) {
				if (extendedSource == nullptr) {
					std::cout << "Error: Only extended nonce supported!" << std::endl;
					return;
				}
			} else {
				extendedSource = r.current;
				r.skip(8);
			}
			Nonce nonce(extendedSource, securityCounter, securityControl);

			// select key
			auto keyType = securityControl & zb::SecurityControl::KEY_MASK;
			AesKey const *key;
			switch (keyType) {
			case zb::SecurityControl::KEY_LINK:
				key = &linkAesKey;
				break;
			case zb::SecurityControl::KEY_KEY_TRANSPORT:
				key = &zb::za09KeyTransportAesKey;
				break;
			case zb::SecurityControl::KEY_KEY_LOAD:
				key = &zb::za09KeyLoadAesKey;
				break;
			default:
				std::cout << "Error: Unsupported key type in APS security header!" << std::endl;
				return;
			}

			// decrypt in-place (mic length of 4)
			r.setMessage();
			if (!r.decrypt(4, nonce, *key)) {
				std::cout << "Error: APS Decryption failed!" << std::endl;
				return;
			}
		}

		auto command = r.e8<zb::ApsCommand>();
		switch (command) {
		case zb::ApsCommand::TRANSPORT_KEY:
			{
				std::cout << "Transport Key" << std::endl;
				auto keyType = r.e8<zb::StandardKeyType>();
				auto key = r.data8<16>();
				if (keyType == zb::StandardKeyType::NETWORK)
					uint8_t keySequenceNumber = r.u8();
				auto extendedDestination = r.data8<8>();
				auto extendedSource = r.data8<8>();

				// set key
				switch (keyType) {
				case zb::StandardKeyType::NETWORK:
					setKey(networkAesKey, key);
					break;
				case zb::StandardKeyType::TRUST_CENTER_LINK:
					setKey(linkAesKey, key);
					break;
				default:
					;
				}
			}
			break;
		case zb::ApsCommand::UPDATE_DEVICE:
			std::cout << "Update Device" << std::endl;
			break;
		case zb::ApsCommand::REQUEST_KEY:
			std::cout << "Request Key" << std::endl;
			break;
		case zb::ApsCommand::VERIFY_KEY:
			std::cout << "Verify Key" << std::endl;
			break;
		case zb::ApsCommand::CONFIRM_KEY:
			std::cout << "Confirm Key" << std::endl;
			break;
		default:
			std::cout << "Unknown APS Command!" << std::endl;
		}
	} else if (frameType == zb::ApsFrameControl::TYPE_DATA) {
		// aps data: zdp or zcl follow
		uint8_t destinationEndpoint = r.u8();
		if (destinationEndpoint == 0)
			handleZdp(r);
		else
			handleZcl(r, destinationEndpoint);
	} else if (frameType == zb::ApsFrameControl::TYPE_ACK) {
		// aps ack
		std::cout << "Ack" << std::endl;
	} else {
		std::cout << "Unknown APS Frame Type!" << std::endl;
	}
}

void handleZdp(PacketReader &r) {
	zb::ZdpCommand command = r.e16L<zb::ZdpCommand>();
	uint16_t profile = r.u16L();
	uint8_t sourceEndpoint = r.u8();
	uint8_t apsCounter = r.u8();

	switch (command) {
	case zb::ZdpCommand::NETWORK_ADDRESS_REQUEST:
		std::cout << "Network Address Request" << std::endl;
		break;
	case zb::ZdpCommand::EXTENDED_ADDRESS_REQUEST:
		std::cout << "Extended Address Request" << std::endl;
		break;
	case zb::ZdpCommand::EXTENDED_ADDRESS_RESPONSE:
		std::cout << "Extended Address Response" << std::endl;
		break;
	case zb::ZdpCommand::NODE_DESCRIPTOR_REQUEST:
		std::cout << "Node Descriptor Request" << std::endl;
		break;
	case zb::ZdpCommand::NODE_DESCRIPTOR_RESPONSE:
		std::cout << "Node Descriptor Response" << std::endl;
		break;
	case zb::ZdpCommand::SIMPLE_DESCRIPTOR_REQUEST:
		std::cout << "Simple Descriptor Request" << std::endl;
		break;
	case zb::ZdpCommand::SIMPLE_DESCRIPTOR_RESPONSE:
		std::cout << "Simple Descriptor Response" << std::endl;
		break;
	case zb::ZdpCommand::ACTIVE_ENDPOINT_REQUEST:
		std::cout << "Active Endpoint Request" << std::endl;
		break;
	case zb::ZdpCommand::ACTIVE_ENDPOINT_RESPONSE:
		std::cout << "Active Endpoint Response" << std::endl;
		break;
	case zb::ZdpCommand::MATCH_DESCRIPTOR_REQUEST:
		std::cout << "Match Descriptor Request" << std::endl;
		break;
	case zb::ZdpCommand::MATCH_DESCRIPTOR_RESPONSE:
		std::cout << "Match Descriptor Response" << std::endl;
		break;
	case zb::ZdpCommand::DEVICE_ANNOUNCEMENT:
		std::cout << "Device Announcement" << std::endl;
		break;
	case zb::ZdpCommand::BIND_REQUEST:
		std::cout << "Bind Request" << std::endl;
		break;
	case zb::ZdpCommand::BIND_RESPONSE:
		std::cout << "Bind Response" << std::endl;
		break;
	case zb::ZdpCommand::PERMIT_JOIN_REQUEST:
		std::cout << "Permit Joint Request" << std::endl;
		break;
	default:
		std::cout << "Unknown ZDP Command 0x" << hex(command) << std::endl;
	}
}

void handleZcl(PacketReader &r, uint8_t destinationEndpoint) {
	zcl::Cluster cluster = r.e16L<zcl::Cluster>();
	zcl::Profile profile = r.e16L<zcl::Profile>();
	uint8_t sourceEndpoint = r.u8();
	uint8_t apsCounter = r.u8();

	// cluster library frame
	auto frameControl = r.e8<zcl::FrameControl>();
	auto frameType = frameControl & zcl::FrameControl::TYPE_MASK;
	bool manufacturerSpecificFlag = (frameControl & zcl::FrameControl::MANUFACTURER_SPECIFIC) != 0;
	//bool directionFlag = frameControl & 0x80; // false: client to server, true: server to client

	uint8_t zclCounter = r.u8();

	std::cout << "ZclCnt " << dec(zclCounter) << "; ";

	if (frameType == zcl::FrameControl::TYPE_PROFILE_WIDE && !manufacturerSpecificFlag) {
		auto command = r.e8<zcl::Command>();
		switch (command) {
		case zcl::Command::CONFIGURE_REPORTING:
			std::cout << "Configure Reporting" << std::endl;
			break;
		case zcl::Command::CONFIGURE_REPORTING_RESPONSE:
			std::cout << "Configure Reporting Response" << std::endl;
			break;
		case zcl::Command::READ_ATTRIBUTES:
			std::cout << "READ Attributes; ";
			switch (cluster) {
			case zcl::Cluster::BASIC:
				{
					auto attribute = r.e16L<zcl::BasicAttribute>();

					switch (attribute) {
					case zcl::BasicAttribute::MODEL_IDENTIFIER:
						std::cout << "Model Identifier" << std::endl;
						break;
					default:
						std::cout << "Unknown Attribute" << std::endl;
					}
				}
				break;
			case zcl::Cluster::POWER_CONFIGURATION:
				{
					auto attribute = r.e16L<zcl::PowerConfigurationAttribute>();

					switch (attribute) {
					case zcl::PowerConfigurationAttribute::BATTERY_VOLTAGE:
						std::cout << "Battery Voltage" << std::endl;
						break;
					default:
						std::cout << "Unknown Attribute" << std::endl;
					}
				}
				break;
			case zcl::Cluster::IDENTIFY:
				std::cout << "Unknown Attribute" << std::endl;
				break;
			case zcl::Cluster::ON_OFF:
				std::cout << "Unknown Attribute" << std::endl;
				break;
			default:
				std::cout << "Unknown Attribute" << std::endl;
			}
			break;
		case zcl::Command::READ_ATTRIBUTES_RESPONSE:
			std::cout << "READ Attributes Response; ";
			switch (cluster) {
			case zcl::Cluster::BASIC:
				{
					auto attribute = r.e16L<zcl::BasicAttribute>();
					uint8_t status = r.u8();

					if (status == 0) {
						auto dataType = r.e8<zcl::DataType>();

						switch (attribute) {
						case zcl::BasicAttribute::MODEL_IDENTIFIER:
							{
								std::cout << "Model Identifier: " << r.string() << std::endl;
							}
							break;
						default:
							std::cout << "Unknown" << std::endl;
						}
					} else {
						std::cout << "Failed" << std::endl;
					}
				}
				break;
			case zcl::Cluster::POWER_CONFIGURATION:
				{
					auto attribute = r.e16L<zcl::PowerConfigurationAttribute>();
					uint8_t status = r.u8();

					if (status == 0) {
						auto dataType = r.e8<zcl::DataType>();

						switch (attribute) {
						case zcl::PowerConfigurationAttribute::BATTERY_VOLTAGE:
							{
								int value;
								switch (dataType) {
								case zcl::DataType::UINT8:
									value = uint8_t(r.u8());
									break;
								default:
									value = 0;
								}

								std::cout << "Battery Voltage " << dec(value / 10) << '.' << dec(value % 10) << "V" << std::endl;
							}
							break;
						default:
							std::cout << "Unknown" << std::endl;
						}
					} else {
						std::cout << "Failed" << std::endl;
					}
				}
				break;
			case zcl::Cluster::IDENTIFY:
				std::cout << "Unknown Attribute" << std::endl;
				break;
			case zcl::Cluster::ON_OFF:
				std::cout << "Unknown Attribute" << std::endl;
				break;
			default:
				std::cout << "Unknown Attribute" << std::endl;
			}
			break;
		case zcl::Command::REPORT_ATTRIBUTES:
			std::cout << "Report Attributes" << std::endl;
			break;
		case zcl::Command::DEFAULT_RESPONSE:
			std::cout << "Default Response" << std::endl;
			break;
		default:
			std::cout << "Unknown ZCL Command" << std::endl;
		}
	} else if (frameType == zcl::FrameControl::TYPE_CLUSTER_SPECIFIC && !manufacturerSpecificFlag) {
		switch (cluster) {
		case zcl::Cluster::BASIC:
			std::cout << "Cluster: Basic" << std::endl;
			break;
		case zcl::Cluster::POWER_CONFIGURATION:
			std::cout << "Cluster: Power Configuration" << std::endl;
			break;
		case zcl::Cluster::ON_OFF:
			std::cout << "Cluster: On/Off; ";
			{
				uint8_t command = r.u8();
				switch (command) {
				case 0:
					std::cout << "Off" << std::endl;
					break;
				case 1:
					std::cout << "On" << std::endl;
					break;
				case 2:
					std::cout << "Toggle" << std::endl;
					break;
				default:
					std::cout << "Unknown Command" << std::endl;
				}
			}
			break;
		case zcl::Cluster::LEVEL_CONTROL:
			std::cout << "Cluster: Level Control; " << std::endl;
			break;
		case zcl::Cluster::GREEN_POWER:
			std::cout << "Cluster: Green Power; ";
			{
				uint8_t command = r.u8();
				switch (command) {
				case 2:
					std::cout << "GP Proxy Commissioning Mode" << std::endl;
					break;
				default:
					std::cout << "Unknown Command" << std::endl;
				}
			}
			break;
		case zcl::Cluster::COLOR_CONTROL:
			std::cout << "Cluster: Color Control; " << std::endl;
			break;
		default:
			std::cout << "Unknown Cluster 0x" << hex(cluster) << std::endl;
		}
	} else {
		std::cout << "Unknown ZCL Frame Type" << std::endl;
	}
}


// receive packets
Coroutine receive(Buffer &radioBuffer, PcapWriter &pcapWriter) {
	bool headerWritten = false;
	uint32_t startTime = -1;
	while (true) {
		std::cout << "Waiting for connection of radio device to USB port ..." << std::endl;
		co_await radioBuffer.untilReady();
		std::cout << "Waiting for IEEE 802.15.4 packets ..." << std::endl;
		while (radioBuffer.ready()) {
			// wait for receive packet
			co_await radioBuffer.read();
			int transferred = radioBuffer.size();
			int size = transferred - Ieee802154Radio::RECEIVE_EXTRA_LENGTH;

			// get timestamp
			uint8_t const *ts = &radioBuffer.data()[transferred - 4];
			uint32_t timestamp = ts[0] | (ts[1] << 8) | (ts[2] << 16) | (ts[3] << 24);

			// first timestamp is zero
			if (startTime == -1)
				startTime = timestamp;
			timestamp -= startTime;

			std::cout << "timestamp: " << dec(timestamp / 1000000) << "." << dec(timestamp % 1000000) << std::endl;

			// dissect
			PacketReader r(radioBuffer.data(), size);
			handleIeee(r);

			// save to pcap
			if (pcapWriter.buffer().state() == Buffer::State::READY) {
				// write pcap header
				if (!headerWritten) {
					headerWritten = true;
					pcap::Header header;
					header.magic_number = 0xa1b2c3d4;
					header.version_major = 2;
					header.version_minor = 4;
					header.thiszone = 0;
					header.sigfigs = 0;
					header.snaplen = 128;
					header.network = pcap::Network::IEEE802_15_4;
					co_await pcapWriter.writeHeader(header);
				}

				// write pcap packet
				pcap::PacketHeader header;
				header.setTimestamp(timestamp);
				header.incl_len = size;
				header.orig_len = size + 2; // 2 byte crc not transferred
				co_await pcapWriter.writePacket(header, radioBuffer.data());
			}
		}
	}
}

// read packets from pcap file
Coroutine read(Loop &loop, File &file, PcapReader &pcapReader) {
	// wait until pcap file is open or opening of the file fails
	co_await select(file.untilOpen(), file.untilIdle());
	if (!file.open()) {
		// error: failed to open file
		loop.exit();
		co_return;
	}

	// read pcap header
	pcap::Header header;
	co_await pcapReader.readHeader(header);

	if (pcapReader.error()) {
		std::cerr << "Error: Could not read PCAP header!" << std::endl;
	} else if (header.network != pcap::Network::IEEE802_15_4) {
		std::cerr << "Error: Protocol not supported!" << std::endl;
	} else {
		// read packets
		while (true) {
			// read pcap packet
			pcap::PacketHeader header;
			uint8_t packet[FILE_BUFFER_SIZE];
			co_await pcapReader.readPacket(header, packet);

			if (pcapReader.error())
				break;

			// dissect
			PacketReader r(packet, header.incl_len);
			handleIeee(r);
		}
	}

	loop.exit();
}

int main(int argc, char const *argv[]) {
	fs::path inputFile;
	fs::path outputFile;
	bool haveKey = false;
	int radioChannel = 15;
	auto radioFlags = Ieee802154Radio::FilterFlags::PASS_ALL;
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];

		if (arg == "-k" || arg == "--key") {
			// get network key from argument
			++i;
			int k[16];
			sscanf(argv[i], "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
				&k[0], &k[1], &k[2], &k[3], &k[4], &k[5], &k[6], &k[7],
				&k[8], &k[9], &k[10], &k[11], &k[12], &k[13], &k[14], &k[15]);

			uint8_t key[16];
			for (int i = 0; i < 16; ++i)
				key[i] = k[i];

			setKey(networkAesKey, key);
			haveKey = true;
		} else if (arg == "-i" || arg == "--input") {
			// input pcap file
			++i;
			inputFile = argv[i];
		} else if (arg == "-c" || arg == "--channel") {
			// radio channel
			++i;
			radioChannel = atoi(argv[i]);
		} else if (arg == "-a" || arg == "--ack") {
			// ack all received packets
			radioFlags |= Ieee802154Radio::FilterFlags::HANDLE_ACK;
		} else {
			// output pcap file
			if (arg == "-o" )
				++i;
			outputFile = argv[i];
		}
	}
	if (!haveKey)
		std::cerr << "no network key given (-k x:y:z:...)" << std::endl;

	// either read from input .pcap file or from usb device
	if (inputFile.empty()) {
		// capture from radio device connected to usb

		Drivers drivers;
		if (!outputFile.empty())
			drivers.file.open((const char *)outputFile.u8string().c_str(), File::Mode::WRITE | File::Mode::TRUNCATE);

		// receive from radio
		drivers.node.configure(0, UINT64_C(0x0000133700001337), 1337, radioFlags);

		// start radio
		std::cout << "Start radio on channel " << dec(radioChannel) << std::endl;
		drivers.radio.start(radioChannel);

		// create pcap writer
		PcapWriter pcapWriter(drivers.fileBuffer);

		// receive from radio
		receive(drivers.radioBuffer, pcapWriter);
		drivers.loop.run();
	} else {
		// read from file

		DriversReader drivers;
		drivers.file.open((const char *)inputFile.u8string().c_str(), File::Mode::READ);

		// create pcap reader
		PcapReader pcapReader(drivers.fileBuffer);

		// read from pcap
		read(drivers.loop, drivers.file, pcapReader);
		drivers.loop.run();
	}
	return 0;
}
