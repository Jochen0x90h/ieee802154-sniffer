# iterate over boards and generate sniffer
foreach(COMPONENT ${coco-devboards_COMPONENT_NAMES})
	string(REGEX REPLACE ".*\\:" "" BOARD ${COMPONENT})
	message("*** Board: ${BOARD}")

	# check if board specific header exists
	if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${BOARD}/ieeeSniffer.hpp)
		set(NAME "ieeeSniffer-${BOARD}")

		add_executable(${NAME}
			ieeeSniffer.cpp
		)
		target_include_directories(${NAME}
			PRIVATE
				${BOARD}
		)

		# find link.ld of board
		get_target_property(INCLUDES ${COMPONENT} INTERFACE_INCLUDE_DIRECTORIES)
		target_link_directories(${NAME}
			PRIVATE
				${INCLUDES}
		)

		target_link_libraries(${NAME}
			coco::coco
			coco-loop::coco-loop
			coco-buffer::coco-buffer
			coco-usb::coco-usb
			coco-ieee802154::coco-ieee802154
			coco-zigbee::coco-zigbee
			coco-file::coco-file
			coco-pcap::coco-pcap
			${COMPONENT}
		)

		# generate hex file for flashing the target
		#generate_hex(${NAME})
	endif()
endforeach()
