from time import time
from .py_bluetooth_utils import bluetooth_utils as btu
from socket import MSG_DONTWAIT
import bluetooth._bluetooth as bluez
from threading import Thread, Event, Lock
import struct
from queue import Queue
from collections import namedtuple
import subprocess

DEBUG_ENABLED = False


MAX_SINGLE_FLOAT_VALUE = 1.175494351e-38
MIN_SINGLE_FLOAT_VALUE = 3.402823466e38
MAX_DOUBLE_FLOAT_VALUE = 1.7976931348623157e308
MIN_DOUBLE_FLOAT_VALUE = 2.2250738585072014e-308


INT8_MIN = -128
RSSI_FILTER_WINDOW_MS = 512
OBSERVED_DATA_TIMEOUT_MS = 1000
BLE_ADVERTISEMENT_DATA_MAX_LENGTH = 31

# Max Advertisement Data Size (31) - Overhead (5)
OBSERVED_DATA_MAX_SIZE = BLE_ADVERTISEMENT_DATA_MAX_LENGTH - 5


## ---Type Codes, used for encoding/decoding data.---
## There can be at most 8 types since the values have to fit in 3 bits.
## Single Object indicates that the next value is the one and only value
# instead of a tuple.
PYBRICKS_BLE_BROADCAST_DATA_TYPE_SINGLE_OBJECT = 0
PYBRICKS_BLE_BROADCAST_DATA_TYPE_TRUE = 1
PYBRICKS_BLE_BROADCAST_DATA_TYPE_FALSE = 2
PYBRICKS_BLE_BROADCAST_DATA_TYPE_INT = 3
PYBRICKS_BLE_BROADCAST_DATA_TYPE_FLOAT = 4
PYBRICKS_BLE_BROADCAST_DATA_TYPE_STR = 5
PYBRICKS_BLE_BROADCAST_DATA_TYPE_BYTES = 6


MFG_SPECIFIC = 255  # (0xff)
LEGO_CID = b"\x03\x97"


PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH = 6
## The scan interval is 100ms according to the Pybricks GitHub.
PYBRICKS_BLE_SCAN_INTERVAL = 0xA0
PYBRICKS_BLE_SCAN_WINDOW = 0xA0
PYBRICKS_BLE_MIN_AD_INTERVAL = 0xA0
PYBRICKS_BLE_MAX_AD_INTERVAL = 0xA0


## HCI Opcode Group Fields (OGF)
# These correspond directly to their respective sections in the official
# Bluetooth core specification documents. The exception to this is
# OGF_NO_OPERATION and OGF_VENDOR_SPECIFIC_DEBUG_COMMANDS which don't
# seem to have a dedicated section.
OGF_NO_OPERATION = 0x00
OGF_LINK_CONTROL_COMMANDS = 0x01
OGF_LINK_POLICY_COMMANDS = 0x02
OGF_CONTROLLER_AND_BASEBAND_COMMANDS = 0x03
OGF_INFORMATIONAL_PARAMETER_COMMANDS = 0x04
OGF_STATUS_PARAMETER_COMMANDS = 0x05
OGF_TESTING_COMMANDS = 0x06
OGF_LE_CONTROLLER_COMMANDS = 0x08
OGF_VENDOR_SPECIFIC_DEBUG_COMMANDS = 0x3F


## HCI Opcode Command Fields (OCF)
OCF_NO_OPERATION = 0x0000
OCF_HCI_RESET = 0x0003
OCF_HCI_SET_EVENT_MASK = 0x0001
OCF_HCI_READ_BUFFER_SIZE = 0x0005
OCF_HCI_LE_SET_EVENT_MASK = 0x0001
OCF_HCI_LE_READ_BUFFER_SIZE = 0x0002
OCF_HCI_LE_SET_ADVERTISING_PARAMETERS = 0x0006
OCF_HCI_LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x0007
OCF_HCI_LE_SET_ADVERTISING_DATA = 0x0008
OCF_HCI_LE_SET_ADVERTISE_ENABLE = 0x000A
OCF_HCI_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_HCI_LE_SET_SCAN_ENABLE = 0x000C


## HCI Events & SubEvents
EVENT_COMMAND_COMPLETE = 0x0E
EVENT_COMMAND_STATUS = 0x0F
EVENT_LE_META = 0x3E
SUBEVENT_LE_ADVERTISING_REPORT = 0x02

## Event Masks
EVENT_MASK_ALL = 0xFFFFFFFFFFFFFFFF
EVENT_MASK_DEFAULT = 0x00001FFFFFFFFFFF
EVENT_MASK_LE_DEFAULT = 0x000000000000001F
EVENT_MASK_LE_META_EVENT = 0x2000000000000000
EVENT_MASK_LE_ADVERTISING_REPORT_EVENT = 0x0000000000000002
EVENT_MASK_HARDWARE_ERROR_EVENT = 0x0000000000008000

## The default recommended timeout value is 1000ms according to the
# Bluetooth 4.2 core specification.
# HCI_DEFAULT_TIMEOUT = 0xe803
HCI_DEFAULT_TIMEOUT = 0x0000

## LE Scan Types
LE_SCAN_TYPE_PASSIVE = 0x00
LE_SCAN_TYPE_ACTIVE = 0x01

## LE Scan Enable Values
LE_SCANNING_DISABLED = 0x00
LE_SCANNING_ENABLED = 0x01

## Filter Duplicates Values
FILTER_DUPLICATES_DISABLED = 0x00
FILTER_DUPLICATES_ENABLED = 0x01

## Advertising Type Values
ADV_IND = 0x00
ADV_DIRECT_IND = 0x01
ADV_SCAN_IND = 0x02
ADV_NONCONN_IND = 0x03
ADV_DIRECT_IND = 0x04

## Advertise Enable Values
ADVERTISING_DISABLED = 0x00
ADVERTISING_ENABLED = 0x01


## HCI Error Codes
RESPONSE_SUCCESS = 0x00
RESPONSE_UNKNOWN_HCI_COMMAND = 0x01
RESPONSE_UNKNOWN_CONNECTION_IDENTIFIER = 0x02
RESPONSE_HARDWARE_FAILURE = 0x03
RESPONSE_PAGE_TIMEOUT = 0x04
RESPONSE_AUTHENTICATION_FAILURE = 0x05
RESPONSE_PIN_OR_KEY_MISSING = 0x06
RESPONSE_MEMORY_CAPACITY_EXCEEDED = 0x07
RESPONSE_CONNECTION_TIMEOUT = 0x08
RESPONSE_CONNECTION_LIMIT_EXCEEDED = 0x09
RESPONSE_SYNCHRONOUS_CONNECTION_LIMIT_TO_A_DEVICE_EXCEEDED = 0x0A
RESPONSE_ACL_CONNECTION_ALREADY_EXISTS = 0x0B
RESPONSE_COMMAND_DISALLOWED = 0x0C
RESPONSE_CONNECTION_REJECTED_DUE_TO_LIMIT_RESOURCES = 0x0D
RESPONSE_CONNECTION_REJECTED_DUE_TO_SECURITY_REASONS = 0x0E
RESPONSE_CONNECTION_REJECTED_DUE_TO_UNACCEPTABLE_BD_ADDR = 0x0F
RESPONSE_CONNECTION_ACCEPT_TIMEOUT_EXCEEDED = 0x10
RESPONSE_UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE = 0x11
RESPONSE_INVALID_HCI_COMMAND_PARAMETERS = 0x12
RESPONSE_REMOTE_USER_TERMINATED_CONNECTION = 0x13
RESPONSE_REMOTE_USER_TERMINATED_CONNECTION = 0x14
## TODO: Finish this, they are the error codes from the Bluetooth 4.2
# core specifications.

ASYNC_BROADCAST_STOP = "async-broadcast-stop"
ASYNC_BROADCAST_START = "async-broadcast-start"
AsyncBroadcastCommand = namedtuple("AsyncBroadcastCommand", ["command", "payload"])


class HCIErrorCode(Exception):
    ## TODO: Add the descriptions from the Bluetooth 4.2 Core Specifications
    _ERROR_CODE_MESSAGES = [
        {
            "name": "Success",
            "description": "This is not an actual error, but is included to maintain consistency with the Bluetooth Core Specification document.",
        },
        {"name": "Unknown HCI Command"},
        {"name": "Unknown Connection Identifier"},
        {"name": "Hardware Failure"},
        {"name": "Page Timeout"},
        {"name": "Authentication Failure"},
        {"name": "Pin or Key Missing"},
        {"name": "Memory Capacity Exceeded"},
        {"name": "Connection Timeout"},
        {"name": "Connection Limit Exceeded"},
        {"name": "Synchronous Connection Limit to a Device Exceeded"},
        {"name": "ACL Connection Already Exists"},
        {
            "name": "Command Disallowed",
            "description": "The Command Disallowed error code indicates that the command requested cannot be executed because the Controller is in a state where it cannot process this command at this time. This error shall not be used for command OpCodes where the error code Unknown HCI Command is valid",
        },
        {"name": "Connection Rejected due to Limited Resources"},
        {"name": "Connection Rejected due to Security Reasons"},
        {"name": "Connection Rejected due to Unacceptable BD_ADDR"},
        {"name": "Connection Accept Timeout Exceeded"},
        {"name": "Unsupported Feature or Parameter Value"},
        {"name": "Invalid HCI Command Parameters"},
        {"name": "Remote User Terminated Connection"},
        {"name": "Remote User Terminated Connection Due to Low Resources"},
        {"name": "Remote User Terminated Connection Due to Power Off"},
        {"name": "Connection Terminated by Local Host"},
        {"name": "Repeated Attempts"},
        {"name": "Pairing not Allowed"},
        {"name": "Unknown LMP PDU"},
        {"name": "Unsupported Remote Feature / Unsupported LMP Feature"},
        {"name": "SCO Offset Rejected"},
        {"name": "SCO Interval Rejected"},
        {"name": "SCO Air Mode Rejected"},
        {"name": "Invalid LMP Parameters / Invalid LL Parameters"},
        {"name": "Unspecified Error"},
        {"name": "Unsupported LMP Parameter Value / Unsupported LL Parameter Value"},
        {"name": "Role Change not Allowed"},
        {"name": "LMP Response Timeout / LL Response Timeout"},
        {"name": "LMP Error Transaction Collision"},
        {"name": "LMP PDU not Allowed"},
        {"name": "Encryption Mode not Acceptable"},
        {"name": "Link Key Cannot be Changed"},
        {"name": "Requested QoS not Suported"},
        {"name": "Instant Passed"},
        {"name": "Pairing with Unit Key Not Supported"},
        {"name": "Different Transaction Collision"},
        {"name": "QoS Unacceptable Parameter"},
        {"name": "QoS Rejected"},
        {"name": "Channel Assessment not Supported"},
        {"name": "Insufficient Security"},
        {"name": "Parameter out of Mandatory Range"},
        {"name": "Role Switch Pending"},
        {"name": "Reserved Slot Violation"},
        {"name": "Role Switch Failed"},
        {"name": "Extended Inquiry Response too Large"},
        {"name": "Simple Pairing Not Supported By Host"},
        {"name": "Host Busy-Pairing"},
        {"name": "Connection Rejected due to no Suitable Channel Found"},
        {"name": "Controller Busy"},
        {"name": "Unacceptable Connection Parameters"},
    ]

    error_code = None
    message = None

    def __init__(self, error_code):
        self.error_code = error_code
        self.message = self.get_message_for_this_code(error_code)

        super().__init__(self.message)

    def get_message_for_this_code(self, error_code):
        return self._ERROR_CODE_MESSAGES[error_code]["name"]

    def get_description_for_this_code(self, error_code):
        if "description" in self._ERROR_CODE_MESSAGES[error_code]:
            return self._ERROR_CODE_MESSAGES[error_code]["description"]
        
        return None

    def output_formatted_description_if_it_exists(self):
        description = self.get_description_for_this_code(self.error_code)
        if description is not None:
            return "\n + {}".format(description)

        return ""


    def __str__(self):
        return "[HCIErrorCode]: {} - {} {}".format(self.error_code, self.message, self.output_formatted_description_if_it_exists())


def _log(string_content):
    """
    Internal function used to print messages to the console.

    Only prints messages when the DEBUG_ENABLED flag is set to true.

    @param `string_content` : Any string content that should be passed
                                into the print() function.
    """
    if DEBUG_ENABLED:
        print("[BrickBLE]: {}".format(string_content))


def get_uint16_little_endian(byte_buffer):
    return (byte_buffer[0] | byte_buffer[1] << 8).to_bytes(2, "big")


def wait_for_thread_signal_to_be_unset(thread_signal):
    """
    Blocks the thread until the specified thread signal is unset.

    @param `thread_signal` : A threading.Event instance to wait for.
    """
    while thread_signal.is_set():
        continue


## DEPRECATED
def bt_send_hci_command(
    hci_socket, opcode_group_field=0x00, opcode_command_field=0x0000, parameters=None
):
    """
    Sends a command to the Bluetooth Host-Controller Interface using the specified `hci_socket`.

    By default, this sends a NOP (No Operation) Command.
    """

    ## Save a copy of the old filter...
    old_filter = hci_socket.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    ## Create and apply a new socket filter to ensure that we can
    # read the event packets...
    new_filter = bluez.hci_filter_new()
    bluez.hci_filter_set_ptype(new_filter, bluez.HCI_EVENT_PKT)
    # bluez.hci_filter_all_events(new_filter)
    bluez.hci_filter_set_event(new_filter, EVENT_COMMAND_COMPLETE)
    hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, new_filter)

    if parameters is not None:
        bluez.hci_send_cmd(
            hci_socket, opcode_group_field, opcode_command_field, parameters
        )
    else:
        bluez.hci_send_cmd(hci_socket, opcode_group_field, opcode_command_field)

    ## Block and wait for the command complete or command status events
    raw_hci_packet = hci_socket.recv(255)
    packet_type, event_type, parameter_length = struct.unpack("BBB", raw_hci_packet[:3])

    ## Handle the events..
    status = None
    if event_type == EVENT_COMMAND_COMPLETE:
        (status,) = struct.unpack("B", raw_hci_packet[6:7])
    elif event_type == EVENT_COMMAND_STATUS:
        (status,) = struct.unpack("B", raw_hci_packet[3:4])
    else:
        raise Exception("Encountered an unexpected event type: {}".format(event_type))

    ## Handle the status...
    if status != 0:
        raise HCIErrorCode(status)

    ## Restore the old filter...
    hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)


def thread_ble_event_parser(
    event_exit_flag,
    event_main_requests_lock_flag,
    socket_lock,
    broadcast_queue,
    bt_hci_socket,
    handler=None,
):
    """
    The thread that handles parsing the BLE advertisment events.

    This is a redefinition of the blocking call to parse BLE advertising
    events from the "bluetooth_utils" library.

    Since we need to be able to kill the thread when the user ends
    the program, we mimic the logic the original function performs
    but we allow it to respond to the thread ending.

    @param `event_exit_flag` : A threading.Event instance, setting this
                                signals the thread to exit and perform
                                cleanup tasks.
    @param `event_main_request_lock_flag` : A threading.Event instance,
                                            setting this signals the
                                            thread to not obtain a lock
                                            to the hci_socket to allow
                                            the main thread to perform
                                            socket operations until it
                                            is done.
    @param broadcast_queue: A Queue containing advertising data to broadcast.
    @param `socket_lock` : A threading.Lock instance, this is used to
                            manage concurrent access to the HCI socket.
    @param `socket` : A socket to the Bluetooth's host controller
                        interface (HCI).
    @param `handler` : A function that handles the parsed advertising
                        data. It should take 2 parameters : First, the
                        advertising data and then the RSSI. E.g handler(ad_data, rssi)
    """


    try:
        ## Create the LE_META_EVENT packet filter...
        le_meta_event_filter = bluez.hci_filter_new()
        bluez.hci_filter_set_ptype(le_meta_event_filter, bluez.HCI_EVENT_PKT)
        bluez.hci_filter_set_event(le_meta_event_filter, EVENT_LE_META)

        ## Now, try to start scanning for BLE packets.
        bt_hci_le_set_scan_parameters(
            bt_hci_socket,
            scan_interval=PYBRICKS_BLE_SCAN_INTERVAL,
            scan_window=PYBRICKS_BLE_SCAN_WINDOW,
        )

        bt_hci_le_set_scan_enable(
            bt_hci_socket, LE_SCANNING_ENABLED, FILTER_DUPLICATES_ENABLED
        )
    except:
        raise Exception("[BrickBLE]: An error occured while initializing the scanning thread.")

    ## Now, we can start parsing the BLE advertising data.
    old_ble_filter = None
    is_broadcasting = False
    while not event_exit_flag.is_set():
        ## Broadcast if there are items in the queue.
        if broadcast_queue.empty() == False:
            ## There are items in the queue...
            _log("Broadcast Queue: {}".format(broadcast_queue))
            async_broadcast_command = broadcast_queue.get()

            if async_broadcast_command.command == ASYNC_BROADCAST_STOP:
                if is_broadcasting == True:
                    bt_hci_le_set_advertise_enable(bt_hci_socket, ADVERTISING_DISABLED)
                    is_broadcasting = False
                    _log("disabled advertising")
            elif async_broadcast_command.command == ASYNC_BROADCAST_START:
                if is_broadcasting == True:
                    bt_hci_le_set_advertising_data(bt_hci_socket, len(async_broadcast_command.payload), async_broadcast_command.payload)
                    _log("advertising data set to {}".format(async_broadcast_command.payload))
                else:
                    bt_hci_le_set_advertising_parameters(
                        bt_hci_socket,
                        PYBRICKS_BLE_MIN_AD_INTERVAL,
                        PYBRICKS_BLE_MAX_AD_INTERVAL,
                        ADV_NONCONN_IND,
                    )
                    _log("advertising parameters set")

                    bt_hci_le_set_advertising_data(bt_hci_socket, len(async_broadcast_command.payload), async_broadcast_command.payload)
                    _log("advertising data set")

                    bt_hci_le_set_advertise_enable(bt_hci_socket, ADVERTISING_ENABLED)
                    is_broadcasting = True
                    _log("broadcasting enabled")
            else:
                raise Exception("[BrickBLE]: Unknown async broadcast command sent: {}".format(async_broadcast_command.command))
            broadcast_queue.task_done()


        ## Otherwise, check if there are any spike packets being broadcasted.
        raw_hci_packet = None
        try:
            ## First, save the current socket filter...
            old_ble_filter = bt_hci_socket.getsockopt(
                bluez.SOL_HCI, bluez.HCI_FILTER, 14
            )
            _log("listener, saved old socket filter")

            ## Set the hci socket filter to only read LE_META_EVENT packet types.
            bt_hci_socket.setsockopt(
                bluez.SOL_HCI, bluez.HCI_FILTER, le_meta_event_filter
            )
            _log("listener, set le_meta_event_filter")

            ## Attempt to read packets from the socket...
            raw_hci_packet = bt_hci_socket.recv(255, MSG_DONTWAIT)
            _log("listener, received raw hci packet : {}".format(raw_hci_packet))
        except Exception as e:
            _log("listener, exception occured : {}".format(e))
        finally:
            ## We should restore the old socket filter after we're
            # done with it.
            bt_hci_socket.setsockopt(
                bluez.SOL_HCI, bluez.HCI_FILTER, old_ble_filter
            )
            _log("listener, restored old socket filter")

        ## We will continue to run the loop until the exit flag thread
        # event is set.
        if raw_hci_packet is None:
            ## If we didn't receive any data from the socket, then we skip...
            continue

        ## Otherwise, if we did receive data, extract the following...
        packet_type, hci_event_type, parameter_length = struct.unpack(
            "BBB", raw_hci_packet[:3]
        )

        if hci_event_type != EVENT_LE_META:
            ## If the packet that we read from the socket is not an LE_META_EVENT,
            # then we ignore it.
            continue

        (sub_event,) = struct.unpack("B", raw_hci_packet[3:4])
        if sub_event != SUBEVENT_LE_ADVERTISING_REPORT:
            ## We're only interested in handling BLE Advertising Events,
            # so we skip packets that don't indicate this flag.
            continue

        raw_hci_packet_copy = raw_hci_packet[4:]
        advertisement_data = raw_hci_packet_copy[9:-1]
        rssi = struct.unpack(
            "b", raw_hci_packet[len(raw_hci_packet) - 1 : len(raw_hci_packet)]
        )[0]
        _log("Advertising data: {}".format(advertisement_data))

        if handler is not None:
            ## If a handler is defined, we call the handler function.
            handler(advertisement_data, rssi)

    ## If we've reached this point, it means the exit flag event was
    # set by the calling thread, so we perform cleanup actions here.

def bt_hci_reset(hci_socket):
    """
    Sends a message to the HCI to reset the controller into a known state.

    @param hci_socket: A bluetooth HCI socket, retreived from hci_open_dev from PyBluez.
    """
    response = bluez.hci_send_req(
        hci_socket,
        OGF_CONTROLLER_AND_BASEBAND_COMMANDS,
        OCF_HCI_RESET,
        EVENT_COMMAND_COMPLETE,
        0x01,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_RESET")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))


    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_CONTROLLER_AND_BASEBAND_COMMANDS, OCF_HCI_RESET)


## DEPRECATED
def bt_hci_set_event_mask(hci_socket, event_mask=EVENT_MASK_DEFAULT):
    command_parameters = struct.pack(
        "<Q",
        event_mask,
    )

    status = bluez.hci_send_req(
        hci_socket,
        OGF_CONTROLLER_AND_BASEBAND_COMMANDS,
        OCF_HCI_SET_EVENT_MASK,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_CONTROLLER_AND_BASEBAND_COMMANDS, OCF_HCI_SET_EVENT_MASK, command_parameters)


## DEPRECATED
def bt_hci_le_set_event_mask(hci_socket, event_mask=EVENT_MASK_LE_DEFAULT):
    command_parameters = struct.pack(
        "<Q",
        event_mask,
    )

    status = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_EVENT_MASK,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_EVENT_MASK, command_parameters)


def bt_hci_le_read_buffer_size(hci_socket):
    """
    Sends a message to the HCI to read the maximum size of the payload for Asynchronous Connectionless HCI packets sent to the Bluetooth controller.

    @param hci_socket: A Bluetooth HCI socket, retreived from hci_open_dev from PyBluez.

    @returns: A tuple containing 2 parameters:
    - hc_le_data_packet_length
    - hc_total_num_le_data_packets

    @throws: HCIErrorCode
    """
    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_READ_BUFFER_SIZE,
        EVENT_COMMAND_COMPLETE,
        0x04,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_LE_READ_BUFFER_SIZE")
    (
        status, 
        hc_le_data_packet_length, 
        hc_total_num_le_data_packets
    ) = unpacked_response = struct.unpack(
        "<BHB", response
    )
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))

    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)

    return (hc_le_data_packet_length, hc_total_num_le_data_packets)


def bt_hci_read_buffer_size(hci_socket):
    response = bluez.hci_send_req(
        hci_socket,
        OGF_INFORMATIONAL_PARAMETER_COMMANDS,
        OCF_HCI_READ_BUFFER_SIZE,
        EVENT_COMMAND_COMPLETE,
        0x08,
        timeout=HCI_DEFAULT_TIMEOUT
    )
    _log("COMMAND SENT: HCI_READ_BUFFER_SIZE")
    (
        status, 
        hc_acl_data_packet_length,
        hc_synchronous_data_packet_length,
        hc_total_num_acl_data_packets,
        hc_total_num_synchronous_data_packets,
    ) = unpacked_response = struct.unpack(
        "<BHBHH", response
    )
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))

    if status != 0:
        raise HCIErrorCode(status)

    return (
        hc_acl_data_packet_length,
        hc_synchronous_data_packet_length,
        hc_total_num_acl_data_packets,
        hc_total_num_synchronous_data_packets,
    )


def bt_hci_le_set_scan_parameters(
    hci_socket,
    scan_type=LE_SCAN_TYPE_PASSIVE,
    scan_interval=0x0010,
    scan_window=0x0010,
    own_address_type=0x00,
    scanning_filter_policy=0x00,
):
    """
    Sends a message to the HCI to set the LE scan parameters.


    @param hci_socket: A bluetooth HCI socket, retreived from hci_open_dev from PyBluez.
    @param scan_type: Either LE_SCAN_TYPE_PASSIVE or LE_SCAN_TYPE_ACTIVE
    @param scan_interval: The time interval from when the controller started its last LE scan until it begins its next LE scan. Valid values are 0x0004 to 0x4000. This value is multiplied by 0.625ms to calculate the actual timeframe in milliseconds.
    @param scan_window: The duration of the LE scan. This value should be less than or equal to the scan_interval. Valid values are 0x0004 to 0x4000. This value is multiplied by 0.625ms to calculate the actual timeframe in milliseconds.
    @param own_address_type: ...
    @param scanning_filter_policy: ...

    TODO: Finish documenting this from the Bluetooth 4.2 Core Specifications.
    """

    ## The struct is:
    # little endian <
    # 1 byte    B
    # 2 bytes   H
    # 2 bytes   H
    # 1 byte    B
    # 1 byte    B
    command_parameters = struct.pack(
        "<BHHBB",
        scan_type,
        scan_interval,
        scan_window,
        own_address_type,
        scanning_filter_policy,
    )

    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_SCAN_PARAMETERS,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_LE_SET_SCAN_PARAMETERS")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))

    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_SCAN_PARAMETERS, command_parameters)


def bt_hci_le_set_scan_enable(hci_socket, scan_enable, filter_duplicates):
    """
    Sends a message to the HCI to start scanning.

    Scanning is used to discover advertising devices nearby.

    @param hci_socket: A bluetooth HCI socket, retreived from hci_open_dev from PyBluez.
    @param scan_enable: Either LE_SCANNING_ENABLED or LE_SCANNING_DISABLED.
    @param filter_duplicates: Either FILTER_DUPLICATES_DISABLED or FILTER_DUPLICATES_ENABLED.
    """
    command_parameters = struct.pack("<BB", scan_enable, filter_duplicates)
    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_SCAN_ENABLE,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_LE_SET_SCAN_ENABLE")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))


    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_SCAN_ENABLE, command_parameters)


def bt_hci_le_set_advertising_parameters(
    hci_socket,
    advertising_interval_min=0x0800,
    advertising_interval_max=0x0800,
    advertising_type=ADV_IND,
    own_address_type=0x00,
    peer_address_type=0x00,
    peer_address=(0,) * 6,
    advertising_channel_map=0b00000111,
    advertising_filter_policy=0x00,
):
    """
    Sends a message to the HCI to set the advertising parameters.

    @param hci_socket: A bluetooth HCI socket, retreived from hci_open_dev from PyBluez.
    @param advertising_interval_min: Minimum advertising interval for undirected and low duty cycle directed advertising. Valid values are from 0x0020 to 0x4000. This value is multiplied by 0.625ms to calculate the actual timeframe. This value should be less than or equal to the advertising_interval_max. They should not be the same value if you want to allow the controller to determine the best advertising interval given other activities.
    @param advertising_interval_max: Maximum advertising interval for undirected and low duty cycle directed advertising. Valid values are from 0x0020 to 0x4000. This value is multiplied by 0.625ms to calculate the actual timeframe.
    @param advertising_type: ...
    """
    command_parameters = struct.pack(
        "<HHBBB6BBB",
        advertising_interval_min,
        advertising_interval_max,
        advertising_type,
        own_address_type,
        peer_address_type,
        *peer_address,
        advertising_channel_map,
        advertising_filter_policy,
    )
    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_ADVERTISING_PARAMETERS,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_LE_SET_ADVERTISING_PARAMETERS")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))


    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_ADVERTISING_PARAMETERS, command_parameters)


## DEPRECATED
def bt_hci_le_read_advertising_channel_tx_power(hci_socket):
    """
    Sends a message to the HCI to read the transmit power level used for LE advertising channel packets.

    @param hci_socket: A bluetooth HCI socket, retreived from hci_open_dev from PyBluez.
    @returns: The transmit power level in dBm with an accuracy of +/- 4dB. Values range from -20 to 10.
    """
    # status = bluez.hci_send_req(
    #         hci_socket,
    #         OGF_LE_CONTROLLER_COMMANDS,
    #         OCF_HCI_LE_READ_ADVERTISING_CHANNEL_TX_POWER,
    #         EVENT_COMMAND_COMPLETE,
    #         0x02,
    #         timeout=HCI_DEFAULT_TIMEOUT
    #     )
    # _log("Testing the output from a function with multiple return values: {}".format(status))
    # if status[0] != RESPONSE_SUCCESS:
    #     raise HCIErrorCode(status)

    # return status[1]


def bt_hci_le_set_advertising_data(
    hci_socket, advertising_data_length, advertising_data
):
    """
    Sends a message to the HCI to set the data used in the advertising packets that have a data field.

    Only the significant part of the advertising_data is transmitted in the advertising packets.

    @param advertising_data_length: Number of significant octets in the advertising data.
    @param advertising_data: 31 octets of advertising data.
    """
    command_parameters = struct.pack(
        "<B{}B".format(advertising_data_length),
        advertising_data_length,
        *advertising_data,
    )
    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_ADVERTISING_DATA,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )

    _log("COMMAND SENT: HCI_LE_SET_ADVERTISING_DATA")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))

    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_ADVERTISING_DATA, command_parameters)


def bt_hci_le_set_advertise_enable(hci_socket, advertising_enable=ADVERTISING_DISABLED):
    """
    Sends a message to the HCI to enable or disable BLE advertising.

    The controller manages the timing of advertisements as per the advertising parameters given in LE_SET_ADVERTISING_PARAMETERS.

    The controller will continue to advertise until the host issues this command again with the disabled flag, or a connection is created or the advertising is timed out due to high duty cycle directed advertising.
    """
    command_parameters = struct.pack(
        "<B",
        advertising_enable,
    )
    response = bluez.hci_send_req(
        hci_socket,
        OGF_LE_CONTROLLER_COMMANDS,
        OCF_HCI_LE_SET_ADVERTISE_ENABLE,
        EVENT_COMMAND_COMPLETE,
        0x01,
        params=command_parameters,
        timeout=HCI_DEFAULT_TIMEOUT,
    )
    _log("COMMAND SENT: HCI_LE_SET_ADVERTISE_ENABLE")
    (status, ) = unpacked_response = struct.unpack("<B", response)
    _log(" + raw response: {}".format(response))
    _log(" + unpacked response: {}".format(unpacked_response))

    if status != RESPONSE_SUCCESS:
        raise HCIErrorCode(status)
    # bt_send_hci_command(hci_socket, OGF_LE_CONTROLLER_COMMANDS, OCF_HCI_LE_SET_ADVERTISE_ENABLE, command_parameters)


class BrickBLE(object):

    # TODO: Enforce singleton pattern.

    # The broadcast channel is has a valid value from 0 to 255.
    _broadcast_channel = 0

    # The observe channels are a dictionary with the keys specifying the
    # channels that this object is observing along with values which contain
    # another dictionary.
    _observed_channel_data = {}

    ## specifies the default Bluetooth device to use.
    _device_id = 0

    ## Stores the handle to the HCI Socket retrieved when we open a
    # socket connection to the Host Controller Interface (HCI) using Bluez.
    _hci_socket = None

    ## Stores a handle to the Thread containing the infinite loop that
    # scans for BLE advertising packets.
    _scanning_thread = None

    ## Stores a handle to the Thread Event containing the exit flag which
    # will be used to exit the infinite loop inside the scanning thread.
    _scanning_thread_exit_event = None

    ## Internal flag to determine whether or not the radio is broadcasting.
    _is_broadcasting = False

    ## This is a Python threading lock object used to synchronize access to
    # the Bluetooth controller between the main thread and the scanning thread.
    _socket_lock = None

    ## Contains a handle to the Thread event containing the request lock
    # flag which will be used to determine when the main thread can
    # acquire the lock from the infinite loop inside the scanning thread.
    _main_thread_request_lock_event = None

    _broadcast_queue = None

    def __init__(self, broadcasting_channel, observing_channels):
        try:
            ## First, try to ensure that the Bluetooth controller is powered.
            btu.toggle_device(self._device_id, True)


            ## Reset the device to a known state.
            # TODO: Figure out what HCI calls this command sends and implement it
            # instead of relying on the external system call.
            subprocess.run(["sudo", "hciconfig", "hci{}".format(self._device_id), "reset"])


            ## Then, try to open a socket connection to the Bluetooth
            # Host Controller Interface (HCI).
            self._hci_socket = bluez.hci_open_dev(self._device_id)


            ## Reset the controller to a known state.
            #bt_hci_reset(self._hci_socket)


            # ## Read the Buffer size for the LE controller.
            # (
            #     le_acl_data_packet_length, 
            #     total_number_of_le_acl_data_packets
            # ) = bt_hci_le_read_buffer_size(self._hci_socket)

            # if le_acl_data_packet_length == 0:
            #     ## This means that there is no LE specific buffer and that
            #     # it shares the buffer size with BR/EDR.
            #     _log("There is no LE specific data packet buffer, therefore it shares the buffer size with BR/EDR")
            #     (
            #         acl_data_packet_length,
            #         synchronous_data_packet_length,
            #         total_number_of_acl_data_packets,
            #         total_number_of_synchronous_data_packets
            #     ) = bt_hci_read_buffer_size(self._hci_socket)




            # new_filter = bluez.hci_filter_new()
            # bluez.hci_filter_set_ptype(new_filter, bluez.HCI_EVENT_PKT)
            # bluez.hci_filter_set_event(new_filter, EVENT_COMMAND_COMPLETE)
            # # bluez.hci_filter_all_events(new_filter)
            # self._hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, new_filter)

            ## Create a new Thread for parsing the BLE Scan Events and
            # initialize the lock object to prevent concurrent access.
            self._broadcast_queue = Queue()
            self._socket_lock = Lock()
            self._scanning_thread_exit_event = Event()
            self._main_thread_request_lock_event = Event()
            self._scanning_thread = Thread(
                target=thread_ble_event_parser,
                args=(
                    self._scanning_thread_exit_event,
                    self._main_thread_request_lock_event,
                    self._socket_lock,
                    self._broadcast_queue,
                    self._hci_socket,
                    self._handle_observe_event,
                ),
            )
            # TODO: Add error-checkin

            ## Set the default broadcasting channel.
            self._broadcast_channel = broadcasting_channel

            ## Initialize the dictionary used to store data for observed channels.
            for c in observing_channels:
                self._observed_channel_data.setdefault(
                    c,
                    {"timestamp": time(), "channel": c, "rssi": INT8_MIN, "data": None},
                )

            ## Start the BLE scanning thread.
            self._scanning_thread.start()

        except:
            raise Exception(
                "An error occured while initializing the PyBrick BLE Module."
            )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._broadcast_queue.join()

        ## Set the exit event flag for the scanning thread, to indicate
        # that it should stop scanning and exit the loop to begin cleanup.
        self._scanning_thread_exit_event.set()

        ## IMPORTANT: We have to wait for the thread to join before disabling
        # the BLE Scanning. If we try to disable the LE scan before the scanning
        # thread finishes, the program will hang.
        self._scanning_thread.join()

        ## Since the thread is now joined, we no longer need to worry
        # about sharing the socket resource.

        ## Disable BLE Broadcasting in case we were advertising data.
        bt_hci_le_set_advertise_enable(self._hci_socket, ADVERTISING_DISABLED)

        bt_hci_le_set_scan_enable(
            self._hci_socket, LE_SCANNING_DISABLED, FILTER_DUPLICATES_DISABLED
        )


        ## Close the socket to the HCI.
        self._hci_socket.close()
        _log("BrickBLE resources cleaned up successfully!")

    ## DEPRECATED
    def _lookup_observed_data(self, channel):
        """
        Looks up a channel in the observed data table.

        @param `channel`: The channel number (1 to 255).
        @returns : A copy of the data inside `channel` or `None` if the
                    channel is not allocated in the table.

        SELF: This function might be redundant, and we can just directly
                reference the observe channel when we need it.
        """
        if channel not in self._observed_channel_data:
            return None
        return self._observed_channel_data[channel]

    def _handle_observe_event(self, advertising_data, rssi):
        """
        Handles the observe event from the bluetooth driver.

        The advertising data is parsed, and if it matches the required
        format, it is then saved in the observe_channels dictionary for
        later use.

        @param advertising_data: The raw advertising data.
        @param rssi: The RSSI of the event in dBm.
        """
        if len(advertising_data) < 8:
            ## If the advertising data doesn't have the minimum required
            # packet size, then we ignore it.
            return

        ## The advertising packet is structured such that it starts with:
        # [0]: The length of the advertising data
        # [1]: The length of the manufacture specific data
        # [2]: A fixed value indicating that there is manufacturer specific data.
        # [3:5]: A fixed value indicating the LEGO CID.
        # [5]: The PyBricks BLE channel.
        # [6]: A fixed null value.
        # [7:]: The PyBricks BLE data.

        if advertising_data[2] is not MFG_SPECIFIC:
            ## If the advertising packet doesn't have manufacturer specific
            # data (where PyBricks stores it's BLE data), then we ignore it.
            return

        if get_uint16_little_endian(advertising_data[3:5]) != LEGO_CID:
            ## If the manufacturer specific data doesn't have the LEGO CID
            # then we ignore it.
            return

        channel = advertising_data[5]
        if channel not in self._observed_channel_data:
            ## If this packet contains data for a channel that this instance
            # is not observing, then we ignore it.
            return

        ## Prepare to calculate the moving average smoothed RSSI value.
        # So first, we have to get the time difference since the last
        # observation in milliseconds.
        last_observation_sec = self._observed_channel_data[channel]["timestamp"]
        current_observation_sec = time()
        time_difference_ms = (current_observation_sec - last_observation_sec) * 1000

        ## Then we update the timestamp value for when we made this observation.
        self._observed_channel_data[channel]["timestamp"] = current_observation_sec
        if time_difference_ms > RSSI_FILTER_WINDOW_MS:
            ## If the time_difference exceeds the RSSI Filter Window, cap it.
            time_difference_ms = RSSI_FILTER_WINDOW_MS

        ## Now calculate the moving average for the RSSI.
        old_rssi = self._observed_channel_data[channel]["rssi"]
        averaged_rssi = (
            old_rssi * (RSSI_FILTER_WINDOW_MS - time_difference_ms)
            + rssi * time_difference_ms
        ) / RSSI_FILTER_WINDOW_MS
        self._observed_channel_data[channel]["rssi"] = averaged_rssi

        ## Lastly, set the data that we observed for the channel during
        # this observe event.
        self._observed_channel_data[channel]["data"] = advertising_data[7:]

    def _decode_pybrick_ble_data(self, raw_data):
        """
        Decodes the data that was received by the Bluetooth Radio.

        @param raw_data: The raw data received by the BLE Bluetooth Radio.
        @returns: The decoded value as a Python object.
        """
        data_type = raw_data[0] >> 5
        size = raw_data[0] & 0x1F

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_SINGLE_OBJECT:
            # TODO: Implement single object parsing for the byte stream.
            return "single object"

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_TRUE:
            return True

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_FALSE:
            return False

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_INT:
            return int.from_bytes(raw_data[1:], byteorder="little", signed=True)

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_FLOAT:
            return struct.unpack("f", raw_data[1:])[0]

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_STR:
            data = (raw_data[1:]).decode(encoding="utf-8")
            return "" if size <= 0 else data

        if data_type is PYBRICKS_BLE_BROADCAST_DATA_TYPE_BYTES:
            return raw_data[1:]

        # TODO: Implement Tuple Support.

    def _get_channel_data(self, channel):
        """
        Retreives a copy of the last received advertising data.

        @param channel: The channel number to retreive data from.
        @returns: A copy of the channel data.
        @throws: An exception if the requested channel is out of range.
        """
        if channel not in self._observed_channel_data:
            raise Exception("[BrickBLE]: Channel {} is not allocated.".format(channel))

        last_observation_sec = self._observed_channel_data[channel]["timestamp"]
        current_observation_sec = time()
        time_difference_ms = (current_observation_sec - last_observation_sec) * 1000
        if time_difference_ms > OBSERVED_DATA_TIMEOUT_MS:
            ## Reset the data if it is too old.
            self._observed_channel_data[channel]["data"] = None
            self._observed_channel_data[channel]["rssi"] = INT8_MIN

        ## Return a copy of the data for the observed channel.
        return self._observed_channel_data[channel]

    def _generate_pybricks_encoded_ad_data(self, input_data):
        """
        Encodes the data using PyBrick's broadcast encoding scheme and
        returns the bytes containing the encoded advertisement data.

        @param `input_data` : A boolean, int, float, string, bytes or tuple.
        @returns : Little endian packed bytes containing the advertisement data.
        """
        if type(input_data) is bool:
            ## Define the format string for the advertisment data based on
            # how we know the advertisement data is structured and python's
            # `struct` format specifiers.
            ad_data_format = "<BB2sBxB"

            ## Determine the size of the advertisement data based on the
            # format string we defined earlier.
            ad_data_length = struct.calcsize(ad_data_format)

            ## The BLE advertisement protocol expects a fixed sized
            # packet, so we need to pad the remaining space with zeros.
            # Define the padded format string for the advertisement data.
            padded_ad_data_format = "{}{}x".format(
                ad_data_format, BLE_ADVERTISEMENT_DATA_MAX_LENGTH - ad_data_length
            )

            ## Now we construct the advertisement data for the BLE packet.
            # And then return it back to the caller.
            ad_data = struct.pack(
                padded_ad_data_format,
                PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH,
                MFG_SPECIFIC,
                get_uint16_little_endian(LEGO_CID),
                self._broadcast_channel,
                32 if input_data is True else 64,
            )
            return ad_data

        if type(input_data) is int:
            ## `0x61 0x00` when `0`                     0110 0001 0000 0000
            ## `0x61 0xff` when `-1`                    0110 0001 1111 1111
            ## `0x61 0x01` when `1`                     0110 0001 0000 0001
            ## `0x61 0x9c` when `-100`                  0110 0001 1001 1100
            ## `0x62 0xff 0x00` when `255`              0110 0010 1111 1111 0000 0000
            ## `0x62 0x01 0xff` when `-255`             0110 0010 0000 0001 1111 1111
            ## `0x64 0xff 0xff 0x0 0x0` when `65535`    0110 0100 1111 1111 ...

            ## Based on the above sample, it seems that the way integers
            # are encoded are as follows :
            #   DATA_TYPE_INTEGER               -> 0x6 (0110)
            #   integer_size                    -> 0x1 (0001) -> 8bit
            #                                   -> 0x2 (0010) -> 16bit
            #                                   -> 0x4 (0100) -> 32bit
            #
            #   2's complement integer value    -> ...

            ## First, determine the size of the input integer.
            integer_size = None

            ## NB: Match-Case is not available in Python 3.5
            # match (input_data):
            #     case n if n < 128 and n >= -128:
            #         ## 8bit signed integer
            #         integer_size = 1  # bytes
            #     case n if n < 32767 and n >= -32768:
            #         ## 16bit signed integer
            #         integer_size = 2  # bytes
            #     case n if n < 2147483647 and n >= -2147483648:
            #         ## 32bit signed integer
            #         integer_size = 4  # bytes
            #     case _:
            #         raise Exception(
            #             "[BrickBLE]: .broadcast() only supports up to 32bit integers!"
            #         )
            if input_data < 128 and input_data >= -128:
                integer_size = 1
            elif input_data < 32767 and input_data >= -32768:
                integer_size = 2
            elif input_data < 2147483647 and input_data >= -2147483648:
                integer_size = 4
            else:
                raise Exception(
                    "[BrickBLE]: .broadcast() only supports up to 32bit integers!"
                )

            ## Specify the format of the advertisement data as the following:
            # <     : Litte Endian
            # B     : Unsigned Char     -> PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH
            # B     : Unsigned Char     -> MFG_SPECIFIC
            # 2s    : char[2]           -> LEGO_CID
            # B     : Unsigned Char     -> broadcast_channel
            # x     : Pad Byte
            # B     : Unsigned Char     -> DATA_TYPE_INTEGER, integer_size
            # {}s   : char[]            -> 2's complement integer value
            ad_data_format = "<BB2sBxB{}s".format(integer_size)

            ## Generate the byte containing the data type and integer size.
            metadata = (6 << 4) | integer_size
            # metadata = ((6 << 4) & 255) | (integer_size & 255)

            ## Generate the ad data based on the format specified above.
            ad_data_length = struct.calcsize(ad_data_format)
            padded_ad_data_format = "{}{}x".format(
                ad_data_format, BLE_ADVERTISEMENT_DATA_MAX_LENGTH - ad_data_length
            )
            ad_data = struct.pack(
                padded_ad_data_format,
                PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH,
                MFG_SPECIFIC,
                get_uint16_little_endian(LEGO_CID),
                self._broadcast_channel,
                metadata,
                input_data.to_bytes(integer_size, byteorder="little", signed=True),
            )
            return ad_data

        if type(input_data) is float:
            ## Floating Point Numbers refresher :
            # Given 32 bits, a float is represented as follows:
            #   - 1 bit : represents the sign positive or negative. 0
            #             is a positive number, 1 is a negative number.
            #   - 8 bits : represents the exponent of 2 because floating
            #              points are scientific notation representation
            #              of numbers in base 2. The full 8 bits = 2^128.
            #   - 23 bits : represents the decimal points of the significant.
            #               The first digit is omitted because it is nearly
            #               almost always 1.xxxx...
            #               So the full 23 bits = .9999999.
            #
            # -S- -------E--------- ---------------------M-------------------------
            # []  [][][][][][][][]  [][][][][][][][][][][][][][][][][][][][][][][]
            #
            # Floating point value = S * 2^E * (1.0 + M) where S = the sign,
            #                                            E = the exponent, and
            #                                            M = the significant

            ## How floating points are handled in PyBricks BLE
            # Similiar to the integers, floating points are handled such
            # that there is a metadata section of 2 bytes (0xff) containing
            # the data type of the data and the size of the data type.

            ## In this case, the data type is FLOAT = 4 (0x8) and the size is
            # either DOUBLE PRECISION = 8 or SINGLE PRECISION = 4

            ## So each floating point data type will be structured with
            # either 0x84 or 0x88 followed by the floating point value.

            floating_point_precision = 4
            ## It seems the PyBricks implementation at the time of testing
            # only supports 32bit floats.

            # if input_data <= MAX_SINGLE_FLOAT_VALUE and input_data >= MIN_SINGLE_FLOAT_VALUE:
            #    _log("Single FLoat Detected: {}".format(input_data))
            #    floating_point_precision = 4
            # elif input_data <= MAX_DOUBLE_FLOAT_VALUE and input_data >= MIN_DOUBLE_FLOAT_VALUE:
            #    _log("Double FLoat Detected: {}".format(input_data))
            #    floating_point_precision = 8
            # else:
            #    raise Exception("[BrickBLE]: _generate_pybricks_encoded_ad_data() inside .broadcast() encountered an error while attempting to determine the floating point precision.")

            ## Specify the format of the advertisement data as the following:
            # <         : Litte Endian
            # B         : Unsigned Char     -> PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH
            # B         : Unsigned Char     -> MFG_SPECIFIC
            # 2s        : char[2]           -> LEGO_CID
            # B         : Unsigned Char     -> broadcast_channel
            # x         : Pad Byte
            # B         : Unsigned Char     -> DATA_TYPE_FLOAT, floating_point_precision
            # f or d    : float or double   -> the float value
            ad_data_format = "<BB2sBxB{}".format(
                "f" if floating_point_precision is 4 else "d"
            )

            ## Generate the bytes containing the data type and floating point precision.
            metadata = (8 << 4) | floating_point_precision

            ## Generate the ad data based on the format specified above.
            ad_data_length = struct.calcsize(ad_data_format)
            padded_ad_data_format = "{}{}x".format(
                ad_data_format, BLE_ADVERTISEMENT_DATA_MAX_LENGTH - ad_data_length
            )
            ad_data = struct.pack(
                padded_ad_data_format,
                PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH,
                MFG_SPECIFIC,
                get_uint16_little_endian(LEGO_CID),
                self._broadcast_channel,
                metadata,
                input_data,
            )
            return ad_data

        if type(input_data) is str:
            ## The string data type is straightforward, it is the data
            # type + the number of characters in the string, followed
            # by the string itself.

            string_length = len(input_data)
            if string_length > 24:
                raise Exception(
                    "[BrickBLE]: .broadcast() only supports strings up to 24 characters!"
                )

            ## Specify the format of the advertisement data as the following:
            # <         : Litte Endian
            # B         : Unsigned Char     -> PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH
            # B         : Unsigned Char     -> MFG_SPECIFIC
            # 2s        : char[2]           -> LEGO_CID
            # B         : Unsigned Char     -> broadcast_channel
            # x         : Pad Byte
            # B         : Unsigned Char     -> DATA_TYPE_STR, string_length
            # {}s       : char[]            -> string input data
            ad_data_format = "<BB2sBxB{}s".format(string_length)

            ## Generate the bytes containing the data type and floating point precision.
            metadata = (10 << 4) | string_length

            ## Generate the ad data based on the format specified above.
            ad_data_length = struct.calcsize(ad_data_format)
            padded_ad_data_format = "{}{}x".format(
                ad_data_format, BLE_ADVERTISEMENT_DATA_MAX_LENGTH - ad_data_length
            )
            ad_data = struct.pack(
                padded_ad_data_format,
                PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH,
                MFG_SPECIFIC,
                get_uint16_little_endian(LEGO_CID),
                self._broadcast_channel,
                metadata,
                bytearray(input_data, encoding="utf-8"),
            )
            return ad_data

        if type(input_data) is bytes:
            _log("{} is bytes".format(input_data))
            ## The bytes data type is almost exactly like the string data type.
            bytes_length = len(input_data)
            if bytes_length > 24:
                raise Exception(
                    "[BrickBLE]: .broadcast() only supports byte payload up to 24 bytes!"
                )

            ## Specify the format of the advertisement data as the following:
            # <         : Litte Endian
            # B         : Unsigned Char     -> PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH
            # B         : Unsigned Char     -> MFG_SPECIFIC
            # 2s        : char[2]           -> LEGO_CID
            # B         : Unsigned Char     -> broadcast_channel
            # x         : Pad Byte
            # B         : Unsigned Char     -> DATA_TYPE_BYTES, string_length
            # {}s       : char[]            -> bytes input data
            ad_data_format = "<BB2sBxB{}s".format(bytes_length)

            ## Generate the metadata byte: 0xcX, where X is the amount of bytes in the payload.
            metadata = (12 << 4) | bytes_length
            _log("metadata: {}".format(metadata.to_bytes(2, byteorder="little")))

            ## Generate the ad data based on the format specified above.
            ad_data_length = struct.calcsize(ad_data_format)
            padded_ad_data_format = "{}{}x".format(
                ad_data_format,
                BLE_ADVERTISEMENT_DATA_MAX_LENGTH - ad_data_length,
            )
            ad_data = struct.pack(
                padded_ad_data_format,
                PYBRICKS_BLE_BROADCAST_DATA_MIN_LENGTH,
                MFG_SPECIFIC,
                get_uint16_little_endian(LEGO_CID),
                self._broadcast_channel,
                metadata,
                input_data,
            )
            _log("Final ad_data (bytes) : {}".format(ad_data.hex()))

            return ad_data

    def observe(self, channel):
        """
        Public function that retreives the last received advertising data.

        @param channel: The channel number to retreive data from.
        @returns: A copy of the channel data.
        @throws: An exception if the requested channel is out of range.
        """

        channel_data = self._get_channel_data(channel)
        if channel_data["rssi"] is INT8_MIN:
            ## This means that we either haven't received any data yet
            # or the channel timed out and the data was reset.
            return None

        decoded_observed_data = self._decode_pybrick_ble_data(channel_data["data"])

        return decoded_observed_data

    def broadcast_old(self, data):
        """
        Sets the broadcast advertising data and enables broadcasting on
        the Bluetooth radio if it is not already enabled.

        The data can be one object of the allowed types or a tuple/list thereof.
        """
        _log("broadcaster, entered")
        _log("broadcaster, data: {}".format(data))

        ## Stop broadcasting if data is None.
        if data is None:
            _log("broadcaster, no data")

            if self._is_broadcasting:
                ## We only stop the broadcasting if the radio is already set
                # to broadcast
                self._main_thread_request_lock_event.set()
                with self._socket_lock:
                    bt_hci_le_set_advertise_enable(
                        self._hci_socket, ADVERTISING_DISABLED
                    )
                    _log("broadcaster, disabled advertising")

                # btu.stop_le_advertising(self._hci_socket)
                self._main_thread_request_lock_event.clear()

                ## Update the broadcasting flag state.
                self._is_broadcasting = False
                _log("broadcaster, flag state updated")

                return

            ## Otherwise, do nothing if the radio is already off..
            _log("broadcaster, radio is already off")

            return

        pybricks_encoded_data = self._generate_pybricks_encoded_ad_data(data)
        _log("broadcasted, generated encoded data: {}".format(pybricks_encoded_data))

        if self._is_broadcasting:
            _log("broadcaster, is already broadcasting")

            ## Otherwise, if broadcasting is already enabled, and there
            # is another call to .broadcast(), we'll just update the
            # advertising data with the new one.
            self._main_thread_request_lock_event.set()
            with self._socket_lock:
                _log("broadcaster, obtained socket lock")

                # bt_hci_le_set_scan_enable(self._hci_socket, LE_SCANNING_DISABLED, FILTER_DUPLICATES_ENABLED)
                # _log("broadcaster, disabled le scanning")

                _log(
                    "broadcaster, preparing to set advertising data: {}, {}".format(
                        len(pybricks_encoded_data), pybricks_encoded_data
                    )
                )
                bt_hci_le_set_advertising_data(
                    self._hci_socket, len(pybricks_encoded_data), pybricks_encoded_data
                )
                _log("broadcaster, ad data set")

                # bt_hci_le_set_scan_enable(self._hci_socket, LE_SCANNING_ENABLED, FILTER_DUPLICATES_ENABLED)
                # _log("broadcaster, enabled le scanning")
            self._main_thread_request_lock_event.clear()
            _log("broadcaster, released socket_lock")
            return

        _log("broadcaster, not enabled yet")
        ## Broadcasting isn't enabled yet, so we need to renable it
        # before we broadcast the data.
        self._main_thread_request_lock_event.set()
        with self._socket_lock:
            _log("broadcaster, obtained socket lock")

            # bt_hci_le_set_scan_enable(self._hci_socket, LE_SCANNING_DISABLED, FILTER_DUPLICATES_ENABLED)
            # _log("broadcaster, le scan disabled")

            bt_hci_le_set_advertising_parameters(
                self._hci_socket,
                PYBRICKS_BLE_MIN_AD_INTERVAL,
                PYBRICKS_BLE_MAX_AD_INTERVAL,
                ADV_NONCONN_IND,
            )
            _log("broadcaster, advertising parameters set")

            _log(
                "broadcaster, preparing to set advertising data: {}, {}".format(
                    len(pybricks_encoded_data), pybricks_encoded_data
                )
            )
            bt_hci_le_set_advertising_data(
                self._hci_socket, len(pybricks_encoded_data), pybricks_encoded_data
            )
            _log("broadcaster, advertising data set")

            bt_hci_le_set_advertise_enable(self._hci_socket, ADVERTISING_ENABLED)
            _log("broadcaster, advertising disabled")

            # bt_hci_le_set_scan_enable(self._hci_socket, LE_SCANNING_ENABLED, FILTER_DUPLICATES_ENABLED)
            # _log("broadcaster, le scan enabled")
        self._is_broadcasting = True
        self._main_thread_request_lock_event.clear()
        _log("broadcaster, released socket_lock")

    def broadcast(self, data):
        if data is None:
            self._broadcast_queue.put(AsyncBroadcastCommand(ASYNC_BROADCAST_STOP, None))
            return

        pybricks_encoded_data = self._generate_pybricks_encoded_ad_data(data)
        self._broadcast_queue.put(AsyncBroadcastCommand(ASYNC_BROADCAST_START, pybricks_encoded_data))

    def set_broadcast_channel(self, new_broadcast_channel):
        """
        Sets the broadcast channel to the specified value.

        This only sets the broadcast channel managed by BrickBLE. It might
        be possible that the effect only applies on the next .broadcast() call.
        """
        ## TODO: add error checking to ensure that the new broadcast channel
        # is within the valid 0-255 unsigned integer range.
        self._broadcast_channel = new_broadcast_channel
