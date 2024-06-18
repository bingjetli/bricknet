from time import time
from .py_bluetooth_utils import bluetooth_utils as btu
import bluetooth._bluetooth as bluez
from threading import Thread, Event
import struct


MAX_SINGLE_FLOAT_VALUE = 1.175494351e-38
MIN_SINGLE_FLOAT_VALUE = 3.402823466e+38
MAX_DOUBLE_FLOAT_VALUE = 1.7976931348623157e+308
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
PYBRICKS_BLE_SCAN_INTERVAL = 0x30
PYBRICKS_BLE_SCAN_WINDOW = 0x30
PYBRICKS_BLE_MIN_AD_INTERVAL = 0x64
PYBRICKS_BLE_MAX_AD_INTERVAL = 0x64


DEBUG_ENABLED = True
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


def thread_ble_event_parser(event_exit_flag, bt_hci_socket, handler=None):
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
    @param `socket` : A socket to the Bluetooth's host controller
                        interface (HCI).
    @param `handler` : A function that handles the parsed advertising
                        data. It should take 2 parameters : First, the
                        advertising data and then the RSSI. E.g handler(ad_data, rssi)
    """

    ## First, save the original bluetooth filter that was active
    # before we start parsing the advertising events.
    old_ble_filter = bt_hci_socket.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    ## Then, create and define the new bluetooth filter that we will
    # be applying to parse the advertising events.
    new_ble_filter = bluez.hci_filter_new()
    bluez.hci_filter_set_ptype(new_ble_filter, bluez.HCI_EVENT_PKT)
    bluez.hci_filter_set_event(new_ble_filter, btu.LE_META_EVENT)

    ## Apply the new bluetooth filter to the current HCI socket.
    bt_hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, new_ble_filter)

    ## Now, we can start parsing the BLE advertising data.
    while not event_exit_flag.is_set():
        ## We will continue to run the loop until the exit flag thread
        # event is set.
        packet = full_packet = bt_hci_socket.recv(255)
        packet_type, event, packet_length = struct.unpack("BBB", packet[:3])

        if event != btu.LE_META_EVENT:
            ## This should never occur because we've set the new BLE filter
            # to filter out these events.

            ## TODO: Maybe this should throw an exception then?
            _log("Not a LE META_EVENT!")
            continue

        (sub_event,) = struct.unpack("B", packet[3:4])
        if sub_event != btu.EVT_LE_ADVERTISING_REPORT:
            ## We're only interested in parsing BLE Advertising Events,
            # so we skip packets that don't indicate this flag.
            _log("Skipped packet... ")
            continue

        packet = packet[4:]
        # advertisement_type = struct.unpack("b", packet[1:2])[0]
        # mac_address_str = bluez.ba2str(packet[3:9])

        ## The original function checks to see if a packet size argument
        # was passed as an argument, if it was, then we check if the
        # packet length we obtained matches this argument, skipping it
        # if it doesn't.

        advertisement_data = packet[9:-1]
        rssi = struct.unpack("b", full_packet[len(full_packet) - 1 : len(full_packet)])[
            0
        ]

        ## The original function also checks to see if the mac address
        # argument was passed into the function. If it was, then it checks
        # to see if the mac address that we obtained from the packet is
        # in the list of allowed mac addresses passed into the function.
        # If it isn't, then we skip it.

        if handler is not None:
            ## If a handler is defined, we call the handler function.
            handler(advertisement_data, rssi)

    ## If we've reached this point, it means the exit flag event was
    # set by the calling thread, so we perform cleanup actions here.
    _log("Stop event received, attempting to restore old BLE filter.")

    bt_hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_ble_filter)

    _log("Reached the end of the BLE Event Parser Thread")


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

    def __init__(self, broadcasting_channel, observing_channels):
        try:
            ## First, try to ensure that the Bluetooth controller is powered.
            btu.toggle_device(self._device_id, True)

            ## Then, try to open a socket connection to the Bluetooth
            # Host Controller Interface (HCI).
            self._hci_socket = bluez.hci_open_dev(self._device_id)

            ## Now, try to start scanning for BLE packets.
            btu.enable_le_scan(
                self._hci_socket,
                interval=PYBRICKS_BLE_SCAN_INTERVAL,
                window=PYBRICKS_BLE_SCAN_WINDOW,
            )

            ## Create a new Thread for parsing the BLE Scan Events.
            self._scanning_thread_exit_event = Event()
            self._scanning_thread = Thread(
                target=thread_ble_event_parser,
                args=(
                    self._scanning_thread_exit_event,
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
            raise Exception("An error occured while initializing the PyBrick BLE Module.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        ## Set the exit event flag for the scanning thread, to indicate
        # that it should stop scanning and exit the loop to begin cleanup.
        self._scanning_thread_exit_event.set()

        ## IMPORTANT: We have to wait for the thread to join before disabling
        # the BLE Scanning. If we try to disable the LE scan before the scanning
        # thread finishes, the program will hang.
        self._scanning_thread.join()
        btu.disable_le_scan(self._hci_socket)

        ## Disable BLE Broadcasting in case we were advertising data.
        btu.stop_le_advertising(self._hci_socket)

        _log("BrickBLE resources cleaned up successfully!")

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
        #_log("Received Advertising Data: {}".format(advertising_data))

    def _decode_pybrick_ble_data(self, raw_data):
        """
        Decodes the data that was received by the Bluetooth Radio.

        @param raw_data: The raw data received by the BLE Bluetooth Radio.
        @returns: The decoded value as a Python object.
        """
        data_type = raw_data[0] >> 5
        size = raw_data[0] & 0x1F

        _log("_decode_pybrick_ble_data -> {}".format(raw_data))

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
            return "" if size <= 0 else (raw_data[1:]).decode(encoding="utf-8")

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
            #metadata = ((6 << 4) & 255) | (integer_size & 255)
            _log("Calculated metadata value : {} ({})".format(metadata.to_bytes(1, byteorder="big").hex(), bin(metadata)))

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
            
            #if input_data <= MAX_SINGLE_FLOAT_VALUE and input_data >= MIN_SINGLE_FLOAT_VALUE:
            #    _log("Single FLoat Detected: {}".format(input_data))
            #    floating_point_precision = 4
            #elif input_data <= MAX_DOUBLE_FLOAT_VALUE and input_data >= MIN_DOUBLE_FLOAT_VALUE:
            #    _log("Double FLoat Detected: {}".format(input_data))
            #    floating_point_precision = 8
            #else:
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
            ad_data_format = "<BB2sBxB{}".format("f" if floating_point_precision is 4 else "d")
            

            ## Generate the bytes containing the data type and floating point precision.
            metadata = (8 << 4) | floating_point_precision
            _log("Calculated metadata value : {} ({})".format(metadata.to_bytes(1, byteorder="big").hex(), bin(metadata)))

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
                raise Exception("[BrickBLE]: .broadcast() only supports strings up to 24 characters!")

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
            _log("Calculated metadata value : {} ({}) -- str_len {}".format(metadata.to_bytes(1, byteorder="big").hex(), bin(metadata), string_length))

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

        return self._decode_pybrick_ble_data(channel_data["data"])

    def broadcast(self, data):
        """
        Sets the broadcast advertising data and enables broadcasting on
        the Bluetooth radio if it is not already enabled.

        The data can be one object of the allowed types or a tuple/list thereof.
        """
        ## Stop broadcasting if data is None.
        if data is None:
            btu.stop_le_advertising(self._hci_socket)
            return

        ## Otherwise, fetch the encoded advertisement data and start broadcasting.
        btu.start_le_advertising(
            self._hci_socket,
            min_interval=PYBRICKS_BLE_MIN_AD_INTERVAL,
            max_interval=PYBRICKS_BLE_MAX_AD_INTERVAL,
            data=self._generate_pybricks_encoded_ad_data(data),
        )