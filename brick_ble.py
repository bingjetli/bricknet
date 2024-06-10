from time import time
import bluetooth_utils as btu
import bluetooth._bluetooth as bluez
from threading import Thread, Event
import struct


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
            print("Not a LE_META_EVENT!")
            continue

        (sub_event,) = struct.unpack("B", packet[3:4])
        if sub_event != btu.EVT_LE_ADVERTISING_REPORT:
            ## We're only interested in parsing BLE Advertising Events,
            # so we skip packets that don't indicate this flag.
            print("Skipped packet... ")
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
    print("Stop event received, attempting to restore old BLE filter.")

    bt_hci_socket.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_ble_filter)

    print("Reached the end of the BLE Event Parser Thread")


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
            print("An error occured while initializing the PyBrick BLE Module.")
            raise

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

        print("BrickBLE resources cleaned up successfully!")

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
            # TODO: Implement Float Parsing from the byte stream.
            return "float"

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

        # data_length = len(input_data)
        # struct_format = "<BB2sBxB{}s".format(data_length)
        # packet_size = struct.calcsize(struct_format)

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

        ## TODO: Now that broadcasting is more or less set up, here what you
        # need to do next week :
        # - test whether or not the `.broadcast()` method works as expected.
        # - find out if we need to call `.stop_le_advertising()` before calling
        #   `.start_le_advertising()`.
        # - finish the encoding logic for `_generate_pybricks_encoded_ad_data()`

        ## OLD
        # value = {
        #    v: None,
        #    d: [None] * (5 + OBSERVED_DATA_MAX_SIZE),
        # }

        # index = None
        # if type(data) is tuple or type(data) is list:
        #    index = 0
        # else:
        #    index = 1
