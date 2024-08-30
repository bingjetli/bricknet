# [x]  TODO: Finish all the remaining imports for the bluetooth managers.
# [x]  TODO: Write a function to split long messages into chunks.
# [x]  TODO: Fix the BLE function to handle sending/receiving bytes properly
# [-]  TODO: Add a way to make fetch requests from BrickNet.
# [x]  TODO: Add a way to ensure that chunked messages are sent once and in order.
# [x]       - Right now, duplicates are merged, so we need to fix that.
# [*]       - We also need to handle cases where the message number might be invalid
#               indicating that we've desynced
# [ ]  TODO: Add more callback functions to hook into the main loop.
#
# x = done
# - = in progress
# * = temporary fix

## *********************
## LOGGING AND DEBUGGING
## *********************

DEBUG_ENABLED = True


def _log(input):
    """
    Prints a message to the console if debugging is enabled.

    The `DEBUG_ENABLED` constant must be set to True in order to
    view debug messages.

    @param `input`: String - A string message to print to the console.
    """
    if DEBUG_ENABLED:
        print("[BrickNet]: {}".format(input))


## ****************
## REQUIRED IMPORTS
## ****************

from socket import MSG_DONTWAIT
from pb_fthreads import FThreadPool, sleep_until_ms

try:
    from brick_ble import BrickBLE
except ImportError:
    _log("Unable to import 'BrickBLE'")

try:
    from pybricks.hubs import CityHub
except ImportError:
    _log("Unable to import CityHub")

try:
    from pybricks.hubs import EssentialHub
except ImportError:
    _log("Unable to import EssentialHub")

try:
    from pybricks.hubs import PrimeHub
except ImportError:
    _log("Unable to import PrimeHub")

try:
    from pybricks.hubs import InventorHub
except ImportError:
    _log("Unable to import InventorHub")

try:
    from pybricks.hubs import TechnicHub
except ImportError:
    _log("Unable to import TechnicHub")

try:
    from pybricks.hubs import MoveHub
except ImportError:
    _log("Unable to import MoveHub")

try:
    from math import ceil
except ImportError:
    _log("Unable to import math.ceil")

try:
    from umath import ceil
except ImportError:
    _log("Unable to import umath.ceil")


try:
    from struct import pack as pack_bytes
except ImportError:
    _log("struct.pack is unavailable")

try:
    from ustruct import pack as pack_bytes
except ImportError:
    _log("ustruct.pack is unavailable")

try:
    from struct import unpack as unpack_bytes
except ImportError:
    _log("struct.unpack is unavailable")

try:
    from ustruct import unpack as unpack_bytes
except ImportError:
    _log("ustruct.unpack is unavailable")


## DEPRECATED
try:
    from urllib.request import urlopen
except ImportError:
    _log("urllib.request.urlopen is unavailable")

try:
    from urllib.request import Request
except ImportError:
    _log("urllib.request.Request is unavailable")

try:
    from urllib.error import HTTPError
except ImportError:
    _log("urllib.error.HTTPError is unavailable")

try:
    from urllib.error import URLError
except ImportError:
    _log("urllib.error.URLError is unavailable")

## REQUIRED FOR ASYNC HTTP REQUESTS
try:
    from socket import socket
except ImportError:
    _log("socket.socket is unavailable")

try:
    from socket import AF_INET
except ImportError:
    _log("socket.AF_INET is unavailable")

try:
    from socket import SOCK_STREAM
except ImportError:
    _log("socket.SOCK_STREAM is unavailable")

try:
    from socket import MSG_DONTWAIT
except ImportError:
    _log("socket.MSG_DONTWAIT is unavailable")

try:
    from socket import gethostbyname
except ImportError:
    _log("socket.gethostbyname is unavailable")

try:
    from ssl import wrap_socket
except ImportError:
    _log("ssl.wrap_socket is unavailable")

## ********************
## CONSTANT DEFINITIONS
## ********************

## This is stored in a set because we are describing an unordered,
# immutable and unindexed collection.
VALID_BLUETOOTH_MANAGERS = {
    ## NB: BrickBLE takes the parameters `broadcasting_channel` and `observing_channels`
    "BrickBLE",
    ## NB: Every Hub takes the parameters `broadcast_channel` and `observe_channels`
    "CityHub",
    ## NB: The following hubs will take additional parameters `top_side`
    # and `front_side` to specify their orientation axes.
    "EssentialHub",
    "PrimeHub",
    "InventorHub",
    "TechnicHub",
    "MoveHub",
}

COMMUNICATION_STATE_READY = "ready"
COMMUNICATION_STATE_SENT = "sent"
COMMUNICATION_STATE_RECEIVED = "received"

# MESSAGE_TYPE_READY = "#R#"
# MESSAGE_TYPE_SENT = "#S#"
# MESSAGE_TYPE_RECEIVED = "#A#"

MESSAGE_TYPE_READY = 0x00
MESSAGE_TYPE_SENT = 0x01
MESSAGE_TYPE_RECEIVED = 0x02

MESSAGE_SUBTYPE_DIRECT = 0x00
MESSAGE_SUBTYPE_REDIRECT = 0x01
MESSAGE_SUBTYPE_GET = 0x02
MESSAGE_SUBTYPE_POST = 0x03
MESSAGE_SUBTYPE_PUT = 0x04
MESSAGE_SUBTYPE_PATCH = 0x05
MESSAGE_SUBTYPE_DELETE = 0x06


## This value specifies the amount of time to wait in any of the transition
# states(SENT/RECEIVED) before timing out and returning to the READY state.
MESSAGE_STATE_TRANSITION_TIMEOUT_MS = 1000


def get_communication_state_from_message_type(input):
    if input == MESSAGE_TYPE_READY:
        return COMMUNICATION_STATE_READY
    elif input == MESSAGE_TYPE_RECEIVED:
        return COMMUNICATION_STATE_RECEIVED
    elif input == MESSAGE_TYPE_SENT:
        return COMMUNICATION_STATE_SENT


def is_valid_communication_state(input):
    return (
        input == COMMUNICATION_STATE_READY
        or input == COMMUNICATION_STATE_RECEIVED
        or input == COMMUNICATION_STATE_SENT
    )


def is_valid_message_type(input):
    return (
        input == MESSAGE_TYPE_READY
        or input == MESSAGE_TYPE_RECEIVED
        or input == MESSAGE_TYPE_SENT
    )


## *****************
## CLASS DEFINITIONS
## *****************

## Conditionally define the Stopwatch class if it hasn't been defined
# using the import statement.
if "StopWatch" not in globals():
    try:
        ## If the StopWatch class is not imported already, we'll try to import
        # it using an exec statement.
        exec("from pybricks.tools import StopWatch")
        ## TODO: Instead of using exec, use the try-catch import blocks.
    except ImportError:
        ## If we failed to import this class, then we are probably not
        # running on the SPIKE Hub. In that case, we are likely running
        # on the EV3 or an external device capable of running Python3
        exec("from time import perf_counter")
        ## TODO: Instead of using exec, use the try-catch import blocks.

        class StopWatch(object):
            ## So in that case, we recreate the methods that the StopWatch
            # class offers to us.
            _start_time = None
            _paused_time = None

            def __init__(self):
                self._start_time = perf_counter()

            def time(self):
                """
                Gets the current time of the StopWatch.

                @returns elapsed time in milliseconds.
                """
                if self._paused_time is not None:
                    ## When the stopwatch is paused, the _paused_time
                    # variable will be set. If it is set, then we calculate
                    # the current time as the difference of the paused time
                    # by the start time.
                    return round((self._paused_time - self._start_time) * 1000)

                ## Otherwise, we return the elapsed time as the difference
                # between the current time and the start time.
                return round((perf_counter() - self._start_time) * 1000)

            def pause(self):
                """
                Pauses the StopWatch.
                """
                self._paused_time = perf_counter()

            def resume(self):
                """
                Resumes the StopWatch.
                """
                self._paused_time = None

            def reset(self):
                """
                Resets the StopWatch to 0.

                The run state is unaffected.
                - if it was paused, it stays paused, but now at 0.
                - if it was running, it stays running, but starting again from 0.
                """
                self._start_time = perf_counter()

                if self._paused_time is not None:
                    ## If there is a paused time, we will set it to be
                    # the same as the start time such that the calculated
                    # elapsed time will output 0.
                    self._paused_time = self._start_time


class Message(object):
    _header = None
    _message_type = None
    _message_subtype = None
    _message_number = None
    _payload = None

    def __init__(
        self,
        message_type,
        message_subtype=MESSAGE_SUBTYPE_DIRECT,
        message_number=0,
        payload=None,
    ):
        ## Validating the message_type parameter...
        if (
            message_type != MESSAGE_TYPE_READY
            and message_type != MESSAGE_TYPE_SENT
            and message_type != MESSAGE_TYPE_RECEIVED
        ):
            raise Exception("[BrickNet]: Unknown message type: {}".format(message_type))

        ## Validating the message_subtype parameter...
        if (
            message_subtype != MESSAGE_SUBTYPE_DIRECT
            and message_subtype != MESSAGE_SUBTYPE_REDIRECT
            and message_subtype != MESSAGE_SUBTYPE_GET
            and message_subtype != MESSAGE_SUBTYPE_POST
            and message_subtype != MESSAGE_SUBTYPE_PUT
            and message_subtype != MESSAGE_SUBTYPE_PATCH
            and message_subtype != MESSAGE_SUBTYPE_DELETE
        ):
            raise Exception(
                "[BrickNet]: Unknown message subtype: {}".format(message_subtype)
            )

        ## Validate payload size...
        if payload is not None:
            if len(payload) > self.get_max_payload_length_for_subtype(message_subtype):
                raise Exception(
                    "[BrickNet]: Payload maximum size exceeded: ({}) {}".format(
                        len(payload), payload
                    )
                )

        self._header = message_type
        self._message_type = message_type
        self._message_subtype = message_subtype
        self._message_number = message_number
        self._payload = payload

    def _get_message_type_and_subtype(self):
        """
        Creates the message type & subtype portion of the header.

        [MESSAGE_TYPE (4 bits)][MESSAGE_SUBTYPE (4 bits)]

        """
        ## Shift the bits 4x to the left:           0000TTTT            --> TTTT0000
        # Then combine it with the message subtype: TTTT0000 | 0000SSSS --> TTTTSSSS
        #
        # where T = Message Type and S = Message Subtype
        return (self._message_type << 4) | self._message_subtype

    def _get_message_header(self):
        """
        Creates the message header.

        [MESSAGE_TYPE_AND_SUBTYPE (1 byte)][MESSAGE_NUMBER (1 byte)]

        """
        return pack_bytes(
            "<BB", self._get_message_type_and_subtype(), self._message_number
        )

    def get_broadcast_data(self):
        """
        Returns the data that can be passed into the .broadcast() method.

        @returns: String - The payload of this message as a string.
        """
        _log("\t + Message->get_broadcast_data(): {}".format(self))
        # return "{}{}".format(self._header, self._payload if self._payload else "")
        if self._payload is None:
            return pack_bytes(
                "<2s",
                self._get_message_header(),
            )

        formatted_payload = self._payload
        if type(self._payload) == str:
            ## The format string `{}s` for pack_bytes expects a bytes object.
            formatted_payload = bytes(self._payload, "utf-8")

        return pack_bytes(
            "<2s{}s".format(len(self._payload)),
            self._get_message_header(),
            formatted_payload,
        )

    def get_message_type(self):
        """
        Returns the type of this message.

        @returns: String - The message type.
        """
        return self._message_type

    def get_message_payload(self):
        """
        Gets the payload of this message.

        @returns: Any - The message payload.
        """
        return self._payload

    def get_message_number(self):
        return self._message_number

    @staticmethod
    def get_max_payload_length_for_subtype(message_subtype):
        if message_subtype == MESSAGE_SUBTYPE_DIRECT:
            return 24 - 2

        ## TODO: complete this for each subtype

    @staticmethod
    def generate_from_observed_data(raw_data):
        message_subtype = raw_data[0] & 0x0F
        message_type = raw_data[0] >> 4
        message_number = raw_data[1]
        message_payload = None

        if message_type == MESSAGE_TYPE_SENT:
            ## ASSUMPTION: Only the SENT message type has payload data.
            message_payload = raw_data[2:]

        return Message(message_type, message_subtype, message_number, message_payload)

    def __str__(self):
        return "Type: {}, Subtype: {}, Number: {}, Payload: {} ({})".format(
            self._message_type,
            self._message_subtype,
            self._message_number,
            self._payload,
            len(self._payload) if self._payload is not None else 0,
        )


class Port(object):
    _channel = None
    _remote_state = None
    _last_message = None

    ## Contains a list of Message instances...
    _to_send = None

    ## These variables are used to keep track of chunked messages.
    # If a chunked message is encountered, the merge_counter is set and
    # the chunked content is stored inside the merge_buffer.
    _merge_counter = None
    _merge_buffer = None

    ## Flag that determines whether or not the dispatcher processed this port yet.
    _is_processed = None

    def __init__(self, channel, list_of_initial_items=[]):
        """
        Initializes a new instance of the Port.
        """
        self._channel = channel
        self._is_processed = False

        ## We should call .observe() in order to get the most recent state
        self._remote_state = None

        ## Typically this is empty, but a list of initial message to send
        # can be specified.
        self._to_send = Queue(list_of_initial_items)

        self._merge_counter = 0

    def get_broadcast_target_channel(self):
        return self._channel

    def this_port_is_processed(self):
        return self._is_processed

    def set_is_processed(self, is_processed):
        """
        Sets the flag to indicate whether or not this port has already
        been processed.

        @param is_processed: boolean
        """
        self._is_processed = is_processed

    def messages_for_this_port(self):
        return self._to_send

    def get_merge_buffer(self):
        return self._merge_buffer

    def append_to_merge_buffer(self, item):
        if self._merge_buffer is None:
            ## Create the merge buffer with the item...
            self._merge_buffer = item
            return

        self._merge_buffer += item

    def set_merge_counter(self, new_value):
        self._merge_counter = new_value

    def get_merge_counter(self):
        return self._merge_counter

    def clear_merge_buffer(self):
        self._merge_buffer = None

    def set_remote_state(self, state):
        if is_valid_communication_state(state):
            self._remote_state = state

    def get_remote_state(self):
        return self._remote_state

    def set_last_message(self, message):
        self._last_message = message

    def get_last_message(self):
        return self._last_message


class Queue(object):
    _queue = None

    def __init__(self, list_of_initial_items=[]):
        """
        Initializes a new instance of Queue with a list of initial items
        """
        self._queue = list_of_initial_items

    def enqueue(self, item):
        """
        Pushes an item into the queue.
        """
        self._queue.append(item)

    def dequeue(self):
        """
        Removes an item from the front of the queue.
        """
        return self._queue.pop(0)

    def peek(self):
        """
        Gets the first item in the queue without dequeuing it.
        """
        return self._queue[0]

    def get_length(self):
        """
        Returns the length of the queue.
        """
        return len(self._queue)


class Stack(object):
    _stack = None

    def __init__(self, list_of_initial_items=[]):
        self._stack = list_of_initial_items

    def push(self, item):
        self._stack.append(item)

    def pop(self):
        return self._stack.pop()

    def peek(self):
        return self._stack[-1]

    def get_length(self):
        return len(self._stack)


class BrickNet(object):
    ## This contains the name of the class that will be used to create
    # the instance of the Bluetooth Manager.
    _bluetooth_manager_type = None

    ## Contains the instance of the Bluetooth manager. For the EV3, this
    # will be an instance of BrickBLE. For the SPIKE, this will be an
    # instance of a Hub. Generally, it is an instance of whatever class
    # that will allow you to call .broadcast() and .observe().
    _bluetooth_manager = None

    ## A flag to indicate whether or not the instance initialized is for
    # an EV3 Hub or a SPIKE hub.
    _is_ev3 = False

    ## Flag to indicate whether or not the main event loop is running.
    _is_running = False

    _message_queue = None

    ## Specifies the current port of the message queue that the main loop
    # is processing in the current iteration.
    _current_port_index = None

    ## The communication state determines what state the device is in
    # for the communication protocol. It can be in either READY, SENT or
    # RECEIVED states.
    _communication_state = None

    ## Used to keep track of how long each state transition takes and
    # determine when to timeout the state transition.
    _stopwatch = None

    ## Expected to contain a reference to the function that will be used
    # to handle whenever a message is received.
    #
    # The handler function takes 2 parameters: channel & message.
    _on_received_handler = None

    ## This contains a reference to the FThreadPool instance used to manage concurrency.
    _fthread_pool = None

    def __init__(self, bluetooth_manager_type, **kwargs):
        """
        Initializes a new instance of BrickNet with the specified
        Bluetooth Manager.

        """

        ## First check to see if a valid bluetooth manager was specified.
        if bluetooth_manager_type not in VALID_BLUETOOTH_MANAGERS:
            raise Exception(
                "[BrickNet]: {} is not a valid bluetooth manager.".format(
                    bluetooth_manager_type
                )
            )
        self._bluetooth_manager_type = bluetooth_manager_type
        _log(
            "BrickNet.__init__ : {} is a valid bluetooth_manager_type.".format(
                bluetooth_manager_type
            )
        )

        ## Then, try to obtain the specified Bluetooth Manager class from
        # the global symbols collection and assign it to bluetooth_manager_class.
        bluetooth_manager_class = globals().get(bluetooth_manager_type)
        _log(
            "BrickNet.__init__ : {} was obtained from the global symbols collection.".format(
                bluetooth_manager_class
            )
        )

        ## This effectively allows us to dynamically instantiate the
        # specified Bluetooth manager class without needing the class
        # to be defined at compile-time.

        ## The class will still need to be imported into the calling script
        # so that it exists in the global symbols table.

        ## Next, try to instantiate the bluetooth manager class.
        if bluetooth_manager_class is None:
            raise Exception(
                "[BrickNet]: Failed to intialize because the bluetooth manager is undefined."
            )

        ## Define the dictionary of all the possible parameters that can
        # be passed into either a Hub or the BrickBLE class.
        VALID_KWARGS = {
            "broadcast_channel": kwargs.get("broadcast_channel"),
            "observe_channels": kwargs.get("observe_channels"),
            "top_side": kwargs.get("top_side"),
            "front_side": kwargs.get("front_side"),
            "broadcasting_channel": kwargs.get("broadcasting_channel"),
            "observing_channels": kwargs.get("observing_channels"),
        }

        ## Now we need to filter out all the kwargs that weren't specified.
        # These are arguments that weren't passed into the BrickNet class
        # during instantiation.

        ## The valid kwargs are conditionally defined using python's dictionary
        # comprehension syntax.

        ## Basically, it defines a dictionary using `{}` and inside that dictionary:
        #   the key-value pairs will be specified as `k:v`
        #   `for` each key-value unpacked to `(k,v)` from the `VALID_KWARGS` dictionary
        #   only `if` the value `v is not None`.
        filtered_kwargs = {k: v for (k, v) in VALID_KWARGS.items() if v is not None}
        _log("BrickNet.__init__ : kwargs passed in to the constructor.")
        for key, value in filtered_kwargs.items():
            _log("\t + {}:{}".format(key, value))

        ## We can then transparently pass in any arguments passed into the
        # BrickNet class by unpacking the filtered_kwargs we defined
        # earlier using the unpacking operator `**` from Python.
        self._bluetooth_manager = bluetooth_manager_class(**filtered_kwargs)
        _log("BrickNet.__init__ : bluetooth manager successfully initialized.")

        ## Now the BrickNet class should be properly instantiated with
        # a valid bluetooth manager.

        ## Initialize the message queue.
        if "observing_channels" in filtered_kwargs:
            self._message_queue = [
                Port(channel) for channel in filtered_kwargs["observing_channels"]
            ]
        elif "observe_channels" in filtered_kwargs:
            self._message_queue = [
                Port(channel) for channel in filtered_kwargs["observe_channels"]
            ]
        _log("BrickNet.__init__ : initialized message queue with the following:")
        for port in self._message_queue:
            _log("\t + {}".format(port.get_broadcast_target_channel()))

        ## Initialize low priority properties...
        self._current_port_index = 0
        _log(
            "BrickNet.__init__ : initialized current_port_index as {}".format(
                self._current_port_index
            )
        )

        self._stopwatch = StopWatch()
        _log("BrickNet.__init__ : stopwatch initialized")

        self._fthread_pool = FThreadPool(5)  # magic number #TODO: Make this a constant
        _log("BrickNet.__init__ : initialized fthread pool with 5 worker threads.")

    def get_bluetooth_manager(self):
        """
        Returns a handle to the bluetooth manager that was initialized.

        This will be a direct handle to the *Hub classes if BrickNet was initialized from PyBricks. Or BrickBLE if initialized from the EV3.
        """
        return self._bluetooth_manager

    def get_bluetooth_manager_type(self):
        return self._bluetooth_manager_type

    def start(self):
        """
        Starts the BrickNet main event loop.

        This is a blocking call.
        """
        # TODO: I think we have it all set up properly, just have to test it now ~past you.
        if self._bluetooth_manager_type == "BrickBLE":
            _log("BrickNet.start : Using the BrickBLE bluetooth manager.")
            with self._bluetooth_manager as brick_ble:
                self._fthread_pool.spawn(self._start_event_loop, brick_ble)

                ## Initiate the blocking call to start the fthread pool executor.
                self._fthread_pool.run()
        else:
            _log("BrickNet.start : Not using the BrickBLE bluetooth manager.")
            hub_ble = self._bluetooth_manager.ble
            self._fthread_pool.spawn(self._start_event_loop, hub_ble)

            ## Initiate the blocking call to start the fthread pool executor.
            self._fthread_pool.run()

    async def _start_event_loop(self, ble, thread_pool, thread_id):
        self._is_running = True
        self._communication_state = COMMUNICATION_STATE_READY

        _log(
            "BrickNet._start_event_loop : broadcasting to the first port that this device is ready."
        )
        ## Broadcast to the first port that it is ready.
        current_port = self._message_queue[self._current_port_index]
        current_port_channel = current_port.get_broadcast_target_channel()
        initial_message = Message(MESSAGE_TYPE_READY)
        _log(
            "_start_event_loop() #{} -> _send_now({}, {}) ".format(
                thread_id, initial_message, current_port_channel
            )
        )
        await self._send_now(initial_message, current_port_channel)

        _log("BrickNet._start_event_loop : Main event loop is started.")
        while self._is_running:
            try:
                await self._main_loop_iterate(thread_id)

                ## Prevent the while loop from hogging the CPU. This is used to yield control back to the other threads.
                await sleep_until_ms(1)

            except KeyboardInterrupt:
                ## If Ctrl+C was encountered, then we break out of the loop.
                self._stop_event_loop()

    def _stop_event_loop(self):
        _log("BrickNet._stop_event_loop : Main event loop set to stop.")
        self._is_running = False

    async def _main_loop_iterate(self, thread_id):
        _log("_main_loop_iterate : using Thread {}".format(thread_id))
        current_port = self._message_queue[self._current_port_index]
        current_port_channel = current_port.get_broadcast_target_channel()

        # _log("BrickNet._main_loop_iterate: processing port: {}".format(current_port_channel))

        ## First, try to observe any data that was broadcasted over Bluetooth.
        # observed_data = self.get_bluetooth_manager().observe(current_port_channel)
        observed_data = self._observe(current_port_channel)
        if observed_data == None:
            ## We didn't observe any data from this channel, so the remote device
            # might not be READY. In this case, we can skip this channel and try
            # to see if another channel might be ready.
            _log(
                "_main_loop_iterate() -> no observed data, incrementing port from {}".format(
                    current_port_channel
                )
            )
            self._increment_port_index()
            _log(" + to {}".format(current_port.get_broadcast_target_channel()))
            return

        ## Otherwise, if we observed something other than None...
        # message_type = observed_data[0:3]
        # message_payload = (
        #    observed_data[3:] if message_type == MESSAGE_TYPE_SENT else None
        # )
        # current_port.set_last_message(Message(message_type, message_payload))
        observed_message = Message.generate_from_observed_data(observed_data)
        current_port.set_last_message(observed_message)
        # _log("BrickNet._main_loop_iterate: observed message: {}".format(observed_message))

        if self._communication_state == COMMUNICATION_STATE_READY:
            ## We're ready to receive or send messages...
            if current_port.get_last_message().get_message_type() == MESSAGE_TYPE_SENT:
                ## We're ready, and the remote device just sent something...

                current_port_message_number = (
                    current_port.get_last_message().get_message_number()
                )
                current_port_merge_counter = current_port.get_merge_counter()
                if current_port_message_number == 0:
                    ## We received a zero message number, so this is either the last
                    # message of a chunk of messages or a non-shot message.
                    _log(
                        "_main_loop_iterate() -> This Device: READY | Remote Message Type: SENT | Received a message numbered 0."
                    )
                    if current_port_merge_counter > 0:
                        ## There is something in the merge buffer, so we should check if this message was expected
                        _log("\t + merge_buffer has content")
                        if (
                            current_port_message_number
                            == current_port_merge_counter - 1
                        ):
                            ## If it is, then we merge the message that we just
                            # received as the final message, clear the buffer and
                            # call the onReceived handler.
                            _log(
                                "\t\t + expected: {}, received: {}".format(
                                    current_port_merge_counter - 1,
                                    current_port_message_number,
                                )
                            )
                            current_port.append_to_merge_buffer(
                                current_port.get_last_message().get_message_payload()
                            )
                            _log(
                                "\t\t\t + appending the following to the merge buffer: {}".format(
                                    current_port.get_last_message().get_message_payload()
                                )
                            )
                            if self._on_received_handler is not None:
                                self._on_received_handler(
                                    current_port_channel,
                                    current_port.get_merge_buffer(),
                                )
                            _log(
                                "_main_loop_iterate() -> Called onReceived handler with {}, {}".format(
                                    current_port_channel,
                                    current_port.get_merge_buffer(),
                                )
                            )

                            ## Reset the merge buffer and merge counter..
                            current_port.clear_merge_buffer()
                            current_port.set_merge_counter(current_port_message_number)
                        else:
                            ## Encountered an unpected message in the sequence, possible cases:
                            # - MESSAGE_NO_RECEIVED > MESSAGE_NO_EXPECTED : Desynchronized
                            # - MESSAGE_NO_RECEIVED = MESSAGE_NO_EXPECTED : Duplicated -> Ignore
                            # - MESSAGE_NO_RECEIVED < MESSAGE_NO_EXPECTED - 1 : Missing messages, Desynchronized

                            if (
                                current_port_message_number
                                != current_port_merge_counter
                            ):
                                ## Handle both desynchronization cases...
                                _log(
                                    "\t\t\t + unexpected message number received, possible desynchronization"
                                )

                                ## Not the best way to handle it, but it's the cheapest fix...
                                current_port.clear_merge_buffer()
                                current_port.set_merge_counter(
                                    current_port_message_number
                                )

                                ## TODO: Figure out a better way to handle this failure case.

                    else:
                        ## If there was nothing in the merge buffer, then this
                        # is likely a one-shot message. So we can call the onReceived
                        # handler to handle the message.
                        _log("\t + merge_buffer doesn't have content")
                        if self._on_received_handler is not None:
                            self._on_received_handler(
                                current_port_channel,
                                current_port.get_last_message().get_message_payload(),
                            )
                        _log(
                            "_main_loop_iterate() -> Called onReceived handler with {}, {}".format(
                                current_port_channel, current_port.get_merge_buffer()
                            )
                        )
                else:
                    ## If we received a non-zero message number, this is probably part
                    # of a chunked message.
                    _log(
                        "_main_loop_iterate() -> This Device: READY | Remote Message Type: SENT | Received a message numbered {}.".format(
                            current_port_message_number
                        )
                    )
                    if current_port_merge_counter > 0:
                        ## If the merge counter is non-zero, then we're currently
                        # in the process of merging a message already...
                        _log("\t + merge_buffer has content")
                        if (
                            current_port_message_number
                            == current_port_merge_counter - 1
                        ):
                            ## If the message we received is part of the expected sequence..
                            _log(
                                "\t\t + expected: {}, received: {}".format(
                                    current_port_merge_counter - 1,
                                    current_port_message_number,
                                )
                            )
                            current_port.append_to_merge_buffer(
                                current_port.get_last_message().get_message_payload()
                            )
                            current_port.set_merge_counter(current_port_message_number)
                            _log(
                                " + Received message fragment: {}".format(
                                    current_port.get_last_message().get_message_payload()
                                )
                            )
                        else:
                            ## Encountered an unpected message in the sequence, possible cases:
                            # - MESSAGE_NO_RECEIVED > MESSAGE_NO_EXPECTED : Desynchronized
                            # - MESSAGE_NO_RECEIVED = MESSAGE_NO_EXPECTED : Duplicated -> Ignore
                            # - MESSAGE_NO_RECEIVED < MESSAGE_NO_EXPECTED - 1 : Missing messages, Desynchronized

                            if (
                                current_port_message_number
                                != current_port_merge_counter
                            ):
                                ## Handle both desynchronization cases...
                                _log(
                                    "\t\t\t + unexpected message number received, possible desynchronization"
                                )

                                ## Not the best way to handle it, but it's the cheapest fix...
                                current_port.clear_merge_buffer()
                                current_port.set_merge_counter(
                                    current_port_message_number
                                )

                                ## TODO: Figure out a better way to handle this failure case.
                    else:
                        ## Otherwise, this is likely the start of a new chunked message...
                        _log("\t + merge_buffer doesn't have content")
                        current_port.append_to_merge_buffer(
                            current_port.get_last_message().get_message_payload()
                        )
                        current_port.set_merge_counter(current_port_message_number)
                        _log(
                            "_main_loop_iterate() -> Received new message fragment: {}".format(
                                current_port.get_last_message().get_message_payload()
                            )
                        )

                ## Start broadcasting that we have received the mssage
                # and set our internal communication state to RECEIVED.
                response_message = Message(MESSAGE_TYPE_RECEIVED)
                _log(
                    "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                        thread_id, response_message, current_port_channel
                    )
                )
                await self._send_now(response_message, current_port_channel)
                self._communication_state = COMMUNICATION_STATE_RECEIVED
                _log(
                    "BrickNet._main_loop_iterate: Received SENT, broadcasting RECEIVED"
                )

                ## Reset the internal stopwatch so that we can start
                # tracking the amount of time the device spends outside
                # of the READY state.
                self._stopwatch.reset()

                ## Skip the rest of the function for this iteration...
                return

            if current_port.get_last_message().get_message_type() == MESSAGE_TYPE_READY:
                ## We,re ready, and the remote device is ready..

                ## First, check if we already processed this port already..
                if current_port.this_port_is_processed():
                    ## If it is, then we reset the flag and increment the
                    # port index.
                    current_port.set_is_processed(False)
                    self._increment_port_index()

                    _log(
                        "BrickNet._main_loop_iterate: Received READY, port is processed already, incrementing"
                    )

                    ## Then skip the rest of the function for this iteration..
                    return

                ## Check if there are any messages in the queue for this port.
                # if len(current_port.messages_for_this_port()) > 0:
                if current_port.messages_for_this_port().get_length() > 0:
                    ## There are messages in the queue for this port...

                    ## Broadcast the first message in the message queue for
                    # this port.
                    _log(
                        "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                            thread_id,
                            current_port.messages_for_this_port().peek(),
                            current_port_channel,
                        )
                    )
                    await self._send_now(
                        current_port.messages_for_this_port().peek(),
                        current_port_channel,
                    )
                    self._communication_state = COMMUNICATION_STATE_SENT
                    _log(
                        "BrickNet._main_loop_iterate: Received READY, there are unsent messages, broadcasting SENT"
                    )

                    ## Reset the stopwatch such that we start tracking how
                    # much time will pass now that the state has transitioned
                    # over to SENT.
                    self._stopwatch.reset()

                    ## Skip the rest of the function for this iteration
                    return

        elif self._communication_state == COMMUNICATION_STATE_SENT:
            ## If the device is in this state, then it's expecting to receive
            # a RECEIVED message back from the other device.
            if (
                current_port.get_last_message().get_message_type()
                == MESSAGE_TYPE_RECEIVED
            ):
                ## We received confirmation that the remote device received our
                # last message.

                # So now we can move this device's state to READY and
                # broadcast that we are ready to send again.
                response_message = Message(MESSAGE_TYPE_READY)
                self._communication_state = COMMUNICATION_STATE_READY
                _log(
                    "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                        thread_id,
                        response_message,
                        current_port_channel,
                    )
                )
                await self._send_now(response_message, current_port_channel)

                _log(
                    "BrickNet._main_loop_iterate: Received RECEIVED, broadcasting READY"
                )

                # We also set the flag for this port to indicate that
                # we have successfully processed the message queue
                # and we can move on to the next port.
                current_port.set_is_processed(True)

                ## We can also dequeue the message for this port.
                current_port.messages_for_this_port().dequeue()

                ## lastly, skip the rest of this iteration.
                return

            ## If it didn't receive RECEIVED from the remote device,
            # then we need to check if we've timedout yet.
            if self._stopwatch.time() > MESSAGE_STATE_TRANSITION_TIMEOUT_MS:
                ## The elapsed time on the stopwatch exceeds the timeout threshold...

                ## Revert the device state back to READY and broadcast
                # that state to the remote device.
                response_message = Message(MESSAGE_TYPE_READY)
                self._communication_state = COMMUNICATION_STATE_READY
                _log(
                    "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                        thread_id,
                        response_message,
                        current_port_channel,
                    )
                )
                await self._send_now(response_message, current_port_channel)
                _log(
                    "BrickNet._main_loop_iterate: SENT but no response, broadcasting READY"
                )

                ## Skip the rest of this iteration.
                return

        elif self._communication_state == COMMUNICATION_STATE_RECEIVED:
            ## If the device is in this state, then it's broadcasting
            # the RECEIVED state and it is expecting the remote device
            # to acknowledge its received state by responding with READY.
            if current_port.get_last_message().get_message_type() == MESSAGE_TYPE_READY:
                ## The remote device received our acknowledgement and is
                # ready to send again, so we should broadcast that we
                # will also be returning to our READY state to complete
                # the process.
                response_message = Message(MESSAGE_TYPE_READY)
                self._communication_state = COMMUNICATION_STATE_READY
                _log(
                    "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                        thread_id,
                        response_message,
                        current_port_channel,
                    )
                )
                await self._send_now(response_message, current_port_channel)
                _log("BrickNet._main_loop_iterate: Received READY, broadcasting READY")

                ## Skip the rest of the iteration
                return

            ## If it didn't receive READY from the remote device,
            # then we need to check if we've timedout yet.
            if self._stopwatch.time() > MESSAGE_STATE_TRANSITION_TIMEOUT_MS:
                ## The elapsed time on the stopwatch exceeds the timeout threshold...

                ## Revert the device state back to READY and broadcast
                # that state to the remote device.
                response_message = Message(MESSAGE_TYPE_READY)
                self._communication_state = COMMUNICATION_STATE_READY
                _log(
                    "_main_loop_iterate() #{} -> _send_now({}, {}) ".format(
                        thread_id,
                        response_message,
                        current_port_channel,
                    )
                )
                await self._send_now(response_message, current_port_channel)
                _log(
                    "BrickNet._main_loop_iterate: RECEIVED, but no response, broadcasting READY"
                )

        else:
            raise Exception(
                "[BrickNet]: Unknown communication state: {}".format(
                    self._communication_state
                )
            )

    async def _broadcast(self, message):
        """
        Reference to the correct broadcast method for the bluetooth manager.
        """
        if self.get_bluetooth_manager_type() == "BrickBLE":
            ## TODO: Make this awaitable?
            self.get_bluetooth_manager().broadcast(message)
            return

        ## Otherwise, use the hub method.
        await self.get_bluetooth_manager().ble.broadcast(message)

    def _observe(self, channel):
        """
        Reference to the correct observe method for the bluetooth manager.
        """
        if self.get_bluetooth_manager_type() == "BrickBLE":
            return self.get_bluetooth_manager().observe(channel)

        ## Otherwise, use the hub method.
        return self.get_bluetooth_manager().ble.observe(channel)

    async def _send_now(self, message, destination_channel):
        """
        Bypasses the message queue and immediately broadcasts the specified message.

        The destination_channel is only used when the bluetooth manager type
        is BrickBLE. Otherwise, it uses the broadcast channel specified when
        the bluetooth manager was initialized.

        @param `message` : Message
        @param `destination_channel` : int, 0-255
        """

        if self.get_bluetooth_manager_type() == "BrickBLE":
            ## Since the BrickBLE package is the only bluetooth manager
            # that supports switching broadcast channels, we only use
            # the destination_channel parameter when BrickBLE is being used.
            self.get_bluetooth_manager().set_broadcast_channel(destination_channel)

        await self._broadcast(message.get_broadcast_data())
        _log("BrickNet._send_now: sent {}".format(message.get_message_type()))

    def _increment_port_index(self):
        """
        Increments the internal port index counter, automatically wrapping
        back to the front when it reaches the end.
        """
        length_of_message_queue = len(self._message_queue)
        self._current_port_index = (
            self._current_port_index + 1
        ) % length_of_message_queue

    def _split_message_into_chunks(self, message, message_subtype):
        ## ASSUMPTION: Only the SENT message type has a payload,
        # so this function will only produce MESSAGE_TYPE_SENT
        messages_to_send = []

        max_payload_length = Message.get_max_payload_length_for_subtype(message_subtype)

        if type(message) is str:
            message_length = len(message)
            if message_length > max_payload_length:
                number_of_chunks = ceil(message_length / max_payload_length)
                for i in range(number_of_chunks):
                    start_i = i * max_payload_length
                    calculated_end_i = start_i + max_payload_length
                    end_i = (
                        message_length
                        if calculated_end_i >= message_length
                        else calculated_end_i
                    )
                    messages_to_send.append(
                        Message(
                            MESSAGE_TYPE_SENT,
                            message_subtype=MESSAGE_SUBTYPE_DIRECT,
                            ## Message number is descending, so that we can just check
                            # if the message number is 0 to know that it's the last message.
                            message_number=number_of_chunks - 1 - i,
                            payload=message[start_i:end_i],
                        )
                    )
                return messages_to_send

            ## Otherwise, the message is shorter than the maximum payload length.
            messages_to_send.append(
                Message(
                    MESSAGE_TYPE_SENT,
                    message_subtype=MESSAGE_SUBTYPE_DIRECT,
                    message_number=0,
                    payload=message,
                )
            )
            return messages_to_send

    def send(self, destination, message):
        """
        Sends a `message` through BrickNet to the targetted `destination`.

        @param `destination` : A destination BrickNet node ID.
        @param `message` : The contents to send to the specified ID.
        """

        messages_to_send = self._split_message_into_chunks(
            message, MESSAGE_SUBTYPE_DIRECT
        )
        _log("send() -> messages_to_send:")
        for message in messages_to_send:
            _log(" + {}".format(message))

        # message = Message(MESSAGE_TYPE_SENT, message)
        enqueued_successfully = False
        for port in self._message_queue:
            ## Iterate through the list of ports inside the message queue...
            if port.get_broadcast_target_channel() == destination:
                ## We found a matching port containing the destination...
                for message in messages_to_send:
                    port.messages_for_this_port().enqueue(message)
                enqueued_successfully = True

        if enqueued_successfully == False:
            ## Otherwise, if we aren't able to enqueue the message...
            raise Exception(
                "[BrickNet]: No ports found with the following target: {}".format(
                    destination
                )
            )

    def onReceived(self, handler):
        """
        Specify the handler function to run whenever a message is received.

        @param `handler`: a function taking the following parameters: (channel, message)
        """
        self._on_received_handler = handler

    def __old_fetch(self, resource, options={}):
        """
        If called from a LEGO SPIKE, it serializes the HTTP request and sends
        it to the EV3 for it to make the request.

        If called from a LEGO EV3, it makes an HTTP request.
        """

        async def __fetch(resource, options, thread_pool, thread_id):
            _log("\t\t__fetch(): handled by thread #{}".format(thread_id))
            default_options = {
                "method": "GET",
                "headers": {},
                "body": {},
            }
            merged_options = {**default_options, **options}

            request = Request(resource, headers=merged_options["headers"])

            _log(
                "\t\t__fetch(): attempting to make http request to {}".format(resource)
            )
            try:
                with urlopen(request, timeout=5) as response:
                    _log("\t\t__fetch(): HTTP{}".format(response.status))
                    _log("\t\t__fetch(): response body: {}".format(response.read()))
            except HTTPError as e:
                print(e.status, e.reason)
            except URLError as e:
                print(e.reason)
            except TimeoutError:
                print("Request timed out")

        ## Spawn the thread to handle the http request.
        self._fthread_pool.spawn(__fetch, resource, options)

    def fetch(self, resource, options={}):
        default_options = {
            "method": "GET",
            "headers": {},
            "body": {},
        }
        merged_options = {**default_options, **options}

        ## PHASE 1 : PARSE THE URL
        ## -----------------------
        url = {
            "protocol": None,
            "hostname": None,
            "port": None,
            "path": None,
        }

        ## Strip the URL
        __url = resource.strip()

        ## Parse the protocol.
        protocol_delimiter = __url.find("://")
        if protocol_delimiter > 0:
            ## A protocol was specified in the URL.
            url["protocol"] = __url[:protocol_delimiter].lower()
            if url["protocol"] == "http":
                url["port"] = 80
            elif url["protocol"] == "https":
                url["port"] = 443
            else:
                raise Exception(
                    "The protocol {} is not supported.".format(url["protocol"])
                )

            ## Eliminate the protocol from the URL since we already parsed it.
            __url = __url[protocol_delimiter + 3 :]

        ## Parse the URL path.
        path_delimiter = __url.find("/")
        if path_delimiter == -1:
            ## The URL is in the form of: hostname:port
            url["path"] = "/"
        else:
            url["path"] = __url[path_delimiter + 1 :]

        ### Parse the hostname.
        # If the protocol was not specified earlier, then
        # either the URL is invalid or it is in the form of:
        # hostname:port/path/to/resource?query=parameters
        # or
        # hostname/path/to/resource?query=parameters
        hostname_port = __url[:path_delimiter]

        port_delimiter = hostname_port.find(":")
        if port_delimiter == -1:
            ## The hostname_port only contains the hostname.
            if url["protocol"] is None:
                url["port"] = 80
                url["protocol"] = "http"
            url["hostname"] = hostname_port
        else:
            ## Otherwise, the hostname_port contains the hostname and port.
            url["port"] = int(hostname_port[port_delimiter + 1 :])
            url["hostname"] = hostname_port[:port_delimiter]

        ## Throw an exception if the URL failed to parse.
        if None in url.values():
            raise Exception(
                "[BrickNet]: An error occured while parsing the URL: {}".format(
                    resource
                )
            )

        async def __fetch(url, merged_options, thread_pool, thread_id):
            ## PHASE 2 : MAKING THE HTTP REQUEST
            ## ---------------------------------

            ## Resolve the hostname to an IP Address.
            hostname_ip = gethostbyname(url["hostname"])

            ## Create the HTTP Client Socket.
            http_socket = socket(AF_INET, SOCK_STREAM)
            if url["protocol"] == "https":
                http_socket = wrap_socket(http_socket)

            ## Building the HTTP Request.
            minimal_header = {"Host": url["hostname"]}  ## Required in HTTP/1.1
            serialized_header = ""
            for k, v in {**minimal_header, **merged_options["headers"]}.items():
                serialized_header += "{}: {}\r\n".format(k, v)

            serialized_request = "{} {} HTTP/1.1\r\n{}\r\n\r\n".format(
                merged_options["method"],
                url["path"],
                serialized_header,
            )

            ## Connecting to the server.
            http_socket.connect((hostname_ip, url["port"]))

            ## Sending the request.
            http_socket.sendall(serialized_request.encode())

            ## Await the response.
            serialized_response = ""
            while True:
                try:
                    data = http_socket.recv(1024, MSG_DONTWAIT)
                    if data == b"":
                        break
                    serialized_response += data.decode()
                except Exception as e:
                    _log(
                        "__fetch() #{}: while listening, an exception occured: {}".format(
                            thread_id, e
                        )
                    )
                finally:
                    ## always yield control to another coroutine.
                    await sleep_until_ms(1)

            ## Handle the HTTP Response.
            _log(
                "__fetch() #{}: Received Response: \n---{}\n---".format(
                    serialized_response
                )
            )

            ## Close the HTTP socket.
            http_socket.close()

        ## Spawn the thread to handle the HTTP Request.
        self._fthread_pool.spawn(__fetch, url, merged_options)
