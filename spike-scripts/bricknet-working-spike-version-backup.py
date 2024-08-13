
## Try to import all availble bluetooth managers..
try:
    from brick_ble import BrickBLE
except ImportError:
    print("BrickNet: Unable to import BrickBLE")

try:
    from pybricks.hubs import InventorHub
except ImportError:
    print("BrickNet: Unable to import InventorHub")


DEBUG_ENABLED = False
def _log(input, repeat_last=False):
    if DEBUG_ENABLED:
        print(input)


## BRICKNET PROJECT SPECIFICATIONS :
# - it should:
#   - be able to send extended string data.
#       - send extended strings in peicewise packets.
#   - be able to specify where to send this data.
#   - run concurrently with the main program.
#       - the EV3 side can run in another thread, but what about the
#         LEGO SPIKE?
#       - Maybe we could make it event handler based? So there is a main
#         event loop, and Pybrick's SPIKE can just react to different events

## RELIABILITY TECHNIQUES :
# 1. Sequenced Messages
#   By assigning a number to each piecewise packets sent, we can ensure
#   that the data is received in order.
#
# 2. Receive Receipts
#   The receiver should send back "acknowledgement" packets to indicate
#   that the previous message has been successfully received and the
#   sender can send the next message.


# with BrickBLE(broadcasting_channel=2, observing_channels=[2, 3]) as ble:
## do something...

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

MESSAGE_TYPE_READY = "#R#"
MESSAGE_TYPE_SENT = "#S#"
MESSAGE_TYPE_RECEIVED = "#A#"

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


## Conditionally define the Stopwatch class if it hasn't been defined
# using the import statement.
if "StopWatch" not in globals():
    try:
        ## If the StopWatch class is not imported already, we'll try to import
        # it using an exec statement.
        exec("from pybricks.tools import StopWatch")
    except ImportError:
        ## If we failed to import this class, then we are probably not
        # running on the SPIKE Hub. In that case, we are likely running
        # on the EV3 or an external device capable of running Python3
        exec("from time import perf_counter")

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
    _payload = None

    def __init__(self, message_type, payload=None):
        ## Error checking to ensure a correct message type is passed in.
        if (
            message_type != MESSAGE_TYPE_READY
            and message_type != MESSAGE_TYPE_SENT
            and message_type != MESSAGE_TYPE_RECEIVED
        ):
            raise Exception("[BrickNet]: Unknown message type: {}".format(message_type))

        self._header = message_type
        ## TODO: Implement error checking to ensure that the correct size
        # is passed in.
        self._payload = payload

    def get_broadcast_data(self):
        """
        Returns the data that can be passed into the .broadcast() method.
        """
        return "{}{}".format(self._header, self._payload if self._payload else "")

    def get_message_type(self):
        return self._header

    def get_message_payload(self):
        return self._payload


class Port(object):
    _channel = None
    _remote_state = None
    _last_message = None

    ## Contains a list of Message instances...
    _to_send = None
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

    # Dynamite Jobs: Job recruiting website. TODO: add this to notes.
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
        _log("BrickNet.__init__ : {} is a valid bluetooth_manager_type.".format(bluetooth_manager_type))

        ## Then, try to obtain the specified Bluetooth Manager class from
        # the global symbols collection and assign it to bluetooth_manager_class.
        bluetooth_manager_class = globals().get(bluetooth_manager_type)
        _log("BrickNet.__init__ : {} was obtained from the global symbols collection.".format(bluetooth_manager_class))

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
        for (key, value) in filtered_kwargs.items():
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

        ## Initialize the current port
        self._current_port_index = 0
        _log("BrickNet.__init__ : initialized current_port_index as {}".format(self._current_port_index))

        ## Initialize the stopwatch
        self._stopwatch = StopWatch()
        _log("BrickNet.__init__ : stopwatch initialized")

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
        """
        if self._bluetooth_manager_type == "BrickBLE":
            _log("BrickNet.start : Using the BrickBLE bluetooth manager.")
            with self._bluetooth_manager as brick_ble:
                self._start_event_loop(brick_ble)
        else:
            _log("BrickNet.start : Not using the BrickBLE bluetooth manager.")
            hub_ble = self._bluetooth_manager.ble
            self._start_event_loop(hub_ble)

    def _start_event_loop(self, ble):
        self._is_running = True
        self._communication_state = COMMUNICATION_STATE_READY

        _log("BrickNet._start_event_loop : broadcasting to the first port that this device is ready.")
        ## Broadcast to the first port that it is ready.
        current_port = self._message_queue[self._current_port_index]
        current_port_channel = current_port.get_broadcast_target_channel()
        initial_message = Message(MESSAGE_TYPE_READY)
        self._send_now(initial_message, current_port_channel)


        _log("BrickNet._start_event_loop : Main event loop is started.")
        while self._is_running:
            try:
                self._main_loop_iterate()

            except KeyboardInterrupt:
                ## If Ctrl+C was encountered, then we break out of the loop.
                self._stop_event_loop()

    def _stop_event_loop(self):
        _log("BrickNet._stop_event_loop : Main event loop set to stop.")
        self._is_running = False

    def _main_loop_iterate(self):

        # ## First check that the device is in a state that is ready to
        # # send messages..
        # if self._communication_state != COMMUNICATION_STATE_READY:
        #     ## We shouldn't try to send any more messages from the message
        #     # queue unless this device is ready to send.
        #     return

        # ## TODO: We also need to check if the receiver is ready to receive.
        # # so maybe we can add some kind of device state tracking inside
        # # the message queue?

        # ## Are there any messages waiting to be sent inside the message queue?
        # if len(self._message_queue) > 0:
        #     ## Send a message then..
        #     message_to_send = self._message_queue.dequeue()

        #     ## TODO: Send this message to the specified destination

        current_port = self._message_queue[self._current_port_index]
        current_port_channel = current_port.get_broadcast_target_channel()

        _log("BrickNet._main_loop_iterate: processing port: {}".format(current_port_channel))

        ## First, try to observe any data that was broadcasted over Bluetooth.
        #observed_data = self.get_bluetooth_manager().observe(current_port_channel)
        observed_data = self._observe(current_port_channel)
        if observed_data == None:
            ## We didn't observe any data from this channel, so the remote device
            # might not be READY. In this case, we can skip this channel and try
            # to see if another channel might be ready.
            self._increment_port_index()
            _log("Bricket._main_loop_iterate: No observed data, incrementing port..")
            return

        ## Otherwise, if we observed something other than None...
        message_type = observed_data[0:3]
        message_payload = (
            observed_data[3:] if message_type == MESSAGE_TYPE_SENT else None
        )
        current_port.set_last_message(Message(message_type, message_payload))
        _log("BrickNet._main_loop_iterate: observed message: {}".format(message_type))


        if self._communication_state == COMMUNICATION_STATE_READY:
            ## We're ready to receive or send messages...
            if current_port.get_last_message().get_message_type() == MESSAGE_TYPE_SENT:
                ## We're ready, and the remote device just sent something...

                # Call the .onReceived event handler with the current
                # port channel, and the last message's payload data.
                if self._on_received_handler is not None:
                    self._on_received_handler(
                        current_port_channel,
                        current_port.get_last_message().get_message_payload(),
                    )
                _log("BrickNet._main_loop_iterate: Received SENT, called received hanlder")

                ## Start broadcasting that we have received the mssage
                # and set our internal communication state to RECEIVED.
                response_message = Message(MESSAGE_TYPE_RECEIVED)
                self._send_now(response_message, current_port_channel)
                self._communication_state = COMMUNICATION_STATE_RECEIVED
                _log("BrickNet._main_loop_iterate: Received SENT, broadcasting RECEIVED")

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

                    _log("BrickNet._main_loop_iterate: Received READY, port is processed already, incrementing")

                    ## Then skip the rest of the function for this iteration..
                    return

                ## Check if there are any messages in the queue for this port.
                #if len(current_port.messages_for_this_port()) > 0:
                if current_port.messages_for_this_port().get_length() > 0:
                    ## There are messages in the queue for this port...

                    ## Broadcast the first message in the message queue for
                    # this port.
                    self._send_now(
                        current_port.messages_for_this_port().peek(),
                        current_port_channel,
                    )
                    self._communication_state = COMMUNICATION_STATE_SENT
                    _log("BrickNet._main_loop_iterate: Received READY, there are unsent messages, broadcasting SENT")


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
                self._send_now(response_message, current_port_channel)

                _log("BrickNet._main_loop_iterate: Received RECEIVED, broadcasting READY")

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
                self._send_now(response_message, current_port_channel)
                _log("BrickNet._main_loop_iterate: SENT but no response, broadcasting READY")

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
                self._send_now(response_message, current_port_channel)
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
                self._send_now(response_message, current_port_channel)
                _log("BrickNet._main_loop_iterate: RECEIVED, but no response, broadcasting READY")

        else:
            raise Exception(
                "[BrickNet]: Unknown communication state: {}".format(
                    self._communication_state
                )
            )

    def _broadcast(self, message):
        """
        Reference to the correct broadcast method for the bluetooth manager.
        """
        if self.get_bluetooth_manager_type() == "BrickBLE":
            self.get_bluetooth_manager().broadcast(message)
            return

        ## Otherwise, use the hub method.
        self.get_bluetooth_manager().ble.broadcast(message)

    def _observe(self, channel):
        """
        Reference to the correct observe method for the bluetooth manager.
        """
        if self.get_bluetooth_manager_type() == "BrickBLE":
            return self.get_bluetooth_manager().observe(channel)

        ## Otherwise, use the hub method.
        return self.get_bluetooth_manager().ble.observe(channel)


    def _send_now(self, message, destination_channel):
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

        self._broadcast(message.get_broadcast_data())
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

    def send(self, destination, message):
        """
        Sends a `message` through BrickNet to the targetted `destination`.

        @param `destination` : A destination BrickNet node ID.
        @param `message` : The contents to send to the specified ID.
        """
        ## PACKET STRUCTURE
        # source_node_id : 1 byte
        # destination_node_id : 1 byte
        # message_flag : 1 byte
        #   - 0 : SEND
        #   - 1 : RECEIVED
        #   - 2 : REQUEST_INDEX
        #   - 3 : END
        # payload : ...

        ## SENDING LOGIC
        #   source                                      destination
        # ----------------------------------------------------------------------
        #   for each message queue,
        #       are there messages in this queue?
        #           YES, send message to destination    on message received,
        #                                                   does it have a SEND flag?
        #                                                       YES, did i receive the right index?
        #   on message received,                                    NO, return REQUEST_INDEX [index]
        #       does it have a SEND flag?                           YES, add message into the stack
        #       ...                                                      increment the index counter
        #                                                                return RECEIVED
        #       does it have a REQUEST_INDEX flag?
        #           YES, send message with that index
        #
        #       does it have a RECEIVED flag?
        #           YES, was that the last message?
        #               YES, send END                       does it have a END flag?
        #               NO, send next message                   YES, reset the index counter
        #                                                            build all the messages in the recieved stack
        #                                                            call completed message received handler
        #                                                            clear the messages in the received stack

        ## MESSAGE QUEUE STRUCTURE
        # [
        #   destination_1 : [
        #       [
        #           message_1_part_1,
        #           message_1_part_2,
        #           ...
        #           message_1_part_n,
        #       ],
        #       [
        #           message_2_part_1,
        #           message_2_part_2,
        #           ...
        #           message_2_part_n,
        #       ],
        #       ...
        #       [
        #           message_n_part_1,
        #           message_n_part_2,
        #           ...
        #           message_n_part_n,
        #       ],
        #   ],
        #   destination_2 : [
        #       [MESSAGE_1],
        #       [MESSAGE_2],
        #       ...
        #       [MESSAGE_n],
        #   ],
        #   ...
        #   destination_n : [DESTINATION_MESSAGE_QUEUE],
        # ]
        #

        ## MESSAGE QUEUE STRUCTURE
        # [m, m, ... m]
        # where `m` is a message with the following schema:
        #   {
        #       destination_id,
        #       current_index,
        #       parts:[p, p, ..., p]
        #   }
        # where `p` is a message part with the following schema:
        #
        ## TODO: Add logic to split long messages into chunks
        message = Message(MESSAGE_TYPE_SENT, message)
        enqueued_successfully = False
        for port in self._message_queue:
            ## Iterate through the list of ports inside the message queue...
            if port.get_broadcast_target_channel() == destination:
                ## We found a matching port containing the destination...
                port.messages_for_this_port().enqueue(message)
                enqueued_successfully = True

        if enqueued_successfully == False:
            ## Otherwise, if we aren't able to enqueue the message...
            raise Exception("[BrickNet]: No ports found with the following target: {}".format(destination))

    def onReceived(self, handler):
        """
        Specify the handler function to run whenever a message is received.

        @param `handler`: a function taking the following parameters: (channel, message)
        """
        self._on_received_handler = handler
