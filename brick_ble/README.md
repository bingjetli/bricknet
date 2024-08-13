# BrickBLE : LEGO EV3 to LEGO SPIKE Bluetooth Low Energy (BLE) Communication

This is an importable python package containing methods that allows the
LEGO EV3 Hub to communicate with the LEGO SPIKE Hub over Bluetooth.

PyBricks exposes the `.broadcast()` and `.observe()` methods to allow
communication between the LEGO SPIKE Hubs over Bluetooth.

This package aims to provide the same `.broadcast()` and `.observe()`
functionality to the LEGO EV3.

&nbsp;
&nbsp;

# Requirements

The EV3 requires a Bluetooth Low Energy (BLE) compatible dongle connected
to the USB port in order to communicate with the LEGO SPIKE Hubs.

Wi-Fi and BLE can be used together if connected together using a USB Hub.

&nbsp;
&nbsp;

# Installation

To install, copy the contents of this directory into a folder called `brick_ble`
inside your projects root directory.

The project directory should look like

```
/project_root_directory
 |
 +--/brick_ble
 |   |
 |   +--/py_bluetooth_utils/...
 |   |
 |   +--__init__.py
 |   |
 |   +--brick_ble.py
 |   |
 |   ...
 |
 +--YOUR_MAIN_PYTHON_FILE
```

&nbsp;
&nbsp;

# Usage

The package can then be imported using the following

```python
from brick_ble import BrickBLE
```

and used inside Python's `with` context manager as follows:

```python
## Setup the context manager
with BrickBLE(broadcasting_channel=2, observing_channels=[2,3]) as ble:
    #...

    ## Observe data from channel 3.
    channel_3_data = ble.observe(3)

    ## Broadcast the data to channel 2
    ble.broadcast("Received {} from channel 3".format(channel_3_data))

    #...
## Automatically cleans up resources used by BrickBLE
```

&nbsp;
&nbsp;

# Documentation

## `BrickBLE(broadcasting_channel=INT, observing_channels=INT\[\])`

This class is similar to how the Hubs are declared in PyBricks, it
initializes a new instance of the BrickBLE class with the specified
parameters.

NOTE: There should only be 1 instance of BrickBLE active at any point
in time.

### Parameters :

-   broadcasting_channel : A value from 0 to 255 indicating which channel the `.broadcast()` method will use. DEFAULT=0.
-   observing_channels : A list of channels to listen to when the `.observe()` method is called. DEFAULT=\[\] (An empty list)

&nbsp;

## `.broadcast(data)`

Broadcasts `data` on the channel specified when `BrickBLE` was instantiated.

Passing `None` as the `data` will turn

### Parameters :

-   data : Can be any of the following data types:
    -   boolean : True or False
    -   integer : A signed 32bit integer : -2147483648 to 2147483647
    -   float : A 32bit floating point : 1.175494351e-38 to 3.402823466e+38
    -   string : Maximum 24 characters due to packet size limits.

&nbsp;

## `.observe(channel)`

Retrieves the last observed data for a specified `channel` when `BrickBLE` was instantiated.

### Parameters :

-   channel : The channel from the list of channels specified when `BrickBLE` was instantiated, to observe.

### Returns :

The last observed data. Can be any of the following return types : \[None, boolean, integer, float, string\]
