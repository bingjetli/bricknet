from brick_ble import BrickBLE
from time import sleep
import struct

if __name__ == "__main__":
    with BrickBLE(broadcasting_channel=1, observing_channels=[0]) as ble:
        print("Listening for BLE Broadcasts...")

        while True:
            try:
                channel_data = ble.observe(0)
                if channel_data is not None:
                    print("Observed {} from channel 1".format(channel_data.hex()))
                    ble.broadcast(channel_data)
                    print(
                        "Returning with {} to channel {}".format(
                            channel_data.hex(), ble._broadcast_channel
                        )
                    )
                    #broadcasting_data+= 1.0
                    #if(broadcasting_data > 2147483647 or broadcasting_data <  -2147483648):
                    #    break
                sleep(1)

            except KeyboardInterrupt:
                break

    print("Program exited gracefully")
