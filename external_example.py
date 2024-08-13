from brick_ble import BrickBLE
from time import sleep

if __name__ == "__main__":
    with BrickBLE(broadcasting_channel=2, observing_channels=[1]) as ble:
        print("Listening for BLE Broadcasts...")

        broadcasting_data = "123456789012345678901234"

        while True:
            try:
                channel_data = ble.observe(1)
                if channel_data is not None:
                    print("Observed {} from channel 1".format(channel_data))
                    print(
                        "Returning with {} to channel {}".format(
                            broadcasting_data, ble._broadcast_channel
                        )
                    )
                    ble.broadcast(broadcasting_data)
                    #broadcasting_data+= 1.0
                    #if(broadcasting_data > 2147483647 or broadcasting_data <  -2147483648):
                    #    break
                sleep(1)

            except KeyboardInterrupt:
                break

    print("Program exited gracefully")
