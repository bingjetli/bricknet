from brick_ble import BrickBLE
from time import sleep

if __name__ == "__main__":
    with BrickBLE(broadcasting_channel=2, observing_channels=[1]) as ble:
        print("Listening for BLE Broadcasts...")

        while True:
            try:
                channel_data = ble.observe(1)
                print("Observed {} from channel 1".format(channel_data))
                sleep(1)

            except KeyboardInterrupt:
                break

    print("Program exited gracefully")
