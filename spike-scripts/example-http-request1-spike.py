from bricknet import BrickNet

DEBUG_ENABLED = True


def _log(input):
    if DEBUG_ENABLED:
        print("[example-http-request1-spike.py]: {}".format(input))


def main():
    _log("Initializing BrickNet instance...")
    _log(" + bluetooth manager: InventorHub")
    _log(" + observing channels: [1]")
    _log(" + broadcasting channel: 1")
    bricknet_instance = BrickNet(
        "InventorHub", observe_channels=[1], broadcast_channel=1
    )

    def handle_received_message(channel, message):
        print(
            "RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message)
        )
        bricknet_instance.stop()

    bricknet_instance.onReceived(handle_received_message)

    initial_message = "https://console.brickmmo.com/api/colours/random"
    _log("Setting the initial message to: \n\t{}".format(initial_message))
    bricknet_instance.send(1, initial_message)

    bricknet_instance.start()
    _log("BrickNet instance started...")
    return


if __name__ == "__main__":
    main()
