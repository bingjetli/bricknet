from bricknet import BrickNet


DEBUG_ENABLED = True


def _log(input):
    if DEBUG_ENABLED:
        print("[example-http-request1.py]: {}".format(input))


_log("initializing the BrickNet instance...")
bricknet = BrickNet("BrickBLE", observing_channels=[1], broadcasting_channel=0)


def handle_received(channel, message):
    print("RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message))

    ## Make another HTTP Request...
    _log("Making another HTTP Request with the url {}".format(message))
    bricknet.fetch(message.decode("utf-8"))


bricknet.onReceived(handle_received)


## Make the HTTP Request...
_log("Making the HTTP Request...")
url = "https://console.brickmmo.com/api/colours/random"
bricknet.fetch(url)


_log("Starting bricknet...")
bricknet.start()
