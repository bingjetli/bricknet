## Test Script for splitted messages.

from bricknet import BrickNet
from random import randrange
from ev3dev2.sound import Sound

from urllib.request import urlopen, Request
from urllib.parse import urlencode


DEBUG_ENABLED = True
def _log(input):
    if DEBUG_ENABLED:
        print("[test2.py]: {}".format(input))

def main():
    _log("Initializing BrickNet instance...")
    _log(" + bluetooth manager: BrickBLE")
    _log(" + observing channels: [1]")
    _log(" + broadcasting channel: 0")
    bricknet_instance = BrickNet("BrickBLE", observing_channels=[1], broadcasting_channel=0)

    def handle_received_message(channel, message):
        print("RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message))

    bricknet_instance.onReceived(handle_received_message)

    ## IDEA: Decouple the HTTP Fetch functionality from BrickNet by making it
    # hook into the BrickNet pipeline to handle custom packets.
    initial_message = "Contrary to popular belief, Lorem Ipsum is not simply random text. It has roots in a piece of classical Latin literature from 45 BC, making it over 2000 years old. Richard McClintock, a Latin professor at Hampden-Sydney College in Virginia, looked up one of the more obscure Latin words, consectetur, from a Lorem Ipsum passage, and going through the cites of the word in classical literature, discovered the undoubtable source. Lorem Ipsum comes from sections 1.10.32 and 1.10.33 of \"de Finibus Bonorum et Malorum\" (The Extremes of Good and Evil) by Cicero, written in 45 BC. This book is a treatise on the theory of ethics, very popular during the Renaissance."
    bricknet_instance.send(1, initial_message)
    _log("Setting the intial message to: \n\t{}".format(initial_message))

    bricknet_instance.start()
    _log("BrickNet instance started...")
    return

if __name__ == "__main__":
    main()
