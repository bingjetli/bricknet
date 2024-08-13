from bricknet import BrickNet
from random import randrange
from ev3dev2.sound import Sound

from urllib.request import urlopen, Request
from urllib.parse import urlencode

# TODO: Sometimes the message received are repeated, figure out of this should be allowed, if not figure out how to prevent it.
# TODO: Add a way to ensure that messages that need to be chunked are sent in the right order and end properly.


DEBUG_ENABLED = True
def _log(input):
    if DEBUG_ENABLED:
        print(input)




reply = True
def main():
    _log("test.py : creating BrickNet instance")
    bricknet_instance = BrickNet("BrickBLE", observing_channels=[1], broadcasting_channel=0)

    ev3_speaker = Sound()

    _log("test.py : defining the message receive handler")
    def handle_received_message(channel, message):
        global reply

        print("RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message))

        random_number = randrange(1, 10)
        if random_number == 5:
            ev3_speaker.speak("Random number is 5, ending transmission")
            print(" + random number is 5, ending transmission")
            reply = False

        if reply == True:
            bricknet_instance.send(channel, "{}".format(random_number))
            ev3_speaker.speak("replying with: {}".format(random_number))
            print(" + replying with: {}".format(random_number))

    _log("test.py : setting the onReceived handler")
    bricknet_instance.onReceived(handle_received_message)

    _log("test.py : sending sample data")
    bricknet_instance.send(1, "Hi SPIKE, I'm EV3")

    _log("test.py : starting the bricknet instance")
    bricknet_instance.start()

    return

if __name__ == "__main__":
    main()
