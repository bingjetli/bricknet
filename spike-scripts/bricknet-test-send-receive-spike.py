from pybricks.hubs import InventorHub
from pybricks.pupdevices import Motor, ColorSensor, UltrasonicSensor
from pybricks.parameters import Button, Color, Direction, Port, Side, Stop
from pybricks.robotics import DriveBase
from pybricks.tools import wait, StopWatch
from bricknet import BrickNet

DEBUG_ENABLED = True
def _log(input):
    if DEBUG_ENABLED:
        print(input)


def main():
    _log("test.py : creating BrickNet instance")
    bricknet_instance = BrickNet("InventorHub", observe_channels=[1], broadcast_channel=1)

    _log("test.py : defining the message receive handler")
    def handle_received_message(channel, message):
        print("RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message))

        bricknet_instance.get_bluetooth_manager().display.text(message)

        reply = "Roger That"
        print(" + replying with: {}".format(reply))
        bricknet_instance.send(channel, reply)

    _log("test.py : setting the onReceived handler")
    bricknet_instance.onReceived(handle_received_message)

    _log("test.py : sending sample data")
    bricknet_instance.send(1, "Hello EV3, I'm SPIKE")

    _log("test.py : starting the bricknet instance")
    bricknet_instance.start()

    return

if __name__ == "__main__":
    main()
