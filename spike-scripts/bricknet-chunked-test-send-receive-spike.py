from pybricks.hubs import InventorHub
from pybricks.pupdevices import Motor, ColorSensor, UltrasonicSensor
from pybricks.parameters import Button, Color, Direction, Port, Side, Stop
from pybricks.robotics import DriveBase
from pybricks.tools import wait, StopWatch
from bricknet import BrickNet

DEBUG_ENABLED = True
def _log(input):
    if DEBUG_ENABLED:
        print("[test2.py]: {}".format(input))

def main():
    _log("Initializing BrickNet instance...")
    _log(" + bluetooth manager: InventorHub")
    _log(" + observing channels: [1]")
    _log(" + broadcasting channel: 1")
    bricknet_instance = BrickNet("InventorHub", observe_channels=[1], broadcast_channel=1)

    def handle_received_message(channel, message):
        print("RECEIVED EVENT:\n + channel: {}\n + message: {}".format(channel, message))

        reply = "Hi EV3, I got your message: {}".format(message)
        print(" + replying with: {}".format(reply))
        bricknet_instance.send(channel, reply)
        bricknet_instance.stop()

    bricknet_instance.onReceived(handle_received_message)

    initial_message = "Hello EV3, I'm SPIKE, and I am ready to receive messages."
    _log("Setting the initial message to: \n\t{}".format(initial_message))
    bricknet_instance.send(1, initial_message)

    bricknet_instance.start()
    _log("BrickNet instance started...")
    return

if __name__ == "__main__":
    main()
