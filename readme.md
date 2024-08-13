# BrickNet Overview

In development.

This project uses BrickBLE to enable the EV3 to communicate bi-directionally with the LEGO SPIKE connectionless Bluetooth network.

The aim of this project is to allow either the EV3 or the SPIKE to function as nodes in a network and communicate with each other through the network.

&nbsp;

---

# Files Overview

- `bricknet.py` : The main file containing everything required for BrickNet to run.
- `external_example.py` : An example on how to use BrickBLE.
- `bricknet-test-send-receive.py` : A testing script to test the sending & receiving functionality of BrickNet.
- `testing-bytes-send-receive.py` : Another testing script to test the implemented bytes broadcasting functionality in BrickBLE.
- `brick_ble/*` : directory containing the BrickBLE package.
- `spike-scripts/*` : directory containing scripts to be uploaded on the LEGO SPIKE.

&nbsp;

---

# EV3 Setup

1. Ensure a Bluetooth Low Energy capable dongle is connected to the EV3.
2. SSH into the EV3 and copy over the `brick_ble` folder, `bricknet.py` and `bricknet-test-send-receive.py`.
3. Run the testing script using `sudo python3 bricknet-test-send-receive.py`

###### NOTE: `sudo` is required for the script to interact with the Bluetooth controller

&nbsp;

# SPIKE Setup

1. Ensure Pybricks is installed on the LEGO SPIKE.
2. Upload `bricknet.py` and `bricknet-test-send-receive-spike.py` to the LEGO SPIKE hub using Pybricks Code.
3. Run the `bricknet-test-send-receive-spike.py` file inside Pybricks Code.
