# Sca-Ed25519

This is repository for Ed25519 signature generation implementation on Cortex-M4 with extensive side-channel protections.

This implementation is built on [Sca25519](https://github.com/sca-secure-library-sca25519/sca25519) scalar multiplication and modular arithmetics. Masked SHAKE256 is used from [Masked Kyber](https://github.com/masked-kyber-m4/mkm4), therefore our implementation is not compliant with standardized Ed25519-SHA512 variant, but this choice provides additional side-channel countermeasures.

## Overview

Code for modular arithmetic from Sca25519 is in files: `fe25519.*`, `fe25519_invert.*`, `bigint.*`, `sc25519.*` and in `asm` folder in optimize assembly format.

Code for scalar multiplication from Sca25519 with our marked modification is in `scalarmult_25519.*` file. This file contains three versions on scalar multiplication, similar as in Sca25519: unprotected, ephemeral and static with extensive side-channel countermeasures.

Code for masked SHAKE256 from Kyber is in `fips202-masked.*` and `keccakf1600.S`

Our code for the Ed25519 signature generation on Cortex-M4 is in `ed25519`. This file contains three versions: unprotected, ephemeral and static with extensive side-channel countermeasures.

Our code for the Ed25519 key pair generation and signature verification in Python is in `cw/ed25519cw_ed25519.py`.

Our code for performance evaluation on STM32F4 is in `main.*`.

Other code in `ed25519` is from Sca25519 and is used for operating the STM32F4 board.

Folder `cw` contains TVLA evaluation. Folders `cw/ed25519/crypto` and `ed25519/crypto` should be same, containing the Ed25519 implementation. Only difference is `support/randombytes.c` where the version for STM32F4 utilizes its on TRNG on device, whereas version in `cw` uses `rand()` from `stdlib.c`, because ChipWhisperer-Lite do not have TRNG. 

Files `cw/ed25519/main.*` and `cw/ed25519/test.*` contains our functions for TVLA on ChipWhisperer.

File `simpleserial_ed25519-CWLITEARM.hex` contains executible for ChipWhisperer.

File `ed25519.ipynb` is our Jupyter notebook for TVLA evaluation on ChipWhisperer.

## Evaluation

### Perormance

Run code on STM32F4 device and uncomment function that needs to be evaluated in `ed25519/main.c` in `main` fnc, such as `cycles_sign_static();`. Compile, flash on device, connect via Python and restart the device to see the ouput.

### Side-Channel

Choose evaluation of scalar multiplication or signing by defining macro in `cw/ed25519/main.c`: `#define TVLA TVLA_SCAMULT` or `#define TVLA TVLA_SIGN`. Then with connected ChipWshiperer-Lite and running environment, run `jupyter notebook` (in VM it is already running) and open in the browser `http://localhost:8888/`. Don't forget to copy the `cw/ed25519` as in installation below. Open `ed25519.ipynb` in the browser environment and start executing cells until the compiled code is flashed into device (or skip the compilation code if you want to use the included one - beware, executed compilation will rewrite it). Skip to cells with evalutaion, such as `TVLA: Sign 1000x static` and run them. Subsequent cells will store measured data into file system and evaluate them, resulting in graph with t statistics. Make sure that you compiled the code with correct define according to wanted test.

## Installation on STM32F407 development board

This part is taken from the original [Sca25519](https://github.com/sca-secure-library-sca25519/sca25519)project.

This code assumes you have the `arm-none-eabi` toolchain installed and accessible (`arm-none-eabi-gcc` or `gcc-arm-none-eabi` package).
Besides a compiler and assembler, you may also want to install `arm-none-eabi-gdb`.

This project relies on the `libopencm3` firmware. This is included as a submodule and we also included it directly to the folder `libopencm3` in the main directory. When using git from the command line, you might need to execute `git submodule init` and `git submodule update` in the root directory first. Compile it (e.g. by calling `make lib` within the `ed25519`) before attempting to compile any of the other targets. On some systems where there is no symlink from the `python3` binary to a python executable available, you might need to replace the line `#!/usr/bin/env python` in the files `gendoxylayout.py` and `genlink.py` with `#!/usr/bin/env python3` instead (subdirectory `libopencm3/scripts`). If you observe problems with building `libopencm3` (e.g. reports regarding "unterminated quotes") it might help to fix line #27 in the file `libopencm3/Makefile` by replacing the assignment

`SRCLIBDIR:= $(subst $(space),\$(space),$(realpath lib))`

with

`SRCLIBDIR:= $(subst $(space),\$(space),$(realpath ./))/lib`

or if your directory path does not contain spaces with

`SRCLIBDIR:= $(subst $(space),/$(space),$(realpath lib)). \`

The binary can be compiled by calling `make` in `ed25519` directory. The binary can then be flashed onto the boards using `stlink`, as follows: `st-flash write main.bin 0x8000000`. Depending on your operating system, `stlink` may be available in your package manager -- otherwise refer to their Github page for instructions on how to compile it from source (in that case, be careful to use `libusb-1.0.0-dev`, `libusb-0.1`).

The host-side Python 3 code requires the `pyserial` module. Your package repository might offer python-serial or python-pyserial directly (as of writing, this is the case for Ubuntu, Debian and Arch). Alternatively, this can be easily installed from PyPA by calling pip install pyserial (or pip3, depending on your system). If you do not have pip installed yet, you can typically find it as python3-pip using your package manager. Use the `host_unidirectional.py` script to receive data from the board.

To get the result from the device, call `python ../hostside/host_unidirectional.py` from `ed25519` directory and restart the device to catch the output. Possibly, the device name woud need to be changed in `host_unidirectional.py` according to your USB device in `/dev/` or similar.

Connect the board to your machine using the mini-USB port. This provides it with power, and allows you to flash binaries onto the board. It should show up in `lsusb` as STMicroelectronics ST-LINK/V2.

Using dupont / jumper cables, connect the `TX`/`TXD` pin of the USB connector to the `PA3` pin on the board, and connect `RX`/`RXD` to `PA2`. Depending on your setup, you may also want to connect the `GND` pins.

For the full tutorial follow Sca25519 [repository](https://github.com/sca-secure-library-sca25519/sca25519).

## Installation on ChipWhisperer-Lite

For the evaluation on ChipWhisperer-Lite, their [release](https://github.com/newaetech/chipwhisperer/releases/tag/5.6.1) `5.6.1` must be use in virtual machine. Follow their [guide](https://chipwhisperer.readthedocs.io/en/latest/virtual-box-inst.html).

Then copy the `cw/ed25519` folder inside the VM into ChipWhisperer file system in `hardware/victims/firmware` and start executing the `ed25519.ipynb`. New `PyCryptodome` library version needs to be installed, possibly by uninstalling the current and installing new via `pip`.

## License
Our code is under CC0 license.

Files for masked SHAKE256 `keccakf1600.S` and `fips202-masked.*` are adapted from [Kyber](https://github.com/masked-kyber-m4/mkm4) under MIT license.

Files related to the modular arithmetic, scalar multiplication and STM32F4 device is taken from [Sca25519](https://github.com/sca-secure-library-sca25519/sca25519) under CC0 license.

Function `fe25519_pow2523` in `fe25519_invert.c` is adapted from [SUPERCOP](https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref/fe25519.c), which is Public Domain.

Folder [libopenmc3](https://github.com/libopencm3/libopencm3) is under GPLv3 license.
