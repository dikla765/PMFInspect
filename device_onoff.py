#!/usr/bin/env python3
import subprocess
import time
import sys
import argparse
from datetime import datetime


# -----------------------------
# Logging
# -----------------------------
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# -----------------------------
# ADB Helpers
# -----------------------------
def run(cmd, silent=False):
    try:
        if silent:
            subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        else:
            subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        log(f"ERROR executing: {' '.join(cmd)}")
        sys.exit(1)


def adb(cmd, silent=False):
    run(["adb"] + cmd, silent=silent)


# -----------------------------
# Screen Handling
# -----------------------------
def get_screen_state():
    result = subprocess.run(
        ["adb", "shell", "dumpsys", "power"],
        capture_output=True,
        text=True
    )
    return result.stdout


def wake_and_unlock():
    log("Checking screen state...")
    power_state = get_screen_state()

    if "Display Power: state=OFF" in power_state:
        log("Screen OFF → Waking device")
        adb(["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
        time.sleep(1)
    else:
        log("Screen already ON")

    log("Unlocking screen")
    adb(["shell", "input", "swipe", "500", "1500", "500", "500", "300"])
    time.sleep(1)

    adb(["shell", "wm", "dismiss-keyguard"], silent=True)
    time.sleep(1)


# -----------------------------
# Argument Parsing
# -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="ADB automation script")

    parser.add_argument(
        "--app",
        default="com.tplink.iot",
        help="Android package name (default: com.tplink.iot)"
    )

    parser.add_argument(
        "--n",
        type=int,
        default=10,
        help="Number of toggle cycles (default: 10)"
    )

    parser.add_argument(
        "--device",
        nargs=2,
        type=int,
        default=[241, 758],
        metavar=("X", "Y"),
        help="Device tap coordinates (default: 241 758)"
    )

    parser.add_argument(
        "--toggle",
        nargs=2,
        type=int,
        default=[890, 940],
        metavar=("X", "Y"),
        help="Toggle tap coordinates (default: 890 940)"
    )

    return parser.parse_args()


# -----------------------------
# Main Logic
# -----------------------------
def main():
    args = parse_args()

    APP = args.app
    N = args.n
    DEVICE_X, DEVICE_Y = args.device
    TOGGLE_X, TOGGLE_Y = args.toggle

    OPEN_WAIT = 6
    DEVICE_WAIT = 3
    TOGGLE_WAIT = 2

    log("Waiting for device...")
    adb(["wait-for-device"])

    wake_and_unlock()

    # Verify package
    log("Checking package...")
    result = subprocess.run(
        ["adb", "shell", "pm", "path", APP],
        capture_output=True,
        text=True
    )

    if APP not in result.stdout:
        log(f"ERROR: Package {APP} not found")
        sys.exit(1)

    log("Force-stop app")
    adb(["shell", "am", "force-stop", APP])
    time.sleep(1)

    log("Launching app")
    adb(["shell", "monkey", "-p", APP,
        "-c", "android.intent.category.LAUNCHER", "1"], silent=True)
    time.sleep(OPEN_WAIT)

    log(f"Opening device @({DEVICE_X},{DEVICE_Y})")
    adb(["shell", "input", "tap",
        str(DEVICE_X), str(DEVICE_Y)])
    time.sleep(DEVICE_WAIT)

    for i in range(1, N + 1):
        log(f"Cycle {i}/{N}: toggle @({TOGGLE_X},{TOGGLE_Y})")
        adb(["shell", "input", "tap",
            str(TOGGLE_X), str(TOGGLE_Y)])
        time.sleep(TOGGLE_WAIT)

    log("Back")
    adb(["shell", "input", "keyevent", "KEYCODE_BACK"])
    time.sleep(1)

    log("Force-stop app")
    adb(["shell", "am", "force-stop", APP])

    log("Done.")


if __name__ == "__main__":
    main()