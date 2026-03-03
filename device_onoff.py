#!/usr/bin/env python3
# device_onoff.py - ADB automation script to toggle smart devices on/off

import subprocess
import time
import sys
import argparse
import logging
from dataclasses import dataclass
from datetime import datetime


# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


# -----------------------------
# Custom Exception
# -----------------------------
class ADBError(Exception):
    pass


# -----------------------------
# Timings Config
# -----------------------------
@dataclass
class Timings:
    open_wait: float = 6.0
    device_wait: float = 3.0
    toggle_wait: float = 2.0
    wake_wait: float = 1.0
    unlock_wait: float = 1.0
    stop_wait: float = 1.0


# -----------------------------
# ADB Helpers
# -----------------------------
def run(cmd, silent=False, timeout=15):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        if not silent and result.returncode != 0:
            raise ADBError(f"Command failed: {' '.join(cmd)}\n{result.stderr.decode().strip()}")
        if silent and result.returncode != 0:
            logger.warning(f"Command failed silently (rc={result.returncode}): {' '.join(cmd)}")
        return result
    except subprocess.TimeoutExpired:
        raise ADBError(f"Command timed out after {timeout}s: {' '.join(cmd)}")


def adb(cmd, silent=False, timeout=15):
    return run(["adb"] + cmd, silent=silent, timeout=timeout)


# -----------------------------
# Screen Handling
# -----------------------------
def get_screen_state():
    result = run(["adb", "shell", "dumpsys", "power"], timeout=10)
    return result.stdout.decode()


def wait_for_screen_on(max_retries=10, interval=0.5):
    """Poll until screen is ON or give up."""
    for _ in range(max_retries):
        if "Display Power: state=ON" in get_screen_state():
            return True
        time.sleep(interval)
    return False


def wake_and_unlock(timings: Timings):
    logger.info("Checking screen state...")
    power_state = get_screen_state()

    if "Display Power: state=OFF" in power_state:
        logger.info("Screen OFF → Waking device")
        adb(["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
        if not wait_for_screen_on():
            raise ADBError("Screen did not turn ON after wakeup")
    else:
        logger.info("Screen already ON")

    logger.info("Unlocking screen")
    adb(["shell", "input", "swipe", "500", "1500", "500", "500", "300"])
    time.sleep(timings.unlock_wait)

    adb(["shell", "wm", "dismiss-keyguard"], silent=True)
    time.sleep(timings.unlock_wait)


# -----------------------------
# Argument Parsing
# -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Professional ADB automation script"
    )

    parser.add_argument(
        "--app",
        default="com.tplink.iot",
        help="Android package name (default: com.tplink.iot)"
    )

    parser.add_argument(
        "-n", "--cycles",
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
    timings = Timings()

    APP = args.app
    N = args.cycles
    DEVICE_X, DEVICE_Y = args.device
    TOGGLE_X, TOGGLE_Y = args.toggle

    try:
        logger.info("Waiting for device...")
        adb(["wait-for-device"], timeout=30)

        wake_and_unlock(timings)

        # Verify package
        logger.info("Checking package...")
        result = adb(["shell", "pm", "path", APP], silent=True)
        if not result.stdout.decode().strip().startswith("package:"):
            raise ADBError(f"Package '{APP}' not found on device")

        logger.info("Force-stopping app")
        adb(["shell", "am", "force-stop", APP], silent=True)
        time.sleep(timings.stop_wait)

        logger.info("Launching app")
        adb(["shell", "monkey", "-p", APP,
             "-c", "android.intent.category.LAUNCHER", "1"], silent=True)
        time.sleep(timings.open_wait)

        logger.info(f"Opening device @({DEVICE_X},{DEVICE_Y})")
        adb(["shell", "input", "tap", str(DEVICE_X), str(DEVICE_Y)])
        time.sleep(timings.device_wait)

        for i in range(1, N + 1):
            logger.info(f"Cycle {i}/{N}: toggle @({TOGGLE_X},{TOGGLE_Y})")
            adb(["shell", "input", "tap", str(TOGGLE_X), str(TOGGLE_Y)])
            time.sleep(timings.toggle_wait)

        logger.info("Navigating back")
        adb(["shell", "input", "keyevent", "KEYCODE_BACK"])
        time.sleep(1)

    except ADBError as e:
        logger.error(str(e))
        sys.exit(1)

    finally:
        logger.info("Force-stopping app (cleanup)")
        try:
            adb(["shell", "am", "force-stop", APP], silent=True)
        except Exception:
            pass

    logger.info("Done.")


if __name__ == "__main__":
    main()