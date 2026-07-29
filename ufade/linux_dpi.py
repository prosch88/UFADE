import os
import configparser
import subprocess
from pathlib import Path

#Linux DPI awareness
def get_linux_scale_factor() -> float:

    if os.name != "posix":
        return 1.0

    desktop = (
        os.environ.get("XDG_CURRENT_DESKTOP", "") +
        ":" +
        os.environ.get("XDG_SESSION_DESKTOP", "")
    ).lower()

    session = os.environ.get("XDG_SESSION_TYPE", "").lower()

    try:
        result = subprocess.run(
            ["xrdb", "-query"],
            capture_output=True,
            text=True,
            timeout=1,
        )

        for line in result.stdout.splitlines():
            if line.startswith("Xft.dpi:"):
                dpi = float(line.split(":")[1].strip())
                return dpi / 96.0

    except Exception as e:
        print(e)
        pass

    if "kde" in desktop or "plasma" in desktop:
        kdeglobals = Path.home() / ".config" / "kdeglobals"

        if kdeglobals.exists():
            print("kdeglobals")
            try:
                cfg = configparser.ConfigParser()
                cfg.read(kdeglobals)

                return float(cfg["KScreen"]["ScaleFactor"])
            except Exception:
                pass

    if any(x in desktop for x in ("gnome", "cinnamon", "mate")):
        try:
            result = subprocess.run(
                [
                    "gsettings",
                    "get",
                    "org.gnome.desktop.interface",
                    "scaling-factor",
                ],
                capture_output=True,
                text=True,
                timeout=1,
            )

            scale = int(result.stdout.strip())

            if scale > 0:
                return float(scale)

        except Exception:
            pass

    if "xfce" in desktop:
        try:
            result = subprocess.run(
                [
                    "xfconf-query",
                    "-c",
                    "xsettings",
                    "-p",
                    "/Gdk/WindowScalingFactor",
                ],
                capture_output=True,
                text=True,
                timeout=1,
            )

            scale = int(result.stdout.strip())

            if scale > 0:
                return float(scale)

        except Exception:
            pass

    return 1.0