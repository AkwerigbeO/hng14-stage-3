import subprocess


def _run_iptables(args, check=True):
    return subprocess.run(["iptables", *args], check=check, capture_output=True, text=True)


def ban_ip(ip, duration_min):
    """Insert a DOCKER-USER DROP rule unless it already exists."""
    try:
        exists = _run_iptables(["-C", "DOCKER-USER", "-s", ip, "-j", "DROP"], check=False)
        if exists.returncode == 0:
            print(f"{ip} is already present in DOCKER-USER; not inserting a duplicate rule.")
            return True

        _run_iptables(["-I", "DOCKER-USER", "-s", ip, "-j", "DROP"])
        print(f"Successfully banned {ip} for {duration_min} minutes in DOCKER-USER.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to ban {ip}: {e.stderr or e}")
        return False


def unban_ip(ip):
    """Remove all matching DOCKER-USER DROP rules for an IP."""
    removed = False
    while True:
        exists = _run_iptables(["-C", "DOCKER-USER", "-s", ip, "-j", "DROP"], check=False)
        if exists.returncode != 0:
            break
        try:
            _run_iptables(["-D", "DOCKER-USER", "-s", ip, "-j", "DROP"])
            removed = True
        except subprocess.CalledProcessError as e:
            print(f"Could not unban {ip}: {e.stderr or e}")
            return False

    if removed:
        print(f"Successfully unbanned {ip} from DOCKER-USER.")
    else:
        print(f"No DOCKER-USER rule existed for {ip}.")
    return True
