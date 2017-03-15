#!/usr/bin/env python3

"""
# access_audit.py


## Notes

* Detail users that *could* access envs
* Detail users that *did* access envs
* Accept duration argument (days)
* Run locally or on MAAS nodes?
* Schedule run and report email w/ cron
* utmp-0.4 installed from PyPI


## TODO

* Date logic
"""

__version__ = "0.1.0"
__author__ = "Stephen Mather <stephen.mather@canonical.com>"

import argparse

import utmp

# Set path to `wtmp` file.
# WTMP = "/var/log/wtmp"
WTMP = "wtmp-ams"

def arg_parser():
    """Parse command line arguments."""
    # Create parser object.
    parser = argparse.ArgumentParser(
        description="Run system access audit.")
    # Create mutually exclusive argument group.
    group = parser.add_mutually_exclusive_group()
    # Populate argument group.
    group.add_argument(
        "-c", "--could", type=days, nargs="?", const=30, metavar="days",
        help=("list users that *could* access system during specified number "
              "of days (default: %(const)s)"))
    group.add_argument(
        "-d", "--did", type=days, nargs="?", const=30, metavar="days",
        help=("list users that *did* access system during specified number of "
              "days (default: %(const)s)"))
    # Parse arguments.
    args = parser.parse_args()
    print(args) # DEBUG
    # If an argument was passed, call related function, otherwise output usage.
    if args.could:
        could_access(args.could)
    elif args.did:
        did_access(args.did)
    else:
        parser.print_usage()

def days(days):
    """Check validity of `days` command line arguments."""
    # Ensure `days` is a positive integer.
    days = int(days)
    if days < 1:
        message = (
            "invalid days value: {} (positive integer required)".format(days))
        raise argparse.ArgumentTypeError(message)
    return days

def could_access(days):
    print("Days: {}".format(days)) # DEBUG

def did_access(days):
    """Query wtmp file for users that *did* access system during specified
    period.
    """
    print("Days: {}".format(days)) # DEBUG
    users = []
    with open(WTMP, "rb") as access_log:
        buffer = access_log.read()
        for entry in utmp.read(buffer):
            print(entry.time, entry.type, entry)
            user = entry.user
            if user and user not in users:
                users.append(user)
        print("\n", users)

def main():
    arg_parser()

if __name__ == "__main__":
    main()

