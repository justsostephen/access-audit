#!/usr/bin/env python3

"""
# access_audit.py


## Notes

* Detail users that *could* access envs
* Detail users that *did* access envs
* Run locally or on MAAS nodes?
* Schedule run and report email w/ cron
* utmp-0.4 installed from PyPI


## TODO

* Date logic
"""

__version__ = "0.1.0"
__author__ = "Stephen Mather <stephen.mather@canonical.com>"

import argparse
import calendar # DEBUG
import datetime
import time

import utmp

# Set path to `wtmp` file.
# WTMP = "/var/log/wtmp"
WTMP = "wtmp-ams"

def parse_arguments():
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
    # Parse and return arguments, along with usage.
    args = parser.parse_args()
    return args, parser.format_usage()

def days(days):
    """Check validity of `days` command line arguments."""
    # Ensure `days` is a positive integer.
    days = int(days)
    if days < 1:
        message = (
            "invalid days value: {} (positive integer required)".format(days))
        raise argparse.ArgumentTypeError(message)
    return days

def query_could_access(days):
    print("Days: {}".format(days)) # DEBUG

def query_did_access(days):
    """Query wtmp file for users that *did* access system during specified
    period.
    """
    QUERY_TIME = time.time() - days * 86400
    HUMAN_QUERY_TIME = datetime.datetime.fromtimestamp(QUERY_TIME)
    users = []
    with open(WTMP, "rb") as access_log:
        log_buffer = access_log.read()
    for entry in utmp.read(log_buffer):
        if entry.sec + entry.usec * .000001 > QUERY_TIME:
            print(entry.time, entry.type, entry)
            user = entry.user
            if user and user not in users:
                users.append(user)
    if users:
        print("\n{} users have accessed this system in the last {} days (since "
              "{}):".format(len(users), days, HUMAN_QUERY_TIME))
        for user in users:
            print(user)
        print() # Is there a cleaner way to achieve this newline?
    else:
        print("This system has not been accessed in the last {} days (since "
              "{}).\n".format(days, HUMAN_QUERY_TIME))
    # time_debug(days, log_buffer) # DEBUG

def time_debug(days, log_buffer): # DEBUG
    print("Days: {}".format(days))
    print("time.ctime(): {}".format(time.ctime()))
    print("time.gmtime(): {}".format(time.gmtime()))
    print("calendar.timegm(time.gmtime()): {}".format(calendar.timegm(time.gmtime())))
    print("time.localtime(): {}".format(time.localtime()))
    print("time.mktime(time.localtime()): {}".format(time.mktime(time.localtime())))
    print("time.time(): {}".format(time.time()))
    for entry in utmp.read(log_buffer):
        print("Entry time: {}".format(entry.time))
        break

def main():
    args, usage = parse_arguments()
    # print(args) # DEBUG
    # If an argument was passed, call related function, otherwise output usage.
    if args.could:
        query_could_access(args.could)
    elif args.did:
        query_did_access(args.did)
    else:
        print(usage)

if __name__ == "__main__":
    main()

