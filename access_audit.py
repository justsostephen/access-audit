#!/usr/bin/env python3

"""
# access_audit.py


## Notes

* Detail users that *could* access envs
* Detail users that *did* access envs
* Run locally or on MAAS nodes?
* Schedule run and report email w/ cron
* https://docs.python.org/3/tutorial/inputoutput.html
* Use keys from "/var/lib/misc/ssh-rsa-shadow"
* Clean up keys (bootstack and jujumanage users,
  "/etc/ssh/user-authorized-keys")
* Cross reference user account and real names using `getent passwd <user>`


## Dependencies

* utmp installed from PyPI
* launchpadlib dep lazr.restfulclient installed via
  `pip install bzr+lp:lazr.restfulclient`
* launchpadlib dep cryptography deps libssl-dev, libffi-dev, python3-dev
  installed via apt
* launchpadlib installed from PyPI
* "lib/python3.5/site-packages/oauth/oauth.py" modified to work with Python 3
* getent installed via `python setup.py install` after replacing `file()` with
  `open()` on line 9 of "resources/getent-0.2/setup.py"


## TODO

* Implement getent querying
* Utilise getent querying in `query_did_access()`
* Replace LP querying with getent querying in `log_could_access()`
* Implement `query_could_access()`
* README
"""

__version__ = "0.1.0"
__author__ = "Stephen Mather <stephen.mather@canonical.com>"

import argparse
import calendar # DEBUG
import csv
import datetime
import os
import platform
import time

from launchpadlib.launchpad import Launchpad
import utmp

# Set default query duration.
QUERY_DAYS = 30
# Set "wtmp" file path.
# WTMP = "/var/log/wtmp"
WTMP = "../resources/wtmp-zag"
# Set "user-authorized-keys" dir path.
# KEY_DIR = "/etc/ssh/user-authorized-keys"
KEY_DIR = "../resources/user-authorized-keys-zag"
# Set default "could access" log path.
# LOG_DEFAULT = "/var/log/could.log"
LOG_DEFAULT = "../resources/could.log"

def parse_arguments():
    """Parse command line arguments."""
    # Create parser object.
    parser = argparse.ArgumentParser(
        description="System access auditing and logging.")
    # Create mutually exclusive argument group.
    group = parser.add_mutually_exclusive_group()
    # Populate argument group.
    group.add_argument(
        "-c", "--could", type=number_of_days,
        nargs="?", const=QUERY_DAYS, metavar="days",
        help=("list users that *could* access system during specified number "
              "of days (default: %(const)s; use `--path` option to override "
              "default log file location)"))
    group.add_argument(
        "-d", "--did", type=number_of_days,
        nargs="?", const=QUERY_DAYS, metavar="days",
        help=("list users that *did* access system during specified number of "
              "days (default: %(const)s)"))
    # group.add_argument(
        # "-l", "--log", type=argparse.FileType("a"), nargs="?",
        # const=LOG_DEFAULT, metavar="path",
        # help=("create or append to specified log of users who could access "
              # "system (default: %(const)s)"))
    group.add_argument(
        "-l", "--log", action="store_true",
        help=("create or append to log of users who could access system (use "
              "`--path` option to override default log file location)"))
    parser.add_argument(
        "-p", "--path", default=LOG_DEFAULT, metavar="path",
        help=("specify alternative log path for `--could` or `--log` options, "
              "overriding the default (%(default)s)"))
    # Parse and return arguments, along with usage.
    args = parser.parse_args()
    return args, parser.format_usage()

def number_of_days(days):
    """Check validity of `days` command line arguments."""
    # Ensure `days` is a positive integer.
    days = int(days)
    if days < 1:
        message = (
            "invalid days value: {} (positive integer required)".format(days))
        raise argparse.ArgumentTypeError(message)
    return days

def query_could_access(days, path):
    """Query log for users that *could* access system during specified period.
    """
    print("Days: {}".format(days)) # DEBUG
    print("Path: {}".format(path)) # DEBUG

def query_did_access(days):
    """Query "wtmp" file for users that *did* access system during specified
    period.
    """
    # Define time variables.
    query_time = time.time() - days * 86400
    human_query_time = datetime.datetime.fromtimestamp(query_time)
    # Parse "wtmp" file and create list of users.
    users = []
    with open(WTMP, "rb") as access_log:
        log_buffer = access_log.read()
    for entry in utmp.read(log_buffer):
        # Add log entry second and microsecond fields, compare with query time.
        if entry.sec + entry.usec * .000001 > query_time:
            print(entry.time, entry.type, entry)
            user = entry.user
            if user and user not in users:
                users.append(user)
    # Output query results.
    if users:
        print("\n{0} {1} accessed {2} in the last {3} (since {4}):"
              .format(len(users),
                      pluralise("user", users),
                      platform.node(),
                      pluralise("day", days),
                      human_query_time))
        for user in users:
            print(user)
        print() # DEBUG: Is there a cleaner way to achieve this newline?
    else:
        print("{0} has not been accessed in the last {1} (since {2}).\n"
              .format(platform.node(),
                      pluralise("day", days),
                      human_query_time))
    # time_debug(days, log_buffer) # DEBUG

def pluralise(word, count):
    """Return singular or plural form of given word."""
    if word == "day":
        if count == 1:
            return "day"
        return "{} days".format(count)
    if word == "user":
        if count == 1:
            return "user has"
        return "users have"

def log_could_access(path):
    """Create or append to log of users who could access system."""
    # Log in to Launchpad anonymously.
    launchpad = Launchpad.login_anonymously(
        "access_audit", "production", version="devel")
    # Define timestamp variables.
    timestamp = time.time()
    human_timestamp = datetime.datetime.fromtimestamp(timestamp)
    # Initialise log entry list.
    users = [timestamp, human_timestamp]
    # Iterate through key files and extract usernames from entries.
    for key_file in os.listdir(KEY_DIR):
        with open(os.path.join(KEY_DIR, key_file)) as in_file:
            for key in in_file:
                parts = key.split()
                if parts:
                    print(parts[2:]) # DEBUG
                    # If key entry contains a Launchpad ID, query LP for
                    # username, otherwise use entry comment.
                    if len(parts[-1]) > 3 and parts[-1][:3] == "lp:":
                        lp_id = parts[-1][3:]
                        username = launchpad.people[lp_id].display_name
                    else:
                        username = parts[2]
                    print("Username: {}".format(username)) # DEBUG
                    # Compile log entry.
                    if username not in users:
                        users.append(username)
    # Write CSV log entry.
    with open(path, "a", newline="") as out_file:
        writer = csv.writer(out_file)
        writer.writerow(users)

def time_debug(days, log_buffer): # DEBUG
    """Test output of various time related methods."""
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
    """If an argument was passed, call related function, otherwise output usage.
    """
    args, usage = parse_arguments()
    print(args) # DEBUG
    if args.could:
        query_could_access(args.could, args.path)
    elif args.did:
        query_did_access(args.did)
    elif args.log:
        log_could_access(args.path)
    else:
        print(usage)

if __name__ == "__main__":
    main()
