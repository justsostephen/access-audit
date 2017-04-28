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
* "wtmp" files are currently rotated monthly with 1 months backlog kept; is this
  appropriate?


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

* Implement `query_could_access()`
* README
* Clean up imports
* Clean up DEBUG and REMOVE
"""

__version__ = "0.1.0"
__author__ = "Stephen Mather <stephen.mather@canonical.com>"

import argparse
import calendar # DEBUG
import csv
from datetime import date, datetime, timedelta
import glob
import os
import platform
import time

import getent
import utmp

# Set default query duration.
QUERY_DAYS = 30
# Set system log path.
# LOG_PATH = "/var/log"
LOG_PATH = "../resources"
# Set "ssh-rsa-shadow" file path.
# KEYS_FILE = "/var/lib/misc/ssh-rsa-shadow"
KEYS_FILE = "../resources/ssh-rsa-shadow-zag"
# Set default "could access" log path.
LOG_DEFAULT = os.path.join(LOG_PATH, "could.log")
# Set `getent passwd` output file path: # REMOVE
GETENT_OUT = "../resources/getent-passwd-zag" # REMOVE

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
    """Query "wtmp" files for users that *did* access system during specified
    period.
    """
    # Define time variables.
    query_time = time.time() - days * 86400
    human_query_time = datetime.fromtimestamp(query_time)
    # Compile chronological list of relevant "wtmp" files and read into buffer.
    wtmp_files = []
    for wtmp_file in glob.glob(os.path.join(LOG_PATH, "wtmp*")):
        if os.path.getmtime(wtmp_file) > query_time:
            wtmp_files.append(wtmp_file)
    wtmp_files.sort(reverse=True)
    log_buffer = b""
    for wtmp_file in wtmp_files:
        with open(wtmp_file, "rb") as access_log:
            log_buffer += access_log.read()
    # Parse buffer, create list of users and dict of access records.
    users = []
    records = {}
    for entry in utmp.read(log_buffer):
        # Compute log entry time and date.
        entry_time = entry.sec + entry.usec * .000001
        entry_date = date.fromtimestamp(entry_time)
        if entry_time > query_time:
            user = entry.user
            if user:
                if user not in users:
                    users.append(user)
                if entry_date not in records:
                    records[entry_date] = {"start": entry_date,
                                           "end": entry_date,
                                           "users": [user]}
                elif user not in records[entry_date]["users"]:
                    records[entry_date]["users"].append(user)
    # Create list of sorted records.
    sorted_records = sorted(records.values(),
                            key=lambda record_value: record_value["start"])
    # Sort user lists for later comparison.
    for record in sorted_records:
        record["users"].sort()
    # Merge records for consecutive days with the same users.
    merged_records = []
    for record in sorted_records:
        if merged_records:
            last_record = merged_records[-1]
            if record["start"] == last_record["end"] + timedelta(1):
                if record["users"] == last_record["users"]:
                    last_record["end"] = record["start"]
                else:
                    merged_records.append(record)
            else:
                merged_records.append(record)
        else:
            merged_records.append(record)
    # Output query results.
    if users:
        print("\n{0} accessed {1} in the last {2} (since {3}):"
              .format(pluralise("user", len(users)),
                      platform.node(),
                      pluralise("day", days),
                      human_query_time))
        for record in merged_records:
            rec_start, rec_end, rec_users = record.values()
            if rec_start == rec_end:
                period = "on {}".format(rec_start)
            else:
                period = "between {} and {}".format(rec_start, rec_end)
            print("\n{} {}:".format(pluralise("user", len(rec_users)), period))
            for rec_user in rec_users:
                # DEBUG: `password_db_entry = getent.passwd(rec_user)`
                password_db_entry = getent_passwd(rec_user)
                name_not_found = "{} (real name not found)".format(rec_user)
                if password_db_entry:
                    real_name = password_db_entry.gecos.split(",")[0]
                    if real_name:
                        print(real_name)
                    else:
                        print(name_not_found)
                else:
                    print(name_not_found)
        print()
    else:
        print("\n{0} has not been accessed in the last {1} (since {2}).\n"
              .format(platform.node(),
                      pluralise("day", days),
                      human_query_time))
    # time_debug(days, log_buffer) # DEBUG

def pluralise(word, count):
    """Return singular or plural form of given word."""
    if count == 1:
        if word == "user":
            return "1 user"
        return word
    return "{} {}s".format(count, word)

def log_could_access(path):
    """Create or append to log of users who could access system."""
    # Define timestamp variables.
    timestamp = time.time()
    human_timestamp = datetime.fromtimestamp(timestamp)
    # Initialise log entry list.
    users = [timestamp, human_timestamp]
    # Compile list of users with SSH keys.
    users_with_keys = []
    with open(KEYS_FILE) as keys:
        for key in keys:
            parts = key.split(":")
            if parts:
                user = parts[0]
                if user not in users_with_keys:
                    users_with_keys.append(user)
    # Cross reference password database entries with list of users with SSH
    # keys and compile log entry.
    for entry in getent_passwd(): # DEBUG: `for entry in getent.passwd():`
        user = entry.name
        if user in users_with_keys and user not in users:
            users.append(user)
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
    print("Entry time: {}".format(list(utmp.read(log_buffer))[0].time))

class PasswordDbEntry:
    """Password database entry data structure for `getent.passwd()` emulation
    using output file.
    """
    def __init__(self, entry_parts):
        self.name = entry_parts[0]
        self.password = entry_parts[1]
        self.uid = entry_parts[2]
        self.gid = entry_parts[3]
        self.gecos = entry_parts[4]
        self.dir = entry_parts[5]
        self.shell = entry_parts[6]

def getent_passwd(user=None):
    """Emulate `getent.passwd()` functionality using output file."""
    with open(GETENT_OUT) as entries:
        if user:
            for entry in entries:
                parts = entry.split(":")
                if parts[0] == user:
                    user_entry = PasswordDbEntry(parts)
                    return user_entry
            user_entry = None
            return user_entry
        else:
            users = []
            for entry in entries:
                parts = entry.split(":")
                user_entry = PasswordDbEntry(parts)
                users.append(user_entry)
            return users

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
