#!/usr/bin/env python3

"""
# access_audit.py

access_audit.py audits and logs system access.  It can detail the users that
*did* access a system by querying "wtmp" files.  It can detail the users that
*could* access a system by generating a log of users who have both password
database entries and SSH keys in "/var/lib/misc/ssh-rsa-shadow", then querying
that log.  Query duration is defined by passing the requisite number of days'
history to the relevant command line option.


## Dependencies

* getent installed by downloading "getent-0.2.tar.gz" from
  "https://pypi.python.org/pypi/getent/0.2", extracting archive contents,
  replacing `file()` with `open()` on line 9 of "getent-0.2/setup.py", and
  running `python setup.py install`
* utmp installed from PyPI with pip


## TODO

* Configure cron jobs to:
    + Generate *could* access log
    + Generate and email *could* access report
    + Generate and email *did* access report
* Add cron job details above
* Clean up SSH keys (bootstack and jujumanage users,
  "/etc/ssh/user-authorized-keys")
* "wtmp" files are currently rotated monthly with 1 month's backlog kept; is
  this appropriate?
"""

__version__ = "0.1.0"
__author__ = "Stephen Mather <stephen.mather@canonical.com>"

import argparse
import csv
from datetime import date, datetime, timedelta
import glob
from os import path
from platform import node
from time import time

from getent import passwd
import utmp

# Set default query duration.
QUERY_DAYS = 31
# Set system log path.
# LOG_PATH = "/var/log"
LOG_PATH = "../resources" # DEBUG
# Set "ssh-rsa-shadow" file path.
# KEYS_FILE = "/var/lib/misc/ssh-rsa-shadow"
KEYS_FILE = "../resources/ssh-rsa-shadow-zag" # DEBUG
# Set default "could access" log path.
LOG_DEFAULT = path.join(LOG_PATH, "could.log")
# Set `getent passwd` output file path: # DEBUG
GETENT_OUT = "../resources/getent-passwd-zag" # DEBUG

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
        nargs="?", const=QUERY_DAYS, metavar="DAYS",
        help=("list users that *could* access system during specified number "
              "of days (default: %(const)s; use `--path` option to override "
              "default log file location)"))
    group.add_argument(
        "-d", "--did", type=number_of_days,
        nargs="?", const=QUERY_DAYS, metavar="DAYS",
        help=("list users that *did* access system during specified number of "
              "days (default: %(const)s)"))
    group.add_argument(
        "-l", "--log", action="store_true",
        help=("create or append to log of users who could access system (use "
              "`--path` option to override default log file location)"))
    parser.add_argument(
        "-p", "--path", default=LOG_DEFAULT,
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

def query_could_access(days, file_path):
    """Query log for users that *could* access system during specified period.
    """
    # Calculate query time and obtain list of log files.
    query_time = time() - days * 86400
    log_files = compile_logs(file_path, query_time)
    # Read log files into buffer.
    log_buffer = []
    for log_file in log_files:
        with open(log_file) as access_log:
            for entry in access_log:
                log_buffer.append(entry)
    # Parse buffer, create list of users and dict of access records.
    users = []
    records = {}
    for entry in csv.reader(log_buffer):
        # Extract log entry time and date.
        entry_time = float(entry[0])
        entry_date = date.fromtimestamp(entry_time)
        if entry_time > query_time:
            entry_users = entry[2:]
            for user in entry_users:
                if user not in users:
                    users.append(user)
            if entry_date not in records:
                records[entry_date] = {"start": entry_date,
                                       "end": entry_date,
                                       "users": entry_users}
            else:
                for user in entry_users:
                    if user not in records[entry_date]["users"]:
                        records[entry_date]["users"].append(user)
    # Sort and merge records, output results.
    merged_records = sort_and_merge(records)
    output_results("could", len(users), merged_records, days, query_time)

def query_did_access(days, file_path):
    """Query "wtmp" files for users that *did* access system during specified
    period.
    """
    # Calculate query time and obtain list of log files.
    query_time = time() - days * 86400
    log_files = compile_logs(file_path, query_time)
    # Read log files into buffer.
    log_buffer = b""
    for log_file in log_files:
        with open(log_file, "rb") as access_log:
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
            # Check if entry "user" field is populated.
            if user:
                if user not in users:
                    users.append(user)
                if entry_date not in records:
                    records[entry_date] = {"start": entry_date,
                                           "end": entry_date,
                                           "users": [user]}
                elif user not in records[entry_date]["users"]:
                    records[entry_date]["users"].append(user)
    # Sort and merge records, output results.
    merged_records = sort_and_merge(records)
    output_results("did", len(users), merged_records, days, query_time)

def compile_logs(file_path, query_time):
    """Compile chronological list of relevant log files."""
    log_files = []
    for log_file in glob.glob("{}*".format(file_path)):
        if path.getmtime(log_file) > query_time:
            log_files.append(log_file)
    log_files.sort(reverse=True)
    return log_files

def sort_and_merge(records):
    """Sort and merge access records."""
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
    return merged_records

def output_results(query_type, no_of_users, merged_records, days, query_time):
    """Output query results."""
    human_query_time = datetime.fromtimestamp(query_time)
    if no_of_users:
        if query_type == "could":
            summary = "\n{0} had access to {1} in the last {2} (since {3}):"
        else:
            summary = "\n{0} accessed {1} in the last {2} (since {3}):"
        print(summary.format(pluralise("user", no_of_users),
                             node(),
                             pluralise("day", days),
                             human_query_time))
        for record in merged_records:
            rec_start, rec_end, rec_users = (record["start"],
                                             record["end"],
                                             record["users"])
            if rec_start == rec_end:
                period = "on {}".format(rec_start)
            else:
                period = "between {} and {}".format(rec_start, rec_end)
            print("\n{} {}:".format(pluralise("user", len(rec_users)), period))
            for rec_user in rec_users:
                # DEBUG: `password_db_entry = passwd(rec_user)`
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
        if query_type == "could":
            summary = ("\nNo users have had access to {0} in the last {1} "
                       "(since {2}).\n")
        else:
            summary = ("\n{0} has not been accessed in the last {1} (since "
                       "{2}).\n")
        print(summary.format(node(),
                             pluralise("day", days),
                             human_query_time))

def pluralise(word, count):
    """Return singular or plural form of given word."""
    if count == 1:
        if word == "user":
            return "1 user"
        return word
    return "{} {}s".format(count, word)

def log_could_access(file_path):
    """Create or append to log of users who could access system."""
    # Define timestamps.
    timestamp = time()
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
    for entry in getent_passwd(): # DEBUG: `for entry in passwd():`
        user = entry.name
        if user in users_with_keys and user not in users:
            users.append(user)
    # Write CSV log entry.
    with open(file_path, "a", newline="") as out_file:
        writer = csv.writer(out_file)
        writer.writerow(users)

class PasswordDbEntry: # DEBUG
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

def getent_passwd(user=None): # DEBUG
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
    if args.could:
        query_could_access(args.could, args.path)
    elif args.did:
        query_did_access(args.did, path.join(LOG_PATH, "wtmp"))
    elif args.log:
        log_could_access(args.path)
    else:
        print(usage)

if __name__ == "__main__":
    main()
