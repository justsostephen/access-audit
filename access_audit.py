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
from datetime import (
    date,
    datetime,
    timedelta,
)
import glob
from os import path
from platform import node
import pwd
from time import (
    mktime,
    time,
)

import utmp

# Set default query duration.
QUERY_DAYS = 31
# Set system log path.
LOG_PATH = "/var/log"
# Set "ssh-rsa-shadow" file path.
KEYS_FILE = "/var/lib/misc/ssh-rsa-shadow"
# Set default "could access" log path.
LOG_DEFAULT = path.join(LOG_PATH, "could.log")


def parse_arguments():
    """Parse command line arguments."""
    # Create parser object.
    parser = argparse.ArgumentParser(
        description="System access auditing and logging."
    )
    # Create mutually exclusive argument group.
    group = parser.add_mutually_exclusive_group()
    # Populate argument group.
    group.add_argument(
        "-c", "--could", type=number_of_days,
        nargs="?", const=QUERY_DAYS, metavar="DAYS",
        help=("list users that *could* access system during specified number "
              "of days (default: %(const)s; use `--path` option to override "
              "default log file location)")
    )
    group.add_argument(
        "-d", "--did", type=number_of_days,
        nargs="?", const=QUERY_DAYS, metavar="DAYS",
        help=("list users that *did* access system during specified number of "
              "days (default: %(const)s)")
    )
    group.add_argument(
        "-l", "--log", action="store_true",
        help=("create or append to log of users who could access system (use "
              "`--path` option to override default log file location)")
    )
    parser.add_argument(
        "-p", "--path", default=LOG_DEFAULT,
        help=("specify alternative log path for `--could` or `--log` options, "
              "overriding the default (%(default)s)")
    )
    parser.add_argument(
        "-s", "--csv", action="store_true",
        help="output results as CSV, suitable for importing into a spreadsheet"
    )
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


def query_could_access(days, file_path, output_csv):
    """Query log for users that *could* access system during specified period.
    """
    # Calculate query time (rounded to beginning of day) and obtain list of log
    # files.
    query_time = mktime((date.today() - timedelta(days)).timetuple())
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
    # Output results.
    if output_csv:
        output_csv_results("could", users, records, days, query_time)
    else:
        output_text_results("could", len(users), records, days, query_time)


def query_did_access(days, file_path, output_csv):
    """Query "wtmp" files for users that *did* access system during specified
    period.
    """
    # Calculate query time (rounded to beginning of day) and obtain list of log
    # files.
    query_time = mktime((date.today() - timedelta(days)).timetuple())
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
    # Output results.
    if output_csv:
        output_csv_results("did", users, records, days, query_time)
    else:
        output_text_results("did", len(users), records, days, query_time)


def compile_logs(file_path, query_time):
    """Compile chronological list of relevant log files."""
    log_files = [log_file for log_file in glob.glob("{}*".format(file_path))
                 if path.getmtime(log_file) > query_time]
    log_files.sort(reverse=True)
    return log_files


def output_text_results(query_type, no_of_users, records, days, query_time):
    """Output text query results."""
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
        # Sort and merge records.
        merged_records = sort_and_merge(records)
        for record in merged_records:
            rec_start, rec_end, rec_users = (record["start"],
                                             record["end"],
                                             record["users"])
            if rec_start == rec_end:
                period = "on {}".format(rec_start)
            else:
                period = "between {} and {}".format(rec_start, rec_end)
            print("\n{} {}:".format(pluralise("user", len(rec_users)), period))
            # Compile, sort and output list of real names.
            sorted_names = [
                resolve_real_name(rec_user) for rec_user in rec_users
            ]
            sorted_names.sort()
            for name in sorted_names:
                print(name)
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


def output_csv_results(query_type, users, records, days, query_time):
    """Output CSV query results."""
    # print("* query_type: {}".format(query_type))  # DEBUG
    # print("* users: {}".format(users))  # DEBUG
    # print("* records: {}".format(records))  # DEBUG
    # print("* days: {}".format(days))  # DEBUG
    # print("* query_time: {}".format(query_time))  # DEBUG
    dates = [
        date.fromtimestamp(query_time) + timedelta(day + 1)
        for day in range(days)
    ]
    # print("* dates: {}".format(dates))  # DEBUG
    iso_dates = [date_object.isoformat() for date_object in dates]
    print(",", ",".join(iso_dates), sep="")
    user_records = []
    for user in users:
        user_record = [user]
        for day in dates:
            if day in records and user in records[day]["users"]:
                user_record.append("*")
            else:
                user_record.append("")
        user_records.append(user_record)
    for user_record in user_records:
        user_record[0] = resolve_real_name(user_record[0])
    user_records.sort()
    for user_record in user_records:
        print(",".join(user_record))


def pluralise(word, count):
    """Return singular or plural form of given word."""
    if count == 1:
        if word == "user":
            return "1 user"
        return word
    return "{} {}s".format(count, word)


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


def resolve_real_name(user):
    try:
        password_db_entry = pwd.getpwnam(user)
    except KeyError:
        password_db_entry = None
    name_not_found = "{} (real name not found)".format(user)
    if password_db_entry:
        real_name = password_db_entry.pw_gecos.split(",")[0]
        if real_name:
            return real_name
        else:
            return name_not_found
    else:
        return name_not_found


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
    for entry in pwd.getpwall():
        user = entry.pw_name
        if user in users_with_keys and user not in users:
            users.append(user)
    # Write CSV log entry.
    with open(file_path, "a", newline="") as out_file:
        writer = csv.writer(out_file)
        writer.writerow(users)


def main():
    """If an argument was passed, call related function, otherwise output usage.
    """
    args, usage = parse_arguments()
    if args.could:
        query_could_access(args.could, args.path, args.csv)
    elif args.did:
        query_did_access(args.did, path.join(LOG_PATH, "wtmp"), args.csv)
    elif args.log:
        log_could_access(args.path)
    else:
        print(usage)


if __name__ == "__main__":
    main()
