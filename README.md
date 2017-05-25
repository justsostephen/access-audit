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
