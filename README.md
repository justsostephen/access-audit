# access_audit.py

access_audit.py audits and logs system access.  It can detail the users that
*did* access a system by querying "wtmp" files.  It can detail the users that
*could* access a system by generating a log of users who have both password
database entries and SSH keys in "/var/lib/misc/ssh-rsa-shadow", then querying
that log.  Query duration is defined by passing the requisite number of days'
history to the relevant command line option.


## Dependencies

* utmp installed from PyPI with pip


## Example cron jobs

```
# Write *could* access log entry at midnight each day.
0 0 * * * root <path>/access_audit.py -l

# Run *could* access audit for the preceding month at midnight on the first day of each month.
0 0 1 * * <user> <path>/access_audit.py -c $(date -d 'yesterday' +\%d) -s > <path>/<env>-could-$(date -d 'yesterday' +\%Y\%m).csv

# Run *did* access audit for the preceding month at midnight on the first day of each month.
0 0 1 * * <user> <path>/access_audit.py -d $(date -d 'yesterday' +\%d) -s > <path>/<env>-did-$(date -d 'yesterday' +\%Y\%m).csv
```


## Version History


### 0.1.0

* Initial release


### 0.2.0

* Added CSV output option


### 0.2.1

* Added example cron jobs to documentation
