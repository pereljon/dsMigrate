# dsMigrate
Migrates filesystem POSIX user and groups, and ACLs from one Mac OS X Directory Service provider to another. Used in OpenDirectory to Active Directory migrations (and vice versa).

## NOTES:
1. Requires that both the source (old) and target (new) Directory Services be connected on the computer where the file system is mounted.
2. The target Directory Service must be in the higher search order and the source in the lower search order.
3. Every file in the file system is scanned once, and has its user, group and ACLs migrated from the source to the target DS.

## OPTIONS:
1. -testing : run the script in testing mode. Commands are not actually run and are only logged. Debug level logging.
2. -swap: run in swapped testing mode. Source and target Directory Services are swapped. Migration commands are logged to log file. (Useful for testing)
3. -debug: force debug level logging, even if not running in testing mode. 
4. -multiprocess: enable multiprocessing.
5. -cpu: number of CPUs to use in multiprocessing mode.
6. -yes: no prompts.
7. -verbose: verbose output.
