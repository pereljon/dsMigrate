# dsMigrate
Migrates file system POSIX user and groups, and ACLs from one Mac OS X Directory Service provider to another. Used in OpenDirectory to Active Directory migrations (and vice versa).

## NOTES:
1. Requires that both the source (old) and target (new) Directory Services be connected on the computer where the file system is mounted.
2. The target Directory Service must be in the higher search order and the source in the lower search order.
3. Every file in the file system is scanned once, and has its user, group and ACLs migrated from the source to the target DS.

## CONSTANTS:
1. kTestingMode: run the script in testing mode. Commands are not actually run and are only logged. Debug level logging. (Enabled)
2. kForceDebug: force debug level logging, even if not running in testing mode. (Disabled)
3. kMultiprocess: enable or disable multiprocessing. (Enabled)
