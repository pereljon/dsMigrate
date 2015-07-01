# dsMigrate
Migrates file system POSIX user and groups, and ACLs from one Mac OS X Directory Service provider to another. Used in OpenDirectory to Active Directory migrations (and vice versa).

# NOTES:
1. Requires that both the source (old) and target (new) Directory Services be connected on the computer where the file system is mounted.
2. The target Directory Service must be in the higher search order and the source in the lower search order.
3. There is a constant (kTestingMode) which will run the script in testing mode, only outputting the commands it would otherwise run.
4. Every file in the file system is scanned once, and has its user, group and ACLs migrated from the source to the target DS.
