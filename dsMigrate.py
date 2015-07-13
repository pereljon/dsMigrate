#!/usr/bin/python
""" dsMigrate.py - Migrates POSIX user & groups and ACLs from one Mac OS X Directory Service provider to another.
    Used during OpenDirectory to Active Directory migrations(and vice versa)
    Author: Jonathan Perel
    Date: June 30, 2015"""

import sys
import os
import exceptions
import subprocess
import re
import logging
import datetime
import multiprocessing
import argparse


def dsGetDirectories():
    # Check Directory Services search order
    logging.info("Get source and target directories")
    try:
        dsSearch = subprocess.check_output(["dscl", "-plist", "/Search", "-read", "/"])
    except exceptions.OSError as theError:
        logging.critical("dscl: OS Error: %s", theError)
        sys.exit(1)
    except:
        logging.critical("dscl: Unexpected error: %s", sys.exc_info()[0])
        sys.exit(1)
    # Find CSPSearchPaths
    theSearchPath = re.search(
        r"\s*<key>dsAttrTypeStandard:CSPSearchPath</key>\n\s*<array>\n(?:\s*<string>.+</string>\n)+\s*</array>\n",
        dsSearch)
    if not theSearchPath:
        logging.error("Error: Couldn't find Search Path")
        sys.exit(1)
    # Find array of nodes
    theNodes = re.findall(r"\s*<string>(.+)</string>\n", theSearchPath.group(0))
    # Make sure appropriate search paths exist in correct order
    if len(theNodes) != 3:
        logging.error("Error: Unexpected length for Search Path: %s", theNodes)
        sys.exit(1)
    sourceNode = theNodes[2]
    if sourceNode.startswith("/LDAPv3/"):
        sourceType = "LDAP"
        sourceDomain = re.search("/LDAPv3/(.+)", sourceNode).group(1)
    elif sourceNode.startswith("/Active Directory/"):
        sourceType = "AD"
        sourceDomain = re.search("/Active Directory/(.+)/All Domains", sourceNode).group(1)
    else:
        logging.critical("Unknown source node type: %s", sourceNode)
        sys.exit(1)
    targetNode = theNodes[1]
    if targetNode.startswith("/LDAPv3/"):
        targetType = "LDAP"
        targetDomain = re.search("/LDAPv3/(.+)", targetNode).group(1)
    elif targetNode.startswith("/Active Directory/"):
        targetType = "AD"
        targetDomain = re.search("/Active Directory/(.+)/All Domains", targetNode).group(1)
    else:
        logging.critical("Unknown target node type: %s", targetNode)
        sys.exit(1)
    return (sourceType, sourceDomain, sourceNode), (targetType, targetDomain, targetNode)


def dsRead(theDirectory, thePath, theKey):
    # Get Directory Services users returning dictionary with username,theKey,and GeneratedUID
    # GeneratedUID isn't being used as ACLs can only be assigned by name
    logging.info("Reading directory %s at path %s for key %s", theDirectory, thePath, theKey)
    theNode = theDirectory[2]
    try:
        theRecords = subprocess.check_output(["dscl", "-plist", theNode, "-readall", thePath, theKey, "GeneratedUID"])
    except exceptions.OSError as theError:
        logging.critical("dscl: OS Error: %s", theError)
        sys.exit(1)
    except:
        logging.critical("dscl: Unexpected error: %s", sys.exc_info()[0])
        sys.exit(1)
    if theKey == "UniqueID":
        # Create dictionary of GeneratedUID and UniqueID by RecordName
        theFind = {}
        for nextFind in re.finditer(
                r"\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:UniqueID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n",
                theRecords):
            if nextFind.group(2)[0] == "_":
                logging.debug("Skipping: %s", nextFind.group(2))
            elif int(nextFind.group(3)) < 1000:
                logging.debug("Skipping: %s with id %s", nextFind.group(2), nextFind.group(3))
            else:
                theFind[nextFind.group(2)] = (nextFind.group(3), nextFind.group(1))
    elif theKey == "PrimaryGroupID":
        # Find RecordName and UniqueID
        theFind = {}
        for nextFind in re.finditer(
                r"\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:PrimaryGroupID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n",
                theRecords):
            if theDirectory[0] == "AD":
                theFind[nextFind.group(3).replace(theDirectory[1] + "\\", "")] = (nextFind.group(2), nextFind.group(1))
            else:
                theFind[nextFind.group(3)] = (nextFind.group(2), nextFind.group(1))
    else:
        logging.error("Unknown key: %s", theKey)
        sys.exit(1)
    if not theFind:
        logging.error("Couldn't find records")
        sys.exit(1)
    logging.debug("%d records in: %s", len(theFind), theDirectory)
    # Convert to a dictionary
    theDictionary = dict(theFind)
    return theDictionary


def dsMergeUniqueIDs(dsDictA, dsDictB):
    # Create merged dictionary of OD and AD uniqueIDs
    logging.info("Merging uniqueIDs")
    aDictionary = {}
    for nextKey in dsDictA.iterkeys():
        if nextKey in dsDictB:
            # Combine uniqueIDs as tuple in new dictionary
            aDictionary[nextKey] = (dsDictA[nextKey][0], dsDictB[nextKey][0])
        else:
            # Report on OpenDirectory users missing in Active Directory
            logging.debug("OpenDirectory record missing in Active Directory: %s", nextKey)
            if gVerbose:
                print "OpenDirectory record missing in Active Directory:", nextKey
    logging.debug("%d records combined", len(aDictionary))
    return aDictionary


def unlockFile(aPath):
    # Unlock file
    logging.warn("Unlocking file: %s", aPath)
    unlockCommand = "chflags", "nouchg", aPath
    returnCode = subprocess.call(unlockCommand)
    if returnCode:
        logging.error("Return code: %s for: %s", returnCode, " ".join(unlockCommand))
    return returnCode


def lockFile(aPath):
    # Lock file
    logging.warn("Locking file: %s", aPath)
    lockCommand = "chflags", "uchg", aPath
    returnCode = subprocess.call(lockCommand)
    if returnCode:
        logging.error("Return code: %s for: %s", returnCode, " ".join(lockCommand))
    return returnCode


def runCommand(aCommand):
    logging.debug("runCommand: %s", " ".join(aCommand))
    if gTestingMode:
        returnCode = 0
    else:
        returnCode = subprocess.call(aCommand)
        if returnCode:
            logging.warn("Return code: %s for: %s", returnCode, " ".join(aCommand))
            # Unlock the path (last item in command list)
            returnCode = unlockFile(aCommand[-1])
            if returnCode:
                # Error unlocking
                return returnCode
            else:
                # Set return code to "unlocked" so we lock file later
                returnCode = "unlocked"
                # Run command again
                retryCode = subprocess.call(aCommand)
                if retryCode:
                    # Failed to run the command the second time
                    logging.error("Return code: %s for: %s", retryCode, " ".join(aCommand))
    return returnCode


def migratePath(thePath):
    logging.debug("migratePath: %s", thePath)
    # Track if this path has been unlocked
    unlockedPath = False
    # List file at thePath
    pathRead = subprocess.check_output(["ls", "-aled", thePath]).splitlines()
    # Read POSIX owner/group
    thePOSIX = re.findall(r".+?\s+.+?\s+(.+?)\s+(.+?)\s+.+", pathRead[0])
    theUser = thePOSIX[0][0]
    theGroup = thePOSIX[0][1]
    # Change ownership and/or group
    if theUser in mergedUserIDs and theGroup in mergedGroupIDs:
        # Change owner and group
        logging.debug("Changing user & group: %s:%s for %s", mergedUserIDs[theUser][1], mergedGroupIDs[theGroup][1],
                      thePath)
        chownCommand = "chown", mergedUserIDs[theUser][1] + ":" + mergedGroupIDs[theGroup][1], thePath
        commandResult = runCommand(chownCommand)
    elif theUser in mergedUserIDs:
        # Change owner
        logging.debug("Changing user: %s for %s", mergedUserIDs[theUser][1], thePath)
        chownCommand = "chown", mergedUserIDs[theUser][1], thePath
        commandResult = runCommand(chownCommand)
    elif theGroup in mergedGroupIDs:
        # Change group
        logging.debug("Changing group: %s for %s", mergedGroupIDs[theGroup][1], thePath)
        chownCommand = "chown", ":" + mergedGroupIDs[theGroup][1], thePath
        commandResult = runCommand(chownCommand)
    else:
        logging.debug("No POSIX change for: %s", thePath)
        commandResult = 0
    # Track if we unlocked the file
    if commandResult == "unlocked":
        unlockedPath = True
    if len(pathRead) > 1:
        # ACL present
        # Find order,user/group,and permission on each ACE
        theACL = re.findall(
            r"\s(\d+):\s(?:((?:group|user):[\w|.]+)|([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}))(?:\s(inherited))?\s(.*)",
            "\n".join(pathRead[1:]))
        aceDeleteCount = 0
        for theACE in theACL:
            # Rewrite ACEs using target directory
            aceOrder = str(int(theACE[0]) - aceDeleteCount)  # Group 0: ACE order (minus number of ACEs removed)
            aceOwner = theACE[1]  # Group 1: ACE group/user if valid
            aceOrphan = theACE[2]  # Group 2: GUID if group/user not valid
            aceInherited = theACE[3]  # Group 3: "inherited" if inherited ACE
            acePermission = theACE[4]  # Group 4: ACL permission string
            if aceOrphan:
                # Orphan ACE. Will be deleted
                logging.warn("Removing orphan ACE: %s %s for %s", aceOrder, aceOrphan, thePath)
                chmodCommand = ("chmod", "-a#", aceOrder, thePath)
                # Keep track of how many ACEs we have deleted
                aceDeleteCount += 1
            elif aceInherited:
                # Inherited ACE
                logging.debug("Changing inherited ACE: %s %s %s for %s", aceOrder, aceOwner, acePermission, thePath)
                chmodCommand = "chmod", "=ai#", aceOrder, aceOwner + " " + acePermission, thePath
            else:
                # Non-inherited ACE
                logging.debug("Changing ACE: %s %s %s for %s", aceOrder, aceOwner, acePermission, thePath)
                chmodCommand = "chmod", "=a#", aceOrder, aceOwner + " " + acePermission, thePath
            commandResult = runCommand(chmodCommand)
            # Track if we unlocked the file
            if commandResult == "unlocked":
                unlockedPath = True
        if unlockedPath:
            # Lock the file if we unlocked the file
            lockFile(thePath)
    else:
        logging.debug("No ACLs to change for: %s", thePath)


def doMigration(directoryList, multiprocess, cpus):
    # Start the timer
    timeStart = datetime.datetime.now()
    logging.info("Starting migration at: %s", timeStart)
    if gVerbose:
        print "Starting migration at:", timeStart
    # Start file processed count
    fileCount = 0
    if multiprocess:
        # Initialize multiprocessing pool
        pool = multiprocessing.Pool(cpus)
    for nextDirectory in directoryList:
        if not os.path.exists(nextDirectory):
            # WARNING: Path not found
            logging.warn("doMigration: The following path does not exist: %s", nextDirectory)
            if gVerbose:
                print "The following path does not exist:", nextDirectory
        else:
            logging.info("Migrating: %s at: %s", nextDirectory, timeStart)
            if gVerbose:
                print "Migrating:", nextDirectory, "at:", timeStart
            # Migrate the root directory
            migratePath(nextDirectory)
            fileCount += 1
            # Migrate all files and subdirectories
            for dirName, subdirList, fileList in os.walk(nextDirectory):
                # Make path list of files and subdirectories
                filesAndSubdirs = [os.path.join(dirName, nextFile) for nextFile in fileList + subdirList]
                # Increment file count
                fileCount += len(filesAndSubdirs)
                logging.debug("Files: %s, Walking: %s", fileCount, dirName)
                if multiprocess:
                    # pool.apply(migratePath,filesAndSubdirs)
                    pool.map_async(migratePath, filesAndSubdirs)
                else:
                    for nextPath in filesAndSubdirs:
                        # For all files and subdirectories
                        migratePath(nextPath)
    if multiprocess:
        logging.info("End pool: %s", str(datetime.datetime.now()))
        # Close multiprocessing pool
        pool.close()
        # Wait until multiprocessing pool processes complete
        pool.join()
    # Stop the timer
    timeEnd = datetime.datetime.now()
    logging.info("Ending migration at: %s", timeEnd)
    if gVerbose:
        print "Ending migration at:", timeEnd
    timeTotal = timeEnd - timeStart
    logging.info("Total migration time: %s", timeTotal)
    logging.info("Total files: %s", fileCount)
    if timeTotal.seconds > 0:
        filesPerSec = fileCount / timeTotal.seconds
        logging.info("Files per second: %s", filesPerSec)


def parseArguments():
    # GLOBALS
    global gTestingMode
    global gForceDebug
    global gVerbose

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Migrate filesystem POSIX and ACL permissions from one Mac OS X Directory Services server to another, where user and group UniqueIDs and Generated UUIDs have changed.')
    parser.add_argument('directory', nargs='+', help='directory to migrate')
    parser.add_argument('-c', '--cpu', type=int, default=multiprocessing.cpu_count() - 2, metavar='CPUs',
                        help='number of CPUs to use. Only matters if running in multiprocessing mode. Defaults to number of CPUs minus 2.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='log all debugging info to log file. Not needed if running in testing mode.')
    parser.add_argument('-m', '--multiprocess', action='store_true',
                        help='run in multiprocessing mode. Use -c/--cpu to specify the number of CPUs to use.')
    parser.add_argument('-s', '--swap', action='store_true',
                        help='run in swapped testing mode. Source and target Directory Services are swapped. Migration commands are logged to log file.')
    parser.add_argument('-t', '--testing', action='store_true',
                        help='run in testing mode. Migration commands are logged to log file.')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='continue without prompting. Warning: do not use this unless you are 100%% sure of what you are doing.')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output.')
    args = parser.parse_args()

    # Set globals from arguments
    # Set testing mode if running in testing mode or swapped testing mode
    gTestingMode = args.testing or args.swap
    gForceDebug = args.debug
    # Set verbose output if requested or running in testing mode
    gVerbose = args.verbose or gTestingMode

    return args


def main():
    # GLOBALS
    global mergedUserIDs
    global mergedGroupIDs

    # Parse arguments
    args = parseArguments()

    # Check arguments
    if args.multiprocess:
        cpu_count = multiprocessing.cpu_count()
        if args.cpu == 0:
            print "ERROR: CPU value cannot be 0."
            sys.exit(1)
        elif args.cpu == 1:
            print "ERROR: Running in multiprocessing mode with 1 CPU. Will run in single processor mode instead."
            sys.exit(1)
        elif args.cpu > cpu_count:
            # Too many CPUs requested
            if gVerbose:
                print args.cpu, "CPUs requested but only", cpu_count, "available. Will run with", cpu_count, "CPUs."
            cpus = cpu_count
        elif args.cpu < 0 and abs(args.cpu) < cpu_count:
            # Negative CPUs request using less than maximum number of CPUs available
            cpus = cpu_count + args.cpu
        elif args.cpu < 0 and abs(args.cpu) >= cpu_count:
            # Negative CPUs request with value equal or greater than number of CPUs available
            print "ERROR: Maximum number of CPUs available are:", cpu_count
            sys.exit(1)
        else:
            cpus = cpu_count
        if gVerbose:
            print "Multiprocess Mode with", cpus, "CPUs."
    else:
        cpus = None

    # Check we are running with administrator privileges
    if not gTestingMode and os.getuid() != 0:
        print "You must run this script with administrator privileges."
        sys.exit(1)

    # Set the logging level
    if gTestingMode or gForceDebug:
        logging.basicConfig(filename='dsMigrate.log', level=logging.DEBUG)
    else:
        logging.basicConfig(filename='dsMigrate.log', level=logging.INFO)
    if gTestingMode:
        logging.info("### Running in Test Mode ###")
        print "### Running in Test Mode ###"
    else:
        logging.info("### Running in Production Mode###")
        if gVerbose:
            print "### Running in Production Mode ###"

    # Get source and target directories from Directory Services
    if args.swap:
        # Running in swapped Directory Services test mode
        (targetDirectory, sourceDirectory) = dsGetDirectories()
    else:
        (sourceDirectory, targetDirectory) = dsGetDirectories()
    print "Migrating from:", sourceDirectory[2], "to:", targetDirectory[2]
    if not gTestingMode and not args.autoYes:
        theInput = raw_input('Type "YES" if this is correct: ')
        if theInput != "YES":
            sys.exit(1)

    # Read source and target users and merge into a single table
    sourceUsers = dsRead(sourceDirectory, "/Users", "UniqueID")
    targetUsers = dsRead(targetDirectory, "/Users", "UniqueID")
    mergedUserIDs = dsMergeUniqueIDs(sourceUsers, targetUsers)

    # Read source and target groups and merge into a single table
    sourceGroups = dsRead(sourceDirectory, "/Groups", "PrimaryGroupID")
    targetGroups = dsRead(targetDirectory, "/Groups", "PrimaryGroupID")
    mergedGroupIDs = dsMergeUniqueIDs(sourceGroups, targetGroups)

    if not gTestingMode and not args.autoYes:
        theInput = raw_input('Type "START" to start the migration: ')
        if theInput != "START":
            sys.exit(1)

    # Do the migration
    doMigration(args.directory, args.multiprocess, cpus)

    logging.info("### Ending ###")

# MAIN
if __name__ == "__main__":
    main()
    sys.exit(0)
