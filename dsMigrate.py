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

# CONSTANTS
kTestingMode=True
kForceDebug=False
kMultiprocess=True

def dsGetDirectories():
    # Check Directory Services search order
    logging.info("Get source and target directories")
    try:
        dsSearch=subprocess.check_output(["dscl","-plist","/Search","-read","/"])
    except exceptions.OSError as theError:
        logging.critical("dscl: OS Error: %s",theError)
        sys.exit(1)
    except:
        logging.critical("dscl: Unexpected error: %s",sys.exc_info()[0])
        sys.exit(1)
    # Find CSPSearchPaths
    theSearchPath=re.search(r"\s*<key>dsAttrTypeStandard:CSPSearchPath</key>\n\s*<array>\n(?:\s*<string>.+</string>\n)+\s*</array>\n",dsSearch)
    if not theSearchPath:
        logging.error("Error: Couldn't find Search Path")
        sys.exit(1)
    # Find array of nodes
    theNodes=re.findall(r"\s*<string>(.+)</string>\n",theSearchPath.group(0))
    # Make sure appropriate search paths exist in correct order
    if len(theNodes)!=3:
        logging.error("Error: Unexpected length for Search Path: %s",theNodes)
        sys.exit(1)
    sourceNode=theNodes[2]
    if sourceNode.startswith("/LDAPv3/"):
        sourceType="LDAP"
        sourceDomain=re.search("/LDAPv3/(.+)",sourceNode).group(1)
    elif sourceNode.startswith("/Active Directory/"):
        sourceType="AD"
        sourceDomain=re.search("/Active Directory/(.+)/All Domains",sourceNode).group(1)
    targetNode=theNodes[1]
    if targetNode.startswith("/LDAPv3/"):
        targetType="LDAP"
        targetDomain=re.search("/LDAPv3/(.+)",targetNode).group(1)
    elif targetNode.startswith("/Active Directory/"):
        targetType="AD"
        targetDomain=re.search("/Active Directory/(.+)/All Domains",targetNode).group(1)
    return((sourceType,sourceDomain,sourceNode),(targetType,targetDomain,targetNode))

def dsRead(theDirectory,thePath,theKey):
    # Get Directory Services users returning dictionary with username,theKey,and GeneratedUID
    # GeneratedUID isn't being used as ACLs can only be assigned by name
    logging.info("Reading directory %s at path %s for key %s",theDirectory,thePath,theKey)
    theNode=theDirectory[2]
    try:
        theRecords=subprocess.check_output(["dscl","-plist",theNode,"-readall",thePath,theKey,"GeneratedUID"])
    except exceptions.OSError as theError:
        logging.critical("dscl: OS Error: %s",theError)
        sys.exit(1)
    except:
        logging.critical("dscl: Unexpected error: %s",sys.exc_info()[0])
        sys.exit(1)
    if theKey=="UniqueID":
        # Create dictionary of GeneratedUID and UniqueID by RecordName
        theFind={}
        for nextFind in re.finditer(r"\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:UniqueID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n",theRecords):
            if nextFind.group(2)[0]=="_":
                logging.debug("Skipping: %s",nextFind.group(2))
            elif int(nextFind.group(3)) < 1000:
                logging.debug("Skipping: %s with id %s",nextFind.group(2),nextFind.group(3))
            else:
                theFind[nextFind.group(2)]=(nextFind.group(3),nextFind.group(1))
    elif theKey=="PrimaryGroupID":
        # Find RecordName and UniqueID
        theFind={}
        for nextFind in re.finditer(r"\s*<key>dsAttrTypeStandard:GeneratedUID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:PrimaryGroupID</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n\s*<key>dsAttrTypeStandard:RecordName</key>\n\s*<array>\n\s*<string>(.+)</string>\n\s*</array>\n",theRecords):
            if theDirectory[0]=="AD":
                theFind[nextFind.group(3).replace(theDirectory[1]+"\\","")]=(nextFind.group(2),nextFind.group(1))
            else:
                theFind[nextFind.group(3)]=(nextFind.group(2),nextFind.group(1))
    else:
        logging.error("Unknown key: %s",theKey)
        sys.exit(1)
    if not theFind:
        logging.error("Couldn't find records")
        sys.exit(1)
    logging.debug("%d records in: %s",len(theFind),theDirectory)
    # Convert to a dictionary
    theDictionary=dict(theFind)
    return theDictionary

def dsMergeUniqueIDs(dsDictA,dsDictB):
# Create merged dictionary of OD and AD uniqueIDs
    logging.info("Merging uniqueIDs")
    aDictionary={}
    for nextKey in dsDictA.iterkeys():
        if nextKey in dsDictB:
            # Combine uniqueIDs as tuple in new dictionary
            aDictionary[nextKey]=(dsDictA[nextKey][0],dsDictB[nextKey][0])
        else:
            # Report on OpenDirectory users missing in Active Directory
            logging.debug("OpenDirectory record missing in Active Directory: %s",nextKey)
            print "OpenDirectory record missing in Active Directory:",nextKey
    logging.debug("%d records combined",len(aDictionary))
    return aDictionary

def unlockFile(aPath):
    # Unlock file
    logging.warn ("Unlocking file: %s",aPath)
    unlockCommand="chflags","nouchg",aPath
    returnCode=subprocess.call(unlockCommand)
    if returnCode:
        logging.error("Return code: %s for: %s",returnCode," ".join(unlockCommand))
    return returnCode

def lockFile(aPath):
    # Lock file
    logging.warn ("Locking file: %s",aPath)
    lockCommand="chflags","uchg",aPath
    returnCode=subprocess.call(lockCommand)
    if returnCode:
        logging.error("Return code: %s for: %s",returnCode," ".join(lockCommand))
    return returnCode

def runCommand(aCommand):
    logging.debug("runCommand: %s"," ".join(aCommand))
    if kTestingMode:
        returnCode=0
    else:
        returnCode=subprocess.call(aCommand)
        if returnCode:
            logging.warn("Return code: %s for: %s",returnCode," ".join(aCommand))
            # Unlock the path (last item in command list)
            returnCode=unlockFile(aCommand[-1])
            if returnCode:
                # Error unlocking
                return returnCode
            else:
                # Set return code to "unlocked" so we lock file later
                returnCode="unlocked"
                # Run command again
                retryCode=subprocess.call(aCommand)
                if retryCode:
                    # Failed to run the command the second time
                    logging.error("Return code: %s for: %s",retryCode," ".join(aCommand))
    return returnCode

def migratePath(thePath):
    logging.debug("migratePath: %s",thePath)
    # Track if this path has been unlocked
    unlockedPath=False
    # List file at thePath
    pathRead=subprocess.check_output(["ls","-aled",thePath]).splitlines()
    # Read POSIX owner/group
    thePOSIX=re.findall(r".+?\s+.+?\s+(.+?)\s+(.+?)\s+.+",pathRead[0])
    theUser=thePOSIX[0][0]
    theGroup=thePOSIX[0][1]
    # Change ownership and/or group
    if theUser in mergedUserIDs and theGroup in mergedGroupIDs:
        # Change owner and group
        logging.debug ("Changing user & group: %s:%s for %s",mergedUserIDs[theUser][1],mergedGroupIDs[theGroup][1],thePath)
        chownCommand="chown",mergedUserIDs[theUser][1]+":"+mergedGroupIDs[theGroup][1],thePath
        commandResult=runCommand(chownCommand)
    elif theUser in mergedUserIDs:
        # Change owner
        logging.debug ("Changing user: %s for %s",mergedUserIDs[theUser][1],thePath)
        chownCommand="chown",mergedUserIDs[theUser][1],thePath
        commandResult=runCommand(chownCommand)
    elif theGroup in mergedGroupIDs:
        # Change group
        logging.debug ("Changing group: %s for %s",mergedGroupIDs[theGroup][1],thePath)
        chownCommand="chown",":"+mergedGroupIDs[theGroup][1],thePath
        commandResult=runCommand(chownCommand)
    else:
        logging.debug ("No POSIX change for: %s",thePath)
        commandResult=0
    # Track if we unlocked the file
    if commandResult=="unlocked":
        unlockedPath=True
    if len(pathRead) > 1:
        # ACL present
        # Find order,user/group,and permission on each ACE
        theACL=re.findall(r"\s(\d+):\s(?:((?:group|user):[\w|.]+)|([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}))(?:\s(inherited))?\s(.*)","\n".join(pathRead[1:]))
        aceDeleteCount=0
        for theACE in theACL:
            # Rewrite ACEs using target directory
            aceOrder=str(int(theACE[0])-aceDeleteCount)   # Group 0: ACE order (minus number of ACEs removed)
            aceOwner=theACE[1]                  # Group 1: ACE group/user if valid
            aceOrphan=theACE[2]                 # Group 2: GUID if group/user not valid
            aceInherited=theACE[3]              # Group 3: "inherited" if inherited ACE
            acePermission=theACE[4]             # Group 4: ACL permision string
            if aceOrphan:
                # Orphan ACE. Will be deleted
                logging.warn ("Removing orphan ACE: %s %s for %s",aceOrder,aceOrphan,thePath)
                chmodCommand=("chmod","-a#",aceOrder,thePath)
                # Keep track of how many ACEs we have deleted
                aceDeleteCount+=1
            elif aceInherited:
                # Inherited ACE
                logging.debug ("Changing inherited ACE: %s %s %s for %s",aceOrder,aceOwner,acePermission,thePath)
                chmodCommand="chmod","=ai#",aceOrder,aceOwner+" "+acePermission,thePath
            else:
                # Non-inherited ACE
                logging.debug ("Changing ACE: %s %s %s for %s",aceOrder,aceOwner,acePermission,thePath)
                chmodCommand="chmod","=a#",aceOrder,aceOwner+" "+acePermission,thePath
            commandResult=runCommand(chmodCommand)
            # Track if we unlocked the file
            if commandResult=="unlocked":
                unlockedPath=True
        if unlockedPath:
            # Lock the file if we unlocked the file
            lockFile(thePath)
    else:
        logging.debug ("No ACLs to change for: %s",thePath)

def doMigration(aDirectory):
    # Start the timer
    timeStart=datetime.datetime.now()
    logging.info("Starting migration on: %s at: %s",migrationPath,str(timeStart))
    print "Starting migration on:",migrationPath,"at:",timeStart
    fileCount=0
    cpus=multiprocessing.cpu_count()-1
    pool=multiprocessing.Pool(cpus)
    # Directory walk
    for dirName,subdirList,fileList in os.walk(aDirectory):
        # Make path list of files and subdirectories
        filesAndSubdirs=[os.path.join(dirName,nextFile) for nextFile in fileList+subdirList]
        fileCount+=len(filesAndSubdirs)
        logging.debug("Files: %s, Walking: %s",fileCount,dirName)
        # Increment file count
        if kMultiprocess:
            # pool.apply(migratePath,filesAndSubdirs)
            pool.map_async(migratePath,filesAndSubdirs)
        else:
            for nextPath in filesAndSubdirs:
                # For all files and subdirectories
                migratePath(nextPath)
    logging.info("End pool: %s", str(datetime.datetime.now()))
    # Close pool
    pool.close()
    # Wait until pool processes complete
    pool.join()
    # Stop the timer
    timeEnd=datetime.datetime.now()
    logging.info("Ending migration at: %s",str(timeEnd))
    timeTotal=timeEnd-timeStart
    logging.info("Total migration time: %s",str(timeTotal))
    logging.info("Total files: %s",fileCount)
    if timeTotal.seconds > 0:
        filesPerSec=fileCount/timeTotal.seconds
        logging.info("Files per second: %s",filesPerSec)

# MAIN
if __name__ == "__main__":
    # Set the logging level
    if kTestingMode or kForceDebug:
        logging.basicConfig(filename='dsMigrate.log',level=logging.DEBUG)
    else:
        logging.basicConfig(filename='dsMigrate.log',level=logging.INFO)
    if kTestingMode:
        logging.info("### Starting in Test Mode ###")
    else:
        logging.info("### Starting in Production Mode###")

    # Check we are running with administrator privileges
    if not kTestingMode and os.getuid()!=0:
        print("You must run this script with administrator privileges.")
        sys.exit(1)

    # Get source and target directories from Directory Services
    (sourceDirectory,targetDirectory)=dsGetDirectories()
    print "Migrating from:",sourceDirectory[2],"to:",targetDirectory[2]
    if not kTestingMode:
        theInput=raw_input('Type "CONTINUE" accept: ')
        if theInput!="CONTINUE":
            sys.exit(1)

    # Read source and target users and merge into a single table
    sourceUsers=dsRead(sourceDirectory,"/Users","UniqueID")
    targetUsers=dsRead(targetDirectory,"/Users","UniqueID")
    mergedUserIDs=dsMergeUniqueIDs(sourceUsers,targetUsers)

    # Read source and target groups and merge into a single table
    sourceGroups=dsRead(sourceDirectory,"/Groups","PrimaryGroupID")
    targetGroups=dsRead(targetDirectory,"/Groups","PrimaryGroupID")
    mergedGroupIDs=dsMergeUniqueIDs(sourceGroups,targetGroups)

    # Get migration path
    migrationPath=raw_input("Enter the path to migrate: ").strip()
    if not os.path.exists(migrationPath):
        print "Path not found. Bye."
        exit(0)

    if not kTestingMode:
        theInput=raw_input('Type "CONTINUE" to start the migration: ')
        if theInput!="CONTINUE":
            sys.exit(1)

    # Do the migration
    doMigration(migrationPath)

    logging.info("### Ending ###")
    sys.exit(0)