#!/usr/bin/python
""" dsMigrate.py - Migrates POSIX user & groups and ACLs from one Mac OS X Directory Service provider to another.
    Used during OpenDirectory to Active Directory migrations (and vice versa)
    Author: Jonathan Perel
    Date: June 30, 2015"""

import sys
import os
import exceptions
import subprocess
import re
import logging
import datetime

# CONSTANTS
kTestingMode = True

def dsGetDirectories():
    # Check Directory Services search order
    logging.info("Get source and target directories")
    try:
        dsSearch = subprocess.check_output(["dscl","/Search","-read","/"])
    except exceptions.OSError as theError:
        logging.critical("OS Error: %s", theError)
        sys.exit(1)
    except:
        logging.critical("Unexpected error: %s", sys.exc_info()[0])
        sys.exit(1)
    # Find CSPSearchPaths
    theFind= re.search("CSPSearchPath:(\n (.*))*",dsSearch)
    if not theFind:
        logging.error("Error: Couldn't find Search Path")
        sys.exit (1)
    # Make sure appropriate search paths exist in correct order
    theList = theFind.group(0).split("\n")
    if len(theList) != 4:
        logging.error("Error: Unexpected length for Search Path: %s",theList)
        sys.exit (1)
    sourceNode=theList[3][1:]
    if sourceNode.startswith("/LDAPv3/"):
        sourceType = "LDAP"
        sourceDomain=re.search("/LDAPv3/(.+)",sourceNode).group(1)
    elif sourceNode.startswith("/Active Directory/"):
        sourceType = "AD"
        sourceDomain=re.search("/Active Directory/(.+)/All Domains",sourceNode).group(1)
    targetNode=theList[2][1:]
    if targetNode.startswith("/LDAPv3/"):
        targetType = "LDAP"
        targetDomain=re.search("/LDAPv3/(.+)",targetNode).group(1)
    elif targetNode.startswith("/Active Directory/"):
        targetType = "AD"
        targetDomain=re.search("/Active Directory/(.+)/All Domains",targetNode).group(1)
    return ((sourceType,sourceDomain,sourceNode),(targetType,targetDomain,targetNode))

def dsRead (theDirectory,thePath,theKey):
    # Get Directory Services users returning dictionary with username, theKey, and GeneratedUID
    # GeneratedUID isn't being used as ACLs can only be assigned by name
    logging.info("Reading directory %s at path %s for key %s",theDirectory,thePath,theKey)
    theNode = theDirectory[2]
    try:
        theRecords = subprocess.check_output(["dscl",theNode,"-readall",thePath,"RecordName",theKey,"GeneratedUID"])
    except exceptions.OSError as theError:
        logging.critical("OS Error: %s", theError)
        sys.exit(1)
    except:
        logging.critical("Unexpected error: %s", sys.exc_info()[0])
        sys.exit(1)
    if theKey == "UniqueID":
        # Find RecordName and UniqueID
        theFind = {}
        for nextFind in re.finditer(r"GeneratedUID: (.+)\nRecordName: ([\w|.]+).*\nUniqueID: (.+)\n",theRecords):
            if nextFind.group(2)[0] == "_":
                logging.debug("Skipping: %s",nextFind.group(2))
            elif int(nextFind.group(3)) < 1000:
                logging.debug("Skipping: %s with id %s",nextFind.group(2),nextFind.group(3))
            else:
                theFind[nextFind.group(2)] = (nextFind.group(3), nextFind.group(1))
    elif theKey == "PrimaryGroupID":
        # Find RecordName and UniqueID
        theFind = {}
        for nextFind in re.finditer(r"GeneratedUID: (.+)\nPrimaryGroupID: (.+)\nRecordName: (.+)\n",theRecords):
            if theDirectory[0] == "AD":
                theFind[nextFind.group(3).replace(theDirectory[1]+"\\","")] = (nextFind.group(2), nextFind.group(1))
            else:
                theFind[nextFind.group(3)] = (nextFind.group(2), nextFind.group(1))
    else:
        logging.error("Unknown key: %s", theKey)
        sys.exit (1)
    if not theFind:
        logging.error("Couldn't find records")
        sys.exit (1)
    logging.debug("%d records in: %s",len(theFind), theDirectory)
    # Convert to a dictionary
    theDictionary = dict(theFind)
    return theDictionary

def dsMergeUniqueIDs (dsDictA, dsDictB):
# Create merged dictionary of OD and AD uniqueIDs
    logging.info("Merging uniqueIDs")
    aDictionary = {}
    for nextKey in dsDictA.iterkeys():
        if nextKey in dsDictB:
            # Combine uniqueIDs as tuple in new dictionary
            aDictionary[nextKey] = (dsDictA[nextKey][0],dsDictB[nextKey][0])
        else:
            # Report on OpenDirectory users missing in Active Directory
            logging.debug("OpenDirectory record missing in Active Directory: %s", nextKey)
            print "OpenDirectory record missing in Active Directory:", nextKey
    logging.debug("%d records combined",len(aDictionary))
    return aDictionary


# def dsMergeGUIDs (dsDictA, dsDictB):
# # Create merged dictionary of OD and AD GUIDs (NOT USED)
#     aDictionary = {}
#     for nextKey in dsDictA.iterkeys():
#         if nextKey in dsDictB:
#             # Combine uniqueIDs as tuple in new dictionary
#             aDictionary[dsDictA[nextKey][1]] = dsDictB[nextKey][1]
#         else:
#             # Report on OpenDirectory users missing in Active Directory
#             print "OpenDirectory record missing in Active Directory:", nextKey
#     print "# Users combined", len(aDictionary)
#     return (aDictionary)

# def findChownUID (uniqueID):
# # Not using this.
#     print "sudo find",kVolume, "-uid ", uniqueID[0], "-exec chown", uniqueID[1], "{} \;"
#     time.sleep (5)

def doMigration(aDirectory,userIDs,groupIDs):
    logging.info("Starting migration on: %s",aDirectory)
    logging.info( str(datetime.datetime.now()) )
    for dirName, subdirList, fileList in os.walk(aDirectory):
        logging.debug("Walking: %s",dirName)
        # Directory walk
        for theName in fileList+subdirList:
            # For all files and subdirectories
            thePath = os.path.join(dirName, theName)
            # List file at thePath
            pathRead = subprocess.check_output(["ls","-aled",thePath]).splitlines()
            # Read POSIX owner/group
            thePOSIX=re.findall(r".+?\s+.+?\s+(.+?)\s+(.+?)\s+.+",pathRead[0])
            theUser=thePOSIX[0][0]
            theGroup=thePOSIX[0][1]
            if theUser in userIDs and theGroup in groupIDs:
                # Change owner and group
                if kTestingMode:
                    print "sudo","chown",userIDs[theUser][1]+":"+groupIDs[theGroup][1],"\""+thePath+"\""
                else:
                    p = subprocess.Popen("sudo","chown",userIDs[theUser][1]+":"+groupIDs[theGroup][1],"\""+thePath+"\"")
            elif theUser in userIDs:
                # Change owner
                if kTestingMode:
                    print "sudo","chown",userIDs[theUser][1],"\""+thePath+"\""
                else:
                    p = subprocess.Popen("sudo","chown",userIDs[theUser][1],"\""+thePath+"\"")
            elif theGroup in groupIDs:
                # Change group
                if kTestingMode:
                    print "sudo","chown",":"+groupIDs[theGroup][1],"\""+thePath+"\""
                else:
                    p = subprocess.Popen("sudo","chown",":"+groupIDs[theGroup][1],"\""+thePath+"\"")
            if len(pathRead) > 1:
                # ACL present
                # Find order, user/group, and permission on each ACE
                theACL=re.findall(r"\s(\d+): ((?:group|user):[\w|.]+)\s(.*)","\n".join(pathRead[1:]))
                for theACE in theACL:
                    # Rewrite ACEs using target directory
                    if kTestingMode:
                        print "sudo","chmod","=a#",theACE[0],"\""+theACE[1],theACE[2]+"\"","\""+thePath+"\""
                    else:
                        p = subprocess.Popen("sudo","chmod","=a#",theACE[0],"\""+theACE[1],theACE[2]+"\"","\""+thePath+"\"")
    logging.info( str(datetime.datetime.now()) )

logging.basicConfig(filename='dsMigrate.log',level=logging.DEBUG)
logging.info("### Starting ###")
if not kTestingMode and os.getuid() != 0:
    print("You must run this script with administrator privileges.")
    sys.exit(1)

logging.debug("Getting directories")
(sourceDirectory, targetDirectory) = dsGetDirectories()
print "Migrating from:", sourceDirectory[2], "to:", targetDirectory[2]
theInput=raw_input('Type "CONTINUE" to start the migration: ')
if (theInput != "CONTINUE"):
    sys.exit(1)

logging.debug("Reading source users")
sourceUsers = dsRead(sourceDirectory,"/Users","UniqueID")
logging.debug("Reading target users")
targetUsers = dsRead(targetDirectory,"/Users","UniqueID")
print ("Merging users:")
mergedUserIDs = dsMergeUniqueIDs(sourceUsers, targetUsers)

logging.debug("Reading source groups")
sourceGroups = dsRead(sourceDirectory,"/Groups","PrimaryGroupID")
logging.debug("Reading target groups")
targetGroups = dsRead(targetDirectory,"/Groups","PrimaryGroupID")

print ("Merging groups:")
mergedGroupIDs = dsMergeUniqueIDs(sourceGroups, targetGroups)

migrationPath = raw_input("Enter the path to migrate: ")
if not os.path.exists(migrationPath):
    print "Path not found. Bye."
    exit(0)

theInput=raw_input('Type "CONTINUE" to start the migration: ')
if (theInput == "CONTINUE"):
    doMigration (migrationPath,mergedUserIDs,mergedGroupIDs)

logging.info("### Ending ###")
sys.exit(0)