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

# CONSTANTS
kTestingMode=True

def dsGetDirectories():
    # Check Directory Services search order
    logging.info("Get source and target directories")
    try:
        dsSearch=subprocess.check_output(["dscl","/Search","-read","/"])
    except exceptions.OSError as theError:
        logging.critical("OS Error: %s",theError)
        sys.exit(1)
    except:
        logging.critical("Unexpected error: %s",sys.exc_info()[0])
        sys.exit(1)
    # Find CSPSearchPaths
    theFind=re.search("CSPSearchPath:(\n( .*))*",dsSearch)
    if not theFind:
        logging.error("Error: Couldn't find Search Path")
        sys.exit(1)
    # Make sure appropriate search paths exist in correct order
    theList=theFind.group(0).split("\n")
    if len(theList)!=4:
        logging.error("Error: Unexpected length for Search Path: %s",theList)
        sys.exit(1)
    sourceNode=theList[3][1:]
    if sourceNode.startswith("/LDAPv3/"):
        sourceType="LDAP"
        sourceDomain=re.search("/LDAPv3/(.+)",sourceNode).group(1)
    elif sourceNode.startswith("/Active Directory/"):
        sourceType="AD"
        sourceDomain=re.search("/Active Directory/(.+)/All Domains",sourceNode).group(1)
    targetNode=theList[2][1:]
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
        theRecords=subprocess.check_output(["dscl",theNode,"-readall",thePath,"RecordName",theKey,"GeneratedUID"])
    except exceptions.OSError as theError:
        logging.critical("OS Error: %s",theError)
        sys.exit(1)
    except:
        logging.critical("Unexpected error: %s",sys.exc_info()[0])
        sys.exit(1)
    if theKey=="UniqueID":
        # Find RecordName and UniqueID
        theFind={}
        for nextFind in re.finditer(r"GeneratedUID: (.+)\nRecordName: ([\w|.]+).*\nUniqueID: (.+)\n",theRecords):
            if nextFind.group(2)[0]=="_":
                logging.debug("Skipping: %s",nextFind.group(2))
            elif int(nextFind.group(3)) < 1000:
                logging.debug("Skipping: %s with id %s",nextFind.group(2),nextFind.group(3))
            else:
                theFind[nextFind.group(2)]=(nextFind.group(3),nextFind.group(1))
    elif theKey=="PrimaryGroupID":
        # Find RecordName and UniqueID
        theFind={}
        for nextFind in re.finditer(r"GeneratedUID: (.+)\nPrimaryGroupID: (.+)\nRecordName: (.+)\n",theRecords):
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

def doMigration(aDirectory,userIDs,groupIDs):
    timeStart=datetime.datetime.now()
    logging.info("Starting migration on: %s at: %s",aDirectory,str(timeStart))
    fileCount=0
    for dirName,subdirList,fileList in os.walk(aDirectory):
        logging.info("Files: %s, Walking: %s",fileCount,dirName)
        # Directory walk
        for theName in fileList+subdirList:
            # For all files and subdirectories
            fileCount=fileCount+1
            thePath=os.path.join(dirName,theName)
            # List file at thePath
            pathRead=subprocess.check_output(["ls","-aled",thePath]).splitlines()
            # Read POSIX owner/group
            thePOSIX=re.findall(r".+?\s+.+?\s+(.+?)\s+(.+?)\s+.+",pathRead[0])
            theUser=thePOSIX[0][0]
            theGroup=thePOSIX[0][1]
            if theUser in userIDs and theGroup in groupIDs:
                # Change owner and group
                logging.debug ("Changing user & group: %s:%s for %s",userIDs[theUser][1],groupIDs[theGroup][1],thePath)
                theCommand="sudo","chown",userIDs[theUser][1]+":"+groupIDs[theGroup][1],thePath
                if kTestingMode:
                    print " ".join(theCommand)
                else:
                    p=subprocess.Popen(theCommand)
            elif theUser in userIDs:
                # Change owner
                logging.debug ("Changing user: %s for %s",userIDs[theUser][1],theName)
                theCommand="sudo","chown",userIDs[theUser][1],thePath
                if kTestingMode:
                    print " ".join(theCommand)
                else:
                    p=subprocess.Popen(theCommand)
            elif theGroup in groupIDs:
                # Change group
                logging.debug ("Changing group: %s for %s",groupIDs[theGroup][1],theName)
                theCommand="sudo","chown",":"+groupIDs[theGroup][1],thePath
                if kTestingMode:
                    print " ".join(theCommand)
                else:
                    p=subprocess.Popen(theCommand)
            else:
                logging.debug ("No POSIX change for: %s",theName)
            if len(pathRead) > 1:
                # ACL present
                # Find order,user/group,and permission on each ACE
                theACL=re.findall(r"\s(\d+):\s((?:group|user):[\w|.]+)(?:\s(inherited))?\s(.*)","\n".join(pathRead[1:]))
                for theACE in theACL:
                    # Rewrite ACEs using target directory
                    if theACE[2]=="inherited":
                        # Inherited ACL
                        logging.debug ("Changing inherited ACL: %s %s %s for %s",theACE[0],theACE[1],theACE[3],theName)
                        theCommand="sudo","chmod","=ai#",theACE[0],theACE[1]+" "+theACE[3],thePath
                    else:
                        # Non-inherited ACL
                        logging.debug ("Changing ACL: %s %s %s for %s",theACE[0],theACE[1],theACE[3],theName)
                        theCommand="sudo","chmod","=a#",theACE[0],theACE[1]+" "+theACE[3],thePath
                    if kTestingMode:
                        print " ".join(theCommand)
                    else:
                        p=subprocess.Popen(theCommand)
            else:
                logging.debug ("No ACL change for: %s",theName)
    timeEnd=datetime.datetime.now()
    logging.info("Ending migration at: %s",str(timeEnd))
    timeTotal=timeEnd-timeStart
    logging.info("Total migration time: %s",str(timeTotal))

# MAIN
# Set the logging level
if kTestingMode:
    logging.basicConfig(filename='dsMigrate.log',level=logging.DEBUG)
    logging.info("### Starting in Test Mode ###")
else:
    logging.basicConfig(filename='dsMigrate.log',level=logging.INFO)
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
doMigration(migrationPath,mergedUserIDs,mergedGroupIDs)

logging.info("### Ending ###")
sys.exit(0)