"""
Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""

import json
from akamai.edgegrid import EdgeGridAuth
from cloudletApiWrapper import cloudlet
import argparse
import configparser
import requests
import os
import logging

#Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logFile = os.path.join('logs', 'VPConfigKit_log.log')

#Set the format of logging in console and file seperately
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
consoleFormatter = logging.Formatter("%(message)s")
rootLogger = logging.getLogger()


logfileHandler = logging.FileHandler(logFile, mode='w')
logfileHandler.setFormatter(logFormatter)
rootLogger.addHandler(logfileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(consoleFormatter)
rootLogger.addHandler(consoleHandler)
#Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
rootLogger.setLevel(logging.INFO)

try:
    config = configparser.ConfigParser()
    config.read(os.path.join('config','credentials.txt'))
    client_token = config['CREDENTIALS']['client_token']
    client_secret = config['CREDENTIALS']['client_secret']
    access_token = config['CREDENTIALS']['access_token']
    access_hostname = config['CREDENTIALS']['host']
    session = requests.Session()
    session.auth = EdgeGridAuth(
    			client_token = client_token,
    			client_secret = client_secret,
    			access_token = access_token
                )
except (NameError, AttributeError, KeyError):
    rootLogger.info("\nLooks like 'config/credentials.txt' are missing\n")
    exit(-1)

#Main arguments
parser = argparse.ArgumentParser(description='OpenAPI credentials are read from ./config/credentials.txt')
parser.add_argument("-help",help="Use -h for detailed help options",action="store_true")
parser.add_argument("-setup","-s",help="Initial setup to download all necessary policy information",action="store_true")
parser.add_argument("-getDetail",help="Display general policy details, active policy versions, or specific policy version details",action="store_true")
parser.add_argument("-generateRulesJson",help="Generate the policy version rules json and output to rules folder. (Optionally, use -outputfile to specify location of outputfile)",action="store_true")
parser.add_argument("-createVersion",help="Create a new policy version using a local file from the rules folder with name <policy>.json (or use -file <file path> as input)",action="store_true")
parser.add_argument("-activate",help="Activate a specific policy version (-version and -network are mandatory)",action="store_true")
parser.add_argument("-throttle",help="Throttle traffic by rule name (value should be from -1 to 100 or \"disabled\")")
parser.add_argument("-listPolicies",help="List all VP policy names", action="store_true")

#Additional arguments
parser.add_argument("-policy",help="Policy name")
parser.add_argument("-file",help="Filepath for input rules file used in -createVersion method (OPTIONAL)")
parser.add_argument("-network",help="Network to be activated on. Allowed values are staging, prod, production (case-sensitive)")
parser.add_argument("-version",help="Version number of the policy")
parser.add_argument("-rule",help="Rule name that needs to be updated for -throttle method (use 'single quotes' to honor spaces in rule name))")
parser.add_argument("-outputfile",help="Output filename to store the rules used in -generateRulesJson method (output file can then be used as input for -createVersion using -file)")
parser.add_argument("-verbose",help="Display detailed rule information for a specific version (only for -getDetail method with -version)", action="store_true")
parser.add_argument("-fromVersion",help="Display policy versions starting from the version number specified (only for -getDetail method w/o version)")

parser.add_argument("-debug",help="DEBUG mode to generate additional logs for troubleshooting",action="store_true")

args = parser.parse_args()


#Check for valid command line arguments
if not args.setup and not args.getDetail and not args.policy \
    and not args.version and not args.generateRulesJson and not args.createVersion and not args.activate \
    and not args.network and not args.debug and not args.outputfile and not args.file and not args.throttle \
    and not args.rule and not args.listPolicies and not args.verbose:
    rootLogger.info("Use -h for help options")
    exit(-1)

#Override log level if user wants to run in debug mode
#Set Log Level to DEBUG, INFO, WARNING, ERROR, CRITICAL
if args.debug:
    rootLogger.setLevel(logging.DEBUG)


if args.setup:
    rootLogger.info('Setting up required files.... please wait')
    #Create the wrapper object to make calls
    cloudletObject = cloudlet(access_hostname)
    groupResponse = cloudletObject.listCloudletGroups(session)
    rootLogger.info('Processing groups...')
    if groupResponse.status_code == 200:
        groupPath = 'groups'
        if not os.path.exists(groupPath):
            os.makedirs(groupPath)
        with open(os.path.join(groupPath,'groups.json'),'w') as groupFile:
            groupsResponseJson = groupResponse.json()
            #Find number of groups using len function
            totalGroups = len(groupsResponseJson)
            groupOutput = []
            for everyGroup in groupsResponseJson:
                groupInfo = {}
                groupInfo['groupName'] = everyGroup['groupName']
                groupInfo['groupId'] = everyGroup['groupId']
                groupOutput.append(groupInfo)
            groupFile.write(json.dumps(groupOutput,indent=4))

        policyPath = 'policies'
        policiesList = []
        if not os.path.exists(policyPath):
            os.makedirs(policyPath)
        rootLogger.info('Total groups found: ' + str(totalGroups))
        rootLogger.info('Fetching VP cloudlet policies under each group..')
        counter = 1
        for everyGroup in groupResponse.json():
            groupId = everyGroup['groupId']
            groupName = everyGroup['groupName']
            rootLogger.info('Processing ' + str(counter) + ' of ' + str(totalGroups) + ' groups, groupId and name is: ' + str(groupId) + ': ' + groupName)
            counter += 1
            cloudletPolicies = cloudletObject.listPolicies(session=session, groupId=groupId, cloudletCode='VP')
            if cloudletPolicies.status_code == 200:
                for everyPolicy in cloudletPolicies.json():
                    policyName = everyPolicy['name'] + '.json'
                    rootLogger.debug('Generating policy file: ' + policyName)
                    policyDetails = {}
                    policyDetails['name'] = everyPolicy['name']
                    policyDetails['description'] = everyPolicy['description']
                    policyDetails['policyId'] = everyPolicy['policyId']
                    policyDetails['groupId'] = everyPolicy['groupId']
                    if everyPolicy['name'] not in policiesList:
                        policiesList.append(everyPolicy['name'])
                        with open(os.path.join(policyPath, policyName),'w') as policyFileHandler:
                            policyFileHandler.write(json.dumps(policyDetails,indent=4))
                    else:
                        #This policy is already processed so move on
                        rootLogger.debug('Duplicate policy in another group again ' + everyPolicy['name'])
                        pass
            else:
                rootLogger.debug('groupId: ' + str(groupId) + ' has no policy details')
        rootLogger.info('\nFound these policies below and stored in ' + policyPath + " folder:")
        for everyPolicyName in policiesList:
            print(everyPolicyName)

if args.getDetail:
    if not args.policy:
        rootLogger.info('Please enter policy name using -policy option.')
        exit(-1)
    policy = args.policy
    cloudletObject = cloudlet(access_hostname)
    policiesFolder = 'policies'
    for root, dirs, files in os.walk(policiesFolder):
        localPolicyFile = policy + '.json'
        if localPolicyFile in files:
            #rootLogger.info(policy + ' Found')
            with open(os.path.join(policiesFolder,localPolicyFile), mode='r') as policyFileHandler:
                policyStringContent = policyFileHandler.read()
            #rootLogger.info(policyStringContent)
            policyJsonContent = json.loads(policyStringContent)
            policy_groupId = policyJsonContent['groupId']
            policy_policyId = policyJsonContent['policyId']
            rootLogger.info('Fetching policy details...')
            if args.version:
                version = args.version
                policyVersionsDetails = cloudletObject.listPolicyVersions(session, policy_policyId)
                versionFound = 0
                rootLogger.debug(json.dumps(policyVersionsDetails.json()))
                for everyVersionDetail in policyVersionsDetails.json():
                    if str(everyVersionDetail['version']) == str(version):
                        versionFound = 1
                        if not everyVersionDetail['deleted']:
                            rootLogger.info('\nDetails of version: ' + str(everyVersionDetail['version']))
                            rootLogger.info('Policy created by: ' + everyVersionDetail['createdBy'] + '\n')
                            #Need to check for match rules, sometimes we see null values
                            if everyVersionDetail['matchRules'] is not None:
                                if not args.verbose:
                                    for everyMatchRule in everyVersionDetail['matchRules']:
                                        multipleMatches = 0
                                        #Loop each match conditon within each rule
                                        #Check wthether rules is disabled, if yes display accordingly
                                        if 'disabled' in everyMatchRule and everyMatchRule['disabled'] is True:
                                            status='DISABLED'
                                        else:
                                            status='ACTIVE'
                                        print('   ' + everyMatchRule['name'] + ' -> ' + str(everyMatchRule['passThroughPercent']) + ' -> ' + status)
                                    print('\nNOTE: You can pass -verbose as an additional argument to get detailed rule information')
                                if args.verbose:
                                        rootLogger.info('     Match Criteria and Rule Details are: ')
                                        rootLogger.info('\n       ----------------------------------------------       \n')
                                        for everyMatchRule in everyVersionDetail['matchRules']:
                                            multipleMatches = 0
                                            rootLogger.info('       Rule Name: ' + everyMatchRule['name'])
                                            rootLogger.info('       Traffic Percentage: ' + str(everyMatchRule['passThroughPercent']))
                                            rootLogger.info('')
                                            # Loop each match conditon within each rule
                                            for everyMatchCondition in everyMatchRule['matches']:
                                                if multipleMatches == 1:
                                                    rootLogger.info('       AND')
                                                rootLogger.info('       Match Type: ' + everyMatchCondition['matchType'])
                                                rootLogger.info('       Match Value: ' + everyMatchCondition['matchValue'])
                                                multipleMatches = 1
                                            # Check wthether rules is disabled, if yes display accordingly
                                            if 'disabled' in everyMatchRule and everyMatchRule['disabled'] is True:
                                                rootLogger.info('\n       Rule is DISABLED')
                                            else:
                                                rootLogger.info('\n       Rule is ACTIVE')
                                            rootLogger.info('\n       ----------------------------------------------       \n')
                            else:
                                rootLogger.info('\nThere are no match criterias for this rule\n')
                if versionFound == 0:
                    rootLogger.info('Requested policy version does not exist - please check version number')
            else:
                policyDetails = cloudletObject.getCloudletPolicy(session, policy_policyId)
                #rootLogger.info(json.dumps(policyDetails.json()))
                rootLogger.info('\nPolicy Details:')
                rootLogger.info('-----------------')
                rootLogger.info('Policy Description: ' + policyDetails.json()['description'] + '\n')
                for everyactivationDetail in policyDetails.json()['activations']:
                    if everyactivationDetail['policyInfo']['status'] == 'active':
                        rootLogger.info('Version ' + str(everyactivationDetail['policyInfo']['version']) + ' is live in ' +  str(everyactivationDetail['network']) + ' for configuration: ' + str(everyactivationDetail['propertyInfo']['name']) + ' v' + str(everyactivationDetail['propertyInfo']['version']))
                        #rootLogger.info(everyactivationDetail['network'] + ' Version: ' + str(everyactivationDetail['policyInfo']['version']) + '\n')
                fromVersion = 1
                if not args.verbose:
                    policyVersions = cloudletObject.listPolicyVersions(session, policy_policyId, pageSize='10')
                    rootLogger.info('\nFetching last 10 policy version details... You can pass -verbose to get all the versions.')
                else:
                    policyVersions = cloudletObject.listPolicyVersions(session, policy_policyId)
                    if args.fromVersion:
                        fromVersion = args.fromVersion
                        rootLogger.info('\nShowing policy version details from version ' + args.fromVersion)
                rootLogger.info('\nVersion Details (Version : Description)')
                rootLogger.info('------------------------------------------')
                for everyVersion in policyVersions.json():
                    if int(everyVersion['version']) >= int(fromVersion):
                        rootLogger.info(str(everyVersion['version']) + ' : ' + str(everyVersion['description']))

                rootLogger.info('\nNOTE: You can pass -version <version_number> as an additional argument to get version specific details\n')

        else:
            rootLogger.info('\nLocal datastore does not have this policy. Please double check policy name or run -setup first')
            exit(-1)

if args.generateRulesJson:
    if not args.policy:
        rootLogger.info('Please enter policy name using -policy option.')
        exit(-1)
    policy = args.policy
    if not args.version:
        rootLogger.info('Please enter the version number using -version option\n')
        exit(-1)
    version = args.version
    cloudletObject = cloudlet(access_hostname)
    policiesFolder = 'policies'
    for root, dirs, files in os.walk(policiesFolder):
        localPolicyFile = policy + '.json'
        if localPolicyFile in files:
            #rootLogger.info(policy + ' Found')
            with open(os.path.join(policiesFolder,localPolicyFile), mode='r') as policyFileHandler:
                policyStringContent = policyFileHandler.read()
            #rootLogger.info(policyStringContent)
            policyJsonContent = json.loads(policyStringContent)
            policy_groupId = policyJsonContent['groupId']
            policy_policyId = policyJsonContent['policyId']
            rootLogger.info('\nFetching policy rule details...')
            policyVersions = cloudletObject.listPolicyVersions(session, policy_policyId)
            if policyVersions.status_code == 200:
                rootLogger.debug(json.dumps(policyVersions.json()))
                rootLogger.info('Fetching policy version...')
                #rootLogger.info(json.dumps(policyVersions.json()))
                versionFound = 0
                #rootLogger.info(json.dumps(policyVersions.json()))
                for everyVersion in policyVersions.json():
                    Responseversion = everyVersion['version']
                    if str(Responseversion) == str(version):
                        versionFound = 1
                        break

                if versionFound == 1:
                    policyDetails = cloudletObject.getCloudletPolicy(session, policy_policyId, version=version)
                    #rootLogger.info(json.dumps(policyDetails.json()))
                    #Update the local copy to latest details
                    if args.outputfile:
                        outputfilename = args.outputfile
                    else:
                        newPolicyFolder = 'rules'
                        if not os.path.exists(newPolicyFolder):
                            os.makedirs(newPolicyFolder)
                        newPolicyFile = args.policy + '_rules.json'
                        outputfilename = os.path.join(newPolicyFolder,newPolicyFile)
                    policyDetailsToFile = {}
                    everyDetailofPolicy = policyDetails.json()
                    if 'description' in everyDetailofPolicy:
                        policyDetailsToFile['description'] = everyDetailofPolicy['description']
                    if 'matchRules' in everyDetailofPolicy:
                        #Check whether it is null value
                        if everyDetailofPolicy['matchRules'] is not None:
                            matchRulesSection = everyDetailofPolicy['matchRules']
                            for everyMatchRule in matchRulesSection:
                                if 'location' in everyMatchRule:
                                    del everyMatchRule['location']
                            policyDetailsToFile['matchRules'] = everyDetailofPolicy['matchRules']
                    if 'description' in everyDetailofPolicy is None:
                        policyDetailsToFile['description'] = 'This is a version created using API'

                    with open(outputfilename, mode='w') as policyFileHandler:
                        policyFileHandler.write(json.dumps(policyDetailsToFile,indent=4))
                    rootLogger.info('\nGenerated policy rule details in json format. File output location is: ' + outputfilename)
                else:
                    rootLogger.info('Requested policy version does not exist - please check version number')
            else:
                rootLogger.info('Unable to fetch version details')
                exit(-1)
        else:
            rootLogger.info('\nLocal datastore does not have this policy. Please double check policy name or run -setup first')
            exit(-1)

if args.createVersion:
    if not args.policy:
        rootLogger.info('Please enter policy name using -policy option.')
        exit(-1)

    rootLogger.info('\nDoes your rules json file have the proper description field updated?  This will be used as comments for this version\n')
    rootLogger.info('\nPress Y to continue and N to exit.')
    option = input()
    if option == 'Y' or option == 'y':
        policy = args.policy
        cloudletObject = cloudlet(access_hostname)
        policiesFolder = 'policies'
        for root, dirs, files in os.walk(policiesFolder):
            localPolicyFile = policy + '.json'
            if localPolicyFile in files:
                rootLogger.info('Found policy: ' + policy + ' and using policyId from local store...')
                with open(os.path.join(policiesFolder,localPolicyFile), mode='r') as policyFileHandler:
                    policyStringContent = policyFileHandler.read()
                #rootLogger.info(policyStringContent)
                policyJsonContent = json.loads(policyStringContent)
                policy_groupId = policyJsonContent['groupId']
                policy_policyId = policyJsonContent['policyId']

                newPolicyFolder = 'rules'
                newPolicyFile = args.policy + '_rules.json'
                if args.file:
                    customFile = args.file
                    rulesFile = os.path.join(newPolicyFolder,customFile)
                else:
                    rootLogger.info('\n-file option was not specified. Picking rules file from: ' + os.path.join(newPolicyFolder,newPolicyFile))
                    rulesFile = os.path.join(newPolicyFolder,newPolicyFile)
                try:
                    with open(rulesFile, mode='r') as policyData:
                        policyDetails = json.load(policyData)
                        policyDetailsJson = json.dumps(policyDetails)
                    policyCreateResponse = cloudletObject.createPolicyVersion(session, policyId=policy_policyId)
                    rootLogger.info('Trying to create a new version of this policy...')
                    if policyCreateResponse.status_code == 200 or 201:
                        newVersion = policyCreateResponse.json()['version']
                        policyUpdateResponse = cloudletObject.updatePolicyVersion(session, policy_policyId, policyDetailsJson, newVersion)
                        if policyUpdateResponse.status_code == 200:
                            rootLogger.info('Success! Created policy version number ' + str(policyUpdateResponse.json()['version']))
                        else:
                            rootLogger.info('Cannot create new policy version, Reason: ' + policyUpdateResponse.json()['detail'])
                            rootLogger.debug('Detailed Json response is: ' + policyUpdateResponse.json())
                    else:
                        rootLogger.info('Unable to create the policy.')
                except FileNotFoundError:
                    rootLogger.info('\n' + os.path.join(newPolicyFolder,newPolicyFile) + ' is not found. This file is the default source for uploading rules.\n')
                    rootLogger.info('You may want to use -generateRulesJson <policyname> first\n')
            else:
                rootLogger.info('\nLocal datastore does not have this policy. Please double check policy name or run -setup first')
    else:
        rootLogger.info('\nExiting the program, you may run it again after updating description\n')
        exit(-1)

if args.activate:
    if not args.policy:
        rootLogger.info('Please enter policy name using -policy option.')
        exit(-1)
    policy = args.policy
    if not args.version:
        rootLogger.info('Please enter the version number using -version option\n')
        exit(-1)
    version = args.version
    if not args.network:
        rootLogger.info('Please enter the network to be activated on using -network option\n')
        exit(-1)
    network = args.network
    if network != 'staging' and network != 'prod' and network != 'production':
        rootLogger.info('Allowed values for network are staging and prod/production\n')
        exit(-1)
    #Over-rider production as prod
    if args.network == 'production':
        args.network = 'prod'
        network = 'prod'

    cloudletObject = cloudlet(access_hostname)
    policiesFolder = 'policies'
    for root, dirs, files in os.walk(policiesFolder):
        localPolicyFile = policy + '.json'
        if localPolicyFile in files:
            rootLogger.info(policy + ' file is Found... Using policyId from local store...')
            with open(os.path.join(policiesFolder,localPolicyFile), mode='r') as policyFileHandler:
                policyStringContent = policyFileHandler.read()
            #rootLogger.info(policyStringContent)
            policyJsonContent = json.loads(policyStringContent)
            policy_groupId = policyJsonContent['groupId']
            policy_policyId = policyJsonContent['policyId']
            #rootLogger.info(json.dumps(policyDetails.json()))
            #Update the local copy to latest details
            rootLogger.info('Trying to activate policy ' + policy + ' version ' + version + ' to ' + network + ' network')
            activationResponse = cloudletObject.activatePolicyVersion(session, policy_policyId, version, network)
            if activationResponse.status_code == 200:
                rootLogger.info('Success! Policy version is activated')
            else:
                rootLogger.info('Unable to activate, check for invalid version')
                policyVersions = cloudletObject.listPolicyVersions(session, policy_policyId)
                #rootLogger.info('\nAvailable versions are:')
                rootLogger.info('Version Details (Version : Description)' )
                rootLogger.info('----------------------' )
                for everyVersion in policyVersions.json():
                    rootLogger.info(str(everyVersion['version']) + ' : ' + str(everyVersion['description']))
                rootLogger.debug(json.dumps(activationResponse.json()))
        else:
            rootLogger.info('\nLocal datastore does not have this policy. Please double check policy name or run -setup first')
            exit(-1)

if args.throttle:
    #Validation steps begin
    try:
        if args.throttle.lower()=='disabled':
            pass
        elif -1 <= int(args.throttle) <= 100:
            pass
        else:
            rootLogger.info('throttle is not a valid number. Use -h to know more..')
            exit(-1)
    except ValueError:
        print("Invalid -throttle value, please specify either disabled or value between -1 and 100")
        exit(-1)
    if not args.policy:
        rootLogger.info('Please enter policy name using -policy option.')
        exit(-1)
    if not args.network:
        rootLogger.info('Please enter network type (staging or prod), to base the version on')
        exit(-1)
    if not args.rule:
        rootLogger.info("Please enter rule name using -rule option")
        exit(-1)

    if args.network == 'staging':
        if not args.throttle.lower()=='disabled':
            rootLogger.info('You are about to throttle ' + args.rule + ' at value = ' + str(args.throttle) + ' for ' + args.policy + ' on the Akamai ' + args.network + ' network. Do you wish to continue? (Press Y or N)')
        else:
            rootLogger.info('You are about to disable ' + args.rule + ' for ' + args.policy + ' on the Akamai ' + args.network + ' network. Do you wish to continue? (Press Y or N)')
        decision = input()
        if decision == 'N' or decision == 'n':
            rootLogger.info('Exiting...')
            exit(-1)
    elif args.network == 'prod':
        if not args.throttle.lower()=='disabled':
            rootLogger.info('You are about to throttle ' + args.rule + ' at value = ' + str(args.throttle) + ' for ' + args.policy + ' on the Akamai ' + args.network + ' network. Do you wish to continue? (Press Y or N)')
        else:
            rootLogger.info('You are about to disable ' + args.rule + ' for ' + args.policy + ' on the Akamai ' + args.network + ' network. Do you wish to continue? (Press Y or N)')
        decision = input()
        if decision == 'N' or decision == 'n':
            rootLogger.info('Exiting...')
            exit(-1)
        else:
            rootLogger.info('This is the Akamai Production Network. Are you absolutely sure? (Press Y or N)')
            decision = input()
            if decision == 'N' or decision == 'n':
                rootLogger.info('Exiting...')
                exit(-1)
    if args.network != 'staging' and args.network != 'prod' and args.network != 'production':
        rootLogger.info('Allowed values for network are staging and prod/production\n')
        exit(-1)
    #Over-rider production as prod
    if args.network == 'production':
        args.network = 'prod'
        network = 'prod'
    #Validation steps end
    #Proceed further only if user intends and has pressed Y or y
    if decision == 'y' or decision == 'Y':
        policy = args.policy
        cloudletObject = cloudlet(access_hostname)
        policiesFolder = 'policies'
        for root, dirs, files in os.walk(policiesFolder):
            localPolicyFile = policy + '.json'
            #Read the policy file to fetch policy ID
            if localPolicyFile in files:
                with open(os.path.join(policiesFolder,localPolicyFile), mode='r') as policyFileHandler:
                    policyStringContent = policyFileHandler.read()
                policyJsonContent = json.loads(policyStringContent)
                policy_groupId = policyJsonContent['groupId']
                policy_policyId = policyJsonContent['policyId']
                rootLogger.info('Fetching policy details...')

                #Fetch policy details to identify the version
                policyDetails = cloudletObject.getCloudletPolicy(session, policy_policyId)
                stagingVersion = str(-1)
                prodVersion = str(-1)
                for everyactivationDetail in policyDetails.json()['activations']:
                    if everyactivationDetail['policyInfo']['status'] == 'active':
                        if everyactivationDetail['network'] == 'staging':
                            stagingVersion = str(everyactivationDetail['policyInfo']['version'])
                        elif everyactivationDetail['network'] == 'prod':
                            prodVersion = str(everyactivationDetail['policyInfo']['version'])

                #Check which network is of interest, and base the version number
                if args.network == 'staging' and stagingVersion != '-1':
                    version = stagingVersion
                elif args.network == 'prod'and prodVersion != '-1':
                    version = prodVersion
                else:
                    rootLogger.info('No current version live in ' + args.network + ' network. Exiting...')
                    exit(-1)

                rootLogger.info('Found version ' + version + ' live in ' + args.network + ' network. Using this version...')
                policyDetails = cloudletObject.getCloudletPolicy(session, policy_policyId, version=version)
                #rootLogger.info(json.dumps(policyDetails.json(), indent = 4))

                #Filter the details of policy
                ruleFound = 0
                ruleCount = 0
                policyDetailsToModify = {}
                everyDetailofPolicy = policyDetails.json()
                rootLogger.info('\nSearching for Rule: ' + args.rule)
                if 'matchRules' in everyDetailofPolicy:
                    #Check whether it is null value
                    if everyDetailofPolicy['matchRules'] is None:
                        rootLogger.info('No rules exist in the policy. Exiting...')
                        exit(-1)
                    if everyDetailofPolicy['matchRules'] is not None:
                        matchRulesSection = everyDetailofPolicy['matchRules']
                        for everyMatchRule in matchRulesSection:
                            #Delete the location tag, as it causes error while uploading
                            if 'location' in everyMatchRule:
                                del everyMatchRule['location']
                            #Match the rule name (case insensitive)
                            if everyMatchRule['name'].lower() == args.rule.lower():
                                #Update the throttle value now
                                ruleFound = 1
                                ruleCount = ruleCount + 1
                                if not args.throttle.lower()=='disabled':
                                    everyMatchRule['passThroughPercent'] = int(args.throttle)
                                    # Check wthether rules is disabled, if yes enable it by deleting the disable entry
                                    if 'disabled' in everyMatchRule and everyMatchRule['disabled'] is True:
                                        del everyMatchRule['disabled']
                                if args.throttle.lower()=='disabled':
                                    everyMatchRule['disabled'] = True

                        policyDetailsToModify['matchRules'] = everyDetailofPolicy['matchRules']
                        policyDetailsToModify['description'] = 'Created from v' + str(version) + ': Throttle Rule = ' + args.rule + ' to value = ' + str(args.throttle) + ' (VPConfigKit)'
                        if ruleFound == 0:
                            rootLogger.info('Rule: ' + args.rule + ' is not found. Exiting...')
                            exit(-1)
                        if ruleCount == 1:
                            rootLogger.info('1 rule has been found...')
                        else:
                            rootLogger.info(str(ruleCount) + ' rules have been found...')
                else:
                    rootLogger.info('No rules exist in the policy. Exiting...')
                    exit(-1)

                #Let us now create a new version and update the rules
                policyCreateResponse = cloudletObject.createPolicyVersion(session, policyId=policy_policyId)
                rootLogger.info('\nTrying to create a new version of this policy with updated rule throttle.')
                if policyCreateResponse.status_code == 200 or 201:
                    newVersion = policyCreateResponse.json()['version']
                    #Let us now update the rules with new throttle values
                    policyUpdateResponse = cloudletObject.updatePolicyVersion(session, policy_policyId, json.dumps(policyDetailsToModify), newVersion)
                    if policyUpdateResponse.status_code == 200:
                        rootLogger.info('Successfully created new policy version : v' + str(policyUpdateResponse.json()['version']))
                        #Let us now activate the version
                        rootLogger.info('Now activating v' + str(policyUpdateResponse.json()['version']) + ' to Akamai ' + args.network + ' network ')
                        activationResponse = cloudletObject.activatePolicyVersion(session, policy_policyId, str(policyUpdateResponse.json()['version']), args.network)
                        if activationResponse.status_code == 200:
                            rootLogger.info('Success! Throttle change is live...')
                        else:
                            rootLogger.info('Unable to activate, check for invalid version')
                            policyVersions = cloudletObject.listPolicyVersions(session, policy_policyId)
                            #rootLogger.info('\nAvailable versions are:')
                            rootLogger.info('Version Details (Version : Description)' )
                            rootLogger.info('----------------------' )
                            for everyVersion in policyVersions.json():
                                rootLogger.info(str(everyVersion['version']) + ' : ' + str(everyVersion['description']))
                            rootLogger.debug(json.dumps(activationResponse.json()))
                    else:
                        rootLogger.info('Cannot create new policy version, Reason: ' + str(policyUpdateResponse.json()['detail']))
                        rootLogger.debug('Detailed Json response is: ' + str(policyUpdateResponse.json()))
                        exit(-1)
                else:
                    rootLogger.info('Unable to create the new version of policy.')
                    exit(-1)
            else:
                rootLogger.info('\nLocal datastore does not have this policy. Please double check policy name or run -setup first')
                exit(-1)
    else:
        rootLogger.info('You seem to have pressed some other key than Y or N. Exiting program.')
        exit(-1)

if args.listPolicies:
    counter = 1
    policiesFolder = 'policies'
    rootLogger.info('\n\nAvailable policies are: ')
    rootLogger.info('--------------------------\n')
    for root, dirs, files in os.walk(policiesFolder):
        for everyFile in files:
            if everyFile.endswith('json'):
                filenName = everyFile.split('.')
                rootLogger.info(str(counter) + '. ' + filenName[0])
                counter += 1
    rootLogger.info('\n--------------------------\n')

#Final or common Successful exit
exit(0)    
