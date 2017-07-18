""" Copyright 2017 Akamai Technologies, Inc. All Rights Reserved.
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


class cloudlet(object):
    def __init__(self,access_hostname):
        self.access_hostname = access_hostname

    def listCloudletGroups(self,session):
        """
        Function to fetch all groups

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletGroupRespose : cloudletGroupRespose
            (cloudletGroupRespose) Object with all details
        """
        cloudletGroupUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/group-info'
        cloudletGroupRespose = session.get(cloudletGroupUrl)
        return cloudletGroupRespose

    def getAllGroupIds(self,session):
        """
        Function to fetch all groupIDs only

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        groupIdList : List
            groupIdList with list of all groupIds
        """
        cloudletGroupUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/group-info'
        cloudletGroupResponse = session.get(cloudletGroupUrl)
        groupIdList = []
        if cloudletGroupResponse.status_code == 200:
            for everyItem in cloudletGroupResponse.json():
                groupIdList.append(everyItem['groupId'])
        return groupIdList

    def listAllCloudlets(self,session):
        """
        Function to fetch all cloudlets

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletList : List
            cloudletList with list of all cloudlets
        """
        groupIdList = self.getAllGroupIds(session)
        cloudletList = []
        for everyGroupId in groupIdList:
            listAllCloudletsUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/cloudlet-info?gid=' + str(everyGroupId)
            print('Fetching cloudlet for Group: ' + str(everyGroupId))
            listAllCloudletsResponse = session.get(listAllCloudletsUrl)
            if listAllCloudletsResponse.status_code == 200:
                cloudletList.append(listAllCloudletsResponse.json())
                print(json.dumps(listAllCloudletsResponse.json()))
                print('Added cloudlet info for Group: ' + str(everyGroupId) + ' to a list\n')
            else:
                print('Group: ' + str(everyGroupId) + ' did not yield any cloudlets\n')
        return cloudletList

    def listPolicies(self,session,groupId,cloudletId='optional',cloudletCode='optional'):
        """
        Function to fetch Policies from cloudletId and GroupId

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        policiesResponse : policiesResponse
            Policies of cloudlet Id
        """
        if cloudletCode == 'optional':
            policiesUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies?gid=' + str(groupId) + '&cloudletId=' + str(cloudletId)
            policiesResponse = session.get(policiesUrl)
        elif cloudletCode == 'VP':
            policiesUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies?gid=' + str(groupId) + '&cloudletId=' + str(1)
            policiesResponse = session.get(policiesUrl)
        return policiesResponse

    def getCloudletPolicy(self,session,policyId,version='optional'):
        """
        Function to fetch a cloudelt policy detail

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyResponse : cloudletPolicyResponse
            Json object details of specific cloudlet policy
        """
        if version == 'optional':
            cloudletPolicyUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId)
        else:
            cloudletPolicyUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions/' + str(version) + '?omitRules=false'
        cloudletPolicyResponse = session.get(cloudletPolicyUrl)
        return cloudletPolicyResponse

    def listPolicyVersions(self,session,policyId,pageSize='optional'):
        """
        Function to fetch a cloudelt policy versions

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyResponse : cloudletPolicyResponse
            Json object details of specific cloudlet policy versions
        """
        if pageSize=='optional':
            cloudletPolicyVersionsUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions?includeRules=true'
        else:
            cloudletPolicyVersionsUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/' + str(policyId) + '/versions?includeRules=true&pageSize=' +pageSize
        cloudletPolicyVersionsResponse = session.get(cloudletPolicyVersionsUrl)
        return cloudletPolicyVersionsResponse

    def createPolicyVersion(self,session,policyId,cloneVersion='optional'):
        """
        Function to create a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyCreateResponse : cloudletPolicyCreateResponse
            Json object details of created cloudlet policy version
        """
        headers = {
            "Content-Type": "application/json"
        }
        if cloneVersion == 'optional':
            cloudletPolicyCreateUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions' +  '?includeRules=true'
        else:
            cloudletPolicyCreateUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions' +  '?includeRules=true&cloneVersion=' + cloneVersion
        cloudletPolicyCreateResponse = session.post(cloudletPolicyCreateUrl,headers=headers)
        return cloudletPolicyCreateResponse

    def updatePolicyVersion(self,session,policyId,policyDetails,version):
        """
        Function to update a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyUpdateResponse : cloudletPolicyUpdateResponse
            Json object details of updated cloudlet policy version
        """
        headers = {
            "Content-Type": "application/json"
        }
        cloudletPolicyUpdateUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions/' + str(version) + '?omitRules=false'
        cloudletPolicyUpdateResponse = session.put(cloudletPolicyUpdateUrl, data=policyDetails,headers=headers)
        return cloudletPolicyUpdateResponse


    def activatePolicyVersion(self,session,policyId,version,network='staging'):
        """
        Function to activate a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyActivateResponse : cloudletPolicyActivateResponse
            Json object details of activated cloudlet policy version
        """
        headers = {
            "Content-Type": "application/json"
        }
        networkData = """{
            "network" : "%s"
        }""" % (network)
        cloudletPolicyActivateUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions/' + str(version) + '/activations'
        cloudletPolicyActivateResponse = session.post(cloudletPolicyActivateUrl, data=networkData, headers=headers)
        return cloudletPolicyActivateResponse

    def deletePolicyVersion(self,session,policyId,version):
        """
        Function to delete a policy version

        Parameters
        -----------
        session : <string>
            An EdgeGrid Auth akamai session object

        Returns
        -------
        cloudletPolicyDeleteResponse : cloudletPolicyDeleteResponse
            Json object details of deleted cloudlet policy version
        """
        
        cloudletPolicyDeleteUrl = 'https://' + self.access_hostname + '/cloudlets/api/v2/policies/'+ str(policyId) + '/versions/' + str(version)
        cloudletPolicyDeleteResponse = session.delete(cloudletPolicyDeleteUrl)
        return cloudletPolicyDeleteResponse
