# cli-cloudlet-visitor-prioritization
Provides a way to interact real-time with your Visitor Prioritization Cloudlet via Open APIs and without manually having to go into the Luna Portal. Provides various functionality such as viewing current policies, current status, rule details, and the ability to invoke actual percentage changes.

## Local Install
* Python 3+
* pip install edgegrid-python

### Credentials
In order to use this module, you need to:
* Set up your credential files as described in the [authorization](https://developer.akamai.com/introduction/Prov_Creds.html) and [credentials](https://developer.akamai.com/introduction/Conf_Client.html) sections of the Get Started pagegetting started guide on developer.akamai.comthe developer portal.  
* When working through this process you need to give grants for the Cloudlets Policy Manager API.  The section in your configuration file should be called 'papi'.

## Functionality (version 1.0.0)
The initial version of the cloudlet-visitor-prioritization provides the following functionality:
* One-time setup/download of local policy ids necessary to invoke APIs quickly
* List current policy details, previous versions, and rules
* Throttle (make percentage updates) rule for the specified policy and invoke change immediately
* Download the specified policy rules file in .json format to edit if necessary
* Create a new policy version based on a raw json file
* Activate a specific policy version

## cli-cloudlet-visitor-prioritization
Main program that wraps this functionality in a command line utility:
* [Setup](#setup)
* [List Policies](#listPolicies)
* [Get Policy Detail](#getDetail)
* [Throttle](#throttle)
* [Activate](#activate)
* [Download Policy Rules Json](#generateRulesJson)
* [Create Version](#createVersion)

### Setup
Does a one time download of visitor prioritization cloudlet policyIds and groupIds and stores them in /setup folder for faster local retrieval. This command can be run anytime and will refresh the /setup folder based on the current list of policies. 

```bash
%  akamai-cloudlet-vp -setup
```

