import traceback
import copy

"""
Tang service xu ly logic ma co tuong tac voi nhieu table
"""
class ServiceViolation:

    def __init__(self, repo_context):
        self.repo_context = repo_context
        self.bls_evidences_repo = self.repo_context.bls_evidences_repo

    def get_all_group(self):
        print "ServiceViolation-get_all_group"
        try:
            data_result = self.bls_evidences_repo.get_all_group()

            list_data = []
            for hit in data_result['hits']['hits']:
                list_data.append(hit['_source'])

            return  list_data

        except Exception as e:
            print e, traceback.format_exc()
            return {}


    #API: /list_violation_computer
    def get_list_violation_computer(self, violation_id, group_id, current_page, item_per_page):
        print "ServiceViolation-get_list_violation_computer_detail"
        try:
            data_result = self.bls_evidences_repo.get_list_violation_computer( \
                violation_id, group_id, current_page, item_per_page)

            responseJson = [] #List of group_template
            group_template = {
                "groupId": "okv3",
                "groupName": "okv3",
                "clientList" : [] #List of client_template
            }
            client_template = {
                "clientId": "F31A583B2C8D1E10F4381710686061A446C8EF20",
                "clientName:": "VT_NTVAG_498311",
                "ruleList": [] #List of rule_template
            }
            rule_template = {
                "ruleId": "AVQESrZd0d47ZLKwg_Pf",
                "ruleDescription": "Quy che 385",
                "policyId": "AVXO6OcXKUVEy8KF_FNW", 
                "policyDescription": "Vi pham",
                "dateTime": ""
            }

            #Some fake data
            rule_template2 = copy.deepcopy(rule_template)
            rule_template3 = copy.deepcopy(rule_template)    
            rule_template2["ruleId"] =                       "ruleId2"
            rule_template2["ruleDescription"] =     "ruleDescription2"
            rule_template2["policyId"] =                   "policyId2"
            rule_template2["policyDescription"] = "policyDescription2"
            rule_template3["ruleId"] =                       "ruleId3"
            rule_template3["ruleDescription"] =     "ruleDescription3"
            rule_template3["policyId"] =                   "policyId3"
            rule_template3["policyDescription"] = "policyDescription3"            

            client_template2 = copy.deepcopy(client_template)
            client_template3 = copy.deepcopy(client_template)
            client_template2["clientId"] =     "clientId2"
            client_template2["clientName"] = "clientName2"
            client_template3["clientId"] =     "clientId3"
            client_template3["clientName"] = "clientName3"

            group_template2 = copy.deepcopy(group_template)
            group_template3 = copy.deepcopy(group_template)
            group_template2["groupId"]   = "groupId2"
            group_template2["groupName"] = "groupName2"
            group_template3["groupId"] = "groupId3"
            group_template3["groupName"] = "groupName3"

            # #Contruct fake data
            client_template["ruleList"].append(rule_template)
            client_template["ruleList"].append(rule_template2)
            client_template["ruleList"].append(rule_template3)
            client_template2["ruleList"].append(rule_template)
            client_template2["ruleList"].append(rule_template2)
            client_template2["ruleList"].append(rule_template3)
            client_template3["ruleList"].append(rule_template)
            client_template3["ruleList"].append(rule_template2)
            client_template3["ruleList"].append(rule_template3)

            group_template["clientList"].append(client_template)
            group_template["clientList"].append(client_template2)
            group_template["clientList"].append(client_template3)
            group_template2["clientList"].append(client_template)
            group_template2["clientList"].append(client_template2)
            group_template2["clientList"].append(client_template3)
            group_template3["clientList"].append(client_template)
            group_template3["clientList"].append(client_template2)
            group_template3["clientList"].append(client_template3)

            responseJson.append(group_template)
            responseJson.append(group_template2)
            responseJson.append(group_template3)

            #responseJson = [
            #   group = {
            #       "groupId":
            #       "groupName":
            #       "clientList": [
            #           clientId
            #           clientName
            #           "ruleList": [
            #               "ruleId"
            #               "ruleDescription"
            #               "policyId": 
            #               "policyDescription":
            #               "dateTime"
            #               ]
            #           ]
            #       }   
            #   ]

            return  responseJson

        except Exception as e:
            print e, traceback.format_exc()
            return {}

    #API: /violation_computer_detail
    def get_violation_computer_detail_old(self, client_id):
        print("ServiceViolation-get_client_info")
        try:
            data_result = self.bls_evidences_repo.get_client_info(client_id)

            responseJson = {
                "clientId": "",
                "groupId": "",
                "userName": "",
                "computer": "",
                "domain": "",
                "email": "",
                "dateTime": "", #Example: 2020-05-28T08:45:42.204Z
                "violationDetail": [] #list of violation_detail_template
            }

            violation_detail_template = {
                "ruleId": "",
                "ruleName": ""
            }

            #Case not found any document
            if len(data_result["hits"]["hits"]) == 0:
                return responseJson
            else:
                #Get first index
                print("Found document")
                if "_source" in data_result["hits"]["hits"][0].keys():
                    base_data = data_result["hits"]["hits"][0]["_source"]
                    if "client_id" in base_data.keys():
                        responseJson["clientId"] = base_data["client_id"]
                    if "group_id" in base_data.keys(): 
                        responseJson["groupId"] = base_data["group_id"]
                    if "user_name" in base_data.keys(): 
                        responseJson["userName"] = base_data["user_name"]
                    if "computer_name" in base_data.keys(): 
                        responseJson["computer"] = base_data["computer_name"]
                    if "domain" in base_data.keys(): 
                        responseJson["domain"] = base_data["domain"]
                    if "email" in base_data.keys(): 
                        responseJson["email"] = base_data["email"]

                    #TODO dateTime is confuse, resolve later

                    #Check if client does't have active violation, for optimize code
                    #Disable if log_source in incorrect format
                    if "policies" in base_data.keys() and base_data["policies"] is not None:
                        total_violated_rule = len(base_data["policies"])
                        total_processed_rule = None
                        if "update_list" in base_data.keys():
                            for policy in base_data["update_list"]:
                                if "rule_entry" in policy["rule_entry"]:
                                    if "user_rule" in policy["rule_entry"]["user_rule"]:
                                        total_processed_rule = len(policy["rule_entry"]["user_rule"])
                        # Check if its equal, all client violations was processed  
                        # Return              
                        if total_violated_rule == total_processed_rule:
                            return  responseJson

                    #Process active violation    
                    #All active violation
                    violate_rules = []
                    if "policies" in base_data.keys() and base_data["policies"] is not None:
                        violate_policies = base_data["policies"] #type: list
                        #Iterate throught Polices
                        for rule in violate_policies: 
                            new_violation_detail = violation_detail_template
                            if "rule_id" in rule.keys():
                                new_violation_detail["ruleId"] = rule["rule_id"]
                            if "rule_description" in rule.keys():
                                new_violation_detail["ruleName"] = rule["rule_description"]
                            if new_violation_detail not in violate_rules:
                                violate_rules.append(new_violation_detail)

                    #All processed violation
                    processed_violation_rule = []
                    if "update_list" in base_data.keys():
                        for policy in base_data["update_list"].keys():
                            if "rule_entry" in policy["rule_entry"].keys():
                                if "user_rule" in policy["rule_entry"]["user_rule"]:
                                    list_rule = policy["rule_entry"]["user_rule"]
                                    for rule in list_rule:
                                        new_violation_detail = violation_detail_template
                                        if "_id" in rule.keys():
                                            new_violation_detail["ruleId"] = rule["_id"]
                                        if "description" in rule.keys():
                                            new_violation_detail["ruleName"] = rule["description"]
                                        if new_violation_detail not in processed_violation_rule:
                                            processed_violation_rule.append(new_violation_detail)

                    #Now, compare to get active violations    
                    for rule in violate_rules:
                        for processed_rule in processed_violation_rule:
                            if rule["ruleId"] == processed_rule["ruleId"]:
                                if rule in violate_rules:
                                    violate_rules.remove(rule)

                    #Now violate_rules contain oly active violation
                    for rule in violate_rules:
                        responseJson["violationDetail"].append(rule)
            return  responseJson    
        except Exception as e:
            print e, traceback.format_exc()
            return {}

    #API: /violation_computer_detail
    def get_violation_computer_detail(self, client_id):
        print("ServiceViolation-get_client_info")
        try:
            data_result = self.bls_evidences_repo.get_client_info(client_id)

            responseJson = {
                "ipAddress": "192.168.3.12",
                "computer": "IDC-QUYNHDT-V",
                "agentId": "ASKDHASKDHAJSDKASJDHJASD",
                "domain": "vtdc.local.domain",
                "groupName": "Tong cong ty",
                "dateTime": "2020-05-28T08:45:42.204Z", #Example: 2020-05-28T08:45:42.204Z
                "violationDetail": [] #list of violation_detail_template
            }

            violation_detail_template = {
                "ruleId": "",
                "ruleName": "",
                "time": "",
                "device": "",
                "deviceName" : ""
            }

            violation_detail1 = copy.deepcopy(violation_detail_template)
            violation_detail2 = copy.deepcopy(violation_detail_template)
            violation_detail3 = copy.deepcopy(violation_detail_template)

            violation_detail1["ruleId"]     =     "ruleId1"
            violation_detail1["ruleName"]   =   "ruleName1"
            violation_detail1["time"]       =       "time1"
            violation_detail1["device"]     =     "device1"
            violation_detail1["deviceName"] = "deviceName1"
            violation_detail2["ruleId"]     =     "ruleId2"
            violation_detail2["ruleName"]   =   "ruleName2"
            violation_detail2["time"]       =       "time2"
            violation_detail2["device"]     =     "device2"
            violation_detail2["deviceName"] = "deviceName2"
            violation_detail3["ruleId"]     =     "ruleId3"
            violation_detail3["ruleName"]   =   "ruleName3"
            violation_detail3["time"]       =       "time3"
            violation_detail3["device"]     =     "device3"
            violation_detail3["deviceName"] = "deviceName3"

            responseJson["violationDetail"].append(violation_detail1)
            responseJson["violationDetail"].append(violation_detail2)
            responseJson["violationDetail"].append(violation_detail3)

            return  responseJson
        except Exception as e:
            print e, traceback.format_exc()
            return {}

    #API: /list_violation_computer_for_group
    def get_list_violation_computer_for_group(self, violation_id, group_id, current_page, item_per_page):
        print "ServiceViolation-list_violation_computer_by_group"
        try:
            data_result = self.bls_evidences_repo.get_list_violation_computer( \
                violation_id, group_id, current_page, item_per_page)

            responseJson = [] #List of group_template
            group_template = {
                "groupId": "okv3",
                "groupName": "okv3",
                "clientList" : [] #List of client_template
            }
            client_template = {
                "clientId": "F31A583B2C8D1E10F4381710686061A446C8EF20",
                "clientName:": "VT_NTVAG_498311",
                "ruleList": [] #List of rule_template
            }
            rule_template = {
                "ruleId": "AVQESrZd0d47ZLKwg_Pf",
                "ruleDescription": "Quy che 385",
                "policyId": "AVXO6OcXKUVEy8KF_FNW", 
                "policyDescription": "Vi pham",
                "dateTime": ""
            }

            #Some fake data
            rule_template2 = copy.deepcopy(rule_template)
            rule_template3 = copy.deepcopy(rule_template)    
            rule_template2["ruleId"] =                       "ruleId2"
            rule_template2["ruleDescription"] =     "ruleDescription2"
            rule_template2["policyId"] =                   "policyId2"
            rule_template2["policyDescription"] = "policyDescription2"
            rule_template3["ruleId"] =                       "ruleId3"
            rule_template3["ruleDescription"] =     "ruleDescription3"
            rule_template3["policyId"] =                   "policyId3"
            rule_template3["policyDescription"] = "policyDescription3"            

            client_template2 = copy.deepcopy(client_template)
            client_template3 = copy.deepcopy(client_template)
            client_template2["clientId"] =     "clientId2"
            client_template2["clientName"] = "clientName2"
            client_template3["clientId"] =     "clientId3"
            client_template3["clientName"] = "clientName3"

            group_template2 = copy.deepcopy(group_template)
            group_template3 = copy.deepcopy(group_template)
            group_template2["groupId"]   = "groupId2"
            group_template2["groupName"] = "groupName2"
            group_template3["groupId"] = "groupId3"
            group_template3["groupName"] = "groupName3"

            # #Contruct fake data
            client_template["ruleList"].append(rule_template)
            client_template["ruleList"].append(rule_template2)
            client_template["ruleList"].append(rule_template3)
            client_template2["ruleList"].append(rule_template)
            client_template2["ruleList"].append(rule_template2)
            client_template2["ruleList"].append(rule_template3)
            client_template3["ruleList"].append(rule_template)
            client_template3["ruleList"].append(rule_template2)
            client_template3["ruleList"].append(rule_template3)

            group_template["clientList"].append(client_template)
            group_template["clientList"].append(client_template2)
            group_template["clientList"].append(client_template3)
            group_template2["clientList"].append(client_template)
            group_template2["clientList"].append(client_template2)
            group_template2["clientList"].append(client_template3)
            group_template3["clientList"].append(client_template)
            group_template3["clientList"].append(client_template2)
            group_template3["clientList"].append(client_template3)

            responseJson.append(group_template)
            responseJson.append(group_template2)
            responseJson.append(group_template3)

            return responseJson
        except Exception as e:
            print e, traceback.format_exc()
            return {}

    #API: /list_violation_computer_detail
    def get_client_info_for_group_view(self, client_id):
        print("ServiceViolation-get_client_info_for_group_view")
        try:
            data_result = self.bls_evidences_repo.get_client_info(client_id)

            responseJson = {
                "ipAddress": "192.168.3.12",
                "computer": "IDC-QUYNHDT-V",
                "agentId": "ASKDHASKDHAJSDKASJDHJASD",
                "domain": "vtdc.local.domain",
                "groupName": "Tong cong ty",
                "dateTime": "2020-05-28T08:45:42.204Z", #Example: 2020-05-28T08:45:42.204Z
                "violationDetail": [] #list of violation_detail_template
            }

            violation_detail_template = {
                "ruleId": "",
                "ruleName": "",
                "time": "",
                "device": "",
                "deviceName" : ""
            }

            violation_detail1 = copy.deepcopy(violation_detail_template)
            violation_detail2 = copy.deepcopy(violation_detail_template)
            violation_detail3 = copy.deepcopy(violation_detail_template)

            violation_detail1["ruleId"]     =     "ruleId1"
            violation_detail1["ruleName"]   =   "ruleName1"
            violation_detail1["time"]       =       "time1"
            violation_detail1["device"]     =     "device1"
            violation_detail1["deviceName"] = "deviceName1"
            violation_detail2["ruleId"]     =     "ruleId2"
            violation_detail2["ruleName"]   =   "ruleName2"
            violation_detail2["time"]       =       "time2"
            violation_detail2["device"]     =     "device2"
            violation_detail2["deviceName"] = "deviceName2"
            violation_detail3["ruleId"]     =     "ruleId3"
            violation_detail3["ruleName"]   =   "ruleName3"
            violation_detail3["time"]       =       "time3"
            violation_detail3["device"]     =     "device3"
            violation_detail3["deviceName"] = "deviceName3"

            responseJson["violationDetail"].append(violation_detail1)
            responseJson["violationDetail"].append(violation_detail2)
            responseJson["violationDetail"].append(violation_detail3)

            return  responseJson   
        except Exception as e:
            print e, traceback.format_exc()
            return {}

    #API: /
    def list_violation_rule_for_group(self, violation_id, group_id):
        print "ServiceViolation-list_violation_rule_for_group"
        try:
            #data_result = self.bls_evidences_repo.get_client_info(client_id)

            responseJson = []

            policy_template = {
                "policyId": "AVXO6OcXKUVEy8KF_FNW", 
                "policyDescription": "Vi pham",
                "ruleList" : []
            }

            rule_template = {
                "ruleId": "AVQESrZd0d47ZLKwg_Pf",
                "ruleDescription": "Quy che 385",
                "dateTime": ""
            }

            rule_template1 = copy.deepcopy(rule_template)
            rule_template2 = copy.deepcopy(rule_template)

            policy_template1 = copy.deepcopy(policy_template)    
            policy_template2 = copy.deepcopy(policy_template)

            rule_template1["ruleId"] = "ruleId1"
            rule_template1["ruleDescription"] = "ruleDescription1"
            rule_template1["dateTime"] = "2020-05-28T08:45:42.204Z"
            rule_template2["ruleId"] = "ruleId2"
            rule_template2["ruleDescription"] = "ruleDescription2"
            rule_template2["dateTime"] = "2020-05-28T08:45:42.204Z"
            
            policy_template1["policyId"] = "policyId1"
            policy_template1["policyDescription"] = "policyDescription1"
            policy_template2["policyId"] = "policyId2"
            policy_template2["policyDescription"] = "policyDescription2"

            policy_template["ruleList"].append(rule_template)
            policy_template["ruleList"].append(rule_template1)
            policy_template["ruleList"].append(rule_template2)
            policy_template1["ruleList"].append(rule_template)
            policy_template1["ruleList"].append(rule_template1)
            policy_template1["ruleList"].append(rule_template2)
            policy_template2["ruleList"].append(rule_template)
            policy_template2["ruleList"].append(rule_template1)
            policy_template2["ruleList"].append(rule_template2)

            responseJson.append(policy_template)
            responseJson.append(policy_template1)
            responseJson.append(policy_template2)

            return responseJson
        except Exception as e:
            print e, traceback.format_exc()
            return {}
