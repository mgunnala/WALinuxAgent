# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is a placeholder policy engine class to test that the regorus
# dependency is correctly installed.
# pylint: disable=too-few-public-methods

import regorus
import os
import json
from azurelinuxagent.common import logger

# Policy rule and data files are expected to be in the same parent dir as this file.
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


class PolicyEngine:
    """Base class for policy engine"""
    is_running = False

    """Constructor"""

    def __init__(self, policy_file=None, data_file=None):
        try:
            self._engine = regorus.Engine()
            if policy_file is not None:
                self.add_policy(policy_file)
            if data_file is not None:
                self.add_data(data_file)
        except Exception as e:
            logger.warn("Exception occurred during policy engine initialization: {0}", str(e))

    def add_policy(self, policy_file):
        """
        Add policy rule from file. Policy_file is expected to point to a valid Rego policy file.
        """
        self._engine.add_policy_from_file(policy_file)

    def add_data(self, data):
        """Add data based on input parameter type"""
        if os.path.isfile(data):
            data_file = json.load(open(data, 'r', encoding='utf-8'))
            self._engine.add_data(data_file)
        elif isinstance(data, dict):
            data_json = json.dumps(data)
            self._engine.add_data_json(data_json)
        elif isinstance(data, str):
            self._engine.add_data_json(data)
        else:
            logger.error("Unsupported data type: {0}".format(type(data)))

    def set_input(self, policy_input):
        """Set input"""
        if os.path.isfile(policy_input):
            input_file = json.load(open(policy_input, 'r', encoding='utf-8'))
            self._engine.set_input(input_file)
        elif isinstance(policy_input, dict):
            input_json = json.dumps(policy_input)
            self._engine.set_input_json(input_json)
        elif isinstance(policy_input, str):
            self._engine.set_input_json(policy_input)
        else:
            logger.error("Unsupported input type: {0}".format(type(policy_input)))

    def evaluate_query(self, query, return_json=True):
        """Evaluate query. If return_json is true,
        return results as json, else return as string."""
        if return_json:
            results = json.loads(self._engine.eval_query_as_json(query))
        else:
            results = str(self._engine.eval_query(query))
        return results


def is_valid_signature(signature=None, signing_method=None):
    # TO DO - update code once extension signing is implemented
    return False


def convert_list_to_json(ext_list):
    """
    Helper function to convert a list of extensions to a json compatible with policy engine.
    Expects a list of tuples in the form (extension_setting, extension_handler).
    Returns json in the format:
    { "extensions":
        {
            "extname1:": {
                "signingInfo": {
                    "extensionSigned": true
                }
                ...
    """

    input_json = {
        "extensions": {}
    }
    # TO DO - eventually, we may need to handle attributes other than name and signature
    for _, ext in ext_list:
        is_signed = is_valid_signature()
        input_json["extensions"][ext.name] = {
            "signingInfo":
                {
                    "extensionSigned": is_signed
                }
        }

    return json.dumps(input_json)


class ExtensionPolicyEngine(PolicyEngine):
    """Implement the policy engine for extension allow/disallow policy"""
    # defaults for policy rule and data
    extension_policy_path = os.path.join(CURRENT_DIR, "agent_extension_policy.rego")
    extension_data_path = os.path.join(CURRENT_DIR, "agent-extension-default-data.json")
    allowed_list = None
    all_extensions = None

    def __init__(self, policy_path=None, data_path=None):
        if policy_path is not None:
            self.extension_policy_path = policy_path
        if data_path is not None:
            self.extension_data_path = data_path
        super().__init__(self.extension_policy_path, self.extension_data_path)

    def set_input(self, all_extensions):
        ext_json = convert_list_to_json(all_extensions)
        super().set_input(ext_json)

    # def is_extension_download_allowed(self):


"""

class ExtensionPolicyEngine(PolicyEngine):  

allowed_list: list = none  

all_extensions: list = none 

require_signed : bool 

def get_global_policy() -> return json 

def get_allowed_list(all_extensions: list) -> return list 

def get_policy_for_extension(extension, enforcement_point=none) -> return json 

def is_extension_allowed(extension_name: str) -> return bool 

def is_extension_download_allowed(extension_name: str) -> return bool 

def is_extension_install_allowed(extension_name: str) -> return bool 

def is_extension_update_allowed(extension_name: str) -> return bool 

def is_extension_uninstall_allowed(extension_name: str) -> return bool 

def is_valid_signature(signature, signing_method) -> return bool 

def __convert_list_to_json(all_extensions: list) -> return regorus-compatible json 

  
"""
