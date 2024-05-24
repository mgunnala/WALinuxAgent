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

import os
import sys
import json
from azurelinuxagent.common import logger


# Import regorus. Regorus sub-folder, policy rule and data files are expected to be in the same parent dir as this file.
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
REGO_PATH = os.path.join(CURRENT_DIR, 'regorus')
sys.path.append(REGO_PATH)
import regorus


class PolicyEngine:
    """Base class for policy engine"""

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
            self._engine.add_data_from_json_file(data)
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
            self._engine.set_input_from_json_file(policy_input)
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
    # TO DO - eventually, we will need to handle attributes other than name
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
    extension_data_path = os.path.join(CURRENT_DIR, "agent-extension-data-allow-only.json")
    allowed_list = None
    all_extensions = None
    policy_output = None

    def __init__(self, policy_path=None, data_path=None):
        if policy_path is not None:
            self.extension_policy_path = policy_path
        if data_path is not None:
            self.extension_data_path = data_path
        super().__init__(self.extension_policy_path, self.extension_data_path)

    def set_input(self, all_extensions):
        ext_json = convert_list_to_json(all_extensions)
        super().set_input(ext_json)

    def get_extension_policy_output(self, all_extensions):
        if self.policy_output is not None and all_extensions == self.all_extensions:
            return self.policy_output
        self.set_input(all_extensions)
        self.policy_output = self.evaluate_query("data.agent_extension_policy", return_json=True)
        return self.policy_output

    def is_extension_download_allowed(self, all_extensions, extension_to_check):
        output = self.get_extension_policy_output(all_extensions)
        extensions_to_download = output['result'][0]['expressions'][0]['value']['extensions_to_download']
        if extension_to_check.name in extensions_to_download:
            return extensions_to_download[extension_to_check.name]['downloadAllowed']
        else:
            return False
