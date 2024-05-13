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


class PolicyEngine:
    """Base class for policy engine"""
    def __init__(self, policy_file=None, data_file=None):
        self._engine = regorus.Engine()
        if policy_file is not None:
            self._engine.add_policy_from_file(policy_file)
        if data_file is not None:
            self.add_data(data_file)


"""
class PolicyEngine::Singleton:  

policy_path: str 

data_path: str 

def __init__(policy_file: path, data_file: path) 

def add_policy_rule(policy_file: path) 

def add_data(data: json or path) 

def set_input(input: json or path) 

def eval_query(query: str) -> return json 

def update_data( ) 

def __clear_data( ) 

  

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

  

class GoalStatePolicyEngine(PolicyEngine): 

def is_valid_signature() -> return bool 
"""