# Copyright 2018 Microsoft Corporation
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
#
# Requires Python 2.4+ and Openssl 1.0+
#

import json
import os
import re
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common import logger
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict

# Schema for policy file.
_POLICY_SCHEMA = \
    {
        "policyVersion": str,
        "extensionPolicies": {
            "allowListedExtensionsOnly": bool,
            "signatureRequired": bool,
            "extensions": {
                "<extensionName>": {
                    "signatureRequired": bool
                }
            }
        }
    }

# Default policy values to be used when customer does not specify these attributes in the policy file.
_DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
_DEFAULT_SIGNATURE_REQUIRED = False

# Agent supports up to this version of the policy file ("policyVersion" in schema).
# Increment this number when any new attributes are added to the policy schema.
_MAX_SUPPORTED_POLICY_VERSION = "0.1.0"


class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """


class InvalidPolicyError(AgentError):
    """
    Error raised if user-provided policy is invalid.
    """
    def __init__(self, msg, inner=None):
        msg = "Customer-provided policy file ('{0}') is invalid, please correct the following error: {1}".format(conf.get_policy_file_path(), msg)
        super(InvalidPolicyError, self).__init__(msg, inner)


class _PolicyEngine(object):
    """
    Implements base policy engine API.
    """
    def __init__(self):
        """
        _PolicyEngine should be initialized on a per-goal state basis. Policy enablement is checked and policy file is
        read only during initialization. The same policy is enforced even if the policy file is deleted or changed
        during a single goal state processing.
        """
        self._policy_enforcement_enabled = self.__get_policy_enforcement_enabled()
        if not self.policy_enforcement_enabled:
            return

        # Set defaults for policy and update with the customer-provided policy file.
        self._policy = \
        {
            "policyVersion": _MAX_SUPPORTED_POLICY_VERSION,
            "extensionPolicies": {
                "allowListedExtensionsOnly": _DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY,
                "signatureRequired": _DEFAULT_SIGNATURE_REQUIRED,
                "extensions": {}
            }
        }
        custom_policy = self.__get_policy()
        self.__parse_policy(custom_policy)

    @staticmethod
    def _log_policy_event(msg, is_success=True, op=WALAEventOperation.Policy, send_event=True):
        """
        Log information to console and telemetry.
        """
        if is_success:
            logger.info(msg)
        else:
            logger.error(msg)
        if send_event:
            add_event(op=op, message=msg, is_success=is_success, log_event=False)

    @staticmethod
    def __get_policy_enforcement_enabled():
        """
        Policy will be enabled if (1) policy file exists at the expected location and (2) the conf flag "Debug.EnableExtensionPolicy" is true.
        """
        return conf.get_extension_policy_enabled() and os.path.exists(conf.get_policy_file_path())

    @property
    def policy_enforcement_enabled(self):
        return self._policy_enforcement_enabled

    @staticmethod
    def __get_policy():
        """
        Read customer-provided policy JSON file, load and return as a dict.
        Policy file is expected to be at conf.get_policy_file_path(). Note that this method should only be called
        after verifying that the file exists (currently done in __init__).
        """
        with open(conf.get_policy_file_path(), 'r') as f:
            _PolicyEngine._log_policy_event(
                "Policy enforcement is enabled. Enforcing policy using policy file found at '{0}'.".format(
                    conf.get_policy_file_path()))
            try:
                # json.load will raise error if file is not in valid json format (including empty file).
                custom_policy = json.load(f)
            except ValueError as ex:
                msg = "policy file does not conform to valid json syntax"
                raise InvalidPolicyError(msg=msg, inner=ex)
            except Exception as ex:
                msg = "unable to load policy file"
                raise InvalidPolicyError(msg=msg, inner=ex)

            return custom_policy

    def __parse_policy(self, custom_policy):
        """
        Update self._policy with attributes specified in custom_policy:
            - attributes provided in custom_policy override the default values in self._policy
            - if an attribute is not provided, use the default value
            - if an unrecognized attribute is present in custom_policy (not defined in _POLICY_SCHEMA), raise an error
            - if an attribute does not match the type specified in the schema, raise an error

        If provided, the "extensions" attribute will be converted to a case-folded dict. CRP allows extensions to be any
        case, so we use case-folded dict to allow for case-insensitive lookup of individual extension policies.
        """
        # Validate top level attributes and then parse each section of the policy file.
        # Individual parsing functions are responsible for validating schema of that section (nested dict).
        self.__validate_schema(custom_policy, _POLICY_SCHEMA)
        self.__parse_version(custom_policy)
        self.__parse_extension_policies(custom_policy)

    def __parse_version(self, policy):
        """
        Validate and return "policyVersion" attribute. If not a string in the format "x.y.z", raise InvalidPolicyError.
        If policy_version is greater than maximum supported version, raise InvalidPolicyError.
        """
        version = self.__parse_string(policy, "policyVersion")
        if version is None:
            return

        pattern = r'^\d+\.\d+\.\d+$'
        if not re.match(pattern, version):
            raise InvalidPolicyError("invalid value for attribute 'policyVersion' attribute 'policyVersion' is expected to be in format 'major.minor.patch' "
                                     "(e.g., '1.0.0'). Please change to a valid value.")
        version_tuple = tuple(map(int, version.split(".")))

        if tuple(map(int, _MAX_SUPPORTED_POLICY_VERSION.split("."))) < version_tuple:
            raise InvalidPolicyError("policy version '{0}' is not supported. The agent supports policy versions up to '{1}'. Please provide a compatible policy version."
                                     .format(version, _MAX_SUPPORTED_POLICY_VERSION))

        self._policy["policyVersion"] = version

    def __parse_extension_policies(self, policy):
        extension_policies = self.__parse_dict(policy, "extensionPolicies")
        if extension_policies is not None:
            self.__validate_schema(extension_policies, _POLICY_SCHEMA["extensionPolicies"])

            # Parse allowlist policy
            allowlist_policy = self.__parse_bool(extension_policies, "allowListedExtensionsOnly")
            if allowlist_policy is not None:
                self._policy["extensionPolicies"]["allowListedExtensionsOnly"] = allowlist_policy

            # Parse global signature policy
            signature_policy = self.__parse_bool(extension_policies, "signatureRequired", "extensionPolicies")
            if signature_policy is not None:
                self._policy["extensionPolicies"]["signatureRequired"] = signature_policy

            # Parse individual extension policies
            self.__parse_extensions(extension_policies)

        return extension_policies

    def __parse_extensions(self, extensions_policy):
        """
        Parse "extensions" dict and update in self._policy.
        "extensions" is expected to be in the format:
        {
            "extensions": {
                "<extensionName>": {
                    "signatureRequired": bool
                }
            }
        }

        If "signatureRequired" isn't provided, the global "signatureRequired" value will be used instead.
        """
        extensions = self.__parse_dict(extensions_policy, "extensions")
        if extensions is None:
            return

        # Validate "extensions" dict against the schema
        extensions_schema = _POLICY_SCHEMA["extensionPolicies"]["extensions"]
        if not isinstance(extensions, dict):
            raise InvalidPolicyError("invalid type {0} for attribute 'extensions', please change to object."
                                     .format(type(extensions).__name__))

        # Parse "extensions" and update self._policy with specified attributes
        parsed_extensions_dict = {}
        for (extension_name, individual_policy) in extensions.items():
            self.__validate_schema(individual_policy, extensions_schema["<extensionName>"])
            if not isinstance(individual_policy, dict):
                raise InvalidPolicyError("invalid type {0} for attribute '{1}', please change to object."
                                         .format(type(individual_policy).__name__, extension_name))

            extension_signature_policy = _PolicyEngine.__parse_bool(individual_policy, "signatureRequired", extension_name)
            if extension_signature_policy is None:
                extension_signature_policy = self._policy["extensionPolicies"]["signatureRequired"]

            policy_to_add = {
                "signatureRequired": extension_signature_policy
            }
            parsed_extensions_dict[extension_name] = policy_to_add

        # Convert "extensions" to a case-folded dict for case-insensitive lookup
        case_folded_extensions_dict = _CaseFoldedDict.from_dict(parsed_extensions_dict)
        self._policy["extensionPolicies"]["extensions"] = case_folded_extensions_dict

    @staticmethod
    def __validate_schema(policy, schema):
        """
        Validate the provided policy against the schema - we only do a shallow check (no recursion into nested dicts).
        If there is an unrecognized attribute, raise an error.
        """
        for key in policy:
            if key not in schema:
                raise InvalidPolicyError("attribute '{0}' is not defined in the policy schema. Please refer to the policy documentation "
                                         "and change or remove this attribute accordingly.".format(key))

    @staticmethod
    def __parse_bool(policy, key, parent_attribute_name=None):
        """
        Raise error if policy[key] is not a boolean. Return none if the key does not exist.
        For attributes that are used in multiple places (ex: "signatureRequired"), we specify the parent attribute in
        the error message to avoid ambiguity.
        """
        value = policy.get(key)
        if value is None:
            return None

        if not isinstance(value, bool):
            if parent_attribute_name is None:
                msg = ("invalid type {0} for attribute '{1}', please change to bool."
                       .format(type(value).__name__, key))
            else:
                msg = ("invalid type {0} for attribute '{1}' in section '{2}', please change to bool."
                       .format(type(value).__name__, key, parent_attribute_name))

            raise InvalidPolicyError(msg)

        return value

    @staticmethod
    def __parse_dict(policy, key):
        value = policy.get(key)
        if value is None:
            return None

        if not isinstance(value, dict):
            raise InvalidPolicyError("invalid type '{0}' for attribute '{1}', please change to object.".format(type(value).__name__, key))

        return value

    @staticmethod
    def __parse_string(policy, key):
        value = policy.get(key)
        if value is None:
            return None

        if not isinstance(value, (str, ustr)):
            raise InvalidPolicyError("invalid type '{0}' for attribute '{1}', please change to object.".format(type(value).__name__, key))

        return value




class ExtensionPolicyEngine(_PolicyEngine):

    def should_allow_extension(self, extension_to_check):
        """
        Return whether we should allow extension download based on policy.
        extension_to_check is expected to be an Extension object.

        If policy feature not enabled, return True.
        If allowListedExtensionsOnly=true, return true only if extension present in "extensions" allowlist.
        If allowListedExtensions=false, return true always.
        """
        if not self.policy_enforcement_enabled:
            return True

        allow_listed_extension_only = self._policy.get("extensionPolicies").get("allowListedExtensionsOnly")
        extension_allowlist = self._policy.get("extensionPolicies").get("extensions")

        should_allow = not allow_listed_extension_only or extension_allowlist.get(extension_to_check.name) is not None
        return should_allow

    def should_enforce_signature_validation(self, extension_to_check):
        """
        Return whether we should enforce signature based on policy.
        extension_to_check is expected to be an Extension object.

        If policy feature not enabled, return False.
        Individual policy takes precedence over global - if individual signing policy present, return true/false based on
        individual policy. Else, return true/false based on global policy.
        """
        if not self.policy_enforcement_enabled:
            return False

        global_signature_required = self._policy.get("extensionPolicies").get("signatureRequired")
        individual_policy = self._policy.get("extensionPolicies").get("extensions").get(extension_to_check.name)
        if individual_policy is None:
            return global_signature_required
        else:
            return individual_policy.get("signatureRequired")

    # TODO: Consider adding a function should_download_extension() combining should_allow_extension() and
    # should_enforce_signature_validation(), such that caller function only needs to make one call.
