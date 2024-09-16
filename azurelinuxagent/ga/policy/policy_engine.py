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
from azurelinuxagent.common import logger
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME
from azurelinuxagent.common.utils.distro_version import DistroVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.protocol.extensions_goal_state_from_vm_settings import _CaseFoldedDict

# Define support matrix for Regorus and policy engine feature.
# Dict in the format: { distro:min_supported_version }
POLICY_SUPPORTED_DISTROS_MIN_VERSIONS = {
    'ubuntu': DistroVersion('16.04'),
    'mariner': DistroVersion('2'),
    'azurelinux': DistroVersion('3')
}
# TODO: add 'arm64', 'aarch64' here once support is enabled for ARM64
POLICY_SUPPORTED_ARCHITECTURE = ['x86_64']

# Customer-defined policy is expected to be located at this path.
# If there is no file at this path, default policy will be used.
CUSTOM_POLICY_PATH = "/etc/waagent_policy.json"

# Default policy values to be used when no custom policy is present.
DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY = False
DEFAULT_SIGNATURE_REQUIRED = False
POLICY_SCHEMA = {
            "policyVersion": str,
            "extensionPolicies": {
                "allowListedExtensionsOnly": bool,
                "signatureRequired": bool,
                "signingPolicy": dict,
                "extensions": {
                    # Extensions keys are dynamic, but must follow this structure
                    "<extensionName>": {
                        "signatureRequired": bool,
                        "signingPolicy": dict,
                        "runtimePolicy": dict
                    }
                }
            },
            "jitPolicies": dict
        }

class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """
    # TODO: split into two error classes for internal/dev errors and user errors.


class PolicyEngine(object):
    """
    Implements base policy engine functions.
    """
    def __init__(self):
        if not self.is_policy_enforcement_feature_enabled():
            self._log_policy(msg="Policy enforcement is not enabled.")
            return

        # If unsupported, this call will raise an error
        self._check_policy_supported_on_platform()
        self.policy = self.__get_policy()

    def __get_policy(self):
        """
        Check if custom policy exists at CUSTOM_POLICY_PATH, load JSON object and return as a dict.
        Validate that no unexpected sections are present in the policy.
        Return {} if no policy exists.
        The expected policy format is:
        {
           "policyVersion": "<x.x.x>",
           "extensionPolicies": {...},
           "jitPolicies": {...}
        }
        """
        if os.path.exists(CUSTOM_POLICY_PATH):
            self._log_policy("Custom policy found at {0}. Using custom policy.".format(CUSTOM_POLICY_PATH))
            with open(CUSTOM_POLICY_PATH, 'r') as f:
                custom_policy = json.load(f)
                self.__validate_policy(custom_policy, POLICY_SCHEMA)    # Will raise ValueError if policy is invalid
                return custom_policy
        else:
            self._log_policy("No custom policy found at {0}. Using default policy.".format(CUSTOM_POLICY_PATH))
            return {}

    def __validate_policy(self, policy, schema):
        """
        Validate policy against the provided schema. Validation is done only at the top level (we don't recurse into nested dicts).
        If there is an attribute in the policy that is undefined in the schema or is the wrong type, raise ValueError.
        No error will be raised if an attribute defined in schema is missing in the policy.
        """
        # Each key in the policy should be in the schema. Raise a ValueError if an unexpected key is found.
        for key, value in policy.items():
            if key not in schema:
                raise ValueError("Unexpected attribute '{0}' found in policy file ({1}).".format(key, CUSTOM_POLICY_PATH))

            schema_value = schema[key]
            # We don't recursively validate the dicts
            if isinstance(schema_value, dict):
                schema_value = dict
            if not isinstance(value, schema_value):
                raise ValueError("Invalid type for attribute '{0}' in policy. Expected {0}.".format(key, schema_value.__name__))

    @classmethod
    def _log_policy(cls, msg, is_success=True, op=WALAEventOperation.Policy, send_event=True):
        """
        Log information to console and telemetry.
        """
        if is_success:
            logger.info(msg)
        else:
            logger.error(msg)
        if send_event:
            add_event(op=op, message=msg, is_success=is_success)

    @staticmethod
    def is_policy_enforcement_feature_enabled():
        """
        Check whether user has opted into policy enforcement feature.
        Caller function should check this before performing any operations.
        """
        # TODO: The conf flag will be removed post private preview. Before public preview, add checks
        # according to the planned user experience (TBD).
        return conf.get_extension_policy_enabled()

    @staticmethod
    def _check_policy_supported_on_platform():
        """
        Check that both platform architecture and distro/version are supported.
        If supported, do nothing.
        If not supported, raise PolicyError with user-friendly error message.
        """
        osutil = get_osutil()
        arch = osutil.get_vm_arch()
        # TODO: surface as a user error with clear instructions for fixing
        msg = "Attempted to enable policy enforcement, but feature is not supported on "
        if arch not in POLICY_SUPPORTED_ARCHITECTURE:
            msg += " architecture " + str(arch)
        elif DISTRO_NAME not in POLICY_SUPPORTED_DISTROS_MIN_VERSIONS:
            msg += " distro " + str(DISTRO_NAME)
        else:
            min_version = POLICY_SUPPORTED_DISTROS_MIN_VERSIONS.get(DISTRO_NAME)
            if DISTRO_VERSION < min_version:
                msg += " distro " + DISTRO_NAME + " " + DISTRO_VERSION + ". Policy is only supported on version " + \
                        str(min_version) + " and above."
            else:
                return  # do nothing if platform is supported
        raise PolicyError(msg)


class ExtensionPolicyEngine(PolicyEngine):

    def __init__(self, extension_to_check):
        self.extension_to_check = extension_to_check    # each instance is tied to an extension.
        super().__init__()
        if not self.is_policy_enforcement_feature_enabled():
            return

        self.extension_policy = {}
        if self.policy is not None and self.policy.get("extensionPolicies") is not None:
            extension_policy_schema = {
                "allowListedExtensionsOnly": bool,
                "signatureRequired": bool,
                "signingPolicy": dict,
                "extensions": {
                    "<extensionName>": {
                        "signatureRequired": bool,
                        "signingPolicy": dict,
                        "runtimePolicy": dict
                    }
                }
            }
            self.__validate_policy(self.policy.get("extensionPolicies"), extension_policy_schema)
            self.extension_policy = self.policy.get("extensionPolicies")

    def should_allow_extension(self):
        if not self.is_policy_enforcement_feature_enabled():
            return True

        allow_listed_extension_only = self.extension_policy.get("allowListedExtensionsOnly", DEFAULT_ALLOW_LISTED_EXTENSIONS_ONLY)
        extension_allowlist = self.extension_policy.get("extensions", {})
        should_allow = not allow_listed_extension_only or extension_allowlist.get(self.extension_to_check.name) is not None
        return should_allow

    def should_enforce_signature(self):
        if not self.is_policy_enforcement_feature_enabled():
            return False

        extension_dict = self.extension_policy.get("extensions", {})
        global_signature_required = self.extension_policy.get("signatureRequired", DEFAULT_SIGNATURE_REQUIRED)
        extension_individual_policy = extension_dict.get(self.extension_to_check.name)
        if extension_individual_policy is None:
            return global_signature_required
        else:
            return extension_individual_policy.get("signatureRequired", DEFAULT_SIGNATURE_REQUIRED)

    def __validate_policy(self, policy, schema):
        """
        {
           "policyVersion": "<x.x.x>",
           "extensionPolicies": {
               "allowListedExtensionsOnly": <true, false>,
               "signatureRequired": <true, false>,
               "signingPolicy": {},
               "extensions": {
                   "<extension_name>": {
                       "signatureRequired": <true, false>,
                       "signingPolicy": {},
                       "runtimePolicy": {
                           "allowedCommands": ["<cmd1>", "<cmd2>"]
                       }
                   }
               }
           },
           "jitPolicies": {}
        }
        """
        # Each key in the policy should be in the schema. Raise a ValueError if an unexpected key is found.
        for key, value in policy.items():
            if key not in schema:
                raise ValueError(
                    "Unexpected attribute '{0}' found in policy file ({1}).".format(key, CUSTOM_POLICY_PATH))

            schema_value = schema[key]
            if key == "extensions":
                # 'extensions' should be a dict itself.
                if not isinstance(value, dict):
                    raise ValueError(
                        "Invalid type '{0}' for attribute 'extensions' in policy file ({0}). Expected dict."
                        .format(type(value), CUSTOM_POLICY_PATH))

                # Validate each extension in 'extensions' against the schema.
                for sub_key, sub_value in value.items():
                    if not isinstance(sub_key, str):
                        raise ValueError(
                            "Unexpected attribute '{0}' in 'extensions' in policy file ({1}).".format(sub_key,
                                                                                                      CUSTOM_POLICY_PATH))
                    self.__validate_policy(sub_value, schema_value["<extensionName>"])
                continue  # Skip the normal dictionary validation for this level

            if not isinstance(value, schema_value):
                raise ValueError(
                    "Invalid type for attribute '{0}' in policy. Expected {0}.".format(key, schema_value.__name__))