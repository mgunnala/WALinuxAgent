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

# Default policy to be used when no custom policy is present.
DEFAULT_POLICY_JSON = """
            {
               "policyVersion": "0.1.0",
               "extensionPolicies": {
                   "allowListedExtensionsOnly": false,
                   "signatureRequired": false,
                   "signingPolicy": {},
                   "extensions": {}
               },
               "jitPolicies": {}
            }
            """


class PolicyError(AgentError):
    """
    Error raised during agent policy enforcement.
    """
    # TODO: split into two error classes for internal/dev errors and user errors.


class PolicyEngine(object):
    """
    Implements base policy engine API.
    If any errors are thrown in regorus.py, they will be caught and re-raised here.
    The caller will be responsible for handling errors.
    """
    def __init__(self):
        self.policy = None
        if not self.is_policy_enforcement_enabled():
            self._log_policy(msg="Policy enforcement is not enabled.")
            return

        # If unsupported, this call will raise an error
        self._check_policy_enforcement_supported()
        self.policy = self.__set_policy()

    def __get_custom_policy(self):
        """
        Check if custom policy exists and validate policy.
        Return None if no policy exists. Raise error if policy invalid.
        Valid JSON file expected to be at CUSTOM_POLICY_PATH
        The expected policy format is:
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
        if os.path.exists(CUSTOM_POLICY_PATH):
            self._log_policy("Custom policy found at {0}. Using custom policy instead of default.".format(CUSTOM_POLICY_PATH))
            with open(CUSTOM_POLICY_PATH, 'r') as f:
                custom_policy = json.load(f)
                self.__validate_policy(custom_policy, POLICY_SCHEMA)
                return custom_policy
        else:
            self._log_policy("No custom policy found at {0}. Using default policy.".format(CUSTOM_POLICY_PATH))
            return None

    @staticmethod
    def __validate_policy(policy, schema):
        """
        Validate that the provided policy matches the schema and contains no unexpected attributes.
        Raise ValueError if invalid attribute or type found.
        If an attribute is missing, continue (don't raise error).
        """

        def __validate_dict(d, s):
            """Recursively validate dictionary against the schema."""

            # Check that each key in the dict is also in the schema.
            for key, value in d.items():
                if key not in s:
                    raise ValueError("Unexpected attribute '{0}' found in policy file ({1}).".format(key, CUSTOM_POLICY_PATH))

                schema_value = s[key]

                # Extension keys can be any valid string. Handle this special case.
                if key == "extensions":
                    # 'extensions' should be a dict itself.
                    if not isinstance(value, dict):
                        raise ValueError("Invalid type '{0}' for attribute 'extensions' in policy file ({0}) Should be JSON object"
                                         .format(type(value), CUSTOM_POLICY_PATH))

                    # Validate each extension in 'extensions' against the schema.
                    for sub_key, sub_value in value.items():
                        if not isinstance(sub_key, str):
                            raise ValueError("Unexpected attribute '{0}' in 'extensions' in policy file ({1}).".format(sub_key, CUSTOM_POLICY_PATH))
                        __validate_dict(sub_value, schema_value["<extensionName>"])
                    continue  # Skip the normal dictionary validation for this level

                # If the schema value is a dictionary, recursively validate.
                if isinstance(schema_value, dict):
                    if isinstance(value, dict):
                        __validate_dict(value, schema_value)
                    else:
                        raise ValueError(f"Invalid type for attribute '{key}' in policy. Expected dict.")

                # Check type for other values
                elif not isinstance(value, schema_value):
                    raise ValueError(f"Invalid type for attribute '{key}' in policy. Expected {schema_value.__name__}.")

        __validate_dict(policy, schema)

    def __set_policy(self):
        custom_policy = self.__get_custom_policy()
        if custom_policy is None:
            policy = json.loads(DEFAULT_POLICY_JSON)
        else:
            policy = custom_policy
        return policy

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
    def is_policy_enforcement_enabled():
        """
        Check whether user has opted into policy enforcement feature.
        Caller function should check this before performing any operations.
        """
        # TODO: The conf flag will be removed post private preview. Before public preview, add checks
        # according to the planned user experience (TBD).
        return conf.get_extension_policy_enabled()

    @staticmethod
    def _check_policy_enforcement_supported():
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

    def should_allow_extension(self):
        if not self.is_policy_enforcement_enabled():
            return True

        ext_policy = self.policy.get("extensionPolicies")
        allow_listed_extension_only = ext_policy.get("allowListedExtensionsOnly")
        extension_allowlist = ext_policy.get("extensions")
        should_allow = not allow_listed_extension_only or extension_allowlist.get(self.extension_to_check.name) is not None
        return should_allow

    def should_enforce_signature(self):
        if not self.is_policy_enforcement_enabled():
            return False

        ext_policy = self.policy.get("extensionPolicies")
        extension_dict = ext_policy.get("extensions")
        global_signature_required = ext_policy.get("signatureRequired")
        extension_individual_policy = extension_dict.get(self.extension_to_check.name)
        if extension_individual_policy is None:
            return global_signature_required
        else:
            return extension_individual_policy.get("signatureRequired")
