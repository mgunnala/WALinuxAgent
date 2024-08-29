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

from azurelinuxagent.common import logger
from azurelinuxagent.common.version import DISTRO_VERSION, DISTRO_NAME
from azurelinuxagent.common.utils.distro_version import DistroVersion
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common import conf
from azurelinuxagent.common.osutil import get_osutil
import azurelinuxagent.ga.policy.regorus as regorus
from azurelinuxagent.ga.policy.regorus import PolicyError

# Define support matrix for Regorus and policy engine feature.
# Dict in the format: { distro:min_supported_version }
POLICY_SUPPORTED_DISTROS_MIN_VERSIONS = {
    'ubuntu': DistroVersion('16.04'),
    'mariner': DistroVersion('2'),
    'azurelinux': DistroVersion('3')
}
# TODO: add 'arm64', 'aarch64' here once support is enabled for ARM64
POLICY_SUPPORTED_ARCHITECTURE = ['x86_64']


class PolicyEngine(object):
    """
    Implements base policy engine API.
    If any errors are thrown in regorus.py, they will be caught and re-raised here.
    The caller will be responsible for handling errors.
    """
    def __init__(self, rule_file, policy_file):
        """
        Constructor checks that policy enforcement should be enabled, and then sets up the
        Regorus policy engine (add rule and policy file).

        rule_file: Path to a Rego file that specifies rules for policy behavior.

        policy_file: Path to a JSON file that specifies parameters for policy behavior - for example,
        whether allowlist or extension signing should be enforced.
        The expected file format is:
        {
            "azureGuestAgentPolicy": {
                "policyVersion": "0.1.0",
                "signingRules": {
                    "extensionSigned": <true, false>
                },
                "allowListOnly": <true, false>
            },
            "azureGuestExtensionsPolicy": {
                "allowed_ext_1": {
                    "signingRules": {
                        "extensionSigned": <true, false>
                    }
                }
        }
        """
        self._engine = None
        if not self.is_policy_enforcement_enabled():
            self._log_policy(msg="Policy enforcement is not enabled.")
            return

        # If unsupported, this call will raise an error
        self._check_policy_enforcement_supported()
        self._engine = regorus.Engine(policy_file=policy_file, rule_file=rule_file)

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

    def evaluate_query(self, input_to_check, query):
        """
        Input_to_check is the input we want to check against the policy engine (ex: extensions we want to install).
        Input_to_check should be a dict. Expected format:
        {
            "extensions": {
                "<extension_name_1>": {
                    "signingInfo": {
                        "extensionSigned": <true, false>
                    }
                }, ...
        }

        The query parameter specifies the value we want to retrieve from the policy engine.
        Example format for query: "data.agent_extension_policy.extensions_to_download"
        """
        # This method should never be called if policy is not enabled, this would be a developer error.
        if not self.is_policy_enforcement_enabled():
            raise PolicyError("Policy enforcement is disabled, cannot evaluate query.")

        try:
            full_result = self._engine.eval_query(input_to_check, query)
            debug_info = "Rule file is located at '{0}'. \nFull query output: {1}".format(self._engine.rule_file, full_result)
            if full_result is None or full_result == {}:
                raise PolicyError("query returned empty output. Please validate rule file. {0}".format(debug_info))
            result = full_result.get('result')
            if result is None or not isinstance(result, list) or len(result) == 0:
                raise PolicyError("query returned unexpected output with no 'result' list. Please validate rule file. {0}".format(debug_info))
            expressions = result[0].get('expressions')
            if expressions is None or not isinstance(expressions, list) or len(expressions) == 0:
                raise PolicyError("query returned unexpected output with no 'expressions' list. {0}".format(debug_info))
            value = expressions[0].get('value')
            if value is None:
                raise PolicyError("query returned unexpected output, 'value' not found in 'expressions' list. {0}".format(debug_info))
            if value == {}:
                raise PolicyError("query returned expected output format, but value is empty. Please validate policy file '{0}'. '{1}"
                                  .format(self._engine.policy_file, debug_info))
                # TODO: surface as a user error with clear instructions for fixing
            return value
        except Exception as ex:
            msg = "Failed to evaluate query for Regorus policy engine: '{0}'".format(ex)
            self._log_policy(msg=msg, is_success=False)
            raise PolicyError(msg)


class ExtensionPolicyEngine(PolicyEngine):
    def __init__(self, ext_handler):
        """
        This class should be called from handle_ext_handler(). The extension handler should be passed into the
        constructor here.
        """
        self.ext_handler = ext_handler
        # TODO 1: need to remove the hardcoding
        rule_file = "/home/manugunnala/agents/WALinuxAgent/tests/data/policy/agent_extension_policy.rego"
        policy_file = self._get_policy_file()
        super().__init__(rule_file=rule_file, policy_file=policy_file)

    def is_extension_download_allowed(self):
        """
        Evaluate query to determine if extension is allowed to download.
        If policy feature is not enabled, we always return true.

        Download is allowed if:
        - extension is present in allowlist, or allowlist rule is false
        - extension is signed, or signing validation rule is false
        """
        if not self.is_policy_enforcement_enabled():
            return True

        name = self.ext_handler.name
        input_to_check = self._build_input()
        query = "data.agent_extension_policy"
        result = self.evaluate_query(input_to_check=input_to_check, query=query)

        # Check if extension is allowed
        allowlist_result = result.get("extensions_to_download")
        if allowlist_result is None:
            msg = "attribute 'extensions_to_download' not found in query result. Query returned: {1}".format(name, result)
            raise PolicyError(msg)
        ext_allowlist_result = allowlist_result.get(name)
        if ext_allowlist_result is None:
            msg = "extension {0} not found in allowlist query result. Query returned: {1}".format(name, result)
            raise PolicyError(msg)
        is_ext_allowed = ext_allowlist_result.get("downloadAllowed")
        if is_ext_allowed is None:
            msg = "attribute 'downloadAllowed' not found in query result. Query returned: {0}".format(result)
            raise PolicyError(msg)

        # If extension is not allowed, raise error to block installation.
        if not is_ext_allowed:
            msg = "extension {0} is not present in allowlist. Extension installation is blocked.".format(name)
            raise PolicyError(msg)

        # If extension is allowed, then check if signing rule is validated
        signing_result = result.get("extensions_validated")
        if allowlist_result is None:
            msg = "attribute 'extensions_validated' not found in query result. Query returned: {1}".format(name, result)
            raise PolicyError(msg)
        ext_sign_result = signing_result.get(name)
        if ext_sign_result is None:
            msg = "extension {0} not found in signing query result. Query returned: {1}".format(name, result)
            raise PolicyError(msg)
        is_signing_validated = ext_sign_result.get("signingValidated")
        if is_signing_validated is None:
            msg = "attribute 'signingValidated' not found in query result. Query returned: {0}".format(result)
            raise PolicyError(msg)
        if not is_signing_validated:
            msg = "extension {0} is not signed. Extension installation is blocked.".format(name)
            raise PolicyError(msg)
        else:
            return True

    @staticmethod
    def _get_policy_file():
        # return either default or custom policy file
        return "/home/manugunnala/agents/WALinuxAgent/tests/data/policy/agent-extension-default-data.json"

    def _build_input(self):
        """
        Converts extension to input json format:
        {
            "extensions": {
                "Microsoft.Azure.ActiveDirectory.AADSSHLoginForLinux": {}
            }
        }
        """
        name = self.ext_handler.name
        input_dict = {
            "extensions": {}
        }

        if self.ext_handler.encoded_signature is None:
            ext_signed = False
        else:
            ext_signed = True

        ext_info = {
            "signingInfo":
                {
                    "extensionSigned": ext_signed
                }
        }
        input_dict["extensions"][name] = ext_info
        return input_dict



