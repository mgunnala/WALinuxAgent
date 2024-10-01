#!/usr/bin/env python3

# Microsoft Azure Linux Agent
#
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

#
# This test disables extension processing on waagent.conf and verifies that extensions are not processed, but the
# agent continues reporting status.
#

import datetime
import json

import pytz
import uuid

from assertpy import assert_that, fail
from typing import Any
from pathlib import Path


from azure.mgmt.compute.models import VirtualMachineInstanceView

from tests_e2e.tests.lib.agent_test import AgentVmTest
from tests_e2e.tests.lib.vm_extension_identifier import VmExtensionIds
from tests_e2e.tests.lib.logging import log
from tests_e2e.tests.lib.ssh_client import SshClient
from tests_e2e.tests.lib.virtual_machine_extension_client import VirtualMachineExtensionClient



class ExtensionPolicy(AgentVmTest):
    class TestCase:
        def __init__(self, extension: VirtualMachineExtensionClient, settings: Any):
            self.extension = extension
            self.settings = settings

    def run(self):
        ssh_client: SshClient = self._context.create_ssh_client()

        # define policy
        # copy policy to tmp folder
        # move from tmp folder to regular expected location

        # test cases
        # - install allowlisted extension
        # - install disallowed extension - validate fail fast and status message
        # - block dependency and validate that dependent extension also fails
        # - 
        #
        # policy = \
        #     {
        #         "policyVersion": "0.1.0",
        #         "extensionPolicies": {
        #             "allowListedExtensionsOnly": True,
        #             "signatureRequired": False,
        #             "extensions": {}
        #         }
        #     }
        # with open("waagent_policy.json", mode='w') as policy_file:
        #     json.dump(policy, policy_file, indent=4)
        #     policy_file.flush()
        #
        #     remote_path = Path("/etc/waagent_policy.json")
        #     local_path = Path(policy_file.name)
        #     ssh_client.copy_to_node(local_path=local_path, remote_path=remote_path)
        #     # output = ssh_client.run_command(f"echo '{policy_str}' > {policy_path}", use_sudo=True)


        # Enable policy enforcement via conf file and place policy file in correct location.
        log.info("")
        log.info("Disabling extension processing on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Extensions.Enabled=n", use_sudo=True)
        log.info("Disable completed:\n%s", output)
        disabled_timestamp: datetime.datetime = datetime.datetime.utcnow() - datetime.timedelta(minutes=60)

        # Prepare test cases
        unique = str(uuid.uuid4())
        test_file = f"waagent-test.{unique}"
        test_cases = [
            ExtensionPolicy.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.CustomScript,
                                              resource_name="CustomScript"),
                {'commandToExecute': f"echo '{unique}' > /tmp/{test_file}"}
            ),
            ExtensionPolicy.TestCase(
                VirtualMachineExtensionClient(self._context.vm, VmExtensionIds.RunCommandHandler,
                                              resource_name="RunCommandHandler"),
                {'source': {'script': f"echo '{unique}' > /tmp/{test_file}"}}
            )
        ]

        for t in test_cases:
            log.info("")
            log.info("Test case: %s", t.extension)
            #
            # Validate that the agent is not processing extensions by attempting to enable extension & checking that
            # provisioning fails fast
            #
            log.info(
                "Executing {0}; the agent should report a VMExtensionProvisioningError without processing the extension"
                .format(t.extension.__str__()))

            try:
                t.extension.enable(settings=t.settings, force_update=True, timeout=6 * 60)
                fail("The agent should have reported an error processing the goal state")
            except Exception as error:
                assert_that("VMExtensionProvisioningError" in str(error)) \
                    .described_as(f"Expected a VMExtensionProvisioningError error, but actual error was: {error}") \
                    .is_true()
                assert_that("Extension will not be processed since extension processing is disabled" in str(error)) \
                    .described_as(
                    f"Error message should communicate that extension will not be processed, but actual error "
                    f"was: {error}").is_true()
                log.info("Goal state processing for {0} failed as expected".format(t.extension.__str__()))

            #
            # Validate the agent did not process the extension by checking it did not execute the extension settings
            #
            output = ssh_client.run_command("dir /tmp", use_sudo=True)
            assert_that(output) \
                .described_as(
                f"Contents of '/tmp' on test VM contains {test_file}. Contents: {output}. \n This indicates "
                f"{t.extension.__str__()} was unexpectedly processed") \
                .does_not_contain(f"{test_file}")
            log.info("The agent did not process the extension settings for {0} as expected".format(t.extension.__str__()))

        #
        # Validate that the agent continued reporting status even if it is not processing extensions
        #
        log.info("")
        instance_view: VirtualMachineInstanceView = self._context.vm.get_instance_view()
        log.info("Instance view of VM Agent:\n%s", instance_view.vm_agent.serialize())
        assert_that(instance_view.vm_agent.statuses).described_as("The VM agent should have exactly 1 status").is_length(1)
        assert_that(instance_view.vm_agent.statuses[0].display_status).described_as("The VM Agent should be ready").is_equal_to('Ready')
        # The time in the status is time zone aware and 'disabled_timestamp' is not; we need to make the latter time zone aware before comparing them
        assert_that(instance_view.vm_agent.statuses[0].time)\
            .described_as("The VM Agent should be have reported status even after extensions were disabled")\
            .is_greater_than(pytz.utc.localize(disabled_timestamp))
        log.info("The VM Agent reported status after extensions were disabled, as expected.")

        #
        # Validate that the agent processes extensions after re-enabling extension processing
        #
        log.info("")
        log.info("Enabling extension processing on the test VM [%s]", self._context.vm.name)
        output = ssh_client.run_command("update-waagent-conf Extensions.Enabled=y", use_sudo=True)
        log.info("Enable completed:\n%s", output)

        for t in test_cases:
            try:
                log.info("")
                log.info("Executing {0}; the agent should process the extension".format(t.extension.__str__()))
                t.extension.enable(settings=t.settings, force_update=True, timeout=15 * 60)
                log.info("Goal state processing for {0} succeeded as expected".format(t.extension.__str__()))
            except Exception as error:
                fail(f"Unexpected error while processing {t.extension.__str__()} after re-enabling extension "
                     f"processing: {error}")


if __name__ == "__main__":
    ExtensionPolicy.run_from_command_line()