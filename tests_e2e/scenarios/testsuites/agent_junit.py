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

from typing import Type

#
# Disable those warnings, since 'lisa' is an external, non-standard, dependency
#     E0401: Unable to import 'dataclasses_json' (import-error)
#     E0401: Unable to import 'lisa.notifiers.junit' (import-error)
#     E0401: Unable to import 'lisa' (import-error)
#     E0401: Unable to import 'lisa.messages' (import-error)
from dataclasses import dataclass  # pylint: disable=E0401
from dataclasses_json import dataclass_json  # pylint: disable=E0401
from lisa.notifiers.junit import JUnit  # pylint: disable=E0401
from lisa import schema  # pylint: disable=E0401
from lisa.messages import (  # pylint: disable=E0401
    MessageBase,
    TestResultMessageBase,
)


@dataclass_json()
@dataclass
class AgentJUnitSchema(schema.Notifier):
    path: str = "agent.junit.xml"


class AgentJUnit(JUnit):
    @classmethod
    def type_name(cls) -> str:
        return "agent.junit"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return AgentJUnitSchema

    def _received_message(self, message: MessageBase) -> None:
        if isinstance(message, TestResultMessageBase):
            image = message.information.get('image')
            if image is not None:
                message.name = image
        super()._received_message(message)
