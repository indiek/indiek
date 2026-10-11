"""Copyright 2026 Adrian Ernesto Radillo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from indiek.events import create_meta_event, create_meta_vertex, write_meta_event
from indiek.models import MetaEventType, Tag


def run(*, tag_name, tag_description, curr_public_key, curr_signing_key, archive_index):
    # Create a node in the dual network
    body = create_meta_vertex(
        tag=Tag(
            name=tag_name,
            description=tag_description,
            event_type=MetaEventType.CREATE_EDGE_TAG,
        )
    )
    event = create_meta_event(
        body=body, public_key=curr_public_key, archive_idx=archive_index
    )
    write_meta_event(event, curr_signing_key, archive_index)
    return str(body.node_id)
