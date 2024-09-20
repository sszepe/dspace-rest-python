import pytest

from ..models import (
    HALResource,
    AddressableHALResource,
    ExternalDataObject,
    DSpaceObject,
    SimpleDSpaceObject,
    Item,
    Collection,
    Bundle,
    Bitstream,
    User,
    Community,
    Group,
    InProgressSubmission,
    WorkspaceItem,
    EntityType,
    RelationshipType,
)


def test_halresource_init_with_api_resource():
    # Mock API resource JSON
    api_resource = {
        "type": "exampleType",
        "_links": {
            "self": {"href": "http://example.com"},
            "other": {"href": "http://example.org"},
        },
    }

    # Initialize HALResource with the mock API resource
    resource = HALResource(api_resource=api_resource)

    # Assert that the type and links are set correctly
    assert resource.type == "exampleType"
    assert resource.links == api_resource["_links"]


def test_halresource_init_without_api_resource():
    resource = HALResource()

    assert resource.type is None
    assert resource.links == {}


def test_halresource_init_with_partial_api_resource():
    api_resource = {"type": "partialType"}

    resource = HALResource(api_resource=api_resource)

    assert resource.type == "partialType"
    assert resource.links == {"self": {"href": None}}


def test_addressablehalresource_init_with_api_resource():
    # Mock API resource JSON including an "id"
    api_resource = {
        "type": "exampleType",
        "id": "123",
        "_links": {"self": {"href": "http://example.com"}},
    }

    resource = AddressableHALResource(api_resource=api_resource)

    # Assert that the id, type, and links are set correctly
    assert resource.id == "123"
    assert resource.type == "exampleType"
    assert resource.links == api_resource["_links"]


def test_addressablehalresource_init_without_id():
    # Mock API resource JSON without an "id"
    api_resource = {
        "type": "exampleType",
        "_links": {"self": {"href": "http://example.com"}},
    }

    resource = AddressableHALResource(api_resource=api_resource)

    # Assert that the id is None and other attributes are set correctly
    assert resource.id is None
    assert resource.type == "exampleType"
    assert resource.links == api_resource["_links"]


def test_addressablehalresource_as_dict():
    # Initialize AddressableHALResource with a specific "id"
    resource = AddressableHALResource(api_resource={"id": "456"})

    # Assert that as_dict returns the correct dictionary representation
    assert resource.as_dict() == {"id": "456"}


def test_externaldataobject_init_with_api_resource():
    # Mock API resource JSON including various attributes
    api_resource = {
        "id": "uniqueID",
        "display": "Test Display",
        "value": "Test Value",
        "externalSource": "Test Source",
        "metadata": {"dc.title": ["Test Title"], "dc.creator": ["Creator Name"]},
    }

    obj = ExternalDataObject(api_resource=api_resource)

    # Assert that attributes are set correctly
    assert obj.id == "uniqueID"
    assert obj.display == "Test Display"
    assert obj.value == "Test Value"
    assert obj.externalSource == "Test Source"
    assert obj.metadata == api_resource["metadata"]


def test_externaldataobject_init_without_api_resource():
    # Initialize ExternalDataObject without an API resource
    obj = ExternalDataObject()

    # Assert that attributes have their default values
    assert obj.id is None
    assert obj.display is None
    assert obj.value is None
    assert obj.externalSource is None
    assert obj.metadata == {}


def test_externaldataobject_get_metadata_values():
    # Initialize ExternalDataObject with specific metadata
    metadata = {
        "dc.title": ["Test Title 1", "Test Title 2"],
        "dc.creator": ["Creator Name"],
    }
    obj = ExternalDataObject(api_resource={"metadata": metadata})

    # Test retrieval of metadata values
    title_values = obj.get_metadata_values("dc.title")
    assert title_values == ["Test Title 1", "Test Title 2"]

    # Test retrieval of metadata values for a field not present
    subject_values = obj.get_metadata_values("dc.subject")
    assert subject_values == []


def test_externaldataobject_metadata_independence():
    # Initialize two ExternalDataObjects, one with metadata and one without
    obj1 = ExternalDataObject(api_resource={"metadata": {"dc.title": ["Title 1"]}})
    obj2 = ExternalDataObject()

    # Modifying obj2's metadata should not affect obj1's metadata
    obj2.metadata["dc.title"] = ["Title 2"]
    assert obj1.get_metadata_values("dc.title") == ["Title 1"]
    assert obj2.get_metadata_values("dc.title") == ["Title 2"]


def test_dspace_object_initialization_with_api_resource():
    # Mock API resource JSON
    api_resource = {
        "uuid": "1234",
        "name": "Test Name",
        "handle": "123456789/10",
        "metadata": {"dc.title": [{"value": "Test Title"}]},
        "type": "item",
        "_links": {"self": {"href": "http://example.com"}},
    }

    obj = DSpaceObject(api_resource=api_resource)

    # Assert that attributes are set correctly
    assert obj.uuid == "1234"
    assert obj.name == "Test Name"
    assert obj.handle == "123456789/10"
    assert obj.metadata == {"dc.title": [{"value": "Test Title"}]}
    assert obj.type == "item"
    assert obj.links == {"self": {"href": "http://example.com"}}


def test_dspace_object_as_dict():
    obj = DSpaceObject(api_resource={"uuid": "1234", "name": "Test Name"})
    obj_dict = obj.as_dict()

    # Assert that the dictionary representation is correct
    expected_dict = {
        "uuid": "1234",
        "name": "Test Name",
        "handle": None,
        "metadata": {},
        "lastModified": None,
        "type": None,
    }

    assert obj_dict == expected_dict


def test_dspace_object_to_json():
    # Initialize DSpaceObject with a specific UUID and no metadata
    # and test the JSON representation
    obj = DSpaceObject(api_resource={"uuid": "1234"})
    json_str = obj.to_json()
    assert '"uuid": "1234"' in json_str
    assert '"metadata": {}' in json_str


def test_dspace_object_to_json_pretty():
    # Initialize DSpaceObject with a specific UUID and no metadata
    # and test the pretty JSON representation
    obj = DSpaceObject(api_resource={"uuid": "1234"})
    json_pretty_str = obj.to_json_pretty()
    assert '"uuid": "1234"' in json_pretty_str
    assert '"metadata": {}' in json_pretty_str
    assert "    " in json_pretty_str  # Check for indentation


@pytest.fixture
def dso_instance():
    dso = DSpaceObject()
    dso.uuid = "test-uuid"
    dso.name = "Test Name"
    dso.handle = "123456789/10"
    dso.metadata = {"dc.title": "Test Title"}
    dso.type = "testType"
    dso.links = {"self": {"href": "http://example.com"}}
    return dso


def test_dspaceobject_init_from_dso(dso_instance):
    # Initialize a new DSpaceObject from an existing one
    new_dso = DSpaceObject(dso=dso_instance)

    # Verify that the links are correctly copied
    assert new_dso.links == dso_instance.links

    # Verify that the new object's attributes are populated based on the `dso_instance`'s `as_dict` return value
    dso_dict = dso_instance.as_dict()
    for key, value in dso_dict.items():
        assert getattr(new_dso, key) == value, f"Attribute {key} did not match"


def test_dspaceobject_add_metadata_new_field():
    dso = DSpaceObject()
    dso.add_metadata(field="dc.title", value="Test Title", language="en")

    assert "dc.title" in dso.metadata
    assert dso.metadata["dc.title"][0]["value"] == "Test Title"
    assert dso.metadata["dc.title"][0]["language"] == "en"


def test_dspaceobject_add_metadata_different_place():
    dso = DSpaceObject()
    dso.add_metadata(field="dc.creator", value="Creator One", place=0)
    dso.add_metadata(field="dc.creator", value="Creator Two", place=1)

    assert len(dso.metadata["dc.creator"]) == 2
    assert dso.metadata["dc.creator"][1]["value"] == "Creator Two"


def test_dspaceobject_add_metadata_duplicate_place():
    dso = DSpaceObject()
    dso.add_metadata(field="dc.contributor", value="Contributor One", place=0)
    dso.add_metadata(
        field="dc.contributor", value="Contributor Two", place=0
    )  # Attempt to add with duplicate place

    assert dso.metadata["dc.contributor"][1]["place"] is None


def test_dspaceobject_add_metadata_missing_mandatory_fields():
    dso = DSpaceObject()
    original_metadata = dso.metadata.copy()

    dso.add_metadata(field=None, value="Missing Field")
    dso.add_metadata(field="dc.description", value=None)

    assert dso.metadata == original_metadata  # Metadata remains unchanged


def test_dspaceobject_clear_metadata_all():
    dso = DSpaceObject()
    dso.metadata = {
        "dc.title": [{"value": "Test Title"}],
        "dc.creator": [{"value": "Creator Name"}],
    }
    dso.clear_metadata()
    assert dso.metadata == {}, "All metadata should be cleared"


def test_dspaceobject_clear_metadata_specific_field():
    dso = DSpaceObject()
    dso.metadata = {
        "dc.title": [{"value": "Test Title"}],
        "dc.creator": [{"value": "Creator Name"}],
    }
    dso.clear_metadata(field="dc.title")
    assert "dc.title" not in dso.metadata, "Specific field should be removed"
    assert "dc.creator" in dso.metadata, "Other fields should remain"


def test_dspaceobject_clear_metadata_specific_value():
    dso = DSpaceObject()
    dso.metadata = {"dc.creator": [{"value": "Creator One"}, {"value": "Creator Two"}]}
    dso.clear_metadata(field="dc.creator", value={"value": "Creator One"})
    assert dso.metadata["dc.creator"] == [
        {"value": "Creator Two"}
    ], "Specific value should be removed"


def test_dspaceobject_clear_metadata_non_existing_field():
    dso = DSpaceObject()
    dso.metadata = {"dc.title": [{"value": "Test Title"}]}
    original_metadata = dso.metadata.copy()
    dso.clear_metadata(field="dc.creator")
    assert (
        dso.metadata == original_metadata
    ), "Non-existing field removal should not change metadata"


def test_dspaceobject_clear_metadata_non_existing_value():
    dso = DSpaceObject()
    dso.metadata = {"dc.creator": [{"value": "Creator Name"}]}
    original_metadata = dso.metadata.copy()
    dso.clear_metadata(field="dc.creator", value={"value": "Non-existing Creator"})
    assert (
        dso.metadata == original_metadata
    ), "Non-existing value removal should not change metadata"


def test_dspaceobject_simple_dspace_object_inheritance():
    api_resource = {
        "uuid": "4321",
        "name": "Simple Test Name",
        "handle": "987654321/10",
        "metadata": {"dc.description": [{"value": "Simple Test Description"}]},
        "type": "collection",
    }

    simple_obj = SimpleDSpaceObject(api_resource=api_resource)

    # Check if the simple object correctly inherits properties from DSpaceObject
    assert simple_obj.uuid == "4321"
    assert simple_obj.name == "Simple Test Name"
    assert simple_obj.handle == "987654321/10"
    assert simple_obj.metadata == {
        "dc.description": [{"value": "Simple Test Description"}]
    }
    assert simple_obj.type == "collection"


def test_item_initialization_with_api_resource():
    api_resource = {
        "uuid": "12345",
        "inArchive": True,
        "discoverable": True,
        "withdrawn": False,
        "metadata": {"dc.title": [{"value": "Test Item Title"}]},
    }
    item = Item(api_resource=api_resource)

    assert item.uuid == "12345"
    assert item.inArchive is True
    assert item.discoverable is True
    assert item.withdrawn is False
    assert item.metadata == {"dc.title": [{"value": "Test Item Title"}]}


def test_item_initialization_defaults():
    item = Item()

    assert item.inArchive is False  # Default when not specified
    assert item.discoverable is False  # Default when not specified
    assert item.withdrawn is False  # Default when not specified


def test_item_as_dict():
    item = Item(api_resource={"uuid": "12345", "discoverable": True})
    item_dict = item.as_dict()

    assert item_dict == {
        "uuid": "12345",
        "name": None,  # Assuming default None from DSpaceObject
        "handle": None,
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "item",
        "inArchive": True,  # Default value when not specified
        "discoverable": True,
        "withdrawn": False,  # Default value when not specified
    }


def test_item_from_dso():
    dso = DSpaceObject(
        api_resource={
            "uuid": "67890",
            "metadata": {"dc.creator": [{"value": "Original Creator"}]},
        }
    )
    item = Item.from_dso(dso)

    assert item.uuid == "67890"
    assert item.metadata == {"dc.creator": [{"value": "Original Creator"}]}
    assert item.inArchive is False
    assert item.discoverable is False
    assert item.withdrawn is False


def test_item_get_metadata_values_existing_field():
    item = Item()
    item.metadata = {
        "dc.creator": [{"value": "Creator One"}, {"value": "Creator Two"}],
        "dc.title": [{"value": "Test Title"}],
    }
    values = item.get_metadata_values("dc.creator")

    expected_values = [{"value": "Creator One"}, {"value": "Creator Two"}]
    assert values == expected_values, "Should return all values for 'dc.creator'"


def test_item_get_metadata_values_non_existing_field():
    item = Item()
    item.metadata = {"dc.title": [{"value": "Test Title"}]}
    values = item.get_metadata_values("dc.subject")

    assert values == [], "Should return an empty list for a non-existing field"


def test_item_get_metadata_values_empty_metadata():
    item = Item()  # Assume metadata is empty by default
    values = item.get_metadata_values("dc.creator")

    assert values == [], "Should return an empty list when metadata is empty"


def test_community_initialization():
    community = Community(api_resource={"uuid": "community123"})
    assert community.type == "community", "Type should be 'community'"
    assert community.uuid == "community123", "UUID should be 'community123'"


def test_community_as_dict():
    community = Community(api_resource={"uuid": "community123"})
    community_dict = community.as_dict()

    expected_dict = {
        "uuid": "community123",
        "name": None,  # Assuming default None from DSpaceObject
        "handle": None,  # Assuming default None from DSpaceObject
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "community",
    }

    assert community_dict == expected_dict


def test_collection_initialization():
    api_resource = {
        "uuid": "collection123",
        "name": "Test Collection",
        "metadata": {"dc.description": [{"value": "A test collection"}]},
    }
    collection = Collection(api_resource=api_resource)

    assert collection.uuid == "collection123"
    assert collection.name == "Test Collection"
    assert collection.type == "collection"
    assert collection.metadata == {"dc.description": [{"value": "A test collection"}]}


def test_collection_as_dict():
    collection = Collection(
        api_resource={"uuid": "collection123", "name": "Test Collection"}
    )
    collection_dict = collection.as_dict()

    expected_dict = {
        "uuid": "collection123",
        "name": "Test Collection",
        "handle": None,  # Assuming default None from DSpaceObject
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "collection",
    }

    assert collection_dict == expected_dict


def test_bundle_initialization():
    api_resource = {
        "uuid": "bundle123",
        "name": "Test Bundle",
        "metadata": {"dc.title": [{"value": "A test bundle"}]},
    }
    bundle = Bundle(api_resource=api_resource)

    assert bundle.uuid == "bundle123"
    assert bundle.name == "Test Bundle"
    assert bundle.type == "bundle"
    assert bundle.metadata == {"dc.title": [{"value": "A test bundle"}]}


def test_bundle_as_dict():
    bundle = Bundle(api_resource={"uuid": "bundle123", "name": "Test Bundle"})
    bundle_dict = bundle.as_dict()

    expected_dict = {
        "uuid": "bundle123",
        "name": "Test Bundle",
        "handle": None,  # Assuming default None from DSpaceObject
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "bundle",
    }

    assert bundle_dict == expected_dict


def test_bitstream_initialization():
    api_resource = {
        "uuid": "bitstream123",
        "bundleName": "ORIGINAL",
        "sizeBytes": 1024,
        "checkSum": {
            "checkSumAlgorithm": "MD5",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
        },
        "sequenceId": 1,
    }
    bitstream = Bitstream(api_resource=api_resource)

    assert bitstream.uuid == "bitstream123"
    assert bitstream.type == "bitstream"
    assert bitstream.bundleName == "ORIGINAL"
    assert bitstream.sizeBytes == 1024
    assert bitstream.checkSum == {
        "checkSumAlgorithm": "MD5",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
    }
    assert bitstream.sequenceId == 1


def test_bitstream_default_values():
    api_resource = {
        "uuid": "bitstream123",
        # Assume "bundleName", "sizeBytes", "checkSum", and "sequenceId" are not provided
    }
    bitstream = Bitstream(api_resource=api_resource)

    assert bitstream.uuid == "bitstream123"
    assert bitstream.bundleName is None
    assert bitstream.sizeBytes is None
    assert bitstream.checkSum == {
        "checkSumAlgorithm": "MD5",
        "value": None,
    }  # Default value
    assert bitstream.sequenceId is None


def test_bitstream_as_dict():
    api_resource = {
        "uuid": "bitstream123",
        "bundleName": "ORIGINAL",
        "sizeBytes": 1024,
        "checkSum": {
            "checkSumAlgorithm": "MD5",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
        },
        "sequenceId": 1,
    }
    bitstream = Bitstream(api_resource=api_resource)
    bitstream_dict = bitstream.as_dict()

    expected_dict = {
        "uuid": "bitstream123",
        "name": None,  # Assuming default None from DSpaceObject
        "handle": None,
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "bitstream",
        "bundleName": "ORIGINAL",
        "sizeBytes": 1024,
        "checkSum": {
            "checkSumAlgorithm": "MD5",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
        },
        "sequenceId": 1,
    }

    assert bitstream_dict == expected_dict


def test_group_initialization():
    api_resource = {
        "uuid": "group123",
        "name": "Test Group",
        "permanent": True,
    }
    group = Group(api_resource=api_resource)

    assert group.uuid == "group123"
    assert group.type == "group"
    assert group.name == "Test Group"
    assert group.permanent is True


def test_group_default_values():
    api_resource = {
        "uuid": "group123",
        # Assume "name" and "permanent" are not provided
    }
    group = Group(api_resource=api_resource)

    assert group.uuid == "group123"
    assert group.name is None  # Default value when not specified
    assert group.permanent is False  # Default value when not specified


def test_group_as_dict():
    api_resource = {
        "uuid": "group123",
        "name": "Test Group",
        "permanent": True,
    }
    group = Group(api_resource=api_resource)
    group_dict = group.as_dict()

    expected_dict = {
        "uuid": "group123",
        "name": "Test Group",
        "handle": None,  # Assuming default None from DSpaceObject
        "metadata": {},  # Empty as not provided but initialized
        "lastModified": None,
        "type": "group",
        "permanent": True,
    }

    assert group_dict == expected_dict


def test_user_initialization():
    api_resource = {
        "uuid": "user123",
        "name": "Test User",
        "netid": "testuser",
        "lastActive": "2023-01-01T12:00:00",
        "canLogIn": True,
        "email": "testuser@example.com",
        "requireCertificate": False,
        "selfRegistered": True,
    }
    user = User(api_resource=api_resource)

    assert user.uuid == "user123"
    assert user.type == "user"
    assert user.name == "Test User"
    assert user.netid == "testuser"
    assert user.lastActive == "2023-01-01T12:00:00"
    assert user.canLogIn is True
    assert user.email == "testuser@example.com"
    assert user.requireCertificate is False
    assert user.selfRegistered is True


def test_user_default_values():
    api_resource = {
        "uuid": "user123",
        # Assume specific attributes are not provided
    }
    user = User(api_resource=api_resource)

    assert user.uuid == "user123"
    assert user.name is None
    assert user.netid is None
    assert user.lastActive is None
    assert user.canLogIn is False
    assert user.email is None
    assert user.requireCertificate is False
    assert user.selfRegistered is False


def test_user_as_dict():
    api_resource = {
        "uuid": "user123",
        "name": "Test User",
        "netid": "testuser",
        "canLogIn": True,
    }
    user = User(api_resource=api_resource)
    user_dict = user.as_dict()

    expected_dict = {
        "uuid": "user123",
        "name": "Test User",
        "netid": "testuser",
        "lastActive": None,  # Default value when not specified
        "canLogIn": True,
        "email": None,  # Default value when not specified
        "requireCertificate": False,  # Default value when not specified
        "selfRegistered": False,  # Default value when not specified
        # Plus any inherited properties initialized to their default states
    }

    # Only compare keys that are expected to be in both dictionaries
    for key in expected_dict:
        assert user_dict.get(key) == expected_dict[key]


def test_in_progress_submission_initialization():
    api_resource = {
        "lastModified": "2023-03-10T12:00:00Z",
        "step": "review",
        "sections": {"basic": {"title": "Submission Title"}},
        "type": "inProgressSubmission",
    }
    submission = InProgressSubmission(api_resource)

    assert submission.lastModified == "2023-03-10T12:00:00Z"
    assert submission.step == "review"
    assert submission.sections == {"basic": {"title": "Submission Title"}}
    assert submission.type == "inProgressSubmission"


def test_in_progress_submission_as_dict():
    api_resource = {
        "lastModified": "2023-03-10T12:00:00Z",
        "step": "review",
        "sections": {"basic": {"title": "Submission Title"}},
        "type": "inProgressSubmission",
    }
    submission = InProgressSubmission(api_resource)
    submission_dict = submission.as_dict()

    expected_dict = {
        "id": None,  # Assuming default None from DSpaceObject
        "lastModified": "2023-03-10T12:00:00Z",
        "step": "review",
        "sections": {"basic": {"title": "Submission Title"}},
        "type": "inProgressSubmission",
    }

    assert submission_dict == expected_dict


def test_workspace_item_initialization():
    api_resource = {
        "lastModified": "2023-04-01T12:00:00Z",
        "step": "submission",
        "sections": {"identification": {"title": "Test Submission"}},
        "type": "workspaceItem",
    }
    workspace_item = WorkspaceItem(api_resource=api_resource)

    assert workspace_item.lastModified == "2023-04-01T12:00:00Z"
    assert workspace_item.step == "submission"
    assert workspace_item.sections == {"identification": {"title": "Test Submission"}}
    assert workspace_item.type == "workspaceItem"


def test_workspace_item_as_dict():
    api_resource = {
        "lastModified": "2023-04-01T12:00:00Z",
        "step": "submission",
        "sections": {"identification": {"title": "Test Submission"}},
        "type": "workspaceItem",
    }
    workspace_item = WorkspaceItem(api_resource=api_resource)
    workspace_item_dict = workspace_item.as_dict()

    expected_dict = {
        "id": None,  # Assuming default None from DSpaceObject
        "lastModified": "2023-04-01T12:00:00Z",
        "step": "submission",
        "sections": {"identification": {"title": "Test Submission"}},
        "type": "workspaceItem",
    }

    assert (
        workspace_item_dict == expected_dict
    ), "as_dict should accurately reflect workspace item attributes"


def test_entity_type_initialization_only_type():
    api_resource = {
        "type": "testType",
    }
    entity_type = EntityType(api_resource=api_resource)

    assert entity_type.type == "testType"
    assert entity_type.links == {"self": {"href": None}}


def test_entity_type_initialization_only_label():
    api_resource = {
        "label": "Test Label",
    }
    entity_type = EntityType(api_resource=api_resource)

    assert entity_type.type is None
    assert entity_type.links == {"self": {"href": None}}


def test_entity_type_initialization_full():
    api_resource = {
        "type": "testType",
        "_links": {
            "self": {"href": "http://example.com"},
            "other": {"href": "http://example.org"},
        },
    }
    entity_type = EntityType(api_resource=api_resource)

    assert entity_type.type == "testType"
    assert entity_type.links == api_resource["_links"]
