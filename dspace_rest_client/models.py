# This software is licenced under the BSD 3-Clause licence
# available at https://opensource.org/licenses/BSD-3-Clause
# and described in the LICENSE.txt file in the root of this project

"""
DSpace REST API client library models.
Intended to make interacting with DSpace in Python 3 easier, particularly
when creating, updating, retrieving and deleting DSpace Objects.

@author Kim Shepherd <kim@shepherd.nz>
"""
import code
import json
import logging

import requests
from requests import Request
import os
from uuid import UUID

__all__ = [
    "DSpaceObject",
    "HALResource",
    "ExternalDataObject",
    "SimpleDSpaceObject",
    "Community",
    "Collection",
    "Item",
    "Bundle",
    "Bitstream",
    "User",
    "Group",
]


class HALResource:
    """
    Base class to represent HAL+JSON API resources
    """

    links = {}
    type = None

    def __init__(self, api_resource=None):
        """
        Default constructor
        @param api_resource: optional API resource (JSON) from a GET response or successful POST can populate instance
        """
        if api_resource is not None:
            if "type" in api_resource:
                self.type = api_resource["type"]
            if "_links" in api_resource:
                self.links = api_resource["_links"].copy()
            else:
                self.links = {"self": {"href": None}}


class AddressableHALResource(HALResource):
    """
    Represents a HAL+JSON API resource that has an addressable ID.

    This class extends the `HALResource` base class, inheriting its functionality
    to manage HAL+JSON resources and adds an `id` attribute to represent a unique
    identifier for the resource. It can initialize its state from an API resource
    provided in the constructor and offers a method to return the resource data
    as a dictionary.
    """
    id = None

    def __init__(self, api_resource=None):
        super().__init__(api_resource)
        if api_resource is not None:
            if "id" in api_resource:
                self.id = api_resource["id"]

    def as_dict(self):
        return {"id": self.id}


class ExternalDataObject(HALResource):
    """
    Generic External Data Object as configured in DSpace's external data providers framework
    """

    id = None
    display = None
    value = None
    externalSource = None
    metadata = {}

    def __init__(self, api_resource=None):
        """
        Default constructor
        @param api_resource: optional API resource (JSON) from a GET response or successful POST can populate instance
        """
        super().__init__(api_resource)

        self.metadata = {}

        if api_resource is not None:
            if "id" in api_resource:
                self.id = api_resource["id"]
            if "display" in api_resource:
                self.display = api_resource["display"]
            if "value" in api_resource:
                self.value = api_resource["value"]
            if "externalSource" in api_resource:
                self.externalSource = api_resource["externalSource"]
            if "metadata" in api_resource:
                self.metadata = api_resource["metadata"].copy()

    def get_metadata_values(self, field):
        """
        Return metadata values as simple list of strings
        @param field: DSpace field, eg. dc.creator
        @return: list of strings
        """
        values = []
        if field in self.metadata:
            values = self.metadata[field]
        return values


class DSpaceObject(HALResource):
    """
    Base class to represent DSpaceObject API resources
    The variables here are present in an _embedded response and the ones required for POST / PUT / PATCH
    operations are included in the dict returned by asDict(). Implements toJSON() as well.
    This class can be used on its own but is generally expected to be extended by other types: Item, Bitstream, etc.
    """

    uuid = None
    name = None
    handle = None
    metadata = {}
    lastModified = None
    type = None
    parent = None

    def __init__(self, api_resource=None, dso=None):
        """
        Default constructor
        @param api_resource: optional API resource (JSON) from a GET response or successful POST can populate instance
        """
        super().__init__(api_resource)
        self.type = None
        self.metadata = {}

        if dso is not None:
            api_resource = dso.as_dict()
            self.links = dso.links.copy()
        if api_resource is not None:
            if "id" in api_resource:
                self.id = api_resource["id"]
            if "uuid" in api_resource:
                self.uuid = api_resource["uuid"]
            if "type" in api_resource:
                self.type = api_resource["type"]
            if "name" in api_resource:
                self.name = api_resource["name"]
            if "handle" in api_resource:
                self.handle = api_resource["handle"]
            if "metadata" in api_resource:
                self.metadata = api_resource["metadata"].copy()
            # Python interprets _ prefix as private so for now, renaming this and handling it separately
            # alternatively - each item could implement getters, or a public method to return links
            if "_links" in api_resource:
                self.links = api_resource["_links"].copy()

    def add_metadata(
        self, field, value, language=None, authority=None, confidence=-1, place=None
    ):
        """
        Add metadata to a DSO. This is performed on the local object only, it is not an API operation (see patch)
        This is useful when constructing new objects for ingest.
        When doing simple changes like "retrieve a DSO, add some metadata, update" then it is best to use a patch
        operation, not this clas method. See
        :param field:
        :param value:
        :param language:
        :param authority:
        :param confidence:
        :param place:
        :return:
        """
        if field is None or value is None:
            return
        if field in self.metadata:
            values = self.metadata[field]
            # Ensure we don't accidentally duplicate place value. If this place already exists, the user
            # should use a patch operation or we should allow another way to re-order / re-calc place?
            # For now, we'll just set place to none if it matches an existing place
            for v in values:
                if v["place"] == place:
                    place = None
                    break
        else:
            values = []
        values.append(
            {
                "value": value,
                "language": language,
                "authority": authority,
                "confidence": confidence,
                "place": place,
            }
        )
        self.metadata[field] = values

        # Return this as an easy way for caller to inspect or use
        return self

    def clear_metadata(self, field=None, value=None):
        """
        Clear metadata from the DSO (Digital Object).

        This method allows for the removal of metadata from the local object's `metadata` dictionary.
        It can clear all metadata, or selectively clear specific metadata based on the field and optionally, the value.
        :param field: The metadata field to clear. If `None`, all metadata will be cleared.
        :param value: The metadata value to clear. If `None`, all values for the field will be cleared.
        """
        if field is None:
            self.metadata = {}
        elif field in self.metadata:
            if value is None:
                self.metadata.pop(field)
            else:
                updated = []
                for v in self.metadata[field]:
                    if v != value:
                        updated.append(v)
                self.metadata[field] = updated

    def as_dict(self):
        """
        Return custom dict of this DSpaceObject with specific attributes included (no _links, etc.)
        @return: dict of this DSpaceObject for API use
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "handle": self.handle,
            "metadata": self.metadata,
            "lastModified": self.lastModified,
            "type": self.type,
        }

    def to_json(self):
        """
        Return JSON representation of this DSpaceObject
        """
        return json.dumps(
            self, default=lambda o: o.__dict__, sort_keys=True, indent=None
        )

    def to_json_pretty(self):
        """
        Return pretty-printed JSON representation of this DSpaceObject
        """
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class SimpleDSpaceObject(DSpaceObject):
    """
    Objects that share similar simple API methods eg. PUT update for full metadata replacement, can have handles, etc.
    By default this is Item, Community, Collection classes
    """


class Item(SimpleDSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and functions for items
    
    An `Item` is the primary digital object in DSpace, containing metadata, bundles / bitstreams.
    This class models an `Item` with attributes related to its archival status, discoverability, 
    and withdrawal status. It also provides methods for interacting with the item's metadata.

    Attributes:
    ----------
    type : str
        The type of the object, always set to "item" for instances of this class.
    inArchive : bool
        A boolean indicating whether the item is currently in the archive (`True` by default).
    discoverable : bool
        A boolean indicating whether the item is discoverable in public searches (`False` by default).
    withdrawn : bool
        A boolean indicating whether the item has been withdrawn (`False` by default).
    metadata : dict
        A dictionary holding the metadata fields for the item.

    Methods:
    -------
    __init__(api_resource=None, dso=None):
        Initializes the `Item` object. If an API resource or another `DSpaceObject` is provided, it populates 
        the item's attributes accordingly. Calls the `SimpleDSpaceObject` constructor to handle common attributes.
    
    get_metadata_values(field):
        Returns a list of metadata values for a specified metadata field. If the field doesn't exist, 
        it returns an empty list.
    
    as_dict():
        Returns a dictionary representation of the `Item`, combining fields from the parent `SimpleDSpaceObject` 
        with item-specific attributes like `inArchive`, `discoverable`, and `withdrawn`.

    from_dso(cls, dso):
        Class method that creates a new `Item` object from an existing `DSpaceObject`. It copies over all 
        attributes from the provided `DSpaceObject` to the new `Item`.
    """

    type = "item"
    inArchive = False
    discoverable = False
    withdrawn = False
    metadata = {}

    def __init__(self, api_resource=None, dso=None):
        """
        Default constructor. Call DSpaceObject init then set item-specific attributes
        @param api_resource: API result object to use as initial data
        """
        if dso is not None:
            api_resource = dso.as_dict()
            super().__init__(dso=dso)
        else:
            super().__init__(api_resource)

        if api_resource is not None:
            self.type = "item"
            self.inArchive = (
                api_resource["inArchive"] if "inArchive" in api_resource else True
            )
            self.discoverable = (
                api_resource["discoverable"]
                if "discoverable" in api_resource
                else False
            )
            self.withdrawn = (
                api_resource["withdrawn"] if "withdrawn" in api_resource else False
            )

    def get_metadata_values(self, field):
        """
        Return metadata values as simple list of strings
        @param field: DSpace field, eg. dc.creator
        @return: list of strings
        """
        values = []
        if field in self.metadata:
            values = self.metadata[field]
        return values

    def as_dict(self):
        """
        Return a dict representation of this Item, based on super with item-specific attributes added
        @return: dict of Item for API use
        """
        dso_dict = super().as_dict()
        item_dict = {
            "inArchive": self.inArchive,
            "discoverable": self.discoverable,
            "withdrawn": self.withdrawn,
        }
        return {**dso_dict, **item_dict}

    @classmethod
    def from_dso(cls, dso: DSpaceObject):
        # Create new Item and copy everything over from this dso
        item = cls()
        for key, value in dso.__dict__.items():
            item.__dict__[key] = value
        return item


class Community(SimpleDSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and functions for communities
    
    A `Community` is a top-level container in the DSpace hierarchy used for  logical 
    grouping. Communities contain collections, which in turn contain items.

    Attributes:
    ----------
    type : str
        The type of the object, always set to "community" for instances of this class.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the `Community` object. Calls the initializer of `SimpleDSpaceObject` 
        to handle common attributes, then sets the `type` attribute specific to a community.
    
    as_dict():
        Returns a dictionary representation of the `Community` object, combining the fields 
        from the parent `SimpleDSpaceObject`. This can be extended to include community-specific 
        attributes as needed.
    """

    type = "community"

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set item-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "community"

    def as_dict(self):
        """
        Return a dict representation of this Community, based on super with community-specific attributes added
        @return: dict of Item for API use
        """
        dso_dict = super().as_dict()
        # TODO: More community-specific stuff
        community_dict = {}
        return {**dso_dict, **community_dict}


class Collection(SimpleDSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and functions for collections
    
    A `Collection` is a container in DSpace that holds items. Collections are grouped 
    under communities, and each collection may contain items of e aspecific entity type,
    e.g., publications, projects, etc.

    Attributes:
    ----------
    type : str
        The type of the object, always set to "collection" for instances of this class.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the `Collection` object. Calls the initializer of `SimpleDSpaceObject` 
        to handle common attributes, then sets the `type` attribute specific to a collection.
    
    as_dict():
        Returns a dictionary representation of the `Collection` object, combining the fields 
        from the parent `SimpleDSpaceObject`. This can be extended to include collection-specific 
        attributes as needed.
    """

    type = "collection"

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set collection-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "collection"

    def as_dict(self):
        dso_dict = super().as_dict()
        """
        Return a dict representation of this Collection, based on super with collection-specific attributes added
        @return: dict of Item for API use
        """
        collection_dict = {}
        return {**dso_dict, **collection_dict}


class Bundle(DSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and functions for bundles
    
    A `Bundle` is a collection of related `Bitstreams` in DSpace. Bundles group bitstreams 
    together, typically used to organize content like different renditions or formats of a  
    file (e.g., original file, thumbnail, etc.). This class extends `DSpaceObject` to add 
    bundle-specific attributes and functionality.

    Attributes:
    ----------
    type : str
        The type of the object, always set to "bundle" for instances of this class.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the `Bundle` object. Calls the initializer of `DSpaceObject` to handle common 
        attributes, then sets the `type` attribute to "bundle".

    as_dict():
        Returns a dictionary representation of the `Bundle` object, combining the fields from the 
        parent `DSpaceObject`. This is useful for API operations or debugging.
    """

    type = "bundle"

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set bundle-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "bundle"

    def as_dict(self):
        """
        Return a dict representation of this Bundle, based on super with bundle-specific attributes added
        @return: dict of Bundle for API use
        """
        dso_dict = super().as_dict()
        bundle_dict = {}
        return {**dso_dict, **bundle_dict}


class Bitstream(DSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and functions for bundles
    
    A `Bitstream` is a single file in DSpace. It contains additional metadata that describes 
    its file-specific attributes such as size, checksum, and the bundle to which it belongs.
    This class extends `DSpaceObject` to add bitstream-specific attributes and functionality.

    Attributes:
    ----------
    type : str
        The type of the object, always set to "bitstream" for instances of this class.
    bundleName : str or None
        The name of the bundle to which this bitstream belongs.
    sizeBytes : int or None
        The size of the bitstream in bytes.
    checkSum : dict
        A dictionary containing the checksum information of the bitstream. The `checkSum` dictionary
        includes keys for the algorithm (e.g., "MD5") and the checksum value.
    sequenceId : int or None
        The sequence identifier for the bitstream, used to order multiple bitstreams in the same bundle.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the `Bitstream` object. Calls the initializer of `DSpaceObject` to handle common 
        attributes and then sets bitstream-specific attributes based on the provided API resource.
    
    as_dict():
        Returns a dictionary representation of the `Bitstream` object, combining the fields from the 
        parent `DSpaceObject` with bitstream-specific attributes (`bundleName`, `sizeBytes`, `checkSum`, 
        and `sequenceId`).
    """

    type = "bitstream"
    # Bitstream has a few extra fields specific to file storage
    bundleName = None
    sizeBytes = None
    checkSum = {"checkSumAlgorithm": "MD5", "value": None}
    sequenceId = None

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set bitstream-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "bitstream"
        if "bundleName" in api_resource:
            self.bundleName = api_resource["bundleName"]
        if "sizeBytes" in api_resource:
            self.sizeBytes = api_resource["sizeBytes"]
        if "checkSum" in api_resource:
            self.checkSum = api_resource["checkSum"]
        if "sequenceId" in api_resource:
            self.sequenceId = api_resource["sequenceId"]

    def as_dict(self):
        """
        Return a dict representation of this Bitstream, based on super with bitstream-specific attributes added
        @return: dict of Bitstream for API use
        """
        dso_dict = super().as_dict()
        bitstream_dict = {
            "bundleName": self.bundleName,
            "sizeBytes": self.sizeBytes,
            "checkSum": self.checkSum,
            "sequenceId": self.sequenceId,
        }
        return {**dso_dict, **bitstream_dict}


class Group(DSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and methods for groups (aka. EPersonGroups)
    
    he `Group` class models a DSpace group, which is a collection of users (EPersons) that can 
    be used to manage permissions and access control within the DSpace system. Groups can be 
    permanent or temporary, and each group has a name.

    Attributes:
    ----------
    type : str
        The type of the object, which is always set to "group" for instances of this class.
    name : str or None
        The name of the group. This is used to identify the group within the DSpace system.
    permanent : bool
        A boolean indicating whether the group is permanent (`True`) or temporary (`False`).
        Permanent groups are usually system-defined and cannot be deleted.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the `Group` object, setting group-specific attributes based on the API resource 
        data provided, if available. Calls the `DSpaceObject` initializer for common attributes.
    
    as_dict():
        Returns a dictionary representation of the `Group` object, combining the fields from the 
        parent `DSpaceObject` and the specific group attributes (`name`, `permanent`). This is 
        useful when serializing the object for API operations or for debugging purposes.
    """

    type = "group"
    name = None
    permanent = False

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set group-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "group"
        if "name" in api_resource:
            self.name = api_resource["name"]
        if "permanent" in api_resource:
            self.permanent = api_resource["permanent"]

    def as_dict(self):
        """
        Return a dict representation of this Group, based on super with group-specific attributes added
        @return: dict of Group for API use
        """
        dso_dict = super().as_dict()
        group_dict = {"name": self.name, "permanent": self.permanent}
        return {**dso_dict, **group_dict}


class User(SimpleDSpaceObject):
    """
    Extends DSpaceObject to implement specific attributes and methods for users (aka. EPersons)
    
    This class models a user in the DSpace system and includes attributes such as the user's 
    name, network ID (netid), last activity timestamp, login capabilities, email, certificate 
    requirement, and whether they self-registered. It is used for both representing and 
    manipulating user data retrieved from the DSpace API.

    Attributes:
    ----------
    type : str
        The type of the object, set to "user" for all instances of this class.
    name : str or None
        TODO: The user's full name as stored in the DSpace system.???
    netid : str or None
        The user's network ID, which can be used for authentication or identification within 
        the institution. (e.g. username)
    lastActive : str or None
        The timestamp of the user's last activity within the DSpace system.
    canLogIn : bool
        A boolean flag indicating whether the user has login capabilities within the system.
    email : str or None
        The user's email address.
    requireCertificate : bool
        A flag indicating if the user is required to use a certificate to log in.
    selfRegistered : bool
        A flag indicating if the user self-registered via an open registration process.

    Methods:
    -------
    __init__(api_resource=None):
        Initializes the user object, setting attributes based on the provided API resource.
    
    as_dict():
        Returns a dictionary representation of the user, combining the parent class attributes 
        with the user-specific fields for use in the DSpace API.
    """

    type = "user"
    name = None
    netid = None
    lastActive = None
    canLogIn = False
    email = None
    requireCertificate = False
    selfRegistered = False

    def __init__(self, api_resource=None):
        """
        Default constructor. Call DSpaceObject init then set user-specific attributes
        @param api_resource: API result object to use as initial data
        """
        super().__init__(api_resource)
        self.type = "user"
        if "name" in api_resource:
            self.name = api_resource["name"]
        if "netid" in api_resource:
            self.netid = api_resource["netid"]
        if "lastActive" in api_resource:
            self.lastActive = api_resource["lastActive"]
        if "canLogIn" in api_resource:
            self.canLogIn = api_resource["canLogIn"]
        if "email" in api_resource:
            self.email = api_resource["email"]
        if "requireCertificate" in api_resource:
            self.requireCertificate = api_resource["requireCertificate"]
        if "selfRegistered" in api_resource:
            self.selfRegistered = api_resource["selfRegistered"]

    def as_dict(self):
        """
        Return a dict representation of this User, based on super with user-specific attributes added
        @return: dict of User for API use
        """
        dso_dict = super().as_dict()
        user_dict = {
            "name": self.name,
            "netid": self.netid,
            "lastActive": self.lastActive,
            "canLogIn": self.canLogIn,
            "email": self.email,
            "requireCertificate": self.requireCertificate,
            "selfRegistered": self.selfRegistered,
        }
        return {**dso_dict, **user_dict}


class InProgressSubmission(AddressableHALResource):
    """
    Represents a submission that is in progress in the DSpace workflow.

    This class extends the `AddressableHALResource` and is used to model an in-progress submission, 
    which contains metadata like the last modification date, the current step of the submission 
    process, and its sections.

    Attributes:
    ----------
    lastModified : str or None
        The timestamp when the submission was last modified.
    step : str or None
        The current step of the submission process.
    sections : dict
        A dictionary representing the sections of the submission.
    type : str or None
        The type of the submission resource.

    Methods:
    -------
    as_dict():
        Returns a dictionary representation of the submission, including the inherited 
        fields and the specific attributes (lastModified, step, sections, and type).
    """
    lastModified = None
    step = None
    sections = {}
    type = None

    def __init__(self, api_resource):
        super().__init__(api_resource)
        if "lastModified" in api_resource:
            self.lastModified = api_resource["lastModified"]
        if "step" in api_resource:
            self.step = api_resource["step"]
        if "sections" in api_resource:
            self.sections = api_resource["sections"].copy()
        if "type" in api_resource:
            self.type = api_resource["type"]

    def as_dict(self):
        parent_dict = super().as_dict()
        dict = {
            "lastModified": self.lastModified,
            "step": self.step,
            "sections": self.sections,
            "type": self.type,
        }
        return {**parent_dict, **dict}


class WorkspaceItem(InProgressSubmission):
    """
    Represents an item in the workspace for submission in DSpace.

    This class extends `InProgressSubmission`, and models a workspace item, 
    which is essentially a submission that hasn't been completed or archived yet.

    It inherits all attributes and methods from `InProgressSubmission`, including metadata such as 
    the last modified timestamp, step in the submission process, and section information.

    Methods:
    -------
    as_dict():
        Returns a dictionary representation of the workspace item, combining the inherited 
        fields from `InProgressSubmission` and `AddressableHALResource`.
    """

    def __init__(self, api_resource):
        super().__init__(api_resource)

    def as_dict(self):
        return super().as_dict()


class EntityType(AddressableHALResource):
    """
    Extends Addressable HAL Resource to model an entity type (aka item type)
    used in entities and relationships. For example, Publication, Person, Project and Journal
    are all common entity types used in DSpace 7+
    """

    def __init__(self, api_resource):
        super().__init__(api_resource)
        if "label" in api_resource:
            self.label = api_resource["label"]
        if "type" in api_resource:
            self.type = api_resource["type"]


class RelationshipType(AddressableHALResource):
    """
    TODO: RelationshipType
    """

    def __init__(self, api_resource):
        super().__init__(api_resource)
