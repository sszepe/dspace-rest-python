# This software is licenced under the BSD 3-Clause licence
# available at https://opensource.org/licenses/BSD-3-Clause
# and described in the LICENCE file in the root of this project

"""
Connection test for the mdwRepository DSpace CRIS REST API
"""

import logging
import os
import sys

from dotenv import load_dotenv

from dspace_rest_client.client import DSpaceClient
from dspace_rest_client.models import (
    Community,
    Collection,
    Item,
    Bundle,
    Bitstream,
    User,
)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
load_dotenv(override=True)

url = os.getenv("DSPACE_API_ENDPOINT")
username = os.getenv("DSPACE_API_USERNAME")
password = os.getenv("DSPACE_API_PASSWORD")
if not url or not username or not password:
    logging.error(
        "Error: DSPACE_API_ENDPOINT, DSPACE_API_USERNAME, or DSPACE_API_PASSWORD not set in .env file"
    )
    sys.exit(1)
else:
    logging.info(f"Connecting to DSpace API at {url} as {username}")

d = DSpaceClient(
    api_endpoint=url, username=username, password=password, fake_user_agent=True
)

# Authenticate against the DSpace client
authenticated = d.authenticate()
if not authenticated:
    logging.error("Error logging in! Giving up.")
    sys.exit(1)
else:
    logging.info(f"Logged in as {username}")

# Get the current user information
eperson_id = d.get_eperson_id_of_user()
if eperson_id:
    logging.info(f"User ID: {eperson_id}")
else:
    logging.error("Error getting user ID")
special_groups = d.get_special_groups_of_user()
if special_groups:
    logging.info(f"Special groups: {special_groups}")
else:
    logging.error("No special groups present")

# Get top communities
top_communities = d.get_communities(top=True)
for top_community in top_communities:
    logging.info(f"Top Community: {top_community.name} ({top_community.uuid})")
    # Get all collections in this community
    collections = d.get_collections(community=top_community)
    for collection in collections:
        logging.info(f"Collection: {collection.name} ({collection.uuid})")
        # Get all items in this collection - see that the recommended method is a search, scoped to this collection
        # (there is no collection/items endpoint, though there is a /mappedItems endpoint, not yet implemented here)
        items = d.search_objects(query="*:*", scope=collection.uuid, dso_type="item")
        for item in items:
            logging.info(f"Item: {item.name} ({item.uuid})")
            # Get all bundles in this item
            bundles = d.get_bundles(parent=item)
            for bundle in bundles:
                logging.info(f"{bundle.name} ({bundle.uuid})")
                # Get all bitstreams in this bundle
                bitstreams = d.get_bitstreams(bundle=bundle)
                for bitstream in bitstreams:
                    logging.info(f"{bitstream.name} ({bitstream.uuid})")

first_community = top_communities[0]
logging.info(f"First Community: {first_community.as_dict()}")

# get Top Community: LIS -> get first item in list returned by d.get_communities
lis_parent_community = d.get_parent_community(
    uuid="49d47738-1a1b-4d91-b364-70511c63aed0"
)
logging.info(f"Parent Community: {lis_parent_community.as_dict()}")

lis_sub_community = d.get_sub_communities(uuid="c78fa4d1-b739-42d4-90b2-9759f7f5df55")
logging.info(f"Sub Communities: {lis_sub_community}")

# get objects for start page
start_page_items = d.search_objects(
    query="*:*",
    sort="dc.date.accessioned,DESC",
    page=0,
    size=5,
    dso_type="item",
)
for item in start_page_items:
    logging.info(f"Item: {item.name} ({item.uuid})")
    logging.info(f"Item type: {item.metadata['dspace.entity.type'][0]['value']}")

# get the most viewed items
most_viewed_items = d.search_objects(
    query="*:*",
    sort="metric.view,DESC",
    page=0,
    size=5,
    dso_type="item",
    configuration="homePageTopItems",
)
for item in most_viewed_items:
    logging.info(f"Item: {item.name} ({item.uuid})")
    # logging.info(f"Item type: {item.metadata['dspace.entity.type'][0]['value']}")

# search objects admin
search_objects = d.search_objects_admin(
    uri="https://repo.mdw.ac.at/fis/api/core/sites/ef5351a2-dee8-490e-93d9-c5cb5348d1c4",
    feature="isCommunityAdmin",
    embed="feature",
)
logging.info(f"Search objects admin: {search_objects}")
for item in search_objects:
    logging.info(f"Item: {item})")

# configuration
config = d.get_config(key="registration.verification.enabled")
logging.info(f"Registration verification enabled: {config['values'][0]}")

# get item f306cec7-d348-41b8-9c1a-4fc53ee5854f
item = d.get_item(uuid="f306cec7-d348-41b8-9c1a-4fc53ee5854f")
logging.info(f"Item: {item.json()}")
# metrices
metrics = d.get_item_metrics(uuid="f306cec7-d348-41b8-9c1a-4fc53ee5854f")
logging.info(f"Metrics: {metrics.json()}")
# thumbnail
thumbnail = d.get_item_thumbnail(uuid="f306cec7-d348-41b8-9c1a-4fc53ee5854f")
logging.info(f"Thumbnail: {thumbnail}")

# Log out
d.logout()

d = DSpaceClient(api_endpoint=url, unauthenticated=True, fake_user_agent=True)

# get objects for start page
start_page_items = d.search_objects(
    query="*:*",
    sort="dc.date.accessioned,DESC",
    page=0,
    size=5,
    dso_type="item",
)
most_viewed_page_items = d.search_objects(
    sort="metric.view,DESC", page=0, size=5, configuration="homePageTopItems"
)
