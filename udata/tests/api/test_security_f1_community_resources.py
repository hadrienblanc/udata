"""
Security regression tests for finding F1 (IDOR on community resources).

A private dataset is a draft that must only be readable by its owner or
organization: `test_dataset_api_get_private` (udata/tests/api/test_datasets_api.py)
asserts that GET /api/1/datasets/<id>/ returns 404 for anonymous users, and
`ResourceAPI.get` (udata/core/dataset/apiv2.py) applies the same
`permissions["read"]` check to the resources of a private dataset.

These tests assert the same protection for the community resources attached
to a private dataset:

- GET /api/1/datasets/community_resources/?dataset=<private_id>/ must not
  disclose them (the marshalled response includes the parent dataset
  reference with its title, slug, uri and page URLs);
- GET /api/1/datasets/community_resources/<crid>/ must not disclose them;
- POST /api/1/datasets/community_resources/ must not let an unrelated user
  attach a resource to someone else's private dataset (the 201 response
  leaks the private dataset reference, and 201 vs 400 for a well-formed but
  unknown dataset id is an existence oracle).

These tests are security regression tests: they assert the expected secure
behavior and are expected to FAIL as long as the vulnerability exists. The
failure output (HTTP 200/201 + leaked payload) is the proof of the
unauthorized access; the future fix will make them pass.
"""

import json

from bson import ObjectId
from flask import url_for

from udata.core.dataset.factories import CommunityResourceFactory, HiddenDatasetFactory
from udata.core.user.factories import UserFactory

from . import APITestCase

PRIVATE_DATASET_TITLE = "SECRET-PRIVATE-DRAFT-TITLE"
RESOURCE_TITLE = "secret-draft-community-resource"


def leak_excerpt(response):
    """Compact extract of the response payload, used as evidence in failures."""
    data = response.json
    if isinstance(data, dict) and "data" in data:  # paginated payload
        items = data.get("data") or []
        data = items[0] if items else {}
    if isinstance(data, dict):
        return json.dumps({key: data.get(key) for key in ("id", "title", "url", "dataset")})
    return data


class CommunityResourcePrivateDatasetSecurityTest(APITestCase):
    """Community resources bound to a private dataset must not be public."""

    def test_anonymous_cannot_list_community_resources_of_private_dataset(self):
        """Anonymous users must not list community resources of a private dataset.

        Regression test for F1: GET /api/1/datasets/community_resources/?dataset=<id>
        currently performs no visibility check on the parent dataset while the
        dataset itself is 404 for anonymous users.
        """
        owner = UserFactory()
        private_dataset = HiddenDatasetFactory(owner=owner, title=PRIVATE_DATASET_TITLE)
        community_resource = CommunityResourceFactory(
            dataset=private_dataset, title=RESOURCE_TITLE
        )

        response = self.get(url_for("api.community_resources", dataset=str(private_dataset.id)))

        payload = response.json if isinstance(response.json, dict) else {}
        secure = response.status_code in (401, 403, 404) or not payload.get("data") or all(
            item.get("id") != str(community_resource.id) for item in payload["data"]
        )
        self.assertTrue(
            secure,
            "Unauthorized access (F1): an anonymous user listed the community "
            f"resources of a private dataset and got HTTP {response.status_code} "
            f"with leaked payload: {leak_excerpt(response)}",
        )

    def test_anonymous_cannot_read_community_resource_of_private_dataset(self):
        """Anonymous users must not read a community resource of a private dataset.

        Regression test for F1: the `<crid:community>` routing converter
        (udata/routing.py) does not filter by visibility, unlike the sibling
        endpoint GET /api/1/datasets/<id>/resources/<rid>/ (apiv2.ResourceAPI.get).
        """
        owner = UserFactory()
        private_dataset = HiddenDatasetFactory(owner=owner, title=PRIVATE_DATASET_TITLE)
        community_resource = CommunityResourceFactory(
            dataset=private_dataset, title=RESOURCE_TITLE
        )

        response = self.get(url_for("api.community_resource", community=str(community_resource.id)))

        secure = response.status_code in (401, 403, 404)
        self.assertTrue(
            secure,
            "Unauthorized access (F1): an anonymous user fetched a community "
            f"resource attached to a private dataset and got HTTP "
            f"{response.status_code} with leaked payload: {leak_excerpt(response)}",
        )

    def test_unrelated_user_cannot_attach_community_resource_to_private_dataset(self):
        """An unrelated user must not attach a community resource to a private dataset.

        Regression test for F1 (H11 chain): POST /api/1/datasets/community_resources/
        only checks authentication, not read permission on the target dataset.
        The 201 response marshals the private dataset reference (title, slug,
        uri, page), leaking the draft's existence and metadata.
        """
        owner = UserFactory()
        private_dataset = HiddenDatasetFactory(owner=owner, title=PRIVATE_DATASET_TITLE)
        self.login()  # authenticated user with no relation to the private dataset

        attrs = CommunityResourceFactory.as_dict()
        attrs["filetype"] = "remote"
        attrs["dataset"] = str(private_dataset.id)
        response = self.post(url_for("api.community_resources"), attrs)

        secure = response.status_code in (401, 403, 404)
        self.assertTrue(
            secure,
            "Unauthorized access (F1): an unrelated user attached a community "
            "resource to someone else's private dataset and got HTTP "
            f"{response.status_code} with leaked payload: {leak_excerpt(response)}",
        )

    def test_community_resource_create_is_an_existence_oracle_for_private_datasets(self):
        """A well-formed but unknown dataset id is rejected with 400.

        Combined with the (currently failing) test above, which gets a 201 for
        an existing *private* dataset id, this documents the existence oracle:
        400 means the id does not exist, 201 means it exists even though it is
        private. This assertion holds both before and after the fix.
        """
        self.login()
        attrs = CommunityResourceFactory.as_dict()
        attrs["filetype"] = "remote"
        attrs["dataset"] = str(ObjectId())  # well-formed but nonexistent
        response = self.post(url_for("api.community_resources"), attrs)
        self.assert400(response)
