import re
from uuid import UUID

import pytest
from starlette.testclient import TestClient

from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import ProfileNotFound


def _csrf(page: str) -> str:
    match = re.search(r'name="csrf" value="([^"\s]+)"', page)
    assert match is not None
    return match.group(1)


def _create(client: TestClient, name: str = "Телефон") -> UUID:
    csrf = _csrf(client.get("/").text)
    response = client.post(
        "/profiles",
        data={"name": name, "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return UUID(response.headers["location"].removeprefix("/profiles/"))


def test_create_profile_redirects_to_card(authenticated_client: TestClient) -> None:
    profile_id = _create(authenticated_client)

    response = authenticated_client.get(f"/profiles/{profile_id}")

    assert response.status_code == 200
    assert "Телефон" in response.text
    assert "Активен" in response.text
    assert "vless://" in response.text
    assert "hysteria2://" in response.text
    assert response.text.count("<svg") == 3
    assert "sudo ezopenpn admin reset-password" in response.text


def test_mutation_without_csrf_is_rejected(
    authenticated_client: TestClient, web_app
) -> None:
    created = web_app.state.services.runtime.create("Ноутбук")

    response = authenticated_client.post(
        f"/profiles/{created.profile_id}/disable", follow_redirects=False
    )

    assert response.status_code == 403


def test_active_profile_can_be_disabled_and_enabled(
    authenticated_client: TestClient, web_app
) -> None:
    profile_id = _create(authenticated_client)
    web_app.state.services.profiles.set_state(profile_id, ProfileState.ACTIVE)
    csrf = _csrf(authenticated_client.get(f"/profiles/{profile_id}").text)

    disabled = authenticated_client.post(
        f"/profiles/{profile_id}/disable",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert disabled.status_code == 303
    assert web_app.state.services.profiles.get(profile_id).state is ProfileState.DISABLED

    csrf = _csrf(authenticated_client.get(f"/profiles/{profile_id}").text)
    enabled = authenticated_client.post(
        f"/profiles/{profile_id}/enable",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert enabled.status_code == 303
    assert web_app.state.services.profiles.get(profile_id).state is ProfileState.ACTIVE


def test_delete_requires_confirmation_and_removes_profile(
    authenticated_client: TestClient, web_app
) -> None:
    profile_id = _create(authenticated_client)
    csrf = _csrf(authenticated_client.get(f"/profiles/{profile_id}").text)

    rejected = authenticated_client.post(
        f"/profiles/{profile_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert rejected.status_code == 400
    assert web_app.state.services.profiles.get(profile_id).profile_id == profile_id

    removed = authenticated_client.post(
        f"/profiles/{profile_id}/delete",
        data={"csrf": csrf, "confirm": "remove"},
        follow_redirects=False,
    )
    assert removed.status_code == 303
    with pytest.raises(ProfileNotFound):
        web_app.state.services.profiles.get(profile_id)


def test_dashboard_has_labeled_create_form_and_empty_guidance(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert 'label for="profile-name"' in response.text
    assert "Создать профиль" in response.text
    assert "Добавьте первое устройство" in response.text


def test_profile_page_explains_four_import_steps(authenticated_client: TestClient) -> None:
    profile_id = _create(authenticated_client)

    response = authenticated_client.get(f"/profiles/{profile_id}")

    for step in range(1, 5):
        assert f'data-step="{step}"' in response.text


def test_non_active_token_is_not_rendered_in_panel(
    authenticated_client: TestClient, web_app
) -> None:
    created = web_app.state.services.runtime.create("Рабочий телефон")
    assert created.subscription_token is not None
    web_app.state.services.profiles.set_state(created.profile_id, ProfileState.ERROR)

    dashboard = authenticated_client.get("/")
    profile = authenticated_client.get(f"/profiles/{created.profile_id}")

    assert created.subscription_token not in dashboard.text
    assert created.subscription_token not in profile.text


def test_rendered_panel_has_no_inline_script_or_style(
    authenticated_client: TestClient,
) -> None:
    profile_id = _create(authenticated_client)

    for response in (
        authenticated_client.get("/"),
        authenticated_client.get(f"/profiles/{profile_id}"),
    ):
        rendered = response.text.casefold()
        assert "<style" not in rendered
        assert "<script>" not in rendered
        assert "onclick=" not in rendered
        assert "onchange=" not in rendered
