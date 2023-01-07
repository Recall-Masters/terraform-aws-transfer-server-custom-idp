import pytest

from transfer_server_custom_idp.home_directory import generate_home_directory
from transfer_server_custom_idp.models.secret_model import Secret


def test_user_name():
    assert (
        generate_home_directory(
            template="test/{{ secret.user_name }}",
            secret=Secret(user_name="john", home_directory_details=False),
        )
        == "test/john"
    )


def test_secret():
    assert (
        generate_home_directory(
            template="{{ secret.type }}/{{ secret.user_name }}",
            secret=Secret(
                user_name="john",
                home_directory_details=False,
                type="staff",
            ),
        )
        == "staff/john"
    )


@pytest.fixture
def conditional_template() -> str:
    return """
        {{ secret.type }}/
        {%- if secret.company_id -%}
            {{ secret.company_id }}/
        {%- endif -%}
        {{ secret.user_name }}
    """


def test_conditional_dms(conditional_template: str):
    assert (
        generate_home_directory(
            template=conditional_template,
            secret=Secret(
                user_name="john",
                home_directory_details=False,
                type="dms",
                company_id="10005",
            ),
        )
        == "dms/10005/john"
    )


def test_conditional_prospect(conditional_template):
    assert (
        generate_home_directory(
            template=conditional_template,
            secret=Secret(
                user_name="john",
                home_directory_details=False,
                type="prospect",
            ),
        )
        == "prospect/john"
    )


def test_secret_missing():
    with pytest.raises(Exception):
        generate_home_directory(
            template="{{ secret.category }}/{{ user_name }}",
            secret={
                "type": "staff",
            },
            user_name="john",
        )
