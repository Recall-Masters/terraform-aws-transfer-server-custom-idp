import pytest

from transfer_server_custom_idp.lambda_handler import generate_home_directory


def test_user_name():
    assert generate_home_directory(
        template='test/{{ user_name }}',
        secret={},
        user_name='john',
    ) == 'test/john'


def test_secret():
    assert generate_home_directory(
        template='{{ secret.type }}/{{ user_name }}',
        secret={
            'type': 'staff',
        },
        user_name='john',
    ) == 'staff/john'


@pytest.fixture
def conditional_template() -> str:
    return '''
        {{ secret.type }}/
        {%- if secret.company_id is defined -%}
            {{ secret.company_id }}/
        {%- endif -%}
        {{ user_name }}
    '''


def test_conditional_dms(conditional_template: str):
    assert generate_home_directory(
        template=conditional_template,
        secret={
            'type': 'dms',
            'company_id': 10005,
        },
        user_name='john',
    ) == 'dms/10005/john'


def test_conditional_prospect(conditional_template):
    assert generate_home_directory(
        template=conditional_template,
        secret={
            'type': 'prospect',
        },
        user_name='john',
    ) == 'prospect/john'


def test_secret_missing():
    with pytest.raises(Exception):
        generate_home_directory(
            template='{{ secret.category }}/{{ user_name }}',
            secret={
                'type': 'staff',
            },
            user_name='john',
        )
