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


def test_secret_missing():
    with pytest.raises(Exception):
        generate_home_directory(
            template='{{ secret.category }}/{{ user_name }}',
            secret={
                'type': 'staff',
            },
            user_name='john',
        )
