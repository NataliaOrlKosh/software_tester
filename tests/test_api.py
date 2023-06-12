from http import HTTPStatus

from django.urls import reverse
from django.test.client import Client

import pytest

# Project
from api.models import Operator, SuperAdmin, AbstractUser


def test_ping():
    client = Client()
    response = client.get(reverse("api:ping"), content_type="application/json")
    assert response.status_code == 200
    assert response.json() == {"response": "pong"}


def test_auth_bad_creds():
    client = Client()
    response = client.post(
        reverse("api:auth"),
        content_type="application/json",
        data={
            "engine": "email",
            "credentials": {
                "email": "some@email",
                "password": "StrongPassword",
            },
        },
    )
    assert response.status_code == 401


class TestUser:
    user = AbstractUser()
    user.is_confirmed = True

    def test_user_me_not_authenticated(self, client):
        response = client.get("/api/users/me/")

        assert (
            response.status_code != HTTPStatus.NOT_FOUND
        ), "Эндпоинт `/api/users/me/` не найден. Проверьте настройки в *urls.py*."

        assert (
            response.status_code == HTTPStatus.UNAUTHORIZED
        ), "Проверьте, что GET-запрос к `/api/users/me/` без токена авторизации возвращается ответ со статусом 401."

    def test_set_password(self):
        before_password_hash = self.user.password_hash
        self.user.set_password("12jhgcjhablknalkquowA34")
        after_password_hash = self.user.password_hash
        assert before_password_hash != after_password_hash, "Пароль не удалось установить."

    def test_check_password(self):
        self.user.set_password("12jhgcjhablknalkquowA34")
        before_password_hash = self.user.password_hash
        self.user.check_password("12jhgcjhablknalkquowA34")
        after_password_hash = self.user.password_hash
        assert before_password_hash == after_password_hash, "Пароль изменился."

    @pytest.mark.parametrize(
        "password_1, password_2, message",
        [
            ("12jhgcjhablknalkquowA34", "567812jhgcjhablknalkquowA34", "Пароль не изменился."),
        ],
    )
    def test_change_password(self, password_1, password_2, message):
        self.user.set_password(password_1)
        before_password_hash = self.user.password_hash
        self.user.change_password(password_1, password_2)
        after_password_hash = self.user.password_hash
        assert before_password_hash != after_password_hash, message


class TestSuperAdmin:
    super_admin = SuperAdmin()
    super_admin.is_confirmed = True

    operator = Operator()

    @pytest.mark.parametrize(
        "user_type, result, message",
        [
            ("SUPER_ADMIN", False, "SuperAdmin не должен иметь возможность создавать администратора."),
            ("OPERATOR", True, "SuperAdmin может создавать оператора."),
            ("USER", True, "SuperAdmin можеть создавать пользователя."),
        ],
    )
    def test_super_admin_create_user(self, user_type, result, message):
        assert self.super_admin.can_create_user(user_type) == result, message

    def test_super_admin_read_user(self):
        assert self.super_admin.can_read_user(self.super_admin) == True, "SuperAdmin может получать данные о себе."
        assert (
            self.super_admin.can_read_user(self.operator) == True
        ), "SuperAdmin может получать информацию о других пользователях."

    def test_super_admn_edit_user(self):
        assert self.super_admin.can_edit_user(self.super_admin) == True, "SuperAdmin может редактировать данные о себе."
        assert (
            self.super_admin.can_edit_user(self.operator) == True
        ), "SuperAdmin может изменять информацию о других пользователях."


class TestOperator:
    first_operator = Operator()
    first_operator.is_confirmed = True

    second_operator = Operator()

    @pytest.mark.parametrize("user_type, result", [("SUPER_ADMIN", False), ("OPERATOR", False), ("USER", False)])
    def test_operator_create_user(self, user_type, result):
        assert (
            self.first_operator.can_create_user(user_type) == result
        ), "Operator не должен иметь возможность создавать пользователя."

    def test_operator_read_user(self):
        assert self.first_operator.can_read_user(self.first_operator) == True, "Operator может получать данные о себе."
        assert (
            self.first_operator.can_read_user(self.second_operator) == False
        ), "Operator не может получать информацию о других пользователях."

    def test_operator_edit_user(self):
        assert (
            self.first_operator.can_edit_user(self.first_operator) == True
        ), "Operator может редактировать данные о себе."
        assert (
            self.first_operator.can_edit_user(self.second_operator) == False
        ), "Operator не может изменять информацию о других пользователях."
