# Дизайн C3A

Для корректного обеспечения авторизации и аутентификации в сервисах с применением C3A используются несколько шагов.

1. Разворачиваемый сервис должен передать полученный от владельца C3A ключ-идентификатор, название приложения, указать заранее оговорённые метаданные, а также список меток прав для домена `common` и для остальных доменов.

Пример:

```json
{
    "validation_key": "5d3dcf62-0b4c-4db2-8f1f-d5506f47604e",
    "application_name": "my_application",
    "application_c3a_cert_address": "{ADDR}/c3a-cert",
    "tags": [
        {
            "type": "any",
            "tag": "user"
        },
        {
            "type": "domain",
            "tag": "admin"
        }
    ],
    "provide_registration": [
        { "from_address": "{ADDR}/sign-up", "for_tags": ["::common::user"], "after_redirect": "{ADDR}/registered" }
    ],
    "tag_setter_key": "69694054-fee9-40b8-8335-3cb30612e0e2",
    "config_updater_key": "c3dc4a1e-5c7c-4528-b7c3-7388f62e61e4"
}
```

2. При этом владелец имеет право переопределять теги и провайдеры для регистрации, а также автоматически назначать теги.
3. Регистрация в C3A включает в себя только определение данных для авторизации. Другие данные вы должны спрашивать самостоятельно; например, делать подтверждение учётной записи (после чего необходимо назначать тег подтверждённому пользователю). Если необходимо предоставлять какие-то данные другим приложениям, вы должны заблаговременно предоставить словарь меток данных и партнёров, например:

```json
{
    "validation_key": "5d3dcf62-0b4c-4db2-8f1f-d5506f47604e",
    "application_name": "my_application",
    "application_c3a_cert_address": "{ADDR}/c3a-cert",
    "application_approve": "{ADDR}/c3a-approve",
    "tags": [
        {
            "type": "any",
            "tag": "user"
        },
        {
            "type": "common",
            "tag": "approved-account"
        },
        {
            "type": "domain",
            "tag": "admin"
        }
    ],
    "provide_registration": [
        { "from_address": "{ADDR}/sign-up", "for_tags": ["::common::user"], "after_redirect": "{ADDR}/registered" }
    ],
    "tag_setter_key": "69694054-fee9-40b8-8335-3cb30612e0e2",
    "config_updater_key": "c3dc4a1e-5c7c-4528-b7c3-7388f62e61e4",
    "common_data": {
        "username": ["my_application1", "my_application2"],
        "first_name": ["my_application1", "my_application2"]
    }
}
```

Все запросы устанавливаются через `kws`, данные шифруются. У всех инстансов одного приложения должен совпадать 
