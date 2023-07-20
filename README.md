### Описание

Были произведены модификации для соединения с Microsoft Active Directory вместо OpenLDAP. Логика взаимодействия с группами была переосмыслена: теперь в "groups-exception" мы указываем список групп, которые исключаются из процесса аутентификации через LDAP. В первозданном варианте приводился перечень групп, в которых аутентификация была возможна. Кроме того, по умолчанию выдаются права на создание ссылок-приглашений для аутентифицированных пользователей. Добавлена пользовательская конфигурация TLS для возможности пропуска проверки сертификата при создании LDAPS-соединения.

### Установка, используя docker

```bash
docker run -d \
--network host \
--name galene-ldap \
--restart=unless-stopped \
-v /data/galene-ldap/data:/srv/app/data \
zerolabnet/galene-ldap:latest
```

Пример "galene-ldap.json" автоматически копируется в смонтированную директорию.
