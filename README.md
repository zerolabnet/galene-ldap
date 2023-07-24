### Описание

Были произведены модификации для соединения с Microsoft Active Directory вместо OpenLDAP. Логика взаимодействия с группами была переосмыслена: теперь в "groups-exception" мы указываем список групп, которые исключаются из процесса аутентификации через LDAP. В первозданном варианте приводился перечень групп, в которых аутентификация была возможна. Кроме того, по умолчанию выдаются права на создание ссылок-приглашений для аутентифицированных пользователей. Добавлена пользовательская конфигурация TLS для возможности пропуска проверки сертификата при создании LDAPS-соединения. Исправлена ошибка, возникающая при закрытия соединения сервером LDAP из-за неактивности. Добавлен функционал для выдачи прав "Оператор". В файле galene-ldap.json вам нужно заполнить поле "op". Это поле должно содержать список групп и пользователей в этих группах, которым вы хотите предоставить права оператора. Посмотрите обновленный пример для наглядности.

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
