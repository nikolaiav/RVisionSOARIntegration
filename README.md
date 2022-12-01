# Обогащение индикаторов в R-Vision SOAR
## Принцип работы
Версии интеграции старше v2.0 работают только с кастомныеми полями с индикаторами. 
Системное поле `iocs` поддерживается в версиях < v2.0.  
Интеграция работает по следующей схеме:
- Сценарий реагирования использует Коннектор.
- Коннектор делает GET-запрос к FastAPI-сервису, работающему в контейнере, передав ID инцидента в параметре запроса.
- Сервис, получив запрос от Коннектора, делает запрос `source` полей, описанных в `config.yml` из инцидента через API R-Vision SOAR.
- Получив индикаторы, Сервис запрашивает их в RST Cloud API.
- Собрав все данные Сервис отправляет их в виде запроса на обновление заданного в конфиге поля инцидента.
- Данные от RST Cloud добавляются в поля `target` конфигурационного файла `config.yml`

## Настройка R-Vision SOAR
1. Сгенерировать API-токен в R-Vision SOAR.
2. Убедиться, что у пользователя, для которого создан токен, есть права на создание и изменение инцидентов.
3. Создать новое поле инцидента в R-Vision SOAR, в котором будет храниться индикатор.
4. Указать что данное поле имеет тим Массив.
5. Создать следующую схему для `source` поля (поля, где будет храниться индикатор):
```
Тип: Текст
Тег: См. config.yml - source
```
6. Создать следующую схему для `target` поля (поля, где будет храниться индикатор):
```
Тип: Массив
Тег: См. config.yml - target

Поля:
Тип: Текст --------------- Тег: rst_field
Тип: Многострочный текст - Тег: rst_value
```
7. Создать REST-Коннектор и указать URL `http://<IP>:9080/ioc?identifier={{tag.IDENTIFIER}}`, метод GET, где IP - адрес расположения сервиса. Если сервис будет работать на хосте SOAR, то 127.0.0.1
8. Выставить в коннекторе таймаут 60 сек.
9. Переименовать `conf/config.yml.sample` в `conf/config.yml`.
10. Вписать в `config.yml` адрес R-Vision SOAR и токены.

## Развертывание в docker
1. Собрать образ `docker build -t rstintegration .`
2. В `docker-compose.yml` для volume указать расположение директорий `conf` и `log`
3. Запустить контейнер `docker-compose up -d`

## Развертывание в systemd
1. Установить python 3.7
2. Выполнить
```pip3.7 install -r requirements.txt
cd /opt
git clone https://github.com/rstcloud/RVisionSOARIntegration.git
cd RVisionSOARIntegration
mkdir logs
mv conf/config.yml.sample conf/config.yml
cp rvisionrstintegration.service /etc/systemd/system/
```
3. Отредактировать `conf/config.yml`
4. `systemctl enable rvisionrstintegration`
5. `systemctl start rvisionrstintegration`