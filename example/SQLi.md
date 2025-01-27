# SQL injections

## Описание
Атака представляет собой внедрение SQL-кода в выполняемый приложением SQL-запрос через пользовательский ввод. Атака эксплуатирует недостаток валидации передаваемых данных из пользовательского ввода.

Пример уязвимого эндпоинта: `http://vulnerable/index?id=first`
1) При передаче значения `first` будет выполнен следующий запрос: `SELECT * FROM pages WHERE id='first';`
2) При передаче значения `first'` (с кавычкой), получим следующий запрос: `SELECT * FROM pages WHERE id='first'';`. Запрос будет невалидным, т.к. осталась незакрытая кавычка, которая ломает синтаксис.
3) Попробуем отбросить часть запроса после внедренной кавычки. Для этого используем комментарий в MySQL (в разных типах БД они могут быть разными) - `-- `. Теперь строка примет вид `SELECT * FROM pages WHERE id='first'-- ';`. Часть, которая идет после `-- `, теперь не влияет на синтаксис - перед нами валидный запрос в БД.
4) Получим все данные с помощью конструкции `' OR ''='`. Теперь запрос выглядит так: `SELECT * FROM pages WHERE id='first' OR ''='';`. Это значит, что в ответ на запрос придут все значения из таблицы `pages`, т.к. условие всегда будет `true` (`''=''`)

С помощью подобных техник внедрения можно считывать данные из БД.

## Классификация
Различают несколько видов SQL инъекций по типу (техникам) эксплуатации (классификация [sqlmap](https://github.com/sqlmapproject/sqlmap/wiki/Techniques)):
- **Stacked queries** - если существует возможность в инъекции использовать разделитель `;`, то можно выполнять разные SQL-запросы после разделителя. Например, после инъекции в `SELECT`, можно выполнить запрос вида `DROP TABLE news` с помощью разделителя `;`
- **UNION query-based** - для эксплуатации используется конструкция `UNION SELECT`. Позволяет вывести дополнительные данные из БД вместе с основными данными.
- **Error-based** - эта техника эксплуатации используется при выводе на страницу SQL-ошибки. Техника позволяет выводить данные из БД в теле этой ошибки.
- **Boolean-based blind** - в случае, если на выходе инъекции получаем только возможность узнать значение `True` или `False` выполняемой инъекции, используется данная техника. Например, при выполнении запроса получаем ответ с кодом 200 (`True`), а при невыполнении с кодом 500 (`False`). При такой инъекции, запрос формируется таким образом, что побитно достается информация из базы данных, исходя из кода ответа.
- **Time-based blind** - техника похожа на **Boolean-based blind**, только в этому случае в ответ нам ничего не возвращается. Поэтому приходится использовать временные задержки (функции, при выполнении которых получаем задержку во времени исполнения) для побитового получения информации из базы данных.

## Условия
- ОС: любая
- язык: любой
- компоненты: SQL база данных, noSQL база данных
- настройки: разные

Ущерб зависит от множества факторов (тип ОС, тип языка, тип БД, тип инъекции, привилегии)

## Детектирование
Для выявления необходимо исследовать места, где есть пользовательский ввод и данные отправлятся на сервер. Первым возможным шагом является подстановка символов синтаксиса, к примеру: 
- `'` (кавычка)
- `"` (двойная кавычка)
- `\` (бэкслэш)
- `%00` (null-byte)

А так же возможны следующие конструкции:
- `' or ''='`
- `or 1=1 `
- `' AND sleep(10)---`
- и другие

Списки для фаззинга можно найти [тут](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20injection/Intruder)

Для детектирования после фаззинга необходимо выявлять аномалии в ответах:
- изменился код
- изменилось тело (ответ больше/меньше/абсолютно другой)
- изменилось время выполнения запроса

Для выявление уязвимостей в первую очередь пользуются сканерами уязвимостей веб-приложений. Но они работают не по принципу поиска аномалий, а по жестким алгоритмам (поиск в ответе вывода ошибки SQL; сравнение длины ответа для `true` и `false` инъекций; время обработки запроса; проверка сниффера DNS с Out-Of-Band нагрузками). Поэтому, лучший способ выявления аномалий - фаззинг.

Информация:
- [Advanced Fuzzing by artsploit](https://2016.zeronights.ru/wp-content/uploads/2016/12/AdvancedWebAppFuzzing.pptx)
- [Backslash Powered Scanning: hunting unknown vulnerability classes by albinowax](https://portswigger.net/blog/backslash-powered-scanning-hunting-unknown-vulnerability-classes)

## Эксплуатация
Пример эксплуатации на основе MySQL и инъекция в `SELECT`. 

Точка инъекции найдена, можно получить следующую информацию:
* Узнать кол-во колонок в таблице:
  `... union select null,...,null -- `

  Происходит перебор кол-ва null, пока в браузере не появится какая-либо информация (либо пропадет ошибка SQL)

* Информация о структуре таблицы
  Название БД:
  `... union select null, database() as <имя колонки, в которую будет выведен>,...,null -- `

  Схема таблицы:
  `ex. ... union select null,table_schema as <имя колонки, в которую будет выведен>,...,null from INFORMATION_SCHEMA.TABLES -- `

  Имя таблицы:
  `ex. ... union select null,table_name as <имя колонки, в которую будет выведен>,...,null from INFORMATION_SCHEMA.TABLES -- `

  Конкатенция схемы, имени таблицы и название колонок в БД:
  `... union select null,concat_ws('.', table_schema, table_name, column_name) as <имя колонки, в которую будет выведен>,...,null from INFORMATION_SCHEMA.COLUMNS --`
  или
  `... union select null,concat_ws('.', table_schema, table_name, column_name) as <имя колонки, в которую будет выведен>,...,null from INFORMATION_SCHEMA.COLUMNS where <условие> -- `

* Просмотр файлов:

  Просмотр происходит с помощью функции `LOAD_FILE('<имя файла>')`
  `... union select null,LOAD_FILE('/etc/passwd') as <имя колонки, в которую будет выведен>,...,null --`

* Просмотр пользователя БД:

  Просмотр происходит с помощью функции `USER()`

  `... union select null,user() as <имя колонки, в которую будет выведен>,...,null --`


### Инструменты
- [sqlmap](https://github.com/sqlmapproject/sqlmap) - автоматизация эксплуатации SQL-инъекций
- [Читшит от pentestmonkey](http://pentestmonkey.net/category/cheat-sheet/sql-injection) - шпаргалка с примерами запросов для разных баз данных

## Ущерб
Возможно развитие вектора атаки в:
1) "Слив" базы данных (данные, которые доступны пользователю веб-приложения)
2) "Слив" секретных данных из базы для развития атаки (например, пароль/хэш пароля от учетной записи администратора)
3) Выполнению любых команд в базе данных (данные, которые доступны пользователю веб-приложения), в т.ч. деструктивных - удаление/изменение информации (условие: наличие Stacked Queries)
4) Чтение локальных файлов на сервере
5) Выполнение произвольного кода (Remote Code Execution)

При реализации векторов атак возможна полная компрометация сервера (выполнение команд под суперпользователем)

## Защита
### Основные меры
- для взаимодействия приложения с БД использовать только параметризированные запросы в Prepared Statement ([подробнее](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#Defense_Option_1:_Prepared_Statements_.28with_Parameterized_Queries.29))
- использование хранимых процедур и передача параметров в процедуры
- валидация пользовательского ввода по белому списку

### Превентивные меры
Использование подхода Defense in Depth:
- разделение пользователей в БД
- минимально необходимые права для пользователей веб-приложений
- использование `Views` в БД для ограничения кол-ва получаемой информации

## Дополнительно
- Интерактивный урок на [hacksplaining.com](https://www.hacksplaining.com/exercises/sql-injection)
