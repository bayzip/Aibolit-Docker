<?php
///////////////////////////////////////////////////////////////////////////
// Version: SOME_VERSION
// Created and developed by Greg Zemskov, Revisium Company
// Email: audit@revisium.com, http://revisium.com/ai/

// Commercial usage is not allowed without a license purchase or written permission of the author
// Source code and signatures usage is not allowed

// Certificated in Federal Institute of Industrial Property in 2012
// http://revisium.com/ai/i/mini_aibolit.jpg

////////////////////////////////////////////////////////////////////////////
// Запрещено использование скрипта в коммерческих целях без приобретения лицензии.
// Запрещено использование исходного кода скрипта и сигнатур.
//
// По вопросам приобретения лицензии обращайтесь в компанию "Ревизиум": http://www.revisium.com
// audit@revisium.com
// На скрипт получено авторское свидетельство в Роспатенте
// http://revisium.com/ai/i/mini_aibolit.jpg
///////////////////////////////////////////////////////////////////////////
ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');

define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль	 

define('PASS', '????????????????');

//////////////////////////////////////////////////////////////////////////

if (isCli()) {
    if (strpos('--eng', $argv[$argc - 1]) !== false) {
        define('LANG', 'EN');
    }
} else {
    if (PASS == '????????????????') {
       die('Forbidden'); 
    }

    define('NEED_REPORT', true);
}

if (!defined('LANG')) {
    define('LANG', 'EN');
}

// put 1 for expert mode, 0 for basic check and 2 for paranoid mode
// установите 1 для режима "Обычное сканирование", 0 для быстрой проверки и 2 для параноидальной проверки (диагностика при лечении сайтов) 
define('AI_EXPERT_MODE', 1);

define('REPORT_MASK_DOORWAYS', 4);
define('REPORT_MASK_FULL', REPORT_MASK_DOORWAYS);

define('AI_HOSTER', 0);

define('AI_EXTRA_WARN', 0);

$defaults = array(
    'path' => dirname(__FILE__),
    'scan_all_files' => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
    'scan_delay' => 0, // delay in file scanning to reduce system load
    'max_size_to_scan' => '650K',
    'site_url' => '', // website url
    'no_rw_dir' => 0,
    'skip_ext' => '',
    'skip_cache' => false,
    'report_mask' => REPORT_MASK_FULL
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)) {
    define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array(
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml'
);
$g_SensitiveFiles  = array_merge(array(
    'php',
    'js',
    'json',
    'htaccess',
    'html',
    'htm',
    'tpl',
    'inc',
    'css',
    'txt',
    'sql',
    'ico',
    '',
    'susp',
    'suspected',
    'zip',
    'tar'
), $g_SuspiciousFiles);
$g_CriticalFiles   = array(
    'php',
    'htaccess',
    'cgi',
    'pl',
    'o',
    'so',
    'py',
    'sh',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php6',
    'php7',
    'pht',
    'shtml',
    'susp',
    'suspected',
    'infected',
    'vir',
    'ico',
    'js',
    'json',  
    ''
);
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction';
$g_VirusFiles      = array(
    'js',
    'json', 
    'html',
    'htm',
    'suspicious'
);
$g_VirusEntries    = '<script|<iframe|<object|<embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles      = array(
    'js',
    'html',
    'htm',
    'suspected',
    'php',
    'phtml',
    'pht',
    'php7'
);
$g_PhishEntries    = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt    = array(
    'php',
    'php3',
    'php4',
    'php5',
    'php7',
    'pht',
    'html',
    'htm',
    'phtml',
    'shtml',
    'khtml',
    '',
    'ico',
    'txt'
);

if (LANG == 'RU') {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // RUSSIAN INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Отображать по _MENU_ записей\"";
    $msg2  = "\"Ничего не найдено\"";
    $msg3  = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
    $msg4  = "\"Нет файлов\"";
    $msg5  = "\"(всего записей _MAX_)\"";
    $msg6  = "\"Поиск:\"";
    $msg7  = "\"Первая\"";
    $msg8  = "\"Предыдущая\"";
    $msg9  = "\"Следующая\"";
    $msg10 = "\"Последняя\"";
    $msg11 = "\": активировать для сортировки столбца по возрастанию\"";
    $msg12 = "\": активировать для сортировки столбцов по убыванию\"";
    
    define('AI_STR_001', 'Отчет сканера <a href="https://revisium.com/ai/">AI-Bolit</a> v@@VERSION@@:');
    define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>.<p> Компания <a href="https://revisium.com/">"Ревизиум"</a> предлагает услугу превентивной защиты сайта от взлома с использованием уникальной <b>процедуры "цементирования сайта"</b>. Подробно на <a href="https://revisium.com/ru/client_protect/">странице услуги</a>. <p>Лучшее лечение &mdash; это профилактика.');
    define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
    define('AI_STR_004', 'Путь');
    define('AI_STR_005', 'Изменение свойств');
    define('AI_STR_006', 'Изменение содержимого');
    define('AI_STR_007', 'Размер');
    define('AI_STR_008', 'Конфигурация PHP');
    define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
    define('AI_STR_010', "Сканер AI-Bolit запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
    define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
    define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
    define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования. Подробнее смотрите в <a href="https://revisium.com/ai/faq.php">FAQ вопрос №10</a>.</div>');
    define('AI_STR_015', '<div class="title">Критические замечания</div>');
    define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
    define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
    define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
    define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
    define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
    define('AI_STR_021', 'Подозрение на вредоносный скрипт');
    define('AI_STR_022', 'Символические ссылки (symlinks)');
    define('AI_STR_023', 'Скрытые файлы');
    define('AI_STR_024', 'Возможно, каталог с дорвеем');
    define('AI_STR_025', 'Не найдено директорий c дорвеями');
    define('AI_STR_026', 'Предупреждения');
    define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
    define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
    define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
    define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
    define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
    define('AI_STR_032', 'Невидимые ссылки');
    define('AI_STR_033', 'Отображены только первые ');
    define('AI_STR_034', 'Подозрение на дорвей');
    define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
    define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
    define('AI_STR_037', 'Версии найденных CMS');
    define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
    define('AI_STR_039', 'Не найдено файлов больше чем %s');
    define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
    define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
    define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
    define('AI_STR_043', 'Использовано памяти при сканировании: ');
    define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
    define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
    define('AI_STR_050', 'Замечания и предложения по работе скрипта и не обнаруженные вредоносные скрипты присылайте на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<p>Также будем чрезвычайно благодарны за любые упоминания скрипта AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. Ссылочку можно поставить на <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>. <p>Если будут вопросы - пишите <a href="mailto:ai@revisium.com">ai@revisium.com</a>. ');
    define('AI_STR_051', 'Отчет по ');
    define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
    define('AI_STR_053', 'Много косвенных вызовов функции');
    define('AI_STR_054', 'Подозрение на обфусцированные переменные');
    define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
    define('AI_STR_056', 'Дробление строки на символы');
    define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.<br> Рекомендуем проверить сайт в режиме "Эксперт" или "Параноидальный". Подробно описано в <a href="https://revisium.com/ai/faq.php">FAQ</a> и инструкции к скрипту.');
    define('AI_STR_058', 'Обнаружены фишинговые страницы');
    
    define('AI_STR_059', 'Мобильных редиректов');
    define('AI_STR_060', 'Вредоносных скриптов');
    define('AI_STR_061', 'JS Вирусов');
    define('AI_STR_062', 'Фишинговых страниц');
    define('AI_STR_063', 'Исполняемых файлов');
    define('AI_STR_064', 'IFRAME вставок');
    define('AI_STR_065', 'Пропущенных больших файлов');
    define('AI_STR_066', 'Ошибок чтения файлов');
    define('AI_STR_067', 'Зашифрованных файлов');
    define('AI_STR_068', 'Подозрительных (эвристика)');
    define('AI_STR_069', 'Символических ссылок');
    define('AI_STR_070', 'Скрытых файлов');
    define('AI_STR_072', 'Рекламных ссылок и кодов');
    define('AI_STR_073', 'Пустых ссылок');
    define('AI_STR_074', 'Сводный отчет');
    define('AI_STR_075', 'Сканер бесплатный только для личного некоммерческого использования. Информация по <a href="https://revisium.com/ai/faq.php#faq11" target=_blank>коммерческой лицензии</a> (пункт №11). <a href="https://revisium.com/images/mini_aibolit.jpg">Авторское свидетельство</a> о гос. регистрации в РосПатенте №2012619254 от 12 октября 2012 г.');
    
    $tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
   <div class="thanx">
      Замечания и предложения по работе скрипта, а также не обнаруженные вредоносные скрипты вы можете присылать на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<br/>
      Также будем чрезвычайно благодарны за любые упоминания сканера AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. <br/>Ссылку можно поставить на страницу <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>.<br/> 
     <p>Получить консультацию или задать вопросы можно по email <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
	</div>
HTML_FOOTER;
    
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Подозрительные параметры времени изменения файла");
    define('AI_STR_078', "Подозрительные атрибуты файла");
    define('AI_STR_079', "Подозрительное местоположение файла");
    define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.<p>Для диагностического сканирования без ложных срабатываний мы разработали специальную версию <u><a href=\"https://revisium.com/ru/blog/ai-bolit-4-ISP.html\" target=_blank style=\"background: none; color: #303030\">сканера для хостинг-компаний</a></u>.");
    define('AI_STR_081', "Уязвимости в скриптах");
    define('AI_STR_082', "Добавленные файлы");
    define('AI_STR_083', "Измененные файлы");
    define('AI_STR_084', "Удаленные файлы");
    define('AI_STR_085', "Добавленные каталоги");
    define('AI_STR_086', "Удаленные каталоги");
    define('AI_STR_087', "Изменения в файловой структуре");
    
    $l_Offer = <<<OFFER
    <div>
	 <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Наш сканер обнаружил подозрительный или вредоносный код</b>.</div> 
	 <p>Возможно, ваш сайт был взломан. Рекомендуем срочно <a href="https://revisium.com/ru/order/#fform" target=_blank>проконсультироваться со специалистами</a> по данному отчету.</p>
	 <p><hr size=1></p>
	 <p>Рекомендуем также проверить сайт бесплатным <b><a href="https://rescan.pro/?utm=aibolit" target=_blank>онлайн-сканером ReScan.Pro</a></b>.</p>
	 <p><hr size=1></p>
         <div class="caution">@@CAUTION@@</div>
    </div>
OFFER;
    
    $l_Offer2 = <<<OFFER2
	   <b>Наши продукты:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="https://revisium.com/ru/products/antivirus_for_ispmanager/" target=_blank>Антивирус для ISPmanager Lite</a></b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/blog/revisium-antivirus-for-plesk.html" target=_blank>Антивирус для Plesk</a> Onyx 17.x</b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://cloudscan.pro/ru/" target=_blank>Облачный антивирус CloudScan.Pro</a> для веб-специалистов</b> &mdash; лечение сайтов в один клик</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/antivirus-server/" target=_blank>Антивирус для сервера</a></b> &mdash; для хостин-компаний, веб-студий и агентств.</li>
              </ul>  
	</div>
OFFER2;
    
} else {
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // ENGLISH INTERFACE
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    $msg1  = "\"Display _MENU_ records\"";
    $msg2  = "\"Not found\"";
    $msg3  = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
    $msg4  = "\"No files\"";
    $msg5  = "\"(total _MAX_)\"";
    $msg6  = "\"Filter/Search:\"";
    $msg7  = "\"First\"";
    $msg8  = "\"Previous\"";
    $msg9  = "\"Next\"";
    $msg10 = "\"Last\"";
    $msg11 = "\": activate to sort row ascending order\"";
    $msg12 = "\": activate to sort row descending order\"";
    
    define('AI_STR_001', 'AI-Bolit v@@VERSION@@ Scan Report:');
    define('AI_STR_002', '');
    define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
    define('AI_STR_004', 'Path');
    define('AI_STR_005', 'iNode Changed');
    define('AI_STR_006', 'Modified');
    define('AI_STR_007', 'Size');
    define('AI_STR_008', 'PHP Info');
    define('AI_STR_009', "Your password for AI-BOLIT is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
    define('AI_STR_010', "Open AI-BOLIT with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
    define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
    define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
    define('AI_STR_013', 'Scanned %s folders and %s files.');
    define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
    define('AI_STR_015', '<div class="title">Critical</div>');
    define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
    define('AI_STR_017', 'Shell scripts signatures not detected.');
    define('AI_STR_018', 'Javascript virus signatures detected:');
    define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
    define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
    define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
    define('AI_STR_022', 'Symlinks:');
    define('AI_STR_023', 'Hidden files:');
    define('AI_STR_024', 'Files might be a part of doorway:');
    define('AI_STR_025', 'Doorway folders not detected');
    define('AI_STR_026', 'Warnings');
    define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
    define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
    define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
    define('AI_STR_030', 'Reading error. Skipped.');
    define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
    define('AI_STR_032', 'List of invisible links:');
    define('AI_STR_033', 'Displayed first ');
    define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
    define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
    define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
    define('AI_STR_037', 'CMS found:');
    define('AI_STR_038', 'Large files (greater than %s! Skipped:');
    define('AI_STR_039', 'Files greater than %s not found');
    define('AI_STR_040', 'Files recommended to be remove due to security reason:');
    define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
    define('AI_STR_042', 'Writable folders not found');
    define('AI_STR_043', 'Memory used: ');
    define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
    define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
    define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script. Please email me: <a href=\"mailto:audit@revisium.com\">audit@revisium.com</a>.<p> Also I appriciate any reference to the script in your blog or forum posts. Thank you for the link to download page: <a href=\"https://revisium.com/aibo/\">https://revisium.com/aibo/</a>");
    define('AI_STR_051', 'Report for ');
    define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
    define('AI_STR_053', 'Function called by reference');
    define('AI_STR_054', 'Suspected for obfuscated variables');
    define('AI_STR_055', 'Suspected for $GLOBAL array usage');
    define('AI_STR_056', 'Abnormal split of string');
    define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
    define('AI_STR_058', 'Phishing pages detected:');
    
    define('AI_STR_059', 'Mobile redirects');
    define('AI_STR_060', 'Malware');
    define('AI_STR_061', 'JS viruses');
    define('AI_STR_062', 'Phishing pages');
    define('AI_STR_063', 'Unix executables');
    define('AI_STR_064', 'IFRAME injections');
    define('AI_STR_065', 'Skipped big files');
    define('AI_STR_066', 'Reading errors');
    define('AI_STR_067', 'Encrypted files');
    define('AI_STR_068', 'Suspicious (heuristics)');
    define('AI_STR_069', 'Symbolic links');
    define('AI_STR_070', 'Hidden files');
    define('AI_STR_072', 'Adware and spam links');
    define('AI_STR_073', 'Empty links');
    define('AI_STR_074', 'Summary');
    define('AI_STR_075', 'For non-commercial use only. In order to purchase the commercial license of the scanner contact us at ai@revisium.com');
    
    $tmp_str = <<<HTML_FOOTER
		   <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
		   </div>
		   <div class="thanx">
		      We're greatly appreciate for any references in the social medias, forums or blogs to our scanner AI-BOLIT <a href="https://revisium.com/aibo/">https://revisium.com/aibo/</a>.<br/> 
		     <p>Contact us via email if you have any questions regarding the scanner or need report analysis: <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
			</div>
HTML_FOOTER;
    define('AI_STR_076', $tmp_str);
    define('AI_STR_077', "Suspicious file mtime and ctime");
    define('AI_STR_078', "Suspicious file permissions");
    define('AI_STR_079', "Suspicious file location");
    define('AI_STR_081', "Vulnerable Scripts");
    define('AI_STR_082', "Added files");
    define('AI_STR_083', "Modified files");
    define('AI_STR_084', "Deleted files");
    define('AI_STR_085', "Added directories");
    define('AI_STR_086', "Deleted directories");
    define('AI_STR_087', "Integrity Check Report");
    
    $l_Offer = <<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
 <br/>Most likely the website has been compromised. Please, <a href="https://revisium.com/en/contacts/" target=_blank>contact web security experts</a> from Revisium to check the report or clean the malware.
 <p><hr size=1></p>
 Also check your website for viruses with our free <b><a href="http://rescan.pro/?en&utm=aibo" target=_blank>online scanner ReScan.Pro</a></b>.
</div>
<br/>
<div>
   Revisium contacts: <a href="mailto:ai@revisium.com">ai@revisium.com</a>, <a href="https://revisium.com/en/contacts/">https://revisium.com/en/home/</a>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;
    
    $l_Offer2 = '<b>Special Offers:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="http://ext.plesk.com/packages/b71916cf-614e-4b11-9644-a5fe82060aaf-revisium-antivirus">Antivirus for Plesk Onyx</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px"><font color=red></font><b><a href="https://www.ispsystem.com/addons-modules/revisium">Antivirus for ISPmanager Lite</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px">Professional malware cleanup and web-protection service with 6 month guarantee for only $99 (one-time payment): <a href="https://revisium.com/en/home/#order_form">https://revisium.com/en/home/</a>.</li>
              </ul>  
	</div>';
    
    define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template = <<<MAIN_PAGE
<html>
<head>
<!-- revisium.com/ai/ -->
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css" title="currentStyle">
	@import "https://cdn.revisium.com/ai/media/css/demo_page2.css";
	@import "https://cdn.revisium.com/ai/media/css/jquery.dataTables2.css";
</style>

<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/jquery.js"></script>
<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/datatables.min.js"></script>

<style type="text/css">
 body 
 {
   font-family: Tahoma;
   color: #5a5a5a;
   background: #FFFFFF;
   font-size: 14px;
   margin: 20px;
   padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #DAF2C1;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #F2F2F2;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
	font-weight: 100;
	background: #FF0090;
	padding: 2px 0px 2px 0px;
	width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}

.offer
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #F2F2F2;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}

.offer2
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #f6f5e0;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #CEE9EF;
}


.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri;
   font-size: 12px;
   margin: 10px 10px 10px 0px;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
  color: #FFF;
  font-weight: 700;
  text-decoration: none;
  padding: 2px;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0px 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0px 0px;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #F4F4F4;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 <div class="offer">
@@OFFER@@
 </div>

 <div class="offer2">
@@OFFER2@@
 </div> 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
	<div class="footer">
	@@FOOTER@@
	</div>
	
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
		"paging": true,
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending": $msg11,
				"sSortDescending": $msg12	
			}
		}

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending":  $msg11,
				"sSortDescending": $msg12	
			}
		},

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
    $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$g_Mnemo = array();

//BEGIN_SIG 19/11/2018 12:22:02
$g_DBShe = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$gX_DBShe = unserialize(gzinflate(/*1542619322*/base64_decode("bVX9b+I4EP1XvDn2oFIpCUmgpNvqKLDtXT9V2L1dVVVkEhOsOB9rO7Swuvvbzx67tFodv5A8j59n3htPcDTwop80ck9ENIyclKxwQrhzQiNPIf0gcr5XDUpwiepGIoyKNERCclpmOqavYo4jp17XYk0Y05CvoEE/cj6ldIMShoU4dZasSnK0lNuaeM7Z+5VUVvUvyFIWzplmCgx5MhrtyUMD8XC4hwYm8dvFFKfpViNDu4+u90HHJujzC5BpZKQQT6X5N1miuQ5DS9jsaSE8TyuxoWw3f2XwQI4wci5xkpNURaMxW+ElkdVXymWDTZQV5NaX+7M93zLOZcWL4RtjYPHrKmnEOzy0qb1WeaTkhQVd6ihycCnpG/vQshRbwMgLSQA/NpmY2u5ywKBoZakO6ji8QF2OuiswEsrWmRPUpJhVAu1wxpsdlbCsqw/VKa2CCIEzgk4R4SSLOamZapiO8zGcfOz3nUPkmL/XwIMT2K918VTuteociZx5jQuSts8+LTlY3dcaBW7kCCKTqsop6SBd0Q8WP5NljNOClnEjCC/VPgdZUi2gr2wlTBC66qyaMpG0KmPyQoUUHQcEiUGRgwPYoaUNVRp0hTpUxAlmDC+ZSt8EIVym6IM6CnOOtxY9bKVU6CjNb3m0E35geDqtmvBCoN+R+zJxXfcAnZ7uH39COHikqkspR727C9T7BrC2yB8oljJhTUo6rXg+e/g6e3hsXy4W9/EX9RaPL2a3i/aTOXZk2njJ3WfhwyX1tW+Bqqi9lrJOj5KqXLUP25t1pRR4fUtWme4h/aQAal5gt2fr6NW8SnpiK3q50piw3hYXuFdLrryNRVLVBMK1i31fCb7BrLOijMQZkbEilaTUgusY3zaSkveZU2nk7W0w78FyYFuwdXF9dz6+nj+2Y/WDJTAnhJ17Y9ragvavxhhUNdk7ZwRwaGOUormrpIB74Gvt+wrKCkxZVxSy7tLyiB1lVZUxoiQqIMxOCNVt3HWh5/2RvVlTPQng2oPkgR2V07dRGXg29BHdr5WUL1v0BLgdB49JlRK+M5gWyNcD8kO3+5suBCVFeuq0wPPxZDK7Xzio2zUjMLCz4OmRV02ZdtyDJ5A5CF+HCi3GUr4lpwXwlIhTzPMJJ8+fOSVlCuIEQ5N43mfM91OAbNlX+ZXn+0OARpbhcjy5mk3R+Xc0X9w93MD4da17N+qKqW+CEQXIQ89uu+FH87Xq6DUuv3mjAaz1zeCaEppijv+F7g99eyn+omWtRlpV7AAOTKxXDv1Eem4JYGjPvVLfnXnOm1pd7MqcO/h/mqGhmZAyo7tLbGiODcj9jV9mQWkIRgY8v1b1frn9E5IbuHbUckmTnJE/nJN//gM=")));
$g_FlexDBShe = unserialize(gzinflate(/*1542619322*/base64_decode("7P0JQxvH0jYM/xV5wokkJLRLgLFYYmOHE9v4BhwnYbC+QRpAsbajkYwd0H//uqp6nx4tQHIv73NyLKSZnu6eXqprvSp4XqlUq8/vus9LO9HzauO598LfG92M/Cjnr/3n16YXTYajViG351/42R1/5u/t+tG6t9N9XobydaN89Lrp+bc5LJ61ildY8XrZKP7m7fFPB29PofS538mxFqCNWfitO/Ez9DgrtrcLj1fZ47VN9fi6vz8ah9etcTjqBe3QzxSK7JmCv+5niyGrMZ8qFFgV8GiNPbq5JR5NXfeGl0Ev5a+dBxt/lTa2L3I7+o9mMB4H31l98h12poMohB6pQrzmOqu5wTrVvYIOsQKt10dvD0/988Lrcq8KNay1PhyfnrEL74N+WKAxjNbD9s2Q/Skc/1LYSR2y192ZQXUNVl25sqXXd3L4Xx8PsYJRMA76ZVbFjz/Gr1ewavbQnb92xdrl75BUcEcUaV11e5NwzH5CV9jzqjOb0JmyuR7g/S9Y4WgyngynoxE+2Y3Y6LC/4degR91mH2t3+KkGLFqfwZVz9pGWV9Nw6QI+cFiwhFwwW6wDlc26Go1oHZtSbbQybw7P7mGA718eH/9ydHh/enjy6+HJPX/prH+e9m/X07wJ+XGnqri9vWV/mw+sjk1FtG6tQ3jBQtAphPByefi1D98K7B8bttZ4OClXqdS4O/ielp2CAmmYMuhSVj4cdDppOUCwM3CgYHy2YYK2q/qWYE/7t3flfK00W/Gtcmm+gJJeqRh0itYr+cu/E2vAfid8IY2aAPmp1+QuxdWU8c4/exc5j1WkreR0ATpbEPdYRUQiymXcP9vPPX+tsPz7Qz/2oZMFoEI4uc/oUXEB32UPi8lrGfP2cxz+7mDCfq0VkDiUK7iDatoEmcPqFdmwFEOPD4sXnnvpwtfgIsdePG2/M5+igsdGTj4BG+lg4w8/YrupxccCBxXbB5JZrzz3rFZ9/1vlKsM+C4VsTlYlL+Q9j1O3MhDOrW2t/zQp1391B1e9YMIq02b/MojCRq3VCdvDDruT5n1jPcsV/egid/BfzWYaKCpRVdVNIKKbjXmtrFC1XjGQU1gNxaL/g59r+jn4wwiV8RtLAq3bIjqe8TP9Tt3PsKlu0Xrxz6Ooi/PchNPtrlqZedjYXTgeD8cwssPxpDu49jMl1oF9Iqz9YMTOENy3uFvLQM7KpTIszvgepZZ2JM1EgtnUfwLhlHf8CyjavcIThl/NiF0nCUQZKMRW6blHA2qN4v5ypEGN9QWnEbQ4KiX7fGB9/RqOo+5wwPvuwZleYB8enDcwtvvsuAlbo+mk1R4OJuFgEuE+yu3tdwft3rQTtoYDPMvZlemg1x18we+1Ui31fjhJvR5OB52C4AgqsN1rNZjfbjQJxuxgYGWvpoP2BPuQY286/j6atKbjHs56Nxx08EFkRdjB4pw/fBG2rtmFKNVMeUGE3ccXT6vXR36EEd/2cMQO2vTNZDJ6XiyygpLKAc0rsJEBUoeEG5+DPVWuOk41fqTJHY8DeIsb1Dq/7grre/t75q5Oa9yP6MH+noOCYNf4icLqwYVSqQtK9dhOhd8m46A9MTgPtiX2Ot1QHAPiNNDbx51a0o4yWC3RHjS/B7uRf11qxXqjIIpuh+OOBz2EeYv2mmw57nnnbBHDXqEdzG8BM2COJW+M0cnCcsenBxuKtVaArbcHTOueWKLERFW0TbK/l4HteM86GY4nMHKZor9+/nn9gtGEeqnEqMI6I2rr2T0cxMWtA134fHGRE7xlhrWd3cPWkeRUt7TW+fw+E7PrOGHYxKRuwqATjtlZ8fPZ2Qe2pvnBYrEF6YJYc4zZydPxmLTedMJcQc6lvOUghbi4duInJZxOe4wUXbEpPNh4fXFXyVdn/PRSN9kdpFNzb9D+rQL52tSZp32ikssyTDBbs7QYdCGkIAdS10Y8J+hRKsNeLQv1Iw1kNCkP1Aq+X4cmPRQFoOoypy0RIy6dnl/ojIejy+G3KVs8/BG/0B72WVWCXrIXoP6ybp6+PDn6cIZCyfuDd4e8u7yvQAU3Ne4kx87F27tSvlIu4Xw4Tw1PnQdFdoYiz2EOQdUeWM7JwWScq4nQDpYi1JO27pu8TLUmTk9ZbWbvOds4BdbhMuyaPbFtVuAeoOE72HP5WZx9qNaFNKYdcGK5MnbjB/iPHUZ0JqR3+P1cE3kiuUf8H9L5VJr942Rvhwq1xyHrXEueVhlWxChBArDqDZDIbbMzLahIjittDrYzZlmiJIy0Uhkx+Goj6IXyHmzwfNovpLXFAYSrToc7tdX0qLpzxjIxWtdMp3fwKvtAMjljy63VMlcY0p/atkl/Mri1+8GkfeNnMu0bRmaAT8j6jPks5JADwxFqNq+CXhT6WVjn3cE03DGGlw1fIZc8tX6uCIvKz+aRRxInziUb9i87s9lMdFGwSK45ZgPj7cByYusMVhdwu+PwK+d6JW0qAMucl22o96+VOFtpiOF0bu7JjcG+WK9hnbkF66R9LgRBbKMcXxf4AhVJUw9IF8BoVrq5W8hFI8baTGCYRbGM8UjerAPeRx0pNZRpKmVildUpssQxdZujw4UUA51mNL1k4+hntvJl1sTVkM0MrAiuuYA1kYcFsSfIcofrCLAbVewGDi0jlBF/U3oWDjhk2GhLfjx5K3lpLHs+DgYdxuvBi7YZR4lvgHdgdDfYP9Yh4rD5OQg1em+H7QC26nNRqzhKakibahWxWdiYtCbdftjqdfuoyOrkuPSeyG7C4EQ56GP6/HOardud1YQtf218EwnZytfIRg2JWMN11OoCDj+rdxSHwJdz6k71j48hEhTHw9q7NOeW4pRQir+0dfJE+2h6URFWRkH+unvVhAPRz3S640HQZ19aeKC1WkAz0sVuP7gOoyJy26xwOl9BEgrP4adQLWZwk+oX1C8Sa+h3RkzrppJ+cVxSuoIvDQo+fJ/UXX/4lZ3Xo96QLZYOaNTCQg40fKn078NpKhiHKba6L7udTjh4ltb0XNgK8WgN2FArNOAseZ6e9EctGCPgu1LLcTLvqTjMi9L91YAsVraM43bVDY+sHA6sWBZMmoqt22UrkppTOBJAzUlK1JTXHXSCSdDCveUZOjLgBvA86QfdHl/R+dgn7yBVFjF+qjX84mktaTdUG3zy6igD18zjI2iuMkrpwbTXazGSLGYB62g3uXJrh5SteOqwy/x8uWr3hhEO3xXMGxOudlKm7rSOynlgw+IsdgHlH77XM/MlAT7UJgWIlVTUSrIwNA+CiZk9cWMrFrkajsKBXAGMyN6mDcpLhW7H3UmoldLeRQ24ej1S4eOV2OviFOBRuQ36J8Y+ROs47PAE8qlSLPiGqxNJrhqAoAn3UTAIxteRqNehPUmzBcLXNz7on5dI5sLvZe17RfteFUr3mdEVODU/w/iU0nhnHE6m4wE+NCTCUIeDd6ssFQVqQgWdl7sVX2ffccdZmswpNS477As9glL1izkWqvB9UCnI28Qwqwnl3BLVimegaTvS5l2KnAkLlMrqC1TybaAlGkW9ILoJo7iqRD0XWx+m6rsOx11DLpQz9vjG2cnBy1823h69P5RLBisERRaWKiYVwxpJ77DJTxXHW2nTlLoDDQR0dr2Y3dt3q3BkiX23KkevglbKlmaeiI3uKjYJGPaYsgs4h/SyZ5zSRKzW9I42R6izaFRXZ3yxNvEepC1crderdRmOLbQllhKVLEIgOA9ABeUX/DRKSjv7NJ3nmkx2sWRnzarEfm7AKVSpViwBcLU3uuOUFi/szOD97riZ7MkMXNy6lQe7VkFjs7k5C/jMuGUO61SmS7lUGkD4q7UEtXv6329+Ry2x0CQ3UGEiWa0CKfSZFHtxV2ZTdrveLKyjJLwjV15hnU8Rk7ybpICR5GUN6yR1ibKmocyXfsH40H4qZOT++yhs9qe9SXcUjCdFuLwBbBTXc99RS0ksJwlXsxlxWvje1GpdKGkeLhyKyaaugvjHLqR9OfP4cyMNIjw2CaRzK65tWtJExWQtU/9jWyUbQEi368+9zJuj11vbAfCUe8JCybvKJbbYkuKvBevKpRdNIzup6VwaW7wtXj87qRnHbOgavoGmgUg3iCvByhx0SrSFDD5IWDjQTPicsyrY3X44uRl2mqNhNIGhedEdMDaEXQdhA8Wzd0HEpPAcVgG/d8GEI6kdl1RkQSarCFFlWQo3CiY3YP9010Y18a0ojlf0YkAyuOkyuwlDhs0IonNDb3jLBX+QfWQJLjqCaXsP5QtpcYs5QHBGRPeGoEvKD0JQEE2/I9nHTaSdlcqqHUevjFU6jhQ55loxt8OW5UfsOvXqJiOf9MLqXZFVBuO/st6tG+Onc3W2jKD2Oi9ubnNnHcROD8fqLps/IKr893Dc4RMqTH/YTzT6bSdQdu9l/9dzRrfJucXP+UVf6sfx6Zp4y/nk0WR+7tAYyQjB3JJcqXLO2mRM4MYFe4tz4Mjo+7wntWJc+7KJZLy6kIxbTNqdPido/EwX1kn1im2oTi3VJb1DQOQ3N+f5URTYa4de3tZz57J39fysIJwafGEdEyfWJvLJDVv/K0VCh3WGbT9l6/XkWlqar+G0GF0JYHFoAoUpO8cdoja3uPDFWITjknQRmI57yjojXGIKjHkoMZpRmonK6ZGMR3fQZiJtN1g7crj1EqqrofB60zsXRgXSGIjr2pHKppgaEFoKmPS0vNo6Lx3DvIu/XoFRryxQfLqArItR0rhF2kSsErfQFlDzRpkkJW5el4LP/jj8z7Q7lj4E61wFHCuLNaGlrlbXyWszbezo9I6hzISO4cyyKQZ/DMVyu8RyuJlPy1WVhoOLppd7OvAy7IIw3Inf2L0Kcs6m9x1fmNKgQdMffmNcGtRHPCEw7uf+BiM/bFtfEBefRX4VVep72ZxD9+GvtcPB9c3V9X+GqCcNx3+2/3PbcSjNJIukhkZVlhG7jN9VfWFzcCH14NqzG+yiyXFtAY2t1JK2pKb25OOvK30WKEqtJywlj6HSIB34MqJFP+gOTAWWycMS6ySObuCg2CbYe4Hs1a6tDt6qaSZ77F53xGg/o0HhgG0u7+Tw3fHZYevg1asTj9w4/TUyUkQpv+A8JBxdZmxTt3cATnjgUOb7A9QzSqO/tHRA9bxfdXQO1u1M8JakO0myazxY5E/9+GMKnbCWe6w97AvhrikOH2AzUNJ7uM7BX/vyReOsxqvK7awjG618mmTFXLGZlrQupgXXNpYaVm1V4AFYMWkVEaVntO/oLPGzbGXtCK0doxj9YWfaCzd2pavAzaTf4w5pW5vodEMbbcnjqwA+3jfNZrpc2fQLJb9QRv+uNB1jYgGlwWukyG6VU5VSVbo/zWbOAmVVwHG/WqqQ2xeUkvflCk2R8KWEqK0t9EqvxX1e2Mcz3alJOp/H+GtumdQYR3k7L692gCIx4pYrfr6Qv3HdLFNGct9G7Qnt2Rfef3z7NrGOpvHLcXtx5+bVuVEWBfh4oyBZkeQ6BStJuRcpD/8ZapSJ9Asnkm++73cu+FIn4z43CvMTJwMOtniWFcHnPnZBP8ksxb0cqMTjqmnXlnw2obt1CQ+mhez7XLJCR0Muugl7vVb4LWyvWsXO4xtfzc9JU+dtA8+0xXiSTEYwZumdLDEmTU7FCozBYNd0jtb9Jy12rlS8YBMV2x8jo3y5z/1b4nGy6FjKeAo2PV4avIWgUOZc3vUL3NRx2b7AOURufxtYi2rloTpcLo+ZzwrWAr27RBF6x2yTHdtt5KLQUJ3eEdd1lqQMrMu+k3Gpxiy6FUZu4epAGm2BldDYjKYH7+FJHZ/nUOd4u6S+SVEJaMxLoSLH88te0bx7Or3sdydwlRgWvstJ+7aN3Eql8bg9cUezDCNDYq5wX3t1/PLju8P3Z62T4+MzYvBUuRcvXqQPj1+lH8NnPP1sVpNnsx6bzRqbzfrfOZvVpWeTjSIbzMQR1mj7/xvoRw10iiSd2GBLtyfG9XhFHiDlb7T8yIezCYRXby8vVHdce0UeU365lAqiFK/L3k8uHUa5Ihj0FAruXSaVwOVqPsWF0FSTPUnud3d+3G0vXWQnN3uRjM/6B+cwE0OKXbDHlauxh9k1kk0qCTZs1h/+JEpDZOHR3yGhOXME06wEeWGymtiBkbJimMo1aKSutSQ71liuY/o/JH+kKLPNW2xAcTw1PbLhlMv3R+vjyREuxnw6jKIAzUxsmwjtgLkJWJ+uutcb3cHVUMYU+FxPpImP2w0MsjRCdhKEM7GpRKSgsSB65C6xzBZXO3i3BPNdbkqFRDr1/Hkqndf0U0tSjYoINJk9SZ8oIGc0jXCzLGtQJecr7IJGgJYmeubiXH0MNJ86vtPBPaxs7HShX21avit1onBiUaCSs/4As5xJntnRnOGv8xA3LmJ1wAYlPe19oEMp2ksot+khIOvk58C19uQBsber84U4CFyvwt2lYjfsnpaN1c8LpdOGOUBTN5V0TdkL0gTQQqzoskfOzynvHaA+jKywT+RHh+MOFtccQth9cLPBO+lvaSHHKKd7VgfFHO7KwzdpQHDwttHizNgw873O0/fexTlFmlzkMv49/seexy9ZeQfLxYeFHjdGEGqpZO1rCc8bpkss41fwTx4/2UJ1zsbix6qux6i3/m2THZcVML02uR+tZSJbUPemOBtwFjLwm8sm5RL6c5c27WGO2sGg07WovMG86lsZ15igKGx9VV4IJ2QcjYqxmPh50iWhuMwWEXfjStMhIAuaPYKzrA8+yPP7xDgNryBqpQ6Sg7x20k2GUzjxHc63eVrs2R1eZH7giSztu+OEDEM9+l1gjYcnr34+ef1Gt2HL/cItl8/Yv0541R2EHfydfnVwdvD26PXh4fs3R+8PVTSyGCvyYGJE4+eg/QXOxGg9mEzC/mjyTBl0Zr5lGiXdzNdueNuCssLgCJWCP7nrJmojvXEUeXrzuM0Zj8Nr99farPT1cPy91e1olbGrLTzvz80SoL+OboaT1mTUS6to5bR6zzV2Z2MXmGLVmcyKdWLkdgF/ihHhDrGJ1cNEmk/QriFX1Mr/mV0DDDpEZz9636hSy2+d9k1/2FnmgVKtVpOEC61JjbqcgiZSO4pIK/zVHSUQcIfsQFT2c/oezlsioEmuqcBq8Y4zZmTU7rGG/EKve4kcbMFqaxACEMOHdu8PVkqe00J3W9vYVX6JUtFfMre0dwi8rk8RMjBD8BRcOoIln5mMp6E8amlcMEIefRRBMY6HLeiY8QuTDIMUmHo3wKz4tem9pDfbOGMSnpfi79n0JqxjRdSrp9o3wZiRiuZtd9AZ3kYb08nVxpaHtU26k164y973RZF/ZReLsrHLYee7cdajw1Yq/eKmvIvWIvY3LcwDKTAgeTCo0glZly6khUh4ZlMhzxB4fR9NUewPlOBiL/vlcv/xPeiDUqPvO1zDdMucINXyCxImMVWsqvlmOvW4kOLZ8YysbrwE3hUSvXxRcNO6GYdX8EJ0+rNXwC8visEucomCdfalWXHOftJ3qu5JoiyXL4pyBnEtEABBqYYqYy3YGywyYbOZppdPGxQr2eGOvShcEC+rDYxhd1wwrIlV5M3ZM8upERarb1FRSQVpDNByuD0n2t6OlyqZW38FcQkMU2nNibBSKqUNMXlV79Nmk+tDEux2q+nABM+ygmlTPPzEHaGZaXBvJnEoeEa13g6JB0iMM2nirNPa4yhWgjbdkJi4GwIcJZ3cPYo45176ghXAP1lYrOdM/Mn5G+gUMLcgKD/AoMC+Zu8q4Mmzxx1d1+7I8Ik92RKeK06XAe7uTP4VzV1yzdijKkv5mdzJlu9ZLBDkTjjgG8NUELYO1yPKLlkugYxW34p5qvIgdf8WnJUa8Irywl01P8uqOOg1wrgpcfAKRDFh/zVfHrz8+TB1enZwctbkUcnre9bdw/ev+D2qhJBybM3VsxU9s32nzddA69AUVahkAkugLwXXMmLkbCeFZpzzFelHfkGsSrLnyKUpjEkq8LfjF4ro1cudenf05uDA3y6ZSoY49sKKUABa9KNoBwn/NjrfZ2hv8YBvb4fgx9A8j7e4iFoRmrg0/MCgxCZXXA1HqCsBdyiqDAXTDg8V52XZtyrpVHhA405hT929/ost7mF/NA6jSETHwoyLNd9iExQR+gBooJtpcYMN4Y8/PosVQ/UY1zVriCu8C8JZqImdvNPe2K+wbkGvy+yPhFVDZQoNHMWrgqtDhLF7+3sPDjI23HBYdQH2sukhcyhdmiH6XawmK55HD+aRoTwgBaVk+HUZQYa26rK/rgi3PVgie/KoXqo1jU4jOhFomdlyqABzYVVv2GjLhDO0DV6CGYvDWQpLRPPRTY6W8DH8xo+BgcUD2T04N3LFi5wUgSGWIrJ9ch1BFfQ2SDUlhJFwMnQIJmlwNLstSJMyh+CiKJg495Ep0XE86LbYhGFPO92IveB3CvOMBDBWieKpdXyiTPQ9wtZB/G0xCS+TBZnw9PD0tCU8JnOe6EEZ36DEQ9V9EYQJHLxvOZ0ZYh0QVDbLrw9PDk+Ee9PB+1e+5saSFHV3R1xVezj8gnIR3ESQrzL+4SJulp3ByiUvFkaf8a6Hw2vGQxbo2e9MXA+/qV83w6H4EQx74ms/Goiv46B/2WNng7gDUYryafHtEjhB+G56ZK91m1z12vVJ8WpF6oubQuzn4yhsL3MGMq9e9xxqYIP2TGJNyKMq/SJqs+052e0M29M++k71uNORXwDZQkwkenbCxBbS3s6LIn8qrYuZiDeFTn2JnnK0DP1569CPL0Qsby9GXwKB4Za01iVHL+NrE30tGw1Ym9xTB1A84GzJApRHk7NO1rYmYXAlSwLV6cuoMnJsb7GfTaNpv4wQIipCf5m62fGhKt5ZUB84wdIfMO4IgQZcfUIZ/l5GlK7aVlVH4pTribV78nvr9Ozk6P0bUpaR12EX9ocS6azjZ10cPzChWjiNr8Rvh+y9KyJt1mVkDfuOVmcS9DDWxiwUoe2Z/WIkcxo2P2K5Xd3hlC1YvAirRbeAiOu8maZVtADrgLRZmilePUK+tcrIrralHQgUe0i319sdiTnWei9uqrvHvzBJu7prhvwL07Fe8P2xo6D+nWa8rgKbnfGyyHkpEmvG0pZFXHM8vpbvNEQ4K1eTvZpXMiwaIB1cAQy+174WeNN8lJC4o9hgz/fNvrLvO57Skguml8DOSuys3Y/FZ4hQOEHNoDO8D8KnXvSCdwoH2WJIOFSlzwHoxNgix7Oli1YEqcbEy9weRiRji4os8JfU47+BaGJIxxov7aOfog3TVAB9GRoalSeulEH8NRiwb+m8X8iwcnu7FJk0uYwatQ5MQiu7c5ETrvKFnBGSQq9CYXk2nA8jksCm+t5O4lswgZgvB07rQG6eJZePF94R2HBgCMHdGnvUAdYgJCVZlodsMnY41sRdmclkNGcIv4bKg5h3qnduovHBmOs+orSe2CHZnv6FS2qlCOm8x9YFj5GhnshAkJMQreiHg+vugLWbQ00Av/hyCFaZ3L/ukJn4yGpvHbw5fH82A7li0BkPux3/PvgaDCbXQ//+MuhAKO1f4YT9+GsS+ow1pfX8/iXMQI7XejJFOut/Zi8W5VRYkX9+kn/rX1D/KjKG+ujqHfpzg/Ay7LARIqt/ob27XEf9DOfo7ol7uwdm7R6Yt3tkw7Ip//z4BJeIszbOQy1VlaoDXjLFXhGAAuE1u8RG8qCW87fY3gu/KN6OY9dWl3RacES5Mt7CCW4aLxqXwZarf0csYwrpq+jAma5TQLP+7UvVxSLcL53USf1hschIKZAg7ZTjV+QJxzlAdbgRlB0woFzdkSM9hyEgCodc7pygfpL2rZqHaHT7HNBw62zH3s+Gh6+2fTXSXSWgJ9AhFotUdXbP6JWIaOO90vw8sjmjXYGITMU/q+fUkQEoFbIVah+OrIamfsrt7yXrfuwDSkcmEpDLW4KjNhEPLDzVjKjKTbaysZUTY4HUOJBb/ZW/AifBK+cyVIedYFf0vT1l8vVg4iea/zTMbbfNT5sLrgPlM034GaamTyC1NgkeWDt9IgNNP37suCC39gwPTOKChYdmb8iIupcijpgJts+8FGwAwRX7muVNZ2kQwa9cqiSwbR73oAm/9jy/cGEFZSdh1M9ZRtQoRn7XGg5x8bB1YEQ0+Cb3rl0xDrPU8QCRFWFUcdKkGk8RY90s7gpo1EvS/Bq+NDLhgK8iBSXUcN69mGKtayQLgQZrhm8lE0JaAUfLhJpvRy3QPrvxOHSlJIFp+tLSxgk1mWFWY77FVjTizGTdPABVdG+Dy+pRkTE04IzA1Qd8DE0zF+PiAdQVlqtSxlptaAw+lCV/EegJGwrOqcJ19WB8XPRFgib33CfGJoiH9HqlYohd2dgFI9142AutTukeD8bGQUX7thUuCI++uNx9cTnGf2kcitaUi5RQHwHn8XIkuZ5/fnGRe1HUHttxNQgncUMP+9IpuZQxkragpURF2MSKXl0utqCEUcjaeNw3js70ll9IO7zQNHQSRnPjMYCgBhM6sLXuC+X8SgRV13up9rkyi1rQPA/1m9mNspozLU7Qp7ComWbKkpReO90Ql7FS2TTDcwx6iGaYVrMIlpg9dVJbBXUE1XvpBkLqL87y4LFtn9++OvZ1JoQ/KmmNcdXxI2NxB+KLjKzOyIWAMu3WwjcGMOFmyxBTkt90wWuKfWW+qYoJXeL1XW9C+Qe2E44yGxqHVbAD+PHLBqidp70LsHPQX8schnCS5Woj8Rg1JD4l7+3vqZM0QYmwLK+T15aQTDxBpztJ2xnWLyX6854hgr5Q/HmWSAWI77m9fYkGJ3babU7DN7H5NdE0Sp2bZOeKTbO/ENtFby/isZvYKEjyMojTQvNnvZUiu9wPOgFDghrTucjq6GQmXEOA41il6wpPZ4muJ2HpGPt4OYwZR/9RsgTd7jL9dyPogDg0S96Mcx5KeMHVZ6EmYBKW2QXxCpdlfBxPanTmYS0v+ZjFcvkapGMZMR0rAqOG3ZBaq6W7JazE0q1w+SfREC/Wo3BgVKTKOocyGhFzUX1x9KtXpIvlmBxPQJEmGaVIdU2AF1QnHqQBRU0CiKcbQNVp6kzuqcCWKGcQMuefZxe52Q7nSkAdSaHRwIOgUx3+kuqA9EyinZzr24K2AXT0Ls2VKMoDQEmKBBzJmQxJlZfMVqPSc2nu5PAL7qjt1oJfcDSsCxl7J22NvxgiOLq2a3O1b2yo5mrDQLp1Kr0snVeDUmDVHUpRCQDCnRPBMdGLc/R2MeHD6ChqRdpH6yUu03H7qR9zZEqgdjijxW/98njUJtlGO3qeGeKmttIhAoULhfG76HRAomrU/SvUb4EpuFoqlZavRVq7CdvdcPIWRUEB0ChB8XXjW3mOUIwsVjhol+WAsB8V/UdV/1ETp4xU2tzekJkNWX3fCi/Sh12D4RWMOq0X9Kwvk2sByG3BNcBUT4Y8q59vmPORCv9wEH3Bjrdv+N32dNxrdQeG1hCvsZ05HOHmbN/ASnj58eTt8QcIW3yL5AuzkuxxhfUetI/NNzWOiRWzeCakAz92hgCa4yr58zFB/F7IFTsOo2lvoneWwybATXwLrc8E0yy3uXZbekpTfdogIlpnGcFV/jMNx995Uw6PDNvwmxW5MZJKPPeFbkYoXwKKoXjWbBqbDRtGYZ2xjxtCaUrrrgUpPFqClyc88DDo0zL8NuGCP9TCposJqNI5QipaOC/rzDUDeWhgcUPH8uqxb5O4bK8tQ1GDNozIVW2WdE24fD+DB8yYYwYvbUTE6vyOqb8QH6jG4XGyvCkeLStmXno/pCkvgKFxMQ2/CJVaqVQTc18t1t/5EHzmXXDpx3gBLdJEApEhyvJeLMMiPLswiZe7qTy/LK6RWVFrTr0tWgK2kzN9LX5b3UlXqmQNBGkjC9jCCmOdTcoWZhXjL4QqiRqT4fb3iOq1vgYado/WvtmwQB28s6rVhlde5RsAhpmdqGeMmL08ePv2p4OXv/CrisQmVAV7cFfM5qpdYn/tyVTri5gmxKmtAOD3vpHY1TfWndFThejtzKtmTZPdJ+Rk5e+Z3K1LViWfnDPc+m/5nsAc1pxZFAkf2k8wuKzs+vhIfbFdHaiMDbYJ0fH3pPLAaQpctRmDg9V9XZ5iSGTlMCqMoGIcoS2hEK7wVsmQKJZYE27uEsUHLjyY+gxjGKXwbKnExDe9GtnfRDXaQx6zZDm7cGyYEJW4UirrZFgsr6W2o9k5t0VCI4J4/lvniPE0HpbY8pKmz9jY0HuhWmsryV42B0812lOG3thAi/wdJEATGAofcO/W1x6SOAjq+aRMHnD1aiif1JxwEI0YEKMNL42c/5k9pfB9N9iLY9Yy9Mhe42YBlPD2bnpszZeFpEeVktaJ1ZoU7nQ9GI7JftMKLodjmSxCrRBNHsL4xptJ0G6HWnQxnDAajtudaxiBW09wG9V8RvExLRia3oF0Troy3OnQKr1ZbVfWfApfdg08aXsA6N1MlGvXgsto2JtOQmcxQ67FnW+Ks6W84q31ivJa28hTWN60a+PhcNLCuwVMTwXBsZbWGOGRq2XMPcZYDQOxKv3h5w/sx9vXMgkNxlw2X7x48fPZOwDtMyH4nThDKRmoAPV7JkSRQl/nlm0ygr9GNCINmagIprKiVtqwirOlyU3hZGODmabC0h4O/aXll9J9wiwPTmgXbAUYrgor5/gXKd9qqZrEbRoPbUUh91Z3mbr/OxaSnH1tORnL52nWFTpkUyJpTssE+dzkEXlWjJgNNH705tfv7f72998KuabCFy8jPjT7NN25SYsqwo5Ig0CHpSjEft8BAybAs3mO1VwW2bIZGXcEI3vR9OLlKEMyJuvQgP844oklMXCVOGLryLAwvhyQewCDzBx3fgs+iQuJ0tdICNfKof8uiU75muN92lxhae5yD2VcBLuQA28EwWOnwBcBw7odFveZXO2IXl3ZlokCTU/1Tm6Oyz1qb0QIZiRtJYIwUX1aAGOmRf72IsY+60t0NREOGasxj3VK+NgYS1pjU1eVmEg6Fo/mySN98Xdcb6cc8bEYuIjYX0xiizDdNVJxqR22hE5U350J5WPKUbVJbRWpuddjulLjdsqmBVj3t74I/THbcahPMTS9fTNWikX2o6L/qKaUJvHpdZC+roakyIK4InI4nbAbipIjYHkDuCbnVtvfkzsNyIC52ZAwyCiXHTpWfUNLBEXE2crpSMHzIYRqjYdXNOGyiLWYe776MhYDHsHaCtimX5AXZIgGNswOXvir4izw6IVL6hTkj2Gz8P1KXeNnsX4Qwx06i3kZOo7hB/d6kY/SiQy/4x7a4jR2dEXJsGtR2LtqOoBIduYDBjgrxasiWoNfE0w2tOMXXh2dHL48OwY96OGHg5MD9lXP2pJcq1YjLALU0TuAWbCV7I5gKeCJ419weJbnOxBkfqum4aHo6rh0AdxpSSoQvilN2JVlHqJeESuWXczzPogDjp/FCORe2ZwDe8CDK5x6OF+X1YzTV7dskMQYK9u+0YriWWipDGUVosW5zZme/pbD9PwnhRrCl3kRfSUrIqR8Be3w/zgfB0FgS3JyglfSODhQKhdyNsCPsiYZMZZkdepPWpR1GM6/deODHRixa6YvJMK/q8RQuJ4zfiLGne6jy8EJPOnrxfkzxEUpw5/sDsYN5eSJu8nxBUTwD7suzim7oQ+vtm+hMcwoMtM40S0ZhIxKvLtyvoqx9QgyEA8m5zCDiAFrPpDdi7OygoM596OCsW0FhrcO5FCmkw2iDQPxYDrz5jQLUksa3nHHrxLXxo6JoB+lMb8zx3/k409ROZX/4W9j6HfKvgiJzKvvAmc/rkZHcHM4vfcz3In1noswWS7D0LJap7UA3Oa9liZQXKMQH7EKEC8c3b6YgMFXJZMm+LcLmePWdddf+jZ3SRA/EScEHGrg6qzAPRhp/fNuYUTN5pzkxnDgm/Ek1EY8os4quSPOnztXcuKUxKFBj0hEKfseTcI+20qULxpAq9beARzsdfjTsPOdMTnplH+fgtjp1EZkFjidXv4ZtidYhq6zUmcQlO1J55ZYVmOrg3peY74SqiIe6jH2MC1wJbIsYRoc1WCSag97Q8bs/VDC/+365+QNfCHDyICvoBfls0epDRuGhlkmHwo7wzZjZWqNMAou05J8Gw635KeiglN27CA/cGLxKNalWJTCOaL9VkgUuRlGE+gnpWaBX5ffmUAYA/rVobiEJHDJzpcvrI8gLkUK+fn8c1bueInsbBUOIiZcwFcazELOEHUxV7vAYwGCJiBZSjYkS8xEQC+IwTigfvhvn3mxQL0Xl4CZ5ol0j2XEsq3C8SRYu7TN8zsTGOoR1xYbT/pRlbgwIZgay15rOrJEWxPRBJf3mmlPWoCipoIuteDoWHX7e7HY6oTn8gm1G/HawtavAE4ImHcrgYgvT6Yfe1un8U5qzU8V5FiB/LvqmzUt7CZtqfG6iUbraeOT6so/9S2f5+iQXUGoGe0CTci2cH1c1ZFyFZ9P/Zl0ehVvT23hP6RBfYGTzyu8dYVj7yZ6kJvQZQUZDxkDilJk35dqpgpilGKu9oxmV7YTIVPkgHT4bxVlekc/4t69DkCXuWkTI+HDtnR5Jk1bbnq+6UaKlIHeqiL0wRoPeRW1MBiuFTEugrOVKjqKX2xFk0BZoPBMOz09On7PuoIPA98q5Zm8hiKjFbwNej0Vb+4sDRQ24T69QFUI0VqUlBYguPTqMo+hWG75ZatwG4CF8w4Xr/PGDbOIEsLzSQ9Zi19rUbk2yTO7QgiT6Ixv+0P4HfazXOJu6rrYQcXU3BzoKQAEWNc6r7Bq55GqqhaUAQHv3nkFyqZcQSw1EK4yeyBO6SBrMwnIkDHrPI//TItf3AUBi3SU1Vkzy4tDSzO1+7McjRH6PJVNo3RG7eON1kUua/P2RqCr9NKQcvR6TI4WrSqcK0FbkK3aMhlWBCHDU02qKEp5iM2yQr/Is7rbpJCvjoj5whVRaCJ9ugTf4rafMcIx8c62n82X8/Hr1Qq7Ucor3UiHHUrdPJcR6b8dmTc0krtxU6CZzkGh4NyvKbgaEXN+3DBN+mhj5eU4I8wfazJmD/sjkmSivEsYkOSe7qPiGh0d7DvKm/k16/Mh7TWjhK3dvpObllzf1X5D/6MtSAEMzGxGgssJIy3md/QXaKB3Ibjxw9vjg1cpYMeeQ3Sjb1lqKb8MmPubXqXuGdZej8dC7sLTKdB7YRUpowJw4hSPSZxWVaFVWoRLC7Mw9s6TqEHSFcGRw0dg2dL5RPDlNneWFj0ww7ihwgRsoDks7Nwq+bzwc76QUNyhKzYfNE13FUTv3GrELLMJ54dLMDLVJZzR0ZkQRPbcNAP0MGlv05nhVygmYaneQb2AjvrL6ZfR8W2z6dkcDiJ+VrZrbq4xAXrH5dW67CsvqCJ29v13d8rFdCI6KcLxxE5XoKpdhXDku6I553g0qXu2iu/WQrRY9F0ufHL77AcjxPfcQUci1OxAfdPrqB1+/x5dfc8fkjv+4ckJYyU5aUdc1HJ1G3UbQSQMoBRzKjAzwPQSjGXgQDpNRBjstmtVP6Mt0rS/VuYR/R7YQ/lzBc8v7KOm6naEEi87bQkvD93W8SzxC+0oUpHYFUJShQzd+3tJlpR9ZcWnIoxHTedV8kftPrsjLfwmzrTEFyR6IWJNKnJ80SkZbJDHPGdoznfGbKipFjHaKlSm6TtDs/1bIy9MZW7YRwUxUis1lw/sqlAGVrTaQ3xCDaVH7C7RZVgo3Uk4DiZscoLRqCcAPqzlrFypI4ebp1wS6DREUWsfDk5Pm4ztpPzkSTvJxXOI5J7zLxnZsfQbJeeF1VII8fUigkEFhHSLC5oy/l6++KYgR9zJWw4TD7GgXCb4uoadDkqY/O0KNBMJpmbgjBHM5m4Fv65Kx1118hdFLqtSc8h9K1B6TejTpmMeMtTCd87w65rHwqPre5IOqev5J+7iXHnUFEYRrLcM8NrqLNKOe1P4tfb5P3L8r3L2I3JwBTh9jabQ8XLDeNxeaCSIfsRp/QT9T9RACGu0MdhGpJAvuBM4QsDTzfmKUNy4oT/Px4sQDeq67x5PwGNj8apwQJEnnaPJ3RPGcFaEv/kikwMjhy+CFKb0AJ+1IuPQU3ushe+9sMk59iwlVwkoncp41+PWOPA84ikVk1GzKxVC2SPbx3yjLp9A2yyrzpgbQnVFHolj+smgbD/DWJ9x2B9OQvaHjVD4NWxB6hD9xjWJTlhPIT3tMjEm/SfFJhaG4+sifd8o+4WGX6j6hX534Bf+jHQMJd+ESwL/xKshq3vMHRTLOkBxpSITI2f45AHJYKtRS4QhlQ8cH5nSvu/M4FrcL4me1dIHco+TeUUsC8kz08lBxADIflXE4gnktOh5PqAKLS1iLQGDStVXVb2gUB1UFlgVy/ABVqPu35I+/sUcUbRSNtRuUAKxPqzaW+uGOz3T0PNUtx9ch8U/R+G1styNQw6OawqshrONVmn6Lceufp5yFqc+1xGpnKfHdrh8S5ORpo42XJFs25eKSzkvbWwHG1cIP63vIpAN2lM2S99bnC9BRiyjGuc1GsXUyKHfa5og5Z/7Gicae2AnsbUx24Z98izTbqIEV+QKQHei4fkmt7yjQZ45bJ4VTrwUJYACAyg396fAVv+MA2EV0Snnua9c3KAk5r/SiohloGylZporWAvraURF7OQo+qVCSMWbOpKWRupaX8Nx9+o70JWvYDO/7XbYfoqQ/t0V1jG3h14cNlvQ6/FiuO+kOg71F5LB9rPieZ1weUGHUTfEeSO8+IQOCERCs+kRkxWDsSgErTjbgOh3XnvsIV6xyqZaQZjjKgxQEiAdHWlE2MSGTTouDNxQgzT8DSBzqZUg5nTquwrAnP4cZXUzIeb8ilbYr9rYcjjj9CLDsQNljiYBHcxqIqngXSVfKc1Eo96573+T6n2lZlmmKOo08BwtYN4jcEtH0x6T+fnPePUmdmGFUJy3ti1U2KUkc2HvuDCEVsvssgSnaFSVYL9RYXWr946HXdz6POgC17gZfSfbytsXLLmBwKAhhltmLYITGL8B8Z0Hg7lv+JVL9Q/8EBogRM7GGUorOZ71hS0DP6N9x3vxHlAXyUCcCPTrC8ac6opJF3dUNSQqvZyCkN4noo6hUxZWOh8nQLZOeeegGkgjuii2Sx5gts+t1io4xrP3FEpIuMYaUcgA9DpoGa5Xlb27ovC3RXjPwcZrzBhRmaFbX7lcKs005F22kdRSymjzS/vFIyWZuKZ954E3VhoLa4HwflYFvvLf08/Kwn4WchKMgFfkoEYEA11p2Em5To2sXH5yGBJ5KbQEgEfm4JTtvrPWwcuzo18P+UyWRYfsNszcXhUCe5bJoP/pMSvk9AbixBEhn7dQ0xxMJzctiBxqehQNZ6nwcrIjxvhLuvj7O18p7gqmroyQncFnWtpSSGzirg30IKQExUzp4mY46Fi36NBHXOdytS7xxhweX3y34fGXDASixfxbvvRWVaCEKTtUMTiU/CW3BYChyyOqkNvXZyn5B3+ikHtxUyEeEhwGXxTZLz8htWWFIyNrq0wtmPPPOxe5Hbaw0CFmQSdyWo/PP/sXFzzRFr2oSNUsprUmsyklR+6lj6+uhIBj77c0Hh3zzZmGaBMzZA6U8LFAKJg6RAKrGuiFlqiJCS3jryCjl/MqR1M5bIhjK1KQSaL/IGHAM8+aZdFlMNnH00fxm8pzyFEor10FJCaeerIpYIt49TLrlOivfwHN6zIdXG6WcQpwtTskbxtxlAz7cLrF+6ATEESGrlR0bN6M0z1b99VqQgayez+69wua3zrGO2ZzesyqmukH1cY7W8g96GlhmNYNtzUdWOkBLrneJIwmrem4l4Qmn0LvgBQUSw2/BN9JagQKrzDlA4C4IDaOFJci5IUbHWSY45VSJyAic61uIueypz+Oe0cdNsNcEXHR1HALs+SxU6OcseyMOPARmZ1nFCHfn/PcenHjgpN9SL/7Bz3U4B6CRX+dRBDK5ZjhrMa9FdiArIe4iD9gVDRgfQiSKLNKqPZNkYiOujIHzhyIZAaSJX3JoqKFnocDhPOPmXj+tvPPjPA5yY5RQmmMCjlNrXll7I9tdJHm6wU3RrNZopwY4Nci/GF8HnVdQRhc0NrH+QU7CQTPT6qKiUNvj80F/RWHFY8HqctwkApi3m6jegkgBTrhVXcQdti4Hbw9OTx49Xvr5ON7nk01hl7lK7xNl3lcOxmpKVLnsrUnk20PWa25w3H369XXm7+oEGk9dZ/SZRVfqR9/TCUqvVLNZipNDI2l6mqnmimHbgsexIllJzDobU65zij1ktGO5yk9eJTcecAsLzx1vCLXeBd337Obz8UP4wHy/Yk/4bvhIUTJU7awvZQFDBHjB9J8emP7fd9k8j0FgmlCalQIzbWicEglJ+FHrQIjcYwLyml6DD5H97hLskJ80C28/myxsSeOwPY5fyHWFXvaCwvpX4PehXDklFkulT0ftoi7oaxmi5EGF7ERMPEyaJAyWj6W7F73yvxt/mKvbZYmEmEVcuUWMdHFhCBfQUHeejw7//ed3ZqoybzeNH+iOZJEnDS5ZmO47oPqSir2Nw+E1Vm0B5iXrP7QRCOeB+Td+e+Z6Lhy4JHTvbBN6wGXeuIhL+KJOrwVJyo+bXOLOydxix9bRuQBdaepJDZxIl7scJul4iqlfonYLSMYyzPo4LawoRquwuLdd6zjKSmLUFb3KYLYxfPP+xc5IW3FU14tVc3OjPtK7k8Hve7giwEkgL1vlJSLocVHIAX8zD6Eb4FGzCW3I9Vqd75SOggmQ3f75qwFxVug5zcWWf4RByOsvDlXbf0hTStOBTF8y+WlB80sBe71dsvgZT9ztI4o1Hgen3/euxDx3hXEvy0b5zYomHL499/dP3shQIh8Ci/Z54efP7DP05uwByxapVSuY6nOX6Ob/csv4kQcT9kHxLS8/klcag/7xX+X/wyPtNp1AHwttlh6mYj+yURw9v7jbm/q2R2rVqfLk5EJfV5BoxXLRSTeS0w/U942eUn38l4eNJ/sc/EVK1mdlZ3/3DXvuKpTZZy3zWGP3VYeJxm5H/JyIyiMOtT48XhX18AHkXsqYiOA66wZu3oeuyJfeObqN48khq7wiNykNzRrNVdx3nk/YUXFaveNQB800tsXsfO08uroK6efT8JpppPzucjsfIH4qifF3Ypl7Uwd9jsvvSjntLGaHW1OfVy/yG2rrhKzixwurv1F8+dugsyH+o6V02XQiwb6+m8mUjX2r+acuAXbUo/2cS7LeYs0ca3/bbWCI2zi7lj08tLb1lF3Kfb8C6OMVTfsFLEnnVQFFHW8LfDdTlwRcVqj/LqXHBYyyy4YZkU8mfQeOfuT8ICFnO6q0oLR/zt6vUwTYq+AFLVZnbtX5pC5pFsLNlLSYwvOvQd0ZP4tw3VTmIujUU8dCvP2nsWMQoGNMv/y4eTwTev0w9ujs9b749bhuw9nvxtTNP9UNvq5u9QJ7d4fy+4uqHSjaiwQ5wne7Y96GhunpnkOZXJUNG8YpRbIpBNzn5HtGGEdJj3iIsEWz/ITw+KZp7rOkLhQvMgVuS5WymXbwndB3z98hrS9KXutXbtwLnn+LJx1ca5b3TfHI6l6cxaSuR1BDhA7u15xpDCIVmYRXBy2pn9/wgofWVHT5MgtUSC67U70nfo4CQNqbDPGRoP1jUWT2LO7AfpgbgrRZw4sJBT91eIwLebM4v1uJ7zUcjbo98hp2b0g+FLRdg7Cj1eNlf4gztHeAE3rBMMh4lx2NEUMbj+Jsj9KKDMB76niZ87eLMGxP35pQJf29xYJ7mq3ix1L1hg7/WPSmWpO2d5z0WHZNXAZ0TbGEkdPIglbkfwVAOmulEd4A9ssIl/NePWqVB5G5Nerj56CpYrmKCJwJqjhmbX5s3pTGCm5NQ+dXQyrKX5rAPNW2EPsCLXpjomMbFWvQ3hZJ50jF1G8LfchO7fAEkeJGK26Cuj2MZ+Fbx9jS28VnTMwZoTQzePgHH8DTbDn6J+lCQtJAo0HphvkruVy0K1XaS6V6S9p5DGNxaO0EImTuSWTxXa6X/0o1+2QIRY2f+ZFwK7w+CRuMs+h6Vn83uVprDE+KXtXYXv5BcU+7/KFBwnsi+rSiyJrhje9jXkBq/Y6mieKLBBTVhToXXP6VF1ZpEdbsSf/UI3zxAq3JmxeHzIWndsjFMsYrV+gKsTVgijzZeXWACUwSd9adg+/a2A87BgTHhaGNVx0uQjZyFTCZSttdnzgVBaVCiG31+nkw63gU4KSWqm2wX3WYKfB7aK8T48Cv1AHd3CoW7h9kDeP0l6Yy8oqSvWQ6QDp7+2oNQBBqWk79EmPujv1jQ0WZSZ1TeaSCi4Xw8q9mKAz6PvavgnbX0hI2yJYy/JzL/Pm6DUjQgFqpLJ7T3E+3bpJGiEw140sRO7sQ4/ik5diQkTaMj0iVtPA58VFqQ7JrjYG6E/4mzEM2smECMvlqsgiZ3t2aUgexHNYAa2GmyVl0PkR/K549KfzQfqC+Nb6c0WJ70Idw5D/SrL1y7dNLejwL5xP9oQTbjJps8FPsR67IqBIfBZklTbd4qkdjATk8+hmjCVD0OhK1ba053QHQbrAPcAI9Uam49ZjseNFcjsIurvC0TSfpq9EBubqNwleumrA9OXaERrnu0YYUM430GOosW/9nliqTWeAK6Kq0J8YjEWgkoFoxJ0SgfigqzLyM+scvdYsjryMJZUJCsW/DL2L7k2IxfDlEXi6Vq+uGivl5kiby/HB2Ar4rkWjsN0Neu2bYCwlkGVEk/ipnCTpIOH/v/pqxFpcUQqRcNARc4pqmEbdHULa7oXBuHU17HVMCAWHDG9g5UKOsuTijmdiYwMWigW1FHLuFl0DNO5rBVyGloTeu+oS0MimLwM53Ljv6covjZgguHmtnKxrmWf2WN68lmCw0OBtEgd5w/lsTtW6yMCvGQtuwm+Afehsy21tSFLU66ZAWwI0mDgXnzxHGMj7c888Qlsv2wkTuSiMU35XLVF2BS2IlRH0vaZ2Cgj3on30j8yBW5B2NNNdOiR9g0lHMPWtWtx3wNZ55RuI6EkLUld/WssppvtD1PRyJdl4R+9Yib3iInGVzB3cPyCbc6ZTVv4MojeokSnVl9REriTHZhyryukGps7gzNLPaEsr5yuvYtouxCpuE6toYBQ+BOk2b27EHRr+cRfChnhF+9FNUE7e4Q7hsKm2N5pDHDqahTYGbTPSCyO/2NBXr24SW+2tnZapQvxFzKnf8EmmPWDS3HAMqTl5o2W9/D/UK7HGt/EE2HqQtv2hgp97ru5wrcxVEi/YafrLgoLMx2Op7wtAf7M0B13FiwmZv0hVD14QKgWAWYmsQV6xn4mXwHgJ90NF3t9EG0EVoc0RfNGmwlLedypuM4lUEX1GrfgD/SJcR2kodoeAKZiwRD1DHQ5mizedRkTSI/5TegKLiaekdhKZonV52UKHy9aoN73uDgptts0jBVEh9wkAWED+W0L3AEvEzXD4xdFMDNTKPIJdLBZqiUBN9E5vqhP+bY1pGSKdz8WQDucxDRgBXuJfqnYzgZLdH9eMIq9VRI+vlw1ndP9v8TSlVeixcnwVLioVc4dOUobofqdcofr/XE+X1ydLVxW+IqoCf/LxnhcuJ5BVdXp2HU/QBf6iNYT4cXtzm7PRlHDV+vKYk+TFOSGu7swfJWjFEX/+mNrd3mPLditJU7BsJU7xoYrY/bVS0kwsPdcYgqYTD8630HVGWeR127+DGO6Ebfh/2rcjPmaJLh5VTHKwaaqpAfyRhxJ8eHMy6nSVGpdbQmL51OCR7I6sFJG2Gra9OLa6bE3Z0oOBJ4CJGJxML50zYfLSIoMBoqMQ/IZ4UFVtz7CbRstsBWpjLllVjHgv/ShNLQ09yFZbiMjUHUSTgJ6M+SPqko3hnJglPCaNt+ToSqI2aoVEFYw8Zwc3ZjkTdoRzOZceuwB5/SC1ID6GQPnbWyJ7a5PjjcgIN/vvUjgJenx9dodwR0iyrpYpj6Gmw4Dg9Gh9A8S/cMCuFHJ/n73QoXjl+wPh6Wtczyr3x/9VZfP/4Vdz69GriMpf3X4ST9f5nERcmaWL4ITA8LQ8/0L451WPLjIfm/LWkvtwnoLd3pY0MQh1AMZ6ArGwpr9oCmCuhNhJVACGhkkkIs390sK2KTBoqOm4VE13vrjsop5+cufnOWvMpb4w5R4o6Rzh5Omk+alLx7sfnhWn0bh42R0Uw8FX8FiXDKiuaV3xTVv8WXhsW76lySMtYlMS+rDcyTHveIj5RVfLDU3DhI+o/E3wKi0tD7HFkwEOEPjbwtHcxNcmzDpHDeLkzlAxRDXKJ3yXRyuxeJUnOMI8zEy3wBnlabT9unXEUErqCkhZxqWpXFkNWXQ8tFgPqT8lFZE08Kg8L20bybwEDyR5aFcyr0WJNZDvU3oc4olh49F8Tsc938Xe3smadTJAq95iZ5OLQkG+5IG1bKBDD08wBT27AI+caO95sYiCTe5c6UiRW/XX2AdAbYJuUko9tFQpIcC24S0FCEDRAxynbI8sJogKTazQgdGaNWnCar6xttdXgm+s2+7y8GYUGcaUAFWw/f0vidSJC/8Pru98PVfc+HzxqDrcxLxCetnG3zWqCz33CH1X570EFqPzkD47+Xi4fGmHrXwJCxIjL7CzW5fTbq/TolQJkeUwaLYFlGrX2Fzm+yerSDnrEgZ9Yv+/TTg0dny/6nVI+pUoPMTOfgG7OI8PoCWBgsKWmSd11WAOPUdsd9CJvkdL+ejExsZiV5cQfZtxjtR0K0CXoWgSTNpB+0bV7GB3l/IT0qZiqffEfUhTMS94U5sPSlrGDleX6dfZqtuE5nAcmefMo+mv1NdYzVTVmuFZOadWw+lYVRs7sNyr1DZPVyuE7biphUQZ85ekRrFW6363D2SpBQMMAJdfg3E3uOypI2yxk7+pUdCO8ni77vgap9xIrLnmKKOagE3fD667bUahhpMwal2PlO+SZgCJE5slHCNiU5UsOBjkyJibBjreV1cOIXOOxOMU9TlTUR+fQzf1SaSuc7TZsTpWgzIg1PskIu6eh8dDLEhzqG7p/ye7x+dcU/NqZtmZvqoQBW9z2fDP/957y8CrDCflqhibhSQ6znD/HY8s79XpsFzPC6lEBsxtT6ajgOfL4Bw/Je5ze/7m2Lb8aThxLalCTotAeaQfkotM6PEtmHD4Pm471eQtDvzqbuTpTaernijJpdSHUX4RpkIVM5Zslhwgh3wNuXd5TGkuPXt54qkYDVVMfQeiTjrhVTDtEXf/13AQ6nKB6yFLdFhIm5eVYFYVSebtV+BoeuWff/v2pWQM+vNeufwtNg29cv04ztHa9T90QzxpXWynXzJB54uxgJIHAti7khiQ4HIO6/I8zkzLC/9qxm4uAlCpVklTs+l0GnhyURlMhby6UdeYSX06o4fhDeT+QWSVKia5qZiOiE+xgQxnWE3MhMP0MpzchuGgkIMkd4MJ0LXBEOq5AnRUXo/IhwcKTwC4hhTCXUpoV/wzGg6MvcmpI1xvhYP5iI4681ulvAIGEKa/joZe/PiArovsi4DZfjuk35+CXk+Dwkkc5uQ7i1z4zF8l/fnlH7WVBphbp1HeVLjvTvbIETXn2/L5Eg5qS+40h0hPeLeJU6gpMDRfPsxM/ug+u205Tj765ceTt8cfzlrsj/+I4EC9KoxPduygFat4fXT49tXp8p1Kmr8HvI1FZvi6q4lsX3OCTti/DJidJjfj6X34LWzfR4A628KvI5CD7qPv0STs3wOB1Fm3h+qtDVKAXme18lOoWGMovnP4PqIiMf5tFT+/GKOmWE/3LWX80GVjd5SUWzif165OlM8/r13kbOZ6YZX2reVET77UGgJPGx3O2Y133JMp/MYOlA5duQ5bfDHAYI+ml+xs8Y2DChMXHBhUVtNE7T1RWH6s94h7WNL9rzd80lpHrPMv2++n/UsHOFYCf0R1IrZcJebU/UD5ce69JG3QKgLeUs47j9+k5lJ3bFC3nok062zXLvSywIpgcyPyUR+zOyUWjPPDhJc0mi5hNLCEeW7OX8QIoT0W1MQHHz4cvn+lL6f9yXCa4CHvjHaca6mobvM1rWj/IsBuSKvxOSsAsPi86NQaU5FV6hVNo7zcQlxhgTwAcsxHhW/7VsFZirE4ZOQL/Aa4HT9n5l5RKV7YLZ6I5Xr4DH4Vdx14YzoHj+nRCKRI52EjA0PFks1lami4NZmM4lJ0vArdKimaRrNkvf7fqDteVhu0vNJ4sej/v0Rb/N/XrznKKrFyqtzX+LO+rM1VmrZXKXfiQLjTvaDJFueP7aaeyJivTfa5Rq2gTW572bDIB4vsS9cbl+GXVs6ouObb3FylgBkqCk+c9oPx5Hv1+fNx2OmOQxUcTI40UZwZxmRstappXP57HA6sOY9vPgfqgU+apjjZTwoNONAdApIBF9UR6ojEcz52/vnuIuekL9y17vzz7kXOjAM1SupehRaRJMnAed4mPKX54WBmvLrJSUJ7yXD/LlAg31YtaMbghPEw0JuWXyQOx9B5+pDHLj/1bRmb+xxSt0QoSYKRHFaNm21H4Hg+IGxOEitth13JRi1C4CguUcZSYBL3hkkQTQVhplicv2vJedxeY0lyw4OFDfZvOu6ZC5Btmh1/7Y6SHpc2tikt8QXkEZ5lcx4RiaS74Mhq8ZmEN7D5YLi0pCA05y2lG1gOP+2/ET6tiikneRIjyGUbfvdd4VEu6JTYiyt9hBaV57yoUThMYVnerDhilaGworcZoSlwKQj3TQP7Cp3Ah1fmoKjrZVTDsrETYNtcY2TEOSeKuIkqGulHGtenmLeSlahP00A8jBrGOsH3zhTnzafgsY8f3h4fvGodnpy0jn8xnlqgw3RwbYteJ64UWEJX+rA5SG5uSd1f3lm3pVVSG5byo1a2TWY4enqGd+0OiTD5ELhmSg9/fFzktp8ka3Dyjele6+CG4pjCFWm47qd9YTYeq/xJWWU4TP+O6N/nscXjXOsxp7+dOMlIxpvAllZFVYjbeNnH8LIVTZggk9yMrURwtjc32JC1EQ7YlutNI0UONbpNPp6Ql/uxloE4PdZTRjxirSbSe8Jgcp7HslOhjiCjZ8ZVtdqnMIZdlXRHryd394+xORbyxWOYnKTYQno5FKKqNQf5+LvC8WMNLa9mWOh/YxX4MA6u+8Hz1E3Q/jKvnAnM5N528x/hAgrnZKXlDk62SAPQWiSRJAodC7MGLOymsqMEnWRjm62SoEWCCPdbBpyf+ejfEsLzaBmEHy78oNzCAJOy033GcJN+ilYFBodT9nmw75IjkobsxfMn88HtLfa7WhjHq/EQL7R/P5+9e8u/PiTIMMGkLGSNuT6EtBpAttuyfKmWy1BtpY/2WgU2HpV6aUb5szHXIvGjmDq4DAETtqBDcwVdptSM3N5xrqVyVITBKQewRQU2psuoUYvGk9H4utf2I7/g0HyJxqhj8WbEdoe/vN8Y4Qa4J/Sqvp3hW17A6uPXnuh8dDSWTbjsuHbnLJqBUbuntO0JlT32nLOq3Im3Iqiro3E+AyDJGFDDBN2h5jXxu7GgOO3DbMOV2qadsZ0ve9lBfZxiBUWGgTukbC0+DG8+HP/68pcjclaYaUsri6ly8q6qBMZn7IY2vdrVHddFPoTLFeaDii4627G89WoUYtFlkFtVaJvkdrQJAg80Zm/7z72QeilEoi07EuWaKIhOTZUbVxEjMMwoYv2KqT7ElK/VauxYTdhXSbTCfW8ZiBvnc+eoCFsKH0cuV1dFjr0rpiqhx6vUM3NXIUYWua56svf6o8iUdi4n2oldrudxE7lM7Ci6mZNp520kLF4l4CJzYGTl+JCT9cHRXC3rZ/P+ctrix0mVnkOsXFpJaaobF3p/JMTFG5otR2xEkidJ7FkxlphVsmHGKN15YBpAkG1Gr0V+hIsmhrzIOc7InW7UVxbGAkeYo3SCO0+/LveqaY2NgXdYxd/PBSpiXXsCG5m2BxyA30vCgouRqaD/Z8wFzWRFI+RQ5Yg55/P6L3YIDfuILDu34DxhMmbv1lL2OVyUmOTan9tWXEE4p6maMFs8IDJu+ZddThe2XOyo7DqeprVt6VqZe8PoYq87+AJTARV+pZSeazfDCEgB7JqMtHGmXzzb2IDSKSRYGxu7abGDZvf+GqA1p5opZzoT3A8aJEiKisvH4V+W+ojun/WY3Zv9G4S37FPvsumiNUfLv+GTZEWtW8/Pc4GJqRmpk5sCkn4e0hEOsuVhCOvr5fE7Y5kBnQFncXCTMeIErMo//Pzh6P3r49bRqbSiI1sXAjCy+DUPVDa7oEl6N7SYludm7l6wxBPDshNQ0M30mnH6EAvgXOQBkkAtDLUPJejb0k8P4XC8wLO4BUub9WmqofQnm7RW0R25tctLkYIFJq7Mk/Rkma32kNaWUqYmG3hjVrVadcuoxj7wTDVisn3Y0q0kUCSFNosLi3L5bZeewk63RLbu5SteMubMODIwI2Bl04AzRGwDLbHE6spRh1+S5gQlp3URcIXlONVEa7MAYOFbg41gPNxqYc2K6VzkxYB5DyF7NTnZQgFwTqlc3Rez577vb4AfbrDx18HGH6WN7VYRlFh7Gb9wD4XCbGYEXzZL2cwNfGlsqStQFUwKE6GoJUw7s5lMmDXlZHyPtlpvj94n3ZSDGVtpq1Nbdcj7JuO0JRUUup+zEPx5n6ATzbhsL2/5jtMglpF5ufNC1Jl4WljMlSmHiJdCR0twhE2wuzq99RalkPEF9v28Yn9jtclCIac2y+XAIfR+VSJGzVepxvb7E7pjN2FcumbIgWj2i8PkcWDESGV2zQIgMumlKPfkVukfwPN6WJxS4okK70ivgDzslovRzsTVBbh2ciZ+CZxO/+fdJzHBJadaETHOHB9KmxWeIDRaKfePAB53uDLE5JZYriITdBUc7XsnlnN4crqhKmavbBhqVWMi5zjOzpnN2Dr6R1LTWQ/l/Fxyp2TSjwUOeYuumAxxghv70pU8X7Kw4tDm6BsSttQiDYFRo4Vg8IDlICpXaeuqlDS0zMjNgS+86VMiu3InlznP+Rvrn4sXWfYDsgn4f9BjGB1VZmQqIzfgInlxVaWkvj98nryNGqf4KMHcZSwIfQM938DVJ5JDhBbTBVbqJRujwEzorVigJEkbXgJzIX3g0L7QVc0hdmUYpBjftLIezsUmOVYYpzqYuLBeT47m8R9zxM2RkpeEj//HXIL+sYba03Gv1R3YEBbs3MY7S0SCLdQ7uJ0SxFW3l95KTg1i8QCjXa8Y3gZo8esHE+XHGAsyMU9myvz9kV1sHbw5fH+2NOx5wkA6V7A8yvAhds4MR8k8TByCwuH1tEpFJ4dnH0/en50cvD99jS8eg6JYpbaXx+/fH748Ozt6d3j8UQBbLOWGw9sB7If5K2zZlZjs90nrAznyciMWTmBSxccsntWQ8uNMXDQdhWMT6NZytPtwcvj66Dfxy1TlTsZTqdZwjnf4bdRzCuhuoDNdHJpHVDQKoD7m1pbbatRKUqsMp7YROq/G7d6/fza/qoTh3U806i6tqzBf7VkCdbN9yxaJ4yYvJSb+IVPumOdHVVdwToOjkGPdBldh9J85h/ziros9sZo6qbDENoR2kpfDUqRq4Rm1QNuduBA4ZQJBu1H92xDVDxD64cHRvfPBDVmdEBym4NKSgtLzzvWVW+TDoAIPTIn2gcJiezgdLAgwcMuKhnZbU24/fG4SqG5cBIQKnrlU176piGv1h5e6W4GcKB2jzAkdpq1FxPrcfBKQJNfCeRS6/4rpjozAv4c3k4StMJrOAWx5LAef+KrY9BLcUBLbTLO8LSCUIKl8TC/9eQfkznJJEjwUePeljpsbdRwGPfMSe92958v7oBkzKt6j0w0zrKos+ZFB72uYWrlq2AnUYuXv23yEn7emW02Eufj/di7QZNyPGmaXLjdImZFhs4MTt79nOF8uuxnOcTWK1QHdTz3sMdTtpOP+mzXMh1wp/230zq2nn8OOPA2FIER4ekO0CtY0D9WcbixT7JOWKIjyh1EEh4HDpmUMF8QgVhTKpeKIJOL8NkYfU64ByJM7+84jhyMRKyiBOK7oxRLXHAPVT06T4eLPVtLWKL5GG66/w63QrdCbTxHpaKlhbt+GTpv3KdpAdMsNtp6LC19ykTTEFuUdK8sBMVBfzIqTYVAONI6Sl9mPj1X7RvGXlutBwuguesJeiFm1RdHSBm533evBcMzmkw1YK7gcqlGzhfvF2XP8RUl53n9cJeGP4Xem2YIYFft48raQ26Mv7uExyFIM7gc+aBykZ9nTIIW5tv5iZLonIsEagrRlMqxhhtxqzeUT8MQJOf9nV9dlx9/X+PaIy43JLvqAGkaJ39xbC7MKqywVkc9YEU6PMvt7loP+/p6iIcC9IlbvuQeOqJ4vkggLsoT5gysltliXtYzO0wW6JdYFt8ygfKG537FWeWICbDnqAEq4nsEKsjk+bmjYKhn+C3+PE4MeFf9wBFGfeLxy3HSH4723ywYmagcDI4/Uo+0pD1RCwO0HKyISMQ6S1AdxuDgtoURyPtwaJioumxBxbMz42FBrvp8uwIcxMpLM8lNZ5TlaugpiEynoT/zivUIbYbW0wEbIYbYX2wFdit0V+cCxHj4Q0wQspfZ8CKv2tDXtr4BJE2d8F0IIUB7YGNv9XLsaixiXS1WPEdMf4JBKInqPU666SOOse2SPgnEUnoT/ORlO5+X0mwtVxP79+4Qykz1/zk6jX4MkfDTSuJpR9YttRUjFljJEzwFhtgn84vRke/YuTRyduB+KSWalawnnVk1aI8gKRkxWKgmhOMv5HLh4adpeGX+ex8GcQ9BZ21NXhnkXnq5GGlCQHra35xHE9Ic3J6NO1zB0zo2pm+emUcMsw2WeUE6qeKRSASoAWcgWhMilUhyKGfORNZH6N/7EXbmUn5EWkrum5pqGKhLIBfzIa1UqqUar2tA9YC7hypZbi/hg9J+YI7iLG1EeOX7MKnvumURwxTi/OZgcOBq6VLKmebGaPq3ZWOhjDRMll0uP27aZuI+VmOO6RAGnmaJGUZm4FYsq9DX0VRTh59/9bxfwMbtvg22YfSl72KJHsuRhCx6YF9YILwT5R+rWUKN/flxqXeSa7DvXrtyzHmfFJiqXZoWcx6EwRa01zNmub4cM5XeAIRQoAY/cHit7SDypuGlhmD3Kbic2FCFXMW5pkpBrdh54vr696jxKJAZj4NJj5Zrayo4dGXQvBhcoWmqgm+VSdG8RL6nktydO/jB/7tKmKThRGFp9i/+Dgddu0GtAA4IsApQRgCaM4Kd0iAkbDwBeRmTvgukoHLbeH58dvaQU3aAU0AU9b9e/L/v3L0yZZGZ8JAfDJaMi2FKkvuiQZSjpTMr+XoaI4YOT/bgxC+ILftsO/V7ATy/yHk6m85ijrmw4sC4rVz1cQb/kg7FxwcRw1RqjORD/ZpKwecjckLIjKflb67IH+dOuhu53lPs7ObTBMKxGbHFbDg1JIIr7xqwxoWc4coOcWzx0kmPFgpzgS2QOp0GGkx9C8vyMV5xG42IPIjGKwQhynhcvu4MiaDA7qY1Xp6dvvbxXjOBa9D1i49hhv/3zcHJT8i/krS94A6vG/PDlxly60BEWN4yw57YpXPKQi4TuTILoS6vbacpLEg5IS4CT0WqQ8xDDC4KKUdRuTcc9uUOSy0bD9hdQ6yIyPZVH6Jor3wBvzthvgIqVW3oAlyB5REAnFesqKue3sIqRfEQnT5i9rAJnYkaOJcB9idWzRHZZe0fGsIXUxnTfWpXRT46/1n1+SNQSMRY1zIGGoptpcM3gWlbQbC1q3KiR1BM8GwdOKekwnU8gErQ6c+lMb0WMirIlEDG293J63QL2lk33dABwC6IeXoYXYWxxGPTVpNFboEXQwAfzHwd0vMKzrMOJ6Tbm+r6RTsT6qtpeqRe+UzCn3GKAhYzomC+Kne5XguDQLf6aMiCXVvxTzkYrwke4IIYZxsqNmhbkthwmER3xnBjLE/TglK3qs9bBy7OjXw992wXdRnGfYzZ2+OzKwUAfpyoiQ4+CyY0f83dIvzp++fHd4fuz1snx8VlaacvTRdrlRTYCxbRfOD06O2wdvYJoRkVnRrQi9QgfuI5NFTzGvw3hPC2w5enpaxfzWpUrVZW9rnc2DgZRv0vHLywAAbLyNRzDVijkJCbK5KYbbeyOgy6jsDgBfgZBVw5PTo5Pnqc+DoLLXpiaDFPTiP2BemF6/AJAsSiyx3uC5z+a1SHgYWM3FkNIU0KF8RwjHtQ3/EBwLopsbNhpNhl3vxW7kPQ1KnYZK9D+wv7gGNgZfKjSKtdcyUR+b1/2uiEqd/VxwHMIVqUciaVf2npl9DcpPfekyNDG9lq9wZeN3ctpt9fh0C9cX0RPEcYcY5RkfJc+61kksRkUkT2M7D//XGDiSSEzwoB9Hq5/g5/8++ie7mnXqGyWm+I0dzdM9ALsP8Z2dQfRJOj1Lq99/dRpptV2FtGnGU1pwpegXkM4IDYC03+Uy2iMDkaj5r9fB+3JcPwdVdwHKievLxJnrNFmrjexfAF0a2u94PtwOqkzYY4n/06DyuLOqWPMCIcPfVcgfalWXVChmr0ITx/znBM2olG3oIDXCFtUED0iosrSabLDyM1ZkF/UJ7TS86yK/9DhMiet1IqHgwPs4eF1JctHS2vnaS1TSo+Sy/MhTWqLTOyGfoXrJyHgvpqf7WRzPBuMu0xuhouWphNTclRLrmwiST7mcYeFvqGrXQSl5KzjcT5nyTOxjCVh0ZVs/IPPG7pJlv4JN8lkB7OEFeMDQOLcgXCyCvReGmQK4AUM6BAW+cduwIC3e/75xUUOfhbpt6/l+lpdBx5jZBLNO/p5yTtUVF2k/tcEk6O0tur9s74rsNda4+UHTOEi1QLmDNhmlHMpbyvhEe5uXDYaw03nx3OdpIHygzM4tc1qtVVoradVfMqtSuNW8RWH/Co22PN8NxCyvlp/+Jhcx8cktv/2HxpgMRKVJ4SzLki69BTe09b7yZaXiTPVNbc02lsChDiBQaTKuBQiotaWgPYleklZY63ZJ0Me3wEo6tQTgdYlAyW2b8T4Y9sKQ1Mskzg0zSfP+TMcbInMHpo6Kc3FzKA3ugkuw4mlctb5KoKFh0BtIzWoubzMoNwlyIjzGEveJiqHaA3h3itloFbLJWUzURdjCeocmSUda3zfEBz5owuSCdhJLwpLNC+oJEKqlwGqIsPEqlZn2mcyCDjS3AOtu2fLiZZpJroJexSWfY8fI9jk95RnQeq7HuU5q8UZuHgNRGtHJbpazaB/c891ovZ70h/hAn1Kw42hWaPO4gEMfpIxL/eYQ81qaQUdg8SbRKAD1Gu0hz30QCSF7g+dq7oH2hN2tTdssVpPj47fF3JpYUDmiQ6oFjw1K2yUXQiWjLq+HA6uutfHI3PzJJ0ES+RaTiJ7K/IYUuW+Px2wEe8GvbkJZjQyjYjiFXNh2UysRSnjtJfUmWyQ94NxNFyUrMqZ1uURXMBcj3Mn6zyPS0DoclgC+1JnkPYLQoHDyF5aUg88YQD4eg4XroH1FXLchtAet6sVqUz0uRZZ/XQuJztRLesVPJDOayWzlniUEfK9dtIg/Dei8EJvhLZ6rcUG28/uluDMW2u3miUmQbZLTeGIk0n/CC0pNSGbgpPfW6dnJ0fv34CWEA2qM/Y/fEeooVlmdcFyVPWfsxtlLMy+1JpoYIKv9SYclWvtBvzlZ0AqjQqwjdvRBmZMQlq7EXT63QEpz3ZIQVECYXZGM7JJcXZVy/08l7weE7LZPxJuG7km7gYNhz6pYMDjyhOCBl9DCBFebSTjYrN//cBAbHP4JLYyuE2WoRb5/zGVyJFaNnndqnjscflC2+aIfV4GT7dYHtCTYNAZ9t9PwcLCc/hRnld9xfwSfo9EG7g9lVvFZXfQScJvwYwhyDptyG+WXAvl9vcoJw28U4I9TZ19hK1eNddQMG7fdL+GLU3LbyNdhd8m46A9SS6iOYRrVs8CJgyaabT1+Bepk+CyLmGmW2i+f3VHvo4A/Ed3dEC9jNNiKAyJDyfTyE9ChtEFLYcDRiKsFdSmh44B3K1fYETSU9YA42UIXB3sPDeTfg/VDuD+gV+K8tvlsPMdv0ST72ift1JXQbQFqivE/USdyShofxHf0z/7DpcDt3UHAdbLJd0pRmSJuZOQaaDtzu6trqJRGhKDhUbg8/pW/e/H9HTHpz6+1bgKRbT4kHh2vTb4LTjuhCb25zPxi2pLgMuwnoq1r9SHMz+Bmi70b5LT8WLSnfTC3Vqplno/nKReM46i86JIF1/clO0b7MoybBgCzVdL9Sf1RF4AGkvkrGz2jiyv6MHju7XRI7LTPUpRvdwexP7flTFTTgKItKAFiKcObD0xHwZHk7FtT+Hrxutf35S/Dr8c/JcSjageQpJ0MbmMAxiHKlQx7AzbbHvUGmEUXJqU2CHVr6KQRrTwWtllIDH7gD6QpkphiUWjKEE8TsxcIYuGwOEF+LAkRRzHF3AhCMw+mei4hi45Y+m8pOfz8hXPzR/M1W5q8xLo+hY7MTO6k4WHUhHGYmbv6vlZIZeMv5c6O/l4qHpO7aogd+1CxvwZH9b5hcw3YzeVqITY61vExECjZp7AjO/SuuI6APe1aO+5dEGX7Wm5vGpbdYHRyiSuu/145fFMWWLVLoSP8YWuJLaOZ/zVkKcBB9AYbSODI9jF2dJb42EsJo1zFul36i272Lpd7KE0r1pKJHr0Ppvc/x/gMdj7XzT3n/k5tPNS2jcck/2NlhwRPp50nZfVTkiqVcJYPwGbYQP0OajKkrYUa22flzFWxbxW4S1JBZda1ai2qCBFf/DJ+RS2MewNAhxXKsooY+joUWmQFm+V5vHmpCHhHEom/ZL23sYZ47chGm/CBJsicOrwzu0b8LycNG+ZUDa8jTbKlXo5bShKyjTusaY04gCrtkhow5k0279pv/DnkO2ZjOflkTIrRQv7r5Bm9CIto3XVyBMqM+ZQjRE0T2qMsrm51E5/NMPJKB3YUjTXSmRjdNC6Z7lqxagknyXKZEauKBnlhKKdobFpQkeXNDrvpyhnb9MbDaOJl+JpfZtef9qbdEfBeIKe/RsY2bP7ojsYTScpKgGj64F4hu5S2R2sc/glvTPDRc3HFY+bUtVAybZfxVTLmW9ZaEo/mYShkmFy8PkHtVqzVu4jiMMqIG5eEorLU+tQtQMdcYTL4PazUjokDcTsAbp+3z7A+FrEWNmSKwVDjBuMofot0qrGHl3BiYW0GhhldzQJx8FEASHYkTpuYFX+UCsYjXpuodCZt8kK4XJrJGno0AJuJGadI6NgRomlJRr/85yi7jdB7igJDmCP9CX/87tJI4tWg+rTpDbJ4ALJJsmpDmeWVWr3K0ZEoJ38mnpb1V8ywzXtPBcoY+Q4VdhGXMx/QPcTm9DHRUE+cgSXCKs0vUCqfCWlM7f3QdbP7c0nSgtcPRIkuyW8NDJOMY7nQBfKGJhmeZlmuk7oko3a/5tplPgYfxL3sxGT/NRDT+HefxsQMpnvF2R9fgpWv46wkvgmj3qJjO9n95xvspdIzp6g9ufK8b+O8JGVUuWBmGwO1oYI+yP77mKZ/ATzmR1qy6cITUnlWgInrXZlLNLKVmiuai4lprqOSInodxRr0sA1ZK+qO2w+CMrgQXzsig4bNo4vH2aCe4kpVd1oP44iBKaRePpo6kM5YK4UoLH2nBep44WcgzTbvFMs+jhOEN0azBW6Z9uh1Kgid7vNuFtlm0DpU8ibDnHziW1J10P4z9zZjzInWVv68RalJSp0G5UcDy6yK9GsEH5l5SHQCsvozPhaXILeuGqEHtsBi0n+Ur4Dv5JekVxNN+POkuidglXqbqES25Vugb6qWcghy5giBTKVlzGTt9wyzRlD6iSG7eZlDdgljRHUCmnuP3XEfqyUa0ki4Jw42qZrSyJvgyFU0U0g3eY1lC+uEubRWzSDJkVLBKW1yAQVRMWa5uIkH1cRvfWyhMhxRQAYryKVblAgVgRvg/JaFplbR7zPy1xJpmgIOFne1icLkGwSzuMCu1IplWYi/Ws8a2mzgPos8ANYqDpaSuhY9G6WmFxH+MRKVceCMB0sl8hFsmSuqeWPMVez7rx3NpPjQG5yDwG9fE2QCfXySdLEslCvrqAyP8HrkYeU80dtP2q5haivdQHkqkA7BBRyJt3pRoy5+E7RtpF0TylxpXcSFeR0/xmjbqNX7Zuw/eUluPj9dD0ipX4hJ0JoM2ATCy9nbDzXgt71kNM/ERTvvhuvNtVMpYNpKANe5TJE69fmUmfSE8m1cdqhafwlhpsvQN9sw6Ev6TcFscx1GERfVdJsXo2H/ZGyOzs0WKajh0NnirVpdbh3OJbqhIzzHCbpIpdksdSAXsJsOweUnZZzM424NHVwbxkliW+slC2Js05PZLRHso9TJ2CLiBlhZYKIzQW8UsZybMzuLYz+L8QqEUgVOlVC5mWrsdB7ENZl4a/uiAe16N6DsM9UrHUhNxlO2zd8wCwvQ04hGRGVcA9A3fqYBSkTa5lPutjAM422HX955ulnS0WG0LgGEwh0kX0r+Ky6YmiIJyvGH0SKTU44Jqg/ZRu9DNkktn6qYMr2l5CX48iJpsws3ryipRdhTRXuNtkhn9+Gg15sON3etbGL+48tnsshuixkYwdrWTGD6TbA8iDUgAIos0tilbzrphQQS0pZR6y+SgPdeaJw/DUc+0tr5grg/ZRnAzhLzJE4R0X6OOeXaHrpEKwX22dKvgXm4USfpqFBFqHWSKTunmWwSrB4zPEQSgi9ij9i01DqIAaxou1NUkJUrOpcfDl+dJoeKnxyaV9ZQT28HYpfbSQanGUV5+kCbqgKrPbotjvRJ/hxhzfMfTvA8yJN8nr6ua95DD1Gj+xUyl2yyf2i76BYWGUdge8qZi4RK0eFyTsuymhhli49sOgD/dw45s2ng5P3R+/f8FIF8nDcQjmF039aq6IOySdlDTK4JbApHFydHrbpocUUmkFK8v/JZFVMjgQf+Pvhl/tyVlEhLl5KSRpxAiu1J/GASmSQKXC2H4weXykMkBZy9fgOEjlCDMMG15qwq5mMqfhPzOiWVLcb4XMpZICV27KYBqTX9/ASf8s76OrHJ36HuTkE/wcNi28QPhL/VFixtOw4s05mURikRVcWEfT+2vg/vuSRWH+IEEbdjq8DFxbu4BAEmlaa7YmN/iJgnzfj8KqJCSXWUIJm33ZJx/iiGOy+uBzvejqLzdsnt+u5ouYCv4tVgNTtZ82j8YFZRRjD1tPhGBa0bKcUMR9wxHoNxx135eexK2rNfTYfTAzrsWUEB3vKjz6EvazU5uC5koOj+3CAxmzOyckIc2aIPx5XRJqrIcbN/LxI1ZBYINmhXY5ATcTzGapSeqZqaZpxjyXr6ldQjUJ8pxNq2a35TZpqPXy+jniU1ZKB+7WfMCPLmP7SL4oYm+ZGrl1yN7rrxXi4B9crN5SVKWU/XsoBfRQbdj56qNsDPDs2/7p3q4Afuedx3eKvxKsTJH9+UhLCQuSwfnjPL7CWrrtX93+Ortm/8Pp+NLi+77aHWUvVUhVJKfRNnRRH+xCVhG0/IITKUmMpPSc6QLMq2Rvepi9yZn3GyW4hjQvvcn03Atu4yebAsEaCEkMLjYAMFZa1F3z1C6MbdpoZSnusE0EiqyYr+hT5bDPQGwRWZT/6YRQF17DEs3urQAe4tsyyWntTL/p35vZz78m4kFkjR/Wac908w7h8gVg8h7AV7oQQ5/aUPR6EQuRTJTZ8CozVTTnLGqN45xGWbWs7lqVNT6K6iieyO4uq1M2xt6yD1c2VY21J8Jy9uASkbbK8uCgdfbOrrZOfz84+tH4z+q+PF8G9AQx91Ga0CIa9Fwyup7QPmh6itXL0YnsmlUExbh1zHYiPg3rxOeCb7CdRmxoFwG8+qTnnPD0XSppCkm9GBq67PbJoRKtvxmJbdAipAPV4GDNRuKtjlNNeHDqmNQEDZwIBwQ9Kr4WnyTDZMBLfOUlY71xvL2qa3IT9sDUJ+yPQCE1HzhYc/KuW5aqOoK0Yp6GO5jhqLOPaoOLsHh4BAB3LLt0M778GWWHhhvxKeNrCQTv5NsFTN8uPDKggixXwcwOj4mvbbpszGzAB7cy+ylECr4XbpufJw4/dDnqA4NVjI0AAuX5GPmyF6uH80M6YeXIPiwAZiJDJmqqrmgw0U+PZTNt5fJpmYnoN97OWn+0YilL/jpeF9EW3Cvrz3HVZxOvoETDoW5FUjz+3oh0x3cAEGNAm7BlqxHyRTBZ49JmMocJfxKfXuCxMGKlbLqDSNG6bfAOoUHrHXpJJvKv0wcGZwS96Lu7Frm7pBEbXpUynKKo6oq1WdKjlDBGRVm94PWxdT7tKmDR20v7efKeuq54kUCbtzBuvmsDdp42MUHz7B3LvPoGWj79+RUcekqSZ10/ZnaCC0+llvxuD4pP7EGgjZSxF0UHpHvrBN65gxWUBUE10AzJHI0XVnLBYi+D/cMooMJqugQCfpwkb7WKHTAqzPeqKl0JzZdPjP3d5JhryK6B3QwG87MBqVpMGIws0inRKbCzZSLJRZCOYpaUn5zMhT4J5+MREb5cbldF2QiPuTDFxrpBwVSto/GmdNj0cJDK8lGaGV1aTB2IJJub8c+ZCAz/SS+pkIA31IszUb5aTF9yQu6jOob/395wi/P5e4umSUcCAGe9fSKQreKBg4CavntBeGm5UL8Nxz3ZBSoglkxZ87QmcQOICpYybzaULqKwozRIDRDht4F0l7La5WXx03dibt8c/Hbw9xQWQFuXS0qDL88MRFUtORuOgjbziwl2N+BebQnW0IECHmszl5blA1lIf/ARFuNHNhmlt/wH+a9IfP8aN8+7iwbEXLy1rJpg3kjszzxgHNPmOK5In9zhvabMDqWVklHKnG3KVLGLv7Cl5LKMm4zwtn28hEZK5BzWDlSjhybqlxD2Lvyp2mxBFa+hj3hkPh5PmvCwPNLGgG26qEWTkqz0cfoG3qOO8GklJdIcOK7WDOAfHfSO1tPTpoOVLGKMQyOnax2TpR9liL0Lt+RVs2rYbWVyoVE3Mc/Vdpm+cd7JnoG7sfawJpGR8czqqyuivRd4YRu7RH/wOPFyZ4cpSRwQtpvmsdEK2Wy6soRUTSNie1FDMg+rwfygaXaGIZuo3yoEVF+FT6885hF47xqnum2O3f5EzrhCDjFtjpk9oTg4iQYgmuilzreEOJS8we9Xc1wkQAPBpjJQ1aQogkZpFia0aDz9ZoBU0VTjof9QPNH36ItWof+/fL3qK3E+ci0X3MqmZi0fJc4nLgt68IXBA5YBbEFAvwQ1oA8AWxsPec0uFJfUAcwTvuCXtQdHwiVFSj6pf7RBO9hEYtVyZuwITNXzAUYGmMxNlzWR88mhbqJXT3NkRknQz2Q5HDLxc4nE5DokX6RYUo4PwpZXtuS/4KEjj+DZZ2tiXGGRpr/qlbERWYh53IdM72lEGBw3RU8uGA3sCXXK+pkEE0+qH2ONewYoNNgmWlq7Ftn9t0mFqCCDP7PRygq7cjpBLbf35n2k4/m6B6sAe03hYs6wcHyWP3QyjiZhFqd1Pc6Igj3BIpxgI5FqoE/kFKYDbPdIiVhAitVI2c3mDSNdiYttg0poMVZ5G6IQBh+D5PxxEX3w/8tf/HYZfw4gzZDXSS0uGCFWkP7MFfWGO7to4jKY98X4YZICOh7RG2pydEbcs7+L2jV6XJMCySttqQpikJUQxkqs2Q7LLnrb7RKfh/QxGTpE0Ysq4lUqozfb8wnX3yvLoQ/RQ4FYkE6lYYA2+mztl1blTVlYlTzIeoirxFN0yEy08VA87GX//PjYIiGG6WUBJyLU+thPlL7lV3eix+46ka09B/vjKxjO3qq9s/VxwObGv6H+xjL/qMgl7VoftSmJmtYUHB+xWw5VqLUPHuZYDJcvzXBF4dLT+FjKGnojAvYxc6ogPXZT83CYloWgoz+gyOYruzBDs8k7jGjlxhcxJ/OtMJci6kLcdHn0ZoUzSCJ63M+OTvG0ZAfy/wYPOGT5QEL4PhVBxno9K8P0UWsAtOkFjLLZ44rMNUzzfG8Pt2PzZ4Vzi2Mlar9DiWUf98sdB99tZtx++DaLJYacriL+h1KcK34WD6UF7SAvXWYxWREX3yEp28qPVcIpI5/8evuS7iSaZdxPPwkpFrWfk6solp5k1/sbWXp/nr+J0ZZ9n7UmeKPfo2+RNnVL8OEQUSQjiJD7DRSSUGe3o1Qq0wRe8BSI8VuqVf35zYhrN/1H7Er2Oypanr+Gy7MwXDZPjAnh1ejf6cafyhZEJy9nQNa7XCk3g3WTLC5RYFbDV76k4QzoCQC1ewC92pGHCfX8Nc4TFGQ6+rhpK+eYichFprJ6C1MWqWpLgxeMIlw/L1347uLJ/ADZ7Fbf6fwRDm2ejA7MQ0GQkZNxKRMNNuYKB2+Fe6br+t5MD1W+TK+CtQ4E4b0bkkffecT2pK43Ztzz9QRvKKoVn+B860FOnkXVp6BqCpM14qzajxgSZ+bSfhqTGvM6Xcpp/LA3XRW2CLC1vPam7yYIEkE/4jnPT5RgqMMIrBdZ10Z4TtlRPpKMHQ8W5J7aa98TBKxC5YkXOIUIpAvCJScn5a4U7MO5QIKTn5ZMywfz9rM58IW5BilXlGyeg6eUEYa7ouiAqLkbD831iSCEuQOratavlcuyyqWES1ADxTsuNueCRbIQNmkMimyBsbrOiaQ3mz8LFO0gcLbsJUzhTVcI9bsDbFPbnmbl664Kll7KfYMV3NI2g5e7i8K+JXwINyPlSJR2XLnbMbgKrUNsSkUWkvLUB+gt3m41ZmnyPxXd6mrTU4Dh0sFTWwHn39vcW0hknC6hsSAiDWa4ofvrfJ+F/pmE0wcTZvwYA1wz68tF42Jm2J+l8KZ8GkgUOUff+/RKlibZRJm3y0iD9Is9WzRMb1xGakgOZJYXSShsUN0LZio6VIcw0dOBGicTchpjX5AMfVzF/C2FBXvZcQ6eZFc6uBqIJbupHl5to3GOg/H1XYRAZkqOtiKa60fBZwXilv0qCIkghTcZb7jlBGU2znEMdtWj0y9LRqoH4fBgD4B/gA3V84MkTFGvqHnNHzFkXFKeynWhnWwa1GA0+d3Ukirhx40fOI8MKlltMZC3V/U8SQWIKd1swVtUFegrb/VAzzcsfmkclNxuQB63s5o5v2GBxVP0fAJlN402FhDfP6085yQhVPb03kOzNsunYSAnq7sFxdHIznt6rlKFZvqe0F3AN5mYs9F/lbqrI1E3+WjCd3GCihVQzBT5YFaGNglXdhJFiNfqFuRlfLNonU2Eq4yH+zRod3IqxvaqDZa2D0huoKi0Gyp6U06c3kLv8UuTabTdN/kHYx9ipudZpYmasDObE0t01Kf1lipXwM9xMDjkI8+xKAB+X+H6zHZGIT3PXyXOCy+7KF92Om1sL4h3ZJPq6oq/Ox1BuQ7WihKqANj4Cr227kR2aigjFjn5Mf1ER6S+y2uoWRJs16O9dcCrH34EQ0BqlOaIbOssppdsa+Agh7EpTDWFwGQ1700kIl9npy66Cc7l9A1KItIMeuvdAB82cAp5WNVuXRkpK2V04OhKC9+aZdqozynIPQjLa9co1YaDyJfeaZwuTWqmKsBaNKXhQ5I0r5PdBAd1zYz+Ng4PQwzY3zTEqFt1pMFQOjJTIgDGdXG1sgWWV52uRi0/zlJXXDEfJglh/wGFz/D2ykdxVuY+7MJXICxd4GutTXBd6f6P//jr3eSzJ3HQi+aFy8UjKYue7IEFicwYTJlyis6ZrRQORwCpGmrGlXCgX+k8CZ4GyDh05NdLQo489vY1PCAX0Ek6fNbMNIT2YS4SzvaJJXbJoIFTYVgzLV4wluIDhODpFDkndSGLyfEcKjEZ5S3gEL4lolxN83dIZVp0ChxwC3g3SU5WtgNnHxFDemdvhoZUZdv9HGJLjPdzxE/1jcUwqJW1hE5nLPOtGPw1RSmL/cU2tFpMknUPRGeLk8PXhyeFJmq84Ci96pkoL71fKBi3cUv076TTK1hAJaCSfr10OJ4b/Pfutzm6fUnLKNcxPdJ4h2FrYiKwF/JcexxMOOi/b76f9SyCGah65vwfGIWo+Ghn0zsjqA1YRKU6cEmNTC6OQ+vZkX3BLbkmn89yBAildOsZvZgxeoVJdGLfLFxBlVWa7qx9tgGbO1Jn9+KPG8KIPbco7BDbg+cCz9Nd8EGpiELQMokUprPGDQ9jHfaeBHAsUcpiqR9OoVEuz2Y6U0rmueeZqQMwyGqSqmzxcRHeH/hJ+J5XiM2TEJD9tWh/cjzQ573Z3kbuLTRuG2eh7wfavwaFF5xrBERYZCZsMx6F0feYWufk1xCPEuBFLPwzEKwHqMJLQ4RdDdMADgOL2RDFBbK+Cbi8Of8g/SEiuEAjmHKwxbfGsblt2kLv5T3hefl4Miy0vVSjZ7UION0bmKNEX3y+CvBk7RY0VIyrdKykYIMDUliHuygUjgomMIzstFOBp3VZLkU5GSa63qJDWatMtJIAXNkp7gh/DpHgzK1Bmpe9ZJfqJl6yS4qpspYcTvjgSds3X3cIl1SEK0fLLSQUyiwrAbACyyGDa69GoEA6OYYYqYiJt4Prh4T0k9cjLGHnfHS8cW5xZP04FPCSOAi3QXLuFu01pUuAucNiXItqDhaSB0DmbNf3wNVoRdIvcAwis/hQVBofkXah10JgcVPjrK1B74dbXcNy9+o5ull8hFOm227kOOcDjHT9/yttkl8vEnEMzHkRtQfQwNUVQhLqWY59toRYAdbZ63T4S8k7OtcNiXI1ixc1Vj+9PipMYA8oXSbqQ1oI3xDCQar9qno8P7sHXYNzqTPsjP6MLHvdco6MUOff4ITQ8WdVHq0pJMAiLZKvsPMfBJJrEBiZ2F86vpkaq8qw1Ag+4DXpfHEudzSnX6Li6KsNfnRZteodNDStZEH/qN2lSKkqL64ZViGUnBW72TmKMKqa7gO6WDvTIORVRPRdmRaLrWyLeFnBl56GMWjXr21++LdUQxwltxoARXK4Q5iPNGO1zSB28v+wMsgiCYD3iCDi+ht/VQBAWsCwVff9bo66MfGsVqLBqhEOm/bUyT/zs4dM1gtN1JX6et2J3FEKr2lYJp0+yoTXG8iMiCTqLHth6c+SvwecLiBmcHOCEboR3g2TBv1ZLEoU1Js0ScEhZBUAZiSPTfKlJ32CpJZOvUFbvhCoD8c1Owkl1mjo8Vy2s+sQG5lyQ25p3usI7zZmMWlVYyv/WWB2NG+Vh/4KuShU5ktMYlc0+bT/4S9c49JJNiBdAcvgcodtVDDEihuNO4a4BepLNuua82KjVhe+EYk8FIh+b+V1hcFSWAzph9PNHHTzmmTMPk1AQVzbpmq5INl3U25Z9bcQs+0lLQyo/tc3g8FfJLDg770eQ7CS7XLVxYrAZUyWaNArNY2VpHoszeFz6qnPLnW35XSS8OK1hiOFRReCxhZprdm+RSBUPZyrEKtLUXaaDlVik0Tw/Kj+mXXPYEZVo42vw8ReyZv2KLt+47jveaYla9V28LVQCCfzUQyjHsoNDiD8Oa/njnXcf2tfHPm8rDQllpZIgX4QDzUsd7Mvk/yf0bHVSs82a+lMZY/TAg2XtkpFOApO/8BlzPzNN3XwzIVQK4ozryjitM6itsQAXMioYWpy5VkdiZz7HJKGDQWNtpdC9ih5Z9xnNivXuMsS799mDm7H0wcY4Vrm/xy2AzASdFoL5jyOhcBTjI6RD4Nuwx61JcI2Wvn4nnATdXsjzBOirBZ3nwcdGs89U0TqD/isJ2hjlIgArgkr1hteCWZN45fGyrJSVcsZZZUJ2muOrK6535TZDPxZ/oVzE2FuU6SXrAh2Ngg59HcHu5Ud2hSxKTDx43Q17nUjIQhSGaLoXHL3yBamHujZ2DzrA25c1IXow4eIaKwtV7dJb+maEGtnruO5PigFU59uD07PW4cnJ8QkRTQI0qdWXUJQlyvdimaS6nQo3DXc7cucrxbalYQfIsqxhA+FWIWOJIopJeVNA/ScFV831LtUyWLgCtKQRbkb4QSYQkFDVnr48Ofpwhq29P3h3KFAxMDUJFeZZSqCtDbjXQW2lSHeiV51Xj3K+GxFKjDwrDj8oLXYYBZWCeXEfpGMpYZWE60ZatkHBZmUXhsPCSEH2GqMRd0TicBdlAcFvchsuZCO7UgU0tCAx0t5zzu/Crsw+qlaNOCH8SaX6D2Qstjh4nWsHJlfj3R/fMrKA7F9l98cy/xp78bKwHQHgynfYBr7B9UqHaP6cOzypsK6ikwS7XC0pV+E0nN0Gc0a4J0gpE3LHIlOV3nHD6IBDJ9e5aPqtl2hKlC05wAqlFsBSmUq7IocAj+tUuUjhS2YAEVBqdSME6pkB0TJXt6gOaGPFOpZMbPc5GYLYlfIyDZg79dnDEWYW9ulJW4s3lgSw5zsomG0CVx80scip1IxgJ8ExeIqr8PJkcEYXJnHb5Ca0Is5DNEmrIPFRduIOEqwYO8ryKd651CLnPWlC0k3v0usqhbXt+DP9jG1YvvD+SsYyOdDGOQtnurZTNzbA61A7rHnnxBfWIwq5hue8F5eQcUCYgGU3gVXBpD/SPx/8/CsSFi3jF+7hQpjNjODLZimbuYEvjS11xVMkCViLxiYH3I65uASffr/+5eXrL398+mN02f/1yy8vOz+dvf736//6ePLHb+V//3rWE75q4nxFJBYYRneFL/u9/tHL65s/3vzaDz7Ve3+8vI7VsC0iA9VMmEirSx4PUjW1tPOvczdiFTr8fAMhTgwrp9Aeffj5gx/lPhJrNUYrJKpQ4H7Kew1SQic1GaaoBEQomJuRzzJCleiznEkXz0sb28HGXwcbf7T8jSKyHvXSTETuIkJjVOxe9obtL+wP4lhIpmeTPDe2HUyPibcikZQ4OiFjomE9XyiPq5PDX08OT1vsqUzYGbYZ/1hrhFFw6Wd6wVd1DHExwnZOF/1B741y1aGlUFkY0u0boWCUuynlHf/iCUGOxk4xrmISDgYp3LqpYZvx12HH24mNb00A1u07dMys7ivQEtopzWPX86sVX/W6xF2Vw4Y0qlZVgBAfRx10iS3z4oF0sPM+HJyefjo+eQV7HQ0wEo47p0MtCVYAgf5NJycbAY8tV7HcDCw70TuUoirKx0zjYJRKuH1TMdTGrpugXaKYj0YdzgMpLl2NFBU3BUftKCPUjKqhGAELNC7EivTBpuAp5XsI8HDZHRHdaZXe26WqqIEtTjNdXhOXwSS4HA77ysjDIVGLAhNVsX0z0WOkeNu6/Lm/4PTdTzp+ScsErr6zpY9IYWQT5yS0rwbd5AldcWE0A/ppShAWW1sxhwSdwoqh9fW4E/vMPWwdvH2LDrWvjt8dHL1nNBVesIZUdYCOACBuZ3dk5m+UMfPyslo8IOfiDJtNJneMXgVho4wcP3MGv9wQHgSiP5YIi9ICr8kf6L6sZTb+7AqEJphZysvmyGeE6FmHGo1YfL+SEKZhwRMqvp5esSJ2brIjg0z98q3f0zO1y4YK7IYWbubLWIK18+OSsLcop1kRVWGsmmoMUE5Ly9mU+aohn8AMfu1kQZ05w3hyzHgptFbJQVEqMknBjmrhHbIrpLlznVAriacEIazj2ynKa3L5TROs0Rl0Vjz/XLzIFUPNiU7esww20sZpJCE0TsGtepzR0hJ65HjQjCkiG2SkcLfNw+5nlG2YRudKdk89a61pVsZYuTLXtjkLBP+ka4QwtQYuDG1TkeFhetnrYsLTNXYoBr7LriTL6E5BLUzKPG2bnsI6JOSCOEdQdMFm4s26pCx7Q5J2lORVp/PeFjnvmTB6V/zpc0uvX0h7KTb5dcS4lyp+dJtqCfP4cDqR0yDcJRPWxZaIDXSo385JFZVmkgxrcjM/2/FNNV3zHHYhv1/Pz6RSzvPBqcJP3jzKNEuSFPTPCqBEvIUtjRbz1FI5v5M793P+BqPlxQtUOqqNZS1ZGePsZy8oqkm9OgIX6N5jOZM/9IoQ9ck2YJ7LN0lhSRxLpSpjbRiTlPc8zfOJoAP0GLnc8LIVTYKxHq6gPEQ0z082laOpAF1iDyG+Zi8MBsJmgZwSB+AEDVtBxIfP77RMy6D5TjpoIwIJmHFacXuu5C9kXInvTuXNRJugUwzTeW6SrgiTtGgNDwWAgMu4IMuXzVWFukKLo410nSGT4Yut0r/gcMFYwkIG0mdQ0qrw+v6yP7KSVTUw3L9ipG9gvIRGmJCPeCzChzu3jqmv1gjWPwqDAaxT2WSXthMPFe31HRG83McxuYCNPmrDDVumCYfaW/SwETecujEF/vj0fnj5/ad+8Olb77dKp9d5vf3nJWM///hUL7W/X3eDn09KbeFqZmcsaRDwwLaDhdC07EJsaN+E7S/puPoIpgHvhR1irhpK0E2/CFKYthKNxsjeFtK7+g9IXZmWs8WNYarujAej5fm2spdnw8NvmL+O3kf4du+bqTaEOgvbvPDPJXqQZn+3ivDbWSnJUwPbAqlBD614SPQedYzxna2LXDPDF9M9OxbYzbsqh7vkt7nITKMLnAyfv82SlGFgV3PjrbavZRi3JbMIHYqUXPSybstrOakYHgfTkbv4vqYDFCAgbHUSjy+2Jr0KnDU6cnVOmFzYYRCyUf3K1gLGNCHxqotoNhH7KocEBYVtRvEEb8FXQTvo9VqIOIsYtQbA7OOcP56oKk25Lgn4JgdB2Iy9ziPaeTIUAeohHDFGAEr89ASZgFamskexavMXOTu3jUadNgmZoJIMmb06bqoDAGMBaOr+Y8BEpoNECDaL5G+WKIa16jL6am6Gxs2CPGLvZISncE5jJGSPGMlNZ+hPQp4TCNgQ47GC91yCGYfebFMAkGmNxTKRUQtslg3ETJI/Gbm+0gR6eIr99ME/ERlLrAaSVGSkSOnZDUjIv5tg0JH5hZD15G1rrWANt74IcJd6G+N5U00iQ8mkyRJ61gmvuoOw02I8svTWIY3aJiExlMiDN6OQLlqMTsGeATGEdYkbmHh/4znlWLGMB87Sz32/CP/PIOhLln2FRVop+agCFcYXJtR1hv2gC46xtOiFzklUblq1hNBrlxXxLoTipb8WevfVqgsSfCZRl2cPT6m+ZAsOHnF554IlvQn+zv7iKCMORXmTjbLD7rSUI2Hc7mtJ0toGVCqA+cbkRYhrvO9l4cr02L47jGaOSw7tZlInqX/IQZQMVeOe6Vi8vG5N6APXRSpcxe9rYbKbZZW+U2U+EmwlYbAI+IF9Gbu7rmJ31wmrQb5W3tSJk5JnuSdLtVqNx/YaKBHxZ4zDmiNbzE1EMRcpdaFzk3l7KWcLE2zVlXCTTzlKhFsLLeuGEklqIMtNjdNghLYmQvRKsyZkmc/chN86VkCgmdaokHAnV+axaPJQsS0a+gwgB1Fx64P/HkRLc188Eq1qsSxvrDdSPsYclRaSXnAYGAa/vf/rj9/+a/jv19unJ7++/vXk1/cfP31HTkriuHnxToi2twQunekpwsM6Mviy8NacsmeliolCde8oxG7vuV1QqaIyxmCigQU3JV+v22KzxVxVSFb/2g1vdVFdBpux0QGxi/QhlhoDdEx/DruSFzTZYx0r1LWTrMgGOWgUQqTRfwS12DIzgSTD6pUFaq4kZNINFYrukJVdaHrWQc+6Ts0sCZ6EUvaQiydNgdNL7sPG7sXtm2NzJL7AvoUI6MrS+9S3bHp6d/HUKZccUypDzXNqSoXhyr6J6grDo9jjeMZlJgjMXhQvp5PJcLArYY2pcTh+qiUDjCMXJ6+3o9aXKIxa3IiQFxcHAjJc49mxIKW6SpDFAppgtHFVUAutoY74Kn7EDrjPpTl9sNX6fkJAgT8/zysJacswMziVZYuPJ7SNsonAwBU3mpu3vKYSAPG1hxf5FwF1osMCOIE6qBOcHlXqMe5BzaNphUoQ5JzefMkZkH40ruwI4WJH5xSTGNy1jjZ98g3w7NouOcyqFgNAJr/7ucJ+hrzVBCKF+KKA3+OPW7zDnApE17N3DVdSmlhVYFS9qzhWlIWMaDco0IQ5ClqBh2WIAdtU2ASLiCg6m6NWdl+SDQoKMJBcqN4t5XsOyuxIvhSly271Bl82di+n3V6nRfcz0uMQ3vaZv9b9ZTC8/X041VcWKGvPGLvvu6JmvYIUWjMvwP4W+YBBkSVpVvyCKtjPc//zLltAeGnXzxYiLSK67PtjJoq/6HS/Yngk91oS70GQLy+KcNtfqyi9j+ydsa8x8LrkzGwjfJkwJtlYyAS8UUpYyNnmOBhcQwV5GZVh3MYDBw4VtfcwzNu/c9wRTZKvOMH1ZgiQYO0yGAzCcR8M0dkmIy+gMoCwjq/BWJ+XCDUJRHItjmMNdfqtNqOl18Pxd2k6oNGpElL3ljoxUhmhmM1yPQw51vtrQbaZVjfTfLVkRJb7zL5uAqtAFDuj8RzS8SJvX8k+aza5ixE7pOjAFUSq2emOUYWjGevZrJs17CCKqci3oqc0g1qqZmtibZX5xqeXr3LzzIt+CCdhDvQvG2Dc+9r0xuHVOIxuWPkcV6M0PQoxybEJaBINQ04AV3SUGw7eDoNO05t0v0yCL7ifPD6zaL3bnI9r92BFrpOyP6UuO7kBlettWSWCMMP4JieOGCLbVZtaoetC7g1b3AaNskka/trYhb0xDvtDVPGZkU5Ygk96QwTKaeitvltybQ97Zioh7V4nvAqmvQmYIlrBn8E3XozDG6wsGK8kNM9LTEYvKV06lOUm52WK975fqm+i1/ZVFlgUPO/JkbtUbwh37i56cW/Dxc0y+yzXy9lMG77Uqnirms0M8TrW1bhSbt6biPNRriZr+4UMY5z0ynYgXVHhSzwlk25k4KNhWoR09wWxurZjIgRn1Li0kBbiAqlmeoyi9YUobHjspruDTvgNNbGxvur+rHxbtT6eHBnYLkXLa1l5x2g0GcE+tnRqYZ2zMEuv4eMQPg7ETw1VxIB39BSzI0akRkLV5rwRIWXVLMEWaphCfR9UTNw/xjNq8nTmxFBEOTlhoxOSURS9rvD4WWVOz81nl7ZkkgGfHONd0ibVXRXLVrPVo6FG65Gv4AyQT875ZKKpzwoCe/gpX5ccA7ef6Niw9DKm0nhOkiHpTbN8QNF+Mn6Dyw1sk/A5DJWX+abLp02Yd4/UXIWc9J/geMR6TxpCHaWtMOneRbl9dwxnbDNLxfnn2UXOUP4p/v9O5gK+k/7kxihsauHvc3IAi+xH8cF1neDzTnU1/6afxQPqnKOOl++HMslWkhOoPN1WySf1oJ6tOkwZhSMfQ1KxsFOegNMSo4XRw2Be0XQ5mhJA482T0XMyqIfMms4+LlfLtOlSSOenKzVE1WyA8eRCW0WLu6a5+GhMPfw0sg4HV4xxJJNuC2288jz1yyKYaJMgMMouL+2VpTCR8CJRGDMK8ElA5AvsQGI0fkwZKe9YuPDglA0pdERYTB4+5LmhXamw80SOgPSXTwwR1NAWMvRCXOLxC3vZnAF7xU/o/b24+TnhcdkPxKnaXiqjNbyFmULajALy6WDVVu6z9nQ8Bq0EcnHtYCDrGYdBRz2dJUxaePKBSbFFLnjMi80r5ihpdTsztngPDEDiZfPJ72dHB20iJMdmUkJhp1EDKvr3m9ff273o9rezEhoyGmqB4C7mE4JONYBAnxjgbbjW62eY0GVqm6VpGrUoXRKbf9KQ1QQ8oBY9rim9uGpMN1YK5ahxLeG7jnvqLJFUSVa7kWE0ILtncrkEtgEoD4lA6BQ0kccYR4gaiQsdWsEPr7Zvg58P3r/s//pn8Gbr+qh3Mgx+e3fdrtyMOi9/ql5W/z1ufz/sHt+WfsFw1je9v9qVX0u/vDy5OvnSe3fy6/vLo/4fo8s3v05//1TuHfVKo1+wdXDgrsMY77C2AL+FJnuHgPE3EZWjXLaNZNwjXcR7fBh3v26xqz8PgT/InbB1a0SI1oVFTHvsOriGJZmj4xauwADO1ErWh5Oc9RvK4M8NZfygkweffeLpikWYMY1RxJ90UZ3UyjFgT7vvKGV5JBDghuEQzEmda+ozNPfsA0dCyGjmVaSDSWtiJbSneL1x6+j+nhbzplAG1G3LM9mGT8RRILCNWs3hgRbrg1PXsOxrwcMxYE6tLgc6p0/RKwmWCwwoIS9QyRouDXygU16C3QAUG0s3ILhdt9OcXi0PTTbzTPFYZYN2pEl8417Zvogt30QEjsp2xTQEZnAZK/4pi0G40oEAh+JHX4EcljNagaxZgk1/hRZR08d5UxFy6Tn8HpaFandktTB+0W13wieSZ2pEmH7Ltyfm75c4J/bE4AcWLbL/1vZkl+4Y28WnDZgMcDCEuBdJYlbYZ9ikkOgRZ6KxjbURnWHDts+JiOy09T2vXXZUiXKqAX7NZMpHeD/xmdzfy7hgd1ZADpAVacpV6jLFtdXto4PN/xq4m5Z1n1L9YhNJhLgB33cotofStznlg9hWlQTnriSrWQ6S/jzxaZdXiRXcRm+O4jSpi7Q3h8EG2pKVDeBGqKM/u2jCFI4tGEUoBPKp3p+mIK/+rcHs3pkV7e+5AxpiY00yKevbnVI9KSc+khO0mRE7TI+78Mvs8Rl/PCNKZMmGKQ8LjLTYMha0nfBHW9YCmjkpqg46nR6l1RStUSsEFanrhEECIDBaU665NwWt++71gB0xRMKDy6Heo1taFnty2rN31Rmv1yXiisXEjhi2wPfEEchHpIOWgjsVTG/PlW3bkIcvDn/7pj/sJBc286PjTES9MFT001Hg9kZTfXC7Quy034yHvzuwAuT6Kov1BTQePEn8tU43Ci576jQUxhAMPb+GWuCJWCkl80DaOzZkdWIs4fqLSzjlkbdkG8a/RZpSnwn2Uj8R9FfB8PftcmyV8OHcFiwEXdWEVSap3FHU9869o/xSJJk3ZdIdqERucxQ+SSDCxuKdO/eZGFKAYE8qtG1wKDZvpz1o29m2bapolRIjRtqB0nPP5fOtExU0WWjkN64A0Ci2FJBHQTQJL7sDv9Ae9ovj4JZRlKwgSEoWJYwVNN8ZlPZ/7UIkxXvs5JhjZaW1oBZOpZbfbsjzji3POr2kmMQCRHps1WarAB27r2CbSedqNv5hrJ+68HIwX/T88/+PQnPzDYLfjLjXW0byD9ztDT9ej4cQRDBhFJTxh370aTjufKBkYsFo1OsSGnyWmmy4T2VNrYRx9w6d0gnj2XvG6SqcImvofFarlQzRAYuuGceqHc5jbGHB+e+p3SvJu5bazbfZWqNLfBPf6TREtD6j9W9fRluQb8zLJj+Vl52W2Lzk8GMfUnQG16AN+Pdw2O8FfuG0OwmzfCq2BNZn0lTwCDDK3KrNRHGPDRz6lQynk/ug0+8O7v17GLPqrLhnrMaHSMhEXt3sHvdXTpTqNQlSjua20F2uvOQyuOayzkW3jaln2P9cYqgvASicGzdeWnqcnp18PIzddfAzGqwDqbQ3dhmddNvwYoRhDpIfiWKIqlOJL8HltL/KTEGcapVgdOLRaziwZW1rOl7UFl9NuULf28pg4zBcVJIIZtU5ZBbBrMlCTgMmIveUq1sJut6lEyzq70V+TfGlJ1+S0S7TFTm7l1Hbn/Y44u1Uaq5wRD4O7FgsiL60hygJmdRy3oOoSIGjuAtPbtpPuh6GSBp6WBsV0SxSUI67VJ3/+o6zUdzCHHaYnAtGoCqUwGIls4Fj44XcnBn4AOCxQuVzb8zPvcSxIAtEZu8hxA0fUp2Wl+gNlRyzJ2eXLv5BL0I5oCpPscbC96POx6g8LZUO/utq9Ol97/d3nfGrm+Ot7c7h8R9nvwxpEdY4ivycWRAbgCJvSPWqDXCCh0FC4ow5Y2cd4/6F2Rcmteq4v47E37altswXaOxNkEFJgKThBkco3snpgp2L6igxRbXJTSsdEWtBvAbaV3YMKoWOBbqos1QdRJfOFz1yofpMy0xbZZpDsjaPDudZmIkyZ76pm0XwpMAYcbZ7t40EkpuI9FPZnHMIJ4c2aflUcMtoS2HPnRcGbbpzy84vZih04mcM5wGQH8MosXqdg+/EFJ7EYBZ9LXYe1BQ0Mgrpb3OLoEhNECbBRups38wwcceg9gx3FGnKs0LeXKEV4ljMEwhchfswaVOIiEXleimpizI/MXvg3GMSVoJMqvF4UizN857fwYP6ye7N45t5LJHRybKIvzHXmQvePYTTslD04sZ6AUoKY5HXMNzKFJ2fh9Tp0taoNs82JbCo2MpWtgow02vrxDTf28m/1VtuSgW8kFXj3gQcIAqHj5700sKQqY0XggI3SsY1MYb4nF9QIrTmsmG8WFWyEerFzlMXCnFYpNHmK08gX1qWJYLo716xorsX6GGYF0Kbv3Z+VO5R/2V5ZfXtmJ4MZmkaDu1KkdSw+cQ6yEtSPSB3N23gndj+JASmam3u/sQJM2EAWN/YrBQxbLigFnlazhYu8jQtcsdluFGQVeQ1J1N3aXQ0ExHHepEtXiS7g06n8P2FuAfqTn7ThoHeRJSlSonMia73xS5mzFdzv1nsxbI7l4wSfWGNvjw4PSRstef+nRPiJROvIy8waDWHJGdLWa0l+o9eDY96Sso+Z1ZrkhFlfUbnPy5/ilyd8t1XkfnZ2wcD0Bg7oGsd7dMT/h1XRDywRYn7vb8n14hBkXnhOFlFY0pta8FQ4QHFNve3UmnD/7b5GshmvlJnw41lBO5RP+j21EsIPMkaxOoKH1nxm3U7/7cWTNsl00ZR06MEganK29tzqYCcryb5kWuJHY0s2FccBndHzqZZheee80Uvp8+ymGRRZgvhlmKTS6DAlF0yIhVLgoTtsM2ZbLkvYg7hVari6JH9ahNNPPzWDkfIeqxB/M8deWer82KHAFfmyPp5+45auPBOWwSphWTLxW/aUblcWY6OeVlL5bSvYb3y4n5ZuD0SA33v/5GlZssxoL6nSOxo6AUqxmhbqrGlIEuetl2pH9UUIxljUCoCIkcTKqQBEDq1hxZZlHu5sv8e/vJs7lmiUqwsiHAteK1Od3wfBVdhq89eLav4F/AmqEEHJITx0q+cYIQFHDdGGWeOuSazR4NJijEYu6wftxsovobHENSkJd1KmLxEZzXeyrEKRBpnw1VXf8KddGWrRDqGOBqD0qhbW5H8kmxYlQctMJeJ37XFMFYstrEdDL7Dy9XVnu6+XDbo/RaheW3NkVo1qEmBBvHQheZrUmesj9SIzVCv2KTZGKV4bi295GJ1GCO1KaAsbG8LF7w0budCtkAWfL8cPoXNwFo/sRMirieWnd8SjOATQq6gLiGjtZ61FH7GjnWprFFBodfmV4wqYmKhObp4BtMA14wBrmqjYxhj5xB0OVTbAmIiaUdEN4F0x3loGlBtqcWGq2ltkkotpp6xD8KnaNvpY5NMF11jR2hf9frTqaKRnu1ZSDj/dVYGFJxO79/l0uiXT79Wfv8kDfeMG4trskjhrNNYxPaiZO1zLPqGvGLafIQkao+RfXT4a7jEcbln9uw6uWnIPA0cMThGDmuu581g1XoYsLsHTBqOTxT6VVRdr28yj2ZvbxUf6kLXhRsI4oIbsyJyIM601n3NxE7IMnw+kNWom+icbI2sCFO959sREMimCxTqveffetG3+86wDf++3Y86VxyV+vp+NLi+77aH99F/evd/dUfKJCqcYuTY1WIQICaC4PLOkabzXJLv3PxTYO59/fUX7W5BS8mZRP609nqsDl5Sb8LiZxC0DMJ9M66UAZr6CsYEqsxyUqGkF+NkBl2vWFEz3gSxMeZ6JgZcvCMfCUiCQx652tibzRh8y//WeXLPBCo5tuNGb9sHEV8uU74HpzwVhWCFiEGZknL+0sZnXoCj7hEaV+EkXFbB8mZsKFWmjd7k+0hApsKjEeYL4kPDltRUvyn8K7HgOsk2CDbF7+NQkthAQGo6wm8OmJdz/6K5/8zPtYjSt1qQwPmuNdvdZT92eLcoD2yrSaoHfIqV9HP8EZo0uLy/0SKIQ/gOtTq4UARUq2xtz1nopPeU+P/4JllM82JTKmPRl/Lbs+mIf5HDzqpu3j/LuoZsPhVb6P7ruMbO8D1tG8gdsGdvgR2h7xWzRD6yjhVfIY5kE4ydqLLP4rGinxz3886YLPGbssXVDhFKd3D9131veH3/Z6TOFKRglivDFgHBVVc6A/+u/mlLjgDftuZ4UbkFe+FKrSADJTc+X8FjMRPseyAOC7FCGhqhXMBf6ANcdZvOxGmk1JOI4ydWlw0STlapdJ4tKf8be6HKLHtXK+U3t8jihLlqY6azLYJfA8QS1kHSphg6FGfaBKjwj9/+/f2y+u+rdv/XW/a3FHyqD4hCNnTvhazeZkZoaahpsnDEyL5LQ27oDPb33FHBDq9CU2Qp6Qyo8Min5FV1TU2kKY7p2V2ez6pRir+WnNfYtGIeTxpYS52jXoqfUvtZGOeMduZDfvsL2QivkWT9mAzI3hsb56ZuWIVFLtsspQTwb3XfQQN7hd4fZJgthSPpW2KsTnk154Y9bZXhQVXaNFR22ccsstqyi4ySgbtYMDe354p+NeCAkSDoiZU1pJqFD+/46IZABKOib2l8CbXG7TjfP3774+by5U3399/e997/eXL1x5tf/7ysnPT4WqqLRGeqBuvIQWS1asNWFIGNnP4P5xqqh7tX2T3pr/MA3Tm5dphy6Z6UzNwKl6WrJdF0z7+QAQGzeMqVSsxvlcv4GT/ja/GF93F1/T136hKyPlhpZ/L9K+a54MQS4kP/x73ctxxhzsQhO2+Vji9idMr0iJHWO3DL2+IuHvpZYrgdA/L/0fWgOwnHvF3K5RHTDc6zYHJWHgGZ8g0yqc3ijiv4OBwr+3tmDsqHWkiVOU450SiIbE5GqjJRFL4QH4YsjYM4hBm78R4jsF8Pp4OOdpWfe+tFfk0h4+4VKQJPujXaRwj5pcjniHmm6srUMzxGtyuxnmlrjy0KrmKyFUtqAJWW6V6u0qxP9pXGzLbLKZd0U7e0w+M9NZf05WIF/AJfOXg0O1dO0tlK4GJiXSQ7sJLu0LTvs9kXDy2IICtrDFByae10q4rTDZ9Q8YoV3+WNXbCvmMpsJWRICqtv84YV05fjrDErR8og8mG19gDjjYH/Fbww8r6MGdaMawbDVt20VYSaMtOV5BfqMbKi8U2H3kci2y/nuWS0UpZIT6OEG2cNRHBfxwZ8+ZFdoUkOxq+7Ya8jooY4BhiFd1brtFeo5NErSfChwo3dg04HuiprwLdlT4IbyWZJiyfQXp9g7gCyCk95GALoPH4BOMmUC0wyZUFJAovXxKwfoIuTiJJFWZM0K96UdwFesju4LhQKrEDZzJ5FfSL8g/LT9amQw9lMNVPvgsmNX7jqDYeMI6Yf42DQGYKRMZvy11Pork4jl2KPMdlq2oeEJwWedMV70e1fp6Jxu5n2Un4u1YMPLy1S0L4oRu1xdzRZ6a05hyXeH4HztpEtfUG1sRUCKo+mh8B1fwZfA7qOw9wbCmKjoPWMuYj3jE8+wudVK+wgfcVWeXsyHH8/QmBAsDsLgED24yTElz8cXHcHYep4oC79FKDwXmTsdVFdfTlEj6B/3Qn8QJFiDpbfs43O0iWvVMmTKaqXtH4x+Sy1AS9z/hYFzL+/cf+zL5CBjZ7sdTtNf41OLgT3Q9RDNdy3rOzw1i9MhqzXarowE52cKspUX9rY3ii0UjlJnfc8fe6oCfRiBO7fsT+oYMq9XHDdihYR7bNwPRxe98J+d9ANRl0KkAwG19NewKhXH0Im/4z4ZtYW9rvDs4MUZD/bYCN39GvTOzl8fXJ4+rOXenn8/owRxqZX3vl48rY5nxi4kuZt1WTmjs9Ij0mA9bnqjv0jkNt1kYFJga5puYnURespRTmSnyVneNgz8AqakQHKFrU6i1rP1qjzeNAj+nrS1GgLgp+QsCz4V7k4+G9YImZHUaNoAs0ZU+MYZnVXUjNePdE0foangbIJmD9XzVghvWZDyJ/LZlfRtVqiQY8N+lX3GveQAn6VJ9SLZ+yYPfv9wyFOW79HLaPMjukannqAX1zknmoklxzFLSHHGAQWMZgB+EinUrl/3WG2QQhfaB28YVuMjXMuaEfsjDKIVE4jUmvs7D9nHTl/mz9pVksV/4La3Rbh1q521xe3C4SQtXAw6IyH3Q42tjaPWLJ+OLqBqHjoiryoGyneiYOXLw8/nM1SRNe+sv4VbgNGUm/7Pf9eY7u1W99glfi5b2z54FHx/mX++MS/UKMmDwHHaz6jZRRt9MNON9iA/JLAt+WgGv3IcYw8R+Gm/Cn2i5eFfebF0dW7YYc9neoPO60x1caI8O7cQ1cfEkZ4D08OT2bUPDSeEYvPL2in1RJvK57vR0wCvx+OwnFA8o/1tvOPzaKLcxBLQvVHL7aH4HNwgmJr/3V6kKcT/UVRjA9tGEQRBKHQXjD66OiTcc5OVHauwqHKKkSIBVwPa5hPJMebvxxT2znkJKilqrCcO5vKOIeTz4XPRR/GeRfYRIjdAcOYYYsvS4E52Zw1NgWMQ5eMG26Yk7zsUA39VUA9/wMr9tPhm6P37O+n0smrD+zkPYUafpDLCc47bUFxGoXLyv/BeqN1fCN5WXJ02jXxmj7X/9gT73M9DfFMD3isoz+mBkQuE/6LnzRgYn3rC7PCD9oqwd/s4/A9iEZSJqcRJNAjNO5F6wtGyqdD/XgkABz83Othrze8Pf3ef8tB2+1x1KmWxhc7CCMH8PI7uCTPN4pIkGKrHbMuN6wlmEpa67iz8ooCpfy1Cl/g/O1ao2Ac9CNY7D+OgusQMjA0IfMEtrYphueBh0Iu4McB7CP2Ok7amV2JehLb5Z+yrRDFqSicnqC8f/C+v7qN73sZvrbiC6/2SpLXb/kbPhKJzLfvf913B1fD+9FtlpYNdotUJvp7Iy6edOV0bubYQSxokCYOF8RmgrrLtJVIKiTUOYLamkdoaY3nzDXOzybH0ZB7tlEgOVzrXkoXqXJxkUrrVUU5wsttGduUuXfT3qT7aze8hR8ozALmWO7wW9h++eYIUwWAVHXQ6fyMiVNBDdO+7m4IOXu9gGxsfSaaxVRUjOwWi68RQHXjLOyPQKHI3iV2jR5BAYaHWGWEKklHo3LgLyuXL+kGpmJ8V3DWBJS9nKSNyIFSp4D6NYR1V0YCnE7GEMVXuBoP+y9vgjFmu81kSAKClUfWFcHN6hU2xHwoHUUPJEdGWJpK5Nx9dGum7EtoaHW2/CF1DGgsLX2lUtiQkv2QCbfwM+Nw7uNoJWUmmZNDiS80nsBg+prkjMVFYSZE88aSXigSAdUAmQNLToIxQB3Uc6o4Eq2qfl+HE97p6KfvZ8H1e8wggz2oiG7TWFByJGHw/X8DgvhsCiQwYUD888zec3z5vedk2gerV1azoOT3snpMAnSxAKGs+XKFUAPRdVc5NfN3M31lYu1SlqBI82QwHapQh4416yBphIHngojQkEK3ED4NDQxyN66jnR1V7LuJI0FhhoDMWaPwb25CUrPCeARzbs8pDp97s8GobLPHZAuibngHqOUKFK10t9tkfYMZxirKdR8but3Y2AEXW8zBJO7fguuQCvi/0MZchIKzgakYIzvjUY3WOLKCAXodsvsmLUGgNqDTWmDU9V9t/u2yUePfxuUqlYcjCHNMiQTca1ejPKQxOYS8JT/9BB+vPYiPBSGfnkFdHdixzCw8/g+dqzqlO9xCnK46lLnUQ7QW0vxzOCmoBsq4B61ct1qt65aYYNJKIVhVlbFK6AnAVX6k6xsVL6ubtS8beBRR4U3OV63amwJ0pyBx9EX+EKoUSBWkcVMp3xZX2O5Dbj4yBhH4ESP7O/ts1KcD0/DsZ7AQof0woU26E5y8rD1/fjhoj7+PqARMeX37udfpRl9aV+MwbEUjkRXHla0rm8qnrLJUEa4FxKMZQb5dzByGIzX5lk/f+T+k8+xOxc8Rd71FuPNyqekg5SrzCxWt8aIvJp1d5NqAN5iicBKk2Ji8KLIbVBQPdTBdsSWneF7IemD8hAaN3+fnPn258AtUE8oa7HVeHZ0cvjw7Pvm9dXr44eDkgH31pSHPbELSrn09ec25KJAmL0f9GWpqE40ObJIYA9ZS5IWNXDDmeeEYCVgbUOktvkdVpiqesqfAniqwpzptePtOmw/0Nq9d+P1oyQAKGtQirSqCggBMnbUvTQ92ExsPxqB5dBf1NGy/Ox1diz6j3+tFKgmrAcLN9imfWKd7ddWafgnJQXJfxHdjjjlGQrPK5Z4er4rtq7bcNxi8b3QbVgQCYV/IwNTXbLQPYQ5m1j/hU0BPojq6gU9m3n98+5Y7fNlrjiLIWf/fvmp9ODl8e3zwCqekUOx1L2+H4y/huBANqShOH1tzFyIu2BdZ1Bj7Cp2+Y//nA7jFm+ews1Dnp9NjHQ+YysGkNXAzdYb9AFP+0pKgnxGestQIrBq+08RN4h3LNKfbGDFbZ6PVn6jCJV6oPZwOBBjzYDhpcRGO1lx2Q9ZR5uPBZMecvzb0RfT9bCY2cEcUrfAlBE4IBdC5VSv+ekXcJT0SOzKGoyFSXL8QjOkWzCo6aS9HXMtEWlPgV5Ta5wjqyxFSaq/OVzN3HNKcMD/8/KF1fArbiEriaqjTqpHpRiEtIjUgKtzkq7apbu3IQ2cbg9EAxF4u6XgWNBjaSHf+4d6o2xSehWk/RaOJy2cb45Fgz7sXJDRzp/pFMUHs7ZqDab/VD9pjSbqp1B0Vg3ltsGJWHsolD0OvV/boKOStVrn8xd1fjNSWy9SHXvs9TxyI2xifgsscQQjsKsHDBkBfUq4bYnViyAam7WbiK86JVxgXBp4ApPD+VQa1yb+qXh6+hkEHvqLRKwOAMv+qiGvsNrA8/6pSvbCAIOXPvnS/IUIYXwH7yuGPHsVFhfR+yLjYjFdk9LoY0j3U+GziChZSpektFYMRWnZzkMM9q7r/nRJNbOwSvX8NxJ5YbiyInuawMP9482v/999+jTqvt8vtyq9Xv38a3YQvD7aPfj753vn0kQojt1E16LrkTXL8ku8jb8j6C98Yv0RKMr4R0C27qkUh5WRN9IWxn+w1qWyV80hapiXYLyKNNRWq8QpN9u5afLnEYSMSVZFKgzVyaKG0tc1lN0E6fMcW50Gnkybd1Tb68NaNHq5/gzN5DeRLxjHBkZllB8hwOmmyMwSFB3+t2yyxfdSlKmCBQPIOM4ZPUCZKHlCG1AEX/m/rV9Gw/QW0KvTsliCBaxQEc81NvjAvL4eDn4YTYsm3K2QiK1MzzxS2CY90YK2sQwv0BeOHDkDnLBPeLjM6g277C0+rCOJKmtD+eM4DokLkZQreOZPupBfu/hqcsP+DIfs0DMbtm3DMuEG8Q8UFe7tIQum2h4OvfiZ9ffklnU9j8sNi8ejN++OTQ6qI0r/XjJniGXhxLRVye/zsTDWbKRK09Pvoh8QP1zHAHIRtyGcMh1f3KuWja3Z3dDMcQE2saBCkmimU42gC0DVxc8sRfafm4HW5V8XxS93FOTRWbYotn8tupxMOnqV3UrOU2FNVkVGBwM4TWH9WAVuIgUjC6PGAAHYZs1ULPpJ3FylpiZaLJg6kr66u0uxchR7l0zdDyA+W3S2lhuOUKIVFfFkGUWipzoawQTHxudWZ9kfLHj88/JyV4t+oGP9Bw8e9otlGG00nbOyHlwQx0AsxbRVjNGDtwKTI7UOuciDEINtwG/bamKIHnCDH9U0/kkLkNrqVgQeXGVXBCJxfqlUxSSt8VPjPcq1Oj21zCVvgpqQP3p4cHrz6vXXy8X0Lthp7B4iGLSD1w2fQWwoOMRdOG3vdTbZSCmKvglSSp+SZeZzogw8fwFh0//b45S+tw9+AxeteUb3lHTOlOVJedAItsuUgjh95vllnDyxrnkbFZG3IQQgJWGolctEH1fYoGE9wzUMWbXkFlg/+zRLZqKkQmJjrLYfU8G4BipyMEs9ZZ3c48n8OlVlgJdlh7L/KUc9zrkF9KPvJeiB0J8fLUeNSXFnr9q9fBeh30yQOkknEIC6Oyrj/+V25i9B7BpTtMIRpRvK/fv3axE/cVEbq2IFHj+AmQREnhtIGHV0j6wTpXG4hi5h2hXRU2gX0HJxXgCiUfoWzTtQZZF6Q/qoT+CVQxUr9A8RbquBXf20cChdPgEqm3SiuwKkFmxEVtn7m4HXr6D1t5lNYp6dnbFO8o59vW2cvP8jUVJl98ehwMAgptVWE6QivgU/ciPqT0QanL+R+UjZxEHUZXAOHRyItxDIpWJXyQp4ynkM5agcfETL+Drn0eMLHcZt8UEBV25TirBwcjnFGAq2WcAvHnM9Tyr/3RZIEus5vwOecW2oC4OY5/bngbCC6pIBM1pQlmACUVz/ENVhKlJNY3Sy4/hgp4XKaCz61V+a6NnnKsFHzmrv7bDq+MnaLQC0Zpx19ZVfxZl5mKGa8czjuBj1EMeViN1Za4bRXm1axBbEK6AEZovCUJuXZNro8QGy1rkVICXUOpMzBCII7dnvOXX8NOAOu7wCgwk6Oaq/x6K0dZ3DSAjZejiQMnxi7Op+rGJrBYlqqKQ4BWp6NwM/+Ok0oUTLIfSHEZM5dozm+HkuDOOcI8F79UdBXgOg4UAkLfjTDms02aXakirAMgGfgWdu8oD4RlaT8daBUaEsLCx+iHX3qYnfv9D0hdjadVHwzgGZ9Rwooh18PekbVM2p/m9P3fb6m0/4P/g8y8amH2UG1vN1pkQd1G03XFjbsuMF7Mxre+plKviG2C+nKpkiG6OkyVyiwezctYNcYdxJbKuxWtwMGf/zKNhFvGnNug0bnvMqIEtlq0MvFwqxaLC8CIZ0MOegdVV4VFt/r3vAy6KXolKQ/TT7MaT7IJf+iaejL+PBiWaIRtG+QhvJIoTRaNiyoes5i7Mx2KBOErIs6hYIeHoxdpaFmh24+7Z9//PCqxV11N9T0wI4CWBcubJyGAybzpQ4Gw8H3fuoQ3jv1/Hnq9dshG+sT+Ho6YrNwYoggZBcGtdCIzR9IVx64v7OOkd87O7gFO5Hyfh9Ox6mjD89T6pqZfv7d8Rnj0V69OmE8DxsNF5s/GU7bN4Wc5kK8jUbiMgdq07cE59zXukipYMA53c2klU9G0c+xDZfOU9pYtoOl5pkClJsFRYykTNEgX87t5ZsEF5lo2OJkvpBbQp9RyDWb6ThBobRUbKYx/QPbuB9616fInv3WDnpsEoMxpc0Ajw18As2FNbRKRYSzjuc68qKmpi+KumiEoRWCFjMUi4204rkm5l2G9SjNMoJVK+QwvJhLhdG6r0MU+goqa8G+gwlG1Abqh+ChdcsDjHQLGX2yEGZiJgPG+QfTyU0LDFV5bpDLx0rxTU2Wu02dTmd06mkq1h6ieeLyiJjObE6v3q3Ww/2dj7X+4BuCcQRhl3MV0KvUc/wiDT/hn1df/sOIzl/RDp0BmzLM3QjGTtESomRWnojr74eTm2GnOcL0xbmQbQwITpDCC87rRodJArsvugOQRvE+7O4UUHn8Bl/43Nc5nyKNfGwmS8DJtVuMSMzcS6IECyJoIZRJHv6W+d+KGAT+Yki+NjdNxQOq27gOaEndFwwgE2HDzuSmG4G3nZkiXfKhet7rdIcV7bGTAZPJRfJEPb66Mvzj40AuGWG5QOstx0AleTiY3LBz0qHgSPmFVLqYhj8SckVTr2CyYQ9ZY7jlCcOuwxjmfmrSH7X4k/mU1htxwOMF7RgXHdAL0jsRw4N6O5p09gRIMgJ/F763IDs2tIM/AJ5c/ugNr7sDdYtt/lv4FcLjrGSPnR8BXJiEvWFr1I36+EtoPEUntndkFmzsfq87aC5pCugOvnjkU0HZSUH/Bc+D5gorR8M1Rruu3Y5abIcIIyMGUtBKTAl9L6P6YmfaDCfqkVgNZOdPe9pJkabXoAwv4EeM6gfFF5Dyjh07bFvm0z+BPoQdNalnTa6WQ3krlVT+9fHH968Sy1PLpFLUcU8Sc8HH1zdpGHEILayKksX2wulT1iAEYA/26NhDKzwclIwzYVt50r8JRpd/tcPxFdviw8HVmI3lf8ajy/+MGbtGT8g4ZBdRKXMgHz7XoFhCqDb2pzn/ZMruUFbEzBiCqjG8E73eNqzfYCpOqCfWtABxA55FsFI8FFJwCpTehPRCV8MecHfNlAW5wNmvQg6jLFuX026v00IP/UJODjLeGsFx2eL7BPikiNGSJmu2759DRt8CfquylU+NNwSX7FDU6a4cImoxn3Ign+oFp9fXbS3KEVc74zeE7GCWjtVFnQJ6uS1D6cANm5jZ6eRK8LXsIrGrwMh+Iq2nYmY5B0pL7RaVuKRJYWsU+6NzplsUbrv9IKk1jXuOcwwpYb9NecMvnlCWcDClO3VssZ2qfCzgawvTa2W0U4h6ts3FW0tjC3wC6TIICUfxyRe57F01PytQ/oOZWGPb5ITDtswMfIDIJWveZtDU6XlDtc5oCXl2JW8CgaQFEhP+AXEIBuFu2Sa5OiWlXdqhjqtYaTLhojsIyO3aIL/sDSO20l6FGHoU/jzshdFP08kE7SUw/BprsU0ezBWekSfHth60d48qh3vPQxi2e3xjAGuuz0QpzyDz3s6Sj1OjVW6Y0NSjhaapzeK84I+lb69f49tLHyUYDOnIpQaixo/CGZlzll2+UC+uXlJE/OdXoZSKJsNRi1ve0GVl08ofwySMzHnhYk858JwXdi6yOamEkW+i4UQT4o/R8QY3/HgQbr9xAOY/gjiaCAduPFk9dnatAQdyNnw1HFvXjgfvvv/MeA3SP1NCga1ynF9cTQTQue+0YzfzKm9vb5e3vkrxgucK2re2NmutGHSKUnOT3pcsv0Y34Qacl2nJuhawn7JDeF3WEYC1V7hzzNTQI+HbtEQ23kM+fef4F6aX79MCiUTaFQ3NJ4e+OaY619BrCYFNr3AP10xzVzyRX1DI8/LU/W2uuVKq1HMYB9qZtDFbHnnFxVSrACmA565ErEnBGlne9OP1I38DGG6PLD9eAdPCiY00ampKE8/ApvD44cu6QKJ73bI7CTk/3SVLKmPf0gVhhqahlYc+nqCd4e0AuiI4deDagV3us+MO5ba0Hog5bE/CyQZbTWHQTwt2l3WmIn0c8YT96fsINRfraEHU9UmsLHrO1Hi/2Yq7CSZ4tnJbgHc9HHbggidMAtJaz47WCfIBWa3pGvd0tA/gOzC/dHIzQy7nQyCIjKOM9METtBAr5G3VuSbeL2T0NM+ermzyUxfre6wEI9n5GX8OvTEt6NmVWAVJ/PAFkIBq6Z9mnlgUm9zxzsGR4RvmhfCRJm4uuyMTEtAIKOrKatsSzgpKOfQSM5J++tASwBI4Zbz8tmAIWdVtUAAIXSky0XSJFKaWoJM+L6gQKlCPQ0dIqcreZBKi1wg9n7dVxK5nlVmhXCJ0a7BMoTot9aE3ZeIjKdAKhooGYed1x5Mcep1guIBGkOhochXGyAWzTkqHqrfJpwrd1sqUAdMmoFKLab1qxk8r91u/6Dcv1n0i8aBsyvp59qewvmdwUqQuitNoVUYojmZKsGDdQ3e5CsRJfTh6/4bVGgVfKZJrBFrtHyHWENraH162okmABDI9vHwZMKb2FH8LPTSrDPXpgMkj+G5goCnOn9VxGlxhwHT4/EUxGgUDuLbcrpBzJI2Cac3Ni3WgQCk8Ur7HA/Vf+BybRWyZsnDblIu8f9lCcQh1V4zid6PhxtZWfXuj7KGnwt5Pqbepw9Qp++8w9Yp9HqXes/8OUycpdpM18OroVyZjsC+d7leUQHyl6mQNoswGoR06O7BGkrc/T1k4GUpswZgX4PTyT/TISbjfD6MIEi5nFYEjPo83q/gVoL5pznOLayjXsy+kRSyIp3Y4eUP3wAaRYFbl1yDS6mMMdMSY6siusz0O+p2gL2pllX7ltZEbah2pCO+2S0O73EmLgRuCrjuQkGXmtn03mrLSU8D4twIQsMNv3LuSkVMuGw7VWkfGaKtMyq2Fc/pIPa8xhb50AFZcJ8lOxg05kVIdzKdTSDbsJdB9Eu0Ci1Xly00E2mFlNhwmZ6rhyTVh1/3tw4OEID25CQZfUt+H07RYvgQ2TL6BKeEciKwJqCBRi5lNcQFdc7DyUEjfh2AOVtgbsFU+/DId+QV2JbWBrNO731JaJQUP+Cp6Xiypbv9bc6PMlw66l6KkvbINU4wuMfRsPaZAb7P8kzumdEJkulaqpXDreyIAyKAdS+si2JuhtRYciJ2OfdCc96LN+JRwvPvicvfVcBAyznU3RX6dUrHMaPjuiyIvx2uGo6VW2rbly4evVIMT/N9Q19+2c8jJgFOODPniZ/c4n7i3o0u0LvJCWia5yzAMCoGUqcMZKbCZXzL0jdSQ2T0/m71/upcj6McZAbhqb+kb8RNJQntGpgPTX5S/Hx7r9U3uMgqWCWHOQMMEvRU/p+kHP93ox8/4vvQdom1b+FQ8tgPFI5d+UNw/HfZD2rapYZttylCVltwd+m0DIt2bo9db2wc7hlzyzHJL4O5R0JU7AxNYqZq4SGLptbAlIZGkd4R7yTlKXwUP4tjSXAV5dbDxGh2PMHC3lIfssLO0crbkEgk6fGMyJ/Ns7QwiVAWPWctjM5xInHJMIkMLpV+YjruXPYzd8eSpjf7h6GNFourPQftL2Eldfk+9f9PY2j79ciuE2BcG+UF/7vImKhKupr2eIoeeNOqIvUrdeHHJSNxoF70vouf46+zwt7ODk8MDxj3uxp6ih4qiDKN/I3x+cB0OboJxN5hbRz8cwBLrc3a/oNfE36DMg234m38YwyoCP3/EUvi1YkrvVan0lJ4WhXRzFzxyGeeJKb9zKnNZMePjOlkHvO0MXzRS+UU/8voQGZFDat4J2BYiF7hu3mH+NLT0PoCEcS2+8j85fXly9EGBWKDvsPmQ8CBf+FBJMo5O/zfebbQ2VZR1gJ1nePT5Itu3QA7FX2DoQyscmjRpIa/h905eFt7YBSl4Yxf5VHJ8ULeOXintYDdqRdMRMLPCA511qM6DLVbxefvjZ/5wg6uJ1VvPlSsXi5y6mF6lQCEQi2wrIrehCfU+k8+6sAUHQQ9Mq8MOFmoJVytRZhxeh9/mFUAhj7NjlgXBEAF5/8jSw3Z6Xq1cuWw1F2JxDRMDM+aG50de6pF5xdRdw1uI9YzSpLpcpss2r4A+vWypoCZGdwU0vKbh+wa4eO3QqgS5iZ0kY0b58Gm9o+LRrFYWnXJU3Ii83RlylytG+G+5HT9t1ULvhEEAjZqwzi/hS5Uu3FVQGVZBnHfhVsWrQ2ULaOCcB1he+0QgAlKwGS0wwio5XPbdK96OfFDislfwfcS4YVeLvl/E7cbOzXEwYUKzXyx67Aa73f+Od4pd+C3iIbxWq/X++Oz08O1r9i2dp1iIPR1dEZQh60WVHpq9DWlbGQ1m1bamQAgzWeS6C2k8DBibnBYOeMChoONOinu7eV6KO/B44MHjpYQDj+fw4PHIY8fjHPvYS3U72i9G91lnV7GPAO8vFDZwslF0nvSGEVlpMv4+z0ejwoNADKC4D+GJIgm4owy/T240bMzoBCkLYx3s9Dv4QL6ogAcXej1L71ltL+D7ycBZw8rGDzOZ8duumnvQDjye252cksnT0zzvpD857zAa5Soi3NbkZw1/08XDnhWerazaunDnJLNGa8ixlzIHp+yxs9ang5P3R+/f5Etat5rpc8acEZd2wThj2Aug/r4Jv7HNgdo6LGUYGtOm7cTY3Q3h8RyjWAfK1sOODSAOaLfh32MMRgaB7dcvIKsI232CxYjRJznSvAPoJVBfxnUFVQLxuETTptAJB9+FTRX8EIHyQSgMb21LyPVJregrzqOwQc++rlyqFM8z79lVdQiWlYQHvvXCgS4k4aatVuRq2hZGKH8NSWGTB+WIhaN7d/gy9siShEUJzQLBKbD2OmJt9Ts39Ae7Nw6/cteecqkuYitpUfi4KopiAX9Ow8rN3lVLwiqDwRpc0RjDumUUXTeu4sM0uUGvR0pCOEpayjapLznhIl7klpsivpl0jlW51rnehtMJ6WaPR9e+oDzaE9oarsuQzlj35xAt/ZtBtBwUK1o3iJbWO94DjDCp6Fge/Iw5B/179C5gp3uBjKjcO7fJlhkg5ajL4kk2pC1AsG5ijBZvAHXzzlgwHqlA06qvGcsVIis5qIxJZ8kDhv/izZEIX3EuCE7JQK0RycWgLWP0jr+CLvnPoC1Yr1aic/ZoGoRe718RStM266N6l6Sa4f1ERpy4eCdFyXAXCy1RU3bPRbz2duS5x6ve5FNqeWuIreaFnWE77LRqjTAKLj0Z58AXx47lvaGplLgkR8EuEJmf3omRiPTVddgKL6/L1bSKoOAzbbjzxW/LheDoQaw/6jjE2BcEX4Q0gOw8qwRRu9tFkimnpNCE24KsFZpCgZGGlQBFC7HTriAnC2NkQC00E35M0O19TcLMZDzvXpmTwQHIy4LXAs6LsPdjtEyFR7Abhm4thj1n8T6aO0VwCdGgfPMAm8REaFDRGQpW1Gi7HYJlOcZ85VWNMpbU1t/iYUF+GfN0uL5CusHh4S9LaEyNmK9+dlm9Nh8M0buUenylMxHjuGgo9x4WEkAR7c/TuEBUL+g347PDALQUghQz/j8VRKK33CGkBh5edTFUmr21pmlrK8oAlPIrWuFwwCaxN41uNOYSA5wgem/G/kdq0P80mx64tm+w/09uwo1JGE02hlcbnSF4TIGGD5zem96r4+OTTwe/H51+Oj755ezo7O0hr5Jg/reFFRBXuQ4XIjff3SM4k30VesIdGlZaDpJsWAmb+CvURZiRov/ud7hz1sK6lBZCpBHCJS+qk2jGCS6GV20ah7hgVvzPgmvR+HB5IWNcuefUsJOTU4yObIySvw6+hBT5BUwkJMD9cPzyjBfa4g50o/HwajLqgC1G4Lmd24MqMkPS4CLqmBb5IyWtxraI4HbnpyZNxuoMqeIKGXNBwLNx7sFXcd7Um03liW8d6SanCn8jjoUi7+xb54ceVNbMUaorSMLDm0JNaglCYqdjoZn+xnrVCqNpa9KbBldhx+fn4Cal8i67OsbPUsleCK5NIsyhGg3FVnQyMuLXIamoFSdv16e/M6qXeZeQKGCPiBwpucMge3STjOaabxy/yuuqxSNDWYkjcQQFQnnM3mWD/ROsEF9DGBMEoaFcKc3uvArGX1Kn4E7mA5C88OQGfIsxo4eTNjie8KfRH6GBUE9aBlCpc/lwgppcLw+ZQYCHkc6OsSK8wk1OLv21l+RP1epfNq/DCYBIfwAHBTYAJ2F/yIgBG4+vkCnKE4j4GfA3ucdsZ3tgC+ZVbsmIvdvw6qrV7nUVdg3lkDr7xG68pOuKdGPcSg15YlDQsKME1VKg2EOz0W14iVjg7AhGXwc8u8c9ehjjUsoAbAemKF0Ck6PkrxH3IFjTge/0KHGjfy0ZR/VXxRE8Jd9QYjq2OGAC6ty6Qa8l/P+YcPcDoz8/EPAlILi0hpdX0whctluIlMNrok1m4hN1IxqoCAF30MwPqt5xeBWOCdGc0xpG9K99AyYC7ZJaYXYQCwDQtALh9At/jvz778HNcKh+XrJ+805RcHFDMnLIGglTG2xHANAuFLMK2bwQTaNR2J6EmqIMPsYixmrxQ3lXGc8YdmmgZdJ1ALpvtnxbERtM+DUdd2OSzr+if0Xi/r86fuFbv6fWDdcXf0SDGMmUa4zlLCqBNGLTKlhsqEJUdR0OWGstkclFbzKpLERktUBpGUwcHeDvVxc+uxqYRws3jvAW9w08j+FwQmFr1AkqCleVKDkZ9fQi+kOMAJwenp62hAoDu9AQgW8XM4kQAYeNAyECkIwZncdPwIrgvwv0d6M8FzgCJngmQieIHxNwEqwXmyK0uViE3rEjTIeIYKMCafIY+wdAHy1hKQDLphocGH+B9cn2Hw8Nx9BqIAcdyderJnjj0j1Kaw94jsNB5yVhFZFhbCQ9bsDZZgGexEihckzsCCiBfUcnkZdPQ/AcG2Hk1Sa6DU/+lLzbSGfkJmqrbAu6AhFEnl+Ytq+67BSCUoh4BsGyEFAE2ng4rtgfxHQVC63bh0OjQMZgKoP32ZLuDoB8RxCgwC/CbwzN4g+I67DoozK7SJ0i7FOIx9NGdsT4/o9cWx9py5twDXDAhDL/lB2i04hQ9LlqRkH9MDqMPpXHgOH38uDlz4etjx8AVvTwpPXqJzkwGFIDGjW3bidOTe1QbVxOAmiAB0hSzWjzqNdjYHiWpoSzIfw1eXQpI/lS16UKoGWJNOls3CmO3arRiGlXTz6Pn4c6VzSjszAZJBUZYLzNF+1cTExd7ywHWuaz0U42PJXQgkx+b1cyKaXnWUPi8/zojGDCGegV/cwSB5ifLUZd9GKjylUwFOtRTdhH7QzzUXLWA1OkIO7Am3DS48V5BN3PRXC1rAeF3IeXb/84gow9B69aGOvaOj36g0um23VNMjV6FuuW6A/rnuRdVulVDh3vU1A2NfwSfFeeN8S+l5l0Z8gd/Jp0OIqV46/Q4KKFBnhAe2VHokZ+a9R5YdThIRweWwrRFDwUoWt+IWQc0ijEmIxgfG26ORhhJmmK9tSROyj/x8eTI479yNoRwiPGZwJ1+GnY+d58E07gO2eUoRF2F9gAhQMjy2qEmtdJtmzDMtRM9k4wNIwmuOQLy3gB1xwRRudw+YJvE1LCRevc9ULcp5CrjbIfaWFQGloBN5TP1EEidcpljBQCiErhXvPzhw3S1xXeHRquNWUCKRYalGW8sFK6WtPlg6W/PdwsJfz1M/orQxh09sWLLdZWTr9e0RQoVauGckNogj2l17XGH64K2xX/6QgItnus6BQfporS0jNGReNM0zwdDndRp1vsHN1j35twSkOHxLCAtxYWgMP6R7bERk08VdlZAT/gIkhrTXLg/bELQVnd0Y9j/DIOgVdjgsnox2nAfk+DHyH3J9JFvmfLGOdUKdfdoCaC/XOgDJ5v+BcpwIU7PEsdnpwcs/2HsKf+xfPUHY+KPUce82KWYgtUXJuxx/h3RpNn9K1JwOJCy4eXmk0Oz3anLrIfeOyacbNmHfw05WHoM/6aRPe50/KHtwdnr49P3vncVPjpWOQzk/gYOqDmGodFQOH7drTBV0Ga2xols+Bzn6bEB9G1Is1VUOWSwrllLOUVG3bOWsPAexW/sMkJML/LZGZgaPEuXOqT91thdCsnEzl3ELuFUyfHo0+jm2baV2yCuMFdPV235GuqWwqdwhfu1z+Ng6/DZ7rzJrCSPMDu+PidRT0Iq5DO30xSL1FdGuugflX1zQDNMALUrZ7FHMdfw/h1UpNhKgoHnRR5shY8xS2US1vCM+6fGM9lhg/D5dlm/QwusWx9Y9yOSvck09Q7dB9wkWrBWLOtLUOpt4QtCvpYxHSBb95/ZEf1m8P3hycHbwH56eNPb49esi/s8/D96SFvBi3XeMRTXjrwMZuOGL8ewjfOoSpuJx4NyG9ITwIathj62vI6HRMEKqbaUXwblDj+BTPO85dBeMOaGrSqwjZl7EFXj2/2RAGp0pBfNOu0xkhVba2qT4g7mhAhy9HrhuPxYCiXEftFOh75UyM8+LtHedokfdMECuAoLAsBH/d02m5BBG4JzasqpvkIwbuAfx0ZfW94wjMsKd4inTwC2oWMfV9CEWXAWHfPpI/r63CcpZbixaGnh5Q9j04opUcqY7Af7AHltoGrm7vpFOnltKadtcd7Z3o9lssSsSrjsNZ/TkO+bdDNp5WJW2MpTZ0nL15npUEtoFV4jlb7LEBjQA3iFQU6tJaLJLe3bw2w/RvWPGvJu7irY9AuT3Ulx63BHb4eWGnZqFRVSwmWNR1oiq2xCqZPFGIrDPiP+F0MIPzL+2t/TYJLKNlEZclfRFTxkWY6rXHSur3ACyLNAV35uqSxELfJMjFgKG0kUjbXCsPttASqY68BBwbBYN2OmAyEGaDhYcYetibhuN+SqlBETPoShVGLKzDy4uJAZKsGJ0vAk2SNYKT/dEBVZlR721w/v8gCYULSM2pW4h11xiMRmQSNIFJA111wj0m6KdxqNPKJQWMUgMAPIzGBWgcUOn5rMuQh1almig98yvfT/g8H0Refrfb1f4eMuY145UCbMSFdQWyKMiy87F2DLTV21GD4xsHG62DjKha+gUcR58gwTAt3K7Lz0ajXxWQQRe5Nnd8o5xmf+KZ1+uHt0Vnr/XHr8N2Hs9+lGKASWvBkFi3Ogusy4MyWMXjbSCnqys+rYpPEik6IFmspIp4lznhYnnhoFzO4BbOgTIqusU7+He8q2r20iHvOFnw6PRatVuTe4knq+JONHZG/SgkbB72roPVhPJwwvqmFKzcty28Kn0STepqZ6PmZbRTB69+6Sq9jvJBFi+0HY6R6oYooITGm6qcaef5mlBRiNUVUQisq571qpelO6Yew4LEx4QMlh+cf7RJY/ef1iI8XxvrWXc64+3tMNG/fxiv5e14DP/bbN+CZ9DQ1Opec+61oMKpCXSMCoHLgMZE7Hd10B99MicEOnMq0PwSDkG36XHbvbDq+HGI62zHXbJUpcAocPQpsT2/AP8g2xm+KdHIg1rcmN+Ph7fUNul5FhdzldNz7fotRf1gWHcPBTP/Ds+I0Ghcvu4PiKARbTG4DwCb639ES84EHETVjjg7iNAEmY4cTaIwM2toyc9xa2ka17ai2pbUa0BhvRri7CGjby8sWGnUqjNdh0gkgiq7ziKvTk5fiNIOD/DmklNEylu5QI3leMaW73p7rUs59I6TuT+j7NCj5C9b5jslZSaHGdtaHVeeoAkOconXhZZtYD+84kqvypk6unuHoCMWfEAbk+gZ+RiYflRsHRD4+qut8VHmngBaMppe9LmR1BV8J/OLmmrGBnZUfKOTmTBF/UVTtlhoESI8bEUxrynAJaEGwZMbfR6Sad6SXEjm9aCHPpNgkc335uqTHlQ0ymIgr6YXKYTIEC+BN2Gd/+oggjKmwsr6eEea59p1XR8hLFYEObg+NSSCfWRRST/2qBGR7aAk2pjPs9b63Rgge46JWGAjU0FKaELewsQF0fgAhSbmZcOzOHLYO3r71Px9CvNHRy0NkrbiCn3MfFCOzGXeWejARts6KQcsQbz3S+F11r6U3Qn7OGMHcOnCNeN/Re6EClMU8P+y6nEcCWvYhtQUFjdrHHbqUnA2dlUKP4+ogZ9OxfQt1my3aNTv6z98Xs/+hgOIjIjMIOqD/3gj/M+1+9Q1Wjg+WeREEcVSJQSfgBOO//R/Ayw3ca/jNon5Xaw0FLqjyS/gdDprIbkrVZLdn19AJiWCAK+biSvgINIQ/h/0G8BuNu2zl/sEkx5a4Sd5uinMUcdZqhBPWsL+3a44E7wIy0Q1XBAnHfWr3/uiO5i9GLWG0vL/B34SR03HQNlltO/kJ7otOV667xPeTlYJO52hwJdezwTi6xZPEJkzmXyhnMOJpc8sxLhI7BwbavwdlS8yVjOBhFJknt4VsTiz9bTHxpE1K0P/Ik4yjzWgOkZCkr0Nop8jKZJaq4p5RV34EUKhRLSn2xkzuvR+/9ARX8r7NEmjrNpvw4eaHl2hpCTq6zIPJdNHqPJ/qOmX0hpguXg55qM8GP4V+o6xGUjiIe6QHl6phc7Umn0krnHVxxu4icbTUTiUdmmguDR6kxbJfKKUAbef9cJJ6DdHuab23ydK2vj9FLIFrmIPI3St+8GMoWb1e13nQhx/6Te2QkZmbnqQyKCScg/6MwDQ+0E/cKOxdnYWROVZqFMkV7mlfT05rbFdh/2yO4KFtwqLSqfTO/IEIeuG3aSQxPOZxns6lNK9quVn40qG4anRNaYHD49HxexAIu6MWV/UWi3hUrb09fnPqC9f7c3k+dUQy2fTvG/2NjhTRXMn/+LhooZS8UqwJsh4fHr/l9/RsgJEStzCksAZhVFdCg7wvNbhPM1GPfXoeBcUL6uxP4h+Mpbl/1e4Nozl8KdTC88tV3aUKZl/hp3KmePSguVYj11LxScM8gg3Dg4vncH3Cxt37mEbbeXDOuWWeKYlHr8ll/LMvh7OIuzF18P5Vyv+hJbaaX0A+N/X26BducMaI0ypE4gLO8OrdavE1G9eURLoGs9X6cHAKgWWv0CQ9Z1aM8QVS0ecQwrZZWwlediEBIZTwzAKmSUbjO/fLwndealDMNREPy+RzA0JI1XRv7IetRJv/ErydRjt4FtGER0u1Wk3vre6bKY0I/kz/oh82CaSraW4N1RvLo8HUj817Dd4vMSyGw9lcshg7GhPekE/FltgmXKAomdRCmaJFUsUWOGgnryHzSjJ7aa4USuK5QqVYB4iGk1/LlZvo399b4mlTwtBXaVbswlZ0071avTnngnBQKXcVMKD9bns81He0zSHx6vncoNS4+dy7/N4aH44Ox8dfIAPZYMJFVozTrjZsw62x6V9o/5DtABXJT4dvjt6zv59KwtWN34BSR1fvhp0p6gzYPmqNQ8rjzalv2xcqlxO6cTi4JneS44F++Sfy8inq114O0bjzLzFqwkNX4JSJ93+2cfWwxzr6YydTpUDhgW38Fx8qmKa3coKl6kh7/11xgziyT8Nx5wNo/vnwl4UbIQSfdMfwRKv16uiEKLLJgDgpMmlcXvbYGvA/AEcXdXz/YKS0L3FaLjQi46lTvUpR6JA7jK/LB4sMPiXjW/3gTDRqzXyTfD5cmontL0k1zTR/drnHs7r63qVWgbxUG6WSPRGY52nTlE9vc8+f+xqcoPoqBfN1rgXQTgOQR+c8yconPZnAjFBjrPQ61wK4WUUyP2UucsksxcIyzqYMP3RzWevvaCyclZ/h04CyU9mYBsdBbIvHyx3fiU/FxilqBwNNxe9Q7zxIFWJuKLJtt5LbwY8DEi5jjTwjcDPziZUKP2rU+HShicBAuSL7EBOU2eehkN4QE4C7zn+i9C9cnP53N3jXFb9fDvt4AK0XbcwZ8VKWXMoTIcZ6SvCZekkl91AAtmQ4nSpNVEZToHasGNRtc/JWE3ZcBVwHt3uhu0ZEhnrDGLZiM1cs8i8YRJJ7dRMMgHXDH9pdqxjka4a3+QnG+GD8Jzto6IlmM+mRA9iYR2yFB/AFgWjH8iHHYyQ6HUQ3X7uDjUqpsV08bk/YlzJ4CmlP+OAQAtMBuZK46AI+9cJPwLXVLDb3UbexB++C3m2Ah/sp54OWeEhd+gkNBT5YN9t8ZLUdML8q3SPLspEY0aW8yJI2PUtMlIuIvPGf1KqfI9p892BPCfbgu5MzMAO3zk4OXr8+esk7q+c6dsPhubd4bMThXPoTcwvOOwzh3tdgzBtH96MtzYhtq8gty4CP8c7xRA6x3s2jEbxowSZF855xdGQubZa6DCBH5npB0Xo6gAjeuaXliU1jhWAmGAS7rBTtySh/0ewCHdTSFQfR6NuDa3aXX56c8OHABPLliuTPE10PnS6D8GJl3yVSn6sVYnLdMZbNRgB10gmrOqdSd+5Scz5RTuwZ1+wtNQCLS5k288Uqarf4TXg35MDt5jmb+0voZsxHdJK5jGIksWkj0mzOikbrhLYA0W0P3AWvdPNBTIoQhkuDeTfH6UoqBpyC1ji4VWB+yywy81xaxgKwL1CHRTGbsebvjN7U7JWPf2EXX+Ln6cdfwPTDC6CyXj9M9tOsRRzrJu+h/Pat2uRPNbi/PRdsM1JK49G0AnqpuV28YJyQJ7yxEJunUt0EtB/uqCZd1yyw56TBXUYj6lwOMckRprepi44JEtpjuqJLZJRJG7y4tYCmiHEx7NspB4lb47/xYS5Q8CQ35t2s3leBiCFvQ7OiVREb8RKdt4A1eTMOLi/RXxY4XcbDDgfA+o7h3lkY9OlBhB8C9CGDucqkP/7876/tN79+7/z85fqy8vv1x/6vleC396POp9L098r2JM3neoswEKvPvV6X0DYmw8vpVZ4yZvA/I0DLx2+YylDLuaGyYDVTGIGQ8jPp58+f8yROjOoEY5XrCVM98UCFtO/79/APMUOgTRlyDoJmiroSAM/C5UueqwvGW/QVukSpy+k7xBWzrogm9tP8urRVInxRRaFgvfILJ37hlA3pq79MX2TEFKqB5x71/vy41LrINZMO1MQb8XMjLrol/Uo6Jf/Z6pbxo5nXgfhBuvqVBeYjU7niCrGwzlwoxue5xsFEo+d+hxWvz9jiEDrWlK5hLrTheLPUyrljHqSEWEjV0iIazQuTo11N7jpa37AJxJjhspW4TjwXnfjNdx0PnGQr3lduYHw0cBfKB2gjRspoT4hFEKJgOnEYKB4yFyPP3+PrJyFGj0uit7i83Lx8eiAIjnEk3UmXo5+RwwmmJcfivKMIicH48w83I4jVOoCwdIgkRu9MgAjwOCocZlLsdMdNNgPgYPvmEKLe2AV2djAhUuxrFI6qVdMxR/jjN6nrlN1VP6g0mTN2ZhmcytzNp5nPEqNYFrAtVo3YY8IeSKyeXpzAjLb0FYozkXHOBR8+GI7oex+kKnb2MUbSnlMuovsQvncpgJngD6V6jNYpDwLiplwOUbyh9AfjsMd4i6+YTpodjFN26XuI/q6QDkGUb8li9A54WgEgk4ghvM3JLEIAVgbIVzz3giP1AjiqU54GSNOwK/qYwx4h55HDR2Ffqbt4ie1AFItlWfGu+M+oiNDL6DFQG7Dv9IIyHSZ3mt/nQTMZOYxFvkgRmglya/SDL+FNF5NxEA54Op9KXwbtL9y5hON0j9j9F6Nd7dfvw+k4dfThOb8E9fDkmwK8ixqSyHn+2sErqNTXTT9B5+2rgw+c48+IIhu7KJWzffqRZy7BDCbn6SlXg3GIUTJ4cBxX76AN88guveqO2cXh+LuXr/AUQRLYRpAnhD6i2DsBO8Al1teMLoIG511w1R3+MSzx8uS77XKPnYeHosAWkIOTnosYXgMgP5o/pO5mC5fz2j1QzF5zugmXO90ouOypIPXIjFOJk0TAE0LqcXuNCsUNCE4EiSqdkPMqbaLQy3HDg8XpJoxYgX7h1dHJ4cuz45PfW6eHHw5ODthXnAKRpQmBDB2F/EJa0Vm2CkuNWi2eeoBI4dLVCJo29tQboPBRlzv8ZTDudPuguM0dREP2P45ZQ9nSTXq2nBIrIS1pvOAi7cuKt112oER9kMtXwyziUAU5XWqYUGB7lS10PG7KwUCW3C3zOc7GJw9dTBASHxU9E9Oa/S/qv8tt8BG1WRqO5XSK/1N6rynE/CSVQPLWiOl+HHISQWLblo550k+C7YIw2BrVJDMvVkJxW0WByOsXuoO2hinrA4iabBFhZ1d/YpnHsMuVEsVjPPdOGb2+xPx6r0nceBcMmOyBmQwJAoo/gIEFTJD6KPLxdeHQfkFcIaYqgW+AcX/0/g1/phKzpz5+M7ri2OljDcIUMehMI44Pdih3tbNTyOlYUe9Ee3RSvyOx7dSS5vhlgO+zr/0s7TZZfW5QN6FSa74PvnbbwSQFkQ+psynjDHsp8NoPx4ZOo0LAYiXQGKPXUUS2OfQ5QgQO9q83bAe9FipSVOgXXRzRUbkrBgAjmSldGx+953pwM3e95E0jgwb5mpDV8aC7Rcb+FikZIy9EduLn3o6Iuj3tMwb+O7hQAykajbtfA5SNtAha3Ee3XdZud8SrARaiVpLD8yZ4S2qzbzfVtwAB9RNjoDulkj06GGFVjefe8RPQQrD5OXD5O7zebdGdZxsb/g9KJQw9b3r6KPgQacq7g8BXgNltpAIByVek+oA1qOk70pi2jnH8BZnDjtdUFsbIDiZ5QHyhjVqptPHTwasNvqzTMvEFzGViJhTO1seKKZgZKIjleOMyp5LL55PRFiaXESaStCo/GcAD7wFp8soi02m0lLNysqbYCi99ssgEB1PIpE7CyiJ75s8fWsenvnL3gL9V8WTT9vGlOKFHVSFZGMtn+THvbDs4G1UvMSmler2uP8/1GxVErwJNuMauYlaX1u1w/IV3fHilNGzTwWSoEVVEoKqBoql3ffqdEc/+b4zohWyBjn8Oe6Nw/Pw5k82OBqzOAcdOE0JLBYGmANSn/51oEhO3R+NhmxMDD0ElkIgWgxFkVUCECXAQgjff+OWXVx6vCNVyVQOTef0tCDOvhrcDOFdPRWQ/5mtmUn5bmeqMMvZFdO2gS3RCG6U4orVIJjGYIiSTHJstATQgz2nlU5qG/G0kzxFJ5Al4Oa/IAQXhokSq0uAvVAm4mAG3GUiIfiFGFohnQ4fvkZhbl8OJQGaOlCjtr0WjrqYw0NUdFUSS2tpc7jXIvRTqgG/QyHTQ/U+XoCx4HgiDvRCroSJgTE6ZpMmOGzQhwVrLnbaHk26AWuO33QEnz4gIpWXm4Kc5qxHOc/aHTnT44jjTEQaqXtZRtY76oyFjKgvXw+lXv3AFcwGqhIN2exp2daQtXgPBjSLOR1dEcLGlHg6+Eud4cvju+OywdfDq1YmOBng5Ht6qmeYPCG4Tuk5odgdvDt+f6c8Jk1Ekc8Ow/uWQWL0EpxuIo4541xBnulIVSWvZmg8GnWG/CX/8TCkPCG3if7L+Tr2JM+aJ4jJHIrB8TVMoztBE8wKdaCKfhXKemlS0ptb0cf75+OzdwRG6aGc+Vat+4ej962NcCtYA06be+m8bYD66r2lT6+OLyvVGiQL+cYj/HmGYHDVt4I4nYOlJx2g5Vc+zRrk8pDu5WNFkvYjySjn/nNUci6+UrLVsWBsM+pzIEkcXcr7UUGlcAkH4/g0cyXnsihz+ZwkOHvr6afWHl9xEZZJKPfza4QOmu7lUEEwLkCHvOCgGjhykgsC/l93rXe3CXT8YfAetewvQ9alop/t1V36hShGUCgHs4jgFcfkeJ3pP72H2rmYCIND3jOObzk9y/aKpNXWUpwK8q2UOYPeuC9QfobPAIeBH+Dac3oTfe+gjQGdqDjHp+JMVjgylqXRwv3yPyMbE3l0mScLl7/vfSnX28fq12C4V2R9Up/CKEY+UdelTeCmaxD5g3hItx+sS+9HpElNBRK7KdtlAnBtMDC0MWqjm0Bwu81uzO2xPOmH7UXXuqOGcs9O14DHgcFsnzk0+J1owFhcXt4vr/C/CjcGI6fLVi8vdQyZwT7kfC0Dlw6kHtjov1k/dlgsKr9bk28To0R1viazXJqv9TTDLP02vrsLxoYaTt6Trj6zh0wdwSjbZbZ2EiDVCbkpbWvrO1pA0Kxk9ct5rtbiQDnmBzz3gRD3/QjNiL1V+Y7fb4S49d2J4gaqQQzD71gsG11NI6Pjv4GtwKq52O83h4BVpLYgK0QO7SzwbjdvN88+7FznjQf72cHRvuRL5ChsMZtjoj8obZQMLyrtVvMLVaKrsYfw2T+pDjWxzz7Tb8BLx4LEmpLVUAHHAEN9qTjgAUnnyYW69CScHvd4nRn7AQPaqO47MUARYGdqqSnxK2u3HQT/SH9YAxPjDHQU2zcTLt12eL66CoGMgtO1HKO4xpu9Lt9cLkJZtbFN+D5Ui3JPIgJhyzpd4wBXEDKvWK8toMe3T1UVkfqR0TY+KP3MJ8XzVZtrD0ff7eOxzdvleJjIPj47Cs5U/3LcAl/W4z8cbsypuYzLCLk9ewFOGoacvCdbDdlRU7w/LW6bPMMrwOmsPU6kiaNimkPz3R0Ls3IAjBvyJN77hh9x9uIoiWEZBmwmqjuvtsVCpczwutslFFsX06c+Hb9/KmH7l4HMDeY06qHrFyBMxnvLBdwe/tT5+aL09/PXw7WlacCOayikj/Re5Hw/vw6bQGQMU8J22NgS9Adv6cERW/sNPH85aH95+fHP0vnXK/vCEahqUPJxhYdRuBZMJug5glXeiAK04rgxByCvA4oONH34IvqNdgVYo10jTtZY2+7AU6KL0jhLbdJtLyuSIOTf/WTp8/5+oeDX98Mv25NPPtU2qgTCqWA2fgpsucD7vvgBVhIN13P26BReCbq96wkuj2nVbJwvc9VNmG1a8HloMpEZEob6o1A2msoRfd6lT1MNw3fWwLxM5+2tHH/QnZW4iKZAqVUy9wg08J+FfAsUV9nLuMvgzmIDmOwcwibnTQXcUjvkzVa6UQycWVgBYVG2t4y704EYHPsA5JgDfgC63CCC2DHipPRdJ+GZNqd32MwazCSm3Pm8UvbwHCNgyOV8FoU62ESebMHg8QPElL7N3NOwERAgepgX6D/XqKsUzbTFhi0GZWvihgBou6EF3BuEtb7AhfOuS49612GWX0AngeMJJS2NQl46qcvqd2WbJCuJc1JWvhX/v/4Cagp8++aAnuBx+42NENihx2ySBCNEA+qsPJ0e/HpwdwhJ4efAOHDY+fHh7CEbUtcuAUdCOXGsoQ/Ont4W/tb92JbJTsq9lQSzY94r2varxrKYJFR4n/kxTKa9JhW9pc3NT0gKEJihXEGMJHXu6k48nb32XAOgAODw5JM8Wtstar4/fvjo8iReUJ1iCYZr3oyyB99bUywc0hx7RM4KE0LD4NR9JSUEoFPD/X9yb97WNLG2gX8XxMGOIwfsKmB0SErZhy4IYHdkWoGBbjmSzBHj/uJ/8di3d6pZlksw593fP+w6xre5Wq9VdXV311FPre5/Wj7dpoDTxgptq9JX84U8sZTEkv1RjCPlUApZp2MPYb6i7xBngRIdH/u2UuTlvxSJ9fuO0qKlL0QEm/G07yFTm8xKFyZeS1OxfjGZMtCGJAQncu9+tZHhyDPKDeH3du8Naz/TD2NQbvnqLKYfRCUyUyjSX0WY9WpyLBhT1l/bkYfH8UzEoFb+c5b1R+cO39Xp//+Rkb7P/+Pjl++fDD5Uf36rHlWC7V7qpe5+CXsX5dPXxtlb40v+2s+M/8N2Rl7sJGWNRiX9BvVhuL0u8WOaWlKMBFBwPM1k88b6SyypXwJyViz4v6fsORj0DcplCxA0CcxnVcRp8cd5ZObB7Z60F9YMQnR1ny+1/gSF9yypqLebW3j3YOl7/sHv6HgQuqIW5LDIyETzDbl9ztQZvoVztDnPeYojmAkp33EqUkMfQ9Y9+O3AWNgO5o1ECevAgw0tmQLB4I5QX7sYXMiPHX9D5I75QxJANyOI8G5kWHLFVMvpkHDioMRKaUFX79H5/88TKjR4Q2Uo3xxDNGvrl7R092539uZU5KvU2j35UD76Uzj9/3HrotW+L7fPzRvX09MPR4VnB//DjZqvzbb3692OVW0PnTEM3k2TT6NYXH7aJHBbcYNn9duAf3nKlktwozfkan6G7784fO/3m4+fyh17nXfOx+643/vp4zaNIsW31iWn/2kaeFK7/mobwW438z9hOkugbY8G4U828Uhmh/Pb1BE+feBm40498m8ETQv+7Hfj3A7vTZ09GXeanmxyVNNxCSqxXJUza/fAY3p1zi6jFgbafzJvIoq4YaQkQpZZH4OvscHD9fO1dzenRiuKj6pwMaMMuqYAL1aCeGWYuwlLU69JqrWcKQMCFTBOgoOTkMNNMKTYnSfMIwSH0CrMOpyKcSHbpaAk7pfZg6t0wAQBZ9jbvgvJNXUXeLnAYM1iFWcnFfSDdNyDSBwrIwlXI2NTgiKs2jkApNhqGhgY/5LTPFyDaLulxbty22GI7/65y4ov4tdr0LA3yLyThsM29/1c8Tj+t8e/QiVCLe6uCAH/JbqXZqIhJmyxOgdvlbZ6UwF8h6Tc9Rv+Ogi7o7uhOpp8GTpcwCBCQHolCPP3h3U6x++7mqvNu50fncb25u7n7+OV0h+uWeftICK0Gp3HnxgETTtgmhDtXIn0nGl9piRL/Yhcgw/ksex84gSE+Sp9nAGRqtL2uXWwp3CxX5aemBkLNg2EgEjA4rVhGcu2Rcx22JCpiKBZs17sTf8OhM0A/ORWgf6wL6WgnN+Us/zy3ULTm0ICgUe6Ji22/+zif/rNIxf4sw0EcnHHit5L6LeoVomZK8j1QwmXxp16DT0X4syn+lBrwqQ4X1uFTE/6wdQrD2Oo1oDjTTy5y2QrpoXTVNEWI5cJxOHRhj1cRFJDwXcO/yt41ojGb8Khvnp8vWqHulVGJM+/uMlqUv2UN0lO88ke7B9PbKEw0wr1qsjHDyCWfMBcz4nkW83kM+jGxfVEWYWwB8QrQSAU/dkHRLkTaF4aNgYFzPIAcvrNpJ+jcQCBPTnxlYIXc6mcz+sVM/CJujRj2oRonZCI9Tq8VYbK1/OwXmW4vw2mSO8NpZTpDVaY7tUxXS39XwhgrCLmeQovsBoGNMNR86AxdbTVjzFSdFrNctBeZvt/NaOb3z4XPsFQpj+OUMgUqI3d3jHkqVZPB0L+joHVuYk5L3SN4+DGGs9T8alJQ/rvbjvyE2/6b6AEejioH5orNVZqHL19aYPi0x6OrBh4twIzcQdHzFC35F8P8RyFRNaHHLbEpxii79EInlZR+3ANuxhAPfPSORzdeuLDSdUcUzXYKoX0t4EZfXNzaPmVL0OmXo217+/Pp9sHW9paoygoVFRON7iMYYks2gvcQBw53ALA7UMJ4e8IIKNwt4vFM8EbiNF9sDvdgqwBXSTGi+hMKkHMr3+tMV70AtD5vEQ0bCR5/4AIvm1wZKPkadUqAqPKGWERpZgNkzuWo5TSTnKXN3Pb0wQb2S12O5SndOvXHbNnIHhqVVVhNzEgO6ZOjanHblnmJHwV1ygpqzJEg+GZDOKc7GFPnQAofnO3tyZ59OBm398VV7prTBQUDoBez4i1uD0YBRsnaH7Y/b29ac9ApxonrUtYyY6m1NnUof7lAiqJBN/HWQcdW2AOfDlo2abuWLk5lUfRCWyX6jIqg4q/lzM18OjnUG4ycRlGdRXoFSTflfhYZOal1M+jDEhS7eokVAwx/xbymoq1WlGqXBEEgJryCZWasP5bRXsDV+C4laQxem/RPWhxoSmfB/lA9xvcH3ml0u+/3B77OgA96DX0+FevaUblAhPv138XnRegfYtxPb6X2U9351JfU9aKXctRMZ0eUNBoqS24Sq14yehY6QTAEELCy25SEs5hwxni9P7/zjOOI2S7eI0W/EyXriNxR4ITkbsrMvl0f3ZM8e7X85OC9g+Toevbxrmv+QrVkrs0yRoo00Hw/5GAk6B5FLa9vHW5t2Ef4u+5jw5ILKwFI3MCGb6CYhHqZr9w8Qksgdd/77fWtleXT3dO97ZXdrY1dCxjz0KqxwEXRvBbhQiHwWlw9G3iQTNVDe/Q7oUWDWALkZdBHw5fhQilTiEgFfay014z6pHyg3V/I5ruWcpUK9Ve87hLtFuUieTJqcSIHIQ7H4tg4GNntng/nbgb3OxiGbQIDXiE277oQ6O3wiqf1Bg2K04gxbWVvUKHDnIFacIjMQ//gdnocRGIZXBAJZXjPyEB8vQxylZzjjyEgzjhoOqF5aaaYiFKRE64zGPVsKK8mFIepNGVGu7dp5hN4a8QA6eHYPL5qd/sLhEsLwBV/AXBHKym+qlLwLERCIJuETmV4ImCsSgn411prSc6+td/mUExGyMao+xLPzP+qksaIY03kaudnBLkF+hhOZOse1bq1VSNzoZ62cG11wib1xODIcpEA4kUmUlHj8V9wqfBrIQ4h+eRTyFQs6dIoF2sSCCXPnlU6e5pgHG2Iqrp9J46YnMZdNx+vrwZ+zfx5dqIg/qIY7oy+Uz7zim7+EX3SnE2RbhdOBf9MpzqZmsFgglRYqmhJnMIwUivJk/2JnwPzfpZMhtA45FwHeOYSwJ06AOnnVBK/1K4muujlLos1vZJJuAz6FFgnxDLo3DjBa5kU+JGbiEiZYmd81e83+YTmNP2XePbXXIIaen3Sx47y4kbdk+lzk/FoUzDp1j9Tn3S6iVQbTQwPqkR4CEKHZJlY5v3pPgSPgv/s4p/ly6y5hWPQT62h6iI0+u0eR8eeuMGdh8sbfG6GcuDDXN3p+YHXdWJNllhQMvJkFhYPAJ9AloLGPr7qMe0RcObIgQSFUyxe66IQWTvKGCZEOaWCjhNEh8H+wgoceJ1BF36Wrg0vChbzuuG4jwMlm6qw4QSjSRPpVcZB7+TvPXhoNwA9jCuisK7UYjnR9JVz7fvXPVctnzeJicFkvOsEkcArLSWkO5jkSCpjkE8RtReLFNynwnzxZeurWwy4BMnKpPyUr2bB/FVb/2StyZWCjyE6VioUCi+Zqc39ZK7jIR9mxITFB7Wk8Ff0Qwh/Euf8zcODnd13kmYXpk1CmrPJR8VlLjdjlgrmzfX+Im8XxBFrQGh4hUsvLy+ap1DdhNz1ShvJsKUis8RmO2msSLOx4ujw+FSoImLKNQppoy7Ya7XyGHn1XnQT4OG59KJp+0hDiO3J9t6OuLr0Ajr5r7VET4lxKRCKhxzkOt854QV2f/SEKIgYz7kWhogASOWvQTscTvu7iaeQ7HYXiaxWWMpglIhGuLM76PqfERFlSiMM+iiWKIoNYPm9ns3vd5oSI55cIlVfIu1FVgbIqvVqtt/YbcxTO4aINBu6tVRF1mcwMNT2QrvtjxTVUFK0Q3QvKpuovfANq4wfnZjJHw5vt4O6NYtzLBST7P7+XtzVeRyKTScndPg8t1CTa06t2AkVSByuOrdu18b0v5ZShCSdfILXjHBBdiyQDEDqfHBP1tZBlyoYTWok4dxfwv5WGCX3aMWMABn4USFJO3d3EwXIGxIzO/wMaVqmBO4AdUkG+t2MnE5HqO1HAPuNDpOSwwofXy9iAAAt7Vxo33NIwSutRhe2XnW4xBtYMuqeesqGEqVNm6zDz99kD4PF9mdgPhV/ci0MTRZ/8Is1M7BymVbGyjndrma4uwNbsmgaym/iCW6R2q2oqDeOU38NvZVAeX1/ozlaQdnbWj9d56mUqGmNB0OnkwABeSXqiYcAgzOQgzh53+jfTgRyLvyMTcG8LtOoJgYnKROrgUzMHBwm9h4p4PoG/eZrFKgmkAd+UtQY/PDE7I1uzWuM+rPDm/GoC4gXnYzrVVxN7E98FMlUdiyO572Jt7/A79QbaB6iV6PWXjEIsGqFQRtAaTgZRpBr4SyZxTEjt8xqer7wIAO7p3yM/JhsGOMbSULXpZ47Cu1v4/5QleF7goMo1gexXF9UQ9RO1Qz4XlzUcP5375EgJ7vJqBbJ1sxVKW4jiopCvEzfQVdVOv/jZqGT99LgOIC4L2uu1aI4WjElk0uG1tuorBLa+uGaQ8n4/hLXDfyMC+vXQkAtpk62/a3D44VNxOKlRJ+ExDkc7D/CkyxQAI38yq2AFG5WDJN/p+c6gS2FFowrSkLcaCKBCW1FhSaF/tbh5tn+9sGpfXx4eMo3a7LiY81QBJd9R+RSloYYt++dHkiTvEXw3DIGZCB1QYjgfrXU0392ktcenBD/1dFyqsZu2jXEfs5dk2G7fefa67R9vx85i9OPaXZWR5hvuMI1EWwonmlNgmIZQYuuezvwR8XyBGoFrFJdV4JHWIhi9EVJtPSw9tAPhCYCBjV/Yej7PeCFWGwU8uJ3LouMmxUMqnJG4sSXHXVAX6bCfW/gUhN+nzeTqvTPJuH1xNYIulCHMCPiOKheBohtH5lhWXnFaIlKc2qwxOwqHHVR1OWe6nWhSOZm5jjRPNbHZJ1wILu0pruH9ZVdVclZnOEQj7/omZs1/Xcz31xwEeJ15i6djWDvxuUtChfF65rnG7Ez9H7hI98cPZLV2mvBIWAZzT1VUcq9vIbqImEZs7nFAhbkxO1OSTqXuG1QXymBo1CxIYbYPh4DjSvaxBeCK4so5XD90/LnScdpBwv6zt2amK2sIKZ/FNLSYr+mYECvnIqXNOcUdTX3VKZxwv/DnfQJ8I8qXrBMSQcpnzbfdghkW5et9CfykO+BPYYLy32qZRqkMebC7oBBeuJhVG/n5vUvuMIjc7giyeIbydCmJPzJTHA1mE9E9XjdCIpSRih7FZ/sxOm54RVgy+0tN7y1i5Y6l3khhdpdif08vBGntBBim6kBWHxNiOSW1r4ZjyuW5LTg85HFMKGSgUCAC3AYjYS/UCw0hyccFrnDfEc8UzTLzErAZtEpk7uhTW50SfRcN8o++RO2VhCWXhITgcIVpF/hyDfRywmn2zTrGzWVMIJHiixP9qBVWDK+L3O6Wq1E9JFYSKJRxCMhmkSF8LRREWM3Jd9V8iLRotE2hl/bLsC/D5KeWkOIPRgQxDZrQ3yd9gbFrOmiv023dtNWzpURGoCHRGOGGTs3xEiM3YlZaOR84AmYME0p1Q1a9ie4e2cxR+0ce6wMuAxTAq3JvHmzGUrC1fOvM/MR4kO7Dp5NLBNm5rm2pCLc3xRvgrtTlq9cnROQ7w8eQMPlG7y5yiqlCQjdPgWz6Ur3VZKmcFdUtiFKEwMqhfXHGwxEb5MFRR7LOFkvCntfbkO0nV3QUhRan9f1r1IMW4Y+qKin0Q16C+QSq8Eyl+cSZIu8De9hO/sL54SUv12faazKiMDHYOUJ2BKMpKbARaC8ebnQoS/pyVIgrSfKaMMqNuC+K9QVqXRRyhs0zgbjgS0KdcZtd4Rx28PeWOqiiW5JAtdXSq9tzMvLy9uHp7mnEm7NNfj7In6YYsmNgG5z4k1KqHia7CH5fC67OpNUMbl3DVYnL+Gw0mppwo9l6Jq2W5G+wzWbcnnCUf11qPivgccjkctwCUS7YyIqFg+id/MRq1J0hk7vHi2iiIsOA5iyfVYKP5iIMX2GBpfDHfh+RfZAcEodQmsa2fVmt22kucQ9WOibXLHEhhXtFTNkVcaQo7/WyuVhnwUQK93epcCgeKEMS+MGIYiS3HDxtBzW8+sOdC3jPMUmy/0nwmaFr4T6JBxokjJYzXO/K6bDS9bZamKqyw1FQIbVTXswYsrrcGJ7aYk9P/XJbYvTcOj33OOjTXL9kEo9Eww7QrzCDwvMRuPSlZcoK97sG1NHJ2x4FYBgt8BbP5veeIS0miePks1trXMz5QIAO7gVPBvA+74prWy5d27PH0YplT4+9ve+DW6X8+Iil8e9HA79MVoo7ZBH55FEbeM3aI8SXv7cU2kevuHZRqwQCtjJZObTQuvl/jU5qkbSOqQ1Brj5VHpf7GSD69QmUEyySKS0H1ViUpplqrBEg05mLYMd0Zm9IoUk9ribYFpYXHznjjYeyclp7Gw/8W0trOy4dDCT+gwhwcG9owVA6M4+5HKRVnzNZia5eDJtp5tiaKpeLKnowB+lrvzxoIurmw87TUlvEGX5XHznj3zxClD9AdT6Cn5azjs8XxAKDjo8nj3Tirc4CwRGH0J/cDzs8FJ44gSj2SMnCN1tJLylNnBbBwfMozu69T4KXT/we/pwzk+MLE4aZkZhQfY/4d0qI+gaHBS8uDJt5BUTykZGW1zid1BLU+xS6/asXDfwh0AXAAYCbqr2e2uPYc8oQyValohXk/dFXBo4qxS2do4Ud9agxPJJuj7RuqFXN+U+a7jdxGFyMEohhzlkrummV/a80QiUruwn1+OaeLCvM2q65yumCOsPtfXT/eOU0alWSqmPxprRAKJT0BrSSKB82v8qFBQfoEJQ5FJ5IsrVUiFos3TYllaJ4Ht7GHy/uRGHVKF6tNXJ7HFA4HIrI38pF0ewPUee456jgxBjCkWlUIwcT6CSR0ZGGlMhdrb8zjFEEs5qRg/MbKy+YbiJqD1JdGYkuWKLAN0XzxkNOMv9TIQlr7EElWpKlsQphpipSKpXXPwTo4cmDCHxmTEANGm7N0Qf2IPozwL+ZUshBgkssfGEMxSK0gBm5wCGwpLpo0DYB99JxuwmhDeROzA5wolrV6XaOLPnddxBGEcZh8lcUTiPIy0KywplmkYnakkbHL5fTe7usMlIGGpymMrapCKV1I0EdevV+RF/tZea7Kkg6hhoFf8xMFV6si4h5yP2mymM7QbJj9xJ+Q4N3uNYvINTIRzBRzrqOsCw35AMCFynyXUo2Zrh4m47g44fOoORA5BqK+dSNHYFQcmlCAzVOXKAQKsdjEfj0FAjK0VJlsxFj8RG4lyL9hymU3rDmCsuTlxrZQoSnh7ClOz0enX9veLD+r1qca37p3p5spvi9+76b7oxN/knGkAWJkUZ8CpTwGaNvKijPYDQn/pb7Q/9aM4gxBck0EQkmwnSikeq6R6tnwSqvfCdqtIDFCWHmHjttFUWETGltsrXyjvDYc8jnF2+j7EMqlZCIlyXzzSqi9w1eYQBU9u4lcaIFlYBxA9CTKZVfIv5M2x3bC+tIDgXjNfrm5uHZwenoEGufzlaByjiztne3tflPCgnXLjBiEHWXojNA2QwlVpBRQZWuqbKiK+ngTu4vnZ67q3KLFspyrQVWwEK7wP/DpYkIxqzp75kfjXXM2Ioq0mEORg8ds1gXAWVEerlyG0DsyTgZALnnpvRvAhdXxyFByFEqHFTEJTQB2VQxjjguTyK4wDufQ01L5tQy8RscdIICUZ3sRd6XSjBMq1EEQLco3FbGUiL8qhhzbgajdsYvNPSQ0AXdHkdpQuO4cE2dwBPdwBBhQfv7N0jvnuZvVxbx7vn5WPQoOEPUG6BP5qAePwmuIaE2a9xNhpt/81gf8QR0uFYC95JlYc2QqZRW9UlmY7vRIjmx4/uYytqTP6kADwVxFEiVGz93e5Oo+loG1lWnsK4aF2eT68UKXFMrE3J4CchdWKnW8BQMo6ylVd498N3S8m6J46omgsis/xm63ATYjhT4Dl8s5Jhcy53U54LltbwaI5aEpqu4Lukf8gZX7gmcedo5AozeJa1VEgOgtXcYAEikjJKDnpXKXxp9hUclW3woeJXGAjUxQ25TWgubasvKwaKvPVHmKCfkg8j4fd4WJrSS4GlcEQrBH9fjdYXXUgyNy3K2+h6ej527qyUKbEn4B6ti40vMLPfHK8X61tfrUtGOVbKJSVPw1DiAgy+Q/FzEt0h/SzvVGaxpkeCoMK6fggEcBKxzeggzilUKVekyV+uX0jIbaPJfZbXvhomZAGNLSl40THO/in5cTX9GiGHaPGPd/bIeTyCo1726AiE8uG73QPYEI4P97lmjbW26TUpji0LQWlcpz5taKI6Xq+H3HN6NTSaifdCNj5xrVv2rq6u+GqTVQFrXeZwmIg/NIMPp2YxkP/Lia28MA8H0RcSbXQnRLfVCkmA0GxG6KheG7NiYIIPdhrD6flFKp4I1+Smigz1BNvFuTjcXnloDKDgvuyRG4T+QA1ifr3bTcGHyJpRQQgX5CNdxvSzK7jBJ8e0hs59cR7/KamjAKKlEFwhWkSQEYYgyPsTsjTMbomdc5TfFNs4Qno3CdivdwNRHfAg7ZWNHmHxToZkIlKUX6VCkUtXedLI+Ifdg11JLiZ3eWg/HD2q/R6xTnBiPgWRlgUVoesBAziGxmWHzmOfPsmgtywEOMI/iN8j1jOaX/otRGmHb4AbBKBY0IHBQKcU5RUGcpF8ZLBDZQbTbIFnqjPGW+d4XxkP3LADVA6zmT/LHVQJxSSYL1YJRm+owPn8wkKcrVtqxIiLglBoDW8cm14sE/8dpSvfReFEcAP7mSvRCmPARWs2Ov3HjwnKM6N5kVrG+UhmCYbMB8pVaEgqDdtXQRgWQHjE7piAZtDZqu7dto0MUJfATZ7n+mT8heDLpHTiaeKPs3GfTMckJkrLXytvGoEMpB11oyQNYIDL7cuXhx54NHvS7t1hcC/+rhQL+WtEssKDr0Jp0kLFDUPdrAMvTMb2ZDZpvLgrZTassHaSqAIJYWCHmJmeYpuV9KiSSbmo+aeT6Iq0abE44dNIiGG5IO8sUQIZk+9Ss0tTaj7uSJV9jyr8Lb28fPhxJeJj++Zz9kAkuVHbpjf45hIPn643LC/nVWX1rDXGrQ3RdBXakFF7Tihffz20SNSKcU9nVsRnrkCgdqZ+haFglCHqYt9ifPRsHTLJKhIHc0bLXcZhv36bzw6IOGvITVB6HgnEAOhMoLa7Io4JDTRBKpr1x3p4a1mh9faD6965ofWHp6xJ1h/cfpPVJxW4hocfwKV12BFUQTBXDXl2MSs5Ln3jXBYdyq4hekAdyvCIBnwc0fEMQV5gqsJXjrG30xwWLflRzDElXsTbDsQLp7/peb0qL0YEbYE1vZVRpkgrbtRW9HR61LfQ2T+JE7uMm9YG3C5w2xLjpRxE0ziWUeNOegA2KaBkjM0YTa2tKa3RmtndUhIfVMCFFaE1JNlkYqZqSlBC5bCJmLovzSVfwPbGd41Oa+iv0i3n6a575/V+cJYYLo920QJq1tA1i6IUV9bHYscOKEtcvKcIKNnd0jhzod97wMp+LLSRgIO6ZtN5oaEE3kOeQRwVwnDwjdHgKd5D5GyUmJVZlT2opGCVZJfMsAYAMZhPEN0sNDi5S7OTirclQmaBTxGC8tHa6Q1u5zlZgBCajFvkO9JYsX+LhxVzlWeiDTLDP+jSQa9nIQ/SuHPDPZDKryLqCc0oHr5NUZm5ZjVJmpAwszRZkO5UV6EdmpOg/Bqy4yfSPtka+hrOX/w5Cjw/KEFqO7yLmSBL6k+IF3sNaGMiqqelSJfm+Oe4S2viSZOD6eP1eE4y1KzBmWq5ifT9jYcn33shKKNtCr5xuNBkZ9VFCMQlzBBChl7kCdKaQbzmrthCrgNn5K4Pwo536gxEvY3emM04iDXDI+D6tXdlmlLe6gxkaczEm47Oy4gXa+jDPAGSYYjba0oGG1UkzFdjUKsg4guYR8ThQiV93hSis0d21Tdv3nBBhGUVlRqQ4W1KVWL+3bcPJ67QqrzRI9ejxHnFSSKqwMWzFJIR8oDbXRbhM/Ys84opnjHFVXaRuUU7FUsUWiugXEvxeBFHX+HKuMxKWYk4rGb0KJHEBJF8Nuw6miG4m43gTziLZDQkzKDWipyM2UR3LOK2gD767HjXyklTIuROcIO8jAuyVt0e4NDBAgonrrDldDAQMA+nibz1h9g8xtQegrRoVxjed8f9YUk+8+n597/X1/fXxf+24Q+XR8dMUxlyy8qQSwfXjJa4WDH6VRBhVa0QMU9IiEGso5ISmfV4TQY0BLKRslRV1pVVDvIgPWHCxxc8mIGCTh+EAo0faE69dyB8Eh333JgMVxcTI6te8z9Ll1nlMJ/FS/R3LuqFPA3DGIqzJpkvoOOjm2AM5JkAIpd8u1wHt1Lii1f69ZylLMKKKfpPZBHgTogRlnBt/Direzdnk2axbuOUmy9VNcZR7q9xJ2Ii8elsnIONeCzmjU8ATqrxnoNoKbBxRJbbqyTQutj1rFwmjIy0XF3lY2EW7uWb4sqyk0I/YwaWZa+H1FArhx8hbKlzm7pxA/eNgt9UENvUINokpaW1ctoXDirLpue1IZtDG+5kkVhFugXSOjQnhzBz4A9cRT6gaIro2xln4ubvZj7uCiKN6k3u9hRwi6VZZ9diOqmcpzxtzSnYlKYjNShFMSjaeT6LNTlLDm22TxXYnAACAiAVbkf69pMWF/qVDBYMS9qFuHZVmi8m/EDxrkSuF9NUEaeAmZv01JNl0FBLZ0aEr030/0oYi7w391XaSvkpT4NHB0ycRCuc3SdCfdPNRWiles3gjHslsFlqSJAu5krsw26QaqU0F9HahPfleHtn+3j7WBFaYRiVqCQpF5HG3/iTd4ae5AMJbfGlVfyL2KtaYkH+JX6wxe7H/W9IwyA91Z7rXFGCQDILxp62yU5gLg2htjPrcFh12kJNH7iP8MOCUamKeKJqOcq39EthbG0xxbo+g+OqCASCGMS1iLNL6WSIgQ9v5CphNvP0QgcOlE5wLb0/pjLNLd073miIWRtmhvN8M+RbiYwu1O+MWFlqJaO5wlibbMVFeH0nLxqzcrA1cYvSa9d16YSCGkWYZdnYSsd3qyoiaiCuI2+Jg+dbQDRRvnnSKe+coBgJ/FVOgep3HzkHKm+KrGpXEWFTjGb2kZhRG+t2UHjg63Tya2i5XzikMzrypCcTNuCpj+KnX6l3P1xg0veIWxn/8L1hBTUp8w3sGZNMo2LSihnCC0kjF2Fl8GGkEywSUZ6EmqOTmJDXfLcGI509vzPSEPBgunAHdgikC5ITrPDQKBTEqbgu6zbZ2GFv7K0ffLTg+A0QdujSCSeIRJc9potEOQ94UNinYFuA/xSUgWaWeDIwU0m8RJVJ/ICjllV6BeJR+7xQ68/YnkW0tGvyVCs7gko6yIuLzKg/tFldn08soHR5EKuK46KKaBxIWcZto0xjvSNialTvAc9umPmD1wfTGiiTXcbKaQQ9V5pyUkUkD5yzxImhPx4QGdKQ4qvffnLbUSLbarEsp6lyoerE8xAXnzGsByGxO0gPy7CIV5mWXug4TleSPuAlVXXNb9vuoGtDmPOA711hNXj5PWUc5pwF4mPfG0AcDLPP8zbBtapSYP5pKfOSIs5lq3qZjep/ssBEwAh47FGuxOL8lXvQ6XY5zSlSWCppeLbxHmUSt0Vu9XKiIqqD2wwwndwfLSSZEAMDr3qztLGzbR+dnr5Hq8/x9vnx9okNwUTwaF2/43btSs0NnbZCduKbN1wFa5ZScw0dtYqQFXA6UpCwXPtghWyDgzJ3L4Zs6HTAFGnlBj/yXK3Jqu2S+TC/91mGSythKgUnoljg8LXmRuY3ZkCXGz37c+BZj26Gm0hZGk6EjHN7aPOoNhMQUZOJ1g3so1D74HyXlNr4yWjFyNb0C20kJ27h7pY0zIIKGkBI4TwBC+feSNKCOZKdNmuwJFBRLFnd+Ym/UmSLj+y9gz1LjlKZLRZSjCysGWQpWN+aWymgLohtxPSHJMs8WrX5BrCY68QGLSrD6Wp1kcXbsxaslfG6irYGCupBmNoD6C1T9Ft9YsTETKsJ+T0ffdTHzusT9SSyS8cGi9XBuVg3xMMJRcpXxbtKka0SfRmedZW8Y6KUWRmVlfAPjKn5EocOoUO5D6qc7opM9Wx9TWntEQU0fqLYTO5dXQKoJoeoEg1RJTZE/TD83rMJMjMb67dyw4kF5A9H0XW9DN+9Iae0iaJurem5dKCKjTskYXhmX7WSKuNZSgtQZ1kiBUlTnsaQqwwST17x3zXvYNcOt08h75AMS03PD8SpF06o3oEnRn/E59AqwXlgR7GeGLmYIk+beE4wJNB+sqTwiXzRTAF08c88F/x/cKz0jQh1ijfEVh+7tEi/it9m5W8qcqeK0B1Ip/Z6x+i3iGXfbGzG2BJjXeH7lFhfNDbpCYM5aka4yYf+OOiQYir3vSFboWY6V5IYKx2w9JszJCDChDB/EWnOH9H3Am4RgEN+2HYPTl2ACwktZW+Pq1R4JxMacTdw7uE+u8ebgFE09UtMlLl/8o6rYRwdmGlBhBEa85HzO85Q8NABKNiYlxR0SdiS/cFA+kdHfqwkN4voU1CZpAmOs1yHSdEhqEF03vVu26Uv119K1UfnU6fFDUkyGeZ16UvYiGbWY10fBK44AgUPDC1BvZ9bwW0ePMGv26DTAKt67PvjUObrqyKCiByX/RCHhfOnWNPCCzLD8D45f0qVKLDA1yXtOEgrtkBaqrbck90wU1KBFa1E14jmoKlWpDmVoLe5nZ2d6va2OBjkDL9TL0wt9JyMlJmUWhyDd3No/XwBPOVFvelcZmNROlyhrKy2kwCq7LnXGb3ppwC7tZDVR6XC58SVdw48l9BjwxSk/1vm67S7kQMbD5mEwYJDPqVPnE2ntYUY0YKkWinNsnGyebx7dIrHEcgNwVvsT4+xiDGqTFCc3zihrcyxoQRUPKjfuHKdrZQqklRMVkxmr6BmOK/xNejTmqvjvgGK2/IXd989AI3/vbN56x4zgWKVkDrg3oDjrhQ1SXZQuJcXoo/DPQr8kS/mQjR5ifh9AAzxEMXdPXWuo4t0kj6QF6fWEpWOnJFQJ7j7xJBUaka8W09mPP2LdXHxj3WpUD4QyEiSQgiucES0RRNkWZQyc0p75g+iwSUkZ+IOEdYHeE/09MoSpByBeLP6QXMKabf6zigaYoFABoOJpuR+VVVcEtFeZE85HegEDReGxMxlLrNLRmrfOLr4BQnF7rOtuEsJq6ptDZE+YEfU9ukI0GZTYO1QaDMdHY9iMGwYDmhxJldPqtAHifZ+42SfAJpmuac8JFMKQ1EKIuO7ynwPWnB3GruYlqeOCJmmyPX1jLVVskpYkVG7Sim1tQxqb9B/GkG+LOvhorDQXF/YcRauMFWQRTaq1M+Kacf/a3+ks9Ho4ptYpjg3oToTpiM2Iunhp1XOlZDHslh/jVIiLb/H9FJ5OR2PTdA2ukSa9BhH+px5SiTSPJTeTCCs0ehNhAZpaIMw5urXiaKqiD8inDIaw8ZSkLKtP3Pd6Qj9vod/6SPRYVUpETfkF1uLawbcY4NuKE4tklRG38QtLQAoK2N41ky4jzRLJypGcsRN4nz9aI9QqKb5jvXknLqjjlarU7Rm4bQ+m6Z8SFaUwVu7CLuYnJzoomZ9jIBRtNuQEbmwBIncFqPTND3C/NbffmP37Pjo7+Lx17Pts2vn/fGovVVp4L+bG5X2p4dx5we3SgwWoPDmlUcVd+Rcdgq7spJGU2LspGYeu3wBBArifDb3VCJ3Lp60oGQkTqMmFCwsFgDPva5I4OjsxMqxLBOj9Q//kEV4LpMsTA/vnYXoZSuBq8OwJXE3qhI4unYFmr48ZURuKXOLhRYbhYmmE2P6qj8VUPw7dwUjb5okJ7MQOzm8DoDQJ7sAP6SF2tNnTplqTWpGGk2ZGCbtKKuzl0UlMly9kYDjcXrDG6ftqsgBcq3ysiQSNVyUit6OpN6EidIY5AhwQwhUdjgUle1uxiqp6cY6I6WsLhqJtbJgwtnhr6E+h+WuIssqsuFM/xF+u/YhdZ/2JrRGoxLwzj0e3LoMgUWNahi4tlDK+rLrOtdJlVJSQ7y2yrgym7my74exGGcuXWIwTRz58DnExEa6Q5aWMtdD0CO+bTzVkNPdWCMUOqen9oUNs7QDf7bhz7r8Wqum56fn6+QbVqTFBU3LTNA5q71qhaIkmw8UQ5YMB2kji/HrCoFGrKuYVC8SEXIxqkzQuCN3xYTuWnN//SXm3sgfD4fK0JadN+xbMUuXNdfxwxtuEdZUvcJgV/04CFzLGp1u9o5CRQI5GfGZbbzj3cIKxXmBohtyw3WGpnyuHuaeStWX7d3N9eOFk9P1g631462F9YPT3fPd47OThVOheC3AsYkromJRLSV41zVE0T8TO1/iqkozqWLMuBXHyEerOUkmJnlEfxpINiWKrPhr0WO8/yJOqhzx9H4q70Fs7P6bgzcYu1KOYleoAgKhMIPDeoJaxoAIprlILyXnCOaBmFPQ5JjZr0EYx4J2yCBKejDFO4Muo9YSzPgk4W7dx1gi5EzX7bmUXplFgtTHw7hPQCZcjb8CHrCG5Jd9ffsTc3rc046nBqqSWyorpTgaPznj/lG7rdxOuJJ0qA3HQs3rAFWRRRyxmBAgl14U/4NYCQhhdjgKqNqQmOb5zbPjvcOjU4yjwzC6eSvz6f2xlSG6TZapBMQC1/vSb7DRaXxy08jozCLq7UY/42IHxJiQJZCWeU4X9YTIakDulDvYj7otqcalV5ZBgXOEoi8uAPFWK10q/ElogZ74UhVfVkAjyVkzF4cF+/KpitnRc+I3McG5Lt8G5QMccaUqEhatXIYImaUTn0riNlkumY4pPmQQrlQdUKLUtdpvoemMgppTHdM5rAR4bYyJU1LpxVw8COsCDN3xA8Q4g7VlGwyOMn6wc8+Hh6bMezHJzzO8H6TEf92Ufz9wu6kbxFlwEDxXLrEv6KpvBxKyDt3f2cf8HbaYZ3L2Z8TYRKm3NdiOKHu0fvpeHpe4ZVwWJaQkwC0vfQbGisUUUmkK/TDlDVNwyuHiSAQrniLmycDzHm53csZjh1Bkw4Au4p98nj2iiLgCqIy0guOO1/Pvacfr9Lua208oGoTAJNyCZlkY3lvTUJ75TPSI0lXdcXA3hOR74WOYoTAiLRErA7Tw/L+wQqUwn1LkQEAoFbxFLR3KHOEGwN6+Phh5nRsHWpukG6gijgmt07lzL/TaPbcluZQ2vIH9vmSfQmkrtzsYuMGpWCWtNDjsU4a7XuGbrvxeN+UNUvAvGLBPxu0d/BimMgsLKzuHe1vbx3RkqhUUyUlMEXN+BJQ4qsgx4DWEMQEqdpLS+xUeb3NPqSE8iehyyO5pRRaEconsB3iIlPk3UVLnnrTwPcmwvAp25+md4PtJb6yRwTR9sLDp+70FzB4uxjX83oOm2Hpx/UOB4U6Pz7bpxxBswSP9Z74BKYhgEycLWfjYh50LZ9EkTQLb9rWMlBkrRuID1yyJEBeP5t25Jacd+j2iHNTU6BpCo1BtaK9YucVF6wJnl3JQhdal+DG3nG+vcAWpBfYfhbAQ2hxH/umpZyHUUezT4np6Pko3wqr2WtBn0h0qwjb+GiUbRaZ4rzfyFzMrR4WzxzXbmikHVr58zKUaLFSWfYSRpRiV3HFGKW2NpmVvm8kaYiwL3y9zJv86jeFEsxxrjRpV/Mj9C4xY0CBGyqF9KLEc9GSbAuuJ9NOw0NQQXcXEAbG4doya37yBmAuewXjAVmBOxHhwKxIahZRkXiIBAQWeujKSlwSqDoPXXFQMgOdSYpuyJCV+jZORUm4jvOx0u7DcWr+Z2DcxsB7jAwKJkrsTUhO42eSvSi7XGHVVfs16+cqNfhYdPRnez7clm86i0ANT5Z3tCAZWQ1AVaDVsVUzDfppyxKINx143BUIq5JJoBUGfKqO1coubj203SOnNUSo3WHdd124/ttIbvYLfLQdpOQDK9UNyfQtyADDpDZdocokrN7zx71vpyBRPfs8aAonAHqMZDLYeMN7FJjjfezdwuWzRvN/2rTcoPOhdRlwOOhEjQEpaqQGgGfbFliPO4IVCHtzFXAtP/hxAj3njXhQZyyz5ep6hy8/ScfYcPcYzuszn5LKjnM/squdNZWmV9yllfKmVKDW1ehL3oRBqT4HmMoQMqBNYdvIwQmzpP4l8n9egF6bDhpvJANkDxl4huh09V3nr7cU/b5U97m1etyK8FgWnRQ2xZ6JWkga3mPaSWkjtOKfOnvH6JJcTKH92p5XeLfXGX0oPxa/vzq6P3h8Uvr7r3e31uXBDeqqt9f6jgTBRHzGdnCUZwGeXIR/TCm86uNVzAqbZzNhKSrzESoZtQ0Xb5hvj1lEqGuueThzGCW9p4oIiuDdKY8gkLn3FHhmAwLVmgfZiaLiNxSmqHSWJnywW3oyvrgi5KYvOGaZjOrOFPa+jF5ovzEOyLIM8lR4WcTVgggEm9ewC8JtZuXxnEGBWnwU4i1HWlIF3fQM0Fgs+VyyyiMGUQClCPKR2B23/ISUJNWqUWw9GkjKIbzC4PaWtBkSagCqNuQITk0F0mgCyBWA5neAyk1E23BbyrjFsTyPAGVO16ABHUApQpnon6GgkVUooMtJ4oCwHk4G9fC+0s9WmITpmOnY0UWY6Bf1LUf9SamW4wRqDEN47nY9usJXaeEw5W2J0K3xdmqs7nU4rOeFBojLN0xoRKNWCaa0ej25QlW5lcqBDZ5Zi5k+Qom/z3ICEciW+o2GUaE465eH9yHAGzGFI7RAEpViJKdbARuB2bBmbDIS6aC2G4ccvEs3MdeJLWc1tqYsaJVkb5R4UWWZNBDXpJ24uW+Jj5XQlALL2inNGheJbX5bkzh9ziE+B4GpG+5pCr5xsru/rTHfn4LFEaX3yfn3r8JP46atQkLhWhVVjHVJrt72RCpvQ81XUCMxSoayGA6HJueGEIS5u+MyrovlI9f1NbqfXomxHTgCBxdQ/yhJJRMJgHhtFuQNZwsoHjSdGpGZ4m0L4pzWrQfIXSP9TbUomAQNka7TB5ypy3FiRYSBB9hBPDzgmhG4iNMqIBYBm98C9txkBv7CioPAymkmzQAONFIHBGb21Smo15jjOGbR68gIRfojX43bFbYz7c+fw9AQKCQDoLqwsvhsZppczSFW5RpPnfZSjUZ4aplIXAkdGOgpJmTZe0HPZJt2sKmNz4aADsh4OdGjpG8G38Mbp+veZ+YzT5vIy2fQsRy8rjB8D+I1QTha28xnx/2yc5Y0/SqNVqyp6w7bTRRS3lRs9qFj3tBNBHXSiPqbYRuM2qp4DjTpZhtuSFVIeJ8FTpt2A7o5nDTiOI5UZrB4GMsg9DM9cESQos755unu+rQpmviAZeObd8eHZkb27pS6Y0YZYRkZhJ9xleN8tQswM96rCBw5Jq0Ix1+IIMHw0zFC1KtGQll/N2ChJlQwcvSEZ9QPx6pL1gjjY2BqPChBMZk1sXy7kwdHeOXeqxhsWbgvaAaTri96ZlKrkXsbMezggJ+8PP9lsKlEZ1pSyDmamLG/TkiNd36oJ+NKMQnvpqBPRvx+Fjx1WpAg7IvSIe+QGzeLqWhXL6+Kf/GUWEtR512K6DGoV1L7g7iPJHFUj+AicFiX8CRD9KmKa7PqUfQXAPiaTvuadiwG3WH2abErFYPPti4x1SsCcpJ2QZAFAR+iIyweRIlpCONFBZsLOR+nKIkbk83Fv8AY9+cS+mEWutwP/nosrxKcmsqV3d7m9ckK4xiy/gi7XqkhQLTF0SjPhJPW7pl5ZE7BhbqzKB9d9cYNU+zF14j5s+depo3HP4RKYZ6wgAUILK+CUCXx2FGYQjulh5kFfUgEoVR3+3A/bNhaymd/AwH3rg1fnG2nT/R3wcGC0Mylq9FFnd1IssnQpzLYgxjmuTPJlvhFSOhHyhGw58sXLjC8GpVVSXIpJoBAPheYjBCX6gmyQbB2Fijd+381nUlYuReMJnzJ5wv5j4sO8GXyZmeeC1CaRxQA2IiQyr1BsnKgjsOh2ul0PBs/pycDx9J9FoORLwSbZsiw9oFV8s9Bxj2gk+DZjXv2znJ7n+nz/Ins8yFAbUXkYPB6hyX4g17L4+YKbQUdmMSHAOPbqtMOC3CC5BempgbyUYq210gfu6N4PbsFAwx6Co/dH0iCEiAZMaaEgFpgVdv1OPPm7YAyiEYzG0vCCUIQyxogLPRFthGyUeOf0+w5mj2ibFiXCGsCbiaVUEdJ+KXwMxTZozYo9EgydQpqJs5fFqWuV/5Uy3MNSgVfHzdZ5tsr1TQDAJASUhBYm2oeNUHv5CfZkOUINnq3TIgwz1osWEBqPrcnk89rq5yWNDn5Q17e8YFNPkQgKpMoi9AR5OKMCVJVc/UV1MtDgdVEuAt2/OQe5tVrwU4Uk9DTSTm6f8lSgqj7y4VpLQlaqjKdJGsXJ6clZGqhHkjYploKilaGXx7cuSUSsPO/pe9B8oV6tsmtCwQGK+iEx6RBbnMg0g8FNGf82M2k5Ied/tBjiW/zuoOt/Fr95rOKh3z9mCe00m+GNpLNCecxlq5oBXOzC4qnnVhG/JW3KQqPLpC/bPYiroUAT+E6N0LBt7aIfAMZbC43knKwW8/PAX0mEGYEoeDIjhqBsZMdaH4/8PgdWfXovjqhvNwNwLbNgpXxTYqqe1U+9/cpp2X5feShAP/YpVpg347fLrL80pPuSN+zEbYKkPZwG5PHAyvUfxaljcMWtSBUq6iiSvZ76PmZtJBcm9GKSF7BG3vaiZiufQQCCP1p7qPAJGx3tUTffpk+Rw/VteIMYXJCY4Zu0djKNslEgBIBbKbHOobNkiZPgEbpHKO3U3TAc2sN7kyUt5sKixspsuJP5GfFNwyQQYwD/rFgaxS3a5bgi0mKJeStZ8ZitwG13KH0Zu8NnrhWKUZ4hRKuknVqLVt4yz3+WIkesNWVmZJViQIfQSouQ5LxKcntxOzVTEYTtJncydHAB6BOKi0v65i1n5Ch5veffelsbQixC7jUw0cHV9uPultwDm5LFJ7rLvnMrNj8YzgUrBNalMnQL0+2Eb7cfcFGr6UM8tbiHHqMN0FKIuBT/IObB1gbcd5omJJavUPi9gZBHgANMKdZDjRRl8/DgFHKG720fvDt9j/bK+dT2webH7S/2fOp0e//IlhKTbptqpSDHJy3mOnnrxUupfjkoVk/Lx3a9UoIUFoQpiIAhdXTWm0nxwHAC0+he+7wgP+OHZa4rrWUa4p4iazkuWr1v+NlKYOHF87LDGMM4TyDMwPfOe4dvVmZUQdTRi6x1AS+sBC/sCLAfURqIj50NKGFdZqkEN0JZRUuSXnmqlQ/lK6WDtUIkJlkADmb4CT7zasJSsiwwhDw4AXC0EQh5Acw6cBEhE+hMopKTygb3rsp7v7aAWA234XDN/HE8ph2UG/NctTYhFC+e1dgcHO6vgzb2fn3z4+7BOxDkh/tH6wdfuHJ9QvRbFyfW5Rjwoxcb61uo9JB44RoEyTSX0eDUx/GPVmm9IK3I7LKYJeX14h8LvWrKJ8MOtT/e5MdhgEw39F4WvlM76NSu1I37oUjIyj3m4q9BOxw+cx5l8cOp945toHV0ZtcqCRjA/d397cXFDdRQFhfjySU74r2NHEoJGXnY68TlYSjGR8TkkcU9iEthOvoSOuK9wTdtXon/rFBscHnLtlr3Yob5d04QXnXc9jVAMaF7ckrlJrVGbQ7p0+nF0nGVuhUlOl6wdIG3C1W3DjfP9kHIHB8enso70m1XqXXq5rwF5uXg4VvYhwxIbq97+VTB6H4amDl+YEk3wJTk+x64SnBGXAViywjfzmIapblVoLrwr8QSCryOQ/ZEH9Q2dwGueIPrfOhdDxbELOCWkVgZJjcdtECQBR1tRCHIQpxD8nOgir6IuxQhW1NnAYxF4IhPusPQ4cvyJkjtTskwxbljYaWHhr85kMu7RzxNgXJuZh1IjPUf2pQ59BQEhPYz0ArryeLr6IMvwYOY0mc6OUaCTYZeYkSPFxLtBfmqM5J21nidBn04N04eDIholb/ErDrx+J9X+hkLFwIRvrZq5N4t6s38LI/VVx4tkDGQvjYpCxFobPbduGcyxiRnNzMJ6eoIY6gj1fxMu1yv3FqJeGAcQfUTj+c8r4uc+AAPePlU19D49ZKk6KP3a+RYicj6s6FzhzRYtCyy46DXQmMZOpSURZBwN7ke4DBUosk6wSaQ6HSSFBKMDhZRyiy438feXQv6zafEBZif/BzSfoEapIqkggs3kLBz1Do73VloSMUyknPvMIE7oDoChIe8NQjxeHG+7TmD67Fz7WLzUXgnNsdPUWK0Hd+PX8Gv3nXhla7wDVBbMPS8EyFT8FSV2MCUjA91Ando2d2+ODe+r5cW/6GxKBp1TTIF7pU4ud+Yw65dZxfXJB3QI9wG3zvXlf1R1CvJTyZ7lnsqV3EFQP+0LBKWod/EMkrwhRVtraXGgxuv62743UflLqojDAQ21E3/6sp1N8dDSIic2vGDfmpj7PH5i5NKaMOGhllAdRn+hDojRYoGvaAQfRJv9axpxnPQQQ1/JcX/3LN1ibIXmANqJNaERBOXGHv1LCR+/7nt9cL+9RzFV6yqHdn6PyFEL5dXrDfWW+svyNIhDj3PWSvXsq17TKbWFC1aA7njclrkYqyZf6wByF+xM+LxaZVrPMOfPPyZW4ItqohK2UTt3+0EDx4iZ8oNae2aPGCxpUtFNCdtFZcW9KwqSbT/y9fAPSOe/pIKjkbxLAbpxXpC1VS8JVGHxhJ8sb40Km9Dhq+luWeZfXoC6pdwd7HLzs09lV6i9msR+7RlJhhPprD4hSyD2iZHz4iImlK5HLPd/NcjiBOZ4gfiff+FLvfdQeh8S8BNaBsukwiEEdQNYC+w5BcT9Ig4EqxORDhJjKdYJfppY/1g83DvcH9jd12/mUXarRglTam15sy5TYiiepLmTtjQpKmMgwcjOc3ae6H3kGY/uoez/yPpgy/tNaTvr808aJs0hKT3IUeIThnN+PwLhdCDyM5w5AQaj1dC5Kk+JsVoNERZVEBsia9PrlGKakA46HDuvxy/5NlUjk0L3JObcYPpLwsKa2roPEcQGVM4h58aOPTyvTjRTFP4ALAne0MmgaopsE/8gTihDLGla5xddYSYEf07Mf/Ix1/veW2nDYodkd5TacLNVP4neyYGUmj9nMw/EH/xE/uH2D5K88Ua7R5X9yVzQLnPRCNc0pNJYe1cHqJ5lWF76V/fn3evWM1/PxkBJsR9R4tHWceJTiN3Em0A4scL5PPxJkcnVDDJzCKC5Bmh83P42ErwgSB6Qv0gSYRFj66bCbDSarTViZqjwOs/4ylNoZljPIlQNxy3+2Q/tvCsKJlIkMWEHrupjqz//TRLFuLapvDKxjOrQPRSd1OVXtWaSlXUmqjoEtZV7PNF0UzybZcmylmlpAdQGzONFoEdIZjPEIavay0W0XdHfBBRilXswTt3tHsUOpEQj/UhwcTMvSEaTsOe+FbaEW3D1KUOz69POmOIUOT+Gq8nVLl1HxOMEtxTdO/V/zcHAOuF1Ea5BUKYVOBTrAf2GWBkwwSJH3tGJeut7GqSuOeu4wZcacZtOmpzie8tUwdU3u9e3i+MI9BgRshSZgkZnqVMLbEQmf/ZiqXdS6nP2vaFuFTaj0CYtyQvVk2R/cQzkA6HPTd1jNxOqcUUpw1Oy+aqfICPaCJC9oPOdu7uSqvPkBa1uzqnjZ7GJA24Nm5I4sKmJtE4GXfGQYgpJs+9YDSmVJeR2srtoPGuYmTcnG63+12r3duEtSHX5H/7HhN3U9ZTIMIC9qRq4sZJb5ufv8FYDc05QTLLppgHLcCfoHUpBnkbEG4si1zO3CwFFZUSUWU4PA4A/hBkkCidp5QhzEXRmqrqYT2cL5dPZssJYYKSTENusGI3uLC6kPZ4de6Jxo5FGYJbMZ4Ew3007RSOBg11vL5b/S9eqXyqmLBGYwLZ7unt0u1Ip6gIFdYCwyxxz3FcU0OGNVmvnQjF10Utg4U6BBK9XSzVHx2B/mfPmZC9K/aUxYL2mOWfPia0vrrybH2Vb6wkrU//HxzhdVtUTH+xfkN9+V3Lk254gpILXO51+9NvdYQHD7e/ZjV5ukfT4L+f7NMsAPSCK9oLfkWBaRTEw5ta3m8uoxKJyn+9jHjYKpFzMLGz1ho/1Zr4nJNPSEdRklaJT8rYDZok8uVHReReCdKgWAY9aX6Vx5r21I4TdCmKDD+6D+pgIlaWPsK/ZkjQ5glFs5JmPG0hzNCs0y2eFWPOGQNv4bspFfQ3/7KqCXsxzU3dyzhpWHMTRiOlaJXkdhUpU7qKhUcBdc+fC05LSyvMEkhlNRRrRUlTDK78H5jB/3/eHpD729gm6oyT1FQHoDmnvLfUYnwm76zvnVAKlJk2a/A2afTcZoOB4JEbZFel0UVM3tv9ILRyR74X+gOJW0D4PabDlb4yLVsoPJKG5eVJN+mz2QAvOHTRG4hPnhvAl64LB8EjNxjLZZfnp6/JfNEaNGNRQTPcjfFH6Ed//QEe4aB9CP+G24Mtl9ELCLsvEstx9A5ycl/9PvbFM9sI74c8HzYHDE0aHnm9Qf9AUFtWMCc9FPC61FlWWxsasRc//MnQ6fcZV1+vSXY2PPsgtN4RtUP1dOLL6iXpPRqcs878i9XXpEFk5dg7fHcSM3ooDZBrpLeh98SPnYuOAZKbgGN1tFpY6YhNmxP1wOapVeNOk8yuqSz3lgEgSpKIv+C+R3m5SgJzVRlS423BvirD1TFQPR6z/iwj2++c3hwbMGdYDOuM4yz7ZngsrZL2RQ2sXLcc6QBnOiOxm2YzyE2+LqWAwwxVuX9+UgG7KFFw0UayqpvpV5GA9+Kf/5BkKrzEc5XHw0MnQvXrNcnkozmXdz5DGPQzfoQMpeLD54UTZBe0GEy2HyysD/w2YGmEfG5wW3UOS1uCEIArRxxj7XHo2s4354FpedTv0q2uUy9jdhBJnspNNiKEtWJVpTVUEScLMVoNCKZZqRQqGBQDSJgdfzzoUpkmh9u8SEYdBovL7J3avbMEpNdGBg19GID/YjA98yHRetGnZUvuN9YDvKLSfPllLsum218ppQeBRb2KPpWikOx5xAdipoh52wbcmvj52H6/vndqH+7snGyfQtj2vG6yZyu/eEI20mAIiGG7zVuwca+PbtyBA8Gs8LAc+lyvK+6TF2Ojf5F/tG0sgVCEGNDw0d897z0fPovHr9Txbwf/XoEuxbdS+XeBOHPebyeQqM9NKiAzVpiAdbF44nPGCMk4rsxBUAbDYZVXSGuH+yM57rS9CldebtVcyTn4mWGgGChSKlYSQJVPtNRhxaqEwGJF4hxIwOSzdJL6LhrNYchK7hxIQPhYL8DfagF+uIGPtQYOamOyBBnxZqL3Ebe5vUzzhStKc00YYnhLg4I9JlqsJbdYi1rEtYAYACs3HnjfPQpB0j7zNkPpgxuG0VaPJb9xHtjQIpdpllgvuDqlwqpz5pcX44+xCRjyd1VJbCM6WP1KZazVAP4MVpXIjmd4+1kFUxzXZeSkJo4BNSflbtcZdDk1Wb1OFLdiljnd7k7g908oTFsqo+xhsay5pzo4gnifwGMT+5Wk7ZRmaIqDKGmj6fS70R5DHY1MrNSDBrF3VxJNVfvAeQeq+r4PqiBO5dDpuWEeFTSItoOsVCSakC1h0+/1XJn/lGGDCyvwcJ7b6576O5woCap0OjYdy0C7w0dhFR6OP1D1zglsSHMMhmls/QTyJlCQG/e+yPh6lYg6C3gd8c+X8eAWaUiyURKMOkbclGqFaFFrZ3s9pOE3lJzYXs7sHGTS7blO8EzRcc9E/jmnxh9n+yqpQb/E4INq0DOFCsfYfDJy0v8jTpht0aD/XJgb4Tftom5cV/kC6xgEBPjsa+fa6WEhEhMvnNVDzWItdSxXRZc1sOHwrLNwSVCSNY1pPAffxbV0xpyH+mlfOX7irgvs+/1wgZGDsVlv3bM2yD3CE3lZbXPqj8Gmgi/Hup9jMRZlpbVeOfYndRbD0CgiDRRTuaupFIda6ZbqMKChyxXNF/iU0hnIoj1film6V5FF34sSOMugsPNzo+O8Wp1qcCaFBfSVF3EsLszXG5q9RQXN6pBRsKflkj9rH+kkpROuZIhwxc3MW8V5TB5pmlcbEpdP2som8gbKhMTZXrnc9u3hjSdmf8Cg8waxlKMJAbgKDZPS6qVSFdSciK9sPW2S9YuLWz23tmYiEwDchjsn8yYkrhPx59EfBxhq/+AHohveYGOLamLUVtXYJzYemRSSA3WOiJGG1HVnHHgjZ+A5qOONopi1erMoDQDiVaxkjCmoT3mxHUzM+Shr+ZQ5H2VLpynOK40iwczYDNJx0JQIxgD+eDK4wrzEzYL5uyrODeLxGcIhKGeuOatQ0RCdcxZ+yBd+acHBKzvxY971UAzNGwwaPDFom4l9pkxIJUp2MydpHSZ39iaxXSYht4Z+6D2Anju8H4Pms7YKmiAw1/Jmh5HiQoB7Tii2T1KZxFHKF4f5QbjKjhf6OxcX0RiNZpqFtgJ/uOE/gFVo7IUDojYxAagYe1ZqRJGJYuPwKPVQwrHSUrnXeGeZoO0E8b0aGQTwa+TZWz/YMmYRXpV7oypKYlBdq8lrUZRU7LiMV4uygeSMXmw/msVSCu9noaHmMpoYUWVylpA/RL7aOsezC5nR7foUXpF0nI+UTZjaXyAAaafn+2w7atJZN9nxJ267tur1mVrAAngLTRNthoCO2oWbD65oY1uVA8yrevYN7jPw3F2P3Y0UwFfX6D0SfYPKORq1FmqBnqGBp7WKJjPr2uqv6ikYXBJv6JWxbxRUgqtofp97wMb/dsvvjPtkqARvD2PCdweTGRIsHasPmHDOTRrhwNMrdHuIV8D7KzS46PYYmKb5uNEoqHCE+Nnv4rBw+VSDfaE1Dnoy+ls/HYHuyiqJBPpGlRDhAwZs7acnsFu8oM8VsV6I+Wq8yIWgldTvow6ekVkgJq0aBXIBGuFlYPw5cTvikPXDIC1oFAjxgexK+ZX9IMWllvMcUszFCKQICdZVvItml0radVa1TVodRiwVTPMLhc0onXh5WqKlwst4qH2J1HHUghMMsGoLb2CEYqlYUyGfncC577nBltDXOyMjhBWbjfGERQ+lFouSSOISlM4XhbAHjWDSxqVsmRDGZMykYkF34zC74u6RrWeO5J3b6F7MgQL2V37O2sTBFNZXiIvK3DwaGD1JaFTQKaT4Y00qEaIcqhSOzBmPOoc24tELwv2DFJEpxgrNqBr9M4VyIjJC4A/G/aUmw09FmmSV8pnoie+pDtmNqXFjmmnbHny9XFIH8cLLMgY9ixca87rQrS/+WeEWke1Zv64oD8K3eTnsTcajYATlvZXre6BB5MKRP7S0U4QUXbz6w7dJ5ZX5pVGkyGl57rVmMdfJ2x1Fa2XNRhRXQKX3JI7eMCdbYjq/zDst+DWbRlrUcNhDzlrQlDqdlmNdFKzLeb/V6cwHLeui0xHfOq1StTY/XLqCXArYVNZrFZe8ZcfK9dzB9ehmyROaW1bdKdvpQkseuCfArAypuNfFAfbPSwwhA6LaPwNZF1camINz33yPz4qALqUfZ52R3+b8HkjWBDlARF9zWaZr4v/TRocghY3FaQSJWgqOSQd15qjU2zwq+uNP18VPW+dfbjuDg8+nZ+e9T2cFK3v2o+Lte9WD/UFvLH4bf9q5rZ5u7tah4N5j9DtW+nzca3sVrnS63fj7fCM42344//t0Z2N/Z8S9LUk4ph6MmJjyjNFqMk9c4eWmvdn43u4/DDvve/32p4PAPfHvPr7reV9KI6/T/1D6uHn8w/l8/ui++/D45eT++sP73u3Hk9v65qDQihJFRGHDDQwIruvcksnZVtz7wkfn05frj5s7t1858yj06O9hc0v8xynUcP/ihpEHFc98h4XC4WHBEudm62VJbhrwY+FQtPxhu3F/+mP9fn+r4J3v7JQ75x/+Pn13XPh6+3XbfX/+1T07/3B+O/r8d2n0+KUw9E97B86JeOR2mffJosx2KHqQ3HnRcX/309diu39QcD41x59L5xXn80Gh83jtffrUK7Zve+efTjulL7cfWBFsYOAt4d6hr4cw/OIZZjMftptH+/DfFnaZS8e5fSLuroQkv8ZYfvo6bPfPbz9uyneNagFzk5HjDdQtvg9y+xQiuiWx6P2+EPDi+BB/6ox78H306bx3Vyp++XTVr21Y2b+b+192j7mpJpMxfNjufTg5g/9uH/ZPd8KT08KgXfpw9fVTlUqWJG0DDuPp+hDe2P7WhhgG+Ldwe1pocsmiVlIM8I+vn//2P+w03x+fH7d3v21Udns8YKXSL7dZ5pJHPyqNo/KG39lcv/1c+NL8XGy+Ozl72PnMrq8GBkUCeqV2cv3j/nQwrJ1Xv62PG1tbw91P7+/f3/3gcpLD/Gvp4e5Lfyfc3Tw+Pyucnxze+7fn5wc7Z57sZY2VKjGUzaur3o/d5ufzZpA/KVQ3jzf2nJCL1fnGotj5p7vR6c7OlZPvdWrn7/ytk2CzPuRyaFhuQLlh87xfDN4VO5/y3rjsB8cnu8OHaqHhPXLRJm/1Xz9/eGyXP1x1+uf34l8xfauDj1ud4aGYQ39T2bLM1bJ13D8YB+8fPq+fbnxr792evBse/j3Y/cE0fw3iS6Z+FsXj3J2Vrmr1et7zXOf731tHN20uV2KLYvLN14eHpV5fSJ0fndJ5QUicq7Pbc55VZclItPfYPDzt3xwenp8F+7fH4/Oz2+C03+x3BzefzkvHx+dcHum8xK3OB58PG9ZM0X5/1hgMvrlHg7PGkfjBtQffQvggK0ieuzUpSILmVbnabVek8o8xKPB6sQvvj086J81+59uHL8c/vt7sl3eOumXWmSnyo7loiKD27dfi1z7LakqZLdbb0Vbz3nm/fk2SJHryvwvNo5NCb+fT44dRu3Rc4WpNFh4f3onVDcTiJ9dCFK+Lfzd+dN9/EIO574v5S6UrKhkW8VBmW0TcOZvJzPMn/gcpFOfTaf45l/TPnOKzzGpbJKHuC9K+mJ1rZXT7TGZJ/fzTZFu5t6uqdDo/C//mIXMD2FDL81ZpPmNVMtGNcberNrUbG21rd47l6CUONc2KESW/xZty5pEnWV/SyplpcsuUIFcWAh8uDCt0tkIjVcVheuHuIk+/NkxpstfT811kntOXvyB6sZzQiZ9h1DL8SvBH2KLACsl3w7RD5VJ0u7DjDDhDSUS7Y1Bi0POgYiYrFZas0rKkZESGsRIpZ0+cg8ijVL9FcZgvCe0OuH4yxtgZ7MOv3DiXxhQH3JC4E2UdfnkZ+WNgTBRdJ4U8oi6ft8qiHF/XG48lIgfKVywq5pfsFvAXffWG60HnBqLpxXsSF60KJDEaBU5ndOrLpYHV0J6ecsX0QfNBf9wbeUMnGCEwZgETmaX67ujG77bSQz8cpVOU+7iVTq8s95y221uhs0AKCa1auNxS1BgmaSLqRfo5v7Kc5zrtAL5RTSpNIUyyvPymt8qpY1RTiN3hBOycfZ3nSJXBIfHtPUk4A3NTvNyX8vkjC3aitUYT7YwdM4CqwxTrnhCrJT8bptxQsrjdRxYUU19FG4rSNpFyUHIPJuYj1PVRDGioyujsJwR5pdLYgSsMxAAPyuQ1lBJpbmIyKepE0lb+kHsqVVC7RgTLtFI6YHH2Nz/PSYG8Kt8nZQVqmFTpRqCGtEKAPZTjMMDzJm0IUYiG+PX1EA39HVNrWIVamzgK4e2RPFFPVGF0RqsedSaqorihpVsziqG2DJoVsojQiFBwQrH0P41hifUpNjKzSa7Y/7L1iaezIqdZA2MSysBDmvCMEylv5auYtfE+c5mfvNukPsGaXkfg9cSLVd3NZVd/2g7+xvRol2qoiupTRJw2P2UM44OXWFnNnOSrUwdYziEkfUNHNu4MVpw7mjuhKGzn/voLUuI5vR7tkMNQCOcbN4wtXrj1X39pWzaGFjCdqbS8/+xeRgpyEghPrL0WpUKgHqQiD7PoTQKS/FmZEDfK6pAGsI9NhmflpAcgq47eE/e1udEq+zjlw5UKLwwxyZF5jez5YIybA4B7qSC7U2PoFQoCMH0/Xfzz9HKZxdGfywIud3buUsoJroR6NUDGKRXMFWNGoIW8hbPubR7vuPZUmH/h8IDYVbxkzTylp04oXpxzfNMGR9RZGuu9/KxAx9lIrqnPGea75XYIjF2TOhm3xNH3KM+excDPycCLF72UoxYcOrPAsbm+8LWw0MxnW/YllGbhOQs3nlvFwX7hwz1CsonFEVd41HNRaRHE6aJQJwmEYXEs7qwsxU2o4NoY65qBaOML2l4srammoeJXBKLcjEQ/puxE8EfmNjn8mOFhRpB2HQIgvatAqB2pMOi00hrxPGc5xottP+i6QStd+HMVfrv3uqMb9e3GhbRA9JXbRk90sWbMd/ke5VnmmfMwPMsCEUpsLjtr/fNs/fVsPc/9chWaD1XO5dBAXDaCya327OzQ64TPN/7omfje5p5nO+N+CD+0e/79N7/9LHYAdxACM93znedcB85zB3y94XPPvfOESHsW//Wdrt97HggJ8Nxxe2478EaPz0M/GPirz9fO4/PIFU2sPocQ5T96DoVccUP89/lq3Ll9HnkjcbXnhm3PGcxZbfHqrIXLLE5i7nSVDQRkXt70vcF7JPpaH/iDx74/ZoMHAparBmbiwLnzOpghlIGrp+PBAKMPTl3K2BBzUNQkjESikR2JK8SFa8FsQn7WfcbaNRCHDLaFxBoJ5VVYxe7h4uIJcoAuLu4ebJ8urMADzh4FpPBhAor0qDOUTPGYaumIeVThYhlscvKiZBHFKyeH++ufNw8PKENhg2jdC7iItcXDqyYmv9BlES0hIfCKL8OS+qh28pZeAJmm1Te+Kxp2xMhsOsORA4xb2c1AzCjIVHDqOn0uRXTV4iQBsJZ3QntmavIGAmzBEHJjIF/e912vziUk7bqE4mQpfjbbBWDCAP1hBJDj8mimwX1sxhtc+Skr10qBm8KaGbpBH2QQpMYpPBQKlQLJidXEy0Ixl5flrAjpH4tSk9OXB/Ubll78eVuZkwy3kFmgDYB7juzvYsf7dHJoRnlbBov12qqZfYg6oDLQRf251Buvs7X9Nxs3mk5sWGH070N/+0FtebIXI3QHda5+3Om/4obvhh1n6CIIwAmuo82S3Weq/LA05ZmabCNT7ozVid1E/orPRdUQtwrjDBOJM3e1sEjgOj3+weiKVB+xF6pWYp8QVgrj/LuN600nNoymUaSO1Q/L+gIVL0B5BuU6nufaaF1CHWWf4otODPaBRCdQQg+x2X54zdwFExJD9RZ5tsX9Trb3tjdPMR1ymN05PtwX//QfMW8w8pmH2U/vt4+3MdH5AMQ43Pg/cOk/LPUya/JI+B/AQv9Hv0tVQm8k0ky+bo4RlF/VLF7f3Nw+OrX31g/ena2/2+ZmcFNp/LwZbaUlN4QmBLGz8DkpfAsfJlqlfNwsMF74P8hNxa1gchHRnQANfX2NtB6FEKwX8Z90AMtD76/J/Ai70JCm4kHnajREP/TbBezkjPhuY9ZdxRLaQMhhuR5PgLu2quBrCF4jzBGrlZShXQj3N7j6pG1Um06YAsAOx0EvacojUBA2+0hgqbeJc8i+d2VmGOgu9FbJYtkHwgaWURuC56JwMUIj6fgjiUkiwPQw8Ds2Q5KwSXpl2SLsvJiCSHwXTQBYubTyFyJsUQnJ6hfhV4SU6z/qqOMG4gIx3mXmyjVvBc1SWS5ajTZ4PRYiEm+/uOvHlzND/WPrWI4f5u7BMA+atC1jp/iXt8wRpUui6EA8XYmkejE6x9iX2RMv4CJyhcAW7020DnMhnFRmLP2UpJcH8ly9eIsXIiWGB8ZdORsmqu6+PxlJNadJaDTQLNV1OFZooDwllfU27kCshT8p1Lm6npTtRoEo4Y+pozURkwaymOXRv39t8YHCcZV3wf2ptpieMNmu6k0wxDveRXTe1WI7+SSTE17hKhXeaNdWTX3GuN2NF3UYhksy9XBWRSWw4G+WG0aTRVHvyxpCwXVbzaRa0USMFLibfqUemSeGCM2ZbKnORpMoTN8cwyh1VHwcG+w21uMlZRHbtuUNiIlUTAkvtMWBoweB0pP3+ZcSM6qPaVtw+8q+kSmJ/j+4jTSsdL0QHgSEIx0Xm0XKdcW6XsJcskx3gzUDRqCL3zhBJYu0S8Zicy8oYh2y3A3tIS72SO2B73aMiZjOY+KC9oxZhElT8XDkjMbhRAXgBSduZVnn8HgLCO6zG1/En//sbv0H6J23Tza5XyUpaVXMMDXnDa/uuYhMtCJ9nMabG4EP0jEkAu8bTQThwN6fWNHt+h23a1dqrnhjyfUltEYLLhVqwjuIE4u9QGuG6KI5+65Y2f5YZR5lSy43iicssbSZ2SJq4WoohMgdN6JpfbruSDNAP+xxq3WOZ4g8BtRosvYMg33tjNwJQRo9O65iMASeHWDasKzSolWlwtSNYNlaTUmwJcWs/OJU7gw7lnITQ38oWEW/CVoiCvoX+je7e3B6CPPt7BRa0ztqzcRkFMJ/isgQlyCkzGXUMvwIiYeUqTqFdAz8Zi3qJCKPkGz/57uZdQFC49Jazbvx8Ypn5WwSXT1xmqiHf10zMrwgfCyj7+jW5EtJbgv1MGR+QXadtivHoUURBAlC0egALK7hGLOym4L9bRTUoL9tvkHspSOWqo7v/IG6KUVXTrH7kVfw9y5z6xXeMFWOUoDlcrEJCKb92ZIpZpqIyKqxSzRLb9dklw7czlAJFzj2Rl9GYwwvoG9XHFDXROgW8pNwmzQPhOCOGo0EFjzEtzDfF5oV5uvKfQt1CWOkBMpCUufsT9vqOJR7kZvS30KdNUFDzfqJgjL763o+34WoYcvKFYD4/rhs/JcqKFv744JTjpd0UEZumP/ZjRQlR/QQ7AKRchuhc8VSktTglvPWPxZmfXkWGo/osGXl8l7sHA//wec1M0ON3jfDIJd0iGqWC1LO8DuY5ulF+5oRgaZPP8wibqpuiXX4pkU+lsHI4xAQ4tsYAGsetqUUIrhX8+phV8VBzr52jcKszylcFit1ZWkJE8IGihO0fxh9vIk+3kYf77h2mS3W6ja7Byfvt/f2+Lm5VIXhrr8/e4SWbTZVlc6ASaXfmoHsecdqokw4sn9yU86/DQCsj+5jeOCy2laWyQu1Fbi2quW119Y+15BnDph2dDttVwaFcxPu4gba7sw1GxLgN3lc4fzuutGX04XbFL8of4USi41CcsGOtjqCSOoj1hGsbWurUfZXZZxI3PbFWTG+IyMGsiRPCJq38of2lrioPEjjskhaUIZyIGZz/yHQBkxtzBgVx5cn76JIpGZA2SdCWBZnJsMP2xJvuF6ZXWgmq1jJDp0rGgAuV2HQp553KNIeKeINzFxCYJ8qZVoz6mO5rgyvy/Uk61nuJnCv+B5Vdt4rMHoM6QBtRSZBrlRjI8AbxuxFIwdU4fhHptLJcxXy9y+mtzqF4/dONDcqEq6usbTBVSPG05hsBMCCzwpcxk1RjsOakdYPnsZPyCV2YcpoM9RLng1jCvv6oBv4XtecJ29aLZkIkIRw0rLsihmLdlopgRHQhONOetlasoaHXRa/cqUiy9Op3k28mXRxxnSKKnFVL6b34cwReP4YT7dewMOHsBXAWU/VpOHNZvNu6HEFVObIPesNzKInG5u7W3LWoF4nN0+uW+XXLt5nT1orJ/YuTiKEAdx+cK0+D9xRNIMQfwLPtRE4P0AhhJT3t8qn2SSoSYVkrA4W1kLIyFtC/hZ9AkQXpclaXplTB/14puKoite5jVWJOWq5g0hQLPrH6FqUPqCvYAZ6bRKSeNZY0YT23Ld//DAUHvqJW1ZAlYgZi1cFwH3VDAv5JhloVsG/zCSXqz+tjGDLDN0ZgSq1OnoEbHguu+f1IylWwHtoQZ9vKBb1SIz/e2cglkuwuIi7itgtucUiH/TW9MjLCTGBYKWb6OMo8eMwmj6IMhFngN1AdCGaNbXIDxdsjK+u9ly5zvxAeXnON+0t0e/HoXqwq8DVU10i4FeaM2OAF6TGKFVrfD9pJUVCGdjGkfHKmo2PFIgYL7QBAa5uc9XrGk3T2+aGq/wgeuo0mp/+At5D/bDESgrapzXhZVJLRsKR2AhjsxmBH4DUHPVvnGH7R8cNrnizQTwHmoqm2vjWt/Z3D4Tc2No9ts+O93hqyUnIWtQIndesQCPkA/Z6PXwYXA3L8ivB3qMdQDmtVc+/J6jnFoWjF/kuaIgFGH4cbcpSRG/uIbm5aAmJ92emKv+t5oyLo/7QNmVT8i07/vDxt25Dz41gFYySn6HXQWc1sfOGWJuTwkQ2pthgY0F9OFXP5A0Ql4IJ0lcTcri/2uMJgf0bw8OWAbcDjCuPKqkEqBUQwBAmBTr/i12CHxLD9JuTx3kwuGpfTYW3LnGkYNsIW+RI/T52g0dN41IGRxAn0m//n3s4O3T9a9vvde1C9T+6GVsy2DcRsAOByNY/MrlGmBfDfVFYaCLzylz82wyiebgoerCs1U7Lmin+NRR/S9wsCpxS8tkamPXFQo1AGvvOrWsCNOYTiyE5WVSObyWhp4pjcOZqgjXUt3K3JPW5Up3Vdk39ZkJfqC9mnST8/+Zy7AfVa7BNGtR6JkrDjL8qS6LapxN/XdDtBwU1NSS3EGVszubFf5yxOQtWqQUAKMG/hQoqA9kFztPbRHRMxcRxTgGJDzuDUc++EidYrop5hYXGIZYns+7O4u5ti21VYm3n5pHsar6K/+Y6EKcz04E4KBlW15UPgZAXiG2lg/Ot+ziRwxfG9dgJ1fuF75R3Vomp6LeLWBX5vhEcgydY7ZkjDwHWukH1QW4c07Xq37KUEQtavWHuMgk7iQQFvYLOM63YljSFkdxjodeaKvOgwGsCb1LY8RMgC2TZfACId0K+PdotNw5PN4+/HJ3a++uf7ZPdr9uyh0GnYlbijRg0n1upoCE4B/D1cDFS5YEeDDjC8J/Tm3G/LSRHt52JaUNPFjFWewPgnyWkjR7igdsB3wjBOyAXFTFvOG5rOqmGktNkLHaZW5BRthTeIS+j0UEdfrkoHSoJKeACn1kuH8mSpsRjg7yJjubMp7LcXtny8WDUQiCoeMnidjgnFV6nScReZW0dz4ghteBgaex1jtezR77+avG4mVw67I+GtrjXnW4G+nkNSAjGvSqxj5yN2KJXY8c4DD86kBClreMM+DhsscLGLZX5lAinr01Q6XePDoVQc0YQn6gbL0MQ8n38jZddU4b+QqbhKG6eWYFnQPmwxSUVOdVsyrhtTf47g/DeDVqY9Ex7c7h1lKTxxtI4O6yHeh34WfFPlYvXGTTBL6mLvDF232/D2+y6d16HWSt5LtMhhSs35BFjNzy1crvy5+aSJGbtuSMCQLdMRSCauOvHx+tfkIcDvN7ftJ1SLDX4CbaP6EdqEO4DrBC8IceiZ2Xj+NAz/dh2pcsJdLuDmCk8FIoTUm1Pjqq4VVGqFDPD6Gl4AqHabsyhJ+sPfXpS14eYpQDOvyWaB6JZ8othu2hGca4jZvtpJnzr+Qxwi5aVo7zn1qJ4BCtMgQPQek4y5qsuRPfg+5cZgUeE8rNp6w9UGq7gDH740bIGQLeueluR8umSBRl0U0cvmPZlvCVtAk/cAlpHAB1yGR3XPANSZJ4I44cSaeTi5mrKskN8+ELx9Tu3qfTR8e75/sm7FHLII5EdV0BHOW0Ws+AKEWNH19+gH9Vag3+4NnxctHL98PoKSNJEF3KkLc7Jp0FpC5n4LhZgSLLMbkSqF4Rsdrkg2omBaATSjf9B5tNsp9+NBsGa0UCd+ngsLKxQI4QkAdNDZBAL/P6iPu80ynz1G6B+4+p7Tn1JaXWjH5dfbRFyoCa3tsLZC9SxWXS7yPA9Y9MzTvk7416P2SKjfXO919uaUojmMloDsbTcVuUdMbymkbBWVWP/fsUiHCXysKEvw8ZIOlU9v+ykwBDdSltWHnyjlrX6vYXTJ2sBXeDFX9YzrKFs3ov8o/Mp4DK9drVxFvNEG2Yo0PMGt6HqCprR0dQYZSuXn5VPg2qbHnW4Bo4Ruw2pweXRy5qhD7J5qVjx4srS4tJ97Qe7mx+1CRQCEQOUAwOh/BZdnpwacqsyFxwRT1qhlZVLjovX2ZyIx8Zxb7Rzthe9X2/Y0T3IlqbHakuBq8U7gg6k2u9FrkR6r44Q1dfFb+njv9JgGI1FUyJ+1KpaW9XUw9+4LTVYKkgfIVtgp54w2K0FfqC4a+u3Dh/inkVWrONHnSu5yieAAb93G/VwpYkzggmxgG8hKhuaqjFy+45lIHjiiVyApJHvAGKBJtD1D5UqKNEtaKr0UJ6atZ3gmhursEU4wW6UZN93e96VPk2iK9JKxO1WWWDohmZSks1dhEVERDyvaR90GDPPety8NJBCrp/sJ7d97PunfAlPNmh0PjwERqnDQkExk5F19hBJscgv0EKNrNiuVgrSBcDtNJZkmCi8MqVZTi71B5sKaOPCTSBLXV2X35Khd5ZUf+v52vevxVg/i0OA2O9Ro9JQeYoZUXOuUduIeagoLR3Sl1/R62vpA7Y7Cg9vrZiBWdQuMtLxCuSsDva2ZlizWO92A6LLhf6UqlyxJLWqGBU3vVvOujr0YlZu45hkzRztHnBzZVaScC+ZmBVgXKQWve7ERpNnpnMg8eDWKmzNuVLv6nvUlBN91JAUD1xV0n/wskV3FKqbs78tAgiPAAGUUdDZ0fsj+/BE3rZzQ4uSyxM/0pTDRVyxbhOpguHxf6Yj+rOuxhtfEPfcdjq3z8rf+0w+qGclNp5D3H2vnnXOHSZveMbzlD8qlp/FyDyT7n3v9G6f9dBzXpyIkaCs0bT6Q+t38UnRlOIWJtYW4iHgJslx16p80cqNHgwcP4yiNNTFtm+GywdjlmIIlwBkycSu0btXsvuqpwkmRE1QIH/4GNpDJ3D68vETIIhcqSQPOzPiNbm0Q3AdSSOJhyNl2IUiPU8cueVtYR1VC0mjMXtyvimW6t6OvoDysGycTke8YW6gwlIzPgXV/KM7+8ORdVGMiEf5l4p8LYiFAGInRTKcRaqeaJswyYZ1jQ5C09X3b6ggLowNYN/Kcp4RG3y3Gtugzo73wLYRyUIQrkvwcVUWrUsk1B+w2bPPIhzCgRc4rLkUamcNWWokzjPELO/z5ku0MuJVYQJjACsP18G0fOx+HfdYNFelQUscPmDeYLwBmHrFGQPPL/fDBaaYCPN3YnIjnoRDWbgJKZ/h8Bh523VMBLqamJtLUqCLiohyb6Jd73LpRWPP0E60NpctR4rd7Jo1c+eIlToL07PvXHsdG3OXhPb1sCMd6hMASjBpBZ6chVUZvQzCST/WzTJYF7y1SLHB5atKy8aFosSE/IY+yhkxOLoio67CjGSmU/WrbFlGzgsZCHHkgR3ejEfgdtFmtr6ZgMvZdgahLaEwog0ZOR9nbJhQAOwFrtHgs7c57LHSSQGll9JeJxpBYymMIiVjZONUtIA0+yVkODKvQsuvXRc3f+0ySFujV0vUqZqE2iTkm5e75BWGkgj5LvdBRBsAPkWiHSOpzFQlOQnCERvQtSbjYU5f+eKdENxLNFVi+da5GQ9uGWk5a6rKs4QbmAU70MxTTOFBKAJpc2IiRWJm+aa4UimUKR9O2+t23cFyXvyG1hOxFfi37mCRm5CzW+GuOTgZH0sPR+byygA1Y5yygHwFaatfKIEDy9HpZbi5Gm8SMkun0Ev9cBOBBqiAgqkEDu7Rrz1P6PShN+IJjdABzNY7M2qJcSBl2NfUM/gPfkXaOyFFgfJuxlsWI9bD7PUzIyS+YU7iJ1WfQAzishh5T454gxXUfp/QHbPs9kih8Rz+8e7gb5fQH6lWCtN+cm3pMhgN3GvHhtO0PRyNeDqgR10IuVHo3+g/F/lUcLx9vL0j9OWj09P3fKnE1sd7t+1ZuWCchw94zgnzcPjoeW3KQI+l0d4uphvJHZtJ/6RSrkVG4322j7kazpB65BVNBS4mjBHi80kehNISbsN1JBeI179OyR3QB9s+nE9ywwEf1CgzWE1Z5afgpRDvM6EsobsWpq577uyh4ONFC8fNExJum/6WKzVSdNOaxwOYbkRhjR+K9MmG/+AP75+Up6tJdsPWSrQULYsV7YaUJJN5S3JnpzuWtdBYtGbRFJM7C3nmUvoq8T4WF7ExWGhy48REavDrIq9T4g4QhdfEq3Odvh0iJYnd6Xlgwo6E0KgDcF3yZ4lqZd76W62CeF3fQn/w9xjz9MoCFX4DPcToGkcaXfcIXLHRC+nOUUVcuSq9ZewZnnEHYtjcEP5cwZ+e3ADQB1jWba+5TmT2VHuhaOKufT3PderceWCgiZLp9J2+wwVQJwdolNAwCUYJk1Rtgk5Ek64k0m8ee9DLx+6u6MWCCxpD+qXLetCN7gBHN80GIi0cFH5f5t0mAXGcF6oKRplz+SKjEcgJJvUlfAZdZRLNUeg9Lwt00JXiKIYtzxk6oVyf6HoDLaDv3LpgS7bBYcb2EdJVRjf2N9/v93io0eEGvQEF3Rtc22hqhcIDf0QuLuY2eOyDkdVlyz363cCug4q9OmpwSjy2EhNZDgNvyOsssR5uB0GC3FiN9zuDchQ2TMnKoY4ChFUbB4xr5jy9ogk0pBi5CLOoJg29jnSoWaHufneicx5NGG6owRshHHvZmoU6MUEUQkrlR18wvv1S6opD/96arVX4IYvcXJOBQGylfFKw69gmyk1irSI68EA3U2jHRS8Eu/6nSEMP326jKrH9MOwJ7SPAlH60l3Ij5Gdmap+TG2STktfQvyZuIPsDsi8s8UUpXOS1sFTkIlygwlPx2Ol/vfUAZCT0j6wLPfFGXKbKOyq8NsqWZ9NxSEZRoYecJQz8dIyFuLY8K8E06NyCAgdmHnuoJwrjonWWoDDHxGEQIuHBOQNzaTwYokdF+3o14GoyHnstISeV083LjjTZlbXcFhvE2GOo5wyZ/+aW822SmUWOZ15M7zyUmu/QThbwFYxNEKM5uPOCwoDvX5RB+doICPUJD6906CWfZoy7lSuXeXiEKMeDt5EKU5flRXSGQL/CswdImije0zlfwegX0YNPTrCBZE1chC/jHl6WaQChM50uE2YsddCZkl04ZEcGjLD4iWvWWR3aEBrUnVfRk9KIq8jYVQOybo2WUbEzo+gTQxjeAHEAVyFU82L6dPzZPrlxxNGILqBxHt59ay2KcIEWQOXNCU0+5vOV1Yqkke25becxemKyhldNU5DUFn+XuMvdFwraelfFbPFsLUlWrbZ/jUxooLgbCweN3LAzWRf0Ri/1je61zNbWRZ5rcEtVdiMxX2QR9B/KZwhkuU9GSmdRvMYyAZbKIv7Ji//xxTq3pcnX/c09NGrOKqnKyatEcTxcAt0OaBroCnt0ceEvpTCIGel6o4sDX7/28sKtSOEJeA+c6qSf2XLK2ZzF1tY2yiIZm8lAheafFqqpbUzD50mSF2um0wrd3tXiYqfI9aQZQzN+qJxuV/z9frig0XlwxRJba0heksDjhLfKRF9E67Hm1JmNbQDzaaF2bgud8mFjA/7spMUMFvdiu/p1+1bJhvHoaqGRz+++Ozg83iZz1wyQRPONJMpTiwC27XCMBjQVAcdKzYF/fzJu7/g9Nd0tGSunanCzVfYP+G2VlRlFjZbQ1bBM8vlafWHlRn3HBcNtS7yCPLSkVRwlpqfJpP4vhSIktcsVZEwcjC9gtMThdFYlwJCupdkE0Yn2XjjCMBIs/hr4VFFEky0a1zA1escNWplj9+vH0t4eFUBzK6zk5T8tGY0hVI7vYzfklUzm1SIyJ9pSqwGNpkSYU3P5VSSlEh36Db1UyIIR8r5KqyoI/jSNozhtSstHkZjq0Zht204rbTxZmmOsban5mLcwy+JNJn+i6up20oWBBoj7p3LpZWFhRcG21oyZsgaGldCVY1PVbIaR9QkNMlD7UiGrFKMSV4w0g1D0+v+si64XdsY/rMv/cyEHAs5ALipxv0e96xOkXfgsDhTuoOsE793ekFWm3YHo44DAXFyvwbot4THsiZyJGQiAhVOTHzxGhk2WgbzqinKMmiw4p5nZbLsdRtOzKo34MXMRBIkMwLes2Ua5hjxuyuGDRpkOUsq+wufPXFhm8RDDimuexdpQNB8K3QltRPbZwdfdo53dY9FFyPLLVctLKgyVtOAQWZLJ02LNZsRPYpSEcAxEv78Hw/Z3VoDI0sqW02vlmyQ+0fWtw60N+wh/V2+AgsXQLTq68cKFFUI2arqfHr6ai5WiR/L613nAl3CLNcMDKRbQr0M2RW00RlUSLYpx+YEyMSZSZI9D0eVuz8p1A3/Y9h/gTtxQZNYvVmWAJMwY/VApbiXGDLE+8en2Ns0UMymW2txUk2WKtmt/FOfKfVfbtMdAP3uL+sT+IxwyDliPpDYosKuopzECYCVIDnG+w7zm2/b28fHhMWueM6DtYx5xIOTlF8VtFXn68SKZUFvXZGeiXBG8jmrS7cT0ssquqUwZxEyEV9mZopPLihbQqlrjkx0Edc3iTJbwBtSl/sEnALzsnAqyA/vHXdSRilpv90PbvodACPrAyyGK6BCFq7yLaEnIuBYXkNmEYkmi2AxFaFRRDOkhysmnFQXAkxR7kqPgNzAnRbSAlkpqfD+V98SMdGND2GQfiJlDBA9XEiYidW2ZB29OO3MztxcChuVRn1pGIylEw6E5XVxXtOZitXXuu5HlLG+uLZVvL8rm/KKffyjcKMqPSBJj3LnygnAksdc8BkSGq78tSmf96eSQC5T53cfjLmbTnWbTBv8/+DO5sDwllx+GxaAs2tl8bKMQWw/6rKvVZTR2gmD5P2uCf5srSVl24z504WwmjWzSzKpHPMuI3LNjVp3QvAq+aDgo0yKNjHROO/R74xHaXeYL8xGU17gARJMdpkydiyjobX8g531d6v86NFXLYSmOJJjJB6JQIrRJOl9rWrlKycpxK03ewPX8CK9qC1SvIZNw42Qy62gYIa+veSVB6e+3osnGLRXZuIdpWoRU+XDy5eTwaPt4/XT38MA+gQDWMLwXwoTLKwKMuaUYz/1MvwMeBSuRWJ1rl7nf9Lwpym/P8WfWXAqPS+nl4Yr6cTk/FPM8FUsdL1qqsLx4LQePWpFJqXhgaGLZeGi05vkOROas1tWOc+ueCN1KWj0oOAQ1DTBKWVNRBagUX/PatlYJERQdUIwOmXTHyuNXRIsybJnL6PVVskPBUSArNxmG8DZtT8iuB6EiiCEM815bTOdb3qLQ9lwj2k8PzX4oISQuCGyXBMrPEeqUWuQkPfJeUKbIKVpFk+QeKkUZxqsv0K76fNnSt6TkImKS/vNKgT9jZeeWogBwdWXpZRh4d+JklIJwY6+TMlVrtGSb2MlEoB26uZ0f94497Hm36kCnxTPx6kFTd7mmtgsWMkC1ejIKyMyVhwopMXG4SomHX/l8yHa4cbiP3+yk+SMk6tEuRw/HObZEk0hwVTNGP+EApIwoo6KlY5jw9WpZXec1Oy1azzFg821+ovVf34HJ9hvVVjOHrOxIN4n+ZR78Y2fQ9fsHY8AVULgc7WJqnwXGGWW7EnOLW6ux5FernS1wtm5mB53IGdF6U7S98sF1Az0a0SkLFzbAN6lLCWis++TXpmnyXFvl8rVmxMnDpFPEnxZW2MPHTmBTGfjhydc0mWHabK9FIRqYvFeNXKw4nChiAr4pITUrbAYSExTkCgBnB8tYpkTW+yKRLU2FKKmp9OFk3N53B+NoypbQdE9IQ9xFjv17oV7JbG7ab3O6YEJPO3sXkZ94iVsrcWtH4J3JYZoDoQ5YOXm4TONBCU4jxF0qnvYv3C4urD+Q1TKIBHsJvQMYSjoQFSAfxQ85G+gUBmdqEKxbuLd1T8Ukw+vJeLISZR/HaJF/SQMtnW0IgI4TO0YsdREODKwoEMEAm+ZfRUvzJpTQbYH8xf9lZ9BORxjh7IKjJuUq3wZ3RyRI0iIS/zv+tSTmZr5bnW0mdGIyN9j70I+Wb6kggcR6dDI/hpULQyEmsit43BIqRV58F4InlP9yE6i1VaO0EHH2pfsb3+l7Rl/luKAXBYYf6ZTE6vOHmnexI+Hvm0LWHx6daoQRESiIxAm5IhetrkkVx+sLXTJokWhr/jglPmNmM6xBKSs5Qgp1DDvKUTShcxvJ2jXofMxUQPuU+WtrwjFIlAuFebX+Y60sFBE/xx1F1xBRmpXQZa25V7hIZUli8vtdd8QAzojbA6x5W64Eo7GlYIvAT3Aa8rpiFYeL3FiVXZXiWMsHf6F5BJ4rdgXQiXB8omuIrMKHJswkN4KuBwDD/FYQw8QGoEabFYAluanLL9omPavPBxns+S20vcGVq7MskRofuADhIEEHagOCuriyxJ+w+xsl8JhcT/iZntTK+cF13njqJr8qimAXwyVkY79rh8pZVipJAMqTFt8qNhh+KHnk5Y8vXEk6MtTcFvrAMb5O9pvzb+/cgRtE8J5SScYAM+cWPP4EnnDoBASqxQGV+BHU63ypkJco7KP5SyY/ei9YbGGFdhpEIVBM12zUpvRkai5rvoKuiSJlibgnup4J/Q6G7M8/tw7313cP/vzT2IHRFmD37npMfcetSpopZa699uH/2M9UKknIZYKdTgwL7vqoDMu4yBJ6xSh/OG2V3xGzMwGD5tJNtlcRFE3t8932wgrJKaD9J3OvmvgvSlrKYaNM0KhLDCQjkFiFICc7GNpKpYrsgQH1PBx1hCoP2ByitqMvgLEbRs2WliR2vMTEIIGLni3GkRNLiHiPYLVupZde/l8=")));
$gX_FlexDBShe = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$g_ExceptFlex = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$g_AdwareSig = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$g_PhishingSig = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$g_JSVirSig = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1542619322*/base64_decode("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")));
$g_SusDB = unserialize(gzinflate(/*1542619322*/base64_decode("S7QysKquBQA=")));
$g_SusDBPrio = unserialize(gzinflate(/*1542619322*/base64_decode("S7QysKquBQA=")));
$g_Mnemo = @array_flip(unserialize(gzinflate(/*1542619322*/base64_decode("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"))));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
    echo "#####################################################\n";
    echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
    echo "#                                                   #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
    echo "#####################################################\n";
    echo "# Warning: PHP Version < 5.3.1                      #\n";
    echo "# Some function might not work properly             #\n";
    echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
    echo "#####################################################\n";
    exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
    echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";
    exit;
}

define('AI_VERSION', '20181117-2210');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_Structure = array();
$g_Counter   = 0;

$g_SpecificExt = false;

$g_UpdatedJsonLog    = 0;
$g_NotRead           = array();
$g_FileInfo          = array();
$g_Iframer           = array();
$g_PHPCodeInside     = array();
$g_CriticalJS        = array();
$g_Phishing          = array();
$g_Base64            = array();
$g_HeuristicDetected = array();
$g_HeuristicType     = array();
$g_UnixExec          = array();
$g_SkippedFolders    = array();
$g_UnsafeFilesFound  = array();
$g_CMS               = array();
$g_SymLinks          = array();
$g_HiddenFiles       = array();
$g_Vulnerable        = array();

$g_RegExpStat = array();

$g_TotalFolder = 0;
$g_TotalFiles  = 0;

$g_FoundTotalDirs  = 0;
$g_FoundTotalFiles = 0;

if (!isCli()) {
    $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/';
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 - 2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size', '16M');
ini_set('realpath_cache_ttl', '1200');
ini_set('pcre.backtrack_limit', '1000000');
ini_set('pcre.recursion_limit', '200000');
ini_set('pcre.jit', '1');

if (!function_exists('stripos')) {
    function stripos($par_Str, $par_Entry, $Offset = 0) {
        return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
define('CMS_BITRIX', 'Bitrix');
define('CMS_WORDPRESS', 'WordPress');
define('CMS_JOOMLA', 'Joomla');
define('CMS_DLE', 'Data Life Engine');
define('CMS_IPB', 'Invision Power Board');
define('CMS_WEBASYST', 'WebAsyst');
define('CMS_OSCOMMERCE', 'OsCommerce');
define('CMS_DRUPAL', 'Drupal');
define('CMS_MODX', 'MODX');
define('CMS_INSTANTCMS', 'Instant CMS');
define('CMS_PHPBB', 'PhpBB');
define('CMS_VBULLETIN', 'vBulletin');
define('CMS_SHOPSCRIPT', 'PHP ShopScript Premium');

define('CMS_VERSION_UNDEFINED', '0.0');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class CmsVersionDetector {
    private $root_path;
    private $versions;
    private $types;
    
    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions  = array();
        $this->types     = array();
        
        $version = '';
        
        $dir_list   = $this->getDirList($root_path);
        $dir_list[] = $root_path;
        
        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
                $this->addCms(CMS_BITRIX, $version);
            }
            
            if ($this->checkWordpress($dir, $version)) {
                $this->addCms(CMS_WORDPRESS, $version);
            }
            
            if ($this->checkJoomla($dir, $version)) {
                $this->addCms(CMS_JOOMLA, $version);
            }
            
            if ($this->checkDle($dir, $version)) {
                $this->addCms(CMS_DLE, $version);
            }
            
            if ($this->checkIpb($dir, $version)) {
                $this->addCms(CMS_IPB, $version);
            }
            
            if ($this->checkWebAsyst($dir, $version)) {
                $this->addCms(CMS_WEBASYST, $version);
            }
            
            if ($this->checkOsCommerce($dir, $version)) {
                $this->addCms(CMS_OSCOMMERCE, $version);
            }
            
            if ($this->checkDrupal($dir, $version)) {
                $this->addCms(CMS_DRUPAL, $version);
            }
            
            if ($this->checkMODX($dir, $version)) {
                $this->addCms(CMS_MODX, $version);
            }
            
            if ($this->checkInstantCms($dir, $version)) {
                $this->addCms(CMS_INSTANTCMS, $version);
            }
            
            if ($this->checkPhpBb($dir, $version)) {
                $this->addCms(CMS_PHPBB, $version);
            }
            
            if ($this->checkVBulletin($dir, $version)) {
                $this->addCms(CMS_VBULLETIN, $version);
            }
            
            if ($this->checkPhpShopScript($dir, $version)) {
                $this->addCms(CMS_SHOPSCRIPT, $version);
            }
            
        }
    }
    
    function getDirList($target) {
        $remove      = array(
            '.',
            '..'
        );
        $directories = array_diff(scandir($target), $remove);
        
        $res = array();
        
        foreach ($directories as $value) {
            if (is_dir($target . '/' . $value)) {
                $res[] = $target . '/' . $value;
            }
        }
        
        return $res;
    }
    
    function isCms($name, $version) {
        for ($i = 0; $i < count($this->types); $i++) {
            if ((strpos($this->types[$i], $name) !== false) && (strpos($this->versions[$i], $version) !== false)) {
                return true;
            }
        }
        
        return false;
    }
    
    function getCmsList() {
        return $this->types;
    }
    
    function getCmsVersions() {
        return $this->versions;
    }
    
    function getCmsNumber() {
        return count($this->types);
    }
    
    function getCmsName($index = 0) {
        return $this->types[$index];
    }
    
    function getCmsVersion($index = 0) {
        return $this->versions[$index];
    }
    
    private function addCms($type, $version) {
        $this->types[]    = $type;
        $this->versions[] = $version;
    }
    
    private function checkBitrix($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/bitrix')) {
            $res = true;
            
            $tmp_content = @file_get_contents($this->root_path . '/bitrix/modules/main/classes/general/version.php');
            if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWordpress($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wp-admin')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/wp-includes/version.php');
            if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
        }
        
        return $res;
    }
    
    private function checkJoomla($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/libraries/joomla')) {
            $res = true;
            
            // for 1.5.x
            $tmp_content = @file_get_contents($dir . '/libraries/joomla/version.php');
            if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            // for 1.7.x
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
            
            // for 2.5.x and 3.x 
            $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');
            
            if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
                
                if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                    $version .= '.' . $tmp_ver[1];
                }
            }
            
        }
        
        return $res;
    }
    
    private function checkDle($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/engine/engine.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
            $tmp_content = @file_get_contents($dir . '/install.php');
            if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkIpb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/ips_kernel')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
            if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkWebAsyst($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/wbs/installer')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/license.txt');
            if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkOsCommerce($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/version.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/includes/version.php');
            if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkDrupal($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/sites/all')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
            if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . '/core/lib/Drupal.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/core/lib/Drupal.php');
            if (preg_match('|VERSION\s*=\s*\'(\d+\.\d+\.\d+)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        if (file_exists($dir . 'modules/system/system.info')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . 'modules/system/system.info');
            if (preg_match('|version\s*=\s*"\d+\.\d+"|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkMODX($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/manager/assets')) {
            $res = true;
            
            // no way to pick up version
        }
        
        return $res;
    }
    
    private function checkInstantCms($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/plugins/p_usertab')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/index.php');
            if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkPhpBb($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/includes/acp')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/config.php');
            if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
    
    private function checkVBulletin($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        if (file_exists($dir . '/core/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/core/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vb5_connect'];
        } else if (file_exists($dir . '/includes/md5_sums_vbulletin.php')) {
            $res = true;
            require_once($dir . '/includes/md5_sums_vbulletin.php');
            $version = $md5_sum_versions['vbulletin'];
        }
        return $res;
    }
    
    private function checkPhpShopScript($dir, &$version) {
        $version = CMS_VERSION_UNDEFINED;
        $res     = false;
        
        if (file_exists($dir . '/install/consts.php')) {
            $res = true;
            
            $tmp_content = @file_get_contents($dir . '/install/consts.php');
            if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version = $tmp_ver[1];
            }
            
        }
        
        return $res;
    }
}

/**
 * Print file
 */
function printFile() {
    die("Not Supported");
 
    $l_FileName = $_GET['fn'];
    $l_CRC      = isset($_GET['c']) ? (int) $_GET['c'] : 0;
    $l_Content  = file_get_contents($l_FileName);
    $l_FileCRC  = realCRC($l_Content);
    if ($l_FileCRC != $l_CRC) {
        echo 'Доступ запрещен.';
        exit;
    }
    
    echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false) {
    $in = crc32($full ? normal($str_in) : $str_in);
    return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli() {
    return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
    return hash('crc32b', $str);
}

function generatePassword($length = 9) {
    
    // start with a blank password
    $password = "";
    
    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";
    
    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);
    
    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
        $length = $maxlength;
    }
    
    // set up a counter for how many characters are in the password so far
    $i = 0;
    
    // add random characters to $password until $length is reached
    while ($i < $length) {
        
        // pick a random character from the possible ones
        $char = substr($possible, mt_rand(0, $maxlength - 1), 1);
        
        // have we already used this character in $password?
        if (!strstr($password, $char)) {
            // no, so it's OK to add it onto the end of whatever we've already got...
            $password .= $char;
            // ... and increase the counter by one
            $i++;
        }
        
    }
    
    // done!
    return $password;
    
}

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true) {
    if (!isCli())
        return;
    
    if (is_bool($text)) {
        $text = $text ? 'true' : 'false';
    } else if (is_null($text)) {
        $text = 'null';
    }
    if (!is_scalar($text)) {
        $text = print_r($text, true);
    }
    
    if ((!BOOL_RESULT) && (!JSON_STDOUT)) {
        @fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
    }
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File) {
    global $g_CriticalPHP, $g_Base64, $g_Phishing, $g_CriticalJS, $g_Iframer, $g_UpdatedJsonLog, $g_AddPrefix, $g_NoPrefix;
    
    $total_files  = $GLOBALS['g_FoundTotalFiles'];
    $elapsed_time = microtime(true) - START_TIME;
    $percent      = number_format($total_files ? $num * 100 / $total_files : 0, 1);
    $stat         = '';
    if ($elapsed_time >= 1) {
        $elapsed_seconds = round($elapsed_time, 0);
        $fs              = floor($num / $elapsed_seconds);
        $left_files      = $total_files - $num;
        if ($fs > 0) {
            $left_time = ($left_files / $fs); //ceil($left_files / $fs);
            $stat      = ' [Avg: ' . round($fs, 2) . ' files/s' . ($left_time > 0 ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($g_CriticalPHP) + count($g_Base64)) . '|' . (count($g_CriticalJS) + count($g_Iframer) + count($g_Phishing)) . ']';
        }
    }
    
    $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File);
    $l_FN = substr($par_File, -60);
    
    $text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
    $text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
    stdOut(str_repeat(chr(8), 160) . $text, false);
    
    
    $data = array(
        'self' => __FILE__,
        'started' => AIBOLIT_START_TIME,
        'updated' => time(),
        'progress' => $percent,
        'time_elapsed' => $elapsed_seconds,
        'time_left' => round($left_time),
        'files_left' => $left_files,
        'files_total' => $total_files,
        'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160)
    );
    
    if (function_exists('aibolit_onProgressUpdate')) {
        aibolit_onProgressUpdate($data);
    }
    
    if (defined('PROGRESS_LOG_FILE') && (time() - $g_UpdatedJsonLog > 1)) {
        if (function_exists('json_encode')) {
            file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
        } else {
            file_put_contents(PROGRESS_LOG_FILE, serialize($data));
        }
        
        $g_UpdatedJsonLog = time();
    }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds) {
    $r        = '';
    $_seconds = floor($seconds);
    $ms       = $seconds - $_seconds;
    $seconds  = $_seconds;
    if ($hours = floor($seconds / 3600)) {
        $r .= $hours . (isCli() ? ' h ' : ' час ');
        $seconds = $seconds % 3600;
    }
    
    if ($minutes = floor($seconds / 60)) {
        $r .= $minutes . (isCli() ? ' m ' : ' мин ');
        $seconds = $seconds % 60;
    }
    
    if ($minutes < 3)
        $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек');
    
    return $r;
}

if (isCli()) {
    
    $cli_options = array(
        'y' => 'deobfuscate',
        'c:' => 'avdb:',
        'm:' => 'memory:',
        's:' => 'size:',
        'a' => 'all',
        'd:' => 'delay:',
        'l:' => 'list:',
        'r:' => 'report:',
        'f' => 'fast',
        'j:' => 'file:',
        'p:' => 'path:',
        'q' => 'quite',
        'e:' => 'cms:',
        'x:' => 'mode:',
        'k:' => 'skip:',
        'i:' => 'idb:',
        'n' => 'sc',
        'o:' => 'json_report:',
        't:' => 'php_report:',
        'z:' => 'progress:',
        'g:' => 'handler:',
        'b' => 'smart',
        'u:' => 'username:',
        'h' => 'help'
    );
    
    $cli_longopts = array(
        'deobfuscate',
        'avdb:',
        'cmd:',
        'noprefix:',
        'addprefix:',
        'scan:',
        'one-pass',
        'smart',
        'quarantine',
        'with-2check',
        'skip-cache',
        'username:',
        'imake',
        'icheck',
        'no-html',
        'json-stdout', 
        'listing:'
    );
    
    $cli_longopts = array_merge($cli_longopts, array_values($cli_options));
    
    $options = getopt(implode('', array_keys($cli_options)), $cli_longopts);
    
    if (isset($options['h']) OR isset($options['help'])) {
        $memory_limit = ini_get('memory_limit');
        echo <<<HELP
Revisium AI-Bolit - an Intelligent Malware File Scanner for Websites.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE      		Full path to single file to check
  -p, --path=PATH      		Directory path to scan, by default the file directory is used
                       		Current path: {$defaults['path']}
  -p, --listing=FILE      	Scan files from the listing. E.g. --listing=/tmp/myfilelist.txt
                                Use --listing=stdin to get listing from stdin stream
  -x, --mode=INT       		Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...   		Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...   		Scan only specific extensions. E.g. --scan=php,htaccess,js

  -r, --report=PATH
  -o, --json_report=FILE	Full path to create json-file with a list of found malware
  -l, --list=FILE      		Full path to create plain text file with a list of found malware
      --no-html                 Disable HTML report

      --smart                   Enable smart mode (skip cache files and optimize scanning)
  -m, --memory=SIZE    		Maximum amount of memory a script may consume. Current value: $memory_limit
                       		Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE      		Scan files are smaller than SIZE. 0 - All files. Current value: {$defaults['max_size_to_scan']}
  -d, --delay=INT      		Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -a, --all            		Scan all files (by default scan. js,. php,. html,. htaccess)
      --one-pass       		Do not calculate remaining time
      --quarantine     		Archive all malware from report
      --with-2check    		Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file	   	Integrity Check database file

  -z, --progress=FILE  		Runtime progress of scanning, saved to the file, full path required. 
  -u, --username=<username>  	Run scanner with specific user id and group id, e.g. --username=www-data
  -g, --hander=FILE    		External php handler for different events, full path to php file required.
      --cmd="command [args...]"	Run command after scanning

      --help           		Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
        exit;
    }
    
    $l_FastCli = false;

    if ((isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory'])) OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))) {
        $memory = getBytes($memory);
        if ($memory > 0) {
            $defaults['memory_limit'] = $memory;
            ini_set('memory_limit', $memory);
        }
    }
    
    
    $avdb = '';
    if ((isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb'])) OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))) {
        if (file_exists($avdb)) {
            $defaults['avdb'] = $avdb;
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)) {
        define('SCAN_FILE', $file);
    }
    
    
    if (isset($options['deobfuscate']) OR isset($options['y'])) {
        define('AI_DEOBFUSCATE', true);
    }
    
    if ((isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false) OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)) {
        
        define('PLAIN_FILE', $file);
    }
    
    if ((isset($options['listing']) AND !empty($options['listing']) AND ($listing = $options['listing']) !== false)) {
        
        if (file_exists($listing) && is_file($listing) && is_readable($listing)) {
            define('LISTING_FILE', $listing);
        }

        if ($listing == 'stdin') {
            define('LISTING_FILE', $listing);
        }
    }
    
    if ((isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false) OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)) {
        define('JSON_FILE', $file);

        if (!function_exists('json_encode')) {
           die('json_encode function is not available. Enable json extension in php.ini');
        }
    }
    
    if ((isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false) OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)) {
        define('PHP_FILE', $file);
    }
    
    if (isset($options['smart']) OR isset($options['b'])) {
        define('SMART_SCAN', 1);
    }
    
    if ((isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false) OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)) {
        if (file_exists($file)) {
            define('AIBOLIT_EXTERNAL_HANDLER', $file);
        }
    }
    
    if ((isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false) OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)) {
        define('PROGRESS_LOG_FILE', $file);
    }
    
    if ((isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false) OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)) {
        $size                         = getBytes($size);
        $defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
    }
    
    if ((isset($options['username']) AND !empty($options['username']) AND ($username = $options['username']) !== false) OR (isset($options['u']) AND !empty($options['u']) AND ($username = $options['u']) !== false)) {
        
        if (!empty($username) && ($info = posix_getpwnam($username)) !== false) {
            posix_setgid($info['gid']);
            posix_setuid($info['uid']);
            $defaults['userid']  = $info['uid'];
            $defaults['groupid'] = $info['gid'];
        } else {
            echo ('Invalid username');
            exit(-1);
        }
    }
    
    if ((isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false) OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false) AND (isset($options['q']))) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['json-stdout'])) {
       define('JSON_STDOUT', true);  
    } else {
       define('JSON_STDOUT', false);  
    }

    if (isset($options['f'])) {
        $l_FastCli = true;
    }
    
    if (isset($options['q']) || isset($options['quite'])) {
        $BOOL_RESULT = true;
    }
    
    if (isset($options['x'])) {
        define('AI_EXPERT', $options['x']);
    } else if (isset($options['mode'])) {
        define('AI_EXPERT', $options['mode']);
    } else {
        define('AI_EXPERT', AI_EXPERT_MODE);
    }
    
    if (AI_EXPERT < 2) {
        $g_SpecificExt              = true;
        $defaults['scan_all_files'] = false;
    } else {
        $defaults['scan_all_files'] = true;
    }
    
    define('BOOL_RESULT', $BOOL_RESULT);
    
    if ((isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false) OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)) {
        $delay = (int) $delay;
        if (!($delay < 0)) {
            $defaults['scan_delay'] = $delay;
        }
    }
    
    if ((isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false) OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)) {
        $defaults['skip_ext'] = $ext_list;
    }
    
    if (isset($options['n']) OR isset($options['skip-cache'])) {
        $defaults['skip_cache'] = true;
    }
    
    if (isset($options['scan'])) {
        $ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
        if ($ext_list != '') {
            $l_FastCli        = true;
            $g_SensitiveFiles = explode(",", $ext_list);
            for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
                if ($g_SensitiveFiles[$i] == '.') {
                    $g_SensitiveFiles[$i] = '';
                }
            }
            
            $g_SpecificExt = true;
        }
    }
    
    
    if (isset($options['all']) OR isset($options['a'])) {
        $defaults['scan_all_files'] = true;
        $g_SpecificExt              = false;
    }
    
    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }
    
    
    if (!defined('SMART_SCAN')) {
        define('SMART_SCAN', 1);
    }
    
    if (!defined('AI_DEOBFUSCATE')) {
        define('AI_DEOBFUSCATE', false);
    }
    
    
    $l_SpecifiedPath = false;
    if ((isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false) OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)) {
        $defaults['path'] = $path;
        $l_SpecifiedPath  = true;
    }
    
    if (isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false) {
    } else {
        $g_NoPrefix = '';
    }
    
    if (isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false) {
    } else {
        $g_AddPrefix = '';
    }
    
    
    
    $l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
    $l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
    $l_SuffixReport = preg_replace('#[/\\\.\s]#', '_', $l_SuffixReport);
    $l_SuffixReport .= "-" . rand(1, 999999);
    
    if ((isset($options['report']) AND ($report = $options['report']) !== false) OR (isset($options['r']) AND ($report = $options['r']) !== false)) {
        $report = str_replace('@PATH@', $l_SuffixReport, $report);
        $report = str_replace('@RND@', rand(1, 999999), $report);
        $report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
        define('REPORT', $report);
        define('NEED_REPORT', true);
    }
    
    if (isset($options['no-html'])) {
        define('REPORT', 'no@email.com');
    }
    
    if ((isset($options['idb']) AND ($ireport = $options['idb']) !== false)) {
        $ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
        $ireport = str_replace('@RND@', rand(1, 999999), $ireport);
        $ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
        define('INTEGRITY_DB_FILE', $ireport);
    }
    
    
    defined('REPORT') OR define('REPORT', 'AI-BOLIT-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');
    
    defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));
    
    $last_arg = max(1, sizeof($_SERVER['argv']) - 1);
    if (isset($_SERVER['argv'][$last_arg])) {
        $path = $_SERVER['argv'][$last_arg];
        if (substr($path, 0, 1) != '-' AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options))) {
            $defaults['path'] = $path;
        }
    }    
    
    define('ONE_PASS', isset($options['one-pass']));
    
    define('IMAKE', isset($options['imake']));
    define('ICHECK', isset($options['icheck']));
    
    if (IMAKE && ICHECK)
        die('One of the following options must be used --imake or --icheck.');
    
} else {
    define('AI_EXPERT', AI_EXPERT_MODE);
    define('ONE_PASS', true);
}


if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
    $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));
    
    $g_DBShe       = explode("\n", base64_decode($avdb[0]));
    $gX_DBShe      = explode("\n", base64_decode($avdb[1]));
    $g_FlexDBShe   = explode("\n", base64_decode($avdb[2]));
    $gX_FlexDBShe  = explode("\n", base64_decode($avdb[3]));
    $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
    $g_ExceptFlex  = explode("\n", base64_decode($avdb[5]));
    $g_AdwareSig   = explode("\n", base64_decode($avdb[6]));
    $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
    $g_JSVirSig    = explode("\n", base64_decode($avdb[8]));
    $gX_JSVirSig   = explode("\n", base64_decode($avdb[9]));
    $g_SusDB       = explode("\n", base64_decode($avdb[10]));
    $g_SusDBPrio   = explode("\n", base64_decode($avdb[11]));
    $g_DeMapper    = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));
    $g_Mnemo    = @array_flip(@array_combine(explode("\n", base64_decode($avdb[14])), explode("\n", base64_decode($avdb[15]))));
    
    if (count($g_DBShe) <= 1) {
        $g_DBShe = array();
    }
    
    if (count($gX_DBShe) <= 1) {
        $gX_DBShe = array();
    }
    
    if (count($g_FlexDBShe) <= 1) {
        $g_FlexDBShe = array();
    }
    
    if (count($gX_FlexDBShe) <= 1) {
        $gX_FlexDBShe = array();
    }
    
    if (count($gXX_FlexDBShe) <= 1) {
        $gXX_FlexDBShe = array();
    }
    
    if (count($g_ExceptFlex) <= 1) {
        $g_ExceptFlex = array();
    }
    
    if (count($g_AdwareSig) <= 1) {
        $g_AdwareSig = array();
    }
    
    if (count($g_PhishingSig) <= 1) {
        $g_PhishingSig = array();
    }
    
    if (count($gX_JSVirSig) <= 1) {
        $gX_JSVirSig = array();
    }
    
    if (count($g_JSVirSig) <= 1) {
        $g_JSVirSig = array();
    }
    
    if (count($g_SusDB) <= 1) {
        $g_SusDB = array();
    }
    
    if (count($g_SusDBPrio) <= 1) {
        $g_SusDBPrio = array();
    }
    
    stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
    $gX_FlexDBShe  = array();
    $gXX_FlexDBShe = array();
    $gX_JSVirSig   = array();
}

if (isset($defaults['userid'])) {
    stdOut('Running from ' . $defaults['userid'] . ':' . $defaults['groupid']);
}

stdOut('Malware signatures: ' . (count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe)));

if ($g_SpecificExt) {
    stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

if (!DEBUG_PERFORMANCE) {
    OptimizeSignatures();
} else {
    stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) {
    define('PLAIN_FILE', '');
}

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 120);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
    include_once(AIBOLIT_EXTERNAL_HANDLER);
    stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
    if (function_exists("aibolit_onStart")) {
        aibolit_onStart();
    }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
    $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
    $defaults['scan_all_files'] = 0;
}

if (!isCli()) {
    define('ICHECK', isset($_GET['icheck']));
    define('IMAKE', isset($_GET['imake']));
    
    define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
    ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH) {
    if (isCli()) {
        die(stdOut("Directory '{$defaults['path']}' not found!"));
    }
} elseif (!is_readable(ROOT_PATH)) {
    if (isCli()) {
        die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
    }
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT)) {
    $report      = str_replace('\\', '/', REPORT);
    $abs         = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
    $report      = array_values(array_filter(explode('/', $report)));
    $report_file = array_pop($report);
    $report_path = realpath($abs . implode(DIR_SEPARATOR, $report));
    
    define('REPORT_FILE', $report_file);
    define('REPORT_PATH', $report_path);
    
    if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE)) {
        @unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
    }
}

if (defined('REPORT_PATH')) {
    $l_ReportDirName = REPORT_PATH;
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000, 9999) . '.txt');

if (function_exists('phpinfo')) {
    ob_start();
    phpinfo();
    $l_PhpInfo = ob_get_contents();
    ob_end_clean();
    
    $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
    preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
    $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>';
} else {
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email) {
    $email = preg_split('#[,\s;]#', $email, -1, PREG_SPLIT_NO_EMPTY);
    $r     = array();
    for ($i = 0, $size = sizeof($email); $i < $size; $i++) {
        if (function_exists('filter_var')) {
            if (filter_var($email[$i], FILTER_VALIDATE_EMAIL)) {
                $r[] = $email[$i];
            }
        } else {
            // for PHP4
            if (strpos($email[$i], '@') !== false) {
                $r[] = $email[$i];
            }
        }
    }
    return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val) {
    $val  = trim($val);
    $last = strtolower($val{strlen($val) - 1});
    switch ($last) {
        case 't':
            $val *= 1024;
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }
    return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites) {
    if ($bites < 1024) {
        return $bites . ' b';
    } elseif (($kb = $bites / 1024) < 1024) {
        return number_format($kb, 2) . ' Kb';
    } elseif (($mb = $kb / 1024) < 1024) {
        return number_format($mb, 2) . ' Mb';
    } elseif (($gb = $mb / 1024) < 1024) {
        return number_format($gb, 2) . ' Gb';
    } else {
        return number_format($gb / 1024, 2) . 'Tb';
    }
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
    global $g_IgnoreList;
    
    for ($i = 0; $i < count($g_IgnoreList); $i++) {
        if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
            if ($par_CRC == $g_IgnoreList[$i][1]) {
                return true;
            }
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
    global $g_AddPrefix, $g_NoPrefix;
    if ($replace_path) {
        $lines = explode("\n", $par_Str);
        array_walk($lines, function(&$n) {
            global $g_AddPrefix, $g_NoPrefix;
            $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
        });
        
        $par_Str = implode("\n", $lines);
    }
    
    return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
    global $g_AddPrefix, $g_NoPrefix;
    array_walk($par_Arr, function(&$n) {
        global $g_AddPrefix, $g_NoPrefix;
        $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n);
    });
    
    return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function getRawJsonVuln($par_List) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos      = $par_List[$i]['ndx'];
        $res['fn']  = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        $res['sig'] = $par_List[$i]['id'];
        
        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['sigid'] = 'vuln_' . md5($g_Structure['n'][$l_Pos] . $par_List[$i]['id']);
        
        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function getRawJson($par_List, $par_Details = null, $par_SigId = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix, $g_Mnemo;
    $results = array();
    $l_Src   = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;',
        '<' . '?php.'
    );
    $l_Dst   = array(
        '"',
        '<',
        '>',
        '&',
        '\'',
        '<' . '?php '
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_n' . rand(1000000, 9000000);
        }
                
        $l_Pos     = $par_List[$i];
        $res['fn'] = convertToUTF8($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]));
        if ($par_Details != null) {
            $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
            $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
            $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
            $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
            $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);            
        }
        
        $res['sig'] = convertToUTF8($res['sig']);

        $res['ct']    = $g_Structure['c'][$l_Pos];
        $res['mt']    = $g_Structure['m'][$l_Pos];
        $res['sz']    = $g_Structure['s'][$l_Pos];
        $res['hash']  = $g_Structure['crc'][$l_Pos];
        $res['sigid'] = $l_SigId;
        
        if (isset($par_SigId) && isset($g_Mnemo[$par_SigId[$i]])) {
           $res['sn'] = $g_Mnemo[$par_SigId[$i]]; 
        } else {
           $res['sn'] = ''; 
        }

        $results[] = $res;
    }
    
    return $results;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $i = 0;
    
    if ($par_TableName == null) {
        $par_TableName = 'table_' . rand(1000000, 9000000);
    }
    
    $l_Result = '';
    $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";
    
    $l_Result .= "<thead><tr class=\"tbgh" . ($i % 2) . "\">";
    $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
    $l_Result .= "<th>" . AI_STR_005 . "</th>";
    $l_Result .= "<th>" . AI_STR_006 . "</th>";
    $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
    $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    $l_Result .= "<th width=0 class=\"hidd\"></th>";
    
    $l_Result .= "</tr></thead><tbody>";
    
    for ($i = 0; $i < count($par_List); $i++) {
        if ($par_SigId != null) {
            $l_SigId = 'id_' . $par_SigId[$i];
        } else {
            $l_SigId = 'id_z' . rand(1000000, 9000000);
        }
        
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        $l_Creat = $g_Structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['c'][$l_Pos]) : '-';
        $l_Modif = $g_Structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['m'][$l_Pos]) : '-';
        $l_Size  = $g_Structure['s'][$l_Pos] > 0 ? bytes2Human($g_Structure['s'][$l_Pos]) : '-';
        
        if ($par_Details != null) {
            $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
            $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
            $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);
            
            $l_Body = '<div class="details">';
            
            if ($par_SigId != null) {
                $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
            }
            
            $l_Body .= $l_WithMarker . '</div>';
        } else {
            $l_Body = '';
        }
        
        $l_Result .= '<tr class="tbg' . ($i % 2) . '" o="' . $l_SigId . '">';
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
        } else {
            $l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]])) . '</a></div></td>';
        }
        
        $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
        $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['crc'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['m'][$l_Pos] . '</div></td>';
        $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
        $l_Result .= '</tr>';
        
    }
    
    $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
    global $g_Structure, $g_NoPrefix, $g_AddPrefix;
    
    $l_Result = "";
    
    $l_Src = array(
        '&quot;',
        '&lt;',
        '&gt;',
        '&amp;',
        '&#039;'
    );
    $l_Dst = array(
        '"',
        '<',
        '>',
        '&',
        '\''
    );
    
    for ($i = 0; $i < count($par_List); $i++) {
        $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
            if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
                continue;
            }
        }
        
        
        if ($par_Details != null) {
            
            $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
            $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
            $l_Body = str_replace($l_Src, $l_Dst, $l_Body);
            
        } else {
            $l_Body = '';
        }
        
        if (is_file($g_Structure['n'][$l_Pos])) {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
        } else {
            $l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]]) . "\n";
        }
        
    }
    
    return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
    if (preg_match('|<tr><td class="e">\s*' . $par_Name . '\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
        return str_replace('no value', '', strip_tags($l_Result[1]));
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
    $l_PhpInfoSystem    = extractValue($par_Str, 'System');
    $l_PhpPHPAPI        = extractValue($par_Str, 'Server API');
    $l_AllowUrlFOpen    = extractValue($par_Str, 'allow_url_fopen');
    $l_AllowUrlInclude  = extractValue($par_Str, 'allow_url_include');
    $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
    $l_DisplayErrors    = extractValue($par_Str, 'display_errors');
    $l_ErrorReporting   = extractValue($par_Str, 'error_reporting');
    $l_ExposePHP        = extractValue($par_Str, 'expose_php');
    $l_LogErrors        = extractValue($par_Str, 'log_errors');
    $l_MQGPC            = extractValue($par_Str, 'magic_quotes_gpc');
    $l_MQRT             = extractValue($par_Str, 'magic_quotes_runtime');
    $l_OpenBaseDir      = extractValue($par_Str, 'open_basedir');
    $l_RegisterGlobals  = extractValue($par_Str, 'register_globals');
    $l_SafeMode         = extractValue($par_Str, 'safe_mode');
        
    $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
    $l_OpenBaseDir      = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);
    
    $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
    $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
    $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI . '</span><br/>';
    $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen . '</span><br/>';
    $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude . '</span><br/>';
    $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction . '</span><br/>';
    $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors . '</span><br/>';
    $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting . '</span><br/>';
    $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP . '</span><br/>';
    $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
    $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC . '</span><br/>';
    $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT . '</span><br/>';
    $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
    $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';
    
    if (phpversion() < '5.3.0') {
        $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode . '</span><br/>';
    }
    
    return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
function addSlash($dir) {
    return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
}

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
    if (!DEBUG_MODE) {
        return;
    }
    
    $l_MemInfo = ' ';
    if (function_exists('memory_get_usage')) {
        $l_MemInfo .= ' curmem=' . bytes2Human(memory_get_usage());
    }
    
    if (function_exists('memory_get_peak_usage')) {
        $l_MemInfo .= ' maxmem=' . bytes2Human(memory_get_peak_usage());
    }
    
    stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, $g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;
    
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    $l_SkipSample = array();
    
    QCR_Debug('Scan ' . $l_RootDir);
    
    $l_QuotedSeparator = quotemeta(DIR_SEPARATOR);
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type = filetype($l_FileName);
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && $l_Type != "dir") {                
                continue;
            }
            
            $l_Ext   = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
            $l_IsDir = is_dir($l_FileName);
            
            if (in_array($l_Ext, $g_SuspiciousFiles)) {
            }
            
            // which files should be scanned
            $l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));
            
            if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                if (ONE_PASS) {
                    $g_Structure['n'][$g_Counter] = $l_FileName . DIR_SEPARATOR;
                } else {
                    $l_Buffer .= $l_FileName . DIR_SEPARATOR . "\n";
                }
                
                $l_DirCounter++;
                
                if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                    $g_Doorway[]  = $l_SourceDirIndex;
                    $l_DirCounter = -655360;
                }
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_ScanDirectories($l_FileName);
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    if (in_array($l_Ext, $g_ShortListExt)) {
                        $l_DoorwayFilesCounter++;
                        
                        if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR) {
                            $g_Doorway[]           = $l_SourceDirIndex;
                            $l_DoorwayFilesCounter = -655360;
                        }
                    }
                    
                    if (ONE_PASS) {
                        QCR_ScanFile($l_FileName, $g_Counter++);
                    } else {
                        $l_Buffer .= $l_FileName . "\n";
                    }
                    
                    $g_Counter++;
                }
            }
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
//echo "\n *********** --------------------------------------------------------\n";

    $l_MaxChars = MAX_PREVIEW_LEN;

    $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

    $l_MaxLen   = strlen($par_Content);
    $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen);
    $l_MinPos   = max(0, $par_Pos - $l_MaxChars);
    
    $l_FoundStart = substr($par_Content, 0, $par_Pos);
    $l_FoundStart = str_replace("\r", '', $l_FoundStart);
    $l_LineNo     = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

//echo "\nMinPos=" . $l_MinPos . " Pos=" . $par_Pos . " l_RightPos=" . $l_RightPos . "\n";
//var_dump($par_Content);
//echo "\n-----------------------------------------------------\n";

                                                                                                                                                      
    $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);
    
    $l_Res = makeSafeFn(UnwrapObfu($l_Res));

    $l_Res = str_replace('~', ' ', $l_Res);

    $l_Res = preg_replace('~[\s\t]+~', ' ', $l_Res);
      
    $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);
    
//echo "\nFinal:\n";
//var_dump($l_Res);
//echo "\n-----------------------------------------------------\n";
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(hexdec($escaped[1]));
}
function escapedOctDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr(octdec($escaped[1]));
}
function escapedDec($escaped) {
    $GLOBALS['g_EncObfu']++;
    return chr($escaped[1]);
}

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
    define('T_ML_COMMENT', T_COMMENT);
} else {
    define('T_DOC_COMMENT', T_ML_COMMENT);
}

function UnwrapObfu($par_Content) {
    $GLOBALS['g_EncObfu'] = 0;
    
    $search      = array(
        ' ;',
        ' =',
        ' ,',
        ' .',
        ' (',
        ' )',
        ' {',
        ' }',
        '; ',
        '= ',
        ', ',
        '. ',
        '( ',
        '( ',
        '{ ',
        '} ',
        ' !',
        ' >',
        ' <',
        ' _',
        '_ ',
        '< ',
        '> ',
        ' $',
        ' %',
        '% ',
        '# ',
        ' #',
        '^ ',
        ' ^',
        ' &',
        '& ',
        ' ?',
        '? '
    );
    $replace     = array(
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        ';',
        '=',
        ',',
        '.',
        '(',
        ')',
        '{',
        '}',
        '!',
        '>',
        '<',
        '_',
        '_',
        '<',
        '>',
        '$',
        '%',
        '%',
        '#',
        '#',
        '^',
        '^',
        '&',
        '&',
        '?',
        '?'
    );
    $par_Content = str_replace('@', '', $par_Content);
    $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
    $par_Content = str_replace($search, $replace, $par_Content);
    $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function($m) {
        return "'" . chr(intval($m[1], 0)) . "'";
    }, $par_Content);
    
    $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i', 'escapedHexToHex', $par_Content);
    $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i', 'escapedOctDec', $par_Content);
    
    $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
    $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);
    
    $content = str_replace('<?$', '<?php$', $content);
    $content = str_replace('<?php', '<?php ', $content);
    
    return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define('UTF32_BIG_ENDIAN_BOM', chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define('UTF16_BIG_ENDIAN_BOM', chr(0xFE) . chr(0xFF));
define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define('UTF8_BOM', chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);
    
    if ($first3 == UTF8_BOM)
        return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM)
        return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM)
        return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM)
        return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM)
        return 'UTF-16LE';
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src) {
    if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
        return $l_Found[0][1];
    }
    
    return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
    global $g_UrlIgnoreList;
    
    for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
        if (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
    return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content) {
    global $g_Vulnerable, $g_CmsListDetector;
    
    
    $l_Vuln = array();
    
    $par_Filename = strtolower($par_Filename);
    
    if ((strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) && (strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)) {
        $l_Vuln['id']   = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) && (strpos($par_Content, '$format == \'\' || $format == false ||') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'joomla/filesystem/file.php') !== false) && (strpos($par_Content, '$file = rtrim($file, \'.\');') === false)) {
        if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
            $l_Vuln['id']   = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) || (stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) || (stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) || (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
        $l_Vuln['id']   = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) || (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
        if (strpos($par_Content, 'showImageByID') === false) {
            $l_Vuln['id']   = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) || (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
        $l_Vuln['id']   = 'AFU : elFinder';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        return true;
    }
    
    if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
        if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
            $l_Vuln['id']   = 'SQLI : DRUPAL : CVE-2014-3704';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
        if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
            $l_Vuln['id']   = 'AFD : MINIFY : CVE-2013-6619';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if ((strpos($par_Filename, 'timthumb.php') !== false) || (strpos($par_Filename, 'thumb.php') !== false) || (strpos($par_Filename, 'cache.php') !== false) || (strpos($par_Filename, '_img.php') !== false)) {
        if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false) {
            $l_Vuln['id']   = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
        if (strpos($par_Content, 'eval($form->ScriptDisplay);') !== false) {
            $l_Vuln['id']   = 'RCE : RSFORM : rsform.php, LINE 1605';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
        if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : FANCYBOX';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
        if (strpos($par_Content, 'verify nonce') === false) {
            $l_Vuln['id']   = 'AFU : Cherry Plugin';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {
        $l_Vuln['id']   = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
        $l_Vuln['ndx']  = $par_Index;
        $g_Vulnerable[] = $l_Vuln;
        
        return true;
    }
    
    if (strpos($par_Filename, '/bx_1c_import.php') !== false) {
        if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
            $l_Vuln['id']   = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            
            return true;
        }
    }
    
    if (strpos($par_Filename, 'scripts/setup.php') !== false) {
        if (strpos($par_Content, 'PMA_Config') !== false) {
            $l_Vuln['id']   = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, '/uploadify.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
            $l_Vuln['id']   = 'AFU : UPLOADIFY : CVE: 2012-1153';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {
        if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
            $l_Vuln['id']   = 'AFU : https://revisium.com/ru/blog/adsmanager_afu.html';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {
        if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
            $l_Vuln['id']   = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    
    if (strpos($par_Filename, 'core/lib/drupal.php') !== false) {
        $version = '';
        if (preg_match('|VERSION\s*=\s*\'(8\.\d+\.\d+)\'|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '8.5.1', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        
        return false;
    }
    
    if (strpos($par_Filename, 'changelog.txt') !== false) {
        $version = '';
        if (preg_match('|Drupal\s+(7\.\d+),|smi', $par_Content, $tmp_ver)) {
            $version = $tmp_ver[1];
        }
        
        if (($version !== '') && (version_compare($version, '7.58', '<'))) {
            $l_Vuln['id']   = 'Drupageddon 2 : SA-CORE-2018–002';
            $l_Vuln['ndx']  = $par_Index;
            $g_Vulnerable[] = $l_Vuln;
            return true;
        }
        
        return false;
    }
    
    if (strpos($par_Filename, 'phpmailer.php') !== false) {
        if (strpos($par_Content, 'PHPMailer') !== false) {
            $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);
            
            if ($l_Found) {
                $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                
                if ($l_Version < 2520) {
                    $l_Found = false;
                }
            }
            
            if (!$l_Found) {
                
                $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~', $par_Content, $l_Match);
                if ($l_Found) {
                    $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                    if ($l_Version < 5220) {
                        $l_Found = false;
                    }
                }
            }
            
            
            if (!$l_Found) {
                $l_Vuln['id']   = 'RCE : CVE-2016-10045, CVE-2016-10031';
                $l_Vuln['ndx']  = $par_Index;
                $g_Vulnerable[] = $l_Vuln;
                return true;
            }
        }
        
        return false;
    }
    
    
    
    
}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($par_Offset) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable;
    
    QCR_Debug('QCR_GoScan ' . $par_Offset);
    
    $i = 0;
    
    try {
        $s_file = new SplFileObject(QUEUE_FILENAME);
        $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
        
        foreach ($s_file as $l_Filename) {
            QCR_ScanFile($l_Filename, $i++);
        }
        
        unset($s_file);
    }
    catch (Exception $e) {
        QCR_Debug($e->getMessage());
    }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $i = 0) {
    global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList, $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList, $g_Vulnerable, $g_CriticalFiles, $g_DeMapper;
    
    global $g_CRC;
    static $_files_and_ignored = 0;
    
    $l_CriticalDetected = false;
    $l_Stat             = stat($l_Filename);
    
    if (substr($l_Filename, -1) == DIR_SEPARATOR) {
        // FOLDER
        $g_Structure['n'][$i] = $l_Filename;
        $g_TotalFolder++;
        printProgress($_files_and_ignored, $l_Filename);
        return;
    }
    
    QCR_Debug('Scan file ' . $l_Filename);
    printProgress(++$_files_and_ignored, $l_Filename);
        
    // FILE
    if ((MAX_SIZE_TO_SCAN > 0 AND $l_Stat['size'] > MAX_SIZE_TO_SCAN) || ($l_Stat['size'] < 0)) {
        $g_BigFiles[] = $i;
        
        if (function_exists('aibolit_onBigFile')) {
            aibolit_onBigFile($l_Filename);
        }
        
        AddResult($l_Filename, $i);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if ((!AI_HOSTER) && in_array($l_Ext, $g_CriticalFiles)) {
            $g_CriticalPHP[]         = $i;
            $g_CriticalPHPFragment[] = "BIG FILE. SKIPPED.";
            $g_CriticalPHPSig[]      = "big_1";
        }
    } else {
        $g_TotalFiles++;
        
        $l_TSStartScan = microtime(true);
        
        $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
        if (filetype($l_Filename) == 'file') {
            $l_Content   = @file_get_contents($l_Filename);
            $l_Unwrapped = @php_strip_whitespace($l_Filename);
        }
                
        if ((($l_Content == '') || ($l_Unwrapped == '')) && ($l_Stat['size'] > 0)) {
            $g_NotRead[] = $i;
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 'io');
            }
            AddResult('[io] ' . $l_Filename, $i);
            return;
        }

        // ignore itself
        if (strpos($l_Content, '9d07bece4193397fb1e52663c881a1d3') !== false) {
           return false;
        }
        
        // unix executables
        if (strpos($l_Content, chr(127) . 'ELF') !== false) {
            // todo: add crc check 
            return;
        }
        
        $g_CRC = _hash_($l_Unwrapped);
        
        $l_UnicodeContent = detect_utf_encoding($l_Content);
        //$l_Unwrapped = $l_Content;
        
        // check vulnerability in files
        $l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content);
        
        if ($l_UnicodeContent !== false) {
            if (function_exists('iconv')) {
                $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
            } else {
                $g_NotRead[] = $i;
                if (function_exists('aibolit_onReadError')) {
                    aibolit_onReadError($l_Filename, 'ec');
                }
                AddResult('[ec] ' . $l_Filename, $i);
            }
        }
        
        // critical
        $g_SkipNextCheck = false;
        
        $l_DeobfType = '';
        if ((!AI_HOSTER) || AI_DEOBFUSCATE) {
            $l_DeobfType = getObfuscateType($l_Unwrapped);
        }
        
        if ($l_DeobfType != '') {
            $l_Unwrapped     = deobfuscate($l_Unwrapped);
            $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
        } else {
            if (DEBUG_MODE) {
                stdOut("\n...... NOT OBFUSCATED\n");
            }
        }
        
        $l_Unwrapped = UnwrapObfu($l_Unwrapped);
        
        if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId)) {
            if ($l_Ext == 'js') {
                $g_CriticalJS[]         = $i;
                $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalJSSig[]      = $l_SigId;
            } else {
                $g_CriticalPHP[]         = $i;
                $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $g_CriticalPHPSig[]      = $l_SigId;
            }
            
            $g_SkipNextCheck = true;
        } else {
            if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId)) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Content, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        $l_TypeDe = 0;
        
        // critical JS
        if (!$g_SkipNextCheck) {
            $l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos !== false) {
                if ($l_Ext == 'js') {
                    $g_CriticalJS[]         = $i;
                    $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalJSSig[]      = $l_SigId;
                } else {
                    $g_CriticalPHP[]         = $i;
                    $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
                    $g_CriticalPHPSig[]      = $l_SigId;
                }
                
                $g_SkipNextCheck = true;
            }
        }
        
        // phishing
        if (!$g_SkipNextCheck) {
            $l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId);
            if ($l_Pos === false) {
                $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId);
            }
            
            if ($l_Pos !== false) {
                $g_Phishing[]            = $i;
                $g_PhishingFragment[]    = getFragment($l_Unwrapped, $l_Pos);
                $g_PhishingSigFragment[] = $l_SigId;
                $g_SkipNextCheck         = true;
            }
        }
        
        
        if (!$g_SkipNextCheck) {
            // warnings
            $l_Pos = '';
            
            // adware
            if (Adware($l_Filename, $l_Unwrapped, $l_Pos)) {
                $g_AdwareList[]         = $i;
                $g_AdwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
                $l_CriticalDetected     = true;
            }
            
            // articles
            if (stripos($l_Filename, 'article_index')) {
                $g_AdwareList[]     = $i;
                $l_CriticalDetected = true;
            }
        }
    } // end of if (!$g_SkipNextCheck) {
    
    unset($l_Unwrapped);
    unset($l_Content);
    
    //printProgress(++$_files_and_ignored, $l_Filename);
    
    $l_TSEndScan = microtime(true);
    if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
        usleep(SCAN_DELAY * 1000);
    }
    
    if ($g_SkipNextCheck || $l_CriticalDetected) {
        AddResult($l_Filename, $i);
    }
}

function AddResult($l_Filename, $i) {
    global $g_Structure, $g_CRC;
    
    $l_Stat                 = stat($l_Filename);
    $g_Structure['n'][$i]   = $l_Filename;
    $g_Structure['s'][$i]   = $l_Stat['size'];
    $g_Structure['c'][$i]   = $l_Stat['ctime'];
    $g_Structure['m'][$i]   = $l_Stat['mtime'];
    $g_Structure['crc'][$i] = $g_CRC;
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_SusDB, $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    
    $l_Res = false;
    
    if (AI_EXTRA_WARN) {
        foreach ($g_SusDB as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    return true;
                }
            }
        }
    }
    
    if (AI_EXPERT < 2) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
    }
    
    if (AI_EXPERT < 1) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                return true;
            }
        }
        
        $l_Content_lo = strtolower($l_Content);
        
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                return true;
            }
        }
    }
    
}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos) {
    global $g_AdwareSig;
    
    $l_Res = false;
    
    foreach ($g_AdwareSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos = $l_Found[0][1];
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
    global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
    $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);
    
    foreach ($g_ExceptFlex as $l_ExceptItem) {
        if (@preg_match('#' . $l_ExceptItem . '#smi', $l_FoundStrPlus, $l_Detected)) {
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_PhishingSig, $g_PhishFiles, $g_PhishEntries;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_PhishFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped phs file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_PhishingSig as $l_Item) {
        $offset = 0;
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            $offset = $l_Found[0][1] + 1;
            
        }
    }
    
    return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId) {
    global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;
    
    $l_Res = false;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_VirusFiles as $l_Ext) {
            if (strpos($l_FN, $l_Ext) !== false) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped js file, not critical.\n";
        }
        
        return false;
    }
    
    
    foreach ($g_JSVirSig as $l_Item) {
        $offset = 0;
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return $l_Pos;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gX_JSVirSig as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    //$l_SigId = myCheckSum($l_Item);
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return $l_Pos;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
function pcre_error($par_FN, $par_Index) {
    global $g_NotRead, $g_Structure;
    
    $err = preg_last_error();
    if (($err == PREG_BACKTRACK_LIMIT_ERROR) || ($err == PREG_RECURSION_LIMIT_ERROR)) {
        if (!in_array($par_Index, $g_NotRead)) {
            if (function_exists('aibolit_onReadError')) {
                aibolit_onReadError($l_Filename, 're');
            }
            $g_NotRead[] = $par_Index;
            AddResult('[re] ' . $par_FN, $par_Index);
        }
        
        return true;
    }
    
    return false;
}



////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

function get_descr_heur($type) {
    switch ($type) {
        case SUSP_MTIME:
            return AI_STR_077;
        case SUSP_PERM:
            return AI_STR_078;
        case SUSP_PHP_IN_UPLOAD:
            return AI_STR_079;
    }
    
    return "---";
}

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId) {
    global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment, $g_CriticalFiles, $g_CriticalEntries, $g_RegExpStat;
    
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
    
    if ($l_SkipCheck) {
        foreach ($g_CriticalFiles as $l_Ext) {
            if ((strpos($l_FN, $l_Ext) !== false) && (strpos($l_FN, '.js') === false)) {
                $l_SkipCheck = false;
                break;
            }
        }
    }
    
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
        $l_SkipCheck = false;
    }
    
    
    // if not critical - skip it 
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
            echo "Skipped file, not critical.\n";
        }
        
        return false;
    }
    
    foreach ($g_FlexDBShe as $l_Item) {
        $offset = 0;
        
        if (DEBUG_PERFORMANCE) {
            $stat_start = microtime(true);
        }
        
        while (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
            if (!CheckException($l_Content, $l_Found)) {
                $l_Pos   = $l_Found[0][1];
                //$l_SigId = myCheckSum($l_Item);
                $l_SigId = getSigId($l_Found);
                
                if (DEBUG_MODE) {
                    echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
            
            $offset = $l_Found[0][1] + 1;
            
        }
        
        if (DEBUG_PERFORMANCE) {
            $stat_stop = microtime(true);
            $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
        }
        
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    if (AI_EXPERT > 1) {
        foreach ($gXX_FlexDBShe as $l_Item) {
            if (DEBUG_PERFORMANCE) {
                $stat_start = microtime(true);
            }
            
            if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
                if (!CheckException($l_Content, $l_Found)) {
                    $l_Pos   = $l_Found[0][1];
                    $l_SigId = getSigId($l_Found);
                    
                    if (DEBUG_MODE) {
                        echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
                    }
                    
                    return true;
                }
            }
            
            if (DEBUG_PERFORMANCE) {
                $stat_stop = microtime(true);
                $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
            }
            
        }
    }
    
    $l_Content_lo = strtolower($l_Content);
    
    foreach ($g_DBShe as $l_Item) {
        $l_Pos = strpos($l_Content_lo, $l_Item);
        if ($l_Pos !== false) {
            $l_SigId = myCheckSum($l_Item);
            
            if (DEBUG_MODE) {
                echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    if (AI_EXPERT > 0) {
        foreach ($gX_DBShe as $l_Item) {
            $l_Pos = strpos($l_Content_lo, $l_Item);
            if ($l_Pos !== false) {
                $l_SigId = myCheckSum($l_Item);
                
                if (DEBUG_MODE) {
                    echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
                }
                
                return true;
            }
        }
    }
    
    if (AI_HOSTER)
        return false;
    
    if (AI_EXPERT > 0) {
        if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false)) {
            $l_Pos = 0;
            
            if (DEBUG_MODE) {
                echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    // detect uploaders / droppers
    if (AI_EXPERT > 1) {
        $l_Found = null;
        if ((filesize($l_FN) < 2048) && (strpos($l_FN, '.ph') !== false) && ((($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) || (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) || (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)))) {
            if ($l_Found != null) {
                $l_Pos = $l_Found[0][1];
            }
            if (DEBUG_MODE) {
                echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
            }
            
            return true;
        }
    }
    
    return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
    header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {
    
    $l_PassOK = false;
    if (strlen(PASS) > 8) {
        $l_PassOK = true;
    }
    
    if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found)) {
        $l_PassOK = true;
    }
    
    if (!$l_PassOK) {
        echo sprintf(AI_STR_009, generatePassword());
        exit;
    }
    
    if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
        printFile();
        exit;
    }
    
    if ($_GET['p'] != PASS) {
        $generated_pass = generatePassword();
        echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
        exit;
    }
}

if (!is_readable(ROOT_PATH)) {
    echo AI_STR_011;
    exit;
}

if (isCli()) {
    if (defined('REPORT_PATH') AND REPORT_PATH) {
        if (!is_writable(REPORT_PATH)) {
            die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
        }
        
        else if (!REPORT_FILE) {
            die2("\nCannot write report. Report filename is empty.");
        }
        
        else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file)) {
            die2("\nCannot write report. Report file '$file' exists but is not writable.");
        }
    }
}


// detect version CMS
$g_KnownCMS        = array();
$tmp_cms           = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum  = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $g_CMS[]                                                  = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
    $g_KnownCMS = array_keys($tmp_cms);
    $len        = count($g_KnownCMS);
    for ($i = 0; $i < $len; $i++) {
        if ($g_KnownCMS[$i] == strtolower(CMS_WORDPRESS))
            $g_KnownCMS[] = 'wp';
        if ($g_KnownCMS[$i] == strtolower(CMS_WEBASYST))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_IPB))
            $g_KnownCMS[] = 'ipb';
        if ($g_KnownCMS[$i] == strtolower(CMS_DLE))
            $g_KnownCMS[] = 'dle';
        if ($g_KnownCMS[$i] == strtolower(CMS_INSTANTCMS))
            $g_KnownCMS[] = 'instantcms';
        if ($g_KnownCMS[$i] == strtolower(CMS_SHOPSCRIPT))
            $g_KnownCMS[] = 'shopscript';
        if ($g_KnownCMS[$i] == strtolower(CMS_DRUPAL))
            $g_KnownCMS[] = 'drupal';
    }
}


$g_DirIgnoreList = array();
$g_IgnoreList    = array();
$g_UrlIgnoreList = array();
$g_KnownList     = array();

$l_IgnoreFilename    = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) {
        $g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);
    
    for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
        $g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
    }
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);
    
    for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
        $g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
    }
}


$l_SkipMask = array(
    '/template_\w{32}.css',
    '/cache/templates/.{1,150}\.tpl\.php',
    '/system/cache/templates_c/\w{1,40}\.php',
    '/assets/cache/rss/\w{1,60}',
    '/cache/minify/minify_\w{32}',
    '/cache/page/\w{32}\.php',
    '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
    '/cache/wp-cache-\d{32}\.php',
    '/cache/page/\w{32}\.php_expire',
    '/cache/page/\w{32}-cache-page-\w{32}\.php',
    '\w{32}-cache-com_content-\w{32}\.php',
    '\w{32}-cache-mod_custom-\w{32}\.php',
    '\w{32}-cache-mod_templates-\w{32}\.php',
    '\w{32}-cache-_system-\w{32}\.php',
    '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php',
    '/autoptimize/js/autoptimize_\w{32}\.js',
    '/bitrix/cache/\w{32}\.php',
    '/bitrix/cache/.{1,200}/\w{32}\.php',
    '/bitrix/cache/iblock_find/',
    '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
    '/bitrix/cache/s1/bitrix/catalog\.section/',
    '/bitrix/cache/s1/bitrix/catalog\.element/',
    '/bitrix/cache/s1/bitrix/menu/',
    '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
    '/bitrix/managed\_cache/.{1,150}/\.\w{32}\.php',
    '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
    '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
    '/smarty/compiled/SC/.{1,100}/%%.{1,200}\.php',
    '/smarty/.{1,150}\.tpl\.php',
    '/smarty/compile/.{1,150}\.tpl\.cache\.php',
    '/files/templates_c/.{1,150}\.html\.php',
    '/uploads/javascript_global/.{1,150}\.js',
    '/assets/cache/rss/\w{32}',
    'сore/cache/resource/web/resources/\d+\.cache\.php',
    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
    '/t3-assets/dev/t3/.{1,150}-cache-\w{1,20}-.{1,150}\.php',
    '/t3-assets/js/js-\w{1,30}\.js',
    '/temp/cache/SC/.{1,100}/\.cache\..{1,100}\.php',
    '/tmp/sess\_\w{32}$',
    '/assets/cache/docid\_.{1,100}\.pageCache\.php',
    '/stat/usage\_\w{1,100}\.html',
    '/stat/site\_\w{1,100}\.html',
    '/gallery/item/list/\w{1,100}\.cache\.php',
    '/core/cache/registry/.{1,100}/ext-.{1,100}\.php',
    '/core/cache/resource/shk\_/\w{1,50}\.cache\.php',
    '/cache/\w{1,40}/\w+-cache-\w+-\w{32,40}\.php',
    '/webstat/awstats.{1,150}\.txt',
    '/awstats/awstats.{1,150}\.txt',
    '/awstats/.{1,80}\.pl',
    '/awstats/.{1,80}\.html',
    '/inc/min/styles_\w+\.min\.css',
    '/inc/min/styles_\w+\.min\.js',
    '/logs/error\_log\.',
    '/logs/xferlog\.',
    '/logs/access_log\.',
    '/logs/cron\.',
    '/logs/exceptions/.{1,200}\.log$',
    '/hyper-cache/[^/]{1,50}/[^/]{1,50}/[^/]{1,50}/index\.html',
    '/mail/new/[^,]+,S=[^,]+,W=',
    '/mail/new/[^,]=,S=',
    '/application/logs/\d+/\d+/\d+\.php',
    '/sites/default/files/js/js_\w{32}\.js',
    '/yt-assets/\w{32}\.css',
    '/wp-content/cache/object/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/catalog\.section/\w{1,5}/\w{1,5}/\w{32}\.php',
    '/simpla/design/compiled/[\w\.]{40,60}\.php',
    '/compile/\w{2}/\w{2}/\w{2}/[\w.]{40,80}\.php',
    '/sys-temp/static-cache/[^/]{1,60}/userCache/[\w\./]{40,100}\.php',
    '/session/sess_\w{32}',
    '/webstat/awstats\.[\w\./]{3,100}\.html',
    '/stat/webalizer\.current',
    '/stat/usage_\d+\.html'
);

$l_SkipSample = array();

if (SMART_SCAN) {
    $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures
if (file_exists($g_AiBolitAbsolutePath . "/ai-bolit.sig")) {
   try {
       $s_file = new SplFileObject($g_AiBolitAbsolutePath . "/ai-bolit.sig");
       $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
       foreach ($s_file as $line) {
           $g_FlexDBShe[] = preg_replace('~\G(?:[^#\\\\]+|\\\\.)*+\K#~', '\\#', $line); // escaping #
       }

       stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
       $s_file = null; // file handler is closed
   }
   catch (Exception $e) {
       QCR_Debug("Import ai-bolit.sig " . $e->getMessage());
   }
}

QCR_Debug();

$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
if ($defaults['skip_ext'] != '') {
    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
        $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
    }
    
    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
}

// scan single file
if (defined('SCAN_FILE')) {
    if (file_exists(SCAN_FILE) && is_file(SCAN_FILE) && is_readable(SCAN_FILE)) {
        stdOut("Start scanning file '" . SCAN_FILE . "'.");
        QCR_ScanFile(SCAN_FILE);
    } else {
        stdOut("Error:" . SCAN_FILE . " either is not a file or readable");
    }
} else {
    if (isset($_GET['2check'])) {
        $options['with-2check'] = 1;
    }
    
    $use_doublecheck = isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE);
    $use_listingfile = defined('LISTING_FILE');
    
    // scan list of files from file
    if (!(ICHECK || IMAKE) && ($use_doublecheck || $use_listingfile)) {
        if ($use_doublecheck) {
            $listing = DOUBLECHECK_FILE;
        } else {
            if ($use_listingfile) {
                $listing = LISTING_FILE;
            }
        }
        
        stdOut("Start scanning the list from '" . $listing . "'.\n");

        if ($listing == 'stdin') {
           $lines = explode("\n", getStdin());
        } else {
           $lines = file($listing);
        }

        for ($i = 0, $size = count($lines); $i < $size; $i++) {
            $lines[$i] = trim($lines[$i]);
            if (empty($lines[$i]))
                unset($lines[$i]);
        }
        
        $i = 0;
        if ($use_doublecheck) {
            /* skip first line with <?php die("Forbidden"); ?> */
            unset($lines[0]);
            $i = 1;
        }
        
        $g_FoundTotalFiles = count($lines);
        foreach ($lines as $l_FN) {
            is_dir($l_FN) && $g_TotalFolder++;
            printProgress($i++, $l_FN);
            $BOOL_RESULT = true; // display disable
            is_file($l_FN) && QCR_ScanFile($l_FN, $i);
            $BOOL_RESULT = false; // display enable
        }
        
        $g_FoundTotalDirs  = $g_TotalFolder;
        $g_FoundTotalFiles = $g_TotalFiles;
        
    } else {
        // scan whole file system
        stdOut("Start scanning '" . ROOT_PATH . "'.\n");
        
        file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
        if (ICHECK || IMAKE) {
            // INTEGRITY CHECK
            IMAKE and unlink(INTEGRITY_DB_FILE);
            ICHECK and load_integrity_db();
            QCR_IntegrityCheck(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
            if (IMAKE)
                exit(0);
            if (ICHECK) {
                $i       = $g_Counter;
                $g_CRC   = 0;
                $changes = array();
                $ref =& $g_IntegrityDB;
                foreach ($g_IntegrityDB as $l_FileName => $type) {
                    unset($g_IntegrityDB[$l_FileName]);
                    $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
                    if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                        continue;
                    }
                    for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                        if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                            continue 2;
                        }
                    }
                    $type = in_array($type, array(
                        'added',
                        'modified'
                    )) ? $type : 'deleted';
                    $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
                    $changes[$type][] = ++$i;
                    AddResult($l_FileName, $i);
                }
                $g_FoundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
                stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
            }
            
        } else {
            QCR_ScanDirectories(ROOT_PATH);
            stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
        }
        
        QCR_Debug();
        stdOut(str_repeat(' ', 160), false);
        QCR_GoScan(0);
        unlink(QUEUE_FILENAME);
        if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE))
            @unlink(PROGRESS_LOG_FILE);
    }
}

QCR_Debug();

if (true) {
    $g_HeuristicDetected = array();
    $g_Iframer           = array();
    $g_Base64            = array();
}


// whitelist

$snum = 0;
$list = check_whitelist($g_Structure['crc'], $snum);

foreach (array(
    'g_CriticalPHP',
    'g_CriticalJS',
    'g_Iframer',
    'g_Base64',
    'g_Phishing',
    'g_AdwareList',
    'g_Redirect'
) as $p) {
    if (empty($$p))
        continue;
    
    $p_Fragment = $p . "Fragment";
    $p_Sig      = $p . "Sig";
    if ($p == 'g_Redirect')
        $p_Fragment = $p . "PHPFragment";
    if ($p == 'g_Phishing')
        $p_Sig = $p . "SigFragment";
    
    $count = count($$p);
    for ($i = 0; $i < $count; $i++) {
        $id = "{${$p}[$i]}";
        if (in_array($g_Structure['crc'][$id], $list)) {
            unset($GLOBALS[$p][$i]);
            unset($GLOBALS[$p_Sig][$i]);
            unset($GLOBALS[$p_Fragment][$i]);
        }
    }
    
    $$p          = array_values($$p);
    $$p_Fragment = array_values($$p_Fragment);
    if (!empty($$p_Sig))
        $$p_Sig = array_values($$p_Sig);
}


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
    $g_IframerFragment       = array();
    $g_Iframer               = array();
    $g_Redirect              = array();
    $g_Doorway               = array();
    $g_EmptyLink             = array();
    $g_HeuristicType         = array();
    $g_HeuristicDetected     = array();
    $g_WarningPHP            = array();
    $g_AdwareList            = array();
    $g_Phishing              = array();
    $g_PHPCodeInside         = array();
    $g_PHPCodeInsideFragment = array();
    $g_WarningPHPFragment    = array();
    $g_WarningPHPSig         = array();
    $g_BigFiles              = array();
    $g_RedirectPHPFragment   = array();
    $g_EmptyLinkSrc          = array();
    $g_Base64Fragment        = array();
    $g_UnixExec              = array();
    $g_PhishingSigFragment   = array();
    $g_PhishingFragment      = array();
    $g_PhishingSig           = array();
    $g_IframerFragment       = array();
    $g_CMS                   = array();
    $g_AdwareListFragment    = array();
}

if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
    if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_PhishingSig) > 0)) {
        exit(2);
    } else {
        exit(0);
    }
}
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $g_TotalFolder, $g_TotalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE))
    if (isset($options['with-2check']) || isset($options['quarantine']))
        if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR (count($g_Iframer) > 0) OR (count($g_UnixExec))) {
            if (!file_exists(DOUBLECHECK_FILE)) {
                if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
                    fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");
                    
                    $l_CurrPath = dirname(__FILE__);
                    
                    if (!isset($g_CriticalPHP)) {
                        $g_CriticalPHP = array();
                    }
                    if (!isset($g_CriticalJS)) {
                        $g_CriticalJS = array();
                    }
                    if (!isset($g_Iframer)) {
                        $g_Iframer = array();
                    }
                    if (!isset($g_Base64)) {
                        $g_Base64 = array();
                    }
                    if (!isset($g_Phishing)) {
                        $g_Phishing = array();
                    }
                    if (!isset($g_AdwareList)) {
                        $g_AdwareList = array();
                    }
                    if (!isset($g_Redirect)) {
                        $g_Redirect = array();
                    }
                    
                    $tmpIndex = array_merge($g_CriticalPHP, $g_CriticalJS, $g_Phishing, $g_Base64, $g_Iframer, $g_AdwareList, $g_Redirect);
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        $tmpIndex[$i] = str_replace($l_CurrPath, '.', $g_Structure['n'][$tmpIndex[$i]]);
                    }
                    
                    for ($i = 0; $i < count($g_UnixExec); $i++) {
                        $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
                    }
                    
                    $tmpIndex = array_values(array_unique($tmpIndex));
                    
                    for ($i = 0; $i < count($tmpIndex); $i++) {
                        fputs($l_FH, $tmpIndex[$i] . "\n");
                    }
                    
                    fclose($l_FH);
                } else {
                    stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
                }
            } else {
                stdOut(DOUBLECHECK_FILE . ' already exists.');
                if (AI_STR_044 != '')
                    $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
            }
            
        }

////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($g_Redirect) > 0) {
    $l_Summary .= makeSummary(AI_STR_059, count($g_Redirect), "crit");
}

if (count($g_CriticalPHP) > 0) {
    $l_Summary .= makeSummary(AI_STR_060, count($g_CriticalPHP), "crit");
}

if (count($g_CriticalJS) > 0) {
    $l_Summary .= makeSummary(AI_STR_061, count($g_CriticalJS), "crit");
}

if (count($g_Phishing) > 0) {
    $l_Summary .= makeSummary(AI_STR_062, count($g_Phishing), "crit");
}

if (count($g_NotRead) > 0) {
    $l_Summary .= makeSummary(AI_STR_066, count($g_NotRead), "crit");
}

if (count($g_BigFiles) > 0) {
    $l_Summary .= makeSummary(AI_STR_065, count($g_BigFiles), "warn");
}

if (count($g_SymLinks) > 0) {
    $l_Summary .= makeSummary(AI_STR_069, count($g_SymLinks), "warn");
}

$l_Summary .= "</table>";

$l_ArraySummary                      = array();
$l_ArraySummary["redirect"]          = count($g_Redirect);
$l_ArraySummary["critical_php"]      = count($g_CriticalPHP);
$l_ArraySummary["critical_js"]       = count($g_CriticalJS);
$l_ArraySummary["phishing"]          = count($g_Phishing);
$l_ArraySummary["unix_exec"]         = 0; // count($g_UnixExec);
$l_ArraySummary["iframes"]           = 0; // count($g_Iframer);
$l_ArraySummary["not_read"]          = count($g_NotRead);
$l_ArraySummary["base64"]            = 0; // count($g_Base64);
$l_ArraySummary["heuristics"]        = 0; // count($g_HeuristicDetected);
$l_ArraySummary["symlinks"]          = count($g_SymLinks);
$l_ArraySummary["big_files_skipped"] = count($g_BigFiles);

if (function_exists('json_encode')) {
    $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->";
}

$l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

$l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);

$l_Result .= AI_STR_015;

$l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);

////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
    $l_HostName = gethostname();
} else {
    $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit (https://revisium.com/ai/) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName . "\n\n";

$l_RawReport = array();

$l_RawReport['summary'] = array(
    'scan_path' => $defaults['path'],
    'report_time' => time(),
    'scan_time' => round(microtime(true) - START_TIME, 1),
    'total_files' => $g_FoundTotalFiles,
    'counters' => $l_ArraySummary,
    'ai_version' => AI_VERSION
);

if (!AI_HOSTER) {
    stdOut("Building list of vulnerable scripts " . count($g_Vulnerable));
    
    if (count($g_Vulnerable) > 0) {
        $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($g_Vulnerable) . ')</div><div class="crit">';
        foreach ($g_Vulnerable as $l_Item) {
            $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
            $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($g_Structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
        }
        
        $l_Result .= '</div><p>' . PHP_EOL;
        $l_PlainResult .= "\n";
    }
}


stdOut("Building list of shells " . count($g_CriticalPHP));

$l_RawReport['vulners'] = getRawJsonVuln($g_Vulnerable);

if (count($g_CriticalPHP) > 0) {
    $g_CriticalPHP              = array_slice($g_CriticalPHP, 0, 15000);
    $l_RawReport['php_malware'] = getRawJson($g_CriticalPHP, $g_CriticalPHPFragment, $g_CriticalPHPSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($g_CriticalPHP) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit');
    $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit') . "\n";
    $l_Result .= '</div>' . PHP_EOL;
    
    $l_ShowOffer = true;
} else {
    $l_Result .= '<div class="ok"><b>' . AI_STR_017 . '</b></div>';
}

stdOut("Building list of js " . count($g_CriticalJS));

if (count($g_CriticalJS) > 0) {
    $g_CriticalJS              = array_slice($g_CriticalJS, 0, 15000);
    $l_RawReport['js_malware'] = getRawJson($g_CriticalJS, $g_CriticalJSFragment, $g_CriticalJSSig);
    $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($g_CriticalJS) . ')</div><div class="crit">';
    $l_Result .= printList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir');
    $l_PlainResult .= '[CLIENT MALWARE / JS]' . "\n" . printPlainList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir') . "\n";
    $l_Result .= "</div>" . PHP_EOL;
    
    $l_ShowOffer = true;
}

stdOut("Building list of unread files " . count($g_NotRead));

if (count($g_NotRead) > 0) {
    $g_NotRead               = array_slice($g_NotRead, 0, AIBOLIT_MAX_NUMBER);
    $l_RawReport['not_read'] = $g_NotRead;
    $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($g_NotRead) . ')</div><div class="crit">';
    $l_Result .= printList($g_NotRead);
    $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
    $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($g_NotRead) . "\n\n";
}

if (!AI_HOSTER) {
    stdOut("Building list of phishing pages " . count($g_Phishing));
    
    if (count($g_Phishing) > 0) {
        $l_RawReport['phishing'] = getRawJson($g_Phishing, $g_PhishingFragment, $g_PhishingSigFragment);
        $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($g_Phishing) . ')</div><div class="crit">';
        $l_Result .= printList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir');
        $l_PlainResult .= '[PHISHING]' . "\n" . printPlainList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir') . "\n";
        $l_Result .= "</div>" . PHP_EOL;
        
        $l_ShowOffer = true;
    }
    
    stdOut("Building list of redirects " . count($g_Redirect));
    if (count($g_Redirect) > 0) {
        $l_RawReport['redirect'] = getRawJson($g_Redirect, $g_RedirectPHPFragment);
        $l_ShowOffer             = true;
        $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($g_Redirect) . ')</div><div class="crit">';
        $l_Result .= printList($g_Redirect, $g_RedirectPHPFragment, true);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of symlinks " . count($g_SymLinks));
    
    if (count($g_SymLinks) > 0) {
        $g_SymLinks               = array_slice($g_SymLinks, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['sym_links'] = $g_SymLinks;
        $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($g_SymLinks) . ')</div><div class="crit">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SymLinks), true));
        $l_Result .= "</div><div class=\"spacer\"></div>";
    }
    
}

////////////////////////////////////
if (!AI_HOSTER) {
    $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($g_BigFiles) + count($g_PHPCodeInside) + count($g_AdwareList) + count($g_EmptyLink) + count($g_Doorway) + (count($g_WarningPHP[0]) + count($g_WarningPHP[1]) + count($g_SkippedFolders));
    
    if ($l_WarningsNum > 0) {
        $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
    }
    
    stdOut("Building list of adware " . count($g_AdwareList));
    
    if (count($g_AdwareList) > 0) {
        $l_RawReport['adware'] = getRawJson($g_AdwareList, $g_AdwareListFragment);
        $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
        $l_Result .= printList($g_AdwareList, $g_AdwareListFragment, true);
        $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($g_AdwareList, $g_AdwareListFragment, true) . "\n";
        $l_Result .= "</div>" . PHP_EOL;        
    }
    
    stdOut("Building list of bigfiles " . count($g_BigFiles));
    $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
    $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');
    
    if (count($g_BigFiles) > 0) {
        $g_BigFiles               = array_slice($g_BigFiles, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['big_files'] = getRawJson($g_BigFiles);
        $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
        $l_Result .= printList($g_BigFiles);
        $l_Result .= "</div>";
        $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($g_BigFiles) . "\n\n";
    }
    
    stdOut("Building list of doorways " . count($g_Doorway));
    
    if ((count($g_Doorway) > 0) && (($defaults['report_mask'] & REPORT_MASK_DOORWAYS) == REPORT_MASK_DOORWAYS)) {
        $g_Doorway              = array_slice($g_Doorway, 0, AIBOLIT_MAX_NUMBER);
        $l_RawReport['doorway'] = getRawJson($g_Doorway);
        $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
        $l_Result .= printList($g_Doorway);
        $l_Result .= "</div>" . PHP_EOL;
        
    }
    
    if (count($g_CMS) > 0) {
        $l_RawReport['cms'] = $g_CMS;
        $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_CMS)));
        $l_Result .= "</div>";
    }
}

if (ICHECK) {
    $l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";
    
    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['modifiedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedFiles']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['addedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
    
    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
        $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
        $l_Result .= printList($changes['deletedDirs']);
        $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
    $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
    $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
    $l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
    $l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)), date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli()) {
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '') {
    die2('Report not written.');
}

// write plain text result
if (PLAIN_FILE != '') {
    
    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);
    
    if ($l_FH = fopen(PLAIN_FILE, "w")) {
        fputs($l_FH, $l_PlainResult);
        fclose($l_FH);
    }
}

// write json result
if (defined('JSON_FILE')) {
    $res = @json_encode($l_RawReport);
    if ($l_FH = fopen(JSON_FILE, "w")) {
        fputs($l_FH, $res);
        fclose($l_FH);
    }

    if (JSON_STDOUT) {
       echo $res;
    }
}

// write serialized result
if (defined('PHP_FILE')) {
    if ($l_FH = fopen(PHP_FILE, "w")) {
        fputs($l_FH, serialize($l_RawReport));
        fclose($l_FH);
    }
}

$emails = getEmails(REPORT);

if (!$emails) {
    if ($l_FH = fopen($file, "w")) {
        fputs($l_FH, $l_Template);
        fclose($l_FH);
        stdOut("\nReport written to '$file'.");
    } else {
        stdOut("\nCannot create '$file'.");
    }
} else {
    $headers = array(
        'MIME-Version: 1.0',
        'Content-type: text/html; charset=UTF-8',
        'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : 'AI-Bolit@myhost')
    );
    
    for ($i = 0, $size = sizeof($emails); $i < $size; $i++) {
        //$res = @mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
    }
    
    if ($res) {
       stdOut("\nReport sended to " . implode(', ', $emails));
    }
}

$time_taken = microtime(true) - START_TIME;
$time_taken = number_format($time_taken, 5);

stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
    $keys = array_keys($g_RegExpStat);
    for ($i = 0; $i < count($keys); $i++) {
        $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
    }
    
    arsort($g_RegExpStat);
    
    foreach ($g_RegExpStat as $r => $v) {
        echo $v . "\t\t" . $r . "\n";
    }
    
    die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
    Quarantine();
}

if (isset($options['cmd'])) {
    stdOut("Run \"{$options['cmd']}\" ");
    system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($g_CriticalPHP);
$l_EC2 = count($g_CriticalJS) + count($g_Phishing) + count($g_WarningPHP[0]) + count($g_WarningPHP[1]);
$code  = 0;

if ($l_EC1 > 0) {
    $code = 2;
} else {
    if ($l_EC2 > 0) {
        $code = 1;
    }
}

$stat = array(
    'php_malware' => count($g_CriticalPHP),
    'js_malware' => count($g_CriticalJS),
    'phishing' => count($g_Phishing)
);

if (function_exists('aibolit_onComplete')) {
    aibolit_onComplete($code, $stat);
}

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine() {
    if (!file_exists(DOUBLECHECK_FILE)) {
        return;
    }
    
    $g_QuarantinePass = 'aibolit';
    
    $archive  = "AI-QUARANTINE-" . rand(100000, 999999) . ".zip";
    $infoFile = substr($archive, 0, -3) . "txt";
    $report   = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;
    
    
    foreach (file(DOUBLECHECK_FILE) as $file) {
        $file = trim($file);
        if (!is_file($file))
            continue;
        
        $lStat = stat($file);
        
        // skip files over 300KB
        if ($lStat['size'] > 300 * 1024)
            continue;
        
        // http://www.askapache.com/security/chmod-stat.html
        $p    = $lStat['mode'];
        $perm = '-';
        $perm .= (($p & 0x0100) ? 'r' : '-') . (($p & 0x0080) ? 'w' : '-');
        $perm .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
        $perm .= (($p & 0x0020) ? 'r' : '-') . (($p & 0x0010) ? 'w' : '-');
        $perm .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
        $perm .= (($p & 0x0004) ? 'r' : '-') . (($p & 0x0002) ? 'w' : '-');
        $perm .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));
        
        $owner = (function_exists('posix_getpwuid')) ? @posix_getpwuid($lStat['uid']) : array(
            'name' => $lStat['uid']
        );
        $group = (function_exists('posix_getgrgid')) ? @posix_getgrgid($lStat['gid']) : array(
            'name' => $lStat['uid']
        );
        
        $inf['permission'][] = $perm;
        $inf['owner'][]      = $owner['name'];
        $inf['group'][]      = $group['name'];
        $inf['size'][]       = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
        $inf['ctime'][]      = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
        $inf['mtime'][]      = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
        $files[]             = strpos($file, './') === 0 ? substr($file, 2) : $file;
    }
    
    // get config files for cleaning
    $configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
    $configFiles      = preg_grep("~$configFilesRegex~", $files);
    
    // get columns width
    $width = array();
    foreach (array_keys($inf) as $k) {
        $width[$k] = strlen($k);
        for ($i = 0; $i < count($inf[$k]); ++$i) {
            $len = strlen($inf[$k][$i]);
            if ($len > $width[$k])
                $width[$k] = $len;
        }
    }
    
    // headings of columns
    $info = '';
    foreach (array_keys($inf) as $k) {
        $info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT) . ' ';
    }
    $info .= "name\n";
    
    for ($i = 0; $i < count($files); ++$i) {
        foreach (array_keys($inf) as $k) {
            $info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT) . ' ';
        }
        $info .= $files[$i] . "\n";
    }
    unset($inf, $width);
    
    exec("zip -v 2>&1", $output, $code);
    
    if ($code == 0) {
        $filter = '';
        if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
            $filter = "|grep -v -E '$configFilesRegex'";
        }
        
        exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
        if ($code == 0) {
            file_put_contents($infoFile, $info);
            $m = array();
            if (!empty($filter)) {
                foreach ($configFiles as $file) {
                    $tmp  = file_get_contents($file);
                    // remove  passwords
                    $tmp  = preg_replace('~^.*?pass.*~im', '', $tmp);
                    // new file name
                    $file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
                    file_put_contents($file, $tmp);
                    $m[] = $file;
                }
            }
            
            exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
            stdOut("\nCreate archive '" . realpath($archive) . "'");
            stdOut("This archive have password '$g_QuarantinePass'");
            foreach ($m as $file)
                unlink($file);
            unlink($infoFile);
            return;
        }
    }
    
    $zip = new ZipArchive;
    
    if ($zip->open($archive, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === false) {
        stdOut("Cannot create '$archive'.");
        return;
    }
    
    foreach ($files as $file) {
        if (in_array($file, $configFiles)) {
            $tmp = file_get_contents($file);
            // remove  passwords
            $tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
            $zip->addFromString($file, $tmp);
        } else {
            $zip->addFile($file);
        }
    }
    $zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
    $zip->addFile($report, REPORT_FILE);
    $zip->addFromString($infoFile, $info);
    $zip->close();
    
    stdOut("\nCreate archive '" . realpath($archive) . "'.");
    stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir) {
    global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, $defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    
    $l_DirCounter          = 0;
    $l_DoorwayFilesCounter = 0;
    $l_SourceDirIndex      = $g_Counter - 1;
    
    QCR_Debug('Check ' . $l_RootDir);
    
    if ($l_DIRH = @opendir($l_RootDir)) {
        while (($l_FileName = readdir($l_DIRH)) !== false) {
            if ($l_FileName == '.' || $l_FileName == '..')
                continue;
            
            $l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;
            
            $l_Type  = filetype($l_FileName);
            $l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else if ($l_Type != "file" && (!$l_IsDir)) {
                $g_UnixExec[] = $l_FileName;
                continue;
            }
            
            $l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);
            
            $l_NeedToScan = true;
            $l_Ext2       = substr(strstr(basename($l_FileName), '.'), 1);
            if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                $l_NeedToScan = false;
            }
            
            // if folder in ignore list
            $l_Skip = false;
            for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                    if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                        $l_SkipSample[] = $g_DirIgnoreList[$dr];
                    } else {
                        $l_Skip       = true;
                        $l_NeedToScan = false;
                    }
                }
            }
            
            if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE)
                $l_NeedToScan = false;
            
            if ($l_IsDir) {
                // skip on ignore
                if ($l_Skip) {
                    $g_SkippedFolders[] = $l_FileName;
                    continue;
                }
                
                $l_BaseName = basename($l_FileName);
                
                $l_DirCounter++;
                
                $g_Counter++;
                $g_FoundTotalDirs++;
                
                QCR_IntegrityCheck($l_FileName);
                
            } else {
                if ($l_NeedToScan) {
                    $g_FoundTotalFiles++;
                    $g_Counter++;
                }
            }
            
            if (!$l_NeedToScan)
                continue;
            
            if (IMAKE) {
                write_integrity_db_file($l_FileName);
                continue;
            }
            
            // ICHECK
            // skip if known and not modified.
            if (icheck($l_FileName))
                continue;
            
            $l_Buffer .= getRelativePath($l_FileName);
            $l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";
            
            if (strlen($l_Buffer) > 32000) {
                file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
                $l_Buffer = '';
            }
            
        }
        
        closedir($l_DIRH);
    }
    
    if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
        file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
        $l_Buffer = '';
    }
    
    if (($l_RootDir == ROOT_PATH)) {
        write_integrity_db_file();
    }
    
}


function getRelativePath($l_FileName) {
    return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}

/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
    global $g_IntegrityDB, $g_ICheck;
    static $l_Buffer = '';
    static $l_status = array('modified' => 'modified', 'added' => 'added');
    
    $l_RelativePath = getRelativePath($l_FileName);
    $l_known        = isset($g_IntegrityDB[$l_RelativePath]);
    
    if (is_dir($l_FileName)) {
        if ($l_known) {
            unset($g_IntegrityDB[$l_RelativePath]);
        } else {
            $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        }
        return $l_known;
    }
    
    if ($l_known == false) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
        return false;
    }
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    if ($g_IntegrityDB[$l_RelativePath] != $hash) {
        $g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
        return false;
    }
    
    unset($g_IntegrityDB[$l_RelativePath]);
    return true;
}

function write_integrity_db_file($l_FileName = '') {
    static $l_Buffer = '';
    
    if (empty($l_FileName)) {
        empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
        return;
    }
    
    $l_RelativePath = getRelativePath($l_FileName);
    
    $hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
    
    $l_Buffer .= "$l_RelativePath|$hash\n";
    
    if (strlen($l_Buffer) > 32000) {
        file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
        $l_Buffer = '';
    }
}

function load_integrity_db() {
    global $g_IntegrityDB;
    file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);
    
    $s_file = new SplFileObject('compress.zlib://' . INTEGRITY_DB_FILE);
    $s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
    
    foreach ($s_file as $line) {
        $i = strrpos($line, '|');
        if (!$i)
            continue;
        $g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i + 1);
    }
    
    $s_file = null;
}


function getStdin()
{
    $stdin  = '';
    $f      = @fopen('php://stdin', 'r');
    while($line = fgets($f)) 
    {
        $stdin .= $line;
    }
    fclose($f);
    return $stdin;
}

function OptimizeSignatures() {
    global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
    global $g_JSVirSig, $gX_JSVirSig;
    global $g_AdwareSig;
    global $g_PhishingSig;
    global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;
    
    (AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
    (AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
    $gX_FlexDBShe = $gXX_FlexDBShe = array();
    
    (AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
    $gX_JSVirSig = array();
    
    $count = count($g_FlexDBShe);
    
    for ($i = 0; $i < $count; $i++) {
        if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)')
            $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
        if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e')
            $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
        if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.')
            $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';
        
        $g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);
        
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
        $g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
    }
    
    optSig($g_FlexDBShe);
    
    optSig($g_JSVirSig);
    optSig($g_AdwareSig);
    optSig($g_PhishingSig);
    optSig($g_SusDB);
    //optSig($g_SusDBPrio);
    //optSig($g_ExceptFlex);
    
    // convert exception rules
    $cnt = count($g_ExceptFlex);
    for ($i = 0; $i < $cnt; $i++) {
        $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
        if (!strlen($g_ExceptFlex[$i]))
            unset($g_ExceptFlex[$i]);
    }
    
    $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs) {
    $sigs = array_unique($sigs);
    
    // Add SigId
    foreach ($sigs as &$s) {
        $s .= '(?<X' . myCheckSum($s) . '>)';
    }
    unset($s);
    
    $fix = array(
        '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
        'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
        '\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
        '[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
    );
    
    $sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
    
    $fix = array(
        '~^\\\\[d]\+&@~' => '&@(?<=\d..)',
        '~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
    );
    
    $sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);
    
    optSigCheck($sigs);
    
    $tmp = array();
    foreach ($sigs as $i => $s) {
        if (!preg_match('#^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$#', $s)) {
            unset($sigs[$i]);
            $tmp[] = $s;
        }
    }
    
    usort($sigs, 'strcasecmp');
    $txt = implode("\n", $sigs);
    
    for ($i = 24; $i >= 1; ($i > 4) ? $i -= 4 : --$i) {
        $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
    }
    
    $sigs = array_merge(explode("\n", $txt), $tmp);
    
    optSigCheck($sigs);
}

function optMergePrefixes($m) {
    $limit = 8000;
    
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $len = $prefix_len;
    $r   = array();
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        
        if (strlen($line) > $limit) {
            $r[] = $line;
            continue;
        }
        
        $s = substr($line, $prefix_len);
        $len += strlen($s);
        if ($len > $limit) {
            if (count($suffixes) == 1) {
                $r[] = $prefix . $suffixes[0];
            } else {
                $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
            }
            $suffixes = array();
            $len      = $prefix_len + strlen($s);
        }
        $suffixes[] = $s;
    }
    
    if (!empty($suffixes)) {
        if (count($suffixes) == 1) {
            $r[] = $prefix . $suffixes[0];
        } else {
            $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
        }
    }
    
    return implode("\n", $r);
}

function optMergePrefixes_Old($m) {
    $prefix     = $m[1];
    $prefix_len = strlen($prefix);
    
    $suffixes = array();
    foreach (explode("\n", $m[0]) as $line) {
        $suffixes[] = substr($line, $prefix_len);
    }
    
    return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs) {
    $result = true;
    
    foreach ($sigs as $k => $sig) {
        if (trim($sig) == "") {
            if (DEBUG_MODE) {
                echo ("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
        
        if (@preg_match('#' . $sig . '#smiS', '') === false) {
            $error = error_get_last();
            if (DEBUG_MODE) {
                echo ("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
            }
            unset($sigs[$k]);
            $result = false;
        }
    }
    
    return $result;
}

function _hash_($text) {
    static $r;
    
    if (empty($r)) {
        for ($i = 0; $i < 256; $i++) {
            if ($i < 33 OR $i > 127)
                $r[chr($i)] = '';
        }
    }
    
    return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) {
    global $defaults;

    if (empty($list))
        return array();
    
    $file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';
    if (isset($defaults['avdb'])) {
       $file = dirname($defaults['avdb']) . '/AIBOLIT-WHITELIST.db';
    }

    if (!file_exists($file)) {
        return array();
    }
    
    $snum = max(0, @filesize($file) - 1024) / 20;
    stdOut("\nLoaded " . ceil($snum) . " known files from " . $file . "\n");
    
    sort($list);
    
    $hash = reset($list);
    
    $fp = @fopen($file, 'rb');
    
    if (false === $fp)
        return array();
    
    $header = unpack('V256', fread($fp, 1024));
    
    $result = array();
    
    foreach ($header as $chunk_id => $chunk_size) {
        if ($chunk_size > 0) {
            $str = fread($fp, $chunk_size);
            
            do {
                $raw = pack("H*", $hash);
                $id  = ord($raw[0]) + 1;
                
                if ($chunk_id == $id AND binarySearch($str, $raw)) {
                    $result[] = $hash;
                }
                
            } while ($chunk_id >= $id AND $hash = next($list));
            
            if ($hash === false)
                break;
        }
    }
    
    fclose($fp);
    
    return $result;
}


function binarySearch($str, $item) {
    $item_size = strlen($item);
    if ($item_size == 0)
        return false;
    
    $first = 0;
    
    $last = floor(strlen($str) / $item_size);
    
    while ($first < $last) {
        $mid = $first + (($last - $first) >> 1);
        $b   = substr($str, $mid * $item_size, $item_size);
        if (strcmp($item, $b) <= 0)
            $last = $mid;
        else
            $first = $mid + 1;
    }
    
    $b = substr($str, $last * $item_size, $item_size);
    if ($b == $item) {
        return true;
    } else {
        return false;
    }
}

function getSigId($l_Found) {
    foreach ($l_Found as $key => &$v) {
        if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
            return substr($key, 1);
        }
    }
    
    return null;
}

function die2($str) {
    if (function_exists('aibolit_onFatalError')) {
        aibolit_onFatalError($str);
    }
    die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
    global $g_DeMapper;
    
    if ($l_DeobfType != '') {
        if (DEBUG_MODE) {
            stdOut("\n-----------------------------------------------------------------------------\n");
            stdOut("[DEBUG]" . $l_Filename . "\n");
            var_dump(getFragment($l_Unwrapped, $l_Pos));
            stdOut("\n...... $l_DeobfType ...........\n");
            var_dump($l_Unwrapped);
            stdOut("\n");
        }
        
        switch ($l_DeobfType) {
            case '_GLOBALS_':
                foreach ($g_DeMapper as $fkey => $fvalue) {
                    if (DEBUG_MODE) {
                        stdOut("[$fkey] => [$fvalue]\n");
                    }
                    
                    if ((strpos($l_Filename, $fkey) !== false) && (strpos($l_Unwrapped, $fvalue) !== false)) {
                        if (DEBUG_MODE) {
                            stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                        }
                        
                        return true;
                    }
                }
                break;
        }
        
        
        return false;
    }
}

$full_code = '';

function deobfuscate_bitrix($str) {
    $res      = $str;
    $funclist = array();
    $strlist  = array();
    $res      = preg_replace("|[\"']\s*\.\s*['\"]|smi", '', $res);
    $res      = preg_replace_callback('~(?:min|max)\(\s*\d+[\,\|\s\|+\|\-\|\*\|\/][\d\s\.\,\+\-\*\/]+\)~ms', "calc", $res);
    $res = preg_replace_callback('|(round\((.+?)\))|smi', function($matches) {
        return round($matches[2]);
    }, $res);
    $res = preg_replace_callback('|base64_decode\(["\'](.*?)["\']\)|smi', function($matches) {
        return "'" . base64_decode($matches[1]) . "'";
    }, $res);
    
    $res = preg_replace_callback('|["\'](.*?)["\']|sm', function($matches) {
        $temp = base64_decode($matches[1]);
        if (base64_encode($temp) === $matches[1] && preg_match('#^[ -~]*$#', $temp)) {
            return "'" . $temp . "'";
        } else {
            return "'" . $matches[1] . "'";
        }
    }, $res);
    
    
    if (preg_match_all('|\$GLOBALS\[\'(.+?)\'\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $varname            = $found[1];
            $funclist[$varname] = explode(',', $found[2]);
            $funclist[$varname] = array_map(function($value) {
                return trim($value, "'");
            }, $funclist[$varname]);
            
            $res = preg_replace_callback('|\$GLOBALS\[\'' . $varname . '\'\]\[(\d+)\]|smi', function($matches) use ($varname, $funclist) {
                return $funclist[$varname][$matches[1]];
            }, $res);
        }
    }
    
    
    if (preg_match_all('|function\s*(\w{1,60})\(\$\w+\){\$\w{1,60}\s*=\s*Array\((.{1,30000}?)\);[^}]+}|smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode(',', $found[2]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|smi', function($matches) use ($strlist) {
                return $strlist[$matches[1]];
            }, $res);
            
            //$res = preg_replace('~' . quotemeta(str_replace('~', '\\~', $found[0])) . '~smi', '', $res);
        }
    }
    
    $res = preg_replace('~<\?(php)?\s*\?>~smi', '', $res);
    if (preg_match_all('~<\?\s*function\s*(_+(.{1,60}?))\(\$[_0-9]+\)\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.{1,30000}?\$\3=array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds, PREG_SET_ORDER)) {
        foreach ($founds as $found) {
            $strlist = explode("',", $found[5]);
            $res = preg_replace_callback('|' . $found[1] . '\((\d+)\)|sm', function($matches) use ($strlist) {
                return $strlist[$matches[1]] . "'";
            }, $res);
            
        }
    }
    
    return $res;
}

function calc($expr) {
    if (is_array($expr))
        $expr = $expr[0];
    preg_match('~(min|max)?\(([^\)]+)\)~msi', $expr, $expr_arr);
    if ($expr_arr[1] == 'min' || $expr_arr[1] == 'max')
        return $expr_arr[1](explode(',', $expr_arr[2]));
    else {
        preg_match_all('~([\d\.]+)([\*\/\-\+])?~', $expr, $expr_arr);
        if (in_array('*', $expr_arr[2]) !== false) {
            $pos  = array_search('*', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] * $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "*" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('/', $expr_arr[2]) !== false) {
            $pos  = array_search('/', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] / $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "/" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('-', $expr_arr[2]) !== false) {
            $pos  = array_search('-', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] - $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "-" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } elseif (in_array('+', $expr_arr[2]) !== false) {
            $pos  = array_search('+', $expr_arr[2]);
            $res  = $expr_arr[1][$pos] + $expr_arr[1][$pos + 1];
            $expr = str_replace($expr_arr[1][$pos] . "+" . $expr_arr[1][$pos + 1], $res, $expr);
            $expr = calc($expr);
        } else {
            return $expr;
        }
        
        return $expr;
    }
}

function my_eval($matches) {
    $string = $matches[0];
    $string = substr($string, 5, strlen($string) - 7);
    return decode($string);
}

function decode($string, $level = 0) {
    if (trim($string) == '')
        return '';
    if ($level > 100)
        return '';
    
    if (($string[0] == '\'') || ($string[0] == '"')) {
        return substr($string, 1, strlen($string) - 2); //
    } elseif ($string[0] == '$') {
        global $full_code;
        $string = str_replace(")", "", $string);
        preg_match_all('~\\' . $string . '\s*=\s*(\'|")([^"\']+)(\'|")~msi', $full_code, $matches);
        return $matches[2][0]; //
    } else {
        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
        
        $arg = decode(substr($string, $pos + 1), $level + 1);
        if (strtolower($function) == 'base64_decode')
            return @base64_decode($arg);
        else if (strtolower($function) == 'gzinflate')
            return @gzinflate($arg);
        else if (strtolower($function) == 'gzuncompress')
            return @gzuncompress($arg);
        else if (strtolower($function) == 'strrev')
            return @strrev($arg);
        else if (strtolower($function) == 'str_rot13')
            return @str_rot13($arg);
        else
            return $arg;
    }
}

function deobfuscate_eval($str) {
    global $full_code;
    $res = preg_replace_callback('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress).*?\);~msi', "my_eval", $str);
    return str_replace($str, $res, $full_code);
}

function getEvalCode($string) {
    preg_match("/eval\((.*?)\);/", $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}

function getTextInsideQuotes($string) {
    if (preg_match_all('/("(.*?)")/', $string, $matches))
        return @end(end($matches));
    elseif (preg_match_all('/(\'(.*?)\')/', $string, $matches))
        return @end(end($matches));
    else
        return '';
}

function deobfuscate_lockit($str) {
    $obfPHP        = $str;
    $phpcode       = base64_decode(getTextInsideQuotes(getEvalCode($obfPHP)));
    $hexvalues     = getHexValues($phpcode);
    $tmp_point     = getHexValues($obfPHP);
    $pointer1      = hexdec($tmp_point[0]);
    $pointer2      = hexdec($hexvalues[0]);
    $pointer3      = hexdec($hexvalues[1]);
    $needles       = getNeedles($phpcode);
    $needle        = $needles[count($needles) - 2];
    $before_needle = end($needles);
    
    
    $phpcode = base64_decode(strtr(substr($obfPHP, $pointer2 + $pointer3, $pointer1), $needle, $before_needle));
    return "<?php {$phpcode} ?>";
}


function getNeedles($string) {
    preg_match_all("/'(.*?)'/", $string, $matches);
    
    return (empty($matches)) ? array() : $matches[1];
}

function getHexValues($string) {
    preg_match_all('/0x[a-fA-F0-9]{1,8}/', $string, $matches);
    return (empty($matches)) ? array() : $matches[0];
}

function deobfuscate_als($str) {
    preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str, $layer1);
    preg_match('~\$[O0]+=(\$[O0]+\()+\$[O0]+,[0-9a-fx]+\),\'([^\']+)\',\'([^\']+)\'\)\);eval\(~msi', base64_decode($layer1[1]), $layer2);
    $res = explode("?>", $str);
    if (strlen(end($res)) > 0) {
        $res = substr(end($res), 380);
        $res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
    }
    return "<?php {$res} ?>";
}

function deobfuscate_byterun($str) {
    global $full_code;
    preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';\s*eval\s*\(\s*\$?\w{1,60}\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\)\s*;~msi', $str, $matches);
    $res = base64_decode($matches[1]);
    $res = strtr($res, '123456aouie', 'aouie123456');
    return "<?php " . str_replace($matches[0], $res, $full_code) . " ?>";
}

function deobfuscate_urldecode($str) {
    preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str, $matches);
    $alph  = urldecode($matches[2]);
    $funcs = $matches[3];
    for ($i = 0; $i < strlen($alph); $i++) {
        $funcs = str_replace($matches[1] . '{' . $i . '}.', $alph[$i], $funcs);
        $funcs = str_replace($matches[1] . '{' . $i . '}', $alph[$i], $funcs);
    }
    
    $str   = str_replace($matches[3], $funcs, $str);
    $funcs = explode(';', $funcs);
    foreach ($funcs as $func) {
        $func_arr = explode("=", $func);
        if (count($func_arr) == 2) {
            $func_arr[0] = str_replace('$', '', $func_arr[0]);
            $str         = str_replace('${"GLOBALS"}["' . $func_arr[0] . '"]', $func_arr[1], $str);
        }
    }
    
    return $str;
}


function formatPHP($string) {
    $string = str_replace('<?php', '', $string);
    $string = str_replace('?>', '', $string);
    $string = str_replace(PHP_EOL, "", $string);
    $string = str_replace(";", ";\n", $string);
    return $string;
}

function deobfuscate_fopo($str) {
    $phpcode = formatPHP($str);
    $phpcode = base64_decode(getTextInsideQuotes(getEvalCode($phpcode)));
    @$phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(end(explode(':', $phpcode))))));
    $old = '';
    while (($old != $phpcode) && (strlen(strstr($phpcode, '@eval($')) > 0)) {
        $old   = $phpcode;
        $funcs = explode(';', $phpcode);
        if (count($funcs) == 5)
            $phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(getEvalCode($phpcode)))));
        else if (count($funcs) == 4)
            $phpcode = gzinflate(base64_decode(getTextInsideQuotes(getEvalCode($phpcode))));
    }
    
    return substr($phpcode, 2);
}

function getObfuscateType($str) {
    if (preg_match('~\$GLOBALS\[\s*[\'"]_+\w{1,60}[\'"]\s*\]\s*=\s*\s*array\s*\(\s*base64_decode\s*\(~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~function\s*_+\d+\s*\(\s*\$i\s*\)\s*{\s*\$a\s*=\s*Array~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str))
        return "ALS-Fullsite";
    if (preg_match('~\$[O0]*=urldecode\(\'%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64\'\);\s*\$GLOBALS\[\'[O0]*\'\]=\$[O0]*~msi', $str))
        return "LockIt!";
    if (preg_match('~\$\w+="(\\\x?[0-9a-f]+){13}";@eval\(\$\w+\(~msi', $str))
        return "FOPO";
    if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms', $str))
        return "ByteRun";
    if (preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str))
        return "urldecode_globals";
    if (preg_match('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress)~msi', $str))
        return "eval";
}

function deobfuscate($str) {
    switch (getObfuscateType($str)) {
        case '_GLOBALS_':
            $str = deobfuscate_bitrix(($str));
            break;
        case 'eval':
            $str = deobfuscate_eval(($str));
            break;
        case 'ALS-Fullsite':
            $str = deobfuscate_als(($str));
            break;
        case 'LockIt!':
            $str = deobfuscate_lockit($str);
            break;
        case 'FOPO':
            $str = deobfuscate_fopo(($str));
            break;
        case 'ByteRun':
            $str = deobfuscate_byterun(($str));
            break;
        case 'urldecode_globals':
            $str = deobfuscate_urldecode(($str));
            break;
    }
    
    return $str;
}

function convertToUTF8($text)
{
    if (function_exists('mb_convert_encoding')) {
       $text = @mb_convert_encoding($text, 'utf-8', 'auto');
       $text = @mb_convert_encoding($text, 'UTF-8', 'UTF-8');
    }

    return $text;
}
