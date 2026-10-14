# SC2 Editor Dark Theme Activator — технический контекст

## 0. Как работать с этим проектом

Пользователь исследует `SC2Editor_x64.exe` и пытается сделать полноценную тёмную тему.

Главная оставшаяся нерешённая часть темы — **цвет текста owner-draw кнопок/параметров**, особенно семантические цвета вроде зелёного, синего и красного.

Рабочий репозиторий:

`https://github.com/XeXxDD/test6666`

Текущий актуальный исходник на момент перехода в новый чат:

`CODE V74.cpp`

Последний подготовленный эксперимент — **V75**, но его лог ещё не был прислан/проанализирован.

Пользователь работает через собственный диагностический проект `hook_diag`.

### Методология

Пользователь хочет:

* один эксперимент за раз;
* одно изменение кода;
* сборка;
* запуск;
* сырой лог;
* один вывод;
* следующий эксперимент.

Не следует одновременно добавлять несколько независимых хуков.

Пользователь предпочитает инструкции вида:

> найти `X`; внутри него найти `Y`; непосредственно после `Y` вставить `Z`.

Не давать расплывчатых указаний вроде «где-нибудь в WndProc».

`Log()` принимает один `std::string`.

Обычно пользователь прогоняет лог через свой dedup-скрипт, который удаляет полностью одинаковые строки 1-в-1. Это означает, что мы не видим количество подряд идущих абсолютно одинаковых вызовов. Пока это считается приемлемым, поскольку нас интересуют изменения параметров/контекста, а не точное количество идентичных вызовов.

---

# 1. Главная цель

Нужно понять, **как SC2 Editor принимает решение, что конкретный параметр сейчас выбран/активен, и поэтому должен рисоваться зелёным**, а затем использовать это знание для реализации тёмной темы.

Ключевой пример:

* пользователь выбирает действие;
* Editor автоматически выбирает первый параметр;
* этот параметр становится зелёным.

Для одного действия первый параметр называется:

`Variable`

Для другого действия первый параметр называется:

`1`

Это очень полезный A/B-тест:

```text
Action A → Variable становится зелёным

Action B → "1" становится зелёным
```

То есть зелёный цвет связан не с самим названием `Variable`, а с **семантическим состоянием параметра**.

---

# 2. Наблюдаемые визуальные состояния

Установлены следующие цвета:

* **красный** — enabled button без начального значения;
* **синий** — enabled button с начальным значением;
* **серый/тускло-синий** — disabled;
* **зелёный** — Editor автоматически выбрал параметр;
* **розовый/rose** — физическое mouse-down/pressed состояние.

Важно:

### Розовый ≠ зелёный

Ранее розовый ошибочно рассматривался как возможный semantic state.

Позже установлено, что розовый появляется при физическом нажатии кнопки мышью.

Не смешивать это с автоматическим выбором параметра Editor.

---

# 3. Контролы

Основной контрол:

`Variable`

CtlID:

```text
471 = 0x1D7
```

Другой интересующий контрол:

`Value`

CtlID:

```text
473 = 0x1D9
```

Также тестировались динамические параметры:

```text
1
Unit
Point
270.0
Нет параметров
```

---

# 4. Owner-draw

SC2 использует owner-draw путь:

```text
WM_DRAWITEM
    ↓
DRAWITEMSTRUCT
    ↓
native renderer
```

Пример Variable:

```text
itemAction = 0x1
itemState  = 0x0
itemData   = 0
rcItem     = (0,0,79,29)
text       = Variable
```

BUTTON META:

```text
itemState=0x0
style=0x5001400b
exStyle=0x0
GWLP_ID=0x1d7
USERDATA=0x0
```

Value:

```text
itemState=0x4
style=0x5801400b
exStyle=0x0
GWLP_ID=0x1d9
USERDATA=0x0
```

---

# 5. Важный отрицательный результат: ODS_SELECTED

Изначально была гипотеза, что зелёный/фиолетовый цвет связан с:

```text
ODS_SELECTED
```

Эта гипотеза не подтвердилась.

Позже V71/V72 показали, что один и тот же control может менять semantic color, хотя стандартный:

```text
DRAWITEMSTRUCT.itemState
```

остаётся тем же.

Поэтому стандартный owner-draw state не является источником semantic selection.

---

# 6. V71

V71 добавлял диагностику Variable:

```cpp
if (dis->hwndItem == g_hVariable)
{
    std::ostringstream ss;
    ss << "[V71] VARIABLE_DRAW"
       << " hwnd=" << HwndToString(dis->hwndItem)
       << " CtlID=" << dis->CtlID
       << " itemAction=0x" << std::hex << dis->itemAction
       << " itemState=0x" << dis->itemState
       << " itemData=" << reinterpret_cast<void*>(dis->itemData)
       << " hDC=" << reinterpret_cast<void*>(dis->hDC)
       << " rc=("
       << std::dec
       << dis->rcItem.left << ","
       << dis->rcItem.top << ","
       << dis->rcItem.right << ","
       << dis->rcItem.bottom << ")";

    Log(ss.str());
}
```

Результат:

Variable:

```text
itemState=0x0
itemData=0
```

и semantic:

```text
SetTextColor = 0xA000
```

Value:

```text
itemState=0x4
itemData=0
```

и:

```text
SetTextColor = 0x804040
```

Вывод:

`itemState`/`itemData` не объясняют semantic selection.

---

# 7. V72 — очень важный эксперимент

V72 тестировал два действия:

### Действие A

Первый параметр:

```text
1
```

При автоматическом выборе становится зелёным.

### Действие B

Первый параметр:

```text
Variable
```

При автоматическом выборе становится зелёным.

Был добавлен parent HWND.

Во всех тестируемых контролах parent был одинаковым.

Пример:

```text
parent = 0x00000000002A097E
```

Следовательно:

> разные parent HWND не объясняют semantic color.

---

## V72: главный результат

Один и тот же `"1"`:

### Синий

```text
CtlID=471
itemState=0x300
itemData=0
SetTextColor=0xff
```

### Позже зелёный

```text
CtlID=471
itemState=0x300
itemData=0
SetTextColor=0xA000
```

При этом:

* CtlID тот же;
* itemState тот же;
* itemData тот же;
* parent тот же.

Следовательно:

**semantic selection state не находится в стандартном `DRAWITEMSTRUCT.itemState`.**

---

# 8. Очень важная последовательность V72

Перед тем как `"1"` становится зелёным, наблюдалась серия redraw:

```text
seq=29  "1"          → blue
seq=30  Unit
seq=31  "1"
seq=32  Point
seq=33  Unit
seq=34  "1"
seq=35  Point
seq=36  "270.0"
seq=37  "Нет параметров"
seq=38  "1"          → green
```

Это очень важный результат.

Он показывает, что Editor сначала выполняет серию отрисовок, а затем на одном из последующих проходов применяет внутреннее состояние, после чего `"1"` получает зелёный цвет.

Гипотеза:

```text
Editor changes internal semantic state
        ↓
control gets redrawn
        ↓
renderer chooses semantic green
```

---

# 9. GDI state

В разных тестах GDI-состояние часто оставалось одинаковым:

```text
text=0xdcdcdc
bk=0x1e1e1e
bkMode=2
rop2=13
map=1
org=(459,863)
```

или:

```text
org=(459,864)
```

Это не объясняет semantic color.

Один и тот же HDC может использоваться для Variable и Value.

Поэтому HDC сам по себе также не является источником semantic selection.

---

# 10. Реальные semantic colors через SetTextColor

V62/V63 подтвердили, что semantic colors действительно задаются через `SetTextColor`.

Ключевые цвета:

```text
Variable green:
0xA000

Value / red semantic:
0x804040

blue:
0xFF
```

Также встречаются обычные цвета:

```text
0x000000
0xDCDCDC
0xFFFFFF
0x606060
0xC0
0x6D6D6D
и другие
```

Важно:

**не фильтировать диагностику только по `0xA000` / `0x804040` / `0xFF`**, поскольку Editor использует много промежуточных и обычных текстовых цветов.

---

# 11. V64 — общий caller

`_ReturnAddress()` показал один и тот же caller для разных semantic цветов:

```text
00007FF6376BEDC8
```

То есть:

```text
Variable green
Value red
```

могут приходить из одного и того же участка SC2.

---

# 12. V65 — RVA

SC2 module base:

```text
00007FF635770000
```

Caller RVA:

```text
0x1F4EDC8
```

Restore caller RVA:

```text
0x1F4F023
```

Таким образом:

```text
SC2Editor + 0x1F4EDC8
```

стал ключевой точкой исследования.

---

# 13. V66 — машинные байты

Вокруг call-site:

```text
before[-16..-1]=
49 8B CF 48 89 85 C0 03 00 00 FF 15 18 C6 59 01

after[0..31]=
8B 4F 0C 89 4C 24 30
8B 4F 14 89 4C 24 38
8B 4F 08 89 4C 24 34
8B 4F 10 89 4C 24 3C
49 8B CF 89
```

По адресу:

```text
SC2Editor + 0x1F4EDC8
```

байты:

```text
FF 15 18 C6 59 01
```

Это x64:

```asm
CALL qword ptr [RIP + 0x159C618]
```

После CALL:

```asm
8B 4F 0C
8B 4F 14
8B 4F 08
8B 4F 10
```

То есть код обращается к:

```text
[RDI+0x0C]
[RDI+0x14]
[RDI+0x08]
[RDI+0x10]
```

Пока неизвестно, что именно представляют собой эти четыре поля.

---

# 14. Критически важная новая находка перед V75

Перед CALL находятся байты:

```asm
49 8B CF
```

Это:

```asm
mov r9,rdi
```

Следовательно, непосредственно перед вызовом `SetTextColor` SC2 копирует:

```text
RDI → R9
```

А на Windows x64:

```text
RCX = arg1
RDX = arg2
R8  = arg3
R9  = arg4
```

Поэтому была сформирована гипотеза:

```text
RDI
 ↓
mov r9,rdi
 ↓
CALL SetTextColor
 ↓
HookSetTextColor(..., arg4)
```

Это потенциально позволяет получить внутренний объект SC2, на который указывает RDI, **не патча машинный код**.

---

# 15. V69/V70 — IAT направление

V69:

```text
[V69] IAT callSite=00007FF6376BEDC2
iatSlot=00007FF638C5B3E0
bytes=49 0A DE 71 32 02 00 00
actualTarget=0000023271DE0A49
g_realSetTextColor=00007FF8B1C70120
```

Важно:

* это `FF 15 ...` indirect CALL;
* адрес вычисляемой памяти был:

```text
00007FF638C5B3E0
```

* содержимое не выглядело как обычный code pointer;
* `g_realSetTextColor` может быть Detours trampoline;
* нельзя утверждать, что это оригинальный target;
* нельзя называть `iatSlot` настоящим IAT slot.

V70:

```text
IAT_MEMORY
address=00007FF638C5B3E0
queryResult=48
allocationBase=00007FF635770000
baseAddress=00007FF638C5B000
regionSize=d95000
state=0x1000
protect=0x20
type=0x40000
```

Память:

```text
MEM_MAPPED
PAGE_EXECUTE_READ
```

и allocationBase совпадает с SC2 image base.

Это направление пока заморожено.

**Не возвращаться к IAT/hex без отдельной причины.**

---

# 16. Hardware breakpoints / внешний debugger

Попытки с hardware execution breakpoints / внешним debugger приводили к немедленному падению SC2.

Поэтому:

**не предлагать снова hardware breakpoints или внешний debugger.**

Также `_AddressOfReturnAddress()` не даёт RDI и не следует использовать его как способ получить RDI.

---

# 17. V73 — полный SetTextColor

Цель V73:

логировать **каждый** вызов `SetTextColor`, а не только semantic colors.

Логирование `[V66] SetTextColor` было перенесено в самое начало `HookSetTextColor`, до проверки:

```cpp
if (hdc != nullptr)
```

Получился огромный лог, около 1445 вызовов.

В нём были:

```text
0xA000
0x804040
0xFF
0x000000
0xDCDCDC
0xFFFFFF
0x606060
0xC0
и другие
```

Это подтвердило, что полный поток `SetTextColor` очень шумный, но содержит переходы между semantic и обычными цветами.

---

# 18. V74

Цель V74 — добавить foreground window и PID к каждому `SetTextColor`.

Текущий блок был сделан примерно так:

```cpp
HWND fg = GetForegroundWindow();

DWORD fgPid = 0;
if (fg)
    GetWindowThreadProcessId(fg, &fgPid);

std::ostringstream ssAll;

ssAll << "[V74] SetTextColor"
      << " hDC=" << reinterpret_cast<void*>(hdc)
      << " color=0x"
      << std::hex
      << static_cast<unsigned int>(color)
      << " foreground="
      << reinterpret_cast<void*>(fg)
      << " fgPID="
      << std::dec
      << fgPid;

Log(ssAll.str());
```

Изначально использовался:

```cpp
HwndToString(fg)
```

но текущий `CODE V74.cpp` не содержит/не видит `HwndToString`, поэтому это было исправлено на:

```cpp
reinterpret_cast<void*>(fg)
```

---

# 19. V74-1

Лог:

`LOG V74-1.txt`

В V74-1 были видны:

* `0xA000` для зелёного;
* `0x804040`;
* `0xFF`;
* `0xC0`;
* `0xDCDCDC`;
* `0x606060`;
* и другие цвета.

Также видно, что foreground PID действительно меняется.

Например, Editor PID в одном запуске:

```text
43484
```

а другой foreground PID:

```text
10868
```

Следовательно, V74 действительно позволяет различать вызовы по активному foreground process.

---

# 20. Вывод по V74

V74 полезен как контрольный эксперимент, но **не является непосредственным поиском источника semantic selection**.

Он проверяет влияние активного окна.

Основной вопрос всё ещё:

```text
где SC2 решает:

"этот параметр сейчас выбран"

и поэтому выбрать 0xA000?
```

Мы уже знаем, что решение происходит раньше конечного `SetTextColor`.

---

# 21. Почему dedup сейчас допустим

Пользователь использует dedup, который удаляет полностью одинаковые строки.

Да:

```text
SetTextColor(A)
SetTextColor(A)
SetTextColor(A)
```

может превратиться в одну строку.

Но пока это не проблема.

Нас сейчас интересуют:

```text
blue → green
green → blue
```

и изменения:

```text
HDC
foreground
PID
color
контекст
```

Если в будущем понадобится узнать **точное число одинаковых вызовов**, тогда dedup станет мешать.

Пока его оставляем.

---

# 22. Текущая гипотеза

Наиболее перспективная цепочка сейчас:

```text
внутреннее состояние SC2
        ↓
рендер объекта параметра
        ↓
внутренний объект / структура
        ↓
RDI
        ↓
mov r9,rdi
        ↓
CALL SetTextColor
        ↓
HookSetTextColor
        ↓
0xA000 / 0x804040 / 0xFF
```

Мы хотим проверить, действительно ли `RDI` указывает на объект, содержащий данные, которые отличаются между:

```text
blue
```

и:

```text
green
```

---

# 23. V75 — последний подготовленный эксперимент

V75 ещё не был запущен/проанализирован на момент перехода.

Идея:

изменить сигнатуру:

```cpp
static COLORREF WINAPI HookSetTextColor(HDC hdc, COLORREF color)
```

на:

```cpp
static COLORREF WINAPI HookSetTextColor(
    HDC hdc,
    COLORREF color,
    ULONG_PTR arg3,
    ULONG_PTR arg4
)
```

Поскольку на Windows x64:

```text
RCX = hdc
RDX = color
R8  = arg3
R9  = arg4
```

а непосредственно перед call-site есть:

```asm
49 8B CF
```

то есть:

```asm
mov r9,rdi
```

гипотеза:

```text
arg4 == RDI
```

---

# 24. V75 диагностический блок

Предложенный блок должен находиться внутри `HookSetTextColor`.

Идея была:

```cpp
// ========================= V75 RDI TEST =========================
HMODULE hModuleV75 = nullptr;

if (GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(caller),
        &hModuleV75))
{
    MODULEINFO moduleInfoV75{};

    if (GetModuleInformation(
            GetCurrentProcess(),
            hModuleV75,
            &moduleInfoV75,
            sizeof(moduleInfoV75)))
    {
        ULONG_PTR baseV75 =
            reinterpret_cast<ULONG_PTR>(
                moduleInfoV75.lpBaseOfDll
            );

        ULONG_PTR callerAddrV75 =
            reinterpret_cast<ULONG_PTR>(caller);

        ULONG_PTR offsetV75 =
            callerAddrV75 - baseV75;

        if (offsetV75 == 0x1F4EDC8 &&
            (color == 0xA000 ||
             color == 0x804040))
        {
            ULONG_PTR rdiValue = arg4;

            ULONG_PTR field08 = 0;
            ULONG_PTR field0C = 0;
            ULONG_PTR field10 = 0;
            ULONG_PTR field14 = 0;

            if (rdiValue != 0)
            {
                field08 = *reinterpret_cast<ULONG_PTR*>(
                    rdiValue + 0x08
                );

                field0C = *reinterpret_cast<ULONG_PTR*>(
                    rdiValue + 0x0C
                );

                field10 = *reinterpret_cast<ULONG_PTR*>(
                    rdiValue + 0x10
                );

                field14 = *reinterpret_cast<ULONG_PTR*>(
                    rdiValue + 0x14
                );
            }

            std::ostringstream ssV75;

            ssV75 << "[V75] OBJECT"
                  << " color=0x"
                  << std::hex
                  << static_cast<unsigned int>(color)
                  << " RDI=0x"
                  << rdiValue
                  << " +08=0x"
                  << field08
                  << " +0C=0x"
                  << field0C
                  << " +10=0x"
                  << field10
                  << " +14=0x"
                  << field14;

            Log(ssV75.str());
        }
    }
}
// ========================= V75 RDI TEST END =========================
```

В V75 предполагается использовать уже существующий:

```cpp
void* caller = _ReturnAddress();
```

и существующую проверку call-site:

```text
offset == 0x1F4EDC8
```

---

# 25. Что именно хотим увидеть в V75

Нужны пары:

### Синий

```text
color=0xFF
RDI=...
+08=...
+0C=...
+10=...
+14=...
```

### Зелёный

```text
color=0xA000
RDI=...
+08=...
+0C=...
+10=...
+14=...
```

Особенно интересует:

```text
blue:
+08 = A
+0C = B
+10 = C
+14 = D

green:
+08 = A'
+0C = B
+10 = C
+14 = D
```

Если одно поле меняется синхронно с semantic selection — это потенциально наш внутренний state.

Если все поля одинаковы — это тоже полезный отрицательный результат.

---

# 26. Важное замечание по V75

V75 пока является **гипотезой**, а не установленным фактом.

Нужно проверить:

```text
arg4 == RDI
```

и не ломает ли изменение сигнатуры существующий Detours hook.

Если V75 падает или даёт бессмысленные данные, не следует автоматически считать гипотезу неверной: нужно отдельно проверить ABI/hook declaration.

---

# 27. Что уже НЕ надо делать

Не возвращаться без причины к:

### Hardware breakpoints

Уже приводили к падению SC2.

### Внешнему debugger

То же самое — нестабильно для данного процесса.

### Широким WndProc hooks

Мы уже получили достаточно информации из owner-draw.

### Бесконечному расширению DRAWITEMSTRUCT

`itemState`, `itemData`, parent и т.д. уже не объяснили green state.

### IAT/hex направлению V69/V70

Пока заморожено.

### `HwndToString`

В текущем коде его нет/он недоступен. Для новых логов использовать:

```cpp
reinterpret_cast<void*>(hwnd)
```

### Возврату к старым CODE Vxx

Старые исходники могут оставаться в истории/контексте, но **актуальным исходником считать только тот, который пользователь последним подтвердил**.

На момент этой выжимки:

```text
CODE V74.cpp
```

---

# 28. Известные проблемы компиляции из истории

Были ошибки:

### V74

Ошибка:

```text
неоднозначный operator <<
```

из-за:

```cpp
<< hdc
```

Исправлено на:

```cpp
<< reinterpret_cast<void*>(hdc)
```

Затем:

```text
HwndToString: идентификатор не найден
```

Исправлено на:

```cpp
<< reinterpret_cast<void*>(fg)
```

---

# 29. История версий в сжатом виде

```text
V51
  первоначальная диагностика Variable / owner draw

V53
  изменения после первых DRAWITEM тестов

V54
  DRAWITEM + BUTTON META
  Variable CtlID 471
  Value CtlID 473

V55
  дальнейшая диагностика WndProc/state

V56
  исследование гипотезы, что controls сначала рисуются
  одним базовым цветом, затем Editor применяет state

V62
  ExtTextOutW/SetTextColor направление
  ExtTextOutW позже отключён

V63
  подтверждены semantic SetTextColor colors

V64
  общий _ReturnAddress caller

V65
  caller RVA 0x1F4EDC8
  restore RVA 0x1F4F023

V66
  hex вокруг call-site
  обнаружены:
  FF 15...
  и чтения [RDI+08/+0C/+10/+14]

V67
  дополнительная диагностика call-site

V69
  попытка понять indirect CALL/IAT

V70
  VirtualQuery по адресу call memory
  направление заморожено

V71
  доказано, что itemState/itemData не объясняют green

V72
  A/B тест "1" vs Variable
  parent одинаковый
  itemState может оставаться 0x300 при blue→green

V73
  полный поток SetTextColor

V74
  полный SetTextColor + foreground HWND/PID

V75
  план: использовать mov r9,rdi
  получить RDI как arg4
  прочитать [RDI+08/+0C/+10/+14]
```

---

# 30. Что сейчас считать установленным

Самые надёжные факты:

1. SC2 Editor использует owner-draw для этих кнопок.

2. Зеленый цвет не объясняется простым `ODS_SELECTED`.

3. Зеленый semantic state не обязан менять `DRAWITEMSTRUCT.itemState`.

4. `itemData` остаётся `0`.

5. Parent HWND одинаковый для тестируемых параметров.

6. Один и тот же control может быть:

   ```text
   blue → green
   ```

   при одинаковом стандартном owner-draw state.

7. `SetTextColor` действительно получает:

   ```text
   0xA000
   ```

   для green.

8. Один и тот же call-site SC2 участвует в разных semantic colors.

9. Этот call-site:

   ```text
   SC2Editor + 0x1F4EDC8
   ```

10. Перед CALL есть:

    ```asm
    49 8B CF
    ```

    то есть:

    ```asm
    mov r9,rdi
    ```

11. Сразу после CALL код читает:

    ```asm
    [RDI+0x0C]
    [RDI+0x14]
    [RDI+0x08]
    [RDI+0x10]
    ```

12. Поэтому RDI → R9 является сейчас наиболее перспективной точкой для следующего эксперимента.

---

# 31. Главная нерешённая задача

Найти источник:

```text
"этот параметр сейчас выбран"
```

который приводит к:

```text
SetTextColor(0xA000)
```

и затем использовать это знание для тёмной темы.

Нам не нужно просто заменить:

```text
0xA000
```

на другой цвет.

Нужно понять semantic color selection, потому что это последний существенный неизвестный элемент механизма тёмной темы.

---

# 32. Следующий шаг

Запустить **V75**.

Тест:

1. Запустить `hook_diag`.
2. Дождаться Editor.
3. Выбрать действие, где первый параметр:

   ```text
   1
   ```
4. Получить его обычное синее состояние и затем зелёное.
5. Выбрать действие, где:

   ```text
   Variable
   ```

   становится зелёным.
6. Сделать несколько переходов туда/обратно.
7. Обычный dedup оставить включённым.
8. Прислать **весь `LOG V75.txt`**.

Нужно искать прежде всего:

```text
[V75] OBJECT color=0xA000 ...
```

и сравнивать с:

```text
[V75] OBJECT color=...
```

для того же параметра в обычном состоянии.

Особенно:

```text
RDI
+08
+0C
+10
+14
```

---

# 33. Рабочая философия дальнейшего поиска

Если V75 найдёт меняющееся поле:

```text
RDI+XX
```

следующий шаг:

```text
кто записывает это поле?
```

Если V75 не найдёт различий:

```text
RDI+08/+0C/+10/+14 одинаковы
```

следующий шаг:

```text
ищем другое поле / другой объект / данные до выбора цвета
```

Но не расширять сразу всё.

Всегда:

```text
один эксперимент
→ один факт
→ одна гипотеза
→ следующий эксперимент
```

Главная цель — не собрать бесконечный лог, а постепенно локализовать конкретный internal semantic selection state SC2 Editor.
