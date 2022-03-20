# Защита от SYN-flood

## Содержание
1. [Сборка](https://github.com/qvntz/xdp-syn-cookie/tree/main#сборка)
2. [Тестовый стенд](#тестовый-стенд)
3. [Задача](#задача)
4. [Псевдокод решения задачи](#псевдокод-решения-задачи)
5. [Технологии](#технологии)


---
## Сборка ##
    
1. Сборка под **Debian 10 kernel 4.19.67**: `make`
2. Сборка под **Arch Linux kernel 5.3.1**:
    1. Переключиться на ветку [arch](https://github.com/qvntz/xdp-syn-cookie/tree/arch): `git switch arch`
    2. `make`
    
После сборки командой `make` мы получим файл `xdp_filter.o`

---
## Тестовый стенд ##
Задача стенда - включать два интерфейса:
1. на котором будет фильтр
2. с которого будут отправляться пакеты

Выбраны устройства типа network, namespaces _(nets)_, т.к. эти сетевые интерфейсы 
соеденины между собой. Стенд присоединяет фильтр на `xdp-local`, 
а с `xdp-remote` будет отправляться входящий трафик. 



Для запуска стенда: `sudo ./stand up` <br>
Для удаления стенда: `sudo ./stand down` <br>
Привязать стенда к интерфейсу: `sudo ./stand attach` <br>
Отвязать стенд от интерфейса: `sudo ./stand detach` <br>
Посмотреть логи: `sudo ./stand log` <br>

---
## Задача ##
Кейс *"Вам печенька"* от компании **DDOS-GUARD**

### Цель ###
Обеспечить защиту веб-сервера от атаки _SYN flood_

Для этого мы реализуем механизм **SYN cookies**.

----
## Псевдокод решения задачи ##
    Если это не Ethernet -> пропустить пакет

    Если это не IPv4 -> пропустить пакет

    Если адрес в таблице проверенных ->
            уменьшить счетчик оставшихся проверок,
            пропустить пакет

    Если это не TCP -> сбросить пакет

    Если это SYN -> ответить SYN-ACK с cookie.

    Если это ACK ->
        если в acknum лежит не cookie ->
            сбросить пакет
        Занести в таблицу адрес с N оставшихся проверок
        Ответить RST

    В остальных случаях сбросить пакет

---
## Технологии ##
1. XDP
2. eBPF
