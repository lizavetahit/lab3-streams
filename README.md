# Лабораторна робота №3

**Виконала:** Хитрук Ліза, група ІА-42

**Тема:** Нескінченні послідовності в Java Stream API, Optional та Stream Gatherers

## Опис
Сервіс `SecurityLogAnalyzer` (пакет `ua.kpi.comsys.streams`) аналізує нескінченний потік
безпекових подій `SecurityLog`:

- `findFirstCriticalEvent` — знаходить першу подію з рівнем `CRITICAL` (`filter` + `findFirst`, результат в `Optional`);
- `getLogsBeforeDeadline` — збирає події, доки не настане дедлайн (`takeWhile`);
- `detectIpBursts` — за допомогою власного Gatherer `IpBurstGatherer` знаходить IP-адреси,
  від яких надійшло `burstThreshold` подій поспіль, і зупиняє обробку після `maxIpsToReport` IP.

## Варіант
V = N mod 3 = 14 mod 3 = **2** — обробка безпекових подій.

## Вимоги
JDK 17+ для запуску Gradle. Для компіляції потрібна Java 24 (Stream Gatherers) —
Gradle завантажить її автоматично при першому запуску.

## Запуск тестів

```
./gradlew test
```
