# Отчёт о готовности к публикации

Дата проверки: 2026-08-31.

## Итог: НЕ ГОТОВ К ПУБЛИКАЦИИ

Репозиторий остаётся приватным. Тег, публичный выпуск и смена видимости не выполнялись. Это ожидаемое состояние до завершения реальных внешних испытаний.

## Что уже подтверждено

- GitHub repository `A1exZabr/EzOpenPN` приватный, не является fork и использует нейтральное описание.
- Default branch называется `main`.
- Для GitHub Actions включено обязательное закрепление действий полным commit SHA.
- Default workflow permissions установлены в read-only, workflow не могут одобрять pull request review.
- Локальная история имеет один root commit.
- Исторический скан текущей зафиксированной истории проверил 1023 объекта, 74 commit и 427 blob без запрещённого текста, запрещённой типографики и очевидного секретного материала.
- CI и CodeQL прошли для последнего отправленного implementation commit до добавления этого отчёта.
- Браузерная матрица прошла 9 сценариев, включая мобильный viewport, клавиатурное управление и отсутствие serious или critical accessibility findings.
- Статические release, security, documentation и VM contract tests прошли локально.
- Репозиторий содержит ручные workflows для immutable images, четырёх чистых систем, внешнего evidence и подписанного выпуска.

## Блокирующие проверки

Последний запуск `bash tools/publication_audit.sh` вернул следующие ожидаемые блокеры:

- `external_evidence_missing`: нет реальных результатов fixed, mobile и client matrix;
- `workflow_missing:images`: финальные подписанные образы для release commit ещё не собраны;
- `workflow_missing:vm_matrix`: полный прогон Ubuntu 22.04, Ubuntu 24.04, Debian 12 и Debian 13 ещё не выполнен;
- `workflow_missing:evidence`: evidence workflow не может пройти до появления реальных результатов;
- `local_branch_not_main` и `local_remote_main_mismatch`: кандидат ещё находится в feature branch;
- `signed_release_tag_missing`: подписанный `v0.1.0` ещё не создан;
- `private_release_missing`: проверенный приватный выпуск ещё не создан.

Предупреждение `branch_protection_deferred_by_private_plan` связано с ограничением текущего GitHub plan: branch protection и rulesets недоступны для этого приватного репозитория. Публичным только ради включения этой настройки репозиторий не делается. До смены видимости используются read-only workflow permissions, обязательное SHA pinning и ручные release gates. После законной смены видимости branch protection становится обязательной проверкой public-фазы аудита.

## Порядок снятия блокеров

1. Зафиксировать и отправить инструменты аудита, дождаться зелёных CI и CodeQL.
2. Перенести проверенный кандидат в `main` без переписывания истории.
3. Запустить `Images` для точного SHA, затем `VM Matrix` с artifact этого же SHA.
4. Выполнить [реальные внешние испытания](release-checklist.md), зафиксировать только sanitized JSON и запустить `Evidence`.
5. Повторить private-фазу `tools/publication_audit.sh` с доступными locked security tools.
6. Только после нулевого списка blockers создать подписанный tag, выполнить ручной release workflow и проверить скачанные assets.
7. Сменить видимость отдельно, включить branch protection и повторить audit в public-фазе.
8. Проверить точную README-команду на ещё одном чистом VPS.

Ни один из отсутствующих внешних результатов не заменяется fixture, локальным handshake или зелёным CI.
