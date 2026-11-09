#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PR Security Review — подготовка данных pull request Azure DevOps Server для анализа ИИ-ассистентом.

Что делает программа (БЕЗ обращений к LLM):
  1. по id PR получает из ADO merge-коммит PR (last_merge_commit) и его базу (last_merge_target_commit);
  2. клонирует в рабочий каталог выгрузку refs/pull/<ID>/merge (merge-коммит + родитель — целевая ветка);
     если merge-коммита в ADO нет — выгружает ветку источника PR и целевую ветку, база — merge-base;
  3. готовит в рабочем каталоге: diff PR (diff.patch, полные версии файлов — в clone/), список файлов,
     комментарии PR (comments.json + comments.md), копирует системный промпт ревью (prompt.md)
     и ваши файлы из inputs/ (контекст: отчёты, выгрузки и т.п.) в context/;
  4. дальше вы открываете рабочий каталог в редакторе (Zoo) и проводите анализ по prompt.md.

Режим релизов: по ссылке вида .../_releaseProgress?...&releaseId=<ID> получает из Release Management
API артефакты релиза (build → коммит и репозиторий через запись сборки), для каждого git-артефакта
выгружает коммит релиза и коммит ПРЕДЫДУЩЕГО релиза того же релизного конвейера (база diff — то, что
реально поехало в окружения с момента прошлого релиза) и готовит diff.patch/files.json по каждому
артефакту (artifacts/<alias>/) и сводные по всему релизу; список коммитов интервала база..head (все
фиксации релиза, через постраничный commits API — не зависит от глубины выгрузки) — в commits.md; связанные
work items — в work_items.json.

Запуск:
  set ADO_PAT=...                # PAT Azure DevOps Server (или DEPP_BOT_TOKEN)
  python main.py --pr-id 123 --project МойПроект --repo МойРепозиторий
  python main.py --release-url=https://host/tfs/Coll/P/_releaseProgress?_a=release-pipeline-progress&releaseId=9186

Аргументы можно задать в блоке НАСТРОЙКИ ЗАПУСКА ниже (аргументы командной строки имеют приоритет).
Очистка после работы: python cleanup.py --pr-id 123 / python cleanup.py --release-id 9186
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# Делаем пакет src импортируемым при запуске из любого каталога
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.ado_client import (ArtifactSource, AzureDevOpsClient, AzureDevOpsError, ReleaseInfo,
                            parse_pr_url, parse_release_url)
from src.comments import format_comments_markdown, save_comments_json
from src.config import get_ado_pat, load_config, resolve_path
from src.fs_safe import safe_remove_tree
from src.git_ops import (GitError, PRDiff, clone_commit_pair, clone_pr_head_commit,
                         clone_pr_merge_commit, repo_url_from_parts)
from src.logging_setup import get_logger, setup_logger
from src.state import (clone_dir_for, pr_dir, release_dir, safe_dir_name, save_state)

# =====================================================================================================================
# НАСТРОЙКИ ЗАПУСКА — можно задать здесь вместо аргументов командной строки (CLI имеет приоритет).
# =====================================================================================================================
PR_ID = ""       # id PR, который нужно подготовить (например "123")
PROJECT = ""     # имя проекта ADO
REPO = ""        # имя репозитория ADO
BRANCH = ""      # целевая ветка PR ("" — возьмётся из данных PR; сверяется с фактической)
RELEASE_ID = ""  # id релиза, который нужно подготовить (вместо PR; например "9186")
# =====================================================================================================================


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Подготовка данных pull request ИЛИ релиза Azure DevOps Server к ИИ-ревью "
                    "(без обращений к LLM).\n"
                    "PR: --pr-url=https://host/tfs/<Collection>/<Project>/_git/<Repo>/pullrequest/<ID>\n"
                    "Релиз: --release-url=https://host/tfs/<Collection>/<Project>/_releaseProgress"
                    "?_a=release-pipeline-progress&releaseId=<ID>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--pr-url", default="", help="ссылка на PR ADO (проект, репозиторий и id берутся из неё)")
    parser.add_argument("--pr-id", default=PR_ID, help="id pull request (если нет --pr-url)")
    parser.add_argument("--project", default=PROJECT, help="имя проекта ADO (если нет --pr-url/--release-url)")
    parser.add_argument("--repo", default=REPO, help="имя репозитория ADO (если нет --pr-url)")
    parser.add_argument("--branch", default=BRANCH,
                        help="целевая ветка PR (пусто — взять из PR; при несовпадении — предупреждение)")
    parser.add_argument("--release-url", default="",
                        help="ссылка на релиз ADO (проект и releaseId берутся из неё; режим ревью релиза)")
    parser.add_argument("--release-id", default=RELEASE_ID,
                        help="id релиза (вместе с --project; режим ревью релиза)")
    parser.add_argument("--config", default=None, help="путь к config.toml (по умолчанию — рядом с main.py)")
    parser.add_argument("--no-comments", action="store_true",
                        help="не выгружать комментарии PR")
    return parser.parse_args(argv)


CONTEXT_README = (
    "Сюда можно в любой момент класть свои файлы (отчёты, выгрузки, чек-листы, списки исключений).\n"
    "ИИ-ассистент при ревью читает всё, что лежит в этом каталоге, и файлы, которые вы назовёте\n"
    "в чате по любому пути. Кладите файлы сюда до или во время анализа — ничего перезапускать не нужно.\n")


def prepare_context(context_dir: Path, inputs_root: Path, log) -> None:
    """
    Создать context/ в рабочем каталоге PR (в него пользователь кладёт свои файлы в ЛЮБОЙ момент,
    не только до клонирования) и скопировать туда текущее содержимое inputs/ (если есть).
    """
    context_dir.mkdir(parents=True, exist_ok=True)
    readme = context_dir / "README.txt"
    if not readme.exists():
        readme.write_text(CONTEXT_README, encoding="utf-8")
    if not inputs_root.is_dir():
        return
    files = [p for p in inputs_root.iterdir() if p.name != ".gitkeep"]
    if not files:
        return
    for item in files:
        target = context_dir / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)
    log.info(f"Файлы из {inputs_root.name}/ скопированы в {context_dir} ({len(files)} шт.) — "
             f"ассистент прочитает их как контекст")


def fresh_work_dir(work_dir: Path, workspace_root: Path, subdirs: List[Path], log) -> None:
    """Пересоздать рабочий каталог (PR или релиза) и гарантировать наличие подкаталогов subdirs."""
    if work_dir.exists():
        log.info(f"Рабочий каталог уже существует — пересоздаётся: {work_dir}")
        try:
            safe_remove_tree(work_dir, workspace_root)
        except OSError as exc:
            # Каталог мог остаться заблокированным (редактор/антивирус держат .git) или содержать
            # длинные пути Windows. Не прерываем запуск: выгрузки ниже пересоздаются отдельно.
            log.warning(f"Рабочий каталог не удалось полностью удалить (возможно, заблокирован "
                        f"редактором/антивирусом): {exc} — продолжаем с чистой выгрузкой")
    work_dir.mkdir(parents=True, exist_ok=True)
    for sub in subdirs:
        if sub.exists():
            try:
                safe_remove_tree(sub, work_dir)
            except OSError as exc:
                log.warning(f"Каталог {sub.name}/ не удалось полностью удалить: {exc} — "
                            f"git пересоздаст выгрузку поверх остатка")
        sub.mkdir(parents=True, exist_ok=True)


def copy_prompt_and_context(work_dir: Path, prompt_path: Path, inputs_root: Path, log) -> None:
    """Скопировать системный промпт и пользовательский контекст в рабочий каталог."""
    if prompt_path.is_file():
        shutil.copy2(prompt_path, work_dir / "prompt.md")
        log.info(f"Системный промпт скопирован: {work_dir / 'prompt.md'} (оригинал: {prompt_path})")
    else:
        log.warning(f"Файл промпта не найден: {prompt_path} — prompt.md не создан")
    prepare_context(work_dir / "context", inputs_root, log)


def make_client(cfg, pat: str, org_url: str) -> AzureDevOpsClient:
    return AzureDevOpsClient(org_url, pat, api_version=str(cfg.get("ado.api_version", "5.1")),
                             timeout=cfg.int("ado.request_timeout_sec", 30))


# =====================================================================================================================
# РЕЖИМ PR
# =====================================================================================================================
def run_pr(args, cfg, pat: str, org_url: str, ca_bundle: str, workspace_root: Path,
           inputs_root: Path, prompt_path: Path) -> int:
    log = get_logger()

    # Ссылка на PR задаёт сразу проект, репозиторий и id; явные параметры имеют приоритет над ссылкой
    project = args.project
    repo = args.repo
    pr_id_raw = args.pr_id
    if str(args.pr_url or "").strip():
        try:
            url_project, url_repo, url_pr_id = parse_pr_url(str(args.pr_url).strip(), org_url)
        except ValueError as exc:
            log.error(f"Не удалось разобрать ссылку на PR: {exc}")
            return 2
        project = project or url_project
        repo = repo or url_repo
        if not str(pr_id_raw).strip().isdigit():
            pr_id_raw = str(url_pr_id)
        log.info(f"Из ссылки на PR: проект={project} репозиторий={repo} PR={pr_id_raw}")

    if not str(pr_id_raw).strip().isdigit():
        log.error(f"Id PR не задан или не число (получено: {pr_id_raw!r}); укажите --pr-url или --pr-id")
        return 2
    pr_id = int(str(pr_id_raw).strip())
    if not project or not repo:
        log.error("Не заданы проект и/или репозиторий (--pr-url либо --project/--repo)")
        return 2

    work_dir = pr_dir(workspace_root, pr_id)
    clone_dir = clone_dir_for(work_dir)

    log.info("=" * 70)
    log.info(f"PR Security Review: проект={project} репозиторий={repo} PR={pr_id}")
    log.info(f"Рабочий каталог: {work_dir}")

    # ---- 1. Данные PR из ADO: merge-коммит и ветки ----
    client = make_client(cfg, pat, org_url)
    try:
        pr_info = client.get_pull_request(project, repo, pr_id)
    except AzureDevOpsError as exc:
        log.error(f"Не удалось получить PR {pr_id}: {exc}")
        return 1
    pr_url = client.pr_url(project, repo, pr_id)
    log.info(f"PR #{pr_id}: {pr_info.title!r} | {pr_info.source_branch_name} -> {pr_info.target_branch_name} | "
             f"статус={pr_info.status}")
    if pr_info.merge_commit:
        log.info(f"Merge-коммит PR: {pr_info.merge_commit[:12]} (база: {pr_info.merge_target_commit[:12]})")
    else:
        log.warning("У PR нет merge-коммита в ADO (например, PR в конфликте) — "
                    "данные по diff ветки источника относительно merge-base")

    if args.branch:
        wanted = args.branch.replace("refs/heads/", "")
        if wanted != pr_info.target_branch_name:
            log.warning(f"Заданная ветка '{wanted}' отличается от целевой ветки PR "
                        f"'{pr_info.target_branch_name}': берётся фактическая цель PR")

    # ---- 2. Рабочий каталог: чистый клон PR ----
    fresh_work_dir(work_dir, workspace_root, [clone_dir], log)

    fetch_depth = cfg.int("review.merge_fetch_depth", 2)
    fetch_retries = cfg.int("review.fetch_retries", 3)
    fetch_pauses = [int(float(x)) for x in (cfg.str_list("review.fetch_retry_pause_sec") or ["5", "15"])]
    git_timeout = cfg.int("review.git_timeout_sec", 600)
    repo_url = repo_url_from_parts(org_url, project, repo)
    try:
        if pr_info.merge_commit:
            head, base = clone_pr_merge_commit(repo_url, pat, pr_id, str(clone_dir), depth=fetch_depth,
                                               fetch_retries=fetch_retries, retry_pause_sec=fetch_pauses,
                                               timeout=git_timeout, ca_bundle=ca_bundle or None)
        else:
            head, base = clone_pr_head_commit(repo_url, pat, pr_info.source_branch_name,
                                              pr_info.target_branch_name, str(clone_dir),
                                              depth=max(50, fetch_depth * 25), fetch_retries=fetch_retries,
                                              retry_pause_sec=fetch_pauses, timeout=git_timeout,
                                              ca_bundle=ca_bundle or None)
    except GitError as exc:
        log.error(f"Клонирование PR не выполнено: {exc}")
        return 1
    if pr_info.merge_commit and head != pr_info.merge_commit:
        log.warning(f"Выгруженный merge-коммит {head[:12]} не совпадает с last_merge_commit ADO "
                    f"{pr_info.merge_commit[:12]} (в PR был пуш после выгрузки) — "
                    f"подготовлена выгруженная версия")

    # ---- 3. Данные PR: diff + список файлов (полные версии файлов — в clone/) ----
    context_lines = cfg.int("review.context_lines", 8)
    pr_diff = PRDiff(str(clone_dir), head, base, timeout=git_timeout)
    changes = pr_diff.changes()
    log.info(f"Файлов изменено в PR: {len(changes)}")
    for path, change_type in changes[:50]:
        log.info(f"  [{change_type}] {path}")
    if len(changes) > 50:
        log.info(f"  ... и ещё {len(changes) - 50}")

    (work_dir / "diff.patch").write_text(pr_diff.full_diff(context_lines=context_lines), encoding="utf-8")
    with open(work_dir / "files.json", "w", encoding="utf-8") as f:
        json.dump([{"file": p, "change_type": t} for p, t in changes], f, ensure_ascii=False, indent=2)

    # ---- 4. Комментарии PR (выгрузка; ИИ-ассистент прочитает их из файлов) ----
    if not args.no_comments:
        try:
            threads = client.get_pr_threads(project, repo, pr_id)
            save_comments_json(threads, work_dir / "comments.json")
            (work_dir / "comments.md").write_text(
                format_comments_markdown(threads, pr_url), encoding="utf-8")
        except AzureDevOpsError as exc:
            log.warning(f"Комментарии PR не выгружены: {exc}")

    # ---- 5. Промпт ревью и ваши контекстные файлы рядом с данными PR ----
    copy_prompt_and_context(work_dir, prompt_path, inputs_root, log)

    # ---- 6. State для cleanup.py и сводка ----
    state_path = save_state(work_dir, {
        "kind": "pr",
        "project": project, "repo": repo, "pr_id": pr_id,
        "pr_title": pr_info.title, "pr_status": pr_info.status,
        "source_branch": pr_info.source_branch_name, "target_branch": pr_info.target_branch_name,
        "merge_commit": head, "base_commit": base, "pr_url": pr_url,
        "changed_files": len(changes), "clone_mode": "merge" if pr_info.merge_commit else "head",
    })
    log.info(f"State: {state_path}")

    log.info("=" * 70)
    log.info("Данные PR готовы. Порядок анализа:")
    log.info(f"  1) откройте рабочий каталог в редакторе: {work_dir}")
    log.info(f"  2) файл prompt.md — системный промпт ревью безопасности (что и как проверять)")
    log.info(f"  3) diff.patch — изменения PR; clone/ — полные версии файлов; "
             f"comments.md — комментарии PR; context/ — ваши файлы")
    log.info(f"  4) попросите ассистента проверить diff.patch по промпту prompt.md")
    log.info(f"     свои файлы можно докладывать в {work_dir / 'context'} в любой момент,")
    log.info(f"     или просто назвать ассистенту путь к любому файлу в чате")
    log.info(f"Очистка после работы: python cleanup.py --pr-id {pr_id}")
    return 0


# =====================================================================================================================
# РЕЖИМ РЕЛИЗА
# =====================================================================================================================
def _ref_value(ref: dict, key: str) -> str:
    """Значение definitionReference[key]: предпочитает name, иначе id."""
    item = (ref or {}).get(key) or {}
    return str(item.get("name") or item.get("id") or "").strip()


def _resolve_build_commit(client: AzureDevOpsClient, log, build_project: str, definition_id: str,
                          build_number: str, allow_latest: bool = False) -> Tuple[int, str, dict]:
    """
    Коммит конкретной сборки по её buildNumber (sourceVersion из записи build).
    Возвращает (build_id, commit, build); (0, "", {}) если сборка или коммит не найдены.
    Без номера сборки «последняя сборка определения» ищется только при allow_latest=True
    (текущий релиз). Для ПРЕДЫДУЩЕГО релиза allow_latest=False: «последняя» на момент запроса
    сборка — это коммит текущего релиза, база diff становилась неверной и в diff релиза попадали
    изменения 1-2 последних коммитов вместо всех изменений релиза.
    """
    if not definition_id:
        return 0, "", {}
    if not str(build_number or "").strip() and not allow_latest:
        log.info(f"Артефакт предыдущего релиза: номер/ id сборки не указаны — поиск «последней "
                 f"сборкой определения {definition_id}» не выполняется (дал бы коммит текущего релиза)")
        return 0, "", {}
    try:
        build = client.find_build(build_project, definition_id, build_number)
    except AzureDevOpsError as exc:
        log.warning(f"Сборка {build_number!r} (определение {definition_id}) в проекте "
                    f"'{build_project}' не найдена: {exc}")
        return 0, "", {}
    if not build:
        log.warning(f"Среди сборок определения {definition_id} в проекте '{build_project}' нет "
                    f"{build_number!r} с коммитом (sourceVersion)")
        return 0, "", {}
    return int(build.get("id", 0) or 0), str(build.get("sourceVersion") or "").strip(), build


def resolve_artifact_source(client: AzureDevOpsClient, log, release_project: str,
                            artifact: dict,
                            allow_latest_fallback: bool = False) -> Tuple[Optional[ArtifactSource], str]:
    """
    Источник git-кода артефакта релиза: для build-артефактов — коммит и репозиторий из записи
    сборки; для git-артефактов (multi-repo) — commit/version из definitionReference.
    allow_latest_fallback=True разрешает при пустом номере сборки взять ПОСЛЕДНЮЮ сборку
    определения — только для артефакта самого текущего релиза (для предыдущего релиза это дало бы
    его же коммит и пустой/неполный diff).
    Возвращает (ArtifactSource | None, причина пропуска).
    """
    alias = str(artifact.get("alias") or artifact.get("id") or "").strip()
    atype = str(artifact.get("type") or "").strip().lower()
    ref = artifact.get("definitionReference") or {}
    if atype == "build":
        build_project = _ref_value(ref, "project") or release_project
        build_def_id = str(((ref.get("definition") or {}).get("id")) or "").strip()
        build_number = str(artifact.get("sourceCitation") or "").strip()
        # На части версий ADO Server у артефактов релиза нет sourceCitation, и поиск сборки по
        # пустому номеру вырождался в «последнюю сборку определения»: для ПРЕДЫДУЩЕГО релиза это
        # давало коммит текущего релиза и пустой diff. Приоритет — явные ссылки из
        # definitionReference: buildUri/version (id сборки -> get_build), затем sourceVersion.id.
        version_id = str(((ref.get("version") or {}).get("id")) or "").strip()
        build_uri = str(((ref.get("buildUri") or {}).get("id")) or "").strip()
        src_ver = str(((ref.get("sourceVersion") or {}).get("id")) or "").strip()
        build_id = int(version_id) if version_id.isdigit() else 0
        if not build_id and build_uri:
            tail = build_uri.rsplit("/", 1)[-1]
            build_id = int(tail) if tail.isdigit() else 0
        build: dict = {}
        commit = ""
        if build_id:
            try:
                build = client.get_build(build_project, build_id)
                commit = str(build.get("sourceVersion") or "").strip()
            except AzureDevOpsError as exc:
                log.warning(f"Сборка {build_id} не получена: {exc} — пробую разбор по номеру сборки")
        if not commit and re.fullmatch(r"[0-9a-fA-F]{7,40}", src_ver or ""):
            commit = src_ver
        if not commit:
            found_id, commit, build = _resolve_build_commit(client, log, build_project, build_def_id,
                                                            build_number, allow_latest=allow_latest_fallback)
            build_id = build_id or found_id
        if not commit:
            return None, f"build-артефакт: сборка/коммит не найдены (build '{build_number or build_id}')"
        repository = build.get("repository") or {}
        repo_project = str(((build.get("project") or {}).get("name")) or build_project).strip()
        repo_name = str(repository.get("name")
                        or ((ref.get("repository") or {}).get("name")) or "").strip()
        repo_type = str(repository.get("type")
                        or ((ref.get("repository.provider") or {}).get("id")) or "git").strip().lower()
        # On-prem ADO Server сообщает тип встроенного git-репозитория как "tfsgit"/"TfsGit"
        if repo_type in ("tfsgit", "tfs-git", "tfs_git"):
            repo_type = "git"
        if not repo_name or repo_type != "git":
            return None, (f"сборка {build_number or build_id}: git-репозиторий сборки не определён "
                          f"(тип {repo_type or '?'})")
        branch = str(build.get("sourceBranch") or _ref_value(ref, "branch")).strip()
        return ArtifactSource(artifact_id=str(artifact.get("id") or ""), alias=alias or "build",
                              artifact_type=atype, repo_project=repo_project, repo_name=repo_name,
                              branch=branch, commit=commit, build_id=build_id,
                              build_number=build_number), ""
    if atype == "git":
        # ArtifactType "Git" (multi-repo): repository/version/branch в definitionReference.
        repo_ref = ref.get("repository") or {}
        repo_name = str(repo_ref.get("name") or "").strip()
        repo_project = _ref_value(ref, "project") or release_project
        commit = (str((ref.get("version") or {}).get("id") or "").strip()
                  or str((ref.get("commit") or {}).get("id") or "").strip())
        branch = _ref_value(ref, "branchName") or _ref_value(ref, "defaultVersionBranch")
        if not (repo_name and commit):
            return None, "git-артефакт: репозиторий/commit не разобраны из definitionReference"
        return ArtifactSource(artifact_id=str(artifact.get("id") or ""), alias=alias or "git",
                              artifact_type=atype, repo_project=repo_project, repo_name=repo_name,
                              branch=branch, commit=commit), ""
    return None, f"тип артефакта '{atype or '?'}' не поддерживается (ожидались build/git)"


def _artifact_commit(client: AzureDevOpsClient, log, release_project: str, artifact: dict) -> Tuple[str, str]:
    """
    Коммит артефакта релиза + доп. сведения (build-номер и т.п.): (commit, build_number).
    Артефакт ПРЕДЫДУЩЕГО релиза: allow_latest_fallback=False — без явного номера/id сборки коммит
    не угадывается (иначе «последняя сборка» = коммит текущего релиза, база diff ломается).
    """
    src, reason = resolve_artifact_source(client, log, release_project, artifact,
                                          allow_latest_fallback=False)
    if not src:
        log.warning(f"Артефакт '{artifact.get('alias')}': {reason} — не использован как база diff")
        return "", ""
    return src.commit, src.build_number


WI_FIELDS = ["System.Title", "System.WorkItemType", "System.State", "System.Reason",
             "System.ChangedDate", "System.CreatedDate", "System.AreaPath", "System.AssignedTo"]


def enrich_work_items(client: AzureDevOpsClient, log, items: List[dict]) -> List[dict]:
    """
    Список work items (ссылки {id, url} из build/RM endpoints) дополняется содержимым: название,
    тип, состояние, дата — батчем wit/workitems (200 id на запрос). Ошибки догрузки не фатальны:
    остаются id/url.
    """
    ids = [it.get("id") for it in items if it.get("id") is not None]
    enriched: dict = {}
    for i in range(0, len(ids), 200):
        try:
            for wi in client.get_work_items_batch(ids[i:i + 200], fields=WI_FIELDS):
                enriched[str(wi.get("id"))] = wi
        except AzureDevOpsError as exc:
            log.warning(f"Work items не догружены содержимым (id {ids[i]}...): {exc}")
    out: List[dict] = []
    for it in items:
        fields = ((enriched.get(str(it.get("id"))) or {}).get("fields")) or {}
        out.append({
            "id": it.get("id"),
            "title": fields.get("System.Title", ""),
            "type": fields.get("System.WorkItemType", ""),
            "state": fields.get("System.State", ""),
            "area_path": fields.get("System.AreaPath", ""),
            "assigned_to": fields.get("System.AssignedTo", ""),
            "changed_date": fields.get("System.ChangedDate", ""),
            "url": it.get("url", ""),
        })
    return out


def extract_base_versions(pr_diff, changes: List[Tuple[str, str]], base_dir: Path, log,
                          max_files: int = 500) -> int:
    """
    Старые версии изменённых файлов (состояние на базу diff) в base_dir/<путь>: ассистент видит и
    «до», и «после» (clone/ — только «после»). Файлы, добавленные PR/релизом, пропускаются (их в
    базе нет). Возвращает число записанных файлов.
    """
    count = 0
    for path, change_type in changes[:max_files]:
        if change_type == "add":
            continue
        try:
            content = pr_diff.file_content(path, pr_diff.base)
        except (FileNotFoundError, GitError):
            continue   # в базе файла нет (rename и т.п.) — старая версия не нужна
        target = base_dir / path.replace("/", os.sep)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            count += 1
        except OSError:
            pass       # бинарное/неписчеемое — не критично
    if len(changes) > max_files:
        log.info(f"Старые версии файлов извлечены только для первых {max_files} из {len(changes)}")
    return count


def format_commits_markdown(commits: List[dict], title: str) -> str:
    """
    Список коммитов из ADO commits API в markdown: sha | дата | автор | первая строка
    сообщения. Порядок — как отдал API (обычно новые первыми).
    """
    lines = [f"# {title}", "", f"Коммитов: {len(commits)}", ""]
    for c in commits:
        cid = str(c.get("commitId") or "")[:12]
        author = ((c.get("author") or {}).get("displayName")
                  or (c.get("author") or {}).get("name") or "?")
        date = str(((c.get("committer") or {}).get("date")) or "")[:19].replace("T", " ")
        first_line = str(c.get("comment") or "").strip().splitlines()
        lines.append(f"- `{cid}` | {date} | {author} | {first_line[0] if first_line else ''}")
    if not commits:
        lines.append("(коммиты не получены: compare-endpoint недоступен на этом ADO Server "
                     "или база совпадает с head)")
    return "\n".join(lines) + "\n"


def format_release_prs_markdown(prs: List[dict], title: str) -> str:
    lines = [f"# {title}", "", f"Pull requests: {len(prs)}", ""]
    for pr in prs:
        pr_id = pr.get("pullRequestId", "?")
        status = pr.get("status", "")
        title_text = str(pr.get("title") or "").replace("\n", " ").strip()
        lines.append(f"- PR #{pr_id} | {status} | {title_text}")
    if not prs:
        lines.append("(связанные PR не найдены или pullrequestquery недоступен на этом ADO Server)")
    return "\n".join(lines) + "\n"


def run_release(args, cfg, pat: str, org_url: str, ca_bundle: str, workspace_root: Path,
                inputs_root: Path, prompt_path: Path) -> int:
    log = get_logger()

    # Ссылка на релиз задаёт сразу проект и releaseId; явные параметры имеют приоритет
    project = args.project
    release_id_raw = args.release_id
    if str(args.release_url or "").strip():
        try:
            url_project, url_release_id = parse_release_url(str(args.release_url).strip(), org_url)
        except ValueError as exc:
            log.error(f"Не удалось разобрать ссылку на релиз: {exc}")
            return 2
        project = project or url_project
        if not str(release_id_raw).strip().isdigit():
            release_id_raw = str(url_release_id)
        log.info(f"Из ссылки на релиз: проект={project} релиз={release_id_raw}")

    if not str(release_id_raw).strip().isdigit():
        log.error(f"Id релиза не задан или не число (получено: {release_id_raw!r}); "
                  f"укажите --release-url или --release-id")
        return 2
    if not project:
        log.error("Не задан проект релиза (--release-url либо --project + --release-id)")
        return 2
    release_id = int(str(release_id_raw).strip())

    log.info("=" * 70)
    log.info(f"Release Security Review: проект={project} релиз={release_id}")
    work_dir = release_dir(workspace_root, release_id)
    log.info(f"Рабочий каталог: {work_dir}")

    # ---- 1. Данные релиза из ADO (Release Management API) ----
    client = make_client(cfg, pat, org_url)
    try:
        rel = client.get_release(project, release_id)
    except AzureDevOpsError as exc:
        log.error(f"Не удалось получить релиз {release_id}: {exc}")
        return 1
    rel_url = client.release_url(project, release_id)
    log.info(f"Релиз #{release_id}: {rel.name!r} | конвейер={rel.definition_name!r} (id={rel.definition_id}) | "
             f"статус={rel.status}")

    # ---- 2. Рабочий каталог ----
    artifacts_root = work_dir / "artifacts"
    fresh_work_dir(work_dir, workspace_root, [artifacts_root], log)
    (work_dir / "release.json").write_text(json.dumps(rel.raw, ensure_ascii=False, indent=2),
                                           encoding="utf-8")

    # ---- 3. Связанные work items (как вкладка 'Work items' в UI) ----
    # На ADO Server 2019 RM-эндпоинт workItemsAndChangesets отвечает 404 (маршрута нет ни на 5.1,
    # ни на 4.1) — это штатная ситуация, не ошибка. Вкладка 'Work items' в UI агрегирует задачи по
    # СБОРКАМ артефактов; тот же резерв здесь: сбор work_items по build'ам артефактов в цикле
    # ниже и сводная запись в шаге 6.
    work_items_rm = None
    try:
        work_items_rm = client.get_release_work_items(project, release_id)
    except AzureDevOpsError:
        log.info("RM-эндпоинт workItemsAndChangesets на этом ADO Server недоступен (404) — "
                 "work items будут собраны по сборкам артефактов")
    if work_items_rm is not None:
        log.info(f"Связанных work items (RM endpoint): {len(work_items_rm)}")

    # ---- 4. Изменения между релизами (как вкладка 'Changes'; может быть недоступна) ----
    changes_raw = None
    try:
        changes_raw = client.get_release_changes(project, release_id)
        (work_dir / "changes.json").write_text(json.dumps(changes_raw, ensure_ascii=False, indent=2),
                                               encoding="utf-8")
    except AzureDevOpsError as exc:
        log.debug(f"Changes релиза недоступны через API (используется git diff): {exc}")

    # ---- 5. По каждому артефакту: коммит релиза и база (коммит предыдущего релиза), diff ----
    fetch_depth = cfg.int("review.merge_fetch_depth", 2)
    fetch_retries = cfg.int("review.fetch_retries", 3)
    fetch_pauses = [int(float(x)) for x in (cfg.str_list("review.fetch_retry_pause_sec") or ["5", "15"])]
    git_timeout = cfg.int("review.git_timeout_sec", 600)
    context_lines = cfg.int("review.context_lines", 8)

    prev_cache: dict = {}   # id источника артефакта -> (release_id, artifact) | None (кэш запросов)
    artifacts_info: List[dict] = []
    merged_diff: List[str] = []
    merged_files: List[dict] = []
    merged_commits_md: List[str] = []
    merged_prs: List[dict] = []
    seen_pr_ids: set = set()
    merged_work_items: List[dict] = []      # резервная агрегация по сборкам (без RM-endpoint)
    seen_work_item_ids: set = set()

    for artifact in rel.artifacts:
        alias = str(artifact.get("alias") or artifact.get("id") or "").strip() or "artifact"
        atype = str(artifact.get("type") or "?")
        # Текущий релиз: при пустом номере сборки допустим резерв «последняя сборка определения»
        src, reason = resolve_artifact_source(client, log, project, artifact, allow_latest_fallback=True)
        if not src:
            log.warning(f"Артефакт '{alias}' (тип {atype}): {reason} — пропущен")
            artifacts_info.append({"alias": alias, "type": atype, "skipped_reason": reason})
            continue
        log.info(f"Артефакт '{alias}' ({atype}): {src.repo_project}/{src.repo_name} "
                 f"commit={src.commit[:12]}" + (f" build={src.build_number}" if src.build_number else ""))

        # Work items сборки артефакта — резерв, когда RM-endpoint релиза не отдаётся (ADO Server
        # 2019): вкладка 'Work items' в UI показывает именно агрегат по сборкам артефактов.
        build_wi: List[dict] = []
        if work_items_rm is None and src.build_id:
            try:
                build_wi = client.get_build_work_items(src.repo_project, src.build_id)
            except AzureDevOpsError as exc:
                log.warning(f"Артефакт '{alias}': work items сборки {src.build_id} не получены: {exc}")
        for wi in build_wi:
            wi_id = wi.get("id")
            if wi_id is not None and wi_id not in seen_work_item_ids:
                seen_work_item_ids.add(wi_id)
                merged_work_items.append(wi)

        # База diff — коммит того же артефакта в предыдущем релизе того же источника
        # (artifactSourceId = id build-определения / git-репозитория источника артефакта)
        src_def_id = str(((artifact.get("definitionReference") or {}).get("definition") or {}).get("id")
                         or "").strip()
        base_commit, prev_release_id, prev_build_number = "", None, ""
        if not src_def_id:
            log.warning(f"Артефакт '{alias}': id источника артефакта не определён — "
                        f"предыдущий релиз не найден, база diff = родитель коммита")
        else:
            if src_def_id not in prev_cache:
                try:
                    # База — предыдущий релиз ТОГО ЖЕ конвейера (как вкладка Changes в UI): одно
                    # build-определение могут использовать несколько конвейеров (test/stage/prod),
                    # релиз чужого конвейера дал бы базу, уже содержащую бóльшую часть изменений
                    # (в diff попадали бы 1-2 коммита вместо всех фиксаций). Внутри find_previous_release
                    # — резервный поиск по всем релизам источника, если в своём конвейере предыдущего нет.
                    prev_cache[src_def_id] = client.find_previous_release(
                        project, src_def_id, release_id, release_definition_id=rel.definition_id)
                except AzureDevOpsError as exc:
                    log.warning(f"Список предыдущих релизов источника {src_def_id} не получен: {exc}")
                    prev_cache[src_def_id] = None
            prev = prev_cache[src_def_id]
            # Один и тот же билд может быть выкачен несколькими релизами подряд (redeploy):
            # diff ближайшего релиза тогда пуст в принципе. Идём назад по истории релизов
            # источника, пока не найдём релиз с ДРУГИМ коммитом артефакта (или история кончится).
            for _ in range(20):
                if prev is None:
                    break
                prev_release_id, prev_artifact = prev
                base_commit, prev_build_number = _artifact_commit(client, log, project, prev_artifact)
                if base_commit and base_commit != src.commit:
                    break
                if base_commit:
                    log.info(f"Артефакт '{alias}': релиз {prev_release_id} собран из того же коммита "
                             f"{base_commit[:12]} (перевыкатка той же сборки) — ищу релиз старше")
                try:
                    prev = client.find_previous_release(project, src_def_id, prev_release_id,
                                                        release_definition_id=rel.definition_id)
                except AzureDevOpsError as exc:
                    log.warning(f"Список релизов источника {src_def_id} старше {prev_release_id} "
                                f"не получен: {exc}")
                    prev = None
                    break
                prev_cache[src_def_id] = prev
                if prev is not None and prev[0] == prev_release_id:
                    break  # защита от зацикливания

            # Если ни один предыдущий релиз источника не дал ДРУГОГО коммита (сплошные перевыкатки
            # той же сборки или коммит предыдущих релизов не разрешился) — найденная «база» равна
            # коммиту релиза и базой не является: сбрасываем её; diff будет только относительно
            # первого родителя коммита — предупреждаем максимально явно.
            if base_commit and base_commit == src.commit:
                log.warning(f"Артефакт '{alias}': среди предыдущих релизов источника не найдено "
                            f"релиза с коммитом, отличающимся от коммита релиза "
                            f"({src.commit[:12]}) — база diff сброшена; diff будет только "
                            f"относительно первого родителя коммита (это НЕ весь релиз!)")
                base_commit, prev_release_id, prev_build_number = "", None, ""

        if base_commit:
            log.info(f"Артефакт '{alias}': база diff — коммит {base_commit[:12]} предыдущего релиза "
                     f"{prev_release_id} (build {prev_build_number or 'н/д'})")

        repo_url = repo_url_from_parts(org_url, src.repo_project, src.repo_name)
        art_dir = artifacts_root / safe_dir_name(alias)
        clone_dir = art_dir / "clone"
        art_dir.mkdir(parents=True, exist_ok=True)
        clone_dir.mkdir(parents=True, exist_ok=True)
        try:
            head, base = clone_commit_pair(repo_url, pat, src.commit, base_commit, str(clone_dir),
                                           depth=fetch_depth, fetch_retries=fetch_retries,
                                           retry_pause_sec=fetch_pauses, timeout=git_timeout,
                                           ca_bundle=ca_bundle or None, branch=src.branch)
        except GitError as exc:
            log.error(f"Артефакт '{alias}': выгрузка не выполнена: {exc}")
            return 1

        if not base_commit:
            log.warning(f"Артефакт '{alias}': предыдущий релиз с коммитом не найден — "
                        f"diff только относительно первого родителя коммита релиза "
                        f"(это НЕ весь релиз с прошлого раза)")
        if base == head:
            log.warning(f"Артефакт '{alias}': коммит релиза совпал с базой diff ({head[:12]}) — diff "
                        f"пуст: ни один более ранний релиз источника не имеет другого коммита "
                        f"(источник выкачивается этим билдом впервые?) — проанализирован только "
                        f"merge-коммит релиза относительно его первого родителя")
        pr_diff = PRDiff(str(clone_dir), head, base, timeout=git_timeout)
        changes = pr_diff.changes()
        log.info(f"Артефакт '{alias}': файлов изменено с прошлого релиза: {len(changes)}")
        # Старые версии изменённых файлов (состояние на базу diff) — clone/ содержит только
        # «после»; ассистент получает и «до» в base/ и может сравнить любую версию напрямую.
        base_versions = extract_base_versions(pr_diff, changes, art_dir / "base", log)
        log.info(f"Артефакт '{alias}': старых версий файлов извлечено: {base_versions}")
        for path, change_type in changes[:50]:
            log.info(f"  [{change_type}] {path}")
        if len(changes) > 50:
            log.info(f"  ... и ещё {len(changes) - 50}")

        art_diff = pr_diff.full_diff(context_lines=context_lines)
        (art_dir / "diff.patch").write_text(art_diff, encoding="utf-8")
        with open(art_dir / "files.json", "w", encoding="utf-8") as f:
            json.dump([{"file": p, "change_type": t} for p, t in changes], f, ensure_ascii=False, indent=2)

        # Все коммиты интервала base..head берём через pageable commits endpoint. REST
        # /diffs/commits возвращает ИЗМЕНЁННЫЕ ФАЙЛЫ, а не список коммитов; прежний код ошибочно
        # искал в его ответе поле commits и поэтому часто записывал 0–2 случайных фиксации.
        # История читается на стороне ADO и не зависит от глубины shallow-выгрузки.
        commits_between: List[dict] = []
        base_reached = False
        try:
            commits_between, base_reached = client.get_commits_between(
                src.repo_project, src.repo_name, base, head,
                max_commits=cfg.int("review.max_release_commits", 10000))
        except AzureDevOpsError as exc:
            log.warning(f"Артефакт '{alias}': список коммитов {base[:12]}..{head[:12]} не получен: {exc}")
        if not base_reached:
            log.warning(f"Артефакт '{alias}': база {base[:12]} не встретилась при обходе истории "
                        f"коммитов (интервал неполон; см. review.max_release_commits)")
        log.info(f"Артефакт '{alias}': коммитов с прошлого релиза: {len(commits_between)}")
        (art_dir / "commits.md").write_text(
            format_commits_markdown(
                commits_between,
                f"Коммиты артефакта {alias} ({src.repo_project}/{src.repo_name}), "
                f"база {base[:12]} -> релиз {head[:12]}"),
            encoding="utf-8")

        # PR — более богатый контекст, чем отдельные commit messages: заголовок и описание
        # объясняют цель совокупного изменения. Endpoint есть не на всех старых ADO Server,
        # поэтому его недоступность не делает подготовку релиза неуспешной.
        release_prs: List[dict] = []
        commit_ids = [str(c.get("commitId") or "") for c in commits_between]
        if commit_ids:
            try:
                release_prs = client.get_pull_requests_for_commits(
                    src.repo_project, src.repo_name, commit_ids)
                enriched_prs: List[dict] = []
                for shallow_pr in release_prs:
                    pr_id = int(shallow_pr.get("pullRequestId", 0) or 0)
                    try:
                        full_pr = client.get_pull_request(src.repo_project, src.repo_name, pr_id)
                        threads = client.get_pr_threads(src.repo_project, src.repo_name, pr_id)
                        enriched_prs.append({**full_pr.raw, "threads": threads})
                    except AzureDevOpsError as pr_exc:
                        log.warning(f"Артефакт '{alias}': детали PR #{pr_id} не получены: {pr_exc}")
                        enriched_prs.append(shallow_pr)
                release_prs = enriched_prs
            except AzureDevOpsError as exc:
                log.info(f"Артефакт '{alias}': связанные PR не получены: "
                         f"{str(exc).splitlines()[0][:160]}")
        (art_dir / "pull_requests.json").write_text(
            json.dumps(release_prs, ensure_ascii=False, indent=2), encoding="utf-8")
        (art_dir / "pull_requests.md").write_text(
            format_release_prs_markdown(release_prs, f"PR артефакта {alias}"), encoding="utf-8")
        for pr in release_prs:
            pr_id = int(pr.get("pullRequestId", 0) or 0)
            if pr_id and pr_id not in seen_pr_ids:
                seen_pr_ids.add(pr_id)
                merged_prs.append({"artifact": alias, **pr})

        info = {
            "alias": alias, "type": atype,
            "repo_project": src.repo_project, "repo_name": src.repo_name, "branch": src.branch,
            "commit": head, "base_commit": base,
            "base_is_previous_release": bool(base_commit),
            "build_id": src.build_id, "build_number": src.build_number,
            "previous_release_id": prev_release_id, "previous_build_number": prev_build_number,
            "changed_files": len(changes), "commits_count": len(commits_between),
            "commit_interval_complete": base_reached,
            "pull_requests_count": len(release_prs),
            "work_items_build": len(build_wi),
        }
        with open(art_dir / "info.json", "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
        artifacts_info.append(info)

        if base != head:
            merged_diff.append(f"# =====================================================================\n"
                               f"# Артефакт: {alias} | {src.repo_project}/{src.repo_name}\n"
                               f"# head={head} (релиз {release_id}) "
                               f"base={base} (релиз {prev_release_id or 'родитель коммита'})\n"
                               f"# =====================================================================\n"
                               f"{art_diff}")
        merged_files.extend({"artifact": alias, "file": p, "change_type": t} for p, t in changes)
        merged_commits_md.append(format_commits_markdown(
            commits_between,
            f"Коммиты артефакта {alias} ({src.repo_project}/{src.repo_name}), "
            f"база {base[:12]} -> релиз {head[:12]}"))

    # ---- 6. Сводные diff, файлы и коммиты по всему релизу ----
    (work_dir / "diff.patch").write_text("\n".join(merged_diff), encoding="utf-8")
    with open(work_dir / "files.json", "w", encoding="utf-8") as f:
        json.dump(merged_files, f, ensure_ascii=False, indent=2)
    (work_dir / "commits.md").write_text("\n".join(merged_commits_md), encoding="utf-8")
    (work_dir / "pull_requests.json").write_text(
        json.dumps(merged_prs, ensure_ascii=False, indent=2), encoding="utf-8")
    (work_dir / "pull_requests.md").write_text(
        format_release_prs_markdown(merged_prs, "Pull requests релиза"), encoding="utf-8")
    if work_items_rm is None:
        merged_work_items = enrich_work_items(client, log, merged_work_items)
        (work_dir / "work_items.json").write_text(
            json.dumps(merged_work_items, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info(f"Связанных work items (сводка по сборкам артефактов): {len(merged_work_items)}")
    else:
        enriched_rm = enrich_work_items(client, log, work_items_rm)
        (work_dir / "work_items.json").write_text(
            json.dumps(enriched_rm, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info(f"Сводно по релизу: файлов изменено {len(merged_files)}, "
             f"коммитов {sum(a.get('commits_count', 0) for a in artifacts_info)} "
             f"(git-артефактов: {sum(1 for a in artifacts_info if 'skipped_reason' not in a)})")

    # ---- 7. Промпт ревью и контекст ----
    copy_prompt_and_context(work_dir, prompt_path, inputs_root, log)

    # ---- 8. State для cleanup.py и сводка ----
    state_path = save_state(work_dir, {
        "kind": "release",
        "project": project, "release_id": release_id, "release_name": rel.name,
        "release_status": rel.status, "definition_id": rel.definition_id,
        "definition_name": rel.definition_name, "release_url": rel_url,
        "artifacts": artifacts_info, "changed_files": len(merged_files),
        "commits_total": sum(a.get("commits_count", 0) for a in artifacts_info),
        "pull_requests_total": len(merged_prs),
        "changes_endpoint_used": bool(changes_raw),
    })
    log.info(f"State: {state_path}")

    log.info("=" * 70)
    log.info("Данные релиза готовы. Порядок анализа:")
    log.info(f"  1) откройте рабочий каталог в редакторе: {work_dir}")
    log.info(f"  2) файл prompt.md — системный промпт ревью безопасности (что и как проверять)")
    log.info(f"  3) diff.patch — сводный diff релиза (от прошлого релиза); commits.md — все коммиты "
             f"релиза; artifacts/<имя>/ — clone/ (код на релиз), base/ (код на прошлый релиз), "
             f"diff.patch, commits.md; work_items.json — связанные задачи")
    log.info(f"  4) попросите ассистента проверить diff.patch по промпту prompt.md")
    log.info(f"     свои файлы можно докладывать в {work_dir / 'context'} в любой момент,")
    log.info(f"     или просто назвать ассистенту путь к любому файлу в чате")
    log.info(f"Очистка после работы: python cleanup.py --release-id {release_id}")
    return 0


def run(args) -> int:
    log = get_logger()
    cfg = load_config(args.config)
    try:
        pat = get_ado_pat()
    except ValueError as exc:
        log.error(str(exc))
        return 2

    org_url = str(cfg.require("ado.org_url")).rstrip("/")

    # Корпоративный CA: requests (REST) берёт из REQUESTS_CA_BUNDLE, git — из http.sslCAInfo (ниже)
    ca_bundle = ""
    ca_value = str(cfg.get("ado.ca_bundle", "") or "").strip()
    if ca_value:
        ca_path = resolve_path(ca_value)
        if not ca_path.is_file():
            log.error(f"Корпоративный CA-сертификат не найден: {ca_path} ([ado] ca_bundle в config.toml)")
            return 2
        ca_bundle = str(ca_path)
        os.environ.setdefault("REQUESTS_CA_BUNDLE", ca_bundle)
    workspace_root = resolve_path(str(cfg.get("paths.workspace_root", "workspace")))
    inputs_root = resolve_path(str(cfg.get("paths.inputs_root", "inputs")))
    prompt_path = resolve_path(str(cfg.get("review.prompt_file", "prompts/security_review.md")))

    release_mode = bool(str(args.release_url or "").strip() or str(args.release_id or "").strip())
    pr_mode = bool(str(args.pr_url or "").strip() or str(args.pr_id or "").strip())
    if release_mode and pr_mode:
        log.error("Заданы и PR (--pr-url/--pr-id), и релиз (--release-url/--release-id) — "
                  "выберите что-то одно")
        return 2
    if release_mode:
        return run_release(args, cfg, pat, org_url, ca_bundle, workspace_root, inputs_root, prompt_path)
    return run_pr(args, cfg, pat, org_url, ca_bundle, workspace_root, inputs_root, prompt_path)


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logger()
    try:
        return run(args)
    except KeyboardInterrupt:
        get_logger().error("Прервано пользователем")
        return 130
    except Exception as exc:  # noqa: BLE001 — скрипт обязан вывести понятную причину
        get_logger().exception(f"Необработанная ошибка: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
