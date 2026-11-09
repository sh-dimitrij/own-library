"""Клиент REST API Azure DevOps Server (только PAT, без облачных удостоверений).

Данные PR: get_pull_request — метаданные, включая last_merge_commit (merge-коммит PR) и
last_merge_target_commit (его база — целевая ветка); get_pr_threads — обсуждения с комментариями.
Данные релизов (Release Management API): get_release — артефакты и окружения релиза;
get_build — коммит/репозиторий build-артефакта; find_previous_release — предыдущий релиз того же
артефакта (база diff релиза); get_release_work_items / get_release_changes — связанные задачи.
Проверка TLS включена всегда; корпоративный корневой сертификат — через REQUESTS_CA_BUNDLE.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

from .logging_setup import get_logger


class AzureDevOpsError(RuntimeError):
    """Ошибка запроса к ADO или неожиданная структура ответа."""


def parse_pr_url(pr_url: str, org_url: str = "") -> Tuple[str, str, int]:
    """
    Разобрать веб-ссылку PR Azure DevOps Server вида
    https://host/tfs/<Collection>/<Project>/_git/<Repo>/pullrequest/<ID>
    (с необязательными ?...query и завершающим слешем; проценты в именах декодируются).
    Возвращает (project, repo, pr_id). org_url (адрес коллекции из config.toml), если задан,
    используется для проверки, что ссылка ведёт на тот же сервер и ту же коллекцию.
    Некорректная ссылка — ValueError с понятной причиной.
    """
    parsed = urlparse(pr_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"это не HTTP(S)-ссылка: {pr_url!r}")
    parts = [unquote(p) for p in parsed.path.split("/") if p]
    if "_git" not in parts:
        raise ValueError("в ссылке нет сегмента '_git' — это не ссылка на репозиторий ADO")
    i = parts.index("_git")
    if i < 1 or i + 3 >= len(parts):
        raise ValueError("недостаточно компонентов пути; ожидался вид "
                         ".../<Project>/_git/<Repo>/pullrequest/<ID>")
    project, repo = parts[i - 1], parts[i + 1]
    if parts[i + 2].lower() != "pullrequest":
        raise ValueError("после имени репозитория ожидался сегмент 'pullrequest/<ID>'")
    try:
        pr_id = int(parts[i + 3])
    except ValueError:
        raise ValueError(f"номер PR в ссылке не число: {parts[i + 3]!r}") from None
    if org_url:
        org = urlparse(org_url)
        if (org.scheme.lower(), org.netloc.lower()) != (parsed.scheme.lower(), parsed.netloc.lower()):
            raise ValueError(f"ссылка ведёт на другой сервер ({parsed.netloc}), чем ado.org_url ({org.netloc})")
        org_path = org.path.rstrip("/").lower()
        url_collection = "/" + "/".join(parts[:i - 1]).lower()
        if org_path and not url_collection.startswith(org_path):
            raise ValueError(f"ссылка ведёт в другую коллекцию ({url_collection}), "
                             f"чем ado.org_url ({org.path})")
    return project, repo, pr_id


def parse_release_url(release_url: str, org_url: str = "") -> Tuple[str, int]:
    """
    Разобрать веб-ссылку релиза Azure DevOps Server вида
    https://host/tfs/<Collection>/<Project>/_releaseProgress?_a=...&releaseId=<ID>
    (подходят также страницы _release?releaseId=..., _releaseEnvironment?... и т.п.).
    Имя проекта — сегмент пути перед страницей '_release*', id релиза — из query (releaseId,
    регистронезависимо). Возвращает (project, release_id). org_url (адрес коллекции из
    config.toml), если задан, проверяет, что ссылка ведёт на тот же сервер и коллекцию.
    Некорректная ссылка — ValueError с понятной причиной.
    """
    parsed = urlparse(release_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"это не HTTP(S)-ссылка: {release_url!r}")
    parts = [unquote(p) for p in parsed.path.split("/") if p]
    page_idx = next((idx for idx, part in enumerate(parts)
                     if part.lower().startswith("_release")), None)
    if page_idx is None or page_idx < 1:
        raise ValueError("в ссылке нет страницы '_releaseProgress'/'_release' — это не ссылка на релиз ADO")
    project = parts[page_idx - 1]
    release_id_raw = ""
    for key, values in parse_qs(parsed.query).items():
        if key.lower() == "releaseid" and values:
            release_id_raw = values[0]
    if not release_id_raw:
        raise ValueError("в query ссылки нет releaseId=<id релиза>")
    try:
        release_id = int(release_id_raw)
    except ValueError:
        raise ValueError(f"releaseId в ссылке не число: {release_id_raw!r}") from None
    if org_url:
        org = urlparse(org_url)
        if (org.scheme.lower(), org.netloc.lower()) != (parsed.scheme.lower(), parsed.netloc.lower()):
            raise ValueError(f"ссылка ведёт на другой сервер ({parsed.netloc}), чем ado.org_url ({org.netloc})")
        org_path = org.path.rstrip("/").lower()
        url_collection = "/" + "/".join(parts[:page_idx - 1]).lower()
        if org_path and not url_collection.startswith(org_path):
            raise ValueError(f"ссылка ведёт в другую коллекцию ({url_collection}), "
                             f"чем ado.org_url ({org.path})")
    return project, release_id


def get_tls_verify():
    """Настройка verify для requests: набор CA из REQUESTS_CA_BUNDLE, иначе системная проверка. False не возвращает."""
    ca_bundle = (os.environ.get("REQUESTS_CA_BUNDLE") or "").strip()
    return ca_bundle if ca_bundle else True


def match_source_artifact(artifacts: List[dict], artifact_source_id: str) -> Optional[dict]:
    """
    Артефакт релиза с заданным источником (definitionReference.definition.id = id build-определения
    или git-репозитория источника). artifact.id НЕ используется как совпадение: это порядковый номер
    артефакта в релизе, он может случайно совпасть с id источника и дать ложный «предыдущий релиз»
    с коммитом чужого артефакта (некорректная база diff). Если артефакт с этим источником явно не
    найден, но артефакт в релизе ровно один — берётся он.
    """
    src_id = str(artifact_source_id or "").strip()
    for artifact in artifacts:
        src_def = str(((artifact.get("definitionReference") or {}).get("definition") or {}).get("id") or "")
        if src_id and src_def == src_id:
            return artifact
    # Никакого фолбэка «взять единственный артефакт»: на практике он подбирал артефакт ЧУЖОГО
    # build-определения из релиза другого конвейера и давал бессмысленную базу diff.
    return None


@dataclass
class PRInfo:
    """Метаданные pull request, нужные для ревью."""
    pr_id: int
    title: str = ""
    description: str = ""
    status: str = ""                       # active / completed / abandoned
    source_branch: str = ""                # refs/heads/... -> исходная ветка PR
    target_branch: str = ""                # refs/heads/... -> целевая ветка
    merge_commit: str = ""                 # last_merge_commit: merge-коммит PR (target + изменения PR)
    merge_target_commit: str = ""          # last_merge_target_commit: первый родитель merge-коммита (база)
    raw: dict = field(default_factory=dict)

    @property
    def source_branch_name(self) -> str:
        return self.source_branch.replace("refs/heads/", "")

    @property
    def target_branch_name(self) -> str:
        return self.target_branch.replace("refs/heads/", "")


@dataclass
class ReleaseInfo:
    """Метаданные релиза, нужные для ревью."""
    release_id: int
    name: str = ""
    description: str = ""
    status: str = ""                       # inProgress / approved / rejected / aborted
    project: str = ""
    definition_id: int = 0
    definition_name: str = ""
    created_on: str = ""
    released_on: str = ""
    artifacts: List[dict] = field(default_factory=list)    # как в ответе ADO (источники кода)
    environments: List[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class ArtifactSource:
    """Источник git-кода артефакта релиза: что и из какого репозитория выгружать."""
    artifact_id: str = ""        # id артефакта релиза — для поиска предыдущего релиза
    alias: str = ""              # имя артефакта — имя подкаталога выгрузки
    artifact_type: str = ""      # build / GitHubGit / ...
    repo_project: str = ""       # проект репозитория (может отличаться от проекта релиза)
    repo_name: str = ""          # имя git-репозитория
    branch: str = ""             # ветка, из которой собрана сборка
    commit: str = ""             # коммит артефакта (build sourceVersion)
    build_id: int = 0
    build_number: str = ""
    build_url: str = ""


class AzureDevOpsClient:
    """Тонкая обёртка над REST API ADO Server с Basic-аутентификацией (:PAT)."""

    def __init__(self, org_url: str, pat: str, api_version: str = "5.1", timeout: int = 30):
        if not org_url:
            raise AzureDevOpsError("Не задан адрес коллекции ADO (ado.org_url в config.toml)")
        if not pat:
            raise AzureDevOpsError("Не задан PAT Azure DevOps")
        self.org_url = org_url.rstrip("/")
        self.api_version = api_version
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = ("", pat)  # Basic с пустым логином — стандартная схема PAT для ADO Server

    # ---------- HTTP ----------
    def _get(self, url: str, params: Optional[dict] = None) -> dict:
        data, _ = self._get_page(url, params)
        return data

    def _get_page(self, url: str, params: Optional[dict] = None) -> Tuple[dict, Optional[str]]:
        """GET JSON and preserve ADO's continuation token used by Release APIs."""
        params = dict(params or {})
        params.setdefault("api-version", self.api_version)
        log = get_logger()
        log.debug(f"GET {url} params={params}")
        try:
            response = self.session.get(url, params=params, timeout=self.timeout, verify=get_tls_verify())
        except requests.RequestException as exc:
            raise AzureDevOpsError(f"Запрос к ADO не выполнен: {url}: {exc}") from exc
        if response.status_code >= 400:
            raise AzureDevOpsError(f"ADO ответил {response.status_code} для {url}: {response.text[:300]}")
        token = response.headers.get("x-ms-continuationtoken")
        return response.json(), token

    def _post(self, url: str, payload: dict, params: Optional[dict] = None) -> dict:
        params = dict(params or {})
        params.setdefault("api-version", self.api_version)
        log = get_logger()
        log.debug(f"POST {url} params={params}")
        try:
            response = self.session.post(url, params=params, json=payload, timeout=self.timeout,
                                         verify=get_tls_verify())
        except requests.RequestException as exc:
            raise AzureDevOpsError(f"Запрос к ADO не выполнен: {url}: {exc}") from exc
        if response.status_code >= 400:
            raise AzureDevOpsError(f"ADO ответил {response.status_code} для {url}: {response.text[:300]}")
        return response.json()

    def _repo_base(self, project: str, repo: str) -> str:
        return (f"{self.org_url}/{quote(project)}/_apis/git/repositories/{quote(repo)}")

    # ---------- Публичные методы ----------
    def get_pull_request(self, project: str, repo: str, pr_id: int) -> PRInfo:
        """Метаданные PR, включая пару коммитов merge-версии PR (head/base для diff)."""
        url = f"{self._repo_base(project, repo)}/pullRequests/{pr_id}"
        # $expand=labels не нужен; merge-коммиты приходят в основном ответе (lastMergeCommit/lastMergeTargetCommit)
        data = self._get(url)
        return PRInfo(
            pr_id=int(data.get("pullRequestId", pr_id)),
            title=data.get("title", "") or "",
            description=data.get("description", "") or "",
            status=data.get("status", "") or "",
            source_branch=data.get("sourceRefName", "") or "",
            target_branch=data.get("targetRefName", "") or "",
            merge_commit=(data.get("lastMergeCommit") or {}).get("commitId", "") or "",
            merge_target_commit=(data.get("lastMergeTargetCommit") or {}).get("commitId", "") or "",
            raw=data,
        )

    def get_pr_threads(self, project: str, repo: str, pr_id: int) -> list:
        """
        Обсуждения PR с комментариями (как get_issue_comments провайдера ADO).
        Возвращает список словарей:
          {thread_id, status, published, file_path, line, comments: [{id, author, published, content}]}
        """
        url = f"{self._repo_base(project, repo)}/pullRequests/{pr_id}/threads"
        threads = self._get(url).get("value", [])
        result = []
        for thread in threads:
            context = thread.get("threadContext") or {}
            entry = {
                "thread_id": thread.get("id"),
                "status": thread.get("status", ""),          # active / fixed / closed / byDesign / pending
                "published": thread.get("publishedDate", "") or "",
                "file_path": context.get("filePath", "") or "",   # пустой путь — общее обсуждение PR
                "line": (context.get("rightFileStart") or {}).get("line"),
                "comments": [
                    {
                        "id": comment.get("id"),
                        "author": ((comment.get("author") or {}).get("displayName")
                                   or (comment.get("author") or {}).get("uniqueName", "")),
                        "published": comment.get("publishedDate", "") or "",
                        "content": comment.get("content", "") or "",
                    }
                    for comment in thread.get("comments", [])
                ],
            }
            if entry["comments"]:
                result.append(entry)
        return result

    def pr_url(self, project: str, repo: str, pr_id: int) -> str:
        """Веб-ссылка на PR (для отчётов)."""
        return f"{self.org_url}/{quote(project)}/_git/{quote(repo)}/pullrequest/{pr_id}"

    # ---------- Релизы (Release Management API) ----------
    def _release_base(self, project: str) -> str:
        return f"{self.org_url}/{quote(project)}/_apis/release"

    def _build_base(self, project: str) -> str:
        return f"{self.org_url}/{quote(project)}/_apis/build"

    def release_url(self, project: str, release_id: int) -> str:
        """Веб-ссылка на релиз (для отчётов)."""
        return (f"{self.org_url}/{quote(project)}/_releaseProgress"
                f"?_a=release-pipeline-progress&releaseId={release_id}")

    def get_release(self, project: str, release_id: int) -> ReleaseInfo:
        """Метаданные релиза: артефакты (источники кода) и окружения."""
        url = f"{self._release_base(project)}/releases/{release_id}"
        data = self._get(url, params={"expand": "environments"})
        definition = data.get("releaseDefinition") or {}
        return ReleaseInfo(
            release_id=int(data.get("id", release_id)),
            name=data.get("name", "") or "",
            description=data.get("description", "") or "",
            status=data.get("status", "") or "",
            project=project,
            definition_id=int(definition.get("id", 0) or 0),
            definition_name=definition.get("name", "") or "",
            created_on=data.get("createdOn", "") or "",
            released_on=data.get("deployedOn", "") or "",
            artifacts=data.get("artifacts", []) or [],
            environments=data.get("environments", []) or [],
            raw=data,
        )

    def get_build(self, project: str, build_id: int) -> dict:
        """Сборка (build): sourceVersion — коммит, sourceBranch, repository (id/имя)."""
        return self._get(f"{self._build_base(project)}/builds/{build_id}")

    def find_build(self, project: str, definition_id: str, build_number: str = "") -> Optional[dict]:
        """
        Запись сборки по buildNumber в определении (или последняя сборка определения), у которой
        есть sourceVersion (коммит). Возвращает полный ответ build или None.
        """
        params: Dict[str, Any] = {"$top": 5}
        if definition_id:
            params["definitions"] = definition_id
        if build_number:
            params["buildNumber"] = build_number
        data = self._get(f"{self._build_base(project)}/builds", params=params)
        for item in data.get("value", []):
            full = self.get_build(project, int(item.get("id", 0) or 0))
            if str(full.get("sourceVersion") or "").strip():
                return full
        return None

    def find_previous_release(self, project: str, artifact_source_id: str,
                              before_release_id: int,
                              release_definition_id: Optional[int] = None) -> Optional[Tuple[int, dict]]:
        """
        Ближайший ПРЕДЫДУЩИЙ релиз с тем же источником артефакта (artifactSourceId = id build-определения
        / git-репозитория источника) — база diff релиза. Возвращает (release_id, artifact) — артефакт
        того же источника из ближайшего по createdOn (затем по id) релиза СТАРШЕ before_release_id —
        или None.

        «Ближайший» выбирается среди ВСЕХ релизов-кандидатов (а не первый в ответе API): после откатов,
        удалений и переиспользования release-id порядок по id и по времени создания может не совпадать,
        и первый попавшийся «старший по id» релиз может оказаться новее ревизии артефакта текущего
        релиза — тогда база diff «уезжает вперёд» и в diff попадают изменения лишь 1-2 последних
        коммитов вместо всего релиза.

        release_definition_id, если задан, задаёт РЕЛИЗНЫЙ КОНВЕЙЕР (как вкладка 'Changes' в UI
        релиза): одно build-определение часто используют несколько конвейеров (test/stage/prod),
        и предыдущий релиз источника из ЧУЖОГО конвейера (например, только что прошедшего тесты)
        даёт базу, уже содержащую бóльшую часть изменений, — в diff попадали 1-2 коммита вместо
        всех фиксаций релиза. Поиск: сначала релизы того же конвейера (параметр definitionId +
        клиентская проверка + пагинация), при неудаче — любые релизы источника.
        """
        log = get_logger()
        if release_definition_id:
            prev = self._find_previous_release_impl(project, artifact_source_id, before_release_id,
                                                    definition_id=int(release_definition_id))
            if prev:
                return prev
            log.info(f"Среди релизов конвейера {release_definition_id} старше релиза "
                     f"{before_release_id} источника {artifact_source_id} нет — ищу по всем "
                     f"релизам источника")
        return self._find_previous_release_impl(project, artifact_source_id, before_release_id,
                                                definition_id=None)

    def _find_previous_release_impl(self, project: str, artifact_source_id: str,
                                    before_release_id: int, definition_id: Optional[int] = None,
                                    pages: int = 10, page_size: int = 50) -> Optional[Tuple[int, dict]]:
        """
        Ближайший (по createdOn, затем id) релиз СТАРШЕ before_release_id, содержащий артефакт
        источника artifact_source_id. definition_id, если задан, ограничивает конвейером: фильтр
        передаётся серверу (definitionId) И проверяется по полному ответу релиза — на части версий
        ADO Server параметры фильтрации списков релизов игнорируются и отдают все релизы проекта,
        поэтому единственный надёжный фильтр — клиентская проверка.
        """
        log = get_logger()
        best: Optional[Tuple[str, int, dict]] = None   # (createdOn, release_id, artifact)
        continuation: Optional[str] = None
        seen_tokens = set()
        fallback_skip = 0
        seen_pages = set()
        for _page in range(pages):
            params: Dict[str, Any] = {"$top": page_size, "queryOrder": "descending"}
            if definition_id:
                params["definitionId"] = definition_id
            else:
                params["artifactSourceId"] = artifact_source_id
            if continuation:
                params["continuationToken"] = continuation
            elif fallback_skip:
                # Совместимость с некоторыми старыми on-prem версиями, которые не присылают
                # continuation header, но поддерживают $skip/$skipping.
                params["$skipping"] = fallback_skip
            data, next_token = self._get_page(f"{self._release_base(project)}/releases", params=params)
            batch = data.get("value", []) or []
            if not batch:
                break
            page_key = tuple(int(item.get("id", 0) or 0) for item in batch)
            if page_key in seen_pages:
                break
            seen_pages.add(page_key)
            for item in batch:
                rid = int(item.get("id", 0) or 0)
                if not rid or rid >= before_release_id:
                    continue
                full = self._get(f"{self._release_base(project)}/releases/{rid}")
                if definition_id:
                    item_def = int(((full.get("releaseDefinition") or {}).get("id")) or 0)
                    if item_def and item_def != int(definition_id):
                        continue   # сервер проигнорировал definitionId — отсеиваем на клиенте
                artifact = match_source_artifact(full.get("artifacts", []) or [], artifact_source_id)
                if artifact is None:
                    continue
                cand = (str(full.get("createdOn") or item.get("createdOn") or ""), rid, artifact)
                if best is None or (cand[0], cand[1]) > (best[0], best[1]):
                    best = cand
            if next_token and next_token not in seen_tokens:
                seen_tokens.add(next_token)
                continuation = next_token
            elif len(batch) >= page_size:
                continuation = None
                fallback_skip += len(batch)
            else:
                break
        if best is None:
            return None
        log.debug(f"Предыдущий релиз для источника {artifact_source_id} (конвейер "
                  f"{definition_id or 'любой'}): {best[1]} (создан {best[0]})")
        return best[1], best[2]

    def get_release_work_items(self, project: str, release_id: int) -> List[dict]:
        """
        Work items и changesets, связанные с релизом (RM-подэндпоинт). НЕ ОТДАЁТСЯ на ADO Server
        2019 (404: маршрута нет ни на 5.1, ни на 4.1). Вкладка 'Work items' в UI релиза агрегирует
        work items по СБОРКАМ артефактов — для этого есть get_build_work_items().
        """
        url = f"{self._release_base(project)}/releases/{release_id}/workItemsAndChangesets"
        return self._get(url, params={"api-version": "4.1"}).get("value", [])

    def get_build_work_items(self, project: str, build_id: int) -> List[dict]:
        """
        Work items, связанные со сборкой (git-коммиты сборки сопоставлены с задачами). Эндпоинт
        есть во всех версиях TFS/ADO Server; вкладка 'Work items' релиза показывает именно
        агрегат по сборкам его артефактов. Возвращает ссылки {id, url} — содержимое (название,
        тип, состояние) догружается get_work_items_batch().
        """
        url = f"{self._build_base(project)}/builds/{build_id}/workItems"
        return self._get(url).get("value", [])

    def get_work_items_batch(self, ids: List, fields: Optional[List[str]] = None) -> List[dict]:
        """
        Содержимое work items по id батчем (коллекционный endpoint wit/workitems — есть во всех
        версиях TFS/ADO Server). ids > 200 за один запрос сервер не принимает — нарезайте.
        """
        ids_str = ",".join(str(i) for i in ids if i is not None)
        if not ids_str:
            return []
        params: Dict[str, Any] = {"ids": ids_str}
        if fields:
            params["fields"] = ",".join(fields)
        return self._get(f"{self.org_url}/_apis/wit/workitems", params=params).get("value", []) or []

    def get_release_changes(self, project: str, release_id: int) -> Dict[str, Any]:
        """Изменения релиза относительно предыдущего (как вкладка 'Changes'; endpoint может быть недоступен)."""
        url = f"{self._release_base(project)}/releases/{release_id}/changes"
        return self._get(url, params={"api-version": "4.1"})

    def get_compare_commits(self, project: str, repo: str, base_version: str,
                            target_version: str) -> List[dict]:
        """
        Совместимый метод для старых callers. /diffs/commits вопреки названию возвращает изменения
        файлов, а не коммиты, поэтому список строится стандартным commits endpoint.
        """
        commits, _ = self.get_commits_between(project, repo, base_version, target_version)
        return commits

    def get_pull_requests_for_commits(self, project: str, repo: str,
                                      commit_ids: List[str]) -> List[dict]:
        """Return completed PRs which merged any supplied release commit (deduplicated)."""
        commits = [str(c).strip() for c in commit_ids if str(c).strip()]
        found: Dict[int, dict] = {}
        url = f"{self._repo_base(project, repo)}/pullrequestquery"
        for start in range(0, len(commits), 100):
            chunk = commits[start:start + 100]
            data = self._post(url, {"queries": [{"type": "commit", "items": chunk}]})
            for result in data.get("results", []) or []:
                for prs in (result or {}).values():
                    for pr in prs or []:
                        pr_id = int(pr.get("pullRequestId", 0) or 0)
                        if pr_id:
                            found[pr_id] = pr
        return sorted(found.values(), key=lambda p: int(p.get("pullRequestId", 0) or 0))

    def get_commits_between(self, project: str, repo: str, base_commit: str, head_commit: str,
                            max_commits: int = 1000, page_size: int = 100) -> Tuple[List[dict], bool]:
        """
        Коммиты от head_commit (включая) назад до base_commit (НЕ включая) через стандартный
        git commits endpoint (pageable searchCriteria.itemVersion.version). Глубина локальной
        shallow-выгрузки не важна.
        Возвращает (commits, base_reached): base_reached=False — история закончилась или достигнут
        лимит max_commits без достижения базы (список мог обрезаться).
        """
        base = str(base_commit or "").strip().lower()
        commits: List[dict] = []
        seen_ids = set()
        skip = 0
        url = f"{self._repo_base(project, repo)}/commits"
        while len(commits) < max_commits:
            # versionType=commit ОБЯЗАТЕЛЕН: без него ADO трактует version как имя ветки и отвечает
            # TF401175 "The version descriptor <Branch: <sha>> could not be resolved".
            params = {"searchCriteria.itemVersion.version": head_commit,
                      "searchCriteria.itemVersion.versionType": "commit",
                      "$top": min(page_size, max_commits - len(commits)),
                      "$skip": skip}
            batch = self._get(url, params=params).get("value", []) or []
            if not batch:
                return commits, False   # история закончилась, база не встретилась
            added = 0
            for c in batch:
                cid = str(c.get("commitId") or "").strip().lower()
                if base and cid and (cid == base or cid.startswith(base) or base.startswith(cid)):
                    return commits, True
                if cid and cid in seen_ids:
                    continue
                if cid:
                    seen_ids.add(cid)
                commits.append(c)
                added += 1
            if added == 0:
                # Некоторые старые ADO Server игнорируют $skip и бесконечно отдают первую страницу.
                return commits, False
            skip += len(batch)
        return commits, False
