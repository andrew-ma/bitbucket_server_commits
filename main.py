# https://docs.atlassian.com/bitbucket-server/rest/7.13.0/bitbucket-rest.html#idp222
import logging
from datetime import datetime, timezone
import sys
import os
import argparse
import getpass
from typing import Optional, TypedDict

# NON STDLIB
import requests
from requests.auth import HTTPBasicAuth, AuthBase

logging.basicConfig(level=logging.INFO)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

CommitDataDict = TypedDict(
    "CommitDataDict",
    {
        "date": datetime,
        "repo": str,
        "message": str,
        "hash": str,
        "author_id": str,
        "author_nickname": str,
        "author_display_name": str,
        "author_uuid": str,
    },
)


class BearerAuth(AuthBase):
    def __init__(self, token: str):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


class BitbucketSession:
    def __init__(
        self,
        *,
        personal_access_token: str,  # https://confluence.atlassian.com/bitbucketserver/personal-access-tokens-939515499.html
        api_url: str = "https://repo.scires.com/rest/api/1.0",
    ) -> None:
        self._PERSONAL_ACCESS_TOKEN = personal_access_token
        self._API_URL = api_url
        self._API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"

        self.session = requests.Session()
        self.session.auth = BearerAuth(self._PERSONAL_ACCESS_TOKEN)

    def get_user_info(self) -> dict[str, str]:

        # GET USER ACCOUNT_ID and USER UUID
        url = f"{self._API_URL}/user"
        res = self.session.get(url)
        res_json = res.json()

        user_username = res_json["username"]
        user_uuid = res_json["uuid"]
        user_nickname = res_json["nickname"]
        user_account_id = res_json["account_id"]

        log.debug(
            f"{user_username=}\n{user_uuid=}\n{user_nickname=}\n{user_account_id=}"
        )

        return {
            "username": user_username,
            "uuid": user_uuid,
            "nickname": user_nickname,
            "account_id": user_account_id,
        }

    def set_user_info(
        self,
        *,
        username: Optional[str] = None,
        uuid: Optional[str] = None,
        nickname: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> None:
        if username is not None:
            self._username = username

        if uuid is not None:
            self._user_uuid = uuid

        if nickname is not None:
            self._nickname = nickname

        if account_id is not None:
            self._account_id = account_id

    def get_repositories_by_permission(
        self, permissions: list[str] = ["admin", "write", "read"]
    ) -> list[str]:
        """
        Returns an object for each repository the caller has explicit
        access to and their effective permission — the highest level of permission
        the caller has.

        This does not return public repositories that the user was
        not granted any specific permission in, and does not distinguish between
        direct and indirect privileges.

        Permissions can be: admin, write, read
        """
        url = f"{self._API_URL}/user/permissions/repositories"
        params = {
            "q": " OR ".join(
                f'permission="{p}"' for p in permissions
            )  ## e.g.,  q='permission="admin" OR permission="write" OR permission="read"'
        }
        res = self.session.get(url, params=params)
        res_json = res.json()

        repo_objects = res_json["values"]

        return [repo["repository"]["full_name"] for repo in repo_objects]

    def get_commits_in_repository(
        self,
        repo_full_name: str,
        *,
        account_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> list[CommitDataDict]:
        repo_workspace, repo_slug = repo_full_name.split("/")

        # FOR EACH REPO THAT USER HAS ACCESS TO, CHECK THE COMMITS (https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commits)
        repo_commits_api_url = (
            f"{self._API_URL}/repositories/{repo_workspace}/{repo_slug}/commits"
        )

        res = self.session.get(repo_commits_api_url)
        res_json = res.json()

        commit_objects = res_json["values"]

        commit_list: list[CommitDataDict] = []

        for commit in commit_objects:
            # Filter By Account ID
            author_id = commit["author"]["user"]["account_id"]
            if account_id is not None:
                if author_id != account_id:
                    continue

            # Filter by Date
            date = datetime.strptime(commit["date"], self._API_DATE_FORMAT)
            # Bitbucket dates are UTC, so we add UTC timezone to date
            date_utc = date.replace(tzinfo=timezone.utc)
            # Detect local system's timezone.  If need to manually specify timezone, can use pytz.timezone("US/Central")
            local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
            date = date_utc.astimezone(local_timezone)

            if start_date is not None:
                if date < start_date:
                    # Inclusive (>=) of start_date
                    continue

            if end_date is not None:
                if date > end_date:
                    # Inclusive (<=) of end_date
                    continue

            commit_data: CommitDataDict = {
                "repo": repo_full_name,
                "date": date,  # type is datetime, not str
                "message": commit["message"],
                "hash": commit["hash"],
                "author_id": author_id,
                "author_nickname": commit["author"]["user"]["nickname"],
                "author_display_name": commit["author"]["user"]["display_name"],
                "author_uuid": commit["author"]["user"]["uuid"],
            }

            commit_list.append(commit_data)

        return commit_list

    @staticmethod
    def sort_by_last_commit_date(x):
        (repo_full_name, commit_list) = x
        return commit_list[-1]["date"]

    def get_projects(self):
        """Retrieve a page of projects.

        Only projects for which the authenticated user has the PROJECT_VIEW permission will be returned.

        paged api
        
        """
        url = f"{self._API_URL}/projects"
        res = self.session.get(url)
        if res.status_code != 200:
            res.raise_for_status()

        res_json = res.json()
        log.info(res_json)
        return res_json

    def get_project_repos(self, project_key: str):
        """Retrieve repositories from the project corresponding to the supplied projectKey.

        The authenticated user must have REPO_READ permission for the specified project to call this resource.
        
        paged api

        """
        url = f"{self._API_URL}/projects/{project_key}/repos"
        res = self.session.get(url)
        if res.status_code != 200:
            res.raise_for_status()

        res_json = res.json()
        log.info(res_json)
        return res_json
        
    def get_repo_commits(self, project_key: str, repo_slug: str):
        """Retrieve a page of commits from a given starting commit or "between" two commits. If no explicit commit is specified, the tip of the repository's default branch is assumed. commits may be identified by branch or tag name or by ID. A path may be supplied to restrict the returned commits to only those which affect that path.

        The authenticated user must have REPO_READ permission for the specified repository to call this resource.
        
        paged api
        """
        url = f"{self._API_URL}/projects/{project_key}/repos/{repo_slug}/commits"
        res = self.session.get(url)
        if res.status_code != 200:
            res.raise_for_status()

        res_json = res.json()
        log.info(res_json)
        return res_json
        
        

    def run(
        self,
        *,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        sort_individually: bool = False,
    ) -> None:
        user_account_id = self.get_user_info()["account_id"]
        repositories = self.get_repositories_by_permission()

        repo_to_commits = {}
        for repo_full_name in repositories:
            commit_list = self.get_commits_in_repository(
                repo_full_name,
                account_id=user_account_id,
                start_date=start_date,
                end_date=end_date,
            )

            repo_to_commits[repo_full_name] = commit_list

        if sort_individually:
            # sort commits individually by each commit's date
            # first flatten commits
            all_commits = [cm for cm_list in repo_to_commits.values() for cm in cm_list]

            sorted_commits = sorted(
                all_commits, key=lambda cm: cm["date"], reverse=True
            )

            for commit_data in sorted_commits:
                print(
                    f"{commit_data['date'].strftime('%Y-%m-%d, %I:%M %p')} | {commit_data['repo']} | {commit_data['message'].strip()}"
                )
        else:
            # sort repos by their last commit's date
            # so commits will grouped by repos
            sorted_repos = sorted(
                repo_to_commits.items(),
                key=BitbucketSession.sort_by_last_commit_date,
                reverse=True,
            )

            for repo_full_name, commit_list in sorted_repos:
                for commit_data in commit_list:
                    print(
                        f"{commit_data['date'].strftime('%Y-%m-%d, %I:%M %p')} | {commit_data['repo']} | {commit_data['message'].strip()}"
                    )


def get_args():
    VALID_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")

    def valid_date(date_string: str):
        for valid_format in VALID_DATE_FORMATS:
            try:
                date_object = datetime.strptime(date_string, valid_format)
                return date_object
            except Exception:
                pass
        else:
            # if date_string could not be parsed to any of the VALID_DATE_FORMATS
            raise argparse.ArgumentTypeError(f"Invalid date string: {date_string}")

    parser = argparse.ArgumentParser(
        description="Bitbucket Server Commits",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_group = parser.add_argument_group("required arguments")
    required_group.add_argument(
        "-p",
        "--personal-access-token",
        help="Personal Access Token for Bitbucket Server (To create one:  https://confluence.atlassian.com/bitbucketserver/personal-access-tokens-939515499.html). This cli argument takes priority over environment variable 'BITBUCKET_PERSONAL_ACCESS_TOKEN'. If neither the cli argument nor environment variable exist, then user will be prompted for personal access token.",
        required=True,
        default=argparse.SUPPRESS,
    )

    escaped_percents_date_formats = ", ".join(
        map(lambda x: f'"{x.replace("%", "%%")}"', VALID_DATE_FORMATS)
    )

    parser.add_argument(
        "--start-date",
        help=f"Filter by start date.  Valid formats: [{escaped_percents_date_formats}]",
        default=None,
        type=valid_date,
    )
    parser.add_argument(
        "--end-date",
        help=f"Filter by end date.  Valid formats: [{escaped_percents_date_formats}]",
        default=None,
        type=valid_date,
    )
    parser.add_argument(
        "--sort-individually",
        help="If True, sort commits individually by their date.  If False, group commits by repo.",
        default=False,
        action="store_true",
    )
    return parser.parse_args()


def main():
    args = get_args()
    PERSONAL_ACCESS_TOKEN = args.personal_access_token
    if PERSONAL_ACCESS_TOKEN is None:
        # if didn't specify personal access token by cli arg "-p/--personal-access-token", then try
        # environment variable "BITBUCKET_PERSONAL_ACCESS_TOKEN"
        PERSONAL_ACCESS_TOKEN = os.getenv("BITBUCKET_PERSONAL_ACCESS_TOKEN")
        if PERSONAL_ACCESS_TOKEN is None:
            # if environment variable is also None, then prompt user for personal access token
            PERSONAL_ACCESS_TOKEN = getpass.getpass()

    START_DATE = args.start_date
    END_DATE = args.end_date

    SORT_INDIVIDUALLY = args.sort_individually

    session = BitbucketSession(personal_access_token=PERSONAL_ACCESS_TOKEN)
    session.run(
        start_date=START_DATE, end_date=END_DATE, sort_individually=SORT_INDIVIDUALLY
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log.exception(e)
        sys.exit(1)
