import logging
from datetime import datetime, timezone
import sys
import os
import argparse
import getpass
import functools
from typing import Callable

# NON STDLIB
import requests
from requests.auth import HTTPBasicAuth, AuthBase

logging.basicConfig(level=logging.INFO)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


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
        username: str,
        password: str,
        consumer_key: str,
        consumer_secret: str,
        api_url: str = "https://api.bitbucket.org/2.0",
    ) -> None:
        self._USERNAME = username
        self._PASSWORD = password
        self._CONSUMER_KEY = consumer_key
        self._CONSUMER_SECRET = consumer_secret
        self._API_URL = api_url
        self._API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"

        self._access_token = None
        self._refresh_token = None

        self.session = requests.Session()

    def new_access_token(
        self, required_token_scopes: list[str] = ["project", "account"]
    ) -> None:
        """[summary] Will use password authentication to get a new access token, then set the private variable"""
        # GET ACCESS TOKEN
        url = "https://bitbucket.org/site/oauth2/access_token"
        request_data = {
            "grant_type": "password",
            "username": self._USERNAME,
            "password": self._PASSWORD,
        }

        # TODO: handle 2FA request and response where password is not valid
        res = requests.post(
            url,
            data=request_data,
            auth=HTTPBasicAuth(self._CONSUMER_KEY, self._CONSUMER_SECRET),
        )
        res_json = res.json()

        access_token_scopes = res_json["scopes"].split()
        for s in required_token_scopes:
            assert (
                s in access_token_scopes
            ), f"Missing required scope (Required: {', '.join(required_token_scopes)}). Edit consumer permission here: https://bitbucket.org/{self._USERNAME}/workspace/settings/oauth-consumers/"

        self._access_token = res_json["access_token"]
        self._refresh_token = res_json["refresh_token"]
        log.debug(f"{self._access_token=}\n{self._refresh_token=}")

        self.session.auth = BearerAuth(self._access_token)

    def refresh_access_token(self) -> None:
        assert self._refresh_token is not None, "No refresh token"

        url = "https://bitbucket.org/site/oauth2/access_token"
        request_data = {
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }

        res = requests.post(
            url,
            data=request_data,
            auth=HTTPBasicAuth(self._CONSUMER_KEY, self._CONSUMER_SECRET),
        )
        res_json = res.json()

        self._access_token = res_json["access_token"]
        self._refresh_token = res_json["refresh_token"]
        log.debug(f"{self._access_token=}\n{self._refresh_token=}")

        self.session.auth = BearerAuth(self._access_token)

    def requires_access_token(func: Callable) -> Callable:
        """Decorator to assert Access Token is set"""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0]
            assert self._access_token is not None, "No access token"

            return func(*args, **kwargs)

        return wrapper

    @requires_access_token
    def get_user_info(self) -> dict[str, str]:

        # GET USER ACCOUNT_ID and USER UUID
        url = f"{self._API_URL}/user"
        res = requests.get(url, auth=BearerAuth(self._access_token))
        res_json = res.json()

        # NOTE: here is how we will get the username if using something other than Password authentication, like Oath2
        user_username = res_json["username"]  # anmacode
        user_uuid = res_json["uuid"]  # numbers
        user_nickname = res_json["nickname"]  # Andrew Ma
        user_account_id = res_json["account_id"]  # numbers

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
        username: str = None,
        uuid: str = None,
        nickname: str = None,
        account_id: str = None,
    ) -> None:
        if username is not None:
            self._username = username

        if uuid is not None:
            self._user_uuid = uuid

        if nickname is not None:
            self._nickname = nickname

        if account_id is not None:
            self._account_id = account_id

    @requires_access_token
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
        res = requests.get(url, params, auth=BearerAuth(self._access_token))
        res_json = res.json()

        repo_objects = res_json["values"]
        # for repo in repo_objects:
        #     repo_permission = repo["permission"] # admin
        #     repo_full_name = repo["repository"]["full_name"] # anmacode/repo1
        #     repo_name = repo["repository"]["name"] # repo1
        #     repo_uuid = repo["repository"]["uuid"]
        #     log.info(f"{repo_permission=}\n{repo_full_name=}\n{repo_name=}\n{repo_uuid=}")
        ##     self.get_commits_in_repository(repo["repository"]["full_name"])

        return [repo["repository"]["full_name"] for repo in repo_objects]

    @requires_access_token
    def get_commits_in_repository(
        self,
        repo_full_name: str,
        *,
        account_id: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
    ) -> list[dict]:
        repo_workspace, repo_slug = repo_full_name.split("/")

        # FOR EACH REPO THAT USER HAS ACCESS TO, CHECK THE COMMITS (https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commits)
        repo_commits_api_url = (
            f"{self._API_URL}/repositories/{repo_workspace}/{repo_slug}/commits"
        )

        params = {}

        res = requests.get(
            repo_commits_api_url, params, auth=BearerAuth(self._access_token)
        )
        res_json = res.json()

        commit_objects = res_json["values"]

        commit_list = []

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

            commit_data = {
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

    def run(
        self,
        *,
        start_date: datetime = None,
        end_date: datetime = None,
        sort_individually: bool = False,
    ) -> None:
        self.new_access_token()

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
        description="Get My Bitbucket Commits",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_group = parser.add_argument_group("required arguments")
    required_group.add_argument(
        "-u",
        "--username",
        help="Your Bitbucket Username",
        required=True,
        default=argparse.SUPPRESS,
    )
    required_group.add_argument(
        "-k",
        "--key",
        help="Your Consumer Key. To create a consumer: https://bitbucket.org/{YOUR_WORKSPACE_ID}/workspace/settings/api",
        required=True,
        default=argparse.SUPPRESS,
    )
    required_group.add_argument(
        "-s",
        "--secret",
        help="Your Consumer Secret. To create a consumer: https://bitbucket.org/{YOUR_WORKSPACE_ID}/workspace/settings/api",
        required=True,
        default=argparse.SUPPRESS,
    )

    parser.add_argument(
        "-p",
        "--password",
        help="Your Bitbucket Password. Note: 2FA accounts do not work. This cli argument takes priority over environment variable 'BITBUCKET_PASSWORD'. If neither the cli argument nor environment variable exist, then user will be prompted for password.",
        default=None,
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
    USERNAME = args.username
    PASSWORD = args.password
    if PASSWORD is None:
        # if didn't specify password by cli arg "-p/--password", then try
        # environment variable "BITBUCKET_PASSWORD"
        PASSWORD = os.getenv("BITBUCKET_PASSWORD")
        if PASSWORD is None:
            # if environment variable is also None, then prompt user for password
            PASSWORD = getpass.getpass()
    CONSUMER_KEY = args.key
    CONSUMER_SECRET = args.secret

    START_DATE = args.start_date
    END_DATE = args.end_date

    SORT_INDIVIDUALLY = args.sort_individually

    session = BitbucketSession(
        username=USERNAME,
        password=PASSWORD,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
    )
    session.run(
        start_date=START_DATE, end_date=END_DATE, sort_individually=SORT_INDIVIDUALLY
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log.exception(e)
        sys.exit(1)
