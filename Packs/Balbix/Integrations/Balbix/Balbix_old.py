import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Balbix Integration for Cortex XSOAR
Development release 1.0

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from collections.abc import Callable

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool):
        # Retrieve credentials from the integration parameters
        credentials = demisto.params().get('credentials', {})
        username = credentials.get('identifier')
        password = credentials.get('password')

        if not username or not password:
            raise ValueError('Username or Password is missing in the credentials.')

        # Encode credentials in base64 for Basic Auth
        creds = f"{username}:{password}"
        encoded_credentials = base64.b64encode(creds.encode()).decode()

        header = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
            'Accept': 'application/json'
        }
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=header)

    def http_request(self, method: str, url_suffix: str, params: dict | None = None,
                     data: dict | None = None):
        """Connects to API and returns response.
           Args:
               method: The HTTP method, for example: GET, POST, and so on
               url_suffix: The API endpoint.
               params: URL parameters to specify the query.
               data: The data to send in a specific request.
           Returns:
               Response from the API.
           """
        url = f'{self._base_url}{url_suffix}'
        try:
            response = requests.request(
                method,
                url,
                headers=self._headers,
                params=params,
                json=data,
                verify=self._verify,
            )
        except requests.exceptions.SSLError as err:
            raise DemistoException(f'Connection error in the API call to Balbix.\n'
                                   f'Check your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            raise DemistoException(f'Connection error in the API call to Balbix.\n'
                                   f'Check your Server URL parameter.\n\n{err}')
        try:
            response_dict = response.json() if response.text else {}
            if not response.ok:
                if response_dict.get('error') == "unauthorized":
                    raise DemistoException(f'Connection error in the API call to Balbix.\n'
                                           f'Check your API Key parameter.\n\n{response_dict.get("message")}')
                else:
                    raise DemistoException(
                        f'API call to Balbix failed with error code: {response.status_code}.\n'
                        f'Error: {response_dict.get("error")}\n'
                        f'Message: {response_dict.get("message")}'
                    )
            elif response.status_code == 204:
                return {'status': 'success'}
            return response_dict
        except TypeError:
            raise Exception(f'Error in API call to Balbix, could not parse result [{response.status_code}]')


def test_module(client: Client) -> str:
    """
    Tests the connection to the Balbix v2 API by performing a basic GET request.
    """
    client.http_request('GET', '/assets/stats')
    return 'ok'


'''HELPER FUNCTIONS'''


def process_tags_field(tagslist):
    if isinstance(tagslist, list):
        return [{'tag': tag} for tag in tagslist if tag]
    return []


def process_users_field(users_list):
    if isinstance(users_list, list):
        return [{'username': user} for user in users_list if user]
    return []


def process_observers_field(observers_list):
    if isinstance(observers_list, list):
        return [{'observer': observer} for observer in observers_list if observer]
    return []


def process_roles_field(roles_list):
    if isinstance(roles_list, list):
        return [{'role': role} for role in roles_list if role]
    return []


def process_ports_field(ports_list):
    if isinstance(ports_list, list):
        return [{'port': port} for port in ports_list if port]
    return []


def parse_response(raw_data: List[dict[str, Any]], wanted_keys: List[Any], actual_keys: List[Any]) -> \
        List[dict[str, Any]]:
    """Lists all raw data and return outputs in Demisto's format.
    Args:
        raw_data: raw response from the api.
        wanted_keys: The keys as we would like them to be.
        actual_keys :The keys as they are in raw response.
    Returns:
        Specific Keys from the raw data.
    """

    context_list = []
    for raw in raw_data:
        context = {}
        for wanted_key, actual_key in zip(wanted_keys, actual_keys):
            if isinstance(wanted_key, list):
                inner_raw = raw.get(actual_key[0])
                if inner_raw:
                    lst_inner = []
                    for in_raw in inner_raw:
                        inner_dict = {}
                        for inner_wanted_key, inner_actual_key in zip(wanted_key[1:], actual_key[1:]):
                            inner_dict.update({inner_wanted_key: in_raw.get(inner_actual_key)})
                        lst_inner.append(inner_dict)
                    context.update({wanted_key[0]: lst_inner})
            else:
                context.update({wanted_key: raw.get(actual_key)})
        context_list.append(context)
    return context_list


def create_asset_table(response_data):
    # Define the column order
    headers = [
        "NAME", "IMPACT", "LIKELIHOOD", "RISK", "MAC Addresses", "IP Addresses",
        "SERIAL NUMBER", "GEO LOCATION", "ASSET TYPE", "ASSET SUBTYPE",
        "OPERATING SYSTEM", "OS PATCH STATUS", "LAST PATCH DATE",
        "MANUFACTURER", "SITE", "LAST OBSERVED", "FIRST OBSERVED",
        "LAST PROCESSED", "Roles", "Ports", "TAGS",
        "Interface Info (IP,MAC,SUBNET,VLAN)", "ACTIVE ISSUES",
        "CVEs", "REBOOT PENDING STATUS", "UPTIME IN DAYS", "OBSERVERS", "USERS"
    ]

    # Generate the markdown table
    markdown = tableToMarkdown("API Response", response_data, headers=headers)

    # Return the CommandResults
    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Balbix.Response",
        outputs_key_field="NAME",
        outputs=response_data
    )


''' COMMAND FUNCTIONS '''


def get_asset_details(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Search for assets in Balbix based on the provided hostname and create a custom indicator.

    Args:
        client (Client): The Balbix client object.
        args (Dict[str, Any]): A dictionary of arguments provided by the user.
            The required argument is:
            - 'hostname': The hostname to search for.

    Returns:
        CommandResults: A CommandResults object containing the raw JSON results of the search.
    """
    hostname = args.get('hostname')
    if not hostname:
        raise ValueError('Hostname must be provided')

    url_suffix = f'/assets/{hostname}'
    response = client.http_request(method='GET', url_suffix=url_suffix)

    # Ensure response is a dictionary
    if not isinstance(response, dict):
        return CommandResults(
            readable_output="The response is not in the expected format.",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="NAME",
            outputs={}
        )

    asset_name = response.get("NAME")
    if not asset_name:
        return CommandResults(
            readable_output="The response does not contain a valid asset name.",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="NAME",
            outputs={}
        )

    # Process fields
    tags_field = process_tags_field(response.get("TAGS", []))
    users_field = process_users_field(response.get("USERS", []))
    observers_field = process_observers_field(response.get("OBSERVERS", []))
    roles_field = process_roles_field(response.get("Roles", []))
    ports_field = process_ports_field(response.get("Ports", []))

    # Set indicator fields based on the response
    indicator_fields = {
        "bximpact": response.get("IMPACT"),
        "bxlikelihood": response.get("LIKELIHOOD"),
        "bxrisk": response.get("RISK"),
        "bxmacaddresses": response.get("MAC Addresses"),
        "bxipaddresses": response.get("IP Addresses"),
        "bxserialnumber": response.get("SERIAL NUMBER"),
        "bxgeolocation": response.get("GEO LOCATION"),
        "bxassettype": response.get("ASSET TYPE"),
        "bxassetsubtype": response.get("ASSET SUBTYPE"),
        "bxos": response.get("OPERATING SYSTEM"),
        "bxospatchstatus": response.get("OS PATCH STATUS"),
        "bxlastpatchdate": response.get("LAST PATCH DATE"),
        "bxmanufacturer": response.get("MANUFACTURER"),
        "bxsite": response.get("SITE"),
        "bxlastobserved": response.get("LAST OBSERVED"),
        "bxfirstobserved": response.get("FIRST OBSERVED"),
        "bxlastprocessed": response.get("LAST PROCESSED"),
        "bxroles": roles_field,
        "bxports": ports_field,
        "bxtags": tags_field,
        "bxinterfaceinfo": response.get("Interface Info (IP,MAC,SUBNET,VLAN)"),
        "bxactiveissues": response.get("ACTIVE ISSUES"),
        "bxcves": response.get("CVEs"),
        "bxrebootpendingstatus": response.get("REBOOT PENDING STATUS"),
        "bxuptimeindays": response.get("UPTIME IN DAYS"),
        "bxobservers": observers_field,
        "bxusers": users_field
    }

    # Remove None values
    indicator_fields = {k: v for k, v in indicator_fields.items() if v is not None}

    # Create the indicator in XSOAR
    try:
        demisto.createIndicators([{
            "type": "Balbix Asset",
            "value": asset_name,
            "fields": indicator_fields
        }])
    except Exception as e:
        return CommandResults(
            readable_output=f"Failed to create indicator: {str(e)}",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="NAME",
            outputs=response
        )

    # Define the column order for the markdown table
    headers = [
        "NAME", "IMPACT", "LIKELIHOOD", "RISK", "MAC Addresses", "IP Addresses",
        "SERIAL NUMBER", "GEO LOCATION", "ASSET TYPE", "ASSET SUBTYPE",
        "OPERATING SYSTEM", "OS PATCH STATUS", "LAST PATCH DATE",
        "MANUFACTURER", "SITE", "LAST OBSERVED", "FIRST OBSERVED",
        "LAST PROCESSED", "Roles", "Ports", "TAGS",
        "Interface Info (IP,MAC,SUBNET,VLAN)", "ACTIVE ISSUES",
        "CVEs", "REBOOT PENDING STATUS", "UPTIME IN DAYS", "OBSERVERS", "USERS"
    ]

    # Generate the markdown table
    markdown = tableToMarkdown("Asset Details", response, headers=headers)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Balbix.Assets",
        outputs_key_field="NAME",
        outputs=response,
        raw_response=response
    )


def get_asset_vulnerabilities(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Returns vulnerabilities for the given Balbix Asset.

    Args:
        client (Client): The Balbix client object.
        args (Dict[str, Any]): A dictionary of arguments provided by the user.
            The required argument is:
            - 'hostname': The hostname of the Balbix Asset.

    Returns:
        CommandResults: A CommandResults object containing the enriched data.
    """
    hostname = args.get('hostname')
    if not hostname:
        raise ValueError('Hostname must be provided')

    # Fetch the existing indicator using the hostname
    indicator_search = demisto.searchIndicators(query=f"value:\"{hostname}\"")
    indicators = indicator_search.get('iocs', [])
    if not indicators:
        raise ValueError(f'Indicator with hostname {hostname} not found')

    indicator = indicators[0]
    demisto.debug(f"Fetched indicator: {json.dumps(indicator, indent=2)}")

    url_suffix = f'/cves/tactical/{hostname}'
    response = client.http_request(method='GET', url_suffix=url_suffix)

    # Ensure response is a list
    if not isinstance(response, list):
        return CommandResults(
            readable_output="The response is not in the expected format.",
            outputs_prefix="Balbix.Assets.Vulnerabilities",
            outputs_key_field="Name",
            outputs={}
        )

    if not response:
        return CommandResults(
            readable_output="No vulnerabilities found for the provided hostname.",
            outputs_prefix="Balbix.Assets.Vulnerabilities",
            outputs_key_field="Name",
            outputs={}
        )

    # Process the response to create a list of vulnerabilities
    vulnerabilities = []
    for vuln in response:
        vulnerabilities.append({
            "Name": vuln.get("Name"),
            "Product": vuln.get("Product"),
            "Vendor": vuln.get("Vendor"),
            "Version": vuln.get("Version"),
            "Product Type": vuln.get("Product Type"),
            "Strategic Fix": vuln.get("Strategic Fix"),
            "Tactical Fixes": vuln.get("Tactical Fixes"),
            "CVE": vuln.get("CVE"),
            "CVSS Version 2.0 Score": vuln.get("CVSS Version 2.0 Score"),
            "CVSS Version 2.0 Severity": vuln.get("CVSS Version 2.0 Severity"),
            "CVSS Version 3.x Score": vuln.get("CVSS Version 3.x Score"),
            "CVSS Version 3.x Severity": vuln.get("CVSS Version 3.x Severity"),
            "CVE Tag": vuln.get("CVE Tag"),
            "First Detected Time": vuln.get("First Detected Time"),
            "Balbix Score": vuln.get("Balbix Score"),
            "Balbix Rank": vuln.get("Balbix Rank"),
            "Risk Accepted": vuln.get("Risk Accepted")
        })

    # Create a readable output
    headers = [
        "Name", "Product", "Vendor", "Version", "Product Type", "Strategic Fix", "Tactical Fixes",
        "CVE", "CVSS Version 2.0 Score", "CVSS Version 2.0 Severity", "CVSS Version 3.x Score",
        "CVSS Version 3.x Severity", "CVE Tag", "First Detected Time", "Balbix Score",
        "Balbix Rank", "Risk Accepted"
    ]
    readable_output = tableToMarkdown("Balbix Asset Vulnerabilities", vulnerabilities, headers=headers)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Balbix.Assets.Vulnerabilities",
        outputs_key_field="Name",
        outputs=vulnerabilities,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    # api = params.get('credentials_key', {}).get('password') or params.get('key')
    # if not api:
    #     raise DemistoException('Balbix API key must be provided.')
    # Service base URL
    base_url = params.get('url', '')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)
    # Should we use system proxy settings
    use_proxy = params.get('proxy', False)
    # Initialize Client object
    client = Client(base_url=base_url, verify=use_ssl, proxy=use_proxy)

    demisto.debug(f'Command being called is {command}')

    commands: dict[str, Callable[[Client, dict[str, str]], CommandResults]] = {
        'balbix-get-asset-details': get_asset_details,
        'balbix-get-asset-vulnerabilities': get_asset_vulnerabilities
    }
    try:
        if command in commands:
            return_results(commands[command](client, args))
        elif command == "test-module":
            result = test_module(client)
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as err:
        return_error(f"Failed to execute {command} command.\nError:\n{err!s}")


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
