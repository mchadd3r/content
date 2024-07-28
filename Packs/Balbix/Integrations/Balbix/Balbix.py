"""Balbix Integration for Cortex XSOAR
Development release 1.0

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import requests
from collections.abc import Callable


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, verify: bool, client_api_key: str):
        super().__init__(base_url=base_url, verify=verify)

        self.token = self.retrieve_auth_token()
        self.client_api_key = client_api_key

    def retrieve_auth_token(self) -> str:
        api_key = demisto.params().get('credentials', {}).get('password')

        # Retrieve basic auth credentials
        basic_credentials = demisto.params().get('basic_credentials', {})
        username = basic_credentials.get('identifier')
        password = basic_credentials.get('password')

        if not username or not password:
            raise DemistoException('Username and password must be provided.')
        creds = f"{username}:{password}"
        encoded_credentials = base64.b64encode(creds.encode()).decode()
        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
            'Accept': 'application/json'
        }
        params = {'key': api_key}
        response = requests.request(
            'GET',
            f'{self._base_url}/apis/v1/basic_token',
            headers=headers,
            params=params,
            verify=self._verify
        )
        if response.status_code != 200:
            raise DemistoException(
                f'Failed to retrieve auth token. Status code: {response.status_code}. Error: {response.text}')
        return response.text

    def http_request(self, method: str, url_suffix: str, params: dict = None, data: dict = None):
        headers = {
            "Authorization": self.token,
            "Client-API-Key": self.client_api_key,
            "Content-Type": "application/json",
            'Accept': 'application/json'
        }
        # data = {
        #     "page_offset": 0,
        #     "page_limit": 10
        # }
        url = f'{self._base_url}{url_suffix}'
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                json=data,
                verify=self._verify
            )
        except requests.exceptions.SSLError as err:
            raise DemistoException(f'Connection error in the API call.\nCheck your not secure parameter.\n\n{err}')
        except requests.ConnectionError as err:
            raise DemistoException(f'Connection error in the API call.\nCheck your Server URL parameter.\n\n{err}')
        if response.status_code not in {200, 204}:
            raise DemistoException(f'API call failed with error code: {response.status_code}.\nError: {response.text}')
        return response.json() if response.text else {}


def test_module(client: Client) -> str:
    """
    Tests the connection to the API by performing a basic GET request with the API key.
    """
    url_suffix = '/apis/v1/bx-it/asset/asset_list'
    request_body = {
        "page_offset": 0,
        "page_limit": 10
    }

    try:
        response = client.http_request(method='POST', url_suffix=url_suffix, data=request_body)
        if response:
            return 'ok'
        return 'Test failed: No response received'
    except Exception as e:
        return f'Test failed: {str(e)}'


''' COMMAND FUNCTIONS '''


def get_asset_id(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Search for the Device ID which uniquely identifies a Balbix Asset

    Args:
        client (Client): The Balbix client object.
        args (Dict[str, Any]): A dictionary of arguments provided by the user.
            The optional arguments are:
            - 'hostname': The hostname to search for.
            - 'ip': The IP Address to search for.
            - 'mac': The MAC Address to search for.

    Returns:
        CommandResults: A CommandResults object containing the raw JSON results of the search.
    """
    hostname = args.get('hostname')
    ip = args.get('ip')
    mac = args.get('mac')

    if not (hostname or ip or mac):
        raise ValueError('At least one of hostname, IP address, or MAC address must be provided')

    request_body = {
        "page_offset": 0,
        "page_limit": 10
    }

    if hostname:
        request_body["host_name"] = hostname
    if ip:
        request_body["ip"] = ip
    if mac:
        request_body["mac"] = mac

    url_suffix = '/apis/v1/bx-it/asset/asset_list'
    response = client.http_request(method='POST', url_suffix=url_suffix, data=request_body)

    # Ensure response is a dictionary
    if not isinstance(response, dict):
        return CommandResults(
            readable_output="The response is not in the expected format.",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="dev_id",
            outputs={}
        )

    # Extract the dev_id from the data array
    data = response.get('data', [])
    if not data:
        return CommandResults(
            readable_output="The response does not contain any data.",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="dev_id",
            outputs={}
        )

    device_ids = [item.get('dev_id') for item in data if item.get('dev_id')]

    if not device_ids:
        return CommandResults(
            readable_output="No valid dev_id found in the response.",
            outputs_prefix="Balbix.Assets",
            outputs_key_field="dev_id",
            outputs={}
        )

    return CommandResults(
        readable_output=f"Device IDs: {', '.join(map(str, device_ids))}",
        outputs_prefix="Balbix.Assets",
        outputs_key_field="dev_id",
        outputs={"Balbix.Assets": [{"dev_id": dev_id} for dev_id in device_ids]}
    )

# TODO Add roles, active issues, cves, users


def get_asset_details(client: Client, args: dict[str, Any]) -> CommandResults:
    device_id = args.get('device_id')
    if not device_id:
        raise ValueError('Balbix Device ID must be provided')

    url_suffix = f'/apis/v1/bx-it/asset/asset_details/{device_id}'
    response = client.http_request(method='GET', url_suffix=url_suffix)

    if not isinstance(response, dict):
        return CommandResults(
            readable_output="The response is not in the expected format.",
            outputs_prefix="Balbix.Asset",
            outputs_key_field="Hostname",
            outputs={}
        )

    data = response.get('data')
    if not data or not isinstance(data, dict):
        return CommandResults(
            readable_output="The response does not contain valid asset details.",
            outputs_prefix="Balbix.Asset",
            outputs_key_field="Hostname",
            outputs={}
        )

    host_name = data.get('host_name')
    if not host_name:
        return CommandResults(
            readable_output="No valid host_name found in the response.",
            outputs_prefix="Balbix.Asset",
            outputs_key_field="Hostname",
            outputs={}
        )

    # Set indicator fields based on the response with default values
    indicator_fields = {
        "bxdevid": data.get("dev_id", ""),
        "bxmacaddresses": data.get("mac", ""),
        "bxipaddresses": data.get("ip", ""),
        "bxserialnumber": data.get("serial_number", ""),
        "bxgeolocation": data.get("location_city", ""),
        "bxassettype": data.get("device_type", ""),
        "bxtags": data.get("device_tags", []),
        "bxgroups": data.get("groups", []),
        "bxassetsubtype": data.get("device_subtype", ""),
        "bxos": data.get("operatingsystem", ""),
        "bxospatchstatus": data.get("os_patch_state", ""),
        "bxmanufacturer": data.get("system_manufacturer", ""),
        "bxsite": data.get("site_name", ""),
        "bxlastprocessed": data.get("updated_at", ""),
        "bxinterfaceinfo": data.get("interfaces", []),
        "bxrebootpendingstatus": data.get("is_reboot_pending", ""),
        "bxuptimeindays": (data.get("uptime_mins", 0) or 0) // 1440  # converting minutes to days
    }

    # Remove None values
    indicator_fields = {k: v for k, v in indicator_fields.items() if v}

    # Create the indicator in XSOAR
    try:
        demisto.createIndicators([{
            "type": "Balbix Asset",
            "value": host_name,
            "fields": indicator_fields
        }])
        success_message = f"Successfully created indicator for host_name: {host_name}"
    except Exception as e:
        return CommandResults(
            readable_output=f"Failed to create indicator: {str(e)}",
            outputs_prefix="Balbix.Asset",
            outputs_key_field="Hostname",
            outputs=response
        )

    # Define the context output to match the YAML context paths
    context_output = {
        "Hostname": data.get("host_name", ""),
        "DeviceID": data.get("dev_id", ""),
        "MACAddresses": data.get("mac", ""),
        "IPAddresses": data.get("ip", ""),
        "SerialNumber": data.get("serial_number", ""),
        "GeoLocation": data.get("location_city", ""),
        "AssetType": data.get("device_type", ""),
        "AssetSubType": data.get("device_subtype", ""),
        "OperatingSystem": data.get("operatingsystem", ""),
        "OSPatchStatus": data.get("os_patch_state", ""),
        "Manufacturer": data.get("system_manufacturer", ""),
        "Site": data.get("site_name", ""),
        "LastProcessed": data.get("updated_at", ""),
        "InterfaceInfo": data.get("interfaces", []),
        "RebootPendingStatus": data.get("is_reboot_pending", ""),
        "UptimeInDays": (data.get("uptime_mins", 0) or 0) // 1440  # converting minutes to days
    }

    # Generate the markdown table
    markdown = tableToMarkdown("Asset Details", context_output)

    return CommandResults(
        readable_output=f"{success_message}\n\n{markdown}",
        outputs_prefix="Balbix.Asset",
        outputs_key_field="Hostname",
        outputs={"Balbix.Asset": context_output},
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
    base_url = params.get('url')
    use_ssl = not params.get('insecure', False)

    client_api_key = demisto.params().get('client_key')

    client = Client(base_url=base_url, verify=use_ssl, client_api_key=client_api_key)

    demisto.debug(f'Command being called is {command}')

    commands: dict[str, Callable[[Client, dict[str, str]], CommandResults]] = {
        'balbix-get-asset-id': get_asset_id,
        'balbix-get-asset-details': get_asset_details,
        'balbix-get-asset-vulnerabilities': get_asset_vulnerabilities
    }

    try:
        if command in commands:
            return_results(commands[command](client, demisto.args()))
        elif command == 'test-module':
            result = test_module(client)
            return_results(result)
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
