import base64
import gzip
import json
from pathlib import Path

from .utils import read_file


class CheckInventory:
    """Manages the code and metadata of checks and services associated with an index of checks.

    Attributes:
        _inventory (dict): Inventory of checks and services. Nested dictionary with the following structure:
            {
                "provider_name": {
                    "service_name": {
                        "description": str,
                        "code": str,
                        "checks": {
                            "check_id": {
                                "metadata": str,
                                "code": str,
                                "fixer": str
                            },
                            ...
                        }
                    },
                    ...
                },
                ...
            }
    """

    def __init__(self, metadata: dict = {}):
        self._inventory = metadata.get("check_inventory", {})

    def to_dict(self):
        """Returns the inventory as a dictionary."""
        return self._inventory

    def get_available_providers(self) -> set[str]:
        """Retrieve the available providers.

        Returns:
            A set of available providers.
        """
        return set(self._inventory.keys())

    def get_available_services_in_provider(self, provider_name: str) -> set[str]:
        """Retrieve the available services for a given provider.

        Args:
            provider_name: The Prowler provider.

        Returns:
            A set of available services for the provider.
        """
        return set(self._inventory.get(provider_name, {}).keys())

    def get_available_checks_in_service(
        self, provider_name: str, service_name: str
    ) -> set[str]:
        """Retrieve the available checks for a given provider and service.

        Args:
            provider_name: The Prowler provider.
            service_name: The service name.

        Returns:
            A set of available checks for the provider and service.
        """
        return set(
            self._inventory.get(provider_name, {})
            .get(service_name, {})
            .get("checks", {})
            .keys()
        )

    def get_service_code(self, provider: str, service: str) -> str:
        """Retrieve the code of a service.

        Args:
            provider: The Prowler provider.
            service: The service name.

        Returns:
            The code of the service.
        """
        return self._get_data_format_for_storage(
            self._inventory.get(provider, {}).get(service, {}).get("code", "")
        )

    def get_check_metadata(self, provider: str, service: str, check_id: str) -> dict:
        """Retrieve the metadata of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The metadata of the check.
        """
        metadata_str = self._get_data_format_for_storage(
            self._inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("metadata", "")
        )
        if metadata_str != "":
            return json.loads(metadata_str)
        else:
            return {}

    def get_check_code(self, provider: str, service: str, check_id: str) -> str:
        """Retrieve the code of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The code of the check.
        """
        return self._get_data_format_for_storage(
            self._inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("code", "")
        )

    def get_check_fixer(self, provider: str, service: str, check_id: str) -> str:
        """Retrieve the fixer of a check.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The check ID.

        Returns:
            The fixer of the check.
        """
        return self._get_data_format_for_storage(
            self._inventory.get(provider, {})
            .get(service, {})
            .get("checks", {})
            .get(check_id, {})
            .get("fixer", "")
        )

    def add_provider(self, provider: str) -> bool:
        """Add a empty provider to the inventory.

        Args:
            provider: The Prowler provider.

        Returns:
            True if the provider was added, False otherwise.
        """
        if provider not in self._inventory:
            self._inventory[provider] = {}
            return True
        return False

    def add_service(self, provider: str, service: str) -> bool:
        """Add a empty service to the inventory, the provider must exist.

        Args:
            provider: The Prowler provider.
            service: The service name.
        Returns:
            True if the service was added, False otherwise.
        Raises:
            Exception: If the provider does not exist.
        """
        if provider not in self._inventory:
            raise Exception(f"Provider {provider} does not exist.")
        if service not in self._inventory[provider]:
            self._inventory[provider][service] = {
                "description": "",
                "code": "",
                "checks": {},
            }
            return True
        return False

    def add_check(self, provider: str, service: str, check_id: str) -> bool:
        """Add a empty check to the inventory, the service must exist.

        Args:
            provider: The Prowler provider.
            service: The service name.
            check_id: The ID of the check.

        Returns:
            True if the check was added, False otherwise.
        Raises:
            Exception: If the service does not exist.
        """
        if provider not in self._inventory:
            raise Exception(f"Provider {provider} does not exist.")
        if service not in self._inventory[provider]:
            raise Exception(f"Service {service} does not exist.")
        if check_id not in self._inventory[provider][service]["checks"]:
            self._inventory[provider][service]["checks"][check_id] = {
                "metadata": "",
                "code": "",
                "fixer": "",
            }
            return True
        return False

    def update_service(self, file_path: Path) -> bool:
        """Update the service code in the check inventory.

        If the service does not exist in the inventory, it will be added. If the service already exists,
        it will be updated only if the service code is different.

        Args:
            file_path: Path to the service file.

        Returns:
            True if the service was updated, False otherwise.
        """
        provider = file_path.parents[2].name
        service = file_path.parent.name

        self._inventory.setdefault(provider, {}).setdefault(
            service, {"description": "", "code": "", "checks": {}}
        )

        updated = False

        if file_path.exists():
            repo_service_code = read_file(file_path)

            if repo_service_code != self.get_service_code(provider, service):
                self._inventory[provider][service]["code"] = (
                    self._prepare_data_for_storage(repo_service_code)
                )
                updated = True

        return updated

    def update_check_metadata(self, provider, service, check_id, file_path) -> bool:
        """Update the metadata of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the metadata.

        Returns:
            True if the metadata was updated, False otherwise.
        """
        if file_path.exists():
            # If it is not set, set the default ID
            if check_id not in self._inventory[provider][service]["checks"]:
                self._inventory[provider][service]["checks"][check_id] = {
                    "metadata": "",
                    "code": "",
                    "fixer": "",
                }

            repo_content = read_file(file_path, json_load=True)
            if repo_content != self.get_check_metadata(provider, service, check_id):
                self._inventory[provider][service]["checks"][check_id]["metadata"] = (
                    self._prepare_data_for_storage(json.dumps(repo_content))
                )
                return True
        return False

    def update_check_code(self, provider, service, check_id, file_path) -> bool:
        """Update the code of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the code.

        Returns:
            True if the code was updated, False otherwise.
        """
        if file_path.exists():
            # If it is not set, set the default ID
            if check_id not in self._inventory[provider][service]["checks"]:
                self._inventory[provider][service]["checks"][check_id] = {
                    "metadata": "",
                    "code": "",
                    "fixer": "",
                }

            repo_content = read_file(file_path)
            if repo_content != self.get_check_code(provider, service, check_id):
                self._inventory[provider][service]["checks"][check_id]["code"] = (
                    self._prepare_data_for_storage(repo_content)
                )
                return True
        return False

    def update_check_fixer(self, provider, service, check_id, file_path) -> bool:
        """Update the fixer of a check.

        Args:
            provider: The Prowler provider of the check.
            service: The service name.
            check_id: The ID of the check.
            file_path: Path to the file containing the fixer.

        Returns:
            True if the fixer was updated, False otherwise.
        """
        if file_path.exists():
            repo_content = read_file(file_path)
            if repo_content != self.get_check_fixer(provider, service, check_id):
                self._inventory[provider][service]["checks"][check_id]["fixer"] = (
                    self._prepare_data_for_storage(repo_content)
                )
                return True
        return False

    def delete_provider(self, provider: str) -> bool:
        """Delete a provider from the inventory.

        Args:
            provider: The Prowler provider.

        Returns:
            True if the provider was deleted, False otherwise.
        """
        try:
            del self._inventory[provider]
            return True
        except KeyError:
            return False
        except Exception as e:
            raise Exception(f"Error deleting provider: {e}")

    def delete_service(self, provider: str, service: str) -> bool:
        """Delete a service from the inventory.

        Args:
            provider: The Prowler provider.
            service: The service name.

        Returns:
            True if the service was deleted, False otherwise.
        """
        try:
            del self._inventory[provider][service]
            return True
        except KeyError:
            return False
        except Exception as e:
            raise Exception(f"Error deleting service: {e}")

    def delete_check(self, provider: str, check_id: str) -> bool:
        """Delete a check from the inventory.

        Args:
            provider: The Prowler provider.
            check_id: The ID of the check.

        Returns:
            True if the check was deleted, False otherwise.
        """
        try:
            del self._inventory[provider][check_id.split("_")[0]]["checks"][check_id]
            return True
        except KeyError:
            return False
        except Exception as e:
            raise Exception(f"Error deleting check: {e}")

    # Storage format functions

    def _prepare_data_for_storage(self, data: str) -> str:
        """Compress and encode data for storage.

        Args:
            data: The data to compress and encode.

        Returns:
            The compressed and encoded data.
        """
        try:
            return base64.b64encode(gzip.compress(data.encode())).decode()
        except Exception as e:
            raise Exception(f"Error preparing data for storage: {e}")

    def _get_data_format_for_storage(self, data: str) -> str:
        """Decompress and decode data for storage.

        Args:
            data: The data to decompress and decode.

        Returns:
            The decompressed and decoded data.
        """
        try:
            return gzip.decompress(base64.b64decode(data)).decode()
        except Exception as e:
            raise Exception(f"Error getting data format for storage: {e}")
