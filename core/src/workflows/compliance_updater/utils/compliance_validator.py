def is_valid_prowler_compliance(data: dict) -> bool:
    """Validate if the passed data is a valid Prowler compliance JSON.

    Args:
        data (dict): The JSON data to validate.

    Returns:
        True if the data is a valid Prowler compliance JSON, False otherwise.
    """
    required_keys = {"Framework", "Version", "Provider", "Description", "Requirements"}
    if not isinstance(data, dict) or not required_keys.issubset(data.keys()):
        return False

    if not isinstance(data["Requirements"], list):
        return False

    for req in data["Requirements"]:
        if not isinstance(req, dict):
            return False

        req_keys = {"Id", "Description", "Attributes", "Checks"}
        if not req_keys.issubset(req.keys()):
            return False

        if not isinstance(req["Attributes"], list) or not isinstance(
            req["Checks"], list
        ):
            return False

        for attr in req["Attributes"]:
            if not isinstance(attr, dict):
                return False

        for check in req["Checks"]:
            if not isinstance(check, str):
                return False

    return True
