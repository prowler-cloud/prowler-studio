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

def validate_max_check_number(
    max_check_number: int,
) -> bool:
    """Validate if the max check number is a positive integer.

    Args:
        max_check_number (int): The max check number to validate.

    Returns:
        True if the max check number is a positive integer, False otherwise.
    """
    return isinstance(max_check_number, int) and max_check_number > 0

def validate_confidence_threshold(
    confidence_threshold: float,
) -> bool:
    """Validate if the confidence threshold is a float between 0 and 1.

    Args:
        confidence_threshold (float): The confidence threshold to validate.

    Returns:
        True if the confidence threshold is a float between 0 and 1, False otherwise.
    """
    return isinstance(confidence_threshold, float) and (
        0 <= confidence_threshold <= 1
    )