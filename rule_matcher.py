import importlib
import io
import json
import os
from pathlib import Path
from pkgutil import walk_packages


def recover_checks_from_provider(provider: str, service: str = None) -> list[tuple]:
    """
    Recover all checks from the selected provider and service

    Returns a list of tuples with the following format (check_name, check_path)
    """
    try:
        checks = []
        modules = list_modules(provider, service)
        for module_name in modules:
            # Format: "prowler.providers.{provider}.services.{service}.{check_name}.{check_name}"
            check_module_name = module_name.name
            # We need to exclude common shared libraries in services
            if check_module_name.count(".") == 6 and "lib" not in check_module_name:
                check_path = module_name.module_finder.path
                # Check name is the last part of the check_module_name
                check_name = check_module_name.split(".")[-1]
                check_info = (check_name, check_path)
                checks.append(check_info)
    except ModuleNotFoundError:
        logger.critical(f"Service {service} was not found for the {provider} provider.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
        sys.exit(1)
    else:
        return checks
    


    # List all available modules in the selected provider and service
def list_modules(provider: str = "aws"):
    # This module path requires the full path including "prowler."
    metadata_files = []
    module_path = f"prowler/prowler/providers/{provider}/services"
    for root, dirs, files in os.walk(module_path, topdown=False):
        for name in files:
            if ".metadata.json" in name:
                metadata_files.append(os.path.join(root, name))

    return metadata_files



def list_rules_scout2():
    
    metadata_files = []
    module_path = "/Users/admin/Documents/work/ScoutSuite/ScoutSuite/providers/aws/rules/findings"
    for root, dirs, files in os.walk(module_path, topdown=False):
        for name in files:
            if ".json" in name:
                metadata_files.append(os.path.join(root, name))

    return metadata_files

# Load all checks metadata
def bulk_load_checks_metadata(tool : str) -> dict:
    bulk_check_metadata = []
    checks = None
    if "prowler" == tool:
        checks = list_modules("aws")
    else:
        checks = list_rules_scout2()
    # Build list of check's metadata files
    for check_info in checks:
        # Build check path name
         
        # Append metadata file extension
        # metadata_file = f"check_info"
        # Load metadata
        check_metadata = load_check_metadata(check_info)
        check_metadata["filename"] = check_info 
        bulk_check_metadata.append(check_metadata)
        # bulk_check_metadata[check_metadata.CheckID] = check_metadata

    return bulk_check_metadata

# Testing Pending
def load_check_metadata(metadata_file: str) -> dict :
    """load_check_metadata loads and parse a Check's metadata file"""
    try:
        check_metadata = json.loads(io.open(metadata_file).read())
    except ValidationError as error:
        logger.critical(f"Metadata from {metadata_file} is not valid: {error}")
        sys.exit(1)
    else:
        return check_metadata
    

from openai import OpenAI


# defaults to getting the key using os.environ.get("OPENAI_API_KEY")
# if you saved the key under a different environment variable name, you can do something like:
client = OpenAI(api_key="")



def chat_gpt():
    response = client.completions.create(
        model="gpt-3.5-turbo-instruct",
        prompt="Write a tagline for an ice cream shop."
    )
    print(response)


def generate_aggregation():
    metadata = bulk_load_checks_metadata("prowler")
    new_arr = []
    services = {}
    for m in metadata:
        service = m.get("CheckID")[0:m.get("CheckID").find("_")]
        new_arr.append({"id":m.get("CheckID"),
                       "title":m.get("CheckTitle"),
                       "descriptiom":m.get("Description"),
                       "tool":"prowler",
                       "service":service})
        if not services.get(service):
            services[service] = []
        services[service].append(new_arr[-1])

    metadata = bulk_load_checks_metadata("scout")
    for m in metadata:
        id = Path(m.get("filename")).name.replace(".json","").replace("-","_")
        service = id[0:id.find("_")]
        new_arr.append({"id":id,
                       "title":m.get("description"),
                       "descriptiom":m.get("rationale"),
                       "tool":"scout",
                       "service":service})
        if not services.get(service):
            services[service] = []
        services[service].append(new_arr[-1])

    json.dump(new_arr,io.open("consolidated_rules_prowler.json","w+"))
    print(new_arr)

if __name__ == "__main__":
    # chat_gpt()
    generate_aggregation()
    