import json
from pathlib import Path


DEFAULT_CONFIG_PATH = Path(__file__).with_name("report_profiles.json")


def load_profile(section_name, iso_standard, config_path=DEFAULT_CONFIG_PATH):
    with Path(config_path).open(encoding="utf-8") as config_file:
        config = json.load(config_file)

    profile_name = config["default_profile"]
    profile = config["profiles"][profile_name]
    section_key = section_name.lower()
    section = profile[section_key]
    if section_key == "security":
        section = section[str(iso_standard)]
    return profile_name, section


def project_rows_for_section(rows, profile_name, section):
    if not rows:
        return []
    source_header = rows[0]
    columns = section["columns"]

    for column in columns:
        index = column["index"]
        expected_header = column["header"]
        if index >= len(source_header) or source_header[index] != expected_header:
            actual_header = source_header[index] if index < len(source_header) else None
            raise ValueError(
                f"Report profile '{profile_name}' expected column {index} to be "
                f"'{expected_header}', but found {actual_header!r}"
            )

    projected = []
    for row in rows:
        projected.append([
            row[column["index"]] if column["index"] < len(row) else ""
            for column in columns
        ])
    return projected


def project_rows(rows, section_name, iso_standard, config_path=DEFAULT_CONFIG_PATH):
    profile_name, section = load_profile(
        section_name,
        iso_standard,
        config_path,
    )
    return project_rows_for_section(rows, profile_name, section), profile_name
