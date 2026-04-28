"""
TypedDict definitions for the plugin UI schema contract.

Each AttackerPlugin / DefenderPlugin subclass implements ui_schema() returning
a PluginUISchema dict.  dashboard.py reads these at startup to render forms
dynamically — no plugin-specific knowledge lives in the dashboard.
"""

from typing import Literal, TypedDict, Union


class TextWithSuggestionsField(TypedDict):
    field_type: Literal["text_with_suggestions"]
    label: str
    key: str            # exact JSON key in the submitted config dict
    suggestions: list[str]
    default: str


class FlatCheckboxesField(TypedDict):
    field_type: Literal["flat_checkboxes"]
    label: str
    key: str
    options: list[str]


class CheckboxGroup(TypedDict):
    group_label: str
    options: list[str]


class GroupedCheckboxesField(TypedDict):
    field_type: Literal["grouped_checkboxes"]
    label: str
    key: str
    groups: list[CheckboxGroup]


class KeyValuePair(TypedDict):
    key: str
    value: str


class KeyValuePairsField(TypedDict):
    field_type: Literal["key_value_pairs"]
    label: str
    key: str
    entries: list[KeyValuePair]


class JsonField(TypedDict):
    field_type: Literal["json"]
    label: str
    key: str
    placeholder: str
    default: str


FieldSchema = Union[
    TextWithSuggestionsField,
    FlatCheckboxesField,
    GroupedCheckboxesField,
    KeyValuePairsField,
    JsonField,
]


class PluginUISchema(TypedDict):
    config_type: str
    label: str
    fields: list[FieldSchema]
    cartesian_product: bool  # if True, "Add" generates cartesian product across checkbox fields
