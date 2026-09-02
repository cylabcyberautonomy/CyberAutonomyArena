"""
TypedDict definitions for the plugin UI schema contract.

Each AttackerPlugin / DefenderPlugin subclass implements ui_schema() returning
a PluginUISchema dict.  dashboard.py reads these at startup to render forms
dynamically — no plugin-specific knowledge lives in the dashboard.
"""

from typing import Literal, NotRequired, TypedDict, Union


# Maps a *sibling* field's key to the list of values for which THIS field is
# shown.  The dashboard evaluates every condition against the form's current
# values: the field is visible only when, for each controlling key, at least one
# currently-selected value appears in the allowed list (OR within a key, AND
# across keys).  A hidden field is excluded from validation and from the emitted
# config entirely, so the plugin must give it a default.  Example:
#   "show_when": {"abstraction": ["agent_scan", "agent_all"]}
ShowWhen = dict[str, list[str]]


class TextWithSuggestionsField(TypedDict):
    field_type: Literal["text_with_suggestions"]
    label: str
    key: str            # exact JSON key in the submitted config dict
    suggestions: list[str]
    default: str
    show_when: NotRequired[ShowWhen]


class FlatCheckboxesField(TypedDict):
    field_type: Literal["flat_checkboxes"]
    label: str
    key: str
    options: list[str]
    show_when: NotRequired[ShowWhen]


class CheckboxGroup(TypedDict):
    group_label: str
    options: list[str]


class GroupedCheckboxesField(TypedDict):
    field_type: Literal["grouped_checkboxes"]
    label: str
    key: str
    groups: list[CheckboxGroup]
    show_when: NotRequired[ShowWhen]


class KeyValuePair(TypedDict):
    key: str
    value: str


class KeyValuePairsField(TypedDict):
    field_type: Literal["key_value_pairs"]
    label: str
    key: str
    entries: list[KeyValuePair]
    show_when: NotRequired[ShowWhen]


class JsonField(TypedDict):
    field_type: Literal["json"]
    label: str
    key: str
    placeholder: str
    default: str
    show_when: NotRequired[ShowWhen]


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
