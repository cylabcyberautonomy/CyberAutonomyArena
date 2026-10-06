"""TypedDict definitions for the plugin UI schema contract."""

from typing import Literal, NotRequired, TypedDict, Union


ShowWhen = dict[str, list[str]]


class TextWithSuggestionsField(TypedDict):
    field_type: Literal["text_with_suggestions"]
    label: str
    key: str
    suggestions: list[str]
    default: str
    show_when: NotRequired[ShowWhen]


class FlatCheckboxesField(TypedDict):
    field_type: Literal["flat_checkboxes"]
    label: str
    key: str
    options: list[str]
    short_names: NotRequired[dict[str, str]]
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
    key_short_names: NotRequired[dict[str, str]]
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
    cartesian_product: bool
