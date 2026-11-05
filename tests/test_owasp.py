from lab.owasp import UNMAPPED, categories_for, category_ids, load_table, parse_cwe


def test_table_has_the_ten_categories():
    assert category_ids() == [f"A{n:02d}:2025" for n in range(1, 11)]


def test_table_is_consistent_in_both_directions():
    table = load_table()
    for cat_id, category in table["categories"].items():
        for cwe in category["cwes"]:
            assert cat_id in table["cwe_to_categories"][cwe]
    for cwe, cats in table["cwe_to_categories"].items():
        for cat_id in cats:
            assert cwe in table["categories"][cat_id]["cwes"]


def test_names_have_no_html_entities():
    for category in load_table()["categories"].values():
        assert "&amp" not in category["name"]


def test_parse_accepts_the_formats_tools_use():
    assert parse_cwe(89) == 89
    assert parse_cwe("89") == 89
    assert parse_cwe("CWE-89") == 89
    assert parse_cwe("cwe-89") == 89
    assert parse_cwe("CWE-89: Improper Neutralization of Special Elements") == 89


def test_parse_rejects_values_that_mean_no_cwe():
    for raw in (-1, "-1", 0, "0", "", None, True, "not-a-cwe"):
        assert parse_cwe(raw) is None, raw


def test_known_mappings():
    assert categories_for(["CWE-89"]) == ["A05:2025"]  # SQLi -> Injection
    assert categories_for(["CWE-79"]) == ["A05:2025"]  # XSS -> Injection
    assert categories_for(["CWE-918"]) == ["A01:2025"]  # SSRF se integró en A01 en 2025


def test_no_cwe_or_unknown_cwe_is_never_guessed():
    assert categories_for([]) == [UNMAPPED]
    assert categories_for(["-1"]) == [UNMAPPED]
    assert categories_for(["CWE-999999"]) == [UNMAPPED]


def test_unknown_cwe_does_not_hide_a_known_one():
    assert categories_for(["CWE-999999", "CWE-89"]) == ["A05:2025"]


def test_several_cwes_yield_sorted_unique_categories():
    assert categories_for(["CWE-89", "CWE-918", "CWE-79"]) == ["A01:2025", "A05:2025"]
