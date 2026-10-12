"""Names as parts of an email address: the shared rules of data contract 10.4.3 (#8, #12)."""

import pytest

from qnsentry.modules.names import CONVENTIONS, JOINED, SEPARATED, local_part, normalise_word, split_name


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ("Peeters", "peeters"),
        ("Gérard", "gerard"),  # accents removed (NFKD)
        ("Çelik", "celik"),
        ("Strauß", "strauss"),  # letters NFKD does not split
        ("Ærø", "aero"),
        ("Łukasz", "lukasz"),
        ("D'Hondt", "dhondt"),  # apostrophes removed
        ("D’Hondt", "dhondt"),
        ("Dierckx-Gérard", "dierckx-gerard"),  # hyphens kept
        ("(Jan)", "jan"),  # anything else cannot be in an address
    ],
)
def test_normalise_word(word, expected):
    assert normalise_word(word) == expected


def test_first_word_is_the_first_name_and_the_rest_the_last_name():
    assert split_name("Sofie Van den Broeck") == ("sofie", ["van", "den", "broeck"])
    assert split_name("  Jan   Peeters ") == ("jan", ["peeters"])


@pytest.mark.parametrize("name", ["Jan", "ljanssens", "", "  ", "'"])
def test_a_name_without_first_and_last_name_is_not_usable(name):
    assert split_name(name) is None
    assert local_part(name, "first.last") is None


@pytest.mark.parametrize(
    ("convention", "expected"),
    [
        ("first.last", "jan.peeters"),
        ("firstlast", "janpeeters"),
        ("flast", "jpeeters"),
        ("f.last", "j.peeters"),
        ("first_last", "jan_peeters"),
        ("last.first", "peeters.jan"),
        ("first", "jan"),
    ],
)
def test_every_convention_of_the_contract(convention, expected):
    # The table of data contract 10.4.2
    assert local_part("Jan Peeters", convention) == expected


def test_all_conventions_are_covered():
    assert set(CONVENTIONS) == {"first.last", "firstlast", "flast", "f.last", "first_last", "last.first", "first"}


@pytest.mark.parametrize(
    ("convention", "style", "expected"),
    [
        ("first.last", JOINED, "lotte.vandenbroeck"),
        ("first.last", SEPARATED, "lotte.van.den.broeck"),
        ("first_last", SEPARATED, "lotte_van_den_broeck"),
        ("last.first", SEPARATED, "van.den.broeck.lotte"),
        ("firstlast", SEPARATED, "lottevandenbroeck"),  # no separator: both styles are the same
    ],
)
def test_last_name_of_several_words(convention, style, expected):
    assert local_part("Lotte Van den Broeck", convention, style) == expected


def test_accents_and_hyphens_in_an_address():
    assert local_part("Gérard Dierckx-Dubois", "first.last") == "gerard.dierckx-dubois"


def test_unknown_convention_is_refused():
    with pytest.raises(ValueError, match="Unknown email convention"):
        local_part("Jan Peeters", "lastfirst")
