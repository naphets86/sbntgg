"""Exakte Arithmetik für den Bedarf (Ausblick, Punkt "Exakte Arithmetik").

Lemma "Gleitkomma-Aufrundung" der Arbeit garantiert ``ceil(round(h * gamma, 9))`` nur für
höchstens acht Nachkommastellen und ``h * gamma <= 10**6``. Mit rationaler Arithmetik ist
``ceil(gamma * h)`` für *alle* Eingaben exakt.

Ein ``float`` wird über seine kürzeste Dezimaldarstellung (``repr``) gelesen: ``1.1`` ist
also genau 11/10 und nicht der binäre Näherungswert 1.100000000000000088...
"""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from typing import Union

Number = Union[int, float, str, Fraction, Decimal]


def to_fraction(value: Number) -> Fraction:
    """Wandelt eine Zahl exakt in einen Bruch (floats über ihre Dezimaldarstellung)."""
    if isinstance(value, bool):
        raise TypeError("bool ist keine Zahl")
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Wert ist nicht endlich")
        return Fraction(repr(value))
    return Fraction(value)


def exact_ceil(value: Fraction) -> int:
    """Kleinste ganze Zahl >= value, ohne Gleitkomma (``-(-p // q)``)."""
    return -((-value.numerator) // value.denominator)


def ceil_product(hosts: int, factor: Number) -> int:
    """Exaktes ``ceil(hosts * factor)``."""
    return exact_ceil(Fraction(hosts) * to_fraction(factor))
