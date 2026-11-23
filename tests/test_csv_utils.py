from django.test import SimpleTestCase

from authorization_platform.core.csv_utils import csv_safe, csv_safe_row


class CsvSafetyTests(SimpleTestCase):
    def test_formula_prefixes_are_neutralized_without_changing_numbers(self):
        self.assertEqual(csv_safe("=HYPERLINK('x')"), "'=HYPERLINK('x')")
        self.assertEqual(csv_safe("+cmd"), "'+cmd")
        self.assertEqual(csv_safe("-danger"), "'-danger")
        self.assertEqual(csv_safe("@user"), "'@user")
        self.assertEqual(csv_safe(12), 12)
        self.assertEqual(csv_safe_row(["=x", 12]), ["'=x", 12])
