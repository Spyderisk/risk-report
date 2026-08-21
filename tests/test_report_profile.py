import unittest

from report_profile import project_rows, project_rows_for_section


class ReportProfileTest(unittest.TestCase):
    def test_projects_configured_columns_in_order(self):
        rows = project_rows_for_section(
            [["A", "B", "C"], ["a", "b", "c"]],
            "test",
            {"columns": [
                {"index": 2, "header": "C"},
                {"index": 0, "header": "A"},
            ]},
        )

        self.assertEqual([["C", "A"], ["c", "a"]], rows)

    def test_rejects_schema_mismatch(self):
        with self.assertRaisesRegex(ValueError, "expected column 1"):
            project_rows_for_section(
                [["A", "Actual"]],
                "test",
                {"columns": [{"index": 1, "header": "Expected"}]},
            )

    def test_default_compliance_profile_removes_first_three_columns(self):
        rows, profile_name = project_rows(
            [[
                "Compliance Set",
                "Compliance Set Comment",
                "Compliant",
                "Compliance Threat",
                "Compliant",
                "Control Strategy",
                "Active",
            ], ["set", "comment", "yes", "threat", "no", "control", "true"]],
            "compliance",
            "27001",
        )

        self.assertEqual("default", profile_name)
        self.assertEqual([
            ["Compliance Threat", "Compliant", "Control Strategy", "Active"],
            ["threat", "no", "control", "true"],
        ], rows)


if __name__ == "__main__":
    unittest.main()
