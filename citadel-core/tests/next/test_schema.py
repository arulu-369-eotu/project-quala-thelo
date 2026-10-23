import json
from pathlib import Path

import pytest

from uql_compiler.next.model import canonical_bytes
from uql_compiler.next.parser import parse

ROOT = Path(__file__).resolve().parents[2]


def test_schema_matches_reference_and_rejects_invalid_shape():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas/uql-ir-0.2.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    data = parse((ROOT / "examples/phase_sensitive.uql").read_text()).to_dict()
    jsonschema.validate(data, schema)
    data["operations"][0]["phase"] = {"numerator": 1, "denominator": 1}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)


def test_golden_circuit_identity():
    vector = json.loads((ROOT / "conformance/canonical/bell-vector.json").read_text())
    program = parse(vector["source"])
    assert canonical_bytes(program.to_dict()).decode() == vector["canonical_ir"]
    assert program.ir_digest == vector["ir_digest"]
    assert program.circuit_digest == vector["circuit_digest"]
