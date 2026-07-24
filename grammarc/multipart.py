"""Multipart/form-data request template synthesis -- ported from
enhance-grammar.py::inject_multipart_seeds's field/boundary logic, but building a
`Template` dict directly (via body_serializer's segment primitives) instead of
text-injecting generated Python source into a `grammar.py` module between marker
comments. Removes the "text-append into an executable module" anti-pattern entirely;
multipart templates are now first-class IR objects like any other operation.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .body_serializer import seg_payload, seg_static
from .oas import FieldHint, MultipartEndpoint


def _split_path_template(path: str) -> List[tuple]:
    import re
    out = []
    for p in re.split(r"(\{[^}]+\})", path):
        if p == "":
            continue
        if p.startswith("{") and p.endswith("}"):
            out.append(("param", p[1:-1].strip() or "id"))
        else:
            out.append(("static", p))
    return out


def build_multipart_template(ep: MultipartEndpoint, template_id: int) -> Dict[str, Any]:
    boundary = "------------------------smartfuzzboundary"
    segs: List[Dict[str, Any]] = [seg_static(f"{ep.method} ")]
    for kind, value in _split_path_template(ep.path):
        if kind == "static":
            segs.append(seg_static(value))
        else:
            segs.append(seg_payload(value, quoted=False))
    segs.append(seg_static(" HTTP/1.1\r\n"))
    segs.append(seg_static("Accept: application/json\r\n"))
    segs.append(seg_static(f"Content-Type: multipart/form-data; boundary={boundary}\r\n"))
    segs.append(seg_static("Authorization: Bearer TOKEN\r\n"))
    segs.append(seg_static("\r\n"))

    fields = ep.fields or [FieldHint(name="file", type_name="string", fmt="binary", multipart_file=True)]
    for fld in fields:
        key = fld.name.split(".")[-1] if "." in fld.name else fld.name
        key = key or "file"
        segs.append(seg_static(f"--{boundary}\r\n"))
        if fld.multipart_file:
            segs.append(seg_static(f'Content-Disposition: form-data; name="{key}"; filename="'))
            segs.append(seg_payload(f"{key}.filename", quoted=False))
            segs.append(seg_static('"\r\n'))
            segs.append(seg_static("Content-Type: "))
            segs.append(seg_payload(f"{key}.contentType", quoted=False))
            segs.append(seg_static("\r\n\r\n"))
            segs.append(seg_payload(f"{key}.content", quoted=False))
            segs.append(seg_static("\r\n"))
        else:
            segs.append(seg_static(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'))
            segs.append(seg_payload(key, quoted=False))
            segs.append(seg_static("\r\n"))
    segs.append(seg_static(f"--{boundary}--\r\n"))

    return {
        "id": template_id,
        "request_id": f"{ep.method}{ep.path}",
        "segments": segs,
        "reads": [],
        "writes": [],
    }


def multipart_dict_seeds(ep: MultipartEndpoint) -> Dict[str, List[str]]:
    """Extra dict.json values for multipart file fields (filename/content-type/content
    pools) -- ported from enhance-grammar.py::DictionaryEnhancer.enhance_multipart_defaults."""
    out: Dict[str, List[str]] = {}
    for fld in ep.fields:
        key = fld.name.split(".")[-1] if "." in fld.name else fld.name
        if not key:
            continue
        if fld.multipart_file:
            out[f"{key}.filename"] = ["fuzz.bin", "payload.txt"]
            out[f"{key}.contentType"] = ["application/octet-stream", "text/plain", "image/png"]
            out[f"{key}.content"] = ["A", "{}", '<svg xmlns="http://www.w3.org/2000/svg"></svg>']
    return out
