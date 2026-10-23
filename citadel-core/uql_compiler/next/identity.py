"""User-supplied visual identity. Branding conveys no assurance status."""
import hashlib
from pathlib import Path

from .model import UQLError

SEAL_SHA256 = "736562814373312a141133bf41a6fe5431bdfd78bce52743332fcae05767df19"


def seal_bytes():
    content = (Path(__file__).parent / "assets" / "seal-of-eotu.jpg").read_bytes()
    if hashlib.sha256(content).hexdigest() != SEAL_SHA256:
        raise UQLError("Seal of Eotu asset does not match the approved original")
    return content


def visual_identity():
    return {"schema": "eotu.visual-identity/1", "name": "Seal of Eotu", "entity": "Eotu Labs WhaleWorks LLC",
            "asset": "seal.jpg", "sha256": SEAL_SHA256, "media_type": "image/jpeg",
            "width": 526, "height": 526,
            "alt": "Gold circular Seal of Eotu with three raised dots and an infinity motif on black",
            "role": "visual_identity", "security_certification": False}
