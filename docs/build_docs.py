#!/usr/bin/env python3
"""Rebuild the report figures and every Word document from Markdown.

    python docs/build_docs.py            # figures + all .docx
    python docs/build_docs.py --no-figures

Uses pandoc with docs/reference.docx (styles, page setup, footer with page
numbers). Pandoc declares embedded PNGs with per-part <Override> entries, which
Word accepts but strict validators dislike, so a <Default Extension="png"> is
added to [Content_Types].xml afterwards.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

DOCS = Path(__file__).resolve().parent
ROOT = DOCS.parent
REFERENCE = DOCS / "reference.docx"
DOCUMENTS = ["NetSentry_Project_Report", "API", "ARCHITECTURE", "DEPLOYMENT", "MODELS"]


def postprocess(docx: Path) -> None:
    """Fix two things pandoc leaves behind: PNG content-type default, and the
    body section's page numbering (footer + decimal from 1), which pandoc drops
    from the reference document's final <w:sectPr>."""
    tmp = docx.with_suffix(".tmp")
    with zipfile.ZipFile(docx) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        names = zin.namelist()
        has_footer_rel = "word/_rels/document.xml.rels" in names and 'Id="rIdftr1"' in zin.read("word/_rels/document.xml.rels").decode("utf-8")
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "[Content_Types].xml":
                text = data.decode("utf-8")
                if 'Extension="png"' not in text:
                    text = text.replace("<Default ", '<Default Extension="png" ContentType="image/png"/><Default ', 1)
                data = text.encode("utf-8")
            elif item.filename == "word/document.xml" and has_footer_rel:
                text = data.decode("utf-8")
                last = list(re.finditer(r"<w:sectPr[^>]*>.*?</w:sectPr>", text, re.S))[-1]
                sect = last.group(0)
                if "footerReference" not in sect:
                    sect = re.sub(r"(<w:sectPr[^>]*>)", r'\1<w:footerReference w:type="default" r:id="rIdftr1"/>', sect, count=1)
                if "pgNumType" not in sect:
                    sect = sect.replace("<w:cols", '<w:pgNumType w:fmt="decimal" w:start="1"/><w:cols', 1)
                text = text[: last.start()] + sect + text[last.end():]
                data = text.encode("utf-8")
            zout.writestr(item, data)
    shutil.move(tmp, docx)


def main() -> None:
    if "--no-figures" not in sys.argv:
        subprocess.run([sys.executable, str(DOCS / "figures" / "make_figures.py")], check=True)
    for name in DOCUMENTS:
        src, out = DOCS / f"{name}.md", DOCS / f"{name}.docx"
        subprocess.run(["pandoc", str(src), "-o", str(out), f"--reference-doc={REFERENCE}", f"--resource-path={DOCS}"], check=True)
        postprocess(out)
        print(f"built {out.relative_to(ROOT)}  ({out.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
